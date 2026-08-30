use crate::domain::RuntimeHealth;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Live provider checks may each consume a bounded OS-command deadline and
/// hold the provider lifecycle lock. A five-minute observation is fresh
/// enough for shell copy; execution still performs its own authoritative
/// preparation. Lifecycle transitions explicitly invalidate this cache.
const RUNTIME_HEALTH_FRESHNESS: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
struct RuntimeHealthMonitorState {
    cached: RuntimeHealth,
    refresh_active: bool,
    last_completed_at: Option<Instant>,
    lifecycle_epoch: u64,
}

/// Keeps slow provider detection off commands that only need saved app data.
///
/// Callers always receive the last completed observation immediately. At most
/// one background detector may run at a time; repeated shell/readiness reads
/// therefore cannot queue uncancelled WSL or container-service commands.
#[derive(Debug, Clone)]
pub struct RuntimeHealthMonitor {
    state: Arc<Mutex<RuntimeHealthMonitorState>>,
}

impl RuntimeHealthMonitor {
    pub fn new(initial: RuntimeHealth) -> Self {
        Self {
            state: Arc::new(Mutex::new(RuntimeHealthMonitorState {
                cached: initial,
                refresh_active: false,
                last_completed_at: None,
                lifecycle_epoch: 0,
            })),
        }
    }

    pub fn cached(&self) -> RuntimeHealth {
        self.lock().cached.clone()
    }

    pub fn replace_cached(&self, health: RuntimeHealth) {
        let mut state = self.lock();
        state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
        state.cached = health;
        state.last_completed_at = None;
    }

    /// Records health produced by an actual lifecycle operation. It is more
    /// authoritative than a shell probe and starts a new freshness window.
    pub fn record_observation(&self, health: RuntimeHealth) {
        let mut state = self.lock();
        state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
        state.cached = health;
        state.last_completed_at = Some(Instant::now());
    }

    pub fn invalidate(&self) {
        let mut state = self.lock();
        state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
        state.last_completed_at = None;
    }

    /// Starts one best-effort refresh without making the caller wait.
    ///
    /// `false` means an exact refresh is already active or the worker could
    /// not be spawned. A detector panic leaves the previous observation
    /// unchanged and releases the slot so a later read can retry.
    pub fn request_refresh<F>(&self, detector: F) -> bool
    where
        F: FnOnce() -> RuntimeHealth + Send + 'static,
    {
        let lifecycle_epoch = {
            let mut state = self.lock();
            if state.refresh_active {
                return false;
            }
            if state
                .last_completed_at
                .is_some_and(|completed| completed.elapsed() < RUNTIME_HEALTH_FRESHNESS)
            {
                return false;
            }
            state.refresh_active = true;
            state.lifecycle_epoch
        };

        let shared = Arc::clone(&self.state);
        let spawn = std::thread::Builder::new()
            .name("runtime-health-refresh".into())
            .spawn(move || {
                let detected = catch_unwind(AssertUnwindSafe(detector));
                let mut state = lock_recovering_poison(&shared);
                if state.lifecycle_epoch == lifecycle_epoch
                    && let Ok(health) = detected
                {
                    state.cached = health;
                    state.last_completed_at = Some(Instant::now());
                }
                state.refresh_active = false;
            });

        if spawn.is_err() {
            self.lock().refresh_active = false;
            return false;
        }
        true
    }

    #[cfg(test)]
    fn refresh_active(&self) -> bool {
        self.lock().refresh_active
    }

    fn lock(&self) -> MutexGuard<'_, RuntimeHealthMonitorState> {
        lock_recovering_poison(&self.state)
    }
}

fn lock_recovering_poison(
    state: &Mutex<RuntimeHealthMonitorState>,
) -> MutexGuard<'_, RuntimeHealthMonitorState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn health(phase: &str, available: bool) -> RuntimeHealth {
        RuntimeHealth {
            provider: "managed_local".into(),
            available,
            phase: phase.into(),
            version: None,
            prerequisite: None,
            detail: phase.into(),
        }
    }

    fn wait_for_refresh(monitor: &RuntimeHealthMonitor) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while monitor.refresh_active() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!monitor.refresh_active(), "refresh did not settle in time");
    }

    #[test]
    fn slow_refresh_never_blocks_reads_or_queues_duplicate_detectors() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        assert!(monitor.request_refresh(move || {
            entered_tx.send(()).expect("signal detector entry");
            release_rx.recv().expect("release detector");
            health("running", true)
        }));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detector started");

        assert_eq!(monitor.cached().phase, "checking");
        assert!(!monitor.request_refresh(|| health("duplicate", false)));

        release_tx.send(()).expect("release slow detector");
        wait_for_refresh(&monitor);
        assert_eq!(monitor.cached().phase, "running");
        assert!(monitor.cached().available);
        assert!(
            !monitor.request_refresh(|| health("too_soon", false)),
            "repeated shell reads inside the freshness window must not relaunch detection",
        );
    }

    #[test]
    fn panicking_detector_preserves_cache_and_allows_retry() {
        let monitor = RuntimeHealthMonitor::new(health("last_known", true));
        let (entered_tx, entered_rx) = mpsc::channel();

        assert!(monitor.request_refresh(move || {
            entered_tx.send(()).expect("signal detector entry");
            panic!("detector panic fixture")
        }));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detector started");
        wait_for_refresh(&monitor);

        assert_eq!(monitor.cached().phase, "last_known");
        assert!(monitor.request_refresh(|| health("recovered", true)));
    }

    #[test]
    fn lifecycle_observation_is_fresh_until_explicitly_invalidated() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        monitor.record_observation(health("running", true));

        assert!(!monitor.request_refresh(|| health("unexpected", false)));
        monitor.invalidate();
        assert!(monitor.request_refresh(|| health("stopped", false)));
    }

    #[test]
    fn lifecycle_change_rejects_an_older_probe_result() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        assert!(monitor.request_refresh(move || {
            entered_tx.send(()).expect("signal detector entry");
            release_rx.recv().expect("release detector");
            health("stale_probe", false)
        }));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detector started");

        monitor.record_observation(health("setup_completed", true));
        release_tx.send(()).expect("release stale detector");
        wait_for_refresh(&monitor);

        assert_eq!(monitor.cached().phase, "setup_completed");
        assert!(monitor.cached().available);
    }
}
