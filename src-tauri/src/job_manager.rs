//! Thread-safe lifecycle control for long-running assessment scan jobs.
//!
//! The manager deliberately knows nothing about Tauri, storage, adapters, or
//! scanners. Callers provide an owned worker closure and a terminal callback,
//! which keeps dependency lifetimes at the integration boundary. A live job is
//! identified only by its `(case_id, scan_run_id)` pair.

use crate::container_runtime::CancellationToken;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use thiserror::Error;

const TERMINAL_HISTORY_LIMIT: usize = 256;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobKey {
    pub case_id: String,
    pub scan_run_id: String,
}

impl JobKey {
    pub fn new(
        case_id: impl Into<String>,
        scan_run_id: impl Into<String>,
    ) -> Result<Self, JobManagerError> {
        let key = Self {
            case_id: case_id.into(),
            scan_run_id: scan_run_id.into(),
        };
        validate_identity(&key.case_id, "case id")?;
        validate_identity(&key.scan_run_id, "scan run id")?;
        Ok(key)
    }
}

impl fmt::Debug for JobKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("JobKey")
            .field(&self.case_id)
            .field(&self.scan_run_id)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Starting,
    Running,
    PauseRequested,
    Paused,
    ResumeRequested,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
}

impl JobStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineJobStatus {
    Queued,
    Running,
    PauseRequested,
    Paused,
    ResumeRequested,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
}

impl EngineJobStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobFailureKind {
    WorkerReported,
    WorkerPanicked,
    WorkerReturnedEarly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineJobSnapshot {
    pub engine_id: String,
    pub status: EngineJobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobSnapshot {
    pub key: JobKey,
    pub status: JobStatus,
    pub engines: Vec<EngineJobSnapshot>,
    pub failure_kind: Option<JobFailureKind>,
}

impl JobSnapshot {
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }
}

/// The worker's aggregate result. For `Completed`, every engine must already
/// have been marked terminal by its [`EngineJobControl`]; otherwise the manager
/// records a fail-closed `WorkerReturnedEarly` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobCompletion {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JobManagerError {
    #[error("invalid {field}")]
    InvalidIdentity { field: &'static str },
    #[error("job must contain at least one unique engine")]
    InvalidEngineSet,
    #[error("a live job already exists for {0:?}")]
    DuplicateLiveJob(JobKey),
    #[error("no live job exists for {0:?}")]
    LiveJobNotFound(JobKey),
    #[error("engine {engine_id} is not registered in job {key:?}")]
    EngineNotFound { key: JobKey, engine_id: String },
    #[error("engine {engine_id} in job {key:?} is already terminal")]
    EngineAlreadyTerminal { key: JobKey, engine_id: String },
    #[error("scan worker thread could not be started")]
    ThreadSpawnFailed,
}

#[derive(Clone, Default)]
pub struct JobManager {
    inner: Arc<ManagerInner>,
}

impl fmt::Debug for JobManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.inner.state);
        formatter
            .debug_struct("JobManager")
            .field("live_jobs", &state.live.len())
            .field("terminal_jobs", &state.terminal.len())
            .finish()
    }
}

impl JobManager {
    /// Starts one owned worker on a dedicated thread. The callback is invoked
    /// after the live entry has been atomically replaced by its terminal
    /// snapshot, so callback code may safely start a new job for the same key.
    pub fn start_job<W, C, I, S>(
        &self,
        key: JobKey,
        engine_ids: I,
        worker: W,
        on_terminal: C,
    ) -> Result<JobSnapshot, JobManagerError>
    where
        W: FnOnce(JobContext) -> JobCompletion + Send + 'static,
        C: FnOnce(JobSnapshot) + Send + 'static,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        validate_identity(&key.case_id, "case id")?;
        validate_identity(&key.scan_run_id, "scan run id")?;
        let engines = build_engine_records(engine_ids)?;

        let record = {
            let mut state = lock(&self.inner.state);
            if state.live.contains_key(&key) {
                return Err(JobManagerError::DuplicateLiveJob(key));
            }
            state.next_generation = state.next_generation.wrapping_add(1).max(1);
            let record = Arc::new(JobRecord::new(key.clone(), state.next_generation, engines));
            state.terminal.remove(&key);
            state.terminal_order.retain(|candidate| candidate != &key);
            state.live.insert(key.clone(), Arc::clone(&record));
            record
        };

        let initial = record.snapshot();
        let manager = self.clone();
        let thread_record = Arc::clone(&record);
        let thread_name = format!("assessment-job-{}", record.generation);
        let spawn = thread::Builder::new().name(thread_name).spawn(move || {
            thread_record.mark_running();
            let context = JobContext {
                record: Arc::clone(&thread_record),
            };
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| worker(context)));
            let (completion, forced_failure) = match outcome {
                Ok(completion) => (completion, None),
                Err(_) => (JobCompletion::Failed, Some(JobFailureKind::WorkerPanicked)),
            };
            let terminal = manager.finalize_job(&thread_record, completion, forced_failure);
            let _ = panic::catch_unwind(AssertUnwindSafe(|| on_terminal(terminal)));
        });

        if spawn.is_err() {
            let mut state = lock(&self.inner.state);
            if state
                .live
                .get(&key)
                .is_some_and(|candidate| candidate.generation == record.generation)
            {
                state.live.remove(&key);
            }
            return Err(JobManagerError::ThreadSpawnFailed);
        }

        Ok(initial)
    }

    pub fn snapshot(&self, key: &JobKey) -> Option<JobSnapshot> {
        let state = lock(&self.inner.state);
        state
            .live
            .get(key)
            .map(|record| record.snapshot())
            .or_else(|| state.terminal.get(key).cloned())
    }

    pub fn live_snapshots(&self) -> Vec<JobSnapshot> {
        let state = lock(&self.inner.state);
        let mut snapshots = state
            .live
            .values()
            .map(|record| record.snapshot())
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| {
            (&left.key.case_id, &left.key.scan_run_id)
                .cmp(&(&right.key.case_id, &right.key.scan_run_id))
        });
        snapshots
    }

    pub fn live_count(&self) -> usize {
        lock(&self.inner.state).live.len()
    }

    pub fn pause(&self, key: &JobKey) -> Result<JobSnapshot, JobManagerError> {
        let state = lock(&self.inner.state);
        let record = state
            .live
            .get(key)
            .ok_or_else(|| JobManagerError::LiveJobNotFound(key.clone()))?;
        record.request_pause();
        Ok(record.snapshot())
    }

    pub fn resume(&self, key: &JobKey) -> Result<JobSnapshot, JobManagerError> {
        let state = lock(&self.inner.state);
        let record = state
            .live
            .get(key)
            .ok_or_else(|| JobManagerError::LiveJobNotFound(key.clone()))?;
        record.request_resume();
        Ok(record.snapshot())
    }

    pub fn cancel(&self, key: &JobKey) -> Result<JobSnapshot, JobManagerError> {
        let state = lock(&self.inner.state);
        let record = state
            .live
            .get(key)
            .ok_or_else(|| JobManagerError::LiveJobNotFound(key.clone()))?;
        record.request_cancel();
        Ok(record.snapshot())
    }

    /// Removes a retained terminal snapshot. Live jobs cannot be forgotten.
    pub fn forget_terminal(&self, key: &JobKey) -> bool {
        let mut state = lock(&self.inner.state);
        if state.live.contains_key(key) {
            return false;
        }
        state.terminal_order.retain(|candidate| candidate != key);
        state.terminal.remove(key).is_some()
    }

    fn finalize_job(
        &self,
        record: &Arc<JobRecord>,
        completion: JobCompletion,
        forced_failure: Option<JobFailureKind>,
    ) -> JobSnapshot {
        let mut state = lock(&self.inner.state);
        let still_current = state
            .live
            .get(&record.key)
            .is_some_and(|candidate| candidate.generation == record.generation);
        if !still_current {
            return record.snapshot();
        }
        let terminal = record.finalize(completion, forced_failure);
        state.live.remove(&record.key);
        state.terminal.insert(record.key.clone(), terminal.clone());
        state.terminal_order.retain(|key| key != &record.key);
        state.terminal_order.push_back(record.key.clone());
        while state.terminal_order.len() > TERMINAL_HISTORY_LIMIT {
            if let Some(expired) = state.terminal_order.pop_front() {
                state.terminal.remove(&expired);
            }
        }
        terminal
    }
}

#[derive(Clone)]
pub struct JobContext {
    record: Arc<JobRecord>,
}

impl fmt::Debug for JobContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobContext")
            .field("key", &self.record.key)
            .field("engine_ids", &self.engine_ids())
            .field("cancelled", &self.is_cancelled())
            .field("pause_requested", &self.is_pause_requested())
            .finish()
    }
}

impl JobContext {
    pub fn key(&self) -> &JobKey {
        &self.record.key
    }

    pub fn engine_ids(&self) -> Vec<String> {
        self.record.engines.keys().cloned().collect()
    }

    pub fn engine(&self, engine_id: &str) -> Result<EngineJobControl, JobManagerError> {
        self.record
            .engines
            .get(engine_id)
            .cloned()
            .map(|record| EngineJobControl {
                key: self.record.key.clone(),
                record,
            })
            .ok_or_else(|| JobManagerError::EngineNotFound {
                key: self.record.key.clone(),
                engine_id: engine_id.to_owned(),
            })
    }

    pub fn is_cancelled(&self) -> bool {
        self.record.cancel_requested.load(Ordering::SeqCst)
    }

    pub fn is_pause_requested(&self) -> bool {
        self.record.pause_requested.load(Ordering::SeqCst)
    }

    /// Blocks dispatch between engines while a pause is requested. Returns
    /// `false` if cancellation won the race, allowing the worker to stop before
    /// starting another engine.
    pub fn wait_until_runnable(&self) -> bool {
        let mut guard = lock(&self.record.gate);
        while self.is_pause_requested() && !self.is_cancelled() {
            guard = self
                .record
                .gate_changed
                .wait(guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        !self.is_cancelled()
    }
}

#[derive(Clone)]
pub struct EngineJobControl {
    key: JobKey,
    record: Arc<EngineRecord>,
}

impl fmt::Debug for EngineJobControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineJobControl")
            .field("key", &self.key)
            .field("engine_id", &self.record.engine_id)
            .field("status", &self.record.snapshot_status())
            .finish()
    }
}

impl EngineJobControl {
    pub fn engine_id(&self) -> &str {
        &self.record.engine_id
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.record.token.clone()
    }

    pub fn status(&self) -> EngineJobStatus {
        self.record.snapshot_status()
    }

    pub fn mark_running(&self) -> Result<(), JobManagerError> {
        self.record.transition_running(&self.key)
    }

    pub fn mark_completed(&self) -> Result<(), JobManagerError> {
        self.record
            .transition_terminal(&self.key, BaseEngineStatus::Completed)
    }

    pub fn mark_cancelled(&self) -> Result<(), JobManagerError> {
        self.record
            .transition_terminal(&self.key, BaseEngineStatus::Cancelled)
    }

    pub fn mark_failed(&self) -> Result<(), JobManagerError> {
        self.record
            .transition_terminal(&self.key, BaseEngineStatus::Failed)
    }
}

#[derive(Default)]
struct ManagerInner {
    state: Mutex<ManagerState>,
}

#[derive(Default)]
struct ManagerState {
    live: HashMap<JobKey, Arc<JobRecord>>,
    terminal: HashMap<JobKey, JobSnapshot>,
    terminal_order: VecDeque<JobKey>,
    next_generation: u64,
}

struct JobRecord {
    key: JobKey,
    generation: u64,
    phase: Mutex<RecordPhase>,
    engines: BTreeMap<String, Arc<EngineRecord>>,
    pause_requested: AtomicBool,
    cancel_requested: AtomicBool,
    gate: Mutex<()>,
    gate_changed: Condvar,
}

impl JobRecord {
    fn new(key: JobKey, generation: u64, engines: BTreeMap<String, Arc<EngineRecord>>) -> Self {
        Self {
            key,
            generation,
            phase: Mutex::new(RecordPhase::Starting),
            engines,
            pause_requested: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
            gate: Mutex::new(()),
            gate_changed: Condvar::new(),
        }
    }

    fn mark_running(&self) {
        let mut phase = lock(&self.phase);
        if matches!(*phase, RecordPhase::Starting) {
            *phase = RecordPhase::Running;
        }
    }

    fn request_pause(&self) {
        if self.cancel_requested.load(Ordering::SeqCst) {
            return;
        }
        self.pause_requested.store(true, Ordering::SeqCst);
        for engine in self.engines.values() {
            if !engine.base_status().is_terminal() {
                engine.token.request_pause();
            }
        }
    }

    fn request_resume(&self) {
        self.pause_requested.store(false, Ordering::SeqCst);
        for engine in self.engines.values() {
            if !engine.base_status().is_terminal() {
                engine.token.resume();
            }
        }
        self.gate_changed.notify_all();
    }

    fn request_cancel(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
        for engine in self.engines.values() {
            if !engine.base_status().is_terminal() {
                engine.token.cancel();
            }
        }
        self.gate_changed.notify_all();
    }

    fn snapshot(&self) -> JobSnapshot {
        let phase = *lock(&self.phase);
        let engines = self
            .engines
            .values()
            .map(|engine| EngineJobSnapshot {
                engine_id: engine.engine_id.clone(),
                status: engine.snapshot_status(),
            })
            .collect::<Vec<_>>();
        let (status, failure_kind) = match phase {
            RecordPhase::Terminal {
                status,
                failure_kind,
            } => (status, failure_kind),
            RecordPhase::Starting if self.cancel_requested.load(Ordering::SeqCst) => {
                (JobStatus::CancelRequested, None)
            }
            RecordPhase::Starting if self.pause_requested.load(Ordering::SeqCst) => {
                (JobStatus::Paused, None)
            }
            RecordPhase::Starting => (JobStatus::Starting, None),
            RecordPhase::Running if self.cancel_requested.load(Ordering::SeqCst) => {
                (JobStatus::CancelRequested, None)
            }
            RecordPhase::Running if self.pause_requested.load(Ordering::SeqCst) => {
                let running = self
                    .engines
                    .values()
                    .filter(|engine| engine.base_status() == BaseEngineStatus::Running)
                    .collect::<Vec<_>>();
                if running.iter().all(|engine| engine.token.is_paused()) {
                    (JobStatus::Paused, None)
                } else {
                    (JobStatus::PauseRequested, None)
                }
            }
            RecordPhase::Running
                if self.engines.values().any(|engine| {
                    engine.base_status() == BaseEngineStatus::Running && engine.token.is_paused()
                }) =>
            {
                (JobStatus::ResumeRequested, None)
            }
            RecordPhase::Running => (JobStatus::Running, None),
        };
        JobSnapshot {
            key: self.key.clone(),
            status,
            engines,
            failure_kind,
        }
    }

    fn finalize(
        &self,
        completion: JobCompletion,
        forced_failure: Option<JobFailureKind>,
    ) -> JobSnapshot {
        let mut failure_kind = forced_failure;
        match completion {
            JobCompletion::Completed => {
                let incomplete = self
                    .engines
                    .values()
                    .filter(|engine| !engine.base_status().is_terminal())
                    .collect::<Vec<_>>();
                if !incomplete.is_empty() {
                    failure_kind.get_or_insert(JobFailureKind::WorkerReturnedEarly);
                    for engine in incomplete {
                        engine.force_terminal(BaseEngineStatus::Failed);
                    }
                }
            }
            JobCompletion::Cancelled => {
                for engine in self.engines.values() {
                    if !engine.base_status().is_terminal() {
                        engine.force_terminal(BaseEngineStatus::Cancelled);
                    }
                }
            }
            JobCompletion::Failed => {
                failure_kind.get_or_insert(JobFailureKind::WorkerReported);
                for engine in self.engines.values() {
                    if !engine.base_status().is_terminal() {
                        engine.force_terminal(BaseEngineStatus::Failed);
                    }
                }
            }
        }

        let statuses = self
            .engines
            .values()
            .map(|engine| engine.base_status())
            .collect::<Vec<_>>();
        let status = if statuses.contains(&BaseEngineStatus::Failed) {
            failure_kind.get_or_insert(JobFailureKind::WorkerReported);
            JobStatus::Failed
        } else if statuses.contains(&BaseEngineStatus::Cancelled) {
            JobStatus::Cancelled
        } else {
            JobStatus::Completed
        };
        *lock(&self.phase) = RecordPhase::Terminal {
            status,
            failure_kind,
        };
        self.pause_requested.store(false, Ordering::SeqCst);
        self.gate_changed.notify_all();
        self.snapshot()
    }
}

#[derive(Clone, Copy)]
enum RecordPhase {
    Starting,
    Running,
    Terminal {
        status: JobStatus,
        failure_kind: Option<JobFailureKind>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseEngineStatus {
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}

impl BaseEngineStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

struct EngineRecord {
    engine_id: String,
    status: Mutex<BaseEngineStatus>,
    token: CancellationToken,
}

impl EngineRecord {
    fn base_status(&self) -> BaseEngineStatus {
        *lock(&self.status)
    }

    fn snapshot_status(&self) -> EngineJobStatus {
        let base = self.base_status();
        match base {
            BaseEngineStatus::Completed => EngineJobStatus::Completed,
            BaseEngineStatus::Cancelled => EngineJobStatus::Cancelled,
            BaseEngineStatus::Failed => EngineJobStatus::Failed,
            _ if self.token.is_cancelled() => EngineJobStatus::CancelRequested,
            _ if self.token.is_paused() && self.token.is_pause_requested() => {
                EngineJobStatus::Paused
            }
            _ if self.token.is_paused() => EngineJobStatus::ResumeRequested,
            _ if self.token.is_pause_requested() => EngineJobStatus::PauseRequested,
            BaseEngineStatus::Queued => EngineJobStatus::Queued,
            BaseEngineStatus::Running => EngineJobStatus::Running,
        }
    }

    fn transition_running(&self, key: &JobKey) -> Result<(), JobManagerError> {
        let mut status = lock(&self.status);
        match *status {
            BaseEngineStatus::Queued => {
                *status = BaseEngineStatus::Running;
                Ok(())
            }
            BaseEngineStatus::Running => Ok(()),
            BaseEngineStatus::Completed
            | BaseEngineStatus::Cancelled
            | BaseEngineStatus::Failed => Err(JobManagerError::EngineAlreadyTerminal {
                key: key.clone(),
                engine_id: self.engine_id.clone(),
            }),
        }
    }

    fn transition_terminal(
        &self,
        key: &JobKey,
        next: BaseEngineStatus,
    ) -> Result<(), JobManagerError> {
        debug_assert!(next.is_terminal());
        let mut status = lock(&self.status);
        if status.is_terminal() {
            return Err(JobManagerError::EngineAlreadyTerminal {
                key: key.clone(),
                engine_id: self.engine_id.clone(),
            });
        }
        *status = next;
        Ok(())
    }

    fn force_terminal(&self, next: BaseEngineStatus) {
        debug_assert!(next.is_terminal());
        *lock(&self.status) = next;
    }
}

fn build_engine_records<I, S>(
    engine_ids: I,
) -> Result<BTreeMap<String, Arc<EngineRecord>>, JobManagerError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut records = BTreeMap::new();
    for raw in engine_ids {
        let engine_id = raw.into();
        validate_identity(&engine_id, "engine id")?;
        let record = Arc::new(EngineRecord {
            engine_id: engine_id.clone(),
            status: Mutex::new(BaseEngineStatus::Queued),
            token: CancellationToken::default(),
        });
        if records.insert(engine_id, record).is_some() {
            return Err(JobManagerError::InvalidEngineSet);
        }
    }
    if records.is_empty() {
        return Err(JobManagerError::InvalidEngineSet);
    }
    Ok(records)
}

fn validate_identity(value: &str, field: &'static str) -> Result<(), JobManagerError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.contains(['\0', '\n', '\r'])
    {
        return Err(JobManagerError::InvalidIdentity { field });
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
