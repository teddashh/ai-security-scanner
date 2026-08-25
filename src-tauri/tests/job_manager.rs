use ai_security_scanner_lib::job_manager::{
    EngineJobStatus, JobCompletion, JobFailureKind, JobKey, JobManager, JobManagerError, JobStatus,
};
use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

fn key() -> JobKey {
    JobKey::new("case-1", "scan-run-1").expect("valid key")
}

#[test]
fn duplicate_live_job_is_rejected_for_the_exact_case_and_run_pair() {
    let manager = JobManager::default();
    let key = key();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_release = Arc::clone(&release);
    let (started_tx, started_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let engine = context.engine("gitleaks").expect("engine control");
                engine.mark_running().expect("running");
                started_tx.send(()).expect("started event");
                let (mutex, changed) = &*worker_release;
                let mut released = mutex.lock().expect("release lock");
                while !*released {
                    released = changed.wait(released).expect("release wait");
                }
                engine.mark_completed().expect("completed");
                JobCompletion::Completed
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("first job starts");
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker started");

    let duplicate = manager
        .start_job(
            key.clone(),
            ["semgrep"],
            |_| JobCompletion::Completed,
            |_| {},
        )
        .expect_err("duplicate rejected");
    assert_eq!(duplicate, JobManagerError::DuplicateLiveJob(key.clone()));

    let (mutex, changed) = &*release;
    *mutex.lock().expect("release lock") = true;
    changed.notify_all();
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Completed);
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn pause_resume_and_cancel_requests_reach_each_engine_control() {
    let manager = JobManager::default();
    let key = key();
    let (token_tx, token_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let engine = context.engine("gitleaks").expect("engine control");
                engine.mark_running().expect("running");
                let token = engine.cancellation_token();
                token_tx.send(token.clone()).expect("token");
                while !token.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                engine.mark_cancelled().expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    let token = token_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("engine token");

    let (paused, pause_changed) = manager.pause_transition(&key).expect("pause request");
    assert!(pause_changed);
    assert_eq!(paused.status, JobStatus::PauseRequested);
    assert_eq!(paused.engines[0].status, EngineJobStatus::PauseRequested);
    assert!(token.is_pause_requested());
    assert!(!token.is_paused(), "a request is not an acknowledged pause");
    let (_, duplicate_pause_changed) = manager
        .pause_transition(&key)
        .expect("duplicate pause request");
    assert!(!duplicate_pause_changed);
    assert!(token.is_pause_requested());

    let (resumed, resume_changed) = manager.resume_transition(&key).expect("resume request");
    assert!(resume_changed);
    assert_eq!(resumed.status, JobStatus::Running);
    assert_eq!(resumed.engines[0].status, EngineJobStatus::Running);
    assert!(!token.is_pause_requested());
    let (_, duplicate_resume_changed) = manager
        .resume_transition(&key)
        .expect("duplicate resume request");
    assert!(!duplicate_resume_changed);
    assert!(!token.is_pause_requested());

    let cancelling = manager.cancel(&key).expect("cancel request");
    assert_eq!(cancelling.status, JobStatus::CancelRequested);
    assert_eq!(
        cancelling.engines[0].status,
        EngineJobStatus::CancelRequested
    );
    assert!(token.is_cancelled());
    assert!(matches!(
        manager.pause_transition(&key),
        Err(JobManagerError::CancellationPending(_))
    ));
    assert!(matches!(
        manager.resume_transition(&key),
        Err(JobManagerError::CancellationPending(_))
    ));

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Cancelled);
    assert_eq!(terminal.engines[0].status, EngineJobStatus::Cancelled);
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn durable_pause_and_resume_transitions_are_serialized_per_job() {
    let manager = JobManager::default();
    let key = key();
    let (token_tx, token_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let engine = context.engine("gitleaks").expect("engine control");
                engine.mark_running().expect("running");
                let token = engine.cancellation_token();
                token_tx.send(token.clone()).expect("token");
                while !token.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                engine.mark_cancelled().expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    let token = token_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("engine token");

    let pause_release = Arc::new(Barrier::new(2));
    let (pause_a_entered_tx, pause_a_entered_rx) = mpsc::channel();
    let pause_a_manager = manager.clone();
    let pause_a_key = key.clone();
    let pause_a_release = Arc::clone(&pause_release);
    let pause_a = thread::spawn(move || {
        pause_a_manager.pause_with_durable_transition(&pause_a_key, || {
            pause_a_entered_tx.send(()).expect("pause A entered");
            pause_a_release.wait();
            Err::<(), _>("simulated revision conflict")
        })
    });
    pause_a_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("pause A entered durable mutation");

    let (pause_b_entered_tx, pause_b_entered_rx) = mpsc::channel();
    let pause_b_manager = manager.clone();
    let pause_b_key = key.clone();
    let pause_b = thread::spawn(move || {
        pause_b_manager.pause_with_durable_transition(&pause_b_key, || {
            pause_b_entered_tx.send(()).expect("pause B entered");
            Ok::<_, &str>(())
        })
    });
    assert!(
        pause_b_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "duplicate durable pause must wait for the first transition"
    );
    pause_release.wait();
    assert!(pause_a.join().expect("pause A thread").unwrap().is_err());
    assert!(pause_b.join().expect("pause B thread").unwrap().is_ok());
    assert!(token.is_pause_requested());

    let resume_release = Arc::new(Barrier::new(2));
    let (resume_a_entered_tx, resume_a_entered_rx) = mpsc::channel();
    let resume_a_manager = manager.clone();
    let resume_a_key = key.clone();
    let resume_a_release = Arc::clone(&resume_release);
    let resume_a = thread::spawn(move || {
        resume_a_manager.resume_with_durable_transition(&resume_a_key, || {
            resume_a_entered_tx.send(()).expect("resume A entered");
            resume_a_release.wait();
            Err::<(), _>("simulated revision conflict")
        })
    });
    resume_a_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("resume A entered durable mutation");

    let (resume_b_entered_tx, resume_b_entered_rx) = mpsc::channel();
    let resume_b_manager = manager.clone();
    let resume_b_key = key.clone();
    let resume_b = thread::spawn(move || {
        resume_b_manager.resume_with_durable_transition(&resume_b_key, || {
            resume_b_entered_tx.send(()).expect("resume B entered");
            Ok::<_, &str>(())
        })
    });
    assert!(
        resume_b_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "duplicate durable resume must wait for the first transition"
    );
    resume_release.wait();
    assert!(resume_a.join().expect("resume A thread").unwrap().is_err());
    assert!(resume_b.join().expect("resume B thread").unwrap().is_ok());
    assert!(!token.is_pause_requested());

    manager.cancel(&key).expect("cancel worker");
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Cancelled);
}

#[test]
fn worker_durable_write_is_serialized_with_pause_transition() {
    let manager = JobManager::default();
    let key = key();
    let durable_release = Arc::new(Barrier::new(2));
    let worker_release = Arc::clone(&durable_release);
    let (durable_entered_tx, durable_entered_rx) = mpsc::channel();
    let (token_tx, token_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let engine = context.engine("gitleaks").expect("engine control");
                engine.mark_running().expect("running");
                let token = engine.cancellation_token();
                token_tx.send(token.clone()).expect("token");
                context.coordinate_durable_write(|| {
                    durable_entered_tx.send(()).expect("worker write entered");
                    worker_release.wait();
                });
                while !token.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                engine.mark_cancelled().expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    let token = token_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("engine token");
    durable_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker durable write entered");

    let (pause_entered_tx, pause_entered_rx) = mpsc::channel();
    let pause_manager = manager.clone();
    let pause_key = key.clone();
    let pause = thread::spawn(move || {
        pause_manager.pause_with_durable_transition(&pause_key, || {
            pause_entered_tx
                .send(())
                .expect("pause durable write entered");
            Ok::<_, &str>(())
        })
    });
    assert!(
        pause_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "pause persistence must wait for the worker's report persistence"
    );

    durable_release.wait();
    assert!(pause.join().expect("pause thread").unwrap().is_ok());
    assert!(token.is_pause_requested());

    manager.cancel(&key).expect("cancel worker");
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Cancelled);
}

#[test]
fn terminal_job_is_removed_before_callback_and_same_key_can_restart() {
    let manager = JobManager::default();
    let key = key();
    let callback_manager = manager.clone();
    let callback_key = key.clone();
    let (restart_tx, restart_rx) = mpsc::channel();
    let (second_terminal_tx, second_terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["first"],
            |context| {
                let engine = context.engine("first").expect("engine");
                engine.mark_running().expect("running");
                engine.mark_completed().expect("completed");
                JobCompletion::Completed
            },
            move |_| {
                let result = callback_manager.start_job(
                    callback_key,
                    ["second"],
                    |context| {
                        let engine = context.engine("second").expect("engine");
                        engine.mark_running().expect("running");
                        engine.mark_completed().expect("completed");
                        JobCompletion::Completed
                    },
                    move |snapshot| {
                        second_terminal_tx
                            .send(snapshot)
                            .expect("second terminal event")
                    },
                );
                restart_tx.send(result.is_ok()).expect("restart result");
            },
        )
        .expect("first job starts");

    assert!(
        restart_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("restart callback")
    );
    let terminal = second_terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second terminal callback");
    assert_eq!(terminal.status, JobStatus::Completed);
    assert_eq!(terminal.engines[0].engine_id, "second");
    assert_eq!(manager.live_count(), 0);
    assert!(manager.forget_terminal(&key));
    assert!(manager.snapshot(&key).is_none());
}

#[test]
fn worker_panic_is_sanitized_and_reported_as_terminal_failure() {
    let manager = JobManager::default();
    let key = key();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            |context| {
                context
                    .engine("gitleaks")
                    .expect("engine")
                    .mark_running()
                    .expect("running");
                panic!("sensitive panic payload must not escape");
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Failed);
    assert_eq!(terminal.failure_kind, Some(JobFailureKind::WorkerPanicked));
    assert_eq!(terminal.engines[0].status, EngineJobStatus::Failed);
    assert!(!format!("{terminal:?}").contains("sensitive panic payload"));
    assert!(
        !serde_json::to_string(&terminal)
            .expect("serialize snapshot")
            .contains("sensitive panic payload")
    );
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn panic_after_engine_completion_cannot_report_a_successful_job() {
    let manager = JobManager::default();
    let key = key();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key,
            ["gitleaks"],
            |context| {
                let engine = context.engine("gitleaks").expect("engine");
                engine.mark_running().expect("running");
                engine.mark_completed().expect("completed engine report");
                panic!("panic after durable engine completion");
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.engines[0].status, EngineJobStatus::Completed);
    assert_eq!(terminal.status, JobStatus::Failed);
    assert_eq!(terminal.failure_kind, Some(JobFailureKind::WorkerPanicked));
}

#[test]
fn completed_worker_must_account_for_every_engine() {
    let manager = JobManager::default();
    let key = key();
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["gitleaks", "semgrep"],
            |context| {
                let engine = context.engine("gitleaks").expect("engine");
                engine.mark_running().expect("running");
                engine.mark_completed().expect("completed");
                JobCompletion::Completed
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Failed);
    assert_eq!(
        terminal.failure_kind,
        Some(JobFailureKind::WorkerReturnedEarly)
    );
    assert_eq!(
        terminal
            .engines
            .iter()
            .find(|engine| engine.engine_id == "semgrep")
            .expect("semgrep")
            .status,
        EngineJobStatus::Failed
    );
}

#[test]
fn concurrent_starts_admit_exactly_one_live_worker() {
    const CONTENDERS: usize = 16;
    let manager = JobManager::default();
    let key = key();
    let start_barrier = Arc::new(Barrier::new(CONTENDERS));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (terminal_tx, terminal_rx) = mpsc::channel();
    let mut contenders = Vec::new();

    for index in 0..CONTENDERS {
        let contender_manager = manager.clone();
        let contender_key = key.clone();
        let contender_barrier = Arc::clone(&start_barrier);
        let worker_release = Arc::clone(&release);
        let contender_terminal = terminal_tx.clone();
        contenders.push(thread::spawn(move || {
            contender_barrier.wait();
            contender_manager.start_job(
                contender_key,
                [format!("engine-{index}")],
                move |context| {
                    let engine_id = context.engine_ids().remove(0);
                    let engine = context.engine(&engine_id).expect("engine");
                    engine.mark_running().expect("running");
                    let (mutex, changed) = &*worker_release;
                    let mut released = mutex.lock().expect("release lock");
                    while !*released {
                        released = changed.wait(released).expect("release wait");
                    }
                    engine.mark_completed().expect("completed");
                    JobCompletion::Completed
                },
                move |snapshot| contender_terminal.send(snapshot).expect("terminal event"),
            )
        }));
    }
    drop(terminal_tx);

    let results = contenders
        .into_iter()
        .map(|contender| contender.join().expect("contender thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(JobManagerError::DuplicateLiveJob(_))))
            .count(),
        CONTENDERS - 1
    );
    assert_eq!(manager.live_count(), 1);

    let (mutex, changed) = &*release;
    *mutex.lock().expect("release lock") = true;
    changed.notify_all();
    assert_eq!(
        terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal callback")
            .status,
        JobStatus::Completed
    );
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn manager_debug_and_snapshots_do_not_capture_worker_closure_data() {
    let manager = JobManager::default();
    let key = key();
    let secret = String::from("never-serialize-this-secret-value");
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_release = Arc::clone(&release);
    let (started_tx, started_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let _owned_sensitive_context = secret;
                let engine = context.engine("gitleaks").expect("engine");
                engine.mark_running().expect("running");
                started_tx.send(()).expect("started");
                let (mutex, changed) = &*worker_release;
                let mut released = mutex.lock().expect("release lock");
                while !*released {
                    released = changed.wait(released).expect("release wait");
                }
                engine.mark_completed().expect("completed");
                JobCompletion::Completed
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker started");

    let snapshot = manager.snapshot(&key).expect("live snapshot");
    assert!(!format!("{manager:?}").contains("never-serialize-this-secret-value"));
    assert!(
        !serde_json::to_string(&snapshot)
            .expect("snapshot json")
            .contains("never-serialize-this-secret-value")
    );

    let (mutex, changed) = &*release;
    *mutex.lock().expect("release lock") = true;
    changed.notify_all();
    terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
}
