pub mod adapter;
pub mod adapters;
pub mod artifact_store;
pub mod beginner_report;
pub mod bootstrap;
pub mod case_service;
#[cfg(feature = "desktop")]
mod commands;
pub mod connectors;
pub mod container_runtime;
pub mod coverage;
pub mod credential_vault;
pub mod demo;
pub mod diff;
pub mod discovery;
pub mod domain;
pub mod error;
pub mod export;
pub mod export_identity;
pub mod exporters;
pub mod external_scope;
#[cfg(any(feature = "desktop", feature = "cli"))]
pub mod gateway_release;
pub mod job_manager;
pub mod local_tcp_probe;
pub mod localhost_quick_scan;
pub mod managed_network;
pub mod managed_runtime;
pub mod orchestrator;
pub mod prioritization;
pub mod process_lease;
pub mod product_uninstall;
pub mod registry;
pub mod runtime;
pub mod runtime_health_monitor;
pub mod source_authorization;
#[cfg(feature = "desktop")]
mod state;
pub mod storage;
pub mod target_candidates;
pub mod workspace_snapshot;

#[cfg(feature = "desktop")]
use artifact_store::ArtifactStore;
#[cfg(feature = "desktop")]
use managed_runtime::ManagedRuntimeManager;
#[cfg(feature = "desktop")]
use process_lease::DataDirectoryExclusiveLease;
#[cfg(feature = "desktop")]
use registry::EngineRegistry;
#[cfg(feature = "desktop")]
use state::AppState;
#[cfg(feature = "desktop")]
use storage::Storage;
#[cfg(feature = "desktop")]
use tauri::Manager;

/// Provider/container reconciliation may execute slow local commands. It runs
/// only after the shell owns managed state and never propagates an error into
/// desktop setup; unresolved obligations remain durable for a later retry.
#[cfg(feature = "desktop")]
fn reconcile_live_startup_resources(state: &AppState) {
    match state.reconcile_managed_networks() {
        Ok(network_recovery)
            if network_recovery.reconciled > 0 || network_recovery.incomplete > 0 =>
        {
            tracing::warn!(
                reconciled = network_recovery.reconciled,
                incomplete = network_recovery.incomplete,
                details = ?network_recovery.details,
                "managed egress resources were reconciled after the desktop shell opened"
            );
        }
        Ok(_) => {}
        Err(error) => tracing::error!(
            error = %error,
            "managed egress background reconciliation was incomplete"
        ),
    }

    match commands::reconcile_interrupted_scan_resources(state, None) {
        Ok(cleanup) if cleanup.reconciled > 0 || cleanup.pending > 0 => tracing::warn!(
            reconciled = cleanup.reconciled,
            pending = cleanup.pending,
            details = ?cleanup.details,
            "scanner runtime resources were reconciled after the desktop shell opened"
        ),
        Ok(_) => {}
        Err(error) => tracing::error!(
            error = %error,
            "scanner runtime background reconciliation was incomplete"
        ),
    }
}

#[cfg(feature = "desktop")]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ai_security_scanner=info".into()),
        )
        .with_target(false)
        .try_init()
        .ok();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let app_data = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&app_data)?;
            let process_lease = DataDirectoryExclusiveLease::acquire(&app_data)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let managed_bundle = app.path().resource_dir()?.join("managed-runtime");
            let managed_manifest = managed_bundle.join("manifest.json");
            let managed_runtime = if managed_manifest.exists() {
                match ManagedRuntimeManager::open(
                    &app_data,
                    &managed_bundle,
                    &managed_manifest,
                ) {
                    Ok(manager) => Some(manager),
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            "packaged managed-local runtime failed release verification"
                        );
                        None
                    }
                }
            } else {
                tracing::warn!(
                    path = %managed_manifest.display(),
                    "managed-local runtime bundle is absent; compatibility providers remain available"
                );
                None
            };
            let storage = Storage::open(app_data.join("casework.db"))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let engines = EngineRegistry::load_builtin().unwrap_or_else(|error| {
                tracing::error!(
                    error = %error,
                    "built-in engine catalog is unavailable; catalog-backed checks remain unavailable"
                );
                EngineRegistry::empty()
            });
            let adapters = adapters::builtin_adapter_registry().unwrap_or_else(|error| {
                tracing::error!(
                    error = %error,
                    "built-in adapter registry is unavailable; catalog-backed checks remain unavailable"
                );
                adapter::AdapterRegistry::default()
            });
            let artifact_store = ArtifactStore::open(app_data.join("artifacts"))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let artifact_root = artifact_store.root().to_path_buf();
            let mut state = AppState::new(
                storage,
                engines,
                adapters,
                artifact_root,
                app_data.join("integrity-signing-key"),
            )
            .with_process_lease(process_lease);
            if let Some(manager) = managed_runtime {
                state = state.with_managed_runtime(manager);
            }
            // Prepare and harden the local export identity early, but never
            // turn a damaged optional export identity into a scanner startup
            // gate. Signed bundle creation remains fail-closed and reports the
            // exact identity recovery action when the user chooses to export.
            match state.case_service().ensure_export_signing_identity() {
                Ok(signing_identity) => tracing::info!(
                    key_id = %signing_identity.key_id,
                    continuity_event = ?signing_identity.continuity_event,
                    "local export-integrity identity is ready"
                ),
                Err(error) => tracing::error!(
                    error = %error,
                    "local export-integrity identity needs attention; scanning remains available"
                ),
            }
            match state.case_service().recover_interrupted_scans() {
                Ok(recovered) if recovered > 0 => tracing::warn!(
                    recovered_runs = recovered,
                    "persisted scans were paused after a desktop process restart"
                ),
                Ok(_) => {}
                Err(error) => tracing::error!(
                    error = %error,
                    "persisted scan restart classification was incomplete; the shell remains available"
                ),
            }
            match state.case_service().reconcile_terminal_verifications() {
                Ok(reconciled) if reconciled > 0 => tracing::info!(
                    reconciled_verifications = reconciled,
                    "terminal verification comparisons were reconciled after desktop startup"
                ),
                Ok(_) => {}
                Err(error) => tracing::error!(
                    error = %error,
                    "terminal verification reconciliation was incomplete; the shell remains available"
                ),
            }
            app.manage(state);
            let startup_app = app.handle().clone();
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let state = startup_app.state::<AppState>();
                reconcile_live_startup_resources(&state);
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_snapshot,
            commands::detect_local_private_subnets,
            commands::get_scan_readiness,
            commands::setup_managed_runtime,
            commands::get_managed_runtime_setup_status,
            commands::cancel_managed_runtime_setup,
            commands::create_case,
            commands::select_case,
            commands::archive_case,
            commands::delete_case,
            commands::delete_case_artifacts,
            commands::connect_source_snapshot,
            commands::begin_provider_authorization,
            commands::poll_provider_authorization,
            commands::cancel_provider_authorization,
            commands::provider_authorization_status,
            commands::revoke_provider_authorization,
            commands::plan_provider_bootstrap,
            commands::execute_provider_bootstrap,
            commands::cleanup_provider_bootstrap,
            commands::list_provider_bootstrap_cleanup,
            commands::attach_workspace_snapshot,
            commands::seed_demo_case,
            commands::list_engine_manifests,
            commands::start_discovery,
            commands::cancel_discovery,
            commands::approve_scope,
            commands::update_finding_workflow,
            commands::group_findings,
            commands::ungroup_findings,
            commands::start_scan,
            commands::start_localhost_quick_scan,
            commands::pause_scan,
            commands::resume_scan,
            commands::cancel_scan,
            commands::start_rescan,
            commands::preview_export,
            commands::export_case,
            commands::verify_case_export,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ai-security-scanner");
}

#[cfg(test)]
mod desktop_nonblocking_source_invariants {
    #[test]
    fn desktop_manages_state_before_scheduling_live_startup_reconciliation() {
        let source = include_str!("lib.rs");
        let setup_start = source.find(".setup(|app| {").expect("desktop setup");
        let manage = source[setup_start..]
            .find("app.manage(state);")
            .map(|offset| setup_start + offset)
            .expect("managed state boundary");
        let schedule = source[manage..]
            .find("let startup_app = app.handle().clone();")
            .map(|offset| manage + offset)
            .expect("background startup scheduling");
        let background_call = source[schedule..]
            .find("reconcile_live_startup_resources(&state);")
            .map(|offset| schedule + offset)
            .expect("live startup reconciler");
        assert!(manage < schedule && schedule < background_call);

        let synchronous_setup = &source[setup_start..manage];
        assert!(!synchronous_setup.contains("state.reconcile_managed_networks()"));
        assert!(
            !synchronous_setup
                .contains("commands::reconcile_interrupted_scan_resources(&state, None)")
        );

        let helper_start = source
            .find("fn reconcile_live_startup_resources(state: &AppState)")
            .expect("background helper");
        let helper_end = source[helper_start..]
            .find("\n#[cfg(feature = \"desktop\")]\n#[cfg_attr")
            .map(|offset| helper_start + offset)
            .expect("background helper end");
        let helper = &source[helper_start..helper_end];
        assert!(!helper.lines().any(|line| line.trim_end().ends_with("?;")));
        assert!(!helper.contains(".map_err("));
    }

    #[test]
    fn snapshot_and_resume_paths_do_not_wait_or_plan_through_an_active_terminal_claim() {
        let source = include_str!("commands.rs");
        let snapshot_start = source
            .find("pub async fn get_app_snapshot(")
            .expect("snapshot command");
        let snapshot_end = source[snapshot_start..]
            .find("\n#[tauri::command]\npub fn get_scan_readiness")
            .map(|offset| snapshot_start + offset)
            .expect("snapshot command end");
        let snapshot = &source[snapshot_start..snapshot_end];
        assert!(snapshot.contains("schedule_retained_terminal_reconciliation(&app);"));
        assert!(!snapshot.contains("reconcile_retained_terminal_jobs(&state)"));

        let schedule_start = source
            .find("fn schedule_retained_terminal_reconciliation(app: &AppHandle)")
            .expect("snapshot reconciliation scheduler");
        let schedule_end = source[schedule_start..]
            .find("\nfn load_readable_desktop_cases")
            .map(|offset| schedule_start + offset)
            .expect("snapshot scheduler end");
        let schedule = &source[schedule_start..schedule_end];
        assert!(schedule.contains("tauri::async_runtime::spawn_blocking"));
        assert!(schedule.contains("reconcile_retained_terminal_jobs(&state)"));

        let resume_start = source
            .find("pub async fn resume_scan(")
            .expect("resume command");
        let resume_end = source[resume_start..]
            .find("\n#[tauri::command]\npub fn cancel_scan")
            .map(|offset| resume_start + offset)
            .expect("resume command end");
        let resume = &source[resume_start..resume_end];
        let detached_terminal = resume
            .find("schedule_exact_terminal_reconciliation(&app, key.clone(), snapshot);")
            .expect("detached terminal reconciliation");
        let admission = resume
            .find("state.jobs.coordinate_admission")
            .expect("resume admission boundary");
        let retry_plan = resume
            .find("persist_resume_before_execution_preflight")
            .expect("retry planning boundary");
        assert!(detached_terminal < admission && admission < retry_plan);
        assert!(resume[detached_terminal..admission].contains("return Ok(case);"));
        assert!(!resume.contains("reconcile_terminal_job("));
        assert!(
            resume[admission..retry_plan]
                .contains("schedule_exact_terminal_reconciliation(&app, key.clone(), snapshot);")
        );
    }

    #[test]
    fn cached_runtime_health_is_advisory_and_never_blocks_scan_readiness() {
        let source = include_str!("commands.rs");
        let readiness_start = source
            .find("pub fn get_scan_readiness(")
            .expect("scan readiness command");
        let readiness_end = source[readiness_start..]
            .find("\n#[tauri::command]\npub fn create_case")
            .map(|offset| readiness_start + offset)
            .expect("scan readiness command end");
        let readiness = &source[readiness_start..readiness_end];

        assert!(readiness.contains("request_runtime_health_refresh()"));
        assert!(!readiness.contains("runtime_health().available"));
        assert!(!readiness.contains("DesktopExecutionBlocker::RuntimeUnavailable"));
    }

    #[test]
    fn cancel_preserves_terminal_truth_and_never_waits_for_no_worker_cleanup() {
        let source = include_str!("commands.rs");
        let cancel_start = source.find("pub fn cancel_scan(").expect("cancel command");
        let cancel_end = source[cancel_start..]
            .find("\n#[tauri::command]\npub async fn start_rescan")
            .map(|offset| cancel_start + offset)
            .expect("cancel command end");
        let cancel = &source[cancel_start..cancel_end];

        let terminal_branch = cancel
            .find("Some(snapshot) if snapshot.is_terminal()")
            .expect("retained terminal branch");
        let live_cancel = cancel
            .find("signal_live_cancel_or_preserve_terminal(&app, &state, &key)")
            .expect("live-worker cancel helper");
        let local_cancel = cancel
            .find(".cancel_scan(&case_id, &run_id)")
            .expect("no-worker durable cancellation");
        assert!(terminal_branch < live_cancel && live_cancel < local_cancel);
        assert!(
            cancel[terminal_branch..live_cancel]
                .contains("schedule_exact_terminal_reconciliation(&app, key, snapshot);")
        );
        assert!(cancel[terminal_branch..live_cancel].contains("return Ok(case);"));

        let live_helper_start = source
            .find("fn signal_live_cancel_or_preserve_terminal(")
            .expect("live cancellation helper");
        let live_helper_end = source[live_helper_start..]
            .find("\n#[tauri::command]\npub fn pause_scan")
            .map(|offset| live_helper_start + offset)
            .expect("live cancellation helper end");
        let live_helper = &source[live_helper_start..live_helper_end];
        assert!(live_helper.contains("state.jobs.cancel(key)"));
        let terminal_edge = live_helper
            .find("Err(JobManagerError::LiveJobNotFound(_))")
            .expect("terminal-edge race branch");
        assert!(
            live_helper[terminal_edge..]
                .contains("schedule_exact_terminal_reconciliation(app, key.clone(), snapshot);")
        );
        assert!(!live_helper.contains("case_service().cancel_scan"));

        let background_cleanup = cancel
            .find("schedule_exact_runtime_cleanup_reconciliation(&app, case_id, run_id);")
            .expect("detached exact cleanup scheduling");
        assert!(cancel[background_cleanup..].contains("Ok(case)"));
        assert!(!cancel.contains("reconcile_interrupted_scan_resources(&state"));
        assert!(!cancel.contains("spawn_blocking"));

        let admission = cancel
            .find("state.jobs.coordinate_admission")
            .expect("no-worker admission boundary");
        let second_snapshot = cancel[admission..]
            .find("state.jobs.snapshot(&key)")
            .map(|offset| admission + offset)
            .expect("exact snapshot under admission");
        assert!(admission < second_snapshot && second_snapshot < local_cancel);
        assert!(
            cancel[second_snapshot..local_cancel]
                .contains("run_is_exact_localhost_quick_scan(run)")
        );

        assert!(live_helper.contains("cancel_with_durable_transition"));
        assert!(live_helper.contains("record_localhost_cancel_transition"));
        assert!(live_helper.contains("DurableCancellationOutcome::TerminalWon"));

        let scheduler_start = source
            .find("fn schedule_exact_runtime_cleanup_reconciliation(")
            .expect("exact cleanup scheduler");
        let scheduler_end = source[scheduler_start..]
            .find("\nfn load_readable_desktop_cases")
            .map(|offset| scheduler_start + offset)
            .expect("exact cleanup scheduler end");
        let scheduler = &source[scheduler_start..scheduler_end];
        assert!(scheduler.contains("tauri::async_runtime::spawn_blocking"));
        assert!(scheduler.contains("reconcile_interrupted_scan_resources("));
    }

    #[test]
    fn localhost_first_value_path_has_one_managed_detached_lifecycle() {
        let commands = include_str!("commands.rs");
        let start = commands
            .find("pub async fn start_localhost_quick_scan(")
            .expect("localhost start command");
        let end = commands[start..]
            .find("\nfn requested_or_latest_run(")
            .map(|offset| start + offset)
            .expect("localhost start command end");
        let start = &commands[start..end];
        assert!(start.contains("state.jobs.coordinate_admission"));
        assert!(start.contains("live_localhost_quick_scan_for_port("));
        assert!(start.contains("state.jobs.start_job("));
        assert!(start.contains("execute_managed_localhost_quick_scan("));
        assert!(start.contains("Ok(queued_case)"));
        assert!(!start.contains(".await"));
        assert!(!start.contains("spawn_blocking"));

        let retained = start
            .find(".terminal_snapshots()")
            .expect("retained terminal reconciliation");
        let new_case = start
            .find("prepare_localhost_quick_scan(")
            .expect("new exact task preparation");
        assert!(
            retained < new_case,
            "old terminals cannot replace the new action"
        );

        let localhost = include_str!("localhost_quick_scan.rs");
        assert!(!localhost.contains("execute_prepared_localhost_quick_scan"));
        assert!(localhost.contains("pub fn execute_managed_localhost_quick_scan("));
        assert!(localhost.contains("cancelled_without_observation"));
    }
}
