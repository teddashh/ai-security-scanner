pub mod adapter;
pub mod adapters;
pub mod artifact_store;
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
pub mod exporters;
pub mod external_scope;
pub mod job_manager;
pub mod managed_network;
pub mod managed_runtime;
pub mod orchestrator;
pub mod prioritization;
pub mod process_lease;
pub mod registry;
pub mod runtime;
pub mod source_authorization;
#[cfg(feature = "desktop")]
mod state;
pub mod storage;
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
            let engines = EngineRegistry::load_builtin()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let adapters = adapters::builtin_adapter_registry()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
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
            match state.reconcile_managed_networks() {
                Ok(network_recovery)
                    if network_recovery.reconciled > 0 || network_recovery.incomplete > 0 =>
                {
                    tracing::warn!(
                        reconciled = network_recovery.reconciled,
                        incomplete = network_recovery.incomplete,
                        details = ?network_recovery.details,
                        "managed egress resources were reconciled after desktop startup"
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    // Startup remains available, but every retained resource stays
                    // fail-closed and its gateway has an independent expiry deadline.
                    tracing::error!(
                        error = %error,
                        "managed egress startup reconciliation was incomplete"
                    );
                }
            }
            let recovered = state
                .case_service()
                .recover_interrupted_scans()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if recovered > 0 {
                tracing::warn!(
                    recovered_runs = recovered,
                    "persisted scans were paused after a desktop process restart"
                );
            }
            let interrupted_cleanup = commands::reconcile_interrupted_scan_resources(&state, None)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if interrupted_cleanup.reconciled > 0 || interrupted_cleanup.pending > 0 {
                tracing::warn!(
                    reconciled = interrupted_cleanup.reconciled,
                    pending = interrupted_cleanup.pending,
                    details = ?interrupted_cleanup.details,
                    "interrupted scanner resources were reconciled after desktop startup"
                );
            }
            let reconciled_verifications = state
                .case_service()
                .reconcile_terminal_verifications()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if reconciled_verifications > 0 {
                tracing::info!(
                    reconciled_verifications,
                    "terminal verification comparisons were reconciled after desktop startup"
                );
            }
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_snapshot,
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
