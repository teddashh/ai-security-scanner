pub mod adapter;
pub mod adapters;
pub mod artifact_store;
pub mod bootstrap;
#[cfg(feature = "desktop")]
mod commands;
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
pub mod orchestrator;
pub mod registry;
pub mod runtime;
#[cfg(feature = "desktop")]
mod state;
pub mod storage;

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
        .setup(|app| {
            let app_data = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&app_data)?;
            let storage = Storage::open(app_data.join("casework.db"))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let engines = EngineRegistry::load_builtin()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            app.manage(AppState { storage, engines });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_snapshot,
            commands::create_case,
            commands::select_case,
            commands::seed_demo_case,
            commands::list_engine_manifests,
            commands::start_discovery,
            commands::approve_scope,
            commands::start_scan,
            commands::pause_scan,
            commands::resume_scan,
            commands::cancel_scan,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ai-security-scanner");
}
