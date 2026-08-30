//! Durable, product-owned first-value scan for one TCP service on this
//! computer.
//!
//! The user starts this check with one explicit action. The exact loopback
//! target, permission, task contract, and queued state are committed before
//! the operating system is asked to make a connection. The task is independent
//! of WSL, a container runtime, the engine catalog, and result adapters.

use crate::coverage::refresh_coverage_ledger;
use crate::domain::{
    AiGeneratedArtifactAnswer, AiSystemApplicabilityAnswer, AssessmentCase, AssessmentIntent,
    Asset, AssetIdentifier, AssetKind, BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE,
    BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE, BUILT_IN_LOCALHOST_TCP_ENGINE_ID, CaseStatus,
    DataClass, DataSource, EngineManifest, EngineRun, EngineRunStatus, EngineTaskKind,
    LocalhostTcpObservation, LocalhostTcpOutcome, OrganizationProfile, ScanPermission, ScanRun,
    ScopeGrant, SourceConnectionStatus, SourceKind, new_id,
};
use crate::error::{AppError, AppResult};
use crate::local_tcp_probe::{
    LocalTcpConnector, LocalTcpProbeFailure, LocalTcpProbeOutcome, probe_localhost_tcp_port_with,
};
use crate::storage::Storage;
use chrono::Utc;
use serde_json::Value;
use std::collections::BTreeMap;

const LOCALHOST_PERSISTENCE_ATTEMPTS: usize = 3;

pub const LOCALHOST_TCP_ENGINE_ID: &str = BUILT_IN_LOCALHOST_TCP_ENGINE_ID;
pub const LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE: &str =
    BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE;
pub const LOCALHOST_TCP_AUTHORIZATION_REFERENCE: &str =
    BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLocalhostQuickScan {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct PreparedLocalhostQuickScanResult {
    pub case: AssessmentCase,
    pub prepared: PreparedLocalhostQuickScan,
}

/// Create and select a complete minimal case, including its exact task and
/// permission snapshot. This function never contacts the target.
pub fn prepare_localhost_quick_scan(
    storage: &Storage,
    manifests: &[EngineManifest],
    port: u16,
) -> AppResult<PreparedLocalhostQuickScanResult> {
    if port == 0 {
        return Err(AppError::InvalidRequest(
            "local TCP port must be between 1 and 65535".into(),
        ));
    }

    let now = Utc::now();
    let endpoint = format!("127.0.0.1:{port}");
    let source_id = new_id();
    let asset_id = new_id();
    let grant_id = new_id();
    let scan_run_id = new_id();
    let engine_run_id = new_id();

    let mut case = AssessmentCase::new(
        format!("This computer · {endpoint}"),
        OrganizationProfile {
            organization_name: "This computer".into(),
            employee_range: "Not provided".into(),
            data_classes: vec![DataClass::General],
            notes: None,
        },
    );
    case.assessment_intent = Some(AssessmentIntent::InternalItEnvironment);
    case.requested_activities = vec![crate::domain::AssessmentActivity::LowImpactExternalChecks];
    case.status = CaseStatus::Scanning;
    case.knowledge_cutoff = Some(now);

    case.data_sources.push(DataSource {
        id: source_id.clone(),
        kind: SourceKind::UserDeclared,
        label: "This computer".into(),
        status: SourceConnectionStatus::Connected,
        connected_at: Some(now),
        last_discovered_at: Some(now),
        read_only: true,
        metadata: BTreeMap::from([(
            "scan_boundary".into(),
            Value::String("one product-owned IPv4 loopback TCP connection attempt".into()),
        )]),
    });
    case.assets.push(Asset {
        id: asset_id.clone(),
        kind: AssetKind::WebService,
        name: endpoint.clone(),
        provider: None,
        region: None,
        identifiers: vec![AssetIdentifier {
            namespace: LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE.into(),
            value: endpoint,
        }],
        discovered_from: vec![source_id],
        candidate: false,
        owner_confirmed: true,
        internet_exposed: Some(false),
        contains_sensitive_data: Some(false),
        metadata: BTreeMap::from([
            (
                "localhost_address".into(),
                Value::String("127.0.0.1".into()),
            ),
            ("tcp_port".into(), Value::from(port)),
        ]),
    });

    let grant = ScopeGrant {
        id: grant_id.clone(),
        asset_id: asset_id.clone(),
        permission: ScanPermission::LowImpactExternalConnection,
        confirmed_by: "Local user".into(),
        confirmed_at: now,
        expires_at: None,
        authorization_reference: Some(LOCALHOST_TCP_AUTHORIZATION_REFERENCE.into()),
        notes: Some(
            "The Start action authorizes one payload-free TCP connection to this exact loopback port."
                .into(),
        ),
        external_scope: None,
    };
    case.scope_grants.push(grant.clone());

    let engine_run = EngineRun {
        id: engine_run_id.clone(),
        scan_run_id: scan_run_id.clone(),
        engine_id: LOCALHOST_TCP_ENGINE_ID.into(),
        task_kind: EngineTaskKind::built_in_localhost_tcp(port),
        localhost_tcp_observation: None,
        asset_ids: vec![asset_id],
        status: EngineRunStatus::Queued,
        progress_percent: 0,
        phase: "queued".into(),
        started_at: None,
        finished_at: None,
        resume_token: None,
        engine_version: None,
        image_digest: None,
        rule_version: None,
        adapter_version: "built-in".into(),
        manifest_schema_version: None,
        source_revision: None,
        repository_url: None,
        distribution_mode: None,
        image_repository: None,
        command_sha256: None,
        execution_timeout_seconds: Some(3),
        knowledge_input: None,
        scope_contract_sha256: None,
        mapping_version: None,
        mapping_provenance: None,
        fingerprint_schema_version: None,
        runtime_provider: None,
        runtime_version: None,
        runtime_security_options: None,
        exit_code: None,
        cleanup_removed: None,
        cleanup_detail: None,
        warnings: Vec::new(),
        raw_artifact_ids: Vec::new(),
        error_code: None,
        error_message: None,
    };
    case.scan_runs.push(ScanRun {
        id: scan_run_id.clone(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: now,
        completed_at: None,
        request_outcome: None,
        knowledge_cutoff: now,
        ai_system_applicable: false,
        ai_system_applicability: AiSystemApplicabilityAnswer::NotApplicable,
        ai_generated_artifact: AiGeneratedArtifactAnswer::No,
        verification_baseline_run_id: None,
        scope_grant_ids: vec![grant_id],
        scope_grant_snapshots: vec![grant],
        engine_runs: vec![engine_run],
    });

    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_queued")?;
    // Selection is navigation convenience, not part of the durable scan
    // contract. A settings-row failure must not orphan or suppress work that
    // is already safely queued.
    if let Err(error) = storage.set_selected_case(Some(&case.id)) {
        tracing::warn!(
            error = %error,
            case_id = %case.id,
            "localhost check was queued but could not become the selected case"
        );
    }

    Ok(PreparedLocalhostQuickScanResult {
        prepared: PreparedLocalhostQuickScan {
            case_id: case.id.clone(),
            scan_run_id,
            engine_run_id,
            port,
        },
        case,
    })
}

/// Execute one previously persisted task. The running state is committed
/// before the injected connector is called, which makes the persist-before-
/// contact ordering directly testable.
pub fn execute_prepared_localhost_quick_scan(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    connector: &dyn LocalTcpConnector,
) -> AppResult<AssessmentCase> {
    if let Err(error) =
        retry_localhost_persistence(|| persist_localhost_running_once(storage, manifests, prepared))
    {
        tracing::error!(
            error = %error,
            case_id = %prepared.case_id,
            scan_run_id = %prepared.scan_run_id,
            "localhost check could not persist its running state"
        );
        return reconcile_interrupted_localhost_quick_scan(storage, manifests, prepared).map_err(
            |reconcile_error| {
                tracing::error!(
                    error = %reconcile_error,
                    case_id = %prepared.case_id,
                    scan_run_id = %prepared.scan_run_id,
                    "localhost running-state failure could not be reconciled immediately"
                );
                AppError::Storage(
                    "The localhost check could not save its status. It will be reconciled when the app starts again."
                        .into(),
                )
            },
        );
    }

    let result = probe_localhost_tcp_port_with(connector, prepared.port);
    match retry_localhost_persistence(|| {
        complete_localhost_quick_scan_once(storage, manifests, prepared, result)
    }) {
        Ok(case) => Ok(case),
        Err(error) => {
            tracing::error!(
                error = %error,
                case_id = %prepared.case_id,
                scan_run_id = %prepared.scan_run_id,
                "localhost result could not be persisted after the target contact"
            );
            reconcile_interrupted_localhost_quick_scan(storage, manifests, prepared).map_err(
                |reconcile_error| {
                    tracing::error!(
                        error = %reconcile_error,
                        case_id = %prepared.case_id,
                        scan_run_id = %prepared.scan_run_id,
                        "localhost result persistence failure could not be reconciled immediately"
                    );
                    AppError::Storage(
                        "The localhost check ran, but its result could not be saved. It will be reconciled when the app starts again."
                            .into(),
                    )
                },
            )
        }
    }
}

fn persist_localhost_running_once(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    let mut case = storage.get_case(&prepared.case_id)?;
    let now = Utc::now();
    let already_running;
    {
        let engine_run = exact_prepared_task_mut(&mut case, prepared)?;
        already_running =
            engine_run.status == EngineRunStatus::Running && engine_run.phase == "connecting";
        if !already_running
            && (engine_run.status != EngineRunStatus::Queued || engine_run.phase != "queued")
        {
            return Err(AppError::Conflict(
                "the localhost check is no longer queued".into(),
            ));
        }
        if !already_running {
            engine_run.status = EngineRunStatus::Running;
            engine_run.progress_percent = 10;
            engine_run.phase = "connecting".into();
            engine_run.started_at = Some(now);
        }
    }
    if already_running {
        return Ok(case);
    }
    case.touch();
    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_running")?;
    Ok(case)
}

fn complete_localhost_quick_scan_once(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    result: Result<LocalTcpProbeOutcome, LocalTcpProbeFailure>,
) -> AppResult<AssessmentCase> {
    let mut case = storage.get_case(&prepared.case_id)?;
    let now = Utc::now();
    let mut terminal_status = None;
    let already_terminal;
    {
        let engine_run = exact_prepared_task_mut(&mut case, prepared)?;
        already_terminal = matches!(
            engine_run.status,
            EngineRunStatus::Completed
                | EngineRunStatus::PartiallyCompleted
                | EngineRunStatus::Failed
                | EngineRunStatus::Cancelled
                | EngineRunStatus::NotExecuted
        );
        if !already_terminal
            && (engine_run.status != EngineRunStatus::Running || engine_run.phase != "connecting")
        {
            return Err(AppError::Conflict(
                "the localhost check is no longer running".into(),
            ));
        }
        if !already_terminal {
            engine_run.progress_percent = 100;
            engine_run.finished_at = Some(now);
            match result {
                Ok(LocalTcpProbeOutcome::Reachable) => {
                    engine_run.status = EngineRunStatus::Completed;
                    engine_run.phase = "completed".into();
                    engine_run.error_code = None;
                    engine_run.error_message = None;
                    engine_run.localhost_tcp_observation = Some(LocalhostTcpObservation {
                        outcome: LocalhostTcpOutcome::Reachable,
                        observed_at: now,
                    });
                }
                Ok(LocalTcpProbeOutcome::Closed) => {
                    engine_run.status = EngineRunStatus::Completed;
                    engine_run.phase = "completed".into();
                    engine_run.error_code = None;
                    engine_run.error_message = None;
                    engine_run.localhost_tcp_observation = Some(LocalhostTcpObservation {
                        outcome: LocalhostTcpOutcome::Closed,
                        observed_at: now,
                    });
                }
                Ok(LocalTcpProbeOutcome::TimedOut) => {
                    engine_run.status = EngineRunStatus::PartiallyCompleted;
                    engine_run.phase = "timed_out".into();
                    engine_run.localhost_tcp_observation = Some(LocalhostTcpObservation {
                        outcome: LocalhostTcpOutcome::TimedOut,
                        observed_at: now,
                    });
                    engine_run.error_code = Some("localhost_tcp_timed_out".into());
                    engine_run.error_message = Some(
                        "No answer arrived within three seconds, so the port was not marked open or closed."
                            .into(),
                    );
                }
                Err(failure) => {
                    engine_run.status = EngineRunStatus::Failed;
                    engine_run.phase = "failed".into();
                    engine_run.localhost_tcp_observation = None;
                    engine_run.error_code = Some(failure.code.as_str().into());
                    engine_run.error_message = Some(
                        "The local connection attempt could not finish, so no result was inferred."
                            .into(),
                    );
                }
            }
            terminal_status = Some(engine_run.status.clone());
        }
    }
    if already_terminal {
        return Ok(case);
    }
    let run = case
        .scan_runs
        .iter_mut()
        .find(|run| run.id == prepared.scan_run_id)
        .ok_or_else(|| AppError::Conflict("the localhost scan run disappeared".into()))?;
    run.completed_at = Some(now);
    case.status = if terminal_status.expect("new terminal status was projected")
        == EngineRunStatus::Completed
    {
        CaseStatus::ReadyForHandoff
    } else {
        CaseStatus::NeedsAttention
    };
    case.touch();
    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_finished")?;
    Ok(case)
}

/// Terminalize one exact product-owned localhost task after a worker, process,
/// or persistence interruption. This never repeats target contact. It is safe
/// to call after any error and returns an existing terminal outcome unchanged.
pub fn reconcile_interrupted_localhost_quick_scan(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    retry_localhost_persistence(|| {
        reconcile_interrupted_localhost_quick_scan_once(storage, manifests, prepared)
    })
}

fn reconcile_interrupted_localhost_quick_scan_once(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    let mut case = storage.get_case(&prepared.case_id)?;
    let now = Utc::now();
    let already_terminal;
    {
        let engine_run = exact_prepared_task_mut(&mut case, prepared)?;
        already_terminal = matches!(
            engine_run.status,
            EngineRunStatus::Completed
                | EngineRunStatus::PartiallyCompleted
                | EngineRunStatus::Failed
                | EngineRunStatus::Cancelled
                | EngineRunStatus::NotExecuted
        );
        if !already_terminal
            && !matches!(
                engine_run.status,
                EngineRunStatus::Queued
                    | EngineRunStatus::Preparing
                    | EngineRunStatus::Running
                    | EngineRunStatus::Paused
            )
        {
            return Err(AppError::Conflict(
                "the localhost check cannot be reconciled from its saved state".into(),
            ));
        }
        if !already_terminal {
            engine_run.status = EngineRunStatus::Failed;
            engine_run.progress_percent = 100;
            engine_run.phase = "localhost_probe_interrupted".into();
            engine_run.finished_at = Some(now);
            engine_run.resume_token = None;
            engine_run.localhost_tcp_observation = None;
            engine_run.error_code = Some("localhost_probe_interrupted".into());
            engine_run.error_message = Some(
                "This localhost check stopped before a result was safely saved. No result was inferred; start the check again."
                    .into(),
            );
        }
    }
    if already_terminal {
        return Ok(case);
    }
    let run = case
        .scan_runs
        .iter_mut()
        .find(|run| run.id == prepared.scan_run_id)
        .ok_or_else(|| AppError::Conflict("the localhost scan run disappeared".into()))?;
    run.completed_at = Some(now);
    case.status = CaseStatus::NeedsAttention;
    case.touch();
    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_interrupted")?;
    Ok(case)
}

fn retry_localhost_persistence<T>(mut operation: impl FnMut() -> AppResult<T>) -> AppResult<T> {
    let mut last_retryable = None;
    for attempt in 0..LOCALHOST_PERSISTENCE_ATTEMPTS {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error @ (AppError::Conflict(_) | AppError::Storage(_))) => {
                last_retryable = Some(error);
                if attempt + 1 < LOCALHOST_PERSISTENCE_ATTEMPTS {
                    std::thread::yield_now();
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_retryable.expect("at least one persistence attempt ran"))
}

fn exact_prepared_task_mut<'a>(
    case: &'a mut AssessmentCase,
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<&'a mut EngineRun> {
    let run = case
        .scan_runs
        .iter_mut()
        .find(|run| run.id == prepared.scan_run_id && run.case_id == prepared.case_id)
        .ok_or_else(|| AppError::Conflict("the localhost scan run disappeared".into()))?;
    let engine_run = run
        .engine_runs
        .iter_mut()
        .find(|engine_run| engine_run.id == prepared.engine_run_id)
        .ok_or_else(|| AppError::Conflict("the localhost check disappeared".into()))?;
    if engine_run.engine_id != LOCALHOST_TCP_ENGINE_ID
        || engine_run.task_kind != EngineTaskKind::built_in_localhost_tcp(prepared.port)
        || engine_run.asset_ids.len() != 1
    {
        return Err(AppError::NotAuthorized(
            "the saved localhost check no longer matches its exact loopback contract".into(),
        ));
    }
    Ok(engine_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::compute_coverage_ledger;
    use crate::domain::CoverageStatus;
    use crate::local_tcp_probe::LOCAL_TCP_CONNECT_TIMEOUT;
    use crate::storage::SaveCaseFault;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Mutex;

    fn storage() -> (tempfile::TempDir, Storage) {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        (directory, storage)
    }

    struct PersistedBeforeContactConnector<'a> {
        storage: &'a Storage,
        prepared: &'a PreparedLocalhostQuickScan,
        result: io::Result<()>,
        calls: Mutex<Vec<(SocketAddr, std::time::Duration)>>,
    }

    impl LocalTcpConnector for PersistedBeforeContactConnector<'_> {
        fn connect(&self, endpoint: SocketAddr, timeout: std::time::Duration) -> io::Result<()> {
            let persisted = self
                .storage
                .get_case(&self.prepared.case_id)
                .expect("queued case must already be durable");
            let task = &persisted.scan_runs[0].engine_runs[0];
            assert_eq!(task.status, EngineRunStatus::Running);
            assert_eq!(task.phase, "connecting");
            self.calls.lock().expect("calls").push((endpoint, timeout));
            match &self.result {
                Ok(()) => Ok(()),
                Err(error) => Err(io::Error::new(error.kind(), "test connector result")),
            }
        }
    }

    #[test]
    fn preparation_persists_one_exact_authorized_loopback_task_without_contact() {
        let (_directory, storage) = storage();

        let result = prepare_localhost_quick_scan(&storage, &[], 9_001).expect("prepare");
        let persisted = storage.get_case(&result.case.id).expect("persisted case");

        assert_eq!(persisted.data_sources.len(), 1);
        assert_eq!(persisted.assets.len(), 1);
        assert_eq!(persisted.scope_grants.len(), 1);
        assert_eq!(persisted.scan_runs.len(), 1);
        let asset = &persisted.assets[0];
        assert_eq!(asset.kind, AssetKind::WebService);
        assert_eq!(asset.name, "127.0.0.1:9001");
        assert!(asset.owner_confirmed);
        assert!(!asset.candidate);
        assert_eq!(asset.identifiers.len(), 1);
        assert_eq!(
            asset.identifiers[0].namespace,
            LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE
        );
        assert_eq!(asset.identifiers[0].value, "127.0.0.1:9001");
        let grant = &persisted.scope_grants[0];
        assert_eq!(
            grant.permission,
            ScanPermission::LowImpactExternalConnection
        );
        assert_eq!(
            grant.authorization_reference.as_deref(),
            Some(LOCALHOST_TCP_AUTHORIZATION_REFERENCE)
        );
        let task = &persisted.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Queued);
        assert_eq!(
            task.task_kind,
            EngineTaskKind::built_in_localhost_tcp(9_001)
        );
        assert_eq!(task.asset_ids, vec![asset.id.clone()]);
        assert!(task.localhost_tcp_observation.is_none());
        assert_eq!(
            storage.selected_case_id().expect("selected"),
            Some(persisted.id)
        );
    }

    #[test]
    fn execution_contacts_only_exact_loopback_after_running_state_is_durable() {
        let (_directory, storage) = storage();
        let prepared = prepare_localhost_quick_scan(&storage, &[], 42_001)
            .expect("prepare")
            .prepared;
        let connector = PersistedBeforeContactConnector {
            storage: &storage,
            prepared: &prepared,
            result: Ok(()),
            calls: Mutex::new(Vec::new()),
        };

        let completed = execute_prepared_localhost_quick_scan(&storage, &[], &prepared, &connector)
            .expect("execute");

        assert_eq!(
            connector.calls.into_inner().expect("calls"),
            vec![(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_001)),
                LOCAL_TCP_CONNECT_TIMEOUT,
            )]
        );
        let task = &completed.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Completed);
        assert_eq!(
            task.localhost_tcp_observation
                .as_ref()
                .map(|value| &value.outcome),
            Some(&LocalhostTcpOutcome::Reachable)
        );
        assert!(completed.scan_runs[0].completed_at.is_some());
    }

    #[test]
    fn timeout_is_a_truthful_partial_result_and_refusal_is_a_completed_observation() {
        for (kind, expected_status, expected_outcome) in [
            (
                io::ErrorKind::TimedOut,
                EngineRunStatus::PartiallyCompleted,
                LocalhostTcpOutcome::TimedOut,
            ),
            (
                io::ErrorKind::ConnectionRefused,
                EngineRunStatus::Completed,
                LocalhostTcpOutcome::Closed,
            ),
        ] {
            let (_directory, storage) = storage();
            let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
                .expect("prepare")
                .prepared;
            let connector = PersistedBeforeContactConnector {
                storage: &storage,
                prepared: &prepared,
                result: Err(io::Error::new(kind, "raw platform text")),
                calls: Mutex::new(Vec::new()),
            };

            let completed =
                execute_prepared_localhost_quick_scan(&storage, &[], &prepared, &connector)
                    .expect("execute");
            let task = &completed.scan_runs[0].engine_runs[0];
            assert_eq!(task.status, expected_status);
            assert_eq!(
                task.localhost_tcp_observation
                    .as_ref()
                    .map(|value| &value.outcome),
                Some(&expected_outcome)
            );
        }
    }

    #[test]
    fn terminal_persistence_fault_is_bounded_and_reconciled_without_second_contact() {
        let (_directory, storage) = storage();
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        storage.inject_save_case_faults(
            "scan.localhost_quick_finished",
            LOCALHOST_PERSISTENCE_ATTEMPTS,
            SaveCaseFault::Storage,
        );
        let connector = PersistedBeforeContactConnector {
            storage: &storage,
            prepared: &prepared,
            result: Ok(()),
            calls: Mutex::new(Vec::new()),
        };

        let reconciled =
            execute_prepared_localhost_quick_scan(&storage, &[], &prepared, &connector)
                .expect("same-process reconciliation");

        assert_eq!(connector.calls.lock().expect("calls").len(), 1);
        let task = &reconciled.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Failed);
        assert_eq!(task.phase, "localhost_probe_interrupted");
        assert!(task.localhost_tcp_observation.is_none());
        assert!(reconciled.scan_runs[0].completed_at.is_some());
        let persisted = storage
            .get_case(&prepared.case_id)
            .expect("persisted failure");
        assert_eq!(
            persisted.scan_runs[0].engine_runs[0].phase,
            "localhost_probe_interrupted"
        );
        assert_eq!(
            reconcile_interrupted_localhost_quick_scan(&storage, &[], &prepared)
                .expect("idempotent reconciliation")
                .storage_revision,
            persisted.storage_revision
        );
    }

    #[test]
    fn running_persistence_fault_terminalizes_without_target_contact() {
        let (_directory, storage) = storage();
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        storage.inject_save_case_faults(
            "scan.localhost_quick_running",
            LOCALHOST_PERSISTENCE_ATTEMPTS,
            SaveCaseFault::Conflict,
        );
        let connector = PersistedBeforeContactConnector {
            storage: &storage,
            prepared: &prepared,
            result: Ok(()),
            calls: Mutex::new(Vec::new()),
        };

        let reconciled =
            execute_prepared_localhost_quick_scan(&storage, &[], &prepared, &connector)
                .expect("same-process reconciliation");

        assert!(connector.calls.lock().expect("calls").is_empty());
        let task = &reconciled.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Failed);
        assert_eq!(task.phase, "localhost_probe_interrupted");
        assert!(task.localhost_tcp_observation.is_none());
    }

    #[test]
    fn invalid_port_creates_no_case_and_contacts_nothing() {
        let (_directory, storage) = storage();

        let error = prepare_localhost_quick_scan(&storage, &[], 0).unwrap_err();

        assert!(matches!(error, AppError::InvalidRequest(_)));
        assert!(storage.list_cases().expect("cases").is_empty());
    }

    fn asset_coverage(case: &AssessmentCase) -> CoverageStatus {
        let asset_id = &case.assets[0].id;
        compute_coverage_ledger(case, &[], Utc::now())
            .into_iter()
            .find(|entry| entry.asset_id.as_ref() == Some(asset_id))
            .expect("asset coverage")
            .status
    }

    #[test]
    fn green_coverage_requires_the_complete_exact_target_and_permission_binding() {
        let (_directory, storage) = storage();
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        let connector = PersistedBeforeContactConnector {
            storage: &storage,
            prepared: &prepared,
            result: Ok(()),
            calls: Mutex::new(Vec::new()),
        };
        let completed = execute_prepared_localhost_quick_scan(&storage, &[], &prepared, &connector)
            .expect("execute");
        assert_eq!(
            asset_coverage(&completed),
            CoverageStatus::DiscoveredAuthorizedScanned
        );

        let mut changed_target = completed.clone();
        changed_target.assets[0].identifiers[0].value = "127.0.0.1:9002".into();
        let mut expanded_assets = completed.clone();
        expanded_assets.scan_runs[0].engine_runs[0]
            .asset_ids
            .push("another-asset".into());
        let mut changed_permission = completed.clone();
        changed_permission.scan_runs[0].scope_grant_snapshots[0].authorization_reference =
            Some("different action".into());
        let mut expanded_run = completed.clone();
        let duplicate_task = expanded_run.scan_runs[0].engine_runs[0].clone();
        expanded_run.scan_runs[0].engine_runs.push(duplicate_task);
        let mut impossible_observation = completed.clone();
        impossible_observation.scan_runs[0].engine_runs[0]
            .localhost_tcp_observation
            .as_mut()
            .expect("observation")
            .observed_at = completed.scan_runs[0].created_at - chrono::Duration::seconds(1);

        for changed in [
            changed_target,
            expanded_assets,
            changed_permission,
            expanded_run,
            impossible_observation,
        ] {
            assert_eq!(
                asset_coverage(&changed),
                CoverageStatus::AuthorizedScanIncomplete
            );
        }
    }
}
