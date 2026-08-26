//! Application-level case lifecycle service shared by the desktop and CLI.
//!
//! This module deliberately stops at a typed execution plan. It never starts a
//! scanner process and never handles credentials. Container execution belongs
//! to `orchestrator`; the resulting durable report is reconciled here.

use crate::adapter::AdapterRegistry;
use crate::adapters::{FINGERPRINT_SCHEMA_VERSION, control_mapping_version};
use crate::bootstrap::executor::list_bootstrap_cleanup_obligations;
use crate::connectors::{
    LIVE_PROVIDER_ARTIFACT_SET_SCHEMA, LiveProviderArtifactSet, MAX_LIVE_PROVIDER_PAGES,
    SNAPSHOT_ARTIFACT_METADATA_KEY, SNAPSHOT_REFERENCE_SCHEMA, SnapshotArtifactReference,
};
use crate::container_runtime::{CleanupOutcome, RuntimePreflight};
use crate::coverage::{NOT_APPLICABLE_REASON_METADATA, refresh_coverage_ledger};
use crate::diff::compare_case_runs;
use crate::discovery::{
    DiscoveredAsset, DiscoveryBatch, ReconciliationReport, reconcile_discovery,
};
use crate::domain::{
    ArtifactCleanupObligation, AssessmentCase, AssessmentIntent, Asset, AssetIdentifier, AssetKind,
    CaseExport, CaseStatus, CaseSummary, CoverageStatus, CreateCaseRequest, DataSource,
    DeclaredAssetInput, DeclaredAssetKind, DeclaredWebProtocol, DeclaredWebServiceInput,
    DistributionMode, EngineKnowledgeInput, EngineManifest, EngineRun, EngineRunStatus, Finding,
    FindingDiffStatus, FindingGroup, FindingGroupAction, FindingGroupEvent, FindingObservation,
    FindingStatus, FindingWorkflowEvent, Id, ManifestStatus, OrganizationProfile, RawArtifact,
    ScanPermission, ScanRun, ScopeGrant, SourceConnectionStatus, SourceKind,
    VerificationComparison, new_id, valid_azure_subscription_id, valid_gcp_project_id,
};
use crate::error::{AppError, AppResult};
use crate::export::{
    BundleVerification, ExportOptions, INTEGRITY_ONLY_NOTICE, case_for_export, create_case_bundle,
    verify_case_bundle_against,
};
use crate::exporters::{export_ocsf_finding_events_bytes, export_oscal_assessment_results_bytes};
use crate::external_scope::{
    CanonicalTarget, ExternalActivity, ExternalScopeGrant, ExternalScopeRequest,
};
use crate::orchestrator::{ExecutionCheckpoint, ExecutionReport, ExecutionStage};
use crate::registry::EngineRegistry;
use crate::source_authorization::PROVIDER_RESOURCE_SCOPE_METADATA_KEY;
use crate::storage::Storage;
use crate::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA,
    WorkspaceSnapshot, WorkspaceSnapshotReference,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_DECLARED_ASSETS: usize = 200;
const MAX_FINDINGS_PER_GROUP: usize = 100;
const LEGACY_DELETION_OBLIGATION_DIRECTORY: &str = ".case-deletion-obligations";
const MAX_LEGACY_DELETION_OBLIGATION_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_DELETION_OBLIGATIONS: usize = 10_000;
const UNSIGNED_SCHEMA_NOTICE: &str = "This schema export is unsigned. The stored SHA-256 digest can detect later byte changes but does not establish correctness, completeness, authorship, audit status, or forensic validity.";

/// Core service dependencies are borrowed so desktop and CLI entry points can
/// own their storage and registries according to their own process lifecycle.
pub struct CaseService<'a> {
    storage: &'a Storage,
    engines: &'a EngineRegistry,
    adapters: &'a AdapterRegistry,
    artifact_root: PathBuf,
    signing_key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMutation {
    /// Omit to add a new source; provide an existing ID to update it.
    pub id: Option<Id>,
    pub kind: SourceKind,
    pub label: String,
    pub status: SourceConnectionStatus,
    pub read_only: bool,
    /// Non-secret descriptive coordinates only. Supplying this map replaces
    /// the prior metadata map, which makes stale values removable.
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct LiveProviderDiscoveryOutcome {
    pub status: SourceConnectionStatus,
    pub code: String,
    pub message: String,
    pub complete: bool,
    pub successful_pages: usize,
    pub record_count: usize,
    pub notices: Vec<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingWorkflowRequest {
    pub finding_id: Id,
    pub status: FindingStatus,
    pub decided_by: String,
    pub reason: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingGroupRequest {
    pub title: String,
    pub finding_ids: Vec<Id>,
    pub rationale: String,
    pub grouped_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingUngroupRequest {
    pub group_id: Id,
    pub removed_by: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeApprovalRequest {
    pub asset_id: Id,
    pub permissions: Vec<ScanPermission>,
    pub confirmed_by: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub authorization_reference: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub external_scope: Option<ExternalScopeRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanPlanRequest {
    /// Empty means every catalog engine applicable to the case's
    /// ownership-confirmed assets and effective scope grants. Unknown
    /// explicitly requested IDs are retained as `not_executed` records.
    #[serde(default)]
    pub engine_ids: Vec<String>,
}

/// A credential-free request that a caller may hand to the container
/// orchestrator. The manifest is resolved and pinned before this is emitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedEngineExecution {
    pub case_id: Id,
    pub scan_run_id: Id,
    pub engine_run_id: Id,
    pub attempt: u32,
    pub manifest: EngineManifest,
    pub assets: Vec<Asset>,
    pub scope_grants: Vec<ScopeGrant>,
    #[serde(default)]
    pub resume_checkpoint: Option<ExecutionCheckpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotExecutedEngine {
    pub engine_id: String,
    pub engine_run_id: Id,
    pub asset_ids: Vec<Id>,
    pub reason_code: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPlan {
    pub scan_run: ScanRun,
    pub executable: Vec<PlannedEngineExecution>,
    pub not_executed: Vec<NotExecutedEngine>,
}

/// Stable, user-facing readiness states for starting a new desktop execution.
/// Planning-only callers may still persist explicit `not_executed` records for
/// audit purposes; a ready state means at least one engine/target execution can
/// be dispatched without widening the current scope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanReadinessState {
    Ready,
    CaseUnavailable,
    ScanInProgress,
    ScopeRequired,
    OwnershipRequired,
    NoCompatibleAuthorizedTargets,
    NoRunnableAuthorizedTargets,
    RuntimeUnavailable,
    ProviderConnectionRequired,
    ProviderCapabilityRequired,
    ProviderReviewRequired,
    ProviderCheckUnavailable,
}

/// Machine-readable reason that the primary start-scan action is blocked.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanReadinessBlocker {
    DemoCase,
    ArchivedCase,
    ScanAlreadyActive,
    NoEffectiveScopeGrants,
    NoOwnershipConfirmedTargets,
    NoCompatibleAuthorizedTargets,
    NoRunnableAuthorizedTargets,
    RuntimeUnavailable,
    ProviderSourceRequired,
    ProviderCapabilityUnavailable,
    ProviderSourceAmbiguous,
    ProviderAuthorizationBindingMismatch,
    ProviderTargetBindingMismatch,
    ProviderPreflightUnavailable,
}

impl ScanReadinessBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DemoCase => "demo_case",
            Self::ArchivedCase => "archived_case",
            Self::ScanAlreadyActive => "scan_already_active",
            Self::NoEffectiveScopeGrants => "no_effective_scope_grants",
            Self::NoOwnershipConfirmedTargets => "no_ownership_confirmed_targets",
            Self::NoCompatibleAuthorizedTargets => "no_compatible_authorized_targets",
            Self::NoRunnableAuthorizedTargets => "no_runnable_authorized_targets",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::ProviderSourceRequired => "provider_source_required",
            Self::ProviderCapabilityUnavailable => "provider_capability_unavailable",
            Self::ProviderSourceAmbiguous => "provider_source_ambiguous",
            Self::ProviderAuthorizationBindingMismatch => "provider_authorization_binding_mismatch",
            Self::ProviderTargetBindingMismatch => "provider_target_binding_mismatch",
            Self::ProviderPreflightUnavailable => "provider_preflight_unavailable",
        }
    }
}

/// Stable destination/action identifiers that a UI can map to its own route.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanReadinessNextStep {
    Cases,
    Coverage,
    Progress,
    ScannerSetup,
    Retry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanReadiness {
    pub case_id: Id,
    pub ready: bool,
    pub state: ScanReadinessState,
    /// Ownership-confirmed, non-candidate assets with at least one effective
    /// grant. Compatibility may still require additional permissions.
    pub authorized_target_count: usize,
    /// Discovered assets that are still candidates, unconfirmed, or have no
    /// effective grant.
    pub pending_target_count: usize,
    /// Catalog engines with at least one compatible authorized asset.
    pub compatible_engine_count: usize,
    /// Compatible engines whose release, adapter, image, and command contract
    /// can be dispatched by the constrained executor.
    pub runnable_engine_count: usize,
    pub blocker_code: Option<ScanReadinessBlocker>,
    pub next_step: Option<ScanReadinessNextStep>,
}

const SCAN_PREFLIGHT_ERROR_PREFIX: &str = "scan_preflight";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanPlanIntent {
    PersistAuditPlan,
    PreviewExecution,
    StartExecution,
}

impl ScanPlanIntent {
    fn is_execution(self) -> bool {
        matches!(self, Self::PreviewExecution | Self::StartExecution)
    }
}

type ExecutionPrePersist<'a> = dyn FnMut(&ScanPlan) -> AppResult<()> + 'a;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescanPlan {
    pub baseline_run_id: Id,
    pub plan: ScanPlan,
}

/// Serializable subset of an orchestrator report suitable for retrying a
/// failed database commit after the process restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableExecutionReport {
    pub checkpoint: ExecutionCheckpoint,
    #[serde(default)]
    pub runtime_preflight: Option<RuntimePreflight>,
    #[serde(default)]
    pub cleanup: Option<CleanupOutcome>,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub raw_artifacts: Vec<RawArtifact>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl From<&ExecutionReport> for DurableExecutionReport {
    fn from(report: &ExecutionReport) -> Self {
        Self {
            checkpoint: report.checkpoint.clone(),
            runtime_preflight: report.runtime_preflight.clone(),
            cleanup: report.cleanup.clone(),
            exit_code: report.exit_code,
            raw_artifacts: report.raw_artifacts.clone(),
            findings: report.findings.clone(),
            warnings: report.warnings.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionApplyResult {
    pub case: AssessmentCase,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone)]
pub struct InterruptedCleanupSuccess {
    pub expected_resume_token: String,
    pub cleanup: CleanupOutcome,
    pub orphan_credentials_removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseExportFormat {
    CaseBundle,
    #[serde(rename = "json", alias = "canonical_json")]
    CanonicalJson,
    #[serde(rename = "ocsf", alias = "ocsf_json")]
    OcsfJson,
    #[serde(rename = "oscal", alias = "oscal_json")]
    OscalJson,
    Html,
}

impl CaseExportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CaseBundle => "case_bundle",
            Self::CanonicalJson => "json",
            Self::OcsfJson => "ocsf",
            Self::OscalJson => "oscal",
            Self::Html => "html",
        }
    }
}

pub type SchemaExportFormat = CaseExportFormat;

/// Exact, side-effect-free disclosure for the backend-selected export. The UI
/// must render these counts instead of reconstructing bundle behavior from its
/// own projection of the case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportPreview {
    pub case_id: Id,
    pub run_id: Id,
    pub format: String,
    pub redaction_profile: String,
    pub data_source_count: usize,
    pub coverage_entry_count: usize,
    pub asset_count: usize,
    pub candidate_asset_count: usize,
    pub canonical_finding_count: usize,
    pub selected_run_finding_count: usize,
    pub evidence_index_count: usize,
    pub selected_run_evidence_count: usize,
    pub scan_run_count: usize,
    pub selected_engine_run_count: usize,
    pub external_scope_grant_count: usize,
    pub incomplete_engine_run_count: usize,
    pub not_executed_engine_run_count: usize,
    pub unknown_source_count: usize,
    pub connected_no_asset_count: usize,
    pub raw_artifact_count: usize,
    pub raw_artifacts_included: usize,
    pub raw_artifacts_omitted: usize,
    pub sensitive_raw_artifacts_omitted: usize,
    pub sensitive_data_warning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredExportVerification {
    pub valid: bool,
    pub export_id: Id,
    pub path: String,
    pub observed_sha256: String,
    pub expected_sha256: String,
    pub bundle: Option<BundleVerification>,
    pub integrity_only_notice: String,
}

/// Deleting the SQLite record never implicitly traverses or removes files.
/// The caller must show and separately confirm this exact case-scoped path.
pub type ArtifactDeletionPlan = ArtifactCleanupObligation;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseDeletionResult {
    pub database_record_deleted: bool,
    pub artifacts: ArtifactDeletionPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDeletionResult {
    pub removed: bool,
    pub exact_path: String,
    pub recoverable: bool,
}

impl<'a> CaseService<'a> {
    pub fn new(
        storage: &'a Storage,
        engines: &'a EngineRegistry,
        adapters: &'a AdapterRegistry,
        artifact_root: impl Into<PathBuf>,
        signing_key_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            storage,
            engines,
            adapters,
            artifact_root: artifact_root.into(),
            signing_key_path: signing_key_path.into(),
        }
    }

    pub fn create_case(&self, request: &CreateCaseRequest) -> AppResult<AssessmentCase> {
        let title = required_text("case title", &request.title, 200)?;
        let organization_name =
            required_text("organization name", &request.organization_name, 200)?;
        let employee_range = required_text("employee range", &request.employee_range, 80)?;
        let notes = optional_text("case notes", request.notes.as_deref(), 8_000)?;
        let now = Utc::now();
        let mut case = AssessmentCase::new(
            title,
            OrganizationProfile {
                organization_name,
                employee_range,
                data_classes: request.data_classes.clone(),
                notes,
            },
        );
        case.assessment_intent = request
            .assessment_intent
            .clone()
            .or_else(|| infer_assessment_intent(request));
        let mut requested_activities = request.requested_activities.clone();
        requested_activities.sort_by_key(enum_key);
        requested_activities.dedup();
        case.requested_activities = requested_activities;
        let mut source_kinds = request.source_kinds.clone();
        source_kinds.sort_by_key(enum_key);
        source_kinds.dedup();
        let mut not_applicable_source_kinds = request.not_applicable_source_kinds.clone();
        not_applicable_source_kinds.sort_by_key(enum_key);
        not_applicable_source_kinds.dedup();
        if source_kinds
            .iter()
            .any(|kind| not_applicable_source_kinds.contains(kind))
            || source_kinds.contains(&SourceKind::UserDeclared)
            || not_applicable_source_kinds.contains(&SourceKind::UserDeclared)
        {
            return Err(AppError::InvalidRequest(
                "questionnaire source areas must be disjoint and cannot predeclare the user-declared source"
                    .into(),
            ));
        }
        for kind in source_kinds {
            case.data_sources.push(DataSource {
                id: new_id(),
                label: planned_source_label(&kind).into(),
                kind,
                status: SourceConnectionStatus::NotConnected,
                connected_at: None,
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            });
        }
        for kind in not_applicable_source_kinds {
            let reason = format!(
                "The user stated during case creation that {} is not used in this assessment context.",
                planned_source_label(&kind)
            );
            case.data_sources.push(DataSource {
                id: new_id(),
                label: planned_source_label(&kind).into(),
                kind,
                status: SourceConnectionStatus::NotApplicable,
                connected_at: None,
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::from([(
                    NOT_APPLICABLE_REASON_METADATA.into(),
                    Value::String(reason),
                )]),
            });
        }

        let declared_assets = normalize_declared_assets(&request.declared_assets)?;
        if !declared_assets.is_empty() {
            let source_id = new_id();
            case.data_sources.push(DataSource {
                id: source_id.clone(),
                kind: SourceKind::UserDeclared,
                label: "Known assets entered in the case questionnaire".into(),
                status: SourceConnectionStatus::Connected,
                connected_at: Some(now),
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::from([(
                    "declaration_boundary".into(),
                    Value::String(
                        "user-supplied coordinates; ownership and scan permission not inferred"
                            .into(),
                    ),
                )]),
            });
            reconcile_discovery(
                &mut case,
                &DiscoveryBatch {
                    source_id,
                    source_kind: SourceKind::UserDeclared,
                    connector_id: "case-questionnaire".into(),
                    connector_version: "1.0.0".into(),
                    observed_at: now,
                    assets: declared_assets,
                    relations: vec![],
                    notices: vec![
                        "Questionnaire entries are candidates only; ownership and scope remain unconfirmed."
                            .into(),
                    ],
                },
            )
            .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            case.status = CaseStatus::ScopeReview;
        }
        refresh_coverage_ledger(&mut case, self.engines.manifests(), now);
        self.storage.save_case(&mut case, "case.created")?;
        self.storage.set_selected_case(Some(&case.id))?;
        Ok(case)
    }

    pub fn list_cases(&self) -> AppResult<Vec<CaseSummary>> {
        self.storage.list_cases()
    }

    pub fn show_case(&self, case_id: &str) -> AppResult<AssessmentCase> {
        self.storage.get_case(case_id)
    }

    pub fn selected_case(&self) -> AppResult<Option<AssessmentCase>> {
        self.storage
            .selected_case_id()?
            .map(|id| self.storage.get_case(&id))
            .transpose()
    }

    pub fn select_case(&self, case_id: &str) -> AppResult<AssessmentCase> {
        let case = self.storage.get_case(case_id)?;
        self.storage.set_selected_case(Some(case_id))?;
        Ok(case)
    }

    pub fn clear_selection(&self) -> AppResult<()> {
        self.storage.set_selected_case(None)
    }

    pub fn archive_case(&self, case_id: &str) -> AppResult<AssessmentCase> {
        let mut case = self.storage.get_case(case_id)?;
        if case.scan_runs.iter().any(|run| !run_is_terminal(run)) {
            return Err(AppError::InvalidRequest(
                "a case with an active or paused scan cannot be archived".into(),
            ));
        }
        case.status = CaseStatus::Archived;
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), Utc::now());
        self.storage.save_case(&mut case, "case.archived")?;
        Ok(case)
    }

    pub fn artifact_deletion_plan(&self, case_id: &str) -> AppResult<ArtifactDeletionPlan> {
        safe_path_component("case id", case_id)?;
        // The root is not canonicalized here because a new installation may
        // not have created it yet. No deletion occurs in this method.
        let path = self.artifact_root.join(case_id);
        Ok(ArtifactDeletionPlan {
            case_id: case_id.to_owned(),
            exact_path: path.display().to_string(),
            exists: fs::symlink_metadata(&path).is_ok(),
            requires_explicit_confirmation: true,
        })
    }

    pub fn validate_case_deletion(&self, case_id: &str) -> AppResult<()> {
        self.validated_case_for_deletion(case_id).map(|_| ())
    }

    fn validated_case_for_deletion(&self, case_id: &str) -> AppResult<AssessmentCase> {
        let case = self.storage.get_case(case_id)?;
        if case.scan_runs.iter().any(|run| {
            run.engine_runs.iter().any(|engine| {
                matches!(
                    engine.status,
                    EngineRunStatus::Queued
                        | EngineRunStatus::Preparing
                        | EngineRunStatus::Running
                        | EngineRunStatus::Paused
                ) || engine.phase == "interrupted_restart_cleanup_pending"
            })
        }) {
            return Err(AppError::InvalidRequest(
                "cancel and finish the active, paused, or pending runtime cleanup before deleting this case"
                    .into(),
            ));
        }
        let bootstrap_root = self.artifact_root.join(case_id).join("provider-bootstrap");
        let pending_bootstrap = list_bootstrap_cleanup_obligations(&bootstrap_root, case_id)?
            .into_iter()
            .filter(|obligation| {
                obligation.pending_items > 0
                    || obligation.in_progress_items > 0
                    || obligation.retryable_items > 0
                    || obligation.waiting_items > 0
            })
            .count();
        if pending_bootstrap > 0 {
            return Err(AppError::InvalidRequest(format!(
                "complete {pending_bootstrap} provider bootstrap cleanup obligation(s) before deleting this case"
            )));
        }
        Ok(case)
    }

    pub fn list_artifact_deletion_obligations(&self) -> AppResult<Vec<ArtifactDeletionPlan>> {
        self.migrate_legacy_artifact_deletion_obligations(None)?;
        let obligations = self.storage.list_artifact_deletion_obligations()?;
        if obligations.len() > MAX_ARTIFACT_DELETION_OBLIGATIONS {
            return Err(AppError::InvalidRequest(
                "case artifact cleanup obligation limit exceeded".into(),
            ));
        }
        obligations
            .into_iter()
            .map(|obligation| {
                safe_path_component("case id", &obligation.case_id)?;
                let expected = self.artifact_deletion_plan(&obligation.case_id)?;
                if obligation.exact_path != expected.exact_path {
                    return Err(AppError::NotAuthorized(
                        "cleanup obligation path does not match the backend-owned case path".into(),
                    ));
                }
                Ok(expected)
            })
            .collect()
    }

    /// Moves v0.1.0's private JSON cleanup records into the transactional
    /// SQLite ledger. The database row is committed before the legacy file is
    /// removed, so a crash or filesystem error can only leave an idempotent
    /// duplicate, never lose the cleanup obligation.
    fn migrate_legacy_artifact_deletion_obligations(
        &self,
        only_case_id: Option<&str>,
    ) -> AppResult<()> {
        if let Some(case_id) = only_case_id {
            safe_path_component("case id", case_id)?;
        }
        let Some(root) = self.legacy_deletion_obligation_root()? else {
            return Ok(());
        };

        if let Some(case_id) = only_case_id {
            let path = root.join(format!("{case_id}.json"));
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(AppError::NotAuthorized(
                        "legacy cleanup obligation is not a regular non-symlink file".into(),
                    ));
                }
                Ok(_) => self.migrate_legacy_artifact_deletion_obligation(&path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(());
        }

        let mut obligation_count = 0_usize;
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                AppError::InvalidRequest("legacy cleanup obligation filename is invalid".into())
            })?;
            if name.starts_with('.') && name.ends_with(".tmp") {
                continue;
            }
            obligation_count += 1;
            if obligation_count > MAX_ARTIFACT_DELETION_OBLIGATIONS {
                return Err(AppError::InvalidRequest(
                    "case artifact cleanup obligation limit exceeded".into(),
                ));
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() || !file_type.is_file() || !name.ends_with(".json") {
                return Err(AppError::NotAuthorized(
                    "legacy cleanup obligation directory contains an unexpected entry".into(),
                ));
            }
            self.migrate_legacy_artifact_deletion_obligation(&entry.path())?;
        }
        Ok(())
    }

    fn legacy_deletion_obligation_root(&self) -> AppResult<Option<PathBuf>> {
        let artifact_metadata = match fs::symlink_metadata(&self.artifact_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if artifact_metadata.file_type().is_symlink() || !artifact_metadata.is_dir() {
            return Err(AppError::NotAuthorized(
                "artifact root containing legacy cleanup obligations must be a real directory"
                    .into(),
            ));
        }
        let canonical_artifact_root = fs::canonicalize(&self.artifact_root)?;
        let root = canonical_artifact_root.join(LEGACY_DELETION_OBLIGATION_DIRECTORY);
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                Err(AppError::NotAuthorized(
                    "legacy cleanup obligation root is not a real directory".into(),
                ))
            }
            Ok(_) => Ok(Some(root)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn migrate_legacy_artifact_deletion_obligation(&self, path: &Path) -> AppResult<()> {
        let bytes = read_legacy_deletion_obligation(path)?;
        let plan: ArtifactDeletionPlan = serde_json::from_slice(&bytes)?;
        safe_path_component("case id", &plan.case_id)?;

        let expected_filename = format!("{}.json", plan.case_id);
        if path.file_name() != Some(std::ffi::OsStr::new(&expected_filename)) {
            return Err(AppError::NotAuthorized(
                "legacy cleanup obligation filename does not match its case id".into(),
            ));
        }
        if !plan.exists || !plan.requires_explicit_confirmation {
            return Err(AppError::NotAuthorized(
                "legacy cleanup obligation does not contain the required deletion safeguards"
                    .into(),
            ));
        }

        let expected = self.artifact_deletion_plan(&plan.case_id)?;
        let recorded_path = Path::new(&plan.exact_path);
        if plan.exact_path != expected.exact_path
            || recorded_path.parent() != Some(self.artifact_root.as_path())
            || recorded_path.file_name() != Some(std::ffi::OsStr::new(&plan.case_id))
        {
            return Err(AppError::NotAuthorized(
                "legacy cleanup obligation path is not the exact backend-owned case path".into(),
            ));
        }

        self.storage
            .import_artifact_deletion_obligation(&plan.case_id, &plan.exact_path)?;

        // Revalidate the file after the database commit. If it changed, retain
        // it for operator review instead of unlinking a different record.
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(AppError::Conflict(
                    "legacy cleanup obligation changed during migration".into(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        if read_legacy_deletion_obligation(path)? != bytes {
            return Err(AppError::Conflict(
                "legacy cleanup obligation changed during migration".into(),
            ));
        }
        fs::remove_file(path)?;
        Ok(())
    }

    pub fn delete_case(&self, case_id: &str) -> AppResult<CaseDeletionResult> {
        // Resolve both the database target and the artifact plan before the
        // irreversible database operation.
        let case = self.validated_case_for_deletion(case_id)?;
        let artifacts = self.artifact_deletion_plan(case_id)?;
        self.storage.delete_case(
            case_id,
            case.storage_revision,
            artifacts.exists.then_some(artifacts.exact_path.as_str()),
        )?;
        Ok(CaseDeletionResult {
            database_record_deleted: true,
            artifacts,
        })
    }

    /// Executes the separately confirmed evidence deletion plan. The target is
    /// recomputed from the private artifact root and exact case ID; a caller
    /// cannot redirect this operation to an arbitrary path.
    pub fn delete_case_artifacts(
        &self,
        case_id: &str,
        exact_path: &str,
        confirmation: &str,
    ) -> AppResult<ArtifactDeletionResult> {
        let plan = self.artifact_deletion_plan(case_id)?;
        if exact_path != plan.exact_path {
            return Err(AppError::NotAuthorized(
                "artifact deletion path does not match the backend-generated case plan".into(),
            ));
        }
        if confirmation != format!("DELETE {case_id}") {
            return Err(AppError::NotAuthorized(
                "artifact deletion confirmation must exactly match the displayed phrase".into(),
            ));
        }
        self.migrate_legacy_artifact_deletion_obligations(Some(case_id))?;
        self.storage
            .consume_artifact_deletion_obligation(case_id, &plan.exact_path, || {
                let target = Path::new(&plan.exact_path);
                let metadata = match fs::symlink_metadata(target) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(ArtifactDeletionResult {
                            removed: false,
                            exact_path: plan.exact_path.clone(),
                            recoverable: false,
                        });
                    }
                    Err(error) => return Err(error.into()),
                };
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(AppError::NotAuthorized(
                        "case artifact deletion target is not a real directory".into(),
                    ));
                }
                let canonical_root = self.artifact_root.canonicalize()?;
                let canonical_target = target.canonicalize()?;
                if canonical_target.parent() != Some(canonical_root.as_path())
                    || canonical_target.file_name() != Some(std::ffi::OsStr::new(case_id))
                {
                    return Err(AppError::NotAuthorized(
                        "case artifact deletion target escaped the backend-owned artifact root"
                            .into(),
                    ));
                }
                fs::remove_dir_all(&canonical_target)?;
                Ok(ArtifactDeletionResult {
                    removed: true,
                    exact_path: plan.exact_path.clone(),
                    recoverable: false,
                })
            })
    }

    pub fn upsert_source(&self, case_id: &str, request: SourceMutation) -> AppResult<DataSource> {
        validate_source_mutation(&request)?;
        let mut case = self.mutable_case(case_id, "change data sources")?;
        ensure_no_active_scan(&case, "change data sources")?;
        let now = Utc::now();

        let result = if let Some(id) = request.id.as_deref() {
            let source = case
                .data_sources
                .iter_mut()
                .find(|source| source.id == id)
                .ok_or_else(|| AppError::InvalidRequest(format!("data source not found: {id}")))?;
            if source.kind != request.kind {
                return Err(AppError::InvalidRequest(
                    "a data source kind is immutable; add a new source instead".into(),
                ));
            }
            source.label = request.label.trim().to_owned();
            source.status = request.status;
            source.read_only = request.read_only;
            source.metadata = request.metadata;
            if source.status == SourceConnectionStatus::Connected && source.connected_at.is_none() {
                source.connected_at = Some(now);
            }
            source.clone()
        } else {
            let connected = request.status == SourceConnectionStatus::Connected;
            let source = DataSource {
                id: new_id(),
                kind: request.kind,
                label: request.label.trim().to_owned(),
                status: request.status,
                connected_at: if connected { Some(now) } else { None },
                last_discovered_at: None,
                read_only: request.read_only,
                metadata: request.metadata,
            };
            case.data_sources.push(source.clone());
            source
        };

        case.status = if result.status == SourceConnectionStatus::Connected {
            CaseStatus::Discovering
        } else {
            CaseStatus::Draft
        };
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), now);
        self.storage.save_case(&mut case, "source.upserted")?;
        Ok(result)
    }

    /// Atomically binds a backend-ingested immutable snapshot to one planned
    /// read-only source. Frontend callers cannot supply this reserved metadata
    /// through `upsert_source`.
    pub fn connect_snapshot_source(
        &self,
        case_id: &str,
        kind: SourceKind,
        label: &str,
        reference: SnapshotArtifactReference,
    ) -> AppResult<DataSource> {
        let label = required_text("data source label", label, 200)?;
        validate_snapshot_reference(&reference)?;
        let mut case = self.mutable_case(case_id, "connect a source snapshot")?;
        ensure_no_active_scan(&case, "connect a source snapshot")?;
        let now = Utc::now();
        let index = case
            .data_sources
            .iter()
            .position(|source| {
                source.kind == kind
                    && matches!(
                        source.status,
                        SourceConnectionStatus::NotConnected
                            | SourceConnectionStatus::NotApplicable
                    )
            })
            .unwrap_or(case.data_sources.len());

        if index == case.data_sources.len() {
            case.data_sources.push(DataSource {
                id: new_id(),
                kind: kind.clone(),
                label: label.clone(),
                status: SourceConnectionStatus::NotConnected,
                connected_at: None,
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            });
        }
        let source = case
            .data_sources
            .get_mut(index)
            .ok_or_else(|| AppError::Internal("planned source index disappeared".into()))?;
        source.label = label;
        source.status = SourceConnectionStatus::Connected;
        source.connected_at = Some(now);
        source.last_discovered_at = None;
        source.read_only = true;
        source.metadata.clear();
        reference
            .insert_into(source)
            .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
        let connected = source.clone();

        case.status = CaseStatus::Discovering;
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), now);
        self.storage
            .save_case(&mut case, "source.snapshot_connected")?;
        Ok(connected)
    }

    /// Durably attaches only references whose exact raw provider response files
    /// have already been synced into the connector artifact store. The source
    /// remains connected during parsing so the ordinary connector validation
    /// and reconciliation path remains authoritative.
    pub fn attach_live_provider_capture(
        &self,
        case_id: &str,
        source_id: &str,
        artifacts: LiveProviderArtifactSet,
    ) -> AppResult<DataSource> {
        validate_live_provider_artifact_set(&artifacts)?;
        let mut case = self.mutable_case(case_id, "attach live provider evidence")?;
        ensure_no_active_scan(&case, "attach live provider evidence")?;
        let source = case
            .data_sources
            .iter_mut()
            .find(|source| source.id == source_id)
            .ok_or_else(|| AppError::InvalidRequest("provider source does not exist".into()))?;
        if !matches!(
            source.kind,
            SourceKind::AwsOrganization
                | SourceKind::AzureTenant
                | SourceKind::GcpOrganization
                | SourceKind::Microsoft365Tenant
        ) || !source.read_only
            || source.status != SourceConnectionStatus::Connected
        {
            return Err(AppError::NotAuthorized(
                "live provider evidence requires the matching connected read-only source".into(),
            ));
        }
        let profile_matches_source = matches!(
            (source.kind.clone(), artifacts.profile.as_str()),
            (
                SourceKind::AwsOrganization,
                "aws-organizations-list-accounts"
            ) | (SourceKind::AzureTenant, "azure-resource-manager-resources")
                | (SourceKind::GcpOrganization, "gcp-resource-manager-projects")
                | (
                    SourceKind::Microsoft365Tenant,
                    "microsoft-graph-directory-inventory"
                )
        );
        if !profile_matches_source {
            return Err(AppError::NotAuthorized(
                "live provider artifact profile does not match its source kind".into(),
            ));
        }
        source.metadata.remove(SNAPSHOT_ARTIFACT_METADATA_KEY);
        artifacts
            .insert_into(source)
            .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
        source.metadata.insert(
            "ai_security_scanner.live_discovery_capture_phase".into(),
            Value::String("raw_pages_preserved_before_parse".into()),
        );
        let captured = source.clone();
        case.status = CaseStatus::Discovering;
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), Utc::now());
        self.storage
            .save_case(&mut case, "source.live_provider_pages_preserved")?;
        Ok(captured)
    }

    /// Records the terminal semantics of a provider discovery attempt without
    /// deleting older asset observations or raw pages. `Connected` means a
    /// complete response contract (including an honestly empty result);
    /// failures and expired capabilities remain unknown coverage.
    pub fn record_live_provider_discovery_outcome(
        &self,
        case_id: &str,
        source_id: &str,
        outcome: LiveProviderDiscoveryOutcome,
    ) -> AppResult<DataSource> {
        if !matches!(
            outcome.status,
            SourceConnectionStatus::Connected
                | SourceConnectionStatus::Failed
                | SourceConnectionStatus::NeedsReauthorization
        ) || (outcome.status == SourceConnectionStatus::Connected && !outcome.complete)
            || outcome.successful_pages > MAX_LIVE_PROVIDER_PAGES
            || outcome.record_count > 1_000
        {
            return Err(AppError::InvalidRequest(
                "live provider discovery outcome is inconsistent or outside limits".into(),
            ));
        }
        let code = required_text("live discovery outcome code", &outcome.code, 128)?;
        let message = required_text("live discovery outcome message", &outcome.message, 1_024)?;
        let notices = outcome
            .notices
            .into_iter()
            .take(32)
            .map(|notice| required_text("live discovery notice", &notice, 1_024))
            .collect::<AppResult<Vec<_>>>()?;
        let mut case = self.mutable_case(case_id, "record provider discovery outcome")?;
        ensure_no_active_scan(&case, "record provider discovery outcome")?;
        let source = case
            .data_sources
            .iter_mut()
            .find(|source| source.id == source_id)
            .ok_or_else(|| AppError::InvalidRequest("provider source does not exist".into()))?;
        if !matches!(
            source.kind,
            SourceKind::AwsOrganization
                | SourceKind::AzureTenant
                | SourceKind::GcpOrganization
                | SourceKind::Microsoft365Tenant
        ) || !source.read_only
        {
            return Err(AppError::NotAuthorized(
                "provider discovery outcome does not match a read-only provider source".into(),
            ));
        }
        source.status = outcome.status.clone();
        source.metadata.insert(
            "ai_security_scanner.live_discovery_outcome".into(),
            serde_json::json!({
                "status": enum_key(&outcome.status),
                "code": code,
                "message": message,
                "complete": outcome.complete,
                "successful_pages": outcome.successful_pages,
                "record_count": outcome.record_count,
                "observed_at": outcome.observed_at,
                "notices": notices,
            }),
        );
        let updated = source.clone();
        case.status = if outcome.status == SourceConnectionStatus::Connected {
            CaseStatus::ScopeReview
        } else {
            CaseStatus::NeedsAttention
        };
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), Utc::now());
        self.storage
            .save_case(&mut case, "source.live_provider_discovery_outcome")?;
        Ok(updated)
    }

    /// Persists one already-created immutable working-tree snapshot as an
    /// attributable connected source and unauthorized candidate asset.
    pub fn attach_workspace_snapshot(
        &self,
        case_id: &str,
        label: &str,
        snapshot: WorkspaceSnapshot,
    ) -> AppResult<AssessmentCase> {
        let label = required_text("workspace source label", label, 200)?;
        if snapshot.reference.schema_version != WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA
            || snapshot.reference.sha256.len() != 64
            || !snapshot
                .reference
                .sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
            || !snapshot.reference.working_tree_only
            || snapshot.asset.kind != snapshot.reference.input_profile.asset_kind()
            || !snapshot.asset.candidate
            || snapshot.asset.owner_confirmed
            || snapshot.asset.discovered_from.len() != 1
        {
            return Err(AppError::InvalidRequest(
                "local input snapshot is not a backend-created unauthorized typed candidate".into(),
            ));
        }
        let source_id = snapshot.asset.discovered_from[0].clone();
        safe_path_component("workspace source id", &source_id)?;
        let reference_value = serde_json::to_value(&snapshot.reference)?;
        validate_non_secret_value("workspace snapshot reference", &reference_value)?;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY.into(),
            reference_value,
        );

        let mut case = self.mutable_case(case_id, "attach a workspace snapshot")?;
        ensure_no_active_scan(&case, "attach a workspace snapshot")?;
        if case
            .data_sources
            .iter()
            .any(|source| source.id == source_id)
        {
            return Err(AppError::InvalidRequest(
                "workspace source id already exists in this case".into(),
            ));
        }
        case.data_sources.push(DataSource {
            id: source_id.clone(),
            kind: snapshot.reference.input_profile.source_kind(),
            label,
            status: SourceConnectionStatus::Connected,
            connected_at: Some(Utc::now()),
            last_discovered_at: Some(Utc::now()),
            read_only: true,
            metadata,
        });

        if let Some(existing) = case
            .assets
            .iter_mut()
            .find(|asset| asset.id == snapshot.asset.id)
        {
            if existing.kind != snapshot.asset.kind
                || existing.metadata != snapshot.asset.metadata
                || existing.identifiers.len() != snapshot.asset.identifiers.len()
                || existing
                    .identifiers
                    .iter()
                    .zip(&snapshot.asset.identifiers)
                    .any(|(left, right)| {
                        left.namespace != right.namespace || left.value != right.value
                    })
            {
                return Err(AppError::InvalidRequest(
                    "workspace snapshot stable asset identity conflicts with the existing case asset"
                        .into(),
                ));
            }
            if !existing.discovered_from.contains(&source_id) {
                existing.discovered_from.push(source_id);
                existing.discovered_from.sort();
            }
        } else {
            case.assets.push(snapshot.asset);
        }
        case.status = CaseStatus::ScopeReview;
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), Utc::now());
        self.storage
            .save_case(&mut case, "source.workspace_snapshot_attached")?;
        Ok(case)
    }

    pub fn reconcile_discovery_batch(
        &self,
        case_id: &str,
        batch: &DiscoveryBatch,
    ) -> AppResult<ReconciliationReport> {
        self.reconcile_discovery_batches(case_id, std::slice::from_ref(batch))?
            .pop()
            .ok_or_else(|| AppError::Internal("discovery reconciliation returned no report".into()))
    }

    /// Reconciles a complete discovery pass in one durable case update. A
    /// malformed or stale batch leaves every source in the pass untouched.
    pub fn reconcile_discovery_batches(
        &self,
        case_id: &str,
        batches: &[DiscoveryBatch],
    ) -> AppResult<Vec<ReconciliationReport>> {
        if batches.is_empty() {
            return Err(AppError::InvalidRequest(
                "at least one source-attributed discovery batch is required".into(),
            ));
        }
        let mut case = self.mutable_case(case_id, "reconcile discovery")?;
        ensure_no_active_scan(&case, "reconcile discovery")?;
        let mut reports = Vec::with_capacity(batches.len());
        for batch in batches {
            if batch.source_id.trim().is_empty() {
                return Err(AppError::InvalidRequest(
                    "discovery batch source id is required".into(),
                ));
            }
            reports.push(
                reconcile_discovery(&mut case, batch)
                    .map_err(|error| AppError::InvalidRequest(error.to_string()))?,
            );
        }
        case.status = CaseStatus::ScopeReview;
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), Utc::now());
        self.storage.save_case(&mut case, "discovery.reconciled")?;
        Ok(reports)
    }

    pub fn approve_scope(
        &self,
        case_id: &str,
        request: ScopeApprovalRequest,
    ) -> AppResult<Vec<ScopeGrant>> {
        self.approve_scopes(case_id, vec![request])
    }

    /// Applies a complete scope decision batch as one optimistic, durable case
    /// update. Any invalid decision leaves every grant and asset unchanged.
    pub fn approve_scopes(
        &self,
        case_id: &str,
        requests: Vec<ScopeApprovalRequest>,
    ) -> AppResult<Vec<ScopeGrant>> {
        if requests.is_empty() {
            return Err(AppError::InvalidRequest(
                "at least one scope approval request is required".into(),
            ));
        }
        let now = Utc::now();
        for request in &requests {
            validate_scope_approval(request, now)?;
        }
        let mut decisions = BTreeSet::new();
        for request in &requests {
            let mut permissions = request.permissions.clone();
            permissions.sort_by_key(enum_key);
            permissions.dedup();
            for permission in permissions {
                if !decisions.insert(grant_key(&request.asset_id, &permission)) {
                    return Err(AppError::InvalidRequest(format!(
                        "scope decision is duplicated for asset {} and permission {}",
                        request.asset_id,
                        enum_key(&permission)
                    )));
                }
            }
        }
        let mut case = self.mutable_case(case_id, "approve scope")?;
        ensure_no_active_scan(&case, "change scan authorization")?;

        // Collapse any legacy duplicates first, preserving the oldest stable
        // grant ID, then replace each requested decision in place.
        let mut grants = BTreeMap::<String, ScopeGrant>::new();
        for grant in case.scope_grants.drain(..) {
            grants
                .entry(grant_key(&grant.asset_id, &grant.permission))
                .or_insert(grant);
        }

        let mut approved = Vec::new();
        for request in requests {
            let asset = case
                .assets
                .iter()
                .find(|asset| asset.id == request.asset_id)
                .cloned()
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!("asset not found: {}", request.asset_id))
                })?;
            let mut permissions = request.permissions.clone();
            permissions.sort_by_key(enum_key);
            permissions.dedup();
            for permission in permissions {
                let key = grant_key(&request.asset_id, &permission);
                let grant = grants.entry(key).or_insert_with(|| ScopeGrant {
                    id: new_id(),
                    asset_id: request.asset_id.clone(),
                    permission: permission.clone(),
                    confirmed_by: String::new(),
                    confirmed_at: now,
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                });
                grant.confirmed_by = request.confirmed_by.trim().to_owned();
                grant.confirmed_at = now;
                grant.expires_at = request.expires_at;
                grant.authorization_reference =
                    trim_option(request.authorization_reference.as_deref());
                grant.notes = optional_text("scope notes", request.notes.as_deref(), 4_000)?;
                grant.external_scope = materialize_external_scope(
                    case_id,
                    &asset,
                    &grant.id,
                    &permission,
                    &request,
                    now,
                )?;
                approved.push(grant.clone());
            }
            if let Some(asset) = case
                .assets
                .iter_mut()
                .find(|asset| asset.id == request.asset_id)
            {
                asset.owner_confirmed = true;
                asset.candidate = false;
            }
        }
        case.scope_grants = grants.into_values().collect();
        case.scope_grants.sort_by(|left, right| {
            left.asset_id
                .cmp(&right.asset_id)
                .then_with(|| enum_key(&left.permission).cmp(&enum_key(&right.permission)))
        });
        case.status = CaseStatus::Ready;
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), now);
        self.storage.save_case(&mut case, "scope.approved")?;
        Ok(approved)
    }

    /// Reports whether a new desktop execution can start without mutating the
    /// case or creating a scan-run record.
    pub fn scan_readiness(&self, case_id: &str) -> AppResult<ScanReadiness> {
        let case = self.storage.get_case(case_id)?;
        Ok(scan_readiness_at(
            &case,
            self.engines,
            self.adapters,
            Utc::now(),
        ))
    }

    /// Persists an audit plan. Explicitly requested unavailable or
    /// incompatible engines remain durable `not_executed` records.
    pub fn plan_scan(&self, case_id: &str, request: ScanPlanRequest) -> AppResult<ScanPlan> {
        self.plan_scan_at(
            case_id,
            request,
            None,
            ScanPlanIntent::PersistAuditPlan,
            Utc::now(),
            None,
        )
    }

    /// Builds the exact desktop execution groups without changing the case.
    /// Readiness callers use this to validate live, process-owned dependencies
    /// that deliberately do not belong in the durable audit planner.
    pub fn preview_scan_for_execution(
        &self,
        case_id: &str,
        request: ScanPlanRequest,
    ) -> AppResult<ScanPlan> {
        self.plan_scan_at(
            case_id,
            request,
            None,
            ScanPlanIntent::PreviewExecution,
            Utc::now(),
            None,
        )
    }

    /// Atomically plans a run that will be dispatched immediately. Unlike an
    /// audit-only plan, this path never persists a run with zero executable
    /// engine/target groups.
    pub fn plan_scan_for_execution(
        &self,
        case_id: &str,
        request: ScanPlanRequest,
    ) -> AppResult<ScanPlan> {
        self.plan_scan_at(
            case_id,
            request,
            None,
            ScanPlanIntent::StartExecution,
            Utc::now(),
            None,
        )
    }

    /// Execution planner with a final live-dependency check at the only safe
    /// seam: the exact groups exist in memory, but no `ScanRun` has been
    /// appended or saved. Hook failure leaves the durable case unchanged.
    pub fn plan_scan_for_execution_checked<F>(
        &self,
        case_id: &str,
        request: ScanPlanRequest,
        mut pre_persist: F,
    ) -> AppResult<ScanPlan>
    where
        F: FnMut(&ScanPlan) -> AppResult<()>,
    {
        self.plan_scan_at(
            case_id,
            request,
            None,
            ScanPlanIntent::StartExecution,
            Utc::now(),
            Some(&mut pre_persist),
        )
    }

    fn plan_scan_at(
        &self,
        case_id: &str,
        request: ScanPlanRequest,
        verification_baseline_run_id: Option<&str>,
        intent: ScanPlanIntent,
        now: DateTime<Utc>,
        mut pre_persist: Option<&mut ExecutionPrePersist<'_>>,
    ) -> AppResult<ScanPlan> {
        let mut case = self.mutable_case(case_id, "plan a scan")?;
        let readiness = scan_readiness_at(&case, self.engines, self.adapters, now);
        if case.scan_runs.iter().any(|run| !run_is_terminal(run)) {
            if intent.is_execution() {
                return Err(scan_preflight_error(&readiness));
            }
            return Err(AppError::InvalidRequest(
                "the case already has an active or paused scan".into(),
            ));
        }
        if let Some(baseline_run_id) = verification_baseline_run_id {
            let baseline = case
                .scan_runs
                .iter()
                .find(|run| run.id == baseline_run_id)
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!("baseline run not found: {baseline_run_id}"))
                })?;
            if !run_is_terminal(baseline) {
                return Err(AppError::InvalidRequest(
                    "a rescan baseline must be terminal".into(),
                ));
            }
        }

        let effective = effective_grants(&case, now);
        if effective.is_empty() {
            if intent.is_execution() {
                return Err(scan_preflight_error(&readiness));
            }
            return Err(AppError::NotAuthorized(
                "no unexpired explicit scope grants exist; discovery alone never authorizes scanning"
                    .into(),
            ));
        }
        let effective_asset_ids = effective
            .iter()
            .map(|grant| grant.asset_id.as_str())
            .collect::<BTreeSet<_>>();
        if !case.assets.iter().any(|asset| {
            effective_asset_ids.contains(asset.id.as_str())
                && asset.owner_confirmed
                && !asset.candidate
        }) {
            if intent.is_execution() {
                return Err(scan_preflight_error(&readiness));
            }
            return Err(AppError::NotAuthorized(
                "scope grants do not refer to an ownership-confirmed asset".into(),
            ));
        }

        let engine_ids = selected_engine_ids(self.engines, &request, &case, &effective, now)?;
        if engine_ids.is_empty() {
            if intent.is_execution() {
                return Err(scan_preflight_error(&readiness));
            }
            return Err(AppError::InvalidRequest(
                "no catalog engine is applicable to the ownership-confirmed assets and effective scope grants"
                    .into(),
            ));
        }
        let scan_run_id = new_id();
        let sequence = case
            .scan_runs
            .iter()
            .map(|run| run.sequence)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let scope_grant_ids = effective.iter().map(|grant| grant.id.clone()).collect();
        let mut engine_runs = Vec::new();
        let mut executable = Vec::new();
        let mut not_executed = Vec::new();

        for engine_id in engine_ids {
            let Some(manifest) = self.engines.get(&engine_id) else {
                let engine_run_id = new_id();
                let explanation = "The requested engine has no installed manifest.".to_owned();
                engine_runs.push(not_executed_run(
                    &scan_run_id,
                    &engine_run_id,
                    &engine_id,
                    Vec::new(),
                    ("manifest_unavailable", &explanation),
                    None,
                    now,
                ));
                not_executed.push(NotExecutedEngine {
                    engine_id,
                    engine_run_id,
                    asset_ids: Vec::new(),
                    reason_code: "manifest_unavailable".into(),
                    explanation,
                });
                continue;
            };

            let assets = compatible_authorized_assets(&case, manifest, &effective, now);
            let asset_ids = assets
                .iter()
                .map(|asset| asset.id.clone())
                .collect::<Vec<_>>();
            if assets.is_empty() {
                let engine_run_id = new_id();
                let explanation = "No ownership-confirmed asset has all unexpired permissions required by this engine.".to_owned();
                engine_runs.push(not_executed_run(
                    &scan_run_id,
                    &engine_run_id,
                    &manifest.id,
                    asset_ids.clone(),
                    ("no_compatible_authorized_assets", &explanation),
                    Some(manifest),
                    now,
                ));
                not_executed.push(NotExecutedEngine {
                    engine_id: manifest.id.clone(),
                    engine_run_id,
                    asset_ids,
                    reason_code: "no_compatible_authorized_assets".into(),
                    explanation,
                });
                continue;
            }

            if let Some((reason_code, explanation)) = engine_unavailable(manifest, self.adapters) {
                let engine_run_id = new_id();
                engine_runs.push(not_executed_run(
                    &scan_run_id,
                    &engine_run_id,
                    &manifest.id,
                    asset_ids.clone(),
                    (&reason_code, &explanation),
                    Some(manifest),
                    now,
                ));
                not_executed.push(NotExecutedEngine {
                    engine_id: manifest.id.clone(),
                    engine_run_id,
                    asset_ids,
                    reason_code,
                    explanation,
                });
                continue;
            }

            let execution_groups = if manifest
                .required_permissions
                .contains(&ScanPermission::LocalArtifactRead)
                || !manifest.supported_providers.is_empty()
            {
                assets
                    .into_iter()
                    .map(|asset| vec![asset])
                    .collect::<Vec<_>>()
            } else {
                vec![assets]
            };
            for assets in execution_groups {
                let engine_run_id = new_id();
                let asset_ids = assets
                    .iter()
                    .map(|asset| asset.id.clone())
                    .collect::<Vec<_>>();
                let relevant_grants = effective
                    .iter()
                    .copied()
                    .filter(|grant| {
                        asset_ids.contains(&grant.asset_id)
                            && (manifest.required_permissions.contains(&grant.permission)
                                || (manifest.active_external
                                    && grant.permission == ScanPermission::ActiveExternalTesting))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let planned_resume_token = ExecutionCheckpoint {
                    case_id: case.id.clone(),
                    scan_run_id: scan_run_id.clone(),
                    engine_run_id: engine_run_id.clone(),
                    engine_id: manifest.id.clone(),
                    attempt: 1,
                    stage: ExecutionStage::Planned,
                    container_name: None,
                    scope_sha256: None,
                    artifact_ids: Vec::new(),
                    cleanup_completed: true,
                    last_error: None,
                    runtime_command_provenance: None,
                    runtime_provider: None,
                    managed_network: None,
                }
                .resume_token()?;
                let engine_run = EngineRun {
                    id: engine_run_id.clone(),
                    scan_run_id: scan_run_id.clone(),
                    engine_id: manifest.id.clone(),
                    asset_ids,
                    status: EngineRunStatus::Queued,
                    progress_percent: 0,
                    phase: "queued".into(),
                    started_at: None,
                    finished_at: None,
                    resume_token: Some(planned_resume_token),
                    engine_version: manifest.engine_version.clone(),
                    image_digest: manifest
                        .image
                        .as_ref()
                        .and_then(|image| image.digest.clone()),
                    rule_version: manifest.rule_version.clone(),
                    adapter_version: manifest.adapter_version.clone(),
                    manifest_schema_version: Some(manifest.schema_version.clone()),
                    source_revision: manifest.source_revision.clone(),
                    repository_url: Some(manifest.repository_url.clone()),
                    distribution_mode: Some(manifest.distribution_mode.clone()),
                    image_repository: manifest
                        .image
                        .as_ref()
                        .map(|image| image.repository.clone()),
                    command_sha256: Some(sha256_bytes(&serde_json::to_vec(&manifest.command)?)),
                    knowledge_input: Some(dated_knowledge_input(manifest)),
                    scope_contract_sha256: Some(comparable_scope_contract_sha256(
                        manifest,
                        &assets,
                        &relevant_grants,
                    )?),
                    mapping_version: Some(control_mapping_version()?.to_owned()),
                    fingerprint_schema_version: Some(FINGERPRINT_SCHEMA_VERSION.to_owned()),
                    runtime_provider: None,
                    runtime_version: None,
                    runtime_security_options: None,
                    exit_code: None,
                    cleanup_removed: None,
                    cleanup_detail: None,
                    warnings: stale_knowledge_warning(manifest, now).into_iter().collect(),
                    raw_artifact_ids: Vec::new(),
                    error_code: None,
                    error_message: None,
                };
                executable.push(PlannedEngineExecution {
                    case_id: case.id.clone(),
                    scan_run_id: scan_run_id.clone(),
                    engine_run_id: engine_run_id.clone(),
                    attempt: 1,
                    manifest: manifest.clone(),
                    assets: assets.into_iter().cloned().collect(),
                    scope_grants: relevant_grants,
                    resume_checkpoint: None,
                });
                engine_runs.push(engine_run);
            }
        }

        if intent.is_execution() && executable.is_empty() {
            return Err(scan_preflight_error(&readiness));
        }

        let completed_at = executable.is_empty().then_some(now);
        let scan_run = ScanRun {
            id: scan_run_id,
            case_id: case.id.clone(),
            sequence,
            created_at: now,
            completed_at,
            knowledge_cutoff: now,
            verification_baseline_run_id: verification_baseline_run_id.map(str::to_owned),
            scope_grant_ids,
            scope_grant_snapshots: frozen_scope_grants(&effective),
            engine_runs,
        };
        let plan = ScanPlan {
            scan_run,
            executable,
            not_executed,
        };
        if intent == ScanPlanIntent::PreviewExecution {
            return Ok(plan);
        }
        if intent == ScanPlanIntent::StartExecution
            && let Some(pre_persist) = pre_persist.as_mut()
        {
            pre_persist(&plan)?;
        }

        case.scan_runs.push(plan.scan_run.clone());
        case.knowledge_cutoff = Some(now);
        case.status = if plan.executable.is_empty() {
            CaseStatus::NeedsAttention
        } else if verification_baseline_run_id.is_some() {
            CaseStatus::Verifying
        } else {
            CaseStatus::Scanning
        };
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), now);
        self.storage.save_case(
            &mut case,
            if verification_baseline_run_id.is_some() {
                "scan.rescan_planned"
            } else {
                "scan.planned"
            },
        )?;
        Ok(plan)
    }

    pub fn plan_rescan(
        &self,
        case_id: &str,
        baseline_run_id: &str,
        request: ScanPlanRequest,
    ) -> AppResult<RescanPlan> {
        let plan = self.plan_scan_at(
            case_id,
            request,
            Some(baseline_run_id),
            ScanPlanIntent::PersistAuditPlan,
            Utc::now(),
            None,
        )?;
        Ok(RescanPlan {
            baseline_run_id: baseline_run_id.to_owned(),
            plan,
        })
    }

    /// Execution-intent counterpart to `plan_rescan`; a verification run is
    /// never persisted unless at least one exact engine/target group can run.
    pub fn plan_rescan_for_execution(
        &self,
        case_id: &str,
        baseline_run_id: &str,
        request: ScanPlanRequest,
    ) -> AppResult<RescanPlan> {
        let plan = self.plan_scan_at(
            case_id,
            request,
            Some(baseline_run_id),
            ScanPlanIntent::StartExecution,
            Utc::now(),
            None,
        )?;
        Ok(RescanPlan {
            baseline_run_id: baseline_run_id.to_owned(),
            plan,
        })
    }

    pub fn plan_rescan_for_execution_checked<F>(
        &self,
        case_id: &str,
        baseline_run_id: &str,
        request: ScanPlanRequest,
        mut pre_persist: F,
    ) -> AppResult<RescanPlan>
    where
        F: FnMut(&ScanPlan) -> AppResult<()>,
    {
        let plan = self.plan_scan_at(
            case_id,
            request,
            Some(baseline_run_id),
            ScanPlanIntent::StartExecution,
            Utc::now(),
            Some(&mut pre_persist),
        )?;
        Ok(RescanPlan {
            baseline_run_id: baseline_run_id.to_owned(),
            plan,
        })
    }

    /// Converts process-owned work left behind by an application restart into
    /// an explicit paused state. No scanner is restarted automatically: the
    /// user can inspect the interruption and choose resume or cancel, while
    /// the last durable checkpoint remains intact.
    pub fn recover_interrupted_scans(&self) -> AppResult<usize> {
        let mut recovered_runs = 0_usize;
        for summary in self.storage.list_cases()? {
            let mut case = self.storage.get_case(&summary.id)?;
            if case.status == CaseStatus::Archived || case.is_demo {
                continue;
            }
            let mut case_changed = false;
            for run in &mut case.scan_runs {
                let mut run_changed = false;
                for engine_run in &mut run.engine_runs {
                    // A prior startup already proved these resources clean, or
                    // deliberately retained an exact cleanup obligation. Do
                    // not erase that durable reconciliation state on every
                    // subsequent desktop launch.
                    if matches!(
                        engine_run.phase.as_str(),
                        "interrupted_restart_cleaned" | "interrupted_restart_cleanup_pending"
                    ) {
                        continue;
                    }
                    if !matches!(
                        engine_run.status,
                        EngineRunStatus::Queued
                            | EngineRunStatus::Preparing
                            | EngineRunStatus::Running
                            | EngineRunStatus::Paused
                    ) {
                        continue;
                    }
                    if engine_run.resume_token.is_none() {
                        engine_run.resume_token = Some(
                            ExecutionCheckpoint {
                                case_id: case.id.clone(),
                                scan_run_id: run.id.clone(),
                                engine_run_id: engine_run.id.clone(),
                                engine_id: engine_run.engine_id.clone(),
                                attempt: 1,
                                stage: ExecutionStage::Planned,
                                container_name: None,
                                scope_sha256: None,
                                artifact_ids: Vec::new(),
                                cleanup_completed: true,
                                last_error: None,
                                runtime_command_provenance: None,
                                runtime_provider: None,
                                managed_network: None,
                            }
                            .resume_token()?,
                        );
                    }
                    engine_run.status = EngineRunStatus::Paused;
                    engine_run.phase = "interrupted_restart".into();
                    engine_run.finished_at = None;
                    engine_run.error_code = Some("desktop_process_restarted".into());
                    engine_run.error_message = Some(
                        "The desktop process ended before this engine reached a terminal checkpoint. Resume revalidates the original scope and starts a new isolated attempt."
                            .into(),
                    );
                    run_changed = true;
                }
                if run_changed {
                    run.completed_at = None;
                    recovered_runs = recovered_runs.saturating_add(1);
                    case_changed = true;
                }
            }
            if case_changed {
                case.status = CaseStatus::NeedsAttention;
                case.touch();
                refresh_coverage_ledger(&mut case, self.engines.manifests(), Utc::now());
                self.storage
                    .save_case(&mut case, "scan.interrupted_after_restart")?;
            }
        }
        Ok(recovered_runs)
    }

    /// Records resource reconciliation for one exact execution that was
    /// paused by `recover_interrupted_scans`. The service derives the updated
    /// checkpoint from the stored token; callers cannot alter identity,
    /// attempt, scope, artifacts, pinned runtime provenance, or findings.
    pub fn record_interrupted_cleanup_success(
        &self,
        case_id: &str,
        run_id: &str,
        engine_run_id: &str,
        result: InterruptedCleanupSuccess,
    ) -> AppResult<AssessmentCase> {
        let mut case = self.mutable_case(case_id, "record interrupted runtime cleanup")?;
        let run_index = case
            .scan_runs
            .iter()
            .position(|run| run.id == run_id)
            .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
        let engine_index = case.scan_runs[run_index]
            .engine_runs
            .iter()
            .position(|engine| engine.id == engine_run_id)
            .ok_or_else(|| {
                AppError::InvalidRequest(format!("engine run not found: {engine_run_id}"))
            })?;
        let engine_run = &mut case.scan_runs[run_index].engine_runs[engine_index];
        if engine_run.phase == "interrupted_restart_cleaned" {
            return Ok(case);
        }
        if engine_run.status != EngineRunStatus::Paused
            || !matches!(
                engine_run.phase.as_str(),
                "interrupted_restart" | "interrupted_restart_cleanup_pending"
            )
            || engine_run.resume_token.as_deref() != Some(result.expected_resume_token.as_str())
        {
            return Err(AppError::NotAuthorized(
                "interrupted cleanup no longer matches the exact paused execution".into(),
            ));
        }
        let mut checkpoint = ExecutionCheckpoint::from_resume_token(&result.expected_resume_token)?;
        if checkpoint.case_id != case_id
            || checkpoint.scan_run_id != run_id
            || checkpoint.engine_run_id != engine_run_id
            || checkpoint.engine_id != engine_run.engine_id
        {
            return Err(AppError::NotAuthorized(
                "interrupted cleanup checkpoint identity conflicts with its durable run".into(),
            ));
        }
        checkpoint.managed_network = None;
        checkpoint.cleanup_completed = true;
        checkpoint.stage = ExecutionStage::Failed;
        checkpoint.last_error = Some(
            "The desktop process restarted; exact runtime resources were reconciled. Resume starts a new isolated attempt."
                .into(),
        );
        engine_run.resume_token = Some(checkpoint.resume_token()?);
        engine_run.phase = "interrupted_restart_cleaned".into();
        engine_run.cleanup_removed = Some(result.cleanup.removed);
        engine_run.cleanup_detail = Some(result.cleanup.detail);
        engine_run.error_code = Some("desktop_process_restarted".into());
        engine_run.error_message = checkpoint.last_error;
        if result.orphan_credentials_removed > 0 {
            engine_run.warnings.push(format!(
                "Zeroized and removed {} crash-left credential envelope(s) from this exact execution attempt.",
                result.orphan_credentials_removed
            ));
        }
        case.scan_runs[run_index].completed_at = None;
        case.status = CaseStatus::NeedsAttention;
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), Utc::now());
        self.storage
            .save_case(&mut case, "scan.interrupted_resources_reconciled")?;
        Ok(case)
    }

    /// Keeps an interrupted execution fail-closed when its exact runtime
    /// resources cannot be proven clean. Cancellation and resume must retry
    /// this obligation; neither may silently discard it.
    pub fn record_interrupted_cleanup_failure(
        &self,
        case_id: &str,
        run_id: &str,
        engine_run_id: &str,
        expected_resume_token: &str,
        explanation: &str,
    ) -> AppResult<AssessmentCase> {
        let mut case = self.mutable_case(case_id, "record pending interrupted cleanup")?;
        let run_index = case
            .scan_runs
            .iter()
            .position(|run| run.id == run_id)
            .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
        let engine_run = case.scan_runs[run_index]
            .engine_runs
            .iter_mut()
            .find(|engine| engine.id == engine_run_id)
            .ok_or_else(|| {
                AppError::InvalidRequest(format!("engine run not found: {engine_run_id}"))
            })?;
        if engine_run.status != EngineRunStatus::Paused
            || !matches!(
                engine_run.phase.as_str(),
                "interrupted_restart" | "interrupted_restart_cleanup_pending"
            )
            || engine_run.resume_token.as_deref() != Some(expected_resume_token)
        {
            return Err(AppError::NotAuthorized(
                "cleanup failure no longer matches the exact paused execution".into(),
            ));
        }
        let mut checkpoint = ExecutionCheckpoint::from_resume_token(expected_resume_token)?;
        if checkpoint.case_id != case_id
            || checkpoint.scan_run_id != run_id
            || checkpoint.engine_run_id != engine_run_id
            || checkpoint.engine_id != engine_run.engine_id
        {
            return Err(AppError::NotAuthorized(
                "cleanup failure checkpoint identity conflicts with its durable run".into(),
            ));
        }
        let explanation = explanation
            .chars()
            .filter(|character| *character != '\0')
            .take(2_000)
            .collect::<String>();
        checkpoint.cleanup_completed = false;
        checkpoint.last_error = Some(explanation.clone());
        if checkpoint.runtime_provider.is_some() && checkpoint.runtime_command_provenance.is_some()
        {
            checkpoint.stage = ExecutionStage::CleanupPending;
        }
        engine_run.resume_token = Some(checkpoint.resume_token()?);
        engine_run.phase = "interrupted_restart_cleanup_pending".into();
        engine_run.cleanup_removed = Some(false);
        engine_run.cleanup_detail = Some(explanation.clone());
        engine_run.error_code = Some("runtime_cleanup_pending".into());
        engine_run.error_message = Some(explanation);
        case.status = CaseStatus::NeedsAttention;
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), Utc::now());
        self.storage
            .save_case(&mut case, "scan.interrupted_cleanup_pending")?;
        Ok(case)
    }

    /// Rebuilds a credential-free execution plan for a persisted interrupted
    /// or failed run. The original run, engine-run IDs, asset IDs, and scope
    /// grant IDs are reused; newly approved or re-approved grants are refused
    /// so resume cannot silently widen the prior scan contract.
    pub fn plan_resume(&self, case_id: &str, run_id: &str) -> AppResult<ScanPlan> {
        self.plan_resume_checked(case_id, run_id, |_| Ok(()))
    }

    /// Desktop resume counterpart whose live dependency hook runs before any
    /// queued/status transition is saved.
    pub fn plan_resume_checked<F>(
        &self,
        case_id: &str,
        run_id: &str,
        mut pre_persist: F,
    ) -> AppResult<ScanPlan>
    where
        F: FnMut(&ScanPlan) -> AppResult<()>,
    {
        let now = Utc::now();
        let mut case = self.mutable_case(case_id, "resume a scan")?;
        let run_index = case
            .scan_runs
            .iter()
            .position(|run| run.id == run_id)
            .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
        if case
            .scan_runs
            .iter()
            .enumerate()
            .any(|(index, run)| index != run_index && !run_is_terminal(run))
        {
            return Err(AppError::InvalidRequest(
                "another scan run is still active or paused".into(),
            ));
        }
        if case.scan_runs[run_index]
            .engine_runs
            .iter()
            .any(|engine_run| {
                matches!(
                    engine_run.phase.as_str(),
                    "interrupted_restart" | "interrupted_restart_cleanup_pending"
                )
            })
        {
            return Err(AppError::NotAvailable(
                "the interrupted run still has an exact runtime cleanup obligation; reconcile it before resume"
                    .into(),
            ));
        }

        let run_created_at = case.scan_runs[run_index].created_at;
        let frozen_grant_ids = case.scan_runs[run_index]
            .scope_grant_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let frozen_effective_grants = case
            .scope_grants
            .iter()
            .filter(|grant| {
                frozen_grant_ids.contains(&grant.id)
                    && grant.confirmed_at <= run_created_at
                    && grant_effective(grant, now)
            })
            .collect::<Vec<_>>();
        if frozen_effective_grants.len() != frozen_grant_ids.len() {
            return Err(AppError::NotAuthorized(
                "the original scan scope is missing, expired, or was re-approved after this run began"
                    .into(),
            ));
        }

        struct ResumeCandidate {
            engine_index: usize,
            execution: PlannedEngineExecution,
            stale_warning: Option<String>,
        }
        let mut candidates = Vec::<ResumeCandidate>::new();
        let run = &case.scan_runs[run_index];
        for (engine_index, engine_run) in run.engine_runs.iter().enumerate() {
            let eligible = engine_run.status == EngineRunStatus::Paused
                || (matches!(
                    engine_run.status,
                    EngineRunStatus::Failed
                        | EngineRunStatus::PartiallyCompleted
                        | EngineRunStatus::Cancelled
                ) && engine_run.resume_token.is_some());
            if !eligible {
                continue;
            }
            let manifest = self.engines.get(&engine_run.engine_id).ok_or_else(|| {
                AppError::NotAvailable(format!(
                    "engine {} is no longer present in the installed catalog",
                    engine_run.engine_id
                ))
            })?;
            if let Some((_, explanation)) = engine_unavailable(manifest, self.adapters) {
                return Err(AppError::NotAvailable(format!(
                    "engine {} cannot be resumed: {explanation}",
                    engine_run.engine_id
                )));
            }
            validate_resume_manifest_identity(engine_run, manifest)?;
            let assets = engine_run
                .asset_ids
                .iter()
                .map(|asset_id| {
                    case.assets
                        .iter()
                        .find(|asset| asset.id == *asset_id)
                        .cloned()
                        .ok_or_else(|| {
                            AppError::InvalidRequest(format!(
                                "resume target asset is no longer present: {asset_id}"
                            ))
                        })
                })
                .collect::<AppResult<Vec<_>>>()?;
            let compatible_ids =
                compatible_authorized_assets(&case, manifest, &frozen_effective_grants, now)
                    .into_iter()
                    .map(|asset| asset.id.as_str())
                    .collect::<BTreeSet<_>>();
            if assets
                .iter()
                .any(|asset| !compatible_ids.contains(asset.id.as_str()))
            {
                return Err(AppError::NotAuthorized(format!(
                    "the original scope no longer authorizes every target for engine {}",
                    engine_run.engine_id
                )));
            }
            let relevant_grants = frozen_effective_grants
                .iter()
                .copied()
                .filter(|grant| {
                    engine_run.asset_ids.contains(&grant.asset_id)
                        && (manifest.required_permissions.contains(&grant.permission)
                            || (manifest.active_external
                                && grant.permission == ScanPermission::ActiveExternalTesting))
                })
                .cloned()
                .collect::<Vec<_>>();
            let resumed_scope_sha256 = comparable_scope_contract_sha256(
                manifest,
                &assets.iter().collect::<Vec<_>>(),
                &relevant_grants,
            )?;
            if engine_run.scope_contract_sha256.as_deref() != Some(resumed_scope_sha256.as_str()) {
                return Err(AppError::NotAuthorized(format!(
                    "engine {} cannot be resumed because its permission or target contract differs from the exact contract frozen into this run",
                    engine_run.engine_id
                )));
            }
            let previous = engine_run
                .resume_token
                .as_deref()
                .map(ExecutionCheckpoint::from_resume_token)
                .transpose()?;
            let attempt = match previous.as_ref().map(ExecutionCheckpoint::resume_action) {
                Some(crate::orchestrator::ResumeAction::AdaptCapturedArtifacts) => previous
                    .as_ref()
                    .map(|checkpoint| checkpoint.attempt)
                    .unwrap_or(1),
                _ => previous
                    .as_ref()
                    .map(|checkpoint| checkpoint.attempt)
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| AppError::Runtime("execution attempt overflowed".into()))?,
            };
            candidates.push(ResumeCandidate {
                engine_index,
                stale_warning: stale_knowledge_warning(manifest, now),
                execution: PlannedEngineExecution {
                    case_id: case.id.clone(),
                    scan_run_id: run.id.clone(),
                    engine_run_id: engine_run.id.clone(),
                    attempt,
                    manifest: manifest.clone(),
                    assets,
                    scope_grants: relevant_grants,
                    resume_checkpoint: previous,
                },
            });
        }
        if candidates.is_empty() {
            return Err(AppError::InvalidRequest(
                "scan has no interrupted or retryable engine runs".into(),
            ));
        }

        let preview = ScanPlan {
            scan_run: case.scan_runs[run_index].clone(),
            executable: candidates
                .iter()
                .map(|candidate| candidate.execution.clone())
                .collect(),
            not_executed: Vec::new(),
        };
        pre_persist(&preview)?;

        for candidate in &candidates {
            let engine_run = &mut case.scan_runs[run_index].engine_runs[candidate.engine_index];
            engine_run.status = EngineRunStatus::Queued;
            engine_run.phase = "queued_for_resume".into();
            engine_run.progress_percent = 0;
            engine_run.started_at = None;
            engine_run.finished_at = None;
            engine_run.error_code = None;
            engine_run.error_message = None;
            if let Some(warning) = candidate.stale_warning.as_ref()
                && !engine_run.warnings.contains(warning)
            {
                engine_run.warnings.push(warning.clone());
            }
        }
        case.scan_runs[run_index].completed_at = None;
        case.status = if case.scan_runs[run_index]
            .verification_baseline_run_id
            .is_some()
        {
            CaseStatus::Verifying
        } else {
            CaseStatus::Scanning
        };
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), now);
        self.storage.save_case(&mut case, "scan.resume_planned")?;

        Ok(ScanPlan {
            scan_run: case.scan_runs[run_index].clone(),
            executable: candidates
                .into_iter()
                .map(|candidate| candidate.execution)
                .collect(),
            not_executed: Vec::new(),
        })
    }

    pub fn apply_execution_report(
        &self,
        case_id: &str,
        report: &DurableExecutionReport,
    ) -> AppResult<ExecutionApplyResult> {
        let mut last_conflict = None;
        for _ in 0..3 {
            match self.apply_execution_report_once(case_id, report) {
                Ok(applied) => return Ok(applied),
                Err(error @ AppError::Conflict(_)) => last_conflict = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_conflict.expect("bounded execution report retry recorded a conflict"))
    }

    fn apply_execution_report_once(
        &self,
        case_id: &str,
        report: &DurableExecutionReport,
    ) -> AppResult<ExecutionApplyResult> {
        let mut case = self.mutable_case(case_id, "apply scanner output")?;
        validate_report_identity(&case, report)?;
        if report_already_applied(&case, report)? {
            return Ok(ExecutionApplyResult {
                case,
                idempotent_replay: true,
            });
        }

        let validated_checkpoint_token = report.checkpoint.resume_token()?;

        let run_index = case
            .scan_runs
            .iter()
            .position(|run| run.id == report.checkpoint.scan_run_id)
            .ok_or_else(|| AppError::InvalidRequest("scan run not found".into()))?;
        let engine_index = case.scan_runs[run_index]
            .engine_runs
            .iter()
            .position(|run| run.id == report.checkpoint.engine_run_id)
            .ok_or_else(|| AppError::InvalidRequest("engine run not found".into()))?;
        if case.scan_runs[run_index].engine_runs[engine_index].status
            == EngineRunStatus::NotExecuted
        {
            return Err(AppError::NotAuthorized(
                "a not-executed planning record cannot accept scanner output".into(),
            ));
        }
        validate_checkpoint_progress(
            &case.scan_runs[run_index].engine_runs[engine_index],
            &report.checkpoint,
            &validated_checkpoint_token,
        )?;

        validate_report_payload(
            &case,
            &case.scan_runs[run_index].engine_runs[engine_index],
            report,
        )?;
        validate_artifact_files(&self.artifact_root, &report.raw_artifacts)?;
        for artifact in &report.raw_artifacts {
            insert_or_validate_artifact(&mut case, artifact)?;
        }
        for finding in &report.findings {
            // Keep the durable engine report immutable. Contextual priority is
            // a bounded case projection: it may add explainable ordering
            // reasons, but it cannot change source severity, evidence, scope,
            // or the scanner's canonical observation identity.
            let mut contextual_finding = finding.clone();
            crate::prioritization::apply_case_context(&case, &mut contextual_finding);
            reconcile_finding(&mut case, &contextual_finding, &report.checkpoint.engine_id)?;
        }

        let now = Utc::now();
        let engine_run = &mut case.scan_runs[run_index].engine_runs[engine_index];
        engine_run.status = status_for_stage(&report.checkpoint.stage);
        engine_run.phase = enum_key(&report.checkpoint.stage);
        engine_run.progress_percent = progress_for_stage(&report.checkpoint.stage);
        engine_run.resume_token = Some(validated_checkpoint_token);
        engine_run.error_message = report.checkpoint.last_error.clone();
        engine_run.error_code = report
            .checkpoint
            .last_error
            .as_ref()
            .map(|_| "execution_failed".into());
        if let Some(preflight) = &report.runtime_preflight {
            engine_run.runtime_provider = Some(enum_key(&preflight.provider));
            engine_run.runtime_version = Some(preflight.server_version.clone());
            engine_run.runtime_security_options = Some(preflight.security_options.clone());
        }
        if let Some(exit_code) = report.exit_code {
            engine_run.exit_code = Some(exit_code);
        }
        if let Some(cleanup) = &report.cleanup {
            engine_run.cleanup_removed = Some(cleanup.removed);
            engine_run.cleanup_detail = Some(cleanup.detail.clone());
        }
        for warning in &report.warnings {
            if !engine_run.warnings.contains(warning) {
                engine_run.warnings.push(warning.clone());
            }
        }
        if engine_run.started_at.is_none()
            && !matches!(report.checkpoint.stage, ExecutionStage::Planned)
        {
            engine_run.started_at = Some(now);
        }
        if engine_status_terminal(&engine_run.status) {
            engine_run.finished_at = Some(now);
        }
        for artifact_id in &report.checkpoint.artifact_ids {
            if !engine_run.raw_artifact_ids.contains(artifact_id) {
                engine_run.raw_artifact_ids.push(artifact_id.clone());
            }
        }
        engine_run.raw_artifact_ids.sort();

        update_run_and_case_status(&mut case, run_index, now);
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), now);
        self.storage
            .save_case(&mut case, "execution.report_applied")?;
        Ok(ExecutionApplyResult {
            case,
            idempotent_replay: false,
        })
    }

    pub fn pause_scan(&self, case_id: &str, run_id: &str) -> AppResult<AssessmentCase> {
        self.transition_scan(case_id, run_id, ScanTransition::Pause)
    }

    pub fn resume_scan(&self, case_id: &str, run_id: &str) -> AppResult<AssessmentCase> {
        self.transition_scan(case_id, run_id, ScanTransition::Resume)
    }

    pub fn cancel_scan(&self, case_id: &str, run_id: &str) -> AppResult<AssessmentCase> {
        self.transition_scan(case_id, run_id, ScanTransition::Cancel)
    }

    fn transition_scan(
        &self,
        case_id: &str,
        run_id: &str,
        transition: ScanTransition,
    ) -> AppResult<AssessmentCase> {
        let mut case = self.mutable_case(case_id, transition.action_name())?;
        let now = Utc::now();
        let run_index = case
            .scan_runs
            .iter()
            .position(|run| run.id == run_id)
            .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
        if matches!(transition, ScanTransition::Resume | ScanTransition::Cancel)
            && case.scan_runs[run_index]
                .engine_runs
                .iter()
                .any(|engine_run| {
                    matches!(
                        engine_run.phase.as_str(),
                        "interrupted_restart" | "interrupted_restart_cleanup_pending"
                    )
                })
        {
            return Err(AppError::NotAvailable(
                "the interrupted run still has an exact runtime cleanup obligation; reconcile it before changing terminal or resume state"
                    .into(),
            ));
        }
        let mut changed = false;
        for engine_run in &mut case.scan_runs[run_index].engine_runs {
            match transition {
                ScanTransition::Pause
                    if matches!(
                        engine_run.status,
                        EngineRunStatus::Queued
                            | EngineRunStatus::Preparing
                            | EngineRunStatus::Running
                    ) =>
                {
                    engine_run.status = EngineRunStatus::Paused;
                    engine_run.phase = "paused".into();
                    changed = true;
                }
                ScanTransition::Resume
                    if engine_run.status == EngineRunStatus::Paused
                        || (matches!(
                            engine_run.status,
                            EngineRunStatus::Failed
                                | EngineRunStatus::PartiallyCompleted
                                | EngineRunStatus::Cancelled
                        ) && engine_run.resume_token.is_some()) =>
                {
                    engine_run.status = EngineRunStatus::Queued;
                    engine_run.phase = "queued_for_resume".into();
                    engine_run.finished_at = None;
                    engine_run.error_code = None;
                    engine_run.error_message = None;
                    changed = true;
                }
                ScanTransition::Cancel
                    if matches!(
                        engine_run.status,
                        EngineRunStatus::Queued
                            | EngineRunStatus::Preparing
                            | EngineRunStatus::Running
                            | EngineRunStatus::Paused
                    ) =>
                {
                    engine_run.status = EngineRunStatus::Cancelled;
                    engine_run.phase = "cancelled".into();
                    engine_run.finished_at = Some(now);
                    changed = true;
                }
                _ => {}
            }
        }
        if !changed {
            return Err(AppError::InvalidRequest(format!(
                "scan has no engine runs eligible to {}",
                transition.verb()
            )));
        }
        update_run_and_case_status(&mut case, run_index, now);
        case.touch();
        refresh_coverage_ledger(&mut case, self.engines.manifests(), now);
        self.storage.save_case(&mut case, transition.event_name())?;
        Ok(case)
    }

    pub fn preview_export(
        &self,
        case_id: &str,
        run_id: &str,
        format: CaseExportFormat,
        options: &ExportOptions,
    ) -> AppResult<ExportPreview> {
        if options.include_raw_artifacts && format != CaseExportFormat::CaseBundle {
            return Err(AppError::InvalidRequest(
                "raw artifacts can only be included in the signed case bundle format".into(),
            ));
        }
        let case = self.storage.get_case(case_id)?;
        let selected_run = case
            .scan_runs
            .iter()
            .find(|run| run.id == run_id)
            .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
        if selected_run.case_id != case.id {
            return Err(AppError::InvalidRequest(
                "scan run does not belong to the selected case".into(),
            ));
        }

        let selected_finding_ids = case
            .finding_observations
            .iter()
            .filter(|observation| observation.run_id == run_id)
            .map(|observation| observation.finding_id.as_str())
            .collect::<BTreeSet<_>>();
        let findings_by_id = case
            .findings
            .iter()
            .map(|finding| (finding.id.as_str(), finding))
            .collect::<BTreeMap<_, _>>();
        let mut evidence_ids = BTreeSet::new();
        let mut selected_run_evidence_ids = BTreeSet::new();
        for observation in &case.finding_observations {
            let finding = observation
                .finding_snapshot
                .as_ref()
                .or_else(|| findings_by_id.get(observation.finding_id.as_str()).copied());
            if let Some(finding) = finding {
                for evidence in finding
                    .evidence
                    .iter()
                    .filter(|evidence| evidence.run_id == observation.run_id)
                {
                    evidence_ids.insert(evidence.id.as_str());
                    if observation.run_id == run_id {
                        selected_run_evidence_ids.insert(evidence.id.as_str());
                    }
                }
            }
        }
        for evidence in case.findings.iter().flat_map(|finding| &finding.evidence) {
            evidence_ids.insert(evidence.id.as_str());
            if evidence.run_id == run_id {
                selected_run_evidence_ids.insert(evidence.id.as_str());
            }
        }
        let evidence_index_count = evidence_ids.len();
        let selected_run_evidence_count = selected_run_evidence_ids.len();
        let include_raw_bytes =
            format == CaseExportFormat::CaseBundle && options.include_raw_artifacts;
        let raw_artifacts_included = case
            .raw_artifacts
            .iter()
            .filter(|artifact| {
                include_raw_bytes
                    && !(options.redaction == crate::export::RedactionProfile::Standard
                        && artifact.contains_sensitive_data)
            })
            .count();
        let raw_artifact_count = case.raw_artifacts.len();
        let raw_artifacts_omitted = raw_artifact_count.saturating_sub(raw_artifacts_included);
        let sensitive_raw_artifacts_omitted = case
            .raw_artifacts
            .iter()
            .filter(|artifact| {
                artifact.contains_sensitive_data
                    && !(include_raw_bytes
                        && options.redaction != crate::export::RedactionProfile::Standard)
            })
            .count();
        let sensitive_raw_artifacts_included = case
            .raw_artifacts
            .iter()
            .filter(|artifact| {
                artifact.contains_sensitive_data
                    && include_raw_bytes
                    && options.redaction != crate::export::RedactionProfile::Standard
            })
            .count();
        let sensitive_data_warning = if options.redaction
            != crate::export::RedactionProfile::Standard
        {
            format!(
                "Standard redaction is disabled. Canonical security details remain identifiable, and {sensitive_raw_artifacts_included} raw artifact(s) marked sensitive will be included."
            )
        } else if sensitive_raw_artifacts_omitted > 0 {
            format!(
                "Standard redaction is enabled and will omit {sensitive_raw_artifacts_omitted} raw artifact(s) marked sensitive. The export still contains security-sensitive findings and hashes."
            )
        } else {
            "Standard redaction is enabled. The export still contains security-sensitive findings and hashes; confirm the recipient and storage location.".into()
        };
        let engine_runs = case
            .scan_runs
            .iter()
            .flat_map(|run| &run.engine_runs)
            .collect::<Vec<_>>();

        Ok(ExportPreview {
            case_id: case.id.clone(),
            run_id: selected_run.id.clone(),
            format: format.as_str().into(),
            redaction_profile: options.redaction.as_str().into(),
            data_source_count: case.data_sources.len(),
            coverage_entry_count: case.coverage.len(),
            asset_count: case.assets.len(),
            candidate_asset_count: case.assets.iter().filter(|asset| asset.candidate).count(),
            canonical_finding_count: case.findings.len(),
            selected_run_finding_count: selected_finding_ids.len(),
            evidence_index_count,
            selected_run_evidence_count,
            scan_run_count: case.scan_runs.len(),
            selected_engine_run_count: selected_run.engine_runs.len(),
            external_scope_grant_count: case
                .scope_grants
                .iter()
                .filter(|grant| grant.external_scope.is_some())
                .count(),
            incomplete_engine_run_count: engine_runs
                .iter()
                .filter(|engine_run| {
                    matches!(
                        engine_run.status,
                        EngineRunStatus::PartiallyCompleted
                            | EngineRunStatus::Failed
                            | EngineRunStatus::Cancelled
                    )
                })
                .count(),
            not_executed_engine_run_count: engine_runs
                .iter()
                .filter(|engine_run| engine_run.status == EngineRunStatus::NotExecuted)
                .count(),
            unknown_source_count: case
                .coverage
                .iter()
                .filter(|entry| entry.status == CoverageStatus::SourceNotConnectedUnknown)
                .count(),
            connected_no_asset_count: case
                .coverage
                .iter()
                .filter(|entry| entry.status == CoverageStatus::SourceConnectedNothingDiscovered)
                .count(),
            raw_artifact_count,
            raw_artifacts_included,
            raw_artifacts_omitted,
            sensitive_raw_artifacts_omitted,
            sensitive_data_warning,
        })
    }

    pub fn export_bundle(
        &self,
        case_id: &str,
        run_id: &str,
        destination: impl AsRef<Path>,
        options: ExportOptions,
    ) -> AppResult<CaseExport> {
        let mut case = self.storage.get_case(case_id)?;
        let export = create_case_bundle(
            &case,
            run_id,
            &self.artifact_root,
            destination,
            &self.signing_key_path,
            options,
        )?;
        case.exports.push(export.clone());
        case.touch();
        self.storage.save_case(&mut case, "export.bundle_created")?;
        Ok(export)
    }

    /// Unified five-format export entry point used by desktop and CLI. Every
    /// format requires a caller-selected destination and refuses overwrite.
    pub fn export_case(
        &self,
        case_id: &str,
        run_id: &str,
        format: CaseExportFormat,
        destination: impl AsRef<Path>,
        options: ExportOptions,
    ) -> AppResult<CaseExport> {
        if options.include_raw_artifacts && format != CaseExportFormat::CaseBundle {
            return Err(AppError::InvalidRequest(
                "raw artifacts can only be included in the signed case bundle format".into(),
            ));
        }
        match format {
            CaseExportFormat::CaseBundle => {
                self.export_bundle(case_id, run_id, destination, options)
            }
            format => self.export_document(case_id, run_id, format, destination, options),
        }
    }

    pub fn export_schema(
        &self,
        case_id: &str,
        run_id: &str,
        format: SchemaExportFormat,
        destination: impl AsRef<Path>,
    ) -> AppResult<CaseExport> {
        self.export_document(
            case_id,
            run_id,
            format,
            destination,
            ExportOptions::default(),
        )
    }

    pub fn export_document(
        &self,
        case_id: &str,
        run_id: &str,
        format: CaseExportFormat,
        destination: impl AsRef<Path>,
        options: ExportOptions,
    ) -> AppResult<CaseExport> {
        let mut case = self.storage.get_case(case_id)?;
        let selected_run = case
            .scan_runs
            .iter()
            .find(|run| run.id == run_id)
            .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
        if selected_run.case_id != case.id {
            return Err(AppError::InvalidRequest(
                "scan run does not belong to the selected case".into(),
            ));
        }
        let document_case = case_for_document_export(&case, &options);
        let bytes = match format {
            CaseExportFormat::CanonicalJson => canonical_json_bytes(&case, run_id, &options)?,
            CaseExportFormat::OcsfJson => export_ocsf_finding_events_bytes(&document_case, run_id)?,
            CaseExportFormat::OscalJson => {
                export_oscal_assessment_results_bytes(&document_case, run_id)?
            }
            CaseExportFormat::Html => html_report_bytes(&case, run_id, &options)?,
            CaseExportFormat::CaseBundle => {
                return Err(AppError::InvalidRequest(
                    "case bundles must be created through export_case or export_bundle".into(),
                ));
            }
        };
        let path = write_new_private_file(destination.as_ref(), &bytes)?;
        let export = CaseExport {
            id: new_id(),
            case_id: case.id.clone(),
            run_id: run_id.to_owned(),
            created_at: Utc::now(),
            format: Some(format.as_str().into()),
            path: path.display().to_string(),
            sha256: sha256_bytes(&bytes),
            signature: None,
            public_key: None,
            redaction_profile: options.redaction.as_str().into(),
            raw_artifacts_included: Some(0),
            raw_artifacts_omitted: Some(case.raw_artifacts.len()),
            integrity_only_notice: UNSIGNED_SCHEMA_NOTICE.into(),
        };
        case.exports.push(export.clone());
        case.touch();
        self.storage.save_case(&mut case, "export.schema_created")?;
        Ok(export)
    }

    pub fn verify_stored_export(
        &self,
        case_id: &str,
        export_id: &str,
    ) -> AppResult<StoredExportVerification> {
        let case = self.storage.get_case(case_id)?;
        let stored = case
            .exports
            .iter()
            .find(|export| export.id == export_id)
            .ok_or_else(|| AppError::InvalidRequest(format!("export not found: {export_id}")))?;
        let observed_sha256 = sha256_file(Path::new(&stored.path))?;
        if stored.signature.is_some() || stored.public_key.is_some() {
            let public_key = stored.public_key.as_deref().ok_or_else(|| {
                AppError::InvalidRequest("signed export record has no stored public key".into())
            })?;
            let bundle =
                verify_case_bundle_against(&stored.path, Some(&stored.sha256), Some(public_key))?;
            return Ok(StoredExportVerification {
                valid: bundle.valid,
                export_id: stored.id.clone(),
                path: stored.path.clone(),
                observed_sha256,
                expected_sha256: stored.sha256.clone(),
                bundle: Some(bundle),
                integrity_only_notice: INTEGRITY_ONLY_NOTICE.into(),
            });
        }
        let valid = observed_sha256.eq_ignore_ascii_case(&stored.sha256);
        if !valid {
            return Err(AppError::InvalidRequest(format!(
                "export hash mismatch: expected {}, observed {observed_sha256}",
                stored.sha256
            )));
        }
        Ok(StoredExportVerification {
            valid,
            export_id: stored.id.clone(),
            path: stored.path.clone(),
            observed_sha256,
            expected_sha256: stored.sha256.clone(),
            bundle: None,
            integrity_only_notice: UNSIGNED_SCHEMA_NOTICE.into(),
        })
    }

    pub fn compare_and_persist(
        &self,
        case_id: &str,
        baseline_run_id: &str,
        current_run_id: &str,
    ) -> AppResult<VerificationComparison> {
        let mut case = self.mutable_case(case_id, "persist a run comparison")?;
        if let Some(existing) = case.comparisons.iter().find(|comparison| {
            comparison.baseline_run_id == baseline_run_id
                && comparison.current_run_id == current_run_id
        }) {
            return Ok(existing.clone());
        }
        let comparison = compare_case_runs(&case, baseline_run_id, current_run_id)?;
        case.comparisons.push(comparison.clone());
        case.status = if comparison.complete {
            CaseStatus::ReadyForHandoff
        } else {
            CaseStatus::NeedsAttention
        };
        case.touch();
        self.storage.save_case(&mut case, "verification.compared")?;
        Ok(comparison)
    }

    /// Completes a durable verification intent once its current run reaches a
    /// terminal state. Returning an existing comparison makes replay from the
    /// worker callback and startup reconciliation safe and idempotent.
    pub fn finalize_verification_if_terminal(
        &self,
        case_id: &str,
        current_run_id: &str,
    ) -> AppResult<Option<VerificationComparison>> {
        let case = self.storage.get_case(case_id)?;
        let current = case
            .scan_runs
            .iter()
            .find(|run| run.id == current_run_id)
            .ok_or_else(|| {
                AppError::InvalidRequest(format!("current run not found: {current_run_id}"))
            })?;
        let Some(baseline_run_id) = current.verification_baseline_run_id.as_deref() else {
            return Ok(None);
        };
        if baseline_run_id == current_run_id {
            return Err(AppError::InvalidRequest(
                "verification baseline and current run must be different".into(),
            ));
        }
        let baseline = case
            .scan_runs
            .iter()
            .find(|run| run.id == baseline_run_id)
            .ok_or_else(|| {
                AppError::InvalidRequest(format!(
                    "verification baseline run not found: {baseline_run_id}"
                ))
            })?;
        if !run_is_terminal(baseline) {
            return Err(AppError::InvalidRequest(
                "verification baseline must remain terminal".into(),
            ));
        }
        if !run_is_terminal(current) {
            return Ok(None);
        }
        self.compare_and_persist(case_id, baseline_run_id, current_run_id)
            .map(Some)
    }

    /// Repairs the crash window between persisting a terminal verification run
    /// and persisting its comparison. Cases without durable verification intent
    /// are intentionally ignored for backward compatibility.
    pub fn reconcile_terminal_verifications(&self) -> AppResult<usize> {
        let mut pending = Vec::new();
        for summary in self.storage.list_cases()? {
            let case = self.storage.get_case(&summary.id)?;
            if case.status == CaseStatus::Archived || case.is_demo {
                continue;
            }
            pending.extend(case.scan_runs.iter().filter_map(|run| {
                let baseline_run_id = run.verification_baseline_run_id.as_ref()?;
                if !run_is_terminal(run)
                    || case.comparisons.iter().any(|comparison| {
                        comparison.baseline_run_id == *baseline_run_id
                            && comparison.current_run_id == run.id
                    })
                {
                    return None;
                }
                Some((case.id.clone(), run.id.clone()))
            }));
        }

        let mut reconciled = 0;
        for (case_id, current_run_id) in pending {
            if self
                .finalize_verification_if_terminal(&case_id, &current_run_id)?
                .is_some()
            {
                reconciled += 1;
            }
        }
        Ok(reconciled)
    }

    pub fn update_finding_workflow(
        &self,
        case_id: &str,
        request: FindingWorkflowRequest,
    ) -> AppResult<AssessmentCase> {
        let mut case = self.mutable_case(case_id, "change finding workflow")?;
        let now = Utc::now();
        let decided_by = required_text("finding decision actor", &request.decided_by, 120)?;
        let reason = required_text("finding decision reason", &request.reason, 2_000)?;
        if request.status != FindingStatus::FalsePositive && request.expires_at.is_some() {
            return Err(AppError::InvalidRequest(
                "only a false-positive decision may carry an expiry".into(),
            ));
        }
        if request.expires_at.is_some_and(|expires_at| {
            expires_at <= now || expires_at > now + chrono::Duration::days(365)
        }) {
            return Err(AppError::InvalidRequest(
                "finding decision expiry must be within the next 365 days".into(),
            ));
        }
        let finding_index = case
            .findings
            .iter()
            .position(|finding| finding.id == request.finding_id)
            .ok_or_else(|| {
                AppError::InvalidRequest(format!("finding not found: {}", request.finding_id))
            })?;
        if case.findings[finding_index].case_id != case.id {
            return Err(AppError::NotAuthorized(
                "finding does not belong to the selected case".into(),
            ));
        }
        let from_status = case.findings[finding_index].status.clone();
        if from_status == request.status {
            return Err(AppError::InvalidRequest(
                "finding already has the requested workflow status".into(),
            ));
        }
        if request.status == FindingStatus::VerifiedResolved {
            let fingerprint = &case.findings[finding_index].fingerprint;
            let verified = case.comparisons.iter().any(|comparison| {
                comparison.diffs.iter().any(|diff| {
                    diff.fingerprint == *fingerprint && diff.status == FindingDiffStatus::Resolved
                })
            });
            if !verified {
                return Err(AppError::InvalidRequest(
                    "a finding can be marked verified resolved only after a comparable rerun records it as resolved"
                        .into(),
                ));
            }
        }

        case.findings[finding_index].status = request.status.clone();
        case.finding_workflow_events.push(FindingWorkflowEvent {
            id: new_id(),
            case_id: case.id.clone(),
            finding_id: request.finding_id,
            from_status,
            to_status: request.status,
            decided_by,
            decided_at: now,
            reason,
            expires_at: request.expires_at,
        });
        case.touch();
        self.storage
            .save_case(&mut case, "finding.workflow_changed")?;
        Ok(case)
    }

    pub fn group_findings(
        &self,
        case_id: &str,
        request: FindingGroupRequest,
    ) -> AppResult<AssessmentCase> {
        let mut case = self.mutable_case(case_id, "group related findings")?;
        let title = required_text("finding group title", &request.title, 200)?;
        let rationale = required_text("finding group rationale", &request.rationale, 2_000)?;
        let grouped_by = required_text("finding group actor", &request.grouped_by, 120)?;
        if request.finding_ids.len() > MAX_FINDINGS_PER_GROUP {
            return Err(AppError::InvalidRequest(format!(
                "a finding group supports at most {MAX_FINDINGS_PER_GROUP} members"
            )));
        }
        let mut finding_ids = request.finding_ids;
        finding_ids.sort();
        finding_ids.dedup();
        if finding_ids.len() < 2 {
            return Err(AppError::InvalidRequest(
                "a finding group requires at least two distinct findings".into(),
            ));
        }
        let known = case
            .findings
            .iter()
            .filter(|finding| finding.case_id == case.id)
            .map(|finding| finding.id.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(unknown) = finding_ids
            .iter()
            .find(|finding_id| !known.contains(finding_id.as_str()))
        {
            return Err(AppError::InvalidRequest(format!(
                "finding does not belong to this case: {unknown}"
            )));
        }
        if let Some(overlap) = case.finding_groups.iter().find_map(|group| {
            group
                .finding_ids
                .iter()
                .find(|finding_id| finding_ids.contains(finding_id))
                .map(|finding_id| (group, finding_id))
        }) {
            return Err(AppError::InvalidRequest(format!(
                "finding {} is already in active group {}",
                overlap.1, overlap.0.id
            )));
        }

        let now = Utc::now();
        let group = FindingGroup {
            id: new_id(),
            case_id: case.id.clone(),
            title,
            finding_ids,
            rationale,
            grouped_by,
            created_at: now,
        };
        case.finding_group_events.push(FindingGroupEvent {
            id: new_id(),
            case_id: case.id.clone(),
            group_id: group.id.clone(),
            action: FindingGroupAction::Created,
            title: group.title.clone(),
            finding_ids: group.finding_ids.clone(),
            rationale: group.rationale.clone(),
            actor: group.grouped_by.clone(),
            occurred_at: now,
        });
        case.finding_groups.push(group);
        case.touch();
        self.storage.save_case(&mut case, "finding.group_created")?;
        Ok(case)
    }

    pub fn ungroup_findings(
        &self,
        case_id: &str,
        request: FindingUngroupRequest,
    ) -> AppResult<AssessmentCase> {
        let mut case = self.mutable_case(case_id, "remove a finding group")?;
        let actor = required_text("finding ungroup actor", &request.removed_by, 120)?;
        let reason = required_text("finding ungroup reason", &request.reason, 2_000)?;
        let index = case
            .finding_groups
            .iter()
            .position(|group| group.id == request.group_id)
            .ok_or_else(|| {
                AppError::InvalidRequest(format!("finding group not found: {}", request.group_id))
            })?;
        let group = case.finding_groups.remove(index);
        if group.case_id != case.id {
            return Err(AppError::NotAuthorized(
                "finding group does not belong to the selected case".into(),
            ));
        }
        case.finding_group_events.push(FindingGroupEvent {
            id: new_id(),
            case_id: case.id.clone(),
            group_id: group.id,
            action: FindingGroupAction::Removed,
            title: group.title,
            finding_ids: group.finding_ids,
            rationale: reason,
            actor,
            occurred_at: Utc::now(),
        });
        case.touch();
        self.storage.save_case(&mut case, "finding.group_removed")?;
        Ok(case)
    }

    fn mutable_case(&self, case_id: &str, action: &str) -> AppResult<AssessmentCase> {
        let case = self.storage.get_case(case_id)?;
        if case.is_demo {
            return Err(AppError::NotAuthorized(format!(
                "synthetic demo cases are immutable and cannot {action}"
            )));
        }
        if case.status == CaseStatus::Archived {
            return Err(AppError::InvalidRequest(format!(
                "archived cases cannot {action}; reopen by creating a new assessment case"
            )));
        }
        Ok(case)
    }
}

fn infer_assessment_intent(request: &CreateCaseRequest) -> Option<AssessmentIntent> {
    if request
        .declared_assets
        .iter()
        .any(|asset| asset.web_service.is_some())
    {
        return Some(AssessmentIntent::DeployedWebsite);
    }
    if let Some(asset) = request.declared_assets.first() {
        return Some(match asset.kind {
            DeclaredAssetKind::ExternalTarget if asset.internet_exposed == Some(false) => {
                AssessmentIntent::InternalItEnvironment
            }
            DeclaredAssetKind::ExternalTarget => AssessmentIntent::ExternalIpOrDomain,
            DeclaredAssetKind::Repository => AssessmentIntent::SourceCode,
            DeclaredAssetKind::IacProject => AssessmentIntent::InfrastructureAsCode,
            DeclaredAssetKind::ContainerImage => AssessmentIntent::ContainerImage,
            DeclaredAssetKind::KubernetesCluster => AssessmentIntent::Kubernetes,
        });
    }
    request
        .source_kinds
        .iter()
        .any(|kind| {
            matches!(
                kind,
                SourceKind::AwsOrganization
                    | SourceKind::AzureTenant
                    | SourceKind::GcpOrganization
                    | SourceKind::Microsoft365Tenant
            )
        })
        .then_some(AssessmentIntent::CloudAccount)
}

fn normalize_declared_assets(inputs: &[DeclaredAssetInput]) -> AppResult<Vec<DiscoveredAsset>> {
    if inputs.len() > MAX_DECLARED_ASSETS {
        return Err(AppError::InvalidRequest(format!(
            "a case questionnaire supports at most {MAX_DECLARED_ASSETS} known asset coordinates"
        )));
    }
    let mut assets = Vec::with_capacity(inputs.len());
    let mut identities = BTreeSet::new();
    for input in inputs {
        if input.web_service.is_some() && input.kind != DeclaredAssetKind::ExternalTarget {
            return Err(AppError::InvalidRequest(
                "website service context is only valid for one external hostname or address".into(),
            ));
        }
        let (kind, namespace, value, internet_exposed) = match input.kind {
            DeclaredAssetKind::ExternalTarget => {
                let target = CanonicalTarget::parse(&input.value)?;
                let internet_exposed = input.internet_exposed.unwrap_or(true);
                match target {
                    CanonicalTarget::Hostname(hostname) => (
                        AssetKind::Domain,
                        "dns_name",
                        hostname,
                        Some(internet_exposed),
                    ),
                    CanonicalTarget::Address(address) => (
                        AssetKind::IpAddress,
                        "ip_address",
                        address.to_string(),
                        Some(internet_exposed),
                    ),
                    CanonicalTarget::Network(network) => (
                        AssetKind::IpAddress,
                        "ip_network",
                        network.to_string(),
                        Some(internet_exposed),
                    ),
                }
            }
            DeclaredAssetKind::Repository => (
                AssetKind::Repository,
                "repository_locator",
                validate_declared_locator("repository coordinate", &input.value, 2_048)?,
                None,
            ),
            DeclaredAssetKind::IacProject => (
                AssetKind::IacProject,
                "iac_locator",
                validate_declared_locator("IaC project coordinate", &input.value, 2_048)?,
                None,
            ),
            DeclaredAssetKind::ContainerImage => (
                AssetKind::ContainerImage,
                "oci_image_digest",
                validate_declared_image(&input.value)?,
                None,
            ),
            DeclaredAssetKind::KubernetesCluster => (
                AssetKind::KubernetesCluster,
                "kubernetes_context",
                validate_declared_locator("Kubernetes cluster coordinate", &input.value, 512)?,
                None,
            ),
        };
        let identity = format!("{}\u{0}{namespace}\u{0}{value}", enum_key(&kind));
        if !identities.insert(identity) {
            continue;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "questionnaire_kind".into(),
            Value::String(enum_key(&input.kind)),
        );
        if let Some(service) = input.web_service.as_ref() {
            if namespace == "ip_network" {
                return Err(AppError::InvalidRequest(
                    "website service context must identify one hostname or address, not a network"
                        .into(),
                ));
            }
            metadata.insert(
                "declared_web_service".into(),
                validate_declared_web_service(service)?,
            );
        }
        assets.push(DiscoveredAsset {
            observation_key: format!("declared-{}", assets.len() + 1),
            kind,
            name: value.clone(),
            provider: None,
            region: None,
            stable_identifier: AssetIdentifier {
                namespace: namespace.into(),
                value,
            },
            additional_identifiers: vec![],
            internet_exposed,
            contains_sensitive_data: None,
            metadata,
        });
    }
    Ok(assets)
}

fn validate_declared_web_service(service: &DeclaredWebServiceInput) -> AppResult<Value> {
    if service.port == 0 {
        return Err(AppError::InvalidRequest(
            "website service port must be between 1 and 65535".into(),
        ));
    }
    if service.path.is_empty()
        || service.path.chars().count() > 2_048
        || !service.path.starts_with('/')
        || service.path.contains(['?', '#'])
        || service.path.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(
            "website service path must be one bounded path without query or fragment data".into(),
        ));
    }
    let protocol = match service.protocol {
        DeclaredWebProtocol::Http => "http",
        DeclaredWebProtocol::Https => "https",
    };
    Ok(serde_json::json!({
        "protocol": protocol,
        "port": service.port,
        "path": service.path,
    }))
}

fn validate_declared_locator(label: &str, value: &str, maximum: usize) -> AppResult<String> {
    let value = required_text(label, value, maximum)?;
    if value == "*" || value.chars().any(char::is_control) {
        return Err(AppError::InvalidRequest(format!(
            "{label} must be one bounded, non-wildcard coordinate"
        )));
    }
    if value.contains("://") {
        let parsed = url::Url::parse(&value)
            .map_err(|_| AppError::InvalidRequest(format!("{label} URL is malformed")))?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AppError::InvalidRequest(format!(
                "{label} URL must be credential-free HTTPS without query or fragment data"
            )));
        }
    }
    Ok(value)
}

fn validate_declared_image(value: &str) -> AppResult<String> {
    let value = required_text("container image coordinate", value, 2_048)?;
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        return Err(AppError::InvalidRequest(
            "container images entered in the questionnaire must use repository@sha256:<64 lowercase hex>"
                .into(),
        ));
    };
    if repository.is_empty()
        || repository.starts_with(['-', '/'])
        || repository.contains("..")
        || repository.contains('@')
        || repository.chars().any(char::is_whitespace)
        || !repository.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '/' | ':' | '_' | '-')
        })
        || digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(AppError::InvalidRequest(
            "container image coordinate is not an exact lowercase OCI digest reference".into(),
        ));
    }
    Ok(format!("{repository}@sha256:{digest}"))
}

fn planned_source_label(kind: &SourceKind) -> &'static str {
    match kind {
        SourceKind::AwsOrganization => "AWS organization",
        SourceKind::AzureTenant => "Azure tenant",
        SourceKind::GcpOrganization => "Google Cloud organization",
        SourceKind::Microsoft365Tenant => "Microsoft 365 tenant",
        SourceKind::Dns => "DNS records",
        SourceKind::CertificateTransparency => "Certificate transparency",
        SourceKind::Billing => "Billing export",
        SourceKind::GitRepository => "Git repositories",
        SourceKind::TerraformState => "Terraform state",
        SourceKind::KubernetesCluster => "Kubernetes clusters",
        SourceKind::ContainerRegistry => "Container registries",
        SourceKind::FileSystem => "Local filesystems",
        SourceKind::UserDeclared => "User-declared assets",
    }
}

fn ensure_no_active_scan(case: &AssessmentCase, action: &str) -> AppResult<()> {
    if case.scan_runs.iter().any(|run| !run_is_terminal(run)) {
        return Err(AppError::InvalidRequest(format!(
            "cannot {action} while a scan is active or paused; the recorded scan contract is immutable"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ScanTransition {
    Pause,
    Resume,
    Cancel,
}

impl ScanTransition {
    fn action_name(self) -> &'static str {
        match self {
            Self::Pause => "pause a scan",
            Self::Resume => "resume a scan",
            Self::Cancel => "cancel a scan",
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
        }
    }

    fn event_name(self) -> &'static str {
        match self {
            Self::Pause => "scan.paused",
            Self::Resume => "scan.resumed",
            Self::Cancel => "scan.cancelled",
        }
    }
}

fn validate_source_mutation(request: &SourceMutation) -> AppResult<()> {
    required_text("data source label", &request.label, 200)?;
    if request
        .metadata
        .contains_key(SNAPSHOT_ARTIFACT_METADATA_KEY)
    {
        return Err(AppError::NotAuthorized(
            "connector artifact coordinates can only be attached by the backend ingestion boundary"
                .into(),
        ));
    }
    if request.status == SourceConnectionStatus::Connected && !request.read_only {
        return Err(AppError::NotAuthorized(
            "connected discovery sources must be explicitly read-only".into(),
        ));
    }
    let encoded = serde_json::to_vec(&request.metadata)?;
    if encoded.len() > MAX_METADATA_BYTES {
        return Err(AppError::InvalidRequest(format!(
            "data source metadata exceeds {MAX_METADATA_BYTES} bytes"
        )));
    }
    validate_non_secret_value(
        "metadata",
        &Value::Object(request.metadata.clone().into_iter().collect()),
    )
}

fn validate_snapshot_reference(reference: &SnapshotArtifactReference) -> AppResult<()> {
    if reference.schema_version != SNAPSHOT_REFERENCE_SCHEMA {
        return Err(AppError::InvalidRequest(
            "connector snapshot reference schema is unsupported".into(),
        ));
    }
    let snapshot_path = Path::new(&reference.canonical_relative_path);
    if reference.canonical_relative_path.len() > 255
        || snapshot_path.components().count() != 1
        || !matches!(
            snapshot_path.components().next(),
            Some(Component::Normal(_))
        )
        || !reference.canonical_relative_path.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(AppError::InvalidRequest(
            "connector snapshot path is not a bounded backend filename".into(),
        ));
    }
    for (label, value) in [
        ("connector artifact id", reference.artifact_id.as_str()),
        ("connector profile", reference.profile.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 512
            || !value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(AppError::InvalidRequest(format!("{label} is invalid")));
        }
    }
    let digest = reference.sha256.as_deref().ok_or_else(|| {
        AppError::InvalidRequest("connector snapshot reference has no integrity digest".into())
    })?;
    if digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(AppError::InvalidRequest(
            "connector snapshot reference has an invalid SHA-256 digest".into(),
        ));
    }
    if reference.observed_at > Utc::now() + chrono::Duration::minutes(5) {
        return Err(AppError::InvalidRequest(
            "connector snapshot observation time is implausibly far in the future".into(),
        ));
    }
    Ok(())
}

fn validate_live_provider_artifact_set(artifacts: &LiveProviderArtifactSet) -> AppResult<()> {
    let expected_operation = match artifacts.profile.as_str() {
        "aws-organizations-list-accounts" => "organizations:ListAccounts",
        "azure-resource-manager-resources" => "resource-manager:ListResources",
        "gcp-resource-manager-projects" => "cloud-resource-manager:ListProjects",
        "microsoft-graph-directory-inventory" => "microsoft-graph:DirectoryInventory",
        _ => {
            return Err(AppError::InvalidRequest(
                "live provider artifact parser profile is not supported".into(),
            ));
        }
    };
    if artifacts.schema_version != LIVE_PROVIDER_ARTIFACT_SET_SCHEMA
        || artifacts.operation != expected_operation
        || artifacts.capture_id.is_empty()
        || artifacts.capture_id.len() > 128
        || !artifacts
            .capture_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || artifacts.pages.is_empty()
        || artifacts.pages.len() > MAX_LIVE_PROVIDER_PAGES
        || artifacts.observed_at > Utc::now() + chrono::Duration::minutes(5)
    {
        return Err(AppError::InvalidRequest(
            "live provider artifact set is malformed or outside limits".into(),
        ));
    }
    for (index, page) in artifacts.pages.iter().enumerate() {
        if usize::from(page.sequence) != index + 1
            || page.operation.is_empty()
            || page.operation.len() > 128
            || page.operation.chars().any(char::is_control)
            || !(100..=599).contains(&page.http_status)
            || (page.parser_eligible && !(200..300).contains(&page.http_status))
            || page.artifact.profile != artifacts.profile
            || page.artifact.observed_at != artifacts.observed_at
        {
            return Err(AppError::InvalidRequest(
                "live provider artifact page is malformed".into(),
            ));
        }
        validate_snapshot_reference(&page.artifact)?;
    }
    Ok(())
}

fn validate_non_secret_value(path: &str, value: &Value) -> AppResult<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let normalized = key.to_ascii_lowercase().replace(['-', '.', ' '], "_");
                let compact = normalized.replace('_', "");
                let prohibited = [
                    "password",
                    "passwd",
                    "api_key",
                    "apikey",
                    "access_token",
                    "refresh_token",
                    "client_secret",
                    "private_key",
                    "credentials",
                    "credential",
                    "session_token",
                ];
                let prohibited_compact = [
                    "password",
                    "passwd",
                    "apikey",
                    "accesstoken",
                    "refreshtoken",
                    "clientsecret",
                    "privatekey",
                    "credentials",
                    "credential",
                    "sessiontoken",
                ];
                if normalized.starts_with("ai_security_scanner_")
                    || prohibited.iter().any(|name| {
                        normalized == *name || normalized.ends_with(&format!("_{name}"))
                    })
                    || prohibited_compact
                        .iter()
                        .any(|name| compact == *name || compact.ends_with(name))
                {
                    return Err(AppError::InvalidRequest(format!(
                        "{path}.{key} is reserved or appears to be secret-bearing metadata"
                    )));
                }
                validate_non_secret_value(&format!("{path}.{key}"), value)?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_non_secret_value(&format!("{path}[{index}]"), value)?;
            }
        }
        Value::String(value) => {
            let trimmed = value.trim();
            let looks_secret = trimmed.contains("-----BEGIN PRIVATE KEY-----")
                || trimmed.contains("-----BEGIN RSA PRIVATE KEY-----")
                || trimmed.to_ascii_lowercase().starts_with("bearer ")
                || trimmed.starts_with("ghp_")
                || trimmed.starts_with("github_pat_")
                || (trimmed.starts_with("AKIA")
                    && trimmed.len() == 20
                    && trimmed
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric()));
            if looks_secret {
                return Err(AppError::InvalidRequest(format!(
                    "{path} appears to contain secret material"
                )));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_scope_approval(request: &ScopeApprovalRequest, now: DateTime<Utc>) -> AppResult<()> {
    required_text("asset id", &request.asset_id, 200)?;
    required_text("scope confirmer", &request.confirmed_by, 200)?;
    if request.permissions.is_empty() {
        return Err(AppError::InvalidRequest(
            "at least one scan permission must be selected".into(),
        ));
    }
    if request
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(AppError::InvalidRequest(
            "scope expiry must be in the future".into(),
        ));
    }
    if request
        .permissions
        .iter()
        .any(is_direct_external_permission)
        && trim_option(request.authorization_reference.as_deref()).is_none()
    {
        return Err(AppError::NotAuthorized(
            "external connection or active testing requires an authorization reference".into(),
        ));
    }
    let external_permissions = request
        .permissions
        .iter()
        .filter(|permission| is_external_permission(permission))
        .map(enum_key)
        .collect::<BTreeSet<_>>()
        .len();
    if external_permissions > 1 {
        return Err(AppError::InvalidRequest(
            "approve passive, low-impact, and active external activity as separate bounded decisions"
                .into(),
        ));
    }
    if external_permissions == 1 && request.external_scope.is_none() {
        return Err(AppError::NotAuthorized(
            "external activity requires a canonical target, ports, protocol, rate, and template policy"
                .into(),
        ));
    }
    if external_permissions == 0 && request.external_scope.is_some() {
        return Err(AppError::InvalidRequest(
            "external scope details were supplied without an external permission".into(),
        ));
    }
    optional_text(
        "authorization reference",
        request.authorization_reference.as_deref(),
        1_000,
    )?;
    optional_text("scope notes", request.notes.as_deref(), 4_000)?;
    Ok(())
}

fn materialize_external_scope(
    case_id: &str,
    asset: &Asset,
    grant_id: &str,
    permission: &ScanPermission,
    request: &ScopeApprovalRequest,
    now: DateTime<Utc>,
) -> AppResult<Option<ExternalScopeGrant>> {
    if !is_external_permission(permission) {
        return Ok(None);
    }
    let external = request
        .external_scope
        .as_ref()
        .ok_or_else(|| AppError::NotAuthorized("external scope policy is required".into()))?;
    let expected_activity = match permission {
        ScanPermission::PassiveExternalDiscovery => ExternalActivity::PassivePublicDiscovery,
        ScanPermission::LowImpactExternalConnection => ExternalActivity::LowImpactExternal,
        ScanPermission::ActiveExternalTesting => ExternalActivity::ActiveExternal,
        _ => unreachable!("external permission checked above"),
    };
    if external.activity != expected_activity {
        return Err(AppError::NotAuthorized(
            "external activity does not match the approved scan permission".into(),
        ));
    }
    let target = CanonicalTarget::parse(&external.target)?;
    if !asset_attributable_to_target(asset, &target) {
        return Err(AppError::NotAuthorized(
            "external target is not attributable to the selected discovered asset".into(),
        ));
    }
    if expected_activity != ExternalActivity::PassivePublicDiscovery {
        match asset.internet_exposed {
            Some(true) => {
                if external.allow_sensitive_networks {
                    return Err(AppError::InvalidRequest(
                        "a public target cannot request the private-network allowance".into(),
                    ));
                }
            }
            Some(false) => {
                if !external.allow_sensitive_networks {
                    return Err(AppError::NotAuthorized(
                        "an internal target requires the explicit private-network allowance".into(),
                    ));
                }
            }
            None => {
                return Err(AppError::NotAuthorized(
                    "direct network activity requires a confirmed public or internal target type"
                        .into(),
                ));
            }
        }
    }
    let expires_at = request.expires_at.ok_or_else(|| {
        AppError::NotAuthorized("external authorization requires an explicit expiry".into())
    })?;
    let grant = ExternalScopeGrant {
        id: grant_id.to_owned(),
        case_id: case_id.to_owned(),
        asset_id: asset.id.clone(),
        target,
        ports: external.ports.clone(),
        protocol: external.protocol,
        activity: external.activity,
        rate_policy: external.rate_policy.clone(),
        template_policy: external.template_policy.clone(),
        asserted_authority: external.asserted_authority.trim().to_owned(),
        approved_by: request.confirmed_by.trim().to_owned(),
        approved_at: now,
        expires_at,
        allow_sensitive_networks: external.allow_sensitive_networks,
    };
    grant.validate(now)?;
    Ok(Some(grant))
}

fn asset_attributable_to_target(asset: &Asset, target: &CanonicalTarget) -> bool {
    let expected = target.canonical_text();
    asset
        .identifiers
        .iter()
        .map(|identifier| identifier.value.as_str())
        .chain(std::iter::once(asset.name.as_str()))
        .any(|candidate| {
            CanonicalTarget::parse(candidate).is_ok_and(|parsed| parsed == *target)
                || url::Url::parse(candidate)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .and_then(|host| CanonicalTarget::parse(&host).ok())
                    .is_some_and(|parsed| parsed.canonical_text() == expected)
        })
}

fn scan_readiness_at(
    case: &AssessmentCase,
    engines: &EngineRegistry,
    adapters: &AdapterRegistry,
    now: DateTime<Utc>,
) -> ScanReadiness {
    let effective = effective_grants(case, now);
    let effective_asset_ids = effective
        .iter()
        .map(|grant| grant.asset_id.as_str())
        .collect::<BTreeSet<_>>();
    let authorized_target_ids = case
        .assets
        .iter()
        .filter(|asset| {
            asset.owner_confirmed
                && !asset.candidate
                && effective_asset_ids.contains(asset.id.as_str())
        })
        .map(|asset| asset.id.as_str())
        .collect::<BTreeSet<_>>();
    let compatible = engines
        .manifests()
        .iter()
        .filter(|manifest| {
            !compatible_authorized_assets(case, manifest, &effective, now).is_empty()
        })
        .collect::<Vec<_>>();
    let runnable_engine_count = compatible
        .iter()
        .filter(|manifest| engine_unavailable(manifest, adapters).is_none())
        .count();

    let (state, blocker_code, next_step) = if case.is_demo {
        (
            ScanReadinessState::CaseUnavailable,
            Some(ScanReadinessBlocker::DemoCase),
            Some(ScanReadinessNextStep::Cases),
        )
    } else if case.status == CaseStatus::Archived {
        (
            ScanReadinessState::CaseUnavailable,
            Some(ScanReadinessBlocker::ArchivedCase),
            Some(ScanReadinessNextStep::Cases),
        )
    } else if case.scan_runs.iter().any(|run| !run_is_terminal(run)) {
        (
            ScanReadinessState::ScanInProgress,
            Some(ScanReadinessBlocker::ScanAlreadyActive),
            Some(ScanReadinessNextStep::Progress),
        )
    } else if effective.is_empty() {
        (
            ScanReadinessState::ScopeRequired,
            Some(ScanReadinessBlocker::NoEffectiveScopeGrants),
            Some(ScanReadinessNextStep::Coverage),
        )
    } else if authorized_target_ids.is_empty() {
        (
            ScanReadinessState::OwnershipRequired,
            Some(ScanReadinessBlocker::NoOwnershipConfirmedTargets),
            Some(ScanReadinessNextStep::Coverage),
        )
    } else if compatible.is_empty() {
        (
            ScanReadinessState::NoCompatibleAuthorizedTargets,
            Some(ScanReadinessBlocker::NoCompatibleAuthorizedTargets),
            Some(ScanReadinessNextStep::Coverage),
        )
    } else if runnable_engine_count == 0 {
        (
            ScanReadinessState::NoRunnableAuthorizedTargets,
            Some(ScanReadinessBlocker::NoRunnableAuthorizedTargets),
            Some(ScanReadinessNextStep::ScannerSetup),
        )
    } else {
        (ScanReadinessState::Ready, None, None)
    };

    ScanReadiness {
        case_id: case.id.clone(),
        ready: state == ScanReadinessState::Ready,
        state,
        authorized_target_count: authorized_target_ids.len(),
        pending_target_count: case
            .assets
            .len()
            .saturating_sub(authorized_target_ids.len()),
        compatible_engine_count: compatible.len(),
        runnable_engine_count,
        blocker_code,
        next_step,
    }
}

pub(crate) fn scan_preflight_error(readiness: &ScanReadiness) -> AppError {
    let blocker = readiness
        .blocker_code
        .unwrap_or(ScanReadinessBlocker::NoRunnableAuthorizedTargets);
    let message = match blocker {
        ScanReadinessBlocker::DemoCase => {
            "the demo is read-only; create or select a real case before scanning"
        }
        ScanReadinessBlocker::ArchivedCase => {
            "archived cases cannot start a scan; create a new assessment case"
        }
        ScanReadinessBlocker::ScanAlreadyActive => "this case already has an active or paused scan",
        ScanReadinessBlocker::NoEffectiveScopeGrants => {
            "no unexpired explicit scope grant authorizes a target"
        }
        ScanReadinessBlocker::NoOwnershipConfirmedTargets => {
            "the effective scope does not include an ownership-confirmed target"
        }
        ScanReadinessBlocker::NoCompatibleAuthorizedTargets => {
            "no installed scanner supports an ownership-confirmed target with its required permissions"
        }
        ScanReadinessBlocker::NoRunnableAuthorizedTargets => {
            "no selected compatible scanner is currently runnable"
        }
        ScanReadinessBlocker::RuntimeUnavailable => {
            "scan tools are not running; open scanner setup and try again"
        }
        ScanReadinessBlocker::ProviderSourceRequired => {
            "the cloud source for this target must be selected before the scan can start"
        }
        ScanReadinessBlocker::ProviderCapabilityUnavailable => {
            "the cloud connection must be reconnected before this scan can start"
        }
        ScanReadinessBlocker::ProviderSourceAmbiguous => {
            "more than one cloud connection matches this target; select the exact connection"
        }
        ScanReadinessBlocker::ProviderAuthorizationBindingMismatch => {
            "the saved read-only authorization does not match this cloud source"
        }
        ScanReadinessBlocker::ProviderTargetBindingMismatch => {
            "the saved cloud connection does not match this scan target"
        }
        ScanReadinessBlocker::ProviderPreflightUnavailable => {
            "cloud readiness could not be checked; no scan started; retry the readiness check"
        }
    };
    let detail = format!(
        "{SCAN_PREFLIGHT_ERROR_PREFIX}:{}: {message}",
        blocker.as_str()
    );
    match blocker {
        ScanReadinessBlocker::NoEffectiveScopeGrants
        | ScanReadinessBlocker::NoOwnershipConfirmedTargets
        | ScanReadinessBlocker::DemoCase => AppError::NotAuthorized(detail),
        ScanReadinessBlocker::ArchivedCase | ScanReadinessBlocker::ScanAlreadyActive => {
            AppError::InvalidRequest(detail)
        }
        ScanReadinessBlocker::NoCompatibleAuthorizedTargets
        | ScanReadinessBlocker::NoRunnableAuthorizedTargets
        | ScanReadinessBlocker::RuntimeUnavailable
        | ScanReadinessBlocker::ProviderSourceRequired
        | ScanReadinessBlocker::ProviderCapabilityUnavailable
        | ScanReadinessBlocker::ProviderSourceAmbiguous
        | ScanReadinessBlocker::ProviderAuthorizationBindingMismatch
        | ScanReadinessBlocker::ProviderTargetBindingMismatch
        | ScanReadinessBlocker::ProviderPreflightUnavailable => AppError::NotAvailable(detail),
    }
}

fn selected_engine_ids(
    engines: &EngineRegistry,
    request: &ScanPlanRequest,
    case: &AssessmentCase,
    effective: &[&ScopeGrant],
    now: DateTime<Utc>,
) -> AppResult<Vec<String>> {
    let values = if request.engine_ids.is_empty() {
        engines
            .manifests()
            .iter()
            .filter(|manifest| {
                !compatible_authorized_assets(case, manifest, effective, now).is_empty()
            })
            .map(|manifest| manifest.id.clone())
            .collect::<Vec<_>>()
    } else {
        request.engine_ids.clone()
    };
    let mut selected = BTreeSet::new();
    for value in values {
        let value = required_text("engine id", &value, 200)?;
        if !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        {
            return Err(AppError::InvalidRequest(format!(
                "engine id contains unsupported characters: {value}"
            )));
        }
        selected.insert(value);
    }
    Ok(selected.into_iter().collect())
}

fn compatible_authorized_assets<'a>(
    case: &'a AssessmentCase,
    manifest: &EngineManifest,
    effective: &[&ScopeGrant],
    now: DateTime<Utc>,
) -> Vec<&'a Asset> {
    case.assets
        .iter()
        .filter(|asset| asset.owner_confirmed && !asset.candidate)
        .filter(|asset| manifest.supports_asset(asset))
        .filter(|asset| provider_target_metadata_matches(case, manifest, asset))
        .filter(|asset| local_input_metadata_matches(case, manifest, asset))
        .filter(|asset| {
            let grants = effective
                .iter()
                .copied()
                .filter(|grant| grant.asset_id == asset.id && grant_effective(grant, now))
                .collect::<Vec<_>>();
            manifest.required_permissions.iter().all(|required| {
                grants.iter().any(|grant| {
                    grant.permission == *required
                        && (!is_external_permission(required)
                            || (grant.external_scope.is_some()
                                && grant
                                    .authorization_reference
                                    .as_deref()
                                    .is_some_and(|value| !value.trim().is_empty())
                                && (!is_direct_external_permission(required)
                                    || grant.external_scope.as_ref().is_some_and(|scope| {
                                        manifest
                                            .direct_network_contract
                                            .as_ref()
                                            .is_some_and(|contract| contract.supports(scope))
                                    }))))
                })
            })
        })
        .collect()
}

fn local_input_metadata_matches(
    case: &AssessmentCase,
    manifest: &EngineManifest,
    asset: &Asset,
) -> bool {
    if !manifest
        .required_permissions
        .contains(&ScanPermission::LocalArtifactRead)
    {
        return true;
    }
    let Some(contract) = manifest
        .input_contracts
        .iter()
        .find(|contract| contract.asset_kind == asset.kind)
    else {
        return false;
    };
    let expected_sha = asset
        .metadata
        .get("workspace_snapshot_sha256")
        .and_then(Value::as_str);
    let mut references = asset.discovered_from.iter().filter_map(|source_id| {
        let source = case.data_sources.iter().find(|source| {
            source.id == *source_id
                && source.read_only
                && source.status == SourceConnectionStatus::Connected
        })?;
        let value = source
            .metadata
            .get(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY)?;
        serde_json::from_value::<WorkspaceSnapshotReference>(value.clone()).ok()
    });
    let Some(reference) = references.next() else {
        return false;
    };
    if references.next().is_some() {
        return false;
    }
    reference.schema_version == WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA
        && reference.working_tree_only
        && reference.input_profile == contract.input_profile
        && reference.input_profile.asset_kind() == asset.kind
        && expected_sha == Some(reference.sha256.as_str())
}

/// Provider discovery attribution is broader than scanner authorization. A
/// provider asset enters a plan only when its native identity and attributable
/// source agree with the provider-signed proof persisted for that source.
/// Runtime credential checkout independently revalidates the same relation.
fn provider_target_metadata_matches(
    case: &AssessmentCase,
    manifest: &EngineManifest,
    asset: &Asset,
) -> bool {
    if manifest.supported_providers.is_empty() {
        return true;
    }
    let Some(provider) = asset.provider.as_deref() else {
        return false;
    };
    if !manifest
        .supported_providers
        .iter()
        .any(|supported| supported == provider)
    {
        return false;
    }
    let (source_kind, expected_scope) = match provider {
        "aws" => {
            let Some(account_id) = exact_asset_identifier(asset, "aws_account_id") else {
                return false;
            };
            if asset.kind != AssetKind::CloudAccount
                || account_id.len() != 12
                || !account_id.bytes().all(|byte| byte.is_ascii_digit())
            {
                return false;
            }
            (
                SourceKind::AwsOrganization,
                format!("aws-account:{account_id}"),
            )
        }
        "azure" => {
            let Some(subscription_id) = exact_asset_identifier(asset, "azure_subscription_id")
            else {
                return false;
            };
            if asset.kind != AssetKind::Subscription
                || !valid_azure_subscription_id(subscription_id)
            {
                return false;
            }
            (
                SourceKind::AzureTenant,
                format!("azure-subscription:{subscription_id}"),
            )
        }
        "gcp" => {
            let Some(project_id) = exact_asset_identifier(asset, "gcp_project_id") else {
                return false;
            };
            if asset.kind != AssetKind::Project || !valid_gcp_project_id(project_id) {
                return false;
            }
            // The GCP credential proof is organization-bound; the exact
            // project binding is completed after selecting its unique source.
            (SourceKind::GcpOrganization, String::new())
        }
        "microsoft365" => {
            let Some(tenant_id) = exact_asset_identifier(asset, "microsoft_tenant_id") else {
                return false;
            };
            if asset.kind != AssetKind::Tenant || uuid::Uuid::parse_str(tenant_id).is_err() {
                return false;
            }
            (
                SourceKind::Microsoft365Tenant,
                format!("microsoft365-tenant:{tenant_id}"),
            )
        }
        _ => return false,
    };
    let mut attributable_sources = case.data_sources.iter().filter(|source| {
        asset.discovered_from.contains(&source.id)
            && source.kind == source_kind
            && source.read_only
            && source.status == SourceConnectionStatus::Connected
    });
    let Some(source) = attributable_sources.next() else {
        return false;
    };
    if attributable_sources.next().is_some() {
        return false;
    }
    let Some(proof_scope) = source
        .metadata
        .get(PROVIDER_RESOURCE_SCOPE_METADATA_KEY)
        .and_then(Value::as_str)
    else {
        return false;
    };
    if provider != "gcp" {
        return proof_scope == expected_scope;
    }
    let Some(organization_id) = proof_scope.strip_prefix("gcp-organization:") else {
        return false;
    };
    if organization_id.is_empty()
        || organization_id.len() > 32
        || !organization_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    case.asset_relations.iter().any(|relation| {
        relation.kind == crate::domain::RelationKind::Contains
            && relation.to_asset_id == asset.id
            && case.assets.iter().any(|parent| {
                parent.id == relation.from_asset_id
                    && parent.kind == AssetKind::CloudOrganization
                    && parent.provider.as_deref() == Some("gcp")
                    && parent.discovered_from.contains(&source.id)
                    && ["gcp_organization_id", "gcp_organization_number"]
                        .iter()
                        .any(|namespace| {
                            exact_asset_identifier(parent, namespace) == Some(organization_id)
                        })
            })
    })
}

fn exact_asset_identifier<'a>(asset: &'a Asset, namespace: &str) -> Option<&'a str> {
    let mut values = asset
        .identifiers
        .iter()
        .filter(|identifier| identifier.namespace == namespace)
        .map(|identifier| identifier.value.as_str());
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn engine_unavailable(
    manifest: &EngineManifest,
    adapters: &AdapterRegistry,
) -> Option<(String, String)> {
    if let Some(explanation) = manifest.release_blocker() {
        return Some(("engine_release_unavailable".into(), explanation));
    }
    match manifest.status {
        ManifestStatus::Deprecated => {
            return Some((
                "engine_deprecated".into(),
                "The engine manifest is deprecated and cannot be dispatched.".into(),
            ));
        }
        ManifestStatus::ResearchOnly => {
            return Some((
                "research_only".into(),
                "The engine is catalogued for research only and cannot be dispatched.".into(),
            ));
        }
        ManifestStatus::LicenseReview => {
            return Some((
                "license_review".into(),
                "The engine is awaiting distribution/license review and is not dispatched.".into(),
            ));
        }
        ManifestStatus::Integrated | ManifestStatus::Experimental => {}
    }
    let Some(adapter) = adapters.get(&manifest.id) else {
        return Some((
            "adapter_unavailable".into(),
            format!(
                "No adapter is loaded for engine {} version {}.",
                manifest.id, manifest.adapter_version
            ),
        ));
    };
    if adapter.adapter_version() != manifest.adapter_version {
        return Some((
            "adapter_version_mismatch".into(),
            format!(
                "Loaded adapter version {} does not match manifest version {}.",
                adapter.adapter_version(),
                manifest.adapter_version
            ),
        ));
    }
    if matches!(
        manifest.distribution_mode,
        DistributionMode::ExternalExecutable
    ) {
        return Some((
            "external_executable_unsupported".into(),
            "The constrained executor only accepts pinned container images.".into(),
        ));
    }
    let Some(image) = manifest.image.as_ref() else {
        return Some((
            "runtime_image_unavailable".into(),
            "No built runtime image is recorded for this pinned source revision.".into(),
        ));
    };
    if image.repository.trim().is_empty()
        || image
            .digest
            .as_deref()
            .is_none_or(|digest| !valid_sha256_digest(digest))
    {
        return Some((
            "runtime_image_unpinned".into(),
            "The runtime image is unavailable or lacks an immutable sha256 digest.".into(),
        ));
    }
    if manifest.command.is_empty() || manifest.command.iter().any(|part| part.trim().is_empty()) {
        return Some((
            "command_unavailable".into(),
            "The manifest has no complete static command.".into(),
        ));
    }
    None
}

fn not_executed_run(
    scan_run_id: &str,
    engine_run_id: &str,
    engine_id: &str,
    asset_ids: Vec<Id>,
    reason: (&str, &str),
    manifest: Option<&EngineManifest>,
    now: DateTime<Utc>,
) -> EngineRun {
    let (reason_code, explanation) = reason;
    let image = manifest.and_then(|value| value.image.as_ref());
    EngineRun {
        id: engine_run_id.into(),
        scan_run_id: scan_run_id.into(),
        engine_id: engine_id.into(),
        asset_ids,
        status: EngineRunStatus::NotExecuted,
        progress_percent: 0,
        phase: "not_executed".into(),
        started_at: None,
        finished_at: Some(now),
        resume_token: None,
        engine_version: manifest.and_then(|value| value.engine_version.clone()),
        image_digest: image.and_then(|value| value.digest.clone()),
        rule_version: manifest.and_then(|value| value.rule_version.clone()),
        adapter_version: manifest
            .map(|value| value.adapter_version.clone())
            .unwrap_or_else(|| "unavailable".into()),
        manifest_schema_version: manifest.map(|value| value.schema_version.clone()),
        source_revision: manifest.and_then(|value| value.source_revision.clone()),
        repository_url: manifest.map(|value| value.repository_url.clone()),
        distribution_mode: manifest.map(|value| value.distribution_mode.clone()),
        image_repository: image.map(|value| value.repository.clone()),
        command_sha256: manifest.and_then(|value| {
            serde_json::to_vec(&value.command)
                .ok()
                .map(|bytes| sha256_bytes(&bytes))
        }),
        knowledge_input: manifest.map(dated_knowledge_input),
        scope_contract_sha256: None,
        mapping_version: manifest
            .and_then(|_| control_mapping_version().ok())
            .map(str::to_owned),
        fingerprint_schema_version: manifest.map(|_| FINGERPRINT_SCHEMA_VERSION.to_owned()),
        runtime_provider: None,
        runtime_version: None,
        runtime_security_options: None,
        exit_code: None,
        cleanup_removed: None,
        cleanup_detail: None,
        warnings: manifest
            .and_then(|value| stale_knowledge_warning(value, now))
            .into_iter()
            .collect(),
        raw_artifact_ids: Vec::new(),
        error_code: Some(reason_code.into()),
        error_message: Some(explanation.into()),
    }
}

fn dated_knowledge_input(manifest: &EngineManifest) -> EngineKnowledgeInput {
    let mut input = manifest.compatibility.knowledge_input.clone();
    input.knowledge_date = Some(manifest.compatibility.knowledge_date.clone());
    input.support_until = Some(manifest.compatibility.support_until.clone());
    input
}

/// Build a deterministic execution-semantics contract. Approval actors,
/// timestamps, notes, and grant IDs remain preserved in `ScanRun` snapshots,
/// but are excluded here because they do not change what the engine can read or
/// target. That keeps a semantically identical re-approval comparable while
/// still failing closed for permission, target, rate, template, or asset drift.
fn comparable_scope_contract_sha256(
    manifest: &EngineManifest,
    assets: &[&Asset],
    grants: &[ScopeGrant],
) -> AppResult<String> {
    let direct_external = manifest.required_permissions.iter().any(|permission| {
        matches!(
            permission,
            ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
        )
    });
    let mut required_permissions = manifest
        .required_permissions
        .iter()
        .map(enum_key)
        .collect::<Vec<_>>();
    required_permissions.sort();

    let mut asset_documents = Vec::with_capacity(assets.len());
    for asset in assets {
        let relevant = grants
            .iter()
            .filter(|grant| grant.asset_id == asset.id)
            .collect::<Vec<_>>();
        let external_targets = if direct_external {
            relevant
                .iter()
                .filter_map(|grant| grant.external_scope.as_ref())
                .map(|external| external.target.canonical_text())
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };

        let mut identifiers = asset
            .identifiers
            .iter()
            .filter(|identifier| {
                external_targets.is_empty() || external_targets.contains(&identifier.value)
            })
            .map(|identifier| {
                serde_json::json!({
                    "namespace": identifier.namespace,
                    "value": identifier.value,
                })
            })
            .collect::<Vec<_>>();
        identifiers.sort_by_key(|left| left.to_string());

        let mut grant_documents = relevant
            .into_iter()
            .map(|grant| {
                let external_scope = grant.external_scope.as_ref().map(|external| {
                    let mut template_ids = external.template_policy.allowed_template_ids.clone();
                    template_ids.sort();
                    serde_json::json!({
                        "target": external.target.canonical_text(),
                        "ports": external.ports.iter().copied().collect::<Vec<_>>(),
                        "protocol": enum_key(&external.protocol),
                        "activity": enum_key(&external.activity),
                        "rate_policy": {
                            "requests_per_second": external.rate_policy.requests_per_second,
                            "concurrency": external.rate_policy.concurrency,
                            "timeout_seconds": external.rate_policy.timeout_seconds,
                        },
                        "template_policy": {
                            "revision": external.template_policy.revision,
                            "allowed_template_ids": template_ids,
                            "allow_headless": external.template_policy.allow_headless,
                            "allow_out_of_band": external.template_policy.allow_out_of_band,
                            "allow_fuzzing": external.template_policy.allow_fuzzing,
                            "allow_file_upload": external.template_policy.allow_file_upload,
                            "allow_denial_of_service": external.template_policy.allow_denial_of_service,
                            "allow_credential_attacks": external.template_policy.allow_credential_attacks,
                        },
                        "allow_sensitive_networks": external.allow_sensitive_networks,
                    })
                });
                serde_json::json!({
                    "permission": enum_key(&grant.permission),
                    "authorization_reference_present": grant
                        .authorization_reference
                        .as_deref()
                        .is_some_and(|reference| !reference.trim().is_empty()),
                    "external_scope": external_scope,
                })
            })
            .collect::<Vec<_>>();
        grant_documents.sort_by_key(|left| left.to_string());

        let provider_execution = if manifest.provider_execution_contracts.is_empty() {
            Value::Null
        } else {
            let contract = manifest
                .provider_execution_contract(asset.provider.as_deref(), &asset.kind)
                .ok_or_else(|| {
                    AppError::EngineRegistry(format!(
                        "engine {} has no provider execution contract for asset {}",
                        manifest.id, asset.id
                    ))
                })?;
            let mut destinations = contract.network_destinations.clone();
            destinations.sort();
            serde_json::json!({
                "provider": contract.provider,
                "asset_kind": enum_key(&contract.asset_kind),
                "profile": contract.profile,
                "network_destinations": destinations,
            })
        };

        asset_documents.push(serde_json::json!({
            "id": asset.id,
            "kind": enum_key(&asset.kind),
            "provider": asset.provider,
            "region": asset.region,
            "identifiers": identifiers,
            "grants": grant_documents,
            "provider_execution": provider_execution,
        }));
    }
    asset_documents.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });

    let document = serde_json::json!({
        "schema_version": "1",
        "engine_id": manifest.id,
        "active_external": manifest.active_external,
        "required_permissions": required_permissions,
        "assets": asset_documents,
    });
    Ok(sha256_bytes(&serde_json::to_vec(&document)?))
}

fn frozen_scope_grants(grants: &[&ScopeGrant]) -> Vec<ScopeGrant> {
    let mut snapshots = grants
        .iter()
        .map(|grant| (*grant).clone())
        .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
        left.asset_id
            .cmp(&right.asset_id)
            .then_with(|| enum_key(&left.permission).cmp(&enum_key(&right.permission)))
            .then_with(|| left.id.cmp(&right.id))
    });
    snapshots
}

fn stale_knowledge_warning(manifest: &EngineManifest, as_of: DateTime<Utc>) -> Option<String> {
    let support_until =
        NaiveDate::parse_from_str(&manifest.compatibility.support_until, "%Y-%m-%d").ok()?;
    (support_until < as_of.date_naive()).then(|| {
        format!(
            "Engine {} uses knowledge dated {} whose declared support ended {}. Execution retains this explicit stale-knowledge warning; its results must not be presented as current knowledge.",
            manifest.id, manifest.compatibility.knowledge_date, manifest.compatibility.support_until
        )
    })
}

fn validate_resume_manifest_identity(
    engine_run: &EngineRun,
    manifest: &EngineManifest,
) -> AppResult<()> {
    let image = manifest.image.as_ref();
    let command_sha256 = sha256_bytes(&serde_json::to_vec(&manifest.command)?);
    let mapping_version = control_mapping_version()?;
    let identity_matches = engine_run.manifest_schema_version.as_deref()
        == Some(manifest.schema_version.as_str())
        && engine_run.engine_version == manifest.engine_version
        && engine_run.image_digest == image.and_then(|value| value.digest.clone())
        && engine_run.rule_version == manifest.rule_version
        && engine_run.adapter_version == manifest.adapter_version
        && engine_run.source_revision == manifest.source_revision
        && engine_run.repository_url.as_deref() == Some(manifest.repository_url.as_str())
        && engine_run.distribution_mode.as_ref() == Some(&manifest.distribution_mode)
        && engine_run.image_repository.as_deref() == image.map(|value| value.repository.as_str())
        && engine_run.command_sha256.as_deref() == Some(command_sha256.as_str())
        && engine_run.knowledge_input.as_ref() == Some(&dated_knowledge_input(manifest))
        && engine_run.mapping_version.as_deref() == Some(mapping_version)
        && engine_run.fingerprint_schema_version.as_deref() == Some(FINGERPRINT_SCHEMA_VERSION);
    if !identity_matches {
        return Err(AppError::NotAvailable(format!(
            "engine {} cannot be resumed because its current release manifest differs from the exact version, image, command, adapter, mapping/fingerprint schema, or knowledge window frozen into this run",
            engine_run.engine_id
        )));
    }
    Ok(())
}

fn validate_report_identity(
    case: &AssessmentCase,
    report: &DurableExecutionReport,
) -> AppResult<()> {
    if report.checkpoint.case_id != case.id {
        return Err(AppError::NotAuthorized(
            "execution report belongs to a different case".into(),
        ));
    }
    if report.checkpoint.attempt == 0 {
        return Err(AppError::InvalidRequest(
            "execution report attempt must start at one".into(),
        ));
    }
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == report.checkpoint.scan_run_id)
        .ok_or_else(|| AppError::InvalidRequest("execution report scan run not found".into()))?;
    if run.case_id != case.id {
        return Err(AppError::NotAuthorized(
            "stored scan run belongs to a different case".into(),
        ));
    }
    let engine_run = run
        .engine_runs
        .iter()
        .find(|engine_run| engine_run.id == report.checkpoint.engine_run_id)
        .ok_or_else(|| AppError::InvalidRequest("execution report engine run not found".into()))?;
    if engine_run.engine_id != report.checkpoint.engine_id {
        return Err(AppError::NotAuthorized(
            "execution report engine identity does not match the plan".into(),
        ));
    }
    if report.checkpoint.stage == ExecutionStage::Completed {
        if !report.checkpoint.cleanup_completed {
            return Err(AppError::Runtime(
                "completed execution report has not completed cleanup".into(),
            ));
        }
        if report.exit_code.is_some_and(|code| code != 0) {
            return Err(AppError::Runtime(
                "a non-zero scanner exit cannot be recorded as completed".into(),
            ));
        }
    }
    Ok(())
}

fn validate_report_payload(
    case: &AssessmentCase,
    engine_run: &EngineRun,
    report: &DurableExecutionReport,
) -> AppResult<()> {
    if report.warnings.len() > 256 {
        return Err(AppError::Runtime(
            "execution report contains too many warnings".into(),
        ));
    }
    let merged_warning_count = engine_run
        .warnings
        .iter()
        .chain(&report.warnings)
        .collect::<BTreeSet<_>>()
        .len();
    if merged_warning_count > 256 {
        return Err(AppError::Runtime(
            "execution warning history exceeds its durable storage boundary".into(),
        ));
    }
    for warning in &report.warnings {
        validate_report_text("execution warning", warning, 4_000)?;
    }
    if let Some(preflight) = &report.runtime_preflight {
        if report.checkpoint.runtime_provider != Some(preflight.provider)
            || report.checkpoint.runtime_command_provenance.as_ref()
                != Some(&preflight.command_provenance)
        {
            return Err(AppError::Runtime(
                "runtime preflight conflicts with durable checkpoint provenance".into(),
            ));
        }
        validate_report_text("runtime server version", &preflight.server_version, 256)?;
        validate_report_text(
            "runtime security options",
            &preflight.security_options,
            8_192,
        )?;
    }
    if let Some(cleanup) = &report.cleanup {
        validate_report_text("runtime cleanup detail", &cleanup.detail, 4_000)?;
    }
    let checkpoint_artifacts = report
        .checkpoint
        .artifact_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let report_artifacts = report
        .raw_artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<BTreeSet<_>>();
    if checkpoint_artifacts != report_artifacts {
        return Err(AppError::Runtime(
            "checkpoint artifact IDs do not exactly match the durable report".into(),
        ));
    }
    if report_artifacts.len() != report.raw_artifacts.len() {
        return Err(AppError::Runtime(
            "execution report contains duplicate artifact IDs".into(),
        ));
    }
    for artifact in &report.raw_artifacts {
        if artifact.case_id != case.id
            || artifact.run_id != report.checkpoint.scan_run_id
            || artifact.engine_run_id != engine_run.id
            || artifact.sha256.len() != 64
            || !artifact
                .sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(AppError::NotAuthorized(format!(
                "artifact {} has invalid provenance or digest",
                artifact.id
            )));
        }
    }
    let allowed_assets = engine_run.asset_ids.iter().collect::<BTreeSet<_>>();
    for finding in &report.findings {
        if finding.case_id != case.id
            || finding.last_seen_run_id != report.checkpoint.scan_run_id
            || finding.fingerprint.trim().is_empty()
            || finding.asset_ids.is_empty()
            || finding
                .asset_ids
                .iter()
                .any(|id| !allowed_assets.contains(id))
            || finding.evidence.is_empty()
        {
            return Err(AppError::NotAuthorized(format!(
                "finding {} is outside the planned case, run, assets, or has no evidence",
                finding.id
            )));
        }
        for evidence in &finding.evidence {
            let artifact = report
                .raw_artifacts
                .iter()
                .find(|artifact| artifact.id == evidence.artifact_id)
                .or_else(|| {
                    case.raw_artifacts
                        .iter()
                        .find(|artifact| artifact.id == evidence.artifact_id)
                })
                .ok_or_else(|| {
                    AppError::Runtime(format!(
                        "finding evidence refers to missing artifact {}",
                        evidence.artifact_id
                    ))
                })?;
            if evidence.finding_id != finding.id
                || evidence.run_id != report.checkpoint.scan_run_id
                || evidence.engine_run_id.as_deref()
                    != Some(report.checkpoint.engine_run_id.as_str())
                || evidence.engine_id != report.checkpoint.engine_id
                || artifact.engine_run_id != report.checkpoint.engine_run_id
                || !evidence
                    .artifact_sha256
                    .eq_ignore_ascii_case(&artifact.sha256)
            {
                return Err(AppError::NotAuthorized(
                    "finding evidence provenance does not match the execution report".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_report_text(label: &str, value: &str, maximum_chars: usize) -> AppResult<()> {
    if value.chars().count() > maximum_chars || value.contains('\0') {
        return Err(AppError::Runtime(format!(
            "{label} exceeds its durable storage boundary"
        )));
    }
    Ok(())
}

fn validate_artifact_files(artifact_root: &Path, artifacts: &[RawArtifact]) -> AppResult<()> {
    if artifacts.is_empty() {
        return Ok(());
    }
    let root = fs::canonicalize(artifact_root).map_err(|error| {
        AppError::Runtime(format!(
            "artifact root {} is unavailable: {error}",
            artifact_root.display()
        ))
    })?;
    for artifact in artifacts {
        let relative = Path::new(&artifact.relative_path);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || artifact.relative_path.contains(['\\', '\0'])
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(AppError::Runtime(format!(
                "artifact {} has an unsafe relative path",
                artifact.id
            )));
        }
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            AppError::Runtime(format!(
                "artifact {} is not available for durable reconciliation: {error}",
                artifact.id
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AppError::Runtime(format!(
                "artifact {} must be a regular non-symlink file",
                artifact.id
            )));
        }
        let canonical = fs::canonicalize(&path)?;
        if !canonical.starts_with(&root) {
            return Err(AppError::Runtime(format!(
                "artifact {} escapes the private artifact root",
                artifact.id
            )));
        }
        if metadata.len() != artifact.byte_length {
            return Err(AppError::Runtime(format!(
                "artifact {} byte length differs from its durable record",
                artifact.id
            )));
        }
        let observed_sha256 = sha256_file(&canonical)?;
        if !observed_sha256.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(AppError::Runtime(format!(
                "artifact {} hash differs from its durable record",
                artifact.id
            )));
        }
    }
    Ok(())
}

fn validate_checkpoint_progress(
    engine_run: &EngineRun,
    incoming: &ExecutionCheckpoint,
    incoming_token: &str,
) -> AppResult<()> {
    let Some(existing_token) = engine_run.resume_token.as_deref() else {
        return Ok(());
    };
    if existing_token == incoming_token {
        // An exact token with a non-identical payload was not accepted by the
        // idempotency check. Treat the durable checkpoint as immutable.
        return Err(AppError::Runtime(
            "execution report payload conflicts with an already applied checkpoint".into(),
        ));
    }
    let existing = ExecutionCheckpoint::from_resume_token(existing_token)?;
    if incoming.attempt < existing.attempt {
        return Err(AppError::Runtime(
            "stale execution attempt cannot replace a newer checkpoint".into(),
        ));
    }
    if incoming.attempt == existing.attempt {
        if matches!(
            existing.stage,
            ExecutionStage::Completed | ExecutionStage::Cancelled | ExecutionStage::Failed
        ) {
            return Err(AppError::Runtime(
                "a terminal checkpoint can only be retried with a higher attempt number".into(),
            ));
        }
        if execution_stage_rank(&incoming.stage) < execution_stage_rank(&existing.stage) {
            return Err(AppError::Runtime(
                "stale execution stage cannot regress a durable checkpoint".into(),
            ));
        }
    }
    Ok(())
}

fn execution_stage_rank(stage: &ExecutionStage) -> u8 {
    match stage {
        ExecutionStage::Planned => 0,
        ExecutionStage::Preflight => 1,
        ExecutionStage::PullingImage => 2,
        ExecutionStage::Running => 3,
        ExecutionStage::CapturingArtifacts => 4,
        ExecutionStage::AdaptingArtifacts | ExecutionStage::CapturedAwaitingAdapter => 5,
        ExecutionStage::CleanupPending => 6,
        ExecutionStage::Completed | ExecutionStage::Cancelled | ExecutionStage::Failed => 7,
    }
}

fn report_already_applied(
    case: &AssessmentCase,
    report: &DurableExecutionReport,
) -> AppResult<bool> {
    let checkpoint = serde_json::to_string(&report.checkpoint)
        .map_err(|error| AppError::Runtime(format!("checkpoint encode failed: {error}")))?;
    let Some(engine_run) = case
        .scan_runs
        .iter()
        .flat_map(|run| &run.engine_runs)
        .find(|engine_run| engine_run.id == report.checkpoint.engine_run_id)
    else {
        return Ok(false);
    };
    if engine_run.resume_token.as_deref() != Some(checkpoint.as_str()) {
        return Ok(false);
    }
    if let Some(preflight) = &report.runtime_preflight {
        let matches_runtime = engine_run.runtime_provider.as_deref()
            == Some(enum_key(&preflight.provider).as_str())
            && engine_run.runtime_version.as_deref() == Some(preflight.server_version.as_str())
            && engine_run.runtime_security_options.as_deref()
                == Some(preflight.security_options.as_str());
        if !matches_runtime {
            return Err(AppError::Runtime(
                "runtime provenance conflicts with an already applied checkpoint".into(),
            ));
        }
    }
    if report
        .exit_code
        .is_some_and(|exit_code| engine_run.exit_code != Some(exit_code))
    {
        return Err(AppError::Runtime(
            "runtime exit code conflicts with an already applied checkpoint".into(),
        ));
    }
    if let Some(cleanup) = &report.cleanup
        && (engine_run.cleanup_removed != Some(cleanup.removed)
            || engine_run.cleanup_detail.as_deref() != Some(cleanup.detail.as_str()))
    {
        return Err(AppError::Runtime(
            "runtime cleanup outcome conflicts with an already applied checkpoint".into(),
        ));
    }
    if report
        .warnings
        .iter()
        .any(|warning| !engine_run.warnings.contains(warning))
    {
        return Err(AppError::Runtime(
            "execution warnings conflict with an already applied checkpoint".into(),
        ));
    }
    for artifact in &report.raw_artifacts {
        let Some(existing) = case
            .raw_artifacts
            .iter()
            .find(|value| value.id == artifact.id)
        else {
            return Ok(false);
        };
        if serde_json::to_value(existing)? != serde_json::to_value(artifact)? {
            return Err(AppError::Runtime(format!(
                "artifact {} conflicts with its previously applied value",
                artifact.id
            )));
        }
    }
    for finding in &report.findings {
        let evidence_hashes = canonical_evidence_hashes(finding);
        let Some(observation) = case.finding_observations.iter().find(|observation| {
            observation.run_id == report.checkpoint.scan_run_id
                && observation.fingerprint == finding.fingerprint
        }) else {
            return Ok(false);
        };
        if observation
            .asset_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != finding.asset_ids.iter().cloned().collect()
            || observation
                .evidence_hashes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                != evidence_hashes.into_iter().collect()
            || !observation
                .engine_ids
                .contains(&report.checkpoint.engine_id)
        {
            return Err(AppError::Runtime(format!(
                "finding {} conflicts with its previously applied observation",
                finding.fingerprint
            )));
        }
    }
    Ok(true)
}

fn insert_or_validate_artifact(case: &mut AssessmentCase, artifact: &RawArtifact) -> AppResult<()> {
    if let Some(existing) = case
        .raw_artifacts
        .iter()
        .find(|value| value.id == artifact.id)
    {
        if serde_json::to_value(existing)? != serde_json::to_value(artifact)? {
            return Err(AppError::Runtime(format!(
                "artifact {} conflicts with an existing record",
                artifact.id
            )));
        }
    } else {
        case.raw_artifacts.push(artifact.clone());
    }
    Ok(())
}

fn reconcile_finding(
    case: &mut AssessmentCase,
    incoming: &Finding,
    engine_id: &str,
) -> AppResult<()> {
    let run_id = incoming.last_seen_run_id.clone();
    let evidence_hashes = canonical_evidence_hashes(incoming);
    let mut asset_ids = incoming.asset_ids.clone();
    asset_ids.sort();
    asset_ids.dedup();
    if let Some(existing_observation) = case.finding_observations.iter().find(|observation| {
        observation.run_id == run_id && observation.fingerprint == incoming.fingerprint
    }) {
        if existing_observation.asset_ids != asset_ids
            || existing_observation.evidence_hashes != evidence_hashes
            || !existing_observation
                .engine_ids
                .contains(&engine_id.to_owned())
        {
            return Err(AppError::Runtime(format!(
                "conflicting duplicate observation for fingerprint {}",
                incoming.fingerprint
            )));
        }
        return Ok(());
    }

    let canonical_id;
    if let Some(index) = case
        .findings
        .iter()
        .position(|finding| finding.fingerprint == incoming.fingerprint)
    {
        let prior_id = case.findings[index].id.clone();
        let first_seen = case.findings[index].first_seen_run_id.clone();
        let review_status = case.findings[index].status.clone();
        let mut replacement = incoming.clone();
        replacement.id = prior_id.clone();
        replacement.first_seen_run_id = first_seen;
        replacement.status = review_status;
        for evidence in &mut replacement.evidence {
            evidence.finding_id = prior_id.clone();
        }
        case.findings[index] = replacement;
        canonical_id = prior_id;
    } else {
        case.findings.push(incoming.clone());
        canonical_id = incoming.id.clone();
    }

    let finding_snapshot = case
        .findings
        .iter()
        .find(|finding| finding.id == canonical_id)
        .cloned()
        .ok_or_else(|| AppError::Runtime("canonical finding projection disappeared".into()))?;
    let observed_at = finding_snapshot
        .evidence
        .iter()
        .map(|evidence| evidence.observed_at)
        .max()
        .unwrap_or_else(Utc::now);
    case.finding_observations.push(FindingObservation {
        id: deterministic_observation_id(&run_id, &incoming.fingerprint),
        run_id,
        finding_id: canonical_id,
        fingerprint: incoming.fingerprint.clone(),
        asset_ids,
        engine_ids: vec![engine_id.to_owned()],
        severity: incoming.severity.clone(),
        confidence: incoming.confidence.clone(),
        evidence_hashes,
        observed_at,
        finding_snapshot: Some(finding_snapshot),
    });
    Ok(())
}

fn update_run_and_case_status(case: &mut AssessmentCase, run_index: usize, now: DateTime<Utc>) {
    let run = &mut case.scan_runs[run_index];
    if run_is_terminal(run) {
        run.completed_at = Some(now);
        case.status = if run
            .engine_runs
            .iter()
            .all(|engine_run| engine_run.status == EngineRunStatus::Completed)
        {
            CaseStatus::ReadyForHandoff
        } else {
            CaseStatus::NeedsAttention
        };
    } else if run
        .engine_runs
        .iter()
        .any(|engine_run| engine_run.status == EngineRunStatus::Paused)
    {
        run.completed_at = None;
        case.status = CaseStatus::NeedsAttention;
    } else {
        run.completed_at = None;
        case.status = if run.verification_baseline_run_id.is_some() {
            CaseStatus::Verifying
        } else {
            CaseStatus::Scanning
        };
    }
}

fn status_for_stage(stage: &ExecutionStage) -> EngineRunStatus {
    match stage {
        ExecutionStage::Planned => EngineRunStatus::Queued,
        ExecutionStage::Preflight | ExecutionStage::PullingImage => EngineRunStatus::Preparing,
        ExecutionStage::Running
        | ExecutionStage::CapturingArtifacts
        | ExecutionStage::AdaptingArtifacts => EngineRunStatus::Running,
        ExecutionStage::CapturedAwaitingAdapter | ExecutionStage::CleanupPending => {
            EngineRunStatus::PartiallyCompleted
        }
        ExecutionStage::Completed => EngineRunStatus::Completed,
        ExecutionStage::Cancelled => EngineRunStatus::Cancelled,
        ExecutionStage::Failed => EngineRunStatus::Failed,
    }
}

fn progress_for_stage(stage: &ExecutionStage) -> u8 {
    match stage {
        ExecutionStage::Planned => 0,
        ExecutionStage::Preflight => 5,
        ExecutionStage::PullingImage => 15,
        ExecutionStage::Running => 45,
        ExecutionStage::CapturingArtifacts => 70,
        ExecutionStage::AdaptingArtifacts | ExecutionStage::CapturedAwaitingAdapter => 85,
        ExecutionStage::CleanupPending => 95,
        ExecutionStage::Completed => 100,
        ExecutionStage::Cancelled | ExecutionStage::Failed => 0,
    }
}

fn effective_grants(case: &AssessmentCase, now: DateTime<Utc>) -> Vec<&ScopeGrant> {
    case.scope_grants
        .iter()
        .filter(|grant| grant_effective(grant, now))
        .collect()
}

fn grant_effective(grant: &ScopeGrant, now: DateTime<Utc>) -> bool {
    grant.confirmed_at <= now
        && !grant.confirmed_by.trim().is_empty()
        && grant.expires_at.is_none_or(|expires_at| expires_at > now)
        && (!is_direct_external_permission(&grant.permission)
            || grant
                .authorization_reference
                .as_deref()
                .is_some_and(|reference| !reference.trim().is_empty()))
}

fn is_external_permission(permission: &ScanPermission) -> bool {
    matches!(
        permission,
        ScanPermission::PassiveExternalDiscovery
            | ScanPermission::LowImpactExternalConnection
            | ScanPermission::ActiveExternalTesting
    )
}

fn is_direct_external_permission(permission: &ScanPermission) -> bool {
    matches!(
        permission,
        ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
    )
}

fn engine_status_terminal(status: &EngineRunStatus) -> bool {
    matches!(
        status,
        EngineRunStatus::NotExecuted
            | EngineRunStatus::Completed
            | EngineRunStatus::PartiallyCompleted
            | EngineRunStatus::Failed
            | EngineRunStatus::Cancelled
    )
}

fn run_is_terminal(run: &ScanRun) -> bool {
    !run.engine_runs.is_empty()
        && run
            .engine_runs
            .iter()
            .all(|engine_run| engine_status_terminal(&engine_run.status))
}

fn canonical_evidence_hashes(finding: &Finding) -> Vec<String> {
    let mut values = finding
        .evidence
        .iter()
        .map(|evidence| evidence.artifact_sha256.to_ascii_lowercase())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn deterministic_observation_id(run_id: &str, fingerprint: &str) -> String {
    let digest =
        Sha256::digest(format!("finding-observation/v1\u{0}{run_id}\u{0}{fingerprint}").as_bytes());
    format!("observation-{}", &hex::encode(digest)[..32])
}

fn grant_key(asset_id: &str, permission: &ScanPermission) -> String {
    format!("{asset_id}\u{0}{}", enum_key(permission))
}

fn enum_key<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
    })
}

fn required_text(label: &str, value: &str, max_chars: usize) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::InvalidRequest(format!("{label} is required")));
    }
    if value.chars().count() > max_chars || value.contains(['\0', '\r']) {
        return Err(AppError::InvalidRequest(format!(
            "{label} exceeds its safe length or contains invalid characters"
        )));
    }
    Ok(value.to_owned())
}

fn optional_text(label: &str, value: Option<&str>, max_chars: usize) -> AppResult<Option<String>> {
    let Some(value) = trim_option(value) else {
        return Ok(None);
    };
    if value.chars().count() > max_chars || value.contains(['\0', '\r']) {
        return Err(AppError::InvalidRequest(format!(
            "{label} exceeds its safe length or contains invalid characters"
        )));
    }
    Ok(Some(value))
}

fn trim_option(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn safe_path_component<'a>(label: &str, value: &'a str) -> AppResult<&'a str> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(format!(
            "{label} contains unsafe path characters"
        )));
    }
    Ok(value)
}

fn validate_destination(destination: &Path) -> AppResult<()> {
    if destination.as_os_str().is_empty()
        || destination.file_name().is_none()
        || destination
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(AppError::InvalidRequest(
            "export destination must be an explicit file path without parent traversal".into(),
        ));
    }
    if fs::symlink_metadata(destination).is_ok() {
        return Err(AppError::InvalidRequest(format!(
            "export destination already exists: {}",
            destination.display()
        )));
    }
    Ok(())
}

fn write_new_private_file(destination: &Path, bytes: &[u8]) -> AppResult<PathBuf> {
    validate_destination(destination)?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent)?;
    let file_name = destination
        .file_name()
        .ok_or_else(|| AppError::InvalidRequest("export filename is required".into()))?;
    let path = parent.join(file_name);
    if fs::symlink_metadata(&path).is_ok() {
        return Err(AppError::InvalidRequest(format!(
            "export destination already exists: {}",
            path.display()
        )));
    }
    let temporary = parent.join(format!(".ai-security-scanner-{}.document.tmp", new_id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| {
            AppError::Internal(format!(
                "could not create private export staging file in {}: {error}",
                parent.display()
            ))
        })?;
    restrict_private_file(&temporary)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = fs::hard_link(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(AppError::Internal(format!(
            "could not publish export {} atomically without overwrite: {error}",
            path.display()
        )));
    }
    if let Err(error) = fs::remove_file(&temporary) {
        let _ = fs::remove_file(&path);
        return Err(AppError::Internal(format!(
            "could not remove private export staging file: {error}"
        )));
    }
    Ok(fs::canonicalize(path)?)
}

#[cfg(unix)]
fn restrict_private_file(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_file(_path: &Path) -> AppResult<()> {
    Ok(())
}

fn read_legacy_deletion_obligation(path: &Path) -> AppResult<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_LEGACY_DELETION_OBLIGATION_BYTES {
        return Err(AppError::InvalidRequest(
            "legacy cleanup obligation must be a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_LEGACY_DELETION_OBLIGATION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LEGACY_DELETION_OBLIGATION_BYTES {
        return Err(AppError::InvalidRequest(
            "legacy cleanup obligation record is too large".into(),
        ));
    }
    Ok(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> AppResult<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn case_for_document_export(case: &AssessmentCase, options: &ExportOptions) -> AssessmentCase {
    case_for_export(case, options.redaction)
}

fn canonical_json_bytes(
    case: &AssessmentCase,
    run_id: &str,
    options: &ExportOptions,
) -> AppResult<Vec<u8>> {
    let exported = case_for_document_export(case, options);
    let run = exported
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "1",
        "product_name": "ai-security-scanner",
        "product_version": env!("CARGO_PKG_VERSION"),
        "export_kind": "canonical_case_document",
        "selected_run_id": run.id,
        "redaction_profile": options.redaction.as_str(),
        "raw_artifact_bytes_included": false,
        "notice": "Preliminary scanner evidence only. This document is not an audit, certification, attestation, compliance determination, or forensic conclusion. Related control references are navigation coordinates only. Finding groups are reversible presentation metadata and do not merge or replace canonical findings or evidence. Recommendations are non-executable guidance and require human review.",
        "case": exported,
    }))
    .map_err(Into::into)
}

fn html_report_bytes(
    case: &AssessmentCase,
    run_id: &str,
    options: &ExportOptions,
) -> AppResult<Vec<u8>> {
    let exported = case_for_document_export(case, options);
    let run = exported
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    let observations = exported
        .finding_observations
        .iter()
        .filter(|observation| observation.run_id == run_id)
        .collect::<Vec<_>>();
    let observed_finding_ids = observations
        .iter()
        .map(|observation| observation.finding_id.as_str())
        .collect::<BTreeSet<_>>();
    let finding_by_id = exported
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();

    let mut coverage_rows = String::new();
    for entry in &exported.coverage {
        coverage_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&entry.label),
            html_escape(&enum_key(&entry.status)),
            html_escape(&entry.explanation),
        ));
    }
    if coverage_rows.is_empty() {
        coverage_rows.push_str("<tr><td colspan=\"3\">No coverage entries recorded.</td></tr>");
    }

    let mut engine_rows = String::new();
    for engine in &run.engine_runs {
        let provenance = [
            engine
                .engine_version
                .as_ref()
                .map(|value| format!("engine {value}")),
            engine
                .source_revision
                .as_ref()
                .map(|value| format!("source {value}")),
            engine
                .image_digest
                .as_ref()
                .map(|value| format!("image {value}")),
            Some(format!("adapter {}", engine.adapter_version)),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
        let runtime = [
            engine.runtime_provider.as_ref().map(|provider| {
                format!(
                    "{} {}",
                    provider,
                    engine
                        .runtime_version
                        .as_deref()
                        .unwrap_or("version unknown")
                )
            }),
            engine.exit_code.map(|code| format!("exit {code}")),
            engine
                .cleanup_removed
                .map(|removed| format!("cleanup removed={removed}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
        let mut messages = engine.warnings.clone();
        if let Some(error) = &engine.error_message {
            messages.push(error.clone());
        }
        engine_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&engine.engine_id),
            html_escape(&enum_key(&engine.status)),
            engine.progress_percent,
            html_escape(&provenance),
            html_escape(&runtime),
            html_escape(&messages.join("; ")),
        ));
    }
    if engine_rows.is_empty() {
        engine_rows.push_str("<tr><td colspan=\"6\">No engine was planned.</td></tr>");
    }

    let mut active_group_articles = String::new();
    for group in &exported.finding_groups {
        let members = group
            .finding_ids
            .iter()
            .map(|finding_id| {
                let title = finding_by_id
                    .get(finding_id.as_str())
                    .map(|finding| finding.title.as_str())
                    .unwrap_or("Canonical finding record unavailable");
                let selected_run_note = if observed_finding_ids.contains(finding_id.as_str()) {
                    "observed in selected run"
                } else {
                    "not observed in selected run; retained as case history"
                };
                format!(
                    "<li>{} <code>{}</code> — {}</li>",
                    html_escape(title),
                    html_escape(finding_id),
                    selected_run_note,
                )
            })
            .collect::<String>();
        active_group_articles.push_str(&format!(
            concat!(
                "<article><h3>{}</h3><p>{}</p><ul>{}</ul>",
                "<p><strong>Created by:</strong> {} · <strong>Created at:</strong> {} · ",
                "<strong>Group ID:</strong> <code>{}</code></p></article>"
            ),
            html_escape(&group.title),
            html_escape(&group.rationale),
            members,
            html_escape(&group.grouped_by),
            html_escape(&group.created_at.to_rfc3339()),
            html_escape(&group.id),
        ));
    }
    if active_group_articles.is_empty() {
        active_group_articles.push_str("<p>No active presentation groups are recorded.</p>");
    }

    let mut grouping_history_rows = String::new();
    for event in &exported.finding_group_events {
        let member_ids = event
            .finding_ids
            .iter()
            .map(|finding_id| html_escape(finding_id))
            .collect::<Vec<_>>()
            .join(", ");
        grouping_history_rows.push_str(&format!(
            concat!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td>",
                "<td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"
            ),
            html_escape(&event.occurred_at.to_rfc3339()),
            html_escape(&enum_key(&event.action)),
            html_escape(&event.group_id),
            html_escape(&event.title),
            member_ids,
            html_escape(&event.rationale),
            html_escape(&event.actor),
        ));
    }
    if grouping_history_rows.is_empty() {
        grouping_history_rows
            .push_str("<tr><td colspan=\"7\">No grouping events are recorded.</td></tr>");
    }

    let mut findings = String::new();
    let mut run_findings = observations
        .iter()
        .filter_map(|observation| {
            observation
                .finding_snapshot
                .as_ref()
                .or_else(|| finding_by_id.get(observation.finding_id.as_str()).copied())
        })
        .collect::<Vec<_>>();
    run_findings.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
    for (index, finding) in run_findings.into_iter().enumerate() {
        let controls = finding
            .control_references
            .iter()
            .map(|reference| {
                html_escape(&format!(
                    "{} {} {} — related coordinate only",
                    reference.framework, reference.framework_version, reference.control_id
                ))
            })
            .collect::<Vec<_>>()
            .join("; ");
        let official_references = finding
            .official_references
            .iter()
            .map(|reference| html_escape(reference))
            .collect::<Vec<_>>()
            .join("; ");
        findings.push_str(&format!(
            concat!(
                "<article><h3>{}</h3>",
                "<p><span class=\"pill\">{}</span> Handoff order #{}</p>",
                "<p>{}</p><h4>Possible impact</h4><p>{}</p>",
                "<h4>Recommendation (non-executable)</h4><p>{}</p>",
                "<h4>Verification and rollback considerations</h4><p>{}</p><p>{}</p>",
                "<h4>Human handoff</h4><p>{}</p>",
                "<p><strong>Related control coordinates:</strong> {}</p>",
                "<p><strong>Official references (display only):</strong> {}</p></article>"
            ),
            html_escape(&finding.title),
            html_escape(&enum_key(&finding.severity)),
            index + 1,
            html_escape(&finding.plain_language_summary),
            html_escape(&finding.possible_impact),
            html_escape(&finding.recommendation),
            html_escape(&finding.verification_guidance),
            html_escape(
                finding
                    .rollback_considerations
                    .as_deref()
                    .unwrap_or("Not recorded.")
            ),
            html_escape(&finding.recommended_expert_type),
            controls,
            official_references,
        ));
    }
    if findings.is_empty() {
        findings.push_str("<p>No canonical findings were observed in this run. This does not by itself establish successful coverage.</p>");
    }

    let document = format!(
        concat!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
            "<title>{} — ai-security-scanner</title><style>",
            "body{{font:16px/1.5 system-ui,sans-serif;max-width:1080px;margin:auto;padding:2rem;color:#17202a}}",
            "h1,h2,h3{{line-height:1.2}} table{{width:100%;border-collapse:collapse}}",
            "th,td{{border:1px solid #ccd1d1;padding:.55rem;text-align:left;vertical-align:top}}",
            "article{{border:1px solid #ccd1d1;border-radius:.5rem;padding:1rem;margin:1rem 0}}",
            ".notice{{background:#fff4d6;border-left:5px solid #b9770e;padding:1rem}}",
            ".pill{{border:1px solid currentColor;border-radius:1rem;padding:.1rem .5rem}}</style></head><body>",
            "<header><p>ai-security-scanner / local case export</p><h1>{}</h1>",
            "<p>{} · Run {} · {}</p></header>",
            "<section class=\"notice\"><strong>Important:</strong> Preliminary scanner evidence only. This report is not an audit, certification, attestation, compliance determination, or forensic conclusion. Related controls are navigation coordinates only. Recommendations are static, non-executable guidance and require human review.</section>",
            "<h2>Coverage ledger</h2><table><thead><tr><th>Area or asset</th><th>State</th><th>Explanation</th></tr></thead><tbody>{}</tbody></table>",
            "<h2>Engine execution</h2><table><thead><tr><th>Engine</th><th>State</th><th>Progress</th><th>Pinned provenance</th><th>Runtime</th><th>Warnings or reason</th></tr></thead><tbody>{}</tbody></table>",
            "<h2>Reversible finding groups</h2><p>Groups are presentation metadata only. Every canonical finding, fingerprint, evidence record, and raw artifact remains independent; removing a group appends history and does not delete its members.</p>{}",
            "<h3>Immutable grouping history</h3><table><thead><tr><th>Time</th><th>Action</th><th>Group ID</th><th>Title</th><th>Finding IDs</th><th>Reason</th><th>Actor</th></tr></thead><tbody>{}</tbody></table>",
            "<h2>Findings</h2><p>Findings are ordered for human handoff. The displayed ordinal is not a risk score or compliance score.</p>{}<footer><p>Redaction profile: {}. Integrity: unsigned HTML with SHA-256 retained in the local case. No scripts, forms, remote resources, or executable remediation are included.</p></footer>",
            "</body></html>"
        ),
        html_escape(&exported.title),
        html_escape(&exported.title),
        html_escape(&exported.profile.organization_name),
        run.sequence,
        html_escape(&run.created_at.to_rfc3339()),
        coverage_rows,
        engine_rows,
        active_group_articles,
        grouping_history_rows,
        findings,
        html_escape(options.redaction.as_str()),
    );
    Ok(document.into_bytes())
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{
        CreatedBootstrapResources, create_cleanup_ledger, write_cleanup_ledger,
    };
    use crate::discovery::{ConnectorDiscovery, DiscoveredAsset};
    use crate::domain::{
        AssessmentActivity, AssetIdentifier, AssetKind, Confidence, CoverageStatus, DataClass,
        EngineCategory, EngineCompatibility, Evidence, EvidenceKind, FindingStatus, ImageReference,
        ManifestStatus, ProviderExecutionContract, Severity,
    };
    use crate::export::RedactionProfile;
    use chrono::Duration;

    struct Fixture {
        directory: tempfile::TempDir,
        storage: Storage,
        engines: EngineRegistry,
        adapters: AdapterRegistry,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let storage = Storage::open(directory.path().join("casework.db")).unwrap();
            let engines = EngineRegistry::load_builtin().unwrap();
            let adapters = crate::adapters::builtin_adapter_registry().unwrap();
            Self {
                directory,
                storage,
                engines,
                adapters,
            }
        }

        fn service(&self) -> CaseService<'_> {
            CaseService::new(
                &self.storage,
                &self.engines,
                &self.adapters,
                self.directory.path().join("artifacts"),
                self.directory.path().join("signing.key"),
            )
        }

        fn create(&self) -> AssessmentCase {
            self.service()
                .create_case(&CreateCaseRequest {
                    title: "Assessment".into(),
                    organization_name: "Example Co".into(),
                    employee_range: "1-10".into(),
                    assessment_intent: None,
                    data_classes: vec![DataClass::General],
                    requested_activities: vec![],
                    source_kinds: vec![],
                    not_applicable_source_kinds: vec![],
                    declared_assets: vec![],
                    notes: None,
                })
                .unwrap()
        }

        fn discovered_asset(&self, case_id: &str, kind: AssetKind) -> (AssessmentCase, Id) {
            let service = self.service();
            if kind == AssetKind::Repository {
                let fixture_id = new_id();
                let selected = self
                    .directory
                    .path()
                    .join("selected-working-trees")
                    .join(&fixture_id);
                fs::create_dir_all(selected.join("src")).unwrap();
                fs::write(
                    selected.join("src").join("main.rs"),
                    b"fn main() { println!(\"snapshot fixture\"); }\n",
                )
                .unwrap();
                fs::create_dir_all(self.directory.path().join("artifacts")).unwrap();
                let snapshot = crate::workspace_snapshot::create_workspace_snapshot(
                    self.directory.path().join("artifacts"),
                    case_id,
                    &format!("workspace-source-{fixture_id}"),
                    &selected,
                    crate::workspace_snapshot::WorkspaceSnapshotLimits::default(),
                )
                .unwrap();
                let asset_id = snapshot.asset.id.clone();
                let case = service
                    .attach_workspace_snapshot(case_id, "Repository snapshot", snapshot)
                    .unwrap();
                return (case, asset_id);
            }
            let source = service
                .upsert_source(
                    case_id,
                    SourceMutation {
                        id: None,
                        kind: SourceKind::UserDeclared,
                        label: "Declared scope".into(),
                        status: SourceConnectionStatus::Connected,
                        read_only: true,
                        metadata: BTreeMap::new(),
                    },
                )
                .unwrap();
            let batch = DiscoveryBatch {
                source_id: source.id,
                source_kind: SourceKind::UserDeclared,
                connector_id: "test".into(),
                connector_version: "1".into(),
                observed_at: Utc::now(),
                assets: vec![DiscoveredAsset {
                    observation_key: "asset".into(),
                    kind,
                    name: "Example asset".into(),
                    provider: None,
                    region: None,
                    stable_identifier: AssetIdentifier {
                        namespace: "example:id".into(),
                        value: "asset-1".into(),
                    },
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: None,
                    metadata: BTreeMap::new(),
                }],
                relations: vec![],
                notices: vec![],
            };
            service.reconcile_discovery_batch(case_id, &batch).unwrap();
            let case = service.show_case(case_id).unwrap();
            let asset_id = case.assets[0].id.clone();
            (case, asset_id)
        }

        fn discovered_aws_accounts(
            &self,
            case_id: &str,
            credential_account_id: &str,
            discovered_account_ids: &[&str],
        ) -> (AssessmentCase, Vec<Id>) {
            let service = self.service();
            let source = service
                .upsert_source(
                    case_id,
                    SourceMutation {
                        id: None,
                        kind: SourceKind::AwsOrganization,
                        label: "AWS organization".into(),
                        status: SourceConnectionStatus::Connected,
                        read_only: true,
                        metadata: BTreeMap::from([(
                            PROVIDER_RESOURCE_SCOPE_METADATA_KEY.into(),
                            Value::String(format!("aws-account:{credential_account_id}")),
                        )]),
                    },
                )
                .unwrap();
            let assets = discovered_account_ids
                .iter()
                .enumerate()
                .map(|(index, account_id)| DiscoveredAsset {
                    observation_key: format!("aws-account-{index}"),
                    kind: AssetKind::CloudAccount,
                    name: format!("AWS account {account_id}"),
                    provider: Some("aws".into()),
                    region: None,
                    stable_identifier: AssetIdentifier {
                        namespace: "aws_account_id".into(),
                        value: (*account_id).into(),
                    },
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: None,
                    metadata: BTreeMap::new(),
                })
                .collect();
            service
                .reconcile_discovery_batch(
                    case_id,
                    &DiscoveryBatch {
                        source_id: source.id,
                        source_kind: SourceKind::AwsOrganization,
                        connector_id: "aws-organizations-list-accounts".into(),
                        connector_version: "1".into(),
                        observed_at: Utc::now(),
                        assets,
                        relations: vec![],
                        notices: vec![],
                    },
                )
                .unwrap();
            let case = service.show_case(case_id).unwrap();
            let asset_ids = discovered_account_ids
                .iter()
                .map(|account_id| {
                    case.assets
                        .iter()
                        .find(|asset| {
                            asset.identifiers.iter().any(|identifier| {
                                identifier.namespace == "aws_account_id"
                                    && identifier.value == *account_id
                            })
                        })
                        .unwrap()
                        .id
                        .clone()
                })
                .collect();
            (case, asset_ids)
        }

        fn discovered_aws_account(&self, case_id: &str, account_id: &str) -> (AssessmentCase, Id) {
            let (case, mut asset_ids) =
                self.discovered_aws_accounts(case_id, account_id, &[account_id]);
            (case, asset_ids.remove(0))
        }
    }

    fn approve_direct_external_target(
        fixture: &Fixture,
        case_id: &str,
        kind: AssetKind,
        target: &str,
        permission: ScanPermission,
        protocol: crate::external_scope::TransportProtocol,
        internet_exposed: bool,
    ) -> Id {
        let (mut discovered, asset_id) = fixture.discovered_asset(case_id, kind);
        let asset = discovered
            .assets
            .iter_mut()
            .find(|asset| asset.id == asset_id)
            .unwrap();
        asset.name = target.into();
        asset.identifiers = vec![AssetIdentifier {
            namespace: "external_target".into(),
            value: target.into(),
        }];
        asset.internet_exposed = Some(internet_exposed);
        fixture
            .storage
            .save_case(&mut discovered, "test.direct_external_target_attributed")
            .unwrap();

        let activity = match permission {
            ScanPermission::LowImpactExternalConnection => ExternalActivity::LowImpactExternal,
            ScanPermission::ActiveExternalTesting => ExternalActivity::ActiveExternal,
            _ => panic!("direct external fixture requires a direct external permission"),
        };
        let (revision, allowed_template_ids) = if activity == ExternalActivity::ActiveExternal {
            (
                "greenbone-community-feed@b26d7237d56b7cf85e6ace2b9351e7851461b3a8",
                vec!["1.3.6.1.4.1.25623.1.0.10335".into()],
            )
        } else {
            ("not_applicable", vec![])
        };
        fixture
            .service()
            .approve_scope(
                case_id,
                ScopeApprovalRequest {
                    asset_id: asset_id.clone(),
                    permissions: vec![permission],
                    confirmed_by: "Target owner".into(),
                    expires_at: Some(Utc::now() + Duration::hours(1)),
                    authorization_reference: Some("CHANGE-4242".into()),
                    notes: None,
                    external_scope: Some(ExternalScopeRequest {
                        target: target.into(),
                        ports: [443].into_iter().collect(),
                        protocol,
                        activity,
                        rate_policy: crate::external_scope::RatePolicy {
                            requests_per_second: 2,
                            concurrency: 1,
                            timeout_seconds: 300,
                        },
                        template_policy: crate::external_scope::TemplatePolicy::conservative(
                            revision,
                            allowed_template_ids,
                        ),
                        asserted_authority: "Approved change CHANGE-4242".into(),
                        allow_sensitive_networks: !internet_exposed,
                    }),
                },
            )
            .unwrap();
        asset_id
    }

    fn write_legacy_artifact_deletion_obligation(
        fixture: &Fixture,
        plan: &ArtifactDeletionPlan,
    ) -> PathBuf {
        let root = fixture
            .directory
            .path()
            .join("artifacts")
            .join(LEGACY_DELETION_OBLIGATION_DIRECTORY);
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("{}.json", plan.case_id));
        fs::write(&path, serde_json::to_vec_pretty(plan).unwrap()).unwrap();
        path
    }

    fn comparison_scope_manifest() -> EngineManifest {
        EngineManifest {
            schema_version: "1".into(),
            id: "scope-contract-test".into(),
            display_name: "Scope contract test".into(),
            category: EngineCategory::CloudConfiguration,
            description: "Test manifest".into(),
            repository_url: "https://example.test/engine".into(),
            homepage_url: None,
            license_spdx: "Apache-2.0".into(),
            distribution_mode: DistributionMode::PullPinnedImage,
            image: Some(ImageReference {
                repository: "ghcr.io/example/engine".into(),
                tag: None,
                digest: Some(format!("sha256:{}", "a".repeat(64))),
                signature_identity: None,
            }),
            source_revision: Some("b".repeat(40)),
            engine_version: Some("1".into()),
            rule_version: Some("rules-1".into()),
            adapter_version: "1".into(),
            supported_providers: vec![],
            supported_asset_kinds: vec![AssetKind::CloudResource],
            input_contracts: vec![],
            provider_execution_contracts: vec![],
            direct_network_contract: None,
            required_permissions: vec![ScanPermission::ConfigurationRead],
            active_external: false,
            default_enabled: true,
            estimated_memory_mb: 1,
            estimated_disk_mb: 1,
            network_destinations: vec![],
            output_formats: vec!["json".into()],
            command: vec!["scan".into()],
            status: ManifestStatus::Integrated,
            notices: vec![],
            compatibility: EngineCompatibility::default(),
        }
    }

    fn comparison_scope_asset() -> Asset {
        Asset {
            id: "asset-1".into(),
            kind: AssetKind::CloudResource,
            name: "Display name excluded from the semantic contract".into(),
            provider: Some("aws".into()),
            region: Some("us-east-1".into()),
            identifiers: vec![AssetIdentifier {
                namespace: "arn".into(),
                value: "arn:aws:s3:::example-a".into(),
            }],
            discovered_from: vec!["source-1".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        }
    }

    fn comparison_scope_grant() -> ScopeGrant {
        ScopeGrant {
            id: "grant-1".into(),
            asset_id: "asset-1".into(),
            permission: ScanPermission::ConfigurationRead,
            confirmed_by: "operator-a".into(),
            confirmed_at: Utc::now(),
            expires_at: None,
            authorization_reference: None,
            notes: None,
            external_scope: None,
        }
    }

    #[test]
    fn comparable_scope_contract_tracks_permissions_but_not_reapproval_metadata() {
        let manifest = comparison_scope_manifest();
        let asset = comparison_scope_asset();
        let grant = comparison_scope_grant();
        let baseline =
            comparable_scope_contract_sha256(&manifest, &[&asset], std::slice::from_ref(&grant))
                .expect("baseline scope contract");

        let mut reapproved = grant.clone();
        reapproved.id = "grant-2".into();
        reapproved.confirmed_by = "operator-b".into();
        reapproved.confirmed_at += Duration::hours(1);
        reapproved.notes = Some("new audit note".into());
        assert_eq!(
            baseline,
            comparable_scope_contract_sha256(&manifest, &[&asset], &[reapproved])
                .expect("equivalent reapproval")
        );

        let mut changed_permission = grant;
        changed_permission.permission = ScanPermission::InventoryRead;
        assert_ne!(
            baseline,
            comparable_scope_contract_sha256(&manifest, &[&asset], &[changed_permission])
                .expect("changed permission contract")
        );
    }

    #[test]
    fn comparable_scope_contract_tracks_exact_target_identifiers() {
        let manifest = comparison_scope_manifest();
        let asset = comparison_scope_asset();
        let grant = comparison_scope_grant();
        let baseline =
            comparable_scope_contract_sha256(&manifest, &[&asset], std::slice::from_ref(&grant))
                .expect("baseline scope contract");
        let mut changed_target = asset.clone();
        changed_target.identifiers[0].value = "arn:aws:s3:::example-b".into();

        assert_ne!(
            baseline,
            comparable_scope_contract_sha256(&manifest, &[&changed_target], &[grant])
                .expect("changed target contract")
        );
    }

    #[test]
    fn comparable_scope_contract_tracks_provider_profile_and_network_closure() {
        let mut manifest = comparison_scope_manifest();
        manifest.supported_providers = vec!["aws".into()];
        manifest.supported_asset_kinds = vec![AssetKind::CloudAccount];
        manifest.provider_execution_contracts = vec![ProviderExecutionContract {
            provider: "aws".into(),
            asset_kind: AssetKind::CloudAccount,
            profile: "aws_iam".into(),
            network_destinations: vec!["iam.amazonaws.com:443".into()],
        }];
        let mut asset = comparison_scope_asset();
        asset.kind = AssetKind::CloudAccount;
        asset.identifiers = vec![AssetIdentifier {
            namespace: "aws_account_id".into(),
            value: "111122223333".into(),
        }];
        let grant = comparison_scope_grant();
        let baseline =
            comparable_scope_contract_sha256(&manifest, &[&asset], std::slice::from_ref(&grant))
                .expect("baseline provider scope contract");

        manifest.provider_execution_contracts[0].profile = "aws_iam_changed".into();
        assert_ne!(
            baseline,
            comparable_scope_contract_sha256(&manifest, &[&asset], &[grant])
                .expect("changed provider profile contract")
        );
    }

    #[test]
    fn standard_redaction_pipeline_is_shared_by_all_document_formats() {
        const SENTINEL: &str = "SENSITIVE_DOCUMENT_SENTINEL_73be19";
        let time = Utc::now();
        let mut case = AssessmentCase::new(
            SENTINEL.into(),
            OrganizationProfile {
                organization_name: SENTINEL.into(),
                employee_range: "1-10".into(),
                data_classes: vec![DataClass::General],
                notes: Some(SENTINEL.into()),
            },
        );
        case.id = "case-redaction".into();
        case.scan_runs.push(ScanRun {
            id: "run-redaction".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: time,
            completed_at: Some(time),
            knowledge_cutoff: time,
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_runs: vec![],
        });
        let options = ExportOptions::default();
        assert!(
            String::from_utf8(
                canonical_json_bytes(
                    &case,
                    "run-redaction",
                    &ExportOptions {
                        redaction: RedactionProfile::None,
                        include_raw_artifacts: false,
                    },
                )
                .unwrap(),
            )
            .unwrap()
            .contains(SENTINEL),
            "the document sentinel fixture must be meaningful"
        );

        let document_case = case_for_document_export(&case, &options);
        let documents = [
            (
                "canonical_json",
                canonical_json_bytes(&case, "run-redaction", &options).unwrap(),
            ),
            (
                "ocsf",
                export_ocsf_finding_events_bytes(&document_case, "run-redaction").unwrap(),
            ),
            (
                "oscal",
                export_oscal_assessment_results_bytes(&document_case, "run-redaction").unwrap(),
            ),
            (
                "html",
                html_report_bytes(&case, "run-redaction", &options).unwrap(),
            ),
        ];
        for (format, bytes) in documents {
            assert!(
                !bytes
                    .windows(SENTINEL.len())
                    .any(|window| window == SENTINEL.as_bytes()),
                "{format} leaked a standard-redaction sentinel"
            );
        }
    }

    fn repository_case_ready_for_execution(fixture: &Fixture) -> Id {
        let created = fixture.create();
        let (_, asset_id) = fixture.discovered_asset(&created.id, AssetKind::Repository);
        let service = fixture.service();
        service
            .approve_scope(
                &created.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        created.id
    }

    fn repository_case_with_completed_baseline(fixture: &Fixture) -> (Id, Id) {
        let case_id = repository_case_ready_for_execution(fixture);
        let service = fixture.service();
        let baseline = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
            )
            .unwrap();
        let mut stored = service.show_case(&case_id).unwrap();
        let run = stored
            .scan_runs
            .iter_mut()
            .find(|run| run.id == baseline.scan_run.id)
            .unwrap();
        for engine_run in &mut run.engine_runs {
            engine_run.status = EngineRunStatus::Completed;
            engine_run.progress_percent = 100;
            engine_run.phase = "completed".into();
            engine_run.started_at = Some(baseline.scan_run.created_at);
            engine_run.finished_at = Some(baseline.scan_run.created_at);
            engine_run.exit_code = Some(0);
        }
        run.completed_at = Some(baseline.scan_run.created_at);
        stored.status = CaseStatus::ReadyForHandoff;
        fixture
            .storage
            .save_case(&mut stored, "test.baseline_completed")
            .unwrap();
        (case_id, baseline.scan_run.id)
    }

    #[test]
    fn empty_engine_selection_automatically_plans_every_applicable_catalog_engine() {
        let fixture = Fixture::new();
        let created = fixture.create();
        let (_, asset_id) = fixture.discovered_asset(&created.id, AssetKind::Repository);
        let service = fixture.service();
        service
            .approve_scope(
                &created.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Repository owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: Some("Read-only local artifact grant".into()),
                    external_scope: None,
                },
            )
            .unwrap();

        let scoped = service.show_case(&created.id).unwrap();
        let now = Utc::now();
        let effective = effective_grants(&scoped, now);
        let expected = fixture
            .engines
            .manifests()
            .iter()
            .filter(|manifest| {
                !compatible_authorized_assets(&scoped, manifest, &effective, now).is_empty()
            })
            .map(|manifest| manifest.id.clone())
            .collect::<BTreeSet<_>>();
        assert!(
            expected.len() > 4,
            "automatic dispatch must extend beyond legacy defaults"
        );

        let plan = service
            .plan_scan(&created.id, ScanPlanRequest::default())
            .unwrap();
        let actual = plan
            .executable
            .iter()
            .map(|execution| execution.manifest.id.clone())
            .chain(
                plan.not_executed
                    .iter()
                    .map(|not_executed| not_executed.engine_id.clone()),
            )
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn execution_preflight_rejects_an_unsupported_authorized_target_without_a_run() {
        let fixture = Fixture::new();
        let created = fixture.create();
        let (_, asset_id) = fixture.discovered_asset(&created.id, AssetKind::FileSystem);
        let service = fixture.service();
        service
            .approve_scope(
                &created.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Filesystem owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();

        let readiness = service.scan_readiness(&created.id).unwrap();
        assert!(!readiness.ready);
        assert_eq!(
            readiness.state,
            ScanReadinessState::NoCompatibleAuthorizedTargets
        );
        assert_eq!(readiness.authorized_target_count, 1);
        assert_eq!(readiness.pending_target_count, 0);
        assert_eq!(readiness.compatible_engine_count, 0);
        assert_eq!(readiness.runnable_engine_count, 0);
        assert_eq!(
            readiness.blocker_code,
            Some(ScanReadinessBlocker::NoCompatibleAuthorizedTargets)
        );
        assert_eq!(readiness.next_step, Some(ScanReadinessNextStep::Coverage));
        let serialized = serde_json::to_value(&readiness).unwrap();
        assert_eq!(
            serialized["blocker_code"],
            "no_compatible_authorized_targets"
        );
        assert_eq!(serialized["next_step"], "coverage");

        let error = service
            .plan_scan_for_execution(&created.id, ScanPlanRequest::default())
            .unwrap_err();
        assert!(matches!(error, AppError::NotAvailable(_)));
        assert!(
            error
                .to_string()
                .contains("scan_preflight:no_compatible_authorized_targets")
        );
        assert!(service.show_case(&created.id).unwrap().scan_runs.is_empty());
    }

    #[test]
    fn provider_readiness_contract_serializes_distinct_safe_routes() {
        let contracts = [
            (
                ScanReadinessState::ProviderConnectionRequired,
                ScanReadinessBlocker::ProviderSourceRequired,
                ScanReadinessNextStep::Coverage,
                "provider_connection_required",
                "provider_source_required",
                "coverage",
            ),
            (
                ScanReadinessState::ProviderCapabilityRequired,
                ScanReadinessBlocker::ProviderCapabilityUnavailable,
                ScanReadinessNextStep::Coverage,
                "provider_capability_required",
                "provider_capability_unavailable",
                "coverage",
            ),
            (
                ScanReadinessState::ProviderReviewRequired,
                ScanReadinessBlocker::ProviderSourceAmbiguous,
                ScanReadinessNextStep::Coverage,
                "provider_review_required",
                "provider_source_ambiguous",
                "coverage",
            ),
            (
                ScanReadinessState::ProviderReviewRequired,
                ScanReadinessBlocker::ProviderAuthorizationBindingMismatch,
                ScanReadinessNextStep::Coverage,
                "provider_review_required",
                "provider_authorization_binding_mismatch",
                "coverage",
            ),
            (
                ScanReadinessState::ProviderReviewRequired,
                ScanReadinessBlocker::ProviderTargetBindingMismatch,
                ScanReadinessNextStep::Coverage,
                "provider_review_required",
                "provider_target_binding_mismatch",
                "coverage",
            ),
            (
                ScanReadinessState::ProviderCheckUnavailable,
                ScanReadinessBlocker::ProviderPreflightUnavailable,
                ScanReadinessNextStep::Retry,
                "provider_check_unavailable",
                "provider_preflight_unavailable",
                "retry",
            ),
        ];

        for (state, blocker, next_step, state_code, blocker_code, next_step_code) in contracts {
            let readiness = ScanReadiness {
                case_id: "case-provider-readiness".into(),
                ready: false,
                state,
                authorized_target_count: 1,
                pending_target_count: 0,
                compatible_engine_count: 1,
                runnable_engine_count: 1,
                blocker_code: Some(blocker),
                next_step: Some(next_step),
            };
            let serialized = serde_json::to_value(readiness).unwrap();
            assert_eq!(serialized["state"], state_code);
            assert_eq!(serialized["blocker_code"], blocker_code);
            assert_eq!(serialized["next_step"], next_step_code);
            assert_eq!(blocker.as_str(), blocker_code);
        }
    }

    #[test]
    fn tcp_network_scope_plans_naabu_without_planning_http_engines() {
        let fixture = Fixture::new();
        let created = fixture.create();
        let asset_id = approve_direct_external_target(
            &fixture,
            &created.id,
            AssetKind::IpAddress,
            "198.51.100.0/30",
            ScanPermission::LowImpactExternalConnection,
            crate::external_scope::TransportProtocol::Tcp,
            true,
        );
        let service = fixture.service();

        let readiness = service.scan_readiness(&created.id).unwrap();
        assert!(readiness.ready);
        assert_eq!(readiness.compatible_engine_count, 1);
        assert_eq!(readiness.runnable_engine_count, 1);

        let plan = service
            .plan_scan(
                &created.id,
                ScanPlanRequest {
                    engine_ids: vec!["naabu".into(), "httpx".into()],
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 1);
        assert_eq!(plan.executable[0].manifest.id, "naabu");
        assert_eq!(plan.executable[0].assets[0].id, asset_id);
        assert!(plan.not_executed.iter().any(|engine| {
            engine.engine_id == "httpx"
                && engine.reason_code == "no_compatible_authorized_assets"
                && engine.asset_ids.is_empty()
        }));
    }

    #[test]
    fn confirmed_private_network_is_ready_for_the_compatible_internal_scanner() {
        let fixture = Fixture::new();
        let created = fixture.create();
        let asset_id = approve_direct_external_target(
            &fixture,
            &created.id,
            AssetKind::IpAddress,
            "192.168.50.0/30",
            ScanPermission::LowImpactExternalConnection,
            crate::external_scope::TransportProtocol::Tcp,
            false,
        );
        let service = fixture.service();

        let readiness = service.scan_readiness(&created.id).unwrap();
        assert!(readiness.ready);
        assert_eq!(readiness.authorized_target_count, 1);
        assert_eq!(readiness.compatible_engine_count, 1);
        assert_eq!(readiness.runnable_engine_count, 1);

        let plan = service
            .plan_scan_for_execution(&created.id, ScanPlanRequest::default())
            .unwrap();
        assert_eq!(plan.executable.len(), 1);
        assert_eq!(plan.executable[0].manifest.id, "naabu");
        assert_eq!(plan.executable[0].assets[0].id, asset_id);
        assert!(plan.not_executed.is_empty());
    }

    #[test]
    fn tcp_address_scope_plans_greenbone_without_planning_nuclei() {
        let fixture = Fixture::new();
        let created = fixture.create();
        let asset_id = approve_direct_external_target(
            &fixture,
            &created.id,
            AssetKind::IpAddress,
            "198.51.100.10",
            ScanPermission::ActiveExternalTesting,
            crate::external_scope::TransportProtocol::Tcp,
            true,
        );
        let service = fixture.service();

        let readiness = service.scan_readiness(&created.id).unwrap();
        assert!(readiness.ready);
        assert_eq!(readiness.compatible_engine_count, 1);
        assert_eq!(readiness.runnable_engine_count, 1);

        let plan = service
            .plan_scan(
                &created.id,
                ScanPlanRequest {
                    engine_ids: vec!["greenbone".into(), "nuclei".into()],
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 1);
        assert_eq!(plan.executable[0].manifest.id, "greenbone");
        assert_eq!(plan.executable[0].assets[0].id, asset_id);
        assert!(plan.not_executed.iter().any(|engine| {
            engine.engine_id == "nuclei"
                && engine.reason_code == "no_compatible_authorized_assets"
                && engine.asset_ids.is_empty()
        }));
    }

    #[test]
    fn execution_preflight_rejects_unavailable_engines_but_audit_planning_stays_durable() {
        let fixture = Fixture::new();
        let created = fixture.create();
        let (_, asset_id) = fixture.discovered_aws_account(&created.id, "111122223333");
        fixture
            .service()
            .approve_scope(
                &created.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::InventoryRead],
                    confirmed_by: "Cloud account owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        let unavailable_adapters = AdapterRegistry::default();
        let service = CaseService::new(
            &fixture.storage,
            &fixture.engines,
            &unavailable_adapters,
            fixture.directory.path().join("artifacts"),
            fixture.directory.path().join("signing.key"),
        );

        let readiness = service.scan_readiness(&created.id).unwrap();
        assert!(!readiness.ready);
        assert_eq!(
            readiness.state,
            ScanReadinessState::NoRunnableAuthorizedTargets
        );
        assert!(readiness.compatible_engine_count > 0);
        assert_eq!(readiness.runnable_engine_count, 0);
        assert_eq!(
            readiness.blocker_code,
            Some(ScanReadinessBlocker::NoRunnableAuthorizedTargets)
        );
        assert_eq!(
            readiness.next_step,
            Some(ScanReadinessNextStep::ScannerSetup)
        );

        let error = service
            .plan_scan_for_execution(&created.id, ScanPlanRequest::default())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("scan_preflight:no_runnable_authorized_targets")
        );
        assert!(service.show_case(&created.id).unwrap().scan_runs.is_empty());

        let audit = service
            .plan_scan(&created.id, ScanPlanRequest::default())
            .unwrap();
        assert!(audit.executable.is_empty());
        assert_eq!(audit.not_executed.len(), readiness.compatible_engine_count);
        assert!(
            audit
                .not_executed
                .iter()
                .all(|engine| engine.reason_code == "adapter_unavailable")
        );
        assert_eq!(service.show_case(&created.id).unwrap().scan_runs.len(), 1);
    }

    #[test]
    fn execution_rescan_preflight_does_not_persist_an_empty_verification_run() {
        let fixture = Fixture::new();
        let created = fixture.create();
        let (_, asset_id) = fixture.discovered_aws_account(&created.id, "111122223333");
        let available_service = fixture.service();
        available_service
            .approve_scope(
                &created.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::InventoryRead],
                    confirmed_by: "Cloud account owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        let baseline = available_service
            .plan_scan(
                &created.id,
                ScanPlanRequest {
                    engine_ids: vec!["steampipe".into()],
                },
            )
            .unwrap();
        let mut completed = available_service.show_case(&created.id).unwrap();
        let baseline_run = completed
            .scan_runs
            .iter_mut()
            .find(|run| run.id == baseline.scan_run.id)
            .unwrap();
        baseline_run.completed_at = Some(baseline.scan_run.created_at);
        for engine_run in &mut baseline_run.engine_runs {
            engine_run.status = EngineRunStatus::Completed;
            engine_run.progress_percent = 100;
            engine_run.phase = "completed".into();
            engine_run.started_at = Some(baseline.scan_run.created_at);
            engine_run.finished_at = Some(baseline.scan_run.created_at);
            engine_run.exit_code = Some(0);
        }
        completed.status = CaseStatus::ReadyForHandoff;
        fixture
            .storage
            .save_case(&mut completed, "test.baseline_completed")
            .unwrap();
        let case_id = created.id;
        let baseline_run_id = baseline.scan_run.id;
        let unavailable_adapters = AdapterRegistry::default();
        let service = CaseService::new(
            &fixture.storage,
            &fixture.engines,
            &unavailable_adapters,
            fixture.directory.path().join("artifacts"),
            fixture.directory.path().join("signing.key"),
        );
        let run_count = service.show_case(&case_id).unwrap().scan_runs.len();

        let error = service
            .plan_rescan_for_execution(&case_id, &baseline_run_id, ScanPlanRequest::default())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("scan_preflight:no_runnable_authorized_targets")
        );
        let retained = service.show_case(&case_id).unwrap();
        assert_eq!(retained.scan_runs.len(), run_count);
        assert!(
            retained
                .scan_runs
                .iter()
                .all(|run| run.verification_baseline_run_id.is_none())
        );
    }

    #[test]
    fn live_execution_hook_failure_leaves_new_scan_case_unchanged() {
        let fixture = Fixture::new();
        let case_id = repository_case_ready_for_execution(&fixture);
        let service = fixture.service();
        let before = service.show_case(&case_id).unwrap();
        let mut called = 0_u8;

        let error = service
            .plan_scan_for_execution_checked(
                &case_id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
                |plan| {
                    called = called.saturating_add(1);
                    assert_eq!(plan.executable.len(), 1);
                    Err(AppError::NotAvailable(
                        "scan_preflight:runtime_unavailable: fixture".into(),
                    ))
                },
            )
            .unwrap_err();

        assert_eq!(called, 1);
        assert!(error.to_string().contains("runtime_unavailable"));
        let after = service.show_case(&case_id).unwrap();
        assert!(after.scan_runs.is_empty());
        assert_eq!(after.status, before.status);
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.storage_revision, before.storage_revision);
    }

    #[test]
    fn execution_preview_is_read_only_and_successful_hook_persists_exactly_one_run() {
        let fixture = Fixture::new();
        let case_id = repository_case_ready_for_execution(&fixture);
        let service = fixture.service();

        let preview = service
            .preview_scan_for_execution(
                &case_id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
            )
            .unwrap();
        assert_eq!(preview.executable.len(), 1);
        assert!(service.show_case(&case_id).unwrap().scan_runs.is_empty());

        let mut called = 0_u8;
        let persisted = service
            .plan_scan_for_execution_checked(
                &case_id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
                |plan| {
                    called = called.saturating_add(1);
                    assert_eq!(plan.executable.len(), 1);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(called, 1);
        let stored = service.show_case(&case_id).unwrap();
        assert_eq!(stored.scan_runs.len(), 1);
        assert_eq!(stored.scan_runs[0].id, persisted.scan_run.id);
    }

    #[test]
    fn live_execution_hook_failure_leaves_rescan_baseline_unchanged() {
        let fixture = Fixture::new();
        let (case_id, baseline_run_id) = repository_case_with_completed_baseline(&fixture);
        let service = fixture.service();
        let before = service.show_case(&case_id).unwrap();
        let baseline_before = before.scan_runs[0].clone();

        let error = service
            .plan_rescan_for_execution_checked(
                &case_id,
                &baseline_run_id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
                |_| {
                    Err(AppError::NotAvailable(
                        "scan_preflight:runtime_unavailable: fixture".into(),
                    ))
                },
            )
            .unwrap_err();

        assert!(error.to_string().contains("runtime_unavailable"));
        let after = service.show_case(&case_id).unwrap();
        assert_eq!(after.scan_runs.len(), 1);
        assert_eq!(after.scan_runs[0].id, baseline_before.id);
        assert_eq!(
            after.scan_runs[0].completed_at,
            baseline_before.completed_at
        );
        assert_eq!(
            after.scan_runs[0].engine_runs[0].status,
            baseline_before.engine_runs[0].status
        );
        assert_eq!(after.status, before.status);
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.storage_revision, before.storage_revision);
    }

    #[test]
    fn live_execution_hook_failure_does_not_queue_a_retryable_run() {
        let fixture = Fixture::new();
        let (case_id, baseline_run_id) = repository_case_with_completed_baseline(&fixture);
        let service = fixture.service();
        let mut retryable = service.show_case(&case_id).unwrap();
        retryable.scan_runs[0].engine_runs[0].status = EngineRunStatus::Failed;
        retryable.scan_runs[0].engine_runs[0].phase = "failed".into();
        retryable.status = CaseStatus::NeedsAttention;
        fixture
            .storage
            .save_case(&mut retryable, "test.retryable_run")
            .unwrap();
        let before = service.show_case(&case_id).unwrap();

        let error = service
            .plan_resume_checked(&case_id, &baseline_run_id, |_| {
                Err(AppError::NotAvailable(
                    "scan_preflight:runtime_unavailable: fixture".into(),
                ))
            })
            .unwrap_err();

        assert!(error.to_string().contains("runtime_unavailable"));
        let after = service.show_case(&case_id).unwrap();
        assert_eq!(after.scan_runs.len(), 1);
        assert_eq!(
            after.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Failed
        );
        assert_eq!(after.scan_runs[0].engine_runs[0].phase, "failed");
        assert_eq!(after.status, before.status);
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.storage_revision, before.storage_revision);
    }

    #[test]
    fn case_questionnaire_creates_untrusted_candidates_and_reasoned_applicability() {
        let fixture = Fixture::new();
        let case = fixture
            .service()
            .create_case(&CreateCaseRequest {
                title: "Questionnaire case".into(),
                organization_name: "Example Co".into(),
                employee_range: "2-49".into(),
                assessment_intent: None,
                data_classes: vec![DataClass::General],
                requested_activities: vec![
                    AssessmentActivity::ConfigurationAssessment,
                    AssessmentActivity::LowImpactExternalChecks,
                ],
                source_kinds: vec![SourceKind::AwsOrganization],
                not_applicable_source_kinds: vec![SourceKind::GcpOrganization],
                declared_assets: vec![
                    DeclaredAssetInput {
                        kind: DeclaredAssetKind::ExternalTarget,
                        value: "App.Example.Test.".into(),
                        internet_exposed: None,
                        web_service: None,
                    },
                    DeclaredAssetInput {
                        kind: DeclaredAssetKind::Repository,
                        value: "https://github.com/example/service".into(),
                        internet_exposed: None,
                        web_service: None,
                    },
                    DeclaredAssetInput {
                        kind: DeclaredAssetKind::ContainerImage,
                        value: format!("registry.example/app@sha256:{}", "a".repeat(64)),
                        internet_exposed: None,
                        web_service: None,
                    },
                    DeclaredAssetInput {
                        kind: DeclaredAssetKind::KubernetesCluster,
                        value: "production-eks".into(),
                        internet_exposed: None,
                        web_service: None,
                    },
                ],
                notes: None,
            })
            .unwrap();

        assert_eq!(case.assets.len(), 4);
        assert_eq!(case.requested_activities.len(), 2);
        assert!(
            case.requested_activities
                .contains(&AssessmentActivity::ConfigurationAssessment)
        );
        assert!(
            case.requested_activities
                .contains(&AssessmentActivity::LowImpactExternalChecks)
        );
        assert!(
            case.scope_grants.is_empty(),
            "intent never authorizes scope"
        );
        assert!(case.assets.iter().all(|asset| {
            asset.candidate && !asset.owner_confirmed && !asset.discovered_from.is_empty()
        }));
        assert!(case.scope_grants.is_empty());
        let external = case
            .assets
            .iter()
            .find(|asset| asset.kind == AssetKind::Domain)
            .unwrap();
        assert_eq!(external.identifiers[0].value, "app.example.test");
        assert_eq!(external.internet_exposed, Some(true));

        let not_applicable = case
            .coverage
            .iter()
            .find(|entry| entry.source_kind == SourceKind::GcpOrganization)
            .unwrap();
        assert_eq!(not_applicable.status, CoverageStatus::NotApplicable);
        assert!(not_applicable.explanation.contains("not used"));
        assert!(!crate::coverage::coverage_status_is_green(
            &not_applicable.status
        ));
        assert!(case.coverage.iter().any(|entry| {
            entry.source_kind == SourceKind::AwsOrganization
                && entry.status == CoverageStatus::SourceNotConnectedUnknown
        }));
    }

    #[test]
    fn questionnaire_rejects_overlapping_sources_and_mutable_image_tags() {
        let fixture = Fixture::new();
        let mut request = CreateCaseRequest {
            title: "Invalid questionnaire".into(),
            organization_name: "Example Co".into(),
            employee_range: "2-49".into(),
            assessment_intent: None,
            data_classes: vec![],
            requested_activities: vec![],
            source_kinds: vec![SourceKind::AwsOrganization],
            not_applicable_source_kinds: vec![SourceKind::AwsOrganization],
            declared_assets: vec![],
            notes: None,
        };
        assert!(fixture.service().create_case(&request).is_err());

        request.not_applicable_source_kinds.clear();
        request.declared_assets.push(DeclaredAssetInput {
            kind: DeclaredAssetKind::ContainerImage,
            value: "registry.example/app:latest".into(),
            internet_exposed: None,
            web_service: None,
        });
        assert!(fixture.service().create_case(&request).is_err());
        assert!(fixture.service().list_cases().unwrap().is_empty());
    }

    #[test]
    fn questionnaire_can_record_internal_target_intent_without_authorizing_it() {
        let fixture = Fixture::new();
        let case = fixture
            .service()
            .create_case(&CreateCaseRequest {
                title: "Internal IT review".into(),
                organization_name: "Example Co".into(),
                employee_range: "2-49".into(),
                assessment_intent: None,
                data_classes: vec![],
                requested_activities: vec![AssessmentActivity::LowImpactExternalChecks],
                source_kinds: vec![],
                not_applicable_source_kinds: vec![],
                declared_assets: vec![DeclaredAssetInput {
                    kind: DeclaredAssetKind::ExternalTarget,
                    value: "10.20.30.40".into(),
                    internet_exposed: Some(false),
                    web_service: None,
                }],
                notes: None,
            })
            .unwrap();

        assert_eq!(case.assets.len(), 1);
        assert_eq!(case.assets[0].internet_exposed, Some(false));
        assert!(case.scope_grants.is_empty());
    }

    #[test]
    fn questionnaire_can_prefill_a_website_service_without_authorizing_it() {
        let fixture = Fixture::new();
        let case = fixture
            .service()
            .create_case(&CreateCaseRequest {
                title: "Deployed website review".into(),
                organization_name: "Example Co".into(),
                employee_range: "2-49".into(),
                assessment_intent: None,
                data_classes: vec![],
                requested_activities: vec![AssessmentActivity::LowImpactExternalChecks],
                source_kinds: vec![],
                not_applicable_source_kinds: vec![],
                declared_assets: vec![DeclaredAssetInput {
                    kind: DeclaredAssetKind::ExternalTarget,
                    value: "app.example.test".into(),
                    internet_exposed: Some(true),
                    web_service: Some(DeclaredWebServiceInput {
                        protocol: DeclaredWebProtocol::Https,
                        port: 8443,
                        path: "/login".into(),
                    }),
                }],
                notes: None,
            })
            .unwrap();

        assert_eq!(case.assets.len(), 1);
        assert_eq!(
            case.assets[0].metadata.get("declared_web_service"),
            Some(&serde_json::json!({
                "protocol": "https",
                "port": 8443,
                "path": "/login",
            }))
        );
        assert!(
            case.scope_grants.is_empty(),
            "a website preset must never authorize scanning"
        );
    }

    #[test]
    fn questionnaire_rejects_unsafe_or_misplaced_website_context() {
        let fixture = Fixture::new();
        let base = || CreateCaseRequest {
            title: "Website context validation".into(),
            organization_name: "Example Co".into(),
            employee_range: "2-49".into(),
            assessment_intent: None,
            data_classes: vec![],
            requested_activities: vec![],
            source_kinds: vec![],
            not_applicable_source_kinds: vec![],
            declared_assets: vec![],
            notes: None,
        };

        let mut unsafe_path = base();
        unsafe_path.declared_assets.push(DeclaredAssetInput {
            kind: DeclaredAssetKind::ExternalTarget,
            value: "app.example.test".into(),
            internet_exposed: Some(true),
            web_service: Some(DeclaredWebServiceInput {
                protocol: DeclaredWebProtocol::Https,
                port: 443,
                path: "/login?token=secret".into(),
            }),
        });
        assert!(fixture.service().create_case(&unsafe_path).is_err());

        let mut misplaced = base();
        misplaced.declared_assets.push(DeclaredAssetInput {
            kind: DeclaredAssetKind::Repository,
            value: "https://github.com/example/service".into(),
            internet_exposed: None,
            web_service: Some(DeclaredWebServiceInput {
                protocol: DeclaredWebProtocol::Https,
                port: 443,
                path: "/".into(),
            }),
        });
        assert!(fixture.service().create_case(&misplaced).is_err());
        assert!(fixture.service().list_cases().unwrap().is_empty());
    }

    #[test]
    fn finding_groups_are_reversible_and_never_replace_canonical_findings() {
        let fixture = Fixture::new();
        let mut case = fixture.create();
        let now = Utc::now();
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: now,
            completed_at: Some(now),
            knowledge_cutoff: now,
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_runs: vec![],
        });
        for (id, fingerprint, priority) in [
            ("finding-a", "engine-a:rule", 40),
            ("finding-b", "engine-b:rule", 80),
        ] {
            case.findings.push(Finding {
                id: id.into(),
                case_id: case.id.clone(),
                first_seen_run_id: "run-1".into(),
                last_seen_run_id: "run-1".into(),
                fingerprint: fingerprint.into(),
                title: format!("Independent {id}"),
                plain_language_summary: "Independent canonical record".into(),
                possible_impact: "Requires human review".into(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                priority,
                priority_reasons: vec![],
                asset_ids: vec!["asset-1".into()],
                evidence: vec![Evidence {
                    id: format!("evidence-{id}"),
                    finding_id: id.into(),
                    run_id: "run-1".into(),
                    engine_run_id: None,
                    kind: EvidenceKind::Configuration,
                    engine_id: fingerprint.split(':').next().unwrap().into(),
                    observed_at: now,
                    summary: format!("Independent evidence for {id}"),
                    artifact_id: format!("artifact-{id}"),
                    artifact_sha256: "a".repeat(64),
                    pointer: Some(format!("/findings/{id}")),
                    redacted: false,
                }],
                control_references: vec![],
                recommendation: "Review without automatic remediation".into(),
                verification_guidance: "Re-run the responsible engine".into(),
                rollback_considerations: None,
                official_references: vec![],
                recommended_expert_type: "Security reviewer".into(),
                status: FindingStatus::Unreviewed,
                tags: vec![],
            });
            case.finding_observations.push(FindingObservation {
                id: format!("observation-{id}"),
                run_id: "run-1".into(),
                finding_id: id.into(),
                fingerprint: fingerprint.into(),
                asset_ids: vec!["asset-1".into()],
                engine_ids: vec![fingerprint.split(':').next().unwrap().into()],
                severity: Severity::Medium,
                confidence: Confidence::High,
                evidence_hashes: vec!["a".repeat(64)],
                observed_at: now,
                finding_snapshot: None,
            });
        }
        case.updated_at = now;
        let canonical_findings = serde_json::to_value(&case.findings).unwrap();
        fixture
            .storage
            .save_case(&mut case, "test.findings")
            .unwrap();

        let group_title = "Related access observations";
        let group_rationale = "A human should review the shared access path together.";
        let group_actor = "Private grouping operator";
        let grouped = fixture
            .service()
            .group_findings(
                &case.id,
                FindingGroupRequest {
                    title: group_title.into(),
                    finding_ids: vec!["finding-b".into(), "finding-a".into()],
                    rationale: group_rationale.into(),
                    grouped_by: group_actor.into(),
                },
            )
            .unwrap();
        assert_eq!(grouped.findings.len(), 2);
        assert_eq!(
            serde_json::to_value(&grouped.findings).unwrap(),
            canonical_findings
        );
        assert_eq!(grouped.finding_groups.len(), 1);
        assert_eq!(
            grouped.finding_groups[0].finding_ids,
            ["finding-a", "finding-b"]
        );
        assert_eq!(grouped.finding_group_events.len(), 1);
        assert_eq!(
            grouped.finding_group_events[0].action,
            FindingGroupAction::Created
        );
        let created_event = serde_json::to_value(&grouped.finding_group_events[0]).unwrap();

        let unredacted_html = String::from_utf8(
            html_report_bytes(
                &grouped,
                "run-1",
                &ExportOptions {
                    redaction: RedactionProfile::None,
                    include_raw_artifacts: false,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(unredacted_html.contains("Reversible finding groups"));
        assert!(unredacted_html.contains(group_title));
        assert!(unredacted_html.contains(group_rationale));
        assert!(unredacted_html.contains("Independent finding-a"));
        assert!(unredacted_html.contains("Independent finding-b"));
        assert!(unredacted_html.contains("Handoff order #1"));
        assert!(
            unredacted_html.rfind("Independent finding-b").unwrap()
                < unredacted_html.rfind("Independent finding-a").unwrap()
        );
        assert!(!unredacted_html.contains("Priority 80"));
        assert!(!unredacted_html.contains("Priority 40"));

        let redacted_html = String::from_utf8(
            html_report_bytes(&grouped, "run-1", &ExportOptions::default()).unwrap(),
        )
        .unwrap();
        assert!(redacted_html.contains("redacted finding group"));
        for sensitive in [group_title, group_rationale, group_actor] {
            assert!(!redacted_html.contains(sensitive));
        }

        assert!(
            fixture
                .service()
                .group_findings(
                    &case.id,
                    FindingGroupRequest {
                        title: "Overlapping group".into(),
                        finding_ids: vec!["finding-a".into(), "finding-b".into()],
                        rationale: "Must not create a second active presentation owner".into(),
                        grouped_by: "Another operator".into(),
                    },
                )
                .is_err()
        );
        assert_eq!(
            fixture
                .service()
                .show_case(&case.id)
                .unwrap()
                .finding_group_events
                .len(),
            1
        );

        let group_id = grouped.finding_groups[0].id.clone();
        let removal_actor = "Private removal operator";
        let removal_reason = "The shared path was disproven; retain both observations.";
        let ungrouped = fixture
            .service()
            .ungroup_findings(
                &case.id,
                FindingUngroupRequest {
                    group_id,
                    removed_by: removal_actor.into(),
                    reason: removal_reason.into(),
                },
            )
            .unwrap();
        assert!(ungrouped.finding_groups.is_empty());
        assert_eq!(ungrouped.findings.len(), 2);
        assert_eq!(
            serde_json::to_value(&ungrouped.findings).unwrap(),
            canonical_findings
        );
        assert_eq!(ungrouped.finding_group_events.len(), 2);
        assert_eq!(
            serde_json::to_value(&ungrouped.finding_group_events[0]).unwrap(),
            created_event
        );
        assert_eq!(
            ungrouped.finding_group_events[1].action,
            FindingGroupAction::Removed
        );
        assert_eq!(ungrouped.finding_group_events[1].title, group_title);
        assert_eq!(
            ungrouped.finding_group_events[1].finding_ids,
            ["finding-a", "finding-b"]
        );
        assert_eq!(ungrouped.finding_group_events[1].rationale, removal_reason);
        assert!(
            ungrouped
                .findings
                .iter()
                .all(|finding| finding.fingerprint.starts_with("engine-"))
        );

        let canonical =
            canonical_json_bytes(&ungrouped, "run-1", &ExportOptions::default()).unwrap();
        let canonical_text = String::from_utf8(canonical.clone()).unwrap();
        for sensitive in [
            group_title,
            group_rationale,
            group_actor,
            removal_actor,
            removal_reason,
        ] {
            assert!(!canonical_text.contains(sensitive));
        }
        let canonical: Value = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(
            canonical
                .pointer("/case/finding_groups")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            canonical
                .pointer("/case/finding_group_events")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn lifecycle_persists_across_reopen_and_delete_returns_explicit_artifact_plan() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("casework.db");
        let case_id = {
            let storage = Storage::open(&database).unwrap();
            let engines = EngineRegistry::load_builtin().unwrap();
            let adapters = AdapterRegistry::default();
            let service = CaseService::new(
                &storage,
                &engines,
                &adapters,
                directory.path().join("artifacts"),
                directory.path().join("key"),
            );
            service
                .create_case(&CreateCaseRequest {
                    title: "Persistent".into(),
                    organization_name: "Example".into(),
                    employee_range: "1-10".into(),
                    assessment_intent: None,
                    data_classes: vec![],
                    requested_activities: vec![],
                    source_kinds: vec![],
                    not_applicable_source_kinds: vec![],
                    declared_assets: vec![],
                    notes: None,
                })
                .unwrap()
                .id
        };
        let storage = Storage::open(&database).unwrap();
        let engines = EngineRegistry::load_builtin().unwrap();
        let adapters = AdapterRegistry::default();
        let service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            directory.path().join("artifacts"),
            directory.path().join("key"),
        );
        assert_eq!(service.show_case(&case_id).unwrap().title, "Persistent");
        let case_artifacts = directory.path().join("artifacts").join(&case_id);
        fs::create_dir_all(&case_artifacts).unwrap();
        fs::write(case_artifacts.join("evidence.bin"), b"sensitive evidence").unwrap();
        let deletion = service.delete_case(&case_id).unwrap();
        assert!(deletion.database_record_deleted);
        assert!(deletion.artifacts.requires_explicit_confirmation);
        assert!(service.show_case(&case_id).is_err());
        assert_eq!(
            service.list_artifact_deletion_obligations().unwrap(),
            vec![deletion.artifacts.clone()]
        );
        drop(service);
        let reopened_service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            directory.path().join("artifacts"),
            directory.path().join("key"),
        );
        assert_eq!(
            reopened_service
                .list_artifact_deletion_obligations()
                .unwrap(),
            vec![deletion.artifacts.clone()]
        );
        assert!(
            reopened_service
                .delete_case_artifacts(
                    &case_id,
                    &deletion.artifacts.exact_path,
                    "wrong confirmation",
                )
                .is_err()
        );
        let removed = reopened_service
            .delete_case_artifacts(
                &case_id,
                &deletion.artifacts.exact_path,
                &format!("DELETE {case_id}"),
            )
            .unwrap();
        assert!(removed.removed);
        assert!(!removed.recoverable);
        assert!(!case_artifacts.exists());
        assert!(
            reopened_service
                .list_artifact_deletion_obligations()
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            reopened_service.delete_case_artifacts(
                &case_id,
                &deletion.artifacts.exact_path,
                &format!("DELETE {case_id}"),
            ),
            Err(AppError::NotAuthorized(_))
        ));
    }

    #[test]
    fn legacy_artifact_obligation_migrates_before_listing_and_remains_deletable() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let case_artifacts = fixture.directory.path().join("artifacts").join(&case.id);
        fs::create_dir_all(&case_artifacts).unwrap();
        fs::write(case_artifacts.join("evidence.bin"), b"legacy evidence").unwrap();
        let service = fixture.service();
        let plan = service.artifact_deletion_plan(&case.id).unwrap();
        fixture
            .storage
            .delete_case(&case.id, case.storage_revision, None)
            .unwrap();
        let legacy_path = write_legacy_artifact_deletion_obligation(&fixture, &plan);

        assert_eq!(
            service.list_artifact_deletion_obligations().unwrap(),
            vec![plan.clone()]
        );
        assert!(!legacy_path.exists());
        let durable = fixture
            .storage
            .list_artifact_deletion_obligations()
            .unwrap();
        assert_eq!(durable.len(), 1);
        assert_eq!(durable[0].case_id, case.id);
        assert_eq!(durable[0].exact_path, plan.exact_path);

        let removed = service
            .delete_case_artifacts(
                &plan.case_id,
                &plan.exact_path,
                &format!("DELETE {}", plan.case_id),
            )
            .unwrap();
        assert!(removed.removed);
        assert!(!case_artifacts.exists());
    }

    #[test]
    fn legacy_artifact_obligation_migrates_on_direct_delete() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let case_artifacts = fixture.directory.path().join("artifacts").join(&case.id);
        fs::create_dir_all(&case_artifacts).unwrap();
        fs::write(case_artifacts.join("evidence.bin"), b"legacy evidence").unwrap();
        let service = fixture.service();
        let plan = service.artifact_deletion_plan(&case.id).unwrap();
        fixture
            .storage
            .delete_case(&case.id, case.storage_revision, None)
            .unwrap();
        let legacy_path = write_legacy_artifact_deletion_obligation(&fixture, &plan);

        let removed = service
            .delete_case_artifacts(&case.id, &plan.exact_path, &format!("DELETE {}", case.id))
            .unwrap();
        assert!(removed.removed);
        assert!(!legacy_path.exists());
        assert!(
            fixture
                .storage
                .list_artifact_deletion_obligations()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn legacy_artifact_obligation_is_preserved_for_a_live_case() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let case_artifacts = fixture.directory.path().join("artifacts").join(&case.id);
        fs::create_dir_all(&case_artifacts).unwrap();
        let service = fixture.service();
        let plan = service.artifact_deletion_plan(&case.id).unwrap();
        let legacy_path = write_legacy_artifact_deletion_obligation(&fixture, &plan);

        assert!(matches!(
            service.list_artifact_deletion_obligations(),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(legacy_path.exists());
        assert!(
            fixture
                .storage
                .list_artifact_deletion_obligations()
                .unwrap()
                .is_empty()
        );
        assert_eq!(service.show_case(&case.id).unwrap().id, case.id);
    }

    #[test]
    fn legacy_artifact_obligation_rejects_a_path_outside_the_artifact_root() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let case_artifacts = fixture.directory.path().join("artifacts").join(&case.id);
        fs::create_dir_all(&case_artifacts).unwrap();
        let service = fixture.service();
        let mut plan = service.artifact_deletion_plan(&case.id).unwrap();
        fixture
            .storage
            .delete_case(&case.id, case.storage_revision, None)
            .unwrap();
        plan.exact_path = fixture
            .directory
            .path()
            .join("outside")
            .join(&case.id)
            .display()
            .to_string();
        let legacy_path = write_legacy_artifact_deletion_obligation(&fixture, &plan);

        assert!(matches!(
            service.list_artifact_deletion_obligations(),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(legacy_path.exists());
        assert!(case_artifacts.exists());
        assert!(
            fixture
                .storage
                .list_artifact_deletion_obligations()
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_artifact_obligation_is_durable_before_unlink_and_retry_is_idempotent() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let case = fixture.create();
        let case_artifacts = fixture.directory.path().join("artifacts").join(&case.id);
        fs::create_dir_all(&case_artifacts).unwrap();
        let service = fixture.service();
        let plan = service.artifact_deletion_plan(&case.id).unwrap();
        fixture
            .storage
            .delete_case(&case.id, case.storage_revision, None)
            .unwrap();
        let legacy_path = write_legacy_artifact_deletion_obligation(&fixture, &plan);
        let legacy_root = legacy_path.parent().unwrap();
        fs::set_permissions(legacy_root, fs::Permissions::from_mode(0o500)).unwrap();

        let result = service.list_artifact_deletion_obligations();
        fs::set_permissions(legacy_root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert!(legacy_path.exists());
        let durable = fixture
            .storage
            .list_artifact_deletion_obligations()
            .unwrap();
        assert_eq!(durable.len(), 1, "SQLite commit must precede legacy unlink");
        assert_eq!(durable[0].exact_path, plan.exact_path);

        assert_eq!(
            service.list_artifact_deletion_obligations().unwrap(),
            vec![plan]
        );
        assert!(!legacy_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_artifact_obligation_symlink_is_never_followed() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let case = fixture.create();
        let case_artifacts = fixture.directory.path().join("artifacts").join(&case.id);
        fs::create_dir_all(&case_artifacts).unwrap();
        let service = fixture.service();
        let plan = service.artifact_deletion_plan(&case.id).unwrap();
        fixture
            .storage
            .delete_case(&case.id, case.storage_revision, None)
            .unwrap();
        let target = fixture.directory.path().join("outside-obligation.json");
        fs::write(&target, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        let root = fixture
            .directory
            .path()
            .join("artifacts")
            .join(LEGACY_DELETION_OBLIGATION_DIRECTORY);
        fs::create_dir_all(&root).unwrap();
        let linked = root.join(format!("{}.json", case.id));
        symlink(&target, &linked).unwrap();

        assert!(matches!(
            service.list_artifact_deletion_obligations(),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(linked.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(target.exists());
        assert!(
            fixture
                .storage
                .list_artifact_deletion_obligations()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn artifact_deletion_refuses_a_live_case_without_an_obligation() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let case_artifacts = fixture.directory.path().join("artifacts").join(&case.id);
        fs::create_dir_all(&case_artifacts).unwrap();
        fs::write(case_artifacts.join("evidence.bin"), b"keep me").unwrap();
        let service = fixture.service();
        let plan = service.artifact_deletion_plan(&case.id).unwrap();

        assert!(matches!(
            service.delete_case_artifacts(
                &case.id,
                &plan.exact_path,
                &format!("DELETE {}", case.id),
            ),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(case_artifacts.join("evidence.bin").exists());
        assert_eq!(service.show_case(&case.id).unwrap().id, case.id);
    }

    #[test]
    fn artifact_deletion_refuses_a_deleted_case_without_an_obligation() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let service = fixture.service();
        let deletion = service.delete_case(&case.id).unwrap();
        assert!(!deletion.artifacts.exists);
        assert!(
            service
                .list_artifact_deletion_obligations()
                .unwrap()
                .is_empty()
        );

        let case_artifacts = fixture.directory.path().join("artifacts").join(&case.id);
        fs::create_dir_all(&case_artifacts).unwrap();
        fs::write(case_artifacts.join("late-file.bin"), b"keep me").unwrap();
        assert!(matches!(
            service.delete_case_artifacts(
                &case.id,
                &deletion.artifacts.exact_path,
                &format!("DELETE {}", case.id),
            ),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(case_artifacts.join("late-file.bin").exists());
    }

    #[test]
    fn case_deletion_refuses_active_or_paused_engine_work() {
        for status in [EngineRunStatus::Running, EngineRunStatus::Paused] {
            let fixture = Fixture::new();
            let mut case = fixture.create();
            let now = Utc::now();
            let mut engine_run = not_executed_run(
                "run-active",
                "engine-active",
                "fixture-engine",
                vec![],
                ("fixture", "fixture"),
                None,
                now,
            );
            engine_run.status = status.clone();
            engine_run.phase = "active_fixture".into();
            engine_run.finished_at = None;
            case.scan_runs.push(ScanRun {
                id: "run-active".into(),
                case_id: case.id.clone(),
                sequence: 1,
                created_at: now,
                completed_at: None,
                knowledge_cutoff: now,
                verification_baseline_run_id: None,
                scope_grant_ids: vec![],
                scope_grant_snapshots: vec![],
                engine_runs: vec![engine_run],
            });
            fixture
                .storage
                .save_case(&mut case, "test.active_run")
                .unwrap();

            let service = fixture.service();
            let error = service.delete_case(&case.id).unwrap_err();
            assert!(error.to_string().contains("active, paused"));
            assert_eq!(service.show_case(&case.id).unwrap().id, case.id);
        }
    }

    #[test]
    fn case_deletion_refuses_unfinished_provider_bootstrap_cleanup() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let now = Utc::now();
        let ledger = create_cleanup_ledger(
            &case.id,
            CreatedBootstrapResources::Aws {
                stack_id: "arn:aws:cloudformation:us-east-1:123456789012:stack/ai-security-scanner/11111111-1111-4111-8111-111111111111".into(),
                stack_name: "ai-security-scanner".into(),
                role_arn: "arn:aws:iam::123456789012:role/ai-security-scanner".into(),
                role_name: "ai-security-scanner".into(),
            },
            now + Duration::minutes(30),
            now,
            now,
        )
        .unwrap();
        let cleanup_path = fixture
            .directory
            .path()
            .join("artifacts")
            .join(&case.id)
            .join("provider-bootstrap")
            .join("cleanup-test-operation.json");
        write_cleanup_ledger(&cleanup_path, &ledger).unwrap();

        let service = fixture.service();
        let error = service.delete_case(&case.id).unwrap_err();
        assert!(error.to_string().contains("bootstrap cleanup obligation"));
        assert_eq!(service.show_case(&case.id).unwrap().id, case.id);
        assert!(cleanup_path.exists());
    }

    #[test]
    fn discovery_without_scope_cannot_create_a_scan_run() {
        let fixture = Fixture::new();
        let case = fixture.create();
        fixture.discovered_asset(&case.id, AssetKind::CloudAccount);
        let service = fixture.service();
        let error = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["cloudquery".into()],
                },
            )
            .unwrap_err();
        assert!(matches!(error, AppError::NotAuthorized(_)));
        assert!(service.show_case(&case.id).unwrap().scan_runs.is_empty());
    }

    #[test]
    fn demo_case_can_never_be_planned_or_mutated_into_a_real_case() {
        let fixture = Fixture::new();
        let mut demo = crate::demo::build_demo_case();
        fixture.storage.save_case(&mut demo, "demo.seeded").unwrap();
        let service = fixture.service();
        let error = service
            .plan_scan(&demo.id, ScanPlanRequest::default())
            .unwrap_err();
        assert!(matches!(error, AppError::NotAuthorized(_)));
        assert!(
            service
                .upsert_source(
                    &demo.id,
                    SourceMutation {
                        id: None,
                        kind: SourceKind::Dns,
                        label: "real".into(),
                        status: SourceConnectionStatus::Connected,
                        read_only: true,
                        metadata: BTreeMap::new(),
                    }
                )
                .is_err()
        );
        assert!(service.show_case(&demo.id).unwrap().is_demo);
    }

    #[test]
    fn external_scope_requires_authorization_and_scope_is_deduplicated() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, asset_id) = fixture.discovered_asset(&case.id, AssetKind::Domain);
        let service = fixture.service();
        let mut attributable = service.show_case(&case.id).unwrap();
        attributable.assets[0].name = "app.example.test".into();
        attributable.assets[0].identifiers.push(AssetIdentifier {
            namespace: "dns:name".into(),
            value: "app.example.test".into(),
        });
        attributable.assets[0].internet_exposed = Some(true);
        fixture
            .storage
            .save_case(&mut attributable, "test.external_target_attributed")
            .unwrap();
        let request = ScopeApprovalRequest {
            asset_id: asset_id.clone(),
            permissions: vec![
                ScanPermission::ActiveExternalTesting,
                ScanPermission::ActiveExternalTesting,
            ],
            confirmed_by: "Owner".into(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            authorization_reference: None,
            notes: None,
            external_scope: Some(ExternalScopeRequest {
                target: "app.example.test".into(),
                ports: [443].into_iter().collect(),
                protocol: crate::external_scope::TransportProtocol::Https,
                activity: ExternalActivity::ActiveExternal,
                rate_policy: crate::external_scope::RatePolicy {
                    requests_per_second: 2,
                    concurrency: 1,
                    timeout_seconds: 300,
                },
                template_policy: crate::external_scope::TemplatePolicy::conservative(
                    "nuclei-templates@0123456789abcdef0123456789abcdef01234567",
                    vec!["http/misconfiguration/fixture".into()],
                ),
                asserted_authority: "ticket SEC-1042".into(),
                allow_sensitive_networks: false,
            }),
        };
        assert!(matches!(
            service
                .approve_scope(&case.id, request.clone())
                .unwrap_err(),
            AppError::NotAuthorized(_)
        ));
        let mut authorized = request;
        authorized.authorization_reference = Some("CHANGE-123".into());
        service.approve_scope(&case.id, authorized.clone()).unwrap();
        service.approve_scope(&case.id, authorized).unwrap();
        let stored = service.show_case(&case.id).unwrap();
        assert_eq!(stored.scope_grants.len(), 1);
        assert!(stored.assets[0].owner_confirmed);
        assert_eq!(
            stored.scope_grants[0]
                .external_scope
                .as_ref()
                .unwrap()
                .target,
            CanonicalTarget::Hostname("app.example.test".into())
        );
    }

    #[test]
    fn scope_approval_batch_rolls_back_every_decision_when_one_is_invalid() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, asset_id) = fixture.discovered_asset(&case.id, AssetKind::Repository);
        let service = fixture.service();
        let before = service.show_case(&case.id).unwrap();
        assert!(before.scope_grants.is_empty());
        assert!(!before.assets[0].owner_confirmed);

        let result = service.approve_scopes(
            &case.id,
            vec![
                ScopeApprovalRequest {
                    asset_id: asset_id.clone(),
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Repository owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: Some("valid first decision".into()),
                    external_scope: None,
                },
                ScopeApprovalRequest {
                    asset_id: "missing-asset".into(),
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Repository owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: Some("invalid second decision".into()),
                    external_scope: None,
                },
            ],
        );
        assert!(matches!(result, Err(AppError::InvalidRequest(_))));

        let after = service.show_case(&case.id).unwrap();
        assert!(after.scope_grants.is_empty());
        let asset = after
            .assets
            .iter()
            .find(|asset| asset.id == asset_id)
            .unwrap();
        assert!(!asset.owner_confirmed);
        assert!(asset.candidate);
    }

    #[test]
    fn source_metadata_rejects_secret_bearing_fields() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let service = fixture.service();
        let error = service
            .upsert_source(
                &case.id,
                SourceMutation {
                    id: None,
                    kind: SourceKind::AwsOrganization,
                    label: "AWS".into(),
                    status: SourceConnectionStatus::Connected,
                    read_only: true,
                    metadata: BTreeMap::from([(
                        "clientSecret".into(),
                        Value::String("must-not-persist".into()),
                    )]),
                },
            )
            .unwrap_err();
        assert!(matches!(error, AppError::InvalidRequest(_)));
        assert!(service.show_case(&case.id).unwrap().data_sources.is_empty());
    }

    #[test]
    fn compatible_pinned_engine_produces_a_least_privilege_typed_plan() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, asset_id) = fixture.discovered_asset(&case.id, AssetKind::Repository);
        let service = fixture.service();
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        let plan = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 1);
        assert!(plan.not_executed.is_empty());
        assert_eq!(plan.scan_run.engine_runs[0].status, EngineRunStatus::Queued);
        assert_eq!(plan.scan_run.scope_grant_snapshots.len(), 1);
        assert_eq!(
            plan.scan_run.scope_grant_snapshots[0].id,
            plan.scan_run.scope_grant_ids[0]
        );
        assert!(
            plan.scan_run.engine_runs[0]
                .scope_contract_sha256
                .as_deref()
                .is_some_and(|digest| digest.len() == 64)
        );
        assert_eq!(
            plan.scan_run.engine_runs[0]
                .fingerprint_schema_version
                .as_deref(),
            Some(FINGERPRINT_SCHEMA_VERSION)
        );
        assert!(plan.scan_run.engine_runs[0].mapping_version.is_some());
        assert_eq!(plan.executable[0].scope_grants.len(), 1);
        assert_eq!(
            plan.executable[0].scope_grants[0].permission,
            ScanPermission::LocalArtifactRead
        );
        assert!(plan.scan_run.engine_runs[0].resume_token.is_some());
    }

    #[test]
    fn rescan_plan_atomically_persists_verification_intent_and_finalizes_idempotently() {
        let fixture = Fixture::new();
        let (case_id, baseline_run_id) = repository_case_with_completed_baseline(&fixture);
        let service = fixture.service();

        let runs_before = service.show_case(&case_id).unwrap().scan_runs.len();
        assert!(
            service
                .plan_rescan(
                    &case_id,
                    "missing-baseline",
                    ScanPlanRequest {
                        engine_ids: vec!["gitleaks".into()],
                    },
                )
                .is_err()
        );
        assert_eq!(
            service.show_case(&case_id).unwrap().scan_runs.len(),
            runs_before,
            "an invalid baseline must not persist an ordinary scan before failing"
        );

        let rescan = service
            .plan_rescan(
                &case_id,
                &baseline_run_id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
            )
            .unwrap();
        assert_eq!(rescan.plan.executable.len(), 1);
        assert_eq!(
            rescan.plan.scan_run.verification_baseline_run_id.as_deref(),
            Some(baseline_run_id.as_str())
        );
        let planned = service.show_case(&case_id).unwrap();
        assert_eq!(planned.scan_runs.len(), runs_before + 1);
        assert_eq!(planned.status, CaseStatus::Verifying);
        assert_eq!(
            planned
                .scan_runs
                .last()
                .unwrap()
                .verification_baseline_run_id,
            Some(baseline_run_id.clone())
        );
        assert!(
            service
                .finalize_verification_if_terminal(&case_id, &rescan.plan.scan_run.id)
                .unwrap()
                .is_none(),
            "a queued verification run cannot be compared"
        );

        let mut terminal = planned;
        let current = terminal.scan_runs.last_mut().unwrap();
        for engine_run in &mut current.engine_runs {
            engine_run.status = EngineRunStatus::Completed;
            engine_run.progress_percent = 100;
            engine_run.phase = "completed".into();
            engine_run.finished_at = Some(Utc::now());
        }
        current.completed_at = Some(Utc::now());
        fixture
            .storage
            .save_case(&mut terminal, "test.verification_terminal")
            .unwrap();

        let first = service
            .finalize_verification_if_terminal(&case_id, &rescan.plan.scan_run.id)
            .unwrap()
            .unwrap();
        let replay = service
            .finalize_verification_if_terminal(&case_id, &rescan.plan.scan_run.id)
            .unwrap()
            .unwrap();
        assert_eq!(first.id, replay.id);
        let finalized = service.show_case(&case_id).unwrap();
        assert_eq!(finalized.comparisons.len(), 1);
        assert_eq!(finalized.status, CaseStatus::ReadyForHandoff);
    }

    #[test]
    fn executable_empty_and_startup_paths_complete_pending_verification_once() {
        let fixture = Fixture::new();
        let (case_id, baseline_run_id) = repository_case_with_completed_baseline(&fixture);
        let service = fixture.service();

        let empty = service
            .plan_rescan(
                &case_id,
                &baseline_run_id,
                ScanPlanRequest {
                    engine_ids: vec!["missing".into()],
                },
            )
            .unwrap();
        assert!(empty.plan.executable.is_empty());
        assert!(empty.plan.scan_run.completed_at.is_some());
        assert_eq!(
            empty.plan.scan_run.verification_baseline_run_id.as_deref(),
            Some(baseline_run_id.as_str())
        );
        let empty_comparison = service
            .finalize_verification_if_terminal(&case_id, &empty.plan.scan_run.id)
            .unwrap()
            .unwrap();
        assert_eq!(empty_comparison.current_run_id, empty.plan.scan_run.id);

        let crash_window = service
            .plan_rescan(
                &case_id,
                &baseline_run_id,
                ScanPlanRequest {
                    engine_ids: vec!["missing".into()],
                },
            )
            .unwrap();
        assert!(crash_window.plan.executable.is_empty());
        assert_eq!(service.show_case(&case_id).unwrap().comparisons.len(), 1);
        assert_eq!(service.reconcile_terminal_verifications().unwrap(), 1);
        assert_eq!(service.reconcile_terminal_verifications().unwrap(), 0);
        let reconciled = service.show_case(&case_id).unwrap();
        assert_eq!(reconciled.comparisons.len(), 2);
        assert!(reconciled.comparisons.iter().any(|comparison| {
            comparison.baseline_run_id == baseline_run_id
                && comparison.current_run_id == crash_window.plan.scan_run.id
        }));
    }

    #[test]
    fn interrupted_cleanup_failure_remains_durable_until_exact_retry_succeeds() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, asset_id) = fixture.discovered_asset(&case.id, AssetKind::Repository);
        let service = fixture.service();
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        let original = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
            )
            .unwrap();

        let mut running = service.show_case(&case.id).unwrap();
        let engine_run = &mut running.scan_runs[0].engine_runs[0];
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(engine_run.resume_token.as_deref().unwrap())
                .unwrap();
        checkpoint.stage = ExecutionStage::Running;
        checkpoint.cleanup_completed = false;
        checkpoint.container_name = Some(
            crate::container_runtime::planned_container_name(
                &checkpoint.engine_id,
                &checkpoint.engine_run_id,
                checkpoint.attempt,
            )
            .unwrap(),
        );
        checkpoint.runtime_command_provenance =
            Some(crate::container_runtime::RuntimeCommandProvenance::Compatibility);
        checkpoint.runtime_provider = Some(crate::container_runtime::RuntimeProvider::Podman);
        engine_run.resume_token = Some(checkpoint.resume_token().unwrap());
        fixture
            .storage
            .save_case(&mut running, "test.running_before_restart")
            .unwrap();

        assert_eq!(service.recover_interrupted_scans().unwrap(), 1);
        let interrupted = service.show_case(&case.id).unwrap();
        let interrupted_token = interrupted.scan_runs[0].engine_runs[0]
            .resume_token
            .clone()
            .unwrap();
        assert!(matches!(
            service.record_interrupted_cleanup_failure(
                &case.id,
                &original.scan_run.id,
                &original.scan_run.engine_runs[0].id,
                "not-the-stored-token",
                "must not be recorded",
            ),
            Err(AppError::NotAuthorized(_))
        ));

        let pending = service
            .record_interrupted_cleanup_failure(
                &case.id,
                &original.scan_run.id,
                &original.scan_run.engine_runs[0].id,
                &interrupted_token,
                "runtime was unavailable during exact reconciliation",
            )
            .unwrap();
        let pending_engine = &pending.scan_runs[0].engine_runs[0];
        assert_eq!(pending_engine.phase, "interrupted_restart_cleanup_pending");
        let pending_token = pending_engine.resume_token.clone().unwrap();
        let pending_checkpoint = ExecutionCheckpoint::from_resume_token(&pending_token).unwrap();
        assert_eq!(pending_checkpoint.stage, ExecutionStage::CleanupPending);
        assert!(!pending_checkpoint.cleanup_completed);
        assert_eq!(service.recover_interrupted_scans().unwrap(), 0);
        assert!(matches!(
            service.plan_resume(&case.id, &original.scan_run.id),
            Err(AppError::NotAvailable(_))
        ));
        assert!(matches!(
            service.resume_scan(&case.id, &original.scan_run.id),
            Err(AppError::NotAvailable(_))
        ));
        assert!(matches!(
            service.cancel_scan(&case.id, &original.scan_run.id),
            Err(AppError::NotAvailable(_))
        ));

        let cleaned = service
            .record_interrupted_cleanup_success(
                &case.id,
                &original.scan_run.id,
                &original.scan_run.engine_runs[0].id,
                InterruptedCleanupSuccess {
                    expected_resume_token: pending_token,
                    cleanup: CleanupOutcome {
                        removed: true,
                        detail: "removed exact immutable container object".into(),
                    },
                    orphan_credentials_removed: 1,
                },
            )
            .unwrap();
        let cleaned_engine = &cleaned.scan_runs[0].engine_runs[0];
        assert_eq!(cleaned_engine.phase, "interrupted_restart_cleaned");
        assert_eq!(cleaned_engine.status, EngineRunStatus::Paused);
        assert_eq!(cleaned_engine.cleanup_removed, Some(true));
        assert!(cleaned_engine.warnings.iter().any(|warning| {
            warning.contains("Zeroized and removed 1 crash-left credential envelope")
        }));
        let cleaned_checkpoint =
            ExecutionCheckpoint::from_resume_token(cleaned_engine.resume_token.as_deref().unwrap())
                .unwrap();
        assert_eq!(cleaned_checkpoint.stage, ExecutionStage::Failed);
        assert!(cleaned_checkpoint.cleanup_completed);
        assert_eq!(cleaned_checkpoint.attempt, 1);
        assert!(cleaned_checkpoint.managed_network.is_none());
        assert_eq!(service.recover_interrupted_scans().unwrap(), 0);
        assert_eq!(
            service
                .plan_resume(&case.id, &original.scan_run.id)
                .unwrap()
                .executable[0]
                .attempt,
            2
        );
    }

    #[test]
    fn interrupted_run_is_paused_and_resumed_as_a_new_attempt_without_scope_widening() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, asset_id) = fixture.discovered_asset(&case.id, AssetKind::Repository);
        let service = fixture.service();
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        let original = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["gitleaks".into()],
                },
            )
            .unwrap();
        assert_eq!(original.executable[0].attempt, 1);

        assert_eq!(service.recover_interrupted_scans().unwrap(), 1);
        let interrupted = service.show_case(&case.id).unwrap();
        assert_eq!(
            interrupted.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Paused
        );
        assert_eq!(
            interrupted.scan_runs[0].engine_runs[0]
                .error_code
                .as_deref(),
            Some("desktop_process_restarted")
        );
        assert!(matches!(
            service.plan_resume(&case.id, &original.scan_run.id),
            Err(AppError::NotAvailable(_))
        ));
        let interrupted_token = interrupted.scan_runs[0].engine_runs[0]
            .resume_token
            .clone()
            .unwrap();
        service
            .record_interrupted_cleanup_success(
                &case.id,
                &original.scan_run.id,
                &original.scan_run.engine_runs[0].id,
                InterruptedCleanupSuccess {
                    expected_resume_token: interrupted_token,
                    cleanup: CleanupOutcome {
                        removed: false,
                        detail: "the planned execution had created no runtime resources".into(),
                    },
                    orphan_credentials_removed: 0,
                },
            )
            .unwrap();
        assert_eq!(service.recover_interrupted_scans().unwrap(), 0);

        let resumed = service
            .plan_resume(&case.id, &original.scan_run.id)
            .unwrap();
        assert_eq!(resumed.executable.len(), 1);
        assert_eq!(resumed.executable[0].attempt, 2);
        assert_eq!(
            resumed.scan_run.engine_runs[0].status,
            EngineRunStatus::Queued
        );

        assert_eq!(service.recover_interrupted_scans().unwrap(), 1);
        let mut changed_scope = service.show_case(&case.id).unwrap();
        let interrupted_token = changed_scope.scan_runs[0].engine_runs[0]
            .resume_token
            .clone()
            .unwrap();
        service
            .record_interrupted_cleanup_success(
                &case.id,
                &original.scan_run.id,
                &original.scan_run.engine_runs[0].id,
                InterruptedCleanupSuccess {
                    expected_resume_token: interrupted_token,
                    cleanup: CleanupOutcome {
                        removed: false,
                        detail: "the queued retry had created no runtime resources".into(),
                    },
                    orphan_credentials_removed: 0,
                },
            )
            .unwrap();
        changed_scope = service.show_case(&case.id).unwrap();
        changed_scope.scope_grants[0].confirmed_at =
            original.scan_run.created_at + Duration::seconds(1);
        fixture
            .storage
            .save_case(&mut changed_scope, "test.scope_reapproved")
            .unwrap();
        let error = service
            .plan_resume(&case.id, &original.scan_run.id)
            .unwrap_err();
        assert!(matches!(error, AppError::NotAuthorized(_)));
    }

    #[test]
    fn runnable_engines_execute_while_unknown_engines_remain_durable_not_executed_records() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, asset_id) = fixture.discovered_aws_account(&case.id, "111122223333");
        let service = fixture.service();
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::InventoryRead],
                    confirmed_by: "Owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        let plan = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["steampipe".into(), "missing".into()],
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 1);
        assert_eq!(plan.executable[0].manifest.id, "steampipe");
        assert_eq!(plan.not_executed.len(), 1);
        assert_eq!(plan.not_executed[0].engine_id, "missing");
        let installed = plan
            .scan_run
            .engine_runs
            .iter()
            .find(|run| run.engine_id == "steampipe")
            .unwrap();
        assert_eq!(installed.status, EngineRunStatus::Queued);
        assert!(installed.manifest_schema_version.is_some());
        assert!(installed.repository_url.is_some());
        assert!(installed.command_sha256.is_some());
        assert!(installed.knowledge_input.is_some());
        let missing = plan
            .scan_run
            .engine_runs
            .iter()
            .find(|run| run.engine_id == "missing")
            .unwrap();
        assert_eq!(missing.status, EngineRunStatus::NotExecuted);
        assert_eq!(missing.adapter_version, "unavailable");
        assert!(missing.repository_url.is_none());
    }

    #[test]
    fn aws_only_cloud_images_never_guess_azure_gcp_or_missing_asset_providers() {
        let aws_engine_ids = ["cloudquery", "steampipe", "scoutsuite", "cloudsplaining"];
        for provider in [Some("aws"), Some("azure"), Some("gcp"), None] {
            let fixture = Fixture::new();
            let case = fixture.create();
            let asset_id = if provider == Some("aws") {
                fixture.discovered_aws_account(&case.id, "111122223333").1
            } else {
                let (mut discovered, asset_id) =
                    fixture.discovered_asset(&case.id, AssetKind::CloudAccount);
                discovered.assets[0].provider = provider.map(str::to_owned);
                fixture
                    .storage
                    .save_case(&mut discovered, "test.provider_attributed")
                    .unwrap();
                asset_id
            };
            let service = fixture.service();
            service
                .approve_scope(
                    &case.id,
                    ScopeApprovalRequest {
                        asset_id,
                        permissions: vec![
                            ScanPermission::InventoryRead,
                            ScanPermission::ConfigurationRead,
                        ],
                        confirmed_by: "Owner".into(),
                        expires_at: None,
                        authorization_reference: None,
                        notes: None,
                        external_scope: None,
                    },
                )
                .unwrap();
            let plan = service
                .plan_scan(
                    &case.id,
                    ScanPlanRequest {
                        engine_ids: aws_engine_ids.iter().map(|id| (*id).into()).collect(),
                    },
                )
                .unwrap();

            if provider == Some("aws") {
                assert_eq!(plan.executable.len(), aws_engine_ids.len());
                assert!(plan.not_executed.is_empty());
            } else {
                assert!(plan.executable.is_empty(), "provider {provider:?}");
                assert_eq!(plan.not_executed.len(), aws_engine_ids.len());
                assert!(plan.not_executed.iter().all(|engine| {
                    engine.reason_code == "no_compatible_authorized_assets"
                        && engine.asset_ids.is_empty()
                }));
            }
        }
    }

    #[test]
    fn aws_organization_child_without_an_exact_account_capability_is_not_executable() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, asset_ids) = fixture.discovered_aws_accounts(
            &case.id,
            "111122223333",
            &["111122223333", "444455556666"],
        );
        let service = fixture.service();
        service
            .approve_scopes(
                &case.id,
                asset_ids
                    .iter()
                    .map(|asset_id| ScopeApprovalRequest {
                        asset_id: asset_id.clone(),
                        permissions: vec![ScanPermission::InventoryRead],
                        confirmed_by: "Owner".into(),
                        expires_at: None,
                        authorization_reference: None,
                        notes: None,
                        external_scope: None,
                    })
                    .collect(),
            )
            .unwrap();

        let plan = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["steampipe".into()],
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 1);
        assert_eq!(plan.executable[0].assets.len(), 1);
        assert_eq!(plan.executable[0].assets[0].id, asset_ids[0]);
        assert!(
            !plan.executable[0]
                .assets
                .iter()
                .any(|asset| asset.id == asset_ids[1])
        );
    }

    #[test]
    fn provider_bound_engine_splits_exactly_bound_accounts_into_independent_executions() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, first_asset_id) = fixture.discovered_aws_account(&case.id, "111122223333");
        let (_, second_asset_id) = fixture.discovered_aws_account(&case.id, "444455556666");
        let service = fixture.service();
        service
            .approve_scopes(
                &case.id,
                [&first_asset_id, &second_asset_id]
                    .into_iter()
                    .map(|asset_id| ScopeApprovalRequest {
                        asset_id: asset_id.clone(),
                        permissions: vec![ScanPermission::InventoryRead],
                        confirmed_by: "Owner".into(),
                        expires_at: None,
                        authorization_reference: None,
                        notes: None,
                        external_scope: None,
                    })
                    .collect(),
            )
            .unwrap();

        let plan = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["steampipe".into()],
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 2);
        assert!(
            plan.executable
                .iter()
                .all(|execution| execution.assets.len() == 1)
        );
        let planned_asset_ids = plan
            .executable
            .iter()
            .map(|execution| execution.assets[0].id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            planned_asset_ids,
            BTreeSet::from([first_asset_id.as_str(), second_asset_id.as_str()])
        );
    }

    #[test]
    fn microsoft365_provider_engine_keeps_exactly_one_tenant_per_execution() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let service = fixture.service();
        let tenant_identifiers = [
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        ];
        for (index, tenant_id) in tenant_identifiers.into_iter().enumerate() {
            let source = service
                .upsert_source(
                    &case.id,
                    SourceMutation {
                        id: None,
                        kind: SourceKind::Microsoft365Tenant,
                        label: format!("Microsoft 365 tenant {index}"),
                        status: SourceConnectionStatus::Connected,
                        read_only: true,
                        metadata: BTreeMap::from([(
                            PROVIDER_RESOURCE_SCOPE_METADATA_KEY.into(),
                            Value::String(format!("microsoft365-tenant:{tenant_id}")),
                        )]),
                    },
                )
                .unwrap();
            service
                .reconcile_discovery_batch(
                    &case.id,
                    &DiscoveryBatch {
                        source_id: source.id,
                        source_kind: SourceKind::Microsoft365Tenant,
                        connector_id: "test-m365".into(),
                        connector_version: "1".into(),
                        observed_at: Utc::now(),
                        assets: vec![DiscoveredAsset {
                            observation_key: format!("tenant-{index}"),
                            kind: AssetKind::Tenant,
                            name: format!("Tenant {index}"),
                            provider: Some("microsoft365".into()),
                            region: None,
                            stable_identifier: AssetIdentifier {
                                namespace: "microsoft_tenant_id".into(),
                                value: tenant_id.into(),
                            },
                            additional_identifiers: vec![],
                            internet_exposed: None,
                            contains_sensitive_data: None,
                            metadata: BTreeMap::new(),
                        }],
                        relations: vec![],
                        notices: vec![],
                    },
                )
                .unwrap();
        }
        let tenant_asset_ids = service
            .show_case(&case.id)
            .unwrap()
            .assets
            .into_iter()
            .map(|asset| asset.id)
            .collect::<Vec<_>>();
        service
            .approve_scopes(
                &case.id,
                tenant_asset_ids
                    .iter()
                    .map(|asset_id| ScopeApprovalRequest {
                        asset_id: asset_id.clone(),
                        permissions: vec![
                            ScanPermission::InventoryRead,
                            ScanPermission::ConfigurationRead,
                        ],
                        confirmed_by: "Tenant administrator".into(),
                        expires_at: None,
                        authorization_reference: None,
                        notes: None,
                        external_scope: None,
                    })
                    .collect(),
            )
            .unwrap();

        let plan = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["scubagear".into()],
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 2);
        assert!(
            plan.executable
                .iter()
                .all(|execution| execution.assets.len() == 1)
        );
    }

    #[test]
    fn resume_revalidates_the_manifest_provider_contract() {
        let fixture = Fixture::new();
        let case = fixture.create();
        let (_, asset_id) = fixture.discovered_aws_account(&case.id, "111122223333");
        let service = fixture.service();
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::InventoryRead],
                    confirmed_by: "Owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        let plan = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["cloudquery".into()],
                },
            )
            .unwrap();
        let mut interrupted = service.show_case(&case.id).unwrap();
        interrupted.assets[0].provider = Some("azure".into());
        interrupted.scan_runs[0].engine_runs[0].status = EngineRunStatus::Paused;
        interrupted.scan_runs[0].engine_runs[0].phase = "paused".into();
        interrupted.status = CaseStatus::NeedsAttention;
        fixture
            .storage
            .save_case(&mut interrupted, "test.provider_changed_before_resume")
            .unwrap();

        let error = service
            .plan_resume(&case.id, &plan.scan_run.id)
            .unwrap_err();
        assert!(matches!(error, AppError::NotAuthorized(_)));
        let retained = service.show_case(&case.id).unwrap();
        assert_eq!(
            retained.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Paused
        );
    }

    #[test]
    fn durable_execution_report_is_idempotent() {
        let fixture = Fixture::new();
        let mut case = fixture.create();
        let now = Utc::now();
        let asset = Asset {
            id: "asset-1".into(),
            kind: AssetKind::CloudAccount,
            name: "Account".into(),
            provider: Some("aws".into()),
            region: None,
            identifiers: vec![],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        };
        case.assets.push(asset);
        case.scope_grants.push(ScopeGrant {
            id: "grant-1".into(),
            asset_id: "asset-1".into(),
            permission: ScanPermission::InventoryRead,
            confirmed_by: "Owner".into(),
            confirmed_at: now,
            expires_at: None,
            authorization_reference: None,
            notes: None,
            external_scope: None,
        });
        case.scan_runs.push(ScanRun {
            id: "scan-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: now,
            completed_at: None,
            knowledge_cutoff: now,
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-1".into()],
            scope_grant_snapshots: case.scope_grants.clone(),
            engine_runs: vec![EngineRun {
                id: "engine-run-1".into(),
                scan_run_id: "scan-1".into(),
                engine_id: "cloudquery".into(),
                asset_ids: vec!["asset-1".into()],
                status: EngineRunStatus::Running,
                progress_percent: 50,
                phase: "running".into(),
                started_at: Some(now),
                finished_at: None,
                resume_token: None,
                engine_version: None,
                image_digest: None,
                rule_version: None,
                adapter_version: "0.1.0".into(),
                manifest_schema_version: None,
                source_revision: None,
                repository_url: None,
                distribution_mode: None,
                image_repository: None,
                command_sha256: None,
                knowledge_input: None,
                scope_contract_sha256: None,
                mapping_version: None,
                fingerprint_schema_version: None,
                runtime_provider: None,
                runtime_version: None,
                runtime_security_options: None,
                exit_code: None,
                cleanup_removed: None,
                cleanup_detail: None,
                warnings: vec![],
                raw_artifact_ids: vec![],
                error_code: None,
                error_message: None,
            }],
        });
        fixture
            .storage
            .save_case(&mut case, "test.prepared")
            .unwrap();
        let artifact_path = fixture
            .directory
            .path()
            .join("artifacts/case/scan/engine/output.json");
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, b"{}").unwrap();
        let artifact = RawArtifact {
            id: "artifact-1".into(),
            case_id: case.id.clone(),
            run_id: "scan-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "case/scan/engine/output.json".into(),
            media_type: "application/json".into(),
            sha256: sha256_bytes(b"{}"),
            byte_length: 2,
            created_at: now,
            contains_sensitive_data: true,
        };
        let finding_id = "finding-1".to_owned();
        let finding = Finding {
            id: finding_id.clone(),
            case_id: case.id.clone(),
            first_seen_run_id: "scan-1".into(),
            last_seen_run_id: "scan-1".into(),
            fingerprint: "fingerprint-1".into(),
            title: "Finding <script>alert(1)</script>".into(),
            plain_language_summary: "Summary".into(),
            possible_impact: "Impact".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 80,
            priority_reasons: vec![],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![Evidence {
                id: "evidence-1".into(),
                finding_id,
                run_id: "scan-1".into(),
                engine_run_id: Some("engine-run-1".into()),
                kind: EvidenceKind::Configuration,
                engine_id: "cloudquery".into(),
                observed_at: now,
                summary: "Observed".into(),
                artifact_id: artifact.id.clone(),
                artifact_sha256: artifact.sha256.clone(),
                pointer: None,
                redacted: false,
            }],
            control_references: vec![],
            recommendation: "Review".into(),
            verification_guidance: "Verify".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Cloud security".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        };
        let report = DurableExecutionReport {
            checkpoint: ExecutionCheckpoint {
                case_id: case.id.clone(),
                scan_run_id: "scan-1".into(),
                engine_run_id: "engine-run-1".into(),
                engine_id: "cloudquery".into(),
                attempt: 1,
                stage: ExecutionStage::Completed,
                container_name: None,
                scope_sha256: Some("b".repeat(64)),
                artifact_ids: vec![artifact.id.clone()],
                cleanup_completed: true,
                last_error: None,
                runtime_command_provenance: Some(
                    crate::container_runtime::RuntimeCommandProvenance::Compatibility,
                ),
                runtime_provider: Some(crate::container_runtime::RuntimeProvider::Podman),
                managed_network: None,
            },
            runtime_preflight: Some(RuntimePreflight {
                provider: crate::container_runtime::RuntimeProvider::Podman,
                server_version: "5.2.2".into(),
                security_options: "rootless,seccomp".into(),
                command_provenance:
                    crate::container_runtime::RuntimeCommandProvenance::Compatibility,
            }),
            cleanup: Some(CleanupOutcome {
                removed: true,
                detail: "removed exact verified container".into(),
            }),
            exit_code: Some(0),
            raw_artifacts: vec![artifact],
            findings: vec![finding],
            warnings: vec!["scanner emitted a bounded warning".into()],
        };
        let service = fixture.service();
        assert!(
            !service
                .apply_execution_report(&case.id, &report)
                .unwrap()
                .idempotent_replay
        );
        assert!(
            service
                .apply_execution_report(&case.id, &report)
                .unwrap()
                .idempotent_replay
        );
        let stored = service.show_case(&case.id).unwrap();
        assert_eq!(stored.raw_artifacts.len(), 1);
        assert_eq!(stored.findings.len(), 1);
        assert_eq!(stored.finding_observations.len(), 1);
        let stored_run = &stored.scan_runs[0].engine_runs[0];
        assert_eq!(stored_run.runtime_provider.as_deref(), Some("podman"));
        assert_eq!(stored_run.runtime_version.as_deref(), Some("5.2.2"));
        assert_eq!(stored_run.exit_code, Some(0));
        assert_eq!(stored_run.cleanup_removed, Some(true));
        assert_eq!(stored_run.warnings, report.warnings);

        let mut conflicting = report.clone();
        conflicting
            .warnings
            .push("different payload for an immutable checkpoint".into());
        assert!(
            service
                .apply_execution_report(&case.id, &conflicting)
                .is_err()
        );

        let workflow = service
            .update_finding_workflow(
                &case.id,
                FindingWorkflowRequest {
                    finding_id: "finding-1".into(),
                    status: FindingStatus::FalsePositive,
                    decided_by: "Security reviewer".into(),
                    reason: "Reproducible environment-specific exception SEC-22".into(),
                    expires_at: Some(Utc::now() + Duration::days(30)),
                },
            )
            .unwrap();
        assert_eq!(workflow.findings[0].status, FindingStatus::FalsePositive);
        assert_eq!(workflow.findings[0].evidence.len(), 1);
        assert_eq!(workflow.finding_workflow_events.len(), 1);
        assert!(workflow.finding_workflow_events[0].expires_at.is_some());
        assert_eq!(
            workflow.finding_workflow_events[0].from_status,
            FindingStatus::Unreviewed
        );
        let mut after_expiry = workflow.clone();
        after_expiry.finding_workflow_events[0].expires_at =
            Some(Utc::now() - Duration::seconds(1));
        after_expiry.apply_effective_finding_statuses(Utc::now());
        assert_eq!(
            after_expiry.findings[0].status,
            FindingStatus::Unreviewed,
            "expired suppression must restore the status recorded in its audit event"
        );
        assert_eq!(after_expiry.finding_workflow_events.len(), 1);
        assert!(
            service
                .update_finding_workflow(
                    &case.id,
                    FindingWorkflowRequest {
                        finding_id: "finding-1".into(),
                        status: FindingStatus::VerifiedResolved,
                        decided_by: "Security reviewer".into(),
                        reason: "Must have comparable rerun evidence".into(),
                        expires_at: None,
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn schema_export_and_coverage_aware_diff_are_persisted() {
        let fixture = Fixture::new();
        let mut case = fixture.create();
        let now = Utc::now();
        case.scope_grants.push(ScopeGrant {
            id: "grant-1".into(),
            asset_id: "asset-1".into(),
            permission: ScanPermission::InventoryRead,
            confirmed_by: "Owner".into(),
            confirmed_at: now,
            expires_at: None,
            authorization_reference: None,
            notes: None,
            external_scope: None,
        });
        let completed_engine = |run_id: &str| EngineRun {
            id: format!("engine-{run_id}"),
            scan_run_id: run_id.into(),
            engine_id: "cloudquery".into(),
            asset_ids: vec!["asset-1".into()],
            status: EngineRunStatus::Completed,
            progress_percent: 100,
            phase: "completed".into(),
            started_at: Some(now),
            finished_at: Some(now),
            resume_token: None,
            engine_version: Some("1".into()),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            rule_version: None,
            adapter_version: "0.1.0".into(),
            manifest_schema_version: Some("1".into()),
            source_revision: Some("b".repeat(40)),
            repository_url: Some("https://example.test/cloudquery".into()),
            distribution_mode: Some(DistributionMode::PullPinnedImage),
            image_repository: Some("ghcr.io/example/cloudquery".into()),
            command_sha256: Some("c".repeat(64)),
            knowledge_input: Some(EngineKnowledgeInput {
                kind: crate::domain::KnowledgeInputKind::RuntimeLive,
                identifier: "AWS inventory".into(),
                version: Some("1".into()),
                acquisition_source: None,
                pin_state: crate::domain::KnowledgePinState::RuntimeLive,
                knowledge_date: Some("2026-08-24".into()),
                support_until: Some("2026-11-22".into()),
            }),
            scope_contract_sha256: Some("d".repeat(64)),
            mapping_version: Some("2026-08-24.1".into()),
            fingerprint_schema_version: Some("v1".into()),
            runtime_provider: None,
            runtime_version: None,
            runtime_security_options: None,
            exit_code: Some(0),
            cleanup_removed: None,
            cleanup_detail: None,
            warnings: vec![],
            raw_artifact_ids: vec![],
            error_code: None,
            error_message: None,
        };
        for (sequence, id) in [(1, "baseline"), (2, "current")] {
            case.scan_runs.push(ScanRun {
                id: id.into(),
                case_id: case.id.clone(),
                sequence,
                created_at: now,
                completed_at: Some(now),
                knowledge_cutoff: now,
                verification_baseline_run_id: None,
                scope_grant_ids: vec!["grant-1".into()],
                scope_grant_snapshots: case.scope_grants.clone(),
                engine_runs: vec![completed_engine(id)],
            });
        }
        case.findings.push(Finding {
            id: "finding-1".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "baseline".into(),
            last_seen_run_id: "baseline".into(),
            fingerprint: "fp".into(),
            title: "Finding <script>alert(1)</script>".into(),
            plain_language_summary: "Summary".into(),
            possible_impact: "Impact".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 50,
            priority_reasons: vec![],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![],
            control_references: vec![],
            recommendation: "Review".into(),
            verification_guidance: "Verify".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        });
        case.finding_observations.push(FindingObservation {
            id: "observation-1".into(),
            run_id: "baseline".into(),
            finding_id: "finding-1".into(),
            fingerprint: "fp".into(),
            asset_ids: vec!["asset-1".into()],
            engine_ids: vec!["cloudquery".into()],
            severity: Severity::High,
            confidence: Confidence::High,
            evidence_hashes: vec!["a".repeat(64)],
            observed_at: now,
            finding_snapshot: None,
        });
        fixture.storage.save_case(&mut case, "test.runs").unwrap();
        let destination = fixture.directory.path().join("ocsf.json");
        let service = fixture.service();
        let export = service
            .export_schema(
                &case.id,
                "baseline",
                SchemaExportFormat::OcsfJson,
                &destination,
            )
            .unwrap();
        assert!(
            service
                .verify_stored_export(&case.id, &export.id)
                .unwrap()
                .valid
        );
        let html_destination = fixture.directory.path().join("report.html");
        let html_export = service
            .export_case(
                &case.id,
                "baseline",
                CaseExportFormat::Html,
                &html_destination,
                ExportOptions::default(),
            )
            .unwrap();
        assert!(
            service
                .verify_stored_export(&case.id, &html_export.id)
                .unwrap()
                .valid
        );
        let html = fs::read_to_string(&html_destination).unwrap();
        assert!(html.contains("Finding &lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("Content-Security-Policy"));
        let comparison = service
            .compare_and_persist(&case.id, "baseline", "current")
            .unwrap();
        assert_eq!(
            comparison.diffs[0].status,
            crate::domain::FindingDiffStatus::Resolved
        );
        let reopened = service.show_case(&case.id).unwrap();
        assert_eq!(reopened.exports.len(), 2);
        assert_eq!(reopened.comparisons.len(), 1);
        assert!(
            service
                .export_schema(
                    &case.id,
                    "baseline",
                    SchemaExportFormat::OcsfJson,
                    &destination,
                )
                .is_err()
        );
    }

    #[test]
    fn connector_discovery_type_remains_separate_from_reconciliation_batch() {
        let discovery = ConnectorDiscovery {
            observed_at: Utc::now(),
            assets: vec![],
            relations: vec![],
            notices: vec![],
        };
        assert!(discovery.assets.is_empty());
    }

    #[test]
    fn repeat_observations_keep_immutable_run_specific_finding_and_evidence_snapshots() {
        let fixture = Fixture::new();
        let mut case = fixture.create();
        let case_id = case.id.clone();
        let observed = |run_id: &str, title: &str, evidence_id: &str, hash: &str| Finding {
            id: format!("finding-{run_id}"),
            case_id: case_id.clone(),
            first_seen_run_id: run_id.into(),
            last_seen_run_id: run_id.into(),
            fingerprint: "stable-fingerprint".into(),
            title: title.into(),
            plain_language_summary: format!("summary for {run_id}"),
            possible_impact: format!("impact for {run_id}"),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 70,
            priority_reasons: vec![format!("priority for {run_id}")],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![Evidence {
                id: evidence_id.into(),
                finding_id: format!("finding-{run_id}"),
                run_id: run_id.into(),
                engine_run_id: Some(format!("engine-{run_id}")),
                kind: EvidenceKind::Configuration,
                engine_id: "cloudquery".into(),
                observed_at: Utc::now(),
                summary: format!("evidence for {run_id}"),
                artifact_id: format!("artifact-{run_id}"),
                artifact_sha256: hash.into(),
                pointer: Some(format!("/{run_id}")),
                redacted: false,
            }],
            control_references: vec![],
            recommendation: format!("recommendation for {run_id}"),
            verification_guidance: format!("verification for {run_id}"),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security reviewer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![run_id.into()],
        };

        reconcile_finding(
            &mut case,
            &observed("run-1", "Original title", "evidence-1", &"a".repeat(64)),
            "cloudquery",
        )
        .expect("first observation");
        reconcile_finding(
            &mut case,
            &observed("run-2", "Updated title", "evidence-2", &"b".repeat(64)),
            "cloudquery",
        )
        .expect("repeat observation");

        assert_eq!(case.findings.len(), 1);
        assert_eq!(case.findings[0].title, "Updated title");
        assert_eq!(case.findings[0].evidence[0].id, "evidence-2");
        assert_eq!(case.finding_observations.len(), 2);
        let first = case.finding_observations[0]
            .finding_snapshot
            .as_ref()
            .expect("run-1 snapshot");
        let second = case.finding_observations[1]
            .finding_snapshot
            .as_ref()
            .expect("run-2 snapshot");
        assert_eq!(first.title, "Original title");
        assert_eq!(first.evidence[0].id, "evidence-1");
        assert_eq!(first.evidence[0].run_id, "run-1");
        assert_eq!(second.title, "Updated title");
        assert_eq!(second.evidence[0].id, "evidence-2");
        assert_eq!(second.evidence[0].run_id, "run-2");
    }
}
