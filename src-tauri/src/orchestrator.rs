use crate::adapter::{AdapterAssetIdentifierMap, AdapterInput, AdapterRegistry};
use crate::artifact_store::{ArtifactContext, ArtifactStore, RunDirectories};
use crate::container_runtime::{
    CancellationToken, CleanupOutcome, ContainerPlanBuilder, ContainerRuntime,
    NAABU_LAUNCHER_PLAN_CONTROL_FILE, NetworkPolicy, PinnedImage, ResourceLimits,
    RuntimeCommandProvenance, RuntimePreflight, ScannerCredentialSet, planned_container_name,
};
use crate::domain::{
    Asset, AssetIdentifier, EngineManifest, Finding, RawArtifact, ScanPermission, ScopeGrant,
};
use crate::error::{AppError, AppResult};
use crate::managed_network::{GatewayDestination, ManagedNetworkIdentity};
use crate::naabu_work_plan::{
    MAX_NAABU_LAUNCHER_PLAN_BYTES, NAABU_ENGINE_ID, NAABU_LAUNCHER_PLAN_SCHEMA_VERSION,
    NaabuLauncherPlanV2,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    Planned,
    Preflight,
    PullingImage,
    Running,
    CapturingArtifacts,
    AdaptingArtifacts,
    CapturedAwaitingAdapter,
    CleanupPending,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResumeAction {
    AlreadyComplete,
    AdaptCapturedArtifacts,
    CleanupContainer,
    ReconcileContainerThenReexecute,
    Reexecute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionCheckpoint {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
    pub engine_id: String,
    pub attempt: u32,
    pub stage: ExecutionStage,
    pub container_name: Option<String>,
    pub scope_sha256: Option<String>,
    pub artifact_ids: Vec<String>,
    pub cleanup_completed: bool,
    pub last_error: Option<String>,
    /// Exact, non-secret runtime identity needed to recover this execution
    /// after an application update. It is populated immediately after the
    /// runtime preflight and is therefore mandatory for cleanup-pending work.
    #[serde(default)]
    pub runtime_command_provenance: Option<RuntimeCommandProvenance>,
    #[serde(default)]
    pub runtime_provider: Option<crate::container_runtime::RuntimeProvider>,
    #[serde(default)]
    pub managed_network: Option<ManagedNetworkIdentity>,
}

impl ExecutionCheckpoint {
    pub fn resume_action(&self) -> ResumeAction {
        match self.stage {
            ExecutionStage::Completed => ResumeAction::AlreadyComplete,
            ExecutionStage::CapturedAwaitingAdapter | ExecutionStage::AdaptingArtifacts => {
                ResumeAction::AdaptCapturedArtifacts
            }
            ExecutionStage::CleanupPending => ResumeAction::CleanupContainer,
            ExecutionStage::Running | ExecutionStage::CapturingArtifacts => {
                ResumeAction::ReconcileContainerThenReexecute
            }
            ExecutionStage::Planned
            | ExecutionStage::Preflight
            | ExecutionStage::PullingImage
            | ExecutionStage::Cancelled
            | ExecutionStage::Failed => ResumeAction::Reexecute,
        }
    }

    pub fn resume_token(&self) -> AppResult<String> {
        self.validate()?;
        serde_json::to_string(self)
            .map_err(|error| AppError::Runtime(format!("checkpoint encode failed: {error}")))
    }

    pub fn from_resume_token(token: &str) -> AppResult<Self> {
        let checkpoint: Self = serde_json::from_str(token)
            .map_err(|error| AppError::InvalidRequest(format!("invalid resume token: {error}")))?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn validate(&self) -> AppResult<()> {
        if let Some(identity) = self.managed_network.as_ref() {
            identity.validate()?;
        }
        if self.runtime_command_provenance.is_some() != self.runtime_provider.is_some() {
            return Err(AppError::InvalidRequest(
                "checkpoint runtime provider and provenance must be recorded together".into(),
            ));
        }
        let expected = planned_container_name(&self.engine_id, &self.engine_run_id, self.attempt)?;
        if self
            .container_name
            .as_deref()
            .is_some_and(|actual| actual != expected)
        {
            return Err(AppError::InvalidRequest(
                "checkpoint container name does not match its execution identity".into(),
            ));
        }
        if self.stage == ExecutionStage::CleanupPending
            && self.container_name.is_none()
            && self.managed_network.is_none()
        {
            return Err(AppError::InvalidRequest(
                "cleanup checkpoint has neither a container nor a managed-network identity".into(),
            ));
        }
        if self.stage == ExecutionStage::CleanupPending
            && (self.runtime_command_provenance.is_none() || self.runtime_provider.is_none())
        {
            return Err(AppError::InvalidRequest(
                "cleanup checkpoint has no exact runtime provider and provenance".into(),
            ));
        }
        if let Some(identity) = self.managed_network.as_ref() {
            let provenance = self.runtime_command_provenance.as_ref().ok_or_else(|| {
                AppError::InvalidRequest(
                    "managed-network checkpoint has no exact runtime provenance".into(),
                )
            })?;
            if self.runtime_provider != Some(identity.provider) {
                return Err(AppError::InvalidRequest(
                    "managed-network provider conflicts with checkpoint runtime provider".into(),
                ));
            }
            let provider_matches = matches!(
                (identity.provider, provenance),
                (
                    crate::container_runtime::RuntimeProvider::ManagedLocal,
                    RuntimeCommandProvenance::ManagedLocal { .. }
                ) | (
                    crate::container_runtime::RuntimeProvider::Docker
                        | crate::container_runtime::RuntimeProvider::Podman,
                    RuntimeCommandProvenance::Compatibility
                )
            );
            if !provider_matches {
                return Err(AppError::InvalidRequest(
                    "managed-network provider conflicts with runtime provenance".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub checkpoint: ExecutionCheckpoint,
    pub runtime_preflight: Option<RuntimePreflight>,
    pub cleanup: Option<CleanupOutcome>,
    pub exit_code: Option<i32>,
    pub raw_artifacts: Vec<RawArtifact>,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    pub artifact_root: PathBuf,
    pub output_directory: PathBuf,
}

impl ExecutionReport {
    fn empty(
        checkpoint: ExecutionCheckpoint,
        artifact_root: PathBuf,
        output_directory: PathBuf,
    ) -> Self {
        Self {
            checkpoint,
            runtime_preflight: None,
            cleanup: None,
            exit_code: None,
            raw_artifacts: Vec::new(),
            findings: Vec::new(),
            warnings: Vec::new(),
            artifact_root,
            output_directory,
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.checkpoint.stage = ExecutionStage::Failed;
        self.checkpoint.last_error = Some(message);
    }
}

fn combined_cleanup_pending_error(
    runtime_error: Option<&str>,
    prior_error: Option<&str>,
    cleanup_error: &str,
) -> String {
    let mut primary = Vec::<String>::new();
    for candidate in [runtime_error, prior_error].into_iter().flatten() {
        let candidate = candidate.trim();
        if !candidate.is_empty() && !primary.iter().any(|message| message == candidate) {
            primary.push(candidate.to_owned());
        }
    }
    let cleanup_error = cleanup_error.trim();
    if primary.is_empty() {
        format!("container cleanup failed: {cleanup_error}")
    } else {
        format!(
            "{}; container cleanup also failed: {cleanup_error}",
            primary.join("; ")
        )
    }
}

pub struct EngineExecutionRequest<'a> {
    pub case_id: &'a str,
    pub scan_run_id: &'a str,
    pub engine_run_id: &'a str,
    pub manifest: &'a EngineManifest,
    /// Framework-classification context frozen by case planning. This never
    /// authorizes a target or changes the engine command.
    pub ai_system_applicable: bool,
    /// Framework-classification context frozen by case planning. `false`
    /// includes both an explicit no and an unknown answer.
    pub ai_generated_artifact_applicable: bool,
    pub assets: &'a [Asset],
    pub scope_grants: &'a [ScopeGrant],
    /// Exact host-side DNS/address snapshot represented by the managed egress
    /// policy. Only the project-owned external launcher receives these
    /// addresses in its scope document; every other engine keeps its existing
    /// strict scope schema.
    pub frozen_destinations: Option<&'a [GatewayDestination]>,
    /// Private, exact launcher-v2 work-unit document. Production planning does
    /// not populate this yet: only a future immutable Naabu manifest that
    /// explicitly opts into launcher journal v2 may supply it.
    pub naabu_launcher_plan: Option<&'a NaabuLauncherPlanV2>,
    pub workspace: Option<&'a Path>,
    pub network_policy: &'a NetworkPolicy,
    pub resource_limits: &'a ResourceLimits,
    pub credentials: &'a ScannerCredentialSet,
    pub attempt: u32,
}

fn validate_naabu_launcher_request(request: &EngineExecutionRequest<'_>) -> AppResult<()> {
    let declared_version = request
        .manifest
        .execution
        .as_ref()
        .and_then(|execution| execution.launcher_journal_version);
    match declared_version {
        Some(version) if version != NAABU_LAUNCHER_PLAN_SCHEMA_VERSION => {
            return Err(AppError::EngineRegistry(format!(
                "engine {} declares unsupported launcher journal version {version}",
                request.manifest.id
            )));
        }
        Some(_) if request.naabu_launcher_plan.is_none() => {
            return Err(AppError::InvalidRequest(
                "Naabu launcher journal v2 requires its private execution plan".into(),
            ));
        }
        None if request.naabu_launcher_plan.is_some() => {
            return Err(AppError::InvalidRequest(
                "a launcher execution plan requires an explicit reviewed launcher version".into(),
            ));
        }
        _ => {}
    }

    let Some(plan) = request.naabu_launcher_plan else {
        return Ok(());
    };
    if request.manifest.id != NAABU_ENGINE_ID
        || plan.schema_version != NAABU_LAUNCHER_PLAN_SCHEMA_VERSION
        || plan.engine_id != NAABU_ENGINE_ID
    {
        return Err(AppError::InvalidRequest(
            "launcher journal v2 is valid only for the reviewed Naabu contract".into(),
        ));
    }
    if plan.engine_run_id != request.engine_run_id || plan.execution_attempt != request.attempt {
        return Err(AppError::InvalidRequest(
            "Naabu launcher plan identity does not match this engine execution".into(),
        ));
    }
    if plan.frozen_grants.is_empty() || plan.requested_work_units.is_empty() {
        return Err(AppError::InvalidRequest(
            "Naabu launcher plan must contain frozen grants and requested work units".into(),
        ));
    }
    let encoded = serde_json::to_vec(plan).map_err(|error| {
        AppError::InvalidRequest(format!("invalid Naabu launcher plan: {error}"))
    })?;
    if encoded.len() > MAX_NAABU_LAUNCHER_PLAN_BYTES {
        return Err(AppError::InvalidRequest(format!(
            "Naabu launcher plan exceeds the {}-byte private control limit",
            MAX_NAABU_LAUNCHER_PLAN_BYTES
        )));
    }
    Ok(())
}

pub struct Orchestrator<'a, R: ContainerRuntime> {
    runtime: &'a R,
    artifacts: &'a ArtifactStore,
    adapters: &'a AdapterRegistry,
}

impl<'a, R: ContainerRuntime> Orchestrator<'a, R> {
    pub fn new(
        runtime: &'a R,
        artifacts: &'a ArtifactStore,
        adapters: &'a AdapterRegistry,
    ) -> Self {
        Self {
            runtime,
            artifacts,
            adapters,
        }
    }

    pub fn execute(
        &self,
        request: &EngineExecutionRequest<'_>,
        cancellation: &CancellationToken,
    ) -> AppResult<ExecutionReport> {
        self.execute_with_observer(request, cancellation, |_| Ok(()))
    }

    /// Executes an engine while exposing non-terminal durable reports at safe
    /// state boundaries. The observer runs before any container starts and
    /// again after captured artifacts are safely closed and the container has
    /// been cleaned. Terminal reconciliation remains the caller's
    /// responsibility so findings and raw artifacts commit atomically.
    pub fn execute_with_observer<F>(
        &self,
        request: &EngineExecutionRequest<'_>,
        cancellation: &CancellationToken,
        mut observer: F,
    ) -> AppResult<ExecutionReport>
    where
        F: FnMut(&ExecutionReport) -> AppResult<()>,
    {
        if let Some(blocker) = request.manifest.release_blocker() {
            return Err(AppError::EngineRegistry(format!(
                "engine {} cannot be executed: {blocker}",
                request.manifest.id
            )));
        }
        let validated_scope = validate_execution_scope(
            request.manifest,
            request.assets,
            request.scope_grants,
            request.network_policy,
        )?;
        let image = PinnedImage::from_manifest(request.manifest)?;
        if request.attempt == 0 {
            return Err(AppError::InvalidRequest(
                "execution attempt must start at one".into(),
            ));
        }
        validate_naabu_launcher_request(request)?;
        if request
            .manifest
            .required_permissions
            .contains(&ScanPermission::LocalArtifactRead)
            && request.workspace.is_none()
        {
            return Err(AppError::InvalidRequest(format!(
                "engine {} requires an explicitly selected local workspace",
                request.manifest.id
            )));
        }

        let context = ArtifactContext {
            case_id: request.case_id.into(),
            scan_run_id: request.scan_run_id.into(),
            engine_run_id: request.engine_run_id.into(),
        };
        let directories = self.artifacts.prepare_run(&context, request.attempt)?;
        let scope_document = ScopeDocument::new(
            request.manifest,
            &validated_scope,
            request.frozen_destinations,
        )?;
        let scope_file =
            self.artifacts
                .write_control_json(&directories, "scope.json", &scope_document)?;
        let launcher_plan_file = request
            .naabu_launcher_plan
            .map(|launcher_plan| {
                self.artifacts.write_control_json(
                    &directories,
                    NAABU_LAUNCHER_PLAN_CONTROL_FILE,
                    launcher_plan,
                )
            })
            .transpose()?;
        let plan_directories = run_directories_with_workspace(
            &directories,
            request.workspace.unwrap_or(&directories.workspace),
        );
        let plan = ContainerPlanBuilder::new(
            request.manifest,
            &image,
            &plan_directories,
            &scope_file.path,
            request.resource_limits,
            request.network_policy,
            request.credentials,
            request.case_id,
            request.scan_run_id,
            request.engine_run_id,
            request.attempt,
        )
        .with_launcher_plan_file(
            launcher_plan_file
                .as_ref()
                .map(|control_file| control_file.path.as_path()),
        )
        .build()?;

        let checkpoint = ExecutionCheckpoint {
            case_id: request.case_id.into(),
            scan_run_id: request.scan_run_id.into(),
            engine_run_id: request.engine_run_id.into(),
            engine_id: request.manifest.id.clone(),
            attempt: request.attempt,
            stage: ExecutionStage::Planned,
            container_name: Some(plan.container_name().to_owned()),
            scope_sha256: Some(plan.scope_sha256().to_owned()),
            artifact_ids: Vec::new(),
            cleanup_completed: false,
            last_error: None,
            runtime_command_provenance: None,
            runtime_provider: None,
            managed_network: None,
        };
        let mut report = ExecutionReport::empty(
            checkpoint,
            self.artifacts.root().to_path_buf(),
            directories.output.clone(),
        );
        observer(&report)?;

        if cancellation.is_cancelled() {
            report.checkpoint.stage = ExecutionStage::Cancelled;
            report.checkpoint.cleanup_completed = true;
            return Ok(report);
        }

        report.checkpoint.stage = ExecutionStage::Preflight;
        observer(&report)?;
        let preflight = match self.runtime.preflight() {
            Ok(preflight) => preflight,
            Err(error) => {
                report.checkpoint.cleanup_completed = true;
                report.fail(error.to_string());
                return Ok(report);
            }
        };
        report.checkpoint.runtime_command_provenance = Some(preflight.command_provenance.clone());
        report.checkpoint.runtime_provider = Some(preflight.provider);
        report.runtime_preflight = Some(preflight);
        if let Err(error) = self.runtime.verify_network(request.network_policy) {
            report.checkpoint.cleanup_completed = true;
            report.fail(error.to_string());
            return Ok(report);
        }

        report.checkpoint.stage = ExecutionStage::PullingImage;
        observer(&report)?;
        if let Err(error) = self.runtime.pull(&image) {
            report.checkpoint.cleanup_completed = true;
            report.fail(error.to_string());
            return Ok(report);
        }
        if cancellation.is_cancelled() {
            report.checkpoint.stage = ExecutionStage::Cancelled;
            report.checkpoint.cleanup_completed = true;
            return Ok(report);
        }

        // The runtime may have stopped, restarted, or changed its security
        // configuration since the batch-level prepare proof above (and an
        // image pull can be long-running). Reinspect the live daemon directly
        // before this engine starts and persist that fresh proof. Never leave
        // the earlier batch proof attached to an execution-preflight failure.
        let execution_preflight = match self.runtime.execution_preflight() {
            Ok(preflight) => preflight,
            Err(error) => {
                report.runtime_preflight = None;
                report.checkpoint.cleanup_completed = true;
                report.fail(error.to_string());
                return Ok(report);
            }
        };
        report.checkpoint.runtime_command_provenance =
            Some(execution_preflight.command_provenance.clone());
        report.checkpoint.runtime_provider = Some(execution_preflight.provider);
        report.runtime_preflight = Some(execution_preflight);

        // Create capture files only after the live daemon proof succeeds. A
        // preflight failure has no scanner output and must not leave empty,
        // untracked evidence files behind.
        let capture = self.artifacts.prepare_capture(&directories)?;

        report.checkpoint.stage = ExecutionStage::Running;
        observer(&report)?;
        let mut created_container = None;
        let runtime_result = self.runtime.run(
            &plan,
            request.credentials,
            cancellation,
            &capture,
            &mut created_container,
        );
        if let Ok(outcome) = runtime_result.as_ref() {
            report.exit_code = outcome.exit_code;
        }

        report.checkpoint.stage = ExecutionStage::CapturingArtifacts;
        let artifact_result = (|| -> AppResult<Vec<RawArtifact>> {
            let mut artifacts = self.artifacts.finalize_capture(&context, &capture)?;
            artifacts.extend(
                self.artifacts
                    .collect_output_artifacts(&context, &directories)?,
            );
            Ok(artifacts)
        })();
        let cleanup_result = match created_container.as_ref() {
            Some(created) => self.runtime.cleanup(plan.ownership(), Some(created)),
            None => {
                report.checkpoint.container_name = None;
                Ok(CleanupOutcome {
                    removed: false,
                    detail: "this runtime invocation did not create a container".into(),
                })
            }
        };

        match artifact_result {
            Ok(artifacts) => {
                report.checkpoint.artifact_ids = artifacts
                    .iter()
                    .map(|artifact| artifact.id.clone())
                    .collect();
                report.raw_artifacts = artifacts;
            }
            Err(error) => report.fail(error.to_string()),
        }

        match cleanup_result {
            Ok(cleanup) => {
                report.checkpoint.cleanup_completed = true;
                report.cleanup = Some(cleanup);
            }
            Err(error) => {
                let runtime_error = match runtime_result.as_ref() {
                    Ok(outcome) if outcome.exit_code.is_some_and(|code| code != 0) => {
                        Some(format!(
                            "scanner container exited with status {:?}",
                            outcome.exit_code
                        ))
                    }
                    Ok(_) => None,
                    Err(runtime_error) => Some(runtime_error.to_string()),
                };
                let combined = combined_cleanup_pending_error(
                    runtime_error.as_deref(),
                    report.checkpoint.last_error.as_deref(),
                    &error.to_string(),
                );
                report.checkpoint.stage = ExecutionStage::CleanupPending;
                report.checkpoint.cleanup_completed = false;
                report.checkpoint.last_error = Some(combined);
                return Ok(report);
            }
        }

        let outcome = match runtime_result {
            Ok(outcome) => outcome,
            Err(error) => {
                report.fail(error.to_string());
                return Ok(report);
            }
        };
        report.exit_code = outcome.exit_code;
        if outcome.cancelled || cancellation.is_cancelled() {
            report.checkpoint.stage = ExecutionStage::Cancelled;
            return Ok(report);
        }
        if outcome.exit_code != Some(0) {
            report.fail(format!(
                "scanner container exited with status {:?}",
                outcome.exit_code
            ));
            return Ok(report);
        }
        if report.checkpoint.stage == ExecutionStage::Failed {
            return Ok(report);
        }

        report.checkpoint.stage = ExecutionStage::AdaptingArtifacts;
        observer(&report)?;
        self.adapt_captured(request, &mut report);
        Ok(report)
    }

    pub fn resume_captured(
        &self,
        request: &EngineExecutionRequest<'_>,
        previous: &ExecutionReport,
    ) -> AppResult<ExecutionReport> {
        resume_captured_artifacts(self.adapters, request, previous)
    }

    pub fn cleanup_checkpoint(
        &self,
        checkpoint: &ExecutionCheckpoint,
        ownership: &crate::container_runtime::OwnedContainerCleanupRequest,
    ) -> AppResult<ExecutionCheckpoint> {
        if checkpoint.resume_action() != ResumeAction::CleanupContainer {
            return Err(AppError::InvalidRequest(
                "checkpoint does not require cleanup".into(),
            ));
        }
        checkpoint.validate()?;
        if checkpoint.managed_network.is_some() {
            return Err(AppError::NotAvailable(
                "container-only cleanup cannot close a managed egress obligation; reconcile the exact durable network identity first"
                    .into(),
            ));
        }
        let container_name = checkpoint
            .container_name
            .as_deref()
            .ok_or_else(|| AppError::Runtime("cleanup checkpoint has no container name".into()))?;
        if ownership.container_name()? != container_name
            || ownership.case_id != checkpoint.case_id
            || ownership.scan_run_id != checkpoint.scan_run_id
            || ownership.engine_run_id != checkpoint.engine_run_id
            || ownership.engine_id != checkpoint.engine_id
            || ownership.attempt != checkpoint.attempt
            || Some(ownership.scope_sha256.as_str()) != checkpoint.scope_sha256.as_deref()
        {
            return Err(AppError::NotAuthorized(
                "cleanup ownership proof does not match the saved execution checkpoint".into(),
            ));
        }
        self.runtime.cleanup(ownership, None)?;
        let mut updated = checkpoint.clone();
        updated.cleanup_completed = true;
        updated.stage = ExecutionStage::Failed;
        updated.last_error = Some("container cleanup completed; execution may be retried".into());
        Ok(updated)
    }

    fn adapt_captured(&self, request: &EngineExecutionRequest<'_>, report: &mut ExecutionReport) {
        adapt_captured_artifacts(self.adapters, request, report);
    }
}

/// Re-runs only the bounded adapter over already-hashed artifacts. Runtime
/// cleanup and managed-network reconciliation remain the caller's obligation;
/// when those are already durably complete, this function needs no container
/// runtime and cannot contend with a newly starting scan.
pub fn resume_captured_artifacts(
    adapters: &AdapterRegistry,
    request: &EngineExecutionRequest<'_>,
    previous: &ExecutionReport,
) -> AppResult<ExecutionReport> {
    if previous.checkpoint.resume_action() != ResumeAction::AdaptCapturedArtifacts {
        return Err(AppError::InvalidRequest(format!(
            "execution at stage {:?} cannot resume from captured artifacts",
            previous.checkpoint.stage
        )));
    }
    if previous.checkpoint.case_id != request.case_id
        || previous.checkpoint.scan_run_id != request.scan_run_id
        || previous.checkpoint.engine_run_id != request.engine_run_id
        || previous.checkpoint.engine_id != request.manifest.id
    {
        return Err(AppError::InvalidRequest(
            "resume request does not match the saved execution checkpoint".into(),
        ));
    }
    let mut report = previous.clone();
    adapt_captured_artifacts(adapters, request, &mut report);
    Ok(report)
}

fn adapt_captured_artifacts(
    adapters: &AdapterRegistry,
    request: &EngineExecutionRequest<'_>,
    report: &mut ExecutionReport,
) {
    report.checkpoint.stage = ExecutionStage::AdaptingArtifacts;
    let asset_ids: Vec<String> = request
        .assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect();
    let asset_identifier_map = AdapterAssetIdentifierMap::from_assets(request.assets);
    let input = AdapterInput {
        case_id: request.case_id,
        scan_run_id: request.scan_run_id,
        engine_run_id: request.engine_run_id,
        manifest: request.manifest,
        ai_system_applicable: request.ai_system_applicable,
        ai_generated_artifact_applicable: request.ai_generated_artifact_applicable,
        asset_ids: &asset_ids,
        asset_identifier_map: &asset_identifier_map,
        artifact_root: &report.artifact_root,
        raw_artifacts: &report.raw_artifacts,
    };
    match adapters.normalize(&input) {
        Ok(Some(output)) => {
            report.findings = output.findings;
            report.warnings.extend(output.warnings);
            if output.complete {
                report.checkpoint.stage = ExecutionStage::Completed;
                report.checkpoint.last_error = None;
            } else {
                report.checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
                report.checkpoint.last_error =
                    Some("adapter normalization was incomplete; raw evidence was retained".into());
            }
        }
        Ok(None) => {
            report.findings.clear();
            report.warnings.push(format!(
                "scanner output was captured, but no verified adapter is registered for {} version {}",
                request.manifest.id, request.manifest.adapter_version
            ));
            report.checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
            report.checkpoint.last_error = None;
        }
        Err(error) => {
            report.findings.clear();
            report.warnings.push(format!(
                "scanner output was captured, but adapter {} version {} failed validation",
                request.manifest.id, request.manifest.adapter_version
            ));
            report.checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
            report.checkpoint.last_error = Some(error.to_string());
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatedAssetScope<'a> {
    asset: &'a Asset,
    identifiers: Vec<&'a AssetIdentifier>,
    grants: Vec<&'a ScopeGrant>,
}

fn validate_execution_scope<'a>(
    manifest: &EngineManifest,
    assets: &'a [Asset],
    grants: &'a [ScopeGrant],
    network_policy: &NetworkPolicy,
) -> AppResult<Vec<ValidatedAssetScope<'a>>> {
    if assets.is_empty() {
        return Err(AppError::NotAuthorized(format!(
            "engine {} has no explicitly selected assets",
            manifest.id
        )));
    }
    let direct_external = manifest.required_permissions.iter().any(|permission| {
        matches!(
            permission,
            ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
        )
    });
    if manifest.active_external && !direct_external {
        return Err(AppError::EngineRegistry(format!(
            "external target engine {} must require low-impact or active external permission",
            manifest.id
        )));
    }
    let mut asset_ids = BTreeSet::new();
    let now = Utc::now();
    let mut validated = Vec::new();

    for asset in assets {
        if !asset_ids.insert(asset.id.as_str()) {
            return Err(AppError::InvalidRequest(format!(
                "asset {} appears more than once in the engine run",
                asset.id
            )));
        }
        if !manifest.supports_asset(asset) {
            return Err(AppError::InvalidRequest(format!(
                "engine {} does not support the provider and kind contract for asset {} ({:?})",
                manifest.id, asset.id, asset.kind
            )));
        }

        let mut matched = Vec::new();
        for permission in &manifest.required_permissions {
            let grant = grants
                .iter()
                .find(|grant| {
                    grant.asset_id == asset.id
                        && grant.permission == *permission
                        && !grant.confirmed_by.trim().is_empty()
                        && grant.confirmed_at <= now
                        && grant.expires_at.is_none_or(|expires_at| expires_at > now)
                        && (!direct_external || grant.expires_at.is_some())
                })
                .ok_or_else(|| {
                    AppError::NotAuthorized(format!(
                        "asset {} lacks a current {:?} scope grant for engine {}",
                        asset.id, permission, manifest.id
                    ))
                })?;
            matched.push(grant);
        }

        let identifiers = if direct_external {
            if asset.candidate || !asset.owner_confirmed {
                return Err(AppError::NotAuthorized(format!(
                    "direct external engine {} requires confirmed ownership for asset {}",
                    manifest.id, asset.id
                )));
            }
            if matched.is_empty()
                || matched.iter().any(|grant| {
                    grant
                        .authorization_reference
                        .as_deref()
                        .unwrap_or_default()
                        .trim()
                        .is_empty()
                })
            {
                return Err(AppError::NotAuthorized(format!(
                    "direct external engine {} requires a written authorization reference for every permission on asset {}",
                    manifest.id, asset.id
                )));
            }
            let allowed_targets: BTreeSet<&str> = network_policy
                .allowed_destinations()
                .iter()
                .map(String::as_str)
                .collect();
            let mut structured_targets = BTreeSet::new();
            for grant in &matched {
                let external = grant.external_scope.as_ref().ok_or_else(|| {
                    AppError::NotAuthorized(format!(
                        "direct external grant {} has no structured target policy",
                        grant.id
                    ))
                })?;
                external.validate(now)?;
                if external.id != grant.id || external.asset_id != asset.id {
                    return Err(AppError::NotAuthorized(
                        "structured external policy does not match its grant and asset".into(),
                    ));
                }
                let expected_activity = match grant.permission {
                    ScanPermission::LowImpactExternalConnection => {
                        crate::external_scope::ExternalActivity::LowImpactExternal
                    }
                    ScanPermission::ActiveExternalTesting => {
                        crate::external_scope::ExternalActivity::ActiveExternal
                    }
                    _ => continue,
                };
                if external.activity != expected_activity
                    || !external_destination_is_frozen(external, &allowed_targets)
                {
                    return Err(AppError::NotAuthorized(format!(
                        "structured external policy {} is not represented by the frozen managed gateway",
                        external.id
                    )));
                }
                structured_targets.insert(external.target.canonical_text());
            }
            let identifiers: Vec<&AssetIdentifier> = asset
                .identifiers
                .iter()
                .filter(|identifier| structured_targets.contains(identifier.value.as_str()))
                .collect();
            if identifiers.is_empty() {
                return Err(AppError::NotAuthorized(format!(
                    "managed network policy does not allow an exact identifier for external asset {}",
                    asset.id
                )));
            }
            identifiers
        } else {
            asset.identifiers.iter().collect()
        };

        validated.push(ValidatedAssetScope {
            asset,
            identifiers,
            grants: matched,
        });
    }
    Ok(validated)
}

fn external_destination_is_frozen(
    grant: &crate::external_scope::ExternalScopeGrant,
    destinations: &BTreeSet<&str>,
) -> bool {
    match &grant.target {
        crate::external_scope::CanonicalTarget::Hostname(hostname) => grant
            .ports
            .iter()
            .all(|port| destinations.contains(format!("{hostname}:{port}").as_str())),
        crate::external_scope::CanonicalTarget::Address(address) => {
            grant.ports.iter().all(|port| {
                destinations.contains(
                    std::net::SocketAddr::new(*address, *port)
                        .to_string()
                        .as_str(),
                )
            })
        }
        crate::external_scope::CanonicalTarget::Network(network) => {
            grant.ports.iter().all(|port| {
                destinations.iter().any(|destination| {
                    destination
                        .parse::<std::net::SocketAddr>()
                        .is_ok_and(|socket| {
                            socket.port() == *port && network.contains(&socket.ip())
                        })
                })
            })
        }
    }
}

#[derive(Debug, Serialize)]
struct ScopeDocument<'a> {
    schema_version: &'static str,
    engine_id: &'a str,
    generated_at: String,
    assets: Vec<ScopeAssetDocument<'a>>,
}

#[derive(Debug, Serialize)]
struct ScopeAssetDocument<'a> {
    id: &'a str,
    name: &'a str,
    kind: &'a crate::domain::AssetKind,
    provider: Option<&'a str>,
    region: Option<&'a str>,
    identifiers: Vec<&'a AssetIdentifier>,
    grants: Vec<ScopeGrantDocument<'a>>,
}

#[derive(Debug, Serialize)]
struct ScopeGrantDocument<'a> {
    id: &'a str,
    permission: &'a ScanPermission,
    confirmed_by: &'a str,
    confirmed_at: String,
    expires_at: Option<String>,
    authorization_reference: Option<&'a str>,
    external_scope: Option<&'a crate::external_scope::ExternalScopeGrant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_addresses: Option<Vec<String>>,
}

impl<'a> ScopeDocument<'a> {
    fn new(
        manifest: &'a EngineManifest,
        scope: &'a [ValidatedAssetScope<'a>],
        frozen_destinations: Option<&[GatewayDestination]>,
    ) -> AppResult<Self> {
        let external_launcher = uses_external_launcher(&manifest.id);
        let destinations = if external_launcher {
            Some(frozen_destinations.ok_or_else(|| {
                AppError::NotAuthorized(format!(
                    "engine {} has no frozen address snapshot for its external launcher",
                    manifest.id
                ))
            })?)
        } else {
            None
        };
        let assets = scope
            .iter()
            .map(|entry| {
                let grants = entry
                    .grants
                    .iter()
                    .map(|grant| {
                        let resolved_addresses = match destinations {
                            Some(destinations) => {
                                let external = grant.external_scope.as_ref().ok_or_else(|| {
                                    AppError::NotAuthorized(format!(
                                        "external launcher grant {} has no structured target policy",
                                        grant.id
                                    ))
                                })?;
                                Some(frozen_addresses_for_grant(external, destinations)?)
                            }
                            None => None,
                        };
                        Ok(ScopeGrantDocument {
                            id: &grant.id,
                            permission: &grant.permission,
                            confirmed_by: &grant.confirmed_by,
                            confirmed_at: grant.confirmed_at.to_rfc3339(),
                            expires_at: grant.expires_at.map(|value| value.to_rfc3339()),
                            authorization_reference: grant.authorization_reference.as_deref(),
                            external_scope: grant.external_scope.as_ref(),
                            resolved_addresses,
                        })
                    })
                    .collect::<AppResult<Vec<_>>>()?;
                Ok(ScopeAssetDocument {
                    id: &entry.asset.id,
                    name: &entry.asset.name,
                    kind: &entry.asset.kind,
                    provider: entry.asset.provider.as_deref(),
                    region: entry.asset.region.as_deref(),
                    identifiers: entry.identifiers.clone(),
                    grants,
                })
            })
            .collect::<AppResult<Vec<_>>>()?;
        Ok(Self {
            schema_version: if external_launcher { "2" } else { "1" },
            engine_id: &manifest.id,
            generated_at: Utc::now().to_rfc3339(),
            assets,
        })
    }
}

fn uses_external_launcher(engine_id: &str) -> bool {
    matches!(engine_id, "naabu" | "httpx" | "nuclei")
}

fn frozen_addresses_for_grant(
    grant: &crate::external_scope::ExternalScopeGrant,
    destinations: &[GatewayDestination],
) -> AppResult<Vec<String>> {
    const MAX_FROZEN_ADDRESSES: usize = 4_096;

    let expected_static_addresses = match &grant.target {
        crate::external_scope::CanonicalTarget::Address(address) => {
            Some(BTreeSet::from([*address]))
        }
        crate::external_scope::CanonicalTarget::Network(network) => {
            let addresses = network
                .hosts()
                .take(MAX_FROZEN_ADDRESSES + 1)
                .collect::<BTreeSet<_>>();
            if addresses.len() > MAX_FROZEN_ADDRESSES {
                return Err(AppError::InvalidRequest(format!(
                    "external grant {} expands beyond the frozen address limit",
                    grant.id
                )));
            }
            Some(addresses)
        }
        crate::external_scope::CanonicalTarget::Hostname(_) => None,
    };
    let mut addresses = BTreeSet::<IpAddr>::new();
    for destination in destinations {
        if destination.ports != grant.ports
            || destination.allow_sensitive_networks != grant.allow_sensitive_networks
        {
            continue;
        }
        let matches_target = match (&grant.target, &expected_static_addresses) {
            (crate::external_scope::CanonicalTarget::Hostname(hostname), None) => {
                destination.hostname.as_deref() == Some(hostname.as_str())
            }
            (
                crate::external_scope::CanonicalTarget::Address(_)
                | crate::external_scope::CanonicalTarget::Network(_),
                Some(expected),
            ) => destination.hostname.is_none() && destination.addresses == *expected,
            _ => false,
        };
        if matches_target {
            addresses.extend(destination.addresses.iter().copied());
        }
    }
    if addresses.is_empty() || addresses.len() > MAX_FROZEN_ADDRESSES {
        return Err(AppError::NotAuthorized(format!(
            "external grant {} is not represented by one bounded frozen address set",
            grant.id
        )));
    }
    Ok(addresses
        .into_iter()
        .map(|address| address.to_string())
        .collect())
}

fn run_directories_with_workspace(
    directories: &RunDirectories,
    workspace: &Path,
) -> RunDirectories {
    RunDirectories {
        root: directories.root.clone(),
        workspace: workspace.to_path_buf(),
        output: directories.output.clone(),
        control: directories.control.clone(),
        raw: directories.raw.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{AdapterOutput, EngineAdapter};
    use crate::artifact_store::CapturePaths;
    use crate::container_runtime::{
        ContainerRunPlan, CreatedContainer, FakeContainerRuntime, FakeRunBehavior,
        OwnedContainerCleanupRequest, RuntimeCall, RuntimeOutcome,
    };
    use crate::domain::{
        AssetIdentifier, AssetKind, DistributionMode, EngineCategory, EngineCompatibility,
        EngineExecutionContract, EngineExecutionResources, ImageReference, ManifestStatus,
    };
    use crate::external_scope::{
        CanonicalTarget, ExternalActivity, ExternalScopeGrant, RatePolicy, TemplatePolicy,
        TransportProtocol,
    };
    use crate::naabu_work_plan::{NaabuLauncherFrozenGrant, NaabuLauncherWorkUnit};
    use chrono::Duration;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    struct IncompleteAdapter;

    impl EngineAdapter for IncompleteAdapter {
        fn engine_id(&self) -> &str {
            "scanner"
        }

        fn adapter_version(&self) -> &str {
            "adapter-1"
        }

        fn normalize(&self, _input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
            Ok(AdapterOutput {
                findings: Vec::new(),
                warnings: vec!["one malformed record was retained only as raw evidence".into()],
                complete: false,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedLauncherPlan {
        path: PathBuf,
        bytes: Vec<u8>,
        runtime_args: Vec<String>,
    }

    #[derive(Default)]
    struct LauncherPlanCaptureRuntime {
        observed: Mutex<Option<ObservedLauncherPlan>>,
    }

    impl LauncherPlanCaptureRuntime {
        fn observed(&self) -> Option<ObservedLauncherPlan> {
            self.observed.lock().expect("observed plan lock").clone()
        }

        fn preflight_result() -> RuntimePreflight {
            RuntimePreflight {
                provider: crate::container_runtime::RuntimeProvider::Docker,
                server_version: "launcher-plan-test".into(),
                security_options: "test-seccomp".into(),
                command_provenance: RuntimeCommandProvenance::Compatibility,
            }
        }
    }

    impl ContainerRuntime for LauncherPlanCaptureRuntime {
        fn preflight(&self) -> AppResult<RuntimePreflight> {
            Ok(Self::preflight_result())
        }

        fn execution_preflight(&self) -> AppResult<RuntimePreflight> {
            Ok(Self::preflight_result())
        }

        fn verify_network(&self, _policy: &NetworkPolicy) -> AppResult<()> {
            Ok(())
        }

        fn pull(&self, _image: &PinnedImage) -> AppResult<()> {
            Ok(())
        }

        fn run(
            &self,
            plan: &ContainerRunPlan,
            _credentials: &ScannerCredentialSet,
            _cancellation: &CancellationToken,
            _capture: &CapturePaths,
            _created_container: &mut Option<CreatedContainer>,
        ) -> AppResult<RuntimeOutcome> {
            let path = plan.launcher_plan_file().ok_or_else(|| {
                AppError::Internal("launcher-v2 plan was not mounted into the run plan".into())
            })?;
            *self.observed.lock().expect("observed plan lock") = Some(ObservedLauncherPlan {
                path: path.to_path_buf(),
                bytes: std::fs::read(path)?,
                runtime_args: plan.runtime_args().to_vec(),
            });
            Err(AppError::Runtime(
                "test runtime stopped after observing the run plan".into(),
            ))
        }

        fn cleanup(
            &self,
            _ownership: &OwnedContainerCleanupRequest,
            _created_container: Option<&CreatedContainer>,
        ) -> AppResult<CleanupOutcome> {
            Err(AppError::Internal(
                "launcher-plan capture runtime must not create a container".into(),
            ))
        }
    }

    fn manifest(active_external: bool) -> EngineManifest {
        EngineManifest {
            schema_version: "1".into(),
            id: "scanner".into(),
            display_name: "Scanner".into(),
            category: if active_external {
                EngineCategory::ExternalAttackSurface
            } else {
                EngineCategory::CodeAndSecrets
            },
            description: "test scanner".into(),
            repository_url: "https://example.invalid/scanner".into(),
            homepage_url: None,
            license_spdx: "Apache-2.0".into(),
            distribution_mode: DistributionMode::PullPinnedImage,
            image: Some(ImageReference {
                repository: "registry.example/scanner".into(),
                tag: None,
                digest: Some(format!("sha256:{}", "a".repeat(64))),
                signature_identity: None,
            }),
            source_revision: None,
            engine_version: Some("1".into()),
            rule_version: Some("rules-1".into()),
            adapter_version: "adapter-1".into(),
            supported_providers: vec![],
            supported_asset_kinds: vec![if active_external {
                AssetKind::Domain
            } else {
                AssetKind::Repository
            }],
            input_contracts: vec![],
            provider_execution_contracts: vec![],
            direct_network_contract: active_external.then(|| {
                crate::domain::DirectNetworkExecutionContract {
                    target_kinds: vec![crate::external_scope::DirectNetworkTargetKind::Hostname],
                    protocols: vec![TransportProtocol::Https],
                }
            }),
            required_permissions: vec![if active_external {
                ScanPermission::ActiveExternalTesting
            } else {
                ScanPermission::LocalArtifactRead
            }],
            active_external,
            default_enabled: false,
            estimated_memory_mb: 512,
            estimated_disk_mb: 512,
            network_destinations: if active_external {
                vec!["authorized target services".into()]
            } else {
                vec![]
            },
            output_formats: vec!["json".into()],
            command: vec!["scanner".into(), "--json".into()],
            status: ManifestStatus::Integrated,
            notices: vec![],
            compatibility: EngineCompatibility {
                runnable: true,
                blocked_by: vec![],
                ..EngineCompatibility::default()
            },
            execution: None,
        }
    }

    fn naabu_launcher_v2_manifest() -> EngineManifest {
        let mut manifest = manifest(true);
        manifest.id = NAABU_ENGINE_ID.into();
        manifest.display_name = "Naabu".into();
        manifest.required_permissions = vec![ScanPermission::LowImpactExternalConnection];
        manifest.command = [
            "--engine",
            "naabu",
            "--scope",
            "/run/ai-security-scanner/scope.json",
            "--output",
            "/output",
            "--journal-version",
            "2",
            "--journal-plan",
            "/run/ai-security-scanner/execution-journal-v2.json",
        ]
        .map(str::to_owned)
        .to_vec();
        manifest.execution = Some(EngineExecutionContract {
            resources: EngineExecutionResources {
                timeout_seconds: 3_600,
            },
            launcher_journal_version: Some(NAABU_LAUNCHER_PLAN_SCHEMA_VERSION),
        });
        manifest
    }

    fn naabu_launcher_plan(engine_run_id: &str, attempt: u32) -> NaabuLauncherPlanV2 {
        NaabuLauncherPlanV2 {
            schema_version: NAABU_LAUNCHER_PLAN_SCHEMA_VERSION,
            engine_id: NAABU_ENGINE_ID.into(),
            engine_run_id: engine_run_id.into(),
            execution_attempt: attempt,
            frozen_grants: vec![NaabuLauncherFrozenGrant {
                scope_grant_id: "grant-one".into(),
                addresses: vec!["192.0.2.10".parse().expect("test address")],
                ports: vec![443],
            }],
            requested_work_units: vec![NaabuLauncherWorkUnit {
                unit_id: "wu_0123456789abcdef0123456789abcdef".into(),
                scope_sha256: "b".repeat(64),
                grant_index: 0,
                address_start: 0,
                address_len: 1,
                port_start: 0,
                port_len: 1,
                endpoint_pair_count: 1,
                conservative_deadline_seconds: 36,
            }],
        }
    }

    fn asset(id: &str, active_external: bool) -> Asset {
        Asset {
            id: id.into(),
            kind: if active_external {
                AssetKind::Domain
            } else {
                AssetKind::Repository
            },
            name: id.into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: if active_external { "dns_name" } else { "path" }.into(),
                value: if active_external {
                    format!("{id}.example")
                } else {
                    id.into()
                },
            }],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(active_external),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        }
    }

    fn grant(asset_id: &str, permission: ScanPermission, external: bool) -> ScopeGrant {
        let now = Utc::now();
        let id = format!("grant-{asset_id}");
        let external_scope = external.then(|| {
            let activity = match permission {
                ScanPermission::LowImpactExternalConnection => ExternalActivity::LowImpactExternal,
                _ => ExternalActivity::ActiveExternal,
            };
            ExternalScopeGrant {
                id: id.clone(),
                case_id: "case-1".into(),
                asset_id: asset_id.into(),
                target: CanonicalTarget::Hostname(format!("{asset_id}.example")),
                ports: [443].into_iter().collect(),
                protocol: TransportProtocol::Https,
                activity,
                rate_policy: RatePolicy {
                    requests_per_second: 2,
                    concurrency: 1,
                    timeout_seconds: 30,
                },
                template_policy: TemplatePolicy::conservative(
                    if activity == ExternalActivity::ActiveExternal {
                        "nuclei-templates@0123456789abcdef0123456789abcdef01234567"
                    } else {
                        "not_applicable"
                    },
                    if activity == ExternalActivity::ActiveExternal {
                        vec!["http/misconfiguration/example".into()]
                    } else {
                        vec![]
                    },
                ),
                asserted_authority: format!("AUTH-{asset_id}"),
                approved_by: "operator".into(),
                approved_at: now - Duration::minutes(1),
                expires_at: now + Duration::hours(1),
                allow_sensitive_networks: false,
            }
        });
        ScopeGrant {
            id,
            asset_id: asset_id.into(),
            permission,
            confirmed_by: "operator".into(),
            confirmed_at: now,
            expires_at: Some(now + Duration::hours(1)),
            authorization_reference: external.then(|| format!("AUTH-{asset_id}")),
            notes: None,
            external_scope,
        }
    }

    #[test]
    fn active_external_scope_is_checked_for_every_asset() {
        let manifest = manifest(true);
        let assets = vec![asset("one", true), asset("two", true)];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into(), "two.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");

        let error = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect_err("second asset must be rejected");
        assert!(error.to_string().contains("asset two lacks"));
    }

    #[test]
    fn active_scope_document_only_contains_policy_allowed_identifiers() {
        let manifest = manifest(true);
        let mut selected = asset("one", true);
        selected.identifiers.push(AssetIdentifier {
            namespace: "dns_name".into(),
            value: "not-authorized.example".into(),
        });
        let assets = vec![selected];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");

        let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect("authorized scope");
        let document = ScopeDocument::new(&manifest, &scope, None).expect("scope document");
        let json = serde_json::to_value(document).expect("scope json");

        assert_eq!(
            json["assets"][0]["identifiers"].as_array().unwrap().len(),
            1
        );
        assert_eq!(json["assets"][0]["identifiers"][0]["value"], "one.example");
        assert!(!json.to_string().contains("not-authorized.example"));
        assert_eq!(json["schema_version"], "1");
        assert!(
            json["assets"][0]["grants"][0]
                .get("resolved_addresses")
                .is_none()
        );
    }

    #[test]
    fn scope_document_preserves_only_the_exact_structured_external_grant() {
        let manifest = manifest(true);
        let assets = vec![asset("one", true)];
        let now = Utc::now();
        let mut selected_grant = grant("one", ScanPermission::ActiveExternalTesting, true);
        selected_grant.external_scope = Some(ExternalScopeGrant {
            id: selected_grant.id.clone(),
            case_id: "case-1".into(),
            asset_id: "one".into(),
            target: CanonicalTarget::Hostname("one.example".into()),
            ports: [443].into_iter().collect(),
            protocol: TransportProtocol::Https,
            activity: ExternalActivity::ActiveExternal,
            rate_policy: RatePolicy {
                requests_per_second: 2,
                concurrency: 1,
                timeout_seconds: 30,
            },
            template_policy: TemplatePolicy::conservative(
                "nuclei-templates@0123456789abcdef0123456789abcdef01234567",
                vec!["http/misconfiguration/example".into()],
            ),
            asserted_authority: "AUTH-one".into(),
            approved_by: "operator".into(),
            approved_at: now - Duration::minutes(1),
            expires_at: now + Duration::hours(1),
            allow_sensitive_networks: false,
        });
        let grants = vec![selected_grant];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");
        let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect("authorized scope");
        let json = serde_json::to_value(
            ScopeDocument::new(&manifest, &scope, None).expect("scope document"),
        )
        .expect("scope json");
        let external = &json["assets"][0]["grants"][0]["external_scope"];

        assert_eq!(external["target"]["kind"], "hostname");
        assert_eq!(external["target"]["value"], "one.example");
        assert_eq!(external["ports"], serde_json::json!([443]));
        assert_eq!(external["protocol"], "https");
        assert_eq!(external["rate_policy"]["requests_per_second"], 2);
        assert_eq!(
            external["template_policy"]["allowed_template_ids"],
            serde_json::json!(["http/misconfiguration/example"])
        );
        assert!(!json.to_string().contains("not-authorized.example"));
    }

    #[test]
    fn external_launcher_scope_receives_only_the_gateway_frozen_addresses() {
        let mut manifest = manifest(true);
        manifest.id = "httpx".into();
        let assets = vec![asset("one", true)];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");
        let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect("authorized scope");
        let destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: [
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ]
            .into_iter()
            .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let document = ScopeDocument::new(&manifest, &scope, Some(&destinations))
            .expect("frozen launcher scope");
        let json = serde_json::to_value(document).expect("scope json");

        assert_eq!(
            json["assets"][0]["grants"][0]["resolved_addresses"],
            serde_json::json!(["192.0.2.10", "2001:db8::10"])
        );
        assert_eq!(json["schema_version"], "2");
        assert!(ScopeDocument::new(&manifest, &scope, None).is_err());

        let unrelated = vec![GatewayDestination {
            hostname: Some("other.example".into()),
            addresses: ["198.51.100.10".parse().unwrap()].into_iter().collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        assert!(ScopeDocument::new(&manifest, &scope, Some(&unrelated)).is_err());
    }

    #[test]
    fn low_impact_external_manifest_uses_the_same_frozen_gateway_contract() {
        let mut manifest = manifest(true);
        manifest.required_permissions = vec![ScanPermission::LowImpactExternalConnection];
        let assets = vec![asset("one", true)];
        let grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");

        let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect("low-impact target scope");
        assert_eq!(scope.len(), 1);
    }

    #[test]
    fn naabu_launcher_v2_sidecar_reaches_the_exact_read_only_run_plan_mount() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = LauncherPlanCaptureRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = naabu_launcher_v2_manifest();
        let assets = vec![asset("one", true)];
        let grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.10".parse().expect("test address")]
                .into_iter()
                .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let launcher_plan = naabu_launcher_plan("engine-run-1", 1);
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: Some(&frozen_destinations),
            naabu_launcher_plan: Some(&launcher_plan),
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("captured launcher plan report");
        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert!(
            report
                .checkpoint
                .last_error
                .as_deref()
                .is_some_and(|message| message.contains("stopped after observing"))
        );

        let observed = runtime
            .observed()
            .expect("run plan reached runtime boundary");
        let expected_path = std::fs::canonicalize(
            temp.path()
                .join("artifacts/case-1/run-1/engine-run-1/attempt-1/control")
                .join(NAABU_LAUNCHER_PLAN_CONTROL_FILE),
        )
        .expect("canonical launcher plan");
        assert_eq!(observed.path, expected_path);
        assert!(
            std::fs::metadata(&observed.path)
                .expect("launcher plan metadata")
                .permissions()
                .readonly()
        );
        assert_eq!(
            serde_json::from_slice::<NaabuLauncherPlanV2>(&observed.bytes)
                .expect("typed launcher plan"),
            launcher_plan
        );
        let expected_mount = format!(
            "type=bind,src={},dst=/run/ai-security-scanner/execution-journal-v2.json,readonly",
            observed.path.display()
        );
        assert_eq!(
            observed
                .runtime_args
                .windows(2)
                .filter_map(|arguments| {
                    (arguments[0] == "--mount"
                        && arguments[1]
                            .contains("/run/ai-security-scanner/execution-journal-v2.json"))
                    .then_some(arguments[1].as_str())
                })
                .collect::<Vec<_>>(),
            [expected_mount.as_str()]
        );
    }

    #[test]
    fn mismatched_naabu_launcher_identity_is_rejected_before_runtime_or_sidecar_write() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = naabu_launcher_v2_manifest();
        let assets = vec![asset("one", true)];
        let grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.10".parse().expect("test address")]
                .into_iter()
                .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let launcher_plan = naabu_launcher_plan("another-engine-run", 1);
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: Some(&frozen_destinations),
            naabu_launcher_plan: Some(&launcher_plan),
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let error = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect_err("mismatched launcher identity must fail closed");
        assert!(error.to_string().contains("identity does not match"));
        assert!(runtime.calls().is_empty());
        assert!(
            !temp
                .path()
                .join("artifacts/case-1/run-1/engine-run-1/attempt-1/control")
                .join(NAABU_LAUNCHER_PLAN_CONTROL_FILE)
                .exists()
        );
    }

    #[test]
    fn successful_runtime_without_adapter_stops_at_captured_artifacts() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        let execution_preflight = RuntimePreflight {
            provider: crate::container_runtime::RuntimeProvider::Docker,
            server_version: "fake-2.0-after-restart".into(),
            security_options: "fake-updated-seccomp".into(),
            command_provenance: crate::container_runtime::RuntimeCommandProvenance::Compatibility,
        };
        runtime.set_execution_preflight(execution_preflight.clone());
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"scanner stdout".to_vec(),
            stderr: b"scanner stderr".to_vec(),
            output_files: BTreeMap::from([("result.json".into(), b"{}".to_vec())]),
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("execution report");

        assert_eq!(
            report.checkpoint.stage,
            ExecutionStage::CapturedAwaitingAdapter
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.runtime_preflight, Some(execution_preflight));
        assert_eq!(report.raw_artifacts.len(), 3);
        assert_eq!(report.raw_artifacts[0].byte_length, 14);
        assert_eq!(
            runtime.calls(),
            vec![
                RuntimeCall::Preflight,
                RuntimeCall::VerifyNetwork("disabled".into()),
                RuntimeCall::Pull(format!(
                    "registry.example/scanner@sha256:{}",
                    "a".repeat(64)
                )),
                RuntimeCall::ExecutionPreflight,
                RuntimeCall::Run("ass-scanner-engine-run-1-a1".into()),
                RuntimeCall::Cleanup("ass-scanner-engine-run-1-a1".into()),
            ]
        );
    }

    #[test]
    fn stale_batch_preflight_is_not_reused_when_execution_preflight_fails() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_fail_execution_preflight(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("failed execution report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert!(report.checkpoint.cleanup_completed);
        assert_eq!(report.runtime_preflight, None);
        let raw_directory = temp
            .path()
            .join("artifacts/case-1/run-1/engine-run-1/attempt-1/raw");
        assert_eq!(
            std::fs::read_dir(raw_directory)
                .expect("raw capture directory")
                .count(),
            0,
            "execution preflight failure must not leave capture files",
        );
        assert!(
            report
                .checkpoint
                .last_error
                .as_deref()
                .is_some_and(|message| message.contains("execution preflight failure"))
        );
        assert_eq!(
            runtime.calls(),
            vec![
                RuntimeCall::Preflight,
                RuntimeCall::VerifyNetwork("disabled".into()),
                RuntimeCall::Pull(format!(
                    "registry.example/scanner@sha256:{}",
                    "a".repeat(64)
                )),
                RuntimeCall::ExecutionPreflight,
            ]
        );
    }

    #[test]
    fn failed_launch_without_a_created_object_never_cleans_a_same_name_container() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_skip_creation(true);
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(125),
            ..FakeRunBehavior::default()
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("failed launch report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert!(report.checkpoint.container_name.is_none());
        assert!(report.checkpoint.cleanup_completed);
        assert!(
            !runtime
                .calls()
                .iter()
                .any(|call| matches!(call, RuntimeCall::Cleanup(_)))
        );
    }

    #[test]
    fn incomplete_normalization_cannot_complete_or_green_the_engine_run() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"scanner stdout".to_vec(),
            stderr: vec![],
            output_files: BTreeMap::from([("result.json".into(), b"{}".to_vec())]),
        });
        let mut adapters = AdapterRegistry::default();
        adapters
            .register(Arc::new(IncompleteAdapter))
            .expect("register adapter");
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("execution report");

        assert_eq!(
            report.checkpoint.stage,
            ExecutionStage::CapturedAwaitingAdapter
        );
        assert!(report.checkpoint.cleanup_completed);
        assert_eq!(
            report.checkpoint.last_error.as_deref(),
            Some("adapter normalization was incomplete; raw evidence was retained")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("malformed record"))
        );
    }

    #[test]
    fn observer_receives_durable_non_terminal_stages_and_captured_artifacts() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"stdout".to_vec(),
            stderr: vec![],
            output_files: BTreeMap::from([("result.json".into(), b"{}".to_vec())]),
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };
        let mut observed = Vec::new();
        let report = orchestrator
            .execute_with_observer(
                &request,
                &CancellationToken::default(),
                |checkpoint_report| {
                    observed.push((
                        checkpoint_report.checkpoint.stage.clone(),
                        checkpoint_report.raw_artifacts.len(),
                        checkpoint_report.checkpoint.cleanup_completed,
                    ));
                    Ok(())
                },
            )
            .expect("execution");

        assert_eq!(
            observed
                .iter()
                .map(|(stage, _, _)| stage)
                .collect::<Vec<_>>(),
            vec![
                &ExecutionStage::Planned,
                &ExecutionStage::Preflight,
                &ExecutionStage::PullingImage,
                &ExecutionStage::Running,
                &ExecutionStage::AdaptingArtifacts,
            ]
        );
        assert!(observed.last().is_some_and(|(_, count, cleaned)| {
            *count == report.raw_artifacts.len() && *cleaned
        }));
    }

    #[test]
    fn failed_managed_network_proof_prevents_image_pull_and_container_run() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_fail_network(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(true);
        let assets = vec![asset("one", true)];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("failure report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert!(report.checkpoint.cleanup_completed);
        assert!(
            report
                .checkpoint
                .last_error
                .as_deref()
                .is_some_and(|message| message.contains("fake managed network rejected"))
        );
        assert_eq!(
            runtime.calls(),
            vec![
                RuntimeCall::Preflight,
                RuntimeCall::VerifyNetwork("policy-1".into()),
            ]
        );
    }

    #[test]
    fn cancellation_before_preflight_is_resumable_without_running() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let report = orchestrator
            .execute(&request, &cancellation)
            .expect("cancel report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::Cancelled);
        assert_eq!(report.checkpoint.resume_action(), ResumeAction::Reexecute);
        assert!(runtime.calls().is_empty());
    }

    #[test]
    fn cleanup_failure_is_a_distinct_resumable_state() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_fail_cleanup(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("execution report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::CleanupPending);
        assert_eq!(
            report.checkpoint.resume_action(),
            ResumeAction::CleanupContainer
        );
        assert!(!report.checkpoint.cleanup_completed);
        assert_eq!(
            report.checkpoint.runtime_command_provenance,
            Some(RuntimeCommandProvenance::Compatibility)
        );
        assert_eq!(
            report.checkpoint.runtime_provider,
            Some(crate::container_runtime::RuntimeProvider::Docker)
        );
        assert_eq!(report.exit_code, Some(0));
        assert!(
            report
                .checkpoint
                .last_error
                .as_deref()
                .is_some_and(|message| message.contains("fake cleanup failure"))
        );
    }

    #[test]
    fn cleanup_pending_preserves_a_nonzero_scanner_exit_as_the_primary_failure() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(17),
            ..FakeRunBehavior::default()
        });
        runtime.set_fail_cleanup(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("cleanup-pending report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::CleanupPending);
        assert_eq!(report.exit_code, Some(17));
        let error = report.checkpoint.last_error.as_deref().unwrap();
        assert_eq!(
            error,
            "scanner container exited with status Some(17); container cleanup also failed: runtime error: fake cleanup failure"
        );
        assert!(!report.checkpoint.cleanup_completed);
        assert!(report.checkpoint.resume_token().is_ok());
    }

    #[test]
    fn cleanup_pending_preserves_the_runtime_root_cause() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            stdout: vec![0_u8; 1_048_577],
            ..FakeRunBehavior::default()
        });
        runtime.set_fail_cleanup(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits {
            output_bytes: 1_048_576,
            ..ResourceLimits::default()
        };
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("cleanup-pending report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::CleanupPending);
        assert!(!report.checkpoint.cleanup_completed);
        assert_eq!(report.exit_code, None);
        let error = report.checkpoint.last_error.as_deref().unwrap();
        assert!(error.contains("scan coverage is incomplete"));
        assert!(error.contains("container cleanup also failed"));
        assert!(error.contains("fake cleanup failure"));
        assert!(report.checkpoint.resume_token().is_ok());

        let deadline = combined_cleanup_pending_error(
            Some("managed local engine launcher: engine exceeded its fixed runtime timeout"),
            None,
            "ownership-proven container removal exceeded its deadline",
        );
        assert!(deadline.contains("engine exceeded its fixed runtime timeout"));
        assert!(deadline.contains("container cleanup also failed"));
        assert!(deadline.contains("container removal exceeded its deadline"));
    }

    #[test]
    fn checkpoint_token_round_trips_without_secrets() {
        let checkpoint = ExecutionCheckpoint {
            case_id: "case-1".into(),
            scan_run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            engine_id: "scanner".into(),
            attempt: 1,
            stage: ExecutionStage::CapturedAwaitingAdapter,
            container_name: Some("ass-scanner-engine-run-1-a1".into()),
            scope_sha256: Some("abc".into()),
            artifact_ids: vec!["artifact-1".into()],
            cleanup_completed: true,
            last_error: None,
            runtime_command_provenance: None,
            runtime_provider: None,
            managed_network: None,
        };

        let token = checkpoint.resume_token().expect("token");
        let decoded = ExecutionCheckpoint::from_resume_token(&token).expect("decoded");
        assert_eq!(decoded.stage, ExecutionStage::CapturedAwaitingAdapter);
        assert_eq!(
            decoded.resume_action(),
            ResumeAction::AdaptCapturedArtifacts
        );
        assert!(!token.to_ascii_lowercase().contains("secret"));

        let mut legacy = serde_json::to_value(&checkpoint).expect("legacy checkpoint");
        legacy
            .as_object_mut()
            .expect("checkpoint object")
            .remove("managed_network");
        let legacy = ExecutionCheckpoint::from_resume_token(&legacy.to_string())
            .expect("pre-managed-network checkpoint remains readable");
        assert!(legacy.managed_network.is_none());
        assert!(legacy.runtime_command_provenance.is_none());
    }

    #[test]
    fn forged_cleanup_container_in_resume_token_is_rejected() {
        let token = serde_json::json!({
            "case_id": "case-1",
            "scan_run_id": "run-1",
            "engine_run_id": "engine-run-1",
            "engine_id": "scanner",
            "attempt": 1,
            "stage": "cleanup_pending",
            "container_name": "unrelated-production-container",
            "scope_sha256": "abc",
            "artifact_ids": [],
            "cleanup_completed": false,
            "last_error": null
        })
        .to_string();

        let error = ExecutionCheckpoint::from_resume_token(&token)
            .expect_err("forged container identity rejected");
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn cleanup_checkpoint_without_runtime_provenance_is_rejected() {
        let token = serde_json::json!({
            "case_id": "case-1",
            "scan_run_id": "run-1",
            "engine_run_id": "engine-run-1",
            "engine_id": "scanner",
            "attempt": 1,
            "stage": "cleanup_pending",
            "container_name": "ass-scanner-engine-run-1-a1",
            "scope_sha256": "abc",
            "artifact_ids": [],
            "cleanup_completed": false,
            "last_error": null,
            "managed_network": null
        })
        .to_string();

        let error = ExecutionCheckpoint::from_resume_token(&token)
            .expect_err("cleanup without runtime provenance rejected");
        assert!(error.to_string().contains("provider and provenance"));
    }
}
