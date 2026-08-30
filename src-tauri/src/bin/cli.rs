use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::artifact_store::{ArtifactContext, ArtifactStore};
use ai_security_scanner_lib::bootstrap::executor::{
    bootstrap_cleanup_obligation_summary, list_bootstrap_cleanup_obligations,
};
use ai_security_scanner_lib::case_service::{
    CaseExportFormat, CaseService, DurableExecutionReport, FindingGroupRequest,
    FindingUngroupRequest, FindingWorkflowRequest, ScanPlanRequest, ScopeApprovalRequest,
    SourceMutation,
};
use ai_security_scanner_lib::connectors::SnapshotConnectorRegistry;
use ai_security_scanner_lib::container_runtime::{
    CancellationToken, CleanupOutcome, ContainerPlanBuilder, ContainerRuntime, NetworkPolicy,
    OwnedContainerCleanupRequest, PinnedImage, ProcessContainerRuntime, ResourceLimits,
    RuntimeCommandProvenance, RuntimePreflight, RuntimeProvider, ScannerCredentialSet,
    cleanup_orphaned_credentials,
};
use ai_security_scanner_lib::demo::build_demo_case;
use ai_security_scanner_lib::discovery::run_connector;
use ai_security_scanner_lib::domain::{
    AssessmentActivity, CaseStatus, CreateCaseRequest, DataClass, DistributionMode, EngineManifest,
    EngineRunStatus, FindingStatus, ScanPermission, SourceConnectionStatus, SourceKind, new_id,
};
use ai_security_scanner_lib::error::{AppError, AppResult};
use ai_security_scanner_lib::export::{ExportOptions, RedactionProfile, verify_case_bundle};
use ai_security_scanner_lib::gateway_release::managed_egress_gateway_spec;
use ai_security_scanner_lib::managed_network::{
    ManagedGatewayQualification, ManagedNetworkCleanupOutcome, ManagedNetworkController,
    ManagedNetworkOwner, ManagedNetworkRegistry,
};
use ai_security_scanner_lib::managed_runtime::{
    ManagedRuntimeManager, ManagedStopMode, ManagedUninstallOptions,
};
use ai_security_scanner_lib::orchestrator::{ExecutionCheckpoint, ExecutionStage};
use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
#[cfg(test)]
use ai_security_scanner_lib::product_uninstall::ALL_DATA_CONFIRMATION;
use ai_security_scanner_lib::product_uninstall::{
    LocalProductUninstallBackend, PRODUCT_DATA_DIRECTORY_NAME, ProductUninstallMode,
    ProductUninstallRequest, ProductUninstallResultClass, coordinate_product_uninstall,
    finalize_all_data_root, prepare_fixed_product_data_root, stage_all_data_root_for_finalization,
};
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::runtime::detect_runtime;
use ai_security_scanner_lib::storage::Storage;
use chrono::{DateTime, Utc};
use clap::parser::ValueSource;
use clap::{ArgAction, Args, CommandFactory, FromArgMatches, Subcommand, ValueEnum};
use directories::{BaseDirs, ProjectDirs};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const MANAGED_RUNTIME_QUALIFICATION_ENGINE_ID: &str = "gitleaks";
// Keep the release-only artifact prefix compact. Podman's Windows client owns
// the `--cidfile` lifecycle and rejects otherwise valid extended-length paths
// once a long LocalApplicationData prefix, two UUIDs, and its CID filename are
// combined. One fresh engine-run UUID still gives every qualification an
// unpredictable, unique ownership namespace.
const MANAGED_RUNTIME_QUALIFICATION_CASE_ID: &str = "q";
const MANAGED_RUNTIME_QUALIFICATION_SCAN_RUN_ID: &str = "s";
const MANAGED_RUNTIME_QUALIFICATION_IMAGE: &str = concat!(
    "ghcr.io/teddashh/ai-security-scanner-engine-gitleaks@",
    "sha256:5b4538ca17201dba53fed7d5ea49f94cfd7815a4ce2a5b36cac408757ff349aa"
);
const MANAGED_RUNTIME_QUALIFICATION_REPORT: &str = "gitleaks.json";
const MAX_MANAGED_RUNTIME_QUALIFICATION_REPORT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, clap::Parser)]
#[command(name = "ai-security-scanner")]
#[command(about = "Local-first security assessment casework CLI")]
#[command(version)]
struct Cli {
    /// Override the local application data directory.
    #[arg(long, global = true, env = "AI_SECURITY_SCANNER_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Override the release-managed runtime bundle directory.
    #[arg(
        long,
        global = true,
        env = "AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE"
    )]
    managed_runtime_bundle: Option<PathBuf>,

    /// Emit compact machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Coordinate one exact installed-product uninstall choice before opening
    /// the case database or engine catalog. Intended for the package uninstaller.
    ProductUninstall(ProductUninstallArgs),
    /// Manage long-lived assessment cases.
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    /// Manage non-secret, read-only discovery source records and snapshots.
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    /// Record explicit human scope decisions.
    Scope {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// Record immutable human handling decisions without altering evidence.
    Finding {
        #[command(subcommand)]
        command: FindingCommand,
    },
    /// Plan and inspect scans. Planning never starts a scanner process.
    Scan {
        #[command(subcommand)]
        command: ScanCommand,
    },
    /// Create and verify explicit local exports.
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    /// Compare two terminal runs and persist the coverage-aware result.
    Compare(CompareArgs),
    /// Inspect scanner engine metadata and retrieve release-approved pinned images.
    Engine {
        #[command(subcommand)]
        command: EngineCommand,
    },
    /// Inspect and resolve exact, case-bound local runtime cleanup obligations.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    /// Inspect secret-free provider bootstrap cleanup obligations.
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommand,
    },
    /// Check local storage, catalog, and container runtime readiness.
    Doctor,
}

#[derive(Debug, Args)]
struct ProductUninstallArgs {
    #[arg(long, value_enum)]
    mode: ProductUninstallModeArg,
    /// Confirms that the package uninstaller, rather than this CLI, owns the
    /// visible choice and any data-loss prompt.
    #[arg(long)]
    non_interactive: bool,
    /// Required only for all-data and compared byte-for-byte with the fixed
    /// confirmation phrase printed by the package uninstaller.
    #[arg(long)]
    confirmation: Option<String>,
    /// Emit the fixed, privacy-safe package-coordinator envelope instead of
    /// the detailed retained-item record.
    #[arg(long, hide = true)]
    coordinator_envelope: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProductUninstallModeArg {
    AppOnly,
    #[value(alias = "verified-scan-tools")]
    ScanTools,
    AllData,
}

impl From<ProductUninstallModeArg> for ProductUninstallMode {
    fn from(value: ProductUninstallModeArg) -> Self {
        match value {
            ProductUninstallModeArg::AppOnly => Self::AppOnly,
            ProductUninstallModeArg::ScanTools => Self::ScanTools,
            ProductUninstallModeArg::AllData => Self::AllData,
        }
    }
}

#[derive(Debug, Subcommand)]
enum CaseCommand {
    Create(CreateCaseArgs),
    List,
    Show {
        case_id: String,
    },
    Selected,
    Select {
        case_id: String,
    },
    ClearSelection,
    Archive {
        case_id: String,
    },
    /// Inspect the exact artifact path before deleting a database record.
    DeletePlan {
        case_id: String,
    },
    /// Delete only the exact case database record; artifact files are retained.
    Delete {
        case_id: String,
        /// Must exactly match CASE_ID. This never deletes artifact files.
        #[arg(long)]
        confirm_case_id: String,
    },
    /// Delete the exact case artifact directory from a previously inspected plan.
    DeleteArtifacts {
        case_id: String,
        /// Must exactly match the backend-generated path from `case delete-plan`.
        #[arg(long)]
        exact_path: String,
        /// Must exactly equal `DELETE CASE_ID`.
        #[arg(long)]
        confirmation: String,
    },
    Events {
        case_id: String,
    },
    /// Create or select a clearly labeled synthetic demonstration case.
    SeedDemo,
}

#[derive(Debug, Args)]
struct CreateCaseArgs {
    #[arg(long)]
    title: String,
    /// Optional company or team label. It never gates local work.
    #[arg(long)]
    organization: Option<String>,
    #[arg(long, default_value = "unknown")]
    employee_range: String,
    /// Comma-separated values: general, pii, phi, pci, financial, secrets, other.
    #[arg(long, value_delimiter = ',')]
    data_class: Vec<String>,
    /// Comma-separated questionnaire intent only: configuration-assessment,
    /// local-artifact-analysis, low-impact-external-checks, active-external-vulnerability-tests.
    /// This never creates a scope grant.
    #[arg(long, value_enum, value_delimiter = ',')]
    requested_activity: Vec<AssessmentActivityArg>,
    /// Expected source kinds establish unknown coverage only; they do not connect anything.
    #[arg(long, value_enum, value_delimiter = ',')]
    source_kind: Vec<SourceKindArg>,
    #[arg(long)]
    notes: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AssessmentActivityArg {
    ConfigurationAssessment,
    LocalArtifactAnalysis,
    LowImpactExternalChecks,
    ActiveExternalVulnerabilityTests,
}

impl From<AssessmentActivityArg> for AssessmentActivity {
    fn from(value: AssessmentActivityArg) -> Self {
        match value {
            AssessmentActivityArg::ConfigurationAssessment => Self::ConfigurationAssessment,
            AssessmentActivityArg::LocalArtifactAnalysis => Self::LocalArtifactAnalysis,
            AssessmentActivityArg::LowImpactExternalChecks => Self::LowImpactExternalChecks,
            AssessmentActivityArg::ActiveExternalVulnerabilityTests => {
                Self::ActiveExternalVulnerabilityTests
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum SourceCommand {
    List {
        case_id: String,
    },
    /// Add a source or update a source that has no backend-owned artifact metadata.
    Upsert(SourceUpsertArgs),
    /// Parse a previously preserved, backend-owned connector artifact.
    Discover {
        case_id: String,
        source_id: String,
    },
    /// Preserve and parse one explicitly selected provider-output snapshot.
    DiscoverFromArtifact(SourceArtifactArgs),
    /// List bounded artifact parsers and whether the desktop can capture their provider pages live.
    Connectors,
}

#[derive(Debug, Subcommand)]
enum BootstrapCommand {
    /// List bounded cleanup summaries for one exact case.
    CleanupList { case_id: String },
    /// Show one cleanup summary without exposing resource IDs or endpoints.
    CleanupShow {
        case_id: String,
        operation_id: String,
    },
}

#[derive(Debug, Args)]
struct SourceUpsertArgs {
    #[arg(long)]
    case_id: String,
    /// Existing source ID. Omit to add a source.
    #[arg(long)]
    source_id: Option<String>,
    #[arg(long, value_enum)]
    kind: SourceKindArg,
    #[arg(long)]
    label: String,
    #[arg(long, value_enum, default_value_t = SourceStatusArg::NotConnected)]
    status: SourceStatusArg,
    /// Connected sources must remain read-only. Use `--read-only false` only for a disconnected draft.
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    read_only: bool,
}

#[derive(Debug, Args)]
struct SourceArtifactArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    source_id: String,
    /// Absolute path to a regular file explicitly selected by the user.
    #[arg(long)]
    snapshot: PathBuf,
    /// One parser profile listed by `source connectors` for this source kind.
    #[arg(long)]
    profile: String,
    /// Observation time in RFC 3339. Defaults to the ingestion time.
    #[arg(long)]
    observed_at: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceKindArg {
    AwsOrganization,
    AzureTenant,
    GcpOrganization,
    Microsoft365Tenant,
    Dns,
    CertificateTransparency,
    Billing,
    GitRepository,
    TerraformState,
    KubernetesCluster,
    ContainerRegistry,
    FileSystem,
    UserDeclared,
}

impl From<SourceKindArg> for SourceKind {
    fn from(value: SourceKindArg) -> Self {
        match value {
            SourceKindArg::AwsOrganization => Self::AwsOrganization,
            SourceKindArg::AzureTenant => Self::AzureTenant,
            SourceKindArg::GcpOrganization => Self::GcpOrganization,
            SourceKindArg::Microsoft365Tenant => Self::Microsoft365Tenant,
            SourceKindArg::Dns => Self::Dns,
            SourceKindArg::CertificateTransparency => Self::CertificateTransparency,
            SourceKindArg::Billing => Self::Billing,
            SourceKindArg::GitRepository => Self::GitRepository,
            SourceKindArg::TerraformState => Self::TerraformState,
            SourceKindArg::KubernetesCluster => Self::KubernetesCluster,
            SourceKindArg::ContainerRegistry => Self::ContainerRegistry,
            SourceKindArg::FileSystem => Self::FileSystem,
            SourceKindArg::UserDeclared => Self::UserDeclared,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceStatusArg {
    NotConnected,
    Connecting,
    Connected,
    NeedsReauthorization,
    Failed,
}

impl From<SourceStatusArg> for SourceConnectionStatus {
    fn from(value: SourceStatusArg) -> Self {
        match value {
            SourceStatusArg::NotConnected => Self::NotConnected,
            SourceStatusArg::Connecting => Self::Connecting,
            SourceStatusArg::Connected => Self::Connected,
            SourceStatusArg::NeedsReauthorization => Self::NeedsReauthorization,
            SourceStatusArg::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ScopeCommand {
    List { case_id: String },
    Approve(ScopeApproveArgs),
}

#[derive(Debug, Subcommand)]
enum FindingCommand {
    History { case_id: String },
    Groups { case_id: String },
    Group(FindingGroupArgs),
    Ungroup(FindingUngroupArgs),
    Update(FindingUpdateArgs),
}

#[derive(Debug, Args)]
struct FindingGroupArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    title: String,
    /// Two or more exact finding IDs. Grouping never merges or deletes them.
    /// The backend enforces two distinct members and the 100-member limit after
    /// comma-delimited values have been expanded.
    #[arg(long, value_delimiter = ',', required = true)]
    finding_id: Vec<String>,
    #[arg(long)]
    rationale: String,
    #[arg(long)]
    grouped_by: String,
}

#[derive(Debug, Args)]
struct FindingUngroupArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    group_id: String,
    #[arg(long)]
    removed_by: String,
    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct FindingUpdateArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    finding_id: String,
    #[arg(long, value_enum)]
    status: FindingStatusArg,
    #[arg(long)]
    decided_by: String,
    #[arg(long)]
    reason: String,
    /// RFC 3339 expiry; accepted only for false-positive decisions.
    #[arg(long)]
    expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FindingStatusArg {
    Unreviewed,
    ExpertReviewRequested,
    Confirmed,
    FalsePositive,
    RemediationReported,
    VerifiedResolved,
}

impl From<FindingStatusArg> for FindingStatus {
    fn from(value: FindingStatusArg) -> Self {
        match value {
            FindingStatusArg::Unreviewed => Self::Unreviewed,
            FindingStatusArg::ExpertReviewRequested => Self::ExpertReviewRequested,
            FindingStatusArg::Confirmed => Self::Confirmed,
            FindingStatusArg::FalsePositive => Self::FalsePositive,
            FindingStatusArg::RemediationReported => Self::RemediationReported,
            FindingStatusArg::VerifiedResolved => Self::VerifiedResolved,
        }
    }
}

#[derive(Debug, Args)]
struct ScopeApproveArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    asset_id: String,
    /// Comma-separated, explicit permissions for this asset.
    #[arg(long, value_enum, value_delimiter = ',', required = true)]
    permission: Vec<PermissionArg>,
    /// Human or accountable local identity recording the decision.
    #[arg(long)]
    confirmed_by: String,
    /// RFC 3339 instant. Omit only when the authorization is intentionally open-ended.
    #[arg(long)]
    expires_at: Option<String>,
    /// Required for low-impact or active external activity.
    #[arg(long)]
    authorization_reference: Option<String>,
    #[arg(long)]
    notes: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PermissionArg {
    InventoryRead,
    ConfigurationRead,
    LocalArtifactRead,
    PassiveExternalDiscovery,
    LowImpactExternalConnection,
    ActiveExternalTesting,
}

impl From<PermissionArg> for ScanPermission {
    fn from(value: PermissionArg) -> Self {
        match value {
            PermissionArg::InventoryRead => Self::InventoryRead,
            PermissionArg::ConfigurationRead => Self::ConfigurationRead,
            PermissionArg::LocalArtifactRead => Self::LocalArtifactRead,
            PermissionArg::PassiveExternalDiscovery => Self::PassiveExternalDiscovery,
            PermissionArg::LowImpactExternalConnection => Self::LowImpactExternalConnection,
            PermissionArg::ActiveExternalTesting => Self::ActiveExternalTesting,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ScanCommand {
    /// Persist an immutable, credential-free dispatch plan. Does not execute it.
    Plan(ScanPlanArgs),
    /// Request execution without accepting credentials on the command line.
    Start(ScanTransitionArgs),
    /// Persist a new plan tied to a terminal baseline. Does not execute it.
    RescanPlan(RescanPlanArgs),
    Status(ScanStatusArgs),
    Pause(ScanTransitionArgs),
    Resume(ScanTransitionArgs),
    Cancel(ScanTransitionArgs),
}

#[derive(Debug, Args)]
struct ScanPlanArgs {
    #[arg(long)]
    case_id: String,
    /// Exact engine IDs. Omit to automatically plan every catalog engine
    /// applicable to the case assets and effective scope grants.
    #[arg(long, value_delimiter = ',')]
    engine: Vec<String>,
}

#[derive(Debug, Args)]
struct RescanPlanArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    baseline_run_id: String,
    #[arg(long, value_delimiter = ',')]
    engine: Vec<String>,
}

#[derive(Debug, Args)]
struct ScanStatusArgs {
    #[arg(long)]
    case_id: String,
    /// Omit to inspect all runs in the case.
    #[arg(long)]
    run_id: Option<String>,
}

#[derive(Debug, Args)]
struct ScanTransitionArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    run_id: String,
}

#[derive(Debug, Subcommand)]
enum ExportCommand {
    Create(ExportCreateArgs),
    Verify {
        #[arg(long)]
        case_id: Option<String>,
        #[arg(long)]
        export_id: Option<String>,
        /// Verify a received signed `.case.tar.gz` without a local case record.
        /// Its embedded signer key remains self-asserted unless pinned elsewhere.
        #[arg(long)]
        path: Option<PathBuf>,
    },
    Identity {
        #[command(subcommand)]
        command: ExportIdentityCommand,
    },
    Formats,
}

#[derive(Debug, Subcommand)]
enum ExportIdentityCommand {
    /// Show or establish the durable public identity for local signed exports.
    Show,
    /// Replace a private key only after its exact recorded key ID is confirmed lost.
    RotateAfterKeyLoss {
        #[arg(long)]
        acknowledge_lost_key_id: String,
    },
}

#[derive(Debug, Args)]
struct ExportCreateArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    run_id: String,
    #[arg(long, value_enum)]
    format: ExportFormatArg,
    /// Explicit local output filename. Existing files are never overwritten.
    #[arg(long)]
    destination: PathBuf,
    #[arg(long, value_enum, default_value_t = RedactionArg::Standard)]
    redaction: RedactionArg,
    /// Bundle only. Raw artifacts may contain sensitive provider or target data.
    #[arg(long, requires = "acknowledge_sensitive_raw_artifacts")]
    include_raw_artifacts: bool,
    /// Explicit acknowledgement required with --include-raw-artifacts.
    #[arg(long)]
    acknowledge_sensitive_raw_artifacts: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExportFormatArg {
    CaseBundle,
    Json,
    FrameworkReport,
    Ocsf,
    Oscal,
    Html,
}

impl From<ExportFormatArg> for CaseExportFormat {
    fn from(value: ExportFormatArg) -> Self {
        match value {
            ExportFormatArg::CaseBundle => Self::CaseBundle,
            ExportFormatArg::Json => Self::CanonicalJson,
            ExportFormatArg::FrameworkReport => Self::FrameworkReport,
            ExportFormatArg::Ocsf => Self::OcsfJson,
            ExportFormatArg::Oscal => Self::OscalJson,
            ExportFormatArg::Html => Self::Html,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RedactionArg {
    Standard,
    None,
}

impl From<RedactionArg> for RedactionProfile {
    fn from(value: RedactionArg) -> Self {
        match value {
            RedactionArg::Standard => Self::Standard,
            RedactionArg::None => Self::None,
        }
    }
}

#[derive(Debug, Args)]
struct CompareArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    baseline_run_id: String,
    #[arg(long)]
    current_run_id: String,
}

#[derive(Debug, Subcommand)]
enum EngineCommand {
    List,
    /// Backward-compatible manifest inspection command.
    Show {
        engine_id: String,
    },
    Inspect {
        engine_id: String,
    },
    /// Retrieve one immutable image only when its manifest is release-approved.
    Install {
        engine_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    /// Manage the app-private, release-pinned local runtime.
    Managed {
        #[command(subcommand)]
        command: ManagedRuntimeCliCommand,
    },
    /// Inspect runtime health and outstanding cleanup records without mutation.
    Inspect(RuntimeInspectArgs),
    /// Show exact runtime containers and managed networks requiring cleanup for one run.
    CleanupPlan {
        #[arg(long)]
        case_id: String,
        #[arg(long)]
        run_id: String,
    },
    /// Reconcile only resources named by stored, provenance-bound cleanup checkpoints.
    Cleanup {
        #[arg(long)]
        case_id: String,
        #[arg(long)]
        run_id: String,
        /// Must exactly match RUN_ID.
        #[arg(long)]
        confirm_run_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ManagedRuntimeCliCommand {
    /// Inspect the verified private runtime and its rootless machine.
    Status,
    /// Verify and install the release-pinned runtime payload.
    Install,
    /// Install if needed and start the owned rootless machine.
    Start,
    /// Stop the owned machine; active engine containers fail closed by default.
    Stop {
        /// Stop even when owned engine containers are still running.
        #[arg(long)]
        force: bool,
    },
    /// Install, prove, and start the runtime bundled with this app version.
    Update,
    /// Run the release-fixed, network-disabled managed-container qualification.
    Qualify,
    /// Prove the pinned gateway is reachable without sending an upstream request.
    QualifyEgress,
    /// Remove only this app's exact managed machine and private payload.
    Uninstall {
        /// Stop even when owned engine containers are still running.
        #[arg(long)]
        force: bool,
        /// Also remove the exact verified machine-image cache file.
        #[arg(long)]
        purge_image_cache: bool,
    },
}

#[derive(Debug, Args)]
struct RuntimeInspectArgs {
    /// Limit cleanup inspection to one case.
    #[arg(long)]
    case_id: Option<String>,
    /// Limit cleanup inspection to one run. Requires --case-id.
    #[arg(long, requires = "case_id")]
    run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CleanupObligation {
    case_id: String,
    scan_run_id: String,
    engine_run_id: String,
    engine_id: String,
    attempt: u32,
    container_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct InvalidCheckpointRecord {
    case_id: String,
    scan_run_id: String,
    engine_run_id: String,
    explanation: &'static str,
}

#[derive(Debug, Default, Serialize)]
struct CleanupInspection {
    pending: Vec<CleanupObligation>,
    invalid_checkpoint_records: Vec<InvalidCheckpointRecord>,
}

#[derive(Debug)]
struct ExactRuntimeCleanup {
    container: CleanupOutcome,
    managed_network: Option<ManagedNetworkCleanupOutcome>,
    orphan_credentials_removed: usize,
}

#[derive(Debug)]
struct ExactRuntimeCleanupFailure {
    container: Option<CleanupOutcome>,
    error: AppError,
}

#[tokio::main]
async fn main() {
    let matches = Cli::command().get_matches();
    let option_sources = GlobalOptionSources {
        data_dir: matches.value_source("data_dir"),
        managed_runtime_bundle: matches.value_source("managed_runtime_bundle"),
    };
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    let json_errors = cli.json;
    match execute(cli, option_sources).await {
        Ok(0) => {}
        Ok(exit_code) => std::process::exit(i32::from(exit_code)),
        Err(error) => {
            if json_errors {
                eprintln!("{}", json!({ "error": error.to_string() }));
            } else {
                eprintln!("error: {error}");
            }
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct GlobalOptionSources {
    data_dir: Option<ValueSource>,
    managed_runtime_bundle: Option<ValueSource>,
}

#[derive(Debug, Serialize)]
struct ProductUninstallCoordinatorEnvelope {
    schema_version: &'static str,
    mode: ProductUninstallMode,
    result_class: ProductUninstallResultClass,
    exit_code: u8,
    retained_item_count: usize,
    retained_classes: Vec<&'static str>,
    terminal: &'static str,
}

impl GlobalOptionSources {
    fn data_dir_was_explicit(self) -> bool {
        self.data_dir == Some(ValueSource::CommandLine)
    }

    fn managed_runtime_bundle_was_explicit(self) -> bool {
        self.managed_runtime_bundle == Some(ValueSource::CommandLine)
    }
}

async fn execute(cli: Cli, option_sources: GlobalOptionSources) -> AppResult<u8> {
    if let Command::ProductUninstall(args) = &cli.command {
        return execute_product_uninstall_early(&cli, args, option_sources);
    }

    let managed_runtime_bundle = cli.managed_runtime_bundle;
    let data_dir = resolve_data_dir(cli.data_dir)?;
    fs::create_dir_all(&data_dir)?;
    let _exclusive_lease = command_requires_exclusive_data_directory(&cli.command)
        .then(|| DataDirectoryExclusiveLease::acquire(&data_dir))
        .transpose()?;
    let artifact_root = data_dir.join("artifacts");
    fs::create_dir_all(&artifact_root)?;

    let storage = Storage::open(data_dir.join("casework.db"))?;
    let engines = EngineRegistry::load_builtin()?;
    let adapters = builtin_adapter_registry()?;
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        &artifact_root,
        data_dir.join("integrity-signing-key"),
    );

    match cli.command {
        Command::ProductUninstall(_) => unreachable!("product uninstall is early-dispatched"),
        Command::Case { command } => {
            execute_case(command, &storage, &service, cli.json)?;
        }
        Command::Source { command } => {
            execute_source(command, &storage, &service, &artifact_root, cli.json)?;
        }
        Command::Scope { command } => execute_scope(command, &service, cli.json)?,
        Command::Finding { command } => execute_finding(command, &service, cli.json)?,
        Command::Scan { command } => execute_scan(command, &service, cli.json)?,
        Command::Export { command } => execute_export(command, &service, cli.json)?,
        Command::Compare(args) => {
            let comparison = service.compare_and_persist(
                &args.case_id,
                &args.baseline_run_id,
                &args.current_run_id,
            )?;
            print_value(&comparison, cli.json)?;
        }
        Command::Engine { command } => {
            execute_engine(command, &engines, &adapters, cli.json)?;
        }
        Command::Runtime { command } => {
            execute_runtime(
                command,
                &service,
                &engines,
                &data_dir,
                &artifact_root,
                managed_runtime_bundle.as_deref(),
                cli.json,
            )
            .await?;
        }
        Command::Bootstrap { command } => {
            service.show_case(match &command {
                BootstrapCommand::CleanupList { case_id }
                | BootstrapCommand::CleanupShow { case_id, .. } => case_id,
            })?;
            match command {
                BootstrapCommand::CleanupList { case_id } => {
                    let root = artifact_root.join(&case_id).join("provider-bootstrap");
                    print_value(
                        &list_bootstrap_cleanup_obligations(&root, &case_id)?,
                        cli.json,
                    )?;
                }
                BootstrapCommand::CleanupShow {
                    case_id,
                    operation_id,
                } => {
                    let path = artifact_root
                        .join(&case_id)
                        .join("provider-bootstrap")
                        .join(format!("cleanup-{operation_id}.json"));
                    print_value(
                        &bootstrap_cleanup_obligation_summary(&path, &case_id, &operation_id)?,
                        cli.json,
                    )?;
                }
            }
        }
        Command::Doctor => {
            let managed_runtime =
                inspect_managed_runtime(&data_dir, managed_runtime_bundle.as_deref()).await;
            let compatibility_runtime = detect_runtime().await;
            let cleanup = inspect_cleanup(&service.list_cases()?, &service, None, None)?;
            let report = json!({
                "product": "ai-security-scanner",
                "product_version": env!("CARGO_PKG_VERSION"),
                "data_dir": data_dir,
                "database": storage.path(),
                "runtime": {
                    "preferred_provider": "managed_local",
                    "managed_local": managed_runtime,
                    "compatibility": compatibility_runtime,
                },
                "engine_manifests": engines.manifests().len(),
                "release_approved_engines": engines.manifests().iter()
                    .filter(|manifest| manifest.release_blocker().is_none())
                    .count(),
                "pending_runtime_cleanup": cleanup.pending.len(),
                "invalid_checkpoint_records": cleanup.invalid_checkpoint_records.len(),
                "notice": "Runtime availability and zero findings do not establish assessment coverage.",
            });
            print_value(&report, cli.json)?;
        }
    }

    Ok(0)
}

fn validate_product_uninstall_option_sources(option_sources: GlobalOptionSources) -> AppResult<()> {
    if option_sources.data_dir_was_explicit() {
        return Err(AppError::NotAuthorized(
            "product-uninstall refuses an explicit global --data-dir override".into(),
        ));
    }
    if option_sources.managed_runtime_bundle_was_explicit() {
        return Err(AppError::NotAuthorized(
            "product-uninstall refuses an explicit managed-runtime bundle override".into(),
        ));
    }
    Ok(())
}

fn execute_product_uninstall_early(
    cli: &Cli,
    args: &ProductUninstallArgs,
    option_sources: GlobalOptionSources,
) -> AppResult<u8> {
    // Environment-backed overrides are intentionally ignored for this one
    // installed-product command. They are useful for ordinary CLI casework,
    // but must not redirect or block the package uninstaller. Explicit command
    // line overrides remain a contract error.
    validate_product_uninstall_option_sources(option_sources)?;
    if args.coordinator_envelope && !cli.json {
        return Err(AppError::InvalidRequest(
            "--coordinator-envelope requires --json".into(),
        ));
    }
    let request = ProductUninstallRequest {
        mode: args.mode.into(),
        non_interactive: args.non_interactive,
        confirmation: args.confirmation.clone(),
    };
    // Confirmation and mode validation happen before a lock file is created or
    // any runtime inventory can issue a command.
    request.validate()?;

    let local_data_root = BaseDirs::new()
        .map(|directories| directories.data_local_dir().to_path_buf())
        .ok_or_else(|| {
            AppError::Internal("could not determine the platform local-data directory".into())
        })?;
    let data_root = local_data_root.join(PRODUCT_DATA_DIRECTORY_NAME);
    let (data_existed_before, data_root_guard) =
        prepare_fixed_product_data_root(&data_root, &local_data_root)?;
    // Always lease the canonical root, including the absent-root case. A
    // desktop that races to create or acquire it wins or loses the same exact
    // lease before runtime inventory begins; absence is never treated as a
    // concurrency exemption.
    let exclusive_lease = DataDirectoryExclusiveLease::acquire(&data_root)?;
    let mut backend = LocalProductUninstallBackend::new(data_root.clone());
    let mut result = coordinate_product_uninstall(&request, &mut backend)?;
    drop(backend);
    drop(data_root_guard);
    let may_finalize = result.result_class != ProductUninstallResultClass::ContactNotStopped
        && (request.mode == ProductUninstallMode::AllData || !data_existed_before);
    let staged_data_root = if may_finalize {
        if !result.canonical_data_root_can_be_staged() {
            result.record_finalization_retained(
                "product_data",
                "ambiguous_or_unremoved_product_state_preserved",
            );
            None
        } else {
            match stage_all_data_root_for_finalization(&data_root, &exclusive_lease) {
                Ok(staged) => Some(staged),
                Err(_) => {
                    result.record_finalization_retained(
                        "product_data",
                        "product_data_root_staging_incomplete",
                    );
                    None
                }
            }
        }
    } else {
        None
    };
    drop(exclusive_lease);

    if let Some(staged_data_root) = staged_data_root {
        for retained in finalize_all_data_root(&staged_data_root) {
            result.record_finalization_retained(retained.item_class, retained.reason_code);
        }
    }
    if args.coordinator_envelope {
        let retained_classes = result
            .retained_items
            .iter()
            .map(|item| item.item_class)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let envelope = ProductUninstallCoordinatorEnvelope {
            schema_version: result.schema_version,
            mode: result.mode,
            result_class: result.result_class,
            exit_code: result.exit_code,
            retained_item_count: result.retained_items.len(),
            retained_classes,
            terminal: "complete",
        };
        // Deliberately no trailing newline: NSIS compares the complete bounded
        // envelope and never mistakes a truncated detailed record for success.
        print!("{}", serde_json::to_string(&envelope)?);
    } else if cli.json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    Ok(result.exit_code)
}

fn command_requires_exclusive_data_directory(command: &Command) -> bool {
    match command {
        // ProductUninstall is early-dispatched and acquires the same lease
        // before database/catalog initialization.
        Command::ProductUninstall(_) => false,
        Command::Case {
            command: CaseCommand::Delete { .. } | CaseCommand::DeleteArtifacts { .. },
        } => true,
        Command::Runtime {
            command: RuntimeCommand::Cleanup { .. },
        } => true,
        Command::Runtime {
            command: RuntimeCommand::Managed { command },
        } => !matches!(command, ManagedRuntimeCliCommand::Status),
        Command::Export {
            command: ExportCommand::Identity { .. },
        } => true,
        _ => false,
    }
}

fn execute_case(
    command: CaseCommand,
    storage: &Storage,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        CaseCommand::Create(args) => {
            let request = CreateCaseRequest {
                title: args.title,
                organization_name: args.organization.unwrap_or_default(),
                employee_range: args.employee_range,
                assessment_intent: None,
                ai_generated_artifact: Default::default(),
                data_classes: args
                    .data_class
                    .iter()
                    .map(|value| parse_data_class(value))
                    .collect::<AppResult<Vec<_>>>()?,
                requested_activities: args
                    .requested_activity
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                source_kinds: args.source_kind.into_iter().map(Into::into).collect(),
                not_applicable_source_kinds: vec![],
                declared_assets: vec![],
                notes: args.notes,
            };
            print_value(&service.create_case(&request)?, json_output)?;
        }
        CaseCommand::List => print_value(&service.list_cases()?, json_output)?,
        CaseCommand::Show { case_id } => {
            print_value(&service.show_case(&case_id)?, json_output)?;
        }
        CaseCommand::Selected => print_value(&service.selected_case()?, json_output)?,
        CaseCommand::Select { case_id } => {
            print_value(&service.select_case(&case_id)?, json_output)?;
        }
        CaseCommand::ClearSelection => {
            service.clear_selection()?;
            print_value(&json!({ "selected_case_id": null }), json_output)?;
        }
        CaseCommand::Archive { case_id } => {
            print_value(&service.archive_case(&case_id)?, json_output)?;
        }
        CaseCommand::DeletePlan { case_id } => {
            service.show_case(&case_id)?;
            let plan = service.artifact_deletion_plan(&case_id)?;
            print_value(
                &json!({
                    "database_record": case_id,
                    "artifacts": plan,
                    "action": "No deletion was performed.",
                }),
                json_output,
            )?;
        }
        CaseCommand::Delete {
            case_id,
            confirm_case_id,
        } => {
            if confirm_case_id != case_id {
                return Err(AppError::NotAuthorized(
                    "--confirm-case-id must exactly match the case being deleted".into(),
                ));
            }
            let result = service.delete_case(&case_id)?;
            print_value(
                &json!({
                    "result": result,
                    "artifact_action": "retained",
                    "notice": "Only the exact SQLite case record and its event rows were deleted. Artifact files were not traversed or removed.",
                }),
                json_output,
            )?;
        }
        CaseCommand::DeleteArtifacts {
            case_id,
            exact_path,
            confirmation,
        } => {
            let result = service.delete_case_artifacts(&case_id, &exact_path, &confirmation)?;
            print_value(
                &json!({
                    "result": result,
                    "notice": "Only the exact backend-generated case artifact directory was removed. The operation is not recoverable.",
                }),
                json_output,
            )?;
        }
        CaseCommand::Events { case_id } => {
            service.show_case(&case_id)?;
            print_value(&storage.list_case_events(&case_id)?, json_output)?;
        }
        CaseCommand::SeedDemo => {
            let case = if let Some(summary) = storage
                .list_cases()?
                .into_iter()
                .find(|summary| summary.is_demo)
            {
                storage.get_case(&summary.id)?
            } else {
                let mut case = build_demo_case();
                storage.save_case(&mut case, "case.demo_seeded.cli")?;
                case
            };
            storage.set_selected_case(Some(&case.id))?;
            print_value(&case, json_output)?;
        }
    }
    Ok(())
}

fn execute_source(
    command: SourceCommand,
    storage: &Storage,
    service: &CaseService<'_>,
    artifact_root: &Path,
    json_output: bool,
) -> AppResult<()> {
    match command {
        SourceCommand::List { case_id } => {
            print_value(&service.show_case(&case_id)?.data_sources, json_output)?;
        }
        SourceCommand::Upsert(args) => {
            if let Some(source_id) = args.source_id.as_deref() {
                let case = service.show_case(&args.case_id)?;
                let source = case
                    .data_sources
                    .iter()
                    .find(|source| source.id == source_id)
                    .ok_or_else(|| {
                        AppError::InvalidRequest(format!("data source not found: {source_id}"))
                    })?;
                if !source.metadata.is_empty() {
                    return Err(AppError::NotAvailable(
                        "CLI source updates are disabled once backend-owned artifact coordinates exist; this prevents accidental loss of preserved discovery provenance"
                            .into(),
                    ));
                }
            }
            let source = service.upsert_source(
                &args.case_id,
                SourceMutation {
                    id: args.source_id,
                    kind: args.kind.into(),
                    label: args.label,
                    status: args.status.into(),
                    read_only: args.read_only,
                    metadata: BTreeMap::new(),
                },
            )?;
            print_value(&source, json_output)?;
        }
        SourceCommand::Discover { case_id, source_id } => {
            let case = service.show_case(&case_id)?;
            let source = case
                .data_sources
                .iter()
                .find(|source| source.id == source_id)
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!("data source not found: {source_id}"))
                })?;
            let connector_root = case_connector_artifact_root(artifact_root, &case_id)?;
            let registry = SnapshotConnectorRegistry::new(connector_root)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let connector = registry.connector_for(&source.kind);
            let batch = run_connector(&connector, source)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let report = service.reconcile_discovery_batch(&case_id, &batch)?;
            print_value(
                &json!({
                    "report": report,
                    "live_discovery": false,
                    "scope_granted": false,
                    "notice": "The bounded connector parsed already-preserved evidence without using a credential. Provider-native capture requires a live in-process desktop authorization; discovered assets remain unauthorized candidates until a human records scope.",
                }),
                json_output,
            )?;
        }
        SourceCommand::DiscoverFromArtifact(args) => {
            let mut case = service.show_case(&args.case_id)?;
            if case.is_demo {
                return Err(AppError::NotAuthorized(
                    "synthetic demo cases are immutable and cannot ingest source artifacts".into(),
                ));
            }
            if case.status == CaseStatus::Archived {
                return Err(AppError::InvalidRequest(
                    "archived cases cannot ingest source artifacts".into(),
                ));
            }
            let source = case
                .data_sources
                .iter_mut()
                .find(|source| source.id == args.source_id)
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!("data source not found: {}", args.source_id))
                })?;
            if source.status != SourceConnectionStatus::Connected || !source.read_only {
                return Err(AppError::NotAuthorized(
                    "snapshot discovery requires a connected source explicitly recorded as read-only"
                        .into(),
                ));
            }
            let connector_root = case_connector_artifact_root(artifact_root, &args.case_id)?;
            let registry = SnapshotConnectorRegistry::new(connector_root)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let observed_at = args
                .observed_at
                .as_deref()
                .map(parse_rfc3339)
                .transpose()?
                .unwrap_or_else(Utc::now);
            let reference = registry
                .ingest_selected_snapshot(&source.kind, &args.snapshot, &args.profile, observed_at)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            reference
                .clone()
                .insert_into(source)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            case.touch();
            storage.save_case(&mut case, "source.snapshot_ingested.cli")?;

            let source = case
                .data_sources
                .iter()
                .find(|source| source.id == args.source_id)
                .ok_or_else(|| AppError::Internal("ingested source disappeared".into()))?;
            let connector = registry.connector_for(&source.kind);
            let batch = run_connector(&connector, source)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let report = service.reconcile_discovery_batch(&args.case_id, &batch)?;
            print_value(
                &json!({
                    "artifact": reference,
                    "report": report,
                    "live_discovery": false,
                    "scope_granted": false,
                    "notice": "The selected file was copied into the private backend artifact store and parsed without a network request. Its contents were not printed. Discovered assets remain unauthorized candidates.",
                }),
                json_output,
            )?;
        }
        SourceCommand::Connectors => {
            // Listing static connector descriptors never ingests or reads an
            // artifact, so it does not need to create a synthetic case root.
            let registry = SnapshotConnectorRegistry::new(artifact_root)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let descriptors = registry
                .descriptors()
                .into_iter()
                .map(|descriptor| {
                    json!({
                        "connector_id": descriptor.connector_id,
                        "source_kind": descriptor.source_kind,
                        "parser_profiles": descriptor.parser_profiles,
                        "live_discovery": descriptor.live_discovery,
                    })
                })
                .collect::<Vec<_>>();
            print_value(&descriptors, json_output)?;
        }
    }
    Ok(())
}

fn execute_scope(
    command: ScopeCommand,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        ScopeCommand::List { case_id } => {
            let case = service.show_case(&case_id)?;
            print_value(
                &json!({
                    "case_id": case.id,
                    "scope_grants": case.scope_grants,
                    "coverage": case.coverage,
                }),
                json_output,
            )?;
        }
        ScopeCommand::Approve(args) => {
            let expires_at = args.expires_at.as_deref().map(parse_rfc3339).transpose()?;
            let grants = service.approve_scope(
                &args.case_id,
                ScopeApprovalRequest {
                    asset_id: args.asset_id,
                    permissions: args.permission.into_iter().map(Into::into).collect(),
                    confirmed_by: args.confirmed_by,
                    expires_at,
                    authorization_reference: args.authorization_reference,
                    notes: args.notes,
                    external_scope: None,
                },
            )?;
            print_value(
                &json!({
                    "grants": grants,
                    "notice": "This records the supplied human authorization; the CLI did not infer ownership or widen scope.",
                }),
                json_output,
            )?;
        }
    }
    Ok(())
}

fn execute_finding(
    command: FindingCommand,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        FindingCommand::History { case_id } => {
            let case = service.show_case(&case_id)?;
            print_value(&case.finding_workflow_events, json_output)?;
        }
        FindingCommand::Groups { case_id } => {
            let case = service.show_case(&case_id)?;
            print_value(
                &json!({
                    "active": case.finding_groups,
                    "history": case.finding_group_events,
                    "notice": "Groups are presentation metadata; every canonical finding and evidence record remains independent.",
                }),
                json_output,
            )?;
        }
        FindingCommand::Group(args) => {
            let case = service.group_findings(
                &args.case_id,
                FindingGroupRequest {
                    title: args.title,
                    finding_ids: args.finding_id,
                    rationale: args.rationale,
                    grouped_by: args.grouped_by,
                },
            )?;
            print_value(&case, json_output)?;
        }
        FindingCommand::Ungroup(args) => {
            let case = service.ungroup_findings(
                &args.case_id,
                FindingUngroupRequest {
                    group_id: args.group_id,
                    removed_by: args.removed_by,
                    reason: args.reason,
                },
            )?;
            print_value(&case, json_output)?;
        }
        FindingCommand::Update(args) => {
            let expires_at = args.expires_at.as_deref().map(parse_rfc3339).transpose()?;
            let case = service.update_finding_workflow(
                &args.case_id,
                FindingWorkflowRequest {
                    finding_id: args.finding_id,
                    status: args.status.into(),
                    decided_by: args.decided_by,
                    reason: args.reason,
                    expires_at,
                },
            )?;
            print_value(&case, json_output)?;
        }
    }
    Ok(())
}

fn execute_scan(
    command: ScanCommand,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        ScanCommand::Plan(args) => {
            let plan = service.plan_scan(
                &args.case_id,
                ScanPlanRequest {
                    engine_ids: args.engine,
                },
            )?;
            print_value(
                &json!({
                    "plan": plan,
                    "execution_state": "not_started",
                    "notice": "This command persisted a credential-free plan only. It did not start a container or contact any asset. Unavailable engines are recorded as not_executed.",
                }),
                json_output,
            )?;
        }
        ScanCommand::Start(args) => {
            let case = service.show_case(&args.case_id)?;
            let run = case
                .scan_runs
                .iter()
                .find(|run| run.id == args.run_id)
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!("scan run not found: {}", args.run_id))
                })?;
            if run
                .engine_runs
                .iter()
                .all(|engine_run| engine_run.status == EngineRunStatus::NotExecuted)
            {
                return Err(AppError::NotAvailable(
                    "every engine in this run is not_executed; inspect engine readiness and create a new plan after the catalog is release-approved"
                        .into(),
                ));
            }
            return Err(out_of_process_scan_control_error(
                "start",
                &args.case_id,
                &args.run_id,
            ));
        }
        ScanCommand::RescanPlan(args) => {
            let plan = service.plan_rescan(
                &args.case_id,
                &args.baseline_run_id,
                ScanPlanRequest {
                    engine_ids: args.engine,
                },
            )?;
            print_value(
                &json!({
                    "rescan": plan,
                    "execution_state": "not_started",
                    "notice": "This command persisted a rescan plan only. No scanner process was started.",
                }),
                json_output,
            )?;
        }
        ScanCommand::Status(args) => {
            let case = service.show_case(&args.case_id)?;
            let runs = match args.run_id.as_deref() {
                Some(run_id) => vec![
                    case.scan_runs
                        .iter()
                        .find(|run| run.id == run_id)
                        .cloned()
                        .ok_or_else(|| {
                            AppError::InvalidRequest(format!("scan run not found: {run_id}"))
                        })?,
                ],
                None => case.scan_runs.clone(),
            };
            print_value(
                &json!({
                    "case_id": case.id,
                    "case_status": case.status,
                    "runs": runs,
                    "coverage": case.coverage,
                    "notice": "Engine status and finding count do not replace the coverage ledger. not_executed means no scanner result exists for that engine run.",
                }),
                json_output,
            )?;
        }
        ScanCommand::Pause(args) => {
            return Err(out_of_process_scan_control_error(
                "pause",
                &args.case_id,
                &args.run_id,
            ));
        }
        ScanCommand::Resume(args) => {
            return Err(out_of_process_scan_control_error(
                "resume",
                &args.case_id,
                &args.run_id,
            ));
        }
        ScanCommand::Cancel(args) => {
            return Err(out_of_process_scan_control_error(
                "cancel",
                &args.case_id,
                &args.run_id,
            ));
        }
    }
    Ok(())
}

fn out_of_process_scan_control_error(action: &str, case_id: &str, run_id: &str) -> AppError {
    AppError::NotAvailable(format!(
        "scan {action} was not applied to case {case_id} run {run_id}: the standalone CLI cannot coordinate the desktop's live worker or capability session; use the desktop scan controls"
    ))
}

fn execute_export(
    command: ExportCommand,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        ExportCommand::Create(args) => {
            if args.include_raw_artifacts && !matches!(args.format, ExportFormatArg::CaseBundle) {
                return Err(AppError::InvalidRequest(
                    "raw artifacts can only be included in the signed case bundle format".into(),
                ));
            }
            let export = service.export_case(
                &args.case_id,
                &args.run_id,
                args.format.into(),
                &args.destination,
                ExportOptions {
                    redaction: args.redaction.into(),
                    include_raw_artifacts: args.include_raw_artifacts,
                },
            )?;
            print_value(&export, json_output)?;
        }
        ExportCommand::Verify {
            case_id,
            export_id,
            path,
        } => match (case_id, export_id, path) {
            (Some(case_id), Some(export_id), None) => print_value(
                &service.verify_stored_export(&case_id, &export_id)?,
                json_output,
            )?,
            (None, None, Some(path)) => print_value(&verify_case_bundle(path)?, json_output)?,
            _ => {
                return Err(AppError::InvalidRequest(
                    "export verify requires either --path or both --case-id and --export-id".into(),
                ));
            }
        },
        ExportCommand::Identity { command } => match command {
            ExportIdentityCommand::Show => {
                print_value(&service.ensure_export_signing_identity()?, json_output)?;
            }
            ExportIdentityCommand::RotateAfterKeyLoss {
                acknowledge_lost_key_id,
            } => {
                print_value(
                    &service.rotate_export_signing_identity_after_confirmed_loss(
                        &acknowledge_lost_key_id,
                    )?,
                    json_output,
                )?;
            }
        },
        ExportCommand::Formats => print_value(
            &json!([
                { "id": "case-bundle", "signed": true, "portable": true },
                { "id": "json", "signed": false, "schema": "canonical" },
                { "id": "framework-report", "signed": false, "schema": "master NIST CSF, ISO/IEC 27001, and AIDEFEND relationship report with incomplete and unknown coverage" },
                { "id": "ocsf", "signed": false, "schema": "OCSF detection findings" },
                { "id": "oscal", "signed": false, "schema": "OSCAL assessment results; coordinates only" },
                { "id": "html", "signed": false, "schema": "local human-readable report" }
            ]),
            json_output,
        )?,
    }
    Ok(())
}

fn execute_engine(
    command: EngineCommand,
    engines: &EngineRegistry,
    adapters: &ai_security_scanner_lib::adapter::AdapterRegistry,
    json_output: bool,
) -> AppResult<()> {
    match command {
        EngineCommand::List => {
            let values = engines
                .manifests()
                .iter()
                .map(|manifest| engine_inspection(manifest, adapters))
                .collect::<Vec<_>>();
            print_value(&values, json_output)?;
        }
        EngineCommand::Show { engine_id } | EngineCommand::Inspect { engine_id } => {
            let manifest = engine(engines, &engine_id)?;
            print_value(&engine_inspection(manifest, adapters), json_output)?;
        }
        EngineCommand::Install { engine_id } => {
            let manifest = engine(engines, &engine_id)?;
            if let Some(blocker) = manifest.release_blocker() {
                return Err(AppError::NotAvailable(format!(
                    "engine {engine_id} is not release-approved: {blocker}; no image was retrieved"
                )));
            }
            if matches!(
                manifest.distribution_mode,
                DistributionMode::ExternalExecutable
            ) {
                return Err(AppError::NotAvailable(format!(
                    "engine {engine_id} is configured as an external executable; the constrained CLI only retrieves pinned container images"
                )));
            }
            let image = PinnedImage::from_manifest(manifest)?;
            let runtime = ProcessContainerRuntime::detect()?;
            let preflight = runtime.preflight()?;
            runtime.pull(&image)?;
            print_value(
                &json!({
                    "engine_id": engine_id,
                    "image": image.reference(),
                    "runtime": preflight,
                    "retrieved": true,
                    "verification": "immutable sha256 digest",
                    "notice": "Retrieval does not start the engine and does not establish scanner correctness.",
                }),
                json_output,
            )?;
        }
    }
    Ok(())
}

async fn execute_runtime(
    command: RuntimeCommand,
    service: &CaseService<'_>,
    engines: &EngineRegistry,
    data_dir: &Path,
    artifact_root: &Path,
    managed_runtime_bundle: Option<&Path>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        RuntimeCommand::Managed { command } => {
            let data_dir = data_dir.to_path_buf();
            let artifact_root = artifact_root.to_path_buf();
            let bundle = managed_runtime_bundle.map(Path::to_path_buf);
            let value = tokio::task::spawn_blocking(move || {
                execute_managed_runtime_command(
                    &data_dir,
                    &artifact_root,
                    bundle.as_deref(),
                    command,
                )
            })
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "managed runtime worker could not be joined: {error}"
                ))
            })??;
            print_value(&value, json_output)?;
        }
        RuntimeCommand::Inspect(args) => {
            let cases = service.list_cases()?;
            let cleanup = inspect_cleanup(
                &cases,
                service,
                args.case_id.as_deref(),
                args.run_id.as_deref(),
            )?;
            let managed_runtime = inspect_managed_runtime(data_dir, managed_runtime_bundle).await;
            let compatibility_runtime = detect_runtime().await;
            print_value(
                &json!({
                    "runtime": {
                        "preferred_provider": "managed_local",
                        "managed_local": managed_runtime,
                        "compatibility": compatibility_runtime,
                    },
                    "cleanup": cleanup,
                    "artifact_root_policy": "case-scoped paths are reported; this command does not traverse or delete them",
                    "credential_capabilities": "ephemeral in-memory only; no credential values are persisted or shown",
                    "provider_identity_cleanup": "unknown unless separately recorded by the bootstrap workflow",
                    "engine_catalog_count": engines.manifests().len(),
                }),
                json_output,
            )?;
        }
        RuntimeCommand::CleanupPlan { case_id, run_id } => {
            let summaries = service.list_cases()?;
            let cleanup = inspect_cleanup(&summaries, service, Some(&case_id), Some(&run_id))?;
            print_value(
                &json!({
                    "case_id": case_id,
                    "run_id": run_id,
                    "cleanup": cleanup,
                    "action": "No cleanup was performed.",
                }),
                json_output,
            )?;
        }
        RuntimeCommand::Cleanup {
            case_id,
            run_id,
            confirm_run_id,
        } => {
            if confirm_run_id != run_id {
                return Err(AppError::NotAuthorized(
                    "--confirm-run-id must exactly match the run being cleaned".into(),
                ));
            }
            let summaries = service.list_cases()?;
            let inspection = inspect_cleanup(&summaries, service, Some(&case_id), Some(&run_id))?;
            if !inspection.invalid_checkpoint_records.is_empty() {
                return Err(AppError::NotAuthorized(
                    "cleanup refused because this run contains an invalid stored checkpoint".into(),
                ));
            }
            if inspection.pending.is_empty() {
                print_value(
                    &json!({
                        "case_id": case_id,
                        "run_id": run_id,
                        "results": [],
                        "remaining_obligations": 0,
                        "notice": "No durable runtime cleanup obligation exists for this exact run.",
                    }),
                    json_output,
                )?;
                return Ok(());
            }

            let mut results = Vec::new();
            for obligation in inspection.pending {
                let container_name = obligation.container_name.clone();
                let case = service.show_case(&case_id)?;
                let engine_run = case
                    .scan_runs
                    .iter()
                    .find(|run| run.id == run_id)
                    .and_then(|run| {
                        run.engine_runs
                            .iter()
                            .find(|engine_run| engine_run.id == obligation.engine_run_id)
                    })
                    .ok_or_else(|| {
                        AppError::InvalidRequest(
                            "cleanup checkpoint disappeared before execution".into(),
                        )
                    })?;
                let token = engine_run.resume_token.as_deref().ok_or_else(|| {
                    AppError::InvalidRequest("cleanup checkpoint has no resume token".into())
                })?;
                let mut checkpoint = ExecutionCheckpoint::from_resume_token(token)?;
                let scope_sha256 = checkpoint.scope_sha256.clone().ok_or_else(|| {
                    AppError::InvalidRequest("cleanup checkpoint has no frozen scope digest".into())
                })?;
                let image = PinnedImage::new(
                    engine_run.image_repository.as_deref().ok_or_else(|| {
                        AppError::InvalidRequest(
                            "cleanup engine run has no pinned image repository".into(),
                        )
                    })?,
                    engine_run.image_digest.as_deref().ok_or_else(|| {
                        AppError::InvalidRequest("cleanup engine run has no image digest".into())
                    })?,
                )?;
                let owned_container = OwnedContainerCleanupRequest {
                    case_id: case_id.clone(),
                    scan_run_id: run_id.clone(),
                    engine_run_id: engine_run.id.clone(),
                    engine_id: engine_run.engine_id.clone(),
                    attempt: checkpoint.attempt,
                    scope_sha256,
                    image,
                };
                if let Some(name) = container_name.as_deref()
                    && owned_container.container_name()? != name
                {
                    return Err(AppError::NotAuthorized(
                        "cleanup obligation container name does not match its execution identity"
                            .into(),
                    ));
                }
                let raw_artifacts = checkpoint
                    .artifact_ids
                    .iter()
                    .map(|artifact_id| {
                        case.raw_artifacts
                            .iter()
                            .find(|artifact| artifact.id == *artifact_id)
                            .cloned()
                            .ok_or_else(|| {
                                AppError::Runtime(format!(
                                    "cleanup checkpoint references missing artifact {artifact_id}"
                                ))
                            })
                    })
                    .collect::<AppResult<Vec<_>>>()?;
                let cleanup_data_dir = data_dir.to_path_buf();
                let cleanup_artifact_root = artifact_root.to_path_buf();
                let cleanup_provider = engine_run.runtime_provider.clone();
                let cleanup_checkpoint = checkpoint.clone();
                let cleanup_container_name = container_name.clone();
                let attempt = match tokio::task::spawn_blocking(move || {
                    perform_exact_runtime_cleanup(
                        &cleanup_data_dir,
                        &cleanup_artifact_root,
                        cleanup_provider.as_deref(),
                        &cleanup_checkpoint,
                        &owned_container,
                        cleanup_container_name.as_deref(),
                    )
                })
                .await
                {
                    Ok(attempt) => attempt,
                    Err(error) => {
                        results.push(json!({
                            "engine_run_id": obligation.engine_run_id,
                            "container_name": container_name,
                            "container_cleanup_completed": false,
                            "managed_network_cleanup_completed": false,
                            "record_updated": false,
                            "obligation_retained": true,
                            "error": format!("exact cleanup worker did not complete: {error}"),
                        }));
                        continue;
                    }
                };
                let ExactRuntimeCleanup {
                    container: container_cleanup,
                    managed_network: managed_cleanup,
                    orphan_credentials_removed,
                } = match attempt {
                    Ok(outcome) => outcome,
                    Err(failure) => {
                        results.push(json!({
                            "engine_run_id": obligation.engine_run_id,
                            "container_name": container_name,
                            "container_cleanup_completed": failure.container.is_some(),
                            "container_removed": failure.container.as_ref().map(|outcome| outcome.removed),
                            "container_detail": failure.container.as_ref().map(|outcome| outcome.detail.as_str()),
                            "managed_network_cleanup_completed": false,
                            "record_updated": false,
                            "obligation_retained": true,
                            "error": failure.error.to_string(),
                        }));
                        continue;
                    }
                };

                checkpoint.managed_network = None;
                checkpoint.cleanup_completed = true;
                checkpoint.stage = ExecutionStage::Failed;
                checkpoint.last_error = Some(
                    "exact container and managed-network cleanup completed; execution may be retried"
                        .into(),
                );
                let cleanup_detail = match managed_cleanup.as_ref() {
                    Some(managed) => format!(
                        "{}; managed egress: {}",
                        container_cleanup.detail, managed.detail
                    ),
                    None => container_cleanup.detail.clone(),
                }
                .chars()
                .take(4_000)
                .collect();
                let durable = DurableExecutionReport {
                    checkpoint,
                    runtime_preflight: None,
                    cleanup: Some(ai_security_scanner_lib::container_runtime::CleanupOutcome {
                        removed: container_cleanup.removed
                            && managed_cleanup.as_ref().is_none_or(|outcome| outcome.removed),
                        detail: cleanup_detail,
                    }),
                    exit_code: None,
                    raw_artifacts,
                    findings: Vec::new(),
                    warnings: vec![
                        "A prior exact runtime cleanup obligation was resolved without executing a scanner."
                            .into(),
                    ],
                };
                match service.apply_execution_report(&case_id, &durable) {
                    Ok(_) => results.push(json!({
                        "engine_run_id": obligation.engine_run_id,
                        "container_name": container_name,
                        "container_cleanup_completed": true,
                        "container_removed": container_cleanup.removed,
                        "container_detail": container_cleanup.detail,
                        "managed_network_cleanup_completed": true,
                        "managed_network_removed": managed_cleanup.as_ref().map(|outcome| outcome.removed),
                        "managed_network_detail": managed_cleanup.as_ref().map(|outcome| outcome.detail.as_str()),
                        "orphan_credentials_removed": orphan_credentials_removed,
                        "record_updated": true,
                        "obligation_retained": false,
                    })),
                    Err(error) => results.push(json!({
                        "engine_run_id": obligation.engine_run_id,
                        "container_name": container_name,
                        "container_cleanup_completed": true,
                        "container_removed": container_cleanup.removed,
                        "container_detail": container_cleanup.detail,
                        "managed_network_cleanup_completed": true,
                        "managed_network_removed": managed_cleanup.as_ref().map(|outcome| outcome.removed),
                        "managed_network_detail": managed_cleanup.as_ref().map(|outcome| outcome.detail.as_str()),
                        "record_updated": false,
                        "obligation_retained": true,
                        "error": error.to_string(),
                    })),
                }
            }
            let remaining = inspect_cleanup(
                &service.list_cases()?,
                service,
                Some(&case_id),
                Some(&run_id),
            )?;
            print_value(
                &json!({
                    "case_id": case_id,
                    "run_id": run_id,
                    "results": results,
                    "remaining_obligations": remaining.pending.len(),
                    "invalid_checkpoint_records": remaining.invalid_checkpoint_records,
                    "notice": "Each obligation used its recorded runtime provenance. The exact container was reconciled first, followed by its exact managed-network identity; the durable obligation was cleared only after both succeeded.",
                }),
                json_output,
            )?;
        }
    }
    Ok(())
}

fn inspect_cleanup(
    summaries: &[ai_security_scanner_lib::domain::CaseSummary],
    service: &CaseService<'_>,
    case_filter: Option<&str>,
    run_filter: Option<&str>,
) -> AppResult<CleanupInspection> {
    if let Some(case_id) = case_filter {
        service.show_case(case_id)?;
    }

    let mut inspection = CleanupInspection::default();
    for summary in summaries
        .iter()
        .filter(|summary| case_filter.is_none_or(|case_id| summary.id == case_id))
    {
        let case = service.show_case(&summary.id)?;
        for run in case
            .scan_runs
            .iter()
            .filter(|run| run_filter.is_none_or(|run_id| run.id == run_id))
        {
            for engine_run in &run.engine_runs {
                let Some(token) = engine_run.resume_token.as_deref() else {
                    continue;
                };
                let Ok(checkpoint) = ExecutionCheckpoint::from_resume_token(token) else {
                    inspection
                        .invalid_checkpoint_records
                        .push(InvalidCheckpointRecord {
                            case_id: case.id.clone(),
                            scan_run_id: run.id.clone(),
                            engine_run_id: engine_run.id.clone(),
                            explanation: "stored checkpoint failed structural validation",
                        });
                    continue;
                };
                if checkpoint.case_id != case.id
                    || checkpoint.scan_run_id != run.id
                    || checkpoint.engine_run_id != engine_run.id
                    || checkpoint.engine_id != engine_run.engine_id
                {
                    inspection
                        .invalid_checkpoint_records
                        .push(InvalidCheckpointRecord {
                            case_id: case.id.clone(),
                            scan_run_id: run.id.clone(),
                            engine_run_id: engine_run.id.clone(),
                            explanation: "stored checkpoint identity does not match its case record",
                        });
                    continue;
                }
                if !checkpoint.cleanup_completed {
                    if checkpoint.container_name.is_none() && checkpoint.managed_network.is_none() {
                        inspection
                            .invalid_checkpoint_records
                            .push(InvalidCheckpointRecord {
                                case_id: case.id.clone(),
                                scan_run_id: run.id.clone(),
                                engine_run_id: engine_run.id.clone(),
                                explanation: "cleanup obligation has neither a container nor a managed-network identity",
                            });
                        continue;
                    }
                    inspection.pending.push(CleanupObligation {
                        case_id: case.id.clone(),
                        scan_run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        engine_id: engine_run.engine_id.clone(),
                        attempt: checkpoint.attempt,
                        container_name: checkpoint.container_name.clone(),
                    });
                }
            }
        }
    }

    if let (Some(case_id), Some(run_id)) = (case_filter, run_filter) {
        let case = service.show_case(case_id)?;
        if !case.scan_runs.iter().any(|run| run.id == run_id) {
            return Err(AppError::InvalidRequest(format!(
                "scan run not found: {run_id}"
            )));
        }
    }
    inspection.pending.sort_by(|left, right| {
        left.case_id
            .cmp(&right.case_id)
            .then_with(|| left.scan_run_id.cmp(&right.scan_run_id))
            .then_with(|| left.engine_run_id.cmp(&right.engine_run_id))
    });
    Ok(inspection)
}

fn engine<'a>(engines: &'a EngineRegistry, engine_id: &str) -> AppResult<&'a EngineManifest> {
    engines
        .get(engine_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("unknown engine: {engine_id}")))
}

fn engine_inspection(
    manifest: &EngineManifest,
    adapters: &ai_security_scanner_lib::adapter::AdapterRegistry,
) -> Value {
    let adapter = adapters.get(&manifest.id);
    let adapter_matches =
        adapter.is_some_and(|adapter| adapter.adapter_version() == manifest.adapter_version);
    let pinned_image = PinnedImage::from_manifest(manifest).ok();
    let release_blocker = manifest.release_blocker();
    let release_approved = release_blocker.is_none();
    let constrained_distribution = !matches!(
        manifest.distribution_mode,
        DistributionMode::ExternalExecutable
    );
    let ready = release_approved
        && adapter_matches
        && pinned_image.is_some()
        && constrained_distribution
        && !manifest.command.is_empty();
    json!({
        "manifest": manifest,
        "readiness": {
            "dispatchable": ready,
            "release_approved": release_approved,
            "adapter_loaded": adapter.is_some(),
            "adapter_version_matches": adapter_matches,
            "pinned_image": pinned_image.as_ref().map(PinnedImage::reference),
            "constrained_distribution": constrained_distribution,
            "compatibility_runnable": manifest.compatibility.runnable,
            "compatibility_blocked_by": manifest.compatibility.blocked_by,
            "not_executed_reason": if ready {
                None
            } else {
                release_blocker.as_deref().or(Some("One or more adapter, immutable-image, distribution, or command requirements are incomplete."))
            },
        }
    })
}

/// Resolves the only connector snapshot root accepted by the CLI for a case.
///
/// Both path components are backend-generated from a strictly bounded case ID,
/// and every existing component must be a real directory. Keeping snapshots
/// below the canonical case artifact root ensures the separately confirmed
/// `CaseService::delete_case_artifacts` operation removes them as part of the
/// same evidence lifecycle.
fn case_connector_artifact_root(artifact_root: &Path, case_id: &str) -> AppResult<PathBuf> {
    if case_id.is_empty()
        || case_id.len() > 128
        || !case_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(
            "case id is unsafe for connector artifact storage".into(),
        ));
    }

    let metadata = fs::symlink_metadata(artifact_root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "case artifact root is not a real directory".into(),
        ));
    }
    let canonical_artifact_root = artifact_root.canonicalize()?;
    let case_root = ensure_private_directory_child(&canonical_artifact_root, case_id)?;
    ensure_private_directory_child(&case_root, "connector-snapshots")
}

fn ensure_private_directory_child(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let child = parent.join(name);
    match fs::create_dir(&child) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }

    let metadata = fs::symlink_metadata(&child)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "case artifact directory is not a real directory".into(),
        ));
    }
    let canonical_parent = parent.canonicalize()?;
    let canonical_child = child.canonicalize()?;
    if canonical_child.parent() != Some(canonical_parent.as_path()) {
        return Err(AppError::NotAuthorized(
            "case artifact directory escaped its backend-owned parent".into(),
        ));
    }
    restrict_private_directory(&canonical_child)?;
    Ok(canonical_child)
}

#[cfg(unix)]
fn restrict_private_directory(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

fn open_managed_runtime_manager(
    data_dir: &Path,
    bundle_override: Option<&Path>,
) -> AppResult<ManagedRuntimeManager> {
    if let Some(bundle) = bundle_override {
        return ManagedRuntimeManager::open(data_dir, bundle, &bundle.join("manifest.json"));
    }

    let mut bundles = std::collections::BTreeSet::new();
    if let Ok(executable) = std::env::current_exe() {
        for candidate in packaged_managed_runtime_candidates(&executable) {
            if candidate.join("manifest.json").exists() {
                bundles.insert(candidate.canonicalize()?);
            }
        }
    }
    match bundles.len() {
        0 => ManagedRuntimeManager::open_installed(data_dir, None),
        1 => {
            let bundle = bundles.pop_first().expect("one managed runtime bundle");
            ManagedRuntimeManager::open(data_dir, &bundle, &bundle.join("manifest.json"))
        }
        _ => Err(AppError::NotAuthorized(
            "multiple packaged managed-runtime bundles were discovered; select one exact bundle with --managed-runtime-bundle"
                .into(),
        )),
    }
}

fn packaged_managed_runtime_candidates(executable: &Path) -> Vec<PathBuf> {
    let Some(parent) = executable.parent() else {
        return Vec::new();
    };
    let candidates = vec![
        parent.join("managed-runtime"),
        parent.join("resources").join("managed-runtime"),
        parent.join("..").join("Resources").join("managed-runtime"),
    ];
    #[cfg(target_os = "linux")]
    let candidates = {
        let mut candidates = candidates;
        if let Some(prefix) = parent.parent() {
            // Tauri's Deb and RPM bundlers install resources below
            // `/usr/lib/<product>`. AppImage reuses the same Debian data tree, so
            // its mounted CLI at `<AppDir>/usr/bin` has this identical relative
            // resource location.
            candidates.push(
                prefix
                    .join("lib")
                    .join("ai-security-scanner")
                    .join("managed-runtime"),
            );
        }
        candidates
    };
    candidates
}

fn execute_managed_runtime_command(
    data_dir: &Path,
    artifact_root: &Path,
    bundle_override: Option<&Path>,
    command: ManagedRuntimeCliCommand,
) -> AppResult<Value> {
    let manager = open_managed_runtime_manager(data_dir, bundle_override)?;
    let value = match command {
        ManagedRuntimeCliCommand::Status => serde_json::to_value(manager.status()?),
        ManagedRuntimeCliCommand::Install => serde_json::to_value(manager.install()?),
        ManagedRuntimeCliCommand::Start => {
            let _command = manager.start()?;
            serde_json::to_value(manager.status()?)
        }
        ManagedRuntimeCliCommand::Stop { force } => {
            let mode = if force {
                ManagedStopMode::Force
            } else {
                ManagedStopMode::OnlyIfIdle
            };
            serde_json::to_value(manager.stop(mode)?)
        }
        ManagedRuntimeCliCommand::Update => serde_json::to_value(manager.update()?),
        ManagedRuntimeCliCommand::Qualify => {
            return execute_managed_runtime_qualification(&manager, artifact_root);
        }
        ManagedRuntimeCliCommand::QualifyEgress => {
            return execute_managed_egress_gateway_qualification(&manager, artifact_root);
        }
        ManagedRuntimeCliCommand::Uninstall {
            force,
            purge_image_cache,
        } => {
            let stop_mode = if force {
                ManagedStopMode::Force
            } else {
                ManagedStopMode::OnlyIfIdle
            };
            serde_json::to_value(manager.uninstall(ManagedUninstallOptions {
                stop_mode,
                remove_machine_image_cache: purge_image_cache,
            })?)
        }
    };
    value.map_err(|error| {
        AppError::Internal(format!(
            "managed runtime result could not be encoded: {error}"
        ))
    })
}

fn execute_managed_runtime_qualification(
    manager: &ManagedRuntimeManager,
    artifact_root: &Path,
) -> AppResult<Value> {
    let runtime = ProcessContainerRuntime::from_managed(manager.start()?)?;
    let preflight = runtime.preflight()?;
    let engines = EngineRegistry::load_builtin()?;
    let canonical_artifact_root = canonical_private_artifact_root(artifact_root)?;
    execute_fixed_managed_container_qualification(
        &runtime,
        preflight,
        &engines,
        &canonical_artifact_root.join("qualification-artifacts"),
    )
}

fn execute_managed_egress_gateway_qualification(
    manager: &ManagedRuntimeManager,
    artifact_root: &Path,
) -> AppResult<Value> {
    let runtime = ProcessContainerRuntime::from_managed(manager.start()?)?;
    let preflight = runtime.preflight()?;
    if preflight.provider != RuntimeProvider::ManagedLocal
        || !matches!(
            &preflight.command_provenance,
            RuntimeCommandProvenance::ManagedLocal { .. }
        )
    {
        return Err(AppError::NotAuthorized(
            "managed egress qualification requires verified managed-local command provenance"
                .into(),
        ));
    }

    let canonical_artifact_root = canonical_private_artifact_root(artifact_root)?;
    let qualification_case_root = ensure_private_directory_child(&canonical_artifact_root, "q")?;
    let policy_root = ensure_private_directory_child(&qualification_case_root, "network-policies")?;
    let registry_root =
        ensure_private_directory_child(&canonical_artifact_root, ".managed-egress-registry")?;
    let gateway = managed_egress_gateway_spec()?;
    let expected_image = gateway.reference();
    let controller = ManagedNetworkController::new_with_registry_context_and_container(
        runtime.command_context(),
        gateway,
        policy_root,
        registry_root,
    )?;
    let owner = ManagedNetworkOwner::new(
        MANAGED_RUNTIME_QUALIFICATION_CASE_ID,
        MANAGED_RUNTIME_QUALIFICATION_SCAN_RUN_ID,
        new_id(),
        1,
    )?;
    let qualification_id = format!(
        "release_gateway_{}",
        env!("CARGO_PKG_VERSION").replace('.', "_")
    );
    let qualification =
        controller.qualify_gateway_container(&owner, &qualification_id, Utc::now())?;
    managed_egress_gateway_qualification_value(preflight, qualification, &expected_image)
}

fn managed_egress_gateway_qualification_value(
    preflight: RuntimePreflight,
    qualification: ManagedGatewayQualification,
    expected_image: &str,
) -> AppResult<Value> {
    if preflight.provider != RuntimeProvider::ManagedLocal
        || !matches!(
            &preflight.command_provenance,
            RuntimeCommandProvenance::ManagedLocal { .. }
        )
    {
        return Err(AppError::NotAuthorized(
            "managed egress qualification lost verified managed-local command provenance".into(),
        ));
    }
    if qualification.image != expected_image
        || !qualification.gateway_reachable
        || qualification.reachability_probe != "socks5_no_connect_greeting"
        || qualification.upstream_connect_attempted
    {
        return Err(AppError::NotAuthorized(
            "managed egress qualification did not prove the pinned no-upstream gateway contract"
                .into(),
        ));
    }
    if [
        qualification.cleanup.gateway_container_removed,
        qualification.cleanup.probe_container_removed,
        qualification.cleanup.internal_network_removed,
        qualification.cleanup.uplink_network_removed,
        qualification.cleanup.policy_file_removed,
        qualification.cleanup.status_directory_removed,
        qualification.cleanup.registry_record_removed,
    ]
    .contains(&false)
    {
        return Err(AppError::Runtime(
            "managed egress qualification cleanup proof is incomplete".into(),
        ));
    }

    Ok(json!({
        "schema_version": "1.0.0",
        "status": "passed",
        "qualification_kind": "managed_egress_gateway_readiness",
        "product_version": env!("CARGO_PKG_VERSION"),
        "runtime": {
            "provider": preflight.provider,
            "server_version": preflight.server_version,
            "command_provenance": preflight.command_provenance,
        },
        "gateway": {
            "image": qualification.image,
            "backend": "pinned_container",
            "ready": true,
            "scanner_reachable": qualification.gateway_reachable,
            "reachability_probe": qualification.reachability_probe,
            "upstream_connection_attempted": qualification.upstream_connect_attempted,
            "container_id": qualification.gateway_container_id,
            "probe_container_id": qualification.probe_container_id,
            "internal_network_id": qualification.internal_network_id,
            "uplink_network_id": qualification.uplink_network_id,
            "policy_sha256": qualification.policy_sha256,
        },
        "cleanup": qualification.cleanup,
    }))
}

fn canonical_private_artifact_root(artifact_root: &Path) -> AppResult<PathBuf> {
    let metadata = fs::symlink_metadata(artifact_root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "qualification artifact root must be a real directory".into(),
        ));
    }
    artifact_root.canonicalize().map_err(AppError::from)
}

fn execute_fixed_managed_container_qualification<R: ContainerRuntime>(
    runtime: &R,
    preflight: RuntimePreflight,
    engines: &EngineRegistry,
    evidence_root: &Path,
) -> AppResult<Value> {
    if preflight.provider != RuntimeProvider::ManagedLocal
        || !matches!(
            preflight.command_provenance,
            RuntimeCommandProvenance::ManagedLocal { .. }
        )
    {
        return Err(AppError::NotAuthorized(
            "managed-container qualification requires verified managed-local command provenance"
                .into(),
        ));
    }

    let manifest = engines
        .get(MANAGED_RUNTIME_QUALIFICATION_ENGINE_ID)
        .ok_or_else(|| {
            AppError::EngineRegistry(
                "managed-container qualification engine is absent from the built-in catalog".into(),
            )
        })?;
    let expected_command = ["--workspace", "/workspace", "--output", "/output"];
    if manifest.command.len() != expected_command.len()
        || !manifest
            .command
            .iter()
            .zip(expected_command)
            .all(|(actual, expected)| actual == expected)
        || manifest.active_external
        || !manifest.network_destinations.is_empty()
        || manifest.required_permissions != [ScanPermission::LocalArtifactRead]
    {
        return Err(AppError::EngineRegistry(
            "managed-container qualification manifest differs from its fixed offline contract"
                .into(),
        ));
    }
    let image = PinnedImage::from_manifest(manifest)?;
    if image.reference() != MANAGED_RUNTIME_QUALIFICATION_IMAGE {
        return Err(AppError::EngineRegistry(
            "managed-container qualification image differs from the release-fixed digest".into(),
        ));
    }

    let store = ArtifactStore::open(evidence_root)?;
    let context = ArtifactContext {
        case_id: MANAGED_RUNTIME_QUALIFICATION_CASE_ID.into(),
        scan_run_id: MANAGED_RUNTIME_QUALIFICATION_SCAN_RUN_ID.into(),
        engine_run_id: new_id(),
    };
    let directories = store.prepare_run(&context, 1)?;
    fs::write(
        directories.workspace.join("qualification.txt"),
        b"ai-security-scanner managed runtime qualification\n",
    )?;
    let scope = store.write_control_json(
        &directories,
        "scope.json",
        &json!({
            "schema_version": "1.0.0",
            "qualification_kind": "managed_container_execution",
            "case_id": context.case_id,
            "scan_run_id": context.scan_run_id,
            "engine_run_id": context.engine_run_id,
            "engine_id": MANAGED_RUNTIME_QUALIFICATION_ENGINE_ID,
            "asset": { "kind": "repository", "path": "/workspace" },
            "permissions": ["local_artifact_read"],
            "network": "disabled"
        }),
    )?;
    let capture = store.prepare_capture(&directories)?;
    let limits = ResourceLimits {
        memory_mb: 512,
        pids: 64,
        cpu_millis: 1000,
        tmpfs_mb: 32,
        output_bytes: 8 * 1024 * 1024,
    };
    let network_policy = NetworkPolicy::Disabled;
    let credentials = ScannerCredentialSet::default();
    let plan = ContainerPlanBuilder::new(
        manifest,
        &image,
        &directories,
        &scope.path,
        &limits,
        &network_policy,
        &credentials,
        &context.case_id,
        &context.scan_run_id,
        &context.engine_run_id,
        1,
    )
    .build()?;
    let runtime_args = plan.runtime_args();
    let network_none = runtime_args
        .windows(2)
        .filter(|pair| pair[0] == "--network" && pair[1] == "none")
        .count()
        == 1;
    if plan.network_policy() != &NetworkPolicy::Disabled
        || runtime_args
            .iter()
            .filter(|arg| *arg == "--read-only")
            .count()
            != 1
        || runtime_args
            .iter()
            .filter(|arg| *arg == "--cap-drop=ALL")
            .count()
            != 1
        || runtime_args
            .iter()
            .filter(|arg| *arg == "--security-opt=no-new-privileges:true")
            .count()
            != 1
        || runtime_args.iter().any(|arg| arg == "--env")
        || !network_none
        || !credentials.is_empty()
    {
        return Err(AppError::NotAuthorized(
            "managed-container qualification plan lost its fixed isolation contract".into(),
        ));
    }

    runtime.verify_network(&network_policy)?;
    runtime.pull(&image)?;
    let mut created_container = None;
    let run_result = runtime.run(
        &plan,
        &credentials,
        &CancellationToken::default(),
        &capture,
        &mut created_container,
    );
    let created_object_id = created_container
        .as_ref()
        .map(|created| created.immutable_id().to_owned());
    let cleanup_result = created_container
        .as_ref()
        .map(|created| runtime.cleanup(plan.ownership(), Some(created)));
    let (outcome, cleanup) = match (run_result, cleanup_result) {
        (Ok(outcome), Some(Ok(cleanup))) => (outcome, cleanup),
        (Ok(_), None) => {
            return Err(AppError::Runtime(
                "managed-container qualification returned without a created-object identity".into(),
            ));
        }
        (Ok(_), Some(Err(cleanup))) => return Err(cleanup),
        (Err(run), Some(Err(cleanup))) => {
            return Err(AppError::Runtime(format!(
                "{run}; managed-container qualification cleanup also failed: {cleanup}"
            )));
        }
        (Err(run), _) => return Err(run),
    };
    if outcome.cancelled || outcome.exit_code != Some(0) {
        return Err(AppError::Runtime(format!(
            "managed-container qualification did not complete successfully: exit={:?}, cancelled={}",
            outcome.exit_code, outcome.cancelled
        )));
    }
    if !cleanup.removed {
        return Err(AppError::Runtime(
            "managed-container qualification could not prove removal of its created container"
                .into(),
        ));
    }

    let report_path = directories
        .output
        .join(MANAGED_RUNTIME_QUALIFICATION_REPORT);
    let report_metadata = fs::symlink_metadata(&report_path).map_err(|error| {
        AppError::Runtime(format!(
            "managed-container qualification report is unavailable: {error}"
        ))
    })?;
    if report_metadata.file_type().is_symlink()
        || !report_metadata.is_file()
        || report_metadata.len() > MAX_MANAGED_RUNTIME_QUALIFICATION_REPORT_BYTES
    {
        return Err(AppError::Runtime(
            "managed-container qualification report must be a bounded regular file".into(),
        ));
    }
    let report_bytes = fs::read(&report_path)?;
    let findings = serde_json::from_slice::<Vec<Value>>(&report_bytes).map_err(|error| {
        AppError::Runtime(format!(
            "managed-container qualification report is malformed: {error}"
        ))
    })?;
    if !findings.is_empty() {
        return Err(AppError::Runtime(
            "managed-container qualification fixture unexpectedly produced findings".into(),
        ));
    }
    let report = store.describe_file(&context, &report_path, "application/json", false)?;
    let stdout = store.describe_file(
        &context,
        &capture.stdout,
        "text/plain; charset=utf-8",
        false,
    )?;
    let stderr = store.describe_file(
        &context,
        &capture.stderr,
        "text/plain; charset=utf-8",
        false,
    )?;

    Ok(json!({
        "schema_version": "1.0.0",
        "status": "passed",
        "qualification_kind": "managed_container_execution",
        "product_version": env!("CARGO_PKG_VERSION"),
        "runtime": {
            "provider": preflight.provider,
            "server_version": preflight.server_version,
            "command_provenance": preflight.command_provenance,
        },
        "container": {
            "engine_id": MANAGED_RUNTIME_QUALIFICATION_ENGINE_ID,
            "image": image.reference(),
            "network": "none",
            "read_only_root": true,
            "capabilities": "drop_all",
            "no_new_privileges": true,
            "credential_count": 0,
            "exit_code": outcome.exit_code,
            "cancelled": outcome.cancelled,
            "created_object_id": created_object_id.expect("successful runtime returns identity"),
            "cleanup_removed": cleanup.removed,
        },
        "evidence": {
            "scope_sha256": scope.sha256,
            "report_sha256": report.sha256,
            "report_bytes": report.byte_length,
            "finding_count": findings.len(),
            "stdout_sha256": stdout.sha256,
            "stderr_sha256": stderr.sha256,
        }
    }))
}

/// Reconstructs only the runtime recorded by a cleanup-pending checkpoint.
/// Managed-local recovery is tied to the exact release manifest SHA-256; the
/// stored command path or environment is never trusted or reconstructed from
/// user input.
fn runtime_for_cleanup(
    data_dir: &Path,
    stored_provider: Option<&str>,
    checkpoint: &ExecutionCheckpoint,
) -> AppResult<ProcessContainerRuntime> {
    let provenance = checkpoint
        .runtime_command_provenance
        .as_ref()
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "cleanup checkpoint does not record exact runtime provenance".into(),
            )
        })?;
    let provider_from_engine_record = match stored_provider {
        Some("managed_local") => Some(RuntimeProvider::ManagedLocal),
        Some("docker") => Some(RuntimeProvider::Docker),
        Some("podman") => Some(RuntimeProvider::Podman),
        Some(_) => {
            return Err(AppError::NotAuthorized(
                "cleanup checkpoint references an unsupported runtime provider".into(),
            ));
        }
        None => None,
    };
    let provider_from_network = checkpoint
        .managed_network
        .as_ref()
        .map(|identity| identity.provider);
    let provider = checkpoint.runtime_provider.ok_or_else(|| {
        AppError::NotAuthorized(
            "cleanup checkpoint does not record an exact runtime provider".into(),
        )
    })?;
    if provider_from_engine_record.is_some_and(|recorded| recorded != provider) {
        return Err(AppError::NotAuthorized(
            "engine runtime record conflicts with checkpoint runtime provenance".into(),
        ));
    }
    if let Some(network) = provider_from_network
        && provider != network
    {
        return Err(AppError::NotAuthorized(
            "checkpoint runtime provider conflicts with managed-network provenance".into(),
        ));
    }

    let runtime = match (provider, provenance) {
        (
            RuntimeProvider::ManagedLocal,
            RuntimeCommandProvenance::ManagedLocal {
                manifest_sha256, ..
            },
        ) => {
            let manager =
                ManagedRuntimeManager::open_installed(data_dir, Some(manifest_sha256.as_str()))?;
            ProcessContainerRuntime::from_managed(manager.start()?)?
        }
        (RuntimeProvider::Docker, RuntimeCommandProvenance::Compatibility) => {
            ProcessContainerRuntime::new(RuntimeProvider::Docker, "docker")
        }
        (RuntimeProvider::Podman, RuntimeCommandProvenance::Compatibility) => {
            ProcessContainerRuntime::new(RuntimeProvider::Podman, "podman")
        }
        _ => {
            return Err(AppError::NotAuthorized(
                "cleanup runtime provider conflicts with its typed command provenance".into(),
            ));
        }
    };
    let observed = runtime.preflight()?;
    if observed.provider != provider || observed.command_provenance != *provenance {
        return Err(AppError::NotAuthorized(
            "resolved cleanup runtime does not match the durable command provenance".into(),
        ));
    }
    Ok(runtime)
}

/// Performs every operation that owns the managed runtime's blocking HTTP
/// client on the caller's blocking thread. Returning only owned cleanup
/// outcomes guarantees the runtime (and its client) is dropped before this
/// function crosses back into Tokio's async worker.
fn perform_exact_runtime_cleanup(
    data_dir: &Path,
    artifact_root: &Path,
    stored_provider: Option<&str>,
    checkpoint: &ExecutionCheckpoint,
    owned_container: &OwnedContainerCleanupRequest,
    container_name: Option<&str>,
) -> Result<ExactRuntimeCleanup, ExactRuntimeCleanupFailure> {
    let runtime = runtime_for_cleanup(data_dir, stored_provider, checkpoint).map_err(|error| {
        ExactRuntimeCleanupFailure {
            container: None,
            error,
        }
    })?;
    let container = match container_name {
        Some(_) => runtime
            .cleanup_owned_container(owned_container)
            .map_err(|error| ExactRuntimeCleanupFailure {
                container: None,
                error,
            })?,
        None => CleanupOutcome {
            removed: false,
            detail: "no scanner container was started; container reconciliation was not required"
                .into(),
        },
    };

    let managed_network = if let Some(identity) = checkpoint.managed_network.as_ref() {
        let after_container = |error| ExactRuntimeCleanupFailure {
            container: Some(container.clone()),
            error,
        };
        let canonical_artifact_root = artifact_root
            .canonicalize()
            .map_err(AppError::from)
            .map_err(after_container)?;
        let registry_root =
            ensure_private_directory_child(&canonical_artifact_root, ".managed-egress-registry")
                .map_err(after_container)?;
        let registry = ManagedNetworkRegistry::new_with_runtime_context(
            registry_root,
            artifact_root,
            runtime.command_context(),
        )
        .map_err(after_container)?;
        let owner = ManagedNetworkOwner::new(
            checkpoint.case_id.clone(),
            checkpoint.scan_run_id.clone(),
            checkpoint.engine_run_id.clone(),
            checkpoint.attempt,
        )
        .map_err(after_container)?;
        Some(
            registry
                .reconcile_identity(&owner, identity, Utc::now())
                .map_err(after_container)?,
        )
    } else {
        None
    };

    let orphan_credentials_removed = cleanup_orphaned_credentials(artifact_root, owned_container)
        .map_err(|error| ExactRuntimeCleanupFailure {
        container: Some(container.clone()),
        error,
    })?;

    Ok(ExactRuntimeCleanup {
        container,
        managed_network,
        orphan_credentials_removed,
    })
}

async fn inspect_managed_runtime(data_dir: &Path, bundle_override: Option<&Path>) -> Value {
    let data_dir = data_dir.to_path_buf();
    let bundle = bundle_override.map(Path::to_path_buf);
    match tokio::task::spawn_blocking(move || {
        inspect_managed_runtime_blocking(&data_dir, bundle.as_deref())
    })
    .await
    {
        Ok(value) => value,
        Err(error) => json!({
            "configured": false,
            "available": false,
            "error": format!("managed runtime status worker failed: {error}"),
        }),
    }
}

fn inspect_managed_runtime_blocking(data_dir: &Path, bundle_override: Option<&Path>) -> Value {
    match open_managed_runtime_manager(data_dir, bundle_override) {
        Ok(manager) => match manager.status() {
            Ok(status) => json!({ "configured": true, "status": status }),
            Err(error) => json!({
                "configured": true,
                "available": false,
                "error": error.to_string(),
            }),
        },
        Err(error) => json!({
            "configured": false,
            "available": false,
            "error": error.to_string(),
        }),
    }
}

fn resolve_data_dir(override_path: Option<PathBuf>) -> AppResult<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }

    ProjectDirs::from("dev", "teddashh", "ai-security-scanner")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .ok_or_else(|| {
            AppError::Internal("could not determine local application data directory".into())
        })
}

fn parse_data_class(value: &str) -> AppResult<DataClass> {
    match value.trim().to_ascii_lowercase().as_str() {
        "general" => Ok(DataClass::General),
        "pii" => Ok(DataClass::PersonallyIdentifiableInformation),
        "phi" => Ok(DataClass::ProtectedHealthInformation),
        "pci" => Ok(DataClass::PaymentCardInformation),
        "financial" => Ok(DataClass::Financial),
        "secrets" => Ok(DataClass::CredentialsAndSecrets),
        "other" => Ok(DataClass::Other),
        other => Err(AppError::InvalidRequest(format!(
            "unsupported data class: {other}"
        ))),
    }
}

fn parse_rfc3339(value: &str) -> AppResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.trim())
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            AppError::InvalidRequest("--expires-at must be a valid RFC 3339 instant".into())
        })
}

fn print_value(value: &(impl Serialize + ?Sized), compact: bool) -> AppResult<()> {
    if compact {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_security_scanner_lib::container_runtime::{
        FakeContainerRuntime, FakeRunBehavior, RuntimeCall,
    };
    use clap::{CommandFactory, Parser};

    fn managed_qualification_preflight() -> RuntimePreflight {
        RuntimePreflight {
            provider: RuntimeProvider::ManagedLocal,
            server_version: "5.8.0".into(),
            security_options: "rootless".into(),
            command_provenance: RuntimeCommandProvenance::ManagedLocal {
                runtime_version: "5.8.0".into(),
                manifest_sha256: "a".repeat(64),
                machine_image_sha256: "b".repeat(64),
            },
        }
    }

    #[test]
    fn parses_supported_data_classes() {
        assert!(matches!(
            parse_data_class("PII"),
            Ok(DataClass::PersonallyIdentifiableInformation)
        ));
        assert!(parse_data_class("legal-opinion").is_err());
    }

    #[test]
    fn complete_command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn product_uninstall_cli_has_three_fixed_modes_and_a_legacy_scan_tools_alias() {
        for mode in ["app-only", "scan-tools", "verified-scan-tools", "all-data"] {
            let mut arguments = vec![
                "ai-security-scanner",
                "product-uninstall",
                "--mode",
                mode,
                "--non-interactive",
            ];
            if mode == "all-data" {
                arguments.extend(["--confirmation", ALL_DATA_CONFIRMATION]);
            }
            let parsed = Cli::try_parse_from(arguments).expect("fixed uninstall CLI mode");
            assert!(matches!(parsed.command, Command::ProductUninstall(_)));
        }
    }

    #[test]
    fn product_uninstall_accepts_the_hidden_bounded_coordinator_envelope() {
        let parsed = Cli::try_parse_from([
            "ai-security-scanner",
            "--json",
            "product-uninstall",
            "--mode",
            "app-only",
            "--non-interactive",
            "--coordinator-envelope",
        ])
        .expect("installed package coordinator invocation");
        let Command::ProductUninstall(args) = parsed.command else {
            panic!("product uninstall command");
        };
        assert!(args.coordinator_envelope);
    }

    #[test]
    fn product_uninstall_coordinator_envelope_is_complete_redacted_and_bounded() {
        let envelope = ProductUninstallCoordinatorEnvelope {
            schema_version: "ai-security-scanner.product-uninstall/v1",
            mode: ProductUninstallMode::AllData,
            result_class: ProductUninstallResultClass::CompletedWithRetainedState,
            exit_code: 10,
            retained_item_count: 129,
            retained_classes: vec![
                "compatibility_provider_image",
                "managed_runtime_state",
                "product_data",
            ],
            terminal: "complete",
        };
        let encoded = serde_json::to_string(&envelope).unwrap();

        assert!(encoded.len() < 512);
        assert!(
            encoded.starts_with("{\"schema_version\":\"ai-security-scanner.product-uninstall/v1\"")
        );
        assert!(encoded.ends_with("\"terminal\":\"complete\"}"));
        assert!(encoded.contains(
            "\"retained_classes\":[\"compatibility_provider_image\",\"managed_runtime_state\",\"product_data\"]"
        ));
        for forbidden in [
            "target",
            "path",
            "case_id",
            "runtime_name",
            "scanner_message",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn product_uninstall_rejects_an_arbitrary_data_directory_before_dispatch() {
        let parsed = Cli::try_parse_from([
            "ai-security-scanner",
            "--data-dir",
            "/tmp/not-the-installed-product-root",
            "product-uninstall",
            "--mode",
            "scan-tools",
            "--non-interactive",
        ])
        .unwrap();
        let Command::ProductUninstall(args) = &parsed.command else {
            panic!("product uninstall command");
        };
        let error = execute_product_uninstall_early(
            &parsed,
            args,
            GlobalOptionSources {
                data_dir: Some(ValueSource::CommandLine),
                managed_runtime_bundle: None,
            },
        )
        .expect_err("arbitrary destructive root must fail before mutation");
        assert!(error.to_string().contains("explicit global --data-dir"));
    }

    #[test]
    fn product_uninstall_ignores_inherited_global_overrides_but_not_explicit_ones() {
        validate_product_uninstall_option_sources(GlobalOptionSources {
            data_dir: Some(ValueSource::EnvVariable),
            managed_runtime_bundle: Some(ValueSource::EnvVariable),
        })
        .expect("inherited development overrides cannot redirect or block package uninstall");

        assert!(
            validate_product_uninstall_option_sources(GlobalOptionSources {
                data_dir: None,
                managed_runtime_bundle: Some(ValueSource::CommandLine),
            })
            .is_err()
        );
    }

    #[test]
    fn destructive_cross_process_commands_require_the_data_directory_lease() {
        let delete = Cli::try_parse_from([
            "ai-security-scanner",
            "case",
            "delete",
            "case-1",
            "--confirm-case-id",
            "case-1",
        ])
        .unwrap();
        let cleanup = Cli::try_parse_from([
            "ai-security-scanner",
            "runtime",
            "cleanup",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
            "--confirm-run-id",
            "run-1",
        ])
        .unwrap();
        let install =
            Cli::try_parse_from(["ai-security-scanner", "runtime", "managed", "install"]).unwrap();
        let qualify =
            Cli::try_parse_from(["ai-security-scanner", "runtime", "managed", "qualify"]).unwrap();
        let qualify_egress = Cli::try_parse_from([
            "ai-security-scanner",
            "runtime",
            "managed",
            "qualify-egress",
        ])
        .unwrap();
        let status =
            Cli::try_parse_from(["ai-security-scanner", "runtime", "managed", "status"]).unwrap();
        let doctor = Cli::try_parse_from(["ai-security-scanner", "doctor"]).unwrap();

        assert!(command_requires_exclusive_data_directory(&delete.command));
        assert!(command_requires_exclusive_data_directory(&cleanup.command));
        assert!(command_requires_exclusive_data_directory(&install.command));
        assert!(command_requires_exclusive_data_directory(&qualify.command));
        assert!(command_requires_exclusive_data_directory(
            &qualify_egress.command
        ));
        assert!(!command_requires_exclusive_data_directory(&status.command));
        assert!(!command_requires_exclusive_data_directory(&doctor.command));
    }

    #[test]
    fn managed_egress_qualification_envelope_is_exact_and_no_upstream() {
        let image = format!(
            "ghcr.io/teddashh/ai-security-scanner-egress-gateway@sha256:{}",
            "1".repeat(64)
        );
        let result = managed_egress_gateway_qualification_value(
            managed_qualification_preflight(),
            ManagedGatewayQualification {
                image: image.clone(),
                gateway_container_id: "2".repeat(64),
                probe_container_id: "3".repeat(64),
                internal_network_id: "4".repeat(64),
                uplink_network_id: "5".repeat(64),
                policy_sha256: "6".repeat(64),
                reachability_probe: "socks5_no_connect_greeting".into(),
                gateway_reachable: true,
                upstream_connect_attempted: false,
                cleanup:
                    ai_security_scanner_lib::managed_network::ManagedGatewayQualificationCleanup {
                        gateway_container_removed: true,
                        probe_container_removed: true,
                        internal_network_removed: true,
                        uplink_network_removed: true,
                        policy_file_removed: true,
                        status_directory_removed: true,
                        registry_record_removed: true,
                    },
            },
            &image,
        )
        .expect("qualification envelope");

        assert_eq!(
            result.pointer("/qualification_kind"),
            Some(&json!("managed_egress_gateway_readiness"))
        );
        assert_eq!(
            result.pointer("/gateway/backend"),
            Some(&json!("pinned_container"))
        );
        assert_eq!(result.pointer("/gateway/ready"), Some(&json!(true)));
        assert_eq!(
            result.pointer("/gateway/scanner_reachable"),
            Some(&json!(true))
        );
        assert_eq!(
            result.pointer("/gateway/upstream_connection_attempted"),
            Some(&json!(false))
        );
        assert_eq!(
            result.pointer("/cleanup/registry_record_removed"),
            Some(&json!(true))
        );
    }

    #[test]
    fn managed_egress_qualification_refuses_upstream_or_incomplete_cleanup_claims() {
        let image = format!(
            "ghcr.io/teddashh/ai-security-scanner-egress-gateway@sha256:{}",
            "1".repeat(64)
        );
        let qualification = |upstream, registry_removed| ManagedGatewayQualification {
            image: image.clone(),
            gateway_container_id: "2".repeat(64),
            probe_container_id: "3".repeat(64),
            internal_network_id: "4".repeat(64),
            uplink_network_id: "5".repeat(64),
            policy_sha256: "6".repeat(64),
            reachability_probe: "socks5_no_connect_greeting".into(),
            gateway_reachable: true,
            upstream_connect_attempted: upstream,
            cleanup: ai_security_scanner_lib::managed_network::ManagedGatewayQualificationCleanup {
                gateway_container_removed: true,
                probe_container_removed: true,
                internal_network_removed: true,
                uplink_network_removed: true,
                policy_file_removed: true,
                status_directory_removed: true,
                registry_record_removed: registry_removed,
            },
        };

        assert!(
            managed_egress_gateway_qualification_value(
                managed_qualification_preflight(),
                qualification(true, true),
                &image,
            )
            .is_err()
        );
        assert!(
            managed_egress_gateway_qualification_value(
                managed_qualification_preflight(),
                qualification(false, false),
                &image,
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_managed_container_qualification_runs_offline_and_cleans_up() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let evidence_root = temporary.path().join("qualification");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"qualification stdout\n".to_vec(),
            stderr: b"qualification stderr\n".to_vec(),
            output_files: BTreeMap::from([("gitleaks.json".into(), b"[]\n".to_vec())]),
        });
        let engines = EngineRegistry::load_builtin().expect("catalog");

        let result = execute_fixed_managed_container_qualification(
            &runtime,
            managed_qualification_preflight(),
            &engines,
            &evidence_root,
        )
        .expect("qualification");

        assert_eq!(result.pointer("/status"), Some(&json!("passed")));
        assert_eq!(
            result.pointer("/runtime/provider"),
            Some(&json!("managed_local"))
        );
        assert_eq!(
            result.pointer("/container/image"),
            Some(&json!(MANAGED_RUNTIME_QUALIFICATION_IMAGE))
        );
        assert_eq!(
            result.pointer("/container/cleanup_removed"),
            Some(&json!(true))
        );
        assert_eq!(result.pointer("/evidence/finding_count"), Some(&json!(0)));
        let calls = runtime.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0], RuntimeCall::VerifyNetwork("disabled".into()));
        assert_eq!(
            calls[1],
            RuntimeCall::Pull(MANAGED_RUNTIME_QUALIFICATION_IMAGE.into())
        );
        let RuntimeCall::Run(run_name) = &calls[2] else {
            panic!("expected fixed runtime run");
        };
        let RuntimeCall::Cleanup(cleanup_name) = &calls[3] else {
            panic!("expected fixed runtime cleanup");
        };
        assert_eq!(run_name, cleanup_name);

        let qualification_scan_root = evidence_root
            .join(MANAGED_RUNTIME_QUALIFICATION_CASE_ID)
            .join(MANAGED_RUNTIME_QUALIFICATION_SCAN_RUN_ID);
        let engine_runs = fs::read_dir(&qualification_scan_root)
            .expect("compact qualification scan root")
            .collect::<Result<Vec<_>, _>>()
            .expect("qualification engine-run entries");
        assert_eq!(engine_runs.len(), 1);
        let projected_cid_file = engine_runs[0]
            .path()
            .join("attempt-1")
            .join("control")
            .join("container-00000000000000000000000000000000.cid");
        let relative_cid_file = projected_cid_file
            .strip_prefix(&evidence_root)
            .expect("qualification CID file remains below evidence root");
        assert!(
            relative_cid_file.to_string_lossy().len() < 128,
            "release qualification reintroduced an unnecessarily long CID path"
        );
        assert!(!evidence_root.join("release-qualification").exists());
    }

    #[test]
    fn fixed_managed_container_qualification_fails_closed_on_cleanup_error() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_files: BTreeMap::from([("gitleaks.json".into(), b"[]\n".to_vec())]),
        });
        runtime.set_fail_cleanup(true);
        let engines = EngineRegistry::load_builtin().expect("catalog");

        let error = execute_fixed_managed_container_qualification(
            &runtime,
            managed_qualification_preflight(),
            &engines,
            &temporary.path().join("qualification"),
        )
        .expect_err("cleanup failure must fail qualification");

        assert!(error.to_string().contains("fake cleanup failure"));
    }

    #[test]
    fn fixed_managed_container_qualification_rejects_compatibility_runtime() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let runtime = FakeContainerRuntime::default();
        let engines = EngineRegistry::load_builtin().expect("catalog");
        let preflight = RuntimePreflight {
            provider: RuntimeProvider::Docker,
            server_version: "compatibility".into(),
            security_options: "unknown".into(),
            command_provenance: RuntimeCommandProvenance::Compatibility,
        };

        let error = execute_fixed_managed_container_qualification(
            &runtime,
            preflight,
            &engines,
            &temporary.path().join("qualification"),
        )
        .expect_err("compatibility runtime must not qualify as managed-local");

        assert!(
            error
                .to_string()
                .contains("managed-local command provenance")
        );
        assert!(runtime.calls().is_empty());
    }

    #[test]
    fn fixed_managed_container_qualification_rejects_findings_after_cleanup() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_files: BTreeMap::from([(
                "gitleaks.json".into(),
                br#"[{"RuleID":"unexpected"}]"#.to_vec(),
            )]),
        });
        let engines = EngineRegistry::load_builtin().expect("catalog");

        let error = execute_fixed_managed_container_qualification(
            &runtime,
            managed_qualification_preflight(),
            &engines,
            &temporary.path().join("qualification"),
        )
        .expect_err("unexpected finding must fail qualification");

        assert!(error.to_string().contains("unexpectedly produced findings"));
        assert!(matches!(
            runtime.calls().last(),
            Some(RuntimeCall::Cleanup(_))
        ));
    }

    #[test]
    fn standalone_live_scan_controls_fail_closed_with_exact_case_and_run() {
        for action in ["start", "pause", "resume", "cancel"] {
            let error = out_of_process_scan_control_error(action, "case-17", "run-23");
            let AppError::NotAvailable(message) = error else {
                panic!("live scan control did not return NotAvailable");
            };
            assert!(message.contains(action));
            assert!(message.contains("case-17"));
            assert!(message.contains("run-23"));
            assert!(message.contains("use the desktop scan controls"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn packaged_linux_cli_checks_tauri_deb_rpm_and_appimage_resource_layout() {
        let executable = Path::new("/mounted-or-installed/usr/bin/ai-security-scanner-cli");
        let candidates = packaged_managed_runtime_candidates(executable);
        assert!(candidates.contains(&PathBuf::from(
            "/mounted-or-installed/usr/lib/ai-security-scanner/managed-runtime"
        )));
    }

    #[test]
    fn parses_case_bound_cleanup_confirmation() {
        let cli = Cli::try_parse_from([
            "ai-security-scanner",
            "runtime",
            "cleanup",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
            "--confirm-run-id",
            "run-1",
        ])
        .expect("cleanup CLI");
        assert!(matches!(
            cli.command,
            Command::Runtime {
                command: RuntimeCommand::Cleanup { .. }
            }
        ));
    }

    #[test]
    fn parses_separately_confirmed_case_artifact_deletion() {
        let cli = Cli::try_parse_from([
            "ai-security-scanner",
            "case",
            "delete-artifacts",
            "case-1",
            "--exact-path",
            "/private/artifacts/case-1",
            "--confirmation",
            "DELETE case-1",
        ])
        .expect("case artifact deletion CLI");
        assert!(matches!(
            cli.command,
            Command::Case {
                command: CaseCommand::DeleteArtifacts { .. }
            }
        ));
    }

    #[test]
    fn raw_export_requires_explicit_acknowledgement() {
        let result = Cli::try_parse_from([
            "ai-security-scanner",
            "export",
            "create",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
            "--format",
            "case-bundle",
            "--destination",
            "out.case.tar.gz",
            "--include-raw-artifacts",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn source_upsert_exposes_no_free_form_secret_or_metadata_argument() {
        let help = Cli::try_parse_from(["ai-security-scanner", "source", "upsert", "--help"])
            .expect_err("help exits through clap")
            .to_string();
        for forbidden in ["password", "credential", "token", "metadata-json"] {
            assert!(!help.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn parses_explicit_scope_and_plan_commands() {
        let scope = Cli::try_parse_from([
            "ai-security-scanner",
            "scope",
            "approve",
            "--case-id",
            "case-1",
            "--asset-id",
            "asset-1",
            "--permission",
            "inventory-read,configuration-read",
            "--confirmed-by",
            "local-owner",
        ])
        .expect("scope CLI");
        assert!(matches!(scope.command, Command::Scope { .. }));

        let plan = Cli::try_parse_from([
            "ai-security-scanner",
            "scan",
            "plan",
            "--case-id",
            "case-1",
            "--engine",
            "prowler,cloudquery",
        ])
        .expect("scan plan CLI");
        assert!(matches!(plan.command, Command::Scan { .. }));

        let start = Cli::try_parse_from([
            "ai-security-scanner",
            "scan",
            "start",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
        ])
        .expect("scan start CLI");
        assert!(matches!(start.command, Command::Scan { .. }));

        let show = Cli::try_parse_from(["ai-security-scanner", "engine", "show", "prowler"])
            .expect("backward-compatible engine show CLI");
        assert!(matches!(show.command, Command::Engine { .. }));
    }

    #[test]
    fn parses_reversible_finding_group_commands() {
        let group = Cli::try_parse_from([
            "ai-security-scanner",
            "finding",
            "group",
            "--case-id",
            "case-1",
            "--title",
            "Related observations",
            "--finding-id",
            "finding-a,finding-b",
            "--rationale",
            "Review together without merging evidence",
            "--grouped-by",
            "local-reviewer",
        ])
        .expect("finding group CLI");
        let Command::Finding {
            command: FindingCommand::Group(args),
        } = group.command
        else {
            panic!("expected finding group command");
        };
        assert_eq!(args.finding_id, ["finding-a", "finding-b"]);

        let ungroup = Cli::try_parse_from([
            "ai-security-scanner",
            "finding",
            "ungroup",
            "--case-id",
            "case-1",
            "--group-id",
            "group-1",
            "--removed-by",
            "local-reviewer",
            "--reason",
            "The relationship was disproven",
        ])
        .expect("finding ungroup CLI");
        assert!(matches!(
            ungroup.command,
            Command::Finding {
                command: FindingCommand::Ungroup(_)
            }
        ));

        let one_member = Cli::try_parse_from([
            "ai-security-scanner",
            "finding",
            "group",
            "--case-id",
            "case-1",
            "--title",
            "Too small",
            "--finding-id",
            "finding-a",
            "--rationale",
            "One member is not a group",
            "--grouped-by",
            "local-reviewer",
        ])
        .expect("CLI syntax is separate from authoritative membership validation");
        let Command::Finding {
            command: FindingCommand::Group(args),
        } = one_member.command
        else {
            panic!("expected finding group command");
        };
        assert_eq!(args.finding_id, ["finding-a"]);
    }

    #[test]
    fn parses_rfc3339_expiry() {
        let parsed = parse_rfc3339("2030-01-02T03:04:05Z").expect("timestamp");
        assert_eq!(parsed.to_rfc3339(), "2030-01-02T03:04:05+00:00");
        assert!(parse_rfc3339("tomorrow").is_err());
    }

    #[test]
    fn not_executed_is_a_terminal_engine_state() {
        let encoded = serde_json::to_string(&EngineRunStatus::NotExecuted).expect("serialize");
        assert_eq!(encoded, "\"not_executed\"");
    }

    #[test]
    fn engine_readiness_fails_closed_on_compatibility_runnable() {
        let engines = EngineRegistry::load_builtin().expect("catalog");
        let adapters = builtin_adapter_registry().expect("adapters");
        let mut manifest = engines.get("prowler").expect("prowler").clone();
        // This is a release-contract fixture, independent of whether the
        // current built-in Prowler artifact has since been published.
        manifest.compatibility.runnable = false;
        manifest.compatibility.blocked_by = vec!["test_artifact_not_released".into()];
        manifest.default_enabled = false;
        let inspection = engine_inspection(&manifest, &adapters);
        assert_eq!(
            inspection.pointer("/readiness/dispatchable"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            inspection.pointer("/readiness/compatibility_runnable"),
            Some(&Value::Bool(false))
        );
    }

    #[test]
    fn connector_artifact_root_is_private_and_scoped_to_one_case() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        fs::create_dir(&artifact_root).expect("artifact root");

        let connector_root =
            case_connector_artifact_root(&artifact_root, "case_A-1").expect("case connector root");
        assert_eq!(
            connector_root,
            artifact_root
                .canonicalize()
                .expect("canonical artifact root")
                .join("case_A-1")
                .join("connector-snapshots")
        );
        assert_eq!(
            case_connector_artifact_root(&artifact_root, "case_A-1")
                .expect("stable connector root"),
            connector_root
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&connector_root)
                .expect("connector root metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn connector_artifact_root_rejects_unsafe_case_paths() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        fs::create_dir(&artifact_root).expect("artifact root");

        for unsafe_case_id in ["", ".", "..", "../outside", "case/path", "case\\path"] {
            assert!(
                case_connector_artifact_root(&artifact_root, unsafe_case_id).is_err(),
                "unsafe case id was accepted: {unsafe_case_id:?}"
            );
        }
        assert!(case_connector_artifact_root(&artifact_root, &"a".repeat(129)).is_err());
        assert!(!temporary.path().join("outside").exists());
    }

    #[cfg(unix)]
    #[test]
    fn connector_artifact_root_rejects_symlinked_case_directory() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        let outside = temporary.path().join("outside");
        fs::create_dir(&artifact_root).expect("artifact root");
        fs::create_dir(&outside).expect("outside directory");
        symlink(&outside, artifact_root.join("case-1")).expect("case symlink");

        let result = case_connector_artifact_root(&artifact_root, "case-1");
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));
        assert!(
            fs::read_dir(&outside)
                .expect("outside listing")
                .next()
                .is_none()
        );
    }

    #[test]
    fn case_artifact_deletion_removes_cli_connector_snapshots() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        fs::create_dir(&artifact_root).expect("artifact root");
        let storage = Storage::open(temporary.path().join("casework.db")).expect("storage");
        let engines = EngineRegistry::load_builtin().expect("engine catalog");
        let adapters = builtin_adapter_registry().expect("adapter registry");
        let service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            &artifact_root,
            temporary.path().join("integrity-signing-key"),
        );
        let case = service
            .create_case(&CreateCaseRequest {
                title: "CLI deletion fixture".into(),
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                assessment_intent: None,
                ai_generated_artifact: Default::default(),
                data_classes: vec![],
                requested_activities: vec![],
                source_kinds: vec![],
                not_applicable_source_kinds: vec![],
                declared_assets: vec![],
                notes: None,
            })
            .expect("case");
        let connector_root =
            case_connector_artifact_root(&artifact_root, &case.id).expect("case connector root");
        let connector_snapshot = connector_root.join("connector-snapshot-test.json");
        fs::write(&connector_snapshot, b"{}\n").expect("connector snapshot");
        let deletion = service.delete_case(&case.id).expect("database deletion");
        let result = service
            .delete_case_artifacts(
                &case.id,
                &deletion.artifacts.exact_path,
                &format!("DELETE {}", case.id),
            )
            .expect("confirmed artifact deletion");

        assert!(result.removed);
        assert!(!connector_snapshot.exists());
        assert!(!artifact_root.join(&case.id).exists());
    }
}
