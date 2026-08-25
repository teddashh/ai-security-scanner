use crate::external_scope::{ExternalScopeGrant, ExternalScopeRequest};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

pub type Id = String;

pub fn new_id() -> Id {
    Uuid::new_v4().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Draft,
    Discovering,
    ScopeReview,
    Ready,
    Scanning,
    NeedsAttention,
    ReadyForHandoff,
    Verifying,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    General,
    PersonallyIdentifiableInformation,
    ProtectedHealthInformation,
    PaymentCardInformation,
    Financial,
    CredentialsAndSecrets,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationProfile {
    pub organization_name: String,
    pub employee_range: String,
    pub data_classes: Vec<DataClass>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceConnectionStatus {
    NotConnected,
    Connecting,
    Connected,
    NeedsReauthorization,
    Failed,
    /// The user explicitly declared this source area outside the current case.
    /// A reason is retained in source metadata; this is never inferred from a
    /// failed connection or an empty discovery result.
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    pub id: Id,
    pub kind: SourceKind,
    pub label: String,
    pub status: SourceConnectionStatus,
    pub connected_at: Option<DateTime<Utc>>,
    pub last_discovered_at: Option<DateTime<Utc>>,
    pub read_only: bool,
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    CloudOrganization,
    CloudAccount,
    Subscription,
    Project,
    Tenant,
    Domain,
    IpAddress,
    Host,
    WebService,
    CloudResource,
    Identity,
    Repository,
    FileSystem,
    IacProject,
    ContainerImage,
    ContainerRegistry,
    KubernetesCluster,
    Other,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalInputProfile {
    #[default]
    RepositoryWorkingTree,
    IacWorkingTree,
    ContainerImageOciLayout,
    KubernetesManifests,
    KubernetesNodeSnapshot,
}

impl LocalInputProfile {
    pub fn is_repository(&self) -> bool {
        matches!(self, Self::RepositoryWorkingTree)
    }

    pub fn asset_kind(self) -> AssetKind {
        match self {
            Self::RepositoryWorkingTree => AssetKind::Repository,
            Self::IacWorkingTree => AssetKind::IacProject,
            Self::ContainerImageOciLayout => AssetKind::ContainerImage,
            Self::KubernetesManifests => AssetKind::KubernetesCluster,
            Self::KubernetesNodeSnapshot => AssetKind::Host,
        }
    }

    pub fn source_kind(self) -> SourceKind {
        match self {
            Self::RepositoryWorkingTree => SourceKind::GitRepository,
            _ => SourceKind::FileSystem,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::RepositoryWorkingTree => "repository working tree",
            Self::IacWorkingTree => "infrastructure-as-code working tree",
            Self::ContainerImageOciLayout => "OCI image layout",
            Self::KubernetesManifests => "Kubernetes manifest tree",
            Self::KubernetesNodeSnapshot => "Kubernetes node configuration snapshot",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineInputContract {
    pub asset_kind: AssetKind,
    pub input_profile: LocalInputProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetIdentifier {
    pub namespace: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Id,
    pub kind: AssetKind,
    pub name: String,
    pub provider: Option<String>,
    pub region: Option<String>,
    pub identifiers: Vec<AssetIdentifier>,
    pub discovered_from: Vec<Id>,
    pub candidate: bool,
    pub owner_confirmed: bool,
    pub internet_exposed: Option<bool>,
    pub contains_sensitive_data: Option<bool>,
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Contains,
    HostedBy,
    ResolvesTo,
    Exposes,
    UsesIdentity,
    BuiltFrom,
    DeployedTo,
    References,
    Related,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRelation {
    pub id: Id,
    pub from_asset_id: Id,
    pub to_asset_id: Id,
    pub kind: RelationKind,
    pub evidence_ids: Vec<Id>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanPermission {
    InventoryRead,
    ConfigurationRead,
    LocalArtifactRead,
    PassiveExternalDiscovery,
    LowImpactExternalConnection,
    ActiveExternalTesting,
}

/// Questionnaire intent only. These values help retain what the user wants to
/// assess, but are deliberately separate from `ScanPermission`: recording an
/// activity can never create a scope grant or authorize an engine run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentActivity {
    ConfigurationAssessment,
    LocalArtifactAnalysis,
    LowImpactExternalChecks,
    ActiveExternalVulnerabilityTests,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeGrant {
    pub id: Id,
    pub asset_id: Id,
    pub permission: ScanPermission,
    pub confirmed_by: String,
    pub confirmed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub authorization_reference: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub external_scope: Option<ExternalScopeGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    DiscoveredAuthorizedScanned,
    DiscoveredNotAuthorized,
    AuthorizedScanIncomplete,
    SourceConnectedNothingDiscovered,
    SourceNotConnectedUnknown,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEntry {
    pub id: Id,
    pub scope_key: String,
    pub label: String,
    pub source_kind: SourceKind,
    pub asset_id: Option<Id>,
    pub status: CoverageStatus,
    pub explanation: String,
    pub last_run_id: Option<Id>,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineCategory {
    CloudInventory,
    CloudConfiguration,
    IdentityAndAccess,
    Microsoft365,
    ExternalAttackSurface,
    CodeAndSecrets,
    InfrastructureAsCode,
    ContainerAndSbom,
    Kubernetes,
    Host,
    SchemaAndExport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DistributionMode {
    BundledImage,
    PullPinnedImage,
    BuildFromPinnedSource,
    ExternalExecutable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageReference {
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
    pub signature_identity: Option<String>,
}

/// Release-time compatibility is an executable safety contract, not display metadata.
/// An engine remains unavailable until this record and the rest of its manifest agree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineCompatibility {
    pub knowledge_date: String,
    pub support_until: String,
    pub maintenance_owner: String,
    pub update_procedure: String,
    pub runnable: bool,
    pub artifact_state: EngineArtifactState,
    pub blocked_by: Vec<String>,
    pub knowledge_input: EngineKnowledgeInput,
    pub wrapper: EngineWrapper,
    pub packaging_plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineArtifactState {
    VerifiedUpstreamImage,
    ManagedBuildPlan,
    MultiComponentPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineKnowledgeInput {
    pub kind: KnowledgeInputKind,
    pub identifier: String,
    pub version: Option<String>,
    pub acquisition_source: Option<String>,
    pub pin_state: KnowledgePinState,
    /// Optional for backward compatibility with case records created before
    /// per-engine knowledge windows were made durable.
    #[serde(default)]
    pub knowledge_date: Option<String>,
    /// Optional for backward compatibility with historical case records.
    #[serde(default)]
    pub support_until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeInputKind {
    Embedded,
    ExternalPinned,
    ExternalPinRequired,
    NotApplicable,
    RuntimeLive,
    RuntimeBound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgePinState {
    AwaitingPin,
    RuntimeLive,
    RuntimeBound,
    PinnedOrNotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineWrapper {
    pub required: bool,
    pub strategy: String,
    pub entrypoint: Option<String>,
}

impl Default for EngineCompatibility {
    fn default() -> Self {
        Self {
            knowledge_date: "1970-01-01".into(),
            support_until: "1970-01-01".into(),
            maintenance_owner: "test fixture owner".into(),
            update_procedure: "docs/engine-maintenance.md".into(),
            runnable: false,
            artifact_state: EngineArtifactState::ManagedBuildPlan,
            blocked_by: vec!["test_manifest_not_released".into()],
            knowledge_input: EngineKnowledgeInput {
                kind: KnowledgeInputKind::NotApplicable,
                identifier: "test fixture".into(),
                version: None,
                acquisition_source: None,
                pin_state: KnowledgePinState::PinnedOrNotApplicable,
                knowledge_date: None,
                support_until: None,
            },
            wrapper: EngineWrapper {
                required: false,
                strategy: "test fixture".into(),
                entrypoint: None,
            },
            packaging_plan: "engines/images/test/plan.json".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineManifest {
    pub schema_version: String,
    pub id: String,
    pub display_name: String,
    pub category: EngineCategory,
    pub description: String,
    pub repository_url: String,
    pub homepage_url: Option<String>,
    pub license_spdx: String,
    pub distribution_mode: DistributionMode,
    pub image: Option<ImageReference>,
    pub source_revision: Option<String>,
    pub engine_version: Option<String>,
    pub rule_version: Option<String>,
    pub adapter_version: String,
    /// Exact provider identifiers accepted by this release. An empty list
    /// means the engine is provider-agnostic; a non-empty list requires an
    /// exact `Asset.provider` match and never guesses a missing provider.
    pub supported_providers: Vec<String>,
    pub supported_asset_kinds: Vec<AssetKind>,
    #[serde(default)]
    pub input_contracts: Vec<EngineInputContract>,
    /// Provider-specific execution closure for a multi-provider engine. A
    /// contract binds one exact provider/asset-kind pair to the product-owned
    /// launcher profile and the only provider endpoints that profile may use.
    /// Single-provider and provider-agnostic manifests may leave this empty.
    #[serde(default)]
    pub provider_execution_contracts: Vec<ProviderExecutionContract>,
    pub required_permissions: Vec<ScanPermission>,
    pub active_external: bool,
    pub default_enabled: bool,
    pub estimated_memory_mb: u32,
    pub estimated_disk_mb: u32,
    pub network_destinations: Vec<String>,
    pub output_formats: Vec<String>,
    pub command: Vec<String>,
    pub status: ManifestStatus,
    pub notices: Vec<String>,
    pub compatibility: EngineCompatibility,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionContract {
    pub provider: String,
    pub asset_kind: AssetKind,
    pub profile: String,
    pub network_destinations: Vec<String>,
}

impl EngineManifest {
    /// Empty means provider-agnostic. Provider-bound releases require an exact
    /// provider identity on the asset; missing or differently cased values are
    /// not inferred from asset kind, source kind, or upstream capabilities.
    pub fn supports_provider(&self, asset_provider: Option<&str>) -> bool {
        self.supported_providers.is_empty()
            || asset_provider.is_some_and(|provider| {
                self.supported_providers
                    .iter()
                    .any(|supported| supported == provider)
            })
    }

    /// Returns the exact provider execution contract for one asset. When a
    /// manifest declares contracts, provider and asset kind are a pair rather
    /// than two independent allowlists; this prevents, for example, treating
    /// an Azure subscription profile as an AWS cloud-account profile.
    pub fn provider_execution_contract(
        &self,
        asset_provider: Option<&str>,
        asset_kind: &AssetKind,
    ) -> Option<&ProviderExecutionContract> {
        let provider = asset_provider?;
        self.provider_execution_contracts
            .iter()
            .find(|contract| contract.provider == provider && contract.asset_kind == *asset_kind)
    }

    pub fn supports_asset(&self, asset: &Asset) -> bool {
        self.supported_asset_kinds.contains(&asset.kind)
            && self.supports_provider(asset.provider.as_deref())
            && (self.provider_execution_contracts.is_empty()
                || self
                    .provider_execution_contract(asset.provider.as_deref(), &asset.kind)
                    .is_some())
    }

    /// Returns the release-contract reason that prevents this manifest from being dispatched.
    /// Runtime callers must still validate the image, command, scope, and credentials.
    pub fn release_blocker(&self) -> Option<String> {
        if !self.compatibility.runnable {
            let blockers = if self.compatibility.blocked_by.is_empty() {
                "the compatibility record is not runnable".into()
            } else {
                self.compatibility.blocked_by.join(", ")
            };
            return Some(format!("engine release is not runnable: {blockers}"));
        }
        if self.status != ManifestStatus::Integrated {
            return Some("only integrated engine releases may be dispatched".into());
        }
        if !self.compatibility.blocked_by.is_empty() {
            return Some(format!(
                "runnable engine release still declares blockers: {}",
                self.compatibility.blocked_by.join(", ")
            ));
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Integrated,
    Experimental,
    ResearchOnly,
    Deprecated,
    LicenseReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineRunStatus {
    NotExecuted,
    Queued,
    Preparing,
    Running,
    Paused,
    Completed,
    PartiallyCompleted,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineRun {
    pub id: Id,
    pub scan_run_id: Id,
    pub engine_id: String,
    pub asset_ids: Vec<Id>,
    pub status: EngineRunStatus,
    pub progress_percent: u8,
    pub phase: String,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub resume_token: Option<String>,
    pub engine_version: Option<String>,
    pub image_digest: Option<String>,
    pub rule_version: Option<String>,
    pub adapter_version: String,
    #[serde(default)]
    pub manifest_schema_version: Option<String>,
    #[serde(default)]
    pub source_revision: Option<String>,
    #[serde(default)]
    pub repository_url: Option<String>,
    #[serde(default)]
    pub distribution_mode: Option<DistributionMode>,
    #[serde(default)]
    pub image_repository: Option<String>,
    #[serde(default)]
    pub command_sha256: Option<String>,
    #[serde(default)]
    pub knowledge_input: Option<EngineKnowledgeInput>,
    /// SHA-256 of the canonical, execution-relevant asset, target, permission,
    /// and external-policy contract. The canonical document deliberately
    /// excludes approval timestamps and other non-behavioural metadata so a
    /// semantically identical re-approval remains comparable.
    #[serde(default)]
    pub scope_contract_sha256: Option<String>,
    /// Exact project-authored control-mapping catalog used while adapting this
    /// run. Missing values identify legacy runs and fail closed during diffing.
    #[serde(default)]
    pub mapping_version: Option<String>,
    /// Exact fingerprint algorithm/schema identity used by the adapter.
    /// Future migrations must be explicitly allowlisted before differently
    /// versioned fingerprints can be compared.
    #[serde(default)]
    pub fingerprint_schema_version: Option<String>,
    #[serde(default)]
    pub runtime_provider: Option<String>,
    #[serde(default)]
    pub runtime_version: Option<String>,
    #[serde(default)]
    pub runtime_security_options: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub cleanup_removed: Option<bool>,
    #[serde(default)]
    pub cleanup_detail: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub raw_artifact_ids: Vec<Id>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: Id,
    pub case_id: Id,
    pub sequence: u32,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub knowledge_cutoff: DateTime<Utc>,
    /// Durable verification intent. Older case files omit this field and are
    /// treated as ordinary scans rather than verification runs.
    #[serde(default)]
    pub verification_baseline_run_id: Option<Id>,
    pub scope_grant_ids: Vec<Id>,
    /// Immutable copies of the grants effective when this run was planned.
    /// `scope_grant_ids` alone is insufficient because live grants may later
    /// expire or be replaced. Empty means a legacy run with unknown history.
    #[serde(default)]
    pub scope_grant_snapshots: Vec<ScopeGrant>,
    pub engine_runs: Vec<EngineRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Configuration,
    Observation,
    ExternalValidation,
    SourceCode,
    PackageInventory,
    UserDeclaration,
    RawToolOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Id,
    pub finding_id: Id,
    pub run_id: Id,
    /// Exact producing engine execution. `None` is retained only for cases
    /// written before engine-run evidence provenance was persisted.
    #[serde(default)]
    pub engine_run_id: Option<Id>,
    pub kind: EvidenceKind,
    pub engine_id: String,
    pub observed_at: DateTime<Utc>,
    pub summary: String,
    pub artifact_id: Id,
    pub artifact_sha256: String,
    pub pointer: Option<String>,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawArtifact {
    pub id: Id,
    pub case_id: Id,
    pub run_id: Id,
    pub engine_run_id: Id,
    pub relative_path: String,
    pub media_type: String,
    pub sha256: String,
    pub byte_length: u64,
    pub created_at: DateTime<Utc>,
    pub contains_sensitive_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlReference {
    pub framework: String,
    pub framework_version: String,
    pub control_id: String,
    pub title: String,
    pub relationship: String,
    pub rationale: String,
    pub mapping_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Unreviewed,
    #[serde(alias = "sent_for_review")]
    ExpertReviewRequested,
    Confirmed,
    FalsePositive,
    #[serde(
        alias = "remediation_planned",
        alias = "remediated_pending_verification"
    )]
    RemediationReported,
    #[serde(alias = "closed")]
    VerifiedResolved,
}

/// Immutable human handling history. Workflow decisions never replace scanner
/// evidence or observations, and an expiry is recorded explicitly rather than
/// silently changing the underlying finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingWorkflowEvent {
    pub id: Id,
    pub case_id: Id,
    pub finding_id: Id,
    pub from_status: FindingStatus,
    pub to_status: FindingStatus,
    pub decided_by: String,
    pub decided_at: DateTime<Utc>,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Id,
    pub case_id: Id,
    pub first_seen_run_id: Id,
    pub last_seen_run_id: Id,
    pub fingerprint: String,
    pub title: String,
    pub plain_language_summary: String,
    pub possible_impact: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub priority: u8,
    pub priority_reasons: Vec<String>,
    pub asset_ids: Vec<Id>,
    pub evidence: Vec<Evidence>,
    pub control_references: Vec<ControlReference>,
    pub recommendation: String,
    pub verification_guidance: String,
    pub rollback_considerations: Option<String>,
    pub official_references: Vec<String>,
    pub recommended_expert_type: String,
    pub status: FindingStatus,
    pub tags: Vec<String>,
}

/// A reversible, user-facing collection of related canonical findings. The
/// member findings and their evidence remain independent records; grouping
/// never merges fingerprints or discards scanner output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingGroup {
    pub id: Id,
    pub case_id: Id,
    pub title: String,
    pub finding_ids: Vec<Id>,
    pub rationale: String,
    pub grouped_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingGroupAction {
    Created,
    Removed,
}

/// Immutable grouping history keeps a removed group reconstructable without
/// retaining it as an active presentation object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingGroupEvent {
    pub id: Id,
    pub case_id: Id,
    pub group_id: Id,
    pub action: FindingGroupAction,
    pub title: String,
    pub finding_ids: Vec<Id>,
    pub rationale: String,
    pub actor: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingObservation {
    pub id: Id,
    pub run_id: Id,
    pub finding_id: Id,
    pub fingerprint: String,
    pub asset_ids: Vec<Id>,
    pub engine_ids: Vec<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence_hashes: Vec<String>,
    pub observed_at: DateTime<Utc>,
    /// Immutable normalized finding content for this exact run. Legacy cases
    /// may omit it and fall back to the latest canonical projection.
    #[serde(default)]
    pub finding_snapshot: Option<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDiffStatus {
    Resolved,
    StillPresent,
    NewlyObserved,
    Changed,
    UnableToVerify,
}

/// Machine-readable reason for a finding comparison result. These reasons are
/// additive detail and intentionally do not create extra top-level statuses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDiffReasonCode {
    CoordinateNotCompleted,
    ComparisonIdentityMissing,
    ScopeContractChanged,
    ManifestSchemaChanged,
    EngineVersionChanged,
    ImageChanged,
    RuleVersionChanged,
    KnowledgeInputChanged,
    AdapterVersionChanged,
    SourceRevisionChanged,
    RepositoryChanged,
    DistributionModeChanged,
    CommandChanged,
    MappingVersionChanged,
    FingerprintSchemaChanged,
    SeverityChanged,
    ConfidenceChanged,
    EvidenceChanged,
    AffectedAssetsChanged,
    ObservingEnginesChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingDiffReason {
    pub code: FindingDiffReasonCode,
    #[serde(default)]
    pub engine_id: Option<String>,
    #[serde(default)]
    pub asset_id: Option<Id>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDiff {
    pub fingerprint: String,
    pub baseline_finding_id: Option<Id>,
    pub current_finding_id: Option<Id>,
    pub status: FindingDiffStatus,
    pub explanation: String,
    /// Actual run-specific severities, rather than the mutable canonical
    /// finding's latest severity. Missing means the finding was not observed.
    #[serde(default)]
    pub baseline_severity: Option<Severity>,
    #[serde(default)]
    pub current_severity: Option<Severity>,
    /// Evidence changes are independent of `Changed`: severity, assets, or
    /// observing engines can change while evidence hashes remain identical.
    #[serde(default)]
    pub evidence_changed: bool,
    #[serde(default)]
    pub reasons: Vec<FindingDiffReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationComparison {
    pub id: Id,
    pub case_id: Id,
    pub baseline_run_id: Id,
    pub current_run_id: Id,
    pub created_at: DateTime<Utc>,
    pub diffs: Vec<FindingDiff>,
    /// True only when every planned engine/asset coordinate completed with an
    /// exactly comparable immutable execution identity in both runs.
    #[serde(default)]
    pub complete: bool,
    /// Run/coordinate-level uncertainty remains visible even when neither run
    /// produced a finding and the fingerprint diff is therefore empty.
    #[serde(default)]
    pub completeness_issues: Vec<FindingDiffReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseExport {
    pub id: Id,
    pub case_id: Id,
    pub run_id: Id,
    pub created_at: DateTime<Utc>,
    /// Exact backend-selected format. `None` is retained only when loading a
    /// record written by an older release that did not persist this field.
    #[serde(default)]
    pub format: Option<String>,
    pub path: String,
    pub sha256: String,
    pub signature: Option<String>,
    pub public_key: Option<String>,
    pub redaction_profile: String,
    /// Exact raw-file inclusion accounting. `None` means that a legacy record
    /// cannot truthfully answer the question; it must never be inferred from
    /// the redaction profile or filename.
    #[serde(default)]
    pub raw_artifacts_included: Option<usize>,
    #[serde(default)]
    pub raw_artifacts_omitted: Option<usize>,
    pub integrity_only_notice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentCase {
    #[serde(skip)]
    pub(crate) storage_revision: i64,
    pub id: Id,
    pub title: String,
    pub profile: OrganizationProfile,
    pub status: CaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub knowledge_cutoff: Option<DateTime<Utc>>,
    pub is_demo: bool,
    #[serde(default)]
    pub requested_activities: Vec<AssessmentActivity>,
    pub data_sources: Vec<DataSource>,
    pub assets: Vec<Asset>,
    pub asset_relations: Vec<AssetRelation>,
    pub scope_grants: Vec<ScopeGrant>,
    pub coverage: Vec<CoverageEntry>,
    pub scan_runs: Vec<ScanRun>,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub finding_groups: Vec<FindingGroup>,
    #[serde(default)]
    pub finding_group_events: Vec<FindingGroupEvent>,
    #[serde(default)]
    pub finding_workflow_events: Vec<FindingWorkflowEvent>,
    pub finding_observations: Vec<FindingObservation>,
    pub raw_artifacts: Vec<RawArtifact>,
    pub exports: Vec<CaseExport>,
    pub comparisons: Vec<VerificationComparison>,
}

impl AssessmentCase {
    pub fn new(title: String, profile: OrganizationProfile) -> Self {
        let now = Utc::now();
        Self {
            storage_revision: 0,
            id: new_id(),
            title,
            profile,
            status: CaseStatus::Draft,
            created_at: now,
            updated_at: now,
            knowledge_cutoff: None,
            is_demo: false,
            requested_activities: Vec::new(),
            data_sources: Vec::new(),
            assets: Vec::new(),
            asset_relations: Vec::new(),
            scope_grants: Vec::new(),
            coverage: Vec::new(),
            scan_runs: Vec::new(),
            findings: Vec::new(),
            finding_groups: Vec::new(),
            finding_group_events: Vec::new(),
            finding_workflow_events: Vec::new(),
            finding_observations: Vec::new(),
            raw_artifacts: Vec::new(),
            exports: Vec::new(),
            comparisons: Vec::new(),
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Projects time-bounded workflow decisions without deleting or rewriting
    /// their immutable audit events. An expired false-positive suppression
    /// returns to the status it temporarily replaced.
    pub(crate) fn apply_effective_finding_statuses(&mut self, now: DateTime<Utc>) {
        for finding in &mut self.findings {
            let latest = self
                .finding_workflow_events
                .iter()
                .filter(|event| event.finding_id == finding.id)
                .max_by(|left, right| {
                    left.decided_at
                        .cmp(&right.decided_at)
                        .then_with(|| left.id.cmp(&right.id))
                });
            let Some(latest) = latest else {
                continue;
            };
            finding.status = if latest.to_status == FindingStatus::FalsePositive
                && latest
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= now)
            {
                latest.from_status.clone()
            } else {
                latest.to_status.clone()
            };
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSummary {
    pub id: Id,
    pub title: String,
    pub organization_name: String,
    pub employee_range: String,
    pub data_classes: Vec<DataClass>,
    #[serde(default)]
    pub requested_activities: Vec<AssessmentActivity>,
    pub source_kinds: Vec<SourceKind>,
    pub notes: Option<String>,
    pub status: CaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_demo: bool,
    pub asset_count: usize,
    pub finding_count: usize,
    pub latest_run_id: Option<Id>,
}

impl From<&AssessmentCase> for CaseSummary {
    fn from(value: &AssessmentCase) -> Self {
        let mut source_kinds = Vec::new();
        for source in &value.data_sources {
            if !source_kinds.contains(&source.kind) {
                source_kinds.push(source.kind.clone());
            }
        }
        Self {
            id: value.id.clone(),
            title: value.title.clone(),
            organization_name: value.profile.organization_name.clone(),
            employee_range: value.profile.employee_range.clone(),
            data_classes: value.profile.data_classes.clone(),
            requested_activities: value.requested_activities.clone(),
            source_kinds,
            notes: value.profile.notes.clone(),
            status: value.status.clone(),
            created_at: value.created_at,
            updated_at: value.updated_at,
            is_demo: value.is_demo,
            asset_count: value.assets.len(),
            finding_count: value.findings.len(),
            latest_run_id: value
                .scan_runs
                .iter()
                .max_by(|left, right| {
                    left.sequence
                        .cmp(&right.sequence)
                        .then_with(|| left.created_at.cmp(&right.created_at))
                        .then_with(|| left.id.cmp(&right.id))
                })
                .map(|run| run.id.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHealth {
    pub provider: String,
    pub available: bool,
    pub phase: String,
    pub version: Option<String>,
    pub prerequisite: Option<String>,
    pub detail: String,
}

/// Secret-free, durable reminder that database deletion intentionally left a
/// case-scoped evidence directory behind for a separately confirmed action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactCleanupObligation {
    pub case_id: Id,
    pub exact_path: String,
    pub exists: bool,
    pub requires_explicit_confirmation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSnapshot {
    pub product_name: String,
    pub product_version: String,
    pub storage_path: String,
    pub cases: Vec<CaseSummary>,
    pub selected_case: Option<AssessmentCase>,
    pub runtime: RuntimeHealth,
    pub artifact_cleanup_obligations: Vec<ArtifactCleanupObligation>,
    pub engine_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
    pub organization_name: String,
    pub employee_range: String,
    #[serde(default)]
    pub data_classes: Vec<DataClass>,
    /// Desired assessment activities from the questionnaire. This field is
    /// informational and must never be treated as target authorization.
    #[serde(default)]
    pub requested_activities: Vec<AssessmentActivity>,
    /// Expected environments establish unknown coverage coordinates only;
    /// they do not connect a source or authorize any scanner.
    #[serde(default)]
    pub source_kinds: Vec<SourceKind>,
    /// Source areas the user explicitly excluded in the questionnaire. These
    /// become reasoned `not_applicable` coverage records, never green records.
    #[serde(default)]
    pub not_applicable_source_kinds: Vec<SourceKind>,
    /// User-entered coordinates become source-attributed candidate assets.
    /// They do not prove ownership or create a scope grant.
    #[serde(default)]
    pub declared_assets: Vec<DeclaredAssetInput>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredAssetKind {
    ExternalTarget,
    Repository,
    IacProject,
    ContainerImage,
    KubernetesCluster,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclaredAssetInput {
    pub kind: DeclaredAssetKind,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDecision {
    pub asset_id: Id,
    pub permissions: Vec<ScanPermission>,
    pub confirmed_by: String,
    pub authorization_reference: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub external_scope: Option<ExternalScopeRequest>,
}

/// Provider-native identifiers are part of the executable security boundary,
/// so discovery, planning, credential checkout, and the managed launcher use
/// the same canonical syntax rather than merely accepting parseable values.
pub fn valid_azure_subscription_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .ok()
        .is_some_and(|parsed| parsed.to_string() == value)
}

pub fn valid_gcp_project_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (6..=30).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_native_identifiers_require_canonical_exact_syntax() {
        assert!(valid_azure_subscription_id(
            "11111111-2222-3333-4444-555555555555"
        ));
        assert!(!valid_azure_subscription_id(
            "11111111-2222-3333-4444-55555555555A"
        ));
        assert!(valid_gcp_project_id("audit-project-123"));
        assert!(!valid_gcp_project_id("-audit-project"));
        assert!(!valid_gcp_project_id("audit-project-"));
        assert!(!valid_gcp_project_id("A-project"));
    }

    #[test]
    fn new_case_is_local_draft_without_implicit_coverage() {
        let case = AssessmentCase::new(
            "Initial assessment".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![DataClass::General],
                notes: None,
            },
        );

        assert_eq!(case.status, CaseStatus::Draft);
        assert!(case.coverage.is_empty());
        assert!(case.findings.is_empty());
        assert!(!case.is_demo);
    }

    #[test]
    fn coverage_unknown_is_distinct_from_connected_and_empty() {
        assert_ne!(
            CoverageStatus::SourceNotConnectedUnknown,
            CoverageStatus::SourceConnectedNothingDiscovered
        );
    }

    #[test]
    fn scan_run_without_verification_link_remains_backward_compatible() {
        let run: ScanRun = serde_json::from_value(serde_json::json!({
            "id": "run-1",
            "case_id": "case-1",
            "sequence": 1,
            "created_at": "2026-08-24T12:00:00Z",
            "completed_at": "2026-08-24T12:01:00Z",
            "knowledge_cutoff": "2026-08-24T12:00:00Z",
            "scope_grant_ids": [],
            "engine_runs": []
        }))
        .unwrap();

        assert!(run.verification_baseline_run_id.is_none());
    }

    #[test]
    fn case_summary_preserves_questionnaire_and_selects_latest_run_deterministically() {
        let mut case = AssessmentCase::new(
            "Assessment".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "50-249".into(),
                data_classes: vec![DataClass::CredentialsAndSecrets],
                notes: Some("Local note".into()),
            },
        );
        case.requested_activities = vec![AssessmentActivity::LocalArtifactAnalysis];
        case.data_sources = vec![
            DataSource {
                id: "source-1".into(),
                kind: SourceKind::GitRepository,
                label: "Repository".into(),
                status: SourceConnectionStatus::NotConnected,
                connected_at: None,
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            },
            DataSource {
                id: "source-2".into(),
                kind: SourceKind::GitRepository,
                label: "Repository duplicate".into(),
                status: SourceConnectionStatus::NotConnected,
                connected_at: None,
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            },
        ];
        let now = Utc::now();
        for (id, sequence) in [("newer", 2), ("older-vector-tail", 1)] {
            case.scan_runs.push(ScanRun {
                id: id.into(),
                case_id: case.id.clone(),
                sequence,
                created_at: now,
                completed_at: None,
                knowledge_cutoff: now,
                verification_baseline_run_id: None,
                scope_grant_ids: vec![],
                scope_grant_snapshots: vec![],
                engine_runs: vec![],
            });
        }

        let summary = CaseSummary::from(&case);
        assert_eq!(summary.employee_range, "50-249");
        assert_eq!(summary.data_classes, [DataClass::CredentialsAndSecrets]);
        assert_eq!(
            summary.requested_activities,
            [AssessmentActivity::LocalArtifactAnalysis]
        );
        assert_eq!(summary.source_kinds, [SourceKind::GitRepository]);
        assert_eq!(summary.notes.as_deref(), Some("Local note"));
        assert_eq!(summary.created_at, case.created_at);
        assert_eq!(summary.latest_run_id.as_deref(), Some("newer"));
    }
}
