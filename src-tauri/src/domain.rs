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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    DiscoveredAuthorizedScanned,
    DiscoveredNotAuthorized,
    AuthorizedScanIncomplete,
    SourceConnectedNothingDiscovered,
    SourceNotConnectedUnknown,
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
    pub supported_asset_kinds: Vec<AssetKind>,
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
    pub scope_grant_ids: Vec<Id>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    SentForReview,
    Confirmed,
    FalsePositive,
    RemediationPlanned,
    RemediatedPendingVerification,
    Closed,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDiff {
    pub fingerprint: String,
    pub baseline_finding_id: Option<Id>,
    pub current_finding_id: Option<Id>,
    pub status: FindingDiffStatus,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationComparison {
    pub id: Id,
    pub case_id: Id,
    pub baseline_run_id: Id,
    pub current_run_id: Id,
    pub created_at: DateTime<Utc>,
    pub diffs: Vec<FindingDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseExport {
    pub id: Id,
    pub case_id: Id,
    pub run_id: Id,
    pub created_at: DateTime<Utc>,
    pub path: String,
    pub sha256: String,
    pub signature: Option<String>,
    pub public_key: Option<String>,
    pub redaction_profile: String,
    pub integrity_only_notice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentCase {
    pub id: Id,
    pub title: String,
    pub profile: OrganizationProfile,
    pub status: CaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub knowledge_cutoff: Option<DateTime<Utc>>,
    pub is_demo: bool,
    pub data_sources: Vec<DataSource>,
    pub assets: Vec<Asset>,
    pub asset_relations: Vec<AssetRelation>,
    pub scope_grants: Vec<ScopeGrant>,
    pub coverage: Vec<CoverageEntry>,
    pub scan_runs: Vec<ScanRun>,
    pub findings: Vec<Finding>,
    pub finding_observations: Vec<FindingObservation>,
    pub raw_artifacts: Vec<RawArtifact>,
    pub exports: Vec<CaseExport>,
    pub comparisons: Vec<VerificationComparison>,
}

impl AssessmentCase {
    pub fn new(title: String, profile: OrganizationProfile) -> Self {
        let now = Utc::now();
        Self {
            id: new_id(),
            title,
            profile,
            status: CaseStatus::Draft,
            created_at: now,
            updated_at: now,
            knowledge_cutoff: None,
            is_demo: false,
            data_sources: Vec::new(),
            assets: Vec::new(),
            asset_relations: Vec::new(),
            scope_grants: Vec::new(),
            coverage: Vec::new(),
            scan_runs: Vec::new(),
            findings: Vec::new(),
            finding_observations: Vec::new(),
            raw_artifacts: Vec::new(),
            exports: Vec::new(),
            comparisons: Vec::new(),
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSummary {
    pub id: Id,
    pub title: String,
    pub organization_name: String,
    pub status: CaseStatus,
    pub updated_at: DateTime<Utc>,
    pub is_demo: bool,
    pub asset_count: usize,
    pub finding_count: usize,
    pub latest_run_id: Option<Id>,
}

impl From<&AssessmentCase> for CaseSummary {
    fn from(value: &AssessmentCase) -> Self {
        Self {
            id: value.id.clone(),
            title: value.title.clone(),
            organization_name: value.profile.organization_name.clone(),
            status: value.status.clone(),
            updated_at: value.updated_at,
            is_demo: value.is_demo,
            asset_count: value.assets.len(),
            finding_count: value.findings.len(),
            latest_run_id: value.scan_runs.last().map(|run| run.id.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHealth {
    pub provider: String,
    pub available: bool,
    pub version: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSnapshot {
    pub product_name: String,
    pub product_version: String,
    pub storage_path: String,
    pub cases: Vec<CaseSummary>,
    pub selected_case: Option<AssessmentCase>,
    pub runtime: RuntimeHealth,
    pub engine_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
    pub organization_name: String,
    pub employee_range: String,
    #[serde(default)]
    pub data_classes: Vec<DataClass>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDecision {
    pub asset_id: Id,
    pub permissions: Vec<ScanPermission>,
    pub confirmed_by: String,
    pub authorization_reference: Option<String>,
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
