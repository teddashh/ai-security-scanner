export type AppMode = "native" | "demo";

export type PageId =
  | "start"
  | "cases"
  | "coverage"
  | "progress"
  | "findings"
  | "export"
  | "verification";

export type CloudPlatform =
  | "aws"
  | "azure"
  | "gcp"
  | "m365"
  | "external"
  | "code"
  | "container"
  | "kubernetes";

export type CompanySize = "solo" | "small" | "medium" | "large";
export type DataClass = "pii" | "phi" | "payment" | "credentials" | "none";

export type AssessmentActivity =
  | "configuration_assessment"
  | "local_artifact_analysis"
  | "low_impact_external_checks"
  | "active_external_vulnerability_tests";

export type CasePhase =
  | "draft"
  | "discovering"
  | "scope_review"
  | "ready"
  | "scanning"
  | "needs_attention"
  | "ready_for_handoff"
  | "verifying"
  | "archived"
  | "complete"
  | "verification_due";

export interface AssessmentCase {
  id: string;
  name: string;
  organizationName: string;
  companySize: CompanySize;
  dataClasses: DataClass[];
  requestedActivities: AssessmentActivity[];
  platforms: CloudPlatform[];
  createdAt: string;
  updatedAt: string;
  phase: CasePhase;
  isDemo?: boolean;
  description?: string;
  latestRunId?: string;
  /** Present on list summaries without loading the full workspace. */
  assetCount?: number;
  /** Canonical finding count across the case, not a selected-run count. */
  findingCount?: number;
}

export interface CreateCaseInput {
  name: string;
  organizationName: string;
  companySize: CompanySize;
  dataClasses: DataClass[];
  requestedActivities: AssessmentActivity[];
  platforms: CloudPlatform[];
  knownAssets: KnownAssetInput[];
  description?: string;
}

export type KnownAssetKind =
  | "external_target"
  | "repository"
  | "iac_project"
  | "container_image"
  | "kubernetes_cluster";

export interface KnownAssetInput {
  kind: KnownAssetKind;
  value: string;
  /** Questionnaire intent only. It never authorizes private-network access. */
  internetExposure?: "public" | "internal";
  /** Website context only. It is a later scope-form preset, never authorization. */
  webService?: {
    protocol: "http" | "https";
    port: number;
    path: string;
  };
}

export type CoverageState =
  | "discovered_authorized_scanned"
  | "discovered_not_authorized"
  | "authorized_incomplete"
  | "source_connected_none"
  | "source_unavailable_unknown"
  | "not_applicable";

export type SourceKind =
  | "aws_organization"
  | "azure_tenant"
  | "gcp_organization"
  | "microsoft365_tenant"
  | "dns"
  | "certificate_transparency"
  | "billing"
  | "git_repository"
  | "terraform_state"
  | "kubernetes_cluster"
  | "container_registry"
  | "file_system"
  | "user_declared";

export type SnapshotParserProfile =
  | "cloudquery"
  | "steampipe"
  | "prowler"
  | "scubagear"
  | "maester"
  | "dns-response"
  | "certificate-transparency-response"
  | "billing-export"
  | "git-manifest"
  | "terraform-state"
  | "kubernetes-manifest"
  | "container-registry-manifest"
  | "filesystem-manifest"
  | "user-declared-manifest";

export interface ConnectSourceSnapshotInput {
  caseId: string;
  sourceKind: SourceKind;
  label: string;
  profile: SnapshotParserProfile;
  selectedPath: string;
}

export type LocalInputProfile =
  | "repository_working_tree"
  | "iac_working_tree"
  | "container_image_oci_layout"
  | "kubernetes_manifests"
  | "kubernetes_node_snapshot";

export interface AttachWorkspaceSnapshotInput {
  caseId: string;
  label: string;
  selectedPath: string;
  inputProfile: LocalInputProfile;
}

export type ProviderSourceProfile =
  | "aws_organization_read_only_session"
  | "azure_tenant_read_only_access_token"
  | "gcp_organization_read_only_access_token"
  | "microsoft365_tenant_read_only_access_token";

export interface AwsNativeAuthorizationConfig {
  start_url: string;
  region: string;
  account_id: string;
  role_name: string;
  role_arn: string;
}

export interface MicrosoftNativeAuthorizationConfig {
  tenant_id: string;
  public_client_id: string;
  profile: ProviderSourceProfile;
  subscription_id: string | null;
}

export interface GcpNativeAuthorizationConfig {
  public_client_id: string;
  redirect_uri: string;
  organization_id: string;
}

export type ProviderAuthorizationConfig =
  | { provider: "aws"; config: AwsNativeAuthorizationConfig }
  | { provider: "azure"; config: MicrosoftNativeAuthorizationConfig }
  | { provider: "gcp"; config: GcpNativeAuthorizationConfig }
  | { provider: "microsoft365"; config: MicrosoftNativeAuthorizationConfig };

export interface BeginProviderAuthorizationInput {
  case_id: string;
  source_id: string;
  allowed_engine_ids: string[];
  max_checkouts: number;
  authorization: ProviderAuthorizationConfig;
}

export interface ProviderDevicePrompt {
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  verification_uri: string;
  verification_uri_complete: string | null;
  user_code: string;
  expires_at: string;
  poll_interval_seconds: number;
  safety_notice: string;
}

export interface ProviderPkcePrompt {
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  authorization_url: string;
  redirect_uri: string;
  expires_at: string;
  safety_notice: string;
}

export type ProviderAuthorizationPrompt =
  | { flow: "device"; session_id: string; prompt: ProviderDevicePrompt }
  | { flow: "pkce"; session_id: string; prompt: ProviderPkcePrompt };

export interface InstalledProviderAuthorization {
  schema_version: string;
  case_id: string;
  source_id: string;
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  source_kind: SourceKind;
  profile: ProviderSourceProfile;
  credential_source: string;
  provider_identity: string;
  permissions: string[];
  expires_at: string;
  allowed_engine_ids: string[];
  max_checkouts: number;
  safety_notice: string;
}

export type ProviderAuthorizationProgress =
  | { status: "pending"; session_id: string; retry_after_seconds: number }
  | { status: "installed"; authorization: InstalledProviderAuthorization };

export type BootstrapOperatorConfig =
  | { provider: "aws"; administrator: AwsNativeAuthorizationConfig }
  | { provider: "azure"; authorization: MicrosoftNativeAuthorizationConfig }
  | { provider: "gcp"; authorization: GcpNativeAuthorizationConfig; project_id: string }
  | { provider: "microsoft365"; authorization: MicrosoftNativeAuthorizationConfig };

export interface BootstrapRequest {
  schema_version: "1.0.0";
  case_id: string;
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  scan_identity_name: string;
  capabilities: Array<
    "inventory" | "configuration" | "identity_and_access" | "security_posture" | "audit_metadata"
  >;
  expires_at: string;
}

export interface ProviderBootstrapPlan {
  schema_version: string;
  case_id: string;
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  scan_identity_name: string;
  capabilities: BootstrapRequest["capabilities"];
  provider_authentication_url: string;
  allowed_endpoint_hosts: string[];
  operations: Array<{
    operation_id: string;
    description: string;
    mutates_provider: boolean;
    provider_api_operations: string[];
  }>;
  template_media_type: string;
  template_sha256: string;
  template: string;
  expires_at: string;
  cleanup_obligations: Array<{ obligation_id: string; description: string; required: boolean }>;
  safety_notice: string;
}

export interface ExecuteProviderBootstrapInput {
  operationId: string;
  execution: {
    schema_version: "1.0.0";
    bootstrap: BootstrapRequest;
    operator: BootstrapOperatorConfig;
  };
  sourceId: string;
  allowedEngineIds: string[];
  maxCheckouts: number;
}

export interface ProviderBootstrapInstalled {
  operationId: string;
  authorization: InstalledProviderAuthorization;
  cleanupLedgerPath: string;
}

export type BootstrapCleanupStatus =
  | "pending"
  | "in_progress"
  | "retryable_failure"
  | "waiting_for_credential_expiry"
  | "completed";

export interface BootstrapCleanupObligationSummary {
  operationId: string;
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  caseId: string;
  schemaVersion: "1.0.0" | "1.0.0-partial";
  status: BootstrapCleanupStatus;
  totalItems: number;
  pendingItems: number;
  inProgressItems: number;
  retryableItems: number;
  waitingItems: number;
  completedItems: number;
  createdAt: string;
}

export interface CaseArtifactDeletionPlan {
  caseId: string;
  exactPath: string;
  exists: boolean;
  requiresExplicitConfirmation: boolean;
}

export interface CaseDeletionResponse {
  accepted: boolean;
  message: string;
  databaseRecordDeleted: boolean;
  artifacts: CaseArtifactDeletionPlan;
}

export interface CaseArtifactCleanupInput {
  caseId: string;
  exactPath: string;
  confirmation: string;
}

export interface CaseArtifactCleanupResult {
  removed: boolean;
  exactPath: string;
  recoverable: false;
}

export interface CoverageRecord {
  id: string;
  label: string;
  platform: CloudPlatform;
  sourceKind: SourceKind;
  state: CoverageState;
  assetCount: number;
  detail: string;
  lastCheckedAt?: string;
}

export interface ConnectedSource {
  id: string;
  kind: SourceKind;
  label: string;
  status: "not_connected" | "connecting" | "connected" | "needs_reauthorization" | "failed" | "not_applicable";
  readOnly: boolean;
  connectedAt?: string;
  lastDiscoveredAt?: string;
}

export type AssetType =
  | "cloud_account"
  | "subscription"
  | "project"
  | "tenant"
  | "domain"
  | "ip"
  | "repository"
  | "image"
  | "cluster"
  | "service"
  | "storage";

export type ScopeMode =
  | "inventory"
  | "configuration"
  | "local_artifact"
  | "public_data"
  | "low_impact_external"
  | "active_external"
  // Backward-compatible aliases accepted from early snapshots.
  | "passive"
  | "active";
export type AuthorizationState = "authorized" | "pending" | "excluded" | "unknown";

export interface AssetIdentifier {
  namespace: string;
  value: string;
}

export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  platform: CloudPlatform;
  locator: string;
  identifiers?: AssetIdentifier[];
  region?: string;
  owner?: string;
  internetExposed?: boolean;
  containsSensitiveData?: boolean;
  coverageState: CoverageState;
  authorizationState: AuthorizationState;
  allowedModes: ScopeMode[];
  findingCount: number;
  lastObservedAt?: string;
  tags?: string[];
  localInputProfile?: LocalInputProfile;
  declaredWebService?: {
    protocol: "http" | "https";
    port: number;
    path: string;
  };
}

export type ExternalActivity = "passive_public_discovery" | "low_impact_external" | "active_external";
export type TransportProtocol = "tcp" | "udp" | "tls" | "http" | "https";

export interface ExternalRatePolicy {
  requestsPerSecond: number;
  concurrency: number;
  timeoutSeconds: number;
}

export interface ExternalTemplatePolicy {
  revision: string;
  allowedTemplateIds: string[];
  allowHeadless: boolean;
  allowOutOfBand: boolean;
  allowFuzzing: boolean;
  allowFileUpload: boolean;
  allowDenialOfService: false;
  allowCredentialAttacks: false;
}

export interface ExternalScopeRequest {
  target: string;
  ports: number[];
  protocol: TransportProtocol;
  activity: ExternalActivity;
  ratePolicy: ExternalRatePolicy;
  templatePolicy: ExternalTemplatePolicy;
  assertedAuthority: string;
  allowSensitiveNetworks: boolean;
}

export interface FrozenExternalScope extends ExternalScopeRequest {
  id: string;
  caseId: string;
  assetId: string;
  targetKind: "hostname" | "address" | "network";
  approvedBy: string;
  approvedAt: string;
  expiresAt: string;
}

export interface ScopeGrant {
  id: string;
  assetId: string;
  modes: ScopeMode[];
  state: AuthorizationState;
  confirmedAt?: string;
  confirmedBy?: string;
  note?: string;
  externalScope?: FrozenExternalScope;
}

export type RunStatus =
  | "queued"
  | "running"
  | "paused"
  | "completed"
  | "partial"
  | "failed"
  | "cancelled";

export type EngineRunStatus =
  | "pending"
  | "running"
  | "paused"
  | "completed"
  | "partial"
  | "failed"
  | "not_executed"
  | "cancelled";

export type ExecutionStage =
  | "planned"
  | "preflight"
  | "pulling_image"
  | "running"
  | "capturing_artifacts"
  | "adapting_artifacts"
  | "captured_awaiting_adapter"
  | "cleanup_pending"
  | "completed"
  | "cancelled"
  | "failed";

export interface EngineCheckpoint {
  attempt: number;
  stage: ExecutionStage;
  artifactCount: number;
  cleanupCompleted: boolean;
  scopeBound: boolean;
  lastError?: string;
}

export interface EngineRun {
  id: string;
  engineId: string;
  engineName: string;
  category: string;
  version: string;
  digest: string;
  ruleVersion?: string;
  adapterVersion?: string;
  manifestSchemaVersion?: string;
  sourceRevision?: string;
  repositoryUrl?: string;
  distributionMode?: string;
  imageRepository?: string;
  commandSha256?: string;
  knowledgeInput?: {
    kind: string;
    identifier: string;
    version?: string;
    acquisitionSource?: string;
    pinState: string;
    knowledgeDate?: string;
    supportUntil?: string;
  };
  runtimeProvider?: string;
  runtimeVersion?: string;
  runtimeSecurityOptions?: string;
  exitCode?: number;
  cleanupRemoved?: boolean;
  cleanupDetail?: string;
  warnings: string[];
  status: EngineRunStatus;
  progress: number;
  phase: string;
  startedAt?: string;
  finishedAt?: string;
  assetIds: string[];
  rawArtifactCount: number;
  findingCount: number;
  /** False only when legacy evidence lacks an exact engine-run identifier. */
  findingCountKnown?: boolean;
  message?: string;
  errorCode?: string;
  checkpoint?: EngineCheckpoint;
  resumable: boolean;
}

export interface ScanRun {
  id: string;
  caseId: string;
  label: string;
  verificationBaselineRunId?: string;
  status: RunStatus;
  progress: number;
  startedAt: string;
  finishedAt?: string;
  knowledgeDate: string;
  engineRuns: EngineRun[];
  coveredAssetCount: number;
  totalAssetCount: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type FindingWorkflowState =
  | "unreviewed"
  | "expert_review_requested"
  | "confirmed"
  | "unconfirmed"
  | "assigned"
  | "false_positive"
  | "remediation_reported"
  | "remediated_pending_verification"
  | "verified_resolved";

export interface Evidence {
  id: string;
  sourceEngine: string;
  observedAt: string;
  summary: string;
  rawArtifactHash: string;
  rawArtifactPath?: string;
  kind?: string;
  runId?: string;
  engineRunId?: string;
  artifactId?: string;
  redacted?: boolean;
}

export interface ControlReference {
  framework: string;
  version: string;
  controlId: string;
  relationship: "related";
  title?: string;
  rationale?: string;
  mappingVersion?: string;
  note?: string;
}

export interface Finding {
  id: string;
  caseId?: string;
  fingerprint: string;
  assetId: string;
  assetIds?: string[];
  assetName: string;
  title: string;
  summary: string;
  impact: string;
  recommendation: string;
  expertType: string;
  severity: Severity;
  confidence: Confidence;
  priority: number;
  priorityReasons?: string[];
  workflowState: FindingWorkflowState;
  evidence: Evidence[];
  controls: ControlReference[];
  officialReferences: string[];
  verificationGuidance?: string;
  rollbackConsiderations?: string;
  tags?: string[];
  firstSeenRunId?: string;
  lastSeenRunId?: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface FindingWorkflowEvent {
  id: string;
  findingId: string;
  fromStatus: FindingWorkflowState;
  toStatus: FindingWorkflowState;
  decidedBy: string;
  decidedAt: string;
  reason: string;
  expiresAt?: string;
}

export interface FindingGroup {
  id: string;
  caseId: string;
  title: string;
  findingIds: string[];
  rationale: string;
  groupedBy: string;
  createdAt: string;
}

export type FindingGroupAction = "created" | "removed";

export interface FindingGroupEvent {
  id: string;
  caseId: string;
  groupId: string;
  action: FindingGroupAction;
  title: string;
  findingIds: string[];
  /** Creation rationale for `created`; explicit removal reason for `removed`. */
  rationale: string;
  actor: string;
  occurredAt: string;
}

export interface FindingGroupInput {
  caseId: string;
  title: string;
  findingIds: string[];
  rationale: string;
  groupedBy: string;
}

export interface FindingUngroupInput {
  caseId: string;
  groupId: string;
  removedBy: string;
  reason: string;
}

export interface FindingWorkflowUpdateInput {
  caseId: string;
  findingId: string;
  status: "unreviewed" | "expert_review_requested" | "confirmed" | "false_positive" | "remediation_reported" | "verified_resolved";
  decidedBy: string;
  reason: string;
  expiresAt?: string;
}

export type DiffState = "resolved" | "persistent" | "new" | "unverifiable";

export interface VerificationDiff {
  id: string;
  findingId?: string;
  title: string;
  assetName: string;
  state: DiffState;
  beforeSeverity?: Severity;
  afterSeverity?: Severity;
  explanation: string;
  evidenceChanged: boolean;
  changeReasons?: Array<{
    code: string;
    engineId?: string;
    assetId?: string;
    detail: string;
  }>;
}

export interface VerificationSummary {
  baselineRunId: string;
  comparisonRunId: string;
  baselineAt: string;
  comparisonAt: string;
  complete?: boolean;
  completenessIssues?: Array<{
    code: string;
    engineId?: string;
    assetId?: string;
    detail: string;
  }>;
  diffs: VerificationDiff[];
}

export type ExportFormat = "case_bundle" | "json" | "ocsf" | "oscal" | "html";

export interface CaseExport {
  id: string;
  caseId: string;
  /** Missing only for a record written before exact export metadata existed. */
  format?: ExportFormat;
  createdAt: string;
  fileName: string;
  sha256: string;
  signatureState: "unsigned" | "local_integrity";
  includesRawEvidence?: boolean;
  rawArtifactsIncluded?: number;
  rawArtifactsOmitted?: number;
  path?: string;
  isDemo?: boolean;
}

export interface ExportPreview {
  caseId: string;
  runId: string;
  format: ExportFormat;
  redactionProfile: "standard" | "none";
  dataSourceCount: number;
  coverageEntryCount: number;
  assetCount: number;
  candidateAssetCount: number;
  canonicalFindingCount: number;
  selectedRunFindingCount: number;
  evidenceIndexCount: number;
  selectedRunEvidenceCount: number;
  scanRunCount: number;
  selectedEngineRunCount: number;
  externalScopeGrantCount: number;
  incompleteEngineRunCount: number;
  notExecutedEngineRunCount: number;
  unknownSourceCount: number;
  connectedNoAssetCount: number;
  rawArtifactCount: number;
  rawArtifactsIncluded: number;
  rawArtifactsOmitted: number;
  sensitiveRawArtifactsOmitted: number;
  sensitiveDataWarning: string;
}

export interface EngineManifest {
  id: string;
  name: string;
  category: string;
  version: string;
  imageDigest: string;
  license: string;
  redistribution: "bundled" | "on_demand" | "external";
  platforms: CloudPlatform[];
  supportedProviders: CloudPlatform[];
  status: "ready" | "not_downloaded" | "unsupported" | "outdated";
  knowledgeDate?: string;
  supportUntil?: string;
  supportStatus: "supported" | "expired" | "unknown";
}

export interface CaseWorkspace {
  case: AssessmentCase;
  sources: ConnectedSource[];
  coverage: CoverageRecord[];
  assets: Asset[];
  scopeGrants: ScopeGrant[];
  runs: ScanRun[];
  findings: Finding[];
  findingGroups: FindingGroup[];
  findingGroupEvents: FindingGroupEvent[];
  workflowEvents: FindingWorkflowEvent[];
  exports: CaseExport[];
  verification?: VerificationSummary;
}

export interface AppSnapshot {
  cases: AssessmentCase[];
  selectedCaseId?: string;
  workspace?: CaseWorkspace;
  engineManifests: EngineManifest[];
  generatedAt: string;
  provenance: "native" | "demo";
  productName?: string;
  productVersion?: string;
  storagePath?: string;
  runtime?: {
    provider: string;
    available: boolean;
    phase: string;
    version?: string;
    prerequisite?: string;
    detail: string;
  };
  artifactCleanupObligations?: CaseArtifactDeletionPlan[];
  engineCount?: number;
}

export type ManagedRuntimeSetupPhase =
  | "idle"
  | "install"
  | "prerequisite"
  | "download"
  | "init"
  | "start"
  | "verify"
  | "completed"
  | "failed"
  | "cancelled";

export type ManagedRuntimeSetupFailureReason =
  | "windows_wsl_not_installed"
  | "windows_wsl_optional_feature_disabled"
  | "windows_wsl_update_required"
  | "windows_restart_required"
  | "windows_wsl_command_failed";

export type ManagedRuntimeSetupNextAction =
  | "install_wsl"
  | "enable_wsl_optional_features"
  | "update_wsl"
  | "restart_windows"
  | "retry_wsl_check";

export interface ManagedRuntimeSetupStatus {
  phase: ManagedRuntimeSetupPhase;
  active: boolean;
  prerequisiteRepairActive: boolean;
  cancelRequested: boolean;
  receivedBytes: number;
  totalBytes?: number;
  progressPercent?: number;
  resumedFromBytes: number;
  canCancel: boolean;
  canRetry: boolean;
  failureReason?: ManagedRuntimeSetupFailureReason;
  nextAction?: ManagedRuntimeSetupNextAction;
  detail: string;
}

export type ManagedRuntimePrerequisiteRepairOutcome =
  | "completed"
  | "cancelled"
  | "failed";

export interface ManagedRuntimePrerequisiteRepairResult {
  outcome: ManagedRuntimePrerequisiteRepairOutcome;
  restartRequired: boolean;
  detail: string;
}

export interface ServiceResult<T> {
  data: T;
  mode: AppMode;
  notice?: string;
}

export interface ExportCaseInput {
  caseId: string;
  format: ExportFormat;
  includeRawEvidence: boolean;
  redactSensitiveValues: boolean;
  destination?: string;
}

export interface ToastMessage {
  id: number;
  tone: "info" | "success" | "warning" | "danger";
  title: string;
  detail?: string;
}
