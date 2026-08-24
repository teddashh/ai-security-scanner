export type AppMode = "native" | "demo";

export type PageId =
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
  platforms: CloudPlatform[];
  createdAt: string;
  updatedAt: string;
  phase: CasePhase;
  isDemo?: boolean;
  description?: string;
  latestRunId?: string;
}

export interface CreateCaseInput {
  name: string;
  organizationName: string;
  companySize: CompanySize;
  dataClasses: DataClass[];
  platforms: CloudPlatform[];
  description?: string;
}

export type CoverageState =
  | "discovered_authorized_scanned"
  | "discovered_not_authorized"
  | "authorized_incomplete"
  | "source_connected_none"
  | "source_unavailable_unknown";

export type SourceKind =
  | "cloud_organization"
  | "tenant"
  | "dns"
  | "certificate_transparency"
  | "load_balancer"
  | "iam_trust"
  | "git"
  | "terraform_state"
  | "billing";

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
  | "public_data"
  | "low_impact_external"
  | "active_external"
  // Backward-compatible aliases accepted from early snapshots.
  | "passive"
  | "active";
export type AuthorizationState = "authorized" | "pending" | "excluded" | "unknown";

export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  platform: CloudPlatform;
  locator: string;
  region?: string;
  owner?: string;
  coverageState: CoverageState;
  authorizationState: AuthorizationState;
  allowedModes: ScopeMode[];
  findingCount: number;
  lastObservedAt?: string;
  tags?: string[];
}

export interface ScopeGrant {
  id: string;
  assetId: string;
  modes: ScopeMode[];
  state: AuthorizationState;
  confirmedAt?: string;
  confirmedBy?: string;
  note?: string;
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

export interface EngineRun {
  id: string;
  engineId: string;
  engineName: string;
  category: string;
  version: string;
  digest: string;
  ruleVersion?: string;
  status: EngineRunStatus;
  progress: number;
  startedAt?: string;
  finishedAt?: string;
  findingCount: number;
  message?: string;
  resumable: boolean;
}

export interface ScanRun {
  id: string;
  caseId: string;
  label: string;
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
}

export interface ControlReference {
  framework: string;
  version: string;
  controlId: string;
  relationship: "related";
  note?: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  assetId: string;
  assetName: string;
  title: string;
  summary: string;
  impact: string;
  recommendation: string;
  expertType: string;
  severity: Severity;
  confidence: Confidence;
  priority: number;
  workflowState: FindingWorkflowState;
  evidence: Evidence[];
  controls: ControlReference[];
  officialReferences: string[];
  firstSeenAt: string;
  lastSeenAt: string;
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
}

export interface VerificationSummary {
  baselineRunId: string;
  comparisonRunId: string;
  baselineAt: string;
  comparisonAt: string;
  diffs: VerificationDiff[];
}

export type ExportFormat = "case_bundle" | "json" | "ocsf" | "oscal" | "html";

export interface CaseExport {
  id: string;
  caseId: string;
  format: ExportFormat;
  createdAt: string;
  fileName: string;
  sha256: string;
  signatureState: "unsigned" | "local_integrity";
  includesRawEvidence: boolean;
  path?: string;
  isDemo?: boolean;
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
  status: "ready" | "not_downloaded" | "unsupported" | "outdated";
}

export interface CaseWorkspace {
  case: AssessmentCase;
  coverage: CoverageRecord[];
  assets: Asset[];
  scopeGrants: ScopeGrant[];
  runs: ScanRun[];
  findings: Finding[];
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
    version?: string;
    detail: string;
  };
  engineCount?: number;
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
}

export interface ToastMessage {
  id: number;
  tone: "info" | "success" | "warning" | "danger";
  title: string;
  detail?: string;
}
