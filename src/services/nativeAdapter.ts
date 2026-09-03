import type {
  AppSnapshot,
  AssessmentCase,
  AssessmentActivity,
  AiGeneratedArtifactAnswer,
  Asset,
  AssetType,
  BeginnerMasterReport,
  CaseExport,
  ExportPreview,
  ReportLocale,
  CasePhase,
  CaseWorkspace,
  CloudPlatform,
  CompanySize,
  Confidence,
  ConnectedSource,
  CoverageRecord,
  CoverageState,
  DataClass,
  DiffState,
  EngineManifest,
  EngineCheckpoint,
  EngineFailureKind,
  EngineRecoveryAction,
  EngineRun,
  EngineRunStatus,
  EngineTaskKind,
  ExternalActivity,
  FrozenExternalScope,
  ExportFormat,
  Finding,
  FindingGroup,
  FindingGroupEvent,
  FindingWorkflowState,
  LocalInputProfile,
  LocalhostTcpObservation,
  LocalNetworkCandidateInventory,
  LocalNetworkCandidateStatus,
  LocalPrivateSubnetCandidate,
  ManagedRuntimePrerequisiteRepairOutcome,
  ManagedRuntimePrerequisiteRepairResult,
  ManagedRuntimeSetupFailureReason,
  ManagedRuntimeSetupNextAction,
  ManagedRuntimeSetupPhase,
  ManagedRuntimeSetupStatus,
  ProviderSourceProfile,
  RunStatus,
  ScanRequestOutcome,
  ScopeGrant,
  ScopeMode,
  Severity,
  SourceKind,
  SourceCapabilityProvider,
  TransportProtocol,
  VerificationSummary,
} from "../types";
import { getActiveLocale } from "../i18n/core";
import { explicitTargetRequiresSensitiveNetworkAllowance } from "../caseForm";
import {
  isExactBuiltInLocalhostQuickScanEngine,
  isExactBuiltInLocalhostQuickScanRun,
} from "../localhostQuickScan";
import { useCaseById } from "../useCases";
import type { UseCaseId } from "../useCases";

const adapterText = (en: string, zhTW: string): string =>
  getActiveLocale() === "en" ? en : zhTW;

const localizedList = (values: string[]): string =>
  values.join(getActiveLocale() === "en" ? ", " : "、");

/** Snake-case DTOs emitted by src-tauri/src/domain.rs. */
type NativeCaseProductIdentity = {
  kind: "localhost_quick_scan";
  port: number;
};

export interface NativeCaseSummary {
  id: string;
  title: string;
  assessment_intent?: string | null;
  ai_generated_artifact?: string | null;
  organization_name: string;
  employee_range: string;
  data_classes: string[];
  requested_activities: string[];
  source_kinds: string[];
  /** Absent snapshots retain the legacy source list. */
  applicable_source_kinds?: string[];
  notes: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  is_demo: boolean;
  asset_count: number;
  finding_count: number;
  latest_run_id: string | null;
  product_identity?: NativeCaseProductIdentity | null;
}

interface NativeDataSource {
  id: string;
  kind: string;
  label: string;
  status: string;
  connected_at: string | null;
  last_discovered_at: string | null;
  read_only: boolean;
  metadata?: Record<string, unknown>;
}

interface NativeAsset {
  id: string;
  kind: string;
  name: string;
  provider: string | null;
  region: string | null;
  identifiers: Array<{ namespace: string; value: string }>;
  discovered_from: string[];
  candidate: boolean;
  owner_confirmed: boolean;
  internet_exposed?: boolean | null;
  contains_sensitive_data?: boolean | null;
  metadata?: Record<string, unknown>;
}

interface NativeExternalScope {
  id: string;
  case_id: string;
  asset_id: string;
  target: { kind: "hostname" | "address" | "network"; value: string };
  ports: number[];
  protocol: TransportProtocol;
  activity: ExternalActivity;
  rate_policy: {
    requests_per_second: number;
    concurrency: number;
    timeout_seconds: number;
  };
  template_policy: {
    revision: string;
    allowed_template_ids: string[];
    allow_headless: boolean;
    allow_out_of_band: boolean;
    allow_fuzzing: boolean;
    allow_file_upload: boolean;
    allow_denial_of_service: false;
    allow_credential_attacks: false;
  };
  asserted_authority: string;
  approved_by: string;
  approved_at: string;
  expires_at: string;
  allow_sensitive_networks: boolean;
}

interface NativeScopeGrant {
  id: string;
  asset_id: string;
  permission: string;
  confirmed_by: string;
  confirmed_at: string;
  notes: string | null;
  external_scope?: NativeExternalScope | null;
}

interface NativeCoverageEntry {
  id: string;
  label: string;
  source_kind: string;
  asset_id: string | null;
  status: string;
  explanation: string;
  last_run_id?: string | null;
  observed_at: string | null;
}

interface NativeEngineRun {
  id: string;
  engine_id: string;
  task_kind?:
    | { kind: "catalog_engine" }
    | {
        kind: "built_in_localhost_tcp";
        port: number;
        timeout_ms: number;
        payload_bytes: number;
      };
  localhost_tcp_observation?: {
    outcome: string;
    observed_at: string;
  } | null;
  asset_ids: string[];
  status: string;
  progress_percent: number;
  phase: string;
  started_at: string | null;
  finished_at: string | null;
  resume_token: string | null;
  engine_version: string | null;
  image_digest: string | null;
  rule_version: string | null;
  adapter_version?: string;
  manifest_schema_version?: string | null;
  source_revision?: string | null;
  repository_url?: string | null;
  distribution_mode?: string | null;
  image_repository?: string | null;
  command_sha256?: string | null;
  scope_contract_sha256?: string | null;
  knowledge_input?: {
    kind: string;
    identifier: string;
    version: string | null;
    acquisition_source: string | null;
    pin_state: string;
    knowledge_date?: string | null;
    support_until?: string | null;
  } | null;
  runtime_provider?: string | null;
  runtime_version?: string | null;
  runtime_security_options?: string | null;
  exit_code?: number | null;
  cleanup_removed?: boolean | null;
  cleanup_detail?: string | null;
  warnings?: string[];
  raw_artifact_ids?: string[];
  error_code: string | null;
  error_message: string | null;
}

interface NativeScanRun {
  id: string;
  case_id: string;
  sequence: number;
  created_at: string;
  completed_at: string | null;
  knowledge_cutoff: string;
  verification_baseline_run_id?: string | null;
  request_outcome?: {
    status: string;
    code: string;
    requested_asset_ids: string[];
    requested_engine_ids: string[];
    explanation: string;
  } | null;
  engine_admission_issues?: NativeEngineAdmissionIssue[];
  engine_runs: NativeEngineRun[];
}

interface NativeEngineAdmissionIssue {
  engine_id: string | null;
  code: string;
  detail: string;
}

export interface NativeBeginnerMasterReport {
  schema_version: string;
  case_id: string;
  run_id: string;
  project_title: string;
  state: {
    summary: BeginnerMasterReport["state"]["summary"];
    lifecycle: BeginnerMasterReport["state"]["lifecycle"];
    last_durable_update: string;
    explanation: string;
  };
  requested: {
    targets: Array<{
      asset_id: string;
      label: string | null;
      asset_kind: string | null;
      label_availability: BeginnerMasterReport["requested"]["targets"][number]["labelAvailability"];
      asset_kind_availability: BeginnerMasterReport["requested"]["targets"][number]["assetKindAvailability"];
    }>;
    stage: {
      value: BeginnerMasterReport["requested"]["stage"]["value"] | null;
      availability: BeginnerMasterReport["requested"]["stage"]["availability"];
      explanation: string;
    };
    limits: Array<{
      name: string;
      value: string;
      source: BeginnerMasterReport["requested"]["limits"][number]["source"];
    }>;
    requested_check_ids: string[];
    request_outcome_code: BeginnerMasterReport["requested"]["requestOutcomeCode"] | null;
    automatic_reductions: Array<{
      dimension: string;
      requested: string;
      executed: string;
      reason: string;
    }>;
    reductions_availability: BeginnerMasterReport["requested"]["reductionsAvailability"];
    unavailable_dimensions: Array<{ dimension: string; explanation: string }>;
  };
  actual: {
    observed_from: string | null;
    observed_until: string | null;
    checks: Array<{
      task_id: string;
      check_id: string;
      target_asset_ids: string[];
      status: BeginnerMasterReport["actual"]["checks"][number]["status"];
      started_at: string | null;
      finished_at: string | null;
      tested_dimensions: Array<{
        dimension: string;
        value: string;
        observation: string;
        observed_at: string | null;
      }>;
    }>;
    network_scopes?: Array<{
      task_id: string;
      check_id: string;
      work_unit_id: string;
      target_asset_id: string;
      target: string;
      address_ranges: string[];
      port_ranges: string[];
      transport: string;
      stage: "quick_discovery" | "inventory" | "deep";
      outcome: "tested_complete" | "tested_partial" | "failed" | "timed_out" | "cancelled" | "not_tested";
      observed_at: string | null;
    }>;
    unavailable_dimensions: Array<{ dimension: string; explanation: string }>;
  };
  coverage_gaps: Array<{
    kind: BeginnerMasterReport["coverageGaps"][number]["kind"];
    task_id: string | null;
    target_asset_ids: string[];
    dimension: string;
    reason: string;
    next_action_code: BeginnerMasterReport["coverageGaps"][number]["nextActionCode"];
    next_action: string;
  }>;
  coverage_counts: {
    tested_complete: number;
    tested_partial: number;
    failed: number;
    timed_out: number;
    cancelled: number;
    not_tested: number;
    excluded: number;
    truncated: number;
    unavailable: number;
  };
  findings: Array<{
    finding_id: string;
    fingerprint: string;
    snapshot_source: BeginnerMasterReport["findings"][number]["snapshotSource"];
    title: string;
    plain_language_risk: string;
    possible_impact: string;
    severity: Severity;
    confidence: Confidence;
    priority: number | null;
    priority_reasons: string[];
    target_asset_ids: string[];
    next_step: string;
    recommended_expert_type: string;
    evidence_references: Array<{
      evidence_id: string;
      engine_id: string;
      artifact_sha256: string;
      observed_at: string;
    }>;
    framework_references: Array<{
      framework: string;
      framework_version: string;
      control_id: string;
      title: string;
      relationship: string;
      rationale: string;
      mapping_version: string;
    }>;
  }>;
  next_steps: Array<{
    priority: number;
    code: BeginnerMasterReport["nextSteps"][number]["code"];
    action: string;
    reason: string;
    finding_id: string | null;
    task_id: string | null;
    recommended_expert_type: string | null;
  }>;
  technical_details: {
    collapsed_by_default: true;
    tasks: Array<{
      task_id: string;
      target_asset_ids: string[];
      status: EngineRunStatus;
      phase: string;
      progress_percent: number;
      started_at: string | null;
      finished_at: string | null;
      exit_code: number | null;
      cleanup_removed: boolean | null;
      error_code: string | null;
      evidence_sha256: string[];
      execution: Record<string, unknown> & { kind?: string };
    }>;
  };
  framework_notice: {
    non_certification: string;
    aidefend_mapping_status: string;
  };
  data_quality_warnings: string[];
}

interface NativeEvidence {
  id: string;
  finding_id?: string;
  run_id?: string;
  engine_run_id?: string | null;
  kind?: string;
  engine_id: string;
  observed_at: string;
  summary: string;
  artifact_sha256: string;
  artifact_id?: string;
  pointer: string | null;
  redacted?: boolean;
}

interface NativeControlReference {
  framework: string;
  framework_version: string;
  control_id: string;
  title: string;
  relationship: string;
  rationale: string;
  mapping_version: string;
  mapping_provenance?: {
    mapping_version: string;
    reviewed_at: string;
    review_process: string;
    catalog_sha256: string;
  } | null;
}

interface NativeFinding {
  id: string;
  case_id?: string;
  first_seen_run_id?: string;
  last_seen_run_id?: string;
  fingerprint: string;
  title: string;
  plain_language_summary: string;
  possible_impact: string;
  severity: string;
  confidence: string;
  priority: number;
  priority_reasons?: string[];
  asset_ids: string[];
  evidence: NativeEvidence[];
  control_references: NativeControlReference[];
  recommendation: string;
  verification_guidance?: string;
  rollback_considerations?: string | null;
  official_references: string[];
  recommended_expert_type: string;
  status: string;
  tags?: string[];
}

interface NativeFindingWorkflowEvent {
  id: string;
  finding_id: string;
  from_status: string;
  to_status: string;
  decided_by: string;
  decided_at: string;
  reason: string;
  expires_at: string | null;
}

export interface NativeCaseExport {
  id: string;
  case_id: string;
  run_id: string;
  created_at: string;
  format?: string | null;
  path: string;
  sha256: string;
  coverage_manifest_path?: string | null;
  coverage_manifest_sha256?: string | null;
  signature: string | null;
  redaction_profile: string;
  raw_artifacts_included?: number | null;
  raw_artifacts_omitted?: number | null;
}

export interface NativeExportPreview {
  case_id: string;
  run_id: string;
  locale: string;
  format: string;
  redaction_profile: string;
  include_raw_evidence: boolean;
  data_source_count: number;
  coverage_entry_count: number;
  asset_count: number;
  candidate_asset_count: number;
  canonical_finding_count: number;
  selected_run_finding_count: number;
  evidence_index_count: number;
  selected_run_evidence_count: number;
  scan_run_count: number;
  selected_engine_run_count: number;
  external_scope_grant_count: number;
  incomplete_engine_run_count: number;
  not_executed_engine_run_count: number;
  unknown_source_count: number;
  connected_no_asset_count: number;
  raw_artifact_count: number;
  raw_artifacts_included: number;
  raw_artifacts_omitted: number;
  sensitive_raw_artifacts_omitted: number;
  sensitive_data_warning: string;
  coverage_manifest_included: boolean;
}

const adaptNativeReportLocale = (value: string): ReportLocale => {
  if (value === "en" || value === "zh-Hant") return value;
  throw new Error(`Unsupported report locale returned by the native service: ${value}`);
};

interface NativeDiffReason {
  code: string;
  engine_id?: string | null;
  asset_id?: string | null;
  detail: string;
}

interface NativeFindingDiff {
  fingerprint: string;
  baseline_finding_id: string | null;
  current_finding_id: string | null;
  status: string;
  explanation: string;
  baseline_severity?: string | null;
  current_severity?: string | null;
  evidence_changed?: boolean;
  reasons?: NativeDiffReason[];
}

interface NativeFindingGroup {
  id: string;
  case_id: string;
  title: string;
  finding_ids: string[];
  rationale: string;
  grouped_by: string;
  created_at: string;
}

interface NativeFindingGroupEvent {
  id: string;
  case_id: string;
  group_id: string;
  action: "created" | "removed";
  title: string;
  finding_ids: string[];
  rationale: string;
  actor: string;
  occurred_at: string;
}

interface NativeComparison {
  id: string;
  baseline_run_id: string;
  current_run_id: string;
  created_at: string;
  diffs: NativeFindingDiff[];
  complete?: boolean;
  completeness_issues?: NativeDiffReason[];
}

export interface NativeAssessmentCase {
  id: string;
  title: string;
  assessment_intent?: string | null;
  ai_generated_artifact?: string | null;
  profile: {
    organization_name: string;
    employee_range: string;
    data_classes: string[];
    notes: string | null;
  };
  status: string;
  created_at: string;
  updated_at: string;
  is_demo: boolean;
  requested_activities?: string[];
  data_sources: NativeDataSource[];
  assets: NativeAsset[];
  scope_grants: NativeScopeGrant[];
  coverage: NativeCoverageEntry[];
  scan_runs: NativeScanRun[];
  findings: NativeFinding[];
  finding_groups?: NativeFindingGroup[];
  finding_group_events?: NativeFindingGroupEvent[];
  finding_workflow_events?: NativeFindingWorkflowEvent[];
  exports: NativeCaseExport[];
  comparisons: NativeComparison[];
}

export interface NativeEngineManifest {
  id: string;
  display_name: string;
  category: string;
  distribution_mode: string;
  image: { digest: string | null } | null;
  engine_version: string | null;
  rule_version: string | null;
  license_spdx: string;
  supported_providers: string[];
  supported_asset_kinds: string[];
  provider_execution_contracts?: Array<{
    provider: string;
    asset_kind: string;
    profile: string;
  }>;
  status: string;
  compatibility?: {
    knowledge_date?: string;
    support_until?: string;
    runnable?: boolean;
    blocked_by?: unknown[];
  };
}

export interface NativeAppSnapshot {
  product_name: string;
  product_version: string;
  storage_path: string;
  cases: NativeCaseSummary[];
  selected_case: NativeAssessmentCase | null;
  runtime: {
    provider: string;
    available: boolean;
    phase: string;
    version: string | null;
    prerequisite: string | null;
    detail: string;
  };
  artifact_cleanup_obligations: Array<{
    case_id: string;
    exact_path: string;
    exists: boolean;
    requires_explicit_confirmation: boolean;
  }>;
  engine_count: number;
  /** Technical-only packaged scanner diagnostics; absent in older snapshots. */
  engine_admission_issues?: NativeEngineAdmissionIssue[];
  /** Added in v0.1.8. Older development snapshots may omit this projection. */
  beginner_reports?: NativeBeginnerMasterReport[];
  /** Added in v0.1.8. Unreadable project bytes are preserved instead of aborting startup. */
  case_recovery_diagnostics?: Array<{
    case_id: string;
    title: string;
    updated_at: string;
    revision: number;
    document_bytes: number;
    code: string;
    message: string;
    preserved: boolean;
  }>;
}

export interface NativeManagedRuntimeSetupStatus {
  phase: ManagedRuntimeSetupPhase;
  active: boolean;
  prerequisite_repair_active: boolean;
  operation_id?: string | null;
  started_at?: string | null;
  last_heartbeat_at?: string | null;
  stale?: boolean;
  cancel_requested: boolean;
  received_bytes: number;
  total_bytes: number | null;
  progress_percent: number | null;
  resumed_from_bytes: number;
  can_cancel: boolean;
  can_retry: boolean;
  failure_reason: ManagedRuntimeSetupFailureReason | null;
  next_action: ManagedRuntimeSetupNextAction | null;
  detail: string;
}

export interface NativeManagedRuntimePrerequisiteRepairResult {
  outcome: string;
  restart_required: boolean;
  detail: string;
}

const managedRuntimePrerequisiteRepairOutcomes = new Set<ManagedRuntimePrerequisiteRepairOutcome>([
  "completed",
  "cancelled",
  "failed",
]);

export const adaptManagedRuntimePrerequisiteRepairResult = (
  result: NativeManagedRuntimePrerequisiteRepairResult,
): ManagedRuntimePrerequisiteRepairResult => {
  const outcome = managedRuntimePrerequisiteRepairOutcomes.has(
    result.outcome as ManagedRuntimePrerequisiteRepairOutcome,
  )
    ? result.outcome as ManagedRuntimePrerequisiteRepairOutcome
    : "failed";
  const detail = typeof result.detail === "string"
    && result.detail.length <= 1_024
    && !/[\0\u2028\u2029]/u.test(result.detail)
    ? result.detail
    : "Windows prerequisite repair returned no safe detail";
  return {
    outcome,
    restartRequired: outcome === "completed" && result.restart_required === true,
    detail,
  };
};

const managedRuntimeRecoveryActions: Partial<
  Record<ManagedRuntimeSetupFailureReason, ManagedRuntimeSetupNextAction>
> = {
  windows_wsl_not_installed: "install_wsl",
  windows_wsl_optional_feature_disabled: "enable_wsl_optional_features",
  windows_wsl_update_required: "update_wsl",
  windows_restart_required: "restart_windows",
  windows_wsl_command_failed: "retry_wsl_check",
};

const managedRuntimeNonRetryableFailures = new Set<ManagedRuntimeSetupFailureReason>([
  "packaged_runtime_missing",
  "packaged_runtime_verification_failed",
]);

const managedRuntimeSetupPhases = new Set<ManagedRuntimeSetupPhase>([
  "idle",
  "install",
  "prerequisite",
  "download",
  "recovery",
  "init",
  "start",
  "verify",
  "completed",
  "failed",
  "cancelled",
]);

const boundedRuntimeOperationField = (
  value: string | null | undefined,
  maximumLength: number,
): string | undefined => typeof value === "string"
  && value.length > 0
  && value.length <= maximumLength
  && !/[\0\u2028\u2029]/u.test(value)
  ? value
  : undefined;

const boundedRuntimeTimestamp = (value: string | null | undefined): string | undefined => {
  const bounded = boundedRuntimeOperationField(value, 64);
  return bounded && Number.isFinite(Date.parse(bounded)) ? bounded : undefined;
};

/**
 * Adapts the snake-case Tauri DTO and enforces its terminal-failure contract.
 * A stale or partially mismatched recovery pair is deliberately hidden rather
 * than presenting the user with the wrong Windows instruction.
 */
export const adaptManagedRuntimeSetupStatus = (
  status: NativeManagedRuntimeSetupStatus,
): ManagedRuntimeSetupStatus => {
  const phase = managedRuntimeSetupPhases.has(status.phase) ? status.phase : "failed";
  const hasValidRecovery = phase === "failed"
    && status.failure_reason !== null
    && managedRuntimeRecoveryActions[status.failure_reason] === status.next_action;
  const hasValidNonRetryableFailure = phase === "failed"
    && status.can_retry === false
    && status.failure_reason !== null
    && managedRuntimeNonRetryableFailures.has(status.failure_reason)
    && status.next_action === null;
  const operationId = boundedRuntimeOperationField(status.operation_id, 128);
  const startedAt = boundedRuntimeTimestamp(status.started_at);
  const lastHeartbeatAt = boundedRuntimeTimestamp(status.last_heartbeat_at);
  return {
    phase,
    active: status.active,
    prerequisiteRepairActive: status.prerequisite_repair_active,
    ...(operationId ? { operationId } : {}),
    ...(startedAt ? { startedAt } : {}),
    ...(lastHeartbeatAt ? { lastHeartbeatAt } : {}),
    ...(status.stale !== undefined ? { stale: status.stale === true } : {}),
    cancelRequested: status.cancel_requested,
    receivedBytes: status.received_bytes,
    totalBytes: status.total_bytes ?? undefined,
    progressPercent: status.progress_percent ?? undefined,
    resumedFromBytes: status.resumed_from_bytes,
    canCancel: status.can_cancel,
    canRetry: status.can_retry,
    failureReason: hasValidRecovery || hasValidNonRetryableFailure
      ? status.failure_reason ?? undefined
      : undefined,
    nextAction: hasValidRecovery ? status.next_action ?? undefined : undefined,
    detail: status.detail,
  };
};

const unavailableLocalNetworkInventory = (): LocalNetworkCandidateInventory => ({
  status: "unavailable",
  candidates: [],
});

const localNetworkCandidateStatuses = new Set<LocalNetworkCandidateStatus>([
  "ready",
  "none",
  "ambiguous",
  "unavailable",
  "unsupported",
]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const canonicalPrivateIpv4Cidr = (value: unknown): { target: string; addressCount: number } | undefined => {
  if (typeof value !== "string" || value.length > 18) return undefined;
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/u.exec(value);
  if (!match) return undefined;
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return undefined;
  if (!Number.isInteger(prefix) || prefix < 20 || prefix > 30) return undefined;
  const first = octets[0] ?? -1;
  const second = octets[1] ?? -1;
  const isPrivate = first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
  if (!isPrivate) return undefined;

  const address = octets.reduce((result, octet) => ((result * 256) + octet) >>> 0, 0);
  const hostBits = 32 - prefix;
  const mask = (0xffff_ffff << hostBits) >>> 0;
  if ((address & mask) >>> 0 !== address) return undefined;
  return { target: value, addressCount: 2 ** hostBits };
};

const adaptLocalPrivateSubnetCandidate = (value: unknown): LocalPrivateSubnetCandidate | undefined => {
  if (!isRecord(value)) return undefined;
  const cidr = canonicalPrivateIpv4Cidr(value.target);
  if (
    !cidr
    || typeof value.id !== "string"
    || !/^local-ipv4-[a-f0-9]{64}$/u.test(value.id)
    || value.kind !== "local_ipv4_subnet"
    || value.useCase !== "internal_it_environment"
    || value.internetExposure !== "internal"
    || value.addressCount !== cidr.addressCount
    || value.requiresConfirmation !== true
  ) return undefined;
  return {
    id: value.id,
    target: cidr.target,
    kind: "local_ipv4_subnet",
    useCase: "internal_it_environment",
    internetExposure: "internal",
    addressCount: cidr.addressCount,
    requiresConfirmation: true,
  };
};

/**
 * Fail closed if the native detector ever returns a widened, public, malformed,
 * or ambiguous target. Only one canonical RFC1918 /20-/30 can reach the UI.
 */
export const adaptLocalNetworkCandidateInventory = (
  value: unknown,
): LocalNetworkCandidateInventory => {
  if (!isRecord(value) || !localNetworkCandidateStatuses.has(value.status as LocalNetworkCandidateStatus)) {
    return unavailableLocalNetworkInventory();
  }
  const status = value.status as LocalNetworkCandidateStatus;
  if (!Array.isArray(value.candidates)) return unavailableLocalNetworkInventory();
  if (status !== "ready") {
    return value.candidates.length === 0
      ? { status, candidates: [] }
      : unavailableLocalNetworkInventory();
  }
  if (value.candidates.length !== 1) return unavailableLocalNetworkInventory();
  const candidate = adaptLocalPrivateSubnetCandidate(value.candidates[0]);
  return candidate
    ? { status: "ready", candidates: [candidate] }
    : unavailableLocalNetworkInventory();
};

const unique = <T,>(values: T[]): T[] => [...new Set(values)];

const assessmentIntents: readonly UseCaseId[] = [
  "deployed_website",
  "external_ip_or_domain",
  "internal_it_environment",
  "ai_application",
  "source_code",
  "infrastructure_as_code",
  "cloud_account",
  "container_image",
  "kubernetes",
];

const mapAssessmentIntent = (value: string | null | undefined): UseCaseId | undefined =>
  assessmentIntents.includes(value as UseCaseId) ? value as UseCaseId : undefined;

const mapAiGeneratedArtifact = (
  value: string | null | undefined,
): AiGeneratedArtifactAnswer =>
  value === "yes" || value === "no" ? value : "unknown";

const suggestedPlatformsForIntent = (intent: UseCaseId | undefined): CloudPlatform[] =>
  intent ? [...useCaseById(intent).suggestedPlatforms] : [];

const withDraftIntentFallback = (
  platforms: CloudPlatform[],
  intent: UseCaseId | undefined,
  status: string,
  assetCount: number,
): CloudPlatform[] =>
  platforms.length === 0 && status === "draft" && assetCount === 0
    ? suggestedPlatformsForIntent(intent)
    : platforms;

const phaseMap: Record<string, CasePhase> = {
  draft: "draft",
  discovering: "discovering",
  scope_review: "scope_review",
  ready: "ready",
  scanning: "scanning",
  needs_attention: "needs_attention",
  ready_for_handoff: "ready_for_handoff",
  verifying: "verifying",
  archived: "archived",
};

const mapPhase = (status: string): CasePhase => phaseMap[status] ?? "needs_attention";

const mapCompanySize = (value: string): CompanySize => {
  if (/250|500|1000|large/i.test(value)) return "large";
  if (/50|100|249|medium/i.test(value)) return "medium";
  if (/^1$|solo/i.test(value)) return "solo";
  return "small";
};

const mapDataClasses = (values: string[]): DataClass[] => {
  const mapped = values.map((value): DataClass => {
    if (value === "personally_identifiable_information") return "pii";
    if (value === "protected_health_information") return "phi";
    if (value === "payment_card_information" || value === "financial") return "payment";
    if (value === "credentials_and_secrets") return "credentials";
    return "none";
  });
  const concrete = unique(mapped.filter((value) => value !== "none"));
  return concrete.length > 0 ? concrete : ["none"];
};

const platformFromSource = (kind: string): CloudPlatform => {
  if (kind === "aws_organization") return "aws";
  if (kind === "azure_tenant") return "azure";
  if (kind === "gcp_organization") return "gcp";
  if (kind === "microsoft365_tenant") return "m365";
  if (kind === "git_repository" || kind === "terraform_state" || kind === "file_system") return "code";
  if (kind === "container_registry") return "container";
  if (kind === "kubernetes_cluster") return "kubernetes";
  return "external";
};

const platformFromAsset = (asset: NativeAsset): CloudPlatform => {
  const provider = asset.provider?.toLowerCase() ?? "";
  if (provider.includes("aws") || provider.includes("amazon")) return "aws";
  if (provider.includes("azure")) return "azure";
  if (provider.includes("gcp") || provider.includes("google")) return "gcp";
  if (provider.includes("m365") || provider.includes("microsoft 365")) return "m365";
  if (asset.kind === "subscription") return "azure";
  if (asset.kind === "project") return "gcp";
  if (asset.kind === "tenant") return "m365";
  if (["repository", "file_system", "iac_project", "host"].includes(asset.kind)) return "code";
  if (["container_image", "container_registry"].includes(asset.kind)) return "container";
  if (asset.kind === "kubernetes_cluster") return "kubernetes";
  return "external";
};

const mapAssetType = (kind: string): AssetType => {
  const types: Record<string, AssetType> = {
    cloud_organization: "cloud_account",
    cloud_account: "cloud_account",
    subscription: "subscription",
    project: "project",
    tenant: "tenant",
    domain: "domain",
    ip_address: "ip",
    host: "service",
    web_service: "service",
    cloud_resource: "service",
    identity: "service",
    repository: "repository",
    file_system: "repository",
    iac_project: "repository",
    container_image: "image",
    container_registry: "image",
    kubernetes_cluster: "cluster",
  };
  return types[kind] ?? "service";
};

const localInputProfiles: LocalInputProfile[] = [
  "repository_working_tree",
  "iac_working_tree",
  "container_image_oci_layout",
  "kubernetes_manifests",
  "kubernetes_node_snapshot",
];

const localInputProfileFromAsset = (asset: NativeAsset): LocalInputProfile | undefined => {
  const profile = asset.metadata?.local_input_profile;
  if (typeof profile === "string" && localInputProfiles.includes(profile as LocalInputProfile)) {
    return profile as LocalInputProfile;
  }
  return asset.kind === "repository" && typeof asset.metadata?.workspace_snapshot_id === "string"
    ? "repository_working_tree"
    : undefined;
};

const localQuestionnaireKinds = new Set(["repository", "iac_project", "container_image", "kubernetes_cluster"]);

export const adaptDeclaredWebServiceMetadata = (
  metadata: Record<string, unknown> | undefined,
): Asset["declaredWebService"] | undefined => {
  const raw = metadata?.declared_web_service;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const candidate = raw as Record<string, unknown>;
  const protocol = candidate.protocol;
  const port = candidate.port;
  const path = candidate.path;
  if (
    (protocol !== "http" && protocol !== "https")
    || !Number.isInteger(port)
    || (port as number) < 1
    || (port as number) > 65_535
    || typeof path !== "string"
    || path.length > 2_048
    || !path.startsWith("/")
    || /[?#\u0000-\u001f\u007f]/u.test(path)
  ) return undefined;
  return { protocol, port: port as number, path };
};

const mapCoverageState = (status: string): CoverageState => {
  const states: Record<string, CoverageState> = {
    discovered_authorized_scanned: "discovered_authorized_scanned",
    discovered_not_authorized: "discovered_not_authorized",
    authorized_scan_incomplete: "authorized_incomplete",
    source_connected_nothing_discovered: "source_connected_none",
    source_not_connected_unknown: "source_unavailable_unknown",
    not_applicable: "not_applicable",
  };
  return states[status] ?? "source_unavailable_unknown";
};

const mapSourceKind = (kind: string): SourceKind => {
  const sourceKinds: SourceKind[] = [
    "aws_organization",
    "azure_tenant",
    "gcp_organization",
    "microsoft365_tenant",
    "dns",
    "certificate_transparency",
    "billing",
    "git_repository",
    "terraform_state",
    "kubernetes_cluster",
    "container_registry",
    "file_system",
    "user_declared",
  ];
  return sourceKinds.includes(kind as SourceKind) ? kind as SourceKind : "user_declared";
};

const providerBindingContracts: Partial<Record<SourceKind, {
  profile: ProviderSourceProfile;
  resourceScope: RegExp;
}>> = {
  aws_organization: {
    profile: "aws_organization_read_only_session",
    resourceScope: /^aws-account:[0-9]{12}$/u,
  },
  azure_tenant: {
    profile: "azure_tenant_read_only_access_token",
    resourceScope: /^azure-subscription:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu,
  },
  gcp_organization: {
    profile: "gcp_organization_read_only_access_token",
    resourceScope: /^gcp-organization:[0-9]{1,32}$/u,
  },
  microsoft365_tenant: {
    profile: "microsoft365_tenant_read_only_access_token",
    resourceScope: /^microsoft365-tenant:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu,
  },
};

/** Project only the two non-secret, exact provider coordinates used by the UI. */
export const adaptNativeProviderBinding = (
  sourceKind: SourceKind,
  metadata: Record<string, unknown> | undefined,
): ConnectedSource["providerBinding"] => {
  const contract = providerBindingContracts[sourceKind];
  const profile = metadata?.provider_profile;
  const resourceScope = metadata?.provider_resource_scope;
  if (
    !contract
    || profile !== contract.profile
    || typeof resourceScope !== "string"
    || !contract.resourceScope.test(resourceScope)
  ) return undefined;
  return { profile: contract.profile, resourceScope };
};

const mapScopeMode = (permission: string): ScopeMode => {
  const modes: Record<string, ScopeMode> = {
    inventory_read: "inventory",
    configuration_read: "configuration",
    local_artifact_read: "local_artifact",
    passive_external_discovery: "public_data",
    low_impact_external_connection: "low_impact_external",
    active_external_testing: "active_external",
  };
  return modes[permission] ?? "inventory";
};

const adaptExternalScope = (scope: NativeExternalScope): FrozenExternalScope => ({
  id: scope.id,
  caseId: scope.case_id,
  assetId: scope.asset_id,
  target: scope.target.value,
  targetKind: scope.target.kind,
  ports: scope.ports,
  protocol: scope.protocol,
  activity: scope.activity,
  ratePolicy: {
    requestsPerSecond: scope.rate_policy.requests_per_second,
    concurrency: scope.rate_policy.concurrency,
    timeoutSeconds: scope.rate_policy.timeout_seconds,
  },
  templatePolicy: {
    revision: scope.template_policy.revision,
    allowedTemplateIds: scope.template_policy.allowed_template_ids,
    allowHeadless: scope.template_policy.allow_headless,
    allowOutOfBand: scope.template_policy.allow_out_of_band,
    allowFuzzing: scope.template_policy.allow_fuzzing,
    allowFileUpload: scope.template_policy.allow_file_upload,
    allowDenialOfService: scope.template_policy.allow_denial_of_service,
    allowCredentialAttacks: scope.template_policy.allow_credential_attacks,
  },
  assertedAuthority: scope.asserted_authority,
  approvedBy: scope.approved_by,
  approvedAt: scope.approved_at,
  expiresAt: scope.expires_at,
  allowSensitiveNetworks: scope.allow_sensitive_networks,
});

const mapSeverity = (severity: string): Severity => {
  const normalized = severity.trim().toLowerCase();
  if (normalized === "informational" || normalized === "info") return "info";
  return (["critical", "high", "medium", "low", "unknown"].includes(normalized)
    ? normalized
    : "unknown") as Severity;
};

const mapConfidence = (confidence: string): Confidence => {
  if (confidence === "confirmed") return "high";
  return (["high", "medium", "low"].includes(confidence) ? confidence : "low") as Confidence;
};

const mapWorkflow = (status: string): FindingWorkflowState => {
  const states: Record<string, FindingWorkflowState> = {
    unreviewed: "unreviewed",
    sent_for_review: "expert_review_requested",
    expert_review_requested: "expert_review_requested",
    confirmed: "confirmed",
    false_positive: "false_positive",
    remediation_planned: "assigned",
    remediation_reported: "remediation_reported",
    remediated_pending_verification: "remediated_pending_verification",
    closed: "verified_resolved",
    verified_resolved: "verified_resolved",
  };
  return states[status] ?? "unreviewed";
};

const mapEngineStatus = (status: string): EngineRunStatus => {
  const states: Record<string, EngineRunStatus> = {
    not_executed: "not_executed",
    queued: "pending",
    preparing: "running",
    running: "running",
    paused: "paused",
    completed: "completed",
    partially_completed: "partial",
    failed: "failed",
    cancelled: "cancelled",
  };
  return states[status] ?? "not_executed";
};

const mapEngineTaskKind = (taskKind: NativeEngineRun["task_kind"]): EngineTaskKind => {
  if (taskKind?.kind !== "built_in_localhost_tcp") return { kind: "catalog_engine" };
  return {
    kind: "built_in_localhost_tcp",
    port: taskKind.port,
    timeoutMs: taskKind.timeout_ms,
    payloadBytes: taskKind.payload_bytes,
  };
};

const mapLocalhostTcpObservation = (
  observation: NativeEngineRun["localhost_tcp_observation"],
): LocalhostTcpObservation | undefined => {
  if (!observation || !["reachable", "closed", "timed_out"].includes(observation.outcome)) {
    return undefined;
  }
  return {
    outcome: observation.outcome as LocalhostTcpObservation["outcome"],
    observedAt: observation.observed_at,
  };
};

const exactCompletedLocalhostBinding = (
  engineRun: EngineRun,
  assetId: string,
  nativeAssets: readonly NativeAsset[],
): boolean => {
  if (!isExactBuiltInLocalhostQuickScanEngine(engineRun)
    || engineRun.taskKind.kind !== "built_in_localhost_tcp") return false;
  const endpoint = `127.0.0.1:${engineRun.taskKind.port}`;
  const asset = nativeAssets.find((candidate) => candidate.id === assetId);
  const exactLoopbackAsset = asset?.kind === "web_service"
    && !asset.candidate
    && asset.owner_confirmed
    && asset.internet_exposed === false
    && asset.name === endpoint
    && asset.identifiers.length === 1
    && asset.identifiers.some((identifier) =>
      identifier.namespace === "localhost_tcp_endpoint"
        && identifier.value === endpoint
    );
  return Boolean(
    exactLoopbackAsset
    && engineRun.assetIds.length === 1
    && engineRun.assetIds[0] === assetId
    && engineRun.status === "completed"
    && Number.isInteger(engineRun.taskKind.port)
    && engineRun.taskKind.port >= 1
    && engineRun.taskKind.port <= 65_535
    && engineRun.taskKind.timeoutMs === 3_000
    && engineRun.taskKind.payloadBytes === 0
    && engineRun.localhostTcpObservation
    && Number.isFinite(Date.parse(engineRun.localhostTcpObservation.observedAt))
    && ["reachable", "closed"].includes(engineRun.localhostTcpObservation?.outcome ?? "")
  );
};

const checkpointStages = new Set([
  "planned",
  "preflight",
  "pulling_image",
  "running",
  "capturing_artifacts",
  "adapting_artifacts",
  "captured_awaiting_adapter",
  "cleanup_pending",
  "completed",
  "cancelled",
  "failed",
]);

const parseCheckpoint = (token: string | null, engineRun: NativeEngineRun): EngineCheckpoint | undefined => {
  if (!token) return undefined;
  try {
    const value = JSON.parse(token) as Record<string, unknown>;
    if (
      value.engine_run_id !== engineRun.id
      || value.engine_id !== engineRun.engine_id
      || typeof value.attempt !== "number"
      || typeof value.stage !== "string"
      || !checkpointStages.has(value.stage)
    ) return undefined;
    return {
      attempt: Math.max(1, Math.trunc(value.attempt)),
      stage: value.stage as EngineCheckpoint["stage"],
      artifactCount: Array.isArray(value.artifact_ids) ? value.artifact_ids.length : 0,
      cleanupCompleted: value.cleanup_completed === true,
      scopeBound: typeof value.scope_sha256 === "string" && value.scope_sha256.length > 0,
      lastError: typeof value.last_error === "string" ? value.last_error : undefined,
    };
  } catch {
    return undefined;
  }
};

const gatewayPreparationMarkers = [
  "pinned egress gateway image pull",
  "managed gateway uplink creation",
  "egress gateway container creation",
  "egress gateway container start",
  "egress gateway container exited",
  "egress gateway container did not report",
  "egress gateway container reported",
  "egress gateway internal-network attachment",
  "egress gateway exited before becoming ready",
  "egress gateway did not become ready",
  "egress gateway could not start",
] as const;

/**
 * Convert only exact product-owned gateway markers into a safe category. The
 * backend text itself may contain target-controlled data. After classification
 * the adapter replaces both the scanner message and checkpoint error with one
 * localized product message, so neither UI layer nor a shareable diagnostic
 * can reproduce the raw text.
 */
const engineFailureKind = (
  engineRun: NativeEngineRun,
  checkpoint: EngineCheckpoint | undefined,
): EngineFailureKind | undefined => {
  if (engineRun.error_code !== "execution_failed") return undefined;
  const technicalText = `${engineRun.error_message ?? ""}\n${checkpoint?.lastError ?? ""}`.toLowerCase();
  return gatewayPreparationMarkers.some((marker) => technicalText.includes(marker))
    ? "gateway_preparation_failed"
    : undefined;
};

const engineRecoveryAction = (
  status: EngineRunStatus,
  hasResumeToken: boolean,
  checkpoint: EngineCheckpoint | undefined,
  errorCode: string | null | undefined,
): EngineRecoveryAction => {
  if ([
    "resume_release_incompatible",
    "resume_work_plan_invalid",
    "runtime_cleanup_identity_unavailable",
    "coverage_incomplete_after_bounded_retries",
    "cancelled_after_partial_results",
  ].includes(errorCode ?? "")) {
    return "none";
  }
  if (!hasResumeToken || !checkpoint || !["paused", "failed", "partial", "cancelled"].includes(status)) {
    return "none";
  }
  if (checkpoint?.stage === "captured_awaiting_adapter" || checkpoint?.stage === "adapting_artifacts") {
    return "continue_saved_results";
  }
  if (checkpoint?.stage === "cleanup_pending") return "finish_cleanup";
  return "restart_check";
};

const runStatus = (runs: EngineRun[]): RunStatus => {
  if (runs.length === 0 || runs.every((run) => run.status === "pending")) return "queued";
  if (runs.some((run) => run.status === "running")) return "running";
  if (runs.some((run) => run.status === "paused")) return "paused";
  if (runs.some((run) => run.status === "pending")) return "queued";
  if (runs.every((run) => run.status === "completed")) return "completed";
  if (runs.every((run) => run.status === "cancelled")) return "cancelled";
  if (runs.every((run) => run.status === "failed" || run.status === "not_executed")) return "failed";
  return "partial";
};

const mapScanRequestOutcome = (
  outcome: NativeScanRun["request_outcome"],
  completedAt: string | null,
  engineRunCount: number,
): ScanRequestOutcome | undefined => {
  if (
    outcome?.status !== "no_checks_completed"
    || !completedAt
    || engineRunCount !== 0
    || ![
      "no_effective_scope_grants",
      "no_ownership_confirmed_targets",
      "no_applicable_checks",
    ].includes(outcome.code)
  ) return undefined;
  return {
    status: "no_checks_completed",
    code: outcome.code as ScanRequestOutcome["code"],
    requestedAssetIds: [...outcome.requested_asset_ids],
    requestedEngineIds: [...outcome.requested_engine_ids],
  };
};

const storedExportFormat = (format?: string | null): ExportFormat | undefined =>
  ["case_bundle", "json", "framework_report", "ocsf", "oscal", "html"].includes(format ?? "")
    ? format as ExportFormat
    : undefined;

export const adaptNativeExport = (item: NativeCaseExport): CaseExport => ({
  id: item.id,
  caseId: item.case_id,
  runId: item.run_id,
  format: storedExportFormat(item.format),
  createdAt: item.created_at,
  fileName: item.path.split(/[\\/]/).at(-1) ?? item.path,
  sha256: item.sha256,
  coverageManifestPath: item.coverage_manifest_path ?? undefined,
  coverageManifestSha256: item.coverage_manifest_sha256 ?? undefined,
  signatureState: item.signature ? "local_integrity" : "unsigned",
  includesRawEvidence: item.raw_artifacts_included == null
    ? undefined
    : item.raw_artifacts_included > 0,
  rawArtifactsIncluded: item.raw_artifacts_included ?? undefined,
  rawArtifactsOmitted: item.raw_artifacts_omitted ?? undefined,
  path: item.path,
});

const stableExportIdentityHash = (value: string): string => {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
};

/**
 * A filename-safe, deterministic run coordinate. The canonical sequence is
 * readable, while the hash distinguishes the immutable ID without copying an
 * imported or otherwise untrusted identifier into a suggested filename.
 */
export const exportRunFileIdentity = (
  run: Pick<CaseWorkspace["runs"][number], "id" | "sequence">,
): string => {
  const shortIdentity = stableExportIdentityHash(run.id);
  return Number.isSafeInteger(run.sequence) && (run.sequence ?? 0) > 0
    ? `scan-${run.sequence}-${shortIdentity}`
    : `run-${shortIdentity}`;
};

export const adaptNativeExportPreview = (item: NativeExportPreview): ExportPreview => ({
  caseId: item.case_id,
  runId: item.run_id,
  locale: adaptNativeReportLocale(item.locale),
  format: storedExportFormat(item.format) ?? "case_bundle",
  redactionProfile: item.redaction_profile === "none" ? "none" : "standard",
  includeRawEvidence: item.include_raw_evidence,
  dataSourceCount: item.data_source_count,
  coverageEntryCount: item.coverage_entry_count,
  assetCount: item.asset_count,
  candidateAssetCount: item.candidate_asset_count,
  canonicalFindingCount: item.canonical_finding_count,
  selectedRunFindingCount: item.selected_run_finding_count,
  evidenceIndexCount: item.evidence_index_count,
  selectedRunEvidenceCount: item.selected_run_evidence_count,
  scanRunCount: item.scan_run_count,
  selectedEngineRunCount: item.selected_engine_run_count,
  externalScopeGrantCount: item.external_scope_grant_count,
  incompleteEngineRunCount: item.incomplete_engine_run_count,
  notExecutedEngineRunCount: item.not_executed_engine_run_count,
  unknownSourceCount: item.unknown_source_count,
  connectedNoAssetCount: item.connected_no_asset_count,
  rawArtifactCount: item.raw_artifact_count,
  rawArtifactsIncluded: item.raw_artifacts_included,
  rawArtifactsOmitted: item.raw_artifacts_omitted,
  sensitiveRawArtifactsOmitted: item.sensitive_raw_artifacts_omitted,
  sensitiveDataWarning: item.sensitive_data_warning,
  coverageManifestIncluded: item.coverage_manifest_included,
});

export const adaptNativeManifest = (manifest: NativeEngineManifest): EngineManifest => {
  const supportedProviders = manifest.supported_providers
    .map((provider): CloudPlatform | undefined => provider === "microsoft365" ? "m365" : ["aws", "azure", "gcp"].includes(provider) ? provider as CloudPlatform : undefined)
    .filter((provider): provider is CloudPlatform => Boolean(provider));
  const platforms = supportedProviders.length > 0 ? supportedProviders : unique(manifest.supported_asset_kinds.map((kind) =>
    platformFromAsset({ id: "", kind, name: "", provider: null, region: null, identifiers: [], discovered_from: [], candidate: false, owner_confirmed: false }),
  ));
  const distribution: EngineManifest["redistribution"] = manifest.distribution_mode === "bundled_image"
    ? "bundled"
    : manifest.distribution_mode === "external_executable" ? "external" : "on_demand";
  const catalogStatus: EngineManifest["status"] = manifest.status === "integrated"
    ? "ready"
    : manifest.status === "deprecated" ? "outdated"
      : manifest.status === "experimental" ? "not_downloaded" : "unsupported";
  const rawRunnable = manifest.compatibility?.runnable;
  const rawBlockedBy = manifest.compatibility?.blocked_by;
  const runnableShapeValid = rawRunnable === undefined || typeof rawRunnable === "boolean";
  const blockedByShapeValid = rawBlockedBy === undefined || (
    Array.isArray(rawBlockedBy)
    && rawBlockedBy.every((item) =>
      typeof item === "string"
      && item.length > 0
      && item.length <= 512
      && !/[\u0000-\u001f\u007f]/u.test(item),
    )
  );
  const blockedBy = blockedByShapeValid && Array.isArray(rawBlockedBy)
    ? rawBlockedBy as string[]
    : [];
  const compatibilityValid = runnableShapeValid
    && blockedByShapeValid
    && !(rawRunnable === true && blockedBy.length > 0);
  const runnable = compatibilityValid && typeof rawRunnable === "boolean"
    ? rawRunnable
    : undefined;
  const status: EngineManifest["status"] = catalogStatus === "ready"
    && (runnable === false || blockedBy.length > 0)
    ? "not_downloaded"
    : catalogStatus;
  const contractAssetKinds: Partial<Record<SourceCapabilityProvider, string>> = {
    aws: "cloud_account",
    azure: "subscription",
    gcp: "project",
    microsoft365: "tenant",
  };
  const providerExecutionProfiles = (Array.isArray(manifest.provider_execution_contracts)
    ? manifest.provider_execution_contracts
    : [])
    .flatMap((contract) => {
      if (!contract || typeof contract !== "object") return [];
      const provider = contract.provider;
      if (!(["aws", "azure", "gcp", "microsoft365"] as const).includes(provider as SourceCapabilityProvider)) return [];
      const safeProvider = provider as SourceCapabilityProvider;
      if (
        contract.asset_kind !== contractAssetKinds[safeProvider]
        || typeof contract.profile !== "string"
        || !/^[a-z0-9][a-z0-9_-]{2,95}$/u.test(contract.profile)
      ) return [];
      return [{ provider: safeProvider, assetKind: contract.asset_kind, profile: contract.profile }];
    })
    .filter((contract, index, values) =>
      values.findIndex((candidate) =>
        candidate.provider === contract.provider
        && candidate.assetKind === contract.assetKind
        && candidate.profile === contract.profile,
      ) === index,
    );
  const knowledgeDate = manifest.compatibility?.knowledge_date;
  const supportUntil = manifest.compatibility?.support_until;
  const today = new Date().toISOString().slice(0, 10);
  return {
    id: manifest.id,
    name: manifest.display_name,
    category: manifest.category,
    version: manifest.engine_version ?? manifest.rule_version ?? adapterText("Not reported", "未回報"),
    imageDigest: manifest.image?.digest ?? adapterText("No image digest", "未提供映像摘要"),
    license: manifest.license_spdx,
    redistribution: distribution,
    platforms,
    supportedProviders,
    status,
    runnable,
    blockedBy,
    compatibilityValid,
    providerExecutionProfiles,
    knowledgeDate,
    supportUntil,
    supportStatus: supportUntil ? (supportUntil < today ? "expired" : "supported") : "unknown",
  };
};

const adaptCaseProductIdentity = (
  identity: NativeCaseProductIdentity | null | undefined,
): AssessmentCase["productIdentity"] => {
  if (
    identity?.kind !== "localhost_quick_scan" ||
    !Number.isInteger(identity.port) ||
    identity.port < 1 ||
    identity.port > 65_535
  ) {
    return undefined;
  }

  return { kind: identity.kind, port: identity.port };
};

const adaptSummary = (summary: NativeCaseSummary): AssessmentCase => {
  const assessmentIntent = mapAssessmentIntent(summary.assessment_intent);
  const sourceKinds = summary.applicable_source_kinds ?? summary.source_kinds;
  const platforms = withDraftIntentFallback(
    unique(sourceKinds.map(platformFromSource)),
    assessmentIntent,
    summary.status,
    summary.asset_count,
  );
  return {
    id: summary.id,
    name: summary.title,
    assessmentIntent,
    aiGeneratedArtifact: mapAiGeneratedArtifact(summary.ai_generated_artifact),
    organizationName: summary.organization_name,
    companySize: mapCompanySize(summary.employee_range),
    dataClasses: mapDataClasses(summary.data_classes),
    requestedActivities: summary.requested_activities.filter(
      (activity): activity is AssessmentActivity => [
        "configuration_assessment",
        "local_artifact_analysis",
        "low_impact_external_checks",
        "active_external_vulnerability_tests",
      ].includes(activity),
    ),
    platforms,
    createdAt: summary.created_at,
    updatedAt: summary.updated_at,
    phase: mapPhase(summary.status),
    isDemo: summary.is_demo,
    description: summary.notes ?? undefined,
    latestRunId: summary.latest_run_id ?? undefined,
    assetCount: summary.asset_count,
    findingCount: summary.finding_count,
    productIdentity: adaptCaseProductIdentity(summary.product_identity),
  };
};

export const adaptNativeCase = (
  nativeCase: NativeAssessmentCase,
  manifests: EngineManifest[] = [],
): CaseWorkspace => {
  const sources: ConnectedSource[] = nativeCase.data_sources.map((source) => {
    const kind = mapSourceKind(source.kind);
    return {
      id: source.id,
      kind,
      label: source.label,
      status: source.status as ConnectedSource["status"],
      readOnly: source.read_only,
      connectedAt: source.connected_at ?? undefined,
      lastDiscoveredAt: source.last_discovered_at ?? undefined,
      providerBinding: adaptNativeProviderBinding(kind, source.metadata),
    };
  });
  const scanAttemptedAssetIds = new Set(
    nativeCase.scan_runs.flatMap((run) => run.engine_runs.flatMap((engineRun) => engineRun.asset_ids)),
  );
  const coverage: CoverageRecord[] = nativeCase.coverage.map((entry) => ({
    id: entry.id,
    label: entry.label,
    platform: platformFromSource(entry.source_kind),
    sourceKind: mapSourceKind(entry.source_kind),
    state: mapCoverageState(entry.status),
    assetId: entry.asset_id ?? undefined,
    assetCount: entry.asset_id ? 1 : 0,
    detail: entry.explanation,
    lastCheckedAt: entry.observed_at ?? undefined,
    scanAttempted: entry.asset_id
      ? Boolean(entry.last_run_id) || scanAttemptedAssetIds.has(entry.asset_id)
      : undefined,
  }));
  const coverageByAsset = new Map(nativeCase.coverage.filter((entry) => entry.asset_id).map((entry) => [entry.asset_id, entry]));
  const grantsByAsset = new Map<string, NativeScopeGrant[]>();
  for (const grant of nativeCase.scope_grants) {
    grantsByAsset.set(grant.asset_id, [...(grantsByAsset.get(grant.asset_id) ?? []), grant]);
  }
  const findingCount = new Map<string, number>();
  for (const finding of nativeCase.findings) {
    for (const assetId of finding.asset_ids) findingCount.set(assetId, (findingCount.get(assetId) ?? 0) + 1);
  }
  const assets: Asset[] = nativeCase.assets.map((asset) => {
    const entry = coverageByAsset.get(asset.id);
    const grants = grantsByAsset.get(asset.id) ?? [];
    const coverageState = entry
      ? mapCoverageState(entry.status)
      : asset.candidate ? "discovered_not_authorized" : asset.owner_confirmed ? "authorized_incomplete" : "source_unavailable_unknown";
    const localInputProfile = localInputProfileFromAsset(asset);
    const internetExposed = explicitTargetRequiresSensitiveNetworkAllowance(asset.name)
      ? false
      : asset.internet_exposed ?? undefined;
    return {
      id: asset.id,
      name: asset.name,
      type: mapAssetType(asset.kind),
      platform: platformFromAsset(asset),
      locator: asset.identifiers[0]?.value ?? asset.name,
      identifiers: asset.identifiers,
      discoveredFromSourceIds: [...asset.discovered_from],
      region: asset.region ?? undefined,
      internetExposed,
      containsSensitiveData: asset.contains_sensitive_data ?? undefined,
      coverageState,
      authorizationState: grants.length > 0 ? "authorized" : asset.candidate ? "pending" : "unknown",
      allowedModes: unique(grants.map((grant) => mapScopeMode(grant.permission))),
      findingCount: findingCount.get(asset.id) ?? 0,
      lastObservedAt: entry?.observed_at ?? undefined,
      scanAttempted: Boolean(entry?.last_run_id) || scanAttemptedAssetIds.has(asset.id),
      questionnairePlaceholder: localQuestionnaireKinds.has(String(asset.metadata?.questionnaire_kind)) && !localInputProfile,
      localInputProfile,
      declaredWebService: adaptDeclaredWebServiceMetadata(asset.metadata),
    };
  });
  const assetById = new Map(assets.map((asset) => [asset.id, asset]));
  const manifestById = new Map(manifests.map((manifest) => [manifest.id, manifest]));
  const findings: Finding[] = nativeCase.findings.map((finding) => {
    const observations = finding.evidence.map((evidence) => evidence.observed_at).sort();
    const assetNames = finding.asset_ids.map((id) => assetById.get(id)?.name).filter((name): name is string => Boolean(name));
    return {
      id: finding.id,
      caseId: finding.case_id,
      fingerprint: finding.fingerprint,
      assetId: finding.asset_ids[0] ?? "unknown-asset",
      assetIds: finding.asset_ids,
      assetName: localizedList(assetNames) || adapterText("Unknown asset", "未知資產"),
      title: finding.title,
      summary: finding.plain_language_summary,
      impact: finding.possible_impact,
      recommendation: finding.recommendation,
      expertType: finding.recommended_expert_type,
      severity: mapSeverity(finding.severity),
      confidence: mapConfidence(finding.confidence),
      priority: finding.priority,
      priorityReasons: finding.priority_reasons ?? [],
      workflowState: mapWorkflow(finding.status),
      evidence: finding.evidence.map((evidence) => ({
        id: evidence.id,
        sourceEngine: evidence.engine_id,
        observedAt: evidence.observed_at,
        summary: evidence.summary,
        rawArtifactHash: evidence.artifact_sha256,
        rawArtifactPath: evidence.pointer ?? undefined,
        kind: evidence.kind,
        runId: evidence.run_id,
        engineRunId: evidence.engine_run_id ?? undefined,
        artifactId: evidence.artifact_id,
        redacted: evidence.redacted,
      })),
      controls: finding.control_references.map((control) => ({
        framework: control.framework,
        version: control.framework_version,
        controlId: control.control_id,
        relationship: "related",
        title: control.title,
        rationale: control.rationale,
        mappingVersion: control.mapping_version,
        mappingProvenance: control.mapping_provenance
          ? {
              mappingVersion: control.mapping_provenance.mapping_version,
              reviewedAt: control.mapping_provenance.reviewed_at,
              reviewProcess: control.mapping_provenance.review_process,
              catalogSha256: control.mapping_provenance.catalog_sha256,
            }
          : undefined,
        note: [control.title, control.rationale, `mapping ${control.mapping_version}`].filter(Boolean).join("；"),
      })),
      officialReferences: finding.official_references,
      verificationGuidance: finding.verification_guidance,
      rollbackConsiderations: finding.rollback_considerations ?? undefined,
      tags: finding.tags ?? [],
      firstSeenRunId: finding.first_seen_run_id,
      lastSeenRunId: finding.last_seen_run_id,
      firstSeenAt: observations[0] ?? nativeCase.created_at,
      lastSeenAt: observations.at(-1) ?? nativeCase.updated_at,
    };
  });
  const findingGroups: FindingGroup[] = (nativeCase.finding_groups ?? []).map((group) => ({
    id: group.id,
    caseId: group.case_id,
    title: group.title,
    findingIds: group.finding_ids,
    rationale: group.rationale,
    groupedBy: group.grouped_by,
    createdAt: group.created_at,
  }));
  const findingGroupEvents: FindingGroupEvent[] = (nativeCase.finding_group_events ?? []).map((event) => ({
    id: event.id,
    caseId: event.case_id,
    groupId: event.group_id,
    action: event.action,
    title: event.title,
    findingIds: event.finding_ids,
    rationale: event.rationale,
    actor: event.actor,
    occurredAt: event.occurred_at,
  }));
  const runs = [...nativeCase.scan_runs].sort((left, right) =>
    right.sequence - left.sequence ||
    right.created_at.localeCompare(left.created_at) ||
    right.id.localeCompare(left.id)
  ).map((run, runIndex) => {
    const requestOutcome = mapScanRequestOutcome(
      run.request_outcome,
      run.completed_at,
      run.engine_runs.length,
    );
    const engineRuns: EngineRun[] = run.engine_runs.map((engineRun) => {
      const taskKind = mapEngineTaskKind(engineRun.task_kind);
      const builtInLocalhostTask = isExactBuiltInLocalhostQuickScanEngine({
        engineId: engineRun.engine_id,
        taskKind,
      }) && taskKind.kind === "built_in_localhost_tcp" ? taskKind : undefined;
      const isBuiltInLocalhostTcp = Boolean(builtInLocalhostTask);
      const manifest = isBuiltInLocalhostTcp ? undefined : manifestById.get(engineRun.engine_id);
      const status = mapEngineStatus(engineRun.status);
      const checkpoint = parseCheckpoint(engineRun.resume_token, engineRun);
      const releaseIncompatible = engineRun.error_code === "resume_release_incompatible";
      const savedWorkPlanUnavailable = engineRun.error_code === "resume_work_plan_invalid";
      const cleanupIdentityUnavailable = engineRun.error_code === "runtime_cleanup_identity_unavailable"
        || [
          "cleanup_identity_unavailable",
          "interrupted_restart_cleanup_identity_unavailable",
        ].includes(engineRun.phase);
      const staticFailure = releaseIncompatible || savedWorkPlanUnavailable || cleanupIdentityUnavailable;
      const failureKind = cleanupIdentityUnavailable ? undefined : engineFailureKind(engineRun, checkpoint);
      const publicErrorCode = cleanupIdentityUnavailable
        ? "runtime_cleanup_identity_unavailable"
        : engineRun.error_code;
      const publicCheckpoint = (failureKind === "gateway_preparation_failed" || staticFailure) && checkpoint
        ? { ...checkpoint, lastError: undefined }
        : checkpoint;
      const recoveryAction = staticFailure
        ? "none"
        : engineRecoveryAction(
          status,
          Boolean(engineRun.resume_token),
          checkpoint,
          publicErrorCode,
        );
      const exactFindingCount = nativeCase.findings.filter((finding) =>
        finding.evidence.some((evidence) => evidence.engine_run_id === engineRun.id)
      ).length;
      const hasLegacyUnattributedEvidence = nativeCase.findings.some((finding) =>
        finding.evidence.some((evidence) =>
          evidence.run_id === run.id &&
          evidence.engine_id === engineRun.engine_id &&
          !evidence.engine_run_id
        )
      );
      return {
        id: engineRun.id,
        engineId: engineRun.engine_id,
        engineName: isBuiltInLocalhostTcp
          ? `127.0.0.1:${builtInLocalhostTask!.port} TCP`
          : manifest?.name ?? engineRun.engine_id,
        category: isBuiltInLocalhostTcp ? "built_in_localhost_tcp" : manifest?.category ?? "unknown",
        version: isBuiltInLocalhostTcp
          ? undefined
          : engineRun.engine_version ?? manifest?.version ?? adapterText("Not reported", "未回報"),
        digest: isBuiltInLocalhostTcp
          ? undefined
          : engineRun.image_digest ?? manifest?.imageDigest ?? adapterText("No image digest", "未提供映像摘要"),
        taskKind,
        localhostTcpObservation: isBuiltInLocalhostTcp
          ? mapLocalhostTcpObservation(engineRun.localhost_tcp_observation)
          : undefined,
        ruleVersion: isBuiltInLocalhostTcp ? undefined : engineRun.rule_version ?? undefined,
        adapterVersion: isBuiltInLocalhostTcp ? undefined : engineRun.adapter_version,
        manifestSchemaVersion: isBuiltInLocalhostTcp ? undefined : engineRun.manifest_schema_version ?? undefined,
        sourceRevision: isBuiltInLocalhostTcp ? undefined : engineRun.source_revision ?? undefined,
        repositoryUrl: isBuiltInLocalhostTcp ? undefined : engineRun.repository_url ?? undefined,
        distributionMode: isBuiltInLocalhostTcp ? undefined : engineRun.distribution_mode ?? undefined,
        imageRepository: isBuiltInLocalhostTcp ? undefined : engineRun.image_repository ?? undefined,
        commandSha256: isBuiltInLocalhostTcp ? undefined : engineRun.command_sha256 ?? undefined,
        knowledgeInput: !isBuiltInLocalhostTcp && engineRun.knowledge_input ? {
          kind: engineRun.knowledge_input.kind,
          identifier: engineRun.knowledge_input.identifier,
          version: engineRun.knowledge_input.version ?? undefined,
          acquisitionSource: engineRun.knowledge_input.acquisition_source ?? undefined,
          pinState: engineRun.knowledge_input.pin_state,
          knowledgeDate: engineRun.knowledge_input.knowledge_date ?? undefined,
          supportUntil: engineRun.knowledge_input.support_until ?? undefined,
        } : undefined,
        runtimeProvider: isBuiltInLocalhostTcp ? undefined : engineRun.runtime_provider ?? undefined,
        runtimeVersion: isBuiltInLocalhostTcp ? undefined : engineRun.runtime_version ?? undefined,
        runtimeSecurityOptions: isBuiltInLocalhostTcp ? undefined : engineRun.runtime_security_options ?? undefined,
        exitCode: isBuiltInLocalhostTcp ? undefined : engineRun.exit_code ?? undefined,
        cleanupRemoved: isBuiltInLocalhostTcp ? undefined : engineRun.cleanup_removed ?? undefined,
        cleanupDetail: isBuiltInLocalhostTcp || staticFailure ? undefined : engineRun.cleanup_detail ?? undefined,
        warnings: staticFailure ? [] : engineRun.warnings ?? [],
        status,
        progress: engineRun.progress_percent,
        phase: engineRun.phase,
        startedAt: engineRun.started_at ?? undefined,
        finishedAt: engineRun.finished_at ?? undefined,
        assetIds: engineRun.asset_ids,
        rawArtifactCount: engineRun.raw_artifact_ids?.length ?? 0,
        findingCount: exactFindingCount,
        findingCountKnown: !hasLegacyUnattributedEvidence,
        message: releaseIncompatible
          ? adapterText(
            "This saved check was created by a different app release and cannot be continued safely. Start a new scan; saved evidence and findings remain unchanged.",
            "這項已保存的檢查由不同版本的應用程式建立，無法安全續跑。請開始新的掃描；已保存的證據與問題不會變更。",
          )
          : savedWorkPlanUnavailable
          ? adapterText(
            "This saved check could not be matched to its original target plan. Nothing was rerun and no target was contacted. Start a new scan; existing data remains available.",
            "這項已保存的檢查無法對應到原本的目標計畫。這次沒有重新執行，也沒有連線到任何目標；請開始新的掃描，既有資料仍會保留。",
          )
          : cleanupIdentityUnavailable
          ? adapterText(
            "This check ended safely, and its older data and results were kept. Start a new scan when you want fresh results; nothing else is required.",
            "這項檢查已安全結束，較舊的資料與結果都已保留。需要新結果時請開始新的掃描；不需要做其他處理。",
          )
          : failureKind === "gateway_preparation_failed"
          ? adapterText(
            "The private scan connection could not be prepared.",
            "無法準備這次掃描使用的專用連線。",
          )
          : engineRun.error_message ?? (engineRun.error_code
            ? adapterText(`Error code: ${engineRun.error_code}`, `錯誤代碼：${engineRun.error_code}`)
            : engineRun.phase),
        errorCode: publicErrorCode ?? undefined,
        checkpoint: publicCheckpoint,
        scopeContractBound: typeof engineRun.scope_contract_sha256 === "string"
          && engineRun.scope_contract_sha256.length > 0,
        failureKind,
        recoveryAction,
        resumable: recoveryAction !== "none",
      };
    });
    const allAssetIds = unique([
      ...run.engine_runs.flatMap((engineRun) => engineRun.asset_ids),
      ...(requestOutcome?.requestedAssetIds ?? []),
    ]);
    const coveredAssetIds = allAssetIds.filter((assetId) => {
      const applicableRuns = engineRuns.filter((engineRun) => engineRun.assetIds.includes(assetId));
      return applicableRuns.length > 0 && applicableRuns.every((engineRun) =>
        engineRun.taskKind.kind === "built_in_localhost_tcp"
          ? exactCompletedLocalhostBinding(engineRun, assetId, nativeCase.assets)
          : engineRun.status === "completed"
      );
    });
    const status = requestOutcome ? "no_checks_completed" : runStatus(engineRuns);
    const lastEngineActivityAt = [...run.engine_runs]
      .flatMap((engineRun) => [engineRun.started_at, engineRun.finished_at])
      .filter((value): value is string => Boolean(value))
      .sort()
      .at(-1);
    return {
      id: run.id,
      caseId: run.case_id,
      label: adapterText(`Scan ${run.sequence}`, `第 ${run.sequence} 次掃描`),
      sequence: run.sequence,
      verificationBaselineRunId: run.verification_baseline_run_id ?? undefined,
      requestOutcome,
      status,
      progress: engineRuns.length > 0
        ? Math.round(engineRuns.reduce((total, engineRun) => total + engineRun.progress, 0) / engineRuns.length)
        : 0,
      startedAt: run.engine_runs.map((engineRun) => engineRun.started_at).filter((value): value is string => Boolean(value)).sort()[0] ?? run.created_at,
      finishedAt: run.completed_at ?? undefined,
      lastProgressAt: runIndex === 0 && ["queued", "running", "paused"].includes(status)
        ? nativeCase.updated_at
        : run.completed_at ?? lastEngineActivityAt ?? run.created_at,
      knowledgeDate: run.knowledge_cutoff,
      engineAdmissionIssues: (run.engine_admission_issues ?? []).map((issue) => ({
        engineId: issue.engine_id ?? undefined,
        code: issue.code,
        detail: issue.detail,
      })),
      engineRuns,
      coveredAssetCount: coveredAssetIds.length,
      totalAssetCount: allAssetIds.length,
    };
  });
  const scopeGrants: ScopeGrant[] = nativeCase.scope_grants.map((grant) => ({
    id: grant.id,
    assetId: grant.asset_id,
    modes: [mapScopeMode(grant.permission)],
    state: "authorized",
    confirmedAt: grant.confirmed_at,
    confirmedBy: grant.confirmed_by,
    note: grant.notes ?? undefined,
    externalScope: grant.external_scope ? adaptExternalScope(grant.external_scope) : undefined,
  }));
  const workflowEvents = (nativeCase.finding_workflow_events ?? []).map((event) => ({
    id: event.id,
    findingId: event.finding_id,
    fromStatus: mapWorkflow(event.from_status),
    toStatus: mapWorkflow(event.to_status),
    decidedBy: event.decided_by,
    decidedAt: event.decided_at,
    reason: event.reason,
    expiresAt: event.expires_at ?? undefined,
  }));
  const exports: CaseExport[] = nativeCase.exports.map((item) => ({
    ...adaptNativeExport(item),
    isDemo: nativeCase.is_demo,
  }));
  const comparison = nativeCase.comparisons.at(-1);
  let verification: VerificationSummary | undefined;
  if (comparison) {
    const nativeFindingById = new Map(nativeCase.findings.map((finding) => [finding.id, finding]));
    const runById = new Map(nativeCase.scan_runs.map((run) => [run.id, run]));
    verification = {
      baselineRunId: comparison.baseline_run_id,
      comparisonRunId: comparison.current_run_id,
      baselineAt: runById.get(comparison.baseline_run_id)?.completed_at ?? runById.get(comparison.baseline_run_id)?.created_at ?? comparison.created_at,
      comparisonAt: runById.get(comparison.current_run_id)?.completed_at ?? runById.get(comparison.current_run_id)?.created_at ?? comparison.created_at,
      complete: comparison.complete ?? false,
      completenessIssues: (comparison.completeness_issues ?? []).map((reason) => ({
        code: reason.code,
        engineId: reason.engine_id ?? undefined,
        assetId: reason.asset_id ?? undefined,
        detail: reason.detail,
      })),
      diffs: comparison.diffs.map((diff, index) => {
        const sourceFinding = nativeFindingById.get(diff.current_finding_id ?? "") ?? nativeFindingById.get(diff.baseline_finding_id ?? "");
        const statusMap: Record<string, DiffState> = {
          resolved: "resolved",
          still_present: "persistent",
          newly_observed: "new",
          changed: "persistent",
          unable_to_verify: "unverifiable",
        };
        return {
          id: `${comparison.id}-${index}`,
          findingId: diff.current_finding_id ?? diff.baseline_finding_id ?? undefined,
          title: sourceFinding?.title ?? diff.fingerprint,
          assetName: localizedList(
            sourceFinding?.asset_ids
              .map((id) => assetById.get(id)?.name)
              .filter((name): name is string => Boolean(name)) ?? [],
          ) || adapterText("Unknown asset", "未知資產"),
          state: statusMap[diff.status] ?? "unverifiable",
          beforeSeverity: diff.baseline_severity ? mapSeverity(diff.baseline_severity) : undefined,
          afterSeverity: diff.current_severity ? mapSeverity(diff.current_severity) : undefined,
          explanation: diff.explanation,
          evidenceChanged: diff.evidence_changed ?? false,
          changeReasons: (diff.reasons ?? []).map((reason) => ({
            code: reason.code,
            engineId: reason.engine_id ?? undefined,
            assetId: reason.asset_id ?? undefined,
            detail: reason.detail,
          })),
        };
      }),
    };
  }
  const assessmentIntent = mapAssessmentIntent(nativeCase.assessment_intent);
  const platforms = withDraftIntentFallback(
    unique([
      ...assets.map((asset) => asset.platform),
      ...nativeCase.data_sources
        .filter((source) => source.status !== "not_applicable")
        .map((source) => platformFromSource(source.kind)),
    ]),
    assessmentIntent,
    nativeCase.status,
    nativeCase.assets.length,
  );
  const assessmentCase: AssessmentCase = {
    id: nativeCase.id,
    name: nativeCase.title,
    assessmentIntent,
    aiGeneratedArtifact: mapAiGeneratedArtifact(nativeCase.ai_generated_artifact),
    organizationName: nativeCase.profile.organization_name,
    companySize: mapCompanySize(nativeCase.profile.employee_range),
    dataClasses: mapDataClasses(nativeCase.profile.data_classes),
    requestedActivities: (nativeCase.requested_activities ?? []).filter(
      (activity): activity is AssessmentActivity => [
        "configuration_assessment",
        "local_artifact_analysis",
        "low_impact_external_checks",
        "active_external_vulnerability_tests",
      ].includes(activity),
    ),
    platforms,
    createdAt: nativeCase.created_at,
    updatedAt: nativeCase.updated_at,
    phase: mapPhase(nativeCase.status),
    isDemo: nativeCase.is_demo,
    description: nativeCase.profile.notes ?? undefined,
    latestRunId: runs[0]?.id,
    assetCount: nativeCase.assets.length,
    findingCount: nativeCase.findings.length,
    productIdentity: (() => {
      const productRuns = runs.filter(isExactBuiltInLocalhostQuickScanRun);
      if (productRuns.length === 0 || productRuns.length !== runs.length) return undefined;
      const ports = new Set(productRuns.map((run) => {
        const taskKind = run.engineRuns[0]?.taskKind;
        return taskKind?.kind === "built_in_localhost_tcp" ? taskKind.port : undefined;
      }));
      if (ports.size !== 1) return undefined;
      const port = [...ports][0];
      return typeof port === "number"
        ? { kind: "localhost_quick_scan" as const, port }
        : undefined;
    })(),
  };
  return { case: assessmentCase, sources, coverage, assets, scopeGrants, runs, findings, findingGroups, findingGroupEvents, workflowEvents, exports, verification };
};

export const adaptNativeSnapshot = (
  snapshot: NativeAppSnapshot,
  nativeManifests: NativeEngineManifest[],
): AppSnapshot => {
  const engineManifests = nativeManifests.map(adaptNativeManifest);
  const workspace = snapshot.selected_case ? adaptNativeCase(snapshot.selected_case, engineManifests) : undefined;
  if (workspace) {
    workspace.beginnerReports = (snapshot.beginner_reports ?? []).map(adaptBeginnerMasterReport);
  }
  const cases = snapshot.cases.map(adaptSummary);
  if (workspace) {
    const index = cases.findIndex((item) => item.id === workspace.case.id);
    if (index >= 0) cases[index] = workspace.case;
    else cases.unshift(workspace.case);
  }
  return {
    cases,
    selectedCaseId: workspace?.case.id,
    workspace,
    engineManifests,
    generatedAt: new Date().toISOString(),
    provenance: "native",
    productName: snapshot.product_name,
    productVersion: snapshot.product_version,
    storagePath: snapshot.storage_path,
    runtime: {
      provider: snapshot.runtime.provider,
      available: snapshot.runtime.available,
      phase: snapshot.runtime.phase,
      version: snapshot.runtime.version ?? undefined,
      prerequisite: snapshot.runtime.prerequisite ?? undefined,
      detail: snapshot.runtime.detail,
    },
    artifactCleanupObligations: snapshot.artifact_cleanup_obligations.map((obligation) => ({
      caseId: obligation.case_id,
      exactPath: obligation.exact_path,
      exists: obligation.exists,
      requiresExplicitConfirmation: obligation.requires_explicit_confirmation,
    })),
    caseRecoveryDiagnostics: (snapshot.case_recovery_diagnostics ?? []).map((diagnostic) => ({
      caseId: diagnostic.case_id,
      title: diagnostic.title,
      updatedAt: diagnostic.updated_at,
      revision: diagnostic.revision,
      documentBytes: diagnostic.document_bytes,
      code: diagnostic.code,
      message: diagnostic.message,
      preserved: diagnostic.preserved,
    })),
    engineAdmissionIssues: (snapshot.engine_admission_issues ?? []).map((issue) => ({
      engineId: issue.engine_id ?? undefined,
      code: issue.code,
      detail: issue.detail,
    })),
    engineCount: snapshot.engine_count,
  };
};

export const adaptBeginnerMasterReport = (
  report: NativeBeginnerMasterReport,
): BeginnerMasterReport => ({
  schemaVersion: report.schema_version,
  caseId: report.case_id,
  runId: report.run_id,
  projectTitle: report.project_title,
  state: {
    summary: report.state.summary,
    lifecycle: report.state.lifecycle,
    lastDurableUpdate: report.state.last_durable_update,
    explanation: report.state.explanation,
  },
  requested: {
    targets: report.requested.targets.map((target) => ({
      assetId: target.asset_id,
      label: target.label ?? undefined,
      assetKind: target.asset_kind ?? undefined,
      labelAvailability: target.label_availability,
      assetKindAvailability: target.asset_kind_availability,
    })),
    stage: {
      value: report.requested.stage.value ?? undefined,
      availability: report.requested.stage.availability,
      explanation: report.requested.stage.explanation,
    },
    limits: report.requested.limits.map((limit) => ({ ...limit })),
    requestedCheckIds: [...report.requested.requested_check_ids],
    requestOutcomeCode: report.requested.request_outcome_code ?? undefined,
    automaticReductions: report.requested.automatic_reductions.map((reduction) => ({ ...reduction })),
    reductionsAvailability: report.requested.reductions_availability,
    unavailableDimensions: report.requested.unavailable_dimensions.map((dimension) => ({ ...dimension })),
  },
  actual: {
    observedFrom: report.actual.observed_from ?? undefined,
    observedUntil: report.actual.observed_until ?? undefined,
    checks: report.actual.checks.map((check) => ({
      taskId: check.task_id,
      checkId: check.check_id,
      targetAssetIds: [...check.target_asset_ids],
      status: check.status,
      startedAt: check.started_at ?? undefined,
      finishedAt: check.finished_at ?? undefined,
      testedDimensions: check.tested_dimensions.map((dimension) => ({
        dimension: dimension.dimension,
        value: dimension.value,
        observation: dimension.observation,
        observedAt: dimension.observed_at ?? undefined,
      })),
    })),
    networkScopes: (report.actual.network_scopes ?? []).map((scope) => ({
      taskId: scope.task_id,
      checkId: scope.check_id,
      workUnitId: scope.work_unit_id,
      targetAssetId: scope.target_asset_id,
      target: scope.target,
      addressRanges: [...scope.address_ranges],
      portRanges: [...scope.port_ranges],
      transport: scope.transport,
      stage: scope.stage,
      outcome: scope.outcome,
      observedAt: scope.observed_at ?? undefined,
    })),
    unavailableDimensions: report.actual.unavailable_dimensions.map((dimension) => ({ ...dimension })),
  },
  coverageGaps: report.coverage_gaps.map((gap) => ({
    kind: gap.kind,
    taskId: gap.task_id ?? undefined,
    targetAssetIds: [...gap.target_asset_ids],
    dimension: gap.dimension,
    reason: gap.reason,
    nextActionCode: gap.next_action_code,
    nextAction: gap.next_action,
  })),
  coverageCounts: {
    testedComplete: report.coverage_counts.tested_complete,
    testedPartial: report.coverage_counts.tested_partial,
    failed: report.coverage_counts.failed,
    timedOut: report.coverage_counts.timed_out,
    cancelled: report.coverage_counts.cancelled,
    notTested: report.coverage_counts.not_tested,
    excluded: report.coverage_counts.excluded,
    truncated: report.coverage_counts.truncated,
    unavailable: report.coverage_counts.unavailable,
  },
  findings: report.findings.map((finding) => ({
    findingId: finding.finding_id,
    fingerprint: finding.fingerprint,
    snapshotSource: finding.snapshot_source,
    title: finding.title,
    plainLanguageRisk: finding.plain_language_risk,
    possibleImpact: finding.possible_impact,
    severity: finding.severity,
    confidence: finding.confidence,
    priority: finding.priority ?? undefined,
    priorityReasons: [...finding.priority_reasons],
    targetAssetIds: [...finding.target_asset_ids],
    nextStep: finding.next_step,
    recommendedExpertType: finding.recommended_expert_type,
    evidenceReferences: finding.evidence_references.map((evidence) => ({
      evidenceId: evidence.evidence_id,
      engineId: evidence.engine_id,
      artifactSha256: evidence.artifact_sha256,
      observedAt: evidence.observed_at,
    })),
    frameworkReferences: finding.framework_references.map((reference) => ({
      framework: reference.framework,
      frameworkVersion: reference.framework_version,
      controlId: reference.control_id,
      title: reference.title,
      relationship: reference.relationship,
      rationale: reference.rationale,
      mappingVersion: reference.mapping_version,
    })),
  })),
  nextSteps: report.next_steps.map((step) => ({
    priority: step.priority,
    code: step.code,
    action: step.action,
    reason: step.reason,
    findingId: step.finding_id ?? undefined,
    taskId: step.task_id ?? undefined,
    recommendedExpertType: step.recommended_expert_type ?? undefined,
  })),
  technicalDetails: {
    collapsedByDefault: true,
    tasks: report.technical_details.tasks.map((task) => ({
      taskId: task.task_id,
      targetAssetIds: [...task.target_asset_ids],
      status: task.status,
      phase: task.phase,
      progressPercent: task.progress_percent,
      startedAt: task.started_at ?? undefined,
      finishedAt: task.finished_at ?? undefined,
      exitCode: task.exit_code ?? undefined,
      cleanupRemoved: task.cleanup_removed ?? undefined,
      errorCode: task.error_code ?? undefined,
      evidenceSha256: [...task.evidence_sha256],
      execution: { ...task.execution },
    })),
  },
  frameworkNotice: {
    nonCertification: report.framework_notice.non_certification,
    aidefendMappingStatus: report.framework_notice.aidefend_mapping_status,
  },
  dataQualityWarnings: [...report.data_quality_warnings],
});
