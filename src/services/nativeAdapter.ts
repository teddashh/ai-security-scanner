import type {
  AppSnapshot,
  AssessmentCase,
  Asset,
  AssetType,
  CaseExport,
  CasePhase,
  CaseWorkspace,
  CloudPlatform,
  CompanySize,
  Confidence,
  CoverageRecord,
  CoverageState,
  DataClass,
  DiffState,
  EngineManifest,
  EngineRun,
  EngineRunStatus,
  ExportFormat,
  Finding,
  FindingWorkflowState,
  RunStatus,
  ScopeGrant,
  ScopeMode,
  Severity,
  SourceKind,
  VerificationSummary,
} from "../types";

/** Snake-case DTOs emitted by src-tauri/src/domain.rs. */
export interface NativeCaseSummary {
  id: string;
  title: string;
  organization_name: string;
  status: string;
  updated_at: string;
  is_demo: boolean;
  asset_count: number;
  finding_count: number;
  latest_run_id: string | null;
}

interface NativeDataSource {
  id: string;
  kind: string;
  label: string;
  status: string;
  connected_at: string | null;
  last_discovered_at: string | null;
}

interface NativeAsset {
  id: string;
  kind: string;
  name: string;
  provider: string | null;
  region: string | null;
  identifiers: Array<{ namespace: string; value: string }>;
  candidate: boolean;
  owner_confirmed: boolean;
}

interface NativeScopeGrant {
  id: string;
  asset_id: string;
  permission: string;
  confirmed_by: string;
  confirmed_at: string;
  notes: string | null;
}

interface NativeCoverageEntry {
  id: string;
  label: string;
  source_kind: string;
  asset_id: string | null;
  status: string;
  explanation: string;
  observed_at: string | null;
}

interface NativeEngineRun {
  id: string;
  engine_id: string;
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
  engine_runs: NativeEngineRun[];
}

interface NativeEvidence {
  id: string;
  engine_id: string;
  observed_at: string;
  summary: string;
  artifact_sha256: string;
  pointer: string | null;
}

interface NativeControlReference {
  framework: string;
  framework_version: string;
  control_id: string;
  title: string;
  relationship: string;
  rationale: string;
  mapping_version: string;
}

interface NativeFinding {
  id: string;
  fingerprint: string;
  title: string;
  plain_language_summary: string;
  possible_impact: string;
  severity: string;
  confidence: string;
  priority: number;
  asset_ids: string[];
  evidence: NativeEvidence[];
  control_references: NativeControlReference[];
  recommendation: string;
  official_references: string[];
  recommended_expert_type: string;
  status: string;
}

export interface NativeCaseExport {
  id: string;
  case_id: string;
  created_at: string;
  path: string;
  sha256: string;
  signature: string | null;
  redaction_profile: string;
}

interface NativeFindingDiff {
  fingerprint: string;
  baseline_finding_id: string | null;
  current_finding_id: string | null;
  status: string;
  explanation: string;
}

interface NativeComparison {
  id: string;
  baseline_run_id: string;
  current_run_id: string;
  created_at: string;
  diffs: NativeFindingDiff[];
}

export interface NativeAssessmentCase {
  id: string;
  title: string;
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
  data_sources: NativeDataSource[];
  assets: NativeAsset[];
  scope_grants: NativeScopeGrant[];
  coverage: NativeCoverageEntry[];
  scan_runs: NativeScanRun[];
  findings: NativeFinding[];
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
  supported_asset_kinds: string[];
  status: string;
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
    version: string | null;
    detail: string;
  };
  engine_count: number;
}

const unique = <T,>(values: T[]): T[] => [...new Set(values)];

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
  if (["repository", "file_system", "iac_project"].includes(asset.kind)) return "code";
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

const mapCoverageState = (status: string): CoverageState => {
  const states: Record<string, CoverageState> = {
    discovered_authorized_scanned: "discovered_authorized_scanned",
    discovered_not_authorized: "discovered_not_authorized",
    authorized_scan_incomplete: "authorized_incomplete",
    source_connected_nothing_discovered: "source_connected_none",
    source_not_connected_unknown: "source_unavailable_unknown",
  };
  return states[status] ?? "source_unavailable_unknown";
};

const mapSourceKind = (kind: string): SourceKind => {
  if (["aws_organization", "azure_tenant", "gcp_organization"].includes(kind)) return "cloud_organization";
  if (kind === "microsoft365_tenant") return "tenant";
  if (kind === "certificate_transparency") return "certificate_transparency";
  if (kind === "git_repository") return "git";
  if (kind === "terraform_state") return "terraform_state";
  if (kind === "billing") return "billing";
  return "dns";
};

const mapScopeMode = (permission: string): ScopeMode => {
  const modes: Record<string, ScopeMode> = {
    inventory_read: "inventory",
    configuration_read: "configuration",
    local_artifact_read: "configuration",
    passive_external_discovery: "public_data",
    low_impact_external_connection: "low_impact_external",
    active_external_testing: "active_external",
  };
  return modes[permission] ?? "inventory";
};

const mapSeverity = (severity: string): Severity => {
  if (severity === "informational") return "info";
  return (["critical", "high", "medium", "low"].includes(severity) ? severity : "info") as Severity;
};

const mapConfidence = (confidence: string): Confidence => {
  if (confidence === "confirmed") return "high";
  return (["high", "medium", "low"].includes(confidence) ? confidence : "low") as Confidence;
};

const mapWorkflow = (status: string): FindingWorkflowState => {
  const states: Record<string, FindingWorkflowState> = {
    unreviewed: "unreviewed",
    sent_for_review: "expert_review_requested",
    confirmed: "confirmed",
    false_positive: "false_positive",
    remediation_planned: "assigned",
    remediated_pending_verification: "remediated_pending_verification",
    closed: "verified_resolved",
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

const runStatus = (runs: EngineRun[]): RunStatus => {
  if (runs.length === 0 || runs.every((run) => run.status === "pending")) return "queued";
  if (runs.some((run) => run.status === "running")) return "running";
  if (runs.some((run) => run.status === "paused")) return "paused";
  if (runs.every((run) => run.status === "completed")) return "completed";
  if (runs.every((run) => run.status === "cancelled")) return "cancelled";
  if (runs.every((run) => run.status === "failed" || run.status === "not_executed")) return "failed";
  return "partial";
};

const formatFromPath = (path: string): ExportFormat => {
  const lower = path.toLowerCase();
  if (lower.endsWith(".html")) return "html";
  if (lower.includes("ocsf")) return "ocsf";
  if (lower.includes("oscal")) return "oscal";
  if (lower.endsWith(".json")) return "json";
  return "case_bundle";
};

export const adaptNativeExport = (
  item: NativeCaseExport,
  includesRawEvidence = false,
): CaseExport => ({
  id: item.id,
  caseId: item.case_id,
  format: formatFromPath(item.path),
  createdAt: item.created_at,
  fileName: item.path.split(/[\\/]/).at(-1) ?? item.path,
  sha256: item.sha256,
  signatureState: item.signature ? "local_integrity" : "unsigned",
  includesRawEvidence,
  path: item.path,
});

export const adaptNativeManifest = (manifest: NativeEngineManifest): EngineManifest => {
  const platforms = unique(manifest.supported_asset_kinds.map((kind) =>
    platformFromAsset({ id: "", kind, name: "", provider: null, region: null, identifiers: [], candidate: false, owner_confirmed: false }),
  ));
  const distribution: EngineManifest["redistribution"] = manifest.distribution_mode === "bundled_image"
    ? "bundled"
    : manifest.distribution_mode === "external_executable" ? "external" : "on_demand";
  const status: EngineManifest["status"] = manifest.status === "integrated"
    ? "ready"
    : manifest.status === "deprecated" ? "outdated"
      : manifest.status === "experimental" ? "not_downloaded" : "unsupported";
  return {
    id: manifest.id,
    name: manifest.display_name,
    category: manifest.category,
    version: manifest.engine_version ?? manifest.rule_version ?? "未回報",
    imageDigest: manifest.image?.digest ?? "未提供映像摘要",
    license: manifest.license_spdx,
    redistribution: distribution,
    platforms,
    status,
  };
};

const adaptSummary = (summary: NativeCaseSummary): AssessmentCase => ({
  id: summary.id,
  name: summary.title,
  organizationName: summary.organization_name,
  companySize: "small",
  dataClasses: ["none"],
  platforms: [],
  createdAt: summary.updated_at,
  updatedAt: summary.updated_at,
  phase: mapPhase(summary.status),
  isDemo: summary.is_demo,
  latestRunId: summary.latest_run_id ?? undefined,
});

export const adaptNativeCase = (
  nativeCase: NativeAssessmentCase,
  manifests: EngineManifest[] = [],
): CaseWorkspace => {
  const coverage: CoverageRecord[] = nativeCase.coverage.map((entry) => ({
    id: entry.id,
    label: entry.label,
    platform: platformFromSource(entry.source_kind),
    sourceKind: mapSourceKind(entry.source_kind),
    state: mapCoverageState(entry.status),
    assetCount: entry.asset_id ? 1 : 0,
    detail: entry.explanation,
    lastCheckedAt: entry.observed_at ?? undefined,
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
    return {
      id: asset.id,
      name: asset.name,
      type: mapAssetType(asset.kind),
      platform: platformFromAsset(asset),
      locator: asset.identifiers[0]?.value ?? asset.name,
      region: asset.region ?? undefined,
      coverageState,
      authorizationState: grants.length > 0 ? "authorized" : asset.candidate ? "pending" : "unknown",
      allowedModes: unique(grants.map((grant) => mapScopeMode(grant.permission))),
      findingCount: findingCount.get(asset.id) ?? 0,
      lastObservedAt: entry?.observed_at ?? undefined,
    };
  });
  const assetById = new Map(assets.map((asset) => [asset.id, asset]));
  const manifestById = new Map(manifests.map((manifest) => [manifest.id, manifest]));
  const findings: Finding[] = nativeCase.findings.map((finding) => {
    const observations = finding.evidence.map((evidence) => evidence.observed_at).sort();
    const assetNames = finding.asset_ids.map((id) => assetById.get(id)?.name).filter((name): name is string => Boolean(name));
    return {
      id: finding.id,
      fingerprint: finding.fingerprint,
      assetId: finding.asset_ids[0] ?? "unknown-asset",
      assetName: assetNames.join("、") || "未知資產",
      title: finding.title,
      summary: finding.plain_language_summary,
      impact: finding.possible_impact,
      recommendation: finding.recommendation,
      expertType: finding.recommended_expert_type,
      severity: mapSeverity(finding.severity),
      confidence: mapConfidence(finding.confidence),
      priority: finding.priority,
      workflowState: mapWorkflow(finding.status),
      evidence: finding.evidence.map((evidence) => ({
        id: evidence.id,
        sourceEngine: evidence.engine_id,
        observedAt: evidence.observed_at,
        summary: evidence.summary,
        rawArtifactHash: evidence.artifact_sha256,
        rawArtifactPath: evidence.pointer ?? undefined,
      })),
      controls: finding.control_references.map((control) => ({
        framework: control.framework,
        version: control.framework_version,
        controlId: control.control_id,
        relationship: "related",
        note: [control.title, control.rationale, `mapping ${control.mapping_version}`].filter(Boolean).join("；"),
      })),
      officialReferences: finding.official_references,
      firstSeenAt: observations[0] ?? nativeCase.created_at,
      lastSeenAt: observations.at(-1) ?? nativeCase.updated_at,
    };
  });
  const runs = [...nativeCase.scan_runs].reverse().map((run) => {
    const engineRuns: EngineRun[] = run.engine_runs.map((engineRun) => {
      const manifest = manifestById.get(engineRun.engine_id);
      const status = mapEngineStatus(engineRun.status);
      return {
        id: engineRun.id,
        engineId: engineRun.engine_id,
        engineName: manifest?.name ?? engineRun.engine_id,
        category: manifest?.category ?? "unknown",
        version: engineRun.engine_version ?? manifest?.version ?? "未回報",
        digest: engineRun.image_digest ?? manifest?.imageDigest ?? "未提供映像摘要",
        ruleVersion: engineRun.rule_version ?? undefined,
        status,
        progress: engineRun.progress_percent,
        startedAt: engineRun.started_at ?? undefined,
        finishedAt: engineRun.finished_at ?? undefined,
        findingCount: nativeCase.findings.filter((finding) => finding.evidence.some((evidence) => evidence.engine_id === engineRun.engine_id)).length,
        message: engineRun.error_message ?? (engineRun.error_code ? `錯誤代碼：${engineRun.error_code}` : engineRun.phase),
        resumable: Boolean(engineRun.resume_token),
      };
    });
    const allAssetIds = unique(run.engine_runs.flatMap((engineRun) => engineRun.asset_ids));
    const coveredAssetIds = unique(run.engine_runs
      .filter((engineRun) => engineRun.status === "completed")
      .flatMap((engineRun) => engineRun.asset_ids));
    return {
      id: run.id,
      caseId: run.case_id,
      label: `第 ${run.sequence} 次掃描`,
      status: runStatus(engineRuns),
      progress: engineRuns.length > 0
        ? Math.round(engineRuns.reduce((total, engineRun) => total + engineRun.progress, 0) / engineRuns.length)
        : 0,
      startedAt: run.engine_runs.map((engineRun) => engineRun.started_at).filter((value): value is string => Boolean(value)).sort()[0] ?? run.created_at,
      finishedAt: run.completed_at ?? undefined,
      knowledgeDate: run.knowledge_cutoff,
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
  }));
  const exports: CaseExport[] = nativeCase.exports.map((item) => ({
    ...adaptNativeExport(item, item.redaction_profile === "none"),
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
          assetName: sourceFinding?.asset_ids.map((id) => assetById.get(id)?.name).filter(Boolean).join("、") || "未知資產",
          state: statusMap[diff.status] ?? "unverifiable",
          beforeSeverity: sourceFinding ? mapSeverity(sourceFinding.severity) : undefined,
          afterSeverity: diff.status === "resolved" ? undefined : sourceFinding ? mapSeverity(sourceFinding.severity) : undefined,
          explanation: diff.explanation,
          evidenceChanged: diff.status === "changed",
        };
      }),
    };
  }
  const platforms = unique([
    ...assets.map((asset) => asset.platform),
    ...nativeCase.data_sources.map((source) => platformFromSource(source.kind)),
  ]);
  const assessmentCase: AssessmentCase = {
    id: nativeCase.id,
    name: nativeCase.title,
    organizationName: nativeCase.profile.organization_name,
    companySize: mapCompanySize(nativeCase.profile.employee_range),
    dataClasses: mapDataClasses(nativeCase.profile.data_classes),
    platforms,
    createdAt: nativeCase.created_at,
    updatedAt: nativeCase.updated_at,
    phase: mapPhase(nativeCase.status),
    isDemo: nativeCase.is_demo,
    description: nativeCase.profile.notes ?? undefined,
    latestRunId: nativeCase.scan_runs.at(-1)?.id,
  };
  return { case: assessmentCase, coverage, assets, scopeGrants, runs, findings, exports, verification };
};

export const adaptNativeSnapshot = (
  snapshot: NativeAppSnapshot,
  nativeManifests: NativeEngineManifest[],
): AppSnapshot => {
  const engineManifests = nativeManifests.map(adaptNativeManifest);
  const workspace = snapshot.selected_case ? adaptNativeCase(snapshot.selected_case, engineManifests) : undefined;
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
      version: snapshot.runtime.version ?? undefined,
      detail: snapshot.runtime.detail,
    },
    engineCount: snapshot.engine_count,
  };
};
