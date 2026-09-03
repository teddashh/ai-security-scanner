import assert from "node:assert/strict";
import test from "node:test";

import { readFileSync } from "node:fs";
import { build } from "esbuild";

const adapterSource = readFileSync(
  new URL("../../src/services/nativeAdapter.ts", import.meta.url),
  "utf8",
);
const scannerSource = readFileSync(
  new URL("../../src/services/scanner.ts", import.meta.url),
  "utf8",
);

const bundled = await build({
  stdin: {
    contents: 'export { adaptBeginnerMasterReport, adaptDeclaredWebServiceMetadata, adaptLocalNetworkCandidateInventory, adaptManagedRuntimePrerequisiteRepairResult, adaptManagedRuntimeSetupStatus, adaptNativeCase, adaptNativeExport, adaptNativeExportPreview, adaptNativeManifest, adaptNativeProviderBinding, adaptNativeSnapshot, exportRunFileIdentity } from "./src/services/nativeAdapter.ts"; export { caseDisplayLabels } from "./src/caseIdentityPresentation.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "native-adapter-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const source = bundled.outputFiles[0]?.text;
assert.ok(source, "the native adapter test bundle should contain JavaScript");
const {
  adaptBeginnerMasterReport,
  adaptDeclaredWebServiceMetadata,
  adaptLocalNetworkCandidateInventory,
  adaptManagedRuntimePrerequisiteRepairResult,
  adaptManagedRuntimeSetupStatus,
  adaptNativeCase,
  adaptNativeExport,
  adaptNativeExportPreview,
  adaptNativeManifest,
  adaptNativeProviderBinding,
  adaptNativeSnapshot,
  caseDisplayLabels,
  exportRunFileIdentity,
} = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
);

const nativeExportPreview = (locale: string) => ({
  case_id: "case-1",
  run_id: "run-1",
  locale,
  format: "html",
  redaction_profile: "standard",
  include_raw_evidence: false,
  data_source_count: 1,
  coverage_entry_count: 1,
  asset_count: 1,
  candidate_asset_count: 0,
  canonical_finding_count: 0,
  selected_run_finding_count: 0,
  evidence_index_count: 0,
  selected_run_evidence_count: 0,
  scan_run_count: 1,
  selected_engine_run_count: 1,
  external_scope_grant_count: 0,
  incomplete_engine_run_count: 0,
  not_executed_engine_run_count: 0,
  unknown_source_count: 0,
  connected_no_asset_count: 0,
  raw_artifact_count: 0,
  raw_artifacts_included: 0,
  raw_artifacts_omitted: 0,
  sensitive_raw_artifacts_omitted: 0,
  sensitive_data_warning: "warning",
  coverage_manifest_included: false,
});

test("native export previews preserve only the closed report locale coordinate", () => {
  assert.equal(adaptNativeExportPreview(nativeExportPreview("en")).locale, "en");
  assert.equal(adaptNativeExportPreview(nativeExportPreview("zh-Hant")).locale, "zh-Hant");
  assert.throws(
    () => adaptNativeExportPreview(nativeExportPreview("fr")),
    /Unsupported report locale/u,
  );
});

test("native exports preserve their immutable scan-run coordinate", () => {
  const adapted = adaptNativeExport({
    id: "export-1",
    case_id: "case-1",
    run_id: "run-history-2",
    created_at: "2026-09-01T01:02:03Z",
    format: "html",
    path: "C:\\reports\\report.html",
    sha256: "abc123",
    signature: null,
    redaction_profile: "standard",
  });

  assert.equal(adapted.caseId, "case-1");
  assert.equal(adapted.runId, "run-history-2");
  assert.equal(adapted.fileName, "report.html");
});

test("suggested export filenames use a stable readable sequence and opaque short identity", () => {
  const untrustedId = "../../private/person@example.com?token=secret";
  const canonical = exportRunFileIdentity({ id: untrustedId, sequence: 7 });
  const repeated = exportRunFileIdentity({ id: untrustedId, sequence: 7 });
  const different = exportRunFileIdentity({ id: `${untrustedId}-other`, sequence: 7 });
  const legacy = exportRunFileIdentity({ id: untrustedId });

  assert.match(canonical, /^scan-7-[0-9a-f]{8}$/u);
  assert.equal(repeated, canonical);
  assert.notEqual(different, canonical);
  assert.match(legacy, /^run-[0-9a-f]{8}$/u);
  assert.doesNotMatch(`${canonical} ${legacy}`, /private|person|example|token|secret|\.\./u);
});

const localCandidate = (overrides: Record<string, unknown> = {}) => ({
  id: `local-ipv4-${"a".repeat(64)}`,
  target: "192.168.50.0/24",
  kind: "local_ipv4_subnet",
  useCase: "internal_it_environment",
  internetExposure: "internal",
  addressCount: 256,
  requiresConfirmation: true,
  ...overrides,
});

test("beginner report adapter preserves the backend's run-bound coverage semantics", () => {
  const report = adaptBeginnerMasterReport({
    schema_version: "1.1.0",
    case_id: "case-1",
    run_id: "run-1",
    project_title: "Local check",
    state: {
      summary: "partial",
      lifecycle: "final",
      last_durable_update: "2026-08-30T12:00:03Z",
      explanation: "Partial results are available.",
    },
    requested: {
      targets: [{
        asset_id: "asset-1",
        label: "127.0.0.1:9001",
        asset_kind: "web_service",
        label_availability: "recorded",
        asset_kind_availability: "recorded",
      }],
      stage: {
        value: "quick_discovery",
        availability: "recorded",
        explanation: "Frozen native task.",
      },
      limits: [{ name: "connection timeout", value: "3000 ms", source: "frozen_task_contract" }],
      requested_check_ids: ["localhost_tcp_endpoint"],
      request_outcome_code: null,
      automatic_reductions: [],
      reductions_availability: "recorded",
      unavailable_dimensions: [],
    },
    actual: {
      observed_from: "2026-08-30T12:00:00Z",
      observed_until: "2026-08-30T12:00:03Z",
      checks: [{
        task_id: "task-1",
        check_id: "localhost_tcp_endpoint",
        target_asset_ids: ["asset-1"],
        status: "tested_partial",
        started_at: "2026-08-30T12:00:00Z",
        finished_at: "2026-08-30T12:00:03Z",
        tested_dimensions: [{
          dimension: "TCP reachability",
          value: "127.0.0.1:9001",
          observation: "The connection timed out.",
          observed_at: "2026-08-30T12:00:03Z",
        }],
      }],
      unavailable_dimensions: [],
    },
    coverage_gaps: [{
      kind: "timed_out",
      task_id: "task-1",
      target_asset_ids: ["asset-1"],
      dimension: "TCP reachability",
      reason: "The bounded attempt timed out.",
      next_action_code: "start_expected_service_and_retry",
      next_action: "Start the service and retry.",
    }],
    coverage_counts: {
      tested_complete: 0,
      tested_partial: 1,
      failed: 0,
      timed_out: 1,
      cancelled: 0,
      not_tested: 0,
      excluded: 0,
      truncated: 0,
      unavailable: 0,
    },
    findings: [{
      finding_id: "finding-1",
      fingerprint: "fp-1",
      snapshot_source: "frozen_selected_run",
      title: "Example problem",
      plain_language_risk: "Risk",
      possible_impact: "Impact",
      severity: "high",
      confidence: "medium",
      priority: 1,
      priority_reasons: ["Reachable service"],
      target_asset_ids: ["asset-1"],
      next_step: "Review it.",
      recommended_expert_type: "IT administrator",
      evidence_references: [{
        evidence_id: "evidence-1",
        engine_id: "native.localhost_tcp",
        artifact_sha256: "a".repeat(64),
        observed_at: "2026-08-30T12:00:03Z",
      }],
      framework_references: [],
    }],
    finding_groups: [{
      group_id: "group-1",
      presentation_scope: "current_case_presentation",
      title: "Related observations",
      rationale: "Review the shared path together.",
      actor: "Human reviewer",
      created_at: "2026-08-30T12:00:04Z",
      members: [{
        finding_id: "finding-1",
        observed_in_selected_run: true,
      }, {
        finding_id: "finding-history",
        observed_in_selected_run: false,
      }],
    }],
    next_steps: [{
      priority: 1,
      code: "start_expected_service_and_retry",
      action: "Start the service and retry.",
      reason: "The endpoint timed out.",
      finding_id: null,
      task_id: "task-1",
      recommended_expert_type: "IT administrator",
    }],
    technical_details: { collapsed_by_default: true, tasks: [] },
    framework_notice: {
      non_certification: "Not certification.",
      aidefend_mapping_status: "Independent mapping.",
    },
    data_quality_warnings: [],
  });

  assert.equal(report.state.summary, "partial");
  assert.equal(report.requested.targets[0]?.label, "127.0.0.1:9001");
  assert.equal(report.actual.checks[0]?.status, "tested_partial");
  assert.equal(report.coverageGaps[0]?.nextActionCode, "start_expected_service_and_retry");
  assert.equal(report.findings[0]?.findingId, "finding-1");
  assert.deepEqual(report.findingGroups, [{
    groupId: "group-1",
    presentationScope: "current_case_presentation",
    title: "Related observations",
    rationale: "Review the shared path together.",
    actor: "Human reviewer",
    createdAt: "2026-08-30T12:00:04Z",
    members: [{
      findingId: "finding-1",
      observedInSelectedRun: true,
    }, {
      findingId: "finding-history",
      observedInSelectedRun: false,
    }],
  }]);
  assert.equal(report.nextSteps[0]?.taskId, "task-1");
});

test("beginner report adapter preserves exact tested and untested network scope slices", () => {
  const report = adaptBeginnerMasterReport({
    schema_version: "1.0.0",
    case_id: "case-network",
    run_id: "run-network",
    project_title: "Exact network coverage",
    state: {
      summary: "partial",
      lifecycle: "final",
      last_durable_update: "2026-08-30T13:00:00Z",
      explanation: "One port was tested and one was not tested.",
    },
    requested: {
      targets: [{
        asset_id: "asset-network",
        label: "192.168.50.10",
        asset_kind: "ip_address",
        label_availability: "recorded",
        asset_kind_availability: "recorded",
      }],
      stage: {
        value: "inventory",
        availability: "recorded",
        explanation: "Frozen network plan.",
      },
      limits: [],
      requested_check_ids: ["naabu"],
      request_outcome_code: null,
      automatic_reductions: [],
      reductions_availability: "recorded",
      unavailable_dimensions: [],
    },
    actual: {
      observed_from: "2026-08-30T12:59:00Z",
      observed_until: "2026-08-30T13:00:00Z",
      checks: [],
      network_scopes: [{
        task_id: "task-naabu",
        check_id: "naabu",
        work_unit_id: "wu_tested_443",
        target_asset_id: "asset-network",
        target: "192.168.50.10",
        address_ranges: ["192.168.50.10"],
        port_ranges: ["443"],
        transport: "tcp",
        stage: "quick_discovery",
        outcome: "tested_complete",
        observed_at: "2026-08-30T12:59:30Z",
      }, {
        task_id: "task-naabu",
        check_id: "naabu",
        work_unit_id: "wu_not_tested_8443",
        target_asset_id: "asset-network",
        target: "192.168.50.10",
        address_ranges: ["192.168.50.10"],
        port_ranges: ["8443"],
        transport: "tcp",
        stage: "inventory",
        outcome: "not_tested",
        observed_at: null,
      }],
      unavailable_dimensions: [],
    },
    coverage_gaps: [],
    coverage_counts: {
      tested_complete: 1,
      tested_partial: 0,
      failed: 0,
      timed_out: 0,
      cancelled: 0,
      not_tested: 1,
      excluded: 0,
      truncated: 0,
      unavailable: 0,
    },
    findings: [],
    next_steps: [],
    technical_details: { collapsed_by_default: true, tasks: [] },
    framework_notice: {
      non_certification: "Not certification.",
      aidefend_mapping_status: "Independent mapping.",
    },
    data_quality_warnings: [],
  });

  assert.deepEqual(report.actual.networkScopes, [{
    taskId: "task-naabu",
    checkId: "naabu",
    workUnitId: "wu_tested_443",
    targetAssetId: "asset-network",
    target: "192.168.50.10",
    addressRanges: ["192.168.50.10"],
    portRanges: ["443"],
    transport: "tcp",
    stage: "quick_discovery",
    outcome: "tested_complete",
    observedAt: "2026-08-30T12:59:30Z",
  }, {
    taskId: "task-naabu",
    checkId: "naabu",
    workUnitId: "wu_not_tested_8443",
    targetAssetId: "asset-network",
    target: "192.168.50.10",
    addressRanges: ["192.168.50.10"],
    portRanges: ["8443"],
    transport: "tcp",
    stage: "inventory",
    outcome: "not_tested",
    observedAt: undefined,
  }]);
  assert.deepEqual(report.findingGroups, []);
});

test("local network candidate adapter accepts one canonical private range", () => {
  assert.deepEqual(adaptLocalNetworkCandidateInventory({
    status: "ready",
    candidates: [localCandidate()],
  }), {
    status: "ready",
    candidates: [localCandidate()],
  });
});

test("local network candidate adapter fails closed for widened or malformed suggestions", () => {
  for (const candidate of [
    localCandidate({ target: "203.0.113.0/24" }),
    localCandidate({ target: "192.168.50.1/24" }),
    localCandidate({ target: "10.0.0.0/16", addressCount: 65_536 }),
    localCandidate({ requiresConfirmation: false }),
  ]) {
    assert.deepEqual(adaptLocalNetworkCandidateInventory({
      status: "ready",
      candidates: [candidate],
    }), { status: "unavailable", candidates: [] });
  }
  assert.deepEqual(adaptLocalNetworkCandidateInventory({
    status: "ambiguous",
    candidates: [localCandidate()],
  }), { status: "unavailable", candidates: [] });
});

const runtimeSetupDto = (overrides: Record<string, unknown> = {}) => ({
  phase: "failed",
  active: false,
  prerequisite_repair_active: false,
  cancel_requested: false,
  received_bytes: 0,
  total_bytes: null,
  progress_percent: null,
  resumed_from_bytes: 0,
  can_cancel: false,
  can_retry: true,
  failure_reason: "windows_wsl_optional_feature_disabled",
  next_action: "enable_wsl_optional_features",
  detail: "bounded technical detail",
  ...overrides,
});

test("managed runtime setup adapter preserves the exact failed recovery contract", () => {
  assert.deepEqual(adaptManagedRuntimeSetupStatus(runtimeSetupDto()), {
    phase: "failed",
    active: false,
    prerequisiteRepairActive: false,
    cancelRequested: false,
    receivedBytes: 0,
    totalBytes: undefined,
    progressPercent: undefined,
    resumedFromBytes: 0,
    canCancel: false,
    canRetry: true,
    failureReason: "windows_wsl_optional_feature_disabled",
    nextAction: "enable_wsl_optional_features",
    detail: "bounded technical detail",
  });
});

test("managed runtime setup adapter rejects the retired manual WSL distribution contract", () => {
  const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    failure_reason: "windows_wsl_distribution_requires_manual_action",
    next_action: "resolve_wsl_distribution_manually",
    detail: "Windows still reports WSL distribution podman-assm1-win-x64-0123456789ab",
  }));

  assert.equal(adapted.failureReason, undefined);
  assert.equal(adapted.nextAction, undefined);
});

test("managed runtime setup adapter preserves only the bounded non-retryable package failures", () => {
  for (const failureReason of [
    "packaged_runtime_missing",
    "packaged_runtime_verification_failed",
  ] as const) {
    const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
      can_retry: false,
      failure_reason: failureReason,
      next_action: null,
    }));

    assert.equal(adapted.failureReason, failureReason);
    assert.equal(adapted.nextAction, undefined);
    assert.equal(adapted.canRetry, false);
  }

  const retryableMismatch = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    can_retry: true,
    failure_reason: "packaged_runtime_missing",
    next_action: null,
  }));
  assert.equal(retryableMismatch.failureReason, undefined);
});

test("managed runtime setup adapter preserves active automatic workspace recovery", () => {
  const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    phase: "recovery",
    active: true,
    can_cancel: true,
    failure_reason: null,
    next_action: null,
    detail: "saving a bounded recovery copy",
  }));

  assert.equal(adapted.phase, "recovery");
  assert.equal(adapted.active, true);
  assert.equal(adapted.canCancel, true);
  assert.equal(adapted.failureReason, undefined);
  assert.equal(adapted.nextAction, undefined);
});

test("managed runtime setup adapter preserves bounded backend operation authority", () => {
  const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    phase: "start",
    active: true,
    operation_id: "runtime-operation-42",
    started_at: "2026-08-30T12:00:00Z",
    last_heartbeat_at: "2026-08-30T12:00:05Z",
    stale: false,
    failure_reason: null,
    next_action: null,
  }));

  assert.equal(adapted.operationId, "runtime-operation-42");
  assert.equal(adapted.startedAt, "2026-08-30T12:00:00Z");
  assert.equal(adapted.lastHeartbeatAt, "2026-08-30T12:00:05Z");
  assert.equal(adapted.stale, false);

  const malformed = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    operation_id: `bad\0${"x".repeat(200)}`,
    started_at: "x".repeat(65),
    last_heartbeat_at: "",
    stale: "yes",
  }));
  assert.equal(malformed.operationId, undefined);
  assert.equal(malformed.startedAt, undefined);
  assert.equal(malformed.lastHeartbeatAt, undefined);
  assert.equal(malformed.stale, false);
});

test("managed runtime setup adapter hides recovery fields outside failed or when mismatched", () => {
  const unwinding = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    phase: "prerequisite",
    active: true,
  }));
  assert.equal(unwinding.failureReason, undefined);
  assert.equal(unwinding.nextAction, undefined);

  const mismatched = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    next_action: "install_wsl",
  }));
  assert.equal(mismatched.failureReason, undefined);
  assert.equal(mismatched.nextAction, undefined);

});

test("managed runtime prerequisite repair adapter accepts only bounded terminal results", () => {
  assert.deepEqual(adaptManagedRuntimePrerequisiteRepairResult({
    outcome: "completed",
    restart_required: true,
    detail: "Windows needs a restart",
  }), {
    outcome: "completed",
    restartRequired: true,
    detail: "Windows needs a restart",
  });
  assert.deepEqual(adaptManagedRuntimePrerequisiteRepairResult({
    outcome: "cancelled",
    restart_required: true,
    detail: "No change was made",
  }), {
    outcome: "cancelled",
    restartRequired: false,
    detail: "No change was made",
  });
  const malformed = adaptManagedRuntimePrerequisiteRepairResult({
    outcome: "surprise",
    restart_required: true,
    detail: `unsafe\0${"x".repeat(1_100)}`,
  });
  assert.equal(malformed.outcome, "failed");
  assert.equal(malformed.restartRequired, false);
  assert.equal(malformed.detail, "Windows prerequisite repair returned no safe detail");
});

test("declared website metadata adapts a bounded preset", () => {
  assert.deepEqual(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "https", port: 8443, path: "/login" },
  }), { protocol: "https", port: 8443, path: "/login" });
});

test("declared website metadata rejects malformed or query-bearing values", () => {
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "https", port: 443, path: "/?token=secret" },
  }), undefined);
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "ftp", port: 21, path: "/" },
  }), undefined);
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "http", port: 0, path: "/" },
  }), undefined);
});

test("native case summaries, workspaces, and case creation preserve AI applicability provenance", () => {
  assert.ok(adapterSource.includes("assessment_intent?: string | null"));
  assert.ok(adapterSource.includes("ai_generated_artifact?: string | null"));
  assert.equal((adapterSource.match(/const assessmentIntent = mapAssessmentIntent/g) ?? []).length, 2);
  assert.ok(scannerSource.includes("assessment_intent: input.assessmentIntent ?? null"));
  assert.ok(scannerSource.includes("ai_generated_artifact: input.aiGeneratedArtifact"));
});

const summaryFixture = (overrides: Record<string, unknown> = {}) => ({
  id: "case-summary-1",
  title: "Summary case",
  assessment_intent: "source_code",
  ai_generated_artifact: "yes",
  organization_name: "Example",
  employee_range: "small",
  data_classes: [],
  requested_activities: ["local_artifact_analysis"],
  source_kinds: [
    "aws_organization",
    "azure_tenant",
    "gcp_organization",
    "microsoft365_tenant",
    "git_repository",
    "container_registry",
    "kubernetes_cluster",
  ],
  applicable_source_kinds: ["git_repository", "container_registry", "kubernetes_cluster"],
  notes: null,
  status: "scope_review",
  created_at: "2026-08-26T00:00:00Z",
  updated_at: "2026-08-26T00:00:00Z",
  is_demo: false,
  asset_count: 2,
  finding_count: 0,
  latest_run_id: null,
  ...overrides,
});

const snapshotFixture = (cases: ReturnType<typeof summaryFixture>[]) => ({
  product_name: "ai-security-scanner",
  product_version: "test",
  storage_path: "redacted",
  cases,
  selected_case: null,
  runtime: {
    provider: "managed",
    available: false,
    phase: "unavailable",
    version: null,
    prerequisite: null,
    detail: "test",
  },
  artifact_cleanup_obligations: [],
  engine_count: 0,
});

const nativeManifestFixture = (overrides: Record<string, unknown> = {}) => ({
  id: "example-engine",
  display_name: "Example engine",
  category: "cloud_configuration",
  distribution_mode: "pull_pinned_image",
  image: { digest: "sha256:example" },
  engine_version: "1.0.0",
  rule_version: "rules-1",
  license_spdx: "Apache-2.0",
  supported_providers: ["aws"],
  supported_asset_kinds: ["cloud_account"],
  status: "integrated",
  compatibility: {
    knowledge_date: "2026-01-01",
    support_until: "9999-12-31",
    runnable: true,
    blocked_by: [],
  },
  ...overrides,
});

test("native manifests safely project exact release availability and provider profiles", () => {
  const m365 = adaptNativeManifest(nativeManifestFixture({
    id: "scubagear",
    display_name: "ScubaGear",
    supported_providers: ["microsoft365"],
    supported_asset_kinds: ["tenant"],
    status: "experimental",
    compatibility: {
      knowledge_date: "2026-01-01",
      support_until: "9999-12-31",
      runnable: false,
      blocked_by: ["not released"],
    },
  }));
  assert.equal(m365.status, "not_downloaded");
  assert.equal(m365.runnable, false);
  assert.equal(m365.compatibilityValid, true);
  assert.deepEqual(m365.blockedBy, ["not released"]);
  assert.deepEqual(m365.supportedProviders, ["m365"]);

  const prowlerManifest = adaptNativeManifest(nativeManifestFixture({
    id: "prowler",
    supported_providers: ["aws", "azure", "gcp"],
    supported_asset_kinds: ["cloud_account", "subscription", "project"],
    provider_execution_contracts: [
      { provider: "aws", asset_kind: "cloud_account", profile: "aws_iam_service_exact_account" },
      { provider: "azure", asset_kind: "subscription", profile: "azure_iam_service_static_token_exact_subscription" },
      { provider: "gcp", asset_kind: "project", profile: "gcp_iam_four_checks_exact_project" },
      { provider: "other", asset_kind: "project", profile: "broad_profile" },
      { provider: "gcp", asset_kind: "organization", profile: "wrong_asset_kind" },
    ],
  }));
  assert.deepEqual(prowlerManifest.providerExecutionProfiles, [
    { provider: "aws", assetKind: "cloud_account", profile: "aws_iam_service_exact_account" },
    { provider: "azure", assetKind: "subscription", profile: "azure_iam_service_static_token_exact_subscription" },
    { provider: "gcp", assetKind: "project", profile: "gcp_iam_four_checks_exact_project" },
  ]);
});

test("missing or malformed manifest compatibility fails soft instead of inventing availability", () => {
  const missing = adaptNativeManifest(nativeManifestFixture({
    compatibility: { knowledge_date: "2026-01-01", support_until: "9999-12-31", blocked_by: [] },
  }));
  assert.equal(missing.runnable, undefined);
  assert.equal(missing.compatibilityValid, true);

  for (const compatibility of [
    { runnable: "yes", blocked_by: [] },
    { runnable: true, blocked_by: ["safe blocker", 7] },
    { runnable: true, blocked_by: ["contradicts runnable"] },
  ]) {
    const malformed = adaptNativeManifest(nativeManifestFixture({ compatibility }));
    assert.equal(malformed.runnable, undefined);
    assert.equal(malformed.compatibilityValid, false);
  }
});

test("case summaries display only applicable source platforms and preserve real multi-platform scope", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture()]), []);

  assert.deepEqual(snapshot.cases[0]?.platforms, ["code", "container", "kubernetes"]);
  assert.equal(snapshot.cases[0]?.aiGeneratedArtifact, "yes");
});

test("native snapshot preserves beginner-safe diagnostics for unreadable saved projects", () => {
  const snapshot = adaptNativeSnapshot({
    ...snapshotFixture([summaryFixture()]),
    case_recovery_diagnostics: [{
      case_id: "damaged-case",
      title: "Older scan project",
      updated_at: "2026-08-26T00:00:00Z",
      revision: 7,
      document_bytes: 2048,
      code: "case_document_unreadable",
      message: "The original local bytes were preserved.",
      preserved: true,
    }],
  }, []);

  assert.deepEqual(snapshot.caseRecoveryDiagnostics, [{
    caseId: "damaged-case",
    title: "Older scan project",
    updatedAt: "2026-08-26T00:00:00Z",
    revision: 7,
    documentBytes: 2048,
    code: "case_document_unreadable",
    message: "The original local bytes were preserved.",
    preserved: true,
  }]);
  assert.equal(snapshot.provenance, "native");
});

test("native snapshot retains packaged scanner issues only as technical structured data", () => {
  const snapshot = adaptNativeSnapshot({
    ...snapshotFixture([summaryFixture()]),
    engine_admission_issues: [{
      engine_id: "gitleaks",
      code: "engine_contract_invalid",
      detail: "test-only catalog detail",
    }, {
      engine_id: null,
      code: "catalog_container_invalid",
      detail: "test-only root detail",
    }],
  }, []);

  assert.deepEqual(snapshot.engineAdmissionIssues, [{
    engineId: "gitleaks",
    code: "engine_contract_invalid",
    detail: "test-only catalog detail",
  }, {
    engineId: undefined,
    code: "catalog_container_invalid",
    detail: "test-only root detail",
  }]);
});

test("missing or malformed AI-generated answers fail closed to unknown", () => {
  for (const ai_generated_artifact of [undefined, null, "maybe", true]) {
    const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({
      ai_generated_artifact,
    })]), []);
    assert.equal(snapshot.cases[0]?.aiGeneratedArtifact, "unknown");
  }
});

test("draft summaries with no assets or applicable sources fall back to the selected assessment route", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({
    assessment_intent: "deployed_website",
    applicable_source_kinds: [],
    status: "draft",
    asset_count: 0,
  })]), []);

  assert.deepEqual(snapshot.cases[0]?.platforms, ["external"]);
});

const platformCaseFixture = (overrides: Record<string, unknown> = {}) => ({
  id: "case-platforms-1",
  title: "Platform display case",
  assessment_intent: "deployed_website",
  profile: {
    organization_name: "Example",
    employee_range: "small",
    data_classes: [],
    notes: null,
  },
  status: "scope_review",
  created_at: "2026-08-26T00:00:00Z",
  updated_at: "2026-08-26T00:00:00Z",
  is_demo: false,
  requested_activities: ["local_artifact_analysis"],
  data_sources: [
    {
      id: "aws-placeholder",
      kind: "aws_organization",
      label: "AWS not used",
      status: "not_applicable",
      connected_at: null,
      last_discovered_at: null,
      read_only: true,
    },
    {
      id: "azure-planned",
      kind: "azure_tenant",
      label: "Azure planned",
      status: "not_connected",
      connected_at: null,
      last_discovered_at: null,
      read_only: true,
    },
    {
      id: "kubernetes-connected",
      kind: "kubernetes_cluster",
      label: "Kubernetes connected",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
    },
  ],
  assets: [{
    id: "repository-asset",
    kind: "repository",
    name: "Repository",
    provider: null,
    region: null,
    identifiers: [],
    discovered_from: [],
    candidate: false,
    owner_confirmed: true,
    metadata: {},
  }],
  scope_grants: [],
  coverage: [],
  scan_runs: [],
  findings: [],
  exports: [],
  comparisons: [],
  ...overrides,
});

test("native sources expose only an exact non-secret provider binding", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    data_sources: [{
      id: "gcp-source",
      kind: "gcp_organization",
      label: "GCP organization",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
      metadata: {
        provider_profile: "gcp_organization_read_only_access_token",
        provider_resource_scope: "gcp-organization:123456789012",
        provider_identity: "MUST_NOT_SURVIVE",
        access_token: "SECRET",
        verification_evidence_sha256: "MUST_NOT_SURVIVE_EITHER",
      },
    }],
  }));

  assert.deepEqual(workspace.sources[0]?.providerBinding, {
    profile: "gcp_organization_read_only_access_token",
    resourceScope: "gcp-organization:123456789012",
  });
  assert.doesNotMatch(
    JSON.stringify(workspace.sources[0]),
    /MUST_NOT_SURVIVE|SECRET|"provider_identity"|"access_token"|"verification_evidence_sha256"/u,
  );
});

test("provider binding projection fails closed for incomplete, mismatched, or malformed metadata", () => {
  const invalid: Array<[string, Record<string, unknown> | undefined]> = [
    ["missing scope", { provider_profile: "aws_organization_read_only_session" }],
    ["missing profile", { provider_resource_scope: "aws-account:123456789012" }],
    ["non-string scope", { provider_profile: "aws_organization_read_only_session", provider_resource_scope: 123456789012 }],
    ["unknown profile", { provider_profile: "administrator", provider_resource_scope: "aws-account:123456789012" }],
    ["wrong source profile", { provider_profile: "gcp_organization_read_only_access_token", provider_resource_scope: "gcp-organization:123" }],
    ["wrong scope prefix", { provider_profile: "aws_organization_read_only_session", provider_resource_scope: "gcp-organization:123456789012" }],
    ["short AWS account", { provider_profile: "aws_organization_read_only_session", provider_resource_scope: "aws-account:123" }],
    ["malformed UUID", { provider_profile: "azure_tenant_read_only_access_token", provider_resource_scope: "azure-subscription:not-a-uuid" }],
    ["long GCP organization", { provider_profile: "gcp_organization_read_only_access_token", provider_resource_scope: `gcp-organization:${"1".repeat(33)}` }],
    ["suffix", { provider_profile: "aws_organization_read_only_session", provider_resource_scope: "aws-account:123456789012\n<script>" }],
  ];

  for (const [label, metadata] of invalid) {
    const sourceKind = label === "wrong source profile"
      ? "aws_organization"
      : label === "malformed UUID" ? "azure_tenant"
        : label === "long GCP organization" ? "gcp_organization"
          : "aws_organization";
    assert.equal(adaptNativeProviderBinding(sourceKind, metadata), undefined, label);
  }
});

const localhostSelectedCaseFixture = ({
  id,
  title,
  createdAt,
  port,
}: {
  id: string;
  title: string;
  createdAt: string;
  port: number;
}) => platformCaseFixture({
  id,
  title,
  created_at: createdAt,
  updated_at: createdAt,
  data_sources: [],
  assets: [{
    id: `${id}-asset`,
    kind: "web_service",
    name: `127.0.0.1:${port}`,
    provider: null,
    region: null,
    identifiers: [{ namespace: "localhost_tcp_endpoint", value: `127.0.0.1:${port}` }],
    discovered_from: [],
    candidate: false,
    owner_confirmed: true,
    internet_exposed: false,
    metadata: {},
  }],
  scan_runs: [{
    id: `${id}-run`,
    case_id: id,
    sequence: 1,
    created_at: createdAt,
    completed_at: createdAt,
    knowledge_cutoff: createdAt,
    engine_runs: [{
      id: `${id}-task`,
      engine_id: "built-in-localhost-tcp",
      task_kind: {
        kind: "built_in_localhost_tcp",
        port,
        timeout_ms: 3000,
        payload_bytes: 0,
      },
      localhost_tcp_observation: {
        outcome: "reachable",
        observed_at: createdAt,
      },
      asset_ids: [`${id}-asset`],
      status: "completed",
      progress_percent: 100,
      phase: "completed",
      started_at: createdAt,
      finished_at: createdAt,
      resume_token: null,
      engine_version: null,
      image_digest: null,
      rule_version: null,
      adapter_version: "",
      raw_artifact_ids: [],
      error_code: null,
      error_message: null,
    }],
  }],
});

test("structured localhost identities remain stable while switching selected cases", () => {
  const createdAt = "2026-08-30T12:00:00Z";
  const summaries = [
    summaryFixture({
      id: "quick-a",
      title: "Persisted legacy name A",
      created_at: createdAt,
      product_identity: { kind: "localhost_quick_scan", port: 9001 },
    }),
    summaryFixture({
      id: "quick-b",
      title: "Persisted legacy name B",
      created_at: createdAt,
      product_identity: { kind: "localhost_quick_scan", port: 9001 },
    }),
  ];
  const selectedA = adaptNativeSnapshot({
    ...snapshotFixture(summaries),
    selected_case: localhostSelectedCaseFixture({
      id: "quick-a",
      title: "Persisted legacy name A",
      createdAt,
      port: 9001,
    }),
  }, []);
  const selectedB = adaptNativeSnapshot({
    ...snapshotFixture(summaries),
    selected_case: localhostSelectedCaseFixture({
      id: "quick-b",
      title: "Persisted legacy name B",
      createdAt,
      port: 9001,
    }),
  }, []);

  for (const snapshot of [selectedA, selectedB]) {
    assert.deepEqual(snapshot.cases.map((assessmentCase: { productIdentity?: unknown }) => (
      assessmentCase.productIdentity
    )), [
      { kind: "localhost_quick_scan", port: 9001 },
      { kind: "localhost_quick_scan", port: 9001 },
    ]);
  }

  const labelsA = [...caseDisplayLabels(selectedA.cases, "zh-TW")];
  const labelsB = [...caseDisplayLabels(selectedB.cases, "zh-TW")];
  assert.deepEqual(labelsA, labelsB);
  assert.notEqual(labelsA[0]?.[1], labelsA[1]?.[1]);
  assert.match(labelsA[0]?.[1] ?? "", /quick-a$/u);
  assert.match(labelsA[1]?.[1] ?? "", /quick-b$/u);
});

test("malformed summary product identities fail closed", () => {
  for (const product_identity of [
    { kind: "localhost_quick_scan", port: 0 },
    { kind: "localhost_quick_scan", port: 65_536 },
    { kind: "localhost_quick_scan", port: 9001.5 },
    { kind: "lookalike", port: 9001 },
  ]) {
    const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({ product_identity })]), []);
    assert.equal(snapshot.cases[0]?.productIdentity, undefined);
  }
});

test("full cases combine asset and applicable source platforms without questionnaire placeholders", () => {
  const workspace = adaptNativeCase(platformCaseFixture());

  assert.deepEqual(workspace.case.platforms, ["code", "azure", "kubernetes"]);
});

test("native findings keep unknown severity distinct from informational", () => {
  const finding = (id: string, severity: string) => ({
    id,
    case_id: "case-platforms-1",
    first_seen_run_id: "run-1",
    last_seen_run_id: "run-1",
    fingerprint: `fingerprint-${id}`,
    title: id,
    plain_language_summary: "Review this scanner observation.",
    possible_impact: "Impact was not rated by the source.",
    severity,
    confidence: "medium",
    priority: 20,
    priority_reasons: [`Source severity: ${severity}`],
    asset_ids: ["repository-asset"],
    evidence: [],
    control_references: [],
    recommendation: "Ask a qualified reviewer.",
    verification_guidance: "Review the source evidence.",
    rollback_considerations: null,
    official_references: [],
    recommended_expert_type: "Security reviewer",
    status: "unreviewed",
    tags: [],
  });
  const workspace = adaptNativeCase(platformCaseFixture({
    findings: [
      finding("backend-unknown", "unknown"),
      finding("unrecognized", "vendor-special"),
      finding("explicit-info", "informational"),
    ],
  }));

  assert.deepEqual(
    workspace.findings.map(({ id, severity }: { id: string; severity: string }) => [id, severity]),
    [
      ["backend-unknown", "unknown"],
      ["unrecognized", "unknown"],
      ["explicit-info", "info"],
    ],
  );
});

test("draft full cases with no assets or applicable sources use the assessment route fallback", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assessment_intent: "source_code",
    status: "draft",
    data_sources: [{
      id: "aws-placeholder",
      kind: "aws_organization",
      label: "AWS not used",
      status: "not_applicable",
      connected_at: null,
      last_discovered_at: null,
      read_only: true,
    }],
    assets: [],
  }));

  assert.deepEqual(workspace.case.platforms, ["code"]);
});

test("questionnaire-only local names stay distinct from attached workspace snapshots", () => {
  assert.ok(adapterSource.includes("localQuestionnaireKinds"));
  assert.ok(adapterSource.includes("questionnairePlaceholder:"));
  assert.ok(adapterSource.includes('asset.metadata?.workspace_snapshot_id === "string"'));
});

test("native assets preserve the exact data-source provenance used for cloud binding", () => {
  const workspace = adaptNativeCase({
    id: "case-1",
    title: "Two AWS accounts",
    assessment_intent: "cloud_account",
    profile: {
      organization_name: "Example",
      employee_range: "small",
      data_classes: [],
      notes: null,
    },
    status: "scope_review",
    created_at: "2026-08-26T00:00:00Z",
    updated_at: "2026-08-26T00:00:00Z",
    is_demo: false,
    requested_activities: ["configuration_assessment"],
    data_sources: [
      {
        id: "aws-source-a",
        kind: "aws_organization",
        label: "AWS account A",
        status: "connected",
        connected_at: "2026-08-26T00:00:00Z",
        last_discovered_at: "2026-08-26T00:00:00Z",
        read_only: true,
      },
      {
        id: "aws-source-b",
        kind: "aws_organization",
        label: "AWS account B",
        status: "connected",
        connected_at: "2026-08-26T00:00:00Z",
        last_discovered_at: "2026-08-26T00:00:00Z",
        read_only: true,
      },
    ],
    assets: [{
      id: "aws-account-a",
      kind: "cloud_account",
      name: "AWS account A",
      provider: "aws",
      region: null,
      identifiers: [{ namespace: "aws_account_id", value: "111111111111" }],
      discovered_from: ["aws-source-a"],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: null,
      contains_sensitive_data: null,
      metadata: {},
    }],
    scope_grants: [],
    coverage: [],
    scan_runs: [],
    findings: [],
    exports: [],
    comparisons: [],
  });

  assert.deepEqual(workspace.assets[0]?.discoveredFromSourceIds, ["aws-source-a"]);
});

test("native adapter repairs stale public display for an explicit loopback asset", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "loopback-asset",
      kind: "ip_address",
      name: "127.0.0.1",
      provider: null,
      region: null,
      identifiers: [{ namespace: "ip_address", value: "127.0.0.1" }],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: true,
      metadata: { questionnaire_kind: "external_target" },
    }],
    data_sources: [],
  }));

  assert.equal(workspace.assets[0]?.internetExposed, false);
});

test("native adapter repairs stale public display for an explicit private CIDR", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "private-network-asset",
      kind: "ip_address",
      name: "192.168.102.0/23",
      provider: null,
      region: null,
      identifiers: [{ namespace: "ip_address", value: "192.168.102.0/23" }],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: true,
      metadata: { questionnaire_kind: "external_target" },
    }],
    data_sources: [],
  }));

  assert.equal(workspace.assets[0]?.internetExposed, false);
});

test("authorized coverage distinguishes a saved permission from an attempted scan", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "loopback-asset",
      kind: "ip_address",
      name: "127.0.0.1",
      provider: null,
      region: null,
      identifiers: [{ namespace: "ip_address", value: "127.0.0.1" }],
      discovered_from: [],
      candidate: false,
      owner_confirmed: true,
      internet_exposed: false,
      metadata: { questionnaire_kind: "external_target" },
    }],
    data_sources: [],
    scope_grants: [{
      id: "scope-loopback",
      asset_id: "loopback-asset",
      permission: "low_impact_external",
      confirmed_by: "Owner",
      confirmed_at: "2026-08-26T00:00:00Z",
      notes: null,
      external_scope: null,
    }],
    coverage: [{
      id: "coverage-loopback",
      label: "127.0.0.1",
      source_kind: "user_declared",
      asset_id: "loopback-asset",
      status: "authorized_scan_incomplete",
      explanation: "Authorized, but no scan plan exists yet.",
      last_run_id: null,
      observed_at: "2026-08-26T00:00:00Z",
    }],
    scan_runs: [],
  }));

  assert.equal(workspace.assets[0]?.authorizationState, "authorized");
  assert.equal(workspace.assets[0]?.scanAttempted, false);
  assert.equal(workspace.coverage[0]?.scanAttempted, false);
  assert.equal(workspace.coverage[0]?.assetId, "loopback-asset");
});

const engineRunFixture = (id: string, status: string) => ({
  id,
  engine_id: id,
  asset_ids: ["repository-asset"],
  status,
  progress_percent: status === "queued" ? 0 : 100,
  phase: status,
  started_at: status === "queued" ? null : "2026-08-26T00:00:00Z",
  finished_at: status === "queued" ? null : "2026-08-26T00:01:00Z",
  resume_token: null,
  engine_version: "test",
  image_digest: null,
  rule_version: null,
  adapter_version: "test",
  raw_artifact_ids: [],
  error_code: status === "failed" ? "execution_failed" : null,
  error_message: status === "failed" ? "bounded test failure" : null,
});

test("mixed terminal and queued engine work keeps the scan queued for downstream pages", () => {
  for (const terminalStatus of [
    "completed",
    "partially_completed",
    "failed",
    "not_executed",
    "cancelled",
  ]) {
    const workspace = adaptNativeCase(platformCaseFixture({
      status: "scanning",
      scan_runs: [{
        id: `run-${terminalStatus}`,
        case_id: "case-platforms-1",
        sequence: 1,
        created_at: "2026-08-26T00:00:00Z",
        completed_at: null,
        knowledge_cutoff: "2026-08-24T00:00:00Z",
        engine_runs: [
          engineRunFixture(`engine-${terminalStatus}`, terminalStatus),
          engineRunFixture("engine-queued", "queued"),
        ],
      }],
    }));

    assert.equal(workspace.runs[0]?.engineRuns[1]?.status, "pending", terminalStatus);
    assert.equal(workspace.runs[0]?.status, "queued", terminalStatus);
  }
});

test("run-bound packaged scanner issues remain available to technical diagnostics", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    status: "needs_attention",
    scan_runs: [{
      id: "run-catalog-limitation",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:00:01Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      request_outcome: {
        status: "no_checks_completed",
        code: "no_applicable_checks",
        requested_asset_ids: [],
        requested_engine_ids: [],
        explanation: "No available check could be planned.",
      },
      engine_admission_issues: [{
        engine_id: "gitleaks",
        code: "engine_contract_invalid",
        detail: "test-only catalog detail",
      }],
      engine_runs: [],
    }],
  }));

  assert.deepEqual(workspace.runs[0]?.engineAdmissionIssues, [{
    engineId: "gitleaks",
    code: "engine_contract_invalid",
    detail: "test-only catalog detail",
  }]);
});

const adaptGatewayFailure = (
  message: string,
  errorCode = "execution_failed",
  checkpointStage = "failed",
  phase = "failed",
  warnings = errorCode === "resume_release_incompatible" ? [message] : [],
  cleanupDetail?: string,
  status = "failed",
) => {
  const checkpoint = JSON.stringify({
    case_id: "case-1",
    scan_run_id: "run-1",
    engine_run_id: "engine-run-1",
    engine_id: "naabu",
    attempt: 1,
    stage: checkpointStage,
    container_name: null,
    scope_sha256: null,
    artifact_ids: [],
    cleanup_completed: true,
    last_error: message,
  });
  return adaptNativeCase({
    id: "case-1",
    title: "Internal IP scan",
    assessment_intent: "internal_it_environment",
    profile: {
      organization_name: "Example",
      employee_range: "small",
      data_classes: [],
      notes: null,
    },
    status: "needs_attention",
    created_at: "2026-08-26T12:01:00Z",
    updated_at: "2026-08-26T12:02:00Z",
    is_demo: false,
    requested_activities: ["low_impact_external_checks"],
    data_sources: [],
    assets: [],
    scope_grants: [],
    coverage: [],
    scan_runs: [{
      id: "run-1",
      case_id: "case-1",
      sequence: 1,
      created_at: "2026-08-26T12:02:00Z",
      completed_at: "2026-08-26T12:02:01Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [{
        id: "engine-run-1",
        engine_id: "naabu",
        asset_ids: ["private-asset-id"],
        status,
        progress_percent: 0,
        phase,
        started_at: "2026-08-26T12:02:00Z",
        finished_at: "2026-08-26T12:02:01Z",
        resume_token: checkpoint,
        engine_version: "2.6.1",
        image_digest: "sha256:redacted",
        rule_version: null,
        adapter_version: "0.1.1",
        scope_contract_sha256: "a".repeat(64),
        raw_artifact_ids: [],
        error_code: errorCode,
        error_message: message,
        cleanup_detail: cleanupDetail,
        warnings,
      }],
    }],
    findings: [],
    exports: [],
    comparisons: [],
  });
};

test("native gateway failures preserve frozen authorization but restart before runtime scope", () => {
  const workspace = adaptGatewayFailure("runtime error: egress gateway exited before becoming ready");

  const failed = workspace.runs[0]?.engineRuns[0];
  assert.deepEqual(failed?.taskKind, { kind: "catalog_engine" });
  assert.equal(failed?.scopeContractBound, true);
  assert.equal(failed?.checkpoint?.scopeBound, false);
  assert.equal(failed?.failureKind, "gateway_preparation_failed");
  assert.equal(failed?.recoveryAction, "restart_check");
  assert.equal(failed?.resumable, true);
});

test("terminal partial-result outcomes do not reopen an exhausted or cancelled scan", () => {
  for (const [errorCode, status, phase] of [
    ["coverage_incomplete_after_bounded_retries", "partially_completed", "results_partial"],
    ["cancelled_after_partial_results", "cancelled", "cancelled_after_partial_results"],
  ] as const) {
    const terminal = adaptGatewayFailure(
      "Saved partial results remain available.",
      errorCode,
      "failed",
      phase,
      [],
      undefined,
      status,
    ).runs[0]?.engineRuns[0];

    assert.equal(terminal?.errorCode, errorCode);
    assert.equal(terminal?.recoveryAction, "none");
    assert.equal(terminal?.resumable, false);
  }
});

test("built-in localhost work exposes its exact task and observation without catalog provenance", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    data_sources: [],
    assets: [{
      id: "localhost-asset",
      kind: "web_service",
      name: "127.0.0.1:9001",
      provider: null,
      region: null,
      identifiers: [{ namespace: "localhost_tcp_endpoint", value: "127.0.0.1:9001" }],
      discovered_from: [],
      candidate: false,
      owner_confirmed: true,
      internet_exposed: false,
      metadata: {},
    }],
    scan_runs: [{
      id: "localhost-run",
      case_id: "case-platforms",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: "2026-08-30T12:00:01Z",
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      engine_runs: [{
        id: "localhost-task",
        engine_id: "built-in-localhost-tcp",
        task_kind: {
          kind: "built_in_localhost_tcp",
          port: 9001,
          timeout_ms: 3000,
          payload_bytes: 0,
        },
        localhost_tcp_observation: {
          outcome: "reachable",
          observed_at: "2026-08-30T12:00:01Z",
        },
        asset_ids: ["localhost-asset"],
        status: "completed",
        progress_percent: 100,
        phase: "completed",
        started_at: "2026-08-30T12:00:00Z",
        finished_at: "2026-08-30T12:00:01Z",
        resume_token: null,
        engine_version: "must-not-be-used",
        image_digest: "sha256:must-not-be-used",
        rule_version: "must-not-be-used",
        adapter_version: "must-not-be-used",
        manifest_schema_version: "must-not-be-used",
        source_revision: "must-not-be-used",
        repository_url: "https://invalid.example/must-not-be-used",
        distribution_mode: "pull_pinned_image",
        image_repository: "invalid.example/must-not-be-used",
        command_sha256: "must-not-be-used",
        knowledge_input: {
          kind: "must-not-be-used",
          identifier: "must-not-be-used",
          version: "must-not-be-used",
          acquisition_source: "must-not-be-used",
          pin_state: "must-not-be-used",
        },
        runtime_provider: "must-not-be-used",
        runtime_version: "must-not-be-used",
        runtime_security_options: "must-not-be-used",
        exit_code: 0,
        cleanup_removed: true,
        cleanup_detail: "must-not-be-used",
        warnings: [],
        raw_artifact_ids: [],
        error_code: null,
        error_message: null,
      }],
    }],
  }), [{
    id: "built-in-localhost-tcp",
    name: "Fake catalog scanner",
    category: "fake-category",
    version: "fake-version",
    imageDigest: "sha256:fake-manifest",
  }]);

  const task = workspace.runs[0]?.engineRuns[0];
  assert.equal(workspace.runs[0]?.sequence, 1);
  assert.deepEqual(workspace.case.productIdentity, {
    kind: "localhost_quick_scan",
    port: 9001,
  });
  assert.equal(workspace.runs[0]?.coveredAssetCount, 1);
  assert.deepEqual(task?.taskKind, {
    kind: "built_in_localhost_tcp",
    port: 9001,
    timeoutMs: 3000,
    payloadBytes: 0,
  });
  assert.deepEqual(task?.localhostTcpObservation, {
    outcome: "reachable",
    observedAt: "2026-08-30T12:00:01Z",
  });
  assert.equal(task?.category, "built_in_localhost_tcp");
  for (const field of [
    "version",
    "digest",
    "ruleVersion",
    "adapterVersion",
    "manifestSchemaVersion",
    "sourceRevision",
    "repositoryUrl",
    "distributionMode",
    "imageRepository",
    "commandSha256",
    "knowledgeInput",
    "runtimeProvider",
    "runtimeVersion",
    "runtimeSecurityOptions",
    "exitCode",
    "cleanupRemoved",
    "cleanupDetail",
  ]) {
    assert.equal(task?.[field], undefined, `${field} must not be synthesized for a built-in task`);
  }
  assert.doesNotMatch(JSON.stringify(task), /Fake catalog scanner|fake-version|fake-manifest|must-not-be-used/u);
});

const adaptLocalhostCoverageFixture = (
  engineOverrides: Record<string, unknown>,
  assetOverrides: Record<string, unknown> = {},
  manifests: Array<Record<string, unknown>> = [],
) => adaptNativeCase(platformCaseFixture({
  data_sources: [],
  assets: [{
    id: "localhost-asset",
    kind: "web_service",
    name: "127.0.0.1:9001",
    provider: null,
    region: null,
    identifiers: [{ namespace: "localhost_tcp_endpoint", value: "127.0.0.1:9001" }],
    discovered_from: [],
    candidate: false,
    owner_confirmed: true,
    internet_exposed: false,
    metadata: {},
    ...assetOverrides,
  }],
  scan_runs: [{
    id: "localhost-coverage-run",
    case_id: "case-platforms",
    sequence: 1,
    created_at: "2026-08-30T12:00:00Z",
    completed_at: "2026-08-30T12:00:01Z",
    knowledge_cutoff: "2026-08-30T00:00:00Z",
    engine_runs: [{
      id: "localhost-coverage-task",
      engine_id: "built-in-localhost-tcp",
      task_kind: {
        kind: "built_in_localhost_tcp",
        port: 9001,
        timeout_ms: 3000,
        payload_bytes: 0,
      },
      localhost_tcp_observation: null,
      asset_ids: ["localhost-asset"],
      status: "completed",
      progress_percent: 100,
      phase: "completed",
      started_at: "2026-08-30T12:00:00Z",
      finished_at: "2026-08-30T12:00:01Z",
      resume_token: null,
      engine_version: null,
      image_digest: null,
      rule_version: null,
      adapter_version: "",
      raw_artifact_ids: [],
      error_code: null,
      error_message: null,
      ...engineOverrides,
    }],
  }],
}), manifests);

test("completed status alone never gives a built-in localhost task covered-target credit", () => {
  assert.equal(adaptLocalhostCoverageFixture({}).runs[0]?.coveredAssetCount, 0);
  assert.equal(adaptLocalhostCoverageFixture({
    localhost_tcp_observation: {
      outcome: "reachable",
      observed_at: "2026-08-30T12:00:01Z",
    },
  }).runs[0]?.coveredAssetCount, 1);
  assert.equal(adaptLocalhostCoverageFixture({
    localhost_tcp_observation: {
      outcome: "reachable",
      observed_at: "2026-08-30T12:00:01Z",
    },
  }, {
    identifiers: [{ namespace: "ip_address", value: "127.0.0.2" }],
  }).runs[0]?.coveredAssetCount, 0);
  assert.equal(adaptLocalhostCoverageFixture({
    status: "partially_completed",
    localhost_tcp_observation: {
      outcome: "timed_out",
      observed_at: "2026-08-30T12:00:01Z",
    },
  }).runs[0]?.coveredAssetCount, 0);
});

test("a lookalike engine cannot claim built-in localhost provenance or coverage", () => {
  const workspace = adaptLocalhostCoverageFixture({
    engine_id: "lookalike-localhost-engine",
    engine_version: "1.2.3",
    image_digest: "sha256:lookalike",
    localhost_tcp_observation: {
      outcome: "reachable",
      observed_at: "2026-08-30T12:00:01Z",
    },
  }, {}, [{
    id: "lookalike-localhost-engine",
    name: "Catalog lookalike",
    category: "network",
    version: "1.2.3",
    imageDigest: "sha256:lookalike",
  }]);

  const task = workspace.runs[0]?.engineRuns[0];
  assert.equal(task?.engineName, "Catalog lookalike");
  assert.equal(task?.category, "network");
  assert.equal(task?.version, "1.2.3");
  assert.equal(task?.digest, "sha256:lookalike");
  assert.equal(task?.localhostTcpObservation, undefined);
  assert.equal(workspace.runs[0]?.coveredAssetCount, 0);
  assert.equal(workspace.case.productIdentity, undefined);
});

test("a durable no-checks request is terminal and excludes the raw backend explanation", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [],
    data_sources: [],
    scan_runs: [{
      id: "no-checks-run",
      case_id: "case-platforms",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: "2026-08-30T12:00:00Z",
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      request_outcome: {
        status: "no_checks_completed",
        code: "no_applicable_checks",
        requested_asset_ids: ["private-asset-id"],
        requested_engine_ids: [],
        explanation: "RAW_BACKEND_EXPLANATION_MUST_NOT_REACH_FIRST_LAYER",
      },
      engine_runs: [],
    }],
  }));

  const run = workspace.runs[0];
  assert.equal(run?.status, "no_checks_completed");
  assert.equal(run?.progress, 0);
  assert.equal(run?.coveredAssetCount, 0);
  assert.equal(run?.totalAssetCount, 1);
  assert.deepEqual(run?.requestOutcome, {
    status: "no_checks_completed",
    code: "no_applicable_checks",
    requestedAssetIds: ["private-asset-id"],
    requestedEngineIds: [],
  });
  assert.doesNotMatch(JSON.stringify(run), /RAW_BACKEND_EXPLANATION/u);
});

test("contradictory no-check outcomes never hide actual or unfinished engine work", () => {
  const noChecksOutcome = {
    status: "no_checks_completed",
    code: "no_applicable_checks",
    requested_asset_ids: ["repository-asset"],
    requested_engine_ids: ["engine-completed"],
    explanation: "contradictory fixture",
  };

  const completedWork = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "contradictory-completed-run",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: "2026-08-30T12:00:01Z",
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      request_outcome: noChecksOutcome,
      engine_runs: [engineRunFixture("engine-completed", "completed")],
    }],
  })).runs[0];
  assert.equal(completedWork?.status, "completed");
  assert.equal(completedWork?.requestOutcome, undefined);
  assert.equal(completedWork?.engineRuns.length, 1);

  const unfinishedOutcome = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "contradictory-unfinished-run",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: null,
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      request_outcome: noChecksOutcome,
      engine_runs: [engineRunFixture("engine-failed", "failed")],
    }],
  })).runs[0];
  assert.equal(unfinishedOutcome?.status, "failed");
  assert.equal(unfinishedOutcome?.requestOutcome, undefined);
  assert.equal(unfinishedOutcome?.engineRuns.length, 1);
});

test("an uncompleted empty run cannot claim that no checks completed", () => {
  const run = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "uncompleted-no-checks-run",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: null,
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      request_outcome: {
        status: "no_checks_completed",
        code: "no_effective_scope_grants",
        requested_asset_ids: [],
        requested_engine_ids: [],
        explanation: "not durable yet",
      },
      engine_runs: [],
    }],
  })).runs[0];

  assert.equal(run?.status, "queued");
  assert.equal(run?.requestOutcome, undefined);
});

test("release-incompatible saved work is static, redacted, and not resumable", () => {
  const rawBackendText = "RAW_BACKEND_SENTINEL mapping 2026-old target-private";
  const failed = adaptGatewayFailure(rawBackendText, "resume_release_incompatible")
    .runs[0]?.engineRuns[0];

  assert.equal(failed?.errorCode, "resume_release_incompatible");
  assert.equal(failed?.recoveryAction, "none");
  assert.equal(failed?.resumable, false);
  assert.equal(
    failed?.message,
    "這項已保存的檢查由不同版本的應用程式建立，無法安全續跑。請開始新的掃描；已保存的證據與問題不會變更。",
  );
  assert.equal(failed?.checkpoint?.lastError, undefined);
  assert.deepEqual(failed?.warnings, []);
  assert.doesNotMatch(JSON.stringify(failed), /RAW_BACKEND_SENTINEL|target-private/u);
});

test("an invalid saved work plan preserves data without offering another resume loop", () => {
  const rawBackendText = "RAW_PLAN_SENTINEL 10.44.55.66 work-plan-secret.example.test";
  const failed = adaptGatewayFailure(
    rawBackendText,
    "resume_work_plan_invalid",
    "planned",
    "resume_work_plan_invalid",
    [rawBackendText],
    rawBackendText,
  ).runs[0]?.engineRuns[0];

  assert.equal(failed?.errorCode, "resume_work_plan_invalid");
  assert.equal(failed?.recoveryAction, "none");
  assert.equal(failed?.resumable, false);
  assert.equal(
    failed?.message,
    "這項已保存的檢查無法對應到原本的目標計畫。這次沒有重新執行，也沒有連線到任何目標；請開始新的掃描，既有資料仍會保留。",
  );
  assert.equal(failed?.checkpoint?.lastError, undefined);
  assert.deepEqual(failed?.warnings, []);
  assert.equal(failed?.cleanupDetail, undefined);
  assert.doesNotMatch(JSON.stringify(failed), /RAW_PLAN_SENTINEL|10\.44\.55\.66|work-plan-secret/u);
});

test("ambiguous cleanup identity never offers an unsafe cleanup retry", () => {
  const rawBackendText = "RAW_CLEANUP_SENTINEL private-runtime-path";
  const failed = adaptGatewayFailure(
    rawBackendText,
    "runtime_cleanup_identity_unavailable",
    "cleanup_pending",
  ).runs[0]?.engineRuns[0];

  assert.equal(failed?.checkpoint?.stage, "cleanup_pending");
  assert.equal(failed?.errorCode, "runtime_cleanup_identity_unavailable");
  assert.equal(failed?.recoveryAction, "none");
  assert.equal(failed?.resumable, false);
  assert.equal(failed?.checkpoint?.lastError, undefined);
  assert.deepEqual(failed?.warnings, []);
  assert.equal(
    failed?.message,
    "這項檢查已安全結束，較舊的資料與結果都已保留。需要新結果時請開始新的掃描；不需要做其他處理。",
  );
  assert.doesNotMatch(failed?.message ?? "", /runtime|identity|cleanup|執行環境|識別|清理/iu);
  assert.doesNotMatch(JSON.stringify(failed), /RAW_CLEANUP_SENTINEL|private-runtime-path/u);
});

test("preserved-cleanup phases override a legacy error code without leaking or offering restart", () => {
  for (const phase of [
    "cleanup_identity_unavailable",
    "interrupted_restart_cleanup_identity_unavailable",
  ]) {
    const rawBackendText = `egress gateway exited before becoming ready RAW_PHASE_SENTINEL ${phase}`;
    const failed = adaptGatewayFailure(
      rawBackendText,
      "execution_failed",
      "cleanup_pending",
      phase,
      [rawBackendText],
      rawBackendText,
    ).runs[0]?.engineRuns[0];

    assert.equal(failed?.phase, phase);
    assert.equal(failed?.errorCode, "runtime_cleanup_identity_unavailable");
    assert.equal(failed?.failureKind, undefined);
    assert.equal(failed?.recoveryAction, "none");
    assert.equal(failed?.resumable, false);
    assert.equal(failed?.checkpoint?.lastError, undefined);
    assert.equal(failed?.cleanupDetail, undefined);
    assert.deepEqual(failed?.warnings, []);
    assert.equal(
      failed?.message,
      "這項檢查已安全結束，較舊的資料與結果都已保留。需要新結果時請開始新的掃描；不需要做其他處理。",
    );
    assert.doesNotMatch(failed?.message ?? "", /runtime|identity|cleanup|執行環境|識別|清理/iu);
    assert.doesNotMatch(JSON.stringify(failed), /RAW_PHASE_SENTINEL|egress gateway exited/u);
  }
});

test("every product-owned gateway preparation marker maps to one redacted failure category", () => {
  const markers = [
    "pinned egress gateway image pull",
    "managed gateway uplink creation",
    "egress gateway container creation",
    "egress gateway container start",
    "egress gateway container exited",
    "egress gateway container did not report",
    "egress gateway container reported",
    "egress gateway internal-network attachment",
  ];

  for (const marker of markers) {
    const secret = `private-target-${marker.replaceAll(" ", "-")}`;
    const failed = adaptGatewayFailure(`runtime error: ${marker}: ${secret}`)
      .runs[0]?.engineRuns[0];
    assert.equal(failed?.failureKind, "gateway_preparation_failed", marker);
    assert.equal(failed?.recoveryAction, "restart_check", marker);
    assert.doesNotMatch(JSON.stringify(failed), new RegExp(secret, "u"), marker);
  }
});
