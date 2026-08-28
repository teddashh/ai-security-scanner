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
    contents: 'export { adaptDeclaredWebServiceMetadata, adaptLocalNetworkCandidateInventory, adaptManagedRuntimePrerequisiteRepairResult, adaptManagedRuntimeSetupStatus, adaptNativeCase, adaptNativeSnapshot } from "./src/services/nativeAdapter.ts";',
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
  adaptDeclaredWebServiceMetadata,
  adaptLocalNetworkCandidateInventory,
  adaptManagedRuntimePrerequisiteRepairResult,
  adaptManagedRuntimeSetupStatus,
  adaptNativeCase,
  adaptNativeSnapshot,
} = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
);

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

test("managed runtime setup adapter preserves the typed manual WSL distribution recovery", () => {
  const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    failure_reason: "windows_wsl_distribution_requires_manual_action",
    next_action: "resolve_wsl_distribution_manually",
    detail: "Windows still reports WSL distribution podman-assm1-win-x64-0123456789ab",
  }));

  assert.equal(
    adapted.failureReason,
    "windows_wsl_distribution_requires_manual_action",
  );
  assert.equal(adapted.nextAction, "resolve_wsl_distribution_manually");
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

  const mismatchedManualRecovery = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    failure_reason: "windows_wsl_distribution_requires_manual_action",
    next_action: "retry_wsl_check",
  }));
  assert.equal(mismatchedManualRecovery.failureReason, undefined);
  assert.equal(mismatchedManualRecovery.nextAction, undefined);
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

test("case summaries display only applicable source platforms and preserve real multi-platform scope", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture()]), []);

  assert.deepEqual(snapshot.cases[0]?.platforms, ["code", "container", "kubernetes"]);
  assert.equal(snapshot.cases[0]?.aiGeneratedArtifact, "yes");
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

test("full cases combine asset and applicable source platforms without questionnaire placeholders", () => {
  const workspace = adaptNativeCase(platformCaseFixture());

  assert.deepEqual(workspace.case.platforms, ["code", "azure", "kubernetes"]);
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

const adaptGatewayFailure = (
  message: string,
  errorCode = "execution_failed",
) => {
  const checkpoint = JSON.stringify({
    case_id: "case-1",
    scan_run_id: "run-1",
    engine_run_id: "engine-run-1",
    engine_id: "naabu",
    attempt: 1,
    stage: "failed",
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
        status: "failed",
        progress_percent: 0,
        phase: "failed",
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
        warnings: errorCode === "resume_release_incompatible" ? [message] : [],
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
  assert.equal(failed?.scopeContractBound, true);
  assert.equal(failed?.checkpoint?.scopeBound, false);
  assert.equal(failed?.failureKind, "gateway_preparation_failed");
  assert.equal(failed?.recoveryAction, "restart_check");
  assert.equal(failed?.resumable, true);
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
