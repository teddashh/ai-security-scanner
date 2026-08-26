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
    contents: 'export { adaptDeclaredWebServiceMetadata, adaptLocalNetworkCandidateInventory, adaptManagedRuntimePrerequisiteRepairResult, adaptManagedRuntimeSetupStatus, adaptNativeCase } from "./src/services/nativeAdapter.ts";',
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

test("native case summaries, workspaces, and case creation preserve assessment intent", () => {
  assert.ok(adapterSource.includes("assessment_intent?: string | null"));
  assert.equal((adapterSource.match(/assessmentIntent: mapAssessmentIntent/g) ?? []).length, 2);
  assert.ok(scannerSource.includes("assessment_intent: input.assessmentIntent ?? null"));
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

test("native gateway failures preserve frozen authorization but restart before runtime scope", () => {
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
    last_error: "runtime error: egress gateway exited before becoming ready",
  });
  const workspace = adaptNativeCase({
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
        error_code: "execution_failed",
        error_message: "runtime error: egress gateway exited before becoming ready",
      }],
    }],
    findings: [],
    exports: [],
    comparisons: [],
  });

  const failed = workspace.runs[0]?.engineRuns[0];
  assert.equal(failed?.scopeContractBound, true);
  assert.equal(failed?.checkpoint?.scopeBound, false);
  assert.equal(failed?.failureKind, "gateway_preparation_failed");
  assert.equal(failed?.recoveryAction, "restart_check");
  assert.equal(failed?.resumable, true);
});
