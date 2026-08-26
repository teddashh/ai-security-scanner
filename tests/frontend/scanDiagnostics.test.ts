import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";
import type { EngineRun, ScanRun } from "../../src/types.ts";

const bundled = await build({
  entryPoints: [new URL("../../src/scanDiagnostics.ts", import.meta.url).pathname],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const bundledSource = bundled.outputFiles[0]?.text;
assert.ok(bundledSource);
const {
  blockedRunSummary,
  buildScanDiagnostic,
  buildReadinessDiagnostic,
  isExplicitPreScannerInfrastructureFailure,
  sharedInfrastructureFailureSummary,
  skippedEngineRunSummary,
} = await import(`data:text/javascript;base64,${Buffer.from(bundledSource).toString("base64")}`);

const engine = (overrides: Partial<EngineRun> = {}): EngineRun => ({
  id: "engine-run-1",
  engineId: "trivy",
  engineName: "Trivy",
  category: "local",
  version: "1.0.0",
  digest: "sha256:redacted",
  warnings: [],
  status: "not_executed",
  progress: 0,
  phase: "not_executed",
  assetIds: [],
  rawArtifactCount: 0,
  findingCount: 0,
  errorCode: "no_compatible_authorized_assets",
  message: "target-controlled detail must not leave the app",
  resumable: false,
  ...overrides,
});

test("preflight diagnostic remains available before any scan run exists", () => {
  const diagnostic = buildReadinessDiagnostic({
    checkFailed: false,
    readiness: {
      caseId: "case-1",
      checkedAt: "2026-08-26T13:20:00Z",
      ready: false,
      state: "scanner_setup_required",
      authorizedTargetCount: 1,
      pendingTargetCount: 0,
      compatibleEngineCount: 1,
      runnableEngineCount: 1,
      blockerCode: "egress_gateway_unavailable",
      nextStep: "scanner_setup",
    },
  }, { productVersion: "0.1.4", runtime: { phase: "failed", available: false } });
  assert.match(diagnostic, /redacted-preflight-diagnostic\/v1/u);
  assert.match(diagnostic, /egress_gateway_unavailable/u);
  assert.match(diagnostic, /2026-08-26T13:20:00Z/u);
  assert.match(diagnostic, /"scan_started": false/u);
  assert.doesNotMatch(diagnostic, /message|target_name|asset_id/u);
});

const run = (engineRuns: EngineRun[]): ScanRun => ({
  id: "run-1",
  caseId: "case-1",
  label: "Scan 1",
  status: "failed",
  progress: 0,
  startedAt: "2026-08-26T03:10:00Z",
  finishedAt: "2026-08-26T03:10:00Z",
  knowledgeDate: "2026-08-26T03:10:00Z",
  engineRuns,
  coveredAssetCount: 0,
  totalAssetCount: 0,
});

test("legacy catalog fanout is one no-target setup block", () => {
  const summary = blockedRunSummary(run([engine(), engine({ id: "engine-run-2", engineId: "trufflehog" })]));
  assert.deepEqual(summary, {
    kind: "no_targets",
    skippedCheckCount: 2,
    reasonCodes: ["no_compatible_authorized_assets"],
  });
});

test("a mixed or actually executed run is never reclassified as a setup block", () => {
  assert.equal(blockedRunSummary(run([engine(), engine({ status: "completed" })])), undefined);
});

test("a legacy zero-engine run is one blocked attempt instead of a failed zero-of-zero scan", () => {
  assert.deepEqual(blockedRunSummary(run([])), {
    kind: "no_runnable_checks",
    skippedCheckCount: 0,
    reasonCodes: [],
  });
});

test("not-executed checks stay in one aggregate even when another check produced a result", () => {
  const summary = skippedEngineRunSummary(run([
    engine({ status: "completed", errorCode: undefined }),
    engine({ id: "engine-run-2" }),
    engine({ id: "engine-run-3", errorCode: "runtime_image_unavailable" }),
  ]));
  assert.deepEqual(summary, {
    checkCount: 2,
    reasonCodes: ["no_compatible_authorized_assets", "runtime_image_unavailable"],
  });
});

test("one shared pre-scanner infrastructure failure is aggregated", () => {
  const commonFailure = (id: string): EngineRun => engine({
    id,
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    message: "same bounded local failure",
    checkpoint: {
      attempt: 1,
      stage: "failed",
      artifactCount: 0,
      cleanupCompleted: true,
      scopeBound: false,
      lastError: "same bounded local failure",
    },
  });
  assert.deepEqual(sharedInfrastructureFailureSummary(run([
    commonFailure("engine-run-1"),
    commonFailure("engine-run-2"),
  ])), {
    checkCount: 2,
    reasonCodes: ["execution_failed"],
  });
});

test("scanner-specific or different failures are never collapsed as one infrastructure problem", () => {
  const first = engine({
    status: "failed",
    errorCode: "execution_failed",
    message: "first",
    checkpoint: { attempt: 1, stage: "failed", artifactCount: 0, cleanupCompleted: true, scopeBound: false, lastError: "first" },
  });
  const second = engine({
    id: "engine-run-2",
    status: "failed",
    errorCode: "execution_failed",
    message: "second",
    checkpoint: { attempt: 1, stage: "failed", artifactCount: 0, cleanupCompleted: true, scopeBound: false, lastError: "second" },
  });
  assert.equal(sharedInfrastructureFailureSummary(run([first, second])), undefined);
  assert.equal(sharedInfrastructureFailureSummary(run([
    first,
    { ...second, message: "first", checkpoint: { ...second.checkpoint!, lastError: "first", scopeBound: true } },
  ])), undefined);
});

test("missing checkpoint, runtime preflight, or an exit code is not pre-start evidence", () => {
  const base = engine({
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    message: "same failure",
    rawArtifactCount: 0,
    findingCount: 0,
  });
  assert.equal(isExplicitPreScannerInfrastructureFailure(base), false);
  assert.equal(sharedInfrastructureFailureSummary(run([
    base,
    { ...base, id: "engine-run-2" },
  ])), undefined);

  const checkpoint = { attempt: 1, stage: "failed" as const, artifactCount: 0, cleanupCompleted: true, scopeBound: false, lastError: "same failure" };
  assert.equal(isExplicitPreScannerInfrastructureFailure({ ...base, checkpoint, runtimeProvider: "managed" }), false);
  assert.equal(isExplicitPreScannerInfrastructureFailure({ ...base, checkpoint, exitCode: 125 }), false);
  assert.equal(isExplicitPreScannerInfrastructureFailure({ ...base, checkpoint }), true);
});

test("shareable diagnostic omits target-controlled messages, warnings, paths, and asset ids", () => {
  const diagnostic = buildScanDiagnostic(run([engine({
    warnings: ["secret warning"],
    assetIds: ["sensitive-asset-id"],
    cleanupDetail: "/private/path",
  })]), { productVersion: "0.1.4" });
  assert.match(diagnostic, /redacted-diagnostic\/v2/);
  assert.match(diagnostic, /no_compatible_authorized_assets/);
  assert.match(diagnostic, /"activity"/);
  assert.match(diagnostic, /"last_progress_at"/);
  assert.doesNotMatch(diagnostic, /target-controlled/);
  assert.doesNotMatch(diagnostic, /secret warning/);
  assert.doesNotMatch(diagnostic, /sensitive-asset-id/);
  assert.doesNotMatch(diagnostic, /private\/path/);
});
