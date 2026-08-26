import assert from "node:assert/strict";
import test from "node:test";

import { blockedRunSummary, buildScanDiagnostic } from "../../src/scanDiagnostics.ts";
import type { EngineRun, ScanRun } from "../../src/types.ts";

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

test("shareable diagnostic omits target-controlled messages, warnings, paths, and asset ids", () => {
  const diagnostic = buildScanDiagnostic(run([engine({
    warnings: ["secret warning"],
    assetIds: ["sensitive-asset-id"],
    cleanupDetail: "/private/path",
  })]), { productVersion: "0.1.4" });
  assert.match(diagnostic, /redacted-diagnostic\/v1/);
  assert.match(diagnostic, /no_compatible_authorized_assets/);
  assert.doesNotMatch(diagnostic, /target-controlled/);
  assert.doesNotMatch(diagnostic, /secret warning/);
  assert.doesNotMatch(diagnostic, /sensitive-asset-id/);
  assert.doesNotMatch(diagnostic, /private\/path/);
});
