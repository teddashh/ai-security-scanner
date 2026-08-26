import assert from "node:assert/strict";
import test from "node:test";

import { buildScanActivity } from "../../src/scanActivity.ts";
import type { EngineRun, ExecutionStage, ScanRun } from "../../src/types.ts";

const engine = (overrides: Partial<EngineRun> = {}): EngineRun => ({
  id: "engine-run-1",
  engineId: "scanner-id-must-stay-technical",
  engineName: "Scanner name must stay technical",
  category: "network",
  version: "1.0.0",
  digest: "sha256:redacted",
  warnings: ["target-controlled warning"],
  status: "running",
  progress: 40,
  phase: "running",
  startedAt: "2026-08-26T13:01:00Z",
  assetIds: ["private-target-id"],
  rawArtifactCount: 0,
  findingCount: 0,
  message: "raw scanner output",
  resumable: false,
  checkpoint: {
    attempt: 1,
    stage: "running",
    artifactCount: 0,
    cleanupCompleted: false,
    scopeBound: true,
  },
  ...overrides,
});

const run = (overrides: Partial<ScanRun> = {}): ScanRun => ({
  id: "run-1",
  caseId: "case-1",
  label: "Scan 1",
  status: "running",
  progress: 40,
  startedAt: "2026-08-26T13:00:00Z",
  lastProgressAt: "2026-08-26T13:02:00Z",
  knowledgeDate: "2026-08-26T12:00:00Z",
  engineRuns: [engine()],
  coveredAssetCount: 0,
  totalAssetCount: 1,
  ...overrides,
});

test("active scan activity explains the wait and reports the last durable progress", () => {
  const activity = buildScanActivity(run(), new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "scanner_working");
  assert.deepEqual(activity.activeCheckNames, ["Scanner name must stay technical"]);
  assert.equal(activity.lastProgressAt, "2026-08-26T13:02:00Z");
  assert.equal(activity.stale, true);
  assert.equal(activity.staleMinutes, 3);
  assert.deepEqual(activity.events.map((event) => event.code), [
    "progress_saved",
    "checks_started",
    "run_started",
  ]);
});

test("every durable execution phase has a plain activity state", () => {
  const expected = {
    planned: "checking_readiness",
    preflight: "checking_readiness",
    pulling_image: "preparing_scanner",
    running: "scanner_working",
    capturing_artifacts: "preparing_results",
    adapting_artifacts: "preparing_results",
    captured_awaiting_adapter: "preparing_results",
    cleanup_pending: "closing_scanner",
  } as const;

  for (const [stage, state] of Object.entries(expected)) {
    const activity = buildScanActivity(run({
      engineRuns: [engine({ checkpoint: {
        attempt: 1,
        stage: stage as ExecutionStage,
        artifactCount: 0,
        cleanupCompleted: false,
        scopeBound: true,
      } })],
    }));
    assert.equal(activity.state, state, stage);
  }
});

test("paused and terminal runs show their own state and terminal timestamp", () => {
  const paused = buildScanActivity(
    run({ status: "paused", engineRuns: [engine({ status: "paused" })] }),
    new Date("2026-08-26T14:30:00Z"),
  );
  assert.equal(paused.state, "paused");
  assert.equal(paused.active, false);
  assert.equal(paused.stale, false, "an intentional pause is never reported as a delayed live scan");
  const completed = buildScanActivity(run({
    status: "completed",
    progress: 100,
    finishedAt: "2026-08-26T13:06:00Z",
    engineRuns: [engine({ status: "completed", progress: 100, finishedAt: "2026-08-26T13:06:00Z" })],
  }));
  assert.equal(completed.state, "completed");
  assert.equal(completed.lastProgressAt, "2026-08-26T13:06:00Z");
  assert.ok(completed.events.some((event) => event.code === "run_finished"));
});

test("first-layer activity identifies the active check but never carries scanner output or target ids", () => {
  const serialized = JSON.stringify(buildScanActivity(run()));
  assert.match(serialized, /Scanner name must stay technical/u);
  assert.doesNotMatch(serialized, /raw scanner output/u);
  assert.doesNotMatch(serialized, /private-target-id/u);
  assert.doesNotMatch(serialized, /target-controlled warning/u);
});
