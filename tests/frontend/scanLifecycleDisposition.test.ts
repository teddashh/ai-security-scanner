import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import { selectNewerWorkspaceByRevision } from "../../src/snapshotWorkspace.ts";
import type { CaseWorkspace, EngineRun, RunStatus, ScanRun } from "../../src/types.ts";

const bundled = await build({
  entryPoints: [fileURLToPath(new URL("../../src/scanLifecycleDisposition.ts", import.meta.url))],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const bundledSource = bundled.outputFiles[0]?.text;
assert.ok(bundledSource, "scan lifecycle disposition bundle should contain JavaScript");
const {
  deriveCancelLifecycleDisposition,
  deriveResumeLifecycleDisposition,
  scanLifecycleToastPresentation,
} = await import(`data:text/javascript;base64,${Buffer.from(bundledSource).toString("base64")}`);

const engine = (overrides: Partial<EngineRun> = {}): EngineRun => ({
  id: "engine-run",
  engineId: "built-in-localhost-tcp",
  engineName: "127.0.0.1:9001 TCP",
  category: "built_in_localhost_tcp",
  taskKind: {
    kind: "built_in_localhost_tcp",
    port: 9001,
    timeoutMs: 3_000,
    payloadBytes: 0,
  },
  warnings: [],
  status: "running",
  progress: 20,
  phase: "connecting",
  assetIds: ["localhost-asset"],
  rawArtifactCount: 0,
  findingCount: 0,
  resumable: false,
  ...overrides,
});

const run = (
  status: RunStatus,
  engineRuns: EngineRun[] = [engine()],
): ScanRun => ({
  id: "run-1",
  caseId: "case-1",
  label: "Scan 1",
  status,
  progress: 20,
  startedAt: "2026-08-30T12:00:00Z",
  knowledgeDate: "2026-08-30",
  engineRuns,
  coveredAssetCount: 0,
  totalAssetCount: 1,
});

const workspace = (
  scanRun: ScanRun,
  updatedAt = "2026-08-30T12:00:00.000000001Z",
): CaseWorkspace => ({
  case: { id: "case-1", updatedAt } as CaseWorkspace["case"],
  runs: [scanRun],
} as CaseWorkspace);

test("cancel disposition distinguishes durable request, cancellation, result, and uncertainty", () => {
  for (const status of ["queued", "running"] as const) {
    const requested = deriveCancelLifecycleDisposition(workspace(run(status, [engine({
      status: status === "queued" ? "pending" : "running",
      phase: "cancel_requested",
    })])), "run-1");
    assert.equal(requested.action, "cancel");
    assert.equal(requested.outcome, "requested");
    assert.equal(requested.outcome === "requested" ? requested.targetContactLimitMs : undefined, 3_000);
  }

  assert.deepEqual(
    deriveCancelLifecycleDisposition(workspace(run("cancelled", [engine({
      status: "cancelled",
      phase: "cancelled",
    })])), "run-1"),
    { action: "cancel", outcome: "cancelled", runId: "run-1" },
  );
  assert.equal(
    deriveCancelLifecycleDisposition(workspace(run("queued", [engine({
      status: "cancelled",
      phase: "cancelled",
    })])), "run-1").outcome,
    "cancelled",
    "an already-terminal engine wins over a stale active aggregate",
  );

  for (const [runStatus, engineStatus, expected] of [
    ["completed", "completed", "completed"],
    ["partial", "partial", "partial"],
    ["failed", "failed", "failed"],
    ["queued", "not_executed", "not_executed"],
  ] as const) {
    const disposition = deriveCancelLifecycleDisposition(workspace(run(runStatus, [engine({
      status: engineStatus,
      phase: engineStatus,
    })])), "run-1");
    assert.equal(disposition.outcome, "result_already_final");
    assert.equal(disposition.outcome === "result_already_final" ? disposition.resultStatus : undefined, expected);
  }

  assert.equal(
    deriveCancelLifecycleDisposition(workspace(run("running")), "run-1").outcome,
    "unconfirmed",
  );
  assert.equal(deriveCancelLifecycleDisposition(workspace(run("running")), "missing").outcome, "unconfirmed");
});

test("a cancelled localhost record with a contradictory observation remains unconfirmed", () => {
  const disposition = deriveCancelLifecycleDisposition(workspace(run("cancelled", [engine({
    status: "cancelled",
    phase: "cancelled",
    localhostTcpObservation: {
      outcome: "reachable",
      observedAt: "2026-08-30T12:00:01Z",
    },
  })])), "run-1");

  assert.deepEqual(disposition, {
    action: "cancel",
    outcome: "unconfirmed",
    runId: "run-1",
  });
  assert.match(scanLifecycleToastPresentation(disposition).detail.en, /refreshing now/u);
});

test("cancelled is never promoted to a result, while mixed saved work remains partial", () => {
  const genericCancelled = run("cancelled", [engine({
    engineId: "generic-engine",
    taskKind: { kind: "catalog_engine" },
    status: "cancelled",
    phase: "cancelled",
    rawArtifactCount: 2,
    findingCount: 1,
  })]);
  const cancelled = deriveCancelLifecycleDisposition(workspace(genericCancelled), "run-1");
  assert.equal(cancelled.outcome, "cancelled");
  assert.match(scanLifecycleToastPresentation(cancelled).detail.en, /results saved before it stopped remain available/u);

  const mixed = deriveCancelLifecycleDisposition(workspace(run("cancelled", [
    engine({ id: "completed", status: "completed", phase: "completed" }),
    engine({
      id: "cancelled",
      engineId: "generic-engine",
      taskKind: { kind: "catalog_engine" },
      status: "cancelled",
      phase: "cancelled",
    }),
  ])), "run-1");
  assert.equal(mixed.outcome, "result_already_final");
  assert.equal(mixed.outcome === "result_already_final" ? mixed.resultStatus : undefined, "partial");
});

test("result-won dispositions preserve reachable, closed, timed-out, and failed truth", () => {
  for (const [outcome, runStatus, engineStatus, expectedCopy] of [
    ["reachable", "completed", "completed", /connection was accepted/u],
    ["closed", "completed", "completed", /connection was refused/u],
    ["timed_out", "partial", "partial", /attempt timed out/u],
  ] as const) {
    const disposition = deriveCancelLifecycleDisposition(workspace(run(runStatus, [engine({
      status: engineStatus,
      phase: engineStatus,
      localhostTcpObservation: {
        outcome,
        observedAt: "2026-08-30T12:00:01Z",
      },
    })])), "run-1");
    assert.equal(disposition.outcome, "result_already_final");
    const presentation = scanLifecycleToastPresentation(disposition);
    assert.match(presentation.detail.en, expectedCopy);
    assert.match(presentation.detail.en, /saved result was kept/u);
  }

  const failed = deriveCancelLifecycleDisposition(workspace(run("failed", [engine({
    status: "failed",
    phase: "failed",
  })])), "run-1");
  assert.equal(failed.outcome, "result_already_final");
  assert.match(scanLifecycleToastPresentation(failed).detail.en, /saved failure/u);
});

test("resume disposition never calls a retained terminal result queued", () => {
  assert.equal(deriveResumeLifecycleDisposition(workspace(run("queued")), "run-1").outcome, "queued");
  assert.equal(deriveResumeLifecycleDisposition(workspace(run("running")), "run-1").outcome, "queued");
  assert.equal(deriveResumeLifecycleDisposition(workspace(run("paused", [engine({ status: "paused" })])), "run-1").outcome, "unconfirmed");

  for (const status of ["completed", "partial", "failed"] as const) {
    const disposition = deriveResumeLifecycleDisposition(workspace(run(status, [engine({ status })])), "run-1");
    assert.equal(disposition.outcome, "result_already_final");
    const presentation = scanLifecycleToastPresentation(disposition);
    assert.match(presentation.title.en, /already finished/u);
    assert.doesNotMatch(`${presentation.title.en} ${presentation.detail.en}`, /queued to continue|work started/iu);
  }

  assert.equal(
    deriveResumeLifecycleDisposition(workspace(run("cancelled", [engine({ status: "cancelled" })])), "run-1").outcome,
    "unconfirmed",
    "cancelled is a lifecycle outcome, not a saved result status",
  );
  assert.equal(
    deriveResumeLifecycleDisposition(workspace(run("running", [engine({ status: "cancelled" })])), "run-1").outcome,
    "unconfirmed",
    "a stale active aggregate cannot restart already-cancelled engine work",
  );
});

test("a newer terminal event wins over an older requested command response", () => {
  const staleResponse = workspace(run("running", [engine({ phase: "cancel_requested" })]));
  const terminalEvent = workspace(
    run("completed", [engine({ status: "completed", phase: "completed" })]),
    "2026-08-30T12:00:00.000000002Z",
  );
  const selected = selectNewerWorkspaceByRevision(staleResponse, terminalEvent);
  const disposition = deriveCancelLifecycleDisposition(selected, "run-1");
  const presentation = scanLifecycleToastPresentation(disposition);

  assert.equal(selected, terminalEvent);
  assert.equal(disposition.outcome, "result_already_final");
  assert.match(presentation.detail.en, /completed with a saved result/u);
  assert.doesNotMatch(`${presentation.title.en} ${presentation.detail.en}`, /stop request (?:was|is) saved/iu);
});

test("lifecycle toast copy is bilingual, bounded, and honest for every disposition", () => {
  const dispositions = [
    deriveCancelLifecycleDisposition(workspace(run("running", [engine({ phase: "cancel_requested" })])), "run-1"),
    deriveCancelLifecycleDisposition(workspace(run("cancelled", [engine({ status: "cancelled" })])), "run-1"),
    deriveCancelLifecycleDisposition(workspace(run("completed", [engine({ status: "completed" })])), "run-1"),
    deriveCancelLifecycleDisposition(workspace(run("running")), "run-1"),
    deriveResumeLifecycleDisposition(workspace(run("running")), "run-1"),
    deriveResumeLifecycleDisposition(workspace(run("failed", [engine({ status: "failed" })])), "run-1"),
    deriveResumeLifecycleDisposition(workspace(run("paused", [engine({ status: "paused" })])), "run-1"),
  ];

  for (const disposition of dispositions) {
    const presentation = scanLifecycleToastPresentation(disposition);
    assert.ok(presentation.title.en && presentation.title.zhTW);
    assert.ok(presentation.detail.en && presentation.detail.zhTW);
  }

  const requested = scanLifecycleToastPresentation(dispositions[0]!);
  assert.equal(
    requested.detail.en,
    "Stopping this check. If a connection attempt already started, it will end within its 3-second limit.",
  );
  const unconfirmed = scanLifecycleToastPresentation(dispositions[3]!);
  assert.equal(unconfirmed.tone, "warning");
  assert.match(unconfirmed.detail.en, /refreshing now/u);
});
