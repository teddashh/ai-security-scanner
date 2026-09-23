import assert from "node:assert/strict";
import test from "node:test";

import { scanRunOverallProgress } from "../../src/scanRunProgress.ts";
import type { EngineRun, EngineRunStatus, ScanRun } from "../../src/types.ts";

const engine = (
  engineId: string,
  status: EngineRunStatus,
  progress: number,
): EngineRun => ({
  id: engineId,
  engineId,
  engineName: engineId,
  category: "code_and_secrets",
  taskKind: { kind: "catalog_engine" },
  warnings: [],
  status,
  progress,
  phase: status,
  assetIds: ["asset-1"],
  rawArtifactCount: 0,
  savedResultArtifactCount: 0,
  findingCount: 0,
  resumable: false,
});

const run = (
  status: ScanRun["status"],
  engineRuns: EngineRun[],
): Pick<ScanRun, "status" | "engineRuns"> => ({ status, engineRuns });

/** Real finished desktop run 754d8c1d: seven checks at 100, trivy partial at 85. */
const finishedPartialEngines = (): EngineRun[] => [
  engine("checkov", "completed", 100),
  engine("gitleaks", "completed", 100),
  engine("grype", "completed", 100),
  engine("kics", "completed", 100),
  engine("semgrep", "completed", 100),
  engine("syft", "completed", 100),
  engine("trivy", "partial", 85),
  engine("trufflehog", "completed", 100),
];

test("a finished scan with seven checks at 100 and one partial check at 85 reports 100, not 98", () => {
  const engineRuns = finishedPartialEngines();
  const measuredMean = Math.round(
    engineRuns.reduce((total, engineRun) => total + engineRun.progress, 0) / engineRuns.length,
  );
  assert.equal(measuredMean, 98);
  assert.equal(scanRunOverallProgress(run("partial", engineRuns)), 100);
});

test("a run with an engine still running reports the measured mean", () => {
  const engineRuns = finishedPartialEngines().map((engineRun) =>
    engineRun.engineId === "trivy" ? engine("trivy", "running", 85) : engineRun
  );
  assert.equal(scanRunOverallProgress(run("running", engineRuns)), 98);
});

test("a finished run with a running, pending, or paused check reports the measured mean, not 100", () => {
  for (const runStatus of ["completed", "partial"] as const) {
    for (const engineStatus of ["running", "pending", "paused"] as const) {
      const engineRuns = finishedPartialEngines().map((engineRun) =>
        engineRun.engineId === "trivy" ? engine("trivy", engineStatus, 85) : engineRun
      );
      assert.equal(
        scanRunOverallProgress(run(runStatus, engineRuns)),
        98,
        `${runStatus} with ${engineStatus}`,
      );
    }
  }
});

test("a cancelled run does not report 100", () => {
  assert.equal(scanRunOverallProgress(run("cancelled", finishedPartialEngines())), 98);
});

test("a finished run with a cancelled check reports the measured mean, not 100", () => {
  const engineRuns = finishedPartialEngines().map((engineRun) =>
    engineRun.engineId === "trivy" ? engine("trivy", "cancelled", 85) : engineRun
  );
  assert.equal(scanRunOverallProgress(run("partial", engineRuns)), 98);
  assert.equal(scanRunOverallProgress(run("completed", engineRuns)), 98);
});

test("a partial run with a not-executed check at 0 reports 100 without rewriting the check", () => {
  const skipped = engine("skipped-check", "not_executed", 0);
  const engineRuns = [
    engine("finished-check", "completed", 100),
    skipped,
  ];
  assert.equal(scanRunOverallProgress(run("partial", engineRuns)), 100);
  assert.equal(skipped.progress, 0);
  assert.equal(engineRuns[1]?.progress, 0);
});
