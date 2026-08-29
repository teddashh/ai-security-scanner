import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  exportFormatIsAvailable,
  resetUnavailableExportFormat,
  runSupportsFindingOnlyExport,
} from "../../src/exportFormatEligibility.ts";
import type { EngineRun, RunStatus, ScanRun } from "../../src/types.ts";

const engine = (status: EngineRun["status"] = "completed"): EngineRun => ({
  id: "engine-run-1",
  engineId: "scanner",
  engineName: "Scanner",
  category: "code",
  version: "1",
  digest: "sha256:test",
  adapterVersion: "1",
  status,
  progress: status === "completed" ? 100 : 50,
  phase: status,
  assetIds: [],
  rawArtifactCount: 0,
  findingCount: 0,
  findingCountKnown: true,
  warnings: [],
  resumable: false,
});

const run = (
  status: RunStatus,
  engineStatus: EngineRun["status"],
  options: { finished?: boolean; engineRuns?: EngineRun[] } = {},
): ScanRun => ({
  id: `run-${status}`,
  caseId: "case-1",
  label: "Scan 1",
  status,
  progress: status === "completed" ? 100 : 50,
  startedAt: "2026-08-27T00:00:00Z",
  finishedAt: options.finished === false ? undefined : "2026-08-27T00:01:00Z",
  knowledgeDate: "2026-08-27T00:00:00Z",
  engineRuns: options.engineRuns ?? [engine(engineStatus)],
  coveredAssetCount: 0,
  totalAssetCount: 0,
});

test("finding-only formats require a durable fully completed run", () => {
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed")), true);
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed", { finished: false })), false);
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed", { engineRuns: [] })), false);
  assert.equal(runSupportsFindingOnlyExport(run("running", "running", { finished: false })), false);
  assert.equal(runSupportsFindingOnlyExport(run("partial", "partial")), false);
  assert.equal(runSupportsFindingOnlyExport(run("failed", "failed")), false);
  assert.equal(runSupportsFindingOnlyExport(undefined), false);
});

test("interim and incomplete runs retain exports that carry the coverage ledger", () => {
  for (const incompleteRun of [
    run("running", "running", { finished: false }),
    run("partial", "partial"),
    run("failed", "failed"),
  ]) {
    for (const format of ["case_bundle", "json", "framework_report", "html"] as const) {
      assert.equal(exportFormatIsAvailable(format, incompleteRun), true);
      assert.equal(resetUnavailableExportFormat(format, incompleteRun), format);
    }
    assert.equal(exportFormatIsAvailable("ocsf", incompleteRun), false);
    assert.equal(exportFormatIsAvailable("oscal", incompleteRun), false);
    assert.equal(resetUnavailableExportFormat("ocsf", incompleteRun), "case_bundle");
    assert.equal(resetUnavailableExportFormat("oscal", incompleteRun), "case_bundle");
  }
});

test("the export page resets blocked formats and skips their preview", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /resetUnavailableExportFormat\(format, latestRun\)/u);
  assert.match(source, /if \(selectedFormatUnavailable\) \{[\s\S]*setPreviewPending\(false\);[\s\S]*return;/u);
  assert.match(source, /disabled=\{unavailableBecauseIncomplete\}/u);
  assert.match(source, /OCSF carries findings but cannot show missing checks/u);
  assert.match(source, /這個 OCSF 檔只包含問題，無法呈現缺少的檢查/u);
  assert.match(source, /This OSCAL findings export cannot show missing checks/u);
  assert.match(source, /這個 OSCAL 問題匯出檔無法呈現缺少的檢查/u);
});
