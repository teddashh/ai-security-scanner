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

test("finding-only formats are available for every existing run", () => {
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed")), true);
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed", { finished: false })), true);
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed", { engineRuns: [] })), true);
  assert.equal(runSupportsFindingOnlyExport(run("running", "running", { finished: false })), true);
  assert.equal(runSupportsFindingOnlyExport(run("partial", "partial")), true);
  assert.equal(runSupportsFindingOnlyExport(run("failed", "failed")), true);
  assert.equal(runSupportsFindingOnlyExport(undefined), false);
});

test("interim and incomplete runs retain every export with coverage companions where needed", () => {
  for (const incompleteRun of [
    run("running", "running", { finished: false }),
    run("partial", "partial"),
    run("failed", "failed"),
  ]) {
    for (const format of ["case_bundle", "json", "framework_report", "html", "ocsf", "oscal"] as const) {
      assert.equal(exportFormatIsAvailable(format, incompleteRun), true);
      assert.equal(resetUnavailableExportFormat(format, incompleteRun), format);
    }
  }
});

test("the export page explains mandatory coverage companions", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /resetUnavailableExportFormat\(format, selectedRun\)/u);
  assert.match(source, /if \(selectedFormatUnavailable\) \{[\s\S]*setPreviewPending\(false\);[\s\S]*return;/u);
  assert.match(source, /disabled=\{unavailable\}/u);
  assert.match(source, /const unavailableInDemo = demoMode && id !== "json"/u);
  assert.match(source, /OCSF findings plus a coverage manifest for missing or unfinished checks/u);
  assert.match(source, /OCSF 問題資料，另附涵蓋說明檔記錄未測或未完成項目/u);
  assert.match(source, /OSCAL observations plus a coverage manifest for missing or unfinished checks/u);
  assert.match(source, /OSCAL 觀察資料，另附涵蓋說明檔記錄未測或未完成項目/u);
});

test("the export page defaults to a readable report without raw source files", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /useState<ExportFormat>\("html"\)/u);
  assert.match(source, /useState\(false\)/u);
  assert.match(source, /const primaryFormats = \["html", "json"\]/u);
  assert.match(source, /const advancedFormats = \[\s*"case_bundle",\s*"framework_report",\s*"ocsf",\s*"oscal",/u);
  assert.match(source, /HTML report \(recommended\)/u);
  assert.match(source, /HTML 報告（建議）/u);
  assert.match(source, /JSON report/u);
  assert.match(source, /JSON 報告/u);
  assert.match(source, /More formats/u);
  assert.match(source, /更多格式/u);
});

test("the technical case bundle discloses its case-wide and run-bound scope before export", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /format === "case_bundle" && !demoMode/u);
  assert.match(
    source,
    /<div className="export-bundle-scope">[\s\S]*text\(copy\.caseBundleScopeTitle\)[\s\S]*<details className="page-technical-details">[\s\S]*text\(copy\.caseBundleScopeBody\)/u,
  );
  assert.match(source, /Includes case-wide records; reports use the selected run\./u);
  assert.match(source, /包含案件全域紀錄；報告使用所選輪次。/u);
  assert.match(
    source,
    /case-wide assets, grants, coverage, scan history, findings, workflow history, comparisons/u,
  );
  assert.match(source, /Reports select observations and evidence from the chosen scan run/u);
  assert.match(source, /older observations without a frozen snapshot/u);
  assert.match(source, /workflow status and asset names may also reflect the current case/u);
  assert.match(source, /包內報告會選取所選掃描輪次的觀察與證據/u);
  assert.match(source, /較舊且沒有凍結快照的觀察/u);
  assert.match(source, /工作流程狀態與資產名稱也可能反映目前案件/u);
  assert.doesNotMatch(source, /Reports inside the bundle remain limited to the selected scan run/u);
  assert.doesNotMatch(source, /包內報告仍只涵蓋選定的掃描輪次/u);
  assert.match(source, /Case \/ selected-run findings/u);
  assert.match(source, /All \/ selected-run evidence records/u);
});
