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
  assert.match(source, /OCSF findings plus a required coverage manifest/u);
  assert.match(source, /OCSF 問題資料，並附上必要的涵蓋說明檔/u);
  assert.match(source, /OSCAL observations plus a required coverage manifest/u);
  assert.match(source, /OSCAL 觀察資料，並附上必要的涵蓋說明檔/u);
});

test("the export page defaults to a readable report without raw source files", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /useState<ExportFormat>\("html"\)/u);
  assert.match(source, /useState\(false\)/u);
  assert.match(source, /const primaryFormats = \["html", "json"\]/u);
  assert.match(source, /const advancedFormats = \[\s*"case_bundle",\s*"framework_report",\s*"ocsf",\s*"oscal",/u);
  assert.match(source, /Readable report \(recommended\)/u);
  assert.match(source, /好讀的報告（建議）/u);
  assert.match(source, /Master-report JSON/u);
  assert.match(source, /主要報告 JSON/u);
  assert.match(source, /Advanced and technical formats/u);
  assert.match(source, /進階與技術格式/u);
});
