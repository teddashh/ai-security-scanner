import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  normalizeDemoExportInput,
  projectDemoSelectedRun,
} from "../../src/demoExportProjection.ts";
import type {
  Asset,
  CaseWorkspace,
  CoverageRecord,
  Finding,
  ScanRun,
  VerificationSummary,
} from "../../src/types.ts";

const run = (id: string, engineRunId: string, assetId: string): ScanRun => ({
  id,
  caseId: "case-1",
  label: id,
  status: "completed",
  progress: 100,
  startedAt: "2026-08-31T12:00:00Z",
  finishedAt: "2026-08-31T12:01:00Z",
  knowledgeDate: "2026-08-31",
  engineRuns: [{
    id: engineRunId,
    engineId: `engine-${id}`,
    engineName: `Engine ${id}`,
    category: "test",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: [assetId],
    rawArtifactCount: 1,
    findingCount: 1,
    resumable: false,
  }],
  coveredAssetCount: 1,
  totalAssetCount: 1,
});

const asset = (id: string): Asset => ({
  id,
  name: id,
  type: "service",
  platform: "external",
  locator: `${id}.invalid`,
  coverageState: "discovered_authorized_scanned",
  authorizationState: "authorized",
  allowedModes: ["inventory"],
  findingCount: 1,
});

const finding = (
  id: string,
  assetId: string,
  evidence: Finding["evidence"],
): Finding => ({
  id,
  fingerprint: `fingerprint-${id}`,
  assetId,
  assetIds: [assetId, "asset-other"],
  assetName: assetId,
  title: id,
  summary: id,
  impact: id,
  recommendation: id,
  expertType: "test",
  severity: "medium",
  confidence: "high",
  priority: 50,
  workflowState: "confirmed",
  evidence,
  controls: [],
  officialReferences: [],
  firstSeenRunId: "run-other",
  lastSeenRunId: "run-selected",
  firstSeenAt: "2026-08-30T12:00:00Z",
  lastSeenAt: "2026-08-31T12:00:00Z",
});

const coverage: CoverageRecord[] = [{
  id: "coverage-workspace-wide",
  label: "Mutable current coverage",
  platform: "external",
  sourceKind: "user_declared",
  state: "discovered_authorized_scanned",
  assetId: "asset-selected",
  assetCount: 1,
  detail: "This is not a frozen selected-run record.",
}];

const verification: VerificationSummary = {
  baselineRunId: "run-other",
  comparisonRunId: "run-selected",
  baselineAt: "2026-08-30T12:00:00Z",
  comparisonAt: "2026-08-31T12:00:00Z",
  diffs: [{
    id: "diff-cross-run",
    title: "Cross-run comparison",
    assetName: "asset-selected",
    state: "persistent",
    explanation: "This requires two runs.",
    evidenceChanged: false,
  }],
};

const selectedRun = run("run-selected", "engine-run-selected", "asset-selected");
const workspace = {
  assets: [asset("asset-selected"), asset("asset-other")],
  coverage,
  findings: [
    finding("finding-selected", "asset-selected", [
      {
        id: "evidence-selected",
        sourceEngine: "selected",
        observedAt: "2026-08-31T12:00:00Z",
        summary: "selected",
        rawArtifactHash: "sha256:selected",
        runId: "run-selected",
        engineRunId: "engine-run-selected",
      },
      {
        id: "evidence-other-run",
        sourceEngine: "other",
        observedAt: "2026-08-30T12:00:00Z",
        summary: "other",
        rawArtifactHash: "sha256:other",
        runId: "run-other",
        engineRunId: "engine-run-other",
      },
      {
        id: "evidence-wrong-engine",
        sourceEngine: "wrong",
        observedAt: "2026-08-31T12:00:00Z",
        summary: "wrong",
        rawArtifactHash: "sha256:wrong",
        runId: "run-selected",
        engineRunId: "engine-run-other",
      },
    ]),
    finding("finding-other", "asset-other", [{
      id: "evidence-other",
      sourceEngine: "other",
      observedAt: "2026-08-30T12:00:00Z",
      summary: "other",
      rawArtifactHash: "sha256:other",
      runId: "run-other",
      engineRunId: "engine-run-other",
    }]),
  ],
  verification,
} satisfies Pick<CaseWorkspace, "assets" | "coverage" | "findings" | "verification">;

test("browser demo export normalization admits only an honest JSON projection", () => {
  assert.deepEqual(normalizeDemoExportInput({
    caseId: "case-1",
    runId: "run-selected",
    locale: "zh-Hant",
    format: "case_bundle",
    includeRawEvidence: true,
    redactSensitiveValues: true,
  }), {
    caseId: "case-1",
    runId: "run-selected",
    locale: "zh-Hant",
    format: "json",
    includeRawEvidence: false,
    redactSensitiveValues: false,
  });
});

test("demo export projection contains only exact selected-run assets and evidence", () => {
  const projected = projectDemoSelectedRun(workspace, selectedRun);

  assert.equal(projected.scope, "selected_run_only");
  assert.deepEqual(projected.assets.map((item) => item.id), ["asset-selected"]);
  assert.deepEqual(projected.findings.map((item) => item.id), ["finding-selected"]);
  assert.deepEqual(projected.findings[0]?.assetIds, ["asset-selected"]);
  assert.deepEqual(projected.findings[0]?.evidence.map((item) => item.id), ["evidence-selected"]);
  assert.equal("workflowState" in projected.findings[0]!, false);
  assert.equal("firstSeenRunId" in projected.findings[0]!, false);
  assert.equal("lastSeenRunId" in projected.findings[0]!, false);
});

test("mutable coverage and cross-run verification fail closed instead of leaking workspace state", () => {
  const projected = projectDemoSelectedRun(workspace, selectedRun);

  assert.deepEqual(projected.coverage, []);
  assert.equal(projected.verification, null);
  assert.deepEqual(projected.omissions, {
    coverage: "omitted_not_run_bound",
    verification: "omitted_cross_run_comparison",
  });
  assert.doesNotMatch(JSON.stringify(projected), /coverage-workspace-wide|diff-cross-run/u);
});

test("a matching run id without a matching selected engine run still fails closed", () => {
  const projected = projectDemoSelectedRun({
    ...workspace,
    findings: [finding("wrong-engine-only", "asset-selected", [{
      id: "evidence-wrong-engine-only",
      sourceEngine: "wrong",
      observedAt: "2026-08-31T12:00:00Z",
      summary: "wrong",
      rawArtifactHash: "sha256:wrong",
      runId: "run-selected",
      engineRunId: "engine-run-other",
    }])],
  }, selectedRun);

  assert.deepEqual(projected.findings, []);
});

test("the demo download and preview are wired to the same selected-run projection", () => {
  const scanner = readFileSync(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");
  const previewStart = scanner.indexOf("async previewExport");
  const previewEnd = scanner.indexOf("async exportCase", previewStart);
  const downloadStart = scanner.indexOf("const downloadDemoExport");
  const downloadEnd = scanner.indexOf("const blob =", downloadStart);
  const preview = scanner.slice(previewStart, previewEnd);
  const download = scanner.slice(downloadStart, downloadEnd);

  assert.match(preview, /const projection = projectDemoSelectedRun\(workspace, run\)/u);
  assert.match(download, /const projection = projectDemoSelectedRun\(workspace, run\)/u);
  assert.match(download, /\.\.\.projection/u);
  assert.doesNotMatch(
    download,
    /coverage: workspace\.coverage|assets: workspace\.assets|findings: workspace\.findings|verification: workspace\.verification/u,
  );
  assert.doesNotMatch(download, /requestedFormat/u);
});
