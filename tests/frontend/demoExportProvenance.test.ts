import assert from "node:assert/strict";
import test from "node:test";

import {
  DEMO_EXPORT_PROVENANCE,
  buildDemoExportPayload,
} from "../../src/demoExportProjection.ts";
import type { CaseWorkspace, ExportCaseInput, Finding, ScanRun } from "../../src/types.ts";

// A demo download carries real-looking finding titles, severities, asset names
// and a scan run. Nothing in its body distinguishes it from an assessment, so
// one string is what stops a sample file being handed on as a security report.
// That string had no test at all: it appeared only in src/, and any refactor of
// the download path could have dropped it with everything still green.

const run: ScanRun = {
  id: "run-1",
  caseId: "case-1",
  label: "Scan 1",
  status: "completed",
  progress: 100,
  startedAt: "2026-09-04T12:00:00Z",
  finishedAt: "2026-09-04T12:05:00Z",
  knowledgeDate: "2026-09-04",
  engineRuns: [{
    id: "engine-run-1",
    engineId: "demo-engine",
    engineName: "Demo engine",
    category: "cloud",
    taskKind: "engine_container",
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: ["asset-1"],
    rawArtifactCount: 1,
    findingCount: 1,
    resumable: false,
  }],
  coveredAssetCount: 1,
  totalAssetCount: 1,
};

const finding: Finding = {
  id: "finding-1",
  fingerprint: "fingerprint-1",
  assetId: "asset-1",
  assetName: "acme.example",
  title: "Public bucket is world readable",
  summary: "Summary.",
  impact: "Impact.",
  recommendation: "Recommendation.",
  expertType: "cloud",
  severity: "critical",
  confidence: "firm",
  priority: 95,
  workflowState: "unreviewed",
  evidence: [{
    id: "evidence-1",
    runId: "run-1",
    engineRunId: "engine-run-1",
    kind: "configuration",
    summary: "Evidence summary.",
    collectedAt: "2026-09-04T12:01:00Z",
  }],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-04T12:01:00Z",
  lastSeenAt: "2026-09-04T12:01:00Z",
};

const workspace = {
  case: {
    id: "case-1",
    name: "Demo project",
    aiGeneratedArtifact: "no",
    organizationName: "Acme",
    companySize: "small",
    dataClasses: [],
    requestedActivities: [],
    platforms: [],
    createdAt: "2026-09-04T11:00:00Z",
    updatedAt: "2026-09-04T12:05:00Z",
    phase: "reporting",
    isDemo: true,
  },
  assets: [{
    id: "asset-1",
    name: "acme.example",
    type: "domain",
    platform: "external",
    locator: "https://acme.example/",
    coverageState: "discovered_authorized_scanned",
    authorizationState: "authorized",
    allowedModes: ["public_data"],
    findingCount: 1,
    scanAttempted: true,
  }],
  coverage: [],
  findings: [finding],
  verification: undefined,
} as unknown as Pick<CaseWorkspace, "assets" | "coverage" | "findings" | "verification" | "case">;

const input: ExportCaseInput = {
  caseId: "case-1",
  runId: "run-1",
  locale: "en",
  format: "json",
  includeRawEvidence: false,
  redactSensitiveValues: false,
};

const NOTICE = "This is built-in demo data.";

test("a demo download is stamped as not being a scan", () => {
  const payload = buildDemoExportPayload(workspace, input, run, NOTICE);
  assert.equal(payload.provenance, DEMO_EXPORT_PROVENANCE);
  assert.equal(DEMO_EXPORT_PROVENANCE, "DEMO_ONLY_NOT_A_SCAN");
  assert.equal(payload.warning, NOTICE);
});

test("the stamp leads the written file rather than trailing its contents", () => {
  // JSON.stringify preserves insertion order for string keys, so this is the
  // difference between a reader seeing the warning immediately and finding it
  // under a run's worth of findings they have already started believing.
  const payload = buildDemoExportPayload(workspace, input, run, NOTICE);
  assert.deepEqual(Object.keys(payload).slice(0, 2), ["provenance", "warning"]);

  const serialized = JSON.stringify(payload, null, 2);
  assert.ok(
    serialized.indexOf("DEMO_ONLY_NOT_A_SCAN") < serialized.indexOf("Public bucket is world readable"),
    "the stamp must appear before any finding",
  );
});

test("the stamp survives everything the projection contributes", () => {
  // The payload spreads the projection over the stamp. Object spread is
  // last-write-wins, so a projection that ever grew a `provenance` or `warning`
  // key would replace the stamp while leaving its position untouched -- the
  // file would still look correctly shaped and would no longer say what it is.
  const payload = buildDemoExportPayload(workspace, input, run, NOTICE);
  assert.equal(payload.provenance, "DEMO_ONLY_NOT_A_SCAN");
  assert.equal(payload.warning, NOTICE);
  assert.notEqual(payload.warning, "");
});

test("the demo file still carries the findings it is a demo of", () => {
  // The stamp is only meaningful on a file that otherwise looks like a report.
  // If this ever renders empty the earlier assertions stop proving anything.
  const payload = buildDemoExportPayload(workspace, input, run, NOTICE);
  assert.equal(payload.findings.length, 1);
  assert.equal(payload.findings[0].title, "Public bucket is world readable");
  assert.equal(payload.scope, "selected_run_only");
  assert.equal(payload.case.isDemo, true);
});

test("the demo file carries only the selected run, not the whole case", () => {
  // The stamp says the file is not a scan; this says the file is not more than
  // the run it claims to be. A demo download that quietly swept in case-wide
  // findings would attribute another run's results to this one.
  const otherRunFinding: Finding = {
    ...finding,
    id: "finding-other-run",
    fingerprint: "fingerprint-other-run",
    title: "Belongs to a different run",
    evidence: [{ ...finding.evidence[0], id: "evidence-other", runId: "run-2" }],
  };
  const unscannedAssetFinding: Finding = {
    ...finding,
    id: "finding-other-asset",
    fingerprint: "fingerprint-other-asset",
    assetId: "asset-never-scanned",
    title: "Belongs to an asset this run never touched",
  };

  // Coverage and verification are populated here on purpose: an empty
  // workspace cannot tell an omission apart from a leak.
  const payload = buildDemoExportPayload(
    {
      ...workspace,
      findings: [finding, otherRunFinding, unscannedAssetFinding],
      coverage: [{
        id: "coverage-1",
        label: "acme.example",
        platform: "external",
        sourceKind: "manual",
        state: "discovered_authorized_scanned",
        assetId: "asset-1",
        assetCount: 1,
        detail: "Case-wide coverage row.",
      }],
      verification: { comparedRunId: "run-2" },
    } as unknown as typeof workspace,
    input,
    run,
    NOTICE,
  );

  assert.deepEqual(payload.findings.map((item) => item.id), ["finding-1"]);
  assert.deepEqual(payload.assets.map((item) => item.id), ["asset-1"]);
  // Coverage is case-wide and mutable, and verification compares runs, so
  // neither can honestly be presented as frozen selected-run data.
  assert.deepEqual(payload.coverage, []);
  assert.equal(payload.verification, null);
  assert.equal(payload.omissions.coverage, "omitted_not_run_bound");
});
