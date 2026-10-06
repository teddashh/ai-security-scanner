import assert from "node:assert/strict";
import test from "node:test";

import { isSecurityFinding } from "../../src/findingClassification.ts";
import { latestProblemCount } from "../../src/latestProblemCount.ts";
import { projectProblemRows } from "../../src/reportProblemPresentation.ts";
import type {
  BeginnerReportFinding,
  BeginnerReportProblemGroup,
  Finding,
  ScanRun,
} from "../../src/types.ts";

const run = (
  id: string,
  status: ScanRun["status"],
  startedAt: string,
  sequence: number,
): ScanRun => ({
  id,
  caseId: "case-1",
  label: "stored label",
  sequence,
  status,
  progress: status === "running" ? 40 : 100,
  startedAt,
  knowledgeDate: "2026-10-01",
  engineRuns: [],
  coveredAssetCount: 1,
  totalAssetCount: 1,
});

const reportFinding = (
  id: string,
  extras: Partial<BeginnerReportFinding> = {},
): BeginnerReportFinding => ({
  findingId: id,
  targetAssetIds: ["asset-1"],
  severity: "high",
  priority: 10,
  ...extras,
} as BeginnerReportFinding);

const saved = (severityBasisCode?: Finding["severityBasisCode"]): Pick<Finding, "severityBasisCode"> =>
  ({ severityBasisCode });

const group = (ids: string[]): BeginnerReportProblemGroup => ({
  groupId: "group",
  ruleVersion: "aws-related-checks-1",
  kind: "iam_password_policy",
  title: "IAM password policy needs attention",
  targetAssetId: "asset-1",
  representativeFindingId: ids[0] ?? "",
  findingIds: ids,
});

test("the latest finished run supplies the count", () => {
  const newer = run("run-2", "completed", "2026-10-06T02:00:00Z", 2);
  const older = run("run-1", "completed", "2026-10-01T00:00:00Z", 1);
  const result = latestProblemCount({
    runs: [newer, older],
    beginnerReports: [
      { runId: older.id, findings: [reportFinding("old-1"), reportFinding("old-2"), reportFinding("old-3")] },
      { runId: newer.id, findings: [reportFinding("new-1")] },
    ],
    findings: [saved(), saved(), saved(), saved()],
    isDemo: false,
  });
  assert.equal(result.count, 1);
  assert.equal(result.run?.id, newer.id);
  assert.equal(result.run?.status, "completed");
});

test("an active newer run is ignored", () => {
  const active = run("run-2", "running", "2026-10-06T03:00:00Z", 2);
  const finished = run("run-1", "completed", "2026-10-01T00:00:00Z", 1);
  const result = latestProblemCount({
    runs: [active, finished],
    beginnerReports: [
      { runId: active.id, findings: [reportFinding("live")] },
      { runId: finished.id, findings: [reportFinding("saved-1"), reportFinding("saved-2")] },
    ],
    findings: [saved(), saved(), saved()],
    isDemo: false,
  });
  assert.equal(result.run?.id, finished.id);
  assert.equal(result.count, 2);
});

test("a partial run is counted and keeps its status", () => {
  const partial = run("run-2", "partial", "2026-10-06T02:00:00Z", 2);
  const completed = run("run-1", "completed", "2026-10-01T00:00:00Z", 1);
  const result = latestProblemCount({
    runs: [partial, completed],
    beginnerReports: [
      { runId: completed.id, findings: [reportFinding("done")] },
      { runId: partial.id, findings: [reportFinding("part-1"), reportFinding("part-2"), reportFinding("part-3")] },
    ],
    findings: [saved()],
    isDemo: false,
  });
  assert.equal(result.run?.id, partial.id);
  assert.equal(result.run?.status, "partial");
  assert.equal(result.count, 3);
});

test("a finished run with no report keeps the saved security-finding total", () => {
  const older = run("run-1", "completed", "2026-10-01T00:00:00Z", 1);
  const newer = run("run-2", "completed", "2026-10-06T02:00:00Z", 2);
  const findings = [saved(), saved(), saved("open_port")];
  const result = latestProblemCount({
    runs: [newer, older],
    beginnerReports: [
      { runId: older.id, findings: [reportFinding("old")] },
    ],
    findings,
    isDemo: false,
  });
  assert.equal(result.run, undefined);
  assert.equal(result.count, findings.filter(isSecurityFinding).length);
  assert.equal(result.count, 2);
});

test("no finished run keeps the saved security-finding total", () => {
  const result = latestProblemCount({
    runs: [run("run-1", "queued", "2026-10-06T02:00:00Z", 1)],
    beginnerReports: [],
    findings: [saved(), saved("reachable_http_service")],
    isDemo: false,
  });
  assert.equal(result.run, undefined);
  assert.equal(result.count, 1);
});

test("a demo case keeps the saved security-finding total", () => {
  const finished = run("run-1", "completed", "2026-10-06T02:00:00Z", 1);
  const result = latestProblemCount({
    runs: [finished],
    beginnerReports: [{ runId: finished.id, findings: [reportFinding("demo")] }],
    findings: [saved(), saved(), saved(), saved()],
    isDemo: true,
  });
  assert.equal(result.run, undefined);
  assert.equal(result.count, 4);
});

test("grouped report findings count as one problem, matching Results", () => {
  const finished = run("run-2", "completed", "2026-10-06T02:00:00Z", 2);
  const findings = [
    reportFinding("low"),
    reportFinding("high"),
    reportFinding("other"),
    reportFinding("port", { severityBasisCode: "open_port" }),
  ];
  const problemGroups = [group(["low", "high"])];
  const securityFindings = findings.filter(isSecurityFinding);
  const rows = projectProblemRows(securityFindings, problemGroups);
  const result = latestProblemCount({
    runs: [finished],
    beginnerReports: [{ runId: finished.id, findings, problemGroups }],
    findings: Array.from({ length: 32 }, () => saved()),
    isDemo: false,
  });
  assert.ok(rows.length < securityFindings.length);
  assert.equal(result.count, rows.length);
  assert.equal(result.count, 2);
  assert.equal(result.run?.id, finished.id);
});
