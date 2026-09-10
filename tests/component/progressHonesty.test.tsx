import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { ProgressPage } from "../../src/pages/ProgressPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import {
  BUILT_IN_LOCALHOST_QUICK_SCAN_ENGINE_ID,
  LOCALHOST_QUICK_SCAN_TIMEOUT_MS,
} from "../../src/localhostQuickScan";
import type {
  Asset,
  BeginnerMasterReport,
  BeginnerRequestedTarget,
  EngineRun,
  EngineRunStatus,
  Finding,
  ScanRun,
} from "../../src/types";
import type { UseCaseId } from "../../src/useCases";

// The progress view is read while a scan is still the user's live picture of
// what happened. Two of its states are easy to lose on the way to the screen:
// a check that never ran, which is filtered out of the main engine list and
// re-added as one aggregate row, and a check that ran without finishing.
//
// `scanDiagnostics.ts` decides both, and its rules are covered by unit tests.
// What was not covered is whether the page honours them: a filter that drops
// never-run checks and an aggregate row that fails to render would remove them
// from the account entirely, and every count on the page would still add up.

const engine = (
  id: string,
  status: EngineRunStatus,
  overrides: Partial<EngineRun> = {},
): EngineRun => ({
  id,
  engineId: id,
  engineName: id,
  category: "cloud",
  taskKind: "engine_container",
  warnings: [],
  status,
  progress: status === "completed" ? 100 : 40,
  phase: status,
  assetIds: ["asset-1"],
  rawArtifactCount: 0,
  findingCount: 0,
  resumable: false,
  ...overrides,
});

const run = (
  engineRuns: EngineRun[],
  status: ScanRun["status"] = "partial",
  overrides: Partial<ScanRun> = {},
): ScanRun => ({
  id: "run-1",
  caseId: "case-1",
  label: "Scan 1",
  status,
  progress: 100,
  startedAt: "2026-09-04T12:00:00Z",
  finishedAt: "2026-09-04T12:05:00Z",
  knowledgeDate: "2026-09-04",
  engineRuns,
  coveredAssetCount: 1,
  totalAssetCount: 1,
  ...overrides,
});

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "finding-1",
  caseId: "case-1",
  fingerprint: "fingerprint-1",
  assetId: "asset-1",
  assetName: "asset-1",
  title: "Unsafe code execution",
  summary: "A security detector matched unsafe code execution.",
  impact: "Untrusted input could execute code.",
  recommendation: "Review and replace the unsafe call.",
  expertType: "Application security engineer",
  severity: "high",
  confidence: "high",
  priority: 90,
  workflowState: "unreviewed",
  evidence: [{
    id: "evidence-1",
    sourceEngine: "semgrep",
    observedAt: "2026-09-04T12:01:00Z",
    summary: "unsafe call",
    rawArtifactHash: "a".repeat(64),
    runId: "run-1",
  }],
  firstSeenRunId: "run-1",
  lastSeenRunId: "run-1",
  firstSeenAt: "2026-09-04T12:01:00Z",
  lastSeenAt: "2026-09-04T12:01:00Z",
  ...overrides,
});

const asset = (id = "asset-1", name = "selected-project"): Asset => ({
  id,
  name,
  type: "repository",
  platform: "code",
  locator: name,
  coverageState: "authorized_incomplete",
  authorizationState: "authorized",
  allowedModes: ["local_artifact"],
  findingCount: 0,
});

const beginnerReport = (
  overrides: Partial<BeginnerMasterReport> = {},
): BeginnerMasterReport => ({
  schemaVersion: "1.0.0",
  caseId: "case-1",
  runId: "run-1",
  projectTitle: "Selected project",
  state: {
    summary: "partial",
    lifecycle: "live",
    lastDurableUpdate: "2026-09-04T12:02:00Z",
    explanation: "Recorded from durable task state.",
  },
  requested: {
    targets: [{
      assetId: "asset-1",
      label: "selected-project",
      assetKind: "repository",
      labelAvailability: "recorded",
      assetKindAvailability: "recorded",
    }],
    stage: { value: "deep", availability: "recorded", explanation: "Recorded with the run." },
    limits: [],
    requestedCheckIds: [],
    automaticReductions: [],
    reductionsAvailability: "recorded",
    unavailableDimensions: [],
  },
  actual: { checks: [], networkScopes: [], unavailableDimensions: [] },
  coverageGaps: [],
  coverageCounts: {
    testedComplete: 0,
    testedPartial: 0,
    failed: 0,
    timedOut: 0,
    cancelled: 0,
    notTested: 0,
    excluded: 0,
    truncated: 0,
    unavailable: 0,
    unattributed: 0,
    manualReview: 0,
  },
  findings: [],
  nextSteps: [],
  technicalDetails: { collapsedByDefault: true, tasks: [] },
  frameworkNotice: { nonCertification: "Not a certification.", aidefendMappingStatus: "Mapped." },
  dataQualityWarnings: [],
  ...overrides,
});

const reportWithCompletedCheck = (
  resultKind?: "security_check" | "inventory" | "connectivity",
  runId = "run-1",
): BeginnerMasterReport => {
  const base = beginnerReport();
  return beginnerReport({
    runId,
    actual: {
      ...base.actual,
      checks: [{
        taskId: "completed-task",
        checkId: "completed-check",
        ...(resultKind ? { resultKind } : {}),
        targetAssetIds: ["asset-1"],
        status: "tested_complete",
        testedDimensions: [],
      }],
    },
    coverageCounts: { ...base.coverageCounts, testedComplete: 1 },
  });
};

const renderProgress = (
  value: ScanRun,
  findings: Finding[] = [],
  assessmentIntent?: UseCaseId,
  assets: Asset[] = [asset()],
  report?: BeginnerMasterReport,
) =>
  render(
    <I18nProvider>
      <ProgressPage
        caseId="case-1"
        assessmentIntent={assessmentIntent}
        assets={assets}
        report={report}
        runs={[value]}
        findings={findings}
        selectedRunId={value.id}
        onStart={() => Promise.resolve()}
        onRetryLocalhostQuickScan={() => Promise.resolve()}
        onFixSetup={() => {}}
        onPause={() => Promise.resolve()}
        onResume={() => Promise.resolve()}
        onCancel={() => Promise.resolve()}
      />
    </I18nProvider>,
  );

/** The engine row naming `engineName`; id and name both render, so match on text. */
const engineRow = (container: HTMLElement, name: string): HTMLElement => {
  const row = Array.from(container.querySelectorAll<HTMLElement>(".engine-row")).find(
    (candidate) => candidate.textContent?.includes(name),
  );
  if (!row) throw new Error(`no engine row rendered for ${name}`);
  return row;
};

const pillTexts = (container: HTMLElement): string[] =>
  Array.from(container.querySelectorAll<HTMLElement>(".status-pill")).map(
    (pill) => pill.textContent ?? "",
  );

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("a check that never ran is still accounted for on screen", () => {
  // Never-run checks are filtered out of the engine list and re-added as one
  // aggregate row. If that row goes missing they leave the page silently, and
  // a reader is left believing the scan covered only what it happened to try.
  const { container } = renderProgress(
    run([engine("ran", "completed", { progress: 100 }), engine("never-ran", "not_executed")]),
  );

  const attention = container.querySelector<HTMLElement>(".scan-attention-summary");
  expect(attention?.textContent).toContain("Not run");
  expect(attention?.textContent).toContain("1");

  // And it is present as its own row, not only as a number in a tally.
  expect(container.querySelector(".engine-not-executed")).not.toBeNull();
});

test("a Traditional Chinese reader sees a translated technical warning", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const english = "Semgrep output had no results array";
  const { container } = renderProgress(run([engine("semgrep", "partial", { warnings: [english] })]));
  const row = engineRow(container, "semgrep");
  expect(row.textContent).toContain("Semgrep 輸出沒有 results 陣列");
  expect(row.textContent).not.toContain(english);
});

test("a check that ran without finishing does not read as completed", () => {
  const { container } = renderProgress(
    run([engine("finished-check", "completed", { progress: 100 }), engine("unfinished-check", "partial")]),
  );

  const unfinished = engineRow(container, "unfinished-check");
  const finished = engineRow(container, "finished-check");

  const unfinishedPill = unfinished.querySelector<HTMLElement>(".status-pill");
  const finishedPill = finished.querySelector<HTMLElement>(".status-pill");
  expect(unfinishedPill?.textContent).not.toEqual(finishedPill?.textContent);
  expect(unfinishedPill?.className).not.toContain("status-pill--positive");
  expect(finishedPill?.className).toContain("status-pill--positive");
  expect(finished.className).toContain("engine-row--compact");
  expect(finished.querySelector(".engine-row__progress")).toBeNull();
  expect(unfinished.className).not.toContain("engine-row--compact");
  expect(unfinished.querySelector(".engine-row__progress")).not.toBeNull();
});

test("a failed check is not presented in the same tone as a stopped one", () => {
  // "failed" is danger and "cancelled" is neutral: one is the product going
  // wrong, the other is the user's own choice, and merging them would either
  // alarm or reassure wrongly.
  const { container } = renderProgress(
    run([engine("broke-check", "failed"), engine("stopped-check", "cancelled")]),
  );

  const failed = engineRow(container, "broke-check");
  const cancelled = engineRow(container, "stopped-check");

  expect(failed.querySelector(".status-pill")?.className).toContain("status-pill--danger");
  expect(cancelled.querySelector(".status-pill")?.className).not.toContain("status-pill--danger");
});

test("no engine state is rendered without a label", () => {
  // Every EngineRunStatus reaches this page. A state with no presentation would
  // render an empty pill rather than failing, which reads as nothing wrong.
  const states: EngineRunStatus[] = [
    "pending",
    "running",
    "paused",
    "completed",
    "partial",
    "failed",
    "cancelled",
  ];
  const { container } = renderProgress(
    run(states.map((state, index) => engine(`check-${index}`, state))),
  );

  const labels = pillTexts(container).filter((label) => label.trim().length === 0);
  expect(labels).toEqual([]);
});

test("collapsing every check into one shared failure still states how many stopped", () => {
  // When two or more checks all fail identically before binding scope, the page
  // replaces the whole engine list with one aggregate row. That is honest only
  // while the count survives: an empty list reads as nothing to report, and the
  // collapse is precisely the case where the most was lost.
  const preScannerFailure = (id: string): EngineRun => engine(id, "failed", {
    errorCode: "execution_failed",
    rawArtifactCount: 0,
    findingCount: 0,
    message: "The private scan engine did not start.",
    checkpoint: {
      attempt: 1,
      stage: "failed",
      artifactCount: 0,
      cleanupCompleted: true,
      scopeBound: false,
      lastError: "gateway unavailable",
    },
  });

  const { container } = renderProgress(
    run([preScannerFailure("check-a"), preScannerFailure("check-b")], "failed"),
  );

  // No per-engine status row survives the collapse; the two checks appear only
  // inside the collapsed technical record.
  expect(container.querySelectorAll(".engine-row").length).toBe(0);
  expect(container.querySelectorAll(".aggregate-engine-record").length).toBe(2);
  // ...so the count and the reason have to carry it instead.
  expect(container.textContent).toContain("stopped 2 checks");
  expect(container.textContent).toContain("The private scan engine did not start");
  expect(container.textContent).toContain("Technical records — checks: 2");

  const overview = container.querySelector<HTMLElement>(".run-overview");
  const recovery = Array.from(container.querySelectorAll<HTMLElement>(".inline-notice"))
    .find((notice) => notice.textContent?.includes("Try stopped checks again"));
  const activity = container.querySelector<HTMLElement>(".scan-activity");
  expect(overview?.textContent).toContain("Scan 1");
  expect(recovery).not.toBeUndefined();
  expect(overview!.compareDocumentPosition(recovery!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  if (activity) {
    expect(recovery!.compareDocumentPosition(activity) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  }
});

test("an active scan keeps durable security findings in progress until the run finishes", () => {
  const { container } = renderProgress(
    run([engine("semgrep", "running", { findingCount: 2 })], "running"),
    [finding()],
    "source_code",
  );

  expect(container.querySelector('a[href="#findings"]')).toBeNull();
  expect(container.querySelector(".run-overview__timing")?.textContent).toContain(
    "Timing target: a useful result within minutes after tools are ready.",
  );
});

test("Traditional Chinese progress stays focused while a scan is active", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderProgress(
    run([engine("semgrep", "running", { findingCount: 1 })], "running"),
    [finding()],
    "source_code",
  );

  expect(container.querySelector('a[href="#findings"]')).toBeNull();
  expect(container.querySelector(".run-overview__timing")?.textContent).toContain(
    "時間目標：工具就緒後幾分鐘內提供有用結果。",
  );
  expect(container.querySelector(".scan-activity__current")?.textContent).toContain(
    "目前或下一項檢查的資產 · selected-project",
  );
});

test("an active scan with no durable finding does not offer results yet", () => {
  const { container } = renderProgress(
    run([engine("semgrep", "running", { findingCount: 0 })], "running"),
    [],
    "source_code",
  );

  expect(container.querySelector('a[href="#findings"]')).toBeNull();
  expect(container.querySelector(".run-overview__timing")?.textContent).toContain(
    "Timing target: a useful result within minutes after tools are ready.",
  );
});

test("a completed security check does not open a half-finished report while sibling work continues", () => {
  const { container } = renderProgress(
    run([
      engine("semgrep", "completed", { progress: 100, findingCount: 0 }),
      engine("trivy", "running", { findingCount: 0 }),
    ], "running"),
    [],
    "source_code",
    [asset()],
    reportWithCompletedCheck("security_check"),
  );

  expect(container.querySelector('a[href="#findings"]')).toBeNull();
  expect(container.querySelector(".run-overview__timing")?.textContent).toContain(
    "Timing target: a useful result within minutes after tools are ready.",
  );
});

test.each([
  ["inventory", "inventory"],
  ["connectivity", "connectivity"],
  ["legacy untyped", undefined],
] as const)(
  "a completed %s check alone does not unlock security results",
  (_label, resultKind) => {
    const { container } = renderProgress(
      run([
        engine("completed-check", "completed", { progress: 100 }),
        engine("security-check", "running"),
      ], "running"),
      [],
      "source_code",
      [asset()],
      reportWithCompletedCheck(resultKind),
    );

    expect(container.querySelector('a[href="#findings"]')).toBeNull();
    expect(container.querySelector(".run-overview__timing")?.textContent).toContain(
      "Timing target: a useful result within minutes after tools are ready.",
    );
  },
);

test("a completed check from another report cannot unlock the selected active run", () => {
  const { container } = renderProgress(
    run([engine("semgrep", "running")], "running"),
    [],
    "source_code",
    [asset()],
    reportWithCompletedCheck("security_check", "another-run"),
  );

  expect(container.querySelector('a[href="#findings"]')).toBeNull();
});

test("live activity names the saved assets in the current check", () => {
  const requestedTargets: BeginnerRequestedTarget[] = [
    {
      assetId: "asset-1",
      label: "frozen-project",
      assetKind: "repository",
      labelAvailability: "recorded",
      assetKindAvailability: "recorded",
    },
    {
      assetId: "asset-2",
      label: "https://example.invalid",
      assetKind: "service",
      labelAvailability: "recorded",
      assetKindAvailability: "recorded",
    },
  ];
  const baseReport = beginnerReport();
  const { container } = renderProgress(
    run([
      engine("active-check", "running", {
        assetIds: ["asset-1", "asset-2", "missing-private-id"],
      }),
      engine("next-check", "pending", { assetIds: ["asset-3"] }),
    ], "running"),
    [],
    "internal_it_environment",
    [asset("asset-1", "current-project-name"), asset("asset-2", "current-website-name"), asset("asset-3", "later-asset")],
    beginnerReport({ requested: { ...baseReport.requested, targets: requestedTargets } }),
  );

  const current = container.querySelector(".scan-activity__current")?.textContent;
  expect(current).toContain(
    "Assets in current or next check · frozen-project, https://example.invalid",
  );
  expect(current).not.toContain("current-project-name");
  expect(current).not.toContain("later-asset");
  expect(current).not.toContain("missing-private-id");
});

test("live progress separates completed, remaining, and attention-needed work", () => {
  const { container } = renderProgress(
    run([
      engine("completed-check", "completed", { assetIds: ["asset-1"], progress: 100 }),
      engine("active-check", "running", { assetIds: ["asset-2"] }),
      engine("failed-check", "failed", { assetIds: ["asset-3"] }),
    ], "running", { coveredAssetCount: 1, totalAssetCount: 3, progress: 55 }),
    [],
    "internal_it_environment",
    [asset("asset-1", "complete"), asset("asset-2", "active"), asset("asset-3", "attention")],
  );

  const summary = container.querySelector(".run-overview__progress-counts")?.textContent;
  expect(summary).toContain("Assets · Fully checked 1 · Remaining 1 · Need attention 1");
  expect(summary).toContain("Checks · Completed 1 · Remaining 1 · Need attention 1");
});

test("terminal uncovered work needs attention instead of appearing to remain active", () => {
  const { container } = renderProgress(
    run([
      engine("completed-check", "completed", { assetIds: ["asset-1"], progress: 100 }),
      engine("stopped-check", "cancelled", { assetIds: ["asset-2"] }),
    ], "cancelled", { coveredAssetCount: 1, totalAssetCount: 3, progress: 50 }),
    [],
    "internal_it_environment",
  );

  const summary = container.querySelector(".run-overview__progress-counts")?.textContent;
  expect(summary).toContain("Assets · Fully checked 1 · Remaining 0 · Need attention 2");
  expect(summary).toContain("Checks · Completed 1 · Remaining 0 · Need attention 1");
});

const primaryTimingCases: Array<[UseCaseId, string]> = [
  ["internal_it_environment", "Timing target: a useful result within minutes after tools are ready."],
  ["deployed_website", "Timing target: a useful result within minutes after tools are ready."],
  ["source_code", "Timing target: a useful result within minutes after tools are ready."],
];

test.each(primaryTimingCases)(
  "an active %s scan carries its first-result target into progress",
  (assessmentIntent, expectedTiming) => {
    const { container } = renderProgress(
      run([engine("active-check", "running")], "running"),
      [],
      assessmentIntent,
    );

    expect(container.querySelector(".run-overview__timing")?.textContent).toContain(expectedTiming);
  },
);

test("an advanced active scan does not invent a timing target", () => {
  const { container } = renderProgress(
    run([engine("cloud-check", "running")], "running"),
    [],
    "cloud_account",
  );

  const timing = container.querySelector(".run-overview__timing")?.textContent;
  expect(timing).toContain("Estimate unavailable");
  expect(timing).not.toContain("within minutes");
});

test("reachable-service inventory does not unlock security results", () => {
  const { container } = renderProgress(
    run([engine("naabu", "running", { findingCount: 1 })], "running"),
    [finding({
      id: "observation-1",
      severityBasisCode: "open_port",
      title: "Open TCP port",
      severity: "info",
      priority: 0,
    })],
  );

  expect(container.querySelector('a[href="#findings"]')).toBeNull();
});

test("the localhost connection utility never unlocks security results", () => {
  const { container } = renderProgress(
    run([
      engine(BUILT_IN_LOCALHOST_QUICK_SCAN_ENGINE_ID, "running", {
        category: "built_in_localhost_tcp",
        taskKind: {
          kind: "built_in_localhost_tcp",
          port: 9001,
          timeoutMs: LOCALHOST_QUICK_SCAN_TIMEOUT_MS,
          payloadBytes: 0,
        },
        findingCount: 1,
      }),
    ], "running"),
    [],
    "internal_it_environment",
  );

  expect(container.querySelector('a[href="#findings"]')).toBeNull();
  const timing = container.querySelector(".run-overview__timing")?.textContent;
  expect(timing).toContain("Estimate unavailable");
  expect(timing).not.toContain("within minutes");
});

test("a terminal scan keeps the results entry even when it found no problems", () => {
  const { container } = renderProgress(
    run([engine("semgrep", "completed", { findingCount: 0, progress: 100 })], "completed"),
  );

  const results = container.querySelector<HTMLAnchorElement>('a[href="#findings"]');
  expect(results?.textContent).toContain("View results");
  expect(results?.className).toContain("button--primary");
});
