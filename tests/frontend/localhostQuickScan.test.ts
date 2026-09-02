import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DEFAULT_LOCALHOST_QUICK_SCAN_PORT,
  isExactBuiltInLocalhostQuickScanRun,
  isLocalhostQuickScanCancelRequested,
  isTerminalExactBuiltInLocalhostQuickScanRun,
  isValidLocalhostQuickScanPort,
  LOCALHOST_QUICK_SCAN_TIMEOUT_MS,
  parseLocalhostQuickScanPort,
} from "../../src/localhostQuickScan.ts";
import type { EngineRun, ScanRun } from "../../src/types.ts";

const engine = (overrides: Partial<EngineRun> = {}): EngineRun => ({
  id: "localhost-task",
  engineId: "built-in-localhost-tcp",
  engineName: "127.0.0.1:9001 TCP",
  category: "built_in_localhost_tcp",
  taskKind: {
    kind: "built_in_localhost_tcp",
    port: 9001,
    timeoutMs: LOCALHOST_QUICK_SCAN_TIMEOUT_MS,
    payloadBytes: 0,
  },
  warnings: [],
  status: "running",
  progress: 10,
  phase: "connecting",
  assetIds: ["localhost-asset"],
  rawArtifactCount: 0,
  findingCount: 0,
  resumable: false,
  ...overrides,
});

const run = (engineRuns: EngineRun[]): ScanRun => ({
  id: "localhost-run",
  caseId: "localhost-case",
  label: "Scan 1",
  status: "running",
  progress: 10,
  startedAt: "2026-08-30T12:00:00Z",
  knowledgeDate: "2026-08-30",
  engineRuns,
  coveredAssetCount: 0,
  totalAssetCount: 1,
});

test("localhost quick-scan port editing is bounded and defaults to 9001", () => {
  assert.equal(DEFAULT_LOCALHOST_QUICK_SCAN_PORT, 9001);
  assert.equal(LOCALHOST_QUICK_SCAN_TIMEOUT_MS, 3_000);
  for (const port of [1, 9001, 65_535]) assert.equal(isValidLocalhostQuickScanPort(port), true);
  for (const port of [0, -1, 65_536, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.equal(isValidLocalhostQuickScanPort(port), false);
  }
  for (const [input, expected] of [
    ["1", 1],
    ["9001", 9001],
    [" 65535 ", 65_535],
  ] as const) assert.equal(parseLocalhostQuickScanPort(input), expected);
  for (const input of ["", "0", "-1", "65536", "1.5", "1e3", "not-a-port"]) {
    assert.equal(parseLocalhostQuickScanPort(input), undefined);
  }
});

test("only the exact single built-in task receives localhost lifecycle controls", () => {
  const exact = run([engine()]);
  assert.equal(isExactBuiltInLocalhostQuickScanRun(exact), true);
  assert.equal(isTerminalExactBuiltInLocalhostQuickScanRun(exact), false);
  assert.equal(isTerminalExactBuiltInLocalhostQuickScanRun({
    ...exact,
    status: "completed",
    progress: 100,
  }), true);
  assert.equal(isLocalhostQuickScanCancelRequested(exact), false);
  assert.equal(isLocalhostQuickScanCancelRequested(run([
    engine({ phase: "cancel_requested" }),
  ])), true);
  assert.equal(isLocalhostQuickScanCancelRequested(run([
    engine({ phase: "cancel_requested", status: "cancelled" }),
  ])), false, "terminal cancellation is not an in-flight stop request");
  assert.equal(isLocalhostQuickScanCancelRequested({
    ...run([engine({ phase: "cancel_requested" })]),
    status: "completed",
  }), false, "a terminal aggregate cannot present an in-flight stop request");

  assert.equal(isExactBuiltInLocalhostQuickScanRun(run([
    engine({ taskKind: { kind: "catalog_engine" } }),
  ])), false);
  assert.equal(isTerminalExactBuiltInLocalhostQuickScanRun({
    ...run([engine({ taskKind: { kind: "catalog_engine" } })]),
    status: "completed",
  }), false, "lookalike terminal work must not suppress generic scan readiness");
  assert.equal(isExactBuiltInLocalhostQuickScanRun(run([
    engine({ taskKind: { kind: "built_in_localhost_tcp", port: 9001, timeoutMs: 4_000, payloadBytes: 0 } }),
  ])), false);
  assert.equal(isExactBuiltInLocalhostQuickScanRun(run([
    engine({ engineId: "lookalike-localhost-engine" }),
  ])), false, "task shape alone cannot claim the product-owned lifecycle");
  assert.equal(isExactBuiltInLocalhostQuickScanRun(run([engine(), engine({ id: "second-task" })])), false);
});

test("the installed start page leads with the bounded localhost action and keeps other use cases secondary", async () => {
  const startPage = await readFile(new URL("../../src/pages/StartPage.tsx", import.meta.url), "utf8");

  for (const copy of [
    "Scan this computer at 127.0.0.1:9001",
    "掃描這台電腦的 127.0.0.1:9001",
    "attempts one TCP connection",
    "waits no more than 3 seconds",
    "It sends no payload and is not a security guarantee.",
    "只會嘗試連線一次",
    "最長等待 3 秒",
    "不會傳送內容，也不代表這台電腦一定安全",
  ]) assert.ok(startPage.includes(copy), copy);

  assert.match(startPage, /nativeMode && \([\s\S]*start-page__localhost-quick-scan/u);
  assert.match(startPage, /disabled=\{localhostQuickScanBusy \|\| localhostPort === undefined\}/u);
  assert.match(startPage, /aria-busy=\{localhostQuickScanBusy\}/u);
  assert.match(startPage, /onStartLocalhostQuickScan\(localhostPort\)/u);
  assert.match(startPage, /<details className="start-page__localhost-options">[\s\S]*type="number"[\s\S]*min=\{1\}[\s\S]*max=\{65535\}/u);
  assert.match(startPage, /nativeMode \? "button--secondary" : "button--primary"/u);
  assert.match(startPage, /href="#start-a-check"/u);
});

test("progress hides pause and resume for the exact task and makes a stop request non-repeatable", async () => {
  const progress = await readFile(new URL("../../src/pages/ProgressPage.tsx", import.meta.url), "utf8");

  assert.match(
    progress,
    /const exactLocalhostQuickScan = Boolean\(\s*selectedRun && isExactBuiltInLocalhostQuickScanRun\(selectedRun\)/u,
  );
  assert.match(progress, /const terminalExactLocalhostQuickScan = Boolean\([\s\S]*isTerminalExactBuiltInLocalhostQuickScanRun\(selectedRun\)/u);
  assert.match(progress, /const canStart = !terminalExactLocalhostQuickScan[\s\S]*canStartPreparedScan/u);
  assert.match(
    progress,
    /terminalLocalhostSummary && \(\s*terminalLocalhostSummary\.outcome === "closed"\s*\|\| terminalLocalhostSummary\.outcome === "timed_out"\s*\|\| needsFreshLocalhostTcpAttempt\(terminalLocalhostSummary\.outcome\)/u,
  );
  assert.doesNotMatch(
    progress,
    /terminalLocalhostSummary\.outcome === "reachable"[\s\S]{0,160}needsFreshLocalhostTcpAttempt/u,
  );
  assert.match(progress, /onRetryLocalhostQuickScan\(terminalLocalhostSummary\.port\)/u);
  assert.match(progress, /Running it again creates a new saved attempt for 127\.0\.0\.1:\{port\}\. This result stays unchanged\./u);
  assert.match(progress, /重新執行會為 127\.0\.0\.1:\{port\} 建立一筆新的已保存嘗試；這筆結果會保持不變。/u);
  assert.match(progress, /\{!terminalExactLocalhostQuickScan && readinessCheckFailed/u);
  assert.match(progress, /\{!terminalExactLocalhostQuickScan && readiness && !readiness\.ready/u);
  assert.match(progress, /const localhostCancelRequested = isLocalhostQuickScanCancelRequested\(selectedRun\)/u);
  assert.match(progress, /const canPause = selectedRun\.status === "running" && !exactLocalhostQuickScan/u);
  assert.match(progress, /const canResume = !startFreshScan &&[\s\S]*\) && !exactLocalhostQuickScan;/u);
  assert.match(progress, /const canCancel = !localhostCancelRequested/u);
  assert.match(progress, /\{localhostCancelRequested && \([\s\S]*role="status"[\s\S]*aria-live="polite"[\s\S]*copy\.stopping/u);
  assert.doesNotMatch(progress, /localhostCancelRequested[\s\S]{0,300}<button/u);
  assert.match(progress, /engine\.phase === "cancel_requested"[\s\S]*copy\.cancelRequestedPhase/u);
});

test("localhost endpoints keep protocol ports ungrouped while measurements stay locale-formatted", async () => {
  const progress = await readFile(new URL("../../src/pages/ProgressPage.tsx", import.meta.url), "utf8");

  assert.doesNotMatch(progress, /formatNumber\(localhostSummary\.port\)/u);
  assert.equal(progress.match(/String\(localhostSummary\.port\)/gu)?.length, 3);
  assert.match(progress, /formatNumber\(localhostSummary\.timeoutMs\)/u);
  assert.match(progress, /formatNumber\(localhostSummary\.payloadBytes\)/u);
});

test("App immediately selects the returned native workspace, opens progress, then refreshes authoritatively", async () => {
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const actionStart = app.indexOf("const startLocalhostQuickScan = async");
  const actionEnd = app.indexOf("const executeAction = async", actionStart);
  const action = app.slice(actionStart, actionEnd);
  assert.ok(actionStart >= 0 && actionEnd > actionStart);

  assert.match(action, /scannerService\.startLocalhostQuickScan\(port\)/u);
  assert.match(action, /result\.mode !== "native" \|\| !result\.data\.accepted \|\| !quickWorkspace/u);
  assert.match(action, /const workspaceEventGenerationAtRequest = scanWorkspaceEventGeneration\.current/u);
  assert.match(action, /observedQuick\.generation > workspaceEventGenerationAtRequest[\s\S]*observedQuick\.workspace,[\s\S]*observedQuick\.freshestWorkspace,[\s\S]*quickWorkspace/u);
  assert.match(action, /selectedCaseIdRef\.current = selectedQuickWorkspace\.case\.id/u);
  assert.match(action, /selectedCaseId: selectedQuickWorkspace\.case\.id/u);
  assert.match(action, /mergeWorkspaceIntoSnapshot\(selectedSnapshot, selectedQuickWorkspace\)/u);
  const navigateIndex = action.indexOf('navigate("progress")');
  const refreshIndex = action.indexOf("void loadSnapshot(selectedQuickWorkspace.case.id, true)");
  assert.ok(navigateIndex >= 0 && refreshIndex > navigateIndex);
  assert.doesNotMatch(action, /await loadSnapshot/u);
  assert.doesNotMatch(action, /result\.data\.message/u);
  assert.doesNotMatch(action, /navigate\("(?:cases|coverage|start)"\)|setupManagedRuntime|approveScope/u);

  assert.match(app, /nativeMode=\{mode === "native"\}/u);
  assert.match(app, /localhostQuickScanBusy=\{busyAction === "localhost-quick-scan"\}/u);
  assert.match(app, /onStartLocalhostQuickScan=\{\(port\) => void startLocalhostQuickScan\(port\)\}/u);
  assert.match(app, /onRetryLocalhostQuickScan=\{startLocalhostQuickScan\}/u);
  assert.match(app, /retryingLocalhostQuickScan=\{busyAction === "localhost-quick-scan"\}/u);
});

test("the scanner service adapts the queued localhost workspace without loading catalog manifests", async () => {
  const scanner = await readFile(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");
  const actionStart = scanner.indexOf("async startLocalhostQuickScan");
  const actionEnd = scanner.indexOf("async updateFindingWorkflow", actionStart);
  const action = scanner.slice(actionStart, actionEnd);
  assert.ok(actionStart >= 0 && actionEnd > actionStart);

  assert.match(scanner, /startLocalhostQuickScan: "start_localhost_quick_scan"/u);
  assert.match(action, /port = DEFAULT_LOCALHOST_QUICK_SCAN_PORT/u);
  assert.match(action, /invoke<NativeAssessmentCase>\(COMMANDS\.startLocalhostQuickScan, \{ port \}\)/u);
  assert.match(action, /workspace: adaptNativeCase\(returnedCase, \[\]\)/u);
  assert.match(action, /The localhost check was saved\. Scan progress will show when the connection begins\./u);
  assert.match(action, /本機連接埠檢查已儲存；開始連線時會顯示在掃描進度。/u);
  assert.doesNotMatch(action, /saved and started|已儲存並開始|target was contacted/iu);
  assert.match(action, /Browser demo mode did not contact this computer or start a real scan\./u);
  assert.doesNotMatch(action, /getNativeManifests|actionResult/u);
});

test("pause refusal and typed cancellation feedback never claim that active contact already stopped", async () => {
  const [app, scanner, lifecycle] = await Promise.all([
    readFile(new URL("../../src/App.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/services/scanner.ts", import.meta.url), "utf8"),
    readFile(new URL("../../src/scanLifecycleDisposition.ts", import.meta.url), "utf8"),
  ]);

  assert.match(app, /scanLifecycleToastPresentation\(lifecycleDisposition\)/u);
  assert.match(app, /deriveScanLifecycleDisposition\([\s\S]*selectedWorkspace/u);
  assert.match(lifecycle, /Stopping this check\. If a connection attempt already started, it will end within its 3-second limit\./u);
  assert.match(app, /const refuseUnsupportedLocalhostPauseOrResume = \(runId: string\)/u);
  assert.match(app, /isExactBuiltInLocalhostQuickScanRun\(run\)/u);
  assert.match(app, /key === "pause-scan" \|\| key === "resume-scan"[\s\S]*refuseUnsupportedLocalhostPauseOrResume\(runId\)/u);
  assert.match(app, /onPause=\{\(runId\) => runAction\("pause-scan"[\s\S]*, runId\)\}/u);
  assert.match(app, /onResume=\{\(runId\) => runAction\("resume-scan"[\s\S]*, runId\)\}/u);

  const cancelStart = scanner.indexOf("async cancelScan");
  const cancelEnd = scanner.indexOf("async startRescan", cancelStart);
  const cancel = scanner.slice(cancelStart, cancelEnd);
  assert.ok(cancelStart >= 0 && cancelEnd > cancelStart);
  assert.match(cancel, /The latest saved scan state was returned\./u);
  assert.doesNotMatch(cancel, /stop request was saved|was cancelled and|contact has stopped/iu);
});
