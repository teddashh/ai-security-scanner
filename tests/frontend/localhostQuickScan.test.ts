import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DEFAULT_LOCALHOST_QUICK_SCAN_PORT,
  isValidLocalhostQuickScanPort,
  parseLocalhostQuickScanPort,
} from "../../src/localhostQuickScan.ts";

test("localhost quick-scan port editing is bounded and defaults to 9001", () => {
  assert.equal(DEFAULT_LOCALHOST_QUICK_SCAN_PORT, 9001);
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

test("the installed start page leads with the bounded localhost action and keeps other use cases secondary", async () => {
  const startPage = await readFile(new URL("../../src/pages/StartPage.tsx", import.meta.url), "utf8");

  for (const copy of [
    "Scan this computer at 127.0.0.1:9001",
    "掃描這台電腦的 127.0.0.1:9001",
    "attempts one TCP connection",
    "It sends no payload and is not a security guarantee.",
    "只會嘗試連線一次",
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

test("App immediately selects the returned native workspace, opens progress, then refreshes authoritatively", async () => {
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const actionStart = app.indexOf("const startLocalhostQuickScan = async");
  const actionEnd = app.indexOf("const executeAction = async", actionStart);
  const action = app.slice(actionStart, actionEnd);
  assert.ok(actionStart >= 0 && actionEnd > actionStart);

  assert.match(action, /scannerService\.startLocalhostQuickScan\(port\)/u);
  assert.match(action, /result\.mode !== "native" \|\| !result\.data\.accepted \|\| !quickWorkspace/u);
  assert.match(action, /selectNewerWorkspaceByRevision\(quickWorkspace, observedQuickWorkspace\)/u);
  assert.match(action, /selectedCaseIdRef\.current = selectedQuickWorkspace\.case\.id/u);
  assert.match(action, /selectedCaseId: selectedQuickWorkspace\.case\.id/u);
  assert.match(action, /mergeWorkspaceIntoSnapshot\(selectedSnapshot, selectedQuickWorkspace\)/u);
  const navigateIndex = action.indexOf('navigate("progress")');
  const refreshIndex = action.indexOf("await loadSnapshot(selectedQuickWorkspace.case.id, true)");
  assert.ok(navigateIndex >= 0 && refreshIndex > navigateIndex);
  assert.doesNotMatch(action, /result\.data\.message/u);
  assert.doesNotMatch(action, /navigate\("(?:cases|coverage|start)"\)|setupManagedRuntime|approveScope/u);

  assert.match(app, /nativeMode=\{mode === "native"\}/u);
  assert.match(app, /localhostQuickScanBusy=\{busyAction === "localhost-quick-scan"\}/u);
  assert.match(app, /onStartLocalhostQuickScan=\{\(port\) => void startLocalhostQuickScan\(port\)\}/u);
});

test("the scanner service exposes one workspace-returning localhost command with a safe demo outcome", async () => {
  const scanner = await readFile(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");
  const actionStart = scanner.indexOf("async startLocalhostQuickScan");
  const actionEnd = scanner.indexOf("async updateFindingWorkflow", actionStart);
  const action = scanner.slice(actionStart, actionEnd);
  assert.ok(actionStart >= 0 && actionEnd > actionStart);

  assert.match(scanner, /startLocalhostQuickScan: "start_localhost_quick_scan"/u);
  assert.match(action, /port = DEFAULT_LOCALHOST_QUICK_SCAN_PORT/u);
  assert.match(action, /COMMANDS\.startLocalhostQuickScan,[\s\S]*\{ port \}/u);
  assert.match(action, /Browser demo mode did not contact this computer or start a real scan\./u);
  assert.match(action, /,[\s\n]*true,[\s\n]*\);/u);
});
