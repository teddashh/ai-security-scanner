import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { resolveRuntimeSetupPresentation } from "../../src/runtimeSetupPresentation.ts";

const source = readFileSync(
  new URL("../../src/components/RuntimeSetupAssistant.tsx", import.meta.url),
  "utf8",
);
const shellSource = readFileSync(
  new URL("../../src/components/AppShell.tsx", import.meta.url),
  "utf8",
);
const scannerSource = readFileSync(
  new URL("../../src/services/scanner.ts", import.meta.url),
  "utf8",
);
const tauriSource = readFileSync(
  new URL("../../src-tauri/src/lib.rs", import.meta.url),
  "utf8",
);

test("missing WSL gets one bilingual Microsoft setup path and one safe recheck", () => {
  for (const phrase of [
    "Open Microsoft’s WSL setup",
    "開啟 Microsoft 的 WSL 設定",
    "I’m done — check again",
    "我完成了，重新檢查",
    "continue automatically",
    "自動接著準備",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(source, /href=\{MICROSOFT_WSL_HELP\}/u);
  assert.match(source, /setupFailed && showMicrosoftSetup/u);
  assert.match(source, /onClick=\{onSetup\}/u);
});

test("a generic setup failure offers a retry without inventing an external action", () => {
  for (const phrase of [
    "Scan-tool setup stopped",
    "掃描工具設定已停止",
    "Try setup again",
    "再試一次設定",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.doesNotMatch(source, /Follow the single action below/u);
  assert.doesNotMatch(source, /照著下方唯一的操作/u);
  assert.match(
    source,
    /setupFailed \? \(nextAction \? text\.recheck : text\.retry\) : setupCancelled \? text\.continue : text\.start/u,
  );
  assert.match(shellSource, /genericSetupFailure = !runtimeSetupWorking[\s\S]*runtimeSetup\?\.phase === "failed"[\s\S]*!runtimeSetup\.nextAction/u);
  assert.match(shellSource, /runtimeSetup\.nextAction[\s\S]*"runtime\.setup\.recheck"[\s\S]*"runtime\.setup\.retry"/u);
});

test("cancelled setup offers an honest continuation", () => {
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: { active: false, phase: "cancelled" },
  });
  assert.equal(state.setupCancelled, true);
  assert.equal(state.setupFailed, false);
  for (const phrase of [
    "Setup paused",
    "The download was kept on this computer",
    "Continue setup",
    "設定已暫停",
    "下載進度已保留在這台電腦上",
    "繼續設定",
  ]) assert.ok(source.includes(phrase), phrase);
  assert.match(source, /setupCancelled \? text\.continue : text\.start/u);
});

test("a retry immediately replaces a stale failure with a visible starting state", () => {
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: {
      active: false,
      prerequisiteRepairActive: false,
      phase: "failed",
    },
    requestPending: true,
  });

  assert.equal(state.setupStarting, true);
  assert.equal(state.setupActive, true);
  assert.equal(state.setupFailed, false);
  assert.equal(state.setupCancelled, false);
  assert.match(source, /requestPending: busy/u);
  assert.match(source, /setupStarting \? \(/u);
  assert.ok(source.includes("Starting setup…"));
  assert.ok(source.includes("正在開始設定…"));
  assert.match(source, /disabled aria-busy="true"/u);
  assert.match(shellSource, /runtimeSetupStarting = runtimeBusy/u);
  assert.match(shellSource, /displayedRuntimeSetupPhase = runtimeSetupStarting \? "install"/u);
});

test("the desktop UI cannot elevate or change Windows optional features", () => {
  for (const candidate of [source, shellSource, scannerSource]) {
    assert.doesNotMatch(candidate, /onRepair|repairManagedRuntimePrerequisite|administrator approval|系統管理員確認|wsl --install|wsl --update|UAC/u);
  }
  assert.doesNotMatch(tauriSource, /commands::repair_managed_runtime_prerequisite/u);
  assert.doesNotMatch(shellSource, /runtimeRepairing|onRepairRuntime|runtime\.setup\.repair/u);
});

test("packaged-component blockers remain visible without rerunning runtime setup", () => {
  for (const copy of [
    "Get the scan tools for this check",
    "取得這項檢查需要的掃描工具",
    "Restore one installed scan component",
    "恢復一項安裝元件",
    "Get the latest installer",
    "取得最新安裝程式",
    "https://github.com/teddashh/ai-security-scanner/releases",
  ]) assert.ok(source.includes(copy), copy);

  assert.match(source, /scannerSetupBlocker\?: ScannerSetupBlocker/u);
  assert.match(source, /resolveRuntimeSetupPresentation\(\{/u);
  assert.match(source, /presentation\.showPackagedComponentIssue && scannerSetupBlocker/u);
  assert.match(source, /scannerIssue \? \(/u);
  assert.match(source, /href=\{scannerIssue\.releaseHref\}/u);
  assert.match(source, /scannerIssue\.action/u);
  assert.doesNotMatch(source, /onClick=\{onSetup\}[^]*scannerIssue\.action/u);
  assert.doesNotMatch(source, /egress_gateway_unavailable[^}]*title:\s*"egress/u);
  assert.doesNotMatch(source, /engine_execution_contract_invalid[^}]*title:\s*"execution/u);
});

test("a current packaged-component blocker wins over stale ready, active, or failed setup status", () => {
  for (const blocker of ["no_runnable_authorized_targets", "egress_gateway_unavailable"] as const) {
    for (const status of [
      { active: true, phase: "start" as const },
      { active: false, phase: "failed" as const },
    ]) {
      const state = resolveRuntimeSetupPresentation({
        mode: "native",
        runtimeAvailable: true,
        status,
        blocker,
      });

      assert.equal(state.ready, false);
      assert.equal(state.showPackagedComponentIssue, true);
      assert.equal(state.setupActive, false);
      assert.equal(state.setupFailed, false);
    }
  }

  assert.equal(resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: true,
    status: { active: false, phase: "failed" },
  }).ready, true);
});
