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
const appSource = readFileSync(
  new URL("../../src/App.tsx", import.meta.url),
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

test("backend prerequisite states stay inside one automatic, plain-language setup path", () => {
  for (const phrase of [
    "One local scan tool is unavailable",
    "Automatic setup could not finish",
    "Try setup again",
    "一項本機掃描工具目前無法使用",
    "自動設定未能完成",
    "再試一次設定",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(source, /onClick=\{onSetup\}/u);
  for (const candidate of [source, shellSource]) {
    assert.doesNotMatch(candidate, /learn\.microsoft\.com|Windows Terminal|wsl\.exe|distribution name|發行版名稱|Windows 終端機/u);
    assert.doesNotMatch(candidate, /MICROSOFT_WSL_|needsMicrosoftWslSetup|showMicrosoftSetup|recoveryHelp|nextAction\.steps|text\.docs|text\.recheck/u);
  }
});

test("an unproven older workspace is preserved without a manual action or retry loop", () => {
  for (const phrase of [
    "Older scan-tool data was preserved",
    "left that data untouched",
    "This scan tool is unavailable in this session",
    "舊的掃描工具資料已保留",
    "沒有更動其中資料",
    "這個掃描工具目前無法使用",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(source, /preservedUnknownWorkspace = status\?\.nextAction === "resolve_wsl_distribution_manually"/u);
  assert.match(source, /setupFailed && preservedUnknownWorkspace \? \([\s\S]*null/u);
  assert.match(shellSource, /preservedUnknownWorkspace = runtimeSetup\?\.nextAction === "resolve_wsl_distribution_manually"/u);
  assert.match(shellSource, /runtimeSetupWorking \? \([\s\S]*preservedUnknownWorkspace \? null/u);
  assert.doesNotMatch(appSource, /onOpenRuntimeSetup/u);
  assert.doesNotMatch(source, /backup|remov(?:e|al)|rename|備份|移除|重新命名/iu);
});

test("active reconciliation stays automatic without claiming a replacement already happened", () => {
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: { active: true, phase: "recovery" },
  });

  assert.equal(state.setupActive, true);
  assert.equal(state.setupRecovering, true);
  assert.equal(state.setupFailed, false);
  for (const phrase of [
    "Finishing a previous setup",
    "reconciling product-owned scan-tool files automatically",
    "Safely recovering the previous workspace",
    "正在完成先前未完成的設定",
    "自動整理可確認屬於本產品的掃描工具檔案",
    "正在安全復原先前的工作區",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(source, /setupRecovering[\s\S]*text\.recoveryTitle/u);
  assert.match(source, /setupRecovering[\s\S]*text\.recoveryDescription/u);
  assert.doesNotMatch(source, /saving a recovery copy|replacing that workspace|保留一份復原備份|換成乾淨的工作區/u);
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
    /setupFailed \? text\.retry : setupCancelled \? text\.continue : text\.start/u,
  );
  assert.match(shellSource, /genericSetupFailure = !runtimeSetupWorking[\s\S]*runtimeSetup\?\.phase === "failed"[\s\S]*!runtimeSetup\.nextAction/u);
  assert.match(shellSource, /runtimeSetup\?\.phase === "failed"[\s\S]*"runtime\.setup\.retry"/u);
});

test("a required Windows restart is explicit without exposing platform administration", () => {
  for (const phrase of [
    "Windows requires a restart to finish its change",
    "reopen ai-security-scanner and automatic setup will resume",
    "Windows 必須重新啟動才能完成變更",
    "自動設定就會繼續",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.doesNotMatch(source, /PowerShell|Windows Terminal|wsl\.exe|optional feature|系統管理員|終端機/u);
});

test("technical details expose only a bounded failure category", () => {
  assert.match(source, /technicalDetail = setupFailed[\s\S]*"older_workspace_ownership_unconfirmed"[\s\S]*"local_scan_tool_unavailable"/u);
  assert.match(source, /<code>\{technicalDetail\}<\/code>/u);
  assert.doesNotMatch(source, /displaySafeTechnicalDetail\(status\?\.detail\)|<code>\{status\?\.detail\}<\/code>/u);
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
