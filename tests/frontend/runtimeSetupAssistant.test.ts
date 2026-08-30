import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  hasManagedRuntimeSetupRequestStarted,
  resolveRuntimeSetupPresentation,
} from "../../src/runtimeSetupPresentation.ts";

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

test("an unproven older workspace never becomes a manual setup contract", () => {
  for (const candidate of [source, shellSource, appSource]) {
    assert.doesNotMatch(
      candidate,
      /resolve_wsl_distribution_manually|windows_wsl_distribution_requires_manual_action/u,
    );
  }
  assert.match(source, /!setupFailed && !setupCancelled && !setupIdleUnavailable \? null/u);
  assert.match(source, /<button[^>]*onClick=\{onSetup\}/u);
  assert.doesNotMatch(source, /unavailable in this session|這個掃描工具目前無法使用/u);
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
    "Preparing a fresh scan workspace",
    "prepares an isolated replacement automatically",
    "Safely recovering the previous workspace",
    "正在準備新的隔離掃描空間",
    "自動準備隔離的新工作空間",
    "正在安全復原先前的工作區",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(source, /setupRecovering[\s\S]*text\.recoveryTitle/u);
  assert.match(source, /setupRecovering[\s\S]*text\.recoveryDescription/u);
  assert.doesNotMatch(source, /saving a recovery copy|replacing that workspace|保留一份復原備份|換成乾淨的工作區/u);
});

test("a generic setup failure offers a retry without inventing an external action", () => {
  for (const phrase of [
    "One local check is unavailable",
    "一項本機檢查目前無法使用",
    "Try preparation again",
    "再試一次自動準備",
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
  assert.match(source, /technicalDetail = setupFailed \? "local_scan_tool_unavailable" : undefined/u);
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

test("a pre-existing terminal result does not override a newly clicked retry", () => {
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
  assert.match(appSource, /runtimeSetupRequestPending = runtimeSetupAdmissionPending/u);
  assert.match(appSource, /requestStarted && isManagedRuntimeSetupTerminal\(result\.data\)/u);
  assert.match(appSource, /runtimeSetupPolling = runtimeSetupCommandPolling/u);
  assert.match(shellSource, /runtimeSetupStarting = runtimeBusy/u);
  assert.match(shellSource, /displayedRuntimeSetupPhase = runtimeSetupStarting \? "install"/u);
});

test("new backend operation identity terminalizes a lost Retry invocation", () => {
  const baseline = {
    operationId: "operation-a",
  };
  assert.equal(hasManagedRuntimeSetupRequestStarted(baseline, {
    active: false,
    operationId: "operation-a",
  }), false);
  assert.equal(hasManagedRuntimeSetupRequestStarted(baseline, {
    active: false,
    operationId: "operation-b",
  }), true);
  assert.equal(hasManagedRuntimeSetupRequestStarted(baseline, {
    active: true,
    operationId: "operation-a",
  }), false);
  assert.match(appSource, /requestGeneration >= admission\.minimumStatusRequestGeneration/u);
  assert.match(appSource, /minimumStatusRequestGeneration: runtimeSetupStatusRequestGeneration\.current \+ 1/u);
});

test("idle unavailable runtime always offers an explicit retry fallback", () => {
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: { active: false, phase: "idle" },
  });

  assert.equal(state.setupIdleUnavailable, true);
  assert.equal(state.setupActive, false);
  for (const phrase of [
    "One local check is not ready yet",
    "safely continue or restart its automatic preparation",
    "一項本機檢查尚未準備好",
    "安全地繼續或重新開始自動準備",
  ]) assert.ok(source.includes(phrase), phrase);
  assert.match(source, /!setupFailed && !setupCancelled && !setupIdleUnavailable \? null/u);
  assert.match(shellSource, /\) : !runtimeSetupWorking \? \(/u);
});

test("backend stale state is visible without the UI inventing a terminal failure", () => {
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: { active: true, phase: "start", stale: true },
  });

  assert.equal(state.setupStale, true);
  assert.equal(state.setupActive, true);
  assert.equal(state.setupFailed, false);
  for (const phrase of [
    "Preparation took longer than expected",
    "stopping that exact attempt safely",
    "準備時間超過預期",
    "安全停止這次作業",
  ]) assert.ok(source.includes(phrase), phrase);
});

test("the desktop UI cannot elevate or change Windows optional features", () => {
  for (const candidate of [source, shellSource, scannerSource]) {
    assert.doesNotMatch(candidate, /onRepair|repairManagedRuntimePrerequisite|administrator approval|系統管理員確認|wsl --install|wsl --update|UAC/u);
  }
  assert.doesNotMatch(tauriSource, /commands::repair_managed_runtime_prerequisite/u);
  assert.doesNotMatch(shellSource, /runtimeRepairing|onRepairRuntime|runtime\.setup\.repair/u);
});

test("packaged-component blockers remain task-scoped without claiming generic setup can repair them", () => {
  for (const copy of [
    "This check is unavailable in the installed version",
    "目前安裝版本無法執行這項檢查",
    "One installed scan component is unavailable",
    "一項隨附掃描元件目前無法使用",
    "Check availability again",
    "重新檢查可用性",
  ]) assert.ok(source.includes(copy), copy);

  assert.match(source, /scannerSetupBlocker\?: ScannerSetupBlocker/u);
  assert.match(source, /onCheckScannerAvailability: \(\) => void/u);
  assert.match(source, /resolveRuntimeSetupPresentation\(\{/u);
  assert.match(source, /presentation\.showPackagedComponentIssue && scannerSetupBlocker/u);
  assert.match(source, /scannerIssue \? \(/u);
  assert.match(source, /onClick=\{onCheckScannerAvailability\}/u);
  assert.match(source, /scannerIssue\.action/u);
  assert.match(appSource, /onCheckScannerAvailability=\{\(\) => \{[\s\S]*retryScanReadiness\(currentCaseId\)/u);
  assert.doesNotMatch(source, /automatic repair|自動修復/iu);
  assert.doesNotMatch(source, /releaseHref|github\.com\/teddashh\/ai-security-scanner\/releases/u);
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
