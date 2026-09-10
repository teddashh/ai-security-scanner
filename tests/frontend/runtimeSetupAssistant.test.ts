import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  hasUnconfirmedManagedRuntimeCompletion,
  hasManagedRuntimeSetupRequestStarted,
  isManagedRuntimePackageAdmissionFailure,
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

test("backend prerequisite states stay inside one user-triggered, plain-language setup path", () => {
  for (const phrase of [
    "Advanced local scan-tool setup did not finish",
    "Try advanced scan setup again",
    "進階本機掃描工具設定未能完成",
    "再試一次進階掃描設定",
  ]) assert.ok(source.includes(phrase), phrase);
  assert.doesNotMatch(source, /localhost quick check|localhost 快速檢查/u);

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
  assert.match(source, /setupNonRetryable \|\| \(!setupFailed && !setupCancelled && !setupIdleUnavailable\) \? null/u);
  assert.match(source, /<button[^>]*onClick=\{onSetup\}/u);
  assert.doesNotMatch(source, /unavailable in this session|這個掃描工具目前無法使用/u);
  assert.doesNotMatch(appSource, /onOpenRuntimeSetup/u);
  assert.doesNotMatch(source, /backup|remov(?:e|al)|rename|備份|移除|重新命名/iu);
});

test("an admitted setup can reconcile its own workspace without claiming a replacement already happened", () => {
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: { active: true, phase: "recovery" },
  });

  assert.equal(state.setupActive, true);
  assert.equal(state.setupRecovering, true);
  assert.equal(state.setupFailed, false);
  for (const phrase of [
    "Preparing a fresh advanced local scan workspace",
    "Preparing an isolated replacement workspace for this request",
    "Recovering the advanced local scan workspace",
    "正在準備新的進階本機掃描隔離工作區",
    "正在為這次要求準備隔離的新工作空間",
    "正在復原進階本機掃描工作區",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(source, /setupRecovering[\s\S]*text\.recoveryTitle/u);
  assert.match(source, /setupRecovering[\s\S]*text\.recoveryDescription/u);
  assert.doesNotMatch(source, /saving a recovery copy|replacing that workspace|保留一份復原備份|換成乾淨的工作區/u);
});

test("a generic setup failure offers a retry without inventing an external action", () => {
  for (const phrase of [
    "Advanced local scan-tool setup did not finish",
    "進階本機掃描工具設定未能完成",
    "Try advanced scan setup again",
    "再試一次進階掃描設定",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.doesNotMatch(source, /Follow the single action below/u);
  assert.doesNotMatch(source, /照著下方唯一的操作/u);
  assert.match(
    source,
    /setupFailed \? nextAction\?\.action \?\? text\.retry : setupCancelled \? text\.continue : text\.start/u,
  );
  assert.match(shellSource, /genericSetupFailure = !runtimeSetupWorking[\s\S]*runtimeSetup\?\.phase === "failed"[\s\S]*!runtimeSetup\.nextAction/u);
  assert.match(shellSource, /runtimeSetup\?\.phase === "failed"[\s\S]*"runtime\.setup\.retry"/u);
});

test("managed-runtime toasts keep the advanced-tool failure focused on the next action", () => {
  for (const phrase of [
    "Advanced local scan-tool setup did not finish",
    "Try advanced local scan preparation again",
    "進階本機掃描工具設定未能完成",
    "請再試一次進階本機掃描準備",
  ]) assert.ok(appSource.includes(phrase), phrase);
  assert.doesNotMatch(appSource, /localhost quick check|localhost 快速檢查/u);

  assert.doesNotMatch(appSource, /title: text\(\{ en: "One local check is unavailable"/u);
  assert.doesNotMatch(appSource, /title: text\(\{ en: "One local check cannot run in this app version"/u);
});

test("an exact packaged-runtime admission failure degrades gracefully without another setup loop", () => {
  const packageFailure = {
    active: false,
    prerequisiteRepairActive: false,
    phase: "failed" as const,
    canRetry: false,
    failureReason: "packaged_runtime_missing" as const,
    nextAction: undefined,
  };
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: packageFailure,
  });

  assert.equal(isManagedRuntimePackageAdmissionFailure(packageFailure), true);
  assert.equal(state.setupNonRetryable, true);
  assert.equal(state.setupFailed, true);
  for (const phrase of [
    "An advanced local scan tool is unavailable in this app version",
    "Install a compatible app version to run this advanced check",
    "這個程式版本無法使用一項進階本機掃描工具",
    "請安裝相容的程式版本，再執行這項進階檢查",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(source, /setupNonRetryable \|\| \(!setupFailed[\s\S]*\? null : \(/u);
  assert.match(shellSource, /!runtimeSetupWorking && !runtimeSetupNonRetryable \? \(/u);
  assert.match(appSource, /if \(isManagedRuntimePackageAdmissionFailure\(runtimeSetup\)\) return;/u);

  const nonRetryableCopy = source.slice(
    source.indexOf("nonRetryableTitle:"),
    source.indexOf("scannerIssues:", source.indexOf("nonRetryableTitle:")),
  );
  assert.doesNotMatch(nonRetryableCopy, /WSL|Podman|gateway|manifest|provenance|package/iu);
});

test("canRetry false alone never masquerades as a package admission failure", () => {
  const completed = {
    active: false,
    phase: "completed" as const,
    canRetry: false,
  };
  const activeRepair = {
    active: false,
    prerequisiteRepairActive: true,
    phase: "prerequisite" as const,
    canRetry: false,
  };
  const unclassifiedFailure = {
    active: false,
    phase: "failed" as const,
    canRetry: false,
  };

  assert.equal(isManagedRuntimePackageAdmissionFailure(completed), false);
  assert.equal(isManagedRuntimePackageAdmissionFailure(activeRepair), false);
  assert.equal(isManagedRuntimePackageAdmissionFailure(unclassifiedFailure), false);
  assert.equal(resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: activeRepair,
  }).setupActive, true);
  assert.equal(resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: unclassifiedFailure,
  }).setupNonRetryable, false);
});

test("a required Windows restart is explicit without exposing platform administration", () => {
  for (const phrase of [
    "Restart Windows, reopen ai-security-scanner, then select Continue setup",
    "Continue after restarting Windows",
    "重新啟動 Windows，開啟 ai-security-scanner",
    "按下「繼續設定」",
    "重新啟動 Windows 後繼續",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.doesNotMatch(source, /PowerShell|Windows Terminal|wsl\.exe|optional feature|系統管理員|終端機/u);
});

test("technical details expose only a bounded failure category", () => {
  assert.match(source, /technicalDetail = setupFailed \? "local_scan_tool_unavailable" : undefined/u);
  assert.match(source, /<code>\{technicalDetail\}<\/code>/u);
  assert.doesNotMatch(source, /displaySafeTechnicalDetail\(status\?\.detail\)|<code>\{status\?\.detail\}<\/code>/u);
});

test("cancelled setup presents a direct terminal state and continuation action", () => {
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: { active: false, phase: "cancelled" },
  });
  assert.equal(state.setupCancelled, true);
  assert.equal(state.setupFailed, false);
  for (const phrase of [
    "Advanced local scan-tool setup cancelled",
    "Scan-tool status: not ready",
    "Continue advanced scan setup",
    "進階本機掃描工具設定已取消",
    "掃描工具狀態：尚未就緒",
    "繼續進階掃描設定",
  ]) assert.ok(source.includes(phrase), phrase);
  for (const phrase of [
    "Advanced local scan-tool setup cancelled",
    "Scan-tool status: not ready",
    "進階本機掃描工具設定已取消",
    "掃描工具狀態：尚未就緒",
  ]) assert.ok(appSource.includes(phrase), phrase);
  assert.doesNotMatch(source, /paused|saved download|download was kept|設定已暫停|已保存的下載|下載進度已保留/iu);
  assert.doesNotMatch(appSource, /setup paused|saved download|設定已暫停|已保存的下載/iu);
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
  assert.match(shellSource, /displayedRuntimeSetupPhase = runtimeSetupStarting\s*\? "install"/u);
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

test("an admitted idle runtime offers an explicit preparation action", () => {
  const state = resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: false,
    status: { active: false, phase: "idle" },
  });

  assert.equal(state.setupIdleUnavailable, true);
  assert.equal(state.setupActive, false);
  for (const phrase of [
    "This scan needs additional local tools",
    "Select Prepare scan tools to begin",
    "Prepare scan tools",
    "這項掃描需要額外的本機工具",
    "按下「準備掃描工具」即可開始",
    "準備掃描工具",
  ]) assert.ok(source.includes(phrase), phrase);
  assert.match(source, /setupNonRetryable \|\| \(!setupFailed && !setupCancelled && !setupIdleUnavailable\) \? null/u);
  assert.match(shellSource, /\) : !runtimeSetupWorking && !runtimeSetupNonRetryable \? \(/u);
});

test("completed setup copy stays hidden until authoritative runtime truth is ready", () => {
  assert.equal(hasUnconfirmedManagedRuntimeCompletion(false, "completed"), true);
  assert.equal(hasUnconfirmedManagedRuntimeCompletion(undefined, "completed"), true);
  assert.equal(hasUnconfirmedManagedRuntimeCompletion(true, "completed"), false);
  assert.equal(hasUnconfirmedManagedRuntimeCompletion(false, "start"), false);

  assert.match(shellSource, /runtimeSetupCompletionUnconfirmed = hasUnconfirmedManagedRuntimeCompletion\([\s\S]*runtime\?\.available,[\s\S]*runtimeSetup\?\.phase/u);
  assert.match(shellSource, /runtimeSetupCompletionUnconfirmed[\s\S]*\? undefined[\s\S]*: runtimeSetup\?\.phase/u);
  assert.match(shellSource, /runtimeSetup\?\.phase === "failed"[\s\S]*\|\| runtimeSetupCompletionUnconfirmed[\s\S]*\? "runtime\.setup\.retry"/u);
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
    "Stopping advanced local scan-tool setup",
    "Current setup step is stopping",
    "正在停止進階本機掃描工具設定",
    "目前設定步驟正在停止",
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
