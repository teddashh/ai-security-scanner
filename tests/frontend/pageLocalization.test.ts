import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { displayTechnicalDetail } from "../../src/pages/pageTechnicalDetails.ts";
import { assertInsideDisclosure } from "./sourceRegions.ts";

const readPage = (name: string) => readFile(new URL(`../../src/pages/${name}`, import.meta.url), "utf8");

const pages = ["ProgressPage.tsx", "ExportPage.tsx", "VerificationPage.tsx"] as const;

test("progress, export, and verification pages use page-local bilingual copy and locale formatters", async () => {
  for (const page of pages) {
    const source = await readPage(page);
    assert.match(source, /useI18n\(\)/u, `${page} should use the shared locale context`);
    assert.match(source, /\ben:\s*"/u, `${page} should include English copy`);
    assert.match(source, /\bzhTW:\s*"/u, `${page} should include Traditional Chinese copy`);
    assert.doesNotMatch(
      source,
      /import\s*\{[^}]*formatDate(?:Time)?[^}]*\}\s*from\s*"\.\.\/lib"/su,
      `${page} should not use a fixed-locale date formatter`,
    );
  }
});

test("non-scan actions use truthful saved-state toasts while scan execution keeps progress copy", async () => {
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const mapStart = app.indexOf("const nonExecutionActionToastCopy");
  const mapEnd = app.indexOf("const scanStartIssueCopy", mapStart);
  const copyMap = app.slice(mapStart, mapEnd);
  assert.ok(mapStart >= 0 && mapEnd > mapStart);

  for (const key of [
    '"attach-workspace"',
    "scope:",
    '"archive-case"',
    '"finding-workflow"',
    '"finding-group"',
    '"finding-ungroup"',
    '"connect-source"',
    "discovery:",
  ]) assert.ok(copyMap.includes(key), key);

  for (const [english, traditionalChinese] of [
    ["Project prepared locally", "專案已在本機準備完成"],
    ["Private copy verified. Review the checks, then start.", "私密副本已驗證；請檢查掃描項目後開始。"],
    ["Project was not prepared", "專案尚未準備完成"],
    ["Scan access saved", "掃描許可已儲存"],
    ["The exact target and limits are saved.", "確切目標與限制已儲存。"],
    ["Change saved", "變更已儲存"],
  ] as const) {
    assert.ok(copyMap.includes(english), english);
    assert.ok(copyMap.includes(traditionalChinese), traditionalChinese);
  }

  assert.doesNotMatch(copyMap, /no scan started|尚未開始掃描/u);

  assert.doesNotMatch(copyMap, /"start-scan"|\brescan:|"resume-scan"/u);
  const actionStart = app.indexOf("const executeAction = async");
  const actionEnd = app.indexOf("const runAction = async", actionStart);
  const action = app.slice(actionStart, actionEnd);
  assert.match(action, /nonExecutionActionToastCopy\[key as keyof typeof nonExecutionActionToastCopy\]/u);
  assert.match(action, /nonExecutionCopy\?\.acceptedTitle \?\? \{ en: "Local work started"/u);
  assert.match(action, /nonExecutionCopy\?\.acceptedDetail \?\? \{ en: "Open Scan progress to follow each scanner\."/u);
  assert.match(action, /nonExecutionCopy\?\.failedTitle \?\? \{ en: "Local action failed"/u);
});

test("all progress controls remain wired while raw scanner status stays in details", async () => {
  const source = await readPage("ProgressPage.tsx");
  for (const callback of ["onStart", "onPause", "onResume", "onCancel"]) {
    assert.match(source, new RegExp(`void ${callback}\\(`, "u"));
  }
  // The claim in this test's name is containment: raw scanner status stays
  // behind a disclosure instead of being pushed at a non-expert reader. A
  // `[\s\S]*` span between the open and close tags cannot check that -- see
  // `sourceRegions.ts`.
  // Named in rendered form. The bare field names also appear in phase-to-copy
  // logic outside any disclosure, which is correct and would make the
  // every-occurrence rule below unsatisfiable.
  for (const raw of [
    "displayTechnicalDetail(engine.phase)",
    "displayTechnicalDetail(engine.errorCode)",
    "displayTechnicalDetail(engine.message)",
    "checkpoint?.lastError)",
  ]) {
    assertInsideDisclosure(source, "page-technical-details", raw);
  }
  assert.doesNotMatch(source, /<code>error:\s*\{engine\.errorCode\}/u);
  assert.doesNotMatch(source, /<small>\{engine\.category\}[\s\S]*\{engine\.version\}<\/small>/u);
  assert.match(source, /Status: not run\./u);
  assert.match(source, /狀態：未執行。/u);
});

test("scan readiness only blocks unsafe empty runs and sends each fix to the useful screen", async () => {
  const progress = await readPage("ProgressPage.tsx");
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");

  assert.match(progress, /const canStart = !terminalExactLocalhostQuickScan[\s\S]*canStartPreparedScan\([\s\S]*action=\{starting \? \([\s\S]*\) : canStart \?/u);
  assert.doesNotMatch(progress, /action=\{starting \? \([\s\S]*\) : readiness\?\.ready \?/u);
  assert.match(progress, /readiness\?\.nextStep === "scanner_setup"[\s\S]*copy\.setupTools/u);
  assert.match(progress, /provider_capability_unavailable:[\s\S]*action: copy\.reconnectCloud/u);
  assert.match(progress, /One quick setup, then scan/u);
  assert.match(progress, /先完成一次設定，就可以開始掃描/u);
  assert.match(progress, /Connect the cloud account you want to scan/u);
  assert.match(progress, /請先連接你要掃描的雲端帳號/u);
  assert.match(progress, /Scan did not start/u);
  assert.match(progress, /掃描沒有開始/u);
  assert.match(progress, /Download diagnostic log/u);
  assert.match(progress, /下載診斷紀錄/u);

  const packagedBranchStart = app.indexOf("if (isPackagedComponentBlocker(scanReadiness?.blockerCode))");
  const runtimeBranchStart = app.indexOf("if (isScannerSetupBlocker(scanReadiness?.blockerCode)", packagedBranchStart);
  const retryBranchStart = app.indexOf("if (isReadinessRetryBlocker(scanReadiness?.blockerCode)", runtimeBranchStart);
  assert.ok(packagedBranchStart >= 0 && runtimeBranchStart > packagedBranchStart && retryBranchStart > runtimeBranchStart);
  assert.match(app.slice(packagedBranchStart, runtimeBranchStart), /navigate\("start"\);[\s\S]*return;/u);
  assert.doesNotMatch(app.slice(packagedBranchStart, runtimeBranchStart), /setupManagedRuntime/u);
  assert.match(app.slice(runtimeBranchStart, retryBranchStart), /navigate\("start"\);[\s\S]*setupManagedRuntime\(\)/u);
  assert.match(app, /isReadinessRetryBlocker\(scanReadiness\?\.blockerCode\) \|\| scanReadiness\?\.nextStep === "retry"[\s\S]*retryScanReadiness\(currentCaseId\)/u);
  assert.match(app, /coverageSetupFocusFor\(scanReadiness\?\.blockerCode\)[\s\S]*navigate\("coverage"\)/u);
  assert.match(app, /focusSetup=\{coverageSetupFocusFor\(scanReadiness\?\.blockerCode\)\}/u);
  assert.match(app, /scanReadiness\?\.nextStep === "cases" \? "cases" : "coverage"/u);
});

test("desktop readiness states stay typed and never render backend messages", async () => {
  const types = await readFile(new URL("../../src/types.ts", import.meta.url), "utf8");
  const progress = await readPage("ProgressPage.tsx");

  for (const value of [
    "runtime_unavailable",
    "provider_connection_required",
    "provider_capability_required",
    "provider_review_required",
    "provider_check_unavailable",
    "provider_source_required",
    "provider_capability_unavailable",
    "provider_source_ambiguous",
    "provider_authorization_binding_mismatch",
    "provider_target_binding_mismatch",
    "provider_preflight_unavailable",
    "execution_input_unavailable",
    "scanner_setup_required",
    "execution_check_unavailable",
    "workspace_snapshot_unavailable",
    "egress_gateway_unavailable",
    "engine_execution_contract_invalid",
    "passive_source_unavailable",
    "captured_evidence_unavailable",
    "execution_preflight_unavailable",
    "retry",
  ]) {
    assert.match(types, new RegExp(`\\| "${value}"`, "u"));
  }
  assert.match(progress, /copy\.readiness\[readiness\.blockerCode\]/u);
  assert.doesNotMatch(progress, /readiness\.(?:message|detail|error)/u);
});

test("cloud readiness failures use distinct plain-language fixes without exposing backend text", async () => {
  const progress = await readPage("ProgressPage.tsx");
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");

  const presentations = [
    ["provider_source_required", "copy.connectCloud"],
    ["provider_capability_unavailable", "copy.reconnectCloud"],
    ["provider_source_ambiguous", "copy.chooseConnection"],
    ["provider_authorization_binding_mismatch", "copy.reviewConnection"],
    ["provider_target_binding_mismatch", "copy.reviewTarget"],
    ["provider_preflight_unavailable", "copy.checkAgain"],
  ] as const;
  for (const [blocker, action] of presentations) {
    assert.match(progress, new RegExp(`${blocker}:[\\s\\S]*?action: ${action.replace(".", "\\.")}`, "u"));
    assert.match(app, new RegExp(`${blocker}:`, "u"));
  }

  const presentationStart = progress.indexOf("const readinessPresentation");
  const capabilityStart = progress.indexOf("provider_capability_unavailable:", presentationStart);
  const ambiguousStart = progress.indexOf("provider_source_ambiguous:", capabilityStart);
  assert.match(progress.slice(capabilityStart, ambiguousStart), /reconnectCloud/u);
  assert.doesNotMatch(progress.slice(ambiguousStart), /action: copy\.reconnectCloud/u);
  assert.match(progress, /Cloud readiness check stopped/u);
  assert.match(progress, /雲端準備狀態檢查已停止/u);
  assert.doesNotMatch(progress, /Cloud readiness check incomplete/u);
  assert.doesNotMatch(progress, /No scan started|掃描尚未開始/u);
  assert.doesNotMatch(progress, /readiness\.(?:message|detail|error)/u);
});

test("execution readiness failures have distinct bilingual fixes and typed destinations", async () => {
  const progress = await readPage("ProgressPage.tsx");
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const presentationStart = progress.indexOf("const readinessPresentation");
  const presentationEnd = progress.indexOf("const engineStates", presentationStart);
  const presentations = progress.slice(presentationStart, presentationEnd);

  for (const [blocker, action] of [
    ["no_runnable_authorized_targets", "copy.getLatestInstaller"],
    ["workspace_snapshot_unavailable", "copy.chooseLocalInputAgain"],
    ["passive_source_unavailable", "copy.reconnectReadOnlySource"],
    ["egress_gateway_unavailable", "copy.getLatestInstaller"],
    ["engine_execution_contract_invalid", "copy.getLatestInstaller"],
    ["execution_preflight_unavailable", "copy.checkAgain"],
    ["captured_evidence_unavailable", "copy.startFreshScan"],
  ] as const) {
    assert.match(presentations, new RegExp(`${blocker}:[\\s\\S]*?action: ${action.replace(".", "\\.")}`, "u"));
    assert.match(app, new RegExp(`${blocker}:`, "u"));
  }

  for (const [english, traditionalChinese] of [
    ["Get the scan tools for this check", "取得這項檢查需要的掃描工具"],
    ["Choose the local files again", "請重新選擇本機檔案"],
    ["Reconnect the saved data source", "請重新連接已保存的資料來源"],
    ["Restore one installed scan component", "恢復一項安裝元件"],
    ["Final readiness check stopped", "最後的準備狀態檢查已停止"],
    ["Open the saved results", "開啟已保存的結果"],
  ] as const) {
    assert.ok(progress.includes(english), english);
    assert.ok(progress.includes(traditionalChinese), traditionalChinese);
  }

  for (const [english, traditionalChinese] of [
    ["Applicable scan tool unavailable", "適用的掃描工具無法使用"],
    ["The saved local copy is missing or changed", "掃描用的本機副本已遺失或有變更"],
    ["Installed scan component missing or changed", "隨附的掃描元件已遺失或變更"],
    ["Required installed scan component missing or out of date", "必要的隨附掃描元件已遺失或過期"],
    ["The saved read-only data source is missing or changed", "已保存的唯讀資料來源已遺失或有變更"],
    ["Final readiness check stopped", "最後的準備狀態檢查已停止"],
    ["Saved results needed to continue are missing or changed", "續跑所需的已保存結果已遺失或有變更"],
    ["This saved check no longer matches its original target plan", "這項已保存的檢查已無法對應原本的目標計畫"],
  ] as const) {
    assert.ok(app.includes(english), english);
    assert.ok(app.includes(traditionalChinese), traditionalChinese);
  }

  assert.match(
    app,
    /as const satisfies Partial<Record<ScanReadinessBlocker \| "resume_release_incompatible" \| "resume_work_plan_invalid", BilingualText>>/u,
  );
  assert.match(app, /const startScannerSetupBlocker = scanReadiness[\s\S]*scanReadiness\.caseId === currentCaseId[\s\S]*isScannerSetupBlocker/u);
  assert.match(app, /scannerSetupBlocker=\{startScannerSetupBlocker\}/u);
  assert.match(progress, /satisfies Record<ScanReadinessBlocker, BilingualText>/u);
  assert.match(progress, /copy\.readiness\[readiness\.blockerCode\] \?\? copy\.readinessUnavailableDescription/u);
  assert.equal(
    [...progress.matchAll(/readiness && !readiness\.ready && readiness\.blockerCode/g)].length,
    1,
    "scan history keeps one typed blocker notice while the no-run screen uses its focused empty state",
  );
  const actionStart = app.indexOf("const executeAction = async");
  const actionEnd = app.indexOf("const runAction = async", actionStart);
  assert.doesNotMatch(app.slice(actionStart, actionEnd), /detail:\s*result\.data\.message/u);
  assert.doesNotMatch(progress, /readiness\.(?:message|detail|error)/u);
});

test("missing captured evidence never offers resume or setup and starts fresh only after a click", async () => {
  const progress = await readPage("ProgressPage.tsx");
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");

  for (const copy of [
    "Start a new scan for fresh results",
    "開始新的掃描取得新結果",
    "Saved results or evidence needed to continue are missing or changed. Start a new scan",
    "續跑所需的已保存結果或證據已遺失或變更；請開始新的掃描",
  ]) {
    assert.ok(progress.includes(copy) || app.includes(copy), copy);
  }

  assert.match(progress, /startFreshScan = !readinessCheckFailed && isCapturedEvidenceBlocker/u);
  assert.match(progress, /if \(startFreshScan\) \{[\s\S]*requestStart\(\);[\s\S]*return;[\s\S]*\}[\s\S]*onFixSetup\(\)/u);
  assert.match(progress, /const canResume = !startFreshScan &&/u);
  assert.match(progress, /readiness\.nextStep !== "progress" \|\| startFreshScan/u);
  assert.match(progress, /readiness\?\.nextStep === "progress" && !startFreshScan/u);
  const presentationStart = progress.indexOf("const readinessPresentation");
  const capturedStart = progress.indexOf("captured_evidence_unavailable:", presentationStart);
  const capturedEnd = progress.indexOf("execution_preflight_unavailable:", capturedStart);
  const capturedPresentation = progress.slice(capturedStart, capturedEnd);
  assert.match(capturedPresentation, /action: copy\.startFreshScan/u);
  assert.doesNotMatch(capturedPresentation, /copy\.(?:finishSetup|setupTools|checkAgain)/u);

  const actionStart = app.indexOf("const executeAction = async");
  const actionEnd = app.indexOf("const runAction = async", actionStart);
  assert.match(app, /onResume=\{\(runId\) => runAction\("resume-scan"/u);
  assert.match(app.slice(actionStart, actionEnd), /preflightCode[\s\S]*scanStartIssueCopy\[preflightCode\]/u);
  assert.doesNotMatch(app.slice(actionStart, actionEnd), /detail:\s*result\.data\.message/u);
});

test("release-incompatible resume explains the next step without exposing native error text", async () => {
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");

  for (const copy of [
    "This unfinished scan was created by a different app release. Start a new scan with this release.",
    "這個未完成的掃描由不同版本的應用程式建立；請使用目前版本開始新的掃描。",
  ]) {
    assert.ok(app.includes(copy), copy);
  }

  assert.match(app, /resume_release_incompatible:\s*\{/u);
  const actionStart = app.indexOf("const executeAction = async");
  const actionEnd = app.indexOf("const runAction = async", actionStart);
  const action = app.slice(actionStart, actionEnd);
  assert.match(action, /result\.data\.message\.includes\(`scan_preflight:\$\{code\}`\)/u);
  assert.match(action, /scanStartIssueCopy\[preflightCode\]/u);
  assert.doesNotMatch(action, /detail:\s*result\.data\.message/u);
});

test("progress keeps scanner implementation data below the first layer", async () => {
  const source = await readPage("ProgressPage.tsx");
  const ledger = source.indexOf('<div className="engine-state-ledger"');
  const runDetails = source.lastIndexOf('<details className="page-technical-details page-technical-details--guide">', ledger);
  const runDetailsEnd = source.indexOf("</details>", ledger);
  assert.ok(runDetails >= 0 && ledger > runDetails && runDetailsEnd > ledger, "the scanner-state ledger should be inside scan details");

  const visibleMap = source.indexOf("{visibleEngineRuns.map((engine) => {");
  const attention = source.indexOf("const showEngineAttention", visibleMap);
  const identity = source.indexOf('<div className="engine-row__identity">', visibleMap);
  const progress = source.indexOf('<div className="engine-row__progress">', identity);
  assert.ok(visibleMap >= 0 && attention > visibleMap && identity > attention && progress > identity);
  assert.doesNotMatch(source.slice(identity, progress), /engine\.engineName|rawArtifactCount|assetIds\.length/u);
  assert.match(source.slice(attention, progress), /engine\.status !== "completed"[\s\S]*showEngineAttention && <small>\{text\(engineNextStepFor\(engine\)\)\}/u);
  assert.doesNotMatch(source, /copy\.checkLabel/u);

  const engineDetails = source.indexOf('<details className="page-technical-details">', progress);
  const engineResult = source.indexOf('<div className="engine-row__result">', engineDetails);
  assert.ok(engineDetails > progress && engineResult > engineDetails);
  assert.match(source.slice(engineDetails, engineResult), /engine\.engineName[\s\S]*engine\.assetIds\.length[\s\S]*engine\.rawArtifactCount/u);
  assert.doesNotMatch(source.slice(engineResult, source.indexOf('<details className="engine-provenance">', engineResult)), /rawArtifactCount|assetIds\.length/u);
  assert.doesNotMatch(source, /<code>\{run\.id\}<\/code>/u);
});

test("progress separates completed, remaining, and attention-needed assets and checks", async () => {
  const source = await readPage("ProgressPage.tsx");
  assert.match(source, /Assets · Fully checked \{completed\} · Remaining \{remaining\} · Need attention \{attention\}/u);
  assert.match(source, /資產 · 已完整檢查 \{completed\} · 尚待完成 \{remaining\} · 需要處理 \{attention\}/u);
  assert.match(source, /Checks · Completed \{completed\} · Remaining \{remaining\} · Need attention \{attention\}/u);
  assert.match(source, /檢查 · 已完成 \{completed\} · 尚待完成 \{remaining\} · 需要處理 \{attention\}/u);
  assert.doesNotMatch(source, /\{covered\} of \{total\} checks have reported/u);
  assert.doesNotMatch(source, /\{covered\}／\{total\} 項檢查已有結果/u);
  assert.match(source, /completedAssetCount = Math\.min\(selectedRun\.totalAssetCount, selectedRun\.coveredAssetCount\)/u);
  assert.match(source, /total: formatNumber\(selectedRun\.totalAssetCount\)/u);
});

test("readiness errors remain retryable and runtime setup receives focus", async () => {
  const progress = await readPage("ProgressPage.tsx");
  const start = await readPage("StartPage.tsx");
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");

  assert.match(progress, /readinessCheckFailed[\s\S]*copy\.checkAgain/u);
  assert.match(progress, /readiness \|\| readinessCheckFailed[\s\S]*onClick=\{onFixSetup\}/u);
  assert.match(app, /setScanReadinessErrorCaseId\(readinessCaseId\)/u);
  assert.match(app, /setScanReadinessErrorCaseId\(caseId\)/u);
  assert.match(app, /scanReadinessRequestGeneration = useRef\(0\)/u);
  assert.match(app, /\+\+scanReadinessRequestGeneration\.current/u);
  assert.match(app, /isCurrentScanReadinessResponse\([\s\S]*readiness\.data\.caseId/u);
  assert.match(app, /isCurrentScanReadinessRequest\(scanReadinessRequestGeneration\.current, readinessRequestGeneration\)[\s\S]*setScanReadinessErrorCaseId/u);
  assert.match(app, /scanReadinessErrorCaseId === currentCaseId[\s\S]*retryScanReadiness\(currentCaseId\)/u);
  assert.match(app, /setRuntimeSetupFocusKey\(\(key\) => key \+ 1\)[\s\S]*navigate\("start"\)/u);
  assert.match(start, /id="start-page-runtime-setup"[\s\S]*tabIndex=\{-1\}/u);
  assert.match(start, /getElementById\("start-page-runtime-setup"\)[\s\S]*\.focus\([\s\S]*\.scrollIntoView\(/u);
  for (const copy of [
    "Scan readiness unavailable",
    "掃描準備狀態無法取得",
    "Check readiness again.",
    "請重新檢查準備狀態。",
  ]) assert.ok(progress.includes(copy), copy);
});

test("progress aggregates empty, skipped, and shared-infrastructure attempts", async () => {
  const progress = await readPage("ProgressPage.tsx");
  assert.match(progress, /blocked \? 1 : visibleWorkCount/u);
  assert.match(progress, /selectedRun\.engineRuns\.filter\(\(engine\) => engine\.status !== "not_executed"\)/u);
  assert.match(progress, /skipped && !blocked/u);
  assert.match(progress, /skippedChecksNextStepFor\(skipped\.reasonCodes\)/u);
  assert.doesNotMatch(progress, /<small>\{skipped\.reasonCodes/u);
  assert.match(progress, /sharedInfrastructureFailure[\s\S]*aggregateTechnicalRecords/u);
  assert.match(progress, /aggregateTechnicalRecords[\s\S]*engine\.engineName[\s\S]*engine\.errorCode[\s\S]*engine\.message/u);
  assert.match(progress, /historyBlocked \|\| historySharedFailure \? text\(copy\.historyNotStarted\)/u);
});

test("progress has a bilingual event log before and during every scan route", async () => {
  const progress = await readPage("ProgressPage.tsx");
  const diagnostics = await readFile(new URL("../../src/scanDiagnostics.ts", import.meta.url), "utf8");
  const adapter = await readFile(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");

  for (const copy of [
    "See exactly where your scan is",
    "清楚看見掃描進行到哪裡",
    "What is happening now",
    "現在正在做什麼",
    "Last progress update",
    "最後一次進度更新",
    "Event log before the scan starts",
    "掃描前事件紀錄",
    "Download redacted technical log",
    "下載已遮蔽的技術紀錄",
  ]) assert.ok(progress.includes(copy), copy);

  const noRunStart = progress.indexOf("if (!selectedRun)");
  const noRunEnd = progress.indexOf("const runMeta", noRunStart);
  const noRun = progress.slice(noRunStart, noRunEnd);
  assert.match(noRun, /readiness\?\.checkedAt/u);
  assert.match(progress, /buildReadinessDiagnostic/u);
  assert.match(noRun, /readiness\?\.blockerCode/u);
  assert.match(noRun, /scan-activity__log/u);
  assert.doesNotMatch(noRun, /blockerTitle|blockerDescription|readinessUnavailableDescription|readyToStartBody/u);
  assert.match(progress, /activity\.activeCheckNames/u);
  assert.match(diagnostics, /redacted-preflight-diagnostic\/v1/u);
  assert.match(adapter, /checked_at/u);

  const currentActivity = progress.indexOf('<div className="scan-activity__current"', noRunEnd);
  const technicalChecks = progress.indexOf('<details className="page-technical-details', currentActivity);
  assert.ok(currentActivity > noRunEnd && technicalChecks > currentActivity);
  assert.doesNotMatch(progress.slice(currentActivity, technicalChecks), /engine\.message|checkpoint\?\.lastError|engine\.assetIds/u);
  for (const copy of [
    "Scan requested",
    "已提出掃描要求",
    "checks stopped before completion",
    "項檢查在完成前停止",
    "Scan stopped",
    "掃描已停止",
    "Private scan connection failed",
    "專用掃描連線失敗",
  ]) assert.ok(progress.includes(copy), copy);
  assert.doesNotMatch(progress, /checks have finished|Scan finished/u);
});

test("pre-scanner failures separate frozen authorization from runtime scope and offer a retry", async () => {
  const progress = await readPage("ProgressPage.tsx");
  const english = await readFile(new URL("../../src/i18n/locales/en.ts", import.meta.url), "utf8");
  const traditionalChinese = await readFile(new URL("../../src/i18n/locales/zh-TW.ts", import.meta.url), "utf8");

  for (const copy of [
    "Target and permission plan",
    "目標與權限計畫",
    "Frozen for this run",
    "已為這一輪固定",
    "Scanner runtime scope",
    "掃描執行環境範圍",
    "Not reached",
    "未進行到這一步",
    "Retry stopped checks",
    "重試已停止的檢查",
  ]) assert.ok(progress.includes(copy), copy);
  assert.match(progress, /engine\.scopeContractBound[\s\S]*checkpoint\.scopeBound/u);
  assert.match(progress, /engineRecoveryLabelFor\(engine\)/u);
  assert.doesNotMatch(progress, /Can continue where it stopped|Scope lock|Not created/u);
  assert.doesNotMatch(english, /You can continue from the last saved point/u);
  assert.doesNotMatch(traditionalChinese, /你可以從最後保存的進度繼續/u);
});

test("export preview, export, and both verification paths remain wired", async () => {
  const [app, findings] = await Promise.all([
    readFile(new URL("../../src/App.tsx", import.meta.url), "utf8"),
    readPage("FindingsPage.tsx"),
  ]);
  assert.match(app, /<FindingsPage[\s\S]*onOpenExport=\{\(runId\) => \{[\s\S]*setSelectedReportRunId\(runId\);[\s\S]*navigate\("export"\);/u);
  assert.match(findings, /onClick=\{\(\) => onOpenExport\(latestRun\.id\)\}/u);
  assert.match(findings, /Save or share report/u);
  assert.match(findings, /保存或分享報告/u);

  const source = await readPage("ExportPage.tsx");
  for (const callback of ["onPreview", "onExport", "onVerify", "onVerifyReceived"]) {
    assert.match(source, new RegExp(`${callback}\\(`, "u"));
  }
  assert.doesNotMatch(source, /\{previewError\s*\?\?/u);
  assertInsideDisclosure(source, "page-technical-details", "{previewError}");
  assert.match(source, /setPreviewRequest\(\(request\) => request \+ 1\)/u);
  assert.match(
    source,
    /id="export-preview-status"[\s\S]*role=\{rawSourcesAttached \? "alert" : "status"\}[\s\S]*aria-live=\{rawSourcesAttached \? "assertive" : "polite"\}[\s\S]*aria-atomic="true"/u,
  );
  assert.match(source, /aria-describedby="export-preview-status"/u);

  const verification = await readPage("VerificationPage.tsx");
  for (const callback of ["onSelectBaseline", "onStartRescan", "onOpenFinding"]) {
    assert.match(verification, new RegExp(`${callback}\\(`, "u"));
  }
  assertInsideDisclosure(verification, "page-technical-details", "displayTechnicalDetail(issue.detail)");
  assertInsideDisclosure(verification, "page-technical-details", "verificationDiffExplanation(locale, item)");
  assert.doesNotMatch(verification, /<p>\{item\.explanation\}<\/p>/u);
  assert.match(verification, /Affected findings stay under Verification incomplete and are not counted as fixed/u);
  assert.match(verification, /受影響的問題會保留在「驗證未完成」，不會算成已修復/u);
  assert.match(verification, /isOnlyMappingVersionDrift\(completenessIssues\)/u);
  assert.match(verification, /Affected checks completed in both scans with different control-mapping catalog versions/u);
  assert.match(verification, /Affected scan tools: \{count\}/u);
  assert.match(verification, /Scanner\/target comparisons needing attention: \{count\}/u);
  assert.doesNotMatch(verification, /not a security-finding count/u);
  assert.doesNotMatch(verification, /\{count\} technical scanner\/target comparison limitations were recorded/u);
  assert.match(verification, /mappingVersionDriftOnlyForFinding \? mappingDiffSummary/u);
});

test("active scans stay in Progress instead of opening defensive interim surfaces", async () => {
  const findings = await readPage("FindingsPage.tsx");
  for (const phrase of [
    "Scan in progress",
    "掃描進行中",
    "Continue in Scan progress.",
    "請回到「掃描進度」繼續。",
  ]) assert.ok(findings.includes(phrase), phrase);
  assert.match(findings, /activeRunStatuses\.has\(latestRun\.status\)/u);
  assert.match(findings, /activeRun[\s\S]*onOpenProgress/u);
  assert.doesNotMatch(findings, /interim results|暫時結果|Still updating|仍在更新/u);

  const exportPage = await readPage("ExportPage.tsx");
  for (const phrase of [
    "Scan in progress",
    "掃描進行中",
    "Export opens after this scan finishes.",
    "本輪掃描完成後即可匯出。",
  ]) assert.ok(exportPage.includes(phrase), phrase);
  assert.match(exportPage, /workspaceExportRevision/u);
  assert.match(exportPage, /if \(activeRun\)[\s\S]*href="#progress"/u);
  assert.doesNotMatch(exportPage, /Interim export|暫時報告|createInterimExport/u);
});

test("setup prerequisites and missing-source states use direct product language", async () => {
  const cases = await readPage("CasesPage.tsx");
  const coverage = await readPage("CoveragePage.tsx");
  const findings = await readPage("FindingsPage.tsx");
  const provider = await readFile(
    new URL("../../src/components/ProviderAuthorizationPanel.tsx", import.meta.url),
    "utf8",
  );

  for (const phrase of [
    "Start requires exact internal-target confirmation",
    "Active testing requires separate authorization",
    "Candidate list status: no connected source",
    "Sources without data: {count}",
    "No problems shown; source data missing",
    "Cleanup records requiring action",
    "Temporary access expiry pending",
  ]) assert.ok(`${cases}\n${coverage}\n${findings}\n${provider}`.includes(phrase), phrase);

  assert.doesNotMatch(cases, /you must confirm access|you must separately confirm|waiting for a connected source/iu);
  assert.doesNotMatch(coverage, /Sources still needing data|source is still missing/iu);
  assert.doesNotMatch(findings, /sources still need data|Sources still needing usable information/iu);
  assert.doesNotMatch(provider, /may need your attention|Earlier setup work still has|Waiting for temporary access to expire/iu);
});

test("primary product copy has no delayed or repeat-failure disclaimers", async () => {
  const inspected = (await Promise.all([
    "../../src/App.tsx",
    "../../src/localhostTcpPresentation.ts",
    "../../src/scanLifecycleDisposition.ts",
    "../../src/scanPresentation.ts",
    "../../src/scanRequestOutcomePresentation.ts",
    "../../src/settingsRuntimePresentation.ts",
    "../../src/components/ProviderAuthorizationPanel.tsx",
    "../../src/components/RuntimeSetupAssistant.tsx",
    "../../src/pages/CasesPage.tsx",
    "../../src/pages/CoveragePage.tsx",
    "../../src/pages/ExportPage.tsx",
    "../../src/pages/FindingsPage.tsx",
    "../../src/pages/ProgressPage.tsx",
    "../../src/pages/SettingsPage.tsx",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")))).join("\n");

  assert.doesNotMatch(
    inspected,
    /if it (?:stops|fails) again|for support|when ready|when you are ready|when you want|not the complete set|next person knows|not checked yet|no (?:scan projects|scan results|checks|observation|reports saved) yet/iu,
  );
  assert.doesNotMatch(
    inspected,
    /若再次(?:停止|失敗)|以便排查|準備好(?:時|後)|之後仍可再|稍後逐項授權|讓接手者一看就懂|並非完整結果|還沒有掃描專案|尚無觀察結果|尚未產生掃描結果/u,
  );
});

test("count copy stays grammatical when exactly one item is shown", async () => {
  const findings = await readPage("FindingsPage.tsx");
  const progress = await readPage("ProgressPage.tsx");
  const cases = await readPage("CasesPage.tsx");
  const exports = await readPage("ExportPage.tsx");
  const coverage = await readPage("CoveragePage.tsx");

  for (const phrase of [
    "Problems in the complete list: {count}",
    "Evidence records: {count}",
    "Assets: {count}",
    "Decisions: {count}",
  ]) assert.ok(findings.includes(phrase), phrase);
  for (const phrase of ["Files: {count}", "Saved results: {count}"]) {
    assert.ok(progress.includes(phrase), phrase);
  }
  assert.ok(cases.includes("Assets: {assets} · Saved results: {findings}"));
  assert.ok(exports.includes("Original evidence files included: {count}"));
  assert.ok(coverage.includes("Exact CIDR scope — usable addresses: {addresses}; ports: {ports}; connection checks: {probes}."));
  assert.ok(coverage.includes("Pacing floor: {effectiveRate}/s; requested rate: {requestedRate}/s; concurrency: {concurrency}."));
  assert.ok(coverage.includes("Allowed IDs: {count}"));
  assert.ok(progress.includes("Final outcomes: {done} of {total}"));

  const providerAuthorization = await readFile(new URL("../../src/components/ProviderAuthorizationPanel.tsx", import.meta.url), "utf8");
  const appShell = await readFile(new URL("../../src/components/AppShell.tsx", import.meta.url), "utf8");
  const runtimeSetup = await readFile(new URL("../../src/components/RuntimeSetupAssistant.tsx", import.meta.url), "utf8");
  assert.ok(providerAuthorization.includes("Cleanup items finished: {completed} of {total}"));
  assert.match(appShell, /value === 1 \? "common\.byte" : "common\.bytes"/u);
  assert.match(runtimeSetup, /value === 1 \? "byte" : "bytes"/u);

  const inspected = `${findings}\n${progress}\n${cases}\n${exports}\n${coverage}`;
  for (const brokenTemplate of [
    "{count} findings",
    "{count} problems",
    "{assets} assets · {findings} findings",
    "{count} evidence records",
    "{count} files",
  ]) assert.ok(!inspected.includes(brokenTemplate), brokenTemplate);
});

test("export leads with recipient choices and keeps file standards and integrity data in details", async () => {
  const source = await readPage("ExportPage.tsx");
  const normalizedSource = source.replaceAll("\r\n", "\n");
  const cardRendererStart = normalizedSource.indexOf("const renderFormatCard");
  const cardRendererEnd = normalizedSource.indexOf("\n  };\n\n  if (activeRun)", cardRendererStart);
  const cardRenderer = normalizedSource.slice(cardRendererStart, cardRendererEnd);
  assert.ok(cardRendererStart >= 0 && cardRendererEnd > cardRendererStart);
  assert.doesNotMatch(cardRenderer, /item\.extension/u);
  assert.match(source, /\{primaryFormats\.map\(renderFormatCard\)\}/u);
  assert.match(source, /<details className="page-secondary-feature export-advanced-formats">[\s\S]*\{advancedFormats\.map\(renderFormatCard\)\}[\s\S]*<\/details>/u);

  const historyRow = source.indexOf('<article key={item.id} className="export-row">');
  const technicalDetails = source.indexOf('<details className="page-technical-details export-row__technical">', historyRow);
  const verifyButton = source.indexOf("onClick={() => item.path", technicalDetails);
  assert.ok(historyRow >= 0 && technicalDetails > historyRow && verifyButton > technicalDetails);
  const firstLayer = source.slice(historyRow, technicalDetails);
  assert.doesNotMatch(firstLayer, /item\.fileName|item\.sha256|signatureState|includesRawEvidence/u);
  assert.match(source.slice(technicalDetails, verifyButton), /item\.fileName[\s\S]*item\.sha256[\s\S]*signatureState[\s\S]*includesRawEvidence/u);
});

test("scan projects keep diagnostic counts, run IDs, and legal workflow in optional details", async () => {
  const source = await readPage("CasesPage.tsx");
  const outcomeMetrics = source.indexOf('<section className="metrics-grid page-outcome-metrics"');
  const diagnosticDetails = source.indexOf('<details className="page-technical-details page-technical-details--guide">', outcomeMetrics);
  assert.ok(outcomeMetrics >= 0 && diagnosticDetails > outcomeMetrics);
  assert.doesNotMatch(source.slice(outcomeMetrics, diagnosticDetails), /unknownMetric|incompleteMetric/u);
  assert.match(source.slice(diagnosticDetails, source.indexOf("</details>", diagnosticDetails)), /unknownMetric[\s\S]*incompleteMetric/u);

  assert.match(source, /<p>\{text\(pageCopy\.interrupted\)\}<\/p>[\s\S]*<details className="page-technical-details">[\s\S]*pageCopy\.interruptedDetails, \{ id: latestRun\.id \}/u);
  assert.match(source, /<details className="page-secondary-feature page-secondary-feature--workflow">[\s\S]*<section className="workflow-strip"[\s\S]*<\/details>/u);

  assert.match(source, /artifactDeleteConfirmation !== `DELETE \$\{artifactCleanupPlan\.caseId\}`/u);
  assert.match(source, /deleteConfirmation !== assessmentCase\.name/u);
  assert.match(source, /onDeleteArtifacts\(artifactDeleteConfirmation\)/u);
  assert.match(source, /onDelete\(assessmentCase\.id, deleteConfirmation\)/u);
});

test("opt-in page diagnostics are bounded and redact common credential shapes", () => {
  const detail = displayTechnicalDetail([
    "client_secret=do-not-display",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz.123456",
    "access_token: also-secret",
    "Authorization: Basic dXNlcjpwYXNzd29yZA==",
    "api_key=api-secret",
    "x-api-key: header-secret",
    "AKIAABCDEFGHIJKLMNOP",
    "-----BEGIN PRIVATE KEY-----\nprivate-secret-material\n-----END PRIVATE KEY-----",
    "x".repeat(5_000),
  ].join("\n"));

  assert.ok(detail);
  assert.doesNotMatch(detail, /do-not-display|also-secret|dXNlcjpwYXNzd29yZA|api-secret|header-secret|AKIAABCDEFGHIJKLMNOP|private-secret-material/u);
  assert.match(detail, /\[REDACTED\]/u);
  assert.ok(Array.from(detail).length <= 4_097);
});
