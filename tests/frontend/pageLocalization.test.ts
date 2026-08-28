import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { displayTechnicalDetail } from "../../src/pages/pageTechnicalDetails.ts";

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
    ["Private copy verified; no scan started.", "私密副本已驗證；尚未開始掃描。"],
    ["Project was not prepared", "專案尚未準備完成"],
    ["Scan access saved", "掃描許可已儲存"],
    ["The exact target and limits are saved; no scan started.", "確切目標與限制已儲存；尚未開始掃描。"],
    ["Change saved", "變更已儲存"],
  ] as const) {
    assert.ok(copyMap.includes(english), english);
    assert.ok(copyMap.includes(traditionalChinese), traditionalChinese);
  }

  assert.doesNotMatch(copyMap, /"start-scan"|\brescan:|"resume-scan"/u);
  const actionStart = app.indexOf("const executeAction = async");
  const actionEnd = app.indexOf("const runAction = async", actionStart);
  const action = app.slice(actionStart, actionEnd);
  assert.match(action, /nonExecutionActionToastCopy\[key as keyof typeof nonExecutionActionToastCopy\]/u);
  assert.match(action, /nonExecutionCopy\?\.acceptedTitle \?\? \{ en: "Local work started"/u);
  assert.match(action, /nonExecutionCopy\?\.acceptedDetail \?\? \{ en: "Open Scan progress to follow each scanner\."/u);
  assert.match(action, /nonExecutionCopy\?\.failedTitle \?\? \{ en: "The local work could not finish"/u);
});

test("all progress controls remain wired while raw scanner status stays in details", async () => {
  const source = await readPage("ProgressPage.tsx");
  for (const callback of ["onStart", "onPause", "onResume", "onCancel"]) {
    assert.match(source, new RegExp(`void ${callback}\\(`, "u"));
  }
  assert.match(source, /<details className="page-technical-details">[\s\S]*engine\.phase[\s\S]*engine\.errorCode[\s\S]*engine\.message[\s\S]*checkpoint\?\.lastError[\s\S]*<\/details>/u);
  assert.doesNotMatch(source, /<code>error:\s*\{engine\.errorCode\}/u);
  assert.doesNotMatch(source, /<small>\{engine\.category\}[\s\S]*\{engine\.version\}<\/small>/u);
  assert.match(source, /A check that did not run is not a passed check/u);
  assert.match(source, /未執行的檢查不能視為已通過/u);
});

test("scan readiness blocks empty runs and sends each fix to the useful screen", async () => {
  const progress = await readPage("ProgressPage.tsx");
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");

  assert.match(progress, /action=\{starting \? \([\s\S]*\) : readiness\?\.ready \?/u);
  assert.match(progress, /readiness\?\.nextStep === "scanner_setup"[\s\S]*copy\.setupTools/u);
  assert.match(progress, /provider_capability_unavailable:[\s\S]*action: copy\.reconnectCloud/u);
  assert.match(progress, /One quick setup, then scan/u);
  assert.match(progress, /先完成一次設定，就可以開始掃描/u);
  assert.match(progress, /Connect the cloud account you want to scan/u);
  assert.match(progress, /請先連接你要掃描的雲端帳號/u);
  assert.match(progress, /Nothing was scanned/u);
  assert.match(progress, /這次其實沒有開始掃描/u);
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
  assert.match(progress, /No scan started/u);
  assert.match(progress, /掃描尚未開始/u);
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
    ["The app could not finish checking the selected inputs and scan tools", "程式尚未完成所選輸入與掃描工具的準備檢查"],
    ["Review the results that are still available", "請查看目前仍可用的結果"],
  ] as const) {
    assert.ok(progress.includes(english), english);
    assert.ok(progress.includes(traditionalChinese), traditionalChinese);
  }

  for (const [english, traditionalChinese] of [
    ["This target is ready, but this version has no working scan tool for it", "目標已準備好，但這個版本沒有可執行這項檢查的工具"],
    ["The saved local copy is missing or changed", "掃描用的本機副本已遺失或有變更"],
    ["An installed scan component is missing or changed", "一項隨附的掃描元件已遺失或變更"],
    ["A required installed scan component is missing or out of date", "一項必要的隨附掃描元件已遺失或過期"],
    ["The saved read-only data source is missing or changed", "已保存的唯讀資料來源已遺失或有變更"],
    ["The final readiness check could not finish", "最後的準備狀態檢查尚未完成"],
    ["The saved results needed to continue are missing or changed", "續跑所需的已保存結果已遺失或有變更"],
  ] as const) {
    assert.ok(app.includes(english), english);
    assert.ok(app.includes(traditionalChinese), traditionalChinese);
  }

  assert.match(
    app,
    /as const satisfies Partial<Record<ScanReadinessBlocker \| "resume_release_incompatible", BilingualText>>/u,
  );
  assert.match(app, /scannerSetupBlocker=\{scanReadiness && scanReadiness\.caseId === currentCaseId && isScannerSetupBlocker/u);
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
    "Nothing was rerun",
    "這次沒有重新執行任何檢查",
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

test("release-incompatible resume explains the safe next step without exposing native error text", async () => {
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");

  for (const copy of [
    "This unfinished scan was created by a different app release and cannot be continued safely.",
    "Nothing was rerun. Start a new scan; saved evidence and findings remain unchanged.",
    "這個未完成的掃描由不同版本的應用程式建立，無法安全續跑。",
    "這次沒有重新執行任何檢查；請開始新的掃描，已保存的證據與問題不會變更。",
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
  const identity = source.indexOf('<div className="engine-row__identity">', visibleMap);
  const progress = source.indexOf('<div className="engine-row__progress">', identity);
  assert.ok(visibleMap >= 0 && identity > visibleMap && progress > identity);
  assert.doesNotMatch(source.slice(identity, progress), /engine\.engineName|rawArtifactCount|assetIds\.length/u);
  assert.match(source.slice(identity, progress), /engineOutcomeFor\(engine\)[\s\S]*engineNextStepFor\(engine\)/u);
  assert.doesNotMatch(source, /copy\.checkLabel/u);

  const engineDetails = source.indexOf('<details className="page-technical-details">', progress);
  const engineResult = source.indexOf('<div className="engine-row__result">', engineDetails);
  assert.ok(engineDetails > progress && engineResult > engineDetails);
  assert.match(source.slice(engineDetails, engineResult), /engine\.engineName[\s\S]*engine\.assetIds\.length[\s\S]*engine\.rawArtifactCount/u);
  assert.doesNotMatch(source.slice(engineResult, source.indexOf('<details className="engine-provenance">', engineResult)), /rawArtifactCount|assetIds\.length/u);
  assert.doesNotMatch(source, /<code>\{run\.id\}<\/code>/u);
});

test("progress describes its asset coverage count as fully checked targets", async () => {
  const source = await readPage("ProgressPage.tsx");
  assert.match(source, /Targets fully checked: \{covered\} of \{total\}/u);
  assert.match(source, /已完整檢查 \{covered\}／\{total\} 個目標/u);
  assert.doesNotMatch(source, /\{covered\} of \{total\} checks have reported/u);
  assert.doesNotMatch(source, /\{covered\}／\{total\} 項檢查已有結果/u);
  assert.match(source, /covered: formatNumber\(selectedRun\.coveredAssetCount\)/u);
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
    "We could not check what is ready",
    "目前無法確認掃描準備狀態",
    "No scan started and nothing changed. Check again now.",
    "掃描尚未開始，也沒有變更任何資料；請立即重新檢查。",
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
    "The private scan connection could not start",
    "專用掃描連線未能啟動",
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
    "尚未進行到這一步",
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
  const source = await readPage("ExportPage.tsx");
  for (const callback of ["onPreview", "onExport", "onVerify", "onVerifyReceived"]) {
    assert.match(source, new RegExp(`${callback}\\(`, "u"));
  }
  assert.doesNotMatch(source, /\{previewError\s*\?\?/u);
  assert.match(source, /<details className="page-technical-details">[\s\S]*\{previewError\}[\s\S]*<\/details>/u);
  assert.match(source, /setPreviewRequest\(\(request\) => request \+ 1\)/u);

  const verification = await readPage("VerificationPage.tsx");
  for (const callback of ["onSelectBaseline", "onStartRescan", "onOpenFinding"]) {
    assert.match(verification, new RegExp(`${callback}\\(`, "u"));
  }
  assert.match(verification, /<details className="page-technical-details">[\s\S]*displayTechnicalDetail\(issue\.detail\)[\s\S]*<\/details>/u);
  assert.match(verification, /<details className="page-technical-details">[\s\S]*displayTechnicalDetail\(item\.explanation\)[\s\S]*<\/details>/u);
  assert.doesNotMatch(verification, /<p>\{item\.explanation\}<\/p>/u);
  assert.match(verification, /Affected findings stay under Could not verify and are not counted as fixed/u);
  assert.match(verification, /受影響的問題會保留在「無法確認」，不會算成已修復/u);
  assert.match(verification, /isOnlyMappingVersionDrift\(completenessIssues\)/u);
  assert.match(verification, /The affected checks completed in both scans, but they used different control-mapping catalog versions/u);
  assert.match(verification, /Affected scanner engines: \{count\}\. This is an engine count, not a security-finding count\./u);
  assert.match(verification, /Technical scanner\/target comparison limitations recorded: \{count\}\. This is not a security-finding count\./u);
  assert.doesNotMatch(verification, /\{count\} technical scanner\/target comparison limitations were recorded/u);
  assert.match(verification, /mappingVersionDriftOnlyForFinding \? mappingDiffSummary/u);
});

test("active and incomplete scans never present findings or exports as final", async () => {
  const findings = await readPage("FindingsPage.tsx");
  for (const phrase of [
    "These are interim results",
    "這些是暫時結果",
    "This is an interim view, not a clean result.",
    "這只是暫時畫面，不代表沒有問題。",
    "These results are incomplete",
    "這些結果尚不完整",
    "Some checks stopped before reaching a final result.",
    "有些檢查在產生最終結果前就停止了。",
  ]) assert.ok(findings.includes(phrase), phrase);
  assert.match(findings, /activeRunStatuses\.has\(latestRun\.status\)/u);
  assert.match(findings, /activeRun[\s\S]*onOpenProgress/u);
  assert.match(findings, /incompleteTerminalRun[\s\S]*onOpenProgress/u);

  const exportPage = await readPage("ExportPage.tsx");
  for (const phrase of [
    "This would be an interim report",
    "這會是一份暫時報告",
    "Save interim file",
    "儲存暫時檔案",
    "This report is incomplete",
    "這份報告尚不完整",
    "Save incomplete file",
    "儲存不完整檔案",
  ]) assert.ok(exportPage.includes(phrase), phrase);
  assert.match(exportPage, /workspaceExportRevision/u);
  assert.match(exportPage, /activeRun[\s\S]*createInterimExport/u);
  assert.match(exportPage, /incompleteTerminalRun[\s\S]*createIncompleteExport/u);
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
  for (const phrase of ["Files: {count}", "Findings: {count}"]) {
    assert.ok(progress.includes(phrase), phrase);
  }
  assert.ok(cases.includes("Assets: {assets} · Findings: {findings}"));
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
  const cardRendererEnd = normalizedSource.indexOf("\n  };\n\n  return (", cardRendererStart);
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
