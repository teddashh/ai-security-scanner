import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../../src/pages/CoveragePage.tsx", import.meta.url),
  "utf8",
);

test("coverage onboarding keeps the complete input and permission surface", () => {
  for (const capability of [
    "ProviderAuthorizationPanel",
    "onConnectSourceSnapshot",
    "onAttachWorkspaceSnapshot",
    "onStartDiscovery",
    "onApprovePending",
    "externalTarget",
    "externalPorts",
    "externalProtocol",
    "requestsPerSecond",
    "externalConcurrency",
    "externalTimeout",
    "templateRevision",
    "allowedTemplateIds",
    "allowSensitiveNetworks",
  ]) {
    assert.ok(source.includes(capability), `missing Coverage capability: ${capability}`);
  }
});

test("coverage onboarding presents all required use-case next steps in both locales", () => {
  for (const [english, traditionalChinese] of [
    ["A website or API that is already online", "已架好的網站或 API"],
    ["Public IP addresses or domains", "公開 IP 或網域"],
    ["Internal IT systems", "內部 IT 環境"],
    ["Source code", "程式碼"],
    ["Infrastructure code", "基礎設施程式碼"],
    ["Container image", "容器映像"],
    ["Kubernetes", "Kubernetes"],
    ["AWS, Azure, Google Cloud, or Microsoft 365", "AWS、Azure、Google Cloud 或 Microsoft 365"],
  ]) {
    assert.ok(source.includes(english), `missing English use-case guidance: ${english}`);
    assert.ok(source.includes(traditionalChinese), `missing Traditional Chinese guidance: ${traditionalChinese}`);
  }
});

test("technical detail is progressive and a website service remains a preset, not permission", () => {
  assert.ok(source.includes("coverage-technical-details"));
  assert.ok(source.includes("source-card__technical"));
  assert.ok(source.includes("asset-review-card__technical"));
  assert.ok(source.includes("selectedExternalAsset.declaredWebService"));
  assert.match(source, /setExternalProtocol\(service\.protocol\)/);
  assert.match(source, /setExternalPorts\(String\(service\.port\)\)/);
  assert.ok(source.includes("path is context, not permission"));
  assert.ok(source.includes("路徑只是提示，不是許可"));
  assert.match(source, /internetExposed === false && effectiveAllowSensitiveNetworks/);
  assert.match(source, /internetExposed === undefined/);

  const advancedStart = source.indexOf('<details\n                  className="coverage-form-technical coverage-scan-advanced"');
  const advancedEnd = source.indexOf("</details>", advancedStart);
  assert.notEqual(advancedStart, -1);
  assert.notEqual(advancedEnd, -1);
  const advancedSettings = source.slice(advancedStart, advancedEnd);
  for (const technicalControl of [
    "pageCopy.declaredServiceTitle",
    "pageCopy.canonicalTarget",
    "pageCopy.protocol",
    "pageCopy.ports",
    "pageCopy.rateTitle",
    "pageCopy.templateIds",
    "pageCopy.sensitiveTechnicalBody",
  ]) {
    assert.ok(advancedSettings.includes(technicalControl), `${technicalControl} must stay behind advanced details`);
  }
  assert.ok(source.indexOf("pageCopy.sensitiveTitle", advancedEnd) > advancedEnd, "custom and active internal-network confirmation must remain available");
  assert.match(
    source.slice(advancedEnd, source.indexOf("</section>", advancedEnd)),
    /isDirectExternal && selectedExternalAsset\.internetExposed === false && !guidedLowImpactNetwork/,
    "the extra internal-network toggle must not clutter the guided low-impact setup",
  );
  assert.doesNotMatch(source.slice(advancedEnd, source.indexOf("</section>", advancedEnd)), /asset\.locator/);
});

test("guided IP and internal scans use a useful bounded TCP service preset", () => {
  assert.ok(source.includes("commonTcpServicePorts"));
  assert.ok(source.includes("recommendedTcpPorts"));
  assert.match(source, /assessmentIntent === "external_ip_or_domain" \|\| assessmentIntent === "internal_it_environment"/u);
  assert.match(source, /setExternalProtocol\("tcp"\)/u);
  assert.match(source, /setExternalPorts\(recommendedTcpPorts\(externalTarget\)\.join\(", "\)\)/u);
  assert.ok(source.includes("pageCopy.guidedNetworkPreset"));
  assert.ok(source.includes("這次只會用保守的連線設定檢查 {target}"));
  assert.doesNotMatch(
    source.match(/guidedNetworkPreset: bilingual\(([\s\S]*?)\n\s*\),/u)?.[1] ?? "",
    /\{protocol\}|\{count\}/u,
    "protocol and port counts must not appear in the first-layer preset",
  );
  assert.match(source, /coverage-technical-preset-summary[\s\S]*guidedNetworkTechnicalPreset[\s\S]*protocol: externalProtocol[\s\S]*count: formatNumber\(parsedPorts\.length\)/u);
});

test("the saved assessment intent opens one guided route and moves unrelated inputs under advanced options", () => {
  assert.ok(source.includes("assessmentIntent?: UseCaseId"));
  assert.ok(source.includes("localProfileByAssessmentIntent"));
  assert.ok(source.includes("setShowProviderSetup(guidedCloudRoute)"));
  assert.ok(source.includes("setShowWorkspaceForm(Boolean(guidedLocalProfile))"));
  assert.ok(source.includes("guidedNetworkInputCard"));
  assert.ok(source.includes('className="coverage-situation-details coverage-advanced-inputs"'));
  assert.ok(source.includes("pageCopy.otherInputsSummary"));
});

test("guided network, local, and signed-in cloud setup use one explicit confirmation without auto-approval", () => {
  assert.ok(source.includes("simpleGuidedConsent = guidedLowImpactNetwork || guidedLocalConsent || guidedCloudConsent"));
  assert.ok(source.includes("pageCopy.confirmAndSave"));
  assert.ok(source.includes("pageCopy.useSignedInCloud"));
  assert.ok(source.includes("pageCopy.guidedCloudConfirmation"));
  assert.ok(source.includes("pageCopy.changeScanType"));
  assert.ok(source.includes("effectiveAllowSensitiveNetworks"));
  const approveStart = source.indexOf("const approve = async () =>");
  const approveEnd = source.indexOf("const changeSourceKind", approveStart);
  assert.notEqual(approveStart, -1);
  assert.notEqual(approveEnd, -1);
  assert.ok(source.slice(approveStart, approveEnd).includes("onApprovePending("));
  assert.equal(source.slice(0, approveStart).includes("onApprovePending("), false, "route setup must not auto-approve");
});

test("cloud sign-in leads to one exact read-only scan confirmation instead of another ownership form", () => {
  assert.match(source, /guidedCloudRoute[\s\S]*providerConnection[\s\S]*selectedScopeAssets\.every\(\(asset\) => isCloudAsset\(asset\) && asset\.platform === providerConnection\.platform\)/u);
  assert.match(source, /selectedScopeAssets\.length === 1/u);
  assert.match(source, /asset\.platform === "external" \|\| selectedIncludesExternal \|\| guidedCloudRoute/u);
  assert.match(source, /!simpleGuidedConsent && \([\s\S]*ownershipConfirmed/u);
  assert.match(source, /guidedLowImpactNetwork \|\| guidedCloudConsent[\s\S]*pageCopy\.changeScanType/u);
  for (const [english, traditionalChinese] of [
    ["Your provider sign-in already identifies the account", "雲端服務商登入已確認帳號"],
    ["Use this signed-in account", "使用這個已登入帳號"],
  ]) {
    assert.ok(source.includes(english), english);
    assert.ok(source.includes(traditionalChinese), traditionalChinese);
  }
});

test("the first layer uses plain-language scan choices in both locales", () => {
  for (const [english, traditionalChinese] of [
    ["Items found", "找到的項目"],
    ["Not set up yet", "尚未設定"],
    ["Recommended settings are ready", "建議設定已準備好"],
    ["I confirm this is my website or a system I am allowed to scan", "我確認這是我的網站，或是我有權掃描的系統"],
    ["I confirm this scan may connect to the selected internal network", "我確認這次掃描可以連線到所選內部網路"],
  ]) {
    assert.ok(source.includes(english), `missing plain-language English copy: ${english}`);
    assert.ok(source.includes(traditionalChinese), `missing plain-language Traditional Chinese copy: ${traditionalChinese}`);
  }
  assert.ok(source.includes("setShowAdvancedExternalSettings(false)"));
  assert.ok(!source.includes('setShowAdvancedExternalSettings(externalActivity === "active_external")'));
});

test("local-project formats stay available behind technical details", () => {
  const workspaceStart = source.indexOf('id="workspace-snapshot-form"');
  const technicalStart = source.indexOf('<details className="coverage-form-technical">', workspaceStart);
  const technicalEnd = source.indexOf("</details>", technicalStart);
  assert.notEqual(workspaceStart, -1);
  assert.notEqual(technicalStart, -1);
  assert.notEqual(technicalEnd, -1);
  const visibleSetup = source.slice(workspaceStart, technicalStart);
  const technicalSetup = source.slice(technicalStart, technicalEnd);
  assert.ok(visibleSetup.includes("selectedLocalInput.cautionBody"));
  assert.ok(visibleSetup.includes("localInputDefinitions[workspaceInputProfile].detail"));
  assert.match(visibleSetup, /!guidedLocalProfile && <label className="field">[\s\S]*pageCopy\.inputType/u);
  assert.match(technicalSetup, /guidedLocalProfile && \([\s\S]*pageCopy\.advancedLocalInputSummary[\s\S]*Object\.keys\(localInputDefinitions\)/u);
  assert.ok(technicalSetup.includes("pageCopy.gitTechnicalBody"));
  assert.ok(technicalSetup.includes("localInputDefinitions[workspaceInputProfile].technical"));
  assert.ok(source.includes("Prepare this project for scanning"));
  assert.ok(source.includes("準備這份專案進行掃描"));
});

test("each guided local route has plain-language first-layer copy in both locales", () => {
  for (const [english, traditionalChinese] of [
    ["Choose the source code you want checked", "選擇想檢查的程式碼"],
    ["Choose the infrastructure code you want checked", "選擇想檢查的基礎設施程式碼"],
    ["Choose the container image you want checked", "選擇想檢查的容器映像"],
    ["Choose the Kubernetes settings you want checked", "選擇想檢查的 Kubernetes 設定"],
    ["Add this source-code project", "加入這份程式碼專案"],
    ["Add this infrastructure code", "加入這份基礎設施程式碼"],
    ["Add this container image", "加入這份容器映像"],
    ["Add these Kubernetes settings", "加入這些 Kubernetes 設定"],
  ]) {
    assert.ok(source.includes(english), english);
    assert.ok(source.includes(traditionalChinese), traditionalChinese);
  }
});

test("guided selection status is honest and does not keep prompting after auto-selection", () => {
  assert.doesNotMatch(source, /bilingual\("Ready to scan"|bilingual\([^\n]+, "準備掃描"\)|Choose your first item/u);
  assert.ok(source.includes('authorized: bilingual("Target confirmed", "目標已確認")'));
  assert.ok(source.includes("shouldPromptForFirstAsset(pendingAssets.length, selectedAssets.length)"));
});

test("every journey step is directly reachable and step 2 points to scan choices", () => {
  assert.ok(source.includes('href={`#coverage-step-${number}`}'));
  assert.ok(source.includes('href="#coverage-step-3"'));
  assert.ok(source.includes('scrollToCoverageStep("coverage-step-3")'));
  assert.ok(source.includes('(prefers-reduced-motion: reduce)'));
  assert.ok(source.includes('id="coverage-step-1"'));
  assert.ok(source.includes('id="coverage-step-2"'));
  assert.ok(source.includes('id="coverage-step-3"'));
  assert.ok(source.includes("text(pageCopy.continueStep3)"));
});

test("the rendered Coverage tree has no hard-coded Traditional Chinese UI copy", () => {
  const renderStart = source.indexOf('\n  return (\n    <div className="page page--coverage">');
  assert.notEqual(renderStart, -1);
  const renderedTree = source.slice(renderStart);
  assert.doesNotMatch(renderedTree, /[\u3400-\u9fff]/u);
  assert.ok(renderedTree.includes("text(pageCopy.headerTitle)"));
});
