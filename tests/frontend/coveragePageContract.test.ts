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
  assert.match(source, /setExternalProtocol\(service\?\.protocol \?\? "https"\)/);
  assert.match(source, /setExternalPorts\(service \? String\(service\.port\) : "443"\)/);
  assert.ok(source.includes("path is context, not permission"));
  assert.ok(source.includes("路徑只是提示，不是許可"));
  assert.match(source, /internetExposed === false && allowSensitiveNetworks/);
  assert.match(source, /internetExposed === undefined/);
});

test("every journey step is directly reachable and step 2 points to permission review", () => {
  assert.ok(source.includes('href={`#coverage-step-${number}`}'));
  assert.ok(source.includes('href="#coverage-step-3"'));
  assert.ok(source.includes('scrollToCoverageStep("coverage-step-3")'));
  assert.ok(source.includes('(prefers-reduced-motion: reduce)'));
  assert.ok(source.includes('id="coverage-step-1"'));
  assert.ok(source.includes('id="coverage-step-2"'));
  assert.ok(source.includes('id="coverage-step-3"'));
  assert.ok(source.includes("Continue to step 3"));
  assert.ok(source.includes("前往步驟 3"));
});

test("the rendered Coverage tree has no hard-coded Traditional Chinese UI copy", () => {
  const renderStart = source.indexOf('\n  return (\n    <div className="page page--coverage">');
  assert.notEqual(renderStart, -1);
  const renderedTree = source.slice(renderStart);
  assert.doesNotMatch(renderedTree, /[\u3400-\u9fff]/u);
  assert.ok(renderedTree.includes("text(pageCopy.headerTitle)"));
});
