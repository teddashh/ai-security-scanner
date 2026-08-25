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

test("progress keeps scanner implementation data below the first layer", async () => {
  const source = await readPage("ProgressPage.tsx");
  const ledger = source.indexOf('<div className="engine-state-ledger"');
  const runDetails = source.lastIndexOf('<details className="page-technical-details page-technical-details--guide">', ledger);
  const runDetailsEnd = source.indexOf("</details>", ledger);
  assert.ok(runDetails >= 0 && ledger > runDetails && runDetailsEnd > ledger, "the scanner-state ledger should be inside scan details");

  const identity = source.indexOf('<div className="engine-row__identity">');
  const progress = source.indexOf('<div className="engine-row__progress">', identity);
  assert.ok(identity >= 0 && progress > identity);
  assert.doesNotMatch(source.slice(identity, progress), /engine\.engineName|rawArtifactCount|assetIds\.length/u);
  assert.match(source.slice(identity, progress), /copy\.checkLabel/u);

  const engineDetails = source.indexOf('<details className="page-technical-details">', progress);
  const engineResult = source.indexOf('<div className="engine-row__result">', engineDetails);
  assert.ok(engineDetails > progress && engineResult > engineDetails);
  assert.match(source.slice(engineDetails, engineResult), /engine\.engineName[\s\S]*engine\.assetIds\.length[\s\S]*engine\.rawArtifactCount/u);
  assert.doesNotMatch(source.slice(engineResult, source.indexOf('<details className="engine-provenance">', engineResult)), /rawArtifactCount|assetIds\.length/u);
  assert.doesNotMatch(source, /<code>\{run\.id\}<\/code>/u);
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
  assert.match(verification, /stay under Could not verify and are not counted as fixed/u);
  assert.match(verification, /會保留在「無法確認」，不會算成已修復/u);
});

test("export leads with recipient choices and keeps file standards and integrity data in details", async () => {
  const source = await readPage("ExportPage.tsx");
  const cardRendererStart = source.indexOf("const renderFormatCard");
  const cardRendererEnd = source.indexOf("\n  };\n\n  return (", cardRendererStart);
  const cardRenderer = source.slice(cardRendererStart, cardRendererEnd);
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
