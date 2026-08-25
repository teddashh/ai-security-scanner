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
  assert.match(source, /no findings does not mean checked/u);
  assert.match(source, /沒有問題不代表已檢查/u);
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
  assert.match(verification, /must remain could not verify/u);
  assert.match(verification, /必須保留為「無法確認」/u);
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
