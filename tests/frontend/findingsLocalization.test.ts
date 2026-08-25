import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(
  new URL("../../src/pages/FindingsPage.tsx", import.meta.url),
  "utf8",
);

test("the problem-review page has complete English and Traditional Chinese UI copy", () => {
  assert.match(source, /useI18n\(\)/u);
  assert.match(source, /en:\s*"Start with what deserves attention/u);
  assert.match(source, /zhTW:\s*"先看最值得處理的事/u);
  assert.doesNotMatch(
    source,
    /import\s*\{[^}]*formatDateTime[^}]*\}\s*from\s*"\.\.\/lib"/su,
  );

  const renderedComponent = source.slice(source.indexOf("export function FindingsPage"));
  assert.doesNotMatch(
    renderedComponent,
    /[\p{Script=Han}]/u,
    "rendered labels should come from bilingual copy instead of fixed Chinese literals",
  );
});

test("problem grouping, review decisions, evidence, and navigation remain wired", () => {
  for (const callback of [
    "onUpdateWorkflow",
    "onGroupFindings",
    "onUngroupFindings",
    "onOpenCoverage",
    "onOpenProgress",
  ]) {
    assert.match(source, new RegExp(`${callback}(?:\\(|=|\\})`, "u"));
  }
  assert.match(source, /<details className="page-technical-details">[\s\S]*evidence\.rawArtifactHash[\s\S]*<\/details>/u);
  assert.match(source, /<details className="page-technical-details">[\s\S]*selected\.fingerprint[\s\S]*<\/details>/u);
  assert.match(source, /The product does not make the change/u);
  assert.match(source, /產品不會自動執行/u);
});
