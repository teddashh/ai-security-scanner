import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { assertInsideDisclosure, regionFrom } from "./sourceRegions.ts";

const source = await readFile(
  new URL("../../src/pages/FindingsPage.tsx", import.meta.url),
  "utf8",
);

test("the problem-review page has complete English and Traditional Chinese UI copy", () => {
  assert.match(source, /useI18n\(\)/u);
  assert.match(source, /en:\s*"Know what to fix first"/u);
  assert.match(source, /zhTW:\s*"先知道該修什麼"/u);
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
  // Both of these are claims that a raw technical value stays behind a
  // disclosure rather than being put in front of a non-expert reader. See
  // `sourceRegions.ts` for why a `[\s\S]*` span cannot check that.
  assertInsideDisclosure(source, "page-technical-details", "evidence.rawArtifactHash");
  assertInsideDisclosure(source, "page-technical-details", "selected.fingerprint");
  assert.match(
    source,
    /visibleFindingGroups\.length > 0[\s\S]*aria-labelledby="finding-groups-title"[\s\S]*visibleFindingIds[\s\S]*finding-browser/u,
    "accepted groups should be visible before the complete finding browser without replacing its members",
  );
  assert.match(source, /Accepted groups reduce repetition during handoff/u);
  assert.match(source, /已接受的群組可減少交接時的重複內容/u);
  assert.match(source, /Shared vulnerability data source; independent confirmation is not established/u);
  assert.match(source, /共用弱點資料來源；未形成獨立確認/u);
  assert.match(source, /Not observed in this selected report; kept as case history/u);
  assert.match(source, /本次選取的報告未觀察到；僅保留為案件歷史/u);
  assert.match(source, /Report terms and technical record/u);
  assert.match(source, /報告條款與技術紀錄/u);
  assert.doesNotMatch(source, /guidance for a person to evaluate/u);
  assert.doesNotMatch(source, /交給人員評估的方向/u);
});

test("the legacy result-kind fallback keeps every inventory engine out of clean security results", () => {
  const fallback = regionFrom(source, "const legacyCheckResultKind", 12);
  for (const engine of ["cloudquery", "steampipe", "syft", "naabu", "httpx"]) {
    assert.match(fallback, new RegExp(`"${engine}"`, "u"), engine);
  }
  assert.match(fallback, /return "inventory"/u);
});
