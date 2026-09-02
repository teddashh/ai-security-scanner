import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { scanRunIdentityPresentation } from "../../src/scanRunIdentityPresentation.ts";

test("product-generated scan sequence labels follow the current locale", () => {
  assert.equal(scanRunIdentityPresentation({ label: "stored label", sequence: 12 }, "zh-TW"), "第 12 次掃描");
  assert.equal(scanRunIdentityPresentation({ label: "stored label", sequence: 12 }, "en"), "Scan 12");
});

test("custom, imported, colliding, and malformed labels without canonical sequence remain untouched", () => {
  for (const label of ["Before remediation", "Scan 0", "Scan 1,000", "第 1 次 掃描", "scan 2"]) {
    assert.equal(scanRunIdentityPresentation({ label }, "zh-TW"), label);
    assert.equal(scanRunIdentityPresentation({ label }, "en"), label);
  }
  assert.equal(scanRunIdentityPresentation({ label: "Scan 12" }, "zh-TW"), "Scan 12");
  assert.equal(scanRunIdentityPresentation({ label: "第 12 次掃描" }, "en"), "第 12 次掃描");
});

test("primary run pickers present labels at render time instead of freezing adapter language", async () => {
  const files = await Promise.all([
    "ProgressPage.tsx",
    "FindingsPage.tsx",
    "CasesPage.tsx",
    "VerificationPage.tsx",
    "ExportPage.tsx",
  ].map((name) => readFile(new URL(`../../src/pages/${name}`, import.meta.url), "utf8")));

  for (const source of files) {
    assert.match(source, /scanRunIdentityPresentation/u);
  }
  assert.doesNotMatch(files[0]!, /<strong>\{run\.label\}<\/strong>/u);
  assert.doesNotMatch(files[0]!, /<span>\{selectedRun\.label\}<\/span>/u);
  assert.doesNotMatch(files[1]!, /<option key=\{run\.id\} value=\{run\.id\}>\{run\.label\}<\/option>/u);
  assert.doesNotMatch(files[3]!, /activeRun\.label|selectedBaselineRun\.label/u);
});
