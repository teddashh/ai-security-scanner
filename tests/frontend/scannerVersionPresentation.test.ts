import assert from "node:assert/strict";
import test from "node:test";

import { scannerVersionLabel } from "../../src/scannerVersionPresentation.ts";
import type { Locale } from "../../src/i18n/core.ts";

const COMMIT = "3ab759fef4bb5935d4fe9ac68b503d05346b8364";
const SOURCE = `source@${COMMIT}`;
const REPORTED = "3.97.0";

const label = (
  engineVersion: string | undefined,
  reportedVersion: string | undefined,
  form: "short" | "exact",
  locale: Locale,
) => scannerVersionLabel(engineVersion, reportedVersion, form, locale);

test("a source pin with a reported version shows that version and the commit", () => {
  assert.equal(label(SOURCE, REPORTED, "short", "en"), "3.97.0 (source 3ab759f)");
  assert.equal(label(SOURCE, REPORTED, "short", "zh-TW"), "3.97.0（source 3ab759f）");
  assert.equal(label(SOURCE, `  ${REPORTED}  `, "exact", "en"), `3.97.0 (source@${COMMIT})`);
  assert.equal(label(SOURCE, REPORTED, "exact", "zh-TW"), `3.97.0（source@${COMMIT}）`);
  assert.equal(label(`  ${SOURCE}  `, REPORTED, "short", "en"), "3.97.0 (source 3ab759f)");
});

test("a source pin without a reported version shows only the commit", () => {
  for (const reportedVersion of [undefined, "", "   "]) {
    assert.equal(label(SOURCE, reportedVersion, "short", "en"), "source 3ab759f");
    assert.equal(label(SOURCE, reportedVersion, "short", "zh-TW"), "source 3ab759f");
    assert.equal(label(SOURCE, reportedVersion, "exact", "en"), SOURCE);
    assert.equal(label(SOURCE, reportedVersion, "exact", "zh-TW"), SOURCE);
  }
});

test("a non-source engine version ignores a reported version", () => {
  for (const form of ["short", "exact"] as const) {
    for (const locale of ["en", "zh-TW"] as const) {
      assert.equal(label("1.174.0", REPORTED, form, locale), "1.174.0");
      assert.equal(label("  v0.16.0  ", "0.16.0", form, locale), "v0.16.0");
    }
  }
});

test("a malformed source pin is shown unchanged and ignores a reported version", () => {
  for (const engineVersion of ["source@xyz", "source@abc123", "source@3AB759F", `source@${"a".repeat(65)}`]) {
    for (const form of ["short", "exact"] as const) {
      for (const locale of ["en", "zh-TW"] as const) {
        assert.equal(label(engineVersion, REPORTED, form, locale), engineVersion);
      }
    }
  }
});

test("a blank or missing engine version stays absent", () => {
  for (const engineVersion of [undefined, "", "   "]) {
    for (const form of ["short", "exact"] as const) {
      for (const locale of ["en", "zh-TW"] as const) {
        assert.equal(label(engineVersion, REPORTED, form, locale), undefined);
      }
    }
  }
});
