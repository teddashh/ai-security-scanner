import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// Case data classification enriches impact only after a scan independently
// finds a matching asset. The form states that behavior in one direct sentence.

const prioritization = readFileSync(
  new URL("../../src-tauri/src/prioritization.rs", import.meta.url),
  "utf8",
);
const production = prioritization.slice(0, prioritization.indexOf("#[cfg(test)]"));
const casesPage = readFileSync(new URL("../../src/pages/CasesPage.tsx", import.meta.url), "utf8");

test("the case questionnaire alone cannot raise a finding's priority", () => {
  // Both halves of the conjunction are load-bearing. `sensitive_context` is the
  // questionnaire answer; `sensitive_asset` is the independently discovered
  // asset attribute with non-questionnaire provenance.
  assert.match(production, /if sensitive_asset && sensitive_context \{/u);
  assert.match(
    production,
    /asset\.contains_sensitive_data == Some\(true\)\s*&& has_only_retained_non_questionnaire_sources\(case, asset\)/u,
  );
});

test("the recorded impact sentence states the matched context directly", () => {
  const impact = production.match(/const SENSITIVE_IMPACT: &str =\s*"([^"]+)"/u)?.[1];
  assert.ok(impact, "SENSITIVE_IMPACT was not found; the extraction above is stale");
  assert.equal(impact, " The affected asset contains sensitive data, increasing the potential impact.");
  assert.doesNotMatch(impact, /human|proof|not retained/u);
});

test("the form explains the effect without shifting responsibility to the reader", () => {
  const help = casesPage.match(/dataTypesHelp: \{\s*en: "([^"]+)"/u)?.[1];
  assert.ok(help, "dataTypesHelp was not found; the extraction above is stale");
  assert.equal(help, "Used to explain impact when a scan finds a matching asset.");
  assert.doesNotMatch(help, /Your answer|never|only where/u);
});

test("both locales carry the same concise behavior", () => {
  const chinese = casesPage.match(/dataTypesHelp: \{[^}]*zhTW: "([^"]+)"/u)?.[1];
  assert.ok(chinese, "the Traditional Chinese dataTypesHelp was not found");
  assert.equal(chinese, "掃描發現對應資產時，這項資料會用來說明影響。");
  assert.doesNotMatch(chinese, /僅憑你的回答|不會|只有/u);
});
