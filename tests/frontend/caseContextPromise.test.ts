import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The new-case form asks which kinds of data a project may involve, and its
// help text tells the user what that answer will do. The backend deliberately
// refuses to act on the answer alone: `apply_case_context` raises priority only
// where a scan independently discovered an asset carrying the matching
// attribute, and only where that asset's provenance is not itself the
// questionnaire. That is the right design -- a self-reported answer must not be
// able to inflate a security result -- but it is invisible from the form, whose
// copy used to read as though ticking a box reprioritized the report.
//
// These two facts have to move together. If the backend ever drops the asset
// requirement the copy becomes an understatement, and if the copy ever drops
// the caveat it becomes a promise the backend does not keep.

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

test("the recorded impact sentence says the questionnaire is not proof", () => {
  const impact = production.match(/const SENSITIVE_IMPACT: &str = "([^"]+)"/u)?.[1];
  assert.ok(impact, "SENSITIVE_IMPACT was not found; the extraction above is stale");
  assert.match(impact, /not retained/u);
  assert.match(impact, /neither entry is itself proof of data exposure/u);
});

test("the form does not promise more than the backend will do", () => {
  const help = casesPage.match(/dataTypesHelp: \{\s*en: "([^"]+)"/u)?.[1];
  assert.ok(help, "dataTypesHelp was not found; the extraction above is stale");
  assert.match(help, /only where a scan independently finds a matching asset/u);
  assert.match(help, /never raises a result's priority/u);
});

test("both locales carry the caveat, not just the one most readers see", () => {
  const chinese = casesPage.match(/dataTypesHelp: \{[^}]*zhTW: "([^"]+)"/u)?.[1];
  assert.ok(chinese, "the Traditional Chinese dataTypesHelp was not found");
  assert.match(chinese, /只有在掃描獨立發現對應資產時才會生效/u);
  assert.match(chinese, /不會提高任何結果的優先順序/u);
});
