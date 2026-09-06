import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { localizedDataQualityWarning } from "../../src/findingNarrative.ts";
import {
  recognizedEngineWarningZhTW,
  recognizedShortfallDescriptionZhTW,
} from "../../src/engineWarningPresentation.ts";

const read = (path: string): string => readFileSync(new URL(path, import.meta.url), "utf8");

const rustLiteral = /"((?:[^"\\]|\\[\s\S])*)"/u;
const indirect: string[] = [];
const calls = (source: string, needles: readonly string[]): string[] => {
  const found: string[] = [];
  for (const needle of needles) {
    let offset = 0;
    while ((offset = source.indexOf(needle, offset)) >= 0) {
      const open = source.indexOf("(", offset + needle.length);
      if (open < 0) break;
      let depth = 0;
      let quote = false;
      let escaped = false;
      let end = open;
      for (; end < source.length; end += 1) {
        const character = source[end];
        if (quote) {
          if (escaped) escaped = false;
          else if (character === "\\") escaped = true;
          else if (character === '"') quote = false;
        } else if (character === '"') quote = true;
        else if (character === "(") depth += 1;
        else if (character === ")" && --depth === 0) break;
      }
      const call = source.slice(open, end + 1);
      const literal = call.match(rustLiteral)?.[1];
      if (literal) found.push(literal.replaceAll(/\\\n\s*/gu, ""));
      else indirect.push(call.replaceAll(/\s+/gu, " "));
      offset = end + 1;
    }
  }
  return found;
};

const sample = (rustFormat: string): string => rustFormat
  .replaceAll(/\{[^}]*\}/gu, "retained-value")
  .replaceAll("{}", "retained-value");

test("every censused product-authored engine-warning sentence has a Chinese shape", () => {
  const files = [
    read("../../src-tauri/src/adapter.rs").split("#[cfg(test)]")[0] ?? "",
    read("../../src-tauri/src/adapters/mod.rs").split("#[cfg(test)]")[0] ?? "",
    read("../../src-tauri/src/orchestrator.rs").split("#[cfg(test)]")[0] ?? "",
    read("../../src-tauri/src/case_service.rs").split("#[cfg(test)]")[0] ?? "",
  ];
  const authored = new Set(files.flatMap((source) => calls(source, [
    "push_warning",
    "report.warnings.push",
    "engine_run.warnings.push",
    "output.warnings.push",
  ])).map(sample));
  const caseSource = files[3] ?? "";
  const adapterSource = files[1] ?? "";
  const indirectPatterns = [
    /const\s+[A-Z0-9_]*(?:WARNING|MESSAGE)[A-Z0-9_]*[^=]*=\s*"([^"]+)"/gu,
    /explanation:\s*(?:format!\(\s*)?"([^"]+)"/gu,
    /let\s+warning\s*=\s*"([^"]+)"/gu,
    /legacy_request_migration_warning\s*=\s*Some\(\s*"([^"]+)"/gu,
    /format!\(\s*"(Engine \{\} uses knowledge dated [^"]+)"/gu,
  ];
  for (const expression of indirectPatterns) {
    for (const match of caseSource.matchAll(expression)) authored.add(sample(match[1] ?? ""));
  }
  for (const expression of [
    /(?:Err|map_err)\([^\n]*"(Greenbone XML [^"]+)"/gu,
    /format!\(\s*"((?:the tenant's ScubaGear|\{engine\} did not evaluate)[^"]+)"/gu,
  ]) {
    for (const match of adapterSource.matchAll(expression)) authored.add(sample(match[1] ?? ""));
  }
  // Whatever this parser cannot read a literal from is covered by the patterns
  // above instead. Pinning that list means a producer that starts composing its
  // sentence somewhere new fails here rather than escaping the census silently.
  assert.deepEqual([...new Set(indirect)].sort(), [
    "(&mut output.warnings, disputed)",
    "(&mut output.warnings, unevaluated.disclosure)",
    "()",
    "(warnings, error)",
    "(warnings: &mut Vec<String>, warning: impl AsRef<str>)",
  ]);
  assert.ok(authored.size >= 70, `producer extractor found only ${authored.size} warning sentences`);
  const untranslated = [...authored].filter((warning) => recognizedEngineWarningZhTW(warning) === undefined);
  assert.deepEqual(untranslated, [], `engine warning shapes without Chinese:\n${untranslated.join("\n")}`);
});

test("every beginner-report data-quality warning has a Chinese form", () => {
  const source = read("../../src-tauri/src/beginner_report.rs").split("#[cfg(test)]")[0] ?? "";
  const authored = new Set(calls(source, ["data_quality_warnings.push", "warnings.push"]).map(sample));
  const warnings = [...authored].filter((value) =>
    value.startsWith("This run") || value.startsWith("The selected run") ||
    value.startsWith("One check") || value.startsWith("Finding "));
  assert.ok(warnings.length >= 6, `producer extractor found only ${warnings.length} data-quality warnings`);
  const untranslated = warnings.filter((warning) => localizedDataQualityWarning(warning, "zh-TW") === warning);
  assert.deepEqual(untranslated, [], `data-quality warnings without Chinese:\n${untranslated.join("\n")}`);
});

test("redaction placeholders and warnings from another build fall back unchanged", () => {
  for (const warning of ["[redacted engine warning]", "A warning from a later build."]) {
    assert.equal(recognizedEngineWarningZhTW(warning), undefined);
  }
  assert.equal(
    localizedDataQualityWarning("[redacted data-quality warning]", "zh-TW"),
    "[redacted data-quality warning]",
  );
});

test("every counted control shortfall the disclosure joins has a Chinese form", () => {
  const source = read("../../src-tauri/src/adapters/mod.rs").split("#[cfg(test)]")[0] ?? "";
  const body = (name: string): string => {
    const start = source.indexOf(`fn ${name}(`);
    assert.ok(start >= 0, `${name} is gone; this census needs rewriting`);
    return source.slice(start, source.indexOf("\n}\n", start));
  };
  // The pairs are `("<diagnostics key>", "<how to say it out loud>")`; only the
  // second half reaches a reader.
  const described = [...body("unevaluated_controls").matchAll(/\("[a-z_]+",\s*"([^"]+)"\)/gu)]
    .map((match) => match[1] ?? "");
  // Any counted description, whatever its count is called: the hole's name
  // is not the census key.
  const shortfall = [...body("normalization_shortfall").matchAll(/"\{[a-z_]+\} ([^"]+)"/gu)]
    .map((match) => match[1] ?? "");
  const descriptions = [...new Set([...described, ...shortfall])];
  assert.ok(descriptions.length >= 6, `found only ${descriptions.length} shortfall descriptions`);
  const untranslated = descriptions.filter((value) => recognizedShortfallDescriptionZhTW(value) === undefined);
  assert.deepEqual(untranslated, [], `shortfall descriptions without Chinese:\n${untranslated.join("\n")}`);
});

test("a translated disclosure keeps the engine's counts and translates its prose", () => {
  const translated = recognizedEngineWarningZhTW(
    "ScubaGear did not evaluate every control in scope (20 reserved for manual review, 5 could not be evaluated); those controls are absent from findings and this run does not establish their state",
  );
  assert.equal(
    translated,
    "ScubaGear 未評估範圍內的所有控制措施（20 保留供人工審查、5 無法評估）；這些控制措施未列於問題中，本輪也無法確認其狀態",
  );
  assert.equal(
    recognizedEngineWarningZhTW(
      "Maester did not evaluate every control in scope (4 not accounted for by any reported category); those controls are absent from findings and this run does not establish their state",
    ),
    "Maester 未評估範圍內的所有控制措施（4 未計入任何已回報類別）；這些控制措施未列於問題中，本輪也無法確認其狀態",
  );
  // A description this build did not author survives rather than being dropped.
  assert.match(
    recognizedEngineWarningZhTW(
      "Maester did not evaluate every control in scope (3 deferred by a later build); those controls are absent from findings and this run does not establish their state",
    ) ?? "",
    /3 deferred by a later build/u,
  );
});
