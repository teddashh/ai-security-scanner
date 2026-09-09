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

test("repo adapter shape-loss warnings have bounded Traditional Chinese presentations", () => {
  const cases = [
    [
      "Semgrep output lacked its required errors array; valid findings were preserved, but completeness cannot be established",
      "Semgrep 輸出缺少必要的 errors 陣列；有效問題已保留，但無法確認完整性",
    ],
    [
      "Semgrep reported one or more scanner errors; valid findings were preserved, but the error details remain only in the raw artifact and completeness cannot be established",
      "Semgrep 回報一項或多項掃描器錯誤；有效問題已保留，錯誤細節只留在原始成品中，且無法確認完整性",
    ],
    [
      "Semgrep finding at /results/2 lacked its check_id; the raw record was retained",
      "/results/2 的 Semgrep 問題缺少 check_id；原始記錄已保留",
    ],
    [
      "KICS output lacked its queries array; the raw artifact was retained",
      "KICS 輸出缺少 queries 陣列；原始成品已保留",
    ],
    [
      "KICS query at /queries/1 was not an object; the raw record was retained",
      "/queries/1 的 KICS 查詢不是物件；原始記錄已保留",
    ],
    [
      "KICS query at /queries/2 lacked a valid query_id; the raw record was retained",
      "/queries/2 的 KICS 查詢缺少有效的 query_id；原始記錄已保留",
    ],
    [
      "KICS query at /queries/3 lacked its files array; the raw record was retained",
      "/queries/3 的 KICS 查詢缺少 files 陣列；原始記錄已保留",
    ],
    [
      "KICS file at /queries/4/files/0 was not an object; the raw record was retained",
      "/queries/4/files/0 的 KICS 檔案記錄不是物件；原始記錄已保留",
    ],
    [
      "Trivy result at /Results/2 was not an object; the raw record was retained",
      "/Results/2 的 Trivy 結果不是物件；原始記錄已保留",
    ],
    [
      "Trivy Secrets at /Results/0/Secrets was present but not an array; the raw value was retained",
      "/Results/0/Secrets 的 Trivy Secrets 已存在但不是陣列；原始值已保留",
    ],
    [
      "Grype match at /matches/1 was not an object; the raw record was retained",
      "/matches/1 的 Grype 配對記錄不是物件；原始記錄已保留",
    ],
    [
      "Grype match at /matches/2 lacked vulnerability.id; the raw record was retained",
      "/matches/2 的 Grype 配對記錄缺少 vulnerability.id；原始記錄已保留",
    ],
  ] as const;

  for (const [english, zhTW] of cases) {
    assert.equal(recognizedEngineWarningZhTW(english), zhTW);
  }
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
