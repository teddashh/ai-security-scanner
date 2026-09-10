import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { localizedDataQualityWarning } from "../../src/findingNarrative.ts";
import {
  localizedEngineWarning,
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
  // Preserve the numeric contract of count-bearing warnings. The generic
  // placeholder below intentionally remains nonnumeric for every other field.
  .replaceAll(/\{(?:total|retained|omitted)_findings\}/gu, "1")
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
    value.startsWith("One check") || value.startsWith("Saved run") ||
    value.startsWith("Finding "));
  assert.ok(warnings.length >= 6, `producer extractor found only ${warnings.length} data-quality warnings`);
  const untranslated = warnings.filter((warning) => localizedDataQualityWarning(warning, "zh-TW") === warning);
  assert.deepEqual(untranslated, [], `data-quality warnings without Chinese:\n${untranslated.join("\n")}`);
});

test("redaction placeholders and warnings from another build fall back unchanged", () => {
  for (const warning of ["[redacted engine warning]", "A warning from a later build."]) {
    assert.equal(recognizedEngineWarningZhTW(warning), undefined);
    assert.equal(localizedEngineWarning(warning, "zh-TW"), warning);
  }
  assert.equal(
    localizedDataQualityWarning("[redacted data-quality warning]", "zh-TW"),
    "[redacted data-quality warning]",
  );
});

test("Steampipe inventory warnings have exact Traditional Chinese presentations", () => {
  const pointer = "/rows/7";
  const cases = [
    [
      "Steampipe output was not its supported JSON document; the raw artifact was retained, and the inventory query should be retried",
      "Steampipe 輸出不是支援的 JSON 文件；原始成品已保留，請重試盤點查詢",
    ],
    [
      "Steampipe output lacked its rows array; the raw artifact was retained, and the inventory query should be retried",
      "Steampipe 輸出缺少 rows 陣列；原始成品已保留，請重試盤點查詢",
    ],
    [
      "Steampipe rows exceeded the record safety boundary; later inventory rows remain only as raw evidence",
      "Steampipe 資料列超過記錄安全界線；後續盤點資料列只保留為原始證據",
    ],
    [
      `Steampipe inventory record at ${pointer} was not an object and was not normalized`,
      `${pointer} 的 Steampipe 盤點記錄不是物件，因此未正規化`,
    ],
    [
      `Steampipe inventory record at ${pointer} lacked its account identifier and was not normalized`,
      `${pointer} 的 Steampipe 盤點記錄缺少帳號識別碼，因此未正規化`,
    ],
    [
      `Steampipe inventory record at ${pointer} did not identify an aws_iam_user and was not normalized`,
      `${pointer} 的 Steampipe 盤點記錄未識別為 aws_iam_user，因此未正規化`,
    ],
    [
      `Steampipe inventory record at ${pointer} carried an IAM user ARN outside its declared account and was not normalized`,
      `${pointer} 的 Steampipe 盤點記錄所含的 IAM 使用者 ARN 不屬於其宣告的帳號，因此未正規化`,
    ],
    [
      `Steampipe inventory record at ${pointer} was not the supported legacy IAM-user shape and was not normalized`,
      `${pointer} 的 Steampipe 盤點記錄不符合支援的舊版 IAM 使用者格式，因此未正規化`,
    ],
    [
      `Steampipe inventory record at ${pointer} lacked its IAM user ARN or user_id and was not normalized`,
      `${pointer} 的 Steampipe 盤點記錄未提供 IAM 使用者 ARN，也未提供 user_id，因此未正規化`,
    ],
  ] as const;

  for (const [english, zhTW] of cases) {
    assert.equal(recognizedEngineWarningZhTW(english), zhTW);
  }

  const engine = "Steampipe 2.1.0";
  assert.equal(
    recognizedEngineWarningZhTW(
      `${engine} output is inventory evidence; no security issue was invented from inventory rows`,
    ),
    `${engine} 輸出是資產清冊證據；未從清冊資料列臆造安全問題`,
  );

  const laterBuildWarning = `${cases[8][0]}; later-build detail`;
  assert.equal(localizedEngineWarning(laterBuildWarning, "zh-TW"), laterBuildWarning);
});

test("Cloudsplaining schema-drift warnings preserve actionable context in Traditional Chinese", () => {
  const cases = [
    ["Cloudsplaining output links were not an object; findings were preserved without those references", "Cloudsplaining 輸出的 links 不是物件；問題已保留，但不含那些參照"],
    ["Cloudsplaining output lacked its required links object; findings were preserved without those references", "Cloudsplaining 輸出缺少必要的 links 物件；問題已保留，但不含那些參照"],
    [
      "Cloudsplaining policy section customer_managed_policies was not an object; valid sibling findings were preserved",
      "Cloudsplaining 原則區段 customer_managed_policies 不是物件；已保留其他有效問題",
    ],
    ["Cloudsplaining output lacked required policy section inline_policies; valid sibling findings were preserved", "Cloudsplaining 輸出缺少必要的原則區段 inline_policies；已保留其他有效問題"],
    [
      "Cloudsplaining policy at /aws_managed_policies/policy was not an object; valid sibling findings were preserved",
      "/aws_managed_policies/policy 的 Cloudsplaining 原則不是物件；已保留其他有效問題",
    ],
    [
      "Cloudsplaining policy at /aws_managed_policies/policy did not carry its required boolean is_excluded value and was retained only as raw evidence",
      "/aws_managed_policies/policy 的 Cloudsplaining 原則缺少必要的布林 is_excluded 值，因此只保留在原始證據中",
    ],
    [
      "Cloudsplaining category at /aws_managed_policies/policy/DataExfiltration was not an object; valid sibling findings were preserved",
      "/aws_managed_policies/policy/DataExfiltration 的 Cloudsplaining 風險類別不是物件；已保留其他有效問題",
    ],
    [
      "Cloudsplaining policy at /customer_managed_policies/policy lacked category CredentialsExposure; valid sibling findings were preserved",
      "/customer_managed_policies/policy 的 Cloudsplaining 原則缺少風險類別 CredentialsExposure；已保留其他有效問題",
    ],
    [
      "Cloudsplaining category at /inline_policies/policy/ResourceExposure lacked its findings array; valid sibling findings were preserved",
      "/inline_policies/policy/ResourceExposure 的 Cloudsplaining 風險類別缺少 findings 陣列；已保留其他有效問題",
    ],
    [
      "Cloudsplaining category at /inline_policies/policy/InfrastructureModification lacked its source severity; valid sibling findings were preserved",
      "/inline_policies/policy/InfrastructureModification 的 Cloudsplaining 風險類別缺少來源嚴重性；已保留其他有效問題",
    ],
    [
      "Cloudsplaining category at /inline_policies/policy/ServiceWildcard lacked its source description; findings were preserved without it",
      "/inline_policies/policy/ServiceWildcard 的 Cloudsplaining 風險類別缺少來源說明；問題已保留，但不含該說明",
    ],
    [
      "Cloudsplaining PrivilegeEscalation category at /inline_policies/policy/PrivilegeEscalation lacked its required links object; findings were preserved without those references",
      "/inline_policies/policy/PrivilegeEscalation 的 Cloudsplaining 權限提升類別缺少必要的 links 物件；問題已保留，但不含那些參照",
    ],
    [
      "Cloudsplaining category links at /inline_policies/policy/PrivilegeEscalation/links were not an object; findings were preserved without those references",
      "/inline_policies/policy/PrivilegeEscalation/links 的 Cloudsplaining 風險類別 links 不是物件；問題已保留，但不含那些參照",
    ],
    [
      "Cloudsplaining finding at /inline_policies/policy/PrivilegeEscalation/findings/2 did not match the pinned PrivilegeEscalation entry shape and was retained only as raw evidence",
      "/inline_policies/policy/PrivilegeEscalation/findings/2 的 Cloudsplaining 問題不符合此版本採用的 PrivilegeEscalation 項目格式，因此只保留在原始證據中",
    ],
    [
      "Cloudsplaining finding at /inline_policies/policy/DataExfiltration/findings/2 did not match the pinned DataExfiltration entry shape and was retained only as raw evidence",
      "/inline_policies/policy/DataExfiltration/findings/2 的 Cloudsplaining 問題不符合此版本採用的 DataExfiltration 項目格式，因此只保留在原始證據中",
    ],
    [
      "Cloudsplaining privilege-escalation finding at /inline_policies/policy/PrivilegeEscalation/findings/0 lacked its required method link; the finding was preserved without that reference",
      "/inline_policies/policy/PrivilegeEscalation/findings/0 的 Cloudsplaining 權限提升問題缺少必要的方法參照連結；問題已保留，但不含該參照",
    ],
    [
      "Cloudsplaining action link for iam:CreateAccessKey was malformed; the finding was preserved without that reference",
      "Cloudsplaining 操作 iam:CreateAccessKey 的參照連結格式錯誤；問題已保留，但不含該參照",
    ],
    [
      "Cloudsplaining reported 10002 valid policy findings; the bounded report retained 10000 in Critical, High, Medium, Unknown, Low, then Informational order, and 2 remain only in raw evidence",
      "Cloudsplaining 回報 10002 筆有效的 IAM 原則問題；有界報告依重大、高、中、未知、低、資訊的優先順序保留 10000 筆，其餘 2 筆只保留在原始證據中",
    ],
  ] as const;

  for (const [english, zhTW] of cases) {
    assert.equal(recognizedEngineWarningZhTW(english), zhTW);
  }
  assert.equal(
    recognizedEngineWarningZhTW(
      "Cloudsplaining reported many valid policy findings; the bounded report retained all in Critical, High, Medium, Unknown, Low, then Informational order, and none remain only in raw evidence",
    ),
    undefined,
    "only the adapter's numeric cardinality warning is recognized as product-authored copy",
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
    "ScubaGear 未評估範圍內的所有控制措施（20 未回傳自動判定、5 無法評估）；這些控制措施未列於問題中，本輪也無法確認其狀態",
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
