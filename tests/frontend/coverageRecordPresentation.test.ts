import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { localizedCoverageRecordDetail } from "../../src/findingNarrative.ts";

// Coverage explanations are authored in Rust and stored before the reader's
// locale is known. Read the producer rather than maintaining a hand-written
// inventory that can silently miss its next sentence.
const source = readFileSync(new URL("../../src-tauri/src/coverage.rs", import.meta.url), "utf8");
const production = source.slice(0, source.indexOf("#[cfg(test)]"));

const naturalLanguageFormatFrames = [
  ...new Set(Array.from(
    production.matchAll(/format!\(\s*"([^"]+)"/gu),
    (match) => match[1] ?? "",
  ).filter((frame) =>
    /[A-Za-z]/u.test(frame)
    && (/^[A-Z]/u.test(frame) || /^ [A-Z]/u.test(frame) || /^\{(?:reason|completion_summary)\}/u.test(frame))
    && (frame.includes(".") || frame.includes("Latest provider discovery"))
    && !frame.startsWith("built_in_localhost_tcp")
  )),
];

const incompleteFixedSentences = Array.from(
  production.matchAll(/return incomplete\([\s\S]*?\n\s*"([A-Z][^"]+\.)",\n\s*\);/gu),
  (match) => match[1] ?? "",
);
const directIntoSentences = Array.from(
  production.matchAll(/"([A-Z][^"]+\.)"\.into\(\)/gu),
  (match) => match[1] ?? "",
).filter((sentence) => sentence.includes("Coverage is not established"));

const reasonBlock = production.match(
  /let reason = if asset\.candidate[\s\S]*?"([^"]+)"[\s\S]*?else \{\s*"([^"]+)"[\s\S]*?\};/u,
);
const discoverySuffix = naturalLanguageFormatFrames.find((frame) => frame.startsWith("{reason} "));
const authorizationSentences = reasonBlock && discoverySuffix
  ? [reasonBlock[1], reasonBlock[2]].map((reason) => discoverySuffix.replace("{reason}", reason ?? ""))
  : [];

const fixedSentences = [
  ...new Set([...incompleteFixedSentences, ...directIntoSentences, ...authorizationSentences]),
];

const fillFrame = (frame: string): string => {
  if (frame.startsWith("The source is not currently connected")) {
    let hole = 0;
    return frame.replaceAll(/\{[^{}]*\}/gu, () => hole++ === 0 ? "offline" : "3");
  }
  if (frame.startsWith(" Latest provider discovery")) {
    return frame.replace("{code}", "provider_timeout").replace("{message}", "Provider response was late.");
  }
  if (frame.startsWith("{reason}")) {
    return frame.replace(
      "{reason}",
      "The discovered candidate has not had ownership and scope explicitly confirmed.",
    );
  }
  if (frame.includes("frozen authorization evidence")) {
    return frame.replace("{detail}", "grant-1=historical_scope_snapshot_missing");
  }
  if (frame.startsWith(" Explicit stale-knowledge warning")) {
    return frame.replace("{}", "scanner knowledge 2026-01-01 (support ended 2026-06-01)");
  }
  if (frame.startsWith(" Exact built-in localhost TCP attempt")) {
    return frame.replace("{}", "127.0.0.1:443=reachable");
  }
  if (frame.startsWith("All ")) return frame.replace("{}", "2");
  if (frame.startsWith("{completion_summary}")) {
    return frame
      .replace("{completion_summary}", "All 2 compatible engine run(s) planned for this asset completed.")
      .replaceAll("{}", "");
  }
  if (frame.startsWith("The authorized scan is incomplete")) {
    return frame.replace("{}", "scanner=failed");
  }
  return frame
    .replace("{retained_asset_count}", "3")
    .replaceAll(/\{[^{}]*\}/gu, "sample");
};

const formattedSentences = naturalLanguageFormatFrames.map(fillFrame);

test("the coverage-detail producer vocabulary was found", () => {
  // Lower bounds: adding a translated sentence or frame is valid, while every
  // newly extracted untranslated value is rejected by the census below.
  assert.ok(
    fixedSentences.length >= 6,
    `found only ${fixedSentences.length} fixed sentences: ${fixedSentences.join(" / ")}`,
  );
  assert.ok(
    naturalLanguageFormatFrames.length >= 12,
    `found only ${naturalLanguageFormatFrames.length} format frames: ${naturalLanguageFormatFrames.join(" / ")}`,
  );
  assert.ok(fixedSentences.some((sentence) => sentence.includes("no scan plan")));
  assert.ok(naturalLanguageFormatFrames.some((frame) => frame.includes("{retained_asset_count}")));
  assert.ok(naturalLanguageFormatFrames.some((frame) => frame.includes("Latest provider discovery")));
});

test("every coverage explanation sentence and format frame has a Traditional Chinese presentation", () => {
  for (const english of [...fixedSentences, ...formattedSentences]) {
    const translated = localizedCoverageRecordDetail(english, "zh-TW");
    assert.notEqual(translated, english, `coverage detail stayed English: ${english}`);
    assert.match(translated, /\p{Script=Han}/u, translated);
    assert.equal(localizedCoverageRecordDetail(english, "en"), english);
  }
});

test("dynamic coverage-detail shapes match the Rust presentation contract", () => {
  for (const [english, expected] of [
    [
      "The source area is explicitly outside this case: Legacy lab stays excluded. This is a scoped applicability statement, not a successful scan result.",
      "此來源範圍明確不在本案件內：Legacy lab stays excluded. 這是範圍適用性的說明，不是掃描成功的結果。",
    ],
    [
      "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; 17 prior asset observation(s) remain retained. Latest provider discovery: provider_timeout: Provider response was late.",
      "來源已連線，且最近一次可歸屬的探索未傳回任何資產。這不是掃描成功的結果；仍保留 17 筆先前的資產觀察結果。 最近一次供應商探索：provider_timeout: Provider response was late.",
    ],
    [
      "The source is not currently connected (status: credentials_expired). Its present coverage is unknown; 17 previously attributed asset(s) are retained but do not make the source green.",
      "來源目前未連線（狀態：credentials_expired）。目前的涵蓋未知；仍保留 17 筆先前歸屬的資產，但這不會讓來源顯示為綠色。",
    ],
    [
      "The scan's frozen authorization evidence is incomplete: grant-1=historical_scope_snapshot_missing. Live grants are never used to reconstruct historical scan permission.",
      "掃描中凍結的授權證據不完整：grant-1=historical_scope_snapshot_missing。絕不會用現行授權重建過去的掃描權限。",
    ],
    [
      "All 2 compatible engine run(s) planned for this asset completed. This state is independent of how many findings were reported. Explicit stale-knowledge warning: scanner knowledge 2026-01-01 (support ended 2026-06-01). Completion proves execution, not current knowledge.",
      "為此資產規劃的 2 項相容掃描工具工作皆已完成。 此狀態與回報了多少個問題無關。 明確的過時知識警告：scanner knowledge 2026-01-01 (support ended 2026-06-01)。完成只證明已執行，不代表知識仍為最新。",
    ],
    [
      "All 1 planned task(s) for this asset completed their exact declared dimensions. This state is independent of how many findings were reported. Exact built-in localhost TCP attempt(s): 127.0.0.1:443=reachable. This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
      "為此資產規劃的 1 項工作，皆已完成各自明確宣告的檢查範圍。 此狀態與回報了多少個問題無關。 精確的內建 localhost TCP 嘗試：127.0.0.1:443=reachable。這只記錄這些連線嘗試；無法證明服務或電腦安全，也不涵蓋其他連接埠或主機。",
    ],
    [
      "The authorized scan is incomplete: scanner=failed. Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
      "已授權的掃描未完成：scanner=failed。只有已完成且相容的目錄掃描工具工作，或精確完成的內建工作，才能產生已掃描涵蓋。",
    ],
  ] as const) {
    assert.equal(localizedCoverageRecordDetail(english, "zh-TW"), expected);
  }
});

test("coverage detail shapes preserve values carried by the stored sentence", () => {
  for (const [english, retained] of [
    [
      "The source area is explicitly outside this case: Legacy lab stays excluded. This is a scoped applicability statement, not a successful scan result.",
      "Legacy lab stays excluded.",
    ],
    [
      "The source is not currently connected (status: credentials_expired). Its present coverage is unknown; 17 previously attributed asset(s) are retained but do not make the source green.",
      "credentials_expired",
    ],
    [
      "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; 17 prior asset observation(s) remain retained.",
      "17",
    ],
    [
      "The source is connected, but no attributable discovery has completed and no assets are known. Coverage is not established. Latest provider discovery: provider_timeout: Keep this provider message verbatim.",
      "provider_timeout: Keep this provider message verbatim.",
    ],
  ] as const) {
    const translated = localizedCoverageRecordDetail(english, "zh-TW");
    assert.ok(translated.includes(retained), `${retained} was lost from ${translated}`);
    assert.match(translated, /\p{Script=Han}/u);
  }
});

test("a coverage sentence this build did not author stays untouched", () => {
  const future = "A later build records a different coverage explanation.";
  assert.equal(localizedCoverageRecordDetail(future, "zh-TW"), future);
});
