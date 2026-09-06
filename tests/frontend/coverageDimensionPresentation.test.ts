import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  localizedCoverageDimension,
  localizedRequestedLimitName,
} from "../../src/coverageDimensionPresentation.ts";
import {
  localizedRequestedLimitValue,
  testedObservationProse,
} from "../../src/findingNarrative.ts";

// A beginner-report coverage row is generated almost entirely from enumerations:
// its explanation comes from the gap's `kind` and its advice from the
// `nextActionCode`. The dimension name is the one part carrying which coverage
// the row is actually about, so two gaps sharing a kind are distinguishable by
// that string alone.
//
// The backend owns the vocabulary. Reading it back from the Rust source is the
// point of this test rather than a shortcut: a new dimension added there with no
// Chinese mapping is otherwise invisible until a Traditional Chinese reader sees
// a row that says nothing.

// Scoped to `beginner_report.rs` on purpose. `export.rs` also assigns gap
// dimensions -- redaction rewrites an excluded gap to "Excluded coverage area"
// -- but that path runs only in `beginner_report_for_export`. The report the UI
// renders comes from `commands.rs` calling `build_beginner_master_report`
// directly, unredacted, so export-only strings never reach this localizer.
// Widening this to `export.rs` would demand translations for strings no reader
// ever sees.
const source = readFileSync(new URL("../../src-tauri/src/beginner_report.rs", import.meta.url), "utf8");
const production = source.slice(0, source.indexOf("#[cfg(test)]"));

/** Every coverage dimension the backend names with a fixed string. */
const staticDimensions = [
  ...new Set(Array.from(production.matchAll(/\bdimension: "([^"]+)"/gu), (match) => match[1])),
].sort();

/** Every fixed tested-dimension observation the backend writes. */
const localhostObservationStart = production.indexOf("fn localhost_observation_text");
const localhostObservationEnd = production.indexOf(
  "fn selected_run_last_durable_update",
  localhostObservationStart,
);
const localhostObservationSource = production.slice(
  localhostObservationStart,
  localhostObservationEnd,
);
const testedObservations = [
  ...new Set([
    ...Array.from(
      production.matchAll(/\bobservation:\s*"([^"]+)"/gu),
      (match) => match[1] ?? "",
    ),
    ...Array.from(
      localhostObservationSource.matchAll(/"([^"]+)"/gu),
      (match) => match[1] ?? "",
    ),
  ]),
].sort();

/**
 * The names the backend composes at runtime, with a plausible identifier
 * substituted for each hole.
 *
 * These matter more than the fixed ones and were the whole blind spot in this
 * file's first version: it censused only `dimension: "..."`, which no composed
 * name matches, so sixteen shapes reached a Chinese reader as raw English while
 * the coverage assertion below passed. Every ordinary run emits at least one --
 * `{engine} granular executed scope` is written for every completed catalog
 * check.
 *
 * Three producers, because the backend writes a dimension three ways:
 *
 *  - `dimension: format!("…")` in a struct literal;
 *  - the second argument of `append_naabu_coverage_gaps`' local `push` closure,
 *    which is where ten of these live and where a `dimension:` search finds
 *    nothing at all;
 *  - `append_task_gap`, which composes `"{check}: {fragment}"` around six
 *    fragments chosen by a match arm, so the fragments come from the arm.
 */
const FORMAT_HOLE = /\{[^{}]*\}/gu;
/** A trailing "(…)" hole is a count everywhere the backend writes one. */
const fillHoles = (frame: string): string =>
  frame.replace(/\((\{[^{}]*\})\)$/u, "(3)").replaceAll(FORMAT_HOLE, "cloudquery");
const composedDimensions = [
  ...new Set([
    ...Array.from(
      production.matchAll(/\bdimension: format!\(\s*"([^"]+)"/gu),
      (match) => match[1] ?? "",
    ),
    ...Array.from(
      production.matchAll(
        /push\(\s*(?:CoverageGapKind::\w+|kind),\s*format!\(\s*"([^"]+)"/gu,
      ),
      (match) => match[1] ?? "",
    ),
  ])]
  // `"{}: {dimension}"` is `append_task_gap`'s frame, not a name; its six
  // fragments are enumerated below. `"{}: results for {provider} {identifier}"`
  // is the unattributed row, which `findingUnattributedGap` composes from the
  // structured payload rather than from this table.
  .filter((frame) => !/\{dimension\}|\{identifier\}/u.test(frame))
  .map(fillHoles)
  .concat(
    Array.from(
      production.matchAll(/CoverageGapKind::\w+,\s*\n\s*"([a-z][^"]*(?:dimension|dimensions))",/gu),
      (match) => `cloudquery: ${match[1]}`,
    ),
  )
  .filter((name, index, all) => all.indexOf(name) === index)
  .sort();

test("the backend's dimension vocabulary was found", () => {
  // Guards the extraction itself: a regex that silently matched nothing would
  // make every assertion below vacuously true.
  assert.ok(staticDimensions.length >= 13, `found only ${staticDimensions.length} dimensions`);
  assert.ok(staticDimensions.includes("requested scan stage"));
  assert.ok(staticDimensions.includes("partly completed planned work units"));

  assert.ok(
    composedDimensions.length >= 18,
    `found only ${composedDimensions.length} composed dimensions: ${composedDimensions.join(", ")}`,
  );
  for (const expected of [
    "cloudquery granular executed scope",
    "cloudquery failed work units (3)",
    "cloudquery final-state reconciliation",
    "cloudquery: not-tested check dimension",
    "requested check cloudquery",
  ]) {
    assert.ok(composedDimensions.includes(expected), `${expected} was not extracted`);
  }
});

test("every tested-dimension observation has a Traditional Chinese sentence", () => {
  // A lower bound, not an exact count: an eighth producer with a translation
  // is not a failure, and an eighth without one is caught below.
  assert.ok(
    testedObservations.length >= 7,
    `found only ${testedObservations.length} observations: ${testedObservations.join(" / ")}`,
  );
  assert.ok(testedObservations.includes("The port accepted the bounded TCP connection."));
  assert.ok(
    testedObservations.some((observation) => observation.includes("it is not a security pass")),
  );

  const untranslated = testedObservations.filter((observation) => {
    const translated = testedObservationProse("zh-TW", observation);
    return translated === observation || !/\p{Script=Han}/u.test(translated);
  });
  assert.deepEqual(
    untranslated,
    [],
    `these observations reach a Traditional Chinese reader untranslated: ${untranslated.join(" / ")}`,
  );
  for (const observation of testedObservations) {
    assert.equal(testedObservationProse("en", observation), observation);
  }
});

test("the row's sentence is the backend's, not one derived from the kind", () => {
  // The backend assigns `CoverageGapKind::NotTested` to several different
  // situations and writes a distinct `reason` for each -- a check that saved
  // partial work, one that never started, one still running. So a sentence
  // composed from the kind is false for all but one of them and contradicts
  // the dimension rendered beside it on the same row.
  const notTestedProducers = [
    ...production.matchAll(/CoverageGapKind::NotTested,\s*\n\s*"([^"]+)",\s*\n\s*"([^"]+)"/gu),
  ].map((match) => ({ dimension: match[1], reason: match[2] }));
  assert.ok(
    notTestedProducers.length >= 2,
    `found ${notTestedProducers.length} not-tested producers; the extraction above is stale`,
  );
  // The premise: they do not agree on a cause, so no single sentence can name
  // one. This fires only when *every* producer collapses onto one reason.
  assert.ok(
    new Set(notTestedProducers.map((producer) => producer.reason)).size > 1,
    "the producers now share one reason; a kind-derived sentence could become specific again",
  );

  // The conclusion, checked at the render rather than in the copy: the row
  // shows `gap.reason`. A per-kind sentence would pass any assertion about its
  // own wording while still being the wrong sentence for two rows in three.
  const findingsPage = readFileSync(
    new URL("../../src/pages/FindingsPage.tsx", import.meta.url),
    "utf8",
  );
  assert.match(findingsPage, /coverageGapProse\(locale, gap\.reason\)/u);
  assert.match(findingsPage, /coverageGapProse\(locale, gap\.nextAction\)/u);
  assert.ok(
    !/gapReasonCopy/u.test(findingsPage),
    "the kind-derived sentence is back on the row",
  );
});

test("every dimension the backend names has a Traditional Chinese label", () => {
  // Matched without the separator so this still fires if the fallback is ever
  // reshaped back into a label that simply replaces the name.
  const untranslated = [...staticDimensions, ...composedDimensions].filter((dimension) =>
    localizedCoverageDimension(dimension, "zh-TW").startsWith("涵蓋範圍細節"),
  );
  assert.deepEqual(
    untranslated,
    [],
    `these dimensions reach a Traditional Chinese reader untranslated: ${untranslated.join(", ")}`,
  );
});

test("a composed name is translated without losing the identifier it carries", () => {
  // Both halves matter and each fails differently. Dropping the identifier
  // leaves several rows on one run reading identically; leaving the phrase in
  // English leaves the row unreadable. The first version of this file tested
  // only the second half, and passed while every composed name was English.
  for (const dimension of composedDimensions) {
    const label = localizedCoverageDimension(dimension, "zh-TW");
    const identifier = dimension.includes("requested check ") ? "cloudquery" : "cloudquery";
    assert.ok(label.includes(identifier), `${dimension} lost its identifier: ${label}`);
    assert.ok(/\p{Script=Han}/u.test(label), `${dimension} was not translated: ${label}`);
    // The English kind is what a fallback would have left behind.
    const kind = dimension.replaceAll("cloudquery", "").replaceAll(/[:()\d]/gu, "").trim();
    assert.ok(kind.length > 0, `the extraction produced no kind for ${dimension}`);
    assert.ok(!label.includes(kind), `${dimension} kept its English wording: ${label}`);
  }
});

test("two checks reporting the same kind of gap stay apart", () => {
  // A run with three engines produces three "failed work units" rows. Replacing
  // the composed name with a fixed label would make them one row repeated.
  const labels = ["trivy", "prowler", "gitleaks"].map((engine) =>
    localizedCoverageDimension(`${engine} failed work units (2)`, "zh-TW"),
  );
  assert.equal(new Set(labels).size, 3, `rows collapsed: ${labels.join(" / ")}`);
  assert.ok(labels.every((label) => label.includes("（2）")), labels.join(" / "));
});

test("no two dimensions collapse into the same Traditional Chinese label", () => {
  // "completed planned work units" and "partly completed planned work units"
  // are reported as adjacent rows on the same check. Sharing a label leaves a
  // reader two identical rows and no way to tell finished work from work that
  // stopped early.
  const byLabel = new Map<string, string[]>();
  for (const dimension of staticDimensions) {
    const label = localizedCoverageDimension(dimension, "zh-TW");
    byLabel.set(label, [...(byLabel.get(label) ?? []), dimension]);
  }
  const collisions = [...byLabel.entries()].filter(([, dimensions]) => dimensions.length > 1);
  assert.deepEqual(
    collisions,
    [],
    `these dimensions are indistinguishable in Traditional Chinese: ${JSON.stringify(collisions)}`,
  );
});

test("English readers see the dimension the backend wrote, unaltered", () => {
  for (const dimension of staticDimensions) {
    assert.equal(localizedCoverageDimension(dimension, "en"), dimension);
  }
});

test("a name this product did not author keeps its own text", () => {
  // A case exclusion's dimension is the label a person typed. There is nothing
  // to translate and no shape to match, so it has to survive whole: a fixed
  // Chinese label substituted for it discards the only part that identified the
  // row. Untranslated detail beats fluent erasure.
  for (const authored of [
    "Excluded by the project owner: legacy VPN appliance",
    "S3 buckets in the archive account",
  ]) {
    assert.match(
      localizedCoverageDimension(authored, "zh-TW"),
      new RegExp(authored.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"),
    );
    assert.equal(localizedCoverageDimension(authored, "en"), authored);
  }
});

test("limits belonging to different grants stay attributable", () => {
  // The backend composes most limit names as "<engine or asset id> <kind>". A
  // case authorizing three targets produces three "approved ports" limits that
  // differ only by that identifier, so dropping it leaves three rows a reader
  // cannot attribute to anything.
  const names = [
    "asset-primary approved ports",
    "asset-secondary approved ports",
    "asset-lab approved ports",
  ];
  const labels = names.map((name) => localizedRequestedLimitName(name, "zh-TW"));
  assert.equal(new Set(labels).size, names.length, `limits collapsed: ${labels.join(" / ")}`);
  for (const [index, label] of labels.entries()) {
    assert.match(label, /允許檢查的連接埠/u);
    assert.ok(label.includes(names[index].replace(" approved ports", "")), label);
  }
});

test("limit names the backend does not compose are translated as they are", () => {
  // Three limit names are fixed strings rather than composed ones, so they
  // reach neither the suffix rules nor the fallback.
  for (const [name, expected] of [
    ["endpoint", "連線端點"],
    ["connection timeout", "連線逾時限制"],
    ["application payload", "應用資料量"],
  ] as const) {
    assert.equal(localizedRequestedLimitName(name, "zh-TW"), expected);
    assert.equal(localizedRequestedLimitName(name, "en"), name);
  }
});

test("a composed limit whose identifier is empty gains no empty decoration", () => {
  // `format!("{} approved ports", grant.asset_id)` degrades to a bare suffix if
  // the grant carries no asset id. The suffix rules still match, so without a
  // guard the label would render as "允許檢查的連接埠（）".
  for (const [suffix, expected] of [
    ["approved ports", "允許檢查的連接埠"],
    ["execution timeout", "檢查逾時限制"],
  ] as const) {
    assert.equal(localizedRequestedLimitName(suffix, "zh-TW"), expected);
    assert.equal(localizedRequestedLimitName(` ${suffix}`, "zh-TW"), expected);
  }
});

/**
 * Every limit name the backend writes, with an identifier substituted for the
 * hole a composed one carries. Eight producers, three of them fixed strings.
 *
 * Read from the producer for the same reason the dimensions are: the fixed
 * list above was written by hand, and a limit added to the backend with no
 * Chinese mapping would pass it while reaching a reader as "本輪使用的限制：
 * <English>". The Rust side asserts the same thing in debug builds.
 */
const limitNames = [
  ...new Set([
    ...Array.from(production.matchAll(/\bname: "([^"]+)"\.into\(\)/gu), (match) => match[1] ?? ""),
    ...Array.from(
      production.matchAll(/\bname: format!\(\s*"([^"]+)"/gu),
      (match) => (match[1] ?? "").replaceAll(FORMAT_HOLE, "asset-primary"),
    ),
  ]),
].sort();

const fillLimitFrame = (frame: string): string => {
  if (frame.includes("per second")) {
    let positional = 0;
    return frame.replaceAll(FORMAT_HOLE, () => positional++ === 0 ? "5" : "2");
  }
  return frame
    .replaceAll("{port}", "443")
    .replaceAll("{timeout_ms}", "250")
    .replaceAll("{payload_bytes}", "64")
    .replaceAll("{seconds}", "600")
    .replaceAll(FORMAT_HOLE, "600");
};

/** Every formatted limit value, kept beside the name that determines its role. */
const formattedLimitValues = Array.from(
  production.matchAll(/RequestedLimit\s*\{([\s\S]*?)source:\s*RequestedLimitSource::/gu),
  (match) => match[1] ?? "",
).flatMap((body) => {
  const fixedName = body.match(/\bname:\s*"([^"]+)"\.into\(\)/u)?.[1];
  const composedName = body.match(/\bname:\s*format!\(\s*"([^"]+)"/u)?.[1];
  const valueFrame = body.match(/\bvalue:\s*format!\(\s*"([^"]+)"/u)?.[1];
  if (!valueFrame || (!fixedName && !composedName)) return [];
  return [{
    name: fixedName ?? (composedName ?? "").replaceAll(FORMAT_HOLE, "asset-primary"),
    frame: valueFrame,
    value: fillLimitFrame(valueFrame),
  }];
});

const unitBearingLimitValues = formattedLimitValues.filter(({ value }) => /[A-Za-z]/u.test(value));

test("every limit name the backend writes is translated around its identifier", () => {
  assert.ok(limitNames.length >= 8, `found only ${limitNames.length} limit names: ${limitNames.join(", ")}`);
  assert.ok(limitNames.includes("endpoint"));
  assert.ok(limitNames.includes("asset-primary approved ports"));
  for (const name of limitNames) {
    const label = localizedRequestedLimitName(name, "zh-TW");
    assert.ok(!label.startsWith("本輪使用的限制："), `${name} reached a Chinese reader as English: ${label}`);
    assert.match(label, /\p{Script=Han}/u, label);
    if (name.startsWith("asset-primary")) {
      assert.ok(label.includes("asset-primary"), `${name} lost its identifier: ${label}`);
    }
    assert.equal(localizedRequestedLimitName(name, "en"), name);
  }
});

test("known requested-limit units are translated without changing their numbers", () => {
  for (const [name, value, expected] of [
    ["connection timeout", "250 ms", "250 毫秒"],
    ["application payload", "64 bytes", "64 位元組"],
    ["gitleaks execution timeout", "600 seconds", "600 秒"],
    ["asset-primary request rate", "5 per second, concurrency 2", "每秒 5 次，並行 2"],
  ] as const) {
    assert.equal(localizedRequestedLimitValue(name, value, "zh-TW"), expected);
    assert.equal(localizedRequestedLimitValue(name, value, "en"), value);
  }
  for (const [name, value] of [
    ["endpoint", "127.0.0.1:443"],
    ["asset-primary approved ports", "80,443"],
    ["asset-primary authorized network target", "example.test"],
    ["future limit", "value from another build"],
  ] as const) {
    assert.equal(localizedRequestedLimitValue(name, value, "zh-TW"), value);
  }
});

test("every unit-bearing limit value frame in the backend is translated", () => {
  // Five producer slots currently use four unit shapes. Keep both numbers as
  // lower bounds so adding a translated producer or reusing a shape is valid.
  assert.ok(
    unitBearingLimitValues.length >= 5,
    `found only ${unitBearingLimitValues.length} unit-bearing frames: ${unitBearingLimitValues.map(({ frame }) => frame).join(" / ")}`,
  );
  assert.ok(new Set(unitBearingLimitValues.map(({ value }) => value)).size >= 4);
  for (const { name, value } of unitBearingLimitValues) {
    const translated = localizedRequestedLimitValue(name, value, "zh-TW");
    assert.notEqual(translated, value, `${name} kept its English unit: ${value}`);
    assert.match(translated, /\p{Script=Han}/u, translated);
    assert.equal(localizedRequestedLimitValue(name, value, "en"), value);
  }
});

test("an unrecognized limit name keeps its text instead of being replaced", () => {
  assert.match(localizedRequestedLimitName("prowler concurrency ceiling", "zh-TW"), /prowler concurrency ceiling/u);
});
