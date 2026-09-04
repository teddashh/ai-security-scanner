import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  localizedCoverageDimension,
  localizedRequestedLimitName,
} from "../../src/coverageDimensionPresentation.ts";

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

const source = readFileSync(new URL("../../src-tauri/src/beginner_report.rs", import.meta.url), "utf8");
const production = source.slice(0, source.indexOf("#[cfg(test)]"));

/** Every coverage dimension the backend names with a fixed string. */
const staticDimensions = [
  ...new Set(Array.from(production.matchAll(/\bdimension: "([^"]+)"/gu), (match) => match[1])),
].sort();

test("the backend's dimension vocabulary was found", () => {
  // Guards the extraction itself: a regex that silently matched nothing would
  // make every assertion below vacuously true.
  assert.ok(staticDimensions.length >= 13, `found only ${staticDimensions.length} dimensions`);
  assert.ok(staticDimensions.includes("requested scan stage"));
  assert.ok(staticDimensions.includes("partly completed planned work units"));
});

test("every dimension the backend names has a Traditional Chinese label", () => {
  // Matched without the separator so this still fires if the fallback is ever
  // reshaped back into a label that simply replaces the name.
  const untranslated = staticDimensions.filter((dimension) =>
    localizedCoverageDimension(dimension, "zh-TW").startsWith("涵蓋範圍細節"),
  );
  assert.deepEqual(
    untranslated,
    [],
    `these dimensions reach a Traditional Chinese reader untranslated: ${untranslated.join(", ")}`,
  );
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

test("a dimension carrying an identifier keeps it rather than being replaced", () => {
  // Several names are composed at runtime around a check id, an engine id, or a
  // user-authored exclusion label. A fixed Chinese label substituted for one of
  // these discards the only part that identified the row, which is a worse
  // outcome than leaving the phrase untranslated.
  for (const composed of [
    "cloudquery granular executed scope",
    "naabu-tcp saved work-unit coverage",
    "requested check prowler",
    "Excluded by the project owner: legacy VPN appliance",
  ]) {
    assert.match(localizedCoverageDimension(composed, "zh-TW"), new RegExp(composed.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
    assert.equal(localizedCoverageDimension(composed, "en"), composed);
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

test("an unrecognized limit name keeps its text instead of being replaced", () => {
  assert.match(localizedRequestedLimitName("prowler concurrency ceiling", "zh-TW"), /prowler concurrency ceiling/u);
});
