import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// `RuntimeSetupAssistant` is read *instead of* a result, and two of its
// sentences describe a report the user has not opened yet. Nothing bound either
// one to the code that builds that report, and both had drifted:
//
//   - "Results will mark this check as not tested" was false in the way a user
//     would check it. A missing or unverifiable packaged runtime fails at
//     preflight, which sets `EngineRunStatus::Failed`, so the gap kind is
//     `Failed` and the tile labelled "Not tested" on the findings page reads 0.
//     The check is listed -- under the heading "What was not tested" -- but it
//     is labelled "Stopped with an error" and counted as failed.
//   - "Other available checks can continue" was false by construction.
//     `no_runnable_authorized_targets` is raised only when the runnable count
//     over the *compatible* engines is zero, so there is no sibling check left
//     to continue. `App.tsx` already said the honest thing for the same blocker
//     code; the setup panel contradicted it.
//
// The copy now states what the code guarantees. These tests fail if either side
// moves: if the panel over-claims again, or if the report stops listing an
// unrunnable check where the panel says it will appear.

const read = (relative: string) => readFileSync(new URL(relative, import.meta.url), "utf8");

const panel = read("../../src/components/RuntimeSetupAssistant.tsx");
const findingsPage = read("../../src/pages/FindingsPage.tsx");
const appSource = read("../../src/App.tsx");
const beginnerReport = read("../../src-tauri/src/beginner_report.rs");
const caseService = read("../../src-tauri/src/case_service.rs");
// Cut at the test *module*, not at the first `#[cfg(test)]`. `case_service.rs`
// carries `#[cfg(test)]` attributes on individual items from line 1818, so
// slicing on the attribute drops 27,000 lines including everything asserted
// below -- and would do it silently if the remaining text happened to match.
const production = (rust: string) => {
  const index = rust.indexOf("#[cfg(test)]\nmod tests {");
  assert.notEqual(index, -1, "the test module marker was not found; this slice is stale");
  return rust.slice(0, index);
};

/** Keeps a failed assertion readable: a whole-file dump hides which line moved. */
const region = (source: string, from: string, lines: number): string => {
  const start = source.indexOf(from);
  assert.notEqual(start, -1, `region anchor not found: ${from}`);
  return source.slice(start).split("\n").slice(0, lines).join("\n");
};

test("the panel names the report heading the unrunnable check is actually listed under", () => {
  // The two literals have to be identical, per locale, or the sentence sends the
  // user looking for a section that is not there.
  const english = findingsPage.match(/gapsTitle: \{ en: "([^"]+)"/u)?.[1];
  const chinese = findingsPage.match(/gapsTitle: \{ en: "[^"]+", zhTW: "([^"]+)"/u)?.[1];
  assert.ok(english, "gapsTitle was not found; the extraction above is stale");
  assert.ok(chinese, "the Traditional Chinese gapsTitle was not found");
  assert.equal(english, "What was not tested");

  const nonRetryable = panel.match(/nonRetryableDescription: "([^"]+)"/u)?.[1];
  assert.ok(nonRetryable, "nonRetryableDescription was not found");
  assert.ok(
    nonRetryable.includes(english.toLowerCase()),
    `the panel must name the "${english}" section it promises the check appears in`,
  );
  assert.match(nonRetryable, /never as a pass/u);

  const chineseNonRetryable = panel.match(/nonRetryableDescription: "([^"]*[^\x00-\x7F][^"]*)"/u)?.[1];
  assert.ok(chineseNonRetryable, "the Traditional Chinese nonRetryableDescription was not found");
  assert.ok(
    chineseNonRetryable.includes(chinese),
    `the Traditional Chinese panel must name the "${chinese}" section`,
  );
});

test("the panel does not claim the counter that this failure path leaves at zero", () => {
  // Preflight failure -> Failed -> the `failed` counter, not `notTested`. A
  // sentence promising the "Not tested" count would be contradicted by the tile
  // sitting next to the gap.
  assert.match(
    region(production(beginnerReport), "    match task.status {", 14),
    /EngineRunStatus::Failed => CoverageDimensionStatus::Failed/u,
  );
  assert.match(
    region(production(caseService), "PersistedPreDispatchTaskOutcome::Failed { reason, .. } => {", 8),
    /engine_run\.status = EngineRunStatus::Failed;/u,
  );
  assert.match(findingsPage, /notTestedCount: \{ en: "Not tested"/u);

  const nonRetryable = panel.match(/nonRetryableDescription: "([^"]+)"/u)?.[1] ?? "";
  assert.doesNotMatch(nonRetryable, /mark this check as not tested|marked not tested/u);
});

test("every check that did not complete is listed, so the panel's promise has something to point at", () => {
  // The promise is only worth making because `append_task_gap` has no escape
  // hatch: every status other than tested-complete produces a gap, and the
  // dimension carries the check id.
  const report = production(beginnerReport);
  for (const status of [
    "CoverageDimensionStatus::Failed",
    "CoverageDimensionStatus::NotTested",
    "CoverageDimensionStatus::Cancelled",
    "CoverageDimensionStatus::TimedOut",
  ]) assert.ok(report.includes(`${status} => (`), `${status} has no gap arm`);
  assert.match(report, /dimension: format!\("\{\}: \{dimension\}", check_id\(task\)\)/u);
  assert.match(findingsPage, /report\.coverageGaps\.map\(\(gap, index\) => \{/u);
});

test("the no-runnable blocker means no sibling check survives, and the panel says so", () => {
  // Both halves are load-bearing: the count is taken over `compatible`, and the
  // blocker fires only at zero. Either one changing would make "no check in
  // this version can run for this target" wrong in the opposite direction.
  const readiness = region(production(caseService), "fn scan_readiness_at(", 120);
  assert.match(
    readiness,
    /let runnable_engine_count = compatible\s*\.iter\(\)\s*\.filter\(\|manifest\| engine_unavailable\(manifest, adapters\)\.is_none\(\)\)\s*\.count\(\);/u,
  );
  assert.match(
    readiness,
    /\} else if runnable_engine_count == 0 \{\s*\(\s*ScanReadinessState::NoRunnableAuthorizedTargets,/u,
  );

  const blocked = panel.match(
    /no_runnable_authorized_targets: \{\s*title: "[^"]+",\s*description: "([^"]+)"/u,
  )?.[1];
  assert.ok(blocked, "the no_runnable_authorized_targets description was not found");
  assert.doesNotMatch(blocked, /Other available checks can continue/u);
  assert.match(blocked, /No check in this version can run for this target/u);
  // The half that is kept: a run still persists and the report still names it.
  assert.match(blocked, /report will still name this coverage gap/u);
});

test("the setup panel and the readiness banner agree about the same blocker code", () => {
  // They render on different screens from the same `no_runnable_authorized_targets`
  // value. Disagreement here is invisible to anyone reading one screen.
  const banner = appSource.match(
    /no_runnable_authorized_targets: \{\s*en: "([^"]+)"/u,
  )?.[1];
  assert.ok(banner, "the App.tsx blocker copy was not found");
  assert.match(banner, /this version has no working scan tool for it/u);

  const blocked = panel.match(
    /no_runnable_authorized_targets: \{\s*title: "[^"]+",\s*description: "([^"]+)"/u,
  )?.[1] ?? "";
  for (const source of [banner, blocked]) {
    assert.doesNotMatch(source, /can continue|remain runnable/u);
  }
});
