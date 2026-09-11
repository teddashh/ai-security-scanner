import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The report's closed vocabularies are declared twice: once as a Rust enum the
// backend serializes, once as a TypeScript union the app narrows on. A variant
// added on one side and missed on the other compiles, passes every existing
// gate, and reaches the reader as an unhandled value -- a coverage row with no
// label, or a next step the page cannot name.
//
// Nothing else catches it. `tsconfig.app.json` includes only `src`, so a bad
// literal in a test is not even a type error, and the Rust side has no reason
// to know the union exists. This test reads both declarations.

const rust = (file: string) =>
  readFileSync(new URL(`../../src-tauri/src/${file}`, import.meta.url), "utf8");

const typescript = readFileSync(new URL("../../src/types.ts", import.meta.url), "utf8");

const beginnerReport = rust("beginner_report.rs");
const domain = rust("domain.rs");

/** Serde's `rename_all = "snake_case"`: lower-case, `_` before each capital. */
const serdeSnakeCase = (variant: string): string =>
  variant.replaceAll(/(?<!^)[A-Z]/gu, (capital) => `_${capital}`).toLowerCase();

/**
 * The variants of one `#[serde(rename_all = "snake_case")]` enum, as the wire
 * spells them.
 *
 * The attribute is required rather than assumed: an enum without it serializes
 * its variants verbatim, and comparing those against a snake_case union would
 * report drift that is not there -- or, worse, miss drift that is.
 */
const rustVariants = (source: string, name: string): string[] => {
  const declaration = source.indexOf(`pub enum ${name} {`);
  assert.ok(declaration > 0, `Rust enum ${name} was not found`);
  const attributes = source.slice(Math.max(0, declaration - 400), declaration);
  assert.ok(
    attributes.includes('#[serde(rename_all = "snake_case")]'),
    `${name} is compared as snake_case but does not declare it`,
  );
  const body = source.slice(declaration + `pub enum ${name} {`.length);
  const end = body.indexOf("\n}");
  assert.ok(end > 0, `Rust enum ${name} has no closing brace`);
  return body
    .slice(0, end)
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => /^[A-Z][A-Za-z0-9]*,$/u.test(line))
    .map((line) => serdeSnakeCase(line.slice(0, -1)));
};

/** The string members of one exported TypeScript string-union type. */
const unionMembers = (name: string): string[] => {
  const declaration = typescript.indexOf(`export type ${name} =`);
  assert.ok(declaration > 0, `TypeScript type ${name} was not found`);
  const body = typescript.slice(declaration);
  const end = body.indexOf(";");
  assert.ok(end > 0, `TypeScript type ${name} is not terminated`);
  return [...body.slice(0, end).matchAll(/"([^"]+)"/gu)].map((match) => match[1]!);
};

// Every closed vocabulary the app has to narrow on. A new one belongs here the
// day it is added, which is cheaper than the day a reader sees a blank label.
const PAIRS: ReadonlyArray<readonly [source: string, rustName: string, typescriptName: string]> = [
  ["beginner_report.rs", "CoverageGapKind", "BeginnerCoverageGapKind"],
  ["beginner_report.rs", "NextActionCode", "BeginnerNextActionCode"],
  ["beginner_report.rs", "CoverageDimensionStatus", "BeginnerCoverageStatus"],
  ["beginner_report.rs", "BeginnerReportSummary", "BeginnerReportSummary"],
  ["beginner_report.rs", "ReportScanStage", "BeginnerReportStage"],
  ["beginner_report.rs", "DataAvailability", "BeginnerReportDataAvailability"],
  ["domain.rs", "FindingFamily", "FindingFamily"],
];

for (const [file, rustName, typescriptName] of PAIRS) {
  test(`${rustName} and ${typescriptName} describe the same set of values`, () => {
    const fromRust = rustVariants(file === "domain.rs" ? domain : beginnerReport, rustName);
    const fromTypescript = unionMembers(typescriptName);

    assert.ok(fromRust.length > 1, `${rustName} extracted no variants`);
    // Sets, not sequences: the two files are free to declare in different
    // orders, and neither order reaches the reader.
    assert.deepEqual(
      [...fromRust].sort(),
      [...fromTypescript].sort(),
      `${rustName} and ${typescriptName} disagree`,
    );
  });
}

test("the extractor reads real variants, not whatever the regex allows", () => {
  // A silent extraction failure would make every assertion above pass by
  // comparing two empty sets, so the shapes it must find are named here.
  assert.deepEqual(rustVariants(beginnerReport, "CoverageGapKind"), [
    "not_tested",
    "failed",
    "timed_out",
    "cancelled",
    "excluded",
    "truncated",
    "unavailable",
    "unattributed",
    "manual_review",
  ]);
  // Digits stay attached to the word they belong to.
  assert.ok(rustVariants(domain, "FindingFamily").includes("microsoft365"));
  assert.deepEqual(unionMembers("BeginnerReportLifecycle"), ["final"]);
});
