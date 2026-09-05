import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The correlation report crosses the Rust/TypeScript boundary as JSON. Nothing
// type-checks that crossing: renaming a Rust field produces a compiling backend
// and a compiling frontend that read `undefined` from each other, and the
// Findings page would then render an empty coordinate as though the engines had
// agreed on nothing. These tests pin the field names on both sides so the drift
// fails here instead of in front of a user.
//
// Cross-boundary, so `src-tauri/src/correlation.rs` is listed in FRONTEND_PATHS
// in scripts/ci/classify-changes.mjs. Without that entry a backend-only commit
// would skip the lane holding this file.

const rust = readFileSync(new URL("../../src-tauri/src/correlation.rs", import.meta.url), "utf8");
const rustProduction = rust.slice(0, rust.indexOf("#[cfg(test)]"));
const typescript = readFileSync(new URL("../../src/types.ts", import.meta.url), "utf8");

const blockAfter = (source: string, header: string): string => {
  const start = source.indexOf(header);
  assert.ok(start >= 0, `declaration not found: ${header}`);
  const end = source.indexOf("\n}", start);
  assert.ok(end > start, `unterminated declaration: ${header}`);
  return source.slice(start + header.length, end);
};

const camel = (snake: string): string =>
  snake.replace(/_([a-z])/gu, (_match, letter: string) => letter.toUpperCase());

const rustFields = (structName: string): string[] =>
  Array.from(
    blockAfter(rustProduction, `pub struct ${structName} {`).matchAll(/^ {4}pub (\w+):/gmu),
    (match) => camel(match[1]),
  ).sort();

const typescriptFields = (interfaceName: string): string[] =>
  Array.from(
    blockAfter(typescript, `export interface ${interfaceName} {`).matchAll(/^ {2}(\w+)\??:/gmu),
    (match) => match[1],
  ).sort();

test("the field extraction reads real declarations rather than matching nothing", () => {
  // Guards every assertion below: two empty arrays compare equal, so a regex
  // that silently stopped matching would make this file vacuously pass.
  assert.ok(rustFields("FindingCorrelationSuggestion").length >= 10, "Rust suggestion fields");
  assert.ok(typescriptFields("FindingCorrelationSuggestion").length >= 10, "TypeScript suggestion fields");
  assert.ok(rustProduction.includes("rename_all = \"camelCase\""), "serde rename is what makes the comparison valid");
});

for (const name of ["FindingCorrelationSuggestion", "UnverifiableCorrelation", "CorrelationReport"]) {
  test(`${name} exposes the same fields to Rust and to TypeScript`, () => {
    assert.deepEqual(typescriptFields(name), rustFields(name));
  });
}

test("every corroboration status the backend can send has a TypeScript member", () => {
  // `CorroborationStatus` is serialized kebab-case. The frontend keys its
  // beginner-facing caveat off this union, so a new Rust variant must break the
  // build rather than fall through to no caveat at all.
  const variants = Array.from(
    blockAfter(rustProduction, "pub enum CorroborationStatus {").matchAll(/^ {4}([A-Z]\w+),/gmu),
    (match) => match[1].replace(/(?<!^)([A-Z])/gu, "-$1").toLowerCase(),
  ).sort();
  assert.ok(variants.length >= 1, "no enum variants extracted");

  const union = blockAfter(typescript, "export type CorroborationStatus =").split(";")[0];
  const declared = Array.from(union.matchAll(/"([a-z-]+)"/gu), (match) => match[1]).sort();
  assert.deepEqual(declared, variants);
});

test("the key schema version is not duplicated as a frontend literal", () => {
  // The version exists so a suggestion computed under an older rule is never
  // treated as equivalent to a newer one. A copy of the string in the frontend
  // would keep comparing equal after the backend bumped it.
  const version = rustProduction.match(/CORRELATION_KEY_SCHEMA_VERSION: &str = "([^"]+)"/u)?.[1];
  assert.ok(version, "schema version constant not found");
  const frontend = [
    "../../src/types.ts",
    "../../src/services/scanner.ts",
    "../../src/pages/FindingsPage.tsx",
    "../../src/App.tsx",
  ].map((path) => readFileSync(new URL(path, import.meta.url), "utf8")).join("\n");
  assert.ok(!frontend.includes(version), `${version} is hardcoded in the frontend`);
});
