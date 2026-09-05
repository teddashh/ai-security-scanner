import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import { classifyChangedPaths } from "../../scripts/ci/classify-changes.mjs";

// Several frontend tests read a Rust source directly, because the contract they
// check spans the boundary: what vocabulary the beginner report emits, which
// engine-run status a preflight failure produces, whether a Tauri command still
// exists. Those tests live in the frontend lane, and the frontend lane runs only
// when `classify-changes.mjs` says a frontend path changed.
//
// So a backend-only commit that breaks such a contract runs the Rust lane and
// *skips the lane holding the test that would have caught it*. CI stays green.
// Nothing about the test looks wrong; it simply never executes. Each missing
// entry has so far been noticed by hand, one at a time, after the fact.
//
// This guard derives the requirement instead. It reads what the tests actually
// open and asserts the classifier agrees, in both directions: no read outside
// the lane's own blanket rules goes unlisted, and no listed backend file has
// stopped being read.
//
// It lives in `tests/ci/` because that lane is always on. See the sibling
// classifier test for why this directory may import only `node:` builtins.

const repoRoot = new URL("../../", import.meta.url);

const testFiles = [
  ...readdirSync(new URL("../frontend/", import.meta.url), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.includes(".test."))
    .map((entry) => new URL(`../frontend/${entry.name}`, import.meta.url)),
  ...readdirSync(new URL("../component/", import.meta.url), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.includes(".test."))
    .map((entry) => new URL(`../component/${entry.name}`, import.meta.url)),
];

// Deliberately not keyed on `new URL(...)`. Tests wrap that call in a local
// helper often enough that matching the call site misses real reads -- the very
// test that prompted this guard reads `case_service.rs` through a one-line
// `read()` helper and would have been invisible.
const relativeLiteral = /["'](\.\.\/[^"'\n]*)["']/gu;

const readsByTest = new Map();
for (const file of testFiles) {
  const source = readFileSync(file, "utf8");
  const name = file.href.slice(repoRoot.href.length);
  for (const [, literal] of source.matchAll(relativeLiteral)) {
    const resolved = new URL(literal, file);
    if (!resolved.href.startsWith(repoRoot.href)) continue;
    // Fixture data can look like a relative path -- `nativeAdapter.test.ts`
    // carries a `../private/person@example.com?token=secret` redaction sample.
    // Only something that exists on disk is a read.
    if (!existsSync(resolved)) continue;
    const path = resolved.href.slice(repoRoot.href.length);
    if (!readsByTest.has(path)) readsByTest.set(path, new Set());
    readsByTest.get(path).add(name);
  }
}

/** The blanket rules already cover these; only reads outside them need an entry. */
const coveredByBlanketRule = (path) =>
  path.startsWith("src/") || path.startsWith("tests/frontend/") || path.startsWith("tests/component/");

test("the frontend lane runs for every file its own tests read", () => {
  assert.ok(readsByTest.size > 0, "no reads were extracted; the pattern above is stale");

  const unlisted = [...readsByTest]
    .filter(([path]) => !coveredByBlanketRule(path))
    .filter(([path]) => !classifyChangedPaths([path]).frontend)
    .map(([path, tests]) => `${path} (read by ${[...tests].sort().join(", ")})`);

  assert.deepEqual(
    unlisted,
    [],
    "add these to FRONTEND_PATHS in scripts/ci/classify-changes.mjs, or the tests reading them "
      + "will not run on a commit that changes only them",
  );
});

test("every backend file the classifier routes to the frontend lane is still read by a test", () => {
  // The mirror. Without it a stale entry survives a test deletion and keeps
  // running the frontend lane on unrelated backend commits forever, which is
  // how a lane stops meaning anything.
  const rustSources = [];
  const walk = (directory) => {
    for (const entry of readdirSync(new URL(directory, repoRoot), { withFileTypes: true })) {
      if (entry.isDirectory()) walk(`${directory}${entry.name}/`);
      else if (entry.name.endsWith(".rs")) rustSources.push(`${directory}${entry.name}`);
    }
  };
  walk("src-tauri/src/");
  assert.ok(rustSources.length > 50, "the Rust source walk found suspiciously little");

  const routedButUnread = rustSources
    .filter((path) => classifyChangedPaths([path]).frontend)
    .filter((path) => !readsByTest.has(path));

  assert.deepEqual(
    routedButUnread,
    [],
    "these are listed in FRONTEND_PATHS but no frontend or component test reads them; "
      + "remove the entry or restore the test",
  );
});
