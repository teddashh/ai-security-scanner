import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The frontend reaches the backend by naming a command string. Nothing checks
// that string: `invoke("suggest_finding_correlatoins")` compiles, ships, and
// fails only when a user opens the page. The two registries are written in
// different languages in different files, so they can drift silently in either
// direction -- a renamed Rust command, or a frontend entry added before the
// command was registered.
//
// Cross-boundary, so `src-tauri/src/lib.rs` and `src-tauri/src/commands.rs` are
// listed in FRONTEND_PATHS in scripts/ci/classify-changes.mjs.

const scanner = readFileSync(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");
const lib = readFileSync(new URL("../../src-tauri/src/lib.rs", import.meta.url), "utf8");
const commands = readFileSync(new URL("../../src-tauri/src/commands.rs", import.meta.url), "utf8");

/** Command strings the frontend can name, from the `COMMANDS` registry. */
const frontendCommands = (() => {
  const start = scanner.indexOf("const COMMANDS = {");
  assert.ok(start >= 0, "COMMANDS registry not found in scanner.ts");
  const end = scanner.indexOf("\n} as const;", start);
  assert.ok(end > start, "COMMANDS registry is unterminated");
  return Array.from(
    scanner.slice(start, end).matchAll(/^ {2}\w+: "([a-z0-9_]+)",$/gmu),
    (match) => match[1],
  ).sort();
})();

/** Commands registered with Tauri's invoke handler. */
const registeredCommands = (() => {
  const start = lib.indexOf("tauri::generate_handler![");
  assert.ok(start >= 0, "invoke handler not found in lib.rs");
  const end = lib.indexOf("\n        ])", start);
  assert.ok(end > start, "invoke handler is unterminated");
  return Array.from(
    lib.slice(start, end).matchAll(/^ {12}commands::(\w+),$/gmu),
    (match) => match[1],
  ).sort();
})();

test("both registries were read rather than matched empty", () => {
  // Guards every assertion below: comparing two empty sets always succeeds, so
  // an extraction that stopped matching would make this file prove nothing. The
  // floors are the counts at the time of writing (40 and 41); a partial match
  // would land under them rather than quietly checking a subset.
  assert.ok(frontendCommands.length >= 40, `found only ${frontendCommands.length} frontend commands`);
  assert.ok(registeredCommands.length >= 41, `found only ${registeredCommands.length} registered commands`);
  assert.ok(frontendCommands.includes("suggest_finding_correlations"));
  assert.ok(registeredCommands.includes("suggest_finding_correlations"));
});

test("every command the frontend can invoke is registered with Tauri", () => {
  const registered = new Set(registeredCommands);
  const missing = frontendCommands.filter((command) => !registered.has(command));
  assert.deepEqual(missing, [], `the frontend names commands the backend does not answer: ${missing.join(", ")}`);
});

test("every registered command is defined in the commands module", () => {
  // A stale entry in the handler list is a compile error in Rust, but the
  // reverse check keeps the extraction above honest: if the regex started
  // capturing something that is not a command, this fails.
  const defined = new Set(Array.from(
    commands.matchAll(/^pub (?:async )?fn (\w+)\(/gmu),
    (match) => match[1],
  ));
  const undeclared = registeredCommands.filter((command) => !defined.has(command));
  assert.deepEqual(undeclared, [], `handler names functions commands.rs does not define: ${undeclared.join(", ")}`);
});
