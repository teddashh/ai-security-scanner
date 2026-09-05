import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The same sentences about a finding are written twice: TypeScript composes
// them for the findings pane, Rust composes them for the shared HTML report,
// because that report is produced as a file rather than rendered. Duplication
// is the price of that split; drift is not.
//
// Two people reading the same finding -- one on screen, one in the report they
// were sent -- being told different things is the failure that matters, and
// neither side's own tests can see it. This one reads both files.

const typescript = readFileSync(new URL("../../src/findingNarrative.ts", import.meta.url), "utf8");
const rustSource = readFileSync(
  new URL("../../src-tauri/src/finding_narrative.rs", import.meta.url),
  "utf8",
);

// The Rust test module asserts on Chinese fragments of its own, which are not
// translations and have no TypeScript counterpart.
const rust = rustSource.split("#[cfg(test)]")[0] ?? "";

const HAN = /\p{Script=Han}/u;

/**
 * Every Chinese string literal in a file, with interpolation collapsed.
 *
 * `${engineName}` and `{engine}` are the same hole in the same sentence, so the
 * two frames compare equal while the words around them still have to match
 * character for character.
 */
const chineseLiterals = (source: string): Set<string> => {
  const found = new Set<string>();
  // Double-quoted (both languages) and backtick template literals (TypeScript).
  for (const match of source.matchAll(/"((?:[^"\\]|\\.)*)"|`((?:[^`\\]|\\.)*)`/gu)) {
    const literal = match[1] ?? match[2] ?? "";
    if (!HAN.test(literal)) continue;
    found.add(literal.replaceAll(/\$\{[^}]*\}|\{[^}]*\}/gu, "⟦⟧").trim());
  }
  return found;
};

test("the report and the screen tell a reader the same thing", () => {
  const fromTypescript = chineseLiterals(typescript);
  const fromRust = chineseLiterals(rust);

  assert.ok(fromTypescript.size > 25, `extractor found only ${fromTypescript.size} strings`);
  assert.ok(fromRust.size > 25, `extractor found only ${fromRust.size} strings`);

  const onlyOnScreen = [...fromTypescript].filter((line) => !fromRust.has(line));
  const onlyInReport = [...fromRust].filter((line) => !fromTypescript.has(line));

  assert.deepEqual(
    onlyOnScreen,
    [],
    `wording the findings pane has and the shared report does not:\n${onlyOnScreen.join("\n")}`,
  );
  assert.deepEqual(
    onlyInReport,
    [],
    `wording the shared report has and the findings pane does not:\n${onlyInReport.join("\n")}`,
  );
});

test("the extractor can tell two translations apart", () => {
  // Guards the test above: if the normalization flattened everything, or the
  // regex matched nothing, both sets would be equal and empty and the parity
  // assertion would pass while saying nothing at all.
  const changed = typescript.replace("雲端資源或資料可能遭到未預期的存取、變更或使用", "雲端資源可能有風險");
  assert.notEqual(changed, typescript, "the sentence this guard edits has moved");
  const drifted = [...chineseLiterals(changed)].filter((line) => !chineseLiterals(rust).has(line));
  assert.ok(drifted.includes("雲端資源可能有風險"), drifted.join("\n"));
});
