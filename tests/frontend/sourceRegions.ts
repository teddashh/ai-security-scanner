import assert from "node:assert/strict";

// Several tests here make a *containment* claim about rendered markup: this raw
// value is shown only inside that collapsed disclosure, never loose on the page
// beside it. The obvious way to write that is
//
//   assert.match(source, /<details className="x">[\s\S]*needle[\s\S]*<\/details>/u)
//
// and it does not work. The wildcard is unbounded, so the match begins at the
// *first* matching disclosure in the file and runs to the *last* `</details>`
// after the needle. On `FindingsPage.tsx` that single assertion accepted a
// 41,000-character span covering six separate disclosures and everything
// between them. Hoisting the fingerprint row out of its disclosure entirely --
// rendering it as bare markup where no reader has to expand anything -- left
// the assertion green.
//
// These helpers cut each disclosure at its own matching close instead. Depth is
// counted because the disclosures nest, and the open tag is read only as far as
// the line it starts on, because one of them carries a multi-line `onToggle`
// handler whose arrow would otherwise be mistaken for the end of the tag.

const DETAILS_TOKEN = /<details\b|<\/details>/gu;

export interface SourceRange {
  start: number;
  end: number;
}

/**
 * The character range of every `<details>` element in `source` whose open tag
 * mentions `className`, each running from `<details` to past its own matching
 * `</details>`.
 */
export const disclosureRanges = (source: string, className: string): SourceRange[] => {
  const ranges: SourceRange[] = [];
  const open: number[] = [];
  DETAILS_TOKEN.lastIndex = 0;
  for (let token = DETAILS_TOKEN.exec(source); token; token = DETAILS_TOKEN.exec(source)) {
    if (token[0] !== "</details>") {
      open.push(token.index);
      continue;
    }
    const start = open.pop();
    assert.notEqual(start, undefined, "a </details> closes nothing; this scan is stale");
    if (source.slice(start!).split("\n", 1)[0].includes(className)) {
      ranges.push({ start: start!, end: DETAILS_TOKEN.lastIndex });
    }
  }
  assert.equal(open.length, 0, "a <details> is never closed; this scan is stale");
  return ranges;
};

/**
 * Asserts that `needle` appears in `source` and that *every* occurrence of it
 * sits inside a `className` disclosure.
 *
 * Every, not any: `ProgressPage.tsx` renders the same raw engine field in two
 * places, so an assertion satisfied by one of them cannot notice the other
 * being lifted into plain view. Occurrences are compared by position rather
 * than counted, because these disclosures nest and a needle inside a nested one
 * would otherwise be tallied twice.
 *
 * Fails loudly when no such disclosure exists at all, so a renamed class turns
 * into an error rather than a containment claim that is vacuously unsatisfiable.
 */
export const assertInsideDisclosure = (
  source: string,
  className: string,
  needle: string,
): void => {
  const ranges = disclosureRanges(source, className);
  assert.ok(ranges.length > 0, `no <details> named "${className}" was found; this assertion is stale`);

  const positions: number[] = [];
  for (let at = source.indexOf(needle); at !== -1; at = source.indexOf(needle, at + 1)) {
    positions.push(at);
  }
  assert.ok(positions.length > 0, `"${needle}" does not appear at all; this assertion is stale`);

  const outside = positions.filter(
    (at) => !ranges.some((range) => at >= range.start && at < range.end),
  );
  const line = (at: number) => source.slice(0, at).split("\n").length;
  assert.deepEqual(
    outside.map(line),
    [],
    `"${needle}" renders outside all ${ranges.length} "${className}" disclosures, `
      + "where a reader sees it without expanding anything",
  );
};

/**
 * The `lines` lines of `source` starting at `anchor`.
 *
 * For assertions that need ordering rather than containment. A failure prints
 * the region instead of the whole file, which for a page source is the
 * difference between a readable diff and 60KB of noise.
 */
export const regionFrom = (source: string, anchor: string, lines: number): string => {
  const start = source.indexOf(anchor);
  assert.notEqual(start, -1, `region anchor not found: ${anchor}`);
  return source.slice(start).split("\n").slice(0, lines).join("\n");
};
