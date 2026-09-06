import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  controlMappingRationaleZhHant,
  localizedControlMappingRationale,
} from "../../src/findingNarrative.ts";

interface MappingCatalog {
  entries: Array<{ rationale: string }>;
}

const catalog = JSON.parse(readFileSync(
  new URL("../../mappings/control-mappings.json", import.meta.url),
  "utf8",
)) as MappingCatalog;

test("every reviewed catalog rationale has a Traditional Chinese presentation", () => {
  // A lower bound, not the catalog's size: the pinned hash is what guards
  // the entry list, and a reviewed twentieth entry should fail here only
  // if it arrives without Chinese.
  assert.ok(catalog.entries.length >= 19, `catalog has only ${catalog.entries.length} entries`);
  for (const { rationale } of catalog.entries) {
    const translated = controlMappingRationaleZhHant(rationale);
    assert.ok(translated, `no Traditional Chinese for catalog rationale: ${rationale}`);
    assert.match(translated, /\p{Script=Han}/u);
    assert.equal(localizedControlMappingRationale(rationale, "en"), rationale);
  }
});

test("a rationale from another build stays in its stored language", () => {
  const future = "A rationale from another build.";
  assert.equal(controlMappingRationaleZhHant(future), undefined);
  assert.equal(localizedControlMappingRationale(future, "zh-TW"), future);
});
