import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// Choosing the public-records scope mode records a scope grant carrying
// `ScanPermission::PassiveExternalDiscovery`. An engine is attached to a run
// only if its manifest declares the grant's own permission --
// `compatible_authorized_assets` in `case_service.rs` filters on
// `required_permissions_satisfied_by`, and the per-engine grant filter in the
// planner repeats the check. No entry in `engines/catalog.json` declares that
// permission, so the grant authorises nothing that any shipped check can act
// on.
//
// The page's copy nonetheless offered to "Review public records" and said "This
// starts a public-record review". Public DNS and certificate records reach a
// project by importing a saved response -- both connectors are
// `live_discovery: false` -- not by starting a scan.
//
// This test derives the constraint from the catalog rather than pinning the
// wording, so it lifts by itself the day an engine declares the permission:
// then the copy is free to promise a review again, and the second assertion
// starts demanding that it does.

const catalog: { id?: string; required_permissions?: string[] }[] = JSON.parse(
  readFileSync(new URL("../../engines/catalog.json", import.meta.url), "utf8"),
);

const page = readFileSync(new URL("../../src/pages/CoveragePage.tsx", import.meta.url), "utf8");

/**
 * The three strings the public-records mode puts in front of a user, kept
 * separate by key.
 *
 * Not concatenated: asserting the stated limit against the joined text let one
 * string drop it while another still satisfied the match, and a mutation
 * removing it from the sentence shown at the moment of pressing the button
 * survived.
 */
const publicRecordsCopy = (): Record<string, string> => {
  const keys = [
    "publicRecordsGrantDescription",
    "publicRecordsBoundaryHelp",
    "publicRecordsStart",
  ];
  return Object.fromEntries(keys.map((key) => {
    const at = page.indexOf(`${key}:`);
    assert.notEqual(at, -1, `${key} was not found; this extraction is stale`);
    // Each entry is a `bilingual(...)` call; a few lines covers both locales
    // without letting the slice wander into the next key.
    return [key, page.slice(at).split("\n").slice(0, 5).join("\n")];
  }));
};

const declaresPassiveDiscovery = catalog.some((engine) =>
  (engine.required_permissions ?? []).includes("passive_external_discovery"),
);

test("the catalog was parsed and its permission vocabulary is intact", () => {
  // Guards the extraction: an empty parse would make the assertions below
  // vacuous in whichever direction happened to be cheap.
  assert.ok(catalog.length > 15, `only ${catalog.length} engines were parsed`);
  const declared = new Set(catalog.flatMap((engine) => engine.required_permissions ?? []));
  assert.ok(declared.has("inventory_read"), "no engine declares inventory_read; the parse is wrong");
  assert.ok(declared.size >= 4, `only ${declared.size} distinct permissions were found`);
});

test("public-record copy promises a review only if some engine could perform one", () => {
  const copy = publicRecordsCopy();
  const joined = Object.values(copy).join("\n");

  if (declaresPassiveDiscovery) {
    assert.match(
      joined,
      /review|Review/u,
      "an engine now declares passive_external_discovery, so this mode may describe the review it performs",
    );
    return;
  }

  for (const promise of [
    "Review public DNS",
    "starts a public-record review",
    '"Review public records"',
  ]) {
    assert.ok(
      !joined.includes(promise),
      `no engine declares passive_external_discovery, so the copy cannot say "${promise}"`,
    );
  }

  // The limit has to be stated, not merely left unsaid: a user picking this
  // mode over a direct connection is choosing it for coverage. Both surfaces
  // carry it independently -- the description while the mode is being chosen,
  // and the boundary help beside the button that starts the scan.
  for (const key of ["publicRecordsGrantDescription", "publicRecordsBoundaryHelp"]) {
    assert.match(
      copy[key],
      /No check in this version reads public records/u,
      `${key} no longer promises a review, but also no longer says the scan reads nothing`,
    );
  }
});
