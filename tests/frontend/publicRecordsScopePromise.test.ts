import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { permittedModes } from "../../src/scopePolicy.ts";

const catalog: { id?: string; required_permissions?: string[] }[] = JSON.parse(
  readFileSync(new URL("../../engines/catalog.json", import.meta.url), "utf8"),
);

const declaresPassiveDiscovery = catalog.some((engine) =>
  (engine.required_permissions ?? []).includes("passive_external_discovery"),
);

test("the catalog was parsed and its permission vocabulary is intact", () => {
  assert.ok(catalog.length > 15, `only ${catalog.length} engines were parsed`);
  const declared = new Set(catalog.flatMap((engine) => engine.required_permissions ?? []));
  assert.ok(declared.has("inventory_read"), "no engine declares inventory_read; the parse is wrong");
  assert.ok(declared.size >= 4, `only ${declared.size} distinct permissions were found`);
});

test("new external scan choices expose public records only when a scanner can run them", () => {
  const choices = permittedModes({ platform: "external" });
  assert.equal(
    choices.includes("public_data"),
    declaresPassiveDiscovery,
    declaresPassiveDiscovery
      ? "a scanner now accepts passive_external_discovery; expose its public-record mode"
      : "no scanner accepts passive_external_discovery; do not expose a scan mode that runs nothing",
  );
});
