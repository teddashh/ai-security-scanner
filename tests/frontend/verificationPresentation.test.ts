import assert from "node:assert/strict";
import test from "node:test";

import { affectedEngineCount, isOnlyMappingVersionDrift } from "../../src/verificationPresentation.ts";

test("mapping-version-only comparison limits are identified from native reason codes", () => {
  assert.equal(isOnlyMappingVersionDrift([]), false);
  assert.equal(isOnlyMappingVersionDrift([
    { code: "mapping_version_changed", engineId: "checkov" },
    { code: "mapping_version_changed", engineId: "semgrep" },
  ]), true);
  assert.equal(isOnlyMappingVersionDrift([
    { code: "mapping_version_changed", engineId: "checkov" },
    { code: "coordinate_not_completed", engineId: "semgrep" },
  ]), false);
});

test("affected engine count is distinct from issue and finding counts", () => {
  assert.equal(affectedEngineCount([
    { code: "mapping_version_changed", engineId: "checkov" },
    { code: "mapping_version_changed", engineId: "checkov" },
    { code: "mapping_version_changed", engineId: " semgrep " },
    { code: "mapping_version_changed" },
  ]), 2);
});
