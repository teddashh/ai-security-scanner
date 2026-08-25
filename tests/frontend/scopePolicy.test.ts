import assert from "node:assert/strict";
import test from "node:test";

import {
  isScopeEligible,
  permittedModes,
  suggestedModesForAsset,
} from "../../src/scopePolicy.ts";

test("configuration assessment requests the inventory prerequisite explicitly", () => {
  assert.deepEqual(
    suggestedModesForAsset(["configuration_assessment"], {
      platform: "aws",
      internetExposed: undefined,
    }),
    ["inventory", "configuration"],
  );
  assert.deepEqual(
    suggestedModesForAsset(["configuration_assessment"], {
      platform: "m365",
      internetExposed: undefined,
    }),
    ["inventory", "configuration"],
  );
});

test("Kubernetes scope matches the catalog permissions required by Kubescape and kube-bench", () => {
  const asset = { platform: "kubernetes" as const, internetExposed: false };

  assert.deepEqual(permittedModes(asset), ["inventory", "configuration"]);
  assert.deepEqual(suggestedModesForAsset(["configuration_assessment"], asset), [
    "inventory",
    "configuration",
  ]);
});

test("an authorized asset remains selectable so a missing permission can be added", () => {
  assert.equal(isScopeEligible({ authorizationState: "pending" }), true);
  assert.equal(isScopeEligible({ authorizationState: "authorized" }), true);
  assert.equal(isScopeEligible({ authorizationState: "unknown" }), false);
  assert.equal(isScopeEligible({ authorizationState: "excluded" }), false);
});

test("external activity is suggested only for an explicitly internet-exposed asset", () => {
  assert.deepEqual(
    suggestedModesForAsset(["active_external_vulnerability_tests"], {
      platform: "external",
      internetExposed: false,
    }),
    [],
  );
  assert.deepEqual(
    suggestedModesForAsset(["active_external_vulnerability_tests"], {
      platform: "external",
      internetExposed: true,
    }),
    ["active_external"],
  );
});
