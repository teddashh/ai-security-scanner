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

test("live Kubernetes and immutable Kubernetes inputs keep distinct permission contracts", () => {
  const asset = { platform: "kubernetes" as const, internetExposed: false };

  assert.deepEqual(permittedModes(asset), ["inventory", "configuration"]);
  assert.deepEqual(suggestedModesForAsset(["configuration_assessment"], asset), [
    "inventory",
    "configuration",
  ]);

  const manifestSnapshot = {
    ...asset,
    localInputProfile: "kubernetes_manifests" as const,
  };
  assert.deepEqual(permittedModes(manifestSnapshot), ["local_artifact"]);
  assert.deepEqual(
    suggestedModesForAsset(["configuration_assessment"], manifestSnapshot),
    ["local_artifact"],
  );
});

test("an authorized asset remains selectable so a missing permission can be added", () => {
  assert.equal(isScopeEligible({ authorizationState: "pending" }), true);
  assert.equal(isScopeEligible({ authorizationState: "authorized" }), true);
  assert.equal(isScopeEligible({ authorizationState: "unknown" }), false);
  assert.equal(isScopeEligible({ authorizationState: "excluded" }), false);
});

test("a local questionnaire name cannot be approved before its immutable input is attached", () => {
  assert.equal(isScopeEligible({
    authorizationState: "pending",
    questionnairePlaceholder: true,
  }), false);
  assert.equal(isScopeEligible({
    authorizationState: "pending",
    questionnairePlaceholder: true,
    localInputProfile: "repository_working_tree",
  }), true);
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

test("an explicitly internal target receives the guided low-impact suggestion", () => {
  assert.deepEqual(
    suggestedModesForAsset(["low_impact_external_checks"], {
      platform: "external",
      internetExposed: false,
    }),
    ["low_impact_external"],
  );
});

test("low-impact stays the safe preset when active testing is also requested", () => {
  assert.deepEqual(
    suggestedModesForAsset([
      "low_impact_external_checks",
      "active_external_vulnerability_tests",
    ], {
      platform: "external",
      internetExposed: true,
    }),
    ["low_impact_external"],
  );
});
