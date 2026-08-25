import assert from "node:assert/strict";
import test from "node:test";

import {
  providerCheckoutLimits,
  providerEngineBindings,
} from "../../src/providerAuthorizationPolicy.ts";

test("provider authorization UI requests the exact released engine capability sets", () => {
  assert.deepEqual(providerEngineBindings, {
    aws: [
      "provider-native-discovery",
      "cloudquery",
      "steampipe",
      "prowler",
      "scoutsuite",
      "cloudsplaining",
    ],
    azure: ["provider-native-discovery", "prowler"],
    gcp: ["provider-native-discovery", "prowler"],
    microsoft365: ["provider-native-discovery", "scubagear", "maester"],
  });
});

test("Azure and GCP authorize narrow Prowler without inheriting AWS-only engines", () => {
  const awsOnly = ["cloudquery", "steampipe", "scoutsuite", "cloudsplaining"];

  for (const provider of ["azure", "gcp"] as const) {
    assert.equal(providerEngineBindings[provider].includes("prowler"), true);
    for (const engineId of awsOnly) {
      assert.equal(providerEngineBindings[provider].includes(engineId), false);
    }
  }
});

test("provider checkout ceilings cover bounded executions without becoming unbounded", () => {
  assert.deepEqual(providerCheckoutLimits, {
    aws: 8,
    azure: 8,
    gcp: 1_001,
    microsoft365: 8,
  });
  assert.equal(providerCheckoutLimits.gcp, 1 + 1_000);
  assert.equal(providerCheckoutLimits.gcp > 1 + 9, true);
});
