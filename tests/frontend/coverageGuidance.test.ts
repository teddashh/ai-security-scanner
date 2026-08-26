import assert from "node:assert/strict";
import test from "node:test";

import {
  matchesGuidedCoverageRoute,
  shouldPromptForFirstAsset,
  singleGuidedPendingAsset,
} from "../../src/coverageGuidance.ts";
import type { Asset } from "../../src/types.ts";

const asset = (overrides: Partial<Asset>): Asset => ({
  id: "asset-1",
  name: "Selected target",
  type: "ip",
  platform: "external",
  locator: "192.168.1.0/24",
  coverageState: "discovered_not_authorized",
  authorizationState: "pending",
  allowedModes: [],
  findingCount: 0,
  ...overrides,
});

test("a guided route preselects one exact matching item but never guesses between two", () => {
  const network = asset({ id: "network" });
  assert.equal(singleGuidedPendingAsset([network], { kind: "network" })?.id, "network");
  assert.equal(singleGuidedPendingAsset([
    network,
    asset({ id: "network-2" }),
  ], { kind: "network" }), undefined);

  const cloud = asset({ id: "cloud", platform: "azure", type: "subscription" });
  assert.equal(singleGuidedPendingAsset([network, cloud], { kind: "cloud" })?.id, "cloud");

  const code = asset({
    id: "code",
    platform: "code",
    type: "repository",
    localInputProfile: "repository_working_tree",
  });
  const iac = asset({
    id: "iac",
    platform: "code",
    type: "repository",
    localInputProfile: "iac_working_tree",
  });
  assert.equal(singleGuidedPendingAsset([code, iac], {
    kind: "local",
    profile: "iac_working_tree",
  })?.id, "iac");
});

test("guided matching never selects an already confirmed item or a different route", () => {
  const confirmedCloud = asset({
    platform: "aws",
    type: "cloud_account",
    authorizationState: "authorized",
  });
  assert.equal(matchesGuidedCoverageRoute(confirmedCloud, { kind: "cloud" }), false);
  assert.equal(matchesGuidedCoverageRoute(asset({}), { kind: "cloud" }), false);
  assert.equal(matchesGuidedCoverageRoute(asset({ platform: "gcp", type: "project" }), { kind: "none" }), false);
});

test("the choose-item prompt disappears as soon as a guided item is selected", () => {
  assert.equal(shouldPromptForFirstAsset(1, 0), true);
  assert.equal(shouldPromptForFirstAsset(1, 1), false);
  assert.equal(shouldPromptForFirstAsset(0, 0), false);
});
