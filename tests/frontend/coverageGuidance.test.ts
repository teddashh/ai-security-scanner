import assert from "node:assert/strict";
import test from "node:test";

import {
  hasExactGuidedCloudConsent,
  matchesGuidedCoverageRoute,
  recommendedGuidedNetworkPreset,
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

test("a signed-in cloud source cannot simplify consent for another account on the same platform", () => {
  const accountA = asset({
    id: "aws-account-a",
    platform: "aws",
    type: "cloud_account",
    discoveredFromSourceIds: ["aws-source-a"],
  });
  const sourceA = { sourceId: "aws-source-a", platform: "aws" as const };
  const sourceB = { sourceId: "aws-source-b", platform: "aws" as const };

  assert.equal(hasExactGuidedCloudConsent([accountA], sourceA), true);
  assert.equal(hasExactGuidedCloudConsent([accountA], sourceB), false);
  assert.equal(hasExactGuidedCloudConsent([
    accountA,
    asset({
      id: "aws-account-b",
      platform: "aws",
      type: "cloud_account",
      discoveredFromSourceIds: ["aws-source-b"],
    }),
  ], sourceA), false);
  assert.equal(hasExactGuidedCloudConsent([
    asset({ ...accountA, discoveredFromSourceIds: undefined }),
  ], sourceA), false);
  assert.equal(hasExactGuidedCloudConsent([
    asset({ ...accountA, discoveredFromSourceIds: ["aws-source-a", "aws-source-b"] }),
  ], sourceA), false);
});

test("the choose-item prompt disappears as soon as a guided item is selected", () => {
  assert.equal(shouldPromptForFirstAsset(1, 0), true);
  assert.equal(shouldPromptForFirstAsset(1, 1), false);
  assert.equal(shouldPromptForFirstAsset(0, 0), false);
});

test("a guided public domain starts with one runnable HTTPS service", () => {
  assert.deepEqual(
    recommendedGuidedNetworkPreset("external_ip_or_domain", "domain", "scanner.example.test"),
    { protocol: "https", ports: [443] },
  );
});

test("guided IP and CIDR targets retain a bounded conservative TCP inventory", () => {
  const address = recommendedGuidedNetworkPreset("external_ip_or_domain", "ip", "203.0.113.10");
  assert.equal(address.protocol, "tcp");
  assert.deepEqual(address.ports.slice(0, 3), [80, 443, 22]);
  assert.ok(address.ports.length > 2);

  const network = recommendedGuidedNetworkPreset("external_ip_or_domain", "ip", "192.0.2.0/24");
  assert.equal(network.protocol, "tcp");
  assert.ok(network.ports.length > 0);
  assert.ok(254 * network.ports.length < 10_000);

  const ipv6Network = recommendedGuidedNetworkPreset("internal_it_environment", "ip", "fd00::/119");
  assert.equal(ipv6Network.protocol, "tcp");
  assert.ok(512 * ipv6Network.ports.length < 10_000);
});

test("an internal hostname keeps the infrastructure-oriented TCP preset", () => {
  const preset = recommendedGuidedNetworkPreset(
    "internal_it_environment",
    "domain",
    "printer.home.arpa",
  );
  assert.equal(preset.protocol, "tcp");
  assert.deepEqual(preset.ports.slice(0, 3), [80, 443, 22]);
});
