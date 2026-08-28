import assert from "node:assert/strict";
import test from "node:test";

import {
  durationParts,
  estimateNetworkScanMinimum,
  ipv4CidrHostCount,
} from "../../src/networkScanEstimate.ts";

test("IPv4 CIDR host counts mirror the frozen backend boundary", () => {
  assert.equal(ipv4CidrHostCount("192.168.102.0/23"), 510);
  assert.equal(ipv4CidrHostCount("192.0.2.0/31"), 2);
  assert.equal(ipv4CidrHostCount("127.0.0.1/32"), 1);
  assert.equal(ipv4CidrHostCount("example.com"), undefined);
  assert.equal(ipv4CidrHostCount("300.0.0.0/24"), undefined);
  assert.equal(ipv4CidrHostCount("192.0.2.0/33"), undefined);
});

test("network estimates expose the pacing floor without claiming an ETA", () => {
  assert.deepEqual(
    estimateNetworkScanMinimum("192.168.102.0/23", 17, 1, 1, 60),
    {
      addressCount: 510,
      probeCount: 8_670,
      effectiveRequestsPerSecond: 1,
      minimumSeconds: 8_670,
      conservativeUpperSeconds: 531_420,
      engineCeilingSeconds: 14_400,
      mayExceedEngineCeiling: true,
    },
  );
  assert.deepEqual(durationParts(8_670), { hours: 2, minutes: 25 });
  assert.equal(estimateNetworkScanMinimum("192.168.102.0/23", 0, 1, 1, 60), undefined);
  assert.equal(estimateNetworkScanMinimum("192.168.102.0/23", 17, 0, 1, 60), undefined);
  assert.equal(estimateNetworkScanMinimum("192.168.102.0/23", 17, 1, 0, 60), undefined);
  assert.equal(estimateNetworkScanMinimum("192.168.102.0/23", 17, 1, 1, 0), undefined);
  assert.equal(estimateNetworkScanMinimum("192.168.102.0/23", 17, 1, 1.5, 60), undefined);
});

test("concurrency caps the effective pacing rate used by the estimate", () => {
  const estimate = estimateNetworkScanMinimum("192.168.102.0/23", 17, 25, 1, 60);
  assert.ok(estimate);
  assert.equal(estimate.effectiveRequestsPerSecond, 1);
  assert.equal(estimate.minimumSeconds, 8_670);
  assert.equal(estimate.mayExceedEngineCeiling, true);
});

test("a small fast scope reports when its conservative bound fits the host ceiling", () => {
  const estimate = estimateNetworkScanMinimum("127.0.0.1/32", 1, 25, 10, 5);
  assert.ok(estimate);
  assert.deepEqual(estimate, {
    addressCount: 1,
    probeCount: 1,
    effectiveRequestsPerSecond: 10,
    minimumSeconds: 1,
    conservativeUpperSeconds: 11,
    engineCeilingSeconds: 14_400,
    mayExceedEngineCeiling: false,
  });
});
