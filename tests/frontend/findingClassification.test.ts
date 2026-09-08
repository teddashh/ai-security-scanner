import assert from "node:assert/strict";
import test from "node:test";

import { isExposureObservation, isSecurityFinding } from "../../src/findingClassification.ts";

test("reachability inventory is distinct from security findings", () => {
  for (const severityBasisCode of ["open_port", "reachable_http_service"] as const) {
    assert.equal(isExposureObservation({ severityBasisCode }), true);
    assert.equal(isSecurityFinding({ severityBasisCode }), false);
  }
  assert.equal(isSecurityFinding({ severityBasisCode: "secret_pattern_match" }), true);
  assert.equal(isSecurityFinding({}), true);
});
