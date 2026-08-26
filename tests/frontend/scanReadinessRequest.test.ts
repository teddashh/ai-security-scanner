import assert from "node:assert/strict";
import test from "node:test";

import {
  isCurrentScanReadinessRequest,
  isCurrentScanReadinessResponse,
} from "../../src/scanReadinessRequest.ts";

test("an older readiness response cannot overwrite a newer request", () => {
  assert.equal(isCurrentScanReadinessRequest(2, 1), false);
  assert.equal(isCurrentScanReadinessResponse(2, 1, "case-a", "case-a"), false);
  assert.equal(isCurrentScanReadinessResponse(2, 2, "case-b", "case-b"), true);
});

test("a response for another case is rejected even at the current generation", () => {
  assert.equal(isCurrentScanReadinessResponse(4, 4, "case-b", "case-a"), false);
  assert.equal(isCurrentScanReadinessResponse(4, 4, "case-b", "case-b"), true);
});
