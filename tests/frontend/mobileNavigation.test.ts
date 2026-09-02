import assert from "node:assert/strict";
import test from "node:test";

import {
  MOBILE_NAVIGATION_MEDIA_QUERY,
  reconcileMobileNavigationOpen,
} from "../../src/mobileNavigation.ts";

test("an open mobile drawer is synchronously non-modal after the viewport becomes desktop", () => {
  assert.equal(MOBILE_NAVIGATION_MEDIA_QUERY, "(max-width: 820px)");
  assert.equal(reconcileMobileNavigationOpen(true, true), true);
  assert.equal(reconcileMobileNavigationOpen(true, false), false);
});

test("viewport reconciliation never opens a closed drawer", () => {
  assert.equal(reconcileMobileNavigationOpen(false, true), false);
  assert.equal(reconcileMobileNavigationOpen(false, false), false);
});
