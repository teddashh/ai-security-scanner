import assert from "node:assert/strict";
import test from "node:test";

import { isProviderConfigurationBlocker } from "../../src/scanReadiness.ts";
import type { ScanReadinessBlocker } from "../../src/types.ts";

test("only fixable provider configuration blockers open cloud setup", () => {
  const providerConfigurationBlockers: ScanReadinessBlocker[] = [
    "provider_source_required",
    "provider_capability_unavailable",
    "provider_source_ambiguous",
    "provider_authorization_binding_mismatch",
    "provider_target_binding_mismatch",
  ];

  for (const blocker of providerConfigurationBlockers) {
    assert.equal(isProviderConfigurationBlocker(blocker), true, blocker);
  }

  assert.equal(isProviderConfigurationBlocker("provider_preflight_unavailable"), false);
  assert.equal(isProviderConfigurationBlocker("runtime_unavailable"), false);
  assert.equal(isProviderConfigurationBlocker(undefined), false);
});

