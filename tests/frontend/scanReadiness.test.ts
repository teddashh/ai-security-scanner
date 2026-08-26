import assert from "node:assert/strict";
import test from "node:test";

import {
  coverageSetupFocusFor,
  isCapturedEvidenceBlocker,
  isProviderConfigurationBlocker,
  isReadinessRetryBlocker,
  isScannerSetupBlocker,
} from "../../src/scanReadiness.ts";
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

test("execution readiness blockers open the exact safe recovery surface", () => {
  assert.equal(coverageSetupFocusFor("workspace_snapshot_unavailable"), "workspace");
  assert.equal(coverageSetupFocusFor("passive_source_unavailable"), "source");
  assert.equal(coverageSetupFocusFor("provider_source_required"), "provider");
  assert.equal(coverageSetupFocusFor("egress_gateway_unavailable"), undefined);

  assert.equal(isScannerSetupBlocker("egress_gateway_unavailable"), true);
  assert.equal(isScannerSetupBlocker("engine_execution_contract_invalid"), true);
  assert.equal(isScannerSetupBlocker("runtime_unavailable"), true);
  assert.equal(isScannerSetupBlocker("workspace_snapshot_unavailable"), false);

  assert.equal(isReadinessRetryBlocker("execution_preflight_unavailable"), true);
  assert.equal(isReadinessRetryBlocker("provider_preflight_unavailable"), true);
  assert.equal(isReadinessRetryBlocker("engine_execution_contract_invalid"), false);

  assert.equal(isCapturedEvidenceBlocker("captured_evidence_unavailable"), true);
  assert.equal(isCapturedEvidenceBlocker("workspace_snapshot_unavailable"), false);
});
