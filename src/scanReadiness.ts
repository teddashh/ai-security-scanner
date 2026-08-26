import type { ScanReadinessBlocker } from "./types";

export type ProviderConfigurationBlocker =
  | "provider_source_required"
  | "provider_capability_unavailable"
  | "provider_source_ambiguous"
  | "provider_authorization_binding_mismatch"
  | "provider_target_binding_mismatch";

export type CoverageSetupFocus = "provider" | "workspace" | "source";

export type ScannerSetupBlocker =
  | "runtime_unavailable"
  | "egress_gateway_unavailable"
  | "engine_execution_contract_invalid";

export type ReadinessRetryBlocker =
  | "provider_preflight_unavailable"
  | "execution_preflight_unavailable";

export type CapturedEvidenceBlocker = "captured_evidence_unavailable";

const providerConfigurationBlockers: ReadonlySet<ScanReadinessBlocker> = new Set([
  "provider_source_required",
  "provider_capability_unavailable",
  "provider_source_ambiguous",
  "provider_authorization_binding_mismatch",
  "provider_target_binding_mismatch",
]);

const scannerSetupBlockers: ReadonlySet<ScanReadinessBlocker> = new Set([
  "runtime_unavailable",
  "egress_gateway_unavailable",
  "engine_execution_contract_invalid",
]);

const readinessRetryBlockers: ReadonlySet<ScanReadinessBlocker> = new Set([
  "provider_preflight_unavailable",
  "execution_preflight_unavailable",
]);

/** Provider configuration fixes stay on the selected case's cloud setup. */
export const isProviderConfigurationBlocker = (
  blocker: ScanReadinessBlocker | undefined,
): blocker is ProviderConfigurationBlocker => Boolean(
  blocker && providerConfigurationBlockers.has(blocker),
);

/** Open the exact Coverage input that can replace the unavailable source. */
export const coverageSetupFocusFor = (
  blocker: ScanReadinessBlocker | undefined,
): CoverageSetupFocus | undefined => {
  if (isProviderConfigurationBlocker(blocker)) return "provider";
  if (blocker === "workspace_snapshot_unavailable") return "workspace";
  if (blocker === "passive_source_unavailable") return "source";
  return undefined;
};

/** These blockers are repaired from the local scanner-setup assistant. */
export const isScannerSetupBlocker = (
  blocker: ScanReadinessBlocker | undefined,
): blocker is ScannerSetupBlocker => Boolean(
  blocker && scannerSetupBlockers.has(blocker),
);

/** A transient preflight failure should retry the check, not change setup. */
export const isReadinessRetryBlocker = (
  blocker: ScanReadinessBlocker | undefined,
): blocker is ReadinessRetryBlocker => Boolean(
  blocker && readinessRetryBlockers.has(blocker),
);

/** Missing saved evidence cannot be resumed; only an explicit fresh scan can replace it. */
export const isCapturedEvidenceBlocker = (
  blocker: ScanReadinessBlocker | undefined,
): blocker is CapturedEvidenceBlocker => blocker === "captured_evidence_unavailable";
