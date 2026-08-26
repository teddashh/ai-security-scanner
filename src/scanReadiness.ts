import type { ScanReadinessBlocker } from "./types";

export type ProviderConfigurationBlocker =
  | "provider_source_required"
  | "provider_capability_unavailable"
  | "provider_source_ambiguous"
  | "provider_authorization_binding_mismatch"
  | "provider_target_binding_mismatch";

const providerConfigurationBlockers: ReadonlySet<ScanReadinessBlocker> = new Set([
  "provider_source_required",
  "provider_capability_unavailable",
  "provider_source_ambiguous",
  "provider_authorization_binding_mismatch",
  "provider_target_binding_mismatch",
]);

/** Provider configuration fixes stay on the selected case's cloud setup. */
export const isProviderConfigurationBlocker = (
  blocker: ScanReadinessBlocker | undefined,
): blocker is ProviderConfigurationBlocker => Boolean(
  blocker && providerConfigurationBlockers.has(blocker),
);

