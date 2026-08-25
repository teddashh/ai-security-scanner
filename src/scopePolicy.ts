import type { AssessmentActivity, Asset, ScopeMode } from "./types";

export const permittedModes = (asset: Pick<Asset, "platform">): ScopeMode[] => {
  if (asset.platform === "external") return ["public_data", "low_impact_external", "active_external"];
  if (["code", "container"].includes(asset.platform)) return ["local_artifact"];
  if (asset.platform === "kubernetes") return ["inventory", "configuration"];
  return ["inventory", "configuration"];
};

export const suggestedModesForAsset = (
  requestedActivities: readonly AssessmentActivity[],
  asset: Pick<Asset, "platform" | "internetExposed">,
): ScopeMode[] => {
  const available = new Set(permittedModes(asset));
  const requested = new Set(requestedActivities);
  const suggested: ScopeMode[] = [];

  // Configuration scanners also require a bounded inventory view. Both modes
  // remain visible in the confirmation form and are granted only on submit.
  if (requested.has("configuration_assessment") && available.has("configuration")) {
    if (available.has("inventory")) suggested.push("inventory");
    suggested.push("configuration");
  }
  if (requested.has("local_artifact_analysis") && available.has("local_artifact")) {
    suggested.push("local_artifact");
  }

  const requestedExternalMode = requested.has("active_external_vulnerability_tests")
    ? "active_external"
    : requested.has("low_impact_external_checks")
      ? "low_impact_external"
      : undefined;
  if (
    requestedExternalMode
    && available.has(requestedExternalMode)
    && asset.internetExposed === true
  ) {
    suggested.push(requestedExternalMode);
  }

  return suggested;
};

export const isScopeEligible = (asset: Pick<Asset, "authorizationState">): boolean =>
  asset.authorizationState === "pending" || asset.authorizationState === "authorized";
