import type { Asset, LocalInputProfile } from "./types";

export type GuidedCoverageRoute =
  | { kind: "network" }
  | { kind: "cloud" }
  | { kind: "local"; profile: LocalInputProfile }
  | { kind: "none" };

const cloudPlatforms = new Set<Asset["platform"]>(["aws", "azure", "gcp", "m365"]);

interface GuidedCloudConnection {
  sourceId: string;
  platform: Asset["platform"];
}

export const matchesGuidedCoverageRoute = (asset: Asset, route: GuidedCoverageRoute): boolean => {
  if (asset.authorizationState !== "pending") return false;
  if (route.kind === "network") return asset.platform === "external";
  if (route.kind === "cloud") return cloudPlatforms.has(asset.platform);
  if (route.kind === "local") return asset.localInputProfile === route.profile;
  return false;
};

export const singleGuidedPendingAsset = (
  assets: readonly Asset[],
  route: GuidedCoverageRoute,
): Asset | undefined => {
  const matching = assets.filter((asset) => matchesGuidedCoverageRoute(asset, route));
  return matching.length === 1 ? matching[0] : undefined;
};

export const shouldPromptForFirstAsset = (
  pendingAssetCount: number,
  selectedAssetCount: number,
): boolean => pendingAssetCount > 0 && selectedAssetCount === 0;

export const isCloudAsset = (asset: Pick<Asset, "platform">): boolean =>
  cloudPlatforms.has(asset.platform);

/**
 * Simplified cloud confirmation is safe only when the selected asset came from
 * this exact signed-in source. Same-provider accounts are not interchangeable,
 * and missing or multi-source provenance remains an explicit review path.
 */
export const hasExactGuidedCloudConsent = (
  selectedAssets: readonly Asset[],
  connection: GuidedCloudConnection | undefined,
): boolean => {
  if (!connection || selectedAssets.length !== 1) return false;
  const asset = selectedAssets[0];
  if (!asset || !isCloudAsset(asset) || asset.platform !== connection.platform) return false;
  return asset.discoveredFromSourceIds?.length === 1
    && asset.discoveredFromSourceIds[0] === connection.sourceId;
};
