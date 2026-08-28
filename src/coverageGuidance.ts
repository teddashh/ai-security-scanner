import type { Asset, LocalInputProfile } from "./types";
import type { UseCaseId } from "./useCases";

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

// Ordered by usefulness for a first low-impact inventory. A CIDR receives only
// as many ports as keep the frozen address/port set comfortably below the
// managed gateway's 10,000-endpoint ceiling.
const commonTcpServicePorts = [80, 443, 22, 445, 3389, 8080, 8443, 21, 25, 53, 110, 139, 143, 465, 587, 993, 995, 3306, 5432, 6379, 9100] as const;

const recommendedTcpPorts = (target: string): number[] => {
  const value = target.trim();
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$/u.exec(value);
  const ipv6 = value.includes(":") ? /\/(\d{1,3})$/u.exec(value) : null;
  if (!ipv4 && !ipv6) return [...commonTcpServicePorts];
  const prefix = Number((ipv4 ?? ipv6)?.[1]);
  const maximumPrefix = ipv4 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maximumPrefix) return [80, 443];
  const total = 2 ** Math.min(53, maximumPrefix - prefix);
  const addresses = ipv4 && prefix <= 30 ? Math.max(1, total - 2) : total;
  const safePortCount = Math.max(1, Math.floor(9_000 / addresses));
  return commonTcpServicePorts.slice(0, safePortCount);
};

export interface GuidedNetworkPreset {
  protocol: "https" | "tcp";
  ports: number[];
}

export interface GuidedNetworkRatePolicy {
  requestsPerSecond: number;
  concurrency: number;
  timeoutSeconds: number;
}

/**
 * A deployed website carries its declared HTTP(S) service separately. The
 * public-exposure and internal-system journeys are service inventories, so a
 * hostname must not silently collapse to HTTPS/443 simply because it can be
 * used as a web address.
 */
export const recommendedGuidedNetworkPreset = (
  _assessmentIntent: UseCaseId | undefined,
  _assetType: Asset["type"] | undefined,
  target: string,
): GuidedNetworkPreset => ({ protocol: "tcp", ports: recommendedTcpPorts(target) });

/**
 * Use the complete low-impact allowance so a normal home network is not
 * crawled one endpoint at a time. This changes pacing, not the selected
 * addresses or ports, and remains inside the frozen low-impact boundary.
 */
export const recommendedGuidedLowImpactRatePolicy = (): GuidedNetworkRatePolicy => ({
  requestsPerSecond: 25,
  concurrency: 10,
  timeoutSeconds: 3,
});

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
