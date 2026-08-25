export type Provider = "aws" | "azure" | "gcp" | "microsoft365";

/**
 * Exact engine capabilities requested by the provider authorization UI.
 * This must remain a subset of the matching Rust
 * `ProviderSourceProfile::allowed_engine_ids` contract.
 */
export const providerEngineBindings: Readonly<Record<Provider, readonly string[]>> = {
  aws: [
    "provider-native-discovery",
    "cloudquery",
    "steampipe",
    "prowler",
    "scoutsuite",
    "cloudsplaining",
  ],
  azure: ["provider-native-discovery", "prowler"],
  gcp: ["provider-native-discovery", "prowler"],
  microsoft365: ["provider-native-discovery", "scubagear", "maester"],
};

/**
 * A GCP organization can yield at most 1,000 records in one bounded live
 * capture. Reserve one checkout for that discovery and one exact-project
 * Prowler execution per record. Other profiles retain the smaller limit.
 */
export const providerCheckoutLimits: Readonly<Record<Provider, number>> = {
  aws: 8,
  azure: 8,
  gcp: 1_001,
  microsoft365: 8,
};
