import { displaySafeTechnicalDetail } from "./technicalDetails";

export type Provider = "aws" | "azure" | "gcp" | "microsoft365";

export type ProviderAuthorizationPath = "preferred" | "bootstrap";

export type ProviderCoordinateField =
  | "start_url"
  | "region"
  | "account_id"
  | "role_name"
  | "role_arn"
  | "tenant_id"
  | "public_client_id"
  | "subscription_id"
  | "organization_id"
  | "project_id"
  | "redirect_uri";

/**
 * Non-secret coordinates the UI may request for each provider and path.
 * Keeping this contract explicit prevents a UI refactor from silently dropping
 * a released provider boundary or adding a credential field.
 */
export const providerAuthorizationRequiredFields: Readonly<
  Record<Provider, Readonly<Record<ProviderAuthorizationPath, readonly ProviderCoordinateField[]>>>
> = {
  aws: {
    preferred: ["start_url", "region", "account_id", "role_name", "role_arn"],
    bootstrap: ["start_url", "region", "account_id", "role_name", "role_arn"],
  },
  azure: {
    preferred: ["tenant_id", "public_client_id", "subscription_id"],
    bootstrap: ["tenant_id", "public_client_id", "subscription_id"],
  },
  gcp: {
    preferred: ["public_client_id", "organization_id", "redirect_uri"],
    bootstrap: ["public_client_id", "organization_id", "project_id", "redirect_uri"],
  },
  microsoft365: {
    preferred: ["tenant_id", "public_client_id"],
    bootstrap: ["tenant_id", "public_client_id"],
  },
};

/**
 * Produces a bounded, display-safe diagnostic for the opt-in technical-details
 * disclosure. The primary error message is always supplied separately in
 * plain language. Common credential shapes are redacted defensively even
 * though provider backends are expected to return non-secret errors.
 */
export const providerAuthorizationTechnicalDetail = displaySafeTechnicalDetail;

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
