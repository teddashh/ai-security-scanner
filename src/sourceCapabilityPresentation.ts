import type {
  ConnectedSource,
  EngineManifest,
  ProviderSourceProfile,
  SourceCapabilityCell,
  SourceCapabilityDimension,
  SourceCapabilityEngine,
  SourceCapabilityProvider,
  SourceCapabilityState,
  SourceCapabilityView,
  SourceKind,
} from "./types";

export const SOURCE_CAPABILITY_SCHEMA_VERSION = "1.0.0" as const;
export const SOURCE_CAPABILITY_DEFINITION_VERSION = "2026-09-04.1";

interface EngineDefinition {
  id: string;
  name: string;
  profile: string;
  builtIn?: boolean;
  requiresDeclaredProviderProfile?: boolean;
}

interface CellDefinition {
  dimension: SourceCapabilityDimension;
  stateWhenAvailable: Exclude<SourceCapabilityState, "unknown" | "unavailable">;
  engines: readonly EngineDefinition[];
  limitation: SourceCapabilityCell["limitation"];
}

const providerSourceKinds: Record<SourceCapabilityProvider, SourceKind> = {
  aws: "aws_organization",
  azure: "azure_tenant",
  gcp: "gcp_organization",
  microsoft365: "microsoft365_tenant",
};

const providerProfiles: Record<SourceCapabilityProvider, ProviderSourceProfile> = {
  aws: "aws_organization_read_only_session",
  azure: "azure_tenant_read_only_access_token",
  gcp: "gcp_organization_read_only_access_token",
  microsoft365: "microsoft365_tenant_read_only_access_token",
};

const nativeInventory: Record<SourceCapabilityProvider, EngineDefinition> = {
  aws: {
    id: "provider-native-discovery",
    name: "Built-in provider inventory",
    profile: "aws-organizations-list-accounts",
    builtIn: true,
  },
  azure: {
    id: "provider-native-discovery",
    name: "Built-in provider inventory",
    profile: "azure-resource-manager-resources",
    builtIn: true,
  },
  gcp: {
    id: "provider-native-discovery",
    name: "Built-in provider inventory",
    profile: "gcp-resource-manager-projects",
    builtIn: true,
  },
  microsoft365: {
    id: "provider-native-discovery",
    name: "Built-in provider inventory",
    profile: "microsoft-graph-directory-inventory",
    builtIn: true,
  },
};

const prowler = (provider: SourceCapabilityProvider, fallbackProfile: string): EngineDefinition => ({
  id: "prowler",
  name: "Prowler",
  profile: fallbackProfile,
  requiresDeclaredProviderProfile: true,
});

const unavailable = (
  dimension: SourceCapabilityDimension,
  en: string,
  zhTW: string,
): CellDefinition => ({
  dimension,
  stateWhenAvailable: "partial",
  engines: [],
  limitation: { en, zhTW },
});

/**
 * Curated product capability definitions. These describe shipped, bounded
 * profiles; they never infer capability breadth from an engine category.
 */
const definitions: Record<SourceCapabilityProvider, readonly CellDefinition[]> = {
  aws: [
    {
      dimension: "inventory",
      stateWhenAvailable: "partial",
      engines: [
        nativeInventory.aws,
        { id: "cloudquery", name: "CloudQuery", profile: "fixed seven-table AWS IAM profile" },
        { id: "steampipe", name: "Steampipe", profile: "fixed AWS IAM query profile" },
      ],
      limitation: {
        en: "Lists AWS accounts and a fixed IAM data subset; it is not broad multi-service resource inventory.",
        zhTW: "可列出 AWS 帳號與固定 IAM 資料子集；不是跨服務的完整資源盤點。",
      },
    },
    {
      dimension: "identity_and_access",
      stateWhenAvailable: "partial",
      engines: [
        prowler("aws", "aws_iam_service_exact_account"),
        { id: "scoutsuite", name: "ScoutSuite", profile: "reduced AWS IAM JSON profile" },
        { id: "cloudsplaining", name: "Cloudsplaining", profile: "bounded AWS IAM authorization details" },
      ],
      limitation: {
        en: "Runs bounded IAM checks for one exact account. Organization children need their own verified account scope.",
        zhTW: "只對一個明確帳號執行受限 IAM 檢查；組織下其他帳號需要各自驗證範圍。",
      },
    },
    unavailable("network_exposure", "No released AWS network-exposure profile is installed.", "目前產品沒有已發布的 AWS 網路暴露檢查設定檔。"),
    unavailable("storage_exposure", "No released AWS storage-exposure profile is installed.", "目前產品沒有已發布的 AWS 儲存空間暴露檢查設定檔。"),
    unavailable("logging", "No released AWS logging profile is installed.", "目前產品沒有已發布的 AWS 記錄檢查設定檔。"),
    {
      dimension: "secret_and_configuration",
      stateWhenAvailable: "partial",
      engines: [
        prowler("aws", "aws_iam_service_exact_account"),
        { id: "scoutsuite", name: "ScoutSuite", profile: "reduced AWS IAM JSON profile" },
      ],
      limitation: {
        en: "Covers only IAM-related configuration in the fixed profiles. It does not read secret values or assess other AWS services.",
        zhTW: "只涵蓋固定設定檔中的 IAM 相關設定；不讀取秘密值，也不評估其他 AWS 服務。",
      },
    },
  ],
  azure: [
    {
      dimension: "inventory",
      stateWhenAvailable: "supported",
      engines: [nativeInventory.azure],
      limitation: {
        en: "Lists generic Azure Resource Manager resources in one exact verified subscription; capture limits are reported separately.",
        zhTW: "列出一個已明確驗證訂閱內的 Azure Resource Manager 一般資源；擷取限制會另外回報。",
      },
    },
    {
      dimension: "identity_and_access",
      stateWhenAvailable: "partial",
      engines: [prowler("azure", "azure_iam_service_static_token_exact_subscription")],
      limitation: {
        en: "Runs only the fixed IAM service checks for one exact Azure subscription.",
        zhTW: "只對一個明確 Azure 訂閱執行固定 IAM 服務檢查。",
      },
    },
    unavailable("network_exposure", "No released Azure network-exposure profile is installed.", "目前產品沒有已發布的 Azure 網路暴露檢查設定檔。"),
    unavailable("storage_exposure", "No released Azure storage-exposure profile is installed.", "目前產品沒有已發布的 Azure 儲存空間暴露檢查設定檔。"),
    unavailable("logging", "No released Azure logging profile is installed.", "目前產品沒有已發布的 Azure 記錄檢查設定檔。"),
    {
      dimension: "secret_and_configuration",
      stateWhenAvailable: "partial",
      engines: [prowler("azure", "azure_iam_service_static_token_exact_subscription")],
      limitation: {
        en: "Covers only configuration observed by the fixed IAM profile. It does not read secret values.",
        zhTW: "只涵蓋固定 IAM 設定檔可觀察的設定；不讀取秘密值。",
      },
    },
  ],
  gcp: [
    {
      dimension: "inventory",
      stateWhenAvailable: "partial",
      engines: [nativeInventory.gcp],
      limitation: {
        en: "Lists folders and projects under one exact organization; it does not inventory resources inside every project.",
        zhTW: "列出一個明確組織下的資料夾與專案；不會盤點每個專案內的所有資源。",
      },
    },
    {
      dimension: "identity_and_access",
      stateWhenAvailable: "partial",
      engines: [prowler("gcp", "gcp_iam_four_checks_exact_project")],
      limitation: {
        en: "Runs exactly four IAM checks per verified project; it is not a broad GCP posture assessment.",
        zhTW: "每個已驗證專案只執行四項明確 IAM 檢查；不是完整 GCP 安全狀態評估。",
      },
    },
    unavailable("network_exposure", "No released GCP network-exposure profile is installed.", "目前產品沒有已發布的 GCP 網路暴露檢查設定檔。"),
    unavailable("storage_exposure", "No released GCP storage-exposure profile is installed.", "目前產品沒有已發布的 GCP 儲存空間暴露檢查設定檔。"),
    unavailable("logging", "No released GCP logging profile is installed.", "目前產品沒有已發布的 GCP 記錄檢查設定檔。"),
    {
      dimension: "secret_and_configuration",
      stateWhenAvailable: "partial",
      engines: [prowler("gcp", "gcp_iam_four_checks_exact_project")],
      limitation: {
        en: "Covers only configuration observed by the four-check IAM profile. It does not read secret values.",
        zhTW: "只涵蓋四項 IAM 檢查可觀察的設定；不讀取秘密值。",
      },
    },
  ],
  microsoft365: [
    {
      dimension: "inventory",
      stateWhenAvailable: "partial",
      engines: [nativeInventory.microsoft365],
      limitation: {
        en: "Lists the tenant organization and users only; it is not full Microsoft 365 service inventory.",
        zhTW: "只列出租用戶組織與使用者；不是完整 Microsoft 365 服務盤點。",
      },
    },
    {
      dimension: "identity_and_access",
      stateWhenAvailable: "partial",
      engines: [
        { id: "scubagear", name: "ScubaGear", profile: "commercial AAD-only baseline" },
        { id: "maester", name: "Maester", profile: "fixed Graph-only Entra test profile" },
      ],
      limitation: {
        en: "Only the fixed Entra profiles are covered: a commercial AAD-only ScubaGear baseline and a Graph-only Maester test profile. No other Microsoft 365 service is checked.",
        zhTW: "只涵蓋固定的 Entra 設定檔：僅商業版 AAD 的 ScubaGear 基準，以及僅使用 Graph 的 Maester 測試設定檔。其他 Microsoft 365 服務都不檢查。",
      },
    },
    unavailable("network_exposure", "No released Microsoft 365 network-exposure profile is installed.", "目前產品沒有已發布的 Microsoft 365 網路暴露檢查設定檔。"),
    unavailable("storage_exposure", "No released Microsoft 365 storage-exposure profile is installed.", "目前產品沒有已發布的 Microsoft 365 儲存空間暴露檢查設定檔。"),
    unavailable("logging", "No released Microsoft 365 logging profile is installed.", "目前產品沒有已發布的 Microsoft 365 記錄檢查設定檔。"),
    {
      dimension: "secret_and_configuration",
      stateWhenAvailable: "partial",
      engines: [
        { id: "scubagear", name: "ScubaGear", profile: "commercial AAD-only baseline" },
        { id: "maester", name: "Maester", profile: "fixed Graph-only Entra test profile" },
      ],
      limitation: {
        en: "Only fixed Entra configuration checks are covered; excluded tests and other Microsoft 365 services remain unavailable.",
        zhTW: "只涵蓋固定的 Entra 設定檢查；排除的測試與其他 Microsoft 365 服務仍不可用。",
      },
    },
  ],
};

const safeVersion = (value: string | undefined): string | undefined =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/u.test(value) ? value : undefined;

const safeDate = (value: string | undefined): string | undefined =>
  typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/u.test(value) ? value : undefined;

const safeProfile = (value: string | undefined): string | undefined =>
  typeof value === "string" && /^[a-z0-9][a-z0-9_-]{2,95}$/u.test(value) ? value : undefined;

const engineAvailability = (manifest: EngineManifest): SourceCapabilityEngine["availability"] => {
  if (manifest.compatibilityValid === false) return "unknown";
  if (manifest.runnable === true && Array.isArray(manifest.blockedBy) && manifest.blockedBy.length > 0) {
    return "unknown";
  }
  if (
    manifest.runnable === false
    || (Array.isArray(manifest.blockedBy) && manifest.blockedBy.length > 0)
    || manifest.status !== "ready"
  ) return "unavailable";
  return manifest.runnable === true ? "available" : "unknown";
};

const projectEngine = (
  definition: EngineDefinition,
  provider: SourceCapabilityProvider,
  manifests: readonly EngineManifest[],
): SourceCapabilityEngine => {
  if (definition.builtIn) {
    return {
      id: definition.id,
      name: definition.name,
      profile: definition.profile,
      availability: "available",
      supportStatus: "unknown",
    };
  }
  const manifest = manifests.find((candidate) => candidate.id === definition.id);
  if (!manifest) {
    return {
      id: definition.id,
      name: definition.name,
      profile: definition.profile,
      availability: "unknown",
      supportStatus: "unknown",
    };
  }
  const expectedPlatform = provider === "microsoft365" ? "m365" : provider;
  const providerDeclared = Array.isArray(manifest.supportedProviders)
    && manifest.supportedProviders.includes(expectedPlatform);
  const declaredProfile = (Array.isArray(manifest.providerExecutionProfiles)
    ? manifest.providerExecutionProfiles
    : []).find((contract) =>
    contract.provider === provider && safeProfile(contract.profile),
  )?.profile;
  const supportStatus = (["supported", "expired", "unknown"] as const).includes(manifest.supportStatus)
    ? manifest.supportStatus
    : "unknown";
  return {
    id: definition.id,
    name: definition.name,
    profile: declaredProfile ?? definition.profile,
    version: safeVersion(manifest.version),
    availability: !providerDeclared || (definition.requiresDeclaredProviderProfile && !declaredProfile)
      ? "unknown"
      : engineAvailability(manifest),
    supportStatus,
    supportUntil: safeDate(manifest.supportUntil),
  };
};

const cellState = (
  definition: CellDefinition,
  engines: readonly SourceCapabilityEngine[],
): SourceCapabilityState => {
  if (engines.length === 0) return "unavailable";
  if (engines.some((engine) => engine.availability === "available")) return definition.stateWhenAvailable;
  if (engines.some((engine) => engine.availability === "unknown")) return "unknown";
  return "unavailable";
};

const validResourceScope = (provider: SourceCapabilityProvider, value: string): boolean => {
  switch (provider) {
    case "aws": return /^aws-account:[0-9]{12}$/u.test(value);
    case "azure": return /^azure-subscription:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu.test(value);
    case "gcp": return /^gcp-organization:[0-9]{1,32}$/u.test(value);
    case "microsoft365": return /^microsoft365-tenant:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu.test(value);
  }
};

export const exactSourceCapabilityScope = (
  provider: SourceCapabilityProvider,
  source: ConnectedSource,
): string | undefined => {
  const binding = source.providerBinding;
  if (
    source.kind !== providerSourceKinds[provider]
    || !binding
    || binding.profile !== providerProfiles[provider]
    || !validResourceScope(provider, binding.resourceScope)
  ) return undefined;
  return binding.resourceScope;
};

export const projectSourceCapabilityView = ({
  provider,
  source,
  manifests,
}: {
  provider: SourceCapabilityProvider;
  source: ConnectedSource;
  manifests: readonly EngineManifest[];
}): SourceCapabilityView => {
  const safeManifests = Array.isArray(manifests) ? manifests : [];
  return {
    schemaVersion: SOURCE_CAPABILITY_SCHEMA_VERSION,
    definitionVersion: SOURCE_CAPABILITY_DEFINITION_VERSION,
    provider,
    sourceId: source.id,
    sourceKind: source.kind,
    resourceScope: exactSourceCapabilityScope(provider, source),
    cells: definitions[provider].map((definition) => {
      const engines = definition.engines.map((engine) => projectEngine(engine, provider, safeManifests));
      return {
        dimension: definition.dimension,
        state: cellState(definition, engines),
        engines,
        limitation: definition.limitation,
      };
    }),
  };
};
