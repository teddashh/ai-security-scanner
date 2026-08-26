import type { KnownAssetInput } from "./types";
import type { UseCaseId } from "./useCases";

export type WebsiteInputError =
  | "empty"
  | "too_long"
  | "invalid_url"
  | "unsupported_protocol"
  | "userinfo_not_allowed"
  | "hostname_missing";

export interface PreparedWebsiteTarget {
  /** Canonical hostname/IP coordinate accepted by DeclaredAssetKind::ExternalTarget. */
  target: string;
  /** Service details are retained for the later explicit scope-grant step. */
  service: {
    protocol: "http" | "https";
    port: number;
    path: string;
    queryWasRemoved: boolean;
  };
}

export type PrepareWebsiteTargetResult =
  | { ok: true; value: PreparedWebsiteTarget }
  | { ok: false; error: WebsiteInputError };

/**
 * A deployed website is a user-facing URL, while the current case
 * questionnaire persists a target coordinate. Keep that conversion explicit:
 * never pass credentials through and never silently accept another protocol.
 * The port and path are returned—not discarded as authorization—so the next
 * step can explain and confirm the exact service grant separately.
 */
export const prepareDeployedWebsiteTarget = (input: string): PrepareWebsiteTargetResult => {
  const value = input.trim();
  if (!value) return { ok: false, error: "empty" };
  if (value.length > 2_048) return { ok: false, error: "too_long" };

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, error: "invalid_url" };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: "unsupported_protocol" };
  }
  if (url.username || url.password) {
    return { ok: false, error: "userinfo_not_allowed" };
  }
  if (!url.hostname) return { ok: false, error: "hostname_missing" };

  const protocol = url.protocol.slice(0, -1) as "http" | "https";
  const defaultPort = protocol === "https" ? 443 : 80;
  const target = url.hostname.startsWith("[") && url.hostname.endsWith("]")
    ? url.hostname.slice(1, -1)
    : url.hostname;

  return {
    ok: true,
    value: {
      target,
      service: {
        protocol,
        port: url.port ? Number(url.port) : defaultPort,
        path: url.pathname,
        queryWasRemoved: Boolean(url.search || url.hash),
      },
    },
  };
};

export interface CaseAssetDraft {
  selectedUseCase?: UseCaseId;
  websiteUrl: string;
  publicTargets: string;
  internalTargets: string;
  repositories: string;
  iacProjects: string;
  containerImages: string;
  kubernetesClusters: string;
}

export type CaseAssetDraftError =
  | { kind: "website"; error: WebsiteInputError }
  | { kind: "missing_target"; target: "public" | "internal" }
  | { kind: "conflicting_exposure"; target: string };

export type BuildKnownAssetsResult =
  | { ok: true; knownAssets: KnownAssetInput[] }
  | { ok: false; error: CaseAssetDraftError };

export const lineValues = (value: string): string[] =>
  [...new Set(value.split(/\r?\n/u).map((item) => item.trim()).filter(Boolean))];

const guidedLocalUseCases: readonly UseCaseId[] = [
  "ai_application",
  "source_code",
  "infrastructure_as_code",
  "container_image",
  "kubernetes",
];

const externalComparisonKey = (value: string): string => {
  const trimmed = value.trim();
  if (trimmed.includes("/")) return trimmed.toLowerCase();
  try {
    const hostname = new URL(`http://${trimmed}`).hostname;
    const withoutIpv6Brackets = hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
    return withoutIpv6Brackets.replace(/\.$/u, "").toLowerCase();
  } catch {
    return trimmed.replace(/\.$/u, "").toLowerCase();
  }
};

export const buildKnownAssets = (draft: CaseAssetDraft): BuildKnownAssetsResult => {
  const knownAssets: KnownAssetInput[] = [];
  const waitsForLocalPicker = Boolean(
    draft.selectedUseCase && guidedLocalUseCases.includes(draft.selectedUseCase),
  );

  if (draft.selectedUseCase === "deployed_website") {
    const prepared = prepareDeployedWebsiteTarget(draft.websiteUrl);
    if (!prepared.ok) return { ok: false, error: { kind: "website", error: prepared.error } };
    knownAssets.push({
      kind: "external_target",
      value: prepared.value.target,
      internetExposure: "public",
      webService: {
        protocol: prepared.value.service.protocol,
        port: prepared.value.service.port,
        path: prepared.value.service.path,
      },
    });
  }

  if (draft.selectedUseCase === "external_ip_or_domain" && lineValues(draft.publicTargets).length === 0) {
    return { ok: false, error: { kind: "missing_target", target: "public" } };
  }
  if (draft.selectedUseCase === "internal_it_environment" && lineValues(draft.internalTargets).length === 0) {
    return { ok: false, error: { kind: "missing_target", target: "internal" } };
  }

  knownAssets.push(
    ...lineValues(draft.publicTargets).map((value) => ({
      kind: "external_target" as const,
      value,
      internetExposure: "public" as const,
    })),
    ...lineValues(draft.internalTargets).map((value) => ({
      kind: "external_target" as const,
      value,
      internetExposure: "internal" as const,
    })),
    ...lineValues(waitsForLocalPicker ? "" : draft.repositories).map((value) => ({
      kind: "repository" as const,
      value,
    })),
    ...lineValues(waitsForLocalPicker ? "" : draft.iacProjects).map((value) => ({
      kind: "iac_project" as const,
      value,
    })),
    ...lineValues(waitsForLocalPicker ? "" : draft.containerImages).map((value) => ({
      kind: "container_image" as const,
      value,
    })),
    ...lineValues(waitsForLocalPicker ? "" : draft.kubernetesClusters).map((value) => ({
      kind: "kubernetes_cluster" as const,
      value,
    })),
  );

  const unique = new Map<string, KnownAssetInput>();
  for (const asset of knownAssets) {
    const comparisonValue = asset.kind === "external_target"
      ? externalComparisonKey(asset.value)
      : asset.value;
    const key = `${asset.kind}\u{0}${comparisonValue}`;
    const previous = unique.get(key);
    if (
      asset.kind === "external_target"
      && previous?.kind === "external_target"
      && previous.internetExposure !== asset.internetExposure
    ) {
      return {
        ok: false,
        error: { kind: "conflicting_exposure", target: asset.value },
      };
    }
    if (!previous) unique.set(key, asset);
  }

  return { ok: true, knownAssets: [...unique.values()] };
};
