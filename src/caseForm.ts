import type { KnownAssetInput } from "./types";
import type { UseCaseId } from "./useCases";

const parseIpv4 = (value: string): [number, number, number, number] | undefined => {
  const parts = value.split(".");
  if (parts.length !== 4) return undefined;
  const octets = parts.map(Number);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return undefined;
  return octets as [number, number, number, number];
};

const sensitiveIpv4 = ([first, second]: [number, number, number, number]): boolean =>
  first === 10
  || first === 127
  || (first === 169 && second === 254)
  || (first === 172 && second >= 16 && second <= 31)
  || (first === 192 && second === 168)
  || (first === 100 && second >= 64 && second <= 127)
  || (first === 198 && (second === 18 || second === 19))
  || first === 0
  || first >= 224;

const parseIpv6 = (input: string): number[] | undefined => {
  let value = input.toLocaleLowerCase("en-US");
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  if (!value.includes(":") || value.includes("%")) return undefined;

  if (value.includes(".")) {
    const separator = value.lastIndexOf(":");
    const ipv4 = parseIpv4(value.slice(separator + 1));
    if (separator < 0 || !ipv4) return undefined;
    value = `${value.slice(0, separator)}:${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }

  const halves = value.split("::");
  if (halves.length > 2) return undefined;
  const parseHalf = (half: string): number[] | undefined => {
    if (!half) return [];
    const segments = half.split(":");
    if (segments.some((segment) => !/^[0-9a-f]{1,4}$/u.test(segment))) return undefined;
    return segments.map((segment) => Number.parseInt(segment, 16));
  };
  const left = parseHalf(halves[0] ?? "");
  const right = parseHalf(halves[1] ?? "");
  if (!left || !right) return undefined;
  if (halves.length === 1) return left.length === 8 ? left : undefined;
  const omitted = 8 - left.length - right.length;
  if (omitted < 1) return undefined;
  return [...left, ...Array<number>(omitted).fill(0), ...right];
};

const sensitiveIpv6 = (segments: number[]): boolean => {
  if (segments.length !== 8) return false;
  const unspecified = segments.every((segment) => segment === 0);
  const loopback = segments.slice(0, 7).every((segment) => segment === 0) && segments[7] === 1;
  const first = segments[0] ?? 0;
  const uniqueLocal = (first & 0xfe00) === 0xfc00;
  const linkLocal = (first & 0xffc0) === 0xfe80;
  const multicast = (first & 0xff00) === 0xff00;
  const mappedIpv4 = segments.slice(0, 5).every((segment) => segment === 0)
    && segments[5] === 0xffff
    ? [
        (segments[6] ?? 0) >> 8,
        (segments[6] ?? 0) & 0xff,
        (segments[7] ?? 0) >> 8,
        (segments[7] ?? 0) & 0xff,
      ] as [number, number, number, number]
    : undefined;
  return unspecified
    || loopback
    || uniqueLocal
    || linkLocal
    || multicast
    || Boolean(mappedIpv4 && sensitiveIpv4(mappedIpv4));
};

/** Classifies only explicit coordinates whose sensitive nature is known without DNS. */
export const explicitTargetRequiresSensitiveNetworkAllowance = (target: string): boolean => {
  let value = target.trim().replace(/\.$/u, "").toLocaleLowerCase("en-US");
  const cidrSeparator = value.lastIndexOf("/");
  if (cidrSeparator >= 0) {
    const address = value.slice(0, cidrSeparator);
    const prefix = Number(value.slice(cidrSeparator + 1));
    const maximumPrefix = address.includes(":") ? 128 : 32;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > maximumPrefix) return false;
    value = address;
  }
  if (value === "localhost" || value.endsWith(".localhost")) return true;
  const ipv4 = parseIpv4(value);
  if (ipv4) return sensitiveIpv4(ipv4);
  const ipv6 = parseIpv6(value);
  return Boolean(ipv6 && sensitiveIpv6(ipv6));
};

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
      internetExposure: explicitTargetRequiresSensitiveNetworkAllowance(prepared.value.target)
        ? "internal"
        : "public",
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
