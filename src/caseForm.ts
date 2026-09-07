import type { KnownAssetInput } from "./types";
import type { UseCaseId } from "./useCases";

const parseIpv4 = (value: string): [number, number, number, number] | undefined => {
  const parts = value.split(".");
  if (parts.length !== 4) return undefined;
  if (parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return undefined;
  const octets = parts.map(Number);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return undefined;
  return octets as [number, number, number, number];
};

// ipnet accepts decimal IPv4 CIDR octets with leading zeroes (for example,
// 010.0.0.0/08). Keep that compatibility scoped to CIDR parsing: accepting the
// same spelling as a bare address would change how the native IpAddr/hostname
// fallback classifies it.
const parseIpv4CidrAddress = (value: string): [number, number, number, number] | undefined => {
  const parts = value.split(".");
  if (parts.length !== 4) return undefined;
  if (parts.some((part) => !/^[0-9]{1,3}$/u.test(part))) return undefined;
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

const parseIpv6 = (input: string, allowIpv4CidrLeadingZeroes = false): number[] | undefined => {
  let value = input.toLocaleLowerCase("en-US");
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  if (!value.includes(":") || value.includes("%")) return undefined;

  if (value.includes(".")) {
    const separator = value.lastIndexOf(":");
    const ipv4 = allowIpv4CidrLeadingZeroes
      ? parseIpv4CidrAddress(value.slice(separator + 1))
      : parseIpv4(value.slice(separator + 1));
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
  let ipv4Cidr: [number, number, number, number] | undefined;
  if (cidrSeparator >= 0) {
    const address = value.slice(0, cidrSeparator);
    const prefix = Number(value.slice(cidrSeparator + 1));
    const maximumPrefix = address.includes(":") ? 128 : 32;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > maximumPrefix) return false;
    ipv4Cidr = parseIpv4CidrAddress(address);
    value = address;
  }
  if (value === "localhost" || value.endsWith(".localhost")) return true;
  const ipv4 = ipv4Cidr ?? parseIpv4(value);
  if (ipv4) return sensitiveIpv4(ipv4);
  const ipv6 = parseIpv6(value, cidrSeparator >= 0);
  return Boolean(ipv6 && sensitiveIpv6(ipv6));
};

export type WebsiteInputError =
  | "empty"
  | "too_long"
  | "invalid_url"
  | "unsupported_protocol"
  | "userinfo_not_allowed"
  | "hostname_missing"
  | "hostname_invalid";

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
  if (!validateExternalTarget(target).ok) {
    return { ok: false, error: "hostname_invalid" };
  }

  return {
    ok: true,
    value: {
      target: externalComparisonKey(target),
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

export type ExternalTargetInputError =
  | "wildcard_not_allowed"
  | "service_coordinate_not_allowed"
  | "invalid_cidr"
  | "invalid_target";

export type ValidateExternalTargetResult =
  | { ok: true }
  | { ok: false; error: ExternalTargetInputError };

const canonicalHostname = (input: string): string | undefined => {
  const withoutTrailingDot = input.replace(/\.+$/u, "");
  if (withoutTrailingDot.toLocaleLowerCase("en-US") === "localhost") return "localhost";

  let ascii: string;
  try {
    // URL's host parser supplies the browser's IDNA conversion. The structural
    // checks below then mirror external_scope::validate_hostname rather than
    // treating a URL, port, path, or credentials as a target coordinate.
    // A fixed alphabetic suffix prevents WHATWG's ends-in-a-number rule from
    // treating an otherwise valid all-numeric final label as legacy IPv4.
    const idnaSuffix = ".canonical-target.invalid";
    const parsed = new URL(`http://${withoutTrailingDot}${idnaSuffix}/`);
    if (
      parsed.username
      || parsed.password
      || parsed.port
      || parsed.pathname !== "/"
      || parsed.search
      || parsed.hash
    ) return undefined;
    const converted = parsed.hostname.replace(/\.$/u, "").toLocaleLowerCase("en-US");
    if (!converted.endsWith(idnaSuffix)) return undefined;
    ascii = converted.slice(0, -idnaSuffix.length);
  } catch {
    return undefined;
  }

  if (ascii.length > 253 || !ascii.includes(".")) return undefined;
  return ascii.split(".").every((label) =>
    label.length > 0
    && label.length <= 63
    && !label.startsWith("-")
    && !label.endsWith("-")
    && /^[a-z0-9-]+$/u.test(label))
    ? ascii
    : undefined;
};

const validateHostname = (input: string): boolean => canonicalHostname(input) !== undefined;

/**
 * Mirrors the accepted shapes of the native `CanonicalTarget::parse` boundary.
 * This is an early UX check only: the native boundary remains authoritative and
 * validates the same value again before it can become a scan target.
 */
export const validateExternalTarget = (input: string): ValidateExternalTargetResult => {
  const value = input.trim();
  if (!value || value.includes("\0") || /[\r\n]/u.test(value)) {
    return { ok: false, error: "invalid_target" };
  }
  if (value.includes("*")) return { ok: false, error: "wildcard_not_allowed" };
  if (value.includes("%")) return { ok: false, error: "invalid_target" };
  if (
    /^[a-z][a-z0-9+.-]*:\/\//iu.test(value)
    || /[@?#\\\[\]]/u.test(value)
  ) {
    return { ok: false, error: "service_coordinate_not_allowed" };
  }

  const cidrSeparators = value.match(/\//gu)?.length ?? 0;
  if (cidrSeparators > 0) {
    if (cidrSeparators !== 1) return { ok: false, error: "invalid_cidr" };
    const separator = value.indexOf("/");
    const address = value.slice(0, separator);
    const prefixText = value.slice(separator + 1);
    const ipv4 = parseIpv4CidrAddress(address);
    const ipv6 = parseIpv6(address, true);
    const maximumPrefix = ipv4 ? 32 : ipv6 ? 128 : undefined;
    if (
      maximumPrefix === undefined
      || !(ipv4 ? /^[0-9]{1,2}$/u : /^[0-9]{1,3}$/u).test(prefixText)
      || Number(prefixText) > maximumPrefix
    ) {
      return { ok: false, error: "invalid_cidr" };
    }
    return { ok: true };
  }

  if (parseIpv4(value) || parseIpv6(value)) return { ok: true };
  if (value.includes(":")) return { ok: false, error: "service_coordinate_not_allowed" };
  if (/\s/u.test(value) || !validateHostname(value)) {
    return { ok: false, error: "invalid_target" };
  }
  return { ok: true };
};

export type CaseAssetDraftError =
  | { kind: "website"; error: WebsiteInputError }
  | { kind: "missing_target"; target: "public" | "internal" }
  | {
      kind: "invalid_target";
      target: "public" | "internal";
      value: string;
      error: ExternalTargetInputError;
    }
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

const canonicalIpv4Network = (
  octets: [number, number, number, number],
  prefix: number,
): string => {
  const address = (
    ((octets[0] << 24) >>> 0)
    | (octets[1] << 16)
    | (octets[2] << 8)
    | octets[3]
  ) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffff_ffff << (32 - prefix)) >>> 0;
  const network = (address & mask) >>> 0;
  return `${network >>> 24}.${(network >>> 16) & 0xff}.${(network >>> 8) & 0xff}.${network & 0xff}/${prefix}`;
};

const canonicalIpv6Comparison = (segments: number[], prefix?: number): string => {
  const normalized = [...segments];
  if (prefix !== undefined) {
    for (let index = 0; index < normalized.length; index += 1) {
      const remaining = prefix - index * 16;
      if (remaining >= 16) continue;
      if (remaining <= 0) normalized[index] = 0;
      else normalized[index] = (normalized[index] ?? 0) & ((0xffff << (16 - remaining)) & 0xffff);
    }
  }
  const hexadecimal = normalized.map((segment) => segment.toString(16));
  let longestStart = -1;
  let longestLength = 0;
  for (let start = 0; start < hexadecimal.length;) {
    if (normalized[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start;
    while (end < hexadecimal.length && normalized[end] === 0) end += 1;
    if (end - start > longestLength) {
      longestStart = start;
      longestLength = end - start;
    }
    start = end;
  }
  const address = longestLength >= 2
    ? `${hexadecimal.slice(0, longestStart).join(":")}::${hexadecimal.slice(longestStart + longestLength).join(":")}`
    : hexadecimal.join(":");
  return prefix === undefined ? address : `${address}/${prefix}`;
};

const externalComparisonKey = (value: string): string => {
  const trimmed = value.trim();
  const separator = trimmed.indexOf("/");
  if (separator >= 0) {
    const address = trimmed.slice(0, separator);
    const prefix = Number(trimmed.slice(separator + 1));
    const ipv4 = parseIpv4CidrAddress(address);
    if (ipv4) return canonicalIpv4Network(ipv4, prefix);
    const ipv6 = parseIpv6(address, true);
    if (ipv6) return canonicalIpv6Comparison(ipv6, prefix);
  }
  const ipv4 = parseIpv4(trimmed);
  if (ipv4) return ipv4.join(".");
  const ipv6 = parseIpv6(trimmed);
  if (ipv6) return canonicalIpv6Comparison(ipv6);
  return canonicalHostname(trimmed) ?? trimmed.replace(/\.+$/u, "").toLocaleLowerCase("en-US");
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

  const publicTargetValues = lineValues(draft.publicTargets);
  const internalTargetValues = lineValues(draft.internalTargets);

  if (draft.selectedUseCase === "external_ip_or_domain" && publicTargetValues.length === 0) {
    return { ok: false, error: { kind: "missing_target", target: "public" } };
  }
  if (draft.selectedUseCase === "internal_it_environment" && internalTargetValues.length === 0) {
    return { ok: false, error: { kind: "missing_target", target: "internal" } };
  }

  for (const [target, values] of [
    ["public", publicTargetValues],
    ["internal", internalTargetValues],
  ] as const) {
    for (const value of values) {
      const validated = validateExternalTarget(value);
      if (!validated.ok) {
        return {
          ok: false,
          error: { kind: "invalid_target", target, value, error: validated.error },
        };
      }
    }
  }

  knownAssets.push(
    ...publicTargetValues.map((value) => ({
      kind: "external_target" as const,
      value: externalComparisonKey(value),
      internetExposure: "public" as const,
    })),
    ...internalTargetValues.map((value) => ({
      kind: "external_target" as const,
      value: externalComparisonKey(value),
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
        error: { kind: "conflicting_exposure", target: comparisonValue },
      };
    }
    if (!previous) unique.set(key, asset);
  }

  return { ok: true, knownAssets: [...unique.values()] };
};
