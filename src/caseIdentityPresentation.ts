import type { Locale } from "./i18n";
import type { AssessmentCase } from "./types";

type CaseIdentitySource = Pick<
  AssessmentCase,
  "id" | "name" | "organizationName" | "createdAt" | "productIdentity"
>;

export interface CaseIdentityPresentation {
  name: string;
  organizationName: string;
  isProductLocalhostQuickScan: boolean;
}

const productDeviceName = (locale: Locale): string =>
  locale === "zh-TW" ? "這台電腦" : "This computer";

const localhostQuickScanPort = (assessmentCase: CaseIdentitySource): number | undefined => {
  if (assessmentCase.productIdentity?.kind !== "localhost_quick_scan") return undefined;
  const port = assessmentCase.productIdentity.port;
  return Number.isInteger(port) && port >= 1 && port <= 65_535 ? port : undefined;
};

/**
 * Localizes only an identity derived from a canonical product-owned execution
 * contract. Saved or imported display strings alone can never claim it.
 */
export const caseIdentityPresentation = (
  assessmentCase: CaseIdentitySource,
  locale: Locale,
): CaseIdentityPresentation => {
  const port = localhostQuickScanPort(assessmentCase);
  if (port === undefined) {
    return {
      name: assessmentCase.name,
      organizationName: assessmentCase.organizationName,
      isProductLocalhostQuickScan: false,
    };
  }

  const deviceName = productDeviceName(locale);
  return {
    name: `${deviceName} · 127.0.0.1:${port}`,
    organizationName: deviceName,
    isProductLocalhostQuickScan: true,
  };
};

const stableCreatedAtSuffix = (createdAt: string): string => {
  const utc = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/u.exec(createdAt);
  if (utc) {
    const fraction = utc[3]?.replace(/0+$/u, "");
    return `${utc[1]} ${utc[2]}${fraction ? `.${fraction}` : ""} UTC`;
  }

  const parsed = new Date(createdAt);
  if (!Number.isNaN(parsed.valueOf())) {
    return parsed.toISOString().replace("T", " ").replace(".000Z", " UTC").replace("Z", " UTC");
  }

  return createdAt.trim();
};

/**
 * Builds labels for case pickers and lists. Repeated product-owned localhost
 * quick scans receive a stable creation-time suffix; an exact timestamp tie
 * falls back to the immutable case id so every option remains distinguishable.
 */
export const caseDisplayLabels = (
  cases: ReadonlyArray<CaseIdentitySource>,
  locale: Locale,
): ReadonlyMap<string, string> => {
  const presented = cases.map((assessmentCase) => ({
    assessmentCase,
    identity: caseIdentityPresentation(assessmentCase, locale),
  }));
  const duplicateCounts = new Map<string, number>();

  for (const entry of presented) {
    if (!entry.identity.isProductLocalhostQuickScan) continue;
    duplicateCounts.set(entry.identity.name, (duplicateCounts.get(entry.identity.name) ?? 0) + 1);
  }

  const createdSuffixCounts = new Map<string, number>();
  for (const entry of presented) {
    if ((duplicateCounts.get(entry.identity.name) ?? 0) < 2) continue;
    const suffix = stableCreatedAtSuffix(entry.assessmentCase.createdAt);
    const key = `${entry.identity.name}\u0000${suffix}`;
    createdSuffixCounts.set(key, (createdSuffixCounts.get(key) ?? 0) + 1);
  }

  return new Map(presented.map((entry) => {
    if ((duplicateCounts.get(entry.identity.name) ?? 0) < 2) {
      return [entry.assessmentCase.id, entry.identity.name];
    }

    const suffix = stableCreatedAtSuffix(entry.assessmentCase.createdAt);
    const suffixKey = `${entry.identity.name}\u0000${suffix}`;
    const collisionSuffix = (createdSuffixCounts.get(suffixKey) ?? 0) > 1
      ? ` · ${entry.assessmentCase.id}`
      : "";
    return [entry.assessmentCase.id, `${entry.identity.name} · ${suffix}${collisionSuffix}`];
  }));
};
