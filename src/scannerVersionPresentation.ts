import type { Locale } from "./i18n";

const SOURCE_COMMIT = /^source@([0-9a-f]{7,64})$/u;

/**
 * First-layer and technical labels for a catalog engine version.
 * A pinned `source@<commit>` shows the version the scanner reports about
 * itself plus that commit. Any other engine version is shown as recorded,
 * and a reported version beside it is ignored. Blank engine versions stay absent.
 */
export const scannerVersionLabel = (
  engineVersion: string | undefined,
  reportedVersion: string | undefined,
  form: "short" | "exact",
  locale: Locale,
): string | undefined => {
  const recorded = engineVersion?.trim();
  if (!recorded) return undefined;
  const commit = SOURCE_COMMIT.exec(recorded)?.[1];
  if (!commit) return recorded;
  const reported = reportedVersion?.trim();
  if (!reported) return form === "short" ? `source ${commit.slice(0, 7)}` : recorded;
  const detail = form === "short" ? `source ${commit.slice(0, 7)}` : `source@${commit}`;
  return locale === "zh-TW" ? `${reported}（${detail}）` : `${reported} (${detail})`;
};
