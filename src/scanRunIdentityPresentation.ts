import type { Locale } from "./i18n";
import type { ScanRun } from "./types";

/**
 * Localizes only a run with a canonical backend sequence. User-authored or
 * imported labels without that discriminator remain byte-for-byte unchanged.
 */
export const scanRunIdentityPresentation = (
  run: Pick<ScanRun, "label" | "sequence">,
  locale: Locale,
): string => {
  const sequence = run.sequence;
  if (!Number.isSafeInteger(sequence) || (sequence ?? 0) < 1) return run.label;
  return locale === "zh-TW" ? `第 ${sequence} 次掃描` : `Scan ${sequence}`;
};
