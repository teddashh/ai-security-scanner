import type { Locale } from "./i18n";

/** Closed locale coordinate accepted by the native HTML report renderer. */
export type ReportLocale = "en" | "zh-Hant";

export const reportLocaleForUiLocale = (locale: Locale): ReportLocale =>
  locale === "zh-TW" ? "zh-Hant" : "en";

export const isReportLocale = (value: unknown): value is ReportLocale =>
  value === "en" || value === "zh-Hant";
