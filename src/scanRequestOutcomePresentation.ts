import type { BilingualText } from "./i18n";
import type { ScanRequestOutcome } from "./types";

export interface ScanRequestOutcomeBeginnerSummary {
  title: BilingualText;
  description: BilingualText;
  nextStep: BilingualText;
}

const title: BilingualText = {
  en: "No checks completed",
  zhTW: "沒有完成任何檢查",
};

const summaries: Record<ScanRequestOutcome["code"], { reason: BilingualText; nextStep: BilingualText }> = {
  no_effective_scope_grants: {
    reason: {
      en: "The saved permission was missing or expired.",
      zhTW: "已保存的許可不存在或已過期。",
    },
    nextStep: {
      en: "Open Scan setup, confirm the intended target and allowed check once, then start a new scan.",
      zhTW: "請打開「掃描設定」，確認一次預期目標與允許的檢查，再開始新的掃描。",
    },
  },
  no_ownership_confirmed_targets: {
    reason: {
      en: "The selected targets have no recorded scan authorization.",
      zhTW: "所選目標沒有已記錄的掃描授權。",
    },
    nextStep: {
      en: "Open Scan setup, record authorization for each exact target, then start a new scan.",
      zhTW: "打開「掃描設定」，記錄每個精確目標的授權，再開始新的掃描。",
    },
  },
  no_applicable_checks: {
    reason: {
      en: "No available check matched the selected items.",
      zhTW: "沒有可用檢查符合已選項目。",
    },
    nextStep: {
      en: "Review the selected target and scan type, then choose the matching check.",
      zhTW: "請檢查所選目標與掃描類型，再選擇相符的檢查。",
    },
  },
};

/** Maps closed backend codes to stable first-layer wording; raw explanations stay technical. */
export const scanRequestOutcomeBeginnerSummary = (
  outcome: ScanRequestOutcome | undefined,
): ScanRequestOutcomeBeginnerSummary | undefined => {
  if (!outcome) return undefined;
  const summary = summaries[outcome.code];
  return {
    title,
    description: summary.reason,
    nextStep: summary.nextStep,
  };
};
