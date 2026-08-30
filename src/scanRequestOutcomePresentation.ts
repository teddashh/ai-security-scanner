import type { BilingualText } from "./i18n";
import type { ScanRequestOutcome } from "./types";

export interface ScanRequestOutcomeBeginnerSummary {
  title: BilingualText;
  description: BilingualText;
  nextStep: BilingualText;
}

const commonDescription: BilingualText = {
  en: "No target was contacted and no check completed. This is not a result with zero problems.",
  zhTW: "這次沒有連線到任何目標，也沒有完成任何檢查；這不代表問題數量是零。",
};

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
      en: "None of the selected targets was confirmed as yours.",
      zhTW: "所選目標都還沒有確認為你所控制。",
    },
    nextStep: {
      en: "Open Scan setup, confirm the target you control, then start a new scan.",
      zhTW: "請打開「掃描設定」，確認你所控制的目標，再開始新的掃描。",
    },
  },
  no_applicable_checks: {
    reason: {
      en: "No available check matched what you selected.",
      zhTW: "目前沒有可用的檢查符合你選擇的內容。",
    },
    nextStep: {
      en: "Review the selected target and scan type. Choose a different check only if it matches what you actually want to test.",
      zhTW: "請查看所選目標與掃描類型；只有在符合真正想測的內容時，才改選其他檢查。",
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
    description: {
      en: `${summary.reason.en} ${commonDescription.en}`,
      zhTW: `${summary.reason.zhTW}${commonDescription.zhTW}`,
    },
    nextStep: summary.nextStep,
  };
};
