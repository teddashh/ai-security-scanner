import type { BilingualText } from "./i18n";

export const unavailableRunBoundReportCopy: {
  title: BilingualText;
  body: BilingualText;
} = {
  title: {
    en: "This saved report is unavailable",
    zhTW: "這份已保存的報告目前無法使用",
  },
  body: {
    en: "Findings from other scan runs are not shown in its place. The original project data remains unchanged; start a new scan to create one complete run-bound report.",
    zhTW: "這裡不會改顯示其他掃描輪次的問題。原始專案資料仍保持不變；請開始新的掃描，以建立一份完整且綁定單一輪次的報告。",
  },
};
