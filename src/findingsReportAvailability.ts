import type { BilingualText } from "./i18n";

export const unavailableRunBoundReportCopy: {
  title: BilingualText;
  body: BilingualText;
} = {
  title: {
    en: "Master report unavailable for this scan",
    zhTW: "這次掃描沒有主要報告",
  },
  body: {
    en: "Start a new scan to create one. Open Review scanner status or Export for this saved run.",
    zhTW: "請開始新的掃描以建立主要報告；這筆掃描可在「查看掃描器狀態」或「匯出」開啟。",
  },
};

export const unavailableSelectedRunCopy: {
  title: BilingualText;
  body: BilingualText;
} = {
  title: {
    en: "This selected scan is no longer available",
    zhTW: "選取的掃描輪次已無法使用",
  },
  body: {
    en: "Refresh this project in My scans, then select an available run.",
    zhTW: "請在「我的掃描」重新整理專案，再選擇可用的掃描輪次。",
  },
};
