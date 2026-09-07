import type { BilingualText } from "./i18n";

export const unavailableRunBoundReportCopy: {
  title: BilingualText;
  body: BilingualText;
} = {
  title: {
    en: "This scan has no durable master report",
    zhTW: "這次掃描缺少可持續保存的主要報告",
  },
  body: {
    en: "Findings from other scan runs are not shown in its place. The exact saved run remains available from the Review scanner status view and can still be exported, but it does not include a durable report bound to this run. Start a new scan to create one.",
    zhTW: "這裡不會改顯示其他掃描輪次的問題。這一輪的精確掃描紀錄仍可在「查看掃描器狀態」中查看，也可以匯出；但它沒有綁定這一輪、可持續保存的主要報告。請開始新的掃描來建立一份。",
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
    en: "The app will not substitute a different scan run. Return to My scans to refresh this project, or choose another saved run when one is listed.",
    zhTW: "程式不會改用其他掃描輪次代替。請回到「我的掃描」重新整理這個專案；若上方列出其他已保存輪次，也可以改選其中一輪。",
  },
};
