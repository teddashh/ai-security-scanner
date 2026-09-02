export type SettingsRuntimeState = "demo" | "ready" | "unavailable" | "unchecked";

export interface SettingsRuntimeCopy {
  en: string;
  zhTW: string;
}

export interface SettingsRuntimePresentation {
  state: SettingsRuntimeState;
  icon: "spark" | "check" | "warning" | "clock";
  status: SettingsRuntimeCopy;
}

const presentations: Record<SettingsRuntimeState, SettingsRuntimePresentation> = {
  demo: {
    state: "demo",
    icon: "spark",
    status: {
      en: "Sample mode is active. No real target is being tested.",
      zhTW: "目前是範例模式，不會檢查真實目標。",
    },
  },
  ready: {
    state: "ready",
    icon: "check",
    status: {
      en: "Local scan tools were ready at the last check.",
      zhTW: "本機掃描工具在上次檢查時已就緒。",
    },
  },
  unavailable: {
    state: "unavailable",
    icon: "warning",
    status: {
      en: "The last check found one or more local scan tools unavailable. Saved projects and reports remain available; try automatic preparation again.",
      zhTW: "上次檢查發現一項或多項本機掃描工具無法使用。已保存的專案與報告仍可使用；請再試一次自動準備。",
    },
  },
  unchecked: {
    state: "unchecked",
    icon: "clock",
    status: {
      en: "Local scan tools have not been checked yet. Their status will appear here after the first check; saved projects and reports remain available.",
      zhTW: "尚未檢查本機掃描工具。完成第一次檢查後，這裡才會顯示工具狀態；已保存的專案與報告仍可使用。",
    },
  },
};

export const getSettingsRuntimePresentation = (
  mode: "native" | "demo",
  runtimeAvailable: boolean | undefined,
): SettingsRuntimePresentation => {
  if (mode === "demo") return presentations.demo;
  if (runtimeAvailable === true) return presentations.ready;
  if (runtimeAvailable === false) return presentations.unavailable;
  return presentations.unchecked;
};
