import type { AppUpdateState } from "../services/appUpdater";
import { Icon } from "./Icon";

interface AppUpdateControlProps {
  state: AppUpdateState;
  onCheck: () => void;
  onInstall: (version: string) => void;
}

const progressLabel = (state: AppUpdateState): string => {
  if (state.phase === "installing") return "正在驗證並安裝…";
  if (state.phase === "restarting") return "即將重新啟動…";
  if (state.totalBytes && state.downloadedBytes !== undefined) {
    const percent = Math.min(100, Math.floor((state.downloadedBytes / state.totalBytes) * 100));
    return `下載更新 ${percent}%`;
  }
  return "正在下載更新…";
};

export function AppUpdateControl({ state, onCheck, onInstall }: AppUpdateControlProps) {
  if (state.phase === "unavailable") return null;

  if (["downloading", "installing", "restarting"].includes(state.phase)) {
    return (
      <span className="update-control update-control--busy" role="status">
        <span className="loading-spinner" aria-hidden="true" />
        {progressLabel(state)}
      </span>
    );
  }

  if (state.phase === "available" && state.availableVersion) {
    return (
      <button
        className="update-control update-control--available"
        type="button"
        title="更新只會替換已簽章的應用程式版本；既有案件與歷史 provenance 不會被改寫。"
        onClick={() => onInstall(state.availableVersion!)}
      >
        <Icon name="download" size={15} />
        更新至 {state.availableVersion}
      </button>
    );
  }

  if (state.phase === "error") {
    return (
      <button
        className="update-control update-control--error"
        type="button"
        title={state.message}
        onClick={onCheck}
      >
        <Icon name="warning" size={15} />
        更新檢查失敗，重試
      </button>
    );
  }

  return (
    <button
      className="update-control"
      type="button"
      disabled={state.phase === "checking"}
      onClick={onCheck}
      title={state.currentVersion ? `目前版本 ${state.currentVersion}` : "檢查已簽章的應用程式更新"}
    >
      <Icon name={state.phase === "current" ? "check" : "refresh"} size={15} />
      {state.phase === "checking" ? "正在檢查更新…" : `版本 ${state.currentVersion ?? "—"}`}
    </button>
  );
}
