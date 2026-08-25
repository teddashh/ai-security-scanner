import { useI18n, type Translator } from "../i18n";
import type { AppUpdateState } from "../services/appUpdater";
import { Icon } from "./Icon";

interface AppUpdateControlProps {
  state: AppUpdateState;
  onCheck: () => void;
  onInstall: (version: string) => void;
}

const progressLabel = (
  state: AppUpdateState,
  t: Translator,
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string,
): string => {
  if (state.phase === "installing") return t("update.installing");
  if (state.phase === "restarting") return t("update.restarting");
  if (state.totalBytes && state.downloadedBytes !== undefined) {
    const percent = Math.min(100, Math.floor((state.downloadedBytes / state.totalBytes) * 100));
    return t("update.downloadingPercent", { percent: formatNumber(percent) });
  }
  return t("update.downloading");
};

export function AppUpdateControl({ state, onCheck, onInstall }: AppUpdateControlProps) {
  const { t, formatNumber } = useI18n();

  if (state.phase === "unavailable") return null;

  if (["downloading", "installing", "restarting"].includes(state.phase)) {
    return (
      <span className="update-control update-control--busy" role="status">
        <span className="loading-spinner" aria-hidden="true" />
        {progressLabel(state, t, formatNumber)}
      </span>
    );
  }

  if (state.phase === "available" && state.availableVersion) {
    const availableVersion = state.availableVersion;
    return (
      <button
        className="update-control update-control--available"
        type="button"
        title={t("update.availableHelp")}
        onClick={() => onInstall(availableVersion)}
      >
        <Icon name="download" size={15} />
        {t("update.available", { version: availableVersion })}
      </button>
    );
  }

  if (state.phase === "error") {
    return (
      <button
        className="update-control update-control--error"
        type="button"
        title={t("update.errorHelp")}
        onClick={onCheck}
      >
        <Icon name="warning" size={15} />
        {t("update.error")}
      </button>
    );
  }

  return (
    <button
      className="update-control"
      type="button"
      disabled={state.phase === "checking"}
      onClick={onCheck}
      title={state.currentVersion
        ? t("update.currentHelp", { version: state.currentVersion })
        : t("update.checkHelp")}
    >
      <Icon name={state.phase === "current" ? "check" : "refresh"} size={15} />
      {state.phase === "checking"
        ? t("update.checking")
        : t("update.version", { version: state.currentVersion ?? t("common.unknownVersion") })}
    </button>
  );
}
