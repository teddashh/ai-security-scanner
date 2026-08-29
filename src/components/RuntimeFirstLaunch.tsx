import type { AppSnapshot, ManagedRuntimeSetupStatus } from "../types";
import type { Locale } from "../i18n";
import { Icon } from "./Icon";
import { RuntimeSetupAssistant } from "./RuntimeSetupAssistant";

import "../runtime-first-launch.css";

interface RuntimeFirstLaunchProps {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  runtime?: AppSnapshot["runtime"];
  status?: ManagedRuntimeSetupStatus;
  statusLoaded: boolean;
  busy: boolean;
  automaticAttemptFailed: boolean;
  onSetup: () => void;
  onCancel: () => void;
}

const copy = {
  en: {
    eyebrow: "FIRST LAUNCH",
    title: "Installing your scan tools",
    description:
      "ai-security-scanner is checking this computer and preparing its private scan tools now, so there is no extra setup after you enter the app.",
    checkingTitle: "Checking this computer",
    checkingDescription:
      "No action is needed. The app detects WSL 2 and prepares the scan tools automatically. If WSL is not ready, you will get one clear Microsoft setup step.",
    restart: "If Microsoft’s WSL setup asks for a restart, reopen ai-security-scanner afterward and preparation will continue automatically.",
    openingTitle: "Opening ai-security-scanner",
    openingDescription: "Checking the scan tools already installed on this computer.",
    recoveryTitle: "Finishing a previous setup",
    recoveryDescription: "We found scan-tool files left by an earlier setup. ai-security-scanner is saving a recovery copy, replacing that workspace, and continuing automatically.",
    externalActionTitle: "Finish one Windows setup step",
    externalActionDescription: "The app found one Windows step that must be completed outside ai-security-scanner. Follow the action below, then check again.",
    stoppedTitle: "Scan-tool setup stopped",
    stoppedDescription: "Automatic setup could not finish. Try setup again below; your scan projects are unchanged.",
    pausedTitle: "Scan-tool setup paused",
    pausedDescription: "The completed part of the download was kept. Continue setup below whenever you are ready.",
    language: "Language",
    english: "English",
    chinese: "Traditional Chinese",
  },
  "zh-TW": {
    eyebrow: "第一次啟動",
    title: "正在安裝掃描工具",
    description:
      "ai-security-scanner 現在就會檢查這台電腦並準備專用掃描工具，進入產品後不必再多做一次設定。",
    checkingTitle: "正在檢查這台電腦",
    checkingDescription:
      "目前不需要操作。程式會自動偵測 WSL 2 並準備掃描工具；如果 WSL 尚未就緒，只會顯示一個清楚的 Microsoft 設定步驟。",
    restart: "如果 Microsoft 的 WSL 設定要求重新開機，再打開 ai-security-scanner 就會自動接著完成。",
    openingTitle: "正在開啟 ai-security-scanner",
    openingDescription: "正在確認這台電腦已安裝的掃描工具。",
    recoveryTitle: "正在完成先前未完成的設定",
    recoveryDescription: "程式找到上次設定留下的掃描工具工作區，會先保留一份復原備份，再換成乾淨的工作區並自動繼續。",
    externalActionTitle: "完成一個 Windows 設定步驟",
    externalActionDescription: "程式找到一個必須在 ai-security-scanner 外完成的 Windows 步驟。請照下方操作完成，再重新檢查。",
    stoppedTitle: "掃描工具設定已停止",
    stoppedDescription: "自動設定未能完成。請在下方再試一次；你的掃描專案沒有變更。",
    pausedTitle: "掃描工具設定已暫停",
    pausedDescription: "已完成的下載進度已保留；準備好時可在下方繼續設定。",
    language: "語言",
    english: "英文",
    chinese: "繁體中文",
  },
} as const;

export function RuntimeFirstLaunch({
  locale,
  setLocale,
  runtime,
  status,
  statusLoaded,
  busy,
  automaticAttemptFailed,
  onSetup,
  onCancel,
}: RuntimeFirstLaunchProps) {
  const text = copy[locale];
  const checkingInstalledState = runtime === undefined;
  const needsExternalAction = status?.phase === "failed" && status.nextAction !== undefined;
  const setupStopped = status?.phase === "failed" && !status.nextAction;
  const setupPaused = status?.phase === "cancelled";
  const recoveringPreviousWorkspace = status?.phase === "recovery" && status.active === true;
  const waitingForAutomaticCheck = !recoveringPreviousWorkspace && (!statusLoaded
    || busy
    || status?.active === true
    || (!automaticAttemptFailed && (!status || status.phase === "idle")));
  const introTitle = checkingInstalledState
    ? text.openingTitle
    : recoveringPreviousWorkspace
      ? text.recoveryTitle
    : setupStopped
      ? text.stoppedTitle
      : needsExternalAction
        ? text.externalActionTitle
        : setupPaused
          ? text.pausedTitle
          : text.title;
  const introDescription = checkingInstalledState
    ? text.openingDescription
    : recoveringPreviousWorkspace
      ? text.recoveryDescription
    : setupStopped
      ? text.stoppedDescription
      : needsExternalAction
        ? text.externalActionDescription
        : setupPaused
          ? text.pausedDescription
          : text.description;

  return (
    <main className="runtime-first-launch">
      <header className="runtime-first-launch__topbar">
        <div className="runtime-first-launch__brand">
          <span><Icon name="shield" size={22} /></span>
          <strong>ai-security-scanner</strong>
        </div>
        <div className="runtime-first-launch__languages" aria-label={text.language}>
          <button
            type="button"
            aria-pressed={locale === "en"}
            onClick={() => setLocale("en")}
          >
            {text.english}
          </button>
          <button
            type="button"
            aria-pressed={locale === "zh-TW"}
            onClick={() => setLocale("zh-TW")}
          >
            {text.chinese}
          </button>
        </div>
      </header>

      <div className="runtime-first-launch__content">
        <section className="runtime-first-launch__intro" aria-labelledby="runtime-first-launch-title">
          {!checkingInstalledState && <p className="eyebrow">{text.eyebrow}</p>}
          <h1 id="runtime-first-launch-title">
            {introTitle}
          </h1>
          <p>{introDescription}</p>
        </section>

        {waitingForAutomaticCheck ? (
          <section className="runtime-first-launch__checking" role="status" aria-live="polite">
            <span className="loading-spinner" aria-hidden="true" />
            <div>
              <strong>{text.checkingTitle}</strong>
              <p>{text.checkingDescription}</p>
            </div>
          </section>
        ) : (
          <RuntimeSetupAssistant
            locale={locale}
            mode="native"
            runtime={runtime}
            status={status}
            busy={busy}
            onSetup={onSetup}
            onCancel={onCancel}
          />
        )}

        {!checkingInstalledState && (
          <p className="runtime-first-launch__restart">
            <Icon name="info" size={16} />
            <span>{text.restart}</span>
          </p>
        )}
      </div>
    </main>
  );
}
