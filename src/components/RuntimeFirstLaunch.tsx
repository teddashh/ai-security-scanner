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
  busy: boolean;
  repairing: boolean;
  automaticAttemptFailed: boolean;
  onSetup: () => void;
  onRepair: () => void;
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
      "No action is needed. If Windows needs WSL 2 installed or updated, we will show one Windows approval button here.",
    restart: "If Windows asks for a restart, reopen ai-security-scanner afterward and setup will continue automatically.",
    openingTitle: "Opening ai-security-scanner",
    openingDescription: "Checking the scan tools already installed on this computer.",
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
      "目前不需要操作。如果 Windows 需要安裝或更新 WSL 2，這裡只會出現一個 Windows 確認按鈕。",
    restart: "如果 Windows 要求重新開機，再打開 ai-security-scanner 就會自動接著完成。",
    openingTitle: "正在開啟 ai-security-scanner",
    openingDescription: "正在確認這台電腦已安裝的掃描工具。",
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
  busy,
  repairing,
  automaticAttemptFailed,
  onSetup,
  onRepair,
  onCancel,
}: RuntimeFirstLaunchProps) {
  const text = copy[locale];
  const checkingInstalledState = runtime === undefined;
  const waitingForAutomaticCheck = !automaticAttemptFailed
    && (!status
      || status.phase === "idle"
      || (status.phase === "completed" && runtime?.available !== true));

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
            {checkingInstalledState ? text.openingTitle : text.title}
          </h1>
          <p>{checkingInstalledState ? text.openingDescription : text.description}</p>
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
            repairing={repairing}
            onSetup={onSetup}
            onRepair={onRepair}
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
