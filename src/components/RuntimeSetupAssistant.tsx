import { useEffect, useMemo, useState } from "react";

import { displaySafeTechnicalDetail } from "../technicalDetails";
import type {
  AppMode,
  AppSnapshot,
  ManagedRuntimeSetupNextAction,
  ManagedRuntimeSetupPhase,
  ManagedRuntimeSetupStatus,
} from "../types";
import { Icon } from "./Icon";

import "../runtime-setup-assistant.css";

type RuntimeSetupLocale = "en" | "zh-TW";

interface RuntimeSetupAssistantProps {
  locale: RuntimeSetupLocale;
  mode: AppMode;
  runtime?: AppSnapshot["runtime"];
  status?: ManagedRuntimeSetupStatus;
  busy?: boolean;
  onSetup: () => void;
  onCancel: () => void;
}

interface RuntimeActionCopy {
  title: string;
  description: string;
  steps: readonly string[];
  command?: string;
}

interface RuntimeAssistantCopy {
  eyebrow: string;
  title: string;
  description: string;
  readyTitle: string;
  readyDescription: string;
  demoTitle: string;
  demoDescription: string;
  progressTitle: string;
  progressDescription: string;
  start: string;
  retry: string;
  cancel: string;
  cancelling: string;
  docs: string;
  copyCommand: string;
  copied: string;
  copyFailed: string;
  technical: string;
  downloaded: string;
  resumed: string;
  failedTitle: string;
  failedDescription: string;
  phases: Record<ManagedRuntimeSetupPhase, string>;
  actions: Record<ManagedRuntimeSetupNextAction, RuntimeActionCopy>;
}

const MICROSOFT_WSL_HELP = "https://learn.microsoft.com/windows/wsl/install";

const copy: Record<RuntimeSetupLocale, RuntimeAssistantCopy> = {
  en: {
    eyebrow: "ONE-TIME LOCAL SETUP",
    title: "Prepare the private scan engine",
    description:
      "Checks run in an isolated environment on this computer. We check Windows first, before downloading the engine, and never turn on operating-system features without you.",
    readyTitle: "The private scan engine is ready",
    readyDescription: "You can set up a check now. Scan data stays in the local case unless you export it.",
    demoTitle: "The browser preview cannot prepare the scan engine",
    demoDescription: "Open the installed desktop app to run real checks. This preview only shows sample case data.",
    progressTitle: "Setting up the private scan engine",
    progressDescription: "You can leave this screen open while setup continues.",
    start: "Prepare scan engine",
    retry: "I've done this — check again",
    cancel: "Stop setup and keep the download",
    cancelling: "Stopping…",
    docs: "Open Microsoft's WSL instructions",
    copyCommand: "Copy command",
    copied: "Copied",
    copyFailed: "Copying was blocked. Select the command and copy it manually.",
    technical: "Technical details",
    downloaded: "downloaded",
    resumed: "Existing download reused",
    failedTitle: "The scan engine still needs one setup step",
    failedDescription: "Nothing was changed. Use the instructions below, then check again.",
    phases: {
      idle: "Ready to begin",
      install: "Checking the signed engine files",
      prerequisite: "Checking this Windows computer",
      download: "Downloading the verified engine",
      init: "Creating the isolated environment",
      start: "Starting the isolated environment",
      verify: "Confirming the engine is ready",
      completed: "Setup complete",
      failed: "Setup needs one Windows step",
      cancelled: "Setup stopped; the download was kept",
    },
    actions: {
      install_wsl: {
        title: "Install the Windows component used by the private engine",
        description: "Windows Subsystem for Linux (WSL 2) is not available yet. This is a one-time Windows setup.",
        steps: [
          "Open PowerShell as Administrator.",
          "Run the command below.",
          "Restart Windows, reopen ai-security-scanner, then check again.",
        ],
        command: "wsl --install --no-distribution",
      },
      enable_wsl_optional_features: {
        title: "Turn on the Windows components used by the private engine",
        description: "WSL or Virtual Machine Platform is turned off. Windows must enable these components before setup can continue.",
        steps: [
          "Open PowerShell as Administrator.",
          "Run the command below.",
          "Restart Windows, reopen ai-security-scanner, then check again.",
        ],
        command: "wsl --install --no-distribution",
      },
      update_wsl: {
        title: "Update Windows Subsystem for Linux",
        description: "WSL is installed, but its current version cannot create the private scan environment.",
        steps: [
          "Open PowerShell.",
          "Run the command below and let Windows finish the update.",
          "Return here and check again.",
        ],
        command: "wsl --update",
      },
      restart_windows: {
        title: "Restart Windows once",
        description: "Windows has a pending WSL change. The private engine cannot start until the restart completes.",
        steps: [
          "Save your work and restart Windows.",
          "Reopen ai-security-scanner.",
          "Return here and check again.",
        ],
      },
      retry_wsl_check: {
        title: "Windows could not report the WSL status",
        description: "No engine changes were made. Retry the check; if it still fails, use Microsoft's WSL troubleshooting instructions.",
        steps: ["Close any Windows update or WSL setup window that is still running.", "Return here and check again."],
      },
    },
  },
  "zh-TW": {
    eyebrow: "只需一次的本機設定",
    title: "準備私有掃描引擎",
    description:
      "所有檢查都在這台電腦的隔離環境執行。我們會先檢查 Windows，再開始下載；產品不會自行開啟作業系統功能。",
    readyTitle: "私有掃描引擎已經準備好",
    readyDescription: "現在可以設定檢查。除非你主動匯出，掃描資料只會留在本機案件裡。",
    demoTitle: "瀏覽器預覽無法準備掃描引擎",
    demoDescription: "請開啟已安裝的桌面版來執行真實檢查；這個預覽只會顯示範例案件。",
    progressTitle: "正在準備私有掃描引擎",
    progressDescription: "設定會繼續進行，你可以先讓這個畫面保持開啟。",
    start: "準備掃描引擎",
    retry: "我已完成，重新檢查",
    cancel: "停止設定並保留下載進度",
    cancelling: "正在停止…",
    docs: "開啟 Microsoft 的 WSL 安裝說明",
    copyCommand: "複製指令",
    copied: "已複製",
    copyFailed: "系統未允許自動複製。請選取指令並手動複製。",
    technical: "技術細節",
    downloaded: "已下載",
    resumed: "已沿用先前下載進度",
    failedTitle: "掃描引擎還需要完成一個設定步驟",
    failedDescription: "這次沒有變更任何設定。請照下方步驟處理，再重新檢查。",
    phases: {
      idle: "可以開始",
      install: "檢查已簽署的引擎檔案",
      prerequisite: "檢查這台 Windows 電腦",
      download: "下載已驗證的掃描引擎",
      init: "建立隔離環境",
      start: "啟動隔離環境",
      verify: "確認掃描引擎可用",
      completed: "設定完成",
      failed: "還差一個 Windows 步驟",
      cancelled: "已停止設定；下載進度已保留",
    },
    actions: {
      install_wsl: {
        title: "安裝私有掃描引擎需要的 Windows 元件",
        description: "這台電腦還沒有 Windows Subsystem for Linux（WSL 2）。這是一次性的 Windows 設定。",
        steps: [
          "以系統管理員身分開啟 PowerShell。",
          "執行下方指令。",
          "重新啟動 Windows、再開啟 ai-security-scanner，然後重新檢查。",
        ],
        command: "wsl --install --no-distribution",
      },
      enable_wsl_optional_features: {
        title: "開啟私有掃描引擎需要的 Windows 元件",
        description: "WSL 或虛擬機器平台目前未開啟；Windows 必須先啟用這些元件，設定才能繼續。",
        steps: [
          "以系統管理員身分開啟 PowerShell。",
          "執行下方指令。",
          "重新啟動 Windows、再開啟 ai-security-scanner，然後重新檢查。",
        ],
        command: "wsl --install --no-distribution",
      },
      update_wsl: {
        title: "更新 Windows Subsystem for Linux",
        description: "WSL 已安裝，但目前版本還不能建立私有掃描環境。",
        steps: [
          "開啟 PowerShell。",
          "執行下方指令，等 Windows 完成更新。",
          "回到這裡重新檢查。",
        ],
        command: "wsl --update",
      },
      restart_windows: {
        title: "重新啟動 Windows 一次",
        description: "Windows 還有尚未套用的 WSL 變更；重新開機完成前，私有掃描引擎無法啟動。",
        steps: ["儲存目前工作並重新啟動 Windows。", "重新開啟 ai-security-scanner。", "回到這裡重新檢查。"],
      },
      retry_wsl_check: {
        title: "Windows 暫時無法回報 WSL 狀態",
        description: "這次沒有改動掃描引擎。請重新檢查；如果仍失敗，再依 Microsoft 的 WSL 說明排除問題。",
        steps: ["關閉仍在執行的 Windows Update 或 WSL 設定視窗。", "回到這裡重新檢查。"],
      },
    },
  },
};

const byteCount = (value: number, locale: RuntimeSetupLocale): string =>
  `${new Intl.NumberFormat(locale).format(value)} ${locale === "en" ? "bytes" : "位元組"}`;

export function RuntimeSetupAssistant({
  locale,
  mode,
  runtime,
  status,
  busy,
  onSetup,
  onCancel,
}: RuntimeSetupAssistantProps) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const text = copy[locale];
  const ready = mode === "native" && runtime?.available === true;
  const active = status?.active === true;
  const nextAction = status?.nextAction ? text.actions[status.nextAction] : undefined;
  const technicalDetail = displaySafeTechnicalDetail(status?.detail);
  const progress = useMemo(() => {
    if (!status?.totalBytes || status.totalBytes <= 0) return undefined;
    return Math.min(status.receivedBytes, status.totalBytes);
  }, [status?.receivedBytes, status?.totalBytes]);

  const copySetupCommand = async () => {
    if (!nextAction?.command) return;
    try {
      await navigator.clipboard.writeText(nextAction.command);
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1800);
    } catch {
      setCopyState("failed");
    }
  };

  useEffect(() => setCopyState("idle"), [nextAction?.command]);

  if (ready) {
    return (
      <section className="runtime-assistant runtime-assistant--ready" aria-label={text.title}>
        <span className="runtime-assistant__icon"><Icon name="check" size={23} /></span>
        <div>
          <strong>{text.readyTitle}</strong>
          <p>{text.readyDescription}</p>
        </div>
      </section>
    );
  }

  if (mode !== "native") {
    return (
      <section className="runtime-assistant runtime-assistant--demo" aria-label={text.title}>
        <span className="runtime-assistant__icon"><Icon name="info" size={23} /></span>
        <div>
          <strong>{text.demoTitle}</strong>
          <p>{text.demoDescription}</p>
        </div>
      </section>
    );
  }

  const failed = status?.phase === "failed";
  const title = failed ? nextAction?.title ?? text.failedTitle : active ? text.progressTitle : text.title;
  const description = failed && nextAction
    ? nextAction.description
    : failed
      ? text.failedDescription
    : active
      ? text.progressDescription
      : text.description;

  return (
    <section
      className={`runtime-assistant${failed ? " runtime-assistant--failed" : ""}`}
      aria-labelledby="runtime-assistant-title"
      aria-live="polite"
    >
      <header className="runtime-assistant__header">
        <span className="runtime-assistant__icon">
          <Icon name={failed ? "warning" : "settings"} size={23} />
        </span>
        <div>
          <p className="eyebrow">{text.eyebrow}</p>
          <h2 id="runtime-assistant-title">{title}</h2>
          <p>{description}</p>
        </div>
      </header>

      {status && status.phase !== "idle" && (
        <div className="runtime-assistant__status" role="status">
          <strong>{text.phases[status.phase as ManagedRuntimeSetupPhase]}</strong>
          {progress !== undefined && status.totalBytes !== undefined && (
            <>
              <progress max={status.totalBytes} value={progress} />
              <span>
                {byteCount(status.receivedBytes, locale)} / {byteCount(status.totalBytes, locale)} · {text.downloaded}
              </span>
            </>
          )}
          {status.resumedFromBytes > 0 && <span>{text.resumed}</span>}
        </div>
      )}

      {failed && nextAction && (
        <div className="runtime-assistant__recovery">
          <ol>
            {nextAction.steps.map((step) => <li key={step}>{step}</li>)}
          </ol>
          {nextAction.command && (
            <div className="runtime-assistant__command">
              <code>{nextAction.command}</code>
              <button className="button button--small button--secondary" type="button" onClick={() => void copySetupCommand()}>
                <Icon name="file" size={15} />
                {copyState === "copied" ? text.copied : text.copyCommand}
              </button>
            </div>
          )}
          {copyState === "failed" && (
            <p className="runtime-assistant__copy-error" role="status">{text.copyFailed}</p>
          )}
          <a href={MICROSOFT_WSL_HELP} target="_blank" rel="noreferrer">
            {text.docs} <Icon name="external" size={14} />
          </a>
        </div>
      )}

      <div className="runtime-assistant__actions">
        {active ? (
          <button
            className="button button--danger-ghost"
            type="button"
            disabled={!status?.canCancel || status.cancelRequested}
            onClick={onCancel}
          >
            <Icon name="close" size={16} />
            {status?.cancelRequested ? text.cancelling : text.cancel}
          </button>
        ) : (
          <button className="button button--primary" type="button" disabled={busy} onClick={onSetup}>
            <Icon name="refresh" size={17} />
            {failed ? text.retry : text.start}
          </button>
        )}
      </div>

      {technicalDetail && failed && (
        <details className="runtime-assistant__technical">
          <summary>{text.technical}</summary>
          <code>{technicalDetail}</code>
        </details>
      )}
    </section>
  );
}
