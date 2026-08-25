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
    eyebrow: "ONE QUICK SETUP",
    title: "Get your local scan tools ready",
    description:
      "Click once and ai-security-scanner will check this computer and automatically prepare the local scan tools. If Windows needs one change, you will get one clear next step.",
    readyTitle: "Your local scan tools are ready",
    readyDescription: "Choose what you want to scan and get started.",
    demoTitle: "Explore a scan with sample results",
    demoDescription: "Open the desktop app when you are ready to scan a real website, cloud account, network, or codebase.",
    progressTitle: "Getting your scan tools ready",
    progressDescription: "We are downloading and setting up everything automatically. First-time setup may take a few minutes.",
    start: "Set up automatically",
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
    failedTitle: "Setup needs one more step",
    failedDescription: "Follow the single action below, then check again. Your scan projects are unchanged.",
    phases: {
      idle: "Ready to begin",
      install: "Preparing the scan tools",
      prerequisite: "Checking this Windows computer",
      download: "Downloading the scan tools",
      init: "Creating your local scan workspace",
      start: "Starting the scan tools",
      verify: "Running one final check",
      completed: "Scan tools ready",
      failed: "Setup needs attention",
      cancelled: "Setup stopped; the download was kept",
    },
    actions: {
      install_wsl: {
        title: "Install the Windows component used by the scan tools",
        description: "Windows Subsystem for Linux (WSL 2) is not available yet. Install it once, then ai-security-scanner can finish automatically.",
        steps: [
          "Open PowerShell as Administrator.",
          "Run the command below.",
          "Restart Windows, reopen ai-security-scanner, then check again.",
        ],
        command: "wsl --install --no-distribution",
      },
      enable_wsl_optional_features: {
        title: "Turn on the Windows components used by the scan tools",
        description: "WSL or Virtual Machine Platform is turned off. Windows must enable these components before automatic setup can continue.",
        steps: [
          "Open PowerShell as Administrator.",
          "Run the command below.",
          "Restart Windows, reopen ai-security-scanner, then check again.",
        ],
        command: "wsl --install --no-distribution",
      },
      update_wsl: {
        title: "Update Windows Subsystem for Linux",
        description: "WSL is installed, but its current version cannot create the local scan workspace.",
        steps: [
          "Open PowerShell.",
          "Run the command below and let Windows finish the update.",
          "Return here and check again.",
        ],
        command: "wsl --update",
      },
      restart_windows: {
        title: "Restart Windows once",
        description: "Windows has a pending WSL change. The scan tools can finish setup after the restart.",
        steps: [
          "Save your work and restart Windows.",
          "Reopen ai-security-scanner.",
          "Return here and check again.",
        ],
      },
      retry_wsl_check: {
        title: "Windows could not report the WSL status",
        description: "No scan tool changes were made. Retry the check; if it still fails, use Microsoft's WSL troubleshooting instructions.",
        steps: ["Close any Windows update or WSL setup window that is still running.", "Return here and check again."],
      },
    },
  },
  "zh-TW": {
    eyebrow: "快速設定一次即可",
    title: "準備本機掃描工具",
    description:
      "按一下，ai-security-scanner 就會檢查這台電腦並自動準備本機掃描工具；如果 Windows 還差一項設定，你只會看到一個清楚的下一步。",
    readyTitle: "本機掃描工具準備好了",
    readyDescription: "選擇你想掃描的項目，就能直接開始。",
    demoTitle: "先用範例結果看看掃描怎麼運作",
    demoDescription: "準備掃描真實網站、雲端帳號、網路或程式碼時，再開啟桌面版即可。",
    progressTitle: "正在準備掃描工具",
    progressDescription: "系統會自動下載並完成設定；第一次可能需要幾分鐘。",
    start: "自動完成設定",
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
    failedTitle: "設定還差一個步驟",
    failedDescription: "照著下方唯一的操作完成後，再重新檢查；你的掃描專案不會受到影響。",
    phases: {
      idle: "可以開始",
      install: "正在準備掃描工具",
      prerequisite: "檢查這台 Windows 電腦",
      download: "正在下載掃描工具",
      init: "正在建立本機掃描工作區",
      start: "正在啟動掃描工具",
      verify: "正在做最後確認",
      completed: "掃描工具準備好了",
      failed: "設定需要處理",
      cancelled: "已停止設定；下載進度已保留",
    },
    actions: {
      install_wsl: {
        title: "安裝掃描工具需要的 Windows 元件",
        description: "這台電腦還沒有 Windows Subsystem for Linux（WSL 2）。安裝一次後，其餘設定會自動完成。",
        steps: [
          "以系統管理員身分開啟 PowerShell。",
          "執行下方指令。",
          "重新啟動 Windows、再開啟 ai-security-scanner，然後重新檢查。",
        ],
        command: "wsl --install --no-distribution",
      },
      enable_wsl_optional_features: {
        title: "開啟掃描工具需要的 Windows 元件",
        description: "WSL 或虛擬機器平台目前未開啟；Windows 啟用後，其餘設定就會自動繼續。",
        steps: [
          "以系統管理員身分開啟 PowerShell。",
          "執行下方指令。",
          "重新啟動 Windows、再開啟 ai-security-scanner，然後重新檢查。",
        ],
        command: "wsl --install --no-distribution",
      },
      update_wsl: {
        title: "更新 Windows Subsystem for Linux",
        description: "WSL 已安裝，但目前版本還不能建立本機掃描工作區。",
        steps: [
          "開啟 PowerShell。",
          "執行下方指令，等 Windows 完成更新。",
          "回到這裡重新檢查。",
        ],
        command: "wsl --update",
      },
      restart_windows: {
        title: "重新啟動 Windows 一次",
        description: "Windows 還有尚未套用的 WSL 變更；重新開機後，掃描工具就能完成設定。",
        steps: ["儲存目前工作並重新啟動 Windows。", "重新開啟 ai-security-scanner。", "回到這裡重新檢查。"],
      },
      retry_wsl_check: {
        title: "Windows 暫時無法回報 WSL 狀態",
        description: "這次沒有改動掃描工具。請重新檢查；如果仍失敗，再依 Microsoft 的 WSL 說明排除問題。",
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
