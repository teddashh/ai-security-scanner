import { useEffect, useMemo, useState } from "react";

import { displaySafeTechnicalDetail } from "../technicalDetails";
import type { ScannerSetupBlocker } from "../scanReadiness";
import { resolveRuntimeSetupPresentation } from "../runtimeSetupPresentation";
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
  repairing?: boolean;
  scannerSetupBlocker?: ScannerSetupBlocker;
  onSetup: () => void;
  onRepair: () => void;
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
  repair: string;
  repairing: string;
  approval: string;
  moreOptions: string;
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
  scannerIssues: Partial<Record<ScannerSetupBlocker, {
    title: string;
    description: string;
    action: string;
    releaseHref: string;
  }>>;
  phases: Record<ManagedRuntimeSetupPhase, string>;
  actions: Record<ManagedRuntimeSetupNextAction, RuntimeActionCopy>;
}

const MICROSOFT_WSL_HELP = "https://learn.microsoft.com/windows/wsl/install";
const PRODUCT_RELEASES = "https://github.com/teddashh/ai-security-scanner/releases";

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
    retry: "Check again",
    repair: "Let ai-security-scanner handle it",
    repairing: "Waiting for Windows…",
    approval: "Windows will ask for administrator approval once. Choose Yes to continue. ai-security-scanner never sees or saves your password.",
    moreOptions: "Other ways",
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
    scannerIssues: {
      no_runnable_authorized_targets: {
        title: "Get the scan tools for this check",
        description: "This target is ready, but this version has no working scan tool for it. Install the newest release; your local scan projects will stay on this device.",
        action: "Get the latest installer",
        releaseHref: PRODUCT_RELEASES,
      },
      egress_gateway_unavailable: {
        title: "Restore one installed scan component",
        description: "The private connection component installed with this app could not be verified. Install the newest release again; your local scan projects will stay on this device.",
        action: "Get the latest installer",
        releaseHref: PRODUCT_RELEASES,
      },
      engine_execution_contract_invalid: {
        title: "Restore one installed scan component",
        description: "A required part of this check is missing or out of date. Install the newest release again; your local scan projects will stay on this device.",
        action: "Get the latest installer",
        releaseHref: PRODUCT_RELEASES,
      },
    },
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
        title: "Windows needs one component",
        description: "ai-security-scanner can install WSL 2 for you, then continue setting up the scan tools.",
        steps: [
          "Open PowerShell as Administrator.",
          "Run the command below.",
          "Restart Windows, reopen ai-security-scanner, then check again.",
        ],
        command: "wsl --install --no-distribution",
      },
      enable_wsl_optional_features: {
        title: "Turn on the Windows tools used for scanning",
        description: "ai-security-scanner can turn on WSL 2 for you, then continue setup.",
        steps: [
          "Open PowerShell as Administrator.",
          "Run the command below.",
          "Restart Windows, reopen ai-security-scanner, then check again.",
        ],
        command: "wsl --install --no-distribution",
      },
      update_wsl: {
        title: "Windows needs a quick WSL update",
        description: "ai-security-scanner can run the update for you and continue setup when it finishes.",
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
    retry: "重新檢查",
    repair: "交給 ai-security-scanner 處理",
    repairing: "正在等候 Windows…",
    approval: "Windows 會顯示一次系統管理員確認；按「是」即可繼續。ai-security-scanner 不會看到或儲存你的密碼。",
    moreOptions: "其他方式",
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
    scannerIssues: {
      no_runnable_authorized_targets: {
        title: "取得這項檢查需要的掃描工具",
        description: "目標已準備好，但這個版本沒有可執行這項檢查的工具。請重新安裝最新版本；這台電腦上的掃描專案會完整保留。",
        action: "取得最新安裝程式",
        releaseHref: PRODUCT_RELEASES,
      },
      egress_gateway_unavailable: {
        title: "恢復一項安裝元件",
        description: "程式無法確認隨附的專用連線元件。請重新安裝最新版本；這台電腦上的掃描專案會完整保留。",
        action: "取得最新安裝程式",
        releaseHref: PRODUCT_RELEASES,
      },
      engine_execution_contract_invalid: {
        title: "恢復一項安裝元件",
        description: "這項檢查缺少必要元件，或元件已過期。請重新安裝最新版本；這台電腦上的掃描專案會完整保留。",
        action: "取得最新安裝程式",
        releaseHref: PRODUCT_RELEASES,
      },
    },
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
        title: "Windows 還差一個元件",
        description: "ai-security-scanner 可以替你安裝 WSL 2，完成後會繼續準備掃描工具。",
        steps: [
          "以系統管理員身分開啟 PowerShell。",
          "執行下方指令。",
          "重新啟動 Windows、再開啟 ai-security-scanner，然後重新檢查。",
        ],
        command: "wsl --install --no-distribution",
      },
      enable_wsl_optional_features: {
        title: "開啟掃描需要的 Windows 工具",
        description: "ai-security-scanner 可以替你開啟 WSL 2，完成後會繼續設定。",
        steps: [
          "以系統管理員身分開啟 PowerShell。",
          "執行下方指令。",
          "重新啟動 Windows、再開啟 ai-security-scanner，然後重新檢查。",
        ],
        command: "wsl --install --no-distribution",
      },
      update_wsl: {
        title: "Windows 需要快速更新 WSL",
        description: "ai-security-scanner 可以替你執行更新，完成後自動繼續。",
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

const canRepairAutomatically = (
  action: ManagedRuntimeSetupNextAction | undefined,
): action is "install_wsl" | "enable_wsl_optional_features" | "update_wsl" =>
  action === "install_wsl"
  || action === "enable_wsl_optional_features"
  || action === "update_wsl";

export function RuntimeSetupAssistant({
  locale,
  mode,
  runtime,
  status,
  busy,
  repairing,
  scannerSetupBlocker,
  onSetup,
  onRepair,
  onCancel,
}: RuntimeSetupAssistantProps) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const text = copy[locale];
  const presentation = resolveRuntimeSetupPresentation({
    mode,
    runtimeAvailable: runtime?.available === true,
    status,
    blocker: scannerSetupBlocker,
  });
  const scannerIssue = presentation.showPackagedComponentIssue && scannerSetupBlocker
    ? text.scannerIssues[scannerSetupBlocker]
    : undefined;
  const { ready, setupActive, setupFailed } = presentation;
  const nextAction = status?.nextAction ? text.actions[status.nextAction] : undefined;
  const repairable = canRepairAutomatically(status?.nextAction);
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

  const title = scannerIssue?.title ?? (setupFailed
    ? nextAction?.title ?? text.failedTitle
    : setupActive
      ? text.progressTitle
      : text.title);
  const description = scannerIssue?.description ?? (setupFailed && nextAction
    ? nextAction.description
    : setupFailed
      ? text.failedDescription
      : setupActive
        ? text.progressDescription
        : text.description);

  return (
    <section
      className={`runtime-assistant${setupFailed ? " runtime-assistant--failed" : ""}`}
      aria-labelledby="runtime-assistant-title"
      aria-live="polite"
    >
      <header className="runtime-assistant__header">
        <span className="runtime-assistant__icon">
          <Icon name={setupFailed ? "warning" : "settings"} size={23} />
        </span>
        <div>
          <p className="eyebrow">{text.eyebrow}</p>
          <h2 id="runtime-assistant-title">{title}</h2>
          <p>{description}</p>
        </div>
      </header>

      {!scannerIssue && status && status.phase !== "idle" && (
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

      {setupFailed && nextAction && (
        <div className="runtime-assistant__recovery">
          {repairable ? (
            <p className="runtime-assistant__approval">
              <Icon name="info" size={17} />
              <span>{text.approval}</span>
            </p>
          ) : (
            <>
              <ol>
                {nextAction.steps.map((step) => <li key={step}>{step}</li>)}
              </ol>
              <a href={MICROSOFT_WSL_HELP} target="_blank" rel="noreferrer">
                {text.docs} <Icon name="external" size={14} />
              </a>
            </>
          )}
        </div>
      )}

      <div className="runtime-assistant__actions">
        {scannerIssue ? (
          <a
            className="button button--primary"
            href={scannerIssue.releaseHref}
            target="_blank"
            rel="noreferrer"
          >
            <Icon name="external" size={17} />
            {scannerIssue.action}
          </a>
        ) : setupActive ? (
          <button
            className="button button--danger-ghost"
            type="button"
            disabled={!status?.canCancel || status.cancelRequested}
            onClick={onCancel}
          >
            <Icon name="close" size={16} />
            {status?.cancelRequested ? text.cancelling : text.cancel}
          </button>
        ) : setupFailed && repairable && status?.nextAction ? (
          <button
            className="button button--primary"
            type="button"
            disabled={busy}
            onClick={onRepair}
          >
            <Icon name="settings" size={17} />
            {repairing ? text.repairing : text.repair}
          </button>
        ) : (
          <button className="button button--primary" type="button" disabled={busy} onClick={onSetup}>
            <Icon name="refresh" size={17} />
            {setupFailed ? text.retry : text.start}
          </button>
        )}
      </div>

      {setupFailed && repairable && nextAction && (
        <details className="runtime-assistant__manual">
          <summary>{text.moreOptions}</summary>
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
        </details>
      )}

      {technicalDetail && setupFailed && (
        <details className="runtime-assistant__technical">
          <summary>{text.technical}</summary>
          <code>{technicalDetail}</code>
        </details>
      )}
    </section>
  );
}
