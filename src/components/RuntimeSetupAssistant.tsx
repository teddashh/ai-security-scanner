import { useMemo } from "react";

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
  scannerIssueBusy?: boolean;
  scannerSetupBlocker?: ScannerSetupBlocker;
  onSetup: () => void;
  onCheckScannerAvailability: () => void;
  onCancel: () => void;
}

interface RuntimeActionCopy {
  title: string;
  description: string;
}

interface RuntimeAssistantCopy {
  eyebrow: string;
  title: string;
  description: string;
  readyTitle: string;
  readyDescription: string;
  idleTitle: string;
  idleDescription: string;
  demoTitle: string;
  demoDescription: string;
  progressTitle: string;
  progressDescription: string;
  staleTitle: string;
  staleDescription: string;
  recoveryTitle: string;
  recoveryDescription: string;
  cancelledTitle: string;
  cancelledDescription: string;
  start: string;
  continue: string;
  retry: string;
  starting: string;
  cancel: string;
  cancelling: string;
  technical: string;
  downloaded: string;
  resumed: string;
  failedTitle: string;
  failedDescription: string;
  scannerIssues: Partial<Record<ScannerSetupBlocker, {
    title: string;
    description: string;
    action: string;
  }>>;
  phases: Record<ManagedRuntimeSetupPhase, string>;
  actions: Record<ManagedRuntimeSetupNextAction, RuntimeActionCopy>;
}

const copy: Record<RuntimeSetupLocale, RuntimeAssistantCopy> = {
  en: {
    eyebrow: "BACKGROUND PREPARATION",
    title: "Local checks are preparing automatically",
    description:
      "Keep using the app while ai-security-scanner prepares what it can. No separate setup is required.",
    readyTitle: "Local scan tools were ready at the last check",
    readyDescription: "Choose a scan and get started. The app checks them again before it runs.",
    idleTitle: "One local check is not ready yet",
    idleDescription: "Try again and the app will safely continue or restart its automatic preparation. Your saved projects are unchanged.",
    demoTitle: "Explore a scan with sample results",
    demoDescription: "Open the desktop app when you are ready to scan a real website, cloud account, network, or codebase.",
    progressTitle: "Preparing local checks in the background",
    progressDescription: "The app is downloading and preparing available checks automatically. You can keep using saved projects and reports.",
    staleTitle: "Preparation took longer than expected",
    staleDescription: "The app is stopping that exact attempt safely and will offer Retry when it has stopped. Your projects and reports remain available.",
    recoveryTitle: "Preparing a fresh scan workspace",
    recoveryDescription: "Older or unfinished tool data is being preserved while the app prepares an isolated replacement automatically.",
    cancelledTitle: "Setup paused",
    cancelledDescription: "The download was kept on this computer. Continue when you are ready; your scan projects are unchanged.",
    start: "Try preparation again",
    continue: "Continue setup",
    retry: "Try setup again",
    starting: "Starting setup…",
    cancel: "Stop setup and keep the download",
    cancelling: "Stopping…",
    technical: "Technical details",
    downloaded: "downloaded",
    resumed: "Existing download reused",
    failedTitle: "One local check is unavailable",
    failedDescription: "Other checks, saved projects, reports, and readable exports remain available. Try automatic preparation again when ready.",
    scannerIssues: {
      no_runnable_authorized_targets: {
        title: "This check is unavailable in the installed version",
        description: "Other available checks can continue and the report will name this coverage gap. Update the app when convenient, then check again.",
        action: "Check availability again",
      },
      egress_gateway_unavailable: {
        title: "One installed scan component is unavailable",
        description: "This installed component cannot run this check right now. Other checks and reports remain available. Update the app if offered, then check again.",
        action: "Check availability again",
      },
      engine_execution_contract_invalid: {
        title: "One installed scan component is unavailable",
        description: "This installed component cannot run this check right now. Other checks and reports remain available. Update the app if offered, then check again.",
        action: "Check availability again",
      },
    },
    phases: {
      idle: "Ready to begin",
      install: "Preparing the scan tools",
      prerequisite: "Checking this Windows computer",
      download: "Downloading the scan tools",
      recovery: "Safely recovering the previous workspace",
      init: "Creating your local scan workspace",
      start: "Starting the scan tools",
      verify: "Running one final check",
      completed: "Scan tools ready",
      failed: "Setup needs attention",
      cancelled: "Setup stopped; the download was kept",
    },
    actions: {
      install_wsl: {
        title: "One local scan tool is unavailable",
        description: "Automatic setup could not finish. Your saved scans are unchanged, and checks that do not need this tool remain available. Try automatic setup again.",
      },
      enable_wsl_optional_features: {
        title: "One local scan tool is unavailable",
        description: "Automatic setup could not finish. Your saved scans are unchanged, and checks that do not need this tool remain available. Try automatic setup again.",
      },
      update_wsl: {
        title: "One local scan tool is unavailable",
        description: "Automatic setup could not finish. Your saved scans are unchanged, and checks that do not need this tool remain available. Try automatic setup again.",
      },
      restart_windows: {
        title: "One local scan tool is unavailable right now",
        description: "Windows requires a restart to finish its change. After Windows restarts, reopen ai-security-scanner and automatic setup will resume. Your saved scans are unchanged.",
      },
      retry_wsl_check: {
        title: "One local scan tool is unavailable",
        description: "The automatic check did not finish, and no saved scan was changed. Try automatic setup again; other available checks can still run.",
      },
      resolve_wsl_distribution_manually: {
        title: "Older scan-tool data was preserved",
        description: "The older workspace was left untouched. Retry and the app will prepare a new isolated workspace without deleting the old one.",
      },
    },
  },
  "zh-TW": {
    eyebrow: "背景自動準備",
    title: "正在自動準備本機檢查",
    description:
      "你可以繼續使用程式；ai-security-scanner 會在背景準備可用的檢查，不需要另外完成設定。",
    readyTitle: "本機掃描工具上次檢查時可用",
    readyDescription: "選擇你想掃描的項目即可開始；程式會在執行前再次確認。",
    idleTitle: "一項本機檢查尚未準備好",
    idleDescription: "請再試一次，程式會安全地繼續或重新開始自動準備；已保存的專案不會變更。",
    demoTitle: "先用範例結果看看掃描怎麼運作",
    demoDescription: "準備掃描真實網站、雲端帳號、網路或程式碼時，再開啟桌面版即可。",
    progressTitle: "正在背景準備本機檢查",
    progressDescription: "程式會自動下載並準備可用檢查；你仍可使用已保存的專案與報告。",
    staleTitle: "準備時間超過預期",
    staleDescription: "程式正在安全停止這次作業；停止後會提供「重試」。你的專案與報告仍可使用。",
    recoveryTitle: "正在準備新的隔離掃描空間",
    recoveryDescription: "程式會保留舊的或未完成的工具資料，並自動準備隔離的新工作空間。",
    cancelledTitle: "設定已暫停",
    cancelledDescription: "下載進度已保留在這台電腦上。準備好時可繼續；你的掃描專案沒有變更。",
    start: "再試一次自動準備",
    continue: "繼續設定",
    retry: "再試一次設定",
    starting: "正在開始設定…",
    cancel: "停止設定並保留下載進度",
    cancelling: "正在停止…",
    technical: "技術細節",
    downloaded: "已下載",
    resumed: "已沿用先前下載進度",
    failedTitle: "一項本機檢查目前無法使用",
    failedDescription: "其他檢查、已保存專案、報告與好讀匯出仍可使用；準備好時可再試一次自動準備。",
    scannerIssues: {
      no_runnable_authorized_targets: {
        title: "目前安裝版本無法執行這項檢查",
        description: "其他可用檢查可以繼續，報告也會列出這個涵蓋缺口；方便時更新程式，再重新檢查。",
        action: "重新檢查可用性",
      },
      egress_gateway_unavailable: {
        title: "一項隨附掃描元件目前無法使用",
        description: "這個隨附元件目前無法執行此項檢查；其他檢查與報告仍可使用。若有更新可先更新，再重新檢查。",
        action: "重新檢查可用性",
      },
      engine_execution_contract_invalid: {
        title: "一項隨附掃描元件目前無法使用",
        description: "這個隨附元件目前無法執行此項檢查；其他檢查與報告仍可使用。若有更新可先更新，再重新檢查。",
        action: "重新檢查可用性",
      },
    },
    phases: {
      idle: "可以開始",
      install: "正在準備掃描工具",
      prerequisite: "檢查這台 Windows 電腦",
      download: "正在下載掃描工具",
      recovery: "正在安全復原先前的工作區",
      init: "正在建立本機掃描工作區",
      start: "正在啟動掃描工具",
      verify: "正在做最後確認",
      completed: "掃描工具準備好了",
      failed: "設定需要處理",
      cancelled: "已停止設定；下載進度已保留",
    },
    actions: {
      install_wsl: {
        title: "一項本機掃描工具目前無法使用",
        description: "自動設定未能完成。已保存的掃描沒有變更，不需要這項工具的檢查仍可使用；請再試一次自動設定。",
      },
      enable_wsl_optional_features: {
        title: "一項本機掃描工具目前無法使用",
        description: "自動設定未能完成。已保存的掃描沒有變更，不需要這項工具的檢查仍可使用；請再試一次自動設定。",
      },
      update_wsl: {
        title: "一項本機掃描工具目前無法使用",
        description: "自動設定未能完成。已保存的掃描沒有變更，不需要這項工具的檢查仍可使用；請再試一次自動設定。",
      },
      restart_windows: {
        title: "一項本機掃描工具目前暫時無法使用",
        description: "Windows 必須重新啟動才能完成變更。Windows 重新啟動後，再開啟 ai-security-scanner，自動設定就會繼續；已保存的掃描沒有變更。",
      },
      retry_wsl_check: {
        title: "一項本機掃描工具目前無法使用",
        description: "自動檢查未能完成，而且沒有更動任何已保存的掃描。請再試一次自動設定；其他可用檢查仍可執行。",
      },
      resolve_wsl_distribution_manually: {
        title: "舊的掃描工具資料已保留",
        description: "程式沒有更動舊工作區。再次嘗試時會建立新的隔離工作空間，不需要刪除舊資料。",
      },
    },
  },
};

const byteCount = (value: number, locale: RuntimeSetupLocale): string =>
  `${new Intl.NumberFormat(locale).format(value)} ${locale === "en" ? (value === 1 ? "byte" : "bytes") : "位元組"}`;

export function RuntimeSetupAssistant({
  locale,
  mode,
  runtime,
  status,
  busy,
  scannerIssueBusy,
  scannerSetupBlocker,
  onSetup,
  onCheckScannerAvailability,
  onCancel,
}: RuntimeSetupAssistantProps) {
  const text = copy[locale];
  const presentation = resolveRuntimeSetupPresentation({
    mode,
    runtimeAvailable: runtime?.available === true,
    status,
    requestPending: busy,
    blocker: scannerSetupBlocker,
  });
  const scannerIssue = presentation.showPackagedComponentIssue && scannerSetupBlocker
    ? text.scannerIssues[scannerSetupBlocker]
    : undefined;
  const {
    ready,
    setupStarting,
    setupActive,
    setupRecovering,
    setupStale,
    setupFailed,
    setupCancelled,
    setupIdleUnavailable,
  } = presentation;
  const nextAction = status?.nextAction ? text.actions[status.nextAction] : undefined;
  const preservedUnknownWorkspace = status?.nextAction === "resolve_wsl_distribution_manually";
  const technicalDetail = setupFailed
    ? preservedUnknownWorkspace
      ? "older_workspace_ownership_unconfirmed"
      : "local_scan_tool_unavailable"
    : undefined;
  const progress = useMemo(() => {
    if (!status?.totalBytes || status.totalBytes <= 0) return undefined;
    return Math.min(status.receivedBytes, status.totalBytes);
  }, [status?.receivedBytes, status?.totalBytes]);

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
    : setupCancelled
      ? text.cancelledTitle
    : setupStale
      ? text.staleTitle
    : setupRecovering
      ? text.recoveryTitle
    : setupActive
      ? text.progressTitle
    : setupIdleUnavailable
      ? text.idleTitle
      : text.title);
  const description = scannerIssue?.description ?? (setupFailed && nextAction
    ? nextAction.description
    : setupFailed
      ? text.failedDescription
      : setupCancelled
        ? text.cancelledDescription
      : setupStale
        ? text.staleDescription
      : setupRecovering
        ? text.recoveryDescription
      : setupActive
        ? text.progressDescription
      : setupIdleUnavailable
        ? text.idleDescription
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

      {!scannerIssue && setupStarting && (
        <div className="runtime-assistant__status" role="status">
          <strong>{text.starting}</strong>
        </div>
      )}

      {!scannerIssue && !setupStarting && status && status.phase !== "idle" && (
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

      <div className="runtime-assistant__actions">
        {scannerIssue ? (
          <button
            className="button button--primary"
            type="button"
            disabled={scannerIssueBusy}
            onClick={onCheckScannerAvailability}
          >
            <Icon name="refresh" size={17} />
            {scannerIssue.action}
          </button>
        ) : setupStarting ? (
          <button className="button button--primary" type="button" disabled aria-busy="true">
            <Icon name="progress" size={17} />
            {text.starting}
          </button>
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
        ) : !setupFailed && !setupCancelled && !setupIdleUnavailable ? null : (
          <button className="button button--primary" type="button" disabled={busy} onClick={onSetup}>
            <Icon name="refresh" size={17} />
            {setupFailed ? text.retry : setupCancelled ? text.continue : text.start}
          </button>
        )}
      </div>

      {technicalDetail && setupFailed && (
        <details className="runtime-assistant__technical">
          <summary>{text.technical}</summary>
          <code>{technicalDetail}</code>
        </details>
      )}
    </section>
  );
}
