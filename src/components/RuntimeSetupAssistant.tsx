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
  nonRetryableTitle: string;
  nonRetryableDescription: string;
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
    eyebrow: "ADVANCED LOCAL SCAN SETUP",
    title: "Preparing advanced local scan tools automatically",
    description:
      "This setup is only for advanced local scans. The localhost quick check that attempts one TCP connection and your saved results remain available while preparation continues.",
    readyTitle: "Advanced local scan tools were ready at the last check",
    readyDescription: "Choose an advanced local scan and get started. The app checks the tools again before it runs.",
    idleTitle: "Advanced local scan tools need setup",
    idleDescription: "The localhost quick check that attempts one TCP connection and your saved results remain available. Try again and the app will safely continue or restart advanced setup.",
    demoTitle: "Explore a scan with sample results",
    demoDescription: "Open the desktop app when you are ready to scan a real website, cloud account, network, or codebase.",
    progressTitle: "Preparing advanced local scan tools in the background",
    progressDescription: "The app is downloading and preparing advanced local scan tools automatically. The localhost quick check and your saved results remain available.",
    staleTitle: "Advanced local scan-tool setup is taking longer than expected",
    staleDescription: "The app is stopping that exact advanced-setup attempt safely and will offer Retry when it has stopped. The localhost quick check and your saved results remain available.",
    recoveryTitle: "Preparing a fresh advanced local scan workspace",
    recoveryDescription: "Older or unfinished advanced-tool data is being preserved while the app prepares an isolated replacement automatically. The localhost quick check and your saved results remain available.",
    cancelledTitle: "Advanced local scan-tool setup paused",
    cancelledDescription: "The advanced-tool download was kept on this computer. Continue when you are ready; the localhost quick check and your saved results remain available.",
    start: "Try advanced scan setup again",
    continue: "Continue advanced scan setup",
    retry: "Try advanced scan setup again",
    starting: "Starting advanced scan setup…",
    cancel: "Stop advanced scan setup and keep the download",
    cancelling: "Stopping…",
    technical: "Technical details",
    downloaded: "downloaded",
    resumed: "Existing download reused",
    failedTitle: "Advanced local scan-tool setup did not finish",
    failedDescription: "The localhost quick check that attempts one TCP connection and your saved results remain available. Try advanced scan setup again when ready.",
    nonRetryableTitle: "An advanced local scan tool is unavailable in this app version",
    nonRetryableDescription: "The localhost quick check that attempts one TCP connection and your saved results remain available. The report lists the affected advanced check under what was not tested, never as a pass; install a newer complete app version when one is available.",
    scannerIssues: {
      no_runnable_authorized_targets: {
        title: "This check is unavailable in the installed version",
        description: "No check in this version can run for this target. The report will still name this coverage gap, and your saved projects and reports are unchanged. Update the app when convenient, then check again.",
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
      idle: "Ready to set up advanced local scans",
      install: "Preparing advanced local scan tools",
      prerequisite: "Checking advanced local scan requirements on this Windows computer",
      download: "Downloading advanced local scan tools",
      recovery: "Safely recovering the advanced local scan workspace",
      init: "Creating the advanced local scan workspace",
      start: "Starting advanced local scan tools",
      verify: "Running one final advanced-tool check",
      completed: "Advanced local scan tools ready",
      failed: "Advanced local scan-tool setup needs attention",
      cancelled: "Advanced local scan-tool setup stopped; the download was kept",
    },
    actions: {
      install_wsl: {
        title: "Advanced local scan-tool setup did not finish",
        description: "Automatic advanced-tool setup did not finish. The localhost quick check that attempts one TCP connection and your saved results remain available; try automatic setup again.",
      },
      enable_wsl_optional_features: {
        title: "Advanced local scan-tool setup did not finish",
        description: "Automatic advanced-tool setup did not finish. The localhost quick check that attempts one TCP connection and your saved results remain available; try automatic setup again.",
      },
      update_wsl: {
        title: "Advanced local scan-tool setup did not finish",
        description: "Automatic advanced-tool setup did not finish. The localhost quick check that attempts one TCP connection and your saved results remain available; try automatic setup again.",
      },
      restart_windows: {
        title: "Advanced local scan-tool setup is waiting for a Windows restart",
        description: "Windows requires a restart to finish the advanced-tool change. After Windows restarts, reopen ai-security-scanner and automatic setup will resume. The localhost quick check and your saved results remain available.",
      },
      retry_wsl_check: {
        title: "Advanced local scan-tool setup did not finish",
        description: "The automatic advanced-tool check did not finish. The localhost quick check that attempts one TCP connection and your saved results remain available; try automatic setup again.",
      },
    },
  },
  "zh-TW": {
    eyebrow: "進階本機掃描設定",
    title: "正在自動準備進階本機掃描工具",
    description:
      "這項設定只供進階本機掃描使用；準備期間，只嘗試一次 TCP 連線的 localhost 快速檢查與已保存的結果仍可使用。",
    readyTitle: "進階本機掃描工具上次檢查時可用",
    readyDescription: "選擇進階本機掃描即可開始；程式會在執行前再次確認工具狀態。",
    idleTitle: "進階本機掃描工具需要設定",
    idleDescription: "只嘗試一次 TCP 連線的 localhost 快速檢查與已保存的結果仍可使用。請再試一次，程式會安全地繼續或重新開始進階設定。",
    demoTitle: "先用範例結果看看掃描怎麼運作",
    demoDescription: "準備掃描真實網站、雲端帳號、網路或程式碼時，再開啟桌面版即可。",
    progressTitle: "正在背景準備進階本機掃描工具",
    progressDescription: "程式會自動下載並準備進階本機掃描工具；localhost 快速檢查與已保存的結果仍可使用。",
    staleTitle: "進階本機掃描工具設定時間超過預期",
    staleDescription: "程式正在安全停止這次進階設定；停止後會提供「重試」。localhost 快速檢查與已保存的結果仍可使用。",
    recoveryTitle: "正在準備新的進階本機掃描隔離工作區",
    recoveryDescription: "程式會保留舊的或未完成的進階工具資料，並自動準備隔離的新工作空間；localhost 快速檢查與已保存的結果仍可使用。",
    cancelledTitle: "進階本機掃描工具設定已暫停",
    cancelledDescription: "進階工具的下載進度已保留在這台電腦上。準備好時可繼續；localhost 快速檢查與已保存的結果仍可使用。",
    start: "再試一次進階掃描設定",
    continue: "繼續進階掃描設定",
    retry: "再試一次進階掃描設定",
    starting: "正在開始進階掃描設定…",
    cancel: "停止進階掃描設定並保留下載進度",
    cancelling: "正在停止…",
    technical: "技術細節",
    downloaded: "已下載",
    resumed: "已沿用先前下載進度",
    failedTitle: "進階本機掃描工具設定未能完成",
    failedDescription: "只嘗試一次 TCP 連線的 localhost 快速檢查與已保存的結果仍可使用；準備好時可再試一次進階掃描設定。",
    nonRetryableTitle: "這個程式版本無法使用一項進階本機掃描工具",
    nonRetryableDescription: "只嘗試一次 TCP 連線的 localhost 快速檢查與已保存的結果仍可使用。報告會把受影響的進階檢查列在「沒有測到的內容」裡，不會當成通過；有新版完整程式時再更新即可。",
    scannerIssues: {
      no_runnable_authorized_targets: {
        title: "目前安裝版本無法執行這項檢查",
        description: "這個版本沒有任何檢查能處理這個目標。報告仍會列出這個涵蓋缺口，你已保存的專案與報告也不會變更。方便時更新程式，再重新檢查。",
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
      idle: "可以開始設定進階本機掃描",
      install: "正在準備進階本機掃描工具",
      prerequisite: "正在檢查這台 Windows 電腦的進階本機掃描需求",
      download: "正在下載進階本機掃描工具",
      recovery: "正在安全復原進階本機掃描工作區",
      init: "正在建立進階本機掃描工作區",
      start: "正在啟動進階本機掃描工具",
      verify: "正在對進階工具做最後確認",
      completed: "進階本機掃描工具準備好了",
      failed: "進階本機掃描工具設定需要處理",
      cancelled: "進階本機掃描工具設定已停止；下載進度已保留",
    },
    actions: {
      install_wsl: {
        title: "進階本機掃描工具設定未能完成",
        description: "進階工具自動設定未能完成。只嘗試一次 TCP 連線的 localhost 快速檢查與已保存的結果仍可使用；請再試一次自動設定。",
      },
      enable_wsl_optional_features: {
        title: "進階本機掃描工具設定未能完成",
        description: "進階工具自動設定未能完成。只嘗試一次 TCP 連線的 localhost 快速檢查與已保存的結果仍可使用；請再試一次自動設定。",
      },
      update_wsl: {
        title: "進階本機掃描工具設定未能完成",
        description: "進階工具自動設定未能完成。只嘗試一次 TCP 連線的 localhost 快速檢查與已保存的結果仍可使用；請再試一次自動設定。",
      },
      restart_windows: {
        title: "進階本機掃描工具設定正在等待 Windows 重新啟動",
        description: "Windows 必須重新啟動才能完成進階工具變更。Windows 重新啟動後，再開啟 ai-security-scanner，自動設定就會繼續；localhost 快速檢查與已保存的結果仍可使用。",
      },
      retry_wsl_check: {
        title: "進階本機掃描工具設定未能完成",
        description: "進階工具自動檢查未能完成。只嘗試一次 TCP 連線的 localhost 快速檢查與已保存的結果仍可使用；請再試一次自動設定。",
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
    setupNonRetryable,
  } = presentation;
  const nextAction = status?.nextAction ? text.actions[status.nextAction] : undefined;
  const technicalDetail = setupFailed ? "local_scan_tool_unavailable" : undefined;
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

  const title = scannerIssue?.title ?? (setupNonRetryable
    ? text.nonRetryableTitle
    : setupFailed
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
  const description = scannerIssue?.description ?? (setupNonRetryable
    ? text.nonRetryableDescription
    : setupFailed && nextAction
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
      className={`runtime-assistant${setupFailed || setupNonRetryable ? " runtime-assistant--failed" : ""}`}
      aria-labelledby="runtime-assistant-title"
      aria-live="polite"
    >
      <header className="runtime-assistant__header">
        <span className="runtime-assistant__icon">
          <Icon name={setupFailed || setupNonRetryable ? "warning" : "settings"} size={23} />
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

      {!scannerIssue && !setupStarting && !setupNonRetryable && status && status.phase !== "idle" && (
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
        ) : setupNonRetryable || (!setupFailed && !setupCancelled && !setupIdleUnavailable) ? null : (
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
