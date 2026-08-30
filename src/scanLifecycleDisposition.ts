import type { BilingualText } from "./i18n";
import {
  isExactBuiltInLocalhostQuickScanRun,
  LOCALHOST_QUICK_SCAN_TIMEOUT_MS,
} from "./localhostQuickScan";
import type {
  CaseWorkspace,
  EngineRunStatus,
  LocalhostTcpOutcome,
  RunStatus,
  ScanRun,
} from "./types";

export type LifecycleResultStatus =
  | "completed"
  | "partial"
  | "failed"
  | "not_executed";

export type ScanLifecycleDisposition =
  | {
      action: "cancel";
      outcome: "requested";
      runId: string;
      targetContactLimitMs?: number;
    }
  | { action: "cancel"; outcome: "cancelled"; runId: string }
  | {
      action: "cancel";
      outcome: "result_already_final";
      runId: string;
      resultStatus: LifecycleResultStatus;
      localhostOutcome?: LocalhostTcpOutcome;
    }
  | { action: "cancel"; outcome: "unconfirmed"; runId: string }
  | { action: "resume"; outcome: "queued"; runId: string }
  | {
      action: "resume";
      outcome: "result_already_final";
      runId: string;
      resultStatus: LifecycleResultStatus;
      localhostOutcome?: LocalhostTcpOutcome;
    }
  | { action: "resume"; outcome: "unconfirmed"; runId: string };

const activeRunStatuses = new Set<RunStatus>(["queued", "running", "paused"]);
const activeEngineStatuses = new Set<EngineRunStatus>(["pending", "running", "paused"]);
const terminalEngineStatuses = new Set<EngineRunStatus>([
  "completed",
  "partial",
  "failed",
  "not_executed",
  "cancelled",
]);

const terminalResultStatus = (run: ScanRun): LifecycleResultStatus | undefined => {
  if (run.status === "completed" || run.status === "partial" || run.status === "failed") {
    return run.status;
  }
  if (run.status === "no_checks_completed") return "not_executed";
  if (run.engineRuns.length === 0 || !run.engineRuns.every((engine) => terminalEngineStatuses.has(engine.status))) {
    return undefined;
  }

  const statuses = new Set(run.engineRuns.map((engine) => engine.status));
  if (statuses.size === 1) {
    const status = run.engineRuns[0]!.status;
    if (status === "completed" || status === "partial" || status === "failed"
      || status === "not_executed") return status;
    return undefined;
  }
  if (statuses.has("failed")) return "failed";
  if (statuses.has("partial") || statuses.has("completed")) return "partial";
  if (statuses.has("not_executed")) return "not_executed";
  return undefined;
};

const exactRun = (workspace: CaseWorkspace | undefined, runId: string): ScanRun | undefined =>
  workspace?.runs.find((run) => run.id === runId);

const savedLocalhostOutcome = (run: ScanRun): LocalhostTcpOutcome | undefined =>
  isExactBuiltInLocalhostQuickScanRun(run)
    ? run.engineRuns[0]?.localhostTcpObservation?.outcome
    : undefined;

export const deriveCancelLifecycleDisposition = (
  workspace: CaseWorkspace | undefined,
  runId: string,
): ScanLifecycleDisposition => {
  const run = exactRun(workspace, runId);
  if (!run) return { action: "cancel", outcome: "unconfirmed", runId };

  const resultStatus = terminalResultStatus(run);
  if (resultStatus) {
    return {
      action: "cancel",
      outcome: "result_already_final",
      runId,
      resultStatus,
      localhostOutcome: savedLocalhostOutcome(run),
    };
  }

  const cancelledIsTerminal = (
    run.engineRuns.length === 0 && run.status === "cancelled"
  ) || (
    run.engineRuns.length > 0 && run.engineRuns.every((engine) => engine.status === "cancelled")
  );
  if (cancelledIsTerminal) {
    // The fixed localhost contract never commits an observation under a
    // Cancelled terminal state. Preserve contradictory data for Technical
    // details and refresh authoritative truth instead of inventing either a
    // cancellation-without-observation or a completed result.
    if (isExactBuiltInLocalhostQuickScanRun(run) && savedLocalhostOutcome(run)) {
      return { action: "cancel", outcome: "unconfirmed", runId };
    }
    return { action: "cancel", outcome: "cancelled", runId };
  }

  const durableRequestIsActive = activeRunStatuses.has(run.status)
    && run.engineRuns.some((engine) =>
      activeEngineStatuses.has(engine.status) && engine.phase === "cancel_requested"
    );
  if (durableRequestIsActive) {
    return {
      action: "cancel",
      outcome: "requested",
      runId,
      targetContactLimitMs: isExactBuiltInLocalhostQuickScanRun(run)
        ? LOCALHOST_QUICK_SCAN_TIMEOUT_MS
        : undefined,
    };
  }

  return { action: "cancel", outcome: "unconfirmed", runId };
};

export const deriveResumeLifecycleDisposition = (
  workspace: CaseWorkspace | undefined,
  runId: string,
): ScanLifecycleDisposition => {
  const run = exactRun(workspace, runId);
  if (!run) return { action: "resume", outcome: "unconfirmed", runId };

  const resultStatus = terminalResultStatus(run);
  if (resultStatus) {
    return {
      action: "resume",
      outcome: "result_already_final",
      runId,
      resultStatus,
      localhostOutcome: savedLocalhostOutcome(run),
    };
  }
  if (
    (run.engineRuns.length === 0 && run.status === "cancelled")
    || (run.engineRuns.length > 0 && run.engineRuns.every((engine) => engine.status === "cancelled"))
  ) {
    // A stale active aggregate must not turn terminal cancellation into a
    // queued restart. Cancellation has no result-won status to resume.
    return { action: "resume", outcome: "unconfirmed", runId };
  }
  if (run.status === "queued" || run.status === "running") {
    return { action: "resume", outcome: "queued", runId };
  }
  return { action: "resume", outcome: "unconfirmed", runId };
};

export const deriveScanLifecycleDisposition = (
  action: ScanLifecycleDisposition["action"],
  workspace: CaseWorkspace | undefined,
  runId: string,
): ScanLifecycleDisposition => action === "cancel"
  ? deriveCancelLifecycleDisposition(workspace, runId)
  : deriveResumeLifecycleDisposition(workspace, runId);

export interface ScanLifecycleToastPresentation {
  tone: "info" | "success" | "warning";
  title: BilingualText;
  detail: BilingualText;
}

const finalResultDetail = (
  action: "cancel" | "resume",
  status: LifecycleResultStatus,
  localhostOutcome?: LocalhostTcpOutcome,
): BilingualText => {
  const localhostResult = localhostOutcome === "reachable"
    ? { en: "recorded that the TCP connection was accepted", zhTW: "已記錄 TCP 連線獲得接受" }
    : localhostOutcome === "closed"
      ? { en: "recorded that the TCP connection was refused", zhTW: "已記錄 TCP 連線遭到拒絕" }
      : localhostOutcome === "timed_out"
        ? { en: "recorded that the TCP connection attempt timed out", zhTW: "已記錄 TCP 連線嘗試逾時" }
        : undefined;
  const result = {
    completed: { en: "completed with a saved result", zhTW: "已完成並保存結果" },
    partial: { en: "ended with partial results", zhTW: "已結束並保存部分結果" },
    failed: { en: "ended with a saved failure", zhTW: "已結束並保存失敗狀態" },
    not_executed: { en: "ended without running this check", zhTW: "已結束且沒有執行這項檢查" },
  } as const;
  const outcome = localhostResult ?? result[status];
  return action === "cancel"
    ? {
        en: `The check ${outcome.en} before the stop request could take effect. That saved result was kept.`,
        zhTW: `這項檢查在停止要求生效前${outcome.zhTW}；該結果已完整保留。`,
      }
    : {
        en: `The check ${outcome.en} before the continue request could take effect. That saved result was kept; nothing was restarted.`,
        zhTW: `這項檢查在繼續要求生效前${outcome.zhTW}；該結果已完整保留，也沒有重新執行。`,
      };
};

export const scanLifecycleToastPresentation = (
  disposition: ScanLifecycleDisposition,
): ScanLifecycleToastPresentation => {
  if (disposition.outcome === "result_already_final") {
    return {
      tone: "info",
      title: { en: "This check had already finished", zhTW: "這項檢查先前已結束" },
      detail: finalResultDetail(
        disposition.action,
        disposition.resultStatus,
        disposition.localhostOutcome,
      ),
    };
  }
  if (disposition.action === "cancel" && disposition.outcome === "requested") {
    return disposition.targetContactLimitMs === LOCALHOST_QUICK_SCAN_TIMEOUT_MS
      ? {
          tone: "info",
          title: { en: "Stopping this check", zhTW: "正在停止這項檢查" },
          detail: {
            en: "Stopping this check. If a connection attempt already started, it will end within its 3-second limit.",
            zhTW: "正在停止這項檢查。如果連線嘗試已經開始，它會在 3 秒的時間上限內結束。",
          },
        }
      : {
          tone: "info",
          title: { en: "Stop requested", zhTW: "已要求停止" },
          detail: {
            en: "The saved scan state shows that active work is stopping. Progress will show Cancelled only after it stops.",
            zhTW: "已保存的掃描狀態顯示作用中的工作正在停止。工作停止後，進度才會顯示「已取消」。",
          },
        };
  }
  if (disposition.action === "cancel" && disposition.outcome === "cancelled") {
    return {
      tone: "success",
      title: { en: "This check is cancelled", zhTW: "這項檢查已取消" },
      detail: {
        en: "The check stopped. Any results saved before it stopped remain available.",
        zhTW: "這項檢查已停止；停止前保存的任何結果仍可查看。",
      },
    };
  }
  if (disposition.action === "resume" && disposition.outcome === "queued") {
    return {
      tone: "success",
      title: { en: "Continue request accepted", zhTW: "已接受繼續要求" },
      detail: {
        en: "Scan progress now shows whether this check is queued or running.",
        zhTW: "掃描進度現在會顯示這項檢查正在等待或執行中。",
      },
    };
  }
  return {
    tone: "warning",
    title: { en: "Checking the latest scan state", zhTW: "正在確認最新掃描狀態" },
    detail: {
      en: "The returned state did not confirm that this request took effect or that the check finished. Scan progress is refreshing now.",
      zhTW: "傳回的狀態尚未確認這項要求已生效，也沒有確認檢查已結束；掃描進度正在重新整理。",
    },
  };
};
