import type { BilingualText } from "./i18n";
import {
  BUILT_IN_LOCALHOST_QUICK_SCAN_ENGINE_ID,
  isExactBuiltInLocalhostQuickScanEngine,
} from "./localhostQuickScan";
import type { EngineRun, LocalhostTcpOutcome } from "./types";

export type LocalhostTcpDisplayedOutcome =
  | LocalhostTcpOutcome
  | "missing"
  | "inconsistent"
  | "in_progress"
  | "cancelling"
  | "cancelled"
  | "failed";

export interface LocalhostTcpBeginnerSummary {
  port: number;
  timeoutMs: number;
  payloadBytes: number;
  outcome: LocalhostTcpDisplayedOutcome;
  title: BilingualText;
  description: BilingualText;
  exclusions: BilingualText;
  nextStep: BilingualText;
  outcomeLabel: BilingualText;
}

const exclusions: BilingualText = {
  en: "Not checked: vulnerabilities, protocol behavior, website or API content, other ports, or other hosts.",
  zhTW: "未檢查：弱點、協定行為、網站或 API 內容、其他連接埠，或其他主機。",
};

const contractDescription = (
  port: number,
  timeoutMs: number,
  payloadBytes: number,
  outcome: LocalhostTcpDisplayedOutcome,
): BilingualText => {
  if (["reachable", "closed", "timed_out"].includes(outcome)) {
    return {
      en: `This saved observation came from one TCP connection attempt to 127.0.0.1:${port}, with a maximum wait of ${timeoutMs} ms and ${payloadBytes} application-data bytes sent.`,
      zhTW: `這筆已保存的觀察結果來自對 127.0.0.1:${port} 的一次 TCP 連線嘗試，最長等待 ${timeoutMs} 毫秒，並傳送 ${payloadBytes} 個應用層資料位元組。`,
    };
  }
  return {
    en: `The saved task allowed only one TCP connection attempt to 127.0.0.1:${port}, a maximum wait of ${timeoutMs} ms, and ${payloadBytes} application-data bytes. No coherent TCP observation was saved.`,
    zhTW: `已保存的工作範圍只允許對 127.0.0.1:${port} 進行一次 TCP 連線嘗試，最長等待 ${timeoutMs} 毫秒，並傳送 ${payloadBytes} 個應用層資料位元組；目前沒有保存一致且可採用的 TCP 觀察結果。`,
  };
};

const summaryForOutcome = (
  outcome: LocalhostTcpDisplayedOutcome,
  port: number,
): Pick<LocalhostTcpBeginnerSummary, "title" | "outcomeLabel" | "nextStep"> => {
  switch (outcome) {
    case "reachable":
      return {
        title: {
          en: `Port ${port} accepted a TCP connection`,
          zhTW: `連接埠 ${port} 接受了 TCP 連線`,
        },
        outcomeLabel: { en: "Connection accepted", zhTW: "已接受連線" },
        nextStep: {
          en: `If this is the service you expected, choose a website/API or deeper network scan to check more. If it is unexpected, identify the app listening on port ${port}.`,
          zhTW: `如果這是預期的服務，可選擇網站／API 或更深入的網路掃描來檢查更多項目；若不是，請確認是哪個程式正在監聽連接埠 ${port}。`,
        },
      };
    case "closed":
      return {
        title: {
          en: `Port ${port} refused the TCP connection`,
          zhTW: `連接埠 ${port} 拒絕了 TCP 連線`,
        },
        outcomeLabel: { en: "Connection refused", zhTW: "連線遭拒" },
        nextStep: {
          en: `Start the local service you meant to check, or correct the port, then try port ${port} again.`,
          zhTW: `請啟動原本要檢查的本機服務，或修正連接埠，再重新檢查連接埠 ${port}。`,
        },
      };
    case "timed_out":
      return {
        title: {
          en: `The connection attempt to port ${port} timed out`,
          zhTW: `連接埠 ${port} 的連線嘗試逾時`,
        },
        outcomeLabel: { en: "Timed out", zhTW: "連線逾時" },
        nextStep: {
          en: `Confirm that the intended local service is running and listening on port ${port}, then try again. A timeout does not show that the port is closed.`,
          zhTW: `請確認預期的本機服務正在執行並監聽連接埠 ${port}，再重試。逾時不代表連接埠已關閉。`,
        },
      };
    case "in_progress":
      return {
        title: {
          en: `The port ${port} check has no observation yet`,
          zhTW: `連接埠 ${port} 的檢查尚無觀察結果`,
        },
        outcomeLabel: { en: "No observation yet", zhTW: "尚無觀察結果" },
        nextStep: {
          en: "No action is needed while the app continues or waits to continue this task.",
          zhTW: "程式繼續處理或等待繼續這項工作時，不需要操作。",
        },
      };
    case "cancelling":
      return {
        title: {
          en: `Stopping the port ${port} connection check`,
          zhTW: `正在停止連接埠 ${port} 的連線檢查`,
        },
        outcomeLabel: { en: "Stopping; no observation yet", zhTW: "正在停止；尚無觀察結果" },
        nextStep: {
          en: "The current connection attempt has a three-second maximum. It will show Cancelled only after the connection has stopped.",
          zhTW: "目前的連線嘗試最長三秒。只有在連線停止後，才會顯示「已取消」。",
        },
      };
    case "cancelled":
      return {
        title: {
          en: `The port ${port} check was cancelled before an outcome was saved`,
          zhTW: `連接埠 ${port} 的檢查已取消，尚未保存結果`,
        },
        outcomeLabel: { en: "Cancelled; no observation", zhTW: "已取消；沒有觀察結果" },
        nextStep: {
          en: "Start this one check again when you want an observation.",
          zhTW: "需要觀察結果時，再開始這一項檢查即可。",
        },
      };
    case "failed":
      return {
        title: {
          en: `The port ${port} check stopped before recording an outcome`,
          zhTW: `連接埠 ${port} 的檢查在記錄結果前停止`,
        },
        outcomeLabel: { en: "Failed; no observation", zhTW: "失敗；沒有觀察結果" },
        nextStep: {
          en: "Open Scan progress for the saved failure, then try this one check again.",
          zhTW: "請到「掃描進度」查看已保存的失敗紀錄，再重試這一項檢查。",
        },
      };
    case "missing":
      return {
        title: {
          en: `The saved port ${port} check has no TCP observation`,
          zhTW: `已保存的連接埠 ${port} 檢查沒有 TCP 觀察結果`,
        },
        outcomeLabel: { en: "Observation not recorded", zhTW: "未記錄觀察結果" },
        nextStep: {
          en: "Run this one check again. Do not draw a reachability conclusion from this saved record.",
          zhTW: "請重新執行這一項檢查；不要從這筆已保存的紀錄推定連線狀態。",
        },
      };
    case "inconsistent":
      return {
        title: {
          en: `The saved port ${port} result is incomplete`,
          zhTW: `已保存的連接埠 ${port} 結果不完整`,
        },
        outcomeLabel: { en: "Inconsistent saved result", zhTW: "已保存的結果不一致" },
        nextStep: {
          en: "Run this one check again. Do not use the conflicting status and observation as a reachability result.",
          zhTW: "請重新執行這一項檢查；不要把互相衝突的狀態與觀察紀錄當成連線結果。",
        },
      };
  }
};

/**
 * Builds first-layer copy only for the exact built-in localhost task. Catalog
 * scanners deliberately return undefined and keep their existing presentation.
 */
export const localhostTcpBeginnerSummary = (
  engine: Pick<EngineRun, "engineId" | "taskKind" | "localhostTcpObservation" | "status" | "phase">,
): LocalhostTcpBeginnerSummary | undefined => {
  if (
    engine.engineId !== BUILT_IN_LOCALHOST_QUICK_SCAN_ENGINE_ID
    || engine.taskKind?.kind !== "built_in_localhost_tcp"
  ) return undefined;

  const observation = engine.localhostTcpObservation;
  const exactContract = isExactBuiltInLocalhostQuickScanEngine(engine);
  const active = ["pending", "running", "paused"].includes(engine.status);
  const cancellationRequested = exactContract && active && engine.phase === "cancel_requested";
  const observationTimestampIsValid = Boolean(
    observation && Number.isFinite(Date.parse(observation.observedAt)),
  );
  const coherentObservedOutcome = exactContract && observationTimestampIsValid && (
    engine.status === "completed" && ["reachable", "closed"].includes(observation?.outcome ?? "")
      || engine.status === "partial" && observation?.outcome === "timed_out"
  );
  const outcome: LocalhostTcpDisplayedOutcome = cancellationRequested
    ? "cancelling"
    : active
      ? "in_progress"
      : engine.status === "cancelled"
        ? "cancelled"
        : engine.status === "failed" || engine.status === "not_executed"
          ? "failed"
          : coherentObservedOutcome && observation
            ? observation.outcome
            : !observation
              ? "missing"
              : "inconsistent";
  const wording = summaryForOutcome(outcome, engine.taskKind.port);
  return {
    port: engine.taskKind.port,
    timeoutMs: engine.taskKind.timeoutMs,
    payloadBytes: engine.taskKind.payloadBytes,
    outcome,
    ...wording,
    description: contractDescription(
      engine.taskKind.port,
      engine.taskKind.timeoutMs,
      engine.taskKind.payloadBytes,
      outcome,
    ),
    exclusions,
  };
};
