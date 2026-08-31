import type { BilingualText } from "./i18n";
import { isExplicitPreScannerInfrastructureFailure } from "./scanDiagnostics";
import { localhostTcpBeginnerSummary } from "./localhostTcpPresentation";
import type { EngineRun } from "./types";

export const catalogEngineIds = [
  "cloudquery",
  "steampipe",
  "prowler",
  "scoutsuite",
  "cloudsplaining",
  "scubagear",
  "maester",
  "naabu",
  "httpx",
  "nuclei",
  "greenbone",
  "semgrep",
  "gitleaks",
  "trufflehog",
  "checkov",
  "kics",
  "trivy",
  "grype",
  "syft",
  "kubescape",
  "kube-bench",
] as const;

export type CatalogEngineId = typeof catalogEngineIds[number];

/**
 * User-facing outcomes intentionally describe what somebody learns, not which
 * implementation produced it. Scanner identities stay in technical details.
 */
export const engineOutcomeCopy = {
  cloudquery: { en: "Cloud assets and services", zhTW: "雲端資產與服務" },
  steampipe: { en: "Cloud inventory and exposure", zhTW: "雲端盤點與暴露狀況" },
  prowler: { en: "Cloud account security settings", zhTW: "雲端帳號安全設定" },
  scoutsuite: { en: "Cloud configuration risks", zhTW: "雲端設定風險" },
  cloudsplaining: { en: "Excessive cloud permissions", zhTW: "過大的雲端權限" },
  scubagear: { en: "Microsoft 365 security settings", zhTW: "Microsoft 365 安全設定" },
  maester: { en: "Microsoft 365 identity protection", zhTW: "Microsoft 365 身分保護" },
  naabu: { en: "Open network ports", zhTW: "開放的網路連接埠" },
  httpx: { en: "Reachable websites and services", zhTW: "可連線的網站與服務" },
  nuclei: { en: "Known website and service weaknesses", zhTW: "網站與服務的已知弱點" },
  greenbone: { en: "Network and system vulnerabilities", zhTW: "網路與系統弱點" },
  semgrep: { en: "Risky code patterns", zhTW: "程式碼中的危險寫法" },
  gitleaks: { en: "Exposed secrets in code", zhTW: "程式碼中暴露的秘密" },
  trufflehog: { en: "Exposed credentials and secrets", zhTW: "外洩的憑證與機密資料" },
  checkov: { en: "Risky infrastructure settings", zhTW: "基礎設施設定風險" },
  kics: { en: "Infrastructure-code mistakes", zhTW: "基礎設施程式碼錯誤" },
  trivy: { en: "Known package vulnerabilities", zhTW: "套件中的已知弱點" },
  grype: { en: "Known software vulnerabilities", zhTW: "軟體中的已知弱點" },
  syft: { en: "Software ingredients", zhTW: "軟體包含的元件" },
  kubescape: { en: "Kubernetes workload risks", zhTW: "Kubernetes 工作負載風險" },
  "kube-bench": { en: "Kubernetes hardening settings", zhTW: "Kubernetes 強化設定" },
} as const satisfies Record<CatalogEngineId, BilingualText>;

const fallbackOutcome: BilingualText = {
  en: "Security check result",
  zhTW: "安全檢查結果",
};

const nextStepCopy = {
  waiting: {
    en: "No action is needed yet. This check is waiting for its turn.",
    zhTW: "目前不需要處理；這項檢查正在等待執行。",
  },
  running: {
    en: "No action is needed while this check is running.",
    zhTW: "這項檢查執行期間不需要操作。",
  },
  paused: {
    en: "Continue this scan when you are ready.",
    zhTW: "準備好後，繼續這次掃描即可。",
  },
  completedWithFindings: {
    en: "Review the problems found and start with the highest priority.",
    zhTW: "查看找到的問題，先處理優先順序最高的項目。",
  },
  completedClear: {
    en: "No action is needed here. Keep reviewing the other checks.",
    zhTW: "這一項目前不需要處理；請繼續查看其他檢查。",
  },
  partial: {
    en: "Review the results already saved, then continue this scan to finish the check.",
    zhTW: "先查看已保存的結果，再繼續掃描以完成這項檢查。",
  },
  boundedRetriesComplete: {
    en: "Review the saved results and what was not tested. If you want to try the unfinished items again, start a new scan.",
    zhTW: "查看已保存的結果與未測試項目；如果想再次嘗試未完成項目，請開始新的掃描。",
  },
  cancelledWithResults: {
    en: "Review the results saved before you stopped the scan. Start a new scan whenever you want to check the remaining items.",
    zhTW: "查看停止掃描前已保存的結果；想檢查剩餘項目時，再開始新的掃描。",
  },
  interrupted: {
    en: "Continue the original scan to pick up where the app stopped.",
    zhTW: "繼續原本的掃描，就能從程式停止的位置接著執行。",
  },
  providerBusy: {
    en: "Wait a few minutes, then continue this scan.",
    zhTW: "請稍等幾分鐘，再繼續這次掃描。",
  },
  targetSetup: {
    en: "Return to scan setup, choose the intended target, and confirm it once.",
    zhTW: "回到掃描設定，選擇正確目標並確認一次。",
  },
  toolSetup: {
    en: "Try this check again. The app will prepare a fresh private scan environment automatically.",
    zhTW: "請再試一次；程式會自動準備新的專用掃描環境。",
  },
  executionStoppedWithResults: {
    en: "Review the results already saved, download the diagnostic log, then retry this check.",
    zhTW: "先查看已保存的結果並下載診斷紀錄，再重試這項檢查。",
  },
  executionStopped: {
    en: "This check began but did not finish. Download the diagnostic log, then retry it.",
    zhTW: "這項檢查已開始但沒有完成；請下載診斷紀錄後再重試。",
  },
  executionUnknown: {
    en: "This check stopped without enough detail to blame setup. Download the diagnostic log, then retry it.",
    zhTW: "目前沒有足夠資訊判定是設定問題；請下載診斷紀錄後重試這項檢查。",
  },
  cleanupPending: {
    en: "Review the saved results and cleanup status, then retry after cleanup finishes.",
    zhTW: "請查看已保存的結果與清理狀態，待清理完成後再重試。",
  },
  providerSetup: {
    en: "Return to cloud setup and reconnect or review the selected account.",
    zhTW: "請回到雲端設定，重新連接或檢查所選帳號。",
  },
  gatewayPreparation: {
    en: "The private scan connection stopped before this check began. Try the check again and the app will rebuild the connection automatically.",
    zhTW: "專用掃描連線在這項檢查開始前就停止了。請再試一次，程式會自動重建連線。",
  },
  unavailableInRelease: {
    en: "These checks are not available in this version. Review completed results and update the app before trying again.",
    zhTW: "這些檢查在目前版本無法使用；請先查看已完成的結果，更新程式後再試。",
  },
  releaseIncompatible: {
    en: "Start a new scan to run this check with the installed release. The saved scan stays unchanged.",
    zhTW: "請開始新的掃描，以目前安裝的版本執行這項檢查；已保存的掃描不會變更。",
  },
  savedPlanUnavailable: {
    en: "Start a new scan for this check. Its older data was preserved, and no target was contacted.",
    zhTW: "請為這項檢查開始新的掃描。較舊的資料已保留，而且這次沒有連線到任何目標。",
  },
  cleanupIdentityUnavailable: {
    en: "This check ended safely, and its older data and results were kept. Start a new scan when you want fresh results; nothing else is required.",
    zhTW: "這項檢查已安全結束，較舊的資料與結果都已保留。需要新結果時請開始新的掃描；不需要做其他處理。",
  },
  mixedSkippedSetup: {
    en: "Finish the target or cloud step shown, then try the unfinished checks again. The app prepares its scan tools automatically.",
    zhTW: "請完成畫面上的目標或雲端步驟，再重試未完成的檢查；程式會自動準備掃描工具。",
  },
  skippedUnknown: {
    en: "Open the technical records for the skipped checks, finish the indicated setup, then start a new scan.",
    zhTW: "請展開未執行檢查的技術紀錄，完成其中指出的設定，再開始新的掃描。",
  },
  retry: {
    en: "Try this check again. If it stops again, download the diagnostic log for support.",
    zhTW: "請再試一次；若再次停止，請下載診斷紀錄以便排查。",
  },
  cancelled: {
    en: "Start a new scan when you want to run this check again.",
    zhTW: "想再次執行這項檢查時，開始新的掃描即可。",
  },
} as const satisfies Record<string, BilingualText>;

const targetSetupErrorCodes = new Set([
  "no_compatible_authorized_assets",
  "no_effective_scope_grants",
  "no_ownership_confirmed_targets",
  "no_compatible_authorized_targets",
]);

const providerSetupErrorCodes = new Set([
  "provider_connection_required",
  "provider_capability_required",
  "provider_review_required",
  "provider_source_required",
  "provider_capability_unavailable",
  "provider_source_ambiguous",
  "provider_authorization_binding_mismatch",
  "provider_target_binding_mismatch",
  "provider_preflight_unavailable",
]);

const toolSetupErrorCodes = new Set([
  "manifest_unavailable",
  "adapter_unavailable",
  "adapter_version_mismatch",
  "runtime_image_unavailable",
  "runtime_image_unpinned",
  "command_unavailable",
  "external_executable_unsupported",
]);

const releaseUnavailableErrorCodes = new Set([
  "engine_release_unavailable",
  "engine_deprecated",
  "research_only",
  "license_review",
]);

export const engineOutcomeFor = (engine: EngineRun): BilingualText =>
  localhostTcpBeginnerSummary(engine)?.title
  ?? engineOutcomeCopy[engine.engineId as CatalogEngineId]
  ?? fallbackOutcome;

export const skippedChecksNextStepFor = (reasonCodes: readonly string[]): BilingualText => {
  const hasTargetIssue = reasonCodes.some((code) => targetSetupErrorCodes.has(code));
  const hasProviderIssue = reasonCodes.some((code) => providerSetupErrorCodes.has(code));
  const hasToolIssue = reasonCodes.some((code) => toolSetupErrorCodes.has(code));
  const hasReleaseIssue = reasonCodes.some((code) => releaseUnavailableErrorCodes.has(code));
  const knownCount = Number(hasTargetIssue) + Number(hasProviderIssue) + Number(hasToolIssue) + Number(hasReleaseIssue);

  if (knownCount > 1) return nextStepCopy.mixedSkippedSetup;
  if (hasTargetIssue) return nextStepCopy.targetSetup;
  if (hasProviderIssue) return nextStepCopy.providerSetup;
  if (hasToolIssue) return nextStepCopy.toolSetup;
  if (hasReleaseIssue) return nextStepCopy.unavailableInRelease;
  return nextStepCopy.skippedUnknown;
};

export const engineNextStepFor = (engine: EngineRun): BilingualText => {
  const localhostSummary = localhostTcpBeginnerSummary(engine);
  if (localhostSummary) return localhostSummary.nextStep;
  if (engine.status === "completed") {
    return engine.findingCount > 0
      ? nextStepCopy.completedWithFindings
      : nextStepCopy.completedClear;
  }
  if (engine.phase === "interrupted_restart" || engine.errorCode === "desktop_process_restarted") {
    return nextStepCopy.interrupted;
  }
  if (engine.failureKind === "gateway_preparation_failed") return nextStepCopy.gatewayPreparation;
  if (engine.errorCode === "provider_rate_limited") return nextStepCopy.providerBusy;
  if (engine.errorCode === "resume_release_incompatible") return nextStepCopy.releaseIncompatible;
  if (engine.errorCode === "resume_work_plan_invalid") return nextStepCopy.savedPlanUnavailable;
  if (engine.errorCode === "runtime_cleanup_identity_unavailable") {
    return nextStepCopy.cleanupIdentityUnavailable;
  }
  if (engine.errorCode === "coverage_incomplete_after_bounded_retries") {
    return nextStepCopy.boundedRetriesComplete;
  }
  if (engine.errorCode === "cancelled_after_partial_results") {
    return nextStepCopy.cancelledWithResults;
  }
  if (engine.status === "partial") return nextStepCopy.partial;
  if (targetSetupErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.targetSetup;
  if (providerSetupErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.providerSetup;

  switch (engine.status) {
    case "pending":
      return nextStepCopy.waiting;
    case "running":
      return nextStepCopy.running;
    case "paused":
      return nextStepCopy.paused;
    case "not_executed":
      return skippedChecksNextStepFor(engine.errorCode ? [engine.errorCode] : []);
    case "cancelled":
      return nextStepCopy.cancelled;
    case "failed": {
      if (engine.errorCode === "runtime_cleanup_pending") return nextStepCopy.cleanupPending;
      if (engine.errorCode === "execution_failed") {
        if (isExplicitPreScannerInfrastructureFailure(engine)) return nextStepCopy.toolSetup;
        if (engine.rawArtifactCount > 0 || engine.findingCount > 0 || (engine.checkpoint?.artifactCount ?? 0) > 0) {
          return nextStepCopy.executionStoppedWithResults;
        }
        if (engine.checkpoint?.scopeBound || engine.runtimeProvider || engine.exitCode !== undefined) {
          return nextStepCopy.executionStopped;
        }
        return nextStepCopy.executionUnknown;
      }
      if (toolSetupErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.toolSetup;
      if (releaseUnavailableErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.unavailableInRelease;
      return nextStepCopy.retry;
    }
  }
};

const recoveryCopy = {
  restart_check: {
    en: "Retry this check from the beginning",
    zhTW: "從頭重試這項檢查",
  },
  continue_saved_results: {
    en: "Continue from saved results",
    zhTW: "從已保存的結果繼續",
  },
  finish_cleanup: {
    en: "Finish cleanup, then retry",
    zhTW: "完成清理後再重試",
  },
} as const satisfies Record<Exclude<NonNullable<EngineRun["recoveryAction"]>, "none">, BilingualText>;

export const engineRecoveryLabelFor = (engine: EngineRun): BilingualText | undefined => {
  const action = engine.recoveryAction ?? (engine.resumable ? "continue_saved_results" : "none");
  return action === "none" ? undefined : recoveryCopy[action];
};
