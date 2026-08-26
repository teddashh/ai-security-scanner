import type { BilingualText } from "./i18n";
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
  naabu: { en: "Open network ports", zhTW: "對外開放的網路連接埠" },
  httpx: { en: "Reachable websites and services", zhTW: "可連線的網站與服務" },
  nuclei: { en: "Known website and service weaknesses", zhTW: "網站與服務的已知弱點" },
  greenbone: { en: "Network and system vulnerabilities", zhTW: "網路與系統弱點" },
  semgrep: { en: "Risky code patterns", zhTW: "程式碼中的危險寫法" },
  gitleaks: { en: "Secrets committed to code", zhTW: "寫進程式碼的機密資料" },
  trufflehog: { en: "Exposed credentials and secrets", zhTW: "外洩的憑證與機密資料" },
  checkov: { en: "Risky infrastructure settings", zhTW: "基礎設施設定風險" },
  kics: { en: "Infrastructure-code mistakes", zhTW: "基礎設施程式碼錯誤" },
  trivy: { en: "Vulnerable packages and image settings", zhTW: "有弱點的套件與映像設定" },
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
    en: "Open scan-tool setup, make sure the private engine is ready, then start a new scan.",
    zhTW: "開啟掃描工具設定，確認私有引擎已就緒，再開始新的掃描。",
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
  "provider_source_required",
  "provider_target_binding_mismatch",
]);

const toolSetupErrorCodes = new Set([
  "execution_failed",
  "runtime_cleanup_pending",
  "runtime_image_unavailable",
  "runtime_image_unpinned",
  "command_unavailable",
  "external_executable_unsupported",
]);

export const engineOutcomeFor = (engine: Pick<EngineRun, "engineId">): BilingualText =>
  engineOutcomeCopy[engine.engineId as CatalogEngineId] ?? fallbackOutcome;

export const engineNextStepFor = (engine: EngineRun): BilingualText => {
  if (engine.phase === "interrupted_restart" || engine.errorCode === "desktop_process_restarted") {
    return nextStepCopy.interrupted;
  }
  if (engine.errorCode === "provider_rate_limited") return nextStepCopy.providerBusy;
  if (targetSetupErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.targetSetup;

  switch (engine.status) {
    case "pending":
      return nextStepCopy.waiting;
    case "running":
      return nextStepCopy.running;
    case "paused":
      return nextStepCopy.paused;
    case "completed":
      return engine.findingCount > 0
        ? nextStepCopy.completedWithFindings
        : nextStepCopy.completedClear;
    case "partial":
      return nextStepCopy.partial;
    case "not_executed":
      return toolSetupErrorCodes.has(engine.errorCode ?? "")
        ? nextStepCopy.toolSetup
        : nextStepCopy.targetSetup;
    case "cancelled":
      return nextStepCopy.cancelled;
    case "failed":
      return toolSetupErrorCodes.has(engine.errorCode ?? "")
        ? nextStepCopy.toolSetup
        : nextStepCopy.retry;
  }
};
