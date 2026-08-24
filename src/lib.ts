import type {
  CasePhase,
  CloudPlatform,
  Confidence,
  CoverageState,
  DiffState,
  EngineRunStatus,
  FindingWorkflowState,
  RunStatus,
  Severity,
} from "./types";

export const cx = (...values: Array<string | false | null | undefined>): string =>
  values.filter(Boolean).join(" ");

export const formatDateTime = (value?: string): string => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-Hant-TW", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
};

export const formatDate = (value?: string): string => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-Hant-TW", {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(date);
};

export const coverageMeta: Record<
  CoverageState,
  { label: string; shortLabel: string; tone: string; description: string }
> = {
  discovered_authorized_scanned: {
    label: "已發現、已授權、已掃描",
    shortLabel: "已掃描",
    tone: "positive",
    description: "已確認資產與範圍，掃描工作完整執行。",
  },
  discovered_not_authorized: {
    label: "已發現，但未授權",
    shortLabel: "待授權",
    tone: "warning",
    description: "知道資產存在，但尚未取得所需掃描範圍。",
  },
  authorized_incomplete: {
    label: "已授權，但掃描未完成",
    shortLabel: "未完成",
    tone: "danger",
    description: "已有合法範圍，但掃描失敗或只完成一部分。",
  },
  source_connected_none: {
    label: "已接來源，沒有發現",
    shortLabel: "未發現",
    tone: "neutral",
    description: "資料來源可用，這次沒有從該來源發現資產。",
  },
  source_unavailable_unknown: {
    label: "沒有資料來源，狀況未知",
    shortLabel: "未知",
    tone: "unknown",
    description: "沒有視野；絕對不能解讀為安全或沒有資產。",
  },
};

export const engineStatusMeta: Record<
  EngineRunStatus,
  { label: string; tone: string }
> = {
  pending: { label: "等待中", tone: "neutral" },
  running: { label: "執行中", tone: "info" },
  paused: { label: "已暫停", tone: "warning" },
  completed: { label: "已完成", tone: "positive" },
  partial: { label: "部分完成", tone: "warning" },
  failed: { label: "失敗", tone: "danger" },
  not_executed: { label: "未執行", tone: "unknown" },
  cancelled: { label: "已取消", tone: "neutral" },
};

export const runStatusMeta: Record<RunStatus, { label: string; tone: string }> = {
  queued: { label: "等待中", tone: "neutral" },
  running: { label: "掃描中", tone: "info" },
  paused: { label: "已暫停", tone: "warning" },
  completed: { label: "已完成", tone: "positive" },
  partial: { label: "部分完成", tone: "warning" },
  failed: { label: "失敗", tone: "danger" },
  cancelled: { label: "已取消", tone: "neutral" },
};

export const severityMeta: Record<Severity, { label: string; tone: string }> = {
  critical: { label: "嚴重", tone: "critical" },
  high: { label: "高", tone: "danger" },
  medium: { label: "中", tone: "warning" },
  low: { label: "低", tone: "info" },
  info: { label: "待確認", tone: "neutral" },
};

export const confidenceMeta: Record<Confidence, string> = {
  high: "高信心",
  medium: "中等信心",
  low: "低信心",
};

export const workflowMeta: Record<FindingWorkflowState, string> = {
  unreviewed: "尚未檢視",
  expert_review_requested: "已請專家複核",
  confirmed: "已人工確認",
  unconfirmed: "尚未人工確認",
  assigned: "已交付負責人",
  false_positive: "確認為誤報",
  remediation_reported: "已回報修復",
  remediated_pending_verification: "已修復，等待複驗",
  verified_resolved: "複驗已解決",
};

export const diffMeta: Record<DiffState, { label: string; tone: string; description: string }> = {
  resolved: { label: "已消失", tone: "positive", description: "基準存在，本次已未再觀察到。" },
  persistent: { label: "仍然存在", tone: "danger", description: "基準與本次都觀察到相同問題。" },
  new: { label: "新出現", tone: "warning", description: "本次首次出現，或新範圍首次發現。" },
  unverifiable: {
    label: "無法驗證",
    tone: "unknown",
    description: "因權限、範圍或引擎狀態改變而無法比較。",
  },
};

export const phaseMeta: Record<CasePhase, { label: string; tone: string }> = {
  draft: { label: "草稿", tone: "neutral" },
  discovering: { label: "盤點中", tone: "info" },
  scope_review: { label: "範圍確認", tone: "warning" },
  ready: { label: "可開始掃描", tone: "positive" },
  scanning: { label: "掃描中", tone: "info" },
  needs_attention: { label: "需要處理", tone: "warning" },
  ready_for_handoff: { label: "可交接", tone: "positive" },
  verifying: { label: "複驗中", tone: "info" },
  archived: { label: "已封存", tone: "neutral" },
  complete: { label: "初檢完成", tone: "positive" },
  verification_due: { label: "等待複驗", tone: "warning" },
};

export const platformMeta: Record<CloudPlatform, { label: string; abbreviation: string }> = {
  aws: { label: "AWS", abbreviation: "AWS" },
  azure: { label: "Azure", abbreviation: "AZ" },
  gcp: { label: "Google Cloud", abbreviation: "GCP" },
  m365: { label: "Microsoft 365", abbreviation: "365" },
  external: { label: "外部攻擊面", abbreviation: "WEB" },
  code: { label: "程式碼與 IaC", abbreviation: "CODE" },
  container: { label: "容器與 SBOM", abbreviation: "IMG" },
  kubernetes: { label: "Kubernetes", abbreviation: "K8S" },
};

export const percentage = (part: number, total: number): number =>
  total <= 0 ? 0 : Math.round((part / total) * 100);
