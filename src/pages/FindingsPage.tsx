import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  confidenceMeta,
  severityMeta,
  workflowMeta,
} from "../lib";
import { useI18n } from "../i18n";
import type {
  CoverageRecord,
  Finding,
  FindingGroup,
  FindingGroupEvent,
  FindingWorkflowEvent,
  FindingWorkflowState,
  FindingWorkflowUpdateInput,
  ScanRun,
  Severity,
} from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

import "./page-technical-details.css";

interface FindingsPageProps {
  findings: Finding[];
  findingGroups: FindingGroup[];
  findingGroupEvents: FindingGroupEvent[];
  coverage: CoverageRecord[];
  runs: ScanRun[];
  focusedFindingId?: string;
  workflowEvents: FindingWorkflowEvent[];
  busy: boolean;
  onUpdateWorkflow: (input: Omit<FindingWorkflowUpdateInput, "caseId">) => Promise<boolean>;
  onGroupFindings: (input: { title: string; findingIds: string[]; rationale: string }) => Promise<boolean>;
  onUngroupFindings: (groupId: string) => Promise<void>;
  onOpenCoverage: () => void;
  onOpenProgress: () => void;
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
const workflowOrder = Object.keys(workflowMeta) as FindingWorkflowState[];
const decisionStates = [
  "unreviewed",
  "expert_review_requested",
  "confirmed",
  "false_positive",
  "remediation_reported",
  "verified_resolved",
] as const;
const controlKey = (framework: string, version: string, controlId: string): string =>
  JSON.stringify([framework, version, controlId]);

const copy = {
  eyebrow: { en: "PROBLEMS FOUND", zhTW: "發現的問題" },
  title: {
    en: "Start with what deserves attention, without hiding the complete result",
    zhTW: "先看最值得處理的事，完整結果一項不少",
  },
  description: {
    en: "Every problem links back to its asset, scan run, evidence file, and scanner version. Framework references help navigation; they are not NIST or ISO compliance decisions.",
    zhTW: "每項問題都連回資產、掃描輪次、證據檔案與掃描器版本。控制項只是導航座標，不是 NIST／ISO 合規判定。",
  },
  emptyHeaderTitle: { en: "Problem list", zhTW: "問題清單" },
  emptyHeaderDescription: {
    en: "An empty list must be read together with coverage and scanner status.",
    zhTW: "空清單也必須連同涵蓋與引擎狀態一起解讀。",
  },
  emptyNoRunTitle: { en: "No scan results yet", zhTW: "尚未產生掃描結果" },
  emptyIncompleteTitle: {
    en: "This run produced no saved problems, but the scan did not finish",
    zhTW: "本輪沒有正式問題紀錄，但掃描未完整完成",
  },
  emptyUnknownTitle: {
    en: "No problems are shown, but some sources are still unknown",
    zhTW: "目前沒有問題，但仍有未知視野",
  },
  emptyCompletedTitle: {
    en: "No problems were observed in the work that completed",
    zhTW: "已完成的範圍內沒有觀察到問題",
  },
  emptyNoRunDescription: {
    en: "Review assets and coverage first, confirm each source and asset boundary, then start work from Scan progress.",
    zhTW: "先查看資產與涵蓋，確認來源與逐資產範圍，再從掃描進度啟動工作。",
  },
  emptyIncompleteDescription: {
    en: "Failed, partly completed, cancelled, or skipped jobs can leave unchecked areas. Review the final state and reason for every scanner.",
    zhTW: "失敗、部分完成、取消或未執行的工作都可能留下未檢查範圍；請查看每個掃描器的終態與原因。",
  },
  emptyUnknownDescription: {
    en: "{count} sources have no usable data. An empty list therefore does not mean there are no assets or that they are secure.",
    zhTW: "{count} 個來源沒有可用資料，因此不能把空清單解讀為沒有資產或安全。",
  },
  emptyCompletedDescription: {
    en: "{count} sources reported ‘connected, nothing found.’ This describes only the known scope of this run; it is not a security guarantee.",
    zhTW: "{count} 個來源回報「已連接但未發現」。這只描述本次已知範圍，不是安全保證。",
  },
  openCoverage: { en: "Review what was covered", zhTW: "查看涵蓋" },
  openProgress: { en: "Review scanner status", zhTW: "查看掃描器狀態" },
  summaryAria: { en: "Problem summary", zhTW: "問題摘要" },
  critical: { en: "Critical", zhTW: "嚴重" },
  criticalDetail: { en: "Ask the appropriate specialist to confirm these first", zhTW: "優先請對應專家確認" },
  high: { en: "High priority", zhTW: "高風險" },
  highDetail: { en: "Ordered by evidence and context, not a risk score", zhTW: "依證據與情境排列，不是風險分數" },
  needsReview: { en: "Needs human review", zhTW: "待人工確認" },
  needsReviewDetail: { en: "A scanner observation is not a confirmed fact", zhTW: "掃描器判定不等於已確認事實" },
  affectedAssets: { en: "Affected assets", zhTW: "受影響資產" },
  completeListCount: { en: "{count} problems in the complete list", zhTW: "完整清單共 {count} 項" },
  reversibleLinks: { en: "REVERSIBLE LINKS", zhTW: "可逆關聯" },
  groupsTitle: { en: "Put related problems into one handoff group", zhTW: "把相關問題放在同一個交接群組" },
  groupsDescription: {
    en: "A group changes presentation only. Every original problem, fingerprint, evidence record, and raw evidence file stays independent.",
    zhTW: "群組只改變呈現方式；每筆原始問題、內容指紋、證據與原始證據檔都保持獨立。",
  },
  items: { en: "{count} items", zhTW: "{count} 項" },
  createdBy: { en: "Created by {actor}", zhTW: "建立者：{actor}" },
  technicalGroupDetails: { en: "Technical group details", zhTW: "群組技術細節" },
  groupId: { en: "Group ID", zhTW: "群組 ID" },
  removeGroup: { en: "Remove the group only; keep every problem", zhTW: "只移除群組（保留全部問題）" },
  groupHistory: { en: "Permanent group history ({count})", zhTW: "不可變群組歷程（{count} 筆）" },
  groupHistoryDescription: {
    en: "Creating and removing groups only appends events. Removing a group never deletes the original problems, evidence, or earlier events.",
    zhTW: "建立與移除都只追加事件；移除群組不會刪除原始問題、證據或先前事件。",
  },
  groupCreated: { en: "Group created", zhTW: "建立群組" },
  groupRemoved: { en: "Group removed", zhTW: "移除群組" },
  performedBy: { en: "Performed by {actor}", zhTW: "執行者：{actor}" },
  findingId: { en: "Problem ID", zhTW: "問題 ID" },
  groupTitle: { en: "Group title", zhTW: "群組標題" },
  groupTitlePlaceholder: {
    en: "For example: Privileged identities that should be reviewed together",
    zhTW: "例如：需要一起檢視的高權限身分保護問題",
  },
  groupReason: { en: "Why these belong together", zhTW: "關聯理由" },
  groupReasonPlaceholder: {
    en: "Explain why one specialist should review them together. Do not write this as an audit conclusion.",
    zhTW: "說明為何應由同一位專家一起檢視；不要把它寫成稽核結論。",
  },
  chooseTwo: { en: "Choose at least two ungrouped problems", zhTW: "選擇至少兩項尚未分組的問題" },
  createGroup: { en: "Create reversible group", zhTW: "建立可逆群組" },
  doNow: { en: "START HERE", zhTW: "現在先處理" },
  priorityTitle: { en: "Priority summary", zhTW: "優先摘要" },
  priorityDescription: {
    en: "This order helps people triage work. It does not hide other problems or make changes to the environment.",
    zhTW: "優先順序方便人員分流；不會隱藏其他問題，也不會自動修改環境。",
  },
  reviewEvidence: { en: "Review evidence", zhTW: "查看證據" },
  boundaryTitle: { en: "This is not an audit conclusion or an executable fix", zhTW: "這不是稽核結論，也不是可執行修復" },
  boundaryBody: {
    en: "This page records observations, possible impact, human decisions, and the kind of specialist to consult. Authorized people evaluate and perform any environment change outside this product.",
    zhTW: "畫面只保存觀察、可能影響、人工決定與建議找哪類專家。任何環境變更都在產品之外由具權限的人員評估及執行。",
  },
  allProblems: { en: "ALL PROBLEMS", zhTW: "全部問題" },
  completeList: { en: "Complete problem list", zhTW: "完整問題清單" },
  searchAria: { en: "Search problems, evidence, or source details", zhTW: "搜尋問題、證據或來源細節" },
  searchPlaceholder: { en: "Search problem, asset, evidence, fingerprint…", zhTW: "搜尋問題、資產、證據、內容指紋…" },
  severityFilter: { en: "Severity", zhTW: "嚴重度" },
  allSeverities: { en: "All severities", zhTW: "所有嚴重度" },
  workflowFilter: { en: "Review status", zhTW: "處理狀態" },
  allWorkflows: { en: "All review statuses", zhTW: "所有處理狀態" },
  expertFilter: { en: "Specialist type", zhTW: "專家類型" },
  allExperts: { en: "All specialist types", zhTW: "所有專家類型" },
  controlFilter: { en: "Framework reference", zhTW: "相關控制項" },
  allControls: { en: "All framework references", zhTW: "所有控制項座標" },
  clearFilterCount: { en: "Clear {count} filters", zhTW: "清除 {count} 個篩選條件" },
  noMatches: { en: "No problems match these filters", zhTW: "沒有符合的問題" },
  noMatchesDescription: {
    en: "Clear the search text, review status, specialist type, or framework filter.",
    zhTW: "清除搜尋字詞、處理狀態、專家類型或控制項篩選。",
  },
  clearFilters: { en: "Clear filters", zhTW: "清除篩選" },
  rankAria: { en: "Handoff priority {rank}", zhTW: "交接優先順序第 {rank} 位" },
  rank: { en: "#{rank}", zhTW: "第 {rank}" },
  evidenceCount: { en: "{count} evidence records", zhTW: "{count} 份證據" },
  asset: { en: "Asset", zhTW: "資產" },
  reviewStatus: { en: "Review status", zhTW: "處理狀態" },
  recommendedExpert: { en: "Specialist to consult", zhTW: "建議專家類型" },
  lastObserved: { en: "Last observed", zhTW: "最後觀察" },
  evidenceConfidence: { en: "Evidence confidence", zhTW: "證據信心" },
  relatedAssets: { en: "Related assets", zhTW: "關聯資產" },
  assetCount: { en: "{count} assets", zhTW: "{count} 個" },
  decisionHistory: { en: "Human review history", zhTW: "人工處理歷程" },
  decisionCount: { en: "{count} decisions", zhTW: "{count} 筆決定" },
  decisionBoundary: {
    en: "This records a review status only. It does not change source evidence or perform a fix. ‘Verified resolved’ requires comparable verification evidence.",
    zhTW: "這裡只記錄處理狀態；不會修改原始證據，也不會執行修復。「已驗證解決」必須已有可比較的複驗證據。",
  },
  newStatus: { en: "New status", zhTW: "新狀態" },
  decidedBy: { en: "Decision made by", zhTW: "決定者" },
  decidedByPlaceholder: { en: "Name, team, or traceable identifier", zhTW: "姓名、團隊或可追溯識別" },
  reason: { en: "Reason", zhTW: "理由" },
  reasonPlaceholder: {
    en: "Record the basis for the decision. This never overwrites scan evidence.",
    zhTW: "記錄判斷依據；不會覆寫掃描證據。",
  },
  falsePositiveExpiry: { en: "False-positive expiration (optional)", zhTW: "誤判到期日（選填）" },
  saveDecision: { en: "Save review decision", zhTW: "保存處理決定" },
  noDecisions: { en: "No human review decision has been recorded.", zhTW: "尚未記錄人工處理決定。" },
  decisionActor: { en: "Decision made by {actor}", zhTW: "決定者：{actor}" },
  expires: { en: "expires {date}", zhTW: "到期：{date}" },
  neverExpires: { en: "no expiration", zhTW: "不到期" },
  possibleImpact: { en: "Possible impact", zhTW: "可能影響" },
  whyPriority: { en: "Why this appears first", zhTW: "為何優先顯示" },
  recommendation: { en: "Suggested next step", zhTW: "建議處理方向" },
  beforeChanging: { en: "Before making a change:", zhTW: "變更前考量：" },
  recommendationBoundary: {
    en: "This is guidance for a person to evaluate. The product does not make the change or guarantee its result.",
    zhTW: "這是交給人員評估的方向；產品不會自動執行，也不對變更結果背書。",
  },
  verification: { en: "How to verify later", zhTW: "複驗指引" },
  scanEvidence: { en: "Scan evidence", zhTW: "掃描證據" },
  noEvidence: {
    en: "This problem has no evidence record to check. Ask a specialist to confirm whether the data is complete.",
    zhTW: "這筆問題沒有可核對的證據；請交由專家確認資料完整性。",
  },
  technicalEvidence: { en: "Technical evidence details", zhTW: "證據技術細節" },
  evidenceKind: { en: "Type", zhTW: "種類" },
  scanRun: { en: "Scan run", zhTW: "掃描輪次" },
  engineRun: { en: "Scanner job", zhTW: "掃描器工作" },
  artifactId: { en: "Evidence file ID", zhTW: "證據檔案 ID" },
  contentHash: { en: "Content hash", zhTW: "內容雜湊" },
  evidencePointer: { en: "Internal evidence pointer", zhTW: "內部證據指標" },
  sensitiveValues: { en: "Sensitive values", zhTW: "敏感值" },
  notReported: { en: "Not reported", zhTW: "未回報" },
  legacyEngineRun: { en: "Not recorded by this older case; cannot be inferred", zhTW: "舊版案件未記錄，無法推定" },
  noPointer: { en: "No internal pointer", zhTW: "無內部位置資訊" },
  redacted: { en: "Redacted", zhTW: "已遮罩" },
  notMarkedRedacted: { en: "Not marked as redacted", zhTW: "未標示遮罩" },
  controlsTitle: { en: "Related framework references", zhTW: "相關控制項（導航）" },
  notCompliance: { en: "Not a compliance decision", zhTW: "非合規判定" },
  noControls: { en: "No framework reference is mapped to this problem.", zhTW: "這筆問題沒有控制項映射。" },
  relatedOnly: { en: "Relationship only", zhTW: "僅表示相關性" },
  viewSameControl: { en: "View problems with the same reference", zhTW: "查看同座標問題" },
  provenance: { en: "Technical source details", zhTW: "技術來源細節" },
  firstRun: { en: "First-seen run", zhTW: "初見輪次" },
  lastRun: { en: "Last-seen run", zhTW: "末見輪次" },
  firstObserved: { en: "First observed", zhTW: "首次觀察" },
  officialReferences: { en: "Official references", zhTW: "官方參考" },
  noReferences: { en: "No official reference link was provided.", zhTW: "沒有提供官方參考連結。" },
  viewSource: { en: "Open source document", zhTW: "查看來源文件" },
  chooseProblem: { en: "Choose a problem", zhTW: "選擇一項問題" },
  chooseProblemDescription: {
    en: "Evidence, source details, review history, and framework navigation will appear here.",
    zhTW: "完整證據、來源細節、處理歷程與控制項導航會顯示在這裡。",
  },
} as const;

const workflowTone = (state: FindingWorkflowState): string => {
  if (state === "verified_resolved" || state === "confirmed") return "positive";
  if (state === "false_positive") return "neutral";
  if (state === "remediated_pending_verification" || state === "remediation_reported") return "info";
  return "warning";
};

export function FindingsPage({
  findings,
  findingGroups,
  findingGroupEvents,
  coverage,
  runs,
  focusedFindingId,
  workflowEvents,
  busy,
  onUpdateWorkflow,
  onGroupFindings,
  onUngroupFindings,
  onOpenCoverage,
  onOpenProgress,
}: FindingsPageProps) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
  const collationLocale = locale === "en" ? "en" : "zh-Hant";
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [workflow, setWorkflow] = useState<FindingWorkflowState | "all">("all");
  const [expertType, setExpertType] = useState("all");
  const [control, setControl] = useState("all");
  const [selectedId, setSelectedId] = useState<string | undefined>(focusedFindingId ?? findings[0]?.id);
  const [decisionStatus, setDecisionStatus] = useState<(typeof decisionStates)[number]>("expert_review_requested");
  const [decidedBy, setDecidedBy] = useState("");
  const [decisionReason, setDecisionReason] = useState("");
  const [decisionExpiry, setDecisionExpiry] = useState("");
  const [groupTitle, setGroupTitle] = useState("");
  const [groupRationale, setGroupRationale] = useState("");
  const [groupFindingIds, setGroupFindingIds] = useState<string[]>([]);
  const appliedFocusId = useRef<string | undefined>(undefined);

  useEffect(() => {
    if (focusedFindingId && appliedFocusId.current !== focusedFindingId && findings.some((finding) => finding.id === focusedFindingId)) {
      appliedFocusId.current = focusedFindingId;
      setSelectedId(focusedFindingId);
      window.setTimeout(() => document.getElementById("finding-browser")?.scrollIntoView({ block: "start" }), 0);
    }
  }, [findings, focusedFindingId]);

  useEffect(() => {
    setSelectedId((current) => findings.some((finding) => finding.id === current) ? current : findings[0]?.id);
  }, [findings]);

  const ordered = useMemo(
    () => [...findings].sort((a, b) => b.priority - a.priority || a.title.localeCompare(b.title, collationLocale)),
    [collationLocale, findings],
  );
  const displayRankByFindingId = useMemo(
    () => new Map(ordered.map((finding, index) => [finding.id, index + 1])),
    [ordered],
  );
  const expertTypes = useMemo(
    () => [...new Set(findings.map((finding) => finding.expertType).filter(Boolean))].sort((a, b) => a.localeCompare(b, collationLocale)),
    [collationLocale, findings],
  );
  const controls = useMemo(() => {
    const values = new Map<string, { key: string; label: string }>();
    for (const finding of findings) {
      for (const item of finding.controls) {
        const key = controlKey(item.framework, item.version, item.controlId);
        values.set(key, { key, label: `${item.framework} ${item.controlId}` });
      }
    }
    return [...values.values()].sort((a, b) => a.label.localeCompare(b.label, collationLocale));
  }, [collationLocale, findings]);
  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase(collationLocale);
    return ordered.filter((finding) => {
      const matchesSeverity = severity === "all" || finding.severity === severity;
      const matchesWorkflow = workflow === "all" || finding.workflowState === workflow;
      const matchesExpert = expertType === "all" || finding.expertType === expertType;
      const matchesControl = control === "all" || finding.controls.some(
        (item) => controlKey(item.framework, item.version, item.controlId) === control,
      );
      const matchesQuery = !normalizedQuery || [
        finding.title,
        finding.assetName,
        finding.summary,
        finding.expertType,
        finding.fingerprint,
        ...(finding.tags ?? []),
        ...finding.evidence.map((item) => `${item.sourceEngine} ${item.summary}`),
        ...finding.controls.map((item) => `${item.framework} ${item.controlId} ${item.title ?? ""}`),
      ].join(" ").toLocaleLowerCase(collationLocale).includes(normalizedQuery);
      return matchesSeverity && matchesWorkflow && matchesExpert && matchesControl && matchesQuery;
    });
  }, [collationLocale, control, expertType, ordered, query, severity, workflow]);

  const selected = findings.find((finding) => finding.id === selectedId);
  const selectedEvents = workflowEvents
    .filter((event) => event.findingId === selectedId)
    .sort((left, right) => right.decidedAt.localeCompare(left.decidedAt));
  const topFindings = ordered.filter((finding) => finding.workflowState !== "verified_resolved" && finding.workflowState !== "false_positive").slice(0, 3);
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const highCount = findings.filter((finding) => finding.severity === "high").length;
  const needsReview = findings.filter((finding) => ["unreviewed", "unconfirmed", "expert_review_requested"].includes(finding.workflowState)).length;
  const affectedAssets = new Set(findings.flatMap((finding) => finding.assetIds ?? [finding.assetId])).size;
  const groupedFindingIds = useMemo(
    () => new Set(findingGroups.flatMap((group) => group.findingIds)),
    [findingGroups],
  );
  const findingById = useMemo(
    () => new Map(findings.map((finding) => [finding.id, finding])),
    [findings],
  );
  const orderedGroupEvents = useMemo(
    () => [...findingGroupEvents].sort((left, right) => right.occurredAt.localeCompare(left.occurredAt) || right.id.localeCompare(left.id)),
    [findingGroupEvents],
  );

  useEffect(() => {
    setGroupFindingIds((current) => current.filter((findingId) => !groupedFindingIds.has(findingId)));
  }, [groupedFindingIds]);

  if (findings.length === 0) {
    const latestRun = runs[0];
    const unknownSources = coverage.filter((item) => item.state === "source_unavailable_unknown").length;
    const connectedWithoutAssets = coverage.filter((item) => item.state === "source_connected_none").length;
    const incompleteRun = latestRun && latestRun.status !== "completed";
    const title = !latestRun
      ? text(copy.emptyNoRunTitle)
      : incompleteRun
        ? text(copy.emptyIncompleteTitle)
        : unknownSources > 0
          ? text(copy.emptyUnknownTitle)
          : text(copy.emptyCompletedTitle);
    const description = !latestRun
      ? text(copy.emptyNoRunDescription)
      : incompleteRun
        ? text(copy.emptyIncompleteDescription)
        : unknownSources > 0
          ? text(copy.emptyUnknownDescription, { count: formatNumber(unknownSources) })
          : text(copy.emptyCompletedDescription, { count: formatNumber(connectedWithoutAssets) });
    return (
      <div className="page">
        <PageHeader eyebrow={text(copy.eyebrow)} title={text(copy.emptyHeaderTitle)} description={text(copy.emptyHeaderDescription)} />
        <EmptyState
          icon={incompleteRun || unknownSources > 0 ? "warning" : "findings"}
          title={title}
          description={description}
          action={
            <div className="button-group">
              <button className="button button--secondary" type="button" onClick={onOpenCoverage}><Icon name="coverage" size={16} />{text(copy.openCoverage)}</button>
              {latestRun && <button className="button button--primary" type="button" onClick={onOpenProgress}><Icon name="progress" size={16} />{text(copy.openProgress)}</button>}
            </div>
          }
        />
      </div>
    );
  }

  const applyControlFilter = (key: string) => {
    setControl(key);
    document.getElementById("finding-browser")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const clearFilters = () => {
    setQuery("");
    setSeverity("all");
    setWorkflow("all");
    setExpertType("all");
    setControl("all");
  };
  const activeFilterCount = [severity !== "all", workflow !== "all", expertType !== "all", control !== "all", Boolean(query.trim())].filter(Boolean).length;
  const submitDecision = async (event: FormEvent) => {
    event.preventDefault();
    if (!selected || !decidedBy.trim() || !decisionReason.trim()) return;
    const updated = await onUpdateWorkflow({
      findingId: selected.id,
      status: decisionStatus,
      decidedBy: decidedBy.trim(),
      reason: decisionReason.trim(),
      expiresAt: decisionStatus === "false_positive" && decisionExpiry
        ? new Date(`${decisionExpiry}T23:59:59`).toISOString()
        : undefined,
    });
    if (!updated) return;
    setDecisionReason("");
    setDecisionExpiry("");
  };
  const toggleGroupedFinding = (findingId: string) => {
    setGroupFindingIds((current) =>
      current.includes(findingId)
        ? current.filter((item) => item !== findingId)
        : [...current, findingId],
    );
  };
  const submitGroup = async (event: FormEvent) => {
    event.preventDefault();
    if (!groupTitle.trim() || !groupRationale.trim() || groupFindingIds.length < 2) return;
    const grouped = await onGroupFindings({
      title: groupTitle.trim(),
      findingIds: groupFindingIds,
      rationale: groupRationale.trim(),
    });
    if (!grouped) return;
    setGroupTitle("");
    setGroupRationale("");
    setGroupFindingIds([]);
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow={text(copy.eyebrow)}
        title={text(copy.title)}
        description={text(copy.description)}
      />

      <section className="metrics-grid metrics-grid--four" aria-label={text(copy.summaryAria)}>
        <MetricCard label={text(copy.critical)} value={criticalCount} detail={text(copy.criticalDetail)} icon="warning" tone={criticalCount ? "danger" : "default"} />
        <MetricCard label={text(copy.high)} value={highCount} detail={text(copy.highDetail)} icon="findings" tone={highCount ? "warning" : "default"} />
        <MetricCard label={text(copy.needsReview)} value={needsReview} detail={text(copy.needsReviewDetail)} icon="search" />
        <MetricCard label={text(copy.affectedAssets)} value={affectedAssets} detail={text(copy.completeListCount, { count: formatNumber(findings.length) })} icon="database" />
      </section>

      <section className="section-block" aria-labelledby="finding-groups-title">
        <div className="section-heading">
          <p className="eyebrow">{text(copy.reversibleLinks)}</p>
          <h2 id="finding-groups-title">{text(copy.groupsTitle)}</h2>
          <p>{text(copy.groupsDescription)}</p>
        </div>

        {findingGroups.length > 0 && (
          <div className="evidence-list">
            {findingGroups.map((group) => {
              const members = group.findingIds
                .map((findingId) => findingById.get(findingId))
                .filter((finding): finding is Finding => Boolean(finding));
              return (
                <article key={group.id} className="evidence-item">
                  <div>
                    <strong>{group.title}</strong>
                    <span>{text(copy.items, { count: formatNumber(members.length) })} · {formatDateTime(group.createdAt)}</span>
                  </div>
                  <p>{group.rationale}</p>
                  <ul className="detail-list">
                    {members.map((finding) => (
                      <li key={finding.id}>
                        <button className="clear-filters" type="button" onClick={() => setSelectedId(finding.id)}>
                          {finding.title}
                        </button>
                      </li>
                    ))}
                  </ul>
                  <small>{text(copy.createdBy, { actor: group.groupedBy })}</small>
                  <details className="page-technical-details">
                    <summary>{text(copy.technicalGroupDetails)}</summary>
                    <dl><div><dt>{text(copy.groupId)}</dt><dd><code>{group.id}</code></dd></div></dl>
                  </details>
                  <button
                    className="button button--ghost button--small"
                    type="button"
                    disabled={busy}
                    onClick={() => void onUngroupFindings(group.id)}
                  >
                    {text(copy.removeGroup)}
                  </button>
                </article>
              );
            })}
          </div>
        )}

        {orderedGroupEvents.length > 0 && (
          <details className="source-connect-panel">
            <summary>{text(copy.groupHistory, { count: formatNumber(orderedGroupEvents.length) })}</summary>
            <p>{text(copy.groupHistoryDescription)}</p>
            <div className="evidence-list">
              {orderedGroupEvents.map((event) => (
                <article key={event.id} className="evidence-item">
                  <div>
                    <strong>{event.action === "created" ? text(copy.groupCreated) : text(copy.groupRemoved)}: {event.title}</strong>
                    <span>{formatDateTime(event.occurredAt)}</span>
                  </div>
                  <p>{event.rationale}</p>
                  <ul className="detail-list">
                    {event.findingIds.map((findingId) => (
                      <li key={findingId}>{findingById.get(findingId)?.title ?? `${text(copy.findingId)}: ${findingId}`}</li>
                    ))}
                  </ul>
                  <small>{text(copy.performedBy, { actor: event.actor })}</small>
                  <details className="page-technical-details">
                    <summary>{text(copy.technicalGroupDetails)}</summary>
                    <dl><div><dt>{text(copy.groupId)}</dt><dd><code>{event.groupId}</code></dd></div></dl>
                  </details>
                </article>
              ))}
            </div>
          </details>
        )}

        <form className="source-connect-panel" onSubmit={(event) => void submitGroup(event)}>
          <label>
            <span>{text(copy.groupTitle)}</span>
            <input maxLength={200} required value={groupTitle} onChange={(event) => setGroupTitle(event.target.value)} placeholder={text(copy.groupTitlePlaceholder)} />
          </label>
          <label>
            <span>{text(copy.groupReason)}</span>
            <textarea maxLength={2000} required value={groupRationale} onChange={(event) => setGroupRationale(event.target.value)} placeholder={text(copy.groupReasonPlaceholder)} />
          </label>
          <fieldset className="choice-fieldset">
            <legend>{text(copy.chooseTwo)}</legend>
            <div className="choice-grid choice-grid--compact">
              {ordered.filter((finding) => !groupedFindingIds.has(finding.id)).map((finding) => (
                <label key={finding.id} className="check-card check-card--compact">
                  <input
                    type="checkbox"
                    checked={groupFindingIds.includes(finding.id)}
                    onChange={() => toggleGroupedFinding(finding.id)}
                  />
                  <span>{finding.title}<small>{finding.assetName} · {severityMeta[finding.severity].label}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
          <button className="button button--secondary" type="submit" disabled={busy || !groupTitle.trim() || !groupRationale.trim() || groupFindingIds.length < 2}>
            {text(copy.createGroup)}
          </button>
        </form>
      </section>

      {topFindings.length > 0 && (
        <section className="section-block priority-section">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.doNow)}</p>
            <h2>{text(copy.priorityTitle)}</h2>
            <p>{text(copy.priorityDescription)}</p>
          </div>
          <div className="priority-grid">
            {topFindings.map((finding, index) => (
              <button
                key={finding.id}
                type="button"
                className="priority-card"
                onClick={() => {
                  setSelectedId(finding.id);
                  document.getElementById("finding-browser")?.scrollIntoView({ behavior: "smooth", block: "start" });
                }}
              >
                <span className="priority-card__number">{String(index + 1).padStart(2, "0")}</span>
                <StatusPill label={severityMeta[finding.severity].label} tone={severityMeta[finding.severity].tone} />
                <h3>{finding.title}</h3>
                <p>{finding.impact}</p>
                <span className="priority-card__asset">{finding.assetName}</span>
                <span className="priority-card__action">{text(copy.reviewEvidence)} <Icon name="arrow" size={15} /></span>
              </button>
            ))}
          </div>
        </section>
      )}

      <InlineNotice tone="info" title={text(copy.boundaryTitle)}>
        <p>{text(copy.boundaryBody)}</p>
      </InlineNotice>

      <section id="finding-browser" className="finding-browser">
        <div className="finding-browser__list">
          <div className="section-heading section-heading--row finding-toolbar-heading">
            <div><p className="eyebrow">{text(copy.allProblems)}</p><h2>{text(copy.completeList)}</h2></div>
            <span className="count-label">{formatNumber(filtered.length)} / {formatNumber(findings.length)}</span>
          </div>

          <div className="finding-filter-stack">
            <label className="search-field">
              <span className="sr-only">{text(copy.searchAria)}</span>
              <Icon name="search" size={18} />
              <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={text(copy.searchPlaceholder)} />
            </label>
            <div className="finding-filter-grid">
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">{text(copy.severityFilter)}</span>
                <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | "all")}>
                  <option value="all">{text(copy.allSeverities)}</option>
                  {severityOrder.map((item) => <option key={item} value={item}>{severityMeta[item].label}</option>)}
                </select>
              </label>
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">{text(copy.workflowFilter)}</span>
                <select value={workflow} onChange={(event) => setWorkflow(event.target.value as FindingWorkflowState | "all")}>
                  <option value="all">{text(copy.allWorkflows)}</option>
                  {workflowOrder.map((item) => <option key={item} value={item}>{workflowMeta[item]}</option>)}
                </select>
              </label>
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">{text(copy.expertFilter)}</span>
                <select value={expertType} onChange={(event) => setExpertType(event.target.value)}>
                  <option value="all">{text(copy.allExperts)}</option>
                  {expertTypes.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </label>
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">{text(copy.controlFilter)}</span>
                <select value={control} onChange={(event) => setControl(event.target.value)}>
                  <option value="all">{text(copy.allControls)}</option>
                  {controls.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}
                </select>
              </label>
            </div>
            {activeFilterCount > 0 && <button className="clear-filters" type="button" onClick={clearFilters}><Icon name="close" size={14} />{text(copy.clearFilterCount, { count: formatNumber(activeFilterCount) })}</button>}
          </div>

          <div className="finding-list" role="list">
            {filtered.length === 0 ? (
              <EmptyState icon="search" title={text(copy.noMatches)} description={text(copy.noMatchesDescription)} action={<button className="button button--ghost button--small" type="button" onClick={clearFilters}>{text(copy.clearFilters)}</button>} />
            ) : filtered.map((finding) => (
              <button
                key={finding.id}
                type="button"
                role="listitem"
                className={selectedId === finding.id ? "finding-row finding-row--active" : "finding-row"}
                onClick={() => setSelectedId(finding.id)}
              >
                <span className="finding-row__priority" aria-label={text(copy.rankAria, { rank: displayRankByFindingId.get(finding.id) ?? "—" })}>
                  {text(copy.rank, { rank: displayRankByFindingId.get(finding.id) ?? "—" })}
                </span>
                <span className="finding-row__main">
                  <span className="finding-row__top">
                    <StatusPill label={severityMeta[finding.severity].label} tone={severityMeta[finding.severity].tone} />
                    <StatusPill label={workflowMeta[finding.workflowState]} tone={workflowTone(finding.workflowState)} />
                  </span>
                  <strong>{finding.title}</strong>
                  <span>{finding.assetName} · {text(copy.evidenceCount, { count: formatNumber(finding.evidence.length) })} · {confidenceMeta[finding.confidence]}</span>
                </span>
                <Icon name="chevron" size={18} />
              </button>
            ))}
          </div>
        </div>

        <aside className="finding-detail" aria-live="polite">
          {selected ? (
            <>
              <div className="finding-detail__header">
                <div className="tag-row">
                  <StatusPill label={severityMeta[selected.severity].label} tone={severityMeta[selected.severity].tone} />
                  <StatusPill label={confidenceMeta[selected.confidence]} tone="neutral" />
                  <StatusPill label={workflowMeta[selected.workflowState]} tone={workflowTone(selected.workflowState)} />
                </div>
                <h2>{selected.title}</h2>
                <p>{selected.summary}</p>
              </div>

              <dl className="detail-facts">
                <div><dt>{text(copy.asset)}</dt><dd>{selected.assetName}</dd></div>
                <div><dt>{text(copy.reviewStatus)}</dt><dd>{workflowMeta[selected.workflowState]}</dd></div>
                <div><dt>{text(copy.recommendedExpert)}</dt><dd>{selected.expertType}</dd></div>
                <div><dt>{text(copy.lastObserved)}</dt><dd>{formatDateTime(selected.lastSeenAt)}</dd></div>
                <div><dt>{text(copy.evidenceConfidence)}</dt><dd>{confidenceMeta[selected.confidence]}</dd></div>
                <div><dt>{text(copy.relatedAssets)}</dt><dd>{text(copy.assetCount, { count: formatNumber(selected.assetIds?.length ?? 1) })}</dd></div>
              </dl>

              <section className="detail-section">
                <div className="detail-section__heading"><h3>{text(copy.decisionHistory)}</h3><span>{text(copy.decisionCount, { count: formatNumber(selectedEvents.length) })}</span></div>
                <form className="source-connect-panel" onSubmit={(event) => void submitDecision(event)}>
                  <p>{text(copy.decisionBoundary)}</p>
                  <label>
                    <span>{text(copy.newStatus)}</span>
                    <select value={decisionStatus} onChange={(event) => setDecisionStatus(event.target.value as (typeof decisionStates)[number])}>
                      {decisionStates.map((state) => <option key={state} value={state}>{workflowMeta[state]}</option>)}
                    </select>
                  </label>
                  <label>
                    <span>{text(copy.decidedBy)}</span>
                    <input required maxLength={120} value={decidedBy} onChange={(event) => setDecidedBy(event.target.value)} placeholder={text(copy.decidedByPlaceholder)} />
                  </label>
                  <label>
                    <span>{text(copy.reason)}</span>
                    <textarea required maxLength={2000} value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)} placeholder={text(copy.reasonPlaceholder)} />
                  </label>
                  {decisionStatus === "false_positive" && (
                    <label>
                      <span>{text(copy.falsePositiveExpiry)}</span>
                      <input type="date" value={decisionExpiry} onChange={(event) => setDecisionExpiry(event.target.value)} />
                    </label>
                  )}
                  <button className="button button--secondary" type="submit" disabled={busy || !decidedBy.trim() || !decisionReason.trim() || decisionStatus === selected.workflowState}>
                    <Icon name="database" size={16} />{text(copy.saveDecision)}
                  </button>
                </form>
                {selectedEvents.length === 0 ? <p>{text(copy.noDecisions)}</p> : (
                  <div className="evidence-list">
                    {selectedEvents.map((event) => (
                      <article key={event.id} className="evidence-item">
                        <div><strong>{workflowMeta[event.fromStatus]} → {workflowMeta[event.toStatus]}</strong><span>{formatDateTime(event.decidedAt)}</span></div>
                        <p>{event.reason}</p>
                        <small>
                          {text(copy.decisionActor, { actor: event.decidedBy })} · {event.expiresAt
                            ? text(copy.expires, { date: formatDateTime(event.expiresAt) })
                            : text(copy.neverExpires)}
                        </small>
                      </article>
                    ))}
                  </div>
                )}
              </section>

              <section className="detail-section">
                <h3>{text(copy.possibleImpact)}</h3>
                <p>{selected.impact}</p>
              </section>

              {(selected.priorityReasons?.length ?? 0) > 0 && (
                <section className="detail-section">
                  <h3>{text(copy.whyPriority)}</h3>
                  <ul className="detail-list">{selected.priorityReasons?.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                </section>
              )}

              <section className="detail-section detail-section--advice">
                <h3>{text(copy.recommendation)}</h3>
                <p>{selected.recommendation}</p>
                {selected.rollbackConsiderations && <p><strong>{text(copy.beforeChanging)}</strong> {selected.rollbackConsiderations}</p>}
                <small>{text(copy.recommendationBoundary)}</small>
              </section>

              {selected.verificationGuidance && (
                <section className="detail-section">
                  <h3>{text(copy.verification)}</h3>
                  <p>{selected.verificationGuidance}</p>
                </section>
              )}

              <section className="detail-section">
                <div className="detail-section__heading"><h3>{text(copy.scanEvidence)}</h3><span>{text(copy.evidenceCount, { count: formatNumber(selected.evidence.length) })}</span></div>
                {selected.evidence.length === 0 ? (
                  <p>{text(copy.noEvidence)}</p>
                ) : (
                  <div className="evidence-list">
                    {selected.evidence.map((evidence) => (
                      <article key={evidence.id} className="evidence-item">
                        <div><strong>{evidence.sourceEngine}</strong><span>{formatDateTime(evidence.observedAt)}</span></div>
                        <p>{evidence.summary}</p>
                        <details className="page-technical-details">
                          <summary>{text(copy.technicalEvidence)}</summary>
                          <dl className="evidence-provenance">
                            <div><dt>{text(copy.evidenceKind)}</dt><dd>{evidence.kind?.replaceAll("_", " ") ?? text(copy.notReported)}</dd></div>
                            <div><dt>{text(copy.scanRun)}</dt><dd><code>{evidence.runId ?? selected.lastSeenRunId ?? text(copy.notReported)}</code></dd></div>
                            <div><dt>{text(copy.engineRun)}</dt><dd><code>{evidence.engineRunId ?? text(copy.legacyEngineRun)}</code></dd></div>
                            <div><dt>{text(copy.artifactId)}</dt><dd><code>{evidence.artifactId ?? text(copy.notReported)}</code></dd></div>
                            <div><dt>{text(copy.contentHash)}</dt><dd><code>{evidence.rawArtifactHash}</code></dd></div>
                            <div><dt>{text(copy.evidencePointer)}</dt><dd><code>{evidence.rawArtifactPath ?? text(copy.noPointer)}</code></dd></div>
                            <div><dt>{text(copy.sensitiveValues)}</dt><dd>{evidence.redacted === true ? text(copy.redacted) : evidence.redacted === false ? text(copy.notMarkedRedacted) : text(copy.notReported)}</dd></div>
                          </dl>
                        </details>
                      </article>
                    ))}
                  </div>
                )}
              </section>

              <section className="detail-section">
                <div className="detail-section__heading"><h3>{text(copy.controlsTitle)}</h3><span>{text(copy.notCompliance)}</span></div>
                {selected.controls.length === 0 ? <p>{text(copy.noControls)}</p> : (
                  <div className="control-list">
                    {selected.controls.map((item) => {
                      const key = controlKey(item.framework, item.version, item.controlId);
                      return (
                        <button key={key} type="button" className={control === key ? "control-item control-item--active" : "control-item"} onClick={() => applyControlFilter(key)}>
                          <span><b>{item.framework}</b><small>{item.version}</small></span>
                          <span><strong>{item.controlId}{item.title ? ` · ${item.title}` : ""}</strong><small>{item.rationale ?? item.note ?? text(copy.relatedOnly)}</small></span>
                          <span className="control-item__action">{text(copy.viewSameControl)} <Icon name="arrow" size={13} /></span>
                          {item.mappingVersion && <code>mapping {item.mappingVersion}</code>}
                        </button>
                      );
                    })}
                  </div>
                )}
              </section>

              <section className="detail-section provenance-section">
                <details className="page-technical-details">
                  <summary>{text(copy.provenance)}</summary>
                  <dl>
                    <div><dt>Fingerprint</dt><dd><code>{selected.fingerprint}</code></dd></div>
                    <div><dt>{text(copy.findingId)}</dt><dd><code>{selected.id}</code></dd></div>
                    <div><dt>{text(copy.firstRun)}</dt><dd><code>{selected.firstSeenRunId ?? text(copy.notReported)}</code></dd></div>
                    <div><dt>{text(copy.lastRun)}</dt><dd><code>{selected.lastSeenRunId ?? text(copy.notReported)}</code></dd></div>
                    <div><dt>{text(copy.firstObserved)}</dt><dd>{formatDateTime(selected.firstSeenAt)}</dd></div>
                    <div><dt>{text(copy.lastObserved)}</dt><dd>{formatDateTime(selected.lastSeenAt)}</dd></div>
                  </dl>
                </details>
                {(selected.tags?.length ?? 0) > 0 && <div className="tag-row">{selected.tags?.map((tag) => <span className="tag tag--light" key={tag}>{tag}</span>)}</div>}
              </section>

              <section className="detail-section">
                <h3>{text(copy.officialReferences)}</h3>
                {selected.officialReferences.length === 0 ? <p>{text(copy.noReferences)}</p> : selected.officialReferences.map((reference) => (
                  <a key={reference} href={reference} target="_blank" rel="noreferrer noopener">{text(copy.viewSource)} <Icon name="external" size={14} /></a>
                ))}
              </section>
            </>
          ) : (
            <EmptyState icon="findings" title={text(copy.chooseProblem)} description={text(copy.chooseProblemDescription)} />
          )}
        </aside>
      </section>
    </div>
  );
}
