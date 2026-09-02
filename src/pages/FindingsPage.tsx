import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  confidenceMeta,
  engineStatusMeta,
  severityMeta,
  workflowMeta,
} from "../lib";
import { useI18n } from "../i18n";
import { unavailableRunBoundReportCopy } from "../findingsReportAvailability";
import {
  localhostTcpBeginnerSummary,
  localhostTestedDimensionValue,
} from "../localhostTcpPresentation";
import { isExactBuiltInLocalhostQuickScanEngine } from "../localhostQuickScan";
import { scanRequestOutcomeBeginnerSummary } from "../scanRequestOutcomePresentation";
import { scanRunIdentityPresentation } from "../scanRunIdentityPresentation";
import type {
  BeginnerCoverageGapKind,
  BeginnerCoverageStatus,
  BeginnerMasterReport,
  BeginnerNextActionCode,
  BeginnerReportStage,
  BeginnerReportSummary,
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
  report?: BeginnerMasterReport;
  selectedRunId?: string;
  reportUnavailable?: boolean;
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
  onOpenExport: (runId: string) => void;
  onSelectRun?: (runId: string) => void;
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "unknown", "info"];
const activeRunStatuses = new Set<ScanRun["status"]>(["queued", "running", "paused"]);
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
    en: "Know what to fix first",
    zhTW: "先知道該修什麼",
  },
  description: {
    en: "See the issues that matter most, what they could affect, and the clearest next step for your team.",
    zhTW: "先看最重要的問題、可能影響，以及團隊接下來可以怎麼做。",
  },
  emptyHeaderTitle: { en: "Problem list", zhTW: "問題清單" },
  emptyHeaderDescription: {
    en: "Your scan results and recommended next steps will appear here.",
    zhTW: "掃描結果與建議的下一步會顯示在這裡。",
  },
  emptyNoRunTitle: { en: "No scan results yet", zhTW: "尚未產生掃描結果" },
  emptyActiveTitle: {
    en: "The scan is still running; no problems have arrived yet",
    zhTW: "掃描仍在執行，目前還沒有收到問題",
  },
  emptyIncompleteTitle: {
    en: "This run produced no saved problems, but the scan did not finish",
    zhTW: "本輪沒有正式問題紀錄，但掃描未完整完成",
  },
  emptyUnknownTitle: {
    en: "No problems are shown, but some sources still need data",
    zhTW: "目前沒有顯示問題，但有些來源還需要資料",
  },
  emptyCompletedTitle: {
    en: "No problems were observed in the work that completed",
    zhTW: "已完成的範圍內沒有觀察到問題",
  },
  emptyNoRunDescription: {
    en: "Add what you want to scan, then start the check from Scan progress.",
    zhTW: "先加入想掃描的目標，再到掃描進度開始檢查。",
  },
  emptyActiveDescription: {
    en: "This is an interim view, not a clean result. Keep Scan progress open until every check has a final outcome.",
    zhTW: "這只是暫時畫面，不代表沒有問題。請查看「掃描進度」，直到每項檢查都有最終結果。",
  },
  activeTitle: { en: "These are interim results", zhTW: "這些是暫時結果" },
  activeDescription: {
    en: "A scan is still running. More problems may appear, and the current counts must not be treated as the final result.",
    zhTW: "掃描仍在執行，之後可能還會出現更多問題；目前數量不能視為最終結果。",
  },
  incompleteTitle: { en: "These results are incomplete", zhTW: "這些結果尚不完整" },
  incompleteDescription: {
    en: "Some checks stopped before reaching a final result. The saved problems still need review, but other problems may be missing. Open Scan progress before treating these counts as final.",
    zhTW: "有些檢查在產生最終結果前就停止了。已保存的問題仍需檢視，但也可能還有未顯示的問題；請先查看「掃描進度」，不要把目前數量視為最終結果。",
  },
  emptyIncompleteDescription: {
    en: "Some checks did not finish, so there may be issues we could not see. Open Scan progress to see what needs attention.",
    zhTW: "有些檢查沒有完成，因此可能還有看不到的問題。打開掃描進度，就能知道哪裡需要處理。",
  },
  emptyUnknownDescription: {
    en: "Sources still needing usable information: {count}. Open Scan setup to connect or check them.",
    zhTW: "還有 {count} 個來源沒有提供可用資訊。打開掃描設定即可連接或確認。",
  },
  emptyCompletedDescription: {
    en: "The completed checks recorded no issues in their tested scope. Sources included: {count}. Open Scan setup to review exactly what was included.",
    zhTW: "已完成的檢查在實際測試範圍內沒有記錄問題。打開掃描設定，即可查看這 {count} 個來源實際包含了什麼。",
  },
  openCoverage: { en: "Open scan setup", zhTW: "開啟掃描設定" },
  openProgress: { en: "Review scanner status", zhTW: "查看掃描器狀態" },
  openExport: { en: "Save or share report", zhTW: "保存或分享報告" },
  summaryAria: { en: "Problem summary", zhTW: "問題摘要" },
  critical: { en: "Critical", zhTW: "嚴重" },
  criticalDetail: { en: "Ask the appropriate specialist to confirm these first", zhTW: "優先請對應專家確認" },
  high: { en: "High priority", zhTW: "高風險" },
  highDetail: { en: "Plan these into the next round of work", zhTW: "排進下一輪處理工作" },
  needsReview: { en: "Needs human review", zhTW: "待人工確認" },
  needsReviewDetail: { en: "Confirm these before your team acts", zhTW: "團隊採取行動前先確認" },
  affectedAssets: { en: "Affected assets", zhTW: "受影響資產" },
  completeListCount: { en: "Problems in the complete list: {count}", zhTW: "完整清單共 {count} 項" },
  reversibleLinks: { en: "TEAM HANDOFF", zhTW: "團隊交接" },
  groupsTitle: { en: "Organize related issues for the right team", zhTW: "把相關問題整理給同一個團隊" },
  groupsDescription: {
    en: "Bundle issues that should be reviewed together, so handoff is faster and easier to follow.",
    zhTW: "把適合一起處理的問題放在同一組，讓交接更快、更容易追蹤。",
  },
  items: { en: "Items: {count}", zhTW: "{count} 項" },
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
    en: "Add a short note so the next person knows why these should be handled together.",
    zhTW: "簡單說明為什麼這些問題適合一起處理，讓接手者一看就懂。",
  },
  chooseTwo: { en: "Choose at least two ungrouped problems", zhTW: "選擇至少兩項尚未分組的問題" },
  createGroup: { en: "Create reversible group", zhTW: "建立可逆群組" },
  doNow: { en: "START HERE", zhTW: "從這裡開始" },
  priorityTitle: { en: "Start with these issues", zhTW: "優先處理這些問題" },
  priorityDescription: {
    en: "These are likely to matter most. Open one to see the impact, evidence, and suggested next step.",
    zhTW: "這些問題最值得先看。打開任一項，就能查看影響、證據與建議的下一步。",
  },
  reviewEvidence: { en: "Review evidence", zhTW: "查看證據" },
  boundaryTitle: { en: "This is not an audit conclusion or an executable fix", zhTW: "這不是稽核結論，也不是可執行修復" },
  boundaryBody: {
    en: "This page records observations, possible impact, human decisions, and the kind of specialist to consult. Authorized people evaluate and perform any environment change outside this product.",
    zhTW: "畫面只保存觀察、可能影響、人工決定與建議找哪類專家。任何環境變更都在產品之外由具權限的人員評估及執行。",
  },
  howToRead: { en: "How to read these results", zhTW: "如何解讀這些結果" },
  allProblems: { en: "EXPLORE RESULTS", zhTW: "查看所有結果" },
  completeList: { en: "Browse every issue", zhTW: "瀏覽所有問題" },
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
  clearFilterCount: { en: "Clear filters ({count})", zhTW: "清除 {count} 個篩選條件" },
  noMatches: { en: "No problems match these filters", zhTW: "沒有符合的問題" },
  noMatchesDescription: {
    en: "Clear the search text, review status, specialist type, or framework filter.",
    zhTW: "清除搜尋字詞、處理狀態、專家類型或控制項篩選。",
  },
  clearFilters: { en: "Clear filters", zhTW: "清除篩選" },
  rankAria: { en: "Handoff priority {rank}", zhTW: "交接優先順序第 {rank} 位" },
  rank: { en: "#{rank}", zhTW: "第 {rank}" },
  evidenceCount: { en: "Evidence records: {count}", zhTW: "{count} 份證據" },
  asset: { en: "Asset", zhTW: "資產" },
  reviewStatus: { en: "Review status", zhTW: "處理狀態" },
  recommendedExpert: { en: "Specialist to consult", zhTW: "建議專家類型" },
  lastObserved: { en: "Last observed", zhTW: "最後觀察" },
  evidenceConfidence: { en: "Evidence confidence", zhTW: "證據信心" },
  relatedAssets: { en: "Related assets", zhTW: "關聯資產" },
  assetCount: { en: "Assets: {count}", zhTW: "{count} 個" },
  decisionHistory: { en: "Human review history", zhTW: "人工處理歷程" },
  decisionCount: { en: "Decisions: {count}", zhTW: "{count} 筆決定" },
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
  masterEyebrow: { en: "YOUR SCAN REPORT", zhTW: "你的掃描報告" },
  masterTitle: { en: "What was checked—and what was not", zhTW: "這次檢查了什麼，也漏了什麼" },
  reportComplete: { en: "Complete", zhTW: "完整" },
  reportPartial: { en: "Partial results", zhTW: "部分結果" },
  reportNoChecks: { en: "No checks completed", zhTW: "沒有完成任何檢查" },
  reportLive: { en: "Still updating", zhTW: "仍在更新" },
  reportFinal: { en: "Final for this run", zhTW: "本輪已結束" },
  reportRun: { en: "Report run", zhTW: "報告輪次" },
  reportRunUnavailable: { en: "Previously selected scan unavailable", zhTW: "先前選擇的掃描已無法使用" },
  lastSaved: { en: "Last saved {time}", zhTW: "最後保存：{time}" },
  requestedTargets: { en: "Targets requested", zhTW: "要求檢查的目標" },
  testedComplete: { en: "Checks completed", zhTW: "完成的檢查" },
  testedPartialCount: { en: "Partly completed", zhTW: "部分完成" },
  failedCount: { en: "Failed", zhTW: "失敗" },
  timedOutCount: { en: "Timed out", zhTW: "逾時" },
  cancelledCount: { en: "Cancelled", zhTW: "已取消" },
  notTestedCount: { en: "Not tested", zhTW: "未測試" },
  excludedCount: { en: "Excluded", zhTW: "排除" },
  truncatedCount: { en: "Reduced by limits", zhTW: "受限制而縮減" },
  unavailableCount: { en: "Detail unavailable", zhTW: "資料不足" },
  coverageGaps: { en: "Coverage gaps", zhTW: "未涵蓋項目" },
  reportFindings: { en: "Problems found", zhTW: "發現的問題" },
  askedTitle: { en: "What you asked to scan", zhTW: "你要求掃描的內容" },
  testedTitle: { en: "What was actually tested", zhTW: "實際完成的測試" },
  gapsTitle: { en: "What was not tested", zhTW: "沒有測到的內容" },
  nextTitle: { en: "What to do next", zhTW: "接下來怎麼做" },
  noRequestedTarget: {
    en: "The older run did not retain an exact target description.",
    zhTW: "這筆舊掃描沒有保留精確的目標說明。",
  },
  noTestedDimension: {
    en: "No completed test dimension was saved for this run.",
    zhTW: "本輪沒有保存已完成的測試範圍。",
  },
  noGap: { en: "No known coverage gap was recorded.", zhTW: "沒有記錄到已知的涵蓋缺口。" },
  noNextStep: {
    en: "Review the saved results; no extra action is required unless you want broader coverage.",
    zhTW: "先檢視已保存的結果；除非想擴大涵蓋範圍，否則不需要額外動作。",
  },
  stage: { en: "Scan depth", zhTW: "掃描深度" },
  stageQuick: { en: "Quick discovery", zhTW: "快速探索" },
  stageInventory: { en: "Full inventory", zhTW: "完整盤點" },
  stageDeep: { en: "Deep scan", zhTW: "深度掃描" },
  stageUnknown: { en: "Not retained by this run", zhTW: "本輪未保存" },
  requestedLimits: { en: "Limits used", zhTW: "使用的限制" },
  automaticReductions: { en: "Automatic reductions", zhTW: "自動縮減的範圍" },
  reductionLine: { en: "Requested {requested}; tested {executed}", zhTW: "原要求：{requested}；實際測試：{executed}" },
  observedWindow: { en: "Observed {from} to {until}", zhTW: "觀察時間：{from} 至 {until}" },
  savedAt: { en: "Saved {time}", zhTW: "保存時間：{time}" },
  currentFallback: { en: "Display name comes from the current project", zhTW: "顯示名稱來自目前專案資料" },
  unavailableProvenance: { en: "Historical detail unavailable", zhTW: "無法取得歷史細節" },
  coverageDetail: { en: "Coverage detail", zhTW: "涵蓋範圍細節" },
  exactNetworkScope: { en: "Exact addresses and ports", zhTW: "實際位址與連接埠" },
  networkScopeCount: { en: "{count} network scope groups", zhTW: "{count} 組網路範圍" },
  networkAddresses: { en: "Addresses", zhTW: "位址" },
  networkPorts: { en: "Ports", zhTW: "連接埠" },
  networkResult: { en: "Result", zhTW: "結果" },
  requestedScope: { en: "Requested scope", zhTW: "要求的範圍" },
  localConnectionCheck: { en: "Local connection check", zhTW: "本機連線檢查" },
  testedStatusComplete: { en: "Completed", zhTW: "完成" },
  testedStatusPartial: { en: "Partly completed", zhTW: "部分完成" },
  testedStatusFailed: { en: "Stopped with an error", zhTW: "因錯誤停止" },
  testedStatusTimeout: { en: "Timed out", zhTW: "逾時" },
  testedStatusCancelled: { en: "Cancelled", zhTW: "已取消" },
  testedStatusNotTested: { en: "Not tested", zhTW: "未測試" },
  testedStatusInProgress: { en: "In progress", zhTW: "進行中" },
  gapNotTested: {
    en: "This part was not tested because no compatible check completed.",
    zhTW: "這部分沒有相容的檢查完成，因此尚未測到。",
  },
  gapFailed: {
    en: "This part was not covered because its check stopped with an error.",
    zhTW: "負責這部分的檢查因錯誤停止，因此沒有涵蓋。",
  },
  gapTimedOut: {
    en: "The time limit was reached before this part completed.",
    zhTW: "這部分在完成前已到達時間限制。",
  },
  gapCancelled: { en: "This part stopped when the scan was cancelled.", zhTW: "掃描取消時，這部分也停止了。" },
  gapExcluded: { en: "This part was deliberately outside the requested scope.", zhTW: "這部分原本就不在要求的範圍內。" },
  gapTruncated: { en: "A saved limit reduced this part of the scan.", zhTW: "已保存的限制縮減了這部分掃描。" },
  gapUnavailable: {
    en: "The run did not retain enough detail to claim this part was tested.",
    zhTW: "本輪沒有保留足夠資料，不能宣稱這部分已測試。",
  },
  actionReviewFinding: { en: "Review the problem and its evidence.", zhTW: "檢視這個問題與相關證據。" },
  actionRetry: { en: "Retry this check; saved results will remain.", zhTW: "重試這項檢查；已保存的結果會保留。" },
  actionScope: { en: "Review the requested scope, then retry.", zhTW: "確認要求的範圍後再重試。" },
  actionCompatible: { en: "Choose an available check for this target.", zhTW: "為這個目標選擇可用的檢查。" },
  actionWait: { en: "Let it finish, or cancel and keep the partial report.", zhTW: "等待完成，或取消並保留部分報告。" },
  actionStartService: { en: "Start the expected local service, then retry.", zhTW: "先啟動預期的本機服務，再重試。" },
  actionReviewCoverage: { en: "Review the coverage gap before relying on the result.", zhTW: "採用結果前，先檢視涵蓋缺口。" },
  actionPreserve: { en: "Keep this limitation visible when sharing the report.", zhTW: "分享報告時，請保留這項限制。" },
  actionNoChange: { en: "No action is needed unless you change the scope.", zhTW: "除非要更改範圍，否則不需處理。" },
  frameworkNotice: {
    en: "NIST, ISO 27001, and AIDEFEND references are navigation aids—not certification, compliance, endorsement, or a pass/fail result.",
    zhTW: "NIST、ISO 27001 與 AIDEFEND 僅供對照，不代表認證、合規、背書或通過／不通過。",
  },
  reportTechnicalDetails: { en: "Technical details", zhTW: "技術細節" },
  taskStatus: { en: "Status", zhTW: "狀態" },
  taskProgress: { en: "Progress", zhTW: "進度" },
  taskEvidence: { en: "Evidence hashes", zhTW: "證據雜湊" },
  taskErrorCode: { en: "Diagnostic code", zhTW: "診斷代碼" },
  taskNoError: { en: "No diagnostic code", zhTW: "沒有診斷代碼" },
  dataWarnings: { en: "Saved-data limitations: {count}", zhTW: "已保存資料的限制：{count} 項" },
  genericExpert: { en: "Security or IT specialist", zhTW: "資安或 IT 專業人員" },
} as const;

const reportSummaryPresentation = (summary: BeginnerReportSummary) => {
  switch (summary) {
    case "complete": return { label: copy.reportComplete, tone: "positive" };
    case "partial": return { label: copy.reportPartial, tone: "warning" };
    case "no_checks_completed": return { label: copy.reportNoChecks, tone: "danger" };
  }
};

const reportStageCopy = (stage?: BeginnerReportStage) => {
  switch (stage) {
    case "quick_discovery": return copy.stageQuick;
    case "inventory": return copy.stageInventory;
    case "deep": return copy.stageDeep;
    default: return copy.stageUnknown;
  }
};

const testedStatusCopy = (status: BeginnerCoverageStatus) => {
  switch (status) {
    case "tested_complete": return copy.testedStatusComplete;
    case "tested_partial": return copy.testedStatusPartial;
    case "failed": return copy.testedStatusFailed;
    case "timed_out": return copy.testedStatusTimeout;
    case "cancelled": return copy.testedStatusCancelled;
    case "not_tested": return copy.testedStatusNotTested;
    case "in_progress": return copy.testedStatusInProgress;
  }
};

const gapReasonCopy = (kind: BeginnerCoverageGapKind) => {
  switch (kind) {
    case "not_tested": return copy.gapNotTested;
    case "failed": return copy.gapFailed;
    case "timed_out": return copy.gapTimedOut;
    case "cancelled": return copy.gapCancelled;
    case "excluded": return copy.gapExcluded;
    case "truncated": return copy.gapTruncated;
    case "unavailable": return copy.gapUnavailable;
  }
};

const nextActionCopy = (code: BeginnerNextActionCode) => {
  switch (code) {
    case "review_finding": return copy.actionReviewFinding;
    case "retry_check": return copy.actionRetry;
    case "review_scope_and_retry": return copy.actionScope;
    case "choose_compatible_check": return copy.actionCompatible;
    case "wait_or_cancel": return copy.actionWait;
    case "start_expected_service_and_retry": return copy.actionStartService;
    case "review_coverage": return copy.actionReviewCoverage;
    case "preserve_visible_limitation": return copy.actionPreserve;
    case "no_action_unless_scope_changes": return copy.actionNoChange;
  }
};

const localizedCheckName = (
  checkId: string,
  locale: "en" | "zh-TW",
  engine?: ScanRun["engineRuns"][number],
): string => {
  if (engine && isExactBuiltInLocalhostQuickScanEngine(engine) && engine.taskKind.kind === "built_in_localhost_tcp") {
    return `${locale === "en" ? "Local connection check" : "本機連線檢查"} · 127.0.0.1:${engine.taskKind.port}`;
  }
  return checkId;
};

const localizedAssetKind = (kind: string, locale: "en" | "zh-TW"): string => {
  if (locale === "en") return kind.replaceAll("_", " ");
  return ({
    web_service: "網站或本機服務",
    ip_address: "IP 位址",
    domain: "網域",
    repository: "程式碼儲存庫",
    iac_project: "基礎設施程式碼",
    container_image: "容器映像",
    kubernetes_cluster: "Kubernetes 叢集",
    cloud_account: "雲端帳號",
  } as Record<string, string>)[kind] ?? "掃描目標";
};

const localizedLimitName = (name: string, locale: "en" | "zh-TW"): string => {
  if (locale === "en") return name;
  if (name === "endpoint") return "連線端點";
  if (name === "connection timeout") return "連線逾時限制";
  if (name === "application payload") return "應用資料量";
  if (name.endsWith("approved ports")) return "允許檢查的連接埠";
  if (name.endsWith("request rate")) return "請求速率";
  if (name.endsWith("network timeout")) return "網路逾時限制";
  if (name.endsWith("authorized network target")) return "已確認的網路目標";
  if (name.endsWith("execution timeout")) return "檢查逾時限制";
  return "本輪使用的限制";
};

const localizedDimension = (dimension: string, locale: "en" | "zh-TW"): string => {
  if (locale === "en") return dimension;
  const normalized = dimension.toLocaleLowerCase("en");
  if (normalized.includes("tcp reachability")) return "TCP 連線狀態";
  if (normalized.includes("bounded connection contract")) return "受限的連線檢查";
  if (normalized.includes("completed check-to-target coordinate")) return "完成的目標檢查";
  if (normalized.includes("requested scan stage")) return "要求的掃描深度";
  if (normalized.includes("requested limits")) return "要求的掃描限制";
  if (normalized.includes("scope reduction") || normalized.includes("truncation")) return "自動縮減的範圍";
  if (normalized.includes("target label") || normalized.includes("target type")) return "目標的歷史顯示資料";
  if (normalized.includes("finding presentation")) return "本輪問題顯示資料";
  if (normalized.includes("request outcome")) return "掃描結果資料一致性";
  return "涵蓋範圍細節";
};

const localizedExpert = (expert: string, locale: "en" | "zh-TW"): string => {
  if (locale === "en") return expert;
  const normalized = expert.toLocaleLowerCase("en");
  if (normalized.includes("network")) return "網路管理人員";
  if (normalized.includes("developer") || normalized.includes("application")) return "軟體開發或應用安全人員";
  if (normalized.includes("cloud")) return "雲端管理人員";
  if (normalized.includes("it") || normalized.includes("system")) return "IT 或系統管理人員";
  if (normalized.includes("security")) return "資安專業人員";
  return "資安或 IT 專業人員";
};

const projectReportFindings = (
  report: BeginnerMasterReport,
  canonicalFindings: Finding[],
  locale: "en" | "zh-TW",
): Finding[] => {
  const canonicalById = new Map(canonicalFindings.map((finding) => [finding.id, finding]));
  const targetById = new Map(report.requested.targets.map((target) => [target.assetId, target]));
  return report.findings.map((frozen, index) => {
    const current = canonicalById.get(frozen.findingId);
    const currentEvidenceById = new Map(current?.evidence.map((evidence) => [evidence.id, evidence]));
    const evidence = frozen.evidenceReferences.map((reference) => {
      const retained = currentEvidenceById.get(reference.evidenceId);
      return {
        id: reference.evidenceId,
        sourceEngine: reference.engineId,
        observedAt: reference.observedAt,
        summary: retained?.summary ?? (locale === "en" ? "Run-bound evidence record" : "本輪保存的證據紀錄"),
        rawArtifactHash: reference.artifactSha256,
        kind: retained?.kind,
        runId: report.runId,
        engineRunId: retained?.engineRunId,
        artifactId: retained?.artifactId,
        redacted: retained?.redacted ?? true,
      };
    });
    const observedTimes = evidence.map((item) => item.observedAt).sort();
    const targetLabel = frozen.targetAssetIds
      .map((assetId) => targetById.get(assetId)?.label)
      .find((label): label is string => Boolean(label));
    return {
      id: frozen.findingId,
      caseId: report.caseId,
      fingerprint: frozen.fingerprint,
      assetId: frozen.targetAssetIds[0] ?? current?.assetId ?? "unknown-target",
      assetIds: [...frozen.targetAssetIds],
      assetName: targetLabel ?? current?.assetName ?? (locale === "en" ? "Recorded target" : "已記錄目標"),
      title: frozen.title,
      summary: frozen.plainLanguageRisk,
      impact: frozen.possibleImpact,
      recommendation: frozen.nextStep,
      expertType: localizedExpert(frozen.recommendedExpertType, locale),
      severity: frozen.severity,
      confidence: frozen.confidence,
      priority: frozen.priority ?? report.findings.length - index,
      priorityReasons: [...frozen.priorityReasons],
      // Workflow is intentionally current user state; scan facts above remain
      // the frozen selected-run projection.
      workflowState: current?.workflowState ?? "unreviewed",
      evidence,
      controls: frozen.frameworkReferences.map((reference) => ({
        framework: reference.framework,
        version: reference.frameworkVersion,
        controlId: reference.controlId,
        relationship: "related" as const,
        title: reference.title,
        rationale: reference.rationale,
        mappingVersion: reference.mappingVersion,
      })),
      officialReferences: [],
      verificationGuidance: current?.verificationGuidance,
      rollbackConsiderations: current?.rollbackConsiderations,
      tags: current?.tags,
      firstSeenRunId: report.runId,
      lastSeenRunId: report.runId,
      firstSeenAt: observedTimes[0] ?? report.state.lastDurableUpdate,
      lastSeenAt: observedTimes.at(-1) ?? report.state.lastDurableUpdate,
    };
  });
};

function BeginnerReportOverview({ report, run }: { report: BeginnerMasterReport; run?: ScanRun }) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
  const summary = reportSummaryPresentation(report.state.summary);
  const testedChecks = report.actual.checks.filter((check) =>
    check.status === "tested_complete"
    || check.status === "tested_partial"
    || check.testedDimensions.length > 0,
  );
  const testedNetworkScopes = report.actual.networkScopes.filter((scope) =>
    scope.outcome === "tested_complete" || scope.outcome === "tested_partial",
  );
  const untestedNetworkScopes = report.actual.networkScopes.filter((scope) =>
    scope.outcome !== "tested_complete" && scope.outcome !== "tested_partial",
  );
  const targetLabelById = new Map(
    report.requested.targets.map((target) => [target.assetId, target.label ?? target.assetId]),
  );
  const engineByTaskId = new Map(run?.engineRuns.map((engine) => [engine.id, engine]) ?? []);
  const countBreakdown = [
    [copy.testedComplete, report.coverageCounts.testedComplete],
    [copy.testedPartialCount, report.coverageCounts.testedPartial],
    [copy.failedCount, report.coverageCounts.failed],
    [copy.timedOutCount, report.coverageCounts.timedOut],
    [copy.cancelledCount, report.coverageCounts.cancelled],
    [copy.notTestedCount, report.coverageCounts.notTested],
    [copy.excludedCount, report.coverageCounts.excluded],
    [copy.truncatedCount, report.coverageCounts.truncated],
    [copy.unavailableCount, report.coverageCounts.unavailable],
  ] as const;

  return (
    <section className="section-block" aria-labelledby="beginner-master-report-title">
      <div className="section-heading section-heading--row">
        <div>
          <p className="eyebrow">{text(copy.masterEyebrow)}</p>
          <h2 id="beginner-master-report-title">{text(copy.masterTitle)}</h2>
          <p role="status" aria-live="polite" aria-atomic="true">
            {text(report.state.lifecycle === "live" ? copy.reportLive : copy.reportFinal)}
            {" · "}
            {text(copy.lastSaved, { time: formatDateTime(report.state.lastDurableUpdate) })}
          </p>
        </div>
        <StatusPill label={text(summary.label)} tone={summary.tone} />
      </div>

      <div className="metrics-grid metrics-grid--four" aria-label={text(copy.masterTitle)}>
        <MetricCard
          label={text(copy.requestedTargets)}
          value={formatNumber(report.requested.targets.length)}
          detail={text(reportStageCopy(report.requested.stage.value))}
          icon="coverage"
        />
        <MetricCard
          label={text(copy.testedComplete)}
          value={formatNumber(report.coverageCounts.testedComplete)}
          detail={report.coverageCounts.testedPartial > 0
            ? text(copy.testedStatusPartial)
            : text(copy.testedStatusComplete)}
          icon="check"
          tone={report.coverageCounts.testedComplete > 0 ? "accent" : "default"}
        />
        <MetricCard
          label={text(copy.coverageGaps)}
          value={formatNumber(report.coverageGaps.length)}
          detail={report.coverageGaps.length > 0 ? text(copy.gapsTitle) : text(copy.noGap)}
          icon="warning"
          tone={report.coverageGaps.length > 0 ? "warning" : "default"}
        />
        <MetricCard
          label={text(copy.reportFindings)}
          value={formatNumber(report.findings.length)}
          detail={text(copy.priorityDescription)}
          icon="findings"
          tone={report.findings.length > 0 ? "warning" : "default"}
        />
      </div>

      <div className="report-count-breakdown" aria-label={text(copy.coverageGaps)}>
        {countBreakdown.map(([label, count]) => (
          <span key={label.en}><strong>{formatNumber(count)}</strong> {text(label)}</span>
        ))}
      </div>

      <div className="coverage-grid">
        <article className="coverage-card">
          <h3>{text(copy.askedTitle)}</h3>
          {report.requested.targets.length > 0 ? (
            <ul className="detail-list">
              {report.requested.targets.map((target) => (
                <li key={target.assetId}>
                  <strong>{target.label ?? target.assetId}</strong>
                  {target.assetKind && <span>{localizedAssetKind(target.assetKind, locale)}</span>}
                  {target.labelAvailability === "current_case_fallback" && <small>{text(copy.currentFallback)}</small>}
                  {target.labelAvailability === "unavailable" && <small>{text(copy.unavailableProvenance)}</small>}
                </li>
              ))}
            </ul>
          ) : <p>{text(copy.noRequestedTarget)}</p>}
          <p><strong>{text(copy.stage)}:</strong> {text(reportStageCopy(report.requested.stage.value))}</p>
          {report.requested.limits.length > 0 && (
            <details>
              <summary>{text(copy.requestedLimits)}</summary>
              <ul className="detail-list">
                {report.requested.limits.map((limit, index) => (
                  <li key={`${limit.name}-${limit.value}-${index}`}><strong>{localizedLimitName(limit.name, locale)}</strong><span>{limit.value}</span></li>
                ))}
              </ul>
            </details>
          )}
          {report.requested.automaticReductions.length > 0 && (
            <div>
              <h4>{text(copy.automaticReductions)}</h4>
              <ul className="detail-list">
                {report.requested.automaticReductions.map((reduction, index) => (
                  <li key={`${reduction.dimension}-${index}`}>
                    <strong>{localizedDimension(reduction.dimension, locale)}</strong>
                    <span>{text(copy.reductionLine, {
                      requested: reduction.requested,
                      executed: reduction.executed,
                    })}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </article>

        <article className="coverage-card">
          <h3>{text(copy.testedTitle)}</h3>
          {report.actual.observedFrom && report.actual.observedUntil && (
            <p>{text(copy.observedWindow, {
              from: formatDateTime(report.actual.observedFrom),
              until: formatDateTime(report.actual.observedUntil),
            })}</p>
          )}
          {testedChecks.length > 0 ? (
            <ul className="detail-list">
              {testedChecks.map((check) => {
                const engine = engineByTaskId.get(check.taskId);
                return (
                <li key={check.taskId}>
                  <strong>{localizedCheckName(check.checkId, locale, engine)}</strong>
                  <span>{text(testedStatusCopy(check.status))}</span>
                  {check.testedDimensions.map((dimension, index) => (
                    <span key={`${dimension.dimension}-${dimension.value}-${index}`}>
                      {localizedDimension(dimension.dimension, locale)}: {localhostTestedDimensionValue(
                        engine,
                        dimension.dimension,
                        dimension.value,
                        locale,
                      )}
                      {dimension.observedAt && ` · ${text(copy.savedAt, { time: formatDateTime(dimension.observedAt) })}`}
                    </span>
                  ))}
                </li>
                );
              })}
            </ul>
          ) : <p>{text(copy.noTestedDimension)}</p>}
          {testedNetworkScopes.length > 0 && (
            <details open={testedNetworkScopes.length <= 8}>
              <summary>{text(copy.networkScopeCount, { count: formatNumber(testedNetworkScopes.length) })} · {text(copy.exactNetworkScope)}</summary>
              <ul className="detail-list">
                {testedNetworkScopes.map((scope) => (
                  <li key={`${scope.taskId}-${scope.workUnitId}`}>
                    <strong>{targetLabelById.get(scope.targetAssetId) ?? scope.target}</strong>
                    <span>{scope.target}</span>
                    <span>{text(copy.networkAddresses)}: {scope.addressRanges.join(locale === "en" ? ", " : "、")}</span>
                    <span>{text(copy.networkPorts)}: {scope.transport.toUpperCase()} {scope.portRanges.join(locale === "en" ? ", " : "、")}</span>
                    <span>{text(copy.stage)}: {text(reportStageCopy(scope.stage))}</span>
                    <span>{text(copy.networkResult)}: {text(testedStatusCopy(scope.outcome))}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </article>

        <article className="coverage-card">
          <h3>{text(copy.gapsTitle)}</h3>
          {report.coverageGaps.length > 0 ? (
            <ul className="detail-list">
              {report.coverageGaps.map((gap, index) => {
                const targets = gap.targetAssetIds
                  .map((assetId) => targetLabelById.get(assetId) ?? assetId)
                  .join(locale === "en" ? ", " : "、");
                return (
                  <li key={`${gap.taskId ?? "request"}-${gap.dimension}-${index}`}>
                    <strong>{targets || text(copy.requestedScope)}</strong>
                    <span>{localizedDimension(gap.dimension, locale)} · {text(gapReasonCopy(gap.kind))}</span>
                    <span>{text(nextActionCopy(gap.nextActionCode))}</span>
                  </li>
                );
              })}
            </ul>
          ) : <p>{text(copy.noGap)}</p>}
          {untestedNetworkScopes.length > 0 && (
            <details open={untestedNetworkScopes.length <= 8}>
              <summary>{text(copy.networkScopeCount, { count: formatNumber(untestedNetworkScopes.length) })} · {text(copy.exactNetworkScope)}</summary>
              <ul className="detail-list">
                {untestedNetworkScopes.map((scope) => (
                  <li key={`${scope.taskId}-${scope.workUnitId}`}>
                    <strong>{targetLabelById.get(scope.targetAssetId) ?? scope.target}</strong>
                    <span>{scope.target}</span>
                    <span>{text(copy.networkAddresses)}: {scope.addressRanges.join(locale === "en" ? ", " : "、")}</span>
                    <span>{text(copy.networkPorts)}: {scope.transport.toUpperCase()} {scope.portRanges.join(locale === "en" ? ", " : "、")}</span>
                    <span>{text(copy.stage)}: {text(reportStageCopy(scope.stage))}</span>
                    <span>{text(copy.networkResult)}: {text(testedStatusCopy(scope.outcome))}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </article>
      </div>

      <div className="section-heading">
        <h3>{text(copy.nextTitle)}</h3>
      </div>
      {report.nextSteps.length > 0 ? (
        <ol className="detail-list">
          {[...report.nextSteps]
            .sort((left, right) => left.priority - right.priority)
            .map((step, index) => (
              <li key={`${step.code}-${step.findingId ?? step.taskId ?? index}`}>
                <strong>{text(nextActionCopy(step.code))}</strong>
                {step.recommendedExpertType && <span>{localizedExpert(step.recommendedExpertType, locale)}</span>}
              </li>
            ))}
        </ol>
      ) : <p>{text(copy.noNextStep)}</p>}

      <details className="page-technical-details">
        <summary>{text(copy.reportTechnicalDetails)}</summary>
        {report.dataQualityWarnings.length > 0 && (
          <InlineNotice tone="warning" title={text(copy.dataWarnings, { count: formatNumber(report.dataQualityWarnings.length) })}>
            <p>{text(copy.gapUnavailable)}</p>
          </InlineNotice>
        )}
        <div className="evidence-list">
          {report.technicalDetails.tasks.map((task) => {
            const check = report.actual.checks.find((item) => item.taskId === task.taskId);
            const engine = engineByTaskId.get(task.taskId);
            return (
              <article key={task.taskId} className="evidence-item">
                <div>
                  <strong>{check ? localizedCheckName(check.checkId, locale, engine) : text(copy.coverageDetail)}</strong>
                  <span>{engineStatusMeta[task.status].label}</span>
                </div>
                <dl>
                  <div><dt>{text(copy.taskProgress)}</dt><dd>{formatNumber(task.progressPercent)}%</dd></div>
                  <div><dt>{text(copy.taskStatus)}</dt><dd>{engineStatusMeta[task.status].label}</dd></div>
                  <div><dt>{text(copy.taskErrorCode)}</dt><dd><code>{task.errorCode ?? text(copy.taskNoError)}</code></dd></div>
                  <div><dt>{text(copy.taskEvidence)}</dt><dd>{formatNumber(task.evidenceSha256.length)}</dd></div>
                  {task.startedAt && <div><dt>{text(copy.firstObserved)}</dt><dd>{formatDateTime(task.startedAt)}</dd></div>}
                  {task.finishedAt && <div><dt>{text(copy.lastObserved)}</dt><dd>{formatDateTime(task.finishedAt)}</dd></div>}
                </dl>
              </article>
            );
          })}
        </div>
      </details>

      <InlineNotice tone="info" title={text(copy.notCompliance)}>
        <p>{text(copy.frameworkNotice)}</p>
      </InlineNotice>
    </section>
  );
}

const workflowTone = (state: FindingWorkflowState): string => {
  if (state === "verified_resolved" || state === "confirmed") return "positive";
  if (state === "false_positive") return "neutral";
  if (state === "remediated_pending_verification" || state === "remediation_reported") return "info";
  return "warning";
};

export function FindingsPage({
  report,
  selectedRunId,
  reportUnavailable,
  findings: canonicalFindings,
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
  onOpenExport,
  onSelectRun,
}: FindingsPageProps) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
  const findings = useMemo(
    () => report
      ? projectReportFindings(report, canonicalFindings, locale)
      : reportUnavailable
        ? []
        : canonicalFindings,
    [canonicalFindings, locale, report, reportUnavailable],
  );
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

  const explicitlySelectedRun = selectedRunId === undefined
    ? undefined
    : runs.find((run) => run.id === selectedRunId);
  const latestRun = selectedRunId === undefined
    ? (report ? runs.find((run) => run.id === report.runId) : undefined) ?? runs[0]
    : explicitlySelectedRun;
  const activeRun = latestRun && activeRunStatuses.has(latestRun.status) ? latestRun : undefined;
  const incompleteTerminalRun = latestRun
    && !activeRun
    && latestRun.status !== "completed"
    ? latestRun
    : undefined;
  const latestRequestOutcomeSummary = scanRequestOutcomeBeginnerSummary(latestRun?.requestOutcome);
  const reportRunPicker = runs.length > 1 || (runs.length > 0 && !latestRun) ? (
    <label className="select-filter">
      <span>{text(copy.reportRun)}</span>
      <select value={latestRun?.id ?? ""} onChange={(event) => onSelectRun?.(event.target.value)}>
        {!latestRun && <option value="" disabled>{text(copy.reportRunUnavailable)}</option>}
        {runs.map((run) => (
          <option key={run.id} value={run.id}>{scanRunIdentityPresentation(run, locale)}</option>
        ))}
      </select>
    </label>
  ) : undefined;
  const reportActions = (
    <div className="button-group">
      {reportRunPicker}
      {latestRun && (
        <button className="button button--primary button--small" type="button" onClick={() => onOpenExport(latestRun.id)}>
          <Icon name="export" size={16} />{text(copy.openExport)}
        </button>
      )}
    </div>
  );

  if (findings.length === 0) {
    const unknownSources = coverage.filter((item) => item.state === "source_unavailable_unknown").length;
    const connectedWithoutAssets = coverage.filter((item) => item.state === "source_connected_none").length;
    const latestRunIsActive = Boolean(latestRun && activeRunStatuses.has(latestRun.status));
    const incompleteRun = latestRun && !latestRunIsActive && latestRun.status !== "completed";
    const localhostSummary = latestRun?.engineRuns
      .map((engine) => localhostTcpBeginnerSummary(engine))
      .find((summary) => summary !== undefined);
    const requestOutcomeSummary = latestRequestOutcomeSummary;
    const title = !latestRun
      ? text(copy.emptyNoRunTitle)
      : requestOutcomeSummary
        ? text(requestOutcomeSummary.title)
        : localhostSummary
          ? text(localhostSummary.title)
          : latestRunIsActive
            ? text(copy.emptyActiveTitle)
            : incompleteRun
              ? text(copy.emptyIncompleteTitle)
              : unknownSources > 0
                ? text(copy.emptyUnknownTitle)
                : text(copy.emptyCompletedTitle);
    const description = !latestRun
      ? text(copy.emptyNoRunDescription)
      : requestOutcomeSummary
        ? [text(requestOutcomeSummary.description), text(requestOutcomeSummary.nextStep)].join(" ")
        : localhostSummary
          ? [
              text(localhostSummary.description),
              text(localhostSummary.exclusions),
              text(localhostSummary.nextStep),
            ].join(" ")
          : latestRunIsActive
            ? text(copy.emptyActiveDescription)
            : incompleteRun
              ? text(copy.emptyIncompleteDescription)
              : unknownSources > 0
                ? text(copy.emptyUnknownDescription, { count: formatNumber(unknownSources) })
                : text(copy.emptyCompletedDescription, { count: formatNumber(connectedWithoutAssets) });
    return (
      <div className="page">
        <PageHeader eyebrow={text(copy.eyebrow)} title={text(copy.emptyHeaderTitle)} description={text(copy.emptyHeaderDescription)} actions={reportActions} />
        {report && <BeginnerReportOverview report={report} run={latestRun} />}
        {reportUnavailable && <InlineNotice tone="warning" title={text(unavailableRunBoundReportCopy.title)}><p>{text(unavailableRunBoundReportCopy.body)}</p></InlineNotice>}
        <EmptyState
          icon={latestRunIsActive
            || incompleteRun
            || unknownSources > 0
            || Boolean(requestOutcomeSummary)
            || ["closed", "timed_out", "failed", "cancelled", "missing", "inconsistent"]
              .includes(localhostSummary?.outcome ?? "")
            ? "warning"
            : "findings"}
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
        actions={reportActions}
      />

      {report && <BeginnerReportOverview report={report} run={latestRun} />}
      {reportUnavailable && <InlineNotice tone="warning" title={text(unavailableRunBoundReportCopy.title)}><p>{text(unavailableRunBoundReportCopy.body)}</p></InlineNotice>}

      {activeRun && (
        <InlineNotice tone="warning" title={text(copy.activeTitle)}>
          <p>{text(copy.activeDescription)}</p>
          <button className="button button--secondary button--small" type="button" onClick={onOpenProgress}>
            <Icon name="progress" size={15} /> {text(copy.openProgress)}
          </button>
        </InlineNotice>
      )}

      {latestRequestOutcomeSummary && (
        <InlineNotice tone="warning" title={text(latestRequestOutcomeSummary.title)}>
          <p>{[text(latestRequestOutcomeSummary.description), text(latestRequestOutcomeSummary.nextStep)].join(" ")}</p>
          <button className="button button--secondary button--small" type="button" onClick={onOpenProgress}>
            <Icon name="progress" size={15} /> {text(copy.openProgress)}
          </button>
        </InlineNotice>
      )}

      {incompleteTerminalRun && !latestRequestOutcomeSummary && (
        <InlineNotice tone="warning" title={text(copy.incompleteTitle)}>
          <p>{text(copy.incompleteDescription)}</p>
          <button className="button button--secondary button--small" type="button" onClick={onOpenProgress}>
            <Icon name="progress" size={15} /> {text(copy.openProgress)}
          </button>
        </InlineNotice>
      )}

      <section className="metrics-grid metrics-grid--four" aria-label={text(copy.summaryAria)}>
        <MetricCard label={text(copy.critical)} value={criticalCount} detail={text(copy.criticalDetail)} icon="warning" tone={criticalCount ? "danger" : "default"} />
        <MetricCard label={text(copy.high)} value={highCount} detail={text(copy.highDetail)} icon="findings" tone={highCount ? "warning" : "default"} />
        <MetricCard label={text(copy.needsReview)} value={needsReview} detail={text(copy.needsReviewDetail)} icon="search" />
        <MetricCard label={text(copy.affectedAssets)} value={affectedAssets} detail={text(copy.completeListCount, { count: formatNumber(findings.length) })} icon="database" />
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

      <details className="section-block page-secondary-feature">
        <summary id="finding-groups-title">{text(copy.groupsTitle)}</summary>
        <p className="page-secondary-feature__intro">{text(copy.groupsDescription)}</p>

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
      </details>

      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(copy.howToRead)}</summary>
        <strong>{text(copy.boundaryTitle)}</strong>
        <p>{text(copy.boundaryBody)}</p>
      </details>

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
