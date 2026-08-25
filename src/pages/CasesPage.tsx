import { Fragment, useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import {
  buildKnownAssets,
  prepareDeployedWebsiteTarget,
  type CaseAssetDraftError,
  type WebsiteInputError,
} from "../caseForm";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import { useI18n, type BilingualText, type StaticTranslationKey } from "../i18n";
import { phaseMeta, runStatusMeta } from "../lib";
import type {
  AssessmentActivity,
  AssessmentCase,
  CaseArtifactCleanupResult,
  CaseArtifactDeletionPlan,
  CloudPlatform,
  CompanySize,
  CreateCaseInput,
  DataClass,
  ScanRun,
} from "../types";
import {
  startPageCopy,
  useCaseById,
  type UseCaseDefinition,
  type UseCaseId,
} from "../useCases";

import "../cases-page.css";

export interface CasesPageProps {
  cases: AssessmentCase[];
  selectedCase?: AssessmentCase;
  selectedUseCase?: UseCaseId;
  selectionKey?: string | number;
  assetCount: number;
  findingCount: number;
  unknownSourceCount: number;
  connectedNoAssetSourceCount: number;
  latestRun?: ScanRun;
  runs: ScanRun[];
  verificationBaselineRunId?: string;
  artifactCleanupPlan?: CaseArtifactDeletionPlan;
  artifactCleanupResult?: CaseArtifactCleanupResult;
  busy?: boolean;
  onClearPreset?: () => void;
  onCreate: (input: CreateCaseInput) => Promise<boolean>;
  onArchive: (caseId: string) => Promise<void>;
  onDelete: (caseId: string, confirmation: string) => Promise<boolean>;
  onDeleteArtifacts: (confirmation: string) => Promise<boolean>;
  onDismissArtifactCleanup: () => void;
  onSelect: (caseId: string) => void;
  onContinue: () => void;
  onOpenProgress: () => void;
  onSelectVerificationBaseline: (runId: string) => void;
  onStartRescan: (baselineRunId: string) => Promise<void>;
  onOpenVerification: () => void;
}

const pageCopy = {
  headerEyebrow: { en: "Security assessment cases", zhTW: "資安健檢案件" },
  headerTitle: { en: "Keep every check in one repeatable case", zhTW: "把每次檢查留在可複驗的案件裡" },
  headerDescription: {
    en: "A case keeps targets, permission boundaries, original evidence, and before-and-after results together. It is more than a report you read once and discard.",
    zhTW: "案件會把目標、授權範圍、原始證據與修復前後結果放在一起；它不是看完一次就丟掉的報告。",
  },
  create: { en: "Create a case", zhTW: "建立案件" },
  closeForm: { en: "Close form", zhTW: "關閉表單" },
  newCaseEyebrow: { en: "New case", zhTW: "新案件" },
  newCaseTitle: { en: "Tell us what this check is for", zhTW: "先說這次要檢查什麼" },
  newCaseDescription: {
    en: "The product will choose appropriate tools later. These answers prepare the case; they are not audit evidence and do not authorize a scan.",
    zhTW: "產品稍後會安排適合的工具。這些答案只是準備案件，不是稽核證據，也不會授權掃描。",
  },
  changeUseCase: { en: "Choose a different goal", zhTW: "改選其他檢查目標" },
  caseName: { en: "Case name", zhTW: "案件名稱" },
  caseNamePlaceholder: { en: "Example: 2026 first security check", zhTW: "例如：2026 年首次安全健檢" },
  organizationName: { en: "Company or team name", zhTW: "公司或團隊名稱" },
  organizationPlaceholder: { en: "Who owns the systems being checked?", zhTW: "這些系統屬於哪個公司或團隊？" },
  selectedGoal: { en: "Selected goal", zhTW: "目前選擇" },
  targetCandidateHelp: {
    en: "Anything entered here becomes an unconfirmed candidate only. It does not prove ownership, connect to a system, or start a scan.",
    zhTW: "這裡輸入的內容只會成為「待確認候選」；不會證明所有權、不會連線，也不會開始掃描。",
  },
  websiteUrl: { en: "Website or API URL", zhTW: "網站或 API 網址" },
  websitePlaceholder: { en: "https://portal.example.com/login", zhTW: "https://portal.example.com/login" },
  websiteHelp: {
    en: "Enter one complete http:// or https:// URL. Do not include a username or password.",
    zhTW: "請輸入一個完整的 http:// 或 https:// 網址；不要放入帳號或密碼。",
  },
  websitePreparedTitle: { en: "What will be saved now", zhTW: "現在會先保存什麼" },
  websitePrepared: {
    en: "The case will save {target} as an unconfirmed candidate. {protocol} port {port} and path {path} are shown for context only; you must confirm the exact service, ownership, limits, and permission before any scanner contacts it.",
    zhTW: "案件現在只會把 {target} 保存成待確認候選。{protocol} 連接埠 {port} 與路徑 {path} 目前只是提示；任何掃描器連線前，你仍要確認精確服務、所有權、限制與許可。",
  },
  websiteQueryRemoved: {
    en: "Query parameters and page fragments are not saved because they can contain private tokens or personal data.",
    zhTW: "網址參數與頁面片段不會保存，因為其中可能含有私人權杖或個人資料。",
  },
  publicTargets: { en: "Public domains, IP addresses, or small CIDR ranges", zhTW: "公開網域、IP 或小型 CIDR 網段" },
  publicTargetsPlaceholder: { en: "example.com\n203.0.113.10\n203.0.113.0/28", zhTW: "example.com\n203.0.113.10\n203.0.113.0/28" },
  publicTargetsHelp: {
    en: "One exact target per line. Wildcards are not accepted. Each target still needs ownership and permission confirmation.",
    zhTW: "每行一個精確目標，不接受萬用字元；每一項之後仍要確認所有權與掃描許可。",
  },
  internalTargets: { en: "Internal IP addresses or small CIDR ranges", zhTW: "內部 IP 或小型 CIDR 網段" },
  internalTargetsPlaceholder: { en: "10.20.0.8\n10.20.1.0/28", zhTW: "10.20.0.8\n10.20.1.0/28" },
  internalTargetsHelp: {
    en: "One approved target per line. Private addresses remain blocked until you create an explicit internal-network grant later.",
    zhTW: "每行一個已核准目標。私有位址仍會被阻擋，直到你稍後建立明確的內部網路授權。",
  },
  repositories: { en: "Source project or repository", zhTW: "程式碼專案或儲存庫" },
  repositoriesPlaceholder: { en: "Local project name or read-only repository coordinate", zhTW: "本機專案名稱或唯讀程式碼儲存庫位置" },
  repositoriesHelp: {
    en: "One per line. You will attach an exact read-only working-tree snapshot before scanning.",
    zhTW: "每行一項；掃描前仍會請你附加精確、唯讀的工作目錄快照。",
  },
  iacProjects: { en: "Infrastructure-code project", zhTW: "基礎設施程式碼專案" },
  iacPlaceholder: { en: "infra/production\nterraform/prod", zhTW: "infra/production\nterraform/prod" },
  iacHelp: {
    en: "Terraform, CloudFormation, Kubernetes YAML, or another deployment-definition project. One coordinate per line.",
    zhTW: "可填 Terraform、CloudFormation、Kubernetes YAML 或其他部署定義專案；每行一項。",
  },
  containerImages: { en: "Exact container image digest", zhTW: "精確的容器映像內容摘要" },
  containerPlaceholder: { en: "registry.example/app@sha256:…", zhTW: "registry.example/app@sha256:…" },
  containerHelp: {
    en: "For a repeatable result, use repository@sha256 followed by 64 lowercase hexadecimal characters.",
    zhTW: "為了讓結果可重現，請使用「映像儲存庫@sha256:」加上 64 個小寫十六進位字元。",
  },
  kubernetes: { en: "Kubernetes cluster or snapshot name", zhTW: "Kubernetes 叢集或快照名稱" },
  kubernetesPlaceholder: { en: "production-eks\nstaging-gke", zhTW: "production-eks\nstaging-gke" },
  kubernetesHelp: {
    en: "This name creates a candidate only. You will later choose a read-only, immutable manifest or node-configuration snapshot.",
    zhTW: "名稱只會建立候選；之後仍要選擇唯讀、不可變的設定檔或節點設定快照。",
  },
  cloudChoice: { en: "Which cloud services do you use?", zhTW: "你使用哪些雲端服務？" },
  cloudChoiceHelp: {
    en: "Keep the ones relevant to this case. After case creation, the product will guide you through the provider's official read-only sign-in—do not paste an administrator password here.",
    zhTW: "只保留這次相關的項目。建立案件後，產品會帶你走雲端服務商的官方唯讀登入流程；不要在這裡貼管理員密碼。",
  },
  moreSummary: { en: "More case details", zhTW: "更多案件資料" },
  moreSummaryHint: {
    en: "Company size, data types, other systems, and optional scan activities",
    zhTW: "公司規模、資料類型、其他系統與可選檢查活動",
  },
  organizationSize: { en: "Organization size", zhTW: "組織規模" },
  notes: { en: "Notes (optional)", zhTW: "備註（選填）" },
  notesPlaceholder: { en: "What question should this case answer first?", zhTW: "這次最想先釐清什麼？" },
  otherSystems: { en: "Other systems to include", zhTW: "這次還要納入哪些系統" },
  otherSystemsHelp: {
    en: "Adding a system keeps the full product scope available. It still does not authorize a scan.",
    zhTW: "加入其他系統可保留完整產品範圍，但仍不會授權掃描。",
  },
  additionalCoordinates: { en: "Other known targets (optional)", zhTW: "其他已知目標（選填）" },
  activities: { en: "What kinds of checks may be needed?", zhTW: "這次可能需要哪些檢查？" },
  activitiesHelp: {
    en: "Select at least one. This records intent only; it does not create a permission grant or start a tool.",
    zhTW: "至少選一項。這只記錄案件意向，不會建立授權，也不會啟動工具。",
  },
  activeWarningTitle: { en: "Active testing is not authorized yet", zhTW: "選擇主動測試不等於已授權" },
  activeWarning: {
    en: "Before active testing, you must separately confirm ownership, exact targets and ports, rate and time limits, and a traceable written authorization reference.",
    zhTW: "開始主動測試前，仍須另外確認所有權、精確目標與連接埠、速度與時間限制，以及可追溯的書面授權。",
  },
  dataTypes: { en: "Data this case may involve", zhTW: "這個案件可能涉及哪些資料" },
  dataTypesHelp: {
    en: "This adjusts explanations and priority context. It is not a legal or regulatory decision.",
    zhTW: "這只用來調整說明與優先順序，不是法律或法規判定。",
  },
  createSafety: { en: "Creating a case does not connect to a cloud service or start a scan.", zhTW: "建立案件不會連接雲端，也不會開始掃描。" },
  creating: { en: "Creating…", zhTW: "建立中…" },
  createLocal: { en: "Create local case", zhTW: "建立本機案件" },
  formConflictTitle: { en: "The same target has two different descriptions", zhTW: "同一目標被標成兩種不同環境" },
  formConflict: {
    en: "{target} appears in both public and internal target lists. Keep it in the one list that describes where it is reached.",
    zhTW: "{target} 同時出現在公開與內部目標清單。請只保留在真正符合連線位置的那一邊。",
  },
  demo: { en: "Demo", zhTW: "展示" },
  latestRun: { en: "Latest run: {status}", zhTW: "最新一輪：{status}" },
  updated: { en: "Updated {date}", zhTW: "更新於 {date}" },
  caseSystems: { en: "Systems in this case", zhTW: "案件環境" },
  caseIntent: { en: "Requested check types", zhTW: "案件檢查意向" },
  handleInterrupted: { en: "Handle interrupted work", zhTW: "處理重啟後中斷" },
  viewCoverage: { en: "Review targets and coverage", zhTW: "查看目標與涵蓋" },
  verificationEyebrow: { en: "Check fixes", zhTW: "確認修復" },
  verificationTitle: { en: "Choose the earlier run to compare", zhTW: "選擇要比較的先前掃描" },
  verificationDescription: {
    en: "Only a run with a clear final state can be used. The chosen baseline is saved with the new run so the comparison can resume safely.",
    zhTW: "只有已明確結束的掃描可當作比較基準；選定後會與新掃描一起保存，讓比較可以安全續跑。",
  },
  viewDifference: { en: "View differences", zhTW: "查看差異" },
  baseline: { en: "Completed baseline run", zhTW: "已結束的基準掃描" },
  baselineSelected: { en: "The new comparison will use run {id}.", zhTW: "新比較將使用掃描 {id}。" },
  baselineChoose: { en: "Choose a completed run.", zhTW: "請選擇一個已結束的掃描。" },
  activeRun: { en: "{label} is still active. Resume or cancel it first.", zhTW: "{label} 尚未結束，請先續跑或取消。" },
  verificationOutcome: {
    en: "When the new scan finishes, the case will show resolved, still present, new, and unverifiable results.",
    zhTW: "新掃描完成後，案件會列出已解決、仍存在、新增與無法確認的結果。",
  },
  handleActiveFirst: { en: "Handle the active run first", zhTW: "先處理未結束的掃描" },
  startVerification: { en: "Start a new check from this baseline", zhTW: "以這次結果開始複驗" },
  unknownZeroTitle: { en: "0 candidates are shown, but visibility is still unknown", zhTW: "目前顯示 0 個候選資產，但視野仍是未知" },
  unknownZero: {
    en: "This only means no usable source has produced a candidate list yet. It does not mean the organization has no assets. Connect a source and check again.",
    zhTW: "這只代表目前沒有可用來源建立候選清單，不表示組織沒有資產。請先連接資料來源再重新盤點。",
  },
  connectedZeroTitle: { en: "A connected source reported no candidates this time", zhTW: "資料來源已連接，而且這次確實沒有候選資產" },
  connectedZero: {
    en: "This is different from unknown visibility. The statement applies only to the connected snapshot, confirmed boundary, and observation time.",
    zhTW: "這與來源未知不同；結論只適用於已連接快照、已確認範圍與當時的觀察時間。",
  },
  interruptedTitle: { en: "{count} scanner jobs paused when the desktop restarted", zhTW: "桌面程式重啟時，有 {count} 個掃描工作暫停" },
  interrupted: {
    en: "Run {id} kept a safe restart point. Open Scan progress to explicitly resume or cancel it; the app will not reconnect automatically.",
    zhTW: "掃描 {id} 已保留安全續跑點。請到「掃描進度」明確續跑或取消；應用程式不會自動重新連線。",
  },
  cleanupEyebrow: { en: "Separate step: local evidence cleanup", zhTW: "獨立步驟：清理本機證據" },
  cleanupRemovedTitle: { en: "Case evidence was permanently removed", zhTW: "案件證據已永久移除" },
  cleanupRetainedTitle: { en: "The case record was deleted; evidence is still retained", zhTW: "案件紀錄已刪除；證據仍完整保留" },
  cleanupAbsentTitle: { en: "The case evidence folder is already absent", zhTW: "案件證據目錄已不存在" },
  cleanupRemoved: {
    en: "This cannot be undone. The database record and local evidence were handled as two separate, explicit actions.",
    zhTW: "這項刪除無法復原。案件資料庫紀錄與本機證據已分成兩個明確動作處理。",
  },
  cleanupRetained: {
    en: "Keeping evidence does not undo deletion of the case record. Evidence is removed only after you type the complete phrase below and confirm the exact path.",
    zhTW: "保留證據不會恢復案件紀錄。只有輸入下方完整片語並確認精確路徑後，才會另外刪除證據。",
  },
  cleanupAbsent: {
    en: "The backend confirmed that this exact case folder does not exist, so no evidence-deletion command is needed or sent.",
    zhTW: "後端確認這個精確案件目錄不存在，因此不需要、也不會送出證據刪除命令。",
  },
  cleanupType: { en: "Type `DELETE {id}`", zhTW: "輸入 `DELETE {id}`" },
  keepEvidence: { en: "Keep evidence", zhTW: "保留證據" },
  deletingEvidence: { en: "Permanently deleting…", zhTW: "永久刪除中…" },
  deleteEvidence: { en: "Permanently delete evidence", zhTW: "永久刪除證據" },
  understood: { en: "Done", zhTW: "知道了" },
  summaryAria: { en: "Current case summary", zhTW: "目前案件摘要" },
  assetsMetric: { en: "Assets found", zhTW: "已發現資產" },
  assetsMetricHelp: { en: "Counts only candidates backed by a source", zhTW: "只計入目前有資料來源的候選資產" },
  findingsMetric: { en: "Complete problem list", zhTW: "完整問題清單" },
  findingsMetricHelp: { en: "Priority views never hide the other results", zhTW: "優先排序不會隱藏其他結果" },
  unknownMetric: { en: "Unknown data sources", zhTW: "未知資料來源" },
  unknownMetricHelp: { en: "Unknown never means no assets or passed", zhTW: "未知不等於沒有資產或已通過" },
  incompleteMetric: { en: "Incomplete scanner jobs", zhTW: "未完成的掃描工作" },
  incompleteMetricHelp: { en: "{count} connected sources reported no assets", zhTW: "{count} 個已連接來源沒有發現資產" },
  allCasesEyebrow: { en: "All cases", zhTW: "所有案件" },
  allCasesTitle: { en: "Cases stored on this device", zhTW: "保存在這台電腦的案件" },
  caseCount: { en: "{count} cases", zhTW: "{count} 個案件" },
  noCases: { en: "No cases yet", zhTW: "尚未建立案件" },
  noCasesHelp: {
    en: "Create the first case to keep its targets, scan evidence, handoff, and later verification in one lifecycle.",
    zhTW: "建立第一個案件後，目標、掃描證據、交接與後續複驗都會保存在同一條生命週期。",
  },
  assetFindingCount: { en: "{assets} assets · {findings} findings", zhTW: "{assets} 個資產 · {findings} 個問題" },
  archiveAria: { en: "Archive {name}", zhTW: "封存 {name}" },
  archiveTitle: { en: "Archive case", zhTW: "封存案件" },
  beginDeleteAria: { en: "Begin deleting {name}", zhTW: "開始刪除 {name}" },
  deleteRecordTitle: { en: "Delete case database record", zhTW: "刪除案件資料庫紀錄" },
  selectAria: { en: "Select {name}", zhTW: "選擇 {name}" },
  deleteStep: { en: "Step 2 of 2", zhTW: "第 2 步／2" },
  confirmDeleteTitle: { en: "Confirm deletion of the case record", zhTW: "確認刪除案件資料庫紀錄" },
  confirmDeleteHelp: {
    en: "This removes the database record from the case list but does not automatically delete the evidence folder. Evidence cleanup is a separate confirmation that shows the exact path.",
    zhTW: "這會從清單移除案件資料庫紀錄，但不會自動刪除證據目錄。證據清理會另外顯示精確路徑並要求確認。",
  },
  typeCaseName: { en: "Type the full case name: {name}", zhTW: "輸入完整案件名稱「{name}」" },
  cancel: { en: "Cancel", zhTW: "取消" },
  deleting: { en: "Deleting…", zhTW: "刪除中…" },
  deleteRecordOnly: { en: "Delete case record only", zhTW: "只刪除案件紀錄" },
  workflowAria: { en: "Complete case workflow", zhTW: "完整案件流程" },
} as const;

const platformIds = ["aws", "azure", "gcp", "m365", "external", "code", "container", "kubernetes"] as const satisfies readonly CloudPlatform[];
const cloudPlatformIds = ["aws", "azure", "gcp", "m365"] as const satisfies readonly CloudPlatform[];

const platformKeys: Record<CloudPlatform, StaticTranslationKey> = {
  aws: "platform.aws",
  azure: "platform.azure",
  gcp: "platform.gcp",
  m365: "platform.m365",
  external: "platform.external",
  code: "platform.code",
  container: "platform.container",
  kubernetes: "platform.kubernetes",
};

const platformAbbreviations: Record<CloudPlatform, string> = {
  aws: "AWS",
  azure: "AZ",
  gcp: "GCP",
  m365: "365",
  external: "WEB",
  code: "CODE",
  container: "IMG",
  kubernetes: "K8S",
};

const phaseKeys: Record<AssessmentCase["phase"], StaticTranslationKey> = {
  draft: "status.case.draft",
  discovering: "status.case.discovering",
  scope_review: "status.case.scopeReview",
  ready: "status.case.ready",
  scanning: "status.case.scanning",
  needs_attention: "status.case.needsAttention",
  ready_for_handoff: "status.case.readyForHandoff",
  verifying: "status.case.verifying",
  archived: "status.case.archived",
  complete: "status.case.complete",
  verification_due: "status.case.verificationDue",
};

const runStatusKeys: Record<ScanRun["status"], StaticTranslationKey> = {
  queued: "status.run.queued",
  running: "status.run.running",
  paused: "status.run.paused",
  completed: "status.run.completed",
  partial: "status.run.partial",
  failed: "status.run.failed",
  cancelled: "status.run.cancelled",
};

const companySizeCopy: Record<CompanySize, BilingualText> = {
  solo: { en: "Just me", zhTW: "個人／1 人" },
  small: { en: "2–49 people", zhTW: "小型／2–49 人" },
  medium: { en: "50–249 people", zhTW: "中型／50–249 人" },
  large: { en: "250 or more people", zhTW: "大型／250 人以上" },
};

const dataClassCopy: Record<DataClass, BilingualText> = {
  pii: { en: "Personal information", zhTW: "個人資料" },
  phi: { en: "Health information", zhTW: "健康資料" },
  payment: { en: "Payment or card information", zhTW: "付款或卡片資料" },
  credentials: { en: "Passwords, keys, or other secrets", zhTW: "帳密、金鑰或其他秘密" },
  none: { en: "None of these, or not sure", zhTW: "以上皆無或不確定" },
};

const activityCopy: Record<AssessmentActivity, { label: BilingualText; detail: BilingualText }> = {
  configuration_assessment: {
    label: { en: "Review cloud and system settings", zhTW: "檢查雲端與系統設定" },
    detail: { en: "Read-only review of cloud, Microsoft 365, Kubernetes, and infrastructure settings", zhTW: "以唯讀方式檢查雲端、Microsoft 365、Kubernetes 與基礎設施設定" },
  },
  local_artifact_analysis: {
    label: { en: "Review files on this device", zhTW: "檢查這台電腦上的檔案" },
    detail: { en: "Analyze only the source, infrastructure code, image, or snapshot you explicitly attach", zhTW: "只分析你明確附加的程式碼、基礎設施程式碼、映像或設定快照" },
  },
  low_impact_external_checks: {
    label: { en: "Low-impact network checks", zhTW: "低影響網路檢查" },
    detail: { en: "Make limited connections only to targets you authorize later", zhTW: "只對你稍後逐項授權的目標發出有限連線" },
  },
  active_external_vulnerability_tests: {
    label: { en: "Active vulnerability tests", zhTW: "主動弱點測試" },
    detail: { en: "Requires separate written authorization, exact targets, ports, and strict rate limits", zhTW: "需要另外提供書面授權、精確目標、連接埠與嚴格限速" },
  },
};

const websiteErrorCopy: Record<WebsiteInputError, BilingualText> = {
  empty: { en: "Enter the website or API URL.", zhTW: "請輸入網站或 API 網址。" },
  too_long: { en: "This URL is too long. Enter one exact URL of at most 2,048 characters.", zhTW: "這個網址太長；請輸入一個不超過 2,048 個字元的精確網址。" },
  invalid_url: { en: "Enter a complete URL beginning with http:// or https://.", zhTW: "請輸入以 http:// 或 https:// 開頭的完整網址。" },
  unsupported_protocol: { en: "Only http:// and https:// website addresses are accepted here.", zhTW: "這裡只接受 http:// 與 https:// 網站位址。" },
  userinfo_not_allowed: { en: "Remove the username or password from the URL. The case never needs it.", zhTW: "請移除網址中的帳號或密碼；案件不需要這些資料。" },
  hostname_missing: { en: "The URL does not contain a website hostname.", zhTW: "這個網址沒有可辨識的網站主機名稱。" },
};

const workflowCopy = [
  { step: "01", title: { en: "Find", zhTW: "盤點" }, detail: { en: "Build a candidate list from real sources", zhTW: "從真實來源建立候選清單" } },
  { step: "02", title: { en: "Authorize", zhTW: "授權" }, detail: { en: "Confirm each legal scan boundary", zhTW: "逐項確認合法掃描範圍" } },
  { step: "03", title: { en: "Scan", zhTW: "掃描" }, detail: { en: "Run only tools that match the assets and permission", zhTW: "只執行符合資產與權限的工具" } },
  { step: "04", title: { en: "Share", zhTW: "交接" }, detail: { en: "Export complete evidence and next steps", zhTW: "匯出完整證據與下一步" } },
  { step: "05", title: { en: "Verify", zhTW: "複驗" }, detail: { en: "Compare the same case after fixes", zhTW: "在同一案件比較修復前後" } },
] as const;

const useCaseNeeds = (definition: UseCaseDefinition | undefined, id: UseCaseId): boolean =>
  definition?.id === id;

export function CasesPage({
  cases,
  selectedCase,
  selectedUseCase,
  selectionKey,
  assetCount,
  findingCount,
  unknownSourceCount,
  connectedNoAssetSourceCount,
  latestRun,
  runs,
  verificationBaselineRunId,
  artifactCleanupPlan,
  artifactCleanupResult,
  busy,
  onClearPreset,
  onCreate,
  onArchive,
  onDelete,
  onDeleteArtifacts,
  onDismissArtifactCleanup,
  onSelect,
  onContinue,
  onOpenProgress,
  onSelectVerificationBaseline,
  onStartRescan,
  onOpenVerification,
}: CasesPageProps) {
  const { t, text, formatDateTime, formatNumber } = useI18n();
  const [showForm, setShowForm] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [name, setName] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [companySize, setCompanySize] = useState<CompanySize>("small");
  const [platforms, setPlatforms] = useState<CloudPlatform[]>(["aws"]);
  const [dataClasses, setDataClasses] = useState<DataClass[]>(["none"]);
  const [requestedActivities, setRequestedActivities] = useState<AssessmentActivity[]>(["configuration_assessment"]);
  const [description, setDescription] = useState("");
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [publicTargets, setPublicTargets] = useState("");
  const [internalTargets, setInternalTargets] = useState("");
  const [repositories, setRepositories] = useState("");
  const [iacProjects, setIacProjects] = useState("");
  const [containerImages, setContainerImages] = useState("");
  const [kubernetesClusters, setKubernetesClusters] = useState("");
  const [assetDraftError, setAssetDraftError] = useState<CaseAssetDraftError>();
  const [pendingDeleteId, setPendingDeleteId] = useState<string>();
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [artifactDeleteConfirmation, setArtifactDeleteConfirmation] = useState("");
  const websiteInputRef = useRef<HTMLInputElement>(null);

  const selectedDefinition = useMemo(
    () => selectedUseCase ? useCaseById(selectedUseCase) : undefined,
    [selectedUseCase],
  );
  const selectedUseCaseTitle = selectedUseCase
    ? text({
      en: startPageCopy.en.cards[selectedUseCase].title,
      zhTW: startPageCopy["zh-TW"].cards[selectedUseCase].title,
    })
    : undefined;
  const selectedUseCaseSummary = selectedUseCase
    ? text({
      en: startPageCopy.en.cards[selectedUseCase].summary,
      zhTW: startPageCopy["zh-TW"].cards[selectedUseCase].summary,
    })
    : undefined;
  const preparedWebsite = websiteUrl.trim() ? prepareDeployedWebsiteTarget(websiteUrl) : undefined;
  const interruptedEngineCount = latestRun?.engineRuns.filter(
    (engine) => engine.phase === "interrupted_restart" || engine.errorCode === "desktop_process_restarted",
  ).length ?? 0;
  const incompleteEngineCount = latestRun?.engineRuns.filter((engine) => engine.status !== "completed").length ?? 0;
  const terminalRuns = runs.filter((run) => ["completed", "partial", "failed", "cancelled"].includes(run.status));
  const activeRun = runs.find((run) => ["queued", "running", "paused"].includes(run.status));
  const selectedVerificationBaseline = terminalRuns.find((run) => run.id === verificationBaselineRunId);
  const additionalPlatforms = selectedDefinition
    ? platformIds.filter((platform) => !selectedDefinition.suggestedPlatforms.includes(platform))
    : platformIds;

  useEffect(() => {
    setArtifactDeleteConfirmation("");
  }, [artifactCleanupPlan?.caseId]);

  useEffect(() => {
    if (!selectedDefinition) return;
    setShowForm(true);
    setAdvancedOpen(false);
    setPlatforms([...selectedDefinition.suggestedPlatforms]);
    setRequestedActivities([...selectedDefinition.suggestedActivities]);
    setWebsiteUrl("");
    setPublicTargets("");
    setInternalTargets("");
    setRepositories("");
    setIacProjects("");
    setContainerImages("");
    setKubernetesClusters("");
    setAssetDraftError(undefined);
  }, [selectedDefinition, selectionKey]);

  const platformLabel = (platform: CloudPlatform): string => t(platformKeys[platform]);
  const activityLabel = (activity: AssessmentActivity): string => text(activityCopy[activity].label);

  const togglePlatform = (platform: CloudPlatform) => {
    setPlatforms((current) => current.includes(platform)
      ? current.filter((item) => item !== platform)
      : [...current, platform]);
  };

  const toggleDataClass = (dataClass: DataClass) => {
    setDataClasses((current) => {
      if (dataClass === "none") return ["none"];
      const withoutNone = current.filter((item) => item !== "none");
      return withoutNone.includes(dataClass)
        ? withoutNone.filter((item) => item !== dataClass)
        : [...withoutNone, dataClass];
    });
  };

  const toggleAssessmentActivity = (activity: AssessmentActivity) => {
    setRequestedActivities((current) => current.includes(activity)
      ? current.filter((item) => item !== activity)
      : [...current, activity]);
  };

  const resetTargetInputs = () => {
    setWebsiteUrl("");
    setPublicTargets("");
    setInternalTargets("");
    setRepositories("");
    setIacProjects("");
    setContainerImages("");
    setKubernetesClusters("");
    setAssetDraftError(undefined);
  };

  const closeForm = () => {
    setShowForm(false);
    setAdvancedOpen(false);
  };

  const changeUseCase = () => {
    setShowForm(false);
    setAdvancedOpen(false);
    resetTargetInputs();
    onClearPreset?.();
  };

  const openBlankForm = () => {
    setShowForm(true);
    setAdvancedOpen(!selectedDefinition);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim() || !organizationName.trim() || platforms.length === 0 || requestedActivities.length === 0) return;

    const assets = buildKnownAssets({
      selectedUseCase,
      websiteUrl,
      publicTargets: platforms.includes("external") ? publicTargets : "",
      internalTargets: platforms.includes("external") ? internalTargets : "",
      repositories: platforms.includes("code") ? repositories : "",
      iacProjects: platforms.includes("code") ? iacProjects : "",
      containerImages: platforms.includes("container") ? containerImages : "",
      kubernetesClusters: platforms.includes("kubernetes") ? kubernetesClusters : "",
    });
    if (!assets.ok) {
      setAssetDraftError(assets.error);
      if (assets.error.kind === "website") {
        websiteInputRef.current?.focus();
      } else {
        setAdvancedOpen(true);
      }
      return;
    }

    setAssetDraftError(undefined);
    const created = await onCreate({
      name: name.trim(),
      organizationName: organizationName.trim(),
      companySize,
      platforms,
      requestedActivities,
      knownAssets: assets.knownAssets,
      dataClasses: dataClasses.length ? dataClasses : ["none"],
      description: description.trim() || undefined,
    });
    if (!created) return;

    setShowForm(false);
    setAdvancedOpen(false);
    setName("");
    setOrganizationName("");
    setCompanySize("small");
    setPlatforms(["aws"]);
    setDataClasses(["none"]);
    setRequestedActivities(["configuration_assessment"]);
    setDescription("");
    resetTargetInputs();
  };

  const beginDelete = (caseId: string) => {
    setPendingDeleteId(caseId);
    setDeleteConfirmation("");
  };

  const cancelDelete = () => {
    setPendingDeleteId(undefined);
    setDeleteConfirmation("");
  };

  const submitDelete = async (event: FormEvent, assessmentCase: AssessmentCase) => {
    event.preventDefault();
    if (deleteConfirmation !== assessmentCase.name) return;
    if (await onDelete(assessmentCase.id, deleteConfirmation)) cancelDelete();
  };

  const submitArtifactDelete = async (event: FormEvent) => {
    event.preventDefault();
    if (!artifactCleanupPlan || artifactDeleteConfirmation !== `DELETE ${artifactCleanupPlan.caseId}`) return;
    await onDeleteArtifacts(artifactDeleteConfirmation);
  };

  const primaryTarget = selectedDefinition && (
    <fieldset className="choice-fieldset case-primary-target">
      <legend>{text(pageCopy.selectedGoal)}</legend>
      <div className="case-primary-target__heading">
        <span className="case-primary-target__icon"><Icon name={selectedDefinition.icon} size={20} /></span>
        <div>
          <strong>{selectedUseCaseTitle}</strong>
          <p>{selectedUseCaseSummary}</p>
        </div>
      </div>

      {useCaseNeeds(selectedDefinition, "deployed_website") && (
        <label className="field">
          <span>{text(pageCopy.websiteUrl)}</span>
          <input
            ref={websiteInputRef}
            required
            type="url"
            inputMode="url"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            value={websiteUrl}
            aria-invalid={assetDraftError?.kind === "website" || undefined}
            aria-describedby={assetDraftError?.kind === "website"
              ? "website-url-help website-url-error"
              : "website-url-help"}
            onChange={(event) => {
              setWebsiteUrl(event.target.value);
              setAssetDraftError(undefined);
            }}
            placeholder={text(pageCopy.websitePlaceholder)}
          />
          <small id="website-url-help">{text(pageCopy.websiteHelp)}</small>
          {assetDraftError?.kind === "website" && (
            <small id="website-url-error" className="field-error" role="alert">
              {text(websiteErrorCopy[assetDraftError.error])}
            </small>
          )}
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "deployed_website") && preparedWebsite?.ok && (
        <InlineNotice tone="info" title={text(pageCopy.websitePreparedTitle)}>
          <p>{text(pageCopy.websitePrepared, {
            target: preparedWebsite.value.target,
            protocol: preparedWebsite.value.service.protocol.toUpperCase(),
            port: formatNumber(preparedWebsite.value.service.port),
            path: preparedWebsite.value.service.path,
          })}</p>
          {preparedWebsite.value.service.queryWasRemoved && <p>{text(pageCopy.websiteQueryRemoved)}</p>}
        </InlineNotice>
      )}

      {useCaseNeeds(selectedDefinition, "external_ip_or_domain") && (
        <label className="field">
          <span>{text(pageCopy.publicTargets)}</span>
          <textarea rows={4} value={publicTargets} onChange={(event) => { setPublicTargets(event.target.value); setAssetDraftError(undefined); }} placeholder={text(pageCopy.publicTargetsPlaceholder)} />
          <small>{text(pageCopy.publicTargetsHelp)}</small>
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "internal_it_environment") && (
        <label className="field">
          <span>{text(pageCopy.internalTargets)}</span>
          <textarea rows={4} value={internalTargets} onChange={(event) => { setInternalTargets(event.target.value); setAssetDraftError(undefined); }} placeholder={text(pageCopy.internalTargetsPlaceholder)} />
          <small>{text(pageCopy.internalTargetsHelp)}</small>
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "source_code") && (
        <label className="field">
          <span>{text(pageCopy.repositories)}</span>
          <textarea rows={4} value={repositories} onChange={(event) => setRepositories(event.target.value)} placeholder={text(pageCopy.repositoriesPlaceholder)} />
          <small>{text(pageCopy.repositoriesHelp)}</small>
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "infrastructure_as_code") && (
        <label className="field">
          <span>{text(pageCopy.iacProjects)}</span>
          <textarea rows={4} value={iacProjects} onChange={(event) => setIacProjects(event.target.value)} placeholder={text(pageCopy.iacPlaceholder)} />
          <small>{text(pageCopy.iacHelp)}</small>
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "container_image") && (
        <label className="field">
          <span>{text(pageCopy.containerImages)}</span>
          <textarea rows={4} value={containerImages} onChange={(event) => setContainerImages(event.target.value)} placeholder={text(pageCopy.containerPlaceholder)} />
          <small>{text(pageCopy.containerHelp)}</small>
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "kubernetes") && (
        <label className="field">
          <span>{text(pageCopy.kubernetes)}</span>
          <textarea rows={4} value={kubernetesClusters} onChange={(event) => setKubernetesClusters(event.target.value)} placeholder={text(pageCopy.kubernetesPlaceholder)} />
          <small>{text(pageCopy.kubernetesHelp)}</small>
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "cloud_account") && (
        <fieldset className="choice-fieldset choice-fieldset--nested">
          <legend>{text(pageCopy.cloudChoice)}</legend>
          <p>{text(pageCopy.cloudChoiceHelp)}</p>
          <div className="choice-grid">
            {cloudPlatformIds.map((platform) => (
              <label key={platform} className="check-card">
                <input type="checkbox" checked={platforms.includes(platform)} onChange={() => togglePlatform(platform)} />
                <span className="platform-avatar">{platformAbbreviations[platform]}</span>
                <span>{platformLabel(platform)}</span>
              </label>
            ))}
          </div>
        </fieldset>
      )}

      <p className="case-primary-target__boundary"><Icon name="lock" size={15} /> {text(pageCopy.targetCandidateHelp)}</p>
    </fieldset>
  );

  return (
    <div className="page page--cases">
      <PageHeader
        eyebrow={text(pageCopy.headerEyebrow)}
        title={text(pageCopy.headerTitle)}
        description={text(pageCopy.headerDescription)}
        actions={
          <button className="button button--primary" type="button" onClick={showForm ? closeForm : openBlankForm}>
            <Icon name={showForm ? "close" : "plus"} size={18} />
            {text(showForm ? pageCopy.closeForm : pageCopy.create)}
          </button>
        }
      />

      {showForm && (
        <form className="create-case-panel" onSubmit={submit}>
          <div className="section-heading section-heading--row">
            <div>
              <p className="eyebrow">{text(pageCopy.newCaseEyebrow)}</p>
              <h2>{text(pageCopy.newCaseTitle)}</h2>
              <p>{text(pageCopy.newCaseDescription)}</p>
            </div>
            {selectedDefinition && onClearPreset && (
              <button className="button button--ghost button--small" type="button" onClick={changeUseCase}>
                <Icon name="refresh" size={15} />
                {text(pageCopy.changeUseCase)}
              </button>
            )}
          </div>

          <div className="form-grid form-grid--two">
            <label className="field">
              <span>{text(pageCopy.caseName)}</span>
              <input required value={name} onChange={(event) => setName(event.target.value)} placeholder={text(pageCopy.caseNamePlaceholder)} />
            </label>
            <label className="field">
              <span>{text(pageCopy.organizationName)}</span>
              <input required value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} placeholder={text(pageCopy.organizationPlaceholder)} />
            </label>
          </div>

          {primaryTarget}

          {assetDraftError?.kind === "conflicting_exposure" && (
            <InlineNotice tone="danger" title={text(pageCopy.formConflictTitle)}>
              <p>{text(pageCopy.formConflict, { target: assetDraftError.target })}</p>
            </InlineNotice>
          )}

          <details className="case-more-details" open={advancedOpen} onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}>
            <summary>
              <span>
                <strong>{text(pageCopy.moreSummary)}</strong>
                <small>{text(pageCopy.moreSummaryHint)}</small>
              </span>
              <Icon name="chevron" size={18} />
            </summary>
            <div className="case-more-details__body">
              <div className="form-grid form-grid--two">
                <label className="field">
                  <span>{text(pageCopy.organizationSize)}</span>
                  <select value={companySize} onChange={(event) => setCompanySize(event.target.value as CompanySize)}>
                    {(Object.keys(companySizeCopy) as CompanySize[]).map((size) => (
                      <option key={size} value={size}>{text(companySizeCopy[size])}</option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span>{text(pageCopy.notes)}</span>
                  <input value={description} onChange={(event) => setDescription(event.target.value)} placeholder={text(pageCopy.notesPlaceholder)} />
                </label>
              </div>

              {additionalPlatforms.length > 0 && (
                <fieldset className="choice-fieldset">
                  <legend>{text(pageCopy.otherSystems)}</legend>
                  <p>{text(pageCopy.otherSystemsHelp)}</p>
                  <div className="choice-grid">
                    {additionalPlatforms.map((platform) => (
                      <label key={platform} className="check-card">
                        <input type="checkbox" checked={platforms.includes(platform)} onChange={() => togglePlatform(platform)} />
                        <span className="platform-avatar">{platformAbbreviations[platform]}</span>
                        <span>{platformLabel(platform)}</span>
                      </label>
                    ))}
                  </div>
                </fieldset>
              )}

              <fieldset className="choice-fieldset">
                <legend>{text(pageCopy.additionalCoordinates)}</legend>
                <p>{text(pageCopy.targetCandidateHelp)}</p>
                <div className="form-grid form-grid--two">
                  {platforms.includes("external") && !useCaseNeeds(selectedDefinition, "external_ip_or_domain") && (
                    <label className="field">
                      <span>{text(pageCopy.publicTargets)}</span>
                      <textarea rows={4} value={publicTargets} onChange={(event) => { setPublicTargets(event.target.value); setAssetDraftError(undefined); }} placeholder={text(pageCopy.publicTargetsPlaceholder)} />
                      <small>{text(pageCopy.publicTargetsHelp)}</small>
                    </label>
                  )}
                  {platforms.includes("external") && !useCaseNeeds(selectedDefinition, "internal_it_environment") && (
                    <label className="field">
                      <span>{text(pageCopy.internalTargets)}</span>
                      <textarea rows={4} value={internalTargets} onChange={(event) => { setInternalTargets(event.target.value); setAssetDraftError(undefined); }} placeholder={text(pageCopy.internalTargetsPlaceholder)} />
                      <small>{text(pageCopy.internalTargetsHelp)}</small>
                    </label>
                  )}
                  {platforms.includes("code") && !useCaseNeeds(selectedDefinition, "source_code") && (
                    <label className="field">
                      <span>{text(pageCopy.repositories)}</span>
                      <textarea rows={4} value={repositories} onChange={(event) => setRepositories(event.target.value)} placeholder={text(pageCopy.repositoriesPlaceholder)} />
                      <small>{text(pageCopy.repositoriesHelp)}</small>
                    </label>
                  )}
                  {platforms.includes("code") && !useCaseNeeds(selectedDefinition, "infrastructure_as_code") && (
                    <label className="field">
                      <span>{text(pageCopy.iacProjects)}</span>
                      <textarea rows={4} value={iacProjects} onChange={(event) => setIacProjects(event.target.value)} placeholder={text(pageCopy.iacPlaceholder)} />
                      <small>{text(pageCopy.iacHelp)}</small>
                    </label>
                  )}
                  {platforms.includes("container") && !useCaseNeeds(selectedDefinition, "container_image") && (
                    <label className="field">
                      <span>{text(pageCopy.containerImages)}</span>
                      <textarea rows={4} value={containerImages} onChange={(event) => setContainerImages(event.target.value)} placeholder={text(pageCopy.containerPlaceholder)} />
                      <small>{text(pageCopy.containerHelp)}</small>
                    </label>
                  )}
                  {platforms.includes("kubernetes") && !useCaseNeeds(selectedDefinition, "kubernetes") && (
                    <label className="field">
                      <span>{text(pageCopy.kubernetes)}</span>
                      <textarea rows={4} value={kubernetesClusters} onChange={(event) => setKubernetesClusters(event.target.value)} placeholder={text(pageCopy.kubernetesPlaceholder)} />
                      <small>{text(pageCopy.kubernetesHelp)}</small>
                    </label>
                  )}
                </div>
              </fieldset>

              <fieldset className="choice-fieldset">
                <legend>{text(pageCopy.activities)}</legend>
                <p>{text(pageCopy.activitiesHelp)}</p>
                <div className="choice-grid choice-grid--compact">
                  {(Object.keys(activityCopy) as AssessmentActivity[]).map((activity) => (
                    <label key={activity} className="check-card check-card--compact">
                      <input type="checkbox" checked={requestedActivities.includes(activity)} onChange={() => toggleAssessmentActivity(activity)} />
                      <span>{text(activityCopy[activity].label)}<small>{text(activityCopy[activity].detail)}</small></span>
                    </label>
                  ))}
                </div>
                {requestedActivities.includes("active_external_vulnerability_tests") && (
                  <InlineNotice tone="warning" title={text(pageCopy.activeWarningTitle)}>
                    <p>{text(pageCopy.activeWarning)}</p>
                  </InlineNotice>
                )}
              </fieldset>

              <fieldset className="choice-fieldset">
                <legend>{text(pageCopy.dataTypes)}</legend>
                <p>{text(pageCopy.dataTypesHelp)}</p>
                <div className="choice-grid choice-grid--compact">
                  {(Object.keys(dataClassCopy) as DataClass[]).map((dataClass) => (
                    <label key={dataClass} className="check-card check-card--compact">
                      <input type="checkbox" checked={dataClasses.includes(dataClass)} onChange={() => toggleDataClass(dataClass)} />
                      <span>{text(dataClassCopy[dataClass])}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            </div>
          </details>

          <div className="form-actions">
            <p><Icon name="lock" size={16} /> {text(pageCopy.createSafety)}</p>
            <button className="button button--primary" type="submit" disabled={busy || !name.trim() || !organizationName.trim() || platforms.length === 0 || requestedActivities.length === 0}>
              {text(busy ? pageCopy.creating : pageCopy.createLocal)}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      {selectedCase && (
        <section className="current-case-hero" aria-labelledby="current-case-title">
          <div>
            <div className="current-case-hero__meta">
              <StatusPill label={t(phaseKeys[selectedCase.phase])} tone={phaseMeta[selectedCase.phase].tone} />
              {selectedCase.isDemo && <StatusPill label={text(pageCopy.demo)} tone="demo" />}
              {latestRun && <StatusPill label={text(pageCopy.latestRun, { status: t(runStatusKeys[latestRun.status]) })} tone={runStatusMeta[latestRun.status].tone} />}
            </div>
            <h2 id="current-case-title">{selectedCase.name}</h2>
            <p>{selectedCase.organizationName} · {text(pageCopy.updated, { date: formatDateTime(selectedCase.updatedAt) })}</p>
            <div className="platform-list" aria-label={text(pageCopy.caseSystems)}>
              {selectedCase.platforms.map((platform) => <span key={platform}>{platformLabel(platform)}</span>)}
            </div>
            {selectedCase.requestedActivities.length > 0 && (
              <div className="platform-list" aria-label={text(pageCopy.caseIntent)}>
                {selectedCase.requestedActivities.map((activity) => <span key={activity}>{activityLabel(activity)}</span>)}
              </div>
            )}
          </div>
          <button className="button button--light" type="button" onClick={interruptedEngineCount > 0 ? onOpenProgress : onContinue}>
            {text(interruptedEngineCount > 0 ? pageCopy.handleInterrupted : pageCopy.viewCoverage)}
            <Icon name="arrow" size={17} />
          </button>
        </section>
      )}

      {selectedCase && terminalRuns.length > 0 && (
        <section className="section-block" aria-labelledby="verification-baseline-title">
          <div className="section-heading section-heading--row">
            <div>
              <p className="eyebrow">{text(pageCopy.verificationEyebrow)}</p>
              <h2 id="verification-baseline-title">{text(pageCopy.verificationTitle)}</h2>
              <p>{text(pageCopy.verificationDescription)}</p>
            </div>
            <button className="button button--light" type="button" onClick={onOpenVerification}>{text(pageCopy.viewDifference)}</button>
          </div>
          <label className="field">
            <span>{text(pageCopy.baseline)}</span>
            <select value={verificationBaselineRunId ?? ""} onChange={(event) => onSelectVerificationBaseline(event.target.value)}>
              {terminalRuns.map((run) => (
                <option key={run.id} value={run.id}>
                  {run.label} · {t(runStatusKeys[run.status])} · {formatDateTime(run.finishedAt ?? run.startedAt)}
                </option>
              ))}
            </select>
            <small>{selectedVerificationBaseline
              ? text(pageCopy.baselineSelected, { id: selectedVerificationBaseline.id })
              : text(pageCopy.baselineChoose)}</small>
          </label>
          <div className="form-actions">
            <p>{activeRun
              ? text(pageCopy.activeRun, { label: activeRun.label })
              : text(pageCopy.verificationOutcome)}</p>
            <button className="button button--primary" type="button" disabled={busy || Boolean(activeRun) || !selectedVerificationBaseline} onClick={() => selectedVerificationBaseline && void onStartRescan(selectedVerificationBaseline.id)}>
              <Icon name="refresh" size={17} />
              {text(busy ? pageCopy.creating : activeRun ? pageCopy.handleActiveFirst : pageCopy.startVerification)}
            </button>
          </div>
        </section>
      )}

      {assetCount === 0 && unknownSourceCount > 0 && (
        <InlineNotice tone="warning" title={text(pageCopy.unknownZeroTitle)}><p>{text(pageCopy.unknownZero)}</p></InlineNotice>
      )}

      {assetCount === 0 && unknownSourceCount === 0 && connectedNoAssetSourceCount > 0 && (
        <InlineNotice tone="info" title={text(pageCopy.connectedZeroTitle)}><p>{text(pageCopy.connectedZero)}</p></InlineNotice>
      )}

      {interruptedEngineCount > 0 && latestRun && (
        <InlineNotice tone="warning" title={text(pageCopy.interruptedTitle, { count: formatNumber(interruptedEngineCount) })}>
          <p>{text(pageCopy.interrupted, { id: latestRun.id })}</p>
        </InlineNotice>
      )}

      {artifactCleanupPlan && (
        <section className={`artifact-cleanup-panel ${artifactCleanupResult?.removed ? "artifact-cleanup-panel--removed" : artifactCleanupPlan.exists ? "artifact-cleanup-panel--danger" : "artifact-cleanup-panel--absent"}`} aria-labelledby="artifact-cleanup-title">
          <div className="artifact-cleanup-panel__copy">
            <p className="eyebrow">{text(pageCopy.cleanupEyebrow)}</p>
            <h2 id="artifact-cleanup-title">{text(artifactCleanupResult?.removed
              ? pageCopy.cleanupRemovedTitle
              : artifactCleanupPlan.exists
                ? pageCopy.cleanupRetainedTitle
                : pageCopy.cleanupAbsentTitle)}</h2>
            <p>{text(artifactCleanupResult?.removed
              ? pageCopy.cleanupRemoved
              : artifactCleanupPlan.exists
                ? pageCopy.cleanupRetained
                : pageCopy.cleanupAbsent)}</p>
            <code>{artifactCleanupPlan.exactPath}</code>
          </div>

          {artifactCleanupPlan.exists && !artifactCleanupResult?.removed ? (
            <form className="artifact-cleanup-panel__form" onSubmit={(event) => void submitArtifactDelete(event)}>
              <label className="field">
                <span>{text(pageCopy.cleanupType, { id: artifactCleanupPlan.caseId })}</span>
                <input autoComplete="off" spellCheck={false} value={artifactDeleteConfirmation} onChange={(event) => setArtifactDeleteConfirmation(event.target.value)} />
              </label>
              <div className="artifact-cleanup-panel__actions">
                <button className="button button--secondary button--small" type="button" disabled={busy} onClick={onDismissArtifactCleanup}>{text(pageCopy.keepEvidence)}</button>
                <button className="button button--danger button--small" type="submit" disabled={busy || artifactDeleteConfirmation !== `DELETE ${artifactCleanupPlan.caseId}`}>
                  <Icon name="trash" size={16} />
                  {text(busy ? pageCopy.deletingEvidence : pageCopy.deleteEvidence)}
                </button>
              </div>
            </form>
          ) : (
            <button className="button button--secondary button--small" type="button" onClick={onDismissArtifactCleanup}>{text(pageCopy.understood)}</button>
          )}
        </section>
      )}

      <section className="metrics-grid metrics-grid--four" aria-label={text(pageCopy.summaryAria)}>
        <MetricCard label={text(pageCopy.assetsMetric)} value={formatNumber(assetCount)} detail={text(pageCopy.assetsMetricHelp)} icon="database" />
        <MetricCard label={text(pageCopy.findingsMetric)} value={formatNumber(findingCount)} detail={text(pageCopy.findingsMetricHelp)} icon="findings" tone={findingCount ? "danger" : "default"} />
        <MetricCard label={text(pageCopy.unknownMetric)} value={formatNumber(unknownSourceCount)} detail={text(pageCopy.unknownMetricHelp)} icon="warning" tone={unknownSourceCount ? "warning" : "default"} />
        <MetricCard label={text(pageCopy.incompleteMetric)} value={formatNumber(incompleteEngineCount)} detail={text(pageCopy.incompleteMetricHelp, { count: formatNumber(connectedNoAssetSourceCount) })} icon="progress" tone={incompleteEngineCount ? "warning" : "default"} />
      </section>

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div><p className="eyebrow">{text(pageCopy.allCasesEyebrow)}</p><h2>{text(pageCopy.allCasesTitle)}</h2></div>
          <span className="count-label">{text(pageCopy.caseCount, { count: formatNumber(cases.length) })}</span>
        </div>

        {cases.length === 0 ? (
          <EmptyState
            icon="cases"
            title={text(pageCopy.noCases)}
            description={text(pageCopy.noCasesHelp)}
            action={<button className="button button--primary" type="button" onClick={openBlankForm}>{text(pageCopy.create)}</button>}
          />
        ) : (
          <div className="case-list">
            {cases.map((assessmentCase) => {
              const active = assessmentCase.id === selectedCase?.id;
              const confirmingDelete = pendingDeleteId === assessmentCase.id;
              const listedAssets = assessmentCase.assetCount === undefined ? "—" : formatNumber(assessmentCase.assetCount);
              const listedFindings = assessmentCase.findingCount === undefined ? "—" : formatNumber(assessmentCase.findingCount);
              return (
                <Fragment key={assessmentCase.id}>
                  <article className={active ? "case-row case-row--active" : "case-row"}>
                    <button type="button" className="case-row__main" onClick={() => onSelect(assessmentCase.id)}>
                      <span className="case-row__icon"><Icon name="cases" /></span>
                      <span className="case-row__copy">
                        <span className="case-row__title"><strong>{assessmentCase.name}</strong>{assessmentCase.isDemo && <small>{text(pageCopy.demo)}</small>}</span>
                        <span>{assessmentCase.organizationName}</span>
                        <span>{text(pageCopy.assetFindingCount, { assets: listedAssets, findings: listedFindings })}</span>
                        <span className="case-row__platforms">
                          {assessmentCase.platforms.slice(0, 4).map(platformLabel).join(" · ")}
                          {assessmentCase.platforms.length > 4 ? ` · +${formatNumber(assessmentCase.platforms.length - 4)}` : ""}
                        </span>
                      </span>
                    </button>
                    <div className="case-row__aside">
                      <StatusPill label={t(phaseKeys[assessmentCase.phase])} tone={phaseMeta[assessmentCase.phase].tone} />
                      <span>{formatDateTime(assessmentCase.updatedAt)}</span>
                    </div>
                    <div className="case-row__actions">
                      {assessmentCase.phase !== "archived" && (
                        <button className="icon-button case-row__archive" type="button" disabled={busy} aria-label={text(pageCopy.archiveAria, { name: assessmentCase.name })} title={text(pageCopy.archiveTitle)} onClick={() => void onArchive(assessmentCase.id)}><Icon name="archive" size={17} /></button>
                      )}
                      <button className="icon-button icon-button--danger" type="button" disabled={busy} aria-label={text(pageCopy.beginDeleteAria, { name: assessmentCase.name })} title={text(pageCopy.deleteRecordTitle)} aria-expanded={confirmingDelete} aria-controls={`delete-confirm-${assessmentCase.id}`} onClick={() => confirmingDelete ? cancelDelete() : beginDelete(assessmentCase.id)}>
                        <Icon name={confirmingDelete ? "close" : "trash"} size={17} />
                      </button>
                      <button className="icon-button" type="button" aria-label={text(pageCopy.selectAria, { name: assessmentCase.name })} onClick={() => onSelect(assessmentCase.id)}><Icon name="chevron" /></button>
                    </div>
                  </article>
                  {confirmingDelete && (
                    <form id={`delete-confirm-${assessmentCase.id}`} className="case-delete-confirmation" aria-labelledby={`delete-title-${assessmentCase.id}`} onSubmit={(event) => void submitDelete(event, assessmentCase)}>
                      <div><p className="eyebrow">{text(pageCopy.deleteStep)}</p><h3 id={`delete-title-${assessmentCase.id}`}>{text(pageCopy.confirmDeleteTitle)}</h3><p>{text(pageCopy.confirmDeleteHelp)}</p></div>
                      <label className="field"><span>{text(pageCopy.typeCaseName, { name: assessmentCase.name })}</span><input autoFocus autoComplete="off" value={deleteConfirmation} onChange={(event) => setDeleteConfirmation(event.target.value)} /></label>
                      <div className="case-delete-confirmation__actions">
                        <button className="button button--ghost button--small" type="button" disabled={busy} onClick={cancelDelete}>{text(pageCopy.cancel)}</button>
                        <button className="button button--danger button--small" type="submit" disabled={busy || deleteConfirmation !== assessmentCase.name}><Icon name="trash" size={16} />{text(busy ? pageCopy.deleting : pageCopy.deleteRecordOnly)}</button>
                      </div>
                    </form>
                  )}
                </Fragment>
              );
            })}
          </div>
        )}
      </section>

      <section className="workflow-strip" aria-label={text(pageCopy.workflowAria)}>
        {workflowCopy.map(({ step, title, detail }) => (
          <div key={step} className="workflow-step"><span>{step}</span><strong>{text(title)}</strong><small>{text(detail)}</small></div>
        ))}
      </section>
    </div>
  );
}
