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
import "./page-technical-details.css";

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
  onStartNewScan: () => void;
  onSelect: (caseId: string) => void;
  onContinue: () => void;
  onOpenProgress: () => void;
  onSelectVerificationBaseline: (runId: string) => void;
  onStartRescan: (baselineRunId: string) => Promise<void>;
  onOpenVerification: () => void;
}

const pageCopy = {
  headerEyebrow: { en: "My security scans", zhTW: "我的資安檢查" },
  headerTitle: { en: "Start a new scan or pick up where you left off", zhTW: "開始新的檢查，或接著上次進度" },
  headerDescription: {
    en: "Keep your targets, results, reports, and follow-up scans together in one project.",
    zhTW: "把檢查目標、結果、報告與修復後複查集中放在同一個專案。",
  },
  create: { en: "Start a new scan", zhTW: "開始新的檢查" },
  closeForm: { en: "Close setup", zhTW: "關閉設定" },
  newCaseEyebrow: { en: "New scan", zhTW: "新的檢查" },
  newCaseTitle: { en: "Let's set up your scan", zhTW: "一起設定這次檢查" },
  newCaseDescription: {
    en: "Give it a name, tell us who it is for, and add the first thing you want checked. You can add more later.",
    zhTW: "取一個好認的名稱、選擇所屬團隊，再加入第一個想檢查的目標；之後隨時都能再加。",
  },
  changeUseCase: { en: "Choose a different scan", zhTW: "改選其他檢查方式" },
  caseName: { en: "Scan project name", zhTW: "掃描專案名稱" },
  caseNamePlaceholder: { en: "Example: 2026 first security check", zhTW: "例如：2026 年首次安全健檢" },
  organizationName: { en: "Company or team name", zhTW: "公司或團隊名稱" },
  organizationPlaceholder: { en: "Who owns the systems being checked?", zhTW: "這些系統屬於哪個公司或團隊？" },
  selectedGoal: { en: "What are you checking?", zhTW: "這次要檢查什麼？" },
  targetCandidateHelp: {
    en: "We'll add this to your scan project. You can review everything before the scan starts.",
    zhTW: "我們會先把它加入掃描專案；開始掃描前，你仍可檢查與調整所有內容。",
  },
  localPickerNextTitle: { en: "Next, choose your project", zhTW: "下一步，選擇你的專案" },
  localPickerNextBody: {
    en: "Create the scan project, then pick the folder or exported image. We'll prepare the right local checks automatically.",
    zhTW: "建立掃描專案後，選擇資料夾或匯出映像；我們會自動準備合適的本機檢查。",
  },
  localPickerBoundary: {
    en: "You choose exactly what is checked, and nothing runs until you press Start.",
    zhTW: "由你決定要檢查什麼；按下「開始」前不會執行任何檢查。",
  },
  websiteUrl: { en: "Website or API URL", zhTW: "網站或 API 網址" },
  websitePlaceholder: { en: "https://portal.example.com/login", zhTW: "https://portal.example.com/login" },
  websiteHelp: {
    en: "Enter one complete http:// or https:// URL. Do not include a username or password.",
    zhTW: "請輸入一個完整的 http:// 或 https:// 網址；不要放入帳號或密碼。",
  },
  websitePreparedTitle: { en: "Website ready to add", zhTW: "網站已準備好加入" },
  websitePrepared: {
    en: "Great — {target} will be the first website in this scan project. We'll suggest sensible scan settings on the next screen.",
    zhTW: "很好，{target} 會成為這個掃描專案的第一個網站；下一頁會幫你準備合適的掃描設定。",
  },
  websiteQueryRemoved: {
    en: "Query parameters and page fragments are not saved because they can contain private tokens or personal data.",
    zhTW: "網址參數與頁面片段不會保存，因為其中可能含有私人權杖或個人資料。",
  },
  publicTargets: { en: "Public domains, IP addresses, or small network ranges", zhTW: "公開網域、IP 或小型網段" },
  publicTargetsPlaceholder: { en: "example.com\n203.0.113.10\n203.0.113.0/28", zhTW: "example.com\n203.0.113.10\n203.0.113.0/28" },
  publicTargetsHelp: {
    en: "Enter one IP address or domain per line. You can review the list before anything runs.",
    zhTW: "每行輸入一個 IP 或網域；開始前仍可檢查與調整清單。",
  },
  internalTargets: { en: "Internal IP addresses or small network ranges", zhTW: "內部 IP 或小型網段" },
  internalTargetsPlaceholder: { en: "10.20.0.8\n10.20.1.0/28", zhTW: "10.20.0.8\n10.20.1.0/28" },
  internalTargetsHelp: {
    en: "Enter one server, device, or small network range per line.",
    zhTW: "每行輸入一台伺服器、設備或小型網段。",
  },
  repositories: { en: "Source project or repository", zhTW: "程式碼專案或儲存庫" },
  repositoriesPlaceholder: { en: "Local project name or read-only repository coordinate", zhTW: "本機專案名稱或唯讀程式碼儲存庫位置" },
  repositoriesHelp: {
    en: "Name the project here; you'll choose its local folder on the next screen.",
    zhTW: "先填專案名稱；下一頁再選擇本機資料夾。",
  },
  iacProjects: { en: "Infrastructure-code project", zhTW: "基礎設施程式碼專案" },
  iacPlaceholder: { en: "infra/production\nterraform/prod", zhTW: "infra/production\nterraform/prod" },
  iacHelp: {
    en: "Name a Terraform, CloudFormation, Kubernetes YAML, or other deployment project. Use one project per line.",
    zhTW: "填入 Terraform、CloudFormation、Kubernetes YAML 或其他部署專案名稱；每行一個專案。",
  },
  containerImages: { en: "Container image name", zhTW: "容器映像名稱" },
  containerPlaceholder: { en: "Example: production-api", zhTW: "例如：production-api" },
  containerHelp: {
    en: "Name the image here. On the next screen, choose the exact local image copy you want checked.",
    zhTW: "先填映像名稱；下一頁再選擇要檢查的精確本機映像副本。",
  },
  kubernetes: { en: "Kubernetes cluster or snapshot name", zhTW: "Kubernetes 叢集或快照名稱" },
  kubernetesPlaceholder: { en: "production-eks\nstaging-gke", zhTW: "production-eks\nstaging-gke" },
  kubernetesHelp: {
    en: "Name the cluster or project here. On the next screen, choose the configuration copy you want checked.",
    zhTW: "先填叢集或專案名稱；下一頁再選擇要檢查的設定副本。",
  },
  cloudChoice: { en: "Which cloud do you want to check first?", zhTW: "想先檢查哪一個雲端服務？" },
  cloudChoiceHelp: {
    en: "Pick one now. We'll open its official sign-in next, and you can add another source later.",
    zhTW: "先選一個；下一步會開啟官方登入，之後仍可再加入其他來源。",
  },
  moreSummary: { en: "Customize this scan", zhTW: "自訂這次檢查" },
  moreSummaryHint: {
    en: "Add other systems, priorities, and optional details",
    zhTW: "加入其他系統、優先方向與選填資料",
  },
  organizationSize: { en: "Organization size", zhTW: "組織規模" },
  notes: { en: "Notes (optional)", zhTW: "備註（選填）" },
  notesPlaceholder: { en: "What question should this case answer first?", zhTW: "這次最想先釐清什麼？" },
  otherSystems: { en: "Other systems to include", zhTW: "這次還要納入哪些系統" },
  otherSystemsHelp: {
    en: "Add anything else you want to include in this scan project.",
    zhTW: "把這次還想一起檢查的內容加進來。",
  },
  additionalCoordinates: { en: "Other known targets (optional)", zhTW: "其他已知目標（選填）" },
  activities: { en: "What kinds of checks may be needed?", zhTW: "這次可能需要哪些檢查？" },
  activitiesHelp: {
    en: "Choose the kind of answers you want. You can fine-tune the actual scan before it runs.",
    zhTW: "選擇你想得到哪類答案；正式開始前仍可微調掃描內容。",
  },
  activeWarningTitle: { en: "Active testing is not authorized yet", zhTW: "選擇主動測試不等於已授權" },
  activeWarning: {
    en: "Before active testing, you must separately confirm ownership, exact targets and ports, rate and time limits, and a traceable written authorization reference.",
    zhTW: "開始主動測試前，仍須另外確認所有權、精確目標與連接埠、速度與時間限制，以及可追溯的書面授權。",
  },
  dataTypes: { en: "Data this case may involve", zhTW: "這個案件可能涉及哪些資料" },
  dataTypesHelp: {
    en: "This helps the app explain impact and put the most useful results first.",
    zhTW: "這會幫助產品說明影響，並把更重要的結果排在前面。",
  },
  createSafety: { en: "You can add or change targets before you run the scan.", zhTW: "正式掃描前，仍可隨時加入或修改目標。" },
  creating: { en: "Creating…", zhTW: "建立中…" },
  createLocal: { en: "Create scan project", zhTW: "建立掃描專案" },
  formConflictTitle: { en: "The same target has two different descriptions", zhTW: "同一目標被標成兩種不同環境" },
  formConflict: {
    en: "{target} appears in both public and internal target lists. Keep it in the one list that describes where it is reached.",
    zhTW: "{target} 同時出現在公開與內部目標清單。請只保留在真正符合連線位置的那一邊。",
  },
  publicTargetRequired: { en: "Enter at least one public IP address or domain.", zhTW: "請至少輸入一個公開 IP 位址或網域。" },
  internalTargetRequired: { en: "Enter at least one internal IP address, range, or hostname.", zhTW: "請至少輸入一個內部 IP 位址、網段或主機名稱。" },
  demo: { en: "Demo", zhTW: "展示" },
  latestRun: { en: "Latest run: {status}", zhTW: "最新一輪：{status}" },
  updated: { en: "Updated {date}", zhTW: "更新於 {date}" },
  caseSystems: { en: "Systems in this scan", zhTW: "這次檢查的系統" },
  caseIntent: { en: "Planned checks", zhTW: "預計檢查項目" },
  handleInterrupted: { en: "Handle interrupted work", zhTW: "處理重啟後中斷" },
  viewCoverage: { en: "Set up this scan", zhTW: "設定這次掃描" },
  verificationEyebrow: { en: "Check fixes", zhTW: "確認修復" },
  verificationTitle: { en: "Choose the earlier run to compare", zhTW: "選擇要比較的先前掃描" },
  verificationDescription: {
    en: "Pick the scan from before the fix. We'll run the same checks again and show what changed.",
    zhTW: "選擇修復前的掃描；我們會再次執行相同檢查，直接顯示前後差異。",
  },
  viewDifference: { en: "View differences", zhTW: "查看差異" },
  baseline: { en: "Completed baseline run", zhTW: "已結束的基準掃描" },
  baselineSelected: { en: "This earlier scan is ready for comparison.", zhTW: "已選好先前掃描，可以開始比較。" },
  baselineChoose: { en: "Choose a completed run.", zhTW: "請選擇一個已結束的掃描。" },
  activeRun: { en: "{label} is still active. Resume or cancel it first.", zhTW: "{label} 尚未結束，請先續跑或取消。" },
  verificationOutcome: {
    en: "When the new scan finishes, the case will show resolved, still present, new, and unverifiable results.",
    zhTW: "新掃描完成後，案件會列出已解決、仍存在、新增與無法確認的結果。",
  },
  handleActiveFirst: { en: "Handle the active run first", zhTW: "先處理未結束的掃描" },
  startVerification: { en: "Start a new check from this baseline", zhTW: "以這次結果開始複驗" },
  unknownZeroTitle: { en: "Add a source to start finding your systems", zhTW: "先加入資料來源，才能開始找出系統" },
  unknownZero: {
    en: "We do not have enough information yet. Open scan setup, connect the place you want to check, then try again.",
    zhTW: "目前資訊還不夠。請打開掃描設定，連接想檢查的位置，再重新嘗試。",
  },
  unknownZeroDetails: {
    en: "No usable source has produced a candidate list yet. This does not mean the organization has no assets.",
    zhTW: "目前沒有可用來源建立候選清單；這不表示組織沒有資產。",
  },
  connectedZeroTitle: { en: "No systems were found this time", zhTW: "這次沒有找到系統" },
  connectedZero: {
    en: "The connected source returned no systems. Check that you connected the right place, then scan again if needed.",
    zhTW: "已連接的位置沒有回傳系統。請確認是否選對位置；需要時再重新掃描。",
  },
  connectedZeroDetails: {
    en: "The zero result applies only to the saved source snapshot, confirmed boundary, and observation time.",
    zhTW: "零項結果只適用於已保存的來源快照、已確認範圍與當時的觀察時間。",
  },
  noticeDetails: { en: "Why this result appears", zhTW: "為什麼會出現這個結果" },
  interruptedTitle: { en: "{count} checks paused when the app restarted", zhTW: "應用程式重新啟動時，有 {count} 項檢查暫停" },
  interrupted: {
    en: "Open Scan progress to continue where you left off or cancel the unfinished work.",
    zhTW: "請打開「掃描進度」，從中斷處繼續，或取消未完成的工作。",
  },
  interruptedDetails: {
    en: "Run {id} kept a restart checkpoint. The app will not reconnect automatically.",
    zhTW: "掃描輪次 {id} 已保留接續點；應用程式不會自動重新連線。",
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
  summaryAria: { en: "Current scan summary", zhTW: "目前掃描摘要" },
  assetsMetric: { en: "Systems found", zhTW: "找到的系統" },
  assetsMetricHelp: { en: "Ready to review in this scan project", zhTW: "可在這個掃描專案中繼續查看" },
  findingsMetric: { en: "Problems found", zhTW: "找到的問題" },
  findingsMetricHelp: { en: "Open the problem list to see what to fix first", zhTW: "打開問題清單，查看該先修什麼" },
  scanDiagnostics: { en: "Source and scan details", zhTW: "資料來源與掃描細節" },
  unknownMetric: { en: "Unknown data sources", zhTW: "未知資料來源" },
  unknownMetricHelp: { en: "Unknown never means no assets or passed", zhTW: "未知不等於沒有資產或已通過" },
  incompleteMetric: { en: "Incomplete scanner jobs", zhTW: "未完成的掃描工作" },
  incompleteMetricHelp: { en: "{count} connected sources reported no assets", zhTW: "{count} 個已連接來源沒有發現資產" },
  allCasesEyebrow: { en: "All scans", zhTW: "所有掃描" },
  allCasesTitle: { en: "Scan projects on this device", zhTW: "這台電腦上的掃描專案" },
  caseCount: { en: "{count} projects", zhTW: "{count} 個專案" },
  noCases: { en: "No scan projects yet", zhTW: "還沒有掃描專案" },
  noCasesHelp: {
    en: "Start with a website, IP address, internal system, code project, cloud account, container, or Kubernetes.",
    zhTW: "從網站、IP、內部系統、程式碼、雲端帳號、容器或 Kubernetes 開始。",
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
  workflowSummary: { en: "See how your scan stays under your control", zhTW: "了解掃描如何始終由你掌控" },
  workflowIntro: {
    en: "Open this when you need the exact workflow behind discovery, permission, scanning, handoff, and follow-up checks.",
    zhTW: "需要了解盤點、授權、掃描、交接與後續複驗的完整流程時，再打開這裡。",
  },
  workflowAria: { en: "Complete case workflow", zhTW: "完整案件流程" },
} as const;

const platformIds = ["aws", "azure", "gcp", "m365", "external", "code", "container", "kubernetes"] as const satisfies readonly CloudPlatform[];
const cloudPlatformIds = ["aws", "azure", "gcp", "m365"] as const satisfies readonly CloudPlatform[];
const guidedLocalUseCaseIds: readonly UseCaseId[] = ["source_code", "infrastructure_as_code", "container_image", "kubernetes"];

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
  onStartNewScan,
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
  const publicTargetsInputRef = useRef<HTMLTextAreaElement>(null);
  const internalTargetsInputRef = useRef<HTMLTextAreaElement>(null);

  const selectedDefinition = useMemo(
    () => selectedUseCase ? useCaseById(selectedUseCase) : undefined,
    [selectedUseCase],
  );
  const guidedLocalUseCase = Boolean(
    selectedUseCase && guidedLocalUseCaseIds.includes(selectedUseCase),
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
    setPlatforms(selectedDefinition.id === "cloud_account"
      ? [selectedDefinition.suggestedPlatforms[0] ?? "aws"]
      : [...selectedDefinition.suggestedPlatforms]);
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
    if (!selectedDefinition) {
      onStartNewScan();
      return;
    }
    setShowForm(true);
    setAdvancedOpen(false);
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
      } else if (assets.error.kind === "missing_target") {
        (assets.error.target === "public" ? publicTargetsInputRef : internalTargetsInputRef).current?.focus();
      } else {
        setAdvancedOpen(true);
      }
      return;
    }

    setAssetDraftError(undefined);
    const created = await onCreate({
      name: name.trim(),
      assessmentIntent: selectedUseCase,
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
          })}</p>
          {preparedWebsite.value.service.queryWasRemoved && <p>{text(pageCopy.websiteQueryRemoved)}</p>}
        </InlineNotice>
      )}

      {useCaseNeeds(selectedDefinition, "external_ip_or_domain") && (
        <label className="field">
          <span>{text(pageCopy.publicTargets)}</span>
          <textarea
            ref={publicTargetsInputRef}
            required
            rows={4}
            value={publicTargets}
            aria-invalid={assetDraftError?.kind === "missing_target" && assetDraftError.target === "public" || undefined}
            aria-describedby="public-targets-help public-targets-error"
            onInvalid={() => setAssetDraftError({ kind: "missing_target", target: "public" })}
            onChange={(event) => { setPublicTargets(event.target.value); setAssetDraftError(undefined); }}
            placeholder={text(pageCopy.publicTargetsPlaceholder)}
          />
          <small id="public-targets-help">{text(pageCopy.publicTargetsHelp)}</small>
          {assetDraftError?.kind === "missing_target" && assetDraftError.target === "public" && (
            <small id="public-targets-error" className="field-error" role="alert">{text(pageCopy.publicTargetRequired)}</small>
          )}
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "internal_it_environment") && (
        <label className="field">
          <span>{text(pageCopy.internalTargets)}</span>
          <textarea
            ref={internalTargetsInputRef}
            required
            rows={4}
            value={internalTargets}
            aria-invalid={assetDraftError?.kind === "missing_target" && assetDraftError.target === "internal" || undefined}
            aria-describedby="internal-targets-help internal-targets-error"
            onInvalid={() => setAssetDraftError({ kind: "missing_target", target: "internal" })}
            onChange={(event) => { setInternalTargets(event.target.value); setAssetDraftError(undefined); }}
            placeholder={text(pageCopy.internalTargetsPlaceholder)}
          />
          <small id="internal-targets-help">{text(pageCopy.internalTargetsHelp)}</small>
          {assetDraftError?.kind === "missing_target" && assetDraftError.target === "internal" && (
            <small id="internal-targets-error" className="field-error" role="alert">{text(pageCopy.internalTargetRequired)}</small>
          )}
        </label>
      )}

      {guidedLocalUseCase && (
        <InlineNotice tone="info" title={text(pageCopy.localPickerNextTitle)}>
          <p>{text(pageCopy.localPickerNextBody)}</p>
        </InlineNotice>
      )}

      {useCaseNeeds(selectedDefinition, "cloud_account") && (
        <fieldset className="choice-fieldset choice-fieldset--nested">
          <legend>{text(pageCopy.cloudChoice)}</legend>
          <p>{text(pageCopy.cloudChoiceHelp)}</p>
          <div className="choice-grid">
            {cloudPlatformIds.map((platform) => (
              <label key={platform} className="check-card">
                <input type="radio" name="cloud-platform" checked={platforms.includes(platform)} onChange={() => setPlatforms([platform])} />
                <span className="platform-avatar">{platformAbbreviations[platform]}</span>
                <span>{platformLabel(platform)}</span>
              </label>
            ))}
          </div>
        </fieldset>
      )}

      <p className="case-primary-target__boundary"><Icon name="lock" size={15} /> {text(guidedLocalUseCase ? pageCopy.localPickerBoundary : pageCopy.targetCandidateHelp)}</p>
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

              {!guidedLocalUseCase && (
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
              )}

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
              ? text(pageCopy.baselineSelected)
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
        <InlineNotice tone="warning" title={text(pageCopy.unknownZeroTitle)}>
          <p>{text(pageCopy.unknownZero)}</p>
          <details className="page-technical-details">
            <summary>{text(pageCopy.noticeDetails)}</summary>
            <p>{text(pageCopy.unknownZeroDetails)}</p>
          </details>
        </InlineNotice>
      )}

      {assetCount === 0 && unknownSourceCount === 0 && connectedNoAssetSourceCount > 0 && (
        <InlineNotice tone="info" title={text(pageCopy.connectedZeroTitle)}>
          <p>{text(pageCopy.connectedZero)}</p>
          <details className="page-technical-details">
            <summary>{text(pageCopy.noticeDetails)}</summary>
            <p>{text(pageCopy.connectedZeroDetails)}</p>
          </details>
        </InlineNotice>
      )}

      {interruptedEngineCount > 0 && latestRun && (
        <InlineNotice tone="warning" title={text(pageCopy.interruptedTitle, { count: formatNumber(interruptedEngineCount) })}>
          <p>{text(pageCopy.interrupted)}</p>
          <details className="page-technical-details">
            <summary>{text(pageCopy.noticeDetails)}</summary>
            <p>{text(pageCopy.interruptedDetails, { id: latestRun.id })}</p>
          </details>
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

      <section className="metrics-grid page-outcome-metrics" aria-label={text(pageCopy.summaryAria)}>
        <MetricCard label={text(pageCopy.assetsMetric)} value={formatNumber(assetCount)} detail={text(pageCopy.assetsMetricHelp)} icon="database" />
        <MetricCard label={text(pageCopy.findingsMetric)} value={formatNumber(findingCount)} detail={text(pageCopy.findingsMetricHelp)} icon="findings" tone={findingCount ? "danger" : "default"} />
      </section>

      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(pageCopy.scanDiagnostics)}</summary>
        <section className="metrics-grid page-diagnostic-metrics">
          <MetricCard label={text(pageCopy.unknownMetric)} value={formatNumber(unknownSourceCount)} detail={text(pageCopy.unknownMetricHelp)} icon="warning" tone={unknownSourceCount ? "warning" : "default"} />
          <MetricCard label={text(pageCopy.incompleteMetric)} value={formatNumber(incompleteEngineCount)} detail={text(pageCopy.incompleteMetricHelp, { count: formatNumber(connectedNoAssetSourceCount) })} icon="progress" tone={incompleteEngineCount ? "warning" : "default"} />
        </section>
      </details>

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

      <details className="page-secondary-feature page-secondary-feature--workflow">
        <summary>{text(pageCopy.workflowSummary)}</summary>
        <p className="page-secondary-feature__intro">{text(pageCopy.workflowIntro)}</p>
        <section className="workflow-strip" aria-label={text(pageCopy.workflowAria)}>
          {workflowCopy.map(({ step, title, detail }) => (
            <div key={step} className="workflow-step"><span>{step}</span><strong>{text(title)}</strong><small>{text(detail)}</small></div>
          ))}
        </section>
      </details>
    </div>
  );
}
