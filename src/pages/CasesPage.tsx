import { Fragment, useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import {
  buildKnownAssets,
  explicitTargetRequiresSensitiveNetworkAllowance,
  prepareDeployedWebsiteTarget,
  type CaseAssetDraftError,
  type ExternalTargetInputError,
  type WebsiteInputError,
} from "../caseForm";
import { caseDisplayLabels, caseIdentityPresentation } from "../caseIdentityPresentation";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import { loadStoredDemoCases } from "../data/demo";
import { useI18n, type BilingualText, type StaticTranslationKey } from "../i18n";
import { phaseMeta, runStatusMeta } from "../lib";
import {
  localInputDefinitions,
  localInputDefinitionForAssessmentIntent,
  localPathDisplayName,
  localPathDisplayLabels,
  localProfileByAssessmentIntent,
} from "../localInputProfiles";
import {
  internalHostGreenboneProfile,
  parseInternalHostPorts,
  prepareInternalHostTarget,
  type InternalHostInputError,
  type InternalHostPortsError,
} from "../internalHostProfile";
import { scanRunIdentityPresentation } from "../scanRunIdentityPresentation";
import { scannerService } from "../services/scanner";
import type {
  AiGeneratedArtifactAnswer,
  AssessmentActivity,
  AssessmentCase,
  CaseArtifactCleanupResult,
  CaseArtifactDeletionPlan,
  CloudPlatform,
  CompanySize,
  CreateCaseInput,
  DataClass,
  AttachWorkspaceSnapshotInput,
  LocalNetworkCandidateInventory,
  ScanRun,
} from "../types";
import {
  startPageCopy,
  useCaseById,
  type UseCaseDefinition,
  type UseCaseId,
} from "../useCases";
import { websiteQuickOrigin } from "../websiteQuickProfile";

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
  preparingLocalSnapshot?: boolean;
  nativeMode: boolean;
  onClearPreset?: () => void;
  onCreate: (input: CreateCaseInput) => Promise<boolean>;
  onCreateWithWorkspace: (
    input: CreateCaseInput,
    workspace: Omit<AttachWorkspaceSnapshotInput, "caseId">,
  ) => Promise<boolean>;
  onCreateWithWorkspaces?: (
    input: CreateCaseInput,
    workspaces: Array<Omit<AttachWorkspaceSnapshotInput, "caseId">>,
  ) => Promise<boolean>;
  onChooseWorkspace: () => Promise<string | null>;
  onSeedDemo: () => Promise<void>;
  onArchive: (caseId: string) => Promise<void>;
  onDelete: (caseId: string, confirmation: string) => Promise<boolean>;
  onDeleteArtifacts: (confirmation: string) => Promise<boolean>;
  onDismissArtifactCleanup: () => void;
  onStartNewScan: () => void;
  onOpenCase: (caseId: string) => void;
  onContinue: () => void;
  onOpenProgress: () => void;
  onOpenResults: () => void;
  onSelectVerificationBaseline: (runId: string) => void;
  onStartRescan: (baselineRunId: string) => Promise<void>;
  onOpenVerification: () => void;
}

const pageCopy = {
  headerEyebrow: { en: "My security scans", zhTW: "我的資安檢查" },
  headerTitle: { en: "Scan projects", zhTW: "掃描專案" },
  headerDescription: {
    en: "Create a scan or continue one.",
    zhTW: "建立新掃描，或繼續現有專案。",
  },
  create: { en: "Start a new scan", zhTW: "開始新的檢查" },
  closeForm: { en: "Close setup", zhTW: "關閉設定" },
  newCaseEyebrow: { en: "New scan", zhTW: "新的檢查" },
  newCaseTitle: { en: "New scan", zhTW: "新掃描" },
  newCaseDescription: {
    en: "Add the target. A project name is generated when this field is blank.",
    zhTW: "加入目標即可；專案名稱留白時會依目標自動建立。",
  },
  changeUseCase: { en: "Choose a different scan", zhTW: "改選其他檢查方式" },
  caseName: { en: "Scan project name (optional)", zhTW: "掃描專案名稱（選填）" },
  caseNamePlaceholder: { en: "Created from the target if left blank", zhTW: "留白時會依目標自動建立" },
  defaultCaseName: { en: "Security scan", zhTW: "資安掃描" },
  organizationName: { en: "Company or team name (optional)", zhTW: "公司或團隊名稱（選填）" },
  organizationPlaceholder: { en: "Optional, and fixed once the project is created", zhTW: "選填，專案建立後就不能修改" },
  selectedGoal: { en: "What are you checking?", zhTW: "這次要檢查什麼？" },
  aiGeneratedQuestion: {
    en: "Did AI generate or substantially change any code in this project?",
    zhTW: "這個專案有程式碼是由 AI 產生，或經 AI 大幅修改嗎？",
  },
  aiGeneratedHelp: {
    en: "Sets the AI-code guidance. Scan scope stays the same.",
    zhTW: "這能讓結果顯示合適的 AI 程式碼建議，不會改變掃描內容。",
  },
  aiGeneratedYes: {
    en: "Yes, AI wrote or changed some of it",
    zhTW: "有，AI 寫過或大幅修改過",
  },
  aiGeneratedNo: {
    en: "No, it was mostly written by people",
    zhTW: "沒有，主要是人寫的",
  },
  aiGeneratedUnknown: { en: "I'm not sure", zhTW: "我不確定" },
  targetCandidateHelp: {
    en: "Press Start to run the selected checks.",
    zhTW: "按下「開始」以執行所選檢查。",
  },
  localPickerEyebrow: { en: "Local check", zhTW: "本機檢查" },
  localPickerBoundary: {
    en: "The selected folder is copied into a private local snapshot. Review the checks, then press Start.",
    zhTW: "所選資料夾會複製成私密本機快照；請檢查掃描項目後按下「開始」。",
  },
  localPathHelp: {
    en: "Only the folder name is shown here. Its full location stays on this computer.",
    zhTW: "這裡只顯示資料夾名稱；完整位置只留在這台電腦上。",
  },
  choosingFolder: { en: "Opening folder picker…", zhTW: "正在開啟資料夾選擇器…" },
  folderFallback: { en: "Selected folder", zhTW: "已選資料夾" },
  localFolderRequired: { en: "Choose the folder you want checked first.", zhTW: "請先選擇想檢查的資料夾。" },
  localFolderPickerError: {
    en: "Open the local folder picker again.",
    zhTW: "請重新開啟本機資料夾選擇器。",
  },
  browserLocalTitle: { en: "Desktop app required for local folders", zhTW: "本機資料夾需要桌面程式" },
  browserLocalBody: {
    en: "Create a preview project to see the review steps. Use the desktop app for a local scan.",
    zhTW: "建立預覽專案以查看檢查步驟；本機掃描請使用桌面程式。",
  },
  createPreview: { en: "Create preview project", zhTW: "建立預覽專案" },
  websiteUrl: { en: "Website or API URL", zhTW: "網站或 API 網址" },
  websitePlaceholder: { en: "https://portal.example.com", zhTW: "https://portal.example.com" },
  websiteHelp: {
    en: "Enter one complete http:// or https:// URL without a username or password.",
    zhTW: "輸入一個不含帳號或密碼的完整 http:// 或 https:// 網址。",
  },
  environmentRepositoriesTitle: { en: "Development projects", zhTW: "開發專案" },
  environmentRepositoriesBody: {
    en: "Choose each local repository you want checked for risky code, exposed secrets, vulnerable dependencies, and unsafe configuration.",
    zhTW: "逐一選擇要檢查的本機 repo；產品會找危險程式碼、暴露秘密、有弱點的相依套件與不安全設定。",
  },
  environmentAddRepository: { en: "Add a project folder", zhTW: "加入專案資料夾" },
  environmentRemoveRepository: { en: "Remove {name}", zhTW: "移除 {name}" },
  environmentWebsitesTitle: { en: "Websites and APIs", zhTW: "網站與 API" },
  environmentWebsitesPlaceholder: {
    en: "https://portal.example.com\nhttps://api.example.com",
    zhTW: "https://portal.example.com\nhttps://api.example.com",
  },
  environmentWebsitesHelp: {
    en: "Enter one complete http:// or https:// website or API URL per line for the fixed Nuclei checks. Credentials are not accepted.",
    zhTW: "每行輸入一個完整的 http:// 或 https:// 網站或 API 網址，執行固定的 Nuclei 檢查。此處不接受登入資訊。",
  },
  environmentHostsTitle: { en: "Internal systems", zhTW: "內部系統" },
  environmentHostsBody: {
    en: "Add each exact hostname or IP once. Greenbone discovers supported services on common ports and runs the remote-safe checks that apply to that host.",
    zhTW: "每個精確主機名稱或 IP 只需加入一次。Greenbone 會在常用連接埠探索支援的服務，並執行適用於該主機的 remote-safe 檢查。",
  },
  environmentAddHost: { en: "Add another system", zhTW: "再加入一個系統" },
  environmentRemoveHost: { en: "Remove internal system {number}", zhTW: "移除內部系統 {number}" },
  environmentHostTarget: { en: "Exact hostname or IP {number}", zhTW: "精確主機名稱或 IP {number}" },
  environmentHostTargetHelp: {
    en: "Enter one hostname or IP only—no URL, CIDR range, port, username, or password.",
    zhTW: "只輸入一個主機名稱或 IP；不要輸入網址、CIDR 網段、連接埠、帳號或密碼。",
  },
  environmentHostAdvanced: { en: "Advanced: choose ports", zhTW: "進階：選擇連接埠" },
  environmentHostPorts: { en: "TCP ports (optional)", zhTW: "TCP 連接埠（選填）" },
  environmentHostPortsHelp: {
    en: "Leave blank for common ports: {ports}. Or enter up to 64 comma-separated ports.",
    zhTW: "留白會使用常用連接埠：{ports}。也可輸入最多 64 個以逗號分隔的連接埠。",
  },
  environmentHostCoverage: {
    en: "Greenbone remote-safe profile · no sign-in or credentials",
    zhTW: "Greenbone remote-safe 設定 · 不登入、不使用帳密",
  },
  environmentInventoryTitle: { en: "Other hosts and ranges — inventory only", zhTW: "其他主機與網段（僅供盤點）" },
  environmentInventoryHint: {
    en: "Record unsupported bare hosts or CIDR ranges; this run will not scan them",
    zhTW: "記錄尚未支援的裸主機或 CIDR 網段；本次執行不會掃描它們",
  },
  environmentInventoryHelp: {
    en: "CIDR ranges are inventory only. Add each exact host above for a vulnerability check.",
    zhTW: "CIDR 網段僅供盤點；請在上方逐一加入需要弱點檢查的精確主機。",
  },
  environmentAtLeastOne: {
    en: "Add at least one scan-ready project folder, website or API URL, or exact internal system. Inventory-only ranges can be saved alongside one of these items.",
    zhTW: "請至少加入一個可掃描的專案資料夾、網站或 API 網址，或精確的內部系統。僅供盤點的網段可與其中一項一起保存。",
  },
  websitePreparedTitle: { en: "Ready: {target}", zhTW: "已準備：{target}" },
  websitePrepared: {
    en: "Scan scope: {origin}. Reference path: {path}. Path-only authorization is not supported.",
    zhTW: "掃描範圍：{origin}。參考路徑：{path}。不支援僅限特定路徑的授權。",
  },
  websitePreparedInternal: {
    en: "Scan scope: {origin}. Reference path: {path}. Start requires exact internal-target confirmation; path-only authorization is not supported.",
    zhTW: "掃描範圍：{origin}。參考路徑：{path}。開始前須確認精確內部目標；不支援僅限特定路徑的授權。",
  },
  websiteQueryRemoved: {
    en: "Not saved: query parameters and page fragments, which can contain tokens or personal data.",
    zhTW: "不保存網址參數與頁面片段；其中可能含有 token 或個人資料。",
  },
  publicTargets: { en: "Public domains, IP addresses, or small network ranges", zhTW: "公開網域、IP 或小型網段" },
  publicTargetsPlaceholder: { en: "example.com\n203.0.113.10\n203.0.113.0/28", zhTW: "example.com\n203.0.113.10\n203.0.113.0/28" },
  publicTargetsHelp: {
    en: "Enter one hostname, IP address, or CIDR range per line—without a protocol, path, port, or sign-in details. Review the list before Start.",
    zhTW: "每行輸入一個主機名稱、IP 或 CIDR 網段；不要加入通訊協定、路徑、連接埠或登入資訊。開始前請檢查清單。",
  },
  internalTargets: { en: "Internal IP addresses or small network ranges", zhTW: "內部 IP 或小型網段" },
  internalTargetsPlaceholder: { en: "10.20.0.8\n10.20.1.0/28", zhTW: "10.20.0.8\n10.20.1.0/28" },
  internalTargetsHelp: {
    en: "Enter one hostname, IP address, or CIDR range per line—without a protocol, path, port, or sign-in details.",
    zhTW: "每行輸入一個主機名稱、IP 或 CIDR 網段；不要加入通訊協定、路徑、連接埠或登入資訊。",
  },
  localNetworkDetectingTitle: { en: "Looking for your local network", zhTW: "正在找這台電腦的區域網路" },
  localNetworkDetectingBody: {
    en: "Reading this computer's network settings.",
    zhTW: "正在讀取這台電腦的網路設定。",
  },
  localNetworkFoundTitle: { en: "Likely local network found", zhTW: "找到一個可能的區域網路" },
  localNetworkFoundBody: {
    en: "Add {target} to the target list?",
    zhTW: "要將 {target} 加入目標清單嗎？",
  },
  localNetworkUseTarget: { en: "Use {target}", zhTW: "使用 {target}" },
  localNetworkTargetAdded: { en: "Added to the target list", zhTW: "已加入目標清單" },
  localNetworkNoneTitle: { en: "Enter the network you want to check", zhTW: "請輸入想檢查的網路" },
  localNetworkNoneBody: {
    en: "Enter an internal IP address or a small network range below.",
    zhTW: "請在下方輸入一個內部 IP 或小型網段。",
  },
  localNetworkAmbiguousTitle: { en: "Exact local network required", zhTW: "需要精確的區域網路" },
  localNetworkAmbiguousBody: {
    en: "Enter the exact internal IP address or range below.",
    zhTW: "請在下方輸入精確的內部 IP 或網段。",
  },
  localNetworkUnavailableTitle: { en: "Local network detection unavailable", zhTW: "無法偵測區域網路" },
  localNetworkUnavailableBody: {
    en: "Enter the internal IP address or small network range below.",
    zhTW: "請在下方輸入內部 IP 或小型網段。",
  },
  localNetworkUnsupportedTitle: { en: "Enter your local network", zhTW: "請輸入你的區域網路" },
  localNetworkUnsupportedBody: {
    en: "Enter an internal IP address or small range below.",
    zhTW: "請在下方輸入內部 IP 或小型網段。",
  },
  repositories: { en: "Source project or repository", zhTW: "程式碼專案或儲存庫" },
  repositoriesPlaceholder: { en: "Local project name or read-only repository coordinate", zhTW: "本機專案名稱或唯讀程式碼儲存庫位置" },
  repositoriesHelp: {
    en: "Choose the project folder above. A project name is optional.",
    zhTW: "請在上方選擇專案資料夾；專案名稱可留白。",
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
    en: "Choose the exported image folder above. A project name is optional.",
    zhTW: "請在上方選擇匯出的映像資料夾；專案名稱可留白。",
  },
  kubernetes: { en: "Kubernetes cluster or snapshot name", zhTW: "Kubernetes 叢集或快照名稱" },
  kubernetesPlaceholder: { en: "production-eks\nstaging-gke", zhTW: "production-eks\nstaging-gke" },
  kubernetesHelp: {
    en: "Choose the exported settings folder above. A project name is optional.",
    zhTW: "請在上方選擇匯出的設定資料夾；專案名稱可留白。",
  },
  cloudChoice: { en: "Which cloud do you want to check first?", zhTW: "想先檢查哪一個雲端服務？" },
  cloudChoiceHelp: {
    en: "Pick one source. Its official sign-in opens next.",
    zhTW: "選擇一個來源；下一步會開啟官方登入。",
  },
  moreSummary: { en: "Optional project details", zhTW: "選填專案資訊" },
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
  activeWarningTitle: { en: "Active testing requires separate authorization", zhTW: "主動測試需要另行授權" },
  activeWarning: {
    en: "Required before active testing: confirmed ownership, exact targets and ports, rate and time limits, and a traceable written authorization reference.",
    zhTW: "開始主動測試前必須確認：所有權、精確目標與連接埠、速度與時間限制，以及可追溯的書面授權。",
  },
  dataTypes: { en: "Data this case may involve", zhTW: "這個案件可能涉及哪些資料" },
  dataTypesHelp: {
    en: "Used to explain impact when a scan finds a matching asset.",
    zhTW: "掃描發現對應資產時，這項資料會用來說明影響。",
  },
  creating: { en: "Creating…", zhTW: "建立中…" },
  preparingLocalSnapshot: { en: "Preparing a private scan copy…", zhTW: "正在建立私密掃描副本…" },
  preparingLocalSnapshotTitle: { en: "Preparing your private scan copy", zhTW: "正在建立你的私密掃描副本" },
  preparingLocalSnapshotBody: {
    en: "The private scan copy is being prepared automatically.",
    zhTW: "系統正在自動準備私密掃描副本。",
  },
  createLocal: { en: "Create scan project", zhTW: "建立掃描專案" },
  reviewEnvironment: { en: "Review scan", zhTW: "檢查掃描內容" },
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
  viewProgress: { en: "View scan progress", zhTW: "查看掃描進度" },
  viewResults: { en: "View results", zhTW: "查看結果" },
  viewCoverage: { en: "Set up this scan", zhTW: "設定這次掃描" },
  verificationEyebrow: { en: "Check fixes", zhTW: "確認修復" },
  verificationTitle: { en: "Choose the earlier run to compare", zhTW: "選擇要比較的先前掃描" },
  verificationDescription: {
    en: "Pick the scan from before the fix. The same checks run again and show what changed.",
    zhTW: "選擇修復前的掃描；相同檢查會再次執行並直接顯示前後差異。",
  },
  viewDifference: { en: "View differences", zhTW: "查看差異" },
  baseline: { en: "Finished baseline run", zhTW: "已結束的基準掃描" },
  baselineSelected: { en: "This earlier scan is ready for comparison.", zhTW: "已選好先前掃描，可以開始比較。" },
  baselineChoose: { en: "Choose a finished run.", zhTW: "請選擇一個已結束的掃描。" },
  activeRun: { en: "{label} is active. Available actions: Resume or Cancel.", zhTW: "{label} 尚未結束。可用操作：續跑或取消。" },
  verificationOutcome: {
    en: "Comparison outcomes: resolved, still present, new, and unverifiable.",
    zhTW: "比較結果：已解決、仍存在、新增與無法確認。",
  },
  handleActiveFirst: { en: "Handle the active run first", zhTW: "先處理未結束的掃描" },
  startVerification: { en: "Start a new check from this baseline", zhTW: "以這次結果開始複驗" },
  unknownZeroTitle: { en: "Add a source to start finding your systems", zhTW: "先加入資料來源，才能開始找出系統" },
  unknownZero: {
    en: "Source status: not connected. Open scan setup and connect the source.",
    zhTW: "資料來源狀態：未連接。開啟掃描設定並連接資料來源。",
  },
  unknownZeroDetails: {
    en: "Candidate list status: no connected source.",
    zhTW: "候選清單狀態：沒有已連接的資料來源。",
  },
  connectedZeroTitle: { en: "No systems were found this time", zhTW: "這次沒有找到系統" },
  connectedZero: {
    en: "Latest connected-source snapshot: zero systems. Scan again after changing the source selection.",
    zhTW: "最新的已連接來源快照：零個系統。變更來源選擇後重新掃描。",
  },
  connectedZeroDetails: {
    en: "The saved source snapshot returned 0 systems.",
    zhTW: "已保存的來源快照回傳 0 個系統。",
  },
  noticeDetails: { en: "Why this result appears", zhTW: "為什麼會出現這個結果" },
  interruptedTitle: { en: "Checks paused when the app restarted: {count}", zhTW: "應用程式重新啟動時，有 {count} 項檢查暫停" },
  interrupted: {
    en: "Open Scan progress to continue where you left off or cancel the unfinished work.",
    zhTW: "請打開「掃描進度」，從中斷處繼續，或取消未完成的工作。",
  },
  interruptedDetails: {
    en: "Run {id} restart checkpoint recorded.",
    zhTW: "掃描輪次 {id} 已記錄重新啟動接續點。",
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
    en: "The backend confirmed that this exact case evidence folder is absent.",
    zhTW: "後端確認這個精確案件證據目錄不存在。",
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
  incompleteMetricHelp: { en: "Connected sources reporting no assets: {count}", zhTW: "{count} 個已連接來源沒有發現資產" },
  allCasesEyebrow: { en: "All scans", zhTW: "所有掃描" },
  allCasesTitle: { en: "Scan projects on this device", zhTW: "這台電腦上的掃描專案" },
  caseCount: { en: "Projects: {count}", zhTW: "{count} 個專案" },
  noCases: { en: "No scan projects", zhTW: "沒有掃描專案" },
  noCasesHelp: {
    en: "Start with a website, IP address, internal system, code project, cloud account, container, or Kubernetes.",
    zhTW: "從網站、IP、內部系統、程式碼、雲端帳號、容器或 Kubernetes 開始。",
  },
  assetFindingCount: { en: "Assets: {assets} · Saved results: {findings}", zhTW: "{assets} 個資產 · {findings} 筆已保存結果" },
  archiveAria: { en: "Archive {name}", zhTW: "封存 {name}" },
  archiveTitle: { en: "Archive case", zhTW: "封存案件" },
  beginDeleteAria: { en: "Begin deleting {name}", zhTW: "開始刪除 {name}" },
  deleteRecordTitle: { en: "Delete case database record", zhTW: "刪除案件資料庫紀錄" },
  beginRemovePreviewAria: { en: "Begin removing {name} from this browser", zhTW: "開始從這個瀏覽器移除 {name}" },
  removePreviewTitle: { en: "Remove browser-saved preview project", zhTW: "移除瀏覽器儲存的預覽專案" },
  selectAria: { en: "Select {name}", zhTW: "選擇 {name}" },
  deleteStep: { en: "Step 2 of 2", zhTW: "第 2 步／2" },
  confirmDeleteTitle: { en: "Confirm deletion of the case record", zhTW: "確認刪除案件資料庫紀錄" },
  confirmDeleteHelp: {
    en: "This removes the database record from the case list but does not automatically delete the evidence folder. Evidence cleanup is a separate confirmation that shows the exact path.",
    zhTW: "這會從清單移除案件資料庫紀錄，但不會自動刪除證據目錄。證據清理會另外顯示精確路徑並要求確認。",
  },
  previewDeleteEyebrow: { en: "Browser preview only", zhTW: "僅限瀏覽器預覽" },
  confirmRemovePreviewTitle: { en: "Remove this preview project from this browser?", zhTW: "要從這個瀏覽器移除這個預覽專案嗎？" },
  confirmRemovePreviewHelp: {
    en: "This removes only the preview project saved in this browser. It does not change projects in the installed desktop app.",
    zhTW: "這只會移除儲存在這個瀏覽器中的預覽專案，不會變更已安裝桌面應用程式中的專案。",
  },
  typeCaseName: { en: "Type the full case name: {name}", zhTW: "輸入完整案件名稱「{name}」" },
  cancel: { en: "Cancel", zhTW: "取消" },
  deleting: { en: "Deleting…", zhTW: "刪除中…" },
  deleteRecordOnly: { en: "Delete case record only", zhTW: "只刪除案件紀錄" },
  removingPreview: { en: "Removing…", zhTW: "移除中…" },
  removePreview: { en: "Remove browser preview", zhTW: "移除瀏覽器預覽" },
  workflowSummary: { en: "See how your scan stays under your control", zhTW: "了解掃描如何始終由你掌控" },
  workflowIntro: {
    en: "Open this when you need the exact workflow behind discovery, permission, scanning, handoff, and follow-up checks.",
    zhTW: "需要了解盤點、授權、掃描、交接與後續複驗的完整流程時，再打開這裡。",
  },
  workflowAria: { en: "Complete case workflow", zhTW: "完整案件流程" },
} as const;

const platformIds = ["aws", "azure", "gcp", "m365", "external", "code", "container", "kubernetes"] as const satisfies readonly CloudPlatform[];
const cloudPlatformIds = ["aws", "azure", "gcp", "m365"] as const satisfies readonly CloudPlatform[];
const guidedLocalUseCaseIds: readonly UseCaseId[] = ["ai_application", "source_code", "infrastructure_as_code", "container_image", "kubernetes"];

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
  no_checks_completed: "status.run.noChecksCompleted",
  partial: "status.run.partial",
  failed: "status.run.failed",
  cancelled: "status.run.cancelled",
};

const companySizeCopy: Record<CompanySize, BilingualText> = {
  unknown: { en: "Not provided", zhTW: "未提供" },
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

const aiGeneratedAnswerCopy: Record<AiGeneratedArtifactAnswer, BilingualText> = {
  yes: pageCopy.aiGeneratedYes,
  no: pageCopy.aiGeneratedNo,
  unknown: pageCopy.aiGeneratedUnknown,
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
    detail: { en: "Limited connections to individually authorized targets", zhTW: "僅對逐項授權的目標發出有限連線" },
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
  hostname_invalid: { en: "The URL hostname must be a fully qualified hostname or IP address.", zhTW: "網址主機名稱必須是完整網域名稱或 IP 位址。" },
  port_invalid: { en: "Use a website port from 1 through 65,535.", zhTW: "網站連接埠必須介於 1 到 65,535。" },
  path_too_long: { en: "The encoded website path must be at most 2,048 characters.", zhTW: "編碼後的網站路徑不得超過 2,048 個字元。" },
};

const internalHostErrorCopy: Record<InternalHostInputError, BilingualText> = {
  empty_target: { en: "Enter the internal system hostname or IP address.", zhTW: "請輸入內部系統的主機名稱或 IP 位址。" },
  url_not_allowed: { en: "Enter only the hostname or IP address, not a URL.", zhTW: "只輸入主機名稱或 IP 位址，不要輸入網址。" },
  credentials_not_allowed: { en: "Remove the username or password. This scan does not use credentials.", zhTW: "請移除帳號或密碼；這項掃描不會使用帳密。" },
  cidr_not_allowed: { en: "Enter one exact hostname or IP address, not a CIDR range.", zhTW: "請輸入一個精確主機名稱或 IP 位址，不要輸入 CIDR 網段。" },
  service_coordinate_not_allowed: { en: "Remove the port. Enter it under Advanced if needed.", zhTW: "請移除連接埠；如有需要，請在「進階」中輸入。" },
  invalid_target: { en: "Enter a valid fully qualified hostname or IP address.", zhTW: "請輸入有效的完整主機名稱或 IP 位址。" },
};

const internalHostPortsErrorCopy: Record<InternalHostPortsError, BilingualText> = {
  invalid_ports: { en: "Enter TCP ports separated by commas, such as 22, 443, 8443.", zhTW: "請輸入以逗號分隔的 TCP 連接埠，例如 22, 443, 8443。" },
  port_out_of_range: { en: "Each port must be from 1 through 65,535.", zhTW: "每個連接埠必須介於 1 到 65,535。" },
  too_many_ports: { en: "Choose at most 64 ports for one system.", zhTW: "每個系統最多可選擇 64 個連接埠。" },
};

const targetInputErrorCopy = {
  wildcard_not_allowed: {
    en: "Remove the wildcard from {target}. Add each exact hostname, IP address, or CIDR range separately.",
    zhTW: "請移除 {target} 中的萬用字元，並分別加入每個精確主機名稱、IP 或 CIDR 網段。",
  },
  service_coordinate_not_allowed: {
    en: "{target} includes URL or service details. Enter only the hostname, IP address, or CIDR range; remove protocols, paths, ports, brackets, and sign-in details.",
    zhTW: "{target} 含有網址或服務細節。請只輸入主機名稱、IP 或 CIDR 網段，並移除通訊協定、路徑、連接埠、方括號與登入資訊。",
  },
  invalid_cidr: {
    en: "{target} is not a valid IP CIDR range. Use an address and valid prefix, such as 203.0.113.0/28 or 2001:db8::/64.",
    zhTW: "{target} 不是有效的 IP CIDR 網段。請使用 IP 位址與有效前綴，例如 203.0.113.0/28 或 2001:db8::/64。",
  },
  invalid_target: {
    en: "{target} is not a valid fully qualified hostname, IP address, or CIDR range.",
    zhTW: "{target} 不是有效的完整主機名稱、IP 位址或 CIDR 網段。",
  },
} as const satisfies Record<ExternalTargetInputError, BilingualText>;

const workflowCopy = [
  { step: "01", title: { en: "Find", zhTW: "盤點" }, detail: { en: "Build a candidate list from real sources", zhTW: "從真實來源建立候選清單" } },
  { step: "02", title: { en: "Authorize", zhTW: "授權" }, detail: { en: "Confirm each legal scan boundary", zhTW: "逐項確認合法掃描範圍" } },
  { step: "03", title: { en: "Scan", zhTW: "掃描" }, detail: { en: "Run only tools that match the assets and permission", zhTW: "只執行符合資產與權限的工具" } },
  { step: "04", title: { en: "Share", zhTW: "交接" }, detail: { en: "Export complete evidence and next steps", zhTW: "匯出完整證據與下一步" } },
  { step: "05", title: { en: "Verify", zhTW: "複驗" }, detail: { en: "Compare the same case after fixes", zhTW: "在同一案件比較修復前後" } },
] as const;

const useCaseNeeds = (definition: UseCaseDefinition | undefined, id: UseCaseId): boolean =>
  definition?.id === id;

interface EnvironmentHostDraft {
  id: number;
  target: string;
  ports: string;
}

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
  preparingLocalSnapshot,
  nativeMode,
  onClearPreset,
  onCreate,
  onCreateWithWorkspace,
  onCreateWithWorkspaces,
  onChooseWorkspace,
  onSeedDemo,
  onArchive,
  onDelete,
  onDeleteArtifacts,
  onDismissArtifactCleanup,
  onStartNewScan,
  onOpenCase,
  onContinue,
  onOpenProgress,
  onOpenResults,
  onSelectVerificationBaseline,
  onStartRescan,
  onOpenVerification,
}: CasesPageProps) {
  const { locale, t, text, formatDateTime, formatNumber } = useI18n();
  const displayedCaseLabels = caseDisplayLabels(cases, locale);
  const selectedCaseIdentity = selectedCase
    ? caseIdentityPresentation(selectedCase, locale)
    : undefined;
  const [showForm, setShowForm] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [name, setName] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [companySize, setCompanySize] = useState<CompanySize>("unknown");
  const [platforms, setPlatforms] = useState<CloudPlatform[]>(["aws"]);
  const [dataClasses, setDataClasses] = useState<DataClass[]>(["none"]);
  const [requestedActivities, setRequestedActivities] = useState<AssessmentActivity[]>(["configuration_assessment"]);
  const [aiGeneratedArtifact, setAiGeneratedArtifact] =
    useState<AiGeneratedArtifactAnswer>("unknown");
  const [description, setDescription] = useState("");
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [environmentWebsiteUrls, setEnvironmentWebsiteUrls] = useState("");
  const [environmentHosts, setEnvironmentHosts] =
    useState<EnvironmentHostDraft[]>([{ id: 0, target: "", ports: "" }]);
  const [publicTargets, setPublicTargets] = useState("");
  const [internalTargets, setInternalTargets] = useState("");
  const [localNetworkInventory, setLocalNetworkInventory] = useState<LocalNetworkCandidateInventory>();
  const [detectingLocalNetwork, setDetectingLocalNetwork] = useState(false);
  const [repositories, setRepositories] = useState("");
  const [iacProjects, setIacProjects] = useState("");
  const [containerImages, setContainerImages] = useState("");
  const [kubernetesClusters, setKubernetesClusters] = useState("");
  const [selectedWorkspacePath, setSelectedWorkspacePath] = useState("");
  const [environmentWorkspacePaths, setEnvironmentWorkspacePaths] = useState<string[]>([]);
  const [choosingWorkspace, setChoosingWorkspace] = useState(false);
  const [workspacePickerError, setWorkspacePickerError] = useState<BilingualText>();
  const [assetDraftError, setAssetDraftError] = useState<CaseAssetDraftError>();
  const [pendingDeleteId, setPendingDeleteId] = useState<string>();
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [artifactDeleteConfirmation, setArtifactDeleteConfirmation] = useState("");
  const websiteInputRef = useRef<HTMLInputElement>(null);
  const environmentWebsiteInputRef = useRef<HTMLTextAreaElement>(null);
  const environmentHostAddButtonRef = useRef<HTMLButtonElement>(null);
  const environmentHostTargetRefs = useRef(new Map<number, HTMLInputElement>());
  const environmentHostPortsRefs = useRef(new Map<number, HTMLInputElement>());
  const environmentHostAdvancedRefs = useRef(new Map<number, HTMLDetailsElement>());
  const environmentInventoryDetailsRef = useRef<HTMLDetailsElement>(null);
  const nextEnvironmentHostId = useRef(1);
  const publicTargetsInputRef = useRef<HTMLTextAreaElement>(null);
  const internalTargetsInputRef = useRef<HTMLTextAreaElement>(null);

  const selectedDefinition = useMemo(
    () => selectedUseCase ? useCaseById(selectedUseCase) : undefined,
    [selectedUseCase],
  );
  const guidedLocalUseCase = Boolean(
    selectedUseCase && guidedLocalUseCaseIds.includes(selectedUseCase),
  );
  const environmentUseCase = selectedUseCase === "internal_it_environment";
  const guidedLocalProfile = selectedUseCase
    ? localProfileByAssessmentIntent[selectedUseCase]
    : undefined;
  const guidedLocalInput = guidedLocalProfile
    ? localInputDefinitionForAssessmentIntent(guidedLocalProfile, selectedUseCase)
    : undefined;
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
  const guidedPublicWebsite = selectedUseCase === "deployed_website"
    && preparedWebsite?.ok === true
    && !explicitTargetRequiresSensitiveNetworkAllowance(preparedWebsite.value.target);
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
  const browserDeletableCaseIds = useMemo(
    () => nativeMode
      ? new Set<string>()
      : new Set(loadStoredDemoCases().map((assessmentCase) => assessmentCase.id)),
    [cases, nativeMode],
  );
  const environmentWorkspaceLabels = localPathDisplayLabels(
    environmentWorkspacePaths,
    text(pageCopy.folderFallback),
  );

  useEffect(() => {
    setArtifactDeleteConfirmation("");
  }, [artifactCleanupPlan?.caseId]);

  useEffect(() => {
    if (assetDraftError?.kind !== "missing_target" && assetDraftError?.kind !== "invalid_target") return;
    if (assetDraftError.target === "internal" && environmentUseCase) {
      if (environmentInventoryDetailsRef.current) environmentInventoryDetailsRef.current.open = true;
    }
    (assetDraftError.target === "public" ? publicTargetsInputRef : internalTargetsInputRef).current?.focus();
  }, [advancedOpen, assetDraftError, environmentUseCase]);

  useEffect(() => {
    if (!selectedDefinition) return;
    setShowForm(true);
    setAdvancedOpen(false);
    setPlatforms(selectedDefinition.id === "cloud_account"
      ? [selectedDefinition.suggestedPlatforms[0] ?? "aws"]
      : [...selectedDefinition.suggestedPlatforms]);
    setRequestedActivities([...selectedDefinition.suggestedActivities]);
    setAiGeneratedArtifact("unknown");
    setWebsiteUrl("");
    setEnvironmentWebsiteUrls("");
    setEnvironmentHosts([{ id: 0, target: "", ports: "" }]);
    environmentHostTargetRefs.current.clear();
    environmentHostPortsRefs.current.clear();
    environmentHostAdvancedRefs.current.clear();
    nextEnvironmentHostId.current = 1;
    setPublicTargets("");
    setInternalTargets("");
    setRepositories("");
    setIacProjects("");
    setContainerImages("");
    setKubernetesClusters("");
    setSelectedWorkspacePath("");
    setEnvironmentWorkspacePaths([]);
    setWorkspacePickerError(undefined);
    setAssetDraftError(undefined);
  }, [selectedDefinition, selectionKey]);

  useEffect(() => {
    let active = true;
    if (selectedDefinition?.id !== "internal_it_environment") {
      setDetectingLocalNetwork(false);
      setLocalNetworkInventory(undefined);
      return () => { active = false; };
    }
    setDetectingLocalNetwork(true);
    setLocalNetworkInventory(undefined);
    void scannerService.detectLocalPrivateSubnets()
      .then(({ data }) => {
        if (active) setLocalNetworkInventory(data);
      })
      .catch(() => {
        if (active) setLocalNetworkInventory({ status: "unavailable", candidates: [] });
      })
      .finally(() => {
        if (active) setDetectingLocalNetwork(false);
      });
    return () => { active = false; };
  }, [selectedDefinition?.id, selectionKey]);

  const platformLabel = (platform: CloudPlatform): string => t(platformKeys[platform]);
  const activityLabel = (activity: AssessmentActivity): string => text(activityCopy[activity].label);

  const useDetectedLocalNetwork = (target: string) => {
    setInternalTargets((current) => {
      const existing = current.split(/\r?\n/u).map((value) => value.trim()).filter(Boolean);
      return existing.includes(target)
        ? current
        : [...existing, target].join("\n");
    });
    setAssetDraftError(undefined);
    internalTargetsInputRef.current?.focus();
  };

  const togglePlatform = (platform: CloudPlatform) => {
    if (platform === "code" && platforms.includes("code")) {
      setAiGeneratedArtifact("unknown");
    }
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
    setEnvironmentWebsiteUrls("");
    setEnvironmentHosts([{ id: 0, target: "", ports: "" }]);
    environmentHostTargetRefs.current.clear();
    environmentHostPortsRefs.current.clear();
    environmentHostAdvancedRefs.current.clear();
    nextEnvironmentHostId.current = 1;
    setPublicTargets("");
    setInternalTargets("");
    setRepositories("");
    setIacProjects("");
    setContainerImages("");
    setKubernetesClusters("");
    setSelectedWorkspacePath("");
    setEnvironmentWorkspacePaths([]);
    setWorkspacePickerError(undefined);
    setAssetDraftError(undefined);
  };

  const addEnvironmentHost = () => {
    const id = nextEnvironmentHostId.current;
    nextEnvironmentHostId.current += 1;
    setEnvironmentHosts((current) => [...current, { id, target: "", ports: "" }]);
    setAssetDraftError(undefined);
    window.setTimeout(() => environmentHostTargetRefs.current.get(id)?.focus(), 0);
  };

  const updateEnvironmentHost = (
    id: number,
    update: Partial<Pick<EnvironmentHostDraft, "target" | "ports">>,
  ) => {
    setEnvironmentHosts((current) => current.map((host) =>
      host.id === id ? { ...host, ...update } : host));
    setAssetDraftError(undefined);
  };

  const removeEnvironmentHost = (id: number) => {
    environmentHostTargetRefs.current.delete(id);
    environmentHostPortsRefs.current.delete(id);
    environmentHostAdvancedRefs.current.delete(id);
    setEnvironmentHosts((current) => current.length === 1
      ? [{ ...current[0]!, target: "", ports: "" }]
      : current.filter((host) => host.id !== id));
    setAssetDraftError(undefined);
    environmentHostAddButtonRef.current?.focus();
  };

  const focusEnvironmentHostInput = (index = 0, field: "target" | "ports" = "target") => {
    const host = environmentHosts[index];
    if (!host) {
      environmentHostAddButtonRef.current?.focus();
      return;
    }
    if (field === "ports") {
      const advanced = environmentHostAdvancedRefs.current.get(host.id);
      if (advanced) advanced.open = true;
      environmentHostPortsRefs.current.get(host.id)?.focus();
    } else {
      environmentHostTargetRefs.current.get(host.id)?.focus();
    }
  };

  const chooseWorkspace = async () => {
    setChoosingWorkspace(true);
    setWorkspacePickerError(undefined);
    try {
      const path = await onChooseWorkspace();
      if (path) setSelectedWorkspacePath(path);
    } catch {
      setWorkspacePickerError(pageCopy.localFolderPickerError);
    } finally {
      setChoosingWorkspace(false);
    }
  };

  const chooseEnvironmentWorkspace = async () => {
    setChoosingWorkspace(true);
    setWorkspacePickerError(undefined);
    try {
      const path = await onChooseWorkspace();
      if (!path) return;
      setEnvironmentWorkspacePaths((current) => current.includes(path) ? current : [...current, path]);
      setAssetDraftError(undefined);
    } catch {
      setWorkspacePickerError(pageCopy.localFolderPickerError);
    } finally {
      setChoosingWorkspace(false);
    }
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
    if (platforms.length === 0 || requestedActivities.length === 0) return;
    if (nativeMode && guidedLocalProfile && !selectedWorkspacePath) {
      setWorkspacePickerError(pageCopy.localFolderRequired);
      return;
    }

    const assets = buildKnownAssets({
      selectedUseCase,
      websiteUrl,
      websiteUrls: environmentWebsiteUrls,
      internalHosts: environmentHosts.map(({ target, ports }) => ({ target, ports })),
      hasLocalWorkspace: environmentWorkspacePaths.length > 0,
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
        (environmentUseCase ? environmentWebsiteInputRef : websiteInputRef).current?.focus();
      } else if (assets.error.kind === "internal_host") {
        focusEnvironmentHostInput(assets.error.index, assets.error.field);
      } else if (assets.error.kind === "missing_environment") {
        focusEnvironmentHostInput();
      } else if (assets.error.kind === "missing_target" || assets.error.kind === "invalid_target") {
        if (
          (assets.error.target === "public" && !useCaseNeeds(selectedDefinition, "external_ip_or_domain"))
          || (assets.error.target === "internal" && !useCaseNeeds(selectedDefinition, "internal_it_environment"))
        ) setAdvancedOpen(true);
        (assets.error.target === "public" ? publicTargetsInputRef : internalTargetsInputRef).current?.focus();
      } else {
        setAdvancedOpen(true);
      }
      return;
    }

    setAssetDraftError(undefined);
    setWorkspacePickerError(undefined);
    const firstWorkspacePath = environmentWorkspacePaths[0] ?? selectedWorkspacePath;
    const selectedFolderName = firstWorkspacePath
      ? environmentWorkspaceLabels[0]
        ?? localPathDisplayName(firstWorkspacePath, text(pageCopy.folderFallback))
      : undefined;
    const projectName = name.trim()
      || selectedFolderName
      || assets.knownAssets[0]?.value
      || selectedUseCaseTitle
      || text(pageCopy.defaultCaseName);
    const input: CreateCaseInput = {
      name: projectName,
      assessmentIntent: selectedUseCase,
      aiGeneratedArtifact: platforms.includes("code") ? aiGeneratedArtifact : "unknown",
      organizationName: organizationName.trim(),
      companySize,
      platforms,
      requestedActivities,
      knownAssets: assets.knownAssets,
      dataClasses: dataClasses.length ? dataClasses : ["none"],
      description: description.trim() || undefined,
    };
    const environmentWorkspaces = environmentWorkspacePaths.map((selectedPath, index) => ({
      label: environmentWorkspaceLabels[index]
        ?? localPathDisplayName(selectedPath, text(pageCopy.folderFallback)),
      selectedPath,
      inputProfile: "repository_working_tree" as const,
    }));
    const created = nativeMode && environmentUseCase && environmentWorkspaces.length > 0 && onCreateWithWorkspaces
      ? await onCreateWithWorkspaces(input, environmentWorkspaces)
      : nativeMode && guidedLocalProfile
      ? await onCreateWithWorkspace(input, {
        label: projectName,
        selectedPath: selectedWorkspacePath,
        inputProfile: guidedLocalProfile,
      })
      : await onCreate(input);
    if (!created) return;

    setShowForm(false);
    setAdvancedOpen(false);
    setName("");
    setOrganizationName("");
    setCompanySize("unknown");
    setPlatforms(["aws"]);
    setDataClasses(["none"]);
    setRequestedActivities(["configuration_assessment"]);
    setAiGeneratedArtifact("unknown");
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

  const detectedLocalNetwork = localNetworkInventory?.status === "ready"
    ? localNetworkInventory.candidates[0]
    : undefined;
  const detectedLocalNetworkAdded = Boolean(
    detectedLocalNetwork
    && internalTargets.split(/\r?\n/u).some((value) => value.trim() === detectedLocalNetwork.target),
  );

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
        <InlineNotice tone="info" title={text(pageCopy.websitePreparedTitle, { target: preparedWebsite.value.target })}>
          <p>{explicitTargetRequiresSensitiveNetworkAllowance(preparedWebsite.value.target)
            ? text(pageCopy.websitePreparedInternal, {
              origin: websiteQuickOrigin(
                preparedWebsite.value.target,
                preparedWebsite.value.service.protocol,
                preparedWebsite.value.service.port,
              ),
              path: preparedWebsite.value.service.path,
            })
            : text(pageCopy.websitePrepared, {
              origin: websiteQuickOrigin(
                preparedWebsite.value.target,
                preparedWebsite.value.service.protocol,
                preparedWebsite.value.service.port,
              ),
              path: preparedWebsite.value.service.path,
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
            aria-invalid={(
              (assetDraftError?.kind === "missing_target" || assetDraftError?.kind === "invalid_target")
              && assetDraftError.target === "public"
            ) || undefined}
            aria-describedby={
              (assetDraftError?.kind === "missing_target" || assetDraftError?.kind === "invalid_target")
              && assetDraftError.target === "public"
                ? "public-targets-help public-targets-error"
                : "public-targets-help"
            }
            onInvalid={() => setAssetDraftError({ kind: "missing_target", target: "public" })}
            onChange={(event) => { setPublicTargets(event.target.value); setAssetDraftError(undefined); }}
            placeholder={text(pageCopy.publicTargetsPlaceholder)}
          />
          <small id="public-targets-help">{text(pageCopy.publicTargetsHelp)}</small>
          {assetDraftError?.kind === "missing_target" && assetDraftError.target === "public" && (
            <small id="public-targets-error" className="field-error" role="alert">{text(pageCopy.publicTargetRequired)}</small>
          )}
          {assetDraftError?.kind === "invalid_target" && assetDraftError.target === "public" && (
            <small id="public-targets-error" className="field-error" role="alert">
              {text(targetInputErrorCopy[assetDraftError.error], { target: assetDraftError.value })}
            </small>
          )}
        </label>
      )}

      {useCaseNeeds(selectedDefinition, "internal_it_environment") && (
        <div className="environment-target-builder">
          <section className="environment-target-group" aria-labelledby="environment-repositories-title">
            <div className="environment-target-group__heading">
              <div>
                <h3 id="environment-repositories-title">{text(pageCopy.environmentRepositoriesTitle)}</h3>
                <p>{text(pageCopy.environmentRepositoriesBody)}</p>
              </div>
              <button
                className="button button--secondary button--small"
                type="button"
                disabled={!nativeMode || busy || choosingWorkspace}
                onClick={() => void chooseEnvironmentWorkspace()}
              >
                <Icon name="plus" size={15} />
                {choosingWorkspace ? text(pageCopy.choosingFolder) : text(pageCopy.environmentAddRepository)}
              </button>
            </div>
            {!nativeMode && (
              <small>{text(pageCopy.browserLocalBody)}</small>
            )}
            {environmentWorkspacePaths.length > 0 && (
              <ul className="environment-folder-list">
                {environmentWorkspacePaths.map((path, index) => {
                  const folderName = environmentWorkspaceLabels[index]
                    ?? localPathDisplayName(path, text(pageCopy.folderFallback));
                  return (
                    <li key={path}>
                      <span><Icon name="file" size={15} /> {folderName}</span>
                      <button
                        className="button button--ghost button--small"
                        type="button"
                        aria-label={text(pageCopy.environmentRemoveRepository, { name: folderName })}
                        onClick={() => setEnvironmentWorkspacePaths((current) => current.filter((item) => item !== path))}
                      >
                        <Icon name="close" size={14} />
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
            {workspacePickerError && (
              <small className="field-error" role="alert">{text(workspacePickerError)}</small>
            )}
          </section>

          <label className="field environment-target-group">
            <span>{text(pageCopy.environmentWebsitesTitle)}</span>
            <textarea
              ref={environmentWebsiteInputRef}
              rows={3}
              value={environmentWebsiteUrls}
              aria-invalid={assetDraftError?.kind === "website" || undefined}
              onChange={(event) => { setEnvironmentWebsiteUrls(event.target.value); setAssetDraftError(undefined); }}
              placeholder={text(pageCopy.environmentWebsitesPlaceholder)}
            />
            <small>{text(pageCopy.environmentWebsitesHelp)}</small>
            {assetDraftError?.kind === "website" && (
              <small className="field-error" role="alert">
                {text(websiteErrorCopy[assetDraftError.error])}
              </small>
            )}
          </label>

          <section className="environment-target-group" aria-labelledby="environment-hosts-title">
            <div className="environment-target-group__heading">
              <div>
                <h3 id="environment-hosts-title">{text(pageCopy.environmentHostsTitle)}</h3>
                <p>{text(pageCopy.environmentHostsBody)}</p>
              </div>
              <button
                ref={environmentHostAddButtonRef}
                className="button button--secondary button--small"
                type="button"
                onClick={addEnvironmentHost}
              >
                <Icon name="plus" size={15} />
                {text(pageCopy.environmentAddHost)}
              </button>
            </div>

            <div className="environment-device-list">
              {environmentHosts.map((host, index) => {
                const number = index + 1;
                const submittedError = assetDraftError?.kind === "internal_host"
                  && assetDraftError.index === index
                  ? assetDraftError
                  : undefined;
                const preparedTarget = host.target.trim()
                  ? prepareInternalHostTarget(host.target)
                  : undefined;
                const preparedPorts = host.ports.trim()
                  ? parseInternalHostPorts(host.ports)
                  : undefined;
                const targetError = submittedError?.field === "target"
                  ? submittedError.error
                  : preparedTarget?.ok === false
                    ? preparedTarget.error
                    : undefined;
                const portsError = submittedError?.field === "ports"
                  ? submittedError.error
                  : preparedPorts?.ok === false
                    ? preparedPorts.error
                    : undefined;
                const targetHelpId = `environment-host-target-help-${host.id}`;
                const targetErrorId = targetError ? `environment-host-target-error-${host.id}` : undefined;
                const portsHelpId = `environment-host-ports-help-${host.id}`;
                const portsErrorId = portsError ? `environment-host-ports-error-${host.id}` : undefined;
                return (
                  <div className="environment-device-row environment-host-row" key={host.id}>
                    <label className="field environment-host-row__target">
                      <span>{text(pageCopy.environmentHostTarget, { number })}</span>
                      <input
                        ref={(node) => {
                          if (node) environmentHostTargetRefs.current.set(host.id, node);
                          else environmentHostTargetRefs.current.delete(host.id);
                        }}
                        type="text"
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck={false}
                        value={host.target}
                        aria-invalid={Boolean(targetError) || undefined}
                        aria-describedby={[targetHelpId, targetErrorId].filter(Boolean).join(" ")}
                        onChange={(event) => updateEnvironmentHost(host.id, { target: event.target.value })}
                        placeholder={internalHostGreenboneProfile.exampleTarget}
                      />
                      <small id={targetHelpId}>{text(pageCopy.environmentHostTargetHelp)}</small>
                      {targetError && (
                        <small id={targetErrorId} className="field-error" role="alert">
                          {text(internalHostErrorCopy[targetError])}
                        </small>
                      )}
                    </label>
                    <button
                      className="button button--ghost button--small environment-device-row__remove"
                      type="button"
                      aria-label={text(pageCopy.environmentRemoveHost, { number })}
                      onClick={() => removeEnvironmentHost(host.id)}
                    >
                      <Icon name="close" size={14} />
                      <span>{text(pageCopy.environmentRemoveHost, { number })}</span>
                    </button>
                    <details
                      ref={(node) => {
                        if (node) environmentHostAdvancedRefs.current.set(host.id, node);
                        else environmentHostAdvancedRefs.current.delete(host.id);
                      }}
                      className="environment-host-row__advanced"
                    >
                      <summary>{text(pageCopy.environmentHostAdvanced)}</summary>
                      <label className="field">
                        <span>{text(pageCopy.environmentHostPorts)}</span>
                        <input
                          ref={(node) => {
                            if (node) environmentHostPortsRefs.current.set(host.id, node);
                            else environmentHostPortsRefs.current.delete(host.id);
                          }}
                          type="text"
                          inputMode="numeric"
                          value={host.ports}
                          aria-invalid={Boolean(portsError) || undefined}
                          aria-describedby={[portsHelpId, portsErrorId].filter(Boolean).join(" ")}
                          onChange={(event) => updateEnvironmentHost(host.id, { ports: event.target.value })}
                          placeholder={internalHostGreenboneProfile.defaultPorts.join(", ")}
                        />
                        <small id={portsHelpId}>{text(pageCopy.environmentHostPortsHelp, {
                          ports: internalHostGreenboneProfile.defaultPorts.join(", "),
                        })}</small>
                        {portsError && (
                          <small id={portsErrorId} className="field-error" role="alert">
                            {text(internalHostPortsErrorCopy[portsError])}
                          </small>
                        )}
                      </label>
                    </details>
                    <small className="environment-device-row__coverage">
                      <strong>{text(pageCopy.environmentHostCoverage)}</strong>{" "}
                      {text(internalHostGreenboneProfile.coverageNote)}
                    </small>
                  </div>
                );
              })}
            </div>
          </section>

          <details ref={environmentInventoryDetailsRef} className="environment-target-group environment-inventory">
            <summary>
              <span>
                <strong>{text(pageCopy.environmentInventoryTitle)}</strong>
                <small>{text(pageCopy.environmentInventoryHint)}</small>
              </span>
              <Icon name="chevron" size={17} />
            </summary>
            <div className="environment-inventory__body">
              <label className="field">
                <span>{text(pageCopy.internalTargets)}</span>
                <textarea
                  ref={internalTargetsInputRef}
                  rows={3}
                  value={internalTargets}
                  aria-invalid={assetDraftError?.kind === "invalid_target" && assetDraftError.target === "internal" || undefined}
                  aria-describedby={assetDraftError?.kind === "invalid_target" && assetDraftError.target === "internal"
                    ? "internal-targets-help internal-targets-error"
                    : "internal-targets-help"}
                  onChange={(event) => { setInternalTargets(event.target.value); setAssetDraftError(undefined); }}
                  placeholder={text(pageCopy.internalTargetsPlaceholder)}
                />
                <small id="internal-targets-help">{text(pageCopy.environmentInventoryHelp)}</small>
                {assetDraftError?.kind === "invalid_target" && assetDraftError.target === "internal" && (
                  <small id="internal-targets-error" className="field-error" role="alert">
                    {text(targetInputErrorCopy[assetDraftError.error], { target: assetDraftError.value })}
                  </small>
                )}
              </label>

              <details className="environment-network-suggestion">
                <summary>{text(pageCopy.localNetworkFoundTitle)}</summary>
                <div aria-live="polite">
                  {detectingLocalNetwork && <p>{text(pageCopy.localNetworkDetectingBody)}</p>}
                  {!detectingLocalNetwork && detectedLocalNetwork && (
                    <>
                      <p>{text(pageCopy.localNetworkFoundBody, { target: detectedLocalNetwork.target })}</p>
                      <button
                        className="button button--secondary button--small"
                        type="button"
                        disabled={detectedLocalNetworkAdded}
                        onClick={() => useDetectedLocalNetwork(detectedLocalNetwork.target)}
                      >
                        <Icon name={detectedLocalNetworkAdded ? "check" : "plus"} size={15} />
                        {text(
                          detectedLocalNetworkAdded ? pageCopy.localNetworkTargetAdded : pageCopy.localNetworkUseTarget,
                          { target: detectedLocalNetwork.target },
                        )}
                      </button>
                    </>
                  )}
                  {!detectingLocalNetwork && localNetworkInventory?.status === "none" && <p>{text(pageCopy.localNetworkNoneBody)}</p>}
                  {!detectingLocalNetwork && localNetworkInventory?.status === "ambiguous" && <p>{text(pageCopy.localNetworkAmbiguousBody)}</p>}
                  {!detectingLocalNetwork && localNetworkInventory?.status === "unavailable" && <p>{text(pageCopy.localNetworkUnavailableBody)}</p>}
                  {!detectingLocalNetwork && localNetworkInventory?.status === "unsupported" && <p>{text(pageCopy.localNetworkUnsupportedBody)}</p>}
                </div>
              </details>
            </div>
          </details>

          {assetDraftError?.kind === "missing_environment" && (
            <p className="form-error" role="alert"><Icon name="warning" size={16} /> {text(pageCopy.environmentAtLeastOne)}</p>
          )}
        </div>
      )}

      {guidedLocalInput && (
        <div className="case-local-picker">
          <p>{text(guidedLocalInput.formIntro)}</p>

          <InlineNotice tone="warning" title={text(guidedLocalInput.cautionTitle)}>
            <p>{text(guidedLocalInput.cautionBody)}</p>
          </InlineNotice>

          {!nativeMode && (
            <InlineNotice tone="info" title={text(pageCopy.browserLocalTitle)}>
              <p>{text(pageCopy.browserLocalBody)}</p>
            </InlineNotice>
          )}

          <div className="field">
            <span id="new-scan-workspace-label">{text(guidedLocalInput.directoryLabel)}</span>
            <button
              className="snapshot-picker"
              type="button"
              disabled={!nativeMode || busy || choosingWorkspace}
              aria-describedby={workspacePickerError
                ? "new-scan-workspace-help new-scan-workspace-error"
                : "new-scan-workspace-help"}
              onClick={() => void chooseWorkspace()}
            >
              <Icon name="database" size={18} />
              <span>{selectedWorkspacePath
                ? localPathDisplayName(selectedWorkspacePath, text(pageCopy.folderFallback))
                : choosingWorkspace
                  ? text(pageCopy.choosingFolder)
                  : text(guidedLocalInput.selection)}</span>
              <Icon name="chevron" size={16} />
            </button>
            <small id="new-scan-workspace-help">{text(pageCopy.localPathHelp)}</small>
          </div>

          {workspacePickerError && (
            <p id="new-scan-workspace-error" className="form-error" role="alert">
              <Icon name="warning" size={16} />
              {text(workspacePickerError)}
            </p>
          )}
        </div>
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
        eyebrow={text(showForm ? pageCopy.newCaseEyebrow : pageCopy.headerEyebrow)}
        title={text(showForm ? pageCopy.newCaseTitle : pageCopy.headerTitle)}
        description={showForm ? text(pageCopy.newCaseDescription) : undefined}
        actions={
          <button className="button button--primary" type="button" disabled={showForm && busy} onClick={showForm ? closeForm : openBlankForm}>
            <Icon name={showForm ? "close" : "plus"} size={18} />
            {text(showForm ? pageCopy.closeForm : pageCopy.create)}
          </button>
        }
      />

      {showForm && (
        <form className="create-case-panel" aria-busy={preparingLocalSnapshot || undefined} onSubmit={submit}>
          <fieldset className="create-case-panel__locked-fields" disabled={busy}>
          {preparingLocalSnapshot && (
            <InlineNotice tone="info" title={text(pageCopy.preparingLocalSnapshotTitle)} announce>
              <p>{text(pageCopy.preparingLocalSnapshotBody)}</p>
            </InlineNotice>
          )}
          {selectedDefinition && onClearPreset && (
            <div className="create-case-panel__top-actions">
              <button className="button button--ghost button--small" type="button" onClick={changeUseCase}>
                <Icon name="refresh" size={15} />
                {text(pageCopy.changeUseCase)}
              </button>
            </div>
          )}

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
                  <span>{text(pageCopy.caseName)}</span>
                  <input value={name} onChange={(event) => setName(event.target.value)} placeholder={text(pageCopy.caseNamePlaceholder)} />
                </label>
                <label className="field">
                  <span>{text(pageCopy.organizationName)}</span>
                  <input value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} placeholder={text(pageCopy.organizationPlaceholder)} />
                </label>
              </div>

              {platforms.includes("code") && (
                <fieldset className="choice-fieldset">
                  <legend>{text(pageCopy.aiGeneratedQuestion)}</legend>
                  <p>{text(pageCopy.aiGeneratedHelp)}</p>
                  <div className="choice-grid choice-grid--compact">
                    {(["yes", "no", "unknown"] as const).map((answer) => (
                      <label className="check-card check-card--compact" key={answer}>
                        <input
                          type="radio"
                          name="ai-generated-artifact"
                          checked={aiGeneratedArtifact === answer}
                          onChange={() => setAiGeneratedArtifact(answer)}
                        />
                        <span>{text(aiGeneratedAnswerCopy[answer])}</span>
                      </label>
                    ))}
                  </div>
                </fieldset>
              )}

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
                      <textarea
                        ref={publicTargetsInputRef}
                        rows={4}
                        value={publicTargets}
                        aria-invalid={assetDraftError?.kind === "invalid_target" && assetDraftError.target === "public" || undefined}
                        aria-describedby={assetDraftError?.kind === "invalid_target" && assetDraftError.target === "public"
                          ? "public-targets-help public-targets-error"
                          : "public-targets-help"}
                        onChange={(event) => { setPublicTargets(event.target.value); setAssetDraftError(undefined); }}
                        placeholder={text(pageCopy.publicTargetsPlaceholder)}
                      />
                      <small id="public-targets-help">{text(pageCopy.publicTargetsHelp)}</small>
                      {assetDraftError?.kind === "invalid_target" && assetDraftError.target === "public" && (
                        <small id="public-targets-error" className="field-error" role="alert">
                          {text(targetInputErrorCopy[assetDraftError.error], { target: assetDraftError.value })}
                        </small>
                      )}
                    </label>
                  )}
                  {platforms.includes("external") && !useCaseNeeds(selectedDefinition, "internal_it_environment") && (
                    <label className="field">
                      <span>{text(pageCopy.internalTargets)}</span>
                      <textarea
                        ref={internalTargetsInputRef}
                        rows={4}
                        value={internalTargets}
                        aria-invalid={assetDraftError?.kind === "invalid_target" && assetDraftError.target === "internal" || undefined}
                        aria-describedby={assetDraftError?.kind === "invalid_target" && assetDraftError.target === "internal"
                          ? "internal-targets-help internal-targets-error"
                          : "internal-targets-help"}
                        onChange={(event) => { setInternalTargets(event.target.value); setAssetDraftError(undefined); }}
                        placeholder={text(pageCopy.internalTargetsPlaceholder)}
                      />
                      <small id="internal-targets-help">{text(pageCopy.internalTargetsHelp)}</small>
                      {assetDraftError?.kind === "invalid_target" && assetDraftError.target === "internal" && (
                        <small id="internal-targets-error" className="field-error" role="alert">
                          {text(targetInputErrorCopy[assetDraftError.error], { target: assetDraftError.value })}
                        </small>
                      )}
                    </label>
                  )}
                  {platforms.includes("code") && !environmentUseCase && !useCaseNeeds(selectedDefinition, "source_code") && (
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
                {requestedActivities.includes("active_external_vulnerability_tests") && !guidedPublicWebsite && (
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
            <button className="button button--primary" type="submit" disabled={busy || platforms.length === 0 || requestedActivities.length === 0}>
              {text(preparingLocalSnapshot
                ? pageCopy.preparingLocalSnapshot
                : busy
                ? pageCopy.creating
                : environmentUseCase
                  ? pageCopy.reviewEnvironment
                : !nativeMode && guidedLocalUseCase
                  ? pageCopy.createPreview
                  : guidedLocalInput?.createAction ?? pageCopy.createLocal)}
              <Icon name="arrow" size={17} />
            </button>
          </div>
          </fieldset>
        </form>
      )}

      {!showForm && (
        <>
      {selectedCase && (
        <section className="current-case-hero" aria-labelledby="current-case-title">
          <div>
            <div className="current-case-hero__meta">
              <StatusPill label={t(phaseKeys[selectedCase.phase])} tone={phaseMeta[selectedCase.phase].tone} />
              {selectedCase.isDemo && <StatusPill label={text(pageCopy.demo)} tone="demo" />}
              {latestRun && <StatusPill label={text(pageCopy.latestRun, { status: t(runStatusKeys[latestRun.status]) })} tone={runStatusMeta[latestRun.status].tone} />}
            </div>
            <h2 id="current-case-title">
              {displayedCaseLabels.get(selectedCase.id) ?? selectedCaseIdentity?.name}
            </h2>
            <p>{selectedCaseIdentity?.organizationName ? `${selectedCaseIdentity.organizationName} · ` : ""}{text(pageCopy.updated, { date: formatDateTime(selectedCase.updatedAt) })}</p>
            <div className="platform-list" aria-label={text(pageCopy.caseSystems)}>
              {selectedCase.platforms.slice(0, 3).map((platform) => <span key={platform}>{platformLabel(platform)}</span>)}
              {selectedCase.platforms.length > 3 && <span>+{formatNumber(selectedCase.platforms.length - 3)}</span>}
            </div>
          </div>
          <button
            className="button button--light"
            type="button"
            onClick={interruptedEngineCount > 0 || activeRun
              ? onOpenProgress
              : terminalRuns.length > 0
                ? onOpenResults
                : onContinue}
          >
            {text(interruptedEngineCount > 0
              ? pageCopy.handleInterrupted
              : activeRun
                ? pageCopy.viewProgress
                : terminalRuns.length > 0
                  ? pageCopy.viewResults
                  : pageCopy.viewCoverage)}
            <Icon name="arrow" size={17} />
          </button>
        </section>
      )}

      {selectedCase && terminalRuns.length > 0 && (
        <details className="section-block page-secondary-feature verification-baseline-panel">
          <summary>
            <span><strong>{text(pageCopy.verificationEyebrow)}</strong><small>{text(pageCopy.verificationTitle)}</small></span>
            <Icon name="chevron" size={19} />
          </summary>
          <div className="verification-baseline-panel__body">
            <p>{text(pageCopy.verificationDescription)}</p>
            <button className="button button--secondary" type="button" onClick={onOpenVerification}>{text(pageCopy.viewDifference)}</button>
          </div>
          <label className="field">
            <span>{text(pageCopy.baseline)}</span>
            <select value={verificationBaselineRunId ?? ""} onChange={(event) => onSelectVerificationBaseline(event.target.value)}>
              {terminalRuns.map((run) => (
                <option key={run.id} value={run.id}>
                  {scanRunIdentityPresentation(run, locale)} · {t(runStatusKeys[run.status])} · {formatDateTime(run.finishedAt ?? run.startedAt)}
                </option>
              ))}
            </select>
            <small>{selectedVerificationBaseline
              ? text(pageCopy.baselineSelected)
              : text(pageCopy.baselineChoose)}</small>
          </label>
          <div className="form-actions">
            <p>{activeRun
              ? text(pageCopy.activeRun, { label: scanRunIdentityPresentation(activeRun, locale) })
              : text(pageCopy.verificationOutcome)}</p>
            <button className="button button--primary" type="button" disabled={busy || Boolean(activeRun) || !selectedVerificationBaseline} onClick={() => selectedVerificationBaseline && void onStartRescan(selectedVerificationBaseline.id)}>
              <Icon name="refresh" size={17} />
              {text(busy ? pageCopy.creating : activeRun ? pageCopy.handleActiveFirst : pageCopy.startVerification)}
            </button>
          </div>
        </details>
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

      {selectedCase && (
        <>
        {runs.length > 0 && (
          <section className="metrics-grid page-outcome-metrics" aria-label={text(pageCopy.summaryAria)}>
            <MetricCard label={text(pageCopy.assetsMetric)} value={formatNumber(assetCount)} icon="database" />
            <MetricCard label={text(pageCopy.findingsMetric)} value={formatNumber(findingCount)} icon="findings" tone={findingCount ? "danger" : "default"} />
          </section>
        )}

        <details className="page-technical-details page-technical-details--guide">
          <summary>{text(pageCopy.scanDiagnostics)}</summary>
          <section className="metrics-grid page-diagnostic-metrics">
            <MetricCard label={text(pageCopy.unknownMetric)} value={formatNumber(unknownSourceCount)} detail={text(pageCopy.unknownMetricHelp)} icon="warning" tone={unknownSourceCount ? "warning" : "default"} />
            <MetricCard label={text(pageCopy.incompleteMetric)} value={formatNumber(incompleteEngineCount)} detail={text(pageCopy.incompleteMetricHelp, { count: formatNumber(connectedNoAssetSourceCount) })} icon="progress" tone={incompleteEngineCount ? "warning" : "default"} />
          </section>
        </details>
        </>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div><h2>{text(pageCopy.allCasesTitle)}</h2></div>
          <span className="count-label">{text(pageCopy.caseCount, { count: formatNumber(cases.length) })}</span>
        </div>

        {cases.length === 0 ? (
          <EmptyState
            icon="cases"
            title={text(pageCopy.noCases)}
            description={text(pageCopy.noCasesHelp)}
            action={(
              <div className="empty-state__actions">
                <button className="button button--primary" type="button" disabled={busy} onClick={openBlankForm}>{text(pageCopy.create)}</button>
                {/* The browser surface already opens its labeled preview fixture; this action is only the explicit entry to the persisted native demo. */}
                {nativeMode && (
                  <div className="empty-state__secondary-action">
                    <button className="button button--secondary" type="button" disabled={busy} onClick={() => void onSeedDemo()}>{t("cases.demoAction")}</button>
                    <small>{t("cases.demoActionHelp")}</small>
                  </div>
                )}
              </div>
            )}
          />
        ) : (
          <div className="case-list">
            {cases.map((assessmentCase) => {
              const active = assessmentCase.id === selectedCase?.id;
              const confirmingDelete = pendingDeleteId === assessmentCase.id;
              const canDelete = nativeMode || browserDeletableCaseIds.has(assessmentCase.id);
              const listedAssets = assessmentCase.assetCount === undefined ? "—" : formatNumber(assessmentCase.assetCount);
              const listedFindings = assessmentCase.findingCount === undefined ? "—" : formatNumber(assessmentCase.findingCount);
              const displayedIdentity = caseIdentityPresentation(assessmentCase, locale);
              const displayedName = displayedCaseLabels.get(assessmentCase.id) ?? displayedIdentity.name;
              return (
                <Fragment key={assessmentCase.id}>
                  <article className={active ? "case-row case-row--active" : "case-row"}>
                    <button type="button" className="case-row__main" disabled={busy} onClick={() => onOpenCase(assessmentCase.id)}>
                      <span className="case-row__icon"><Icon name="cases" /></span>
                      <span className="case-row__copy">
                        <span className="case-row__title"><strong>{displayedName}</strong>{assessmentCase.isDemo && <small>{text(pageCopy.demo)}</small>}</span>
                        {displayedIdentity.organizationName && <span>{displayedIdentity.organizationName}</span>}
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
                        <button className="icon-button case-row__archive" type="button" disabled={busy} aria-label={text(pageCopy.archiveAria, { name: displayedName })} title={text(pageCopy.archiveTitle)} onClick={() => void onArchive(assessmentCase.id)}><Icon name="archive" size={17} /></button>
                      )}
                      {canDelete && (
                        <button
                          className="icon-button icon-button--danger"
                          type="button"
                          disabled={busy}
                          aria-label={text(nativeMode ? pageCopy.beginDeleteAria : pageCopy.beginRemovePreviewAria, { name: displayedName })}
                          title={text(nativeMode ? pageCopy.deleteRecordTitle : pageCopy.removePreviewTitle)}
                          aria-expanded={confirmingDelete}
                          aria-controls={`delete-confirm-${assessmentCase.id}`}
                          onClick={() => confirmingDelete ? cancelDelete() : beginDelete(assessmentCase.id)}
                        >
                          <Icon name={confirmingDelete ? "close" : "trash"} size={17} />
                        </button>
                      )}
                      <button className="icon-button" type="button" disabled={busy} aria-label={text(pageCopy.selectAria, { name: displayedName })} onClick={() => onOpenCase(assessmentCase.id)}><Icon name="chevron" /></button>
                    </div>
                  </article>
                  {canDelete && confirmingDelete && (
                    <form id={`delete-confirm-${assessmentCase.id}`} className="case-delete-confirmation" aria-labelledby={`delete-title-${assessmentCase.id}`} onSubmit={(event) => void submitDelete(event, assessmentCase)}>
                      <div>
                        <p className="eyebrow">{text(nativeMode ? pageCopy.deleteStep : pageCopy.previewDeleteEyebrow)}</p>
                        <h3 id={`delete-title-${assessmentCase.id}`}>{text(nativeMode ? pageCopy.confirmDeleteTitle : pageCopy.confirmRemovePreviewTitle)}</h3>
                        <p>{text(nativeMode ? pageCopy.confirmDeleteHelp : pageCopy.confirmRemovePreviewHelp)}</p>
                      </div>
                      <label className="field"><span>{text(pageCopy.typeCaseName, { name: assessmentCase.name })}</span><input autoFocus autoComplete="off" value={deleteConfirmation} onChange={(event) => setDeleteConfirmation(event.target.value)} /></label>
                      <div className="case-delete-confirmation__actions">
                        <button className="button button--ghost button--small" type="button" disabled={busy} onClick={cancelDelete}>{text(pageCopy.cancel)}</button>
                        <button className="button button--danger button--small" type="submit" disabled={busy || deleteConfirmation !== assessmentCase.name}>
                          <Icon name="trash" size={16} />
                          {text(nativeMode
                            ? busy ? pageCopy.deleting : pageCopy.deleteRecordOnly
                            : busy ? pageCopy.removingPreview : pageCopy.removePreview)}
                        </button>
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
        </>
      )}
    </div>
  );
}
