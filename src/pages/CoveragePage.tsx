import { useEffect, useMemo, useState, type FormEvent } from "react";

import { coverageMeta, platformMeta } from "../lib";
import type {
  AssessmentActivity,
  Asset,
  AttachWorkspaceSnapshotInput,
  ConnectSourceSnapshotInput,
  ConnectedSource,
  CoverageRecord,
  CoverageState,
  ExternalActivity,
  ExternalScopeRequest,
  ScopeGrant,
  ScopeMode,
  SnapshotParserProfile,
  SourceKind,
  TransportProtocol,
} from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import { ProviderAuthorizationPanel } from "../components/ProviderAuthorizationPanel";
import { useI18n, type BilingualText } from "../i18n";
import { isScopeEligible, permittedModes, suggestedModesForAsset } from "../scopePolicy";

import "../coverage-page.css";

interface CoveragePageProps {
  caseId: string;
  requestedActivities: AssessmentActivity[];
  coverage: CoverageRecord[];
  sources: ConnectedSource[];
  assets: Asset[];
  scopeGrants: ScopeGrant[];
  nativeMode: boolean;
  busy?: boolean;
  onChooseSnapshot: () => Promise<string | null>;
  onConnectSourceSnapshot: (input: ConnectSourceSnapshotInput) => Promise<void>;
  onChooseWorkspace: () => Promise<string | null>;
  onAttachWorkspaceSnapshot: (input: AttachWorkspaceSnapshotInput) => Promise<void>;
  onStartDiscovery: () => Promise<void>;
  onAuthorizationChanged: () => Promise<void>;
  onApprovePending: (assetIds: string[], modes: ScopeMode[], confirmation: string, externalScope?: ExternalScopeRequest) => Promise<boolean>;
}

interface SourceDefinition {
  label: BilingualText;
  platform: keyof typeof platformMeta;
  profiles: readonly SnapshotParserProfile[];
  description: BilingualText;
}

const bilingual = <const En extends string, const ZhTW extends string>(en: En, zhTW: ZhTW) => ({ en, zhTW });

const sourceDefinitions = {
  aws_organization: {
    label: bilingual("AWS organization", "AWS 組織"),
    platform: "aws",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: bilingual("A saved export of AWS accounts, Regions, and resources.", "AWS 帳號、區域與資源的既有匯出結果。"),
  },
  azure_tenant: {
    label: bilingual("Azure tenant", "Azure 租用戶"),
    platform: "azure",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: bilingual("A saved export of an Azure tenant, subscriptions, and resources.", "Azure 租用戶、訂閱與資源的既有匯出結果。"),
  },
  gcp_organization: {
    label: bilingual("Google Cloud organization", "Google Cloud 組織"),
    platform: "gcp",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: bilingual("A saved export of a Google Cloud organization, folders, projects, and resources.", "Google Cloud 組織、資料夾、專案與資源的既有匯出結果。"),
  },
  microsoft365_tenant: {
    label: bilingual("Microsoft 365 tenant", "Microsoft 365 租用戶"),
    platform: "m365",
    profiles: ["scubagear", "maester"],
    description: bilingual("Saved tenant results from ScubaGear or Maester.", "ScubaGear 或 Maester 已保存的租用戶結果。"),
  },
  dns: {
    label: bilingual("DNS records", "DNS 紀錄"),
    platform: "external",
    profiles: ["dns-response"],
    description: bilingual("Saved DNS responses for an exact query boundary.", "明確查詢範圍內已保存的 DNS 回應。"),
  },
  certificate_transparency: {
    label: bilingual("Certificate Transparency", "憑證透明度紀錄"),
    platform: "external",
    profiles: ["certificate-transparency-response"],
    description: bilingual("Saved responses from public Certificate Transparency searches.", "已保存的公開憑證透明度查詢回應。"),
  },
  billing: {
    label: bilingual("Billing export", "帳務匯出"),
    platform: "external",
    profiles: ["billing-export"],
    description: bilingual("A saved billing export that can identify asset candidates.", "可用來建立候選資產的帳務匯出快照。"),
  },
  git_repository: {
    label: bilingual("Git repositories", "Git 程式碼儲存庫"),
    platform: "code",
    profiles: ["git-manifest"],
    description: bilingual("A bounded JSON manifest of repositories you selected.", "你所選程式碼儲存庫的受限 JSON 清單。"),
  },
  terraform_state: {
    label: bilingual("Terraform state", "Terraform 狀態檔"),
    platform: "code",
    profiles: ["terraform-state"],
    description: bilingual("A JSON snapshot of Terraform state; remove secret values first.", "Terraform 狀態的 JSON 快照；請先移除秘密值。"),
  },
  kubernetes_cluster: {
    label: bilingual("Kubernetes clusters", "Kubernetes 叢集"),
    platform: "kubernetes",
    profiles: ["kubernetes-manifest"],
    description: bilingual("A saved JSON manifest of clusters and workloads.", "已保存的叢集與工作負載 JSON 清單。"),
  },
  container_registry: {
    label: bilingual("Container registries", "容器映像倉庫"),
    platform: "container",
    profiles: ["container-registry-manifest"],
    description: bilingual("A bounded manifest of registries, repositories, images, and digests.", "映像倉庫、映像名稱與精確內容指紋的受限清單。"),
  },
  file_system: {
    label: bilingual("Local files", "本機檔案"),
    platform: "code",
    profiles: ["filesystem-manifest"],
    description: bilingual("A filesystem manifest containing only the content you explicitly selected.", "只包含你明確選取內容的檔案清單。"),
  },
  user_declared: {
    label: bilingual("Targets entered for this case", "案件中輸入的目標"),
    platform: "external",
    profiles: ["user-declared-manifest"],
    description: bilingual("Candidate assets entered by a person; this does not prove ownership.", "由使用者列出的候選資產；不會自動證明所有權。"),
  },
} as const satisfies Record<SourceKind, SourceDefinition>;

const parserProfileLabels: Record<SnapshotParserProfile, string> = {
  cloudquery: "CloudQuery JSON",
  steampipe: "Steampipe JSON",
  prowler: "Prowler JSON",
  scubagear: "ScubaGear JSON",
  maester: "Maester JSON",
  "dns-response": "DNS response JSON",
  "certificate-transparency-response": "Certificate Transparency response JSON",
  "billing-export": "Billing export JSON",
  "git-manifest": "Git manifest JSON",
  "terraform-state": "Terraform state JSON",
  "kubernetes-manifest": "Kubernetes manifest JSON",
  "container-registry-manifest": "Container registry manifest JSON",
  "filesystem-manifest": "Filesystem manifest JSON",
  "user-declared-manifest": "User-declared manifest JSON",
};

const allSourceKinds = Object.keys(sourceDefinitions) as SourceKind[];
const coverageStates = Object.keys(coverageMeta) as CoverageState[];
type LocalInputProfile = AttachWorkspaceSnapshotInput["inputProfile"];

const localInputDefinitions: Record<LocalInputProfile, { label: BilingualText; detail: BilingualText; selection: BilingualText }> = {
  repository_working_tree: {
    label: bilingual("Source-code project", "程式碼專案"),
    detail: bilingual("Reads only the selected working tree. Git history is excluded.", "只讀取選定的目前工作目錄，不包含 Git 版本紀錄。"),
    selection: bilingual("Choose the repository root folder", "選擇程式碼專案根目錄"),
  },
  iac_working_tree: {
    label: bilingual("Infrastructure-code project", "基礎設施程式碼專案"),
    detail: bilingual("Reads the selected Terraform, JSON, and YAML deployment files without changing them.", "唯讀檢查選定的 Terraform、JSON 與 YAML 部署檔案。"),
    selection: bilingual("Choose the infrastructure-code project folder", "選擇 IaC 專案根目錄"),
  },
  container_image_oci_layout: {
    label: bilingual("Container image (OCI layout)", "容器映像（OCI 配置目錄）"),
    detail: bilingual("Reviews one digest-bound OCI Image Layout without contacting a registry.", "離線檢查一份綁定精確內容指紋的 OCI 映像，不連接映像倉庫。"),
    selection: bilingual("Choose the folder containing oci-layout, index.json, and blobs/", "選擇含 oci-layout、index.json 與 blobs/ 的根目錄"),
  },
  kubernetes_manifests: {
    label: bilingual("Kubernetes manifest files", "Kubernetes 設定檔"),
    detail: bilingual("Reviews the selected YAML and JSON manifests offline. It does not connect to a live cluster.", "離線檢查選定的 YAML 與 JSON 設定檔，不連線到正在運作的叢集。"),
    selection: bilingual("Choose the Kubernetes manifests folder", "選擇 Kubernetes 設定檔根目錄"),
  },
  kubernetes_node_snapshot: {
    label: bilingual("Kubernetes node settings snapshot", "Kubernetes 節點設定快照"),
    detail: bilingual("Reads a bounded CIS node-settings snapshot without mounting the host filesystem.", "讀取有限範圍的 CIS 節點設定快照，不掛載主機檔案系統。"),
    selection: bilingual("Choose the folder containing node-snapshot/", "選擇含 node-snapshot/ 的父目錄"),
  },
};

const localInputEngines: Record<LocalInputProfile, string> = {
  repository_working_tree: "Semgrep, Gitleaks, TruffleHog, Trivy, Syft",
  iac_working_tree: "Checkov, KICS",
  container_image_oci_layout: "Trivy, Grype",
  kubernetes_manifests: "Kubescape",
  kubernetes_node_snapshot: "kube-bench",
};

const scopeModeLabels: Record<ScopeMode, { label: BilingualText; detail: BilingualText }> = {
  inventory: { label: bilingual("Read-only inventory", "唯讀盤點"), detail: bilingual("Read asset names and identifiers only", "只讀取資產清單與識別資訊") },
  configuration: { label: bilingual("Review settings", "檢查設定"), detail: bilingual("Read configuration or an attached snapshot without making changes", "唯讀檢查設定或已附加快照") },
  local_artifact: { label: bilingual("Review the saved local copy", "檢查本機快照"), detail: bilingual("Read only the immutable copy attached to this case", "只讀取案件內不可變的本機快照") },
  public_data: { label: bilingual("Use public records", "使用公開資料"), detail: bilingual("Use saved DNS, certificate, and similar public records only", "只使用 DNS、憑證等既有公開資料") },
  low_impact_external: { label: bilingual("Low-impact connection checks", "低影響連線檢查"), detail: bilingual("Send limited requests only to the confirmed target", "只對已確認目標發出受限連線") },
  active_external: { label: bilingual("Approved active website tests", "已核准的主動網站測試"), detail: bilingual("Requires a traceable permission reference and exact test list", "需要可追溯的明確授權參考與精確測試清單") },
  passive: { label: bilingual("Use public records", "使用公開資料"), detail: bilingual("Legacy-case name for the public-records mode", "相容舊案件的公開資料模式") },
  active: { label: bilingual("Approved active website tests", "已核准的主動網站測試"), detail: bilingual("Legacy-case name for the active-testing mode", "相容舊案件的主動測試模式") },
};

const externalActivities: Partial<Record<ScopeMode, ExternalActivity>> = {
  public_data: "passive_public_discovery",
  passive: "passive_public_discovery",
  low_impact_external: "low_impact_external",
  active_external: "active_external",
  active: "active_external",
};

const rateLimits: Record<ExternalActivity, { rate: number; concurrency: number; timeout: number }> = {
  passive_public_discovery: { rate: 100, concurrency: 20, timeout: 3_600 },
  low_impact_external: { rate: 25, concurrency: 10, timeout: 1_800 },
  active_external: { rate: 10, concurrency: 5, timeout: 3_600 },
};

const activityLabels: Record<ExternalActivity, BilingualText> = {
  passive_public_discovery: bilingual("Public-record review", "公開資料盤點"),
  low_impact_external: bilingual("Low-impact external checks", "低影響外部連線"),
  active_external: bilingual("Approved active external tests", "已核准的主動外部測試"),
};

const NUCLEI_TEMPLATE_REVISION = "nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012";

const pageCopy = {
  headerEyebrow: bilingual("What to scan", "要檢查什麼"),
  headerTitle: bilingual("Add what you want checked, then approve each boundary", "加入要檢查的東西，再逐項確認允許範圍"),
  headerDescription: bilingual(
    "First let the product build a candidate list. Then confirm what it can see and exactly which checks are allowed. Missing visibility is unknown—not a pass.",
    "先讓產品建立候選清單，再確認它看得到什麼，以及每一項到底允許哪些檢查。看不到就是未知，不是通過。",
  ),
  refresh: bilingual("Refresh candidates", "重新整理候選資產"),
  refreshing: bilingual("Refreshing…", "正在重新確認…"),
  journeyLabel: bilingual("Three steps for choosing scan coverage", "選擇掃描範圍的三個步驟"),
  step1Short: bilingual("Add", "加入"),
  step1Title: bilingual("Add what you want checked", "加入你要檢查的東西"),
  step1Detail: bilingual("Use a saved file, a local folder, or temporary read-only cloud access.", "使用已保存的檔案、本機資料夾，或暫時的雲端唯讀存取。"),
  step2Short: bilingual("See", "確認"),
  step2Title: bilingual("Confirm what the product can see", "確認產品看得到什麼"),
  step2Detail: bilingual("A candidate is something observed—not proof that it is yours or safe.", "候選資產只是目前觀察到的東西，不代表屬於你，也不代表安全。"),
  step3Short: bilingual("Allow", "允許"),
  step3Title: bilingual("Confirm allowed checks one item at a time", "逐項確認允許哪些檢查"),
  step3Detail: bilingual("Nothing is authorized merely because you selected a card or candidate.", "選擇卡片或候選資產都不會自動授權。"),
  addEyebrow: bilingual("Step 1", "步驟 1"),
  addTitle: bilingual("How can the product see it?", "產品要怎麼看得到？"),
  addDescription: bilingual("Choose the input you already have. You can add more than one; scan permission always stays separate.", "選擇你現在已有的輸入；可以加入多種來源，但掃描許可永遠另外確認。"),
  providerTitle: bilingual("Cloud account", "雲端帳號"),
  providerBody: bilingual("Connect short-lived, read-only access through the provider's official sign-in page.", "透過雲端服務商的官方登入頁連接短效唯讀存取。"),
  providerOpen: bilingual("Set up cloud read-only access", "設定雲端唯讀存取"),
  providerClose: bilingual("Close cloud access setup", "關閉雲端存取設定"),
  snapshotTitle: bilingual("A saved JSON inventory", "已保存的 JSON 盤點檔"),
  snapshotBody: bilingual("Attach one bounded export from a supported inventory source. The file is parsed locally.", "附加一份支援來源的有界盤點匯出；檔案只在本機解析。"),
  snapshotOpen: bilingual("Choose a saved inventory", "選擇已保存的盤點檔"),
  snapshotClose: bilingual("Close inventory form", "關閉盤點檔表單"),
  workspaceTitle: bilingual("Source, IaC, container, or Kubernetes files", "程式碼、IaC、容器或 Kubernetes 檔案"),
  workspaceBody: bilingual("Make an immutable local copy of only the folder you choose.", "只把你明確選擇的資料夾製成不可變本機副本。"),
  workspaceOpen: bilingual("Choose local files", "選擇本機檔案"),
  workspaceClose: bilingual("Close local-files form", "關閉本機檔案表單"),
  knownTargetsTitle: bilingual("Website, public IP, or internal system already named in this case", "案件中已填入的網站、公開 IP 或內部系統"),
  knownTargetsBody: bilingual("Refresh the candidate list, then confirm each exact target in step 3. This does not contact the target.", "重新整理候選清單，再到步驟 3 確認每個精確目標；這不會連線到目標。"),
  selectDoesNotAuthorizeTitle: bilingual("Adding an input or choosing a card does not authorize a scan", "加入輸入或選擇卡片都不會授權掃描"),
  selectDoesNotAuthorizeBody: bilingual("The product only creates candidates here. Ownership, exact targets, scan type, network limits, and permission are confirmed separately in step 3.", "這裡只會建立候選資產；所有權、精確目標、檢查種類、網路限制與許可都要在步驟 3 另外確認。"),
  situationSummary: bilingual("Show the next step for my situation", "查看不同情境的下一步"),
  situationIntro: bilingual("The same three steps apply to every use case; only the input and permission boundary change.", "每種情境都走相同三步，差別只在輸入方式與需要確認的權限邊界。"),

  sourceEyebrow: bilingual("Saved inventory", "已保存的盤點檔"),
  sourceTitle: bilingual("Attach one saved JSON inventory", "附加一份已保存的 JSON 盤點檔"),
  sourceIntro: bilingual("This is not a live sign-in or an unlimited discovery. The local core reads only the one JSON file you choose, up to 8 MiB, and accepts only the selected format.", "這不是即時登入，也不是無限制盤點。本機核心最多只讀取你選擇的一個 8 MiB JSON 檔，並且只接受指定格式。"),
  noSecretsSnapshotTitle: bilingual("Remove passwords, tokens, private keys, and other secrets first", "請先移除密碼、token、私鑰與其他秘密值"),
  noSecretsSnapshotBody: bilingual("Export only the inventory fields this case needs. Attaching a file creates candidates; it does not prove ownership, authorize a scan, or start one.", "請只匯出案件需要的盤點欄位。附加檔案只會建立候選資產，不會證明所有權、授權或啟動掃描。"),
  demoFileTitle: bilingual("Browser preview cannot read a local file", "瀏覽器預覽不會讀取本機檔案"),
  demoFileBody: bilingual("Open the signed desktop app to attach a real snapshot. This preview only shows the steps.", "請使用已簽章的桌面程式附加真實快照；目前預覽只會顯示步驟。"),
  sourceKind: bilingual("What produced this inventory?", "這份盤點檔來自哪裡？"),
  snapshotFormat: bilingual("Saved-file format", "盤點檔格式"),
  snapshotFormatHelp: bilingual("The choice is limited by the source. The product never guesses with a general-purpose parser.", "格式會依來源限制；產品不會用通用解析器猜測。"),
  inputTechnicalSummary: bilingual("Technical input details", "輸入技術細節"),
  localEngineDetail: bilingual("Bound scanner engines: {engines}.", "綁定的掃描引擎：{engines}。"),
  sourceLabel: bilingual("Name shown in this case", "案件中顯示的名稱"),
  sourceLabelPlaceholder: bilingual("Example: Production AWS inventory", "例如：正式環境 AWS 盤點"),
  sourceLabelHelp: bilingual("Use a recognizable name. Do not include credentials or secrets.", "請使用容易辨識的名稱，不要放入憑證或秘密值。"),
  jsonSnapshot: bilingual("JSON file", "JSON 檔案"),
  choosingPicker: bilingual("Opening the file picker…", "正在開啟檔案選擇器…"),
  chooseJson: bilingual("Choose one .json file", "選擇一份 .json 檔"),
  snapshotPathHelp: bilingual("The product does not scan the folder or save the original path in the canonical case.", "產品不會掃描資料夾，也不會把原始路徑寫入正式案件紀錄。"),
  sourceAfterHelp: bilingual("After attaching it, refresh what the product can see.", "附加後仍要重新確認產品看得到什麼。"),
  connectSnapshot: bilingual("Copy and attach this inventory", "複製並附加這份盤點檔"),
  connectingSnapshot: bilingual("Attaching…", "正在附加…"),
  fileFallback: bilingual("Selected JSON file", "已選取 JSON 檔"),
  sourceErrorJson: bilingual("Choose one .json file. Nothing was read or copied.", "只接受一份 .json 檔；沒有讀取或複製這個檔案。"),
  sourceErrorPicker: bilingual("The local file picker could not open. Nothing was read or copied.", "無法開啟本機檔案選擇器；沒有讀取或複製任何檔案。"),
  sourceErrorLabel: bilingual("Enter a name that identifies this inventory.", "請輸入能辨識這份來源的標籤。"),
  sourceErrorPath: bilingual("Choose one JSON inventory first.", "請先明確選擇一份 JSON 快照。"),

  workspaceEyebrow: bilingual("Saved local copy", "保存本機副本"),
  workspaceFormTitle: bilingual("Attach one exact type of local input", "附加一種明確類型的本機輸入"),
  workspaceIntro: bilingual("The local core copies only the folder you choose, verifies its type, applies file-count, size, and depth limits, and fixes it to this case with content hashes.", "本機核心只會複製你選擇的資料夾、驗證類型、限制檔案數量、大小與深度，再用內容雜湊固定到案件。"),
  gitWarningTitle: bilingual("Only .git metadata is excluded—remove secret files from the working tree first", "只會排除 .git metadata；請先移除工作樹裡的秘密檔案"),
  gitWarningBody: bilingual("Git history, refs, hooks, and credentials inside .git are not opened or copied. Files such as .env, keys, or tokens elsewhere in the working tree are still content, so remove them first.", "所有名為 .git 的項目都不會被開啟或複製，因此 Git history、refs、hooks 與其中 credentials 不會進入快照；但工作樹裡的 .env、金鑰或 token 檔仍屬內容，請先移除。"),
  localNoGrantTitle: bilingual("The input type is fixed, but attaching it does not grant scan permission", "輸入類型會固定，但附加動作不會授予掃描權限"),
  localNoGrantBody: bilingual("The case saves a snapshot ID, input type, content hash, and relative-path manifest—not the original host path. Confirm ownership and read-only local review in step 3.", "案件只保存快照 ID、輸入類型、內容雜湊與相對路徑 manifest，不保存原始主機路徑。請在步驟 3 確認所有權與本機唯讀檢查。"),
  demoFolderTitle: bilingual("Browser preview cannot read a local folder", "瀏覽器預覽不會讀取本機目錄"),
  demoFolderBody: bilingual("Open the signed desktop app to create a real local snapshot. This preview only shows the steps.", "請使用已簽章的桌面程式建立真實本機快照；目前預覽只會顯示步驟。"),
  inputType: bilingual("What are you attaching?", "你要附加什麼？"),
  localLabel: bilingual("Name shown in this case", "案件中顯示的名稱"),
  localLabelPlaceholder: bilingual("Example: Production container image", "例如：Production container image"),
  localLabelHelp: bilingual("Use a recognizable name. Do not include the host path or a secret.", "只用來辨識案件內的候選資產；不要放入主機路徑或秘密值。"),
  localDirectory: bilingual("Folder to copy", "要複製的資料夾"),
  localPathHelp: bilingual("Only the folder name is shown here. The canonical case does not save the original absolute path.", "畫面只顯示目錄名稱；canonical case 不保存原始絕對路徑。"),
  workspaceAfterHelp: bilingual("After the copy is created, confirm ownership and allowed checks in step 3.", "建立副本後，仍要在步驟 3 確認所有權與允許的檢查。"),
  attachWorkspace: bilingual("Create the immutable local copy", "建立不可變本機副本"),
  attachingWorkspace: bilingual("Creating the copy…", "正在建立副本…"),
  folderFallback: bilingual("Selected folder", "已選取資料夾"),
  workspaceErrorPicker: bilingual("The local folder picker could not open. Nothing was read or copied.", "無法開啟本機目錄選擇器；沒有讀取或複製任何目錄。"),
  workspaceErrorLabel: bilingual("Enter a name that identifies this local copy.", "請輸入能辨識這份工作樹的標籤。"),
  workspaceErrorPath: bilingual("Choose one working-tree folder first.", "請先明確選擇一個目前工作目錄。"),

  seeEyebrow: bilingual("Step 2", "步驟 2"),
  seeTitle: bilingual("Confirm what the product can see", "確認產品看得到什麼"),
  seeDescription: bilingual("These are observations from the inputs above. A missing source stays unknown; an empty connected source means only that this input returned no candidates this time.", "以下內容來自上方輸入。缺少來源時仍是未知；已連接來源沒有候選，只代表這次輸入沒有回傳項目。"),
  continueStep3: bilingual("Continue to step 3", "前往步驟 3"),
  candidateAssets: bilingual("Candidates seen", "看到的候選資產"),
  candidateDetail: bilingual("Observed from the inputs attached to this case", "來自這個案件已附加的輸入"),
  scannedAssets: bilingual("Checks completed", "已完成檢查"),
  scannedDetail: bilingual("Permission was recorded and all planned work finished", "已留下許可，而且規劃工作完整完成"),
  incompleteAssets: bilingual("Allowed, but incomplete", "已允許，但未完成"),
  incompleteDetail: bilingual("Resume the work or resolve its execution problem", "需要續跑或排除執行問題"),
  pendingAssets: bilingual("Need your confirmation", "需要你確認"),
  pendingDetail: bilingual("No active check runs before confirmation", "確認前不會開始主動檢查"),
  metricsLabel: bilingual("What the product can currently see", "產品目前看得到的摘要"),
  unknownTitle: bilingual("{count} sources are still unknown", "{count} 個來源目前仍是未知"),
  unknownBody: bilingual("No usable input is connected, so the product does not know whether assets exist. This is not zero assets and not a pass.", "沒有可用輸入，所以產品不知道是否存在資產。這不是零資產，也不是通過。"),
  noneTitle: bilingual("{count} connected sources returned no candidates", "{count} 個已連接來源沒有回傳候選資產"),
  noneBody: bilingual("The input was available and returned zero candidates at this moment. The statement applies only to that saved input and time.", "輸入可以使用，而且此刻回傳零個候選資產；這只代表該份輸入與時間點。"),
  sourcesEyebrow: bilingual("Inputs and visibility", "輸入與可見範圍"),
  sourcesTitle: bilingual("What each input reported", "每個輸入回報了什麼"),
  noSourcesTitle: bilingual("No input has been attached yet", "尚未附加任何輸入"),
  noSourcesBody: bilingual("Attach a bounded inventory or local copy in step 1, then refresh what the product can see.", "請先在步驟 1 附加有界盤點檔或本機副本，再重新確認產品看得到什麼。"),
  assetsCount: bilingual("{count} candidates", "{count} 個候選資產"),
  lastChecked: bilingual("Checked {date}", "確認時間 {date}"),
  notConnected: bilingual("Not connected", "尚未連接"),
  sourceTechnical: bilingual("Technical source details", "來源技術細節"),
  rawSourceDetail: bilingual("Raw saved-source detail", "原始來源細節"),
  acceptedProfiles: bilingual("Accepted profiles", "接受的檔案格式"),
  sourceKindTechnical: bilingual("Source kind", "來源種類"),
  sourceStatusTechnical: bilingual("Connection state", "連接狀態"),
  coverageStateTechnical: bilingual("Coverage state", "涵蓋狀態"),
  coverageDetailsSummary: bilingual("Coverage states and filters", "涵蓋狀態與篩選條件"),
  coverageDetailsIntro: bilingual("Use these technical states when diagnosing why an item has or does not have results.", "排查為什麼某一項有結果或沒有結果時，可使用這些技術狀態。"),
  showAll: bilingual("Show all candidates", "顯示所有候選資產"),

  allowEyebrow: bilingual("Step 3", "步驟 3"),
  allowTitle: bilingual("Confirm what may be checked—one item at a time", "逐項確認允許檢查什麼"),
  allowDescription: bilingual("Choose a candidate, review the suggested read-only or network checks, and record the exact boundary. Selecting it does not authorize anything.", "選擇候選資產、確認建議的唯讀或網路檢查，再留下精確邊界；選取動作本身不會授權。"),
  pendingNoticeTitle: bilingual("Some candidates still need your decision", "有候選資產仍需要你決定"),
  pendingNoticeBody: bilingual("Before ownership is confirmed, the product keeps only existing inventory evidence and does not start connection probes or active vulnerability tests.", "確認所有權前，產品只保留既有盤點證據，不會啟動連線探測或主動弱點測試。"),
  selectedCount: bilingual("{count} selected", "已選 {count} 項"),
  chooseAsset: bilingual("Choose {name}", "選取 {name}"),
  incompatibleSelection: bilingual("External targets need their own exact network boundary. Finish or clear the current selection first.", "外部目標需要自己的精確網路邊界；請先完成或清除目前選取。"),
  addPermission: bilingual("Select this item again to add a missing read-only permission.", "可以再次選取這一項，補上缺少的唯讀許可。"),
  assetNext: bilingual("Next step", "下一步"),
  noOwner: bilingual("Owner not recorded", "尚未記錄負責人"),
  owner: bilingual("Owner", "負責人"),
  region: bilingual("Region", "區域"),
  identifiers: bilingual("Source identifiers", "來源識別碼"),
  allowedModes: bilingual("Allowed checks", "已允許的檢查"),
  noAllowedModes: bilingual("No checks allowed yet", "尚未允許任何檢查"),
  findingsCount: bilingual("Problems currently linked", "目前連結的問題"),
  assetTechnical: bilingual("Technical asset details", "資產技術細節"),
  locator: bilingual("Exact coordinate", "精確位置"),
  assetType: bilingual("Asset type", "資產類型"),
  authorizationState: bilingual("Permission state", "授權狀態"),
  internetExposure: bilingual("Internet exposure", "對外狀態"),
  exposed: bilingual("Source says public", "來源顯示為公開"),
  internal: bilingual("Source says internal", "來源顯示為內部"),
  exposureUnknown: bilingual("Unknown", "未知"),
  clearSelection: bilingual("Clear selected candidates", "清除已選候選資產"),
  grantEyebrow: bilingual("Exact permission", "精確許可"),
  grantTitle: bilingual("Confirm ownership and allowed checks", "確認所有權與允許的檢查"),
  grantDescription: bilingual("This creates permission only for the {count} candidates listed below. It does not start a scan.", "只會為下方 {count} 個候選資產建立許可，不會啟動掃描。"),
  presetTitle: bilingual("Suggested checks are not permission", "建議檢查不是授權"),
  presetBody: bilingual("The first selection may suggest checks that match the case goal and every selected item. You must still confirm ownership, checks, and boundaries before recording permission.", "首次選取時可能依案件目標與所有已選項目建議檢查；你仍須確認所有權、檢查與邊界，再明確記錄許可。"),
  noCommonTitle: bilingual("These candidates do not share one permission type", "這些候選資產沒有共同的許可類型"),
  noCommonBody: bilingual("Confirm external targets separately from cloud accounts and local copies so a network permission can never spill into another item.", "請把外部目標與雲端帳號、本機副本分開確認，避免網路許可套用到其他項目。"),
  allowedQuestion: bilingual("Which checks do you allow?", "你允許哪些檢查？"),

  externalEyebrow: bilingual("Exact network boundary", "精確網路邊界"),
  externalTitle: bilingual("Set the limits for {name}", "設定 {name} 的限制"),
  externalDescription: bilingual("The target must exactly match this candidate. Permission lasts 30 days and never accepts a wildcard.", "目標必須與此候選資產完全相符。許可保存 30 天，而且不接受萬用字元。"),
  sourcePublic: bilingual("Source says public", "來源證明對外"),
  sourceInternal: bilingual("Source says internal", "來源顯示非對外"),
  sourceExposureUnknown: bilingual("Exposure unknown", "對外狀態未知"),
  noDirectTitle: bilingual("Direct connection checks cannot be allowed for this candidate", "目前不能允許直接連線檢查"),
  noDirectBody: bilingual("The source does not contain internet_exposed=true evidence. Public-record review remains available; a checkbox cannot override source evidence.", "來源沒有證據顯示它對外開放。你仍可選擇公開資料盤點，但不能用人工勾選覆寫來源證據。"),
  internalGrantTitle: bilingual("An internal target needs explicit sensitive-network permission", "內部目標需要明確的敏感網路許可"),
  internalGrantBody: bilingual("Direct checks stay blocked until you turn on the exact private-network permission below. Metadata endpoints remain blocked in every case.", "直接檢查會保持阻擋，直到你開啟下方的精確私網許可；雲端執行個體中繼資料位址在任何情況都仍禁止。"),
  noTargetTitle: bilingual("This candidate has no exact network target", "這個候選資產沒有精確網路目標"),
  noTargetBody: bilingual("Its identifiers are empty, wildcarded, or unsafe. Correct the input and refresh the candidates before recording network permission.", "identifier 是空值、萬用字元或格式不安全；請修正輸入並重新整理候選資產後再記錄網路許可。"),
  declaredServiceTitle: bilingual("Prepared from the website URL—review before approving", "已依網站網址預填；核准前請重新確認"),
  declaredServiceBody: bilingual("The case suggested {protocol} port {port} and path {path}. Only protocol and port are prefilled below; the path is context, not permission. Confirm the exact live service yourself.", "案件依原始網址建議 {protocol}、連接埠 {port} 與路徑 {path}。下方只預填協定與連接埠；路徑只是提示，不是許可。請自行確認精確服務。"),
  canonicalTarget: bilingual("Exact target", "精確目標"),
  canonicalTargetHelp: bilingual("Only identifiers from this candidate are available; arbitrary input is not accepted.", "只列出這個候選資產原有的識別資訊，不接受任意輸入。"),
  protocol: bilingual("Protocol", "傳輸協定"),
  protocolHelp: bilingual("The scanner cannot add another protocol while running.", "掃描工具不能在執行時自行擴充協定。"),
  ports: bilingual("Allowed ports", "允許的連接埠"),
  portsInvalid: bilingual("Use numbers from 1 to 65535, separated by commas or spaces.", "格式錯誤：只接受 1–65535 的數字，以逗號或空白分隔。"),
  portsValid: bilingual("{count} exact ports; ranges and port 0 are not accepted.", "{count} 個固定連接埠；不支援範圍或連接埠 0。"),
  policyRevision: bilingual("Locked test-list revision", "鎖定的測試清單版本"),
  revisionValid: bilingual("Locked to the exact template commit bundled with this product.", "已鎖定到產品內嵌測試範本的精確版本。"),
  revisionInvalid: bilingual("The bundled template revision does not match the product's pinned value.", "內嵌測試範本版本不符合產品鎖定值。"),
  rateTitle: bilingual("Request and timeout limits", "請求速率與逾時限制"),
  rps: bilingual("Requests per second", "每秒請求"),
  concurrency: bilingual("Concurrent requests", "並行請求數"),
  timeout: bilingual("Timeout in seconds", "逾時秒數"),
  maximum: bilingual("Maximum {value}", "最多 {value}"),
  templateIds: bilingual("Exact active-test IDs (required)", "精確主動測試 ID（必填）"),
  templatePlaceholder: bilingual("One exact template ID per line; * is not accepted", "每行一個精確 template ID；不接受 *"),
  templateValid: bilingual("{count} exact IDs.", "{count} 個精確 ID。"),
  templateInvalid: bilingual("Wildcard * is not accepted.", "不可使用萬用字元 *。"),
  prohibitedIntro: bilingual("The following capabilities always remain off:", "以下能力固定保持關閉："),
  sensitiveTitle: bilingual("Allow this exact target to resolve to approved private, loopback, or link-local networks", "允許這個精確目標解析到已核准的私有、回送或本機連線網段"),
  sensitiveBody: bilingual("Off by default. Metadata endpoints always remain blocked. This is recorded in the fixed permission and never adds another target.", "預設關閉；雲端執行個體中繼資料位址永遠禁止。這個選擇會記錄在固定許可中，而且不會加入其他目標。"),
  ownershipTitle: bilingual("I confirmed that every listed item belongs to this authorized assessment", "我已確認列出的每一項都屬於本次合法評估範圍"),
  ownershipBody: bilingual("A candidate source or similar name never proves ownership by itself.", "候選來源或名稱相似都不能自動證明所有權。"),
  authorityRequired: bilingual("Permission reference (required)", "授權參考（必填）"),
  scopeNote: bilingual("Scope note (optional)", "範圍備註（選填）"),
  authorityPlaceholder: bilingual("Example: ticket or contract number and approver", "例如：工單／合約編號與核准人"),
  notePlaceholder: bilingual("Example: internal approval for this read-only review", "例如：本次唯讀檢查的內部核准紀錄"),
  authorityHelp: bilingual("Every network activity needs a traceable authority statement. Never enter a secret or credential here.", "任何網路活動都必須留下可追溯的授權聲明；不要在這裡填入秘密值或憑證。"),
  noteHelp: bilingual("Never enter a secret or credential here.", "不要在這裡填入秘密值或憑證。"),
  activeAuthorityLength: bilingual("An active-test permission reference needs at least 8 characters.", "主動測試的授權參考至少需要 8 個字元。"),
  grantBoundaryHelp: bilingual("Permission applies only to the listed candidates and checks.", "許可只套用到列出的候選資產與檢查。"),
  saveGrant: bilingual("Record this exact permission", "記錄這份精確許可"),
  savingGrant: bilingual("Recording…", "正在記錄…"),
  defaultScopeNote: bilingual("The user confirmed ownership and the read-only boundary item by item in the local interface.", "使用者已在本機介面逐項確認資產所有權與唯讀範圍。"),

  emptyUnknownTitle: bilingual("There are no candidates, and visibility is still unknown", "目前沒有候選資產，而且可見範圍仍是未知"),
  emptyUnknownBody: bilingual("At least one needed input is missing. Do not interpret the empty list as proof that the environment has no assets.", "至少一個需要的輸入尚未連接；不能把空清單解讀為環境沒有資產。"),
  emptyNoneTitle: bilingual("The connected inputs returned no candidates this time", "已連接的輸入這次沒有回傳候選資產"),
  emptyNoneBody: bilingual("The inputs were available and returned zero items. This is different from having no input and therefore no visibility.", "輸入確實可用且回傳零項；這與缺少輸入、因此無法看見的未知狀態不同。"),
  emptyNeverTitle: bilingual("Candidate discovery has not run yet", "尚未執行候選資產盤點"),
  emptyNeverBody: bilingual("Attach an input in step 1, then refresh what the product can see.", "請先在步驟 1 附加輸入，再重新確認產品看得到什麼。"),
  emptyFilterTitle: bilingual("No candidates match this technical filter", "這個技術篩選下沒有候選資產"),
  emptyFilterBody: bilingual("Clear the filter to review the other candidates.", "請清除篩選以查看其他候選資產。"),

  grantsEyebrow: bilingual("Recorded network permissions", "已記錄的網路許可"),
  grantsTitle: bilingual("Exact external boundaries already approved", "已核准的精確外部邊界"),
  grantsDescription: bilingual("Each permission belongs to one case and one candidate. The runner may narrow it, but can never add targets, ports, rate, or tests.", "每份許可只屬於一個案件與候選資產。執行端可以縮小，但不能加入目標、連接埠、速率或測試。"),
  grantsCount: bilingual("{count} permissions", "{count} 份許可"),
  expires: bilingual("Expires {date}", "到期 {date}"),
  sensitiveAllowed: bilingual("Approved sensitive networks", "允許已核准敏感網段"),
  sensitiveBlocked: bilingual("Sensitive networks blocked", "敏感網段保持阻擋"),
  targetTerm: bilingual("Target", "目標"),
  protocolPortsTerm: bilingual("Protocol and ports", "協定與連接埠"),
  noDirectPort: bilingual("No direct-connection port", "沒有直接連線連接埠"),
  rateTerm: bilingual("Request limits", "請求限制"),
  templatesTerm: bilingual("Test-list policy", "測試清單政策"),
  authorityTerm: bilingual("Permission reference", "授權參考"),
  approvalTerm: bilingual("Recorded by", "記錄者"),
  prohibitedAll: bilingual("Headless browser, out-of-band callback, fuzzing, file upload, denial of service, and credential attacks are all blocked.", "無頭瀏覽器、站外回呼、模糊測試、檔案上傳、阻斷服務與密碼攻擊全部禁止。"),
  finalNoticeTitle: bilingual("Inventory and active checks have separate permission", "盤點與主動檢查分開授權"),
  finalNoticeBody: bilingual("Saved DNS and certificate records can create candidates. Tools that contact a target still require an exact candidate, network boundary, limits, and permission in step 3.", "已保存的 DNS 與憑證紀錄可以建立候選資產；任何會接觸目標的工具仍須在步驟 3 確認精確候選、網路邊界、限制與許可。"),
} as const;

const coverageJourneySteps = [
  { number: "1", short: pageCopy.step1Short, title: pageCopy.step1Title, detail: pageCopy.step1Detail },
  { number: "2", short: pageCopy.step2Short, title: pageCopy.step2Title, detail: pageCopy.step2Detail },
  { number: "3", short: pageCopy.step3Short, title: pageCopy.step3Title, detail: pageCopy.step3Detail },
] as const;

const useCaseNextSteps = [
  {
    id: "website",
    icon: "external" as const,
    title: bilingual("A website or API that is already online", "已架好的網站或 API"),
    detail: bilingual("Refresh the website candidate, select it in step 3, then confirm the exact protocol, port, rate, and allowed tests.", "重新整理網站候選資產，在步驟 3 選取它，再確認精確協定、連接埠、速率與允許的測試。"),
  },
  {
    id: "public-target",
    icon: "coverage" as const,
    title: bilingual("Public IP addresses or domains", "公開 IP 或網域"),
    detail: bilingual("Review each public candidate separately. Public-record review and direct connection checks remain different permissions.", "逐一確認公開候選資產；公開資料盤點與直接連線檢查仍是不同許可。"),
  },
  {
    id: "internal-it",
    icon: "lock" as const,
    title: bilingual("Internal IT systems", "內部 IT 環境"),
    detail: bilingual("Select the exact internal candidate, then explicitly allow its approved sensitive-network boundary. Private access is never inferred.", "選取精確內部候選資產，再明確允許已核准的敏感網路邊界；產品永遠不會自行推定私網許可。"),
  },
  {
    id: "source-code",
    icon: "file" as const,
    title: bilingual("Source code", "程式碼"),
    detail: bilingual("Attach the exact working-tree folder, confirm the immutable copy, then allow read-only local review in step 3.", "附加精確工作目錄、確認不可變副本，再到步驟 3 允許本機唯讀檢查。"),
  },
  {
    id: "infrastructure-code",
    icon: "file" as const,
    title: bilingual("Infrastructure code", "基礎設施程式碼"),
    detail: bilingual("Attach the Terraform, JSON, or YAML project, then approve read-only review of that saved copy only.", "附加 Terraform、JSON 或 YAML 專案，再只允許唯讀檢查該保存副本。"),
  },
  {
    id: "container",
    icon: "database" as const,
    title: bilingual("Container image", "容器映像"),
    detail: bilingual("Attach one digest-bound OCI layout, then approve read-only review of that saved copy only.", "附加一份綁定精確內容指紋的 OCI 映像配置目錄，再只允許檢查該保存副本。"),
  },
  {
    id: "kubernetes",
    icon: "shield" as const,
    title: bilingual("Kubernetes", "Kubernetes"),
    detail: bilingual("Choose manifest files or a bounded node snapshot. Live-cluster access and offline files use separate permission boundaries.", "選擇設定檔或有限範圍的節點快照；連線叢集與離線檔案使用不同許可邊界。"),
  },
  {
    id: "cloud",
    icon: "database" as const,
    title: bilingual("AWS, Azure, Google Cloud, or Microsoft 365", "AWS、Azure、Google Cloud 或 Microsoft 365"),
    detail: bilingual("Connect one exact account or tenant with short-lived read-only access, refresh inventory, then confirm allowed reviews per candidate.", "以短效唯讀方式連接一個精確帳號或租用戶、重新盤點，再逐候選資產確認允許的檢查。"),
  },
];

const assetTypeLabels: Record<Asset["type"], BilingualText> = {
  cloud_account: bilingual("Cloud account", "雲端帳號"),
  subscription: bilingual("Cloud subscription", "雲端訂閱"),
  project: bilingual("Cloud project", "雲端專案"),
  tenant: bilingual("Tenant", "租用戶"),
  domain: bilingual("Domain", "網域"),
  ip: bilingual("IP address", "IP 位址"),
  repository: bilingual("Source or infrastructure-code project", "程式碼或基礎設施程式碼專案"),
  image: bilingual("Container image", "容器映像"),
  cluster: bilingual("Kubernetes cluster", "Kubernetes 叢集"),
  service: bilingual("Network service", "網路服務"),
  storage: bilingual("Cloud storage", "雲端儲存空間"),
};

const authorizationStateLabels: Record<Asset["authorizationState"], BilingualText> = {
  authorized: bilingual("Permission recorded", "已記錄許可"),
  pending: bilingual("Needs your decision", "需要你決定"),
  excluded: bilingual("Excluded from this case", "已從案件排除"),
  unknown: bilingual("Ownership unknown", "所有權未知"),
};

const prohibitedCapabilities = [
  bilingual("Headless browser", "無頭瀏覽器"),
  bilingual("Out-of-band callback", "站外回呼"),
  bilingual("Fuzzing", "模糊測試"),
  bilingual("File upload", "檔案上傳"),
  bilingual("Denial of service", "阻斷服務"),
  bilingual("Credential attacks", "密碼攻擊"),
];

const nextStepForAsset = (asset: Asset): BilingualText => {
  if (asset.platform === "external" && asset.internetExposed === false) {
    return bilingual(
      "Confirm the exact internal target and explicitly allow its approved sensitive-network boundary.",
      "確認精確內部目標，並明確允許已核准的敏感網路邊界。",
    );
  }
  if (asset.platform === "external" && asset.type === "ip") {
    return bilingual(
      "Choose public-record review or an exact, rate-limited connection check for this IP address.",
      "為這個 IP 選擇公開資料盤點，或精確且受速率限制的連線檢查。",
    );
  }
  if (asset.platform === "external") {
    return bilingual(
      "Confirm the exact website or domain, protocol, ports, request limits, and allowed test type.",
      "確認精確網站或網域、協定、連接埠、請求限制與允許的測試類型。",
    );
  }
  if (asset.platform === "code") {
    return asset.localInputProfile === "iac_working_tree"
      ? bilingual("Allow read-only review of this saved infrastructure-code copy.", "允許唯讀檢查這份已保存的基礎設施程式碼副本。")
      : bilingual("Allow read-only review of this saved source-code copy.", "允許唯讀檢查這份已保存的程式碼副本。");
  }
  if (asset.platform === "container") {
    return bilingual("Allow read-only review of this exact digest-bound image copy.", "允許唯讀檢查這份綁定精確內容指紋的映像副本。");
  }
  if (asset.platform === "kubernetes") {
    return asset.localInputProfile
      ? bilingual("Allow offline review of this saved Kubernetes input only.", "只允許離線檢查這份已保存的 Kubernetes 輸入。")
      : bilingual("Confirm read-only inventory and configuration access for this exact cluster.", "為這個精確叢集確認唯讀盤點與設定檢查權限。");
  }
  return bilingual(
    "Confirm read-only inventory first, then separately allow the configuration review this case needs.",
    "先確認唯讀盤點，再另外允許這個案件需要的設定檢查。",
  );
};

const scrollToCoverageStep = (id: string): boolean => {
  const target = document.getElementById(id);
  if (!target) return false;
  const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  target.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
  return true;
};

const parsePorts = (value: string): number[] | undefined => {
  if (!value.trim()) return [];
  const parts = value.split(/[\s,]+/).filter(Boolean).map(Number);
  if (parts.some((port) => !Number.isInteger(port) || port < 1 || port > 65_535)) return undefined;
  return [...new Set(parts)].sort((a, b) => a - b);
};

const parseTemplateIds = (value: string): string[] =>
  [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];

const fileNameFromPath = (path: string, fallback: string): string =>
  path.split(/[\\/]/).filter(Boolean).at(-1) ?? fallback;

export function CoveragePage({
  caseId,
  requestedActivities,
  coverage,
  sources,
  assets,
  scopeGrants,
  nativeMode,
  busy,
  onChooseSnapshot,
  onConnectSourceSnapshot,
  onChooseWorkspace,
  onAttachWorkspaceSnapshot,
  onStartDiscovery,
  onAuthorizationChanged,
  onApprovePending,
}: CoveragePageProps) {
  const { text, formatDateTime, formatNumber } = useI18n();
  const [filter, setFilter] = useState<CoverageState | "all">("all");
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [showSourceForm, setShowSourceForm] = useState(false);
  const [showWorkspaceForm, setShowWorkspaceForm] = useState(false);
  const [showProviderSetup, setShowProviderSetup] = useState(false);
  const [sourceKind, setSourceKind] = useState<SourceKind>("aws_organization");
  const [profile, setProfile] = useState<SnapshotParserProfile>("cloudquery");
  const [sourceLabel, setSourceLabel] = useState<string>(() => text(sourceDefinitions.aws_organization.label));
  const [selectedPath, setSelectedPath] = useState("");
  const [choosingSnapshot, setChoosingSnapshot] = useState(false);
  const [sourceFormError, setSourceFormError] = useState<BilingualText>();
  const [workspaceLabel, setWorkspaceLabel] = useState(() => text(bilingual("Local source-code project", "本機程式碼專案")));
  const [workspaceInputProfile, setWorkspaceInputProfile] = useState<LocalInputProfile>("repository_working_tree");
  const [selectedWorkspacePath, setSelectedWorkspacePath] = useState("");
  const [choosingWorkspace, setChoosingWorkspace] = useState(false);
  const [workspaceFormError, setWorkspaceFormError] = useState<BilingualText>();
  const [scopeModes, setScopeModes] = useState<ScopeMode[]>([]);
  const [scopeConfirmation, setScopeConfirmation] = useState("");
  const [ownershipConfirmed, setOwnershipConfirmed] = useState(false);
  const [externalTarget, setExternalTarget] = useState("");
  const [externalPorts, setExternalPorts] = useState("443");
  const [externalProtocol, setExternalProtocol] = useState<TransportProtocol>("https");
  const [requestsPerSecond, setRequestsPerSecond] = useState(1);
  const [externalConcurrency, setExternalConcurrency] = useState(1);
  const [externalTimeout, setExternalTimeout] = useState(60);
  const [templateRevision, setTemplateRevision] = useState(NUCLEI_TEMPLATE_REVISION);
  const [allowedTemplateIds, setAllowedTemplateIds] = useState("");
  const [allowSensitiveNetworks, setAllowSensitiveNetworks] = useState(false);

  const counts = useMemo(
    () => Object.fromEntries(coverageStates.map((state) => [state, coverage.filter((item) => item.state === state).length])) as Record<CoverageState, number>,
    [coverage],
  );

  const filteredAssets = useMemo(
    () => (filter === "all" ? assets : assets.filter((asset) => asset.coverageState === filter)),
    [assets, filter],
  );

  const pendingAssets = assets.filter((asset) => asset.authorizationState === "pending");
  const scopeEligibleAssets = assets.filter(isScopeEligible);
  const scannedAssets = assets.filter((asset) => asset.coverageState === "discovered_authorized_scanned").length;
  const incompleteAssets = assets.filter((asset) => asset.coverageState === "authorized_incomplete").length;
  const unknownSourceCount = coverage.filter((item) => item.state === "source_unavailable_unknown").length;
  const connectedNoAssetCount = coverage.filter((item) => item.state === "source_connected_none").length;
  const frozenExternalGrants = scopeGrants.filter((grant) => grant.externalScope);
  const selectedSource = sourceDefinitions[sourceKind];
  const selectedScopeAssets = assets.filter((asset) => selectedAssets.includes(asset.id));
  const firstSelectedScopeAsset = selectedScopeAssets[0];
  const availableScopeModes = !firstSelectedScopeAsset
    ? []
    : permittedModes(firstSelectedScopeAsset).filter((mode) => selectedScopeAssets.every((asset) => permittedModes(asset).includes(mode)));
  const selectedExternalAsset = selectedScopeAssets.length === 1 && selectedScopeAssets[0]?.platform === "external"
    ? selectedScopeAssets[0]
    : undefined;
  const externalMode = scopeModes.find((mode) => externalActivities[mode]);
  const externalActivity = externalMode ? externalActivities[externalMode] : undefined;
  const requiresAuthorizationReference = Boolean(externalActivity);
  const limits = externalActivity ? rateLimits[externalActivity] : undefined;
  const externalTargetOptions = useMemo(() => {
    if (!selectedExternalAsset) return [];
    return [...new Set([
      ...(selectedExternalAsset.identifiers ?? []).map((identifier) => identifier.value),
      selectedExternalAsset.name,
    ].map((value) => value.trim()).filter((value) => Boolean(value) && !value.includes("*") && !/[\n\r\0]/.test(value)))];
  }, [selectedExternalAsset]);
  const parsedPorts = parsePorts(externalPorts);
  const parsedTemplateIds = parseTemplateIds(allowedTemplateIds);
  const templateIdsValid = parsedTemplateIds.every((id) => id !== "*" && !/[\n\r\0]/.test(id));
  const templateRevisionPinned = /(?:^|@)(?:sha256:)?(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(templateRevision.trim());
  const isDirectExternal = externalActivity === "low_impact_external" || externalActivity === "active_external";
  const directNetworkBoundaryConfirmed = selectedExternalAsset?.internetExposed === true
    || (selectedExternalAsset?.internetExposed === false && allowSensitiveNetworks);
  const externalScopeReady = !externalActivity || Boolean(
    selectedExternalAsset
    && externalTarget
    && externalTargetOptions.includes(externalTarget)
    && scopeConfirmation.trim()
    && (externalActivity !== "active_external" || scopeConfirmation.trim().length >= 8)
    && (externalActivity !== "active_external" || templateRevisionPinned)
    && parsedPorts
    && (!isDirectExternal || (parsedPorts.length > 0 && directNetworkBoundaryConfirmed))
    && templateIdsValid
    && (externalActivity !== "active_external" || parsedTemplateIds.length > 0)
    && requestsPerSecond >= 1
    && limits
    && requestsPerSecond <= limits.rate
    && externalConcurrency >= 1
    && externalConcurrency <= limits.concurrency
    && externalTimeout >= 1
    && externalTimeout <= limits.timeout
  );

  useEffect(() => {
    if (!externalTargetOptions.includes(externalTarget)) setExternalTarget(externalTargetOptions[0] ?? "");
  }, [externalTarget, externalTargetOptions]);

  useEffect(() => {
    const service = selectedExternalAsset?.declaredWebService;
    setExternalProtocol(service?.protocol ?? "https");
    setExternalPorts(service ? String(service.port) : "443");
  }, [
    selectedExternalAsset?.id,
    selectedExternalAsset?.declaredWebService?.port,
    selectedExternalAsset?.declaredWebService?.protocol,
  ]);

  const resetScopeForm = () => {
    setSelectedAssets([]);
    setScopeModes([]);
    setScopeConfirmation("");
    setOwnershipConfirmed(false);
    setExternalTarget("");
    setExternalPorts("443");
    setExternalProtocol("https");
    setRequestsPerSecond(1);
    setExternalConcurrency(1);
    setExternalTimeout(60);
    setTemplateRevision(NUCLEI_TEMPLATE_REVISION);
    setAllowedTemplateIds("");
    setAllowSensitiveNetworks(false);
  };

  const toggleAsset = (assetId: string) => {
    setSelectedAssets((current) => {
      const removing = current.includes(assetId);
      const next = removing ? current.filter((id) => id !== assetId) : [...current, assetId];
      const selected = assets.filter((asset) => next.includes(asset.id));
      const firstSelected = selected[0];
      const common = !firstSelected
        ? []
        : permittedModes(firstSelected).filter((mode) => selected.every((asset) => permittedModes(asset).includes(mode)));
      setScopeModes((modes) => (
        !removing && current.length === 0 && firstSelected
          ? suggestedModesForAsset(requestedActivities, firstSelected).filter((mode) => common.includes(mode))
          : modes.filter((mode) => common.includes(mode))
      ));
      if (next.length === 0) {
        setScopeConfirmation("");
        setOwnershipConfirmed(false);
      }
      return next;
    });
  };

  const toggleScopeMode = (mode: ScopeMode) => {
    setScopeModes((current) => {
      if (externalActivities[mode]) return current.includes(mode) ? [] : [mode];
      return current.includes(mode) ? current.filter((item) => item !== mode) : [...current, mode];
    });
  };

  const approve = async () => {
    if (selectedAssets.length === 0 || scopeModes.length === 0 || !ownershipConfirmed) return;
    if (requiresAuthorizationReference && !scopeConfirmation.trim()) return;
    if (!externalScopeReady) return;
    const externalScope: ExternalScopeRequest | undefined = externalActivity && parsedPorts ? {
      target: externalTarget,
      ports: parsedPorts,
      protocol: externalProtocol,
      activity: externalActivity,
      ratePolicy: {
        requestsPerSecond,
        concurrency: externalConcurrency,
        timeoutSeconds: externalTimeout,
      },
      templatePolicy: {
        revision: externalActivity === "active_external" ? templateRevision.trim() : "not_applicable",
        allowedTemplateIds: externalActivity === "active_external" ? parsedTemplateIds : [],
        allowHeadless: false,
        allowOutOfBand: false,
        allowFuzzing: false,
        allowFileUpload: false,
        allowDenialOfService: false,
        allowCredentialAttacks: false,
      },
      assertedAuthority: scopeConfirmation.trim(),
      allowSensitiveNetworks,
    } : undefined;
    const approved = await onApprovePending(
      selectedAssets,
      scopeModes,
      scopeConfirmation.trim() || text(pageCopy.defaultScopeNote),
      externalScope,
    );
    if (approved) resetScopeForm();
  };

  const changeSourceKind = (nextKind: SourceKind) => {
    const nextSource = sourceDefinitions[nextKind];
    setSourceKind(nextKind);
    setProfile(nextSource.profiles[0]);
    setSourceLabel(text(nextSource.label));
    setSelectedPath("");
    setSourceFormError(undefined);
  };

  const chooseSnapshot = async () => {
    setChoosingSnapshot(true);
    setSourceFormError(undefined);
    try {
      const path = await onChooseSnapshot();
      if (!path) return;
      if (!path.toLocaleLowerCase("en-US").endsWith(".json")) {
        setSourceFormError(pageCopy.sourceErrorJson);
        return;
      }
      setSelectedPath(path);
    } catch {
      setSourceFormError(pageCopy.sourceErrorPicker);
    } finally {
      setChoosingSnapshot(false);
    }
  };

  const connectSnapshot = async (event: FormEvent) => {
    event.preventDefault();
    if (!sourceLabel.trim()) {
      setSourceFormError(pageCopy.sourceErrorLabel);
      return;
    }
    if (!selectedPath) {
      setSourceFormError(pageCopy.sourceErrorPath);
      return;
    }
    setSourceFormError(undefined);
    await onConnectSourceSnapshot({
      caseId,
      sourceKind,
      label: sourceLabel.trim(),
      profile,
      selectedPath,
    });
  };

  const chooseWorkspace = async () => {
    setChoosingWorkspace(true);
    setWorkspaceFormError(undefined);
    try {
      const path = await onChooseWorkspace();
      if (path) setSelectedWorkspacePath(path);
    } catch {
      setWorkspaceFormError(pageCopy.workspaceErrorPicker);
    } finally {
      setChoosingWorkspace(false);
    }
  };

  const attachWorkspace = async (event: FormEvent) => {
    event.preventDefault();
    if (!workspaceLabel.trim()) {
      setWorkspaceFormError(pageCopy.workspaceErrorLabel);
      return;
    }
    if (!selectedWorkspacePath) {
      setWorkspaceFormError(pageCopy.workspaceErrorPath);
      return;
    }
    setWorkspaceFormError(undefined);
    await onAttachWorkspaceSnapshot({
      caseId,
      label: workspaceLabel.trim(),
      selectedPath: selectedWorkspacePath,
      inputProfile: workspaceInputProfile,
    });
  };

  return (
    <div className="page page--coverage">
      <PageHeader
        eyebrow={text(pageCopy.headerEyebrow)}
        title={text(pageCopy.headerTitle)}
        description={text(pageCopy.headerDescription)}
        actions={
          <button className="button button--primary" type="button" disabled={busy} onClick={() => void onStartDiscovery()}>
            <Icon name="refresh" size={18} />
            {busy ? text(pageCopy.refreshing) : text(pageCopy.refresh)}
          </button>
        }
      />

      <ol className="coverage-journey" aria-label={text(pageCopy.journeyLabel)}>
        {coverageJourneySteps.map(({ number, short, title, detail }) => (
          <li key={number}>
            <a
              href={`#coverage-step-${number}`}
              onClick={(event) => {
                if (scrollToCoverageStep(`coverage-step-${number}`)) event.preventDefault();
              }}
            >
              <span className="coverage-journey__number">{number}</span>
              <div>
                <small>{text(short)}</small>
                <strong>{text(title)}</strong>
                <p>{text(detail)}</p>
              </div>
            </a>
          </li>
        ))}
      </ol>

      <section id="coverage-step-1" className="section-block coverage-step-section">
        <div className="section-heading">
          <p className="eyebrow">{text(pageCopy.addEyebrow)}</p>
          <h2>{text(pageCopy.addTitle)}</h2>
          <p>{text(pageCopy.addDescription)}</p>
        </div>

        <div className="coverage-input-grid">
          <article className={showProviderSetup ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
            <span><Icon name="database" size={20} /></span>
            <div><strong>{text(pageCopy.providerTitle)}</strong><p>{text(pageCopy.providerBody)}</p></div>
            <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showProviderSetup} onClick={() => setShowProviderSetup((value) => !value)}>
              {text(showProviderSetup ? pageCopy.providerClose : pageCopy.providerOpen)}
            </button>
          </article>
          <article className={showSourceForm ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
            <span><Icon name="file" size={20} /></span>
            <div><strong>{text(pageCopy.snapshotTitle)}</strong><p>{text(pageCopy.snapshotBody)}</p></div>
            <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showSourceForm} aria-controls="source-snapshot-form" onClick={() => { setShowSourceForm((value) => !value); setShowWorkspaceForm(false); }}>
              {text(showSourceForm ? pageCopy.snapshotClose : pageCopy.snapshotOpen)}
            </button>
          </article>
          <article className={showWorkspaceForm ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
            <span><Icon name="database" size={20} /></span>
            <div><strong>{text(pageCopy.workspaceTitle)}</strong><p>{text(pageCopy.workspaceBody)}</p></div>
            <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showWorkspaceForm} aria-controls="workspace-snapshot-form" onClick={() => { setShowWorkspaceForm((value) => !value); setShowSourceForm(false); }}>
              {text(showWorkspaceForm ? pageCopy.workspaceClose : pageCopy.workspaceOpen)}
            </button>
          </article>
          <article className="coverage-input-card">
            <span><Icon name="coverage" size={20} /></span>
            <div><strong>{text(pageCopy.knownTargetsTitle)}</strong><p>{text(pageCopy.knownTargetsBody)}</p></div>
            <button className="button button--secondary button--small" type="button" disabled={busy} onClick={() => void onStartDiscovery()}>
              {busy ? text(pageCopy.refreshing) : text(pageCopy.refresh)}
            </button>
          </article>
        </div>

        <InlineNotice tone="info" title={text(pageCopy.selectDoesNotAuthorizeTitle)}>
          <p>{text(pageCopy.selectDoesNotAuthorizeBody)}</p>
        </InlineNotice>

        <details className="coverage-situation-details">
          <summary>{text(pageCopy.situationSummary)}</summary>
          <p>{text(pageCopy.situationIntro)}</p>
          <div className="coverage-situation-grid">
            {useCaseNextSteps.map((item) => (
              <article key={item.id}>
                <span><Icon name={item.icon} size={18} /></span>
                <div><strong>{text(item.title)}</strong><p>{text(item.detail)}</p></div>
              </article>
            ))}
          </div>
        </details>

        {showProviderSetup && (
          <div className="coverage-provider-slot">
            <ProviderAuthorizationPanel
              caseId={caseId}
              sources={sources}
              nativeMode={nativeMode}
              disabled={busy}
              onAuthorizationChanged={onAuthorizationChanged}
            />
          </div>
        )}

      {showSourceForm && (
        <form id="source-snapshot-form" className="source-connect-panel" aria-labelledby="source-connect-title" onSubmit={connectSnapshot}>
          <div className="section-heading">
            <p className="eyebrow">{text(pageCopy.sourceEyebrow)}</p>
            <h2 id="source-connect-title">{text(pageCopy.sourceTitle)}</h2>
            <p>{text(pageCopy.sourceIntro)}</p>
          </div>

          <InlineNotice tone="warning" title={text(pageCopy.noSecretsSnapshotTitle)}>
            <p>{text(pageCopy.noSecretsSnapshotBody)}</p>
          </InlineNotice>

          {!nativeMode && (
            <InlineNotice tone="info" title={text(pageCopy.demoFileTitle)}>
              <p>{text(pageCopy.demoFileBody)}</p>
            </InlineNotice>
          )}

          <div className="form-grid form-grid--two">
            <label className="field">
              <span>{text(pageCopy.sourceKind)}</span>
              <select value={sourceKind} onChange={(event) => changeSourceKind(event.target.value as SourceKind)}>
                {allSourceKinds.map((kind) => (
                  <option key={kind} value={kind}>{text(sourceDefinitions[kind].label)}</option>
                ))}
              </select>
              <small>{text(selectedSource.description)}</small>
            </label>
            <label className="field">
              <span>{text(pageCopy.sourceLabel)}</span>
              <input required maxLength={120} value={sourceLabel} onChange={(event) => setSourceLabel(event.target.value)} placeholder={text(pageCopy.sourceLabelPlaceholder)} />
              <small>{text(pageCopy.sourceLabelHelp)}</small>
            </label>
            <div className="field">
              <span id="snapshot-file-label">{text(pageCopy.jsonSnapshot)}</span>
              <button className="snapshot-picker" type="button" disabled={!nativeMode || busy || choosingSnapshot} aria-describedby="snapshot-file-help" onClick={() => void chooseSnapshot()}>
                <Icon name="file" size={18} />
                <span>{selectedPath
                  ? fileNameFromPath(selectedPath, text(pageCopy.fileFallback))
                  : choosingSnapshot
                    ? text(pageCopy.choosingPicker)
                    : text(pageCopy.chooseJson)}</span>
                <Icon name="chevron" size={16} />
              </button>
              <small id="snapshot-file-help">{text(pageCopy.snapshotPathHelp)}</small>
            </div>
          </div>

          <details className="coverage-form-technical">
            <summary>{text(pageCopy.inputTechnicalSummary)}</summary>
            <label className="field">
              <span>{text(pageCopy.snapshotFormat)}</span>
              <select value={profile} onChange={(event) => setProfile(event.target.value as SnapshotParserProfile)}>
                {selectedSource.profiles.map((parserProfile) => (
                  <option key={parserProfile} value={parserProfile}>{parserProfileLabels[parserProfile]}</option>
                ))}
              </select>
              <small>{text(pageCopy.snapshotFormatHelp)}</small>
            </label>
          </details>

          {sourceFormError && <p className="form-error" role="alert"><Icon name="warning" size={16} />{text(sourceFormError)}</p>}

          <div className="form-actions">
            <p><Icon name="lock" size={16} /> {text(pageCopy.sourceAfterHelp)}</p>
            <button className="button button--primary" type="submit" disabled={!nativeMode || busy || choosingSnapshot || !sourceLabel.trim() || !selectedPath}>
              {busy ? text(pageCopy.connectingSnapshot) : text(pageCopy.connectSnapshot)}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      {showWorkspaceForm && (
        <form id="workspace-snapshot-form" className="source-connect-panel" aria-labelledby="workspace-snapshot-title" onSubmit={attachWorkspace}>
          <div className="section-heading">
            <p className="eyebrow">{text(pageCopy.workspaceEyebrow)}</p>
            <h2 id="workspace-snapshot-title">{text(pageCopy.workspaceFormTitle)}</h2>
            <p>{text(pageCopy.workspaceIntro)}</p>
          </div>

          <InlineNotice tone="warning" title={text(pageCopy.gitWarningTitle)}>
            <p>{text(pageCopy.gitWarningBody)}</p>
          </InlineNotice>

          <InlineNotice tone="info" title={text(pageCopy.localNoGrantTitle)}>
            <p>{text(pageCopy.localNoGrantBody)}</p>
          </InlineNotice>

          {!nativeMode && (
            <InlineNotice tone="info" title={text(pageCopy.demoFolderTitle)}>
              <p>{text(pageCopy.demoFolderBody)}</p>
            </InlineNotice>
          )}

          <div className="form-grid form-grid--two">
            <label className="field">
              <span>{text(pageCopy.inputType)}</span>
              <select
                value={workspaceInputProfile}
                onChange={(event) => {
                  const next = event.target.value as LocalInputProfile;
                  setWorkspaceInputProfile(next);
                  setSelectedWorkspacePath("");
                  setWorkspaceFormError(undefined);
                }}
              >
                {(Object.keys(localInputDefinitions) as LocalInputProfile[]).map((inputProfile) => (
                  <option key={inputProfile} value={inputProfile}>{text(localInputDefinitions[inputProfile].label)}</option>
                ))}
              </select>
              <small>{text(localInputDefinitions[workspaceInputProfile].detail)}</small>
            </label>
            <label className="field">
              <span>{text(pageCopy.localLabel)}</span>
              <input required maxLength={120} value={workspaceLabel} onChange={(event) => setWorkspaceLabel(event.target.value)} placeholder={text(pageCopy.localLabelPlaceholder)} />
              <small>{text(pageCopy.localLabelHelp)}</small>
            </label>
            <div className="field">
              <span id="workspace-directory-label">{text(pageCopy.localDirectory)}</span>
              <button className="snapshot-picker" type="button" disabled={!nativeMode || busy || choosingWorkspace} aria-describedby="workspace-directory-help" onClick={() => void chooseWorkspace()}>
                <Icon name="database" size={18} />
                <span>{selectedWorkspacePath
                  ? fileNameFromPath(selectedWorkspacePath, text(pageCopy.folderFallback))
                  : choosingWorkspace
                    ? text(pageCopy.choosingPicker)
                    : text(localInputDefinitions[workspaceInputProfile].selection)}</span>
                <Icon name="chevron" size={16} />
              </button>
              <small id="workspace-directory-help">{text(pageCopy.localPathHelp)}</small>
            </div>
          </div>

          <details className="coverage-form-technical">
            <summary>{text(pageCopy.inputTechnicalSummary)}</summary>
            <p>{text(pageCopy.localEngineDetail, { engines: localInputEngines[workspaceInputProfile] })}</p>
            <code>{workspaceInputProfile}</code>
          </details>

          {workspaceFormError && <p className="form-error" role="alert"><Icon name="warning" size={16} />{text(workspaceFormError)}</p>}

          <div className="form-actions">
            <p><Icon name="lock" size={16} /> {text(pageCopy.workspaceAfterHelp)}</p>
            <button className="button button--primary" type="submit" disabled={!nativeMode || busy || choosingWorkspace || !workspaceLabel.trim() || !selectedWorkspacePath}>
              {busy ? text(pageCopy.attachingWorkspace) : text(pageCopy.attachWorkspace)}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      </section>

      <section id="coverage-step-2" className="section-block coverage-step-section">
        <div className="section-heading section-heading--row coverage-step-heading">
          <div>
            <p className="eyebrow">{text(pageCopy.seeEyebrow)}</p>
            <h2>{text(pageCopy.seeTitle)}</h2>
            <p>{text(pageCopy.seeDescription)}</p>
          </div>
          <a
            className="button button--primary"
            href="#coverage-step-3"
            onClick={(event) => {
              if (scrollToCoverageStep("coverage-step-3")) event.preventDefault();
            }}
          >
            {text(pageCopy.continueStep3)}
            <Icon name="arrow" size={17} />
          </a>
        </div>

      <section className="metrics-grid metrics-grid--four" aria-label={text(pageCopy.metricsLabel)}>
        <MetricCard label={text(pageCopy.candidateAssets)} value={formatNumber(assets.length)} detail={text(pageCopy.candidateDetail)} icon="database" />
        <MetricCard label={text(pageCopy.scannedAssets)} value={formatNumber(scannedAssets)} detail={text(pageCopy.scannedDetail)} icon="check" tone="accent" />
        <MetricCard label={text(pageCopy.incompleteAssets)} value={formatNumber(incompleteAssets)} detail={text(pageCopy.incompleteDetail)} icon="warning" tone={incompleteAssets ? "warning" : "default"} />
        <MetricCard label={text(pageCopy.pendingAssets)} value={formatNumber(pendingAssets.length)} detail={text(pageCopy.pendingDetail)} icon="lock" tone={pendingAssets.length ? "warning" : "default"} />
      </section>

      {(unknownSourceCount > 0 || connectedNoAssetCount > 0) && (
        <section className="coverage-truth-grid" aria-label={text(pageCopy.metricsLabel)}>
          {unknownSourceCount > 0 && (
            <div className="coverage-truth-card coverage-truth-card--unknown">
              <Icon name="warning" size={20} />
              <div><strong>{text(pageCopy.unknownTitle, { count: formatNumber(unknownSourceCount) })}</strong><p>{text(pageCopy.unknownBody)}</p></div>
            </div>
          )}
          {connectedNoAssetCount > 0 && (
            <div className="coverage-truth-card coverage-truth-card--none">
              <Icon name="database" size={20} />
              <div><strong>{text(pageCopy.noneTitle, { count: formatNumber(connectedNoAssetCount) })}</strong><p>{text(pageCopy.noneBody)}</p></div>
            </div>
          )}
        </section>
      )}

      <section className="coverage-source-ledger">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">{text(pageCopy.sourcesEyebrow)}</p>
            <h2>{text(pageCopy.sourcesTitle)}</h2>
          </div>
        </div>
        {coverage.length === 0 ? (
          <EmptyState icon="coverage" title={text(pageCopy.noSourcesTitle)} description={text(pageCopy.noSourcesBody)} />
        ) : <div className="source-grid">
          {coverage.map((record) => {
            const meta = coverageMeta[record.state];
            const connectedSource = sources.find((source) => source.kind === record.sourceKind && source.label === record.label)
              ?? sources.find((source) => source.kind === record.sourceKind);
            return (
              <article key={record.id} className={`source-card source-card--${meta.tone}`}>
                <div className="source-card__top">
                  <span className="platform-avatar">{platformMeta[record.platform].abbreviation}</span>
                  <StatusPill label={meta.shortLabel} tone={meta.tone} />
                </div>
                <h3>{record.label}</h3>
                <p>{meta.description}</p>
                <div className="source-card__footer">
                  <span>{text(pageCopy.assetsCount, { count: formatNumber(record.assetCount) })}</span>
                  <span>{record.lastCheckedAt
                    ? text(pageCopy.lastChecked, { date: formatDateTime(record.lastCheckedAt) })
                    : text(pageCopy.notConnected)}</span>
                </div>
                <details className="source-card__technical">
                  <summary>{text(pageCopy.sourceTechnical)}</summary>
                  <dl>
                    <div><dt>{text(pageCopy.sourceKindTechnical)}</dt><dd><code>{record.sourceKind}</code></dd></div>
                    <div><dt>{text(pageCopy.coverageStateTechnical)}</dt><dd><code>{record.state}</code></dd></div>
                    <div><dt>{text(pageCopy.acceptedProfiles)}</dt><dd>{sourceDefinitions[record.sourceKind].profiles.map((item) => parserProfileLabels[item]).join(", ")}</dd></div>
                    {connectedSource && <div><dt>{text(pageCopy.sourceStatusTechnical)}</dt><dd><code>{connectedSource.status}</code></dd></div>}
                    <div><dt>{text(pageCopy.rawSourceDetail)}</dt><dd>{record.detail}</dd></div>
                  </dl>
                </details>
              </article>
            );
          })}
        </div>}
      </section>

      <details className="coverage-technical-details">
        <summary>{text(pageCopy.coverageDetailsSummary)}</summary>
        <p>{text(pageCopy.coverageDetailsIntro)}</p>
        <button className="button button--ghost button--small" type="button" onClick={() => setFilter("all")}>
          {text(pageCopy.showAll)}
        </button>
        <div className="coverage-legend">
          {coverageStates.map((state) => {
            const meta = coverageMeta[state];
            return (
              <button
                key={state}
                type="button"
                className={filter === state ? "coverage-legend__item coverage-legend__item--active" : "coverage-legend__item"}
                onClick={() => setFilter((current) => (current === state ? "all" : state))}
                aria-pressed={filter === state}
              >
                <span className={`coverage-state-mark coverage-state-mark--${meta.tone}`} aria-hidden="true" />
                <span><strong>{meta.label}</strong><small>{meta.description}</small></span>
                <b>{formatNumber(counts[state])}</b>
              </button>
            );
          })}
        </div>
      </details>
      </section>

      {pendingAssets.length > 0 && (
        <InlineNotice tone="warning" title={text(pageCopy.pendingNoticeTitle)}>
          <p>{text(pageCopy.pendingNoticeBody)}</p>
        </InlineNotice>
      )}

      <section id="coverage-step-3" className="section-block coverage-step-section">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">{text(pageCopy.allowEyebrow)}</p>
            <h2>{text(pageCopy.allowTitle)}</h2>
            <p>{text(pageCopy.allowDescription)}</p>
          </div>
          {selectedAssets.length > 0 && <span className="count-label">{text(pageCopy.selectedCount, { count: formatNumber(selectedAssets.length) })}</span>}
        </div>

        {selectedAssets.length > 0 && (
          <form className="scope-confirmation-panel" onSubmit={(event) => { event.preventDefault(); void approve(); }}>
            <div className="scope-confirmation-panel__heading">
              <div>
                <p className="eyebrow">{text(pageCopy.grantEyebrow)}</p>
                <h3>{text(pageCopy.grantTitle)}</h3>
                <p>{text(pageCopy.grantDescription, { count: formatNumber(selectedAssets.length) })}</p>
              </div>
              <button className="icon-button" type="button" aria-label={text(pageCopy.clearSelection)} onClick={resetScopeForm}><Icon name="close" size={17} /></button>
            </div>

            <InlineNotice tone="info" title={text(pageCopy.presetTitle)}>
              <p>{text(pageCopy.presetBody)}</p>
            </InlineNotice>

            {availableScopeModes.length === 0 ? (
              <InlineNotice tone="warning" title={text(pageCopy.noCommonTitle)}>
                <p>{text(pageCopy.noCommonBody)}</p>
              </InlineNotice>
            ) : (
              <fieldset className="scope-mode-fieldset">
                <legend>{text(pageCopy.allowedQuestion)}</legend>
                <div className="scope-mode-grid">
                  {availableScopeModes.map((mode) => {
                    const unavailableExternalMode = Boolean(
                      externalActivities[mode]
                      && mode !== "public_data"
                      && selectedExternalAsset?.internetExposed === undefined,
                    );
                    return (
                      <label key={mode} className={`${scopeModes.includes(mode) ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}${unavailableExternalMode ? " scope-mode-card--disabled" : ""}`}>
                        <input
                          type={externalActivities[mode] ? "radio" : "checkbox"}
                          name={externalActivities[mode] ? "external-activity" : undefined}
                          checked={scopeModes.includes(mode)}
                          disabled={unavailableExternalMode}
                          onChange={() => toggleScopeMode(mode)}
                        />
                        <span><strong>{text(scopeModeLabels[mode].label)}</strong><small>{text(scopeModeLabels[mode].detail)}</small></span>
                      </label>
                    );
                  })}
                </div>
              </fieldset>
            )}

            {externalActivity && selectedExternalAsset && limits && (
              <section className="external-scope-builder" aria-labelledby="external-scope-title">
                <div className="external-scope-builder__heading">
                  <div>
                    <p className="eyebrow">{text(pageCopy.externalEyebrow)}</p>
                    <h4 id="external-scope-title">{text(pageCopy.externalTitle, { name: selectedExternalAsset.name })}</h4>
                    <p>{text(pageCopy.externalDescription)}</p>
                  </div>
                  <StatusPill
                    label={text(selectedExternalAsset.internetExposed === true
                      ? pageCopy.sourcePublic
                      : selectedExternalAsset.internetExposed === false
                        ? pageCopy.sourceInternal
                        : pageCopy.sourceExposureUnknown)}
                    tone={selectedExternalAsset.internetExposed === true ? "positive" : "unknown"}
                  />
                </div>

                {selectedExternalAsset.declaredWebService && (
                  <InlineNotice tone="info" title={text(pageCopy.declaredServiceTitle)}>
                    <p>{text(pageCopy.declaredServiceBody, {
                      protocol: selectedExternalAsset.declaredWebService.protocol.toUpperCase(),
                      port: formatNumber(selectedExternalAsset.declaredWebService.port),
                      path: selectedExternalAsset.declaredWebService.path,
                    })}</p>
                  </InlineNotice>
                )}

                {isDirectExternal && selectedExternalAsset.internetExposed === undefined && (
                  <InlineNotice tone="warning" title={text(pageCopy.noDirectTitle)}>
                    <p>{text(pageCopy.noDirectBody)}</p>
                  </InlineNotice>
                )}

                {isDirectExternal && selectedExternalAsset.internetExposed === false && !allowSensitiveNetworks && (
                  <InlineNotice tone="warning" title={text(pageCopy.internalGrantTitle)}>
                    <p>{text(pageCopy.internalGrantBody)}</p>
                  </InlineNotice>
                )}

                {externalTargetOptions.length === 0 && (
                  <InlineNotice tone="warning" title={text(pageCopy.noTargetTitle)}>
                    <p>{text(pageCopy.noTargetBody)}</p>
                  </InlineNotice>
                )}

                <div className="form-grid form-grid--two">
                  <label className="field">
                    <span>{text(pageCopy.canonicalTarget)}</span>
                    <select value={externalTarget} onChange={(event) => setExternalTarget(event.target.value)}>
                      {externalTargetOptions.map((target) => <option key={target} value={target}>{target}</option>)}
                    </select>
                    <small>{text(pageCopy.canonicalTargetHelp)}</small>
                  </label>
                  <label className="field">
                    <span>{text(pageCopy.protocol)}</span>
                    <select value={externalProtocol} onChange={(event) => setExternalProtocol(event.target.value as TransportProtocol)}>
                      <option value="https">HTTPS</option>
                      <option value="http">HTTP</option>
                      <option value="tls">TLS</option>
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                    <small>{text(pageCopy.protocolHelp)}</small>
                  </label>
                  <label className="field">
                    <span>{text(pageCopy.ports)}</span>
                    <input value={externalPorts} onChange={(event) => setExternalPorts(event.target.value)} placeholder="443, 8443" inputMode="numeric" />
                    <small>{parsedPorts === undefined
                      ? text(pageCopy.portsInvalid)
                      : text(pageCopy.portsValid, { count: formatNumber(parsedPorts.length) })}</small>
                  </label>
                  {externalActivity === "active_external" && <label className="field">
                    <span>{text(pageCopy.policyRevision)}</span>
                    <input value={templateRevision} readOnly aria-readonly="true" />
                    <small>{text(templateRevisionPinned ? pageCopy.revisionValid : pageCopy.revisionInvalid)}</small>
                  </label>}
                </div>

                <fieldset className="rate-policy-fieldset">
                  <legend>{text(pageCopy.rateTitle)}</legend>
                  <div className="rate-policy-grid">
                    <label className="field"><span>{text(pageCopy.rps)}</span><input type="number" min={1} max={limits.rate} value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.target.valueAsNumber)} /><small>{text(pageCopy.maximum, { value: formatNumber(limits.rate) })}</small></label>
                    <label className="field"><span>{text(pageCopy.concurrency)}</span><input type="number" min={1} max={limits.concurrency} value={externalConcurrency} onChange={(event) => setExternalConcurrency(event.target.valueAsNumber)} /><small>{text(pageCopy.maximum, { value: formatNumber(limits.concurrency) })}</small></label>
                    <label className="field"><span>{text(pageCopy.timeout)}</span><input type="number" min={1} max={limits.timeout} value={externalTimeout} onChange={(event) => setExternalTimeout(event.target.valueAsNumber)} /><small>{text(pageCopy.maximum, { value: formatNumber(limits.timeout) })}</small></label>
                  </div>
                </fieldset>

                {externalActivity === "active_external" && <label className="field">
                  <span>{text(pageCopy.templateIds)}</span>
                  <textarea rows={3} value={allowedTemplateIds} onChange={(event) => setAllowedTemplateIds(event.target.value)} placeholder={text(pageCopy.templatePlaceholder)} />
                  <small>{templateIdsValid
                    ? text(pageCopy.templateValid, { count: formatNumber(parsedTemplateIds.length) })
                    : text(pageCopy.templateInvalid)} {text(pageCopy.prohibitedIntro)}</small>
                </label>}

                <div className="prohibited-template-list" aria-label={text(pageCopy.prohibitedIntro)}>
                  {prohibitedCapabilities.map((item) => <span key={item.en}><Icon name="lock" size={13} />{text(item)}</span>)}
                </div>

                <label className="toggle-row toggle-row--danger">
                  <input type="checkbox" checked={allowSensitiveNetworks} onChange={(event) => setAllowSensitiveNetworks(event.target.checked)} />
                  <span><strong>{text(pageCopy.sensitiveTitle)}</strong><small>{text(pageCopy.sensitiveBody)}</small></span>
                </label>
              </section>
            )}

            <div className="scope-confirmation-panel__assets">
              {selectedScopeAssets.map((asset) => <span key={asset.id}><b>{asset.name}</b><small>{asset.locator}</small></span>)}
            </div>

            <label className="toggle-row">
              <input type="checkbox" checked={ownershipConfirmed} onChange={(event) => setOwnershipConfirmed(event.target.checked)} />
              <span><strong>{text(pageCopy.ownershipTitle)}</strong><small>{text(pageCopy.ownershipBody)}</small></span>
            </label>

            <label className="field">
              <span>{text(requiresAuthorizationReference ? pageCopy.authorityRequired : pageCopy.scopeNote)}</span>
              <input value={scopeConfirmation} onChange={(event) => setScopeConfirmation(event.target.value)} placeholder={text(requiresAuthorizationReference ? pageCopy.authorityPlaceholder : pageCopy.notePlaceholder)} />
              <small>{text(requiresAuthorizationReference ? pageCopy.authorityHelp : pageCopy.noteHelp)}</small>
              {externalActivity === "active_external" && scopeConfirmation.trim().length > 0 && scopeConfirmation.trim().length < 8 && <small className="field-error">{text(pageCopy.activeAuthorityLength)}</small>}
            </label>

            <div className="form-actions">
              <p><Icon name="lock" size={16} /> {text(pageCopy.grantBoundaryHelp)}</p>
              <button className="button button--primary" type="submit" disabled={busy || availableScopeModes.length === 0 || scopeModes.length === 0 || !ownershipConfirmed || (requiresAuthorizationReference && !scopeConfirmation.trim()) || !externalScopeReady}>
                <Icon name="lock" size={16} />{busy ? text(pageCopy.savingGrant) : text(pageCopy.saveGrant)}
              </button>
            </div>
          </form>
        )}

        {filteredAssets.length === 0 ? (
          <EmptyState
            icon={assets.length === 0 && unknownSourceCount > 0 ? "warning" : "database"}
            title={assets.length === 0
              ? unknownSourceCount > 0
                ? text(pageCopy.emptyUnknownTitle)
                : connectedNoAssetCount > 0
                  ? text(pageCopy.emptyNoneTitle)
                  : text(pageCopy.emptyNeverTitle)
              : text(pageCopy.emptyFilterTitle)}
            description={assets.length === 0
              ? unknownSourceCount > 0
                ? text(pageCopy.emptyUnknownBody)
                : connectedNoAssetCount > 0
                  ? text(pageCopy.emptyNoneBody)
                  : text(pageCopy.emptyNeverBody)
              : text(pageCopy.emptyFilterBody)}
          />
        ) : (
          <div className="asset-review-list">
            {filteredAssets.map((asset) => {
              const scopeEligible = scopeEligibleAssets.some((item) => item.id === asset.id);
              const meta = coverageMeta[asset.coverageState];
              const anotherAssetSelected = selectedAssets.length > 0 && !selectedAssets.includes(asset.id);
              const selectedIncludesExternal = selectedScopeAssets.some((item) => item.platform === "external");
              const incompatibleWithSelection = anotherAssetSelected && (asset.platform === "external" || selectedIncludesExternal);
              return (
                <article key={asset.id} className={selectedAssets.includes(asset.id) ? "asset-review-card asset-review-card--selected" : "asset-review-card"}>
                  <label className="asset-review-card__choice">
                    <input
                      type="checkbox"
                      aria-label={text(pageCopy.chooseAsset, { name: asset.name })}
                      checked={selectedAssets.includes(asset.id)}
                      disabled={!scopeEligible || incompatibleWithSelection}
                      title={incompatibleWithSelection
                        ? text(pageCopy.incompatibleSelection)
                        : asset.authorizationState === "authorized"
                          ? text(pageCopy.addPermission)
                          : undefined}
                      onChange={() => toggleAsset(asset.id)}
                    />
                    <span className="platform-avatar platform-avatar--small">{platformMeta[asset.platform].abbreviation}</span>
                    <span>
                      <strong>{asset.name}</strong>
                      <small>{platformMeta[asset.platform].label} · {text(assetTypeLabels[asset.type])}</small>
                    </span>
                  </label>
                  <div className="asset-review-card__status">
                    <StatusPill label={meta.shortLabel} tone={meta.tone} />
                    <small>{text(authorizationStateLabels[asset.authorizationState])}</small>
                  </div>
                  <div className="asset-review-card__next">
                    <strong>{text(pageCopy.assetNext)}</strong>
                    <p>{text(nextStepForAsset(asset))}</p>
                  </div>
                  <details className="asset-review-card__technical">
                    <summary>{text(pageCopy.assetTechnical)}</summary>
                    <dl>
                      <div><dt>{text(pageCopy.locator)}</dt><dd><code>{asset.locator}</code></dd></div>
                      <div><dt>{text(pageCopy.assetType)}</dt><dd><code>{asset.type}</code></dd></div>
                      <div><dt>{text(pageCopy.coverageStateTechnical)}</dt><dd><code>{asset.coverageState}</code></dd></div>
                      <div><dt>{text(pageCopy.authorizationState)}</dt><dd><code>{asset.authorizationState}</code></dd></div>
                      <div><dt>{text(pageCopy.internetExposure)}</dt><dd>{text(asset.internetExposed === true ? pageCopy.exposed : asset.internetExposed === false ? pageCopy.internal : pageCopy.exposureUnknown)}</dd></div>
                      <div><dt>{text(pageCopy.allowedModes)}</dt><dd>{asset.allowedModes.length
                        ? asset.allowedModes.map((mode) => text(scopeModeLabels[mode].label)).join(", ")
                        : text(pageCopy.noAllowedModes)}</dd></div>
                      <div><dt>{text(pageCopy.findingsCount)}</dt><dd>{formatNumber(asset.findingCount)}</dd></div>
                      <div><dt>{text(pageCopy.owner)}</dt><dd>{asset.owner ?? text(pageCopy.noOwner)}</dd></div>
                      {asset.region && <div><dt>{text(pageCopy.region)}</dt><dd>{asset.region}</dd></div>}
                      {asset.identifiers && asset.identifiers.length > 0 && <div><dt>{text(pageCopy.identifiers)}</dt><dd>{asset.identifiers.map((identifier) => `${identifier.namespace}:${identifier.value}`).join(", ")}</dd></div>}
                    </dl>
                  </details>
                </article>
              );
            })}
          </div>
        )}
      </section>

      {frozenExternalGrants.length > 0 && (
        <section className="section-block">
          <div className="section-heading section-heading--row">
            <div>
              <p className="eyebrow">{text(pageCopy.grantsEyebrow)}</p>
              <h2>{text(pageCopy.grantsTitle)}</h2>
              <p>{text(pageCopy.grantsDescription)}</p>
            </div>
            <span className="count-label">{text(pageCopy.grantsCount, { count: formatNumber(frozenExternalGrants.length) })}</span>
          </div>
          <div className="external-grant-list">
            {frozenExternalGrants.map((grant) => {
              const scope = grant.externalScope!;
              const asset = assets.find((item) => item.id === grant.assetId);
              return (
                <article key={grant.id} className="external-grant-card">
                  <div className="external-grant-card__header">
                    <span><Icon name="lock" size={17} /></span>
                    <div><strong>{asset?.name ?? grant.assetId}</strong><small>{text(activityLabels[scope.activity])} · {text(pageCopy.expires, { date: formatDateTime(scope.expiresAt) })}</small></div>
                    <StatusPill label={text(scope.allowSensitiveNetworks ? pageCopy.sensitiveAllowed : pageCopy.sensitiveBlocked)} tone={scope.allowSensitiveNetworks ? "warning" : "positive"} />
                  </div>
                  <dl>
                    <div><dt>{text(pageCopy.targetTerm)}</dt><dd><code>{scope.targetKind}:{scope.target}</code></dd></div>
                    <div><dt>{text(pageCopy.protocolPortsTerm)}</dt><dd>{scope.protocol.toUpperCase()} · {scope.ports.length ? scope.ports.join(", ") : text(pageCopy.noDirectPort)}</dd></div>
                    <div><dt>{text(pageCopy.rateTerm)}</dt><dd>{formatNumber(scope.ratePolicy.requestsPerSecond)} req/s · {formatNumber(scope.ratePolicy.concurrency)} concurrent · {formatNumber(scope.ratePolicy.timeoutSeconds)}s</dd></div>
                    <div><dt>{text(pageCopy.templatesTerm)}</dt><dd><code>{scope.templatePolicy.revision}</code> · {formatNumber(scope.templatePolicy.allowedTemplateIds.length)} IDs</dd></div>
                    <div><dt>{text(pageCopy.authorityTerm)}</dt><dd>{scope.assertedAuthority}</dd></div>
                    <div><dt>{text(pageCopy.approvalTerm)}</dt><dd>{scope.approvedBy} · {formatDateTime(scope.approvedAt)}</dd></div>
                  </dl>
                  <p><Icon name="lock" size={13} /> {text(pageCopy.prohibitedAll)}</p>
                </article>
              );
            })}
          </div>
        </section>
      )}

      <InlineNotice tone="info" title={text(pageCopy.finalNoticeTitle)}>
        <p>{text(pageCopy.finalNoticeBody)}</p>
      </InlineNotice>
    </div>
  );
}
