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
import {
  ProviderAuthorizationPanel,
  type ProviderConnectionBoundary,
} from "../components/ProviderAuthorizationPanel";
import { useI18n, type BilingualText } from "../i18n";
import type { CoverageSetupFocus } from "../scanReadiness";
import { isScopeEligible, permittedModes, suggestedModesForAsset } from "../scopePolicy";
import type { UseCaseId } from "../useCases";
import {
  hasExactGuidedCloudConsent,
  shouldPromptForFirstAsset,
  singleGuidedPendingAsset,
  type GuidedCoverageRoute,
} from "../coverageGuidance";

import "../coverage-page.css";

interface CoveragePageProps {
  caseId: string;
  assessmentIntent?: UseCaseId;
  focusSetup?: CoverageSetupFocus;
  requestedActivities: AssessmentActivity[];
  coverage: CoverageRecord[];
  sources: ConnectedSource[];
  assets: Asset[];
  scopeGrants: ScopeGrant[];
  nativeMode: boolean;
  busy?: boolean;
  discoveryBusy?: boolean;
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
    description: bilingual("Saved DNS answers for a website or domain.", "網站或網域的既有 DNS 查詢結果。"),
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
    description: bilingual("A saved billing export that can help find cloud resources.", "可協助找出雲端資源的既有帳務匯出檔。"),
  },
  git_repository: {
    label: bilingual("Git repositories", "Git 程式碼儲存庫"),
    platform: "code",
    profiles: ["git-manifest"],
    description: bilingual("A saved list of the code repositories you selected.", "你所選程式碼儲存庫的既有清單。"),
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
    description: bilingual("A saved list of container registries and images.", "容器映像倉庫與映像的既有清單。"),
  },
  file_system: {
    label: bilingual("Local files", "本機檔案"),
    platform: "code",
    profiles: ["filesystem-manifest"],
    description: bilingual("A saved list of the local files you selected.", "你所選本機檔案的既有清單。"),
  },
  user_declared: {
    label: bilingual("Websites and systems already added", "已加入的網站與系統"),
    platform: "external",
    profiles: ["user-declared-manifest"],
    description: bilingual("Websites, IP addresses, and systems already added to this scan.", "已加入這次掃描的網站、IP 位址與系統。"),
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

const networkAssessmentIntents: readonly UseCaseId[] = [
  "deployed_website",
  "external_ip_or_domain",
  "internal_it_environment",
];

const localProfileByAssessmentIntent: Partial<Record<UseCaseId, LocalInputProfile>> = {
  ai_application: "repository_working_tree",
  source_code: "repository_working_tree",
  infrastructure_as_code: "iac_working_tree",
  container_image: "container_image_oci_layout",
  kubernetes: "kubernetes_manifests",
};

interface LocalInputDefinition {
  label: BilingualText;
  detail: BilingualText;
  formTitle: BilingualText;
  formIntro: BilingualText;
  cautionTitle: BilingualText;
  cautionBody: BilingualText;
  directoryLabel: BilingualText;
  selection: BilingualText;
  attachAction: BilingualText;
  technical: BilingualText;
}

const localInputDefinitions: Record<LocalInputProfile, LocalInputDefinition> = {
  repository_working_tree: {
    label: bilingual("Code you wrote or generated with AI", "自己寫或 AI 生成的程式碼"),
    detail: bilingual("Check one local project without changing its files.", "在本機檢查一個專案，不會修改任何檔案。"),
    formTitle: bilingual("Choose code you wrote or generated with AI", "選擇自己寫或 AI 生成的程式碼"),
    formIntro: bilingual("Pick one project folder. We'll check it locally for risky code, exposed secrets, and vulnerable packages without changing its files.", "選擇一個專案資料夾；我們會在本機檢查危險程式碼、暴露的秘密與有弱點的套件，不會修改任何檔案。"),
    cautionTitle: bilingual("Your project stays local and unchanged", "專案留在本機，檔案不會被修改"),
    cautionBody: bilingual("Only the selected folder is copied into the private local scan. Detected secret values are masked in results.", "只會把選定資料夾複製到私密的本機掃描；找到的秘密值會在結果中遮罩。"),
    directoryLabel: bilingual("Source-code folder", "程式碼資料夾"),
    selection: bilingual("Choose the source-code folder", "選擇程式碼資料夾"),
    attachAction: bilingual("Add this source-code project", "加入這份程式碼專案"),
    technical: bilingual("Input profile: repository_working_tree. Every .git directory, including refs and hooks, is excluded from the saved copy.", "輸入格式：repository_working_tree。保存副本時會排除所有 .git 目錄，包括 refs 與 hooks。"),
  },
  iac_working_tree: {
    label: bilingual("Infrastructure-code project", "基礎設施程式碼專案"),
    detail: bilingual("Check the Terraform, JSON, and YAML files in one project folder without changing them.", "檢查一個專案資料夾內的 Terraform、JSON 與 YAML 檔案，不會修改內容。"),
    formTitle: bilingual("Choose the infrastructure code you want checked", "選擇想檢查的基礎設施程式碼"),
    formIntro: bilingual("Pick the folder that contains your Terraform, CloudFormation, JSON, or YAML deployment files. We'll look for risky settings before they go live.", "選擇包含 Terraform、CloudFormation、JSON 或 YAML 部署檔案的資料夾；我們會在上線前找出危險設定。"),
    cautionTitle: bilingual("Remove secret values from deployment files first", "請先移除部署檔案中的秘密值"),
    cautionBody: bilingual("The selected files are copied for local checks. Replace embedded passwords, keys, and tokens before adding the folder.", "所選檔案會複製到本機進行檢查；加入資料夾前，請先移除檔案內的密碼、金鑰與 token。"),
    directoryLabel: bilingual("Infrastructure-code folder", "基礎設施程式碼資料夾"),
    selection: bilingual("Choose the infrastructure-code folder", "選擇基礎設施程式碼資料夾"),
    attachAction: bilingual("Add this infrastructure code", "加入這份基礎設施程式碼"),
    technical: bilingual("Input profile: iac_working_tree. The saved copy accepts Terraform, JSON, and YAML deployment files.", "輸入格式：iac_working_tree。保存副本接受 Terraform、JSON 與 YAML 部署檔案。"),
  },
  container_image_oci_layout: {
    label: bilingual("Exported container image", "匯出的容器映像"),
    detail: bilingual("Check one exported container image on this computer without signing in to a registry.", "在這台電腦上檢查一份匯出的容器映像，不必登入映像倉庫。"),
    formTitle: bilingual("Choose the container image you want checked", "選擇想檢查的容器映像"),
    formIntro: bilingual("Pick one exported OCI image folder. We'll inspect its packages and known vulnerabilities locally without running the image.", "選擇一個匯出的 OCI 映像資料夾；我們會在本機檢查其中套件與已知弱點，不會執行映像。"),
    cautionTitle: bilingual("Choose an exported image, not a running container", "請選擇匯出的映像，不是正在執行的容器"),
    cautionBody: bilingual("The app reads only this exported copy. It does not start the image or sign in to a container registry.", "產品只讀取這份匯出副本，不會啟動映像，也不會登入容器映像倉庫。"),
    directoryLabel: bilingual("Exported image folder", "匯出映像資料夾"),
    selection: bilingual("Choose the exported container-image folder", "選擇匯出的容器映像資料夾"),
    attachAction: bilingual("Add this container image", "加入這份容器映像"),
    technical: bilingual("Input profile: container_image_oci_layout. Choose one digest-bound OCI Image Layout containing oci-layout, index.json, and blobs/.", "輸入格式：container_image_oci_layout。請選擇一份綁定精確內容指紋、且包含 oci-layout、index.json 與 blobs/ 的 OCI Image Layout。"),
  },
  kubernetes_manifests: {
    label: bilingual("Kubernetes configuration", "Kubernetes 設定"),
    detail: bilingual("Check exported Kubernetes settings on this computer without connecting to the live cluster.", "在這台電腦上檢查匯出的 Kubernetes 設定，不會連線到正在運作的叢集。"),
    formTitle: bilingual("Choose the Kubernetes settings you want checked", "選擇想檢查的 Kubernetes 設定"),
    formIntro: bilingual("Pick a folder of exported YAML or JSON settings. We'll find risky workload and cluster settings without connecting to the live cluster.", "選擇包含匯出 YAML 或 JSON 設定的資料夾；我們會找出危險的工作負載與叢集設定，不會連線到正式叢集。"),
    cautionTitle: bilingual("Use exported settings, not live-cluster credentials", "請使用匯出設定，不要加入正式叢集憑證"),
    cautionBody: bilingual("Do not include kubeconfig files, tokens, or certificates. This route checks saved settings only.", "請勿加入 kubeconfig、token 或憑證；這條路線只檢查已保存的設定。"),
    directoryLabel: bilingual("Kubernetes settings folder", "Kubernetes 設定資料夾"),
    selection: bilingual("Choose the Kubernetes configuration folder", "選擇 Kubernetes 設定資料夾"),
    attachAction: bilingual("Add these Kubernetes settings", "加入這些 Kubernetes 設定"),
    technical: bilingual("Input profile: kubernetes_manifests. The folder may contain Kubernetes YAML and JSON manifest files.", "輸入格式：kubernetes_manifests。資料夾可包含 Kubernetes YAML 與 JSON manifest 檔。"),
  },
  kubernetes_node_snapshot: {
    label: bilingual("Exported Kubernetes node settings", "匯出的 Kubernetes 節點設定"),
    detail: bilingual("Check an exported copy of one node's security settings on this computer.", "在這台電腦上檢查一份節點安全設定的匯出副本。"),
    formTitle: bilingual("Choose the Kubernetes node settings you want checked", "選擇想檢查的 Kubernetes 節點設定"),
    formIntro: bilingual("Pick one exported node-settings folder. We'll check the saved security settings without mounting or reading the live node.", "選擇一個匯出的節點設定資料夾；我們會檢查已保存的安全設定，不會掛載或讀取正式節點。"),
    cautionTitle: bilingual("Use an exported node snapshot", "請使用匯出的節點快照"),
    cautionBody: bilingual("This route checks the saved snapshot only. Do not add live-cluster credentials or unrelated host files.", "這條路線只檢查已保存的快照；請勿加入正式叢集憑證或其他主機檔案。"),
    directoryLabel: bilingual("Exported node-settings folder", "匯出節點設定資料夾"),
    selection: bilingual("Choose the exported node-settings folder", "選擇匯出的節點設定資料夾"),
    attachAction: bilingual("Add these node settings", "加入這些節點設定"),
    technical: bilingual("Input profile: kubernetes_node_snapshot. Choose the parent of node-snapshot/; the bounded CIS snapshot is read without mounting the host filesystem.", "輸入格式：kubernetes_node_snapshot。請選擇 node-snapshot/ 的父目錄；產品不掛載 host filesystem，只讀取有限範圍的 CIS 快照。"),
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
  inventory: { label: bilingual("Read-only inventory", "唯讀盤點"), detail: bilingual("Read the names of the selected items only", "只讀取已選項目的名稱") },
  configuration: { label: bilingual("Review settings", "檢查設定"), detail: bilingual("Read configuration or an attached snapshot without making changes", "唯讀檢查設定或已附加快照") },
  local_artifact: { label: bilingual("Review the saved local copy", "檢查本機副本"), detail: bilingual("Check the prepared copy without changing your project", "檢查準備好的副本，不會修改你的專案") },
  public_data: { label: bilingual("Use public records", "使用公開資料"), detail: bilingual("Use saved DNS, certificate, and similar public records only", "只使用 DNS、憑證等既有公開資料") },
  low_impact_external: { label: bilingual("Low-impact connection checks", "低影響連線檢查"), detail: bilingual("Send limited requests only to the confirmed target", "只對已確認目標發出受限連線") },
  active_external: { label: bilingual("Approved active website tests", "已核准的主動網站測試"), detail: bilingual("Use only with written approval and a specific test list", "只在取得書面核准與指定測試清單時使用") },
  passive: { label: bilingual("Use public records", "使用公開資料"), detail: bilingual("Legacy-case name for the public-records mode", "相容舊案件的公開資料模式") },
  active: { label: bilingual("Approved active website tests", "已核准的主動網站測試"), detail: bilingual("Use only with written approval and a specific test list", "只在取得書面核准與指定測試清單時使用") },
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

const coverageStatePlainCopy: Record<CoverageState, { short: BilingualText; description: BilingualText }> = {
  discovered_authorized_scanned: {
    short: bilingual("Finished", "已完成"),
    description: bilingual("The selected checks for these items finished.", "這些項目的已選檢查都已完成。"),
  },
  discovered_not_authorized: {
    short: bilingual("Choose checks", "選擇檢查方式"),
    description: bilingual("These items are ready for you to choose checks in step 3.", "這些項目已整理好，請在步驟 3 選擇檢查方式。"),
  },
  authorized_incomplete: {
    short: bilingual("Needs attention", "需要處理"),
    description: bilingual("Some checks did not finish and can be continued.", "部分檢查尚未完成，可以繼續執行。"),
  },
  source_connected_none: {
    short: bilingual("Nothing found", "沒有找到"),
    description: bilingual("This source had nothing to add to the list this time.", "這個來源本次沒有內容可加入清單。"),
  },
  source_unavailable_unknown: {
    short: bilingual("Connect source", "連接來源"),
    description: bilingual("Connect this source to see what it contains.", "連接這個來源後，就能查看其中內容。"),
  },
  not_applicable: {
    short: bilingual("Not included", "未納入"),
    description: bilingual("This source is not included in the current scan.", "這個來源未納入目前的掃描。"),
  },
};

const NUCLEI_TEMPLATE_REVISION = "nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012";

const pageCopy = {
  headerEyebrow: bilingual("Set up your scan", "設定這次掃描"),
  headerTitle: bilingual("Bring everything you want to check into one place", "把想檢查的網站、系統與程式碼集中到一起"),
  headerDescription: bilingual(
    "Add a website, cloud account, internal system, or local project. We'll organize everything into a clear list and suggest the right checks.",
    "加入網站、雲端帳號、內部系統或本機專案；我們會整理成清楚清單，並建議適合的檢查。",
  ),
  refresh: bilingual("Find what I can scan", "整理可掃描項目"),
  refreshing: bilingual("Refreshing…", "正在重新確認…"),
  journeyLabel: bilingual("Three steps to set up a scan", "設定掃描的三個步驟"),
  step1Short: bilingual("Connect", "加入"),
  step1Title: bilingual("Add what you want to protect", "加入想保護的內容"),
  step1Detail: bilingual("Choose the easiest input: cloud, local files, an inventory, or targets already entered.", "選擇最方便的方式：雲端、本機檔案、盤點檔，或已輸入的目標。"),
  step2Short: bilingual("Review", "查看"),
  step2Title: bilingual("See everything in one list", "在同一份清單查看全部內容"),
  step2Detail: bilingual("Check the names and sources, then move on when the list looks right.", "確認名稱與來源，清單看起來沒問題就繼續。"),
  step3Short: bilingual("Choose", "選擇"),
  step3Title: bilingual("Pick the checks you want to run", "選擇想執行的檢查"),
  step3Detail: bilingual("Start with recommended settings and customize only when you need to.", "先用建議設定，需要時再打開進階選項。"),
  addEyebrow: bilingual("Step 1", "步驟 1"),
  addTitle: bilingual("Add something to scan", "加入要掃描的內容"),
  addDescription: bilingual("Choose the option that matches what you have now. You can always add another source later.", "選擇最符合你目前資料的方式；之後隨時都能再加入其他來源。"),
  providerTitle: bilingual("Cloud account", "雲端帳號"),
  providerBody: bilingual("Sign in through AWS, Azure, Google Cloud, or Microsoft and turn cloud settings into a fix list.", "透過 AWS、Azure、Google Cloud 或 Microsoft 登入，把雲端設定整理成改善清單。"),
  providerOpen: bilingual("Connect a cloud account", "連接雲端帳號"),
  providerClose: bilingual("Close cloud setup", "關閉雲端設定"),
  snapshotTitle: bilingual("An inventory file", "盤點檔"),
  snapshotBody: bilingual("Already have a JSON export? Add it here and review the assets locally.", "已經有 JSON 匯出檔？直接加入並在本機整理資產。"),
  snapshotOpen: bilingual("Add an inventory file", "加入盤點檔"),
  snapshotClose: bilingual("Close inventory form", "關閉盤點檔表單"),
  workspaceTitle: bilingual("Code, infrastructure, containers, or Kubernetes", "程式碼、基礎設施、容器或 Kubernetes"),
  workspaceBody: bilingual("Choose a local folder and find issues without uploading the project.", "選擇本機資料夾，不必上傳專案就能找問題。"),
  workspaceOpen: bilingual("Choose a project", "選擇專案"),
  workspaceClose: bilingual("Close local-files form", "關閉本機檔案表單"),
  guidedWorkspaceOpen: bilingual("Show setup", "顯示設定"),
  guidedWorkspaceClose: bilingual("Hide setup", "隱藏設定"),
  knownTargetsTitle: bilingual("Website, IP, or internal system already added", "已加入的網站、IP 或內部系統"),
  knownTargetsBody: bilingual("Turn the targets from your scan project into a review list.", "把掃描專案中的目標整理成可確認的清單。"),
  networkReadyTitle: bilingual("Review your network target", "確認你的網路目標"),
  networkReadyBody: bilingual("Check the exact website, IP address, or internal network below. We've already chosen a useful low-impact starting point.", "在下方確認精確的網站、IP 位址或內部網路；我們已準備好實用的低影響起始設定。"),
  networkReadyAction: bilingual("Review this target", "確認這個目標"),
  otherInputsSummary: bilingual("Other ways to add scan inputs", "其他加入掃描內容的方式"),
  otherInputsBody: bilingual("Open these technical options only when the suggested path does not match what you have.", "只有建議路徑不符合現況時，才需要打開這些技術選項。"),
  selectDoesNotAuthorizeTitle: bilingual("How scan approval works", "掃描確認方式"),
  selectDoesNotAuthorizeBody: bilingual("Adding something here only prepares the scan. Before a network check runs, you'll review the exact target, scan type, and limits in step 3.", "在這裡加入內容只會準備掃描；執行網路檢查前，你會在步驟 3 確認目標、檢查方式與限制。"),
  situationSummary: bilingual("Not sure which option to choose?", "不確定該選哪一種？"),
  situationIntro: bilingual("Find your situation below and follow the suggested path.", "在下方找到最接近的情況，照著建議方式開始。"),

  sourceEyebrow: bilingual("Saved inventory", "已保存的盤點檔"),
  sourceTitle: bilingual("Attach one saved JSON inventory", "附加一份已保存的 JSON 盤點檔"),
  sourceIntro: bilingual("Choose an inventory export you already have. We'll copy it into this scan project and organize the assets on this computer.", "選擇現有的盤點匯出檔；我們會複製到掃描專案，並在這台電腦上整理資產。"),
  noSecretsSnapshotTitle: bilingual("Remove passwords, tokens, private keys, and other secrets first", "請先移除密碼、token、私鑰與其他秘密值"),
  noSecretsSnapshotBody: bilingual("Include only what you want checked. This step adds items to the list; you will confirm them before any network scan can run.", "只保留想檢查的內容。這一步只會把項目加入清單；任何網路掃描執行前，你都會再次確認。"),
  demoFileTitle: bilingual("Browser preview cannot read a local file", "瀏覽器預覽不會讀取本機檔案"),
  demoFileBody: bilingual("Open the signed desktop app to attach a real snapshot. This preview only shows the steps.", "請使用已簽章的桌面程式附加真實快照；目前預覽只會顯示步驟。"),
  sourceKind: bilingual("What produced this inventory?", "這份盤點檔來自哪裡？"),
  snapshotFormat: bilingual("Saved-file format", "盤點檔格式"),
  snapshotFormatHelp: bilingual("The choice is limited by the source. The product never guesses with a general-purpose parser.", "格式會依來源限制；產品不會用通用解析器猜測。"),
  inputTechnicalSummary: bilingual("Technical input details", "輸入技術細節"),
  localEngineDetail: bilingual("Bound scanner engines: {engines}.", "綁定的掃描引擎：{engines}。"),
  sourceLabel: bilingual("Name shown in this scan", "這次掃描中顯示的名稱"),
  sourceLabelPlaceholder: bilingual("Example: Production AWS inventory", "例如：正式環境 AWS 盤點"),
  sourceLabelHelp: bilingual("Use a recognizable name. Do not include credentials or secrets.", "請使用容易辨識的名稱，不要放入憑證或秘密值。"),
  jsonSnapshot: bilingual("JSON file", "JSON 檔案"),
  choosingPicker: bilingual("Opening the file picker…", "正在開啟檔案選擇器…"),
  chooseJson: bilingual("Choose one .json file", "選擇一份 .json 檔"),
  snapshotPathHelp: bilingual("Only this file is copied. Its original folder location stays on this computer.", "只會複製這個檔案；原本的資料夾位置會留在這台電腦上。"),
  sourceAfterHelp: bilingual("After attaching it, refresh what the product can see.", "附加後仍要重新確認產品看得到什麼。"),
  connectSnapshot: bilingual("Copy and attach this inventory", "複製並附加這份盤點檔"),
  connectingSnapshot: bilingual("Attaching…", "正在附加…"),
  fileFallback: bilingual("Selected JSON file", "已選取 JSON 檔"),
  sourceErrorJson: bilingual("Choose one .json file. Nothing was read or copied.", "只接受一份 .json 檔；沒有讀取或複製這個檔案。"),
  sourceErrorPicker: bilingual("The local file picker could not open. Nothing was read or copied.", "無法開啟本機檔案選擇器；沒有讀取或複製任何檔案。"),
  sourceErrorLabel: bilingual("Enter a name that identifies this inventory.", "請輸入能辨識這份來源的標籤。"),
  sourceErrorPath: bilingual("Choose one JSON inventory first.", "請先明確選擇一份 JSON 快照。"),

  workspaceEyebrow: bilingual("Saved local copy", "保存本機副本"),
  workspaceFormTitle: bilingual("Choose the local project you want checked", "選擇想檢查的本機專案"),
  workspaceIntro: bilingual("Pick one folder. The app prepares a private local copy for the scan and leaves your working files untouched.", "選擇一個資料夾；產品會準備掃描用的本機副本，不會動到你的工作檔案。"),
  gitWarningTitle: bilingual("Your project stays local and unchanged", "專案留在本機，檔案不會被修改"),
  gitWarningBody: bilingual("Only the selected folder is copied into the private local scan. Detected secret values are masked in results.", "只會把選定資料夾複製到私密的本機掃描；找到的秘密值會在結果中遮罩。"),
  gitTechnicalBody: bilingual("Every .git directory is excluded, so Git history, refs, hooks, and credentials stored inside .git are not opened or copied.", "所有 .git 目錄都會排除，因此不會開啟或複製其中的 Git history、refs、hooks 與 credentials。"),
  localNoGrantTitle: bilingual("The input type is fixed, but attaching it does not grant scan permission", "輸入類型會固定，但附加動作不會授予掃描權限"),
  localNoGrantBody: bilingual("The case saves a snapshot ID, input type, content hash, and relative-path manifest—not the original host path. Confirm ownership and read-only local review in step 3.", "案件只保存快照 ID、輸入類型、內容雜湊與相對路徑 manifest，不保存原始主機路徑。請在步驟 3 確認所有權與本機唯讀檢查。"),
  demoFolderTitle: bilingual("Browser preview cannot read a local folder", "瀏覽器預覽不會讀取本機目錄"),
  demoFolderBody: bilingual("Open the signed desktop app to create a real local snapshot. This preview only shows the steps.", "請使用已簽章的桌面程式建立真實本機快照；目前預覽只會顯示步驟。"),
  inputType: bilingual("What are you attaching?", "你要附加什麼？"),
  localLabel: bilingual("Name shown in this scan", "這次掃描中顯示的名稱"),
  localLabelPlaceholder: bilingual("Example: Production container image", "例如：Production container image"),
  localLabelHelp: bilingual("Use a name you will recognize later. Do not include passwords, keys, or tokens.", "使用之後容易辨識的名稱，不要放入密碼、金鑰或 token。"),
  localDirectory: bilingual("Folder to copy", "要複製的資料夾"),
  localPathHelp: bilingual("Only the folder name is shown here. Its full location stays on this computer.", "這裡只會顯示資料夾名稱；完整位置會留在這台電腦上。"),
  workspaceAfterHelp: bilingual("This creates a private local copy. It does not start a scan.", "這只會建立私密的本機副本，不會開始掃描。"),
  attachWorkspace: bilingual("Prepare this project for scanning", "準備這份專案進行掃描"),
  attachingWorkspace: bilingual("Creating the copy…", "正在建立副本…"),
  folderFallback: bilingual("Selected folder", "已選取資料夾"),
  workspaceErrorPicker: bilingual("The local folder picker could not open. Nothing was read or copied.", "無法開啟本機目錄選擇器；沒有讀取或複製任何目錄。"),
  workspaceErrorLabel: bilingual("Enter a name for this project.", "請輸入這份專案的名稱。"),
  workspaceErrorPath: bilingual("Choose one project folder first.", "請先選擇一個專案資料夾。"),

  seeEyebrow: bilingual("Step 2", "步驟 2"),
  seeTitle: bilingual("Review what we found", "查看整理結果"),
  seeDescription: bilingual("Check the list below. If something is missing, add another source above; if it looks right, continue to choose the checks.", "確認下方清單；若少了什麼，就回上方再加來源。清單沒問題，就繼續選擇檢查方式。"),
  continueStep3: bilingual("Choose scan settings", "選擇掃描方式"),
  candidateAssets: bilingual("Items found", "找到的項目"),
  candidateDetail: bilingual("Websites, systems, and projects in this scan", "這次掃描中的網站、系統與專案"),
  scannedAssets: bilingual("Checks completed", "已完成檢查"),
  scannedDetail: bilingual("All selected checks for these items finished", "這些項目的所有已選檢查都已完成"),
  incompleteAssets: bilingual("Needs attention", "需要處理"),
  incompleteDetail: bilingual("Some checks did not finish; you can continue them", "部分檢查尚未完成，可以繼續執行"),
  pendingAssets: bilingual("Not set up yet", "尚未設定"),
  pendingDetail: bilingual("Choose checks for these items in step 3", "在步驟 3 為這些項目選擇檢查方式"),
  metricsLabel: bilingual("What the product can currently see", "產品目前看得到的摘要"),
  unknownTitle: bilingual("{count} sources still need data", "{count} 個來源還需要資料"),
  unknownBody: bilingual("Connect or import these sources to see what they contain.", "連接或匯入這些來源，就能查看其中內容。"),
  noneTitle: bilingual("{count} connected sources found no items", "{count} 個已連接來源沒有找到項目"),
  noneBody: bilingual("The source connected successfully but had nothing to add to this list right now.", "來源已成功連接，只是目前沒有內容可加入這份清單。"),
  sourcesEyebrow: bilingual("Your sources", "你的資料來源"),
  sourcesTitle: bilingual("Everything connected to this scan", "這次掃描已連接的內容"),
  noSourcesTitle: bilingual("No input has been attached yet", "尚未附加任何輸入"),
  noSourcesBody: bilingual("Add an inventory file or local project in step 1, then refresh this list.", "請先在步驟 1 加入盤點檔或本機專案，再重新整理這份清單。"),
  assetsCount: bilingual("{count} items", "{count} 個項目"),
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
  showAll: bilingual("Show all items", "顯示所有項目"),

  allowEyebrow: bilingual("Step 3", "步驟 3"),
  allowTitle: bilingual("Choose what to scan", "選擇要掃描的內容"),
  allowDescription: bilingual("Select one or more items, choose the checks, and save. Recommended settings work for most scans; advanced controls are still available.", "選擇一個或多個項目、挑選檢查方式並儲存。大多數情況直接使用建議設定即可，進階控制仍完整保留。"),
  pendingNoticeTitle: bilingual("Choose an item below", "從下方選擇一個項目"),
  pendingNoticeBody: bilingual("Select an item to see the checks we recommend for it.", "選取項目後，就會看到我們建議的檢查方式。"),
  selectedCount: bilingual("{count} selected", "已選 {count} 項"),
  chooseAsset: bilingual("Choose {name}", "選取 {name}"),
  incompatibleSelection: bilingual("Set up each website or internal system separately. Finish or clear the current selection first.", "網站或內部系統需要逐一設定；請先完成或清除目前的選取。"),
  addPermission: bilingual("Select this item again to finish its scan setup.", "再次選取這個項目，即可完成掃描設定。"),
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
  clearSelection: bilingual("Clear selected items", "清除已選項目"),
  grantEyebrow: bilingual("Scan choices", "掃描選項"),
  grantTitle: bilingual("Set up checks for {count} selected items", "設定 {count} 個已選項目的檢查"),
  grantDescription: bilingual("Review our suggestions, confirm you are allowed to run the checks, then save.", "確認建議內容與你有權執行這些檢查，再儲存。"),
  guidedNetworkGrantDescription: bilingual("The exact target and recommended low-impact check are shown below.", "下方會顯示精確目標與建議的低影響檢查。"),
  guidedLocalGrantDescription: bilingual("Review the saved local copy and the recommended checks, then add it to this scan.", "確認已保存的本機副本與建議檢查，再加入這次掃描。"),
  guidedCloudGrantDescription: bilingual("Your provider sign-in already identifies the account. Review the exact account and read-only checks below, then add it to this scan.", "雲端服務商登入已確認帳號；請查看下方的精確帳號與唯讀檢查，再加入這次掃描。"),
  presetTitle: bilingual("Recommended settings are ready", "建議設定已準備好"),
  presetBody: bilingual("We picked a safe, useful starting point for the selected items. You can still change anything before saving.", "我們已依所選項目準備安全又實用的起始設定；儲存前仍可調整。"),
  guidedNetworkPreset: bilingual(
    "We'll check only {target} with conservative connection settings. You can change the technical details if needed.",
    "這次只會用保守的連線設定檢查 {target}；需要時可修改技術細節。",
  ),
  guidedNetworkTechnicalPreset: bilingual(
    "Current preset: {protocol}, {count} exact service ports, one connection at a time.",
    "目前設定：{protocol}、{count} 個精確服務連接埠、一次一個連線。",
  ),
  noCommonTitle: bilingual("These items need different scan setups", "這些項目需要不同的掃描設定"),
  noCommonBody: bilingual("Set up websites and internal systems separately from cloud accounts and local projects.", "請把網站與內部系統，和雲端帳號與本機專案分開設定。"),
  allowedQuestion: bilingual("What should we check?", "想檢查哪些內容？"),
  changeScanType: bilingual("Use a different scan type (advanced)", "改用其他掃描方式（進階）"),

  externalEyebrow: bilingual("Target confirmation", "確認掃描目標"),
  externalTitle: bilingual("Confirm {name}", "確認 {name}"),
  externalDescription: bilingual("We've chosen conservative settings. Confirm this is your website or internal system, then save.", "我們已選好保守設定；確認這是你的網站或內部系統，再儲存即可。"),
  guidedExternalDescription: bilingual("This is the exact target saved in your scan project.", "這是掃描專案中保存的精確目標。"),
  advancedScanSettings: bilingual("Advanced scan settings", "進階掃描設定"),
  advancedScanSettingsHelp: bilingual("Connection details, speed limits, and the active-test list", "連線細節、速度限制與主動測試清單"),
  activeSetupTitle: bilingual("Active testing needs one more step", "主動測試還需要一個步驟"),
  activeSetupBody: bilingual("Open Advanced scan settings and add the approved test list before saving.", "請打開「進階掃描設定」，加入已核准的測試清單後再儲存。"),
  sourcePublic: bilingual("Public website", "公開網站"),
  sourceInternal: bilingual("Internal system", "內部系統"),
  sourceExposureUnknown: bilingual("Needs source details", "需要補充來源資料"),
  noDirectTitle: bilingual("We cannot confirm that this system is open to the internet", "目前無法確認這個系統是否對外開放"),
  noDirectBody: bilingual("You can still review public records. To connect directly, update the source information first.", "你仍可查看公開資料；若要直接連線，請先更新來源資料。"),
  internalGrantTitle: bilingual("This is an internal system", "這是內部系統"),
  internalGrantBody: bilingual("To connect from this computer, turn on the internal-network confirmation below.", "若要從這台電腦連線，請開啟下方的內部網路確認。"),
  noTargetTitle: bilingual("Add one specific website or IP address first", "請先加入一個明確的網站或 IP 位址"),
  noTargetBody: bilingual("Go back to the scan project, enter one complete address, then refresh this list.", "請回到掃描專案，輸入一個完整位址，再重新整理這份清單。"),
  declaredServiceTitle: bilingual("Prepared from the website URL—review before approving", "已依網站網址預填；核准前請重新確認"),
  declaredServiceBody: bilingual("The case suggested {protocol} port {port} and path {path}. Only protocol and port are prefilled below; the path is context, not permission. Confirm the exact live service yourself.", "案件依原始網址建議 {protocol}、連接埠 {port} 與路徑 {path}。下方只預填協定與連接埠；路徑只是提示，不是許可。請自行確認精確服務。"),
  canonicalTarget: bilingual("Website or system to check", "要檢查的網站或系統"),
  canonicalTargetHelp: bilingual("This value comes from the item you added. Return to the scan project if it needs to change.", "這個值來自你加入的項目；若要修改，請回到掃描專案。"),
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
  sensitiveTitle: bilingual("I confirm this scan may connect to the selected internal network", "我確認這次掃描可以連線到所選內部網路"),
  sensitiveBody: bilingual("Turn this on only when the system owner approved access from this computer. Most public websites leave it off.", "只有系統負責人已核准從這台電腦存取時才開啟；一般公開網站不需要。"),
  sensitiveTechnicalTitle: bilingual("Exact internal-network behavior", "內部網路的精確行為"),
  sensitiveTechnicalBody: bilingual("This permits only the selected target to resolve to approved private, loopback, or link-local networks. Metadata endpoints remain blocked, and no additional target is added.", "只允許所選目標解析到已核准的 private、loopback 或 link-local 網段；metadata endpoints 仍保持阻擋，也不會加入其他目標。"),
  ownershipTitle: bilingual("I confirm that I am allowed to scan every selected item", "我確認自己有權掃描每一個已選項目"),
  externalOwnershipTitle: bilingual("I confirm this is my website or a system I am allowed to scan", "我確認這是我的網站，或是我有權掃描的系統"),
  internalOwnershipTitle: bilingual("I confirm this is an internal system I am allowed to scan", "我確認這是我有權掃描的內部系統"),
  ownershipBody: bilingual("If you are unsure, ask the system owner before continuing.", "如果不確定，請先向系統負責人確認。"),
  authorityRequired: bilingual("Approval reference (required)", "核准紀錄（必填）"),
  scopeNote: bilingual("Note (optional)", "備註（選填）"),
  authorityPlaceholder: bilingual("Example: ticket or contract number and approver", "例如：工單／合約編號與核准人"),
  notePlaceholder: bilingual("Example: internal approval for this read-only review", "例如：本次唯讀檢查的內部核准紀錄"),
  authorityHelp: bilingual("Add the ticket, contract, or approver that confirms this scan. Never enter a password, key, or token here.", "填入可證明這次掃描已核准的工單、合約或核准人；不要放入密碼、金鑰或 token。"),
  noteHelp: bilingual("Never enter a secret or credential here.", "不要在這裡填入秘密值或憑證。"),
  activeAuthorityLength: bilingual("An active-test permission reference needs at least 8 characters.", "主動測試的授權參考至少需要 8 個字元。"),
  grantBoundaryHelp: bilingual("Next, open Scan progress and press Start when you're ready.", "下一步到「掃描進度」，準備好時再按下開始。"),
  saveGrant: bilingual("Save scan choices", "儲存掃描選項"),
  confirmAndSave: bilingual("I confirm and prepare this scan", "我確認並準備這次掃描"),
  useSignedInCloud: bilingual("Use this signed-in account", "使用這個已登入帳號"),
  savingGrant: bilingual("Recording…", "正在記錄…"),
  defaultScopeNote: bilingual("The user confirmed ownership and the read-only boundary item by item in the local interface.", "使用者已在本機介面逐項確認資產所有權與唯讀範圍。"),
  guidedNetworkConfirmation: bilingual("The user explicitly confirmed this exact low-impact network target in the guided local interface.", "使用者已在本機引導介面明確確認這個精確的低影響網路目標。"),
  guidedLocalConfirmation: bilingual("The user explicitly selected this saved local copy and confirmed the recommended read-only checks.", "使用者已明確選擇這份已保存的本機副本，並確認建議的唯讀檢查。"),
  guidedCloudConfirmation: bilingual("The user signed in through the provider and explicitly added this exact account with the displayed read-only checks.", "使用者已透過雲端服務商登入，並明確以畫面所列唯讀檢查加入這個精確帳號。"),
  advancedLocalInputSummary: bilingual("Use a different kind of local input", "改用其他本機輸入類型"),
  advancedLocalInputHelp: bilingual("The route you chose is already selected. Change this only when you meant to attach a different kind of project or export.", "你選擇的路線已經設定完成；只有要改附加其他類型的專案或匯出檔時才需要變更。"),

  emptyUnknownTitle: bilingual("No items yet because a source is still missing", "尚未看到項目，因為還缺少資料來源"),
  emptyUnknownBody: bilingual("At least one needed input is missing. Do not interpret the empty list as proof that the environment has no assets.", "至少一個需要的輸入尚未連接；不能把空清單解讀為環境沒有資產。"),
  emptyNoneTitle: bilingual("The connected sources found no items this time", "已連接的來源這次沒有找到項目"),
  emptyNoneBody: bilingual("The inputs were available and returned zero items. This is different from having no input and therefore no visibility.", "輸入確實可用且回傳零項；這與缺少輸入、因此無法看見的未知狀態不同。"),
  emptyNeverTitle: bilingual("This list has not been refreshed yet", "這份清單尚未重新整理"),
  emptyNeverBody: bilingual("Attach an input in step 1, then refresh what the product can see.", "請先在步驟 1 附加輸入，再重新確認產品看得到什麼。"),
  emptyFilterTitle: bilingual("No items match this filter", "沒有項目符合這個篩選條件"),
  emptyFilterBody: bilingual("Clear the filter to review the other items.", "請清除篩選以查看其他項目。"),

  grantsEyebrow: bilingual("Saved scan access", "已儲存的掃描許可"),
  grantsTitle: bilingual("Network checks already approved", "已確認的網路檢查"),
  grantsDescription: bilingual("These saved choices keep future runs consistent. Open a record when you need the exact technical limits.", "這些選擇會讓後續掃描維持一致；需要時可打開紀錄查看精確技術限制。"),
  grantsCount: bilingual("{count} saved setups", "{count} 份已儲存設定"),
  grantTechnical: bilingual("View saved scan settings", "查看已儲存的掃描設定"),
  expires: bilingual("Expires {date}", "到期 {date}"),
  sensitiveAllowed: bilingual("Internal network access allowed", "已允許內部網路存取"),
  sensitiveBlocked: bilingual("Internal network access off", "未開啟內部網路存取"),
  targetTerm: bilingual("Target", "目標"),
  protocolPortsTerm: bilingual("Protocol and ports", "協定與連接埠"),
  noDirectPort: bilingual("No direct-connection port", "沒有直接連線連接埠"),
  rateTerm: bilingual("Request limits", "請求限制"),
  templatesTerm: bilingual("Test-list policy", "測試清單政策"),
  authorityTerm: bilingual("Permission reference", "授權參考"),
  approvalTerm: bilingual("Recorded by", "記錄者"),
  prohibitedAll: bilingual("Headless browser, out-of-band callback, fuzzing, file upload, denial of service, and credential attacks are all blocked.", "無頭瀏覽器、站外回呼、模糊測試、檔案上傳、阻斷服務與密碼攻擊全部禁止。"),
  finalNoticeTitle: bilingual("How local inventory and network scans differ", "本機盤點與網路掃描有什麼不同"),
  finalNoticeBody: bilingual("Inventory files can be reviewed locally. Checks that connect to a website or network target use the exact settings and approval saved in step 3.", "盤點檔可以直接在本機整理；會連線到網站或網路目標的檢查，則使用步驟 3 儲存的明確設定與核准紀錄。"),
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
    detail: bilingual("Use the website already added to this project, then choose it in step 3. Recommended web settings are filled in for you.", "使用專案中已加入的網站，再到步驟 3 選取；系統會幫你填好建議的網站掃描設定。"),
  },
  {
    id: "public-target",
    icon: "coverage" as const,
    title: bilingual("Public IP addresses or domains", "公開 IP 或網域"),
    detail: bilingual("Use the targets already added to this project, then choose whether to review public records or run a light connection check.", "使用專案中已加入的目標，再選擇查看公開資料或執行低影響連線檢查。"),
  },
  {
    id: "internal-it",
    icon: "lock" as const,
    title: bilingual("Internal IT systems", "內部 IT 環境"),
    detail: bilingual("Choose the approved internal systems, confirm this computer can reach them, and use the suggested low-impact settings.", "選擇已核准的內部系統、確認這台電腦能連線，再使用建議的低影響設定。"),
  },
  {
    id: "source-code",
    icon: "file" as const,
    title: bilingual("Code you wrote or generated with AI", "自己寫或 AI 生成的程式碼"),
    detail: bilingual("Choose one project folder, then check it locally without changing its files.", "選擇一個專案資料夾，在本機檢查，而且不會修改任何檔案。"),
  },
  {
    id: "infrastructure-code",
    icon: "file" as const,
    title: bilingual("Infrastructure code", "基礎設施程式碼"),
    detail: bilingual("Choose the Terraform, JSON, or YAML project and run the recommended configuration checks locally.", "選擇 Terraform、JSON 或 YAML 專案，在本機執行建議的設定檢查。"),
  },
  {
    id: "container",
    icon: "database" as const,
    title: bilingual("Container image", "容器映像"),
    detail: bilingual("Choose an exported container image and review its packages, vulnerabilities, and software list locally.", "選擇匯出的容器映像，在本機查看套件、弱點與軟體清單。"),
  },
  {
    id: "kubernetes",
    icon: "shield" as const,
    title: bilingual("Kubernetes", "Kubernetes"),
    detail: bilingual("Choose exported cluster or node settings, then run the recommended Kubernetes checks.", "選擇匯出的叢集或節點設定，再執行建議的 Kubernetes 檢查。"),
  },
  {
    id: "cloud",
    icon: "database" as const,
    title: bilingual("AWS, Azure, Google Cloud, or Microsoft 365", "AWS、Azure、Google Cloud 或 Microsoft 365"),
    detail: bilingual("Sign in through the provider, import the cloud inventory, then choose the accounts and settings you want reviewed.", "透過服務商登入、匯入雲端盤點，再選擇想檢查的帳號與設定。"),
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
  authorized: bilingual("Target confirmed", "目標已確認"),
  pending: bilingual("Choose checks first", "請先選擇檢查方式"),
  excluded: bilingual("Not included in this scan", "未納入這次掃描"),
  unknown: bilingual("Confirm who owns it", "請確認負責人"),
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
      "Confirm this is your internal system, then use the recommended low-impact settings.",
      "確認這是你的內部系統，再使用建議的低影響設定。",
    );
  }
  if (asset.platform === "external" && asset.type === "ip") {
    return bilingual(
      "Choose public-record review or a light connection check for this IP address.",
      "為這個 IP 選擇公開資料盤點，或低影響連線檢查。",
    );
  }
  if (asset.platform === "external") {
    return bilingual(
      "Confirm this is your website, then use the recommended scan settings.",
      "確認這是你的網站，再使用建議的掃描設定。",
    );
  }
  if (asset.platform === "code") {
    return asset.localInputProfile === "iac_working_tree"
      ? bilingual("Allow read-only review of this saved infrastructure-code copy.", "允許唯讀檢查這份已保存的基礎設施程式碼副本。")
      : bilingual("Allow read-only review of this saved source-code copy.", "允許唯讀檢查這份已保存的程式碼副本。");
  }
  if (asset.platform === "container") {
    return bilingual("Confirm this is the container image you want checked.", "確認這是你想檢查的容器映像。");
  }
  if (asset.platform === "kubernetes") {
    return asset.localInputProfile
      ? bilingual("Allow offline review of this saved Kubernetes input only.", "只允許離線檢查這份已保存的 Kubernetes 輸入。")
      : bilingual("Confirm that this is the Kubernetes cluster you want checked.", "確認這是你想檢查的 Kubernetes 叢集。");
  }
  return bilingual(
    "Confirm this is the cloud account you want checked, then choose the recommended read-only checks.",
    "確認這是你想檢查的雲端帳號，再選擇建議的唯讀檢查。",
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

// Ordered by usefulness for a first low-impact inventory. A CIDR receives only
// as many ports as keep the frozen address/port set comfortably below the
// managed gateway's 10,000-endpoint ceiling.
const commonTcpServicePorts = [80, 443, 22, 445, 3389, 8080, 8443, 21, 25, 53, 110, 139, 143, 465, 587, 993, 995, 3306, 5432, 6379, 9100] as const;

const recommendedTcpPorts = (target: string): number[] => {
  const match = /^(?:\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$/u.exec(target.trim());
  if (!match) return [...commonTcpServicePorts];
  const prefix = Number(match[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return [80, 443];
  const total = 2 ** (32 - prefix);
  const addresses = prefix <= 30 ? Math.max(1, total - 2) : total;
  const safePortCount = Math.max(1, Math.floor(9_000 / addresses));
  return commonTcpServicePorts.slice(0, safePortCount);
};

const parseTemplateIds = (value: string): string[] =>
  [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];

const fileNameFromPath = (path: string, fallback: string): string =>
  path.split(/[\\/]/).filter(Boolean).at(-1) ?? fallback;

export function CoveragePage({
  caseId,
  assessmentIntent,
  focusSetup,
  requestedActivities,
  coverage,
  sources,
  assets,
  scopeGrants,
  nativeMode,
  busy,
  discoveryBusy,
  onChooseSnapshot,
  onConnectSourceSnapshot,
  onChooseWorkspace,
  onAttachWorkspaceSnapshot,
  onStartDiscovery,
  onAuthorizationChanged,
  onApprovePending,
}: CoveragePageProps) {
  const { text, formatDateTime, formatNumber } = useI18n();
  const guidedLocalProfile = assessmentIntent ? localProfileByAssessmentIntent[assessmentIntent] : undefined;
  const guidedNetworkRoute = Boolean(assessmentIntent && networkAssessmentIntents.includes(assessmentIntent));
  const guidedCloudRoute = assessmentIntent === "cloud_account";
  const guidedCoverageRoute = useMemo<GuidedCoverageRoute>(() => {
    if (guidedNetworkRoute) return { kind: "network" };
    if (guidedCloudRoute) return { kind: "cloud" };
    if (guidedLocalProfile) return { kind: "local", profile: guidedLocalProfile };
    return { kind: "none" };
  }, [guidedCloudRoute, guidedLocalProfile, guidedNetworkRoute]);
  const [filter, setFilter] = useState<CoverageState | "all">("all");
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [showSourceForm, setShowSourceForm] = useState(false);
  const [showWorkspaceForm, setShowWorkspaceForm] = useState(Boolean(guidedLocalProfile));
  const [showProviderSetup, setShowProviderSetup] = useState(guidedCloudRoute);
  const [sourceKind, setSourceKind] = useState<SourceKind>("aws_organization");
  const [profile, setProfile] = useState<SnapshotParserProfile>("cloudquery");
  const [sourceLabel, setSourceLabel] = useState<string>(() => text(sourceDefinitions.aws_organization.label));
  const [selectedPath, setSelectedPath] = useState("");
  const [choosingSnapshot, setChoosingSnapshot] = useState(false);
  const [sourceFormError, setSourceFormError] = useState<BilingualText>();
  const [workspaceLabel, setWorkspaceLabel] = useState(() => text(
    guidedLocalProfile
      ? localInputDefinitions[guidedLocalProfile].label
      : bilingual("Local source-code project", "本機程式碼專案"),
  ));
  const [workspaceInputProfile, setWorkspaceInputProfile] = useState<LocalInputProfile>(guidedLocalProfile ?? "repository_working_tree");
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
  const [showAdvancedExternalSettings, setShowAdvancedExternalSettings] = useState(false);
  const [providerConnection, setProviderConnection] = useState<ProviderConnectionBoundary>();

  const counts = useMemo(
    () => Object.fromEntries(coverageStates.map((state) => [state, coverage.filter((item) => item.state === state).length])) as Record<CoverageState, number>,
    [coverage],
  );

  const filteredAssets = useMemo(
    () => (filter === "all" ? assets : assets.filter((asset) => asset.coverageState === filter)),
    [assets, filter],
  );

  const pendingAssets = assets.filter((asset) => asset.authorizationState === "pending");
  const scopeEligibleAssets = useMemo(() => assets.filter(isScopeEligible), [assets]);
  const guidedPendingAsset = useMemo(
    () => singleGuidedPendingAsset(scopeEligibleAssets, guidedCoverageRoute),
    [guidedCoverageRoute, scopeEligibleAssets],
  );
  const scannedAssets = assets.filter((asset) => asset.coverageState === "discovered_authorized_scanned").length;
  const incompleteAssets = assets.filter((asset) => asset.coverageState === "authorized_incomplete").length;
  const unknownSourceCount = coverage.filter((item) => item.state === "source_unavailable_unknown").length;
  const connectedNoAssetCount = coverage.filter((item) => item.state === "source_connected_none").length;
  const frozenExternalGrants = scopeGrants.filter((grant) => grant.externalScope);
  const selectedSource = sourceDefinitions[sourceKind];
  const selectedLocalInput = localInputDefinitions[workspaceInputProfile];
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
  const guidedLowImpactNetwork = guidedNetworkRoute && externalActivity === "low_impact_external";
  const guidedLocalConsent = Boolean(
    guidedLocalProfile
    && selectedScopeAssets.length > 0
    && selectedScopeAssets.every((asset) => Boolean(asset.localInputProfile))
    && scopeModes.length === 1
    && scopeModes[0] === "local_artifact",
  );
  const guidedCloudConsent = guidedCloudRoute
    && hasExactGuidedCloudConsent(selectedScopeAssets, providerConnection);
  const simpleGuidedConsent = guidedLowImpactNetwork || guidedLocalConsent || guidedCloudConsent;
  const requiresAuthorizationReference = Boolean(externalActivity) && !guidedLowImpactNetwork;
  const effectiveScopeConfirmation = scopeConfirmation.trim()
    || (guidedLowImpactNetwork
      ? text(pageCopy.guidedNetworkConfirmation)
      : guidedLocalConsent
        ? text(pageCopy.guidedLocalConfirmation)
        : guidedCloudConsent
          ? text(pageCopy.guidedCloudConfirmation)
          : text(pageCopy.defaultScopeNote));
  const effectiveAllowSensitiveNetworks = allowSensitiveNetworks
    || Boolean(guidedLowImpactNetwork && selectedExternalAsset?.internetExposed === false);
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
    || (selectedExternalAsset?.internetExposed === false && effectiveAllowSensitiveNetworks);
  const externalScopeReady = !externalActivity || Boolean(
    selectedExternalAsset
    && externalTarget
    && externalTargetOptions.includes(externalTarget)
    && effectiveScopeConfirmation
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
    if (service) {
      setExternalProtocol(service.protocol);
      setExternalPorts(String(service.port));
      return;
    }
    if (assessmentIntent === "external_ip_or_domain" || assessmentIntent === "internal_it_environment") {
      setExternalProtocol("tcp");
      setExternalPorts(recommendedTcpPorts(externalTarget).join(", "));
      return;
    }
    setExternalProtocol("https");
    setExternalPorts("443");
  }, [
    assessmentIntent,
    externalTarget,
    selectedExternalAsset?.id,
    selectedExternalAsset?.declaredWebService?.port,
    selectedExternalAsset?.declaredWebService?.protocol,
  ]);

  useEffect(() => {
    setShowAdvancedExternalSettings(false);
  }, [externalActivity, selectedExternalAsset?.id]);

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
    setShowAdvancedExternalSettings(false);
  };

  useEffect(() => {
    resetScopeForm();
    setShowSourceForm(false);
    setShowProviderSetup(guidedCloudRoute);
    setShowWorkspaceForm(Boolean(guidedLocalProfile));
    setProviderConnection(undefined);
    if (guidedLocalProfile) {
      setWorkspaceInputProfile(guidedLocalProfile);
      setWorkspaceLabel(text(localInputDefinitions[guidedLocalProfile].label));
      setSelectedWorkspacePath("");
      setWorkspaceFormError(undefined);
    }
  }, [caseId, assessmentIntent]);

  useEffect(() => {
    if (!focusSetup) return undefined;
    setShowProviderSetup(focusSetup === "provider");
    setShowSourceForm(focusSetup === "source");
    setShowWorkspaceForm(focusSetup === "workspace");
    const targetId = focusSetup === "provider"
      ? "coverage-cloud-connection"
      : focusSetup === "source"
        ? "source-snapshot-form"
        : "workspace-snapshot-form";
    const frame = window.requestAnimationFrame(() => {
      document.getElementById(targetId)?.scrollIntoView({ block: "start" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [caseId, focusSetup]);

  useEffect(() => {
    const asset = guidedPendingAsset;
    if (!asset) return;
    setSelectedAssets((current) => {
      if (current.length > 0) return current;
      setScopeModes(suggestedModesForAsset(requestedActivities, asset));
      if (guidedLocalProfile || guidedCloudRoute) {
        window.requestAnimationFrame(() => scrollToCoverageStep("coverage-step-3"));
      }
      return [asset.id];
    });
  }, [caseId, assessmentIntent, guidedCloudRoute, guidedLocalProfile, guidedPendingAsset, requestedActivities]);

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
      } else if (!removing && current.length === 0) {
        window.requestAnimationFrame(() => scrollToCoverageStep("coverage-step-3"));
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
    if (selectedAssets.length === 0 || scopeModes.length === 0 || (!simpleGuidedConsent && !ownershipConfirmed)) return;
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
      assertedAuthority: effectiveScopeConfirmation,
      allowSensitiveNetworks: effectiveAllowSensitiveNetworks,
    } : undefined;
    const approved = await onApprovePending(
      selectedAssets,
      scopeModes,
      effectiveScopeConfirmation,
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

  const providerInputCard = (
    <article key="provider" className={showProviderSetup ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
      <span><Icon name="database" size={20} /></span>
      <div><strong>{text(pageCopy.providerTitle)}</strong><p>{text(pageCopy.providerBody)}</p></div>
      <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showProviderSetup} onClick={() => { setShowProviderSetup((value) => !value); setShowSourceForm(false); setShowWorkspaceForm(false); }}>
        {text(showProviderSetup ? pageCopy.providerClose : pageCopy.providerOpen)}
      </button>
    </article>
  );
  const sourceInputCard = (
    <article key="snapshot" className={showSourceForm ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
      <span><Icon name="file" size={20} /></span>
      <div><strong>{text(pageCopy.snapshotTitle)}</strong><p>{text(pageCopy.snapshotBody)}</p></div>
      <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showSourceForm} aria-controls="source-snapshot-form" onClick={() => { setShowSourceForm((value) => !value); setShowWorkspaceForm(false); setShowProviderSetup(false); }}>
        {text(showSourceForm ? pageCopy.snapshotClose : pageCopy.snapshotOpen)}
      </button>
    </article>
  );
  const workspaceInputCard = (
    <article key="workspace" className={showWorkspaceForm ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
      <span><Icon name="database" size={20} /></span>
      <div>
        <strong>{text(guidedLocalProfile ? localInputDefinitions[guidedLocalProfile].label : pageCopy.workspaceTitle)}</strong>
        <p>{text(guidedLocalProfile ? localInputDefinitions[guidedLocalProfile].detail : pageCopy.workspaceBody)}</p>
      </div>
      <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showWorkspaceForm} aria-controls="workspace-snapshot-form" onClick={() => { setShowWorkspaceForm((value) => !value); setShowSourceForm(false); setShowProviderSetup(false); }}>
        {text(guidedLocalProfile
          ? showWorkspaceForm ? pageCopy.guidedWorkspaceClose : pageCopy.guidedWorkspaceOpen
          : showWorkspaceForm ? pageCopy.workspaceClose : pageCopy.workspaceOpen)}
      </button>
    </article>
  );
  const knownTargetsInputCard = (
    <article key="known-targets" className="coverage-input-card">
      <span><Icon name="coverage" size={20} /></span>
      <div><strong>{text(pageCopy.knownTargetsTitle)}</strong><p>{text(pageCopy.knownTargetsBody)}</p></div>
      <button className="button button--secondary button--small" type="button" disabled={busy} onClick={() => void onStartDiscovery()}>
        {busy ? text(pageCopy.refreshing) : text(pageCopy.refresh)}
      </button>
    </article>
  );
  const guidedNetworkInputCard = (
    <article className="coverage-input-card coverage-input-card--active">
      <span><Icon name="coverage" size={20} /></span>
      <div><strong>{text(pageCopy.networkReadyTitle)}</strong><p>{text(pageCopy.networkReadyBody)}</p></div>
      <button className="button button--primary button--small" type="button" onClick={() => scrollToCoverageStep("coverage-step-3")}>
        {text(pageCopy.networkReadyAction)}
      </button>
    </article>
  );
  const scopeModeChooser = (
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
  );

  return (
    <div className="page page--coverage">
      <PageHeader
        eyebrow={text(pageCopy.headerEyebrow)}
        title={text(pageCopy.headerTitle)}
        description={text(pageCopy.headerDescription)}
        actions={!guidedCloudRoute ? (
          <button className="button button--primary" type="button" disabled={busy} onClick={() => void onStartDiscovery()}>
            <Icon name="refresh" size={18} />
            {busy ? text(pageCopy.refreshing) : text(pageCopy.refresh)}
          </button>
        ) : undefined}
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

        {assessmentIntent ? (
          <>
            <div className="coverage-input-grid coverage-input-grid--guided">
              {guidedNetworkRoute
                ? guidedNetworkInputCard
                : guidedCloudRoute
                  ? providerInputCard
                  : workspaceInputCard}
            </div>
            <details className="coverage-situation-details coverage-advanced-inputs">
              <summary>{text(pageCopy.otherInputsSummary)}</summary>
              <p>{text(pageCopy.otherInputsBody)}</p>
              <div className="coverage-input-grid">
                {!guidedCloudRoute && providerInputCard}
                {sourceInputCard}
                {!guidedLocalProfile && workspaceInputCard}
                {!guidedNetworkRoute && !guidedCloudRoute && knownTargetsInputCard}
              </div>
            </details>
          </>
        ) : (
          <div className="coverage-input-grid">
            {providerInputCard}
            {sourceInputCard}
            {workspaceInputCard}
            {knownTargetsInputCard}
          </div>
        )}

        <details className="coverage-situation-details">
          <summary>{text(pageCopy.selectDoesNotAuthorizeTitle)}</summary>
          <p>{text(pageCopy.selectDoesNotAuthorizeBody)}</p>
        </details>

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
          <div id="coverage-cloud-connection" className="coverage-provider-slot">
            <ProviderAuthorizationPanel
              caseId={caseId}
              sources={sources}
              nativeMode={nativeMode}
              disabled={busy}
              findingAssets={discoveryBusy}
              onAuthorizationChanged={onAuthorizationChanged}
              onFindAssets={onStartDiscovery}
              onConnectionStateChanged={setProviderConnection}
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
            <h2 id="workspace-snapshot-title">{text(guidedLocalProfile ? selectedLocalInput.formTitle : pageCopy.workspaceFormTitle)}</h2>
            <p>{text(guidedLocalProfile ? selectedLocalInput.formIntro : pageCopy.workspaceIntro)}</p>
          </div>

          <InlineNotice tone="warning" title={text(guidedLocalProfile ? selectedLocalInput.cautionTitle : pageCopy.gitWarningTitle)}>
            <p>{text(guidedLocalProfile ? selectedLocalInput.cautionBody : pageCopy.gitWarningBody)}</p>
          </InlineNotice>

          {!nativeMode && (
            <InlineNotice tone="info" title={text(pageCopy.demoFolderTitle)}>
              <p>{text(pageCopy.demoFolderBody)}</p>
            </InlineNotice>
          )}

          <div className="form-grid form-grid--two">
            {!guidedLocalProfile && <label className="field">
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
            </label>}
            <label className="field">
              <span>{text(pageCopy.localLabel)}</span>
              <input required maxLength={120} value={workspaceLabel} onChange={(event) => setWorkspaceLabel(event.target.value)} placeholder={text(pageCopy.localLabelPlaceholder)} />
              <small>{text(pageCopy.localLabelHelp)}</small>
            </label>
            <div className="field">
              <span id="workspace-directory-label">{text(guidedLocalProfile ? selectedLocalInput.directoryLabel : pageCopy.localDirectory)}</span>
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
            {guidedLocalProfile && (
              <label className="field">
                <span>{text(pageCopy.advancedLocalInputSummary)}</span>
                <select
                  value={workspaceInputProfile}
                  onChange={(event) => {
                    const next = event.target.value as LocalInputProfile;
                    setWorkspaceInputProfile(next);
                    setWorkspaceLabel(text(localInputDefinitions[next].label));
                    setSelectedWorkspacePath("");
                    setWorkspaceFormError(undefined);
                  }}
                >
                  {(Object.keys(localInputDefinitions) as LocalInputProfile[]).map((inputProfile) => (
                    <option key={inputProfile} value={inputProfile}>{text(localInputDefinitions[inputProfile].label)}</option>
                  ))}
                </select>
                <small>{text(pageCopy.advancedLocalInputHelp)}</small>
              </label>
            )}
            {workspaceInputProfile === "repository_working_tree" && <p>{text(pageCopy.gitTechnicalBody)}</p>}
            <p>{text(localInputDefinitions[workspaceInputProfile].technical)}</p>
            <p><strong>{text(pageCopy.localNoGrantTitle)}</strong></p>
            <p>{text(pageCopy.localNoGrantBody)}</p>
            <p>{text(pageCopy.localEngineDetail, { engines: localInputEngines[workspaceInputProfile] })}</p>
            <code>{workspaceInputProfile}</code>
          </details>

          {workspaceFormError && <p className="form-error" role="alert"><Icon name="warning" size={16} />{text(workspaceFormError)}</p>}

          <div className="form-actions">
            {!guidedLocalProfile && <p><Icon name="lock" size={16} /> {text(pageCopy.workspaceAfterHelp)}</p>}
            <button className="button button--primary" type="submit" disabled={!nativeMode || busy || choosingWorkspace || !workspaceLabel.trim() || !selectedWorkspacePath}>
              {busy ? text(pageCopy.attachingWorkspace) : text(guidedLocalProfile ? selectedLocalInput.attachAction : pageCopy.attachWorkspace)}
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

      {shouldPromptForFirstAsset(pendingAssets.length, selectedAssets.length) && (
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
                <h3>{text(pageCopy.grantTitle, { count: formatNumber(selectedAssets.length) })}</h3>
                <p>{text(guidedLowImpactNetwork
                  ? pageCopy.guidedNetworkGrantDescription
                  : guidedLocalConsent
                    ? pageCopy.guidedLocalGrantDescription
                    : guidedCloudConsent
                      ? pageCopy.guidedCloudGrantDescription
                      : pageCopy.grantDescription)}</p>
              </div>
              <button className="icon-button" type="button" aria-label={text(pageCopy.clearSelection)} onClick={resetScopeForm}><Icon name="close" size={17} /></button>
            </div>

            <div className="coverage-recommended-callout">
              <span><Icon name="check" size={18} /></span>
              <div>
                <strong>{text(pageCopy.presetTitle)}</strong>
                <p>{guidedLowImpactNetwork && selectedExternalAsset && parsedPorts
                  ? text(pageCopy.guidedNetworkPreset, {
                    target: externalTarget || selectedExternalAsset.name,
                  })
                  : text(pageCopy.presetBody)}</p>
              </div>
            </div>

            {availableScopeModes.length === 0 ? (
              <InlineNotice tone="warning" title={text(pageCopy.noCommonTitle)}>
                <p>{text(pageCopy.noCommonBody)}</p>
              </InlineNotice>
            ) : guidedLowImpactNetwork || guidedCloudConsent ? (
              <details className="coverage-situation-details coverage-scan-type-advanced">
                <summary>{text(pageCopy.changeScanType)}</summary>
                {scopeModeChooser}
              </details>
            ) : !guidedLocalConsent ? scopeModeChooser : null}

            {externalActivity && selectedExternalAsset && limits && (
              <section className="external-scope-builder" aria-labelledby="external-scope-title">
                <div className="external-scope-builder__heading">
                  <div>
                    <p className="eyebrow">{text(pageCopy.externalEyebrow)}</p>
                    <h4 id="external-scope-title">{text(pageCopy.externalTitle, { name: selectedExternalAsset.name })}</h4>
                    <p>{text(guidedLowImpactNetwork ? pageCopy.guidedExternalDescription : pageCopy.externalDescription)}</p>
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

                {isDirectExternal && selectedExternalAsset.internetExposed === undefined && (
                  <InlineNotice tone="warning" title={text(pageCopy.noDirectTitle)}>
                    <p>{text(pageCopy.noDirectBody)}</p>
                  </InlineNotice>
                )}

                {isDirectExternal && selectedExternalAsset.internetExposed === false && !effectiveAllowSensitiveNetworks && (
                  <InlineNotice tone="warning" title={text(pageCopy.internalGrantTitle)}>
                    <p>{text(pageCopy.internalGrantBody)}</p>
                  </InlineNotice>
                )}

                {externalTargetOptions.length === 0 && (
                  <InlineNotice tone="warning" title={text(pageCopy.noTargetTitle)}>
                    <p>{text(pageCopy.noTargetBody)}</p>
                  </InlineNotice>
                )}

                {externalActivity === "active_external" && (
                  <InlineNotice tone="info" title={text(pageCopy.activeSetupTitle)}>
                    <p>{text(pageCopy.activeSetupBody)}</p>
                  </InlineNotice>
                )}

                <details
                  className="coverage-form-technical coverage-scan-advanced"
                  open={showAdvancedExternalSettings}
                  onToggle={(event) => setShowAdvancedExternalSettings(event.currentTarget.open)}
                >
                  <summary>
                    <span>{text(pageCopy.advancedScanSettings)}</span>
                    <small>{text(pageCopy.advancedScanSettingsHelp)}</small>
                  </summary>
                  {guidedLowImpactNetwork && parsedPorts && (
                    <p className="coverage-technical-preset-summary">{text(pageCopy.guidedNetworkTechnicalPreset, {
                      protocol: externalProtocol.toUpperCase(),
                      count: formatNumber(parsedPorts.length),
                    })}</p>
                  )}
                  {selectedExternalAsset.declaredWebService && (
                    <InlineNotice tone="info" title={text(pageCopy.declaredServiceTitle)}>
                      <p>{text(pageCopy.declaredServiceBody, {
                        protocol: selectedExternalAsset.declaredWebService.protocol.toUpperCase(),
                        port: formatNumber(selectedExternalAsset.declaredWebService.port),
                        path: selectedExternalAsset.declaredWebService.path,
                      })}</p>
                    </InlineNotice>
                  )}
                  <label className="field">
                    <span>{text(pageCopy.canonicalTarget)}</span>
                    <select value={externalTarget} onChange={(event) => setExternalTarget(event.target.value)}>
                      {externalTargetOptions.map((target) => <option key={target} value={target}>{target}</option>)}
                    </select>
                    <small>{text(pageCopy.canonicalTargetHelp)}</small>
                  </label>
                  <div className="form-grid form-grid--two">
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
                  <InlineNotice tone="info" title={text(pageCopy.sensitiveTechnicalTitle)}>
                    <p>{text(pageCopy.sensitiveTechnicalBody)}</p>
                  </InlineNotice>
                </details>

                {isDirectExternal && selectedExternalAsset.internetExposed === false && !guidedLowImpactNetwork && (
                  <label className="toggle-row toggle-row--danger">
                    <input type="checkbox" checked={allowSensitiveNetworks} onChange={(event) => setAllowSensitiveNetworks(event.target.checked)} />
                    <span><strong>{text(pageCopy.sensitiveTitle)}</strong><small>{text(pageCopy.sensitiveBody)}</small></span>
                  </label>
                )}
              </section>
            )}

            <div className="scope-confirmation-panel__assets">
              {selectedScopeAssets.map((asset) => <span key={asset.id}><b>{asset.name}</b><small>{platformMeta[asset.platform].label} · {text(assetTypeLabels[asset.type])}</small></span>)}
            </div>

            {!simpleGuidedConsent && (
              <>
                <label className="toggle-row">
                  <input type="checkbox" checked={ownershipConfirmed} onChange={(event) => setOwnershipConfirmed(event.target.checked)} />
                  <span><strong>{text(selectedExternalAsset
                    ? selectedExternalAsset.internetExposed === false
                      ? pageCopy.internalOwnershipTitle
                      : pageCopy.externalOwnershipTitle
                    : pageCopy.ownershipTitle)}</strong><small>{text(pageCopy.ownershipBody)}</small></span>
                </label>

                <label className="field">
                  <span>{text(requiresAuthorizationReference ? pageCopy.authorityRequired : pageCopy.scopeNote)}</span>
                  <input value={scopeConfirmation} onChange={(event) => setScopeConfirmation(event.target.value)} placeholder={text(requiresAuthorizationReference ? pageCopy.authorityPlaceholder : pageCopy.notePlaceholder)} />
                  <small>{text(requiresAuthorizationReference ? pageCopy.authorityHelp : pageCopy.noteHelp)}</small>
                  {externalActivity === "active_external" && scopeConfirmation.trim().length > 0 && scopeConfirmation.trim().length < 8 && <small className="field-error">{text(pageCopy.activeAuthorityLength)}</small>}
                </label>
              </>
            )}

            <div className="form-actions">
              <p><Icon name="lock" size={16} /> {text(pageCopy.grantBoundaryHelp)}</p>
              <button className="button button--primary" type="submit" disabled={busy || availableScopeModes.length === 0 || scopeModes.length === 0 || (!simpleGuidedConsent && !ownershipConfirmed) || (requiresAuthorizationReference && !scopeConfirmation.trim()) || !externalScopeReady}>
                <Icon name="lock" size={16} />{busy
                  ? text(pageCopy.savingGrant)
                  : text(guidedCloudConsent
                    ? pageCopy.useSignedInCloud
                    : simpleGuidedConsent
                      ? pageCopy.confirmAndSave
                      : pageCopy.saveGrant)}
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
              const incompatibleWithSelection = anotherAssetSelected
                && (asset.platform === "external" || selectedIncludesExternal || guidedCloudRoute);
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
                  <details className="external-grant-card__technical">
                    <summary>{text(pageCopy.grantTechnical)}</summary>
                    <dl>
                      <div><dt>{text(pageCopy.targetTerm)}</dt><dd><code>{scope.targetKind}:{scope.target}</code></dd></div>
                      <div><dt>{text(pageCopy.protocolPortsTerm)}</dt><dd>{scope.protocol.toUpperCase()} · {scope.ports.length ? scope.ports.join(", ") : text(pageCopy.noDirectPort)}</dd></div>
                      <div><dt>{text(pageCopy.rateTerm)}</dt><dd>{formatNumber(scope.ratePolicy.requestsPerSecond)} req/s · {formatNumber(scope.ratePolicy.concurrency)} concurrent · {formatNumber(scope.ratePolicy.timeoutSeconds)}s</dd></div>
                      <div><dt>{text(pageCopy.templatesTerm)}</dt><dd><code>{scope.templatePolicy.revision}</code> · {formatNumber(scope.templatePolicy.allowedTemplateIds.length)} IDs</dd></div>
                      <div><dt>{text(pageCopy.authorityTerm)}</dt><dd>{scope.assertedAuthority}</dd></div>
                      <div><dt>{text(pageCopy.approvalTerm)}</dt><dd>{scope.approvedBy} · {formatDateTime(scope.approvedAt)}</dd></div>
                    </dl>
                    <p><Icon name="lock" size={13} /> {text(pageCopy.prohibitedAll)}</p>
                  </details>
                </article>
              );
            })}
          </div>
        </section>
      )}

      <details className="coverage-situation-details">
        <summary>{text(pageCopy.finalNoticeTitle)}</summary>
        <p>{text(pageCopy.finalNoticeBody)}</p>
      </details>
    </div>
  );
}
