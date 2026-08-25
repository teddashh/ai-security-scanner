import type { IconName } from "./components/Icon";
import type { Provider } from "./providerAuthorizationPolicy";
import type { AssessmentActivity, CloudPlatform, KnownAssetKind } from "./types";

export type UseCaseId =
  | "deployed_website"
  | "external_ip_or_domain"
  | "internal_it_environment"
  | "source_code"
  | "infrastructure_as_code"
  | "cloud_account"
  | "container_image"
  | "kubernetes";

export type UseCaseInputKind =
  | "url"
  | "ip_or_domain"
  | "internal_ip_or_snapshot"
  | "repository_or_folder"
  | "iac_project"
  | "provider_account"
  | "container_image"
  | "manifest_or_node_snapshot";

export interface UseCaseDefinition {
  id: UseCaseId;
  icon: IconName;
  inputKind: UseCaseInputKind;
  suggestedActivities: readonly AssessmentActivity[];
  suggestedPlatforms: readonly CloudPlatform[];
  knownAssetKind?: KnownAssetKind;
  internetExposure: "public" | "internal" | "not_applicable";
  supportedProviders?: readonly Provider[];
}

export interface UseCaseCardCopy {
  title: string;
  summary: string;
  want: string;
  prepare: string;
  productDoes: string;
  productDoesNot: string;
}

export interface StartPageCopy {
  eyebrow: string;
  title: string;
  description: string;
  choiceTitle: string;
  choiceDescription: string;
  wantLabel: string;
  prepareLabel: string;
  productDoesLabel: string;
  productDoesNotLabel: string;
  chooseAction: string;
  existingCaseAction: string;
  scopeNoticeTitle: string;
  scopeNotice: string;
  cards: Record<UseCaseId, UseCaseCardCopy>;
}

export const useCaseDefinitions = [
  {
    id: "deployed_website",
    icon: "external",
    inputKind: "url",
    suggestedActivities: ["low_impact_external_checks"],
    suggestedPlatforms: ["external"],
    knownAssetKind: "external_target",
    internetExposure: "public",
  },
  {
    id: "external_ip_or_domain",
    icon: "coverage",
    inputKind: "ip_or_domain",
    suggestedActivities: ["low_impact_external_checks"],
    suggestedPlatforms: ["external"],
    knownAssetKind: "external_target",
    internetExposure: "public",
  },
  {
    id: "internal_it_environment",
    icon: "database",
    inputKind: "internal_ip_or_snapshot",
    suggestedActivities: ["low_impact_external_checks"],
    suggestedPlatforms: ["external"],
    knownAssetKind: "external_target",
    internetExposure: "internal",
  },
  {
    id: "source_code",
    icon: "file",
    inputKind: "repository_or_folder",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["code"],
    knownAssetKind: "repository",
    internetExposure: "not_applicable",
  },
  {
    id: "infrastructure_as_code",
    icon: "settings",
    inputKind: "iac_project",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["code"],
    knownAssetKind: "iac_project",
    internetExposure: "not_applicable",
  },
  {
    id: "cloud_account",
    icon: "spark",
    inputKind: "provider_account",
    suggestedActivities: ["configuration_assessment"],
    suggestedPlatforms: ["aws", "azure", "gcp", "m365"],
    internetExposure: "not_applicable",
    supportedProviders: ["aws", "azure", "gcp", "microsoft365"],
  },
  {
    id: "container_image",
    icon: "archive",
    inputKind: "container_image",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["container"],
    knownAssetKind: "container_image",
    internetExposure: "not_applicable",
  },
  {
    id: "kubernetes",
    icon: "shield",
    inputKind: "manifest_or_node_snapshot",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["kubernetes"],
    knownAssetKind: "kubernetes_cluster",
    internetExposure: "not_applicable",
  },
] as const satisfies readonly UseCaseDefinition[];

export const startPageCopy: Record<"en" | "zh-TW", StartPageCopy> = {
  en: {
    eyebrow: "Start with your goal",
    title: "What would you like to check?",
    description:
      "Choose the situation closest to yours. You do not need to know scanner names or security jargon; we will ask only for the target and permission details that this check needs.",
    choiceTitle: "Choose one place to start",
    choiceDescription:
      "You can add other types of checks to the same case later. This choice only makes the next setup screen shorter.",
    wantLabel: "What you want to check",
    prepareLabel: "What to prepare",
    productDoesLabel: "What the product does",
    productDoesNotLabel: "What it does not do",
    chooseAction: "Set up this check",
    existingCaseAction: "Open an existing case",
    scopeNoticeTitle: "Choosing a card does not authorize a scan",
    scopeNotice:
      "The product will still ask you to confirm the exact targets, ownership, allowed scan type, and limits before anything contacts a system. Unconfirmed areas remain unknown—not safe or passed.",
    cards: {
      deployed_website: {
        title: "A website or API that is already online",
        summary: "Check an Internet-facing site you operate or have written permission to test.",
        want:
          "An exact website or API URL, including the hostname and the service you want reviewed.",
        prepare:
          "The URL, proof that you may test it, and a choice between low-impact checks and separately approved active tests.",
        productDoes:
          "Confirms reachable web services and runs only the network and vulnerability checks you approve, with target and rate limits.",
        productDoesNot:
          "It does not try to bypass your application's sign-in or business workflows, follow redirects outside the approved target, or replace a human penetration test.",
      },
      external_ip_or_domain: {
        title: "External IP addresses or domains",
        summary: "See what your organization exposes to the public Internet.",
        want:
          "Specific public IP addresses, domains, or hostnames that belong to your organization.",
        prepare:
          "An exact target list, ownership or authorization evidence, exclusions, and the allowed scan intensity.",
        productDoes:
          "Checks approved targets for reachable ports and services, then runs only the external checks allowed by the case.",
        productDoesNot:
          "It does not expand the target list on its own, contact neighboring addresses, or treat an unreachable target as secure.",
      },
      internal_it_environment: {
        title: "An internal IT environment",
        summary: "Review approved servers and devices that are reachable only inside your network.",
        want:
          "Specific internal servers, workstations, or network devices—not an undefined entire company network.",
        prepare:
          "A computer that can reach the approved targets, an exact IP list or configuration snapshots, scan limits, and IT-owner approval.",
        productDoes:
          "Uses the same exact-target and rate-limit controls for authorized internal checks, and can analyze attached configuration evidence locally.",
        productDoesNot:
          "It does not discover and scan every private address automatically, install agents, change devices, or bypass network access controls.",
      },
      source_code: {
        title: "Source code you have written",
        summary: "Look for risky code patterns and accidentally committed secrets without uploading the project.",
        want:
          "A local project folder or read-only copy of a repository that you are allowed to assess.",
        prepare:
          "The exact folder or repository snapshot and a quick check that unrelated secrets or personal files are excluded.",
        productDoes:
          "Mounts only the selected copy as read-only, checks code and secret patterns locally, and keeps sensitive evidence in the case.",
        productDoesNot:
          "It does not push changes, verify discovered secrets against live services, inspect unselected folders, or prove that the code is bug-free.",
      },
      infrastructure_as_code: {
        title: "Infrastructure as code",
        summary: "Review Terraform, CloudFormation, Kubernetes YAML, and other deployment definitions before rollout.",
        want:
          "The files that describe how cloud or infrastructure resources should be created.",
        prepare:
          "A local read-only project snapshot, including the modules and variable files needed to understand it.",
        productDoes:
          "Checks the selected files locally for risky defaults and configuration mistakes and preserves the exact input snapshot used.",
        productDoesNot:
          "It does not deploy a plan, contact your cloud account, rewrite files, or assume that a clean template matches the live environment.",
      },
      cloud_account: {
        title: "An AWS, Azure, GCP, or Microsoft 365 account",
        summary: "Review inventory, identity, and security settings with a short-lived read-only connection.",
        want:
          "One exact AWS account, Azure subscription, GCP project, or Microsoft 365 tenant at a time.",
        prepare:
          "The account or tenant identifier, permission to assess it, and access to the provider's official sign-in page. Do not paste an admin password into the app.",
        productDoes:
          "Opens the provider's sign-in flow, checks that the granted capability is read-only and bound to the chosen account, and runs the applicable checks.",
        productDoesNot:
          "It does not accept a client secret in the case UI, keep an administrator credential, change cloud settings, or silently include another account.",
      },
      container_image: {
        title: "A container image",
        summary: "Find known vulnerable packages and create a software inventory from one exact image.",
        want:
          "The exact image artifact or OCI layout that you build or are authorized to inspect.",
        prepare:
          "A local exported copy of the image with its unique digest. If the image is private, export it before attaching it to the case.",
        productDoes:
          "Analyzes the attached image read-only with pinned offline vulnerability data, records recognized packages, and produces a software inventory (SBOM).",
        productDoesNot:
          "It does not run the image, sign in to an image registry, scan an ambiguous version such as latest, or claim coverage for content it could not recognize.",
      },
      kubernetes: {
        title: "Kubernetes configuration",
        summary: "Review workload manifests and a bounded node-configuration snapshot without giving away cluster admin access.",
        want:
          "Kubernetes YAML or an approved, immutable snapshot of the node configuration you want checked.",
        prepare:
          "The selected manifests or snapshot, cluster-owner permission, and confirmation that unrelated secrets have been removed.",
        productDoes:
          "Checks the selected YAML settings against pinned security rules and checks an attached node snapshot against a bounded CIS baseline.",
        productDoesNot:
          "It does not request administrator access to the cluster, mount a live server, change workloads, or continuously monitor the running cluster.",
      },
    },
  },
  "zh-TW": {
    eyebrow: "從你想解決的問題開始",
    title: "你想檢查什麼？",
    description:
      "選一個最接近你的情況就好。你不需要先懂掃描器名稱或資安術語；接下來只會問這種檢查真正需要的目標與授權資訊。",
    choiceTitle: "先選一個地方開始",
    choiceDescription: "之後仍可在同一案件加入其他檢查；這個選擇只會讓下一個設定畫面更短。",
    wantLabel: "你想檢查什麼",
    prepareLabel: "需要準備什麼",
    productDoesLabel: "產品會做什麼",
    productDoesNotLabel: "不會做什麼",
    chooseAction: "設定這項檢查",
    existingCaseAction: "開啟既有案件",
    scopeNoticeTitle: "選卡片不等於授權掃描",
    scopeNotice:
      "在真的接觸任何系統前，產品仍會請你確認精確目標、所有權、允許的掃描類型與限制。沒有確認的範圍會維持「未知」，不會被說成安全或通過。",
    cards: {
      deployed_website: {
        title: "已經架好的網站或 API",
        summary: "檢查你負責營運，或已取得書面測試許可的公開服務。",
        want: "一個精確的網站或 API 網址，包含要檢查的主機名稱與服務。",
        prepare: "網址、你可以測試它的證明，以及要做低影響檢查，或另行核准的主動測試。",
        productDoes: "先確認可連線的網站服務，再依你的授權執行網路與弱點檢查，並限制目標與速度。",
        productDoesNot: "不測商業邏輯、不冒充使用者登入、不跟著重新導向跑出核准範圍，也不能取代人工滲透測試。",
      },
      external_ip_or_domain: {
        title: "外部 IP 或網域",
        summary: "看看你的組織在公開網路上曝露了哪些入口。",
        want: "明確屬於你組織的公開 IP、網域或主機名稱。",
        prepare: "精確目標清單、所有權或授權證明、排除項目，以及允許的掃描強度。",
        productDoes: "只檢查核准目標可連線的連接埠與服務，再依案件授權執行外部檢查。",
        productDoesNot: "不自行擴大目標、不掃相鄰 IP，也不會把無法連線說成安全。",
      },
      internal_it_environment: {
        title: "公司內部 IT 環境",
        summary: "檢查只有內網才能連到，而且已逐項核准的伺服器與設備。",
        want: "明確的內部伺服器、工作站或網路設備，不是一句模糊的「整間公司」。",
        prepare: "一台能連到核准目標的電腦、精確 IP 清單或設定快照、掃描限制，以及 IT 負責人的同意。",
        productDoes: "用相同的精確目標與限速保護執行內部檢查，也能在本機分析你附上的設定證據。",
        productDoesNot: "不自動掃完整個私有網段、不安裝代理程式、不修改設備，也不繞過現有網路存取控制。",
      },
      source_code: {
        title: "寫好的程式碼",
        summary: "找出高風險寫法與不小心提交的秘密，而且不把專案上傳。",
        want: "你有權檢查的本機專案資料夾或唯讀程式碼儲存庫副本。",
        prepare: "精確的資料夾或程式碼快照，並先排除無關的秘密與個人檔案。",
        productDoes: "只把選定副本以唯讀方式交給本機引擎，檢查程式碼與秘密模式，敏感證據留在案件裡。",
        productDoesNot: "不推送修改、不拿找到的秘密去登入線上服務、不讀未選取資料夾，也不保證程式完全沒有錯誤。",
      },
      infrastructure_as_code: {
        title: "基礎設施程式碼（IaC）",
        summary: "在部署前檢查 Terraform、CloudFormation、Kubernetes YAML 等定義。",
        want: "描述雲端或基礎設施應如何建立的檔案。",
        prepare: "本機唯讀專案快照，包含理解設定所需的模組與變數檔。",
        productDoes: "在本機檢查選定檔案裡的危險預設值與設定錯誤，並保留這次使用的精確輸入快照。",
        productDoesNot: "不執行部署、不連你的雲端帳號、不改寫檔案，也不假設乾淨的範本等於線上環境沒問題。",
      },
      cloud_account: {
        title: "AWS、Azure、GCP 或 Microsoft 365 帳號",
        summary: "透過短效唯讀連線，檢查資產、身分與安全設定。",
        want: "一次只檢查一個精確的 AWS 帳號、Azure 訂閱、GCP 專案或 Microsoft 365 租用戶。",
        prepare: "帳號或租用戶識別碼、檢查許可，以及能開啟雲端服務商官方登入頁面的權限；不要把管理員密碼貼進產品。",
        productDoes: "開啟雲端服務商的官方登入流程，確認取得的是綁定所選帳號的唯讀能力，再執行適用檢查。",
        productDoesNot: "案件畫面不收用戶端密鑰、不保存管理員權限、不修改雲端設定，也不會偷偷加入其他帳號。",
      },
      container_image: {
        title: "容器映像",
        summary: "從一個精確映像找出已知弱點套件，並建立軟體清單。",
        want: "你建立或有權檢查的一份精確本機映像匯出檔。",
        prepare: "帶有唯一內容摘要的本機映像副本；若映像位於私人倉庫，請先匯出再附加到案件。",
        productDoes: "用固定的離線弱點資料唯讀分析映像，記錄辨識到的套件，並產生軟體內容清單（SBOM）。",
        productDoesNot: "不執行映像、不登入映像倉庫、不掃名為 latest 的不確定標籤，也不替無法辨識的內容宣稱已有涵蓋。",
      },
      kubernetes: {
        title: "Kubernetes 設定",
        summary: "不用交出叢集管理員權限，就能檢查工作負載設定檔與有限範圍的節點設定快照。",
        want: "要檢查的 Kubernetes YAML 設定檔，或經核准且不可變更的節點設定快照。",
        prepare: "選定的設定檔或快照、叢集負責人的許可，並確認已移除無關秘密。",
        productDoes: "以固定的安全規則檢查 YAML 設定，並用有限範圍的 CIS 安全基準檢查附加的節點快照。",
        productDoesNot: "不要求叢集管理員權限、不掛載線上主機、不修改工作負載，也不持續監控執行中的叢集。",
      },
    },
  },
};

export const useCaseById = (id: UseCaseId): UseCaseDefinition => {
  const definition = useCaseDefinitions.find((candidate) => candidate.id === id);
  if (!definition) throw new Error(`Unknown use case: ${id}`);
  return definition;
};
