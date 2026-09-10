import type { BilingualText } from "./i18n";
import type { AttachWorkspaceSnapshotInput } from "./types";
import type { UseCaseId } from "./useCases";

export type LocalInputProfile = AttachWorkspaceSnapshotInput["inputProfile"];

const bilingual = (en: string, zhTW: string): BilingualText => ({ en, zhTW });

export interface LocalInputDefinition {
  label: BilingualText;
  detail: BilingualText;
  formTitle: BilingualText;
  formIntro: BilingualText;
  cautionTitle: BilingualText;
  cautionBody: BilingualText;
  directoryLabel: BilingualText;
  selection: BilingualText;
  attachAction: BilingualText;
  createAction: BilingualText;
  technical: BilingualText;
}

export const localProfileByAssessmentIntent: Partial<Record<UseCaseId, LocalInputProfile>> = {
  ai_application: "repository_working_tree",
  source_code: "repository_working_tree",
  infrastructure_as_code: "iac_working_tree",
  container_image: "container_image_oci_layout",
  kubernetes: "kubernetes_manifests",
};

export const localInputDefinitions: Record<LocalInputProfile, LocalInputDefinition> = {
  repository_working_tree: {
    label: bilingual("Source-code project", "程式碼專案"),
    detail: bilingual("Check one local source-code project.", "檢查一個本機程式碼專案。"),
    formTitle: bilingual("Choose the source code you want checked", "選擇想檢查的程式碼"),
    formIntro: bilingual("Pick one project folder to check for risky code, exposed secrets, software components, and vulnerable packages.", "選擇一個專案資料夾，檢查危險程式碼、暴露的秘密、軟體元件與有弱點的套件。"),
    cautionTitle: bilingual("Scan a private local copy", "掃描私密的本機副本"),
    cautionBody: bilingual("Only the selected folder is copied into the private local scan. Detected secret values are masked in results.", "只會把選定資料夾複製到私密的本機掃描；找到的秘密值會在結果中遮罩。"),
    directoryLabel: bilingual("Source-code folder", "程式碼資料夾"),
    selection: bilingual("Choose the source-code folder", "選擇程式碼資料夾"),
    attachAction: bilingual("Add this source-code project", "加入這份程式碼專案"),
    createAction: bilingual("Create scan with this code", "用這份程式碼建立掃描"),
    technical: bilingual("Input profile: repository_working_tree. Every .git directory, including refs and hooks, is excluded from the saved copy.", "輸入格式：repository_working_tree。保存副本時會排除所有 .git 目錄，包括 refs 與 hooks。"),
  },
  iac_working_tree: {
    label: bilingual("Infrastructure-code project", "基礎設施程式碼專案"),
    detail: bilingual("Check the Terraform, JSON, and YAML files in one project folder.", "檢查一個專案資料夾內的 Terraform、JSON 與 YAML 檔案。"),
    formTitle: bilingual("Choose the infrastructure code you want checked", "選擇想檢查的基礎設施程式碼"),
    formIntro: bilingual("Pick the folder that contains your Terraform, CloudFormation, JSON, or YAML deployment files. The scan finds risky settings before they go live.", "選擇包含 Terraform、CloudFormation、JSON 或 YAML 部署檔案的資料夾；掃描會在上線前找出危險設定。"),
    cautionTitle: bilingual("Deployment files must not contain secret values", "部署檔案不得包含秘密值"),
    cautionBody: bilingual("Input requirement: no embedded passwords, keys, or tokens. The selected files are copied for local checks.", "輸入規格：不得包含嵌入的密碼、金鑰或 token。所選檔案會複製到本機進行檢查。"),
    directoryLabel: bilingual("Infrastructure-code folder", "基礎設施程式碼資料夾"),
    selection: bilingual("Choose the infrastructure-code folder", "選擇基礎設施程式碼資料夾"),
    attachAction: bilingual("Add this infrastructure code", "加入這份基礎設施程式碼"),
    createAction: bilingual("Create scan with this infrastructure code", "用這份基礎設施程式碼建立掃描"),
    technical: bilingual("Input profile: iac_working_tree. The saved copy accepts Terraform, JSON, and YAML deployment files.", "輸入格式：iac_working_tree。保存副本接受 Terraform、JSON 與 YAML 部署檔案。"),
  },
  container_image_oci_layout: {
    label: bilingual("Exported container image", "匯出的容器映像"),
    detail: bilingual("Check one exported container image on this computer without signing in to a registry.", "在這台電腦上檢查一份匯出的容器映像，不必登入映像倉庫。"),
    formTitle: bilingual("Choose the container image you want checked", "選擇想檢查的容器映像"),
    formIntro: bilingual("Pick one exported OCI image folder. Syft inventories its software components, while Trivy and Grype check them for known vulnerabilities. Everything runs locally without starting the image.", "選擇一個匯出的 OCI 映像資料夾；Syft 會盤點其中的軟體元件，Trivy 與 Grype 會檢查已知弱點。所有工作都在本機完成，不會執行映像。"),
    cautionTitle: bilingual("Input: exported container image", "輸入：匯出的容器映像"),
    cautionBody: bilingual("The app reads this exported copy without starting the image or signing in to a container registry.", "產品只讀取這份匯出副本，不會啟動映像或登入容器映像倉庫。"),
    directoryLabel: bilingual("Exported image folder", "匯出映像資料夾"),
    selection: bilingual("Choose the exported container-image folder", "選擇匯出的容器映像資料夾"),
    attachAction: bilingual("Add this container image", "加入這份容器映像"),
    createAction: bilingual("Create scan with this container image", "用這份容器映像建立掃描"),
    technical: bilingual("Input profile: container_image_oci_layout. Choose one digest-bound OCI Image Layout containing oci-layout, index.json, and blobs/.", "輸入格式：container_image_oci_layout。請選擇一份綁定精確內容指紋、且包含 oci-layout、index.json 與 blobs/ 的 OCI Image Layout。"),
  },
  kubernetes_manifests: {
    label: bilingual("Kubernetes configuration", "Kubernetes 設定"),
    detail: bilingual("Check exported Kubernetes settings on this computer without connecting to the live cluster.", "在這台電腦上檢查匯出的 Kubernetes 設定，不會連線到正在運作的叢集。"),
    formTitle: bilingual("Choose the Kubernetes settings you want checked", "選擇想檢查的 Kubernetes 設定"),
    formIntro: bilingual("Pick a folder of exported YAML or JSON settings. The scan finds risky workload and cluster settings from the saved files.", "選擇包含匯出 YAML 或 JSON 設定的資料夾；掃描會從已保存的檔案找出危險的工作負載與叢集設定。"),
    cautionTitle: bilingual("Input: exported settings without live-cluster credentials", "輸入：不含正式叢集憑證的匯出設定"),
    cautionBody: bilingual("Input requirement: no kubeconfig files, tokens, or certificates. Checks use the saved settings only.", "輸入規格：不得包含 kubeconfig、token 或憑證。檢查只使用已保存的設定。"),
    directoryLabel: bilingual("Kubernetes settings folder", "Kubernetes 設定資料夾"),
    selection: bilingual("Choose the Kubernetes configuration folder", "選擇 Kubernetes 設定資料夾"),
    attachAction: bilingual("Add these Kubernetes settings", "加入這些 Kubernetes 設定"),
    createAction: bilingual("Create scan with these Kubernetes settings", "用這些 Kubernetes 設定建立掃描"),
    technical: bilingual("Input profile: kubernetes_manifests. The folder may contain Kubernetes YAML and JSON manifest files.", "輸入格式：kubernetes_manifests。資料夾可包含 Kubernetes YAML 與 JSON manifest 檔。"),
  },
  kubernetes_node_snapshot: {
    label: bilingual("Exported Kubernetes node settings", "匯出的 Kubernetes 節點設定"),
    detail: bilingual("Check an exported copy of one node's security settings on this computer.", "在這台電腦上檢查一份節點安全設定的匯出副本。"),
    formTitle: bilingual("Choose the Kubernetes node settings you want checked", "選擇想檢查的 Kubernetes 節點設定"),
    formIntro: bilingual("Pick one exported node-settings folder. The scan checks its saved security settings.", "選擇一個匯出的節點設定資料夾；掃描會檢查其中已保存的安全設定。"),
    cautionTitle: bilingual("Input: exported node snapshot", "輸入：匯出的節點快照"),
    cautionBody: bilingual("Input requirement: no live-cluster credentials or unrelated host files. Checks use the saved snapshot only.", "輸入規格：不得包含正式叢集憑證或無關的主機檔案。檢查只使用已保存的快照。"),
    directoryLabel: bilingual("Exported node-settings folder", "匯出節點設定資料夾"),
    selection: bilingual("Choose the exported node-settings folder", "選擇匯出的節點設定資料夾"),
    attachAction: bilingual("Add these node settings", "加入這些節點設定"),
    createAction: bilingual("Create scan with these node settings", "用這些節點設定建立掃描"),
    technical: bilingual("Input profile: kubernetes_node_snapshot. Choose the parent of node-snapshot/; the bounded CIS snapshot is read without mounting the host filesystem.", "輸入格式：kubernetes_node_snapshot。請選擇 node-snapshot/ 的父目錄；產品不掛載 host filesystem，只讀取有限範圍的 CIS 快照。"),
  },
};

const aiApplicationInputDefinition: LocalInputDefinition = {
  ...localInputDefinitions.repository_working_tree,
  label: bilingual("Code you wrote or generated with AI", "自己寫或 AI 生成的程式碼"),
  formTitle: bilingual("Choose code you wrote or generated with AI", "選擇自己寫或 AI 生成的程式碼"),
  formIntro: bilingual("Pick the AI app or agent project folder to check for risky code, exposed secrets, vulnerable packages, and related deployment settings.", "選擇 AI 應用或 Agent 的專案資料夾，檢查危險程式碼、暴露的秘密、有弱點的套件與相關部署設定。"),
  attachAction: bilingual("Add this AI project", "加入這份 AI 專案"),
  createAction: bilingual("Create scan with this AI project", "用這份 AI 專案建立掃描"),
};

export const localInputDefinitionForAssessmentIntent = (
  profile: LocalInputProfile,
  assessmentIntent: UseCaseId | undefined,
): LocalInputDefinition => assessmentIntent === "ai_application" && profile === "repository_working_tree"
  ? aiApplicationInputDefinition
  : localInputDefinitions[profile];

export const localInputEngines: Record<LocalInputProfile, string> = {
  repository_working_tree: "Gitleaks, Semgrep, Syft, Trivy, Grype, TruffleHog, KICS, Checkov",
  iac_working_tree: "Checkov, KICS, Trivy",
  container_image_oci_layout: "Syft, Trivy, Grype",
  kubernetes_manifests: "Kubescape",
  kubernetes_node_snapshot: "kube-bench",
};

/** Exact upstream engine set used when a mixed scan routes work per local asset. */
export const localInputEngineIds: Record<LocalInputProfile, readonly string[]> = {
  repository_working_tree: ["gitleaks", "semgrep", "syft", "trivy", "grype", "trufflehog", "kics", "checkov"],
  iac_working_tree: ["checkov", "kics", "trivy"],
  container_image_oci_layout: ["syft", "trivy", "grype"],
  kubernetes_manifests: ["kubescape"],
  kubernetes_node_snapshot: ["kube-bench"],
};

export const localPathDisplayName = (path: string, fallback: string): string =>
  path.split(/[\\/]/).filter(Boolean).at(-1) ?? fallback;

/**
 * Produces short, privacy-conscious labels for a set of local folders.
 *
 * A basename is normally enough. When two selected repositories share it, we
 * add only the immediate parent folder. If that still collides, stable numbers
 * distinguish the remaining labels without exposing more of either path.
 */
export const localPathDisplayLabels = (paths: readonly string[], fallback: string): string[] => {
  const entries = paths.map((path, index) => {
    const segments = path.split(/[\\/]/).filter(Boolean);
    const basename = segments.at(-1) ?? fallback;
    const parent = segments.at(-2);
    return {
      index,
      path,
      basename,
      basenameKey: basename.toLocaleLowerCase(),
      parentLabel: parent ? `${parent}/${basename}` : basename,
    };
  });

  const basenameCounts = new Map<string, number>();
  for (const entry of entries) {
    basenameCounts.set(entry.basenameKey, (basenameCounts.get(entry.basenameKey) ?? 0) + 1);
  }

  const candidates = entries.map((entry) => ({
    ...entry,
    candidate: (basenameCounts.get(entry.basenameKey) ?? 0) > 1
      ? entry.parentLabel
      : entry.basename,
  }));
  const candidateGroups = new Map<string, typeof candidates>();
  for (const entry of candidates) {
    const key = entry.candidate.toLocaleLowerCase();
    candidateGroups.set(key, [...(candidateGroups.get(key) ?? []), entry]);
  }

  const labels = new Array<string>(paths.length);
  for (const group of candidateGroups.values()) {
    if (group.length === 1) {
      labels[group[0]!.index] = group[0]!.candidate;
      continue;
    }
    const stableOrder = [...group].sort((left, right) => {
      const byPath = left.path.replaceAll("\\", "/").localeCompare(
        right.path.replaceAll("\\", "/"),
        undefined,
        { sensitivity: "base" },
      );
      return byPath || left.index - right.index;
    });
    stableOrder.forEach((entry, index) => {
      labels[entry.index] = `${entry.candidate} (${index + 1})`;
    });
  }
  return labels;
};
