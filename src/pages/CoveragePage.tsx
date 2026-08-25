import { useEffect, useMemo, useState, type FormEvent } from "react";

import { coverageMeta, formatDateTime, platformMeta } from "../lib";
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
import { isScopeEligible, permittedModes, suggestedModesForAsset } from "../scopePolicy";

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
  label: string;
  platform: keyof typeof platformMeta;
  profiles: readonly SnapshotParserProfile[];
  description: string;
}

const sourceDefinitions = {
  aws_organization: {
    label: "AWS Organization",
    platform: "aws",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: "AWS 帳號、區域與資源的既有匯出結果。",
  },
  azure_tenant: {
    label: "Azure Tenant",
    platform: "azure",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: "Azure tenant、subscription 與資源的既有匯出結果。",
  },
  gcp_organization: {
    label: "Google Cloud Organization",
    platform: "gcp",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: "GCP organization、folder、project 與資源的既有匯出結果。",
  },
  microsoft365_tenant: {
    label: "Microsoft 365 Tenant",
    platform: "m365",
    profiles: ["scubagear", "maester"],
    description: "ScubaGear 或 Maester 已保存的 tenant 結果。",
  },
  dns: {
    label: "DNS records",
    platform: "external",
    profiles: ["dns-response"],
    description: "明確查詢範圍內已保存的 DNS 回應。",
  },
  certificate_transparency: {
    label: "Certificate Transparency",
    platform: "external",
    profiles: ["certificate-transparency-response"],
    description: "已保存的公開憑證透明度查詢回應。",
  },
  billing: {
    label: "Billing export",
    platform: "external",
    profiles: ["billing-export"],
    description: "可用來建立候選資產的帳務匯出快照。",
  },
  git_repository: {
    label: "Git repositories",
    platform: "code",
    profiles: ["git-manifest"],
    description: "使用者選取 repositories 的受限 JSON manifest。",
  },
  terraform_state: {
    label: "Terraform state",
    platform: "code",
    profiles: ["terraform-state"],
    description: "Terraform state 的 JSON 快照；請先移除秘密值。",
  },
  kubernetes_cluster: {
    label: "Kubernetes clusters",
    platform: "kubernetes",
    profiles: ["kubernetes-manifest"],
    description: "已保存的 cluster 與工作負載 JSON manifest。",
  },
  container_registry: {
    label: "Container registries",
    platform: "container",
    profiles: ["container-registry-manifest"],
    description: "Registry、repository、image 與 digest 的受限 manifest。",
  },
  file_system: {
    label: "Local filesystems",
    platform: "code",
    profiles: ["filesystem-manifest"],
    description: "使用者明確選取內容的檔案系統 manifest。",
  },
  user_declared: {
    label: "User-declared assets",
    platform: "external",
    profiles: ["user-declared-manifest"],
    description: "由使用者列出的候選資產；不會自動證明所有權。",
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

const scopeModeLabels: Record<ScopeMode, { label: string; detail: string }> = {
  inventory: { label: "唯讀盤點", detail: "只讀取資產清單與識別資訊" },
  configuration: { label: "設定／本機 artifact", detail: "唯讀檢查設定或已附加快照" },
  local_artifact: { label: "本機 artifact 唯讀", detail: "只讀取案件內不可變的本機快照" },
  public_data: { label: "公開資料盤點", detail: "只使用 DNS、CT 等既有公開資料" },
  low_impact_external: { label: "低影響連線", detail: "對已確認目標發出受限連線" },
  active_external: { label: "主動外部測試", detail: "需可追溯的明確授權參考" },
  passive: { label: "公開資料盤點", detail: "相容舊案件的被動模式" },
  active: { label: "主動外部測試", detail: "相容舊案件的主動模式" },
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

const activityLabels: Record<ExternalActivity, string> = {
  passive_public_discovery: "公開資料盤點",
  low_impact_external: "低影響外部連線",
  active_external: "主動外部測試",
};

const NUCLEI_TEMPLATE_REVISION = "nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012";

const parsePorts = (value: string): number[] | undefined => {
  if (!value.trim()) return [];
  const parts = value.split(/[\s,]+/).filter(Boolean).map(Number);
  if (parts.some((port) => !Number.isInteger(port) || port < 1 || port > 65_535)) return undefined;
  return [...new Set(parts)].sort((a, b) => a - b);
};

const parseTemplateIds = (value: string): string[] =>
  [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];

const fileNameFromPath = (path: string): string =>
  path.split(/[\\/]/).filter(Boolean).at(-1) ?? "已選取 JSON 快照";

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
  const [filter, setFilter] = useState<CoverageState | "all">("all");
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [showSourceForm, setShowSourceForm] = useState(false);
  const [showWorkspaceForm, setShowWorkspaceForm] = useState(false);
  const [sourceKind, setSourceKind] = useState<SourceKind>("aws_organization");
  const [profile, setProfile] = useState<SnapshotParserProfile>("cloudquery");
  const [sourceLabel, setSourceLabel] = useState<string>(sourceDefinitions.aws_organization.label);
  const [selectedPath, setSelectedPath] = useState("");
  const [choosingSnapshot, setChoosingSnapshot] = useState(false);
  const [sourceFormError, setSourceFormError] = useState<string>();
  const [workspaceLabel, setWorkspaceLabel] = useState("Local working tree");
  const [selectedWorkspacePath, setSelectedWorkspacePath] = useState("");
  const [choosingWorkspace, setChoosingWorkspace] = useState(false);
  const [workspaceFormError, setWorkspaceFormError] = useState<string>();
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
  const externalScopeReady = !externalActivity || Boolean(
    selectedExternalAsset
    && externalTarget
    && externalTargetOptions.includes(externalTarget)
    && scopeConfirmation.trim()
    && (externalActivity !== "active_external" || scopeConfirmation.trim().length >= 8)
    && (externalActivity !== "active_external" || templateRevisionPinned)
    && parsedPorts
    && (!isDirectExternal || (parsedPorts.length > 0 && selectedExternalAsset.internetExposed === true))
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
      scopeConfirmation.trim() || "使用者已在本機介面逐項確認資產所有權與唯讀範圍。",
      externalScope,
    );
    if (approved) resetScopeForm();
  };

  const changeSourceKind = (nextKind: SourceKind) => {
    const nextSource = sourceDefinitions[nextKind];
    setSourceKind(nextKind);
    setProfile(nextSource.profiles[0]);
    setSourceLabel(nextSource.label);
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
        setSourceFormError("只接受一份 .json 快照；沒有讀取或複製這個檔案。");
        return;
      }
      setSelectedPath(path);
    } catch {
      setSourceFormError("無法開啟本機檔案選擇器；沒有讀取或複製任何檔案。");
    } finally {
      setChoosingSnapshot(false);
    }
  };

  const connectSnapshot = async (event: FormEvent) => {
    event.preventDefault();
    if (!sourceLabel.trim()) {
      setSourceFormError("請輸入能辨識這份來源的標籤。");
      return;
    }
    if (!selectedPath) {
      setSourceFormError("請先明確選擇一份 JSON 快照。");
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
      setWorkspaceFormError("無法開啟本機目錄選擇器；沒有讀取或複製任何目錄。");
    } finally {
      setChoosingWorkspace(false);
    }
  };

  const attachWorkspace = async (event: FormEvent) => {
    event.preventDefault();
    if (!workspaceLabel.trim()) {
      setWorkspaceFormError("請輸入能辨識這份工作樹的標籤。");
      return;
    }
    if (!selectedWorkspacePath) {
      setWorkspaceFormError("請先明確選擇一個 working-tree 目錄。");
      return;
    }
    setWorkspaceFormError(undefined);
    await onAttachWorkspaceSnapshot({
      caseId,
      label: workspaceLabel.trim(),
      selectedPath: selectedWorkspacePath,
    });
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Coverage Ledger"
        title="清楚交代看過哪裡，也交代看不到哪裡"
        description="「已接來源但沒有發現」和「根本沒有資料來源」是兩回事。未知不會被畫成綠燈。"
        actions={
          <div className="button-group">
            <button className="button button--secondary" type="button" disabled={busy} aria-expanded={showSourceForm} aria-controls="source-snapshot-form" onClick={() => { setShowSourceForm((value) => !value); setShowWorkspaceForm(false); }}>
              <Icon name={showSourceForm ? "close" : "plus"} size={18} />
              {showSourceForm ? "關閉來源表單" : "連接來源快照"}
            </button>
            <button className="button button--secondary" type="button" disabled={busy} aria-expanded={showWorkspaceForm} aria-controls="workspace-snapshot-form" onClick={() => { setShowWorkspaceForm((value) => !value); setShowSourceForm(false); }}>
              <Icon name={showWorkspaceForm ? "close" : "database"} size={18} />
              {showWorkspaceForm ? "關閉工作樹表單" : "加入本機工作樹"}
            </button>
            <button className="button button--primary" type="button" disabled={busy} onClick={() => void onStartDiscovery()}>
              <Icon name="refresh" size={18} />
              {busy ? "處理中…" : "重新盤點來源"}
            </button>
          </div>
        }
      />

      <ProviderAuthorizationPanel
        caseId={caseId}
        sources={sources}
        nativeMode={nativeMode}
        disabled={busy}
        onAuthorizationChanged={onAuthorizationChanged}
      />

      {showSourceForm && (
        <form id="source-snapshot-form" className="source-connect-panel" aria-labelledby="source-connect-title" onSubmit={connectSnapshot}>
          <div className="section-heading">
            <p className="eyebrow">Snapshot-only connector</p>
            <h2 id="source-connect-title">連接一份已保存的 JSON 來源快照</h2>
            <p>這不是即時登入或全域盤點。後端最多只讀取你明確選取的一個 8 MiB JSON 檔，複製進本機案件後再以限定格式解析。</p>
          </div>

          <InlineNotice tone="warning" title="快照不可包含密碼、token、私鑰或其他秘密值">
            <p>請先在來源工具中產生只含必要盤點欄位的 JSON。連接來源只建立候選資產，不會證明所有權，也不會授權或啟動掃描。</p>
          </InlineNotice>

          {!nativeMode && (
            <InlineNotice tone="info" title="展示模式不會讀取本機檔案">
              <p>請在 Tauri 桌面版中連接真實快照；目前畫面只用來預覽流程。</p>
            </InlineNotice>
          )}

          <div className="form-grid form-grid--two">
            <label className="field">
              <span>來源種類</span>
              <select value={sourceKind} onChange={(event) => changeSourceKind(event.target.value as SourceKind)}>
                {allSourceKinds.map((kind) => (
                  <option key={kind} value={kind}>{sourceDefinitions[kind].label}</option>
                ))}
              </select>
              <small>{selectedSource.description}</small>
            </label>
            <label className="field">
              <span>快照格式</span>
              <select value={profile} onChange={(event) => setProfile(event.target.value as SnapshotParserProfile)}>
                {selectedSource.profiles.map((parserProfile) => (
                  <option key={parserProfile} value={parserProfile}>{parserProfileLabels[parserProfile]}</option>
                ))}
              </select>
              <small>格式選項會依來源種類限制，不會用通用解析器猜測。</small>
            </label>
            <label className="field">
              <span>來源標籤</span>
              <input required maxLength={120} value={sourceLabel} onChange={(event) => setSourceLabel(event.target.value)} placeholder="例如：Production AWS inventory" />
              <small>標籤會顯示在涵蓋帳本中；請勿放入憑證或秘密。</small>
            </label>
            <div className="field">
              <span id="snapshot-file-label">JSON 快照</span>
              <button className="snapshot-picker" type="button" disabled={!nativeMode || busy || choosingSnapshot} aria-describedby="snapshot-file-help" onClick={() => void chooseSnapshot()}>
                <Icon name="file" size={18} />
                <span>{selectedPath ? fileNameFromPath(selectedPath) : choosingSnapshot ? "正在開啟選擇器…" : "選擇一份 .json 檔"}</span>
                <Icon name="chevron" size={16} />
              </button>
              <small id="snapshot-file-help">不會掃描資料夾，也不會把檔案路徑寫入 canonical case。</small>
            </div>
          </div>

          {sourceFormError && <p className="form-error" role="alert"><Icon name="warning" size={16} />{sourceFormError}</p>}

          <div className="form-actions">
            <p><Icon name="lock" size={16} /> 連接後仍需另外按「重新盤點來源」。</p>
            <button className="button button--primary" type="submit" disabled={!nativeMode || busy || choosingSnapshot || !sourceLabel.trim() || !selectedPath}>
              {busy ? "連接中…" : "複製並連接快照"}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      {showWorkspaceForm && (
        <form id="workspace-snapshot-form" className="source-connect-panel" aria-labelledby="workspace-snapshot-title" onSubmit={attachWorkspace}>
          <div className="section-heading">
            <p className="eyebrow">Immutable working-tree snapshot</p>
            <h2 id="workspace-snapshot-title">附加一份本機 working-tree 副本</h2>
            <p>後端只複製你明確選取的目錄，套用檔案數、單檔大小、總容量與深度上限，完成後以內容雜湊固定成不可變案件證據。</p>
          </div>

          <InlineNotice tone="warning" title="只排除 .git metadata；先移除工作樹內的秘密檔案">
            <p>所有名為 .git 的項目都不會被開啟或複製，因此 Git history、refs、hooks 與其中 credentials 不會進入快照；但工作樹裡的 .env、金鑰或 token 檔若存在仍屬內容，請先移除。</p>
          </InlineNotice>

          <InlineNotice tone="info" title="這個動作不會授予掃描範圍">
            <p>案件只保存後端產生的快照 ID、內容雜湊與相對路徑 manifest，不保存原始主機路徑。產生的 repository 候選資產仍需由你另外確認所有權與允許範圍。</p>
          </InlineNotice>

          {!nativeMode && (
            <InlineNotice tone="info" title="展示模式不會讀取本機目錄">
              <p>請在 Tauri 桌面版中建立真實 working-tree 快照；目前畫面只用來預覽流程。</p>
            </InlineNotice>
          )}

          <div className="form-grid form-grid--two">
            <label className="field">
              <span>工作樹標籤</span>
              <input required maxLength={120} value={workspaceLabel} onChange={(event) => setWorkspaceLabel(event.target.value)} placeholder="例如：frontend production working tree" />
              <small>只用來辨識案件內的候選資產；請勿放入主機路徑或秘密。</small>
            </label>
            <div className="field">
              <span id="workspace-directory-label">Working-tree 目錄</span>
              <button className="snapshot-picker" type="button" disabled={!nativeMode || busy || choosingWorkspace} aria-describedby="workspace-directory-help" onClick={() => void chooseWorkspace()}>
                <Icon name="database" size={18} />
                <span>{selectedWorkspacePath ? fileNameFromPath(selectedWorkspacePath) : choosingWorkspace ? "正在開啟選擇器…" : "選擇一個工作目錄"}</span>
                <Icon name="chevron" size={16} />
              </button>
              <small id="workspace-directory-help">畫面只顯示目錄名稱；canonical case 不保存原始絕對路徑。</small>
            </div>
          </div>

          {workspaceFormError && <p className="form-error" role="alert"><Icon name="warning" size={16} />{workspaceFormError}</p>}

          <div className="form-actions">
            <p><Icon name="lock" size={16} /> 建立快照後仍需在下方逐項確認所有權與範圍。</p>
            <button className="button button--primary" type="submit" disabled={!nativeMode || busy || choosingWorkspace || !workspaceLabel.trim() || !selectedWorkspacePath}>
              {busy ? "建立快照中…" : "建立不可變工作樹快照"}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      <section className="metrics-grid metrics-grid--four" aria-label="涵蓋摘要">
        <MetricCard label="候選資產" value={assets.length} detail="從已連接資料來源觀察到" icon="database" />
        <MetricCard label="已完成掃描" value={scannedAssets} detail="已授權且工作完整完成" icon="check" tone="accent" />
        <MetricCard label="授權但未完成" value={incompleteAssets} detail="需續跑或排除執行問題" icon="warning" tone={incompleteAssets ? "warning" : "default"} />
        <MetricCard label="待確認資產" value={pendingAssets.length} detail="未確認前不會主動掃描" icon="lock" tone={pendingAssets.length ? "warning" : "default"} />
      </section>

      {(unknownSourceCount > 0 || connectedNoAssetCount > 0) && (
        <section className="coverage-truth-grid" aria-label="未知來源與未發現資產的差異">
          {unknownSourceCount > 0 && (
            <div className="coverage-truth-card coverage-truth-card--unknown">
              <Icon name="warning" size={20} />
              <div><strong>{unknownSourceCount} 個來源目前未知</strong><p>沒有可用資料來源，所以不知道是否存在資產。這不是「0 個資產」，也不是通過。</p></div>
            </div>
          )}
          {connectedNoAssetCount > 0 && (
            <div className="coverage-truth-card coverage-truth-card--none">
              <Icon name="database" size={20} />
              <div><strong>{connectedNoAssetCount} 個來源已檢查但未發現</strong><p>來源可用且本次回傳 0 個候選資產；只代表該快照與時間點的觀察。</p></div>
            </div>
          )}
        </section>
      )}

      <section className="section-block">
        <div className="section-heading">
          <p className="eyebrow">六種涵蓋狀態</p>
          <h2>不是只有紅燈和綠燈</h2>
          <p>每個來源與資產都必須能說明為什麼有結果，或為什麼目前沒有結果。</p>
        </div>
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
                <span>
                  <strong>{meta.label}</strong>
                  <small>{meta.description}</small>
                </span>
                <b>{counts[state]}</b>
              </button>
            );
          })}
        </div>
      </section>

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">資料來源</p>
            <h2>盤點視野</h2>
          </div>
          <button className="button button--ghost button--small" type="button" onClick={() => setFilter("all")}>
            顯示全部
          </button>
        </div>
        {coverage.length === 0 ? (
          <EmptyState icon="coverage" title="尚未建立任何盤點視野" description="案件沒有來源紀錄；先連接一份有界快照或工作樹，再執行來源盤點。" />
        ) : <div className="source-grid">
          {coverage.map((record) => {
            const meta = coverageMeta[record.state];
            return (
              <article key={record.id} className={`source-card source-card--${meta.tone}`}>
                <div className="source-card__top">
                  <span className="platform-avatar">{platformMeta[record.platform].abbreviation}</span>
                  <StatusPill label={meta.shortLabel} tone={meta.tone} />
                </div>
                <h3>{record.label}</h3>
                <p>{record.detail}</p>
                <div className="source-card__footer">
                  <span>{record.assetCount} 個資產</span>
                  <span>{record.lastCheckedAt ? formatDateTime(record.lastCheckedAt) : "尚未連接"}</span>
                </div>
              </article>
            );
          })}
        </div>}
      </section>

      {pendingAssets.length > 0 && (
        <InlineNotice tone="warning" title="有候選資產等待你確認">
          <p>確認所有權前只保留公開盤點證據，不會啟動連線探測或主動弱點測試。</p>
        </InlineNotice>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">資產清單</p>
            <h2>{filter === "all" ? "所有候選資產" : coverageMeta[filter].label}</h2>
            <p>選取待授權資產後，只會送出範圍確認請求；不會立刻掃描。</p>
          </div>
          {selectedAssets.length > 0 && <span className="count-label">已選 {selectedAssets.length} 項</span>}
        </div>

        {selectedAssets.length > 0 && (
          <form className="scope-confirmation-panel" onSubmit={(event) => { event.preventDefault(); void approve(); }}>
            <div className="scope-confirmation-panel__heading">
              <div><p className="eyebrow">逐資產授權</p><h3>確認所有權與允許模式</h3><p>只會為下方選取的 {selectedAssets.length} 個資產建立 grant；這一步不會啟動掃描。</p></div>
              <button className="icon-button" type="button" aria-label="清除選取資產" onClick={resetScopeForm}><Icon name="close" size={17} /></button>
            </div>

            <InlineNotice tone="info" title="問卷預選只是建議，不是授權">
              <p>首次選取資產時，系統只會預選案件問卷意圖與該資產共同適用的模式。你仍須逐項確認所有權、檢查模式與邊界，並明確送出後才會建立 grant。</p>
            </InlineNotice>

            {availableScopeModes.length === 0 ? (
              <InlineNotice tone="warning" title="選取的資產沒有共同授權模式">
                <p>請分開確認外部目標與雲端／本機 artifact，避免把主動外部授權套用到其他資產。</p>
              </InlineNotice>
            ) : (
              <fieldset className="scope-mode-fieldset">
                <legend>允許模式</legend>
                <div className="scope-mode-grid">
                  {availableScopeModes.map((mode) => (
                    <label key={mode} className={`${scopeModes.includes(mode) ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}${externalActivities[mode] && mode !== "public_data" && selectedExternalAsset?.internetExposed !== true ? " scope-mode-card--disabled" : ""}`}>
                      <input
                        type={externalActivities[mode] ? "radio" : "checkbox"}
                        name={externalActivities[mode] ? "external-activity" : undefined}
                        checked={scopeModes.includes(mode)}
                        disabled={Boolean(externalActivities[mode] && mode !== "public_data" && selectedExternalAsset?.internetExposed !== true)}
                        onChange={() => toggleScopeMode(mode)}
                      />
                      <span><strong>{scopeModeLabels[mode].label}</strong><small>{scopeModeLabels[mode].detail}</small></span>
                    </label>
                  ))}
                </div>
              </fieldset>
            )}

            {externalActivity && selectedExternalAsset && limits && (
              <section className="external-scope-builder" aria-labelledby="external-scope-title">
                <div className="external-scope-builder__heading">
                  <div>
                    <p className="eyebrow">Frozen external policy</p>
                    <h4 id="external-scope-title">為 {selectedExternalAsset.name} 固定可執行邊界</h4>
                    <p>目標必須逐字來自來源建立的 identifier 或資產名稱。此 grant 保存 30 天，不能套用 wildcard。</p>
                  </div>
                  <StatusPill
                    label={selectedExternalAsset.internetExposed === true ? "來源證明對外" : selectedExternalAsset.internetExposed === false ? "來源顯示非對外" : "對外狀態未知"}
                    tone={selectedExternalAsset.internetExposed === true ? "positive" : "unknown"}
                  />
                </div>

                {isDirectExternal && selectedExternalAsset.internetExposed !== true && (
                  <InlineNotice tone="warning" title="不能建立直接外部連線授權">
                    <p>來源沒有 `internet_exposed=true` 證據。你仍可選擇公開資料盤點；不能在這裡用人工勾選覆寫來源歸屬。</p>
                  </InlineNotice>
                )}

                {externalTargetOptions.length === 0 && (
                  <InlineNotice tone="warning" title="來源沒有可用的 bounded target">
                    <p>這個資產只有空值、wildcard 或格式不安全的 identifier，不能建立外部 grant。請修正來源快照後重新盤點。</p>
                  </InlineNotice>
                )}

                <div className="form-grid form-grid--two">
                  <label className="field">
                    <span>Canonical target</span>
                    <select value={externalTarget} onChange={(event) => setExternalTarget(event.target.value)}>
                      {externalTargetOptions.map((target) => <option key={target} value={target}>{target}</option>)}
                    </select>
                    <small>只列出此資產的 source-derived identifiers 與名稱；不接受任意輸入。</small>
                  </label>
                  <label className="field">
                    <span>傳輸協定</span>
                    <select value={externalProtocol} onChange={(event) => setExternalProtocol(event.target.value as TransportProtocol)}>
                      <option value="https">HTTPS</option>
                      <option value="http">HTTP</option>
                      <option value="tls">TLS</option>
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                    <small>引擎不得在執行時自行擴充協定。</small>
                  </label>
                  <label className="field">
                    <span>允許連接埠</span>
                    <input value={externalPorts} onChange={(event) => setExternalPorts(event.target.value)} placeholder="443, 8443" inputMode="numeric" />
                    <small>{parsedPorts === undefined ? "格式錯誤：只接受 1–65535 的數字，以逗號或空白分隔。" : `${parsedPorts.length} 個固定 port；不支援範圍或 port 0。`}</small>
                  </label>
                  {externalActivity === "active_external" && <label className="field">
                    <span>Policy revision</span>
                    <input value={templateRevision} readOnly aria-readonly="true" />
                    <small>{templateRevisionPinned ? "由產品鎖定到映像內嵌的 exact template commit。" : "內嵌 template revision 不符合產品鎖定值。"}</small>
                  </label>}
                </div>

                <fieldset className="rate-policy-fieldset">
                  <legend>速率與逾時上限</legend>
                  <div className="rate-policy-grid">
                    <label className="field"><span>每秒請求</span><input type="number" min={1} max={limits.rate} value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.target.valueAsNumber)} /><small>最多 {limits.rate}</small></label>
                    <label className="field"><span>並行數</span><input type="number" min={1} max={limits.concurrency} value={externalConcurrency} onChange={(event) => setExternalConcurrency(event.target.valueAsNumber)} /><small>最多 {limits.concurrency}</small></label>
                    <label className="field"><span>逾時秒數</span><input type="number" min={1} max={limits.timeout} value={externalTimeout} onChange={(event) => setExternalTimeout(event.target.valueAsNumber)} /><small>最多 {limits.timeout}</small></label>
                  </div>
                </fieldset>

                {externalActivity === "active_external" && <label className="field">
                  <span>允許的 template IDs {externalActivity === "active_external" ? "（主動測試必填）" : "（選填）"}</span>
                  <textarea rows={3} value={allowedTemplateIds} onChange={(event) => setAllowedTemplateIds(event.target.value)} placeholder="每行一個精確 template ID；不接受 *" />
                  <small>{templateIdsValid ? `${parsedTemplateIds.length} 個 ID。` : "不可使用 wildcard `*`。"} Headless、OOB、fuzzing、檔案上傳、阻斷服務與密碼攻擊全部固定為不允許。</small>
                </label>}

                <div className="prohibited-template-list" aria-label="固定禁止的 template 能力">
                  {["Headless browser", "Out-of-band callback", "Fuzzing", "File upload", "Denial of service", "Credential attacks"].map((item) => <span key={item}><Icon name="lock" size={13} />{item}</span>)}
                </div>

                <label className="toggle-row toggle-row--danger">
                  <input type="checkbox" checked={allowSensitiveNetworks} onChange={(event) => setAllowSensitiveNetworks(event.target.checked)} />
                  <span><strong>允許解析到明確授權的 private、loopback 或 link-local 網段</strong><small>預設拒絕；metadata endpoints 永遠禁止。此選擇會記錄在 frozen grant，且不會擴充 canonical target。</small></span>
                </label>
              </section>
            )}

            <div className="scope-confirmation-panel__assets">
              {selectedScopeAssets.map((asset) => <span key={asset.id}><b>{asset.name}</b><small>{asset.locator}</small></span>)}
            </div>

            <label className="toggle-row">
              <input type="checkbox" checked={ownershipConfirmed} onChange={(event) => setOwnershipConfirmed(event.target.checked)} />
              <span><strong>我已逐項確認這些資產屬於本次合法評估範圍</strong><small>候選來源或名稱相似不能自動證明所有權。</small></span>
            </label>

            <label className="field">
              <span>{requiresAuthorizationReference ? "授權參考（必填）" : "範圍備註（選填）"}</span>
              <input value={scopeConfirmation} onChange={(event) => setScopeConfirmation(event.target.value)} placeholder={requiresAuthorizationReference ? "例如：工單／合約編號與核准人" : "例如：本次只讀盤點的內部核准紀錄"} />
              <small>{requiresAuthorizationReference ? "任何外部活動都必須留下可追溯的 authority assertion；秘密值與憑證不可填在這裡。" : "秘密值與憑證不可填在這裡。"}</small>
              {externalActivity === "active_external" && scopeConfirmation.trim().length > 0 && scopeConfirmation.trim().length < 8 && <small className="field-error">主動測試的授權參考至少需要 8 個字元。</small>}
            </label>

            <div className="form-actions">
              <p><Icon name="lock" size={16} /> 授權只套用到列出的資產與模式。</p>
              <button className="button button--primary" type="submit" disabled={busy || availableScopeModes.length === 0 || scopeModes.length === 0 || !ownershipConfirmed || (requiresAuthorizationReference && !scopeConfirmation.trim()) || !externalScopeReady}>
                <Icon name="lock" size={16} />{busy ? "記錄中…" : "記錄逐資產範圍"}
              </button>
            </div>
          </form>
        )}

        {filteredAssets.length === 0 ? (
          <EmptyState
            icon={assets.length === 0 && unknownSourceCount > 0 ? "warning" : "database"}
            title={assets.length === 0
              ? unknownSourceCount > 0
                ? "目前沒有候選資產，且盤點視野仍未知"
                : connectedNoAssetCount > 0
                  ? "已連接的來源在本次未發現資產"
                  : "尚未執行資產盤點"
              : "這個篩選下沒有資產"}
            description={assets.length === 0
              ? unknownSourceCount > 0
                ? "至少一個來源尚未連接；不能把目前的空清單解讀為環境沒有資產。"
                : connectedNoAssetCount > 0
                  ? "來源確實可用且回傳零項；這與缺少資料來源的未知狀態不同。"
                  : "先連接資料來源或 working-tree 快照，再執行盤點。"
              : "請切換涵蓋狀態查看其他資產。"}
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table asset-table">
              <thead>
                <tr>
                  <th className="checkbox-cell"><span className="sr-only">選取</span></th>
                  <th>資產</th>
                  <th>平台／位置</th>
                  <th>所有權／授權</th>
                  <th>允許模式</th>
                  <th>涵蓋狀態</th>
                  <th>問題</th>
                </tr>
              </thead>
              <tbody>
                {filteredAssets.map((asset) => {
                  const scopeEligible = scopeEligibleAssets.some((item) => item.id === asset.id);
                  const meta = coverageMeta[asset.coverageState];
                  const anotherAssetSelected = selectedAssets.length > 0 && !selectedAssets.includes(asset.id);
                  const selectedIncludesExternal = selectedScopeAssets.some((item) => item.platform === "external");
                  const incompatibleWithSelection = anotherAssetSelected && (asset.platform === "external" || selectedIncludesExternal);
                  return (
                    <tr key={asset.id}>
                      <td className="checkbox-cell">
                        <input
                          type="checkbox"
                          aria-label={`選取 ${asset.name}`}
                          checked={selectedAssets.includes(asset.id)}
                          disabled={!scopeEligible || incompatibleWithSelection}
                          title={incompatibleWithSelection
                            ? "外部目標必須逐項建立 canonical scope，請先完成或清除目前選取。"
                            : asset.authorizationState === "authorized"
                              ? "可重新確認資產，補充缺少的唯讀允許模式。"
                              : undefined}
                          onChange={() => toggleAsset(asset.id)}
                        />
                      </td>
                      <td>
                        <div className="asset-name">
                          <span className="platform-avatar platform-avatar--small">{platformMeta[asset.platform].abbreviation}</span>
                          <span>
                            <strong>{asset.name}</strong>
                            <small>{asset.type.replaceAll("_", " ")}</small>
                          </span>
                        </div>
                      </td>
                      <td>
                        <strong>{platformMeta[asset.platform].label}</strong>
                        <small className="table-subtext">{asset.region ? `${asset.region} · ` : ""}{asset.locator}</small>
                      </td>
                      <td>
                        <strong>{asset.owner ?? "尚未記錄負責人"}</strong>
                        <small className="table-subtext">
                          {asset.authorizationState === "authorized" ? "已確認範圍" : asset.authorizationState === "pending" ? "候選，等待確認" : asset.authorizationState === "excluded" ? "已排除" : "所有權未知"}
                        </small>
                      </td>
                      <td>
                        <div className="tag-row">
                          {asset.allowedModes.length > 0
                            ? asset.allowedModes.map((mode) => <span key={mode} className="tag tag--light">{scopeModeLabels[mode].label}</span>)
                            : <span className="table-subtext">尚未授權</span>}
                        </div>
                      </td>
                      <td><StatusPill label={meta.shortLabel} tone={meta.tone} /></td>
                      <td><strong>{asset.findingCount}</strong></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {frozenExternalGrants.length > 0 && (
        <section className="section-block">
          <div className="section-heading section-heading--row">
            <div>
              <p className="eyebrow">Frozen external grants</p>
              <h2>已固定的外部執行政策</h2>
              <p>每個 grant 只綁定一個案件與資產。執行端只能縮小，不能擴充目標、port、速率或 template。</p>
            </div>
            <span className="count-label">{frozenExternalGrants.length} 份</span>
          </div>
          <div className="external-grant-list">
            {frozenExternalGrants.map((grant) => {
              const scope = grant.externalScope!;
              const asset = assets.find((item) => item.id === grant.assetId);
              return (
                <article key={grant.id} className="external-grant-card">
                  <div className="external-grant-card__header">
                    <span><Icon name="lock" size={17} /></span>
                    <div><strong>{asset?.name ?? grant.assetId}</strong><small>{activityLabels[scope.activity]} · 到期 {formatDateTime(scope.expiresAt)}</small></div>
                    <StatusPill label={scope.allowSensitiveNetworks ? "允許敏感網段" : "拒絕敏感網段"} tone={scope.allowSensitiveNetworks ? "warning" : "positive"} />
                  </div>
                  <dl>
                    <div><dt>Target</dt><dd><code>{scope.targetKind}:{scope.target}</code></dd></div>
                    <div><dt>Protocol／ports</dt><dd>{scope.protocol.toUpperCase()} · {scope.ports.length ? scope.ports.join(", ") : "無直接連線 port"}</dd></div>
                    <div><dt>Rate</dt><dd>{scope.ratePolicy.requestsPerSecond} req/s · {scope.ratePolicy.concurrency} concurrent · {scope.ratePolicy.timeoutSeconds}s</dd></div>
                    <div><dt>Template policy</dt><dd><code>{scope.templatePolicy.revision}</code> · {scope.templatePolicy.allowedTemplateIds.length} IDs</dd></div>
                    <div><dt>Authority</dt><dd>{scope.assertedAuthority}</dd></div>
                    <div><dt>核准</dt><dd>{scope.approvedBy} · {formatDateTime(scope.approvedAt)}</dd></div>
                  </dl>
                  <p><Icon name="lock" size={13} /> Headless、OOB、fuzzing、file upload、DoS 與 credential attacks：全部禁止</p>
                </article>
              );
            })}
          </div>
        </section>
      )}

      <InlineNotice tone="info" title="主動掃描與盤點分開授權">
        <p>DNS 與公開憑證紀錄可以建立候選清單；Naabu、httpx、Nuclei、Greenbone 等會接觸目標的工作，必須另外確認資產與範圍。</p>
      </InlineNotice>
    </div>
  );
}
