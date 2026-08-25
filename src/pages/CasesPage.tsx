import { Fragment, useEffect, useState, type FormEvent } from "react";

import { formatDateTime, phaseMeta, platformMeta, runStatusMeta } from "../lib";
import type {
  AssessmentActivity,
  AssessmentCase,
  CaseArtifactCleanupResult,
  CaseArtifactDeletionPlan,
  CloudPlatform,
  CompanySize,
  CreateCaseInput,
  DataClass,
  KnownAssetInput,
  ScanRun,
} from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

interface CasesPageProps {
  cases: AssessmentCase[];
  selectedCase?: AssessmentCase;
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

const allPlatforms = Object.entries(platformMeta) as Array<
  [CloudPlatform, (typeof platformMeta)[CloudPlatform]]
>;

const dataClassOptions: Array<{ id: DataClass; label: string }> = [
  { id: "pii", label: "個人資料 PII" },
  { id: "phi", label: "健康資料 PHI" },
  { id: "payment", label: "付款／卡片資料" },
  { id: "credentials", label: "帳密與機密" },
  { id: "none", label: "以上皆無或不確定" },
];

const assessmentActivityOptions: Array<{
  id: AssessmentActivity;
  label: string;
  detail: string;
}> = [
  {
    id: "configuration_assessment",
    label: "設定安全評估",
    detail: "以唯讀方式檢查雲端、SaaS 與基礎設施設定",
  },
  {
    id: "local_artifact_analysis",
    label: "本機 artifact 分析",
    detail: "分析使用者明確附加的程式碼、IaC、映像或設定快照",
  },
  {
    id: "low_impact_external_checks",
    label: "低影響外部檢查",
    detail: "只對日後逐項授權的公開目標發出受限連線",
  },
  {
    id: "active_external_vulnerability_tests",
    label: "主動外部弱點測試",
    detail: "日後仍需可追溯授權、精確目標與限速策略",
  },
];

const assessmentActivityLabels = Object.fromEntries(
  assessmentActivityOptions.map((activity) => [activity.id, activity.label]),
) as Record<AssessmentActivity, string>;

const lineValues = (value: string): string[] =>
  [...new Set(value.split(/\r?\n/u).map((item) => item.trim()).filter(Boolean))];

export function CasesPage({
  cases,
  selectedCase,
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
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [companySize, setCompanySize] = useState<CompanySize>("small");
  const [platforms, setPlatforms] = useState<CloudPlatform[]>(["aws"]);
  const [dataClasses, setDataClasses] = useState<DataClass[]>(["none"]);
  const [requestedActivities, setRequestedActivities] = useState<AssessmentActivity[]>([
    "configuration_assessment",
  ]);
  const [description, setDescription] = useState("");
  const [externalTargets, setExternalTargets] = useState("");
  const [repositories, setRepositories] = useState("");
  const [iacProjects, setIacProjects] = useState("");
  const [containerImages, setContainerImages] = useState("");
  const [kubernetesClusters, setKubernetesClusters] = useState("");
  const [pendingDeleteId, setPendingDeleteId] = useState<string>();
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [artifactDeleteConfirmation, setArtifactDeleteConfirmation] = useState("");
  const interruptedEngineCount = latestRun?.engineRuns.filter((engine) => engine.phase === "interrupted_restart" || engine.errorCode === "desktop_process_restarted").length ?? 0;
  const incompleteEngineCount = latestRun?.engineRuns.filter((engine) => engine.status !== "completed").length ?? 0;
  const terminalRuns = runs.filter((run) => ["completed", "partial", "failed", "cancelled"].includes(run.status));
  const activeRun = runs.find((run) => ["queued", "running", "paused"].includes(run.status));
  const selectedVerificationBaseline = terminalRuns.find((run) => run.id === verificationBaselineRunId);

  useEffect(() => {
    setArtifactDeleteConfirmation("");
  }, [artifactCleanupPlan?.caseId]);

  const togglePlatform = (platform: CloudPlatform) => {
    setPlatforms((current) =>
      current.includes(platform)
        ? current.filter((item) => item !== platform)
        : [...current, platform],
    );
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
    setRequestedActivities((current) =>
      current.includes(activity)
        ? current.filter((item) => item !== activity)
        : [...current, activity],
    );
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (
      !name.trim()
      || !organizationName.trim()
      || platforms.length === 0
      || requestedActivities.length === 0
    ) return;
    const knownAssets: KnownAssetInput[] = [
      ...lineValues(externalTargets).map((value) => ({ kind: "external_target" as const, value })),
      ...lineValues(repositories).map((value) => ({ kind: "repository" as const, value })),
      ...lineValues(iacProjects).map((value) => ({ kind: "iac_project" as const, value })),
      ...lineValues(containerImages).map((value) => ({ kind: "container_image" as const, value })),
      ...lineValues(kubernetesClusters).map((value) => ({ kind: "kubernetes_cluster" as const, value })),
    ];
    const created = await onCreate({
      name: name.trim(),
      organizationName: organizationName.trim(),
      companySize,
      platforms,
      requestedActivities,
      knownAssets,
      dataClasses: dataClasses.length ? dataClasses : ["none"],
      description: description.trim() || undefined,
    });
    if (!created) return;
    setShowForm(false);
    setName("");
    setDescription("");
    setRequestedActivities(["configuration_assessment"]);
    setExternalTargets("");
    setRepositories("");
    setIacProjects("");
    setContainerImages("");
    setKubernetesClusters("");
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

  return (
    <div className="page page--cases">
      <PageHeader
        eyebrow="Assessment Case"
        title="從一個可複驗的案件開始"
        description="每個案件都保留資產、授權範圍、原始證據與前後差異；它不是一次掃完就丟掉的報告。"
        actions={
          <button className="button button--primary" type="button" onClick={() => setShowForm((value) => !value)}>
            <Icon name={showForm ? "close" : "plus"} size={18} />
            {showForm ? "關閉表單" : "建立案件"}
          </button>
        }
      />

      {showForm && (
        <form className="create-case-panel" onSubmit={submit}>
          <div className="section-heading">
            <div>
              <p className="eyebrow">新案件</p>
              <h2>先描述環境，不需要先選掃描器</h2>
              <p>系統會依資產與授權範圍安排合適工具。這些答案不會被當成稽核證據。</p>
            </div>
          </div>

          <div className="form-grid form-grid--two">
            <label className="field">
              <span>案件名稱</span>
              <input
                required
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="例如：2026 年首次安全健檢"
              />
            </label>
            <label className="field">
              <span>組織名稱</span>
              <input
                required
                value={organizationName}
                onChange={(event) => setOrganizationName(event.target.value)}
                placeholder="公司或團隊名稱"
              />
            </label>
            <label className="field">
              <span>組織規模</span>
              <select value={companySize} onChange={(event) => setCompanySize(event.target.value as CompanySize)}>
                <option value="solo">個人／1 人</option>
                <option value="small">小型／2–49 人</option>
                <option value="medium">中型／50–249 人</option>
                <option value="large">大型／250 人以上</option>
              </select>
            </label>
            <label className="field">
              <span>備註（選填）</span>
              <input
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="這次想先釐清什麼？"
              />
            </label>
          </div>

          <fieldset className="choice-fieldset">
            <legend>目前使用的環境</legend>
            <p>至少選一項；之後可在資產盤點中調整。</p>
            <div className="choice-grid">
              {allPlatforms.map(([id, meta]) => (
                <label key={id} className="check-card">
                  <input
                    type="checkbox"
                    checked={platforms.includes(id)}
                    onChange={() => togglePlatform(id)}
                  />
                  <span className="platform-avatar">{meta.abbreviation}</span>
                  <span>{meta.label}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="choice-fieldset">
            <legend>已知資產座標（選填）</legend>
            <p>每行一項。這些只會建立「待確認」候選，不會證明所有權、連線或啟動掃描；不知道就留白，後續由來源盤點。</p>
            <div className="form-grid form-grid--two">
              {platforms.includes("external") && (
                <label className="field">
                  <span>公開網域、IP 或 CIDR</span>
                  <textarea rows={4} value={externalTargets} onChange={(event) => setExternalTargets(event.target.value)} placeholder={"example.com\n203.0.113.10\n203.0.113.0/28"} />
                  <small>不接受 wildcard；外部連線仍需逐項所有權與書面範圍確認。</small>
                </label>
              )}
              {platforms.includes("code") && (
                <>
                  <label className="field">
                    <span>程式碼 repository URL 或名稱</span>
                    <textarea rows={4} value={repositories} onChange={(event) => setRepositories(event.target.value)} placeholder={"https://github.com/example/service\ninternal-api"} />
                    <small>之後仍要由目錄選擇器建立不可變工作樹快照。</small>
                  </label>
                  <label className="field">
                    <span>IaC project 或 state 座標</span>
                    <textarea rows={4} value={iacProjects} onChange={(event) => setIacProjects(event.target.value)} placeholder={"infra/production\nterraform/prod"} />
                  </label>
                </>
              )}
              {platforms.includes("container") && (
                <label className="field">
                  <span>容器映像 digest</span>
                  <textarea rows={4} value={containerImages} onChange={(event) => setContainerImages(event.target.value)} placeholder="registry.example/app@sha256:…" />
                  <small>為了可複驗，只接受完整 repository@sha256:64 位小寫十六進位。</small>
                </label>
              )}
              {platforms.includes("kubernetes") && (
                <label className="field">
                  <span>Kubernetes cluster／context 名稱</span>
                  <textarea rows={4} value={kubernetesClusters} onChange={(event) => setKubernetesClusters(event.target.value)} placeholder={"production-eks\nstaging-gke"} />
                  <small>名稱只建立候選；掃描仍使用後續選取的唯讀、不可變 cluster 設定快照。</small>
                </label>
              )}
            </div>
          </fieldset>

          <fieldset className="choice-fieldset">
            <legend>這次想進行的評估活動</legend>
            <p>至少選一項。這只是案件意向，不會建立 scope grant、證明所有權或啟動引擎。</p>
            <div className="choice-grid choice-grid--compact">
              {assessmentActivityOptions.map((activity) => (
                <label key={activity.id} className="check-card check-card--compact">
                  <input
                    type="checkbox"
                    checked={requestedActivities.includes(activity.id)}
                    onChange={() => toggleAssessmentActivity(activity.id)}
                  />
                  <span>
                    {activity.label}
                    <small>{activity.detail}</small>
                  </span>
                </label>
              ))}
            </div>
            {requestedActivities.includes("active_external_vulnerability_tests") && (
              <InlineNotice tone="warning" title="主動測試意向不是授權">
                <p>建立案件後仍須逐項確認所有權、活動類型、連接埠、限速、期限與書面授權參考；未完成前不會派送主動引擎。</p>
              </InlineNotice>
            )}
          </fieldset>

          <fieldset className="choice-fieldset">
            <legend>可能涉及的資料</legend>
            <p>只用來調整風險說明與優先順序，不代表法規判定。</p>
            <div className="choice-grid choice-grid--compact">
              {dataClassOptions.map((item) => (
                <label key={item.id} className="check-card check-card--compact">
                  <input
                    type="checkbox"
                    checked={dataClasses.includes(item.id)}
                    onChange={() => toggleDataClass(item.id)}
                  />
                  <span>{item.label}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <div className="form-actions">
            <p><Icon name="lock" size={16} /> 建立案件不會連接雲端或啟動掃描。</p>
            <button
              className="button button--primary"
              type="submit"
              disabled={busy || !name.trim() || !organizationName.trim() || platforms.length === 0 || requestedActivities.length === 0}
            >
              {busy ? "建立中…" : "建立本機案件"}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      {selectedCase && (
        <section className="current-case-hero" aria-labelledby="current-case-title">
          <div>
            <div className="current-case-hero__meta">
              <StatusPill label={phaseMeta[selectedCase.phase].label} tone={phaseMeta[selectedCase.phase].tone} />
              {selectedCase.isDemo && <StatusPill label="展示案件" tone="demo" />}
              {latestRun && <StatusPill label={`最新輪次：${runStatusMeta[latestRun.status].label}`} tone={runStatusMeta[latestRun.status].tone} />}
            </div>
            <h2 id="current-case-title">{selectedCase.name}</h2>
            <p>{selectedCase.organizationName} · 更新於 {formatDateTime(selectedCase.updatedAt)}</p>
            <div className="platform-list" aria-label="案件環境">
              {selectedCase.platforms.map((platform) => (
                <span key={platform}>{platformMeta[platform].label}</span>
              ))}
            </div>
            {selectedCase.requestedActivities.length > 0 && (
              <div className="platform-list" aria-label="問卷評估意向">
                {selectedCase.requestedActivities.map((activity) => (
                  <span key={activity}>{assessmentActivityLabels[activity]}</span>
                ))}
              </div>
            )}
          </div>
          <button className="button button--light" type="button" onClick={interruptedEngineCount > 0 ? onOpenProgress : onContinue}>
            {interruptedEngineCount > 0 ? "處理重啟後中斷" : "查看資產與涵蓋"}
            <Icon name="arrow" size={17} />
          </button>
        </section>
      )}

      {selectedCase && terminalRuns.length > 0 && (
        <section className="section-block" aria-labelledby="verification-baseline-title">
          <div className="section-heading section-heading--row">
            <div>
              <p className="eyebrow">Verification baseline</p>
              <h2 id="verification-baseline-title">選擇複驗基準輪次</h2>
              <p>只有已到達明確終態的輪次可選；送出後，這個 baseline 會和新輪次一起持久保存。</p>
            </div>
            <button className="button button--light" type="button" onClick={onOpenVerification}>查看差異</button>
          </div>
          <label className="field">
            <span>終態 baseline</span>
            <select
              value={verificationBaselineRunId ?? ""}
              onChange={(event) => onSelectVerificationBaseline(event.target.value)}
            >
              {terminalRuns.map((run) => (
                <option key={run.id} value={run.id}>
                  {run.label} · {runStatusMeta[run.status].label} · {formatDateTime(run.finishedAt ?? run.startedAt)}
                </option>
              ))}
            </select>
            <small>{selectedVerificationBaseline ? `將以 ${selectedVerificationBaseline.id} 建立可恢復的比較意圖。` : "請選擇一個終態輪次。"}</small>
          </label>
          <div className="form-actions">
            <p>{activeRun ? `${activeRun.label} 尚未終止，需先續跑或取消。` : "新掃描完成後會自動建立 resolved、persistent、new 與 unverifiable 差異。"}</p>
            <button
              className="button button--primary"
              type="button"
              disabled={busy || Boolean(activeRun) || !selectedVerificationBaseline}
              onClick={() => selectedVerificationBaseline && void onStartRescan(selectedVerificationBaseline.id)}
            >
              <Icon name="refresh" size={17} />
              {busy ? "建立中…" : activeRun ? "先處理未終止輪次" : "以此基準開始複驗"}
            </button>
          </div>
        </section>
      )}

      {assetCount === 0 && unknownSourceCount > 0 && (
        <InlineNotice tone="warning" title="目前顯示 0 個候選資產，但來源視野仍未知">
          <p>這個數字只代表尚未從可用來源建立候選清單，不能解讀為組織沒有資產。先連接來源並重新盤點。</p>
        </InlineNotice>
      )}

      {assetCount === 0 && unknownSourceCount === 0 && connectedNoAssetSourceCount > 0 && (
        <InlineNotice tone="info" title="已連接來源，本次確實未發現候選資產">
          <p>這與來源未知不同；結論仍只限於已連接快照、既定範圍與觀察時間。</p>
        </InlineNotice>
      )}

      {interruptedEngineCount > 0 && latestRun && (
        <InlineNotice tone="warning" title={`${interruptedEngineCount} 個引擎因桌面程式重啟而暫停`}>
          <p>最新輪次 {latestRun.id} 保留了 durable checkpoint。到掃描進度明確續跑或取消；應用程式不會自動恢復連線。</p>
        </InlineNotice>
      )}

      {artifactCleanupPlan && (
        <section className={`artifact-cleanup-panel ${artifactCleanupResult?.removed ? "artifact-cleanup-panel--removed" : artifactCleanupPlan.exists ? "artifact-cleanup-panel--danger" : "artifact-cleanup-panel--absent"}`} aria-labelledby="artifact-cleanup-title">
          <div className="artifact-cleanup-panel__copy">
            <p className="eyebrow">獨立步驟：本機證據清理</p>
            <h2 id="artifact-cleanup-title">
              {artifactCleanupResult?.removed
                ? "案件證據已永久移除"
                : artifactCleanupPlan.exists
                  ? "資料庫紀錄已刪除；證據仍完整保留"
                  : "案件證據目錄已不存在"}
            </h2>
            <p>
              {artifactCleanupResult?.removed
                ? "這項刪除不可復原。案件資料庫紀錄與本機證據已經分成兩個明確動作處理。"
                : artifactCleanupPlan.exists
                  ? "保留證據不會影響案件紀錄刪除。只有輸入下方完整片語後，才會另外刪除這個精確目錄；刪除後無法復原。"
                  : "後端回報這個精確案件目錄目前不存在，因此不需要也不會送出證據刪除命令。"}
            </p>
            <code>{artifactCleanupPlan.exactPath}</code>
          </div>

          {artifactCleanupPlan.exists && !artifactCleanupResult?.removed ? (
            <form className="artifact-cleanup-panel__form" onSubmit={(event) => void submitArtifactDelete(event)}>
              <label className="field">
                <span>輸入 `DELETE {artifactCleanupPlan.caseId}`</span>
                <input autoComplete="off" spellCheck={false} value={artifactDeleteConfirmation} onChange={(event) => setArtifactDeleteConfirmation(event.target.value)} />
              </label>
              <div className="artifact-cleanup-panel__actions">
                <button className="button button--secondary button--small" type="button" disabled={busy} onClick={onDismissArtifactCleanup}>保留證據</button>
                <button className="button button--danger button--small" type="submit" disabled={busy || artifactDeleteConfirmation !== `DELETE ${artifactCleanupPlan.caseId}`}>
                  <Icon name="trash" size={16} />
                  {busy ? "永久刪除中…" : "永久刪除證據"}
                </button>
              </div>
            </form>
          ) : (
            <button className="button button--secondary button--small" type="button" onClick={onDismissArtifactCleanup}>知道了</button>
          )}
        </section>
      )}

      <section className="metrics-grid metrics-grid--four" aria-label="目前案件摘要">
        <MetricCard label="已發現資產" value={assetCount} detail="只計入目前有來源的候選資產" icon="database" />
        <MetricCard label="完整問題清單" value={findingCount} detail="首頁排序不會隱藏其他結果" icon="findings" tone={findingCount ? "danger" : "default"} />
        <MetricCard label="未知資料來源" value={unknownSourceCount} detail="未知不等於沒有資產或已通過" icon="warning" tone={unknownSourceCount ? "warning" : "default"} />
        <MetricCard label="不完整引擎工作" value={incompleteEngineCount} detail={`${connectedNoAssetSourceCount} 個來源已接但未發現資產`} icon="progress" tone={incompleteEngineCount ? "warning" : "default"} />
      </section>

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">所有案件</p>
            <h2>本機案件清單</h2>
          </div>
          <span className="count-label">{cases.length} 個案件</span>
        </div>

        {cases.length === 0 ? (
          <EmptyState
            icon="cases"
            title="尚未建立案件"
            description="建立第一個案件後，資產、掃描證據與複驗會被保存在同一條生命週期。"
            action={<button className="button button--primary" type="button" onClick={() => setShowForm(true)}>建立案件</button>}
          />
        ) : (
          <div className="case-list">
            {cases.map((assessmentCase) => {
              const active = assessmentCase.id === selectedCase?.id;
              const confirmingDelete = pendingDeleteId === assessmentCase.id;
              return (
                <Fragment key={assessmentCase.id}>
                <article className={active ? "case-row case-row--active" : "case-row"}>
                  <button type="button" className="case-row__main" onClick={() => onSelect(assessmentCase.id)}>
                    <span className="case-row__icon"><Icon name="cases" /></span>
                    <span className="case-row__copy">
                      <span className="case-row__title">
                        <strong>{assessmentCase.name}</strong>
                        {assessmentCase.isDemo && <small>展示</small>}
                      </span>
                      <span>{assessmentCase.organizationName}</span>
                      <span>{assessmentCase.assetCount ?? "—"} 個資產 · {assessmentCase.findingCount ?? "—"} 項 canonical finding</span>
                      <span className="case-row__platforms">
                        {assessmentCase.platforms.slice(0, 4).map((platform) => platformMeta[platform].label).join(" · ")}
                        {assessmentCase.platforms.length > 4 ? ` · +${assessmentCase.platforms.length - 4}` : ""}
                      </span>
                    </span>
                  </button>
                  <div className="case-row__aside">
                    <StatusPill label={phaseMeta[assessmentCase.phase].label} tone={phaseMeta[assessmentCase.phase].tone} />
                    <span>{formatDateTime(assessmentCase.updatedAt)}</span>
                  </div>
                  <div className="case-row__actions">
                    {assessmentCase.phase !== "archived" && (
                      <button className="icon-button case-row__archive" type="button" disabled={busy} aria-label={`封存 ${assessmentCase.name}`} title="封存案件" onClick={() => void onArchive(assessmentCase.id)}>
                        <Icon name="archive" size={17} />
                      </button>
                    )}
                    <button
                      className="icon-button icon-button--danger"
                      type="button"
                      disabled={busy}
                      aria-label={`開始刪除 ${assessmentCase.name}`}
                      title="刪除案件資料庫紀錄"
                      aria-expanded={confirmingDelete}
                      aria-controls={`delete-confirm-${assessmentCase.id}`}
                      onClick={() => confirmingDelete ? cancelDelete() : beginDelete(assessmentCase.id)}
                    >
                      <Icon name={confirmingDelete ? "close" : "trash"} size={17} />
                    </button>
                    <button className="icon-button" type="button" aria-label={`選擇 ${assessmentCase.name}`} onClick={() => onSelect(assessmentCase.id)}>
                      <Icon name="chevron" />
                    </button>
                  </div>
                </article>
                {confirmingDelete && (
                  <form id={`delete-confirm-${assessmentCase.id}`} className="case-delete-confirmation" aria-labelledby={`delete-title-${assessmentCase.id}`} onSubmit={(event) => void submitDelete(event, assessmentCase)}>
                    <div>
                      <p className="eyebrow">第 2 步／2</p>
                      <h3 id={`delete-title-${assessmentCase.id}`}>確認刪除案件資料庫紀錄</h3>
                      <p>這會從案件清單移除資料庫紀錄，但不會自動刪除證據目錄。證據檔清理必須在看到精確路徑後另行確認。</p>
                    </div>
                    <label className="field">
                      <span>輸入完整案件名稱「{assessmentCase.name}」</span>
                      <input autoFocus autoComplete="off" value={deleteConfirmation} onChange={(event) => setDeleteConfirmation(event.target.value)} />
                    </label>
                    <div className="case-delete-confirmation__actions">
                      <button className="button button--ghost button--small" type="button" disabled={busy} onClick={cancelDelete}>取消</button>
                      <button className="button button--danger button--small" type="submit" disabled={busy || deleteConfirmation !== assessmentCase.name}>
                        <Icon name="trash" size={16} />
                        {busy ? "刪除中…" : "只刪除案件紀錄"}
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

      <section className="workflow-strip" aria-label="完整案件流程">
        {[
          ["01", "盤點", "找到有來源的候選資產"],
          ["02", "授權", "逐項確認合法掃描範圍"],
          ["03", "掃描", "依資產自動派送引擎"],
          ["04", "交接", "輸出完整證據與建議"],
          ["05", "複驗", "同案件比較修復差異"],
        ].map(([step, title, detail]) => (
          <div key={step} className="workflow-step">
            <span>{step}</span>
            <strong>{title}</strong>
            <small>{detail}</small>
          </div>
        ))}
      </section>
    </div>
  );
}
