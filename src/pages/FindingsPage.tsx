import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  confidenceMeta,
  formatDateTime,
  severityMeta,
  workflowMeta,
} from "../lib";
import type {
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

interface FindingsPageProps {
  findings: Finding[];
  findingGroups: FindingGroup[];
  findingGroupEvents: FindingGroupEvent[];
  coverage: CoverageRecord[];
  runs: ScanRun[];
  focusedFindingId?: string;
  workflowEvents: FindingWorkflowEvent[];
  busy: boolean;
  onUpdateWorkflow: (input: Omit<FindingWorkflowUpdateInput, "caseId">) => Promise<void>;
  onGroupFindings: (input: { title: string; findingIds: string[]; rationale: string }) => Promise<void>;
  onUngroupFindings: (groupId: string) => Promise<void>;
  onOpenCoverage: () => void;
  onOpenProgress: () => void;
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
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

const workflowTone = (state: FindingWorkflowState): string => {
  if (state === "verified_resolved" || state === "confirmed") return "positive";
  if (state === "false_positive") return "neutral";
  if (state === "remediated_pending_verification" || state === "remediation_reported") return "info";
  return "warning";
};

export function FindingsPage({
  findings,
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
}: FindingsPageProps) {
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
    () => [...findings].sort((a, b) => b.priority - a.priority || a.title.localeCompare(b.title, "zh-Hant")),
    [findings],
  );
  const displayRankByFindingId = useMemo(
    () => new Map(ordered.map((finding, index) => [finding.id, index + 1])),
    [ordered],
  );
  const expertTypes = useMemo(
    () => [...new Set(findings.map((finding) => finding.expertType).filter(Boolean))].sort((a, b) => a.localeCompare(b, "zh-Hant")),
    [findings],
  );
  const controls = useMemo(() => {
    const values = new Map<string, { key: string; label: string }>();
    for (const finding of findings) {
      for (const item of finding.controls) {
        const key = controlKey(item.framework, item.version, item.controlId);
        values.set(key, { key, label: `${item.framework} ${item.controlId}` });
      }
    }
    return [...values.values()].sort((a, b) => a.label.localeCompare(b.label, "zh-Hant"));
  }, [findings]);
  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase("zh-Hant");
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
      ].join(" ").toLocaleLowerCase("zh-Hant").includes(normalizedQuery);
      return matchesSeverity && matchesWorkflow && matchesExpert && matchesControl && matchesQuery;
    });
  }, [control, expertType, ordered, query, severity, workflow]);

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

  if (findings.length === 0) {
    const latestRun = runs[0];
    const unknownSources = coverage.filter((item) => item.state === "source_unavailable_unknown").length;
    const connectedWithoutAssets = coverage.filter((item) => item.state === "source_connected_none").length;
    const incompleteRun = latestRun && latestRun.status !== "completed";
    const title = !latestRun
      ? "尚未產生掃描結果"
      : incompleteRun
        ? "本輪沒有 canonical finding，但掃描未完整完成"
        : unknownSources > 0
          ? "目前沒有 finding，但仍有未知視野"
          : "已完成的範圍內沒有觀察到 finding";
    const description = !latestRun
      ? "先查看資產與涵蓋，確認來源與逐資產範圍，再從掃描進度啟動工作。"
      : incompleteRun
        ? "失敗、部分完成、取消或未執行的工作都可能留下未檢查範圍；請查看每個引擎的終態與原因。"
        : unknownSources > 0
          ? `${unknownSources} 個來源沒有可用資料，因此不能把空清單解讀為沒有資產或安全。`
          : `${connectedWithoutAssets} 個來源回報「已連接但未發現」；這只描述本次已知範圍，不是安全保證。`;
    return (
      <div className="page">
        <PageHeader eyebrow="Findings" title="問題清單" description="空清單也必須連同涵蓋與引擎狀態一起解讀。" />
        <EmptyState
          icon={incompleteRun || unknownSources > 0 ? "warning" : "findings"}
          title={title}
          description={description}
          action={
            <div className="button-group">
              <button className="button button--secondary" type="button" onClick={onOpenCoverage}><Icon name="coverage" size={16} />查看涵蓋</button>
              {latestRun && <button className="button button--primary" type="button" onClick={onOpenProgress}><Icon name="progress" size={16} />查看引擎狀態</button>}
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
    await onUpdateWorkflow({
      findingId: selected.id,
      status: decisionStatus,
      decidedBy: decidedBy.trim(),
      reason: decisionReason.trim(),
      expiresAt: decisionStatus === "false_positive" && decisionExpiry
        ? new Date(`${decisionExpiry}T23:59:59`).toISOString()
        : undefined,
    });
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
    await onGroupFindings({
      title: groupTitle.trim(),
      findingIds: groupFindingIds,
      rationale: groupRationale.trim(),
    });
    setGroupTitle("");
    setGroupRationale("");
    setGroupFindingIds([]);
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Findings"
        title="先看最值得處理的事，完整結果一項不少"
        description="每項 finding 都連回資產、掃描輪次、證據 artifact 與來源版本。控制項只是導航座標，不是 NIST／ISO 合規判定。"
      />

      <section className="metrics-grid metrics-grid--four" aria-label="問題摘要">
        <MetricCard label="嚴重" value={criticalCount} detail="優先請對應專家確認" icon="warning" tone={criticalCount ? "danger" : "default"} />
        <MetricCard label="高風險" value={highCount} detail="依證據與情境排列，不是風險分數" icon="findings" tone={highCount ? "warning" : "default"} />
        <MetricCard label="待人工確認" value={needsReview} detail="掃描器判定不等於已確認事實" icon="search" />
        <MetricCard label="受影響資產" value={affectedAssets} detail={`完整清單共 ${findings.length} 項`} icon="database" />
      </section>

      <section className="section-block" aria-labelledby="finding-groups-title">
        <div className="section-heading">
          <p className="eyebrow">可逆關聯</p>
          <h2 id="finding-groups-title">把相關 findings 放在同一個交接群組</h2>
          <p>群組只改變呈現方式；每筆 canonical finding、fingerprint、證據與 raw artifact 都保持獨立。</p>
        </div>

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
                    <span>{members.length} 項 · {formatDateTime(group.createdAt)}</span>
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
                  <small>建立者：{group.groupedBy} · Group ID：{group.id}</small>
                  <button
                    className="button button--ghost button--small"
                    type="button"
                    disabled={busy}
                    onClick={() => void onUngroupFindings(group.id)}
                  >
                    只移除群組（保留全部 findings）
                  </button>
                </article>
              );
            })}
          </div>
        )}

        {orderedGroupEvents.length > 0 && (
          <details className="source-connect-panel">
            <summary>不可變群組歷程（{orderedGroupEvents.length} 筆）</summary>
            <p>建立與移除都只追加事件；移除群組不會刪除 canonical findings、證據或先前事件。</p>
            <div className="evidence-list">
              {orderedGroupEvents.map((event) => (
                <article key={event.id} className="evidence-item">
                  <div>
                    <strong>{event.action === "created" ? "建立群組" : "移除群組"}：{event.title}</strong>
                    <span>{formatDateTime(event.occurredAt)}</span>
                  </div>
                  <p>{event.rationale}</p>
                  <ul className="detail-list">
                    {event.findingIds.map((findingId) => (
                      <li key={findingId}>{findingById.get(findingId)?.title ?? `Finding ID：${findingId}`}</li>
                    ))}
                  </ul>
                  <small>執行者：{event.actor} · Group ID：{event.groupId}</small>
                </article>
              ))}
            </div>
          </details>
        )}

        <form className="source-connect-panel" onSubmit={(event) => void submitGroup(event)}>
          <label>
            <span>群組標題</span>
            <input maxLength={200} required value={groupTitle} onChange={(event) => setGroupTitle(event.target.value)} placeholder="例如：高權限身分保護需要一起檢視" />
          </label>
          <label>
            <span>關聯理由</span>
            <textarea maxLength={2000} required value={groupRationale} onChange={(event) => setGroupRationale(event.target.value)} placeholder="說明為何應由同一位專家一起檢視；不要把它寫成稽核結論。" />
          </label>
          <fieldset className="choice-fieldset">
            <legend>選擇至少兩項尚未分組的 findings</legend>
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
            建立可逆群組
          </button>
        </form>
      </section>

      {topFindings.length > 0 && (
        <section className="section-block priority-section">
          <div className="section-heading">
            <p className="eyebrow">現在先處理</p>
            <h2>優先摘要</h2>
            <p>優先順序方便人員分流；不會隱藏其他 findings，也不會自動執行 remediation。</p>
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
                <span className="priority-card__action">查看證據 <Icon name="arrow" size={15} /></span>
              </button>
            ))}
          </div>
        </section>
      )}

      <InlineNotice tone="info" title="這不是稽核結論，也不是可執行修復">
        <p>畫面只保存觀察、可能影響、人工 workflow 與建議找哪類專家。任何環境變更都在產品之外由具權限的人員評估及執行。</p>
      </InlineNotice>

      <section id="finding-browser" className="finding-browser">
        <div className="finding-browser__list">
          <div className="section-heading section-heading--row finding-toolbar-heading">
            <div><p className="eyebrow">全部 findings</p><h2>完整問題清單</h2></div>
            <span className="count-label">{filtered.length}／{findings.length}</span>
          </div>

          <div className="finding-filter-stack">
            <label className="search-field">
              <span className="sr-only">搜尋問題、證據或 provenance</span>
              <Icon name="search" size={18} />
              <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜尋問題、資產、證據、fingerprint…" />
            </label>
            <div className="finding-filter-grid">
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">嚴重度</span>
                <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | "all")}>
                  <option value="all">所有嚴重度</option>
                  {severityOrder.map((item) => <option key={item} value={item}>{severityMeta[item].label}</option>)}
                </select>
              </label>
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">處理狀態</span>
                <select value={workflow} onChange={(event) => setWorkflow(event.target.value as FindingWorkflowState | "all")}>
                  <option value="all">所有處理狀態</option>
                  {workflowOrder.map((item) => <option key={item} value={item}>{workflowMeta[item]}</option>)}
                </select>
              </label>
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">專家類型</span>
                <select value={expertType} onChange={(event) => setExpertType(event.target.value)}>
                  <option value="all">所有專家類型</option>
                  {expertTypes.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </label>
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">相關控制項</span>
                <select value={control} onChange={(event) => setControl(event.target.value)}>
                  <option value="all">所有控制項座標</option>
                  {controls.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}
                </select>
              </label>
            </div>
            {activeFilterCount > 0 && <button className="clear-filters" type="button" onClick={clearFilters}><Icon name="close" size={14} />清除 {activeFilterCount} 個篩選條件</button>}
          </div>

          <div className="finding-list" role="list">
            {filtered.length === 0 ? (
              <EmptyState icon="search" title="沒有符合的問題" description="清除搜尋字詞、workflow、專家類型或控制項篩選。" action={<button className="button button--ghost button--small" type="button" onClick={clearFilters}>清除篩選</button>} />
            ) : filtered.map((finding) => (
              <button
                key={finding.id}
                type="button"
                role="listitem"
                className={selectedId === finding.id ? "finding-row finding-row--active" : "finding-row"}
                onClick={() => setSelectedId(finding.id)}
              >
                <span className="finding-row__priority" aria-label={`交接優先順序第 ${displayRankByFindingId.get(finding.id) ?? "—"} 位`}>
                  第 {displayRankByFindingId.get(finding.id) ?? "—"}
                </span>
                <span className="finding-row__main">
                  <span className="finding-row__top">
                    <StatusPill label={severityMeta[finding.severity].label} tone={severityMeta[finding.severity].tone} />
                    <StatusPill label={workflowMeta[finding.workflowState]} tone={workflowTone(finding.workflowState)} />
                  </span>
                  <strong>{finding.title}</strong>
                  <span>{finding.assetName} · {finding.evidence.length} 份證據 · {confidenceMeta[finding.confidence]}</span>
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
                <div><dt>資產</dt><dd>{selected.assetName}</dd></div>
                <div><dt>處理狀態</dt><dd>{workflowMeta[selected.workflowState]}</dd></div>
                <div><dt>建議專家類型</dt><dd>{selected.expertType}</dd></div>
                <div><dt>最後觀察</dt><dd>{formatDateTime(selected.lastSeenAt)}</dd></div>
                <div><dt>證據信心</dt><dd>{confidenceMeta[selected.confidence]}</dd></div>
                <div><dt>關聯資產</dt><dd>{selected.assetIds?.length ?? 1} 個</dd></div>
              </dl>

              <section className="detail-section">
                <div className="detail-section__heading"><h3>人工處理歷程</h3><span>{selectedEvents.length} 筆決定</span></div>
                <form className="source-connect-panel" onSubmit={(event) => void submitDecision(event)}>
                  <p>只記錄處理狀態；不會修改原始 evidence，也不會執行 remediation。「已驗證解決」必須已有可比較複驗證據。</p>
                  <label>
                    <span>新狀態</span>
                    <select value={decisionStatus} onChange={(event) => setDecisionStatus(event.target.value as (typeof decisionStates)[number])}>
                      {decisionStates.map((state) => <option key={state} value={state}>{workflowMeta[state]}</option>)}
                    </select>
                  </label>
                  <label>
                    <span>決定者</span>
                    <input required maxLength={120} value={decidedBy} onChange={(event) => setDecidedBy(event.target.value)} placeholder="姓名、團隊或可追溯識別" />
                  </label>
                  <label>
                    <span>理由</span>
                    <textarea required maxLength={2000} value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)} placeholder="記錄判斷依據；不會覆寫掃描證據。" />
                  </label>
                  {decisionStatus === "false_positive" && (
                    <label>
                      <span>False-positive 到期日（選填）</span>
                      <input type="date" value={decisionExpiry} onChange={(event) => setDecisionExpiry(event.target.value)} />
                    </label>
                  )}
                  <button className="button button--secondary" type="submit" disabled={busy || !decidedBy.trim() || !decisionReason.trim() || decisionStatus === selected.workflowState}>
                    <Icon name="database" size={16} />保存處理決定
                  </button>
                </form>
                {selectedEvents.length === 0 ? <p>尚未記錄人工處理決定。</p> : (
                  <div className="evidence-list">
                    {selectedEvents.map((event) => (
                      <article key={event.id} className="evidence-item">
                        <div><strong>{workflowMeta[event.fromStatus]} → {workflowMeta[event.toStatus]}</strong><span>{formatDateTime(event.decidedAt)}</span></div>
                        <p>{event.reason}</p>
                        <small>決定者：{event.decidedBy}{event.expiresAt ? ` · 到期：${formatDateTime(event.expiresAt)}` : " · 不到期"}</small>
                      </article>
                    ))}
                  </div>
                )}
              </section>

              <section className="detail-section">
                <h3>可能影響</h3>
                <p>{selected.impact}</p>
              </section>

              {(selected.priorityReasons?.length ?? 0) > 0 && (
                <section className="detail-section">
                  <h3>為何優先顯示</h3>
                  <ul className="detail-list">{selected.priorityReasons?.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                </section>
              )}

              <section className="detail-section detail-section--advice">
                <h3>建議處理方向</h3>
                <p>{selected.recommendation}</p>
                {selected.rollbackConsiderations && <p><strong>變更前考量：</strong>{selected.rollbackConsiderations}</p>}
                <small>這是交給人員評估的方向；產品不會自動執行，也不對變更結果背書。</small>
              </section>

              {selected.verificationGuidance && (
                <section className="detail-section">
                  <h3>複驗指引</h3>
                  <p>{selected.verificationGuidance}</p>
                </section>
              )}

              <section className="detail-section">
                <div className="detail-section__heading"><h3>掃描證據</h3><span>{selected.evidence.length} 份</span></div>
                {selected.evidence.length === 0 ? (
                  <p>這筆 finding 沒有可核對的 evidence；請交由專家確認資料完整性。</p>
                ) : (
                  <div className="evidence-list">
                    {selected.evidence.map((evidence) => (
                      <article key={evidence.id} className="evidence-item">
                        <div><strong>{evidence.sourceEngine}</strong><span>{formatDateTime(evidence.observedAt)}</span></div>
                        <p>{evidence.summary}</p>
                        <dl className="evidence-provenance">
                          <div><dt>種類</dt><dd>{evidence.kind?.replaceAll("_", " ") ?? "未回報"}</dd></div>
                          <div><dt>掃描輪次</dt><dd><code>{evidence.runId ?? selected.lastSeenRunId ?? "未回報"}</code></dd></div>
                          <div><dt>Engine run</dt><dd><code>{evidence.engineRunId ?? "舊版未記錄，無法推定"}</code></dd></div>
                          <div><dt>Artifact ID</dt><dd><code>{evidence.artifactId ?? "未回報"}</code></dd></div>
                          <div><dt>內容雜湊</dt><dd><code>{evidence.rawArtifactHash}</code></dd></div>
                          <div><dt>證據指標</dt><dd><code>{evidence.rawArtifactPath ?? "無內部 pointer"}</code></dd></div>
                          <div><dt>敏感值</dt><dd>{evidence.redacted === true ? "已遮罩" : evidence.redacted === false ? "未標示遮罩" : "未回報"}</dd></div>
                        </dl>
                      </article>
                    ))}
                  </div>
                )}
              </section>

              <section className="detail-section">
                <div className="detail-section__heading"><h3>相關控制項（導航）</h3><span>非合規判定</span></div>
                {selected.controls.length === 0 ? <p>這筆 finding 沒有控制項映射。</p> : (
                  <div className="control-list">
                    {selected.controls.map((item) => {
                      const key = controlKey(item.framework, item.version, item.controlId);
                      return (
                        <button key={key} type="button" className={control === key ? "control-item control-item--active" : "control-item"} onClick={() => applyControlFilter(key)}>
                          <span><b>{item.framework}</b><small>{item.version}</small></span>
                          <span><strong>{item.controlId}{item.title ? ` · ${item.title}` : ""}</strong><small>{item.rationale ?? item.note ?? "僅表示相關性"}</small></span>
                          <span className="control-item__action">查看同座標 findings <Icon name="arrow" size={13} /></span>
                          {item.mappingVersion && <code>mapping {item.mappingVersion}</code>}
                        </button>
                      );
                    })}
                  </div>
                )}
              </section>

              <section className="detail-section provenance-section">
                <h3>Finding provenance</h3>
                <dl>
                  <div><dt>Fingerprint</dt><dd><code>{selected.fingerprint}</code></dd></div>
                  <div><dt>Finding ID</dt><dd><code>{selected.id}</code></dd></div>
                  <div><dt>初見輪次</dt><dd><code>{selected.firstSeenRunId ?? "未回報"}</code></dd></div>
                  <div><dt>末見輪次</dt><dd><code>{selected.lastSeenRunId ?? "未回報"}</code></dd></div>
                  <div><dt>首次觀察</dt><dd>{formatDateTime(selected.firstSeenAt)}</dd></div>
                  <div><dt>最後觀察</dt><dd>{formatDateTime(selected.lastSeenAt)}</dd></div>
                </dl>
                {(selected.tags?.length ?? 0) > 0 && <div className="tag-row">{selected.tags?.map((tag) => <span className="tag tag--light" key={tag}>{tag}</span>)}</div>}
              </section>

              <section className="detail-section">
                <h3>官方參考</h3>
                {selected.officialReferences.length === 0 ? <p>沒有提供官方參考連結。</p> : selected.officialReferences.map((reference) => (
                  <a key={reference} href={reference} target="_blank" rel="noreferrer noopener">查看來源文件 <Icon name="external" size={14} /></a>
                ))}
              </section>
            </>
          ) : (
            <EmptyState icon="findings" title="選擇一項問題" description="完整證據、provenance、workflow 與控制項導航會顯示在這裡。" />
          )}
        </aside>
      </section>
    </div>
  );
}
