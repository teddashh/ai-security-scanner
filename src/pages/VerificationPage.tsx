import { useMemo, useState } from "react";

import { diffMeta, formatDateTime, severityMeta } from "../lib";
import type { DiffState, Finding, ScanRun, VerificationSummary } from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

interface VerificationPageProps {
  verification?: VerificationSummary;
  runs: ScanRun[];
  findings: Finding[];
  baselineRunId?: string;
  busy?: boolean;
  onSelectBaseline: (runId: string) => void;
  onStartRescan: (baselineRunId: string) => Promise<void>;
  onOpenFinding: (findingId: string) => void;
}

const states: DiffState[] = ["resolved", "persistent", "new", "unverifiable"];

export function VerificationPage({ verification, runs, findings, baselineRunId, busy, onSelectBaseline, onStartRescan, onOpenFinding }: VerificationPageProps) {
  const [filter, setFilter] = useState<DiffState | "all">("all");

  const counts = useMemo(
    () => Object.fromEntries(states.map((state) => [state, verification?.diffs.filter((item) => item.state === state).length ?? 0])) as Record<DiffState, number>,
    [verification],
  );

  const activeRun = runs.find((run) => run.status === "running" || run.status === "queued" || run.status === "paused");
  const terminalRuns = runs.filter((run) => ["completed", "partial", "failed", "cancelled"].includes(run.status));
  const selectedBaselineRun = terminalRuns.find((run) => run.id === baselineRunId);
  const baselinePicker = terminalRuns.length > 0 ? (
    <section className="section-block" aria-labelledby="verification-baseline-picker-title">
      <div className="section-heading">
        <p className="eyebrow">Durable baseline</p>
        <h2 id="verification-baseline-picker-title">本次複驗基準</h2>
        <p>選定的終態輪次會在 dispatch 前寫入新 ScanRun，完成或重啟後仍可自動建立同一組比較。</p>
      </div>
      <label className="field">
        <span>終態 baseline</span>
        <select value={baselineRunId ?? ""} onChange={(event) => onSelectBaseline(event.target.value)}>
          {terminalRuns.map((run) => (
            <option key={run.id} value={run.id}>
              {run.label} · {run.status} · {formatDateTime(run.finishedAt ?? run.startedAt)}
            </option>
          ))}
        </select>
        <small>{selectedBaselineRun ? `已選 ${selectedBaselineRun.id}` : "請先選擇一個終態輪次。"}</small>
      </label>
    </section>
  ) : undefined;

  if (!verification) {
    const canStart = Boolean(selectedBaselineRun) && !activeRun;
    return (
      <div className="page">
        <PageHeader
          eyebrow="Verification"
          title="修復後沿用同一案件複驗"
          description="複驗沿用同一案件，固定基準與本次輪次，顯示已消失、仍存在、新出現或無法驗證。"
        />
        {baselinePicker}
        {activeRun && (
          <InlineNotice tone="warning" title="目前有尚未終止的掃描輪次">
            <p>{activeRun.label} 是{activeRun.status === "paused" ? "暫停" : "進行中"}狀態。請先到掃描進度續跑或取消；複驗不會在旁邊偷偷建立另一個範圍。</p>
          </InlineNotice>
        )}
        <EmptyState
          icon="verification"
          title={terminalRuns.length === 0 ? "還沒有可用的基準輪次" : "已有基準，尚未建立比較"}
          description={!selectedBaselineRun
            ? "至少需要一個已到達明確終態的掃描輪次。失敗或部分完成可以當基準，但差異可能因此標示無法驗證。"
            : `選定基準是 ${selectedBaselineRun.label}（${formatDateTime(selectedBaselineRun.finishedAt ?? selectedBaselineRun.startedAt)}）。複驗會重新驗證原範圍，不會沿用舊 finding 當新證據。`}
          action={terminalRuns.length > 0
            ? <button className="button button--primary" type="button" disabled={busy || !canStart} onClick={() => selectedBaselineRun && void onStartRescan(selectedBaselineRun.id)}><Icon name="refresh" size={17} />{activeRun ? "先處理未終止輪次" : "開始複驗"}</button>
            : undefined}
        />
      </div>
    );
  }

  const filtered = filter === "all" ? verification.diffs : verification.diffs.filter((item) => item.state === filter);
  const baselineRun = runs.find((run) => run.id === verification.baselineRunId);
  const comparisonRun = runs.find((run) => run.id === verification.comparisonRunId);
  const comparisonIncomplete = verification.complete === false || Boolean(comparisonRun && comparisonRun.status !== "completed");
  const completenessIssues = verification.completenessIssues ?? [];
  const canRescan = !activeRun && Boolean(selectedBaselineRun);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Verification"
        title="修復前後差異"
        description="以相同案件與授權範圍重新執行。權限、範圍或工具狀態改變時，結果會標示無法驗證。"
        actions={
          <button className="button button--primary" type="button" disabled={busy || !canRescan} onClick={() => selectedBaselineRun && void onStartRescan(selectedBaselineRun.id)}>
            <Icon name="refresh" size={18} />
            {busy ? "準備中…" : activeRun ? "先處理未終止輪次" : "再次複驗"}
          </button>
        }
      />

      {baselinePicker}

      <section className="comparison-header">
        <div className="comparison-run">
          <span>基準掃描</span>
          <strong>{formatDateTime(verification.baselineAt)}</strong>
          <code>{verification.baselineRunId}</code>
          {baselineRun && <StatusPill label={`${baselineRun.progress}% · ${baselineRun.status}`} tone={baselineRun.status === "completed" ? "positive" : "warning"} />}
        </div>
        <div className="comparison-arrow"><Icon name="arrow" size={22} /><span>同案件比較</span></div>
        <div className="comparison-run comparison-run--current">
          <span>本次複驗</span>
          <strong>{formatDateTime(verification.comparisonAt)}</strong>
          <code>{verification.comparisonRunId}</code>
          {comparisonRun && <StatusPill label={`${comparisonRun.progress}% · ${comparisonRun.status}`} tone={comparisonRun.status === "completed" ? "positive" : "warning"} />}
        </div>
      </section>

      <section className="metrics-grid metrics-grid--four" aria-label="複驗差異四種狀態">
        <MetricCard label="已消失" value={counts.resolved} detail="本次未再觀察到" icon="check" tone="accent" />
        <MetricCard label="仍然存在" value={counts.persistent} detail="相同問題持續存在" icon="warning" tone={counts.persistent ? "danger" : "default"} />
        <MetricCard label="新出現" value={counts.new} detail="新範圍或新證據" icon="plus" tone={counts.new ? "warning" : "default"} />
        <MetricCard label="無法驗證" value={counts.unverifiable} detail="權限或工作狀態改變" icon="info" />
      </section>

      <InlineNotice tone="info" title="消失不等於永久安全">
        <p>「已消失」只表示相同檢查在本次未再觀察到。它不是修復品質保證，也不代表其他未知範圍已安全。</p>
      </InlineNotice>

      {comparisonIncomplete && (
        <InlineNotice tone="warning" title="本次複驗輪次或比較座標沒有完整完成">
          <p>差異只反映有可比證據的範圍。未完成引擎對應的項目應標示為「無法驗證」，不能歸類為已消失。</p>
          {completenessIssues.length > 0 && (
            <ul>
              {completenessIssues.slice(0, 6).map((issue, index) => (
                <li key={`${issue.code}-${issue.engineId ?? "run"}-${issue.assetId ?? "global"}-${index}`}>{issue.detail}</li>
              ))}
              {completenessIssues.length > 6 && <li>另有 {completenessIssues.length - 6} 個不可比座標；完整內容保存在案件與匯出包。</li>}
            </ul>
          )}
        </InlineNotice>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">Diff</p>
            <h2>複驗項目</h2>
            <p>問題證據改變但仍存在時，會留在「仍然存在」並另外標示證據已變動。</p>
          </div>
          <span className="count-label">{filtered.length}／{verification.diffs.length}</span>
        </div>

        <div className="segmented-filter" aria-label="篩選複驗狀態">
          <button type="button" className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>全部 <b>{verification.diffs.length}</b></button>
          {states.map((state) => (
            <button key={state} type="button" className={filter === state ? "active" : ""} onClick={() => setFilter(state)}>
              {diffMeta[state].label} <b>{counts[state]}</b>
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <EmptyState icon="verification" title="這個篩選沒有差異項目" description="切換其他差異狀態；空篩選不是沒有風險或已完成修復。" />
        ) : <div className="diff-list">
          {filtered.map((item) => {
            const meta = diffMeta[item.state];
            const severity = item.afterSeverity ?? item.beforeSeverity;
            return (
              <article key={item.id} className={`diff-row diff-row--${meta.tone}`}>
                <span className="diff-row__icon">
                  <Icon
                    name={item.state === "resolved" ? "check" : item.state === "new" ? "plus" : item.state === "persistent" ? "warning" : "info"}
                    size={19}
                  />
                </span>
                <div className="diff-row__copy">
                  <div className="diff-row__meta">
                    <StatusPill label={meta.label} tone={meta.tone} />
                    {severity && <StatusPill label={severityMeta[severity].label} tone={severityMeta[severity].tone} />}
                    {item.evidenceChanged && <span className="evidence-changed">證據已變動</span>}
                  </div>
                  <h3>{item.title}</h3>
                  <p>{item.explanation}</p>
                  <span>{item.assetName}</span>
                  {(item.beforeSeverity || item.afterSeverity) && (
                    <div className="diff-severity-change">
                      <span>基準：{item.beforeSeverity ? severityMeta[item.beforeSeverity].label : "未觀察"}</span>
                      <Icon name="arrow" size={13} />
                      <span>本次：{item.afterSeverity ? severityMeta[item.afterSeverity].label : item.state === "resolved" ? "未再觀察" : "未知"}</span>
                    </div>
                  )}
                  {item.findingId && findings.some((finding) => finding.id === item.findingId) ? (
                    <button className="button button--ghost button--small diff-row__action" type="button" onClick={() => onOpenFinding(item.findingId!)}>
                      查看 finding 證據 <Icon name="arrow" size={14} />
                    </button>
                  ) : item.findingId ? <small className="diff-row__baseline-note">這筆基準 finding 已不在目前清單；完整 provenance 保留於案件包。</small> : null}
                </div>
              </article>
            );
          })}
        </div>}
      </section>
    </div>
  );
}
