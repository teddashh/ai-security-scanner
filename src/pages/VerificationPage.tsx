import { useMemo, useState } from "react";

import { diffMeta, formatDateTime, severityMeta } from "../lib";
import type { DiffState, VerificationSummary } from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

interface VerificationPageProps {
  verification?: VerificationSummary;
  busy?: boolean;
  onStartRescan: () => Promise<void>;
}

const states: DiffState[] = ["resolved", "persistent", "new", "unverifiable"];

export function VerificationPage({ verification, busy, onStartRescan }: VerificationPageProps) {
  const [filter, setFilter] = useState<DiffState | "all">("all");

  const counts = useMemo(
    () => Object.fromEntries(states.map((state) => [state, verification?.diffs.filter((item) => item.state === state).length ?? 0])) as Record<DiffState, number>,
    [verification],
  );

  if (!verification) {
    return (
      <div className="page">
        <PageHeader
          eyebrow="Verification"
          title="修復後沿用同一案件複驗"
          description="第二次掃描不是新的算命；它會保留原範圍與基準，顯示問題消失、仍存在、新出現或無法驗證。"
        />
        <EmptyState
          icon="verification"
          title="還沒有可比較的複驗"
          description="需要至少一個基準掃描。完成修復後，以同一案件與範圍啟動複驗。"
          action={<button className="button button--primary" type="button" disabled={busy} onClick={() => void onStartRescan()}><Icon name="refresh" size={17} />開始複驗</button>}
        />
      </div>
    );
  }

  const filtered = filter === "all" ? verification.diffs : verification.diffs.filter((item) => item.state === filter);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Verification"
        title="修復前後差異"
        description="以相同案件與授權範圍重新執行。權限、範圍或工具狀態改變時，結果會標示無法驗證。"
        actions={
          <button className="button button--primary" type="button" disabled={busy} onClick={() => void onStartRescan()}>
            <Icon name="refresh" size={18} />
            {busy ? "準備中…" : "再次複驗"}
          </button>
        }
      />

      <section className="comparison-header">
        <div className="comparison-run">
          <span>基準掃描</span>
          <strong>{formatDateTime(verification.baselineAt)}</strong>
          <code>{verification.baselineRunId}</code>
        </div>
        <div className="comparison-arrow"><Icon name="arrow" size={22} /><span>同案件比較</span></div>
        <div className="comparison-run comparison-run--current">
          <span>本次複驗</span>
          <strong>{formatDateTime(verification.comparisonAt)}</strong>
          <code>{verification.comparisonRunId}</code>
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

        <div className="diff-list">
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
                </div>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}
