import { useMemo, useState } from "react";

import {
  confidenceMeta,
  formatDateTime,
  severityMeta,
  workflowMeta,
} from "../lib";
import type { Finding, Severity } from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

interface FindingsPageProps {
  findings: Finding[];
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function FindingsPage({ findings }: FindingsPageProps) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [selectedId, setSelectedId] = useState<string | undefined>(findings[0]?.id);

  const ordered = useMemo(
    () => [...findings].sort((a, b) => a.priority - b.priority),
    [findings],
  );
  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase("zh-Hant");
    return ordered.filter((finding) => {
      const matchesSeverity = severity === "all" || finding.severity === severity;
      const matchesQuery =
        !normalizedQuery ||
        `${finding.title} ${finding.assetName} ${finding.summary} ${finding.expertType}`
          .toLocaleLowerCase("zh-Hant")
          .includes(normalizedQuery);
      return matchesSeverity && matchesQuery;
    });
  }, [ordered, query, severity]);

  const selected = findings.find((finding) => finding.id === selectedId);
  const topFindings = ordered.slice(0, 3);
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const highCount = findings.filter((finding) => finding.severity === "high").length;
  const needsReview = findings.filter((finding) => finding.workflowState === "unconfirmed").length;
  const affectedAssets = new Set(findings.map((finding) => finding.assetId)).size;

  if (findings.length === 0) {
    return (
      <div className="page">
        <PageHeader
          eyebrow="Findings"
          title="問題清單"
          description="排序只決定首頁先看什麼，所有原始發現與證據都會完整保留。"
        />
        <EmptyState
          icon="findings"
          title="目前沒有 finding"
          description="這可能代表尚未掃描、資料來源未知，或掃描器沒有發現問題；請先查看涵蓋清冊，不能直接解讀為安全。"
        />
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow="Findings"
        title="先看最值得處理的事，完整結果一項不少"
        description="每項 finding 都連回資產、原始證據與來源版本。NIST／ISO 僅是相關控制項座標，不是合規判定。"
      />

      <section className="metrics-grid metrics-grid--four" aria-label="問題摘要">
        <MetricCard label="嚴重" value={criticalCount} detail="建議優先請專家確認" icon="warning" tone={criticalCount ? "danger" : "default"} />
        <MetricCard label="高風險" value={highCount} detail="依資產暴露與影響排序" icon="findings" tone={highCount ? "warning" : "default"} />
        <MetricCard label="待人工確認" value={needsReview} detail="掃描器判定不等於事實" icon="search" />
        <MetricCard label="受影響資產" value={affectedAssets} detail={`完整清單共 ${findings.length} 項`} icon="database" />
      </section>

      <section className="section-block priority-section">
        <div className="section-heading">
          <p className="eyebrow">現在先處理</p>
          <h2>優先摘要</h2>
          <p>根據嚴重度、資產暴露、資料敏感性與證據信心排序；這不是刪除或隱藏其他項目。</p>
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
              <span className="priority-card__number">0{index + 1}</span>
              <StatusPill label={severityMeta[finding.severity].label} tone={severityMeta[finding.severity].tone} />
              <h3>{finding.title}</h3>
              <p>{finding.impact}</p>
              <span className="priority-card__asset">{finding.assetName}</span>
              <span className="priority-card__action">查看證據 <Icon name="arrow" size={15} /></span>
            </button>
          ))}
        </div>
      </section>

      <InlineNotice tone="info" title="這不是稽核結論，也不是修復指令">
        <p>內容只說明掃描器觀察到什麼、可能影響什麼，以及建議找哪類專家複核。產品不會替你修改環境。</p>
      </InlineNotice>

      <section id="finding-browser" className="finding-browser">
        <div className="finding-browser__list">
          <div className="section-heading section-heading--row finding-toolbar-heading">
            <div>
              <p className="eyebrow">全部 findings</p>
              <h2>完整問題清單</h2>
            </div>
            <span className="count-label">{filtered.length}／{findings.length}</span>
          </div>

          <div className="filter-bar">
            <label className="search-field">
              <span className="sr-only">搜尋問題或資產</span>
              <Icon name="search" size={18} />
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="搜尋問題、資產或專家類型"
              />
            </label>
            <label className="select-filter">
              <Icon name="filter" size={17} />
              <span className="sr-only">嚴重度</span>
              <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | "all")}>
                <option value="all">所有嚴重度</option>
                {severityOrder.map((item) => <option key={item} value={item}>{severityMeta[item].label}</option>)}
              </select>
            </label>
          </div>

          <div className="finding-list" role="list">
            {filtered.length === 0 ? (
              <EmptyState icon="search" title="沒有符合的問題" description="清除搜尋字詞或切換嚴重度篩選。" />
            ) : filtered.map((finding) => (
              <button
                key={finding.id}
                type="button"
                role="listitem"
                className={selectedId === finding.id ? "finding-row finding-row--active" : "finding-row"}
                onClick={() => setSelectedId(finding.id)}
              >
                <span className="finding-row__priority">#{finding.priority}</span>
                <span className="finding-row__main">
                  <span className="finding-row__top">
                    <StatusPill label={severityMeta[finding.severity].label} tone={severityMeta[finding.severity].tone} />
                    <small>{confidenceMeta[finding.confidence]}</small>
                  </span>
                  <strong>{finding.title}</strong>
                  <span>{finding.assetName} · {finding.evidence.length} 份證據</span>
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
                </div>
                <h2>{selected.title}</h2>
                <p>{selected.summary}</p>
              </div>

              <dl className="detail-facts">
                <div><dt>資產</dt><dd>{selected.assetName}</dd></div>
                <div><dt>處理狀態</dt><dd>{workflowMeta[selected.workflowState]}</dd></div>
                <div><dt>建議尋找</dt><dd>{selected.expertType}</dd></div>
                <div><dt>最後觀察</dt><dd>{formatDateTime(selected.lastSeenAt)}</dd></div>
              </dl>

              <section className="detail-section">
                <h3>可能影響</h3>
                <p>{selected.impact}</p>
              </section>

              <section className="detail-section detail-section--advice">
                <h3>建議處理方向</h3>
                <p>{selected.recommendation}</p>
                <small>此建議不會自動執行，也不代表對修復結果背書。</small>
              </section>

              <section className="detail-section">
                <h3>掃描證據</h3>
                <div className="evidence-list">
                  {selected.evidence.map((evidence) => (
                    <article key={evidence.id} className="evidence-item">
                      <div><strong>{evidence.sourceEngine}</strong><span>{formatDateTime(evidence.observedAt)}</span></div>
                      <p>{evidence.summary}</p>
                      <code>{evidence.rawArtifactHash}</code>
                    </article>
                  ))}
                </div>
              </section>

              <section className="detail-section">
                <h3>相關控制項</h3>
                <div className="control-list">
                  {selected.controls.map((control) => (
                    <span key={`${control.framework}-${control.controlId}`}>
                      <b>{control.framework}</b>
                      {control.controlId}
                      <small>相關，不代表符合／不符合</small>
                    </span>
                  ))}
                </div>
              </section>

              <section className="detail-section">
                <h3>官方參考</h3>
                {selected.officialReferences.map((reference) => (
                  <a key={reference} href={reference} target="_blank" rel="noreferrer">
                    查看來源文件 <Icon name="external" size={14} />
                  </a>
                ))}
              </section>
            </>
          ) : (
            <EmptyState icon="findings" title="選擇一項問題" description="完整證據、控制項座標與建議會顯示在這裡。" />
          )}
        </aside>
      </section>
    </div>
  );
}
