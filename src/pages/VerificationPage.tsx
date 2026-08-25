import { useMemo, useState } from "react";

import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import { useI18n } from "../i18n";
import { diffMeta, runStatusMeta, severityMeta } from "../lib";
import type { DiffState, Finding, ScanRun, VerificationSummary } from "../types";
import "./page-technical-details.css";
import { displayTechnicalDetail } from "./pageTechnicalDetails";

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

const copy = {
  eyebrow: { en: "CHECK FIXES", zhTW: "確認修復" },
  beforeTitle: { en: "Check the same systems again after a fix", zhTW: "修復後，用相同範圍再檢查一次" },
  beforeDescription: {
    en: "Choose an earlier scan as the baseline. The app checks the original approved scope again and records what was not comparable.",
    zhTW: "先選一輪過往掃描當基準；系統會重新檢查原本已授權的範圍，並記錄哪些項目無法比較。",
  },
  resultTitle: { en: "What changed after the fix", zhTW: "查看修復前後有什麼變化" },
  resultDescription: {
    en: "The comparison uses the same case and approved scope. Permission, scope, or scanner changes are shown as could not verify—not as fixed.",
    zhTW: "比較會沿用同一案件與授權範圍。若權限、範圍或工具有變化，結果會標成「無法確認」，不會算成已修復。",
  },
  baselineEyebrow: { en: "COMPARISON STARTING POINT", zhTW: "比較起點" },
  baselineTitle: { en: "Choose the scan from before the fix", zhTW: "選擇修復前的掃描" },
  baselineDescription: {
    en: "The chosen final-outcome run is saved with the new scan before work starts, so the same comparison can be rebuilt after a restart.",
    zhTW: "開始前會把選定的最終狀態輪次寫進新掃描，因此重新啟動後仍能重建同一組比較。",
  },
  baselineLabel: { en: "Earlier scan", zhTW: "修復前掃描" },
  baselineSelected: { en: "Selected run ID: {id}", zhTW: "已選輪次 ID：{id}" },
  baselinePrompt: { en: "Choose a scan with a clear final outcome first.", zhTW: "請先選擇一輪已有明確最終結果的掃描。" },
  activeTitle: { en: "Another scan has not reached a final outcome", zhTW: "目前有另一輪掃描尚未結束" },
  activePaused: {
    en: "{run} is paused. Continue or cancel it on Scan progress first. Verification will not quietly start another scope beside it.",
    zhTW: "{run} 目前已暫停。請先到掃描進度繼續或取消；複驗不會在旁邊偷偷建立另一個範圍。",
  },
  activeRunning: {
    en: "{run} is still in progress. Finish or cancel it on Scan progress first. Verification will not quietly start another scope beside it.",
    zhTW: "{run} 仍在進行中。請先到掃描進度完成或取消；複驗不會在旁邊偷偷建立另一個範圍。",
  },
  noBaselineTitle: { en: "There is no earlier scan to compare yet", zhTW: "目前還沒有可比較的過往掃描" },
  readyTitle: { en: "The baseline is ready; no comparison has been run", zhTW: "基準已選好，尚未開始比較" },
  noBaselineDescription: {
    en: "At least one scan must have a clear final outcome. A failed or partial run can be selected, but some differences may correctly become could not verify.",
    zhTW: "至少需要一輪已有明確最終結果的掃描。失敗或部分完成也能當基準，但部分差異可能會正確標成「無法確認」。",
  },
  selectedDescription: {
    en: "The baseline is {run} ({date}). Verification runs the approved scope again; old findings are not reused as new evidence.",
    zhTW: "目前基準是 {run}（{date}）。複驗會重新執行已授權範圍，不會把舊問題當成新證據。",
  },
  handleActiveFirst: { en: "Handle the unfinished scan first", zhTW: "先處理未完成的掃描" },
  start: { en: "Start verification scan", zhTW: "開始複驗" },
  preparing: { en: "Preparing…", zhTW: "準備中…" },
  rescan: { en: "Check again", zhTW: "再次複驗" },
  baselineRun: { en: "Before-fix scan", zhTW: "修復前掃描" },
  comparisonRun: { en: "After-fix check", zhTW: "修復後複驗" },
  sameCase: { en: "Same case", zhTW: "同一案件" },
  runProgress: { en: "{progress}% · {status}", zhTW: "{progress}% · {status}" },
  metricsAria: { en: "Four possible verification outcomes", zhTW: "四種複驗結果" },
  resolvedDetail: { en: "Not observed by the same check this time", zhTW: "相同檢查這次沒有再觀察到" },
  persistentDetail: { en: "The same problem is still observed", zhTW: "相同問題仍然存在" },
  newDetail: { en: "New scope or new evidence produced a finding", zhTW: "新範圍或新證據出現問題" },
  unverifiableDetail: { en: "Permission, scope, or scanner state prevented comparison", zhTW: "權限、範圍或工具狀態使它無法比較" },
  resolvedCautionTitle: { en: "Not observed does not mean permanently safe", zhTW: "這次沒看到，不代表永久安全" },
  resolvedCautionBody: {
    en: "This outcome means only that the same check did not observe the problem this time. It does not guarantee the quality of the fix or say anything about unknown scope.",
    zhTW: "這只表示相同檢查這次沒有觀察到問題；不能保證修復品質，也不能代表其他未知範圍安全。",
  },
  incompleteTitle: { en: "This verification could not compare everything", zhTW: "這次複驗沒有辦法比較所有項目" },
  incompleteBody: {
    en: "Differences cover only coordinates with comparable evidence. Work tied to incomplete scanners must remain could not verify and must never be counted as no longer observed.",
    zhTW: "差異只涵蓋有可比證據的項目。未完成工具對應的項目必須保留為「無法確認」，不能算成這次沒看到。",
  },
  issueCount: { en: "{count} comparison issues were recorded.", zhTW: "已記錄 {count} 個無法比較的原因。" },
  technicalIssues: { en: "Technical comparison issues", zhTW: "無法比較的技術細節" },
  issueCode: { en: "Issue code", zhTW: "問題代碼" },
  scanner: { en: "Scanner", zhTW: "掃描工具" },
  asset: { en: "Asset", zhTW: "資產" },
  detail: { en: "Recorded detail", zhTW: "記錄內容" },
  notSpecified: { en: "Not specified", zhTW: "未指定" },
  diffEyebrow: { en: "COMPARISON RESULTS", zhTW: "比較結果" },
  diffTitle: { en: "Items checked again", zhTW: "再次檢查的項目" },
  diffDescription: {
    en: "If a problem remains but its evidence changed, it stays in Still present and the evidence change is called out separately.",
    zhTW: "如果問題仍存在但證據有變化，它仍會留在「仍然存在」，並另外標示證據已改變。",
  },
  count: { en: "{shown} of {total}", zhTW: "{shown}／{total}" },
  filterAria: { en: "Filter verification outcomes", zhTW: "篩選複驗結果" },
  all: { en: "All", zhTW: "全部" },
  emptyFilterTitle: { en: "No items match this filter", zhTW: "這個篩選沒有項目" },
  emptyFilterDescription: {
    en: "Try another outcome. An empty filter does not mean there is no risk or that every fix is complete.",
    zhTW: "請切換其他結果；空白篩選不代表沒有風險，也不代表所有修復都完成。",
  },
  evidenceChanged: { en: "Evidence changed", zhTW: "證據已改變" },
  technicalExplanation: { en: "Scanner comparison detail", zhTW: "掃描工具的比較細節" },
  before: { en: "Before: {severity}", zhTW: "修復前：{severity}" },
  after: { en: "After: {severity}", zhTW: "修復後：{severity}" },
  notObserved: { en: "Not observed", zhTW: "沒有觀察到" },
  notObservedAgain: { en: "Not observed this time", zhTW: "這次沒有再觀察到" },
  unknown: { en: "Unknown", zhTW: "未知" },
  openEvidence: { en: "Open finding evidence", zhTW: "查看問題證據" },
  baselineMissing: {
    en: "The baseline finding is no longer in the current list. Its complete technical history remains in the case package.",
    zhTW: "這筆基準問題已不在目前清單；完整技術歷史仍保留在案件包。",
  },
} as const;

const states: DiffState[] = ["resolved", "persistent", "new", "unverifiable"];

const stateSummaryCopy = {
  resolved: {
    en: "The same check did not observe this problem this time. Review the evidence before closing the work.",
    zhTW: "相同檢查這次沒有再觀察到這個問題；關閉工作前仍請確認證據。",
  },
  persistent: {
    en: "The same problem is still present. Review its latest evidence and continue the fix.",
    zhTW: "相同問題仍然存在；請查看最新證據並繼續修復。",
  },
  new: {
    en: "This problem appeared in the new scan. Review the evidence before deciding how to handle it.",
    zhTW: "這個問題出現在新的掃描中；請先查看證據，再決定如何處理。",
  },
  unverifiable: {
    en: "The app could not make a trustworthy comparison. Restore the missing scope, permission, or scanner work and try again.",
    zhTW: "系統無法做出可信的比較；請補回缺少的範圍、權限或掃描工作後再試一次。",
  },
} as const satisfies Record<DiffState, { en: string; zhTW: string }>;

export function VerificationPage({ verification, runs, findings, baselineRunId, busy, onSelectBaseline, onStartRescan, onOpenFinding }: VerificationPageProps) {
  const { text, formatDateTime, formatNumber } = useI18n();
  const [filter, setFilter] = useState<DiffState | "all">("all");

  const counts = useMemo(
    () => Object.fromEntries(states.map((state) => [state, verification?.diffs.filter((item) => item.state === state).length ?? 0])) as Record<DiffState, number>,
    [verification],
  );

  const activeRun = runs.find((run) => run.status === "running" || run.status === "queued" || run.status === "paused");
  const terminalRuns = runs.filter((run) => ["completed", "partial", "failed", "cancelled"].includes(run.status));
  const selectedBaselineRun = terminalRuns.find((run) => run.id === baselineRunId);
  const showRunDate = (run: ScanRun): string => formatDateTime(run.finishedAt ?? run.startedAt);
  const baselinePicker = terminalRuns.length > 0 ? (
    <section className="section-block" aria-labelledby="verification-baseline-picker-title">
      <div className="section-heading">
        <p className="eyebrow">{text(copy.baselineEyebrow)}</p>
        <h2 id="verification-baseline-picker-title">{text(copy.baselineTitle)}</h2>
        <p>{text(copy.baselineDescription)}</p>
      </div>
      <label className="field">
        <span>{text(copy.baselineLabel)}</span>
        <select value={baselineRunId ?? ""} onChange={(event) => onSelectBaseline(event.target.value)}>
          {terminalRuns.map((run) => (
            <option key={run.id} value={run.id}>
              {run.label} · {runStatusMeta[run.status].label} · {showRunDate(run)}
            </option>
          ))}
        </select>
        <small>{selectedBaselineRun ? text(copy.baselineSelected, { id: selectedBaselineRun.id }) : text(copy.baselinePrompt)}</small>
      </label>
    </section>
  ) : undefined;

  if (!verification) {
    const canStart = Boolean(selectedBaselineRun) && !activeRun;
    return (
      <div className="page">
        <PageHeader eyebrow={text(copy.eyebrow)} title={text(copy.beforeTitle)} description={text(copy.beforeDescription)} />
        {baselinePicker}
        {activeRun && (
          <InlineNotice tone="warning" title={text(copy.activeTitle)}>
            <p>{activeRun.status === "paused"
              ? text(copy.activePaused, { run: activeRun.label })
              : text(copy.activeRunning, { run: activeRun.label })}</p>
          </InlineNotice>
        )}
        <EmptyState
          icon="verification"
          title={terminalRuns.length === 0 ? text(copy.noBaselineTitle) : text(copy.readyTitle)}
          description={!selectedBaselineRun
            ? text(copy.noBaselineDescription)
            : text(copy.selectedDescription, { run: selectedBaselineRun.label, date: showRunDate(selectedBaselineRun) })}
          action={terminalRuns.length > 0 ? (
            <button className="button button--primary" type="button" disabled={busy || !canStart} onClick={() => selectedBaselineRun && void onStartRescan(selectedBaselineRun.id)}>
              <Icon name="refresh" size={17} />{activeRun ? text(copy.handleActiveFirst) : text(copy.start)}
            </button>
          ) : undefined}
        />
      </div>
    );
  }

  const filtered = filter === "all" ? verification.diffs : verification.diffs.filter((item) => item.state === filter);
  const baselineRun = runs.find((run) => run.id === verification.baselineRunId);
  const comparisonRun = runs.find((run) => run.id === verification.comparisonRunId);
  const comparisonIncomplete = verification.complete !== true
    || !baselineRun
    || !comparisonRun
    || comparisonRun.status !== "completed";
  const completenessIssues = verification.completenessIssues ?? [];
  const canRescan = !activeRun && Boolean(selectedBaselineRun);

  return (
    <div className="page">
      <PageHeader
        eyebrow={text(copy.eyebrow)}
        title={text(copy.resultTitle)}
        description={text(copy.resultDescription)}
        actions={(
          <button className="button button--primary" type="button" disabled={busy || !canRescan} onClick={() => selectedBaselineRun && void onStartRescan(selectedBaselineRun.id)}>
            <Icon name="refresh" size={18} />
            {busy ? text(copy.preparing) : activeRun ? text(copy.handleActiveFirst) : text(copy.rescan)}
          </button>
        )}
      />

      {baselinePicker}

      <section className="comparison-header">
        <div className="comparison-run">
          <span>{text(copy.baselineRun)}</span>
          <strong>{formatDateTime(verification.baselineAt)}</strong>
          <code>{verification.baselineRunId}</code>
          {baselineRun && (
            <StatusPill
              label={text(copy.runProgress, { progress: formatNumber(baselineRun.progress), status: runStatusMeta[baselineRun.status].label })}
              tone={baselineRun.status === "completed" ? "positive" : "warning"}
            />
          )}
        </div>
        <div className="comparison-arrow"><Icon name="arrow" size={22} /><span>{text(copy.sameCase)}</span></div>
        <div className="comparison-run comparison-run--current">
          <span>{text(copy.comparisonRun)}</span>
          <strong>{formatDateTime(verification.comparisonAt)}</strong>
          <code>{verification.comparisonRunId}</code>
          {comparisonRun && (
            <StatusPill
              label={text(copy.runProgress, { progress: formatNumber(comparisonRun.progress), status: runStatusMeta[comparisonRun.status].label })}
              tone={comparisonRun.status === "completed" ? "positive" : "warning"}
            />
          )}
        </div>
      </section>

      <section className="metrics-grid metrics-grid--four" aria-label={text(copy.metricsAria)}>
        <MetricCard label={diffMeta.resolved.label} value={formatNumber(counts.resolved)} detail={text(copy.resolvedDetail)} icon="check" tone="accent" />
        <MetricCard label={diffMeta.persistent.label} value={formatNumber(counts.persistent)} detail={text(copy.persistentDetail)} icon="warning" tone={counts.persistent ? "danger" : "default"} />
        <MetricCard label={diffMeta.new.label} value={formatNumber(counts.new)} detail={text(copy.newDetail)} icon="plus" tone={counts.new ? "warning" : "default"} />
        <MetricCard label={diffMeta.unverifiable.label} value={formatNumber(counts.unverifiable)} detail={text(copy.unverifiableDetail)} icon="info" />
      </section>

      <InlineNotice tone="info" title={text(copy.resolvedCautionTitle)}>
        <p>{text(copy.resolvedCautionBody)}</p>
      </InlineNotice>

      {comparisonIncomplete && (
        <InlineNotice tone="warning" title={text(copy.incompleteTitle)}>
          <p>{text(copy.incompleteBody)}</p>
          {completenessIssues.length > 0 && (
            <>
              <p>{text(copy.issueCount, { count: formatNumber(completenessIssues.length) })}</p>
              <details className="page-technical-details">
                <summary>{text(copy.technicalIssues)}</summary>
                <dl>
                  {completenessIssues.map((issue, index) => (
                    <div key={`${issue.code}-${issue.engineId ?? "run"}-${issue.assetId ?? "global"}-${index}`}>
                      <dt>{text(copy.issueCode)}</dt><dd><code>{issue.code}</code></dd>
                      <dt>{text(copy.scanner)}</dt><dd><code>{issue.engineId ?? text(copy.notSpecified)}</code></dd>
                      <dt>{text(copy.asset)}</dt><dd><code>{issue.assetId ?? text(copy.notSpecified)}</code></dd>
                      <dt>{text(copy.detail)}</dt><dd>{displayTechnicalDetail(issue.detail) ?? text(copy.notSpecified)}</dd>
                    </div>
                  ))}
                </dl>
              </details>
            </>
          )}
        </InlineNotice>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">{text(copy.diffEyebrow)}</p>
            <h2>{text(copy.diffTitle)}</h2>
            <p>{text(copy.diffDescription)}</p>
          </div>
          <span className="count-label">{text(copy.count, { shown: formatNumber(filtered.length), total: formatNumber(verification.diffs.length) })}</span>
        </div>

        <div className="segmented-filter" aria-label={text(copy.filterAria)}>
          <button type="button" className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>
            {text(copy.all)} <b>{formatNumber(verification.diffs.length)}</b>
          </button>
          {states.map((state) => (
            <button key={state} type="button" className={filter === state ? "active" : ""} onClick={() => setFilter(state)}>
              {diffMeta[state].label} <b>{formatNumber(counts[state])}</b>
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <EmptyState icon="verification" title={text(copy.emptyFilterTitle)} description={text(copy.emptyFilterDescription)} />
        ) : (
          <div className="diff-list">
            {filtered.map((item) => {
              const meta = diffMeta[item.state];
              const severity = item.afterSeverity ?? item.beforeSeverity;
              const findingId = item.findingId;
              const findingAvailable = Boolean(findingId && findings.some((finding) => finding.id === findingId));
              return (
                <article key={item.id} className={`diff-row diff-row--${meta.tone}`}>
                  <span className="diff-row__icon">
                    <Icon name={item.state === "resolved" ? "check" : item.state === "new" ? "plus" : item.state === "persistent" ? "warning" : "info"} size={19} />
                  </span>
                  <div className="diff-row__copy">
                    <div className="diff-row__meta">
                      <StatusPill label={meta.label} tone={meta.tone} />
                      {severity && <StatusPill label={severityMeta[severity].label} tone={severityMeta[severity].tone} />}
                      {item.evidenceChanged && <span className="evidence-changed">{text(copy.evidenceChanged)}</span>}
                    </div>
                    <h3>{item.title}</h3>
                    <p>{text(stateSummaryCopy[item.state])}</p>
                    <span>{item.assetName}</span>
                    {(item.beforeSeverity || item.afterSeverity) && (
                      <div className="diff-severity-change">
                        <span>{text(copy.before, { severity: item.beforeSeverity ? severityMeta[item.beforeSeverity].label : text(copy.notObserved) })}</span>
                        <Icon name="arrow" size={13} />
                        <span>{text(copy.after, {
                          severity: item.afterSeverity
                            ? severityMeta[item.afterSeverity].label
                            : item.state === "resolved" ? text(copy.notObservedAgain) : text(copy.unknown),
                        })}</span>
                      </div>
                    )}
                    {findingId && findingAvailable ? (
                      <button className="button button--ghost button--small diff-row__action" type="button" onClick={() => onOpenFinding(findingId)}>
                        {text(copy.openEvidence)} <Icon name="arrow" size={14} />
                      </button>
                    ) : findingId ? <small className="diff-row__baseline-note">{text(copy.baselineMissing)}</small> : null}
                    {item.explanation && (
                      <details className="page-technical-details">
                        <summary>{text(copy.technicalExplanation)}</summary>
                        <p>{displayTechnicalDetail(item.explanation) ?? text(copy.notSpecified)}</p>
                      </details>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
