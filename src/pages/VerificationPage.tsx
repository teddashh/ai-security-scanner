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
  beforeTitle: { en: "See whether the fix worked", zhTW: "看看修復有沒有成功" },
  beforeDescription: {
    en: "Choose a scan from before the change. We will check again and show what disappeared, what remains, and what is new.",
    zhTW: "選擇修復前的掃描，我們會再次檢查，告訴你哪些消失了、哪些還在，以及有哪些新問題。",
  },
  resultTitle: { en: "See whether the fix worked", zhTW: "看看修復有沒有成功" },
  resultDescription: {
    en: "See what is fixed, what still needs work, and anything new since the earlier scan.",
    zhTW: "快速看出哪些已修好、哪些還要處理，以及和上次相比出現了哪些新問題。",
  },
  baselineEyebrow: { en: "COMPARISON STARTING POINT", zhTW: "比較起點" },
  baselineTitle: { en: "Choose the scan from before the fix", zhTW: "選擇修復前的掃描" },
  baselineDescription: {
    en: "Pick the earlier scan you want to compare with.",
    zhTW: "挑選一輪修復前的掃描來比較。",
  },
  baselineLabel: { en: "Earlier scan", zhTW: "修復前掃描" },
  baselineSelected: { en: "Selected run ID: {id}", zhTW: "已選輪次 ID：{id}" },
  baselinePrompt: { en: "Choose an earlier scan first.", zhTW: "請先選擇一輪過往掃描。" },
  comparisonDetails: { en: "How this comparison works", zhTW: "這次比較如何運作" },
  comparisonMechanics: {
    en: "The app saves the selected earlier run with the new scan, checks the same approved scope, and keeps both run IDs so the comparison can be rebuilt after a restart.",
    zhTW: "系統會把選定的舊掃描和新掃描一起保存，重新檢查相同的已授權範圍，並保留兩個輪次 ID，讓重新啟動後仍能重建比較。",
  },
  comparisonRunIds: { en: "Scan run IDs", zhTW: "掃描輪次 ID" },
  activeTitle: { en: "Another scan has not reached a final outcome", zhTW: "目前有另一輪掃描尚未結束" },
  activePaused: {
    en: "{run} is paused. Continue or cancel it on Scan progress before checking the fix.",
    zhTW: "{run} 目前已暫停。請先到掃描進度繼續或取消，再確認修復結果。",
  },
  activeRunning: {
    en: "{run} is still running. Finish or cancel it on Scan progress before checking the fix.",
    zhTW: "{run} 仍在掃描中。請先到掃描進度完成或取消，再確認修復結果。",
  },
  noBaselineTitle: { en: "Run your first scan to create a starting point", zhTW: "先完成第一次掃描，建立比較起點" },
  readyTitle: { en: "Ready to check the fix", zhTW: "已準備好確認修復" },
  noBaselineDescription: {
    en: "Complete at least one scan, then return here after making a change.",
    zhTW: "先完成至少一輪掃描；做完修復後，再回到這裡比較。",
  },
  selectedDescription: {
    en: "We will compare the new check with {run} from {date}.",
    zhTW: "新的檢查會和 {date} 的 {run} 比較。",
  },
  handleActiveFirst: { en: "Handle the unfinished scan first", zhTW: "先處理未完成的掃描" },
  start: { en: "Check the fix again", zhTW: "重新檢查修復結果" },
  preparing: { en: "Preparing…", zhTW: "準備中…" },
  rescan: { en: "Check the fix again", zhTW: "重新檢查修復結果" },
  baselineRun: { en: "Before-fix scan", zhTW: "修復前掃描" },
  comparisonRun: { en: "After-fix check", zhTW: "修復後複驗" },
  sameCase: { en: "Same scan project", zhTW: "同一掃描專案" },
  runProgress: { en: "{progress}% · {status}", zhTW: "{progress}% · {status}" },
  metricsAria: { en: "Four possible verification outcomes", zhTW: "四種複驗結果" },
  resolvedDetail: { en: "Not observed by the same check this time", zhTW: "相同檢查這次沒有再觀察到" },
  persistentDetail: { en: "The same problem is still observed", zhTW: "相同問題仍然存在" },
  newDetail: { en: "New scope or new evidence produced a finding", zhTW: "新範圍或新證據出現問題" },
  unverifiableDetail: { en: "Permission, scope, or scanner state prevented comparison", zhTW: "權限、範圍或工具狀態使它無法比較" },
  resolvedCautionTitle: { en: "Not observed does not mean permanently safe", zhTW: "這次沒看到，不代表永久安全" },
  resolvedCautionBody: {
    en: "A clean recheck is encouraging, but it covers only the checks that ran this time. Review the evidence before closing the work.",
    zhTW: "複驗沒有再看到問題是好消息，但只代表這次實際完成的檢查。關閉工作前，請再確認證據。",
  },
  incompleteTitle: { en: "This verification could not compare everything", zhTW: "這次複驗沒有辦法比較所有項目" },
  incompleteBody: {
    en: "Some checks did not finish or could not be matched. Those items stay under Could not verify and are not counted as fixed.",
    zhTW: "有些檢查沒有完成或無法配對；這些項目會保留在「無法確認」，不會算成已修復。",
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
    en: "Open any item to see what changed and the evidence behind the result.",
    zhTW: "打開任一項，就能查看哪裡改變，以及結果背後的證據。",
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
        {!selectedBaselineRun && <small>{text(copy.baselinePrompt)}</small>}
      </label>
      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(copy.comparisonDetails)}</summary>
        <p>{text(copy.comparisonMechanics)}</p>
        {selectedBaselineRun && (
          <dl><div><dt>{text(copy.baselineLabel)}</dt><dd><code>{selectedBaselineRun.id}</code></dd></div></dl>
        )}
      </details>
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
          {comparisonRun && (
            <StatusPill
              label={text(copy.runProgress, { progress: formatNumber(comparisonRun.progress), status: runStatusMeta[comparisonRun.status].label })}
              tone={comparisonRun.status === "completed" ? "positive" : "warning"}
            />
          )}
        </div>
      </section>

      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(copy.comparisonRunIds)}</summary>
        <p>{text(copy.comparisonMechanics)}</p>
        <dl>
          <div><dt>{text(copy.baselineRun)}</dt><dd><code>{verification.baselineRunId}</code></dd></div>
          <div><dt>{text(copy.comparisonRun)}</dt><dd><code>{verification.comparisonRunId}</code></dd></div>
        </dl>
      </details>

      <section className="metrics-grid metrics-grid--four" aria-label={text(copy.metricsAria)}>
        <MetricCard label={diffMeta.resolved.label} value={formatNumber(counts.resolved)} detail={text(copy.resolvedDetail)} icon="check" tone="accent" />
        <MetricCard label={diffMeta.persistent.label} value={formatNumber(counts.persistent)} detail={text(copy.persistentDetail)} icon="warning" tone={counts.persistent ? "danger" : "default"} />
        <MetricCard label={diffMeta.new.label} value={formatNumber(counts.new)} detail={text(copy.newDetail)} icon="plus" tone={counts.new ? "warning" : "default"} />
        <MetricCard label={diffMeta.unverifiable.label} value={formatNumber(counts.unverifiable)} detail={text(copy.unverifiableDetail)} icon="info" />
      </section>

      {counts.resolved > 0 && (
        <InlineNotice tone="info" title={text(copy.resolvedCautionTitle)}>
          <p>{text(copy.resolvedCautionBody)}</p>
        </InlineNotice>
      )}

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
