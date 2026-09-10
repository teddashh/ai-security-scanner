import { useMemo, useState } from "react";

import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import { useI18n } from "../i18n";
import { diffMeta, runStatusMeta, severityMeta } from "../lib";
import { scanRunIdentityPresentation } from "../scanRunIdentityPresentation";
import type { DiffState, Finding, ScanRun, VerificationSummary } from "../types";
import {
  affectedEngineCount,
  isOnlyMappingVersionDrift,
  verificationDiffExplanation,
} from "../verificationPresentation.ts";
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
    en: "Choose a scan from before the change. The recheck shows what disappeared, what remains, and what is new.",
    zhTW: "選擇修復前的掃描；複驗會顯示哪些問題已消失、仍存在或是新出現。",
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
  readyTitle: { en: "Ready to prepare the follow-up check", zhTW: "可以準備後續檢查" },
  noBaselineDescription: {
    en: "Complete at least one scan, then return here after making a change.",
    zhTW: "先完成至少一輪掃描；做完修復後，再回到這裡比較。",
  },
  selectedDescription: {
    en: "Scanner readiness is checked first, then the new result is compared with {run} from {date}.",
    zhTW: "先確認掃描工具，再把新的檢查與 {date} 的 {run} 比較。",
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
  unverifiableDetail: {
    en: "A comparison input changed or a scanner/target check was incomplete",
    zhTW: "比較條件有變更，或某個掃描工具／目標檢查未完成",
  },
  mappingUnverifiableDetail: {
    en: "Control mapping changed; finding classification incomplete",
    zhTW: "控制對照已變更；問題分類未完成",
  },
  resolvedCautionTitle: { en: "No longer observed in this recheck", zhTW: "本次複驗未再觀察到" },
  resolvedCautionBody: {
    en: "The same completed check no longer found this problem. Review the new evidence, then close it.",
    zhTW: "相同檢查已完成，且沒有再找到這個問題；查看新證據後即可關閉。",
  },
  incompleteTitle: { en: "Verification comparison incomplete", zhTW: "複驗比對未完成" },
  incompleteBody: {
    en: "Some scanner/target comparisons were incomplete or used different comparison inputs. Affected findings stay under Verification incomplete and are not counted as fixed.",
    zhTW: "部分掃描工具／目標的比較未完成，或使用了不同的比較條件；受影響的問題會保留在「驗證未完成」，不會算成已修復。",
  },
  issueCount: {
    en: "Scanner/target comparisons needing attention: {count}",
    zhTW: "需要處理的掃描工具／目標比較：{count}",
  },
  mappingTitle: { en: "Scanner mappings changed between these scans", zhTW: "兩次掃描使用的對照映射版本不同" },
  mappingBody: {
    en: "Affected checks completed in both scans with different control-mapping catalog versions. Comparison classification is unavailable for these findings.",
    zhTW: "受影響的檢查在兩次掃描中都已完成，但控制對照目錄版本不同；這些問題目前沒有比較分類。",
  },
  mappingEngineCount: {
    en: "Affected scan tools: {count}",
    zhTW: "受影響的掃描工具：{count}",
  },
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
    en: "Choose another outcome to see its items.",
    zhTW: "請選擇其他結果查看項目。",
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
    en: "The same completed check no longer found this problem. Review the new evidence, then close it.",
    zhTW: "相同檢查已完成，且沒有再找到這個問題；查看新證據後即可關閉。",
  },
  persistent: {
    en: "The same problem is still present. Continue its recommended fix, then check again.",
    zhTW: "相同問題仍然存在；請繼續執行建議修復，完成後再次檢查。",
  },
  new: {
    en: "The new scan found this problem. Open its evidence and follow the next action.",
    zhTW: "新的掃描找到這個問題；請開啟證據並執行下一步。",
  },
  unverifiable: {
    en: "Comparison is unavailable for this item. Open the recorded reason and complete its next action.",
    zhTW: "這個項目目前無法比較；請開啟記錄原因並完成下一步。",
  },
} as const satisfies Record<DiffState, { en: string; zhTW: string }>;

const mappingDiffSummary = {
  en: "This check completed in both scans with different control-mapping catalog versions. Comparison classification is unavailable for this finding.",
  zhTW: "這項檢查在兩次掃描中都已完成，但控制對照目錄版本不同；這個問題目前沒有比較分類。",
} as const;

export function VerificationPage({ verification, runs, findings, baselineRunId, busy, onSelectBaseline, onStartRescan, onOpenFinding }: VerificationPageProps) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
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
              {scanRunIdentityPresentation(run, locale)} · {runStatusMeta[run.status].label} · {showRunDate(run)}
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
              ? text(copy.activePaused, { run: scanRunIdentityPresentation(activeRun, locale) })
              : text(copy.activeRunning, { run: scanRunIdentityPresentation(activeRun, locale) })}</p>
          </InlineNotice>
        )}
        <EmptyState
          icon="verification"
          title={terminalRuns.length === 0 ? text(copy.noBaselineTitle) : text(copy.readyTitle)}
          description={!selectedBaselineRun
            ? text(copy.noBaselineDescription)
            : text(copy.selectedDescription, {
              run: scanRunIdentityPresentation(selectedBaselineRun, locale),
              date: showRunDate(selectedBaselineRun),
            })}
          action={terminalRuns.length > 0 ? (
            <button className="button button--primary" type="button" disabled={busy || !canStart} onClick={() => selectedBaselineRun && void onStartRescan(selectedBaselineRun.id)}>
              <Icon name="refresh" size={17} />{busy ? text(copy.preparing) : activeRun ? text(copy.handleActiveFirst) : text(copy.start)}
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
  const mappingVersionDriftOnly = isOnlyMappingVersionDrift(completenessIssues);
  const mappingAffectedEngineCount = affectedEngineCount(completenessIssues);
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
        <MetricCard
          label={diffMeta.unverifiable.label}
          value={formatNumber(counts.unverifiable)}
          detail={text(mappingVersionDriftOnly ? copy.mappingUnverifiableDetail : copy.unverifiableDetail)}
          icon="info"
        />
      </section>

      {counts.resolved > 0 && (
        <InlineNotice tone="info" title={text(copy.resolvedCautionTitle)}>
          <p>{text(copy.resolvedCautionBody)}</p>
        </InlineNotice>
      )}

      {comparisonIncomplete && (
        <InlineNotice tone="warning" title={text(mappingVersionDriftOnly ? copy.mappingTitle : copy.incompleteTitle)}>
          <p>{text(mappingVersionDriftOnly ? copy.mappingBody : copy.incompleteBody)}</p>
          {completenessIssues.length > 0 && (
            <>
              <p>{text(
                mappingVersionDriftOnly && mappingAffectedEngineCount > 0 ? copy.mappingEngineCount : copy.issueCount,
                { count: formatNumber(mappingVersionDriftOnly && mappingAffectedEngineCount > 0 ? mappingAffectedEngineCount : completenessIssues.length) },
              )}</p>
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
              const mappingVersionDriftOnlyForFinding = item.state === "unverifiable"
                && isOnlyMappingVersionDrift(item.changeReasons ?? []);
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
                    <p>{text(mappingVersionDriftOnlyForFinding ? mappingDiffSummary : stateSummaryCopy[item.state])}</p>
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
                        <p>{displayTechnicalDetail(verificationDiffExplanation(locale, item)) ?? text(copy.notSpecified)}</p>
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
