import { useEffect, useMemo, useState } from "react";

import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader, ProgressBar } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import { useI18n } from "../i18n";
import { engineStatusMeta, executionStageMeta, runStatusMeta } from "../lib";
import type { EngineRun, EngineRunStatus, ExecutionStage, ScanRun } from "../types";
import "./page-technical-details.css";
import { displayTechnicalDetail } from "./pageTechnicalDetails";

interface ProgressPageProps {
  runs: ScanRun[];
  busy?: boolean;
  onStart: () => Promise<void>;
  onPause: (runId: string) => Promise<void>;
  onResume: (runId: string) => Promise<void>;
  onCancel: (runId: string) => Promise<void>;
}

const copy = {
  eyebrow: { en: "LIVE SCAN", zhTW: "即時掃描" },
  title: { en: "Follow your scan", zhTW: "掌握掃描進度" },
  description: {
    en: "See what is running, what has finished, and anything that needs your attention—all in one place.",
    zhTW: "哪些正在檢查、哪些已經完成、哪裡需要你處理，一個畫面就看懂。",
  },
  emptyTitle: { en: "This case has not been scanned yet", zhTW: "這個案件還沒有開始掃描" },
  emptyDescription: {
    en: "When you are ready, start the scan and follow every check here as results arrive.",
    zhTW: "準備好後就開始掃描；每項檢查與新結果都會顯示在這裡。",
  },
  start: { en: "Start scan", zhTW: "開始掃描" },
  pause: { en: "Pause", zhTW: "暫停" },
  resume: { en: "Continue unfinished work", zhTW: "繼續未完成的工作" },
  cancel: { en: "Cancel this run", zhTW: "取消這一輪" },
  pauseAria: { en: "Pause scan run {id}", zhTW: "暫停掃描輪次 {id}" },
  resumeAria: { en: "Resume scan run {id}", zhTW: "續跑掃描輪次 {id}" },
  cancelAria: { en: "Cancel scan run {id}", zhTW: "取消掃描輪次 {id}" },
  chooseRun: { en: "Choose a scan run", zhTW: "選擇掃描輪次" },
  viewRun: { en: "View run", zhTW: "查看輪次" },
  latest: { en: "Latest · ", zhTW: "最新 · " },
  interruptedTitle: {
    en: "Your scan paused when the app closed",
    zhTW: "應用程式關閉時，掃描已暫停",
  },
  interruptedBody: {
    en: "{count} checks are waiting. Continue where you left off, or cancel this scan and keep the results already saved.",
    zhTW: "有 {count} 項檢查正在等待。你可以從中斷處繼續，或取消這次掃描並保留已存下的結果。",
  },
  resumeOriginal: { en: "Continue the original scope", zhTW: "繼續原本的範圍" },
  cancelKeepRecord: { en: "Cancel and keep the record", zhTW: "取消並保留紀錄" },
  expiredTitle: { en: "Update needed before checking fixes again", zhTW: "再次確認修復前，需要先更新" },
  expiredBody: {
    en: "{count} checks need newer security knowledge. Your existing results stay available; update the scan tools before running a new comparison.",
    zhTW: "有 {count} 項檢查需要更新資安知識。現有結果仍可查看；執行新的前後比較前，請先更新掃描工具。",
  },
  runIdTitle: { en: "Local scan run ID", zhTW: "本機掃描輪次 ID" },
  processed: { en: "{percent}% processed", zhTW: "已處理 {percent}%" },
  runSummary: {
    en: "{covered} of {total} checks have reported a result · Started {started}",
    zhTW: "{covered}／{total} 項檢查已有結果 · 開始於 {started}",
  },
  finished: { en: " · Ended {finished}", zhTW: " · 結束於 {finished}" },
  overallProgress: { en: "Overall scan progress", zhTW: "整體掃描進度" },
  scanTechnicalDetails: { en: "Scan details and versions", zhTW: "掃描細節與版本" },
  knowledgeTitle: { en: "Knowledge dates used for this run", zhTW: "這一輪採用的知識日期" },
  legacyKnowledge: { en: "Not recorded per scanner in this older case", zhTW: "舊版案件未逐一記錄" },
  caseSnapshot: { en: "Case snapshot {date}", zhTW: "案件快照 {date}" },
  supportUntil: { en: " · Earliest supported through {date}", zhTW: " · 最早支援至 {date}" },
  legacySupport: { en: " · Support date not recorded in this older case", zhTW: " · 舊版案件未記錄支援日期" },
  noGuarantee: { en: ". This is not an ongoing guarantee of safety.", zhTW: "。這不是持續安全保證。" },
  metricsAria: { en: "Scan outcome summary", zhTW: "掃描結果摘要" },
  completed: { en: "Completed", zhTW: "已完成" },
  completedDetail: { en: "Results are ready to review", zhTW: "結果已準備好，可以查看" },
  partial: { en: "Needs attention", zhTW: "需要處理" },
  partialDetail: { en: "Some results arrived, but a check did not finish", zhTW: "已有部分結果，但仍有檢查尚未完成" },
  failedCancelled: { en: "Stopped", zhTW: "已停止" },
  failedCancelledDetail: { en: "A check stopped early or was cancelled", zhTW: "有檢查提早停止或已被取消" },
  notRun: { en: "Not run", zhTW: "未執行" },
  notRunDetail: { en: "Finish setup before running these checks", zhTW: "完成設定後，才能執行這些檢查" },
  notRunTechnical: { en: "A check that did not run is not a passed check.", zhTW: "未執行的檢查不能視為已通過。" },
  ledgerAria: { en: "Counts for every scanner state", zhTW: "所有掃描工具狀態數量" },
  scannerStates: { en: "Scanner states", zhTW: "掃描工具狀態" },
  terminalCount: { en: "{done} of {total} have a clear final outcome", zhTW: "{done}／{total} 個已有明確最終結果" },
  incompleteTitle: { en: "This run did not cover everything", zhTW: "這一輪沒有完整涵蓋" },
  incompleteBody: {
    en: "Some checks did not finish. You can still review the results that arrived, then open a check below to see what needs attention.",
    zhTW: "有些檢查沒有完成。你仍可先查看已收到的結果，再打開下方檢查項目，看看需要處理什麼。",
  },
  workEyebrow: { en: "CHECKS", zhTW: "檢查項目" },
  workTitle: { en: "See every check", zhTW: "查看每一項檢查" },
  workDescription: {
    en: "Each check shows its result, current step, and whether you need to do anything next.",
    zhTW: "每項檢查都會顯示結果、目前進度，以及是否需要你接著處理。",
  },
  workCount: { en: "{count} checks", zhTW: "{count} 項檢查" },
  noWorkTitle: { en: "No checks are ready yet", zhTW: "目前還沒有可執行的檢查" },
  noWorkDescription: {
    en: "Return to scan setup and choose what you want to check. No checks means there are no results yet.",
    zhTW: "請回到掃描設定，選擇想檢查的內容；目前沒有檢查，因此也還沒有結果。",
  },
  notStarted: { en: "This check did not start", zhTW: "這項檢查沒有開始" },
  notStartedReason: {
    en: "Open details to see what stopped it and what to try next.",
    zhTW: "打開詳細資料，查看停止原因與可嘗試的下一步。",
  },
  checkLabel: { en: "Check {number}", zhTW: "檢查 {number}" },
  checkProgress: { en: "Check progress", zhTW: "檢查進度" },
  currentStep: { en: "Current step: ", zhTW: "目前步驟：" },
  interruptedPhase: { en: "Stopped when the desktop app restarted", zhTW: "桌面程式重新啟動時中斷" },
  queuedResumePhase: { en: "Waiting to continue", zhTW: "等待繼續執行" },
  unknownPhase: { en: "Scanner-reported step", zhTW: "掃描工具回報的步驟" },
  checkpoint: { en: "Saved restart point", zhTW: "已保存的接續點" },
  attempt: { en: "Attempt", zhTW: "嘗試次數" },
  evidence: { en: "Evidence", zhTW: "證據" },
  evidenceCount: { en: "{count} files", zhTW: "{count} 份" },
  scopeLock: { en: "Scope lock", zhTW: "範圍固定" },
  scopeLocked: { en: "Locked", zhTW: "已固定" },
  scopeNotCreated: { en: "Not created", zhTW: "尚未建立" },
  cleanup: { en: "Cleanup", zhTW: "環境清理" },
  cleanupDone: { en: "Done", zhTW: "完成" },
  cleanupPending: { en: "Still needed", zhTW: "仍待處理" },
  legacyFindingUnknown: { en: "Problem count unavailable", zhTW: "目前無法取得問題數量" },
  findingCount: { en: "{count} findings", zhTW: "{count} 個問題" },
  targets: { en: "Targets", zhTW: "目標數" },
  rawEvidenceFiles: { en: "Raw evidence files", zhTW: "原始證據檔案" },
  resumable: { en: "Can continue where it stopped", zhTW: "可從中斷處繼續" },
  technicalDetails: { en: "Technical status and errors", zhTW: "技術狀態與錯誤" },
  scannerName: { en: "Scanner name", zhTW: "掃描工具名稱" },
  reportedPhase: { en: "Reported phase", zhTW: "回報階段" },
  errorCode: { en: "Error code", zhTW: "錯誤代碼" },
  scannerMessage: { en: "Scanner message", zhTW: "掃描工具訊息" },
  checkpointError: { en: "Last checkpoint error", zhTW: "接續點最後錯誤" },
  noneReported: { en: "None reported", zhTW: "沒有回報" },
  provenance: { en: "Versions and technical execution record", zhTW: "版本與技術執行紀錄" },
  jobId: { en: "Scanner job ID", zhTW: "掃描工作 ID" },
  engineId: { en: "Scanner ID", zhTW: "掃描工具 ID" },
  categoryCode: { en: "Category code", zhTW: "類別代碼" },
  scannerVersion: { en: "Scanner version", zhTW: "掃描工具版本" },
  imageDigest: { en: "Image digest", zhTW: "映像摘要" },
  ruleVersion: { en: "Rule version", zhTW: "規則版本" },
  adapter: { en: "Result adapter", zhTW: "結果轉換器" },
  manifestSchema: { en: "Manifest schema", zhTW: "內容清單格式版本" },
  sourceRevision: { en: "Source revision", zhTW: "來源版本" },
  sourceRepository: { en: "Source repository", zhTW: "原始程式碼儲存庫" },
  distributionMode: { en: "Distribution mode", zhTW: "發佈模式" },
  imageRepository: { en: "Image repository", zhTW: "映像儲存庫" },
  commandDigest: { en: "Command digest", zhTW: "命令摘要" },
  knowledgeInput: { en: "Knowledge input", zhTW: "知識輸入" },
  noIndependentVersion: { en: "no separate version", zhTW: "沒有獨立版本" },
  knowledgeDate: { en: "Knowledge date", zhTW: "知識日期" },
  olderNotRecorded: { en: "Not recorded in this older case", zhTW: "舊版案件未記錄" },
  supportDate: { en: "Support date", zhTW: "支援日期" },
  expiredReadable: { en: "past support date; history remains readable", zhTW: "已超過支援日期；歷史仍可閱讀" },
  currentlySupported: { en: "within stated support date", zhTW: "仍在宣告支援日期內" },
  runtime: { en: "Runtime", zhTW: "執行環境" },
  unknownVersion: { en: "version not reported", zhTW: "版本未回報" },
  notRunYet: { en: "Not run", zhTW: "尚未執行" },
  runtimeSecurity: { en: "Runtime security options", zhTW: "執行環境安全選項" },
  exitCode: { en: "Exit code", zhTW: "結束代碼" },
  cleanupResult: { en: "Cleanup result", zhTW: "清理結果" },
  removed: { en: "Removed", zhTW: "已移除" },
  absentOrUnneeded: { en: "Already absent or did not need removal", zhTW: "已不存在或不需要移除" },
  started: { en: "Started", zhTW: "開始" },
  ended: { en: "Ended", zhTW: "結束" },
  warnings: { en: "Technical warnings", zhTW: "技術警告" },
  historyEyebrow: { en: "SCAN HISTORY", zhTW: "掃描紀錄" },
  historyTitle: { en: "Earlier scans", zhTW: "過往掃描" },
  historySnapshot: { en: "Case snapshot {date}", zhTW: "案件快照 {date}" },
} as const;

const engineStates: EngineRunStatus[] = [
  "pending",
  "running",
  "paused",
  "completed",
  "partial",
  "failed",
  "not_executed",
  "cancelled",
];

const terminalEngineStates: EngineRunStatus[] = ["completed", "partial", "failed", "not_executed", "cancelled"];

const isExecutionStage = (phase: string): phase is ExecutionStage =>
  Object.prototype.hasOwnProperty.call(executionStageMeta, phase);

const engineIcon = (engine: EngineRun) => {
  if (engine.status === "completed") return "check" as const;
  if (engine.status === "running") return "refresh" as const;
  if (engine.status === "paused") return "pause" as const;
  if (engine.status === "failed" || engine.status === "partial") return "warning" as const;
  if (engine.status === "cancelled") return "stop" as const;
  return "settings" as const;
};

export function ProgressPage({ runs, busy, onStart, onPause, onResume, onCancel }: ProgressPageProps) {
  const { locale, text, formatDate, formatDateTime, formatNumber } = useI18n();
  const [selectedRunId, setSelectedRunId] = useState(runs[0]?.id);

  useEffect(() => {
    if (!runs.some((run) => run.id === selectedRunId)) setSelectedRunId(runs[0]?.id);
  }, [runs, selectedRunId]);

  const selectedRun = runs.find((run) => run.id === selectedRunId) ?? runs[0];
  const stateCounts = useMemo(
    () => Object.fromEntries(
      engineStates.map((state) => [state, selectedRun?.engineRuns.filter((engine) => engine.status === state).length ?? 0]),
    ) as Record<EngineRunStatus, number>,
    [selectedRun],
  );
  const showDateTime = (value?: string): string => value ? formatDateTime(value) : text(copy.noneReported);
  const showPlainDate = (value: string): string => formatDate(`${value}T12:00:00`);
  const phaseLabel = (engine: EngineRun): string => {
    if (engine.phase === "interrupted_restart") return text(copy.interruptedPhase);
    if (engine.phase === "queued_for_resume") return text(copy.queuedResumePhase);
    if (isExecutionStage(engine.phase)) return executionStageMeta[engine.phase].label;
    return text(copy.unknownPhase);
  };

  if (!selectedRun) {
    return (
      <div className="page">
        <PageHeader eyebrow={text(copy.eyebrow)} title={text(copy.title)} description={text(copy.description)} />
        <EmptyState
          icon="progress"
          title={text(copy.emptyTitle)}
          description={text(copy.emptyDescription)}
          action={(
            <button className="button button--primary" type="button" disabled={busy} onClick={() => void onStart()}>
              <Icon name="play" size={17} />{text(copy.start)}
            </button>
          )}
        />
      </div>
    );
  }

  const runMeta = runStatusMeta[selectedRun.status];
  const canPause = selectedRun.status === "running";
  const hasResumableEngine = selectedRun.engineRuns.some((engine) => engine.resumable);
  const canResume = selectedRun.status === "paused"
    || ((selectedRun.status === "partial" || selectedRun.status === "failed" || selectedRun.status === "cancelled") && hasResumableEngine);
  const canCancel = selectedRun.status === "running" || selectedRun.status === "paused" || selectedRun.status === "queued";
  const interruptedEngines = selectedRun.engineRuns.filter(
    (engine) => engine.phase === "interrupted_restart" || engine.errorCode === "desktop_process_restarted",
  );
  const incompleteCount = stateCounts.partial + stateCounts.failed + stateCounts.not_executed + stateCounts.cancelled;
  const terminalCount = terminalEngineStates.reduce((sum, state) => sum + stateCounts[state], 0);
  const today = new Date().toISOString().slice(0, 10);
  const expiredSupportEngines = selectedRun.engineRuns.filter((engine) =>
    Boolean(engine.knowledgeInput?.supportUntil && engine.knowledgeInput.supportUntil < today),
  );
  const knowledgeDates = [...new Set(selectedRun.engineRuns
    .map((engine) => engine.knowledgeInput?.knowledgeDate)
    .filter((value): value is string => Boolean(value)))]
    .sort();
  const supportDeadlines = [...new Set(selectedRun.engineRuns
    .map((engine) => engine.knowledgeInput?.supportUntil)
    .filter((value): value is string => Boolean(value)))]
    .sort();
  const knowledgeRange = knowledgeDates.length === 0
    ? text(copy.legacyKnowledge)
    : knowledgeDates.length === 1
      ? showPlainDate(knowledgeDates[0]!)
      : `${showPlainDate(knowledgeDates[0]!)} — ${showPlainDate(knowledgeDates.at(-1)!)}`;

  return (
    <div className="page">
      <PageHeader
        eyebrow={text(copy.eyebrow)}
        title={text(copy.title)}
        description={text(copy.description)}
        actions={(
          <div className="button-group">
            {canPause && (
              <button className="button button--secondary" type="button" disabled={busy} aria-label={text(copy.pauseAria, { id: selectedRun.id })} onClick={() => void onPause(selectedRun.id)}>
                <Icon name="pause" size={17} />{text(copy.pause)}
              </button>
            )}
            {canResume && (
              <button className="button button--primary" type="button" disabled={busy} aria-label={text(copy.resumeAria, { id: selectedRun.id })} onClick={() => void onResume(selectedRun.id)}>
                <Icon name="play" size={17} />{text(copy.resume)}
              </button>
            )}
            {canCancel && (
              <button className="button button--danger-ghost" type="button" disabled={busy} aria-label={text(copy.cancelAria, { id: selectedRun.id })} onClick={() => void onCancel(selectedRun.id)}>
                <Icon name="stop" size={17} />{text(copy.cancel)}
              </button>
            )}
          </div>
        )}
      />

      {runs.length > 1 && (
        <div className="run-picker" role="group" aria-label={text(copy.chooseRun)}>
          <span>{text(copy.viewRun)}</span>
          <div>
            {runs.map((run, index) => (
              <button
                key={run.id}
                type="button"
                className={run.id === selectedRun.id ? "run-picker__item run-picker__item--active" : "run-picker__item"}
                aria-pressed={run.id === selectedRun.id}
                onClick={() => setSelectedRunId(run.id)}
              >
                <strong>{run.label}</strong>
                <span>{index === 0 ? text(copy.latest) : ""}{runStatusMeta[run.status].label} · {showDateTime(run.startedAt)}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {interruptedEngines.length > 0 && (
        <InlineNotice tone="warning" title={text(copy.interruptedTitle)}>
          <div className="interrupted-run-notice">
            <p>{text(copy.interruptedBody, { count: formatNumber(interruptedEngines.length) })}</p>
            <div className="button-group">
              <button className="button button--primary button--small" type="button" disabled={busy || !canResume} onClick={() => void onResume(selectedRun.id)}>
                <Icon name="play" size={15} />{text(copy.resumeOriginal)}
              </button>
              <button className="button button--danger-ghost button--small" type="button" disabled={busy || !canCancel} onClick={() => void onCancel(selectedRun.id)}>
                <Icon name="stop" size={15} />{text(copy.cancelKeepRecord)}
              </button>
            </div>
          </div>
        </InlineNotice>
      )}

      {expiredSupportEngines.length > 0 && (
        <InlineNotice tone="warning" title={text(copy.expiredTitle)}>
          <p>{text(copy.expiredBody, { count: formatNumber(expiredSupportEngines.length) })}</p>
        </InlineNotice>
      )}

      <section className="run-overview run-overview--single">
        <div className="run-overview__copy">
          <div className="run-overview__meta">
            <StatusPill label={runMeta.label} tone={runMeta.tone} />
            <span>{selectedRun.label}</span>
          </div>
          <h2>{text(copy.processed, { percent: formatNumber(selectedRun.progress) })}</h2>
          <p>
            {text(copy.runSummary, {
              covered: formatNumber(selectedRun.coveredAssetCount),
              total: formatNumber(selectedRun.totalAssetCount),
              started: showDateTime(selectedRun.startedAt),
            })}
            {selectedRun.finishedAt ? text(copy.finished, { finished: showDateTime(selectedRun.finishedAt) }) : ""}
          </p>
          <ProgressBar value={selectedRun.progress} label={text(copy.overallProgress)} tone={selectedRun.status === "failed" ? "danger" : selectedRun.status === "partial" ? "warning" : "accent"} />
        </div>
      </section>

      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(copy.scanTechnicalDetails)}</summary>
        <dl>
          <div><dt>{text(copy.runIdTitle)}</dt><dd><code>{selectedRun.id}</code></dd></div>
          <div><dt>{text(copy.knowledgeTitle)}</dt><dd>{knowledgeRange}</dd></div>
        </dl>
        <p>
          {text(copy.caseSnapshot, { date: showDateTime(selectedRun.knowledgeDate) })}
          {supportDeadlines.length
            ? text(copy.supportUntil, { date: showPlainDate(supportDeadlines[0]!) })
            : text(copy.legacySupport)}
          {text(copy.noGuarantee)}
        </p>
        <div className="engine-state-ledger" aria-label={text(copy.ledgerAria)}>
          <span>{text(copy.scannerStates)}</span>
          {engineStates.map((state) => (
            <span key={state} className="engine-state-ledger__item">
              <StatusPill label={engineStatusMeta[state].label} tone={engineStatusMeta[state].tone} />
              <b>{formatNumber(stateCounts[state])}</b>
            </span>
          ))}
          <small>{text(copy.terminalCount, { done: formatNumber(terminalCount), total: formatNumber(selectedRun.engineRuns.length) })}</small>
        </div>
      </details>

      <section className="metrics-grid metrics-grid--four" aria-label={text(copy.metricsAria)}>
        <MetricCard label={text(copy.completed)} value={formatNumber(stateCounts.completed)} detail={text(copy.completedDetail)} icon="check" tone="accent" />
        <MetricCard label={text(copy.partial)} value={formatNumber(stateCounts.partial)} detail={text(copy.partialDetail)} icon="warning" tone={stateCounts.partial ? "warning" : "default"} />
        <MetricCard label={text(copy.failedCancelled)} value={formatNumber(stateCounts.failed + stateCounts.cancelled)} detail={text(copy.failedCancelledDetail)} icon="stop" tone={stateCounts.failed ? "danger" : "default"} />
        <MetricCard label={text(copy.notRun)} value={formatNumber(stateCounts.not_executed)} detail={text(copy.notRunDetail)} icon="clock" tone={stateCounts.not_executed ? "warning" : "default"} />
      </section>

      {incompleteCount > 0 && (
        <InlineNotice tone="warning" title={text(copy.incompleteTitle)}>
          <p>{text(copy.incompleteBody)}</p>
        </InlineNotice>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">{text(copy.workEyebrow)}</p>
            <h2>{text(copy.workTitle)}</h2>
            <p>{text(copy.workDescription)}</p>
          </div>
          <span className="count-label">{text(copy.workCount, { count: formatNumber(selectedRun.engineRuns.length) })}</span>
        </div>

        {selectedRun.engineRuns.length === 0 ? (
          <EmptyState icon="progress" title={text(copy.noWorkTitle)} description={text(copy.noWorkDescription)} />
        ) : (
          <div className="engine-list">
            {selectedRun.engineRuns.map((engine, index) => {
              const meta = engineStatusMeta[engine.status];
              const checkpoint = engine.checkpoint;
              return (
                <article key={engine.id} className={`engine-row engine-row--${meta.tone}`}>
                  <div className="engine-row__identity">
                    <span className={`engine-icon engine-icon--${meta.tone}`}><Icon name={engineIcon(engine)} size={19} /></span>
                    <span>
                      <strong>{text(copy.checkLabel, { number: formatNumber(index + 1) })}</strong>
                    </span>
                  </div>
                  <div className="engine-row__progress">
                    {engine.status === "not_executed" ? (
                      <div className="engine-not-executed">
                        <Icon name="info" size={16} />
                        <span><strong>{text(copy.notStarted)}</strong><small>{text(copy.notStartedReason)}</small></span>
                      </div>
                    ) : (
                      <ProgressBar value={engine.progress} label={text(copy.checkProgress)} tone={engine.status === "failed" ? "danger" : engine.status === "partial" ? "warning" : "accent"} />
                    )}
                    <details className="page-technical-details">
                      <summary>{text(copy.technicalDetails)}</summary>
                      <div className="engine-phase-line">
                        <span>{text(copy.currentStep)}<strong>{phaseLabel(engine)}</strong></span>
                      </div>
                      {engine.status === "not_executed" && <p>{text(copy.notRunTechnical)}</p>}
                      <dl>
                        <div><dt>{text(copy.scannerName)}</dt><dd>{engine.engineName}</dd></div>
                        <div><dt>{text(copy.targets)}</dt><dd>{formatNumber(engine.assetIds.length)}</dd></div>
                        <div><dt>{text(copy.rawEvidenceFiles)}</dt><dd>{formatNumber(engine.rawArtifactCount)}</dd></div>
                      </dl>
                      {checkpoint && (
                        <div className="checkpoint-card">
                          <div>
                            <Icon name="database" size={15} />
                            <strong>{text(copy.checkpoint)}</strong>
                            <StatusPill label={executionStageMeta[checkpoint.stage].label} tone={engine.status === "failed" ? "danger" : engine.status === "partial" || engine.status === "paused" ? "warning" : "neutral"} />
                          </div>
                          <dl>
                            <div><dt>{text(copy.attempt)}</dt><dd>#{formatNumber(checkpoint.attempt)}</dd></div>
                            <div><dt>{text(copy.evidence)}</dt><dd>{text(copy.evidenceCount, { count: formatNumber(checkpoint.artifactCount) })}</dd></div>
                            <div><dt>{text(copy.scopeLock)}</dt><dd>{checkpoint.scopeBound ? text(copy.scopeLocked) : text(copy.scopeNotCreated)}</dd></div>
                            <div><dt>{text(copy.cleanup)}</dt><dd>{checkpoint.cleanupCompleted ? text(copy.cleanupDone) : text(copy.cleanupPending)}</dd></div>
                          </dl>
                          <p>{executionStageMeta[checkpoint.stage].description}</p>
                        </div>
                      )}
                      <dl>
                        <div><dt>{text(copy.reportedPhase)}</dt><dd><code>{displayTechnicalDetail(engine.phase) ?? text(copy.noneReported)}</code></dd></div>
                        <div><dt>{text(copy.errorCode)}</dt><dd><code>{displayTechnicalDetail(engine.errorCode) ?? text(copy.noneReported)}</code></dd></div>
                        <div><dt>{text(copy.scannerMessage)}</dt><dd>{displayTechnicalDetail(engine.message) ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.checkpointError)}</dt><dd>{displayTechnicalDetail(checkpoint?.lastError) ?? text(copy.noneReported)}</dd></div>
                      </dl>
                    </details>
                  </div>
                  <div className="engine-row__result">
                    <StatusPill label={meta.label} tone={meta.tone} />
                    <span>{engine.findingCountKnown === false
                      ? text(copy.legacyFindingUnknown)
                      : text(copy.findingCount, { count: formatNumber(engine.findingCount) })}</span>
                    {engine.resumable && <small><Icon name="refresh" size={13} /> {text(copy.resumable)}</small>}
                  </div>
                  <details className="engine-provenance">
                    <summary>{text(copy.provenance)}</summary>
                    <dl>
                      <div><dt>{text(copy.jobId)}</dt><dd><code>{engine.id}</code></dd></div>
                      <div><dt>{text(copy.engineId)}</dt><dd><code>{engine.engineId}</code></dd></div>
                      <div><dt>{text(copy.categoryCode)}</dt><dd><code>{engine.category}</code></dd></div>
                      <div><dt>{text(copy.scannerVersion)}</dt><dd>{engine.version}</dd></div>
                      <div><dt>{text(copy.imageDigest)}</dt><dd><code>{engine.digest}</code></dd></div>
                      <div><dt>{text(copy.ruleVersion)}</dt><dd>{engine.ruleVersion ?? text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.adapter)}</dt><dd>{engine.adapterVersion ?? text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.manifestSchema)}</dt><dd>{engine.manifestSchemaVersion ?? text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.sourceRevision)}</dt><dd><code>{engine.sourceRevision ?? text(copy.noneReported)}</code></dd></div>
                      <div><dt>{text(copy.sourceRepository)}</dt><dd>{engine.repositoryUrl ?? text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.distributionMode)}</dt><dd>{engine.distributionMode ?? text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.imageRepository)}</dt><dd>{engine.imageRepository ?? text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.commandDigest)}</dt><dd><code>{engine.commandSha256 ?? text(copy.noneReported)}</code></dd></div>
                      <div><dt>{text(copy.knowledgeInput)}</dt><dd>{engine.knowledgeInput
                        ? `${engine.knowledgeInput.identifier} · ${engine.knowledgeInput.version ?? text(copy.noIndependentVersion)} · ${engine.knowledgeInput.pinState}`
                        : text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.knowledgeDate)}</dt><dd>{engine.knowledgeInput?.knowledgeDate ? showPlainDate(engine.knowledgeInput.knowledgeDate) : text(copy.olderNotRecorded)}</dd></div>
                      <div><dt>{text(copy.supportDate)}</dt><dd>{engine.knowledgeInput?.supportUntil
                        ? `${showPlainDate(engine.knowledgeInput.supportUntil)} · ${engine.knowledgeInput.supportUntil < today ? text(copy.expiredReadable) : text(copy.currentlySupported)}`
                        : text(copy.olderNotRecorded)}</dd></div>
                      <div><dt>{text(copy.runtime)}</dt><dd>{engine.runtimeProvider ? `${engine.runtimeProvider} ${engine.runtimeVersion ?? text(copy.unknownVersion)}` : text(copy.notRunYet)}</dd></div>
                      <div><dt>{text(copy.runtimeSecurity)}</dt><dd>{engine.runtimeSecurityOptions ?? text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.exitCode)}</dt><dd>{engine.exitCode ?? text(copy.noneReported)}</dd></div>
                      <div><dt>{text(copy.cleanupResult)}</dt><dd>
                        {engine.cleanupRemoved === undefined ? text(copy.noneReported) : engine.cleanupRemoved ? text(copy.removed) : text(copy.absentOrUnneeded)}
                        {engine.cleanupDetail ? ` · ${displayTechnicalDetail(engine.cleanupDetail) ?? ""}` : ""}
                      </dd></div>
                      <div><dt>{text(copy.started)}</dt><dd>{showDateTime(engine.startedAt)}</dd></div>
                      <div><dt>{text(copy.ended)}</dt><dd>{showDateTime(engine.finishedAt)}</dd></div>
                    </dl>
                    {engine.warnings.length > 0 && (
                      <div className="engine-not-executed">
                        <Icon name="info" size={16} />
                        <span><strong>{text(copy.warnings)}</strong><small>{displayTechnicalDetail(engine.warnings.join(locale === "zh-TW" ? "；" : "; "))}</small></span>
                      </div>
                    )}
                  </details>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className="section-block section-block--muted">
        <div className="section-heading section-heading--row">
          <div><p className="eyebrow">{text(copy.historyEyebrow)}</p><h2>{text(copy.historyTitle)}</h2></div>
        </div>
        <div className="history-list">
          {runs.map((run) => (
            <button key={run.id} type="button" className={run.id === selectedRun.id ? "history-row history-row--active" : "history-row"} onClick={() => setSelectedRunId(run.id)}>
              <span className="history-row__line" aria-hidden="true" />
              <span className="history-row__copy">
                <strong>{run.label}</strong>
                <span>{showDateTime(run.startedAt)} · {text(copy.historySnapshot, { date: showDateTime(run.knowledgeDate) })}</span>
              </span>
              <StatusPill label={runStatusMeta[run.status].label} tone={runStatusMeta[run.status].tone} />
              <b>{formatNumber(run.progress)}%</b>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}
