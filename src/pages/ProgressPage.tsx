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
  eyebrow: { en: "SCAN PROGRESS", zhTW: "掃描進度" },
  title: { en: "See what is being checked", zhTW: "查看目前檢查到哪裡" },
  description: {
    en: "Each scanner reports its own outcome. Pausing or restarting never turns unfinished work into a completed check.",
    zhTW: "每個掃描工具都會留下自己的結果；暫停或重新啟動時，未完成的工作不會被包裝成已完成。",
  },
  emptyTitle: { en: "This case has not been scanned yet", zhTW: "這個案件還沒有開始掃描" },
  emptyDescription: {
    en: "Confirm what you want to check and that you have permission first. Scanners that cannot run will still be recorded as not run—not as passed.",
    zhTW: "請先確認要檢查的系統與授權範圍。無法執行的掃描工具仍會留下「未執行」紀錄，不會被寫成通過。",
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
    en: "The app closed before this run reached a final outcome",
    zhTW: "應用程式關閉前，這一輪尚未完成",
  },
  interruptedBody: {
    en: "{engines} stopped at their last saved checkpoint. Choose whether to continue the original approved work or cancel it. The app will not contact assets on its own after a restart.",
    zhTW: "{engines} 已停在最後保存的進度。請選擇要繼續原本已授權的工作，或取消這一輪；應用程式重新啟動後不會自行接觸資產。",
  },
  resumeOriginal: { en: "Continue the original scope", zhTW: "繼續原本的範圍" },
  cancelKeepRecord: { en: "Cancel and keep the record", zhTW: "取消並保留紀錄" },
  expiredTitle: { en: "Some scanner knowledge is past its support date", zhTW: "部分掃描工具的知識版本已超過支援日期" },
  expiredBody: {
    en: "The pinned versions for {engines} are past their stated support dates. Historical evidence remains readable. Update their manifests before relying on a new verification; this does not erase the case history.",
    zhTW: "{engines} 使用的固定版本已超過宣告的支援日期。歷史證據仍可閱讀；再次確認修復前，請先更新這些工具的版本清單。案件歷史不會因此消失。",
  },
  runIdTitle: { en: "Local scan run ID", zhTW: "本機掃描輪次 ID" },
  processed: { en: "{percent}% processed", zhTW: "已處理 {percent}%" },
  runSummary: {
    en: "{covered} of {total} planned target assignments reached an engine outcome · Started {started}",
    zhTW: "{covered}／{total} 個預定目標已有掃描工具結果 · 開始於 {started}",
  },
  finished: { en: " · Ended {finished}", zhTW: " · 結束於 {finished}" },
  overallProgress: { en: "Overall scan progress", zhTW: "整體掃描進度" },
  knowledgeTitle: { en: "Knowledge dates used for this run", zhTW: "這一輪採用的知識日期" },
  legacyKnowledge: { en: "Not recorded per scanner in this older case", zhTW: "舊版案件未逐一記錄" },
  caseSnapshot: { en: "Case snapshot {date}", zhTW: "案件快照 {date}" },
  supportUntil: { en: " · Earliest supported through {date}", zhTW: " · 最早支援至 {date}" },
  legacySupport: { en: " · Support date not recorded in this older case", zhTW: " · 舊版案件未記錄支援日期" },
  noGuarantee: { en: ". This is not an ongoing guarantee of safety.", zhTW: "。這不是持續安全保證。" },
  metricsAria: { en: "Scanner outcome summary", zhTW: "掃描工具結果摘要" },
  completed: { en: "Completed", zhTW: "已完成" },
  completedDetail: { en: "Evidence, result processing, and cleanup finished", zhTW: "證據、結果整理與清理都已完成" },
  partial: { en: "Partly completed", zhTW: "部分完成" },
  partialDetail: { en: "Saved results exist, but coverage is incomplete", zhTW: "已有保存的結果，但涵蓋仍不完整" },
  failedCancelled: { en: "Failed or cancelled", zhTW: "失敗或取消" },
  failedCancelledDetail: { en: "Failures and user cancellations remain separate records", zhTW: "失敗與使用者取消會分開記錄" },
  notRun: { en: "Not run", zhTW: "未執行" },
  notRunDetail: { en: "A reason is kept; no findings does not mean checked", zhTW: "會保留原因；沒有問題不代表已檢查" },
  ledgerAria: { en: "Counts for every scanner state", zhTW: "所有掃描工具狀態數量" },
  scannerStates: { en: "Scanner states", zhTW: "掃描工具狀態" },
  terminalCount: { en: "{done} of {total} have a clear final outcome", zhTW: "{done}／{total} 個已有明確最終結果" },
  incompleteTitle: { en: "This run did not cover everything", zhTW: "這一輪沒有完整涵蓋" },
  incompleteBody: {
    en: "Partly completed, failed, cancelled, and not-run work have different causes. Existing findings can still be reviewed, but missing results must never be treated as safe.",
    zhTW: "部分完成、失敗、取消與未執行各有不同原因。已有的問題仍可查看，但沒有結果的工具或資產不能解讀為安全。",
  },
  workEyebrow: { en: "SCANNER WORK", zhTW: "掃描工具工作" },
  workTitle: { en: "What each scanner did", zhTW: "每個掃描工具做了什麼" },
  workDescription: {
    en: "See the outcome and saved restart point here. Exact versions, identifiers, and technical errors stay available under details.",
    zhTW: "這裡先顯示結果與可接續位置；精確版本、識別碼與技術錯誤仍保留在詳細資料中。",
  },
  workCount: { en: "{count} jobs", zhTW: "{count} 個工作" },
  noWorkTitle: { en: "No scanner work was created for this run", zhTW: "這一輪沒有建立掃描工具工作" },
  noWorkDescription: {
    en: "The plan created no runnable jobs. This is not a scan with zero problems.",
    zhTW: "掃描計畫沒有建立可執行工作；這不代表掃描結果是零問題。",
  },
  notStarted: { en: "Scanner did not start", zhTW: "掃描工具沒有啟動" },
  notStartedReason: {
    en: "This scanner could not start under the recorded conditions. Open technical details for the exact reason.",
    zhTW: "這個掃描工具無法在當時條件下啟動；精確原因可在技術細節查看。",
  },
  engineProgress: { en: "{engine} progress", zhTW: "{engine} 進度" },
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
  legacyFindingUnknown: { en: "Finding count cannot be tied to this older evidence", zhTW: "舊版證據無法確認問題數量屬於哪個工具" },
  findingCount: { en: "{count} findings", zhTW: "{count} 個問題" },
  targetEvidence: { en: "{targets} targets · {evidence} raw evidence files", zhTW: "{targets} 個目標 · {evidence} 份原始證據" },
  resumable: { en: "Can continue from saved progress", zhTW: "可從已保存的進度繼續" },
  technicalDetails: { en: "Technical status and errors", zhTW: "技術狀態與錯誤" },
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
  const joinNames = (values: string[]): string => values.join(locale === "zh-TW" ? "、" : ", ");
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
            <p>{text(copy.interruptedBody, { engines: joinNames(interruptedEngines.map((engine) => engine.engineName)) })}</p>
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
          <p>{text(copy.expiredBody, { engines: joinNames(expiredSupportEngines.map((engine) => engine.engineName)) })}</p>
        </InlineNotice>
      )}

      <section className="run-overview">
        <div className="run-overview__copy">
          <div className="run-overview__meta">
            <StatusPill label={runMeta.label} tone={runMeta.tone} />
            <span>{selectedRun.label}</span>
            <code title={text(copy.runIdTitle)}>{selectedRun.id}</code>
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
        <div className="knowledge-card">
          <Icon name="clock" size={20} />
          <span>{text(copy.knowledgeTitle)}</span>
          <strong>{knowledgeRange}</strong>
          <small>
            {text(copy.caseSnapshot, { date: showDateTime(selectedRun.knowledgeDate) })}
            {supportDeadlines.length
              ? text(copy.supportUntil, { date: showPlainDate(supportDeadlines[0]!) })
              : text(copy.legacySupport)}
            {text(copy.noGuarantee)}
          </small>
        </div>
      </section>

      <section className="metrics-grid metrics-grid--four" aria-label={text(copy.metricsAria)}>
        <MetricCard label={text(copy.completed)} value={formatNumber(stateCounts.completed)} detail={text(copy.completedDetail)} icon="check" tone="accent" />
        <MetricCard label={text(copy.partial)} value={formatNumber(stateCounts.partial)} detail={text(copy.partialDetail)} icon="warning" tone={stateCounts.partial ? "warning" : "default"} />
        <MetricCard label={text(copy.failedCancelled)} value={formatNumber(stateCounts.failed + stateCounts.cancelled)} detail={text(copy.failedCancelledDetail)} icon="stop" tone={stateCounts.failed ? "danger" : "default"} />
        <MetricCard label={text(copy.notRun)} value={formatNumber(stateCounts.not_executed)} detail={text(copy.notRunDetail)} icon="clock" tone={stateCounts.not_executed ? "warning" : "default"} />
      </section>

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
            {selectedRun.engineRuns.map((engine) => {
              const meta = engineStatusMeta[engine.status];
              const checkpoint = engine.checkpoint;
              return (
                <article key={engine.id} className={`engine-row engine-row--${meta.tone}`}>
                  <div className="engine-row__identity">
                    <span className={`engine-icon engine-icon--${meta.tone}`}><Icon name={engineIcon(engine)} size={19} /></span>
                    <span>
                      <strong>{engine.engineName}</strong>
                    </span>
                  </div>
                  <div className="engine-row__progress">
                    {engine.status === "not_executed" ? (
                      <div className="engine-not-executed">
                        <Icon name="info" size={16} />
                        <span><strong>{text(copy.notStarted)}</strong><small>{text(copy.notStartedReason)}</small></span>
                      </div>
                    ) : (
                      <ProgressBar value={engine.progress} label={text(copy.engineProgress, { engine: engine.engineName })} tone={engine.status === "failed" ? "danger" : engine.status === "partial" ? "warning" : "accent"} />
                    )}
                    <div className="engine-phase-line">
                      <span>{text(copy.currentStep)}<strong>{phaseLabel(engine)}</strong></span>
                    </div>
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
                    <details className="page-technical-details">
                      <summary>{text(copy.technicalDetails)}</summary>
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
                    <span>{text(copy.targetEvidence, {
                      targets: formatNumber(engine.assetIds.length),
                      evidence: formatNumber(engine.rawArtifactCount),
                    })}</span>
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
                <code>{run.id}</code>
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
