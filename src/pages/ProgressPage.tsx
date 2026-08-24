import { useEffect, useMemo, useState } from "react";

import {
  engineStatusMeta,
  executionStageMeta,
  formatDateTime,
  runStatusMeta,
} from "../lib";
import type { EngineRun, EngineRunStatus, ExecutionStage, ScanRun } from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader, ProgressBar } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

interface ProgressPageProps {
  runs: ScanRun[];
  busy?: boolean;
  onStart: () => Promise<void>;
  onPause: (runId: string) => Promise<void>;
  onResume: (runId: string) => Promise<void>;
  onCancel: (runId: string) => Promise<void>;
}

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

const phaseLabel = (engine: EngineRun): string => {
  if (engine.phase === "interrupted_restart") return "桌面程式重啟後中斷";
  if (engine.phase === "queued_for_resume") return "已排入續跑佇列";
  if (isExecutionStage(engine.phase)) return executionStageMeta[engine.phase].label;
  return engine.phase.replaceAll("_", " ") || "未回報階段";
};

const engineIcon = (engine: EngineRun) => {
  if (engine.status === "completed") return "check" as const;
  if (engine.status === "running") return "refresh" as const;
  if (engine.status === "paused") return "pause" as const;
  if (engine.status === "failed" || engine.status === "partial") return "warning" as const;
  if (engine.status === "cancelled") return "stop" as const;
  return "settings" as const;
};

export function ProgressPage({ runs, busy, onStart, onPause, onResume, onCancel }: ProgressPageProps) {
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

  if (!selectedRun) {
    return (
      <div className="page">
        <PageHeader
          eyebrow="Scan Orchestrator"
          title="掃描進度"
          description="每個引擎都有獨立狀態；掃描中斷時，不會把部分結果包裝成完成。"
        />
        <EmptyState
          icon="progress"
          title="這個案件尚未開始掃描"
          description="先完成資料來源盤點與範圍確認，再由系統依固定範圍安排可用引擎；不具執行條件的引擎也會留下未執行紀錄。"
          action={<button className="button button--primary" type="button" disabled={busy} onClick={() => void onStart()}><Icon name="play" size={17} />開始掃描</button>}
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
    ? "舊版案件未逐引擎記錄"
    : knowledgeDates.length === 1 ? knowledgeDates[0] : `${knowledgeDates[0]} — ${knowledgeDates.at(-1)}`;

  return (
    <div className="page">
      <PageHeader
        eyebrow="Scan Orchestrator"
        title="掃描進度"
        description="每個引擎的終態、錯誤與 durable checkpoint 都獨立保存；續跑只重建原本已授權的工作，不會擴大範圍。"
        actions={
          <div className="button-group">
            {canPause && <button className="button button--secondary" type="button" disabled={busy} aria-label={`暫停掃描輪次 ${selectedRun.id}`} onClick={() => void onPause(selectedRun.id)}><Icon name="pause" size={17} />暫停</button>}
            {canResume && <button className="button button--primary" type="button" disabled={busy} aria-label={`續跑掃描輪次 ${selectedRun.id}`} onClick={() => void onResume(selectedRun.id)}><Icon name="play" size={17} />續跑未完成</button>}
            {canCancel && <button className="button button--danger-ghost" type="button" disabled={busy} aria-label={`取消掃描輪次 ${selectedRun.id}`} onClick={() => void onCancel(selectedRun.id)}><Icon name="stop" size={17} />取消這一輪</button>}
          </div>
        }
      />

      {runs.length > 1 && (
        <div className="run-picker" role="group" aria-label="選擇掃描輪次">
          <span>查看輪次</span>
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
                <span>{index === 0 ? "最新 · " : ""}{runStatusMeta[run.status].label} · {formatDateTime(run.startedAt)}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {interruptedEngines.length > 0 && (
        <InlineNotice tone="warning" title="桌面程式重啟時，這一輪尚未到達終態">
          <div className="interrupted-run-notice">
            <p>{interruptedEngines.map((engine) => engine.engineName).join("、")} 已在最後持久化檢查點暫停。請明確選擇續跑或取消；系統不會在重啟後自行接觸資產。</p>
            <div className="button-group">
              <button className="button button--primary button--small" type="button" disabled={busy || !canResume} onClick={() => void onResume(selectedRun.id)}><Icon name="play" size={15} />從原範圍續跑</button>
              <button className="button button--danger-ghost button--small" type="button" disabled={busy || !canCancel} onClick={() => void onCancel(selectedRun.id)}><Icon name="stop" size={15} />取消並保留紀錄</button>
            </div>
          </div>
        </InlineNotice>
      )}

      {expiredSupportEngines.length > 0 && (
        <InlineNotice tone="warning" title="這輪使用的引擎知識已超過支援期限">
          <p>
            {expiredSupportEngines.map((engine) => engine.engineName).join("、")} 的固定版本已過宣告期限。
            歷史證據仍然有效且可讀；重新驗證前請先取得新版 manifest，這不代表目前案件本身失效。
          </p>
        </InlineNotice>
      )}

      <section className="run-overview">
        <div className="run-overview__copy">
          <div className="run-overview__meta">
            <StatusPill label={runMeta.label} tone={runMeta.tone} />
            <span>{selectedRun.label}</span>
            <code title="本機掃描輪次 ID">{selectedRun.id}</code>
          </div>
          <h2>{selectedRun.progress}% 已處理</h2>
          <p>
            所有已規劃引擎完成 {selectedRun.coveredAssetCount}／{selectedRun.totalAssetCount} 個本輪目標 ·
            開始於 {formatDateTime(selectedRun.startedAt)}
            {selectedRun.finishedAt ? ` · 終止於 ${formatDateTime(selectedRun.finishedAt)}` : ""}
          </p>
          <ProgressBar value={selectedRun.progress} label="案件掃描整體進度" tone={selectedRun.status === "failed" ? "danger" : selectedRun.status === "partial" ? "warning" : "accent"} />
        </div>
        <div className="knowledge-card">
          <Icon name="clock" size={20} />
          <span>這輪引擎的知識日期</span>
          <strong>{knowledgeRange}</strong>
          <small>
            案件快照 {formatDateTime(selectedRun.knowledgeDate)}
            {supportDeadlines.length ? ` · 最早支援至 ${supportDeadlines[0]}` : " · 舊版未記錄支援期限"}。
            這不是持續安全保證。
          </small>
        </div>
      </section>

      <section className="metrics-grid metrics-grid--four" aria-label="引擎結果摘要">
        <MetricCard label="已完成" value={stateCounts.completed} detail="證據、adapter 與清理均完成" icon="check" tone="accent" />
        <MetricCard label="部分完成" value={stateCounts.partial} detail="保留已有結果，涵蓋仍不完整" icon="warning" tone={stateCounts.partial ? "warning" : "default"} />
        <MetricCard label="失敗／取消" value={stateCounts.failed + stateCounts.cancelled} detail="錯誤或使用者終止均獨立保留" icon="stop" tone={stateCounts.failed ? "danger" : "default"} />
        <MetricCard label="未執行" value={stateCounts.not_executed} detail="原因會保留；零 finding 不代表已檢查" icon="clock" tone={stateCounts.not_executed ? "warning" : "default"} />
      </section>

      <div className="engine-state-ledger" aria-label="全部引擎狀態數量">
        <span>引擎狀態</span>
        {engineStates.map((state) => (
          <span key={state} className="engine-state-ledger__item">
            <StatusPill label={engineStatusMeta[state].label} tone={engineStatusMeta[state].tone} />
            <b>{stateCounts[state]}</b>
          </span>
        ))}
        <small>{terminalCount}／{selectedRun.engineRuns.length} 已到達明確終態</small>
      </div>

      {incompleteCount > 0 && (
        <InlineNotice tone="warning" title="本輪不是完整涵蓋">
          <p>部分完成、失敗、取消與未執行各有不同原因。既有 findings 仍可檢視，但沒有結果的引擎或資產不能解讀為安全。</p>
        </InlineNotice>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">Engine runs</p>
            <h2>引擎工作與檢查點</h2>
            <p>版本、映像摘要、範圍、原始證據數、錯誤與可恢復位置都直接來自本機案件。</p>
          </div>
          <span className="count-label">{selectedRun.engineRuns.length} 個工作</span>
        </div>

        {selectedRun.engineRuns.length === 0 ? (
          <EmptyState icon="progress" title="本輪沒有引擎工作" description="掃描計畫尚未建立工作；這不是零問題的掃描結果。" />
        ) : (
          <div className="engine-list">
            {selectedRun.engineRuns.map((engine) => {
              const meta = engineStatusMeta[engine.status];
              const checkpoint = engine.checkpoint;
              return (
                <article key={engine.id} className={`engine-row engine-row--${meta.tone}`}>
                  <div className="engine-row__identity">
                    <span className={`engine-icon engine-icon--${meta.tone}`}>
                      <Icon name={engineIcon(engine)} size={19} />
                    </span>
                    <span>
                      <strong>{engine.engineName}</strong>
                      <small>{engine.category} · v{engine.version}</small>
                      <code>{engine.id}</code>
                    </span>
                  </div>
                  <div className="engine-row__progress">
                    {engine.status === "not_executed" ? (
                      <div className="engine-not-executed"><Icon name="info" size={16} /><span><strong>沒有啟動引擎</strong><small>{engine.message ?? "本輪沒有符合執行條件的目標或授權。"}</small></span></div>
                    ) : (
                      <>
                        <ProgressBar value={engine.progress} label={`${engine.engineName} 進度`} tone={engine.status === "failed" ? "danger" : engine.status === "partial" ? "warning" : "accent"} />
                        {engine.message && <p className="engine-message">{engine.message}</p>}
                      </>
                    )}
                    <div className="engine-phase-line">
                      <span>目前階段：<strong>{phaseLabel(engine)}</strong></span>
                      {engine.errorCode && <code>error: {engine.errorCode}</code>}
                    </div>
                    {checkpoint && (
                      <div className="checkpoint-card">
                        <div>
                          <Icon name="database" size={15} />
                          <strong>Durable checkpoint</strong>
                          <StatusPill label={executionStageMeta[checkpoint.stage].label} tone={engine.status === "failed" ? "danger" : engine.status === "partial" || engine.status === "paused" ? "warning" : "neutral"} />
                        </div>
                        <dl>
                          <div><dt>嘗試</dt><dd>#{checkpoint.attempt}</dd></div>
                          <div><dt>證據</dt><dd>{checkpoint.artifactCount} 份</dd></div>
                          <div><dt>範圍雜湊</dt><dd>{checkpoint.scopeBound ? "已固定" : "尚未建立"}</dd></div>
                          <div><dt>容器清理</dt><dd>{checkpoint.cleanupCompleted ? "完成" : "待處理"}</dd></div>
                        </dl>
                        <p>{executionStageMeta[checkpoint.stage].description}</p>
                        {checkpoint.lastError && <small>{checkpoint.lastError}</small>}
                      </div>
                    )}
                  </div>
                  <div className="engine-row__result">
                    <StatusPill label={meta.label} tone={meta.tone} />
                    <span>{engine.findingCountKnown === false ? "finding 數量無法由舊版證據歸屬" : `${engine.findingCount} 項 finding`}</span>
                    <span>{engine.assetIds.length} 個目標 · {engine.rawArtifactCount} 份原始證據</span>
                    {engine.resumable && <small><Icon name="refresh" size={13} /> 可從持久化狀態續跑</small>}
                  </div>
                  <details className="engine-provenance">
                    <summary>版本與執行 provenance</summary>
                    <dl>
                      <div><dt>Engine ID</dt><dd><code>{engine.engineId}</code></dd></div>
                      <div><dt>映像摘要</dt><dd><code>{engine.digest}</code></dd></div>
                      <div><dt>規則版本</dt><dd>{engine.ruleVersion ?? "未回報"}</dd></div>
                      <div><dt>Adapter</dt><dd>{engine.adapterVersion ?? "未回報"}</dd></div>
                      <div><dt>Manifest schema</dt><dd>{engine.manifestSchemaVersion ?? "未回報"}</dd></div>
                      <div><dt>來源 revision</dt><dd><code>{engine.sourceRevision ?? "未回報"}</code></dd></div>
                      <div><dt>來源 repository</dt><dd>{engine.repositoryUrl ?? "未回報"}</dd></div>
                      <div><dt>發佈模式</dt><dd>{engine.distributionMode ?? "未回報"}</dd></div>
                      <div><dt>映像 repository</dt><dd>{engine.imageRepository ?? "未回報"}</dd></div>
                      <div><dt>命令摘要</dt><dd><code>{engine.commandSha256 ?? "未回報"}</code></dd></div>
                      <div><dt>知識輸入</dt><dd>{engine.knowledgeInput ? `${engine.knowledgeInput.identifier} · ${engine.knowledgeInput.version ?? "無獨立版本"} · ${engine.knowledgeInput.pinState}` : "未回報"}</dd></div>
                      <div><dt>知識日期</dt><dd>{engine.knowledgeInput?.knowledgeDate ?? "舊版未記錄"}</dd></div>
                      <div><dt>支援期限</dt><dd>{engine.knowledgeInput?.supportUntil ? `${engine.knowledgeInput.supportUntil}${engine.knowledgeInput.supportUntil < today ? " · 已過期，歷史仍可讀" : " · 目前支援"}` : "舊版未記錄"}</dd></div>
                      <div><dt>Runtime</dt><dd>{engine.runtimeProvider ? `${engine.runtimeProvider} ${engine.runtimeVersion ?? "版本未知"}` : "尚未執行"}</dd></div>
                      <div><dt>Runtime 安全選項</dt><dd>{engine.runtimeSecurityOptions ?? "尚未回報"}</dd></div>
                      <div><dt>Exit code</dt><dd>{engine.exitCode ?? "尚未回報"}</dd></div>
                      <div><dt>清理結果</dt><dd>{engine.cleanupRemoved === undefined ? "尚未回報" : engine.cleanupRemoved ? "已移除" : "目標已不存在或無須移除"}{engine.cleanupDetail ? ` · ${engine.cleanupDetail}` : ""}</dd></div>
                      <div><dt>開始</dt><dd>{formatDateTime(engine.startedAt)}</dd></div>
                      <div><dt>終止</dt><dd>{formatDateTime(engine.finishedAt)}</dd></div>
                    </dl>
                    {engine.warnings.length > 0 && <div className="engine-not-executed"><Icon name="info" size={16} /><span><strong>執行警告</strong><small>{engine.warnings.join("；")}</small></span></div>}
                  </details>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className="section-block section-block--muted">
        <div className="section-heading section-heading--row">
          <div><p className="eyebrow">執行紀錄</p><h2>過往掃描</h2></div>
        </div>
        <div className="history-list">
          {runs.map((run) => (
            <button key={run.id} type="button" className={run.id === selectedRun.id ? "history-row history-row--active" : "history-row"} onClick={() => setSelectedRunId(run.id)}>
              <span className="history-row__line" aria-hidden="true" />
              <span className="history-row__copy"><strong>{run.label}</strong><span>{formatDateTime(run.startedAt)} · 案件快照 {formatDateTime(run.knowledgeDate)}</span><code>{run.id}</code></span>
              <StatusPill label={runStatusMeta[run.status].label} tone={runStatusMeta[run.status].tone} />
              <b>{run.progress}%</b>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}
