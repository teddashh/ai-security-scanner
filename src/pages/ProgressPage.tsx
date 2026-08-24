import { useMemo } from "react";

import { engineStatusMeta, formatDateTime, runStatusMeta } from "../lib";
import type { EngineRunStatus, ScanRun } from "../types";
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

const finalEngineStates: EngineRunStatus[] = ["completed", "partial", "failed", "not_executed"];

export function ProgressPage({ runs, busy, onStart, onPause, onResume, onCancel }: ProgressPageProps) {
  const latestRun = runs[0];
  const stateCounts = useMemo(
    () => Object.fromEntries(
      finalEngineStates.map((state) => [state, latestRun?.engineRuns.filter((engine) => engine.status === state).length ?? 0]),
    ) as Record<EngineRunStatus, number>,
    [latestRun],
  );

  if (!latestRun) {
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
          description="先完成資料來源盤點與範圍確認，再由系統自動安排合適引擎。"
          action={<button className="button button--primary" type="button" disabled={busy} onClick={() => void onStart()}><Icon name="play" size={17} />開始掃描</button>}
        />
      </div>
    );
  }

  const runMeta = runStatusMeta[latestRun.status];
  const canPause = latestRun.status === "running";
  const canResume = latestRun.status === "paused" || latestRun.status === "partial" || latestRun.status === "failed";
  const canCancel = latestRun.status === "running" || latestRun.status === "paused" || latestRun.status === "queued";

  return (
    <div className="page">
      <PageHeader
        eyebrow="Scan Orchestrator"
        title="掃描進度"
        description="完成、部分完成、失敗與未執行會被分開保存；可續跑工作只從中斷處恢復。"
        actions={
          <div className="button-group">
            {canPause && <button className="button button--secondary" type="button" disabled={busy} onClick={() => void onPause(latestRun.id)}><Icon name="pause" size={17} />暫停</button>}
            {canResume && <button className="button button--primary" type="button" disabled={busy} onClick={() => void onResume(latestRun.id)}><Icon name="play" size={17} />續跑未完成</button>}
            {canCancel && <button className="button button--danger-ghost" type="button" disabled={busy} onClick={() => void onCancel(latestRun.id)}><Icon name="stop" size={17} />停止並清理</button>}
          </div>
        }
      />

      <section className="run-overview">
        <div className="run-overview__copy">
          <div className="run-overview__meta">
            <StatusPill label={runMeta.label} tone={runMeta.tone} />
            <span>{latestRun.label}</span>
          </div>
          <h2>{latestRun.progress}% 已處理</h2>
          <p>
            涵蓋 {latestRun.coveredAssetCount}／{latestRun.totalAssetCount} 個授權資產 ·
            開始於 {formatDateTime(latestRun.startedAt)}
          </p>
          <ProgressBar value={latestRun.progress} label="案件掃描整體進度" tone={latestRun.status === "failed" ? "danger" : "accent"} />
        </div>
        <div className="knowledge-card">
          <Icon name="clock" size={20} />
          <span>這份結果的知識停在</span>
          <strong>{latestRun.knowledgeDate}</strong>
          <small>這是當時快照，不是持續安全保證。</small>
        </div>
      </section>

      <section className="metrics-grid metrics-grid--four" aria-label="引擎最終狀態">
        <MetricCard label="已完成" value={stateCounts.completed} detail="工作與輸出均完成" icon="check" tone="accent" />
        <MetricCard label="部分完成" value={stateCounts.partial} detail="已有結果，但涵蓋不完整" icon="warning" tone={stateCounts.partial ? "warning" : "default"} />
        <MetricCard label="失敗" value={stateCounts.failed} detail="需排除問題後續跑" icon="stop" tone={stateCounts.failed ? "danger" : "default"} />
        <MetricCard label="未執行" value={stateCounts.not_executed} detail="未授權、不適用或未排程" icon="clock" />
      </section>

      {(stateCounts.partial > 0 || stateCounts.failed > 0) && (
        <InlineNotice tone="warning" title="本次掃描不是完整完成">
          <p>下方引擎已明確標示原因。現有 findings 可以查看，但未完成的範圍不能解讀為安全。</p>
        </InlineNotice>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">Engine runs</p>
            <h2>引擎工作</h2>
            <p>版本、規則日期與工作狀態都會收進案件包，首頁只保留必要資訊。</p>
          </div>
          <span className="count-label">{latestRun.engineRuns.length} 個引擎</span>
        </div>

        <div className="engine-list">
          {latestRun.engineRuns.map((engine) => {
            const meta = engineStatusMeta[engine.status];
            return (
              <article key={engine.id} className="engine-row">
                <div className="engine-row__identity">
                  <span className={`engine-icon engine-icon--${meta.tone}`}>
                    <Icon name={engine.status === "completed" ? "check" : engine.status === "running" ? "refresh" : engine.status === "failed" ? "warning" : "settings"} size={19} />
                  </span>
                  <span>
                    <strong>{engine.engineName}</strong>
                    <small>{engine.category} · v{engine.version}</small>
                  </span>
                </div>
                <div className="engine-row__progress">
                  <ProgressBar value={engine.progress} label={`${engine.engineName} 進度`} tone={engine.status === "failed" ? "danger" : engine.status === "partial" ? "warning" : "accent"} />
                  {engine.message && <p className="engine-message">{engine.message}</p>}
                </div>
                <div className="engine-row__result">
                  <StatusPill label={meta.label} tone={meta.tone} />
                  <span>{engine.findingCount} 項發現</span>
                  {engine.resumable && <small><Icon name="refresh" size={13} /> 可續跑</small>}
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section className="section-block section-block--muted">
        <div className="section-heading section-heading--row">
          <div>
            <p className="eyebrow">執行紀錄</p>
            <h2>過往掃描</h2>
          </div>
        </div>
        <div className="history-list">
          {runs.map((run) => (
            <div key={run.id} className="history-row">
              <span className="history-row__line" aria-hidden="true" />
              <div>
                <strong>{run.label}</strong>
                <span>{formatDateTime(run.startedAt)} · 知識日期 {run.knowledgeDate}</span>
              </div>
              <StatusPill label={runStatusMeta[run.status].label} tone={runStatusMeta[run.status].tone} />
              <b>{run.progress}%</b>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
