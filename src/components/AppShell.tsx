import { useEffect, useState, type ReactNode } from "react";

import { cx, phaseMeta } from "../lib";
import type {
  AppMode,
  AppSnapshot,
  AssessmentCase,
  ManagedRuntimeSetupPhase,
  ManagedRuntimeSetupStatus,
  PageId,
} from "../types";
import type { AppUpdateState } from "../services/appUpdater";
import { AppUpdateControl } from "./AppUpdateControl";
import { Icon, type IconName } from "./Icon";
import { StatusPill } from "./StatusPill";

const navigation: Array<{ id: PageId; label: string; hint: string; icon: IconName }> = [
  { id: "cases", label: "案件", hint: "建立與選擇案件", icon: "cases" },
  { id: "coverage", label: "資產與涵蓋", hint: "視野與授權範圍", icon: "coverage" },
  { id: "progress", label: "掃描進度", hint: "引擎工作狀態", icon: "progress" },
  { id: "findings", label: "問題清單", hint: "優先事項與證據", icon: "findings" },
  { id: "export", label: "案件匯出", hint: "可交接案件包", icon: "export" },
  { id: "verification", label: "複驗比較", hint: "修復前後差異", icon: "verification" },
];

const runtimeSetupLabels: Record<ManagedRuntimeSetupPhase, string> = {
  idle: "尚未開始",
  install: "安裝並驗證執行環境",
  download: "下載執行環境映像",
  init: "初始化隔離虛擬機",
  start: "啟動隔離虛擬機",
  verify: "驗證服務可用性",
  completed: "設定完成",
  failed: "設定失敗",
  cancelled: "已取消，可續傳重試",
};

const exactBytes = (value: number): string => `${new Intl.NumberFormat("zh-TW").format(value)} bytes`;

interface AppShellProps {
  children: ReactNode;
  page: PageId;
  mode: AppMode;
  cases: AssessmentCase[];
  selectedCase?: AssessmentCase;
  loading?: boolean;
  onNavigate: (page: PageId) => void;
  onSelectCase: (caseId: string) => void;
  demoNotice?: string;
  appUpdate: AppUpdateState;
  onCheckForUpdate: () => void;
  onInstallUpdate: (version: string) => void;
  runtime?: AppSnapshot["runtime"];
  runtimeSetup?: ManagedRuntimeSetupStatus;
  runtimeBusy?: boolean;
  onSetupRuntime: () => void;
  onCancelRuntime: () => void;
}

export function AppShell({
  children,
  page,
  mode,
  cases,
  selectedCase,
  loading,
  onNavigate,
  onSelectCase,
  demoNotice,
  appUpdate,
  onCheckForUpdate,
  onInstallUpdate,
  runtime,
  runtimeSetup,
  runtimeBusy,
  onSetupRuntime,
  onCancelRuntime,
}: AppShellProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => setMobileOpen(false), [page]);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">跳到主要內容</a>

      <aside className={cx("sidebar", mobileOpen && "sidebar--open")} aria-label="主要導覽">
        <div className="brand">
          <span className="brand__mark"><Icon name="shield" size={22} /></span>
          <span className="brand__copy">
            <strong>ai-security-scanner</strong>
            <small>local casework</small>
          </span>
          <button
            className="icon-button sidebar__close"
            type="button"
            aria-label="關閉導覽"
            onClick={() => setMobileOpen(false)}
          >
            <Icon name="close" />
          </button>
        </div>

        <div className="sidebar__case">
          <label htmlFor="case-switcher">目前案件</label>
          <div className="select-wrap select-wrap--dark">
            <select
              id="case-switcher"
              value={selectedCase?.id ?? ""}
              onChange={(event) => onSelectCase(event.target.value)}
              disabled={loading || cases.length === 0}
            >
              {cases.length === 0 && <option value="">尚無案件</option>}
              {cases.map((assessmentCase) => (
                <option key={assessmentCase.id} value={assessmentCase.id}>
                  {assessmentCase.name}
                </option>
              ))}
            </select>
            <Icon name="chevron" size={16} />
          </div>
          {selectedCase && (
            <StatusPill
              label={phaseMeta[selectedCase.phase].label}
              tone={phaseMeta[selectedCase.phase].tone}
              className="sidebar__phase"
            />
          )}
        </div>

        <nav className="nav-list">
          {navigation.map((item) => (
            <button
              key={item.id}
              type="button"
              className={cx("nav-item", page === item.id && "nav-item--active")}
              aria-current={page === item.id ? "page" : undefined}
              onClick={() => onNavigate(item.id)}
            >
              <Icon name={item.icon} size={20} />
              <span>
                <strong>{item.label}</strong>
                <small>{item.hint}</small>
              </span>
            </button>
          ))}
        </nav>

        <div className="sidebar__footer">
          <div className="privacy-note">
            <Icon name="lock" size={17} />
            <span>
              <strong>資料留在本機</strong>
              <small>只有你主動匯出時才會離開</small>
            </span>
          </div>
          <span className={cx("runtime-badge", mode === "native" && runtime?.available ? "runtime-badge--native" : "runtime-badge--demo")}>
            <span aria-hidden="true" />
            {mode === "native"
              ? runtime?.available
                ? `隔離執行環境已就緒 · ${runtime.provider}`
                : `隔離執行環境未就緒 · ${runtime?.phase ?? "unknown"}`
              : "展示模式"}
          </span>
          {mode === "native" && runtime && !runtime.available && (
            <div className="runtime-setup" aria-live="polite">
              <small>{runtime.detail}</small>
              {runtime.prerequisite && <small>必要條件：{runtime.prerequisite}</small>}
              {runtimeSetup && runtimeSetup.phase !== "idle" && (
                <div className="runtime-setup__progress" role="status">
                  <strong>{runtimeSetupLabels[runtimeSetup.phase]}</strong>
                  <small>{runtimeSetup.detail}</small>
                  {runtimeSetup.totalBytes !== undefined && (
                    <>
                      <progress
                        max={runtimeSetup.totalBytes}
                        value={Math.min(runtimeSetup.receivedBytes, runtimeSetup.totalBytes)}
                        aria-label="隔離執行環境映像下載進度"
                      />
                      <small className="runtime-setup__bytes">
                        {exactBytes(runtimeSetup.receivedBytes)} / {exactBytes(runtimeSetup.totalBytes)}
                        {runtimeSetup.progressPercent !== undefined
                          ? ` · ${runtimeSetup.progressPercent.toFixed(2)}%`
                          : ""}
                      </small>
                      {runtimeSetup.resumedFromBytes > 0 && (
                        <small>已從 {exactBytes(runtimeSetup.resumedFromBytes)} 的部分檔續傳</small>
                      )}
                    </>
                  )}
                </div>
              )}
              {runtimeSetup?.active ? (
                <button
                  className="button button--small button--danger"
                  type="button"
                  disabled={!runtimeSetup.canCancel || runtimeSetup.cancelRequested}
                  onClick={onCancelRuntime}
                >
                  <Icon name="close" size={15} />
                  {runtimeSetup.cancelRequested ? "正在取消…" : "取消設定並保留下載進度"}
                </button>
              ) : (
                <button className="button button--small" type="button" disabled={runtimeBusy} onClick={onSetupRuntime}>
                  <Icon name="progress" size={15} />
                  {runtimeSetup?.canRetry && ["failed", "cancelled"].includes(runtimeSetup.phase)
                    ? "重試設定（可續傳）"
                    : "設定隔離執行環境"}
                </button>
              )}
            </div>
          )}
        </div>
      </aside>

      {mobileOpen && (
        <button
          className="sidebar-backdrop"
          aria-label="關閉導覽"
          type="button"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <div className="workspace">
        <header className="topbar">
          <button
            className="icon-button topbar__menu"
            type="button"
            aria-label="開啟導覽"
            onClick={() => setMobileOpen(true)}
          >
            <Icon name="menu" />
          </button>
          <div className="topbar__context">
            <span>{navigation.find((item) => item.id === page)?.label}</span>
            {selectedCase && <strong>{selectedCase.name}</strong>}
          </div>
          <div className="topbar__right">
            <AppUpdateControl
              state={appUpdate}
              onCheck={onCheckForUpdate}
              onInstall={onInstallUpdate}
            />
            <span className="knowledge-chip"><Icon name="clock" size={15} /> 知識日期依案件記錄</span>
          </div>
        </header>

        {(mode === "demo" || selectedCase?.isDemo) && (
          <div className="demo-banner" role="status">
            <Icon name="spark" size={19} />
            <div>
              <strong>{selectedCase?.isDemo ? "目前是展示案件，不是真實掃描" : "展示資料，不是真實掃描"}</strong>
              <span>{demoNotice}</span>
            </div>
          </div>
        )}

        <main id="main-content" className="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
