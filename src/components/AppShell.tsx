import { useEffect, useState, type ReactNode } from "react";

import { cx, phaseMeta } from "../lib";
import type { AppMode, AssessmentCase, PageId } from "../types";
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
          <span className={cx("runtime-badge", mode === "native" ? "runtime-badge--native" : "runtime-badge--demo")}>
            <span aria-hidden="true" />
            {mode === "native" ? "本機核心已連線" : "展示模式"}
          </span>
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
