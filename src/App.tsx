import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { AppShell } from "./components/AppShell";
import { Icon } from "./components/Icon";
import { EmptyState } from "./components/Shared";
import { DEMO_NOTICE } from "./data/demo";
import { CasesPage } from "./pages/CasesPage";
import { CoveragePage } from "./pages/CoveragePage";
import { ExportPage } from "./pages/ExportPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ProgressPage } from "./pages/ProgressPage";
import { VerificationPage } from "./pages/VerificationPage";
import { EVENTS, scannerService, type ActionResponse } from "./services/scanner";
import type {
  AppMode,
  AppSnapshot,
  CaseWorkspace,
  CreateCaseInput,
  ExportFormat,
  PageId,
  ServiceResult,
  ToastMessage,
} from "./types";

const pageFromHash = (): PageId => {
  const value = window.location.hash.replace(/^#\/?/, "") as PageId;
  return ["cases", "coverage", "progress", "findings", "export", "verification"].includes(value)
    ? value
    : "cases";
};

const describeError = (error: unknown): string => {
  if (error instanceof Error) return error.message;
  return typeof error === "string" ? error : "本機核心未能完成這項工作。";
};

export default function App() {
  const [page, setPage] = useState<PageId>(pageFromHash);
  const [snapshot, setSnapshot] = useState<AppSnapshot>();
  const [mode, setMode] = useState<AppMode>(scannerService.isNative() ? "native" : "demo");
  const [notice, setNotice] = useState<string | undefined>(scannerService.isNative() ? undefined : DEMO_NOTICE);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string>();
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const toastId = useRef(0);

  const pushToast = useCallback((toast: Omit<ToastMessage, "id">) => {
    const id = ++toastId.current;
    setToasts((current) => [...current, { ...toast, id }]);
    window.setTimeout(() => setToasts((current) => current.filter((item) => item.id !== id)), 5200);
  }, []);

  const applyServiceMeta = useCallback(<T,>(result: ServiceResult<T>) => {
    setMode(result.mode);
    setNotice(result.notice);
  }, []);

  const loadSnapshot = useCallback(async (caseId?: string, quiet = false) => {
    if (!quiet) setLoading(true);
    const result = await scannerService.getSnapshot(caseId);
    applyServiceMeta(result);
    setSnapshot(result.data);
    if (!quiet) setLoading(false);
  }, [applyServiceMeta]);

  useEffect(() => {
    void loadSnapshot();
  }, [loadSnapshot]);

  useEffect(() => {
    const onHashChange = () => setPage(pageFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (!scannerService.isNative()) return undefined;
    let disposed = false;
    const unlisteners: Array<() => void> = [];
    const eventNames = Object.values(EVENTS);

    void Promise.all(
      eventNames.map(async (eventName) => {
        const unlisten = await scannerService.subscribe(eventName, () => {
          if (!disposed) void loadSnapshot(snapshot?.selectedCaseId, true);
        });
        unlisteners.push(unlisten);
      }),
    );

    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, [loadSnapshot, snapshot?.selectedCaseId]);

  const navigate = (target: PageId) => {
    window.location.hash = target;
    setPage(target);
    document.getElementById("main-content")?.focus();
  };

  const selectCase = async (caseId: string) => {
    setLoading(true);
    try {
      const result = await scannerService.selectCase(caseId);
      applyServiceMeta(result);
      setSnapshot((current) => current ? { ...current, selectedCaseId: caseId, workspace: result.data } : current);
    } catch (error) {
      pushToast({ tone: "danger", title: "無法切換案件", detail: describeError(error) });
    } finally {
      setLoading(false);
    }
  };

  const createCase = async (input: CreateCaseInput) => {
    setBusyAction("create");
    try {
      const result = await scannerService.createCase(input);
      applyServiceMeta(result);
      await loadSnapshot(result.data.id, true);
      pushToast({
        tone: result.mode === "native" ? "success" : "info",
        title: result.mode === "native" ? "案件已建立" : "展示案件已建立",
        detail: result.mode === "native" ? "資料保存在本機案件核心。" : "只保存在瀏覽器 localStorage，沒有啟動掃描。",
      });
    } catch (error) {
      pushToast({ tone: "danger", title: "案件建立失敗", detail: describeError(error) });
    } finally {
      setBusyAction(undefined);
    }
  };

  const runAction = async (
    key: string,
    action: () => Promise<ServiceResult<ActionResponse>>,
  ) => {
    setBusyAction(key);
    const result = await action();
    applyServiceMeta(result);
    pushToast({
      tone: result.data.accepted ? "success" : result.mode === "demo" ? "info" : "warning",
      title: result.data.accepted ? "已送出本機工作" : result.mode === "demo" ? "展示模式未執行" : "工作未啟動",
      detail: result.data.message,
    });
    if (result.data.snapshot) setSnapshot(result.data.snapshot);
    else if (result.mode === "native") await loadSnapshot(snapshot?.selectedCaseId, true);
    setBusyAction(undefined);
  };

  const workspace = snapshot?.workspace;
  const selectedCase = useMemo(
    () => snapshot?.cases.find((assessmentCase) => assessmentCase.id === snapshot.selectedCaseId) ?? workspace?.case,
    [snapshot, workspace],
  );

  const exportCase = async (options: {
    format: ExportFormat;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => {
    if (!workspace) return;
    setBusyAction("export");
    try {
      const result = await scannerService.exportCase(
        { caseId: workspace.case.id, ...options },
        workspace,
      );
      applyServiceMeta(result);
      if (!result.data) {
        pushToast({ tone: "info", title: "已取消匯出", detail: "沒有建立或寫出任何檔案。" });
        return;
      }
      const exported = result.data;
      setSnapshot((current) => current?.workspace ? {
        ...current,
        workspace: {
          ...current.workspace,
          exports: [exported, ...current.workspace.exports],
        },
      } : current);
      pushToast({
        tone: result.mode === "native" ? "success" : "info",
        title: result.mode === "native" ? "案件已匯出" : "已下載展示檔",
        detail: result.mode === "native"
          ? `${exported.fileName} 已寫入本機選擇的位置。`
          : "檔案開頭明確標示 DEMO_ONLY_NOT_A_SCAN，不能當成掃描報告。",
      });
    } catch (error) {
      pushToast({ tone: "danger", title: "案件匯出失敗", detail: describeError(error) });
    } finally {
      setBusyAction(undefined);
    }
  };

  const verifyExport = async (path: string) => {
    setBusyAction("verify-export");
    const result = await scannerService.verifyCaseExport(path);
    applyServiceMeta(result);
    setBusyAction(undefined);
    pushToast({
      tone: result.data.accepted ? "success" : "info",
      title: result.data.accepted ? "完整性驗證完成" : "無法驗證展示檔",
      detail: result.data.message,
    });
  };

  const currentCaseId = workspace?.case.id ?? selectedCase?.id;
  const currentRun = workspace?.runs[0];

  const content = (() => {
    if (loading && !snapshot) {
      return (
        <div className="loading-state" role="status">
          <span className="loading-spinner" aria-hidden="true" />
          <strong>正在讀取本機案件…</strong>
          <span>若本機核心尚未提供，將明確切換為展示資料。</span>
        </div>
      );
    }

    if (page === "cases") {
      return (
        <CasesPage
          cases={snapshot?.cases ?? []}
          selectedCase={selectedCase}
          assetCount={workspace?.assets.length ?? 0}
          findingCount={workspace?.findings.length ?? 0}
          unknownSourceCount={workspace?.coverage.filter((item) => item.state === "source_unavailable_unknown").length ?? 0}
          busy={busyAction === "create"}
          onCreate={createCase}
          onSelect={(caseId) => void selectCase(caseId)}
          onContinue={() => navigate("coverage")}
        />
      );
    }

    if (!workspace || !currentCaseId) {
      return (
        <EmptyState
          icon="cases"
          title="先建立或選擇案件"
          description="資產、掃描與 findings 都必須保存在一個可重跑的 Assessment Case 中。"
          action={<button className="button button--primary" type="button" onClick={() => navigate("cases")}>回到案件</button>}
        />
      );
    }

    switch (page) {
      case "coverage":
        return (
          <CoveragePage
            coverage={workspace.coverage}
            assets={workspace.assets}
            busy={busyAction === "discovery" || busyAction === "scope"}
            onStartDiscovery={() => runAction("discovery", () => scannerService.startDiscovery(currentCaseId))}
            onApprovePending={(assetIds) => runAction("scope", () => scannerService.approveScope({
              caseId: currentCaseId,
              assetIds,
              modes: ["public_data"],
              confirmation: "使用者在本機介面選取候選資產；主動掃描仍需另外授權。",
            }))}
          />
        );
      case "progress":
        return (
          <ProgressPage
            runs={workspace.runs}
            busy={Boolean(busyAction)}
            onStart={() => runAction("start-scan", () => scannerService.startScan(currentCaseId))}
            onPause={(runId) => runAction("pause-scan", () => scannerService.pauseScan(currentCaseId, runId))}
            onResume={(runId) => runAction("resume-scan", () => scannerService.resumeScan(currentCaseId, runId))}
            onCancel={(runId) => runAction("cancel-scan", () => scannerService.cancelScan(currentCaseId, runId))}
          />
        );
      case "findings":
        return <FindingsPage findings={workspace.findings} />;
      case "export":
        return (
          <ExportPage
            workspace={workspace}
            exports={workspace.exports}
            busy={busyAction === "export" || busyAction === "verify-export"}
            onExport={exportCase}
            onVerify={verifyExport}
          />
        );
      case "verification":
        return (
          <VerificationPage
            verification={workspace.verification}
            busy={busyAction === "rescan"}
            onStartRescan={() => runAction("rescan", () => scannerService.startRescan(currentCaseId))}
          />
        );
      default:
        return null;
    }
  })();

  return (
    <>
      <AppShell
        page={page}
        mode={mode}
        cases={snapshot?.cases ?? []}
        selectedCase={selectedCase}
        loading={loading}
        onNavigate={navigate}
        onSelectCase={(caseId) => void selectCase(caseId)}
        demoNotice={notice ?? DEMO_NOTICE}
      >
        {content}
      </AppShell>

      <div className="toast-region" aria-live="polite" aria-label="應用程式通知">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast--${toast.tone}`}>
            <Icon name={toast.tone === "success" ? "check" : toast.tone === "danger" || toast.tone === "warning" ? "warning" : "info"} size={19} />
            <div><strong>{toast.title}</strong>{toast.detail && <span>{toast.detail}</span>}</div>
            <button type="button" aria-label="關閉通知" onClick={() => setToasts((current) => current.filter((item) => item.id !== toast.id))}><Icon name="close" size={16} /></button>
          </div>
        ))}
      </div>

      {busyAction && <span className="sr-only" role="status">正在處理 {busyAction}</span>}
      {currentRun?.status === "running" && <span className="sr-only" aria-live="polite">掃描目前進度 {currentRun.progress}%</span>}
    </>
  );
}
