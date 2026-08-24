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
import {
  checkForAppUpdate,
  installAppUpdate,
  type AppUpdateState,
} from "./services/appUpdater";
import { EVENTS, scannerService, type ActionResponse } from "./services/scanner";
import type {
  AppMode,
  AppSnapshot,
  CaseArtifactCleanupResult,
  CaseArtifactDeletionPlan,
  CaseWorkspace,
  CreateCaseInput,
  ExportPreview,
  ExportFormat,
  ManagedRuntimeSetupStatus,
  PageId,
  ScanRun,
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

const isTerminalRun = (run: ScanRun): boolean =>
  ["completed", "partial", "failed", "cancelled"].includes(run.status);

export default function App() {
  const [page, setPage] = useState<PageId>(pageFromHash);
  const [snapshot, setSnapshot] = useState<AppSnapshot>();
  const [mode, setMode] = useState<AppMode>(scannerService.isNative() ? "native" : "demo");
  const [notice, setNotice] = useState<string | undefined>(scannerService.isNative() ? undefined : DEMO_NOTICE);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string>();
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [artifactCleanupPlan, setArtifactCleanupPlan] = useState<CaseArtifactDeletionPlan>();
  const [artifactCleanupResult, setArtifactCleanupResult] = useState<CaseArtifactCleanupResult>();
  const [runtimeSetup, setRuntimeSetup] = useState<ManagedRuntimeSetupStatus>();
  const [focusedFindingId, setFocusedFindingId] = useState<string>();
  const [verificationBaselineRunId, setVerificationBaselineRunId] = useState<string>();
  const [appUpdate, setAppUpdate] = useState<AppUpdateState>({
    phase: scannerService.isNative() ? "checking" : "unavailable",
  });
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
    setArtifactCleanupPlan((current) => current ?? result.data.artifactCleanupObligations?.[0]);
    if (!quiet) setLoading(false);
  }, [applyServiceMeta]);

  useEffect(() => {
    void loadSnapshot();
  }, [loadSnapshot]);

  useEffect(() => {
    if (!scannerService.isNative()) return;
    let disposed = false;
    void scannerService.getManagedRuntimeSetupStatus().then((result) => {
      if (!disposed) setRuntimeSetup(result.data);
    }).catch(() => undefined);
    return () => {
      disposed = true;
    };
  }, []);

  const runtimeSetupPolling = busyAction === "runtime-setup" || runtimeSetup?.active === true;

  useEffect(() => {
    if (!scannerService.isNative() || !runtimeSetupPolling) return;
    let disposed = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const result = await scannerService.getManagedRuntimeSetupStatus();
        if (disposed) return;
        setRuntimeSetup(result.data);
      } catch {
        // The authoritative runtime status remains available through the next
        // bounded poll; a transient IPC failure must not abandon setup UI.
      } finally {
        if (!disposed) timer = window.setTimeout(() => void poll(), 250);
      }
    };
    void poll();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [runtimeSetupPolling]);

  const checkAppUpdate = useCallback(async () => {
    if (!scannerService.isNative()) return;
    setAppUpdate((current) => ({ ...current, phase: "checking", message: undefined }));
    setAppUpdate(await checkForAppUpdate());
  }, []);

  useEffect(() => {
    void checkAppUpdate();
  }, [checkAppUpdate]);

  const installUpdate = useCallback(async (version: string) => {
    try {
      await installAppUpdate(version, setAppUpdate);
    } catch (error) {
      pushToast({
        tone: "danger",
        title: "應用程式更新未完成",
        detail: describeError(error),
      });
    }
  }, [pushToast]);

  const setupManagedRuntime = async () => {
    setBusyAction("runtime-setup");
    try {
      const result = await scannerService.setupManagedRuntime();
      applyServiceMeta(result);
      const setupResult = await scannerService.getManagedRuntimeSetupStatus();
      setRuntimeSetup(setupResult.data);
      await loadSnapshot(snapshot?.selectedCaseId, true);
      const cancelled = setupResult.data.phase === "cancelled";
      pushToast({
        tone: result.data.accepted ? "success" : "warning",
        title: result.data.accepted
          ? "隔離執行環境已就緒"
          : cancelled
            ? "已取消隔離執行環境設定"
            : "隔離執行環境尚未就緒，可再次重試",
        detail: result.data.message,
      });
    } catch (error) {
      pushToast({ tone: "danger", title: "隔離執行環境設定失敗，可再次重試", detail: describeError(error) });
    } finally {
      setBusyAction(undefined);
    }
  };

  const cancelManagedRuntimeSetup = async () => {
    try {
      const result = await scannerService.cancelManagedRuntimeSetup();
      applyServiceMeta(result);
      setRuntimeSetup(result.data);
      if (result.data.cancelRequested) {
        pushToast({
          tone: "info",
          title: "正在取消隔離執行環境設定",
          detail: "已送出取消要求；已下載的部分會保留，重試時可續傳。",
        });
      }
    } catch (error) {
      pushToast({ tone: "danger", title: "取消要求未送出", detail: describeError(error) });
    }
  };

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
    if (target !== "findings") setFocusedFindingId(undefined);
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
    try {
      const result = await action();
      applyServiceMeta(result);
      pushToast({
        tone: result.data.accepted ? "success" : result.mode === "demo" ? "info" : "warning",
        title: result.data.accepted ? "已送出本機工作" : result.mode === "demo" ? "展示模式未執行" : "工作未啟動",
        detail: result.data.message,
      });
      if (result.data.snapshot) setSnapshot(result.data.snapshot);
      else if (result.mode === "native") await loadSnapshot(snapshot?.selectedCaseId, true);
    } catch (error) {
      pushToast({ tone: "danger", title: "本機工作失敗", detail: describeError(error) });
    } finally {
      setBusyAction(undefined);
    }
  };

  const deleteCase = async (caseId: string, confirmation: string): Promise<boolean> => {
    setBusyAction("delete-case");
    try {
      const result = await scannerService.deleteCase(caseId, confirmation);
      applyServiceMeta(result);
      pushToast({
        tone: result.data.accepted ? "success" : result.mode === "demo" ? "info" : "warning",
        title: result.data.accepted ? "案件紀錄已刪除" : result.mode === "demo" ? "展示模式未刪除" : "案件未刪除",
        detail: result.data.message,
      });
      if (result.data.accepted) {
        setArtifactCleanupPlan(result.data.artifacts);
        setArtifactCleanupResult(undefined);
        await loadSnapshot(undefined, true);
      }
      return result.data.accepted;
    } catch (error) {
      pushToast({ tone: "danger", title: "案件刪除失敗", detail: describeError(error) });
      return false;
    } finally {
      setBusyAction(undefined);
    }
  };

  const deleteCaseArtifacts = async (confirmation: string): Promise<boolean> => {
    if (!artifactCleanupPlan?.exists) return false;
    setBusyAction("delete-artifacts");
    try {
      const result = await scannerService.deleteCaseArtifacts({
        caseId: artifactCleanupPlan.caseId,
        exactPath: artifactCleanupPlan.exactPath,
        confirmation,
      });
      applyServiceMeta(result);
      setArtifactCleanupResult(result.data);
      setArtifactCleanupPlan((current) => current ? { ...current, exists: false } : current);
      pushToast({
        tone: result.data.removed ? "warning" : "info",
        title: result.data.removed ? "案件證據已永久移除" : "證據目錄未移除",
        detail: result.data.removed
          ? `${result.data.exactPath} 已刪除且不可復原。`
          : `${result.data.exactPath} 已不存在或未被移除。`,
      });
      return result.data.removed;
    } catch (error) {
      pushToast({ tone: "danger", title: "證據清理失敗", detail: describeError(error) });
      return false;
    } finally {
      setBusyAction(undefined);
    }
  };

  const dismissArtifactCleanup = () => {
    setArtifactCleanupPlan(undefined);
    setArtifactCleanupResult(undefined);
  };

  const workspace = snapshot?.workspace;
  const selectedCase = useMemo(
    () => snapshot?.cases.find((assessmentCase) => assessmentCase.id === snapshot.selectedCaseId) ?? workspace?.case,
    [snapshot, workspace],
  );
  const terminalRuns = useMemo(
    () => workspace?.runs.filter(isTerminalRun) ?? [],
    [workspace?.runs],
  );

  useEffect(() => {
    setVerificationBaselineRunId((current) =>
      terminalRuns.some((run) => run.id === current) ? current : terminalRuns[0]?.id,
    );
  }, [workspace?.case.id, terminalRuns]);

  const previewExport = useCallback(async (options: {
    format: ExportFormat;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }): Promise<ExportPreview | undefined> => {
    if (!workspace) return undefined;
    const result = await scannerService.previewExport(
      { caseId: workspace.case.id, ...options },
      workspace,
    );
    applyServiceMeta(result);
    return result.data;
  }, [applyServiceMeta, workspace]);

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

  const verifyReceivedExport = async () => {
    const path = await scannerService.chooseCaseBundle();
    if (path) await verifyExport(path);
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
          connectedNoAssetSourceCount={workspace?.coverage.filter((item) => item.state === "source_connected_none").length ?? 0}
          latestRun={workspace?.runs[0]}
          runs={workspace?.runs ?? []}
          verificationBaselineRunId={verificationBaselineRunId}
          busy={["create", "archive-case", "delete-case", "delete-artifacts", "rescan"].includes(busyAction ?? "")}
          artifactCleanupPlan={artifactCleanupPlan}
          artifactCleanupResult={artifactCleanupResult}
          onCreate={createCase}
          onArchive={(caseId) => runAction("archive-case", () => scannerService.archiveCase(caseId))}
          onDelete={deleteCase}
          onDeleteArtifacts={deleteCaseArtifacts}
          onDismissArtifactCleanup={dismissArtifactCleanup}
          onSelect={(caseId) => void selectCase(caseId)}
          onContinue={() => navigate("coverage")}
          onOpenProgress={() => navigate("progress")}
          onSelectVerificationBaseline={setVerificationBaselineRunId}
          onStartRescan={(baselineRunId) => currentCaseId
            ? runAction("rescan", () => scannerService.startRescan(currentCaseId, baselineRunId))
            : Promise.resolve()}
          onOpenVerification={() => navigate("verification")}
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
            caseId={currentCaseId}
            requestedActivities={workspace.case.requestedActivities}
            coverage={workspace.coverage}
            sources={workspace.sources}
            assets={workspace.assets}
            scopeGrants={workspace.scopeGrants}
            nativeMode={mode === "native"}
            busy={busyAction === "connect-source" || busyAction === "attach-workspace" || busyAction === "discovery" || busyAction === "scope"}
            onChooseSnapshot={() => scannerService.chooseSourceSnapshot()}
            onConnectSourceSnapshot={(input) => runAction("connect-source", () => scannerService.connectSourceSnapshot(input))}
            onChooseWorkspace={() => scannerService.chooseWorkspaceDirectory()}
            onAttachWorkspaceSnapshot={(input) => runAction("attach-workspace", () => scannerService.attachWorkspaceSnapshot(input))}
            onStartDiscovery={() => runAction("discovery", () => scannerService.startDiscovery(currentCaseId))}
            onAuthorizationChanged={() => loadSnapshot(currentCaseId, true)}
            onApprovePending={(assetIds, modes, confirmation, externalScope) => runAction("scope", () => scannerService.approveScope({
              caseId: currentCaseId,
              assetIds,
              modes,
              confirmation,
              externalScope,
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
        return (
          <FindingsPage
            findings={workspace.findings}
            findingGroups={workspace.findingGroups}
            findingGroupEvents={workspace.findingGroupEvents}
            workflowEvents={workspace.workflowEvents}
            coverage={workspace.coverage}
            runs={workspace.runs}
            focusedFindingId={focusedFindingId}
            busy={["finding-workflow", "finding-group", "finding-ungroup"].includes(busyAction ?? "")}
            onUpdateWorkflow={(input) => runAction("finding-workflow", () => scannerService.updateFindingWorkflow({ caseId: currentCaseId, ...input }))}
            onGroupFindings={(input) => runAction("finding-group", () => scannerService.groupFindings({
              caseId: currentCaseId,
              groupedBy: "本機使用者",
              ...input,
            }))}
            onUngroupFindings={(groupId) => runAction("finding-ungroup", () => scannerService.ungroupFindings({
              caseId: currentCaseId,
              groupId,
              removedBy: "本機使用者",
              reason: "使用者從 Findings 畫面移除呈現群組；原始 findings 與證據完整保留。",
            }))}
            onOpenCoverage={() => navigate("coverage")}
            onOpenProgress={() => navigate("progress")}
          />
        );
      case "export":
        return (
          <ExportPage
            workspace={workspace}
            exports={workspace.exports}
            demoMode={mode === "demo" || Boolean(workspace.case.isDemo)}
            busy={busyAction === "export" || busyAction === "verify-export"}
            onPreview={previewExport}
            onExport={exportCase}
            onVerify={verifyExport}
            onVerifyReceived={verifyReceivedExport}
          />
        );
      case "verification":
        return (
          <VerificationPage
            verification={workspace.verification}
            runs={workspace.runs}
            findings={workspace.findings}
            baselineRunId={verificationBaselineRunId}
            busy={busyAction === "rescan"}
            onSelectBaseline={setVerificationBaselineRunId}
            onStartRescan={(baselineRunId) => runAction("rescan", () => scannerService.startRescan(currentCaseId, baselineRunId))}
            onOpenFinding={(findingId) => {
              setFocusedFindingId(findingId);
              navigate("findings");
            }}
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
        appUpdate={appUpdate}
        onCheckForUpdate={() => void checkAppUpdate()}
        onInstallUpdate={(version) => void installUpdate(version)}
        runtime={snapshot?.runtime}
        runtimeSetup={runtimeSetup}
        runtimeBusy={busyAction === "runtime-setup" || runtimeSetup?.active}
        onSetupRuntime={() => void setupManagedRuntime()}
        onCancelRuntime={() => void cancelManagedRuntimeSetup()}
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
