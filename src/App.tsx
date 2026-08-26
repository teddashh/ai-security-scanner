import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { AppShell } from "./components/AppShell";
import { Icon } from "./components/Icon";
import { RuntimeFirstLaunch } from "./components/RuntimeFirstLaunch";
import { RuntimeSetupAssistant } from "./components/RuntimeSetupAssistant";
import { EmptyState } from "./components/Shared";
import { getDemoNotice } from "./data/demo";
import { useI18n, type BilingualText } from "./i18n";
import { CasesPage } from "./pages/CasesPage";
import { CoveragePage } from "./pages/CoveragePage";
import { ExportPage } from "./pages/ExportPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ProgressPage } from "./pages/ProgressPage";
import { StartPage } from "./pages/StartPage";
import { VerificationPage } from "./pages/VerificationPage";
import {
  coverageSetupFocusFor,
  isPackagedComponentBlocker,
  isReadinessRetryBlocker,
  isScannerSetupBlocker,
} from "./scanReadiness";
import {
  isCurrentScanReadinessRequest,
  isCurrentScanReadinessResponse,
} from "./scanReadinessRequest";
import {
  shouldAutomaticallyPrepareRuntime,
  shouldShowRuntimeFirstLaunch,
} from "./runtimeFirstLaunch";
import {
  checkForAppUpdate,
  installAppUpdate,
  type AppUpdateState,
} from "./services/appUpdater";
import { EVENTS, scannerService, type ActionResponse } from "./services/scanner";
import { startPageCopy, type UseCaseDefinition } from "./useCases";
import { displaySafeTechnicalDetail } from "./technicalDetails";
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
  ScanReadiness,
  ScanReadinessBlocker,
  ScanRun,
  ServiceResult,
  ToastMessage,
} from "./types";

const pageFromHash = (): PageId => {
  const value = window.location.hash.replace(/^#\/?/, "") as PageId;
  return ["start", "cases", "coverage", "progress", "findings", "export", "verification"].includes(value)
    ? value
    : "start";
};

const recordTechnicalError = (context: string, error: unknown): void => {
  console.error(
    `[ai-security-scanner] ${context}`,
    displaySafeTechnicalDetail(error) ?? "No display-safe technical detail was available.",
  );
};

const busyActionCopy = {
  "runtime-setup": { en: "scan-tool setup", zhTW: "掃描工具設定" },
  "runtime-repair": { en: "Windows setup", zhTW: "Windows 設定" },
  create: { en: "scan project creation", zhTW: "建立掃描專案" },
  "archive-case": { en: "case archiving", zhTW: "封存案件" },
  "delete-case": { en: "case-record deletion", zhTW: "刪除案件紀錄" },
  "delete-artifacts": { en: "evidence deletion", zhTW: "刪除證據" },
  rescan: { en: "the follow-up scan", zhTW: "複驗掃描" },
  "connect-source": { en: "source connection", zhTW: "連接資料來源" },
  "attach-workspace": { en: "local-file attachment", zhTW: "附加本機檔案" },
  discovery: { en: "asset discovery", zhTW: "盤點資產" },
  scope: { en: "permission confirmation", zhTW: "確認授權範圍" },
  "start-scan": { en: "starting the scan", zhTW: "開始掃描" },
  "pause-scan": { en: "pausing the scan", zhTW: "暫停掃描" },
  "resume-scan": { en: "resuming the scan", zhTW: "繼續掃描" },
  "cancel-scan": { en: "cancelling the scan", zhTW: "取消掃描" },
  "finding-workflow": { en: "updating a problem", zhTW: "更新問題狀態" },
  "finding-group": { en: "grouping related problems", zhTW: "整理相關問題" },
  "finding-ungroup": { en: "removing a problem group", zhTW: "移除問題群組" },
  export: { en: "report export", zhTW: "匯出報告" },
  "verify-export": { en: "file integrity verification", zhTW: "驗證檔案完整性" },
} as const;

const unknownBusyActionCopy = { en: "the current task", zhTW: "目前工作" } as const;

const scanStartIssueCopy = {
  no_effective_scope_grants: {
    en: "Choose the exact target you want to check, then confirm it once.",
    zhTW: "請先選擇這次要檢查的確切目標，並確認一次即可。",
  },
  no_ownership_confirmed_targets: {
    en: "Return to scan setup and confirm the target shown there.",
    zhTW: "請回到掃描設定，確認畫面上的目標。",
  },
  no_compatible_authorized_targets: {
    en: "The current input is not usable by any check yet. Finish the target step in scan setup.",
    zhTW: "目前的輸入還不能交給任何檢查使用；請完成掃描設定中的目標步驟。",
  },
  no_runnable_authorized_targets: {
    en: "This target is ready, but this version has no working scan tool for it. Get the latest installer; your local scan projects will stay on this device.",
    zhTW: "目標已準備好，但這個版本沒有可執行這項檢查的工具。請取得最新安裝程式；這台電腦上的掃描專案會完整保留。",
  },
  runtime_unavailable: {
    en: "The target is ready. Set up the private scan tools once, then start the scan.",
    zhTW: "目標已準備好。先完成一次專用掃描工具設定，就能開始掃描。",
  },
  provider_source_required: {
    en: "Connect the cloud account you want to scan. No scan has started yet.",
    zhTW: "請先連接你要掃描的雲端帳號；掃描尚未開始。",
  },
  provider_capability_unavailable: {
    en: "The read-only connection has expired or is no longer available. Reconnect the same account, then start the scan.",
    zhTW: "唯讀連線已失效或無法繼續使用。請重新連接同一個帳號，再開始掃描。",
  },
  provider_source_ambiguous: {
    en: "More than one cloud connection matches this target. Choose the exact connection before scanning.",
    zhTW: "有多個雲端連線可能符合這個目標；請先選擇正確的連線。",
  },
  provider_authorization_binding_mismatch: {
    en: "The saved read-only access does not match this cloud connection. Review the connection before scanning.",
    zhTW: "已保存的唯讀權限與這個雲端連線不一致；請先檢查連線。",
  },
  provider_target_binding_mismatch: {
    en: "The connected cloud account does not match this scan target. Review the target before scanning.",
    zhTW: "已連接的雲端帳號與這次掃描目標不一致；請先檢查目標。",
  },
  provider_preflight_unavailable: {
    en: "The cloud readiness check could not finish. No scan started. Check again.",
    zhTW: "雲端準備狀態尚未檢查完成；掃描尚未開始。請重新檢查。",
  },
  workspace_snapshot_unavailable: {
    en: "The saved local copy is missing or changed. Choose the local project again before scanning.",
    zhTW: "掃描用的本機副本已遺失或有變更；請重新選擇本機專案後再掃描。",
  },
  egress_gateway_unavailable: {
    en: "An installed scan component is missing or changed. Get the latest installer; your local scan projects will stay on this device.",
    zhTW: "一項隨附的掃描元件已遺失或變更。請取得最新安裝程式；這台電腦上的掃描專案會完整保留。",
  },
  engine_execution_contract_invalid: {
    en: "A required installed scan component is missing or out of date. Get the latest installer; your local scan projects will stay on this device.",
    zhTW: "一項必要的隨附掃描元件已遺失或過期。請取得最新安裝程式；這台電腦上的掃描專案會完整保留。",
  },
  passive_source_unavailable: {
    en: "The saved read-only data source is missing or changed. Reconnect it before scanning.",
    zhTW: "已保存的唯讀資料來源已遺失或有變更；請重新連接後再掃描。",
  },
  captured_evidence_unavailable: {
    en: "The saved results needed to continue are missing or changed. Nothing was rerun. Review what remains, then start a new scan for fresh results.",
    zhTW: "續跑所需的已保存結果已遺失或有變更；這次沒有重新執行任何檢查。請查看目前仍可用的結果，再開始新的掃描取得新結果。",
  },
  execution_preflight_unavailable: {
    en: "The final readiness check could not finish. No scan started. Check again.",
    zhTW: "最後的準備狀態檢查尚未完成；掃描尚未開始。請重新檢查。",
  },
} as const satisfies Partial<Record<ScanReadinessBlocker, BilingualText>>;

const isTerminalRun = (run: ScanRun): boolean =>
  ["completed", "partial", "failed", "cancelled"].includes(run.status);

export default function App() {
  const { locale, setLocale, text, formatNumber } = useI18n();
  const [page, setPage] = useState<PageId>(pageFromHash);
  const [snapshot, setSnapshot] = useState<AppSnapshot>();
  const [mode, setMode] = useState<AppMode>(scannerService.isNative() ? "native" : "demo");
  const [notice, setNotice] = useState<string | undefined>(scannerService.isNative() ? undefined : getDemoNotice());
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string>();
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [artifactCleanupPlan, setArtifactCleanupPlan] = useState<CaseArtifactDeletionPlan>();
  const [artifactCleanupResult, setArtifactCleanupResult] = useState<CaseArtifactCleanupResult>();
  const [runtimeSetup, setRuntimeSetup] = useState<ManagedRuntimeSetupStatus>();
  const [runtimeAutomaticAttemptFailed, setRuntimeAutomaticAttemptFailed] = useState(false);
  const [scanReadiness, setScanReadiness] = useState<ScanReadiness>();
  const [scanReadinessErrorCaseId, setScanReadinessErrorCaseId] = useState<string>();
  const [runtimeSetupFocusKey, setRuntimeSetupFocusKey] = useState(0);
  const [focusedFindingId, setFocusedFindingId] = useState<string>();
  const [verificationBaselineRunId, setVerificationBaselineRunId] = useState<string>();
  const [selectedUseCase, setSelectedUseCase] = useState<{
    definition: UseCaseDefinition;
    selectionKey: number;
  }>();
  const [appUpdate, setAppUpdate] = useState<AppUpdateState>({
    phase: scannerService.isNative() ? "checking" : "unavailable",
  });
  const toastId = useRef(0);
  const snapshotLocale = useRef(locale);
  const scanReadinessRequestGeneration = useRef(0);
  const automaticRuntimeSetupAttempted = useRef(false);

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
    const readinessRequestGeneration = ++scanReadinessRequestGeneration.current;
    if (!quiet) setLoading(true);
    try {
      const result = await scannerService.getSnapshot(caseId);
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
      applyServiceMeta(result);
      setSnapshot(result.data);
      const readinessCaseId = result.data.workspace?.case.id;
      if (readinessCaseId) {
        try {
          const readiness = await scannerService.getScanReadiness(readinessCaseId);
          if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
          if (!isCurrentScanReadinessResponse(
            scanReadinessRequestGeneration.current,
            readinessRequestGeneration,
            readinessCaseId,
            readiness.data.caseId,
          )) throw new Error("scan readiness response did not match the requested case");
          setScanReadiness(readiness.data);
          setScanReadinessErrorCaseId(undefined);
        } catch (error) {
          if (isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) {
            setScanReadiness(undefined);
            setScanReadinessErrorCaseId(readinessCaseId);
            recordTechnicalError("check scan readiness", error);
          }
        }
      } else if (isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) {
        setScanReadiness(undefined);
        setScanReadinessErrorCaseId(undefined);
      }
      setArtifactCleanupPlan((current) => current ?? result.data.artifactCleanupObligations?.[0]);
    } catch (error) {
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
      recordTechnicalError("load local cases", error);
      if (!quiet) {
        pushToast({
          tone: "danger",
          title: text({ en: "Scan projects could not be loaded", zhTW: "目前無法讀取掃描專案" }),
          detail: text({
            en: "Nothing was changed. Keep the app open and try again.",
            zhTW: "這次沒有更動任何資料；請讓程式保持開啟並再試一次。",
          }),
        });
      }
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [applyServiceMeta, pushToast, text]);

  useEffect(() => {
    void loadSnapshot();
  }, [loadSnapshot]);

  useEffect(() => {
    if (snapshotLocale.current === locale) return;
    snapshotLocale.current = locale;
    if (snapshot) void loadSnapshot(snapshot.selectedCaseId, true);
  }, [loadSnapshot, locale, snapshot?.selectedCaseId]);

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

  const runtimeSetupPolling = busyAction === "runtime-setup"
    || busyAction === "runtime-repair"
    || runtimeSetup?.active === true
    || runtimeSetup?.prerequisiteRepairActive === true;

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
      recordTechnicalError("install update", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The app update did not finish", zhTW: "應用程式更新未完成" }),
        detail: text({
          en: "Your scan projects were not changed. Check the connection and try again.",
          zhTW: "掃描專案沒有被更動；請確認網路連線後再試一次。",
        }),
      });
    }
  }, [pushToast, text]);

  const setupManagedRuntime = async ({ automatic = false }: { automatic?: boolean } = {}) => {
    setRuntimeAutomaticAttemptFailed(false);
    setBusyAction("runtime-setup");
    try {
      const result = await scannerService.setupManagedRuntime();
      applyServiceMeta(result);
      const setupResult = await scannerService.getManagedRuntimeSetupStatus();
      setRuntimeSetup(setupResult.data);
      if (!result.data.accepted && setupResult.data.phase === "idle") {
        setRuntimeAutomaticAttemptFailed(true);
      }
      await loadSnapshot(snapshot?.selectedCaseId, true);
      const cancelled = setupResult.data.phase === "cancelled";
      if (!automatic && !result.data.accepted && !cancelled) {
        window.location.hash = "start";
        setPage("start");
      }
      pushToast({
        tone: result.data.accepted ? "success" : "warning",
        title: result.data.accepted
          ? text({ en: "The private scan engine is ready", zhTW: "私有掃描引擎已就緒" })
          : cancelled
            ? text({ en: "Scan-engine setup was stopped", zhTW: "已停止掃描引擎設定" })
            : text({ en: "One setup step still needs attention", zhTW: "設定還有一個步驟需要處理" }),
        detail: result.data.accepted
          ? automatic
            ? text({
              en: "Setup is complete. You can start using ai-security-scanner.",
              zhTW: "安裝已完成，現在可以直接使用 ai-security-scanner。",
            })
            : text({
              en: "You can continue with your chosen check.",
              zhTW: "現在可以繼續設定你選擇的檢查。",
            })
          : automatic
            ? text({
              en: "Existing results remain available. Use the one setup action shown when you are ready.",
              zhTW: "既有結果仍可查看；準備好時，再使用畫面顯示的唯一設定操作。",
            })
            : text({
              en: "Follow the step shown on the start page, then check again.",
              zhTW: "請照首頁顯示的步驟處理，再重新檢查。",
            }),
      });
    } catch (error) {
      setRuntimeAutomaticAttemptFailed(true);
      recordTechnicalError("prepare managed runtime", error);
      pushToast({
        tone: "danger",
        title: text({ en: "Scan-engine setup could not start", zhTW: "掃描引擎設定無法開始" }),
        detail: text({
          en: "Nothing was changed. Return to the setup card and try again.",
          zhTW: "這次沒有變更任何設定；請回到設定卡片再試一次。",
        }),
      });
    } finally {
      setBusyAction(undefined);
    }
  };

  useEffect(() => {
    if (!shouldAutomaticallyPrepareRuntime(
      mode,
      snapshot?.runtime,
      runtimeSetup,
      automaticRuntimeSetupAttempted.current,
    )) return;
    automaticRuntimeSetupAttempted.current = true;
    void setupManagedRuntime({ automatic: true });
  }, [mode, runtimeSetup?.phase, snapshot?.runtime?.available, snapshot?.runtime?.phase, snapshot?.runtime?.provider]);

  const repairManagedRuntimePrerequisite = async () => {
    setBusyAction("runtime-repair");
    try {
      const result = await scannerService.repairManagedRuntimePrerequisite();
      applyServiceMeta(result);
      if (result.data.outcome === "cancelled") {
        pushToast({
          tone: "info",
          title: text({ en: "Windows made no changes", zhTW: "Windows 沒有進行變更" }),
          detail: text({
            en: "You can try again whenever you are ready.",
            zhTW: "準備好時可以再按一次，由程式重新處理。",
          }),
        });
        return;
      }
      if (result.data.restartRequired) {
        const latest = await scannerService.getManagedRuntimeSetupStatus();
        setRuntimeSetup(latest.data);
        pushToast({
          tone: "warning",
          title: text({ en: "Restart Windows once", zhTW: "請重新啟動 Windows 一次" }),
          detail: text({
            en: "The Windows change is complete. Reopen ai-security-scanner after the restart and setup will continue.",
            zhTW: "Windows 變更已完成；重新開機後再打開 ai-security-scanner，設定就會繼續。",
          }),
        });
        return;
      }

      // Re-run the existing read-only prerequisite check even after a
      // non-zero installer result. The probe is authoritative: it either
      // continues setup or shows the one remaining Windows action.
      await setupManagedRuntime();
    } catch (error) {
      recordTechnicalError("repair Windows runtime prerequisite", error);
      try {
        const latest = await scannerService.getManagedRuntimeSetupStatus();
        setRuntimeSetup(latest.data);
      } catch {
        // Keep the already-rendered recovery action when status refresh fails.
      }
      pushToast({
        tone: "danger",
        title: text({ en: "Windows setup could not start", zhTW: "無法啟動 Windows 設定" }),
        detail: text({
          en: "No change was made. Return to the setup card and try again.",
          zhTW: "這次沒有進行任何變更；請回到設定卡片再試一次。",
        }),
      });
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
          title: text({ en: "Stopping scan-engine setup", zhTW: "正在停止掃描引擎設定" }),
          detail: text({
            en: "The completed part of the download will be kept for the next attempt.",
            zhTW: "已完成的下載會保留，下次可以接著使用。",
          }),
        });
      }
    } catch (error) {
      recordTechnicalError("cancel managed runtime setup", error);
      pushToast({
        tone: "danger",
        title: text({ en: "Setup could not be stopped yet", zhTW: "目前無法停止設定" }),
        detail: text({
          en: "Setup is still safe to leave running. Try the stop button again in a moment.",
          zhTW: "設定仍可安全繼續；請稍後再按一次停止。",
        }),
      });
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
        if (disposed) unlisten();
        else unlisteners.push(unlisten);
      }),
    ).catch((error: unknown) => {
      if (!disposed) {
        recordTechnicalError("subscribe to desktop status", error);
        pushToast({
          tone: "warning",
          title: text({ en: "Live status is temporarily unavailable", zhTW: "即時狀態暫時無法使用" }),
          detail: text({
            en: "Saved work is unaffected. Reopen the case to refresh its status.",
            zhTW: "已保存的工作不受影響；重新開啟案件即可更新狀態。",
          }),
        });
      }
    });

    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, [loadSnapshot, pushToast, snapshot?.selectedCaseId, text]);

  const navigate = (target: PageId) => {
    if (target !== "findings") setFocusedFindingId(undefined);
    window.location.hash = target;
    setPage(target);
    document.getElementById("main-content")?.focus();
  };

  const selectCase = async (caseId: string) => {
    const readinessRequestGeneration = ++scanReadinessRequestGeneration.current;
    setLoading(true);
    try {
      const result = await scannerService.selectCase(caseId);
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
      applyServiceMeta(result);
      setSnapshot((current) => current ? { ...current, selectedCaseId: caseId, workspace: result.data } : current);
      try {
        const readiness = await scannerService.getScanReadiness(caseId);
        if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
        if (!isCurrentScanReadinessResponse(
          scanReadinessRequestGeneration.current,
          readinessRequestGeneration,
          caseId,
          readiness.data.caseId,
        )) throw new Error("scan readiness response did not match the selected case");
        setScanReadiness(readiness.data);
        setScanReadinessErrorCaseId(undefined);
      } catch (error) {
        if (isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) {
          setScanReadiness(undefined);
          setScanReadinessErrorCaseId(caseId);
          recordTechnicalError("check selected case scan readiness", error);
        }
      }
    } catch (error) {
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
      recordTechnicalError("select case", error);
      pushToast({
        tone: "danger",
        title: text({ en: "This scan project could not be opened", zhTW: "目前無法開啟這個掃描專案" }),
        detail: text({
          en: "The current scan project was left unchanged. Try opening it again.",
          zhTW: "目前掃描專案沒有被更動；請再開啟一次。",
        }),
      });
    } finally {
      setLoading(false);
    }
  };

  const retryScanReadiness = async (caseId: string) => {
    const readinessRequestGeneration = ++scanReadinessRequestGeneration.current;
    setBusyAction("scan-readiness");
    try {
      const result = await scannerService.getScanReadiness(caseId);
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
      if (!isCurrentScanReadinessResponse(
        scanReadinessRequestGeneration.current,
        readinessRequestGeneration,
        caseId,
        result.data.caseId,
      )) throw new Error("scan readiness response did not match the requested case");
      applyServiceMeta(result);
      setScanReadiness(result.data);
      setScanReadinessErrorCaseId(undefined);
    } catch (error) {
      if (isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) {
        setScanReadinessErrorCaseId(caseId);
        recordTechnicalError("retry scan readiness", error);
        pushToast({
          tone: "warning",
          title: text({ en: "Could not check yet", zhTW: "目前仍無法完成檢查" }),
          detail: text({
            en: "No scan started and nothing changed. Check again in a moment.",
            zhTW: "掃描尚未開始，也沒有變更任何資料；請稍後重新檢查。",
          }),
        });
      }
    } finally {
      setBusyAction(undefined);
    }
  };

  const createCase = async (input: CreateCaseInput): Promise<boolean> => {
    setBusyAction("create");
    try {
      const result = await scannerService.createCase(input);
      applyServiceMeta(result);
      await loadSnapshot(result.data.id, true);
      setSelectedUseCase(undefined);
      pushToast({
        tone: result.mode === "native" ? "success" : "info",
        title: result.mode === "native"
          ? text({ en: "Scan project created", zhTW: "掃描專案已建立" })
          : text({ en: "Demo scan project created", zhTW: "展示掃描專案已建立" }),
        detail: result.mode === "native"
          ? text({ en: "The scan project is saved on this device. No scan has started.", zhTW: "掃描專案已保存在這台電腦；尚未開始任何掃描。" })
          : text({ en: "It is saved only in this browser. No real target was contacted.", zhTW: "只保存在這個瀏覽器；沒有接觸任何真實目標。" }),
      });
      return true;
    } catch (error) {
      recordTechnicalError("create case", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The scan project was not created", zhTW: "掃描專案沒有建立成功" }),
        detail: text({ en: "Review the highlighted fields and try again.", zhTW: "請檢查畫面標示的欄位後再試一次。" }),
      });
      return false;
    } finally {
      setBusyAction(undefined);
    }
  };

  const executeAction = async (
    key: string,
    action: () => Promise<ServiceResult<ActionResponse>>,
  ): Promise<boolean> => {
    setBusyAction(key);
    try {
      const result = await action();
      applyServiceMeta(result);
      if (!result.data.accepted) recordTechnicalError(`action ${key} did not start`, result.data.message);
      const preflightCode = Object.keys(scanStartIssueCopy).find((code) => result.data.message.includes(`scan_preflight:${code}`)) as keyof typeof scanStartIssueCopy | undefined;
      pushToast({
        tone: result.data.accepted ? "success" : result.mode === "demo" ? "info" : "warning",
        title: result.data.accepted
          ? text({ en: "Local work started", zhTW: "本機工作已開始" })
          : result.mode === "demo"
            ? text({ en: "Demo mode did not run a scan", zhTW: "展示模式沒有執行掃描" })
            : text({ en: "The work did not start", zhTW: "工作尚未開始" }),
        detail: result.data.accepted
          ? text({ en: "Open Scan progress to follow each scanner.", zhTW: "可到「掃描進度」查看每個工具的狀態。" })
          : preflightCode
            ? text(scanStartIssueCopy[preflightCode])
          : text({ en: "No target was contacted. Check the current step and try again.", zhTW: "沒有接觸任何目標；請確認目前步驟後再試一次。" }),
      });
      if (result.data.snapshot) setSnapshot(result.data.snapshot);
      else if (result.mode === "native") await loadSnapshot(snapshot?.selectedCaseId, true);
      return result.data.accepted;
    } catch (error) {
      recordTechnicalError(`run action ${key}`, error);
      pushToast({
        tone: "danger",
        title: text({ en: "The local work could not finish", zhTW: "本機工作未能完成" }),
        detail: text({ en: "Saved scan data was kept. Check the current step before trying again.", zhTW: "已保存的掃描資料仍保留；請確認目前步驟後再試一次。" }),
      });
      return false;
    } finally {
      setBusyAction(undefined);
    }
  };

  const runAction = async (
    key: string,
    action: () => Promise<ServiceResult<ActionResponse>>,
  ): Promise<void> => {
    await executeAction(key, action);
  };

  const deleteCase = async (caseId: string, confirmation: string): Promise<boolean> => {
    setBusyAction("delete-case");
    try {
      const result = await scannerService.deleteCase(caseId, confirmation);
      applyServiceMeta(result);
      pushToast({
        tone: result.data.accepted ? "success" : result.mode === "demo" ? "info" : "warning",
        title: result.data.accepted
          ? text({ en: "Case record deleted", zhTW: "案件紀錄已刪除" })
          : result.mode === "demo"
            ? text({ en: "Demo mode did not delete the case", zhTW: "展示模式沒有刪除案件" })
            : text({ en: "The case was not deleted", zhTW: "案件沒有被刪除" }),
        detail: result.data.accepted
          ? text({ en: "Local evidence is still present until you confirm its separate cleanup.", zhTW: "本機證據仍保留，直到你另外確認清理為止。" })
          : text({ en: "No case data was changed.", zhTW: "案件資料沒有被更動。" }),
      });
      if (result.data.accepted) {
        setArtifactCleanupPlan(result.data.artifacts);
        setArtifactCleanupResult(undefined);
        await loadSnapshot(undefined, true);
      }
      return result.data.accepted;
    } catch (error) {
      recordTechnicalError("delete case", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The case was not deleted", zhTW: "案件沒有被刪除" }),
        detail: text({ en: "Nothing was changed. Confirm the exact case name and try again.", zhTW: "這次沒有更動資料；請確認完整案件名稱後再試一次。" }),
      });
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
        title: result.data.removed
          ? text({ en: "Case evidence was permanently deleted", zhTW: "案件證據已永久刪除" })
          : text({ en: "The evidence folder was not deleted", zhTW: "證據資料夾沒有被刪除" }),
        detail: result.data.removed
          ? text(
            { en: "{path} was deleted and cannot be recovered.", zhTW: "{path} 已刪除，而且無法復原。" },
            { path: result.data.exactPath },
          )
          : text(
            { en: "{path} was already absent or was left unchanged.", zhTW: "{path} 原本就不存在，或這次沒有被移除。" },
            { path: result.data.exactPath },
          ),
      });
      return result.data.removed;
    } catch (error) {
      recordTechnicalError("delete case artifacts", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The evidence folder was not deleted", zhTW: "證據資料夾沒有被刪除" }),
        detail: text({ en: "Nothing was removed. Check the exact path and confirmation, then try again.", zhTW: "這次沒有移除任何檔案；請確認精確路徑與確認文字後再試一次。" }),
      });
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
        pushToast({
          tone: "info",
          title: text({ en: "Export cancelled", zhTW: "已取消匯出" }),
          detail: text({ en: "No file was created or written.", zhTW: "沒有建立或寫出任何檔案。" }),
        });
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
        title: result.mode === "native"
          ? text({ en: "Case exported", zhTW: "案件已匯出" })
          : text({ en: "Demo file downloaded", zhTW: "展示檔已下載" }),
        detail: result.mode === "native"
          ? text(
            { en: "{fileName} was written to the location you selected.", zhTW: "{fileName} 已寫入你選擇的位置。" },
            { fileName: exported.fileName },
          )
          : text({
            en: "The file is marked DEMO_ONLY_NOT_A_SCAN and is not a scan report.",
            zhTW: "檔案已標示 DEMO_ONLY_NOT_A_SCAN，不能當成掃描報告。",
          }),
      });
    } catch (error) {
      recordTechnicalError("export case", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The case was not exported", zhTW: "案件沒有匯出成功" }),
        detail: text({ en: "No output file was written. Choose a destination and try again.", zhTW: "沒有寫出檔案；請選擇目的地後再試一次。" }),
      });
    } finally {
      setBusyAction(undefined);
    }
  };

  const verifyExport = async (path: string) => {
    setBusyAction("verify-export");
    try {
      const result = await scannerService.verifyCaseExport(path);
      applyServiceMeta(result);
      pushToast({
        tone: result.data.accepted ? "success" : "info",
        title: result.data.accepted
          ? text({ en: "Integrity check complete", zhTW: "完整性檢查完成" })
          : text({ en: "This demo file cannot be verified", zhTW: "這份展示檔無法驗證" }),
        detail: result.data.accepted
          ? text({ en: "The case package matches its signed integrity record.", zhTW: "案件包與簽署的完整性紀錄一致。" })
          : text({ en: "No real case package was changed.", zhTW: "沒有更動任何真實案件包。" }),
      });
    } catch (error) {
      recordTechnicalError("verify case export", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The file could not be verified", zhTW: "目前無法驗證這個檔案" }),
        detail: text({
          en: "The file was not changed. Choose it again, or ask the sender for a new case package.",
          zhTW: "檔案沒有被更動；請重新選擇，或請寄件者提供新的案件包。",
        }),
      });
    } finally {
      setBusyAction(undefined);
    }
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
          <strong>{text({ en: "Loading scan projects from this device…", zhTW: "正在讀取這台電腦上的掃描專案…" })}</strong>
          <span>{text({
            en: "If the desktop service is unavailable, the app will clearly switch to demo data.",
            zhTW: "如果桌面服務無法使用，產品會清楚切換成展示資料。",
          })}</span>
        </div>
      );
    }

    if (page === "start") {
      return (
        <StartPage
          locale={locale}
          copy={startPageCopy[locale]}
          setupFocusKey={runtimeSetupFocusKey}
          setup={
            <RuntimeSetupAssistant
              locale={locale}
              mode={mode}
              runtime={snapshot?.runtime}
              status={runtimeSetup}
              busy={["runtime-setup", "runtime-repair"].includes(busyAction ?? "")
                || runtimeSetup?.active
                || runtimeSetup?.prerequisiteRepairActive}
              repairing={busyAction === "runtime-repair" || runtimeSetup?.prerequisiteRepairActive}
              scannerSetupBlocker={scanReadiness && scanReadiness.caseId === currentCaseId && isScannerSetupBlocker(scanReadiness.blockerCode)
                ? scanReadiness.blockerCode
                : undefined}
              onSetup={() => void setupManagedRuntime()}
              onRepair={() => void repairManagedRuntimePrerequisite()}
              onCancel={() => void cancelManagedRuntimeSetup()}
            />
          }
          onChoose={(definition) => {
            setSelectedUseCase((current) => ({
              definition,
              selectionKey: (current?.selectionKey ?? 0) + 1,
            }));
            navigate("cases");
          }}
          onOpenExistingCase={snapshot?.cases.length ? () => navigate("cases") : undefined}
        />
      );
    }

    if (page === "cases") {
      return (
        <CasesPage
          cases={snapshot?.cases ?? []}
          selectedCase={selectedCase}
          selectedUseCase={selectedUseCase?.definition.id}
          selectionKey={selectedUseCase?.selectionKey}
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
          onClearPreset={() => {
            setSelectedUseCase(undefined);
            navigate("start");
          }}
          onCreate={createCase}
          onArchive={(caseId) => runAction("archive-case", () => scannerService.archiveCase(caseId))}
          onDelete={deleteCase}
          onDeleteArtifacts={deleteCaseArtifacts}
          onDismissArtifactCleanup={dismissArtifactCleanup}
          onStartNewScan={() => {
            setSelectedUseCase(undefined);
            navigate("start");
          }}
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
          title={text({ en: "Create or choose a scan project first", zhTW: "請先建立或選擇掃描專案" })}
          description={text({
            en: "Keep targets, results, reports, and follow-up checks together in one place.",
            zhTW: "把目標、結果、報告與後續確認集中放在同一個地方。",
          })}
          action={
            <button className="button button--primary" type="button" onClick={() => navigate("cases")}>
              {text({ en: "Open my scans", zhTW: "開啟我的掃描" })}
            </button>
          }
        />
      );
    }

    switch (page) {
      case "coverage":
        return (
          <CoveragePage
            caseId={currentCaseId}
            assessmentIntent={workspace.case.assessmentIntent}
            focusSetup={coverageSetupFocusFor(scanReadiness?.blockerCode)}
            requestedActivities={workspace.case.requestedActivities}
            coverage={workspace.coverage}
            sources={workspace.sources}
            assets={workspace.assets}
            scopeGrants={workspace.scopeGrants}
            nativeMode={mode === "native"}
            busy={busyAction === "connect-source" || busyAction === "attach-workspace" || busyAction === "discovery" || busyAction === "scope"}
            discoveryBusy={busyAction === "discovery"}
            onChooseSnapshot={() => scannerService.chooseSourceSnapshot()}
            onConnectSourceSnapshot={(input) => runAction("connect-source", () => scannerService.connectSourceSnapshot(input))}
            onChooseWorkspace={() => scannerService.chooseWorkspaceDirectory()}
            onAttachWorkspaceSnapshot={(input) => runAction("attach-workspace", () => scannerService.attachWorkspaceSnapshot(input))}
            onStartDiscovery={() => runAction("discovery", () => scannerService.startDiscovery(currentCaseId))}
            onAuthorizationChanged={() => loadSnapshot(currentCaseId, true)}
            onApprovePending={(assetIds, modes, confirmation, externalScope) => executeAction("scope", () => scannerService.approveScope({
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
            readiness={scanReadiness?.caseId === currentCaseId ? scanReadiness : undefined}
            readinessCheckFailed={scanReadinessErrorCaseId === currentCaseId}
            diagnosticContext={{
              productVersion: snapshot?.productVersion,
              runtime: snapshot?.runtime,
            }}
            busy={Boolean(busyAction)}
            onStart={() => runAction("start-scan", () => scannerService.startScan(currentCaseId))}
            onFixSetup={() => {
              if (scanReadinessErrorCaseId === currentCaseId) {
                void retryScanReadiness(currentCaseId);
                return;
              }
              if (isPackagedComponentBlocker(scanReadiness?.blockerCode)) {
                setRuntimeSetupFocusKey((key) => key + 1);
                navigate("start");
                return;
              }
              if (isScannerSetupBlocker(scanReadiness?.blockerCode) || scanReadiness?.nextStep === "scanner_setup") {
                setRuntimeSetupFocusKey((key) => key + 1);
                navigate("start");
                void setupManagedRuntime();
                return;
              }
              if (isReadinessRetryBlocker(scanReadiness?.blockerCode) || scanReadiness?.nextStep === "retry") {
                void retryScanReadiness(currentCaseId);
                return;
              }
              if (coverageSetupFocusFor(scanReadiness?.blockerCode)) {
                navigate("coverage");
                return;
              }
              navigate(scanReadiness?.nextStep === "cases" ? "cases" : "coverage");
            }}
            onOpenToolSetup={() => {
              setRuntimeSetupFocusKey((key) => key + 1);
              navigate("start");
            }}
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
            onUpdateWorkflow={(input) => executeAction("finding-workflow", () => scannerService.updateFindingWorkflow({ caseId: currentCaseId, ...input }))}
            onGroupFindings={(input) => executeAction("finding-group", () => scannerService.groupFindings({
              caseId: currentCaseId,
              groupedBy: text({ en: "Local user", zhTW: "本機使用者" }),
              ...input,
            }))}
            onUngroupFindings={(groupId) => runAction("finding-ungroup", () => scannerService.ungroupFindings({
              caseId: currentCaseId,
              groupId,
              removedBy: text({ en: "Local user", zhTW: "本機使用者" }),
              reason: text({
                en: "The user removed this presentation group from the Problems found page; original findings and evidence remain unchanged.",
                zhTW: "使用者從「發現的問題」頁面移除這個呈現群組；原始問題與證據完整保留。",
              }),
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

  const showRuntimeFirstLaunch = mode === "native"
    && snapshot !== undefined
    && shouldShowRuntimeFirstLaunch(
      mode,
      snapshot.runtime,
      snapshot.cases.length > 0,
    );

  return (
    <>
      {showRuntimeFirstLaunch ? (
        <RuntimeFirstLaunch
          locale={locale}
          setLocale={setLocale}
          runtime={snapshot?.runtime}
          status={runtimeSetup}
          busy={["runtime-setup", "runtime-repair"].includes(busyAction ?? "")
            || runtimeSetup?.active === true
            || runtimeSetup?.prerequisiteRepairActive === true}
          repairing={busyAction === "runtime-repair" || runtimeSetup?.prerequisiteRepairActive === true}
          automaticAttemptFailed={runtimeAutomaticAttemptFailed}
          onSetup={() => void setupManagedRuntime()}
          onRepair={() => void repairManagedRuntimePrerequisite()}
          onCancel={() => void cancelManagedRuntimeSetup()}
        />
      ) : (
        <AppShell
          page={page}
          mode={mode}
          cases={snapshot?.cases ?? []}
          selectedCase={selectedCase}
          loading={loading}
          onNavigate={navigate}
          onSelectCase={(caseId) => void selectCase(caseId)}
          demoNotice={notice ?? getDemoNotice()}
          appUpdate={appUpdate}
          onCheckForUpdate={() => void checkAppUpdate()}
          onInstallUpdate={(version) => void installUpdate(version)}
          runtime={snapshot?.runtime}
          runtimeSetup={runtimeSetup}
          runtimeBusy={["runtime-setup", "runtime-repair"].includes(busyAction ?? "")
            || runtimeSetup?.active
            || runtimeSetup?.prerequisiteRepairActive}
          runtimeRepairing={busyAction === "runtime-repair" || runtimeSetup?.prerequisiteRepairActive}
          onSetupRuntime={() => void setupManagedRuntime()}
          onRepairRuntime={() => void repairManagedRuntimePrerequisite()}
          onCancelRuntime={() => void cancelManagedRuntimeSetup()}
        >
          {content}
        </AppShell>
      )}

      <div
        className="toast-region"
        aria-live="polite"
        aria-label={text({ en: "Application notifications", zhTW: "應用程式通知" })}
      >
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast--${toast.tone}`}>
            <Icon name={toast.tone === "success" ? "check" : toast.tone === "danger" || toast.tone === "warning" ? "warning" : "info"} size={19} />
            <div><strong>{toast.title}</strong>{toast.detail && <span>{toast.detail}</span>}</div>
            <button
              type="button"
              aria-label={text({ en: "Close notification", zhTW: "關閉通知" })}
              onClick={() => setToasts((current) => current.filter((item) => item.id !== toast.id))}
            ><Icon name="close" size={16} /></button>
          </div>
        ))}
      </div>

      {busyAction && (
        <span className="sr-only" role="status">
          {text(
            { en: "Working on {action}", zhTW: "正在處理：{action}" },
            { action: text(busyActionCopy[busyAction as keyof typeof busyActionCopy] ?? unknownBusyActionCopy) },
          )}
        </span>
      )}
      {currentRun?.status === "running" && (
        <span className="sr-only" aria-live="polite">
          {text(
            { en: "Current scan progress: {progress}%", zhTW: "目前掃描進度：{progress}%" },
            { progress: formatNumber(currentRun.progress, { maximumFractionDigits: 1 }) },
          )}
        </span>
      )}
    </>
  );
}
