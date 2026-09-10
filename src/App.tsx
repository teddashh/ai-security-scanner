import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { AppShell } from "./components/AppShell";
import { Icon } from "./components/Icon";
import { RuntimeSetupAssistant } from "./components/RuntimeSetupAssistant";
import { EmptyState, InlineNotice } from "./components/Shared";
import { useI18n, type BilingualText } from "./i18n";
import { CasesPage } from "./pages/CasesPage";
import { CoveragePage } from "./pages/CoveragePage";
import { ExportPage } from "./pages/ExportPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ProgressPage } from "./pages/ProgressPage";
import { SettingsPage } from "./pages/SettingsPage";
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
  deriveScanLifecycleDisposition,
  scanLifecycleToastPresentation,
} from "./scanLifecycleDisposition";
import { findRunCreatedAfterStart, hasActiveScanWork } from "./freshScanSelection";
import { reconcileReportRunId } from "./exportRunSelection";
import { isSecurityFinding } from "./findingClassification";
import {
  afterLatestCaseSelection,
  appendExportToMatchingSnapshot,
  selectVerificationBaselineRunId,
} from "./caseScopedUiState";
import { isExactBuiltInLocalhostQuickScanRun } from "./localhostQuickScan";
import {
  cloneRuntimeDeferredScanInput,
  shouldPrepareRuntimeBeforeScanAction,
  shouldStartRuntimePreparedScan,
  shouldShowRuntimeSetupAssistant,
} from "./runtimeFirstLaunch";
import {
  hasManagedRuntimeSetupRequestStarted,
  isManagedRuntimePackageAdmissionFailure,
  isManagedRuntimeSetupTerminal,
  type ManagedRuntimeSetupRequestBaseline,
} from "./runtimeSetupPresentation";
import {
  checkForAppUpdate,
  installAppUpdate,
  type AppUpdateState,
} from "./services/appUpdater";
import {
  createInFlightReadCoalescer,
  observePromiseWithin,
  settleReadOnlyWithin,
} from "./services/boundedReadOnly";
import {
  EVENTS,
  scannerService,
  type ActionResponse,
  type CaseExportVerificationResult,
  type StartScanInput,
} from "./services/scanner";
import { subscribeAllThenReconcile } from "./services/bufferedEventSubscription";
import {
  mergeWorkspaceIntoSnapshot,
  reconcileAuthoritativeSnapshot,
  selectNewerWorkspaceByRevision,
} from "./snapshotWorkspace";
import { startPageCopy, type UseCaseDefinition } from "./useCases";
import { displaySafeTechnicalDetail } from "./technicalDetails";
import type {
  AppMode,
  AppSnapshot,
  AttachWorkspaceSnapshotInput,
  CaseArtifactCleanupResult,
  CaseArtifactDeletionPlan,
  CaseWorkspace,
  CorrelationReport,
  CreateCaseInput,
  ExportPreview,
  ExportFormat,
  ReportLocale,
  ManagedRuntimeSetupStatus,
  PageId,
  ScanReadiness,
  ScanReadinessBlocker,
  ScanRun,
  ServiceResult,
  ToastMessage,
} from "./types";

interface AppToastMessage extends ToastMessage {
  persistent?: boolean;
  actionLabel?: string;
  actionLabelText?: BilingualText;
  titleText?: BilingualText;
  detailText?: BilingualText;
  actionCaseId?: string;
  actionPage?: PageId;
  action?: () => void;
}

interface PendingRuntimeScanStart {
  input: StartScanInput;
  page: PageId;
  pageTransitionGeneration: number;
  caseSelectionGeneration: number;
  setupCommandGeneration: number;
}

interface RuntimeSetupCompletion {
  setupCommandGeneration: number;
  phase: ManagedRuntimeSetupStatus["phase"];
  operationId?: string;
}

interface RuntimeSetupCompletionSnapshot {
  completion: RuntimeSetupCompletion;
  snapshot: AppSnapshot | undefined;
}

const pageFromHash = (): PageId => {
  const value = window.location.hash.replace(/^#\/?/, "") as PageId;
  return ["start", "cases", "coverage", "progress", "findings", "export", "settings", "verification"].includes(value)
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
  create: { en: "scan project creation", zhTW: "建立掃描專案" },
  "create-local": { en: "local scan project setup", zhTW: "建立本機掃描專案" },
  "archive-case": { en: "case archiving", zhTW: "封存案件" },
  "delete-case": { en: "case-record deletion", zhTW: "刪除案件紀錄" },
  "delete-artifacts": { en: "evidence deletion", zhTW: "刪除證據" },
  rescan: { en: "the follow-up scan", zhTW: "複驗掃描" },
  "connect-source": { en: "source connection", zhTW: "連接資料來源" },
  "attach-workspace": { en: "local-file attachment", zhTW: "附加本機檔案" },
  discovery: { en: "asset discovery", zhTW: "盤點資產" },
  scope: { en: "permission confirmation", zhTW: "確認授權範圍" },
  "localhost-quick-scan": { en: "testing a local service connection", zhTW: "測試本機服務連線" },
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

const caseExportVerificationCopy = {
  verified: {
    tone: "success",
    title: { en: "Integrity check complete", zhTW: "完整性檢查完成" },
    detail: { en: "The case package matches its signed integrity record.", zhTW: "案件包與簽署的完整性紀錄一致。" },
  },
  native_failed: {
    tone: "danger",
    title: { en: "Integrity check failed", zhTW: "完整性檢查失敗" },
    detail: {
      en: "Do not trust or share this package. Choose it again, or ask the sender for a new case package.",
      zhTW: "請勿信任或分享這份案件包；請重新選擇，或請寄件者提供新的案件包。",
    },
  },
  demo_unavailable: {
    tone: "info",
    title: { en: "This demo file cannot be verified", zhTW: "這份展示檔無法驗證" },
    detail: { en: "No real case package was changed.", zhTW: "沒有更動任何真實案件包。" },
  },
} as const satisfies Record<CaseExportVerificationResult["outcome"], {
  tone: ToastMessage["tone"];
  title: BilingualText;
  detail: BilingualText;
}>;

interface NonExecutionActionToastCopy {
  acceptedTitle: BilingualText;
  acceptedDetail: BilingualText;
  failedTitle: BilingualText;
  failedDetail: BilingualText;
}

const nonExecutionActionToastCopy = {
  "attach-workspace": {
    acceptedTitle: { en: "Project prepared locally", zhTW: "專案已在本機準備完成" },
    acceptedDetail: { en: "Private copy verified. Review the checks, then start.", zhTW: "私密副本已驗證；請檢查掃描項目後開始。" },
    failedTitle: { en: "Project was not prepared", zhTW: "專案尚未準備完成" },
    failedDetail: { en: "Choose the local project again.", zhTW: "請重新選擇本機專案。" },
  },
  scope: {
    acceptedTitle: { en: "Scan access saved", zhTW: "掃描許可已儲存" },
    acceptedDetail: { en: "The exact target and limits are saved.", zhTW: "確切目標與限制已儲存。" },
    failedTitle: { en: "Scan access was not saved", zhTW: "掃描許可尚未儲存" },
    failedDetail: { en: "Review the selected target and permission, then try again.", zhTW: "請檢查所選目標與許可後再試一次。" },
  },
  "archive-case": {
    acceptedTitle: { en: "Change saved", zhTW: "變更已儲存" },
    acceptedDetail: { en: "The scan project was moved to the archive.", zhTW: "掃描專案已移至封存區。" },
    failedTitle: { en: "Change was not saved", zhTW: "變更尚未儲存" },
    failedDetail: { en: "Try archiving the scan project again.", zhTW: "請再試一次封存掃描專案。" },
  },
  "finding-workflow": {
    acceptedTitle: { en: "Change saved", zhTW: "變更已儲存" },
    acceptedDetail: { en: "The problem's review status was updated.", zhTW: "問題的審查狀態已更新。" },
    failedTitle: { en: "Change was not saved", zhTW: "變更尚未儲存" },
    failedDetail: { en: "Try updating the review status again.", zhTW: "請再試一次更新審查狀態。" },
  },
  "finding-group": {
    acceptedTitle: { en: "Change saved", zhTW: "變更已儲存" },
    acceptedDetail: { en: "The related problems were grouped.", zhTW: "相關問題已分組。" },
    failedTitle: { en: "Change was not saved", zhTW: "變更尚未儲存" },
    failedDetail: { en: "Try grouping the problems again.", zhTW: "請再試一次將問題分組。" },
  },
  "finding-ungroup": {
    acceptedTitle: { en: "Change saved", zhTW: "變更已儲存" },
    acceptedDetail: { en: "The group was removed.", zhTW: "群組已移除。" },
    failedTitle: { en: "Change was not saved", zhTW: "變更尚未儲存" },
    failedDetail: { en: "Try removing the group again.", zhTW: "請再試一次移除群組。" },
  },
  "connect-source": {
    acceptedTitle: { en: "Source prepared", zhTW: "資料來源已準備完成" },
    acceptedDetail: { en: "The read-only source is ready for review.", zhTW: "唯讀資料來源已準備好，可供檢查。" },
    failedTitle: { en: "Source was not prepared", zhTW: "資料來源尚未準備完成" },
    failedDetail: { en: "Check the selected source and try again.", zhTW: "請檢查所選資料來源後再試一次。" },
  },
  discovery: {
    acceptedTitle: { en: "Asset list updated", zhTW: "資產清單已更新" },
    acceptedDetail: { en: "Review the items found.", zhTW: "請檢視找到的項目。" },
    failedTitle: { en: "Asset list was not updated", zhTW: "資產清單尚未更新" },
    failedDetail: { en: "Check the source setup and try again.", zhTW: "請檢查資料來源設定後再試一次。" },
  },
} as const satisfies Partial<Record<keyof typeof busyActionCopy, NonExecutionActionToastCopy>>;

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
    en: "This version has no working scan tool for this target. Install the latest version.",
    zhTW: "目前版本沒有可執行這個目標的掃描工具；請安裝最新版本。",
  },
  runtime_unavailable: {
    en: "Prepare the required local scan tools, then start the scan.",
    zhTW: "請準備必要的本機掃描工具，再開始掃描。",
  },
  provider_source_required: {
    en: "Connect the cloud account you want to scan.",
    zhTW: "請連接你要掃描的雲端帳號。",
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
    en: "The cloud readiness check did not finish. Check again.",
    zhTW: "雲端準備狀態檢查未完成；請重新檢查。",
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
    en: "Saved results needed to continue are missing or changed. Start a new scan.",
    zhTW: "續跑所需的已保存結果已遺失或有變更；請開始新的掃描。",
  },
  resume_release_incompatible: {
    en: "This unfinished scan was created by a different app release. Start a new scan with this release.",
    zhTW: "這個未完成的掃描由不同版本的應用程式建立；請使用目前版本開始新的掃描。",
  },
  resume_work_plan_invalid: {
    en: "This saved check no longer matches its original target plan. Start a new scan.",
    zhTW: "這項已保存的檢查已無法對應原本的目標計畫；請開始新的掃描。",
  },
  execution_preflight_unavailable: {
    en: "The final readiness check did not finish. Check again.",
    zhTW: "最後的準備狀態檢查未完成；請重新檢查。",
  },
} as const satisfies Partial<Record<ScanReadinessBlocker | "resume_release_incompatible" | "resume_work_plan_invalid", BilingualText>>;

const isTerminalRun = (run: ScanRun): boolean =>
  ["completed", "partial", "failed", "cancelled"].includes(run.status);

const ACTIVE_SCAN_REFRESH_INTERVAL_MS = 5_000;
const RUNTIME_TRUTH_REFRESH_INTERVAL_MS = 10_000;
const RUNTIME_TRUTH_READ_TIMEOUT_MS = 8_000;
const RUNTIME_SETUP_COMMAND_UI_TIMEOUT_MS = 8_000;
const SELECTED_SNAPSHOT_READ_KEY = "__currently_selected_case__";
const MANAGED_RUNTIME_STATUS_READ_KEY = "__managed_runtime_setup_status__";

export default function App() {
  const { locale, setLocale, t, text, formatNumber } = useI18n();
  const [page, setPage] = useState<PageId>(pageFromHash);
  const [snapshot, setSnapshot] = useState<AppSnapshot>();
  const [mode, setMode] = useState<AppMode>(scannerService.isNative() ? "native" : "demo");
  const [loading, setLoading] = useState(true);
  const [snapshotRefreshUnavailable, setSnapshotRefreshUnavailable] = useState(false);
  const [caseSelectionUnavailableId, setCaseSelectionUnavailableId] = useState<string>();
  const [busyAction, setBusyAction] = useState<string>();
  const [startingScanCaseId, setStartingScanCaseId] = useState<string>();
  const [toasts, setToasts] = useState<AppToastMessage[]>([]);
  const [artifactCleanupPlan, setArtifactCleanupPlan] = useState<CaseArtifactDeletionPlan>();
  const [artifactCleanupResult, setArtifactCleanupResult] = useState<CaseArtifactCleanupResult>();
  const [runtimeSetup, setRuntimeSetup] = useState<ManagedRuntimeSetupStatus>();
  const [runtimeSetupCompletion, setRuntimeSetupCompletion] = useState<RuntimeSetupCompletion>();
  const [runtimeSetupCompletionSnapshot, setRuntimeSetupCompletionSnapshot] = useState<RuntimeSetupCompletionSnapshot>();
  const [runtimeSetupCommandPolling, setRuntimeSetupCommandPolling] = useState(false);
  const [runtimeSetupAdmissionPending, setRuntimeSetupAdmissionPending] = useState(false);
  const [scanReadiness, setScanReadiness] = useState<ScanReadiness>();
  const [scanReadinessErrorCaseId, setScanReadinessErrorCaseId] = useState<string>();
  const [runtimeSetupFocusKey, setRuntimeSetupFocusKey] = useState(0);
  const [focusedFindingId, setFocusedFindingId] = useState<string>();
  const [correlationReport, setCorrelationReport] = useState<CorrelationReport>();
  const correlationRequestGeneration = useRef(0);
  const [selectedReportRunId, setSelectedReportRunId] = useState<string>();
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
  const scanReadinessResponseGeneration = useRef(0);
  const selectedCaseIdRef = useRef<string | undefined>(undefined);
  const currentPageRef = useRef<PageId>(page);
  const pageTransitionGeneration = useRef(0);
  const caseSelectionBarrierRef = useRef({
    generation: 0,
    settled: Promise.resolve(),
    superseded: new Promise<void>(() => undefined),
  });
  const supersedeCaseSelectionRef = useRef<() => void>(() => undefined);
  const reportSelectionCaseIdRef = useRef<string | undefined>(undefined);
  const verificationBaselineCaseIdRef = useRef<string | undefined>(undefined);
  const scanWorkspaceEventGeneration = useRef(0);
  const observedScanWorkspaces = useRef(new Map<string, {
    generation: number;
    workspace: CaseWorkspace;
    freshestWorkspace: CaseWorkspace;
  }>());
  const runtimeSetupStatusRequestGeneration = useRef(0);
  const runtimeSetupStatusRefreshInFlight = useRef<Promise<ManagedRuntimeSetupStatus | undefined> | undefined>(undefined);
  const runtimeSetupStatusReadCoalescer = useRef(
    createInFlightReadCoalescer<string, ServiceResult<ManagedRuntimeSetupStatus>>(),
  ).current;
  const runtimeSnapshotRefreshInFlight = useRef<Promise<AppSnapshot | undefined> | undefined>(undefined);
  const snapshotReadCoalescer = useRef(
    createInFlightReadCoalescer<string, ServiceResult<AppSnapshot>>(),
  ).current;
  const scanReadinessReadCoalescer = useRef(
    createInFlightReadCoalescer<string, ServiceResult<ScanReadiness>>(),
  ).current;
  const runtimeSetupCommandGeneration = useRef(0);
  const pendingRuntimeScanStart = useRef<PendingRuntimeScanStart | undefined>(undefined);
  const runtimeSetupRequestAdmission = useRef<{
    baseline: ManagedRuntimeSetupRequestBaseline;
    setupCommandGeneration: number;
    minimumStatusRequestGeneration: number;
    observed: boolean;
  } | undefined>(undefined);
  const reconciledRuntimeTerminalKey = useRef<string | undefined>(undefined);

  const pushToast = useCallback((toast: Omit<AppToastMessage, "id">) => {
    const id = ++toastId.current;
    setToasts((current) => [...current, { ...toast, id }]);
    if (!toast.persistent) {
      window.setTimeout(() => setToasts((current) => current.filter((item) => item.id !== id)), 5200);
    }
  }, []);

  const applyServiceMeta = useCallback(<T,>(result: ServiceResult<T>) => {
    setMode(result.mode);
  }, []);

  const applyScanWorkspaceEvent = useCallback((workspace: CaseWorkspace) => {
    const generation = ++scanWorkspaceEventGeneration.current;
    const existing = observedScanWorkspaces.current.get(workspace.case.id);
    const freshestWorkspace = selectNewerWorkspaceByRevision(
      existing?.freshestWorkspace,
      workspace,
    );
    // Keep the payload received by this generation separate from the freshest
    // provable event payload. Pairing a new generation with an older payload
    // would let an unrelated stale event fabricate a post-action outcome.
    observedScanWorkspaces.current.set(workspace.case.id, {
      generation,
      workspace,
      freshestWorkspace,
    });
    setSnapshot((current) => mergeWorkspaceIntoSnapshot(current, workspace));
  }, []);

  const readScanReadinessWithin = useCallback(async (
    caseId: string,
    onLateResult: (result: ServiceResult<ScanReadiness>) => void,
    timeoutMs = RUNTIME_TRUTH_READ_TIMEOUT_MS,
  ): Promise<ServiceResult<ScanReadiness>> => {
    const readinessRead = scanReadinessReadCoalescer.read(
      caseId,
      () => scannerService.getScanReadiness(caseId),
    );
    const observation = await settleReadOnlyWithin(readinessRead, timeoutMs);
    if (observation.outcome === "timed_out") {
      // The UI may show Retry now, but the same uncancelled read remains the
      // authority. A Retry reuses it, and its late result can still reconcile.
      void readinessRead.then(onLateResult).catch((error: unknown) => {
        recordTechnicalError("apply late scan-readiness result", error);
      });
      throw new Error("read-only scan-readiness refresh timed out");
    }
    if (observation.outcome === "failed") throw observation.error;
    return observation.value;
  }, [scanReadinessReadCoalescer]);

  const loadSnapshot = useCallback(async (
    caseId?: string,
    quiet = false,
    readTimeoutMs = RUNTIME_TRUTH_READ_TIMEOUT_MS,
  ) => {
    const readinessRequestGeneration = ++scanReadinessRequestGeneration.current;
    const workspaceEventGenerationAtRequest = scanWorkspaceEventGeneration.current;

    const applySnapshotResult = async (result: ServiceResult<AppSnapshot>) => {
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
      applyServiceMeta(result);
      setSnapshotRefreshUnavailable(false);
      selectedCaseIdRef.current = result.data.selectedCaseId;
      setSnapshot((current) => reconcileAuthoritativeSnapshot(
        current,
        result.data,
        [...observedScanWorkspaces.current.values()]
          .filter((observed) => observed.generation > workspaceEventGenerationAtRequest)
          .map((observed) => selectNewerWorkspaceByRevision(
            observed.workspace,
            observed.freshestWorkspace,
          )),
      ));
      const readinessCaseId = result.data.workspace?.case.id;
      const readinessResponseGeneration = ++scanReadinessResponseGeneration.current;
      if (readinessCaseId) {
        const handleReadinessError = (error: unknown) => {
          if (
            isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)
            && isCurrentScanReadinessRequest(scanReadinessResponseGeneration.current, readinessResponseGeneration)
          ) {
            setScanReadiness(undefined);
            setScanReadinessErrorCaseId(readinessCaseId);
            recordTechnicalError("check scan readiness", error);
          }
        };
        const acceptReadiness = (readiness: ServiceResult<ScanReadiness>) => {
          if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
          if (!isCurrentScanReadinessResponse(
            scanReadinessResponseGeneration.current,
            readinessResponseGeneration,
            readinessCaseId,
            readiness.data.caseId,
          )) {
            handleReadinessError(new Error("scan readiness response did not match the requested case"));
            return;
          }
          setScanReadiness(readiness.data);
          setScanReadinessErrorCaseId(undefined);
        };
        try {
          const readiness = await readScanReadinessWithin(
            readinessCaseId,
            acceptReadiness,
            readTimeoutMs,
          );
          acceptReadiness(readiness);
        } catch (error) {
          handleReadinessError(error);
        }
      } else if (isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) {
        setScanReadiness(undefined);
        setScanReadinessErrorCaseId(undefined);
      }
      setArtifactCleanupPlan((current) => current ?? result.data.artifactCleanupObligations?.[0]);
      return result.data;
    };

    if (!quiet) setLoading(true);
    try {
      const snapshotRead = snapshotReadCoalescer.read(
        caseId ?? SELECTED_SNAPSHOT_READ_KEY,
        () => scannerService.getSnapshot(caseId),
      );
      const boundedSnapshotRead = await settleReadOnlyWithin(snapshotRead, readTimeoutMs);
      if (boundedSnapshotRead.outcome === "timed_out") {
        // Keep accepting the one underlying authoritative read. Repeated
        // focus/watchdog/Retry observations reuse it instead of queuing IPC.
        void snapshotRead.then((lateResult) => {
          void applySnapshotResult(lateResult).catch((error: unknown) => {
            if (isCurrentScanReadinessRequest(
              scanReadinessRequestGeneration.current,
              readinessRequestGeneration,
            )) recordTechnicalError("apply late snapshot result", error);
          });
        }).catch((error: unknown) => {
          if (isCurrentScanReadinessRequest(
            scanReadinessRequestGeneration.current,
            readinessRequestGeneration,
          )) recordTechnicalError("complete late snapshot read", error);
        });
        throw new Error("read-only snapshot refresh timed out");
      }
      if (boundedSnapshotRead.outcome === "failed") throw boundedSnapshotRead.error;
      return await applySnapshotResult(boundedSnapshotRead.value);
    } catch (error) {
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return undefined;
      recordTechnicalError("load local cases", error);
      setSnapshotRefreshUnavailable(true);
      if (!quiet) {
        pushToast({
          tone: "danger",
          title: text({ en: "Scan projects could not be loaded", zhTW: "目前無法讀取掃描專案" }),
          detail: text({
            en: "Keep the app open and try again.",
            zhTW: "請讓程式保持開啟並再試一次。",
          }),
        });
      }
      return undefined;
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [applyServiceMeta, pushToast, readScanReadinessWithin, snapshotReadCoalescer, text]);

  const refreshRuntimeSnapshot = useCallback(() => {
    if (runtimeSnapshotRefreshInFlight.current) return runtimeSnapshotRefreshInFlight.current;
    const refresh = loadSnapshot(selectedCaseIdRef.current, true, RUNTIME_TRUTH_READ_TIMEOUT_MS);
    runtimeSnapshotRefreshInFlight.current = refresh;
    void refresh.finally(() => {
      if (runtimeSnapshotRefreshInFlight.current === refresh) {
        runtimeSnapshotRefreshInFlight.current = undefined;
      }
    });
    return refresh;
  }, [loadSnapshot]);

  const refreshRuntimeSnapshotAfterCurrent = useCallback(async () => {
    // A runtime read that began before setup reached its terminal state cannot
    // prove the newly prepared tools are ready. Let it settle, then start a
    // read whose observation point is after that terminal state.
    const previousRefresh = runtimeSnapshotRefreshInFlight.current;
    if (previousRefresh) {
      try {
        await previousRefresh;
      } catch {
        // A fresh authoritative read is still the useful next step.
      }
      if (runtimeSnapshotRefreshInFlight.current === previousRefresh) {
        runtimeSnapshotRefreshInFlight.current = undefined;
      }
    }
    return refreshRuntimeSnapshot();
  }, [refreshRuntimeSnapshot]);

  useEffect(() => {
    void loadSnapshot();
  }, [loadSnapshot]);

  useEffect(() => {
    if (snapshotLocale.current === locale) return;
    snapshotLocale.current = locale;
    if (snapshot) void loadSnapshot(snapshot.selectedCaseId, true);
  }, [loadSnapshot, locale, snapshot?.selectedCaseId]);

  useEffect(() => {
    selectedCaseIdRef.current = snapshot?.selectedCaseId;
  }, [snapshot?.selectedCaseId]);

  useEffect(() => {
    const pending = pendingRuntimeScanStart.current;
    if (
      pending
      && (pending.page !== page || pending.input.caseId !== snapshot?.selectedCaseId)
    ) {
      pendingRuntimeScanStart.current = undefined;
    }
  }, [page, snapshot?.selectedCaseId]);

  const refreshManagedRuntimeSetupStatus = useCallback(() => {
    if (!scannerService.isNative()) return undefined;
    if (runtimeSetupStatusRefreshInFlight.current) return runtimeSetupStatusRefreshInFlight.current;
    const requestGeneration = ++runtimeSetupStatusRequestGeneration.current;
    const refresh = (async () => {
      const applyStatusResult = (result: ServiceResult<ManagedRuntimeSetupStatus>) => {
        if (requestGeneration !== runtimeSetupStatusRequestGeneration.current) return undefined;
        setRuntimeSetup(result.data);
        const admission = runtimeSetupRequestAdmission.current;
        if (admission && requestGeneration >= admission.minimumStatusRequestGeneration) {
          const requestStarted = admission.observed
            || hasManagedRuntimeSetupRequestStarted(admission.baseline, result.data);
          if (requestStarted && !admission.observed) {
            admission.observed = true;
            setRuntimeSetupAdmissionPending(false);
          }
          if (requestStarted && isManagedRuntimeSetupTerminal(result.data)) {
            const scanWillStart = result.data.phase === "completed"
              && pendingRuntimeScanStart.current?.setupCommandGeneration
                === admission.setupCommandGeneration;
            setRuntimeSetupCompletion({
              setupCommandGeneration: admission.setupCommandGeneration,
              phase: result.data.phase,
              operationId: result.data.operationId,
            });
            runtimeSetupRequestAdmission.current = undefined;
            setRuntimeSetupAdmissionPending(false);
            setRuntimeSetupCommandPolling(false);
            if (!scanWillStart) {
              setBusyAction((current) => current === "runtime-setup" ? undefined : current);
            }
          }
        }
        return result.data;
      };

      try {
        const statusRead = runtimeSetupStatusReadCoalescer.read(
          MANAGED_RUNTIME_STATUS_READ_KEY,
          () => scannerService.getManagedRuntimeSetupStatus(),
        );
        const boundedStatusRead = await settleReadOnlyWithin(
          statusRead,
          RUNTIME_TRUTH_READ_TIMEOUT_MS,
        );
        if (boundedStatusRead.outcome === "timed_out") {
          // Keep the one raw IPC read alive. Later observers reuse it, and the
          // newest request generation may still accept its late truth.
          void statusRead.then((lateResult) => {
            applyStatusResult(lateResult);
          }).catch((error: unknown) => {
            if (requestGeneration === runtimeSetupStatusRequestGeneration.current) {
              recordTechnicalError("apply late runtime-status result", error);
            }
          });
          if (requestGeneration === runtimeSetupStatusRequestGeneration.current) {
            recordTechnicalError(
              "check managed runtime setup status",
              new Error("read-only runtime-status refresh timed out"),
            );
          }
          return undefined;
        }
        if (boundedStatusRead.outcome === "failed") throw boundedStatusRead.error;
        return applyStatusResult(boundedStatusRead.value);
      } catch (error) {
        if (requestGeneration === runtimeSetupStatusRequestGeneration.current) {
          recordTechnicalError("check managed runtime setup status", error);
        }
        return undefined;
      }
    })();
    runtimeSetupStatusRefreshInFlight.current = refresh;
    void refresh.finally(() => {
      if (runtimeSetupStatusRefreshInFlight.current === refresh) {
        runtimeSetupStatusRefreshInFlight.current = undefined;
      }
    });
    return refresh;
  }, [runtimeSetupStatusReadCoalescer]);

  useEffect(() => {
    void refreshManagedRuntimeSetupStatus();
  }, [refreshManagedRuntimeSetupStatus]);

  const runtimeSetupTerminal = isManagedRuntimeSetupTerminal(runtimeSetup);
  const runtimeSetupRequestPending = runtimeSetupAdmissionPending;
  const runtimeSetupPolling = runtimeSetupCommandPolling
    || runtimeSetup?.active === true
    || runtimeSetup?.prerequisiteRepairActive === true;

  useEffect(() => {
    if (!scannerService.isNative() || !runtimeSetupPolling) return;
    let disposed = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        await refreshManagedRuntimeSetupStatus();
        if (disposed) return;
      } catch {
        // The shared authoritative refresh records a bounded diagnostic and a
        // later poll/focus read remains able to supersede this request.
      } finally {
        if (!disposed) timer = window.setTimeout(() => void poll(), 1_000);
      }
    };
    void poll();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [refreshManagedRuntimeSetupStatus, runtimeSetupPolling]);

  useEffect(() => {
    if (!runtimeSetup) return;
    if (!runtimeSetupTerminal) {
      reconciledRuntimeTerminalKey.current = undefined;
      return;
    }
    const terminalKey = [
      runtimeSetup.operationId ?? "legacy",
      runtimeSetup.phase,
      runtimeSetup.lastHeartbeatAt ?? "",
    ].join(":");
    if (reconciledRuntimeTerminalKey.current === terminalKey) return;
    reconciledRuntimeTerminalKey.current = terminalKey;
    const matchingCompletionOwnsRefresh = runtimeSetupCompletion
      && runtimeSetupCompletion.phase === runtimeSetup.phase
      && runtimeSetupCompletion.operationId === runtimeSetup.operationId;
    if (matchingCompletionOwnsRefresh) return;
    void refreshRuntimeSnapshot();
  }, [refreshRuntimeSnapshot, runtimeSetup, runtimeSetupCompletion, runtimeSetupTerminal]);

  useEffect(() => {
    if (!runtimeSetupCompletion) return;
    if (runtimeSetupCompletion.phase !== "completed") {
      if (
        pendingRuntimeScanStart.current?.setupCommandGeneration
        === runtimeSetupCompletion.setupCommandGeneration
      ) pendingRuntimeScanStart.current = undefined;
      return;
    }
    let disposed = false;
    const completion = runtimeSetupCompletion;
    void refreshRuntimeSnapshotAfterCurrent().then((refreshedSnapshot) => {
      if (!disposed) {
        setRuntimeSetupCompletionSnapshot({ completion, snapshot: refreshedSnapshot });
      }
    });
    return () => {
      disposed = true;
    };
  }, [refreshRuntimeSnapshotAfterCurrent, runtimeSetupCompletion]);

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
          en: "Check the connection and try again.",
          zhTW: "請確認網路連線後再試一次。",
        }),
      });
    }
  }, [pushToast, text]);

  const setupManagedRuntime = async () => {
    if (isManagedRuntimePackageAdmissionFailure(runtimeSetup)) return;
    const commandGeneration = ++runtimeSetupCommandGeneration.current;
    const clearMatchingPendingScan = () => {
      if (pendingRuntimeScanStart.current?.setupCommandGeneration === commandGeneration) {
        pendingRuntimeScanStart.current = undefined;
      }
    };
    if (
      pendingRuntimeScanStart.current
      && pendingRuntimeScanStart.current.setupCommandGeneration !== commandGeneration
    ) pendingRuntimeScanStart.current = undefined;
    setRuntimeSetupCompletion(undefined);
    setRuntimeSetupCompletionSnapshot(undefined);
    const requestBaseline: ManagedRuntimeSetupRequestBaseline = {
      operationId: runtimeSetup?.operationId,
    };
    runtimeSetupRequestAdmission.current = {
      baseline: requestBaseline,
      setupCommandGeneration: commandGeneration,
      // Ignore a status response that was already in flight before this click.
      minimumStatusRequestGeneration: runtimeSetupStatusRequestGeneration.current + 1,
      observed: false,
    };
    setRuntimeSetupAdmissionPending(true);
    setBusyAction("runtime-setup");
    setRuntimeSetupCommandPolling(true);
    let commandReplyReceived = false;
    let keepFollowingAuthoritativeOperation = false;

    const readFreshSetupStatus = async () => {
      // A shared read that began before the click cannot acknowledge this
      // request. Let its bounded slot clear, then issue one fresh read.
      const priorStatusRefresh = runtimeSetupStatusRefreshInFlight.current;
      if (priorStatusRefresh) await priorStatusRefresh;
      return refreshManagedRuntimeSetupStatus();
    };

    const retainActiveSetup = () => {
      const admission = runtimeSetupRequestAdmission.current;
      if (admission) admission.observed = true;
      setRuntimeSetupAdmissionPending(false);
      keepFollowingAuthoritativeOperation = true;
    };

    const reconcileUnknownSetupOutcome = async (): Promise<"active" | "terminal" | "unconfirmed"> => {
      const requestWasAlreadyObserved = runtimeSetupRequestAdmission.current?.observed === true;
      const setupStatus = await readFreshSetupStatus();
      if (commandGeneration !== runtimeSetupCommandGeneration.current || !setupStatus) {
        return "unconfirmed";
      }
      const setupActive = setupStatus.active === true
        || setupStatus.prerequisiteRepairActive === true;
      const currentRequestWasObserved = requestWasAlreadyObserved
        || hasManagedRuntimeSetupRequestStarted(requestBaseline, setupStatus);
      if (setupActive) {
        // The command reply is unknown, but the authoritative operation is
        // alive. Keep polling it instead of reporting a false failure.
        retainActiveSetup();
        return "active";
      }
      if (currentRequestWasObserved && isManagedRuntimeSetupTerminal(setupStatus)) {
        // The reply was lost after the operation reached a real terminal
        // state. The assistant now presents that backend truth.
        await refreshRuntimeSnapshotAfterCurrent();
        return "terminal";
      }
      return "unconfirmed";
    };

    try {
      const commandObservation = await observePromiseWithin(
        scannerService.setupManagedRuntime(),
        RUNTIME_SETUP_COMMAND_UI_TIMEOUT_MS,
      );
      if (commandGeneration !== runtimeSetupCommandGeneration.current) return;
      if (commandObservation.outcome === "timed_out") {
        // This is an unknown command outcome, not a setup failure. A bounded
        // status read decides whether to follow an operation or return to Retry.
        const reconciliation = await reconcileUnknownSetupOutcome();
        if (reconciliation === "unconfirmed") clearMatchingPendingScan();
        return;
      }
      if (commandObservation.outcome === "failed") throw commandObservation.error;
      const result = commandObservation.value;
      commandReplyReceived = true;
      applyServiceMeta(result);
      const setupStatus = await readFreshSetupStatus();
      if (commandGeneration !== runtimeSetupCommandGeneration.current) return;
      if (!setupStatus) throw new Error("managed runtime setup status was unavailable after setup");
      if (setupStatus.active || setupStatus.prerequisiteRepairActive) {
        retainActiveSetup();
        return;
      }
      const refreshedSnapshot = await refreshRuntimeSnapshotAfterCurrent();
      const completed = setupStatus.phase === "completed";
      const runtimeReady = refreshedSnapshot?.runtime?.available === true;
      const completedAndReady = completed && runtimeReady;
      const pendingScan = pendingRuntimeScanStart.current;
      const willStartRequestedScan = completedAndReady
        && runtimeSetupRequestAdmission.current === undefined
        && pendingScan !== undefined
        && pendingScan.setupCommandGeneration === commandGeneration
        && selectedCaseIdRef.current === pendingScan.input.caseId
        && shouldStartRuntimePreparedScan({
          requestedPage: pendingScan.page,
          currentPage: currentPageRef.current,
          requestedPageTransitionGeneration: pendingScan.pageTransitionGeneration,
          currentPageTransitionGeneration: pageTransitionGeneration.current,
          requestedCaseSelectionGeneration: pendingScan.caseSelectionGeneration,
          currentCaseSelectionGeneration: caseSelectionBarrierRef.current.generation,
          requestedCaseId: pendingScan.input.caseId,
          selectedCaseId: refreshedSnapshot?.selectedCaseId,
          workspaceCaseId: refreshedSnapshot?.workspace?.case.id,
          runtimeAvailable: refreshedSnapshot?.runtime?.available,
          setupPhase: setupStatus.phase,
          activeScanWork: refreshedSnapshot?.workspace
            ? hasActiveScanWork(refreshedSnapshot.workspace.runs)
            : false,
        });
      if (willStartRequestedScan) keepFollowingAuthoritativeOperation = true;
      const cancelled = setupStatus.phase === "cancelled";
      const nonRetryable = isManagedRuntimePackageAdmissionFailure(setupStatus);
      if (!completed && !cancelled) {
        if (currentPageRef.current !== "start") {
          currentPageRef.current = "start";
          pageTransitionGeneration.current += 1;
        }
        window.location.hash = "start";
        setPage("start");
      }
      pushToast({
        tone: completedAndReady ? "success" : "warning",
        title: completed
          ? completedAndReady
            ? text({ en: "Advanced local scan tools are ready", zhTW: "進階本機掃描工具已就緒" })
            : text({ en: "Advanced local scan setup finished; checking availability", zhTW: "進階本機掃描設定已完成，正在確認可用狀態" })
          : nonRetryable
            ? text({ en: "An advanced local scan tool is unavailable in this app version", zhTW: "這個程式版本無法使用一項進階本機掃描工具" })
            : cancelled
            ? text({ en: "Advanced local scan-tool setup paused", zhTW: "進階本機掃描工具設定已暫停" })
            : text({ en: "Advanced local scan-tool setup stopped", zhTW: "進階本機掃描工具設定已停止" }),
        detail: completed
          ? completedAndReady
            ? text({
              en: "The scan tools are ready.",
              zhTW: "掃描工具已就緒。",
            })
            : text({
              en: "Checking whether the advanced tools are ready. Select Retry if the status does not update.",
              zhTW: "正在確認進階工具是否就緒；若狀態沒有更新，請按「再試一次」。",
            })
          : nonRetryable
            ? text({
              en: "Install a compatible app version to run this advanced check.",
              zhTW: "請安裝相容的程式版本，再執行這項進階檢查。",
            })
          : cancelled
            ? text({
              en: "Continue setup from the saved download.",
              zhTW: "可從已保存的下載進度繼續設定。",
            })
            : text({
              en: "Try setup again. Open Technical details if it stops again.",
              zhTW: "請再試一次；若再次停止，可查看「技術細節」。",
            }),
      });
    } catch (error) {
      if (commandGeneration !== runtimeSetupCommandGeneration.current) return;
      recordTechnicalError("prepare managed runtime", error);
      if (!commandReplyReceived) {
        const reconciliation = await reconcileUnknownSetupOutcome();
        if (commandGeneration !== runtimeSetupCommandGeneration.current) return;
        if (reconciliation !== "unconfirmed") return;
      }
      clearMatchingPendingScan();
      pushToast({
        tone: "danger",
        title: text({ en: "Advanced local scan-tool setup did not finish", zhTW: "進階本機掃描工具設定未能完成" }),
        detail: text({
          en: "Try advanced local scan preparation again.",
          zhTW: "請再試一次進階本機掃描準備。",
        }),
      });
    } finally {
      if (
        commandGeneration === runtimeSetupCommandGeneration.current
        && !keepFollowingAuthoritativeOperation
      ) {
        runtimeSetupRequestAdmission.current = undefined;
        setRuntimeSetupAdmissionPending(false);
        setRuntimeSetupCommandPolling(false);
        setBusyAction((current) => current === "runtime-setup" ? undefined : current);
      }
    }
  };

  const cancelManagedRuntimeSetup = async () => {
    pendingRuntimeScanStart.current = undefined;
    try {
      const result = await scannerService.cancelManagedRuntimeSetup();
      applyServiceMeta(result);
      setRuntimeSetup(result.data);
      if (result.data.cancelRequested) {
        pushToast({
          tone: "info",
          title: text({ en: "Stopping scan-engine setup", zhTW: "正在停止掃描引擎設定" }),
          detail: text({
            en: "The next setup attempt resumes this download.",
            zhTW: "下次設定會接續這次下載。",
          }),
        });
      }
    } catch (error) {
      recordTechnicalError("cancel managed runtime setup", error);
      pushToast({
        tone: "danger",
        title: text({ en: "Setup could not be stopped yet", zhTW: "目前無法停止設定" }),
        detail: text({
          en: "Try the stop button again in a moment.",
          zhTW: "請稍後再按一次停止。",
        }),
      });
    }
  };

  useEffect(() => {
    const onHashChange = () => {
      const nextPage = pageFromHash();
      if (currentPageRef.current !== nextPage) {
        currentPageRef.current = nextPage;
        pageTransitionGeneration.current += 1;
      }
      setPage(nextPage);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (!scannerService.isNative()) return undefined;
    let disposed = false;
    let listenersReady = false;
    const refreshEventNames = [EVENTS.coverageChanged, EVENTS.exportProgress, EVENTS.bootstrapMessage];

    const subscriptions = subscribeAllThenReconcile({
      subscriptions: [
        () => scannerService.subscribeScanWorkspace((workspace, eventName) => {
          if (disposed) return;
          applyScanWorkspaceEvent(workspace);
          if (eventName === EVENTS.runFinished && workspace.case.id === selectedCaseIdRef.current) {
            const readinessRequestGeneration = scanReadinessRequestGeneration.current;
            const readinessResponseGeneration = ++scanReadinessResponseGeneration.current;
            const acceptReadiness = (result: ServiceResult<ScanReadiness>) => {
              if (
                disposed
                || selectedCaseIdRef.current !== workspace.case.id
                || !isCurrentScanReadinessResponse(
                  scanReadinessResponseGeneration.current,
                  readinessResponseGeneration,
                  workspace.case.id,
                  result.data.caseId,
                )
                || !isCurrentScanReadinessRequest(
                  scanReadinessRequestGeneration.current,
                  readinessRequestGeneration,
                )
              ) return;
              applyServiceMeta(result);
              setScanReadiness(result.data);
              setScanReadinessErrorCaseId(undefined);
            };
            void readScanReadinessWithin(workspace.case.id, acceptReadiness).then(acceptReadiness).catch((error: unknown) => {
              if (
                disposed
                || selectedCaseIdRef.current !== workspace.case.id
                || !isCurrentScanReadinessRequest(
                  scanReadinessRequestGeneration.current,
                  readinessRequestGeneration,
                )
                || !isCurrentScanReadinessRequest(
                  scanReadinessResponseGeneration.current,
                  readinessResponseGeneration,
                )
              ) return;
              setScanReadiness(undefined);
              setScanReadinessErrorCaseId(workspace.case.id);
              recordTechnicalError("refresh scan readiness after completion", error);
            });
          }
        }),
        ...refreshEventNames.map((eventName) => () => scannerService.subscribe(eventName, () => {
          if (!disposed && listenersReady) void loadSnapshot(selectedCaseIdRef.current, true);
        })),
      ],
      reconcile: async () => {
        // A transition emitted before its OS listener existed cannot be
        // replayed. Once every listener is live, one authoritative read closes
        // every startup window. Later events may request their own fresh read.
        listenersReady = true;
        await loadSnapshot(selectedCaseIdRef.current, true);
      },
    });

    void subscriptions.ready.catch((error: unknown) => {
      if (!disposed) {
        recordTechnicalError("subscribe to desktop status", error);
        pushToast({
          tone: "warning",
          title: text({ en: "Live status is unavailable", zhTW: "即時狀態無法使用" }),
          detail: text({
            en: "Reopen the case to refresh its status.",
            zhTW: "重新開啟案件以更新狀態。",
          }),
        });
      }
    });

    return () => {
      disposed = true;
      subscriptions.close();
    };
  }, [applyScanWorkspaceEvent, applyServiceMeta, loadSnapshot, pushToast, readScanReadinessWithin, text]);

  const navigate = (target: PageId) => {
    if (
      pendingRuntimeScanStart.current
      && pendingRuntimeScanStart.current.page !== target
    ) {
      pendingRuntimeScanStart.current = undefined;
    }
    if (currentPageRef.current !== target) {
      currentPageRef.current = target;
      pageTransitionGeneration.current += 1;
    }
    if (target !== "findings") setFocusedFindingId(undefined);
    window.location.hash = target;
    setPage(target);
  };

  const selectCase = async (caseId: string): Promise<CaseWorkspace | undefined> => {
    if (pendingRuntimeScanStart.current) {
      pendingRuntimeScanStart.current = undefined;
    }
    supersedeCaseSelectionRef.current();
    let settleSelection: () => void = () => undefined;
    let supersedeSelection: () => void = () => undefined;
    const settled = new Promise<void>((resolve) => {
      settleSelection = resolve;
    });
    const superseded = new Promise<void>((resolve) => {
      supersedeSelection = resolve;
    });
    const selectionGeneration = caseSelectionBarrierRef.current.generation + 1;
    caseSelectionBarrierRef.current = {
      generation: selectionGeneration,
      settled,
      superseded,
    };
    supersedeCaseSelectionRef.current = supersedeSelection;
    const readinessRequestGeneration = ++scanReadinessRequestGeneration.current;
    setLoading(true);
    try {
      const result = await scannerService.selectCase(caseId);
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return undefined;
      applyServiceMeta(result);
      selectedCaseIdRef.current = caseId;
      setCaseSelectionUnavailableId(undefined);
      setToasts((current) => current.filter((toast) =>
        toast.actionCaseId === undefined || toast.actionCaseId === caseId));
      setSnapshot((current) => current ? { ...current, selectedCaseId: caseId, workspace: result.data } : current);
      const readinessResponseGeneration = ++scanReadinessResponseGeneration.current;
      const handleReadinessError = (error: unknown) => {
        if (
          isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)
          && isCurrentScanReadinessRequest(scanReadinessResponseGeneration.current, readinessResponseGeneration)
        ) {
          setScanReadiness(undefined);
          setScanReadinessErrorCaseId(caseId);
          recordTechnicalError("check selected case scan readiness", error);
        }
      };
      const acceptReadiness = (readiness: ServiceResult<ScanReadiness>) => {
        if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
        if (!isCurrentScanReadinessResponse(
          scanReadinessResponseGeneration.current,
          readinessResponseGeneration,
          caseId,
          readiness.data.caseId,
        )) {
          handleReadinessError(new Error("scan readiness response did not match the selected case"));
          return;
        }
        setScanReadiness(readiness.data);
        setScanReadinessErrorCaseId(undefined);
      };
      try {
        const readiness = await readScanReadinessWithin(caseId, acceptReadiness);
        acceptReadiness(readiness);
      } catch (error) {
        handleReadinessError(error);
      }
      return result.data;
    } catch (error) {
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return undefined;
      recordTechnicalError("select case", error);
      setCaseSelectionUnavailableId(caseId);
      pushToast({
        tone: "danger",
        title: text({ en: "This scan project could not be opened", zhTW: "目前無法開啟這個掃描專案" }),
        detail: text({
          en: "Try opening it again.",
          zhTW: "請再開啟一次。",
        }),
      });
      return undefined;
    } finally {
      if (caseSelectionBarrierRef.current.generation === selectionGeneration) setLoading(false);
      settleSelection();
    }
  };

  const openCaseAtUsefulStep = async (caseId: string): Promise<void> => {
    const requestedPage = currentPageRef.current;
    const pageGenerationAtStart = pageTransitionGeneration.current;
    const selection = selectCase(caseId);
    const caseSelectionGenerationAtStart = caseSelectionBarrierRef.current.generation;
    const workspace = await selection;
    if (
      !workspace
      || selectedCaseIdRef.current !== caseId
      || currentPageRef.current !== requestedPage
      || pageTransitionGeneration.current !== pageGenerationAtStart
      || caseSelectionBarrierRef.current.generation !== caseSelectionGenerationAtStart
    ) return;
    const activeRun = workspace.runs.find((run) => ["queued", "running", "paused"].includes(run.status));
    const interruptedRun = workspace.runs.find((run) => run.engineRuns.some(
      (engine) => engine.phase === "interrupted_restart" || engine.errorCode === "desktop_process_restarted",
    ));
    const terminalRun = workspace.runs.find((run) => ["completed", "partial", "failed", "cancelled"].includes(run.status));
    navigate(activeRun || interruptedRun ? "progress" : terminalRun ? "findings" : "coverage");
  };

  const retryScanReadiness = async (caseId: string) => {
    const readinessRequestGeneration = ++scanReadinessRequestGeneration.current;
    const readinessResponseGeneration = ++scanReadinessResponseGeneration.current;
    setBusyAction("scan-readiness");
    const handleReadinessError = (error: unknown) => {
      if (
        isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)
        && isCurrentScanReadinessRequest(scanReadinessResponseGeneration.current, readinessResponseGeneration)
      ) {
        setScanReadinessErrorCaseId(caseId);
        recordTechnicalError("retry scan readiness", error);
        pushToast({
          tone: "warning",
          title: text({ en: "Could not check yet", zhTW: "目前仍無法完成檢查" }),
          detail: text({
            en: "Check readiness again in a moment.",
            zhTW: "請稍後重新檢查準備狀態。",
          }),
        });
      }
    };
    const acceptReadiness = (result: ServiceResult<ScanReadiness>) => {
      if (!isCurrentScanReadinessRequest(scanReadinessRequestGeneration.current, readinessRequestGeneration)) return;
      if (!isCurrentScanReadinessResponse(
        scanReadinessResponseGeneration.current,
        readinessResponseGeneration,
        caseId,
        result.data.caseId,
      )) {
        handleReadinessError(new Error("scan readiness response did not match the requested case"));
        return;
      }
      applyServiceMeta(result);
      setScanReadiness(result.data);
      setScanReadinessErrorCaseId(undefined);
    };
    try {
      const result = await readScanReadinessWithin(caseId, acceptReadiness);
      acceptReadiness(result);
    } catch (error) {
      handleReadinessError(error);
    } finally {
      setBusyAction(undefined);
    }
  };

  const createCase = async (input: CreateCaseInput): Promise<boolean> => {
    const requestedPage = currentPageRef.current;
    const pageGenerationAtStart = pageTransitionGeneration.current;
    const caseSelectionGenerationAtStart = caseSelectionBarrierRef.current.generation;
    const shouldReturnToReview = () => currentPageRef.current === requestedPage
      && pageTransitionGeneration.current === pageGenerationAtStart
      && caseSelectionBarrierRef.current.generation === caseSelectionGenerationAtStart;
    setBusyAction("create");
    try {
      const result = await scannerService.createCase(input);
      applyServiceMeta(result);
      let returnToReview = shouldReturnToReview();
      await loadSnapshot(returnToReview ? result.data.id : undefined, true);
      returnToReview = returnToReview && shouldReturnToReview();
      if (returnToReview) {
        setSelectedUseCase(undefined);
        navigate("coverage");
      }
      pushToast({
        tone: result.mode === "native" ? "success" : "info",
        title: result.mode === "native"
          ? text({ en: "Scan project created", zhTW: "掃描專案已建立" })
          : text({ en: "Demo scan project created", zhTW: "展示掃描專案已建立" }),
        detail: result.mode === "native"
          ? returnToReview
            ? text({ en: "Review the selected assets and checks, then start.", zhTW: "請檢查所選資產與掃描項目後開始。" })
            : text({ en: "Open My scans to review and start it.", zhTW: "請開啟「我的掃描」檢查並開始。" })
          : text({ en: "This demo project is saved in this browser.", zhTW: "這個展示專案已保存在瀏覽器中。" }),
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

  const createCaseWithWorkspaces = async (
    input: CreateCaseInput,
    workspaces: Array<Omit<AttachWorkspaceSnapshotInput, "caseId">>,
  ): Promise<boolean> => {
    const requestedPage = currentPageRef.current;
    const pageGenerationAtStart = pageTransitionGeneration.current;
    const caseSelectionGenerationAtStart = caseSelectionBarrierRef.current.generation;
    const shouldReturnToReview = () => currentPageRef.current === requestedPage
      && pageTransitionGeneration.current === pageGenerationAtStart
      && caseSelectionBarrierRef.current.generation === caseSelectionGenerationAtStart;
    setBusyAction("create-local");
    let caseId: string;
    try {
      const created = await scannerService.createCase(input);
      applyServiceMeta(created);
      caseId = created.data.id;
      selectedCaseIdRef.current = caseId;
    } catch (error) {
      recordTechnicalError("create local scan project", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The scan project was not created", zhTW: "掃描專案沒有建立成功" }),
        detail: text({ en: "No folder was copied. Check the current choices and try again.", zhTW: "沒有複製任何資料夾；請檢查目前選項後再試一次。" }),
      });
      setBusyAction(undefined);
      return false;
    }

    try {
      let failedWorkspaceCount = 0;
      for (const workspace of workspaces) {
        try {
          const attached = await scannerService.attachWorkspaceSnapshot({ caseId, ...workspace });
          applyServiceMeta(attached);
          if (!attached.data.accepted) {
            failedWorkspaceCount += 1;
            recordTechnicalError("attach initial local scan snapshot", attached.data.message);
          }
        } catch (error) {
          failedWorkspaceCount += 1;
          recordTechnicalError("attach initial local scan snapshot", error);
        }
      }
      let returnToReview = shouldReturnToReview();
      await loadSnapshot(returnToReview ? caseId : undefined, true);
      returnToReview = returnToReview && shouldReturnToReview();
      if (returnToReview) {
        setSelectedUseCase(undefined);
        navigate("coverage");
      }
      pushToast({
        tone: failedWorkspaceCount === 0 ? "success" : "warning",
        title: failedWorkspaceCount === 0
          ? text({ en: "Local projects ready for review", zhTW: "本機專案可供檢查" })
          : text({ en: "Scan project created; some folders were not added", zhTW: "掃描專案已建立；部分資料夾尚未加入" }),
        detail: failedWorkspaceCount === 0
          ? returnToReview
            ? text({
              en: "The private snapshots are attached. Review the exact checks, then press Start.",
              zhTW: "私密快照已附加；請檢查確切掃描項目後按下「開始」。",
            })
            : text({
              en: "The private snapshots are attached. Open My scans when ready to review and start them.",
              zhTW: "私密快照已附加。準備好時請開啟「我的掃描」，檢查後再開始。",
            })
          : returnToReview
            ? text({
              en: `${failedWorkspaceCount} folder(s) could not be copied. Add them again in Scan setup.`,
              zhTW: `有 ${failedWorkspaceCount} 個資料夾無法複製；請在掃描設定重新加入。`,
            })
            : text({
              en: `${failedWorkspaceCount} folder(s) could not be copied. Open My scans to review the saved project and add the missing folder again.`,
              zhTW: `有 ${failedWorkspaceCount} 個資料夾無法複製。請開啟「我的掃描」檢查已保存的專案，再重新加入缺少的資料夾。`,
            }),
      });
      return failedWorkspaceCount === 0;
    } catch (error) {
      recordTechnicalError("load locally prepared scan project", error);
      let returnToReview = shouldReturnToReview();
      await loadSnapshot(returnToReview ? caseId : undefined, true);
      returnToReview = returnToReview && shouldReturnToReview();
      if (returnToReview) {
        setSelectedUseCase(undefined);
        navigate("coverage");
      }
      pushToast({
        tone: "warning",
        title: text({ en: "Scan project created; review is unavailable", zhTW: "掃描專案已建立；目前無法開啟檢查畫面" }),
        detail: returnToReview
          ? text({
            en: "Reopen the project from My scans.",
            zhTW: "請從「我的掃描」重新開啟專案。",
          })
          : text({
            en: "Open the project from My scans.",
            zhTW: "請從「我的掃描」開啟專案。",
          }),
      });
      return false;
    } finally {
      setBusyAction(undefined);
    }
  };

  const createCaseWithWorkspace = (
    input: CreateCaseInput,
    workspace: Omit<AttachWorkspaceSnapshotInput, "caseId">,
  ): Promise<boolean> => createCaseWithWorkspaces(input, [workspace]);

  const seedDemoCase = async (): Promise<void> => {
    setBusyAction("seed-demo");
    try {
      const result = await scannerService.seedDemoCase();
      applyServiceMeta(result);
      await loadSnapshot(result.data.id, true);
      setSelectedUseCase(undefined);
      pushToast({
        tone: "info",
        title: text({ en: "Example project opened", zhTW: "已開啟範例專案" }),
        detail: text({
          en: "Explore the workflow with synthetic demonstration data.",
          zhTW: "可使用合成展示資料體驗完整流程。",
        }),
      });
    } catch (error) {
      recordTechnicalError("seed demo case", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The example project could not be opened", zhTW: "目前無法開啟範例專案" }),
        detail: text({ en: "Try again.", zhTW: "請再試一次。" }),
      });
    } finally {
      setBusyAction(undefined);
    }
  };

  const startLocalhostQuickScan = async (port: number): Promise<void> => {
    setBusyAction("localhost-quick-scan");
    const workspaceEventGenerationAtRequest = scanWorkspaceEventGeneration.current;
    const recoverScanProgress = () => {
      void loadSnapshot(undefined, true).finally(() => navigate("progress"));
    };
    try {
      const result = await scannerService.startLocalhostQuickScan(port);
      applyServiceMeta(result);
      const quickWorkspace = result.data.workspace;
      if (result.mode !== "native" || !result.data.accepted || !quickWorkspace) {
        pushToast({
          tone: result.mode === "demo" ? "info" : "warning",
          persistent: result.mode === "native",
          actionLabelText: result.mode === "native"
            ? { en: "Open Scan progress", zhTW: "開啟掃描進度" }
            : undefined,
          actionLabel: result.mode === "native"
            ? text({ en: "Open Scan progress", zhTW: "開啟掃描進度" })
            : undefined,
          action: result.mode === "native" ? recoverScanProgress : undefined,
          titleText: result.mode === "native"
            ? { en: "This computer check needs attention", zhTW: "這台電腦的檢查需要留意" }
            : undefined,
          title: result.mode === "demo"
            ? text({ en: "Browser demo did not run a real check", zhTW: "瀏覽器展示模式沒有執行真實檢查" })
            : text({ en: "This computer check needs attention", zhTW: "這台電腦的檢查需要留意" }),
          detailText: result.mode === "native"
            ? {
              en: "Open Scan progress. If no new check appears, try again.",
              zhTW: "請開啟「掃描進度」；若沒有新的檢查，再試一次。",
            }
            : undefined,
          detail: result.mode === "demo"
            ? text({
              en: "Open the desktop app to run this check.",
              zhTW: "請開啟桌面版執行這項檢查。",
            })
            : text({
              en: "Open Scan progress. If no new check appears, try again.",
              zhTW: "請開啟「掃描進度」；若沒有新的檢查，再試一次。",
            }),
        });
        return;
      }

      const observedQuick = observedScanWorkspaces.current.get(quickWorkspace.case.id);
      const selectedQuickWorkspace = observedQuick
        && observedQuick.generation > workspaceEventGenerationAtRequest
        ? selectNewerWorkspaceByRevision(
          selectNewerWorkspaceByRevision(
            observedQuick.workspace,
            observedQuick.freshestWorkspace,
          ),
          quickWorkspace,
        )
        : quickWorkspace;
      selectedCaseIdRef.current = selectedQuickWorkspace.case.id;
      setCaseSelectionUnavailableId(undefined);
      setSnapshotRefreshUnavailable(false);
      setScanReadiness(undefined);
      setScanReadinessErrorCaseId(undefined);
      setSelectedUseCase(undefined);
      setSelectedReportRunId(selectedQuickWorkspace.runs[0]?.id);
      setSnapshot((current) => {
        if (!current) return current;
        const selectedSnapshot = {
          ...current,
          selectedCaseId: selectedQuickWorkspace.case.id,
          workspace: current.workspace?.case.id === selectedQuickWorkspace.case.id
            ? current.workspace
            : undefined,
        };
        return mergeWorkspaceIntoSnapshot(selectedSnapshot, selectedQuickWorkspace) ?? selectedSnapshot;
      });
      navigate("progress");
      // The queued workspace is enough to make Progress and Cancel usable.
      // Optional manifest enrichment must not keep this connection utility
      // busy longer than the fixed three-second target contact.
      void loadSnapshot(selectedQuickWorkspace.case.id, true);
    } catch (error) {
      recordTechnicalError("start local connection test", error);
      pushToast({
        tone: "danger",
        persistent: true,
        actionLabelText: { en: "Open Scan progress", zhTW: "開啟掃描進度" },
        actionLabel: text({ en: "Open Scan progress", zhTW: "開啟掃描進度" }),
        action: recoverScanProgress,
        titleText: { en: "This computer check needs attention", zhTW: "這台電腦的檢查需要留意" },
        title: text({ en: "This computer check needs attention", zhTW: "這台電腦的檢查需要留意" }),
        detailText: {
          en: "Open Scan progress. If no new check appears, try again.",
          zhTW: "請開啟「掃描進度」；若沒有新的檢查，再試一次。",
        },
        detail: text({
          en: "Open Scan progress. If no new check appears, try again.",
          zhTW: "請開啟「掃描進度」；若沒有新的檢查，再試一次。",
        }),
      });
    } finally {
      setBusyAction(undefined);
    }
  };

  const executeAction = async (
    key: string,
    action: () => Promise<ServiceResult<ActionResponse>>,
    onResult?: (response: ActionResponse) => void,
    options: { suppressToast?: (response: ActionResponse) => boolean } = {},
  ): Promise<boolean> => {
    setBusyAction(key);
    const workspaceEventGenerationAtRequest = scanWorkspaceEventGeneration.current;
    const workspaceBeforeAction = snapshot?.workspace;
    const nonExecutionCopy = nonExecutionActionToastCopy[key as keyof typeof nonExecutionActionToastCopy];
    try {
      const result = await action();
      applyServiceMeta(result);
      const returnedWorkspace = result.data.workspace;
      let selectedWorkspace = returnedWorkspace;
      const lifecycleRunId = result.data.lifecycleDisposition?.runId;
      const lifecycleCaseId = returnedWorkspace?.case.id
        ?? (lifecycleRunId && workspaceBeforeAction?.runs.some((run) => run.id === lifecycleRunId)
          ? workspaceBeforeAction.case.id
          : undefined);
      if (!selectedWorkspace && lifecycleCaseId === workspaceBeforeAction?.case.id) {
        selectedWorkspace = workspaceBeforeAction;
      }
      if (returnedWorkspace) {
        const currentWorkspace = snapshot?.workspace?.case.id === returnedWorkspace.case.id
          ? snapshot.workspace
          : undefined;
        if (currentWorkspace) {
          selectedWorkspace = selectNewerWorkspaceByRevision(
            currentWorkspace,
            selectedWorkspace ?? returnedWorkspace,
          );
        }
      }
      const observed = lifecycleCaseId
        ? observedScanWorkspaces.current.get(lifecycleCaseId)
        : undefined;
      if (observed) {
        const eventTruth = selectNewerWorkspaceByRevision(
          observed.workspace,
          observed.freshestWorkspace,
        );
        if (!returnedWorkspace) {
          selectedWorkspace = observed.generation > workspaceEventGenerationAtRequest
            ? selectedWorkspace
              ? selectNewerWorkspaceByRevision(eventTruth, selectedWorkspace)
              : eventTruth
            : selectNewerWorkspaceByRevision(selectedWorkspace, observed.freshestWorkspace);
        } else {
          const protectedWorkspace = selectedWorkspace ?? returnedWorkspace;
          selectedWorkspace = observed.generation > workspaceEventGenerationAtRequest
            ? selectNewerWorkspaceByRevision(eventTruth, protectedWorkspace)
            : selectNewerWorkspaceByRevision(protectedWorkspace, observed.freshestWorkspace);
        }
      }
      const lifecycleDisposition = result.data.lifecycleDisposition && selectedWorkspace
        ? deriveScanLifecycleDisposition(
          result.data.lifecycleDisposition.action,
          selectedWorkspace,
          result.data.lifecycleDisposition.runId,
        )
        : result.data.lifecycleDisposition;
      const response: ActionResponse = selectedWorkspace || lifecycleDisposition
        ? { ...result.data, workspace: selectedWorkspace, lifecycleDisposition }
        : result.data;
      onResult?.(response);
      const suppressToast = options.suppressToast?.(response) === true;
      if (!response.accepted && !suppressToast) {
        recordTechnicalError(`action ${key} did not start`, response.message);
      }
      const preflightCode = Object.keys(scanStartIssueCopy).find((code) => result.data.message.includes(`scan_preflight:${code}`)) as keyof typeof scanStartIssueCopy | undefined;
      const lifecycleToast = lifecycleDisposition
        ? scanLifecycleToastPresentation(lifecycleDisposition)
        : undefined;
      if (!suppressToast) pushToast({
        tone: lifecycleToast
          ? lifecycleToast.tone
          : response.accepted ? "success" : result.mode === "demo" ? "info" : "warning",
        title: lifecycleToast
          ? text(lifecycleToast.title)
          : response.accepted
          ? text(nonExecutionCopy?.acceptedTitle ?? { en: "Local work started", zhTW: "本機工作已開始" })
          : nonExecutionCopy
            ? text(nonExecutionCopy.failedTitle)
          : result.mode === "demo"
            ? text({ en: "Preview only — no scan ran", zhTW: "僅供預覽，未執行掃描" })
            : text({ en: "The work did not start", zhTW: "工作尚未開始" }),
        detail: lifecycleToast
          ? text(lifecycleToast.detail)
          : response.accepted
          ? text(nonExecutionCopy?.acceptedDetail ?? { en: "Open Scan progress to follow each scanner.", zhTW: "可到「掃描進度」查看每個工具的狀態。" })
          : nonExecutionCopy
            ? text(nonExecutionCopy.failedDetail)
          : result.mode === "demo"
            ? text({ en: "Open the desktop app to run this scan.", zhTW: "請使用桌面程式執行這次掃描。" })
          : preflightCode
            ? text(scanStartIssueCopy[preflightCode])
          : text({ en: "Check the current step and try again.", zhTW: "請確認目前步驟後再試一次。" }),
      });
      if (response.snapshot) setSnapshot(response.snapshot);
      else if (response.workspace) {
        const workspace = response.workspace;
        setSnapshot((current) => mergeWorkspaceIntoSnapshot(current, workspace));
      } else if (result.mode === "native" && lifecycleDisposition?.outcome !== "unconfirmed") {
        await loadSnapshot(snapshot?.selectedCaseId, true);
      }
      if (lifecycleDisposition?.outcome === "unconfirmed" && result.mode === "native") {
        // Reconcile exactly once in the background. Optional manifest
        // enrichment in a full snapshot must not keep a failed Cancel/Resume
        // action busy.
        void loadSnapshot(lifecycleCaseId ?? snapshot?.selectedCaseId, true);
      }
      return response.accepted;
    } catch (error) {
      recordTechnicalError(`run action ${key}`, error);
      pushToast({
        tone: "danger",
        title: text(nonExecutionCopy?.failedTitle ?? { en: "The local work could not finish", zhTW: "本機工作未能完成" }),
        detail: text(nonExecutionCopy?.failedDetail ?? { en: "Check the current step before trying again.", zhTW: "請確認目前步驟後再試一次。" }),
      });
      return false;
    } finally {
      setBusyAction(undefined);
    }
  };

  const refuseUnsupportedLocalhostPauseOrResume = (runId: string): boolean => {
    const run = snapshot?.workspace?.runs.find((candidate) => candidate.id === runId);
    if (!run || !isExactBuiltInLocalhostQuickScanRun(run)) return false;
    pushToast({
      tone: "info",
      title: text({
        en: "This connection test cannot be paused or resumed",
        zhTW: "這項連線測試不能暫停或續跑",
      }),
      detail: text({
        en: "Its connection attempt has a three-second maximum. Let it finish, or cancel it and start a new check later.",
        zhTW: "這次連線嘗試最長三秒。請讓它完成，或取消後再開始一次新的檢查。",
      }),
    });
    return true;
  };

  const runAction = async (
    key: string,
    action: () => Promise<ServiceResult<ActionResponse>>,
    runId?: string,
  ): Promise<void> => {
    if (
      runId
      && (key === "pause-scan" || key === "resume-scan")
      && refuseUnsupportedLocalhostPauseOrResume(runId)
    ) return;
    await executeAction(key, action);
  };

  const startScan = async (
    input: StartScanInput,
    options: { allowRuntimePreparation?: boolean } = {},
  ): Promise<boolean> => {
    const allowRuntimePreparation = options.allowRuntimePreparation !== false;
    const requestedPage = currentPageRef.current;
    const pageGenerationAtStart = pageTransitionGeneration.current;
    const caseSelectionGenerationAtStart = caseSelectionBarrierRef.current.generation;
    const selectedCaseAtStart = selectedCaseIdRef.current;
    const startContextStillCurrent = () => selectedCaseAtStart === input.caseId
      && selectedCaseIdRef.current === input.caseId
      && currentPageRef.current === requestedPage
      && pageTransitionGeneration.current === pageGenerationAtStart
      && caseSelectionBarrierRef.current.generation === caseSelectionGenerationAtStart;
    if (allowRuntimePreparation) pendingRuntimeScanStart.current = undefined;
    const runtimeAtScanAction = snapshot?.runtime;
    if (
      allowRuntimePreparation
      && startContextStillCurrent()
      && shouldPrepareRuntimeBeforeScanAction({
        mode,
        runtime: runtimeAtScanAction,
        status: runtimeSetup,
        scanActionRequested: true,
      })
    ) {
      // Do not probe runtime readiness through start_scan: the backend freezes
      // a run before its worker performs that check. Preserve the exact
      // reviewed request, prepare the prerequisite, then submit it once.
      pendingRuntimeScanStart.current = {
        input: cloneRuntimeDeferredScanInput(input),
        page: requestedPage,
        pageTransitionGeneration: pageGenerationAtStart,
        caseSelectionGeneration: caseSelectionGenerationAtStart,
        setupCommandGeneration: runtimeSetupCommandGeneration.current + 1,
      };
      void setupManagedRuntime();
      return false;
    }
    const existingRunIds = new Set(
      snapshot?.workspace?.case.id === input.caseId
        ? snapshot.workspace.runs.map((run) => run.id)
        : [],
    );
    setStartingScanCaseId(input.caseId);
    try {
      const accepted = await executeAction(
        "start-scan",
        () => scannerService.startScan(input),
        (response) => {
          if (!response.accepted) return;
          const returnedWorkspace = response.workspace ?? response.snapshot?.workspace;
          if (!returnedWorkspace || returnedWorkspace.case.id !== input.caseId) return;
          const createdRunId = findRunCreatedAfterStart(returnedWorkspace.runs, existingRunIds);
          if (createdRunId) setSelectedReportRunId(createdRunId);
        },
      );
      if (accepted) navigate("progress");
      return accepted;
    } finally {
      setStartingScanCaseId((current) => current === input.caseId ? undefined : current);
    }
  };

  useEffect(() => {
    const pending = pendingRuntimeScanStart.current;
    const observed = runtimeSetupCompletionSnapshot;
    if (!observed) return;
    if (!pending) {
      setBusyAction((current) => current === "runtime-setup" ? undefined : current);
      return;
    }
    if (
      pending.setupCommandGeneration
      !== observed.completion.setupCommandGeneration
    ) return;

    // Consume before deciding or starting. Snapshot refreshes and repeated
    // terminal status can never duplicate Start.
    pendingRuntimeScanStart.current = undefined;
    const refreshedSnapshot = observed.snapshot;
    const sameCaseStillSelected = selectedCaseIdRef.current === pending.input.caseId;
    if (!sameCaseStillSelected || !shouldStartRuntimePreparedScan({
      requestedPage: pending.page,
      currentPage: currentPageRef.current,
      requestedPageTransitionGeneration: pending.pageTransitionGeneration,
      currentPageTransitionGeneration: pageTransitionGeneration.current,
      requestedCaseSelectionGeneration: pending.caseSelectionGeneration,
      currentCaseSelectionGeneration: caseSelectionBarrierRef.current.generation,
      requestedCaseId: pending.input.caseId,
      selectedCaseId: refreshedSnapshot?.selectedCaseId,
      workspaceCaseId: refreshedSnapshot?.workspace?.case.id,
      runtimeAvailable: refreshedSnapshot?.runtime?.available,
      setupPhase: observed.completion.phase,
      activeScanWork: refreshedSnapshot?.workspace
        ? hasActiveScanWork(refreshedSnapshot.workspace.runs)
        : false,
    })) {
      setBusyAction((current) => current === "runtime-setup" ? undefined : current);
      return;
    }

    void startScan(pending.input, { allowRuntimePreparation: false });
  }, [runtimeSetupCompletionSnapshot]);

  const deleteCase = async (caseId: string, confirmation: string): Promise<boolean> => {
    setBusyAction("delete-case");
    try {
      const result = await scannerService.deleteCase(caseId, confirmation);
      applyServiceMeta(result);
      pushToast({
        tone: result.data.accepted ? "success" : result.mode === "demo" ? "info" : "warning",
        title: result.data.accepted
          ? result.mode === "demo"
            ? text({ en: "Browser preview project deleted", zhTW: "瀏覽器預覽專案已刪除" })
            : text({ en: "Case record deleted", zhTW: "案件紀錄已刪除" })
          : result.mode === "demo"
            ? text({ en: "Demo mode did not delete the case", zhTW: "展示模式沒有刪除案件" })
            : text({ en: "The case was not deleted", zhTW: "案件沒有被刪除" }),
        detail: result.data.accepted
          ? result.data.artifacts.exists
            ? text({ en: "Local evidence is still present until you confirm its separate cleanup.", zhTW: "本機證據仍保留，直到你另外確認清理為止。" })
            : result.mode === "demo"
              ? text({
                en: "Only its browser-saved project record was removed; the preview creates no evidence files.",
                zhTW: "只移除瀏覽器儲存的專案紀錄；預覽模式不會建立證據檔案。",
              })
              : text({
                en: "The case record was removed, and no evidence folder remains.",
                zhTW: "案件紀錄已移除，而且沒有留下證據資料夾。",
              })
          : text({ en: "No case data was changed.", zhTW: "案件資料沒有被更動。" }),
      });
      if (result.data.accepted) {
        setArtifactCleanupPlan(result.data.artifacts.exists ? result.data.artifacts : undefined);
        setArtifactCleanupResult(undefined);
        await afterLatestCaseSelection(
          () => caseSelectionBarrierRef.current,
          () => {
            const selectedCaseIdAfterDeletion = selectedCaseIdRef.current;
            return loadSnapshot(
              selectedCaseIdAfterDeletion && selectedCaseIdAfterDeletion !== caseId
                ? selectedCaseIdAfterDeletion
                : undefined,
              true,
            );
          },
        );
      }
      return result.data.accepted;
    } catch (error) {
      recordTechnicalError("delete case", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The case was not deleted", zhTW: "案件沒有被刪除" }),
        detail: text({ en: "Confirm the exact case name and try again.", zhTW: "請確認完整案件名稱後再試一次。" }),
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
            { en: "No evidence folder was found at {path}.", zhTW: "在 {path} 找不到證據資料夾。" },
            { path: result.data.exactPath },
          ),
      });
      return result.data.removed;
    } catch (error) {
      recordTechnicalError("delete case artifacts", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The evidence folder was not deleted", zhTW: "證據資料夾沒有被刪除" }),
        detail: text({ en: "Check the exact path and confirmation, then try again.", zhTW: "請確認精確路徑與確認文字後再試一次。" }),
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
  const workspaceRef = useRef(workspace);
  workspaceRef.current = workspace;
  useEffect(() => {
    const runs = workspace?.runs ?? [];
    const caseId = workspace?.case.id;
    const previousCaseId = reportSelectionCaseIdRef.current;
    reportSelectionCaseIdRef.current = caseId;
    setSelectedReportRunId((current) => reconcileReportRunId(
      previousCaseId,
      caseId,
      current,
      runs,
    ));
  }, [workspace?.case.id, workspace?.runs]);
  const activeScanCaseId = mode === "native"
    && !loading
    && workspace
    && hasActiveScanWork(workspace.runs)
    ? workspace.case.id
    : undefined;

  useEffect(() => {
    if (!scannerService.isNative()) return undefined;
    const reconcileRuntime = () => {
      void refreshManagedRuntimeSetupStatus();
      // Active-scan focus reconciliation below already reloads the same
      // snapshot. With no active scan, runtime truth must still refresh so the
      // sidebar cannot stay falsely Ready or Preparing after sleep/resume.
      if (!activeScanCaseId) void refreshRuntimeSnapshot();
    };
    const onWindowFocus = () => reconcileRuntime();
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") reconcileRuntime();
    };

    const watchdog = window.setInterval(reconcileRuntime, RUNTIME_TRUTH_REFRESH_INTERVAL_MS);
    window.addEventListener("focus", onWindowFocus);
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      window.clearInterval(watchdog);
      window.removeEventListener("focus", onWindowFocus);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [activeScanCaseId, refreshManagedRuntimeSetupStatus, refreshRuntimeSnapshot]);

  useEffect(() => {
    if (!activeScanCaseId) return undefined;
    let disposed = false;
    let refreshInFlight = false;

    const reconcileActiveScan = () => {
      if (
        disposed
        || refreshInFlight
        || selectedCaseIdRef.current !== activeScanCaseId
      ) return;
      refreshInFlight = true;
      void loadSnapshot(activeScanCaseId, true).finally(() => {
        refreshInFlight = false;
      });
    };
    const onWindowFocus = () => reconcileActiveScan();
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") reconcileActiveScan();
    };

    const interval = window.setInterval(reconcileActiveScan, ACTIVE_SCAN_REFRESH_INTERVAL_MS);
    window.addEventListener("focus", onWindowFocus);
    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      disposed = true;
      window.clearInterval(interval);
      window.removeEventListener("focus", onWindowFocus);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [activeScanCaseId, loadSnapshot]);

  const selectedCase = useMemo(
    () => snapshot?.cases.find((assessmentCase) => assessmentCase.id === snapshot.selectedCaseId) ?? workspace?.case,
    [snapshot, workspace],
  );
  const terminalRuns = useMemo(
    () => workspace?.runs.filter(isTerminalRun) ?? [],
    [workspace?.runs],
  );

  useEffect(() => {
    const nextCaseId = workspace?.case.id;
    setVerificationBaselineRunId((current) => {
      const selected = selectVerificationBaselineRunId({
        previousCaseId: verificationBaselineCaseIdRef.current,
        nextCaseId,
        currentRunId: current,
        savedRunId: workspace?.verification?.baselineRunId,
        terminalRunIds: terminalRuns.map((run) => run.id),
      });
      verificationBaselineCaseIdRef.current = nextCaseId;
      return selected;
    });
  }, [workspace?.case.id, workspace?.verification?.baselineRunId, terminalRuns]);

  const previewExport = useCallback(async (options: {
    runId: string;
    locale: ReportLocale;
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
    runId: string;
    locale: ReportLocale;
    format: ExportFormat;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => {
    const exportWorkspace = workspaceRef.current;
    if (!exportWorkspace) return;
    const exportCaseId = exportWorkspace.case.id;
    setBusyAction("export");
    try {
      const result = await scannerService.exportCase(
        { caseId: exportCaseId, ...options },
        exportWorkspace,
      );
      applyServiceMeta(result);
      if (!result.data) {
        if (selectedCaseIdRef.current === exportCaseId) {
          pushToast({
            tone: "info",
            title: text({ en: "Export cancelled", zhTW: "已取消匯出" }),
            detail: text({ en: "No file was created or written.", zhTW: "沒有建立或寫出任何檔案。" }),
          });
        }
        return;
      }
      const exported = result.data;
      setSnapshot((current) => appendExportToMatchingSnapshot(current, exportCaseId, exported));
      if (selectedCaseIdRef.current !== exportCaseId) return;
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
      if (selectedCaseIdRef.current !== exportCaseId) return;
      pushToast({
        tone: "danger",
        persistent: true,
        actionCaseId: exportCaseId,
        actionLabelText: { en: "Try export again", zhTW: "再次嘗試匯出" },
        actionLabel: text({ en: "Try export again", zhTW: "再次嘗試匯出" }),
        action: () => {
          if (selectedCaseIdRef.current === exportCaseId) void exportCase(options);
        },
        titleText: { en: "The case was not exported", zhTW: "案件沒有匯出成功" },
        title: text({ en: "The case was not exported", zhTW: "案件沒有匯出成功" }),
        detailText: {
          en: "No output file was written. Try another report type or location; open Technical details if it keeps happening.",
          zhTW: "沒有寫出檔案；請改用另一種報告格式或儲存位置。如果問題持續發生，請查看「技術細節」。",
        },
        detail: text({
          en: "No output file was written. Try another report type or location; open Technical details if it keeps happening.",
          zhTW: "沒有寫出檔案；請改用另一種報告格式或儲存位置。如果問題持續發生，請查看「技術細節」。",
        }),
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
      const presentation = caseExportVerificationCopy[result.data.outcome];
      if (result.data.outcome === "native_failed") {
        recordTechnicalError("verify case export", result.data.message);
      }
      pushToast({
        tone: presentation.tone,
        title: text(presentation.title),
        detail: text(presentation.detail),
      });
    } catch (error) {
      recordTechnicalError("verify case export", error);
      pushToast({
        tone: "danger",
        title: text({ en: "The file could not be verified", zhTW: "目前無法驗證這個檔案" }),
        detail: text({
          en: "Choose it again, or ask the sender for a new case package.",
          zhTW: "請重新選擇，或請寄件者提供新的案件包。",
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
  const currentRun = selectedReportRunId === undefined
    ? workspace?.runs[0]
    : workspace?.runs.find((run) => run.id === selectedReportRunId);
  const currentBeginnerReport = currentRun
    ? workspace?.beginnerReports?.find((report) => report.runId === currentRun.id)
    : undefined;

  // Correlation is a pure function of the case's findings and its active
  // groups, so recomputing on any other workspace change would be wasted work.
  // Sorted ids, because arrival order is not a meaningful difference.
  const correlationInputKey = useMemo(() => JSON.stringify([
    currentCaseId ?? "",
    workspace?.findings.map((finding) => finding.id).sort() ?? [],
    workspace?.findingGroups.map((group) => group.id).sort() ?? [],
  ]), [currentCaseId, workspace?.findings, workspace?.findingGroups]);

  useEffect(() => {
    const caseId = currentCaseId;
    const generation = ++correlationRequestGeneration.current;
    if (!caseId) {
      setCorrelationReport(undefined);
      return;
    }
    void (async () => {
      let report: CorrelationReport | undefined;
      try {
        report = (await scannerService.suggestFindingCorrelations(caseId)).data;
      } catch {
        // A read that failed is not evidence that nothing is related. Clearing
        // the report makes the panel disappear rather than assert an all-clear.
        report = undefined;
      }
      if (generation !== correlationRequestGeneration.current) return;
      setCorrelationReport(report);
    })();
    // `correlationInputKey` is the only dependency needed: it already folds in
    // the case id and every finding and group the computation reads.
  }, [correlationInputKey, currentCaseId]);

  const startScannerSetupBlocker = scanReadiness
    && scanReadiness.caseId === currentCaseId
    && isScannerSetupBlocker(scanReadiness.blockerCode)
    ? scanReadiness.blockerCode
    : undefined;
  const showStartRuntimeSetup = shouldShowRuntimeSetupAssistant({
    mode,
    runtimeAvailable: snapshot?.runtime?.available,
    status: runtimeSetup,
    requestPending: runtimeSetupRequestPending,
    selectedScanNeedsSetup: startScannerSetupBlocker !== undefined,
  });
  const coverageRuntimePreparing = mode === "native"
    && snapshot?.runtime?.available !== true
    && (runtimeSetupRequestPending || runtimeSetupPolling);

  const content = (() => {
    if (loading && !snapshot) {
      return (
        <div className="loading-state" role="status">
          <span className="loading-spinner" aria-hidden="true" />
          <strong>{t("shell.data.loadingTitle")}</strong>
          <span>{t("shell.data.loadingDetail")}</span>
        </div>
      );
    }

    if (snapshotRefreshUnavailable && !snapshot) {
      return (
        <div className="loading-state loading-state--error" role="alert">
          <span className="loading-state__icon" aria-hidden="true"><Icon name="warning" size={24} /></span>
          <strong>{t("shell.data.initialErrorTitle")}</strong>
          <span>{t("shell.data.initialErrorDetail")}</span>
          <button className="button button--primary" type="button" onClick={() => void loadSnapshot()}>
            <Icon name="refresh" size={16} /> {t("shell.data.retry")}
          </button>
        </div>
      );
    }

    if (page === "start") {
      return (
        <StartPage
          locale={locale}
          copy={startPageCopy[locale]}
          nativeMode={mode === "native"}
          localhostQuickScanBusy={busyAction === "localhost-quick-scan"}
          onStartLocalhostQuickScan={(port) => void startLocalhostQuickScan(port)}
          setupFocusKey={runtimeSetupFocusKey}
          setup={showStartRuntimeSetup ? (
            <RuntimeSetupAssistant
              locale={locale}
              mode={mode}
              runtime={snapshot?.runtime}
              status={runtimeSetup}
              busy={runtimeSetupRequestPending
                || runtimeSetup?.active
                || runtimeSetup?.prerequisiteRepairActive}
              scannerIssueBusy={busyAction === "scan-readiness"}
              scannerSetupBlocker={startScannerSetupBlocker}
              onSetup={() => void setupManagedRuntime()}
              onCheckScannerAvailability={() => {
                if (currentCaseId) void retryScanReadiness(currentCaseId);
              }}
              onCancel={() => void cancelManagedRuntimeSetup()}
            />
          ) : undefined}
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
          findingCount={workspace?.findings.filter(isSecurityFinding).length ?? 0}
          unknownSourceCount={workspace?.coverage.filter((item) => item.state === "source_unavailable_unknown").length ?? 0}
          connectedNoAssetSourceCount={workspace?.coverage.filter((item) => item.state === "source_connected_none").length ?? 0}
          latestRun={workspace?.runs[0]}
          runs={workspace?.runs ?? []}
          verificationBaselineRunId={verificationBaselineRunId}
          busy={["create", "create-local", "seed-demo", "archive-case", "delete-case", "delete-artifacts", "rescan"].includes(busyAction ?? "")}
          preparingLocalSnapshot={busyAction === "create-local"}
          nativeMode={scannerService.isNative()}
          artifactCleanupPlan={artifactCleanupPlan}
          artifactCleanupResult={artifactCleanupResult}
          onClearPreset={() => {
            setSelectedUseCase(undefined);
            navigate("start");
          }}
          onCreate={createCase}
          onCreateWithWorkspace={createCaseWithWorkspace}
          onCreateWithWorkspaces={createCaseWithWorkspaces}
          onChooseWorkspace={() => scannerService.chooseWorkspaceDirectory()}
          onSeedDemo={seedDemoCase}
          onArchive={(caseId) => runAction("archive-case", () => scannerService.archiveCase(caseId))}
          onDelete={deleteCase}
          onDeleteArtifacts={deleteCaseArtifacts}
          onDismissArtifactCleanup={dismissArtifactCleanup}
          onStartNewScan={() => {
            setSelectedUseCase(undefined);
            navigate("start");
          }}
          onOpenCase={(caseId) => void openCaseAtUsefulStep(caseId)}
          onContinue={() => navigate("coverage")}
          onOpenProgress={() => navigate("progress")}
          onOpenResults={() => navigate("findings")}
          onSelectVerificationBaseline={setVerificationBaselineRunId}
          onStartRescan={(baselineRunId) => currentCaseId
            ? runAction("rescan", () => scannerService.startRescan(currentCaseId, baselineRunId))
            : Promise.resolve()}
          onOpenVerification={() => navigate("verification")}
        />
      );
    }

    if (page === "settings") {
      return (
        <SettingsPage
          locale={locale}
          mode={mode}
          runtimeAvailable={snapshot?.runtime?.available}
          onLocaleChange={setLocale}
          onOpenNewScan={() => navigate("start")}
          onOpenProjects={() => navigate("cases")}
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
            engineManifests={snapshot?.engineManifests ?? []}
            assets={workspace.assets}
            scopeGrants={workspace.scopeGrants}
            nativeMode={mode === "native"}
            busy={busyAction === "connect-source" || busyAction === "attach-workspace" || busyAction === "discovery" || busyAction === "start-scan" || coverageRuntimePreparing}
            discoveryBusy={busyAction === "discovery"}
            runtimeSetupNotice={(
              coverageRuntimePreparing
              || (snapshot?.runtime?.available !== true && runtimeSetup?.nextAction === "restart_windows")
            ) ? (
              <>
                <InlineNotice
                  tone="info"
                  title={text(pendingRuntimeScanStart.current?.input.caseId === currentCaseId
                    ? { en: "Preparing the tools this scan needs", zhTW: "正在準備這次掃描需要的工具" }
                    : runtimeSetup?.nextAction === "restart_windows"
                      ? { en: "Restart Windows, then continue this scan", zhTW: "重新啟動 Windows，再繼續這次掃描" }
                      : { en: "Finish preparing the tools, then start this scan", zhTW: "完成工具準備，再開始這次掃描" })}
                >
                  <p>{text(pendingRuntimeScanStart.current?.input.caseId === currentCaseId
                    ? {
                      en: "Progress and download status appear below. When the tools are ready, this exact reviewed scan will start automatically.",
                      zhTW: "下載與準備進度會顯示在下方。工具就緒後，這次已確認的掃描會自動開始。",
                    }
                    : runtimeSetup?.nextAction === "restart_windows"
                      ? {
                        en: "Your scan project and choices are saved. After the restart, reopen this project, continue tool setup, review the selected target, and press Start.",
                        zhTW: "掃描專案與選擇都已保存。重新啟動後，請再次開啟這個專案、繼續工具設定，確認已選目標後按下「開始」。",
                      }
                      : {
                        en: "Progress appears below. When setup finishes, review the selected target and press Start.",
                        zhTW: "準備進度會顯示在下方。完成後，請確認已選目標並按下「開始」。",
                      })}</p>
                </InlineNotice>
                <RuntimeSetupAssistant
                  locale={locale}
                  mode={mode}
                  runtime={snapshot?.runtime}
                  status={runtimeSetup}
                  busy={runtimeSetupRequestPending
                    || runtimeSetup?.active
                    || runtimeSetup?.prerequisiteRepairActive}
                  scannerIssueBusy={busyAction === "scan-readiness"}
                  scannerSetupBlocker={startScannerSetupBlocker}
                  onSetup={() => void setupManagedRuntime()}
                  onCheckScannerAvailability={() => void retryScanReadiness(currentCaseId)}
                  onCancel={() => void cancelManagedRuntimeSetup()}
                />
              </>
            ) : undefined}
            onChooseSnapshot={() => scannerService.chooseSourceSnapshot()}
            onConnectSourceSnapshot={(input) => runAction("connect-source", () => scannerService.connectSourceSnapshot(input))}
            onChooseWorkspace={() => scannerService.chooseWorkspaceDirectory()}
            onAttachWorkspaceSnapshot={(input) => executeAction("attach-workspace", () => scannerService.attachWorkspaceSnapshot(input))}
            onStartDiscovery={() => runAction("discovery", () => scannerService.startDiscovery(currentCaseId))}
            onAuthorizationChanged={async () => {
              await loadSnapshot(currentCaseId, true);
            }}
            onStartScan={(assetIds, modes, confirmation, externalScope, engineIds) => startScan({
              caseId: currentCaseId,
              authorization: { assetIds, modes, confirmation, externalScope },
              engineIds,
            })}
            onStartEnvironmentScan={(authorizations, engineAssetRoutes) => startScan({
              caseId: currentCaseId,
              authorizations,
              engineAssetRoutes,
            })}
          />
        );
      case "progress":
        return (
          <ProgressPage
            caseId={currentCaseId}
            assessmentIntent={workspace.case.assessmentIntent}
            assets={workspace.assets}
            report={currentBeginnerReport}
            runs={workspace.runs}
            findings={workspace.findings}
            selectedRunId={currentRun?.id}
            readiness={scanReadiness?.caseId === currentCaseId ? scanReadiness : undefined}
            readinessCheckFailed={scanReadinessErrorCaseId === currentCaseId}
            diagnosticContext={{
              productVersion: snapshot?.productVersion,
              runtime: snapshot?.runtime,
            }}
            busy={Boolean(busyAction)}
            starting={Boolean(currentCaseId && busyAction === "start-scan" && startingScanCaseId === currentCaseId)}
            retryingLocalhostQuickScan={busyAction === "localhost-quick-scan"}
            onStart={async () => {
              if (currentCaseId) await startScan({ caseId: currentCaseId });
            }}
            onRetryLocalhostQuickScan={startLocalhostQuickScan}
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
            onPause={(runId) => runAction("pause-scan", () => scannerService.pauseScan(currentCaseId, runId), runId)}
            onResume={(runId) => runAction("resume-scan", () => scannerService.resumeScan(currentCaseId, runId), runId)}
            onCancel={(runId) => runAction("cancel-scan", () => scannerService.cancelScan(currentCaseId, runId))}
            onSelectRun={setSelectedReportRunId}
          />
        );
      case "findings":
        return (
          <FindingsPage
            report={currentBeginnerReport}
            selectedRunId={selectedReportRunId}
            reportUnavailable={!(mode === "demo" || Boolean(workspace.case.isDemo))
              && Boolean((currentRun || selectedReportRunId) && !currentBeginnerReport)}
            findings={workspace.findings}
            findingGroups={workspace.findingGroups}
            findingGroupEvents={workspace.findingGroupEvents}
            correlationReport={correlationReport}
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
                en: "Presentation group removed from the Problems found page.",
                zhTW: "已從「發現的問題」頁面移除呈現群組。",
              }),
            }))}
            onOpenCoverage={() => navigate("coverage")}
            onOpenProgress={() => navigate("progress")}
            onOpenExport={(runId) => {
              setSelectedReportRunId(runId);
              navigate("export");
            }}
            onSelectRun={setSelectedReportRunId}
          />
        );
      case "export":
        return (
          <ExportPage
            workspace={workspace}
            selectedRunId={selectedReportRunId}
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
              const findingRunId = workspace.findings.find((finding) => finding.id === findingId)?.lastSeenRunId;
              if (findingRunId && workspace.runs.some((run) => run.id === findingRunId)) {
                setSelectedReportRunId(findingRunId);
              }
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
        dataUnavailable={snapshotRefreshUnavailable && snapshot !== undefined}
        dataRetrying={loading && (snapshotRefreshUnavailable
          || Boolean(snapshot?.caseRecoveryDiagnostics?.length))}
        onRetryData={() => void loadSnapshot(snapshot?.selectedCaseId)}
        caseRecoveryDiagnostics={snapshot?.caseRecoveryDiagnostics}
        caseSelectionUnavailable={caseSelectionUnavailableId !== undefined}
        caseSelectionRetrying={caseSelectionUnavailableId !== undefined && loading}
        onRetryCaseSelection={() => {
          if (caseSelectionUnavailableId) void selectCase(caseSelectionUnavailableId);
        }}
        onNavigate={navigate}
        onSelectCase={(caseId) => void selectCase(caseId)}
        appUpdate={appUpdate}
        onCheckForUpdate={() => void checkAppUpdate()}
        onInstallUpdate={(version) => void installUpdate(version)}
        runtime={snapshot?.runtime}
        runtimeSetup={runtimeSetup}
        runtimeBusy={runtimeSetupRequestPending
          || runtimeSetup?.active
          || runtimeSetup?.prerequisiteRepairActive}
        onSetupRuntime={() => void setupManagedRuntime()}
        onCancelRuntime={() => void cancelManagedRuntimeSetup()}
      >
        {content}
      </AppShell>

      <div
        className="toast-region"
        role="region"
        aria-live="polite"
        aria-label={text({ en: "Application notifications", zhTW: "應用程式通知" })}
      >
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast--${toast.tone}`}>
            <Icon name={toast.tone === "success" ? "check" : toast.tone === "danger" || toast.tone === "warning" ? "warning" : "info"} size={19} />
            <div>
              <strong>{toast.titleText ? text(toast.titleText) : toast.title}</strong>
              {(toast.detailText || toast.detail) && (
                <span>{toast.detailText ? text(toast.detailText) : toast.detail}</span>
              )}
              {toast.actionLabel && (toast.action || toast.actionPage) && (
                <button
                  className="toast__action"
                  type="button"
                  onClick={() => {
                    setToasts((current) => current.filter((item) => item.id !== toast.id));
                    if (toast.action) toast.action();
                    else if (toast.actionPage) navigate(toast.actionPage);
                  }}
                >
                  {toast.actionLabelText ? text(toast.actionLabelText) : toast.actionLabel}
                </button>
              )}
            </div>
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
