import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";

import {
  createStoredDemoCase,
  getDemoNotice,
  getDemoSnapshot,
  getDemoWorkspace,
} from "../data/demo";
import { getActiveLocale } from "../i18n/core";
import {
  DEFAULT_LOCALHOST_QUICK_SCAN_PORT,
  isValidLocalhostQuickScanPort,
} from "../localhostQuickScan";
import type {
  AppSnapshot,
  AttachWorkspaceSnapshotInput,
  BeginProviderAuthorizationInput,
  BootstrapOperatorConfig,
  BootstrapRequest,
  AssessmentCase,
  CaseExport,
  CaseArtifactCleanupInput,
  CaseArtifactCleanupResult,
  CaseDeletionResponse,
  CaseWorkspace,
  CloudPlatform,
  ConnectSourceSnapshotInput,
  CreateCaseInput,
  EngineManifest,
  ExportCaseInput,
  ExportPreview,
  ExternalScopeRequest,
  ExecuteProviderBootstrapInput,
  FindingWorkflowUpdateInput,
  FindingGroupInput,
  FindingUngroupInput,
  ServiceResult,
  ScopeMode,
  ProviderAuthorizationProgress,
  ProviderAuthorizationPrompt,
  BootstrapCleanupObligationSummary,
  ProviderBootstrapInstalled,
  ProviderBootstrapPlan,
  InstalledProviderAuthorization,
  ManagedRuntimeSetupStatus,
  LocalNetworkCandidateInventory,
  ScanReadiness,
} from "../types";
import { buildNativeExportCaseArguments } from "../exportRequest";
import { subscribeBufferedEvents } from "./bufferedEventSubscription";
import {
  adaptLocalNetworkCandidateInventory,
  adaptManagedRuntimeSetupStatus,
  adaptNativeCase,
  adaptNativeExport,
  adaptNativeExportPreview,
  adaptNativeManifest,
  adaptNativeSnapshot,
  type NativeAppSnapshot,
  type NativeAssessmentCase,
  type NativeCaseExport,
  type NativeExportPreview,
  type NativeEngineManifest,
  type NativeManagedRuntimeSetupStatus,
} from "./nativeAdapter";

export const COMMANDS = {
  getSnapshot: "get_app_snapshot",
  setupManagedRuntime: "setup_managed_runtime",
  getManagedRuntimeSetupStatus: "get_managed_runtime_setup_status",
  cancelManagedRuntimeSetup: "cancel_managed_runtime_setup",
  createCase: "create_case",
  selectCase: "select_case",
  seedDemoCase: "seed_demo_case",
  listEngineManifests: "list_engine_manifests",
  detectLocalPrivateSubnets: "detect_local_private_subnets",
  getScanReadiness: "get_scan_readiness",
  startDiscovery: "start_discovery",
  cancelDiscovery: "cancel_discovery",
  connectSourceSnapshot: "connect_source_snapshot",
  attachWorkspaceSnapshot: "attach_workspace_snapshot",
  approveScope: "approve_scope",
  updateFindingWorkflow: "update_finding_workflow",
  groupFindings: "group_findings",
  ungroupFindings: "ungroup_findings",
  startLocalhostQuickScan: "start_localhost_quick_scan",
  startScan: "start_scan",
  pauseScan: "pause_scan",
  resumeScan: "resume_scan",
  cancelScan: "cancel_scan",
  previewExport: "preview_export",
  exportCase: "export_case",
  verifyCaseExport: "verify_case_export",
  startRescan: "start_rescan",
  archiveCase: "archive_case",
  deleteCase: "delete_case",
  deleteCaseArtifacts: "delete_case_artifacts",
  beginProviderAuthorization: "begin_provider_authorization",
  pollProviderAuthorization: "poll_provider_authorization",
  cancelProviderAuthorization: "cancel_provider_authorization",
  providerAuthorizationStatus: "provider_authorization_status",
  revokeProviderAuthorization: "revoke_provider_authorization",
  planProviderBootstrap: "plan_provider_bootstrap",
  executeProviderBootstrap: "execute_provider_bootstrap",
  cleanupProviderBootstrap: "cleanup_provider_bootstrap",
  listProviderBootstrapCleanup: "list_provider_bootstrap_cleanup",
} as const;

export const EVENTS = {
  coverageChanged: "case://coverage-changed",
  runProgress: "scan://run-progress",
  runFinished: "scan://run-finished",
  exportProgress: "export://progress",
  bootstrapMessage: "provider://bootstrap-message",
} as const;

export type ScannerEventName = (typeof EVENTS)[keyof typeof EVENTS];

export interface ScannerEventEnvelope<T = unknown> {
  schemaVersion: "1.0.0";
  eventType: ScannerEventName;
  occurredAt: string;
  payload: T;
}

const packagedTauriPlatform = import.meta.env?.TAURI_ENV_PLATFORM?.trim();

const hasLiveTauriBridge = (): boolean =>
  typeof window !== "undefined" &&
  typeof (window as Window & {
    __TAURI_INTERNALS__?: { invoke?: unknown };
  }).__TAURI_INTERNALS__?.invoke === "function";

/**
 * Demo data belongs only to the explicit browser-development surface. A
 * packaged desktop build stays native even while its bridge is starting or
 * unavailable, so a bridge failure can never silently change real projects
 * into sample data.
 */
const isNativeSurface = (): boolean => Boolean(packagedTauriPlatform) || hasLiveTauriBridge();

const invoke = async <T,>(command: string, args?: Record<string, unknown>): Promise<T> => {
  if (!hasLiveTauriBridge()) {
    throw new Error(serviceText(
      "The desktop service is not ready. No sample data was substituted. Keep the app open and try again.",
      "桌面服務尚未就緒；程式沒有改用範例資料。請讓程式保持開啟並再試一次。",
    ));
  }
  return tauriInvoke<T>(command, args);
};

const errorMessage = (error: unknown): string => {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch {
    return "Unknown error";
  }
};

const serviceText = (en: string, zhTW: string): string =>
  getActiveLocale() === "en" ? en : zhTW;

const nativeResult = <T,>(data: T): ServiceResult<T> => ({ data, mode: "native" });

interface NativeScanReadiness {
  case_id: string;
  checked_at: string;
  ready: boolean;
  state: ScanReadiness["state"];
  authorized_target_count: number;
  pending_target_count: number;
  compatible_engine_count: number;
  runnable_engine_count: number;
  blocker_code: ScanReadiness["blockerCode"] | null;
  next_step: ScanReadiness["nextStep"] | null;
}

const adaptScanReadiness = (value: NativeScanReadiness): ScanReadiness => ({
  caseId: value.case_id,
  checkedAt: value.checked_at,
  ready: value.ready,
  state: value.state,
  authorizedTargetCount: value.authorized_target_count,
  pendingTargetCount: value.pending_target_count,
  compatibleEngineCount: value.compatible_engine_count,
  runnableEngineCount: value.runnable_engine_count,
  blockerCode: value.blocker_code ?? undefined,
  nextStep: value.next_step ?? undefined,
});

const demoResult = <T,>(data: T, reason?: string): ServiceResult<T> => {
  if (reason) console.warn("[ai-security-scanner] desktop service unavailable", reason);
  return { data, mode: "demo", notice: getDemoNotice() };
};

const demoRuntimeSetupStatus = (): ManagedRuntimeSetupStatus => ({
  phase: "idle",
  active: false,
  prerequisiteRepairActive: false,
  cancelRequested: false,
  receivedBytes: 0,
  resumedFromBytes: 0,
  canCancel: false,
  canRetry: true,
  detail: serviceText(
    "Demo mode does not download or start a scan environment.",
    "展示模式不會下載或啟動掃描環境。",
  ),
});

const getNativeManifests = async (): Promise<NativeEngineManifest[]> => {
  try {
    return await invoke<NativeEngineManifest[]>(COMMANDS.listEngineManifests);
  } catch {
    // A usable case snapshot should stay native even if the optional registry view fails.
    return [];
  }
};

const actionResult = async (
  command: string,
  args: Record<string, unknown>,
  nativeMessage: string,
  demoMessage: string,
  returnWorkspace = false,
): Promise<ServiceResult<ActionResponse>> => {
  if (!isNativeSurface()) {
    return demoResult({ accepted: false, message: demoMessage });
  }
  try {
    const returnedCase = await invoke<NativeAssessmentCase>(command, args);
    const workspace = adaptNativeCase(
      returnedCase,
      returnWorkspace ? (await getNativeManifests()).map(adaptNativeManifest) : [],
    );
    return nativeResult({
      accepted: true,
      message: nativeMessage,
      workspace: returnWorkspace ? workspace : undefined,
    });
  } catch (error) {
    return nativeResult({ accepted: false, message: errorMessage(error) });
  }
};

const employeeRanges: Record<CreateCaseInput["companySize"], string> = {
  solo: "1",
  small: "2-49",
  medium: "50-249",
  large: "250+",
};

const nativeDataClasses: Record<CreateCaseInput["dataClasses"][number], string> = {
  pii: "personally_identifiable_information",
  phi: "protected_health_information",
  payment: "payment_card_information",
  credentials: "credentials_and_secrets",
  none: "general",
};

const platformSourceKinds: Record<CloudPlatform, ConnectSourceSnapshotInput["sourceKind"][]> = {
  aws: ["aws_organization"],
  azure: ["azure_tenant"],
  gcp: ["gcp_organization"],
  m365: ["microsoft365_tenant"],
  external: ["dns", "certificate_transparency"],
  code: ["git_repository", "terraform_state", "file_system"],
  container: ["container_registry"],
  kubernetes: ["kubernetes_cluster"],
};

export const plannedSourceKinds = (platforms: CloudPlatform[]): ConnectSourceSnapshotInput["sourceKind"][] =>
  [...new Set(platforms.flatMap((platform) => platformSourceKinds[platform]))];

const questionnaireSourceKinds = [...new Set(Object.values(platformSourceKinds).flat())];

export const plannedNotApplicableSourceKinds = (
  platforms: CloudPlatform[],
): ConnectSourceSnapshotInput["sourceKind"][] => {
  const applicable = new Set(plannedSourceKinds(platforms));
  return questionnaireSourceKinds.filter((kind) => !applicable.has(kind));
};

const exportFileTypes: Record<ExportCaseInput["format"], { suffix: string; extensions: string[]; label: string }> = {
  case_bundle: { suffix: "case.tar.gz", extensions: ["gz"], label: "ai-security-scanner case bundle" },
  json: { suffix: "json", extensions: ["json"], label: "Canonical JSON" },
  framework_report: {
    suffix: "frameworks.json",
    extensions: ["json"],
    label: "NIST, ISO, and AIDEFEND framework report",
  },
  ocsf: { suffix: "ocsf.json", extensions: ["json"], label: "OCSF JSON" },
  oscal: { suffix: "oscal.json", extensions: ["json"], label: "OSCAL JSON" },
  html: { suffix: "html", extensions: ["html"], label: "HTML report" },
};

export interface ActionResponse {
  accepted: boolean;
  message: string;
  snapshot?: AppSnapshot;
  workspace?: CaseWorkspace;
}

export type CaseExportVerificationResult =
  | { outcome: "verified"; message: string }
  | { outcome: "native_failed"; message: string }
  | { outcome: "demo_unavailable"; message: string };

export interface ScopeApprovalInput {
  caseId: string;
  assetIds: string[];
  modes: ScopeMode[];
  confirmation: string;
  externalScope?: ExternalScopeRequest;
}

export interface StartScanInput {
  caseId: string;
  /** Present only when Start also records the inline target assertion. */
  authorization?: Omit<ScopeApprovalInput, "caseId">;
  /** Empty means every applicable scanner. */
  engineIds?: string[];
}

const nativeScopeDecisions = (input: ScopeApprovalInput) => {
  const permissionMap: Record<string, string> = {
    inventory: "inventory_read",
    configuration: "configuration_read",
    local_artifact: "local_artifact_read",
    public_data: "passive_external_discovery",
    passive: "passive_external_discovery",
    low_impact_external: "low_impact_external_connection",
    active_external: "active_external_testing",
    active: "active_external_testing",
  };
  const permissions = input.modes
    .map((mode) => permissionMap[mode])
    .filter((mode): mode is string => Boolean(mode));
  const needsReference = permissions.some((permission) =>
    permission === "low_impact_external_connection" || permission === "active_external_testing"
  );
  const externalScope = input.externalScope ? {
    target: input.externalScope.target,
    ports: input.externalScope.ports,
    protocol: input.externalScope.protocol,
    activity: input.externalScope.activity,
    rate_policy: {
      requests_per_second: input.externalScope.ratePolicy.requestsPerSecond,
      concurrency: input.externalScope.ratePolicy.concurrency,
      timeout_seconds: input.externalScope.ratePolicy.timeoutSeconds,
    },
    template_policy: {
      revision: input.externalScope.templatePolicy.revision,
      allowed_template_ids: input.externalScope.templatePolicy.allowedTemplateIds,
      allow_headless: input.externalScope.templatePolicy.allowHeadless,
      allow_out_of_band: input.externalScope.templatePolicy.allowOutOfBand,
      allow_fuzzing: input.externalScope.templatePolicy.allowFuzzing,
      allow_file_upload: input.externalScope.templatePolicy.allowFileUpload,
      allow_denial_of_service: input.externalScope.templatePolicy.allowDenialOfService,
      allow_credential_attacks: input.externalScope.templatePolicy.allowCredentialAttacks,
    },
    asserted_authority: input.externalScope.assertedAuthority,
    allow_sensitive_networks: input.externalScope.allowSensitiveNetworks,
  } : null;
  return input.assetIds.map((assetId) => ({
    asset_id: assetId,
    permissions,
    confirmed_by: serviceText("Local user", "本機使用者"),
    authorization_reference: needsReference || input.externalScope ? input.confirmation : null,
    notes: input.confirmation,
    external_scope: externalScope,
  }));
};

interface NativeCaseDeletionResult {
  database_record_deleted: boolean;
  artifacts: {
    case_id: string;
    exact_path: string;
    exists: boolean;
    requires_explicit_confirmation: boolean;
  };
}

interface NativeCaseArtifactCleanupResult {
  removed: boolean;
  exact_path: string;
  recoverable: boolean;
}

export const scannerService = {
  isNative: isNativeSurface,

  async getSnapshot(caseId?: string): Promise<ServiceResult<AppSnapshot>> {
    if (!isNativeSurface()) return demoResult(getDemoSnapshot(caseId));
    const nativeSnapshot = await invoke<NativeAppSnapshot>(COMMANDS.getSnapshot);
    const manifests = await getNativeManifests();
    return nativeResult(adaptNativeSnapshot(nativeSnapshot, manifests));
  },

  async setupManagedRuntime(): Promise<ServiceResult<ActionResponse>> {
    if (!isNativeSurface()) return demoResult({
      accepted: false,
      message: serviceText(
        "Demo mode does not install or start a scan environment.",
        "展示模式不會安裝或啟動掃描環境。",
      ),
    });
    const response = await invoke<{ accepted: boolean; message: string }>(COMMANDS.setupManagedRuntime);
    return nativeResult(response);
  },

  async getManagedRuntimeSetupStatus(): Promise<ServiceResult<ManagedRuntimeSetupStatus>> {
    if (!isNativeSurface()) return demoResult(demoRuntimeSetupStatus());
    const status = await invoke<NativeManagedRuntimeSetupStatus>(COMMANDS.getManagedRuntimeSetupStatus);
    return nativeResult(adaptManagedRuntimeSetupStatus(status));
  },

  async cancelManagedRuntimeSetup(): Promise<ServiceResult<ManagedRuntimeSetupStatus>> {
    if (!isNativeSurface()) return demoResult(demoRuntimeSetupStatus());
    const status = await invoke<NativeManagedRuntimeSetupStatus>(COMMANDS.cancelManagedRuntimeSetup);
    return nativeResult(adaptManagedRuntimeSetupStatus(status));
  },

  async createCase(input: CreateCaseInput): Promise<ServiceResult<AssessmentCase>> {
    if (!isNativeSurface()) return demoResult(createStoredDemoCase(input));
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.createCase, {
      request: {
        title: input.name,
        assessment_intent: input.assessmentIntent ?? null,
        ai_generated_artifact: input.aiGeneratedArtifact,
        organization_name: input.organizationName,
        employee_range: employeeRanges[input.companySize],
        data_classes: input.dataClasses.map((dataClass) => nativeDataClasses[dataClass]),
        requested_activities: input.requestedActivities,
        source_kinds: plannedSourceKinds(input.platforms),
        not_applicable_source_kinds: plannedNotApplicableSourceKinds(input.platforms),
        declared_assets: input.knownAssets.map(({ internetExposure, webService, ...asset }) => ({
          ...asset,
          internet_exposed: internetExposure === undefined
            ? null
            : internetExposure === "public",
          web_service: webService
            ? {
              protocol: webService.protocol,
              port: webService.port,
              path: webService.path,
            }
            : null,
        })),
        notes: input.description ?? null,
      },
    });
    return nativeResult(adaptNativeCase(nativeCase).case);
  },

  async selectCase(caseId: string): Promise<ServiceResult<CaseWorkspace>> {
    if (!isNativeSurface()) return demoResult(getDemoWorkspace(caseId));
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.selectCase, { caseId });
    const manifests = (await getNativeManifests()).map(adaptNativeManifest);
    return nativeResult(adaptNativeCase(nativeCase, manifests));
  },

  async listEngineManifests(): Promise<ServiceResult<EngineManifest[]>> {
    const demo = getDemoSnapshot().engineManifests;
    if (!isNativeSurface()) return demoResult(demo);
    return nativeResult((await getNativeManifests()).map(adaptNativeManifest));
  },

  async detectLocalPrivateSubnets(): Promise<ServiceResult<LocalNetworkCandidateInventory>> {
    const fallback: LocalNetworkCandidateInventory = {
      status: isNativeSurface() ? "unavailable" : "unsupported",
      candidates: [],
    };
    if (!isNativeSurface()) return demoResult(fallback);
    try {
      const inventory = await invoke<unknown>(COMMANDS.detectLocalPrivateSubnets);
      return nativeResult(adaptLocalNetworkCandidateInventory(inventory));
    } catch {
      // Interface detection is an optional convenience. Never expose native
      // details or turn a detection failure into a guessed scan target.
      return nativeResult(fallback);
    }
  },

  async getScanReadiness(caseId: string): Promise<ServiceResult<ScanReadiness>> {
    if (!isNativeSurface()) return demoResult({
      caseId,
      checkedAt: new Date().toISOString(),
      ready: false,
      state: "case_unavailable",
      authorizedTargetCount: 0,
      pendingTargetCount: 0,
      compatibleEngineCount: 0,
      runnableEngineCount: 0,
      blockerCode: "demo_case",
      nextStep: "cases",
    });
    return nativeResult(adaptScanReadiness(await invoke<NativeScanReadiness>(
      COMMANDS.getScanReadiness,
      { caseId },
    )));
  },

  async beginProviderAuthorization(
    request: BeginProviderAuthorizationInput,
  ): Promise<ServiceResult<ProviderAuthorizationPrompt>> {
    if (!isNativeSurface()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<ProviderAuthorizationPrompt>(COMMANDS.beginProviderAuthorization, { request }));
  },

  async pollProviderAuthorization(
    sessionId: string,
  ): Promise<ServiceResult<ProviderAuthorizationProgress>> {
    if (!isNativeSurface()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<ProviderAuthorizationProgress>(COMMANDS.pollProviderAuthorization, { sessionId }));
  },

  async cancelProviderAuthorization(sessionId: string): Promise<ServiceResult<boolean>> {
    if (!isNativeSurface()) return demoResult(false);
    return nativeResult(await invoke<boolean>(COMMANDS.cancelProviderAuthorization, { sessionId }));
  },

  async providerAuthorizationStatus(
    caseId: string,
    sourceId: string,
  ): Promise<ServiceResult<InstalledProviderAuthorization | null>> {
    if (!isNativeSurface()) return demoResult(null);
    return nativeResult(await invoke<InstalledProviderAuthorization | null>(COMMANDS.providerAuthorizationStatus, {
      caseId,
      sourceId,
    }));
  },

  async revokeProviderAuthorization(
    caseId: string,
    sourceId: string,
  ): Promise<ServiceResult<Record<string, unknown>>> {
    if (!isNativeSurface()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<Record<string, unknown>>(COMMANDS.revokeProviderAuthorization, {
      caseId,
      sourceId,
    }));
  },

  async planProviderBootstrap(request: BootstrapRequest): Promise<ServiceResult<ProviderBootstrapPlan>> {
    if (!isNativeSurface()) throw new Error("Provider bootstrap requires the native app.");
    return nativeResult(await invoke<ProviderBootstrapPlan>(COMMANDS.planProviderBootstrap, { request }));
  },

  async executeProviderBootstrap(
    input: ExecuteProviderBootstrapInput,
  ): Promise<ServiceResult<ProviderBootstrapInstalled>> {
    if (!isNativeSurface()) throw new Error("Provider bootstrap requires the native app.");
    return nativeResult(await invoke<ProviderBootstrapInstalled>(COMMANDS.executeProviderBootstrap, { input }));
  },

  async cleanupProviderBootstrap(
    caseId: string,
    operationId: string,
    operator: BootstrapOperatorConfig,
  ): Promise<ServiceResult<Record<string, unknown>>> {
    if (!isNativeSurface()) throw new Error("Provider cleanup requires the native app.");
    return nativeResult(await invoke<Record<string, unknown>>(COMMANDS.cleanupProviderBootstrap, {
      caseId,
      operationId,
      operator,
    }));
  },

  async listProviderBootstrapCleanup(
    caseId: string,
  ): Promise<ServiceResult<BootstrapCleanupObligationSummary[]>> {
    if (!isNativeSurface()) return demoResult([]);
    return nativeResult(await invoke<BootstrapCleanupObligationSummary[]>(
      COMMANDS.listProviderBootstrapCleanup,
      { caseId },
    ));
  },

  async startDiscovery(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.startDiscovery,
      { caseId },
      serviceText("The case is now finding assets.", "案件已開始尋找資產。"),
      serviceText("Demo mode does not connect to or inventory a real data source.", "展示模式不會連接或盤點任何真實資料來源。"),
    );
  },

  async cancelDiscovery(caseId: string): Promise<ServiceResult<boolean>> {
    if (!isNativeSurface()) return demoResult(false, serviceText(
      "Demo mode has no real inventory work to cancel.",
      "展示模式沒有執行中的真實盤點工作。",
    ));
    return nativeResult(await invoke<boolean>(COMMANDS.cancelDiscovery, { caseId }));
  },

  async chooseSourceSnapshot(): Promise<string | null> {
    if (!isNativeSurface()) return null;
    const selected = await open({
      title: serviceText("Choose a source JSON snapshot", "選擇一份來源 JSON 快照"),
      multiple: false,
      directory: false,
      filters: [{ name: "JSON snapshot", extensions: ["json"] }],
    });
    return typeof selected === "string" ? selected : null;
  },

  async connectSourceSnapshot(input: ConnectSourceSnapshotInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.connectSourceSnapshot,
      { ...input },
      serviceText(
        "The source snapshot was copied into the local case. It did not grant permission or start a scan.",
        "來源快照已複製進本機案件；尚未授權或啟動掃描。",
      ),
      serviceText(
        "Demo mode does not read, copy, or parse the file you selected.",
        "展示模式不會讀取、複製或解析你選擇的檔案。",
      ),
    );
  },

  async chooseWorkspaceDirectory(): Promise<string | null> {
    if (!isNativeSurface()) return null;
    const selected = await open({
      title: serviceText(
        "Choose the folder to copy into a read-only scan snapshot",
        "選擇要複製成唯讀掃描快照的資料夾",
      ),
      multiple: false,
      directory: true,
    });
    return typeof selected === "string" ? selected : null;
  },

  async attachWorkspaceSnapshot(input: AttachWorkspaceSnapshotInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.attachWorkspaceSnapshot,
      { ...input },
      serviceText(
        "The selected local input was attached to the case as a bounded snapshot. This did not grant ownership or scan permission.",
        "選定的本機輸入已用有限範圍的快照附加到案件；這不會授予所有權或掃描權限。",
      ),
      serviceText(
        "Demo mode does not read or copy the folder you selected.",
        "展示模式不會讀取或複製你選擇的資料夾。",
      ),
    );
  },

  async approveScope(input: ScopeApprovalInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.approveScope,
      {
        caseId: input.caseId,
        decisions: nativeScopeDecisions(input),
      },
      serviceText(
        "The selected target and permission boundary were recorded. No scan started automatically.",
        "已記錄選定目標與權限範圍；尚未自動開始掃描。",
      ),
      serviceText(
        "Demo mode only shows the permission flow and does not create real scan permission.",
        "展示模式只呈現權限流程，不會建立真實掃描授權。",
      ),
    );
  },

  async startScan(input: StartScanInput): Promise<ServiceResult<ActionResponse>> {
    const decisions = input.authorization
      ? nativeScopeDecisions({ caseId: input.caseId, ...input.authorization })
      : [];
    return actionResult(
      COMMANDS.startScan,
      {
        caseId: input.caseId,
        decisions,
        engineIds: input.engineIds ?? [],
      },
      serviceText(
        "Your exact target, limits, and scan were saved together. Unavailable checks will be listed in the report while the others continue.",
        "精確目標、限制與掃描已一起保存；無法執行的檢查會列在報告中，其餘檢查會繼續。",
      ),
      serviceText(
        "Demo mode does not start a container or contact a target.",
        "展示模式不會啟動容器，也不會接觸任何目標。",
      ),
      true,
    );
  },

  async startLocalhostQuickScan(
    port = DEFAULT_LOCALHOST_QUICK_SCAN_PORT,
  ): Promise<ServiceResult<ActionResponse>> {
    if (!isValidLocalhostQuickScanPort(port)) {
      const response = {
        accepted: false,
        message: serviceText(
          "Enter a whole-number local port from 1 to 65535.",
          "請輸入 1 到 65535 的整數本機連接埠。",
        ),
      };
      return isNativeSurface() ? nativeResult(response) : demoResult(response);
    }
    return actionResult(
      COMMANDS.startLocalhostQuickScan,
      { port },
      serviceText(
        "The localhost check was saved and started.",
        "本機連接埠檢查已儲存並開始。",
      ),
      serviceText(
        "Browser demo mode did not contact this computer or start a real scan.",
        "瀏覽器展示模式沒有連線這台電腦，也沒有開始真實掃描。",
      ),
      true,
    );
  },

  async updateFindingWorkflow(input: FindingWorkflowUpdateInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.updateFindingWorkflow,
      {
        caseId: input.caseId,
        request: {
          finding_id: input.findingId,
          status: input.status,
          decided_by: input.decidedBy,
          reason: input.reason,
          expires_at: input.expiresAt ?? null,
        },
      },
      serviceText(
        "The decision was added to the finding history. Original evidence was not changed.",
        "這項決定已加入問題歷程；原始證據沒有變更。",
      ),
      serviceText(
        "Demo mode does not save a real finding decision.",
        "展示模式不會保存真實的問題處理決定。",
      ),
    );
  },

  async groupFindings(input: FindingGroupInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.groupFindings,
      {
        caseId: input.caseId,
        request: {
          title: input.title,
          finding_ids: input.findingIds,
          rationale: input.rationale,
          grouped_by: input.groupedBy,
        },
      },
      serviceText(
        "The related findings were grouped for presentation. Every fingerprint, evidence item, and original artifact remains separate.",
        "相關問題已建立可移除的呈現群組；每筆指紋、證據與原始檔案仍分開保留。",
      ),
      serviceText(
        "Demo mode only shows the group and does not rewrite demo findings.",
        "展示模式只呈現群組，不會改寫展示問題。",
      ),
    );
  },

  async ungroupFindings(input: FindingUngroupInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.ungroupFindings,
      {
        caseId: input.caseId,
        request: {
          group_id: input.groupId,
          removed_by: input.removedBy,
          reason: input.reason,
        },
      },
      serviceText(
        "The presentation group was removed. Every finding and the group history remain available.",
        "呈現群組已移除；所有問題與群組歷程仍保留。",
      ),
      serviceText("Demo mode does not change demo groups.", "展示模式不會變更展示群組。"),
    );
  },

  async pauseScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.pauseScan,
      { caseId, runId },
      serviceText("The selected scan was paused.", "選定的掃描已暫停。"),
      serviceText("Demo mode has no real scan to pause.", "展示模式沒有可暫停的真實掃描。"),
      true,
    );
  },

  async resumeScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.resumeScan,
      { caseId, runId },
      serviceText("The selected scan was queued to continue.", "選定的掃描已排入佇列，準備繼續。"),
      serviceText("Demo mode has no real scan to resume.", "展示模式沒有可繼續的真實掃描。"),
      true,
    );
  },

  async cancelScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.cancelScan,
      { caseId, runId },
      serviceText("The selected scan was cancelled and the case now needs attention.", "選定的掃描已取消，案件現在需要處理。"),
      serviceText("Demo mode has no real scan to cancel.", "展示模式沒有可取消的真實掃描。"),
      true,
    );
  },

  async startRescan(caseId: string, baselineRunId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.startRescan,
      { caseId, baselineRunId },
      serviceText("The follow-up scan was created.", "後續確認掃描已建立。"),
      serviceText(
        "Demo mode does not run a follow-up scan; every comparison shown is marked sample data.",
        "展示模式不會執行後續確認掃描；目前差異都已標成樣本資料。",
      ),
      true,
    );
  },

  async archiveCase(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.archiveCase,
      { caseId },
      serviceText(
        "The case was archived. Its local data remains available, and no new work will be added.",
        "案件已封存；本機資料仍保留，而且不會再加入新工作。",
      ),
      serviceText("Demo mode does not change local case status.", "展示模式不會變更本機案件狀態。"),
    );
  },

  async deleteCase(caseId: string, confirmation: string): Promise<ServiceResult<CaseDeletionResponse>> {
    if (!isNativeSurface()) {
      return demoResult({
        accepted: false,
        message: serviceText(
          "Demo mode does not delete a local case or file.",
          "展示模式不會刪除任何本機案件或檔案。",
        ),
        databaseRecordDeleted: false,
        artifacts: {
          caseId,
          exactPath: "",
          exists: false,
          requiresExplicitConfirmation: true,
        },
      });
    }
    try {
      const response = await invoke<NativeCaseDeletionResult>(COMMANDS.deleteCase, { caseId, confirmation });
      const artifacts = {
        caseId: response.artifacts.case_id,
        exactPath: response.artifacts.exact_path,
        exists: response.artifacts.exists,
        requiresExplicitConfirmation: response.artifacts.requires_explicit_confirmation,
      };
      const artifactDetail = artifacts.exists
        ? serviceText(
          `The case record was deleted. Evidence remains at ${artifacts.exactPath} until you separately confirm cleanup.`,
          `案件紀錄已刪除；證據仍保留在 ${artifacts.exactPath}，必須另外確認才能清理。`,
        )
        : serviceText(
          "The case record was deleted. There is no remaining case evidence folder to clean up.",
          "案件紀錄已刪除；目前沒有需要清理的案件證據資料夾。",
        );
      return nativeResult({
        accepted: response.database_record_deleted,
        message: artifactDetail,
        databaseRecordDeleted: response.database_record_deleted,
        artifacts,
      });
    } catch (error) {
      return nativeResult({
        accepted: false,
        message: errorMessage(error),
        databaseRecordDeleted: false,
        artifacts: {
          caseId,
          exactPath: "",
          exists: false,
          requiresExplicitConfirmation: true,
        },
      });
    }
  },

  async deleteCaseArtifacts(input: CaseArtifactCleanupInput): Promise<ServiceResult<CaseArtifactCleanupResult>> {
    if (!isNativeSurface()) {
      return demoResult({ removed: false, exactPath: input.exactPath, recoverable: false });
    }
    const response = await invoke<NativeCaseArtifactCleanupResult>(COMMANDS.deleteCaseArtifacts, { ...input });
    if (response.recoverable) {
      throw new Error("The local service returned a result that violates the permanent-deletion contract.");
    }
    if (response.exact_path !== input.exactPath) {
      throw new Error("The evidence-cleanup path returned by the local service did not match the confirmed plan.");
    }
    return nativeResult({
      removed: response.removed,
      exactPath: response.exact_path,
      recoverable: false,
    });
  },

  async previewExport(
    input: ExportCaseInput,
    workspace: CaseWorkspace,
  ): Promise<ServiceResult<ExportPreview>> {
    if (isNativeSurface()) {
      const preview = await invoke<NativeExportPreview>(COMMANDS.previewExport, { input });
      return nativeResult(adaptNativeExportPreview(preview));
    }
    const run = workspace.runs[0];
    if (!run) throw new Error(serviceText(
      "This demo case has no scan run to preview.",
      "這個展示案件沒有可預覽的掃描紀錄。",
    ));
    const engineRuns = workspace.runs.flatMap((item) => item.engineRuns);
    const evidence = workspace.findings.flatMap((finding) => finding.evidence);
    const rawArtifactCount = engineRuns.reduce((total, engine) => total + engine.rawArtifactCount, 0);
    const rawArtifactsIncluded = input.format === "case_bundle" && input.includeRawEvidence
      ? rawArtifactCount
      : 0;
    return demoResult({
      caseId: workspace.case.id,
      runId: run.id,
      format: input.format,
      redactionProfile: input.redactSensitiveValues ? "standard" : "none",
      dataSourceCount: workspace.coverage.length,
      coverageEntryCount: workspace.coverage.length,
      assetCount: workspace.assets.length,
      candidateAssetCount: workspace.assets.filter((asset) => asset.authorizationState === "pending").length,
      canonicalFindingCount: workspace.findings.length,
      selectedRunFindingCount: workspace.findings.filter((finding) =>
        finding.evidence.some((item) => item.runId === run.id)).length,
      evidenceIndexCount: evidence.length,
      selectedRunEvidenceCount: evidence.filter((item) => item.runId === run.id).length,
      scanRunCount: workspace.runs.length,
      selectedEngineRunCount: run.engineRuns.length,
      externalScopeGrantCount: workspace.scopeGrants.filter((grant) => grant.externalScope).length,
      incompleteEngineRunCount: engineRuns.filter((engine) =>
        ["partial", "failed", "cancelled"].includes(engine.status)).length,
      notExecutedEngineRunCount: engineRuns.filter((engine) => engine.status === "not_executed").length,
      unknownSourceCount: workspace.coverage.filter((item) => item.state === "source_unavailable_unknown").length,
      connectedNoAssetCount: workspace.coverage.filter((item) => item.state === "source_connected_none").length,
      rawArtifactCount,
      rawArtifactsIncluded,
      rawArtifactsOmitted: rawArtifactCount - rawArtifactsIncluded,
      sensitiveRawArtifactsOmitted: 0,
      coverageManifestIncluded: input.format === "ocsf" || input.format === "oscal",
      sensitiveDataWarning: serviceText(
        "This is an approximate demo preview. A DEMO_ONLY_NOT_A_SCAN file is not a signed case package and contains no verifiable original evidence.",
        "這是展示資料的近似預覽；DEMO_ONLY_NOT_A_SCAN 檔不是正式案件包，也不含可驗證的原始證據。",
      ),
    });
  },

  async exportCase(input: ExportCaseInput, workspace: CaseWorkspace): Promise<ServiceResult<CaseExport | null>> {
    if (isNativeSurface()) {
      const fileType = exportFileTypes[input.format];
      const safeName = workspace.case.name
        .normalize("NFKC")
        .replace(/[^\p{L}\p{N}-]+/gu, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 80) || "assessment-case";
      const destination = await save({
        title: serviceText("Export ai-security-scanner case", "匯出 ai-security-scanner 案件"),
        defaultPath: `${safeName}.${fileType.suffix}`,
        filters: [{ name: fileType.label, extensions: fileType.extensions }],
      });
      if (!destination) return nativeResult(null);
      const exported = await invoke<NativeCaseExport>(
        COMMANDS.exportCase,
        buildNativeExportCaseArguments(input, destination),
      );
      return nativeResult(adaptNativeExport(exported));
    }

    const exported = createDemoExport(input, workspace);
    downloadDemoExport(exported, workspace, input);
    return demoResult(exported);
  },

  async verifyCaseExport(path: string): Promise<ServiceResult<CaseExportVerificationResult>> {
    if (!isNativeSurface()) return demoResult({
      outcome: "demo_unavailable",
      message: serviceText(
        "A demo file has no real local signature and cannot produce an integrity result.",
        "展示檔沒有正式本機簽章，不能視為完整性驗證結果。",
      ),
    });
    try {
      const response = await invoke<{ accepted: boolean; message?: string } | boolean>(COMMANDS.verifyCaseExport, { path });
      const accepted = typeof response === "boolean" ? response : response.accepted === true;
      return nativeResult({
        outcome: accepted ? "verified" : "native_failed",
        message: typeof response === "boolean"
          ? response
            ? serviceText("Integrity verification passed.", "完整性驗證通過。")
            : serviceText("Integrity verification failed.", "完整性驗證失敗。")
          : response.message ?? serviceText("Integrity verification finished.", "完整性驗證完成。"),
      });
    } catch (error) {
      return nativeResult({ outcome: "native_failed", message: errorMessage(error) });
    }
  },

  async chooseCaseBundle(): Promise<string | null> {
    if (!isNativeSurface()) return null;
    const selected = await open({
      title: serviceText(
        "Choose an ai-security-scanner case package to verify",
        "選擇要驗證的 ai-security-scanner 案件包",
      ),
      multiple: false,
      directory: false,
      filters: [{ name: "Signed case bundle", extensions: ["gz"] }],
    });
    return typeof selected === "string" ? selected : null;
  },

  async subscribeScanWorkspace(
    handler: (workspace: CaseWorkspace, eventName: ScannerEventName) => void,
  ): Promise<UnlistenFn> {
    if (!isNativeSurface()) return () => undefined;
    return subscribeBufferedEvents({
      eventNames: [EVENTS.runProgress, EVENTS.runFinished],
      loadContext: async () => (await getNativeManifests()).map(adaptNativeManifest),
      listen: (eventName, onEvent) =>
        listen<ScannerEventEnvelope<NativeAssessmentCase>>(eventName, (event) => onEvent(event.payload)),
      adapt: (
        event: ScannerEventEnvelope<NativeAssessmentCase>,
        manifests: EngineManifest[],
      ) => adaptNativeCase(event.payload, manifests),
      handle: handler,
    });
  },

  async subscribe(
    eventName: ScannerEventName,
    handler: (event: ScannerEventEnvelope) => void,
  ): Promise<UnlistenFn> {
    if (!isNativeSurface()) return () => undefined;
    return listen<ScannerEventEnvelope>(eventName, (event) => handler(event.payload));
  },
};

const createDemoExport = (input: ExportCaseInput, workspace: CaseWorkspace): CaseExport => {
  const timestamp = new Date();
  const safeName = workspace.case.name.replace(/[^\p{L}\p{N}-]+/gu, "-").replace(/^-|-$/g, "");
  return {
    id: `export-demo-${timestamp.getTime()}`,
    caseId: input.caseId,
    format: input.format,
    createdAt: timestamp.toISOString(),
    fileName: `${safeName || "case"}-${input.format}.demo.json`,
    sha256: "demo-export-has-no-cryptographic-signature",
    signatureState: "unsigned",
    includesRawEvidence: input.includeRawEvidence,
    isDemo: true,
  };
};

const downloadDemoExport = (
  exported: CaseExport,
  workspace: CaseWorkspace,
  input: ExportCaseInput,
): void => {
  const demoPayload = {
    provenance: "DEMO_ONLY_NOT_A_SCAN",
    warning: getDemoNotice(),
    requestedFormat: input.format,
    case: workspace.case,
    coverage: workspace.coverage,
    assets: workspace.assets,
    findings: workspace.findings,
    verification: workspace.verification,
    options: {
      includeRawEvidence: input.includeRawEvidence,
      redactSensitiveValues: input.redactSensitiveValues,
    },
  };
  const blob = new Blob([JSON.stringify(demoPayload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = exported.fileName;
  anchor.click();
  URL.revokeObjectURL(url);
};
