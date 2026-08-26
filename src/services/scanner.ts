import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";

import {
  createStoredDemoCase,
  getDemoNotice,
  getDemoSnapshot,
  getDemoWorkspace,
} from "../data/demo";
import { getActiveLocale } from "../i18n/core";
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
  ManagedRuntimePrerequisiteRepairResult,
  ManagedRuntimeSetupStatus,
  LocalNetworkCandidateInventory,
  ScanReadiness,
} from "../types";
import {
  adaptLocalNetworkCandidateInventory,
  adaptManagedRuntimePrerequisiteRepairResult,
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
  type NativeManagedRuntimePrerequisiteRepairResult,
  type NativeManagedRuntimeSetupStatus,
} from "./nativeAdapter";

export const COMMANDS = {
  getSnapshot: "get_app_snapshot",
  setupManagedRuntime: "setup_managed_runtime",
  getManagedRuntimeSetupStatus: "get_managed_runtime_setup_status",
  cancelManagedRuntimeSetup: "cancel_managed_runtime_setup",
  repairManagedRuntimePrerequisite: "repair_managed_runtime_prerequisite",
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

const hasTauriRuntime = (): boolean =>
  typeof window !== "undefined" &&
  "__TAURI_INTERNALS__" in (window as Window & { __TAURI_INTERNALS__?: unknown });

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
): Promise<ServiceResult<ActionResponse>> => {
  if (!hasTauriRuntime()) {
    return demoResult({ accepted: false, message: demoMessage });
  }
  try {
    const returnedCase = await invoke<NativeAssessmentCase>(command, args);
    // Adapt the DTO here as a contract check; App refreshes the authoritative snapshot next.
    adaptNativeCase(returnedCase);
    return nativeResult({ accepted: true, message: nativeMessage });
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
  ocsf: { suffix: "ocsf.json", extensions: ["json"], label: "OCSF JSON" },
  oscal: { suffix: "oscal.json", extensions: ["json"], label: "OSCAL JSON" },
  html: { suffix: "html", extensions: ["html"], label: "HTML report" },
};

export interface ActionResponse {
  accepted: boolean;
  message: string;
  snapshot?: AppSnapshot;
}

export interface ScopeApprovalInput {
  caseId: string;
  assetIds: string[];
  modes: ScopeMode[];
  confirmation: string;
  externalScope?: ExternalScopeRequest;
}

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
  isNative: hasTauriRuntime,

  async getSnapshot(caseId?: string): Promise<ServiceResult<AppSnapshot>> {
    if (!hasTauriRuntime()) return demoResult(getDemoSnapshot(caseId));
    try {
      const nativeSnapshot = await invoke<NativeAppSnapshot>(COMMANDS.getSnapshot);
      const manifests = await getNativeManifests();
      return nativeResult(adaptNativeSnapshot(nativeSnapshot, manifests));
    } catch (error) {
      return demoResult(getDemoSnapshot(caseId), errorMessage(error));
    }
  },

  async setupManagedRuntime(): Promise<ServiceResult<ActionResponse>> {
    if (!hasTauriRuntime()) return demoResult({
      accepted: false,
      message: serviceText(
        "Demo mode does not install or start a scan environment.",
        "展示模式不會安裝或啟動掃描環境。",
      ),
    });
    try {
      const response = await invoke<{ accepted: boolean; message: string }>(COMMANDS.setupManagedRuntime);
      return nativeResult(response);
    } catch (error) {
      return nativeResult({ accepted: false, message: errorMessage(error) });
    }
  },

  async getManagedRuntimeSetupStatus(): Promise<ServiceResult<ManagedRuntimeSetupStatus>> {
    if (!hasTauriRuntime()) return demoResult(demoRuntimeSetupStatus());
    const status = await invoke<NativeManagedRuntimeSetupStatus>(COMMANDS.getManagedRuntimeSetupStatus);
    return nativeResult(adaptManagedRuntimeSetupStatus(status));
  },

  async cancelManagedRuntimeSetup(): Promise<ServiceResult<ManagedRuntimeSetupStatus>> {
    if (!hasTauriRuntime()) return demoResult(demoRuntimeSetupStatus());
    const status = await invoke<NativeManagedRuntimeSetupStatus>(COMMANDS.cancelManagedRuntimeSetup);
    return nativeResult(adaptManagedRuntimeSetupStatus(status));
  },

  async repairManagedRuntimePrerequisite(): Promise<ServiceResult<ManagedRuntimePrerequisiteRepairResult>> {
    if (!hasTauriRuntime()) return demoResult({
      outcome: "failed",
      restartRequired: false,
      detail: serviceText(
        "Windows setup is available only in the installed desktop app.",
        "Windows 設定只能在已安裝的桌面應用程式中使用。",
      ),
    });
    const result = await invoke<NativeManagedRuntimePrerequisiteRepairResult>(
      COMMANDS.repairManagedRuntimePrerequisite,
    );
    return nativeResult(adaptManagedRuntimePrerequisiteRepairResult(result));
  },

  async createCase(input: CreateCaseInput): Promise<ServiceResult<AssessmentCase>> {
    if (!hasTauriRuntime()) return demoResult(createStoredDemoCase(input));
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.createCase, {
      request: {
        title: input.name,
        assessment_intent: input.assessmentIntent ?? null,
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
    if (!hasTauriRuntime()) return demoResult(getDemoWorkspace(caseId));
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.selectCase, { caseId });
    const manifests = (await getNativeManifests()).map(adaptNativeManifest);
    return nativeResult(adaptNativeCase(nativeCase, manifests));
  },

  async listEngineManifests(): Promise<ServiceResult<EngineManifest[]>> {
    const demo = getDemoSnapshot().engineManifests;
    if (!hasTauriRuntime()) return demoResult(demo);
    try {
      return nativeResult((await getNativeManifests()).map(adaptNativeManifest));
    } catch (error) {
      return demoResult(demo, errorMessage(error));
    }
  },

  async detectLocalPrivateSubnets(): Promise<ServiceResult<LocalNetworkCandidateInventory>> {
    const fallback: LocalNetworkCandidateInventory = {
      status: hasTauriRuntime() ? "unavailable" : "unsupported",
      candidates: [],
    };
    if (!hasTauriRuntime()) return demoResult(fallback);
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
    if (!hasTauriRuntime()) return demoResult({
      caseId,
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
    if (!hasTauriRuntime()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<ProviderAuthorizationPrompt>(COMMANDS.beginProviderAuthorization, { request }));
  },

  async pollProviderAuthorization(
    sessionId: string,
  ): Promise<ServiceResult<ProviderAuthorizationProgress>> {
    if (!hasTauriRuntime()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<ProviderAuthorizationProgress>(COMMANDS.pollProviderAuthorization, { sessionId }));
  },

  async cancelProviderAuthorization(sessionId: string): Promise<ServiceResult<boolean>> {
    if (!hasTauriRuntime()) return demoResult(false);
    return nativeResult(await invoke<boolean>(COMMANDS.cancelProviderAuthorization, { sessionId }));
  },

  async providerAuthorizationStatus(
    caseId: string,
    sourceId: string,
  ): Promise<ServiceResult<InstalledProviderAuthorization | null>> {
    if (!hasTauriRuntime()) return demoResult(null);
    return nativeResult(await invoke<InstalledProviderAuthorization | null>(COMMANDS.providerAuthorizationStatus, {
      caseId,
      sourceId,
    }));
  },

  async revokeProviderAuthorization(
    caseId: string,
    sourceId: string,
  ): Promise<ServiceResult<Record<string, unknown>>> {
    if (!hasTauriRuntime()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<Record<string, unknown>>(COMMANDS.revokeProviderAuthorization, {
      caseId,
      sourceId,
    }));
  },

  async planProviderBootstrap(request: BootstrapRequest): Promise<ServiceResult<ProviderBootstrapPlan>> {
    if (!hasTauriRuntime()) throw new Error("Provider bootstrap requires the native app.");
    return nativeResult(await invoke<ProviderBootstrapPlan>(COMMANDS.planProviderBootstrap, { request }));
  },

  async executeProviderBootstrap(
    input: ExecuteProviderBootstrapInput,
  ): Promise<ServiceResult<ProviderBootstrapInstalled>> {
    if (!hasTauriRuntime()) throw new Error("Provider bootstrap requires the native app.");
    return nativeResult(await invoke<ProviderBootstrapInstalled>(COMMANDS.executeProviderBootstrap, { input }));
  },

  async cleanupProviderBootstrap(
    caseId: string,
    operationId: string,
    operator: BootstrapOperatorConfig,
  ): Promise<ServiceResult<Record<string, unknown>>> {
    if (!hasTauriRuntime()) throw new Error("Provider cleanup requires the native app.");
    return nativeResult(await invoke<Record<string, unknown>>(COMMANDS.cleanupProviderBootstrap, {
      caseId,
      operationId,
      operator,
    }));
  },

  async listProviderBootstrapCleanup(
    caseId: string,
  ): Promise<ServiceResult<BootstrapCleanupObligationSummary[]>> {
    if (!hasTauriRuntime()) return demoResult([]);
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
    if (!hasTauriRuntime()) return demoResult(false, serviceText(
      "Demo mode has no real inventory work to cancel.",
      "展示模式沒有執行中的真實盤點工作。",
    ));
    return nativeResult(await invoke<boolean>(COMMANDS.cancelDiscovery, { caseId }));
  },

  async chooseSourceSnapshot(): Promise<string | null> {
    if (!hasTauriRuntime()) return null;
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
    if (!hasTauriRuntime()) return null;
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
    const permissions = input.modes.map((mode) => permissionMap[mode]).filter((mode): mode is string => Boolean(mode));
    const needsReference = permissions.some((permission) => permission === "low_impact_external_connection" || permission === "active_external_testing");
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
    return actionResult(
      COMMANDS.approveScope,
      {
        caseId: input.caseId,
        decisions: input.assetIds.map((assetId) => ({
          asset_id: assetId,
          permissions,
          confirmed_by: serviceText("Local user", "本機使用者"),
          authorization_reference: needsReference || input.externalScope ? input.confirmation : null,
          notes: input.confirmation,
          external_scope: externalScope,
        })),
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

  async startScan(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.startScan,
      { caseId },
      serviceText(
        "The app selected every applicable scanner from the assets and current permissions. Anything that cannot run is marked Not run.",
        "產品已依資產與目前權限選擇所有適用掃描工具；無法執行的項目會明確標成「未執行」。",
      ),
      serviceText(
        "Demo mode does not start a container or contact a target.",
        "展示模式不會啟動容器，也不會接觸任何目標。",
      ),
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
    );
  },

  async resumeScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.resumeScan,
      { caseId, runId },
      serviceText("The selected scan was queued to continue.", "選定的掃描已排入佇列，準備繼續。"),
      serviceText("Demo mode has no real scan to resume.", "展示模式沒有可繼續的真實掃描。"),
    );
  },

  async cancelScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.cancelScan,
      { caseId, runId },
      serviceText("The selected scan was cancelled and the case now needs attention.", "選定的掃描已取消，案件現在需要處理。"),
      serviceText("Demo mode has no real scan to cancel.", "展示模式沒有可取消的真實掃描。"),
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
    if (!hasTauriRuntime()) {
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
    if (!hasTauriRuntime()) {
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
    if (hasTauriRuntime()) {
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
      sensitiveDataWarning: serviceText(
        "This is an approximate demo preview. A DEMO_ONLY_NOT_A_SCAN file is not a signed case package and contains no verifiable original evidence.",
        "這是展示資料的近似預覽；DEMO_ONLY_NOT_A_SCAN 檔不是正式案件包，也不含可驗證的原始證據。",
      ),
    });
  },

  async exportCase(input: ExportCaseInput, workspace: CaseWorkspace): Promise<ServiceResult<CaseExport | null>> {
    if (hasTauriRuntime()) {
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
      const exported = await invoke<NativeCaseExport>(COMMANDS.exportCase, {
        input: { ...input, destination },
      });
      return nativeResult(adaptNativeExport(exported));
    }

    const exported = createDemoExport(input, workspace);
    downloadDemoExport(exported, workspace, input);
    return demoResult(exported);
  },

  async verifyCaseExport(path: string): Promise<ServiceResult<ActionResponse>> {
    if (!hasTauriRuntime()) return demoResult({
      accepted: false,
      message: serviceText(
        "A demo file has no real local signature and cannot produce an integrity result.",
        "展示檔沒有正式本機簽章，不能視為完整性驗證結果。",
      ),
    });
    try {
      const response = await invoke<{ accepted?: boolean; message?: string } | boolean>(COMMANDS.verifyCaseExport, { path });
      const accepted = typeof response === "boolean" ? response : response.accepted ?? true;
      return nativeResult({
        accepted,
        message: typeof response === "boolean"
          ? response
            ? serviceText("Integrity verification passed.", "完整性驗證通過。")
            : serviceText("Integrity verification failed.", "完整性驗證失敗。")
          : response.message ?? serviceText("Integrity verification finished.", "完整性驗證完成。"),
      });
    } catch (error) {
      return nativeResult({ accepted: false, message: errorMessage(error) });
    }
  },

  async chooseCaseBundle(): Promise<string | null> {
    if (!hasTauriRuntime()) return null;
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

  async subscribe(
    eventName: ScannerEventName,
    handler: (event: ScannerEventEnvelope) => void,
  ): Promise<UnlistenFn> {
    if (!hasTauriRuntime()) return () => undefined;
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
