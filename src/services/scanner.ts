import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";

import {
  createStoredDemoCase,
  DEMO_NOTICE,
  getDemoSnapshot,
  getDemoWorkspace,
} from "../data/demo";
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
} from "../types";
import {
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
    return "未知錯誤";
  }
};

const nativeResult = <T,>(data: T): ServiceResult<T> => ({ data, mode: "native" });

const demoResult = <T,>(data: T, reason?: string): ServiceResult<T> => ({
  data,
  mode: "demo",
  notice: reason ? `${DEMO_NOTICE}（本機核心回應：${reason}）` : DEMO_NOTICE,
});

interface NativeManagedRuntimeSetupStatus {
  phase: ManagedRuntimeSetupStatus["phase"];
  active: boolean;
  cancel_requested: boolean;
  received_bytes: number;
  total_bytes: number | null;
  progress_percent: number | null;
  resumed_from_bytes: number;
  can_cancel: boolean;
  can_retry: boolean;
  detail: string;
}

const adaptManagedRuntimeSetupStatus = (
  status: NativeManagedRuntimeSetupStatus,
): ManagedRuntimeSetupStatus => ({
  phase: status.phase,
  active: status.active,
  cancelRequested: status.cancel_requested,
  receivedBytes: status.received_bytes,
  totalBytes: status.total_bytes ?? undefined,
  progressPercent: status.progress_percent ?? undefined,
  resumedFromBytes: status.resumed_from_bytes,
  canCancel: status.can_cancel,
  canRetry: status.can_retry,
  detail: status.detail,
});

const demoRuntimeSetupStatus = (): ManagedRuntimeSetupStatus => ({
  phase: "idle",
  active: false,
  cancelRequested: false,
  receivedBytes: 0,
  resumedFromBytes: 0,
  canCancel: false,
  canRetry: true,
  detail: "展示模式不會下載或啟動容器執行環境。",
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
      message: "展示模式不會安裝或啟動容器執行環境。",
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

  async createCase(input: CreateCaseInput): Promise<ServiceResult<AssessmentCase>> {
    if (!hasTauriRuntime()) return demoResult(createStoredDemoCase(input));
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.createCase, {
      request: {
        title: input.name,
        organization_name: input.organizationName,
        employee_range: employeeRanges[input.companySize],
        data_classes: input.dataClasses.map((dataClass) => nativeDataClasses[dataClass]),
        requested_activities: input.requestedActivities,
        source_kinds: plannedSourceKinds(input.platforms),
        not_applicable_source_kinds: plannedNotApplicableSourceKinds(input.platforms),
        declared_assets: input.knownAssets,
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
      "案件已進入盤點階段。",
      "展示模式不會連接或盤點任何真實資料來源。",
    );
  },

  async cancelDiscovery(caseId: string): Promise<ServiceResult<boolean>> {
    if (!hasTauriRuntime()) return demoResult(false, "展示模式沒有執行中的真實盤點工作。");
    return nativeResult(await invoke<boolean>(COMMANDS.cancelDiscovery, { caseId }));
  },

  async chooseSourceSnapshot(): Promise<string | null> {
    if (!hasTauriRuntime()) return null;
    const selected = await open({
      title: "選擇一份來源 JSON 快照",
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
      "來源快照已複製進本機案件；尚未自動授權或啟動掃描。",
      "展示模式不會讀取、複製或解析你選擇的檔案。",
    );
  },

  async chooseWorkspaceDirectory(): Promise<string | null> {
    if (!hasTauriRuntime()) return null;
    const selected = await open({
      title: "選擇要建立不可變快照的本機掃描輸入目錄",
      multiple: false,
      directory: true,
    });
    return typeof selected === "string" ? selected : null;
  },

  async attachWorkspaceSnapshot(input: AttachWorkspaceSnapshotInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.attachWorkspaceSnapshot,
      { ...input },
      "有界、明確類型的本機輸入已附加到案件；尚未授予所有權或掃描範圍。",
      "展示模式不會讀取或複製你選擇的工作目錄。",
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
          confirmed_by: "本機使用者",
          authorization_reference: needsReference || input.externalScope ? input.confirmation : null,
          notes: input.confirmation,
          external_scope: externalScope,
        })),
      },
      "選取的資產範圍已記錄；尚未自動啟動掃描。",
      "展示模式只呈現範圍流程，不會建立真實掃描授權。",
    );
  },

  async startScan(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.startScan, { caseId }, "本機已依資產與有效授權自動選擇所有適用引擎；不具執行條件者會明確標為未執行。", "展示模式不會啟動容器或對任何目標發出請求。");
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
      "Finding 處理決定已寫入不可變歷程；原始證據沒有變更。",
      "展示模式不會建立真實的 finding 處理決定。",
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
      "相關 findings 已建立可逆群組；每筆 fingerprint、證據與原始 artifact 仍獨立保留。",
      "展示模式只呈現群組，不會改寫展示 findings。",
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
      "群組已移除；所有 findings 與不可變群組歷程仍保留。",
      "展示模式不會變更展示群組。",
    );
  },

  async pauseScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.pauseScan, { caseId, runId }, "指定掃描輪次已暫停。", "展示模式沒有可暫停的真實掃描工作。");
  },

  async resumeScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.resumeScan, { caseId, runId }, "指定掃描輪次已重新排入佇列。", "展示模式沒有可續跑的真實掃描工作。");
  },

  async cancelScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.cancelScan, { caseId, runId }, "指定掃描輪次已取消，案件標記為需要處理。", "展示模式沒有可取消的真實掃描工作。");
  },

  async startRescan(caseId: string, baselineRunId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.startRescan, { caseId, baselineRunId }, "複驗工作已建立。", "展示模式不會執行複驗；目前差異均為明確標記的樣本資料。");
  },

  async archiveCase(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.archiveCase,
      { caseId },
      "案件已封存；資料仍保留在本機，且不會再排入新工作。",
      "展示模式不會變更本機案件狀態。",
    );
  },

  async deleteCase(caseId: string, confirmation: string): Promise<ServiceResult<CaseDeletionResponse>> {
    if (!hasTauriRuntime()) {
      return demoResult({
        accepted: false,
        message: "展示模式不會刪除任何本機案件或檔案。",
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
        ? `案件資料庫紀錄已刪除；證據檔仍保留於 ${artifacts.exactPath}，必須另行明確確認後才能清理。`
        : "案件資料庫紀錄已刪除；目前沒有需要清理的案件證據目錄。";
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
      throw new Error("本機核心回傳不符合不可復原刪除契約的結果。");
    }
    if (response.exact_path !== input.exactPath) {
      throw new Error("本機核心回傳的證據清理路徑與已確認計畫不一致。");
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
    if (!run) throw new Error("展示案件沒有可預覽的掃描執行。");
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
      sensitiveDataWarning: "這是展示資料的近似預覽；DEMO_ONLY_NOT_A_SCAN 檔不含正式案件包或可驗證原始證據。",
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
        title: "匯出 ai-security-scanner 案件",
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
      message: "展示檔沒有正式本機簽章，不能視為完整性驗證結果。",
    });
    try {
      const response = await invoke<{ accepted?: boolean; message?: string } | boolean>(COMMANDS.verifyCaseExport, { path });
      const accepted = typeof response === "boolean" ? response : response.accepted ?? true;
      return nativeResult({ accepted, message: typeof response === "boolean" ? (response ? "完整性驗證通過。" : "完整性驗證失敗。") : response.message ?? "完整性驗證完成。" });
    } catch (error) {
      return nativeResult({ accepted: false, message: errorMessage(error) });
    }
  },

  async chooseCaseBundle(): Promise<string | null> {
    if (!hasTauriRuntime()) return null;
    const selected = await open({
      title: "選擇要驗證的 ai-security-scanner 案件包",
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
    warning: DEMO_NOTICE,
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
