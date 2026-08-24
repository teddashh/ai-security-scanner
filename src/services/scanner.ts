import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";

import {
  createStoredDemoCase,
  DEMO_NOTICE,
  getDemoSnapshot,
  getDemoWorkspace,
} from "../data/demo";
import type {
  AppSnapshot,
  AssessmentCase,
  CaseExport,
  CaseWorkspace,
  CreateCaseInput,
  EngineManifest,
  ExportCaseInput,
  ServiceResult,
} from "../types";
import {
  adaptNativeCase,
  adaptNativeExport,
  adaptNativeManifest,
  adaptNativeSnapshot,
  type NativeAppSnapshot,
  type NativeAssessmentCase,
  type NativeCaseExport,
  type NativeEngineManifest,
} from "./nativeAdapter";

export const COMMANDS = {
  getSnapshot: "get_app_snapshot",
  createCase: "create_case",
  selectCase: "select_case",
  seedDemoCase: "seed_demo_case",
  listEngineManifests: "list_engine_manifests",
  startDiscovery: "start_discovery",
  approveScope: "approve_scope",
  startScan: "start_scan",
  pauseScan: "pause_scan",
  resumeScan: "resume_scan",
  cancelScan: "cancel_scan",
  exportCase: "export_case",
  verifyCaseExport: "verify_case_export",
  startRescan: "start_rescan",
} as const;

export const EVENTS = {
  coverageChanged: "case://coverage-changed",
  runProgress: "scan://run-progress",
  engineState: "scan://engine-state",
  findingBatch: "scan://finding-batch",
  runFinished: "scan://run-finished",
  exportProgress: "export://progress",
} as const;

export type ScannerEventName = (typeof EVENTS)[keyof typeof EVENTS];

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

const exportFileTypes: Record<ExportCaseInput["format"], { suffix: string; extensions: string[]; label: string }> = {
  case_bundle: { suffix: "aisscase", extensions: ["aisscase"], label: "ai-security-scanner case bundle" },
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
  modes: string[];
  confirmation: string;
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

  async createCase(input: CreateCaseInput): Promise<ServiceResult<AssessmentCase>> {
    if (!hasTauriRuntime()) return demoResult(createStoredDemoCase(input));
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.createCase, {
      request: {
        title: input.name,
        organization_name: input.organizationName,
        employee_range: employeeRanges[input.companySize],
        data_classes: input.dataClasses.map((dataClass) => nativeDataClasses[dataClass]),
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

  async startDiscovery(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.startDiscovery,
      { caseId },
      "案件已進入盤點階段。",
      "展示模式不會連接或盤點任何真實資料來源。",
    );
  },

  async approveScope(input: ScopeApprovalInput): Promise<ServiceResult<ActionResponse>> {
    const permissionMap: Record<string, string> = {
      inventory: "inventory_read",
      configuration: "configuration_read",
      public_data: "passive_external_discovery",
      passive: "passive_external_discovery",
      low_impact_external: "low_impact_external_connection",
      active_external: "active_external_testing",
      active: "active_external_testing",
    };
    const permissions = input.modes.map((mode) => permissionMap[mode]).filter((mode): mode is string => Boolean(mode));
    const needsReference = permissions.some((permission) => permission === "low_impact_external_connection" || permission === "active_external_testing");
    return actionResult(
      COMMANDS.approveScope,
      {
        caseId: input.caseId,
        decisions: input.assetIds.map((assetId) => ({
          asset_id: assetId,
          permissions,
          confirmed_by: "本機使用者",
          authorization_reference: needsReference ? input.confirmation : null,
          notes: input.confirmation,
        })),
      },
      "選取的資產範圍已記錄；尚未自動啟動掃描。",
      "展示模式只呈現範圍流程，不會建立真實掃描授權。",
    );
  },

  async startScan(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.startScan, { caseId }, "掃描工作已排入本機執行佇列。", "展示模式不會啟動容器或對任何目標發出請求。");
  },

  async pauseScan(caseId: string, _runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.pauseScan, { caseId }, "最新一輪掃描已暫停。", "展示模式沒有可暫停的真實掃描工作。");
  },

  async resumeScan(caseId: string, _runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.resumeScan, { caseId }, "最新一輪掃描已重新排入佇列。", "展示模式沒有可續跑的真實掃描工作。");
  },

  async cancelScan(caseId: string, _runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.cancelScan, { caseId }, "最新一輪掃描已取消，案件標記為需要處理。", "展示模式沒有可取消的真實掃描工作。");
  },

  async startRescan(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.startRescan, { caseId }, "複驗工作已建立。", "展示模式不會執行複驗；目前差異均為明確標記的樣本資料。");
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
      return nativeResult(adaptNativeExport(exported, input.includeRawEvidence));
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

  async subscribe(
    eventName: ScannerEventName,
    handler: (payload: unknown) => void,
  ): Promise<UnlistenFn> {
    if (!hasTauriRuntime()) return () => undefined;
    return listen(eventName, (event) => handler(event.payload));
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
