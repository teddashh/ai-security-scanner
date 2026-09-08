import type { StartScanInput } from "./services/scanner";
import type { AppMode, AppSnapshot, ManagedRuntimeSetupStatus, PageId } from "./types";
import { isManagedRuntimePackageAdmissionFailure } from "./runtimeSetupPresentation.ts";

type RuntimeHealth = AppSnapshot["runtime"];

interface RuntimeSetupAssistantVisibility {
  mode: AppMode;
  runtimeAvailable: boolean | undefined;
  status: ManagedRuntimeSetupStatus | undefined;
  requestPending: boolean;
  selectedScanNeedsSetup: boolean;
}

interface SelectedScanRuntimeSetupRequest {
  mode: AppMode;
  runtime: RuntimeHealth;
  status: ManagedRuntimeSetupStatus | undefined;
  scanActionRequested: boolean;
  blocker: "runtime_unavailable" | undefined;
}

interface RuntimeBlockedScanResumeContext {
  requestedPage: PageId;
  currentPage: PageId;
  requestedPageTransitionGeneration: number;
  currentPageTransitionGeneration: number;
  requestedCaseSelectionGeneration: number;
  currentCaseSelectionGeneration: number;
  requestedCaseId: string;
  selectedCaseId: string | undefined;
  workspaceCaseId: string | undefined;
  runtimeAvailable: boolean | undefined;
  setupPhase: ManagedRuntimeSetupStatus["phase"];
  activeScanWork: boolean;
}

/** Keep the exact reviewed request independent from later form edits. */
export const cloneRuntimeBlockedScanInput = (input: StartScanInput): StartScanInput => ({
  caseId: input.caseId,
  ...(input.engineIds ? { engineIds: [...input.engineIds] } : {}),
  ...(input.authorization ? {
    authorization: {
      assetIds: [...input.authorization.assetIds],
      modes: [...input.authorization.modes],
      confirmation: input.authorization.confirmation,
      ...(input.authorization.externalScope ? {
        externalScope: {
          ...input.authorization.externalScope,
          ports: [...input.authorization.externalScope.ports],
          ratePolicy: { ...input.authorization.externalScope.ratePolicy },
          templatePolicy: {
            ...input.authorization.externalScope.templatePolicy,
            allowedTemplateIds: [
              ...input.authorization.externalScope.templatePolicy.allowedTemplateIds,
            ],
          },
        },
      } : {}),
    },
  } : {}),
});

/** A prepared runtime may resume only the same still-visible, still-idle scan. */
export const shouldResumeRuntimeBlockedScan = ({
  requestedPage,
  currentPage,
  requestedPageTransitionGeneration,
  currentPageTransitionGeneration,
  requestedCaseSelectionGeneration,
  currentCaseSelectionGeneration,
  requestedCaseId,
  selectedCaseId,
  workspaceCaseId,
  runtimeAvailable,
  setupPhase,
  activeScanWork,
}: RuntimeBlockedScanResumeContext): boolean => setupPhase === "completed"
  && runtimeAvailable === true
  && requestedPage === currentPage
  && requestedPageTransitionGeneration === currentPageTransitionGeneration
  && requestedCaseSelectionGeneration === currentCaseSelectionGeneration
  && requestedCaseId === selectedCaseId
  && requestedCaseId === workspaceCaseId
  && !activeScanWork;

/**
 * Opening the app and observing an unavailable runtime never authorizes a
 * download or lifecycle change. Runtime setup begins only from an explicit
 * user action in App: starting a selected scan whose preflight requires these
 * tools, or selecting one of the setup actions.
 *
 * Keep this policy boundary as a function so a future runtime phase cannot
 * accidentally turn passive first-launch reconciliation back into setup.
 */
export const shouldAutomaticallyPrepareRuntime = (
  _mode: AppMode,
  _runtime: RuntimeHealth,
  _status: ManagedRuntimeSetupStatus | undefined,
  _statusLoaded: boolean,
  _alreadyAttempted: boolean,
): boolean => false;

/**
 * A Start action may prepare its prerequisite only after backend preflight has
 * confirmed that this exact selected scan is blocked by the managed runtime.
 * Merely selecting a case or observing runtime health is intentionally
 * insufficient.
 */
export const shouldPrepareRuntimeAfterScanAction = ({
  mode,
  runtime,
  status,
  scanActionRequested,
  blocker,
}: SelectedScanRuntimeSetupRequest): boolean => scanActionRequested
  && blocker === "runtime_unavailable"
  && mode === "native"
  && runtime?.provider === "managed_local"
  && runtime.available !== true
  && runtime.phase !== "starting"
  && status?.active !== true
  && status?.prerequisiteRepairActive !== true
  && !isManagedRuntimePackageAdmissionFailure(status);

/**
 * The Start-page assistant is contextual: an idle, unavailable runtime is not
 * first-run work. Show it after a selected scan reports a setup blocker, while
 * a user-requested setup is running, or when an earlier request needs attention.
 */
export const shouldShowRuntimeSetupAssistant = ({
  mode,
  runtimeAvailable,
  status,
  requestPending,
  selectedScanNeedsSetup,
}: RuntimeSetupAssistantVisibility): boolean => mode !== "native"
  || selectedScanNeedsSetup
  || requestPending
  || status?.active === true
  || status?.prerequisiteRepairActive === true
  || (
    runtimeAvailable !== true
    && status !== undefined
    && status.phase !== "idle"
  );
