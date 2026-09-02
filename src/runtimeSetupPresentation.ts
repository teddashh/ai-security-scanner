import type { ScannerSetupBlocker } from "./scanReadiness";
import type { AppMode, ManagedRuntimeSetupStatus } from "./types";

interface RuntimeSetupPresentationInput {
  mode: AppMode;
  runtimeAvailable: boolean;
  status?: Pick<ManagedRuntimeSetupStatus, "active" | "phase">
    & Partial<Pick<ManagedRuntimeSetupStatus,
      "prerequisiteRepairActive" | "stale" | "canRetry" | "failureReason" | "nextAction"
    >>;
  requestPending?: boolean;
  blocker?: ScannerSetupBlocker;
}

const terminalSetupPhases = new Set(["completed", "failed", "cancelled"]);
const packageAdmissionFailureReasons = new Set([
  "packaged_runtime_missing",
  "packaged_runtime_verification_failed",
]);

export interface ManagedRuntimeSetupRequestBaseline {
  operationId?: string;
}

/** A setup completion is not user-visible readiness until runtime truth agrees. */
export const hasUnconfirmedManagedRuntimeCompletion = (
  runtimeAvailable: boolean | undefined,
  setupPhase: ManagedRuntimeSetupStatus["phase"] | undefined,
): boolean => runtimeAvailable !== true && setupPhase === "completed";

/** Only immutable packaged-runtime admission failures are terminal without Retry. */
export const isManagedRuntimePackageAdmissionFailure = (
  status: Pick<ManagedRuntimeSetupStatus, "active" | "phase">
    & Partial<Pick<ManagedRuntimeSetupStatus,
      "prerequisiteRepairActive" | "canRetry" | "failureReason" | "nextAction"
    >>
    | undefined,
): boolean => Boolean(
  status
  && status.phase === "failed"
  && status.active === false
  && status.prerequisiteRepairActive !== true
  && status.canRetry === false
  && status.failureReason !== undefined
  && packageAdmissionFailureReasons.has(status.failureReason)
  && status.nextAction === undefined,
);

/** Backend terminal truth must release a frontend request that lost its command reply. */
export const isManagedRuntimeSetupTerminal = (
  status: Pick<ManagedRuntimeSetupStatus, "active" | "phase">
    & Partial<Pick<ManagedRuntimeSetupStatus, "prerequisiteRepairActive">>
    | undefined,
): boolean => Boolean(
  status
  && status.active !== true
  && status.prerequisiteRepairActive !== true
  && terminalSetupPhases.has(status.phase),
);

/**
 * A terminal result that predates a Retry click is not the result of that
 * click. A changed backend operation identity (or its first legacy active
 * observation) is the admission acknowledgement.
 */
export const hasManagedRuntimeSetupRequestStarted = (
  baseline: ManagedRuntimeSetupRequestBaseline,
  status: Pick<ManagedRuntimeSetupStatus, "active" | "operationId">,
): boolean => {
  if (status.operationId !== undefined) {
    return status.operationId !== baseline.operationId;
  }
  return baseline.operationId === undefined && status.active === true;
};

/** Keeps one authoritative presentation when runtime status and scan readiness update at different times. */
export const resolveRuntimeSetupPresentation = ({
  mode,
  runtimeAvailable,
  status,
  requestPending = false,
  blocker,
}: RuntimeSetupPresentationInput) => {
  const setupStarting = requestPending
    && status?.active !== true
    && status?.prerequisiteRepairActive !== true;
  const active = status?.active === true
    || status?.prerequisiteRepairActive === true
    || requestPending;
  const failed = !active && status?.phase === "failed";
  const cancelled = !active && status?.phase === "cancelled";
  const recovering = active && status?.phase === "recovery";
  const stale = active && status?.stale === true;
  const nonRetryable = mode === "native"
    && !runtimeAvailable
    && isManagedRuntimePackageAdmissionFailure(status);
  const idleUnavailable = mode === "native"
    && !runtimeAvailable
    && !active
    && !failed
    && !cancelled;
  const packagedComponentBlocker = blocker === "no_runnable_authorized_targets"
    || blocker === "egress_gateway_unavailable"
    || blocker === "engine_execution_contract_invalid";
  const showPackagedComponentIssue = packagedComponentBlocker
    && (runtimeAvailable || (!active && !failed));

  return {
    ready: mode === "native" && runtimeAvailable && !blocker,
    showPackagedComponentIssue,
    setupStarting: setupStarting && !nonRetryable && !showPackagedComponentIssue,
    setupActive: active && !nonRetryable && !showPackagedComponentIssue,
    setupRecovering: recovering && !showPackagedComponentIssue,
    setupStale: stale && !showPackagedComponentIssue,
    setupFailed: failed && !showPackagedComponentIssue,
    setupCancelled: cancelled && !showPackagedComponentIssue,
    setupIdleUnavailable: idleUnavailable && !showPackagedComponentIssue,
    setupNonRetryable: nonRetryable && !showPackagedComponentIssue,
  };
};
