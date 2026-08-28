import type { ScannerSetupBlocker } from "./scanReadiness";
import type { AppMode, ManagedRuntimeSetupStatus } from "./types";

interface RuntimeSetupPresentationInput {
  mode: AppMode;
  runtimeAvailable: boolean;
  status?: Pick<ManagedRuntimeSetupStatus, "active" | "phase">
    & Partial<Pick<ManagedRuntimeSetupStatus, "prerequisiteRepairActive">>;
  requestPending?: boolean;
  blocker?: ScannerSetupBlocker;
}

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
  const packagedComponentBlocker = blocker === "no_runnable_authorized_targets"
    || blocker === "egress_gateway_unavailable"
    || blocker === "engine_execution_contract_invalid";
  const showPackagedComponentIssue = packagedComponentBlocker
    && (runtimeAvailable || (!active && !failed));

  return {
    ready: mode === "native" && runtimeAvailable && !blocker,
    showPackagedComponentIssue,
    setupStarting: setupStarting && !showPackagedComponentIssue,
    setupActive: active && !showPackagedComponentIssue,
    setupFailed: failed && !showPackagedComponentIssue,
    setupCancelled: cancelled && !showPackagedComponentIssue,
  };
};
