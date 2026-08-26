import type { ScannerSetupBlocker } from "./scanReadiness";
import type { AppMode, ManagedRuntimeSetupStatus } from "./types";

interface RuntimeSetupPresentationInput {
  mode: AppMode;
  runtimeAvailable: boolean;
  status?: Pick<ManagedRuntimeSetupStatus, "active" | "phase">;
  blocker?: ScannerSetupBlocker;
}

/** Keeps one authoritative presentation when runtime status and scan readiness update at different times. */
export const resolveRuntimeSetupPresentation = ({
  mode,
  runtimeAvailable,
  status,
  blocker,
}: RuntimeSetupPresentationInput) => {
  const active = status?.active === true;
  const failed = status?.phase === "failed";
  const packagedComponentBlocker = blocker === "no_runnable_authorized_targets"
    || blocker === "egress_gateway_unavailable"
    || blocker === "engine_execution_contract_invalid";
  const showPackagedComponentIssue = packagedComponentBlocker
    && (runtimeAvailable || (!active && !failed));

  return {
    ready: mode === "native" && runtimeAvailable && !blocker,
    showPackagedComponentIssue,
    setupActive: active && !showPackagedComponentIssue,
    setupFailed: failed && !showPackagedComponentIssue,
  };
};
