import type { AppMode, AppSnapshot, ManagedRuntimeSetupStatus } from "./types";

type RuntimeHealth = AppSnapshot["runtime"];

const automaticallyRecoverablePhases = new Set([
  "not_installed",
  "installed",
  "stopped",
  "starting",
]);

const firstInstallationPhases = new Set(["not_installed", "installed"]);

const isUnavailableManagedRuntime = (
  mode: AppMode,
  runtime: RuntimeHealth,
): boolean => mode === "native"
  && runtime?.provider === "managed_local"
  && runtime.available !== true;

/**
 * The release-managed runtime is part of the installed product, so its first
 * preparation happens before the user enters the scan workspace. Compatibility
 * providers and browser demo mode keep their existing explicit behavior.
 */
export const shouldShowRuntimeFirstLaunch = (
  mode: AppMode,
  runtime: RuntimeHealth,
  hasExistingCases = false,
): boolean => !hasExistingCases
  && isUnavailableManagedRuntime(mode, runtime)
  && firstInstallationPhases.has(runtime?.phase ?? "");

/**
 * Starts only a safe, product-owned lifecycle operation. The backend performs
 * the authoritative read-only host check first and will stop for one explicit
 * UAC action if Windows needs WSL installed or updated.
 */
export const shouldAutomaticallyPrepareRuntime = (
  mode: AppMode,
  runtime: RuntimeHealth,
  status: ManagedRuntimeSetupStatus | undefined,
  alreadyAttempted: boolean,
): boolean => !alreadyAttempted
  && isUnavailableManagedRuntime(mode, runtime)
  && (status === undefined || status.phase === "idle")
  && automaticallyRecoverablePhases.has(runtime?.phase ?? "");
