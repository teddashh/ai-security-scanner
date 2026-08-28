import type { AppMode, AppSnapshot, ManagedRuntimeSetupStatus } from "./types";

type RuntimeHealth = AppSnapshot["runtime"];

const automaticallyRecoverablePhases = new Set([
  "not_installed",
  "installed",
  "stopped",
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
 * the authoritative read-only host check first. It never elevates or changes
 * Windows optional features; when WSL is unavailable it stops with one typed
 * instruction that the UI can explain clearly. A `starting` runtime already
 * has a live managed machine whose API probe is temporarily unavailable, so it
 * must be allowed to settle instead of launching a second lifecycle operation.
 */
export const shouldAutomaticallyPrepareRuntime = (
  mode: AppMode,
  runtime: RuntimeHealth,
  status: ManagedRuntimeSetupStatus | undefined,
  statusLoaded: boolean,
  alreadyAttempted: boolean,
): boolean => statusLoaded
  && !alreadyAttempted
  && isUnavailableManagedRuntime(mode, runtime)
  && (status === undefined || status.phase === "idle" || status.phase === "completed")
  && automaticallyRecoverablePhases.has(runtime?.phase ?? "");
