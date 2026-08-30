import type { AppMode, AppSnapshot, ManagedRuntimeSetupStatus } from "./types";

type RuntimeHealth = AppSnapshot["runtime"];

const automaticallyRecoverablePhases = new Set([
  "not_installed",
  "installed",
  "stopped",
]);

const isUnavailableManagedRuntime = (
  mode: AppMode,
  runtime: RuntimeHealth,
): boolean => mode === "native"
  && runtime?.provider === "managed_local"
  && runtime.available !== true;

/**
 * Starts a safe product-owned lifecycle operation in the background while the
 * main workspace stays usable. A `starting` runtime already has a live managed
 * machine whose API probe is temporarily unavailable, so it must be allowed to
 * settle instead of launching a second lifecycle operation.
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
