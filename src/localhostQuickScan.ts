import type { EngineRun, ScanRun } from "./types";

export const DEFAULT_LOCALHOST_QUICK_SCAN_PORT = 9001;
export const LOCALHOST_QUICK_SCAN_TIMEOUT_MS = 3_000;
export const BUILT_IN_LOCALHOST_QUICK_SCAN_ENGINE_ID = "built-in-localhost-tcp";

export const isValidLocalhostQuickScanPort = (port: number): boolean =>
  Number.isInteger(port) && port >= 1 && port <= 65_535;

export const parseLocalhostQuickScanPort = (value: string): number | undefined => {
  const normalized = value.trim();
  if (!/^\d{1,5}$/u.test(normalized)) return undefined;
  const port = Number(normalized);
  return isValidLocalhostQuickScanPort(port) ? port : undefined;
};

/**
 * Identifies only the product-owned, payload-free localhost task contract.
 * Catalog engines and malformed/expanded task records deliberately remain
 * outside this predicate.
 */
export const isExactBuiltInLocalhostQuickScanEngine = (
  engine: Pick<EngineRun, "engineId" | "taskKind">,
): boolean => engine.engineId === BUILT_IN_LOCALHOST_QUICK_SCAN_ENGINE_ID
  && engine.taskKind.kind === "built_in_localhost_tcp"
  && isValidLocalhostQuickScanPort(engine.taskKind.port)
  && engine.taskKind.timeoutMs === LOCALHOST_QUICK_SCAN_TIMEOUT_MS
  && engine.taskKind.payloadBytes === 0;

export const isExactBuiltInLocalhostQuickScanRun = (
  run: Pick<ScanRun, "engineRuns">,
): boolean => run.engineRuns.length === 1
  && isExactBuiltInLocalhostQuickScanEngine(run.engineRuns[0]!);

/** A cancel request is not a terminal cancellation result. */
export const isLocalhostQuickScanCancelRequested = (
  run: Pick<ScanRun, "status" | "engineRuns">,
): boolean => ["queued", "running", "paused"].includes(run.status)
  && isExactBuiltInLocalhostQuickScanRun(run)
  && run.engineRuns[0]?.phase === "cancel_requested"
  && ["pending", "running"].includes(run.engineRuns[0].status);
