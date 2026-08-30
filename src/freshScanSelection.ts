export const findRunCreatedAfterStart = (
  runs: ReadonlyArray<{ id: string }>,
  existingRunIds: ReadonlySet<string>,
): string | undefined => runs.find((run) => !existingRunIds.has(run.id))?.id;

const activeRunStatuses = new Set(["queued", "running", "paused"]);
const activeEngineStatuses = new Set(["pending", "running", "paused"]);
const startBlockingReasons = new Set([
  "demo_case",
  "archived_case",
  "scan_already_active",
  "no_effective_scope_grants",
  "no_ownership_confirmed_targets",
]);

export const hasActiveScanWork = (
  runs: ReadonlyArray<{
    status: string;
    engineRuns?: ReadonlyArray<{ status: string }>;
  }>,
): boolean => runs.some((run) =>
  activeRunStatuses.has(run.status)
  || run.engineRuns?.some((engineRun) => activeEngineStatuses.has(engineRun.status)) === true);

export const canStartPreparedScan = (
  readiness: { ready: boolean; blockerCode?: string } | undefined,
  _readinessCheckFailed: boolean,
  runs: ReadonlyArray<{ status: string }>,
): boolean => {
  if (hasActiveScanWork(runs)) return false;
  const blocker = readiness?.blockerCode;
  return !blocker || !startBlockingReasons.has(blocker);
};
