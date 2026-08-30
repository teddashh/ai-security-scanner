export const findRunCreatedAfterStart = (
  runs: ReadonlyArray<{ id: string }>,
  existingRunIds: ReadonlySet<string>,
): string | undefined => runs.find((run) => !existingRunIds.has(run.id))?.id;

const activeRunStatuses = new Set(["queued", "running", "paused"]);
const activeEngineStatuses = new Set(["pending", "running", "paused"]);

export const hasActiveScanWork = (
  runs: ReadonlyArray<{
    status: string;
    engineRuns?: ReadonlyArray<{ status: string }>;
  }>,
): boolean => runs.some((run) =>
  activeRunStatuses.has(run.status)
  || run.engineRuns?.some((engineRun) => activeEngineStatuses.has(engineRun.status)) === true);

export const canStartPreparedScan = (
  readiness: { ready: boolean } | undefined,
  readinessCheckFailed: boolean,
  runs: ReadonlyArray<{ status: string }>,
): boolean => Boolean(
  !readinessCheckFailed
  && readiness?.ready
  && !hasActiveScanWork(runs),
);
