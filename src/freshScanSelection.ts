export const findRunCreatedAfterStart = (
  runs: ReadonlyArray<{ id: string }>,
  existingRunIds: ReadonlySet<string>,
): string | undefined => runs.find((run) => !existingRunIds.has(run.id))?.id;

const activeRunStatuses = new Set(["queued", "running", "paused"]);

export const hasActiveScanWork = (
  runs: ReadonlyArray<{ status: string }>,
): boolean => runs.some((run) => activeRunStatuses.has(run.status));

export const canStartPreparedScan = (
  readiness: { ready: boolean } | undefined,
  readinessCheckFailed: boolean,
  runs: ReadonlyArray<{ status: string }>,
): boolean => Boolean(
  !readinessCheckFailed
  && readiness?.ready
  && !hasActiveScanWork(runs),
);
