import type { ExportCaseInput, ScanRun } from "./types";

type ExportRunCoordinates = Pick<ExportCaseInput, "caseId" | "runId">;
type ExportRunWorkspace = {
  case: { id: string };
  runs: readonly ScanRun[];
};

/** Resolve only the run named by the export request; never substitute another run. */
export const findRequestedExportRun = (
  input: ExportRunCoordinates,
  workspace: ExportRunWorkspace,
): ScanRun | undefined => {
  if (workspace.case.id !== input.caseId) return undefined;
  return workspace.runs.find((run) => run.id === input.runId && run.caseId === input.caseId);
};

/**
 * Initialize a report run only when entering a case or when no selection has
 * ever been made. A non-empty stale id is retained so every consumer fails
 * closed instead of silently exporting a different run.
 */
export const reconcileReportRunId = (
  previousCaseId: string | undefined,
  caseId: string | undefined,
  selectedRunId: string | undefined,
  runs: readonly Pick<ScanRun, "id">[],
): string | undefined => {
  if (!caseId || runs.length === 0) return undefined;
  if (previousCaseId !== caseId || selectedRunId === undefined) return runs[0]?.id;
  return selectedRunId;
};
