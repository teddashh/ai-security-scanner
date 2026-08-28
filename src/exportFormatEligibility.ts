import type { ExportFormat, ScanRun } from "./types";

export type FindingOnlyExportFormat = "ocsf" | "oscal";

export const isFindingOnlyExportFormat = (
  format: ExportFormat,
): format is FindingOnlyExportFormat => format === "ocsf" || format === "oscal";

/**
 * OCSF and OSCAL exports contain findings, but no engine-outcome ledger. They
 * are safe to offer only after the selected run has durably finished and every
 * planned engine has completed successfully.
 */
export const runSupportsFindingOnlyExport = (run: ScanRun | undefined): boolean =>
  Boolean(
    run
    && run.status === "completed"
    && run.finishedAt
    && run.engineRuns.length > 0
    && run.engineRuns.every((engineRun) => engineRun.status === "completed"),
  );

export const exportFormatIsAvailable = (
  format: ExportFormat,
  run: ScanRun | undefined,
): boolean => !isFindingOnlyExportFormat(format) || runSupportsFindingOnlyExport(run);

export const resetUnavailableExportFormat = (
  format: ExportFormat,
  run: ScanRun | undefined,
): ExportFormat => exportFormatIsAvailable(format, run) ? format : "case_bundle";
