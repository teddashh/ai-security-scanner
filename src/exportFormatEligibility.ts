import type { ExportFormat, ScanRun } from "./types";

export type FindingOnlyExportFormat = "ocsf" | "oscal";

export const isFindingOnlyExportFormat = (
  format: ExportFormat,
): format is FindingOnlyExportFormat => format === "ocsf" || format === "oscal";

const terminalRunStatuses = new Set<ScanRun["status"]>([
  "completed",
  "no_checks_completed",
  "partial",
  "failed",
  "cancelled",
]);

/** OCSF and OSCAL are paired with a mandatory coverage manifest by the backend. */
export const runSupportsFindingOnlyExport = (run: ScanRun | undefined): boolean =>
  Boolean(run && terminalRunStatuses.has(run.status));

export const exportFormatIsAvailable = (
  format: ExportFormat,
  run: ScanRun | undefined,
): boolean => Boolean(
  run
  && terminalRunStatuses.has(run.status)
  && (!isFindingOnlyExportFormat(format) || runSupportsFindingOnlyExport(run)),
);

export const resetUnavailableExportFormat = (
  format: ExportFormat,
  run: ScanRun | undefined,
): ExportFormat => exportFormatIsAvailable(format, run) ? format : "html";
