import type { ScanRun } from "./types";

const terminalResultStatuses = new Set<ScanRun["status"]>([
  "completed",
  "no_checks_completed",
  "partial",
  "failed",
  "cancelled",
]);

const verificationBaselineStatuses = new Set<ScanRun["status"]>([
  "completed",
  "partial",
  "failed",
  "cancelled",
]);

export const isTerminalResultRun = (run: Pick<ScanRun, "status">): boolean =>
  terminalResultStatuses.has(run.status);

/** A run with no completed checks has no scanner result to compare. */
export const isVerificationBaselineRun = (run: Pick<ScanRun, "status">): boolean =>
  verificationBaselineStatuses.has(run.status);
