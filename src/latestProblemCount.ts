import { isSecurityFinding } from "./findingClassification.ts";
import { projectProblemRows } from "./reportProblemPresentation.ts";
import { isTerminalResultRun } from "./runLifecycle.ts";
import type { BeginnerMasterReport, Finding, ScanRun } from "./types";

type ProblemCountRun = Pick<ScanRun, "id" | "status">;
type ProblemCountReport = Pick<BeginnerMasterReport, "runId" | "findings" | "problemGroups">;
type ProblemCountFinding = Pick<Finding, "severityBasisCode">;

export interface LatestProblemCount<TRun extends ProblemCountRun = ProblemCountRun> {
  count: number;
  /** Set when `count` comes from this finished run's beginner report. */
  run?: TRun;
}

/**
 * `runs` is newest-first, the order the native adapter gives `workspace.runs`
 * (sequence, then created time, then id). The first terminal run is the latest
 * finished scan; a newer active run stays ahead of it and is skipped.
 */
const latestFinishedRun = <TRun extends ProblemCountRun>(runs: readonly TRun[]): TRun | undefined =>
  runs.find(isTerminalResultRun);

/** Problem count for the My scans card, or the saved security-finding total when no report applies. */
export function latestProblemCount<TRun extends ProblemCountRun>(input: {
  runs: readonly TRun[];
  beginnerReports: readonly ProblemCountReport[];
  findings: readonly ProblemCountFinding[];
  isDemo: boolean;
}): LatestProblemCount<TRun> {
  const savedCount = input.findings.filter(isSecurityFinding).length;
  if (input.isDemo) return { count: savedCount };
  const run = latestFinishedRun(input.runs);
  const report = run
    ? input.beginnerReports.find((item) => item.runId === run.id)
    : undefined;
  if (!run || !report) return { count: savedCount };
  return {
    count: projectProblemRows(report.findings.filter(isSecurityFinding), report.problemGroups).length,
    run,
  };
}
