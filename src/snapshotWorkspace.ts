import type { AppSnapshot, AssessmentCase, CaseWorkspace } from "./types";

interface ComparableTimestamp {
  epochMilliseconds: number;
  subMillisecondNanoseconds: number;
}

const rfc3339Timestamp =
  /^(\d{4})-(\d{2})-(\d{2})T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.(\d{1,9}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/u;

const isLeapYear = (year: number) => year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);

const daysInMonth = (year: number, month: number) => {
  const monthLengths = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return monthLengths[month - 1];
};

/**
 * Parse the RFC 3339 timestamps emitted by the native case model without
 * discarding Chrono's sub-millisecond precision. Invalid or non-canonical
 * values are deliberately not orderable, so callers retain current state.
 */
const comparableTimestamp = (value: string): ComparableTimestamp | undefined => {
  const match = rfc3339Timestamp.exec(value);
  if (!match) return undefined;

  const [yearText, monthText, dayText] = match.slice(1, 4);
  const fraction = match[7] ?? "";
  const zone = match[8];
  if (!yearText || !monthText || !dayText || !zone) return undefined;

  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const maximumDay = daysInMonth(year, month);
  if (maximumDay === undefined || day < 1 || day > maximumDay) return undefined;

  const nanoseconds = fraction.padEnd(9, "0");
  const millisecondText = nanoseconds.slice(0, 3);
  const normalized = `${value.slice(0, 19)}.${millisecondText}${zone}`;
  const epochMilliseconds = Date.parse(normalized);
  if (!Number.isFinite(epochMilliseconds)) return undefined;

  return {
    epochMilliseconds,
    subMillisecondNanoseconds: Number(nanoseconds.slice(3)),
  };
};

const compareTimestamps = (left: ComparableTimestamp, right: ComparableTimestamp) => {
  if (left.epochMilliseconds !== right.epochMilliseconds) {
    return left.epochMilliseconds < right.epochMilliseconds ? -1 : 1;
  }
  if (left.subMillisecondNanoseconds === right.subMillisecondNanoseconds) return 0;
  return left.subMillisecondNanoseconds < right.subMillisecondNanoseconds ? -1 : 1;
};

const compareCaseRevisions = (
  left: AssessmentCase,
  right: AssessmentCase,
): number | undefined => {
  const leftTimestamp = comparableTimestamp(left.updatedAt);
  const rightTimestamp = comparableTimestamp(right.updatedAt);
  if (!leftTimestamp || !rightTimestamp) return undefined;
  return compareTimestamps(leftTimestamp, rightTimestamp);
};

/**
 * Keep the already-observed payload unless another workspace can prove that
 * it has a newer native case revision. This is also used by App's bounded
 * per-case event journal, so reordered progress/finished channels cannot make
 * a stale event the protected revision for an in-flight snapshot request.
 */
export const selectNewerWorkspaceByRevision = (
  current: CaseWorkspace | undefined,
  incoming: CaseWorkspace,
): CaseWorkspace => {
  if (!current || compareCaseRevisions(incoming.case, current.case) === 1) return incoming;
  return current;
};

/**
 * Apply a case event without replacing unrelated app-level state such as the
 * last verified runtime health. Events for a background case still refresh its
 * list summary, but must never switch the case the user is viewing.
 */
export const mergeWorkspaceIntoSnapshot = (
  snapshot: AppSnapshot | undefined,
  workspace: CaseWorkspace,
): AppSnapshot | undefined => {
  if (!snapshot) return snapshot;

  const cases = [...snapshot.cases];
  const existingIndex = cases.findIndex((item) => item.id === workspace.case.id);
  const existingCase = existingIndex >= 0 ? cases[existingIndex] : undefined;
  const isSelectedCase = snapshot.selectedCaseId === workspace.case.id;
  const existingWorkspace =
    isSelectedCase && snapshot.workspace?.case.id === workspace.case.id ? snapshot.workspace : undefined;
  const incomingTimestamp = comparableTimestamp(workspace.case.updatedAt);

  // A malformed timestamp cannot prove that an asynchronous result is newer.
  // Preserve the current snapshot rather than risking a same-case rollback.
  if (!incomingTimestamp) return snapshot;

  const existingCaseTimestamp = existingCase
    ? comparableTimestamp(existingCase.updatedAt)
    : undefined;
  const existingWorkspaceTimestamp = existingWorkspace
    ? comparableTimestamp(existingWorkspace.case.updatedAt)
    : undefined;
  if ((existingCase && !existingCaseTimestamp) || (existingWorkspace && !existingWorkspaceTimestamp)) {
    return snapshot;
  }

  const currentTimestamps = [existingCaseTimestamp, existingWorkspaceTimestamp].filter(
    (timestamp): timestamp is ComparableTimestamp => timestamp !== undefined,
  );
  const newestCurrentTimestamp = currentTimestamps.reduce<ComparableTimestamp | undefined>(
    (newest, timestamp) =>
      !newest || compareTimestamps(timestamp, newest) > 0 ? timestamp : newest,
    undefined,
  );
  const incomingOrder = newestCurrentTimestamp
    ? compareTimestamps(incomingTimestamp, newestCurrentTimestamp)
    : 1;

  // This is the fast-event/slow-command race: once a newer event has landed,
  // an older command response must not roll back either the case summary or
  // the detailed workspace.
  if (incomingOrder < 0) return snapshot;

  let casesChanged = false;
  let nextWorkspace = snapshot.workspace;

  if (incomingOrder > 0) {
    if (existingIndex >= 0) cases[existingIndex] = workspace.case;
    else cases.unshift(workspace.case);
    casesChanged = true;
    if (isSelectedCase) nextWorkspace = workspace;
  } else if (newestCurrentTimestamp) {
    // Equal revisions are ambiguous and must not replace an equally current
    // payload. They may, however, safely bring an older/missing representation
    // up to the revision already known elsewhere in this snapshot.
    const caseIsOlder =
      !existingCaseTimestamp || compareTimestamps(existingCaseTimestamp, newestCurrentTimestamp) < 0;
    if (caseIsOlder) {
      const authoritativeCase =
        existingWorkspaceTimestamp &&
        compareTimestamps(existingWorkspaceTimestamp, newestCurrentTimestamp) === 0
          ? existingWorkspace?.case
          : workspace.case;
      if (authoritativeCase) {
        if (existingIndex >= 0) cases[existingIndex] = authoritativeCase;
        else cases.unshift(authoritativeCase);
        casesChanged = true;
      }
    }

    const workspaceIsOlder =
      isSelectedCase &&
      (!existingWorkspaceTimestamp ||
        compareTimestamps(existingWorkspaceTimestamp, newestCurrentTimestamp) < 0);
    if (workspaceIsOlder) nextWorkspace = workspace;
  }

  if (!casesChanged && nextWorkspace === snapshot.workspace) return snapshot;
  return { ...snapshot, cases, workspace: nextWorkspace };
};

/**
 * Refresh app-level state from an authoritative snapshot without rolling back
 * a newer case revision already delivered by the native event bus. Only cases
 * that still exist in the authoritative list are inherited from `current`;
 * workspaces observed after this request began are applied separately so a
 * genuinely deleted case is not resurrected by ordinary stale UI state.
 */
export const reconcileAuthoritativeSnapshot = (
  current: AppSnapshot | undefined,
  authoritative: AppSnapshot,
  workspacesObservedAfterRequest: readonly CaseWorkspace[] = [],
): AppSnapshot => {
  const currentCases = new Map(current?.cases.map((item) => [item.id, item]) ?? []);
  const cases = authoritative.cases.map((incoming) => {
    const existing = currentCases.get(incoming.id);
    if (!existing) return incoming;
    const order = compareCaseRevisions(existing, incoming);
    return order !== undefined && order >= 0 ? existing : incoming;
  });

  let workspace = authoritative.workspace;
  const currentWorkspace =
    current?.selectedCaseId === authoritative.selectedCaseId
    && current?.workspace?.case.id === authoritative.selectedCaseId
      ? current?.workspace
      : undefined;
  if (currentWorkspace && workspace?.case.id === currentWorkspace.case.id) {
    const order = compareCaseRevisions(currentWorkspace.case, workspace.case);
    if (order !== undefined && order >= 0) workspace = currentWorkspace;
  }

  if (workspace) {
    const caseIndex = cases.findIndex((item) => item.id === workspace.case.id);
    if (caseIndex >= 0 && compareCaseRevisions(workspace.case, cases[caseIndex]!) === 1) {
      cases[caseIndex] = workspace.case;
    }
  }

  let reconciled: AppSnapshot = { ...authoritative, cases, workspace };
  for (const observed of workspacesObservedAfterRequest) {
    reconciled = mergeWorkspaceIntoSnapshot(reconciled, observed) ?? reconciled;
  }
  return reconciled;
};
