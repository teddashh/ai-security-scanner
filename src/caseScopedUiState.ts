import type { AppSnapshot, CaseExport } from "./types";

interface VerificationBaselineSelection {
  previousCaseId?: string;
  nextCaseId?: string;
  currentRunId?: string;
  savedRunId?: string;
  terminalRunIds: readonly string[];
}

export const selectVerificationBaselineRunId = ({
  previousCaseId,
  nextCaseId,
  currentRunId,
  savedRunId,
  terminalRunIds,
}: VerificationBaselineSelection): string | undefined => {
  const runExists = (runId?: string): runId is string =>
    Boolean(runId && terminalRunIds.includes(runId));

  if (previousCaseId === nextCaseId && runExists(currentRunId)) return currentRunId;
  if (runExists(savedRunId)) return savedRunId;
  return terminalRunIds[0];
};

export const appendExportToMatchingSnapshot = (
  snapshot: AppSnapshot | undefined,
  caseId: string,
  exported: CaseExport,
): AppSnapshot | undefined => {
  if (
    !snapshot?.workspace
    || snapshot.workspace.case.id !== caseId
    || exported.caseId !== caseId
  ) return snapshot;

  return {
    ...snapshot,
    workspace: {
      ...snapshot.workspace,
      exports: [
        exported,
        ...snapshot.workspace.exports.filter((item) => item.id !== exported.id),
      ],
    },
  };
};
