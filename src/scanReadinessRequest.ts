export const isCurrentScanReadinessRequest = (
  currentGeneration: number,
  requestGeneration: number,
): boolean => currentGeneration === requestGeneration;

export const isCurrentScanReadinessResponse = (
  currentGeneration: number,
  requestGeneration: number,
  requestedCaseId: string,
  responseCaseId: string,
): boolean => isCurrentScanReadinessRequest(currentGeneration, requestGeneration)
  && requestedCaseId === responseCaseId;
