export interface ComparisonLimitation {
  code: string;
  engineId?: string;
}

const mappingVersionChanged = "mapping_version_changed";

export function isOnlyMappingVersionDrift(issues: readonly ComparisonLimitation[]): boolean {
  return issues.length > 0 && issues.every((issue) => issue.code === mappingVersionChanged);
}

export function affectedEngineCount(issues: readonly ComparisonLimitation[]): number {
  return new Set(
    issues
      .map((issue) => issue.engineId?.trim())
      .filter((engineId): engineId is string => Boolean(engineId)),
  ).size;
}
