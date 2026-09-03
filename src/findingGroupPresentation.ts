import type { FindingGroup } from "./types";

export interface VisibleFindingGroup {
  group: FindingGroup;
  visibleFindingIds: string[];
  caseHistoryFindingCount: number;
}

/**
 * Projects case-wide presentation groups onto the findings that are safe to
 * show in the current report view. A group needs at least two visible members
 * to reduce repetition; missing members remain case history and are counted
 * explicitly instead of being borrowed into another run.
 */
export function projectVisibleFindingGroups(
  groups: ReadonlyArray<FindingGroup>,
  visibleFindingIds: ReadonlySet<string>,
): VisibleFindingGroup[] {
  return groups.flatMap((group) => {
    const distinctFindingIds = [...new Set(group.findingIds)];
    const visibleGroupFindingIds = distinctFindingIds.filter((findingId) =>
      visibleFindingIds.has(findingId)
    );
    if (visibleGroupFindingIds.length < 2) return [];

    return [{
      group,
      visibleFindingIds: visibleGroupFindingIds,
      caseHistoryFindingCount: distinctFindingIds.length - visibleGroupFindingIds.length,
    }];
  });
}
