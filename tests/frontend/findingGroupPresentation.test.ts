import assert from "node:assert/strict";
import test from "node:test";

import { projectVisibleFindingGroups } from "../../src/findingGroupPresentation.ts";
import type { FindingGroup } from "../../src/types.ts";

const group = (id: string, findingIds: string[]): FindingGroup => ({
  id,
  caseId: "case-1",
  title: `Group ${id}`,
  findingIds,
  rationale: "These observations should be reviewed together.",
  groupedBy: "reviewer",
  createdAt: "2026-09-03T12:00:00Z",
});

test("accepted groups reduce repetition only when the current report has two members", () => {
  const groups = [
    group("visible", ["finding-1", "finding-2", "historical-finding"]),
    group("one-current", ["finding-2", "historical-finding"]),
    group("other-run", ["historical-a", "historical-b"]),
  ];

  const projected = projectVisibleFindingGroups(
    groups,
    new Set(["finding-1", "finding-2", "unrelated-finding"]),
  );

  assert.equal(projected.length, 1);
  assert.equal(projected[0]?.group.id, "visible");
  assert.deepEqual(projected[0]?.visibleFindingIds, ["finding-1", "finding-2"]);
  assert.equal(projected[0]?.caseHistoryFindingCount, 1);
});

test("projection de-duplicates member identifiers without mutating durable groups", () => {
  const durable = group("duplicate-input", ["finding-1", "finding-1", "finding-2"]);
  const before = structuredClone(durable);

  const [projected] = projectVisibleFindingGroups(
    [durable],
    new Set(["finding-1", "finding-2"]),
  );

  assert.deepEqual(projected?.visibleFindingIds, ["finding-1", "finding-2"]);
  assert.equal(projected?.caseHistoryFindingCount, 0);
  assert.deepEqual(durable, before);
});
