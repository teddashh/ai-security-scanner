import assert from "node:assert/strict";
import test from "node:test";

import {
  afterLatestCaseSelection,
  appendExportToMatchingSnapshot,
  selectVerificationBaselineRunId,
} from "../../src/caseScopedUiState.ts";
import type { AppSnapshot, CaseExport } from "../../src/types.ts";

const deferred = () => {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((fulfill) => {
    resolve = fulfill;
  });
  return { promise, resolve };
};

test("post-delete work follows a newer completed selection without waiting for the obsolete request", async () => {
  const firstSettled = deferred();
  const firstSuperseded = deferred();
  const secondSettled = deferred();
  const secondSuperseded = deferred();
  let selectedCaseId = "case-a";
  let barrier = {
    generation: 1,
    settled: firstSettled.promise,
    superseded: firstSuperseded.promise,
  };
  const observedByAction: string[] = [];

  const postDelete = afterLatestCaseSelection(
    () => barrier,
    () => observedByAction.push(selectedCaseId),
  );

  barrier = {
    generation: 2,
    settled: secondSettled.promise,
    superseded: secondSuperseded.promise,
  };
  firstSuperseded.resolve();
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(observedByAction, []);

  selectedCaseId = "case-c";
  secondSettled.resolve();
  await postDelete;
  assert.deepEqual(observedByAction, ["case-c"]);
});

test("verification baseline does not survive a case change merely because run IDs collide", () => {
  assert.equal(selectVerificationBaselineRunId({
    previousCaseId: "case-a",
    nextCaseId: "case-b",
    currentRunId: "shared-run-id",
    savedRunId: "case-b-saved",
    terminalRunIds: ["shared-run-id", "case-b-saved"],
  }), "case-b-saved");
});

test("verification baseline stays stable within one case and otherwise uses the newest terminal run", () => {
  assert.equal(selectVerificationBaselineRunId({
    previousCaseId: "case-a",
    nextCaseId: "case-a",
    currentRunId: "older-run",
    savedRunId: "saved-run",
    terminalRunIds: ["newest-run", "older-run", "saved-run"],
  }), "older-run");
  assert.equal(selectVerificationBaselineRunId({
    previousCaseId: "case-a",
    nextCaseId: "case-b",
    currentRunId: "missing-run",
    terminalRunIds: ["newest-run"],
  }), "newest-run");
});

const caseExport = (caseId: string): CaseExport => ({
  id: "export-1",
  caseId,
  runId: "run-1",
  createdAt: "2026-09-01T00:00:00.000Z",
  fileName: "report.html",
  sha256: "0".repeat(64),
  signatureState: "unsigned",
});

const snapshotFor = (caseId: string): AppSnapshot => ({
  cases: [],
  selectedCaseId: caseId,
  workspace: {
    case: { id: caseId } as NonNullable<AppSnapshot["workspace"]>["case"],
    runs: [],
    findings: [],
    findingGroups: [],
    findingGroupEvents: [],
    coverage: [],
    workflowEvents: [],
    exports: [],
  },
  engineManifests: [],
  generatedAt: "2026-09-01T00:00:00.000Z",
  provenance: "native",
});

test("an export completion cannot mutate a snapshot for another case", () => {
  const caseBSnapshot = snapshotFor("case-b");
  const result = appendExportToMatchingSnapshot(caseBSnapshot, "case-a", caseExport("case-a"));

  assert.strictEqual(result, caseBSnapshot);
  assert.deepEqual(result?.workspace?.exports, []);
});

test("a matching export is prepended once to its own case", () => {
  const caseASnapshot = snapshotFor("case-a");
  const exported = caseExport("case-a");
  const first = appendExportToMatchingSnapshot(caseASnapshot, "case-a", exported);
  const second = appendExportToMatchingSnapshot(first, "case-a", exported);

  assert.deepEqual(second?.workspace?.exports, [exported]);
});
