import assert from "node:assert/strict";
import test from "node:test";

import {
  appendExportToMatchingSnapshot,
  selectVerificationBaselineRunId,
} from "../../src/caseScopedUiState.ts";
import type { AppSnapshot, CaseExport } from "../../src/types.ts";

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
