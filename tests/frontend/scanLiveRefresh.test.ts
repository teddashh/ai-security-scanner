import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { mergeWorkspaceIntoSnapshot } from "../../src/snapshotWorkspace.ts";
import type { AppSnapshot, AssessmentCase, CaseWorkspace } from "../../src/types.ts";

const initialUpdatedAt = "2026-08-27T12:00:00.000000001Z";

const assessmentCase = (id: string, name: string, updatedAt = initialUpdatedAt) =>
  ({ id, name, updatedAt }) as AssessmentCase;
const workspace = (id: string, name: string, updatedAt = initialUpdatedAt, runId?: string) =>
  ({
    case: assessmentCase(id, name, updatedAt),
    runs: runId ? [{ id: runId }] : [],
  }) as unknown as CaseWorkspace;

const snapshot = (selectedCaseId = "case-a") => ({
  selectedCaseId,
  cases: [assessmentCase("case-a", "Old A"), assessmentCase("case-b", "Old B")],
  workspace: workspace(selectedCaseId, `Old ${selectedCaseId}`),
  runtime: { provider: "managed_local", available: true, phase: "ready", detail: "ready" },
}) as AppSnapshot;

test("a scan event updates the visible workspace without replacing app-level runtime health", () => {
  const current = snapshot();
  const runtime = current.runtime;
  const updated = mergeWorkspaceIntoSnapshot(
    current,
    workspace("case-a", "Live A", "2026-08-27T12:00:00.000000002Z"),
  );

  assert.equal(updated?.workspace?.case.name, "Live A");
  assert.equal(updated?.cases.find((item) => item.id === "case-a")?.name, "Live A");
  assert.equal(updated?.runtime, runtime);
});

test("a background case event updates its summary without switching the visible case", () => {
  const current = snapshot();
  const visibleWorkspace = current.workspace;
  const updated = mergeWorkspaceIntoSnapshot(
    current,
    workspace("case-b", "Live B", "2026-08-27T12:00:00.000000002Z"),
  );

  assert.equal(updated?.selectedCaseId, "case-a");
  assert.equal(updated?.workspace, visibleWorkspace);
  assert.equal(updated?.cases.find((item) => item.id === "case-b")?.name, "Live B");
});

test("a fast scan event cannot be overwritten by an older same-case command result", () => {
  const eventWorkspace = workspace(
    "case-a",
    "Live event",
    "2026-08-27T12:00:00.000000003Z",
    "event-run",
  );
  const afterEvent = mergeWorkspaceIntoSnapshot(snapshot(), eventWorkspace);
  const delayedCommandWorkspace = workspace(
    "case-a",
    "Delayed command",
    "2026-08-27T12:00:00.000000002Z",
    "command-run",
  );
  const afterCommand = mergeWorkspaceIntoSnapshot(afterEvent, delayedCommandWorkspace);

  assert.equal(afterCommand, afterEvent);
  assert.equal(afterCommand?.workspace, eventWorkspace);
  assert.equal(afterCommand?.workspace?.runs[0]?.id, "event-run");
  assert.equal(afterCommand?.cases.find((item) => item.id === "case-a")?.name, "Live event");
});

test("an equal ambiguous command result preserves the workspace already in state", () => {
  const updatedAt = "2026-08-27T12:00:00.123456789Z";
  const liveWorkspace = workspace("case-a", "Live event", updatedAt, "event-run");
  const current = mergeWorkspaceIntoSnapshot(snapshot(), liveWorkspace);
  const delayedCommandWorkspace = workspace("case-a", "Delayed command", updatedAt, "command-run");
  const updated = mergeWorkspaceIntoSnapshot(current, delayedCommandWorkspace);

  assert.equal(updated, current);
  assert.equal(updated?.workspace, liveWorkspace);
});

test("an equal authoritative revision can fill an older visible workspace", () => {
  const current = snapshot();
  const authoritativeUpdatedAt = "2026-08-27T12:00:00.000000003Z";
  current.cases[0] = assessmentCase("case-a", "Current summary", authoritativeUpdatedAt);
  const liveWorkspace = workspace(
    "case-a",
    "Current summary",
    authoritativeUpdatedAt,
    "event-run",
  );
  const updated = mergeWorkspaceIntoSnapshot(current, liveWorkspace);

  assert.notEqual(updated, current);
  assert.equal(updated?.cases[0], current.cases[0]);
  assert.equal(updated?.workspace, liveWorkspace);
});

test("a stale background event changes neither its summary nor the visible workspace", () => {
  const current = snapshot();
  current.cases[1] = assessmentCase(
    "case-b",
    "Newer background summary",
    "2026-08-27T12:00:00.000000003Z",
  );
  const visibleWorkspace = current.workspace;
  const updated = mergeWorkspaceIntoSnapshot(
    current,
    workspace("case-b", "Stale background event", "2026-08-27T12:00:00.000000002Z"),
  );

  assert.equal(updated, current);
  assert.equal(updated?.workspace, visibleWorkspace);
  assert.equal(updated?.cases[1]?.name, "Newer background summary");
});

test("unorderable case timestamps fail closed", () => {
  const current = snapshot();
  const invalidIncoming = mergeWorkspaceIntoSnapshot(
    current,
    workspace("case-a", "Invalid incoming", "not-a-timestamp"),
  );
  assert.equal(invalidIncoming, current);

  current.cases[0] = assessmentCase("case-a", "Invalid current", "2026-02-30T12:00:00Z");
  const validIncoming = mergeWorkspaceIntoSnapshot(
    current,
    workspace("case-a", "Cannot prove newer", "2026-08-27T12:00:00.000000004Z"),
  );
  assert.equal(validIncoming, current);
});

test("scan lifecycle actions and events carry the authoritative workspace into App state", () => {
  const scannerSource = readFileSync(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");
  const appSource = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");

  assert.match(scannerSource, /workspace: returnWorkspace \? workspace : undefined/u);
  assert.match(scannerSource, /\[EVENTS\.runProgress, EVENTS\.runFinished\]/u);
  assert.match(scannerSource, /handler\(adaptNativeCase\(event\.payload\.payload, manifests\), eventName\)/u);
  assert.match(appSource, /scannerService\.subscribeScanWorkspace/u);
  assert.match(appSource, /mergeWorkspaceIntoSnapshot\(current, workspace\)/u);
  const finishedRefreshStart = appSource.indexOf("if (eventName === EVENTS.runFinished");
  const finishedRefreshEnd = appSource.indexOf("\n          }", finishedRefreshStart);
  const finishedRefresh = appSource.slice(finishedRefreshStart, finishedRefreshEnd);
  assert.ok(finishedRefreshStart >= 0 && finishedRefreshEnd > finishedRefreshStart);
  assert.match(finishedRefresh, /workspace\.case\.id === selectedCaseIdRef\.current/u);
  assert.match(finishedRefresh, /const readinessRequestGeneration = scanReadinessRequestGeneration\.current/u);
  assert.match(finishedRefresh, /const readinessResponseGeneration = \+\+scanReadinessResponseGeneration\.current/u);
  assert.match(finishedRefresh, /scannerService\.getScanReadiness\(workspace\.case\.id\)/u);
  assert.match(finishedRefresh, /selectedCaseIdRef\.current !== workspace\.case\.id/u);
  assert.match(finishedRefresh, /isCurrentScanReadinessResponse/u);
  assert.doesNotMatch(finishedRefresh, /loadSnapshot/u);
  assert.equal(
    [...finishedRefresh.matchAll(/scannerService\.getScanReadiness\(workspace\.case\.id\)/gu)].length,
    1,
  );
  assert.match(appSource, /selectedCaseIdRef\.current = caseId;[\s\S]*?setSnapshot\(\(current\)/u);
  assert.equal(
    [...appSource.matchAll(/\+\+scanReadinessResponseGeneration\.current/gu)].length,
    4,
    "every readiness request must supersede earlier readiness responses",
  );
  assert.doesNotMatch(appSource, /const eventNames = Object\.values\(EVENTS\)/u);

  for (const method of ["startScan", "pauseScan", "resumeScan", "cancelScan", "startRescan"]) {
    const start = scannerSource.indexOf(`async ${method}`);
    const end = scannerSource.indexOf("\n  },", start);
    assert.notEqual(start, -1, `${method} must exist`);
    assert.match(scannerSource.slice(start, end), /,\r?\n\s+true,\r?\n\s+\);/u, `${method} must return its workspace`);
  }
});
