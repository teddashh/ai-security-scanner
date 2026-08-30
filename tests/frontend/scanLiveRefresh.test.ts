import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  mergeWorkspaceIntoSnapshot,
  reconcileAuthoritativeSnapshot,
  selectNewerWorkspaceByRevision,
} from "../../src/snapshotWorkspace.ts";
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

test("an old authoritative fetch keeps newer selected and background events while refreshing app state", () => {
  const selectedEvent = workspace(
    "case-a",
    "Selected event",
    "2026-08-27T12:00:00.000000004Z",
    "selected-event-run",
  );
  const backgroundEvent = workspace(
    "case-c",
    "Background event",
    "2026-08-27T12:00:00.000000005Z",
    "background-event-run",
  );
  const afterSelectedEvent = mergeWorkspaceIntoSnapshot(snapshot(), selectedEvent);
  const current = mergeWorkspaceIntoSnapshot(afterSelectedEvent, backgroundEvent);
  const fetched = snapshot();
  fetched.generatedAt = "2026-08-27T12:00:01Z";
  fetched.runtime = {
    provider: "managed_local",
    available: false,
    phase: "repairing",
    detail: "fresh authoritative runtime state",
  };

  const reconciled = reconcileAuthoritativeSnapshot(
    current,
    fetched,
    [selectedEvent, backgroundEvent],
  );

  assert.equal(reconciled.workspace, selectedEvent);
  assert.equal(reconciled.workspace?.runs[0]?.id, "selected-event-run");
  assert.equal(reconciled.cases.find((item) => item.id === "case-a")?.name, "Selected event");
  assert.equal(reconciled.cases.find((item) => item.id === "case-c")?.name, "Background event");
  assert.equal(reconciled.runtime, fetched.runtime, "app-level runtime state comes from the fetch");
  assert.equal(reconciled.generatedAt, fetched.generatedAt);
});

test("ordinary stale state cannot resurrect a case omitted by the authoritative snapshot", () => {
  const current = snapshot();
  current.cases.push(assessmentCase(
    "case-deleted",
    "Deleted case",
    "2026-08-27T12:00:00.000000006Z",
  ));

  const reconciled = reconcileAuthoritativeSnapshot(current, snapshot());

  assert.equal(reconciled.cases.some((item) => item.id === "case-deleted"), false);
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

test("a delayed older post-action event cannot replace newer render-time truth", () => {
  const newerRenderTime = workspace(
    "case-a",
    "Already failed",
    "2026-08-27T12:00:00.000000004Z",
    "failed-run",
  );
  const delayedProgressEvent = workspace(
    "case-a",
    "Old queued event",
    "2026-08-27T12:00:00.000000002Z",
    "queued-run",
  );

  const selected = selectNewerWorkspaceByRevision(delayedProgressEvent, newerRenderTime);
  assert.equal(selected, newerRenderTime);
  assert.equal(selected.runs[0]?.id, "failed-run");
});

test("scan lifecycle actions and events carry the authoritative workspace into App state", () => {
  const scannerSource = readFileSync(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");
  const appSource = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");

  assert.match(scannerSource, /workspace: returnWorkspace \? workspace : undefined/u);
  const actionResultStart = scannerSource.indexOf("const actionResult = async");
  const actionResultEnd = scannerSource.indexOf("const employeeRanges", actionResultStart);
  const actionResultSource = scannerSource.slice(actionResultStart, actionResultEnd);
  assert.ok(actionResultStart >= 0 && actionResultEnd > actionResultStart);
  assert.match(actionResultSource, /adaptNativeCase\(returnedCase, \[\]\)/u);
  assert.doesNotMatch(actionResultSource, /getNativeManifests|listEngineManifests/u);
  assert.match(scannerSource, /eventNames: \[EVENTS\.runProgress, EVENTS\.runFinished\]/u);
  assert.match(scannerSource, /subscribeBufferedEvents/u);
  assert.match(scannerSource, /adapt:[\s\S]*?adaptNativeCase\(event\.payload, manifests\)/u);
  assert.match(appSource, /scannerService\.subscribeScanWorkspace/u);
  assert.match(appSource, /applyScanWorkspaceEvent\(workspace\)/u);
  assert.match(appSource, /observedScanWorkspaces\.current\.get\(lifecycleCaseId\)[\s\S]*const eventTruth = selectNewerWorkspaceByRevision\([\s\S]*observed\.workspace,[\s\S]*observed\.freshestWorkspace[\s\S]*observed\.generation > workspaceEventGenerationAtRequest[\s\S]*selectNewerWorkspaceByRevision\(eventTruth, selectedWorkspace\)[\s\S]*: eventTruth[\s\S]*: selectNewerWorkspaceByRevision\(selectedWorkspace, observed\.freshestWorkspace\)/u);
  assert.match(appSource, /observedScanWorkspaces\.current\.set\(workspace\.case\.id, \{[\s\S]*generation,[\s\S]*workspace,[\s\S]*freshestWorkspace/u);
  assert.match(appSource, /deriveScanLifecycleDisposition\([\s\S]*selectedWorkspace[\s\S]*lifecycleDisposition\.runId/u);
  assert.match(appSource, /scanLifecycleToastPresentation\(lifecycleDisposition\)/u);
  assert.match(appSource, /lifecycleDisposition\?\.outcome === "unconfirmed"[\s\S]*void loadSnapshot/u);
  const unconfirmedRefreshStart = appSource.indexOf('if (lifecycleDisposition?.outcome === "unconfirmed"');
  const unconfirmedRefreshEnd = appSource.indexOf("\n      }", unconfirmedRefreshStart);
  const unconfirmedRefresh = appSource.slice(unconfirmedRefreshStart, unconfirmedRefreshEnd);
  assert.ok(unconfirmedRefreshStart >= 0 && unconfirmedRefreshEnd > unconfirmedRefreshStart);
  assert.equal([...unconfirmedRefresh.matchAll(/loadSnapshot\(/gu)].length, 1);
  assert.match(unconfirmedRefresh, /void loadSnapshot/u);
  assert.doesNotMatch(unconfirmedRefresh, /await loadSnapshot/u);
  assert.match(appSource, /reconcileAuthoritativeSnapshot/u);
  assert.match(appSource, /observed\.generation > workspaceEventGenerationAtRequest/u);
  const registrationStart = appSource.indexOf("const subscriptions = subscribeAllThenReconcile");
  const registrationEnd = appSource.indexOf("void subscriptions.ready.catch", registrationStart);
  const registration = appSource.slice(registrationStart, registrationEnd);
  assert.ok(registrationStart >= 0 && registrationEnd > registrationStart);
  assert.match(registration, /subscriptions: \[[\s\S]*scannerService\.subscribeScanWorkspace/u);
  assert.match(registration, /refreshEventNames\.map[\s\S]*scannerService\.subscribe/u);
  assert.match(registration, /reconcile: async \(\) => \{[\s\S]*listenersReady = true;[\s\S]*await loadSnapshot\(selectedCaseIdRef\.current, true\)/u);
  const finishedRefreshStart = appSource.indexOf("if (eventName === EVENTS.runFinished");
  const finishedRefreshEnd = appSource.indexOf("\n          }", finishedRefreshStart);
  const finishedRefresh = appSource.slice(finishedRefreshStart, finishedRefreshEnd);
  assert.ok(finishedRefreshStart >= 0 && finishedRefreshEnd > finishedRefreshStart);
  assert.match(finishedRefresh, /workspace\.case\.id === selectedCaseIdRef\.current/u);
  assert.match(finishedRefresh, /const readinessRequestGeneration = scanReadinessRequestGeneration\.current/u);
  assert.match(finishedRefresh, /const readinessResponseGeneration = \+\+scanReadinessResponseGeneration\.current/u);
  assert.match(finishedRefresh, /readScanReadinessWithin\(workspace\.case\.id, acceptReadiness\)/u);
  assert.match(finishedRefresh, /selectedCaseIdRef\.current !== workspace\.case\.id/u);
  assert.match(finishedRefresh, /isCurrentScanReadinessResponse/u);
  assert.doesNotMatch(finishedRefresh, /loadSnapshot/u);
  assert.equal(
    [...finishedRefresh.matchAll(/readScanReadinessWithin\(workspace\.case\.id, acceptReadiness\)/gu)].length,
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
