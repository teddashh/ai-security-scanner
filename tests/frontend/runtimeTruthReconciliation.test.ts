import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const appSource = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");
const scannerSource = readFileSync(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");

test("initial and recurring snapshot truth reads are bounded and expose unavailability", () => {
  const loadSnapshot = appSource.slice(
    appSource.indexOf("const loadSnapshot ="),
    appSource.indexOf("const refreshRuntimeSnapshot ="),
  );

  assert.match(loadSnapshot, /readTimeoutMs = RUNTIME_TRUTH_READ_TIMEOUT_MS/u);
  assert.match(loadSnapshot, /settleReadOnlyWithin\(snapshotRead, readTimeoutMs\)/u);
  assert.match(loadSnapshot, /boundedSnapshotRead\.outcome === "timed_out"[\s\S]*throw new Error/u);
  assert.match(loadSnapshot, /catch \(error\)[\s\S]*setSnapshotRefreshUnavailable\(true\)/u);
  assert.match(appSource, /useEffect\(\(\) => \{\s*void loadSnapshot\(\);/u);

  assert.match(loadSnapshot, /readScanReadinessWithin\([\s\S]*readinessCaseId,[\s\S]*acceptReadiness,[\s\S]*readTimeoutMs/u);
  assert.match(loadSnapshot, /setScanReadiness\(undefined\);[\s\S]*setScanReadinessErrorCaseId\(readinessCaseId\)/u);
  assert.match(loadSnapshot, /snapshotReadCoalescer\.read\([\s\S]*scannerService\.getSnapshot\(caseId\)/u);
  assert.match(loadSnapshot, /boundedSnapshotRead\.outcome === "timed_out"[\s\S]*snapshotRead\.then[\s\S]*applySnapshotResult\(lateResult\)/u);
  assert.match(loadSnapshot, /applySnapshotResult[\s\S]*setSnapshotRefreshUnavailable\(false\)/u);
});

test("every App readiness read uses one bounded helper and keeps existing error paths", () => {
  const helper = appSource.slice(
    appSource.indexOf("const readScanReadinessWithin ="),
    appSource.indexOf("const loadSnapshot ="),
  );
  assert.match(helper, /scanReadinessReadCoalescer\.read\([\s\S]*scannerService\.getScanReadiness\(caseId\)[\s\S]*settleReadOnlyWithin\(readinessRead, timeoutMs\)/u);
  assert.match(helper, /observation\.outcome === "timed_out"[\s\S]*throw new Error/u);
  assert.match(helper, /readinessRead\.then\(onLateResult/u);
  assert.equal(
    [...appSource.matchAll(/scannerService\.getScanReadiness\(/gu)].length,
    1,
    "App must not call readiness IPC outside the bounded helper",
  );

  for (const boundedCall of [
    "readScanReadinessWithin(workspace.case.id, acceptReadiness)",
    "readScanReadinessWithin(caseId, acceptReadiness)",
  ]) assert.ok(appSource.includes(boundedCall), boundedCall);

  const selectCase = appSource.slice(appSource.indexOf("const selectCase ="), appSource.indexOf("const retryScanReadiness ="));
  assert.match(selectCase, /readScanReadinessWithin\(caseId, acceptReadiness\)/u);
  assert.match(selectCase, /setScanReadinessErrorCaseId\(caseId\)/u);
  assert.match(selectCase, /finally[\s\S]*setLoading\(false\)/u);
  const retry = appSource.slice(appSource.indexOf("const retryScanReadiness ="), appSource.indexOf("const createCase ="));
  assert.match(retry, /readScanReadinessWithin\(caseId, acceptReadiness\)/u);
  assert.match(retry, /setScanReadinessErrorCaseId\(caseId\)/u);
  assert.match(retry, /finally[\s\S]*setBusyAction\(undefined\)/u);
});

test("a never-settling runtime status read releases single-flight without inventing terminal state", () => {
  const refreshStatus = appSource.slice(
    appSource.indexOf("const refreshManagedRuntimeSetupStatus ="),
    appSource.indexOf("const runtimeSetupTerminal ="),
  );

  assert.match(refreshStatus, /runtimeSetupStatusReadCoalescer\.read\([\s\S]*getManagedRuntimeSetupStatus\(\)[\s\S]*settleReadOnlyWithin\([\s\S]*statusRead,[\s\S]*RUNTIME_TRUTH_READ_TIMEOUT_MS/u);
  const timeoutBranch = refreshStatus.slice(
    refreshStatus.indexOf('boundedStatusRead.outcome === "timed_out"'),
    refreshStatus.indexOf('boundedStatusRead.outcome === "failed"'),
  );
  assert.match(timeoutBranch, /return undefined/u);
  assert.doesNotMatch(timeoutBranch, /setRuntimeSetup\(|phase|active:/u);
  assert.match(timeoutBranch, /statusRead\.then\([\s\S]*applyStatusResult\(lateResult\)/u);
  assert.match(refreshStatus, /runtimeSetupStatusRefreshInFlight\.current === refresh[\s\S]*= undefined/u);
});

test("setup command timeout is an unknown outcome reconciled through authoritative status", () => {
  const setup = appSource.slice(
    appSource.indexOf("const setupManagedRuntime ="),
    appSource.indexOf("useEffect(() => {", appSource.indexOf("const setupManagedRuntime =")),
  );
  const nativeSetup = scannerSource.slice(
    scannerSource.indexOf("async setupManagedRuntime"),
    scannerSource.indexOf("async getManagedRuntimeSetupStatus"),
  );

  assert.match(setup, /observePromiseWithin\([\s\S]*scannerService\.setupManagedRuntime\(\)[\s\S]*RUNTIME_SETUP_COMMAND_UI_TIMEOUT_MS/u);
  assert.doesNotMatch(nativeSetup, /catch/u, "native invoke rejection must reach App reconciliation");
  assert.match(setup, /commandObservation\.outcome === "timed_out"[\s\S]*await reconcileUnknownSetupOutcome\(\);[\s\S]*return;/u);
  assert.match(setup, /setupActive[\s\S]*retainActiveSetup\(\)[\s\S]*return "active"/u);
  assert.match(setup, /currentRequestWasObserved && isManagedRuntimeSetupTerminal\(setupStatus\)[\s\S]*return "terminal"/u);
  assert.match(setup, /return "unconfirmed"/u);

  const timeoutBranch = setup.slice(
    setup.indexOf('commandObservation.outcome === "timed_out"'),
    setup.indexOf('commandObservation.outcome === "failed"'),
  );
  assert.doesNotMatch(timeoutBranch, /pushToast|recordTechnicalError/u);

  const rejectionCatch = setup.slice(setup.indexOf("} catch (error)"), setup.indexOf("} finally"));
  assert.match(rejectionCatch, /reconcileUnknownSetupOutcome\(\)[\s\S]*reconciliation !== "unconfirmed"[\s\S]*return/u);
  assert.match(rejectionCatch, /pushToast/u, "only an unconfirmed real rejection becomes retryable failure feedback");
  assert.match(setup, /!keepFollowingAuthoritativeOperation[\s\S]*setRuntimeSetupAdmissionPending\(false\)[\s\S]*setRuntimeSetupCommandPolling\(false\)/u);
});

test("a completed setup claims ready only after the refreshed runtime is authoritatively available", () => {
  const loadSnapshot = appSource.slice(
    appSource.indexOf("const loadSnapshot ="),
    appSource.indexOf("const refreshRuntimeSnapshot ="),
  );
  const setup = appSource.slice(
    appSource.indexOf("const setupManagedRuntime ="),
    appSource.indexOf("useEffect(() => {", appSource.indexOf("const setupManagedRuntime =")),
  );

  assert.match(loadSnapshot, /return await applySnapshotResult\(boundedSnapshotRead\.value\)/u);
  assert.match(loadSnapshot, /catch \(error\)[\s\S]*return undefined/u);
  assert.match(setup, /const refreshedSnapshot = await refreshRuntimeSnapshot\(\)/u);
  assert.match(setup, /const runtimeReady = refreshedSnapshot\?\.runtime\?\.available === true/u);
  assert.match(setup, /const completedAndReady = completed && runtimeReady/u);
  assert.match(setup, /tone: completedAndReady \? "success" : "warning"/u);
  assert.match(setup, /completedAndReady[\s\S]*The private scan engine is ready[\s\S]*Setup finished; checking availability/u);
  assert.match(setup, /has not confirmed that the scan engine is available/u);
});
