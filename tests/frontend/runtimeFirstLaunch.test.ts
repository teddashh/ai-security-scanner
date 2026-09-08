import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import {
  cloneRuntimeDeferredScanInput,
  shouldAutomaticallyPrepareRuntime,
  shouldPrepareRuntimeBeforeScanAction,
  shouldStartRuntimePreparedScan,
  shouldShowRuntimeSetupAssistant,
} from "../../src/runtimeFirstLaunch.ts";
import type { StartScanInput } from "../../src/services/scanner.ts";
import type { AppSnapshot, ManagedRuntimeSetupStatus } from "../../src/types.ts";

const runtime = (
  phase: string,
  available = false,
  provider = "managed_local",
): NonNullable<AppSnapshot["runtime"]> => ({
  provider,
  available,
  phase,
  detail: "test-only runtime detail",
});

const status = (
  phase: ManagedRuntimeSetupStatus["phase"],
  active = !["idle", "completed", "failed", "cancelled"].includes(phase),
): ManagedRuntimeSetupStatus => ({
  phase,
  active,
  prerequisiteRepairActive: false,
  cancelRequested: false,
  receivedBytes: 0,
  resumedFromBytes: 0,
  canCancel: false,
  canRetry: true,
  detail: "test-only setup detail",
});

test("passive first launch never authorizes managed-runtime preparation", () => {
  for (const runtimePhase of ["not_installed", "installed", "stopped", "starting", "corrupt"]) {
    for (const setupStatus of [undefined, status("idle"), status("completed"), status("failed")]) {
      assert.equal(
        shouldAutomaticallyPrepareRuntime(
          "native",
          runtime(runtimePhase),
          setupStatus,
          true,
          false,
        ),
        false,
        `${runtimePhase}/${setupStatus?.phase ?? "unloaded"} stays passive`,
      );
    }
  }

  assert.equal(
    shouldAutomaticallyPrepareRuntime("demo", runtime("not_installed"), status("idle"), true, false),
    false,
  );
});

test("the Start-page setup assistant is contextual instead of first-launch work", () => {
  const firstLaunch = {
    mode: "native" as const,
    runtimeAvailable: false,
    status: status("idle"),
    requestPending: false,
    selectedScanNeedsSetup: false,
  };

  assert.equal(shouldShowRuntimeSetupAssistant(firstLaunch), false);
  assert.equal(shouldShowRuntimeSetupAssistant({ ...firstLaunch, status: undefined }), false);
  assert.equal(shouldShowRuntimeSetupAssistant({ ...firstLaunch, selectedScanNeedsSetup: true }), true);
  assert.equal(shouldShowRuntimeSetupAssistant({ ...firstLaunch, requestPending: true }), true);
  assert.equal(shouldShowRuntimeSetupAssistant({ ...firstLaunch, status: status("download") }), true);
  assert.equal(shouldShowRuntimeSetupAssistant({ ...firstLaunch, status: status("failed") }), true);
  assert.equal(shouldShowRuntimeSetupAssistant({ ...firstLaunch, status: status("cancelled") }), true);
  assert.equal(shouldShowRuntimeSetupAssistant({ ...firstLaunch, status: status("completed") }), true);
  assert.equal(shouldShowRuntimeSetupAssistant({
    ...firstLaunch,
    runtimeAvailable: true,
    status: status("completed"),
  }), false);
  assert.equal(shouldShowRuntimeSetupAssistant({ ...firstLaunch, mode: "demo" }), true);
});

test("only an explicit Start action with a missing managed runtime admits setup before scan", () => {
  const selectedScanAction = {
    mode: "native" as const,
    runtime: runtime("not_installed"),
    status: status("idle"),
    scanActionRequested: true,
  };

  assert.equal(shouldPrepareRuntimeBeforeScanAction(selectedScanAction), true);
  assert.equal(shouldPrepareRuntimeBeforeScanAction({
    ...selectedScanAction,
    scanActionRequested: false,
  }), false);
  assert.equal(shouldPrepareRuntimeBeforeScanAction({
    ...selectedScanAction,
    runtime: runtime("ready", true),
  }), false);
  assert.equal(shouldPrepareRuntimeBeforeScanAction({
    ...selectedScanAction,
    mode: "demo",
  }), false);
  assert.equal(shouldPrepareRuntimeBeforeScanAction({
    ...selectedScanAction,
    runtime: runtime("starting"),
  }), false);
  assert.equal(shouldPrepareRuntimeBeforeScanAction({
    ...selectedScanAction,
    status: status("download"),
  }), false);
  assert.equal(shouldPrepareRuntimeBeforeScanAction({
    ...selectedScanAction,
    status: {
      ...status("failed"),
      canRetry: false,
      failureReason: "packaged_runtime_verification_failed",
    },
  }), false);
});

test("a runtime-deferred start keeps the exact reviewed scan input", () => {
  const input: StartScanInput = {
    caseId: "case-a",
    engineIds: ["nuclei"],
    authorization: {
      assetIds: ["asset-a"],
      modes: ["active_external"],
      confirmation: "confirmed exact public target",
      externalScope: {
        target: "example.test",
        ports: [443],
        protocol: "https",
        activity: "active_external",
        ratePolicy: { requestsPerSecond: 3, concurrency: 2, timeoutSeconds: 10 },
        templatePolicy: {
          revision: "nuclei-templates@test",
          allowedTemplateIds: ["one", "two"],
          allowHeadless: false,
          allowOutOfBand: false,
          allowFuzzing: false,
          allowFileUpload: false,
          allowDenialOfService: false,
          allowCredentialAttacks: false,
        },
        assertedAuthority: "user-confirmed",
        allowSensitiveNetworks: false,
      },
    },
  };
  const saved = cloneRuntimeDeferredScanInput(input);

  input.engineIds?.push("httpx");
  input.authorization?.assetIds.push("asset-b");
  input.authorization?.modes.push("inventory");
  input.authorization?.externalScope?.ports.push(8443);
  input.authorization?.externalScope?.templatePolicy.allowedTemplateIds.push("three");

  assert.deepEqual(saved.engineIds, ["nuclei"]);
  assert.deepEqual(saved.authorization?.assetIds, ["asset-a"]);
  assert.deepEqual(saved.authorization?.modes, ["active_external"]);
  assert.deepEqual(saved.authorization?.externalScope?.ports, [443]);
  assert.deepEqual(
    saved.authorization?.externalScope?.templatePolicy.allowedTemplateIds,
    ["one", "two"],
  );
});

test("a runtime-deferred start deep-copies every combined authorization and engine route", () => {
  const input: StartScanInput = {
    caseId: "environment-a",
    authorizations: [
      {
        assetIds: ["repo-a"],
        modes: ["local_artifact"],
        confirmation: "selected local copy",
      },
      {
        assetIds: ["site-a"],
        modes: ["active_external"],
        confirmation: "authorized site",
        externalScope: {
          target: "site.example.test",
          ports: [443],
          protocol: "https",
          activity: "active_external",
          ratePolicy: { requestsPerSecond: 3, concurrency: 2, timeoutSeconds: 10 },
          templatePolicy: {
            revision: "nuclei-templates@test",
            allowedTemplateIds: ["one"],
            allowHeadless: false,
            allowOutOfBand: false,
            allowFuzzing: false,
            allowFileUpload: false,
            allowDenialOfService: false,
            allowCredentialAttacks: false,
          },
          assertedAuthority: "authorized site",
          allowSensitiveNetworks: false,
        },
      },
    ],
    engineAssetRoutes: [
      { engineId: "gitleaks", assetIds: ["repo-a"] },
      { engineId: "nuclei", assetIds: ["site-a"] },
    ],
  };
  const saved = cloneRuntimeDeferredScanInput(input);

  input.authorizations?.[0]?.assetIds.push("repo-b");
  input.authorizations?.[1]?.externalScope?.ports.push(8443);
  input.authorizations?.[1]?.externalScope?.templatePolicy.allowedTemplateIds.push("two");
  input.engineAssetRoutes?.[0]?.assetIds.push("repo-b");

  assert.deepEqual(saved.authorizations?.[0]?.assetIds, ["repo-a"]);
  assert.deepEqual(saved.authorizations?.[1]?.externalScope?.ports, [443]);
  assert.deepEqual(
    saved.authorizations?.[1]?.externalScope?.templatePolicy.allowedTemplateIds,
    ["one"],
  );
  assert.deepEqual(saved.engineAssetRoutes?.[0]?.assetIds, ["repo-a"]);
});

test("a prepared runtime starts only the same visible idle request", () => {
  const ready = {
    requestedPage: "coverage" as const,
    currentPage: "coverage" as const,
    requestedPageTransitionGeneration: 2,
    currentPageTransitionGeneration: 2,
    requestedCaseSelectionGeneration: 4,
    currentCaseSelectionGeneration: 4,
    requestedCaseId: "case-a",
    selectedCaseId: "case-a",
    workspaceCaseId: "case-a",
    runtimeAvailable: true,
    setupPhase: "completed" as const,
    activeScanWork: false,
  };
  assert.equal(shouldStartRuntimePreparedScan(ready), true);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, currentPage: "cases" }), false);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, currentPageTransitionGeneration: 3 }), false);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, currentCaseSelectionGeneration: 5 }), false);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, selectedCaseId: "case-b" }), false);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, workspaceCaseId: "case-b" }), false);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, runtimeAvailable: false }), false);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, setupPhase: "failed" }), false);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, setupPhase: "cancelled" }), false);
  assert.equal(shouldStartRuntimePreparedScan({ ...ready, activeScanWork: true }), false);
});

test("App prepares before start_scan and consumes one matching completion", () => {
  const app = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const preparation = app.indexOf("shouldPrepareRuntimeBeforeScanAction({");
  const scanCommand = app.indexOf("() => scannerService.startScan(input)", preparation);
  assert.notEqual(preparation, -1);
  assert.notEqual(scanCommand, -1);
  assert.ok(preparation < scanCommand, "runtime preparation must be decided before start_scan");
  assert.match(app, /shouldPrepareRuntimeBeforeScanAction\(\{[\s\S]*pendingRuntimeScanStart\.current = \{[\s\S]*cloneRuntimeDeferredScanInput\(input\)[\s\S]*runtimeSetupCommandGeneration\.current \+ 1[\s\S]*setupManagedRuntime\(\)[\s\S]*return false/u);
  assert.match(app, /pageTransitionGeneration\.current === pageGenerationAtStart/u);
  assert.match(app, /caseSelectionBarrierRef\.current\.generation === caseSelectionGenerationAtStart/u);
  assert.match(app, /refreshRuntimeSnapshotAfterCurrent/u);
  assert.match(app, /pending\.setupCommandGeneration[\s\S]*observed\.completion\.setupCommandGeneration[\s\S]*pendingRuntimeScanStart\.current = undefined[\s\S]*shouldStartRuntimePreparedScan\(\{[\s\S]*startScan\(pending\.input, \{ allowRuntimePreparation: false \}\)/u);
  assert.match(app, /activeScanWork: refreshedSnapshot\?\.workspace[\s\S]*hasActiveScanWork/u);
  assert.match(app, /const coverageRuntimePreparing = mode === "native"[\s\S]*runtimeSetupRequestPending \|\| runtimeSetupPolling/u);
  assert.match(app, /busy=\{busyAction === "connect-source"[\s\S]*\|\| coverageRuntimePreparing\}/u);
  assert.doesNotMatch(app, /scanActionRuntimeBlocker|shouldPrepareRuntimeAfterScanAction/u);
  assert.match(app, /runtimeSetupNotice=\{\([\s\S]*coverageRuntimePreparing[\s\S]*Preparing the tools this scan needs[\s\S]*will start automatically[\s\S]*<RuntimeSetupAssistant/u);
});

test("App has no passive setup effect and preserves explicit setup actions", () => {
  const app = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const assistant = readFileSync(
    new URL("../../src/components/RuntimeSetupAssistant.tsx", import.meta.url),
    "utf8",
  );
  const shell = readFileSync(new URL("../../src/components/AppShell.tsx", import.meta.url), "utf8");

  assert.doesNotMatch(app, /shouldAutomaticallyPrepareRuntime|automaticRuntimeSetupAttempted/u);
  assert.doesNotMatch(app, /setupManagedRuntime\(\{\s*automatic/u);
  assert.doesNotMatch(app, /const setupManagedRuntime = async \([^)]*automatic/u);
  assert.match(app, /const setupManagedRuntime = async \(\) => \{[\s\S]*scannerService\.setupManagedRuntime\(\)/u);

  assert.match(app, /onSetup=\{\(\) => void setupManagedRuntime\(\)\}/u);
  assert.match(app, /onSetupRuntime=\{\(\) => void setupManagedRuntime\(\)\}/u);
  assert.match(app, /onFixSetup=\{\(\) => \{[\s\S]*void setupManagedRuntime\(\)/u);
  assert.match(app, /shouldPrepareRuntimeBeforeScanAction\(\{[\s\S]*cloneRuntimeDeferredScanInput\(input\)/u);
  assert.match(assistant, /onClick=\{onSetup\}/u);
  assert.match(shell, /onClick=\{onSetupRuntime\}/u);
});

test("an idle unavailable runtime does not occupy the Start page before scan selection", () => {
  const app = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const shell = readFileSync(new URL("../../src/components/AppShell.tsx", import.meta.url), "utf8");

  assert.match(app, /const showStartRuntimeSetup = shouldShowRuntimeSetupAssistant\(\{/u);
  assert.match(app, /selectedScanNeedsSetup: startScannerSetupBlocker !== undefined/u);
  assert.match(app, /<StartPage[\s\S]*?setup=\{showStartRuntimeSetup \? \([\s\S]*?<RuntimeSetupAssistant/u);
  assert.match(shell, /mode === "native" && runtime && !runtime\.available/u);
  assert.doesNotMatch(app, /RuntimeFirstLaunch|shouldShowRuntimeFirstLaunch|showRuntimeFirstLaunch/u);
  assert.equal(
    existsSync(new URL("../../src/components/RuntimeFirstLaunch.tsx", import.meta.url)),
    false,
    "the obsolete full-screen setup component must not remain available for reuse",
  );
});

test("runtime truth refreshes on focus and visibility without starting setup", () => {
  const source = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const runtimeFocusEffect = source.slice(
    source.indexOf("const reconcileRuntime = () =>"),
    source.indexOf("const reconcileActiveScan = () =>"),
  );

  assert.match(runtimeFocusEffect, /refreshManagedRuntimeSetupStatus\(\)/u);
  assert.match(runtimeFocusEffect, /if \(!activeScanCaseId\) void refreshRuntimeSnapshot\(\)/u);
  assert.doesNotMatch(runtimeFocusEffect, /setupManagedRuntime/u);
  assert.match(runtimeFocusEffect, /window\.setInterval\(reconcileRuntime, RUNTIME_TRUTH_REFRESH_INTERVAL_MS\)/u);
  assert.match(runtimeFocusEffect, /window\.addEventListener\("focus", onWindowFocus\)/u);
  assert.match(runtimeFocusEffect, /document\.visibilityState === "visible"[\s\S]*reconcileRuntime\(\)/u);
  assert.match(runtimeFocusEffect, /window\.removeEventListener\("focus", onWindowFocus\)/u);
  assert.match(runtimeFocusEffect, /document\.removeEventListener\("visibilitychange", onVisibilityChange\)/u);
  assert.match(runtimeFocusEffect, /window\.clearInterval\(watchdog\)/u);
  assert.match(source, /if \(runtimeSetupStatusRefreshInFlight\.current\) return runtimeSetupStatusRefreshInFlight\.current/u);
  assert.match(source, /runtimeSetupStatusRefreshInFlight\.current === refresh/u);
  assert.match(source, /if \(runtimeSnapshotRefreshInFlight\.current\) return runtimeSnapshotRefreshInFlight\.current/u);
  assert.match(source, /runtimeSnapshotRefreshInFlight\.current === refresh/u);
});
