import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import { shouldAutomaticallyPrepareRuntime } from "../../src/runtimeFirstLaunch.ts";
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
  canRetry = phase === "idle" || phase === "failed" || phase === "cancelled",
): ManagedRuntimeSetupStatus => ({
  phase,
  active: phase !== "idle" && !["completed", "failed", "cancelled"].includes(phase),
  prerequisiteRepairActive: false,
  cancelRequested: false,
  receivedBytes: 0,
  resumedFromBytes: 0,
  canCancel: false,
  canRetry,
  detail: "test-only setup detail",
});

test("the native workspace stays available while product-owned scan tools prepare in the background", () => {
  for (const phase of ["not_installed", "installed", "stopped"]) {
    assert.equal(
      shouldAutomaticallyPrepareRuntime("native", runtime(phase), status("idle"), false, false),
      false,
      `${phase} waits until authoritative setup status is loaded`,
    );
    assert.equal(
      shouldAutomaticallyPrepareRuntime("native", runtime(phase), status("idle"), true, false),
      true,
      `${phase} starts background preparation after status loads`,
    );
  }

  const app = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const shell = readFileSync(new URL("../../src/components/AppShell.tsx", import.meta.url), "utf8");
  assert.match(app, /return \([\s\S]*?<AppShell[\s\S]*?>[\s\S]*?\{content\}[\s\S]*?<\/AppShell>/u);
  assert.match(app, /<StartPage[\s\S]*?setup=\{[\s\S]*?<RuntimeSetupAssistant/u);
  assert.match(shell, /mode === "native" && runtime && !runtime\.available/u);
  assert.doesNotMatch(app, /RuntimeFirstLaunch|shouldShowRuntimeFirstLaunch|showRuntimeFirstLaunch/u);
  assert.equal(
    existsSync(new URL("../../src/components/RuntimeFirstLaunch.tsx", import.meta.url)),
    false,
    "the obsolete full-screen setup component must not remain available for reuse",
  );
});

test("automatic runtime preparation is single-flight and does not loop after a failed action", () => {
  const missing = runtime("not_installed");
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, undefined, false, false), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, undefined, true, false), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("idle"), true, true), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("prerequisite"), true, false), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("failed"), true, false), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("completed"), true, false), true);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("completed", true), true, false), true);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("idle", false), true, false), true);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("completed"), true, true), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", runtime("corrupt"), status("idle"), true, false), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("demo", missing, status("idle"), true, false), false);
  assert.equal(
    shouldAutomaticallyPrepareRuntime("native", runtime("not_installed", false, "none"), status("idle"), true, false),
    false,
  );
  assert.match(
    readFileSync(new URL("../../src/runtimeFirstLaunch.ts", import.meta.url), "utf8"),
    /!isManagedRuntimePackageAdmissionFailure\(status\)/u,
    "automatic preparation must stop only for an exact package admission failure",
  );
});

test("automatic preparation excludes exact package admission failures, not every false canRetry flag", () => {
  const missing = runtime("not_installed");
  const packageFailure: ManagedRuntimeSetupStatus = {
    ...status("failed", false),
    failureReason: "packaged_runtime_verification_failed",
  };

  assert.equal(
    shouldAutomaticallyPrepareRuntime("native", missing, packageFailure, true, false),
    false,
  );
  assert.equal(
    shouldAutomaticallyPrepareRuntime("native", runtime("stopped"), status("completed", false), true, false),
    true,
    "a later stopped managed runtime must reconcile after a completed setup status",
  );
});

test("a managed runtime that is already starting is never started again automatically", () => {
  const starting = runtime("starting");

  for (const setupStatus of [undefined, status("idle"), status("completed")]) {
    assert.equal(
      shouldAutomaticallyPrepareRuntime("native", starting, setupStatus, true, false),
      false,
    );
  }
});

test("App keeps automatic preparation behind the visible shell", () => {
  const source = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");

  assert.match(source, /shouldAutomaticallyPrepareRuntime\([\s\S]*runtimeSetupStatusLoaded[\s\S]*automaticRuntimeSetupAttempted\.current/u);
  assert.match(source, /automaticRuntimeSetupAttempted\.current = true;[\s\S]*setupManagedRuntime\(\{ automatic: true \}\)/u);
  assert.match(source, /snapshot\.runtime\.available === true[\s\S]*automaticRuntimeSetupAttempted\.current = false/u);
  assert.match(source, /const applyStatusResult[\s\S]*setRuntimeSetupStatusLoaded\(true\)/u);
  assert.match(source, /runtimeSetupStatusReadCoalescer\.read\([\s\S]*getManagedRuntimeSetupStatus\(\)/u);
  assert.doesNotMatch(
    source,
    /catch[\s\S]{0,400}setRuntimeSetupStatusLoaded\(true\)/u,
    "a failed status read must not authorize an automatic setup attempt",
  );
  assert.doesNotMatch(source, /runtimeAutomaticAttemptFailed/u);
  assert.doesNotMatch(source, /repairManagedRuntimePrerequisite|runtime-repair/u);
});

test("runtime truth refreshes on focus and visibility even when no scan is active", () => {
  const source = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const runtimeFocusEffect = source.slice(
    source.indexOf("const reconcileRuntime = () =>"),
    source.indexOf("const reconcileActiveScan = () =>"),
  );

  assert.match(runtimeFocusEffect, /refreshManagedRuntimeSetupStatus\(\)/u);
  assert.match(runtimeFocusEffect, /if \(!activeScanCaseId\) void refreshRuntimeSnapshot\(\)/u);
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
