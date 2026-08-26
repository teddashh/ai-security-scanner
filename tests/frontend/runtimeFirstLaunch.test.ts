import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  shouldAutomaticallyPrepareRuntime,
  shouldShowRuntimeFirstLaunch,
} from "../../src/runtimeFirstLaunch.ts";
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

const status = (phase: ManagedRuntimeSetupStatus["phase"]): ManagedRuntimeSetupStatus => ({
  phase,
  active: phase !== "idle" && !["completed", "failed", "cancelled"].includes(phase),
  prerequisiteRepairActive: false,
  cancelRequested: false,
  receivedBytes: 0,
  resumedFromBytes: 0,
  canCancel: false,
  canRetry: phase === "failed" || phase === "cancelled",
  detail: "test-only setup detail",
});

test("a release-managed runtime is prepared before the native workspace appears", () => {
  for (const phase of ["not_installed", "installed", "stopped", "starting"]) {
    assert.equal(
      shouldAutomaticallyPrepareRuntime("native", runtime(phase), status("idle"), false, false),
      false,
      phase,
    );
    assert.equal(
      shouldAutomaticallyPrepareRuntime("native", runtime(phase), status("idle"), true, false),
      true,
      phase,
    );
  }

  assert.equal(shouldShowRuntimeFirstLaunch("native", runtime("not_installed")), true);
  assert.equal(shouldShowRuntimeFirstLaunch("native", runtime("installed")), true);
  assert.equal(shouldShowRuntimeFirstLaunch("native", runtime("stopped")), false);
  assert.equal(shouldShowRuntimeFirstLaunch("native", runtime("starting")), false);
  assert.equal(shouldShowRuntimeFirstLaunch("native", runtime("running", true)), false);
  assert.equal(shouldShowRuntimeFirstLaunch("demo", runtime("not_installed")), false);
  assert.equal(
    shouldShowRuntimeFirstLaunch("native", runtime("unavailable", false, "none")),
    false,
  );
});

test("existing cases and results stay accessible while scan tools start or need attention", () => {
  assert.equal(shouldShowRuntimeFirstLaunch("native", runtime("not_installed"), true), false);
  assert.equal(shouldShowRuntimeFirstLaunch("native", runtime("installed"), true), false);
  assert.equal(shouldShowRuntimeFirstLaunch("native", runtime("corrupt"), false), false);
  assert.equal(
    shouldAutomaticallyPrepareRuntime("native", runtime("stopped"), status("idle"), false, false),
    false,
  );
  assert.equal(
    shouldAutomaticallyPrepareRuntime("native", runtime("stopped"), status("idle"), true, false),
    true,
  );
});

test("automatic first-launch preparation is single-flight and never repeats a failed action", () => {
  const missing = runtime("not_installed");
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, undefined, false, false), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, undefined, true, false), true);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("idle"), true, true), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("prerequisite"), true, false), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("failed"), true, false), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("completed"), true, false), true);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", missing, status("completed"), true, true), false);
  assert.equal(shouldAutomaticallyPrepareRuntime("native", runtime("corrupt"), status("idle"), true, false), false);
});

test("first-launch copy promises automatic checking without an in-app elevation loop", () => {
  const source = readFileSync(
    new URL("../../src/components/RuntimeFirstLaunch.tsx", import.meta.url),
    "utf8",
  );

  for (const phrase of [
    "No action is needed",
    "目前不需要操作",
    "one clear Microsoft setup step",
    "一個清楚的 Microsoft 設定步驟",
    "preparation will continue automatically",
    "就會自動接著完成",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.doesNotMatch(source, /administrator|系統管理員|approval|UAC|prerequisite|gate|contract/iu);
  assert.match(source, /waitingForAutomaticCheck[\s\S]*role="status"/u);
  assert.match(source, /!statusLoaded[\s\S]*status\?\.active === true/u);
  assert.doesNotMatch(source, /status\.phase === "completed" && runtime\?\.available !== true/u);
});

test("the native app checks installed tools automatically before rendering its workspace", () => {
  const source = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");

  assert.match(source, /shouldAutomaticallyPrepareRuntime\([\s\S]*runtimeSetupStatusLoaded[\s\S]*automaticRuntimeSetupAttempted\.current/u);
  assert.match(source, /automaticRuntimeSetupAttempted\.current = true;[\s\S]*setupManagedRuntime\(\{ automatic: true \}\)/u);
  assert.match(source, /snapshot\.runtime\.available === true[\s\S]*automaticRuntimeSetupAttempted\.current = false/u);
  assert.match(source, /getManagedRuntimeSetupStatus\(\)[\s\S]*setRuntimeSetupStatusLoaded\(true\)/u);
  assert.match(source, /snapshot !== undefined[\s\S]*shouldShowRuntimeFirstLaunch\([\s\S]*snapshot\.cases\.length > 0/u);
  assert.match(source, /showRuntimeFirstLaunch \? \([\s\S]*<RuntimeFirstLaunch/u);
  assert.match(source, /if \(!automatic && !result\.data\.accepted && !cancelled\)/u);
  assert.match(source, /if \(!result\.data\.accepted && setupResult\.data\.phase === "idle"\) \{[\s\S]*setRuntimeAutomaticAttemptFailed\(true\)/u);
  assert.doesNotMatch(source, /if \(automatic && !result\.data\.accepted && setupResult\.data\.phase === "idle"\)/u);
  assert.doesNotMatch(source, /repairManagedRuntimePrerequisite|runtime-repair/u);
});
