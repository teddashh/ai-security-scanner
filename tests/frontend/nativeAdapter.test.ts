import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  stdin: {
    contents: 'export { adaptDeclaredWebServiceMetadata, adaptManagedRuntimePrerequisiteRepairResult, adaptManagedRuntimeSetupStatus } from "./src/services/nativeAdapter.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "native-adapter-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const source = bundled.outputFiles[0]?.text;
assert.ok(source, "the native adapter test bundle should contain JavaScript");
const {
  adaptDeclaredWebServiceMetadata,
  adaptManagedRuntimePrerequisiteRepairResult,
  adaptManagedRuntimeSetupStatus,
} = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
);

const runtimeSetupDto = (overrides: Record<string, unknown> = {}) => ({
  phase: "failed",
  active: false,
  prerequisite_repair_active: false,
  cancel_requested: false,
  received_bytes: 0,
  total_bytes: null,
  progress_percent: null,
  resumed_from_bytes: 0,
  can_cancel: false,
  can_retry: true,
  failure_reason: "windows_wsl_optional_feature_disabled",
  next_action: "enable_wsl_optional_features",
  detail: "bounded technical detail",
  ...overrides,
});

test("managed runtime setup adapter preserves the exact failed recovery contract", () => {
  assert.deepEqual(adaptManagedRuntimeSetupStatus(runtimeSetupDto()), {
    phase: "failed",
    active: false,
    prerequisiteRepairActive: false,
    cancelRequested: false,
    receivedBytes: 0,
    totalBytes: undefined,
    progressPercent: undefined,
    resumedFromBytes: 0,
    canCancel: false,
    canRetry: true,
    failureReason: "windows_wsl_optional_feature_disabled",
    nextAction: "enable_wsl_optional_features",
    detail: "bounded technical detail",
  });
});

test("managed runtime setup adapter hides recovery fields outside failed or when mismatched", () => {
  const unwinding = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    phase: "prerequisite",
    active: true,
  }));
  assert.equal(unwinding.failureReason, undefined);
  assert.equal(unwinding.nextAction, undefined);

  const mismatched = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    next_action: "install_wsl",
  }));
  assert.equal(mismatched.failureReason, undefined);
  assert.equal(mismatched.nextAction, undefined);
});

test("managed runtime prerequisite repair adapter accepts only bounded terminal results", () => {
  assert.deepEqual(adaptManagedRuntimePrerequisiteRepairResult({
    outcome: "completed",
    restart_required: true,
    detail: "Windows needs a restart",
  }), {
    outcome: "completed",
    restartRequired: true,
    detail: "Windows needs a restart",
  });
  assert.deepEqual(adaptManagedRuntimePrerequisiteRepairResult({
    outcome: "cancelled",
    restart_required: true,
    detail: "No change was made",
  }), {
    outcome: "cancelled",
    restartRequired: false,
    detail: "No change was made",
  });
  const malformed = adaptManagedRuntimePrerequisiteRepairResult({
    outcome: "surprise",
    restart_required: true,
    detail: `unsafe\0${"x".repeat(1_100)}`,
  });
  assert.equal(malformed.outcome, "failed");
  assert.equal(malformed.restartRequired, false);
  assert.equal(malformed.detail, "Windows prerequisite repair returned no safe detail");
});

test("declared website metadata adapts a bounded preset", () => {
  assert.deepEqual(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "https", port: 8443, path: "/login" },
  }), { protocol: "https", port: 8443, path: "/login" });
});

test("declared website metadata rejects malformed or query-bearing values", () => {
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "https", port: 443, path: "/?token=secret" },
  }), undefined);
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "ftp", port: 21, path: "/" },
  }), undefined);
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "http", port: 0, path: "/" },
  }), undefined);
});
