import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import type { EngineRun } from "../../src/types.ts";

const bundled = await build({
  entryPoints: [fileURLToPath(new URL("../../src/settledSkippedChecks.ts", import.meta.url))],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const bundledSource = bundled.outputFiles[0]?.text;
assert.ok(bundledSource, "settled skipped checks bundle should contain JavaScript");
const { settledSkipReasonCodes, isSettledSkippedCheck } = await import(
  `data:text/javascript;base64,${Buffer.from(bundledSource).toString("base64")}`
);

const rustReasonCodes = (constantName: string): string[] => {
  const rust = readFileSync(new URL("../../src-tauri/src/case_service.rs", import.meta.url), "utf8");
  const marker = `pub const ${constantName}: &[&str] = &[`;
  const start = rust.indexOf(marker);
  assert.ok(start >= 0, `${constantName} was not found in case_service.rs`);
  const body = rust.slice(start + marker.length);
  const end = body.indexOf("];");
  assert.ok(end > 0, `${constantName} has no closing bracket`);
  const codes = [...body.slice(0, end).matchAll(/"([a-z0-9_]+)"/gu)].map((match) => match[1]!);
  assert.ok(codes.length > 0, `${constantName} is empty`);
  return codes;
};

const engine = (overrides: Partial<EngineRun> = {}): EngineRun => ({
  id: "engine-run-1",
  engineId: "mcp-armor",
  engineName: "raw implementation name",
  category: "ai_mcp_configuration",
  taskKind: { kind: "catalog_engine" },
  warnings: [],
  status: "not_executed",
  progress: 0,
  phase: "not_executed",
  assetIds: ["asset-1"],
  rawArtifactCount: 0,
  savedResultArtifactCount: 0,
  findingCount: 0,
  resumable: false,
  errorCode: "mcp_configuration_absent",
  ...overrides,
});

test("the settled-skip reason codes mirror SETTLED_SKIP_REASON_CODES in case_service.rs exactly", () => {
  const codes = rustReasonCodes("SETTLED_SKIP_REASON_CODES");
  assert.deepEqual([...settledSkipReasonCodes].sort(), [...codes].sort());
});

test("every settled-skip reason code is also a planner not-executed reason code", () => {
  const plannerCodes = new Set(rustReasonCodes("PLANNER_NOT_EXECUTED_REASON_CODES"));
  for (const code of settledSkipReasonCodes) {
    assert.ok(plannerCodes.has(code), `${code} is missing from PLANNER_NOT_EXECUTED_REASON_CODES`);
  }
});

test("mcp_configuration_discovery_incomplete is deliberately excluded from the settled-skip codes", () => {
  assert.equal(settledSkipReasonCodes.has("mcp_configuration_discovery_incomplete"), false);
});

test("isSettledSkippedCheck is true for a not-executed catalog engine with a settled-skip reason", () => {
  assert.equal(
    isSettledSkippedCheck(engine({ errorCode: "mcp_configuration_absent" })),
    true,
  );
  assert.equal(
    isSettledSkippedCheck(
      engine({ engineId: "agentic-radar", errorCode: "engine_release_unavailable" }),
    ),
    true,
  );
});

test("isSettledSkippedCheck is false for a completed check, an unresolved discovery gap, a missing error code, or a non-catalog task", () => {
  assert.equal(
    isSettledSkippedCheck(engine({ status: "completed" })),
    false,
    "a completed check is not a skip",
  );
  assert.equal(
    isSettledSkippedCheck(engine({ errorCode: "mcp_configuration_discovery_incomplete" })),
    false,
    "an unresolved discovery gap keeps its unchanged behavior",
  );
  assert.equal(
    isSettledSkippedCheck(engine({ errorCode: undefined })),
    false,
    "a missing error code is not a settled skip",
  );
  assert.equal(
    isSettledSkippedCheck(engine({
      taskKind: { kind: "built_in_localhost_tcp", port: 22, timeoutMs: 500, payloadBytes: 0 },
    })),
    false,
    "a non-catalog-engine task kind is never a settled skip",
  );
});
