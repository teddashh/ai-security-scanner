import assert from "node:assert/strict";
import test from "node:test";

import {
  catalogEngineIds,
  engineNextStepFor,
  engineOutcomeCopy,
  engineOutcomeFor,
} from "../../src/scanPresentation.ts";
import type { EngineRun } from "../../src/types.ts";

const engine = (overrides: Partial<EngineRun> = {}): EngineRun => ({
  id: "engine-run-1",
  engineId: "trivy",
  engineName: "raw implementation name",
  category: "raw category",
  version: "1.0.0",
  digest: "sha256:redacted",
  warnings: [],
  status: "completed",
  progress: 100,
  phase: "completed",
  assetIds: ["asset-1"],
  rawArtifactCount: 1,
  findingCount: 0,
  resumable: false,
  ...overrides,
});

test("all 21 catalog engines have plain-language English and Traditional Chinese outcomes", () => {
  assert.equal(catalogEngineIds.length, 21);
  assert.deepEqual(Object.keys(engineOutcomeCopy).sort(), [...catalogEngineIds].sort());
  for (const engineId of catalogEngineIds) {
    const outcome = engineOutcomeCopy[engineId];
    assert.ok(outcome.en.trim(), `${engineId} needs English outcome copy`);
    assert.ok(outcome.zhTW.trim(), `${engineId} needs Traditional Chinese outcome copy`);
    assert.doesNotMatch(outcome.en, new RegExp(`^${engineId}$`, "iu"));
  }
});

test("unknown scanner identities never leak into the first-layer fallback", () => {
  const outcome = engineOutcomeFor(engine({ engineId: "future-engine", engineName: "do-not-render" }));
  assert.deepEqual(outcome, { en: "Security check result", zhTW: "安全檢查結果" });
  assert.doesNotMatch(`${outcome.en}${outcome.zhTW}`, /future-engine|do-not-render/u);
});

test("every check state provides an actionable bilingual next step without raw errors", () => {
  for (const status of ["pending", "running", "paused", "completed", "partial", "failed", "not_executed", "cancelled"] as const) {
    const action = engineNextStepFor(engine({
      status,
      phase: status,
      errorCode: status === "failed" ? "opaque-backend-error" : undefined,
    }));
    assert.ok(action.en.trim(), `${status} needs English action copy`);
    assert.ok(action.zhTW.trim(), `${status} needs Traditional Chinese action copy`);
    assert.doesNotMatch(`${action.en}${action.zhTW}`, /opaque-backend-error/u);
  }
});

test("known setup failures lead to the matching safe next step", () => {
  const target = engineNextStepFor(engine({ status: "not_executed", errorCode: "no_compatible_authorized_assets" }));
  const tools = engineNextStepFor(engine({ status: "failed", errorCode: "execution_failed" }));
  assert.match(target.en, /scan setup/u);
  assert.match(target.zhTW, /掃描設定/u);
  assert.match(tools.en, /scan-tool setup/u);
  assert.match(tools.zhTW, /掃描工具設定/u);
});
