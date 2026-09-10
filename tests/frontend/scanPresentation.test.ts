import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import type { EngineRun } from "../../src/types.ts";

const bundled = await build({
  entryPoints: [fileURLToPath(new URL("../../src/scanPresentation.ts", import.meta.url))],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const bundledSource = bundled.outputFiles[0]?.text;
assert.ok(bundledSource, "scan presentation bundle should contain JavaScript");
const {
  catalogEngineIds,
  engineNextStepFor,
  engineOutcomeCopy,
  engineOutcomeFor,
  engineRecoveryLabelFor,
  skippedChecksNextStepFor,
} = await import(`data:text/javascript;base64,${Buffer.from(bundledSource).toString("base64")}`);

const engine = (overrides: Partial<EngineRun> = {}): EngineRun => ({
  id: "engine-run-1",
  engineId: "trivy",
  engineName: "raw implementation name",
  category: "raw category",
  taskKind: { kind: "catalog_engine" },
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

test("every currently supported catalog engine has plain-language bilingual outcomes", () => {
  assert.ok(catalogEngineIds.length > 0);
  assert.deepEqual(Object.keys(engineOutcomeCopy).sort(), [...catalogEngineIds].sort());
  for (const engineId of catalogEngineIds) {
    const outcome = engineOutcomeCopy[engineId];
    assert.ok(outcome.en.trim(), `${engineId} needs English outcome copy`);
    assert.ok(outcome.zhTW.trim(), `${engineId} needs Traditional Chinese outcome copy`);
    assert.doesNotMatch(outcome.en, new RegExp(`^${engineId}$`, "iu"));
  }
});

test("Gitleaks, Trivy, and Steampipe describe their exact plain-language outcomes", () => {
  assert.deepEqual(engineOutcomeCopy.gitleaks, {
    en: "Exposed secrets in code",
    zhTW: "程式碼中暴露的秘密",
  });
  assert.deepEqual(engineOutcomeCopy.trivy, {
    en: "Known package vulnerabilities",
    zhTW: "套件中的已知弱點",
  });
  assert.deepEqual(engineOutcomeCopy.steampipe, {
    en: "AWS IAM user inventory",
    zhTW: "AWS IAM 使用者盤點",
  });
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

test("queued and paused checks state their status or available action directly", () => {
  assert.deepEqual(
    engineNextStepFor(engine({ status: "pending", phase: "planned" })),
    {
      en: "This check is queued.",
      zhTW: "這項檢查已排入佇列。",
    },
  );
  assert.deepEqual(
    engineNextStepFor(engine({ status: "paused", phase: "paused" })),
    {
      en: "Select Continue scan.",
      zhTW: "請選擇「繼續掃描」。",
    },
  );
});

test("known setup failures lead to the matching automatic next step", () => {
  const target = engineNextStepFor(engine({ status: "not_executed", errorCode: "no_compatible_authorized_assets" }));
  const tools = engineNextStepFor(engine({
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    rawArtifactCount: 0,
    findingCount: 0,
    checkpoint: {
      attempt: 1,
      stage: "failed",
      artifactCount: 0,
      cleanupCompleted: true,
      scopeBound: false,
      lastError: "bounded local failure",
    },
  }));
  assert.match(target.en, /scan setup/u);
  assert.match(target.zhTW, /掃描設定/u);
  assert.match(tools.en, /prepare.*automatically/u);
  assert.match(tools.zhTW, /自動準備/u);
});

test("provider rate limits use a direct status and next action", () => {
  const action = engineNextStepFor(engine({
    status: "failed",
    errorCode: "provider_rate_limited",
  }));

  assert.deepEqual(action, {
    en: "Provider rate limit reached. Continue this scan after the limit resets.",
    zhTW: "雲端服務已達速率上限；上限重設後繼續這次掃描。",
  });
  assert.doesNotMatch(`${action.en}${action.zhTW}`, /wait|稍等|later|稍後/iu);
});

test("an unavailable cleanup identity recommends a new scan without infrastructure jargon", () => {
  const action = engineNextStepFor(engine({
    status: "failed",
    phase: "cleanup_identity_unavailable",
    errorCode: "runtime_cleanup_identity_unavailable",
    recoveryAction: "none",
    resumable: false,
  }));

  assert.match(action.en, /Start a new scan/u);
  assert.match(action.zhTW, /開始新的掃描取得新結果/u);
  assert.doesNotMatch(`${action.en} ${action.zhTW}`, /older data|nothing else|較舊|保留/iu);
  assert.doesNotMatch(`${action.en} ${action.zhTW}`, /runtime|identity|cleanup|執行環境|識別|清理/iu);
});

test("execution_failed only recommends tool setup with explicit pre-start evidence", () => {
  const missingCheckpoint = engineNextStepFor(engine({
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    checkpoint: undefined,
    rawArtifactCount: 0,
    findingCount: 0,
  }));
  assert.doesNotMatch(missingCheckpoint.en, /scan-tool setup/u);
  assert.match(missingCheckpoint.en, /diagnostic log/u);
  assert.match(missingCheckpoint.zhTW, /診斷紀錄/u);

  for (const started of [
    engine({
      status: "failed",
      phase: "failed",
      errorCode: "execution_failed",
      runtimeProvider: "managed",
      checkpoint: { attempt: 1, stage: "failed", artifactCount: 0, cleanupCompleted: true, scopeBound: false },
    }),
    engine({
      status: "failed",
      phase: "failed",
      errorCode: "execution_failed",
      exitCode: 2,
      checkpoint: { attempt: 1, stage: "failed", artifactCount: 0, cleanupCompleted: true, scopeBound: true },
    }),
  ]) {
    const action = engineNextStepFor(started);
    assert.doesNotMatch(action.en, /scan-tool setup/u);
    assert.match(action.en, /did not finish|diagnostic log/u);
    assert.match(action.zhTW, /沒有完成|診斷紀錄/u);
  }
});

test("post-start failures preserve results and cleanup guidance", () => {
  const withResults = engineNextStepFor(engine({
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    rawArtifactCount: 1,
    findingCount: 2,
    checkpoint: { attempt: 1, stage: "failed", artifactCount: 1, cleanupCompleted: true, scopeBound: true },
  }));
  assert.match(withResults.en, /Open the completed results/u);
  assert.match(withResults.zhTW, /開啟已完成結果/u);

  const cleanup = engineNextStepFor(engine({ status: "failed", errorCode: "runtime_cleanup_pending" }));
  assert.match(cleanup.en, /Finish cleanup/u);
  assert.match(cleanup.zhTW, /完成清理/u);
  assert.doesNotMatch(cleanup.en, /scan-tool setup/u);
});

test("an unclassified stopped check gives one direct retry path", () => {
  const action = engineNextStepFor(engine({
    status: "failed",
    phase: "failed",
    errorCode: "unclassified_failure",
  }));

  assert.equal(action.en, "Retry this check. Its diagnostic log is available under Technical details.");
  assert.equal(action.zhTW, "請重試這項檢查；診斷紀錄位於「技術細節」。");
  assert.doesNotMatch(`${action.en} ${action.zhTW}`, /if it stops again|for support|若再次停止|以便排查/iu);
});

test("bounded retry exhaustion and cancellation never promise an impossible resume", () => {
  const exhausted = engineNextStepFor(engine({
    status: "partial",
    phase: "results_partial",
    errorCode: "coverage_incomplete_after_bounded_retries",
    resumable: false,
  }));
  assert.match(exhausted.en, /completed results and untested items/u);
  assert.match(exhausted.en, /Start a new scan/u);
  assert.match(exhausted.zhTW, /已完成結果與未測試項目/u);
  assert.doesNotMatch(`${exhausted.en}${exhausted.zhTW}`, /continue this scan|繼續掃描/iu);

  const cancelled = engineNextStepFor(engine({
    status: "cancelled",
    phase: "cancelled_after_partial_results",
    errorCode: "cancelled_after_partial_results",
    rawArtifactCount: 1,
    resumable: false,
  }));
  assert.match(cancelled.en, /results captured before the stop/u);
  assert.match(cancelled.en, /remaining items/u);
  assert.match(cancelled.zhTW, /停止前擷取的結果/u);
  assert.doesNotMatch(`${cancelled.en}${cancelled.zhTW}`, /continue this scan|繼續掃描/iu);
});

test("a gateway preparation failure says automatic rebuild and retry, never resume saved progress", () => {
  const failed = engine({
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    failureKind: "gateway_preparation_failed",
    recoveryAction: "restart_check",
    resumable: true,
    scopeContractBound: true,
    checkpoint: {
      attempt: 1,
      stage: "failed",
      artifactCount: 0,
      cleanupCompleted: true,
      scopeBound: false,
    },
  });
  const nextStep = engineNextStepFor(failed);
  const recovery = engineRecoveryLabelFor(failed);

  assert.match(nextStep.en, /private scan connection/u);
  assert.match(nextStep.en, /rebuild.*automatically/iu);
  assert.match(nextStep.zhTW, /專用掃描連線/u);
  assert.match(recovery.en, /from the beginning/u);
  assert.match(recovery.zhTW, /從頭重試/u);
  assert.doesNotMatch(`${nextStep.en}${recovery.en}`, /continue from saved|last saved point/u);
});

test("typed skipped reasons choose a specific bilingual next step without rendering the code", () => {
  const cases = [
    [["no_compatible_authorized_assets"], /scan setup/u, /掃描設定/u],
    [["provider_source_required"], /cloud setup/u, /雲端設定/u],
    [["runtime_image_unavailable"], /prepare.*automatically/u, /自動準備/u],
    [["engine_release_unavailable"], /Update the app/u, /更新應用程式/u],
  ] as const;
  for (const [codes, english, traditionalChinese] of cases) {
    const action = skippedChecksNextStepFor(codes);
    assert.match(action.en, english);
    assert.match(action.zhTW, traditionalChinese);
    assert.doesNotMatch(`${action.en}${action.zhTW}`, new RegExp(codes[0], "u"));
  }

  const mixed = skippedChecksNextStepFor(["no_compatible_authorized_assets", "runtime_image_unavailable"]);
  assert.match(mixed.en, /Finish the target or cloud step/u);
  assert.match(mixed.zhTW, /完成畫面上的目標或雲端步驟/u);
});
