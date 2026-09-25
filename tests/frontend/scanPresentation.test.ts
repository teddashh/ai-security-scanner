import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
  engineRecoveryModeFor,
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
  savedResultArtifactCount: 0,
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
      en: "Select Continue unfinished work.",
      zhTW: "請選擇「繼續未完成的工作」。",
    },
  );
  assert.deepEqual(
    engineNextStepFor(engine({
      status: "paused",
      phase: "running",
      recoveryAction: "restart_check",
      resumable: true,
    })),
    {
      en: "Retry this check from the beginning",
      zhTW: "從頭重試這項檢查",
    },
  );
  assert.deepEqual(
    engineNextStepFor(engine({
      status: "paused",
      phase: "captured_awaiting_adapter",
      recoveryAction: "continue_saved_results",
      resumable: true,
    })),
    {
      en: "Continue from saved results",
      zhTW: "從已保存的結果繼續",
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
  assert.match(tools.en, /setup is automatic/u);
  assert.match(tools.zhTW, /自動準備/u);
});

test("provider rate limits use a direct status and next action", () => {
  const action = engineNextStepFor(engine({
    status: "failed",
    errorCode: "provider_rate_limited",
  }));

  assert.deepEqual(action, {
    en: "Provider rate limit reached. Continue this scan from its saved checkpoint.",
    zhTW: "雲端服務已達速率上限；從已保存的檢查點繼續這次掃描。",
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
  assert.equal(missingCheckpoint.en, "This check stopped. Retry it; its error code is under Technical status and errors.");
  assert.equal(missingCheckpoint.zhTW, "這項檢查已停止；請重試，錯誤代碼位於「技術狀態與錯誤」。");

  for (const started of [
    engine({
      status: "failed",
      phase: "failed",
      errorCode: "execution_failed",
      rawArtifactCount: 0,
      runtimeProvider: "managed",
      checkpoint: { attempt: 1, stage: "failed", artifactCount: 0, cleanupCompleted: true, scopeBound: false },
    }),
    engine({
      status: "failed",
      phase: "failed",
      errorCode: "execution_failed",
      rawArtifactCount: 0,
      exitCode: 2,
      checkpoint: { attempt: 1, stage: "failed", artifactCount: 0, cleanupCompleted: true, scopeBound: true },
    }),
  ]) {
    const action = engineNextStepFor(started);
    assert.doesNotMatch(action.en, /scan-tool setup/u);
    assert.equal(action.en, "This check began but did not finish. Retry it; its error code is under Technical status and errors.");
    assert.equal(action.zhTW, "這項檢查已開始但沒有完成；請重試，錯誤代碼位於「技術狀態與錯誤」。");
  }
});

test("post-start failures preserve results and cleanup guidance", () => {
  const logsOnly = engineNextStepFor(engine({
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    rawArtifactCount: 2,
    savedResultArtifactCount: 0,
    findingCount: 0,
    checkpoint: { attempt: 1, stage: "failed", artifactCount: 2, cleanupCompleted: true, scopeBound: true },
  }));
  assert.equal(logsOnly.en, "This check began but did not finish. Retry it; its error code is under Technical status and errors.");
  assert.equal(logsOnly.zhTW, "這項檢查已開始但沒有完成；請重試，錯誤代碼位於「技術狀態與錯誤」。");

  const cleanResult = engineNextStepFor(engine({
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    rawArtifactCount: 1,
    savedResultArtifactCount: 1,
    findingCount: 0,
    checkpoint: { attempt: 1, stage: "failed", artifactCount: 1, cleanupCompleted: true, scopeBound: true },
  }));
  assert.equal(cleanResult.en, "This check saved partial results before it stopped. Retry it to complete the missing work.");
  assert.equal(cleanResult.zhTW, "這項檢查在停止前已保存部分結果；請重試以完成缺少的工作。");

  const withResults = engineNextStepFor(engine({
    status: "failed",
    phase: "failed",
    errorCode: "execution_failed",
    rawArtifactCount: 1,
    savedResultArtifactCount: 0,
    findingCount: 2,
    checkpoint: { attempt: 1, stage: "failed", artifactCount: 1, cleanupCompleted: true, scopeBound: true },
  }));
  assert.equal(withResults.en, "This check saved partial results before it stopped. Retry it to complete the missing work.");
  assert.equal(withResults.zhTW, "這項檢查在停止前已保存部分結果；請重試以完成缺少的工作。");

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

  assert.equal(action.en, "Retry this check. Its error code and scanner message are under Technical status and errors.");
  assert.equal(action.zhTW, "請重試這項檢查；錯誤代碼與掃描工具訊息位於「技術狀態與錯誤」。");
  assert.doesNotMatch(`${action.en} ${action.zhTW}`, /if it stops again|for support|若再次停止|以便排查/iu);
});

test("a failed check's next step does not name a control absent from its row", () => {
  // "Technical details" and "Download the diagnostic log" are real labels in this product,
  // but they live on other components and inside notices this row never renders. A grep
  // for the label alone would not have caught a failed-check sentence that names them.
  const absentEnglish = [/Technical details/u, /Download the diagnostic log/u];
  const absentTraditionalChinese = [/技術細節/u, /下載診斷紀錄/u];
  const stoppedCheckpoint = {
    attempt: 1,
    stage: "failed" as const,
    artifactCount: 0,
    cleanupCompleted: true,
    scopeBound: false,
  };
  const cases = [
    {
      branch: "runtime_cleanup_pending",
      run: engine({ status: "failed", phase: "failed", errorCode: "runtime_cleanup_pending" }),
      expected: {
        en: "Finish cleanup, then retry this check.",
        zhTW: "完成清理後，再重試這項檢查。",
      },
    },
    {
      branch: "execution_failed before the scanner starts",
      run: engine({
        status: "failed",
        phase: "failed",
        errorCode: "execution_failed",
        rawArtifactCount: 0,
        findingCount: 0,
        checkpoint: stoppedCheckpoint,
      }),
      expected: {
        en: "Retry this check; scan-tool setup is automatic.",
        zhTW: "重試這項檢查；掃描工具會自動準備。",
      },
    },
    {
      branch: "execution_failed with saved results",
      run: engine({
        status: "failed",
        phase: "failed",
        errorCode: "execution_failed",
        rawArtifactCount: 1,
        findingCount: 2,
        checkpoint: { ...stoppedCheckpoint, artifactCount: 1, scopeBound: true },
      }),
      expected: {
        en: "This check saved partial results before it stopped. Retry it to complete the missing work.",
        zhTW: "這項檢查在停止前已保存部分結果；請重試以完成缺少的工作。",
      },
    },
    {
      branch: "execution_failed after scope, runtime, or an exit code",
      run: engine({
        status: "failed",
        phase: "failed",
        errorCode: "execution_failed",
        rawArtifactCount: 0,
        findingCount: 0,
        runtimeProvider: "managed",
        exitCode: 2,
        checkpoint: { ...stoppedCheckpoint, scopeBound: true },
      }),
      expected: {
        en: "This check began but did not finish. Retry it; its error code is under Technical status and errors.",
        zhTW: "這項檢查已開始但沒有完成；請重試，錯誤代碼位於「技術狀態與錯誤」。",
      },
    },
    {
      branch: "execution_failed with no start or result evidence",
      run: engine({
        status: "failed",
        phase: "failed",
        errorCode: "execution_failed",
        checkpoint: undefined,
        rawArtifactCount: 0,
        findingCount: 0,
      }),
      expected: {
        en: "This check stopped. Retry it; its error code is under Technical status and errors.",
        zhTW: "這項檢查已停止；請重試，錯誤代碼位於「技術狀態與錯誤」。",
      },
    },
    {
      branch: "tool-setup error code",
      run: engine({ status: "failed", phase: "failed", errorCode: "runtime_image_unavailable" }),
      expected: {
        en: "Retry this check; scan-tool setup is automatic.",
        zhTW: "重試這項檢查；掃描工具會自動準備。",
      },
    },
    {
      branch: "release-unavailable error code",
      run: engine({ status: "failed", phase: "failed", errorCode: "engine_release_unavailable" }),
      expected: {
        en: "Update the app, then retry these checks.",
        zhTW: "請更新應用程式，再重試這些檢查。",
      },
    },
    {
      branch: "unclassified error code",
      run: engine({ status: "failed", phase: "failed", errorCode: "unclassified_failure" }),
      expected: {
        en: "Retry this check. Its error code and scanner message are under Technical status and errors.",
        zhTW: "請重試這項檢查；錯誤代碼與掃描工具訊息位於「技術狀態與錯誤」。",
      },
    },
  ];

  for (const { branch, run, expected } of cases) {
    const action = engineNextStepFor(run);
    assert.deepEqual(action, expected, branch);
    for (const pattern of absentEnglish) assert.doesNotMatch(action.en, pattern, branch);
    for (const pattern of absentTraditionalChinese) assert.doesNotMatch(action.zhTW, pattern, branch);
  }
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

test("a recorded unevaluated target states reachability or the shared retry sentence, and a running check stays running", () => {
  const reachability = {
    en: "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.",
    zhTW: "請確認這台主機已開機，且本機能連到已核准的連接埠，然後再執行一次這項檢查。",
  };
  const retry = {
    en: "Retry this check to complete the missing work.",
    zhTW: "重新執行這項檢查以完成缺少的工作。",
  };
  const clear = {
    en: "Continue with the other checks.",
    zhTW: "請繼續查看其他檢查。",
  };
  const running = {
    en: "This check is running now.",
    zhTW: "這項檢查正在執行。",
  };
  const deadHost = [{ assetId: "asset-1", cause: "target_did_not_respond" as const }];
  const causes = [
    "target_did_not_respond",
    "scanner_error",
    "no_security_template_execution_evidence",
    "unknown",
  ] as const;

  assert.deepEqual(
    engineNextStepFor(engine({ findingCount: 0, unevaluatedTargets: deadHost })),
    reachability,
  );
  assert.deepEqual(
    engineNextStepFor(engine({
      status: "partial",
      phase: "partial",
      unevaluatedTargets: deadHost,
    })),
    reachability,
  );
  assert.deepEqual(
    engineNextStepFor(engine({
      findingCount: 0,
      unevaluatedTargets: [{ assetId: "asset-1", cause: "scanner_error" }],
    })),
    retry,
  );
  assert.deepEqual(
    engineNextStepFor(engine({
      findingCount: 0,
      unevaluatedTargets: [{ assetId: "asset-1", cause: "no_security_template_execution_evidence" }],
    })),
    retry,
  );
  assert.deepEqual(
    engineNextStepFor(engine({
      findingCount: 0,
      unevaluatedTargets: [
        { assetId: "asset-1", cause: "target_did_not_respond" },
        { assetId: "asset-2", cause: "scanner_error" },
      ],
    })),
    reachability,
  );
  assert.deepEqual(
    engineNextStepFor(engine({
      findingCount: 0,
      unevaluatedTargets: [{ assetId: "asset-1", cause: "unknown" }],
    })),
    clear,
  );
  for (const cause of causes) {
    assert.deepEqual(
      engineNextStepFor(engine({
        status: "running",
        phase: "running",
        progress: 40,
        unevaluatedTargets: [{ assetId: "asset-1", cause }],
      })),
      running,
    );
  }
});

test("a retryable cancelled check uses the report's recorded next step", () => {
  const retryable = engineNextStepFor(engine({
    status: "cancelled",
    phase: "cancelled_before_dispatch",
    errorCode: "cancelled_before_dispatch",
    recoveryAction: "restart_check",
    resumable: true,
  }));
  assert.deepEqual(retryable, {
    en: "Retry this check to complete the missing coverage.",
    zhTW: "重新執行這項檢查以完成缺少的涵蓋範圍。",
  });

  const continued = engineNextStepFor(engine({
    status: "cancelled",
    phase: "cancelled",
    recoveryAction: "continue_saved_results",
    resumable: true,
  }));
  assert.deepEqual(continued, {
    en: "Continue from saved results",
    zhTW: "從已保存的結果繼續",
  });

  const cleanup = engineNextStepFor(engine({
    status: "cancelled",
    phase: "cancelled",
    recoveryAction: "finish_cleanup",
    resumable: true,
  }));
  assert.deepEqual(cleanup, {
    en: "Finish cleanup, then retry",
    zhTW: "完成清理後再重試",
  });

  const fresh = engineNextStepFor(engine({
    status: "cancelled",
    phase: "cancelled_before_dispatch",
    errorCode: "cancelled_before_dispatch",
    recoveryAction: "none",
    resumable: false,
  }));
  assert.deepEqual(fresh, {
    en: "Start a new scan to run this check again.",
    zhTW: "開始新的掃描，再次執行這項檢查。",
  });
});

test("a gateway preparation failure gives direct automatic setup and retry", () => {
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
  const recovery = engineRecoveryModeFor(failed);

  assert.match(nextStep.en, /private connection setup is automatic/u);
  assert.match(nextStep.zhTW, /專用連線會自動準備/u);
  assert.match(recovery.en, /starts this check over/u);
  assert.match(recovery.zhTW, /從頭執行/u);
  assert.doesNotMatch(`${nextStep.en}${recovery.en}`, /continue from saved|last saved point/u);
});

test("typed skipped reasons choose a specific bilingual next step without rendering the code", () => {
  const cases = [
    [["no_compatible_authorized_assets"], /scan setup/u, /掃描設定/u],
    [["no_ownership_confirmed_targets"], /scan setup/u, /掃描設定/u],
    [["workspace_snapshot_unavailable"], /scan setup/u, /掃描設定/u],
    [["provider_source_required"], /cloud account/u, /雲端帳號/u],
    [["provider_target_binding_mismatch"], /cloud account/u, /雲端帳號/u],
    [["runtime_image_unavailable"], /setup is automatic/u, /自動準備/u],
    [["engine_execution_contract_invalid"], /setup is automatic/u, /自動準備/u],
    [["engine_release_unavailable"], /Update the app/u, /更新應用程式/u],
    [["direct_network_protocol_mismatch"], /approved protocol or target form/u, /已核准的通訊協定或目標形式/u],
    [["direct_network_target_kind_mismatch"], /approved protocol or target form/u, /已核准的通訊協定或目標形式/u],
    [["external_scope_missing"], /approved protocol or target form/u, /已核准的通訊協定或目標形式/u],
    [["authorization_reference_empty"], /approved protocol or target form/u, /已核准的通訊協定或目標形式/u],
    [["mcp_configuration_absent"], /no MCP configuration/u, /沒有可檢查的 MCP 設定/u],
    [["mcp_configuration_unselected"], /choose which MCP configuration/u, /選擇要檢查的 MCP 設定/u],
    [["mcp_configuration_discovery_incomplete"], /discovery did not finish/u, /設定探索未完成/u],
  ] as const;
  for (const [codes, english, traditionalChinese] of cases) {
    const action = skippedChecksNextStepFor(codes);
    assert.match(action.en, english);
    assert.match(action.zhTW, traditionalChinese);
    assert.doesNotMatch(`${action.en}${action.zhTW}`, new RegExp(codes[0], "u"));
  }

  const mixed = skippedChecksNextStepFor(["no_compatible_authorized_assets", "runtime_image_unavailable"]);
  assert.match(mixed.en, /Finish the displayed target or cloud step/u);
  assert.match(mixed.zhTW, /完成畫面上的目標或雲端步驟/u);
});

test("every planner skip reason is classified without falling through to skippedUnknown", () => {
  const rust = readFileSync(new URL("../../src-tauri/src/case_service.rs", import.meta.url), "utf8");
  const marker = "pub const PLANNER_NOT_EXECUTED_REASON_CODES: &[&str] = &[";
  const start = rust.indexOf(marker);
  assert.ok(start >= 0, "planner reason census was not found in case_service.rs");
  const body = rust.slice(start + marker.length);
  const end = body.indexOf("];");
  assert.ok(end > 0, "planner reason census has no closing bracket");
  const codes = [...body.slice(0, end).matchAll(/"([a-z0-9_]+)"/gu)].map((match) => match[1]!);
  assert.ok(codes.length > 0, "planner reason census is empty");
  const unknown = skippedChecksNextStepFor(["__not_a_planner_reason__"]);
  assert.match(unknown.en, /technical records/u);
  for (const code of codes) {
    const action = skippedChecksNextStepFor([code]);
    assert.notDeepEqual(
      action,
      unknown,
      `${code} fell through to skippedUnknown`,
    );
  }
});
