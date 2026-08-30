import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { build } from "esbuild";

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");

const setTestWindow = (value: object): void => {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    writable: true,
    value,
  });
};

test.after(() => {
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
});

const bundled = await build({
  stdin: {
    contents: 'export { COMMANDS, scannerService } from "./src/services/scanner.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "snapshot-recovery-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const bundledSource = bundled.outputFiles[0]?.text;
assert.ok(bundledSource, "scanner service test bundle should contain JavaScript");
const { COMMANDS, scannerService } = await import(
  `data:text/javascript;base64,${Buffer.from(bundledSource).toString("base64")}`
);

const packagedBundle = await build({
  stdin: {
    contents: 'export { COMMANDS, scannerService } from "./src/services/scanner.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "packaged-snapshot-recovery-test-entry.ts",
  },
  bundle: true,
  define: {
    "import.meta.env.TAURI_ENV_PLATFORM": JSON.stringify("windows"),
  },
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const packagedBundleSource = packagedBundle.outputFiles[0]?.text;
assert.ok(packagedBundleSource, "packaged scanner service test bundle should contain JavaScript");
const { scannerService: packagedScannerService } = await import(
  `data:text/javascript;base64,${Buffer.from(packagedBundleSource).toString("base64")}`
);

const queuedLocalhostNativeCase = () => ({
  id: "localhost-case",
  title: "This computer · 127.0.0.1:9001",
  assessment_intent: "internal_it_environment",
  profile: {
    organization_name: "This computer",
    employee_range: "Not provided",
    data_classes: ["general"],
    notes: null,
  },
  status: "scanning",
  created_at: "2026-08-30T12:00:00.000000001Z",
  updated_at: "2026-08-30T12:00:00.000000002Z",
  is_demo: false,
  requested_activities: ["low_impact_external_checks"],
  data_sources: [],
  assets: [{
    id: "localhost-asset",
    kind: "web_service",
    name: "127.0.0.1:9001",
    provider: null,
    region: null,
    identifiers: [{ namespace: "localhost_tcp_endpoint", value: "127.0.0.1:9001" }],
    discovered_from: [],
    candidate: false,
    owner_confirmed: true,
    internet_exposed: false,
    contains_sensitive_data: false,
    metadata: {},
  }],
  scope_grants: [],
  coverage: [],
  scan_runs: [{
    id: "localhost-run",
    case_id: "localhost-case",
    sequence: 1,
    created_at: "2026-08-30T12:00:00.000000001Z",
    completed_at: null,
    knowledge_cutoff: "2026-08-30T00:00:00Z",
    engine_runs: [{
      id: "localhost-task",
      engine_id: "built-in-localhost-tcp",
      task_kind: {
        kind: "built_in_localhost_tcp",
        port: 9001,
        timeout_ms: 3000,
        payload_bytes: 0,
      },
      localhost_tcp_observation: null,
      asset_ids: ["localhost-asset"],
      status: "queued",
      progress_percent: 0,
      phase: "queued",
      started_at: null,
      finished_at: null,
      resume_token: null,
      engine_version: null,
      image_digest: null,
      rule_version: null,
      adapter_version: "built-in",
      raw_artifact_ids: [],
      error_code: null,
      error_message: null,
      warnings: [],
    }],
  }],
  findings: [],
  exports: [],
  comparisons: [],
});

test("native snapshot failures reject instead of returning synthetic demo projects", async () => {
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string) => {
        assert.equal(command, COMMANDS.getSnapshot);
        throw new Error("test-only native database failure");
      },
    },
  });

  await assert.rejects(
    () => scannerService.getSnapshot(),
    /test-only native database failure/u,
  );
});

test("the browser development preview remains explicitly demo", async () => {
  setTestWindow({});

  const result = await scannerService.getSnapshot();

  assert.equal(result.mode, "demo");
  assert.equal(result.data.workspace?.case.isDemo, true);
  assert.ok(result.notice);
});

test("the browser preview never runs or claims a localhost quick scan", async () => {
  setTestWindow({});

  const result = await scannerService.startLocalhostQuickScan();

  assert.equal(result.mode, "demo");
  assert.equal(result.data.accepted, false);
  assert.equal(result.data.workspace, undefined);
  assert.ok(result.notice);
});

test("the native localhost quick scan invokes its command once with the default and exact edited ports", async () => {
  const invocations: { command: string; args: unknown }[] = [];
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        invocations.push({ command, args });
        throw new Error("test-only quick-scan stop");
      },
    },
  });

  const defaultResult = await scannerService.startLocalhostQuickScan();
  const editedResult = await scannerService.startLocalhostQuickScan(43_123);

  assert.deepEqual(invocations, [
    { command: COMMANDS.startLocalhostQuickScan, args: { port: 9001 } },
    { command: COMMANDS.startLocalhostQuickScan, args: { port: 43_123 } },
  ]);
  for (const result of [defaultResult, editedResult]) {
    assert.equal(result.mode, "native");
    assert.equal(result.data.accepted, false);
    assert.equal(result.data.workspace, undefined);
  }
});

test("queued localhost first value does not wait for an unrelated manifest read", async () => {
  let manifestReads = 0;
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        if (command === COMMANDS.startLocalhostQuickScan) {
          assert.deepEqual(args, { port: 9001 });
          return queuedLocalhostNativeCase();
        }
        if (command === COMMANDS.listEngineManifests) {
          manifestReads += 1;
          return new Promise<never>(() => undefined);
        }
        throw new Error(`unexpected command: ${command}`);
      },
    },
  });

  const result = await Promise.race([
    scannerService.startLocalhostQuickScan(),
    new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error("localhost start waited for engine manifests")), 250);
    }),
  ]);

  assert.equal(result.mode, "native");
  assert.equal(result.data.accepted, true);
  assert.equal(result.data.workspace?.case.id, "localhost-case");
  assert.equal(result.data.workspace?.runs[0]?.status, "queued");
  assert.deepEqual(result.data.workspace?.runs[0]?.engineRuns[0]?.taskKind, {
    kind: "built_in_localhost_tcp",
    port: 9001,
    timeoutMs: 3000,
    payloadBytes: 0,
  });
  assert.equal(manifestReads, 0);
});

test("scan lifecycle mutation acknowledgements never read optional manifests", async () => {
  const mutations = [
    {
      command: COMMANDS.startScan,
      run: () => scannerService.startScan({ caseId: "localhost-case" }),
    },
    {
      command: COMMANDS.pauseScan,
      run: () => scannerService.pauseScan("localhost-case", "localhost-run"),
    },
    {
      command: COMMANDS.resumeScan,
      run: () => scannerService.resumeScan("localhost-case", "localhost-run"),
      lifecycleOutcome: "queued",
    },
    {
      command: COMMANDS.cancelScan,
      run: () => scannerService.cancelScan("localhost-case", "localhost-run"),
      lifecycleOutcome: "requested",
    },
    {
      command: COMMANDS.startRescan,
      run: () => scannerService.startRescan("localhost-case", "localhost-run"),
    },
  ] as const;

  for (const mutation of mutations) {
    let manifestReads = 0;
    let commandCalls = 0;
    setTestWindow({
      __TAURI_INTERNALS__: {
        invoke: async (command: string) => {
          if (command === mutation.command) {
            commandCalls += 1;
            const nativeCase = queuedLocalhostNativeCase();
            if (command === COMMANDS.cancelScan) {
              nativeCase.scan_runs[0]!.engine_runs[0]!.phase = "cancel_requested";
            }
            return nativeCase;
          }
          if (command === COMMANDS.listEngineManifests) {
            manifestReads += 1;
            return new Promise<never>(() => undefined);
          }
          throw new Error(`unexpected command: ${command}`);
        },
      },
    });

    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const result = await Promise.race([
        mutation.run(),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(
            () => reject(new Error(`${mutation.command} waited for engine manifests`)),
            250,
          );
        }),
      ]);
      assert.equal(result.mode, "native", mutation.command);
      assert.equal(result.data.accepted, true, mutation.command);
      assert.equal(result.data.workspace?.case.id, "localhost-case", mutation.command);
      if ("lifecycleOutcome" in mutation) {
        assert.equal(result.data.lifecycleDisposition?.outcome, mutation.lifecycleOutcome, mutation.command);
      } else {
        assert.equal(result.data.lifecycleDisposition, undefined, mutation.command);
      }
    } finally {
      if (timeout) clearTimeout(timeout);
    }
    assert.equal(commandCalls, 1, mutation.command);
    assert.equal(manifestReads, 0, mutation.command);
  }
});

test("a retained terminal Resume response reports the saved result instead of a queued restart", async () => {
  let manifestReads = 0;
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string) => {
        if (command === COMMANDS.resumeScan) {
          const nativeCase = queuedLocalhostNativeCase();
          nativeCase.status = "completed";
          const nativeRun = nativeCase.scan_runs[0]!;
          nativeRun.completed_at = "2026-08-30T12:00:01Z";
          const nativeEngine = nativeRun.engine_runs[0]!;
          nativeEngine.status = "completed";
          nativeEngine.progress_percent = 100;
          nativeEngine.phase = "completed";
          nativeEngine.started_at = "2026-08-30T12:00:00Z";
          nativeEngine.finished_at = "2026-08-30T12:00:01Z";
          nativeEngine.localhost_tcp_observation = {
            outcome: "reachable",
            observed_at: "2026-08-30T12:00:01Z",
          };
          return nativeCase;
        }
        if (command === COMMANDS.listEngineManifests) {
          manifestReads += 1;
          return new Promise<never>(() => undefined);
        }
        throw new Error(`unexpected command: ${command}`);
      },
    },
  });

  const result = await scannerService.resumeScan("localhost-case", "localhost-run");
  assert.equal(result.data.accepted, true);
  assert.equal(result.data.lifecycleDisposition?.outcome, "result_already_final");
  assert.equal(
    result.data.lifecycleDisposition?.outcome === "result_already_final"
      ? result.data.lifecycleDisposition.resultStatus
      : undefined,
    "completed",
  );
  assert.doesNotMatch(result.data.message, /queued|started|排入佇列|開始/u);
  assert.equal(manifestReads, 0);
});

test("an uncertain native Cancel outcome is typed unconfirmed and does not read manifests", async () => {
  let manifestReads = 0;
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string) => {
        if (command === COMMANDS.cancelScan) throw new Error("command response was lost");
        if (command === COMMANDS.listEngineManifests) {
          manifestReads += 1;
          return new Promise<never>(() => undefined);
        }
        throw new Error(`unexpected command: ${command}`);
      },
    },
  });

  const result = await scannerService.cancelScan("localhost-case", "localhost-run");
  assert.equal(result.mode, "native");
  assert.equal(result.data.accepted, false);
  assert.deepEqual(result.data.lifecycleDisposition, {
    action: "cancel",
    outcome: "unconfirmed",
    runId: "localhost-run",
  });
  assert.equal(manifestReads, 0);
});

test("a packaged surface with a missing bridge stays native and fails visibly", async () => {
  setTestWindow({});

  assert.equal(packagedScannerService.isNative(), true);
  await assert.rejects(
    () => packagedScannerService.getSnapshot(),
    /(?:desktop service is not ready.*No sample data was substituted|桌面服務尚未就緒.*沒有改用範例資料)/iu,
  );

  const manifests = await packagedScannerService.listEngineManifests();
  assert.equal(manifests.mode, "native");
  assert.deepEqual(manifests.data, []);
  assert.equal(manifests.notice, undefined);
});

test("snapshot errors keep real state visible with persistent bilingual retry UI", async () => {
  const [app, shell, scanner, english, chinese] = await Promise.all([
    readFile(new URL("../../src/App.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/components/AppShell.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/services/scanner.ts", import.meta.url), "utf8"),
    readFile(new URL("../../src/i18n/locales/en.ts", import.meta.url), "utf8"),
    readFile(new URL("../../src/i18n/locales/zh-TW.ts", import.meta.url), "utf8"),
  ]);

  const snapshotStart = scanner.indexOf("async getSnapshot");
  const snapshotEnd = scanner.indexOf("async setupManagedRuntime", snapshotStart);
  const getSnapshot = scanner.slice(snapshotStart, snapshotEnd);
  assert.ok(snapshotStart >= 0 && snapshotEnd > snapshotStart);
  assert.match(getSnapshot, /if \(!isNativeSurface\(\)\) return demoResult/u);
  assert.match(getSnapshot, /await invoke<NativeAppSnapshot>\(COMMANDS\.getSnapshot\)/u);
  assert.doesNotMatch(getSnapshot, /catch|return demoResult\([^]*error/u);
  assert.match(scanner, /TAURI_ENV_PLATFORM/u);
  assert.match(scanner, /Boolean\(packagedTauriPlatform\) \|\| hasLiveTauriBridge\(\)/u);

  const loadStart = app.indexOf("const loadSnapshot");
  const loadEnd = app.indexOf("useEffect(() =>", loadStart);
  const loadSnapshot = app.slice(loadStart, loadEnd);
  assert.ok(loadStart >= 0 && loadEnd > loadStart);
  assert.match(loadSnapshot, /setSnapshotRefreshUnavailable\(false\)/u);
  assert.match(loadSnapshot, /catch \(error\)[\s\S]*setSnapshotRefreshUnavailable\(true\)/u);
  assert.doesNotMatch(loadSnapshot, /setSnapshot\((?:undefined|null)\)/u);

  assert.match(app, /snapshotRefreshUnavailable && !snapshot/u);
  assert.match(app, /dataUnavailable=\{snapshotRefreshUnavailable && snapshot !== undefined\}/u);
  assert.match(app, /onRetryData=\{\(\) => void loadSnapshot\(snapshot\?\.selectedCaseId\)\}/u);
  assert.doesNotMatch(app, /switch to demo data|\u5207\u63db\u6210\u5c55\u793a\u8cc7\u6599/u);

  assert.match(shell, /className="data-status-banner" role="alert"/u);
  assert.match(shell, /disabled=\{dataRetrying\}/u);
  assert.match(shell, /onClick=\{onRetryData\}/u);
  assert.match(shell, /shell\.data\.refreshErrorTitle/u);
  assert.match(shell, /shell\.data\.refreshErrorDetail/u);

  const selectStart = app.indexOf("const selectCase");
  const selectEnd = app.indexOf("const retryScanReadiness", selectStart);
  const selectCase = app.slice(selectStart, selectEnd);
  assert.ok(selectStart >= 0 && selectEnd > selectStart);
  assert.match(selectCase, /setCaseSelectionUnavailableId\(undefined\)/u);
  assert.match(selectCase, /catch \(error\)[\s\S]*setCaseSelectionUnavailableId\(caseId\)/u);
  assert.doesNotMatch(selectCase, /setSnapshot\((?:undefined|null)\)/u);
  assert.match(app, /caseSelectionUnavailable=\{caseSelectionUnavailableId !== undefined\}/u);
  assert.match(app, /onRetryCaseSelection=\{\(\) => \{[\s\S]*selectCase\(caseSelectionUnavailableId\)/u);
  assert.match(shell, /caseSelectionUnavailable && \([\s\S]*shell\.data\.selectionErrorTitle/u);
  assert.match(shell, /onClick=\{onRetryCaseSelection\}/u);

  for (const source of [english, chinese]) {
    for (const key of [
      "shell.data.initialErrorTitle",
      "shell.data.initialErrorDetail",
      "shell.data.refreshErrorTitle",
      "shell.data.refreshErrorDetail",
      "shell.data.selectionErrorTitle",
      "shell.data.selectionErrorDetail",
      "shell.data.retry",
      "shell.data.retrying",
    ]) assert.ok(source.includes(`\"${key}\"`), `${key} must be translated`);
  }
});
