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
