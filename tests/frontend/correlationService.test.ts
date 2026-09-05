import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { build } from "esbuild";

// The wire-contract test pins the field names and the component test pins what
// the page renders, but neither one ever runs `suggestFindingCorrelations`.
// Between them sits the part that decides whether a user in the packaged app
// gets anything at all: does the service reach the native command, and does the
// browser preview say it is a preview instead of quietly answering "nothing is
// related"? That is only provable by executing the service.

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");

const setTestWindow = (value: object): void => {
  Object.defineProperty(globalThis, "window", { configurable: true, writable: true, value });
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
    sourcefile: "correlation-service-test-entry.ts",
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

const nativeReport = {
  keyVersion: "cross-engine-vulnerability-id-1",
  suggestions: [{
    id: "correlation-abc",
    caseId: "case-1",
    comparisonKey: "cross-engine-vulnerability-id-1|vuln:CVE-2024-3094|pkg:xz-utils|asset:asset-1",
    keyVersion: "cross-engine-vulnerability-id-1",
    vulnerabilityId: "CVE-2024-3094",
    package: "xz-utils",
    title: "CVE-2024-3094 in xz-utils",
    basis: "2 engines (grype, trivy) reported vulnerability CVE-2024-3094 against package xz-utils on the same asset.",
    uncertainty: "Grouping these is a presentation choice.",
    corroboration: "not-established",
    findingIds: ["finding-grype", "finding-trivy"],
    engineIds: ["grype", "trivy"],
  }],
  unverifiable: [],
  truncatedSuggestions: 3,
};

test("the native read invokes the registered command with the case id", async () => {
  const invocations: { command: string; args: unknown }[] = [];
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        invocations.push({ command, args });
        return nativeReport;
      },
    },
  });

  const result = await scannerService.suggestFindingCorrelations("case-1");

  assert.deepEqual(invocations, [{
    command: COMMANDS.suggestFindingCorrelations,
    args: { caseId: "case-1" },
  }]);
  assert.equal(result.mode, "native");
  // The report crosses unchanged: the backend already emits camelCase, so an
  // adapter here would be a second place for the contract to drift.
  assert.deepEqual(result.data, nativeReport);
  assert.equal(result.data.truncatedSuggestions, 3);
});

test("a native failure rejects rather than resolving to an empty report", async () => {
  // Resolving to `{suggestions: []}` would let the page render an all-clear
  // that the product never established. The caller must see the failure.
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async () => {
        throw new Error("test-only native correlation failure");
      },
    },
  });

  await assert.rejects(
    () => scannerService.suggestFindingCorrelations("case-1"),
    /test-only native correlation failure/u,
  );
});

test("the browser preview labels its empty report as a preview, not as a result", async () => {
  setTestWindow({});

  const result = await scannerService.suggestFindingCorrelations("case-1");

  assert.equal(result.mode, "demo");
  assert.deepEqual(result.data.suggestions, []);
  assert.deepEqual(result.data.unverifiable, []);
  assert.equal(result.data.truncatedSuggestions, 0);
  // Without the notice a reader cannot tell an uncompared demo case from a
  // real case where nothing correlated.
  assert.ok(result.notice, "demo mode must carry a notice");
});

// The shell between the service and the page is not rendered by any test, so
// these read its source. Weaker than executing it, but they cover the two ways
// the chain silently breaks: the result never reaching the page, and a failed
// read being converted into an empty report the page would show as an
// all-clear.
const app = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");

test("the shell hands the suggestion report to the findings page", () => {
  assert.match(app, /<FindingsPage[\s\S]*?correlationReport=\{correlationReport\}/u);
  assert.match(app, /scannerService\.suggestFindingCorrelations\(caseId\)/u);
});

test("a failed read clears the report instead of substituting an empty one", () => {
  const effect = app.slice(app.indexOf("suggestFindingCorrelations(caseId)"));
  const body = effect.slice(0, effect.indexOf("setCorrelationReport(report)"));
  assert.match(body, /catch \{[\s\S]*?report = undefined;/u);
  // An empty literal here would turn "we could not ask" into "nothing matched".
  assert.doesNotMatch(body, /suggestions: \[\]/u);
});

test("a slow response cannot overwrite a newer one", () => {
  // Selecting another case while a read is in flight must not repaint the new
  // case's page with the previous case's suggestions.
  const effect = app.slice(app.indexOf("correlationRequestGeneration.current;"));
  const body = effect.slice(0, effect.indexOf("setCorrelationReport(report)"));
  assert.match(body, /if \(generation !== correlationRequestGeneration\.current\) return;/u);
});
