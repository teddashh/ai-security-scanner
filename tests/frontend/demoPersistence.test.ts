import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  stdin: {
    contents: 'export { deleteStoredDemoCase, loadStoredDemoCases } from "./src/data/demo.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "demo-persistence-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});

const moduleUrl = `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`;
const demo = await import(moduleUrl) as {
  deleteStoredDemoCase: (caseId: string, confirmation: string) => boolean;
  loadStoredDemoCases: () => Array<{ aiGeneratedArtifact: unknown }>;
};

let storedValue = "[]";
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    localStorage: {
      getItem: () => storedValue,
      setItem: (_key: string, value: string) => {
        storedValue = value;
      },
    },
  },
});

const loadAnswer = (value: unknown, includeProperty = true): unknown => {
  storedValue = JSON.stringify([{
    id: "case-demo-persisted",
    ...(includeProperty ? { aiGeneratedArtifact: value } : {}),
  }]);
  return demo.loadStoredDemoCases()[0]?.aiGeneratedArtifact;
};

test("stored demo AI-origin answers preserve the three supported values", () => {
  for (const answer of ["yes", "no", "unknown"] as const) {
    assert.equal(loadAnswer(answer), answer);
  }
});

test("stored demo AI-origin answers fail closed when missing or malformed", () => {
  assert.equal(loadAnswer(undefined, false), "unknown");
  for (const malformed of [null, "maybe", true, false, 1, {}, []]) {
    assert.equal(loadAnswer(malformed), "unknown");
  }
});

test("exact-name deletion removes only a browser-persisted preview project", () => {
  storedValue = JSON.stringify([
    { id: "case-local-delete", name: "Delete this preview", aiGeneratedArtifact: "unknown" },
    { id: "case-local-keep", name: "Keep this preview", aiGeneratedArtifact: "unknown" },
  ]);

  assert.equal(demo.deleteStoredDemoCase("case-local-delete", "wrong name"), false);
  assert.equal(demo.loadStoredDemoCases().length, 2);
  assert.equal(demo.deleteStoredDemoCase("case-local-delete", "Delete this preview"), true);
  assert.deepEqual(
    demo.loadStoredDemoCases().map((assessmentCase) => (assessmentCase as { id: string }).id),
    ["case-local-keep"],
  );
});

test("built-in and missing preview projects cannot be deleted through browser storage", () => {
  storedValue = "[]";

  assert.equal(demo.deleteStoredDemoCase("case-demo-northstar", "Northstar 初步安全健檢"), false);
  assert.equal(demo.deleteStoredDemoCase("missing", "Missing"), false);
  assert.equal(storedValue, "[]");
});
