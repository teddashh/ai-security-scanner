import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  stdin: {
    contents: 'export { loadStoredDemoCases } from "./src/data/demo.ts";',
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
  loadStoredDemoCases: () => Array<{ aiGeneratedArtifact: unknown }>;
};

let storedValue = "[]";
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    localStorage: {
      getItem: () => storedValue,
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
