import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  stdin: {
    contents: [
      'export { getDemoNotice, getDemoSnapshot } from "./src/data/demo.ts";',
      'export { setActiveLocale } from "./src/i18n/core.ts";',
    ].join("\n"),
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "demo-localization-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});

const moduleUrl = `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`;
const demo = await import(moduleUrl) as {
  getDemoNotice: () => string;
  getDemoSnapshot: () => unknown;
  setActiveLocale: (locale: "en" | "zh-TW") => void;
};

const collectStrings = (value: unknown): string[] => {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(collectStrings);
  if (value && typeof value === "object") return Object.values(value).flatMap(collectStrings);
  return [];
};

test("the full built-in demo contains no Chinese text in English mode", () => {
  demo.setActiveLocale("en");
  const chinese = collectStrings(demo.getDemoSnapshot()).filter((value) => /\p{Script=Han}/u.test(value));
  assert.deepEqual(chinese, []);
  assert.doesNotMatch(demo.getDemoNotice(), /\p{Script=Han}/u);
});

test("the built-in demo remains fully available in Traditional Chinese", () => {
  demo.setActiveLocale("zh-TW");
  const strings = collectStrings(demo.getDemoSnapshot());
  assert.ok(strings.some((value) => value === "Northstar 初步安全健檢"));
  assert.match(demo.getDemoNotice(), /展示資料/u);
});
