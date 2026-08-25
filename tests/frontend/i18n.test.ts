import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  stdin: {
    contents: [
      'export * from "./src/i18n/core.ts";',
      'export { formatDate, formatDateTime, phaseMeta, coverageMeta } from "./src/lib.ts";',
    ].join("\n"),
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "i18n-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});

const source = bundled.outputFiles[0]?.text;
assert.ok(source, "the i18n core bundle should contain JavaScript");
const i18n = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

const placeholders = (message: string): string[] =>
  [...message.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu)]
    .map((match) => match[1] ?? "")
    .sort();

test("English and Traditional Chinese locales cover the exact same message contract", () => {
  const englishKeys = Object.keys(i18n.localeMessages.en).sort();
  const chineseKeys = Object.keys(i18n.localeMessages["zh-TW"]).sort();

  assert.deepEqual(chineseKeys, englishKeys);
  assert.deepEqual([...i18n.messageKeys].sort(), englishKeys);
  for (const key of i18n.messageKeys) {
    assert.deepEqual(
      placeholders(i18n.localeMessages["zh-TW"][key]),
      placeholders(i18n.localeMessages.en[key]),
      `${key} should use the same interpolation parameters in both locales`,
    );
  }
});

test("typed translators interpolate central and page-local bilingual copy", () => {
  assert.equal(
    i18n.translate("en", "runtime.badge.ready", { provider: "Podman" }),
    "Local scan tools ready · Podman",
  );
  assert.equal(
    i18n.translate("zh-TW", "runtime.badge.ready", { provider: "Podman" }),
    "本機掃描工具已就緒 · Podman",
  );

  const localCopy = {
    en: "Scan {target}",
    zhTW: "掃描 {target}",
  } as const;
  assert.equal(i18n.translateBilingualText("en", localCopy, { target: "example.com" }), "Scan example.com");
  assert.equal(i18n.translateBilingualText("zh-TW", localCopy, { target: "example.com" }), "掃描 example.com");
});

test("stored language wins, browser language is a fallback, and unsupported browsers use English", () => {
  assert.equal(i18n.resolveLocalePreference("zh-TW", ["en-US"]), "zh-TW");
  assert.equal(i18n.resolveLocalePreference("en", ["zh-Hant-TW"]), "en");
  assert.equal(i18n.resolveLocalePreference(undefined, ["zh-Hant-TW", "en"]), "zh-TW");
  assert.equal(i18n.resolveLocalePreference(undefined, ["zh-CN"]), "zh-TW");
  assert.equal(i18n.resolveLocalePreference(undefined, ["fr-FR"]), "en");
});

test("locale persistence and the document language use the stable locale contract", () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
  };
  const document = { documentElement: { lang: "" } };

  assert.equal(i18n.persistLocalePreference(storage, "zh-TW"), true);
  assert.equal(values.get(i18n.localeStorageKey), "zh-TW");
  assert.equal(i18n.readLocalePreference(storage, ["en-US"]), "zh-TW");
  i18n.applyDocumentLocale(document, "en");
  assert.equal(document.documentElement.lang, "en");

  const blockedStorage = {
    getItem: () => { throw new Error("blocked"); },
    setItem: () => { throw new Error("blocked"); },
  };
  assert.equal(i18n.readLocalePreference(blockedStorage, ["zh-Hant"]), "zh-TW");
  assert.equal(i18n.persistLocalePreference(blockedStorage, "en"), false);
});

test("number and date formatting use the selected Intl locale", () => {
  const date = new Date("2026-08-25T14:30:00.000Z");
  const dateOptions = { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" } as const;

  assert.equal(
    i18n.formatLocaleNumber("en", 1234567.89),
    new Intl.NumberFormat("en").format(1234567.89),
  );
  assert.equal(
    i18n.formatLocaleNumber("zh-TW", 1234567.89),
    new Intl.NumberFormat("zh-TW").format(1234567.89),
  );
  assert.equal(
    i18n.formatLocaleDate("en", date, dateOptions),
    new Intl.DateTimeFormat("en", dateOptions).format(date),
  );
  assert.equal(
    i18n.formatLocaleDate("zh-TW", date, dateOptions),
    new Intl.DateTimeFormat("zh-TW", dateOptions).format(date),
  );
});

test("shared status copy and legacy date helpers follow the active locale", () => {
  i18n.setActiveLocale("en");
  assert.equal(i18n.phaseMeta.ready.label, "Ready to scan");
  assert.equal(i18n.coverageMeta.source_unavailable_unknown.shortLabel, "Unknown");

  i18n.setActiveLocale("zh-TW");
  assert.equal(i18n.phaseMeta.ready.label, "可以開始掃描");
  assert.equal(i18n.coverageMeta.source_unavailable_unknown.shortLabel, "未知");

  const value = "2026-08-25T14:30:00.000Z";
  assert.equal(
    i18n.formatDate(value),
    new Intl.DateTimeFormat("zh-TW", { year: "numeric", month: "short", day: "numeric" })
      .format(new Date(value)),
  );
});

test("runtime failures become plain-language guidance without echoing backend output", () => {
  const raw = String.raw`runtime error: command \\?\C:\Windows\System32\wsl.exe failed with exit status 1`;
  const issue = i18n.classifyRuntimeIssue(raw);
  assert.equal(issue, "wsl");

  const guidance = i18n.translate("en", `runtime.prerequisite.${issue}`);
  assert.match(guidance, /Windows needs WSL 2/u);
  assert.doesNotMatch(guidance, /exit status|System32|runtime error/u);
});
