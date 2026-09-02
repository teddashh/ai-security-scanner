import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { getSettingsRuntimePresentation } from "../../src/settingsRuntimePresentation.ts";

test("settings keeps demo mode distinct from native runtime truth", () => {
  for (const runtimeAvailable of [true, false, undefined]) {
    const presentation = getSettingsRuntimePresentation("demo", runtimeAvailable);
    assert.equal(presentation.state, "demo");
    assert.equal(presentation.icon, "spark");
  }
});

test("settings presents an authoritative true runtime as ready", () => {
  const presentation = getSettingsRuntimePresentation("native", true);

  assert.equal(presentation.state, "ready");
  assert.equal(presentation.icon, "check");
  assert.match(presentation.status.en, /ready at the last check/u);
  assert.match(presentation.status.zhTW, /上次檢查時已就緒/u);
});

test("settings presents an authoritative false runtime as unavailable", () => {
  const presentation = getSettingsRuntimePresentation("native", false);

  assert.equal(presentation.state, "unavailable");
  assert.equal(presentation.icon, "warning");
  assert.match(presentation.status.en, /last check.*unavailable/u);
  assert.match(presentation.status.zhTW, /上次檢查.*無法使用/u);
});

test("settings presents undefined runtime truth as not yet checked", () => {
  const presentation = getSettingsRuntimePresentation("native", undefined);

  assert.equal(presentation.state, "unchecked");
  assert.equal(presentation.icon, "clock");
  assert.match(presentation.status.en, /have not been checked yet/u);
  assert.match(presentation.status.zhTW, /尚未檢查/u);
  assert.doesNotMatch(presentation.status.en, /unavailable|could not|failed/u);
  assert.doesNotMatch(presentation.status.zhTW, /無法使用|失敗/u);
});

test("SettingsPage renders the pure presentation result", () => {
  const source = readFileSync(new URL("../../src/pages/SettingsPage.tsx", import.meta.url), "utf8");

  assert.match(source, /getSettingsRuntimePresentation\(mode, runtimeAvailable\)/u);
  assert.match(source, /name=\{runtimePresentation\.icon\}/u);
  assert.match(source, /text\(runtimePresentation\.status\)/u);
});
