import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../../src/components/RuntimeSetupAssistant.tsx", import.meta.url),
  "utf8",
);

test("Windows prerequisite repair is the primary bilingual path", () => {
  assert.match(source, /Let ai-security-scanner handle it/u);
  assert.match(source, /交給 ai-security-scanner 處理/u);
  assert.match(source, /Windows will ask for administrator approval once/u);
  assert.match(source, /Windows 會顯示一次系統管理員確認/u);
  assert.match(source, /never sees or saves your password/u);
  assert.match(source, /不會看到或儲存你的密碼/u);
  assert.match(source, /onClick=\{onRepair\}/u);
});

test("manual commands remain available only under the secondary options", () => {
  assert.match(source, /<details className="runtime-assistant__manual">/u);
  assert.match(source, /Other ways/u);
  assert.match(source, /其他方式/u);
  assert.match(source, /wsl --install --no-distribution/u);
  assert.match(source, /wsl --update/u);
  assert.ok(
    source.indexOf("onClick={onRepair}") < source.indexOf('className="runtime-assistant__manual"'),
    "the automatic action should be wired before the secondary manual path",
  );
});
