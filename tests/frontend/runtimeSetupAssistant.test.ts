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

test("packaged-component blockers remain visible without rerunning runtime setup", () => {
  for (const copy of [
    "Restore one installed scan component",
    "恢復一項安裝元件",
    "Get the latest installer",
    "取得最新安裝程式",
    "https://github.com/teddashh/ai-security-scanner/releases",
  ]) assert.ok(source.includes(copy), copy);

  assert.match(source, /scannerSetupBlocker\?: ScannerSetupBlocker/u);
  assert.match(source, /scannerIssue = !active && !failed && scannerSetupBlocker/u);
  assert.match(source, /runtime\?\.available === true && !scannerIssue/u);
  assert.match(source, /scannerIssue \? \(/u);
  assert.match(source, /href=\{scannerIssue\.releaseHref\}/u);
  assert.match(source, /scannerIssue\.action/u);
  assert.doesNotMatch(source, /onClick=\{onSetup\}[^]*scannerIssue\.action/u);
  assert.doesNotMatch(source, /egress_gateway_unavailable[^}]*title:\s*"egress/u);
  assert.doesNotMatch(source, /engine_execution_contract_invalid[^}]*title:\s*"execution/u);
});
