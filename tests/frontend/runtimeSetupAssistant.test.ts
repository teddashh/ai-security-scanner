import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { resolveRuntimeSetupPresentation } from "../../src/runtimeSetupPresentation.ts";

const source = readFileSync(
  new URL("../../src/components/RuntimeSetupAssistant.tsx", import.meta.url),
  "utf8",
);
const shellSource = readFileSync(
  new URL("../../src/components/AppShell.tsx", import.meta.url),
  "utf8",
);
const scannerSource = readFileSync(
  new URL("../../src/services/scanner.ts", import.meta.url),
  "utf8",
);
const tauriSource = readFileSync(
  new URL("../../src-tauri/src/lib.rs", import.meta.url),
  "utf8",
);

test("missing WSL gets one bilingual Microsoft setup path and one safe recheck", () => {
  for (const phrase of [
    "Open Microsoft’s WSL setup",
    "開啟 Microsoft 的 WSL 設定",
    "I’m done — check again",
    "我完成了，重新檢查",
    "continue automatically",
    "自動接著準備",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(source, /href=\{MICROSOFT_WSL_HELP\}/u);
  assert.match(source, /setupFailed && showMicrosoftSetup/u);
  assert.match(source, /onClick=\{onSetup\}/u);
});

test("the desktop UI cannot elevate or change Windows optional features", () => {
  for (const candidate of [source, shellSource, scannerSource]) {
    assert.doesNotMatch(candidate, /onRepair|repairManagedRuntimePrerequisite|administrator approval|系統管理員確認|wsl --install|wsl --update|UAC/u);
  }
  assert.doesNotMatch(tauriSource, /commands::repair_managed_runtime_prerequisite/u);
  assert.doesNotMatch(shellSource, /runtimeRepairing|onRepairRuntime|runtime\.setup\.repair/u);
});

test("packaged-component blockers remain visible without rerunning runtime setup", () => {
  for (const copy of [
    "Get the scan tools for this check",
    "取得這項檢查需要的掃描工具",
    "Restore one installed scan component",
    "恢復一項安裝元件",
    "Get the latest installer",
    "取得最新安裝程式",
    "https://github.com/teddashh/ai-security-scanner/releases",
  ]) assert.ok(source.includes(copy), copy);

  assert.match(source, /scannerSetupBlocker\?: ScannerSetupBlocker/u);
  assert.match(source, /resolveRuntimeSetupPresentation\(\{/u);
  assert.match(source, /presentation\.showPackagedComponentIssue && scannerSetupBlocker/u);
  assert.match(source, /scannerIssue \? \(/u);
  assert.match(source, /href=\{scannerIssue\.releaseHref\}/u);
  assert.match(source, /scannerIssue\.action/u);
  assert.doesNotMatch(source, /onClick=\{onSetup\}[^]*scannerIssue\.action/u);
  assert.doesNotMatch(source, /egress_gateway_unavailable[^}]*title:\s*"egress/u);
  assert.doesNotMatch(source, /engine_execution_contract_invalid[^}]*title:\s*"execution/u);
});

test("a current packaged-component blocker wins over stale ready, active, or failed setup status", () => {
  for (const blocker of ["no_runnable_authorized_targets", "egress_gateway_unavailable"] as const) {
    for (const status of [
      { active: true, phase: "start" as const },
      { active: false, phase: "failed" as const },
    ]) {
      const state = resolveRuntimeSetupPresentation({
        mode: "native",
        runtimeAvailable: true,
        status,
        blocker,
      });

      assert.equal(state.ready, false);
      assert.equal(state.showPackagedComponentIssue, true);
      assert.equal(state.setupActive, false);
      assert.equal(state.setupFailed, false);
    }
  }

  assert.equal(resolveRuntimeSetupPresentation({
    mode: "native",
    runtimeAvailable: true,
    status: { active: false, phase: "failed" },
  }).ready, true);
});
