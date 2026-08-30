import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { hasActiveScanWork } from "../../src/freshScanSelection.ts";

const appSource = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");

test("only nonterminal scan work enables authoritative polling", () => {
  for (const status of ["queued", "running", "paused"]) {
    assert.equal(hasActiveScanWork([{ status }]), true, status);
  }
  for (const status of ["completed", "partial", "failed", "cancelled"]) {
    assert.equal(hasActiveScanWork([{ status }]), false, status);
  }
  for (const status of ["pending", "running", "paused"]) {
    assert.equal(
      hasActiveScanWork([{ status: "completed", engineRuns: [{ status }] }]),
      true,
      `engine ${status}`,
    );
  }
  for (const status of ["completed", "partial", "failed", "not_executed", "cancelled"]) {
    assert.equal(
      hasActiveScanWork([{ status: "completed", engineRuns: [{ status }] }]),
      false,
      `engine ${status}`,
    );
  }

  assert.match(
    appSource,
    /activeScanCaseId = mode === "native"[\s\S]*!loading[\s\S]*hasActiveScanWork\(workspace\.runs\)[\s\S]*workspace\.case\.id/u,
  );
  assert.match(appSource, /if \(!activeScanCaseId\) return undefined/u);
  assert.match(appSource, /ACTIVE_SCAN_REFRESH_INTERVAL_MS = 5_000/u);
  assert.match(appSource, /window\.setInterval\(reconcileActiveScan, ACTIVE_SCAN_REFRESH_INTERVAL_MS\)/u);
});

test("focus and visible-document transitions reconcile through the same quiet load", () => {
  const effectStart = appSource.indexOf("if (!activeScanCaseId) return undefined");
  const effectEnd = appSource.indexOf("const selectedCase = useMemo", effectStart);
  const effect = appSource.slice(effectStart, effectEnd);
  assert.ok(effectStart >= 0 && effectEnd > effectStart);

  assert.match(effect, /const onWindowFocus = \(\) => reconcileActiveScan\(\)/u);
  assert.match(effect, /document\.visibilityState === "visible"[\s\S]*reconcileActiveScan\(\)/u);
  assert.match(effect, /window\.addEventListener\("focus", onWindowFocus\)/u);
  assert.match(effect, /document\.addEventListener\("visibilitychange", onVisibilityChange\)/u);
  assert.match(effect, /loadSnapshot\(activeScanCaseId, true\)/u);
  assert.doesNotMatch(effect, /scannerService\.getSnapshot|setSnapshot\(/u);
});

test("active polling is single-flight, generation-safe, and fully cleaned up", () => {
  const effectStart = appSource.indexOf("if (!activeScanCaseId) return undefined");
  const effectEnd = appSource.indexOf("const selectedCase = useMemo", effectStart);
  const effect = appSource.slice(effectStart, effectEnd);

  assert.match(effect, /disposed[\s\S]*refreshInFlight[\s\S]*selectedCaseIdRef\.current !== activeScanCaseId/u);
  assert.match(effect, /refreshInFlight = true[\s\S]*loadSnapshot\(activeScanCaseId, true\)\.finally/u);
  assert.match(effect, /disposed = true/u);
  assert.match(effect, /window\.clearInterval\(interval\)/u);
  assert.match(effect, /window\.removeEventListener\("focus", onWindowFocus\)/u);
  assert.match(effect, /document\.removeEventListener\("visibilitychange", onVisibilityChange\)/u);

  const loadStart = appSource.indexOf("const loadSnapshot");
  const loadEnd = appSource.indexOf("useEffect(() =>", loadStart);
  const loadSnapshot = appSource.slice(loadStart, loadEnd);
  assert.match(loadSnapshot, /\+\+scanReadinessRequestGeneration\.current/u);
  assert.match(loadSnapshot, /workspaceEventGenerationAtRequest = scanWorkspaceEventGeneration\.current/u);
  assert.match(loadSnapshot, /isCurrentScanReadinessRequest/u);
  assert.match(loadSnapshot, /reconcileAuthoritativeSnapshot/u);
  assert.match(loadSnapshot, /observed\.generation > workspaceEventGenerationAtRequest/u);
  assert.match(loadSnapshot, /if \(!quiet\)[\s\S]*pushToast/u);
});
