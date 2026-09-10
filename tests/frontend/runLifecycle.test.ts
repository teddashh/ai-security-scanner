import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  isTerminalResultRun,
  isVerificationBaselineRun,
} from "../../src/runLifecycle.ts";
import type { RunStatus } from "../../src/types.ts";

test("result routes and verification baselines use distinct terminal sets", () => {
  const resultStatuses: RunStatus[] = [
    "completed",
    "no_checks_completed",
    "partial",
    "failed",
    "cancelled",
  ];
  for (const status of resultStatuses) assert.equal(isTerminalResultRun({ status }), true, status);
  for (const status of ["queued", "running", "paused"] as const) {
    assert.equal(isTerminalResultRun({ status }), false, status);
  }

  for (const status of ["completed", "partial", "failed", "cancelled"] as const) {
    assert.equal(isVerificationBaselineRun({ status }), true, status);
  }
  for (const status of ["queued", "running", "paused", "no_checks_completed"] as const) {
    assert.equal(isVerificationBaselineRun({ status }), false, status);
  }
});

test("case entry uses result eligibility while verification uses baseline eligibility", async () => {
  const [app, cases, verification] = await Promise.all([
    readFile(new URL("../../src/App.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/pages/CasesPage.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/pages/VerificationPage.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(app, /workspace\.runs\.find\(isTerminalResultRun\)/u);
  assert.match(app, /workspace\?\.runs\.filter\(isVerificationBaselineRun\)/u);
  assert.match(cases, /const terminalResultRuns = runs\.filter\(isTerminalResultRun\)/u);
  assert.match(cases, /const verificationBaselineRuns = runs\.filter\(isVerificationBaselineRun\)/u);
  assert.match(verification, /runs\.filter\(isVerificationBaselineRun\)/u);
});
