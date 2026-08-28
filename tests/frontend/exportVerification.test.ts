import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readSource = (path: string) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("case-bundle verification has distinct typed demo, success, and native-failure outcomes", async () => {
  const scanner = await readSource("src/services/scanner.ts");
  const start = scanner.indexOf("export type CaseExportVerificationResult");
  const end = scanner.indexOf("export interface ScopeApprovalInput", start);
  const resultType = scanner.slice(start, end);
  assert.ok(start >= 0 && end > start);
  for (const outcome of ["verified", "native_failed", "demo_unavailable"]) {
    assert.match(resultType, new RegExp(`outcome: "${outcome}"`, "u"));
  }

  const verificationStart = scanner.indexOf("async verifyCaseExport");
  const verificationEnd = scanner.indexOf("async chooseCaseBundle", verificationStart);
  const verification = scanner.slice(verificationStart, verificationEnd);
  assert.match(verification, /outcome: "demo_unavailable"/u);
  assert.match(verification, /outcome: accepted \? "verified" : "native_failed"/u);
  assert.match(verification, /response\.accepted === true/u, "malformed native responses must fail closed");
  assert.match(verification, /catch \(error\)[\s\S]*outcome: "native_failed"/u);
  assert.doesNotMatch(verification, /accepted: false/u);
});

test("native verification failures use danger copy without rendering native error text", async () => {
  const app = await readSource("src/App.tsx");
  const copyStart = app.indexOf("const caseExportVerificationCopy");
  const copyEnd = app.indexOf("interface NonExecutionActionToastCopy", copyStart);
  const copy = app.slice(copyStart, copyEnd);
  assert.match(copy, /native_failed:[\s\S]*tone: "danger"/u);
  assert.match(copy, /demo_unavailable:[\s\S]*tone: "info"/u);
  assert.match(copy, /Do not trust or share this package/u);
  assert.match(copy, /請勿信任或分享這份案件包/u);

  const verifyStart = app.indexOf("const verifyExport = async");
  const verifyEnd = app.indexOf("const verifyReceivedExport", verifyStart);
  const verify = app.slice(verifyStart, verifyEnd);
  assert.match(verify, /caseExportVerificationCopy\[result\.data\.outcome\]/u);
  assert.match(verify, /result\.data\.outcome === "native_failed"[\s\S]*recordTechnicalError\("verify case export", result\.data\.message\)/u);
  assert.doesNotMatch(verify, /text\(result\.data\.message\)|detail:\s*result\.data\.message/u);
  assert.doesNotMatch(verify, /result\.data\.accepted/u);
});
