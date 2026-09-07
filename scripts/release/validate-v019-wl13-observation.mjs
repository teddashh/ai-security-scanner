#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_HANDOFF_ROOT = path.resolve(SCRIPT_DIRECTORY, "../..");
const MAX_RECORD_BYTES = 256 * 1024;
const OUTPUT_DIRECTORY = "redacted-output";
const LIFECYCLE_DIRECTORY = "windows-installed-lifecycle";
const ROW_DIRECTORY = "wl-13";
const RECORD_FILENAME = "runtime_reconciliation.json";
const RECORD_RELATIVE_PATH = `${OUTPUT_DIRECTORY}/${LIFECYCLE_DIRECTORY}/${ROW_DIRECTORY}/${RECORD_FILENAME}`;

const V019_WL13_APPROVED_HARNESS_POLICIES = Object.freeze({
  "WL-13": Object.freeze({
    kind: "checked-in-version-pinned",
    repository: "teddashh/ai-security-scanner",
    sourceCommit: "bd47e26b6c8024eb3461176637d7fce3e8370561",
    path: "scripts/release/windows-localhost-fixture.mjs",
    sha256: "de31dceede3f1aafcdc222d9c91f68913d69e077baa3a663577d62ac0354973a",
    contractVersion: 1,
    fixtureRuntime: Object.freeze({
      name: "node",
      version: "v24.15.0",
      platform: "win32",
      architecture: "x64",
      distribution: Object.freeze({
        file: "node-v24.15.0-win-x64.zip",
        bytes: 36_465_163,
        sha256: "cc5149eabd53779ce1e7bdc5401643622d0c7e6800ade18928a767e940bb0e62",
      }),
      executable: Object.freeze({
        file: "node.exe",
        bytes: 91_694_408,
        sha256: "3331e1ffe19874215472217c5e94f5a0c6d8e18c4ac7111d3937aa0ad5e9b4a5",
      }),
    }),
  }),
});

export const V019_WL13_EVIDENCE_POLICY = Object.freeze({
  rowId: "WL-13",
  boundary: "runtime_reconciliation",
  platform: "windows-x86_64",
  architecture: "x86_64",
  installerType: "nsis",
  version: "0.1.9",
  tag: "v0.1.9",
  commit: "5c95572f54220adbd170d9bfb5af3159c56708ef",
  releaseChannel: "prerelease",
  artifact: Object.freeze({
    file: "ai-security-scanner_0.1.9_x64-setup.exe",
    bytes: 40_186_968,
    sha256: "f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e",
  }),
  runtimeManifest: Object.freeze({
    file: "managed-runtime-windows-x86_64.manifest.json",
    bytes: 3_724,
    sha256: "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a",
    managementContractRevision: "2026-08-29.1",
  }),
  requireApprovedHarness: true,
  harnesses: V019_WL13_APPROVED_HARNESS_POLICIES,
});

function fail(code) {
  const error = new Error("WL-13 local validation failed");
  error.safeCode = code;
  throw error;
}

async function plainMetadata(target, unavailableCode) {
  try {
    return await lstat(target);
  } catch {
    fail(unavailableCode);
  }
}

async function onlyEntry(directory, expectedName, expectedType) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    fail("REDACTED_OUTPUT_UNREADABLE");
  }
  if (entries.length !== 1 || entries[0].name !== expectedName) {
    fail("REDACTED_OUTPUT_INVENTORY_INVALID");
  }

  const entryPath = path.join(directory, expectedName);
  const metadata = await plainMetadata(entryPath, "REDACTED_OUTPUT_INVENTORY_INVALID");
  const hasExpectedType = expectedType === "directory" ? metadata.isDirectory() : metadata.isFile();
  if (metadata.isSymbolicLink() || !hasExpectedType) {
    fail("REDACTED_OUTPUT_INVENTORY_INVALID");
  }
  if (expectedType === "file" && metadata.nlink !== 1) {
    fail("WL13_RECORD_NOT_INDEPENDENT_FILE");
  }
  return { path: entryPath, metadata };
}

async function inspectExactOutputTree(handoffRoot) {
  const outputRoot = path.join(handoffRoot, OUTPUT_DIRECTORY);
  const rootMetadata = await plainMetadata(outputRoot, "REDACTED_OUTPUT_UNAVAILABLE");
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    fail("REDACTED_OUTPUT_NOT_PLAIN_DIRECTORY");
  }

  const lifecycle = await onlyEntry(outputRoot, LIFECYCLE_DIRECTORY, "directory");
  const row = await onlyEntry(lifecycle.path, ROW_DIRECTORY, "directory");
  const record = await onlyEntry(row.path, RECORD_FILENAME, "file");
  if (record.metadata.size <= 0 || record.metadata.size > MAX_RECORD_BYTES) {
    fail("WL13_RECORD_FILE_INVALID");
  }
  return record;
}

function sameFileSnapshot(before, after) {
  return (
    after.isFile()
    && !after.isSymbolicLink()
    && before.dev === after.dev
    && before.ino === after.ino
    && before.mode === after.mode
    && before.nlink === after.nlink
    && before.size === after.size
    && before.mtimeMs === after.mtimeMs
    && before.ctimeMs === after.ctimeMs
  );
}

export async function validateV019Wl13ObservationAtRoot(handoffRoot) {
  if (typeof handoffRoot !== "string" || !path.isAbsolute(handoffRoot) || handoffRoot.includes("\0")) {
    fail("HANDOFF_ROOT_INVALID");
  }

  const before = await inspectExactOutputTree(handoffRoot);
  let bytes;
  try {
    bytes = await readFile(before.path);
  } catch {
    fail("WL13_RECORD_READ_FAILED");
  }
  const afterRead = await plainMetadata(before.path, "WL13_RECORD_CHANGED_DURING_READ");
  if (bytes.length !== before.metadata.size || !sameFileSnapshot(before.metadata, afterRead)) {
    fail("WL13_RECORD_CHANGED_DURING_READ");
  }

  let record;
  try {
    record = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("WL13_RECORD_JSON_INVALID");
  }
  if (!["passed", "failed", "inconclusive"].includes(record?.outcome)) {
    fail("WL13_RECORD_POLICY_INVALID");
  }
  let validateWindowsInstalledLifecycleEvidence;
  try {
    ({ validateWindowsInstalledLifecycleEvidence } = await import(
      "./windows-installed-lifecycle-evidence.mjs"
    ));
  } catch {
    fail("VALIDATOR_MODULE_UNAVAILABLE");
  }
  try {
    validateWindowsInstalledLifecycleEvidence(record, {
      ...V019_WL13_EVIDENCE_POLICY,
      label: "v0.1.9 WL-13 installed-lifecycle observation",
    });
  } catch {
    fail("WL13_RECORD_POLICY_INVALID");
  }

  const afterValidation = await inspectExactOutputTree(handoffRoot);
  if (!sameFileSnapshot(before.metadata, afterValidation.metadata)) {
    fail("WL13_RECORD_CHANGED_DURING_VALIDATION");
  }

  return Object.freeze({
    lane: "WINDOWS-INSTALLED-LIFECYCLE",
    localValidator: "passed",
    rowId: "WL-13",
    boundary: "runtime_reconciliation",
    recordOutcome: record.outcome,
    evidenceFile: RECORD_RELATIVE_PATH,
    evidenceBytes: bytes.length,
    evidenceSha256: createHash("sha256").update(bytes).digest("hex"),
  });
}

async function main() {
  try {
    if (process.argv.length !== 2) fail("ARGUMENT_OVERRIDE_REJECTED");
    const summary = await validateV019Wl13ObservationAtRoot(DEFAULT_HANDOFF_ROOT);
    process.stdout.write(`${JSON.stringify(summary)}\n`);
  } catch (error) {
    const safeCode = typeof error?.safeCode === "string" && /^[A-Z0-9_]+$/u.test(error.safeCode)
      ? error.safeCode
      : "UNEXPECTED_LOCAL_VALIDATOR_ERROR";
    process.stderr.write(
      `${JSON.stringify({
        lane: "WINDOWS-INSTALLED-LIFECYCLE",
        localValidator: "failed",
        rowId: "WL-13",
        boundary: "runtime_reconciliation",
        errorCode: safeCode,
      })}\n`,
    );
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
