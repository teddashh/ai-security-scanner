#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const V019_BEGINNER_EVIDENCE_FILE =
  "human-path-qualification-windows-x86_64-nsis.json";

const MAX_EVIDENCE_BYTES = 1024 * 1024;
const SCRIPT_ROOT = path.dirname(fileURLToPath(import.meta.url));
const EXPECTED_EVIDENCE = Object.freeze({
  label: "v0.1.9 Windows beginner human-path evidence",
  evidenceType: "beginner-human-path",
  platform: "windows-x86_64",
  installerType: "nsis",
  version: "0.1.9",
  tag: "v0.1.9",
  commit: "5c95572f54220adbd170d9bfb5af3159c56708ef",
  artifact: Object.freeze({
    file: "ai-security-scanner_0.1.9_x64-setup.exe",
    bytes: 40_186_968,
    sha256: "f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e",
  }),
});

class SafeValidationError extends Error {
  constructor(code) {
    super("local validation failed");
    this.safeCode = code;
  }
}

function fail(code) {
  throw new SafeValidationError(code);
}

function metadataMatches(before, after) {
  return before.isFile()
    && after.isFile()
    && !before.isSymbolicLink()
    && !after.isSymbolicLink()
    && before.dev === after.dev
    && before.ino === after.ino
    && before.mode === after.mode
    && before.nlink === after.nlink
    && before.size === after.size
    && before.mtimeMs === after.mtimeMs
    && before.ctimeMs === after.ctimeMs;
}

async function requireStrictInventory(evidenceRoot) {
  let rootMetadata;
  try {
    rootMetadata = await lstat(evidenceRoot);
  } catch {
    fail("REDACTED_OUTPUT_UNAVAILABLE");
  }
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    fail("REDACTED_OUTPUT_NOT_PLAIN_DIRECTORY");
  }

  let entries;
  try {
    entries = await readdir(evidenceRoot, { withFileTypes: true });
  } catch {
    fail("REDACTED_OUTPUT_UNREADABLE");
  }
  if (
    entries.length !== 1
    || entries[0].name !== V019_BEGINNER_EVIDENCE_FILE
    || !entries[0].isFile()
    || entries[0].isSymbolicLink()
  ) {
    fail("REDACTED_OUTPUT_INVENTORY_INVALID");
  }
}

async function validateV019BeginnerHumanPath() {
  const evidenceRoot = path.join(SCRIPT_ROOT, "redacted-output");
  const evidencePath = path.join(evidenceRoot, V019_BEGINNER_EVIDENCE_FILE);

  await requireStrictInventory(evidenceRoot);

  let before;
  let bytes;
  let after;
  try {
    before = await lstat(evidencePath);
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1
      || before.size <= 0
      || before.size > MAX_EVIDENCE_BYTES
    ) {
      fail("EVIDENCE_FILE_INVALID");
    }
    bytes = await readFile(evidencePath);
    after = await lstat(evidencePath);
  } catch (error) {
    if (error?.safeCode) throw error;
    fail("EVIDENCE_READ_FAILED");
  }
  if (bytes.length !== before.size || !metadataMatches(before, after)) {
    fail("EVIDENCE_CHANGED_DURING_READ");
  }

  // Recheck the directory after the read so a concurrently added supporting
  // file cannot be hidden by a successful validation of the canonical record.
  await requireStrictInventory(evidenceRoot);

  let evidence;
  try {
    evidence = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("EVIDENCE_JSON_INVALID");
  }

  let validateBoundArtifactEvidence;
  try {
    ({ validateBoundArtifactEvidence } = await import("./artifact-evidence.mjs"));
  } catch {
    fail("VALIDATOR_MODULE_UNAVAILABLE");
  }
  try {
    validateBoundArtifactEvidence(evidence, EXPECTED_EVIDENCE);
  } catch {
    fail("EVIDENCE_SCHEMA_INVALID");
  }

  await requireStrictInventory(evidenceRoot);
  let afterValidation;
  try {
    afterValidation = await lstat(evidencePath);
  } catch {
    fail("EVIDENCE_CHANGED_DURING_VALIDATION");
  }
  if (!metadataMatches(before, afterValidation)) {
    fail("EVIDENCE_CHANGED_DURING_VALIDATION");
  }

  return Object.freeze({
    lane: "BEGINNER",
    localValidator: "passed",
    evidenceFile: V019_BEGINNER_EVIDENCE_FILE,
    evidenceBytes: bytes.length,
    evidenceSha256: createHash("sha256").update(bytes).digest("hex"),
  });
}

async function main() {
  if (process.argv.length !== 2) fail("ARGUMENT_OVERRIDE_REJECTED");
  const summary = await validateV019BeginnerHumanPath();
  process.stdout.write(`${JSON.stringify(summary)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const errorCode = typeof error?.safeCode === "string" && /^[A-Z0-9_]+$/u.test(error.safeCode)
      ? error.safeCode
      : "UNEXPECTED_LOCAL_VALIDATOR_ERROR";
    process.stderr.write(
      `${JSON.stringify({
        lane: "BEGINNER",
        localValidator: "failed",
        evidenceClaim: "not-accepted-locally",
        errorCode,
      })}\n`,
    );
    process.exitCode = 1;
  });
}
