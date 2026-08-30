import { execFileSync } from "node:child_process";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MAX_EVIDENCE_FILE_BYTES = 1024 * 1024;
const TASK_IDS = [
  "install_and_start",
  "create_case",
  "prepare_runtime",
  "connect_aws",
  "confirm_scope",
  "run_assessment",
  "interpret_coverage",
  "prepare_handoff",
  "inspect_cleanup",
];
const ARTIFACT_ROLES = [
  "consent-record",
  "observer-notes",
  "interaction-record",
  "case-export",
  "application-logs",
  "cloud-audit-cleanup",
];
const REQUIRED_ARTIFACT_ROLES = ARTIFACT_ROLES.filter((role) => role !== "application-logs");
const ASSISTANCE_CATEGORIES = [
  "repeat-neutral-prompt",
  "think-aloud-reminder",
  "lab-recovery",
  "operational-instruction",
  "takeover",
];

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function object(value, label, keys) {
  assert(isObject(value), `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${label} fields must be exactly ${expected.join(", ")}; received ${actual.join(", ")}`,
  );
  return value;
}

function string(value, label, { min = 1, max = 4096, pattern } = {}) {
  assert(typeof value === "string", `${label} must be a string`);
  assert(value.length >= min && value.length <= max, `${label} length is outside ${min}..${max}`);
  assert(!/\u0000/u.test(value), `${label} contains a NUL byte`);
  assert(!/^(?:todo|tbd|placeholder|example|unknown)$/iu.test(value.trim()), `${label} is a placeholder`);
  if (pattern) assert(pattern.test(value), `${label} has an invalid format`);
  return value;
}

function bool(value, label) {
  assert(typeof value === "boolean", `${label} must be a boolean`);
  return value;
}

function integer(value, label, min, max) {
  assert(Number.isInteger(value) && value >= min && value <= max, `${label} is outside ${min}..${max}`);
  return value;
}

function oneOf(value, label, choices) {
  assert(choices.includes(value), `${label} must be one of ${choices.join(", ")}`);
  return value;
}

function timestamp(value, label) {
  string(value, label, { max: 64 });
  assert(/(?:Z|[+-][0-9]{2}:[0-9]{2})$/u.test(value), `${label} must include a timezone`);
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds), `${label} must be a valid RFC 3339 timestamp`);
  return milliseconds;
}

function id(value, label) {
  return string(value, label, { max: 64, pattern: /^[a-z0-9][a-z0-9._-]{2,63}$/u });
}

function sha256(value, label) {
  return string(value, label, { min: 71, max: 71, pattern: /^sha256:[0-9a-f]{64}$/u });
}

function validateProduct(value, label) {
  const product = object(value, label, [
    "name",
    "version",
    "sourceCommit",
    "installerSha256",
    "os",
    "osVersion",
    "architecture",
    "runtimeProvider",
  ]);
  assert(product.name === "ai-security-scanner", `${label}.name is incorrect`);
  string(product.version, `${label}.version`, {
    max: 64,
    pattern: /^(?:0|[1-9][0-9]*)\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/u,
  });
  string(product.sourceCommit, `${label}.sourceCommit`, {
    min: 40,
    max: 40,
    pattern: /^[0-9a-f]{40}$/u,
  });
  sha256(product.installerSha256, `${label}.installerSha256`);
  oneOf(product.os, `${label}.os`, ["linux", "macos", "windows"]);
  string(product.osVersion, `${label}.osVersion`, { max: 256 });
  oneOf(product.architecture, `${label}.architecture`, ["x86_64", "aarch64"]);
  assert(product.runtimeProvider === "managed_local", `${label}.runtimeProvider must be managed_local`);
}

function validateParticipant(value, label) {
  const participant = object(value, label, [
    "pseudonymousId",
    "adult",
    "consentRecorded",
    "priorProductExposure",
    "securityBackground",
    "cloudIamExperience",
    "synthetic",
  ]);
  id(participant.pseudonymousId, `${label}.pseudonymousId`);
  assert(participant.adult === true, `${label}.adult must be true`);
  assert(participant.consentRecorded === true, `${label}.consentRecorded must be true`);
  assert(participant.priorProductExposure === "none", `${label}.priorProductExposure must be none`);
  assert(participant.securityBackground === "none", `${label}.securityBackground must be none`);
  assert(
    participant.cloudIamExperience === "cannot-create-or-explain-role",
    `${label}.cloudIamExperience does not meet the study criterion`,
  );
  assert(participant.synthetic === false, `${label}.synthetic must be false`);
}

function validateFacilitator(value, label) {
  const facilitator = object(value, label, ["pseudonymousId", "relationship", "conflictDisclosed"]);
  id(facilitator.pseudonymousId, `${label}.pseudonymousId`);
  oneOf(facilitator.relationship, `${label}.relationship`, ["independent-observer", "project-maintainer"]);
  bool(facilitator.conflictDisclosed, `${label}.conflictDisclosed`);
}

function validateTask(value, index, sessionStart, sessionEnd) {
  const label = `tasks[${index}]`;
  const task = object(value, label, [
    "id",
    "startedAt",
    "endedAt",
    "outcome",
    "attempts",
    "assistance",
    "observations",
  ]);
  oneOf(task.id, `${label}.id`, TASK_IDS);
  const startedAt = timestamp(task.startedAt, `${label}.startedAt`);
  const endedAt = timestamp(task.endedAt, `${label}.endedAt`);
  assert(startedAt >= sessionStart && endedAt <= sessionEnd && endedAt >= startedAt, `${label} time range is invalid`);
  oneOf(task.outcome, `${label}.outcome`, ["completed", "blocked", "abandoned"]);
  integer(task.attempts, `${label}.attempts`, 1, 100);
  assert(Array.isArray(task.assistance) && task.assistance.length <= 128, `${label}.assistance is invalid`);
  task.assistance.forEach((entry, assistanceIndex) => {
    const assistanceLabel = `${label}.assistance[${assistanceIndex}]`;
    const item = object(entry, assistanceLabel, ["at", "category", "detail"]);
    const at = timestamp(item.at, `${assistanceLabel}.at`);
    assert(at >= startedAt && at <= endedAt, `${assistanceLabel}.at is outside the task`);
    oneOf(item.category, `${assistanceLabel}.category`, ASSISTANCE_CATEGORIES);
    string(item.detail, `${assistanceLabel}.detail`);
  });
  assert(
    Array.isArray(task.observations) && task.observations.length >= 1 && task.observations.length <= 256,
    `${label}.observations must contain 1..256 entries`,
  );
  task.observations.forEach((entry, observationIndex) => {
    const observationLabel = `${label}.observations[${observationIndex}]`;
    const item = object(entry, observationLabel, ["at", "location", "severity", "detail"]);
    const at = timestamp(item.at, `${observationLabel}.at`);
    assert(at >= startedAt && at <= endedAt, `${observationLabel}.at is outside the task`);
    string(item.location, `${observationLabel}.location`);
    oneOf(item.severity, `${observationLabel}.severity`, ["note", "friction", "blocking", "critical"]);
    string(item.detail, `${observationLabel}.detail`);
  });
  return task;
}

function validateArtifact(value, index, recordCreatedAt) {
  const label = `artifacts[${index}]`;
  const artifact = object(value, label, [
    "role",
    "sha256",
    "sizeBytes",
    "capturedAt",
    "redacted",
    "containsSecrets",
    "retentionReference",
  ]);
  oneOf(artifact.role, `${label}.role`, ARTIFACT_ROLES);
  sha256(artifact.sha256, `${label}.sha256`);
  integer(artifact.sizeBytes, `${label}.sizeBytes`, 1, 10 * 1024 * 1024 * 1024);
  assert(timestamp(artifact.capturedAt, `${label}.capturedAt`) <= recordCreatedAt, `${label} was captured after record creation`);
  bool(artifact.redacted, `${label}.redacted`);
  assert(artifact.containsSecrets === false, `${label}.containsSecrets must be false`);
  string(artifact.retentionReference, `${label}.retentionReference`);
  return artifact;
}

export function validateEvidence(value, label = "evidence") {
  const evidence = object(value, label, [
    "schemaVersion",
    "studyId",
    "sessionId",
    "product",
    "participant",
    "facilitator",
    "session",
    "tasks",
    "artifacts",
    "comprehension",
    "cleanup",
    "decision",
    "attestations",
  ]);
  assert(evidence.schemaVersion === "1.0.0", `${label}.schemaVersion must be 1.0.0`);
  assert(evidence.studyId === "advanced-aws-iam-naive/v1", `${label}.studyId is incorrect`);
  id(evidence.sessionId, `${label}.sessionId`);
  validateProduct(evidence.product, `${label}.product`);
  validateParticipant(evidence.participant, `${label}.participant`);
  validateFacilitator(evidence.facilitator, `${label}.facilitator`);
  assert(
    evidence.participant.pseudonymousId !== evidence.facilitator.pseudonymousId,
    `${label} participant and facilitator IDs must differ`,
  );

  const session = object(evidence.session, `${label}.session`, [
    "mode",
    "startedAt",
    "endedAt",
    "cleanInstall",
    "emptyDataDirectory",
    "disposableAwsAccount",
    "promptVersion",
  ]);
  assert(session.mode === "observed-live", `${label}.session.mode must be observed-live`);
  const sessionStart = timestamp(session.startedAt, `${label}.session.startedAt`);
  const sessionEnd = timestamp(session.endedAt, `${label}.session.endedAt`);
  assert(sessionEnd > sessionStart, `${label}.session must have positive duration`);
  assert(session.cleanInstall === true, `${label}.session.cleanInstall must be true`);
  assert(session.emptyDataDirectory === true, `${label}.session.emptyDataDirectory must be true`);
  assert(session.disposableAwsAccount === true, `${label}.session.disposableAwsAccount must be true`);
  assert(session.promptVersion === "advanced-aws-iam-naive/v1", `${label}.session.promptVersion is incorrect`);

  assert(Array.isArray(evidence.tasks) && evidence.tasks.length === TASK_IDS.length, `${label}.tasks must contain exactly nine tasks`);
  const tasks = evidence.tasks.map((task, index) => validateTask(task, index, sessionStart, sessionEnd));
  const taskIds = tasks.map((task) => task.id);
  assert(new Set(taskIds).size === TASK_IDS.length, `${label}.tasks contains a duplicate task ID`);
  assert(
    TASK_IDS.every((taskId) => taskIds.includes(taskId)),
    `${label}.tasks must contain every required task ID`,
  );

  const attestations = object(evidence.attestations, `${label}.attestations`, [
    "participantConfirmedAt",
    "facilitatorAttestedAt",
    "recordCreatedAt",
  ]);
  const participantConfirmedAt = timestamp(attestations.participantConfirmedAt, `${label}.attestations.participantConfirmedAt`);
  const facilitatorAttestedAt = timestamp(attestations.facilitatorAttestedAt, `${label}.attestations.facilitatorAttestedAt`);
  const recordCreatedAt = timestamp(attestations.recordCreatedAt, `${label}.attestations.recordCreatedAt`);
  assert(participantConfirmedAt >= sessionEnd, `${label} participant confirmation predates session end`);
  assert(facilitatorAttestedAt >= sessionEnd, `${label} facilitator attestation predates session end`);
  assert(recordCreatedAt >= participantConfirmedAt && recordCreatedAt >= facilitatorAttestedAt, `${label} record was created before attestation`);

  assert(
    Array.isArray(evidence.artifacts) && evidence.artifacts.length >= 5 && evidence.artifacts.length <= 32,
    `${label}.artifacts must contain 5..32 entries`,
  );
  const artifacts = evidence.artifacts.map((artifact, index) => validateArtifact(artifact, index, recordCreatedAt));
  const artifactRoles = artifacts.map((artifact) => artifact.role);
  assert(new Set(artifactRoles).size === artifactRoles.length, `${label}.artifacts contains a duplicate role`);
  assert(
    REQUIRED_ARTIFACT_ROLES.every((role) => artifactRoles.includes(role)),
    `${label}.artifacts lacks a required role`,
  );
  assert(new Set(artifacts.map((artifact) => artifact.sha256)).size === artifacts.length, `${label}.artifacts repeats a digest`);

  const comprehension = object(evidence.comprehension, `${label}.comprehension`, [
    "unknownIsNotGreen",
    "coverageStatesExplained",
    "noComplianceClaim",
    "nextExpertIdentified",
    "participantWords",
  ]);
  for (const field of ["unknownIsNotGreen", "coverageStatesExplained", "noComplianceClaim", "nextExpertIdentified"]) {
    bool(comprehension[field], `${label}.comprehension.${field}`);
  }
  string(comprehension.participantWords, `${label}.comprehension.participantWords`);

  const cleanup = object(evidence.cleanup, `${label}.cleanup`, [
    "bootstrapCredentialCleared",
    "scannerIdentityInspected",
    "oldSessionsAndKeysReviewed",
    "runtimeCleanupInspected",
    "secretExposureObserved",
  ]);
  for (const field of Object.keys(cleanup)) bool(cleanup[field], `${label}.cleanup.${field}`);

  const decision = object(evidence.decision, `${label}.decision`, [
    "outcome",
    "decidedAt",
    "evaluatorId",
    "rationale",
    "unresolvedBlockers",
  ]);
  oneOf(decision.outcome, `${label}.decision.outcome`, ["pass", "fail", "inconclusive"]);
  assert(timestamp(decision.decidedAt, `${label}.decision.decidedAt`) >= sessionEnd, `${label}.decision predates session end`);
  id(decision.evaluatorId, `${label}.decision.evaluatorId`);
  string(decision.rationale, `${label}.decision.rationale`);
  assert(Array.isArray(decision.unresolvedBlockers) && decision.unresolvedBlockers.length <= 64, `${label}.decision.unresolvedBlockers is invalid`);
  decision.unresolvedBlockers.forEach((entry, index) => string(entry, `${label}.decision.unresolvedBlockers[${index}]`));

  if (decision.outcome === "pass") {
    assert(tasks.every((task) => task.outcome === "completed"), `${label} pass requires every task to complete`);
    assert(
      tasks.every((task) => task.assistance.every((entry) => !["operational-instruction", "takeover"].includes(entry.category))),
      `${label} pass cannot include operational instruction or takeover`,
    );
    assert(
      tasks.every((task) => task.observations.every((entry) => entry.severity !== "critical")),
      `${label} pass cannot contain a critical observation`,
    );
    assert(Object.entries(comprehension).every(([key, value]) => key === "participantWords" || value === true), `${label} pass requires all comprehension checks`);
    assert(
      cleanup.bootstrapCredentialCleared &&
        cleanup.scannerIdentityInspected &&
        cleanup.oldSessionsAndKeysReviewed &&
        cleanup.runtimeCleanupInspected &&
        !cleanup.secretExposureObserved,
      `${label} pass requires complete, secret-safe cleanup`,
    );
    assert(decision.unresolvedBlockers.length === 0, `${label} pass cannot retain unresolved blockers`);
  }
  if (cleanup.secretExposureObserved) {
    assert(decision.outcome === "fail", `${label} secret exposure must produce a failed decision`);
  }

  return evidence;
}

async function readEvidenceFile(file) {
  const metadata = await lstat(file);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), `${file} must be a regular non-symlink file`);
  assert(metadata.size > 0 && metadata.size <= MAX_EVIDENCE_FILE_BYTES, `${file} exceeds the evidence file size boundary`);
  let value;
  try {
    value = JSON.parse(await readFile(file, "utf8"));
  } catch {
    fail(`${file} is not valid JSON`);
  }
  return validateEvidence(value, path.basename(file));
}

async function validateContract() {
  const schemaPath = path.join(PROJECT_ROOT, "docs/usability/session-evidence.schema.json");
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  assert(schema.$schema === "https://json-schema.org/draft/2020-12/schema", "usability schema draft is incorrect");
  const schemaTasks = schema.$defs?.task?.properties?.id?.enum;
  const schemaRoles = schema.$defs?.artifact?.properties?.role?.enum;
  const schemaAssistance = schema.$defs?.assistance?.properties?.category?.enum;
  assert(JSON.stringify(schemaTasks) === JSON.stringify(TASK_IDS), "validator task IDs differ from the JSON schema");
  assert(JSON.stringify(schemaRoles) === JSON.stringify(ARTIFACT_ROLES), "validator artifact roles differ from the JSON schema");
  assert(JSON.stringify(schemaAssistance) === JSON.stringify(ASSISTANCE_CATEGORIES), "validator assistance categories differ from the JSON schema");
}

function currentCommit() {
  return execFileSync("git", ["rev-parse", "HEAD"], { cwd: PROJECT_ROOT, encoding: "utf8" }).trim();
}

function workingTreeIsClean() {
  return execFileSync("git", ["status", "--porcelain"], { cwd: PROJECT_ROOT, encoding: "utf8" }).trim() === "";
}

async function currentVersion() {
  return JSON.parse(await readFile(path.join(PROJECT_ROOT, "package.json"), "utf8")).version;
}

async function main() {
  await validateContract();
  const args = process.argv.slice(2);
  const files = [];
  let evidenceDirectory;
  let requireCurrentPass = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--evidence") {
      const value = args[++index];
      assert(value, "--evidence requires a file path");
      files.push(path.resolve(value));
    } else if (argument === "--evidence-dir") {
      const value = args[++index];
      assert(value && !evidenceDirectory, "--evidence-dir requires one directory path");
      evidenceDirectory = path.resolve(value);
    } else if (argument === "--require-current-pass") {
      requireCurrentPass = true;
    } else if (argument === "--check-contract") {
      // Contract validation already ran before argument handling.
    } else {
      fail(`unknown argument: ${argument}`);
    }
  }

  if (evidenceDirectory) {
    const metadata = await lstat(evidenceDirectory);
    assert(metadata.isDirectory() && !metadata.isSymbolicLink(), "evidence directory must be a non-symlink directory");
    const entries = (await readdir(evidenceDirectory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    assert(entries.length <= 64, "evidence directory contains more than 64 entries");
    for (const entry of entries) {
      assert(entry.isFile() && !entry.isSymbolicLink() && entry.name.endsWith(".json"), `invalid evidence directory entry: ${entry.name}`);
      files.push(path.join(evidenceDirectory, entry.name));
    }
  }

  if (files.length === 0) {
    assert(!requireCurrentPass, "--require-current-pass requires evidence files");
    console.log("IAM-naive usability evidence contract is structurally consistent; no human session was supplied or claimed.");
    return;
  }

  assert(new Set(files).size === files.length, "the same evidence file was supplied more than once");
  const records = [];
  for (const file of files) records.push(await readEvidenceFile(file));
  const sessionIds = records.map((record) => record.sessionId);
  assert(new Set(sessionIds).size === sessionIds.length, "usability evidence repeats a session ID");

  if (requireCurrentPass) {
    assert(workingTreeIsClean(), "current-pass validation requires a clean release-candidate worktree");
    const commit = currentCommit();
    const version = await currentVersion();
    const passing = records.filter(
      (record) =>
        record.decision.outcome === "pass" &&
        record.product.sourceCommit === commit &&
        record.product.version === version,
    );
    assert(
      passing.length >= 1,
      `no passing live session is bound to current version ${version} and commit ${commit}`,
    );
  }

  const outcomes = records.reduce((counts, record) => {
    counts[record.decision.outcome] += 1;
    return counts;
  }, { pass: 0, fail: 0, inconclusive: 0 });
  console.log(`Validated ${records.length} IAM-naive live session record(s): ${outcomes.pass} pass, ${outcomes.fail} fail, ${outcomes.inconclusive} inconclusive.`);
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`Usability evidence validation failed: ${error.message}`);
    process.exitCode = 1;
  });
}
