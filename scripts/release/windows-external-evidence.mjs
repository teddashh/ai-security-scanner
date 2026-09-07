#!/usr/bin/env node

import { constants } from "node:fs";
import { copyFile, lstat, mkdir, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  RELEASE_CANDIDATE_LOCK_FILE,
  verifyReleaseCandidateLock,
} from "./release-candidate-lock.mjs";
import {
  assertSafeRelativePath,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  toPosix,
  writeJsonAtomic,
} from "./lib.mjs";
import {
  verifyBoundArtifactEvidenceFile,
} from "./artifact-evidence.mjs";
import {
  WINDOWS_INSTALLED_LIFECYCLE_RECORDS,
  verifyWindowsInstalledLifecycleEvidenceDirectory,
} from "./windows-installed-lifecycle-evidence.mjs";

export const WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE = "windows-external-evidence-import.json";
export const WINDOWS_HUMAN_PATH_FILE = "human-path-qualification-windows-x86_64-nsis.json";
export const WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE =
  "unsigned-os-signing-observation-windows-x86_64-nsis.json";
export const WINDOWS_LIFECYCLE_DIRECTORY = "windows-installed-lifecycle";

const PRODUCT = "ai-security-scanner";
const PLATFORM = "windows-x86_64";
const INSTALLER_TYPE = "nsis";
const CANDIDATE_WORKFLOW = ".github/workflows/release.yml";
const CANDIDATE_JOB = "finalize-supported-artifacts";
const MAX_RECEIPT_BYTES = 1024 * 1024;
const MAX_EXTERNAL_FILES = WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length + 3;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} fields are not the Windows external-evidence schema-v1 set`,
  );
}

function boundedText(value, label, maximum = 500) {
  assert(
    typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\0\r\n]/u.test(value),
    `${label} must be non-empty bounded single-line text`,
  );
}

function positiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  const source = typeof value === "number" ? String(value) : value;
  assert(typeof source === "string" && /^[1-9][0-9]*$/u.test(source), `${label} must be a positive integer`);
  const parsed = Number(source);
  assert(Number.isSafeInteger(parsed) && parsed <= maximum, `${label} exceeds its supported range`);
  return parsed;
}

function canonicalRunId(value, label) {
  return String(positiveInteger(value, label));
}

function digest(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{64}$/u.test(value), `${label} must be a lowercase SHA-256`);
}

function artifactDigest(value, label) {
  assert(typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value), `${label} must be an artifact SHA-256`);
}

function repository(value, label) {
  assert(
    typeof value === "string" && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(value),
    `${label} is invalid`,
  );
}

function workflowPath(value, label) {
  assert(
    typeof value === "string" && /^\.github\/workflows\/[A-Za-z0-9._-]+\.ya?ml$/u.test(value),
    `${label} is invalid`,
  );
}

function fullSha(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{40}$/u.test(value), `${label} must be a full lowercase Git object ID`);
}

function flatFile(value, label) {
  boundedText(value, label, 255);
  assert(
    path.posix.basename(value) === value && path.win32.basename(value) === value && value !== "." && value !== "..",
    `${label} must be one flat filename`,
  );
}

function safePosixPath(value, label) {
  boundedText(value, label, 512);
  assertSafeRelativePath(value);
  assert(value === value.split("\\").join("/") && value === path.posix.normalize(value), `${label} is not canonical POSIX`);
  assert(!value.split("/").includes("."), `${label} contains a dot component`);
}

function validateReleaseIdentity(identity, label) {
  exactKeys(identity, ["version", "tag", "sourceCommit", "releaseChannel", "publicationMode"], label);
  assert(isSemver(identity.version) && identity.tag === `v${identity.version}`, `${label} version/tag is invalid`);
  fullSha(identity.sourceCommit, `${label} sourceCommit`);
  assert(["prerelease", "stable"].includes(identity.releaseChannel), `${label} release channel is invalid`);
  assert(
    ["commit-bound-qc", "public-github-release"].includes(identity.publicationMode),
    `${label} publication mode is invalid`,
  );
}

function validateArtifactIdentity(artifact, label) {
  exactKeys(artifact, ["file", "bytes", "sha256"], label);
  flatFile(artifact.file, `${label} file`);
  assert(Number.isSafeInteger(artifact.bytes) && artifact.bytes > 0, `${label} byte count is invalid`);
  digest(artifact.sha256, `${label} sha256`);
}

function validateRuntimeManifestIdentity(runtimeManifest, label) {
  exactKeys(runtimeManifest, ["file", "bytes", "sha256", "managementContractRevision"], label);
  assert(
    runtimeManifest.file === "managed-runtime-windows-x86_64.manifest.json",
    `${label} names the wrong runtime manifest`,
  );
  assert(Number.isSafeInteger(runtimeManifest.bytes) && runtimeManifest.bytes > 0, `${label} byte count is invalid`);
  digest(runtimeManifest.sha256, `${label} sha256`);
  boundedText(runtimeManifest.managementContractRevision, `${label} management contract revision`, 64);
}

function producerIdentity({ provider = "github-actions", repository: repository_, workflow, workflowSha, runId, runAttempt, job, environment }) {
  assert(provider === "github-actions", "external-evidence producer provider must be github-actions");
  repository(repository_, "external-evidence producer repository");
  workflowPath(workflow, "external-evidence producer workflow");
  fullSha(workflowSha, "external-evidence producer workflow SHA");
  const result = {
    provider,
    repository: repository_,
    workflow,
    workflowRef: `${repository_}/${workflow}@${workflowSha}`,
    workflowSha,
    runId: canonicalRunId(runId, "external-evidence producer run ID"),
    runAttempt: positiveInteger(runAttempt, "external-evidence producer run attempt", 100),
    job,
  };
  boundedText(job, "external-evidence producer job");
  if (environment !== undefined) {
    boundedText(environment, "external-evidence producer environment");
    result.environment = environment;
  }
  return result;
}

export function windowsExternalEvidenceImporterIdentity(inputs) {
  return producerIdentity(inputs);
}

async function regularFiles(directory, root = directory, output = [], maximum = 1024) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    const metadata = await lstat(absolute);
    assert(!metadata.isSymbolicLink(), `external evidence contains a symlink: ${absolute}`);
    if (metadata.isDirectory()) {
      await regularFiles(absolute, root, output, maximum);
    } else {
      assert(metadata.isFile(), `external evidence contains a special file: ${absolute}`);
      const relative = toPosix(path.relative(root, absolute));
      safePosixPath(relative, "external-evidence path");
      output.push({ absolute, relative, bytes: metadata.size });
      assert(output.length <= maximum, "file inventory exceeds its bounded maximum");
    }
  }
  return output;
}

async function ensureEmptyOutput(directory) {
  try {
    const metadata = await lstat(directory);
    assert(metadata.isDirectory() && !metadata.isSymbolicLink(), `${directory} must be a real output directory`);
    assert((await readdir(directory)).length === 0, `${directory} must start empty`);
  } catch (error) {
    if (!error || typeof error !== "object" || error.code !== "ENOENT") throw error;
    await mkdir(directory, { recursive: true });
  }
}

async function copyRegularFile(source, destination) {
  const metadata = await lstat(source);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), `${source} is not a regular non-symlink file`);
  await mkdir(path.dirname(destination), { recursive: true });
  await copyFile(source, destination, constants.COPYFILE_EXCL);
}

async function copyRegularTree(source, destination) {
  for (const file of await regularFiles(source)) {
    await copyRegularFile(file.absolute, path.join(destination, file.relative));
  }
}

function candidateInputsFromArgs(args) {
  return {
    version: requireString(args, "candidate-version"),
    tag: requireString(args, "candidate-tag"),
    commit: requireString(args, "candidate-commit"),
    releaseChannel: requireString(args, "candidate-release-channel"),
    publicationMode: requireString(args, "candidate-publication-mode"),
    repository: requireString(args, "candidate-repository"),
    workflow: requireString(args, "candidate-workflow"),
    workflowSha: requireString(args, "candidate-workflow-sha"),
    runId: requireString(args, "candidate-run-id"),
    runAttempt: requireString(args, "candidate-run-attempt"),
    job: requireString(args, "candidate-job"),
  };
}

function importerFromPrefixedArgs(args) {
  return producerIdentity({
    repository: requireString(args, "importer-repository"),
    workflow: requireString(args, "importer-workflow"),
    workflowSha: requireString(args, "importer-workflow-sha"),
    runId: requireString(args, "importer-run-id"),
    runAttempt: requireString(args, "importer-run-attempt"),
    job: requireString(args, "importer-job"),
    environment: requireString(args, "importer-environment"),
  });
}

function importerExpectedFromArgs(args) {
  const workflowRef = requireString(args, "workflow-ref");
  const separator = workflowRef.lastIndexOf("@");
  assert(separator > 0, "--workflow-ref must end in a full workflow SHA");
  const workflowSha = workflowRef.slice(separator + 1);
  const expected = producerIdentity({
    repository: requireString(args, "repository"),
    workflow: requireString(args, "workflow"),
    workflowSha,
    runId: requireString(args, "run-id"),
    runAttempt: requireString(args, "run-attempt"),
    job: requireString(args, "job"),
    environment: requireString(args, "environment"),
  });
  assert(expected.workflowRef === workflowRef, "external-evidence workflow ref differs from its repository/path/SHA");
  return expected;
}

async function verifyCandidate(directory, expected) {
  assert(expected.workflow === CANDIDATE_WORKFLOW, "candidate was not produced by the release candidate workflow");
  assert(expected.job === CANDIDATE_JOB, "candidate was not frozen by the release finalizer job");
  const lock = await verifyReleaseCandidateLock({ directory, ...expected });
  const manifest = await readJson(path.join(directory, "installers-windows-x86_64.json"));
  assert(
    manifest?.schemaVersion === 2 &&
      manifest.version === lock.version && manifest.tag === lock.tag &&
      manifest.sourceCommit === lock.sourceCommit && manifest.platform === PLATFORM,
    "candidate Windows installer manifest identity is invalid",
  );
  const matches = manifest.installers?.filter((record) => record?.bundleType === INSTALLER_TYPE) ?? [];
  assert(matches.length === 1, "candidate must contain exactly one Windows NSIS installer");
  const artifact = {
    file: matches[0].file,
    bytes: matches[0].bytes,
    sha256: matches[0].sha256,
  };
  validateArtifactIdentity(artifact, "candidate NSIS artifact");
  const artifactMetadata = await lstat(path.join(directory, artifact.file));
  assert(
    artifactMetadata.isFile() && !artifactMetadata.isSymbolicLink() &&
      artifactMetadata.size === artifact.bytes &&
      await sha256File(path.join(directory, artifact.file)) === artifact.sha256,
    "candidate NSIS installer differs from its frozen manifest",
  );
  const runtimeFile = "managed-runtime-windows-x86_64.manifest.json";
  const runtimePath = path.join(directory, runtimeFile);
  const runtimeMetadata = await lstat(runtimePath);
  assert(runtimeMetadata.isFile() && !runtimeMetadata.isSymbolicLink(), "candidate Windows runtime manifest is missing");
  const runtime = await readJson(runtimePath);
  boundedText(runtime.management_contract_revision, "candidate runtime management contract revision", 64);
  const runtimeManifest = {
    file: runtimeFile,
    bytes: runtimeMetadata.size,
    sha256: await sha256File(runtimePath),
    managementContractRevision: runtime.management_contract_revision,
  };
  return { lock, artifact, runtimeManifest, lockSha256: await sha256File(path.join(directory, RELEASE_CANDIDATE_LOCK_FILE)) };
}

function expectedEvidence(candidate) {
  return {
    platform: PLATFORM,
    architecture: "x86_64",
    installerType: INSTALLER_TYPE,
    version: candidate.lock.version,
    tag: candidate.lock.tag,
    commit: candidate.lock.sourceCommit,
    releaseChannel: candidate.lock.releaseChannel,
    artifact: candidate.artifact,
    runtimeManifest: candidate.runtimeManifest,
  };
}

async function evidenceFileRecord(file, relative) {
  const metadata = await lstat(file);
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size > 0, `${relative} is not a non-empty evidence file`);
  return { path: relative, bytes: metadata.size, sha256: await sha256File(file) };
}

async function inspectEvidenceDirectory(directory, candidate) {
  const root = path.resolve(directory);
  const metadata = await lstat(root);
  assert(metadata.isDirectory() && !metadata.isSymbolicLink(), "external evidence source must be one real directory");
  const rootEntries = await readdir(root, { withFileTypes: true });
  const allowedRoot = new Set([
    WINDOWS_HUMAN_PATH_FILE,
    WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE,
    WINDOWS_LIFECYCLE_DIRECTORY,
  ]);
  for (const entry of rootEntries) {
    assert(allowedRoot.has(entry.name), `unexpected external evidence path: ${entry.name}`);
    const entryMetadata = await lstat(path.join(root, entry.name));
    assert(!entryMetadata.isSymbolicLink(), `external evidence contains a symlink: ${entry.name}`);
    if (entry.name === WINDOWS_LIFECYCLE_DIRECTORY) {
      assert(entryMetadata.isDirectory(), `${entry.name} must be a directory`);
    } else {
      assert(entryMetadata.isFile(), `${entry.name} must be a regular file`);
    }
  }
  assert(
    !rootEntries.some(({ name }) => name === "os-signing-windows-x86_64-nsis.json"),
    "generic external importer must not accept Authenticode promotion evidence",
  );

  const expected = expectedEvidence(candidate);
  let humanPath = null;
  const humanFile = path.join(root, WINDOWS_HUMAN_PATH_FILE);
  if (rootEntries.some(({ name }) => name === WINDOWS_HUMAN_PATH_FILE)) {
    await verifyBoundArtifactEvidenceFile(humanFile, {
      ...expected,
      evidenceType: "beginner-human-path",
      label: WINDOWS_HUMAN_PATH_FILE,
    });
    humanPath = await evidenceFileRecord(humanFile, WINDOWS_HUMAN_PATH_FILE);
  }

  let unsignedSigningObservation = null;
  const unsignedFile = path.join(root, WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE);
  if (rootEntries.some(({ name }) => name === WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE)) {
    await verifyBoundArtifactEvidenceFile(unsignedFile, {
      ...expected,
      evidenceType: "operating-system-code-signing-observation",
      label: WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE,
    });
    unsignedSigningObservation = await evidenceFileRecord(
      unsignedFile,
      WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE,
    );
  }

  let lifecycle = {
    summary: {
      state: "not-observed",
      requiredCount: WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length,
      presentCount: 0,
      passedCount: 0,
      failedCount: 0,
      inconclusiveCount: 0,
      notObservedCount: 0,
      missingKeys: WINDOWS_INSTALLED_LIFECYCLE_RECORDS.map(({ key }) => key),
    },
    records: [],
  };
  if (rootEntries.some(({ name }) => name === WINDOWS_LIFECYCLE_DIRECTORY)) {
    const lifecycleRoot = path.join(root, WINDOWS_LIFECYCLE_DIRECTORY);
    const verified = await verifyWindowsInstalledLifecycleEvidenceDirectory(lifecycleRoot, expected);
    const byKey = new Map(verified.records.map((record) => [`${record.rowId}/${record.boundary}`, record]));
    const records = [];
    for (const contract of WINDOWS_INSTALLED_LIFECYCLE_RECORDS) {
      const evidence = byKey.get(contract.key);
      if (!evidence) continue;
      const relative = `${WINDOWS_LIFECYCLE_DIRECTORY}/${contract.path}`;
      records.push({
        rowId: evidence.rowId,
        boundary: evidence.boundary,
        outcome: evidence.outcome,
        ...await evidenceFileRecord(path.join(root, relative), relative),
      });
    }
    lifecycle = { summary: verified.summary, records };
  }
  assert(
    humanPath || unsignedSigningObservation || lifecycle.records.length > 0,
    "external evidence import contains no supported record",
  );
  return { root, humanPath, unsignedSigningObservation, lifecycle };
}

function validateFileRecord(record, label) {
  exactKeys(record, ["path", "bytes", "sha256"], label);
  safePosixPath(record.path, `${label} path`);
  assert(Number.isSafeInteger(record.bytes) && record.bytes > 0, `${label} bytes are invalid`);
  digest(record.sha256, `${label} sha256`);
}

function validateSummary(summary) {
  exactKeys(
    summary,
    [
      "state", "requiredCount", "presentCount", "passedCount", "failedCount",
      "inconclusiveCount", "notObservedCount", "missingKeys",
    ],
    "Windows lifecycle summary",
  );
  assert(["verified", "failed", "partial", "not-observed"].includes(summary.state), "Windows lifecycle summary state is invalid");
  for (const field of ["requiredCount", "presentCount", "passedCount", "failedCount", "inconclusiveCount", "notObservedCount"]) {
    assert(Number.isSafeInteger(summary[field]) && summary[field] >= 0, `Windows lifecycle summary ${field} is invalid`);
  }
  assert(
    summary.requiredCount === WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length &&
      summary.presentCount === summary.passedCount + summary.failedCount + summary.inconclusiveCount + summary.notObservedCount,
    "Windows lifecycle summary counts are inconsistent",
  );
  assert(Array.isArray(summary.missingKeys), "Windows lifecycle summary missingKeys is invalid");
  const allowedKeys = WINDOWS_INSTALLED_LIFECYCLE_RECORDS.map(({ key }) => key);
  assert(
    summary.missingKeys.every((key) => allowedKeys.includes(key)) &&
      new Set(summary.missingKeys).size === summary.missingKeys.length,
    "Windows lifecycle summary contains invalid or duplicate missing keys",
  );
}

function lifecycleSummaryForReceiptRecords(records) {
  const presentKeys = new Set(records.map(({ rowId, boundary }) => `${rowId}/${boundary}`));
  const missingKeys = WINDOWS_INSTALLED_LIFECYCLE_RECORDS
    .map(({ key }) => key)
    .filter((key) => !presentKeys.has(key));
  const count = (outcome) => records.filter((record) => record.outcome === outcome).length;
  const passedCount = count("passed");
  const failedCount = count("failed");
  const inconclusiveCount = count("inconclusive");
  const notObservedCount = count("not-observed");
  let state = "partial";
  if (failedCount > 0) state = "failed";
  else if (missingKeys.length === 0 && passedCount === WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length) {
    state = "verified";
  } else if (records.length === 0 || (passedCount === 0 && inconclusiveCount === 0)) {
    state = "not-observed";
  }
  return {
    state,
    requiredCount: WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length,
    presentCount: records.length,
    passedCount,
    failedCount,
    inconclusiveCount,
    notObservedCount,
    missingKeys,
  };
}

export function validateWindowsExternalEvidenceReceipt(receipt, expectedImporter) {
  exactKeys(
    receipt,
    [
      "schemaVersion", "product", "platform", "installerType", "releaseIdentity", "artifact",
      "runtimeManifest", "candidate", "evidenceSource", "importer", "humanPath",
      "unsignedSigningObservation", "windowsLifecycle", "importedAt",
    ],
    "Windows external-evidence receipt",
  );
  assert(receipt.schemaVersion === 1 && receipt.product === PRODUCT, "external-evidence receipt identity is invalid");
  assert(receipt.platform === PLATFORM && receipt.installerType === INSTALLER_TYPE, "external-evidence receipt platform/installer is invalid");
  validateReleaseIdentity(receipt.releaseIdentity, "external-evidence release identity");
  validateArtifactIdentity(receipt.artifact, "external-evidence artifact");
  validateRuntimeManifestIdentity(receipt.runtimeManifest, "external-evidence runtime manifest");

  exactKeys(receipt.candidate, ["artifactId", "artifactDigest", "lockFile", "lockSha256", "producer"], "external-evidence candidate");
  assert(
    receipt.candidate.artifactId === canonicalRunId(receipt.candidate.artifactId, "candidate artifact ID"),
    "candidate artifact ID is not canonical",
  );
  artifactDigest(receipt.candidate.artifactDigest, "candidate artifact digest");
  assert(receipt.candidate.lockFile === RELEASE_CANDIDATE_LOCK_FILE, "external-evidence receipt names the wrong candidate lock");
  digest(receipt.candidate.lockSha256, "external-evidence candidate lock digest");
  exactKeys(
    receipt.candidate.producer,
    ["provider", "repository", "workflow", "workflowRef", "workflowSha", "runId", "runAttempt", "job"],
    "external-evidence candidate producer",
  );
  const candidateProducer = producerIdentity(receipt.candidate.producer);
  assert(JSON.stringify(candidateProducer) === JSON.stringify(receipt.candidate.producer), "external-evidence candidate producer is not canonical");
  assert(candidateProducer.workflow === CANDIDATE_WORKFLOW && candidateProducer.job === CANDIDATE_JOB, "external-evidence candidate producer is unsupported");

  exactKeys(receipt.evidenceSource, ["repository", "commit", "path"], "external-evidence source");
  repository(receipt.evidenceSource.repository, "external-evidence source repository");
  fullSha(receipt.evidenceSource.commit, "external-evidence source commit");
  safePosixPath(receipt.evidenceSource.path, "external-evidence source path");

  exactKeys(
    receipt.importer,
    ["provider", "repository", "workflow", "workflowRef", "workflowSha", "runId", "runAttempt", "job", "environment"],
    "external-evidence importer",
  );
  const importer = producerIdentity(receipt.importer);
  assert(JSON.stringify(importer) === JSON.stringify(receipt.importer), "external-evidence importer is not canonical");
  if (expectedImporter) {
    assert(JSON.stringify(importer) === JSON.stringify(expectedImporter), "external-evidence receipt importer differs from the protected run");
  }
  assert(typeof receipt.importedAt === "string" && !Number.isNaN(Date.parse(receipt.importedAt)), "external-evidence receipt importedAt is invalid");

  if (receipt.humanPath !== null) {
    validateFileRecord(receipt.humanPath, "external-evidence human path");
    assert(receipt.humanPath.path === WINDOWS_HUMAN_PATH_FILE, "external-evidence receipt names the wrong human record");
  }
  if (receipt.unsignedSigningObservation !== null) {
    validateFileRecord(receipt.unsignedSigningObservation, "external-evidence unsigned signing observation");
    assert(
      receipt.unsignedSigningObservation.path === WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE,
      "external-evidence receipt names the wrong unsigned signing observation",
    );
  }
  exactKeys(receipt.windowsLifecycle, ["summary", "records"], "external-evidence Windows lifecycle");
  validateSummary(receipt.windowsLifecycle.summary);
  assert(Array.isArray(receipt.windowsLifecycle.records), "external-evidence lifecycle records must be an array");
  let previous = -1;
  for (const record of receipt.windowsLifecycle.records) {
    exactKeys(record, ["rowId", "boundary", "outcome", "path", "bytes", "sha256"], "external-evidence lifecycle record");
    const index = WINDOWS_INSTALLED_LIFECYCLE_RECORDS.findIndex(({ rowId, boundary, path: recordPath }) =>
      rowId === record.rowId && boundary === record.boundary &&
        `${WINDOWS_LIFECYCLE_DIRECTORY}/${recordPath}` === record.path);
    assert(index > previous, "external-evidence lifecycle records are invalid, duplicated, or out of canonical order");
    previous = index;
    assert(["passed", "failed", "inconclusive", "not-observed"].includes(record.outcome), "external-evidence lifecycle outcome is invalid");
    validateFileRecord({ path: record.path, bytes: record.bytes, sha256: record.sha256 }, "external-evidence lifecycle record file");
  }
  assert(
    receipt.windowsLifecycle.summary.presentCount === receipt.windowsLifecycle.records.length,
    "external-evidence lifecycle receipt count differs from its records",
  );
  assert(
    JSON.stringify(receipt.windowsLifecycle.summary) ===
      JSON.stringify(lifecycleSummaryForReceiptRecords(receipt.windowsLifecycle.records)),
    "external-evidence lifecycle summary differs from its exact receipted rows",
  );
  assert(receipt.humanPath || receipt.unsignedSigningObservation || receipt.windowsLifecycle.records.length > 0, "external-evidence receipt is empty");
  return receipt;
}

export function verifyFinalizedWindowsExternalEvidenceOutcomes({
  receipt,
  receiptFile,
  humanPath,
  windowsLifecycle,
}) {
  validateWindowsExternalEvidenceReceipt(receipt);
  validateFileRecord(receiptFile, "finalized external-evidence receipt file");
  assert(
    receiptFile.path === WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
    "finalized external-evidence receipt has the wrong path",
  );
  const expectedHumanPath = receipt.humanPath
    ? { state: "verified", evidenceFile: receipt.humanPath.path, reason: null }
    : { state: "not-observed", evidenceFile: null, reason: "exact-candidate-beginner-path-not-observed" };
  const lifecycleObserved = receipt.windowsLifecycle.summary.state !== "not-observed";
  const expectedWindowsLifecycle = lifecycleObserved
    ? {
        state: receipt.windowsLifecycle.summary.state,
        evidenceFiles: [
          receiptFile,
          ...receipt.windowsLifecycle.records.map(({ path: recordPath, bytes, sha256 }) => ({
            path: recordPath,
            bytes,
            sha256,
          })),
        ],
        reason: receipt.windowsLifecycle.summary.state === "verified"
          ? null
          : `external-installed-app-lifecycle-${receipt.windowsLifecycle.summary.state}`,
      }
    : {
        state: "not-observed",
        evidenceFiles: [],
        reason: "real-installed-app-localhost-lifecycle-not-observed",
      };
  assert(
    JSON.stringify(humanPath) === JSON.stringify(expectedHumanPath),
    "finalized human-path outcome differs from the protected external-evidence receipt",
  );
  assert(
    JSON.stringify(windowsLifecycle) === JSON.stringify(expectedWindowsLifecycle),
    "finalized Windows lifecycle outcome differs from the protected external-evidence receipt",
  );
  return { humanPath: expectedHumanPath, windowsLifecycle: expectedWindowsLifecycle };
}

async function validateReceiptFiles(receiptRoot, receipt, candidate) {
  const expected = expectedEvidence(candidate);
  const claimed = [];
  if (receipt.humanPath) {
    claimed.push(receipt.humanPath);
    await verifyBoundArtifactEvidenceFile(path.join(receiptRoot, receipt.humanPath.path), {
      ...expected,
      evidenceType: "beginner-human-path",
      label: receipt.humanPath.path,
    });
  }
  if (receipt.unsignedSigningObservation) {
    claimed.push(receipt.unsignedSigningObservation);
    await verifyBoundArtifactEvidenceFile(path.join(receiptRoot, receipt.unsignedSigningObservation.path), {
      ...expected,
      evidenceType: "operating-system-code-signing-observation",
      label: receipt.unsignedSigningObservation.path,
    });
  }
  claimed.push(...receipt.windowsLifecycle.records.map(({ path: recordPath, bytes, sha256 }) => ({ path: recordPath, bytes, sha256 })));
  for (const record of claimed) {
    const metadata = await lstat(path.join(receiptRoot, record.path));
    assert(
      metadata.isFile() && !metadata.isSymbolicLink() && metadata.size === record.bytes &&
        await sha256File(path.join(receiptRoot, record.path)) === record.sha256,
      `external-evidence record differs from its receipt: ${record.path}`,
    );
  }
  if (receipt.windowsLifecycle.records.length > 0) {
    const verified = await verifyWindowsInstalledLifecycleEvidenceDirectory(
      path.join(receiptRoot, WINDOWS_LIFECYCLE_DIRECTORY),
      expected,
    );
    const normalizedRecords = [];
    const byKey = new Map(verified.records.map((record) => [`${record.rowId}/${record.boundary}`, record]));
    for (const contract of WINDOWS_INSTALLED_LIFECYCLE_RECORDS) {
      const evidence = byKey.get(contract.key);
      if (!evidence) continue;
      const recordPath = `${WINDOWS_LIFECYCLE_DIRECTORY}/${contract.path}`;
      const metadata = await lstat(path.join(receiptRoot, recordPath));
      normalizedRecords.push({
        rowId: evidence.rowId,
        boundary: evidence.boundary,
        outcome: evidence.outcome,
        path: recordPath,
        bytes: metadata.size,
        sha256: await sha256File(path.join(receiptRoot, recordPath)),
      });
    }
    assert(
      JSON.stringify(verified.summary) === JSON.stringify(receipt.windowsLifecycle.summary) &&
        JSON.stringify(normalizedRecords) === JSON.stringify(receipt.windowsLifecycle.records),
      "external-evidence lifecycle records differ from the receipt summary",
    );
  } else {
    assert(receipt.windowsLifecycle.summary.state === "not-observed", "empty lifecycle receipt claims an observed state");
  }
}

export async function verifyWindowsExternalEvidenceReceipt({ directory, candidateDirectory, expectedImporter }) {
  const root = path.resolve(directory);
  const candidateRoot = path.resolve(candidateDirectory);
  const receiptFile = path.join(root, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
  const metadata = await lstat(receiptFile);
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size > 0 && metadata.size <= MAX_RECEIPT_BYTES, "external-evidence receipt must be one bounded regular file");
  const receipt = validateWindowsExternalEvidenceReceipt(await readJson(receiptFile), expectedImporter);
  const candidate = await verifyCandidate(candidateRoot, {
    version: receipt.releaseIdentity.version,
    tag: receipt.releaseIdentity.tag,
    commit: receipt.releaseIdentity.sourceCommit,
    releaseChannel: receipt.releaseIdentity.releaseChannel,
    publicationMode: receipt.releaseIdentity.publicationMode,
    ...receipt.candidate.producer,
    runAttempt: String(receipt.candidate.producer.runAttempt),
  });
  assert(candidate.lockSha256 === receipt.candidate.lockSha256, "external-evidence receipt belongs to a different candidate lock");
  assert(JSON.stringify(candidate.artifact) === JSON.stringify(receipt.artifact), "external-evidence receipt belongs to different installer bytes");
  assert(JSON.stringify(candidate.runtimeManifest) === JSON.stringify(receipt.runtimeManifest), "external-evidence receipt belongs to a different runtime manifest");
  await validateReceiptFiles(root, receipt, candidate);
  const actual = (await regularFiles(root, root, [], MAX_EXTERNAL_FILES)).map(({ relative }) => relative).sort();
  const expectedPaths = [
    WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
    ...(receipt.humanPath ? [receipt.humanPath.path] : []),
    ...(receipt.unsignedSigningObservation ? [receipt.unsignedSigningObservation.path] : []),
    ...receipt.windowsLifecycle.records.map(({ path: recordPath }) => recordPath),
  ].sort();
  assert(JSON.stringify(actual) === JSON.stringify(expectedPaths), "accepted external-evidence artifact contains unreceipted files");
  return { receipt, candidate };
}

export async function verifyMaterializedWindowsExternalEvidence({ directory, expectedImporter }) {
  const root = path.resolve(directory);
  const receiptFile = path.join(root, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
  const receiptMetadata = await lstat(receiptFile);
  assert(
    receiptMetadata.isFile() && !receiptMetadata.isSymbolicLink() &&
      receiptMetadata.size > 0 && receiptMetadata.size <= MAX_RECEIPT_BYTES,
    "materialized external-evidence receipt is invalid",
  );
  const receipt = validateWindowsExternalEvidenceReceipt(await readJson(receiptFile), expectedImporter);
  const lockFile = path.join(root, RELEASE_CANDIDATE_LOCK_FILE);
  assert(await sha256File(lockFile) === receipt.candidate.lockSha256, "materialized candidate lock differs from the accepted receipt");
  const lock = await readJson(lockFile);
  assert(
    lock.version === receipt.releaseIdentity.version && lock.tag === receipt.releaseIdentity.tag &&
      lock.sourceCommit === receipt.releaseIdentity.sourceCommit &&
      lock.releaseChannel === receipt.releaseIdentity.releaseChannel &&
      lock.publicationMode === receipt.releaseIdentity.publicationMode &&
      JSON.stringify(lock.producer) === JSON.stringify(receipt.candidate.producer),
    "materialized candidate identity differs from the external-evidence receipt",
  );
  assert(Array.isArray(lock.files) && lock.files.length > 0, "materialized candidate lock has no file inventory");
  for (const record of lock.files) {
    safePosixPath(record.path, "materialized candidate path");
    const metadata = await lstat(path.join(root, record.path));
    assert(
      metadata.isFile() && !metadata.isSymbolicLink() && metadata.size === record.bytes &&
        await sha256File(path.join(root, record.path)) === record.sha256,
      `materialized candidate differs from its lock: ${record.path}`,
    );
  }
  const candidate = await (async () => {
    const manifest = await readJson(path.join(root, "installers-windows-x86_64.json"));
    assert(manifest?.schemaVersion === 2, "materialized candidate Windows installer manifest is invalid");
    const matches = manifest.installers?.filter((record) => record?.bundleType === INSTALLER_TYPE) ?? [];
    assert(matches.length === 1, "materialized candidate has no unique NSIS installer");
    const artifact = { file: matches[0].file, bytes: matches[0].bytes, sha256: matches[0].sha256 };
    const runtimePath = path.join(root, "managed-runtime-windows-x86_64.manifest.json");
    const runtimeMetadata = await lstat(runtimePath);
    const runtime = await readJson(runtimePath);
    return {
      lock,
      artifact,
      runtimeManifest: {
        file: "managed-runtime-windows-x86_64.manifest.json",
        bytes: runtimeMetadata.size,
        sha256: await sha256File(runtimePath),
        managementContractRevision: runtime.management_contract_revision,
      },
    };
  })();
  assert(JSON.stringify(candidate.artifact) === JSON.stringify(receipt.artifact), "materialized installer differs from external evidence");
  assert(JSON.stringify(candidate.runtimeManifest) === JSON.stringify(receipt.runtimeManifest), "materialized runtime manifest differs from external evidence");
  await validateReceiptFiles(root, receipt, candidate);
  const actual = (await regularFiles(root)).map(({ relative }) => relative).sort();
  const evidencePaths = [
    WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
    ...(receipt.humanPath ? [receipt.humanPath.path] : []),
    ...(receipt.unsignedSigningObservation ? [receipt.unsignedSigningObservation.path] : []),
    ...receipt.windowsLifecycle.records.map(({ path: recordPath }) => recordPath),
  ];
  const expectedPaths = [RELEASE_CANDIDATE_LOCK_FILE, ...lock.files.map(({ path: file }) => file), ...evidencePaths].sort();
  assert(JSON.stringify(actual) === JSON.stringify(expectedPaths), "materialized candidate contains files outside its lock and accepted receipt");
  return { receipt, candidate };
}

export async function verifyFinalizedWindowsExternalEvidence({
  directory,
  expectedImporter,
  artifact,
  version,
  tag,
  commit,
  releaseChannel,
  publicationMode,
}) {
  const root = path.resolve(directory);
  const receiptFile = path.join(root, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
  const receiptMetadata = await lstat(receiptFile);
  assert(
    receiptMetadata.isFile() && !receiptMetadata.isSymbolicLink() &&
      receiptMetadata.size > 0 && receiptMetadata.size <= MAX_RECEIPT_BYTES,
    "finalized external-evidence receipt is invalid",
  );
  const receipt = validateWindowsExternalEvidenceReceipt(await readJson(receiptFile), expectedImporter);
  assert(
    receipt.releaseIdentity.version === version && receipt.releaseIdentity.tag === tag &&
      receipt.releaseIdentity.sourceCommit === commit &&
      receipt.releaseIdentity.releaseChannel === releaseChannel &&
      receipt.releaseIdentity.publicationMode === publicationMode,
    "finalized external evidence belongs to a different release identity",
  );
  assert(JSON.stringify(receipt.artifact) === JSON.stringify(artifact), "finalized external evidence belongs to different installer bytes");
  const lockFile = path.join(root, RELEASE_CANDIDATE_LOCK_FILE);
  const lockMetadata = await lstat(lockFile);
  assert(lockMetadata.isFile() && !lockMetadata.isSymbolicLink(), "finalized release has no regular candidate lock");
  assert(await sha256File(lockFile) === receipt.candidate.lockSha256, "finalized candidate lock differs from the external-evidence receipt");
  const lock = await readJson(lockFile);
  assert(
    lock.version === version && lock.tag === tag && lock.sourceCommit === commit &&
      lock.releaseChannel === releaseChannel && lock.publicationMode === publicationMode &&
      JSON.stringify(lock.producer) === JSON.stringify(receipt.candidate.producer) &&
      Array.isArray(lock.files),
    "finalized candidate lock identity is invalid",
  );
  for (const expectedFile of [artifact, receipt.runtimeManifest]) {
    const locked = lock.files.find(({ path: lockedPath }) => lockedPath === expectedFile.file);
    assert(
      locked && locked.bytes === expectedFile.bytes && locked.sha256 === expectedFile.sha256,
      `finalized external evidence is not bound by the candidate lock: ${expectedFile.file}`,
    );
  }
  const runtimePath = path.join(root, receipt.runtimeManifest.file);
  const runtimeMetadata = await lstat(runtimePath);
  const runtime = await readJson(runtimePath);
  const runtimeManifest = {
    file: receipt.runtimeManifest.file,
    bytes: runtimeMetadata.size,
    sha256: await sha256File(runtimePath),
    managementContractRevision: runtime.management_contract_revision,
  };
  assert(
    runtimeMetadata.isFile() && !runtimeMetadata.isSymbolicLink() &&
      JSON.stringify(runtimeManifest) === JSON.stringify(receipt.runtimeManifest),
    "finalized runtime manifest differs from the external-evidence receipt",
  );
  const candidate = { lock, artifact, runtimeManifest };
  await validateReceiptFiles(root, receipt, candidate);
  return { receipt, candidate };
}

export async function importWindowsExternalEvidence(options) {
  const candidateDirectory = path.resolve(options.candidateDirectory);
  const output = path.resolve(options.output);
  assert(candidateDirectory !== output, "candidate and external-evidence output directories must differ");
  const candidate = await verifyCandidate(candidateDirectory, options.candidate);
  const observed = await inspectEvidenceDirectory(options.evidenceDirectory, candidate);
  await ensureEmptyOutput(output);
  if (observed.humanPath) {
    await copyRegularFile(path.join(observed.root, observed.humanPath.path), path.join(output, observed.humanPath.path));
  }
  if (observed.unsignedSigningObservation) {
    await copyRegularFile(
      path.join(observed.root, observed.unsignedSigningObservation.path),
      path.join(output, observed.unsignedSigningObservation.path),
    );
  }
  for (const record of observed.lifecycle.records) {
    await copyRegularFile(path.join(observed.root, record.path), path.join(output, record.path));
  }
  const receipt = {
    schemaVersion: 1,
    product: PRODUCT,
    platform: PLATFORM,
    installerType: INSTALLER_TYPE,
    releaseIdentity: {
      version: candidate.lock.version,
      tag: candidate.lock.tag,
      sourceCommit: candidate.lock.sourceCommit,
      releaseChannel: candidate.lock.releaseChannel,
      publicationMode: candidate.lock.publicationMode,
    },
    artifact: candidate.artifact,
    runtimeManifest: candidate.runtimeManifest,
    candidate: {
      artifactId: String(positiveInteger(options.candidateArtifactId, "candidate artifact ID")),
      artifactDigest: options.candidateArtifactDigest,
      lockFile: RELEASE_CANDIDATE_LOCK_FILE,
      lockSha256: candidate.lockSha256,
      producer: candidate.lock.producer,
    },
    evidenceSource: options.evidenceSource,
    importer: options.importer,
    humanPath: observed.humanPath,
    unsignedSigningObservation: observed.unsignedSigningObservation,
    windowsLifecycle: observed.lifecycle,
    importedAt: options.importedAt,
  };
  artifactDigest(receipt.candidate.artifactDigest, "candidate artifact digest");
  validateWindowsExternalEvidenceReceipt(receipt, options.importer);
  await writeJsonAtomic(path.join(output, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE), receipt);
  await verifyWindowsExternalEvidenceReceipt({
    directory: output,
    candidateDirectory,
    expectedImporter: options.importer,
  });
  return receipt;
}

export async function materializeWindowsExternalEvidence({ directory, candidateDirectory, output, expectedImporter }) {
  const acceptedRoot = path.resolve(directory);
  const candidateRoot = path.resolve(candidateDirectory);
  const target = path.resolve(output);
  assert(target !== acceptedRoot && target !== candidateRoot, "materialized output must differ from its inputs");
  await verifyWindowsExternalEvidenceReceipt({
    directory: acceptedRoot,
    candidateDirectory: candidateRoot,
    expectedImporter,
  });
  await ensureEmptyOutput(target);
  await copyRegularTree(candidateRoot, target);
  await copyRegularTree(acceptedRoot, target);
  await verifyMaterializedWindowsExternalEvidence({ directory: target, expectedImporter });
}

async function main() {
  const [command, ...argv] = process.argv.slice(2);
  const args = parseArgs(argv);
  if (command === "import") {
    const candidate = candidateInputsFromArgs(args);
    const importer = importerFromPrefixedArgs(args);
    const evidenceSource = {
      repository: requireString(args, "evidence-source-repository"),
      commit: requireString(args, "evidence-source-commit"),
      path: requireString(args, "evidence-source-path"),
    };
    repository(evidenceSource.repository, "external-evidence source repository");
    fullSha(evidenceSource.commit, "external-evidence source commit");
    safePosixPath(evidenceSource.path, "external-evidence source path");
    const importedAt = requireString(args, "imported-at");
    assert(!Number.isNaN(Date.parse(importedAt)), "--imported-at must be a valid timestamp");
    await importWindowsExternalEvidence({
      candidateDirectory: path.resolve(requireString(args, "candidate-dir")),
      evidenceDirectory: path.resolve(requireString(args, "evidence-dir")),
      output: path.resolve(requireString(args, "out")),
      candidate,
      candidateArtifactId: requireString(args, "candidate-artifact-id"),
      candidateArtifactDigest: requireString(args, "candidate-artifact-digest"),
      evidenceSource,
      importer,
      importedAt,
    });
    process.stdout.write("Imported redacted Windows external evidence through the protected receipt contract.\n");
    return;
  }
  if (command === "verify-receipt") {
    await verifyWindowsExternalEvidenceReceipt({
      directory: path.resolve(requireString(args, "dir")),
      candidateDirectory: path.resolve(requireString(args, "candidate-dir")),
      expectedImporter: importerExpectedFromArgs(args),
    });
    process.stdout.write("Verified protected Windows external-evidence receipt.\n");
    return;
  }
  if (command === "materialize") {
    await materializeWindowsExternalEvidence({
      directory: path.resolve(requireString(args, "dir")),
      candidateDirectory: path.resolve(requireString(args, "candidate-dir")),
      output: path.resolve(requireString(args, "out")),
      expectedImporter: importerExpectedFromArgs(args),
    });
    process.stdout.write("Materialized only receipted external evidence beside the immutable candidate.\n");
    return;
  }
  throw new Error("usage: windows-external-evidence.mjs <import|verify-receipt|materialize> [options]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runMain(main);
