import { appendFile, lstat, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

export const RELEASE_CANDIDATE_LOCK_FILE = "release-candidate-lock.json";

const MAX_LOCK_BYTES = 1024 * 1024;
const MAX_CANDIDATE_FILES = 512;
const PUBLICATION_MODES = new Set(["commit-bound-qc", "public-github-release"]);
const RELEASE_CHANNELS = new Set(["prerelease", "stable"]);

function compareCanonicalPaths(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} fields are not the release-candidate-lock schema-v1 set`,
  );
}

function boundedText(value, label) {
  assert(
    typeof value === "string" && value.length > 0 && value.length <= 500 && !/[\0\r\n]/u.test(value),
    `${label} must be non-empty bounded single-line text`,
  );
}

function parsePositiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  assert(typeof value === "string" && /^[1-9][0-9]*$/u.test(value), `${label} must be a positive integer`);
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed) && parsed <= maximum, `${label} exceeds its supported range`);
  return parsed;
}

function expectedIdentity(inputs) {
  const {
    version,
    tag,
    commit,
    releaseChannel,
    publicationMode,
    repository,
    workflow,
    workflowSha,
    runId,
    runAttempt,
    job,
  } = inputs;
  assert(isSemver(version) && tag === `v${version}`, "candidate lock version/tag is malformed or inconsistent");
  assert(/^[0-9a-f]{40}$/u.test(commit), "candidate lock source commit must be a full lowercase Git object ID");
  assert(RELEASE_CHANNELS.has(releaseChannel), "candidate lock release channel is invalid");
  assert(PUBLICATION_MODES.has(publicationMode), "candidate lock publication mode is invalid");
  assert(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository), "candidate lock repository is invalid");
  assert(
    /^\.github\/workflows\/[A-Za-z0-9._-]+\.ya?ml$/u.test(workflow),
    "candidate lock workflow path is invalid",
  );
  assert(/^[0-9a-f]{40}$/u.test(workflowSha), "candidate lock workflow SHA must be a full lowercase Git object ID");
  const canonicalRunId = String(parsePositiveInteger(runId, "candidate lock run ID"));
  const canonicalRunAttempt = parsePositiveInteger(runAttempt, "candidate lock run attempt", 100);
  boundedText(job, "candidate lock job");
  return {
    schemaVersion: 1,
    product: "ai-security-scanner",
    version,
    tag,
    sourceCommit: commit,
    releaseChannel,
    publicationMode,
    producer: {
      provider: "github-actions",
      repository,
      workflow,
      workflowRef: `${repository}/${workflow}@${workflowSha}`,
      workflowSha,
      runId: canonicalRunId,
      runAttempt: canonicalRunAttempt,
      job,
    },
  };
}

async function inventoryCandidate(directory, root = directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    const metadata = await lstat(absolute);
    if (metadata.isSymbolicLink()) {
      throw new Error(`release candidate contains a symlink: ${absolute}`);
    }
    if (metadata.isDirectory()) {
      files.push(...(await inventoryCandidate(absolute, root)));
      continue;
    }
    if (!metadata.isFile()) {
      throw new Error(`release candidate contains a special file: ${absolute}`);
    }
    const relative = toPosix(path.relative(root, absolute));
    assertSafeRelativePath(relative);
    if (relative === RELEASE_CANDIDATE_LOCK_FILE) continue;
    files.push({
      path: relative,
      bytes: metadata.size,
      sha256: await sha256File(absolute),
    });
  }
  return files;
}

function validateLockShape(lock, expected) {
  exactKeys(
    lock,
    [
      "schemaVersion",
      "product",
      "version",
      "tag",
      "sourceCommit",
      "releaseChannel",
      "publicationMode",
      "producer",
      "files",
    ],
    "release candidate lock",
  );
  for (const field of [
    "schemaVersion",
    "product",
    "version",
    "tag",
    "sourceCommit",
    "releaseChannel",
    "publicationMode",
  ]) {
    assert(lock[field] === expected[field], `candidate lock ${field} differs from the expected identity`);
  }
  exactKeys(
    lock.producer,
    ["provider", "repository", "workflow", "workflowRef", "workflowSha", "runId", "runAttempt", "job"],
    "release candidate producer",
  );
  assert(
    JSON.stringify(lock.producer) === JSON.stringify(expected.producer),
    "candidate lock producer differs from the expected protected workflow",
  );
  assert(
    Array.isArray(lock.files) && lock.files.length > 0 && lock.files.length <= MAX_CANDIDATE_FILES,
    `candidate lock must inventory between 1 and ${MAX_CANDIDATE_FILES} files`,
  );
  let previous = null;
  for (const record of lock.files) {
    exactKeys(record, ["path", "bytes", "sha256"], "candidate lock file record");
    assertSafeRelativePath(record.path);
    assert(record.path === toPosix(record.path), `candidate lock path is not canonical POSIX: ${record.path}`);
    assert(record.path !== RELEASE_CANDIDATE_LOCK_FILE, "candidate lock must not inventory itself");
    assert(
      previous === null || compareCanonicalPaths(previous, record.path) < 0,
      "candidate lock file paths are duplicated or unsorted",
    );
    assert(Number.isSafeInteger(record.bytes) && record.bytes >= 0, `candidate lock byte count is invalid: ${record.path}`);
    assert(/^[0-9a-f]{64}$/u.test(record.sha256), `candidate lock digest is invalid: ${record.path}`);
    previous = record.path;
  }
}

export async function createReleaseCandidateLock({ directory, ...inputs }) {
  const root = path.resolve(directory);
  const output = path.join(root, RELEASE_CANDIDATE_LOCK_FILE);
  try {
    await lstat(output);
    throw new Error(`candidate lock already exists: ${output}`);
  } catch (error) {
    if (!error || typeof error !== "object" || error.code !== "ENOENT") throw error;
  }
  const identity = expectedIdentity(inputs);
  const files = (await inventoryCandidate(root)).sort((left, right) =>
    compareCanonicalPaths(left.path, right.path));
  const lock = { ...identity, files };
  validateLockShape(lock, identity);
  await writeJsonAtomic(output, lock);
  return lock;
}

export async function verifyReleaseCandidateLock({ directory, ...inputs }) {
  const root = path.resolve(directory);
  const lockFile = path.join(root, RELEASE_CANDIDATE_LOCK_FILE);
  const metadata = await lstat(lockFile);
  assert(
    metadata.isFile() && !metadata.isSymbolicLink() && metadata.size > 0 && metadata.size <= MAX_LOCK_BYTES,
    "candidate lock must be a bounded regular non-symlink file",
  );
  const expected = expectedIdentity(inputs);
  const lock = await readJson(lockFile);
  validateLockShape(lock, expected);
  const actual = (await inventoryCandidate(root)).sort((left, right) =>
    compareCanonicalPaths(left.path, right.path));
  assert(
    JSON.stringify(actual) === JSON.stringify(lock.files),
    "release candidate files differ from the immutable candidate lock",
  );
  return lock;
}

function inputsFromArgs(args) {
  return {
    directory: path.resolve(requireString(args, "dir")),
    version: requireString(args, "version"),
    tag: requireString(args, "tag"),
    commit: requireString(args, "commit"),
    releaseChannel: requireString(args, "release-channel"),
    publicationMode: requireString(args, "publication-mode"),
    repository: requireString(args, "repository"),
    workflow: requireString(args, "workflow"),
    workflowSha: requireString(args, "workflow-sha"),
    runId: requireString(args, "run-id"),
    runAttempt: requireString(args, "run-attempt"),
    job: requireString(args, "job"),
  };
}

async function main() {
  const [command, ...argv] = process.argv.slice(2);
  assert(command === "create" || command === "verify", "usage: release-candidate-lock.mjs <create|verify> [options]");
  const args = parseArgs(argv);
  const inputs = inputsFromArgs(args);
  const lock = command === "create"
    ? await createReleaseCandidateLock(inputs)
    : await verifyReleaseCandidateLock(inputs);
  const githubOutput = args.get("github-output");
  if (githubOutput !== undefined) {
    assert(typeof githubOutput === "string" && githubOutput.length > 0, "--github-output requires a path");
    await appendFile(githubOutput, [
      `version=${lock.version}`,
      `tag=${lock.tag}`,
      `commit=${lock.sourceCommit}`,
      `release_channel=${lock.releaseChannel}`,
      "",
    ].join("\n"));
  }
  process.stdout.write(`${command === "create" ? "Created" : "Verified"} immutable release candidate ${lock.tag}.\n`);
}

if (path.resolve(process.argv[1] ?? "") === path.resolve(fileURLToPath(import.meta.url))) {
  runMain(main);
}
