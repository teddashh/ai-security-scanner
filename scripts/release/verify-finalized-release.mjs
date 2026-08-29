import { lstat, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import {
  assertSafeRelativePath,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  toPosix,
} from "./lib.mjs";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const PUBLICATION_MODES = new Set(["commit-bound-qc", "public-github-release"]);

async function regularFiles(directory, root = directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    const metadata = await lstat(absolute);
    if (metadata.isSymbolicLink()) {
      throw new Error(`finalized release contains a symlink: ${absolute}`);
    }
    if (metadata.isDirectory()) {
      files.push(...(await regularFiles(absolute, root)));
    } else if (metadata.isFile()) {
      files.push({
        absolute,
        relative: toPosix(path.relative(root, absolute)),
        bytes: metadata.size,
      });
    } else {
      throw new Error(`finalized release contains a special file: ${absolute}`);
    }
  }
  return files;
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const directory = path.resolve(requireString(args, "dir"));
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  const publicationMode = requireString(args, "publication-mode");
  if (!isSemver(version) || tag !== `v${version}` || !/^[0-9a-f]{40}$/u.test(commit)) {
    throw new Error("release identity is malformed or inconsistent");
  }
  assert(
    PUBLICATION_MODES.has(publicationMode),
    "publication mode must be commit-bound-qc or public-github-release",
  );

  const files = await regularFiles(directory);
  const actualByPath = new Map(files.map((file) => [file.relative, file]));
  assert(actualByPath.has("SHA256SUMS.txt"), "finalized release has no SHA256SUMS.txt");
  assert(actualByPath.has("release-assets.json"), "finalized release has no release-assets.json");

  const checksumContents = await readFile(path.join(directory, "SHA256SUMS.txt"), "utf8");
  assert(checksumContents.endsWith("\n"), "SHA256SUMS.txt must end with one newline");
  const checksumBody = checksumContents.slice(0, -1);
  assert(checksumBody.length > 0, "SHA256SUMS.txt must not be empty");
  const checksumLines = checksumBody.split("\n");
  assert(
    checksumLines.every((line) => line.length > 0),
    "SHA256SUMS.txt must not contain blank lines",
  );
  const checksums = new Map();
  for (const line of checksumLines) {
    const match = line.match(/^([0-9a-f]{64})  ([^\0\r\n]+)$/u);
    assert(match, `malformed SHA256SUMS.txt line: ${line}`);
    const relative = match[2];
    assertSafeRelativePath(relative);
    assert(toPosix(relative) === relative, `checksum path is not canonical POSIX form: ${relative}`);
    assert(relative !== "SHA256SUMS.txt", "SHA256SUMS.txt must not claim to cover itself");
    assert(!checksums.has(relative), `duplicate checksum entry: ${relative}`);
    checksums.set(relative, match[1]);
  }

  const checksumCoveredPaths = sorted(
    [...actualByPath.keys()].filter((relative) => relative !== "SHA256SUMS.txt"),
  );
  assert(
    JSON.stringify(sorted(checksums.keys())) === JSON.stringify(checksumCoveredPaths),
    "SHA256SUMS.txt does not exactly cover every other finalized release file",
  );
  for (const [relative, expectedDigest] of checksums) {
    const actual = actualByPath.get(relative);
    assert(actual, `checksum references a missing file: ${relative}`);
    assert((await sha256File(actual.absolute)) === expectedDigest, `checksum mismatch: ${relative}`);
  }

  const index = await readJson(path.join(directory, "release-assets.json"));
  assert(index.schemaVersion === 2, "release index schemaVersion must be 2");
  assert(index.product === "ai-security-scanner", "release index product is incorrect");
  assert(index.version === version && index.tag === tag, "release index version/tag mismatch");
  assert(index.sourceCommit === commit, "release index source commit mismatch");
  assert(index.publicationMode === publicationMode, "release index publication mode mismatch");
  assert(index.indexSelfExcluded === true, "release index must declare its self-exclusion");
  assert(Array.isArray(index.files), "release index has no files array");

  const indexEntries = new Map();
  for (const record of index.files) {
    assert(record && typeof record === "object", "release index contains an invalid file record");
    assertSafeRelativePath(record.path);
    assert(toPosix(record.path) === record.path, `index path is not canonical POSIX form: ${record.path}`);
    assert(
      record.path !== "SHA256SUMS.txt" && record.path !== "release-assets.json",
      `release index improperly includes a self-generated file: ${record.path}`,
    );
    assert(!indexEntries.has(record.path), `release index contains a duplicate path: ${record.path}`);
    assert(Number.isSafeInteger(record.bytes) && record.bytes >= 0, `invalid byte count: ${record.path}`);
    assert(/^[0-9a-f]{64}$/u.test(record.sha256), `invalid digest: ${record.path}`);
    indexEntries.set(record.path, record);
  }

  const indexCoveredPaths = sorted(
    [...actualByPath.keys()].filter(
      (relative) => relative !== "SHA256SUMS.txt" && relative !== "release-assets.json",
    ),
  );
  assert(
    JSON.stringify(sorted(indexEntries.keys())) === JSON.stringify(indexCoveredPaths),
    "release-assets.json does not exactly index every pre-index release file",
  );
  for (const [relative, record] of indexEntries) {
    const actual = actualByPath.get(relative);
    assert(actual, `release index references a missing file: ${relative}`);
    assert(actual.bytes === record.bytes, `release index byte count mismatch: ${relative}`);
    assert(checksums.get(relative) === record.sha256, `release index digest mismatch: ${relative}`);
  }

  process.stdout.write(
    `Verified ${checksums.size} finalized files and ${indexEntries.size} indexed release inputs for ${tag}.\n`,
  );
}

runMain(main);
