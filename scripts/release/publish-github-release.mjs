import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  isSemver,
  parseArgs,
  requireString,
  runMain,
  toPosix,
} from "./lib.mjs";
import { publishedReleaseAssetName } from "./release-asset-name.mjs";

const API_VERSION = "2022-11-28";
const MAX_RELEASE_FILES = 256;
const MAX_RELEASE_FILE_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_RELEASE_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_RELEASE_PAGES = 100;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const READ_BUFFER_BYTES = 1024 * 1024;
const GET_TIMEOUT_MS = 60_000;
const MUTATION_TIMEOUT_MS = 30 * 60_000;
const READ_RETRY_DELAYS_MS = Object.freeze([0, 250, 750, 1_500, 3_000]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

class RetryableReadError extends Error {}

function retryableRead(message) {
  throw new RetryableReadError(message);
}

async function defaultSleep(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function retryConsistentRead(label, operation, sleepImpl) {
  let lastError;
  for (const [attempt, delay] of READ_RETRY_DELAYS_MS.entries()) {
    if (delay > 0) await sleepImpl(delay);
    try {
      return await operation();
    } catch (error) {
      if (!(error instanceof RetryableReadError)) throw error;
      lastError = error;
      if (attempt === READ_RETRY_DELAYS_MS.length - 1) break;
    }
  }
  throw new Error(`${label} did not converge within the bounded read retries: ${lastError?.message ?? "unknown read state"}`);
}

function exactBoolean(value, label) {
  assert(value === "true" || value === "false", `${label} must be exactly true or false`);
  return value === "true";
}

function exactHttpsRoot(value, label) {
  const url = new URL(value);
  assert(
    url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      url.pathname.replace(/\/+$/u, "") === "",
    `${label} must be one HTTPS origin`,
  );
  return url.origin;
}

async function sha256FileByHandle(file) {
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const handle = await open(file, constants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    assert(before.isFile() && before.size > 0, `release asset is empty or non-regular: ${file}`);
    assert(before.size <= MAX_RELEASE_FILE_BYTES, `release asset exceeds the fixed byte bound: ${file}`);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(READ_BUFFER_BYTES);
    let position = 0;
    while (position < before.size) {
      const length = Math.min(buffer.length, before.size - position);
      const { bytesRead } = await handle.read(buffer, 0, length, position);
      assert(bytesRead > 0, `release asset ended during bounded hashing: ${file}`);
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat();
    assert(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        before.mtimeMs === after.mtimeMs,
      `release asset changed while its exact handle was hashed: ${file}`,
    );
    const pathAfter = await lstat(file);
    assert(
      pathAfter.isFile() &&
        !pathAfter.isSymbolicLink() &&
        pathAfter.dev === after.dev &&
        pathAfter.ino === after.ino &&
        pathAfter.size === after.size,
      `release asset path changed while its exact handle was hashed: ${file}`,
    );
    return {
      bytes: before.size,
      sha256: hash.digest("hex"),
      dev: before.dev,
      ino: before.ino,
      mtimeMs: before.mtimeMs,
    };
  } finally {
    await handle.close();
  }
}

function inventoryFingerprint(entries) {
  return createHash("sha256")
    .update(
      JSON.stringify(
        entries.map(({ relative, name, bytes, sha256 }) => ({ relative, name, bytes, sha256 })),
      ),
    )
    .digest("hex");
}

export async function inventoryReleaseDirectory(directory) {
  const suppliedRootMetadata = await lstat(directory);
  assert(
    suppliedRootMetadata.isDirectory() && !suppliedRootMetadata.isSymbolicLink(),
    "release asset root must be one non-symlink directory",
  );
  const root = await realpath(directory);
  const rootMetadata = await lstat(root);
  assert(rootMetadata.isDirectory() && !rootMetadata.isSymbolicLink(), "release asset root is not one real directory");
  const candidates = [];
  const visit = async (current) => {
    const directoryEntries = await readdir(current, { withFileTypes: true });
    assert(directoryEntries.length > 0, "release asset tree contains an empty directory");
    for (const directoryEntry of directoryEntries.sort((left, right) => left.name.localeCompare(right.name))) {
      const candidate = path.join(current, directoryEntry.name);
      const metadata = await lstat(candidate);
      assert(!metadata.isSymbolicLink(), `release asset tree contains a symlink: ${candidate}`);
      if (metadata.isDirectory()) {
        await visit(candidate);
      } else {
        assert(metadata.isFile(), `release asset tree contains a special file: ${candidate}`);
        candidates.push({ file: candidate, relative: toPosix(path.relative(root, candidate)) });
        assert(candidates.length <= MAX_RELEASE_FILES, "release asset count exceeds its fixed bound");
      }
    }
  };
  await visit(root);
  assert(
    candidates.length > 0 && candidates.length <= MAX_RELEASE_FILES,
    "release asset count is empty or exceeds its fixed bound",
  );
  const exactNames = new Set();
  const foldedNames = new Set();
  const entries = [];
  let totalBytes = 0;
  for (const { file, relative } of candidates.sort((left, right) => left.relative.localeCompare(right.relative))) {
    const name = publishedReleaseAssetName(relative);
    const folded = name.toLowerCase();
    assert(!exactNames.has(name) && !foldedNames.has(folded), `release publication asset name collides: ${name}`);
    exactNames.add(name);
    foldedNames.add(folded);
    const proof = await sha256FileByHandle(file);
    totalBytes += proof.bytes;
    assert(Number.isSafeInteger(totalBytes) && totalBytes <= MAX_RELEASE_BYTES, "release asset inventory exceeds its fixed total byte bound");
    entries.push({ relative, name, file, ...proof });
  }
  assert(
    entries.some(({ relative, name }) => relative === "RELEASE_NOTES.md" && name === relative),
    "release asset inventory has no exact RELEASE_NOTES.md",
  );
  return { root, entries, fingerprint: inventoryFingerprint(entries), totalBytes };
}

async function readExactReleaseBody(inventory) {
  const entry = inventory.entries.find(({ relative }) => relative === "RELEASE_NOTES.md");
  assert(entry && entry.bytes <= 1024 * 1024, "RELEASE_NOTES.md is missing or exceeds its fixed byte bound");
  const bytes = await readFile(entry.file);
  assert(
    bytes.length === entry.bytes && createHash("sha256").update(bytes).digest("hex") === entry.sha256,
    "RELEASE_NOTES.md changed after release inventory",
  );
  const body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  assert(body.length > 0 && !body.includes("\0"), "RELEASE_NOTES.md is empty or invalid UTF-8 text");
  return body;
}

function releaseAssetMap(inventory) {
  return new Map(inventory.entries.map((entry) => [entry.name, entry]));
}

function validateRepository(value) {
  assert(
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(value) &&
      !value.includes("..") &&
      value === value.normalize("NFKC"),
    "GitHub repository coordinate is invalid",
  );
  return value;
}

function validateRequestUrl(url, allowedOrigins) {
  const parsed = new URL(url);
  assert(
    parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      allowedOrigins.has(parsed.origin),
    "GitHub request escaped its exact HTTPS API origins",
  );
}

async function boundedResponseText(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    total += chunk.length;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel("bounded response limit exceeded");
      throw new Error("GitHub API response exceeded its fixed byte bound");
    }
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks, total);
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

async function parseJsonResponse(response, expectedStatus, label) {
  const text = await boundedResponseText(response);
  assert(
    response.status === expectedStatus,
    `${label} failed closed with HTTP ${response.status}${text ? `: ${text.slice(0, 512)}` : ""}`,
  );
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} did not return one JSON document: ${error.message}`);
  }
}

function createClient({ token, apiRoot, uploadRoot, fetchImpl }) {
  assert(typeof token === "string" && token.length >= 1 && token.length <= 4096, "GitHub token is unavailable");
  const allowedOrigins = new Set([apiRoot, uploadRoot]);
  const headers = {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "User-Agent": "ai-security-scanner-release-publisher",
    "X-GitHub-Api-Version": API_VERSION,
  };
  const request = async (url, init = {}, mutation = false) => {
    validateRequestUrl(url, allowedOrigins);
    return fetchImpl(url, {
      ...init,
      redirect: "error",
      signal: AbortSignal.timeout(mutation ? MUTATION_TIMEOUT_MS : GET_TIMEOUT_MS),
      headers: { ...headers, ...(init.headers ?? {}) },
    });
  };
  return {
    api: (pathname, init, mutation = false) =>
      request(`${apiRoot}${pathname}`, init, mutation),
    upload: (url, init) => request(url, init, true),
  };
}

async function listAll(client, pathname, label, { retryNotFound = false } = {}) {
  const values = [];
  let complete = false;
  for (let page = 1; page <= MAX_RELEASE_PAGES; page += 1) {
    const separator = pathname.includes("?") ? "&" : "?";
    const response = await client.api(`${pathname}${separator}per_page=100&page=${page}`);
    if (retryNotFound && response.status === 404) {
      await boundedResponseText(response);
      retryableRead(`${label} is not visible yet`);
    }
    const pageValues = await parseJsonResponse(response, 200, label);
    assert(Array.isArray(pageValues), `${label} response is not an array`);
    values.push(...pageValues);
    if (pageValues.length < 100) {
      complete = true;
      break;
    }
  }
  assert(complete, `${label} exceeded its fixed pagination bound`);
  return values;
}

async function listMatchingReleases(client, repository, tag, options) {
  const releases = await listAll(
    client,
    `/repos/${repository}/releases`,
    "complete GitHub Release listing",
    options,
  );
  return releases.filter((release) => release?.tag_name === tag);
}

function assertExactTag(record, tag, commit, label) {
  assert(
    record &&
      record.ref === `refs/tags/${tag}` &&
      record.object?.type === "commit" &&
      record.object?.sha === commit,
    `${label} does not bind the exact lightweight tag to the frozen commit`,
  );
}

async function ensureExactTag(client, repository, tag, commit) {
  const path_ = `/repos/${repository}/git/ref/tags/${encodeURIComponent(tag)}`;
  const response = await client.api(path_);
  if (response.status === 200) {
    assertExactTag(await parseJsonResponse(response, 200, "release tag lookup"), tag, commit, "existing release tag");
    return;
  }
  if (response.status !== 404) {
    await parseJsonResponse(response, 404, "release tag lookup");
  } else {
    await boundedResponseText(response);
  }
  const createResponse = await client.api(
    `/repos/${repository}/git/refs`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ref: `refs/tags/${tag}`, sha: commit }),
    },
    true,
  );
  const created = await parseJsonResponse(createResponse, 201, "release tag creation");
  assertExactTag(created, tag, commit, "created release tag");
}

async function verifyExactTag(client, repository, tag, commit, { retryNotFound = false } = {}) {
  const response = await client.api(`/repos/${repository}/git/ref/tags/${encodeURIComponent(tag)}`);
  if (retryNotFound && response.status === 404) {
    await boundedResponseText(response);
    retryableRead("exact release tag is not visible yet");
  }
  const record = await parseJsonResponse(response, 200, "release tag revalidation");
  assertExactTag(record, tag, commit, "release tag revalidation");
}

function validateReleaseRecord(record, expected, draft, label) {
  assert(
    record &&
      Number.isSafeInteger(record.id) &&
      record.id === expected.id &&
      record.tag_name === expected.tag &&
      record.target_commitish === expected.commit &&
      record.name === expected.name &&
      record.body === expected.body &&
      record.draft === draft &&
      record.prerelease === expected.prerelease,
    `${label} metadata differs from the exact frozen release`,
  );
  if (draft) {
    assert(record.published_at === null && record.immutable === false, `${label} is not one unpublished mutable draft`);
  } else {
    assert(
      typeof record.published_at === "string" && Number.isFinite(Date.parse(record.published_at)),
      `${label} has no valid publication time`,
    );
  }
}

function validateCreatedDraft(record, expected, apiRoot, uploadRoot, repository) {
  validateReleaseRecord(record, expected, true, "created draft release");
  assert(Array.isArray(record.assets) && record.assets.length === 0, "created draft release was not empty");
  assert(
    record.assets_url === `${apiRoot}/repos/${repository}/releases/${expected.id}/assets` &&
      record.upload_url === `${uploadRoot}/repos/${repository}/releases/${expected.id}/assets{?name,label}`,
    "created draft returned an unexpected asset endpoint",
  );
}

function validateAsset(record, expected, label) {
  assert(
    record &&
      Number.isSafeInteger(record.id) &&
      record.id > 0 &&
      record.name === expected.name &&
      (record.label === null || record.label === "") &&
      record.state === "uploaded" &&
      record.content_type === "application/octet-stream" &&
      record.size === expected.bytes &&
      record.digest === `sha256:${expected.sha256}`,
    `${label} differs from the exact local release asset`,
  );
}

async function listReleaseAssets(client, repository, releaseId, options) {
  return listAll(
    client,
    `/repos/${repository}/releases/${releaseId}/assets`,
    "complete draft asset listing",
    options,
  );
}

async function verifyRemoteAssets(client, repository, releaseId, inventory, { retryMissing = false } = {}) {
  const expectedByName = releaseAssetMap(inventory);
  const assets = await listReleaseAssets(client, repository, releaseId, {
    retryNotFound: retryMissing,
  });
  if (retryMissing && assets.length < expectedByName.size) {
    retryableRead("remote release asset listing has not reached the frozen inventory yet");
  }
  assert(assets.length === expectedByName.size, "remote release asset count differs from the frozen inventory");
  const seenNames = new Set();
  const seenIds = new Set();
  for (const asset of assets) {
    assert(!seenNames.has(asset?.name) && !seenIds.has(asset?.id), "remote release assets contain a duplicate name or ID");
    seenNames.add(asset?.name);
    seenIds.add(asset?.id);
    const expected = expectedByName.get(asset?.name);
    assert(expected, `remote release contains an unexpected asset: ${String(asset?.name)}`);
    validateAsset(asset, expected, `remote release asset ${expected.name}`);
  }
}

async function getRelease(client, repository, releaseId, label, { retryNotFound = false } = {}) {
  const response = await client.api(`/repos/${repository}/releases/${releaseId}`);
  if (retryNotFound && response.status === 404) {
    await boundedResponseText(response);
    retryableRead(`${label} is not visible yet`);
  }
  return parseJsonResponse(response, 200, label);
}

async function verifyDraftState(client, repository, expected, inventory) {
  const release = await getRelease(client, repository, expected.id, "draft release lookup", {
    retryNotFound: true,
  });
  validateReleaseRecord(release, expected, true, "draft release");
  const matching = await listMatchingReleases(client, repository, expected.tag, {
    retryNotFound: true,
  });
  if (matching.length === 0) retryableRead("draft release is not visible in the complete namespace yet");
  assert(
    matching.length === 1 && matching[0]?.id === expected.id && matching[0]?.draft === true,
    "draft release namespace is missing, duplicated, or points at another release ID",
  );
  await verifyExactTag(client, repository, expected.tag, expected.commit, { retryNotFound: true });
  await verifyRemoteAssets(client, repository, expected.id, inventory, { retryMissing: true });
}

async function verifyCreatedDraftVisibility(client, repository, expected) {
  const release = await getRelease(client, repository, expected.id, "new draft release lookup", {
    retryNotFound: true,
  });
  validateReleaseRecord(release, expected, true, "new draft release");
  const matching = await listMatchingReleases(client, repository, expected.tag, {
    retryNotFound: true,
  });
  if (matching.length === 0) retryableRead("new draft release is not visible in the complete namespace yet");
  assert(
    matching.length === 1 && matching[0]?.id === expected.id && matching[0]?.draft === true,
    "new draft release did not exclusively reserve the exact tag namespace",
  );
  const assets = await listReleaseAssets(client, repository, expected.id, { retryNotFound: true });
  assert(assets.length === 0, "new draft release asset endpoint was not empty");
  await verifyExactTag(client, repository, expected.tag, expected.commit, { retryNotFound: true });
}

async function verifyPublishedState(client, repository, expected, inventory, makeLatest) {
  const finalRelease = await getRelease(client, repository, expected.id, "published release lookup", {
    retryNotFound: true,
  });
  if (finalRelease?.id === expected.id && finalRelease?.draft === true) {
    retryableRead("published release lookup still exposes the prior draft state");
  }
  validateReleaseRecord(finalRelease, expected, false, "published release");

  const byTagResponse = await client.api(`/repos/${repository}/releases/tags/${encodeURIComponent(expected.tag)}`);
  if (byTagResponse.status === 404) {
    await boundedResponseText(byTagResponse);
    retryableRead("published release tag lookup is not visible yet");
  }
  const byTag = await parseJsonResponse(byTagResponse, 200, "published release tag lookup");
  if (byTag?.id === expected.id && byTag?.draft === true) {
    retryableRead("published release tag lookup still exposes the prior draft state");
  }
  validateReleaseRecord(byTag, expected, false, "published release tag lookup");

  const finalMatches = await listMatchingReleases(client, repository, expected.tag, {
    retryNotFound: true,
  });
  if (finalMatches.length === 0) retryableRead("published release is not visible in the complete namespace yet");
  if (finalMatches.length === 1 && finalMatches[0]?.id === expected.id && finalMatches[0]?.draft === true) {
    retryableRead("complete release namespace still exposes the prior draft state");
  }
  assert(
    finalMatches.length === 1 && finalMatches[0]?.id === expected.id && finalMatches[0]?.draft === false,
    "published release namespace is missing, duplicated, or points at another release ID",
  );
  await verifyExactTag(client, repository, expected.tag, expected.commit, { retryNotFound: true });
  await verifyRemoteAssets(client, repository, expected.id, inventory, { retryMissing: true });
  if (makeLatest) {
    const latestResponse = await client.api(`/repos/${repository}/releases/latest`);
    if (latestResponse.status === 404) {
      await boundedResponseText(latestResponse);
      retryableRead("latest stable release lookup is not visible yet");
    }
    const latest = await parseJsonResponse(latestResponse, 200, "latest stable release lookup");
    if (latest?.id !== expected.id) retryableRead("latest stable release still points at the prior release");
    validateReleaseRecord(latest, expected, false, "latest stable release");
  }
  return finalRelease;
}

async function assertInventoryUnchanged(directory, expectedFingerprint, label) {
  const current = await inventoryReleaseDirectory(directory);
  assert(current.fingerprint === expectedFingerprint, `release asset inventory changed ${label}`);
  return current;
}

async function uploadAsset(client, uploadRoot, repository, releaseId, expected) {
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const handle = await open(expected.file, constants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    assert(
      before.isFile() &&
        before.dev === expected.dev &&
        before.ino === expected.ino &&
        before.size === expected.bytes &&
        before.mtimeMs === expected.mtimeMs,
      `release asset changed before upload: ${expected.name}`,
    );
    const body = {
      async *[Symbol.asyncIterator]() {
        let position = 0;
        while (position < expected.bytes) {
          const length = Math.min(READ_BUFFER_BYTES, expected.bytes - position);
          const buffer = Buffer.allocUnsafe(length);
          const { bytesRead } = await handle.read(buffer, 0, length, position);
          assert(bytesRead > 0, `release asset ended during bounded upload: ${expected.name}`);
          position += bytesRead;
          yield buffer.subarray(0, bytesRead);
        }
      },
    };
    const url = `${uploadRoot}/repos/${repository}/releases/${releaseId}/assets?name=${encodeURIComponent(expected.name)}`;
    const response = await client.upload(url, {
      method: "POST",
      duplex: "half",
      headers: {
        Accept: "application/vnd.github+json",
        "Content-Length": String(expected.bytes),
        "Content-Type": "application/octet-stream",
      },
      body,
    });
    const uploaded = await parseJsonResponse(response, 201, `release asset upload ${expected.name}`);
    validateAsset(uploaded, expected, `uploaded release asset ${expected.name}`);
    const after = await handle.stat();
    assert(
      after.dev === before.dev &&
        after.ino === before.ino &&
        after.size === before.size &&
        after.mtimeMs === before.mtimeMs,
      `release asset changed during upload: ${expected.name}`,
    );
    return uploaded.id;
  } finally {
    await handle.close();
  }
}

export async function publishGithubRelease(options) {
  const {
    directory,
    version,
    tag,
    commit,
    repository: repositoryInput,
    prerelease,
    makeLatest,
    token,
    fetchImpl = globalThis.fetch,
    sleepImpl = defaultSleep,
  } = options;
  assert(typeof fetchImpl === "function", "Fetch API is unavailable");
  assert(typeof sleepImpl === "function", "read retry timer is unavailable");
  assert(isSemver(version) && tag === `v${version}`, "release version and tag are inconsistent");
  assert(/^[0-9a-f]{40}$/u.test(commit), "release commit is not one full lowercase Git SHA");
  assert(
    typeof prerelease === "boolean" && typeof makeLatest === "boolean",
    "release channel flags must be booleans",
  );
  assert(prerelease !== makeLatest, "release channel must be exactly prerelease or latest stable");
  const repository = validateRepository(repositoryInput);
  const apiRoot = exactHttpsRoot(options.apiRoot, "GitHub API root");
  const uploadRoot = exactHttpsRoot(options.uploadRoot, "GitHub upload root");
  assert(apiRoot !== uploadRoot, "GitHub API and upload origins must be distinct");
  const client = createClient({ token, apiRoot, uploadRoot, fetchImpl });

  const inventory = await inventoryReleaseDirectory(directory);
  const body = await readExactReleaseBody(inventory);
  const name = `ai-security-scanner ${version}`;
  assert((await listMatchingReleases(client, repository, tag)).length === 0, "a draft or published release already occupies the exact tag");
  await ensureExactTag(client, repository, tag, commit);
  assert((await listMatchingReleases(client, repository, tag)).length === 0, "release namespace changed after exact tag reservation");

  const createBody = {
    tag_name: tag,
    target_commitish: commit,
    name,
    body,
    draft: true,
    prerelease,
    make_latest: "false",
    generate_release_notes: false,
  };
  const createResponse = await client.api(
    `/repos/${repository}/releases`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(createBody),
    },
    true,
  );
  const created = await parseJsonResponse(createResponse, 201, "draft release creation");
  assert(Number.isSafeInteger(created?.id) && created.id > 0, "draft release creation returned an invalid ID");
  const expected = { id: created.id, version, tag, commit, name, body, prerelease };
  validateCreatedDraft(created, expected, apiRoot, uploadRoot, repository);
  await retryConsistentRead(
    "new draft release visibility",
    () => verifyCreatedDraftVisibility(client, repository, expected),
    sleepImpl,
  );

  const uploadedIds = new Set();
  for (const entry of inventory.entries) {
    const assetId = await uploadAsset(client, uploadRoot, repository, expected.id, entry);
    assert(!uploadedIds.has(assetId), "GitHub returned a duplicate uploaded asset ID");
    uploadedIds.add(assetId);
  }

  let currentInventory = await assertInventoryUnchanged(directory, inventory.fingerprint, "after draft upload");
  await retryConsistentRead(
    "first complete draft verification",
    () => verifyDraftState(client, repository, expected, currentInventory),
    sleepImpl,
  );
  currentInventory = await assertInventoryUnchanged(directory, inventory.fingerprint, "before public transition");
  await retryConsistentRead(
    "second complete draft verification",
    () => verifyDraftState(client, repository, expected, currentInventory),
    sleepImpl,
  );

  const publishBody = {
    tag_name: tag,
    target_commitish: commit,
    name,
    body,
    draft: false,
    prerelease,
    make_latest: makeLatest ? "true" : "false",
  };
  const publishResponse = await client.api(
    `/repos/${repository}/releases/${expected.id}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(publishBody),
    },
    true,
  );
  const published = await parseJsonResponse(publishResponse, 200, "draft release publication");
  validateReleaseRecord(published, expected, false, "published release response");

  const finalRelease = await retryConsistentRead(
    "published release visibility",
    () => verifyPublishedState(client, repository, expected, currentInventory, makeLatest),
    sleepImpl,
  );
  await assertInventoryUnchanged(directory, inventory.fingerprint, "after public transition");
  return {
    releaseId: expected.id,
    tag,
    commit,
    prerelease,
    assetCount: currentInventory.entries.length,
    assetInventorySha256: inventory.fingerprint,
    url: finalRelease.html_url,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const allowed = new Set([
    "dir",
    "version",
    "tag",
    "commit",
    "repository",
    "prerelease",
    "make-latest",
    "api-root",
    "upload-root",
  ]);
  for (const key of args.keys()) assert(allowed.has(key), `unexpected publisher argument: --${key}`);
  const result = await publishGithubRelease({
    directory: path.resolve(requireString(args, "dir")),
    version: requireString(args, "version"),
    tag: requireString(args, "tag"),
    commit: requireString(args, "commit"),
    repository: requireString(args, "repository"),
    prerelease: exactBoolean(requireString(args, "prerelease"), "--prerelease"),
    makeLatest: exactBoolean(requireString(args, "make-latest"), "--make-latest"),
    apiRoot: requireString(args, "api-root"),
    uploadRoot: requireString(args, "upload-root"),
    token: process.env.GH_TOKEN,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (path.resolve(process.argv[1] ?? "") === path.resolve(fileURLToPath(import.meta.url))) {
  runMain(main);
}
