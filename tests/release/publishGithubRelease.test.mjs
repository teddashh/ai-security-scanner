import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  inventoryReleaseDirectory,
  publishGithubRelease,
} from "../../scripts/release/publish-github-release.mjs";

const apiRoot = "https://api.example.test";
const uploadRoot = "https://uploads.example.test";
const repository = "owner/repository";
const version = "0.1.9";
const tag = `v${version}`;
const commit = "a".repeat(40);

async function withReleaseDirectory(run) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "ass-release-publisher-"));
  try {
    await writeFile(path.join(directory, "RELEASE_NOTES.md"), "Exact release notes.\n", "utf8");
    await writeFile(path.join(directory, "artifact.bin"), Buffer.from([0, 1, 2, 3, 255]));
    return await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function createGithubTranscript({
  existingDraft = false,
  corruptUploadDigest = false,
  stalePublishedRead = false,
} = {}) {
  const requests = [];
  const mutations = [];
  const assets = [];
  let tagCreated = false;
  let release;
  let stalePublishedReadsRemaining = stalePublishedRead ? 1 : 0;
  const releaseId = 741;

  const cloneRelease = () => ({ ...release, assets: [...assets] });
  const tagRecord = () => ({
    ref: `refs/tags/${tag}`,
    object: { type: "commit", sha: commit },
  });

  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method ?? "GET";
    requests.push({ method, url: url.href });
    if (method !== "GET") mutations.push({ method, url: url.href });

    if (url.origin === apiRoot && url.pathname === `/repos/${repository}/releases` && method === "GET") {
      if (existingDraft && !release) {
        return jsonResponse([{ id: 99, tag_name: tag, draft: true }]);
      }
      return jsonResponse(release ? [cloneRelease()] : []);
    }

    if (url.origin === apiRoot && url.pathname === `/repos/${repository}/git/ref/tags/${tag}` && method === "GET") {
      return tagCreated ? jsonResponse(tagRecord()) : jsonResponse({ message: "Not Found" }, 404);
    }

    if (url.origin === apiRoot && url.pathname === `/repos/${repository}/git/refs` && method === "POST") {
      const body = JSON.parse(init.body);
      assert.deepEqual(body, { ref: `refs/tags/${tag}`, sha: commit });
      tagCreated = true;
      return jsonResponse(tagRecord(), 201);
    }

    if (url.origin === apiRoot && url.pathname === `/repos/${repository}/releases` && method === "POST") {
      const body = JSON.parse(init.body);
      assert.deepEqual(body, {
        tag_name: tag,
        target_commitish: commit,
        name: `ai-security-scanner ${version}`,
        body: "Exact release notes.\n",
        draft: true,
        prerelease: true,
        make_latest: "false",
        generate_release_notes: false,
      });
      release = {
        id: releaseId,
        ...body,
        published_at: null,
        immutable: false,
        assets_url: `${apiRoot}/repos/${repository}/releases/${releaseId}/assets`,
        upload_url: `${uploadRoot}/repos/${repository}/releases/${releaseId}/assets{?name,label}`,
        html_url: "https://example.test/release",
      };
      return jsonResponse(cloneRelease(), 201);
    }

    if (
      url.origin === apiRoot &&
      url.pathname === `/repos/${repository}/releases/${releaseId}/assets` &&
      method === "GET"
    ) {
      return jsonResponse(assets);
    }

    if (
      url.origin === uploadRoot &&
      url.pathname === `/repos/${repository}/releases/${releaseId}/assets` &&
      method === "POST"
    ) {
      const chunks = [];
      for await (const chunk of init.body) chunks.push(Buffer.from(chunk));
      const bytes = Buffer.concat(chunks);
      assert.equal(Number(init.headers["Content-Length"]), bytes.length);
      assert.equal(init.headers["Content-Type"], "application/octet-stream");
      const name = url.searchParams.get("name");
      const digest = createHash("sha256").update(bytes).digest("hex");
      const asset = {
        id: 1000 + assets.length,
        name,
        label: "",
        state: "uploaded",
        content_type: "application/octet-stream",
        size: bytes.length,
        digest: `sha256:${corruptUploadDigest ? "0".repeat(64) : digest}`,
      };
      assets.push(asset);
      return jsonResponse(asset, 201);
    }

    if (
      url.origin === apiRoot &&
      url.pathname === `/repos/${repository}/releases/${releaseId}` &&
      method === "GET"
    ) {
      if (release?.draft === false && stalePublishedReadsRemaining > 0) {
        stalePublishedReadsRemaining -= 1;
        return jsonResponse({ ...cloneRelease(), draft: true, published_at: null });
      }
      return jsonResponse(cloneRelease());
    }

    if (
      url.origin === apiRoot &&
      url.pathname === `/repos/${repository}/releases/${releaseId}` &&
      method === "PATCH"
    ) {
      const body = JSON.parse(init.body);
      assert.deepEqual(body, {
        tag_name: tag,
        target_commitish: commit,
        name: `ai-security-scanner ${version}`,
        body: "Exact release notes.\n",
        draft: false,
        prerelease: true,
        make_latest: "false",
      });
      release = {
        ...release,
        ...body,
        published_at: "2026-09-07T12:00:00Z",
      };
      return jsonResponse(cloneRelease());
    }

    if (
      url.origin === apiRoot &&
      url.pathname === `/repos/${repository}/releases/tags/${tag}` &&
      method === "GET"
    ) {
      return jsonResponse(cloneRelease());
    }

    return jsonResponse({ message: `unexpected ${method} ${url.href}` }, 500);
  };

  return { fetchImpl, requests, mutations };
}

function publishOptions(directory, fetchImpl) {
  return {
    directory,
    version,
    tag,
    commit,
    repository,
    prerelease: true,
    makeLatest: false,
    apiRoot,
    uploadRoot,
    token: "test-token",
    fetchImpl,
    sleepImpl: async () => {},
  };
}

test("release inventory maps nested evidence to deterministic flat publication names", async () => {
  await withReleaseDirectory(async (directory) => {
    const inventory = await inventoryReleaseDirectory(directory);
    assert.deepEqual(
      inventory.entries.map(({ name }) => name),
      ["artifact.bin", "RELEASE_NOTES.md"].sort((left, right) => left.localeCompare(right)),
    );

    await mkdir(path.join(directory, "nested"));
    await writeFile(path.join(directory, "nested", "evidence.json"), "{}\n", "utf8");
    const nestedInventory = await inventoryReleaseDirectory(directory);
    const nested = nestedInventory.entries.find(({ relative }) => relative === "nested/evidence.json");
    assert.equal(
      nested.name,
      `path-v1-${Buffer.from("nested/evidence.json", "utf8").toString("base64url")}`,
    );
  });

  await withReleaseDirectory(async (directory) => {
    await writeFile(path.join(directory, "ARTIFACT.bin"), "collision", "utf8");
    await assert.rejects(inventoryReleaseDirectory(directory), /release publication asset name collides/u);
  });

  await withReleaseDirectory(async (directory) => {
    await writeFile(path.join(directory, "path-v1-literal.json"), "{}\n", "utf8");
    await assert.rejects(
      inventoryReleaseDirectory(directory),
      /flat release asset uses the reserved nested-path prefix/u,
    );
  });

  await withReleaseDirectory(async (directory) => {
    const link = `${directory}-link`;
    try {
      await symlink(directory, link, "dir");
      await assert.rejects(
        inventoryReleaseDirectory(link),
        /release asset root must be one non-symlink directory/u,
      );
    } finally {
      await rm(link, { force: true });
    }
  });
});

test("publisher uploads a private draft, verifies it twice, and publishes by recorded ID last", async () => {
  await withReleaseDirectory(async (directory) => {
    await mkdir(path.join(directory, "windows-installed-lifecycle"));
    await writeFile(
      path.join(directory, "windows-installed-lifecycle", "wl-01-before-start.json"),
      "{}\n",
      "utf8",
    );
    const transcript = createGithubTranscript();
    const result = await publishGithubRelease(publishOptions(directory, transcript.fetchImpl));
    assert.equal(result.releaseId, 741);
    assert.equal(result.assetCount, 3);
    assert.match(result.assetInventorySha256, /^[0-9a-f]{64}$/u);
    assert.deepEqual(transcript.mutations.map(({ method }) => method), [
      "POST",
      "POST",
      "POST",
      "POST",
      "POST",
      "PATCH",
    ]);
    assert.match(transcript.mutations.at(-1).url, /\/releases\/741$/u);
    assert(
      transcript.mutations.some(({ url }) =>
        new URL(url).searchParams.get("name") ===
          `path-v1-${Buffer.from("windows-installed-lifecycle/wl-01-before-start.json").toString("base64url")}`),
    );
    const firstPatch = transcript.requests.findIndex(({ method }) => method === "PATCH");
    const prepublicationDraftReads = transcript.requests
      .slice(0, firstPatch)
      .filter(({ method, url }) =>
        method === "GET" && new URL(url).pathname.endsWith("/releases/741"));
    assert.equal(prepublicationDraftReads.length, 3);
  });
});

test("publisher refuses an existing draft before any remote mutation", async () => {
  await withReleaseDirectory(async (directory) => {
    const transcript = createGithubTranscript({ existingDraft: true });
    await assert.rejects(
      publishGithubRelease(publishOptions(directory, transcript.fetchImpl)),
      /draft or published release already occupies the exact tag/u,
    );
    assert.deepEqual(transcript.mutations, []);
  });
});

test("publisher retries only stale reads after a successful public transition", async () => {
  await withReleaseDirectory(async (directory) => {
    const transcript = createGithubTranscript({ stalePublishedRead: true });
    const result = await publishGithubRelease(publishOptions(directory, transcript.fetchImpl));
    assert.equal(result.releaseId, 741);
    assert.equal(transcript.mutations.filter(({ method }) => method === "PATCH").length, 1);
    assert(
      transcript.requests.filter(({ method, url }) =>
        method === "GET" && new URL(url).pathname.endsWith("/releases/741")).length >= 5,
    );
  });
});

test("publisher never makes the release public after an upload digest mismatch", async () => {
  await withReleaseDirectory(async (directory) => {
    const transcript = createGithubTranscript({ corruptUploadDigest: true });
    await assert.rejects(
      publishGithubRelease(publishOptions(directory, transcript.fetchImpl)),
      /uploaded release asset .* differs from the exact local release asset/u,
    );
    assert.equal(transcript.mutations.some(({ method }) => method === "PATCH"), false);
  });
});
