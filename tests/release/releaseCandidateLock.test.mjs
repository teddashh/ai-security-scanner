import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  RELEASE_CANDIDATE_LOCK_FILE,
  createReleaseCandidateLock,
  verifyReleaseCandidateLock,
} from "../../scripts/release/release-candidate-lock.mjs";

const identity = {
  version: "0.1.9",
  tag: "v0.1.9",
  commit: "01".repeat(20),
  releaseChannel: "prerelease",
  publicationMode: "public-github-release",
  repository: "teddashh/ai-security-scanner",
  workflow: ".github/workflows/release.yml",
  workflowSha: "01".repeat(20),
  runId: "123456789",
  runAttempt: "1",
  job: "finalize-supported-artifacts",
};

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "release-candidate-lock-"));
  await mkdir(path.join(root, "nested"));
  await writeFile(path.join(root, "installer.exe"), "exact installer bytes\n");
  await writeFile(path.join(root, "nested", "evidence.json"), "{}\n");
  return root;
}

test("candidate lock binds the complete exact regular-file inventory and protected producer", async (t) => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  const created = await createReleaseCandidateLock({ directory: root, ...identity });
  assert.equal(created.schemaVersion, 1);
  assert.equal(created.producer.workflowRef,
    `${identity.repository}/${identity.workflow}@${identity.workflowSha}`);
  assert.deepEqual(created.files.map(({ path: file }) => file), ["installer.exe", "nested/evidence.json"]);
  await assert.doesNotReject(() => verifyReleaseCandidateLock({ directory: root, ...identity }));
});

test("candidate lock rejects added, missing, modified, and identity-mismatched content", async (t) => {
  for (const mutation of ["added", "missing", "modified", "identity"]) {
    await t.test(mutation, async () => {
      const root = await fixture();
      try {
        await createReleaseCandidateLock({ directory: root, ...identity });
        if (mutation === "added") await writeFile(path.join(root, "late.txt"), "late\n");
        if (mutation === "missing") await rm(path.join(root, "nested", "evidence.json"));
        if (mutation === "modified") await writeFile(path.join(root, "installer.exe"), "different bytes\n");
        const expected = mutation === "identity" ? { ...identity, runAttempt: "2" } : identity;
        await assert.rejects(
          () => verifyReleaseCandidateLock({ directory: root, ...expected }),
          mutation === "identity"
            ? /producer differs from the expected protected workflow/u
            : /files differ from the immutable candidate lock/u,
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
});

test("candidate lock refuses symlinks and cannot be silently replaced", async (t) => {
  const root = await fixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await symlink(path.join(root, "installer.exe"), path.join(root, "linked-installer.exe"));
  await assert.rejects(
    () => createReleaseCandidateLock({ directory: root, ...identity }),
    /contains a symlink/u,
  );
  await rm(path.join(root, "linked-installer.exe"));
  await createReleaseCandidateLock({ directory: root, ...identity });
  await assert.rejects(
    () => createReleaseCandidateLock({ directory: root, ...identity }),
    /candidate lock already exists/u,
  );
  assert.equal(RELEASE_CANDIDATE_LOCK_FILE, "release-candidate-lock.json");
});
