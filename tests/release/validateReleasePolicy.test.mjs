import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  validateProductEngineRegistry,
  validateReleaseWorkflow,
} from "../../scripts/release/validate-release.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function minimalSecurePublicationWorkflow() {
  const identityJobName = "source_identity";
  return {
    on: {
      push: { tags: ["v[0-9]*.[0-9]*.[0-9]*"] },
      workflow_dispatch: null,
    },
    permissions: { contents: "read" },
    jobs: {
      [identityJobName]: {
        outputs: {
          version: "${{ steps.identity.outputs.version }}",
          tag: "${{ steps.identity.outputs.tag }}",
          commit: "${{ steps.identity.outputs.commit }}",
          release_channel: "${{ steps.identity.outputs.release_channel }}",
          publication_mode: "${{ steps.identity.outputs.publication_mode }}",
          prerelease: "${{ steps.identity.outputs.prerelease }}",
          make_latest: "${{ steps.identity.outputs.make_latest }}",
        },
        steps: [{
          id: "identity",
          run: [
            'candidate_tag="v${version}"',
            '"refs/tags/${candidate_tag}"',
            '"refs/heads/main"',
            'event_commit="$(git rev-parse "${EVENT_SHA}^{commit}")"',
            '"${commit}" != "${event_commit}"',
            'release_channel="$(node -p "require(\'./package.json\').release.channel")"',
            'case "${release_channel}" in',
            "isSemver(process.argv[1])",
            "release_channel=%s",
            "publication_mode=%s",
            'publication_mode="commit-bound-qc"',
            'publication_mode="public-github-release"',
            "prerelease=%s",
            "make_latest=%s",
          ].join("\n"),
        }],
      },
      finalize_supported_artifacts: {
        needs: [identityJobName],
        steps: [
          {
            env: {
              RELEASE_VERSION: `\${{ needs.${identityJobName}.outputs.version }}`,
              RELEASE_TAG: `\${{ needs.${identityJobName}.outputs.tag }}`,
              SOURCE_COMMIT: `\${{ needs.${identityJobName}.outputs.commit }}`,
              PUBLICATION_MODE: `\${{ needs.${identityJobName}.outputs.publication_mode }}`,
            },
            run: [
              "node scripts/release/finalize-release.mjs",
              "--dir release-assets",
              '--version "${RELEASE_VERSION}"',
              '--tag "${RELEASE_TAG}"',
              '--commit "${SOURCE_COMMIT}"',
              '--publication-mode "${PUBLICATION_MODE}"',
            ].join(" "),
          },
          {
            env: {
              RELEASE_VERSION: `\${{ needs.${identityJobName}.outputs.version }}`,
              RELEASE_TAG: `\${{ needs.${identityJobName}.outputs.tag }}`,
              SOURCE_COMMIT: `\${{ needs.${identityJobName}.outputs.commit }}`,
              PUBLICATION_MODE: `\${{ needs.${identityJobName}.outputs.publication_mode }}`,
            },
            run: [
              "node scripts/release/verify-finalized-release.mjs",
              "--dir release-assets",
              '--version "${RELEASE_VERSION}"',
              '--tag "${RELEASE_TAG}"',
              '--commit "${SOURCE_COMMIT}"',
              '--publication-mode "${PUBLICATION_MODE}"',
            ].join(" "),
          },
          {
            uses: `actions/upload-artifact@${"c".repeat(40)}`,
            with: {
              name: "release-finalized",
              path: "release-assets",
              "if-no-files-found": "error",
            },
          },
        ],
      },
      publish_supported_artifacts: {
        needs: [identityJobName, "finalize_supported_artifacts"],
        if: `github.event_name == 'push' && github.ref == format('refs/tags/{0}', needs.${identityJobName}.outputs.tag)`,
        permissions: {
          contents: "write",
          "id-token": "write",
          attestations: "write",
        },
        steps: [
          {
            uses: `actions/download-artifact@${"d".repeat(40)}`,
            with: { name: "release-finalized", path: "release-assets" },
          },
          {
            env: {
              RELEASE_VERSION: `\${{ needs.${identityJobName}.outputs.version }}`,
              RELEASE_TAG: `\${{ needs.${identityJobName}.outputs.tag }}`,
              SOURCE_COMMIT: `\${{ needs.${identityJobName}.outputs.commit }}`,
              PUBLICATION_MODE: `\${{ needs.${identityJobName}.outputs.publication_mode }}`,
            },
            run: [
              "node scripts/release/verify-finalized-release.mjs",
              "--dir release-assets",
              '--version "${RELEASE_VERSION}"',
              '--tag "${RELEASE_TAG}"',
              '--commit "${SOURCE_COMMIT}"',
              '--publication-mode "${PUBLICATION_MODE}"',
            ].join(" "),
          },
          {
            uses: `actions/attest-build-provenance@${"a".repeat(40)}`,
            with: { "subject-path": "release-assets/**/*" },
          },
          {
            uses: `softprops/action-gh-release@${"b".repeat(40)}`,
            with: {
              tag_name: `\${{ needs.${identityJobName}.outputs.tag }}`,
              target_commitish: `\${{ needs.${identityJobName}.outputs.commit }}`,
              draft: false,
              prerelease: `\${{ needs.${identityJobName}.outputs.prerelease }}`,
              make_latest: `\${{ needs.${identityJobName}.outputs.make_latest }}`,
              fail_on_unmatched_files: true,
              files: "release-assets/**/*",
            },
          },
        ],
      },
    },
  };
}

test("release workflow validation accepts a safe platform-scoped topology", () => {
  const workflow = minimalSecurePublicationWorkflow();
  assert.doesNotThrow(() => validateReleaseWorkflow(workflow));
  assert.equal(workflow.jobs.build, undefined);
  assert.equal(workflow.jobs.qualification, undefined);
  assert.equal(workflow.jobs.assemble, undefined);
});

test("release workflow validation still rejects unrelated write authority", () => {
  const workflow = minimalSecurePublicationWorkflow();
  workflow.jobs.finalize_supported_artifacts.permissions = { packages: "write" };
  assert.throws(
    () => validateReleaseWorkflow(workflow),
    /finalize_supported_artifacts job must not receive write permissions/u,
  );
});

test("release workflow validation limits publisher write authority to publication needs", () => {
  const workflow = minimalSecurePublicationWorkflow();
  workflow.jobs.publish_supported_artifacts.permissions.packages = "write";
  assert.throws(
    () => validateReleaseWorkflow(workflow),
    /publish job has unrelated write authority: packages/u,
  );
});

test("release workflow validation rejects a decoy verifier outside the publication dependency path", () => {
  const workflow = minimalSecurePublicationWorkflow();
  workflow.jobs.decoy_verifier = workflow.jobs.finalize_supported_artifacts;
  delete workflow.jobs.finalize_supported_artifacts;
  workflow.jobs.publish_supported_artifacts.needs = ["source_identity"];
  assert.throws(
    () => validateReleaseWorkflow(workflow),
    /depend on exactly one job that produced its finalized artifact/u,
  );
});

test("release workflow validation binds verification, attestation, and publication to one path", () => {
  const workflow = minimalSecurePublicationWorkflow();
  const publication = workflow.jobs.publish_supported_artifacts.steps.at(-1);
  publication.with.files = "different-assets/**/*";
  assert.throws(
    () => validateReleaseWorkflow(workflow),
    /publish the exact verified and attested artifact path/u,
  );
});

test("release workflow validation requires publisher-side reverification", () => {
  const workflow = minimalSecurePublicationWorkflow();
  workflow.jobs.publish_supported_artifacts.steps.splice(1, 1);
  assert.throws(
    () => validateReleaseWorkflow(workflow),
    /reverify the downloaded finalized artifact/u,
  );
});

test("release workflow validation cannot ignore a failed required publication step", () => {
  const workflow = minimalSecurePublicationWorkflow();
  workflow.jobs.publish_supported_artifacts.steps[1]["continue-on-error"] = true;
  assert.throws(
    () => validateReleaseWorkflow(workflow),
    /publisher verification cannot continue after failure/u,
  );
});

test("release workflow validation rejects artifact mutation after verification", () => {
  const workflow = minimalSecurePublicationWorkflow();
  workflow.jobs.publish_supported_artifacts.steps.splice(2, 0, {
    run: "cp unverified-file release-assets/unverified-file",
  });
  assert.throws(
    () => validateReleaseWorkflow(workflow),
    /attestation must immediately follow verification/u,
  );
});

test("release workflow validation rejects a tag condition with an unsafe escape", () => {
  const workflow = minimalSecurePublicationWorkflow();
  workflow.jobs.publish_supported_artifacts.if += " || true";
  assert.throws(
    () => validateReleaseWorkflow(workflow),
    /publish job must require an exact version-derived tag-push identity/u,
  );
});

test("optional unavailable engines do not become a global product release gate", () => {
  const result = validateProductEngineRegistry([
    { id: "ready-engine", status: "integrated", compatibility: { runnable: true } },
    {
      id: "optional-engine",
      status: "planned",
      compatibility: { runnable: false, blocked_by: ["artifact_not_published"] },
    },
  ]);
  assert.deepEqual(result, {
    engineCount: 2,
    unavailableEngineIds: ["optional-engine"],
    rejectedEntries: [],
  });
});

test("malformed optional engine records are isolated instead of becoming a product gate", () => {
  assert.deepEqual(
    validateProductEngineRegistry([
      { id: "ready", status: "integrated", compatibility: { runnable: true } },
      { id: "ready", status: "integrated", compatibility: { runnable: true } },
      { id: "sibling", status: "integrated", compatibility: { runnable: true } },
      { status: "planned" },
      { id: " sibling ", status: "integrated", compatibility: { runnable: true } },
    ]),
    {
      engineCount: 1,
      unavailableEngineIds: [],
      rejectedEntries: [
        { index: 0, id: "ready", code: "duplicate_engine_id" },
        { index: 1, id: "ready", code: "duplicate_engine_id" },
        { index: 3, id: null, code: "missing_engine_id" },
        { index: 4, id: " sibling ", code: "non_canonical_engine_id" },
      ],
    },
  );
  assert.deepEqual(validateProductEngineRegistry(null), {
    engineCount: 0,
    unavailableEngineIds: [],
    rejectedEntries: [{ index: null, id: null, code: "catalog_not_array" }],
  });
});

test("the generic release policy entry point succeeds without platform qualification or release builds", () => {
  const result = spawnSync(process.execPath, ["scripts/release/validate-release.mjs"], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /Common release identity and publication policy are consistent/u);
});

test("product release validation does not depend on subordinate marketing prose", async () => {
  const source = await readFile(
    path.join(projectRoot, "scripts/release/validate-release.mjs"),
    "utf8",
  );
  for (const staleCoupling of [
    "repositoryReadme",
    "releaseGuide",
    "releaseLineNotes",
    "README release line is out of sync",
    "release guide does not document the strict pre-release hosted-macOS observation contract",
    "release-line notes omit the honest hosted-macOS pre-release qualification contract",
    "macos-15-intel",
    "github_hosted_macos_nested_virtualization_unsupported",
    "Installed macOS desktop exited before the 12-second observation window.",
    "PUBLIC_RELEASE_BLOCKED_AUTHENTICODE",
    "engine catalog must contain 21 records",
    "release requires every required engine",
    "scripts/validate-engine-catalog.mjs",
    "scripts/engine-image-evidence.mjs",
    "validatePlatformQualificationSources",
    "validateManagedRuntimeBuildContract",
    "validateManagedRuntimeExecutionContract",
    "assertOrderedTokens",
    "assertSourceStringArray",
    "sourceFunction",
    "managed_runtime_recovery:wsl_distribution_requires_manual_action",
  ]) {
    assert.equal(source.includes(staleCoupling), false, `stale global coupling remains: ${staleCoupling}`);
  }
  const mainSource = source.slice(source.indexOf("async function main()"));
  for (const platformCoupling of [
    "validateManagedRuntimeBuildContract(",
    "validateManagedRuntimeExecutionContract(",
    "validatePlatformQualificationSources(",
    "validate-windows-nsis-template.mjs",
    "qualify-windows-nsis-upgrade.ps1",
    "qualify-windows-nsis-ghost-recovery.ps1",
    "validateProductEngineRegistry(catalog)",
  ]) {
    assert.equal(
      mainSource.includes(platformCoupling),
      false,
      `generic release policy still invokes a platform/engine contract: ${platformCoupling}`,
    );
  }
});
