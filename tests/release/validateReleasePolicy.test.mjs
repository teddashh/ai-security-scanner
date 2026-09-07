import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

import {
  validateProductEngineRegistry,
  validateReleaseWorkflow,
} from "../../scripts/release/validate-release.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const secureCandidateWorkflow = parse(
  readFileSync(path.join(projectRoot, ".github/workflows/release.yml"), "utf8"),
);
const securePromotionWorkflow = parse(
  readFileSync(path.join(projectRoot, ".github/workflows/promote-release.yml"), "utf8"),
);

function secureWorkflowPair() {
  return {
    candidate: structuredClone(secureCandidateWorkflow),
    promotion: structuredClone(securePromotionWorkflow),
  };
}

function validatePair({ candidate, promotion }) {
  return validateReleaseWorkflow(candidate, promotion);
}

test("release policy accepts manual candidate freeze and protected exact-byte promotion", () => {
  const pair = secureWorkflowPair();
  assert.doesNotThrow(() => validatePair(pair));
  assert.deepEqual(Object.keys(pair.candidate.on), ["workflow_dispatch"]);
  assert.equal(pair.candidate.jobs.publish, undefined);
  assert.equal(pair.promotion.jobs.publish.environment, "release-publication");
});

test("candidate dispatch accepts only false-by-default public intent and fixture switches", () => {
  const pair = secureWorkflowPair();
  pair.candidate.on.workflow_dispatch.inputs.unsafe_publish_anyway = {
    description: "unsafe",
    required: false,
    type: "boolean",
    default: false,
  };
  assert.throws(
    () => validatePair(pair),
    /may accept only false-by-default public-candidate and Windows-fixture switches/u,
  );
});

test("public candidate intent must seal, verify, and freeze one exact assembled input", () => {
  const pair = secureWorkflowPair();
  const steps = pair.candidate.jobs["finalize-supported-artifacts"].steps;
  steps.splice(steps.findIndex((step) => step.run?.includes("release-candidate-lock.mjs verify")), 1);
  assert.throws(
    () => validatePair(pair),
    /consecutively lock, verify, freeze, then preview-finalize/u,
  );
});

test("candidate artifact name is attempt-scoped and non-overwriting", () => {
  const pair = secureWorkflowPair();
  const upload = pair.candidate.jobs["finalize-supported-artifacts"].steps.find(
    (step) => step.id === "upload_candidate",
  );
  upload.with.name = "release-candidate-input";
  assert.throws(
    () => validatePair(pair),
    /consecutively lock, verify, freeze, then preview-finalize/u,
  );
});

test("candidate workflow has no publication or attestation authority", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs["finalize-supported-artifacts"].steps.push({
    uses: "softprops/action-gh-release@" + "a".repeat(40),
  });
  assert.throws(
    () => validatePair(pair),
    /must not publish a GitHub Release/u,
  );
});

test("candidate jobs cannot receive write authority", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs["finalize-supported-artifacts"].permissions.packages = "write";
  assert.throws(
    () => validatePair(pair),
    /finalize-supported-artifacts job must not receive write permissions/u,
  );
});

test("release workflow rejects coupled installer sibling failures", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs.build.steps.find(({ id }) => id === "bundle_msi")["continue-on-error"] = false;
  assert.throws(
    () => validatePair(pair),
    /bundle_msi must independently bundle its installer and continue after sibling failure/u,
  );
});

test("installer-only bundle formats cannot depend on updater private keys", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs.build.steps.find(({ id }) => id === "bundle_msi").env = {
    TAURI_SIGNING_PRIVATE_KEY: "$" + "{{ secrets.TAURI_SIGNING_PRIVATE_KEY }}",
  };
  assert.throws(
    () => validatePair(pair),
    /bundle_msi must not depend on updater signing material/u,
  );
});

test("candidate assembly rejects an unprotected cross-run observation namespace", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs["finalize-supported-artifacts"].steps.unshift({
    uses: "actions/download-artifact@" + "d".repeat(40),
    "continue-on-error": true,
    with: {
      pattern: "artifact-promotion-evidence-*",
      path: "assembled-input",
      "merge-multiple": true,
    },
  });
  assert.throws(
    () => validatePair(pair),
    /must not ingest an unprotected observation or promotion namespace/u,
  );
});

test("promotion inputs are limited to exact candidate and complete evidence selectors", () => {
  const pair = secureWorkflowPair();
  delete pair.promotion.on.workflow_dispatch.inputs.evidence_artifact_digest;
  assert.throws(
    () => validatePair(pair),
    /only exact candidate and all-or-none protected-evidence selectors/u,
  );
});

test("promotion is restricted to the workflow definition on main", () => {
  const pair = secureWorkflowPair();
  const selectors = pair.promotion.jobs.assemble.steps.find((step) => step.id === "selectors");
  selectors.run = selectors.run.replace(
    "promotion workflow ref is not the protected main-branch workflow",
    "unchecked workflow ref",
  );
  assert.throws(
    () => validatePair(pair),
    /fail closed on canonical candidate and all-or-none evidence identities/u,
  );
});

test("candidate artifact selection uses exact run, attempt, ID, and canonical digest", () => {
  const pair = secureWorkflowPair();
  const candidateProducer = pair.promotion.jobs.assemble.steps.find(
    (step) => step.run?.includes("candidate workflow run ID mismatch"),
  );
  candidateProducer.env.CANDIDATE_ARTIFACT_DIGEST =
    "$" + "{{ inputs.candidate_artifact_digest }}";
  assert.throws(
    () => validatePair(pair),
    /must use the selector's canonical artifact digest/u,
  );
});

test("promotion accepts upload-artifact SHA-256 prefixes only through canonical normalization", () => {
  const pair = secureWorkflowPair();
  const selectors = pair.promotion.jobs.assemble.steps.find((step) => step.id === "selectors");
  selectors.run = selectors.run.replace("(?:sha256:)?", "");
  assert.throws(
    () => validatePair(pair),
    /fail closed on canonical candidate and all-or-none evidence identities/u,
  );
});

test("candidate producer verification resolves the exact workflow attempt", () => {
  const pair = secureWorkflowPair();
  const candidateProducer = pair.promotion.jobs.assemble.steps.find(
    (step) => step.run?.includes("candidate workflow run ID mismatch"),
  );
  candidateProducer.run = candidateProducer.run.replace(
    "/attempts/" + "$" + "{CANDIDATE_RUN_ATTEMPT}",
    "",
  );
  assert.throws(
    () => validatePair(pair),
    /candidate producer verification is missing/u,
  );
});

test("promotion downloads candidate bytes only by exact artifact ID", () => {
  const pair = secureWorkflowPair();
  const download = pair.promotion.jobs.assemble.steps.find(
    (step) => step.with?.path === "candidate-input",
  );
  delete download.with["artifact-ids"];
  download.with.name = "release-candidate-input-*";
  assert.throws(
    () => validatePair(pair),
    /download the exact verified candidate artifact ID/u,
  );
});

test("promotion reverifies the candidate lock in public mode", () => {
  const pair = secureWorkflowPair();
  const lock = pair.promotion.jobs.assemble.steps.find((step) => step.id === "candidate_lock");
  lock.run = lock.run.replace("public-github-release", "commit-bound-qc");
  assert.throws(
    () => validatePair(pair),
    /reverify the candidate lock against every protected producer identity/u,
  );
});

test("accepted evidence is exact-ID selected after protected producer verification", () => {
  const pair = secureWorkflowPair();
  const download = pair.promotion.jobs.assemble.steps.find(
    (step) => step.with?.path === "accepted-evidence",
  );
  download.with["artifact-ids"] = "$" + "{{ inputs.candidate_artifact_id }}";
  assert.throws(
    () => validatePair(pair),
    /only the exact accepted-evidence artifact ID/u,
  );
});

test("accepted evidence is verified then materialized through the trusted CLI", () => {
  const pair = secureWorkflowPair();
  const steps = pair.promotion.jobs.assemble.steps;
  const receiptIndex = steps.findIndex((step) =>
    step.run?.includes("windows-external-evidence.mjs verify-receipt"),
  );
  [steps[receiptIndex], steps[receiptIndex + 1]] = [steps[receiptIndex + 1], steps[receiptIndex]];
  assert.throws(
    () => validatePair(pair),
    /receipt-verified then materialized without an intervening step/u,
  );
});

test("promotion forbids inline base64 evidence and release rebuilds", () => {
  for (const forbidden of ["base64 evidence.txt", "npm run tauri build"]) {
    const pair = secureWorkflowPair();
    pair.promotion.jobs.assemble.steps.unshift({ run: forbidden });
    assert.throws(
      () => validatePair(pair),
      /must not rebuild or inline external evidence/u,
    );
  }
});

test("finalization passes protected evidence provenance only through an optional argument array", () => {
  const pair = secureWorkflowPair();
  const finalize = pair.promotion.jobs.assemble.steps.find(
    (step) => step.run?.includes("scripts/release/finalize-release.mjs"),
  );
  finalize.run = finalize.run.replace("--external-evidence-job import", "");
  assert.throws(
    () => validatePair(pair),
    /public finalizer must pass the exact protected evidence identity/u,
  );
});

test("publisher crosses the release environment with only scoped write authority", () => {
  const pair = secureWorkflowPair();
  pair.promotion.jobs.publish.permissions.packages = "write";
  assert.throws(
    () => validatePair(pair),
    /must receive only release, attestation, and finalized-artifact permissions/u,
  );
  const secondPair = secureWorkflowPair();
  secondPair.promotion.jobs.publish.environment = "unprotected";
  assert.throws(
    () => validatePair(secondPair),
    /cross the protected release-publication environment/u,
  );
});

test("publisher downloads only the same-run finalized artifact ID", () => {
  const pair = secureWorkflowPair();
  const download = pair.promotion.jobs.publish.steps.find(
    (step) => step.uses?.includes("actions/download-artifact@"),
  );
  download.with.name = "release-finalized";
  assert.throws(
    () => validatePair(pair),
    /only the exact same-run finalized artifact ID/u,
  );
});

test("publisher revalidates optional evidence provenance before attestation", () => {
  const pair = secureWorkflowPair();
  const verify = pair.promotion.jobs.publish.steps.find(
    (step) => step.run?.includes("verify-finalized-release.mjs"),
  );
  delete verify.env.EXPECTED_EVIDENCE_WORKFLOW_REF;
  assert.throws(
    () => validatePair(pair),
    /reverify finalized metadata against the exact optional protected evidence identity/u,
  );
});

test("publisher rejects artifact mutation after final verification", () => {
  const pair = secureWorkflowPair();
  const steps = pair.promotion.jobs.publish.steps;
  const attestIndex = steps.findIndex((step) => step.uses?.includes("attest-build-provenance@"));
  steps.splice(attestIndex, 0, { run: "cp unverified release-assets/unverified" });
  assert.throws(
    () => validatePair(pair),
    /consecutively download, reverify, attest, guard the tag, then publish/u,
  );
});

test("GitHub Release publication cannot overwrite an existing release asset", () => {
  const pair = secureWorkflowPair();
  const publication = pair.promotion.jobs.publish.steps.find(
    (step) => step.uses?.includes("softprops/action-gh-release@"),
  );
  publication.with.overwrite_files = true;
  assert.throws(
    () => validatePair(pair),
    /non-overwriting release from exact verified and attested files/u,
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

test("Windows NSIS source validation is isolated to the Windows installer matrix", async () => {
  const workflow = parse(await readFile(path.join(projectRoot, ".github/workflows/release.yml"), "utf8"));
  const validationCommand = "node scripts/release/validate-windows-nsis-template.mjs";
  const commonSteps = workflow.jobs.validate.steps;
  const buildSteps = workflow.jobs.build.steps;

  assert.equal(commonSteps.some((step) => step?.run === validationCommand), false);
  const platformSteps = buildSteps.filter((step) => step?.run === validationCommand);
  assert.equal(platformSteps.length, 1);
  assert.equal(platformSteps[0].if, "matrix.platform == 'windows-x86_64'");
  assert.equal(workflow.jobs.build["continue-on-error"], true);
});
