import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";
import {
  PROJECT_ROOT,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
} from "./lib.mjs";
import { validateReleaseMetadataV3 } from "./release-metadata.mjs";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function compareNumericSemver(left, right) {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
  }
  return 0;
}

function cargoPackageVersion(toml) {
  const packageStart = toml.indexOf("[package]");
  if (packageStart === -1) {
    throw new Error("src-tauri/Cargo.toml has no package section");
  }
  const remainder = toml.slice(packageStart + "[package]".length);
  const nextSection = remainder.search(/^\[/mu);
  const packageSection = nextSection === -1 ? remainder : remainder.slice(0, nextSection);
  const version = packageSection?.match(/^version\s*=\s*"([^"]+)"\s*$/mu)?.[1];
  if (!version) {
    throw new Error("src-tauri/Cargo.toml has no package version");
  }
  return version;
}

function cargoLockPackageVersion(lock) {
  const packageRecord = lock.match(
    /\[\[package\]\]\r?\nname = "ai-security-scanner"\r?\nversion = "([^"]+)"/u,
  );
  if (!packageRecord) {
    throw new Error("Cargo.lock has no ai-security-scanner package version");
  }
  return packageRecord[1];
}

function validateReleaseMetadata(metadata, version, tag, releaseChannel, releaseTarget, publicationMode) {
  validateReleaseMetadataV3(metadata, {
    releaseState: "prepared",
    version,
    tag,
    publicationMode,
  });
  assert(metadata.releaseChannel === releaseChannel, "release metadata channel is incorrect");
  assert(metadata.stableTarget === releaseTarget, "release metadata stable target is incorrect");
  assert(
    ["commit-bound-qc", "public-github-release"].includes(publicationMode),
    "expected publication mode is invalid",
  );
}

function validateActionReferences(value, workflowName) {
  if (Array.isArray(value)) {
    for (const item of value) {
      validateActionReferences(item, workflowName);
    }
    return;
  }
  if (!value || typeof value !== "object") {
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (key === "uses") {
      assert(typeof item === "string", `${workflowName} has a non-string action reference`);
      if (item.startsWith("./")) {
        continue;
      }
      if (item.startsWith("docker://")) {
        assert(
          /@sha256:[0-9a-f]{64}$/u.test(item),
          `${workflowName} container action must use an immutable digest: ${item}`,
        );
        continue;
      }
      const separator = item.lastIndexOf("@");
      assert(separator > 0, `${workflowName} has an unversioned action: ${item}`);
      const revision = item.slice(separator + 1);
      assert(
        /^[0-9a-f]{40}$/u.test(revision),
        `${workflowName} action must be pinned to a full commit SHA: ${item}`,
      );
      continue;
    }
    validateActionReferences(item, workflowName);
  }
}

async function readWorkflow(relative, label) {
  const file = path.join(PROJECT_ROOT, relative);
  const source = await readFile(file, "utf8");
  const document = parseDocument(source, { prettyErrors: true, strict: true });
  if (document.errors.length > 0) {
    throw new Error(`${label} is invalid YAML: ${document.errors[0].message}`);
  }
  const workflow = document.toJS();
  assert(workflow && typeof workflow === "object", `${label} must contain a mapping`);
  assert(workflow.jobs && typeof workflow.jobs === "object", `${label} has no jobs`);
  validateActionReferences(workflow, label);
  return workflow;
}

async function readReleaseWorkflow() {
  return readWorkflow(".github/workflows/release.yml", "release.yml");
}

async function readPromotionWorkflow() {
  return readWorkflow(".github/workflows/promote-release.yml", "promote-release.yml");
}

export function validateReleaseWorkflow(workflow, promotionWorkflow) {
  assert(workflow, ".github/workflows/release.yml is missing");
  assert(promotionWorkflow, ".github/workflows/promote-release.yml is missing");
  validateActionReferences(workflow, "release.yml");
  const trigger = workflow.on;
  assert(trigger && typeof trigger === "object", "release workflow has no structured trigger");
  assert(
    JSON.stringify(Object.keys(trigger)) === JSON.stringify(["workflow_dispatch"]),
    "release candidate workflow must be manually dispatched and must not rebuild from a tag push",
  );
  const dispatch = trigger.workflow_dispatch;
  const publicCandidateInput = dispatch?.inputs?.public_release_candidate;
  const dataPreservationInput = dispatch?.inputs?.windows_data_preservation;
  assert(
    dispatch && typeof dispatch === "object" &&
      JSON.stringify(Object.keys(dispatch)) === JSON.stringify(["inputs"]) &&
      JSON.stringify(Object.keys(dispatch.inputs ?? {})) ===
        JSON.stringify(["public_release_candidate", "windows_data_preservation"]) &&
      [publicCandidateInput, dataPreservationInput].every((input) =>
        input && typeof input === "object" &&
          JSON.stringify(Object.keys(input).sort()) ===
            JSON.stringify(["default", "description", "required", "type"]) &&
          typeof input.description === "string" && input.description.length > 0 &&
          input.required === false && input.type === "boolean" && input.default === false),
    "release candidate workflow may accept only false-by-default public-candidate and Windows-fixture switches",
  );
  const supportsOptionalWindowsDataPreservation = true;
  assert(workflow.permissions?.contents === "read", "release workflow default contents permission must be read");
  assert(
    !Object.values(workflow.permissions ?? {}).includes("write"),
    "release workflow defaults must not grant write authority",
  );
  const identityEntries = Object.entries(workflow.jobs ?? {}).filter(([, job]) =>
    job.steps?.some((step) => step.id === "identity"),
  );
  assert(identityEntries.length === 1, "release workflow must have one identity resolver");
  const [identityJobName, validate] = identityEntries[0];
  assert(
    validate.outputs?.version === "${{ steps.identity.outputs.version }}" &&
      validate.outputs?.tag === "${{ steps.identity.outputs.tag }}" &&
      validate.outputs?.commit === "${{ steps.identity.outputs.commit }}",
    "release workflow must export its version-derived candidate identity",
  );
  assert(
    validate.outputs?.release_channel === "${{ steps.identity.outputs.release_channel }}" &&
      validate.outputs?.publication_mode === "${{ steps.identity.outputs.publication_mode }}" &&
      validate.outputs?.prerelease === "${{ steps.identity.outputs.prerelease }}" &&
      validate.outputs?.make_latest === "${{ steps.identity.outputs.make_latest }}",
    "release workflow must export its source-declared publication channel",
  );
  const identity = validate.steps?.find((step) => step.id === "identity");
  assert(identity && typeof identity.run === "string", "release workflow has no identity resolver");
  for (const required of [
    'candidate_tag="v${version}"',
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
    'case "${PUBLIC_RELEASE_CANDIDATE}" in',
    'true) publication_mode="public-github-release" ;;',
    'false) publication_mode="commit-bound-qc" ;;',
    '"${EVENT_NAME}" != "workflow_dispatch" || "${EVENT_REF}" != "refs/heads/main"',
    "prerelease=%s",
    "make_latest=%s",
  ]) {
    assert(identity.run.includes(required), `release identity resolver is missing: ${required}`);
  }

  const collectionEntries = Object.entries(workflow.jobs ?? {}).filter(([, job]) =>
    job.steps?.some((step) =>
      typeof step.run === "string" && step.run.includes("scripts/release/collect-bundles.mjs"),
    ),
  );
  assert(collectionEntries.length === 1, "release workflow must have one installer collection job");
  const [buildJobName, buildJob] = collectionEntries[0];
  assert(buildJob["continue-on-error"] === true, "platform build job must not cancel supported siblings");
  const buildSteps = buildJob.steps ?? [];
  const unbundledBuilds = buildSteps.filter((step) =>
    typeof step.run === "string" && step.run.includes("tauri build") && step.run.includes("--no-bundle"),
  );
  assert(
    unbundledBuilds.length === 1 && unbundledBuilds[0].id === "build_unbundled",
    "platform build must compile once with one identified tauri build --no-bundle step",
  );
  const installerBundleSteps = [
    ["bundle_deb", "--bundles deb"],
    ["bundle_rpm", "--bundles rpm"],
    ["bundle_appimage", "--bundles appimage"],
    ["bundle_macos", "--bundles app,dmg"],
    ["bundle_nsis", "--bundles nsis"],
    ["bundle_msi", "--bundles msi"],
  ];
  for (const [stepId, bundleArgument] of installerBundleSteps) {
    const step = buildSteps.find((candidate) => candidate.id === stepId);
    assert(
      step && typeof step.run === "string" &&
        step.run.includes("scripts/release/bundle-with-optional-updater.mjs") &&
        step.run.includes(bundleArgument) && step["continue-on-error"] === true,
      `${stepId} must independently bundle its installer and continue after sibling failure`,
    );
    if (["bundle_deb", "bundle_rpm", "bundle_msi"].includes(stepId)) {
      assert(
        !Object.hasOwn(step.env ?? {}, "TAURI_SIGNING_PRIVATE_KEY"),
        `${stepId} must not depend on updater signing material`,
      );
    }
  }
  const availableStep = buildSteps.find((step) => step.id === "available_bundles");
  const availableSource = JSON.stringify(availableStep ?? {});
  assert(
    installerBundleSteps.every(([stepId]) => availableSource.includes(`steps.${stepId}.outcome`)),
    "installer collection must derive availability from every independent bundle-step outcome",
  );
  const collectStep = buildSteps.find((step) =>
    typeof step.run === "string" && step.run.includes("scripts/release/collect-bundles.mjs"),
  );
  assert(
    collectStep?.run.includes("--expect") && collectStep.run.includes("--available") &&
      String(collectStep.if ?? "").includes("steps.available_bundles.outcome"),
    "installer collection must pass requested and successful bundle sets explicitly",
  );

  let windowsDataPreservationJobName = null;
  if (supportsOptionalWindowsDataPreservation) {
    const entries = Object.entries(workflow.jobs ?? {}).filter(([, job]) =>
      String(job.if ?? "").includes("inputs.windows_data_preservation"),
    );
    assert(
      entries.length === 1,
      "the optional Windows data-preservation input must control exactly one supporting job",
    );
    const [jobName, job] = entries[0];
    windowsDataPreservationJobName = jobName;
    const condition = String(job.if).replaceAll(/\s+/gu, " ").trim();
    assert(
      condition === "github.event_name == 'workflow_dispatch' && inputs.windows_data_preservation == true" &&
        job["continue-on-error"] === true &&
        job["timeout-minutes"] === 360 &&
        job["runs-on"] === "windows-2025" &&
        job.permissions?.contents === "read" &&
        !Object.values(job.permissions ?? {}).includes("write"),
      "Windows data-preservation fixtures must remain explicit, bounded, read-only, and non-gating",
    );
    const needs = Array.isArray(job.needs) ? job.needs : [job.needs].filter(Boolean);
    assert(
      needs.includes(identityJobName) && needs.includes(buildJobName),
      "Windows data-preservation fixtures must bind the exact identity and Windows installer bytes",
    );
    const scenarios = job.strategy?.matrix?.include;
    const expectedScenarios = {
      "n-minus-one-upgrade": {
        fixture_script: "scripts/release/qualify-windows-nsis-upgrade.ps1",
        evidence_script: "scripts/release/windows-nsis-upgrade-evidence.mjs",
        work_name: "ai-security-scanner-nsis-upgrade-evidence",
      },
      "ghost-repair-uninstall": {
        fixture_script: "scripts/release/qualify-windows-nsis-ghost-recovery.ps1",
        evidence_script: "scripts/release/windows-nsis-ghost-recovery-evidence.mjs",
        work_name: "ai-security-scanner-nsis-ghost-recovery-evidence",
      },
    };
    assert(
      Array.isArray(scenarios) && scenarios.length === 2 &&
        JSON.stringify(scenarios.map(({ scenario }) => scenario).sort()) ===
          JSON.stringify(["ghost-repair-uninstall", "n-minus-one-upgrade"]),
      "Windows data-preservation fixtures must keep N-1 and ambiguous-runtime evidence separate",
    );
    for (const scenario of scenarios) {
      const expected = expectedScenarios[scenario.scenario];
      assert(
        expected &&
          JSON.stringify(Object.keys(scenario).sort()) ===
            JSON.stringify(["evidence_script", "fixture_script", "scenario", "work_name"]) &&
          scenario.fixture_script === expected.fixture_script &&
          scenario.evidence_script === expected.evidence_script &&
          scenario.work_name === expected.work_name,
        `Windows supporting fixture contract drifted: ${scenario.scenario}`,
      );
    }
    const jobSource = JSON.stringify(job);
    for (const required of [
      "qualify-windows-nsis-upgrade.ps1",
      "qualify-windows-nsis-ghost-recovery.ps1",
      "windows-nsis-upgrade-evidence.mjs",
      "windows-nsis-ghost-recovery-evidence.mjs",
      "ai-security-scanner-nsis-upgrade-evidence",
      "ai-security-scanner-nsis-ghost-recovery-evidence",
      "${{ matrix.work_name }}",
      "windows-nsis-supporting-data-preservation-${{ matrix.scenario }}",
      "supporting-evidence/",
    ]) {
      assert(jobSource.includes(required), `Windows supporting fixture job is missing: ${required}`);
    }
  }

  validateReleaseCandidateFreeze({
    workflow,
    identityJobName,
    buildJobName,
    windowsDataPreservationJobName,
  });
  validatePromotionWorkflow(promotionWorkflow);
}

function validateReleaseCandidateFreeze({
  workflow,
  identityJobName,
  buildJobName,
  windowsDataPreservationJobName,
}) {
  const allReleaseSteps = Object.values(workflow.jobs ?? {}).flatMap((job) => job.steps ?? []);
  const unsupportedPromotionDownloads = allReleaseSteps.filter((step) =>
    typeof step.uses === "string" &&
      step.uses.includes("actions/download-artifact@") &&
      ["artifact-qc-observations-*", "artifact-promotion-evidence-*"].includes(step.with?.pattern),
  );
  assert(
    unsupportedPromotionDownloads.length === 0,
    "release candidate workflow must not ingest an unprotected observation or promotion namespace",
  );
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    assert(
      !Object.values(job.permissions ?? {}).includes("write"),
      `${jobName} job must not receive write permissions`,
    );
    const source = JSON.stringify(job);
    assert(!source.includes("action-gh-release"), "release candidate workflow must not publish a GitHub Release");
    assert(!source.includes("attest-build-provenance"), "release candidate workflow must not create attestations");
  }

  const finalizerEntries = Object.entries(workflow.jobs ?? {}).filter(([, job]) =>
    job.steps?.some((step) =>
      typeof step.run === "string" && step.run.includes("scripts/release/finalize-release.mjs"),
    ),
  );
  assert(finalizerEntries.length === 1, "release candidate workflow must have exactly one finalizer");
  const [finalizerJobName, finalizer] = finalizerEntries[0];
  assert(finalizer["continue-on-error"] === undefined, "candidate finalizer cannot continue after failure");
  const finalizerNeeds = Array.isArray(finalizer.needs)
    ? finalizer.needs
    : [finalizer.needs].filter(Boolean);
  assert(
    finalizerNeeds.includes(identityJobName) && finalizerNeeds.includes(buildJobName),
    "candidate finalizer must consume the version-derived identity and collected installer siblings",
  );
  if (windowsDataPreservationJobName) {
    assert(
      finalizerNeeds.includes(windowsDataPreservationJobName),
      "candidate finalizer must wait for explicitly requested same-run Windows supporting fixtures",
    );
  }
  const finalizerSteps = finalizer.steps ?? [];
  if (windowsDataPreservationJobName) {
    const preservationDownloads = finalizerSteps.filter((step) =>
      typeof step.uses === "string" &&
        step.uses.includes("actions/download-artifact@") &&
        step.with?.pattern === "windows-nsis-supporting-data-preservation-*",
    );
    assert(
      preservationDownloads.length === 1 &&
        preservationDownloads[0]["continue-on-error"] === true &&
        preservationDownloads[0].with?.path === "assembled-input" &&
        preservationDownloads[0].with?.["merge-multiple"] === true &&
        preservationDownloads[0].with?.["run-id"] === undefined &&
        preservationDownloads[0].with?.["github-token"] === undefined,
      "candidate finalizer must optionally ingest only exact-current-run Windows supporting evidence",
    );
  }

  const candidateCreateIndex = finalizerSteps.findIndex((step) =>
    typeof step.run === "string" &&
      step.run.includes("scripts/release/release-candidate-lock.mjs create"),
  );
  const candidateVerifyIndex = finalizerSteps.findIndex((step) =>
    typeof step.run === "string" &&
      step.run.includes("scripts/release/release-candidate-lock.mjs verify"),
  );
  const candidateUploadIndex = finalizerSteps.findIndex((step) =>
    typeof step.uses === "string" &&
      step.uses.includes("actions/upload-artifact@") &&
      step.with?.name === "release-candidate-input-${{ github.run_id }}-${{ github.run_attempt }}",
  );
  const finalizeIndex = finalizerSteps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("scripts/release/finalize-release.mjs"),
  );
  assert(
    candidateCreateIndex >= 0 &&
      candidateVerifyIndex === candidateCreateIndex + 1 &&
      candidateUploadIndex === candidateVerifyIndex + 1 &&
      finalizeIndex === candidateUploadIndex + 1,
    "public candidate preparation must consecutively lock, verify, freeze, then preview-finalize one assembled input",
  );
  const candidateCondition = "inputs.public_release_candidate == true";
  for (const [index, label] of [
    [candidateCreateIndex, "candidate lock creation"],
    [candidateVerifyIndex, "candidate lock verification"],
    [candidateUploadIndex, "candidate freeze upload"],
  ]) {
    const step = finalizerSteps[index];
    assert(step.if === candidateCondition, `${label} must require explicit public candidate intent`);
    assert(step["continue-on-error"] === undefined, `${label} cannot continue after failure`);
  }
  for (const [index, command] of [
    [candidateCreateIndex, "create"],
    [candidateVerifyIndex, "verify"],
  ]) {
    const source = finalizerSteps[index].run;
    for (const required of [
      `release-candidate-lock.mjs ${command}`,
      "--dir assembled-input",
      "--workflow .github/workflows/release.yml",
      '--workflow-sha "${GITHUB_WORKFLOW_SHA}"',
      '--run-id "${GITHUB_RUN_ID}"',
      '--run-attempt "${GITHUB_RUN_ATTEMPT}"',
      "--job finalize-supported-artifacts",
      '--publication-mode "${PUBLICATION_MODE}"',
    ]) {
      assert(source.includes(required), `${command} candidate lock is missing protected binding: ${required}`);
    }
  }
  const candidateUpload = finalizerSteps[candidateUploadIndex];
  assert(
    candidateUpload.id === "upload_candidate" &&
      candidateUpload.with?.path === "assembled-input" &&
      candidateUpload.with?.["if-no-files-found"] === "error" &&
      candidateUpload.with?.["compression-level"] === 0 &&
      candidateUpload.with?.["retention-days"] === 90 &&
      candidateUpload.with?.["include-hidden-files"] === true &&
      candidateUpload.with?.overwrite === false,
    "public candidate upload must preserve the exact locked input as a non-overwriting immutable artifact",
  );

  const finalizerVerifyIndex = finalizerSteps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("scripts/release/verify-finalized-release.mjs"),
  );
  const uploadIndex = finalizerSteps.findIndex((step) =>
    typeof step.uses === "string" &&
      step.uses.includes("actions/upload-artifact@") &&
      step.with?.name === "release-finalized" &&
      step.with?.path === "release-assets",
  );
  assert(
    finalizerVerifyIndex === finalizeIndex + 1 && uploadIndex === finalizerVerifyIndex + 1,
    "candidate preview must consecutively finalize, verify, then upload its exact result",
  );
  for (const [index, label] of [
    [finalizeIndex, "candidate preview finalization"],
    [finalizerVerifyIndex, "candidate preview verification"],
    [uploadIndex, "candidate preview upload"],
  ]) {
    const step = finalizerSteps[index];
    assert(step && step.if === undefined, `${label} cannot be conditionally skipped`);
    assert(step["continue-on-error"] === undefined, `${label} cannot continue after failure`);
  }
  assert(
    finalizerSteps[finalizeIndex].run.includes("--input assembled-input") &&
      finalizerSteps[finalizeIndex].run.includes("--out release-assets") &&
      finalizerSteps[finalizerVerifyIndex].run.includes("--dir release-assets") &&
      finalizerSteps[uploadIndex].with?.["if-no-files-found"] === "error" &&
      finalizerSteps[uploadIndex].with?.["include-hidden-files"] === true &&
      finalizerSteps[uploadIndex].with?.overwrite === undefined,
    "candidate preview must bind its assembled input and clean finalized output without overwrite authority",
  );
  const summaryStep = finalizerSteps[uploadIndex + 1];
  assert(
    summaryStep?.if === candidateCondition &&
      summaryStep?.env?.CANDIDATE_ARTIFACT_ID ===
        "${{ steps.upload_candidate.outputs.artifact-id }}" &&
      summaryStep?.env?.CANDIDATE_ARTIFACT_DIGEST ===
        "${{ steps.upload_candidate.outputs.artifact-digest }}" &&
      summaryStep?.run?.includes("${GITHUB_RUN_ID}") &&
      summaryStep?.run?.includes("${GITHUB_RUN_ATTEMPT}") &&
      summaryStep?.run?.includes("${CANDIDATE_ARTIFACT_ID}") &&
      summaryStep?.run?.includes("${CANDIDATE_ARTIFACT_DIGEST}"),
    "candidate workflow must report the exact run, attempt, artifact ID, and upload digest needed for promotion",
  );

  const identityBindings = [
    ["version", "--version"],
    ["tag", "--tag"],
    ["commit", "--commit"],
    ["publication_mode", "--publication-mode"],
  ];
  const assertIdentityBindings = (step, label) => {
    for (const [outputName, flag] of identityBindings) {
      const expression = `\${{ needs.${identityJobName}.outputs.${outputName} }}`;
      const directBinding = step.run.includes(expression);
      const envBinding = Object.entries(step.env ?? {}).find(([, value]) => value === expression);
      const envReference = envBinding &&
        step.run.includes(flag) &&
        (step.run.includes(`\${${envBinding[0]}}`) || step.run.includes(`$${envBinding[0]}`));
      assert(
        directBinding || envReference,
        `${label} must bind source identity: needs.${identityJobName}.outputs.${outputName}`,
      );
    }
  };
  assertIdentityBindings(finalizerSteps[finalizeIndex], "candidate preview finalizer");
  assertIdentityBindings(finalizerSteps[finalizerVerifyIndex], "candidate preview verification");
}

export function validatePromotionWorkflow(workflow) {
  assert(workflow && typeof workflow === "object", ".github/workflows/promote-release.yml is missing");
  validateActionReferences(workflow, "promote-release.yml");
  const trigger = workflow.on;
  assert(
    trigger && typeof trigger === "object" &&
      JSON.stringify(Object.keys(trigger)) === JSON.stringify(["workflow_dispatch"]),
    "promotion workflow must be manually dispatched only",
  );
  const inputs = trigger.workflow_dispatch?.inputs;
  const requiredInputs = [
    "candidate_run_id",
    "candidate_run_attempt",
    "candidate_artifact_id",
    "candidate_artifact_digest",
    "expected_commit",
  ];
  const optionalInputs = [
    "evidence_run_id",
    "evidence_run_attempt",
    "evidence_artifact_id",
    "evidence_artifact_digest",
  ];
  assert(
    inputs &&
      JSON.stringify(Object.keys(inputs)) === JSON.stringify([...requiredInputs, ...optionalInputs]) &&
      requiredInputs.every((name) =>
        inputs[name]?.required === true &&
          inputs[name]?.type === "string" &&
          typeof inputs[name]?.description === "string" &&
          !Object.hasOwn(inputs[name], "default")) &&
      optionalInputs.every((name) =>
        inputs[name]?.required === false &&
          inputs[name]?.type === "string" &&
          inputs[name]?.default === "" &&
          typeof inputs[name]?.description === "string"),
    "promotion workflow must accept only exact candidate and all-or-none protected-evidence selectors",
  );
  assert(
    JSON.stringify(workflow.permissions) === JSON.stringify({ contents: "read", actions: "read" }),
    "promotion workflow defaults must grant only contents/actions read",
  );
  assert(
    workflow.concurrency?.group === "release-publication" &&
      workflow.concurrency?.["cancel-in-progress"] === false,
    "promotion workflow must serialize release publication without cancelling an in-flight release",
  );
  assert(
    JSON.stringify(Object.keys(workflow.jobs ?? {})) === JSON.stringify(["assemble", "publish"]),
    "promotion workflow must separate one read-only assembler from one protected publisher",
  );
  const assemble = workflow.jobs.assemble;
  const publish = workflow.jobs.publish;
  assert(
    assemble.if === undefined &&
      assemble["continue-on-error"] === undefined &&
      JSON.stringify(assemble.permissions) === JSON.stringify({ contents: "read", actions: "read" }),
    "promotion assembler must fail closed with read-only repository and artifact authority",
  );
  const workflowSource = JSON.stringify(workflow);
  for (const forbidden of [
    "tauri build",
    "bundle-with-optional-updater.mjs",
    "collect-bundles.mjs",
    "vendor-managed-runtime",
    "base64",
  ]) {
    assert(
      !workflowSource.includes(forbidden),
      `promotion workflow must not rebuild or inline external evidence: ${forbidden}`,
    );
  }
  assert(
    assemble.outputs?.version === "${{ steps.candidate_lock.outputs.version }}" &&
      assemble.outputs?.tag === "${{ steps.candidate_lock.outputs.tag }}" &&
      assemble.outputs?.commit === "${{ steps.candidate_lock.outputs.commit }}" &&
      assemble.outputs?.release_channel === "${{ steps.candidate_lock.outputs.release_channel }}" &&
      assemble.outputs?.finalized_artifact_id === "${{ steps.upload_finalized.outputs.artifact-id }}" &&
      assemble.outputs?.finalized_artifact_digest === "${{ steps.upload_finalized.outputs.artifact-digest }}" &&
      assemble.outputs?.has_evidence === "${{ steps.selectors.outputs.has_evidence }}" &&
      assemble.outputs?.evidence_workflow_ref === "${{ steps.evidence_producer.outputs.workflow_ref }}" &&
      assemble.outputs?.evidence_run_id === "${{ steps.selectors.outputs.evidence_run_id }}" &&
      assemble.outputs?.evidence_run_attempt === "${{ steps.selectors.outputs.evidence_run_attempt }}",
    "promotion assembler must export lock-derived identity and exact finalized/evidence identities",
  );

  const steps = assemble.steps ?? [];
  const selectors = steps.find((step) => step.id === "selectors");
  const selectorsSource = JSON.stringify(selectors ?? {});
  for (const required of [
    "CANDIDATE_RUN_ID",
    "CANDIDATE_RUN_ATTEMPT",
    "CANDIDATE_ARTIFACT_ID",
    "CANDIDATE_ARTIFACT_DIGEST",
    "EXPECTED_COMMIT",
    "EVIDENCE_RUN_ID",
    "EVIDENCE_RUN_ATTEMPT",
    "EVIDENCE_ARTIFACT_ID",
    "EVIDENCE_ARTIFACT_DIGEST",
    "PROMOTION_EVENT_NAME",
    "PROMOTION_REF",
    "PROMOTION_SHA",
    "PROMOTION_WORKFLOW_REF",
    "PROMOTION_WORKFLOW_SHA",
    "has_evidence",
  ]) {
    assert(selectorsSource.includes(required), `promotion selector validation is missing: ${required}`);
  }
  assert(
    selectors?.["continue-on-error"] === undefined &&
      selectors?.if === undefined &&
      selectorsSource.includes("complete tuple") &&
      selectorsSource.includes("lowercase SHA-256") &&
      selectorsSource.includes("full lowercase Git object ID") &&
      selectors.run.includes("Number.isSafeInteger") &&
      selectors.run.includes('requiredPositiveInteger("CANDIDATE_RUN_ATTEMPT", 100)') &&
      selectors.run.includes('requiredPositiveInteger("EVIDENCE_RUN_ATTEMPT", 100)') &&
      selectorsSource.includes("^(?:sha256:)?([0-9a-f]{64})$") &&
      selectorsSource.includes("candidate_artifact_digest=${candidateDigest}") &&
      selectorsSource.includes("evidence_artifact_digest=${hasEvidence ? canonicalDigest") &&
      selectorsSource.includes("evidence_run_id=${hasEvidence ? process.env.EVIDENCE_RUN_ID") &&
      selectorsSource.includes("evidence_run_attempt=${hasEvidence ? process.env.EVIDENCE_RUN_ATTEMPT") &&
      selectorsSource.includes("promotion must be manually dispatched from refs/heads/main") &&
      selectorsSource.includes("promotion workflow and event SHA must be the same full lowercase Git object ID") &&
      selectorsSource.includes(".github/workflows/promote-release.yml@refs/heads/main") &&
      selectorsSource.includes("promotion workflow ref is not the protected main-branch workflow"),
    "promotion selectors must fail closed on canonical candidate and all-or-none evidence identities",
  );

  const candidateProducerIndex = steps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("candidate workflow run ID mismatch"),
  );
  assert(candidateProducerIndex >= 0, "promotion must verify the protected candidate workflow run and artifact");
  assert(
    steps[candidateProducerIndex].env?.CANDIDATE_ARTIFACT_DIGEST ===
      "${{ steps.selectors.outputs.candidate_artifact_digest }}",
    "candidate producer verification must use the selector's canonical artifact digest",
  );
  const candidateProducerSource = JSON.stringify(steps[candidateProducerIndex]);
  for (const required of [
    "/actions/runs/${CANDIDATE_RUN_ID}/attempts/${CANDIDATE_RUN_ATTEMPT}",
    "/actions/artifacts/${CANDIDATE_ARTIFACT_ID}",
    ".github/workflows/release.yml",
    "workflow_dispatch",
    "main",
    "completed",
    "success",
    "run_attempt",
    "run.head_repository?.full_name",
    "EXPECTED_COMMIT",
    "release-candidate-input-${process.env.CANDIDATE_RUN_ID}-${process.env.CANDIDATE_RUN_ATTEMPT}",
    "artifact.workflow_run?.id",
    "artifact.workflow_run?.head_sha",
    "artifact.digest",
    "artifact.expired === false",
  ]) {
    assert(candidateProducerSource.includes(required), `candidate producer verification is missing: ${required}`);
  }

  const checkout = steps.find((step) =>
    typeof step.uses === "string" && step.uses.includes("actions/checkout@"),
  );
  assert(
    checkout?.with?.ref === "${{ inputs.expected_commit }}" &&
      checkout.with?.["persist-credentials"] === false,
    "promotion assembler must check out the exact frozen candidate commit without credentials",
  );
  const candidateDownloadIndex = steps.findIndex((step) =>
    typeof step.uses === "string" &&
      step.uses.includes("actions/download-artifact@") &&
      step.with?.path === "candidate-input",
  );
  const candidateDownload = steps[candidateDownloadIndex];
  assert(
    candidateDownloadIndex > candidateProducerIndex &&
      candidateDownload?.with?.["artifact-ids"] === "${{ inputs.candidate_artifact_id }}" &&
      candidateDownload.with?.["run-id"] === "${{ inputs.candidate_run_id }}" &&
      candidateDownload.with?.["github-token"] === "${{ github.token }}" &&
      candidateDownload.with?.repository === "${{ github.repository }}" &&
      candidateDownload.with?.["digest-mismatch"] === "error" &&
      candidateDownload.with?.name === undefined &&
      candidateDownload.with?.pattern === undefined,
    "promotion must download the exact verified candidate artifact ID from its exact run",
  );
  const candidateLockIndex = steps.findIndex((step) => step.id === "candidate_lock");
  const candidateLockSource = JSON.stringify(steps[candidateLockIndex] ?? {});
  assert(
    candidateLockIndex === candidateDownloadIndex + 1 &&
      candidateLockSource.includes("release-candidate-lock.mjs verify") &&
      candidateLockSource.includes("--dir candidate-input") &&
      candidateLockSource.includes("--publication-mode public-github-release") &&
      candidateLockSource.includes("--workflow .github/workflows/release.yml") &&
      candidateLockSource.includes('--workflow-sha \\"${EXPECTED_COMMIT}\\"') &&
      candidateLockSource.includes('--run-id \\"${CANDIDATE_RUN_ID}\\"') &&
      candidateLockSource.includes('--run-attempt \\"${CANDIDATE_RUN_ATTEMPT}\\"') &&
      candidateLockSource.includes("--job finalize-supported-artifacts") &&
      candidateLockSource.includes('--github-output \\"${GITHUB_OUTPUT}\\"'),
    "promotion must reverify the candidate lock against every protected producer identity",
  );

  validatePromotionEvidenceFlow(steps, candidateLockIndex);
  validatePromotionPublication(publish);
}

function validatePromotionEvidenceFlow(steps, candidateLockIndex) {
  const evidenceCondition = "steps.selectors.outputs.has_evidence == 'true'";
  const evidenceProducerIndex = steps.findIndex((step) => step.id === "evidence_producer");
  const evidenceProducer = steps[evidenceProducerIndex];
  const evidenceProducerSource = JSON.stringify(evidenceProducer ?? {});
  assert(
    evidenceProducerIndex === candidateLockIndex + 1 &&
      evidenceProducer?.if === evidenceCondition &&
      evidenceProducer?.["continue-on-error"] === undefined &&
      evidenceProducer?.env?.EVIDENCE_ARTIFACT_DIGEST ===
        "${{ steps.selectors.outputs.evidence_artifact_digest }}",
    "optional evidence must first pass protected producer verification",
  );
  for (const required of [
    "/actions/runs/${EVIDENCE_RUN_ID}/attempts/${EVIDENCE_RUN_ATTEMPT}",
    "/actions/artifacts/${EVIDENCE_ARTIFACT_ID}",
    ".github/workflows/windows-external-evidence.yml",
    "workflow_dispatch",
    "main",
    "completed",
    "success",
    "run_attempt",
    "run.head_repository?.full_name",
    "windows-external-evidence-${process.env.EVIDENCE_RUN_ID}-${process.env.EVIDENCE_RUN_ATTEMPT}",
    "artifact.workflow_run?.id",
    "artifact.workflow_run?.head_sha",
    "artifact.digest",
    "artifact.expired === false",
    "workflow_ref",
  ]) {
    assert(evidenceProducerSource.includes(required), `evidence producer verification is missing: ${required}`);
  }

  const evidenceDownloadIndex = steps.findIndex((step) =>
    typeof step.uses === "string" &&
      step.uses.includes("actions/download-artifact@") &&
      step.with?.path === "accepted-evidence",
  );
  const evidenceDownload = steps[evidenceDownloadIndex];
  assert(
    evidenceDownloadIndex === evidenceProducerIndex + 1 &&
      evidenceDownload?.if === evidenceCondition &&
      evidenceDownload?.["continue-on-error"] === undefined &&
      evidenceDownload.with?.["artifact-ids"] === "${{ inputs.evidence_artifact_id }}" &&
      evidenceDownload.with?.["run-id"] === "${{ inputs.evidence_run_id }}" &&
      evidenceDownload.with?.["github-token"] === "${{ github.token }}" &&
      evidenceDownload.with?.repository === "${{ github.repository }}" &&
      evidenceDownload.with?.["digest-mismatch"] === "error" &&
      evidenceDownload.with?.name === undefined &&
      evidenceDownload.with?.pattern === undefined,
    "promotion must download only the exact accepted-evidence artifact ID from its verified run",
  );
  const receiptIndex = steps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("windows-external-evidence.mjs verify-receipt"),
  );
  const materializeIndex = steps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("windows-external-evidence.mjs materialize"),
  );
  assert(
    receiptIndex === evidenceDownloadIndex + 1 &&
      materializeIndex === receiptIndex + 1 &&
      steps[receiptIndex]?.if === evidenceCondition &&
      steps[materializeIndex]?.if === evidenceCondition &&
      steps[receiptIndex]?.["continue-on-error"] === undefined &&
      steps[materializeIndex]?.["continue-on-error"] === undefined,
    "accepted evidence must be receipt-verified then materialized without an intervening step",
  );
  for (const [index, command] of [[receiptIndex, "verify-receipt"], [materializeIndex, "materialize"]]) {
    const source = steps[index].run;
    assert(
      steps[index].env?.EXPECTED_EVIDENCE_WORKFLOW_REF ===
        "${{ steps.evidence_producer.outputs.workflow_ref }}" &&
        steps[index].env?.EVIDENCE_RUN_ID === "${{ inputs.evidence_run_id }}" &&
        steps[index].env?.EVIDENCE_RUN_ATTEMPT === "${{ inputs.evidence_run_attempt }}",
      `${command} must consume only verified evidence producer outputs`,
    );
    for (const required of [
      `windows-external-evidence.mjs ${command}`,
      "--dir accepted-evidence",
      "--candidate-dir candidate-input",
      '--repository "${GITHUB_REPOSITORY}"',
      "--workflow .github/workflows/windows-external-evidence.yml",
      '--workflow-ref "${EXPECTED_EVIDENCE_WORKFLOW_REF}"',
      '--run-id "${EVIDENCE_RUN_ID}"',
      '--run-attempt "${EVIDENCE_RUN_ATTEMPT}"',
      "--job import",
      "--environment windows-external-evidence",
    ]) {
      assert(source.includes(required), `${command} external-evidence contract is missing: ${required}`);
    }
  }
  assert(
    steps[materializeIndex].run.includes("--out candidate-with-evidence"),
    "verified external evidence must materialize into a separate candidate directory",
  );

  const finalizeIndex = steps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("scripts/release/finalize-release.mjs"),
  );
  const verifyIndex = steps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("scripts/release/verify-finalized-release.mjs"),
  );
  const uploadIndex = steps.findIndex((step) => step.id === "upload_finalized");
  assert(
    finalizeIndex === materializeIndex + 1 &&
      verifyIndex === finalizeIndex + 1 &&
      uploadIndex === verifyIndex + 1,
    "promotion must consecutively materialize, finalize, verify, and freeze its public release",
  );
  const externalEvidenceFlags = [
    '--external-evidence-repository "${GITHUB_REPOSITORY}"',
    "--external-evidence-workflow .github/workflows/windows-external-evidence.yml",
    '--external-evidence-workflow-ref "${EXPECTED_EVIDENCE_WORKFLOW_REF}"',
    '--external-evidence-run-id "${EVIDENCE_RUN_ID}"',
    '--external-evidence-run-attempt "${EVIDENCE_RUN_ATTEMPT}"',
    "--external-evidence-job import",
    "--external-evidence-environment windows-external-evidence",
  ];
  for (const [index, label] of [[finalizeIndex, "public finalizer"], [verifyIndex, "public verification"]]) {
    const step = steps[index];
    assert(
      step.if === undefined && step["continue-on-error"] === undefined &&
        step.env?.HAS_EVIDENCE === "${{ steps.selectors.outputs.has_evidence }}" &&
        step.env?.EXPECTED_EVIDENCE_WORKFLOW_REF ===
          "${{ steps.evidence_producer.outputs.workflow_ref }}" &&
        step.env?.EVIDENCE_RUN_ID === "${{ inputs.evidence_run_id }}" &&
        step.env?.EVIDENCE_RUN_ATTEMPT === "${{ inputs.evidence_run_attempt }}" &&
        step.run.includes('external_evidence_args=()') &&
        step.run.includes('if [[ "${HAS_EVIDENCE}" == "true" ]]') &&
        externalEvidenceFlags.every((flag) => step.run.includes(flag)) &&
        step.run.includes('"${external_evidence_args[@]}"'),
      `${label} must pass the exact protected evidence identity only when evidence is present`,
    );
  }
  assert(
    steps[finalizeIndex].run.includes('candidate_input="candidate-input"') &&
      steps[finalizeIndex].run.includes('candidate_input="candidate-with-evidence"') &&
      steps[finalizeIndex].run.includes("--publication-mode public-github-release") &&
      steps[finalizeIndex].run.includes("--out release-assets") &&
      steps[verifyIndex].run.includes("--dir release-assets") &&
      steps[verifyIndex].run.includes("--publication-mode public-github-release"),
    "promotion finalization and verification must bind the locked candidate and public mode",
  );
  const finalizedUpload = steps[uploadIndex];
  assert(
    finalizedUpload?.uses?.includes("actions/upload-artifact@") &&
      finalizedUpload?.if === undefined &&
      finalizedUpload?.["continue-on-error"] === undefined &&
      finalizedUpload.with?.name === "release-finalized-${{ github.run_id }}-${{ github.run_attempt }}" &&
      finalizedUpload.with?.path === "release-assets" &&
      finalizedUpload.with?.["if-no-files-found"] === "error" &&
      finalizedUpload.with?.["compression-level"] === 0 &&
      finalizedUpload.with?.["retention-days"] === 14 &&
      finalizedUpload.with?.["include-hidden-files"] === true &&
      finalizedUpload.with?.overwrite === false,
    "promotion must freeze the exact finalized public release without overwrite authority",
  );
}

function validatePromotionPublication(publish) {
  assert(
    publish.needs === "assemble" &&
      publish.environment === "release-publication" &&
      publish["continue-on-error"] === undefined,
    "publisher must consume only the assembler and cross the protected release-publication environment",
  );
  const expectedPermissions = {
    contents: "write",
    "id-token": "write",
    attestations: "write",
    actions: "read",
  };
  assert(
    JSON.stringify(publish.permissions) === JSON.stringify(expectedPermissions),
    "publisher must receive only release, attestation, and finalized-artifact permissions",
  );
  const steps = publish.steps ?? [];
  const checkout = steps.find((step) =>
    typeof step.uses === "string" && step.uses.includes("actions/checkout@"),
  );
  assert(
    checkout?.with?.ref === "${{ needs.assemble.outputs.commit }}" &&
      checkout.with?.["persist-credentials"] === false,
    "publisher must check out the exact lock-derived source commit without credentials",
  );
  const downloadIndex = steps.findIndex((step) =>
    typeof step.uses === "string" && step.uses.includes("actions/download-artifact@"),
  );
  const download = steps[downloadIndex];
  assert(
    download?.with?.["artifact-ids"] === "${{ needs.assemble.outputs.finalized_artifact_id }}" &&
      download.with?.path === "release-assets" &&
      download.with?.["digest-mismatch"] === "error" &&
      download.with?.name === undefined &&
      download.with?.pattern === undefined &&
      download.with?.["run-id"] === undefined &&
      download.with?.["github-token"] === undefined,
    "publisher must download only the exact same-run finalized artifact ID",
  );
  const verifyIndex = steps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("scripts/release/verify-finalized-release.mjs"),
  );
  const attestationIndex = steps.findIndex((step) =>
    typeof step.uses === "string" && step.uses.includes("attest-build-provenance@"),
  );
  const tagGuardIndex = steps.findIndex((step) =>
    typeof step.run === "string" && step.run.includes("existing release tag does not bind"),
  );
  const publicationIndex = steps.findIndex((step) =>
    typeof step.uses === "string" && step.uses.includes("softprops/action-gh-release@"),
  );
  assert(
    verifyIndex === downloadIndex + 1 &&
      attestationIndex === verifyIndex + 1 &&
      tagGuardIndex === attestationIndex + 1 &&
      publicationIndex === tagGuardIndex + 1,
    "publisher must consecutively download, reverify, attest, guard the tag, then publish exact bytes",
  );
  for (const [index, label] of [
    [downloadIndex, "publisher artifact download"],
    [verifyIndex, "publisher verification"],
    [attestationIndex, "publisher attestation"],
    [tagGuardIndex, "publisher tag guard"],
    [publicationIndex, "GitHub Release publication"],
  ]) {
    const step = steps[index];
    assert(step && step.if === undefined, `${label} cannot be conditionally skipped`);
    assert(step["continue-on-error"] === undefined, `${label} cannot continue after failure`);
  }
  const verify = steps[verifyIndex];
  const externalEvidenceFlags = [
    '--external-evidence-repository "${GITHUB_REPOSITORY}"',
    "--external-evidence-workflow .github/workflows/windows-external-evidence.yml",
    '--external-evidence-workflow-ref "${EXPECTED_EVIDENCE_WORKFLOW_REF}"',
    '--external-evidence-run-id "${EVIDENCE_RUN_ID}"',
    '--external-evidence-run-attempt "${EVIDENCE_RUN_ATTEMPT}"',
    "--external-evidence-job import",
    "--external-evidence-environment windows-external-evidence",
  ];
  assert(
    verify.env?.HAS_EVIDENCE === "${{ needs.assemble.outputs.has_evidence }}" &&
      verify.env?.EXPECTED_EVIDENCE_WORKFLOW_REF ===
        "${{ needs.assemble.outputs.evidence_workflow_ref }}" &&
      verify.env?.EVIDENCE_RUN_ID === "${{ needs.assemble.outputs.evidence_run_id }}" &&
      verify.env?.EVIDENCE_RUN_ATTEMPT === "${{ needs.assemble.outputs.evidence_run_attempt }}" &&
      verify.run.includes("--dir release-assets") &&
      verify.run.includes("--publication-mode public-github-release") &&
      verify.run.includes('if [[ "${HAS_EVIDENCE}" == "true" ]]') &&
      externalEvidenceFlags.every((flag) => verify.run.includes(flag)) &&
      verify.run.includes('"${external_evidence_args[@]}"'),
    "publisher must reverify finalized metadata against the exact optional protected evidence identity",
  );
  const publishedFiles = "release-assets/**/*";
  assert(
    steps[attestationIndex].with?.["subject-path"] === publishedFiles,
    "publisher attestation must cover every exact finalized file",
  );
  const tagGuardSource = steps[tagGuardIndex].run;
  for (const required of [
    "/git/ref/tags/${encodeURIComponent(releaseTag)}",
    "body: JSON.stringify({ ref: `refs/tags/${releaseTag}`, sha: sourceCommit })",
    "/releases/tags/${encodeURIComponent(releaseTag)}",
    "tagResponse.status === 404",
    "createResponse.status !== 201",
    "releaseResponse.status !== 404",
    "failed closed with HTTP",
    "refusing to update or overwrite",
  ]) {
    assert(tagGuardSource.includes(required), `publisher tag/release guard is missing: ${required}`);
  }
  const publication = steps[publicationIndex];
  assert(
    publication.with?.tag_name === "${{ needs.assemble.outputs.tag }}" &&
      publication.with?.target_commitish === "${{ needs.assemble.outputs.commit }}" &&
      publication.with?.draft === false &&
      publication.with?.prerelease === "${{ needs.assemble.outputs.prerelease }}" &&
      publication.with?.make_latest === "${{ needs.assemble.outputs.make_latest }}" &&
      publication.with?.fail_on_unmatched_files === true &&
      publication.with?.overwrite_files === false &&
      publication.with?.files === publishedFiles,
    "GitHub Release publication must create a non-overwriting release from exact verified and attested files",
  );
}

export function validateProductEngineRegistry(catalog) {
  const records = Array.isArray(catalog) ? catalog : [];
  const rejectedEntries = [];
  const candidates = [];
  if (!Array.isArray(catalog)) {
    rejectedEntries.push({ index: null, id: null, code: "catalog_not_array" });
  }
  for (const [index, engine] of records.entries()) {
    if (typeof engine?.id !== "string" || engine.id.length === 0) {
      rejectedEntries.push({ index, id: null, code: "missing_engine_id" });
      continue;
    }
    if (engine.id !== engine.id.trim()) {
      rejectedEntries.push({ index, id: engine.id, code: "non_canonical_engine_id" });
      continue;
    }
    candidates.push({ index, engine, id: engine.id });
  }
  const idCounts = new Map();
  for (const { id } of candidates) {
    idCounts.set(id, (idCounts.get(id) ?? 0) + 1);
  }
  const admitted = [];
  for (const candidate of candidates) {
    if (idCounts.get(candidate.id) > 1) {
      rejectedEntries.push({
        index: candidate.index,
        id: candidate.id,
        code: "duplicate_engine_id",
      });
      continue;
    }
    admitted.push(candidate.engine);
  }
  rejectedEntries.sort((left, right) => (left.index ?? -1) - (right.index ?? -1));

  // This reports product-data issues without turning an optional engine record
  // into a whole-product publication gate. The engine's own admission workflow
  // remains responsible for artifact, digest, license, provenance, and evidence.
  return {
    engineCount: admitted.length,
    unavailableEngineIds: admitted
      .filter((engine) => engine.status !== "integrated" || engine.compatibility?.runnable !== true)
      .map((engine) => engine.id),
    rejectedEntries,
  };
}

export function validateWindowsQualificationLifecycle(source) {
  source = source.replaceAll(/\r\n?/gu, "\n");
  const install = '  $installStatus = Invoke-Managed "install" @("install")\n';
  const preStartAbsence =
    '    throw "Managed runtime install/status created a provider namespace before start."\n';
  const start = '  $startStatus = Invoke-Managed "start" @("start")\n';
  const namespaceInspection = "  $podmanNamespaceDirectories = @(\n";
  const installIndex = source.indexOf(install);
  const absenceIndex = source.indexOf(preStartAbsence);
  const startIndex = source.indexOf(start);
  const namespaceIndex = source.indexOf(namespaceInspection);
  assert(
    installIndex !== -1 &&
      absenceIndex > installIndex &&
      startIndex > absenceIndex &&
      namespaceIndex > startIndex &&
      source.indexOf(start, startIndex + start.length) === -1,
    "Windows qualification must start the managed provider before inspecting its private namespace",
  );

  const defaultDataRoot =
    '(Join-Path $localApplicationData "dev.teddashh.ai-security-scanner")';
  const containerQualification =
    '  $containerQualification = Invoke-Managed "container-qualification" @("qualify")\n';
  const desktopObservation =
    "  $desktopProcess = Start-Process -FilePath $desktop -PassThru\n";
  const stop = '  $stopStatus = Invoke-Managed "stop" @("stop")\n';
  const containerIndex = source.indexOf(containerQualification);
  const desktopIndex = source.indexOf(desktopObservation);
  const stopIndex = source.indexOf(stop);
  assert(
    source.split(defaultDataRoot).length === 2 &&
      source.includes(
        '[IO.Path]::GetFileName($dataDirectory) -cne "dev.teddashh.ai-security-scanner"',
      ),
    "Windows qualification must exercise the desktop and CLI through the exact product LocalAppData root",
  );
  assert(
    containerIndex !== -1 &&
      desktopIndex > containerIndex &&
      stopIndex > desktopIndex &&
      source.indexOf(desktopObservation, desktopIndex + desktopObservation.length) === -1,
    "Windows desktop observation must occur once while the already-qualified managed runtime is healthy",
  );
  validateSynchronousNsisQualificationFixture(source, "ordinary Windows qualification");
}

export function validateSynchronousNsisQualificationFixture(
  source,
  label,
  { allowsRetainedState = false } = {},
) {
  source = source.replaceAll(/\r\n?/gu, "\n");
  for (const required of [
    'function Invoke-BoundedCopiedNsisUninstaller(',
    '$copyName = "bounded-nsis-uninstaller-copy.exe"',
    'Copy-Item -LiteralPath $SourceUninstaller -Destination $copyPath',
    '[string]$copyProof.Sha256 -cne [string]$sourceBefore.Sha256',
    '[string]$RawFinalNsisUninstallDirectory = ""',
    '$Arguments.Count -ne 1 -or $Arguments[0] -cne "/S"',
    '$rawNsisDirectory = [IO.Path]::GetFullPath($RawFinalNsisUninstallDirectory)',
    '[IO.Path]::IsPathFullyQualified($rawNsisDirectory)',
    "$rawNsisDirectory -cmatch '[\"\\r\\n]'",
    '$startInfo.Arguments = "/S _?=$rawNsisDirectory"',
    '-RawFinalNsisUninstallDirectory $InstallDirectory',
    'Remove-Item -LiteralPath $copyPath -Force',
    'throw "$Label execution copy remains after bounded cleanup."',
  ]) {
    assert(source.includes(required), `${label} is missing copied-uninstaller invariant: ${required}`);
  }
  assert(
    source.split("Invoke-BoundedCopiedNsisUninstaller").length === 4 &&
      source.split('$startInfo.Arguments = "/S _?=$rawNsisDirectory"').length === 2 &&
      source.split("bounded-nsis-uninstaller-copy.exe").length === 2,
    `${label} must define one copied-uninstaller helper with one raw NSIS tail and use it in exactly the happy and failure paths`,
  );
  for (const forbidden of [
    'Invoke-ExactProcess $candidateUninstaller @("/S", "_?=',
    'Invoke-ExactProcess $activeUninstaller @("/S", "_?=',
    'Start-Process -FilePath $uninstallerPath -ArgumentList "/S"',
    'Invoke-BoundedCleanupProcess $uninstallerPath @("/S")',
    '"_?=$InstallDirectory"',
    '$startInfo.ArgumentList.Add("_?=$rawNsisDirectory")',
  ]) {
    assert(
      !source.includes(forbidden),
      `${label} still invokes an installed NSIS uninstaller in place: ${forbidden}`,
    );
  }
  if (allowsRetainedState) {
    assert(
      source.includes("[switch]$AllowRetainedState") &&
      source.includes("$process.ExitCode -ne 10") &&
        source.split("-AllowRetainedState").length === 4 &&
        source.includes("$uninstallResult.exitCode -ne 10") &&
        source.includes("retained the exact application installation directory") &&
        source.includes("retained a product application binary") &&
        source.includes(
          'Get-VerbatimWindowsPath ([string]$Receipt.path) "$Label receipt path"',
        ) &&
        source.includes("$receiptPathProof = Get-NoFollowFileSha256Proof") &&
        !source.includes("[IO.Path]::GetFullPath([string]$Receipt.path)") &&
        /if \(@\(Get-(?:CurrentUserUninstallEntries|ProductRegistryEntries)\)\.Count -ne 0\) \{\r?\n\s+throw "Candidate NSIS (?:uninstall left its current-user product registration behind|uninstaller left the product registry entry)\."\r?\n\s+\}/u.test(
          source,
        ) &&
        /\$appOnlyUninstallSnapshotBefore = (?:Get-PrivateDataSnapshot \$dataDirectory -ExcludeProcessLease|Get-NonLeasePrivateDataSnapshot \$dataDirectory)/u.test(
          source,
        ) &&
        /\$appOnlyUninstallSnapshotAfter = (?:Get-PrivateDataSnapshot \$dataDirectory -ExcludeProcessLease|Get-NonLeasePrivateDataSnapshot \$dataDirectory)/u.test(
          source,
        ) &&
        source.includes("Get-NoFollowEmptyFileProof $processLeasePath") &&
        source.includes("allNonLeaseProductDataPreserved = $true") &&
        !source.includes("completePrivateDataPreserved") &&
        !source.includes("ExcludeManagedRuntimeState") &&
        source.includes("$beginnerReportAfterUninstall = Get-NoFollowFileSha256Proof") &&
        source.includes("Assert-SameFileProof $beginnerReportProof $beginnerReportAfterUninstall") &&
        source.includes(
          "$appOnlyUninstallSnapshotAfter.digest -cne $appOnlyUninstallSnapshotBefore.digest",
        ) &&
        source.includes(
          "$appOnlyUninstallSnapshotAfter.fileCount -ne $appOnlyUninstallSnapshotBefore.fileCount",
        ) &&
        source.includes(
          "$appOnlyUninstallSnapshotAfter.totalBytes -ne $appOnlyUninstallSnapshotBefore.totalBytes",
        ),
      `${label} must accept retained-state status only while independently proving application removal and exact report identity`,
    );
    if (source.includes("Get-ProductRegistryEntries")) {
      const emptyProofStart = source.indexOf("function Get-NoFollowEmptyFileProof(");
      const emptyProofEnd = source.indexOf("\nfunction ", emptyProofStart + 1);
      const emptyProofSource = source.slice(emptyProofStart, emptyProofEnd);
      assert(
        emptyProofStart >= 0 &&
          emptyProofEnd > emptyProofStart &&
          emptyProofSource.includes("NumberOfLinks = [uint32]$before.links") &&
          emptyProofSource.includes("Attributes = [uint32]$before.attributes") &&
          source.includes("function Get-QuiescedVhdSha256Proof(") &&
          source.includes("[DateTime]::UtcNow.AddSeconds(60)") &&
          source.includes("$win32Exception = $_.Exception") &&
          source.includes("$win32Exception = $win32Exception.InnerException") &&
          source.includes("[int]$win32Exception.NativeErrorCode -notin @(32, 33)") &&
          !source.includes("$_.Exception.NativeErrorCode") &&
          source.includes("Start-Sleep -Milliseconds 500") &&
          source.split("Get-QuiescedVhdSha256Proof $oldVhdPath").length === 3 &&
          source.split("Get-QuiescedVhdSha256Proof $unrelatedVhdPath").length === 3 &&
          source.includes("function Assert-ExactFixtureWslRegistrationSet(") &&
          source.includes("function Invoke-FixtureOnlyWslShutdown(") &&
          source.includes("$ExpectedRegistrations.Count -ne 2") &&
          source.includes("$actualRegistrations.Count -ne $ExpectedRegistrations.Count") &&
          source.includes("$actual = Get-ExactWslRegistration $name $basePath") &&
          source.includes("[string]$actual.RegistrationId -cne $registrationId") &&
          source.split("Assert-ExactFixtureWslRegistrationSet $ExpectedRegistrations").length === 3 &&
          source.includes("$runningBefore.Count -ne 0") &&
          source.includes("$runningAfter.Count -ne 0") &&
          source.includes("[String]::IsNullOrWhiteSpace([string]$shutdown.stdout)") &&
          source.includes("$oldRegistrationAfterPurge,") &&
          source.includes("$unrelatedRegistrationAfterPurge") &&
          source.split('@("--shutdown")').length === 2 &&
          source.split("Invoke-FixtureOnlyWslShutdown $trustedWsl $fixtureWslRegistrations").length === 2 &&
          source.indexOf("Invoke-FixtureOnlyWslShutdown $trustedWsl $fixtureWslRegistrations") >
            source.indexOf('"--terminate", $unrelatedDistributionName') &&
          source.indexOf("Invoke-FixtureOnlyWslShutdown $trustedWsl $fixtureWslRegistrations") <
            source.indexOf("$oldVhdBeforeUninstall = Get-QuiescedVhdSha256Proof") &&
          source.includes('foreach ($identityField in @("volumeSerialNumber", "fileIndex", "numberOfLinks", "attributes"))') &&
          !source.includes('foreach ($identityField in @("sizeBytes", "volumeSerialNumber", "fileIndex", "numberOfLinks", "attributes"))') &&
          source.includes("Assert-SameFileProof $oldVhdBeforeUninstall $oldVhdFileAfterUninstall") &&
          source.includes("Assert-SameFileProof $unrelatedVhdBeforeUninstall $unrelatedVhdAfterUninstall") &&
          source.includes("Assert-SameFileProof $processLeaseBeforeUninstall $processLeaseAfterUninstall"),
        `${label} must retain complete empty-file identity, quiesce only its two stopped fixtures, then wait a bounded time only for WSL VHD sharing and lock violations before exact no-follow hashing`,
      );
    } else {
      assert(
        source.includes("processLeaseAbsentBefore = $true") &&
          source.includes("$processLeaseAfterUninstall = Get-NoFollowEmptyFileProof"),
        `${label} must prove that the current product added only its exact empty root process lease`,
      );
    }
  } else {
    assert(
      !source.includes("AllowRetainedState"),
      `${label} must keep fresh-install uninstallation strict`,
    );
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const packageJson = await readJson(path.join(PROJECT_ROOT, "package.json"));
  const packageLock = await readJson(path.join(PROJECT_ROOT, "package-lock.json"));
  const tauri = await readJson(path.join(PROJECT_ROOT, "src-tauri/tauri.conf.json"));
  const desktopCapability = await readJson(
    path.join(PROJECT_ROOT, "src-tauri/capabilities/default.json"),
  );
  const cargoToml = await readFile(path.join(PROJECT_ROOT, "src-tauri/Cargo.toml"), "utf8");
  const cargoLock = await readFile(path.join(PROJECT_ROOT, "Cargo.lock"), "utf8");
  const releaseMetadataSchema = await readJson(
    path.join(PROJECT_ROOT, "docs/release/release-metadata.schema.json"),
  );
  const version = packageJson.version;
  const tag = typeof args.get("tag") === "string" ? args.get("tag") : `v${version}`;
  assert(
    releaseMetadataSchema.properties?.schemaVersion?.const === 3 &&
      JSON.stringify(releaseMetadataSchema.properties?.publicationMode?.enum) ===
        JSON.stringify(["commit-bound-qc", "public-github-release"]) &&
      releaseMetadataSchema.properties?.distribution?.properties?.platforms?.minItems === 3,
    "release metadata schema does not bind artifact-scoped support and publication modes",
  );
  assert(isSemver(version), `package version is not native-compatible numeric SemVer: ${version}`);
  assert(tag === `v${version}`, `tag ${tag} does not exactly match package version ${version}`);
  const releaseChannel = packageJson.release?.channel;
  const releaseTarget = packageJson.release?.target;
  assert(
    releaseChannel === "prerelease" || releaseChannel === "stable",
    "package release channel must be prerelease or stable",
  );
  assert(isSemver(releaseTarget), "package release target must be native-compatible numeric SemVer");
  if (releaseChannel === "prerelease") {
    assert(
      compareNumericSemver(version, releaseTarget) < 0,
      "pre-release product version must sort below its planned stable target on native package managers",
    );
  } else {
    assert(releaseTarget === version, "stable release target must equal the product version");
  }
  assert(packageLock.version === version, "package-lock document version is out of sync");
  assert(packageLock.packages?.[""]?.version === version, "package-lock root version is out of sync");
  assert(tauri.version === version, "Tauri version is out of sync");
  assert(cargoPackageVersion(cargoToml) === version, "Cargo package version is out of sync");
  assert(cargoLockPackageVersion(cargoLock) === version, "Cargo.lock package version is out of sync");
  assert(packageJson.license === "Apache-2.0", "package.json license must be Apache-2.0");
  assert(
    packageJson.repository?.url === "git+https://github.com/teddashh/ai-security-scanner.git",
    "package repository metadata is incorrect",
  );
  assert(tauri.productName === "ai-security-scanner", "Tauri product name is incorrect");
  assert(tauri.identifier === "dev.teddashh.ai-security-scanner", "Tauri identifier is incorrect");
  assert(tauri.bundle?.active === true, "Tauri bundling must be active");
  assert(
    tauri.bundle?.license === "Apache-2.0" && tauri.bundle?.licenseFile === "../LICENSE",
    "Tauri bundles must carry the project license metadata and file",
  );
  assert(
    Array.isArray(tauri.bundle?.externalBin) &&
      JSON.stringify(tauri.bundle.externalBin) === JSON.stringify([
        "binaries/ai-security-scanner-egress-gateway",
        "binaries/ai-security-scanner-bootstrap-broker",
        "binaries/ai-security-scanner-cli",
      ]),
    "Tauri bundle must install all first-party companion executables in fixed order",
  );
  assert(
    JSON.stringify(tauri.plugins?.updater?.endpoints) ===
      JSON.stringify(["https://github.com/teddashh/ai-security-scanner/releases/latest/download/latest.json"]),
    "Tauri updater endpoint must be the fixed HTTPS GitHub Release manifest",
  );
  assert(
    desktopCapability.permissions?.includes("updater:allow-check") &&
      desktopCapability.permissions?.includes("updater:allow-download-and-install") &&
      desktopCapability.permissions?.includes("process:allow-restart") &&
      !desktopCapability.permissions?.includes("updater:default") &&
      !desktopCapability.permissions?.includes("updater:allow-install") &&
      !desktopCapability.permissions?.includes("updater:allow-download"),
    "desktop updater capability must expose only check, combined signed install, and relaunch",
  );
  const openerPermission = desktopCapability.permissions?.find(
    (permission) => permission && typeof permission === "object" && permission.identifier === "opener:allow-open-url",
  );
  assert(
    JSON.stringify(openerPermission?.allow) === JSON.stringify([
      { url: "https://*.amazonaws.com/**" },
      { url: "https://*.awsapps.com/**" },
      { url: "https://microsoft.com/**" },
      { url: "https://*.microsoft.com/**" },
      { url: "https://microsoftonline.com/**" },
      { url: "https://*.microsoftonline.com/**" },
      { url: "https://google.com/**" },
      { url: "https://*.google.com/**" },
      { url: "https://googleusercontent.com/**" },
      { url: "https://*.googleusercontent.com/**" },
    ]) &&
      !desktopCapability.permissions?.includes("opener:default") &&
      !desktopCapability.permissions?.includes("opener:allow-default-urls") &&
      !desktopCapability.permissions?.includes("opener:allow-open-path"),
    "desktop opener capability must expose only the fixed provider-login HTTPS hosts",
  );
  assert(
    packageJson.dependencies?.["@tauri-apps/plugin-updater"] === "2.10.1" &&
      packageJson.dependencies?.["@tauri-apps/plugin-process"] === "2.3.1" &&
      packageJson.dependencies?.["@tauri-apps/plugin-opener"] === "2.5.4",
    "frontend desktop plugin dependencies must be exactly pinned",
  );
  assert(
    cargoToml.includes('tauri-plugin-updater = { version = "=2.10.1"') &&
      cargoToml.includes('tauri-plugin-process = { version = "=2.3.1"') &&
      cargoToml.includes('tauri-plugin-opener = { version = "=2.5.4"'),
    "Rust desktop plugin dependencies must be exactly pinned",
  );

  const releaseWorkflow = await readReleaseWorkflow();
  const promotionWorkflow = await readPromotionWorkflow();
  validateReleaseWorkflow(releaseWorkflow, promotionWorkflow);
  const windowsQualification = await readFile(
    path.join(PROJECT_ROOT, "scripts/release/qualify-windows.ps1"),
    "utf8",
  );
  validateWindowsQualificationLifecycle(windowsQualification);

  if (typeof args.get("metadata") === "string") {
    const publicationMode = requireString(args, "publication-mode");
    assert(
      ["commit-bound-qc", "public-github-release"].includes(publicationMode),
      "publication mode must be commit-bound-qc or public-github-release",
    );
    const metadata = await readJson(path.resolve(PROJECT_ROOT, args.get("metadata")));
    validateReleaseMetadata(metadata, version, tag, releaseChannel, releaseTarget, publicationMode);
  }

  process.stdout.write(
    `Common release identity and publication policy are consistent for ${tag}; candidate and promotion workflows are valid YAML with SHA-pinned actions.\n`,
  );
}

if (path.resolve(process.argv[1] ?? "") === path.resolve(fileURLToPath(import.meta.url))) {
  runMain(main);
}
