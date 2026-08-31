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

async function readReleaseWorkflow() {
  const file = path.join(PROJECT_ROOT, ".github/workflows/release.yml");
  const source = await readFile(file, "utf8");
  const document = parseDocument(source, { prettyErrors: true, strict: true });
  if (document.errors.length > 0) {
    throw new Error(`release.yml is invalid YAML: ${document.errors[0].message}`);
  }
  const workflow = document.toJS();
  assert(workflow && typeof workflow === "object", "release.yml must contain a mapping");
  assert(workflow.jobs && typeof workflow.jobs === "object", "release.yml has no jobs");
  validateActionReferences(workflow, "release.yml");
  return workflow;
}

export function validateReleaseWorkflow(workflow) {
  assert(workflow, ".github/workflows/release.yml is missing");
  const trigger = workflow.on;
  assert(trigger && typeof trigger === "object", "release workflow has no structured trigger");
  assert(
    JSON.stringify(Object.keys(trigger).sort()) === JSON.stringify(["push", "workflow_dispatch"]),
    "release workflow must use only tag push and manual preflight triggers",
  );
  assert(Object.hasOwn(trigger, "workflow_dispatch"), "release preflight must remain manually runnable");
  const dispatch = trigger.workflow_dispatch;
  const dispatchIsEmpty = dispatch === null ||
    (typeof dispatch === "object" && Object.keys(dispatch).length === 0);
  let supportsOptionalWindowsDataPreservation = false;
  if (!dispatchIsEmpty) {
    const input = dispatch?.inputs?.windows_data_preservation;
    assert(
      typeof dispatch === "object" &&
        JSON.stringify(Object.keys(dispatch)) === JSON.stringify(["inputs"]) &&
        dispatch.inputs && typeof dispatch.inputs === "object" &&
        JSON.stringify(Object.keys(dispatch.inputs)) === JSON.stringify(["windows_data_preservation"]) &&
        input && typeof input === "object" &&
        JSON.stringify(Object.keys(input).sort()) ===
          JSON.stringify(["default", "description", "required", "type"]) &&
        typeof input.description === "string" && input.description.length > 0 &&
        input.required === false && input.type === "boolean" && input.default === false,
      "release preflight may accept only the false-by-default Windows data-preservation fixture switch",
    );
    supportsOptionalWindowsDataPreservation = true;
  }
  assert(
    Array.isArray(trigger.push.tags) &&
      trigger.push.tags.length === 1 &&
      trigger.push.tags[0] === "v[0-9]*.[0-9]*.[0-9]*",
    "release workflow tag prefilter is incorrect",
  );
  assert(!trigger.push.branches, "release workflow must not publish from branch pushes");
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

  const publicationEntries = Object.entries(workflow.jobs ?? {}).filter(([, job]) =>
    job.steps?.some((step) =>
      typeof step.uses === "string" && step.uses.includes("softprops/action-gh-release@"),
    ),
  );
  assert(publicationEntries.length === 1, "release workflow must have one GitHub Release publication job");
  const [publishJobName, publish] = publicationEntries[0];
  const publishCondition = String(publish.if ?? "").replaceAll(/\s+/gu, " ").trim();
  const expectedPublishCondition =
    `github.event_name == 'push' && github.ref == format('refs/tags/{0}', needs.${identityJobName}.outputs.tag)`;
  assert(
    publishCondition === expectedPublishCondition,
    "publish job must require an exact version-derived tag-push identity",
  );
  const publishNeeds = Array.isArray(publish.needs) ? publish.needs : [publish.needs].filter(Boolean);
  assert(
    publishNeeds.includes(identityJobName),
    "publish job must consume the version-derived identity",
  );
  assert(publish.permissions?.contents === "write", "publish job needs contents: write");
  assert(publish.permissions?.["id-token"] === "write", "publish job needs id-token: write");
  assert(publish.permissions?.attestations === "write", "publish job needs attestations: write");
  for (const [permission, value] of Object.entries(publish.permissions ?? {})) {
    assert(
      value !== "write" || ["contents", "id-token", "attestations"].includes(permission),
      `publish job has unrelated write authority: ${permission}`,
    );
  }
  assert(publish["continue-on-error"] === undefined, "publish job cannot continue after a publication error");
  const assertRequiredStep = (step, label) => {
    assert(step && step.if === undefined, `${label} cannot be conditionally skipped`);
    assert(step["continue-on-error"] === undefined, `${label} cannot continue after failure`);
  };
  const publishSteps = publish.steps ?? [];
  const downloadIndex = publishSteps.findIndex(
    (step) => typeof step.uses === "string" && step.uses.includes("actions/download-artifact@"),
  );
  assert(downloadIndex >= 0, "publish job must download one finalized artifact");
  const download = publishSteps[downloadIndex];
  const finalizedArtifactName = download.with?.name;
  const finalizedArtifactPath = download.with?.path;
  assert(
    typeof finalizedArtifactName === "string" && finalizedArtifactName.length > 0 &&
      typeof finalizedArtifactPath === "string" && finalizedArtifactPath.length > 0,
    "publish job finalized-artifact download must bind an exact name and path",
  );
  assert(
    /^[A-Za-z0-9._-]+$/u.test(finalizedArtifactName) &&
      /^(?!\.\.?$)[A-Za-z0-9._-]+(?:\/(?!\.\.?$)[A-Za-z0-9._-]+)*$/u.test(finalizedArtifactPath),
    "publish job finalized-artifact name and path must be safe fixed relative values",
  );
  assertRequiredStep(download, "finalized-artifact download");
  const finalizerEntries = Object.entries(workflow.jobs ?? {}).filter(([jobName, job]) =>
    publishNeeds.includes(jobName) &&
      job.steps?.some((step) =>
        typeof step.uses === "string" &&
          step.uses.includes("actions/upload-artifact@") &&
          step.with?.name === finalizedArtifactName &&
          step.with?.path === finalizedArtifactPath,
      ),
  );
  assert(
    finalizerEntries.length === 1,
    "publish job must depend on exactly one job that produced its finalized artifact",
  );
  const [finalizerJobName, finalizer] = finalizerEntries[0];
  assert(finalizer["continue-on-error"] === undefined, "finalizer job cannot continue after failure");
  const finalizerNeeds = Array.isArray(finalizer.needs)
    ? finalizer.needs
    : [finalizer.needs].filter(Boolean);
  assert(
    finalizerNeeds.includes(identityJobName),
    "finalizer job must consume the version-derived identity",
  );
  assert(
    finalizerNeeds.includes(buildJobName),
    "finalizer job must consume independently collected installer siblings",
  );
  if (windowsDataPreservationJobName) {
    assert(
      finalizerNeeds.includes(windowsDataPreservationJobName),
      "finalizer must wait for explicitly requested same-run Windows supporting fixtures",
    );
  }
  const finalizerSteps = finalizer.steps ?? [];
  const unsupportedPromotionDownloads = Object.values(workflow.jobs ?? {})
    .flatMap((job) => job.steps ?? [])
    .filter((step) =>
      typeof step.uses === "string" &&
        step.uses.includes("actions/download-artifact@") &&
        ["artifact-qc-observations-*", "artifact-promotion-evidence-*"].includes(
          step.with?.pattern,
        ),
    );
  assert(
    unsupportedPromotionDownloads.length === 0,
    "release workflow must not ingest an unimplemented artifact observation or promotion namespace",
  );
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
        preservationDownloads[0].with?.["run-id"] === undefined,
      "finalizer must optionally ingest only exact-current-run Windows supporting evidence",
    );
  }
  const finalizeIndex = finalizerSteps.findIndex(
    (step) => typeof step.run === "string" && step.run.includes("scripts/release/finalize-release.mjs"),
  );
  const finalizerVerifyIndex = finalizerSteps.findIndex(
    (step) => typeof step.run === "string" && step.run.includes("scripts/release/verify-finalized-release.mjs"),
  );
  const uploadIndex = finalizerSteps.findIndex(
    (step) => typeof step.uses === "string" &&
      step.uses.includes("actions/upload-artifact@") &&
      step.with?.name === finalizedArtifactName &&
      step.with?.path === finalizedArtifactPath,
  );
  assert(
    finalizeIndex >= 0 &&
      finalizerVerifyIndex === finalizeIndex + 1 &&
      uploadIndex === finalizerVerifyIndex + 1,
    "finalizer must consecutively finalize, verify, then upload the exact artifact consumed by publication",
  );
  assertRequiredStep(finalizerSteps[finalizeIndex], "release finalization");
  assertRequiredStep(finalizerSteps[finalizerVerifyIndex], "finalizer verification");
  assertRequiredStep(finalizerSteps[uploadIndex], "finalized-artifact upload");
  assert(
    finalizerSteps[uploadIndex].with?.["if-no-files-found"] === "error",
    "finalized-artifact upload must fail when its exact output is absent",
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
  assert(
    finalizerSteps[finalizeIndex].run.includes(`--out ${finalizedArtifactPath}`) &&
      finalizerSteps[finalizeIndex].run.includes("--input "),
    "finalizer must read assembled candidates and bind the clean finalized artifact output",
  );
  assertIdentityBindings(finalizerSteps[finalizeIndex], "finalizer");
  assert(
    finalizerSteps[finalizerVerifyIndex].run.includes(`--dir ${finalizedArtifactPath}`),
    "finalizer verification must bind the finalized artifact path",
  );
  assertIdentityBindings(finalizerSteps[finalizerVerifyIndex], "finalizer verification");
  const publishVerifyIndex = publishSteps.findIndex(
    (step) => typeof step.run === "string" && step.run.includes("scripts/release/verify-finalized-release.mjs"),
  );
  assert(
    publishVerifyIndex > downloadIndex,
    "publish job must reverify the downloaded finalized artifact before publication",
  );
  const publishVerification = publishSteps[publishVerifyIndex];
  assertRequiredStep(publishVerification, "publisher verification");
  assert(
    publishVerification.run.includes(`--dir ${finalizedArtifactPath}`),
    "publish verification must bind the downloaded finalized artifact path",
  );
  assertIdentityBindings(publishVerification, "publish verification");
  const attestationIndex = publishSteps.findIndex(
    (step) => typeof step.uses === "string" && step.uses.includes("attest-build-provenance@"),
  );
  const attestation = publishSteps[attestationIndex];
  const publishedFiles = `${finalizedArtifactPath}/**/*`;
  assert(
    attestationIndex === publishVerifyIndex + 1 &&
      attestation?.with?.["subject-path"] === publishedFiles,
    "publication attestation must immediately follow verification and cover every finalized file",
  );
  assertRequiredStep(attestation, "publication attestation");
  const publicationIndex = publishSteps.findIndex(
    (step) => typeof step.uses === "string" && step.uses.includes("softprops/action-gh-release@"),
  );
  const publication = publishSteps[publicationIndex];
  assertRequiredStep(publication, "GitHub Release publication");
  assert(
    publication?.with?.prerelease === `\${{ needs.${identityJobName}.outputs.prerelease }}` &&
      publication?.with?.make_latest === `\${{ needs.${identityJobName}.outputs.make_latest }}`,
    "GitHub Release publication must preserve the source-declared pre-release/latest channel",
  );
  assert(
    publicationIndex === attestationIndex + 1 &&
      publication?.with?.tag_name === `\${{ needs.${identityJobName}.outputs.tag }}` &&
      publication?.with?.target_commitish === `\${{ needs.${identityJobName}.outputs.commit }}` &&
      publication?.with?.draft === false &&
      publication?.with?.fail_on_unmatched_files === true &&
      publication?.with?.files === publishedFiles,
    "GitHub Release publication must publish the exact verified and attested artifact path",
  );
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    if (jobName === publishJobName) {
      continue;
    }
    assert(
      !Object.values(job.permissions ?? {}).includes("write"),
      `${jobName} job must not receive write permissions`,
    );
    const source = JSON.stringify(job);
    assert(!source.includes("action-gh-release"), `${jobName} job must not create a GitHub Release`);
    assert(!source.includes("attest-build-provenance"), `${jobName} job must not create attestations`);
  }
  assert(finalizerJobName !== publishJobName, "publisher cannot finalize its own release artifact");
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
  validateReleaseWorkflow(releaseWorkflow);
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
    `Common release identity and publication policy are consistent for ${tag}; release.yml is valid YAML with SHA-pinned actions.\n`,
  );
}

if (path.resolve(process.argv[1] ?? "") === path.resolve(fileURLToPath(import.meta.url))) {
  runMain(main);
}
