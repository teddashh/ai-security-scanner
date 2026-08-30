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
  assert(metadata.schemaVersion === 2, "release metadata schemaVersion must be 2");
  assert(metadata.product === "ai-security-scanner", "release metadata product is incorrect");
  assert(metadata.version === version, "release metadata version is incorrect");
  assert(metadata.tag === tag, "release metadata tag is incorrect");
  assert(metadata.releaseChannel === releaseChannel, "release metadata channel is incorrect");
  assert(metadata.stableTarget === releaseTarget, "release metadata stable target is incorrect");
  assert(
    ["commit-bound-qc", "public-github-release"].includes(publicationMode),
    "expected publication mode is invalid",
  );
  assert(metadata.publicationMode === publicationMode, "release metadata publication mode is incorrect");
  assert(
    /^[0-9a-f]{40}$/u.test(metadata.sourceCommit),
    "release metadata sourceCommit must be a full lowercase Git object ID",
  );
  assert(
    Array.isArray(metadata.distribution?.bundledEngines) &&
      metadata.distribution.bundledEngines.length === 0,
    "desktop release metadata must not claim that engines are bundled",
  );
  assert(
    Array.isArray(metadata.distribution?.bundledAuxiliaryExecutables) &&
      JSON.stringify(metadata.distribution.bundledAuxiliaryExecutables) === JSON.stringify([
        "ai-security-scanner-egress-gateway",
        "ai-security-scanner-bootstrap-broker",
        "ai-security-scanner-cli",
      ]),
    "release metadata must identify all first-party companion executables",
  );
  assert(
    metadata.security?.operatingSystemCodeSigning?.state === "not-configured",
    "release metadata must honestly report absent OS code signing",
  );
  assert(
    metadata.security?.appleNotarization?.state === "not-configured",
    "release metadata must honestly report absent Apple notarization",
  );
  assert(metadata.security?.updater?.state === "enabled-signed", "updater must be reported enabled and signed");
  assert(
    metadata.security?.updater?.artifactsGenerated === true &&
      metadata.security?.updater?.signingConfigured === true,
    "updater metadata must require generated and signed updater artifacts",
  );
  const expectedAttestation = publicationMode === "public-github-release"
    ? { state: "required-before-publication", provider: "GitHub artifact attestations" }
    : { state: "not-created-for-commit-bound-qc", provider: "none" };
  assert(
    JSON.stringify(metadata.security?.provenanceAttestation) === JSON.stringify(expectedAttestation),
    "release metadata provenance-attestation state does not match its publication mode",
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
  assert(
    trigger.workflow_dispatch === null ||
      (typeof trigger.workflow_dispatch === "object" &&
        Object.keys(trigger.workflow_dispatch).length === 0),
    "release preflight must not accept caller-controlled inputs",
  );
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
  const finalizerSteps = finalizer.steps ?? [];
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
  for (const [label, step] of [
    ["finalizer", finalizerSteps[finalizeIndex]],
    ["finalizer verification", finalizerSteps[finalizerVerifyIndex]],
  ]) {
    assert(step.run.includes(`--dir ${finalizedArtifactPath}`), `${label} must bind the finalized artifact path`);
    assertIdentityBindings(step, label);
  }
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
    releaseMetadataSchema.properties?.schemaVersion?.const === 2 &&
      JSON.stringify(releaseMetadataSchema.properties?.publicationMode?.enum) ===
        JSON.stringify(["commit-bound-qc", "public-github-release"]) &&
      Array.isArray(releaseMetadataSchema.allOf) &&
      releaseMetadataSchema.allOf.length === 1,
    "release metadata schema does not bind QC/public publication and attestation modes",
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
    tauri.bundle?.createUpdaterArtifacts === true,
    "Tauri updater artifacts must be generated for signed releases",
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
    tauri.plugins?.updater?.pubkey ===
      "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEIyQzI1RTVEMTJCMzJCRkUKUldUK0s3TVNYVjdDc3M2QU9nbGdqRTNQVStNR3hRQStuZEFQNStac2Y2U0FsQmZ5cjB5UTNHUmIK",
    "Tauri updater public key differs from the release signing identity",
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
