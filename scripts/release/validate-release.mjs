import { execFileSync } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { parseDocument } from "yaml";
import {
  PROJECT_ROOT,
  isSemver,
  parseArgs,
  readJson,
  runMain,
} from "./lib.mjs";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
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

function validateReleaseMetadata(metadata, version, tag) {
  assert(metadata.schemaVersion === 1, "release metadata schemaVersion must be 1");
  assert(metadata.product === "ai-security-scanner", "release metadata product is incorrect");
  assert(metadata.version === version, "release metadata version is incorrect");
  assert(metadata.tag === tag, "release metadata tag is incorrect");
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
  assert(
    metadata.security?.provenanceAttestation?.state === "required-before-publication",
    "publication must require a provenance attestation",
  );
}

async function workflowFiles() {
  const directory = path.join(PROJECT_ROOT, ".github/workflows");
  return (await readdir(directory))
    .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
    .sort()
    .map((file) => path.join(directory, file));
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

async function validateWorkflowSyntaxAndPins() {
  const parsed = new Map();
  for (const file of await workflowFiles()) {
    const source = await readFile(file, "utf8");
    const document = parseDocument(source, { prettyErrors: true, strict: true });
    if (document.errors.length > 0) {
      throw new Error(`${path.basename(file)} is invalid YAML: ${document.errors[0].message}`);
    }
    const workflow = document.toJS();
    assert(workflow && typeof workflow === "object", `${path.basename(file)} must contain a mapping`);
    assert(workflow.jobs && typeof workflow.jobs === "object", `${path.basename(file)} has no jobs`);
    validateActionReferences(workflow, path.basename(file));
    parsed.set(path.basename(file), workflow);
  }
  return parsed;
}

function validateReleaseWorkflow(workflow) {
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
  const build = workflow.jobs?.build;
  assert(build, "release workflow has no platform build job");
  const macosBuild = build.steps?.find((step) => step.name === "Build universal macOS installer");
  assert(
    typeof macosBuild?.run === "string" && macosBuild.run.includes("--bundles app,dmg"),
    "macOS release build must create both the signed app updater payload and DMG installer",
  );
  const validate = workflow.jobs?.validate;
  assert(validate, "release workflow has no identity validation job");
  assert(
    validate.outputs?.tag === "${{ steps.identity.outputs.tag }}",
    "release workflow must export its version-derived candidate tag",
  );
  const identity = validate.steps?.find((step) => step.id === "identity");
  assert(identity && typeof identity.run === "string", "release workflow has no identity resolver");
  for (const required of [
    'candidate_tag="v${version}"',
    '"refs/tags/${candidate_tag}"',
    '"refs/heads/main"',
    'event_commit="$(git rev-parse "${EVENT_SHA}^{commit}")"',
    '"${commit}" != "${event_commit}"',
  ]) {
    assert(identity.run.includes(required), `release identity resolver is missing: ${required}`);
  }

  const assemble = workflow.jobs?.assemble;
  assert(assemble, "release workflow has no read-only assemble job");
  assert(
    JSON.stringify(assemble.needs) === JSON.stringify(["validate", "supply-chain", "build"]),
    "assemble job must depend on validation, supply-chain evidence, and every platform build",
  );
  assert(assemble.permissions?.contents === "read", "assemble job must remain read-only");
  assert(
    !Object.values(assemble.permissions ?? {}).includes("write"),
    "assemble job must not receive write permissions",
  );

  const publish = workflow.jobs?.publish;
  assert(publish, "release workflow has no publish job");
  const publishCondition = String(publish.if ?? "").replaceAll(/\s+/gu, " ").trim();
  assert(
    publishCondition ===
      "github.event_name == 'push' && github.ref == format('refs/tags/{0}', needs.validate.outputs.tag)",
    "publish job must require an exact version-derived tag-push identity",
  );
  assert(
    JSON.stringify(publish.needs) === JSON.stringify(["validate", "assemble"]),
    "publish job must consume only the validated finalized release candidate",
  );
  assert(publish.permissions?.contents === "write", "publish job needs contents: write");
  assert(publish.permissions?.["id-token"] === "write", "publish job needs id-token: write");
  assert(publish.permissions?.attestations === "write", "publish job needs attestations: write");
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    if (jobName === "publish") {
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
  const serialized = JSON.stringify(workflow);
  for (const required of [
    "ubuntu-24.04",
    "macos-14",
    "windows-2022",
    "deb,rpm,appimage",
    "universal-apple-darwin",
    "nsis,msi",
    "cyclonedx-json",
    "spdx-json",
    "attest-build-provenance",
    "action-gh-release",
    "TAURI_SIGNING_PRIVATE_KEY",
    "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
    "sign-linux-installers.mjs",
    "ai-security-scanner-bootstrap-broker",
    "ai-security-scanner-cli",
    "xvfb-run",
    "hdiutil attach",
    "msiexec.exe",
    "workflow_dispatch",
    "release-finalized",
    "verify-finalized-release.mjs",
  ]) {
    assert(serialized.includes(required), `release workflow is missing required element: ${required}`);
  }
}

function validateEngineImageWorkflow(workflow, { image, tag, requiredPaths, sourceDateEpoch = null }) {
  assert(workflow, `managed image workflow is missing for ${image}`);
  const branches = workflow.on?.push?.branches;
  assert(
    Array.isArray(branches) && branches.length === 1 && branches[0] === "main",
    `${image} publication must only run automatically from main`,
  );
  assert(workflow.on?.workflow_dispatch !== undefined, `${image} publication must remain manually runnable`);
  assert(workflow.permissions?.contents === "read", `${image} workflow needs contents: read`);
  assert(workflow.permissions?.packages === "write", `${image} workflow needs packages: write`);
  const source = JSON.stringify(workflow);
  for (const required of [
    image,
    tag,
    "linux/amd64,linux/arm64",
    '"provenance":false',
    '"sbom":false',
    "docker logout ghcr.io",
    "docker buildx imagetools inspect",
    ...requiredPaths,
  ]) {
    assert(source.includes(required), `${image} workflow is missing required publication metadata: ${required}`);
  }
  if (sourceDateEpoch !== null) {
    assert(
      workflow.env?.SOURCE_DATE_EPOCH === sourceDateEpoch,
      `${image} workflow has the wrong SOURCE_DATE_EPOCH`,
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
  const catalog = await readJson(path.join(PROJECT_ROOT, "engines/catalog.json"));
  const version = packageJson.version;
  const tag = typeof args.get("tag") === "string" ? args.get("tag") : `v${version}`;

  assert(isSemver(version), `package version is not strict SemVer: ${version}`);
  assert(tag === `v${version}`, `tag ${tag} does not exactly match package version ${version}`);
  assert(packageLock.packages?.[""]?.version === version, "package-lock root version is out of sync");
  assert(tauri.version === version, "Tauri version is out of sync");
  assert(cargoPackageVersion(cargoToml) === version, "Cargo package version is out of sync");
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
    tauri.plugins?.updater?.windows?.installMode === "passive",
    "Windows updater install mode must remain visible and passive",
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

  const workflows = await validateWorkflowSyntaxAndPins();
  validateReleaseWorkflow(workflows.get("release.yml"));

  assert(Array.isArray(catalog) && catalog.length === 21, "engine catalog must contain 21 records");
  const incompleteEngines = catalog
    .filter((engine) =>
      engine.status !== "integrated" ||
      engine.compatibility?.runnable !== true ||
      engine.compatibility?.blocked_by?.length !== 0 ||
      !["allow", "source_offer"].includes(engine.license?.disposition) ||
      !["pull_pinned_image", "bundled_image"].includes(engine.distribution_mode) ||
      !/^sha256:[0-9a-f]{64}$/u.test(engine.image?.digest ?? ""),
    )
    .map((engine) => engine.id);
  assert(
    incompleteEngines.length === 0,
    `release requires every required engine to be integrated, runnable, licensed, and digest-pinned: ${incompleteEngines.join(", ")}`,
  );

  execFileSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", "validate-engine-catalog.mjs")], {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
  execFileSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", "engine-image-evidence.mjs"), "self-test"], {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });

  validateEngineImageWorkflow(workflows.get("engine-image-syft.yml"), {
    image: "ghcr.io/teddashh/ai-security-scanner-engine-syft",
    tag: "1.51.0-1",
    requiredPaths: ["engines/images/syft/Dockerfile"],
  });
  validateEngineImageWorkflow(workflows.get("engine-image-checkov.yml"), {
    image: "ghcr.io/teddashh/ai-security-scanner-engine-checkov",
    tag: "3.3.13-1",
    requiredPaths: [
      "engines/images/checkov/.dockerignore",
      "engines/images/checkov/Dockerfile",
      "engines/images/checkov/prepare_source.py",
    ],
    sourceDateEpoch: "1787218764",
  });

  if (typeof args.get("metadata") === "string") {
    const metadata = await readJson(path.resolve(PROJECT_ROOT, args.get("metadata")));
    validateReleaseMetadata(metadata, version, tag);
  }

  process.stdout.write(
    `Release metadata is consistent for ${tag}; ${workflows.size} workflow files are valid YAML with SHA-pinned actions.\n`,
  );
}

runMain(main);
