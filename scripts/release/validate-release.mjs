import { execFileSync } from "node:child_process";
import { mkdir, readdir, readFile } from "node:fs/promises";
import path from "node:path";
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

function assertExactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} fields are not the strict released set`,
  );
}

function validateManagedEgressGatewayManifest(manifest, version) {
  assertExactKeys(
    manifest,
    ["schema_version", "product_version", "image"],
    "managed egress gateway manifest",
  );
  assert(manifest.schema_version === "1.0.0", "managed egress gateway schema is unsupported");
  assert(manifest.product_version === version, "managed egress gateway product version is out of sync");
  assertExactKeys(
    manifest.image,
    ["repository", "publication_tag", "digest", "source_revision"],
    "managed egress gateway image",
  );
  assert(
    manifest.image.repository === "ghcr.io/teddashh/ai-security-scanner-egress-gateway",
    "managed egress gateway repository is not release-owned",
  );
  assert(
    manifest.image.publication_tag === `${version}-1`,
    "managed egress gateway publication tag is out of sync",
  );
  assert(
    /^sha256:[0-9a-f]{64}$/u.test(manifest.image.digest),
    "managed egress gateway digest is not immutable",
  );
  assert(
    /^[0-9a-f]{40}$/u.test(manifest.image.source_revision),
    "managed egress gateway source revision is malformed",
  );
  return `${manifest.image.repository}@${manifest.image.digest}`;
}

function compareNumericSemver(left, right) {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
  }
  return 0;
}

function assertOrderedTokens(source, tokens, label) {
  let previous = -1;
  for (const token of tokens) {
    const index = source.indexOf(token);
    assert(index !== -1, label + " is missing ordered marker: " + token);
    assert(index > previous, label + " has an out-of-order marker: " + token);
    previous = index;
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
  const macosBuildTarget = build.strategy?.matrix?.include?.find(
    (target) => target.platform === "macos-universal",
  );
  assert(
    macosBuildTarget?.runner === "macos-14" &&
      macosBuildTarget?.managed_runtime_target === "universal-apple-darwin",
    "universal macOS packaging must remain on the macos-14 build runner",
  );
  const macosBuild = build.steps?.find((step) => step.name === "Build universal macOS installer");
  assert(
    typeof macosBuild?.run === "string" && macosBuild.run.includes("--bundles app,dmg"),
    "macOS release build must create both the signed app updater payload and DMG installer",
  );
  const runtimeEvidence = build.steps?.find(
    (step) => step.name === "Generate exact managed runtime manifest, SBOM, notices, and source evidence",
  );
  assert(
    typeof runtimeEvidence?.run === "string" &&
      runtimeEvidence.run.includes('[[ "${RELEASE_PLATFORM}" == "windows-x86_64" ]]') &&
      runtimeEvidence.run.includes("runtime_evidence_args=(") &&
      runtimeEvidence.run.includes('node scripts/release/generate-runtime-evidence.mjs "${runtime_evidence_args[@]}"') &&
      runtimeEvidence.run.includes("--expected-manifest-sha256 a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a") &&
      !runtimeEvidence.run.includes("=()"),
    "release builds must use Bash 3.2-safe arguments and verify the exact reviewed Windows v0.1.8 managed-runtime identity",
  );
  const debianSmoke = build.steps?.find(
    (step) => step.name === "Install the Debian package and prove the desktop starts",
  );
  assert(
    typeof debianSmoke?.run === "string" &&
      debianSmoke.run.includes('realpath -- "${packages[0]}"') &&
      debianSmoke.run.includes('apt-get install -y "${package_path}"'),
    "Debian release smoke test must install the local package through an absolute path",
  );
  const validate = workflow.jobs?.validate;
  assert(validate, "release workflow has no identity validation job");
  assert(
    validate.outputs?.tag === "${{ steps.identity.outputs.tag }}",
    "release workflow must export its version-derived candidate tag",
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
    "PUBLIC_RELEASE_BLOCKED_AUTHENTICODE",
  ]) {
    assert(identity.run.includes(required), `release identity resolver is missing: ${required}`);
  }

  const qualification = workflow.jobs?.qualification;
  assert(qualification, "release workflow has no fresh-runner platform qualification job");
  assert(
    JSON.stringify(qualification.needs) === JSON.stringify(["validate", "build"]),
    "platform qualification must consume identity and completed build artifacts in a separate job",
  );
  assert(qualification.permissions?.contents === "read", "platform qualification must remain read-only");
  assert(Number.isInteger(qualification["timeout-minutes"]) && qualification["timeout-minutes"] >= 360, "platform qualification timeout cannot truncate the N-1 runtime and registered-WSL migration proof");
  assert(
    JSON.stringify(qualification.strategy?.matrix?.include) === JSON.stringify([
      { platform: "linux-x86_64", runner: "ubuntu-24.04", qualification_id: "linux-x86_64-deb", installer_type: "deb" },
      { platform: "macos-universal", runner: "macos-15-intel", qualification_id: "macos-universal-dmg", installer_type: "dmg" },
      { platform: "windows-x86_64", runner: "windows-2025", qualification_id: "windows-x86_64-msi", installer_type: "msi" },
      { platform: "windows-x86_64", runner: "windows-2025", qualification_id: "windows-x86_64-nsis", installer_type: "nsis" },
    ]),
    "installer qualification matrix must independently cover the exact four released installer contracts",
  );
  assert(qualification["runs-on"] === "${{ matrix.runner }}", "platform qualification must run on its declared fresh matrix runner");
  const qualificationSource = JSON.stringify(qualification);
  for (const required of [
    "release-${{ matrix.platform }}",
    "qualify-linux.sh",
    "qualify-macos.sh",
    "qualify-windows.ps1",
    "platform-qualification.mjs create",
    "platform-qualification.mjs validate",
    "--release-channel",
    "--installer-type",
    "needs.validate.outputs.release_channel",
    "platform-qualification-${{ matrix.qualification_id }}.json",
  ]) {
    assert(qualificationSource.includes(required), `platform qualification job is missing: ${required}`);
  }
  assert(
    !qualificationSource.includes("qualify-windows-nsis-upgrade.ps1") &&
      !qualificationSource.includes("qualify-windows-nsis-ghost-recovery.ps1"),
    "generic installer qualification must not contaminate either migration qualification runner",
  );

  const isolatedWindowsQualifications = [
    {
      jobName: "windows-nsis-upgrade-qualification",
      required: [
        "qualify-windows-nsis-upgrade.ps1",
        "windows-nsis-upgrade-evidence.mjs create",
        "windows-nsis-upgrade-evidence.mjs validate",
        "windows-nsis-upgrade-qualification.json",
        "master-framework-report.json",
        "master-framework-report.case.tar.gz",
        "n-minus-one-before-upgrade.case.tar.gz",
        "--report",
        "--bundle",
        "--prior-bundle",
      ],
    },
    {
      jobName: "windows-nsis-ghost-recovery-qualification",
      required: [
        "qualify-windows-nsis-ghost-recovery.ps1",
        "windows-nsis-ghost-recovery-evidence.mjs create",
        "windows-nsis-ghost-recovery-evidence.mjs validate",
        "windows-nsis-ghost-recovery-qualification.json",
      ],
    },
  ];
  for (const { jobName, required } of isolatedWindowsQualifications) {
    const job = workflow.jobs?.[jobName];
    assert(job, `release workflow has no isolated ${jobName} job`);
    assert(
      JSON.stringify(job.needs) === JSON.stringify(["validate", "build"]),
      `${jobName} must consume only the validated independently built Windows artifact`,
    );
    assert(job["runs-on"] === "windows-2025", `${jobName} must use a fresh hosted Windows runner`);
    assert(job.permissions?.contents === "read", `${jobName} must remain read-only`);
    assert(
      Number.isInteger(job["timeout-minutes"]) && job["timeout-minutes"] >= 360,
      `${jobName} timeout cannot truncate its real Windows migration proof`,
    );
    const source = JSON.stringify(job);
    for (const token of required) {
      assert(source.includes(token), `${jobName} is missing: ${token}`);
    }
  }

  const supplyChainSource = JSON.stringify(workflow.jobs?.["supply-chain"]);
  assert(
    supplyChainSource.includes("generate-notices.mjs") &&
      supplyChainSource.includes("--publication-mode") &&
      supplyChainSource.includes("needs.validate.outputs.publication_mode"),
    "release metadata generation must bind the explicit publication mode",
  );

  const assemble = workflow.jobs?.assemble;
  assert(assemble, "release workflow has no read-only assemble job");
  assert(
    JSON.stringify(assemble.needs) === JSON.stringify([
      "validate",
      "supply-chain",
      "build",
      "qualification",
      "windows-nsis-upgrade-qualification",
      "windows-nsis-ghost-recovery-qualification",
    ]),
    "assemble job must depend on validation, supply-chain evidence, every platform build, and every isolated qualification",
  );
  assert(assemble.permissions?.contents === "read", "assemble job must remain read-only");
  assert(
    !Object.values(assemble.permissions ?? {}).includes("write"),
    "assemble job must not receive write permissions",
  );
  const assembleSource = JSON.stringify(assemble);
  assert(
    assembleSource.includes("--publication-mode") &&
      assembleSource.includes("needs.validate.outputs.publication_mode"),
    "assemble and finalized verification must bind the explicit publication mode",
  );
  for (const platform of ["linux-x86_64-deb", "macos-universal-dmg", "windows-x86_64-msi", "windows-x86_64-nsis"]) {
    assert(
      assembleSource.includes(`platform-qualification-${platform}`),
      `assemble job does not download ${platform} qualification evidence`,
    );
  }
  for (const migrationEvidence of [
    "windows-nsis-upgrade-qualification",
    "windows-nsis-ghost-recovery-qualification",
  ]) {
    assert(
      assembleSource.includes(migrationEvidence),
      `assemble job does not download and revalidate ${migrationEvidence}`,
    );
  }

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
  const attestation = publish.steps?.find((step) => step.name === "Attest every published file");
  assert(
    attestation?.with?.["subject-path"] === "release-assets/**/*",
    "publication attestation must cover platform qualification JSON with every finalized file",
  );
  const publication = publish.steps?.find(
    (step) => typeof step.uses === "string" && step.uses.includes("softprops/action-gh-release@"),
  );
  assert(
    publication?.with?.prerelease === "${{ needs.validate.outputs.prerelease }}" &&
      publication?.with?.make_latest === "${{ needs.validate.outputs.make_latest }}",
    "GitHub Release publication must preserve the source-declared pre-release/latest channel",
  );
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
    "macos-15-intel",
    "windows-2022",
    "windows-2025",
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
    "platform-qualification-linux-x86_64-deb",
    "platform-qualification-macos-universal-dmg",
    "platform-qualification-windows-x86_64-msi",
    "platform-qualification-windows-x86_64-nsis",
    "windows-nsis-upgrade-qualification",
    "windows-nsis-ghost-recovery-qualification",
    "commit-bound-qc",
    "public-github-release",
    "--publication-mode",
  ]) {
    assert(serialized.includes(required), `release workflow is missing required element: ${required}`);
  }
}

function validatePlatformQualificationSources(sources) {
  const linux = sources.get("qualify-linux.sh");
  const macos = sources.get("qualify-macos.sh");
  const windows = sources.get("qualify-windows.ps1");
  const evidence = sources.get("platform-qualification.mjs");
  const nsisUpgrade = sources.get("qualify-windows-nsis-upgrade.ps1");
  const nsisUpgradeEvidence = sources.get("windows-nsis-upgrade-evidence.mjs");
  const nsisGhost = sources.get("qualify-windows-nsis-ghost-recovery.ps1");
  const nsisGhostEvidence = sources.get("windows-nsis-ghost-recovery-evidence.mjs");
  const finalizer = sources.get("finalize-release.mjs");
  const selfTest = sources.get("self-test.mjs");
  for (const [name, source] of sources) {
    assert(typeof source === "string" && source.length > 0, `${name} is empty`);
    assert(!/(?:docker|podman)\s+(?:run|pull)\b/iu.test(source), `${name} bypasses the fixed qualification CLI with an arbitrary container command`);
  }
  for (const required of [
    "run_managed initial-status status",
    "run_managed install install",
    "run_managed installed-status status",
    "run_managed start start",
    "run_managed running-status status",
    "run_managed egress-qualification qualify-egress",
    "run_managed container-qualification qualify",
    "run_managed stop stop",
    "run_managed stopped-status status",
    "run_managed uninstall-purge uninstall --force --purge-image-cache",
    "run_managed final-status status",
    "xvfb-run",
    "apt-get purge",
    'const binary = path.join(runtimeRoot, "bin", "qemu-img")',
    "execFileSync(executable, args",
    "QEMU component does not bind the installed qemu-img file.",
    'run(["create", "-f", "qcow2", probe, "1G"])',
    'run(["resize", probe, "40G"])',
    'run(["info", "--output=json", probe])',
    'const helper = path.join(runtimeRoot, "bin", "virtiofsd")',
    "virtiofsd component does not bind the installed helper file.",
    "Installed virtiofsd unexpectedly requires a host ELF interpreter.",
    'runBinary(helper, ["--version"])',
    "assert_managed_ssh_identity",
    "data/containers/podman/machine/machine",
    ".machine.private-key-new",
    ".machine.public-key-new",
    "Managed SSH identity staging entries remain after start.",
    "Managed runtime uninstall left its exact release provider home behind.",
    "ai-security-scanner-linux-xdg-runtime-v1\\0",
    "Linux qualification did not begin with a fresh exact short XDG runtime directory.",
    "Initial managed status created the Linux short XDG runtime directory before installation.",
    "Managed payload installation created the Linux short XDG runtime directory before a Podman command.",
    '[[ -d "${short_runtime}" && ! -L "${short_runtime}" ]]',
    '[[ "$(stat -c \'%u\' "${short_runtime}")" == "$(id -u)" ]]',
    '[[ "$(stat -c \'%a\' "${short_runtime}")" == "700" ]]',
    '[[ "$(stat -c \'%u\' "${podman_runtime}")" == "$(id -u)" ]]',
    'podman_runtime_mode_value=$((8#${podman_runtime_mode}))',
    "(podman_runtime_mode_value & 0700) != 0700",
    "(podman_runtime_mode_value & ~0755) != 0",
    "Managed runtime Linux Podman runtime directory has unsafe permissions.",
    "Managed runtime Linux gvproxy socket exceeds Podman 5.8.2 path budget.",
    "vhost-user-fs-pci",
    'const emulator = path.join(runtimeRoot, "bin", "qemu-system-x86_64.real")',
    "QEMU component does not bind the installed system emulator.",
    'runBinary(emulator, ["-device", "help"])',
    'deviceNames.has("vhost-user-fs-pci")',
    "Installed QEMU system emulator omits the vhost-user-fs-pci device required by Podman.",
    "virtiofschar0.pid",
    'flock -n "${virtiofs_pid}" true',
    "Managed runtime uninstall left its exact Linux short XDG runtime directory behind.",
    "managed-runtime/provider-home",
  ]) assert(linux.includes(required), `Linux qualification is missing: ${required}`);
  for (const required of [
    "hdiutil attach",
    "Installed macOS managed-runtime manifest is malformed or lacks its released AppleHV target.",
    'manifest.schema_version !== "3"',
    'manifest.management_contract_revision !== "2026-08-29.1"',
    '"${cli}" --help',
    "Installed macOS desktop exited before the 12-second observation window.",
    "Do not invoke any managed-runtime lifecycle command",
    "github_hosted_macos_nested_virtualization_unsupported",
    'outcome: "not_observed"',
    'notObserved("initial_status")',
    'notObserved("install")',
    'notObserved("start")',
    'notObserved("uninstall_purge")',
    'egressGateway: { outcome: "not_observed", reasonCode }',
    'containerExecution: { outcome: "not_observed", reasonCode }',
    'diskImageDetached: true',
    'installedApplicationRemoved: true',
    'privateDataRemoved: true',
    'managedRuntimeState: "not_created"',
    'machineImageCacheState: "not_created"',
    'rmdir -- "${data_directory}"',
  ]) assert(macos.includes(required), `macOS qualification is missing: ${required}`);
  for (const required of [
    'Invoke-Managed "initial-status"',
    'Invoke-Managed "install"',
    'Invoke-Managed "start"',
    'Invoke-Managed "egress-qualification"',
    'Invoke-Managed "container-qualification"',
    'Invoke-Managed "stop"',
    'Invoke-Managed "uninstall-purge"',
    '"--purge-image-cache"',
    '"msiexec.exe"',
    '[ValidateSet("msi", "nsis")]',
    '"/S", "/D=$installDirectory"',
    'Filter "uninstall.exe"',
    "GetSystemWindowsDirectoryW",
    'Join-Path $systemRoot "System32"',
    'Join-Path $system32 "wsl.exe"',
    "QualificationBoundedMemoryStream",
    '$startInfo.ArgumentList.Add("--list")',
    '$startInfo.ArgumentList.Add("--quiet")',
    "$startInfo.Environment.Clear()",
    "[Text.UTF8Encoding]::new($false, $true)",
    "[Text.UnicodeEncoding]::new($false, $false, $true)",
    "unsupported UTF-16BE",
    "contained an invalid name",
    '"podman-$managedMachineName"',
    "Assert-ManagedSshIdentity $providerReleaseHome",
    "Assert-ManagedPrivateDirectory",
    '$podmanNamespaceDirectories = @(',
    'run\\podman',
    'config\\containers\\podman\\machine\\wsl',
    'data\\containers\\podman\\machine\\wsl\\cache',
    "inheritable current-user full control",
    "exact protected current-user-only DACL",
    ".machine.private-key-new",
    ".machine.public-key-new",
    "Managed SSH identity staging entries remain after start.",
    "Managed runtime uninstall left its exact release provider home behind.",
    "Managed runtime uninstall left its exact WSL distribution registered:",
    "managed-runtime\\provider-home",
    "GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)",
    '(Join-Path $localApplicationData "ai-security-scanner-platform-qualification-windows-$InstallerType-data")',
    "Where-Object { [String]::Equals($_.Name, $name, [StringComparison]::OrdinalIgnoreCase) }",
    "OS-resolved LocalApplicationData is not a real directory.",
    "Qualification data directory escaped OS-resolved LocalApplicationData.",
    "Qualification requires a fresh LocalApplicationData namespace.",
    "if (Test-ExactEntryExists $dataDirectory)",
    "New-Item -ItemType Directory -Path $dataDirectory -Force",
  ]) assert(windows.includes(required), `Windows qualification is missing: ${required}`);
  for (const required of [
    "ai-security-scanner_0.1.7_x64-setup.exe",
    "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a",
    "podman-machine-5.8.2-$providerNamespace",
    'Invoke-ExactProcess $candidateInstallerPath @("/S", "/D=$installDirectory")',
    "Candidate same-version silent NSIS reinstall",
    'unattendedMode = "silent"',
    "transitionReceiptSurvivedSameVersionReinstall",
    'transitionReceipt = "uninstalled-$priorVersion"',
    '"export", "identity", "show"',
    'continuity_event -cne "legacy_key_adopted"',
    "integrity-signing-key",
    "integrity-signing-key.identity-anchor.json",
    "integrity-signing-key.rotation-intent.json",
    "Assert-OwnerOnlyFullControlFile",
    "anchorIdentitySha256",
    "identityDocumentSha256",
    "rotationIntentAbsent = $true",
    "master-framework-report.case.tar.gz",
    "n-minus-one-before-upgrade.case.tar.gz",
    "Retained signed candidate case bundle after cleanup",
    "Retained signed N-1 case bundle after cleanup",
    "FILE_FLAG_OPEN_REPARSE_POINT",
    "Open-NoFollowSingleLinkFile",
    "Get-NoFollowFileSha256Proof",
    "ConvertFrom-Json -DateKind String",
    "$writerOptions.Encoder = [Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping",
    "Assert-SerdeCompatibleJsonCompaction",
    "ExpectedExecutableProof",
    "HashData($executionGuard)",
    "executable is not the exact previously verified installer",
    "-ExpectedExecutableProof $priorInstallerProof",
    "-ExpectedExecutableProof $candidateInstallerItem",
    "[NsisUpgradeQualificationNativeMethods]::CreateFileW",
    "registeredWslStateExercised = $false",
    'Invoke-ExactProcess $candidateUninstaller @("/S", "_?=$installDirectory") 180000 "Candidate NSIS uninstall"',
    'Invoke-ExactProcess $activeUninstaller @("/S", "_?=$installDirectory") 180000 "Failure-path NSIS uninstall"',
  ]) assert(nsisUpgrade.includes(required), `normal Windows N-1 upgrade qualification is missing: ${required}`);
  assert(
    (nsisUpgrade.match(/"_\?=\$installDirectory"/gu) ?? []).length === 2,
    "normal Windows N-1 qualification must use the exact synchronous NSIS uninstall argument only for happy-path and bounded failure cleanup",
  );
  const synchronousCandidateUninstall = nsisUpgrade.indexOf(
    'Invoke-ExactProcess $candidateUninstaller @("/S", "_?=$installDirectory") 180000 "Candidate NSIS uninstall"',
  );
  const postUninstallRegistryCheck = nsisUpgrade.indexOf(
    "if (@(Get-CurrentUserUninstallEntries).Count -ne 0)",
    synchronousCandidateUninstall,
  );
  const successfulUninstallMarker = nsisUpgrade.indexOf(
    "$happyPathUninstalled = $true",
    synchronousCandidateUninstall,
  );
  const clearedActiveUninstaller = nsisUpgrade.indexOf(
    "$activeUninstaller = $null",
    synchronousCandidateUninstall,
  );
  assert(
    synchronousCandidateUninstall >= 0 &&
      postUninstallRegistryCheck > synchronousCandidateUninstall &&
      successfulUninstallMarker > postUninstallRegistryCheck &&
      clearedActiveUninstaller > successfulUninstallMarker,
    "normal Windows N-1 qualification must prove registry removal before marking the synchronous NSIS uninstall complete",
  );
  for (const required of [
    "windows_nsis_n_minus_one_upgrade_and_data_preservation",
    "managedRuntimeFilesystemSentinel",
    "normal N-1 upgrade did not exercise /S",
    "transition receipt survival across same-version reinstall",
    "legacy_key_adopted",
    "identityDocumentCompactSha256",
    "anchorIdentityDocumentSha256",
    "anchorMatchesIdentityDocument",
    "rotationIntentAbsent",
    "gunzipSync",
    "parseBoundedTarGz",
    "tar header checksum mismatch",
    "nonzero or truncated tar padding",
    "manifest entries are not deterministically sorted",
    "verifySignedCaseBundle",
    "master-framework-report.case.tar.gz",
    "n-minus-one-before-upgrade.case.tar.gz",
    "N-1 and candidate signed case bundles do not prove the same integrity-signing identity",
    "retained master framework report bytes differ from the independently verified signed bundle entry",
    "validateReportAgainstSignedBundle(reportRecord.report, candidate)",
    "declared AI-context explanation differs from the fixed truthful contract",
    "validateWindowsNsisUpgradeEvidenceFile",
  ]) assert(nsisUpgradeEvidence.includes(required), `normal Windows N-1 evidence contract is missing: ${required}`);
  for (const required of [
    '"runtime", "managed", "install"',
    '"runtime", "managed", "start"',
    '"runtime", "managed", "stop", "--force"',
    "podman-$oldMachineName",
    "Remove-ExactTree $oldVersionDirectory",
    "recovered-ghost-v0.1.7",
    "wsl_distribution_requires_manual_action",
    "workspace-recovery.tar",
    "FILE_FLAG_OPEN_REPARSE_POINT",
    "FILE_FLAG_BACKUP_SEMANTICS",
    "Get-BoundedAbsoluteWindowsPath",
    "$maximumWindowsPathUtf16CodeUnits = 32760",
    "$maximumVerbatimWindowsPathUtf16CodeUnits = 32766",
    "Open-NoFollowSingleLinkFile",
    "$identity.links -ne 1",
    '$processLeaseRelativePath = ".exclusive-process.lock"',
    "Assert-ExactEmptyProcessLeaseFile",
    "Assert-PreservedDataSnapshotHousekeepingRegression $workRoot",
    "Open-NoFollowWindowsSystemFile",
    "$identity.links -lt 1",
    "Get-NoFollowWindowsSystemExecutableProof",
    "Open-NoFollowRealDirectory",
    "Assert-SameNoFollowDirectoryIdentity",
    "Assert-NoFollowDirectoryIdentityRegression $workRoot",
    "Same-directory extended-prefix regression",
    "Different-directory regression",
    "Get-AuthenticodeSignature -LiteralPath",
    "O=Microsoft Corporation",
    "windows_system32_microsoft_authenticode_v1",
    "-ExpectedSystemExecutableProof $TrustedWsl.proof",
    "Get-NoFollowFileSha256Proof",
    "ExpectedExecutableProof",
    "HashData($executionGuard)",
    "executable is not the exact previously verified installer",
    "-ExpectedExecutableProof $priorInstallerProof",
    "-ExpectedExecutableProof $candidateInstaller",
    "[GhostQualificationNativeMethods]::CreateFileW",
    "ai-security-scanner.managed-wsl-recovery-intent/v2",
    "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a",
    '$candidateRuntimeEvidence.schema_version -cne "3"',
    '$candidateRuntimeEvidence.management_contract_revision -cne "2026-08-29.1"',
    "ai-security-scanner.managed-wsl-ghost-migration-consumed/v1",
    "bounded_n_minus_one_ghost_migration",
    "intentProofValid = $true",
    "ghost-migration-consumed-$oldMachineName.json",
    "InstallTransitionPresent",
    "Automatic recovery did not consume the exact HKCU InstallTransition value.",
    "Assert-OwnerOnlyFullControlFile $consumedProofPath",
    "proofRetainedAfterRuntimePurge = $true",
    "proofRetainedUntilExplicitPrivateDataCleanup = $true",
    "Candidate same-version silent reinstall before ghost recovery",
    "transitionReceiptSurvivedSameVersionReinstall = $true",
    "backup.json",
    "import.json",
    '"export", "identity", "show"',
    "integrity-signing-key.identity-anchor.json",
    "integrity-signing-key.rotation-intent.json",
    "Assert-OwnerOnlyFullControlFile",
    "anchorIdentitySha256",
    "identityDocumentSha256",
    "$writerOptions.Encoder = [Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping",
    "Assert-SerdeCompatibleJsonCompaction",
    "rotationIntentAbsent = $true",
    'registeredWslStateExercised = $true',
  ]) assert(nsisGhost.includes(required), `registered-WSL ghost qualification is missing: ${required}`);

  const ordinaryFileOpenStart = nsisGhost.indexOf("function Open-NoFollowSingleLinkFile(");
  const ordinaryFileOpenEnd = nsisGhost.indexOf("function Assert-ExactEmptyProcessLeaseFile(", ordinaryFileOpenStart);
  assert(
    ordinaryFileOpenStart >= 0 && ordinaryFileOpenEnd > ordinaryFileOpenStart,
    "registered-WSL ghost qualification has no isolated non-empty product-file opener",
  );
  const ordinaryFileOpen = nsisGhost.slice(ordinaryFileOpenStart, ordinaryFileOpenEnd);
  assert(
    ordinaryFileOpen.includes("$identity.links -ne 1") &&
      ordinaryFileOpen.includes("$identity.bytes -lt 1") &&
      !ordinaryFileOpen.includes("processLease") &&
      !ordinaryFileOpen.includes("MinimumBytes"),
    "registered-WSL generic installer/key/archive proof must remain single-link and non-empty",
  );

  const processLeaseProofStart = ordinaryFileOpenEnd;
  const processLeaseProofEnd = nsisGhost.indexOf("function Open-NoFollowWindowsSystemFile(", processLeaseProofStart);
  assert(
    processLeaseProofEnd > processLeaseProofStart,
    "registered-WSL ghost qualification has no isolated root process-lease proof",
  );
  const processLeaseProof = nsisGhost.slice(processLeaseProofStart, processLeaseProofEnd);
  for (const required of [
    "[GhostQualificationNativeMethods]::CreateFileW",
    "[GhostQualificationNativeMethods]::GENERIC_READ",
    "[GhostQualificationNativeMethods]::FILE_SHARE_READ",
    "[GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT",
    "$before.links -ne 1",
    "$before.bytes -ne 0",
    "$before.volume -ne $after.volume",
    "$before.index -ne $after.index",
    "$stream.Dispose()",
    "$handle.Dispose()",
  ]) assert(processLeaseProof.includes(required), `registered-WSL root process-lease proof is missing: ${required}`);
  assert(
    !processLeaseProof.includes("Open-NoFollowSingleLinkFile") &&
      !processLeaseProof.includes("FILE_SHARE_WRITE") &&
      !processLeaseProof.includes("FILE_SHARE_DELETE"),
    "registered-WSL empty process-lease exception must not weaken or share the generic file proof",
  );

  const preservedSnapshotStart = nsisGhost.indexOf("function Get-PreservedDataSnapshot(");
  const preservedRegressionStart = nsisGhost.indexOf(
    "function Assert-PreservedDataSnapshotHousekeepingRegression(",
    preservedSnapshotStart,
  );
  assert(
    preservedSnapshotStart >= 0 && preservedRegressionStart > preservedSnapshotStart,
    "registered-WSL ghost qualification has no bounded preserved-data snapshot",
  );
  const preservedSnapshot = nsisGhost.slice(preservedSnapshotStart, preservedRegressionStart);
  const exactLeaseExclusion = "if (-not $item.PSIsContainer -and $relative -ceq $processLeaseRelativePath)";
  assert(
    preservedSnapshot.includes(exactLeaseExclusion) &&
      preservedSnapshot.includes('Assert-ExactEmptyProcessLeaseFile $item.FullName "Root process lease"') &&
      preservedSnapshot.includes('if ($relative -eq "managed-runtime" -or $relative.StartsWith("managed-runtime/", [StringComparison]::Ordinal))') &&
      preservedSnapshot.includes('Get-NoFollowFileSha256Proof $item.FullName "Preserved data file"') &&
      (preservedSnapshot.match(/\$processLeaseRelativePath/gu) ?? []).length === 1,
    "registered-WSL preserved-data snapshot must exclude only the proven exact root process lease",
  );

  const preservedRegressionEnd = nsisGhost.indexOf("function Read-BoundedUtf8File(", preservedRegressionStart);
  assert(
    preservedRegressionEnd > preservedRegressionStart,
    "registered-WSL ghost qualification has no process-lease snapshot regression",
  );
  const preservedRegression = nsisGhost.slice(preservedRegressionStart, preservedRegressionEnd);
  for (const required of [
    '[IO.File]::WriteAllBytes((Join-Path $fixtureRoot $processLeaseRelativePath), [byte[]]::new(0))',
    "$snapshot.fileCount -ne 1",
    "$snapshot.totalBytes -ne $payloadBytes.Length",
    "Join-Path $nestedDirectory $processLeaseRelativePath",
    '"Preserved data file is not one bounded no-follow single-link regular file."',
    "Preserved-data snapshot ignored a nested process-lease-shaped file.",
    "Remove-ExactTree $fixtureRoot $Parent $fixtureName",
  ]) assert(preservedRegression.includes(required), `registered-WSL process-lease snapshot regression is missing: ${required}`);
  assert(
    (nsisGhost.match(/Assert-PreservedDataSnapshotHousekeepingRegression/gu) ?? []).length === 2 &&
      (nsisGhost.match(/Assert-ExactEmptyProcessLeaseFile/gu) ?? []).length === 2,
    "registered-WSL process-lease exception must be defined once, exercised once, and used only by the snapshot",
  );

  const synchronousGhostUninstall = 'Invoke-ExactProcess $candidateUninstaller @("/S", "_?=$installDirectory") 180000 "Candidate NSIS cleanup uninstall"';
  const synchronousGhostFailureUninstall = 'Invoke-ExactProcess $activeUninstaller @("/S", "_?=$installDirectory") 180000 "Failure-path candidate uninstall"';
  assert(
    nsisGhost.includes(synchronousGhostUninstall) &&
      nsisGhost.includes(synchronousGhostFailureUninstall) &&
      (nsisGhost.match(/"_\?=\$installDirectory"/gu) ?? []).length === 2 &&
      !nsisGhost.includes('Invoke-ExactProcess $candidateUninstaller @("/S")') &&
      !nsisGhost.includes('Invoke-ExactProcess $activeUninstaller @("/S")'),
    "registered-WSL ghost cleanup must synchronously wait for the exact NSIS uninstall directory",
  );
  const happyGhostUninstall = nsisGhost.indexOf(synchronousGhostUninstall);
  const productRegistrationCheck = nsisGhost.indexOf(
    'if (@(Get-ProductRegistryEntries).Count -ne 0) { throw "Candidate uninstaller left the product registry entry." }',
    happyGhostUninstall,
  );
  const clearedActiveUninstaller = nsisGhost.indexOf("$activeUninstaller = $null", happyGhostUninstall);
  assert(
    happyGhostUninstall >= 0 &&
      productRegistrationCheck > happyGhostUninstall &&
      clearedActiveUninstaller > productRegistrationCheck,
    "registered-WSL ghost qualification must retain cleanup ownership until NSIS registry removal is proven",
  );
  const escapedSerdeCompactionFixture = "$fixture = '{\"public_key_base64\":\"A\\u002BB\\/==\"}'";
  const literalSerdeCompactionExpected = "$expected = '{\"public_key_base64\":\"A+B/==\"}'";
  for (const [label, source] of [
    ["normal Windows N-1", nsisUpgrade],
    ["registered-WSL ghost", nsisGhost],
  ]) {
    assert(
      source.includes(escapedSerdeCompactionFixture) &&
        source.includes(literalSerdeCompactionExpected) &&
        (source.match(/Assert-SerdeCompatibleJsonCompaction/gu) ?? []).length === 2,
      `${label} qualification must prove escaped JSON input compacts to the literal serde_json byte contract`,
    );
  }
  assert(
    (nsisGhost.match(/ConvertFrom-Json -DateKind String/gu) ?? []).length === 5 &&
      !/ConvertFrom-Json(?! -DateKind String)/u.test(nsisGhost),
    "registered-WSL ghost qualification must preserve every JSON date as an exact source string",
  );
  assert(
    (nsisUpgrade.match(/-ExpectedExecutableProof/gu) ?? []).length === 3,
    "normal Windows N-1 qualification must bind all three installer launches to exact handle proofs",
  );
  assert(
    (nsisGhost.match(/-ExpectedExecutableProof/gu) ?? []).length === 3,
    "registered-WSL ghost qualification must bind all three installer launches to exact handle proofs",
  );
  assert(
    (nsisGhost.match(/-ExpectedSystemExecutableProof/gu) ?? []).length === 1,
    "registered-WSL ghost qualification must reserve its hard-link-aware proof for one OS-trusted WSL cleanup launch",
  );
  assert(
    (nsisGhost.match(/Open-NoFollowWindowsSystemFile/gu) ?? []).length === 3 &&
      (nsisGhost.match(/\$identity\.links -lt 1/gu) ?? []).length === 1 &&
      (nsisGhost.match(/\$identity\.links -ne 1/gu) ?? []).length === 1,
    "registered-WSL ghost qualification must isolate Windows system hard-link handling from the single-link product evidence policy",
  );
  assert(
    (nsisGhost.match(/Get-NoFollowWindowsSystemExecutableProof/gu) ?? []).length === 2,
    "registered-WSL ghost qualification must create its Windows system proof only through the fixed trusted-WSL resolver",
  );
  const systemProofStart = nsisGhost.indexOf("function Get-NoFollowWindowsSystemExecutableProof(");
  const systemProofEnd = nsisGhost.indexOf("function Get-LowerSha256(", systemProofStart);
  assert(systemProofStart >= 0 && systemProofEnd > systemProofStart, "registered-WSL ghost qualification has no bounded Windows system proof function");
  const systemProof = nsisGhost.slice(systemProofStart, systemProofEnd);
  const systemHandleOpen = systemProof.indexOf("$stream = Open-NoFollowWindowsSystemFile");
  const authenticodeCheck = systemProof.indexOf("Get-AuthenticodeSignature -LiteralPath");
  const sameHandleRehash = systemProof.indexOf("$afterSignatureDigest = [Security.Cryptography.SHA256]::HashData($stream)");
  const systemHandleDispose = systemProof.indexOf("$stream.Dispose()");
  assert(
    systemHandleOpen >= 0 &&
      authenticodeCheck > systemHandleOpen &&
      sameHandleRehash > authenticodeCheck &&
      systemHandleDispose > sameHandleRehash &&
      (systemProof.match(/\$stream\.Dispose\(\)/gu) ?? []).length === 1,
    "registered-WSL ghost qualification must hold and rehash the original restrictive system-file handle across Authenticode verification",
  );
  const directoryOpenStart = nsisGhost.indexOf("function Open-NoFollowRealDirectory(");
  const directoryOpenEnd = nsisGhost.indexOf("function Assert-SameNoFollowDirectoryIdentity(", directoryOpenStart);
  assert(directoryOpenStart >= 0 && directoryOpenEnd > directoryOpenStart, "registered-WSL ghost qualification has no bounded no-follow directory opener");
  const directoryOpen = nsisGhost.slice(directoryOpenStart, directoryOpenEnd);
  for (const required of [
    "FILE_READ_ATTRIBUTES",
    "FILE_SHARE_READ -bor [GhostQualificationNativeMethods]::FILE_SHARE_WRITE",
    "FILE_FLAG_BACKUP_SEMANTICS -bor [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT",
    "[IO.FileAttributes]::Directory",
    "[IO.FileAttributes]::ReparsePoint",
    "Get-OpenDirectoryIdentity $handle",
  ]) assert(directoryOpen.includes(required), `registered-WSL no-follow directory opener is missing: ${required}`);
  assert(
    !directoryOpen.includes("FILE_SHARE_DELETE"),
    "registered-WSL no-follow directory proof must prevent path deletion or replacement while its handles are held",
  );
  const directoryProofStart = directoryOpenEnd;
  const directoryProofEnd = nsisGhost.indexOf("function Assert-SingleLinkFile(", directoryProofStart);
  assert(directoryProofEnd > directoryProofStart, "registered-WSL ghost qualification has no bounded directory-identity proof");
  const directoryProof = nsisGhost.slice(directoryProofStart, directoryProofEnd);
  const actualDirectoryOpen = directoryProof.indexOf("$actualHandle = Open-NoFollowRealDirectory");
  const expectedDirectoryOpen = directoryProof.indexOf("$expectedHandle = Open-NoFollowRealDirectory");
  const volumeIdentityCheck = directoryProof.indexOf("$actualBefore.volume -ne $expectedBefore.volume");
  const fileIndexIdentityCheck = directoryProof.indexOf("$actualBefore.index -ne $expectedBefore.index");
  const expectedDirectoryDispose = directoryProof.indexOf("$expectedHandle.Dispose()");
  const actualDirectoryDispose = directoryProof.indexOf("$actualHandle.Dispose()");
  assert(
    actualDirectoryOpen >= 0 &&
      expectedDirectoryOpen > actualDirectoryOpen &&
      volumeIdentityCheck > expectedDirectoryOpen &&
      fileIndexIdentityCheck > volumeIdentityCheck &&
      expectedDirectoryDispose > fileIndexIdentityCheck &&
      actualDirectoryDispose > expectedDirectoryDispose &&
      (directoryProof.match(/Open-NoFollowRealDirectory/gu) ?? []).length === 2 &&
      (directoryProof.match(/\.Dispose\(\)/gu) ?? []).length === 2,
    "registered-WSL directory identity must compare volume and file index while both restrictive no-follow handles remain open",
  );
  const boundedPathStart = nsisGhost.indexOf("function Get-BoundedAbsoluteWindowsPath(");
  const boundedPathEnd = nsisGhost.indexOf("function Get-VerbatimWindowsPath(", boundedPathStart);
  assert(boundedPathStart >= 0 && boundedPathEnd > boundedPathStart, "registered-WSL ghost qualification has no bounded Windows path parser");
  const boundedPath = nsisGhost.slice(boundedPathStart, boundedPathEnd);
  for (const required of [
    "$Path.IndexOf([char]0) -ge 0",
    "$Path.Length -gt $maximumWindowsPathUtf16CodeUnits",
    "[IO.Path]::IsPathFullyQualified($Path)",
    "$full.IndexOf([char]0) -ge 0",
    "$full.Length -gt $maximumWindowsPathUtf16CodeUnits",
  ]) assert(boundedPath.includes(required), `registered-WSL bounded Windows path parser is missing: ${required}`);
  const exactWslStart = nsisGhost.indexOf("function Get-ExactWslRegistration(");
  const exactWslEnd = nsisGhost.indexOf("function Assert-NoFollowDirectoryIdentityRegression(", exactWslStart);
  assert(exactWslStart >= 0 && exactWslEnd > exactWslStart, "registered-WSL ghost qualification has no exact registration binding function");
  const exactWsl = nsisGhost.slice(exactWslStart, exactWslEnd);
  assert(
    exactWsl.includes("[String]::Equals($_.Name, $Name, [StringComparison]::Ordinal)") &&
      exactWsl.includes("$matches.Count -ne 1") &&
      exactWsl.includes("Get-BoundedAbsoluteWindowsPath $matches[0].BasePath") &&
      exactWsl.includes("Get-BoundedAbsoluteWindowsPath $ExpectedBasePath") &&
      exactWsl.includes("Assert-SameNoFollowDirectoryIdentity $registeredBasePath $boundedExpectedBasePath") &&
      !exactWsl.includes("Resolve-RealDirectory") &&
      !exactWsl.includes("[String]::Equals($actual, $expected"),
    "registered-WSL binding must retain the exact distro identity and bind its registry BasePath by directory object, not path spelling",
  );
  const directoryRegressionStart = exactWslEnd;
  const directoryRegressionEnd = nsisGhost.indexOf("function Get-PreservedDataSnapshot(", directoryRegressionStart);
  assert(directoryRegressionEnd > directoryRegressionStart, "registered-WSL ghost qualification has no directory-identity regression fixture");
  const directoryRegression = nsisGhost.slice(directoryRegressionStart, directoryRegressionEnd);
  for (const required of [
    "Get-VerbatimWindowsPath $sameDirectory",
    "Directory identity regression did not exercise two Windows path spellings.",
    "Assert-SameNoFollowDirectoryIdentity $sameDirectory $extendedSameDirectory",
    "Assert-SameNoFollowDirectoryIdentity $sameDirectory $differentDirectory",
    "Directory identity comparison accepted two different directory objects.",
    "Remove-ExactTree $fixtureRoot $Parent $fixtureName",
  ]) assert(directoryRegression.includes(required), `registered-WSL directory-identity regression is missing: ${required}`);
  assert(
    (nsisGhost.match(/Assert-NoFollowDirectoryIdentityRegression/gu) ?? []).length === 2,
    "registered-WSL directory-identity regression must be defined once and run once",
  );
  for (const required of [
    "windows_nsis_real_registered_wsl_n_minus_one_ghost_recovery",
    "registeredWslStateExercised",
    "noManualActionFallback",
    "intentProofValid",
    "intentSourceProviderManifestSha256",
    "receiptConsumption",
    "registryValueAbsent",
    "proofPathExact",
    "proofProtected",
    "proofRetainedAfterRuntimePurge",
    "proofRetainedUntilExplicitPrivateDataCleanup",
    "ai-security-scanner.managed-wsl-ghost-migration-consumed/v1",
    "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a",
    'runtime.schema_version === "3"',
    'runtime.management_contract_revision === "2026-08-29.1"',
    "transitionReceiptSurvivedSameVersionReinstall",
    "legacy_key_adopted",
    "identityDocumentCompactSha256",
    "anchorIdentityDocumentSha256",
    "anchorMatchesIdentityDocument",
    "rotationIntentAbsent",
    "validateWindowsNsisGhostRecoveryEvidenceFile",
  ]) assert(nsisGhostEvidence.includes(required), `registered-WSL ghost evidence contract is missing: ${required}`);
  for (const required of [
    "validateWindowsNsisUpgradeEvidenceFile",
    "validateWindowsNsisGhostRecoveryEvidenceFile",
    "windows-nsis-upgrade-qualification.json",
    "windows-nsis-ghost-recovery-qualification.json",
    "master-framework-report.case.tar.gz",
    "n-minus-one-before-upgrade.case.tar.gz",
    "two separate v0.1.7 migration qualifications",
    'manifest.schema_version === "3"',
    'manifest.management_contract_revision === "2026-08-29.1"',
    "These files are a commit-bound GitHub Actions QC artifact, not a public GitHub Release.",
    "This workflow artifact has no public",
    "These desktop installers are published as a GitHub Release.",
    "public GitHub artifact attestation before installing.",
    "release metadata publication mode mismatch",
  ]) assert(finalizer.includes(required), `release finalizer is missing Windows migration contract: ${required}`);
  for (const required of [
    "createWindowsNsisMigrationQualificationFixtures",
    "missing normal NSIS upgrade qualification",
    "missing registered-WSL ghost qualification",
    "upgrade evidence without legacy identity adoption",
    "upgrade evidence with mismatched signing identity anchor",
    "N-1 signed case bundle with the wrong integrity signer",
    "signed case bundle whose report bytes do not bind to the retained report",
    "signed case bundle with impossible observation provenance",
    "signed case bundle whose frozen AI answers contradict the report",
    "ghost evidence without a verified v2 recovery intent",
    "ghost evidence with a lost same-version transition receipt",
    "ghost evidence with an unconsumed registry receipt",
    "ghost evidence with a mutated consumed proof",
    "ghost evidence with an incomplete consumed proof",
    "windows-nsis-upgrade-qualification.json",
    "windows-nsis-ghost-recovery-qualification.json",
    'schema_version: "3"',
    'management_contract_revision: "2026-08-29.1"',
    "release metadata with a mismatched publication mode",
    "commit-bound GitHub Actions QC artifact, not a public GitHub Release",
    "public GitHub artifact attestation before installing",
  ]) assert(selfTest.includes(required), `release self-test is missing Windows migration coverage: ${required}`);
  assertOrderedTokens(linux, [
    "Linux qualification did not begin with a fresh exact short XDG runtime directory.",
    "run_managed initial-status status",
    "Initial managed status created the Linux short XDG runtime directory before installation.",
    "run_managed install install",
    "Managed payload installation created the Linux short XDG runtime directory before a Podman command.",
    "run_managed installed-status status",
    "Managed runtime Linux Podman runtime directory has unsafe permissions.",
    "Managed runtime Linux gvproxy socket exceeds Podman 5.8.2 path budget.",
    "run_managed start start",
    "run_managed running-status status",
    "run_managed egress-qualification qualify-egress",
    "run_managed container-qualification qualify",
    "run_managed stop stop",
    'flock -n "${virtiofs_pid}" true',
    "run_managed stopped-status status",
    "run_managed uninstall-purge uninstall --force --purge-image-cache",
    "Managed runtime uninstall left its exact Linux short XDG runtime directory behind.",
    "run_managed final-status status",
  ], "Linux qualification");
  assertOrderedTokens(macos, [
    "hdiutil attach",
    "Installed macOS managed-runtime manifest is malformed or lacks its released AppleHV target.",
    '"${cli}" --help',
    "Installed macOS desktop exited before the 12-second observation window.",
    "Do not invoke any managed-runtime lifecycle command",
    'rm -rf -- "${installed_app}"',
    'rmdir -- "${data_directory}"',
    "github_hosted_macos_nested_virtualization_unsupported",
    'notObserved("initial_status")',
    'notObserved("final_status")',
    'egressGateway: { outcome: "not_observed", reasonCode }',
    'containerExecution: { outcome: "not_observed", reasonCode }',
    'diskImageDetached: true',
  ], "macOS qualification");
  assertOrderedTokens(windows, [
    "GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)",
    '(Join-Path $localApplicationData "ai-security-scanner-platform-qualification-windows-$InstallerType-data")',
    "if (Test-ExactEntryExists $dataDirectory)",
    "New-Item -ItemType Directory -Path $dataDirectory -Force",
    '$initialStatus = Invoke-Managed "initial-status" @("status")',
    '$installStatus = Invoke-Managed "install" @("install")',
    '$installedStatus = Invoke-Managed "installed-status" @("status")',
    '$podmanNamespaceDirectories = @(',
    '$startStatus = Invoke-Managed "start" @("start")',
    '$runningStatus = Invoke-Managed "running-status" @("status")',
    '$egressQualification = Invoke-Managed "egress-qualification" @("qualify-egress")',
    '$containerQualification = Invoke-Managed "container-qualification" @("qualify")',
    '$stopStatus = Invoke-Managed "stop" @("stop")',
    '$stoppedStatus = Invoke-Managed "stopped-status" @("status")',
    '$uninstallStatus = Invoke-Managed "uninstall-purge" @("uninstall", "--force", "--purge-image-cache")',
    '$finalStatus = Invoke-Managed "final-status" @("status")',
  ], "Windows qualification");
  assert(
    !windows.includes('$dataDirectory = Join-Path $runnerTemp "ai-security-scanner-platform-qualification-windows-$InstallerType-data"'),
    "Windows qualification regressed its managed data directory to RUNNER_TEMP",
  );
  for (const [name, source] of [["Linux", linux], ["macOS", macos], ["Windows", windows]]) {
    assert(!source.includes("ssh-keygen"), `${name} qualification depends on a host ssh-keygen`);
  }
  assert(!linux.includes("command -v qemu-img"), "Linux qualification can resolve qemu-img from the host PATH");
  assert(!linux.includes("qemu-utils"), "Linux qualification installs a host qemu-img package");
  assert(
    !linux.includes('[[ "${podman_runtime_mode}" == "700" || "${podman_runtime_mode}" == "755" ]]'),
    "Linux qualification rejects safe umask-derived Podman runtime modes",
  );
  assert(!windows.includes("$env:SystemRoot"), "Windows qualification trusts inherited SystemRoot for WSL cleanup");
  assert(!windows.includes('.Replace([string][char]0, "")'), "Windows qualification silently repairs malformed WSL inventory");
  for (const forbidden of ["run_managed", "runtime managed", "container-qualification", "short_home"]) {
    assert(!macos.includes(forbidden), `hosted macOS qualification must not attempt an unobservable managed runtime: ${forbidden}`);
  }
  for (const required of [
    'engine_id === "gitleaks"',
    'network === "none"',
    "read_only_root === true",
    'capabilities === "drop_all"',
    "no_new_privileges === true",
    "credential_count === 0",
    "cleanup_removed === true",
    "qualificationImageFromCatalog",
    "gatewayImageFromReleaseManifest",
    "runtime/managed-egress-gateway.json",
    "result.gateway.image === expectedGatewayImage",
    "installedManifestExactMatch",
    "github-hosted",
    "macos-15-intel",
    "QUALIFICATION_SCHEMA_VERSION = 3",
    "managed_egress_gateway_readiness",
    "scanner_reachable",
    "reachability_probe",
    "socks5_no_connect_greeting",
    "upstream_connection_attempted",
    "probe_container_id",
    "probe_container_removed",
    "registry_record_removed",
    "pinned_container",
    "qualificationId",
    'bundleTypes: Object.freeze(["msi", "nsis"])',
    'qualificationState: "installer_passed_runtime_not_observed"',
    "github_hosted_macos_nested_virtualization_unsupported",
    'operation.outcome === "not_observed"',
    'evidence.releaseIdentity.releaseChannel === "prerelease"',
  ]) assert(evidence.includes(required), `strict platform qualification evidence is missing: ${required}`);
  for (const forbidden of [
    "host_limited",
    "not_run",
  ]) {
    assert(!macos.includes(forbidden), `macOS qualification retains a bypass state: ${forbidden}`);
    assert(!evidence.includes(forbidden), `platform evidence validator retains a bypass state: ${forbidden}`);
  }
}

function validateManagedRuntimeBuildContract(lock, dockerfile, vendor) {
  assert(
    lock?.schema_version === "1" &&
      lock?.updated_at === "2026-08-29T00:00:00Z" &&
      lock?.management_contract_revision === "2026-08-29.1",
    "managed runtime lock must identify the reviewed dated management contract",
  );
  const contractDate = lock.management_contract_revision.split(".")[0];
  assert(
    new Date(`${contractDate}T00:00:00Z`).toISOString().slice(0, 10) === contractDate,
    "managed runtime management contract revision has an invalid calendar date",
  );
  const qemu = lock?.linux_qemu;
  const virtiofsd = lock?.linux_virtiofsd;
  assert(
    qemu?.build_contract?.build_platform === "linux/amd64" &&
      qemu?.build_contract?.static === true &&
      JSON.stringify(qemu?.build_contract?.explicit_build_targets) ===
      JSON.stringify(["qemu-img", "qemu-system-x86_64"]) &&
      JSON.stringify(qemu?.build_contract?.required_device_models) ===
        JSON.stringify(["vhost-user-fs-pci"]) &&
      JSON.stringify(qemu?.build_contract?.exported_executables) ===
        JSON.stringify([
          "bin/qemu-img",
          "bin/qemu-system-x86_64",
          "bin/qemu-system-x86_64.real",
        ]) &&
      JSON.stringify(qemu?.build_contract?.required_outputs) ===
        JSON.stringify([
          "bin/qemu-img",
          "bin/qemu-system-x86_64",
          "bin/qemu-system-x86_64.real",
          "share/qemu",
        ]),
    "Linux managed QEMU lock must include the exact amd64 static executable exports",
  );
  assert(
    virtiofsd?.version === "1.14.0" &&
      virtiofsd?.build_contract?.build_platform === "linux/amd64" &&
      virtiofsd?.build_contract?.rust_version === "1.91.1" &&
      virtiofsd?.build_contract?.rust_builder_image ===
        "rust@sha256:d9f4b83fd097eaae5f9ace6d939e5a955dbbaa92804f9af4925f646cf9e46636" &&
      virtiofsd?.build_contract?.target === "x86_64-unknown-linux-musl" &&
      virtiofsd?.build_contract?.cargo_locked === true &&
      virtiofsd?.build_contract?.static === true &&
      virtiofsd?.build_contract?.exported_executable === "bin/virtiofsd",
    "Linux managed virtiofsd lock must include the exact static amd64 build contract",
  );
  for (const required of [
    'test "$TARGETPLATFORM" = "linux/amd64"',
    "--enable-tools",
    "--enable-vhost-user",
    "samu -C build qemu-system-x86_64 qemu-img",
    "-device help > /tmp/qemu-device-help",
    "^name \"vhost-user-fs-pci\"(,|$)",
    "/stage/opt/managed-qemu/bin/qemu-img /bin/qemu-img",
    "FROM rust@sha256:d9f4b83fd097eaae5f9ace6d939e5a955dbbaa92804f9af4925f646cf9e46636 AS virtiofsd-build",
    "COPY --from=virtiofsd . /src/",
    "cargo build --locked --release --target x86_64-unknown-linux-musl",
    "release/virtiofsd /bin/virtiofsd",
  ]) {
    assert(dockerfile.includes(required), `Linux managed QEMU build is missing: ${required}`);
  }
  for (const required of [
    "requireManagementContractRevision(lock.management_contract_revision)",
    "schema_version: '3'",
    "management_contract_revision: requireManagementContractRevision(",
    "'bin/virtiofsd'",
    "'--platform'",
    "'linux/amd64'",
    "`virtiofsd=${virtiofsdRoot}`",
    "readElfExecutableContract",
    "executable.machine !== 62",
    "executable.hasInterpreter",
    "qemu-img version ${expectedVersion}",
    "requiredQemuDeviceModels",
    "requiredQemuDeviceModels(lock)",
    "deviceHelp.stdout.matchAll",
    "deviceNames.has(model)",
    "managed QEMU omitted required device model ${model}",
    "virtiofsd ${expectedVirtiofsdVersion}",
    "qemuFiles.map(bundledArtifact)",
    "select('bin/virtiofsd')",
  ]) {
    assert(vendor.includes(required), `managed-runtime vendor contract is missing: ${required}`);
  }
}

function validateManagedRuntimeExecutionContract(managedRuntime, containerRuntime) {
  for (const required of [
    "canonical_application_data_root",
    "linux_machine_volume_spec",
    "linux_short_runtime_directory",
    "let runtime_directory = self.runtime_directory(target, &persistent_run)?;",
    'OsString::from("XDG_RUNTIME_DIR")',
    "runtime_directory.as_os_str().to_owned()",
    'OsString::from("XDG_RUNTIME_DIR"),\n            runtime_directory.as_os_str().to_owned(),',
    "ai-security-scanner-linux-xdg-runtime-v1\\0",
    "PODMAN_LINUX_MAX_SOCKET_PATH_BYTES",
    "wait_for_unlocked_linux_virtiofs_pid",
    "PODMAN_VIRTIOFS_PID_NAME",
    "remove_linux_short_runtime_directory_at",
    "self.remove_temporary_command_state_after_machine_removal_locked(target)?;",
    "linux_short_runtime_is_domain_separated_private_and_socket_bounded",
    "linux_short_runtime_cleanup_is_exact_and_unsafe_entries_fail_closed",
    'OsString::from("--volume")',
    "self.initialize_machine_with_one_shot_wsl_intent(",
    "WindowsWslOwnershipBasis::InitIntent",
    "let proof_cleanup = self.remove_windows_wsl_ownership_proof_locked",
    "managed Windows WSL initialization journal could not be consumed safely",
    "managed_runtime_recovery:wsl_distribution_requires_manual_action",
    "ManagedOperatingSystem::Macos | ManagedOperatingSystem::Windows => Ok(None)",
    "machine_application_data_volume_is_linux_only",
    "Pinned Podman 5.8.2 GetMachineDirs uses os.MkdirAll",
    'persistent_run.join("podman")',
    'containers.join("podman").join("machine").join(provider)',
    'join(provider)\n                    .join("cache")',
    "windows_runtime_command_precreates_the_exact_private_podman_machine_namespace",
  ]) {
    assert(
      managedRuntime.includes(required),
      `managed runtime execution contract is missing: ${required}`,
    );
  }
  const directWslUnregister = 'OsString::from("--unregister")';
  const managedRuntimeProduction = managedRuntime.split("\n#[cfg(test)]\nmod tests {")[0];
  const boundedRecoverySection = (start, end, label) => {
    const startIndex = managedRuntimeProduction.indexOf(start);
    const endIndex = managedRuntimeProduction.indexOf(end, startIndex + start.length);
    assert(startIndex !== -1 && endIndex > startIndex, `managed runtime is missing ${label}`);
    return managedRuntimeProduction.slice(startIndex, endIndex);
  };
  const unregisterCount = (source) => source.split(directWslUnregister).length - 1;
  assert(
    unregisterCount(managedRuntimeProduction) === 4 &&
      !managedRuntimeProduction.includes('.arg("--unregister")') &&
      managedRuntime.includes("direct_wsl_unregister_is_whitelisted_only_for_verified_backup_recovery"),
    "managed runtime has an unreviewed direct Windows WSL unregister path",
  );
  const handoffRecovery = boundedRecoverySection(
    "fn recover_windows_wsl_distribution_locked",
    "fn prepare_windows_wsl_quarantine_import_directory",
    "bounded Windows WSL handoff recovery",
  );
  assert(
    unregisterCount(handoffRecovery) === 2 &&
      handoffRecovery.split("verify_windows_wsl_recovery_archive").length - 1 >= 2 &&
      handoffRecovery.includes("verify_windows_wsl_quarantine_registration") &&
      handoffRecovery.includes("verify_pending_windows_wsl_registration"),
    "Windows WSL handoff unregister is not bound to the verified backup transaction",
  );
  const incompleteImportCleanup = boundedRecoverySection(
    "fn remove_uncheckpointed_windows_wsl_quarantine_locked",
    "fn verify_windows_wsl_quarantine_registration",
    "bounded incomplete Windows WSL import cleanup",
  );
  assert(
    unregisterCount(incompleteImportCleanup) === 1 &&
      incompleteImportCleanup.includes("verify_windows_wsl_quarantine_registration_path"),
    "incomplete Windows WSL import cleanup is not bound to its generated quarantine workspace",
  );
  const completedRecoveryCleanup = boundedRecoverySection(
    "fn complete_windows_wsl_recovery_locked",
    "fn windows_wsl_ownership_proof_path",
    "bounded completed Windows WSL recovery cleanup",
  );
  assert(
    unregisterCount(completedRecoveryCleanup) === 1 &&
      completedRecoveryCleanup.includes("verify_windows_wsl_recovery_archive") &&
      completedRecoveryCleanup.includes("verify_windows_wsl_quarantine_registration"),
    "completed Windows WSL recovery cleanup is not bound to the verified recovery copy",
  );
  assert(
    !managedRuntimeProduction.includes("--import-in-place"),
    "managed runtime recovery depends on unsupported in-place Windows WSL import",
  );
  for (const required of [
    'podman_userns: format!("keep-id:uid={uid},gid={gid}")',
    "if provider.uses_podman_dialect()",
    'format!("--userns={}", plan.rootless_user.podman_userns)',
    "rootless_user_mapping_for_ids(65532, 65532)",
    "validate_run_plan_user_integrity(plan)?",
    "podman_execution_injects_exact_keep_id_mapping_but_docker_does_not",
    'RuntimeProvider::Docker => "{{json .SecurityOptions}}"',
    'RuntimeProvider::ManagedLocal | RuntimeProvider::Podman => "{{json .Host.Security}}"',
    "validate_runtime_security_options",
    "MAX_RUNTIME_SECURITY_OPTIONS_BYTES",
    "release-managed Podman did not report rootless seccomp isolation",
    "security_preflight_uses_the_provider_native_template_and_bounded_schema",
    "process_preflight_invokes_the_exact_podman_security_selector",
  ]) {
    assert(
      containerRuntime.includes(required),
      `container rootless execution contract is missing: ${required}`,
    );
  }
  assert(
    containerRuntime.includes("matches!(self, Self::ManagedLocal | Self::Podman)"),
    "keep-id injection must remain limited to Podman-dialect providers",
  );
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
  const cargoLock = await readFile(path.join(PROJECT_ROOT, "Cargo.lock"), "utf8");
  const repositoryReadme = await readFile(path.join(PROJECT_ROOT, "README.md"), "utf8");
  const releaseGuide = await readFile(path.join(PROJECT_ROOT, "docs/release/README.md"), "utf8");
  const releaseMetadataSchema = await readJson(
    path.join(PROJECT_ROOT, "docs/release/release-metadata.schema.json"),
  );
  const catalog = await readJson(path.join(PROJECT_ROOT, "engines/catalog.json"));
  const version = packageJson.version;
  const tag = typeof args.get("tag") === "string" ? args.get("tag") : `v${version}`;
  const releaseLineNotes = await readFile(
    path.join(PROJECT_ROOT, `docs/release/v${version}.md`),
    "utf8",
  );
  const managedRuntimeLock = await readJson(path.join(PROJECT_ROOT, "runtime/upstreams.lock.json"));
  const managedRuntimeSchema = await readJson(
    path.join(PROJECT_ROOT, "runtime/managed-runtime.schema.json"),
  );
  const managedEgressGatewayManifest = await readJson(
    path.join(PROJECT_ROOT, "runtime/managed-egress-gateway.json"),
  );
  const managedRuntimeDockerfile = await readFile(
    path.join(PROJECT_ROOT, "runtime/linux-qemu.Dockerfile"),
    "utf8",
  );
  const managedRuntimeVendor = await readFile(
    path.join(PROJECT_ROOT, "runtime/vendor-managed-runtime.mjs"),
    "utf8",
  );
  const managedRuntimeSource = await readFile(
    path.join(PROJECT_ROOT, "src-tauri/src/managed_runtime.rs"),
    "utf8",
  );
  assert(
    releaseMetadataSchema.properties?.schemaVersion?.const === 2 &&
      JSON.stringify(releaseMetadataSchema.properties?.publicationMode?.enum) ===
        JSON.stringify(["commit-bound-qc", "public-github-release"]) &&
      Array.isArray(releaseMetadataSchema.allOf) &&
      releaseMetadataSchema.allOf.length === 1,
    "release metadata schema does not bind QC/public publication and attestation modes",
  );
  const containerRuntimeSource = await readFile(
    path.join(PROJECT_ROOT, "src-tauri/src/container_runtime.rs"),
    "utf8",
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
  validateManagedEgressGatewayManifest(managedEgressGatewayManifest, version);
  const [major, minor, patch] = version.split(".").map(Number);
  assert(
    major <= 255 && minor <= 255 && patch <= 65_535,
    "release version exceeds the Windows MSI native version bounds",
  );
  assert(
    tauri.bundle?.windows?.wix?.version === undefined,
    "numeric releases must derive their WiX version from the exact app version",
  );
  assert(
    repositoryReadme.includes(`<!-- Release line: v${version}. -->`),
    "README release line is out of sync",
  );
  assert(
    releaseLineNotes.startsWith(`# v${version} `),
    `docs/release/v${version}.md has the wrong release heading`,
  );
  assert(
    releaseGuide.includes(`npm run release:validate -- --tag v${version}`) &&
      releaseGuide.includes(`git tag -a v${version} <preflight-head-sha>`) &&
      releaseGuide.includes(`git push origin v${version}`),
    "release guide commands are out of sync",
  );
  assert(
      releaseGuide.includes("`macos-15-intel`") &&
      releaseGuide.includes("Linux and Windows must prove this exact sequence") &&
      releaseGuide.includes("github_hosted_macos_nested_virtualization_unsupported") &&
      releaseGuide.includes("records every managed-runtime operation, the egress gateway probe, and the container probe as `not_observed`") &&
      releaseGuide.includes("can publish only a `prerelease`") &&
      releaseGuide.includes("https://docs.github.com/en/actions/concepts/runners/github-hosted-runners") &&
      !releaseGuide.includes("`not_run`"),
    "release guide does not document the strict pre-release hosted-macOS observation contract",
  );
  assert(
    releaseGuide.includes("resolves `bin/qemu-img` from the installed managed-runtime") &&
      releaseGuide.includes("resolves `bin/virtiofsd` from that manifest") &&
      releaseGuide.includes("bounded raw bytes") &&
      releaseGuide.includes("both fixed staging names are absent") &&
      releaseGuide.includes("provider-home directory itself must be absent") &&
      releaseGuide.includes("Windows NSIS Setup executable") &&
      releaseGuide.includes("dual-network pinned gateway container") &&
      releaseGuide.includes("exchanges only a SOCKS greeting") &&
      releaseGuide.includes("sends no CONNECT request") &&
      releaseGuide.includes("never emits a passing") &&
      releaseGuide.includes("runtime status, gateway result, or container result"),
    "release guide omits the exact per-platform managed-runtime qualification contract",
  );
  assert(
      releaseLineNotes.includes("macOS 15 Intel") &&
      releaseLineNotes.includes("network-disabled Gitleaks container probe") &&
      releaseLineNotes.includes("Windows NSIS Setup") &&
      releaseLineNotes.includes("never sends CONNECT") &&
      releaseLineNotes.includes("`not_observed`, not passed") &&
      releaseLineNotes.includes("limited evidence is accepted only for a pre-release"),
    "release-line notes omit the honest hosted-macOS pre-release qualification contract",
  );
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

  execFileSync(
    process.execPath,
    [path.join(PROJECT_ROOT, "scripts", "release", "validate-windows-nsis-template.mjs")],
    { cwd: PROJECT_ROOT, stdio: "inherit" },
  );

  const workflows = await validateWorkflowSyntaxAndPins();
  validateReleaseWorkflow(workflows.get("release.yml"));
  assert(
    workflows.get("ci.yml")?.jobs?.["windows-managed-runtime"]?.["runs-on"] === "windows-2025",
    "Windows managed-runtime native tests must match the fresh release qualification runner",
  );
  const windowsCiSource = JSON.stringify(workflows.get("ci.yml")?.jobs?.["windows-managed-runtime"]);
  for (const required of [
    "Vendor the release-equivalent Windows managed runtime",
    "runtime/vendor-managed-runtime.mjs",
    "--target x86_64-pc-windows-msvc",
    "--output runtime/staged/managed-runtime",
    "Verify the staged Windows managed-runtime manifest and files",
    "scripts/release/generate-runtime-evidence.mjs",
    "--manifest runtime/staged/managed-runtime/manifest.json",
    "--expected-manifest-sha256 a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a",
  ]) {
    assert(windowsCiSource.includes(required), `Windows release-equivalent CI is missing: ${required}`);
  }
  const windowsCiSteps = workflows.get("ci.yml")?.jobs?.["windows-managed-runtime"]?.steps ?? [];
  const windowsVendorIndex = windowsCiSteps.findIndex(
    (step) => step.name === "Vendor the release-equivalent Windows managed runtime",
  );
  const windowsManifestVerificationIndex = windowsCiSteps.findIndex(
    (step) => step.name === "Verify the staged Windows managed-runtime manifest and files",
  );
  const windowsNsisBuildIndex = windowsCiSteps.findIndex(
    (step) => step.name === "Compile the reviewed custom NSIS installer",
  );
  assert(
    windowsVendorIndex >= 0 &&
      windowsVendorIndex < windowsManifestVerificationIndex &&
      windowsManifestVerificationIndex < windowsNsisBuildIndex,
    "Windows CI must vendor and verify the release managed runtime before compiling NSIS",
  );
  assert(
    !JSON.stringify(workflows.get("release.yml")).includes("qemu-utils"),
    "release qualification must not mask a missing bundled qemu-img with a host package",
  );
  validateManagedRuntimeBuildContract(
    managedRuntimeLock,
    managedRuntimeDockerfile,
    managedRuntimeVendor,
  );
  assert(
    managedRuntimeSchema?.properties?.schema_version?.const === "3" &&
      managedRuntimeSchema?.required?.includes("management_contract_revision") &&
      typeof managedRuntimeSchema?.properties?.management_contract_revision?.pattern === "string",
    "managed runtime schema must require the schema-3 management contract revision",
  );
  validateManagedRuntimeExecutionContract(managedRuntimeSource, containerRuntimeSource);
  const qualificationSources = new Map();
  for (const name of [
    "qualify-linux.sh",
    "qualify-macos.sh",
    "qualify-windows.ps1",
    "platform-qualification.mjs",
    "qualify-windows-nsis-upgrade.ps1",
    "windows-nsis-upgrade-evidence.mjs",
    "qualify-windows-nsis-ghost-recovery.ps1",
    "windows-nsis-ghost-recovery-evidence.mjs",
    "finalize-release.mjs",
    "self-test.mjs",
  ]) {
    qualificationSources.set(
      name,
      await readFile(path.join(PROJECT_ROOT, "scripts", "release", name), "utf8"),
    );
  }
  validatePlatformQualificationSources(qualificationSources);

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
  const releaseTestTemporaryRoot = path.join(PROJECT_ROOT, "target", "release-validation-tmp");
  await mkdir(releaseTestTemporaryRoot, { recursive: true });
  execFileSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", "engine-image-evidence.mjs"), "self-test"], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      TEMP: releaseTestTemporaryRoot,
      TMP: releaseTestTemporaryRoot,
      TMPDIR: releaseTestTemporaryRoot,
    },
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
  validateEngineImageWorkflow(workflows.get("engine-image-gitleaks.yml"), {
    image: "ghcr.io/teddashh/ai-security-scanner-engine-gitleaks",
    tag: "8.30.1-1",
    requiredPaths: [
      "engines/images/gitleaks/Dockerfile",
      "engines/images/gitleaks/launcher",
      "generic-api-key",
      "REDACTED",
    ],
  });

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
    `Release metadata is consistent for ${tag}; ${workflows.size} workflow files are valid YAML with SHA-pinned actions.\n`,
  );
}

runMain(main);
