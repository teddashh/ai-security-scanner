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

function assertSourceStringArray(source, startToken, endToken, expected, label) {
  const start = source.indexOf(startToken);
  const end = source.indexOf(endToken, start + startToken.length);
  assert(start >= 0 && end > start, `${label} source array is missing or unbounded`);
  const values = [...source.slice(start + startToken.length, end).matchAll(/"([^"\r\n]+)"/gu)].map((match) => match[1]);
  assert(
    JSON.stringify(values) === JSON.stringify(expected),
    `${label} source array is not the exact ordered released set`,
  );
}

function sourceFunction(source, name, label) {
  const start = source.indexOf(`function ${name}(`);
  const end = source.indexOf("\nfunction ", start + 1);
  assert(start >= 0 && end > start, `${label} function is missing or unbounded`);
  return source.slice(start, end);
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
    "Remove-ExactTree $oldVersionDirectory",
    "recovered-ghost-v0.1.7",
    "wsl_distribution_requires_manual_action",
    '$currentMachinePrefix = "assm2-win-x64"',
    '$candidateDistributionName = "podman-$candidateMachineName"',
    "Get-RetainedVhdIdentity",
    "Start-WslSentinelLease",
    "Assert-WslSentinelLeaseCheckpoint",
    "Stop-WslSentinelLease",
    "Qualification-only unrelated WSL rootfs export",
    "Qualification-only unrelated WSL import",
    "Candidate automatic side-by-side managed WSL initialization",
    "ai-security-scanner.managed-wsl-legacy-workspace-retained/v1",
    '$retainedProof.authorizes_cleanup -ne $false',
    '$retainedProof.transition_evidence_source -cne "nsis_install_transition"',
    "legacy_registration_id",
    "current_registration_id",
    "legacy_vhd_file_index",
    "legacy_provider_config_sha256",
    "legacy_ssh_public_key_sha256",
    "Candidate did not consume the transition after durably recording legacy retention.",
    "Current assm2 managed runtime cleanup uninstall",
    "Explicit qualification teardown",
    "master-framework-report.json",
    "NIST CSF",
    "ISO/IEC 27001",
    "AIDEFEND",
    "legacy_key_adopted",
    "integrity-signing-key.identity-anchor.json",
    "transitionReceiptSurvivedSameVersionReinstall = $true",
    "missingVersionsManifestExercised = $true",
    "schemaVersion = 2",
    "sentinelLifecycle",
    "proofAbsentWhileRegistryReceiptPresent = $true",
    "proofValidatedBeforeRegistryAbsenceCheck = $true",
    "registryValueAbsentAfterDurableProof = $true",
    "public const uint FILE_READ_DATA = 0x00000001;",
  ]) assert(nsisGhost.includes(required), "registered-WSL side-by-side qualification is missing: " + required);
  for (const obsolete of [
    "Start-WslSentinelProcess",
    "Assert-WslSentinelProcess",
    "legacySentinelProcessSurvived",
    "unrelatedSentinelProcessSurvived",
  ]) assert(!nsisGhost.includes(obsolete), "registered-WSL side-by-side qualification retains obsolete sentinel evidence: " + obsolete);

  const retainedVhdStart = nsisGhost.indexOf("function Get-RetainedVhdIdentity(");
  const retainedVhdEnd = nsisGhost.indexOf("function Open-NoFollowSingleLinkFile(", retainedVhdStart);
  assert(
    retainedVhdStart >= 0 && retainedVhdEnd > retainedVhdStart,
    "registered-WSL side-by-side qualification has no bounded VHD observation function",
  );
  const retainedVhd = nsisGhost.slice(retainedVhdStart, retainedVhdEnd);
  for (const required of [
    "[GhostQualificationNativeMethods]::CreateFileW",
    "[GhostQualificationNativeMethods]::FILE_READ_DATA",
    "[GhostQualificationNativeMethods]::FILE_SHARE_READ -bor",
    "[GhostQualificationNativeMethods]::FILE_SHARE_WRITE",
    "[GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT",
    "GetFileInformationByHandle",
    "[IO.FileAttributes]::ReparsePoint",
    "$handle.Dispose()",
  ]) assert(retainedVhd.includes(required), "retained VHD observation is missing: " + required);
  assert(
    !retainedVhd.includes("FILE_SHARE_DELETE") &&
      !retainedVhd.includes("GENERIC_WRITE") &&
      !retainedVhd.includes("GENERIC_READ"),
    "retained VHD observation must use minimum read share arbitration, remain no-follow, and stay non-destructive",
  );

  const wslRegistrationStart = nsisGhost.indexOf("function Get-WslRegistrations");
  const wslRegistrationEnd = nsisGhost.indexOf("function Get-ExactWslRegistration", wslRegistrationStart);
  const wslRegistration = nsisGhost.slice(wslRegistrationStart, wslRegistrationEnd);
  for (const required of [
    "[Guid]::Parse($_.PSChildName.Trim('{', '}'))",
    '.ToString("D").ToLowerInvariant()',
    "RegistrationId = $registrationId",
    "DistributionName",
    "BasePath",
  ]) assert(wslRegistration.includes(required), "WSL registry proof is missing: " + required);

  const exactProcess = sourceFunction(nsisGhost, "Invoke-ExactProcess", "exact process execution");
  for (const required of [
    '[bool]$KeepRunning = $false',
    "$KeepRunning -and -not $CaptureOutput",
    "$process = [Diagnostics.Process]::new()",
    "$process.Start()",
    "[GhostQualificationBoundedCaptureStream]::new($captureLimit)",
    "$process.StandardOutput.BaseStream.CopyToAsync($stdoutCapture)",
    "$process.StandardError.BaseStream.CopyToAsync($stderrCapture)",
    "$process.HasExited",
    "$process.StartTime.ToUniversalTime()",
    "Complete-BoundedProcessCapture",
    "$process.ExitCode",
    "$processLeaseReturned = $true",
    "Process = $process",
    "ProcessId = [int]$process.Id",
    "ProcessStartedAt = $processStartedAt",
    "StdoutTask = $stdoutTask",
    "StderrTask = $stderrTask",
    "StdoutCapture = $stdoutCapture",
    "StderrCapture = $stderrCapture",
    "if (-not $processLeaseReturned)",
    "$process.Dispose()",
  ]) assert(exactProcess.includes(required), "foreground process lease support is missing: " + required);
  assert(!exactProcess.includes("ReadToEndAsync"), "exact process capture must remain fixed-cap and continuously drained");
  assertOrderedTokens(exactProcess, [
    "$started = $process.Start()",
    "$stdoutCapture = [GhostQualificationBoundedCaptureStream]::new($captureLimit)",
    "$stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutCapture)",
    "$stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrCapture)",
    "if ($KeepRunning) {\n      $process.Refresh()",
    "$process.HasExited",
    "$processLeaseReturned = $true",
    "Process = $process",
  ], "retained bounded process capture");

  for (const required of [
    "public sealed class GhostQualificationBoundedCaptureStream",
    "private readonly byte[] retained",
    "if (copied != buffer.Length) { overflowed = true; }",
    "WriteCore(buffer.Span)",
    "public byte[] Snapshot()",
    "Assert-BoundedCaptureStreamRegression",
    "Assert-WslGuestScriptNormalizationRegression",
  ]) assert(nsisGhost.includes(required), "bounded process/guest-script regression support is missing: " + required);
  assert(
    nsisGhost.includes(
      "\nAssert-WslGuestScriptNormalizationRegression\nAssert-BoundedCaptureStreamRegression\n",
    ),
    "bounded guest-script and process-capture regressions are not executed before qualification setup",
  );

  const captureCompletion = sourceFunction(
    nsisGhost,
    "Complete-BoundedProcessCapture",
    "bounded process capture completion",
  );
  for (const required of [
    "[Threading.Tasks.Task]::WhenAll",
    "$drain.Wait(5000)",
    "$StdoutCapture.Snapshot()",
    "$StderrCapture.Snapshot()",
    "[Text.UTF8Encoding]::new",
    "stdoutOverflowed = [bool]$StdoutCapture.Overflowed",
    "stderrOverflowed = [bool]$StderrCapture.Overflowed",
  ]) assert(captureCompletion.includes(required), "bounded process capture completion is missing: " + required);

  const captureRegression = sourceFunction(
    nsisGhost,
    "Assert-BoundedCaptureStreamRegression",
    "bounded process capture regression",
  );
  for (const required of [
    "[GhostQualificationBoundedCaptureStream]::new(8)",
    "$capture.Write($first, 0, $first.Length)",
    "$capture.Write($later, 0, $later.Length)",
    "$source.CopyToAsync($asyncCapture)",
    "$copy.Wait(1000)",
    "$source.Position -ne $source.Length",
    "$asyncCapture.Overflowed",
  ]) assert(captureRegression.includes(required), "bounded process capture regression is missing: " + required);

  const guestNormalizer = sourceFunction(
    nsisGhost,
    "ConvertTo-LfWslGuestScript",
    "WSL guest-script normalizer",
  );
  for (const required of [
    '.Replace("`r`n", "`n")',
    "$normalized.Contains(\"`r\")",
    "$Script.IndexOf([char]0)",
    "$maximumWslGuestScriptBytes",
    "[Text.Encoding]::UTF8.GetByteCount($normalized)",
  ]) assert(guestNormalizer.includes(required), "WSL guest-script normalizer is missing: " + required);
  assert(
    !guestNormalizer.includes('.Replace("`r", "`n")') &&
      !guestNormalizer.includes('.Replace("`r", "")'),
    "WSL guest-script normalization must reject a bare CR instead of silently rewriting it",
  );

  const guestNormalizationRegression = sourceFunction(
    nsisGhost,
    "Assert-WslGuestScriptNormalizationRegression",
    "WSL guest-script normalization regression",
  );
  for (const required of [
    '"first`r`nsecond`r`n"',
    '"first`nsecond`n"',
    '"first`rsecond"',
    '"first$([char]0)second"',
    "$maximumWslGuestScriptBytes + 1",
  ]) assert(guestNormalizationRegression.includes(required), "WSL guest-script normalization regression is missing: " + required);

  const runningInventory = sourceFunction(
    nsisGhost,
    "Get-WslRunningDistributionNames",
    "running WSL inventory",
  );
  for (const required of [
    '"--list", "--running", "--quiet"',
    "$TrustedWsl",
    "running inventory",
  ]) assert(runningInventory.includes(required), "running WSL inventory proof is missing: " + required);

  const exactWslUnregisterStart = nsisGhost.indexOf("function Unregister-ProvenExactWsl(");
  const exactWslUnregisterEnd = nsisGhost.indexOf(
    "\n}\n\nAssert-WslGuestScriptNormalizationRegression",
    exactWslUnregisterStart,
  );
  assert(
    exactWslUnregisterStart >= 0 && exactWslUnregisterEnd > exactWslUnregisterStart,
    "exact WSL unregister function is missing or unbounded",
  );
  const exactWslUnregister = nsisGhost.slice(exactWslUnregisterStart, exactWslUnregisterEnd);
  for (const required of [
    '$environment["WSL_UTF8"] = "1"',
    'Invoke-ExactProcess $TrustedWsl.executable @("--unregister", $Name)',
    "-ExpectedSystemExecutableProof $TrustedWsl.proof",
  ]) assert(exactWslUnregister.includes(required), "exact WSL unregister is missing: " + required);

  const sentinelGuestIdentity = sourceFunction(
    nsisGhost,
    "Get-WslSentinelGuestIdentity",
    "sentinel guest identity",
  );
  for (const required of [
    'state="/run/assm-qc-sentinel-$token"',
    "ConvertTo-LfWslGuestScript",
    'test -r "/proc/$pid/stat"',
    'awk \'{ print $22 }\' "/proc/$pid/stat"',
    "cat /proc/sys/kernel/random/boot_id",
    'readlink "/proc/$pid/exe"',
    '"/usr/bin/sleep"',
    "LinuxPid",
    "LinuxStartTicks",
    "LinuxBootId",
  ]) assert(sentinelGuestIdentity.includes(required), "sentinel guest identity proof is missing: " + required);

  const sentinelProcessReproof = sourceFunction(
    nsisGhost,
    "Assert-WslSentinelLeaseProcess",
    "foreground sentinel client reproof",
  );
  for (const required of [
    "$process.Refresh()",
    "$process.HasExited",
    "Complete-WslSentinelLeaseOutput",
    "$process.ExitCode",
    "Get-SingleLineProcessDiagnostic",
    "$Lease.StdoutCapture.Overflowed",
    "$Lease.StderrCapture.Overflowed",
    "$process.StartTime.ToUniversalTime()",
    "$process.Id",
    "$Lease.WindowsClientPid",
    "$Lease.WindowsClientStartedAt",
  ]) assert(sentinelProcessReproof.includes(required), "foreground sentinel client reproof is missing: " + required);

  const sentinelStart = sourceFunction(nsisGhost, "Start-WslSentinelLease", "sentinel lease start");
  for (const required of [
    "Get-ExactWslRegistration $DistributionName $ExpectedBasePath",
    'state="/run/assm-qc-sentinel-$token"',
    "ConvertTo-LfWslGuestScript",
    "phase=runtime_directory",
    "phase=sleep_executable",
    "phase=publish_state",
    "assm sentinel startup failed at %s (exit %s)",
    'pid="$$"',
    'awk \'{ print $22 }\' "/proc/$pid/stat"',
    "cat /proc/sys/kernel/random/boot_id",
    "exec /usr/bin/sleep 2147483647",
    "Invoke-ExactProcess $TrustedWsl.executable",
    ') 120000 "$Label foreground sentinel start" $true $environment',
    "-ExpectedSystemExecutableProof $TrustedWsl.proof -KeepRunning $true",
    "Process = $processLease.Process",
    "RegistrationId = [string]$registration.RegistrationId",
    "WindowsClientPid = [int]$processLease.ProcessId",
    "WindowsClientStartedAt = [string]$processLease.ProcessStartedAt",
    "TokenSha256",
    "LinuxBootId",
    "LinuxPid",
    "LinuxStartTicks",
    "StdoutTask = $processLease.StdoutTask",
    "StderrTask = $processLease.StderrTask",
    "StdoutCapture = $processLease.StdoutCapture",
    "StderrCapture = $processLease.StderrCapture",
    "$deadline.ElapsedMilliseconds -lt 30000",
  ]) assert(sentinelStart.includes(required), "foreground sentinel lease start is missing: " + required);
  assert(
    !/\bnohup\b/iu.test(sentinelStart) &&
      !sentinelStart.includes("$!") &&
      !/(?:^|[;\s])&(?!&)(?=$|[;\s])/mu.test(sentinelStart) &&
      !sentinelStart.includes("/tmp/assm-qc-"),
    "sentinel lease start must retain a foreground process handle without a detached shell process",
  );

  const sentinelCheckpoint = sourceFunction(
    nsisGhost,
    "Assert-WslSentinelLeaseCheckpoint",
    "sentinel lifecycle checkpoint",
  );
  for (const required of [
    "$sentinelLifecycleRequiredPhases -ccontains $Phase",
    "Assert-WslSentinelLeaseProcess $Lease",
    "Get-WslRunningDistributionNames $TrustedWsl",
    "Get-ExactWslRegistration $Lease.DistributionName $Lease.ExpectedBasePath",
    "$registration.RegistrationId -cne [string]$Lease.RegistrationId",
    "Get-WslSentinelGuestIdentity",
    "$identity.LinuxBootId -cne [string]$Lease.LinuxBootId",
    "$identity.LinuxPid -ne [uint64]$Lease.LinuxPid",
    "$identity.LinuxStartTicks -ne [uint64]$Lease.LinuxStartTicks",
    "$rebound.RegistrationId -cne [string]$Lease.RegistrationId",
  ]) assert(sentinelCheckpoint.includes(required), "sentinel lifecycle checkpoint is missing: " + required);
  assert(
    (sentinelCheckpoint.match(/Get-ExactWslRegistration/gu) ?? []).length === 2,
    "each sentinel checkpoint must re-prove its exact WSL registration before and after guest identity observation",
  );
  assertOrderedTokens(sentinelCheckpoint, [
    "phase = $Phase",
    "observedAt =",
    "distributionName =",
    "registrationId =",
    "windowsClientPid =",
    "windowsClientStartedAt =",
    "linuxBootId =",
    "linuxPid =",
    "linuxStartTicks =",
    "tokenSha256 =",
  ], "sentinel lifecycle checkpoint record");

  const sentinelStop = sourceFunction(nsisGhost, "Stop-WslSentinelLease", "sentinel lease stop");
  for (const required of [
    "Get-ExactWslRegistration $Lease.DistributionName $Lease.ExpectedBasePath",
    'state="/run/assm-qc-sentinel-$token"',
    "ConvertTo-LfWslGuestScript",
    "kill -TERM",
    'test "$attempt" -lt 100',
    ") 30000 \"$Label exact guest stop\"",
    "$process.WaitForExit(15000)",
    "Complete-WslSentinelLeaseOutput",
    "$output.stdoutOverflowed",
    "$output.stderrOverflowed",
    "$output.stdoutBytes -ne 0",
    "$output.stderrBytes -ne 0",
    "$process.Kill($true)",
    "$process.WaitForExit(5000)",
    "$process.Dispose()",
    "$Lease.Stopped = $true",
  ]) assert(sentinelStop.includes(required), "bounded sentinel lease stop is missing: " + required);
  assertOrderedTokens(sentinelStop, [
    "$process.WaitForExit(15000)",
    "Complete-WslSentinelLeaseOutput",
    "$output.stdoutOverflowed",
    "$output.stdoutBytes -ne 0",
    "$stopIdentityProven = $true",
    "$process.Dispose()",
    "$Lease.Stopped = $true",
  ], "bounded quiet sentinel stop");

  const sideBySideStart = nsisGhost.indexOf("$sideBySideProcess = Invoke-ExactProcess");
  const sideBySideEnd = nsisGhost.indexOf("$candidateCase = Invoke-CliJson", sideBySideStart);
  assert(
    sideBySideStart >= 0 && sideBySideEnd > sideBySideStart,
    "registered-WSL qualification has no bounded side-by-side initialization section",
  );
  const sideBySideSection = nsisGhost.slice(sideBySideStart, sideBySideEnd);
  for (const forbidden of ['"--export"', '"--import"', '"--unregister"', '"--shutdown"', '"--terminate"']) {
    assert(
      !sideBySideSection.includes(forbidden),
      "candidate side-by-side initialization includes a destructive or global legacy WSL action: " + forbidden,
    );
  }
  for (const required of [
    "Get-ExactWslRegistration $oldDistributionName $oldWslBasePath",
    "Get-ExactWslRegistration $candidateDistributionName $candidateWslBasePath",
    "$unrelatedRegistrationAfter.RegistrationId -cne",
    "Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease",
    "Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease",
    "Candidate changed legacy VHD identity field",
    "Retained legacy-workspace proof",
    "authorizes_cleanup",
    "current_registration_id",
  ]) assert(sideBySideSection.includes(required), "bounded side-by-side initialization proof is missing: " + required);

  const proofRead = sideBySideSection.indexOf("$retainedProof = Read-BoundedJsonFile");
  const proofSchema = sideBySideSection.indexOf('$retainedProof.schema_version -cne "ai-security-scanner.managed-wsl-legacy-workspace-retained/v1"');
  const proofAcl = sideBySideSection.indexOf("$retainedProofItem = Assert-OwnerOnlyFullControlFile");
  const receiptAbsenceCheck = sideBySideSection.indexOf("$postSideBySideRegistry = Get-ExactProductRegistry");
  assert(
    proofAcl >= 0 && proofRead > proofAcl && proofSchema > proofRead && receiptAbsenceCheck > proofSchema,
    "qualification must validate the durable retained proof before confirming receipt consumption",
  );
  const fixtureExport = nsisGhost.indexOf('"--export", $oldDistributionName, $unrelatedExportArchive');
  const candidateStart = nsisGhost.indexOf("$sideBySideProcess = Invoke-ExactProcess");
  assert(
    fixtureExport >= 0 && fixtureExport < candidateStart,
    "unrelated WSL setup export must be isolated before candidate execution",
  );
  assert(
    !nsisGhost.includes('Invoke-TrustedWsl $trustedWsl @("--shutdown"') &&
      !nsisGhost.includes('Invoke-TrustedWsl $trustedWsl @("--terminate", $oldDistributionName'),
    "qualification must not globally stop WSL or terminate the retained legacy distribution",
  );

  const runtimePurge = nsisGhost.indexOf('"Current assm2 managed runtime cleanup uninstall"');
  const oldAfterPurge = nsisGhost.indexOf("$oldRegistrationAfterPurge = Get-ExactWslRegistration", runtimePurge);
  const unrelatedAfterPurge = nsisGhost.indexOf("$unrelatedRegistrationAfterPurge = Get-ExactWslRegistration", oldAfterPurge);
  const nsisUninstall = nsisGhost.indexOf('"Candidate NSIS cleanup uninstall"', unrelatedAfterPurge);
  const signingIdentityAdoption = nsisGhost.indexOf("$candidateSigningIdentity = Invoke-CliJson");
  const postSideBySideBundleVerification = nsisGhost.indexOf(
    "$afterVerification = Invoke-CliJson",
    candidateStart,
  );
  const masterReportExport = nsisGhost.indexOf(
    '"--format", "framework-report", "--destination", $masterFrameworkReportPath',
    postSideBySideBundleVerification,
  );
  const masterReportBundleBinding = nsisGhost.indexOf(
    "$masterReportBundleEntries = @(",
    masterReportExport,
  );
  const masterReportObservation = nsisGhost.indexOf(
    "$masterFrameworkReportObservation = [ordered]@{",
    masterReportBundleBinding,
  );
  const postUninstallSigningKeyReproof = nsisGhost.indexOf(
    "(Get-LowerSha256 $privateSigningKey (64 * 1024)) -cne $privateSigningKeySha256Before",
    nsisUninstall,
  );
  assert(
    signingIdentityAdoption >= 0 &&
      signingIdentityAdoption < candidateStart &&
      postSideBySideBundleVerification > candidateStart &&
      masterReportExport > postSideBySideBundleVerification &&
      masterReportBundleBinding > masterReportExport &&
      masterReportObservation > masterReportBundleBinding &&
      runtimePurge > masterReportObservation &&
      postUninstallSigningKeyReproof > nsisUninstall,
    "registered-WSL qualification must re-prove signing continuity and bind the master framework report after assm2 starts and before cleanup",
  );
  const explicitOldTeardown = nsisGhost.indexOf(
    "Unregister-ProvenExactWsl $trustedWsl $oldDistributionName $oldWslBasePath",
    nsisUninstall,
  );
  const explicitUnrelatedTeardown = nsisGhost.indexOf(
    "Unregister-ProvenExactWsl $trustedWsl $unrelatedDistributionName $unrelatedWslBasePath",
    explicitOldTeardown,
  );
  assert(
    runtimePurge >= 0 &&
      oldAfterPurge > runtimePurge &&
      unrelatedAfterPurge > oldAfterPurge &&
      nsisUninstall > unrelatedAfterPurge &&
      explicitOldTeardown > nsisUninstall &&
      explicitUnrelatedTeardown > explicitOldTeardown,
    "qualification teardown must occur only after current-runtime purge and NSIS data-preservation proofs",
  );

  const sentinelPhases = [
    "fixture_ready",
    "before_candidate_install",
    "after_candidate_install",
    "after_same_version_reinstall",
    "before_candidate_runtime_start",
    "after_candidate_runtime_running",
    "after_current_runtime_purge",
    "after_candidate_uninstall",
  ];
  const sentinelCheckpointFields = [
    "phase",
    "observedAt",
    "distributionName",
    "registrationId",
    "windowsClientPid",
    "windowsClientStartedAt",
    "linuxBootId",
    "linuxPid",
    "linuxStartTicks",
    "tokenSha256",
  ];
  const sentinelIdentityFields = sentinelCheckpointFields.slice(2);
  assertSourceStringArray(
    nsisGhost,
    "$sentinelLifecycleRequiredPhases = @(",
    ")",
    sentinelPhases,
    "registered-WSL qualification sentinel phases",
  );

  const sentinelFlowStart = nsisGhost.indexOf(
    "$oldSentinelLease = Start-WslSentinelLease",
    fixtureExport,
  );
  const sentinelFlowEnd = nsisGhost.indexOf("$observations = [ordered]@{", sentinelFlowStart);
  assert(
    sentinelFlowStart >= 0 && sentinelFlowEnd > sentinelFlowStart,
    "registered-WSL qualification has no bounded sentinel lifecycle execution section",
  );
  const sentinelFlow = nsisGhost.slice(sentinelFlowStart, sentinelFlowEnd);
  const observationsEnd = nsisGhost.indexOf("\n} catch {", sentinelFlowEnd);
  assert(observationsEnd > sentinelFlowEnd, "registered-WSL observations source is unbounded");
  const observationsSource = nsisGhost.slice(sentinelFlowEnd, observationsEnd);
  const runtimeSideBySideObservation = observationsSource.indexOf(
    "\n    runtimeSideBySide = [ordered]@{",
  );
  const nestedSentinelLifecycle = observationsSource.indexOf(
    "\n      sentinelLifecycle = [ordered]@{",
    runtimeSideBySideObservation,
  );
  const dataPreservationObservation = observationsSource.indexOf(
    "\n    dataPreservation = [ordered]@{",
    runtimeSideBySideObservation,
  );
  assert(
    runtimeSideBySideObservation >= 0 &&
      nestedSentinelLifecycle > runtimeSideBySideObservation &&
      dataPreservationObservation > nestedSentinelLifecycle &&
      (observationsSource.match(/^ {6}sentinelLifecycle = \[ordered\]@\{\r?$/gmu) ?? []).length === 1 &&
      !/^ {4}sentinelLifecycle = \[ordered\]@\{\r?$/mu.test(observationsSource),
    "sentinel lifecycle must be nested exactly once inside runtimeSideBySide before dataPreservation",
  );
  const checkpointEvents = [...sentinelFlow.matchAll(
    /Assert-WslSentinelLeaseCheckpoint\s+\$trustedWsl\s+\$(old|unrelated)SentinelLease\s+(?:\(\s*)?"([a-z_]+)"/gu,
  )].map((match) => ({
    lease: match[1],
    phase: match[2],
    index: sentinelFlowStart + match.index,
  }));
  const expectedCheckpointEvents = sentinelPhases.flatMap((phase) => [
    { lease: "old", phase },
    { lease: "unrelated", phase },
  ]);
  assert(
    JSON.stringify(checkpointEvents.map(({ lease, phase }) => ({ lease, phase }))) ===
      JSON.stringify(expectedCheckpointEvents),
    "registered-WSL qualification must capture both sentinel leases at exactly eight ordered phases",
  );
  const checkpointIndex = new Map(
    checkpointEvents.filter(({ lease }) => lease === "old").map(({ phase, index }) => [phase, index]),
  );
  const oldSentinelStart = sentinelFlowStart;
  const unrelatedSentinelStart = nsisGhost.indexOf(
    "$unrelatedSentinelLease = Start-WslSentinelLease",
    oldSentinelStart,
  );
  const firstCandidateInstall = nsisGhost.indexOf(
    'Invoke-ExactProcess $candidateInstallerPath @("/S") 180000 "Candidate bounded ghost NSIS migration"',
    sentinelFlowStart,
  );
  const secondCandidateInstall = nsisGhost.indexOf(
    'Invoke-ExactProcess $candidateInstallerPath @("/S") 180000 "Candidate same-version silent reinstall before ghost recovery"',
    firstCandidateInstall,
  );
  const candidateRuntimeStart = nsisGhost.indexOf(
    "$sideBySideProcess = Invoke-ExactProcess $candidateCli",
    secondCandidateInstall,
  );
  const candidateRunningProof = nsisGhost.indexOf(
    "Candidate assm2 workspace did not reach the released running runtime identity.",
    candidateRuntimeStart,
  );
  const lifecycleOrderProof = nsisGhost.indexOf(
    "foreach ($checkpointSet in @(",
    checkpointIndex.get("after_candidate_uninstall"),
  );
  const successStopOld = nsisGhost.indexOf(
    'Stop-WslSentinelLease $trustedWsl $oldSentinelLease "Legacy assm1 WSL qualification teardown"',
    lifecycleOrderProof,
  );
  const successStopUnrelated = nsisGhost.indexOf(
    'Stop-WslSentinelLease $trustedWsl $unrelatedSentinelLease "Unrelated WSL qualification teardown"',
    successStopOld,
  );
  assert(
    oldSentinelStart < unrelatedSentinelStart &&
      unrelatedSentinelStart < checkpointIndex.get("fixture_ready") &&
      checkpointIndex.get("fixture_ready") < checkpointIndex.get("before_candidate_install") &&
      checkpointIndex.get("before_candidate_install") < firstCandidateInstall &&
      firstCandidateInstall < checkpointIndex.get("after_candidate_install") &&
      checkpointIndex.get("after_candidate_install") < secondCandidateInstall &&
      secondCandidateInstall < checkpointIndex.get("after_same_version_reinstall") &&
      checkpointIndex.get("after_same_version_reinstall") < checkpointIndex.get("before_candidate_runtime_start") &&
      checkpointIndex.get("before_candidate_runtime_start") < candidateRuntimeStart &&
      candidateRuntimeStart < candidateRunningProof &&
      candidateRunningProof < checkpointIndex.get("after_candidate_runtime_running") &&
      checkpointIndex.get("after_candidate_runtime_running") < runtimePurge &&
      runtimePurge < checkpointIndex.get("after_current_runtime_purge") &&
      checkpointIndex.get("after_current_runtime_purge") < nsisUninstall &&
      nsisUninstall < checkpointIndex.get("after_candidate_uninstall") &&
      checkpointIndex.get("after_candidate_uninstall") < lifecycleOrderProof &&
      lifecycleOrderProof < successStopOld &&
      successStopOld < successStopUnrelated &&
      successStopUnrelated < explicitOldTeardown &&
      explicitOldTeardown < explicitUnrelatedTeardown,
    "sentinel checkpoints must surround both installs, runtime start, runtime purge, uninstall, and final teardown",
  );
  assert(
    (sentinelFlow.match(/Invoke-ExactProcess \$candidateInstallerPath @\("\/S"\)/gu) ?? []).length === 2 &&
      (sentinelFlow.match(/= Start-WslSentinelLease/gu) ?? []).length === 2,
    "registered-WSL qualification must run exactly two candidate installs under two retained sentinel leases",
  );
  const candidateSentinelSection = nsisGhost.slice(
    firstCandidateInstall,
    checkpointIndex.get("after_candidate_uninstall"),
  );
  assert(
    !candidateSentinelSection.includes("Start-WslSentinelLease") &&
      !candidateSentinelSection.includes("Stop-WslSentinelLease"),
    "candidate install/runtime/purge/uninstall must not restart or stop either retained sentinel lease",
  );
  for (const required of [
    "$legacySentinelCheckpoints = [Collections.Generic.List[object]]::new()",
    "$unrelatedSentinelCheckpoints = [Collections.Generic.List[object]]::new()",
    "$checkpointSet.Checkpoints.Count -ne $sentinelLifecycleRequiredPhases.Count",
    "$checkpointSet.Checkpoints[$checkpointIndex].phase -cne",
    "schemaVersion = 2",
    "sentinelLifecycle = [ordered]@{",
    "schemaVersion = 1",
    "requiredPhases = @($sentinelLifecycleRequiredPhases)",
    "legacyCheckpoints = @($legacySentinelCheckpoints | ForEach-Object { $_ })",
    "unrelatedCheckpoints = @($unrelatedSentinelCheckpoints | ForEach-Object { $_ })",
  ]) assert(nsisGhost.includes(required), "sentinel lifecycle observation source is missing: " + required);

  for (const required of [
    "windows_nsis_real_registered_wsl_n_minus_one_ghost_side_by_side",
    "const SCHEMA_VERSION = 2",
    "const SENTINEL_LIFECYCLE_SCHEMA_VERSION = 1",
    "SENTINEL_PHASES",
    '"fixture_ready"',
    '"before_candidate_install"',
    '"after_candidate_install"',
    '"after_same_version_reinstall"',
    '"before_candidate_runtime_start"',
    '"after_candidate_runtime_running"',
    '"after_current_runtime_purge"',
    '"after_candidate_uninstall"',
    "SENTINEL_CHECKPOINT_FIELDS",
    '"phase"',
    '"observedAt"',
    '"distributionName"',
    '"registrationId"',
    '"windowsClientPid"',
    '"windowsClientStartedAt"',
    '"linuxBootId"',
    '"linuxPid"',
    '"linuxStartTicks"',
    '"tokenSha256"',
    "SENTINEL_IDENTITY_FIELDS",
    "exactKeys(checkpoint, SENTINEL_CHECKPOINT_FIELDS",
    "checkpoints.length === SENTINEL_PHASES.length",
    "validateSentinelCheckpoints",
    "checkpoint.phase === SENTINEL_PHASES[index]",
    "observedAt >= previousObservedAt",
    "checkpoint.distributionName === expectedDistribution",
    "checkpoint.registrationId === expectedRegistration",
    "bounded(checkpoint.windowsClientPid, 1, 0xffffffff",
    "utcTimestampOrderKey(checkpoint.windowsClientStartedAt",
    "canonicalUuid(checkpoint.linuxBootId",
    "bounded(checkpoint.linuxPid, 1, 0x7fffffff",
    "canonicalPositiveDecimal(checkpoint.linuxStartTicks",
    "sha256(checkpoint.tokenSha256",
    "JSON.stringify(identity) === JSON.stringify(baselineIdentity)",
    "validateSentinelLifecycle",
    '["schemaVersion", "requiredPhases", "legacyCheckpoints", "unrelatedCheckpoints"]',
    "lifecycle.schemaVersion === SENTINEL_LIFECYCLE_SCHEMA_VERSION",
    "JSON.stringify(lifecycle.requiredPhases) === JSON.stringify(SENTINEL_PHASES)",
    "JSON.stringify(legacyIdentity) !== JSON.stringify(unrelatedIdentity)",
    "legacy and unrelated sentinels share one token identity",
    "legacy and unrelated sentinels share one Windows client process",
    "runtimeSideBySide",
    '"sentinelLifecycle"',
    "CURRENT_MACHINE",
    "CURRENT_DISTRIBUTION",
    "legacyRegistrationIdBefore",
    "legacyRegistrationIdAfter",
    "unrelatedRegistrationIdBefore",
    "unrelatedRegistrationIdAfter",
    "retainedProof",
    "authorizesCleanup === false",
    "ai-security-scanner.managed-wsl-legacy-workspace-retained/v1",
    "transitionEvidenceSource",
    "nsis_install_transition",
    "proofAbsentWhileRegistryReceiptPresent",
    "proofValidatedBeforeRegistryAbsenceCheck",
    "registryValueAbsentAfterDurableProof",
    "masterFrameworkReport",
    "nist_csf",
    "iso_iec_27001",
    "aidefend",
    "legacy_key_adopted",
    "validateWindowsNsisGhostRecoveryEvidenceFile",
  ]) assert(nsisGhostEvidence.includes(required), "registered-WSL side-by-side evidence contract is missing: " + required);
  assertSourceStringArray(
    nsisGhostEvidence,
    "const SENTINEL_PHASES = Object.freeze([",
    "]);",
    sentinelPhases,
    "registered-WSL evidence sentinel phases",
  );
  assertSourceStringArray(
    nsisGhostEvidence,
    "const SENTINEL_CHECKPOINT_FIELDS = Object.freeze([",
    "]);",
    sentinelCheckpointFields,
    "registered-WSL evidence sentinel checkpoint fields",
  );
  assertSourceStringArray(
    nsisGhostEvidence,
    "const SENTINEL_IDENTITY_FIELDS = Object.freeze([",
    "]);",
    sentinelIdentityFields,
    "registered-WSL evidence sentinel identity fields",
  );
  for (const obsolete of [
    "legacySentinelProcessSurvived",
    "unrelatedSentinelProcessSurvived",
    "unrelatedDistributionRunning",
  ]) assert(!nsisGhostEvidence.includes(obsolete), "registered-WSL evidence retains obsolete sentinel evidence: " + obsolete);

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
    "ghost evidence that turns retention into cleanup authority",
    "ghost evidence with a lost same-version transition receipt",
    "ghost evidence with an unconsumed registry receipt",
    "ghost evidence with a mutated retained proof",
    "ghost evidence with an incomplete retained proof",
    "ghost evidence with a missing required sentinel lifecycle phase",
    "ghost evidence with a missing sentinel checkpoint phase",
    "ghost evidence with reordered sentinel checkpoints",
    "ghost evidence whose Linux sentinel PID changes",
    "ghost evidence whose Linux sentinel start ticks change",
    "ghost evidence whose Windows sentinel client PID changes",
    "ghost evidence whose Windows sentinel client start time changes",
    "ghost evidence whose distinct WSL sentinel leases share one token identity",
    "ghost evidence whose distinct WSL sentinel leases share one Windows client identity",
    "legacy ghost evidence with booleans instead of sentinel lifecycle checkpoints",
    "lifecycle.requiredPhases.splice(3, 1)",
    "lifecycle.unrelatedCheckpoints.splice(4, 1)",
    "[lifecycle.legacyCheckpoints[2], lifecycle.legacyCheckpoints[3]]",
    "lifecycle.legacyCheckpoints[5].linuxPid += 1",
    'lifecycle.legacyCheckpoints[5].linuxStartTicks = "123456791"',
    "lifecycle.unrelatedCheckpoints[6].windowsClientPid += 1",
    "lifecycle.unrelatedCheckpoints[6].windowsClientStartedAt =",
    "for (const checkpoint of lifecycle.unrelatedCheckpoints) checkpoint.tokenSha256 = sharedToken",
    "checkpoint.windowsClientPid = legacy.windowsClientPid",
    "checkpoint.windowsClientStartedAt = legacy.windowsClientStartedAt",
    "sentinelLifecycle",
    "legacyCheckpoints",
    "unrelatedCheckpoints",
    "windows-nsis-upgrade-qualification.json",
    "windows-nsis-ghost-recovery-qualification.json",
    'schema_version: "3"',
    'management_contract_revision: "2026-08-29.1"',
    "release metadata with a mismatched publication mode",
    "commit-bound GitHub Actions QC artifact, not a public GitHub Release",
    "public GitHub artifact attestation before installing",
  ]) assert(selfTest.includes(required), `release self-test is missing Windows migration coverage: ${required}`);
  assertSourceStringArray(
    selfTest,
    "const sentinelPhases = [",
    "];",
    sentinelPhases,
    "release self-test sentinel phases",
  );
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
    "const WINDOWS_WSL_VHD_RELEASE_TIMEOUT: Duration = MACHINE_STOP_TIMEOUT;",
    "verify_windows_wsl_recovery_vhd_with_timing",
    "windows_directory_guards_block_replacement_until_release",
    "windows_wsl_vhd_verification_waits_for_exact_read_holder_release",
    "windows_wsl_vhd_verification_blocks_writers_and_deleters_while_guarded",
    "windows_wsl_vhd_observation_allows_live_writers_and_blocks_replacement",
    "windows_wsl_vhd_verification_waits_for_exact_writer_release",
    "windows_wsl_vhd_writer_timeout_is_typed_and_preserves_the_file",
    "n_minus_one_vhd_release_reproof_rejects_a_rebound_distribution_before_export",
    "n_minus_one_vhd_timeout_preserves_the_full_recovery_checkpoint",
    "uncheckpointed_quarantine_without_a_vhd_is_exactly_unregistered",
    "current_windows_compatibility_generation_match_is_exact_and_bounded",
    "full_setup_with_pending_assm2_checkpoint_fails_closed_without_name_based_wsl_mutation",
    "uninstall_waits_for_exact_windows_wsl_vhd_release",
    "uninstall_provider_attribute_open_timeout_retains_install_and_image_cache",
  ]) {
    assert(
      managedRuntime.includes(required),
      `managed runtime execution contract is missing: ${required}`,
    );
  }
  const directWslUnregister = 'OsString::from("--unregister")';
  const managedRuntimeProduction = managedRuntime.split("\n#[cfg(test)]\nmod tests {")[0];
  assert(
    !managedRuntimeProduction.includes('OsString::from("--shutdown")') &&
      !managedRuntimeProduction.includes('.arg("--shutdown")'),
    "managed runtime must not globally stop unrelated Windows WSL distributions",
  );
  const boundedRecoverySection = (start, end, label) => {
    const startIndex = managedRuntimeProduction.indexOf(start);
    const endIndex = managedRuntimeProduction.indexOf(end, startIndex + start.length);
    assert(startIndex !== -1 && endIndex > startIndex, `managed runtime is missing ${label}`);
    return managedRuntimeProduction.slice(startIndex, endIndex);
  };
  const unregisterCount = (source) => source.split(directWslUnregister).length - 1;
  const currentGenerationPredicate = boundedRecoverySection(
    "fn windows_machine_uses_current_compatibility_generation",
    "fn machine_name(target: &ManagedTarget)",
    "current Windows compatibility-generation predicate",
  );
  assert(
    currentGenerationPredicate.includes("strip_prefix(WINDOWS_MACHINE_PREFIX)") &&
      currentGenerationPredicate.includes("suffix.strip_prefix('-')") &&
      currentGenerationPredicate.includes("!suffix.is_empty()"),
    "current Windows compatibility generation must use an exact, non-empty assm2 namespace prefix",
  );
  const currentDistributionAbsenceProof = boundedRecoverySection(
    "fn prove_windows_wsl_distribution_absent_locked",
    "fn windows_wsl_distribution_inventory",
    "current Windows distribution absence proof",
  );
  const absenceCurrentGuard = currentDistributionAbsenceProof.indexOf(
    "if windows_machine_uses_current_compatibility_generation(machine_name)",
  );
  const absenceManualFailure = currentDistributionAbsenceProof.indexOf(
    "return fail_windows_wsl_distribution_requires_manual_action",
    absenceCurrentGuard,
  );
  const absenceLegacyRecovery = currentDistributionAbsenceProof.indexOf(
    "self.recover_windows_wsl_distribution_locked",
  );
  assert(
    absenceCurrentGuard !== -1 &&
      absenceManualFailure > absenceCurrentGuard &&
      absenceLegacyRecovery > absenceManualFailure,
    "current assm2 collision/pending state must fail closed before legacy WSL recovery",
  );
  assert(
    managedRuntimeProduction.split("self.recover_windows_wsl_distribution_locked(").length - 1 ===
      1,
    "legacy Windows WSL recovery must retain one guarded production caller",
  );
  for (const forbidden of [
    "ManagedCommandOperation::MachineInitialization",
    "ManagedCommandOperation::MachineStop",
    "ManagedCommandOperation::MachineRemoval",
    "ManagedCommandOperation::WslDistributionTerminate",
    "ManagedCommandOperation::WslDistributionExport",
    "ManagedCommandOperation::WslDistributionImport",
    "ManagedCommandOperation::WslDistributionRemoval",
    'OsString::from("--shutdown")',
  ]) {
    assert(
      !currentDistributionAbsenceProof.slice(0, absenceLegacyRecovery).includes(forbidden),
      `current assm2 absence proof contains a pre-guard destructive edge: ${forbidden}`,
    );
  }
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
  const interruptedReplacementStart = handoffRecovery.indexOf(
    "if interrupted_replacement_present {",
  );
  const interruptedReplacementEnd = handoffRecovery.indexOf(
    "\n        if original_present {",
    interruptedReplacementStart,
  );
  assert(
    interruptedReplacementStart !== -1 && interruptedReplacementEnd > interruptedReplacementStart,
    "Windows WSL handoff has no bounded interrupted-replacement branch",
  );
  const interruptedReplacement = handoffRecovery.slice(
    interruptedReplacementStart,
    interruptedReplacementEnd,
  );
  const interruptedTerminate = interruptedReplacement.indexOf(
    "ManagedCommandOperation::WslDistributionTerminate",
  );
  const interruptedVhdReproof = interruptedReplacement.indexOf(
    "self.verify_current_windows_wsl_machine_registration(machine_name)?",
  );
  const interruptedUnregister = interruptedReplacement.indexOf(
    "ManagedCommandOperation::WslDistributionRemoval",
  );
  assert(
    interruptedTerminate !== -1 &&
      interruptedVhdReproof > interruptedTerminate &&
      interruptedUnregister > interruptedVhdReproof,
    "interrupted Windows replacement must re-prove the exact current registration and VHD after terminate and before unregister",
  );
  const originalReplacementStart = interruptedReplacementEnd + 1;
  const originalReplacementEnd = handoffRecovery.indexOf(
    "\n        let original_present = distributions",
    originalReplacementStart,
  );
  assert(
    originalReplacementEnd > originalReplacementStart,
    "Windows WSL handoff has no bounded original-replacement branch",
  );
  const originalReplacement = handoffRecovery.slice(
    originalReplacementStart,
    originalReplacementEnd,
  );
  const originalTerminate = originalReplacement.indexOf(
    "ManagedCommandOperation::WslDistributionTerminate",
  );
  const originalVhdReproof = originalReplacement.indexOf(
    "self.verify_pending_windows_wsl_registration(&intent)?",
  );
  const originalUnregister = originalReplacement.indexOf(
    "ManagedCommandOperation::WslDistributionRemoval",
  );
  assert(
    originalTerminate !== -1 &&
      originalVhdReproof > originalTerminate &&
      originalUnregister > originalVhdReproof,
    "original Windows workspace replacement must re-prove the exact pending registration and VHD after terminate and before unregister",
  );
  const firstHandoffTerminate = handoffRecovery.indexOf(
    "ManagedCommandOperation::WslDistributionTerminate",
  );
  const firstHandoffVhdProof = handoffRecovery.indexOf(
    "let source_vhd = self.verify_pending_windows_wsl_registration",
  );
  const firstHandoffFreeSpace = handoffRecovery.indexOf(
    "require_windows_wsl_recovery_free_space",
  );
  const firstHandoffExport = handoffRecovery.indexOf(
    "ManagedCommandOperation::WslDistributionExport",
  );
  assert(
    firstHandoffTerminate !== -1 &&
      firstHandoffTerminate < firstHandoffVhdProof &&
      firstHandoffVhdProof < firstHandoffFreeSpace &&
      firstHandoffFreeSpace < firstHandoffExport &&
      handoffRecovery.includes("source_vhd.size") &&
      !handoffRecovery.includes(
        'fs::symlink_metadata(intent.registration_base_path.join("ext4.vhdx"))',
      ),
    "Windows WSL handoff must terminate, prove VHD release, check space, then export",
  );
  const recoveryFreeSpace = boundedRecoverySection(
    "fn require_windows_wsl_recovery_free_space",
    "fn require_windows_wsl_recovery_import_space",
    "Windows WSL recovery free-space check",
  );
  assert(
    recoveryFreeSpace.includes("source_vhd_size: u64") &&
      !recoveryFreeSpace.includes("symlink_metadata") &&
      !recoveryFreeSpace.includes("source_vhd: &Path"),
    "Windows WSL free-space check must use the already verified VHD snapshot",
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
  const incompleteTerminate = incompleteImportCleanup.indexOf(
    "ManagedCommandOperation::WslDistributionTerminate",
  );
  const incompleteReproof = incompleteImportCleanup.lastIndexOf(
    "verify_windows_wsl_quarantine_registration_path(intent)?",
  );
  const incompleteUnregister = incompleteImportCleanup.indexOf(
    "ManagedCommandOperation::WslDistributionRemoval",
  );
  assert(
    incompleteTerminate !== -1 &&
      incompleteReproof > incompleteTerminate &&
      incompleteUnregister > incompleteReproof,
    "incomplete Windows WSL import cleanup must re-prove its exact registration path after terminate and before unregister without requiring a completed VHD",
  );
  const completedRecoveryCleanup = boundedRecoverySection(
    "fn complete_windows_wsl_recovery_locked",
    "fn windows_wsl_ownership_proof_path",
    "bounded completed Windows WSL recovery cleanup",
  );
  const completionCurrentGuard = completedRecoveryCleanup.indexOf(
    "if windows_machine_uses_current_compatibility_generation(machine_name)",
  );
  const completionCurrentPending = completedRecoveryCleanup.indexOf(
    "if private_entry_exists(&pending)?",
    completionCurrentGuard,
  );
  const completionCurrentManual = completedRecoveryCleanup.indexOf(
    "return fail_windows_wsl_distribution_requires_manual_action",
    completionCurrentPending,
  );
  const completionCurrentOk = completedRecoveryCleanup.indexOf(
    "return Ok(());",
    completionCurrentManual,
  );
  const completionLegacyPending = completedRecoveryCleanup.indexOf(
    "if private_entry_exists(&pending)?",
    completionCurrentOk + 1,
  );
  assert(
    completionCurrentGuard !== -1 &&
      completionCurrentPending > completionCurrentGuard &&
      completionCurrentManual > completionCurrentPending &&
      completionCurrentOk > completionCurrentManual &&
      completionLegacyPending > completionCurrentOk,
    "completed recovery must fail current assm2 pending state closed before the legacy branch",
  );
  const completionCurrentFailClosed = completedRecoveryCleanup.slice(
    0,
    completionLegacyPending,
  );
  for (const forbidden of [
    "windows_wsl_distribution_inventory",
    "read_windows_wsl_recovery_intent_locked",
    "ManagedCommandOperation::WslDistributionTerminate",
    "ManagedCommandOperation::WslDistributionExport",
    "ManagedCommandOperation::WslDistributionImport",
    "ManagedCommandOperation::WslDistributionRemoval",
    "remove_regular_file(&pending)",
    'OsString::from("--shutdown")',
  ]) {
    assert(
      !completionCurrentFailClosed.includes(forbidden),
      `current assm2 completion reaches a name-based recovery edge before failing closed: ${forbidden}`,
    );
  }
  assert(
    unregisterCount(completedRecoveryCleanup) === 1 &&
      completedRecoveryCleanup.includes("verify_windows_wsl_recovery_archive") &&
      completedRecoveryCleanup.includes("verify_windows_wsl_quarantine_registration"),
    "completed Windows WSL recovery cleanup is not bound to the verified recovery copy",
  );
  const completedQuarantineStart = completedRecoveryCleanup.indexOf(
    "if quarantine_present {",
  );
  const completedQuarantineEnd = completedRecoveryCleanup.indexOf(
    "            } else {",
    completedQuarantineStart,
  );
  assert(
    completedQuarantineStart !== -1 && completedQuarantineEnd > completedQuarantineStart,
    "completed Windows WSL recovery has no bounded quarantine-cleanup branch",
  );
  const completedQuarantine = completedRecoveryCleanup.slice(
    completedQuarantineStart,
    completedQuarantineEnd,
  );
  const completedQuarantineTerminate = completedQuarantine.indexOf(
    "ManagedCommandOperation::WslDistributionTerminate",
  );
  const completedQuarantineArchive = completedQuarantine.indexOf(
    "self.verify_windows_wsl_recovery_archive(",
    completedQuarantineTerminate,
  );
  const completedQuarantineVhd = completedQuarantine.indexOf(
    "self.verify_windows_wsl_quarantine_registration(&intent)?",
    completedQuarantineArchive,
  );
  const completedQuarantineUnregister = completedQuarantine.indexOf(
    "ManagedCommandOperation::WslDistributionRemoval",
  );
  assert(
    completedQuarantineTerminate !== -1 &&
      completedQuarantineArchive > completedQuarantineTerminate &&
      completedQuarantineVhd > completedQuarantineArchive &&
      completedQuarantineUnregister > completedQuarantineVhd,
    "completed quarantine cleanup must verify the archive and exact quarantine registration/VHD after terminate and before unregister",
  );
  const boundedVhdRelease = boundedRecoverySection(
    "fn verify_windows_wsl_recovery_vhd_with_timing",
    "#[cfg(not(windows))]\nfn verify_windows_wsl_recovery_vhd_with_timing",
    "bounded Windows WSL VHD release proof",
  );
  const realDirectoryGuard = boundedRecoverySection(
    "fn open_windows_real_directory_security_handle",
    "fn verify_windows_managed_namespace_ancestor_chain",
    "Windows real-directory share guard",
  );
  const managedDirectoryGuard = boundedRecoverySection(
    "fn open_or_create_windows_managed_directory_guard",
    "fn ensure_windows_managed_private_directory",
    "Windows managed-directory share guard",
  );
  for (const [section, label] of [
    [realDirectoryGuard, "real-directory"],
    [managedDirectoryGuard, "managed-directory"],
  ]) {
    assert(
      section.includes("FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL,") &&
        section.includes("FILE_SHARE_READ | FILE_SHARE_WRITE,") &&
        section.includes("FILE_FLAG_OPEN_REPARSE_POINT"),
      `Windows ${label} guard must use a directory read-category share lock and open no-follow`,
    );
  }
  const vhdQuiescenceGuard = boundedRecoverySection(
    "fn open_windows_wsl_vhd_quiescence_guard",
    "fn open_windows_wsl_vhd_observation_guard",
    "Windows WSL VHD quiescence guard",
  );
  assert(
    vhdQuiescenceGuard.includes("CreateFileW") &&
      vhdQuiescenceGuard.includes("            FILE_READ_DATA,") &&
      vhdQuiescenceGuard.includes("            FILE_SHARE_READ,") &&
      vhdQuiescenceGuard.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
      vhdQuiescenceGuard.includes("File::from_raw_handle") &&
      !vhdQuiescenceGuard.includes("FILE_SHARE_WRITE") &&
      !vhdQuiescenceGuard.includes("FILE_SHARE_DELETE") &&
      !vhdQuiescenceGuard.includes("FILE_GENERIC_READ") &&
      !vhdQuiescenceGuard.includes(".read(true)") &&
      !vhdQuiescenceGuard.includes(".write(true)"),
    "Windows WSL VHD guard must request minimum read access, share read only, open no-follow, and retain the exact handle",
  );
  const vhdObservationGuard = boundedRecoverySection(
    "fn open_windows_wsl_vhd_observation_guard",
    "fn open_windows_managed_ssh_cleanup_file",
    "Windows WSL VHD observation guard",
  );
  assert(
    vhdObservationGuard.includes("CreateFileW") &&
      vhdObservationGuard.includes("            FILE_READ_DATA,") &&
      vhdObservationGuard.includes("FILE_SHARE_READ | FILE_SHARE_WRITE") &&
      vhdObservationGuard.includes("FILE_FLAG_OPEN_REPARSE_POINT") &&
      vhdObservationGuard.includes("File::from_raw_handle") &&
      !vhdObservationGuard.includes("FILE_SHARE_DELETE") &&
      !vhdObservationGuard.includes("FILE_GENERIC_READ") &&
      !vhdObservationGuard.includes(".read(true)") &&
      !vhdObservationGuard.includes(".write(true)"),
    "retained Windows WSL VHD observation must allow a live writer while denying replacement with minimum read access",
  );
  const retainedLegacyRecorder = boundedRecoverySection(
    "fn record_bounded_windows_legacy_workspace_retained",
    "fn record_bounded_windows_ghost_migration_consumed",
    "bounded Windows retained-legacy recorder",
  );
  for (const required of [
    "WINDOWS_GHOST_MIGRATION_CURRENT_MACHINE_NAME",
    "legacy_registrations.len() != 1",
    "legacy_registration.registration_id",
    "windows_wsl_legacy_retained_path",
    "verify_current_windows_wsl_machine_registration_binding",
    "exact_bounded_windows_legacy_pending_evidence",
    "open_windows_wsl_vhd_observation_guard",
    "legacy_provider_config_sha256",
    "legacy_ssh_public_key_sha256",
    "legacy_vhd_volume_serial_number",
    "authorizes_cleanup: false",
    "write_private_atomic(&retained_path, &encoded)?",
    "let persisted: WindowsWslLegacyWorkspaceRetainedProof",
    "persisted != proof",
    "consume_install_transition(&installation, &install_transition_receipt)",
  ]) {
    assert(
      retainedLegacyRecorder.includes(required),
      `bounded retained-legacy recorder is missing: ${required}`,
    );
  }
  for (const forbidden of [
    "ManagedCommandOperation::MachineInitialization",
    "ManagedCommandOperation::MachineStop",
    "ManagedCommandOperation::MachineRemoval",
    "ManagedCommandOperation::WslDistributionTerminate",
    "ManagedCommandOperation::WslDistributionExport",
    "ManagedCommandOperation::WslDistributionImport",
    "ManagedCommandOperation::WslDistributionRemoval",
    'OsString::from("--shutdown")',
    "remove_provider_home_after_machine_removal",
  ]) {
    assert(
      !retainedLegacyRecorder.includes(forbidden),
      `observation-only retained-legacy recorder contains a destructive edge: ${forbidden}`,
    );
  }
  assertOrderedTokens(
    retainedLegacyRecorder,
    [
      "write_private_atomic(&retained_path, &encoded)?",
      "let persisted: WindowsWslLegacyWorkspaceRetainedProof",
      "if persisted != proof",
      "consume_install_transition(&installation, &install_transition_receipt)",
    ],
    "durable retained-legacy proof before NSIS receipt consumption",
  );
  const nonblockingLegacyRecorder = boundedRecoverySection(
    "fn retain_bounded_windows_legacy_workspace_nonblocking",
    "fn validate_windows_wsl_legacy_workspace_retained_proof",
    "nonblocking Windows retained-legacy wrapper",
  );
  assert(
    nonblockingLegacyRecorder.includes(
      "let _ =\n                self.record_bounded_windows_legacy_workspace_retained",
    ),
    "unclassifiable assm1 state must remain nonblocking after assm2 is live",
  );
  const startLocked = boundedRecoverySection(
    "fn start_locked",
    "fn require_windows_wsl_prerequisite_locked",
    "managed runtime start lifecycle",
  );
  assertOrderedTokens(
    startLocked,
    [
      "self.wait_for_server(&command, MACHINE_START_TIMEOUT, setup)?",
      "self.complete_windows_wsl_recovery_locked",
      "self.retain_bounded_windows_legacy_workspace_nonblocking",
      "Ok(command)",
    ],
    "assm2 preflight before nonblocking legacy observation",
  );
  const machineNaming = boundedRecoverySection(
    "fn machine_name(target: &ManagedTarget)",
    "fn installation_directory_name",
    "managed runtime machine naming",
  );
  assert(
    managedRuntime.includes('const WINDOWS_MACHINE_PREFIX: &str = "assm2";') &&
      managedRuntime.includes(
        'const WINDOWS_GHOST_MIGRATION_CURRENT_MACHINE_NAME: &str = "assm2-win-x64-e2b6cbcadd8b";',
      ) &&
      machineNaming.includes("ManagedOperatingSystem::Windows") &&
      machineNaming.includes("WINDOWS_MACHINE_PREFIX"),
    "Windows runtime compatibility generation must remain explicitly pinned to assm2",
  );
  const atomicPrivateCommit = boundedRecoverySection(
    "fn commit_private_atomic_rename",
    "fn remove_regular_file",
    "durable private-file atomic commit",
  );
  assert(
    atomicPrivateCommit.includes("MoveFileExW") &&
      atomicPrivateCommit.includes("MOVEFILE_WRITE_THROUGH") &&
      managedRuntime.includes("commit_private_atomic_rename(&temporary, path)?"),
    "Windows retained proof must use a write-through atomic namespace commit",
  );
  assert(
    boundedVhdRelease.includes("windows_error_is_sharing_violation") &&
      boundedVhdRelease.includes("checked_add(timeout)") &&
      boundedVhdRelease.includes("thread::sleep") &&
      boundedVhdRelease.includes("open_windows_wsl_vhd_quiescence_guard") &&
      boundedVhdRelease.includes("validate_windows_wsl_recovery_file_information") &&
      boundedVhdRelease.includes("AppError::Runtime") &&
      boundedVhdRelease.includes("retaining the exact registration and recovery checkpoint") &&
      boundedVhdRelease.includes("last_sharing_error") &&
      (boundedVhdRelease.match(/verify_registration_base_path\(\)\?/gu) ?? []).length === 2 &&
      boundedVhdRelease.includes(
        "let rebound_base_path = verify_registration_base_path()?",
      ) &&
      boundedVhdRelease.includes("windows_paths_refer_to_same_location") &&
      boundedVhdRelease.includes("rebound_information != information"),
    "Windows WSL VHD proof does not use one bounded sharing-violation-only wait with per-retry and post-open binding/identity reproof",
  );
  const vhdDeadline = boundedVhdRelease.indexOf("checked_add(timeout)");
  const vhdLoop = boundedVhdRelease.indexOf("    loop {");
  const vhdBaseProof = boundedVhdRelease.indexOf(
    "let base_path = verify_registration_base_path()?",
  );
  const vhdFirstOpen = boundedVhdRelease.indexOf(
    "open_windows_wsl_vhd_quiescence_guard(&path)",
  );
  const vhdSharingBranch = boundedVhdRelease.indexOf(
    "Err(error) if windows_error_is_sharing_violation(&error)",
  );
  const vhdRememberSharing = boundedVhdRelease.indexOf(
    "last_sharing_error = Some(error.to_string())",
    vhdSharingBranch,
  );
  const vhdSleep = boundedVhdRelease.indexOf("thread::sleep", vhdRememberSharing);
  const vhdContinue = boundedVhdRelease.indexOf("continue;", vhdSleep);
  const vhdPostOpenProof = boundedVhdRelease.indexOf(
    "let rebound_base_path = verify_registration_base_path()?",
  );
  const vhdReboundOpen = boundedVhdRelease.indexOf(
    "open_windows_wsl_vhd_quiescence_guard(&rebound_path)",
  );
  const vhdIdentityComparison = boundedVhdRelease.indexOf(
    "rebound_information != information",
  );
  const vhdReturn = boundedVhdRelease.indexOf("return Ok(snapshot)");
  assert(
    vhdDeadline !== -1 &&
      vhdLoop > vhdDeadline &&
      vhdBaseProof > vhdLoop &&
      vhdFirstOpen > vhdBaseProof &&
      vhdSharingBranch > vhdFirstOpen &&
      vhdRememberSharing > vhdSharingBranch &&
      vhdSleep > vhdRememberSharing &&
      vhdContinue > vhdSleep &&
      vhdPostOpenProof > vhdContinue &&
      vhdReboundOpen > vhdPostOpenProof &&
      vhdIdentityComparison > vhdReboundOpen &&
      vhdReturn > vhdIdentityComparison,
    "Windows WSL VHD release loop must bind before each open, retry only sharing violations under one deadline, then rebind and compare exact VHD identity before returning",
  );
  const pendingVhdProof = boundedRecoverySection(
    "fn verify_pending_windows_wsl_registration(",
    "fn verify_pending_windows_wsl_registration_binding(",
    "pending Windows WSL registration VHD proof",
  );
  const currentVhdProof = boundedRecoverySection(
    "fn verify_current_windows_wsl_machine_registration(",
    "fn verify_current_windows_wsl_machine_registration_binding(",
    "current Windows WSL registration VHD proof",
  );
  const quarantineVhdProof = boundedRecoverySection(
    "fn verify_windows_wsl_quarantine_registration(",
    "fn verify_windows_wsl_quarantine_registration_path(",
    "quarantine Windows WSL registration VHD proof",
  );
  assert(
    pendingVhdProof.includes("windows_wsl_vhd_release_timing") &&
      pendingVhdProof.includes("verify_windows_wsl_recovery_vhd_with_timing(") &&
      pendingVhdProof.includes("verify_pending_windows_wsl_registration_binding(intent)") &&
      pendingVhdProof.includes(".map(|(base_path, _)| base_path)"),
    "pending Windows WSL VHD proof does not re-run the exact pending ownership/receipt binding on every helper invocation",
  );
  assert(
    currentVhdProof.includes("windows_wsl_vhd_release_timing") &&
      currentVhdProof.includes("verify_windows_wsl_recovery_vhd_with_timing(") &&
      currentVhdProof.includes(
        "|| self.verify_current_windows_wsl_machine_registration_binding(machine_name)",
      ),
    "current Windows WSL VHD proof does not re-run the exact current product binding on every helper invocation",
  );
  assert(
    quarantineVhdProof.includes("windows_wsl_vhd_release_timing") &&
      quarantineVhdProof.includes("verify_windows_wsl_quarantine_storage(") &&
      quarantineVhdProof.includes(
        "|| self.verify_windows_wsl_quarantine_registration_path(intent)",
      ),
    "quarantine Windows WSL VHD proof does not re-run the exact quarantine binding on every helper invocation",
  );
  const quarantineStorage = boundedRecoverySection(
    "fn verify_windows_wsl_quarantine_storage",
    "#[cfg(windows)]\nfn verify_windows_wsl_recovery_vhd_with_timing",
    "Windows WSL quarantine storage proof",
  );
  assert(
    quarantineStorage.includes(
      "verify_windows_wsl_recovery_vhd_with_timing(verify_registration_base_path, timeout, poll)",
    ),
    "Windows WSL quarantine storage does not share the bounded VHD release proof",
  );
  const providerMetadataRetry = boundedRecoverySection(
    "fn windows_private_entry_metadata_with_policy",
    "fn remove_windows_private_file",
    "bounded Windows provider metadata release wait",
  );
  const providerFileDelete = boundedRecoverySection(
    "fn remove_windows_private_file",
    "fn set_windows_entry_readonly_nofollow",
    "bounded Windows provider file deletion",
  );
  assert(
    providerMetadataRetry.includes("wait_for_windows_private_file_release_if_allowed") &&
      providerFileDelete.split("wait_for_windows_private_file_release_if_allowed").length - 1 ===
        2,
    "Windows provider metadata, attribute-open, and delete paths do not share one bounded deadline",
  );
  const windowsTestSection = (name) => {
    const marker = `    #[cfg(windows)]\n    #[test]\n    fn ${name}()`;
    const start = managedRuntime.indexOf(marker);
    const end = managedRuntime.indexOf("\n    #[cfg(windows)]\n    #[test]", start + marker.length);
    assert(start !== -1 && end > start, `managed runtime is missing the real Windows test ${name}`);
    return managedRuntime.slice(start, end);
  };
  const directoryGuardTest = windowsTestSection(
    "windows_directory_guards_block_replacement_until_release",
  );
  for (const required of [
    "open_windows_real_directory_security_handle(&directory)",
    'expect("a second read-category guard remains compatible")',
    ".access_mode(FILE_TRAVERSE | DELETE)",
    'expect_err("the real-directory guard must reject delete access")',
    "windows_error_is_sharing_violation",
    "assert!(fs::rename(&directory, &renamed).is_err());",
    "drop(compatible_guard);",
    "drop(guard);",
    'fs::rename(&directory, &renamed).expect("rename after real-directory guard release")',
    "open_or_create_windows_managed_private_directory_guard(&managed, false)",
    "assert!(fs::rename(&managed, &managed_renamed).is_err());",
    "drop(managed_guard);",
    'expect("rename after managed-directory guard release")',
  ]) {
    assert(
      directoryGuardTest.includes(required),
      `Windows directory share-guard test is missing: ${required}`,
    );
  }
  const vhdReaderTest = windowsTestSection(
    "windows_wsl_vhd_verification_waits_for_exact_read_holder_release",
  );
  const pendingAssm2FullSetupTest = windowsTestSection(
    "full_setup_with_pending_assm2_checkpoint_fails_closed_without_name_based_wsl_mutation",
  );
  for (const required of [
    "current_verified_pending_fixture()",
    "machine_json(&fixture.manager, true)",
    'expect_err("pending assm2 recovery must fail closed")',
    "ManagedRuntimeSetupFailureReason::WslDistributionRequiresManualAction",
    "ManagedRuntimeSetupNextAction::ResolveWslDistributionManually",
    '"--terminate" | "--export" | "--import" | "--unregister" | "--shutdown"',
    "pending assm2 state changed",
    "windows_wsl_ghost_migration_consumed_path",
  ]) {
    assert(
      pendingAssm2FullSetupTest.includes(required),
      `pending assm2 full-setup fail-closed test is missing: ${required}`,
    );
  }
  assertOrderedTokens(
    vhdReaderTest,
    [
      'let base_path = versions_root.join("exclusive-reader");',
      'let vhd = base_path.join("ext4.vhdx");',
      "let read_holder = open_without_windows_sharing(&vhd);",
      "let started = Instant::now();",
      "let release = thread::spawn(move || {",
      "verify_windows_wsl_recovery_vhd_with_timing(",
      'expect("VHD proof resumes after the exact reader is released")',
      'release.join().expect("release fixture VHD reader")',
      "assert_eq!(snapshot.size, expected_size);",
      "assert!(started.elapsed() >= Duration::from_millis(250));",
    ],
    "Windows exact-reader release-wait test",
  );
  const vhdGuardTest = windowsTestSection(
    "windows_wsl_vhd_verification_blocks_writers_and_deleters_while_guarded",
  );
  for (const required of [
    "open_windows_wsl_vhd_quiescence_guard(&vhd)",
    'expect("the guard still permits a reader")',
    'expect_err("the guard must reject a writer")',
    'expect_err("the guard must reject delete access")',
    "windows_error_is_sharing_violation",
    "assert!(fs::rename(&vhd, &renamed).is_err());",
    "drop(guard);",
    'fs::rename(&vhd, &renamed).expect("rename after guard release")',
  ]) {
    assert(vhdGuardTest.includes(required), `Windows VHD guard test is missing: ${required}`);
  }
  const vhdObservationTest = windowsTestSection(
    "windows_wsl_vhd_observation_allows_live_writers_and_blocks_replacement",
  );
  for (const required of [
    "open_windows_writer_with_full_sharing(&vhd)",
    "open_windows_wsl_vhd_observation_guard(&vhd)",
    'expect("observe a VHD that already has a fully shared writer")',
    'expect("the existing live writer remains usable")',
    "let concurrent_writer = open_windows_writer_with_full_sharing(&vhd);",
    'expect_err("the observation guard must reject delete access")',
    "windows_error_is_sharing_violation",
    "assert!(fs::rename(&vhd, &renamed).is_err());",
    "drop(concurrent_writer);",
    "drop(guard);",
    'fs::rename(&vhd, &renamed).expect("rename after observation guard release")',
  ]) {
    assert(
      vhdObservationTest.includes(required),
      `Windows live-VHD observation test is missing: ${required}`,
    );
  }
  const vhdReleaseWaitTest = windowsTestSection(
    "windows_wsl_vhd_verification_waits_for_exact_writer_release",
  );
  assertOrderedTokens(
    vhdReleaseWaitTest,
    [
      "let versions_root = fixture.manager.versions_root();",
      "ensure_private_directory(&versions_root).unwrap();",
      'let base_path = versions_root.join("release-wait");',
      "ensure_private_directory(&base_path).unwrap();",
      'let vhd = base_path.join("ext4.vhdx");',
      "let locked_vhd = open_windows_writer_with_full_sharing(&vhd);",
      "verify_windows_wsl_recovery_vhd_with_timing(",
      "|| Ok(base_path.clone()),",
      'expect("VHD proof resumes after the exact writer is released")',
      'release.join().expect("release fixture VHD handle")',
      "assert_eq!(snapshot.size, expected_size);",
      "assert!(started.elapsed() >= Duration::from_millis(250));",
    ],
    "Windows exact-VHD release-wait test",
  );
  assert(
    vhdReleaseWaitTest.includes("drop(locked_vhd);") &&
      vhdReleaseWaitTest.includes("Duration::from_secs(5)") &&
      vhdReleaseWaitTest.includes("Duration::from_millis(25)"),
    "Windows exact-VHD release-wait test does not prove a bounded sharing-violation retry",
  );
  const vhdReleaseTimeoutTest = windowsTestSection(
    "windows_wsl_vhd_writer_timeout_is_typed_and_preserves_the_file",
  );
  assertOrderedTokens(
    vhdReleaseTimeoutTest,
    [
      "let versions_root = fixture.manager.versions_root();",
      "ensure_private_directory(&versions_root).unwrap();",
      'let base_path = versions_root.join("release-timeout");',
      "ensure_private_directory(&base_path).unwrap();",
      'let vhd = base_path.join("ext4.vhdx");',
      "let locked_vhd = open_windows_writer_with_full_sharing(&vhd);",
      "verify_windows_wsl_recovery_vhd_with_timing(",
      "|| Ok(base_path.clone()),",
      "Duration::from_millis(150)",
      'expect_err("an unreleased VHD must hit the bounded deadline")',
      "matches!(error, AppError::Runtime(_))",
      'contains("remained writable or replaceable")',
      "assert!(vhd.is_file());",
      "drop(locked_vhd);",
      'expect("the retained VHD can be verified on retry")',
    ],
    "Windows exact-VHD release-timeout test",
  );
  assert(
    vhdReleaseTimeoutTest.split("verify_windows_wsl_recovery_vhd_with_timing(").length - 1 === 2 &&
      vhdReleaseTimeoutTest.split("|| Ok(base_path.clone()),").length - 1 === 2 &&
      vhdReleaseTimeoutTest.includes("Duration::from_millis(25)"),
    "Windows exact-VHD release-timeout test does not retain and retry the same BasePath checkpoint",
  );
  const unregisterContractStart = managedRuntime.indexOf(
    "    #[test]\n    fn direct_wsl_unregister_is_whitelisted_only_for_verified_backup_recovery()",
  );
  const unregisterContractEnd = managedRuntime.indexOf(
    "\n    #[test]\n    fn managed_ssh_identity_is_reused_and_partial_regular_pair_is_safely_repaired()",
    unregisterContractStart,
  );
  assert(
    unregisterContractStart !== -1 && unregisterContractEnd > unregisterContractStart,
    "managed runtime is missing the scoped direct-unregister source-contract test",
  );
  const unregisterContractTest = managedRuntime.slice(
    unregisterContractStart,
    unregisterContractEnd,
  );
  assertOrderedTokens(
    unregisterContractTest,
    [
      'let normalized_source = include_str!("managed_runtime.rs").replace("\\r\\n", "\\n");',
      "let source = normalized_source.as_str();",
      '.split("\\n#[cfg(test)]")',
      '.find("#[cfg(not(windows))]\\nfn verify_windows_wsl_recovery_vhd_with_timing")',
    ],
    "direct-unregister CRLF-neutral source-contract test",
  );
  const reboundVhdTest = windowsTestSection(
    "n_minus_one_vhd_release_reproof_rejects_a_rebound_distribution_before_export",
  );
  for (const required of [
    "RebindingWindowsWslRegistrations",
    "arm_on_read: 3",
    "open_windows_writer_with_full_sharing(&source_vhd)",
    "Some((Duration::from_secs(5), Duration::from_millis(25)))",
    "matches!(error, AppError::NotAuthorized(_))",
    "fs::read(&pending_path).unwrap(), pending_before",
    "fs::read(&durable_intent_path).unwrap(), intent_before",
    ".install_transition",
    'String::from("--terminate")',
    '"a rebound registration must stop before export or unregister"',
  ]) {
    assert(reboundVhdTest.includes(required), `rebound VHD Windows test is missing: ${required}`);
  }
  const timeoutCheckpointTest = windowsTestSection(
    "n_minus_one_vhd_timeout_preserves_the_full_recovery_checkpoint",
  );
  for (const required of [
    "backup_path.clone()",
    "import_path.clone()",
    "intent.recovery_archive.clone()",
    "open_windows_writer_with_full_sharing(&source_vhd)",
    "matches!(error, AppError::Runtime(_))",
    'contains("remained writable or replaceable")',
    "windows_wsl_ghost_migration_consumed_path(&machine)",
    'String::from("--terminate")',
    '"timeout must stop before export or either unregister"',
    "assert!(source_vhd.is_file())",
    'assert!(\n            intent\n                .quarantine_install_directory\n                .join("ext4.vhdx")\n                .is_file()',
  ]) {
    assert(
      timeoutCheckpointTest.includes(required),
      `VHD-timeout checkpoint Windows test is missing: ${required}`,
    );
  }
  const incompleteQuarantineTest = windowsTestSection(
    "uncheckpointed_quarantine_without_a_vhd_is_exactly_unregistered",
  );
  for (const required of [
    "let machine = intent.machine_name.clone();",
    "!quarantine_vhd.exists()",
    "SequencedWindowsWslRegistrations",
    "remove_uncheckpointed_windows_wsl_quarantine_locked",
    "distribution_root.join(\"ext4.vhdx\").is_file()",
    "!intent.attempt_directory.join(\"import.json\").exists()",
    'String::from("--terminate")',
    'String::from("--unregister")',
    'String::from("--list")',
    'String::from("--quiet")',
  ]) {
    assert(
      incompleteQuarantineTest.includes(required),
      `incomplete-quarantine Windows test is missing: ${required}`,
    );
  }
  assert(
    !managedRuntimeProduction.includes("--import-in-place"),
    "managed runtime recovery depends on unsupported in-place Windows WSL import",
  );
  const registryRead = boundedRecoverySection(
    "fn read_windows_registry_string_once",
    "fn windows_registry_string(",
    "bounded stable Windows registry read",
  );
  const registryDecoder = boundedRecoverySection(
    "fn decode_windows_registry_string_read",
    "fn decode_stable_windows_registry_string_reads",
    "bounded Windows registry decoder",
  );
  const stableRegistryDecoder = boundedRecoverySection(
    "fn decode_stable_windows_registry_string_reads",
    "fn read_windows_registry_string_once",
    "stable Windows registry read comparison",
  );
  const registryString = boundedRecoverySection(
    "fn windows_registry_string(",
    "fn windows_registry_optional_string",
    "stable Windows registry string snapshot",
  );
  assert(
    registryRead.includes("RRF_RT_REG_SZ | RRF_NOEXPAND | RRF_ZEROONFAILURE") &&
      registryRead.includes("vec![0xa5a5_u16;") &&
      registryRead.includes("status == ERROR_MORE_DATA") &&
      registryRead.includes("value_type != REG_SZ") &&
      registryRead.includes("decode_windows_registry_string_read(&encoded, returned_bytes)?"),
    "Windows registry data reads are not bounded, type-locked, and fail-closed",
  );
  assert(
    registryDecoder.includes("2..=MAX_WINDOWS_REGISTRY_STRING_BYTES") &&
      registryDecoder.includes("returned_bytes.is_multiple_of(2)") &&
      registryDecoder.includes("returned_units > encoded.len()") &&
      registryDecoder.includes("encoded[returned_units - 1] != 0") &&
      registryDecoder.includes("encoded[..returned_units - 1].contains(&0)") &&
      registryDecoder.includes("String::from_utf16(&encoded[..returned_units - 1])") &&
      stableRegistryDecoder.includes("first_returned_bytes != second_returned_bytes") &&
      stableRegistryDecoder.includes("first[..first_units] != second[..second_units]") &&
      stableRegistryDecoder.includes("first_value != second_value"),
    "Windows registry decoding no longer proves bounded, canonical, stable UTF-16 bytes",
  );
  assert(
    registryString.includes("checked_add(2)") &&
      registryString.includes("candidate <= MAX_WINDOWS_REGISTRY_STRING_BYTES") &&
      registryString.split("read_windows_registry_string_once(").length - 1 === 2 &&
      registryString.includes("decode_stable_windows_registry_string_reads(") &&
      !registryString.includes("returned_bytes != size_bytes") &&
      managedRuntime.includes(
        "windows_registry_string_accepts_a_bounded_size_probe_overestimate_only_when_reads_stabilize",
      ) &&
      managedRuntime.includes("windows_registry_string_rejects_unbounded_or_malformed_reads"),
    "Windows registry strings do not use two identical bounded reads after a non-exact size probe",
  );
  const optionalRegistryString = boundedRecoverySection(
    "fn windows_registry_optional_string",
    "fn windows_nsis_installation_from_key",
    "optional Windows registry string probe",
  );
  assert(
    optionalRegistryString.includes(
      "RRF_RT_REG_SZ | RRF_NOEXPAND | RRF_ZEROONFAILURE",
    ) && optionalRegistryString.includes("windows_registry_string(key, value_name).map(Some)"),
    "optional Windows registry probes are not bound to the literal stable string reader",
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
  const gitAttributes = await readFile(path.join(PROJECT_ROOT, ".gitattributes"), "utf8");
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

  assert(
    /^scripts\/release\/qualify-windows-nsis-ghost-recovery\.ps1 text eol=lf$/mu.test(
      gitAttributes,
    ),
    "the WSL ghost qualification script must remain LF-only in Windows checkouts",
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
