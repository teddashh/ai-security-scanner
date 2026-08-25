import { execFileSync } from "node:child_process";
import { mkdir, readdir, readFile } from "node:fs/promises";
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

  const qualification = workflow.jobs?.qualification;
  assert(qualification, "release workflow has no fresh-runner platform qualification job");
  assert(
    JSON.stringify(qualification.needs) === JSON.stringify(["validate", "build"]),
    "platform qualification must consume identity and completed build artifacts in a separate job",
  );
  assert(qualification.permissions?.contents === "read", "platform qualification must remain read-only");
  assert(Number.isInteger(qualification["timeout-minutes"]) && qualification["timeout-minutes"] >= 180, "platform qualification timeout cannot truncate managed runtime lifecycle proof");
  assert(
    JSON.stringify(qualification.strategy?.matrix?.include) === JSON.stringify([
      { platform: "linux-x86_64", runner: "ubuntu-24.04" },
      { platform: "macos-universal", runner: "macos-15-intel" },
      { platform: "windows-x86_64", runner: "windows-2025" },
    ]),
    "platform qualification matrix must use the exact three released hosted runner images",
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
    "platform-qualification-${{ matrix.platform }}.json",
  ]) {
    assert(qualificationSource.includes(required), `platform qualification job is missing: ${required}`);
  }

  const assemble = workflow.jobs?.assemble;
  assert(assemble, "release workflow has no read-only assemble job");
  assert(
    JSON.stringify(assemble.needs) === JSON.stringify(["validate", "supply-chain", "build", "qualification"]),
    "assemble job must depend on validation, supply-chain evidence, every platform build, and all qualifications",
  );
  assert(assemble.permissions?.contents === "read", "assemble job must remain read-only");
  assert(
    !Object.values(assemble.permissions ?? {}).includes("write"),
    "assemble job must not receive write permissions",
  );
  const assembleSource = JSON.stringify(assemble);
  for (const platform of ["linux-x86_64", "macos-universal", "windows-x86_64"]) {
    assert(
      assembleSource.includes(`platform-qualification-${platform}`),
      `assemble job does not download ${platform} qualification evidence`,
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
    "platform-qualification-linux-x86_64",
    "platform-qualification-macos-universal",
    "platform-qualification-windows-x86_64",
  ]) {
    assert(serialized.includes(required), `release workflow is missing required element: ${required}`);
  }
}

function validatePlatformQualificationSources(sources) {
  const linux = sources.get("qualify-linux.sh");
  const macos = sources.get("qualify-macos.sh");
  const windows = sources.get("qualify-windows.ps1");
  const evidence = sources.get("platform-qualification.mjs");
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
    "run_managed initial-status status",
    "run_managed install install",
    "run_managed installed-status status",
    "run_managed start start",
    "run_managed running-status status",
    "run_managed container-qualification qualify",
    "run_managed stop stop",
    "run_managed stopped-status status",
    "run_managed uninstall-purge uninstall --force --purge-image-cache",
    "runtime managed stop --force",
    "runtime managed uninstall --force --purge-image-cache",
    "hdiutil attach",
    "ai-security-scanner-macos-command-home-v1\\0",
    "macOS qualification did not begin with a fresh exact short HOME.",
    "Managed runtime macOS socket alias exceeds Podman 5.8.2 path budget.",
    "Qualification cleanup found the exact macOS short HOME still present:",
    "^/tmp/assm1-[0-9a-f]{32}$",
    "Refusing to follow or remove an unsafe macOS short HOME during qualification cleanup.",
    "[[ -d \"${short_home}\" && ! -L \"${short_home}\" ]]",
    "stat -f '%u'",
    "stat -f '%Lp'",
    "Managed runtime uninstall left its exact macOS short HOME behind.",
    "assert_managed_ssh_identity",
    "data/containers/podman/machine/machine",
    ".machine.private-key-new",
    ".machine.public-key-new",
    "Managed SSH identity staging entries remain after start.",
    "Managed runtime uninstall left its exact release provider home behind.",
    "managed-runtime/provider-home",
  ]) assert(macos.includes(required), `macOS qualification is missing: ${required}`);
  for (const required of [
    'Invoke-Managed "initial-status"',
    'Invoke-Managed "install"',
    'Invoke-Managed "start"',
    'Invoke-Managed "container-qualification"',
    'Invoke-Managed "stop"',
    'Invoke-Managed "uninstall-purge"',
    '"--purge-image-cache"',
    '"msiexec.exe"',
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
    '(Join-Path $localApplicationData "ai-security-scanner-platform-qualification-windows-data")',
    "Where-Object { [String]::Equals($_.Name, $name, [StringComparison]::OrdinalIgnoreCase) }",
    "OS-resolved LocalApplicationData is not a real directory.",
    "Qualification data directory escaped OS-resolved LocalApplicationData.",
    "Qualification requires a fresh LocalApplicationData namespace.",
    "if (Test-ExactEntryExists $dataDirectory)",
    "New-Item -ItemType Directory -Path $dataDirectory -Force",
  ]) assert(windows.includes(required), `Windows qualification is missing: ${required}`);
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
    "run_managed container-qualification qualify",
    "run_managed stop stop",
    'flock -n "${virtiofs_pid}" true',
    "run_managed stopped-status status",
    "run_managed uninstall-purge uninstall --force --purge-image-cache",
    "Managed runtime uninstall left its exact Linux short XDG runtime directory behind.",
    "run_managed final-status status",
  ], "Linux qualification");
  assertOrderedTokens(macos, [
    "run_managed initial-status status",
    "run_managed install install",
    "macOS qualification did not begin with a fresh exact short HOME.",
    "run_managed installed-status status",
    "run_managed start start",
    "run_managed running-status status",
    "run_managed container-qualification qualify",
    "run_managed stop stop",
    "run_managed stopped-status status",
    "run_managed uninstall-purge uninstall --force --purge-image-cache",
    "Managed runtime uninstall left its exact macOS short HOME behind.",
    "run_managed final-status status",
  ], "macOS qualification");
  assertOrderedTokens(windows, [
    "GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)",
    '(Join-Path $localApplicationData "ai-security-scanner-platform-qualification-windows-data")',
    "if (Test-ExactEntryExists $dataDirectory)",
    "New-Item -ItemType Directory -Path $dataDirectory -Force",
    '$initialStatus = Invoke-Managed "initial-status" @("status")',
    '$installStatus = Invoke-Managed "install" @("install")',
    '$installedStatus = Invoke-Managed "installed-status" @("status")',
    '$podmanNamespaceDirectories = @(',
    '$startStatus = Invoke-Managed "start" @("start")',
    '$runningStatus = Invoke-Managed "running-status" @("status")',
    '$containerQualification = Invoke-Managed "container-qualification" @("qualify")',
    '$stopStatus = Invoke-Managed "stop" @("stop")',
    '$stoppedStatus = Invoke-Managed "stopped-status" @("status")',
    '$uninstallStatus = Invoke-Managed "uninstall-purge" @("uninstall", "--force", "--purge-image-cache")',
    '$finalStatus = Invoke-Managed "final-status" @("status")',
  ], "Windows qualification");
  assert(
    !windows.includes('$dataDirectory = Join-Path $runnerTemp "ai-security-scanner-platform-qualification-windows-data"'),
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
  for (const required of [
    'engine_id === "gitleaks"',
    'network === "none"',
    "read_only_root === true",
    'capabilities === "drop_all"',
    "no_new_privileges === true",
    "credential_count === 0",
    "cleanup_removed === true",
    "qualificationImageFromCatalog",
    "installedManifestExactMatch",
    "github-hosted",
    "macos-15-intel",
  ]) assert(evidence.includes(required), `strict platform qualification evidence is missing: ${required}`);
  for (const forbidden of [
    "host_limited",
    "not_run",
    "github_macos_hosted_nested_virtualization_unavailable",
  ]) {
    assert(!macos.includes(forbidden), `macOS qualification retains a bypass state: ${forbidden}`);
    assert(!evidence.includes(forbidden), `platform evidence validator retains a bypass state: ${forbidden}`);
  }
}

function validateManagedRuntimeBuildContract(lock, dockerfile, vendor) {
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
    "self.initialize_machine(&command, target, &image, &machine_name)?",
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
  const catalog = await readJson(path.join(PROJECT_ROOT, "engines/catalog.json"));
  const version = packageJson.version;
  const tag = typeof args.get("tag") === "string" ? args.get("tag") : `v${version}`;
  const releaseLineNotes = await readFile(
    path.join(PROJECT_ROOT, `docs/release/v${version}.md`),
    "utf8",
  );
  const managedRuntimeLock = await readJson(path.join(PROJECT_ROOT, "runtime/upstreams.lock.json"));
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
  const containerRuntimeSource = await readFile(
    path.join(PROJECT_ROOT, "src-tauri/src/container_runtime.rs"),
    "utf8",
  );

  assert(isSemver(version), `package version is not strict SemVer: ${version}`);
  assert(tag === `v${version}`, `tag ${tag} does not exactly match package version ${version}`);
  assert(packageLock.version === version, "package-lock document version is out of sync");
  assert(packageLock.packages?.[""]?.version === version, "package-lock root version is out of sync");
  assert(tauri.version === version, "Tauri version is out of sync");
  assert(cargoPackageVersion(cargoToml) === version, "Cargo package version is out of sync");
  assert(cargoLockPackageVersion(cargoLock) === version, "Cargo.lock package version is out of sync");
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
      releaseGuide.includes("Every platform must prove this exact sequence") &&
      !releaseGuide.includes("github_macos_hosted_nested_virtualization_unavailable") &&
      !releaseGuide.includes("`not_run`"),
    "release guide does not require a real Intel-hosted macOS runtime qualification",
  );
  assert(
    releaseGuide.includes("resolves `bin/qemu-img` from the installed managed-runtime") &&
      releaseGuide.includes("resolves `bin/virtiofsd` from that manifest") &&
      releaseGuide.includes("bounded raw bytes") &&
      releaseGuide.includes("both fixed staging names are absent") &&
      releaseGuide.includes("provider-home directory itself must be absent") &&
      releaseGuide.includes("103-byte Podman socket-path budget"),
    "release guide omits the self-contained managed-runtime qualification contract",
  );
  assert(
    releaseLineNotes.includes("macOS 15 Intel") &&
      releaseLineNotes.includes("network-disabled Gitleaks container probe"),
    "release-line notes omit the full macOS managed-runtime qualification contract",
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

  const workflows = await validateWorkflowSyntaxAndPins();
  validateReleaseWorkflow(workflows.get("release.yml"));
  assert(
    workflows.get("ci.yml")?.jobs?.["windows-managed-runtime"]?.["runs-on"] === "windows-2025",
    "Windows managed-runtime native tests must match the fresh release qualification runner",
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
  validateManagedRuntimeExecutionContract(managedRuntimeSource, containerRuntimeSource);
  const qualificationSources = new Map();
  for (const name of [
    "qualify-linux.sh",
    "qualify-macos.sh",
    "qualify-windows.ps1",
    "platform-qualification.mjs",
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

  if (typeof args.get("metadata") === "string") {
    const metadata = await readJson(path.resolve(PROJECT_ROOT, args.get("metadata")));
    validateReleaseMetadata(metadata, version, tag);
  }

  process.stdout.write(
    `Release metadata is consistent for ${tag}; ${workflows.size} workflow files are valid YAML with SHA-pinned actions.\n`,
  );
}

runMain(main);
