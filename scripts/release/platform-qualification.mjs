import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  PROJECT_ROOT,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  writeJsonAtomic,
} from "./lib.mjs";

const PLATFORM_CONTRACTS = Object.freeze({
  "linux-x86_64": Object.freeze({
    bundleType: "deb",
    runnerLabel: "ubuntu-24.04",
    runnerOs: "Linux",
    runnerArch: "X64",
    qualificationState: "passed",
  }),
  "macos-universal": Object.freeze({
    bundleType: "dmg",
    runnerLabel: "macos-14",
    runnerOs: "macOS",
    runnerArch: "X64",
    qualificationState: "host_limited",
  }),
  "windows-x86_64": Object.freeze({
    bundleType: "msi",
    runnerLabel: "windows-2025",
    runnerOs: "Windows",
    runnerArch: "X64",
    qualificationState: "passed",
  }),
});

const MAX_QUALIFICATION_DOCUMENT_BYTES = 1024 * 1024;
const MAX_CONTAINER_REPORT_BYTES = 1024 * 1024;

const STATUS_KEYS = [
  "architecture",
  "available",
  "detail",
  "machine_image_sha256",
  "machine_provider",
  "manifest_sha256",
  "operating_system",
  "phase",
  "prerequisite",
  "provider",
  "runtime_version",
];

const LIFECYCLE_OPERATION_NAMES = Object.freeze({
  full: Object.freeze([
    "initial_status",
    "install",
    "installed_status",
    "start",
    "running_status",
    "stop",
    "stopped_status",
    "uninstall_purge",
    "final_status",
  ]),
  macos: Object.freeze([
    "initial_status",
    "install",
    "installed_status",
    "start",
    "uninstall_purge",
    "final_status",
  ]),
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assert(JSON.stringify(actual) === JSON.stringify(wanted), `${label} fields are not the strict released set`);
}

function requireText(value, label) {
  assert(typeof value === "string" && value.length > 0 && !/[\0\r\n]/u.test(value), `${label} must be non-empty single-line text`);
}

function requireDigest(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{64}$/u.test(value), `${label} must be a lowercase SHA-256`);
}

function requireInteger(value, label, minimum = 0) {
  assert(Number.isSafeInteger(value) && value >= minimum, `${label} must be an integer >= ${minimum}`);
}

function requireAbsolutePath(value, platform, label) {
  requireText(value, label);
  const absolute = platform === "windows-x86_64"
    ? path.win32.isAbsolute(value)
    : path.posix.isAbsolute(value);
  assert(absolute, `${label} must be an absolute installed path`);
}

function validateStatus(status, phase, available, runtime, target, label) {
  exactKeys(status, STATUS_KEYS, label);
  assert(status.provider === "managed_local", `${label} provider must be managed_local`);
  assert(status.phase === phase, `${label} phase must be ${phase}`);
  assert(status.available === available, `${label} availability is inconsistent with ${phase}`);
  assert(status.runtime_version === runtime.runtimeVersion, `${label} runtime version mismatch`);
  assert(status.manifest_sha256 === runtime.manifestSha256, `${label} manifest digest mismatch`);
  assert(status.machine_image_sha256 === target.sha256, `${label} machine-image digest mismatch`);
  assert(status.operating_system === target.operatingSystem, `${label} operating system mismatch`);
  assert(status.architecture === target.architecture, `${label} architecture mismatch`);
  assert(status.machine_provider === target.provider, `${label} machine provider mismatch`);
  assert(status.prerequisite === null || typeof status.prerequisite === "string", `${label} prerequisite is malformed`);
  requireText(status.detail, `${label} detail`);
}

function validateContainerResult(result, runtime, target, version, expectedImage) {
  exactKeys(result, ["schema_version", "status", "qualification_kind", "product_version", "runtime", "container", "evidence"], "container qualification");
  assert(result.schema_version === "1.0.0", "container qualification schema is unsupported");
  assert(result.status === "passed", "container qualification did not pass");
  assert(result.qualification_kind === "managed_container_execution", "container qualification kind is incorrect");
  assert(result.product_version === version, "container qualification product version mismatch");
  exactKeys(result.runtime, ["provider", "server_version", "command_provenance"], "container qualification runtime");
  assert(result.runtime.provider === "managed_local", "container qualification did not use managed_local");
  requireText(result.runtime.server_version, "container qualification server version");
  exactKeys(result.runtime.command_provenance, ["kind", "runtime_version", "manifest_sha256", "machine_image_sha256"], "container command provenance");
  assert(result.runtime.command_provenance.kind === "managed_local", "container command provenance kind is incorrect");
  assert(result.runtime.command_provenance.runtime_version === runtime.runtimeVersion, "container runtime version mismatch");
  assert(result.runtime.command_provenance.manifest_sha256 === runtime.manifestSha256, "container manifest digest mismatch");
  assert(result.runtime.command_provenance.machine_image_sha256 === target.sha256, "container machine-image digest mismatch");
  exactKeys(result.container, ["engine_id", "image", "network", "read_only_root", "capabilities", "no_new_privileges", "credential_count", "exit_code", "cancelled", "created_object_id", "cleanup_removed"], "container qualification container");
  assert(result.container.engine_id === "gitleaks", "container qualification must use the fixed Gitleaks probe");
  assert(result.container.image === expectedImage, "container qualification image differs from the released immutable Gitleaks image");
  assert(result.container.network === "none", "container qualification must disable network access");
  assert(result.container.read_only_root === true, "container qualification root must be read-only");
  assert(result.container.capabilities === "drop_all", "container qualification must drop all capabilities");
  assert(result.container.no_new_privileges === true, "container qualification must set no-new-privileges");
  assert(result.container.credential_count === 0, "container qualification exposed credentials");
  assert(result.container.exit_code === 0 && result.container.cancelled === false, "container qualification process did not complete successfully");
  assert(/^[0-9a-f]{64}$/u.test(result.container.created_object_id), "container qualification has no exact created object id");
  assert(result.container.cleanup_removed === true, "container qualification did not remove its exact container");
  exactKeys(result.evidence, ["scope_sha256", "report_sha256", "report_bytes", "finding_count", "stdout_sha256", "stderr_sha256"], "container qualification evidence");
  for (const field of ["scope_sha256", "report_sha256", "stdout_sha256", "stderr_sha256"]) requireDigest(result.evidence[field], `container evidence ${field}`);
  requireInteger(result.evidence.report_bytes, "container evidence report_bytes", 1);
  assert(result.evidence.report_bytes <= MAX_CONTAINER_REPORT_BYTES, "container qualification report exceeds its released bound");
  assert(result.evidence.finding_count === 0, "fixed container qualification fixture unexpectedly produced findings");
}

function qualificationImageFromCatalog(catalog) {
  const engine = catalog.find((candidate) => candidate?.id === "gitleaks");
  assert(engine?.distribution_mode === "pull_pinned_image", "catalog has no pull-pinned Gitleaks qualification image");
  requireText(engine.image?.repository, "Gitleaks image repository");
  assert(/^sha256:[0-9a-f]{64}$/u.test(engine.image?.digest ?? ""), "Gitleaks image digest is not immutable");
  return `${engine.image.repository}@${engine.image.digest}`;
}

function validateOperations(operations, platform, runtime, target) {
  const macos = platform === "macos-universal";
  const expectedNames = macos ? LIFECYCLE_OPERATION_NAMES.macos : LIFECYCLE_OPERATION_NAMES.full;
  assert(Array.isArray(operations), "managed lifecycle operations must be an array");
  assert(JSON.stringify(operations.map((operation) => operation?.name)) === JSON.stringify(expectedNames), "managed lifecycle operation order is incomplete or unexpected");
  const expectedPhases = new Map([
    ["initial_status", ["not_installed", false]],
    ["install", ["installed", false]],
    ["installed_status", ["installed", false]],
    ["start", ["running", true]],
    ["running_status", ["running", true]],
    ["stop", ["stopped", false]],
    ["stopped_status", ["stopped", false]],
    ["uninstall_purge", ["not_installed", false]],
    ["final_status", ["not_installed", false]],
  ]);
  for (const operation of operations) {
    if (macos && operation.name === "start") {
      exactKeys(operation, ["name", "outcome", "reason"], "macOS start operation");
      assert(operation.outcome === "unsupported", "macOS hosted start must be recorded as unsupported, not passed");
      assert(operation.reason === "github_macos_hosted_nested_virtualization_unavailable", "macOS hosted start limitation is not the released reason");
      continue;
    }
    exactKeys(operation, ["name", "outcome", "status"], `${operation.name} operation`);
    assert(operation.outcome === "passed", `${operation.name} operation did not pass`);
    const [phase, available] = expectedPhases.get(operation.name);
    validateStatus(operation.status, phase, available, runtime, target, `${operation.name} status`);
  }
}

export function validatePlatformQualification(evidence, context = {}) {
  exactKeys(evidence, ["schemaVersion", "evidenceType", "product", "platform", "qualificationState", "releaseIdentity", "runner", "sourceArtifact", "installer", "installedLayout", "runtime", "desktopStartup", "managedRuntime", "containerExecution", "cleanup"], "platform qualification");
  assert(evidence.schemaVersion === 1, "platform qualification schemaVersion must be 1");
  assert(evidence.evidenceType === "hosted-platform-qualification", "platform qualification evidenceType is incorrect");
  assert(evidence.product === "ai-security-scanner", "platform qualification product is incorrect");
  const contract = PLATFORM_CONTRACTS[evidence.platform];
  assert(contract, `unsupported qualification platform: ${String(evidence.platform)}`);
  if (context.platform) assert(evidence.platform === context.platform, "platform qualification filename/platform mismatch");
  assert(evidence.qualificationState === contract.qualificationState, `${evidence.platform} qualification state is dishonest`);

  exactKeys(evidence.releaseIdentity, ["version", "tag", "sourceCommit"], "qualification release identity");
  assert(isSemver(evidence.releaseIdentity.version), "qualification version is not stable SemVer");
  assert(evidence.releaseIdentity.tag === `v${evidence.releaseIdentity.version}`, "qualification tag/version mismatch");
  assert(/^[0-9a-f]{40}$/u.test(evidence.releaseIdentity.sourceCommit), "qualification commit must be a full lowercase object id");
  if (context.version) assert(evidence.releaseIdentity.version === context.version, "qualification version differs from release");
  if (context.tag) assert(evidence.releaseIdentity.tag === context.tag, "qualification tag differs from release");
  if (context.commit) assert(evidence.releaseIdentity.sourceCommit === context.commit, "qualification commit differs from release");

  exactKeys(evidence.runner, ["provider", "environment", "runnerLabel", "os", "arch", "imageOs", "imageVersion", "workflow", "job", "runId", "runAttempt", "freshJob", "artifactOnlyFromBuild"], "qualification runner");
  assert(evidence.runner.provider === "github-actions" && evidence.runner.environment === "github-hosted", "qualification did not run on a GitHub-hosted runner");
  assert(evidence.runner.runnerLabel === contract.runnerLabel, "qualification runner label is incorrect");
  assert(evidence.runner.os === contract.runnerOs && evidence.runner.arch === contract.runnerArch, "qualification runner OS/architecture is incorrect");
  for (const field of ["imageOs", "imageVersion", "workflow", "job", "runId", "runAttempt"]) requireText(evidence.runner[field], `qualification runner ${field}`);
  assert(evidence.runner.freshJob === true && evidence.runner.artifactOnlyFromBuild === true, "qualification is not bound to a fresh post-build job");

  exactKeys(evidence.sourceArtifact, ["name"], "qualification source artifact");
  assert(evidence.sourceArtifact.name === `release-${evidence.platform}`, "qualification source artifact is incorrect");
  exactKeys(evidence.installer, ["bundleType", "file", "bytes", "sha256"], "qualified installer");
  assert(evidence.installer.bundleType === contract.bundleType, "qualification used the wrong installer kind");
  requireText(evidence.installer.file, "qualified installer filename");
  assert(path.posix.basename(evidence.installer.file) === evidence.installer.file && path.win32.basename(evidence.installer.file) === evidence.installer.file, "qualified installer filename is not flat");
  requireInteger(evidence.installer.bytes, "qualified installer bytes", 1);
  requireDigest(evidence.installer.sha256, "qualified installer digest");

  exactKeys(evidence.installedLayout, ["pathsVerifiedAbsolute", "desktop", "cli", "companions", "runtimeManifestOriginalPath"], "installed layout");
  assert(evidence.installedLayout.pathsVerifiedAbsolute === true, "installed paths were not verified absolute on the platform runner");
  for (const field of ["desktop", "cli", "runtimeManifestOriginalPath"]) requireAbsolutePath(evidence.installedLayout[field], evidence.platform, `installed layout ${field}`);
  assert(Array.isArray(evidence.installedLayout.companions) && evidence.installedLayout.companions.length === 3, "installed layout must contain exactly three companions");
  const expectedCompanions = ["ai-security-scanner-egress-gateway", "ai-security-scanner-bootstrap-broker", "ai-security-scanner-cli"];
  for (const [index, companion] of evidence.installedLayout.companions.entries()) {
    exactKeys(companion, ["name", "path"], `installed companion ${index}`);
    assert(companion.name === expectedCompanions[index], "installed companions are incomplete or out of order");
    requireAbsolutePath(companion.path, evidence.platform, `installed companion ${companion.name} path`);
  }
  assert(evidence.installedLayout.cli === evidence.installedLayout.companions[2].path, "installed CLI path differs from its companion record");

  exactKeys(evidence.runtime, ["bundleId", "runtimeVersion", "manifestReleaseFile", "manifestSha256", "installedManifestSnapshotSha256", "installedManifestExactMatch", "machineImages", "selectedTarget"], "qualified runtime");
  requireText(evidence.runtime.bundleId, "runtime bundle id");
  requireText(evidence.runtime.runtimeVersion, "runtime version");
  assert(evidence.runtime.manifestReleaseFile === `managed-runtime-${evidence.platform}.manifest.json`, "runtime release manifest filename is incorrect");
  requireDigest(evidence.runtime.manifestSha256, "runtime manifest digest");
  assert(evidence.runtime.installedManifestSnapshotSha256 === evidence.runtime.manifestSha256 && evidence.runtime.installedManifestExactMatch === true, "installed runtime manifest does not exactly match release evidence");
  assert(Array.isArray(evidence.runtime.machineImages) && evidence.runtime.machineImages.length > 0, "runtime has no machine-image records");
  for (const [index, image] of evidence.runtime.machineImages.entries()) {
    exactKeys(image, ["operatingSystem", "architecture", "provider", "url", "sha256", "bytes"], `machine image ${index}`);
    for (const field of ["operatingSystem", "architecture", "provider", "url"]) requireText(image[field], `machine image ${index} ${field}`);
    assert(image.url.startsWith("https://"), `machine image ${index} URL must use HTTPS`);
    requireDigest(image.sha256, `machine image ${index} digest`);
    requireInteger(image.bytes, `machine image ${index} bytes`, 1);
  }
  exactKeys(evidence.runtime.selectedTarget, ["operatingSystem", "architecture", "provider", "sha256"], "selected runtime target");
  const target = evidence.runtime.machineImages.find((image) => image.operatingSystem === evidence.runtime.selectedTarget.operatingSystem && image.architecture === evidence.runtime.selectedTarget.architecture && image.provider === evidence.runtime.selectedTarget.provider && image.sha256 === evidence.runtime.selectedTarget.sha256);
  assert(target, "selected runtime target is absent from the exact machine-image inventory");

  exactKeys(evidence.desktopStartup, ["outcome", "observationSeconds", "installedExecutable"], "desktop startup observation");
  assert(evidence.desktopStartup.outcome === "passed", "installed desktop startup did not pass");
  requireInteger(evidence.desktopStartup.observationSeconds, "desktop startup observation seconds", 10);
  assert(evidence.desktopStartup.installedExecutable === evidence.installedLayout.desktop, "desktop startup used a different executable");

  exactKeys(evidence.managedRuntime, ["privateDataDirectory", "operations"], "managed runtime qualification");
  requireAbsolutePath(evidence.managedRuntime.privateDataDirectory, evidence.platform, "managed runtime private data directory");
  validateOperations(evidence.managedRuntime.operations, evidence.platform, evidence.runtime, evidence.runtime.selectedTarget);

  if (evidence.platform === "macos-universal") {
    exactKeys(evidence.containerExecution, ["outcome", "reason"], "macOS container execution");
    assert(evidence.containerExecution.outcome === "not_run", "macOS hosted container execution must not be recorded as passed");
    assert(evidence.containerExecution.reason === "github_macos_hosted_nested_virtualization_unavailable", "macOS container limitation reason is incorrect");
  } else {
    exactKeys(evidence.containerExecution, ["outcome", "result"], "container execution");
    assert(evidence.containerExecution.outcome === "passed", "managed container execution did not pass");
    assert(typeof context.expectedQualificationImage === "string", "validator has no released qualification image identity");
    validateContainerResult(evidence.containerExecution.result, evidence.runtime, evidence.runtime.selectedTarget, evidence.releaseIdentity.version, context.expectedQualificationImage);
  }

  exactKeys(evidence.cleanup, ["managedRuntimePurged", "machineImageCachePurged", "installerRemoved", "privateDataRemoved"], "qualification cleanup");
  assert(Object.values(evidence.cleanup).every((value) => value === true), "qualification cleanup is incomplete");
  return evidence;
}

function observationsToEvidence(observations, inputs) {
  const { platform, version, tag, commit, runnerLabel, installer, runtimeManifest, runtimeManifestSha256, installedManifestSha256, expectedQualificationImage, environment } = inputs;
  const contract = PLATFORM_CONTRACTS[platform];
  exactKeys(observations, ["installedLayout", "desktopStartup", "privateDataDirectory", "operations", "containerExecution", "cleanup", "installedManifestSnapshot"], "platform observations");
  exactKeys(observations.installedLayout, ["pathsVerifiedAbsolute", "desktop", "cli", "companions", "runtimeManifestOriginalPath"], "observed installed layout");
  assert(observations.installedManifestSnapshot === "installed-runtime-manifest.json", "installed manifest snapshot must use the fixed local filename");
  const selectedStatus = observations.operations.find((operation) => operation.name === "installed_status")?.status;
  assert(selectedStatus && typeof selectedStatus === "object", "observations have no installed runtime status");
  const machineImages = runtimeManifest.targets.map((target) => ({
    operatingSystem: target.operating_system,
    architecture: target.architecture,
    provider: target.provider,
    url: target.machine_image.url,
    sha256: target.machine_image.sha256,
    bytes: target.machine_image.size_bytes,
  }));
  const selectedTarget = {
    operatingSystem: selectedStatus.operating_system,
    architecture: selectedStatus.architecture,
    provider: selectedStatus.machine_provider,
    sha256: selectedStatus.machine_image_sha256,
  };
  const evidence = {
    schemaVersion: 1,
    evidenceType: "hosted-platform-qualification",
    product: "ai-security-scanner",
    platform,
    qualificationState: contract.qualificationState,
    releaseIdentity: { version, tag, sourceCommit: commit },
    runner: {
      provider: "github-actions",
      environment: environment.RUNNER_ENVIRONMENT,
      runnerLabel,
      os: environment.RUNNER_OS,
      arch: environment.RUNNER_ARCH,
      imageOs: environment.ImageOS,
      imageVersion: environment.ImageVersion,
      workflow: environment.GITHUB_WORKFLOW,
      job: environment.GITHUB_JOB,
      runId: environment.GITHUB_RUN_ID,
      runAttempt: environment.GITHUB_RUN_ATTEMPT,
      freshJob: true,
      artifactOnlyFromBuild: true,
    },
    sourceArtifact: { name: `release-${platform}` },
    installer,
    installedLayout: observations.installedLayout,
    runtime: {
      bundleId: runtimeManifest.bundle_id,
      runtimeVersion: runtimeManifest.runtime_version,
      manifestReleaseFile: `managed-runtime-${platform}.manifest.json`,
      manifestSha256: runtimeManifestSha256,
      installedManifestSnapshotSha256: installedManifestSha256,
      installedManifestExactMatch: installedManifestSha256 === runtimeManifestSha256,
      machineImages,
      selectedTarget,
    },
    desktopStartup: observations.desktopStartup,
    managedRuntime: {
      privateDataDirectory: observations.privateDataDirectory,
      operations: observations.operations,
    },
    containerExecution: observations.containerExecution,
    cleanup: observations.cleanup,
  };
  return validatePlatformQualification(evidence, { platform, version, tag, commit, expectedQualificationImage });
}

export async function createPlatformQualification({ artifactDirectory, observationsFile, outputFile, platform, version, tag, commit, runnerLabel, environment = process.env }) {
  const contract = PLATFORM_CONTRACTS[platform];
  assert(contract, `unsupported qualification platform: ${platform}`);
  assert(runnerLabel === contract.runnerLabel, `runner label ${runnerLabel} is not released for ${platform}`);
  assert(environment.GITHUB_ACTIONS === "true", "platform qualification creation is restricted to GitHub Actions");
  assert(environment.RUNNER_ENVIRONMENT === "github-hosted", "platform qualification creation requires a GitHub-hosted runner");
  assert(environment.RUNNER_OS === contract.runnerOs && environment.RUNNER_ARCH === contract.runnerArch, "actual runner OS/architecture differs from the qualification contract");
  for (const field of ["ImageOS", "ImageVersion", "GITHUB_WORKFLOW", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"]) requireText(environment[field], `runner environment ${field}`);
  assert(isSemver(version) && tag === `v${version}` && /^[0-9a-f]{40}$/u.test(commit), "qualification release identity is malformed");
  assert(environment.GITHUB_SHA === commit, "qualification checkout SHA differs from validated release identity");

  const installerManifest = await readJson(path.join(artifactDirectory, `installers-${platform}.json`));
  assert(installerManifest.version === version && installerManifest.tag === tag && installerManifest.sourceCommit === commit && installerManifest.platform === platform, "installer manifest release identity mismatch");
  const installers = installerManifest.installers?.filter((candidate) => candidate.bundleType === contract.bundleType) ?? [];
  assert(installers.length === 1, `${platform} must have exactly one ${contract.bundleType} qualification installer`);
  const installerRecord = installers[0];
  assert(path.posix.basename(installerRecord.file) === installerRecord.file && path.win32.basename(installerRecord.file) === installerRecord.file, "qualification installer manifest path is not flat");
  const installerPath = path.join(artifactDirectory, installerRecord.file);
  const installerMetadata = await lstat(installerPath);
  assert(installerMetadata.isFile() && !installerMetadata.isSymbolicLink(), "qualification installer is not a regular file");
  const installer = { bundleType: contract.bundleType, file: installerRecord.file, bytes: installerMetadata.size, sha256: await sha256File(installerPath) };
  assert(installer.bytes === installerRecord.bytes && installer.sha256 === installerRecord.sha256, "qualification installer bytes differ from their release manifest");

  const runtimeManifestFile = path.join(artifactDirectory, `managed-runtime-${platform}.manifest.json`);
  const runtimeManifestMetadata = await lstat(runtimeManifestFile);
  assert(runtimeManifestMetadata.isFile() && !runtimeManifestMetadata.isSymbolicLink(), "qualification runtime manifest is not a regular file");
  const runtimeManifest = await readJson(runtimeManifestFile);
  assert(runtimeManifest.schema_version === "2" && Array.isArray(runtimeManifest.targets) && runtimeManifest.targets.length > 0, "qualification runtime manifest is malformed");
  const runtimeManifestSha256 = await sha256File(runtimeManifestFile);
  const observationsMetadata = await lstat(observationsFile);
  assert(
    observationsMetadata.isFile() &&
      !observationsMetadata.isSymbolicLink() &&
      observationsMetadata.size > 0 &&
      observationsMetadata.size <= MAX_QUALIFICATION_DOCUMENT_BYTES,
    "platform observations must be a bounded regular file",
  );
  const observations = await readJson(observationsFile);
  const installedManifestSnapshot = path.resolve(path.dirname(observationsFile), observations.installedManifestSnapshot);
  const installedMetadata = await lstat(installedManifestSnapshot);
  assert(installedMetadata.isFile() && !installedMetadata.isSymbolicLink(), "installed runtime manifest snapshot is not a regular file");
  const installedManifestSha256 = await sha256File(installedManifestSnapshot);
  const catalog = await readJson(path.join(PROJECT_ROOT, "engines/catalog.json"));
  const expectedQualificationImage = qualificationImageFromCatalog(catalog);
  const evidence = observationsToEvidence(observations, { platform, version, tag, commit, runnerLabel, installer, runtimeManifest, runtimeManifestSha256, installedManifestSha256, expectedQualificationImage, environment });
  await writeJsonAtomic(outputFile, evidence);
  return evidence;
}

export async function verifyPlatformQualificationFile(file, context = {}) {
  const metadata = await lstat(file);
  assert(
    metadata.isFile() &&
      !metadata.isSymbolicLink() &&
      metadata.size > 0 &&
      metadata.size <= MAX_QUALIFICATION_DOCUMENT_BYTES,
    "platform qualification must be a bounded regular file",
  );
  const evidence = await readJson(file);
  let expectedQualificationImage = context.expectedQualificationImage;
  if (!expectedQualificationImage) {
    const catalog = await readJson(path.join(PROJECT_ROOT, "engines/catalog.json"));
    expectedQualificationImage = qualificationImageFromCatalog(catalog);
  }
  validatePlatformQualification(evidence, { ...context, expectedQualificationImage });
  if (context.releaseDirectory) {
    const installerManifest = await readJson(path.join(context.releaseDirectory, `installers-${evidence.platform}.json`));
    const installer = installerManifest.installers?.find((candidate) => candidate.bundleType === evidence.installer.bundleType && candidate.file === evidence.installer.file);
    assert(installer && installer.bytes === evidence.installer.bytes && installer.sha256 === evidence.installer.sha256, `${evidence.platform} qualification installer does not match finalized assets`);
    const runtimeManifestFile = path.join(context.releaseDirectory, evidence.runtime.manifestReleaseFile);
    assert((await sha256File(runtimeManifestFile)) === evidence.runtime.manifestSha256, `${evidence.platform} qualification runtime manifest does not match finalized assets`);
    const runtimeManifest = await readJson(runtimeManifestFile);
    const expectedImages = runtimeManifest.targets.map((target) => ({ operatingSystem: target.operating_system, architecture: target.architecture, provider: target.provider, url: target.machine_image.url, sha256: target.machine_image.sha256, bytes: target.machine_image.size_bytes }));
    assert(JSON.stringify(evidence.runtime.machineImages) === JSON.stringify(expectedImages), `${evidence.platform} qualification machine-image inventory differs from finalized runtime evidence`);
  }
  return evidence;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);
  if (command === "create") {
    const outputFile = path.resolve(requireString(args, "out"));
    const evidence = await createPlatformQualification({
      artifactDirectory: path.resolve(requireString(args, "artifact-dir")),
      observationsFile: path.resolve(requireString(args, "observations")),
      outputFile,
      platform: requireString(args, "platform"),
      version: requireString(args, "version"),
      tag: requireString(args, "tag"),
      commit: requireString(args, "commit"),
      runnerLabel: requireString(args, "runner-label"),
    });
    process.stdout.write(`Created strict ${evidence.qualificationState} qualification evidence for ${evidence.platform}.\n`);
    return;
  }
  if (command === "validate") {
    const evidence = await verifyPlatformQualificationFile(path.resolve(requireString(args, "file")), {
      platform: requireString(args, "platform"),
      version: requireString(args, "version"),
      tag: requireString(args, "tag"),
      commit: requireString(args, "commit"),
      releaseDirectory: path.resolve(requireString(args, "artifact-dir")),
    });
    process.stdout.write(`Validated strict ${evidence.qualificationState} qualification evidence for ${evidence.platform}.\n`);
    return;
  }
  throw new Error("usage: platform-qualification.mjs <create|validate> --platform ... --version ... --tag ... --commit ...");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runMain(main);
