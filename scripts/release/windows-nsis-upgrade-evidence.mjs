import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  writeJsonAtomic,
} from "./lib.mjs";

export const PRIOR_WINDOWS_NSIS = Object.freeze({
  version: "0.1.7",
  tag: "v0.1.7",
  file: "ai-security-scanner_0.1.7_x64-setup.exe",
  bytes: 38_730_365,
  sha256: "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a",
  url: "https://github.com/teddashh/ai-security-scanner/releases/download/v0.1.7/ai-security-scanner_0.1.7_x64-setup.exe",
  runtimeManifestSha256: "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f",
  machineImageSha256: "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968",
});

const SCHEMA_VERSION = 7;
const PLATFORM = "windows-x86_64";
const INSTALLER_TYPE = "nsis";
const RUNNER = "windows-2025";
const BEGINNER_REPORT_FILE = "beginner-report.html";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, keys, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()),
    `${label} fields are not the data-preservation fixture contract`,
  );
}

function yes(value, label) {
  assert(value === true, `${label} was not proven`);
}

function bounded(value, minimum, maximum, label) {
  assert(Number.isSafeInteger(value) && value >= minimum && value <= maximum, `${label} is outside its bound`);
}

function sha256(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{64}$/u.test(value), `${label} is not SHA-256`);
}

function canonicalUuid(value, label) {
  assert(
    typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value),
    `${label} is not a canonical lowercase UUID`,
  );
}

function positiveDecimal(value, label) {
  assert(typeof value === "string" && /^[1-9][0-9]{0,19}$/u.test(value), `${label} is not a positive decimal string`);
  assert(BigInt(value) <= 18_446_744_073_709_551_615n, `${label} exceeds uint64`);
}

function validateFileProof(value, label) {
  exactKeys(value, ["length", "sha256", "volume", "fileIndex"], label);
  bounded(value.length, 1, 64 * 1024, `${label} length`);
  sha256(value.sha256, `${label} digest`);
  bounded(value.volume, 0, 0xffff_ffff, `${label} volume`);
  positiveDecimal(value.fileIndex, `${label} file index`);
}

export function validateWindowsNsisUpgradeInstallerManifestShape(manifest) {
  if (manifest.schemaVersion === 2) {
    exactKeys(manifest, [
      "schemaVersion", "product", "version", "tag", "sourceCommit", "platform",
      "requestedBundleTypes", "availableBundleTypes", "updaters", "updaterFailures",
      "installers", "auxiliaryExecutables",
    ], "source Windows installer manifest");
    for (const field of [
      "requestedBundleTypes", "availableBundleTypes", "updaters", "updaterFailures",
      "installers", "auxiliaryExecutables",
    ]) assert(Array.isArray(manifest[field]), `source Windows installer manifest ${field} is not an array`);
  } else if (manifest.schemaVersion === 3) {
    exactKeys(manifest, [
      "schemaVersion", "product", "version", "tag", "sourceCommit", "platform",
      "artifactScoped", "sourceManifestSha256", "installers", "auxiliaryExecutables", "updaters",
    ], "finalized Windows installer manifest");
    assert(manifest.artifactScoped === true, "finalized Windows installer manifest is not artifact-scoped");
    sha256(manifest.sourceManifestSha256, "finalized Windows source-manifest digest");
    for (const field of ["installers", "auxiliaryExecutables", "updaters"]) {
      assert(Array.isArray(manifest[field]), `finalized Windows installer manifest ${field} is not an array`);
    }
  } else {
    throw new Error("Windows installer manifest schema is unsupported");
  }
}

async function currentNsisInstaller(artifactDirectory, version, tag, commit) {
  const manifest = await readJson(path.join(artifactDirectory, "installers-windows-x86_64.json"));
  validateWindowsNsisUpgradeInstallerManifestShape(manifest);
  assert(manifest.product === "ai-security-scanner" && manifest.platform === PLATFORM, "Windows installer identity is incorrect");
  assert(manifest.version === version && manifest.tag === tag && manifest.sourceCommit === commit, "Windows installer release identity differs");
  const installers = manifest.installers?.filter((item) => item.bundleType === INSTALLER_TYPE) ?? [];
  assert(installers.length === 1, "Windows installer manifest must contain exactly one NSIS installer");
  const installer = installers[0];
  exactKeys(installer, ["bundleType", "file", "bytes", "sha256"], "candidate NSIS installer");
  assert(
    path.posix.basename(installer.file) === installer.file && path.win32.basename(installer.file) === installer.file,
    "candidate NSIS installer path is not flat",
  );
  bounded(installer.bytes, 1, 256 * 1024 * 1024, "candidate NSIS installer bytes");
  sha256(installer.sha256, "candidate NSIS installer digest");
  const file = path.join(artifactDirectory, installer.file);
  const metadata = await lstat(file);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "candidate NSIS installer is not a regular file");
  assert(metadata.size === installer.bytes && (await sha256File(file)) === installer.sha256, "candidate NSIS installer bytes changed");
  return installer;
}

export function validateWindowsNsisUpgradeFixtureScope(scope) {
  exactKeys(scope, [
    "classification", "qualifiesPublicLifecycle", "syntheticCliCaseUsed", "installedDesktopInteractionObserved",
    "localhost1270019001ReportObserved", "projectReopenedInDesktopObserved",
    "postUninstallReinstallObserved",
  ], "Windows NSIS upgrade fixture scope");
  assert(scope.classification === "risk_focused_automated_data_preservation", "upgrade fixture classification changed");
  assert(scope.syntheticCliCaseUsed === true, "upgrade data-preservation fixture must disclose its synthetic CLI case");
  for (const field of [
    "qualifiesPublicLifecycle", "installedDesktopInteractionObserved",
    "localhost1270019001ReportObserved", "projectReopenedInDesktopObserved",
    "postUninstallReinstallObserved",
  ]) assert(scope[field] === false, `upgrade data-preservation fixture cannot claim ${field}`);
}

async function identity(args) {
  const artifactDirectory = path.resolve(requireString(args, "artifact-dir"));
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  assert(isSemver(version) && version === "0.1.8" && tag === `v${version}`, "candidate is not the bounded v0.1.7 to v0.1.8 upgrade");
  assert(/^[0-9a-f]{40}$/u.test(commit), "candidate commit is not a full lowercase Git object ID");
  return {
    artifactDirectory,
    version,
    tag,
    commit,
    installer: await currentNsisInstaller(artifactDirectory, version, tag, commit),
  };
}

function validateObservations(observations, currentVersion, currentInstaller) {
  exactKeys(observations, [
    "schemaVersion", "scenario", "platform", "runner", "priorRelease", "candidate",
    "fixtureScope", "installation", "dataPreservation", "managedRuntimeFilesystemSentinel", "cleanup",
  ], "Windows NSIS upgrade observations");
  assert(observations.schemaVersion === SCHEMA_VERSION, "Windows NSIS upgrade observation schema is unsupported");
  assert(
    observations.scenario === "automated_n_minus_one_nsis_data_preservation_fixture",
    "Windows NSIS upgrade data-preservation fixture scenario is incorrect",
  );
  assert(observations.platform === PLATFORM && observations.runner === RUNNER, "Windows NSIS upgrade runner is incorrect");
  validateWindowsNsisUpgradeFixtureScope(observations.fixtureScope);

  exactKeys(observations.priorRelease, [
    "version", "tag", "installerFile", "installerBytes", "installerSha256", "downloadUrl",
    "runtimeManifestSha256", "machineImageSha256",
  ], "prior release observation");
  assert(JSON.stringify(observations.priorRelease) === JSON.stringify({
    version: PRIOR_WINDOWS_NSIS.version,
    tag: PRIOR_WINDOWS_NSIS.tag,
    installerFile: PRIOR_WINDOWS_NSIS.file,
    installerBytes: PRIOR_WINDOWS_NSIS.bytes,
    installerSha256: PRIOR_WINDOWS_NSIS.sha256,
    downloadUrl: PRIOR_WINDOWS_NSIS.url,
    runtimeManifestSha256: PRIOR_WINDOWS_NSIS.runtimeManifestSha256,
    machineImageSha256: PRIOR_WINDOWS_NSIS.machineImageSha256,
  }), "prior release differs from the immutable N-1 pin");

  exactKeys(observations.candidate, ["version", "installerFile", "installerBytes", "installerSha256"], "candidate observation");
  assert(observations.candidate.version === currentVersion, "installed candidate version is incorrect");
  assert(observations.candidate.installerFile === currentInstaller.file &&
    observations.candidate.installerBytes === currentInstaller.bytes &&
    observations.candidate.installerSha256 === currentInstaller.sha256, "candidate observation differs from its release manifest");

  const installation = observations.installation;
  exactKeys(installation, [
    "priorCliVersion", "candidateCliVersion", "sameCanonicalInstallDirectory", "registryHive",
    "registryEntryIdentityPreserved", "displayVersionUpdated", "uninstallerReplaced", "unattendedMode",
    "sameVersionSilentReinstallCompleted",
  ], "installation observation");
  assert(installation.priorCliVersion === PRIOR_WINDOWS_NSIS.version && installation.candidateCliVersion === currentVersion, "installed CLI versions are incorrect");
  for (const field of [
    "sameCanonicalInstallDirectory", "registryEntryIdentityPreserved", "displayVersionUpdated", "uninstallerReplaced",
    "sameVersionSilentReinstallCompleted",
  ]) yes(installation[field], `installation ${field}`);
  assert(installation.registryHive === "HKEY_CURRENT_USER" && installation.unattendedMode === "silent", "NSIS upgrade mode is incorrect");

  const data = observations.dataPreservation;
  exactKeys(data, [
    "defaultLocalDataDirectoryUsed", "preInstallerFileCount", "preInstallerBytes",
    "exactPreInstallerSnapshotPreserved", "sentinelPreserved", "demoCaseId", "demoRunId", "demoCasePreserved",
    "existingExportIdentity", "beginnerReportExport", "appOnlyUninstallSnapshot",
  ], "data-preservation observation");
  for (const field of [
    "defaultLocalDataDirectoryUsed", "exactPreInstallerSnapshotPreserved", "sentinelPreserved",
    "demoCasePreserved",
  ]) yes(data[field], `data preservation ${field}`);
  bounded(data.preInstallerFileCount, 1, 4096, "pre-installer file count");
  bounded(data.preInstallerBytes, 1, 512 * 1024 * 1024, "pre-installer bytes");
  canonicalUuid(data.demoCaseId, "demo case ID");
  canonicalUuid(data.demoRunId, "demo run ID");

  const exportIdentity = data.existingExportIdentity;
  exactKeys(exportIdentity, [
    "fixtureSha256", "initial", "afterUpgrade", "afterReinstall", "afterReportExport", "afterAppOnlyUninstall",
  ], "existing export identity preservation");
  assert(exportIdentity.fixtureSha256 === "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd", "existing export identity fixture digest changed");
  for (const field of ["initial", "afterUpgrade", "afterReinstall", "afterReportExport", "afterAppOnlyUninstall"]) {
    validateFileProof(exportIdentity[field], `existing export identity ${field}`);
    assert(JSON.stringify(exportIdentity[field]) === JSON.stringify(exportIdentity.initial), `existing export identity ${field} changed bytes or NTFS identity`);
  }
  assert(exportIdentity.initial.length === 32 && exportIdentity.initial.sha256 === exportIdentity.fixtureSha256, "existing export identity is not the exact 32-byte fixture");

  const report = data.beginnerReportExport;
  exactKeys(report, ["receipt", "independentFile"], "beginner report export evidence");
  const receipt = report.receipt;
  exactKeys(receipt, [
    "id", "case_id", "run_id", "created_at", "format", "path", "sha256",
    "coverage_manifest_path", "coverage_manifest_sha256", "signature", "public_key",
    "redaction_profile", "raw_artifacts_included", "raw_artifacts_omitted",
    "integrity_only_notice",
  ], "raw CLI CaseExport receipt");
  canonicalUuid(receipt.id, "beginner report export ID");
  canonicalUuid(receipt.case_id, "beginner report case ID");
  canonicalUuid(receipt.run_id, "beginner report run ID");
  assert(
    receipt.case_id === data.demoCaseId && receipt.run_id === data.demoRunId && receipt.format === "html",
    "beginner report receipt is for the wrong seeded case, run, or format",
  );
  assert(typeof receipt.created_at === "string" && Number.isFinite(Date.parse(receipt.created_at)), "beginner report creation time is invalid");
  assert(
    typeof receipt.path === "string" && path.win32.isAbsolute(receipt.path) &&
      path.win32.basename(receipt.path) === BEGINNER_REPORT_FILE,
    "beginner report runner destination is not one exact absolute Windows path",
  );
  sha256(receipt.sha256, "beginner report CLI digest");
  assert(receipt.coverage_manifest_path === null && receipt.coverage_manifest_sha256 === null, "HTML export unexpectedly has a companion coverage manifest");
  assert(receipt.signature === null && receipt.public_key === null, "ordinary beginner report unexpectedly carries signing fields");
  assert(receipt.redaction_profile === "standard", "beginner report did not use standard redaction");
  assert(receipt.raw_artifacts_included === 0, "beginner report unexpectedly includes raw artifacts");
  bounded(receipt.raw_artifacts_omitted, 0, 4096, "beginner report omitted raw-artifact count");
  assert(typeof receipt.integrity_only_notice === "string" && receipt.integrity_only_notice.length > 0, "beginner report integrity notice is absent");
  exactKeys(report.independentFile, ["file", "bytes", "sha256"], "independent beginner report file proof");
  assert(report.independentFile.file === BEGINNER_REPORT_FILE, "beginner report portable artifact filename changed");
  assert(path.win32.basename(receipt.path) === report.independentFile.file, "CLI receipt and portable report filename differ");
  bounded(report.independentFile.bytes, 1, 16 * 1024 * 1024, "beginner report bytes");
  sha256(report.independentFile.sha256, "independent beginner report digest");
  assert(receipt.sha256 === report.independentFile.sha256, "CLI and independent beginner report digests differ");

  const uninstall = data.appOnlyUninstallSnapshot;
  exactKeys(uninstall, [
    "beforeFileCount", "afterFileCount", "beforeBytes", "afterBytes", "beforeDigest", "afterDigest",
    "processLeaseAbsentBefore", "processLeaseAfter", "allNonLeaseProductDataPreserved",
  ], "app-only uninstall non-lease product-data snapshot");
  bounded(uninstall.beforeFileCount, 1, 4096, "pre-uninstall non-lease file count");
  bounded(uninstall.afterFileCount, 1, 4096, "post-uninstall non-lease file count");
  bounded(uninstall.beforeBytes, 1, 512 * 1024 * 1024, "pre-uninstall non-lease product-data bytes");
  bounded(uninstall.afterBytes, 1, 512 * 1024 * 1024, "post-uninstall non-lease product-data bytes");
  sha256(uninstall.beforeDigest, "pre-uninstall non-lease product-data digest");
  sha256(uninstall.afterDigest, "post-uninstall non-lease product-data digest");
  yes(uninstall.processLeaseAbsentBefore, "pre-uninstall root process-lease absence");
  exactKeys(uninstall.processLeaseAfter, ["length", "sha256", "volume", "fileIndex"], "post-uninstall root process lease");
  assert(uninstall.processLeaseAfter.length === 0, "post-uninstall root process lease is not empty");
  assert(uninstall.processLeaseAfter.sha256 === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "post-uninstall root process lease has unexpected bytes");
  bounded(uninstall.processLeaseAfter.volume, 0, 0xffff_ffff, "post-uninstall root process lease volume");
  positiveDecimal(uninstall.processLeaseAfter.fileIndex, "post-uninstall root process lease file index");
  yes(uninstall.allNonLeaseProductDataPreserved, "app-only uninstall non-lease product-data preservation");
  assert(uninstall.beforeFileCount === uninstall.afterFileCount && uninstall.beforeBytes === uninstall.afterBytes && uninstall.beforeDigest === uninstall.afterDigest, "app-only uninstall changed non-lease product data");

  const runtime = observations.managedRuntimeFilesystemSentinel;
  exactKeys(runtime, [
    "priorProviderNamespace", "priorVersionDirectory", "priorVersionPayloadDirectoryAbsentBeforeUpgrade",
    "priorVersionPayloadDirectoryAbsentAfterInstaller", "providerHomeSentinelPreserved", "registeredWslStateExercised",
  ], "managed-runtime filesystem sentinel");
  assert(runtime.priorProviderNamespace === PRIOR_WINDOWS_NSIS.runtimeManifestSha256.slice(0, 16), "managed-runtime namespace is not N-1");
  assert(runtime.priorVersionDirectory === "podman-machine-5.8.2-8b2257ace33ecb14", "managed-runtime versions directory is incorrect");
  for (const field of [
    "priorVersionPayloadDirectoryAbsentBeforeUpgrade", "priorVersionPayloadDirectoryAbsentAfterInstaller", "providerHomeSentinelPreserved",
  ]) yes(runtime[field], `managed runtime ${field}`);
  assert(runtime.registeredWslStateExercised === false, "normal upgrade fixture must not claim registered WSL coverage");

  exactKeys(observations.cleanup, [
    "uninstallerInvoked", "productRegistryRemovedByUninstaller",
    "fixtureTeardownInstallDirectoryRemoved", "fixtureTeardownPrivateDataRemoved",
    "fixtureTeardownRegistrySentinelRemoved",
  ], "fixture teardown observation");
  for (const [name, value] of Object.entries(observations.cleanup)) yes(value, `cleanup ${name}`);
}

async function validateBeginnerReport(file, observation) {
  const absolute = path.resolve(file);
  const { receipt, independentFile } = observation;
  assert(path.basename(absolute) === independentFile.file, "beginner report portable artifact filename is incorrect");
  const metadata = await lstat(absolute);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "beginner report is not a regular file");
  assert(metadata.size === independentFile.bytes, "beginner report byte length differs from the independent proof");
  assert((await sha256File(absolute)) === receipt.sha256 && receipt.sha256 === independentFile.sha256, "beginner report digest differs from the CLI receipt or independent proof");
  const html = await readFile(absolute, "utf8");
  for (const marker of [
    "<!doctype html><html lang=\"en\">",
    "ai-security-scanner / local case export",
    `<p>Selected run <code>${receipt.run_id}</code></p>`,
    "<h2>What you asked to scan</h2>",
    "<h2>What was actually tested</h2>",
    "<h2>What was not tested</h2>",
    "<section><h2>What to do next</h2>",
    "<h2>Problems found</h2>",
    "Integrity: unsigned HTML with SHA-256 retained in the local case.",
  ]) assert(html.includes(marker), `beginner report is missing required structure: ${marker}`);
}

async function createEvidence(args) {
  const current = await identity(args);
  const observationsPath = path.resolve(requireString(args, "observations"));
  const metadata = await lstat(observationsPath);
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size > 0 && metadata.size <= 256 * 1024, "upgrade observations are not one bounded regular file");
  const observations = JSON.parse(await readFile(observationsPath, "utf8"));
  validateObservations(observations, current.version, current.installer);
  await validateBeginnerReport(requireString(args, "beginner-report"), observations.dataPreservation.beginnerReportExport);
  const evidence = {
    schemaVersion: SCHEMA_VERSION,
    qualification: "windows_nsis_n_minus_one_data_preservation_fixture",
    releaseIdentity: { product: "ai-security-scanner", version: current.version, tag: current.tag, sourceCommit: current.commit },
    platform: PLATFORM,
    runner: RUNNER,
    installerType: INSTALLER_TYPE,
    fixtureScope: { ...observations.fixtureScope },
    candidateInstaller: { ...current.installer },
    priorReleasePin: { ...PRIOR_WINDOWS_NSIS },
    observations,
  };
  const output = path.resolve(requireString(args, "out"));
  await writeJsonAtomic(output, evidence);
  process.stdout.write(`Created Windows NSIS N-1 data-preservation fixture evidence at ${output}\n`);
}

async function validateEvidence(args) {
  const current = await identity(args);
  const evidencePath = path.resolve(requireString(args, "file"));
  const metadata = await lstat(evidencePath);
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size > 0 && metadata.size <= 256 * 1024, "upgrade evidence is not one bounded regular file");
  const evidence = JSON.parse(await readFile(evidencePath, "utf8"));
  exactKeys(evidence, [
    "schemaVersion", "qualification", "releaseIdentity", "platform", "runner", "installerType",
    "fixtureScope", "candidateInstaller", "priorReleasePin", "observations",
  ], "Windows NSIS upgrade evidence");
  assert(
    evidence.schemaVersion === SCHEMA_VERSION &&
      evidence.qualification === "windows_nsis_n_minus_one_data_preservation_fixture",
    "upgrade data-preservation fixture evidence identity is incorrect",
  );
  assert(JSON.stringify(evidence.releaseIdentity) === JSON.stringify({
    product: "ai-security-scanner", version: current.version, tag: current.tag, sourceCommit: current.commit,
  }), "upgrade evidence release identity changed");
  assert(evidence.platform === PLATFORM && evidence.runner === RUNNER && evidence.installerType === INSTALLER_TYPE, "upgrade evidence execution identity changed");
  validateWindowsNsisUpgradeFixtureScope(evidence.fixtureScope);
  assert(
    JSON.stringify(evidence.fixtureScope) === JSON.stringify(evidence.observations.fixtureScope),
    "upgrade fixture scope differs between evidence and observations",
  );
  assert(JSON.stringify(evidence.candidateInstaller) === JSON.stringify(current.installer), "upgrade evidence installer binding changed");
  assert(JSON.stringify(evidence.priorReleasePin) === JSON.stringify(PRIOR_WINDOWS_NSIS), "upgrade evidence N-1 pin changed");
  validateObservations(evidence.observations, current.version, current.installer);
  await validateBeginnerReport(requireString(args, "beginner-report"), evidence.observations.dataPreservation.beginnerReportExport);
  process.stdout.write(`Validated Windows NSIS N-1 data-preservation fixture evidence for ${current.tag}\n`);
  return evidence;
}

export async function validateWindowsNsisUpgradeDataPreservationFixtureFile({
  file,
  artifactDirectory,
  version,
  tag,
  commit,
  beginnerReportFile,
}) {
  return validateEvidence(new Map([
    ["file", file],
    ["artifact-dir", artifactDirectory],
    ["version", version],
    ["tag", tag],
    ["commit", commit],
    ["beginner-report", beginnerReportFile],
  ]));
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);
  if (command === "create") return createEvidence(args);
  if (command === "validate") return validateEvidence(args);
  throw new Error("usage: windows-nsis-upgrade-evidence.mjs <create|validate> --artifact-dir <dir> --version <semver> --tag <tag> --commit <sha> --beginner-report <beginner-report.html> [--observations <json>|--file <json>] [--out <json>]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(main);
}
