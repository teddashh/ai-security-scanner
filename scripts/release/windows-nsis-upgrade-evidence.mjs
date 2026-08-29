import { createHash } from "node:crypto";
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
  runtimeManifestSha256:
    "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f",
  machineImageSha256:
    "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968",
});

const SCHEMA_VERSION = 1;
const PLATFORM = "windows-x86_64";
const INSTALLER_TYPE = "nsis";
const RUNNER = "windows-2025";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, keys, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()),
    `${label} fields are not the strict qualification set`,
  );
}

function assertSha256(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{64}$/u.test(value), `${label} is not a SHA-256`);
}

function assertTrue(value, label) {
  assert(value === true, `${label} was not proven`);
}

function assertBoundedInteger(value, minimum, maximum, label) {
  assert(
    Number.isSafeInteger(value) && value >= minimum && value <= maximum,
    `${label} is outside its qualification bound`,
  );
}

function validatePublicSigningIdentity(publicKeyBase64, keyId, label) {
  assertSha256(keyId, `${label} key ID`);
  assert(
    typeof publicKeyBase64 === "string" && /^[A-Za-z0-9+/]{43}=$/u.test(publicKeyBase64),
    `${label} public key is not canonical base64`,
  );
  const publicKey = Buffer.from(publicKeyBase64, "base64");
  assert(publicKey.length === 32, `${label} public key is not Ed25519-sized`);
  assert(
    createHash("sha256").update(publicKey).digest("hex") === keyId,
    `${label} key ID is not the public-key SHA-256`,
  );
}

function validateObservations(observations, currentVersion, currentInstaller) {
  assertExactKeys(
    observations,
    [
      "schemaVersion",
      "scenario",
      "platform",
      "runner",
      "priorRelease",
      "candidate",
      "installation",
      "dataPreservation",
      "managedRuntimeFilesystemSentinel",
      "cleanup",
    ],
    "Windows NSIS upgrade observations",
  );
  assert(observations.schemaVersion === SCHEMA_VERSION, "Windows NSIS upgrade observation schema is unsupported");
  assert(observations.scenario === "real_n_minus_one_nsis_upgrade", "Windows NSIS upgrade scenario is not real N-1 installation");
  assert(observations.platform === PLATFORM, "Windows NSIS upgrade platform is incorrect");
  assert(observations.runner === RUNNER, "Windows NSIS upgrade runner is incorrect");

  assertExactKeys(
    observations.priorRelease,
    [
      "version",
      "tag",
      "installerFile",
      "installerBytes",
      "installerSha256",
      "downloadUrl",
      "runtimeManifestSha256",
      "machineImageSha256",
    ],
    "prior release observation",
  );
  const prior = observations.priorRelease;
  assert(prior.version === PRIOR_WINDOWS_NSIS.version, "prior release version is not the pinned N-1");
  assert(prior.tag === PRIOR_WINDOWS_NSIS.tag, "prior release tag is not the pinned N-1");
  assert(prior.installerFile === PRIOR_WINDOWS_NSIS.file, "prior installer filename is not pinned");
  assert(prior.installerBytes === PRIOR_WINDOWS_NSIS.bytes, "prior installer byte length is not pinned");
  assert(prior.installerSha256 === PRIOR_WINDOWS_NSIS.sha256, "prior installer digest is not pinned");
  assert(prior.downloadUrl === PRIOR_WINDOWS_NSIS.url, "prior installer URL is not pinned");
  assert(
    prior.runtimeManifestSha256 === PRIOR_WINDOWS_NSIS.runtimeManifestSha256,
    "prior managed-runtime manifest digest is not pinned",
  );
  assert(
    prior.machineImageSha256 === PRIOR_WINDOWS_NSIS.machineImageSha256,
    "prior managed-runtime machine-image digest is not pinned",
  );

  assertExactKeys(
    observations.candidate,
    ["version", "installerFile", "installerBytes", "installerSha256"],
    "candidate observation",
  );
  assert(observations.candidate.version === currentVersion, "installed candidate version is incorrect");
  assert(observations.candidate.installerFile === currentInstaller.file, "candidate filename differs from its release manifest");
  assert(observations.candidate.installerBytes === currentInstaller.bytes, "candidate byte length differs from its release manifest");
  assert(observations.candidate.installerSha256 === currentInstaller.sha256, "candidate digest differs from its release manifest");

  assertExactKeys(
    observations.installation,
    [
      "priorCliVersion",
      "candidateCliVersion",
      "sameCanonicalInstallDirectory",
      "registryHive",
      "registryEntryIdentityPreserved",
      "displayVersionUpdated",
      "uninstallerReplaced",
      "unattendedMode",
      "sameVersionSilentReinstallCompleted",
      "transitionReceiptSurvivedSameVersionReinstall",
      "transitionReceipt",
    ],
    "installation observation",
  );
  assert(observations.installation.priorCliVersion === PRIOR_WINDOWS_NSIS.version, "prior CLI was not N-1");
  assert(observations.installation.candidateCliVersion === currentVersion, "candidate CLI version is incorrect");
  assertTrue(observations.installation.sameCanonicalInstallDirectory, "same canonical install directory");
  assert(observations.installation.registryHive === "HKEY_CURRENT_USER", "NSIS upgrade did not use the current-user registry hive");
  assertTrue(observations.installation.registryEntryIdentityPreserved, "registry entry identity preservation");
  assertTrue(observations.installation.displayVersionUpdated, "registry DisplayVersion update");
  assertTrue(observations.installation.uninstallerReplaced, "candidate uninstaller replacement");
  assert(observations.installation.unattendedMode === "silent", "normal N-1 upgrade did not exercise /S");
  assertTrue(observations.installation.sameVersionSilentReinstallCompleted, "same-version silent reinstall");
  assertTrue(
    observations.installation.transitionReceiptSurvivedSameVersionReinstall,
    "transition receipt survival across same-version reinstall",
  );
  assert(
    observations.installation.transitionReceipt === `uninstalled-${PRIOR_WINDOWS_NSIS.version}`,
    "normal NSIS upgrade did not record a completed N-1 uninstaller transition",
  );

  const data = observations.dataPreservation;
  assertExactKeys(
    data,
    [
      "defaultLocalDataDirectoryUsed",
      "preInstallerFileCount",
      "preInstallerBytes",
      "exactPreInstallerSnapshotPreserved",
      "sentinelPreserved",
      "demoCaseId",
      "demoCasePreserved",
      "privateSigningMaterialBytePreserved",
      "signingKeyIdBefore",
      "signingKeyIdAfter",
      "publicKeyBase64Before",
      "publicKeyBase64After",
      "privateSigningKeyProtected",
      "publicIdentitySummaryExact",
      "durableIdentityDocumentPresent",
      "identityDocumentBytes",
      "identityDocumentCompactSha256",
      "identityDocumentProtected",
      "durableIdentityAnchorPresent",
      "identityAnchorBytes",
      "identityAnchorProtected",
      "anchorSchemaVersion",
      "anchorIdentityDocumentSha256",
      "anchorDigestVerified",
      "anchorMatchesIdentityDocument",
      "identitySelfSignatureVerifiedByCandidate",
      "rotationIntentAbsent",
      "continuityEvent",
      "identityKeyId",
      "identityPublicKeyBase64",
      "firstBundleValid",
      "secondBundleValid",
    ],
    "data-preservation observation",
  );
  assertTrue(data.defaultLocalDataDirectoryUsed, "default LocalAppData directory use");
  assertBoundedInteger(data.preInstallerFileCount, 4, 4096, "pre-installer file count");
  assertBoundedInteger(data.preInstallerBytes, 1, 512 * 1024 * 1024, "pre-installer byte count");
  assertTrue(data.exactPreInstallerSnapshotPreserved, "pre-installer byte snapshot preservation");
  assertTrue(data.sentinelPreserved, "local sentinel preservation");
  assert(
    typeof data.demoCaseId === "string" && /^[0-9a-f]{8}-[0-9a-f-]{27,}$/u.test(data.demoCaseId),
    "synthetic case ID is malformed",
  );
  assertTrue(data.demoCasePreserved, "synthetic case preservation");
  assertTrue(data.privateSigningMaterialBytePreserved, "private signing material byte preservation");
  assertTrue(data.privateSigningKeyProtected, "managed signing key protection");
  assertTrue(data.publicIdentitySummaryExact, "public signing identity summary contract");
  assertTrue(data.durableIdentityDocumentPresent, "durable signing identity document");
  assertBoundedInteger(data.identityDocumentBytes, 1, 64 * 1024, "durable signing identity document bytes");
  assertSha256(data.identityDocumentCompactSha256, "durable signing identity document compact digest");
  assertTrue(data.identityDocumentProtected, "durable signing identity document protection");
  assertTrue(data.durableIdentityAnchorPresent, "durable signing identity anchor");
  assertBoundedInteger(data.identityAnchorBytes, 1, 64 * 1024, "durable signing identity anchor bytes");
  assertTrue(data.identityAnchorProtected, "durable signing identity anchor protection");
  assert(data.anchorSchemaVersion === "1", "durable signing identity anchor schema is not v1");
  assertSha256(data.anchorIdentityDocumentSha256, "durable signing identity anchor digest");
  assert(
    data.anchorIdentityDocumentSha256 === data.identityDocumentCompactSha256,
    "durable signing identity anchor digest differs from the identity document",
  );
  assertTrue(data.anchorDigestVerified, "durable signing identity anchor digest verification");
  assertTrue(data.anchorMatchesIdentityDocument, "durable signing identity anchor/document equality");
  assertTrue(data.identitySelfSignatureVerifiedByCandidate, "durable signing identity self-signature verification");
  assertTrue(data.rotationIntentAbsent, "completed signing identity adoption rotation-intent cleanup");
  assert(data.continuityEvent === "legacy_key_adopted", "candidate did not record legacy-key adoption");
  assertTrue(data.firstBundleValid, "N-1 signed bundle verification");
  assertTrue(data.secondBundleValid, "candidate signed bundle verification");
  validatePublicSigningIdentity(data.publicKeyBase64Before, data.signingKeyIdBefore, "N-1 signing identity");
  validatePublicSigningIdentity(data.publicKeyBase64After, data.signingKeyIdAfter, "candidate signing identity");
  assert(data.signingKeyIdAfter === data.signingKeyIdBefore, "integrity signing key ID changed during NSIS upgrade");
  assert(data.publicKeyBase64After === data.publicKeyBase64Before, "integrity signing public key changed during NSIS upgrade");
  assert(data.identityKeyId === data.signingKeyIdBefore, "durable identity key ID differs from both bundles");
  assert(
    data.identityPublicKeyBase64 === data.publicKeyBase64Before,
    "durable identity public key differs from both bundles",
  );

  const ghost = observations.managedRuntimeFilesystemSentinel;
  assertExactKeys(
    ghost,
    [
      "priorProviderNamespace",
      "priorVersionDirectory",
      "priorVersionPayloadDirectoryAbsentBeforeUpgrade",
      "priorVersionPayloadDirectoryAbsentAfterInstaller",
      "providerHomeSentinelPreserved",
      "registeredWslStateExercised",
    ],
    "managed-runtime ghost observation",
  );
  assert(
    ghost.priorProviderNamespace === PRIOR_WINDOWS_NSIS.runtimeManifestSha256.slice(0, 16),
    "managed-runtime sentinel provider namespace is not N-1",
  );
  assert(
    ghost.priorVersionDirectory === "podman-machine-5.8.2-8b2257ace33ecb14",
    "managed-runtime sentinel uses the wrong N-1 versions directory",
  );
  assertTrue(ghost.priorVersionPayloadDirectoryAbsentBeforeUpgrade, "absent N-1 versions payload setup");
  assertTrue(ghost.priorVersionPayloadDirectoryAbsentAfterInstaller, "absent N-1 versions payload preservation");
  assertTrue(ghost.providerHomeSentinelPreserved, "N-1 provider-home preservation");
  assert(
    ghost.registeredWslStateExercised === false,
    "normal NSIS qualification must not claim that its filesystem sentinel is a registered WSL distribution",
  );

  assertExactKeys(
    observations.cleanup,
    ["candidateUninstalled", "installDirectoryRemoved", "privateDataRemoved", "registrySentinelRemoved"],
    "cleanup observation",
  );
  for (const [name, value] of Object.entries(observations.cleanup)) {
    assertTrue(value, `cleanup ${name}`);
  }
}

async function currentNsisInstaller(artifactDirectory, version, tag, commit) {
  const manifestPath = path.join(artifactDirectory, "installers-windows-x86_64.json");
  const manifest = await readJson(manifestPath);
  assert(manifest.schemaVersion === 2, "Windows installer manifest schema is unsupported");
  assert(manifest.product === "ai-security-scanner", "Windows installer manifest product is incorrect");
  assert(manifest.platform === PLATFORM, "Windows installer manifest platform is incorrect");
  assert(manifest.version === version && manifest.tag === tag, "Windows installer manifest version/tag mismatch");
  assert(manifest.sourceCommit === commit, "Windows installer manifest source commit mismatch");
  const installers = manifest.installers?.filter((item) => item.bundleType === INSTALLER_TYPE) ?? [];
  assert(installers.length === 1, "Windows installer manifest must contain exactly one NSIS installer");
  const installer = installers[0];
  assertExactKeys(installer, ["bundleType", "file", "bytes", "sha256"], "candidate NSIS installer record");
  assert(path.basename(installer.file) === installer.file, "candidate NSIS installer path is not flat");
  assertBoundedInteger(installer.bytes, 1, 256 * 1024 * 1024, "candidate NSIS installer bytes");
  assertSha256(installer.sha256, "candidate NSIS installer digest");
  const absolute = path.join(artifactDirectory, installer.file);
  const metadata = await lstat(absolute);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "candidate NSIS installer is not a regular file");
  assert(metadata.size === installer.bytes, "candidate NSIS installer byte length mismatch");
  assert((await sha256File(absolute)) === installer.sha256, "candidate NSIS installer digest mismatch");
  return installer;
}

async function validateIdentity(args) {
  const artifactDirectory = path.resolve(requireString(args, "artifact-dir"));
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  assert(
    isSemver(version) && version === "0.1.8" && tag === `v${version}`,
    "candidate version/tag is not the bounded v0.1.7 to v0.1.8 upgrade",
  );
  assert(/^[0-9a-f]{40}$/u.test(commit), "candidate commit is not a full lowercase Git object ID");
  const installer = await currentNsisInstaller(artifactDirectory, version, tag, commit);
  return { artifactDirectory, version, tag, commit, installer };
}

async function createEvidence(args) {
  const identity = await validateIdentity(args);
  const observationsPath = path.resolve(requireString(args, "observations"));
  const observationsMetadata = await lstat(observationsPath);
  assert(
    observationsMetadata.isFile() && !observationsMetadata.isSymbolicLink() && observationsMetadata.size <= 256 * 1024,
    "Windows NSIS upgrade observations are not one bounded regular file",
  );
  const observations = JSON.parse(await readFile(observationsPath, "utf8"));
  validateObservations(observations, identity.version, identity.installer);
  const evidence = {
    schemaVersion: SCHEMA_VERSION,
    qualification: "windows_nsis_n_minus_one_upgrade_and_data_preservation",
    releaseIdentity: {
      product: "ai-security-scanner",
      version: identity.version,
      tag: identity.tag,
      sourceCommit: identity.commit,
    },
    platform: PLATFORM,
    runner: RUNNER,
    installerType: INSTALLER_TYPE,
    candidateInstaller: {
      file: identity.installer.file,
      bytes: identity.installer.bytes,
      sha256: identity.installer.sha256,
    },
    priorReleasePin: { ...PRIOR_WINDOWS_NSIS },
    observations,
  };
  const output = path.resolve(requireString(args, "out"));
  await writeJsonAtomic(output, evidence);
  process.stdout.write(`Created strict Windows NSIS N-1 upgrade evidence at ${output}\n`);
}

async function validateEvidence(args) {
  const identity = await validateIdentity(args);
  const evidencePath = path.resolve(requireString(args, "file"));
  const metadata = await lstat(evidencePath);
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= 256 * 1024, "upgrade evidence is not one bounded regular file");
  const evidence = JSON.parse(await readFile(evidencePath, "utf8"));
  assertExactKeys(
    evidence,
    [
      "schemaVersion",
      "qualification",
      "releaseIdentity",
      "platform",
      "runner",
      "installerType",
      "candidateInstaller",
      "priorReleasePin",
      "observations",
    ],
    "Windows NSIS upgrade evidence",
  );
  assert(evidence.schemaVersion === SCHEMA_VERSION, "upgrade evidence schema is unsupported");
  assert(
    evidence.qualification === "windows_nsis_n_minus_one_upgrade_and_data_preservation",
    "upgrade evidence qualification ID is incorrect",
  );
  assertExactKeys(evidence.releaseIdentity, ["product", "version", "tag", "sourceCommit"], "release identity");
  assert(evidence.releaseIdentity.product === "ai-security-scanner", "upgrade evidence product is incorrect");
  assert(evidence.releaseIdentity.version === identity.version, "upgrade evidence version mismatch");
  assert(evidence.releaseIdentity.tag === identity.tag, "upgrade evidence tag mismatch");
  assert(evidence.releaseIdentity.sourceCommit === identity.commit, "upgrade evidence commit mismatch");
  assert(evidence.platform === PLATFORM && evidence.runner === RUNNER, "upgrade evidence execution platform mismatch");
  assert(evidence.installerType === INSTALLER_TYPE, "upgrade evidence installer type is incorrect");
  assert(
    JSON.stringify(evidence.candidateInstaller) ===
      JSON.stringify({ file: identity.installer.file, bytes: identity.installer.bytes, sha256: identity.installer.sha256 }),
    "upgrade evidence candidate installer binding mismatch",
  );
  assert(
    JSON.stringify(evidence.priorReleasePin) === JSON.stringify(PRIOR_WINDOWS_NSIS),
    "upgrade evidence N-1 pin changed",
  );
  validateObservations(evidence.observations, identity.version, identity.installer);
  process.stdout.write(`Validated Windows NSIS N-1 upgrade evidence for ${identity.tag}\n`);
  return evidence;
}

export async function validateWindowsNsisUpgradeEvidenceFile({
  file,
  artifactDirectory,
  version,
  tag,
  commit,
}) {
  return validateEvidence(new Map([
    ["file", file],
    ["artifact-dir", artifactDirectory],
    ["version", version],
    ["tag", tag],
    ["commit", commit],
  ]));
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);
  if (command === "create") return createEvidence(args);
  if (command === "validate") return validateEvidence(args);
  throw new Error("usage: windows-nsis-upgrade-evidence.mjs <create|validate> [arguments]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(main);
}
