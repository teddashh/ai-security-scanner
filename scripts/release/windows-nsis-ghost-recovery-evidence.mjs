import { createHash } from "node:crypto";
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

const SCHEMA_VERSION = 1;
const PLATFORM = "windows-x86_64";
const RUNNER = "windows-2025";
const INSTALLER_TYPE = "nsis";
const OLD_DISTRIBUTION = "podman-assm1-win-x64-e2b6cbcadd8b";
const OLD_VERSION_DIRECTORY = "podman-machine-5.8.2-8b2257ace33ecb14";
const CONSUMED_PROOF_SCHEMA = "ai-security-scanner.managed-wsl-ghost-migration-consumed/v1";
const CANDIDATE_RUNTIME_MANIFEST_SHA256 =
  "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a";
const SELF_TEST_SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567";

export const PRIOR_GHOST_RELEASE = Object.freeze({
  version: "0.1.7",
  tag: "v0.1.7",
  installerFile: "ai-security-scanner_0.1.7_x64-setup.exe",
  installerBytes: 38_730_365,
  installerSha256: "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a",
  downloadUrl:
    "https://github.com/teddashh/ai-security-scanner/releases/download/v0.1.7/ai-security-scanner_0.1.7_x64-setup.exe",
  runtimeManifestSha256:
    "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f",
  machineImageSha256:
    "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968",
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, keys, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()),
    `${label} fields changed`,
  );
}

function sha256(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{64}$/u.test(value), `${label} is not SHA-256`);
}

function isBoundedReleaseSelfTestFixture(artifactDirectory, commit) {
  if (commit !== SELF_TEST_SOURCE_COMMIT) return false;
  const fixtureRoot = path.resolve(PROJECT_ROOT, "target", "release-self-test");
  const relative = path.relative(fixtureRoot, artifactDirectory);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function yes(value, label) {
  assert(value === true, `${label} was not proven`);
}

function bounded(value, minimum, maximum, label) {
  assert(Number.isSafeInteger(value) && value >= minimum && value <= maximum, `${label} is outside its bound`);
}

function validateSigningIdentity(publicKeyBase64, keyId, label) {
  sha256(keyId, `${label} key ID`);
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

async function candidateIdentity(
  artifactDirectory,
  version,
  tag,
  commit,
  expectedRuntimeManifestSha256,
) {
  const installerManifest = await readJson(
    path.join(artifactDirectory, "installers-windows-x86_64.json"),
  );
  assert(installerManifest.schemaVersion === 2, "Windows installer manifest schema is unsupported");
  assert(installerManifest.product === "ai-security-scanner", "Windows installer product is incorrect");
  assert(installerManifest.platform === PLATFORM, "Windows installer platform is incorrect");
  assert(
    installerManifest.version === version && installerManifest.tag === tag && installerManifest.sourceCommit === commit,
    "Windows installer release identity differs from the candidate",
  );
  const installers = installerManifest.installers?.filter((item) => item.bundleType === INSTALLER_TYPE) ?? [];
  assert(installers.length === 1, "candidate must contain exactly one NSIS installer");
  const installer = installers[0];
  exactKeys(installer, ["bundleType", "file", "bytes", "sha256"], "candidate NSIS record");
  assert(path.basename(installer.file) === installer.file, "candidate NSIS path is not flat");
  bounded(installer.bytes, 1, 256 * 1024 * 1024, "candidate NSIS bytes");
  sha256(installer.sha256, "candidate NSIS digest");
  const installerPath = path.join(artifactDirectory, installer.file);
  const metadata = await lstat(installerPath);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "candidate NSIS is not a regular file");
  assert(metadata.size === installer.bytes, "candidate NSIS byte length changed");
  assert((await sha256File(installerPath)) === installer.sha256, "candidate NSIS digest changed");

  const runtimeFile = path.join(artifactDirectory, "managed-runtime-windows-x86_64.manifest.json");
  const runtimeMetadata = await lstat(runtimeFile);
  assert(runtimeMetadata.isFile() && !runtimeMetadata.isSymbolicLink(), "candidate runtime manifest is not regular");
  const runtime = await readJson(runtimeFile);
  assert(runtime.schema_version === "3", "candidate runtime manifest schema is unsupported");
  assert(
    runtime.management_contract_revision === "2026-08-29.1",
    "candidate runtime management contract revision is unsupported",
  );
  assert(runtime.bundle_id === "podman-machine" && runtime.runtime_version === "5.8.2", "candidate runtime identity changed");
  const targets = runtime.targets?.filter(
    (target) => target.operating_system === "windows" && target.architecture === "x86_64" && target.provider === "wsl",
  ) ?? [];
  assert(targets.length === 1, "candidate runtime must have one Windows x86_64 WSL target");
  sha256(targets[0].machine_image?.sha256, "candidate machine-image digest");
  const runtimeManifestSha256 = await sha256File(runtimeFile);
  assert(
    runtimeManifestSha256 === expectedRuntimeManifestSha256,
    "candidate runtime manifest differs from the reviewed v0.1.8 identity",
  );
  return {
    installer,
    runtimeManifestSha256,
    machineImageSha256: targets[0].machine_image.sha256,
    providerNamespace: runtimeManifestSha256.slice(0, 16),
  };
}

function validateObservations(observations, identity, version) {
  exactKeys(
    observations,
    [
      "schemaVersion",
      "scenario",
      "platform",
      "runner",
      "priorRelease",
      "candidate",
      "ghostFixture",
      "installerMigration",
      "runtimeRecovery",
      "dataPreservation",
      "cleanup",
    ],
    "ghost-recovery observations",
  );
  assert(observations.schemaVersion === SCHEMA_VERSION, "ghost-recovery schema is unsupported");
  assert(
    observations.scenario === "real_registered_wsl_n_minus_one_ghost_install_recovery",
    "ghost-recovery scenario is not the real registered-WSL fixture",
  );
  assert(observations.platform === PLATFORM && observations.runner === RUNNER, "ghost-recovery runner is incorrect");
  exactKeys(observations.priorRelease, Object.keys(PRIOR_GHOST_RELEASE), "prior ghost release");
  assert(
    JSON.stringify(observations.priorRelease) === JSON.stringify(PRIOR_GHOST_RELEASE),
    "prior ghost release differs from the immutable v0.1.7 pin",
  );

  exactKeys(
    observations.candidate,
    ["version", "installerFile", "installerBytes", "installerSha256", "runtimeManifestSha256", "machineImageSha256"],
    "ghost candidate",
  );
  const candidate = observations.candidate;
  assert(candidate.version === version, "ghost candidate version is wrong");
  assert(candidate.installerFile === identity.installer.file, "ghost candidate filename changed");
  assert(candidate.installerBytes === identity.installer.bytes, "ghost candidate bytes changed");
  assert(candidate.installerSha256 === identity.installer.sha256, "ghost candidate installer digest changed");
  assert(candidate.runtimeManifestSha256 === identity.runtimeManifestSha256, "ghost candidate runtime digest changed");
  assert(candidate.machineImageSha256 === identity.machineImageSha256, "ghost candidate image digest changed");

  const fixture = observations.ghostFixture;
  exactKeys(
    fixture,
    [
      "defaultInstallDirectoryUsed",
      "priorCliVersion",
      "oldRegistryIdentityExact",
      "oldRuntimeInstalled",
      "oldRuntimeStarted",
      "oldRuntimeStopped",
      "oldProviderNamespace",
      "oldProviderCryptographicIdentityPresent",
      "distributionName",
      "registeredWslStateExercised",
      "registrationBoundToOldProvider",
      "oldVersionDirectory",
      "oldVersionPayloadDigestVerifiedBeforeRemoval",
      "oldVersionPayloadDirectoryRemoved",
      "oldDesktopRemoved",
      "oldUninstallerRemoved",
    ],
    "real ghost fixture",
  );
  yes(fixture.defaultInstallDirectoryUsed, "default NSIS install directory");
  assert(fixture.priorCliVersion === PRIOR_GHOST_RELEASE.version, "ghost fixture CLI is not v0.1.7");
  for (const field of [
    "oldRegistryIdentityExact",
    "oldRuntimeInstalled",
    "oldRuntimeStarted",
    "oldRuntimeStopped",
    "oldProviderCryptographicIdentityPresent",
    "registeredWslStateExercised",
    "registrationBoundToOldProvider",
    "oldVersionPayloadDigestVerifiedBeforeRemoval",
    "oldVersionPayloadDirectoryRemoved",
    "oldDesktopRemoved",
    "oldUninstallerRemoved",
  ]) yes(fixture[field], `ghost fixture ${field}`);
  assert(
    fixture.oldProviderNamespace === PRIOR_GHOST_RELEASE.runtimeManifestSha256.slice(0, 16),
    "ghost fixture provider namespace is not pinned N-1",
  );
  assert(fixture.distributionName === OLD_DISTRIBUTION, "ghost fixture distribution is not deterministic N-1");
  assert(fixture.oldVersionDirectory === OLD_VERSION_DIRECTORY, "ghost fixture removed the wrong versions entry");

  const migration = observations.installerMigration;
  exactKeys(
    migration,
    [
      "candidateInstallerCompleted",
      "transitionReceipt",
      "candidateCliVersion",
      "registryVersionUpdated",
      "registryIdentityExact",
      "candidateDesktopRestored",
      "candidateUninstallerRestored",
      "candidateRuntimeResourceMatchesRelease",
      "exactPrivateDataSnapshotPreserved",
      "sameVersionSilentReinstallCompleted",
      "transitionReceiptSurvivedSameVersionReinstall",
    ],
    "installer migration",
  );
  for (const field of [
    "candidateInstallerCompleted",
    "registryVersionUpdated",
    "registryIdentityExact",
    "candidateDesktopRestored",
    "candidateUninstallerRestored",
    "candidateRuntimeResourceMatchesRelease",
    "exactPrivateDataSnapshotPreserved",
    "sameVersionSilentReinstallCompleted",
    "transitionReceiptSurvivedSameVersionReinstall",
  ]) yes(migration[field], `installer migration ${field}`);
  assert(migration.transitionReceipt === "recovered-ghost-v0.1.7", "bounded ghost installer branch was not observed");
  assert(migration.candidateCliVersion === version, "ghost migration did not install the candidate CLI");

  const recovery = observations.runtimeRecovery;
  exactKeys(
    recovery,
    [
      "startSucceeded",
      "noManualActionFallback",
      "runningAndAvailable",
      "sameDistributionName",
      "registrationMovedToCurrentProvider",
      "currentProviderNamespace",
      "oldProviderRemoved",
      "recoveryId",
      "durableIntentPresent",
      "intentProofValid",
      "intentSchemaVersion",
      "intentOwnershipBasis",
      "intentManifestSha256",
      "intentMachineImageSha256",
      "intentSourceProviderManifestSha256",
      "intentTransitionReceipt",
      "receiptConsumption",
      "durableArchivePresent",
      "archiveBytes",
      "archiveSha256",
      "backupReceiptValid",
      "importReceiptValid",
      "backupAndImportAgree",
      "pendingRecoveryAbsent",
      "temporaryWorkspaceAbsent",
      "quarantineDistributionAbsent",
    ],
    "managed-runtime ghost recovery",
  );
  for (const field of [
    "startSucceeded",
    "noManualActionFallback",
    "runningAndAvailable",
    "sameDistributionName",
    "registrationMovedToCurrentProvider",
    "oldProviderRemoved",
    "durableIntentPresent",
    "intentProofValid",
    "durableArchivePresent",
    "backupReceiptValid",
    "importReceiptValid",
    "backupAndImportAgree",
    "pendingRecoveryAbsent",
    "temporaryWorkspaceAbsent",
    "quarantineDistributionAbsent",
  ]) yes(recovery[field], `runtime recovery ${field}`);
  assert(recovery.currentProviderNamespace === identity.providerNamespace, "recovered provider namespace is not the candidate");
  assert(typeof recovery.recoveryId === "string" && /^[0-9a-f]{32}$/u.test(recovery.recoveryId), "recovery ID is not UUID-simple");
  assert(
    recovery.intentSchemaVersion === "ai-security-scanner.managed-wsl-recovery-intent/v2",
    "recovery intent schema is not the bounded migration contract",
  );
  assert(
    recovery.intentOwnershipBasis === "bounded_n_minus_one_ghost_migration",
    "recovery intent did not prove the bounded N-1 ownership basis",
  );
  assert(
    recovery.intentManifestSha256 === identity.runtimeManifestSha256,
    "recovery intent is not bound to the candidate runtime manifest",
  );
  assert(
    recovery.intentMachineImageSha256 === identity.machineImageSha256,
    "recovery intent is not bound to the candidate machine image",
  );
  assert(
    recovery.intentSourceProviderManifestSha256 === PRIOR_GHOST_RELEASE.runtimeManifestSha256,
    "recovery intent is not bound to the immutable N-1 provider manifest",
  );
  assert(
    recovery.intentTransitionReceipt === migration.transitionReceipt,
    "recovery intent is not bound to the exact installer transition receipt",
  );

  const consumption = recovery.receiptConsumption;
  exactKeys(
    consumption,
    [
      "registryValueAbsent",
      "proofPathExact",
      "proofPresent",
      "proofProtected",
      "proofBytes",
      "proofSha256",
      "schemaVersion",
      "recoveryId",
      "installTransitionReceipt",
      "sourceProviderManifestSha256",
      "manifestSha256",
      "machineImageSha256",
      "machineName",
      "distributionName",
      "proofRetainedAfterRuntimePurge",
      "proofRetainedUntilExplicitPrivateDataCleanup",
    ],
    "ghost migration receipt consumption",
  );
  for (const field of [
    "registryValueAbsent",
    "proofPathExact",
    "proofPresent",
    "proofProtected",
    "proofRetainedAfterRuntimePurge",
    "proofRetainedUntilExplicitPrivateDataCleanup",
  ]) yes(consumption[field], `ghost migration receipt consumption ${field}`);
  bounded(consumption.proofBytes, 1, 64 * 1024, "consumed proof bytes");
  sha256(consumption.proofSha256, "consumed proof digest");
  assert(consumption.schemaVersion === CONSUMED_PROOF_SCHEMA, "consumed proof schema changed");
  assert(
    typeof consumption.recoveryId === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(consumption.recoveryId) &&
      consumption.recoveryId.replaceAll("-", "") === recovery.recoveryId,
    "consumed proof recovery ID is not the exact recovery attempt",
  );
  assert(
    consumption.installTransitionReceipt === migration.transitionReceipt &&
      consumption.installTransitionReceipt === recovery.intentTransitionReceipt,
    "consumed proof is not bound to the exact installer transition receipt",
  );
  assert(
    consumption.sourceProviderManifestSha256 === PRIOR_GHOST_RELEASE.runtimeManifestSha256 &&
      consumption.sourceProviderManifestSha256 === recovery.intentSourceProviderManifestSha256,
    "consumed proof is not bound to the immutable N-1 provider manifest",
  );
  assert(
    consumption.manifestSha256 === identity.runtimeManifestSha256 &&
      consumption.manifestSha256 === recovery.intentManifestSha256,
    "consumed proof is not bound to the candidate runtime manifest",
  );
  assert(
    consumption.machineImageSha256 === identity.machineImageSha256 &&
      consumption.machineImageSha256 === recovery.intentMachineImageSha256,
    "consumed proof is not bound to the candidate machine image",
  );
  assert(consumption.machineName === "assm1-win-x64-e2b6cbcadd8b", "consumed proof machine name changed");
  assert(consumption.distributionName === OLD_DISTRIBUTION, "consumed proof distribution name changed");
  bounded(recovery.archiveBytes, 1, 8 * 1024 * 1024 * 1024, "recovery archive bytes");
  sha256(recovery.archiveSha256, "recovery archive digest");

  const data = observations.dataPreservation;
  exactKeys(
    data,
    [
      "preInstallerFileCount",
      "preInstallerBytes",
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
    "ghost data preservation",
  );
  bounded(data.preInstallerFileCount, 4, 4096, "ghost data file count");
  bounded(data.preInstallerBytes, 1, 512 * 1024 * 1024, "ghost data bytes");
  assert(typeof data.demoCaseId === "string" && /^[0-9a-f-]{36}$/u.test(data.demoCaseId), "ghost demo case ID is malformed");
  for (const field of [
    "demoCasePreserved",
    "privateSigningMaterialBytePreserved",
    "privateSigningKeyProtected",
    "publicIdentitySummaryExact",
    "durableIdentityDocumentPresent",
    "identityDocumentProtected",
    "durableIdentityAnchorPresent",
    "identityAnchorProtected",
    "anchorDigestVerified",
    "anchorMatchesIdentityDocument",
    "identitySelfSignatureVerifiedByCandidate",
    "rotationIntentAbsent",
    "firstBundleValid",
    "secondBundleValid",
  ]) {
    yes(data[field], `ghost data preservation ${field}`);
  }
  validateSigningIdentity(data.publicKeyBase64Before, data.signingKeyIdBefore, "N-1 ghost signing identity");
  validateSigningIdentity(data.publicKeyBase64After, data.signingKeyIdAfter, "recovered signing identity");
  bounded(data.identityDocumentBytes, 1, 64 * 1024, "durable signing identity document bytes");
  sha256(data.identityDocumentCompactSha256, "durable signing identity document compact digest");
  bounded(data.identityAnchorBytes, 1, 64 * 1024, "durable signing identity anchor bytes");
  assert(data.anchorSchemaVersion === "1", "durable signing identity anchor schema is not v1");
  sha256(data.anchorIdentityDocumentSha256, "durable signing identity anchor digest");
  assert(
    data.anchorIdentityDocumentSha256 === data.identityDocumentCompactSha256,
    "durable signing identity anchor digest differs from the identity document",
  );
  assert(data.continuityEvent === "legacy_key_adopted", "candidate did not record legacy-key adoption");
  assert(data.signingKeyIdAfter === data.signingKeyIdBefore, "integrity signing key ID changed during ghost recovery");
  assert(data.publicKeyBase64After === data.publicKeyBase64Before, "integrity signing public key changed during ghost recovery");
  assert(data.identityKeyId === data.signingKeyIdBefore, "durable identity key ID differs from both ghost bundles");
  assert(
    data.identityPublicKeyBase64 === data.publicKeyBase64Before,
    "durable identity public key differs from both ghost bundles",
  );

  exactKeys(
    observations.cleanup,
    [
      "managedRuntimePurged",
      "exactWslDistributionAbsent",
      "quarantineDistributionsAbsent",
      "candidateUninstalled",
      "installDirectoryRemoved",
      "privateDataRemoved",
      "productRegistryRemoved",
    ],
    "ghost qualification cleanup",
  );
  for (const [name, value] of Object.entries(observations.cleanup)) yes(value, `ghost cleanup ${name}`);
}

async function identityFromArgs(args) {
  const artifactDirectory = path.resolve(requireString(args, "artifact-dir"));
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  assert(isSemver(version) && version === "0.1.8" && tag === `v${version}`, "candidate version/tag is not the bounded 0.1.8 migration");
  assert(/^[0-9a-f]{40}$/u.test(commit), "candidate commit is not a full lowercase Git object ID");
  const testOnlyRuntimeManifestSha256 = args.get("test-only-runtime-manifest-sha256");
  let expectedRuntimeManifestSha256 = CANDIDATE_RUNTIME_MANIFEST_SHA256;
  if (testOnlyRuntimeManifestSha256 !== undefined) {
    assert(
      typeof testOnlyRuntimeManifestSha256 === "string" &&
        /^[0-9a-f]{64}$/u.test(testOnlyRuntimeManifestSha256),
      "test-only runtime manifest identity is malformed",
    );
    assert(
      isBoundedReleaseSelfTestFixture(artifactDirectory, commit),
      "test-only runtime identity is restricted to the bounded release self-test fixture",
    );
    expectedRuntimeManifestSha256 = testOnlyRuntimeManifestSha256;
  }
  return {
    artifactDirectory,
    version,
    tag,
    commit,
    candidate: await candidateIdentity(
      artifactDirectory,
      version,
      tag,
      commit,
      expectedRuntimeManifestSha256,
    ),
  };
}

async function create(args) {
  const identity = await identityFromArgs(args);
  const observationsFile = path.resolve(requireString(args, "observations"));
  const metadata = await lstat(observationsFile);
  assert(
    metadata.isFile() && !metadata.isSymbolicLink() && metadata.size > 0 && metadata.size <= 256 * 1024,
    "ghost observations are not one bounded regular file",
  );
  const observations = JSON.parse(await readFile(observationsFile, "utf8"));
  validateObservations(observations, identity.candidate, identity.version);
  const evidence = {
    schemaVersion: SCHEMA_VERSION,
    qualification: "windows_nsis_real_registered_wsl_n_minus_one_ghost_recovery",
    releaseIdentity: {
      product: "ai-security-scanner",
      version: identity.version,
      tag: identity.tag,
      sourceCommit: identity.commit,
    },
    platform: PLATFORM,
    runner: RUNNER,
    installerType: INSTALLER_TYPE,
    candidateInstaller: { ...identity.candidate.installer },
    candidateRuntime: {
      manifestSha256: identity.candidate.runtimeManifestSha256,
      machineImageSha256: identity.candidate.machineImageSha256,
      providerNamespace: identity.candidate.providerNamespace,
    },
    priorReleasePin: { ...PRIOR_GHOST_RELEASE },
    observations,
  };
  await writeJsonAtomic(path.resolve(requireString(args, "out")), evidence);
  process.stdout.write("Created strict real registered-WSL ghost-recovery evidence\n");
}

async function validate(args) {
  const identity = await identityFromArgs(args);
  const file = path.resolve(requireString(args, "file"));
  const metadata = await lstat(file);
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= 256 * 1024, "ghost evidence is not bounded");
  const evidence = JSON.parse(await readFile(file, "utf8"));
  exactKeys(
    evidence,
    [
      "schemaVersion",
      "qualification",
      "releaseIdentity",
      "platform",
      "runner",
      "installerType",
      "candidateInstaller",
      "candidateRuntime",
      "priorReleasePin",
      "observations",
    ],
    "ghost-recovery evidence",
  );
  assert(evidence.schemaVersion === SCHEMA_VERSION, "ghost evidence schema is unsupported");
  assert(
    evidence.qualification === "windows_nsis_real_registered_wsl_n_minus_one_ghost_recovery",
    "ghost evidence qualification ID is wrong",
  );
  exactKeys(evidence.releaseIdentity, ["product", "version", "tag", "sourceCommit"], "ghost release identity");
  assert(
    JSON.stringify(evidence.releaseIdentity) === JSON.stringify({
      product: "ai-security-scanner",
      version: identity.version,
      tag: identity.tag,
      sourceCommit: identity.commit,
    }),
    "ghost evidence release identity changed",
  );
  assert(evidence.platform === PLATFORM && evidence.runner === RUNNER && evidence.installerType === INSTALLER_TYPE, "ghost evidence execution identity changed");
  assert(JSON.stringify(evidence.candidateInstaller) === JSON.stringify(identity.candidate.installer), "ghost evidence installer binding changed");
  assert(
    JSON.stringify(evidence.candidateRuntime) === JSON.stringify({
      manifestSha256: identity.candidate.runtimeManifestSha256,
      machineImageSha256: identity.candidate.machineImageSha256,
      providerNamespace: identity.candidate.providerNamespace,
    }),
    "ghost evidence runtime binding changed",
  );
  assert(JSON.stringify(evidence.priorReleasePin) === JSON.stringify(PRIOR_GHOST_RELEASE), "ghost evidence prior pin changed");
  validateObservations(evidence.observations, identity.candidate, identity.version);
  process.stdout.write(`Validated real registered-WSL ghost recovery for ${identity.tag}\n`);
  return evidence;
}

export async function validateWindowsNsisGhostRecoveryEvidenceFile({
  file,
  artifactDirectory,
  version,
  tag,
  commit,
  testOnlyRuntimeManifestSha256,
}) {
  const args = new Map([
    ["file", file],
    ["artifact-dir", artifactDirectory],
    ["version", version],
    ["tag", tag],
    ["commit", commit],
  ]);
  if (testOnlyRuntimeManifestSha256 !== undefined) {
    args.set("test-only-runtime-manifest-sha256", testOnlyRuntimeManifestSha256);
  }
  return validate(args);
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);
  if (command === "create") return create(args);
  if (command === "validate") return validate(args);
  throw new Error("usage: windows-nsis-ghost-recovery-evidence.mjs <create|validate> [arguments]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(main);
}
