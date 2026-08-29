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
const OLD_MACHINE = "assm1-win-x64-e2b6cbcadd8b";
const OLD_DISTRIBUTION = "podman-assm1-win-x64-e2b6cbcadd8b";
const CURRENT_MACHINE = "assm2-win-x64-e2b6cbcadd8b";
const CURRENT_DISTRIBUTION = "podman-assm2-win-x64-e2b6cbcadd8b";
const OLD_VERSION_DIRECTORY = "podman-machine-5.8.2-8b2257ace33ecb14";
const RETAINED_PROOF_SCHEMA = "ai-security-scanner.managed-wsl-legacy-workspace-retained/v1";
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
      "runtimeSideBySide",
      "dataPreservation",
      "cleanup",
    ],
    "side-by-side ghost observations",
  );
  assert(observations.schemaVersion === SCHEMA_VERSION, "side-by-side ghost schema is unsupported");
  assert(
    observations.scenario === "real_registered_wsl_n_minus_one_ghost_install_side_by_side",
    "ghost fixture did not exercise the non-destructive side-by-side contract",
  );
  assert(observations.platform === PLATFORM && observations.runner === RUNNER, "ghost runner is incorrect");
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
      "registrationId",
      "registeredWslStateExercised",
      "registrationBoundToOldProvider",
      "missingVersionsManifestExercised",
      "oldVersionDirectory",
      "oldVersionPayloadDigestVerifiedBeforeRemoval",
      "oldVersionPayloadDirectoryRemoved",
      "oldDesktopRemoved",
      "oldUninstallerRemoved",
      "unrelatedDistributionName",
      "unrelatedRegistrationId",
      "unrelatedDistributionRunning",
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
    "missingVersionsManifestExercised",
    "oldVersionPayloadDigestVerifiedBeforeRemoval",
    "oldVersionPayloadDirectoryRemoved",
    "oldDesktopRemoved",
    "oldUninstallerRemoved",
    "unrelatedDistributionRunning",
  ]) yes(fixture[field], "ghost fixture " + field);
  assert(
    fixture.oldProviderNamespace === PRIOR_GHOST_RELEASE.runtimeManifestSha256.slice(0, 16),
    "ghost fixture provider namespace is not pinned N-1",
  );
  assert(fixture.distributionName === OLD_DISTRIBUTION, "ghost fixture distribution is not deterministic N-1");
  assert(fixture.oldVersionDirectory === OLD_VERSION_DIRECTORY, "ghost fixture removed the wrong versions entry");
  assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(fixture.registrationId), "legacy registration ID is not canonical");
  assert(/^ai-security-scanner-unrelated-[0-9a-f]{32}$/u.test(fixture.unrelatedDistributionName), "unrelated WSL fixture name is malformed");
  assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(fixture.unrelatedRegistrationId), "unrelated registration ID is not canonical");

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
  ]) yes(migration[field], "installer migration " + field);
  assert(migration.transitionReceipt === "recovered-ghost-v0.1.7", "bounded ghost installer branch was not observed");
  assert(migration.candidateCliVersion === version, "ghost migration did not install the candidate CLI");

  const sideBySide = observations.runtimeSideBySide;
  exactKeys(
    sideBySide,
    [
      "startSucceeded",
      "noManualActionFallback",
      "runningAndAvailable",
      "legacyMachineName",
      "legacyDistributionName",
      "legacyRegistrationIdBefore",
      "legacyRegistrationIdAfter",
      "legacyRegistrationBasePathExact",
      "legacyProviderRetained",
      "legacyProviderNamespace",
      "legacyVhdIdentityPreserved",
      "legacyProviderProofFilesPreserved",
      "legacySentinelProcessSurvived",
      "currentMachineName",
      "currentDistributionName",
      "currentRegistrationId",
      "currentRegistrationBasePathExact",
      "currentProviderNamespace",
      "currentProviderCreated",
      "unrelatedDistributionName",
      "unrelatedRegistrationIdBefore",
      "unrelatedRegistrationIdAfter",
      "unrelatedRegistrationBasePathExact",
      "unrelatedSentinelProcessSurvived",
      "noQuarantineDistributionCreated",
      "retainedProof",
      "receiptConsumption",
    ],
    "managed-runtime side-by-side initialization",
  );
  for (const field of [
    "startSucceeded",
    "noManualActionFallback",
    "runningAndAvailable",
    "legacyRegistrationBasePathExact",
    "legacyProviderRetained",
    "legacyVhdIdentityPreserved",
    "legacyProviderProofFilesPreserved",
    "legacySentinelProcessSurvived",
    "currentRegistrationBasePathExact",
    "currentProviderCreated",
    "unrelatedRegistrationBasePathExact",
    "unrelatedSentinelProcessSurvived",
    "noQuarantineDistributionCreated",
  ]) yes(sideBySide[field], "runtime side-by-side " + field);
  assert(sideBySide.legacyMachineName === OLD_MACHINE, "legacy machine epoch changed");
  assert(sideBySide.legacyDistributionName === OLD_DISTRIBUTION, "legacy distribution changed");
  assert(sideBySide.legacyRegistrationIdBefore === fixture.registrationId, "legacy registration does not match fixture");
  assert(sideBySide.legacyRegistrationIdAfter === sideBySide.legacyRegistrationIdBefore, "legacy registration GUID changed");
  assert(
    sideBySide.legacyProviderNamespace === PRIOR_GHOST_RELEASE.runtimeManifestSha256.slice(0, 16),
    "legacy provider namespace changed",
  );
  assert(sideBySide.currentMachineName === CURRENT_MACHINE, "candidate did not use the assm2 epoch");
  assert(sideBySide.currentDistributionName === CURRENT_DISTRIBUTION, "candidate distribution is not assm2");
  assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(sideBySide.currentRegistrationId), "current registration ID is not canonical");
  assert(sideBySide.currentProviderNamespace === identity.providerNamespace, "current provider namespace is not the candidate");
  assert(sideBySide.unrelatedDistributionName === fixture.unrelatedDistributionName, "unrelated distribution identity changed");
  assert(sideBySide.unrelatedRegistrationIdBefore === fixture.unrelatedRegistrationId, "unrelated registration does not match fixture");
  assert(sideBySide.unrelatedRegistrationIdAfter === sideBySide.unrelatedRegistrationIdBefore, "unrelated registration GUID changed");

  const proof = sideBySide.retainedProof;
  exactKeys(
    proof,
    [
      "pathBoundToLegacyRegistrationId",
      "proofPresent",
      "proofProtected",
      "proofBytes",
      "proofSha256",
      "schemaVersion",
      "authorizesCleanup",
      "transitionEvidenceSource",
      "installTransitionReceipt",
      "previousManifestSha256",
      "currentManifestSha256",
      "machineImageSha256",
      "legacyMachineName",
      "legacyDistributionName",
      "currentMachineName",
      "currentDistributionName",
      "legacyRegistrationId",
      "currentRegistrationId",
      "legacyProviderNamespace",
      "legacyVhdSizeBytes",
      "legacyVhdVolumeSerialNumber",
      "legacyVhdFileIndex",
      "legacyVhdNumberOfLinks",
      "legacyVhdAttributes",
      "legacyProviderConfigSha256",
      "legacySshPublicKeySha256",
      "proofRetainedAfterCurrentRuntimePurge",
      "proofRetainedUntilExplicitPrivateDataCleanup",
    ],
    "retained legacy-workspace proof",
  );
  for (const field of [
    "pathBoundToLegacyRegistrationId",
    "proofPresent",
    "proofProtected",
    "proofRetainedAfterCurrentRuntimePurge",
    "proofRetainedUntilExplicitPrivateDataCleanup",
  ]) yes(proof[field], "retained proof " + field);
  assert(proof.authorizesCleanup === false, "retained proof incorrectly grants cleanup authority");
  assert(proof.schemaVersion === RETAINED_PROOF_SCHEMA, "retained proof schema changed");
  assert(proof.transitionEvidenceSource === "nsis_install_transition", "live ghost fixture did not use the exact NSIS receipt");
  assert(proof.installTransitionReceipt === migration.transitionReceipt, "retained proof lost the exact transition receipt");
  assert(proof.previousManifestSha256 === PRIOR_GHOST_RELEASE.runtimeManifestSha256, "retained proof is not bound to N-1");
  assert(proof.currentManifestSha256 === identity.runtimeManifestSha256, "retained proof is not bound to candidate manifest");
  assert(proof.machineImageSha256 === identity.machineImageSha256, "retained proof is not bound to machine image");
  assert(proof.legacyMachineName === OLD_MACHINE && proof.legacyDistributionName === OLD_DISTRIBUTION, "retained proof legacy identity changed");
  assert(proof.currentMachineName === CURRENT_MACHINE && proof.currentDistributionName === CURRENT_DISTRIBUTION, "retained proof current identity changed");
  assert(proof.legacyRegistrationId === sideBySide.legacyRegistrationIdBefore, "retained proof legacy GUID changed");
  assert(proof.currentRegistrationId === sideBySide.currentRegistrationId, "retained proof current GUID changed");
  assert(proof.legacyProviderNamespace === PRIOR_GHOST_RELEASE.runtimeManifestSha256.slice(0, 16), "retained proof provider namespace changed");
  bounded(proof.proofBytes, 1, 64 * 1024, "retained proof bytes");
  sha256(proof.proofSha256, "retained proof digest");
  bounded(proof.legacyVhdSizeBytes, 1, 64 * 1024 * 1024 * 1024, "legacy VHD bytes");
  bounded(proof.legacyVhdVolumeSerialNumber, 0, 0xffffffff, "legacy VHD volume serial");
  assert(typeof proof.legacyVhdFileIndex === "string" && /^[0-9]{1,20}$/u.test(proof.legacyVhdFileIndex), "legacy VHD file index is not a bounded decimal string");
  bounded(proof.legacyVhdNumberOfLinks, 1, 1024, "legacy VHD link count");
  bounded(proof.legacyVhdAttributes, 0, 0xffffffff, "legacy VHD attributes");
  sha256(proof.legacyProviderConfigSha256, "legacy provider config digest");
  sha256(proof.legacySshPublicKeySha256, "legacy SSH public-key digest");

  exactKeys(
    sideBySide.receiptConsumption,
    [
      "proofAbsentWhileRegistryReceiptPresent",
      "proofValidatedBeforeRegistryAbsenceCheck",
      "registryValueAbsentAfterDurableProof",
    ],
    "side-by-side receipt consumption",
  );
  for (const [name, value] of Object.entries(sideBySide.receiptConsumption)) {
    yes(value, "side-by-side receipt consumption " + name);
  }

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
      "masterFrameworkReport",
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
  ]) yes(data[field], "ghost data preservation " + field);
  validateSigningIdentity(data.publicKeyBase64Before, data.signingKeyIdBefore, "N-1 ghost signing identity");
  validateSigningIdentity(data.publicKeyBase64After, data.signingKeyIdAfter, "side-by-side signing identity");
  bounded(data.identityDocumentBytes, 1, 64 * 1024, "durable signing identity document bytes");
  sha256(data.identityDocumentCompactSha256, "durable signing identity document compact digest");
  bounded(data.identityAnchorBytes, 1, 64 * 1024, "durable signing identity anchor bytes");
  assert(data.anchorSchemaVersion === "1", "durable signing identity anchor schema is not v1");
  sha256(data.anchorIdentityDocumentSha256, "durable signing identity anchor digest");
  assert(data.anchorIdentityDocumentSha256 === data.identityDocumentCompactSha256, "signing identity anchor digest differs");
  assert(data.continuityEvent === "legacy_key_adopted", "candidate did not record legacy-key adoption");
  assert(data.signingKeyIdAfter === data.signingKeyIdBefore, "integrity signing key ID changed");
  assert(data.publicKeyBase64After === data.publicKeyBase64Before, "integrity signing public key changed");
  assert(data.identityKeyId === data.signingKeyIdBefore, "durable identity key ID differs");
  assert(data.identityPublicKeyBase64 === data.publicKeyBase64Before, "durable identity public key differs");

  const report = data.masterFrameworkReport;
  exactKeys(
    report,
    [
      "reportFile",
      "reportBytes",
      "reportSha256",
      "bundleEntryPath",
      "bundleEntryBytes",
      "bundleEntrySha256",
      "exactBundleEntryMatch",
      "schemaVersion",
      "product",
      "productVersion",
      "caseId",
      "runId",
      "frameworkKeys",
      "truthfulUnknownCoverage",
      "noComplianceOutcomeClaims",
    ],
    "master NIST ISO AIDEFEND report",
  );
  assert(report.reportFile === "master-framework-report.json", "master report filename changed");
  bounded(report.reportBytes, 1, 4 * 1024 * 1024, "master report bytes");
  sha256(report.reportSha256, "master report digest");
  assert(report.bundleEntryPath === "exports/master-framework-report.json", "master report bundle path changed");
  assert(report.bundleEntryBytes === report.reportBytes, "master report bundle bytes differ");
  assert(report.bundleEntrySha256 === report.reportSha256, "master report bundle digest differs");
  yes(report.exactBundleEntryMatch, "master report exact signed-bundle binding");
  assert(report.schemaVersion === "1.1.0", "master report schema changed");
  assert(report.product === "ai-security-scanner" && report.productVersion === version, "master report product identity changed");
  assert(report.caseId === data.demoCaseId, "master report case changed");
  assert(typeof report.runId === "string" && /^[0-9a-f-]{36}$/u.test(report.runId), "master report run ID is malformed");
  assert(JSON.stringify(report.frameworkKeys) === JSON.stringify(["nist_csf", "iso_iec_27001", "aidefend"]), "master report frameworks changed");
  yes(report.truthfulUnknownCoverage, "master report truthful unknown coverage");
  yes(report.noComplianceOutcomeClaims, "master report no-compliance-outcome contract");

  exactKeys(
    observations.cleanup,
    [
      "currentRuntimePurged",
      "currentDistributionAbsent",
      "legacyDistributionRetainedThroughRuntimePurge",
      "unrelatedDistributionRetainedThroughRuntimePurge",
      "retainedProofPreservedThroughRuntimePurge",
      "legacyDataPreservedThroughNsisUninstall",
      "explicitQualificationTeardownRemovedLegacy",
      "explicitQualificationTeardownRemovedUnrelated",
      "quarantineDistributionsAbsent",
      "candidateUninstalled",
      "installDirectoryRemoved",
      "privateDataRemoved",
      "productRegistryRemoved",
    ],
    "ghost side-by-side qualification cleanup",
  );
  for (const [name, value] of Object.entries(observations.cleanup)) yes(value, "ghost cleanup " + name);
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
    qualification: "windows_nsis_real_registered_wsl_n_minus_one_ghost_side_by_side",
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
  process.stdout.write("Created strict real registered-WSL side-by-side ghost evidence\n");
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
    evidence.qualification === "windows_nsis_real_registered_wsl_n_minus_one_ghost_side_by_side",
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
  process.stdout.write(`Validated real registered-WSL side-by-side ghost handling for ${identity.tag}\n`);
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
