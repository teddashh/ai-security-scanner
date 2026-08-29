import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { PROJECT_ROOT, isSemver, readJson, runMain, sha256File } from "./lib.mjs";
import {
  createPlatformQualification,
  validatePlatformQualification,
} from "./platform-qualification.mjs";
import { verifyUpdaterSignatures } from "./verify-updater-signatures.mjs";

const VERSION = JSON.parse(
  readFileSync(path.join(PROJECT_ROOT, "package.json"), "utf8"),
).version;
const GITLEAKS_RELEASE = JSON.parse(
  readFileSync(path.join(PROJECT_ROOT, "engines", "catalog.json"), "utf8"),
).find((engine) => engine?.id === "gitleaks");
if (!GITLEAKS_RELEASE?.image?.repository || !/^sha256:[0-9a-f]{64}$/u.test(GITLEAKS_RELEASE.image.digest ?? "")) {
  throw new Error("release self-test requires the immutable managed Gitleaks catalog image");
}
const EXPECTED_QUALIFICATION_IMAGE =
  `${GITLEAKS_RELEASE.image.repository}@${GITLEAKS_RELEASE.image.digest}`;
const GATEWAY_RELEASE_MANIFEST = JSON.parse(
  readFileSync(
    path.join(PROJECT_ROOT, "runtime", "managed-egress-gateway.json"),
    "utf8",
  ),
);
const EXPECTED_GATEWAY_IMAGE =
  `${GATEWAY_RELEASE_MANIFEST.image.repository}@${GATEWAY_RELEASE_MANIFEST.image.digest}`;
const TAG = `v${VERSION}`;
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const TEST_KEY_PASSWORD = "release-self-test-only";
const TAURI_CLI = path.join(PROJECT_ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js");
const LEGACY_PUBLIC_KEY_BASE64 = Buffer.alloc(32, 0x5a).toString("base64");
const LEGACY_KEY_ID = createHash("sha256").update(Buffer.alloc(32, 0x5a)).digest("hex");

function run(script, arguments_) {
  execFileSync(process.execPath, [path.join(PROJECT_ROOT, "scripts/release", script), ...arguments_], {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
}

function tauriSigner(arguments_) {
  execFileSync(process.execPath, [TAURI_CLI, "signer", ...arguments_], {
    cwd: PROJECT_ROOT,
    stdio: "ignore",
  });
}

function expectFailure(action, label) {
  try {
    action();
  } catch {
    return;
  }
  throw new Error(`${label} unexpectedly passed`);
}

async function createPlatformFixture(
  root,
  platform,
  kinds,
  signingKey,
  macUpdaterName = "ai-security-scanner.app.tar.gz",
  replaceInstallerWithSymlink = false,
) {
  const bundleRoot = path.join(root, `bundle-${platform}`);
  for (const [kind, filename] of kinds) {
    const directory = path.join(bundleRoot, kind);
    await mkdir(directory, { recursive: true });
    await writeFile(
      path.join(directory, filename),
      Buffer.concat([
        Buffer.from(`fixture:${platform}:${kind}:${VERSION}\n`),
        Buffer.alloc(2048, `${platform}:${kind}`),
      ]),
    );
  }
  let updaterPayloads;
  if (platform === "linux-x86_64") {
    updaterPayloads = ["appimage", "deb", "rpm"].map((kind) =>
      path.join(bundleRoot, kind, kinds.find(([candidate]) => candidate === kind)[1]),
    );
  } else if (platform === "windows-x86_64") {
    updaterPayloads = ["nsis", "msi"].map((kind) =>
      path.join(bundleRoot, kind, kinds.find(([candidate]) => candidate === kind)[1]),
    );
  } else {
    const macos = path.join(bundleRoot, "macos");
    await mkdir(macos, { recursive: true });
    // Match Tauri's real macOS updater output: the `.app` name intentionally
    // omits the version. Collection must publish a canonical versioned asset.
    const updaterPayload = path.join(macos, macUpdaterName);
    await writeFile(updaterPayload, Buffer.alloc(4096, "macos-universal-updater"));
    updaterPayloads = [updaterPayload];
  }
  const stagingDirectory =
    platform === "linux-x86_64"
      ? path.join(bundleRoot, "appimage", "ai-security-scanner.AppDir")
      : platform === "macos-universal"
        ? path.join(bundleRoot, "macos", "ai-security-scanner.app", "Contents", "Resources")
        : null;
  if (stagingDirectory) {
    await mkdir(stagingDirectory, { recursive: true });
    await writeFile(path.join(stagingDirectory, "application-icon.png"), Buffer.alloc(2048, "icon"));
    await symlink("application-icon.png", path.join(stagingDirectory, ".DirIcon"));
  }
  for (const updaterPayload of updaterPayloads) {
    tauriSigner([
      "sign",
      "--private-key-path",
      signingKey,
      "--password",
      TEST_KEY_PASSWORD,
      updaterPayload,
    ]);
  }
  if (replaceInstallerWithSymlink) {
    const [kind, filename] = kinds[0];
    const installer = path.join(bundleRoot, kind, filename);
    const regularTarget = `${installer}.regular`;
    await rename(installer, regularTarget);
    await symlink(path.basename(regularTarget), installer);
  }
  const sidecarExtension = platform === "windows-x86_64" ? ".exe" : "";
  const magic =
    platform === "windows-x86_64"
      ? Buffer.from([0x4d, 0x5a, 0, 0])
      : platform === "macos-universal"
        ? Buffer.from([0xca, 0xfe, 0xba, 0xbe])
        : Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
  const egressSidecar = path.join(root, `egress-sidecar-${platform}${sidecarExtension}`);
  const bootstrapBroker = path.join(root, `bootstrap-broker-${platform}${sidecarExtension}`);
  const caseworkCli = path.join(root, `casework-cli-${platform}${sidecarExtension}`);
  await writeFile(egressSidecar, Buffer.concat([magic, Buffer.alloc(4096, platform.length)]));
  await writeFile(bootstrapBroker, Buffer.concat([magic, Buffer.alloc(4096, platform.length + 1)]));
  await writeFile(caseworkCli, Buffer.concat([magic, Buffer.alloc(4096, platform.length + 2)]));
  const output = path.join(root, `output-${platform}`);
  run("collect-bundles.mjs", [
    "--bundle-root",
    bundleRoot,
    "--out",
    output,
    "--platform",
    platform,
    "--expect",
    kinds.map(([kind]) => kind).join(","),
    "--egress-sidecar",
    egressSidecar,
    "--bootstrap-broker",
    bootstrapBroker,
    "--casework-cli",
    caseworkCli,
    "--version",
    VERSION,
    "--tag",
    TAG,
    "--commit",
    COMMIT,
  ]);
  const runtimeRoot = path.join(root, `runtime-${platform}`);
  const runtimeBinaryRelative = platform === "windows-x86_64" ? "bin/podman.exe" : "bin/podman";
  const runtimeBinary = path.join(runtimeRoot, ...runtimeBinaryRelative.split("/"));
  await mkdir(path.dirname(runtimeBinary), { recursive: true });
  await writeFile(runtimeBinary, Buffer.concat([magic, Buffer.alloc(3072, platform.length + 2)]));
  const runtimeBinaryBytes = (await readFile(runtimeBinary)).length;
  const runtimeBinarySha256 = await sha256File(runtimeBinary);
  const machineImageUrl =
    `https://github.com/podman-container-tools/podman-machine-os/releases/download/v0.0.1/${platform}.qcow2.xz`;
  const machineImageSha256 = "ab".repeat(32);
  const runtimeManifest = path.join(runtimeRoot, "manifest.json");
  await writeFile(
    runtimeManifest,
    `${JSON.stringify({
      schema_version: "3",
      management_contract_revision: "2026-08-29.1",
      bundle_id: platform === "windows-x86_64" ? "podman-machine" : "release-self-test",
      runtime_version: platform === "windows-x86_64" ? "5.8.2" : VERSION,
      driver_path: runtimeBinaryRelative,
      files: [{
        path: runtimeBinaryRelative,
        sha256: runtimeBinarySha256,
        size_bytes: runtimeBinaryBytes,
        executable: true,
      }],
      components: [
        {
          id: "fixture-runtime-client",
          name: "Fixture runtime client",
          version: VERSION,
          repository_url: "https://github.com/containers/podman",
          source_revision: COMMIT,
          license_spdx: "Apache-2.0",
          relationship: "Release self-test stand-in for one exact bundled runtime executable.",
          artifacts: [{
            delivery: "bundled_file",
            locator: runtimeBinaryRelative,
            sha256: runtimeBinarySha256,
            size_bytes: runtimeBinaryBytes,
          }],
        },
        {
          id: "fixture-machine-os",
          name: "Fixture machine OS",
          version: VERSION,
          repository_url: "https://github.com/podman-container-tools/podman-machine-os",
          source_revision: COMMIT,
          license_spdx: "Apache-2.0",
          relationship: "Release self-test stand-in for one exact runtime-downloaded machine image.",
          artifacts: [{
            delivery: "runtime_download",
            locator: machineImageUrl,
            sha256: machineImageSha256,
            size_bytes: 4096,
          }],
        },
      ],
      targets: [{
        operating_system: platform.startsWith("linux") ? "linux" : platform.startsWith("macos") ? "macos" : "windows",
        architecture: "x86_64",
        provider: platform.startsWith("linux") ? "qemu" : platform.startsWith("macos") ? "applehv" : "wsl",
        machine_image: {
          url: machineImageUrl,
          sha256: machineImageSha256,
          size_bytes: 4096,
        },
      }],
      resources: { cpus: 2, memory_mb: 2048, disk_size_gb: 20 },
      source: {
        repository_url: "https://github.com/containers/podman",
        source_revision: COMMIT,
        license_spdx: "Apache-2.0",
      },
    }, null, 2)}\n`,
  );
  run("generate-runtime-evidence.mjs", [
    "--manifest",
    runtimeManifest,
    "--out",
    output,
    "--platform",
    platform,
  ]);
  return output;
}

async function mergeFlat(source, destination) {
  for (const name of await readdir(source)) {
    await copyFile(path.join(source, name), path.join(destination, name));
  }
}

async function createQualificationFixture(output, platform, installerType) {
  const runtimeManifestFile = path.join(output, `managed-runtime-${platform}.manifest.json`);
  const runtimeManifest = await readJson(runtimeManifestFile);
  const manifestSha256 = await sha256File(runtimeManifestFile);
  const target = runtimeManifest.targets[0];
  const status = (phase, available) => ({
    provider: "managed_local",
    phase,
    available,
    runtime_version: runtimeManifest.runtime_version,
    manifest_sha256: manifestSha256,
    machine_image_sha256: target.machine_image.sha256,
    operating_system: target.operating_system,
    architecture: target.architecture,
    machine_provider: target.provider,
    prerequisite: null,
    detail: `release self-test ${phase} status`,
  });
  const passed = (name, phase, available) => ({ name, outcome: "passed", status: status(phase, available) });
  const macosHostedLimitation = "github_hosted_macos_nested_virtualization_unsupported";
  const notObserved = (name) => ({
    name,
    outcome: "not_observed",
    reasonCode: macosHostedLimitation,
  });
  const qualificationRoot = path.join(output, `qualification-fixture-${platform}`);
  await mkdir(qualificationRoot);
  await copyFile(runtimeManifestFile, path.join(qualificationRoot, "installed-runtime-manifest.json"));
  const installedPath = platform === "windows-x86_64" ? path.win32 : path.posix;
  const prefix = platform === "windows-x86_64"
    ? installedPath.join("C:\\fixture-installed", platform, installerType)
    : installedPath.join("/fixture-installed", platform, installerType);
  const extension = platform === "windows-x86_64" ? ".exe" : "";
  const observations = {
    installedLayout: {
      pathsVerifiedAbsolute: true,
      desktop: installedPath.join(prefix, `ai-security-scanner${extension}`),
      cli: installedPath.join(prefix, `ai-security-scanner-cli${extension}`),
      companions: [
        { name: "ai-security-scanner-egress-gateway", path: installedPath.join(prefix, `ai-security-scanner-egress-gateway${extension}`) },
        { name: "ai-security-scanner-bootstrap-broker", path: installedPath.join(prefix, `ai-security-scanner-bootstrap-broker${extension}`) },
        { name: "ai-security-scanner-cli", path: installedPath.join(prefix, `ai-security-scanner-cli${extension}`) },
      ],
      runtimeManifestOriginalPath: installedPath.join(prefix, "managed-runtime", "manifest.json"),
    },
    desktopStartup: {
      outcome: "passed",
      observationSeconds: 12,
      installedExecutable: installedPath.join(prefix, `ai-security-scanner${extension}`),
    },
    privateDataDirectory: platform === "windows-x86_64"
      ? installedPath.join("C:\\fixture-private", platform, installerType)
      : installedPath.join("/fixture-private", platform, installerType),
    operations: platform === "macos-universal"
      ? [
          notObserved("initial_status"),
          notObserved("install"),
          notObserved("installed_status"),
          notObserved("start"),
          notObserved("running_status"),
          notObserved("stop"),
          notObserved("stopped_status"),
          notObserved("uninstall_purge"),
          notObserved("final_status"),
        ]
      : [
          passed("initial_status", "not_installed", false),
          passed("install", "installed", false),
          passed("installed_status", "installed", false),
          passed("start", "running", true),
          passed("running_status", "running", true),
          passed("stop", "stopped", false),
          passed("stopped_status", "stopped", false),
          passed("uninstall_purge", "not_installed", false),
          passed("final_status", "not_installed", false),
        ],
    egressGateway: platform === "macos-universal"
      ? { outcome: "not_observed", reasonCode: macosHostedLimitation }
      : {
          outcome: "passed",
          result: {
            schema_version: "1.0.0",
            status: "passed",
            qualification_kind: "managed_egress_gateway_readiness",
            product_version: VERSION,
            runtime: {
              provider: "managed_local",
              server_version: runtimeManifest.runtime_version,
              command_provenance: {
                kind: "managed_local",
                runtime_version: runtimeManifest.runtime_version,
                manifest_sha256: manifestSha256,
                machine_image_sha256: target.machine_image.sha256,
              },
            },
            gateway: {
              image: EXPECTED_GATEWAY_IMAGE,
              backend: "pinned_container",
              ready: true,
              scanner_reachable: true,
              reachability_probe: "socks5_no_connect_greeting",
              upstream_connection_attempted: false,
              container_id: "15".repeat(32),
              probe_container_id: "19".repeat(32),
              internal_network_id: "16".repeat(32),
              uplink_network_id: "17".repeat(32),
              policy_sha256: "18".repeat(32),
            },
            cleanup: {
              gateway_container_removed: true,
              probe_container_removed: true,
              internal_network_removed: true,
              uplink_network_removed: true,
              policy_file_removed: true,
              status_directory_removed: true,
              registry_record_removed: true,
            },
          },
        },
    containerExecution: platform === "macos-universal"
      ? { outcome: "not_observed", reasonCode: macosHostedLimitation }
      : {
          outcome: "passed",
          result: {
            schema_version: "1.0.0",
            status: "passed",
            qualification_kind: "managed_container_execution",
            product_version: VERSION,
            runtime: {
              provider: "managed_local",
              server_version: runtimeManifest.runtime_version,
              command_provenance: {
                kind: "managed_local",
                runtime_version: runtimeManifest.runtime_version,
                manifest_sha256: manifestSha256,
                machine_image_sha256: target.machine_image.sha256,
              },
            },
            container: {
              engine_id: "gitleaks",
              image: EXPECTED_QUALIFICATION_IMAGE,
              network: "none",
              read_only_root: true,
              capabilities: "drop_all",
              no_new_privileges: true,
              credential_count: 0,
              exit_code: 0,
              cancelled: false,
              created_object_id: "cd".repeat(32),
              cleanup_removed: true,
            },
            evidence: {
              scope_sha256: "10".repeat(32),
              report_sha256: "11".repeat(32),
              report_bytes: 2,
              finding_count: 0,
              stdout_sha256: "12".repeat(32),
              stderr_sha256: "13".repeat(32),
            },
          },
        },
    cleanup: platform === "macos-universal"
      ? {
          diskImageDetached: true,
          installedApplicationRemoved: true,
          privateDataRemoved: true,
          managedRuntimeState: "not_created",
          machineImageCacheState: "not_created",
        }
      : {
          managedRuntimePurged: true,
          machineImageCachePurged: true,
          installerRemoved: true,
          privateDataRemoved: true,
        },
    installedManifestSnapshot: "installed-runtime-manifest.json",
  };
  const observationsFile = path.join(qualificationRoot, "observations.json");
  await writeFile(observationsFile, `${JSON.stringify(observations, null, 2)}\n`);
  const runner = platform === "linux-x86_64"
    ? { label: "ubuntu-24.04", os: "Linux", image: "ubuntu24" }
    : platform === "macos-universal"
      ? { label: "macos-15-intel", os: "macOS", image: "macos15" }
      : { label: "windows-2025", os: "Windows", image: "win25" };
  await createPlatformQualification({
    artifactDirectory: output,
    observationsFile,
    outputFile: path.join(output, `platform-qualification-${platform}-${installerType}.json`),
    platform,
    installerType,
    version: VERSION,
    tag: TAG,
    commit: COMMIT,
    releaseChannel: "prerelease",
    runnerLabel: runner.label,
    environment: {
      GITHUB_ACTIONS: "true",
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: runner.os,
      RUNNER_ARCH: "X64",
      ImageOS: runner.image,
      ImageVersion: "20260824.1",
      GITHUB_WORKFLOW: "Release self-test fixture",
      GITHUB_JOB: "qualification",
      GITHUB_RUN_ID: "123456789",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_SHA: COMMIT,
    },
  });
  await rm(qualificationRoot, { recursive: true, force: true });
}

async function createWindowsNsisMigrationQualificationFixtures(output) {
  const installerManifest = await readJson(path.join(output, "installers-windows-x86_64.json"));
  const nsis = installerManifest.installers.find((installer) => installer.bundleType === "nsis");
  if (!nsis) throw new Error("release self-test Windows fixture has no NSIS installer");
  const runtimeFile = path.join(output, "managed-runtime-windows-x86_64.manifest.json");
  const runtime = await readJson(runtimeFile);
  const runtimeSha256 = await sha256File(runtimeFile);
  const machineImageSha256 = runtime.targets[0].machine_image.sha256;
  const fixtureRoot = path.join(output, "windows-nsis-migration-fixtures");
  await mkdir(fixtureRoot);
  const priorRelease = {
    version: "0.1.7",
    tag: "v0.1.7",
    installerFile: "ai-security-scanner_0.1.7_x64-setup.exe",
    installerBytes: 38_730_365,
    installerSha256: "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a",
    downloadUrl: "https://github.com/teddashh/ai-security-scanner/releases/download/v0.1.7/ai-security-scanner_0.1.7_x64-setup.exe",
    runtimeManifestSha256: "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f",
    machineImageSha256: "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968",
  };
  const signing = {
    signingKeyIdBefore: LEGACY_KEY_ID,
    signingKeyIdAfter: LEGACY_KEY_ID,
    publicKeyBase64Before: LEGACY_PUBLIC_KEY_BASE64,
    publicKeyBase64After: LEGACY_PUBLIC_KEY_BASE64,
    privateSigningKeyProtected: true,
    publicIdentitySummaryExact: true,
    durableIdentityDocumentPresent: true,
    identityDocumentBytes: 1024,
    identityDocumentCompactSha256: "ab".repeat(32),
    identityDocumentProtected: true,
    durableIdentityAnchorPresent: true,
    identityAnchorBytes: 2048,
    identityAnchorProtected: true,
    anchorSchemaVersion: "1",
    anchorIdentityDocumentSha256: "ab".repeat(32),
    anchorDigestVerified: true,
    anchorMatchesIdentityDocument: true,
    identitySelfSignatureVerifiedByCandidate: true,
    rotationIntentAbsent: true,
    continuityEvent: "legacy_key_adopted",
    identityKeyId: LEGACY_KEY_ID,
    identityPublicKeyBase64: LEGACY_PUBLIC_KEY_BASE64,
    firstBundleValid: true,
    secondBundleValid: true,
  };
  const candidate = {
    version: VERSION,
    installerFile: nsis.file,
    installerBytes: nsis.bytes,
    installerSha256: nsis.sha256,
  };
  const upgradeObservations = {
    schemaVersion: 1,
    scenario: "real_n_minus_one_nsis_upgrade",
    platform: "windows-x86_64",
    runner: "windows-2025",
    priorRelease,
    candidate,
    installation: {
      priorCliVersion: "0.1.7",
      candidateCliVersion: VERSION,
      sameCanonicalInstallDirectory: true,
      registryHive: "HKEY_CURRENT_USER",
      registryEntryIdentityPreserved: true,
      displayVersionUpdated: true,
      uninstallerReplaced: true,
      unattendedMode: "silent",
      sameVersionSilentReinstallCompleted: true,
      transitionReceiptSurvivedSameVersionReinstall: true,
      transitionReceipt: "uninstalled-0.1.7",
    },
    dataPreservation: {
      defaultLocalDataDirectoryUsed: true,
      preInstallerFileCount: 8,
      preInstallerBytes: 8192,
      exactPreInstallerSnapshotPreserved: true,
      sentinelPreserved: true,
      demoCaseId: "00112233-4455-6677-8899-aabbccddeeff",
      demoCasePreserved: true,
      privateSigningMaterialBytePreserved: true,
      ...signing,
    },
    managedRuntimeFilesystemSentinel: {
      priorProviderNamespace: "8b2257ace33ecb14",
      priorVersionDirectory: "podman-machine-5.8.2-8b2257ace33ecb14",
      priorVersionPayloadDirectoryAbsentBeforeUpgrade: true,
      priorVersionPayloadDirectoryAbsentAfterInstaller: true,
      providerHomeSentinelPreserved: true,
      registeredWslStateExercised: false,
    },
    cleanup: {
      candidateUninstalled: true,
      installDirectoryRemoved: true,
      privateDataRemoved: true,
      registrySentinelRemoved: true,
    },
  };
  const upgradeObservationsFile = path.join(fixtureRoot, "upgrade-observations.json");
  await writeFile(upgradeObservationsFile, `${JSON.stringify(upgradeObservations, null, 2)}\n`);
  const upgradeEvidence = path.join(output, "windows-nsis-upgrade-qualification.json");
  run("windows-nsis-upgrade-evidence.mjs", [
    "create", "--artifact-dir", output, "--observations", upgradeObservationsFile,
    "--out", upgradeEvidence, "--version", VERSION, "--tag", TAG, "--commit", COMMIT,
  ]);
  run("windows-nsis-upgrade-evidence.mjs", [
    "validate", "--file", upgradeEvidence, "--artifact-dir", output,
    "--version", VERSION, "--tag", TAG, "--commit", COMMIT,
  ]);

  const ghostObservations = {
    schemaVersion: 1,
    scenario: "real_registered_wsl_n_minus_one_ghost_install_recovery",
    platform: "windows-x86_64",
    runner: "windows-2025",
    priorRelease,
    candidate: {
      ...candidate,
      runtimeManifestSha256: runtimeSha256,
      machineImageSha256,
    },
    ghostFixture: {
      defaultInstallDirectoryUsed: true,
      priorCliVersion: "0.1.7",
      oldRegistryIdentityExact: true,
      oldRuntimeInstalled: true,
      oldRuntimeStarted: true,
      oldRuntimeStopped: true,
      oldProviderNamespace: "8b2257ace33ecb14",
      oldProviderCryptographicIdentityPresent: true,
      distributionName: "podman-assm1-win-x64-e2b6cbcadd8b",
      registeredWslStateExercised: true,
      registrationBoundToOldProvider: true,
      oldVersionDirectory: "podman-machine-5.8.2-8b2257ace33ecb14",
      oldVersionPayloadDigestVerifiedBeforeRemoval: true,
      oldVersionPayloadDirectoryRemoved: true,
      oldDesktopRemoved: true,
      oldUninstallerRemoved: true,
    },
    installerMigration: {
      candidateInstallerCompleted: true,
      transitionReceipt: "recovered-ghost-v0.1.7",
      candidateCliVersion: VERSION,
      registryVersionUpdated: true,
      registryIdentityExact: true,
      candidateDesktopRestored: true,
      candidateUninstallerRestored: true,
      candidateRuntimeResourceMatchesRelease: true,
      exactPrivateDataSnapshotPreserved: true,
      sameVersionSilentReinstallCompleted: true,
      transitionReceiptSurvivedSameVersionReinstall: true,
    },
    runtimeRecovery: {
      startSucceeded: true,
      noManualActionFallback: true,
      runningAndAvailable: true,
      sameDistributionName: true,
      registrationMovedToCurrentProvider: true,
      currentProviderNamespace: runtimeSha256.slice(0, 16),
      oldProviderRemoved: true,
      recoveryId: "00112233445566778899aabbccddeeff",
      durableIntentPresent: true,
      intentProofValid: true,
      intentSchemaVersion: "ai-security-scanner.managed-wsl-recovery-intent/v2",
      intentOwnershipBasis: "bounded_n_minus_one_ghost_migration",
      intentManifestSha256: runtimeSha256,
      intentMachineImageSha256: machineImageSha256,
      intentSourceProviderManifestSha256: priorRelease.runtimeManifestSha256,
      intentTransitionReceipt: "recovered-ghost-v0.1.7",
      receiptConsumption: {
        registryValueAbsent: true,
        proofPathExact: true,
        proofPresent: true,
        proofProtected: true,
        proofBytes: 1024,
        proofSha256: "ef".repeat(32),
        schemaVersion: "ai-security-scanner.managed-wsl-ghost-migration-consumed/v1",
        recoveryId: "00112233-4455-6677-8899-aabbccddeeff",
        installTransitionReceipt: "recovered-ghost-v0.1.7",
        sourceProviderManifestSha256: priorRelease.runtimeManifestSha256,
        manifestSha256: runtimeSha256,
        machineImageSha256,
        machineName: "assm1-win-x64-e2b6cbcadd8b",
        distributionName: "podman-assm1-win-x64-e2b6cbcadd8b",
        proofRetainedAfterRuntimePurge: true,
        proofRetainedUntilExplicitPrivateDataCleanup: true,
      },
      durableArchivePresent: true,
      archiveBytes: 65_536,
      archiveSha256: "cd".repeat(32),
      backupReceiptValid: true,
      importReceiptValid: true,
      backupAndImportAgree: true,
      pendingRecoveryAbsent: true,
      temporaryWorkspaceAbsent: true,
      quarantineDistributionAbsent: true,
    },
    dataPreservation: {
      preInstallerFileCount: 8,
      preInstallerBytes: 8192,
      demoCaseId: "00112233-4455-6677-8899-aabbccddeeff",
      demoCasePreserved: true,
      privateSigningMaterialBytePreserved: true,
      ...signing,
    },
    cleanup: {
      managedRuntimePurged: true,
      exactWslDistributionAbsent: true,
      quarantineDistributionsAbsent: true,
      candidateUninstalled: true,
      installDirectoryRemoved: true,
      privateDataRemoved: true,
      productRegistryRemoved: true,
    },
  };
  const ghostObservationsFile = path.join(fixtureRoot, "ghost-observations.json");
  await writeFile(ghostObservationsFile, `${JSON.stringify(ghostObservations, null, 2)}\n`);
  const ghostEvidence = path.join(output, "windows-nsis-ghost-recovery-qualification.json");
  run("windows-nsis-ghost-recovery-evidence.mjs", [
    "create", "--artifact-dir", output, "--observations", ghostObservationsFile,
    "--out", ghostEvidence, "--version", VERSION, "--tag", TAG, "--commit", COMMIT,
    "--test-only-runtime-manifest-sha256", runtimeSha256,
  ]);
  run("windows-nsis-ghost-recovery-evidence.mjs", [
    "validate", "--file", ghostEvidence, "--artifact-dir", output,
    "--version", VERSION, "--tag", TAG, "--commit", COMMIT,
    "--test-only-runtime-manifest-sha256", runtimeSha256,
  ]);
  await rm(fixtureRoot, { recursive: true, force: true });
  return runtimeSha256;
}

async function main() {
  for (const version of ["0.1.2", "0.1.4", "0.2.0", "2.3.4"]) {
    if (!isSemver(version)) throw new Error(`native-compatible release version was rejected: ${version}`);
  }
  for (const version of ["01.2.0", "0.02.0", "0.2.00", "0.2.0-rc.1", "0.2.0+build"]) {
    if (isSemver(version)) throw new Error(`non-native release version was accepted: ${version}`);
  }

  const temporaryRoot = path.join(PROJECT_ROOT, "target", "release-self-test");
  await mkdir(temporaryRoot, { recursive: true });
  const temporary = await mkdtemp(path.join(temporaryRoot, "run-"));
  try {
    const signingKey = path.join(temporary, "updater-test.key");
    tauriSigner([
      "generate",
      "--ci",
      "--password",
      TEST_KEY_PASSWORD,
      "--write-keys",
      signingKey,
    ]);
    const updaterPublicKey = (await readFile(`${signingKey}.pub`, "utf8")).trim();
    const tauriConfig = path.join(temporary, "tauri-test.conf.json");
    await writeFile(
      tauriConfig,
      `${JSON.stringify({ plugins: { updater: { pubkey: updaterPublicKey } } })}\n`,
    );

    const verificationPayload = path.join(temporary, "signature-contract.bin");
    await writeFile(verificationPayload, Buffer.from("authentic updater payload\n"));
    tauriSigner([
      "sign",
      "--private-key-path",
      signingKey,
      "--password",
      TEST_KEY_PASSWORD,
      verificationPayload,
    ]);
    verifyUpdaterSignatures(updaterPublicKey, [{
      payload: verificationPayload,
      signature: `${verificationPayload}.sig`,
    }]);
    const tamperedPayload = path.join(temporary, "tampered-updater.bin");
    await writeFile(tamperedPayload, Buffer.from("tampered updater payload\n"));
    expectFailure(
      () => verifyUpdaterSignatures(updaterPublicKey, [{
        payload: tamperedPayload,
        signature: `${verificationPayload}.sig`,
      }]),
      "tampered updater payload",
    );
    const otherKey = path.join(temporary, "other-updater-test.key");
    tauriSigner([
      "generate",
      "--ci",
      "--password",
      TEST_KEY_PASSWORD,
      "--write-keys",
      otherKey,
    ]);
    const otherPublicKey = (await readFile(`${otherKey}.pub`, "utf8")).trim();
    expectFailure(
      () => verifyUpdaterSignatures(otherPublicKey, [{
        payload: verificationPayload,
        signature: `${verificationPayload}.sig`,
      }]),
      "mismatched updater public key",
    );

    let rejectedUnexpectedMacUpdaterName = false;
    try {
      await createPlatformFixture(
        path.join(temporary, "negative-mac-updater"),
        "macos-universal",
        [["dmg", `ai-security-scanner_${VERSION}_unexpected-name-test.dmg`]],
        signingKey,
        "unexpected-product.app.tar.gz",
      );
    } catch {
      rejectedUnexpectedMacUpdaterName = true;
    }
    if (!rejectedUnexpectedMacUpdaterName) {
      throw new Error("unexpected unversioned macOS updater payload name was accepted");
    }

    let rejectedSymlinkInstaller = false;
    try {
      await createPlatformFixture(
        path.join(temporary, "negative-symlink-installer"),
        "linux-x86_64",
        [
          ["deb", `ai-security-scanner_${VERSION}_amd64.deb`],
          ["rpm", `ai-security-scanner-${VERSION}-1.x86_64.rpm`],
          ["appimage", `ai-security-scanner_${VERSION}_amd64.AppImage`],
        ],
        signingKey,
        undefined,
        true,
      );
    } catch {
      rejectedSymlinkInstaller = true;
    }
    if (!rejectedSymlinkInstaller) {
      throw new Error("top-level symlink installer was accepted");
    }

    const outputs = [
      await createPlatformFixture(temporary, "linux-x86_64", [
        ["deb", `ai-security-scanner_${VERSION}_amd64.deb`],
        ["rpm", `ai-security-scanner-${VERSION}-1.x86_64.rpm`],
        ["appimage", `ai-security-scanner_${VERSION}_amd64.AppImage`],
      ], signingKey),
      await createPlatformFixture(temporary, "macos-universal", [
        ["dmg", `ai-security-scanner_${VERSION}_universal.dmg`],
      ], signingKey),
      await createPlatformFixture(temporary, "windows-x86_64", [
        ["nsis", `ai-security-scanner_${VERSION}_x64-setup.exe`],
        ["msi", `ai-security-scanner_${VERSION}_x64_en-US.msi`],
      ], signingKey),
    ];
    await createQualificationFixture(outputs[0], "linux-x86_64", "deb");
    await createQualificationFixture(outputs[1], "macos-universal", "dmg");
    await createQualificationFixture(outputs[2], "windows-x86_64", "msi");
    await createQualificationFixture(outputs[2], "windows-x86_64", "nsis");
    const selfTestRuntimeManifestSha256 =
      await createWindowsNsisMigrationQualificationFixtures(outputs[2]);
    const release = path.join(temporary, "release-assets");
    await mkdir(release);
    for (const output of outputs) {
      await mergeFlat(output, release);
    }

    await writeFile(path.join(release, "THIRD_PARTY_NOTICES.txt"), "fixture dependency notice\n");
    await writeFile(path.join(release, "ENGINE_NOTICES.md"), "# Fixture engine notice\n");
    await writeFile(path.join(release, "ENGINE_NOTICES.json"), "{\"engines\":[]}\n");
    await writeFile(path.join(release, "LICENSE.txt"), "Apache-2.0 fixture\n");
    await writeFile(
      path.join(release, `ai-security-scanner-${VERSION}.cyclonedx.json`),
      `${JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: [] })}\n`,
    );
    await writeFile(
      path.join(release, `ai-security-scanner-${VERSION}.spdx.json`),
      `${JSON.stringify({ spdxVersion: "SPDX-2.3", SPDXID: "SPDXRef-DOCUMENT", packages: [], relationships: [] })}\n`,
    );
    await writeFile(
      path.join(release, "release-metadata.json"),
      `${JSON.stringify({
        schemaVersion: 2,
        product: "ai-security-scanner",
        version: VERSION,
        tag: TAG,
        releaseChannel: "prerelease",
        stableTarget: "0.2.0",
        sourceRepository: "https://github.com/teddashh/ai-security-scanner",
        sourceCommit: COMMIT,
        sourceDate: "2026-08-24T00:00:00Z",
        publicationMode: "commit-bound-qc",
        distribution: {
          desktopInstallers: ["linux-x86_64", "macos-universal", "windows-x86_64"],
          bundledEngines: [],
          bundledAuxiliaryExecutables: [
            "ai-security-scanner-egress-gateway",
            "ai-security-scanner-bootstrap-broker",
            "ai-security-scanner-cli",
          ],
          engineDelivery: "separate-artifacts-not-bundled-in-desktop-installers",
        },
        security: {
          operatingSystemCodeSigning: { state: "not-configured", statement: "fixture" },
          appleNotarization: { state: "not-configured", statement: "fixture" },
          updater: { state: "enabled-signed", artifactsGenerated: true, signingConfigured: true },
          checksums: "SHA256SUMS.txt",
          sboms: [
            `ai-security-scanner-${VERSION}.cyclonedx.json`,
            `ai-security-scanner-${VERSION}.spdx.json`,
          ],
          provenanceAttestation: {
            state: "not-created-for-commit-bound-qc",
            provider: "none",
          },
        },
        inventories: { npmPackageCount: 0, cargoPackageCount: 0, engineReferenceCount: 0 },
      })}\n`,
    );

    const finalizeArguments = [
      "--dir",
      release,
      "--version",
      VERSION,
      "--tag",
      TAG,
      "--commit",
      COMMIT,
      "--publication-mode",
      "commit-bound-qc",
      "--tauri-config",
      tauriConfig,
      "--test-only-windows-runtime-manifest-sha256",
      selfTestRuntimeManifestSha256,
    ];
    const upgradeQualification = path.join(release, "windows-nsis-upgrade-qualification.json");
    const hiddenUpgradeQualification = `${upgradeQualification}.missing`;
    await rename(upgradeQualification, hiddenUpgradeQualification);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "missing normal NSIS upgrade qualification");
    await rename(hiddenUpgradeQualification, upgradeQualification);
    const ghostQualification = path.join(release, "windows-nsis-ghost-recovery-qualification.json");
    const hiddenGhostQualification = `${ghostQualification}.missing`;
    await rename(ghostQualification, hiddenGhostQualification);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "missing registered-WSL ghost qualification");
    await rename(hiddenGhostQualification, ghostQualification);
    const validUpgradeQualification = await readFile(upgradeQualification);
    const dishonestUpgradeQualification = JSON.parse(validUpgradeQualification.toString("utf8"));
    dishonestUpgradeQualification.observations.dataPreservation.continuityEvent = "generated";
    await writeFile(upgradeQualification, `${JSON.stringify(dishonestUpgradeQualification, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "upgrade evidence without legacy identity adoption");
    await writeFile(upgradeQualification, validUpgradeQualification);
    const mismatchedUpgradeAnchor = JSON.parse(validUpgradeQualification.toString("utf8"));
    mismatchedUpgradeAnchor.observations.dataPreservation.anchorIdentityDocumentSha256 = "cd".repeat(32);
    await writeFile(upgradeQualification, `${JSON.stringify(mismatchedUpgradeAnchor, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "upgrade evidence with mismatched signing identity anchor");
    await writeFile(upgradeQualification, validUpgradeQualification);
    const validGhostQualification = await readFile(ghostQualification);
    const dishonestGhostQualification = JSON.parse(validGhostQualification.toString("utf8"));
    dishonestGhostQualification.observations.runtimeRecovery.intentProofValid = false;
    await writeFile(ghostQualification, `${JSON.stringify(dishonestGhostQualification, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "ghost evidence without a verified v2 recovery intent");
    await writeFile(ghostQualification, validGhostQualification);
    const lostGhostTransition = JSON.parse(validGhostQualification.toString("utf8"));
    lostGhostTransition.observations.installerMigration.transitionReceiptSurvivedSameVersionReinstall = false;
    await writeFile(ghostQualification, `${JSON.stringify(lostGhostTransition, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "ghost evidence with a lost same-version transition receipt");
    await writeFile(ghostQualification, validGhostQualification);
    const unconsumedGhostReceipt = JSON.parse(validGhostQualification.toString("utf8"));
    unconsumedGhostReceipt.observations.runtimeRecovery.receiptConsumption.registryValueAbsent = false;
    await writeFile(ghostQualification, `${JSON.stringify(unconsumedGhostReceipt, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "ghost evidence with an unconsumed registry receipt");
    await writeFile(ghostQualification, validGhostQualification);
    const tamperedConsumedProof = JSON.parse(validGhostQualification.toString("utf8"));
    tamperedConsumedProof.observations.runtimeRecovery.receiptConsumption.manifestSha256 = "ef".repeat(32);
    await writeFile(ghostQualification, `${JSON.stringify(tamperedConsumedProof, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "ghost evidence with a mutated consumed proof");
    await writeFile(ghostQualification, validGhostQualification);
    const incompleteConsumedProof = JSON.parse(validGhostQualification.toString("utf8"));
    delete incompleteConsumedProof.observations.runtimeRecovery.receiptConsumption.installTransitionReceipt;
    await writeFile(ghostQualification, `${JSON.stringify(incompleteConsumedProof, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "ghost evidence with an incomplete consumed proof");
    await writeFile(ghostQualification, validGhostQualification);
    const macQualification = path.join(release, "platform-qualification-macos-universal-dmg.json");
    const hiddenMacQualification = `${macQualification}.missing`;
    await rename(macQualification, hiddenMacQualification);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "missing platform qualification");
    await rename(hiddenMacQualification, macQualification);
    const validMacQualification = JSON.parse((await readFile(macQualification)).toString("utf8"));
    const legacyMacState = JSON.parse(JSON.stringify(validMacQualification));
    legacyMacState.qualificationState = "host_limited";
    expectFailure(
      () => validatePlatformQualification(legacyMacState),
      "legacy host-limited macOS qualification",
    );
    const skippedMacContainer = JSON.parse(JSON.stringify(validMacQualification));
    skippedMacContainer.containerExecution = {
      outcome: "not_run",
      reason: "legacy-host-limitation",
    };
    expectFailure(
      () => validatePlatformQualification(skippedMacContainer),
      "untyped macOS container observation",
    );
    const dishonestMacGateway = JSON.parse(JSON.stringify(validMacQualification));
    dishonestMacGateway.egressGateway = {
      outcome: "passed",
      result: { status: "passed" },
    };
    expectFailure(
      () => validatePlatformQualification(dishonestMacGateway),
      "dishonest hosted-macOS egress gateway observation",
    );
    const unsupportedMacStart = JSON.parse(JSON.stringify(validMacQualification));
    unsupportedMacStart.managedRuntime.operations[3] = {
      name: "start",
      outcome: "unsupported",
      reason: "legacy-host-limitation",
    };
    expectFailure(
      () => validatePlatformQualification(unsupportedMacStart),
      "untyped macOS managed-runtime observation",
    );
    const stableMacQualification = JSON.parse(JSON.stringify(validMacQualification));
    stableMacQualification.releaseIdentity.releaseChannel = "stable";
    expectFailure(
      () => validatePlatformQualification(stableMacQualification),
      "stable release with runtime-not-observed macOS evidence",
    );
    const legacyMacSchema = JSON.parse(JSON.stringify(validMacQualification));
    legacyMacSchema.schemaVersion = 2;
    expectFailure(
      () => validatePlatformQualification(legacyMacSchema),
      "legacy platform qualification schema",
    );
    const incompleteMacCleanup = JSON.parse(JSON.stringify(validMacQualification));
    incompleteMacCleanup.cleanup.installedApplicationRemoved = false;
    expectFailure(
      () => validatePlatformQualification(incompleteMacCleanup),
      "incomplete macOS installer cleanup",
    );
    const wrongMacRunner = JSON.parse(JSON.stringify(validMacQualification));
    wrongMacRunner.runner.runnerLabel = "macos-14";
    expectFailure(
      () => validatePlatformQualification(wrongMacRunner),
      "wrong macOS qualification runner",
    );
    const wrongMacTarget = JSON.parse(JSON.stringify(validMacQualification));
    wrongMacTarget.runtime.selectedTarget.architecture = "aarch64";
    expectFailure(
      () => validatePlatformQualification(wrongMacTarget),
      "wrong macOS qualification runtime target",
    );
    const linuxQualification = path.join(release, "platform-qualification-linux-x86_64-deb.json");
    const validLinuxQualification = await readFile(linuxQualification);
    const tamperedQualification = JSON.parse(validLinuxQualification.toString("utf8"));
    const expectedQualificationImage =
      tamperedQualification.containerExecution.result.container.image;
    tamperedQualification.cleanup.privateDataRemoved = false;
    await writeFile(linuxQualification, `${JSON.stringify(tamperedQualification, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "dishonest platform qualification");
    await writeFile(linuxQualification, validLinuxQualification);
    const extendedQualification = JSON.parse(validLinuxQualification.toString("utf8"));
    extendedQualification.unreleasedClaim = "must fail closed";
    await writeFile(linuxQualification, `${JSON.stringify(extendedQualification, null, 2)}\n`);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "unknown qualification field");
    await writeFile(linuxQualification, validLinuxQualification);
    const relativePathQualification = JSON.parse(validLinuxQualification.toString("utf8"));
    relativePathQualification.installedLayout.cli = "relative/ai-security-scanner-cli";
    expectFailure(
      () => validatePlatformQualification(relativePathQualification, { expectedQualificationImage, expectedGatewayImage: EXPECTED_GATEWAY_IMAGE }),
      "relative installed path qualification",
    );
    const oversizedReportQualification = JSON.parse(validLinuxQualification.toString("utf8"));
    oversizedReportQualification.containerExecution.result.evidence.report_bytes = 1024 * 1024 + 1;
    expectFailure(
      () => validatePlatformQualification(oversizedReportQualification, { expectedQualificationImage, expectedGatewayImage: EXPECTED_GATEWAY_IMAGE }),
      "oversized container qualification report",
    );
    const skippedLinuxContainer = JSON.parse(validLinuxQualification.toString("utf8"));
    skippedLinuxContainer.containerExecution = {
      outcome: "not_observed",
      reasonCode: "github_hosted_macos_nested_virtualization_unsupported",
    };
    expectFailure(
      () => validatePlatformQualification(skippedLinuxContainer, { expectedQualificationImage, expectedGatewayImage: EXPECTED_GATEWAY_IMAGE }),
      "skipped Linux container qualification",
    );
    const unsafeLinuxGateway = JSON.parse(validLinuxQualification.toString("utf8"));
    unsafeLinuxGateway.egressGateway.result.gateway.upstream_connection_attempted = true;
    expectFailure(
      () => validatePlatformQualification(unsafeLinuxGateway, { expectedQualificationImage, expectedGatewayImage: EXPECTED_GATEWAY_IMAGE }),
      "egress qualification that contacted an upstream destination",
    );
    const unreachableLinuxGateway = JSON.parse(validLinuxQualification.toString("utf8"));
    unreachableLinuxGateway.egressGateway.result.gateway.scanner_reachable = false;
    expectFailure(
      () => validatePlatformQualification(unreachableLinuxGateway, { expectedQualificationImage, expectedGatewayImage: EXPECTED_GATEWAY_IMAGE }),
      "egress gateway unreachable from the isolated scanner network",
    );
    const connectingLinuxProbe = JSON.parse(validLinuxQualification.toString("utf8"));
    connectingLinuxProbe.egressGateway.result.gateway.reachability_probe = "socks5_connect";
    expectFailure(
      () => validatePlatformQualification(connectingLinuxProbe, { expectedQualificationImage, expectedGatewayImage: EXPECTED_GATEWAY_IMAGE }),
      "egress gateway qualification using a CONNECT probe",
    );
    const incompleteGatewayCleanup = JSON.parse(validLinuxQualification.toString("utf8"));
    incompleteGatewayCleanup.egressGateway.result.cleanup.probe_container_removed = false;
    expectFailure(
      () => validatePlatformQualification(incompleteGatewayCleanup, { expectedQualificationImage, expectedGatewayImage: EXPECTED_GATEWAY_IMAGE }),
      "egress gateway qualification with an unremoved probe container",
    );
    const wrongGatewayImage = JSON.parse(validLinuxQualification.toString("utf8"));
    wrongGatewayImage.egressGateway.result.gateway.image =
      `ghcr.io/teddashh/ai-security-scanner-egress-gateway@sha256:${"ff".repeat(32)}`;
    expectFailure(
      () => validatePlatformQualification(wrongGatewayImage, { expectedQualificationImage, expectedGatewayImage: EXPECTED_GATEWAY_IMAGE }),
      "egress gateway qualification with an image absent from the release manifest",
    );
    const wrongPublicationModeArguments = [...finalizeArguments];
    wrongPublicationModeArguments[wrongPublicationModeArguments.indexOf("commit-bound-qc")] =
      "public-github-release";
    expectFailure(
      () => run("finalize-release.mjs", wrongPublicationModeArguments),
      "release metadata with a mismatched publication mode",
    );
    run("finalize-release.mjs", finalizeArguments);
    const finalizedVerificationArguments = [
      "--dir",
      release,
      "--version",
      VERSION,
      "--tag",
      TAG,
      "--commit",
      COMMIT,
      "--publication-mode",
      "commit-bound-qc",
    ];
    const tamperedFinalizedFile = path.join(release, "LICENSE.txt");
    const originalFinalizedBytes = await readFile(tamperedFinalizedFile);
    await writeFile(
      tamperedFinalizedFile,
      Buffer.concat([originalFinalizedBytes, Buffer.from("tampered\n")]),
    );
    expectFailure(
      () => run("verify-finalized-release.mjs", finalizedVerificationArguments),
      "tampered finalized release",
    );
    await writeFile(tamperedFinalizedFile, originalFinalizedBytes);
    run("verify-finalized-release.mjs", finalizedVerificationArguments);
    const cyclonedx = await readJson(path.join(release, `ai-security-scanner-${VERSION}.cyclonedx.json`));
    const spdx = await readJson(path.join(release, `ai-security-scanner-${VERSION}.spdx.json`));
    const latest = await readJson(path.join(release, "latest.json"));
    const releaseNotes = await readFile(path.join(release, "RELEASE_NOTES.md"), "utf8");
    const checksums = await readFile(path.join(release, "SHA256SUMS.txt"), "utf8");
    if (
      cyclonedx.components.length !== 15 ||
      spdx.packages.length !== 15 ||
      latest.version !== VERSION ||
      !latest.notes.includes("Automatically recovers product-owned Windows scan-tool workspaces") ||
      !latest.notes.includes("preserves a verified recovery copy") ||
      !latest.notes.includes("clear bilingual progress") ||
      !releaseNotes.includes("Automatic Windows setup recovery pre-release") ||
      !releaseNotes.includes("a verified recovery archive") ||
      !releaseNotes.includes("Interrupted handoffs resume from durable checkpoints") ||
      !releaseNotes.includes("Manual Windows instructions appear only") ||
      latest.notes.includes("repair release") ||
      releaseNotes.includes("This patch release") ||
      !checksums.includes("ai-security-scanner-egress-gateway") ||
      !checksums.includes("ai-security-scanner-bootstrap-broker") ||
      !checksums.includes("ai-security-scanner-cli") ||
      !checksums.includes("platform-qualification-linux-x86_64-deb.json") ||
      !checksums.includes("platform-qualification-macos-universal-dmg.json") ||
      !checksums.includes("platform-qualification-windows-x86_64-msi.json") ||
      !checksums.includes("platform-qualification-windows-x86_64-nsis.json") ||
      !checksums.includes("windows-nsis-upgrade-qualification.json") ||
      !checksums.includes("windows-nsis-ghost-recovery-qualification.json") ||
      !releaseNotes.includes("Linux and both Windows installers completed") ||
      !releaseNotes.includes("two separate v0.1.7 migration qualifications") ||
      !releaseNotes.includes("automatic bounded recovery without the manual-action fallback") ||
      !releaseNotes.includes("fixed no-upstream managed egress gateway readiness") ||
      !releaseNotes.includes("managed-runtime, egress gateway, and container lifecycle is explicitly recorded as not observed") ||
      !releaseNotes.includes("commit-bound GitHub Actions QC artifact, not a public GitHub Release") ||
      !releaseNotes.includes("This workflow artifact has no public") ||
      releaseNotes.includes("public GitHub artifact attestation before installing") ||
      Object.keys(latest.platforms).length !== 11 ||
      !latest.platforms["windows-x86_64-nsis"] ||
      !latest.platforms["windows-x86_64-msi"] ||
      !latest.platforms["darwin-aarch64-app"] ||
      !latest.platforms["darwin-aarch64-app"].url.endsWith(
        `/ai-security-scanner_${VERSION}_universal.app.tar.gz`,
      ) ||
      !latest.platforms["linux-x86_64-appimage"] ||
      !latest.platforms["linux-x86_64-deb"] ||
      !latest.platforms["linux-x86_64-rpm"]
    ) {
      throw new Error("finalized release did not preserve updater and companion executable evidence");
    }
    process.stdout.write(
      "Release tooling self-test passed with six installers, six signed updater payloads, nine companion executables, three exact runtime-manifest evidence sets, four strict hosted installer qualifications, and two required Windows NSIS migration qualifications.\n",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

runMain(main);
