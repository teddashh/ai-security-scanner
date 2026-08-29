import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { gzipSync, gunzipSync } from "node:zlib";
import {
  copyFile,
  lstat,
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
function deterministicEd25519KeyPair(seedLabel) {
  const seed = createHash("sha256").update(seedLabel, "utf8").digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

const LEGACY_TEST_KEY_PAIR = deterministicEd25519KeyPair(
  "ai-security-scanner release self-test retained signed bundle identity v1",
);
const WRONG_PRIOR_TEST_KEY_PAIR = deterministicEd25519KeyPair(
  "ai-security-scanner release self-test wrong prior signer v1",
);
const LEGACY_TEST_PUBLIC_SPKI = LEGACY_TEST_KEY_PAIR.publicKey.export({ format: "der", type: "spki" });
const LEGACY_TEST_PUBLIC_KEY = LEGACY_TEST_PUBLIC_SPKI.subarray(-32);
const LEGACY_PUBLIC_KEY_BASE64 = LEGACY_TEST_PUBLIC_KEY.toString("base64");
const LEGACY_KEY_ID = createHash("sha256").update(LEGACY_TEST_PUBLIC_KEY).digest("hex");
const LOCAL_SIGNING_IDENTITY_NOTICE =
  "This is a local export-integrity identity. It does not prove scanner correctness, completeness, authorship, organizational identity, audit status, or compliance.";
const MASTER_FRAMEWORK_REPORT_NOTICE =
  "This report groups preliminary scanner observations by related framework coordinate. It is not an audit, certification, attestation, compliance determination, implementation assessment, score, pass, or fail. Missing relationships are unknown whenever coverage is incomplete.";
const BUNDLE_INTEGRITY_ONLY_NOTICE =
  "The Ed25519 signature establishes integrity of the signed manifest only. It does not prove scanner correctness, completeness, legal authorization, authorship, identity, audit status, or forensic validity.";

function createLegacySigningIdentityFixture() {
  const unsigned = {
    schema_version: "1",
    algorithm: "Ed25519",
    key_id: LEGACY_KEY_ID,
    public_key_base64: LEGACY_PUBLIC_KEY_BASE64,
    established_at: "2026-08-29T12:00:00Z",
    continuity_event: "legacy_key_adopted",
    previous_identity: null,
    notice: LOCAL_SIGNING_IDENTITY_NOTICE,
  };
  const selfSignature = sign(
    null,
    Buffer.from(JSON.stringify(unsigned), "utf8"),
    LEGACY_TEST_KEY_PAIR.privateKey,
  ).toString("base64");
  const document = {
    schema_version: unsigned.schema_version,
    algorithm: unsigned.algorithm,
    key_id: unsigned.key_id,
    public_key_base64: unsigned.public_key_base64,
    established_at: unsigned.established_at,
    continuity_event: unsigned.continuity_event,
    self_signature_base64: selfSignature,
    notice: unsigned.notice,
  };
  const compact = Buffer.from(JSON.stringify(document), "utf8");
  return {
    document,
    compactSha256: createHash("sha256").update(compact).digest("hex"),
    bytes: compact.length,
  };
}

function jsonFixtureBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function writeTarText(header, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > length) throw new Error(`release self-test tar field is too long: ${value}`);
  bytes.copy(header, offset);
}

function writeTarOctal(header, offset, length, value) {
  const encoded = `${value.toString(8).padStart(length - 1, "0")}\0`;
  if (encoded.length !== length) throw new Error(`release self-test tar integer exceeds its field: ${value}`);
  header.write(encoded, offset, length, "ascii");
}

function tarEntry(pathname, bytes) {
  const header = Buffer.alloc(512);
  writeTarText(header, 0, 100, pathname);
  writeTarOctal(header, 100, 8, 0o600);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, bytes.length);
  writeTarOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeTarText(header, 257, 6, "ustar");
  writeTarText(header, 263, 2, "00");
  const checksum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  const padding = Buffer.alloc((512 - (bytes.length % 512)) % 512);
  return Buffer.concat([header, bytes, padding]);
}

function createSignedCaseBundleFixture({
  version,
  caseId,
  runId,
  payloads,
  keyPair = LEGACY_TEST_KEY_PAIR,
  schemas = { bundle: "1" },
  rawArtifactCount = 0,
}) {
  const publicSpki = keyPair.publicKey.export({ format: "der", type: "spki" });
  const publicKey = publicSpki.subarray(-32);
  const keyId = createHash("sha256").update(publicKey).digest("hex");
  const publicKeyBase64 = publicKey.toString("base64");
  const sortedPayloads = Object.entries(payloads)
    .sort(([left], [right]) => left.localeCompare(right));
  const entries = sortedPayloads.map(([pathname, record]) => ({
    path: pathname,
    media_type: record.mediaType,
    sha256: createHash("sha256").update(record.bytes).digest("hex"),
    byte_length: record.bytes.length,
    contains_sensitive_data: record.sensitive,
  }));
  const manifest = {
    schema_version: "1",
    product_name: "ai-security-scanner",
    product_version: version,
    created_at: "2026-08-29T12:30:00Z",
    case_id: caseId,
    run_id: runId,
    redaction_profile: "standard",
    demo_data: true,
    schemas,
    entries,
    raw_artifact_count: rawArtifactCount,
    raw_artifacts_included: 0,
    signing: {
      algorithm: "Ed25519",
      key_id: keyId,
      signed_file: "manifest.json",
      integrity_only_notice: BUNDLE_INTEGRITY_ONLY_NOTICE,
    },
    notices: [
      "This package contains preliminary scanner evidence, not an audit, certification, attestation, compliance determination, or forensic conclusion. Related control references are navigation coordinates only.",
      BUNDLE_INTEGRITY_ONLY_NOTICE,
      "SYNTHETIC DEMO DATA: this package must not be represented as a real scan or engine validation.",
    ],
  };
  const manifestBytes = jsonFixtureBytes(manifest);
  const envelope = {
    algorithm: "Ed25519",
    key_id: keyId,
    public_key_base64: publicKeyBase64,
    signature_base64: sign(null, manifestBytes, keyPair.privateKey).toString("base64"),
    signed_file: "manifest.json",
    integrity_only_notice: BUNDLE_INTEGRITY_ONLY_NOTICE,
  };
  return gzipSync(Buffer.concat([
    ...sortedPayloads.map(([pathname, record]) => tarEntry(pathname, record.bytes)),
    tarEntry("manifest.json", manifestBytes),
    tarEntry("signature.json", jsonFixtureBytes(envelope)),
    Buffer.alloc(1024),
  ]), { level: 9, mtime: 0 });
}

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

function createMasterFrameworkSignedFixture(caseId, runId, identityDocument) {
  const recordedAt = "2026-08-27T12:18:00Z";
  const knowledgeDate = "2026-08-27T12:00:00Z";
  const observedAt = "2026-08-27T12:10:00Z";
  const engineRunId = "engine-run-gitleaks-001";
  const artifactId = "raw-artifact-gitleaks-001";
  const observationId = "observation-secret-001";
  const findingId = "finding-secret-001";
  const evidenceId = "evidence-secret-001";
  const assetId = "asset-source-code-001";
  const fingerprint = "release-self-test:gitleaks:synthetic-secret";
  const artifactSha256 = createHash("sha256")
    .update("synthetic redacted Gitleaks evidence for release self-test", "utf8")
    .digest("hex");
  const mappingVersion = "synthetic-fixture-1";
  const findingTitle = "Synthetic credential-like value requires review";
  const finding = {
    observation_id: observationId,
    finding_id: findingId,
    fingerprint,
    title: findingTitle,
    severity: "high",
    confidence: "high",
    observed_at: observedAt,
    snapshot_source: "run_snapshot",
    evidence_hashes: [artifactSha256],
    asset_ids: [assetId],
    engine_ids: ["gitleaks"],
  };
  const binding = {
    evidence_id: evidenceId,
    artifact_id: artifactId,
    artifact_sha256: artifactSha256,
    engine_run_id: engineRunId,
    engine_id: "gitleaks",
    source_rule: null,
    engine_mapping_version: null,
    engine_mapping_provenance_state: "unavailable_legacy",
    engine_mapping_provenance: null,
    mapping_version_state: "unavailable",
  };
  const frameworkSource = (framework) => {
    if (framework === "NIST CSF") {
      return {
        source_url: "https://doi.org/10.6028/NIST.CSWP.29",
        attribution_notice: "NIST Cybersecurity Framework (CSF) 2.0, National Institute of Standards and Technology.",
        license_notice: "Use of NIST source material remains subject to the source publication's notices.",
        modifications_notice: "Framework relationships and rationales in this report are project-authored navigation metadata.",
        non_endorsement_notice: "NIST has not reviewed or endorsed this report or integration.",
      };
    }
    if (framework === "ISO/IEC 27001") {
      return {
        source_url: "https://www.iso.org/standard/27001",
        attribution_notice: "ISO/IEC 27001:2022 control coordinates are referenced nominatively.",
        license_notice: "ISO/IEC standard content remains subject to ISO's terms; this report is not a copy of the standard.",
        modifications_notice: "Framework relationships and rationales in this report are project-authored navigation metadata.",
        non_endorsement_notice: "ISO and IEC have not reviewed or endorsed this report or integration.",
      };
    }
    return {
      source_url: "https://github.com/edward-playground/aidefense-framework/blob/e10c1678ee49f03f8fb0c97d446ba3fbc3543655/data/data.json",
      attribution_notice: "AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.",
      license_notice: "Creative Commons Attribution 4.0 International: https://creativecommons.org/licenses/by/4.0/",
      modifications_notice: "ai-security-scanner uses a modified, project-authored six-record metadata selection from AIDEFEND 1.20260805 at pinned commit e10c1678ee49f03f8fb0c97d446ba3fbc3543655.",
      non_endorsement_notice: "This independent integration is not affiliated with, approved, certified, sponsored, or endorsed by AIDEFEND or its owner.",
    };
  };
  const relatedFramework = ({ framework, expectedVersion, controlId, title, rationale }) => ({
    framework,
    expected_version: expectedVersion,
    source: frameworkSource(framework),
    observed_versions: [expectedVersion],
    version_state: "expected_version_only",
    observed_mapping_versions: [mappingVersion],
    evidence_engine_mapping_versions: [],
    mapping_version_state: "relationship_provenance_unavailable",
    exact_match_relationship_count: 0,
    mismatch_relationship_count: 0,
    unavailable_relationship_count: 1,
    state: "related_coordinates_observed",
    relationship_count: 1,
    control_count: 1,
    finding_count: 1,
    explanation: "One or more preliminary findings carry an evidence-bound relationship to this framework. The relationship is a navigation aid, not a control result.",
    controls: [{
      control_id: controlId,
      title,
      framework_version: expectedVersion,
      relationships: [{
        relationship: "related",
        rationale,
        mapping_version: mappingVersion,
        mapping_provenance_state: "unavailable_legacy",
        mapping_provenance: null,
        mapping_version_state: "unavailable",
        finding: { ...finding },
        evidence_bindings: [{ ...binding }],
      }],
    }],
  });
  const nistReference = {
    control_id: "PR.DS-01",
    framework: "NIST CSF",
    framework_version: "2.0",
    mapping_provenance: null,
    mapping_version: mappingVersion,
    rationale: "Credential exposure evidence is related to protecting stored authentication data.",
    relationship: "related",
    title: "Data-at-rest protection",
  };
  const isoReference = {
    control_id: "A.8.3",
    framework: "ISO/IEC 27001",
    framework_version: "2022",
    mapping_provenance: null,
    mapping_version: mappingVersion,
    rationale: "Credential exposure evidence is related to restricting access to sensitive information.",
    relationship: "related",
    title: "Information access restriction",
  };
  const report = {
    schema_version: "1.1.0",
    product_name: "ai-security-scanner",
    product_version: VERSION,
    export_kind: "master_framework_relationship_report",
    case_id: caseId,
    selected_run_id: runId,
    selected_run_sequence: 1,
    selected_run_recorded_at: recordedAt,
    knowledge_date: knowledgeDate,
    notice: MASTER_FRAMEWORK_REPORT_NOTICE,
    coverage: {
      state: "incomplete_or_unknown",
      coverage_ledger_basis: "current_case_coverage_as_of_export",
      selected_run_checks_complete: true,
      current_coverage_ledger_has_unknown_or_incomplete_entries: true,
      historical_coverage_mismatch_count: 0,
      planned_engine_count: 1,
      completed_engine_count: 1,
      unfinished_engine_count: 0,
      not_executed_engine_count: 0,
      coverage_entry_count: 1,
      unknown_source_count: 1,
      connected_no_asset_count: 0,
      authorized_incomplete_count: 0,
      discovered_not_authorized_count: 0,
      selected_run_finding_count: 1,
      selected_run_snapshot_count: 1,
      selected_run_missing_snapshot_count: 0,
      selected_run_observations_without_evidence_count: 0,
      engine_states: { completed: 1 },
      coverage_states: { source_not_connected_unknown: 1 },
      limitations: [
        "1 source area(s) had no visibility; this is unknown coverage, not zero assets.",
        "No related finding or framework coordinate is interpreted as a passed control or a complete environment.",
      ],
    },
    declared_ai_context: {
      ai_system_applicability: "unknown",
      ai_generated_artifact: "unknown",
      aidefend_applicability: "unknown",
      explanation: "At least one required AI-context answer is legacy or unanswered, and no answer explicitly establishes AI applicability. AIDEFEND applicability remains unknown.",
    },
    observation_provenance: [{
      observation_id: observationId,
      finding_id: findingId,
      fingerprint,
      snapshot_state: "run_snapshot",
      evidence_reference_state: "validated_from_run_snapshot",
      framework_mapping_state: "run_snapshot_relationships_used",
    }],
    frameworks: [
      relatedFramework({
        framework: "NIST CSF",
        expectedVersion: "2.0",
        controlId: nistReference.control_id,
        title: nistReference.title,
        rationale: nistReference.rationale,
      }),
      relatedFramework({
        framework: "ISO/IEC 27001",
        expectedVersion: "2022",
        controlId: isoReference.control_id,
        title: isoReference.title,
        rationale: isoReference.rationale,
      }),
      {
        framework: "AIDEFEND",
        expected_version: "1.20260805",
        source: frameworkSource("AIDEFEND"),
        observed_versions: [],
        version_state: "no_relationship_observed",
        observed_mapping_versions: [],
        evidence_engine_mapping_versions: [],
        mapping_version_state: "no_relationship_observed",
        exact_match_relationship_count: 0,
        mismatch_relationship_count: 0,
        unavailable_relationship_count: 0,
        state: "unknown_due_to_unanswered_context",
        relationship_count: 0,
        control_count: 0,
        finding_count: 0,
        explanation: "No AIDEFEND coordinate was inferred because at least one required AI-context answer is legacy or unanswered. This remains unknown, not not-applicable.",
        controls: [],
      },
    ],
    unrecognized_relationships: [],
  };
  const rawArtifacts = {
    raw_artifacts: [{
      id: artifactId,
      case_id: caseId,
      run_id: runId,
      engine_run_id: engineRunId,
      sha256: artifactSha256,
    }],
  };
  const scanRuns = {
    scan_runs: [{
      id: runId,
      case_id: caseId,
      sequence: 1,
      created_at: knowledgeDate,
      completed_at: recordedAt,
      knowledge_cutoff: knowledgeDate,
      ai_system_applicable: false,
      ai_system_applicability: "unknown",
      ai_generated_artifact: "unknown",
      engine_runs: [{
        id: engineRunId,
        scan_run_id: runId,
        engine_id: "gitleaks",
        status: "completed",
        mapping_version: null,
        mapping_provenance: null,
      }],
    }],
  };
  const observations = {
    finding_observations: [{
      id: observationId,
      finding_id: findingId,
      fingerprint,
      observed_at: observedAt,
      run_id: runId,
      severity: "high",
      confidence: "high",
      asset_ids: [assetId],
      engine_ids: ["gitleaks"],
      evidence_hashes: [artifactSha256],
      finding_snapshot: {
        id: findingId,
        case_id: caseId,
        fingerprint,
        last_seen_run_id: runId,
        severity: "high",
        confidence: "high",
        title: findingTitle,
        asset_ids: [assetId],
        evidence: [{
          id: evidenceId,
          artifact_id: artifactId,
          artifact_sha256: artifactSha256,
          engine_id: "gitleaks",
          engine_run_id: engineRunId,
          finding_id: findingId,
          run_id: runId,
          source_rule: null,
        }],
        control_references: [nistReference, isoReference],
      },
    }],
  };
  const coverage = {
    coverage: [{
      id: "coverage-source-unknown-001",
      last_run_id: runId,
      status: "source_not_connected_unknown",
    }],
  };
  const reportBytes = jsonFixtureBytes(report);
  const candidatePayloads = {
    "coverage.json": { bytes: jsonFixtureBytes(coverage), mediaType: "application/json", sensitive: true },
    "exports/master-framework-report.json": { bytes: reportBytes, mediaType: "application/json", sensitive: true },
    "integrity/local-signing-identity.json": { bytes: jsonFixtureBytes(identityDocument), mediaType: "application/json", sensitive: false },
    "observations.json": { bytes: jsonFixtureBytes(observations), mediaType: "application/json", sensitive: true },
    "raw-artifacts.json": { bytes: jsonFixtureBytes(rawArtifacts), mediaType: "application/json", sensitive: true },
    "scan-runs.json": { bytes: jsonFixtureBytes(scanRuns), mediaType: "application/json", sensitive: true },
  };
  return {
    report,
    reportBytes,
    candidatePayloads,
    priorPayloads: {
      "case.json": {
        bytes: jsonFixtureBytes({ case_id: caseId, selected_run_id: runId, fixture: "n-minus-one-before-upgrade" }),
        mediaType: "application/json",
        sensitive: true,
      },
    },
  };
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
  const identityFixture = createLegacySigningIdentityFixture();
  const signing = {
    signingKeyIdBefore: LEGACY_KEY_ID,
    signingKeyIdAfter: LEGACY_KEY_ID,
    publicKeyBase64Before: LEGACY_PUBLIC_KEY_BASE64,
    publicKeyBase64After: LEGACY_PUBLIC_KEY_BASE64,
    privateSigningKeyProtected: true,
    publicIdentitySummaryExact: true,
    durableIdentityDocumentPresent: true,
    identityDocumentBytes: identityFixture.bytes,
    identityDocumentCompactSha256: identityFixture.compactSha256,
    identityDocumentProtected: true,
    durableIdentityAnchorPresent: true,
    identityAnchorBytes: 2048,
    identityAnchorProtected: true,
    anchorSchemaVersion: "1",
    anchorIdentityDocumentSha256: identityFixture.compactSha256,
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
  const reportCaseId = "00112233-4455-6677-8899-aabbccddeeff";
  const reportRunId = "11223344-5566-7788-99aa-bbccddeeff00";
  const signedFrameworkFixture = createMasterFrameworkSignedFixture(
    reportCaseId,
    reportRunId,
    identityFixture.document,
  );
  const masterFrameworkReportFile = path.join(output, "master-framework-report.json");
  await writeFile(masterFrameworkReportFile, signedFrameworkFixture.reportBytes);
  const masterFrameworkReportBytes = (await lstat(masterFrameworkReportFile)).size;
  const masterFrameworkReportSha256 = await sha256File(masterFrameworkReportFile);
  const candidateBundleFile = path.join(output, "master-framework-report.case.tar.gz");
  const priorBundleFile = path.join(output, "n-minus-one-before-upgrade.case.tar.gz");
  const candidateBundleOptions = {
    version: VERSION,
    caseId: reportCaseId,
    runId: reportRunId,
    payloads: signedFrameworkFixture.candidatePayloads,
    schemas: {
      bundle: "1",
      local_signing_identity: "1",
      master_framework_report: "1.1.0",
    },
    rawArtifactCount: 1,
  };
  const priorBundleOptions = {
    version: "0.1.7",
    caseId: reportCaseId,
    runId: reportRunId,
    payloads: signedFrameworkFixture.priorPayloads,
  };
  const validCandidateBundle = createSignedCaseBundleFixture(candidateBundleOptions);
  const validPriorBundle = createSignedCaseBundleFixture(priorBundleOptions);
  if (
    !validCandidateBundle.equals(createSignedCaseBundleFixture(candidateBundleOptions)) ||
    !validPriorBundle.equals(createSignedCaseBundleFixture(priorBundleOptions))
  ) {
    throw new Error("release self-test signed case bundle fixtures are not byte-deterministic");
  }
  await writeFile(candidateBundleFile, validCandidateBundle);
  await writeFile(priorBundleFile, validPriorBundle);
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
      demoCaseId: reportCaseId,
      demoCasePreserved: true,
      privateSigningMaterialBytePreserved: true,
      ...signing,
      identityDocument: identityFixture.document,
    },
    masterFrameworkReport: {
      reportFile: "master-framework-report.json",
      reportBytes: masterFrameworkReportBytes,
      reportSha256: masterFrameworkReportSha256,
      bundleEntryPath: "exports/master-framework-report.json",
      bundleEntryBytes: masterFrameworkReportBytes,
      bundleEntrySha256: masterFrameworkReportSha256,
      exactBundleEntryMatch: true,
      schemaVersion: "1.1.0",
      product: "ai-security-scanner",
      productVersion: VERSION,
      caseId: reportCaseId,
      runId: reportRunId,
      frameworkKeys: ["nist_csf", "iso_iec_27001", "aidefend"],
      truthfulUnknownCoverage: true,
      noComplianceOutcomeClaims: true,
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
    "--report", masterFrameworkReportFile,
    "--bundle", candidateBundleFile, "--prior-bundle", priorBundleFile,
    "--out", upgradeEvidence, "--version", VERSION, "--tag", TAG, "--commit", COMMIT,
  ]);
  const validateUpgradeEvidence = () => run("windows-nsis-upgrade-evidence.mjs", [
    "validate", "--file", upgradeEvidence, "--artifact-dir", output,
    "--report", masterFrameworkReportFile,
    "--bundle", candidateBundleFile, "--prior-bundle", priorBundleFile,
    "--version", VERSION, "--tag", TAG, "--commit", COMMIT,
  ]);
  validateUpgradeEvidence();

  await writeFile(priorBundleFile, createSignedCaseBundleFixture({
    ...priorBundleOptions,
    keyPair: WRONG_PRIOR_TEST_KEY_PAIR,
  }));
  expectFailure(validateUpgradeEvidence, "N-1 signed case bundle with the wrong integrity signer");
  await writeFile(priorBundleFile, validPriorBundle);

  const candidateBundleWithJsonMutation = (entryPath, mutate) => {
    const payloads = Object.fromEntries(Object.entries(signedFrameworkFixture.candidatePayloads)
      .map(([pathname, record]) => [pathname, { ...record, bytes: Buffer.from(record.bytes) }]));
    const document = JSON.parse(payloads[entryPath].bytes.toString("utf8"));
    mutate(document);
    payloads[entryPath].bytes = jsonFixtureBytes(document);
    return createSignedCaseBundleFixture({ ...candidateBundleOptions, payloads });
  };
  const reportBindingPayloads = Object.fromEntries(
    Object.entries(signedFrameworkFixture.candidatePayloads)
      .map(([pathname, record]) => [pathname, { ...record, bytes: Buffer.from(record.bytes) }]),
  );
  reportBindingPayloads["exports/master-framework-report.json"].bytes = Buffer.concat([
    signedFrameworkFixture.reportBytes,
    Buffer.from(" \n", "utf8"),
  ]);
  await writeFile(candidateBundleFile, createSignedCaseBundleFixture({
    ...candidateBundleOptions,
    payloads: reportBindingPayloads,
  }));
  expectFailure(validateUpgradeEvidence, "signed case bundle whose report bytes do not bind to the retained report");
  await writeFile(candidateBundleFile, validCandidateBundle);

  const impossibleProvenanceBundle = candidateBundleWithJsonMutation("observations.json", (document) => {
    document.finding_observations[0].finding_snapshot.evidence[0].artifact_sha256 = "ff".repeat(32);
  });
  if (
    impossibleProvenanceBundle.equals(validCandidateBundle) ||
    !gunzipSync(impossibleProvenanceBundle).includes(Buffer.from(`"artifact_sha256": "${"ff".repeat(32)}"`))
  ) {
    throw new Error("release self-test failed to construct its impossible signed provenance fixture");
  }
  await writeFile(candidateBundleFile, impossibleProvenanceBundle);
  expectFailure(validateUpgradeEvidence, "signed case bundle with impossible observation provenance");
  await writeFile(candidateBundleFile, validCandidateBundle);

  await writeFile(candidateBundleFile, candidateBundleWithJsonMutation("scan-runs.json", (document) => {
    document.scan_runs[0].ai_system_applicability = "not_applicable";
    document.scan_runs[0].ai_generated_artifact = "no";
  }));
  expectFailure(validateUpgradeEvidence, "signed case bundle whose frozen AI answers contradict the report");
  await writeFile(candidateBundleFile, validCandidateBundle);

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
    const candidateSignedBundle = path.join(release, "master-framework-report.case.tar.gz");
    const hiddenCandidateSignedBundle = `${candidateSignedBundle}.missing`;
    await rename(candidateSignedBundle, hiddenCandidateSignedBundle);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "missing candidate signed case bundle");
    await rename(hiddenCandidateSignedBundle, candidateSignedBundle);
    const priorSignedBundle = path.join(release, "n-minus-one-before-upgrade.case.tar.gz");
    const hiddenPriorSignedBundle = `${priorSignedBundle}.missing`;
    await rename(priorSignedBundle, hiddenPriorSignedBundle);
    expectFailure(() => run("finalize-release.mjs", finalizeArguments), "missing N-1 signed case bundle");
    await rename(hiddenPriorSignedBundle, priorSignedBundle);
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
    const invalidIdentitySignature = JSON.parse(validUpgradeQualification.toString("utf8"));
    const identityDocument = invalidIdentitySignature.observations.dataPreservation.identityDocument;
    const invalidSignatureBytes = Buffer.from(identityDocument.self_signature_base64, "base64");
    invalidSignatureBytes[0] ^= 0x01;
    identityDocument.self_signature_base64 = invalidSignatureBytes.toString("base64");
    const invalidIdentityCompact = Buffer.from(JSON.stringify(identityDocument), "utf8");
    const invalidIdentityDigest = createHash("sha256").update(invalidIdentityCompact).digest("hex");
    invalidIdentitySignature.observations.dataPreservation.identityDocumentCompactSha256 = invalidIdentityDigest;
    invalidIdentitySignature.observations.dataPreservation.anchorIdentityDocumentSha256 = invalidIdentityDigest;
    await writeFile(upgradeQualification, `${JSON.stringify(invalidIdentitySignature, null, 2)}\n`);
    expectFailure(
      () => run("finalize-release.mjs", finalizeArguments),
      "upgrade evidence with a forged public identity self-signature",
    );
    await writeFile(upgradeQualification, validUpgradeQualification);
    const masterFrameworkReportPath = path.join(release, "master-framework-report.json");
    const validMasterFrameworkReport = await readFile(masterFrameworkReportPath);
    await writeFile(
      masterFrameworkReportPath,
      Buffer.concat([validMasterFrameworkReport, Buffer.from(" \n")]),
    );
    expectFailure(
      () => run("finalize-release.mjs", finalizeArguments),
      "retained master framework report whose bytes differ from its signed bundle entry",
    );
    await writeFile(masterFrameworkReportPath, validMasterFrameworkReport);
    const expectSemanticallyInvalidBoundReport = async (mutate, label) => {
      const report = JSON.parse(validMasterFrameworkReport.toString("utf8"));
      mutate(report);
      const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`, "utf8");
      const reportSha256 = createHash("sha256").update(reportBytes).digest("hex");
      const qualification = JSON.parse(validUpgradeQualification.toString("utf8"));
      const binding = qualification.observations.masterFrameworkReport;
      binding.reportBytes = reportBytes.length;
      binding.reportSha256 = reportSha256;
      binding.bundleEntryBytes = reportBytes.length;
      binding.bundleEntrySha256 = reportSha256;
      await writeFile(masterFrameworkReportPath, reportBytes);
      await writeFile(upgradeQualification, `${JSON.stringify(qualification, null, 2)}\n`);
      expectFailure(() => run("finalize-release.mjs", finalizeArguments), label);
      await writeFile(masterFrameworkReportPath, validMasterFrameworkReport);
      await writeFile(upgradeQualification, validUpgradeQualification);
    };
    await expectSemanticallyInvalidBoundReport(
      (report) => { report.schema_version = "1.0.0"; },
      "master framework report with an unsupported schema",
    );
    await expectSemanticallyInvalidBoundReport(
      (report) => { [report.frameworks[0], report.frameworks[1]] = [report.frameworks[1], report.frameworks[0]]; },
      "master framework report with reordered framework identities",
    );
    await expectSemanticallyInvalidBoundReport(
      (report) => { report.compliance_score = 100; },
      "master framework report with a forbidden compliance outcome",
    );
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
      "--test-only-windows-runtime-manifest-sha256",
      selfTestRuntimeManifestSha256,
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
    const releaseAssets = await readJson(path.join(release, "release-assets.json"));
    const releaseNotes = await readFile(path.join(release, "RELEASE_NOTES.md"), "utf8");
    const checksums = await readFile(path.join(release, "SHA256SUMS.txt"), "utf8");
    const checksumLines = checksums.trimEnd().split("\n");
    if (
      cyclonedx.components.length !== 15 ||
      spdx.packages.length !== 15 ||
      releaseAssets.files.length !== 58 ||
      checksumLines.length !== 59 ||
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
      !checksums.includes("master-framework-report.json") ||
      !checksums.includes("master-framework-report.case.tar.gz") ||
      !checksums.includes("n-minus-one-before-upgrade.case.tar.gz") ||
      !releaseNotes.includes("Linux and both Windows installers completed") ||
      !releaseNotes.includes("two separate v0.1.7 migration qualifications") ||
      !releaseNotes.includes("NIST CSF 2.0") ||
      !releaseNotes.includes("AIDEFEND 1.20260805") ||
      !releaseNotes.includes("without turning them into a compliance score") ||
      !releaseNotes.includes("same report bytes are bound to the candidate's verified signed case bundle") ||
      !releaseNotes.includes("Both bounded synthetic case bundles—from the real N-1 install and the candidate—are retained") ||
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
      "Release tooling self-test passed with six installers, six signed updater payloads, nine companion executables, three exact runtime-manifest evidence sets, four strict hosted installer qualifications, one evidence-bound master framework report, two deterministic retained signed case bundles, and two required Windows NSIS migration qualifications.\n",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

runMain(main);
