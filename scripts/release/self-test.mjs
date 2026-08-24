import { execFileSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PROJECT_ROOT, readJson, runMain, sha256File } from "./lib.mjs";
import { verifyUpdaterSignatures } from "./verify-updater-signatures.mjs";

const VERSION = "0.1.0";
const TAG = `v${VERSION}`;
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const TEST_KEY_PASSWORD = "release-self-test-only";
const TAURI_CLI = path.join(PROJECT_ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js");

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
      schema_version: "2",
      bundle_id: "release-self-test",
      runtime_version: VERSION,
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
        architecture: platform === "macos-universal" ? "aarch64" : "x86_64",
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

async function main() {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "ai-security-scanner-release-self-test-"));
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
        schemaVersion: 1,
        product: "ai-security-scanner",
        version: VERSION,
        tag: TAG,
        sourceRepository: "https://github.com/teddashh/ai-security-scanner",
        sourceCommit: COMMIT,
        sourceDate: "2026-08-24T00:00:00Z",
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
            state: "required-before-publication",
            provider: "GitHub artifact attestations",
          },
        },
        inventories: { npmPackageCount: 0, cargoPackageCount: 0, engineReferenceCount: 0 },
      })}\n`,
    );

    run("finalize-release.mjs", [
      "--dir",
      release,
      "--version",
      VERSION,
      "--tag",
      TAG,
      "--commit",
      COMMIT,
      "--tauri-config",
      tauriConfig,
    ]);
    const finalizedVerificationArguments = [
      "--dir",
      release,
      "--version",
      VERSION,
      "--tag",
      TAG,
      "--commit",
      COMMIT,
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
    const checksums = await readFile(path.join(release, "SHA256SUMS.txt"), "utf8");
    if (
      cyclonedx.components.length !== 15 ||
      spdx.packages.length !== 15 ||
      !checksums.includes("ai-security-scanner-egress-gateway") ||
      !checksums.includes("ai-security-scanner-bootstrap-broker") ||
      !checksums.includes("ai-security-scanner-cli") ||
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
      "Release tooling self-test passed with six installers, six signed updater payloads, nine companion executables, and three exact managed-runtime evidence sets.\n",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

runMain(main);
