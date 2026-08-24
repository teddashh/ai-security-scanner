import { constants } from "node:fs";
import { copyFile, lstat, mkdir, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import {
  isSemver,
  parseArgs,
  requireString,
  runMain,
  sha256File,
  writeJsonAtomic,
  writeTextAtomic,
} from "./lib.mjs";
import { UPDATER_LAYOUTS, updaterLayoutsFor } from "./updater-layout.mjs";

const BUNDLE_EXTENSIONS = new Map([
  ["appimage", ".AppImage"],
  ["deb", ".deb"],
  ["dmg", ".dmg"],
  ["msi", ".msi"],
  ["nsis", ".exe"],
  ["rpm", ".rpm"],
]);

const AUXILIARY_LAYOUTS = Object.freeze([
  Object.freeze({
    argument: "egress-sidecar",
    role: "managed-egress-gateway",
    binaryName: "ai-security-scanner-egress-gateway",
  }),
  Object.freeze({
    argument: "bootstrap-broker",
    role: "isolated-bootstrap-broker",
    binaryName: "ai-security-scanner-bootstrap-broker",
  }),
  Object.freeze({
    argument: "casework-cli",
    role: "local-casework-cli",
    binaryName: "ai-security-scanner-cli",
  }),
]);

async function regularFilesDirectlyBelow(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    const metadata = await lstat(candidate);
    if (metadata.isSymbolicLink()) {
      throw new Error(`bundle output contains a symlink: ${candidate}`);
    }
    if (metadata.isDirectory()) {
      // Tauri keeps non-publishable staging trees beside the final artifacts
      // (for example, an AppDir and a macOS .app). Their internal symlinks are
      // valid bundle structure; only direct, regular files can be released.
      continue;
    } else if (metadata.isFile()) {
      output.push(candidate);
    } else {
      throw new Error(`bundle output contains a special file: ${candidate}`);
    }
  }
  return output;
}

async function collectUpdater(bundleRoot, output, platform, version, names, layout) {
  const directory = path.join(bundleRoot, layout.directory);
  const signatures = (await regularFilesDirectlyBelow(directory))
    .filter((file) => file.endsWith(layout.signatureSuffix))
    .sort();
  if (signatures.length !== 1) {
    throw new Error(
      `${platform}/${layout.bundleType} must produce exactly one ${layout.signatureSuffix} updater signature; found ${signatures.length}`,
    );
  }
  const signatureSource = signatures[0];
  const payloadSource = signatureSource.slice(0, -".sig".length);
  const payloadMetadata = await lstat(payloadSource);
  if (!payloadMetadata.isFile() || payloadMetadata.isSymbolicLink() || payloadMetadata.size < 1024) {
    throw new Error(`${platform}/${layout.bundleType} updater payload is not a non-empty regular file`);
  }
  const sourcePayloadName = path.basename(payloadSource);
  const sourceSignatureName = path.basename(signatureSource);
  let payloadName = sourcePayloadName;
  let signatureName = sourceSignatureName;
  if (platform === "macos-universal" && layout.bundleType === "app") {
    const tauriPayloadName = "ai-security-scanner.app.tar.gz";
    const releasePayloadName = `ai-security-scanner_${version}_universal.app.tar.gz`;
    if (![tauriPayloadName, releasePayloadName].includes(sourcePayloadName)) {
      throw new Error(
        `${platform}/${layout.bundleType} updater payload has an unexpected Tauri application archive name`,
      );
    }
    if (sourceSignatureName !== `${sourcePayloadName}.sig`) {
      throw new Error(`${platform}/${layout.bundleType} updater signature does not name its payload`);
    }
    // Tauri intentionally names macOS application bundles without a version and
    // therefore emits `<product>.app.tar.gz`. GitHub release assets need an
    // immutable, versioned name; renaming leaves the already-signed bytes intact.
    payloadName = releasePayloadName;
    signatureName = `${releasePayloadName}.sig`;
  }
  if (
    !payloadName.toLowerCase().includes(version.toLowerCase()) ||
    /[\0\r\n]/u.test(payloadName) ||
    /[\0\r\n]/u.test(signatureName)
  ) {
    throw new Error(`${platform}/${layout.bundleType} updater filenames are malformed or lack their version`);
  }

  const payloadDestination = path.join(output, payloadName);
  if (names.has(payloadName)) {
    if ((await sha256File(payloadDestination)) !== (await sha256File(payloadSource))) {
      throw new Error(`${platform}/${layout.bundleType} updater payload differs from its collected installer`);
    }
  } else {
    names.add(payloadName);
    await copyFile(payloadSource, payloadDestination, constants.COPYFILE_EXCL);
  }
  if (names.has(signatureName)) {
    throw new Error(`duplicate updater signature filename: ${signatureName}`);
  }
  names.add(signatureName);
  const signatureDestination = path.join(output, signatureName);
  await copyFile(signatureSource, signatureDestination, constants.COPYFILE_EXCL);
  const signatureMetadata = await lstat(signatureDestination);
  const signature = (await readFile(signatureDestination, "utf8")).trim();
  if (
    signatureMetadata.size < 64 ||
    signatureMetadata.size > 32 * 1024 ||
    signature.length < 64 ||
    !/^[A-Za-z0-9+/=]+$/u.test(signature)
  ) {
    throw new Error(`${platform}/${layout.bundleType} updater signature is not a bounded base64 minisign envelope`);
  }

  return {
    bundleType: layout.bundleType,
    targetKeys: [...layout.targetKeys],
    payloadFile: payloadName,
    payloadBytes: payloadMetadata.size,
    payloadSha256: await sha256File(payloadDestination),
    signatureFile: signatureName,
    signatureBytes: signatureMetadata.size,
    signatureSha256: await sha256File(signatureDestination),
    signature,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bundleRoot = path.resolve(requireString(args, "bundle-root"));
  const output = path.resolve(requireString(args, "out"));
  const platform = requireString(args, "platform");
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  const auxiliarySources = AUXILIARY_LAYOUTS.map((layout) => ({
    ...layout,
    source: path.resolve(requireString(args, layout.argument)),
  }));
  const expected = requireString(args, "expect").split(",");

  if (!Object.hasOwn(UPDATER_LAYOUTS, platform)) {
    throw new Error(`unsupported release platform: ${platform}`);
  }
  if (!isSemver(version) || tag !== `v${version}`) {
    throw new Error("bundle version and tag are inconsistent");
  }
  if (!/^[0-9a-f]{40}$/u.test(commit)) {
    throw new Error("bundle commit must be a full lowercase Git object ID");
  }
  if (new Set(expected).size !== expected.length || expected.length === 0) {
    throw new Error("expected bundle kinds must be non-empty and unique");
  }
  for (const kind of expected) {
    if (!BUNDLE_EXTENSIONS.has(kind)) {
      throw new Error(`unknown bundle kind: ${kind}`);
    }
  }

  await mkdir(output, { recursive: true });
  const existing = await readdir(output);
  if (existing.length !== 0) {
    throw new Error(`output directory must start empty: ${output}`);
  }

  const installers = [];
  const names = new Set();
  for (const kind of expected) {
    const typeDirectory = path.join(bundleRoot, kind);
    const extension = BUNDLE_EXTENSIONS.get(kind);
    const matches = (await regularFilesDirectlyBelow(typeDirectory)).filter((file) =>
      file.endsWith(extension),
    );
    if (matches.length === 0) {
      throw new Error(`no ${kind} installer was produced below ${typeDirectory}`);
    }
    for (const source of matches.sort()) {
      const name = path.basename(source);
      if (
        name.includes("\0") ||
        /[\r\n]/u.test(name) ||
        !name.toLowerCase().includes(version.toLowerCase())
      ) {
        throw new Error(`installer filename is malformed or lacks its version: ${name}`);
      }
      if (names.has(name)) {
        throw new Error(`duplicate installer filename: ${name}`);
      }
      names.add(name);
      const destination = path.join(output, name);
      await copyFile(source, destination, constants.COPYFILE_EXCL);
      const metadata = await lstat(destination);
      installers.push({
        bundleType: kind,
        file: name,
        bytes: metadata.size,
        sha256: await sha256File(destination),
      });
    }
  }

  installers.sort((left, right) => left.file.localeCompare(right.file));
  const updaters = [];
  for (const layout of updaterLayoutsFor(platform)) {
    updaters.push(await collectUpdater(bundleRoot, output, platform, version, names, layout));
  }
  const sidecarExtension = platform === "windows-x86_64" ? ".exe" : "";
  const auxiliaryExecutables = [];
  for (const auxiliary of auxiliarySources) {
    const metadata = await lstat(auxiliary.source);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1024) {
      throw new Error(`${auxiliary.role} sidecar is not a non-empty regular file`);
    }
    const installedSiblingName = `${auxiliary.binaryName}${sidecarExtension}`;
    const releaseFile = `${auxiliary.binaryName}-${version}-${platform}${sidecarExtension}`;
    if (names.has(releaseFile)) {
      throw new Error(`duplicate auxiliary executable filename: ${releaseFile}`);
    }
    names.add(releaseFile);
    await copyFile(auxiliary.source, path.join(output, releaseFile), constants.COPYFILE_EXCL);
    auxiliaryExecutables.push({
      role: auxiliary.role,
      binaryName: auxiliary.binaryName,
      releaseFile,
      installedSiblingName,
      bytes: metadata.size,
      sha256: await sha256File(auxiliary.source),
    });
  }
  await writeJsonAtomic(path.join(output, `installers-${platform}.json`), {
    schemaVersion: 2,
    product: "ai-security-scanner",
    version,
    tag,
    sourceCommit: commit,
    platform,
    platformCodeSigning: "not-configured",
    updaterArtifact: true,
    updaters,
    installers,
    auxiliaryExecutables,
  });
  const checksumEntries = new Map();
  for (const item of [...installers, ...auxiliaryExecutables]) {
    checksumEntries.set(item.file ?? item.releaseFile, item.sha256);
  }
  for (const updater of updaters) {
    checksumEntries.set(updater.payloadFile, updater.payloadSha256);
    checksumEntries.set(updater.signatureFile, updater.signatureSha256);
  }
  await writeTextAtomic(
    path.join(output, `SHA256SUMS-${platform}.txt`),
    `${[...checksumEntries]
      .map(([file, digest]) => `${digest}  ${file}`)
      .join("\n")}\n`,
  );
  process.stdout.write(
    `Collected ${installers.length} ${platform} installer(s), ${updaters.length} signed updater payload(s), and ${auxiliaryExecutables.length} companion executables in ${output}\n`,
  );
}

runMain(main);
