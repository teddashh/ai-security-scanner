import { lstat, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import {
  PROJECT_ROOT,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  toPosix,
  writeJsonAtomic,
  writeTextAtomic,
} from "./lib.mjs";
import { verifyUpdaterSignatures } from "./verify-updater-signatures.mjs";
import {
  ALL_UPDATER_TARGET_KEYS,
  updaterLayoutsFor,
} from "./updater-layout.mjs";
import { verifyPlatformQualificationFile } from "./platform-qualification.mjs";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const RELEASE_COPY = new Map([
  [
    "0.1.3",
    {
      updaterNotes:
        "Public testing pre-release with one-click Windows WSL setup, plain-language bilingual guidance, typed immutable local-input snapshots, exact-scope AWS/Azure/GCP provider execution, and digest-pinned engine integration. Existing local cases and historical provenance remain intact.",
      releaseNotes: [
        "> **Public testing pre-release.** This build replaces the manual Administrator PowerShell",
        "> step with one in-app action and the standard Windows confirmation dialog. It is not the",
        "> latest stable release and has not completed the planned formal QC/code review.",
        "",
        "When WSL 2 is missing, disabled, or outdated, choose **Fix this for me** /",
        "**交給程式處理**. Windows asks for administrator approval once, then the app checks the",
        "result and continues automatically. A required restart remains explicit and is never",
        "triggered by the app.",
        "",
        "The backend accepts no executable or arguments from the UI. It derives the only allowed",
        "operation from the current failed prerequisite, runs the Windows-owned System32 wsl.exe",
        "with fixed Microsoft arguments, and never receives or stores the administrator password.",
        "",
        "Manual Microsoft commands remain available under **Other ways** as a fallback. The same",
        "plain-language flow is available in English and Traditional Chinese on the setup page and",
        "in the sidebar.",
        "",
        "This candidate retains typed immutable snapshots for repository, IaC, OCI image-layout,",
        "Kubernetes manifest, and node-configuration inputs.",
        "",
        "Provider discovery stays inside its released AWS Organizations, Azure subscription, or GCP",
        "organization source boundary. Prowler execution remains separately bound to one exact AWS",
        "account, Azure subscription, or GCP project.",
        "",
        "The required 21-engine catalog is bound to immutable image, launcher, adapter, evidence,",
        "coverage, license, and verification contracts. Scanner images remain separate artifacts",
        "and are not bundled in the desktop installers.",
        "",
        "Existing local cases, cleanup obligations, evidence snapshots, and provenance remain intact.",
        "",
      ],
    },
  ],
  [
    "0.1.2",
    {
      updaterNotes:
        "Public testing pre-release with simplified bilingual setup, typed immutable local-input snapshots, exact-scope AWS/Azure/GCP provider execution, and digest-pinned engine integration. Existing local cases and historical provenance remain intact.",
      releaseNotes: [
        "> **Public testing pre-release.** Use this build to exercise the real desktop installer,",
        "> one-time scan-tool setup, guided use cases, and end-to-end results flow. It is not the",
        "> latest stable release and has not completed the planned formal QC/code review.",
        "",
        "This candidate includes the simplified English and Traditional Chinese product flow and",
        "typed immutable snapshots for repository, IaC, OCI image-layout, Kubernetes manifest, and",
        "node-configuration inputs.",
        "",
        "Provider discovery stays inside its released AWS Organizations, Azure subscription, or GCP",
        "organization source boundary. Prowler execution is separately bound to one exact AWS account,",
        "Azure subscription, or GCP project with provider-specific identity preflight and endpoint closure.",
        "Other cloud engines retain their narrower released provider scope.",
        "",
        "The required 21-engine catalog is bound to immutable image, launcher, adapter, evidence,",
        "coverage, license, and verification contracts. Scanner images remain separate artifacts",
        "and are not bundled in the desktop installers.",
        "",
        "Existing local cases, cleanup obligations, evidence snapshots, and provenance remain intact.",
        "Unknown or partial scope remains visibly distinct from a completed or passing result.",
        "",
      ],
    },
  ],
  [
    "0.2.0",
    {
      updaterNotes:
        "Product-completion line with typed immutable local-input snapshots, exact-scope AWS/Azure/GCP provider execution, and digest-pinned engine integration. Existing local cases and historical provenance remain intact.",
      releaseNotes: [
        "This product-completion release adds typed immutable snapshots for repository, IaC, OCI",
        "image-layout, Kubernetes manifest, and node-configuration inputs.",
        "",
        "Provider discovery stays inside its released AWS Organizations, Azure subscription, or GCP",
        "organization source boundary. Prowler execution is separately bound to one exact AWS account,",
        "Azure subscription, or GCP project with provider-specific identity preflight and endpoint closure.",
        "Other cloud engines retain their narrower released provider scope.",
        "",
        "The required 21-engine catalog is bound to immutable image, launcher, adapter, evidence,",
        "coverage, license, and verification contracts. Scanner images remain separate artifacts",
        "and are not bundled in the desktop installers.",
        "",
        "Existing local cases, cleanup obligations, evidence snapshots, and provenance remain intact.",
        "Unknown or partial scope remains visibly distinct from a completed or passing result.",
        "",
      ],
    },
  ],
]);

function releaseCopyFor(version) {
  return RELEASE_COPY.get(version) ?? {
    updaterNotes:
      "Signed ai-security-scanner application update. Existing local cases and historical provenance remain intact.",
    releaseNotes: [],
  };
}

async function regularFiles(directory, root = directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    const metadata = await lstat(candidate);
    if (metadata.isSymbolicLink()) {
      throw new Error(`release artifacts contain a symlink: ${candidate}`);
    }
    if (metadata.isDirectory()) {
      files.push(...(await regularFiles(candidate, root)));
    } else if (metadata.isFile()) {
      files.push({
        absolute: candidate,
        relative: toPosix(path.relative(root, candidate)),
        bytes: metadata.size,
      });
    } else {
      throw new Error(`release artifacts contain a special file: ${candidate}`);
    }
  }
  return files;
}

async function verifyPlatformManifest(directory, platform, version, tag, commit) {
  const name = `installers-${platform}.json`;
  const manifest = await readJson(path.join(directory, name));
  assert(manifest.schemaVersion === 2, `${name} has the wrong schema version`);
  assert(manifest.product === "ai-security-scanner", `${name} has the wrong product`);
  assert(manifest.version === version && manifest.tag === tag, `${name} version/tag mismatch`);
  assert(manifest.sourceCommit === commit, `${name} source commit mismatch`);
  assert(manifest.platform === platform, `${name} platform mismatch`);
  assert(manifest.platformCodeSigning === "not-configured", `${name} makes a signing claim`);
  assert(manifest.updaterArtifact === true, `${name} has no signed updater artifact`);
  assert(Array.isArray(manifest.installers) && manifest.installers.length > 0, `${name} is empty`);

  const checksumEntries = new Map();
  for (const installer of manifest.installers) {
    assert(typeof installer.file === "string", `${name} has an invalid installer path`);
    assert(path.basename(installer.file) === installer.file, `${name} installer path is not flat`);
    const file = path.join(directory, installer.file);
    const metadata = await lstat(file);
    assert(metadata.isFile() && !metadata.isSymbolicLink(), `${installer.file} is not a regular file`);
    assert(metadata.size === installer.bytes, `${installer.file} byte length mismatch`);
    assert((await sha256File(file)) === installer.sha256, `${installer.file} digest mismatch`);
    checksumEntries.set(installer.file, installer.sha256);
  }
  assert(
    Array.isArray(manifest.auxiliaryExecutables) && manifest.auxiliaryExecutables.length === 3,
    `${name} must contain exactly three first-party companion executables`,
  );
  const expectedAuxiliary = [
    ["managed-egress-gateway", "ai-security-scanner-egress-gateway"],
    ["isolated-bootstrap-broker", "ai-security-scanner-bootstrap-broker"],
    ["local-casework-cli", "ai-security-scanner-cli"],
  ];
  for (const [index, sidecar] of manifest.auxiliaryExecutables.entries()) {
    const [expectedRole, expectedBinary] = expectedAuxiliary[index];
    const expectedSibling = `${expectedBinary}${platform === "windows-x86_64" ? ".exe" : ""}`;
    assert(sidecar.role === expectedRole, `${name} has an unknown or out-of-order auxiliary role`);
    assert(sidecar.binaryName === expectedBinary, `${name} has the wrong auxiliary binary name`);
    assert(sidecar.installedSiblingName === expectedSibling, `${name} has the wrong installed sidecar name`);
    assert(
      typeof sidecar.releaseFile === "string" && path.basename(sidecar.releaseFile) === sidecar.releaseFile,
      `${name} has an invalid sidecar release path`,
    );
    const sidecarFile = path.join(directory, sidecar.releaseFile);
    const sidecarMetadata = await lstat(sidecarFile);
    assert(
      sidecarMetadata.isFile() && !sidecarMetadata.isSymbolicLink(),
      `${sidecar.releaseFile} is not regular`,
    );
    assert(sidecarMetadata.size === sidecar.bytes, `${sidecar.releaseFile} byte length mismatch`);
    assert((await sha256File(sidecarFile)) === sidecar.sha256, `${sidecar.releaseFile} digest mismatch`);
    checksumEntries.set(sidecar.releaseFile, sidecar.sha256);
  }

  const expectedLayouts = updaterLayoutsFor(platform);
  assert(
    Array.isArray(manifest.updaters) && manifest.updaters.length === expectedLayouts.length,
    `${name} has incomplete signed updater records`,
  );
  for (const [index, updater] of manifest.updaters.entries()) {
    const expected = expectedLayouts[index];
    assert(updater && typeof updater === "object", `${name} has an invalid updater record`);
    assert(updater.bundleType === expected.bundleType, `${name} updater bundle type is out of order`);
    assert(
      JSON.stringify(updater.targetKeys) === JSON.stringify(expected.targetKeys),
      `${name}/${expected.bundleType} updater target keys are incomplete or out of order`,
    );
    for (const field of ["payloadFile", "signatureFile"]) {
      assert(
        typeof updater[field] === "string" && path.basename(updater[field]) === updater[field],
        `${name}/${expected.bundleType} updater ${field} is not a flat filename`,
      );
    }
    const payloadFile = path.join(directory, updater.payloadFile);
    const payloadMetadata = await lstat(payloadFile);
    assert(
      payloadMetadata.isFile() && !payloadMetadata.isSymbolicLink(),
      `${name}/${expected.bundleType} updater payload is not regular`,
    );
    assert(
      payloadMetadata.size === updater.payloadBytes,
      `${name}/${expected.bundleType} updater payload byte length mismatch`,
    );
    assert(
      (await sha256File(payloadFile)) === updater.payloadSha256,
      `${name}/${expected.bundleType} updater payload digest mismatch`,
    );
    const signatureFile = path.join(directory, updater.signatureFile);
    const signatureMetadata = await lstat(signatureFile);
    assert(
      signatureMetadata.isFile() && !signatureMetadata.isSymbolicLink(),
      `${name}/${expected.bundleType} updater signature is not regular`,
    );
    assert(
      signatureMetadata.size === updater.signatureBytes,
      `${name}/${expected.bundleType} updater signature byte length mismatch`,
    );
    assert(
      (await sha256File(signatureFile)) === updater.signatureSha256,
      `${name}/${expected.bundleType} updater signature digest mismatch`,
    );
    const signature = (await readFile(signatureFile, "utf8")).trim();
    assert(
      signature === updater.signature,
      `${name}/${expected.bundleType} embedded updater signature differs from its file`,
    );
    assert(
      signature.length >= 64 && /^[A-Za-z0-9+/=]+$/u.test(signature),
      `${name}/${expected.bundleType} updater signature is malformed`,
    );
    checksumEntries.set(updater.payloadFile, updater.payloadSha256);
    checksumEntries.set(updater.signatureFile, updater.signatureSha256);
  }
  const checksumFile = path.join(directory, `SHA256SUMS-${platform}.txt`);
  const checksumContents = await readFile(checksumFile, "utf8");
  const checksumLines = [...checksumEntries].map(([file, digest]) => `${digest}  ${file}`);
  assert(checksumContents === `${checksumLines.join("\n")}\n`, `${platform} checksum file mismatch`);
  return {
    installers: manifest.installers.map((installer) => installer.file),
    sidecars: manifest.auxiliaryExecutables.map((sidecar) => ({ ...sidecar, platform })),
    updaters: manifest.updaters.map((updater) => ({ ...updater, platform })),
  };
}

async function verifyRuntimeEvidence(directory, platform) {
  const prefix = `managed-runtime-${platform}`;
  const manifest = await readJson(path.join(directory, `${prefix}.manifest.json`));
  const cyclonedx = await readJson(path.join(directory, `${prefix}.cyclonedx.json`));
  const spdx = await readJson(path.join(directory, `${prefix}.spdx.json`));
  const notices = await readFile(path.join(directory, `${prefix}.NOTICES.txt`), "utf8");
  assert(manifest.schema_version === "2", `${prefix} has an unsupported manifest schema`);
  assert(Array.isArray(manifest.files) && manifest.files.length > 0, `${prefix} has no file inventory`);
  assert(Array.isArray(manifest.targets) && manifest.targets.length > 0, `${prefix} has no target inventory`);
  assert(Array.isArray(manifest.components) && manifest.components.length > 0, `${prefix} has no components`);
  const coveredFiles = new Set();
  const coveredDownloads = new Set();
  for (const component of manifest.components) {
    assert(component.id && component.version && component.source_revision, `${prefix} component identity is incomplete`);
    assert(component.license_spdx && component.repository_url, `${prefix} component license/source is incomplete`);
    assert(notices.includes(component.name) && notices.includes(component.license_spdx), `${prefix} notices omit ${component.id}`);
    if (/GPL-/u.test(component.license_spdx)) {
      assert(
        component.source_archive?.url && component.source_archive?.sha256 && component.source_archive?.size_bytes,
        `${prefix} GPL component ${component.id} has no exact corresponding-source archive`,
      );
    }
    for (const artifact of component.artifacts ?? []) {
      if (artifact.delivery === "bundled_file") coveredFiles.add(artifact.locator);
      if (artifact.delivery === "runtime_download") coveredDownloads.add(artifact.locator);
    }
  }
  assert(manifest.files.every((file) => coveredFiles.has(file.path)), `${prefix} leaves a bundled file unattributed`);
  assert(manifest.targets.every((target) => coveredDownloads.has(target.machine_image.url)), `${prefix} leaves a runtime download unattributed`);
  assert(
    cyclonedx.bomFormat === "CycloneDX" && cyclonedx.components?.length === manifest.components.length,
    `${prefix} CycloneDX inventory does not match its manifest`,
  );
  assert(
    spdx.spdxVersion === "SPDX-2.3" && spdx.packages?.length === manifest.components.length,
    `${prefix} SPDX inventory does not match its manifest`,
  );
  return manifest.components.map((component) => ({ ...component, platform }));
}

function enrichSboms(cyclonedx, spdx, sidecars, runtimeComponents, version) {
  assert(Array.isArray(cyclonedx.components), "CycloneDX SBOM has no components array");
  assert(Array.isArray(spdx.packages), "SPDX SBOM has no packages array");
  if (!Array.isArray(spdx.relationships)) {
    spdx.relationships = [];
  }
  for (const sidecar of sidecars) {
    const purl = `pkg:cargo/ai-security-scanner@${version}?binary=${sidecar.binaryName}&platform=${sidecar.platform}`;
    cyclonedx.components.push({
      type: "application",
      "bom-ref": purl,
      name: sidecar.binaryName,
      version,
      hashes: [{ alg: "SHA-256", content: sidecar.sha256 }],
      licenses: [{ license: { id: "Apache-2.0" } }],
      properties: [
        { name: "ai-security-scanner:platform", value: sidecar.platform },
        { name: "ai-security-scanner:release-file", value: sidecar.releaseFile },
        { name: "ai-security-scanner:installed-sibling-name", value: sidecar.installedSiblingName },
        { name: "ai-security-scanner:sidecar-role", value: sidecar.role },
      ],
    });
    const spdxId = `SPDXRef-Package-${sidecar.binaryName}-${sidecar.platform}`;
    spdx.packages.push({
      SPDXID: spdxId,
      name: `${sidecar.binaryName}-${sidecar.platform}`,
      versionInfo: version,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      checksums: [{ algorithm: "SHA256", checksumValue: sidecar.sha256 }],
      licenseConcluded: "Apache-2.0",
      licenseDeclared: "Apache-2.0",
      copyrightText: "Copyright 2026 Ted Huang and ai-security-scanner contributors",
      primaryPackagePurpose: "APPLICATION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: purl,
        },
      ],
      summary: `First-party ${sidecar.role} installed beside the desktop executable for ${sidecar.platform}.`,
    });
    spdx.relationships.push({
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: spdxId,
    });
  }
  for (const component of runtimeComponents) {
    const purl = `pkg:generic/${encodeURIComponent(component.id)}@${encodeURIComponent(component.version)}?platform=${encodeURIComponent(component.platform)}`;
    cyclonedx.components.push({
      type: "application",
      "bom-ref": purl,
      name: component.name,
      version: component.version,
      licenses: [{ expression: component.license_spdx }],
      externalReferences: [{ type: "vcs", url: `${component.repository_url}/tree/${component.source_revision}` }],
      properties: [
        { name: "ai-security-scanner:platform", value: component.platform },
        { name: "ai-security-scanner:relationship", value: component.relationship },
        ...component.artifacts.map((artifact) => ({
          name: `ai-security-scanner:runtime-artifact:${artifact.delivery}:${artifact.locator}`,
          value: `sha256:${artifact.sha256};bytes:${artifact.size_bytes}`,
        })),
      ],
    });
    const spdxId = `SPDXRef-Runtime-${component.id}-${component.platform}`.replace(/[^A-Za-z0-9.-]/gu, "-");
    spdx.packages.push({
      SPDXID: spdxId,
      name: `${component.name}-${component.platform}`,
      versionInfo: component.version,
      downloadLocation: `${component.repository_url}/tree/${component.source_revision}`,
      filesAnalyzed: false,
      licenseConcluded: component.license_spdx,
      licenseDeclared: component.license_spdx,
      copyrightText: "NOASSERTION",
      primaryPackagePurpose: "APPLICATION",
      externalRefs: [{
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: purl,
      }],
      summary: `${component.relationship}; exact artifacts are recorded in the platform runtime manifest.`,
    });
    spdx.relationships.push({
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: spdxId,
    });
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const directory = path.resolve(requireString(args, "dir"));
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  const configuredPath = args.get("tauri-config");
  if (configuredPath !== undefined && typeof configuredPath !== "string") {
    throw new Error("--tauri-config requires an explicit path");
  }
  const tauriConfigPath = path.resolve(
    configuredPath ?? path.join(PROJECT_ROOT, "src-tauri", "tauri.conf.json"),
  );
  if (!isSemver(version) || tag !== `v${version}` || !/^[0-9a-f]{40}$/u.test(commit)) {
    throw new Error("release identity is malformed or inconsistent");
  }

  const metadata = await readJson(path.join(directory, "release-metadata.json"));
  const tauriConfig = await readJson(tauriConfigPath);
  const packageJson = await readJson(path.join(PROJECT_ROOT, "package.json"));
  const updaterPublicKey = tauriConfig.plugins?.updater?.pubkey;
  assert(
    typeof updaterPublicKey === "string" && updaterPublicKey.length >= 64,
    "tauri config has no embedded updater public key",
  );
  assert(metadata.version === version && metadata.tag === tag, "release metadata version/tag mismatch");
  assert(
    metadata.releaseChannel === packageJson.release?.channel &&
      metadata.stableTarget === packageJson.release?.target,
    "release metadata publication channel does not match the source package",
  );
  assert(metadata.sourceCommit === commit, "release metadata commit mismatch");
  assert(
    metadata.security?.operatingSystemCodeSigning?.state === "not-configured" &&
      metadata.security?.appleNotarization?.state === "not-configured",
    "release metadata must not claim OS code signing or notarization",
  );
  assert(
    metadata.security?.updater?.state === "enabled-signed" &&
      metadata.security.updater.artifactsGenerated === true &&
      metadata.security.updater.signingConfigured === true,
    "release metadata must report updater artifacts enabled and signed",
  );
  assert(
    Array.isArray(metadata.distribution?.bundledEngines) &&
      metadata.distribution.bundledEngines.length === 0,
    "release metadata must report that no engines are bundled",
  );

  const cyclonedxName = `ai-security-scanner-${version}.cyclonedx.json`;
  const spdxName = `ai-security-scanner-${version}.spdx.json`;
  const cyclonedx = await readJson(path.join(directory, cyclonedxName));
  const spdx = await readJson(path.join(directory, spdxName));
  assert(cyclonedx.bomFormat === "CycloneDX", "CycloneDX SBOM has the wrong format marker");
  assert(typeof spdx.spdxVersion === "string" && spdx.spdxVersion.startsWith("SPDX-"), "SPDX SBOM has the wrong format marker");
  for (const required of [
    "THIRD_PARTY_NOTICES.txt",
    "ENGINE_NOTICES.md",
    "ENGINE_NOTICES.json",
    "LICENSE.txt",
  ]) {
    const metadata_ = await lstat(path.join(directory, required));
    assert(metadata_.isFile() && metadata_.size > 0, `required release evidence is empty: ${required}`);
  }

  const platforms = ["linux-x86_64", "macos-universal", "windows-x86_64"];
  const qualificationNames = (await regularFiles(directory))
    .map((file) => file.relative)
    .filter((name) => name.startsWith("platform-qualification-") && name.endsWith(".json"))
    .sort();
  assert(
    JSON.stringify(qualificationNames) === JSON.stringify(platforms.map((platform) => `platform-qualification-${platform}.json`).sort()),
    "release must contain exactly the three recognized platform qualification records",
  );
  const installers = [];
  const sidecars = [];
  const updaters = [];
  const runtimeComponents = [];
  const platformQualifications = [];
  for (const platform of platforms) {
    const verified = await verifyPlatformManifest(directory, platform, version, tag, commit);
    installers.push(...verified.installers);
    sidecars.push(...verified.sidecars);
    updaters.push(...verified.updaters);
    runtimeComponents.push(...(await verifyRuntimeEvidence(directory, platform)));
    platformQualifications.push(await verifyPlatformQualificationFile(
      path.join(directory, `platform-qualification-${platform}.json`),
      {
        platform,
        version,
        tag,
        commit,
        releaseChannel: metadata.releaseChannel,
        releaseDirectory: directory,
      },
    ));
  }
  assert(installers.some((file) => file.endsWith(".deb")), "release has no Debian installer");
  assert(installers.some((file) => file.endsWith(".rpm")), "release has no RPM installer");
  assert(installers.some((file) => file.endsWith(".AppImage")), "release has no AppImage installer");
  assert(installers.some((file) => file.endsWith(".dmg")), "release has no macOS DMG installer");
  assert(installers.some((file) => file.endsWith(".msi")), "release has no Windows MSI installer");
  assert(installers.some((file) => file.endsWith(".exe")), "release has no Windows NSIS installer");
  assert(new Set(installers).size === installers.length, "installer names collide across platforms");
  assert(
    sidecars.length === 9 && new Set(sidecars.map((sidecar) => sidecar.releaseFile)).size === 9,
    "companion executable set is incomplete or filenames collide",
  );
  verifyUpdaterSignatures(
    updaterPublicKey,
    updaters.map((updater) => ({
      payload: path.join(directory, updater.payloadFile),
      signature: path.join(directory, updater.signatureFile),
    })),
  );

  const updatePlatforms = {};
  for (const updater of updaters) {
    const url = `https://github.com/teddashh/ai-security-scanner/releases/download/${tag}/${encodeURIComponent(updater.payloadFile)}`;
    for (const target of updater.targetKeys) {
      assert(!updatePlatforms[target], `duplicate updater target key: ${target}`);
      updatePlatforms[target] = { url, signature: updater.signature };
    }
  }
  assert(
    Object.keys(updatePlatforms).length === ALL_UPDATER_TARGET_KEYS.length &&
      ALL_UPDATER_TARGET_KEYS.every((target) => updatePlatforms[target]),
    "release updater manifest has incomplete platform coverage",
  );
  const releaseCopy = releaseCopyFor(version);
  await writeJsonAtomic(path.join(directory, "latest.json"), {
    version,
    notes: releaseCopy.updaterNotes,
    pub_date: metadata.sourceDate,
    platforms: updatePlatforms,
  });

  enrichSboms(cyclonedx, spdx, sidecars, runtimeComponents, version);
  await writeJsonAtomic(path.join(directory, cyclonedxName), cyclonedx);
  await writeJsonAtomic(path.join(directory, spdxName), spdx);

  const notes = [
    `# ai-security-scanner ${version}`,
    "",
    `Source: \`${commit}\``,
    "",
    ...releaseCopy.releaseNotes,
    "These desktop installers are built for Linux x86-64, universal macOS (Intel + Apple silicon),",
    "and Windows x86-64. Verify the selected file against `SHA256SUMS.txt` and the public GitHub",
    "artifact attestation before installing.",
    "",
    "Fresh GitHub-hosted qualification jobs independently installed the Debian package, macOS DMG,",
    "and Windows MSI. Linux and Windows completed managed-runtime install, start, status, fixed",
    "network-disabled Gitleaks container execution, stop, uninstall with image-cache purge, and",
    "private-state cleanup. The universal macOS artifact's DMG installation, bundled layout, exact",
    "runtime manifest, CLI, desktop startup, and cleanup passed on GitHub's Intel macos-15-intel",
    "runner. Its managed-runtime and container lifecycle is explicitly recorded as not observed",
    "because GitHub-hosted macOS does not support the nested virtualization required by AppleHV.",
    "This limited macOS evidence is accepted only for a pre-release. Exact evidence is published",
    "per platform.",
    "",
    "> The current installers are not signed with Apple Developer ID or Windows Authenticode and",
    "> are not Apple-notarized. Application update payloads are separately signed with the updater",
    "> key, but the operating system may still show an unidentified-developer warning. No scanner",
    "> engine image is bundled.",
    "",
    "The first-party `ai-security-scanner-egress-gateway`, isolated",
    "`ai-security-scanner-bootstrap-broker`, and local `ai-security-scanner-cli` companion",
    "executables are installed beside the desktop executable.",
    "Platform copies and hashes are included as release evidence and SBOM entries.",
    "",
    "CycloneDX and SPDX JSON SBOMs, generated third-party notices, engine reference notices, and",
    "machine-readable release metadata accompany the installers.",
    "",
  ].join("\n");
  await writeTextAtomic(path.join(directory, "RELEASE_NOTES.md"), notes);

  const beforeIndex = (await regularFiles(directory))
    .filter((file) => file.relative !== "SHA256SUMS.txt" && file.relative !== "release-assets.json")
    .sort((left, right) => left.relative.localeCompare(right.relative));
  const fileRecords = [];
  for (const file of beforeIndex) {
    fileRecords.push({ path: file.relative, bytes: file.bytes, sha256: await sha256File(file.absolute) });
  }
  await writeJsonAtomic(path.join(directory, "release-assets.json"), {
    schemaVersion: 1,
    product: "ai-security-scanner",
    version,
    tag,
    sourceCommit: commit,
    indexSelfExcluded: true,
    files: fileRecords,
  });

  const finalFiles = (await regularFiles(directory))
    .filter((file) => file.relative !== "SHA256SUMS.txt")
    .sort((left, right) => left.relative.localeCompare(right.relative));
  const checksums = [];
  for (const file of finalFiles) {
    checksums.push(`${await sha256File(file.absolute)}  ${file.relative}`);
  }
  await writeTextAtomic(path.join(directory, "SHA256SUMS.txt"), `${checksums.join("\n")}\n`);
  process.stdout.write(
    `Finalized ${installers.length} installers, ${updaters.length} signed updater payloads, ${sidecars.length} first-party companion executables, ${platformQualifications.length} hosted platform qualifications, and ${finalFiles.length} evidence files for ${tag}.\n`,
  );
}

runMain(main);
