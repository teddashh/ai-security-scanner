import { copyFile, lstat, mkdir, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import {
  PROJECT_ROOT,
  assertSafeRelativePath,
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
import { updaterLayoutsFor } from "./updater-layout.mjs";
import { verifyPlatformQualificationFile } from "./platform-qualification.mjs";
import { verifyBoundArtifactEvidenceFile } from "./artifact-evidence.mjs";
import { verifyWindowsNsisSupportingDataPreservationEvidence } from "./windows-data-preservation-evidence.mjs";
import {
  platformContract,
  provenanceForArtifact,
  requiresStablePublicWindowsEvidence,
  validateReleaseMetadataV3,
} from "./release-metadata.mjs";

const PUBLICATION_MODES = new Set(["commit-bound-qc", "public-github-release"]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const RELEASE_COPY = new Map([
  [
    "0.1.8",
    {
      updaterNotes:
        "Keeps old or uncertain scan-tool workspaces untouched, prepares a fresh isolated workspace automatically, and gets the first useful local scan moving without a manual cleanup detour.",
      releaseNotes: [
        "> **Faster first scan, safer automatic recovery.** This build keeps internal runtime details",
        "> out of the beginner path and favors an isolated, reversible recovery when old state is unclear.",
        "",
        "On first launch, product-owned disposable state is reconciled automatically. Old state whose",
        "ownership is uncertain is left untouched while the app creates a uniquely named isolated",
        "workspace and continues. Nothing unfamiliar is deleted just to make the scanner start.",
        "",
        "The app opens the selected task immediately, keeps recovery in the background, and reports",
        "tested, not tested, failed, and incomplete coverage separately instead of turning one optional",
        "component failure into an all-or-nothing result.",
        "",
        "Existing local cases, cleanup obligations, evidence snapshots, and provenance remain intact.",
        "The app still waits for an explicit Start action before contacting a scan target.",
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

async function verifyRuntimeEvidence(directory, platform) {
  const prefix = `managed-runtime-${platform}`;
  const manifestPath = path.join(directory, `${prefix}.manifest.json`);
  const manifest = await readJson(manifestPath);
  const manifestSha256 = await sha256File(manifestPath);
  const cyclonedx = await readJson(path.join(directory, `${prefix}.cyclonedx.json`));
  const spdx = await readJson(path.join(directory, `${prefix}.spdx.json`));
  const notices = await readFile(path.join(directory, `${prefix}.NOTICES.txt`), "utf8");
  assert(manifest.schema_version === "3", `${prefix} has an unsupported manifest schema`);
  assert(
    manifest.management_contract_revision === "2026-08-29.1",
    `${prefix} has the wrong management contract revision`,
  );
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
  const runtimeProperties = new Map(
    (cyclonedx.metadata?.properties ?? []).map((property) => [
      property.name,
      property.value,
    ]),
  );
  assert(
    runtimeProperties.get("ai-security-scanner:manifest-sha256") === manifestSha256 &&
      runtimeProperties.get("ai-security-scanner:management-contract-revision") ===
        manifest.management_contract_revision,
    `${prefix} CycloneDX metadata does not bind its manifest and management contract`,
  );
  assert(
    spdx.spdxVersion === "SPDX-2.3" && spdx.packages?.length === manifest.components.length,
    `${prefix} SPDX inventory does not match its manifest`,
  );
  assert(
    spdx.documentNamespace?.endsWith(`/${manifestSha256}`) &&
      notices.includes(`Manifest SHA-256: ${manifestSha256}`) &&
      notices.includes(
        `Management contract revision: ${manifest.management_contract_revision}`,
      ),
    `${prefix} release provenance does not bind its exact manifest identity`,
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

async function regularFileIfPresent(file) {
  try {
    const metadata = await lstat(file);
    return metadata.isFile() && !metadata.isSymbolicLink() ? metadata : null;
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return null;
    throw error;
  }
}

function isFlatReleaseName(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !/[\0\r\n]/u.test(value) &&
    value !== "." &&
    value !== ".." &&
    path.posix.basename(value) === value &&
    path.win32.basename(value) === value
  );
}

async function readCandidatePlatformManifest(input, platform, version, tag, commit) {
  const name = `installers-${platform}.json`;
  if (!(await regularFileIfPresent(path.join(input, name)))) return null;
  const manifest = await readJson(path.join(input, name));
  assert(manifest.schemaVersion === 2, `${name} has the wrong schema version`);
  assert(manifest.product === "ai-security-scanner", `${name} has the wrong product`);
  assert(manifest.version === version && manifest.tag === tag, `${name} version/tag mismatch`);
  assert(manifest.sourceCommit === commit && manifest.platform === platform, `${name} release identity mismatch`);
  assert(Array.isArray(manifest.installers), `${name} has no installer records`);
  assert(Array.isArray(manifest.auxiliaryExecutables), `${name} has no companion records`);
  assert(Array.isArray(manifest.updaters), `${name} has no updater records array`);
  assert(Array.isArray(manifest.updaterFailures), `${name} has no optional-updater failure records array`);
  const releasedInstallerTypes = platformContract(platform).installerTypes;
  assert(
    Array.isArray(manifest.requestedBundleTypes) &&
      JSON.stringify([...manifest.requestedBundleTypes].sort()) ===
        JSON.stringify([...releasedInstallerTypes].sort()),
    `${name} requested installer matrix is invalid`,
  );
  assert(
    Array.isArray(manifest.availableBundleTypes) && manifest.availableBundleTypes.length > 0 &&
      new Set(manifest.availableBundleTypes).size === manifest.availableBundleTypes.length &&
      manifest.availableBundleTypes.every((installerType) => releasedInstallerTypes.includes(installerType)),
    `${name} available installer matrix is invalid`,
  );
  return manifest;
}

async function verifyCompanionEvidence(input, platform, manifest) {
  const expected = [
    ["managed-egress-gateway", "ai-security-scanner-egress-gateway"],
    ["isolated-bootstrap-broker", "ai-security-scanner-bootstrap-broker"],
    ["local-casework-cli", "ai-security-scanner-cli"],
  ];
  assert(manifest.auxiliaryExecutables.length === expected.length, `${platform} companion evidence is incomplete`);
  for (const [index, sidecar] of manifest.auxiliaryExecutables.entries()) {
    const [role, binaryName] = expected[index];
    assert(sidecar.role === role && sidecar.binaryName === binaryName, `${platform} companion identity is invalid`);
    assert(isFlatReleaseName(sidecar.releaseFile), `${platform} companion filename is invalid`);
    const metadata = await regularFileIfPresent(path.join(input, sidecar.releaseFile));
    assert(metadata && metadata.size === sidecar.bytes, `${platform}/${sidecar.releaseFile} companion bytes are invalid`);
    assert((await sha256File(path.join(input, sidecar.releaseFile))) === sidecar.sha256, `${platform}/${sidecar.releaseFile} companion digest is invalid`);
  }
  return manifest.auxiliaryExecutables.map((sidecar) => ({ ...sidecar, platform }));
}

async function verifyUpdaterForInstaller(input, platform, installerType, manifest, updaterPublicKey) {
  try {
    const updaterType = platform === "macos-universal" && installerType === "dmg" ? "app" : installerType;
    const layout = updaterLayoutsFor(platform).find(({ bundleType }) => bundleType === updaterType);
    if (!layout) return null;
    if (typeof updaterPublicKey !== "string" || updaterPublicKey.length < 64) return null;
    const matches = manifest.updaters.filter((record) =>
      record && typeof record === "object" && !Array.isArray(record) && record.bundleType === updaterType,
    );
    if (matches.length !== 1) return null;
    const updater = matches[0];
    if (JSON.stringify(updater.targetKeys) !== JSON.stringify(layout.targetKeys)) return null;
    for (const field of ["payloadFile", "signatureFile"]) {
      if (!isFlatReleaseName(updater[field])) return null;
    }
    if (
      !Number.isSafeInteger(updater.payloadBytes) || updater.payloadBytes <= 0 ||
      !Number.isSafeInteger(updater.signatureBytes) || updater.signatureBytes <= 0 ||
      !/^[0-9a-f]{64}$/u.test(updater.payloadSha256) ||
      !/^[0-9a-f]{64}$/u.test(updater.signatureSha256) ||
      typeof updater.signature !== "string"
    ) return null;
    const payloadMetadata = await regularFileIfPresent(path.join(input, updater.payloadFile));
    const signatureMetadata = await regularFileIfPresent(path.join(input, updater.signatureFile));
    if (
      !payloadMetadata || payloadMetadata.size !== updater.payloadBytes ||
      !signatureMetadata || signatureMetadata.size !== updater.signatureBytes ||
      (await sha256File(path.join(input, updater.payloadFile))) !== updater.payloadSha256 ||
      (await sha256File(path.join(input, updater.signatureFile))) !== updater.signatureSha256
    ) return null;
    const signature = (await readFile(path.join(input, updater.signatureFile), "utf8")).trim();
    if (signature !== updater.signature) return null;
    verifyUpdaterSignatures(updaterPublicKey, [{
      payload: path.join(input, updater.payloadFile),
      signature: path.join(input, updater.signatureFile),
    }]);
    return updater;
  } catch {
    return null;
  }
}

function unavailable(installer, reason) {
  installer.availability = "not-offered";
  installer.reason = reason;
  installer.artifact = null;
}

async function scopedFinalizeMain() {
  const args = parseArgs(process.argv.slice(2));
  const input = path.resolve(requireString(args, "input"));
  const output = path.resolve(requireString(args, "out"));
  assert(input !== output, "--input and --out must be different directories");
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  const publicationMode = requireString(args, "publication-mode");
  assert(isSemver(version) && tag === `v${version}` && /^[0-9a-f]{40}$/u.test(commit), "release identity is malformed or inconsistent");
  assert(PUBLICATION_MODES.has(publicationMode), "publication mode must be commit-bound-qc or public-github-release");
  const outputMetadata = await regularFileIfPresent(output);
  assert(!outputMetadata, "release output must be a directory, not a file");
  try {
    assert((await readdir(output)).length === 0, "release output directory must start empty");
  } catch (error) {
    if (!error || typeof error !== "object" || error.code !== "ENOENT") throw error;
  }

  const metadata = await readJson(path.join(input, "release-metadata.json"));
  validateReleaseMetadataV3(metadata, {
    releaseState: "prepared",
    version,
    tag,
    sourceCommit: commit,
    publicationMode,
  });
  const packageJson = await readJson(path.join(PROJECT_ROOT, "package.json"));
  assert(
    metadata.releaseChannel === packageJson.release?.channel &&
      metadata.stableTarget === packageJson.release?.target,
    "release metadata publication channel does not match the source package",
  );
  const tauriConfigPath = path.resolve(args.get("tauri-config") ?? path.join(PROJECT_ROOT, "src-tauri", "tauri.conf.json"));
  const tauriConfig = await readJson(tauriConfigPath);
  const updaterPublicKey = tauriConfig.plugins?.updater?.pubkey;

  const finalized = structuredClone(metadata);
  finalized.releaseState = "finalized";
  const selections = [];
  const rejectionMessages = [];
  for (const platformRecord of finalized.distribution.platforms) {
    if (platformRecord.availability === "not-offered") continue;
    let manifest;
    try {
      manifest = await readCandidatePlatformManifest(input, platformRecord.platform, version, tag, commit);
    } catch (error) {
      manifest = null;
      rejectionMessages.push(`${platformRecord.platform}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!manifest) {
      platformRecord.availability = "not-offered";
      platformRecord.reason = "platform-build-unavailable-or-invalid";
      for (const installer of platformRecord.installers) unavailable(installer, "platform-build-unavailable-or-invalid");
      continue;
    }
    let shared;
    try {
      shared = {
        sidecars: await verifyCompanionEvidence(input, platformRecord.platform, manifest),
        runtimeComponents: await verifyRuntimeEvidence(input, platformRecord.platform),
      };
    } catch (error) {
      rejectionMessages.push(`${platformRecord.platform}: ${error instanceof Error ? error.message : String(error)}`);
      platformRecord.availability = "not-offered";
      platformRecord.reason = "platform-shared-evidence-invalid";
      for (const installer of platformRecord.installers) unavailable(installer, "platform-shared-evidence-invalid");
      continue;
    }
    for (const installerSupport of platformRecord.installers) {
      const qualificationName = `platform-qualification-${platformRecord.platform}-${installerSupport.installerType}.json`;
      if (!(await regularFileIfPresent(path.join(input, qualificationName)))) {
        unavailable(installerSupport, "technical-qualification-not-observed");
        continue;
      }
      const installers = manifest.installers.filter((record) =>
        record && typeof record === "object" && !Array.isArray(record) &&
          record.bundleType === installerSupport.installerType,
      );
      if (installers.length !== 1) {
        unavailable(installerSupport, "qualified-installer-artifact-missing-or-ambiguous");
        continue;
      }
      const installer = installers[0];
      if (
        !isFlatReleaseName(installer.file) ||
        !Number.isSafeInteger(installer.bytes) || installer.bytes <= 0 ||
        !/^[0-9a-f]{64}$/u.test(installer.sha256)
      ) {
        unavailable(installerSupport, "qualified-installer-filename-invalid");
        rejectionMessages.push(
          `${platformRecord.platform}/${installerSupport.installerType}: qualified installer record is invalid`,
        );
        continue;
      }
      let installerBytesValid = false;
      try {
        const installerMetadata = await regularFileIfPresent(path.join(input, installer.file));
        installerBytesValid = Boolean(
          installerMetadata && installerMetadata.size === installer.bytes &&
            (await sha256File(path.join(input, installer.file))) === installer.sha256,
        );
      } catch (error) {
        rejectionMessages.push(
          `${platformRecord.platform}/${installerSupport.installerType}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (!installerBytesValid) {
        unavailable(installerSupport, "qualified-installer-bytes-invalid");
        rejectionMessages.push(
          `${platformRecord.platform}/${installerSupport.installerType}: qualified installer bytes are invalid`,
        );
        continue;
      }
      let qualification;
      try {
        qualification = await verifyPlatformQualificationFile(path.join(input, qualificationName), {
          platform: platformRecord.platform,
          installerType: installerSupport.installerType,
          version,
          tag,
          commit,
          releaseChannel: metadata.releaseChannel,
          releaseDirectory: input,
        });
      } catch (error) {
        rejectionMessages.push(`${platformRecord.platform}/${installerSupport.installerType}: ${error instanceof Error ? error.message : String(error)}`);
        unavailable(installerSupport, "technical-qualification-invalid");
        continue;
      }
      const identity = {
        platform: platformRecord.platform,
        installerType: installerSupport.installerType,
        version,
        tag,
        commit,
      };
      let dataPreservationEvidence = null;
      // No producer currently exercises the exact installed desktop application
      // through localhost report, reopen, export, and uninstall/reinstall. The
      // bounded data-preservation fixtures below deliberately do not fill this.
      const installedAppLifecycleEvidence = null;
      if (
        platformRecord.platform === "windows-x86_64" &&
        installerSupport.installerType === "nsis"
      ) {
        try {
          dataPreservationEvidence = await verifyWindowsNsisSupportingDataPreservationEvidence({
            root: input,
            artifactDirectory: input,
            version,
            tag,
            commit,
          });
        } catch (error) {
          rejectionMessages.push(
            `${platformRecord.platform}/${installerSupport.installerType} data preservation: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }
      const humanName = `human-path-qualification-${platformRecord.platform}-${installerSupport.installerType}.json`;
      let humanEvidence = null;
      try {
        if (await regularFileIfPresent(path.join(input, humanName))) {
          humanEvidence = await verifyBoundArtifactEvidenceFile(path.join(input, humanName), {
            ...identity,
            artifact: installer,
            evidenceType: "beginner-human-path",
            label: humanName,
          });
        }
      } catch (error) {
        rejectionMessages.push(`${humanName}: ${error instanceof Error ? error.message : String(error)}`);
      }
      const signingName = `os-signing-${platformRecord.platform}-${installerSupport.installerType}.json`;
      // v0.1.8 has no reviewed protected-producer/publisher allowlist contract.
      // A same-run file alone must therefore never become OS-signing promotion
      // evidence. The standalone verifier remains available for future policy
      // work, while this candidate records the exact claim as not configured.
      const signingEvidence = null;
      if (
        requiresStablePublicWindowsEvidence({
          publicationMode,
          releaseChannel: metadata.releaseChannel,
          platform: platformRecord.platform,
        }) &&
        (!humanEvidence || !signingEvidence || !installedAppLifecycleEvidence)
      ) {
        const missing = [
          !signingEvidence ? "authenticode-not-verified" : null,
          !humanEvidence ? "beginner-human-path-not-observed" : null,
          installerSupport.installerType === "msi"
            ? "equivalent-msi-lifecycle-not-observed"
            : "real-installed-app-localhost-lifecycle-not-observed",
        ].filter(Boolean).join(";");
        unavailable(installerSupport, missing);
        continue;
      }
      const notarizationName = `notarization-${platformRecord.platform}-${installerSupport.installerType}.json`;
      let notarizationEvidence = null;
      if (
        platformRecord.platform === "macos-universal" &&
        await regularFileIfPresent(path.join(input, notarizationName))
      ) {
        try {
          notarizationEvidence = await verifyBoundArtifactEvidenceFile(path.join(input, notarizationName), {
            ...identity,
            artifact: installer,
            evidenceType: "apple-notarization",
            label: notarizationName,
          });
        } catch (error) {
          rejectionMessages.push(`${notarizationName}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      const updater = await verifyUpdaterForInstaller(
        input,
        platformRecord.platform,
        installerSupport.installerType,
        manifest,
        updaterPublicKey,
      );
      const limitations = [];
      if (!humanEvidence) limitations.push("beginner-human-path-not-observed");
      if (!signingEvidence) limitations.push("operating-system-signing-not-configured");
      if (platformRecord.platform === "windows-x86_64") {
        limitations.push("windows-lifecycle-not-observed");
        if (installerSupport.installerType === "nsis" && dataPreservationEvidence) {
          limitations.push("windows-data-preservation-fixtures-only");
        } else {
          limitations.push("windows-data-preservation-not-observed");
        }
      }
      if (platformRecord.platform === "macos-universal" && !notarizationEvidence) {
        limitations.push("apple-notarization-not-configured");
      }
      if (!updater) limitations.push("updater-not-offered-for-this-artifact");
      if (qualification.qualificationState === "installer_passed_runtime_not_observed") {
        limitations.push("managed-runtime-not-observed-on-qualification-host");
      }
      installerSupport.availability = "offered";
      installerSupport.reason = null;
      installerSupport.artifact = {
        file: installer.file,
        bytes: installer.bytes,
        sha256: installer.sha256,
        technicalQualification: {
          state: qualification.qualificationState === "passed"
            ? "passed"
            : "installer-passed-runtime-not-observed",
          evidenceFile: qualificationName,
          reason: null,
        },
        humanPath: humanEvidence
          ? { state: "verified", evidenceFile: humanName, reason: null }
          : { state: "not-observed", evidenceFile: null, reason: "exact-candidate-beginner-path-not-observed" },
        operatingSystemSigning: signingEvidence
          ? { state: "verified", evidenceFile: signingName, reason: null }
          : { state: "not-configured", evidenceFile: null, reason: "artifact-has-no-verified-operating-system-signature" },
        notarization: platformRecord.platform === "macos-universal"
          ? notarizationEvidence
            ? { state: "verified", evidenceFile: notarizationName, reason: null }
            : { state: "not-configured", evidenceFile: null, reason: "artifact-has-no-verified-apple-notarization" }
          : { state: "not-applicable", evidenceFile: null, reason: "apple-notarization-does-not-apply" },
        windowsLifecycle: platformRecord.platform !== "windows-x86_64"
          ? { state: "not-applicable", evidenceFiles: [], reason: "Windows lifecycle does not apply" }
          : {
              state: "not-observed",
              evidenceFiles: [],
              reason: installerSupport.installerType === "msi"
                ? "equivalent-msi-lifecycle-not-observed"
                : "real-installed-app-localhost-lifecycle-not-observed",
            },
        windowsDataPreservation: platformRecord.platform !== "windows-x86_64"
          ? { state: "not-applicable", evidenceFiles: [], reason: "Windows data preservation does not apply" }
          : installerSupport.installerType === "nsis" && dataPreservationEvidence
            ? dataPreservationEvidence
            : {
                state: "not-observed",
                evidenceFiles: [],
                reason: installerSupport.installerType === "msi"
                  ? "equivalent-msi-data-preservation-not-observed"
                  : "exact-current-candidate-nsis-data-preservation-not-observed",
              },
        updater: updater
          ? {
              state: "signed",
              payloadFile: updater.payloadFile,
              signatureFile: updater.signatureFile,
              targetKeys: [...updater.targetKeys],
              reason: null,
            }
          : {
              state: "not-offered",
              payloadFile: null,
              signatureFile: null,
              targetKeys: [],
              reason: "no-valid-artifact-scoped-updater",
            },
        provenanceAttestation: provenanceForArtifact(publicationMode),
        knownLimitations: limitations,
      };
      selections.push({
        platform: platformRecord.platform,
        installerType: installerSupport.installerType,
        installer,
        qualificationName,
        humanName: humanEvidence ? humanName : null,
        signingName: signingEvidence ? signingName : null,
        notarizationName: notarizationEvidence ? notarizationName : null,
        dataPreservationFiles: dataPreservationEvidence?.evidenceFiles ?? [],
        updater,
        manifest,
        shared,
      });
    }
    const offered = platformRecord.installers.filter(({ availability }) => availability === "offered");
    platformRecord.availability = offered.length > 0 ? "offered" : "not-offered";
    platformRecord.reason = offered.length > 0 ? null : "no-qualified-installer-artifact";
  }
  assert(selections.length > 0, `no releasable installer artifact remains (${rejectionMessages.join(" | ")})`);
  validateReleaseMetadataV3(finalized, { releaseState: "finalized" });

  await mkdir(output, { recursive: true });
  const copied = new Map();
  const copySelected = async (name) => {
    assert(typeof name === "string" && name === toPosix(name), `release file path is not canonical POSIX: ${String(name)}`);
    assertSafeRelativePath(name);
    const source = path.join(input, name);
    const metadata_ = await regularFileIfPresent(source);
    assert(metadata_ && metadata_.size > 0, `selected release file is missing: ${name}`);
    const digest = await sha256File(source);
    if (copied.has(name)) {
      assert(copied.get(name) === digest, `selected release filename collision: ${name}`);
      return;
    }
    const destination = path.join(output, name);
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    copied.set(name, digest);
  };
  const cyclonedxName = `ai-security-scanner-${version}.cyclonedx.json`;
  const spdxName = `ai-security-scanner-${version}.spdx.json`;
  for (const name of [
    "THIRD_PARTY_NOTICES.txt",
    "ENGINE_NOTICES.md",
    "ENGINE_NOTICES.json",
    "LICENSE.txt",
    cyclonedxName,
    spdxName,
  ]) await copySelected(name);

  const includedPlatforms = new Map();
  for (const selection of selections) {
    const platform = includedPlatforms.get(selection.platform) ?? {
      installers: [], sidecars: selection.shared.sidecars, updaters: [], runtimeComponents: selection.shared.runtimeComponents,
    };
    platform.installers.push(selection.installer);
    if (selection.updater && !platform.updaters.some(({ bundleType }) => bundleType === selection.updater.bundleType)) {
      platform.updaters.push(selection.updater);
    }
    includedPlatforms.set(selection.platform, platform);
    await copySelected(selection.installer.file);
    await copySelected(selection.qualificationName);
    for (const name of [selection.humanName, selection.signingName, selection.notarizationName].filter(Boolean)) {
      await copySelected(name);
    }
    for (const dataPreservationFile of selection.dataPreservationFiles) {
      assert(
        (await sha256File(path.join(input, dataPreservationFile.path))) === dataPreservationFile.sha256,
        `data-preservation evidence changed before copy: ${dataPreservationFile.path}`,
      );
      await copySelected(dataPreservationFile.path);
    }
    if (selection.updater) {
      await copySelected(selection.updater.payloadFile);
      await copySelected(selection.updater.signatureFile);
    }
  }
  const runtimeSuffixes = ["manifest.json", "cyclonedx.json", "spdx.json", "NOTICES.txt"];
  for (const [platform, records] of includedPlatforms) {
    for (const sidecar of records.sidecars) await copySelected(sidecar.releaseFile);
    for (const suffix of runtimeSuffixes) await copySelected(`managed-runtime-${platform}.${suffix}`);
    const sourceManifestSha256 = await sha256File(path.join(input, `installers-${platform}.json`));
    const filteredManifestName = `installers-${platform}.json`;
    await writeJsonAtomic(path.join(output, filteredManifestName), {
      schemaVersion: 3,
      product: "ai-security-scanner",
      version,
      tag,
      sourceCommit: commit,
      platform,
      artifactScoped: true,
      sourceManifestSha256,
      installers: records.installers,
      auxiliaryExecutables: records.sidecars.map(({ platform: _platform, ...sidecar }) => sidecar),
      updaters: records.updaters,
    });
    copied.set(filteredManifestName, await sha256File(path.join(output, filteredManifestName)));
    const names = [...new Set([
      filteredManifestName,
      ...records.installers.map(({ file }) => file),
      ...records.sidecars.map(({ releaseFile }) => releaseFile),
      ...records.updaters.flatMap(({ payloadFile, signatureFile }) => [payloadFile, signatureFile]),
      ...runtimeSuffixes.map((suffix) => `managed-runtime-${platform}.${suffix}`),
    ])].sort();
    const lines = [];
    for (const name of names) lines.push(`${await sha256File(path.join(output, name))}  ${name}`);
    await writeTextAtomic(path.join(output, `SHA256SUMS-${platform}.txt`), `${lines.join("\n")}\n`);
  }

  const cyclonedx = await readJson(path.join(output, cyclonedxName));
  const spdx = await readJson(path.join(output, spdxName));
  const sidecars = [...includedPlatforms.values()].flatMap(({ sidecars }) => sidecars);
  const runtimeComponents = [...includedPlatforms.values()].flatMap(({ runtimeComponents }) => runtimeComponents);
  enrichSboms(cyclonedx, spdx, sidecars, runtimeComponents, version);
  await writeJsonAtomic(path.join(output, cyclonedxName), cyclonedx);
  await writeJsonAtomic(path.join(output, spdxName), spdx);
  await writeJsonAtomic(path.join(output, "release-metadata.json"), finalized);

  const updatePlatforms = {};
  for (const selection of selections.filter(({ updater }) => updater)) {
    const url = `https://github.com/teddashh/ai-security-scanner/releases/download/${tag}/${encodeURIComponent(selection.updater.payloadFile)}`;
    for (const target of selection.updater.targetKeys) {
      assert(!updatePlatforms[target], `duplicate updater target key: ${target}`);
      updatePlatforms[target] = { url, signature: selection.updater.signature };
    }
  }
  await writeJsonAtomic(path.join(output, "latest.json"), {
    version,
    tag,
    notes: releaseCopyFor(version).updaterNotes,
    pub_date: metadata.sourceDate,
    platforms: updatePlatforms,
  });

  const offeredLines = finalized.distribution.platforms.flatMap((platform) =>
    platform.installers
      .filter(({ availability }) => availability === "offered")
      .map(({ installerType, artifact }) =>
        `- ${platform.platform} / ${installerType}: ${artifact.file}; technical qualification ${artifact.technicalQualification.state}; beginner human path ${artifact.humanPath.state}.`),
  );
  const unavailableLines = finalized.distribution.platforms.flatMap((platform) =>
    platform.installers
      .filter(({ availability }) => availability === "not-offered")
      .map(({ installerType, reason }) => `- ${platform.platform} / ${installerType}: not offered (${reason}).`),
  );
  const distributionVerification = publicationMode === "public-github-release"
    ? "Verify the selected file against SHA256SUMS.txt and its artifact-specific public provenance before installing."
    : "These are commit-bound QC artifacts, not a public release; public provenance has not been created.";
  const offeredWindowsPrereleaseInstallers =
    publicationMode === "public-github-release" &&
    metadata.releaseChannel === "prerelease" &&
    finalized.distribution.platforms
      .find(({ platform }) => platform === "windows-x86_64")
      ?.installers.filter(({ availability }) => availability === "offered");
  const windowsPrereleaseNotice = offeredWindowsPrereleaseInstallers?.length > 0
    ? [
        "## Windows pre-release testing notice",
        "",
        "> This is a public testing pre-release, not a stable deployment. The Windows installers",
        "> are intentionally available so this build can be tested now. Windows may show an",
        "> Unknown publisher warning.",
        "",
        ...offeredWindowsPrereleaseInstallers.map(({ installerType, artifact }) => {
          const limitations = [];
          if (artifact.operatingSystemSigning.state !== "verified") limitations.push("Authenticode not verified");
          if (artifact.humanPath.state !== "verified") limitations.push("exact-candidate beginner path not observed");
          if (artifact.windowsLifecycle.state !== "verified") limitations.push("installed-app lifecycle not observed");
          if (artifact.windowsDataPreservation.state === "not-observed") {
            limitations.push("data-preservation path not observed");
          } else if (artifact.windowsDataPreservation.state === "supporting-data-preservation-only") {
            limitations.push("data-preservation fixtures only");
          }
          return `- ${installerType.toUpperCase()}: ${limitations.join("; ")}.`;
        }),
        "",
      ]
    : [];
  await writeTextAtomic(path.join(output, "RELEASE_NOTES.md"), [
    `# ai-security-scanner ${version}`,
    "",
    `Source: \`${commit}\``,
    "",
    ...windowsPrereleaseNotice,
    ...releaseCopyFor(version).releaseNotes,
    "Artifacts offered by this finalized set:",
    ...offeredLines,
    "",
    "Not offered in this finalized set:",
    ...unavailableLines,
    "",
    distributionVerification,
    "Qualification, human-path observation, OS signing, notarization, updater availability,",
    "provenance requirements, and known limitations are recorded independently for every offered artifact",
    "in release-metadata.json. An absent platform never implies that it passed.",
    "",
  ].join("\n"));

  const beforeIndex = (await regularFiles(output))
    .filter((file) => file.relative !== "SHA256SUMS.txt" && file.relative !== "release-assets.json")
    .sort((left, right) => left.relative.localeCompare(right.relative));
  const fileRecords = [];
  for (const file of beforeIndex) {
    fileRecords.push({ path: file.relative, bytes: file.bytes, sha256: await sha256File(file.absolute) });
  }
  await writeJsonAtomic(path.join(output, "release-assets.json"), {
    schemaVersion: 2,
    product: "ai-security-scanner",
    version,
    tag,
    sourceCommit: commit,
    publicationMode,
    indexSelfExcluded: true,
    files: fileRecords,
  });
  const finalFiles = (await regularFiles(output))
    .filter((file) => file.relative !== "SHA256SUMS.txt")
    .sort((left, right) => left.relative.localeCompare(right.relative));
  const checksums = [];
  for (const file of finalFiles) checksums.push(`${await sha256File(file.absolute)}  ${file.relative}`);
  await writeTextAtomic(path.join(output, "SHA256SUMS.txt"), `${checksums.join("\n")}\n`);
  for (const message of rejectionMessages) process.stderr.write(`release tooling: excluded candidate: ${message}\n`);
  process.stdout.write(
    `Finalized ${selections.length} independently qualified installer artifact(s) across ${includedPlatforms.size} platform(s); absent or unqualified siblings remain explicit in release-metadata.json.\n`,
  );
}

runMain(scopedFinalizeMain);
