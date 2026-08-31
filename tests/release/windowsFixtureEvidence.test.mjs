import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { validateSynchronousNsisQualificationFixture } from "../../scripts/release/validate-release.mjs";

import {
  validateWindowsNsisUpgradeFixtureScope,
  validateWindowsNsisUpgradeInstallerManifestShape,
} from "../../scripts/release/windows-nsis-upgrade-evidence.mjs";
import {
  validateWindowsNsisGenerationSelection,
  validateWindowsNsisGhostFixtureScope,
  validateWindowsNsisGhostInstallerManifestShape,
  validateWindowsNsisUnrelatedVhdPreservation,
} from "../../scripts/release/windows-nsis-ghost-recovery-evidence.mjs";

function fixtureScope() {
  return {
    classification: "risk_focused_automated_data_preservation",
    qualifiesPublicLifecycle: false,
    syntheticCliCaseUsed: true,
    installedDesktopInteractionObserved: false,
    localhost1270019001ReportObserved: false,
    projectReopenedInDesktopObserved: false,
    postUninstallReinstallObserved: false,
  };
}

function finalizedManifest() {
  return {
    schemaVersion: 3,
    product: "ai-security-scanner",
    version: "0.1.8",
    tag: "v0.1.8",
    sourceCommit: "01".repeat(20),
    platform: "windows-x86_64",
    artifactScoped: true,
    sourceManifestSha256: "ab".repeat(32),
    installers: [],
    auxiliaryExecutables: [],
    updaters: [],
  };
}

test("Windows preservation fixtures run verified NSIS copies and prove retained-state app removal", async () => {
  for (const [relative, label] of [
    ["../../scripts/release/qualify-windows-nsis-upgrade.ps1", "N-1 NSIS qualification"],
    [
      "../../scripts/release/qualify-windows-nsis-ghost-recovery.ps1",
      "ghost-install NSIS qualification",
    ],
  ]) {
    const source = await readFile(new URL(relative, import.meta.url), "utf8");
    const registryRemovalProof = source.includes("Get-CurrentUserUninstallEntries")
      ? '  if (@(Get-CurrentUserUninstallEntries).Count -ne 0) {\n    throw "Candidate NSIS uninstall left its current-user product registration behind."\n  }\n'
      : '  if (@(Get-ProductRegistryEntries).Count -ne 0) {\n    throw "Candidate NSIS uninstaller left the product registry entry."\n  }\n';
    const afterSnapshotAssignment = source.includes("Get-CompletePrivateDataSnapshot")
      ? "  $appOnlyUninstallSnapshotAfter = Get-CompletePrivateDataSnapshot $dataDirectory\n"
      : "  $appOnlyUninstallSnapshotAfter = Get-PrivateDataSnapshot $dataDirectory\n";
    assert.notEqual(source.indexOf(registryRemovalProof), -1);
    assert.notEqual(source.indexOf(afterSnapshotAssignment), -1);
    assert.doesNotThrow(() =>
      validateSynchronousNsisQualificationFixture(source, label, {
        allowsRetainedState: true,
      }),
    );
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace("      Remove-Item -LiteralPath $copyPath -Force\n", ""),
          label,
          { allowsRetainedState: true },
        ),
      /missing copied-uninstaller invariant|one copied-uninstaller helper/u,
    );
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace(
            /^    throw "Candidate NSIS(?: cleanup)? uninstall retained the exact application installation directory\."\n/mu,
            "",
          ),
          label,
          { allowsRetainedState: true },
        ),
      /independently proving application removal/u,
    );
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace(registryRemovalProof, ""),
          label,
          { allowsRetainedState: true },
        ),
      /independently proving application removal/u,
    );
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace(afterSnapshotAssignment, ""),
          label,
          { allowsRetainedState: true },
        ),
      /independently proving application removal/u,
    );
  }
});

test("Windows data-preservation fixtures cannot claim public lifecycle coverage", () => {
  for (const validate of [validateWindowsNsisUpgradeFixtureScope, validateWindowsNsisGhostFixtureScope]) {
    assert.doesNotThrow(() => validate(fixtureScope()));
    for (const field of [
      "qualifiesPublicLifecycle",
      "installedDesktopInteractionObserved",
      "localhost1270019001ReportObserved",
      "projectReopenedInDesktopObserved",
      "postUninstallReinstallObserved",
    ]) {
      const tampered = fixtureScope();
      tampered[field] = true;
      assert.throws(() => validate(tampered), /data-preservation fixture cannot claim/u);
    }
    const hiddenSyntheticCase = fixtureScope();
    hiddenSyntheticCase.syntheticCliCaseUsed = false;
    assert.throws(
      () => validate(hiddenSyntheticCase),
      /data-preservation fixture must disclose its synthetic CLI case/u,
    );
  }
});

test("Windows fixture validators accept only the exact artifact-scoped finalized manifest shape", () => {
  for (const validate of [
    validateWindowsNsisUpgradeInstallerManifestShape,
    validateWindowsNsisGhostInstallerManifestShape,
  ]) {
    assert.doesNotThrow(() => validate(finalizedManifest()));

    const extra = finalizedManifest();
    extra.untrusted = true;
    assert.throws(() => validate(extra), /fields (?:are not|changed)/u);

    const missing = finalizedManifest();
    delete missing.sourceManifestSha256;
    assert.throws(() => validate(missing), /fields (?:are not|changed)/u);

    const notArtifactScoped = finalizedManifest();
    notArtifactScoped.artifactScoped = false;
    assert.throws(() => validate(notArtifactScoped), /not artifact-scoped/u);
  }
});

test("app-only uninstall cannot change unrelated WSL VHD bytes or NTFS identity", () => {
  const before = {
    length: 4096,
    sha256: "cd".repeat(32),
    volume: 123,
    fileIndex: "456",
    numberOfLinks: 1,
    attributes: 32,
  };
  assert.doesNotThrow(() => validateWindowsNsisUnrelatedVhdPreservation(before, { ...before }));

  const digestChanged = { ...before, sha256: "ef".repeat(32) };
  assert.throws(
    () => validateWindowsNsisUnrelatedVhdPreservation(before, digestChanged),
    /changed unrelated WSL VHD sha256/u,
  );
  const identityChanged = { ...before, fileIndex: "457" };
  assert.throws(
    () => validateWindowsNsisUnrelatedVhdPreservation(before, identityChanged),
    /changed unrelated WSL VHD fileIndex/u,
  );
});

test("ghost qualification accepts only the exact non-authorizing generation-zero routing record", () => {
  const identity = {
    runtimeManifestSha256: "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a",
    machineImageSha256: "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968",
  };
  const selection = {
    pathBoundToCandidateManifestGenerationZero: true,
    recordPresent: true,
    recordProtected: true,
    recordBytes: 512,
    recordSha256: "ab".repeat(32),
    schemaVersion: "ai-security-scanner.managed-wsl-generation-selection/v1",
    authorizesCleanup: false,
    manifestSha256: identity.runtimeManifestSha256,
    machineImageSha256: identity.machineImageSha256,
    defaultMachineName: "assm2-win-x64-e2b6cbcadd8b",
    selectedMachineName: "assm2-win-x64-e2b6cbcadd8b",
    generationIndex: 0,
    preservedCollisionNames: [],
    recordPreservedAfterCurrentRuntimePurge: true,
    recordPreservedThroughAppOnlyUninstall: true,
  };
  assert.doesNotThrow(() => validateWindowsNsisGenerationSelection(selection, identity));
  assert.throws(
    () => validateWindowsNsisGenerationSelection({ ...selection, authorizesCleanup: true }, identity),
    /incorrectly grants cleanup authority/u,
  );
  assert.throws(
    () => validateWindowsNsisGenerationSelection({
      ...selection,
      preservedCollisionNames: [selection.defaultMachineName],
    }, identity),
    /unexpectedly claims a preserved current-generation collision/u,
  );
});
