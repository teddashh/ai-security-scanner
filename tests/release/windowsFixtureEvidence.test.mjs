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

test("Windows preservation fixtures bind the 0.1.10 candidate and its true N-1 release", async () => {
  const upgradeFixture = await readFile(
    new URL("../../scripts/release/qualify-windows-nsis-upgrade.ps1", import.meta.url),
    "utf8",
  );
  const upgradeEvidence = await readFile(
    new URL("../../scripts/release/windows-nsis-upgrade-evidence.mjs", import.meta.url),
    "utf8",
  );
  const ghostFixture = await readFile(
    new URL("../../scripts/release/qualify-windows-nsis-ghost-recovery.ps1", import.meta.url),
    "utf8",
  );
  const ghostEvidence = await readFile(
    new URL("../../scripts/release/windows-nsis-ghost-recovery-evidence.mjs", import.meta.url),
    "utf8",
  );

  for (const source of [upgradeFixture, upgradeEvidence, ghostFixture, ghostEvidence]) {
    assert.match(source, /candidateVersion|CANDIDATE_VERSION/u);
    assert.match(source, /0\.1\.10/u);
  }
  for (const source of [upgradeFixture, upgradeEvidence]) {
    assert.match(source, /0\.1\.9/u);
    assert.match(source, /f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e/u);
    assert.doesNotMatch(source, /ai-security-scanner_0\.1\.7_x64-setup\.exe/u);
    assert.doesNotMatch(source, /managed-runtime-ghost|providerHomeSentinel|providerSentinel/u);
  }
  assert.match(upgradeFixture, /\$uninstallResult\.exitCode -ne 0/u);
  assert.doesNotMatch(upgradeFixture, /AllowRetainedState/u);
  assert.match(ghostFixture, /\$uninstallResult\.exitCode -ne 10/u);
  assert.match(ghostFixture, /AllowRetainedState/u);
});

test("Windows preservation fixtures require exact NSIS uninstall outcomes and prove app removal", async () => {
  for (const [relative, label] of [
    ["../../scripts/release/qualify-windows-nsis-upgrade.ps1", "N-1 NSIS qualification"],
    [
      "../../scripts/release/qualify-windows-nsis-ghost-recovery.ps1",
      "ghost-install NSIS qualification",
    ],
  ]) {
    const source = (await readFile(new URL(relative, import.meta.url), "utf8"))
      .replaceAll(/\r\n?/gu, "\n");
    const registryRemovalProof = source.includes("Get-CurrentUserUninstallEntries")
      ? '  if (@(Get-CurrentUserUninstallEntries).Count -ne 0) {\n    throw "Candidate NSIS uninstall left its current-user product registration behind."\n  }\n'
      : '  if (@(Get-ProductRegistryEntries).Count -ne 0) {\n    throw "Candidate NSIS uninstaller left the product registry entry."\n  }\n';
    const isGhostFixture = source.includes("Get-ProductRegistryEntries");
    const validatorOptions = {
      allowsRetainedState: isGhostFixture,
      provesAppOnlyDataPreservation: true,
    };
    const afterSnapshotAssignment = isGhostFixture
      ? "  $appOnlyUninstallSnapshotAfter = Get-NonLeasePrivateDataSnapshot $dataDirectory\n"
      : "  $appOnlyUninstallSnapshotAfter = Get-PrivateDataSnapshot $dataDirectory -ExcludeProcessLease\n";
    assert.notEqual(source.indexOf(registryRemovalProof), -1);
    assert.notEqual(source.indexOf(afterSnapshotAssignment), -1);
    assert.doesNotThrow(() =>
      validateSynchronousNsisQualificationFixture(source, label, validatorOptions),
    );
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace("      Remove-Item -LiteralPath $copyPath -Force\n", ""),
          label,
          validatorOptions,
        ),
      /missing copied-uninstaller invariant|one copied-uninstaller helper/u,
    );
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace(
            '$startInfo.Arguments = "/S _?=$rawNsisDirectory"',
            '$startInfo.ArgumentList.Add("_?=$rawNsisDirectory")',
          ),
          label,
          validatorOptions,
        ),
      /missing copied-uninstaller invariant|raw NSIS tail|invokes an installed NSIS/u,
    );
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace(
            /^    throw "Candidate NSIS(?: cleanup)? uninstall retained the exact application installation directory\."\n/mu,
            "",
          ),
          label,
          validatorOptions,
        ),
      /independently proving application removal/u,
    );
    const exactExitCheck = isGhostFixture
      ? "$uninstallResult.exitCode -ne 10"
      : "$uninstallResult.exitCode -ne 0";
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace(exactExitCheck, "$uninstallResult.exitCode -notin @(0, 10)"),
          label,
          validatorOptions,
        ),
      /exact (?:retained-state exit class|exit class)/u,
    );
    if (isGhostFixture) {
      for (const proofField of [
        "      NumberOfLinks = [uint32]$before.links\n",
        "      Attributes = [uint32]$before.attributes\n",
      ]) {
        assert.throws(
          () =>
            validateSynchronousNsisQualificationFixture(
              source.replace(proofField, ""),
              label,
              validatorOptions,
            ),
          /complete empty-file identity/u,
        );
      }
      assert.throws(
        () =>
          validateSynchronousNsisQualificationFixture(
            source.replace("      Start-Sleep -Milliseconds 500\n", ""),
            label,
            validatorOptions,
          ),
        /quiesce only its two stopped fixtures/u,
      );
      assert.throws(
        () =>
          validateSynchronousNsisQualificationFixture(
            source.replace(
              "[int]$win32Exception.NativeErrorCode -notin @(32, 33)",
              "$_.Exception.NativeErrorCode -notin @(32, 33)",
            ),
            label,
            validatorOptions,
          ),
        /quiesce only its two stopped fixtures/u,
      );
      assert.throws(
        () =>
          validateSynchronousNsisQualificationFixture(
            source.replace(
              "  Invoke-FixtureOnlyWslShutdown $trustedWsl $fixtureWslRegistrations (\n" +
                "    \"Fixture-only WSL quiescence before VHD preservation proof\"\n" +
                "  )\n",
              "",
            ),
            label,
            validatorOptions,
          ),
        /quiesce only its two stopped fixtures/u,
      );
      assert.throws(
        () =>
          validateSynchronousNsisQualificationFixture(
            source.replace("$runningBefore.Count -ne 0", "$runningBefore.Count -gt 2"),
            label,
            validatorOptions,
          ),
        /quiesce only its two stopped fixtures/u,
      );
      assert.throws(
        () =>
          validateSynchronousNsisQualificationFixture(
            source.replace(
              "[string]$actual.RegistrationId -cne $registrationId",
              "[string]$actual.Name -cne $name",
            ),
            label,
            validatorOptions,
          ),
        /quiesce only its two stopped fixtures/u,
      );
      assert.throws(
        () =>
          validateSynchronousNsisQualificationFixture(
            source.replace(
              'foreach ($identityField in @("volumeSerialNumber", "fileIndex", "numberOfLinks", "attributes"))',
              'foreach ($identityField in @("sizeBytes", "volumeSerialNumber", "fileIndex", "numberOfLinks", "attributes"))',
            ),
            label,
            validatorOptions,
          ),
        /quiesce only its two stopped fixtures/u,
      );
    }
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace(registryRemovalProof, ""),
          label,
          validatorOptions,
        ),
      /independently proving application removal/u,
    );
    assert.throws(
      () =>
        validateSynchronousNsisQualificationFixture(
          source.replace(afterSnapshotAssignment, ""),
          label,
          validatorOptions,
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
