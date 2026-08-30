import assert from "node:assert/strict";
import test from "node:test";

import {
  validateWindowsNsisUpgradeFixtureScope,
  validateWindowsNsisUpgradeInstallerManifestShape,
} from "../../scripts/release/windows-nsis-upgrade-evidence.mjs";
import {
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
