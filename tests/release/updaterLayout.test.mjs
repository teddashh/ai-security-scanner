import assert from "node:assert/strict";
import test from "node:test";

import {
  ALL_UPDATER_TARGET_KEYS,
  updaterLayoutsFor,
} from "../../scripts/release/updater-layout.mjs";
import {
  optionalUpdaterPlan,
  tauriBundleInvocation,
} from "../../scripts/release/bundle-with-optional-updater.mjs";

test("desktop updater layouts include only runtime-consumable package formats", () => {
  assert.deepEqual(updaterLayoutsFor("linux-x86_64").map(({ bundleType }) => bundleType), ["appimage"]);
  assert.deepEqual(updaterLayoutsFor("macos-universal").map(({ bundleType }) => bundleType), ["app"]);
  assert.deepEqual(updaterLayoutsFor("windows-x86_64").map(({ bundleType }) => bundleType), ["nsis"]);
  assert.equal(ALL_UPDATER_TARGET_KEYS.some((key) => /(?:deb|rpm|msi)/u.test(key)), false);
});

test("installer bundling never requires updater signing material", () => {
  for (const bundleTypes of ["appimage", "app,dmg", "nsis"]) {
    assert.deepEqual(
      optionalUpdaterPlan({ bundleTypes, signingKeyPresent: false, publicKeyPresent: true }),
      { updaterAttempted: false, fallbackCreatesUpdaterArtifacts: false },
    );
    assert.deepEqual(
      optionalUpdaterPlan({ bundleTypes, signingKeyPresent: true, publicKeyPresent: false }),
      { updaterAttempted: false, fallbackCreatesUpdaterArtifacts: false },
    );
    assert.deepEqual(
      optionalUpdaterPlan({ bundleTypes, signingKeyPresent: true, publicKeyPresent: true }),
      { updaterAttempted: true, fallbackCreatesUpdaterArtifacts: false },
    );
  }
  for (const bundleTypes of ["deb", "rpm", "msi"]) {
    assert.deepEqual(
      optionalUpdaterPlan({ bundleTypes, signingKeyPresent: true, publicKeyPresent: true }),
      { updaterAttempted: false, fallbackCreatesUpdaterArtifacts: false },
    );
  }
});

test("installer bundling launches the local Tauri CLI without a platform shell", () => {
  const invocation = tauriBundleInvocation("nsis", "x86_64-pc-windows-msvc", false);
  assert.equal(invocation.executable, process.execPath);
  assert.match(invocation.arguments[0], /[\\/]@tauri-apps[\\/]cli[\\/]tauri\.js$/u);
  assert.deepEqual(invocation.arguments.slice(1), [
    "bundle",
    "--ci",
    "--verbose",
    "--bundles",
    "nsis",
    "--config",
    JSON.stringify({ bundle: { createUpdaterArtifacts: false } }),
    "--target",
    "x86_64-pc-windows-msvc",
  ]);
  assert.equal(invocation.arguments.includes("npm.cmd"), false);
});
