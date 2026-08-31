import { spawnSync } from "node:child_process";
import { lstat, readFile, readdir, unlink } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseArgs, requireString, runMain } from "./lib.mjs";

const SUPPORTED = new Map([
  ["deb", { updaterEligible: false }],
  ["rpm", { updaterEligible: false }],
  ["appimage", { updaterEligible: true, platform: "linux-x86_64", directory: "appimage" }],
  ["app,dmg", { updaterEligible: true, platform: "macos-universal", directory: "macos" }],
  ["nsis", { updaterEligible: true, platform: "windows-x86_64", directory: "nsis" }],
  ["msi", { updaterEligible: false }],
]);
const require = createRequire(import.meta.url);
const TAURI_CLI = require.resolve("@tauri-apps/cli/tauri.js");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function tauriBundleArguments(bundleTypes, target, createUpdaterArtifacts) {
  const arguments_ = [
    TAURI_CLI,
    "bundle",
    "--ci",
    "--verbose",
    "--bundles",
    bundleTypes,
    "--config",
    JSON.stringify({ bundle: { createUpdaterArtifacts } }),
  ];
  if (target) arguments_.push("--target", target);
  return arguments_;
}

export function tauriBundleInvocation(bundleTypes, target, createUpdaterArtifacts) {
  return {
    executable: process.execPath,
    arguments: tauriBundleArguments(bundleTypes, target, createUpdaterArtifacts),
  };
}

function runTauriBundle(bundleTypes, target, createUpdaterArtifacts) {
  const invocation = tauriBundleInvocation(bundleTypes, target, createUpdaterArtifacts);
  const result = spawnSync(invocation.executable, invocation.arguments, {
    cwd: process.cwd(),
    env: process.env,
    stdio: "inherit",
    shell: false,
  });
  if (result.error) {
    process.stderr.write(
      `release tooling: Tauri ${bundleTypes} bundler could not start: ${result.error.message}\n`,
    );
  }
  return result;
}

function updaterCandidateName(name, bundleTypes, version) {
  if (bundleTypes === "app,dmg") {
    return [
      "ai-security-scanner.app.tar.gz",
      "ai-security-scanner.app.tar.gz.sig",
      `ai-security-scanner_${version}_universal.app.tar.gz`,
      `ai-security-scanner_${version}_universal.app.tar.gz.sig`,
    ].includes(name);
  }
  return name.endsWith(".sig");
}

async function removePartialUpdaterFiles(bundleRoot, contract, bundleTypes, version) {
  if (!contract.updaterEligible) return;
  const directory = path.join(bundleRoot, contract.directory);
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return;
    throw error;
  }
  for (const entry of entries) {
    if (!updaterCandidateName(entry.name, bundleTypes, version)) continue;
    const candidate = path.join(directory, entry.name);
    const metadata = await lstat(candidate);
    assert(
      metadata.isFile() && !metadata.isSymbolicLink(),
      `refusing to clean a non-regular updater staging entry: ${candidate}`,
    );
    await unlink(candidate);
  }
}

async function hasEmbeddedUpdaterPublicKey(configFile) {
  try {
    const config = JSON.parse(await readFile(configFile, "utf8"));
    return typeof config.plugins?.updater?.pubkey === "string" && config.plugins.updater.pubkey.length >= 64;
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return false;
    throw error;
  }
}

export function optionalUpdaterPlan({ bundleTypes, signingKeyPresent, publicKeyPresent }) {
  const contract = SUPPORTED.get(bundleTypes);
  assert(contract, `unsupported installer bundle set: ${String(bundleTypes)}`);
  return {
    updaterAttempted: contract.updaterEligible && signingKeyPresent && publicKeyPresent,
    fallbackCreatesUpdaterArtifacts: false,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bundleTypes = requireString(args, "bundles");
  const bundleRoot = path.resolve(requireString(args, "bundle-root"));
  const version = requireString(args, "version");
  const target = args.get("target") || null;
  const configFile = path.resolve(args.get("tauri-config") ?? "src-tauri/tauri.conf.json");
  const contract = SUPPORTED.get(bundleTypes);
  assert(contract, `unsupported installer bundle set: ${bundleTypes}`);
  assert(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.test(version), "bundle version is invalid");

  const plan = optionalUpdaterPlan({
    bundleTypes,
    signingKeyPresent: Boolean(process.env.TAURI_SIGNING_PRIVATE_KEY),
    publicKeyPresent: await hasEmbeddedUpdaterPublicKey(configFile),
  });
  if (plan.updaterAttempted) {
    const signed = runTauriBundle(bundleTypes, target, true);
    if (signed.status === 0) return;
    process.stderr.write(
      `release tooling: optional ${bundleTypes} updater generation failed; retrying the installer without updater artifacts\n`,
    );
    await removePartialUpdaterFiles(bundleRoot, contract, bundleTypes, version);
  } else if (contract.updaterEligible) {
    process.stderr.write(
      `release tooling: optional ${bundleTypes} updater key material is unavailable; building the installer without an updater\n`,
    );
  }

  const installerOnly = runTauriBundle(bundleTypes, target, false);
  if (installerOnly.status !== 0) {
    throw new Error(`${bundleTypes} installer bundling failed independently of updater signing`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(main);
}
