import { execFileSync } from "node:child_process";
import path from "node:path";
import { PROJECT_ROOT, parseArgs, requireString, runMain } from "./lib.mjs";

const BINARIES = Object.freeze([
  Object.freeze({ name: "ai-security-scanner-egress-gateway", feature: "egress-gateway" }),
  Object.freeze({ name: "ai-security-scanner-bootstrap-broker", feature: "broker" }),
  Object.freeze({ name: "ai-security-scanner-cli", feature: "cli" }),
]);
const SUPPORTED_TARGETS = new Set([
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
  "universal-apple-darwin",
  "x86_64-pc-windows-msvc",
  "x86_64-pc-windows-gnu",
]);

function cargoBuild(binary, target) {
  const cargo = process.env.CARGO || "cargo";
  const features = binary.name === "ai-security-scanner-cli" && target.includes("windows")
    ? `${binary.feature},installer-runtime-cache`
    : binary.feature;
  execFileSync(
    cargo,
    [
      "build",
      "--locked",
      "--release",
      "--package",
      "ai-security-scanner",
      "--no-default-features",
      "--features",
      features,
      "--bin",
      binary.name,
      "--target",
      target,
    ],
    { cwd: PROJECT_ROOT, env: process.env, stdio: "inherit" },
  );
}

function binaryPath(binary, target) {
  const extension = target.includes("windows") ? ".exe" : "";
  return path.join(PROJECT_ROOT, "target", target, "release", `${binary.name}${extension}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const target = requireString(args, "target");
  if (!SUPPORTED_TARGETS.has(target)) {
    throw new Error(`unsupported sidecar target: ${target}`);
  }
  const stage = path.join(PROJECT_ROOT, "scripts/release/stage-sidecar.mjs");
  for (const binary of BINARIES) {
    if (target === "universal-apple-darwin") {
      cargoBuild(binary, "x86_64-apple-darwin");
      cargoBuild(binary, "aarch64-apple-darwin");
      for (const thinTarget of ["x86_64-apple-darwin", "aarch64-apple-darwin"]) {
        execFileSync(
          process.execPath,
          [
            stage,
            "--binary",
            binary.name,
            "--target",
            thinTarget,
            "--source",
            binaryPath(binary, thinTarget),
          ],
          { cwd: PROJECT_ROOT, stdio: "inherit" },
        );
      }
      execFileSync(
        process.execPath,
        [
          stage,
          "--binary",
          binary.name,
          "--target",
          target,
          "--source-x86",
          binaryPath(binary, "x86_64-apple-darwin"),
          "--source-arm",
          binaryPath(binary, "aarch64-apple-darwin"),
        ],
        { cwd: PROJECT_ROOT, stdio: "inherit" },
      );
    } else {
      cargoBuild(binary, target);
      execFileSync(
        process.execPath,
        [
          stage,
          "--binary",
          binary.name,
          "--target",
          target,
          "--source",
          binaryPath(binary, target),
        ],
        { cwd: PROJECT_ROOT, stdio: "inherit" },
      );
    }
  }
}

runMain(main);
