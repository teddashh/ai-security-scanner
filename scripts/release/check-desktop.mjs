import { execFileSync } from "node:child_process";
import path from "node:path";
import { PROJECT_ROOT, parseArgs, requireString, runMain } from "./lib.mjs";

function rustHost() {
  const rustc = process.env.RUSTC || "rustc";
  const verbose = execFileSync(rustc, ["-vV"], { encoding: "utf8" });
  const host = verbose.match(/^host:\s*(\S+)\s*$/mu)?.[1];
  if (!host) {
    throw new Error("rustc did not report a host target");
  }
  return host;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const target = args.has("target") ? requireString(args, "target") : rustHost();
  const buildSidecar = path.join(PROJECT_ROOT, "scripts/release/build-sidecar.mjs");
  execFileSync(process.execPath, [buildSidecar, "--target", target], {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
  const cargo = process.env.CARGO || "cargo";
  const cargoArgs = ["check", "--locked", "--package", "ai-security-scanner", "--features", "desktop"];
  if (args.has("target")) {
    cargoArgs.push("--target", target);
  }
  execFileSync(cargo, cargoArgs, { cwd: PROJECT_ROOT, env: process.env, stdio: "inherit" });
}

runMain(main);
