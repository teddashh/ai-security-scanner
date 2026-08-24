import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { PROJECT_ROOT } from "./lib.mjs";

export function verifyUpdaterSignatures(publicKey, pairs) {
  if (typeof publicKey !== "string" || publicKey.length < 64 || !/^[A-Za-z0-9+/=]+$/u.test(publicKey)) {
    throw new Error("embedded updater public key is not a bounded outer Base64 document");
  }
  if (!Array.isArray(pairs) || pairs.length === 0) {
    throw new Error("at least one updater payload/signature pair is required");
  }
  const paths = [];
  for (const pair of pairs) {
    if (!pair || typeof pair.payload !== "string" || typeof pair.signature !== "string") {
      throw new Error("updater verification pair is malformed");
    }
    paths.push(path.resolve(pair.payload), path.resolve(pair.signature));
  }
  const rustupCargo = path.join(os.homedir(), ".cargo", "bin", process.platform === "win32" ? "cargo.exe" : "cargo");
  const cargo = process.env.CARGO ?? (existsSync(rustupCargo) ? rustupCargo : "cargo");
  execFileSync(cargo, [
    "run",
    "--quiet",
    "--locked",
    "--manifest-path",
    path.join(PROJECT_ROOT, "src-tauri", "Cargo.toml"),
    "--no-default-features",
    "--features",
    "release-verifier",
    "--bin",
    "ai-security-scanner-updater-verifier",
    "--",
    publicKey,
    ...paths,
  ], {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
}
