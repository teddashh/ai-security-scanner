import { execFileSync } from "node:child_process";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import {
  PROJECT_ROOT,
  parseArgs,
  requireString,
  runMain,
} from "./lib.mjs";

const PACKAGE_LAYOUTS = Object.freeze([
  Object.freeze({ directory: "deb", suffix: ".deb" }),
  Object.freeze({ directory: "rpm", suffix: ".rpm" }),
]);

async function regularFilesBelow(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    const metadata = await lstat(candidate);
    if (metadata.isSymbolicLink()) {
      throw new Error(`Linux bundle output contains a symlink: ${candidate}`);
    }
    if (metadata.isDirectory()) {
      output.push(...(await regularFilesBelow(candidate)));
    } else if (metadata.isFile()) {
      output.push(candidate);
    } else {
      throw new Error(`Linux bundle output contains a special file: ${candidate}`);
    }
  }
  return output;
}

async function validateSignature(signatureFile) {
  const metadata = await lstat(signatureFile);
  const signature = (await readFile(signatureFile, "utf8")).trim();
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size < 64 ||
    metadata.size > 32 * 1024 ||
    signature.length < 64 ||
    !/^[A-Za-z0-9+/=]+$/u.test(signature)
  ) {
    throw new Error(`Tauri produced a malformed update signature: ${signatureFile}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bundleRoot = path.resolve(requireString(args, "bundle-root"));
  if (!process.env.TAURI_SIGNING_PRIVATE_KEY) {
    throw new Error("TAURI_SIGNING_PRIVATE_KEY is required to sign Linux package updates");
  }

  const tauriCli = path.join(PROJECT_ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js");
  let signed = 0;
  for (const layout of PACKAGE_LAYOUTS) {
    const packages = (await regularFilesBelow(path.join(bundleRoot, layout.directory)))
      .filter((file) => file.endsWith(layout.suffix))
      .sort();
    if (packages.length !== 1) {
      throw new Error(
        `expected exactly one ${layout.suffix} package to sign; found ${packages.length}`,
      );
    }
    const packageFile = packages[0];
    const signatureFile = `${packageFile}.sig`;
    try {
      await validateSignature(signatureFile);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      execFileSync(process.execPath, [tauriCli, "signer", "sign", packageFile], {
        cwd: PROJECT_ROOT,
        env: process.env,
        stdio: "inherit",
      });
      await validateSignature(signatureFile);
      signed += 1;
    }
  }
  process.stdout.write(`Linux package updater signatures ready; generated ${signed}.\n`);
}

runMain(main);
