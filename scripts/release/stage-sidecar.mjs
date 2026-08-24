import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { chmod, copyFile, lstat, mkdir, readFile, unlink } from "node:fs/promises";
import path from "node:path";
import { PROJECT_ROOT, parseArgs, requireString, runMain } from "./lib.mjs";

const SIDECARS = new Set([
  "ai-security-scanner-egress-gateway",
  "ai-security-scanner-bootstrap-broker",
  "ai-security-scanner-cli",
]);
const TARGETS = new Map([
  ["x86_64-unknown-linux-gnu", { extension: "", magic: "elf" }],
  ["aarch64-unknown-linux-gnu", { extension: "", magic: "elf" }],
  ["x86_64-apple-darwin", { extension: "", magic: "mach-o" }],
  ["aarch64-apple-darwin", { extension: "", magic: "mach-o" }],
  ["universal-apple-darwin", { extension: "", magic: "mach-o" }],
  ["x86_64-pc-windows-msvc", { extension: ".exe", magic: "pe" }],
  ["x86_64-pc-windows-gnu", { extension: ".exe", magic: "pe" }],
]);

async function prepareDestination(file) {
  try {
    const metadata = await lstat(file);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`refusing to replace a non-regular staged sidecar: ${file}`);
    }
    await unlink(file);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    throw error;
  }
}

async function verifyExecutable(file, kind) {
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1024) {
    throw new Error(`sidecar is not a non-empty regular executable: ${file}`);
  }
  const bytes = (await readFile(file)).subarray(0, 4);
  const hex = bytes.toString("hex");
  const valid =
    (kind === "elf" && hex === "7f454c46") ||
    (kind === "pe" && bytes[0] === 0x4d && bytes[1] === 0x5a) ||
    (kind === "mach-o" &&
      new Set(["cafebabe", "cafebabf", "feedface", "feedfacf", "cefaedfe", "cffaedfe"]).has(hex));
  if (!valid) {
    throw new Error(`sidecar has an unexpected ${kind} file header: ${hex}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const sidecar = requireString(args, "binary");
  if (!SIDECARS.has(sidecar)) {
    throw new Error(`unsupported sidecar binary: ${sidecar}`);
  }
  const targetTriple = requireString(args, "target");
  const target = TARGETS.get(targetTriple);
  if (!target) {
    throw new Error(`unsupported sidecar target: ${targetTriple}`);
  }
  const outputDirectory = path.join(PROJECT_ROOT, "src-tauri/binaries");
  const output = path.join(outputDirectory, `${sidecar}-${targetTriple}${target.extension}`);
  await mkdir(outputDirectory, { recursive: true });
  await prepareDestination(output);

  if (targetTriple === "universal-apple-darwin") {
    const x86 = path.resolve(requireString(args, "source-x86"));
    const arm = path.resolve(requireString(args, "source-arm"));
    await verifyExecutable(x86, "mach-o");
    await verifyExecutable(arm, "mach-o");
    execFileSync("lipo", ["-create", x86, arm, "-output", output], { stdio: "inherit" });
    execFileSync("lipo", ["-verify_arch", "x86_64", "arm64", output], { stdio: "inherit" });
  } else {
    const source = path.resolve(requireString(args, "source"));
    await verifyExecutable(source, target.magic);
    await copyFile(source, output, constants.COPYFILE_EXCL);
  }
  if (process.platform !== "win32") {
    await chmod(output, 0o755);
  }
  await verifyExecutable(output, target.magic);
  process.stdout.write(`${output}\n`);
}

runMain(main);
