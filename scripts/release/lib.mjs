import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export function parseArgs(argv) {
  const parsed = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      throw new Error(`unexpected argument: ${item}`);
    }
    const equals = item.indexOf("=");
    if (equals !== -1) {
      parsed.set(item.slice(2, equals), item.slice(equals + 1));
      continue;
    }
    const key = item.slice(2);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      parsed.set(key, true);
    } else {
      parsed.set(key, value);
      index += 1;
    }
  }
  return parsed;
}

export function requireString(args, key) {
  const value = args.get(key);
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`--${key} is required`);
  }
  return value;
}

export async function readJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

export async function writeTextAtomic(file, contents) {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  await writeFile(temporary, contents, { encoding: "utf8", flag: "wx", mode: 0o644 });
  await rename(temporary, file);
}

export async function writeJsonAtomic(file, value) {
  await writeTextAtomic(file, `${JSON.stringify(value, null, 2)}\n`);
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export async function sha256File(file) {
  return sha256(await readFile(file));
}

export function toPosix(file) {
  return file.split(path.sep).join("/");
}

export function assertSafeRelativePath(relative) {
  if (
    typeof relative !== "string" ||
    relative.length === 0 ||
    path.isAbsolute(relative) ||
    relative.includes("\0") ||
    relative.split(/[\\/]/u).some((component) => component === "..")
  ) {
    throw new Error(`unsafe relative path: ${String(relative)}`);
  }
}

export async function assertRegularFile(file) {
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`expected a regular, non-symlink file: ${file}`);
  }
  return metadata;
}

export async function resolveInside(root, relative) {
  assertSafeRelativePath(relative);
  const canonicalRoot = await realpath(root);
  const candidate = path.resolve(canonicalRoot, relative);
  const prefix = `${canonicalRoot}${path.sep}`;
  if (candidate !== canonicalRoot && !candidate.startsWith(prefix)) {
    throw new Error(`path escapes root: ${relative}`);
  }
  return candidate;
}

export function isSemver(value) {
  return /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(value);
}

export function normalizeLicense(value) {
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim().replaceAll(/\s+/gu, " ");
  }
  if (value && typeof value === "object" && typeof value.type === "string") {
    return value.type.trim();
  }
  return "NOASSERTION";
}

export function runMain(main) {
  Promise.resolve()
    .then(main)
    .catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`release tooling: ${message}\n`);
      process.exitCode = 1;
    });
}
