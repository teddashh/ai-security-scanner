#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

const root = resolve(import.meta.dirname, "..");

function git(args, options = {}) {
  return execFileSync("git", ["-C", root, ...args], {
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    ...options,
  });
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function nulFields(bytes) {
  const fields = bytes.toString("utf8").split("\0");
  if (fields.at(-1) === "") fields.pop();
  return fields;
}

const temporaryRoot = mkdtempSync(join(tmpdir(), "ai-security-scanner-engine-eol-"));
let trackedPathCount = 0;
try {
  const checkoutRoot = join(temporaryRoot, "checkout");
  const temporaryIndex = join(temporaryRoot, "index");
  mkdirSync(checkoutRoot);
  const indexEnvironment = { ...process.env, GIT_INDEX_FILE: temporaryIndex };

  // Snapshot the current worktree into a private index. This makes local
  // validation cover modified, staged, and newly added engine inputs without
  // changing the user's real index. Reading only HEAD here would falsely pass
  // precisely the launcher/Dockerfile edits the check is meant to qualify.
  git(["read-tree", "HEAD"], { env: indexEnvironment });
  git(["add", "--all", "--", "engines"], { env: indexEnvironment });
  const trackedPaths = nulFields(git(
    ["ls-files", "-z", "--", "engines"],
    { env: indexEnvironment },
  ));
  trackedPathCount = trackedPaths.length;
  if (trackedPaths.length === 0) {
    throw new Error("engine line-ending validation found no tracked engine inputs");
  }
  if (trackedPaths.some((path) => !path.startsWith("engines/") || path.includes("\0"))) {
    throw new Error("engine line-ending validation received an unsafe tracked path");
  }

  const pathInput = Buffer.from(`${trackedPaths.join("\0")}\0`, "utf8");
  const attributeFields = nulFields(git(
    ["check-attr", "-z", "--stdin", "text", "eol"],
    { input: pathInput },
  ));
  const attributeErrors = [];
  for (let index = 0; index < attributeFields.length; index += 3) {
    const path = attributeFields[index];
    const attribute = attributeFields[index + 1];
    const value = attributeFields[index + 2];
    if (attribute === "text" && value !== "auto") {
      attributeErrors.push(`${path}: text must be auto, observed ${value}`);
    }
    if (attribute === "eol" && value !== "lf") {
      attributeErrors.push(`${path}: eol must be lf, observed ${value}`);
    }
  }
  if (attributeFields.length !== trackedPaths.length * 6) {
    attributeErrors.push("git check-attr did not return both text and eol for every tracked engine input");
  }
  if (attributeErrors.length > 0) {
    throw new Error(`engine line-ending attributes are incomplete:\n${attributeErrors.join("\n")}`);
  }

  const checkoutPrefix = `${checkoutRoot.split(sep).join("/")}/`;
  git(
    [
      "-c",
      "core.autocrlf=true",
      "checkout-index",
      "--stdin",
      "-z",
      `--prefix=${checkoutPrefix}`,
    ],
    { env: indexEnvironment, input: pathInput },
  );

  const mismatches = [];
  for (const path of trackedPaths) {
    const canonicalBlob = git(["show", `:${path}`], { env: indexEnvironment });
    const checkedOut = readFileSync(join(checkoutRoot, ...path.split("/")));
    if (!canonicalBlob.equals(checkedOut)) {
      mismatches.push(
        `${path}: Git blob ${sha256(canonicalBlob)} != autocrlf checkout ${sha256(checkedOut)}`,
      );
    }
  }
  if (mismatches.length > 0) {
    throw new Error(
      `engine inputs are not byte-stable under core.autocrlf=true:\n${mismatches.join("\n")}`,
    );
  }
} finally {
  rmSync(temporaryRoot, { force: true, recursive: true });
}

console.log(
  `Verified ${trackedPathCount} current engine inputs are byte-stable in a core.autocrlf=true checkout.`,
);
