#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const upstreamRoot = join(root, ".upstreams");
const outputPath = join(root, "engines", "upstreams.lock.json");

const git = (directory, ...args) =>
  execFileSync("git", ["-C", directory, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

const repositories = [];

for (const owner of readdirSync(upstreamRoot).sort()) {
  const ownerPath = join(upstreamRoot, owner);
  if (!statSync(ownerPath).isDirectory()) continue;

  for (const repository of readdirSync(ownerPath).sort()) {
    const repositoryPath = join(ownerPath, repository);
    if (!statSync(repositoryPath).isDirectory()) continue;

    try {
      const remote = git(repositoryPath, "remote", "get-url", "origin")
        .replace(/\.git$/, "")
        .replace(/^git@github\.com:/, "https://github.com/");
      repositories.push({
        id: `${owner}/${repository}`,
        path: relative(root, repositoryPath),
        remote,
        branch: git(repositoryPath, "branch", "--show-current"),
        revision: git(repositoryPath, "rev-parse", "HEAD"),
        shallow: git(repositoryPath, "rev-parse", "--is-shallow-repository") === "true",
      });
    } catch (error) {
      throw new Error(`Could not inspect ${repositoryPath}: ${error.message}`);
    }
  }
}

const lock = {
  schema_version: "1.0.0",
  generated_by: "scripts/lock-upstreams.mjs",
  note: "Research/source checkout lock only. Engine release manifests independently pin tested tags, images, rule databases, and adapters.",
  repositories,
};

writeFileSync(outputPath, `${JSON.stringify(lock, null, 2)}\n`, "utf8");
console.log(`Locked ${repositories.length} upstream repositories in ${outputPath}`);
