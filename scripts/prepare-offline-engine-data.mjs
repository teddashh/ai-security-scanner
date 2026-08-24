#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, rename, rm, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

const root = resolve(import.meta.dirname, "..");
const requested = process.argv.length === 2 ? "all" : process.argv[2];
if (!new Set(["all", "semgrep", "trivy", "grype"]).has(requested) || process.argv.length > 3) {
  throw new Error("usage: prepare-offline-engine-data.mjs [all|semgrep|trivy|grype]");
}

const trivy = {
  manifest: "sha256:a61aa42edc534843230ca24ef72ef322a2da18d717c3de4b6277f4aac43926a1",
  layer: "sha256:8cf3aaad2dde16ff1529445dab19c2e2a9adc457dbe8d2b02fdbce06b0f638dc",
  size: 114273436,
  output: resolve(root, ".engine-cache/offline/trivy/db.tar.gz"),
};
const grype = {
  url: "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-08-24T00:17:18Z_1787552533.tar.zst",
  digest: "sha256:20a7315860b2d07231103a73bedec01de31e7a7f3d590aedfc61709dc9e117f9",
  size: 146693420,
  output: resolve(root, ".engine-cache/offline/grype/db.tar.zst"),
};

async function fetchChecked(url, output, expectedDigest, expectedSize, headers = {}) {
  const response = await fetch(url, { headers, redirect: "follow", signal: AbortSignal.timeout(20 * 60 * 1000) });
  if (!response.ok || !response.body) {
    throw new Error(`immutable engine input download failed (${response.status})`);
  }
  if (response.url.startsWith("http://")) {
    throw new Error("immutable engine input followed an insecure redirect");
  }
  await mkdir(dirname(output), { recursive: true, mode: 0o700 });
  const temporary = `${output}.partial-${process.pid}`;
  await rm(temporary, { force: true });
  try {
    await pipeline(Readable.fromWeb(response.body), createWriteStream(temporary, { flags: "wx", mode: 0o600 }));
    const info = await stat(temporary);
    if (!info.isFile() || info.size !== expectedSize) {
      throw new Error(`immutable engine input size mismatch (expected ${expectedSize}, got ${info.size})`);
    }
    const digest = createHash("sha256");
    const file = await import("node:fs").then(({ createReadStream }) => createReadStream(temporary));
    for await (const chunk of file) digest.update(chunk);
    const actual = `sha256:${digest.digest("hex")}`;
    if (actual !== expectedDigest) {
      throw new Error(`immutable engine input digest mismatch (expected ${expectedDigest}, got ${actual})`);
    }
    await rename(temporary, output);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

async function prepareTrivy() {
  const tokenResponse = await fetch("https://ghcr.io/token?service=ghcr.io&scope=repository%3Aaquasecurity%2Ftrivy-db%3Apull", {
    signal: AbortSignal.timeout(30_000),
  });
  if (!tokenResponse.ok) throw new Error("could not obtain anonymous Trivy DB pull token");
  const tokenDocument = await tokenResponse.json();
  if (typeof tokenDocument.token !== "string" || tokenDocument.token.length < 32) {
    throw new Error("anonymous Trivy DB pull token is invalid");
  }
  const headers = {
    Accept: "application/vnd.oci.image.manifest.v1+json",
    Authorization: `Bearer ${tokenDocument.token}`,
  };
  const manifestURL = `https://ghcr.io/v2/aquasecurity/trivy-db/manifests/${trivy.manifest}`;
  const manifestResponse = await fetch(manifestURL, { headers, signal: AbortSignal.timeout(30_000) });
  if (!manifestResponse.ok) throw new Error("could not read the immutable Trivy DB OCI manifest");
  const returnedDigest = manifestResponse.headers.get("docker-content-digest");
  const manifest = await manifestResponse.json();
  if (returnedDigest !== trivy.manifest || manifest.schemaVersion !== 2 || manifest.layers?.length !== 1) {
    throw new Error("Trivy DB OCI manifest does not match its release contract");
  }
  const layer = manifest.layers[0];
  if (layer.digest !== trivy.layer || layer.size !== trivy.size || layer.annotations?.["org.opencontainers.image.title"] !== "db.tar.gz") {
    throw new Error("Trivy DB OCI layer does not match its release contract");
  }
  await fetchChecked(
    `https://ghcr.io/v2/aquasecurity/trivy-db/blobs/${trivy.layer}`,
    trivy.output,
    trivy.layer,
    trivy.size,
    { Authorization: `Bearer ${tokenDocument.token}` },
  );
}

async function prepareSemgrepSubmodules() {
  const lockPath = resolve(root, "engines/images/semgrep/submodules.lock");
  const records = (await readFile(lockPath, "utf8"))
    .split(/\r?\n/u)
    .filter((line) => line !== "" && !line.startsWith("#"))
    .map((line) => {
      const [path, repository, revision, digest, sizeText, archive] = line.split("|");
      if (
        !/^[a-z0-9_./-]+$/u.test(path) || path.includes("..") ||
        !/^https:\/\/github\.com\/(?:returntocorp|semgrep)\/[a-z0-9_.-]+$/u.test(repository) ||
        !/^[0-9a-f]{40}$/u.test(revision) ||
        !/^sha256:[0-9a-f]{64}$/u.test(digest) ||
        !/^[1-9][0-9]*$/u.test(sizeText) ||
        !/^[a-z0-9_.-]+\.tar\.gz$/u.test(archive)
      ) {
        throw new Error(`invalid Semgrep submodule lock record: ${line}`);
      }
      return { repository, revision, digest, size: Number(sizeText), archive };
    });
  if (records.length !== 36 || new Set(records.map(({ archive }) => archive)).size !== records.length) {
    throw new Error("Semgrep submodule lock must contain 36 unique archives");
  }

  for (let offset = 0; offset < records.length; offset += 6) {
    await Promise.all(records.slice(offset, offset + 6).map((record) => fetchChecked(
      `${record.repository}/archive/${record.revision}.tar.gz`,
      resolve(root, ".engine-cache/offline/semgrep-submodules", record.archive),
      record.digest,
      record.size,
    )));
  }
}

if (requested === "all" || requested === "semgrep") await prepareSemgrepSubmodules();
if (requested === "all" || requested === "trivy") await prepareTrivy();
if (requested === "all" || requested === "grype") await fetchChecked(grype.url, grype.output, grype.digest, grype.size);

process.stdout.write(`Prepared checksum-verified offline data for ${requested}.\n`);
