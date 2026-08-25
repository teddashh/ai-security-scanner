#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const fixtureRoot = resolve(root, "engines/images/local-launcher/testdata/oci-layout");
const sourcePath = resolve(
  root,
  "engines/images/local-launcher/testdata/oci-layout-source/spring-core-2.5.6.SEC03.jar.base64",
);
const blobRoot = resolve(fixtureRoot, "blobs/sha256");
const expectedJarSHA256 = "b9883ae1fd6b53762b285cfeb1e59bb52313855893fd3cd1ff1eafea26faa41e";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function writeString(buffer, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > length) throw new Error(`ustar field exceeds ${length} bytes`);
  bytes.copy(buffer, offset);
}

function writeOctal(buffer, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 1, "0");
  if (encoded.length !== length - 1) throw new Error("ustar numeric field overflowed");
  writeString(buffer, offset, length, `${encoded}\0`);
}

function ustarFile(path, contents) {
  if (!/^[a-zA-Z0-9._/-]+$/u.test(path) || path.startsWith("/") || path.includes("..")) {
    throw new Error("unsafe deterministic ustar path");
  }
  const header = Buffer.alloc(512);
  writeString(header, 0, 100, path);
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, contents.length);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = "0".charCodeAt(0);
  writeString(header, 257, 6, "ustar\0");
  writeString(header, 263, 2, "00");
  writeString(header, 265, 32, "root");
  writeString(header, 297, 32, "root");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeString(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  const padding = Buffer.alloc((512 - (contents.length % 512)) % 512);
  return Buffer.concat([header, contents, padding]);
}

function jsonBytes(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

const encodedJar = (await readFile(sourcePath, "utf8")).replace(/\s+/gu, "");
const jar = Buffer.from(encodedJar, "base64");
if (jar.length !== 1105 || sha256(jar) !== expectedJarSHA256) {
  throw new Error("pinned OCI fixture JAR does not match its source digest");
}

const layer = Buffer.concat([
  ustarFile("app/lib/spring-core-2.5.6.SEC03.jar", jar),
  Buffer.alloc(1024),
]);
const layerDigest = sha256(layer);
const config = jsonBytes({
  architecture: "amd64",
  os: "linux",
  rootfs: { type: "layers", diff_ids: [`sha256:${layerDigest}`] },
  config: {},
});
const configDigest = sha256(config);
const manifest = jsonBytes({
  schemaVersion: 2,
  mediaType: "application/vnd.oci.image.manifest.v1+json",
  config: {
    mediaType: "application/vnd.oci.image.config.v1+json",
    digest: `sha256:${configDigest}`,
    size: config.length,
  },
  layers: [{
    mediaType: "application/vnd.oci.image.layer.v1.tar",
    digest: `sha256:${layerDigest}`,
    size: layer.length,
  }],
});
const manifestDigest = sha256(manifest);
const index = {
  schemaVersion: 2,
  mediaType: "application/vnd.oci.image.index.v1+json",
  manifests: [{
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    digest: `sha256:${manifestDigest}`,
    size: manifest.length,
    annotations: { "org.opencontainers.image.ref.name": "fixture" },
  }],
};

await rm(blobRoot, { recursive: true, force: true });
await mkdir(blobRoot, { recursive: true, mode: 0o755 });
await Promise.all([
  writeFile(resolve(fixtureRoot, "oci-layout"), `${JSON.stringify({ imageLayoutVersion: "1.0.0" })}\n`),
  writeFile(resolve(fixtureRoot, "index.json"), `${JSON.stringify(index)}\n`),
  writeFile(
    resolve(fixtureRoot, ".ai-security-scanner-input.json"),
    `${JSON.stringify({
      schema_version: "ai-security-scanner.local-input/v1",
      input_profile: "container_image_oci_layout",
    })}\n`,
  ),
  writeFile(resolve(blobRoot, layerDigest), layer),
  writeFile(resolve(blobRoot, configDigest), config),
  writeFile(resolve(blobRoot, manifestDigest), manifest),
]);

process.stdout.write(`${JSON.stringify({
  image_id: `sha256:${configDigest}`,
  layer_digest: `sha256:${layerDigest}`,
  manifest_digest: `sha256:${manifestDigest}`,
})}\n`);
