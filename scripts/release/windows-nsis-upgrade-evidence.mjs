import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import {
  PROJECT_ROOT,
  assertSafeRelativePath,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  writeJsonAtomic,
} from "./lib.mjs";

export const PRIOR_WINDOWS_NSIS = Object.freeze({
  version: "0.1.7",
  tag: "v0.1.7",
  file: "ai-security-scanner_0.1.7_x64-setup.exe",
  bytes: 38_730_365,
  sha256: "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a",
  url: "https://github.com/teddashh/ai-security-scanner/releases/download/v0.1.7/ai-security-scanner_0.1.7_x64-setup.exe",
  runtimeManifestSha256:
    "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f",
  machineImageSha256:
    "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968",
});

const SCHEMA_VERSION = 1;
const PLATFORM = "windows-x86_64";
const INSTALLER_TYPE = "nsis";
const RUNNER = "windows-2025";
const MASTER_FRAMEWORK_REPORT_FILE = "master-framework-report.json";
const MASTER_FRAMEWORK_REPORT_ENTRY = "exports/master-framework-report.json";
const MASTER_FRAMEWORK_SIGNED_CASE_BUNDLE = "master-framework-report.case.tar.gz";
const N_MINUS_ONE_SIGNED_CASE_BUNDLE = "n-minus-one-before-upgrade.case.tar.gz";
const MASTER_FRAMEWORK_MANIFEST_ENTRY = "manifest.json";
const MASTER_FRAMEWORK_SIGNATURE_ENTRY = "signature.json";
const MASTER_FRAMEWORK_IDENTITY_ENTRY = "integrity/local-signing-identity.json";
const MASTER_FRAMEWORK_OBSERVATIONS_ENTRY = "observations.json";
const MASTER_FRAMEWORK_RAW_ARTIFACTS_ENTRY = "raw-artifacts.json";
const MASTER_FRAMEWORK_SCAN_RUNS_ENTRY = "scan-runs.json";
const MASTER_FRAMEWORK_COVERAGE_ENTRY = "coverage.json";
const MAX_MASTER_FRAMEWORK_REPORT_BYTES = 4 * 1024 * 1024;
const MAX_MASTER_FRAMEWORK_BUNDLE_BYTES = 64 * 1024 * 1024;
const MAX_MASTER_FRAMEWORK_BUNDLE_UNCOMPRESSED_BYTES = 128 * 1024 * 1024;
const MAX_MASTER_FRAMEWORK_BUNDLE_ENTRIES = 256;
const MASTER_FRAMEWORK_REPORT_NOTICE =
  "This report groups preliminary scanner observations by related framework coordinate. It is not an audit, certification, attestation, compliance determination, implementation assessment, score, pass, or fail. Missing relationships are unknown whenever coverage is incomplete.";
const LOCAL_SIGNING_IDENTITY_NOTICE =
  "This is a local export-integrity identity. It does not prove scanner correctness, completeness, authorship, organizational identity, audit status, or compliance.";
const BUNDLE_INTEGRITY_ONLY_NOTICE =
  "The Ed25519 signature establishes integrity of the signed manifest only. It does not prove scanner correctness, completeness, legal authorization, authorship, identity, audit status, or forensic validity.";
const CURRENT_MAPPING_REVIEW_PROCESS = "source_coordinate_and_rationale_review_v1";
const CURRENT_CONTROL_MAPPING_CATALOG = JSON.parse(
  readFileSync(path.join(PROJECT_ROOT, "mappings", "control-mappings.json"), "utf8"),
);
const CURRENT_MAPPING_PROVENANCE = Object.freeze({
  mapping_version: "2026-08-28.1",
  reviewed_at: "2026-08-29",
  review_process: CURRENT_MAPPING_REVIEW_PROCESS,
  catalog_sha256: "7e53c9fe72584ee455ec2a94ee6bcf5705fc717b8bb3fbe97cd7377bb7fd5123",
});
const FRAMEWORK_CONTRACTS = Object.freeze([
  Object.freeze({
    key: "nist_csf",
    name: "NIST CSF",
    version: "2.0",
    sourceUrl: "https://doi.org/10.6028/NIST.CSWP.29",
    source: Object.freeze({
      source_url: "https://doi.org/10.6028/NIST.CSWP.29",
      attribution_notice: "NIST Cybersecurity Framework (CSF) 2.0, National Institute of Standards and Technology.",
      license_notice: "Use of NIST source material remains subject to the source publication's notices.",
      modifications_notice: "Framework relationships and rationales in this report are project-authored navigation metadata.",
      non_endorsement_notice: "NIST has not reviewed or endorsed this report or integration.",
    }),
  }),
  Object.freeze({
    key: "iso_iec_27001",
    name: "ISO/IEC 27001",
    version: "2022",
    sourceUrl: "https://www.iso.org/standard/27001",
    source: Object.freeze({
      source_url: "https://www.iso.org/standard/27001",
      attribution_notice: "ISO/IEC 27001:2022 control coordinates are referenced nominatively.",
      license_notice: "ISO/IEC standard content remains subject to ISO's terms; this report is not a copy of the standard.",
      modifications_notice: "Framework relationships and rationales in this report are project-authored navigation metadata.",
      non_endorsement_notice: "ISO and IEC have not reviewed or endorsed this report or integration.",
    }),
  }),
  Object.freeze({
    key: "aidefend",
    name: "AIDEFEND",
    version: "1.20260805",
    sourceUrl:
      "https://github.com/edward-playground/aidefense-framework/blob/e10c1678ee49f03f8fb0c97d446ba3fbc3543655/data/data.json",
    source: Object.freeze({
      source_url: "https://github.com/edward-playground/aidefense-framework/blob/e10c1678ee49f03f8fb0c97d446ba3fbc3543655/data/data.json",
      attribution_notice: "AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.",
      license_notice: "Creative Commons Attribution 4.0 International: https://creativecommons.org/licenses/by/4.0/",
      modifications_notice: "ai-security-scanner uses a modified, project-authored six-record metadata selection from AIDEFEND 1.20260805 at pinned commit e10c1678ee49f03f8fb0c97d446ba3fbc3543655.",
      non_endorsement_notice: "This independent integration is not affiliated with, approved, certified, sponsored, or endorsed by AIDEFEND or its owner.",
    }),
  }),
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, keys, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()),
    `${label} fields are not the strict qualification set`,
  );
}

function assertSha256(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{64}$/u.test(value), `${label} is not a SHA-256`);
}

function assertTrue(value, label) {
  assert(value === true, `${label} was not proven`);
}

function assertBoundedInteger(value, minimum, maximum, label) {
  assert(
    Number.isSafeInteger(value) && value >= minimum && value <= maximum,
    `${label} is outside its qualification bound`,
  );
}

function assertString(value, label, maximum = 16 * 1024) {
  assert(
    typeof value === "string" && value.length > 0 && value.length <= maximum && value.trim() === value,
    `${label} is empty, malformed, or exceeds its bound`,
  );
}

function assertNullableString(value, label, maximum = 16 * 1024) {
  if (value === null) return;
  assertString(value, label, maximum);
}

function assertEnum(value, allowed, label) {
  assert(allowed.includes(value), `${label} is outside the supported contract`);
}

function assertRfc3339(value, label) {
  assertString(value, label, 128);
  assert(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u.test(value) &&
      Number.isFinite(Date.parse(value)),
    `${label} is not an RFC 3339 timestamp`,
  );
}

function assertDate(value, label) {
  assert(typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/u.test(value), `${label} is not an ISO calendar date`);
  const parsed = new Date(`${value}T00:00:00Z`);
  assert(
    Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value,
    `${label} is not a real ISO calendar date`,
  );
  return Math.floor(parsed.getTime() / 86_400_000);
}

function assertStringArray(value, label, { minimum = 0, maximum = 16_384, unique = false, sha256 = false } = {}) {
  assert(Array.isArray(value), `${label} must be an array`);
  assert(value.length >= minimum && value.length <= maximum, `${label} length is outside its bound`);
  for (const [index, item] of value.entries()) {
    if (sha256) assertSha256(item, `${label}[${index}]`);
    else assertString(item, `${label}[${index}]`);
  }
  if (unique) assert(new Set(value).size === value.length, `${label} contains duplicates`);
}

function assertExactStringArray(value, expected, label) {
  assert(
    Array.isArray(value) && JSON.stringify(value) === JSON.stringify(expected),
    `${label} differs from the required ordered values`,
  );
}

function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  assert(value && typeof value === "object", "control mapping catalog contains an unsupported JSON value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function validateCurrentMappingCatalog() {
  assertExactKeys(
    CURRENT_CONTROL_MAPPING_CATALOG,
    ["schema_version", "mapping_version", "provenance", "relationship", "disclaimer", "sources", "controls", "entries"],
    "current control mapping catalog",
  );
  assert(CURRENT_CONTROL_MAPPING_CATALOG.schema_version === "1.1", "current control mapping catalog schema changed");
  assert(CURRENT_CONTROL_MAPPING_CATALOG.relationship === "related", "current control mapping catalog relationship changed");
  assertExactKeys(
    CURRENT_CONTROL_MAPPING_CATALOG.provenance,
    ["reviewed_at", "review_process", "canonical_sha256"],
    "current control mapping catalog provenance",
  );
  assert(
    JSON.stringify({
      mapping_version: CURRENT_CONTROL_MAPPING_CATALOG.mapping_version,
      reviewed_at: CURRENT_CONTROL_MAPPING_CATALOG.provenance.reviewed_at,
      review_process: CURRENT_CONTROL_MAPPING_CATALOG.provenance.review_process,
      catalog_sha256: CURRENT_CONTROL_MAPPING_CATALOG.provenance.canonical_sha256,
    }) === JSON.stringify(CURRENT_MAPPING_PROVENANCE),
    "current control mapping catalog identity differs from the release validator",
  );
  const withoutDigest = structuredClone(CURRENT_CONTROL_MAPPING_CATALOG);
  delete withoutDigest.provenance.canonical_sha256;
  assert(
    sha256Bytes(Buffer.from(canonicalJson(withoutDigest), "utf8")) === CURRENT_MAPPING_PROVENANCE.catalog_sha256,
    "current control mapping catalog canonical digest failed independent recomputation",
  );
}

validateCurrentMappingCatalog();

function decodeCanonicalBase64(value, bytes, label) {
  assert(typeof value === "string" && /^[A-Za-z0-9+/]+={0,2}$/u.test(value), `${label} is not base64`);
  const decoded = Buffer.from(value, "base64");
  assert(decoded.length === bytes && decoded.toString("base64") === value, `${label} is not canonical ${bytes}-byte base64`);
  return decoded;
}

function validatePublicSigningIdentity(publicKeyBase64, keyId, label) {
  assertSha256(keyId, `${label} key ID`);
  const publicKey = decodeCanonicalBase64(publicKeyBase64, 32, `${label} public key`);
  assert(
    sha256Bytes(publicKey) === keyId,
    `${label} key ID is not the public-key SHA-256`,
  );
}

function canonicalIdentityDocument(document) {
  const canonical = {
    schema_version: document.schema_version,
    algorithm: document.algorithm,
    key_id: document.key_id,
    public_key_base64: document.public_key_base64,
    established_at: document.established_at,
    continuity_event: document.continuity_event,
  };
  if (document.previous_identity !== undefined) {
    canonical.previous_identity = canonicalIdentityDocument(document.previous_identity);
  }
  canonical.self_signature_base64 = document.self_signature_base64;
  canonical.notice = document.notice;
  return canonical;
}

function identitySignaturePayload(document) {
  return Buffer.from(JSON.stringify({
    schema_version: document.schema_version,
    algorithm: document.algorithm,
    key_id: document.key_id,
    public_key_base64: document.public_key_base64,
    established_at: document.established_at,
    continuity_event: document.continuity_event,
    // Rust's UnsignedIdentityDocument serializes Option::None as JSON null,
    // even though the public document omits the same optional field.
    previous_identity:
      document.previous_identity === undefined ? null : canonicalIdentityDocument(document.previous_identity),
    notice: document.notice,
  }), "utf8");
}

function validateIdentityDocument(document, depth = 1) {
  assert(depth <= 8, "public signing identity history exceeds its bounded depth");
  const hasPrevious = document?.previous_identity !== undefined;
  assertExactKeys(
    document,
    [
      "schema_version",
      "algorithm",
      "key_id",
      "public_key_base64",
      "established_at",
      "continuity_event",
      ...(hasPrevious ? ["previous_identity"] : []),
      "self_signature_base64",
      "notice",
    ],
    `public signing identity document depth ${depth}`,
  );
  assert(document.schema_version === "1", "public signing identity schema is not v1");
  assert(document.algorithm === "Ed25519", "public signing identity algorithm is not Ed25519");
  assert(document.notice === LOCAL_SIGNING_IDENTITY_NOTICE, "public signing identity notice changed");
  assertRfc3339(document.established_at, "public signing identity establishment time");
  assertEnum(
    document.continuity_event,
    ["generated", "legacy_key_adopted", "rotated_after_confirmed_key_loss"],
    "public signing identity continuity event",
  );
  const expectsPrevious = document.continuity_event === "rotated_after_confirmed_key_loss";
  assert(hasPrevious === expectsPrevious, "public signing identity predecessor shape is invalid");
  validatePublicSigningIdentity(document.public_key_base64, document.key_id, "public signing identity");
  const signature = decodeCanonicalBase64(document.self_signature_base64, 64, "public signing identity self-signature");
  if (hasPrevious) {
    validateIdentityDocument(document.previous_identity, depth + 1);
    assert(document.previous_identity.key_id !== document.key_id, "public signing identity rotation reused its predecessor key");
  }
  const rawPublicKey = Buffer.from(document.public_key_base64, "base64");
  const publicKey = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawPublicKey]),
    format: "der",
    type: "spki",
  });
  assert(
    verify(null, identitySignaturePayload(document), publicKey, signature),
    "public signing identity self-signature failed independent Node verification",
  );
  const compactBytes = Buffer.from(JSON.stringify(canonicalIdentityDocument(document)), "utf8");
  return { compactBytes, compactSha256: sha256Bytes(compactBytes) };
}

async function readStableBoundedFile(file, expectedBasename, maximumBytes, label) {
  const absolute = path.resolve(file);
  assert(path.basename(absolute) === expectedBasename, `${label} filename is incorrect`);
  const before = await lstat(absolute);
  assert(
    before.isFile() && !before.isSymbolicLink() && before.size >= 1 && before.size <= maximumBytes,
    `${label} is not one bounded regular file`,
  );
  const bytes = await readFile(absolute);
  const after = await lstat(absolute);
  assert(
    after.isFile() && !after.isSymbolicLink() && before.dev === after.dev && before.ino === after.ino &&
      before.size === after.size && bytes.length === after.size,
    `${label} changed while it was read`,
  );
  return { absolute, bytes, sha256: sha256Bytes(bytes) };
}

function decodeUtf8Json(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid UTF-8 JSON`);
  }
}

function tarText(field, label) {
  const zero = field.indexOf(0);
  const end = zero === -1 ? field.length : zero;
  assert(field.subarray(end).every((byte) => byte === 0), `${label} has nonzero bytes after its terminator`);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(field.subarray(0, end));
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

function tarOctal(field, label) {
  assert((field[0] & 0x80) === 0, `${label} uses unsupported base-256 encoding`);
  const text = Buffer.from(field).toString("ascii").replace(/\0.*$/u, "").trim();
  assert(/^[0-7]+$/u.test(text), `${label} is not canonical bounded octal`);
  const value = Number.parseInt(text, 8);
  assert(Number.isSafeInteger(value) && value >= 0, `${label} exceeds the safe integer bound`);
  return value;
}

function parseBoundedTarGz(compressed, label) {
  let archive;
  try {
    archive = gunzipSync(compressed, { maxOutputLength: MAX_MASTER_FRAMEWORK_BUNDLE_UNCOMPRESSED_BYTES });
  } catch (error) {
    throw new Error(`${label} is not a bounded valid gzip stream: ${error.message}`);
  }
  assert(
    archive.length >= 1024 && archive.length <= MAX_MASTER_FRAMEWORK_BUNDLE_UNCOMPRESSED_BYTES,
    `${label} expanded outside its tar bound`,
  );
  const entries = new Map();
  let offset = 0;
  let ended = false;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      let zeroBlocks = 0;
      while (offset + 512 <= archive.length && archive.subarray(offset, offset + 512).every((byte) => byte === 0)) {
        zeroBlocks += 1;
        offset += 512;
      }
      assert(zeroBlocks >= 2 && archive.subarray(offset).every((byte) => byte === 0), `${label} has a malformed tar terminator`);
      ended = true;
      break;
    }
    assert(entries.size < MAX_MASTER_FRAMEWORK_BUNDLE_ENTRIES, `${label} has too many tar entries`);
    const expectedChecksum = tarOctal(header.subarray(148, 156), `${label} tar checksum`);
    let actualChecksum = 0;
    for (let index = 0; index < header.length; index += 1) {
      actualChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
    }
    assert(actualChecksum === expectedChecksum, `${label} has a tar header checksum mismatch`);
    const magic = Buffer.from(header.subarray(257, 263)).toString("ascii");
    assert(magic === "ustar\0" || magic === "ustar ", `${label} uses an unsupported tar header format`);
    const name = tarText(header.subarray(0, 100), `${label} tar path`);
    const prefix = tarText(header.subarray(345, 500), `${label} tar prefix`);
    const relative = prefix.length > 0 ? `${prefix}/${name}` : name;
    assertSafeRelativePath(relative);
    assert(
      relative === path.posix.normalize(relative) && !relative.startsWith("./") && !relative.includes("\\"),
      `${label} has a noncanonical tar path: ${relative}`,
    );
    const type = header[156];
    assert(type === 0 || type === 0x30, `${label} contains a non-regular tar entry: ${relative}`);
    assert(tarText(header.subarray(157, 257), `${label} tar link target`).length === 0, `${label} regular entry has a link target`);
    const size = tarOctal(header.subarray(124, 136), `${label} tar entry size`);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    assert(dataEnd <= archive.length, `${label} tar entry exceeds the archive: ${relative}`);
    const paddedEnd = dataStart + Math.ceil(size / 512) * 512;
    assert(
      paddedEnd <= archive.length && archive.subarray(dataEnd, paddedEnd).every((byte) => byte === 0),
      `${label} has nonzero or truncated tar padding: ${relative}`,
    );
    assert(!entries.has(relative), `${label} repeats tar path: ${relative}`);
    entries.set(relative, Buffer.from(archive.subarray(dataStart, dataEnd)));
    offset = paddedEnd;
  }
  assert(ended && entries.size >= 1, `${label} has no complete tar terminator or payload`);
  return entries;
}

function verifyManifestPayloads(manifest, files, label) {
  assert(Array.isArray(manifest.entries) && manifest.entries.length >= 1 && manifest.entries.length <= MAX_MASTER_FRAMEWORK_BUNDLE_ENTRIES - 2, `${label} manifest entries are outside the bound`);
  assert(
    JSON.stringify(manifest.entries.map((entry) => entry?.path)) ===
      JSON.stringify(manifest.entries.map((entry) => entry?.path).sort()),
    `${label} manifest entries are not deterministically sorted`,
  );
  const declared = new Map();
  for (const [index, entry] of manifest.entries.entries()) {
    const entryLabel = `${label} manifest entry ${index + 1}`;
    assertExactKeys(entry, ["path", "media_type", "sha256", "byte_length", "contains_sensitive_data"], entryLabel);
    assertSafeRelativePath(entry.path);
    assert(entry.path === path.posix.normalize(entry.path) && !entry.path.includes("\\"), `${entryLabel} path is noncanonical`);
    assert(![MASTER_FRAMEWORK_MANIFEST_ENTRY, MASTER_FRAMEWORK_SIGNATURE_ENTRY].includes(entry.path), `${entryLabel} names a reserved signature file`);
    assert(!declared.has(entry.path), `${label} manifest repeats ${entry.path}`);
    assertString(entry.media_type, `${entryLabel} media type`, 256);
    assertSha256(entry.sha256, `${entryLabel} digest`);
    assertBoundedInteger(entry.byte_length, 0, MAX_MASTER_FRAMEWORK_BUNDLE_UNCOMPRESSED_BYTES, `${entryLabel} byte length`);
    assert(typeof entry.contains_sensitive_data === "boolean", `${entryLabel} sensitivity flag is not boolean`);
    const payload = files.get(entry.path);
    assert(payload, `${label} signed manifest references a missing payload: ${entry.path}`);
    assert(payload.length === entry.byte_length && sha256Bytes(payload) === entry.sha256, `${label} payload differs from its signed manifest: ${entry.path}`);
    declared.set(entry.path, entry);
  }
  const payloadPaths = [...files.keys()].filter((name) =>
    name !== MASTER_FRAMEWORK_MANIFEST_ENTRY && name !== MASTER_FRAMEWORK_SIGNATURE_ENTRY).sort();
  assert(
    JSON.stringify([...declared.keys()].sort()) === JSON.stringify(payloadPaths),
    `${label} signed manifest does not exactly enumerate every payload`,
  );
  return declared;
}

async function verifySignedCaseBundle(file, { expectedBasename, expectedVersion, requireCandidateIdentity, label }) {
  const record = await readStableBoundedFile(file, expectedBasename, MAX_MASTER_FRAMEWORK_BUNDLE_BYTES, label);
  const files = parseBoundedTarGz(record.bytes, label);
  const manifestBytes = files.get(MASTER_FRAMEWORK_MANIFEST_ENTRY);
  const signatureBytes = files.get(MASTER_FRAMEWORK_SIGNATURE_ENTRY);
  assert(manifestBytes && signatureBytes, `${label} is missing its manifest or signature envelope`);
  const manifest = decodeUtf8Json(manifestBytes, `${label} manifest`);
  const envelope = decodeUtf8Json(signatureBytes, `${label} signature envelope`);
  assertExactKeys(
    manifest,
    ["schema_version", "product_name", "product_version", "created_at", "case_id", "run_id", "redaction_profile", "demo_data", "schemas", "entries", "raw_artifact_count", "raw_artifacts_included", "signing", "notices"],
    `${label} manifest`,
  );
  assert(manifest.schema_version === "1" && manifest.product_name === "ai-security-scanner", `${label} manifest identity is unsupported`);
  assert(manifest.product_version === expectedVersion, `${label} product version is not ${expectedVersion}`);
  assertRfc3339(manifest.created_at, `${label} creation time`);
  assertString(manifest.case_id, `${label} case ID`, 512);
  assertString(manifest.run_id, `${label} run ID`, 512);
  assert(manifest.redaction_profile === "standard" && manifest.demo_data === true, `${label} is not the bounded standard-redaction synthetic fixture`);
  assert(manifest.schemas && typeof manifest.schemas === "object" && !Array.isArray(manifest.schemas), `${label} schemas are missing`);
  assert(manifest.schemas.bundle === "1", `${label} bundle schema is unsupported`);
  assertBoundedInteger(manifest.raw_artifact_count, 0, 1_000_000, `${label} raw-artifact count`);
  assert(manifest.raw_artifacts_included === 0, `${label} unexpectedly includes raw artifact payloads`);
  assertStringArray(manifest.notices, `${label} notices`, { minimum: 1, maximum: 64, unique: true });
  assertExactKeys(manifest.signing, ["algorithm", "key_id", "signed_file", "integrity_only_notice"], `${label} signing metadata`);
  assertExactKeys(envelope, ["algorithm", "key_id", "public_key_base64", "signature_base64", "signed_file", "integrity_only_notice"], `${label} signature envelope`);
  for (const signed of [manifest.signing, envelope]) {
    assert(signed.algorithm === "Ed25519" && signed.signed_file === MASTER_FRAMEWORK_MANIFEST_ENTRY &&
      signed.integrity_only_notice === BUNDLE_INTEGRITY_ONLY_NOTICE, `${label} signing contract is unsupported or misleading`);
  }
  assert(envelope.key_id === manifest.signing.key_id, `${label} signature key differs from its signed manifest`);
  validatePublicSigningIdentity(envelope.public_key_base64, envelope.key_id, `${label} signer`);
  const signature = decodeCanonicalBase64(envelope.signature_base64, 64, `${label} manifest signature`);
  const publicKey = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(envelope.public_key_base64, "base64")]),
    format: "der",
    type: "spki",
  });
  assert(verify(null, manifestBytes, publicKey, signature), `${label} manifest signature failed independent Node verification`);
  const manifestEntries = verifyManifestPayloads(manifest, files, label);
  let identity = null;
  if (requireCandidateIdentity) {
    assert(manifest.schemas.local_signing_identity === "1", `${label} does not declare the public signing identity schema`);
    const identityBytes = files.get(MASTER_FRAMEWORK_IDENTITY_ENTRY);
    assert(identityBytes, `${label} is missing its embedded public signing identity`);
    identity = decodeUtf8Json(identityBytes, `${label} embedded public signing identity`);
    validateIdentityDocument(identity);
    assert(identity.key_id === envelope.key_id && identity.public_key_base64 === envelope.public_key_base64, `${label} public identity differs from its manifest signer`);
  }
  return { ...record, files, manifest, envelope, manifestEntries, identity };
}

function validateCountMap(value, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(Object.keys(value).length <= 1024, `${label} has too many entries`);
  for (const [key, count] of Object.entries(value)) {
    assertString(key, `${label} key`, 256);
    assertBoundedInteger(count, 0, 1_000_000, `${label}.${key}`);
  }
}

function sumCountMap(value) {
  return Object.values(value).reduce((total, count) => total + count, 0);
}

function validateMappingProvenance(value, state, label) {
  assertExactKeys(
    value,
    ["mapping_version", "reviewed_at", "review_process", "catalog_sha256"],
    label,
  );
  assert(
    typeof value.mapping_version === "string" && /^\d{4}-\d{2}-\d{2}\.[1-9]\d*$/u.test(value.mapping_version),
    `${label} mapping version is malformed`,
  );
  const mappingDate = assertDate(value.mapping_version.slice(0, 10), `${label} mapping-version date`);
  const reviewDate = assertDate(value.reviewed_at, `${label} review date`);
  assert(reviewDate >= mappingDate, `${label} review date predates its mapping version`);
  assert(
    value.review_process === CURRENT_MAPPING_REVIEW_PROCESS,
    `${label} review process is not the recognized source-coordinate review`,
  );
  assertSha256(value.catalog_sha256, `${label} catalog digest`);
  if (state === "verified_current_catalog") {
    assert(
      JSON.stringify(value) === JSON.stringify(CURRENT_MAPPING_PROVENANCE),
      `${label} does not match the exact embedded current catalog`,
    );
  } else {
    assert(
      state === "unverified_historical_catalog" && value.mapping_version !== CURRENT_MAPPING_PROVENANCE.mapping_version,
      `${label} provenance state contradicts the catalog version available to this release`,
    );
  }
}

function validateEvidenceBinding(binding, label) {
  assertExactKeys(
    binding,
    [
      "evidence_id",
      "artifact_id",
      "artifact_sha256",
      "engine_run_id",
      "engine_id",
      "source_rule",
      "engine_mapping_version",
      "engine_mapping_provenance_state",
      "engine_mapping_provenance",
      "mapping_version_state",
    ],
    label,
  );
  assertString(binding.evidence_id, `${label} evidence ID`, 512);
  assertString(binding.artifact_id, `${label} artifact ID`, 512);
  assertSha256(binding.artifact_sha256, `${label} artifact digest`);
  assertString(binding.engine_run_id, `${label} engine-run ID`, 512);
  assertString(binding.engine_id, `${label} engine ID`, 256);
  assertNullableString(binding.source_rule, `${label} source rule`, 512);
  assertNullableString(binding.engine_mapping_version, `${label} engine mapping version`, 128);
  assertEnum(
    binding.engine_mapping_provenance_state,
    ["verified_current_catalog", "unverified_historical_catalog", "unavailable_legacy"],
    `${label} engine mapping provenance state`,
  );
  assertEnum(binding.mapping_version_state, ["exact_match", "mismatch", "unavailable"], `${label} mapping version state`);
  if (binding.engine_mapping_provenance === null) {
    assert(
      binding.engine_mapping_provenance_state === "unavailable_legacy",
      `${label} claims mapping provenance without a complete frozen provenance record`,
    );
  } else {
    assertString(binding.engine_mapping_version, `${label} engine mapping version`, 128);
    assert(
      binding.engine_mapping_version === binding.engine_mapping_provenance.mapping_version,
      `${label} engine mapping version differs from its provenance`,
    );
    validateMappingProvenance(
      binding.engine_mapping_provenance,
      binding.engine_mapping_provenance_state,
      `${label} engine mapping provenance`,
    );
  }
  if (binding.mapping_version_state === "exact_match") {
    assertString(binding.source_rule, `${label} exact-match source rule`, 512);
    assertString(binding.engine_mapping_version, `${label} exact-match engine mapping version`, 128);
    assert(
      binding.engine_mapping_provenance_state === "verified_current_catalog" && binding.engine_mapping_provenance !== null,
      `${label} exact match lacks verified current-catalog provenance`,
    );
    assert(
      binding.engine_mapping_version === binding.engine_mapping_provenance.mapping_version,
      `${label} engine mapping version differs from its provenance`,
    );
  }
}

function validateFrameworkFinding(finding, label) {
  assertExactKeys(
    finding,
    [
      "observation_id",
      "finding_id",
      "fingerprint",
      "title",
      "severity",
      "confidence",
      "observed_at",
      "snapshot_source",
      "evidence_hashes",
      "asset_ids",
      "engine_ids",
    ],
    label,
  );
  for (const [field, maximum] of [
    ["observation_id", 512],
    ["finding_id", 512],
    ["fingerprint", 1024],
    ["title", 4096],
  ]) {
    assertString(finding[field], `${label} ${field}`, maximum);
  }
  assertEnum(finding.severity, ["informational", "low", "medium", "high", "critical"], `${label} severity`);
  assertEnum(finding.confidence, ["low", "medium", "high", "confirmed"], `${label} confidence`);
  assertRfc3339(finding.observed_at, `${label} observed time`);
  assert(finding.snapshot_source === "run_snapshot", `${label} is not bound to an immutable run snapshot`);
  assertStringArray(finding.evidence_hashes, `${label} evidence hashes`, { unique: true, sha256: true });
  assertStringArray(finding.asset_ids, `${label} asset IDs`, { unique: true });
  assertStringArray(finding.engine_ids, `${label} engine IDs`, { unique: true });
}

function sourceRuleMatches(entry, sourceRule) {
  return entry.match_kind === "exact"
    ? sourceRule === entry.source_rule
    : entry.match_kind === "prefix" && sourceRule.startsWith(entry.source_rule);
}

function validateCurrentCatalogRelationship(relationship, contract, control, declaredAiContext, label) {
  const matchingControls = CURRENT_CONTROL_MAPPING_CATALOG.controls.filter((candidate) =>
    candidate.framework === contract.name &&
    candidate.framework_version === control.framework_version &&
    candidate.control_id === control.control_id);
  assert(matchingControls.length === 1, `${label} is not one exact current-catalog coordinate`);
  const catalogControl = matchingControls[0];
  assert(catalogControl.title === control.title, `${label} title differs from the current catalog`);
  if (contract.key === "aidefend") {
    const applicable = catalogControl.aidefend_applicability === "ai_system"
      ? declaredAiContext.ai_system_applicability === "applicable"
      : catalogControl.aidefend_applicability === "ai_generated_artifact" &&
        declaredAiContext.ai_generated_artifact === "yes";
    assert(applicable, `${label} contradicts the current-catalog AIDEFEND applicability condition`);
  }
  for (const binding of relationship.evidence_bindings) {
    assertString(binding.source_rule, `${label} current-catalog source rule`, 512);
    const matches = CURRENT_CONTROL_MAPPING_CATALOG.entries.filter((entry) =>
      entry.engine_id === binding.engine_id &&
      sourceRuleMatches(entry, binding.source_rule) &&
      entry.rationale === relationship.rationale &&
      entry.controls.includes(catalogControl.key));
    assert(matches.length >= 1, `${label} evidence source/rationale does not match the exact current catalog`);
  }
}

function validateFrameworkRelationship(relationship, contract, control, declaredAiContext, label) {
  assertExactKeys(
    relationship,
    [
      "relationship",
      "rationale",
      "mapping_version",
      "mapping_provenance_state",
      "mapping_provenance",
      "mapping_version_state",
      "finding",
      "evidence_bindings",
    ],
    label,
  );
  assert(relationship.relationship === "related", `${label} uses an outcome instead of the bounded 'related' relationship`);
  assertString(relationship.rationale, `${label} rationale`, 2048);
  assertString(relationship.mapping_version, `${label} mapping version`, 128);
  assertEnum(
    relationship.mapping_provenance_state,
    ["verified_current_catalog", "unverified_historical_catalog", "unavailable_legacy"],
    `${label} mapping provenance state`,
  );
  assertEnum(relationship.mapping_version_state, ["exact_match", "mismatch", "unavailable"], `${label} mapping version state`);
  if (relationship.mapping_provenance === null) {
    assert(
      relationship.mapping_provenance_state === "unavailable_legacy",
      `${label} claims mapping provenance without a complete frozen provenance record`,
    );
  } else {
    assert(
      relationship.mapping_version === relationship.mapping_provenance.mapping_version,
      `${label} mapping version differs from its provenance`,
    );
    validateMappingProvenance(
      relationship.mapping_provenance,
      relationship.mapping_provenance_state,
      `${label} mapping provenance`,
    );
  }
  validateFrameworkFinding(relationship.finding, `${label} finding`);
  assert(
    Array.isArray(relationship.evidence_bindings) && relationship.evidence_bindings.length >= 1,
    `${label} has no evidence binding`,
  );
  relationship.evidence_bindings.forEach((binding, index) =>
    validateEvidenceBinding(binding, `${label} evidence binding ${index + 1}`));
  const oneEngineRun = new Set(relationship.evidence_bindings.map((binding) => binding.engine_run_id)).size === 1;
  const expectedBindingStates = relationship.evidence_bindings.map((binding) => {
    if (!oneEngineRun || relationship.mapping_provenance_state !== "verified_current_catalog" ||
        binding.engine_mapping_provenance_state !== "verified_current_catalog") {
      return "unavailable";
    }
    if (binding.engine_mapping_version !== relationship.mapping_version) return "mismatch";
    return JSON.stringify(binding.engine_mapping_provenance) === JSON.stringify(relationship.mapping_provenance)
      ? "exact_match"
      : "mismatch";
  });
  relationship.evidence_bindings.forEach((binding, index) => {
    assert(
      binding.mapping_version_state === expectedBindingStates[index],
      `${label} evidence binding ${index + 1} mapping state is inconsistent`,
    );
  });
  const expectedRelationshipState = expectedBindingStates.includes("mismatch")
    ? "mismatch"
    : expectedBindingStates.includes("unavailable")
      ? "unavailable"
      : "exact_match";
  assert(
    relationship.mapping_version_state === expectedRelationshipState,
    `${label} mapping state is inconsistent with its evidence bindings`,
  );
  if (relationship.mapping_provenance_state === "verified_current_catalog") {
    validateCurrentCatalogRelationship(relationship, contract, control, declaredAiContext, label);
  }
  const boundHashes = new Set(relationship.evidence_bindings.map((binding) => binding.artifact_sha256));
  assert(
    JSON.stringify([...boundHashes].sort()) === JSON.stringify([...relationship.finding.evidence_hashes].sort()),
    `${label} finding evidence hashes differ from its exact bindings`,
  );
  const boundEngines = new Set(relationship.evidence_bindings.map((binding) => binding.engine_id));
  assert(
    JSON.stringify([...boundEngines].sort()) === JSON.stringify([...relationship.finding.engine_ids].sort()),
    `${label} finding engines differ from its exact bindings`,
  );
}

function validateFrameworkSource(source, contract, label) {
  assertExactKeys(
    source,
    ["source_url", "attribution_notice", "license_notice", "modifications_notice", "non_endorsement_notice"],
    label,
  );
  assert(
    JSON.stringify(source) === JSON.stringify(contract.source),
    `${label} differs from the fixed source attribution and non-endorsement contract`,
  );
  for (const field of ["attribution_notice", "license_notice", "modifications_notice", "non_endorsement_notice"]) {
    assertString(source[field], `${label} ${field}`, 4096);
  }
  if (contract.key === "aidefend") {
    assert(/Edward Lee/u.test(source.attribution_notice), "AIDEFEND attribution omits its creator");
    assert(/CC BY 4\.0/u.test(source.attribution_notice), "AIDEFEND attribution omits its license");
    assert(/creativecommons\.org\/licenses\/by\/4\.0/u.test(source.license_notice), "AIDEFEND license URL changed");
  }
}

function validateFrameworkSummary(framework, contract, coverage, declaredAiContext, label) {
  assertExactKeys(
    framework,
    [
      "framework",
      "expected_version",
      "source",
      "observed_versions",
      "version_state",
      "observed_mapping_versions",
      "evidence_engine_mapping_versions",
      "mapping_version_state",
      "exact_match_relationship_count",
      "mismatch_relationship_count",
      "unavailable_relationship_count",
      "state",
      "relationship_count",
      "control_count",
      "finding_count",
      "explanation",
      "controls",
    ],
    label,
  );
  assert(framework.framework === contract.name, `${label} name is incorrect`);
  assert(framework.expected_version === contract.version, `${label} expected version is incorrect`);
  validateFrameworkSource(framework.source, contract, `${label} source`);
  for (const field of ["observed_versions", "observed_mapping_versions", "evidence_engine_mapping_versions"]) {
    assertStringArray(framework[field], `${label} ${field}`, { unique: true });
    assert(
      JSON.stringify(framework[field]) === JSON.stringify([...framework[field]].sort()),
      `${label} ${field} is not deterministically ordered`,
    );
  }
  assertEnum(framework.version_state, ["no_relationship_observed", "expected_version_only", "unexpected_version_observed"], `${label} version state`);
  assertEnum(
    framework.mapping_version_state,
    ["no_relationship_observed", "all_relationships_exact_match", "relationship_mismatch_observed", "relationship_provenance_unavailable"],
    `${label} mapping-version state`,
  );
  assertEnum(
    framework.state,
    [
      "related_coordinates_observed",
      "not_applicable_to_declared_context",
      "unknown_due_to_unanswered_context",
      "unknown_due_to_incomplete_coverage",
      "no_related_coordinate_observed",
    ],
    `${label} state`,
  );
  for (const field of [
    "exact_match_relationship_count",
    "mismatch_relationship_count",
    "unavailable_relationship_count",
    "relationship_count",
    "control_count",
    "finding_count",
  ]) {
    assertBoundedInteger(framework[field], 0, 1_000_000, `${label} ${field}`);
  }
  assertString(framework.explanation, `${label} explanation`, 8192);
  assert(Array.isArray(framework.controls), `${label} controls must be an array`);
  assert(framework.controls.length === framework.control_count, `${label} control count does not match its controls`);
  const relationships = [];
  for (const [controlIndex, control] of framework.controls.entries()) {
    const controlLabel = `${label} control ${controlIndex + 1}`;
    assertExactKeys(control, ["control_id", "title", "framework_version", "relationships"], controlLabel);
    assertString(control.control_id, `${controlLabel} ID`, 160);
    assertString(control.title, `${controlLabel} title`, 256);
    assertString(control.framework_version, `${controlLabel} framework version`, 80);
    assert(Array.isArray(control.relationships) && control.relationships.length >= 1, `${controlLabel} has no relationships`);
    control.relationships.forEach((relationship, relationshipIndex) => {
      validateFrameworkRelationship(
        relationship,
        contract,
        control,
        declaredAiContext,
        `${controlLabel} relationship ${relationshipIndex + 1}`,
      );
      relationships.push(relationship);
    });
  }
  assert(relationships.length === framework.relationship_count, `${label} relationship count does not match its controls`);
  const exact = relationships.filter((item) => item.mapping_version_state === "exact_match").length;
  const mismatch = relationships.filter((item) => item.mapping_version_state === "mismatch").length;
  const unavailable = relationships.filter((item) => item.mapping_version_state === "unavailable").length;
  assert(exact === framework.exact_match_relationship_count, `${label} exact-match relationship count is incorrect`);
  assert(mismatch === framework.mismatch_relationship_count, `${label} mismatch relationship count is incorrect`);
  assert(unavailable === framework.unavailable_relationship_count, `${label} unavailable relationship count is incorrect`);
  assert(
    new Set(relationships.map((item) => item.finding.finding_id)).size === framework.finding_count,
    `${label} finding count is incorrect`,
  );
  const observedVersions = [...new Set(framework.controls.map((control) => control.framework_version))].sort();
  assert(JSON.stringify(observedVersions) === JSON.stringify(framework.observed_versions), `${label} observed versions are incorrect`);
  const observedMappingVersions = [...new Set(relationships.map((relationship) => relationship.mapping_version))].sort();
  assert(
    JSON.stringify(observedMappingVersions) === JSON.stringify(framework.observed_mapping_versions),
    `${label} observed mapping versions are incorrect`,
  );
  const evidenceEngineMappingVersions = [...new Set(
    relationships.flatMap((relationship) =>
      relationship.evidence_bindings
        .map((binding) => binding.engine_mapping_version)
        .filter((version) => version !== null)),
  )].sort();
  assert(
    JSON.stringify(evidenceEngineMappingVersions) === JSON.stringify(framework.evidence_engine_mapping_versions),
    `${label} evidence-engine mapping versions are incorrect`,
  );
  const expectedVersionState = observedVersions.length === 0
    ? "no_relationship_observed"
    : observedVersions.every((version) => version === contract.version)
      ? "expected_version_only"
      : "unexpected_version_observed";
  assert(framework.version_state === expectedVersionState, `${label} version-state summary is incorrect`);
  const expectedMappingState = relationships.length === 0
    ? "no_relationship_observed"
    : mismatch > 0
      ? "relationship_mismatch_observed"
      : unavailable > 0
        ? "relationship_provenance_unavailable"
        : "all_relationships_exact_match";
  assert(framework.mapping_version_state === expectedMappingState, `${label} mapping-state summary is incorrect`);
  const incompleteForEmptyFramework = !coverage.selected_run_checks_complete ||
    coverage.selected_run_coverage_has_unknown_or_incomplete_entries ||
    coverage.selected_run_missing_snapshot_count > 0 ||
    coverage.selected_run_observations_without_evidence_count > 0;
  const expectedState = relationships.length > 0
    ? "related_coordinates_observed"
    : contract.key === "aidefend" && declaredAiContext.aidefend_applicability === "not_applicable"
      ? "not_applicable_to_declared_context"
      : contract.key === "aidefend" && declaredAiContext.aidefend_applicability === "unknown"
        ? "unknown_due_to_unanswered_context"
        : incompleteForEmptyFramework
          ? "unknown_due_to_incomplete_coverage"
          : "no_related_coordinate_observed";
  assert(framework.state === expectedState, `${label} state is inconsistent with its evidence and frozen context`);
  const expectedExplanation = expectedState === "related_coordinates_observed"
    ? "One or more preliminary findings carry an evidence-bound relationship to this framework. The relationship is a navigation aid, not a control result."
    : expectedState === "not_applicable_to_declared_context"
      ? "The frozen answers explicitly identify a non-AI assessment and a non-AI-generated artifact, so AIDEFEND coordinates were not inferred."
      : expectedState === "unknown_due_to_unanswered_context"
        ? "No AIDEFEND coordinate was inferred because at least one required AI-context answer is legacy or unanswered. This remains unknown, not not-applicable."
        : expectedState === "unknown_due_to_incomplete_coverage"
          ? "No related coordinate was observed, but coverage is incomplete or unknown. This cannot be interpreted as a passed or implemented control."
          : "No selected-run finding carried an evidence-bound relationship to this framework. This is not a pass, implementation claim, or compliance conclusion.";
  assert(framework.explanation === expectedExplanation, `${label} explanation differs from the fixed truthful contract`);
}

function validateCoverage(coverage) {
  assertExactKeys(
    coverage,
    [
      "state",
      "selected_run_coverage_ledger_basis",
      "selected_run_checks_complete",
      "selected_run_coverage_ledger_available",
      "selected_run_coverage_has_unknown_or_incomplete_entries",
      "excluded_other_run_coverage_entry_count",
      "excluded_unbound_coverage_entry_count",
      "planned_engine_count",
      "completed_engine_count",
      "unfinished_engine_count",
      "not_executed_engine_count",
      "selected_run_planned_asset_count",
      "selected_run_matched_coverage_entry_count",
      "selected_run_missing_planned_asset_coverage_count",
      "selected_run_unmatched_coverage_entry_count",
      "unknown_source_count",
      "connected_no_asset_count",
      "authorized_incomplete_count",
      "discovered_not_authorized_count",
      "selected_run_finding_count",
      "selected_run_snapshot_count",
      "selected_run_missing_snapshot_count",
      "selected_run_observations_without_evidence_count",
      "engine_states",
      "selected_run_coverage_states",
      "limitations",
    ],
    "master framework report coverage",
  );
  assertEnum(
    coverage.state,
    ["selected_run_checks_complete_with_no_known_coverage_gap", "incomplete_or_unknown"],
    "master framework report coverage state",
  );
  assert(
    coverage.selected_run_coverage_ledger_basis === "selected_run_entries_matching_frozen_planned_assets",
    "master framework report coverage basis changed",
  );
  assert(typeof coverage.selected_run_checks_complete === "boolean", "selected-run completion is not boolean");
  assert(
    typeof coverage.selected_run_coverage_ledger_available === "boolean",
    "selected-run coverage-ledger availability is not boolean",
  );
  assert(
    typeof coverage.selected_run_coverage_has_unknown_or_incomplete_entries === "boolean",
    "selected-run coverage-ledger unknown flag is not boolean",
  );
  const countFields = [
    "excluded_other_run_coverage_entry_count",
    "excluded_unbound_coverage_entry_count",
    "planned_engine_count",
    "completed_engine_count",
    "unfinished_engine_count",
    "not_executed_engine_count",
    "selected_run_planned_asset_count",
    "selected_run_matched_coverage_entry_count",
    "selected_run_missing_planned_asset_coverage_count",
    "selected_run_unmatched_coverage_entry_count",
    "unknown_source_count",
    "connected_no_asset_count",
    "authorized_incomplete_count",
    "discovered_not_authorized_count",
    "selected_run_finding_count",
    "selected_run_snapshot_count",
    "selected_run_missing_snapshot_count",
    "selected_run_observations_without_evidence_count",
  ];
  for (const field of countFields) {
    assertBoundedInteger(coverage[field], 0, 1_000_000, `master framework report coverage ${field}`);
  }
  validateCountMap(coverage.engine_states, "master framework report engine states");
  validateCountMap(coverage.selected_run_coverage_states, "master framework report selected-run coverage states");
  const allowedEngineStates = new Set([
    "not_executed", "queued", "preparing", "running", "paused", "completed",
    "partially_completed", "failed", "cancelled",
  ]);
  const allowedCoverageStates = new Set([
    "discovered_authorized_scanned", "discovered_not_authorized", "authorized_scan_incomplete",
    "source_connected_nothing_discovered", "source_not_connected_unknown", "not_applicable",
  ]);
  assert(Object.keys(coverage.engine_states).every((state) => allowedEngineStates.has(state)), "master framework report has an unknown engine state");
  assert(Object.keys(coverage.selected_run_coverage_states).every((state) => allowedCoverageStates.has(state)), "master framework report has an unknown selected-run coverage state");
  assertStringArray(coverage.limitations, "master framework report limitations", { minimum: 1, maximum: 4096 });
  assert(
    sumCountMap(coverage.engine_states) === coverage.planned_engine_count,
    "master framework report planned-engine count differs from its state ledger",
  );
  assert(
    sumCountMap(coverage.selected_run_coverage_states) === coverage.selected_run_matched_coverage_entry_count,
    "master framework report matched selected-run coverage-entry count differs from its state ledger",
  );
  assert(
    coverage.unfinished_engine_count === coverage.planned_engine_count - coverage.completed_engine_count,
    "master framework report unfinished-engine count is inconsistent",
  );
  assert(
    coverage.not_executed_engine_count <= coverage.unfinished_engine_count,
    "master framework report not-executed count exceeds unfinished checks",
  );
  assert(
    coverage.completed_engine_count === (coverage.engine_states.completed ?? 0) &&
      coverage.not_executed_engine_count === (coverage.engine_states.not_executed ?? 0),
    "master framework report engine summary counts differ from the state ledger",
  );
  assert(
    coverage.unknown_source_count === (coverage.selected_run_coverage_states.source_not_connected_unknown ?? 0) &&
      coverage.connected_no_asset_count === (coverage.selected_run_coverage_states.source_connected_nothing_discovered ?? 0) &&
      coverage.authorized_incomplete_count === (coverage.selected_run_coverage_states.authorized_scan_incomplete ?? 0) &&
      coverage.discovered_not_authorized_count === (coverage.selected_run_coverage_states.discovered_not_authorized ?? 0),
    "master framework report gap counts differ from the selected-run coverage ledger",
  );
  assert(
    coverage.selected_run_coverage_ledger_available === (coverage.selected_run_matched_coverage_entry_count > 0),
    "master framework report selected-run coverage availability is inconsistent",
  );
  assert(
    coverage.selected_run_matched_coverage_entry_count + coverage.selected_run_missing_planned_asset_coverage_count ===
      coverage.selected_run_planned_asset_count,
    "master framework report planned-asset coverage counts are inconsistent",
  );
  const expectedSelectedRunCoverageGap = coverage.selected_run_planned_asset_count === 0 ||
    coverage.selected_run_missing_planned_asset_coverage_count > 0 ||
    coverage.selected_run_unmatched_coverage_entry_count > 0 ||
    coverage.unknown_source_count > 0 || coverage.connected_no_asset_count > 0 ||
    coverage.authorized_incomplete_count > 0 || coverage.discovered_not_authorized_count > 0;
  assert(
    coverage.selected_run_coverage_has_unknown_or_incomplete_entries === expectedSelectedRunCoverageGap,
    "master framework report selected-run coverage gap flag is inconsistent",
  );
  const incompleteReasons = [
    !coverage.selected_run_checks_complete,
    coverage.selected_run_coverage_has_unknown_or_incomplete_entries,
    coverage.unfinished_engine_count > 0,
    coverage.not_executed_engine_count > 0,
    coverage.unknown_source_count > 0,
    coverage.connected_no_asset_count > 0,
    coverage.authorized_incomplete_count > 0,
    coverage.discovered_not_authorized_count > 0,
    coverage.selected_run_missing_snapshot_count > 0,
    coverage.selected_run_observations_without_evidence_count > 0,
  ].some(Boolean);
  assert(
    (coverage.state === "incomplete_or_unknown") === incompleteReasons,
    "master framework report coverage state is not a truthful summary of its gaps",
  );
  return incompleteReasons;
}

function validateDeclaredAiContext(context) {
  assertExactKeys(
    context,
    ["ai_system_applicability", "ai_generated_artifact", "aidefend_applicability", "explanation"],
    "master framework report declared AI context",
  );
  assertEnum(context.ai_system_applicability, ["applicable", "not_applicable", "unknown"], "AI-system applicability");
  assertEnum(context.ai_generated_artifact, ["yes", "no", "unknown"], "AI-generated-artifact answer");
  assertEnum(context.aidefend_applicability, ["applicable", "not_applicable", "unknown"], "AIDEFEND applicability");
  assertString(context.explanation, "declared AI-context explanation", 8192);
  const expected = context.ai_system_applicability === "applicable" || context.ai_generated_artifact === "yes"
    ? "applicable"
    : context.ai_system_applicability === "not_applicable" && context.ai_generated_artifact === "no"
      ? "not_applicable"
      : "unknown";
  assert(context.aidefend_applicability === expected, "AIDEFEND applicability is not derived from the frozen AI answers");
  const expectedExplanation = expected === "applicable"
    ? "At least one frozen answer explicitly identifies an AI system or an AI-generated or materially AI-modified artifact. Evidence-bound AIDEFEND coordinates may therefore appear when their mapping condition is met."
    : expected === "not_applicable"
      ? "The frozen answers explicitly identify a non-AI assessment and a non-AI-generated artifact. AIDEFEND coordinates are not inferred for this run."
      : "At least one required AI-context answer is legacy or unanswered, and no answer explicitly establishes AI applicability. AIDEFEND applicability remains unknown.";
  assert(context.explanation === expectedExplanation, "declared AI-context explanation differs from the fixed truthful contract");
}

function validateObservationProvenance(entry, label) {
  assertExactKeys(
    entry,
    ["observation_id", "finding_id", "fingerprint", "snapshot_state", "evidence_reference_state", "framework_mapping_state"],
    label,
  );
  assertString(entry.observation_id, `${label} observation ID`, 512);
  assertString(entry.finding_id, `${label} finding ID`, 512);
  assertString(entry.fingerprint, `${label} fingerprint`, 1024);
  assertEnum(entry.snapshot_state, ["run_snapshot", "legacy_run_snapshot_missing"], `${label} snapshot state`);
  assertEnum(
    entry.evidence_reference_state,
    ["missing", "validated_from_observation_only", "validated_from_run_snapshot"],
    `${label} evidence-reference state`,
  );
  assertEnum(
    entry.framework_mapping_state,
    ["run_snapshot_relationships_used", "not_exported_without_exact_evidence", "not_exported_without_run_snapshot"],
    `${label} framework-mapping state`,
  );
  if (entry.framework_mapping_state === "run_snapshot_relationships_used") {
    assert(
      entry.snapshot_state === "run_snapshot" && entry.evidence_reference_state === "validated_from_run_snapshot",
      `${label} claims exported relationships without an exact run snapshot and evidence`,
    );
  }
}

function assertNoComplianceOutcomeClaims(report) {
  const encoded = JSON.stringify(report).toLowerCase();
  for (const prohibitedField of [
    "compliance_score",
    "compliance_status",
    "compliance_outcome",
    "audit_result",
    "audit_outcome",
    "certification_status",
    "certification_outcome",
    "control_passed",
    "control_failed",
    "pass_fail",
  ]) {
    assert(!encoded.includes(`\"${prohibitedField}\"`), `master framework report contains prohibited outcome field ${prohibitedField}`);
  }
  const narrative = [
    report.declared_ai_context.explanation,
    ...report.coverage.limitations,
    ...report.frameworks.flatMap((framework) => [
      framework.explanation,
      framework.source.attribution_notice,
      framework.source.license_notice,
      framework.source.modifications_notice,
      framework.source.non_endorsement_notice,
      ...framework.controls.flatMap((control) => [
        control.title,
        ...control.relationships.flatMap((relationship) => [relationship.rationale, relationship.finding.title]),
      ]),
    ]),
  ].join("\n");
  const positiveOutcomeClaims = [
    /\b(?:is|are|was|were|has been|have been)\s+(?:fully\s+)?(?:compliant|certified)\b/iu,
    /\b(?:compliance|audit|certification)\s+(?:score|status|result|outcome)\s*(?::|=|is)\s*(?:\d|pass|fail|compliant|certified)/iu,
    /\b(?:certification|compliance)\s+(?:achieved|granted|confirmed)\b/iu,
  ];
  for (const pattern of positiveOutcomeClaims) {
    assert(!pattern.test(narrative), "master framework report contains a prohibited compliance or certification outcome claim");
  }
}

function validateMasterFrameworkReport(report, reportObservation, currentVersion) {
  assertExactKeys(
    report,
    [
      "schema_version",
      "product_name",
      "product_version",
      "export_kind",
      "case_id",
      "selected_run_id",
      "selected_run_sequence",
      "selected_run_recorded_at",
      "knowledge_date",
      "notice",
      "coverage",
      "declared_ai_context",
      "observation_provenance",
      "frameworks",
      "unrecognized_relationships",
    ],
    "master framework report",
  );
  assert(report.schema_version === "1.2.0", "master framework report schema is not 1.2.0");
  assert(report.product_name === "ai-security-scanner", "master framework report product is incorrect");
  assert(report.product_version === currentVersion, "master framework report product version differs from the installed candidate");
  assert(report.export_kind === "master_framework_relationship_report", "master framework report export kind is incorrect");
  assertString(report.case_id, "master framework report case ID", 512);
  assertString(report.selected_run_id, "master framework report selected-run ID", 512);
  assertBoundedInteger(report.selected_run_sequence, 1, 1_000_000, "master framework report selected-run sequence");
  assertRfc3339(report.selected_run_recorded_at, "master framework report selected-run time");
  assertRfc3339(report.knowledge_date, "master framework report knowledge date");
  assert(report.notice === MASTER_FRAMEWORK_REPORT_NOTICE, "master framework report non-compliance notice changed");
  assert(reportObservation.schemaVersion === report.schema_version, "report observation schema differs from the retained report");
  assert(reportObservation.product === report.product_name, "report observation product differs from the retained report");
  assert(reportObservation.productVersion === report.product_version, "report observation version differs from the retained report");
  assert(reportObservation.caseId === report.case_id, "report observation case differs from the retained report");
  assert(reportObservation.runId === report.selected_run_id, "report observation run differs from the retained report");

  const truthfulUnknownCoverage = validateCoverage(report.coverage);
  assert(truthfulUnknownCoverage, "qualified master framework report does not preserve the fixture's intentionally unknown coverage");
  assertTrue(reportObservation.truthfulUnknownCoverage, "truthful unknown framework coverage");
  validateDeclaredAiContext(report.declared_ai_context);

  assert(Array.isArray(report.observation_provenance), "master framework report observation provenance must be an array");
  report.observation_provenance.forEach((entry, index) =>
    validateObservationProvenance(entry, `master framework report observation provenance ${index + 1}`));
  assert(
    new Set(report.observation_provenance.map((entry) => entry.observation_id)).size === report.observation_provenance.length,
    "master framework report repeats an observation provenance ID",
  );
  assert(
    report.coverage.selected_run_snapshot_count ===
      report.observation_provenance.filter((entry) => entry.snapshot_state === "run_snapshot").length,
    "master framework report selected-run snapshot count differs from provenance",
  );
  assert(
    report.coverage.selected_run_missing_snapshot_count ===
      report.observation_provenance.filter((entry) => entry.snapshot_state === "legacy_run_snapshot_missing").length,
    "master framework report missing-snapshot count differs from provenance",
  );
  assert(
    report.coverage.selected_run_finding_count ===
      new Set(report.observation_provenance.map((entry) => entry.finding_id)).size,
    "master framework report selected-run finding count differs from provenance",
  );
  assert(
    report.coverage.selected_run_observations_without_evidence_count ===
      report.observation_provenance.filter((entry) => entry.evidence_reference_state === "missing").length,
    "master framework report missing-evidence count differs from provenance",
  );

  assert(Array.isArray(report.frameworks) && report.frameworks.length === FRAMEWORK_CONTRACTS.length, "master framework report must contain exactly three frameworks");
  report.frameworks.forEach((framework, index) =>
    validateFrameworkSummary(
      framework,
      FRAMEWORK_CONTRACTS[index],
      report.coverage,
      report.declared_ai_context,
      `master framework report ${FRAMEWORK_CONTRACTS[index].key}`,
    ));
  const provenanceByObservation = new Map(
    report.observation_provenance.map((entry) => [entry.observation_id, entry]),
  );
  for (const relationship of report.frameworks.flatMap((framework) =>
    framework.controls.flatMap((control) => control.relationships))) {
    const provenance = provenanceByObservation.get(relationship.finding.observation_id);
    assert(
      provenance?.finding_id === relationship.finding.finding_id &&
        provenance?.fingerprint === relationship.finding.fingerprint &&
        provenance?.framework_mapping_state === "run_snapshot_relationships_used",
      "master framework relationship is not bound to matching selected-run observation provenance",
    );
  }
  assertExactStringArray(
    reportObservation.frameworkKeys,
    FRAMEWORK_CONTRACTS.map((contract) => contract.key),
    "master framework report framework keys",
  );
  const aidefend = report.frameworks[2];
  if (report.declared_ai_context.aidefend_applicability === "not_applicable") {
    assert(
      aidefend.state === "not_applicable_to_declared_context" && aidefend.relationship_count === 0,
      "AIDEFEND output contradicts the frozen non-AI context",
    );
  }
  if (report.declared_ai_context.aidefend_applicability === "unknown") {
    assert(
      aidefend.state === "unknown_due_to_unanswered_context" && aidefend.relationship_count === 0,
      "AIDEFEND output invents applicability while frozen context is unknown",
    );
  }

  assert(Array.isArray(report.unrecognized_relationships), "master framework report unrecognized relationships must be an array");
  report.unrecognized_relationships.forEach((relationship, index) => {
    const label = `master framework report unrecognized relationship ${index + 1}`;
    assertExactKeys(relationship, ["finding_id", "framework", "framework_version", "control_id"], label);
    for (const field of ["finding_id", "framework", "framework_version", "control_id"]) {
      assertString(relationship[field], `${label} ${field}`, 512);
    }
  });
  assertNoComplianceOutcomeClaims(report);
  assertTrue(reportObservation.noComplianceOutcomeClaims, "absence of compliance outcome claims");
}

async function validateMasterFrameworkReportFile(reportFile, reportObservation, currentVersion) {
  const absolute = path.resolve(reportFile);
  assert(path.basename(absolute) === MASTER_FRAMEWORK_REPORT_FILE, "retained master framework report filename is incorrect");
  const before = await lstat(absolute);
  assert(
    before.isFile() && !before.isSymbolicLink() && before.size >= 1 && before.size <= MAX_MASTER_FRAMEWORK_REPORT_BYTES,
    "retained master framework report is not one bounded regular file",
  );
  const bytes = await readFile(absolute);
  const after = await lstat(absolute);
  assert(
    after.isFile() && !after.isSymbolicLink() &&
      before.dev === after.dev && before.ino === after.ino && before.size === after.size && bytes.length === after.size,
    "retained master framework report changed while it was read",
  );
  const digest = sha256Bytes(bytes);
  assert(reportObservation.reportFile === MASTER_FRAMEWORK_REPORT_FILE, "report observation retained filename is incorrect");
  assert(reportObservation.reportBytes === bytes.length, "report observation byte length differs from the retained report");
  assert(reportObservation.reportSha256 === digest, "report observation digest differs from the retained report");
  assert(reportObservation.bundleEntryPath === MASTER_FRAMEWORK_REPORT_ENTRY, "signed bundle report entry path is incorrect");
  assert(reportObservation.bundleEntryBytes === bytes.length, "signed bundle report entry byte length differs from the retained report");
  assert(reportObservation.bundleEntrySha256 === digest, "signed bundle report entry digest differs from the retained report");
  assertTrue(reportObservation.exactBundleEntryMatch, "standalone report equality with the signed bundle entry");
  let report;
  try {
    report = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("retained master framework report is not valid UTF-8 JSON");
  }
  validateMasterFrameworkReport(report, reportObservation, currentVersion);
  return { absolute, content: bytes, bytes: bytes.length, sha256: digest, report };
}

function jsonEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sortedUniqueStrings(values, label, { sha256 = false } = {}) {
  assertStringArray(values, label, { unique: false, sha256 });
  return [...new Set(values.map((value) => sha256 ? value.toLowerCase() : value))].sort();
}

function requiredBundleJson(bundle, entryPath, label) {
  const bytes = bundle.files.get(entryPath);
  assert(bytes, `${label} is missing signed ${entryPath}`);
  return decodeUtf8Json(bytes, `${label} ${entryPath}`);
}

function derivedMappingProvenanceState(mappingVersion, provenance, label) {
  if (provenance === null || provenance === undefined) return "unavailable_legacy";
  assertString(mappingVersion, `${label} mapping version`, 128);
  assert(mappingVersion === provenance.mapping_version, `${label} mapping version differs from its frozen provenance`);
  const state = provenance.mapping_version === CURRENT_MAPPING_PROVENANCE.mapping_version
    ? "verified_current_catalog"
    : "unverified_historical_catalog";
  validateMappingProvenance(provenance, state, `${label} mapping provenance`);
  return state;
}

function exactCoverageLimitations(run, summary) {
  const limitations = [];
  if (run.engine_runs.length === 0) {
    limitations.push("No scanner checks were recorded for the selected run.");
  }
  if (summary.selected_run_planned_asset_count === 0) {
    limitations.push("The selected run has no frozen planned asset coordinate. Exact selected-run coverage cannot be established and remains unknown.");
  }
  if (summary.selected_run_missing_planned_asset_coverage_count > 0) {
    limitations.push(`${summary.selected_run_missing_planned_asset_coverage_count} frozen planned asset(s) have no unique coverage-ledger entry bound to the selected run. Missing historical coverage remains unknown; entries from later or unbound snapshots were not borrowed.`);
  }
  if (summary.selected_run_unmatched_coverage_entry_count > 0) {
    limitations.push(`${summary.selected_run_unmatched_coverage_entry_count} selected-run-bound coverage-ledger entry or entries do not uniquely match the frozen planned asset coordinates and were excluded from coverage states and counts.`);
  }
  if (summary.unfinished_engine_count > 0) {
    limitations.push(`${summary.unfinished_engine_count} scanner check(s) did not complete; their areas remain unknown.`);
  }
  if (summary.unknown_source_count > 0) {
    limitations.push(`${summary.unknown_source_count} source area(s) had no visibility; this is unknown coverage, not zero assets.`);
  }
  if (summary.authorized_incomplete_count > 0) {
    limitations.push(`${summary.authorized_incomplete_count} authorized area(s) were only partly scanned.`);
  }
  if (summary.discovered_not_authorized_count > 0) {
    limitations.push(`${summary.discovered_not_authorized_count} discovered area(s) were outside the approved scan scope.`);
  }
  if (summary.connected_no_asset_count > 0) {
    limitations.push(`${summary.connected_no_asset_count} connected source(s) returned no assets in the saved snapshot; that does not prove the source has no assets.`);
  }
  if (summary.selected_run_missing_snapshot_count > 0) {
    limitations.push(`${summary.selected_run_missing_snapshot_count} selected-run observation(s) have no immutable finding snapshot. Mutable current finding text and framework mappings were not used to reconstruct them.`);
  }
  if (summary.selected_run_observations_without_evidence_count > 0) {
    limitations.push(`${summary.selected_run_observations_without_evidence_count} selected-run observation(s) have no exact evidence hash reference; their provenance remains incomplete.`);
  }
  if (summary.excluded_other_run_coverage_entry_count > 0) {
    const noun = summary.excluded_other_run_coverage_entry_count === 1 ? "entry" : "entries";
    const verb = summary.excluded_other_run_coverage_entry_count === 1 ? "is" : "are";
    limitations.push(`${summary.excluded_other_run_coverage_entry_count} coverage-ledger ${noun} ${verb} bound to other runs and excluded from selected-run coverage states, counts, and completeness.`);
  }
  if (summary.excluded_unbound_coverage_entry_count > 0) {
    const noun = summary.excluded_unbound_coverage_entry_count === 1 ? "entry" : "entries";
    const verb = summary.excluded_unbound_coverage_entry_count === 1 ? "has" : "have";
    const excludedVerb = summary.excluded_unbound_coverage_entry_count === 1 ? "was" : "were";
    limitations.push(`${summary.excluded_unbound_coverage_entry_count} coverage-ledger ${noun} ${verb} no run ID and ${excludedVerb} excluded from selected-run coverage states, counts, and completeness.`);
  }
  limitations.push("No related finding or framework coordinate is interpreted as a passed control or a complete environment.");
  return limitations;
}

function validateReportAgainstSignedBundle(report, bundle) {
  const observationsDocument = requiredBundleJson(bundle, MASTER_FRAMEWORK_OBSERVATIONS_ENTRY, "candidate signed case bundle");
  const rawArtifactsDocument = requiredBundleJson(bundle, MASTER_FRAMEWORK_RAW_ARTIFACTS_ENTRY, "candidate signed case bundle");
  const scanRunsDocument = requiredBundleJson(bundle, MASTER_FRAMEWORK_SCAN_RUNS_ENTRY, "candidate signed case bundle");
  const coverageDocument = requiredBundleJson(bundle, MASTER_FRAMEWORK_COVERAGE_ENTRY, "candidate signed case bundle");
  assertExactKeys(observationsDocument, ["finding_observations"], "candidate signed observations document");
  assertExactKeys(rawArtifactsDocument, ["raw_artifacts"], "candidate signed raw-artifacts document");
  assertExactKeys(scanRunsDocument, ["scan_runs"], "candidate signed scan-runs document");
  assertExactKeys(coverageDocument, ["coverage"], "candidate signed coverage document");
  for (const [value, label] of [
    [observationsDocument.finding_observations, "candidate signed observations"],
    [rawArtifactsDocument.raw_artifacts, "candidate signed raw artifacts"],
    [scanRunsDocument.scan_runs, "candidate signed scan runs"],
    [coverageDocument.coverage, "candidate signed coverage entries"],
  ]) {
    assert(Array.isArray(value) && value.length <= 100_000, `${label} are malformed or exceed the release bound`);
  }

  const matchingRuns = scanRunsDocument.scan_runs.filter((run) => run?.id === report.selected_run_id);
  assert(matchingRuns.length === 1, "master framework report does not resolve one exact signed scan run");
  const run = matchingRuns[0];
  assert(run.case_id === report.case_id, "signed selected run does not belong to the master framework report case");
  assert(run.case_id === bundle.manifest.case_id && run.id === bundle.manifest.run_id, "signed manifest case/run differs from its canonical scan-run record");
  assert(run.sequence === report.selected_run_sequence, "master framework report sequence differs from the signed selected run");
  assert((run.completed_at ?? run.created_at) === report.selected_run_recorded_at, "master framework report recorded time differs from the signed selected run");
  assert(run.knowledge_cutoff === report.knowledge_date, "master framework report knowledge date differs from the signed selected run");
  assert(Array.isArray(run.engine_runs) && run.engine_runs.length <= 10_000, "signed selected-run engine ledger is malformed or unbounded");
  const enginesById = new Map();
  for (const engine of run.engine_runs) {
    assertString(engine?.id, "signed engine-run ID", 512);
    assert(!enginesById.has(engine.id), `signed selected run repeats engine-run ID ${engine.id}`);
    assert(engine.scan_run_id === run.id, `signed engine run ${engine.id} belongs to a different run`);
    assertString(engine.engine_id, `signed engine run ${engine.id} engine ID`, 256);
    enginesById.set(engine.id, engine);
  }

  const rawArtifactsById = new Map();
  for (const artifact of rawArtifactsDocument.raw_artifacts) {
    assertString(artifact?.id, "signed raw-artifact ID", 512);
    assert(!rawArtifactsById.has(artifact.id), `signed bundle repeats raw-artifact ID ${artifact.id}`);
    assert(artifact.case_id === report.case_id, `signed raw artifact ${artifact.id} belongs to a different case`);
    assertSha256(artifact.sha256, `signed raw artifact ${artifact.id} digest`);
    rawArtifactsById.set(artifact.id, artifact);
  }

  const selectedObservations = observationsDocument.finding_observations
    .filter((observation) => observation?.run_id === run.id)
    .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint) || left.id.localeCompare(right.id));
  const observationsById = new Map();
  const evidenceOwners = new Map();
  const expectedProvenance = [];
  const expectedRelationships = new Map();
  const expectedUnrecognized = new Set();
  let missingSnapshots = 0;
  let observationsWithoutEvidence = 0;
  for (const observation of selectedObservations) {
    assertString(observation?.id, "signed observation ID", 512);
    assert(!observationsById.has(observation.id), `signed bundle repeats observation ID ${observation.id}`);
    assertString(observation.finding_id, `signed observation ${observation.id} finding ID`, 512);
    assertString(observation.fingerprint, `signed observation ${observation.id} fingerprint`, 1024);
    assertRfc3339(observation.observed_at, `signed observation ${observation.id} observed time`);
    const observationAssets = sortedUniqueStrings(observation.asset_ids, `signed observation ${observation.id} asset IDs`);
    const observationEngines = sortedUniqueStrings(observation.engine_ids, `signed observation ${observation.id} engine IDs`);
    const observationHashes = sortedUniqueStrings(observation.evidence_hashes, `signed observation ${observation.id} evidence hashes`, { sha256: true });
    for (const engineId of observationEngines) {
      assert([...enginesById.values()].some((engine) => engine.engine_id === engineId), `signed observation ${observation.id} names an engine absent from the selected run`);
    }
    observationsById.set(observation.id, observation);
    const snapshot = observation.finding_snapshot;
    if (snapshot === null || snapshot === undefined) {
      missingSnapshots += 1;
      if (observationHashes.length === 0) observationsWithoutEvidence += 1;
      for (const digest of observationHashes) {
        const matches = [...rawArtifactsById.values()].filter((artifact) =>
          artifact.sha256.toLowerCase() === digest &&
          observationEngines.includes(enginesById.get(artifact.engine_run_id).engine_id));
        assert(matches.length === 1, `signed legacy observation ${observation.id} evidence does not resolve one exact artifact and engine`);
      }
      expectedProvenance.push({
        observation_id: observation.id,
        finding_id: observation.finding_id,
        fingerprint: observation.fingerprint,
        snapshot_state: "legacy_run_snapshot_missing",
        evidence_reference_state: observationHashes.length === 0 ? "missing" : "validated_from_observation_only",
        framework_mapping_state: "not_exported_without_run_snapshot",
      });
      continue;
    }
    assert(snapshot.case_id === report.case_id && snapshot.id === observation.finding_id &&
      snapshot.fingerprint === observation.fingerprint && snapshot.last_seen_run_id === run.id,
    `signed observation ${observation.id} differs from its immutable finding snapshot identity`);
    assert(snapshot.severity === observation.severity && snapshot.confidence === observation.confidence,
      `signed observation ${observation.id} differs from its immutable finding snapshot severity or confidence`);
    assert(jsonEqual(sortedUniqueStrings(snapshot.asset_ids, `signed snapshot ${snapshot.id} asset IDs`), observationAssets),
      `signed observation ${observation.id} asset IDs differ from its immutable finding snapshot`);
    assert(Array.isArray(snapshot.evidence), `signed snapshot ${snapshot.id} has no evidence array`);
    const bindings = [];
    const snapshotHashes = [];
    const snapshotEngines = [];
    for (const evidence of snapshot.evidence) {
      assertString(evidence?.id, `signed snapshot ${snapshot.id} evidence ID`, 512);
      assert(!evidenceOwners.has(evidence.id), `signed selected-run snapshots reuse evidence ID ${evidence.id}`);
      evidenceOwners.set(evidence.id, { observationId: observation.id, findingId: snapshot.id });
      const artifact = rawArtifactsById.get(evidence.artifact_id);
      assert(artifact, `signed evidence ${evidence.id} does not resolve one exact raw artifact`);
      const engine = enginesById.get(artifact.engine_run_id);
      assert(engine && artifact.run_id === run.id, `signed evidence ${evidence.id} raw artifact does not resolve a selected-run engine`);
      assert(evidence.finding_id === snapshot.id && evidence.run_id === run.id &&
        evidence.artifact_sha256?.toLowerCase() === artifact.sha256.toLowerCase() &&
        evidence.engine_id === engine.engine_id &&
        (evidence.engine_run_id === null || evidence.engine_run_id === undefined || evidence.engine_run_id === engine.id),
      `signed evidence ${evidence.id} differs from its finding, artifact, run, or engine provenance`);
      const engineMappingVersion = engine.mapping_version ?? null;
      const engineMappingProvenance = engine.mapping_provenance ?? null;
      const engineMappingProvenanceState = derivedMappingProvenanceState(
        engineMappingVersion,
        engineMappingProvenance,
        `signed engine run ${engine.id}`,
      );
      snapshotHashes.push(artifact.sha256.toLowerCase());
      snapshotEngines.push(engine.engine_id);
      bindings.push({
        evidence_id: evidence.id,
        artifact_id: artifact.id,
        artifact_sha256: artifact.sha256.toLowerCase(),
        engine_run_id: engine.id,
        engine_id: engine.engine_id,
        source_rule: evidence.source_rule ?? null,
        engine_mapping_version: engineMappingVersion,
        engine_mapping_provenance_state: engineMappingProvenanceState,
        engine_mapping_provenance: engineMappingProvenance,
      });
    }
    bindings.sort((left, right) => left.engine_run_id.localeCompare(right.engine_run_id) ||
      left.artifact_id.localeCompare(right.artifact_id) || left.artifact_sha256.localeCompare(right.artifact_sha256) ||
      left.evidence_id.localeCompare(right.evidence_id));
    const exactSnapshotHashes = [...new Set(snapshotHashes)].sort();
    const exactSnapshotEngines = [...new Set(snapshotEngines)].sort();
    assert(jsonEqual(exactSnapshotHashes, observationHashes) && jsonEqual(exactSnapshotEngines, observationEngines),
      `signed observation ${observation.id} evidence hashes or engines differ from its immutable finding snapshot`);
    if ((bindings.length === 0) !== (observationHashes.length === 0)) {
      throw new Error(`signed observation ${observation.id} has inconsistent immutable evidence references`);
    }
    if (bindings.length === 0) observationsWithoutEvidence += 1;
    expectedProvenance.push({
      observation_id: observation.id,
      finding_id: observation.finding_id,
      fingerprint: observation.fingerprint,
      snapshot_state: "run_snapshot",
      evidence_reference_state: bindings.length === 0 ? "missing" : "validated_from_run_snapshot",
      framework_mapping_state: bindings.length === 0 ? "not_exported_without_exact_evidence" : "run_snapshot_relationships_used",
    });
    if (bindings.length === 0) continue;
    assert(Array.isArray(snapshot.control_references), `signed snapshot ${snapshot.id} has no control-reference array`);
    for (const reference of snapshot.control_references) {
      const contract = FRAMEWORK_CONTRACTS.find((candidate) => candidate.name === reference.framework);
      if (!contract) {
        expectedUnrecognized.add(JSON.stringify({
          finding_id: snapshot.id,
          framework: reference.framework,
          framework_version: reference.framework_version,
          control_id: reference.control_id,
        }));
        continue;
      }
      const key = JSON.stringify([observation.id, reference.framework, reference.framework_version, reference.control_id,
        reference.title, reference.relationship, reference.rationale, reference.mapping_version, reference.mapping_provenance ?? null]);
      expectedRelationships.set(key, { observation, snapshot, reference, bindings, observationAssets, observationEngines, observationHashes });
    }
  }
  assert(jsonEqual(report.observation_provenance, expectedProvenance), "master framework report provenance ledger differs from the signed observations and immutable snapshots");

  const actualRelationships = new Map();
  for (const framework of report.frameworks) {
    for (const control of framework.controls) {
      for (const relationship of control.relationships) {
        const key = JSON.stringify([relationship.finding.observation_id, framework.framework, control.framework_version,
          control.control_id, control.title, relationship.relationship, relationship.rationale, relationship.mapping_version,
          relationship.mapping_provenance]);
        assert(!actualRelationships.has(key), "master framework report repeats an evidence-bound relationship");
        actualRelationships.set(key, relationship);
      }
    }
  }
  assert(jsonEqual([...actualRelationships.keys()].sort(), [...expectedRelationships.keys()].sort()),
    "master framework report relationship set differs from immutable signed finding snapshots");
  for (const [key, expected] of expectedRelationships) {
    const relationship = actualRelationships.get(key);
    const expectedFinding = {
      observation_id: expected.observation.id,
      finding_id: expected.snapshot.id,
      fingerprint: expected.observation.fingerprint,
      title: expected.snapshot.title,
      severity: expected.observation.severity,
      confidence: expected.observation.confidence,
      observed_at: expected.observation.observed_at,
      snapshot_source: "run_snapshot",
      evidence_hashes: expected.observationHashes,
      asset_ids: expected.observationAssets,
      engine_ids: expected.observationEngines,
    };
    assert(jsonEqual(relationship.finding, expectedFinding), "master framework relationship finding differs from its signed immutable snapshot");
    assert(relationship.evidence_bindings.length === expected.bindings.length, "master framework relationship omits or invents signed evidence bindings");
    relationship.evidence_bindings.forEach((binding, index) => {
      const signed = expected.bindings[index];
      for (const field of Object.keys(signed)) {
        assert(jsonEqual(binding[field], signed[field]), `master framework evidence binding ${binding.evidence_id} differs from signed ${field}`);
      }
    });
  }
  assert(jsonEqual(report.unrecognized_relationships.map((value) => JSON.stringify(value)).sort(), [...expectedUnrecognized].sort()),
    "master framework unrecognized relationship ledger differs from signed finding snapshots");

  const engineStates = {};
  for (const engine of run.engine_runs) engineStates[engine.status] = (engineStates[engine.status] ?? 0) + 1;
  const selectedRunPlannedAssets = new Set([
    ...(run.scope_grant_snapshots ?? [])
      .filter((grant) => (run.scope_grant_ids ?? []).includes(grant.id))
      .map((grant) => grant.asset_id),
    ...run.engine_runs.flatMap((engine) => engine.asset_ids ?? []),
  ].filter((assetId) => typeof assetId === "string" && assetId.length > 0));
  const selectedRunBoundCoverage = coverageDocument.coverage.filter((entry) => entry.last_run_id === run.id);
  const selectedRunCoverage = [];
  for (const assetId of [...selectedRunPlannedAssets].sort()) {
    const matches = selectedRunBoundCoverage.filter((entry) =>
      entry.asset_id === assetId && entry.scope_key === `asset:${assetId}`);
    if (matches.length === 1) selectedRunCoverage.push(matches[0]);
  }
  const selectedRunCoverageStates = {};
  for (const entry of selectedRunCoverage) {
    selectedRunCoverageStates[entry.status] = (selectedRunCoverageStates[entry.status] ?? 0) + 1;
  }
  const completedEngines = engineStates.completed ?? 0;
  const unfinishedEngines = run.engine_runs.length - completedEngines;
  const coverageSummary = {
    excluded_other_run_coverage_entry_count: coverageDocument.coverage.filter((entry) =>
      entry.last_run_id !== null && entry.last_run_id !== undefined && entry.last_run_id !== run.id).length,
    excluded_unbound_coverage_entry_count: coverageDocument.coverage.filter((entry) =>
      entry.last_run_id === null || entry.last_run_id === undefined).length,
    planned_engine_count: run.engine_runs.length,
    completed_engine_count: completedEngines,
    unfinished_engine_count: unfinishedEngines,
    not_executed_engine_count: engineStates.not_executed ?? 0,
    selected_run_planned_asset_count: selectedRunPlannedAssets.size,
    selected_run_matched_coverage_entry_count: selectedRunCoverage.length,
    selected_run_missing_planned_asset_coverage_count: selectedRunPlannedAssets.size - selectedRunCoverage.length,
    selected_run_unmatched_coverage_entry_count: selectedRunBoundCoverage.length - selectedRunCoverage.length,
    unknown_source_count: selectedRunCoverageStates.source_not_connected_unknown ?? 0,
    connected_no_asset_count: selectedRunCoverageStates.source_connected_nothing_discovered ?? 0,
    authorized_incomplete_count: selectedRunCoverageStates.authorized_scan_incomplete ?? 0,
    discovered_not_authorized_count: selectedRunCoverageStates.discovered_not_authorized ?? 0,
    selected_run_finding_count: new Set(selectedObservations.map((observation) => observation.finding_id)).size,
    selected_run_snapshot_count: selectedObservations.length - missingSnapshots,
    selected_run_missing_snapshot_count: missingSnapshots,
    selected_run_observations_without_evidence_count: observationsWithoutEvidence,
  };
  const selectedRunChecksComplete = run.completed_at !== null && run.completed_at !== undefined &&
    run.engine_runs.length > 0 && unfinishedEngines === 0;
  const selectedRunCoverageGap = selectedRunPlannedAssets.size === 0 ||
    coverageSummary.selected_run_missing_planned_asset_coverage_count > 0 ||
    coverageSummary.selected_run_unmatched_coverage_entry_count > 0 ||
    coverageSummary.unknown_source_count > 0 ||
    coverageSummary.connected_no_asset_count > 0 || coverageSummary.authorized_incomplete_count > 0 ||
    coverageSummary.discovered_not_authorized_count > 0;
  for (const [field, expected] of Object.entries(coverageSummary)) {
    assert(report.coverage[field] === expected, `master framework coverage ${field} differs from the signed run or coverage ledger`);
  }
  assert(report.coverage.selected_run_checks_complete === selectedRunChecksComplete,
    "master framework selected-run completion differs from the signed engine ledger");
  assert(report.coverage.selected_run_coverage_ledger_available === (selectedRunCoverage.length > 0),
    "master framework selected-run coverage availability differs from signed coverage");
  assert(report.coverage.selected_run_coverage_has_unknown_or_incomplete_entries === selectedRunCoverageGap,
    "master framework selected-run coverage gap flag differs from signed coverage");
  assert(jsonEqual(report.coverage.engine_states, Object.fromEntries(Object.entries(engineStates).sort())),
    "master framework engine-state counts differ from the signed engine ledger");
  assert(jsonEqual(report.coverage.selected_run_coverage_states, Object.fromEntries(Object.entries(selectedRunCoverageStates).sort())),
    "master framework coverage-state counts differ from selected-run entries that uniquely match the frozen planned assets");
  assert(jsonEqual(report.coverage.limitations, exactCoverageLimitations(run, coverageSummary)),
    "master framework limitations differ from the exact signed coverage limitations");

  const frozenAiSystem = (run.ai_system_applicability ?? "unknown") === "unknown" && run.ai_system_applicable === true
    ? "applicable"
    : (run.ai_system_applicability ?? "unknown");
  const frozenAiArtifact = run.ai_generated_artifact ?? "unknown";
  const aidefend = frozenAiSystem === "applicable" || frozenAiArtifact === "yes"
    ? "applicable"
    : frozenAiSystem === "not_applicable" && frozenAiArtifact === "no"
      ? "not_applicable"
      : "unknown";
  assert(report.declared_ai_context.ai_system_applicability === frozenAiSystem &&
    report.declared_ai_context.ai_generated_artifact === frozenAiArtifact &&
    report.declared_ai_context.aidefend_applicability === aidefend,
  "master framework AI context differs from the frozen signed scan-run answers");
}

async function validateMasterFrameworkArtifacts(
  reportFile,
  bundleFile,
  priorBundleFile,
  reportObservation,
  dataPreservation,
  currentVersion,
) {
  const reportRecord = await validateMasterFrameworkReportFile(reportFile, reportObservation, currentVersion);
  const candidate = await verifySignedCaseBundle(bundleFile, {
    expectedBasename: MASTER_FRAMEWORK_SIGNED_CASE_BUNDLE,
    expectedVersion: currentVersion,
    requireCandidateIdentity: true,
    label: "candidate signed case bundle",
  });
  const prior = await verifySignedCaseBundle(priorBundleFile, {
    expectedBasename: N_MINUS_ONE_SIGNED_CASE_BUNDLE,
    expectedVersion: PRIOR_WINDOWS_NSIS.version,
    requireCandidateIdentity: false,
    label: "N-1 signed case bundle",
  });
  assert(candidate.manifest.case_id === reportRecord.report.case_id &&
    candidate.manifest.run_id === reportRecord.report.selected_run_id,
  "candidate signed case bundle case/run differs from the retained master framework report");
  assert(prior.manifest.case_id === candidate.manifest.case_id && prior.manifest.run_id === candidate.manifest.run_id,
    "N-1 and candidate signed case bundles do not preserve the same synthetic case/run");
  assert(prior.envelope.key_id === candidate.envelope.key_id &&
    prior.envelope.public_key_base64 === candidate.envelope.public_key_base64,
  "N-1 and candidate signed case bundles do not prove the same integrity-signing identity");
  assert(candidate.manifest.schemas.master_framework_report === "1.2.0",
    "candidate signed case bundle does not declare master framework report schema 1.2.0");
  const reportEntry = candidate.manifestEntries.get(MASTER_FRAMEWORK_REPORT_ENTRY);
  assert(reportEntry?.media_type === "application/json" && reportEntry.contains_sensitive_data === true,
    "candidate signed report entry metadata is incorrect");
  const bundleReportBytes = candidate.files.get(MASTER_FRAMEWORK_REPORT_ENTRY);
  assert(bundleReportBytes?.equals(reportRecord.content),
    "retained master framework report bytes differ from the independently verified signed bundle entry");
  assert(candidate.identity.key_id === dataPreservation.signingKeyIdAfter &&
    candidate.identity.public_key_base64 === dataPreservation.publicKeyBase64After,
  "candidate embedded public signing identity differs from the installed-upgrade observations");
  assert(prior.envelope.key_id === dataPreservation.signingKeyIdBefore &&
    prior.envelope.public_key_base64 === dataPreservation.publicKeyBase64Before,
  "N-1 bundle signer differs from the pre-upgrade signing identity observation");
  assert(jsonEqual(canonicalIdentityDocument(candidate.identity), canonicalIdentityDocument(dataPreservation.identityDocument)),
    "candidate signed bundle identity document differs from the durable identity observed after upgrade");
  validateReportAgainstSignedBundle(reportRecord.report, candidate);
  return { report: reportRecord, candidate, prior };
}

function validateObservations(observations, currentVersion, currentInstaller) {
  assertExactKeys(
    observations,
    [
      "schemaVersion",
      "scenario",
      "platform",
      "runner",
      "priorRelease",
      "candidate",
      "installation",
      "dataPreservation",
      "masterFrameworkReport",
      "managedRuntimeFilesystemSentinel",
      "cleanup",
    ],
    "Windows NSIS upgrade observations",
  );
  assert(observations.schemaVersion === SCHEMA_VERSION, "Windows NSIS upgrade observation schema is unsupported");
  assert(observations.scenario === "real_n_minus_one_nsis_upgrade", "Windows NSIS upgrade scenario is not real N-1 installation");
  assert(observations.platform === PLATFORM, "Windows NSIS upgrade platform is incorrect");
  assert(observations.runner === RUNNER, "Windows NSIS upgrade runner is incorrect");

  assertExactKeys(
    observations.priorRelease,
    [
      "version",
      "tag",
      "installerFile",
      "installerBytes",
      "installerSha256",
      "downloadUrl",
      "runtimeManifestSha256",
      "machineImageSha256",
    ],
    "prior release observation",
  );
  const prior = observations.priorRelease;
  assert(prior.version === PRIOR_WINDOWS_NSIS.version, "prior release version is not the pinned N-1");
  assert(prior.tag === PRIOR_WINDOWS_NSIS.tag, "prior release tag is not the pinned N-1");
  assert(prior.installerFile === PRIOR_WINDOWS_NSIS.file, "prior installer filename is not pinned");
  assert(prior.installerBytes === PRIOR_WINDOWS_NSIS.bytes, "prior installer byte length is not pinned");
  assert(prior.installerSha256 === PRIOR_WINDOWS_NSIS.sha256, "prior installer digest is not pinned");
  assert(prior.downloadUrl === PRIOR_WINDOWS_NSIS.url, "prior installer URL is not pinned");
  assert(
    prior.runtimeManifestSha256 === PRIOR_WINDOWS_NSIS.runtimeManifestSha256,
    "prior managed-runtime manifest digest is not pinned",
  );
  assert(
    prior.machineImageSha256 === PRIOR_WINDOWS_NSIS.machineImageSha256,
    "prior managed-runtime machine-image digest is not pinned",
  );

  assertExactKeys(
    observations.candidate,
    ["version", "installerFile", "installerBytes", "installerSha256"],
    "candidate observation",
  );
  assert(observations.candidate.version === currentVersion, "installed candidate version is incorrect");
  assert(observations.candidate.installerFile === currentInstaller.file, "candidate filename differs from its release manifest");
  assert(observations.candidate.installerBytes === currentInstaller.bytes, "candidate byte length differs from its release manifest");
  assert(observations.candidate.installerSha256 === currentInstaller.sha256, "candidate digest differs from its release manifest");

  assertExactKeys(
    observations.installation,
    [
      "priorCliVersion",
      "candidateCliVersion",
      "sameCanonicalInstallDirectory",
      "registryHive",
      "registryEntryIdentityPreserved",
      "displayVersionUpdated",
      "uninstallerReplaced",
      "unattendedMode",
      "sameVersionSilentReinstallCompleted",
      "transitionReceiptSurvivedSameVersionReinstall",
      "transitionReceipt",
    ],
    "installation observation",
  );
  assert(observations.installation.priorCliVersion === PRIOR_WINDOWS_NSIS.version, "prior CLI was not N-1");
  assert(observations.installation.candidateCliVersion === currentVersion, "candidate CLI version is incorrect");
  assertTrue(observations.installation.sameCanonicalInstallDirectory, "same canonical install directory");
  assert(observations.installation.registryHive === "HKEY_CURRENT_USER", "NSIS upgrade did not use the current-user registry hive");
  assertTrue(observations.installation.registryEntryIdentityPreserved, "registry entry identity preservation");
  assertTrue(observations.installation.displayVersionUpdated, "registry DisplayVersion update");
  assertTrue(observations.installation.uninstallerReplaced, "candidate uninstaller replacement");
  assert(observations.installation.unattendedMode === "silent", "normal N-1 upgrade did not exercise /S");
  assertTrue(observations.installation.sameVersionSilentReinstallCompleted, "same-version silent reinstall");
  assertTrue(
    observations.installation.transitionReceiptSurvivedSameVersionReinstall,
    "transition receipt survival across same-version reinstall",
  );
  assert(
    observations.installation.transitionReceipt === `overlaid-${PRIOR_WINDOWS_NSIS.version}`,
    "normal NSIS upgrade did not record the reviewed data-preserving N-1 overlay",
  );

  const data = observations.dataPreservation;
  assertExactKeys(
    data,
    [
      "defaultLocalDataDirectoryUsed",
      "preInstallerFileCount",
      "preInstallerBytes",
      "exactPreInstallerSnapshotPreserved",
      "sentinelPreserved",
      "demoCaseId",
      "demoCasePreserved",
      "privateSigningMaterialBytePreserved",
      "signingKeyIdBefore",
      "signingKeyIdAfter",
      "publicKeyBase64Before",
      "publicKeyBase64After",
      "privateSigningKeyProtected",
      "publicIdentitySummaryExact",
      "durableIdentityDocumentPresent",
      "identityDocumentBytes",
      "identityDocumentCompactSha256",
      "identityDocument",
      "identityDocumentProtected",
      "durableIdentityAnchorPresent",
      "identityAnchorBytes",
      "identityAnchorProtected",
      "anchorSchemaVersion",
      "anchorIdentityDocumentSha256",
      "anchorDigestVerified",
      "anchorMatchesIdentityDocument",
      "identitySelfSignatureVerifiedByCandidate",
      "rotationIntentAbsent",
      "continuityEvent",
      "identityKeyId",
      "identityPublicKeyBase64",
      "firstBundleValid",
      "secondBundleValid",
    ],
    "data-preservation observation",
  );
  assertTrue(data.defaultLocalDataDirectoryUsed, "default LocalAppData directory use");
  assertBoundedInteger(data.preInstallerFileCount, 4, 4096, "pre-installer file count");
  assertBoundedInteger(data.preInstallerBytes, 1, 512 * 1024 * 1024, "pre-installer byte count");
  assertTrue(data.exactPreInstallerSnapshotPreserved, "pre-installer byte snapshot preservation");
  assertTrue(data.sentinelPreserved, "local sentinel preservation");
  assert(
    typeof data.demoCaseId === "string" && /^[0-9a-f]{8}-[0-9a-f-]{27,}$/u.test(data.demoCaseId),
    "synthetic case ID is malformed",
  );
  assertTrue(data.demoCasePreserved, "synthetic case preservation");
  assertTrue(data.privateSigningMaterialBytePreserved, "private signing material byte preservation");
  assertTrue(data.privateSigningKeyProtected, "managed signing key protection");
  assertTrue(data.publicIdentitySummaryExact, "public signing identity summary contract");
  assertTrue(data.durableIdentityDocumentPresent, "durable signing identity document");
  assertBoundedInteger(data.identityDocumentBytes, 1, 64 * 1024, "durable signing identity document bytes");
  assertSha256(data.identityDocumentCompactSha256, "durable signing identity document compact digest");
  const independentlyVerifiedIdentity = validateIdentityDocument(data.identityDocument);
  assert(
    independentlyVerifiedIdentity.compactSha256 === data.identityDocumentCompactSha256,
    "durable signing identity document digest failed independent recomputation",
  );
  assert(
    independentlyVerifiedIdentity.compactBytes.length <= data.identityDocumentBytes,
    "durable signing identity document byte claim is smaller than its compact representation",
  );
  assertTrue(data.identityDocumentProtected, "durable signing identity document protection");
  assertTrue(data.durableIdentityAnchorPresent, "durable signing identity anchor");
  assertBoundedInteger(data.identityAnchorBytes, 1, 64 * 1024, "durable signing identity anchor bytes");
  assertTrue(data.identityAnchorProtected, "durable signing identity anchor protection");
  assert(data.anchorSchemaVersion === "1", "durable signing identity anchor schema is not v1");
  assertSha256(data.anchorIdentityDocumentSha256, "durable signing identity anchor digest");
  assert(
    data.anchorIdentityDocumentSha256 === data.identityDocumentCompactSha256,
    "durable signing identity anchor digest differs from the identity document",
  );
  assertTrue(data.anchorDigestVerified, "durable signing identity anchor digest verification");
  assertTrue(data.anchorMatchesIdentityDocument, "durable signing identity anchor/document equality");
  assertTrue(data.identitySelfSignatureVerifiedByCandidate, "durable signing identity self-signature verification");
  assertTrue(data.rotationIntentAbsent, "completed signing identity adoption rotation-intent cleanup");
  assert(data.continuityEvent === "legacy_key_adopted", "candidate did not record legacy-key adoption");
  assertTrue(data.firstBundleValid, "N-1 signed bundle verification");
  assertTrue(data.secondBundleValid, "candidate signed bundle verification");
  validatePublicSigningIdentity(data.publicKeyBase64Before, data.signingKeyIdBefore, "N-1 signing identity");
  validatePublicSigningIdentity(data.publicKeyBase64After, data.signingKeyIdAfter, "candidate signing identity");
  assert(data.signingKeyIdAfter === data.signingKeyIdBefore, "integrity signing key ID changed during NSIS upgrade");
  assert(data.publicKeyBase64After === data.publicKeyBase64Before, "integrity signing public key changed during NSIS upgrade");
  assert(data.identityKeyId === data.signingKeyIdBefore, "durable identity key ID differs from both bundles");
  assert(
    data.identityPublicKeyBase64 === data.publicKeyBase64Before,
    "durable identity public key differs from both bundles",
  );
  assert(data.identityDocument.continuity_event === data.continuityEvent, "public identity document continuity event differs from its summary");
  assert(data.identityDocument.key_id === data.identityKeyId, "public identity document key ID differs from its summary and bundles");
  assert(
    data.identityDocument.public_key_base64 === data.identityPublicKeyBase64,
    "public identity document public key differs from its summary and bundles",
  );

  const report = observations.masterFrameworkReport;
  assertExactKeys(
    report,
    [
      "reportFile",
      "reportBytes",
      "reportSha256",
      "bundleEntryPath",
      "bundleEntryBytes",
      "bundleEntrySha256",
      "exactBundleEntryMatch",
      "schemaVersion",
      "product",
      "productVersion",
      "caseId",
      "runId",
      "frameworkKeys",
      "truthfulUnknownCoverage",
      "noComplianceOutcomeClaims",
    ],
    "master framework report observation",
  );
  assert(report.reportFile === MASTER_FRAMEWORK_REPORT_FILE, "retained master framework report filename is incorrect");
  assertBoundedInteger(report.reportBytes, 1, MAX_MASTER_FRAMEWORK_REPORT_BYTES, "retained master framework report bytes");
  assertSha256(report.reportSha256, "retained master framework report digest");
  assert(report.bundleEntryPath === MASTER_FRAMEWORK_REPORT_ENTRY, "signed bundle master framework report entry path is incorrect");
  assertBoundedInteger(report.bundleEntryBytes, 1, MAX_MASTER_FRAMEWORK_REPORT_BYTES, "signed bundle framework report bytes");
  assertSha256(report.bundleEntrySha256, "signed bundle framework report digest");
  assertTrue(report.exactBundleEntryMatch, "standalone report equality with signed bundle entry");
  assert(report.reportBytes === report.bundleEntryBytes, "standalone and signed-bundle report byte lengths differ");
  assert(report.reportSha256 === report.bundleEntrySha256, "standalone and signed-bundle report digests differ");
  assert(report.schemaVersion === "1.2.0", "master framework report observation schema is not 1.2.0");
  assert(report.product === "ai-security-scanner", "master framework report observation product is incorrect");
  assert(report.productVersion === currentVersion, "master framework report observation version differs from the candidate");
  assertString(report.caseId, "master framework report observation case ID", 512);
  assert(report.caseId === data.demoCaseId, "master framework report is not for the preserved synthetic case");
  assertString(report.runId, "master framework report observation run ID", 512);
  assertExactStringArray(report.frameworkKeys, FRAMEWORK_CONTRACTS.map((contract) => contract.key), "master framework report framework keys");
  assertTrue(report.truthfulUnknownCoverage, "truthful unknown framework coverage");
  assertTrue(report.noComplianceOutcomeClaims, "absence of framework compliance outcome claims");

  const ghost = observations.managedRuntimeFilesystemSentinel;
  assertExactKeys(
    ghost,
    [
      "priorProviderNamespace",
      "priorVersionDirectory",
      "priorVersionPayloadDirectoryAbsentBeforeUpgrade",
      "priorVersionPayloadDirectoryAbsentAfterInstaller",
      "providerHomeSentinelPreserved",
      "registeredWslStateExercised",
    ],
    "managed-runtime ghost observation",
  );
  assert(
    ghost.priorProviderNamespace === PRIOR_WINDOWS_NSIS.runtimeManifestSha256.slice(0, 16),
    "managed-runtime sentinel provider namespace is not N-1",
  );
  assert(
    ghost.priorVersionDirectory === "podman-machine-5.8.2-8b2257ace33ecb14",
    "managed-runtime sentinel uses the wrong N-1 versions directory",
  );
  assertTrue(ghost.priorVersionPayloadDirectoryAbsentBeforeUpgrade, "absent N-1 versions payload setup");
  assertTrue(ghost.priorVersionPayloadDirectoryAbsentAfterInstaller, "absent N-1 versions payload preservation");
  assertTrue(ghost.providerHomeSentinelPreserved, "N-1 provider-home preservation");
  assert(
    ghost.registeredWslStateExercised === false,
    "normal NSIS qualification must not claim that its filesystem sentinel is a registered WSL distribution",
  );

  assertExactKeys(
    observations.cleanup,
    ["candidateUninstalled", "installDirectoryRemoved", "privateDataRemoved", "registrySentinelRemoved"],
    "cleanup observation",
  );
  for (const [name, value] of Object.entries(observations.cleanup)) {
    assertTrue(value, `cleanup ${name}`);
  }
}

async function currentNsisInstaller(artifactDirectory, version, tag, commit) {
  const manifestPath = path.join(artifactDirectory, "installers-windows-x86_64.json");
  const manifest = await readJson(manifestPath);
  assert(manifest.schemaVersion === 2, "Windows installer manifest schema is unsupported");
  assert(manifest.product === "ai-security-scanner", "Windows installer manifest product is incorrect");
  assert(manifest.platform === PLATFORM, "Windows installer manifest platform is incorrect");
  assert(manifest.version === version && manifest.tag === tag, "Windows installer manifest version/tag mismatch");
  assert(manifest.sourceCommit === commit, "Windows installer manifest source commit mismatch");
  const installers = manifest.installers?.filter((item) => item.bundleType === INSTALLER_TYPE) ?? [];
  assert(installers.length === 1, "Windows installer manifest must contain exactly one NSIS installer");
  const installer = installers[0];
  assertExactKeys(installer, ["bundleType", "file", "bytes", "sha256"], "candidate NSIS installer record");
  assert(path.basename(installer.file) === installer.file, "candidate NSIS installer path is not flat");
  assertBoundedInteger(installer.bytes, 1, 256 * 1024 * 1024, "candidate NSIS installer bytes");
  assertSha256(installer.sha256, "candidate NSIS installer digest");
  const absolute = path.join(artifactDirectory, installer.file);
  const metadata = await lstat(absolute);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "candidate NSIS installer is not a regular file");
  assert(metadata.size === installer.bytes, "candidate NSIS installer byte length mismatch");
  assert((await sha256File(absolute)) === installer.sha256, "candidate NSIS installer digest mismatch");
  return installer;
}

async function validateIdentity(args) {
  const artifactDirectory = path.resolve(requireString(args, "artifact-dir"));
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  assert(
    isSemver(version) && version === "0.1.8" && tag === `v${version}`,
    "candidate version/tag is not the bounded v0.1.7 to v0.1.8 upgrade",
  );
  assert(/^[0-9a-f]{40}$/u.test(commit), "candidate commit is not a full lowercase Git object ID");
  const installer = await currentNsisInstaller(artifactDirectory, version, tag, commit);
  return { artifactDirectory, version, tag, commit, installer };
}

async function createEvidence(args) {
  const identity = await validateIdentity(args);
  const observationsPath = path.resolve(requireString(args, "observations"));
  const observationsMetadata = await lstat(observationsPath);
  assert(
    observationsMetadata.isFile() && !observationsMetadata.isSymbolicLink() && observationsMetadata.size <= 256 * 1024,
    "Windows NSIS upgrade observations are not one bounded regular file",
  );
  const observations = JSON.parse(await readFile(observationsPath, "utf8"));
  validateObservations(observations, identity.version, identity.installer);
  await validateMasterFrameworkArtifacts(
    path.resolve(requireString(args, "report")),
    path.resolve(requireString(args, "bundle")),
    path.resolve(requireString(args, "prior-bundle")),
    observations.masterFrameworkReport,
    observations.dataPreservation,
    identity.version,
  );
  const evidence = {
    schemaVersion: SCHEMA_VERSION,
    qualification: "windows_nsis_n_minus_one_upgrade_and_data_preservation",
    releaseIdentity: {
      product: "ai-security-scanner",
      version: identity.version,
      tag: identity.tag,
      sourceCommit: identity.commit,
    },
    platform: PLATFORM,
    runner: RUNNER,
    installerType: INSTALLER_TYPE,
    candidateInstaller: {
      file: identity.installer.file,
      bytes: identity.installer.bytes,
      sha256: identity.installer.sha256,
    },
    priorReleasePin: { ...PRIOR_WINDOWS_NSIS },
    observations,
  };
  const output = path.resolve(requireString(args, "out"));
  await writeJsonAtomic(output, evidence);
  process.stdout.write(`Created strict Windows NSIS N-1 upgrade evidence at ${output}\n`);
}

async function validateEvidence(args) {
  const identity = await validateIdentity(args);
  const evidencePath = path.resolve(requireString(args, "file"));
  const metadata = await lstat(evidencePath);
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= 256 * 1024, "upgrade evidence is not one bounded regular file");
  const evidence = JSON.parse(await readFile(evidencePath, "utf8"));
  assertExactKeys(
    evidence,
    [
      "schemaVersion",
      "qualification",
      "releaseIdentity",
      "platform",
      "runner",
      "installerType",
      "candidateInstaller",
      "priorReleasePin",
      "observations",
    ],
    "Windows NSIS upgrade evidence",
  );
  assert(evidence.schemaVersion === SCHEMA_VERSION, "upgrade evidence schema is unsupported");
  assert(
    evidence.qualification === "windows_nsis_n_minus_one_upgrade_and_data_preservation",
    "upgrade evidence qualification ID is incorrect",
  );
  assertExactKeys(evidence.releaseIdentity, ["product", "version", "tag", "sourceCommit"], "release identity");
  assert(evidence.releaseIdentity.product === "ai-security-scanner", "upgrade evidence product is incorrect");
  assert(evidence.releaseIdentity.version === identity.version, "upgrade evidence version mismatch");
  assert(evidence.releaseIdentity.tag === identity.tag, "upgrade evidence tag mismatch");
  assert(evidence.releaseIdentity.sourceCommit === identity.commit, "upgrade evidence commit mismatch");
  assert(evidence.platform === PLATFORM && evidence.runner === RUNNER, "upgrade evidence execution platform mismatch");
  assert(evidence.installerType === INSTALLER_TYPE, "upgrade evidence installer type is incorrect");
  assert(
    JSON.stringify(evidence.candidateInstaller) ===
      JSON.stringify({ file: identity.installer.file, bytes: identity.installer.bytes, sha256: identity.installer.sha256 }),
    "upgrade evidence candidate installer binding mismatch",
  );
  assert(
    JSON.stringify(evidence.priorReleasePin) === JSON.stringify(PRIOR_WINDOWS_NSIS),
    "upgrade evidence N-1 pin changed",
  );
  validateObservations(evidence.observations, identity.version, identity.installer);
  await validateMasterFrameworkArtifacts(
    path.resolve(requireString(args, "report")),
    path.resolve(requireString(args, "bundle")),
    path.resolve(requireString(args, "prior-bundle")),
    evidence.observations.masterFrameworkReport,
    evidence.observations.dataPreservation,
    identity.version,
  );
  process.stdout.write(`Validated Windows NSIS N-1 upgrade evidence for ${identity.tag}\n`);
  return evidence;
}

export async function validateWindowsNsisUpgradeEvidenceFile({
  file,
  artifactDirectory,
  version,
  tag,
  commit,
  reportFile,
  bundleFile,
  priorBundleFile,
}) {
  return validateEvidence(new Map([
    ["file", file],
    ["artifact-dir", artifactDirectory],
    ["version", version],
    ["tag", tag],
    ["commit", commit],
    ["report", reportFile],
    ["bundle", bundleFile],
    ["prior-bundle", priorBundleFile],
  ]));
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);
  if (command === "create") return createEvidence(args);
  if (command === "validate") return validateEvidence(args);
  throw new Error(
    "usage: windows-nsis-upgrade-evidence.mjs <create|validate> --artifact-dir <dir> --version <semver> --tag <tag> --commit <sha> --report <master-framework-report.json> --bundle <master-framework-report.case.tar.gz> --prior-bundle <n-minus-one-before-upgrade.case.tar.gz> [--observations <json>|--file <json>] [--out <json>]",
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(main);
}
