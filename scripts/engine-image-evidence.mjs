import { execFileSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  PROJECT_ROOT,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256,
  sha256File,
  writeJsonAtomic,
  writeTextAtomic,
} from "./release/lib.mjs";

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const SOURCE_REVISION_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const ENGINE_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;
const IMAGE_PATTERN = /^[a-z0-9.-]+\/[a-z0-9._/-]+$/u;
const MAX_ATTESTABLE_SBOM_BYTES = 16 * 1024 * 1024;
const SYFT = Object.freeze({
  name: "anchore/syft",
  version: "1.51.0",
  image: "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0",
});
const PREDICATES = Object.freeze({
  provenance: "https://slsa.dev/provenance/v1",
  spdx: "https://spdx.dev/Document/v2.3",
  cyclonedx: "https://cyclonedx.org/bom",
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function digestHex(digest) {
  assert(DIGEST_PATTERN.test(digest), `invalid OCI digest: ${String(digest)}`);
  return digest.slice("sha256:".length);
}

function platformKey(platform) {
  return platform.replace("linux/", "");
}

function outputLine(key, value) {
  assert(!String(value).includes("\n"), `GitHub output ${key} contains a newline`);
  return `${key}=${value}\n`;
}

function parseIndex(rawBytes, expectedDigest) {
  const expectedHex = digestHex(expectedDigest);
  const candidates = [rawBytes];
  if (rawBytes.at(-1) === 0x0a) candidates.push(rawBytes.subarray(0, rawBytes.length - 1));
  assert(
    candidates.some((candidate) => sha256(candidate) === expectedHex),
    "registry index bytes do not match the build output digest",
  );
  const index = JSON.parse(rawBytes.toString("utf8"));
  assert(Array.isArray(index.manifests), "published image is not a multi-platform OCI/Docker index");

  const result = new Map();
  for (const descriptor of index.manifests) {
    const operatingSystem = descriptor?.platform?.os;
    const architecture = descriptor?.platform?.architecture;
    if (operatingSystem !== "linux" || !["amd64", "arm64"].includes(architecture)) continue;
    const platform = `${operatingSystem}/${architecture}`;
    assert(!result.has(platform), `image index contains duplicate ${platform} descriptors`);
    digestHex(descriptor.digest);
    result.set(platform, descriptor.digest);
  }
  assert(result.size === 2, "image index must contain linux/amd64 and linux/arm64 manifests");
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    assert(result.has(platform), `image index is missing ${platform}`);
  }
  return result;
}

function describedSpdxPackage(document) {
  assert(document?.spdxVersion === "SPDX-2.3", "SBOM is not SPDX 2.3 JSON");
  assert(document?.SPDXID === "SPDXRef-DOCUMENT", "SPDX document identity is missing");
  assert(Array.isArray(document.packages) && document.packages.length > 0, "SPDX package inventory is empty");
  const describes = document.relationships?.find(
    (relationship) =>
      relationship?.spdxElementId === "SPDXRef-DOCUMENT" &&
      relationship?.relationshipType === "DESCRIBES",
  );
  assert(describes?.relatedSpdxElement, "SPDX document does not identify the described image");
  const root = document.packages.find((entry) => entry?.SPDXID === describes.relatedSpdxElement);
  assert(root, "SPDX described-image package is absent");
  return root;
}

function validateSpdx(document, platformDigest) {
  const root = describedSpdxPackage(document);
  const expectedHex = digestHex(platformDigest);
  assert(root.versionInfo === platformDigest, "SPDX described image version is not the platform digest");
  assert(
    root.checksums?.some(
      (checksum) => checksum?.algorithm === "SHA256" && checksum?.checksumValue === expectedHex,
    ),
    "SPDX described image checksum is not the platform digest",
  );
}

function validateCycloneDx(document, platformDigest) {
  digestHex(platformDigest);
  assert(document?.bomFormat === "CycloneDX", "SBOM is not CycloneDX JSON");
  assert(/^1\.[0-9]+$/u.test(document?.specVersion ?? ""), "CycloneDX specVersion is invalid");
  assert(document?.metadata?.component?.type === "container", "CycloneDX metadata does not describe a container");
  assert(
    document.metadata.component.version === platformDigest,
    "CycloneDX described image version is not the platform digest",
  );
  assert(Array.isArray(document.components), "CycloneDX component inventory is missing");
}

async function sbomRecord(root, filename, format, predicateType, platformDigest) {
  const absolute = path.join(root, filename);
  const metadata = await stat(absolute);
  assert(metadata.isFile(), `SBOM is not a regular file: ${filename}`);
  assert(metadata.size > 0, `SBOM is empty: ${filename}`);
  assert(metadata.size <= MAX_ATTESTABLE_SBOM_BYTES, `SBOM exceeds the GitHub attestation limit: ${filename}`);
  const document = await readJson(absolute);
  if (format === "spdx-json") validateSpdx(document, platformDigest);
  else validateCycloneDx(document, platformDigest);
  return {
    format,
    predicateType,
    file: filename,
    sha256: await sha256File(absolute),
    sizeBytes: metadata.size,
  };
}

function runSyft(image, digest, outputRoot, prefix) {
  const user = typeof process.getuid === "function" ? `${process.getuid()}:${process.getgid()}` : "0:0";
  execFileSync(
    "docker",
    [
      "run",
      "--rm",
      "--pull",
      "always",
      "--user",
      user,
      "--env",
      "SYFT_CHECK_FOR_APP_UPDATE=false",
      "--env",
      "SYFT_CACHE_DIR=/tmp/syft-cache",
      "--env",
      "XDG_CACHE_HOME=/tmp/xdg-cache",
      "--tmpfs",
      "/tmp:rw,nosuid,nodev,mode=1777",
      "--volume",
      `${outputRoot}:/evidence`,
      SYFT.image,
      `registry:${image}@${digest}`,
      "-o",
      `spdx-json=/evidence/${prefix}.spdx.json`,
      "-o",
      `cyclonedx-json=/evidence/${prefix}.cyclonedx.json`,
    ],
    { stdio: "inherit" },
  );
}

async function createPreparedEvidence({ engine, image, tag, indexDigest, sourceRevision, outputRoot, platformDigests, runSyftScan }) {
  assert(ENGINE_PATTERN.test(engine), `invalid engine id: ${engine}`);
  assert(IMAGE_PATTERN.test(image) && !image.includes("@") && !image.includes(":"), `image must be an untagged fully-qualified name: ${image}`);
  assert(typeof tag === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(tag), `invalid image tag: ${tag}`);
  digestHex(indexDigest);
  assert(SOURCE_REVISION_PATTERN.test(sourceRevision), `invalid source revision: ${sourceRevision}`);
  if (process.env.GITHUB_SHA) {
    assert(sourceRevision === process.env.GITHUB_SHA, "source revision does not match the executing workflow commit");
  }
  await mkdir(outputRoot, { recursive: true });

  const platforms = [];
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    const digest = platformDigests.get(platform);
    digestHex(digest);
    const prefix = `${engine}-linux-${platformKey(platform)}`;
    if (runSyftScan) runSyftScan(image, digest, outputRoot, prefix);
    platforms.push({
      platform,
      digest,
      sboms: [
        await sbomRecord(outputRoot, `${prefix}.spdx.json`, "spdx-json", PREDICATES.spdx, digest),
        await sbomRecord(outputRoot, `${prefix}.cyclonedx.json`, "cyclonedx-json", PREDICATES.cyclonedx, digest),
      ],
    });
  }

  const evidence = {
    schemaVersion: 1,
    engine,
    image,
    tag,
    indexDigest,
    sourceRevision,
    public: true,
    generator: SYFT,
    imageBuild: {
      inlineProvenance: false,
      inlineSbom: false,
      digestMutatedByEvidence: false,
    },
    platforms,
    attestations: [],
    verification: {
      repository: process.env.GITHUB_REPOSITORY ?? null,
      workflowRun:
        process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
          ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
          : null,
      runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
      registryReferrers: true,
      githubAttestationApi: true,
      onlineVerificationRequiredBeforeUpload: true,
    },
  };
  const manifest = path.join(outputRoot, `${engine}-image-supply-chain.json`);
  await writeJsonAtomic(manifest, evidence);
  return { evidence, manifest };
}

function decodeBundle(bundle) {
  assert(typeof bundle?.mediaType === "string" && bundle.mediaType.includes("sigstore.bundle"), "attestation is not a Sigstore bundle");
  assert(bundle?.dsseEnvelope?.payloadType === "application/vnd.in-toto+json", "attestation has the wrong DSSE payload type");
  assert(Array.isArray(bundle.dsseEnvelope.signatures) && bundle.dsseEnvelope.signatures.length > 0, "attestation has no DSSE signature");
  assert(bundle.verificationMaterial && typeof bundle.verificationMaterial === "object", "attestation verification material is absent");
  const encoded = bundle.dsseEnvelope.payload;
  assert(typeof encoded === "string" && encoded.length > 0, "attestation DSSE payload is absent");
  const decoded = Buffer.from(encoded, "base64");
  assert(decoded.length > 0, "attestation DSSE payload is invalid");
  return JSON.parse(decoded.toString("utf8"));
}

async function copyAndValidateBundle({ source, destination, image, digest, predicateType, predicate }) {
  const bundle = await readJson(source);
  const statement = decodeBundle(bundle);
  assert(statement?._type === "https://in-toto.io/Statement/v1", "attestation is not an in-toto v1 statement");
  assert(statement?.predicateType === predicateType, `unexpected attestation predicate: ${statement?.predicateType}`);
  const subject = statement?.subject?.find((candidate) => candidate?.name === image);
  assert(subject, `attestation does not name ${image}`);
  assert(subject.digest?.sha256 === digestHex(digest), "attestation subject digest is incorrect");
  if (predicate) assert(isDeepStrictEqual(statement.predicate, predicate), "attested SBOM differs from the downloadable SBOM");
  await copyFile(source, destination);
  const metadata = await stat(destination);
  return { sha256: await sha256File(destination), sizeBytes: metadata.size };
}

async function finalizeEvidence(args) {
  const manifest = path.resolve(requireString(args, "manifest"));
  const root = path.dirname(manifest);
  const evidence = await readJson(manifest);
  assert(evidence?.schemaVersion === 1 && evidence.attestations?.length === 0, "prepared engine evidence is invalid or already finalized");

  const specifications = [
    {
      key: "provenance",
      kind: "build-provenance",
      digest: evidence.indexDigest,
      predicateType: PREDICATES.provenance,
    },
  ];
  for (const platform of evidence.platforms) {
    const architecture = platformKey(platform.platform);
    for (const sbom of platform.sboms) {
      specifications.push({
        key: `${architecture}-${sbom.format === "spdx-json" ? "spdx" : "cyclonedx"}`,
        kind: "sbom",
        platform: platform.platform,
        digest: platform.digest,
        predicateType: sbom.predicateType,
        predicateFile: sbom.file,
      });
    }
  }

  const records = [];
  for (const specification of specifications) {
    const source = path.resolve(requireString(args, `${specification.key}-bundle`));
    const bundleFile = `${evidence.engine}-${specification.key}.sigstore.json`;
    const predicate = specification.predicateFile
      ? await readJson(path.join(root, specification.predicateFile))
      : null;
    const copied = await copyAndValidateBundle({
      source,
      destination: path.join(root, bundleFile),
      image: evidence.image,
      digest: specification.digest,
      predicateType: specification.predicateType,
      predicate,
    });
    const attestationId = requireString(args, `${specification.key}-id`);
    const attestationUrl = requireString(args, `${specification.key}-url`);
    assert(/^https:\/\/github\.com\//u.test(attestationUrl), `invalid GitHub attestation URL: ${attestationUrl}`);
    if (evidence.verification.repository) {
      assert(
        attestationUrl.startsWith(`https://github.com/${evidence.verification.repository}/attestations/`),
        `attestation URL belongs to another repository: ${attestationUrl}`,
      );
    }
    records.push({
      kind: specification.kind,
      platform: specification.platform ?? null,
      predicateType: specification.predicateType,
      subject: { name: evidence.image, digest: specification.digest },
      bundleFile,
      bundleSha256: copied.sha256,
      bundleSizeBytes: copied.sizeBytes,
      attestationId,
      attestationUrl,
      registryPushed: true,
      githubAttestationsApi: true,
    });
  }

  evidence.attestations = records;
  evidence.checksumsFile = "SHA256SUMS.txt";
  await writeJsonAtomic(manifest, evidence);
  const checksummed = [
    path.basename(manifest),
    ...evidence.platforms.flatMap((platform) => platform.sboms.map((sbom) => sbom.file)),
    ...records.map((record) => record.bundleFile),
  ].sort();
  const checksumLines = [];
  for (const file of checksummed) checksumLines.push(`${await sha256File(path.join(root, file))}  ${file}`);
  await writeTextAtomic(path.join(root, evidence.checksumsFile), `${checksumLines.join("\n")}\n`);
  process.stdout.write(`Finalized signed image evidence for ${evidence.engine}.\n`);
}

async function prepare(args) {
  const engine = requireString(args, "engine");
  const image = requireString(args, "image");
  const tag = requireString(args, "tag");
  const indexDigest = requireString(args, "digest");
  const sourceRevision = requireString(args, "source-revision");
  const outputRoot = path.resolve(requireString(args, "out"));
  const rawIndex = execFileSync("docker", ["buildx", "imagetools", "inspect", "--raw", `${image}@${indexDigest}`]);
  const platformDigests = parseIndex(rawIndex, indexDigest);
  const { manifest } = await createPreparedEvidence({
    engine,
    image,
    tag,
    indexDigest,
    sourceRevision,
    outputRoot,
    platformDigests,
    runSyftScan: runSyft,
  });
  const githubOutput = process.env.GITHUB_OUTPUT;
  if (githubOutput) {
    await writeFile(
      githubOutput,
      [
        outputLine("manifest", manifest),
        outputLine("amd64_digest", platformDigests.get("linux/amd64")),
        outputLine("arm64_digest", platformDigests.get("linux/arm64")),
        outputLine("amd64_spdx", path.join(outputRoot, `${engine}-linux-amd64.spdx.json`)),
        outputLine("amd64_cyclonedx", path.join(outputRoot, `${engine}-linux-amd64.cyclonedx.json`)),
        outputLine("arm64_spdx", path.join(outputRoot, `${engine}-linux-arm64.spdx.json`)),
        outputLine("arm64_cyclonedx", path.join(outputRoot, `${engine}-linux-arm64.cyclonedx.json`)),
      ].join(""),
      { flag: "a" },
    );
  }
  process.stdout.write(`Generated exact per-platform SBOMs for ${image}@${indexDigest}.\n`);
}

function fakeSboms(image, digest) {
  const id = `SPDXRef-DocumentRoot-Image-${digestHex(digest).slice(0, 12)}`;
  return {
    spdx: {
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: image,
      documentNamespace: `https://example.invalid/${digestHex(digest)}`,
      creationInfo: { created: new Date(0).toISOString(), creators: ["Tool: fixture"] },
      packages: [{
        SPDXID: id,
        name: image,
        versionInfo: digest,
        checksums: [{ algorithm: "SHA256", checksumValue: digestHex(digest) }],
      }],
      relationships: [{ spdxElementId: "SPDXRef-DOCUMENT", relatedSpdxElement: id, relationshipType: "DESCRIBES" }],
    },
    cyclonedx: {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: "urn:uuid:00000000-0000-0000-0000-000000000000",
      version: 1,
      metadata: { component: { type: "container", name: image, version: digest } },
      components: [],
    },
  };
}

async function fakeBundle(file, image, digest, predicateType, predicate) {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: image, digest: { sha256: digestHex(digest) } }],
    predicateType,
    predicate,
  };
  await writeJsonAtomic(file, {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { tlogEntries: [{}] },
    dsseEnvelope: {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
      signatures: [{ sig: Buffer.from("fixture-signature").toString("base64") }],
    },
  });
}

async function selfTest() {
  const root = await mkdtemp(path.join(os.tmpdir(), "ai-security-scanner-engine-evidence-"));
  try {
    const engine = "fixture-engine";
    const image = "ghcr.io/example/fixture-engine";
    const indexDigest = `sha256:${"11".repeat(32)}`;
    const platformDigests = new Map([
      ["linux/amd64", `sha256:${"22".repeat(32)}`],
      ["linux/arm64", `sha256:${"33".repeat(32)}`],
    ]);
    for (const [platform, digest] of platformDigests) {
      const prefix = `${engine}-linux-${platformKey(platform)}`;
      const fixtures = fakeSboms(image, digest);
      await writeJsonAtomic(path.join(root, `${prefix}.spdx.json`), fixtures.spdx);
      await writeJsonAtomic(path.join(root, `${prefix}.cyclonedx.json`), fixtures.cyclonedx);
    }
    const { manifest } = await createPreparedEvidence({
      engine,
      image,
      tag: "1.0.0-1",
      indexDigest,
      sourceRevision: process.env.GITHUB_SHA ?? "ab".repeat(20),
      outputRoot: root,
      platformDigests,
      runSyftScan: null,
    });

    const specifications = [
      ["provenance", indexDigest, PREDICATES.provenance, {}],
      ["amd64-spdx", platformDigests.get("linux/amd64"), PREDICATES.spdx, await readJson(path.join(root, `${engine}-linux-amd64.spdx.json`))],
      ["amd64-cyclonedx", platformDigests.get("linux/amd64"), PREDICATES.cyclonedx, await readJson(path.join(root, `${engine}-linux-amd64.cyclonedx.json`))],
      ["arm64-spdx", platformDigests.get("linux/arm64"), PREDICATES.spdx, await readJson(path.join(root, `${engine}-linux-arm64.spdx.json`))],
      ["arm64-cyclonedx", platformDigests.get("linux/arm64"), PREDICATES.cyclonedx, await readJson(path.join(root, `${engine}-linux-arm64.cyclonedx.json`))],
    ];
    const finalArgs = new Map([["manifest", manifest]]);
    for (const [key, digest, predicateType, predicate] of specifications) {
      const bundle = path.join(root, `${key}.input.json`);
      await fakeBundle(bundle, image, digest, predicateType, predicate);
      finalArgs.set(`${key}-bundle`, bundle);
      finalArgs.set(`${key}-id`, `fixture-${key}`);
      finalArgs.set(`${key}-url`, `https://github.com/example/repository/attestations/fixture-${key}`);
    }
    await finalizeEvidence(finalArgs);
    const finalized = await readJson(manifest);
    assert(finalized.attestations.length === 5, "self-test did not preserve all five attestations");
    assert((await readFile(path.join(root, "SHA256SUMS.txt"), "utf8")).split("\n").filter(Boolean).length === 10, "self-test checksum inventory is incomplete");

    const wrongDigestBundle = path.join(root, "wrong-digest.json");
    await fakeBundle(wrongDigestBundle, image, `sha256:${"44".repeat(32)}`, PREDICATES.spdx, {});
    let rejected = false;
    try {
      await copyAndValidateBundle({
        source: wrongDigestBundle,
        destination: path.join(root, "must-not-copy.json"),
        image,
        digest: platformDigests.get("linux/amd64"),
        predicateType: PREDICATES.spdx,
        predicate: {},
      });
    } catch {
      rejected = true;
    }
    assert(rejected, "self-test accepted an attestation for the wrong image digest");

    const malformed = fakeSboms(image, platformDigests.get("linux/amd64")).spdx;
    malformed.packages[0].checksums[0].checksumValue = "00".repeat(32);
    rejected = false;
    try {
      validateSpdx(malformed, platformDigests.get("linux/amd64"));
    } catch {
      rejected = true;
    }
    assert(rejected, "self-test accepted an SPDX document for the wrong image digest");

    const workflowCoverage = new Map([
      [".github/workflows/engine-images-cloud.yml", ["cloudquery", "prowler", "cloudsplaining", "scoutsuite", "steampipe"]],
      [".github/workflows/engine-images-external.yml", ["naabu", "httpx", "nuclei"]],
      [".github/workflows/engine-images-m365.yml", ["scubagear", "maester"]],
      [".github/workflows/engine-images-local-k8s.yml", ["semgrep", "trufflehog", "trivy", "grype", "kubescape", "kube-bench"]],
      [".github/workflows/engine-image-greenbone.yml", ["greenbone"]],
      [".github/workflows/engine-image-checkov.yml", ["checkov"]],
      [".github/workflows/engine-image-syft.yml", ["syft"]],
    ]);
    let coveredEngines = 0;
    for (const [relative, engines] of workflowCoverage) {
      const workflow = await readFile(path.join(PROJECT_ROOT, relative), "utf8");
      assert(workflow.includes("uses: ./.github/actions/engine-image-evidence"), `${relative} does not invoke signed image evidence`);
      assert(workflow.includes("id-token: write") && workflow.includes("attestations: write"), `${relative} cannot create GitHub attestations`);
      assert(workflow.includes("provenance: false") && workflow.includes("sbom: false"), `${relative} may mutate the published index digest`);
      for (const engineId of engines) {
        assert(workflow.includes(`engine: ${engineId}`), `${relative} does not cover ${engineId}`);
        coveredEngines += 1;
      }
    }
    assert(coveredEngines === 19, "self-test engine workflow coverage changed unexpectedly");
    process.stdout.write("Engine image evidence self-test passed (19 engines, 5 attestations, 4 SBOMs, negative digest checks).\n");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (command === "prepare") return prepare(parseArgs(rest));
  if (command === "finalize") return finalizeEvidence(parseArgs(rest));
  if (command === "self-test") return selfTest();
  throw new Error("expected command: prepare, finalize, or self-test");
}

runMain(main);
