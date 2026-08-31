import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const verifier = path.join(projectRoot, "scripts/release/verify-publication-artifact.mjs");
const repository = "teddashh/ai-security-scanner";
const sourceRevision = "ab".repeat(20);
const runId = "123456789";
const attempt = "2";
const indexDigest = `sha256:${"11".repeat(32)}`;
const platformDigests = {
  "linux/amd64": `sha256:${"22".repeat(32)}`,
  "linux/arm64": `sha256:${"33".repeat(32)}`,
};
const specs = {
  naabu: { tag: "2.6.1-5", group: "external" },
  httpx: { tag: "1.10.0-5", group: "external" },
  nuclei: { tag: "3.11.1-5", group: "external" },
  semgrep: { tag: "1.174.0-3", group: "local", smokeFiles: ["semgrep.json"] },
  trufflehog: { tag: "3.97.0-3", group: "local", smokeFiles: ["trufflehog.jsonl"] },
  trivy: { tag: "0.74.0-3", group: "local", smokeFiles: ["trivy-oci.json", "trivy-library.json"] },
  grype: { tag: "0.117.0-3", group: "local", smokeFiles: ["grype.json"] },
  kubescape: { tag: "4.0.12-3", group: "local", smokeFiles: ["kubescape.json"] },
  "kube-bench": { tag: "0.16.0-3", group: "local", smokeFiles: ["kube-bench.json"] },
  "egress-gateway": { tag: "0.1.8-1", group: "gateway" },
};
const platforms = ["linux/amd64", "linux/arm64"];
const sbomSpecs = [
  { format: "spdx-json", suffix: "spdx", predicateType: "https://spdx.dev/Document/v2.3" },
  { format: "cyclonedx-json", suffix: "cyclonedx", predicateType: "https://cyclonedx.org/bom" },
];
let fakeGhDirectory;

test.before(async () => {
  fakeGhDirectory = await mkdtemp(path.join(os.tmpdir(), "publication-fake-gh-"));
  const executable = path.join(fakeGhDirectory, "gh");
  await writeFile(executable, `#!/usr/bin/env node
const { readFileSync } = require("node:fs");
const args = process.argv.slice(2);
const value = (flag) => args[args.indexOf(flag) + 1];
if (process.env.FAKE_GH_ATTESTATION_FAILURE === "1") {
  process.stderr.write("fixture cryptographic failure\\n");
  process.exit(1);
}
const bundle = JSON.parse(readFileSync(value("--bundle"), "utf8"));
const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
const sourceRevision = value("--source-digest");
const sourceRef = value("--source-ref");
const signerIdentity = \`https://github.com/\${value("--signer-workflow")}@\${sourceRef}\`;
const repository = value("--repo");
const invocation = \`https://github.com/\${repository}/actions/runs/\${process.env.FAKE_GH_RUN_ID}/attempts/\${process.env.FAKE_GH_ATTEMPT}\`;
process.stdout.write(JSON.stringify([{
  verificationResult: {
    signature: { certificate: {
      sourceRepositoryURI: \`https://github.com/\${repository}\`,
      sourceRepositoryDigest: sourceRevision,
      sourceRepositoryRef: sourceRef,
      githubWorkflowRepository: repository,
      githubWorkflowSHA: sourceRevision,
      buildSignerURI: signerIdentity,
      buildSignerDigest: sourceRevision,
      subjectAlternativeName: signerIdentity,
      runInvocationURI: invocation,
      runnerEnvironment: "github-hosted",
      sourceRepositoryVisibilityAtSigning: "public",
    } },
    verifiedTimestamps: [{ type: "Tlog", uri: "https://rekor.sigstore.dev" }],
    statement,
  },
}]) + "\\n");
`);
  await chmod(executable, 0o755);
});

test.after(async () => {
  if (fakeGhDirectory) await rm(fakeGhDirectory, { recursive: true, force: true });
});

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const imageFor = (engine) => engine === "egress-gateway"
  ? "ghcr.io/teddashh/ai-security-scanner-egress-gateway"
  : `ghcr.io/teddashh/ai-security-scanner-engine-${engine}`;

async function writeJson(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function fileRecord(file) {
  const bytes = await readFile(file);
  return { sha256: sha256(bytes), sizeBytes: bytes.length };
}

async function writeChecksums(file, directory, names, rootStyle = false) {
  const lines = [];
  for (const name of [...names].sort()) {
    const bytes = await readFile(path.join(directory, ...name.split("/")));
    lines.push(`${sha256(bytes)}  ${rootStyle ? "./" : ""}${name}`);
  }
  await writeFile(file, `${lines.join("\n")}\n`);
}

async function regularFiles(directory, prefix = "") {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await regularFiles(path.join(directory, entry.name), relative));
    else if (entry.isFile()) files.push(relative);
  }
  return files;
}

async function sealRoot(root) {
  const names = (await regularFiles(root)).filter((name) => name !== "SHA256SUMS.txt");
  await writeChecksums(path.join(root, "SHA256SUMS.txt"), root, names, true);
}

async function sealNested(root, engine) {
  const nested = path.join(root, engine);
  const names = (await regularFiles(nested)).filter((name) => name !== "SHA256SUMS.txt");
  await writeChecksums(path.join(nested, "SHA256SUMS.txt"), nested, names);
}

function fakeSbom(engine, platform, format) {
  return format === "spdx-json"
    ? {
      spdxVersion: "SPDX-2.3",
      SPDXID: "SPDXRef-DOCUMENT",
      name: `${engine}-${platform}`,
      packages: [{ name: imageFor(engine), versionInfo: platformDigests[platform] }],
    }
    : {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      metadata: { component: { type: "container", name: imageFor(engine), version: platformDigests[platform] } },
    };
}

function fakeBundle(image, digest, predicateType, predicate) {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: image, digest: { sha256: digest.slice(7) } }],
    predicateType,
    predicate,
  };
  return {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { tlogEntries: [{}] },
    dsseEnvelope: {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
      signatures: [{ sig: Buffer.from("fixture-signature").toString("base64") }],
    },
  };
}

async function createArtifact(testContext, engine) {
  const spec = specs[engine];
  const root = await mkdtemp(path.join(os.tmpdir(), `publication-${engine}-`));
  testContext.after(() => rm(root, { recursive: true, force: true }));
  const nested = path.join(root, engine);
  await mkdir(nested, { recursive: true });
  const image = imageFor(engine);
  const platformRecords = [];
  const documents = new Map();

  for (const platform of platforms) {
    const architecture = platform.split("/")[1];
    const sboms = [];
    for (const sbomSpec of sbomSpecs) {
      const file = `${engine}-linux-${architecture}.${sbomSpec.suffix}.json`;
      const document = fakeSbom(engine, platform, sbomSpec.format);
      documents.set(file, document);
      await writeJson(path.join(nested, file), document);
      const record = await fileRecord(path.join(nested, file));
      sboms.push({
        format: sbomSpec.format,
        predicateType: sbomSpec.predicateType,
        file,
        sha256: record.sha256,
        sizeBytes: record.sizeBytes,
      });
    }
    platformRecords.push({ platform, digest: platformDigests[platform], sboms });
  }

  const attestationSpecs = [
    {
      key: "provenance",
      kind: "build-provenance",
      platform: null,
      predicateType: "https://slsa.dev/provenance/v1",
      digest: indexDigest,
      predicate: {
        buildDefinition: {
          buildType: "https://actions.github.io/buildtypes/workflow/v1",
          externalParameters: {
            workflow: {
              ref: "refs/heads/main",
              repository: `https://github.com/${repository}`,
              path: spec.group === "external"
                ? ".github/workflows/engine-images-external.yml"
                : spec.group === "local"
                  ? ".github/workflows/engine-images-local-k8s.yml"
                  : ".github/workflows/managed-egress-gateway-image.yml",
            },
          },
          resolvedDependencies: [{
            uri: `git+https://github.com/${repository}@refs/heads/main`,
            digest: { gitCommit: sourceRevision },
          }],
        },
        runDetails: {
          builder: {
            id: `https://github.com/${repository}/${spec.group === "external"
              ? ".github/workflows/engine-images-external.yml"
              : spec.group === "local"
                ? ".github/workflows/engine-images-local-k8s.yml"
                : ".github/workflows/managed-egress-gateway-image.yml"}@refs/heads/main`,
          },
          metadata: {
            invocationId: `https://github.com/${repository}/actions/runs/${runId}/attempts/${attempt}`,
          },
        },
      },
    },
    ...platforms.flatMap((platform) => {
      const architecture = platform.split("/")[1];
      return sbomSpecs.map((sbom) => ({
        key: `${architecture}-${sbom.suffix}`,
        kind: "sbom",
        platform,
        predicateType: sbom.predicateType,
        digest: platformDigests[platform],
        predicate: documents.get(`${engine}-linux-${architecture}.${sbom.suffix}.json`),
      }));
    }),
  ];
  const attestations = [];
  for (const [attestationIndex, attestation] of attestationSpecs.entries()) {
    const bundleFile = `${engine}-${attestation.key}.sigstore.json`;
    await writeJson(
      path.join(nested, bundleFile),
      fakeBundle(image, attestation.digest, attestation.predicateType, attestation.predicate),
    );
    const record = await fileRecord(path.join(nested, bundleFile));
    const attestationId = String(1000 + attestationIndex);
    attestations.push({
      kind: attestation.kind,
      platform: attestation.platform,
      predicateType: attestation.predicateType,
      subject: { name: image, digest: attestation.digest },
      bundleFile,
      bundleSha256: record.sha256,
      bundleSizeBytes: record.sizeBytes,
      attestationId,
      attestationUrl: `https://github.com/${repository}/attestations/${attestationId}`,
      registryPushed: true,
      githubAttestationsApi: true,
    });
  }

  const transformations = spec.group === "gateway"
    ? platforms.map((platform) => {
      const architecture = platform.split("/")[1];
      const spdx = platformRecords.find((record) => record.platform === platform).sboms[0];
      return {
        kind: "cyclonedx-first-party-scratch-application-v3",
        platform,
        platformDigest: platformDigests[platform],
        sourceRevision,
        sourceFile: `${engine}-linux-${architecture}.spdx.json`,
        outputFile: `${engine}-linux-${architecture}.cyclonedx.json`,
        componentBomRef: `urn:ai-security-scanner:egress-gateway:${platformDigests[platform].slice(7)}`,
        spdxPreserved: true,
        spdxFileCount: 2,
        spdxFileChecksumStatus: "unavailable-syft-zero-sha1-placeholder",
        spdxZeroSha1PlaceholderCount: 2,
        spdxSha256: spdx.sha256,
        tool: { name: "ai-security-scanner/scripts/engine-image-evidence.mjs", version: "3" },
      };
    })
    : [];

  const evidence = {
    schemaVersion: 1,
    engine,
    image,
    tag: spec.tag,
    indexDigest,
    sourceRevision,
    public: true,
    generator: {
      name: "anchore/syft",
      version: "1.51.0",
      image: "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0",
    },
    sbomTransformations: transformations,
    imageBuild: { inlineProvenance: false, inlineSbom: false, digestMutatedByEvidence: false },
    platforms: platformRecords,
    attestations,
    verification: {
      repository,
      workflowRun: `https://github.com/${repository}/actions/runs/${runId}`,
      runAttempt: attempt,
      registryReferrers: true,
      githubAttestationApi: true,
      onlineVerificationRequiredBeforeUpload: true,
    },
    checksumsFile: "SHA256SUMS.txt",
  };
  await writeJson(path.join(nested, `${engine}-image-supply-chain.json`), evidence);
  await sealNested(root, engine);

  let smokeReceipt;
  if (spec.group === "local") {
    const smoke = path.join(root, `${engine}-managed-smoke`);
    await mkdir(smoke);
    for (const file of spec.smokeFiles) await writeFile(path.join(smoke, file), `fixture evidence for ${engine} ${file}\n`);
    await writeChecksums(path.join(smoke, "SHA256SUMS.txt"), smoke, spec.smokeFiles);
    smokeReceipt = `sha256:${sha256(await readFile(path.join(smoke, "SHA256SUMS.txt")))}`;
  }

  if (spec.group !== "gateway") {
    const common = {
      schemaVersion: 1,
      engine,
      image,
      tag: spec.tag,
      digest: indexDigest,
      sourceRevision,
    };
    const summary = spec.group === "local"
      ? {
        ...common,
        platformDigests,
        anonymousPullVerified: true,
        managedSmokeEvidenceSha256: smokeReceipt,
      }
      : { ...common, platforms, public: true };
    await writeJson(path.join(root, `${engine}-image-manifest.json`), summary);
  }
  await sealRoot(root);
  return root;
}

function runVerifier(engine, artifact, overrides = {}) {
  return spawnSync(process.execPath, [
    verifier,
    "--engine", engine,
    "--artifact-dir", artifact,
    "--source-revision", overrides.sourceRevision ?? sourceRevision,
    "--run-id", overrides.runId ?? runId,
    "--attempt", overrides.attempt ?? attempt,
  ], {
    cwd: projectRoot,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    env: {
      ...process.env,
      PATH: `${fakeGhDirectory}${path.delimiter}${process.env.PATH ?? ""}`,
      FAKE_GH_RUN_ID: overrides.runId ?? runId,
      FAKE_GH_ATTEMPT: overrides.attempt ?? attempt,
      FAKE_GH_ATTESTATION_FAILURE: overrides.cryptographicFailure ? "1" : "0",
    },
  });
}

async function mutateNested(root, engine, mutate) {
  const manifest = path.join(root, engine, `${engine}-image-supply-chain.json`);
  const evidence = JSON.parse(await readFile(manifest, "utf8"));
  mutate(evidence);
  await writeJson(manifest, evidence);
  await sealNested(root, engine);
  await sealRoot(root);
}

test("publication verifier accepts all nine fixed engines and the gateway with one normalized JSON result", async (t) => {
  for (const [engine, spec] of Object.entries(specs)) {
    const artifact = await createArtifact(t, engine);
    const result = runVerifier(engine, artifact);
    assert.equal(result.status, 0, `${engine}: ${result.stderr}`);
    assert.equal(result.stderr, "", engine);
    assert.equal(result.stdout.trim().split("\n").length, 1, `${engine} emitted more than one payload`);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.engine, engine);
    assert.equal(payload.image, imageFor(engine));
    assert.equal(payload.tag, spec.tag);
    assert.equal(payload.indexDigest, indexDigest);
    assert.deepEqual(payload.platformDigests, platformDigests);
    assert.equal(payload.sourceRevision, sourceRevision);
    assert.equal(payload.workflowRun, `https://github.com/${repository}/actions/runs/${runId}`);
    assert.equal(payload.runId, runId);
    assert.equal(payload.runAttempt, attempt);
    assert.match(payload.evidence.rootChecksumReceiptSha256, /^sha256:[0-9a-f]{64}$/u);
    assert.match(payload.evidence.nestedChecksumReceiptSha256, /^sha256:[0-9a-f]{64}$/u);
    assert.equal(payload.evidence.sbomCount, 4);
    assert.equal(payload.evidence.attestationCount, 5);
    if (spec.group === "local") assert.match(payload.evidence.managedSmokeEvidenceSha256, /^sha256:[0-9a-f]{64}$/u);
    if (spec.group === "gateway") assert.deepEqual(payload.evidence.sbomTransformationPlatforms, platforms);
  }
});

test("publication verifier rejects a root-seal mismatch before trusting nested evidence", async (t) => {
  const artifact = await createArtifact(t, "naabu");
  await writeFile(path.join(artifact, "naabu", "naabu-linux-amd64.spdx.json"), "tampered\n");
  const result = runVerifier("naabu", artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SHA256SUMS\.txt checksum mismatch/u);
  assert.equal(result.stdout, "");
});

test("publication verifier rejects a bad nested seal even when the root seal is current", async (t) => {
  const engine = "semgrep";
  const artifact = await createArtifact(t, engine);
  const nestedReceipt = path.join(artifact, engine, "SHA256SUMS.txt");
  const contents = await readFile(nestedReceipt, "utf8");
  await writeFile(nestedReceipt, contents.replace(/^[0-9a-f]{64}/u, "00".repeat(32)));
  await sealRoot(artifact);
  const result = runVerifier(engine, artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /semgrep\/SHA256SUMS\.txt checksum mismatch/u);
});

test("publication verifier rejects resealed source/run identity drift", async (t) => {
  const sourceArtifact = await createArtifact(t, "httpx");
  await mutateNested(sourceArtifact, "httpx", (evidence) => {
    evidence.sourceRevision = "cd".repeat(20);
  });
  let result = runVerifier("httpx", sourceArtifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /source revision mismatch/u);

  const runArtifact = await createArtifact(t, "nuclei");
  await mutateNested(runArtifact, "nuclei", (evidence) => {
    evidence.verification.workflowRun = `https://github.com/${repository}/actions/runs/999`;
  });
  result = runVerifier("nuclei", runArtifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /workflow run URL mismatch/u);
});

test("publication verifier rejects provenance that is signed for another source or run", async (t) => {
  const engine = "naabu";
  const artifact = await createArtifact(t, engine);
  const bundleFile = path.join(artifact, engine, `${engine}-provenance.sigstore.json`);
  const bundle = JSON.parse(await readFile(bundleFile, "utf8"));
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = "cd".repeat(20);
  statement.predicate.runDetails.metadata.invocationId = `https://github.com/${repository}/actions/runs/999/attempts/1`;
  bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  await writeJson(bundleFile, bundle);

  const manifestFile = path.join(artifact, engine, `${engine}-image-supply-chain.json`);
  const manifest = JSON.parse(await readFile(manifestFile, "utf8"));
  const record = await fileRecord(bundleFile);
  manifest.attestations[0].bundleSha256 = record.sha256;
  manifest.attestations[0].bundleSizeBytes = record.sizeBytes;
  await writeJson(manifestFile, manifest);
  await sealNested(artifact, engine);
  await sealRoot(artifact);

  const result = runVerifier(engine, artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /provenance source revision/u);
  assert.equal(result.stdout, "");
});

test("publication verifier rejects a resealed local smoke receipt mismatch", async (t) => {
  const engine = "trivy";
  const artifact = await createArtifact(t, engine);
  const summaryFile = path.join(artifact, `${engine}-image-manifest.json`);
  const summary = JSON.parse(await readFile(summaryFile, "utf8"));
  summary.managedSmokeEvidenceSha256 = `sha256:${"ff".repeat(32)}`;
  await writeJson(summaryFile, summary);
  await sealRoot(artifact);
  const result = runVerifier(engine, artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /managed smoke receipt hash/u);
});

test("publication verifier rejects missing gateway platform transformations even after resealing", async (t) => {
  const engine = "egress-gateway";
  const artifact = await createArtifact(t, engine);
  await mutateNested(artifact, engine, (evidence) => {
    evidence.sbomTransformations.pop();
  });
  const result = runVerifier(engine, artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /two SBOM transformations/u);
});

test("publication verifier rejects a cryptographically invalid bundle without stdout", async (t) => {
  const artifact = await createArtifact(t, "naabu");
  const result = runVerifier("naabu", artifact, { cryptographicFailure: true });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /cryptographic verification failed/u);
  assert.equal(result.stdout, "");
});

test("publication verifier rejects unsafe checksum paths and symlinks", async (t) => {
  const unsafeArtifact = await createArtifact(t, "httpx");
  const checksumFile = path.join(unsafeArtifact, "SHA256SUMS.txt");
  const checksums = await readFile(checksumFile, "utf8");
  await writeFile(checksumFile, checksums.replace("./httpx-image-manifest.json", "./../httpx-image-manifest.json"));
  let result = runVerifier("httpx", unsafeArtifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsafe path/u);
  assert.equal(result.stdout, "");

  const symlinkArtifact = await createArtifact(t, "nuclei");
  await symlink("nuclei-image-manifest.json", path.join(symlinkArtifact, "unexpected-link"));
  result = runVerifier("nuclei", symlinkArtifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /contains a symlink/u);
  assert.equal(result.stdout, "");
});
