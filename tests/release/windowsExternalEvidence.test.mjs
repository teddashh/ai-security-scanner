import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { sha256File } from "../../scripts/release/lib.mjs";
import {
  createReleaseCandidateLock,
} from "../../scripts/release/release-candidate-lock.mjs";
import {
  WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS,
  WINDOWS_INSTALLED_LIFECYCLE_RECORDS,
} from "../../scripts/release/windows-installed-lifecycle-evidence.mjs";
import {
  WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
  WINDOWS_HUMAN_PATH_FILE,
  WINDOWS_LIFECYCLE_DIRECTORY,
  WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE,
  importWindowsExternalEvidence,
  materializeWindowsExternalEvidence,
  verifyFinalizedWindowsExternalEvidence,
  verifyFinalizedWindowsExternalEvidenceOutcomes,
  verifyMaterializedWindowsExternalEvidence,
  verifyWindowsExternalEvidenceReceipt,
  windowsExternalEvidenceImporterIdentity,
} from "../../scripts/release/windows-external-evidence.mjs";

const version = "0.1.9";
const tag = `v${version}`;
const commit = "01".repeat(20);
const repository = "teddashh/ai-security-scanner";
const candidateIdentity = {
  version,
  tag,
  commit,
  releaseChannel: "prerelease",
  publicationMode: "public-github-release",
  repository,
  workflow: ".github/workflows/release.yml",
  workflowSha: commit,
  runId: "123456789",
  runAttempt: "1",
  job: "finalize-supported-artifacts",
};
const importer = windowsExternalEvidenceImporterIdentity({
  repository,
  workflow: ".github/workflows/windows-external-evidence.yml",
  workflowSha: "02".repeat(20),
  runId: "987654321",
  runAttempt: "2",
  job: "import",
  environment: "windows-external-evidence",
});
const evidenceSource = {
  repository,
  commit: "03".repeat(20),
  path: "evidence/v0.1.9/windows-x86_64",
};

function humanEvidence(artifact) {
  return {
    schemaVersion: 1,
    evidenceType: "beginner-human-path",
    product: "ai-security-scanner",
    platform: "windows-x86_64",
    installerType: "nsis",
    releaseIdentity: { version, tag, sourceCommit: commit },
    artifact: { ...artifact },
    outcome: "passed",
    observedAt: "2026-09-06T12:00:00Z",
    details: {
      participantProfile: "windows-beginner-no-security-or-linux-experience",
      participantBuiltProduct: false,
      participantContributedToProduct: false,
      participantRehearsedSetup: false,
      facilitatorTookControl: false,
      facilitatorDictatedOperationalSteps: false,
      facilitatorAdministeredWsl: false,
      terminalOpened: false,
      typedCommandCount: 0,
      windowsVersion: "Windows 11 Pro 24H2 build 26100",
      firstReportTimingBasis:
        "installer-launch-to-first-durable-report-excluding-os-shutdown-to-desktop",
      firstReportElapsedSeconds: 540,
      firstReportWallClockElapsedSeconds: 840,
      excludedOperatingSystemRestartSeconds: 300,
      totalJourneyElapsedSeconds: 3_600,
      userDecisions: ["install", "approve-windows-prompt", "start-localhost-scan"],
      visibleErrors: [],
      installed: true,
      launched: true,
      minimumLocalhostScanStarted: true,
      beginnerReportViewed: true,
      projectReopened: true,
      readableReportExported: true,
      readableExport: {
        format: "html",
        outcome: "exported-and-opened-readable",
      },
      finalCoverage: {
        state: "complete",
        testedCount: 1,
        notTestedCount: 0,
        failedCount: 0,
        coverageGapCount: 0,
      },
      localhostReport: {
        target: "127.0.0.1:9001",
        taskExecutionState: "executed",
        outcome: "reachable",
        findingCount: 0,
        durableReportId: "11111111-2222-4333-8444-555555555555",
        durableReportState: "saved",
      },
    },
  };
}

function unsignedSigningObservation(artifact) {
  return {
    schemaVersion: 1,
    evidenceType: "operating-system-code-signing-observation",
    product: "ai-security-scanner",
    platform: "windows-x86_64",
    installerType: "nsis",
    releaseIdentity: { version, tag, sourceCommit: commit },
    artifact: { ...artifact },
    outcome: "not-configured",
    observedAt: "2026-09-06T12:01:00Z",
    details: {
      signatureScheme: "authenticode",
      signatureStatus: "NotSigned",
      artifactSha256: artifact.sha256,
      verificationTool: "Get-AuthenticodeSignature",
    },
  };
}

function notObservedLifecycleRecord(contract, artifact, runtimeManifest) {
  return {
    schemaVersion: 1,
    evidenceType: "windows-installed-app-lifecycle",
    product: "ai-security-scanner",
    rowId: contract.rowId,
    boundary: contract.boundary,
    platform: "windows-x86_64",
    architecture: "x86_64",
    installerType: "nsis",
    releaseIdentity: {
      version,
      tag,
      sourceCommit: commit,
      releaseChannel: "prerelease",
    },
    artifact: { ...artifact },
    runtimeManifest: { ...runtimeManifest },
    relatedArtifact: null,
    environment: null,
    harness: null,
    execution: null,
    outcome: "not-observed",
    reasonCode: "not-scheduled",
    reason: "This exact lifecycle row was not scheduled.",
    checks: contract.checks.map(({ caseId, id }) => ({
      caseId,
      id,
      state: "not-observed",
      observedAt: null,
      detail: "Required observation was not scheduled.",
    })),
    installedAppJourney: null,
    cleanup: null,
    observedAt: "2026-09-06T12:02:00Z",
  };
}

async function writeJson(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), "windows-external-evidence-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const candidateDirectory = path.join(root, "candidate");
  const evidenceDirectory = path.join(root, "evidence");
  const acceptedDirectory = path.join(root, "accepted");
  const materializedDirectory = path.join(root, "materialized");
  await mkdir(candidateDirectory, { recursive: true });
  await mkdir(evidenceDirectory, { recursive: true });

  const installerFile = `ai-security-scanner_${version}_x64-setup.exe`;
  const installerPath = path.join(candidateDirectory, installerFile);
  await writeFile(installerPath, "exact Windows NSIS installer bytes\n");
  const artifact = {
    file: installerFile,
    bytes: (await readFile(installerPath)).byteLength,
    sha256: await sha256File(installerPath),
  };

  const runtimeFile = "managed-runtime-windows-x86_64.manifest.json";
  const runtimePath = path.join(candidateDirectory, runtimeFile);
  await writeJson(runtimePath, {
    schema_version: 1,
    management_contract_revision: "2026-08-29.1",
  });
  const runtimeManifest = {
    file: runtimeFile,
    bytes: (await readFile(runtimePath)).byteLength,
    sha256: await sha256File(runtimePath),
    managementContractRevision: "2026-08-29.1",
  };
  await writeJson(path.join(candidateDirectory, "installers-windows-x86_64.json"), {
    schemaVersion: 2,
    version,
    tag,
    sourceCommit: commit,
    platform: "windows-x86_64",
    installers: [{ bundleType: "nsis", ...artifact }],
  });
  await createReleaseCandidateLock({ directory: candidateDirectory, ...candidateIdentity });

  await writeJson(path.join(evidenceDirectory, WINDOWS_HUMAN_PATH_FILE), humanEvidence(artifact));
  await writeJson(
    path.join(evidenceDirectory, WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE),
    unsignedSigningObservation(artifact),
  );
  const lifecycleContract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0];
  const lifecycleRecord = WINDOWS_INSTALLED_LIFECYCLE_RECORDS[0];
  await writeJson(
    path.join(evidenceDirectory, WINDOWS_LIFECYCLE_DIRECTORY, lifecycleRecord.path),
    notObservedLifecycleRecord(lifecycleContract, artifact, runtimeManifest),
  );

  return {
    root,
    candidateDirectory,
    evidenceDirectory,
    acceptedDirectory,
    materializedDirectory,
    artifact,
    runtimeManifest,
  };
}

function importOptions(f) {
  return {
    candidateDirectory: f.candidateDirectory,
    evidenceDirectory: f.evidenceDirectory,
    output: f.acceptedDirectory,
    candidate: candidateIdentity,
    candidateArtifactId: "11223344",
    candidateArtifactDigest: `sha256:${"ab".repeat(32)}`,
    evidenceSource,
    importer,
    importedAt: "2026-09-06T12:05:00Z",
  };
}

test("protected import verifies and materializes exact candidate-bound Windows evidence", async (t) => {
  const f = await fixture(t);
  const receipt = await importWindowsExternalEvidence(importOptions(f));
  assert.deepEqual(receipt.artifact, f.artifact);
  assert.deepEqual(receipt.runtimeManifest, f.runtimeManifest);
  assert.equal(receipt.humanPath.path, WINDOWS_HUMAN_PATH_FILE);
  assert.equal(receipt.unsignedSigningObservation.path, WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE);
  assert.equal(receipt.windowsLifecycle.summary.state, "not-observed");
  assert.equal(receipt.windowsLifecycle.summary.presentCount, 1);

  await assert.doesNotReject(() => verifyWindowsExternalEvidenceReceipt({
    directory: f.acceptedDirectory,
    candidateDirectory: f.candidateDirectory,
    expectedImporter: importer,
  }));
  await materializeWindowsExternalEvidence({
    directory: f.acceptedDirectory,
    candidateDirectory: f.candidateDirectory,
    output: f.materializedDirectory,
    expectedImporter: importer,
  });
  await assert.doesNotReject(() => verifyMaterializedWindowsExternalEvidence({
    directory: f.materializedDirectory,
    expectedImporter: importer,
  }));
  await assert.doesNotReject(() => verifyFinalizedWindowsExternalEvidence({
    directory: f.materializedDirectory,
    expectedImporter: importer,
    artifact: f.artifact,
    version,
    tag,
    commit,
    releaseChannel: "prerelease",
    publicationMode: "public-github-release",
  }));
});

test("finalized metadata must retain the exact receipted human and lifecycle outcomes", async (t) => {
  const f = await fixture(t);
  await importWindowsExternalEvidence(importOptions(f));
  const receiptPath = path.join(f.acceptedDirectory, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
  const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
  const receiptFile = {
    path: WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
    bytes: (await readFile(receiptPath)).byteLength,
    sha256: await sha256File(receiptPath),
  };
  const humanPath = {
    state: "verified",
    evidenceFile: WINDOWS_HUMAN_PATH_FILE,
    reason: null,
  };
  const windowsLifecycle = {
    state: "not-observed",
    evidenceFiles: [],
    reason: "real-installed-app-localhost-lifecycle-not-observed",
  };
  assert.doesNotThrow(() => verifyFinalizedWindowsExternalEvidenceOutcomes({
    receipt,
    receiptFile,
    humanPath,
    windowsLifecycle,
  }));

  assert.throws(
    () => verifyFinalizedWindowsExternalEvidenceOutcomes({
      receipt,
      receiptFile,
      humanPath: { ...humanPath, evidenceFile: "unreceipted-human-path.json" },
      windowsLifecycle,
    }),
    /human-path outcome differs/u,
  );

  const partialReceipt = structuredClone(receipt);
  partialReceipt.windowsLifecycle.records[0].outcome = "inconclusive";
  partialReceipt.windowsLifecycle.summary.state = "partial";
  partialReceipt.windowsLifecycle.summary.inconclusiveCount = 1;
  partialReceipt.windowsLifecycle.summary.notObservedCount = 0;
  const partialLifecycle = {
    state: "partial",
    evidenceFiles: [
      receiptFile,
      {
        path: partialReceipt.windowsLifecycle.records[0].path,
        bytes: partialReceipt.windowsLifecycle.records[0].bytes,
        sha256: partialReceipt.windowsLifecycle.records[0].sha256,
      },
    ],
    reason: "external-installed-app-lifecycle-partial",
  };
  assert.doesNotThrow(() => verifyFinalizedWindowsExternalEvidenceOutcomes({
    receipt: partialReceipt,
    receiptFile,
    humanPath,
    windowsLifecycle: partialLifecycle,
  }));
  assert.throws(
    () => verifyFinalizedWindowsExternalEvidenceOutcomes({
      receipt: partialReceipt,
      receiptFile,
      humanPath,
      windowsLifecycle: { ...partialLifecycle, evidenceFiles: [receiptFile] },
    }),
    /Windows lifecycle outcome differs/u,
  );
});

test("receipt lifecycle summaries and artifact selectors are canonical", async (t) => {
  await t.test("summary", async (t) => {
    const f = await fixture(t);
    await importWindowsExternalEvidence(importOptions(f));
    const receiptFile = path.join(f.acceptedDirectory, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
    const receipt = JSON.parse(await readFile(receiptFile, "utf8"));
    receipt.windowsLifecycle.summary.state = "partial";
    receipt.windowsLifecycle.summary.passedCount = 1;
    receipt.windowsLifecycle.summary.notObservedCount = 0;
    await writeJson(receiptFile, receipt);
    await assert.rejects(
      () => verifyWindowsExternalEvidenceReceipt({
        directory: f.acceptedDirectory,
        candidateDirectory: f.candidateDirectory,
        expectedImporter: importer,
      }),
      /summary differs from its exact receipted rows/u,
    );
  });

  await t.test("artifact ID", async (t) => {
    const f = await fixture(t);
    await importWindowsExternalEvidence(importOptions(f));
    const receiptFile = path.join(f.acceptedDirectory, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
    const receipt = JSON.parse(await readFile(receiptFile, "utf8"));
    receipt.candidate.artifactId = Number(receipt.candidate.artifactId);
    await writeJson(receiptFile, receipt);
    await assert.rejects(
      () => verifyWindowsExternalEvidenceReceipt({
        directory: f.acceptedDirectory,
        candidateDirectory: f.candidateDirectory,
        expectedImporter: importer,
      }),
      /artifact ID is not canonical/u,
    );
  });
});

test("receipt verification binds the exact candidate lock, installer bytes, and receipted evidence", async (t) => {
  await t.test("candidate lock", async (t) => {
    const f = await fixture(t);
    await importWindowsExternalEvidence(importOptions(f));
    const receiptFile = path.join(f.acceptedDirectory, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
    const receipt = JSON.parse(await readFile(receiptFile, "utf8"));
    receipt.candidate.lockSha256 = "ff".repeat(32);
    await writeJson(receiptFile, receipt);
    await assert.rejects(
      () => verifyWindowsExternalEvidenceReceipt({
        directory: f.acceptedDirectory,
        candidateDirectory: f.candidateDirectory,
        expectedImporter: importer,
      }),
      /different candidate lock/u,
    );
  });

  await t.test("installer identity", async (t) => {
    const f = await fixture(t);
    await importWindowsExternalEvidence(importOptions(f));
    const receiptFile = path.join(f.acceptedDirectory, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
    const receipt = JSON.parse(await readFile(receiptFile, "utf8"));
    receipt.artifact.sha256 = "ff".repeat(32);
    await writeJson(receiptFile, receipt);
    await assert.rejects(
      () => verifyWindowsExternalEvidenceReceipt({
        directory: f.acceptedDirectory,
        candidateDirectory: f.candidateDirectory,
        expectedImporter: importer,
      }),
      /different installer bytes/u,
    );
  });

  await t.test("evidence receipt", async (t) => {
    const f = await fixture(t);
    await importWindowsExternalEvidence(importOptions(f));
    const receiptFile = path.join(f.acceptedDirectory, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
    const receipt = JSON.parse(await readFile(receiptFile, "utf8"));
    receipt.humanPath.sha256 = "ff".repeat(32);
    await writeJson(receiptFile, receipt);
    await assert.rejects(
      () => verifyWindowsExternalEvidenceReceipt({
        directory: f.acceptedDirectory,
        candidateDirectory: f.candidateDirectory,
        expectedImporter: importer,
      }),
      /differs from its receipt/u,
    );
  });
});

test("tampered accepted evidence cannot pass its immutable receipt", async (t) => {
  const f = await fixture(t);
  await importWindowsExternalEvidence(importOptions(f));
  const humanFile = path.join(f.acceptedDirectory, WINDOWS_HUMAN_PATH_FILE);
  const human = JSON.parse(await readFile(humanFile, "utf8"));
  human.artifact.sha256 = "ff".repeat(32);
  await writeJson(humanFile, human);
  await assert.rejects(
    () => verifyWindowsExternalEvidenceReceipt({
      directory: f.acceptedDirectory,
      candidateDirectory: f.candidateDirectory,
      expectedImporter: importer,
    }),
    /artifact identity mismatch/u,
  );
});

test("receipt rejects a verifier from the wrong protected importer run, workflow, or environment", async (t) => {
  const f = await fixture(t);
  await importWindowsExternalEvidence(importOptions(f));
  for (const [label, changed] of [
    ["run", { runId: "987654322" }],
    ["workflow", { workflow: ".github/workflows/not-the-importer.yml" }],
    ["environment", { environment: "unprotected-environment" }],
  ]) {
    await t.test(label, async () => {
      const expectedImporter = windowsExternalEvidenceImporterIdentity({ ...importer, ...changed });
      await assert.rejects(
        () => verifyWindowsExternalEvidenceReceipt({
          directory: f.acceptedDirectory,
          candidateDirectory: f.candidateDirectory,
          expectedImporter,
        }),
        /differs from the protected run/u,
      );
    });
  }
});

test("accepted artifacts reject files that are not covered by the receipt", async (t) => {
  const f = await fixture(t);
  await importWindowsExternalEvidence(importOptions(f));
  await writeFile(path.join(f.acceptedDirectory, "unreceipted.txt"), "not receipted\n");
  await assert.rejects(
    () => verifyWindowsExternalEvidenceReceipt({
      directory: f.acceptedDirectory,
      candidateDirectory: f.candidateDirectory,
      expectedImporter: importer,
    }),
    /contains unreceipted files/u,
  );
});

test("generic importer rejects the reserved Authenticode promotion record", async (t) => {
  const f = await fixture(t);
  await writeJson(path.join(f.evidenceDirectory, "os-signing-windows-x86_64-nsis.json"), {});
  await assert.rejects(
    () => importWindowsExternalEvidence(importOptions(f)),
    /unexpected external evidence path|must not accept Authenticode promotion evidence/u,
  );
});

test("an unsigned observation remains non-promotional and cannot claim verified signing", async (t) => {
  const f = await fixture(t);
  const receipt = await importWindowsExternalEvidence(importOptions(f));
  assert.equal(receipt.unsignedSigningObservation.path, WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE);
  assert.ok(!Object.hasOwn(receipt, "osSigning"));
  const retained = JSON.parse(await readFile(
    path.join(f.acceptedDirectory, WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE),
    "utf8",
  ));
  assert.equal(retained.outcome, "not-configured");
  assert.equal(retained.details.signatureStatus, "NotSigned");

  const rejected = await fixture(t);
  const unsignedFile = path.join(rejected.evidenceDirectory, WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE);
  const falseClaim = JSON.parse(await readFile(unsignedFile, "utf8"));
  falseClaim.outcome = "passed";
  await writeJson(unsignedFile, falseClaim);
  await assert.rejects(
    () => importWindowsExternalEvidence(importOptions(rejected)),
    /without claiming verified signing/u,
  );
});
