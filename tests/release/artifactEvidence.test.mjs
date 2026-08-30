import assert from "node:assert/strict";
import test from "node:test";

import { validateBoundArtifactEvidence } from "../../scripts/release/artifact-evidence.mjs";

const artifact = {
  file: "ai-security-scanner_0.1.8_x64-setup.exe",
  bytes: 4096,
  sha256: "ab".repeat(32),
};

const expected = {
  evidenceType: "beginner-human-path",
  platform: "windows-x86_64",
  installerType: "nsis",
  version: "0.1.8",
  tag: "v0.1.8",
  commit: "01".repeat(20),
  artifact,
};

function humanEvidence() {
  return {
    schemaVersion: 1,
    evidenceType: "beginner-human-path",
    product: "ai-security-scanner",
    platform: "windows-x86_64",
    installerType: "nsis",
    releaseIdentity: {
      version: "0.1.8",
      tag: "v0.1.8",
      sourceCommit: "01".repeat(20),
    },
    artifact: { ...artifact },
    outcome: "passed",
    observedAt: "2026-08-30T12:00:00Z",
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

test("first report alone is subject to the ten-minute beginner bound", () => {
  const evidence = humanEvidence();
  assert.equal(evidence.details.totalJourneyElapsedSeconds, 3_600);
  assert.doesNotThrow(() => validateBoundArtifactEvidence(evidence, expected));
  evidence.details.firstReportElapsedSeconds = 601;
  assert.throws(
    () => validateBoundArtifactEvidence(evidence, expected),
    /first durable report within ten minutes/u,
  );
});

test("human evidence binds exact artifact, release, decisions, errors, coverage, and localhost outcome", () => {
  const evidence = humanEvidence();
  evidence.artifact.sha256 = "cd".repeat(32);
  assert.throws(() => validateBoundArtifactEvidence(evidence, expected), /artifact identity mismatch/u);

  const missingCoverage = humanEvidence();
  delete missingCoverage.details.finalCoverage;
  assert.throws(
    () => validateBoundArtifactEvidence(missingCoverage, expected),
    /fields are not the artifact-evidence schema-v1 set/u,
  );

  const tooManyDecisions = humanEvidence();
  tooManyDecisions.details.userDecisions = Array.from({ length: 4 }, (_, index) => `Decision ${index}`);
  assert.throws(() => validateBoundArtifactEvidence(tooManyDecisions, expected), /at most 3 entries/u);

  const missingStart = humanEvidence();
  missingStart.details.userDecisions = ["install", "approve-windows-prompt"];
  assert.throws(() => validateBoundArtifactEvidence(missingStart, expected), /fixed beginner path/u);
});

test("beginner evidence forbids rehearsed participants, facilitator operation, Terminal, and typed commands", () => {
  for (const [field, value, pattern] of [
    ["participantBuiltProduct", true, /participant built the product/u],
    ["participantContributedToProduct", true, /participant contributed/u],
    ["participantRehearsedSetup", true, /participant rehearsed/u],
    ["facilitatorTookControl", true, /facilitator took control/u],
    ["facilitatorDictatedOperationalSteps", true, /facilitator dictated/u],
    ["facilitatorAdministeredWsl", true, /facilitator administered WSL/u],
    ["terminalOpened", true, /open Terminal/u],
    ["typedCommandCount", 1, /type a command/u],
  ]) {
    const evidence = humanEvidence();
    evidence.details[field] = value;
    assert.throws(() => validateBoundArtifactEvidence(evidence, expected), pattern);
  }
});

test("first-report timing reconciles installer launch, durable save, and only OS restart downtime", () => {
  const wrongBasis = humanEvidence();
  wrongBasis.details.firstReportTimingBasis = "app-launch-to-report-view";
  assert.throws(() => validateBoundArtifactEvidence(wrongBasis, expected), /installer launch to durable report/u);

  const unreconciled = humanEvidence();
  unreconciled.details.firstReportWallClockElapsedSeconds += 1;
  assert.throws(() => validateBoundArtifactEvidence(unreconciled, expected), /sole restart exclusion/u);
});

test("localhost evidence records the observed TCP outcome and durable report identity", () => {
  for (const outcome of ["reachable", "closed", "timed_out", "unreachable"]) {
    const evidence = humanEvidence();
    evidence.details.localhostReport.outcome = outcome;
    if (["timed_out", "unreachable"].includes(outcome)) {
      evidence.details.finalCoverage = {
        state: "partial",
        testedCount: 0,
        notTestedCount: 0,
        failedCount: 0,
        coverageGapCount: 1,
      };
    }
    assert.doesNotThrow(() => validateBoundArtifactEvidence(evidence, expected));
  }

  const genericOutcome = humanEvidence();
  genericOutcome.details.localhostReport.outcome = "completed";
  assert.throws(() => validateBoundArtifactEvidence(genericOutcome, expected), /outcome is invalid/u);

  const notExecuted = humanEvidence();
  notExecuted.details.localhostReport.taskExecutionState = "planned";
  assert.throws(() => validateBoundArtifactEvidence(notExecuted, expected), /not actually executed/u);

  const missingDurableId = humanEvidence();
  missingDurableId.details.localhostReport.durableReportId = "not-a-report-id";
  assert.throws(() => validateBoundArtifactEvidence(missingDurableId, expected), /no durable report ID/u);

  const unsaved = humanEvidence();
  unsaved.details.localhostReport.durableReportState = "viewed-only";
  assert.throws(() => validateBoundArtifactEvidence(unsaved, expected), /not durably saved/u);
});

test("first-value evidence uses canonical master-report states and rejects zero completed checks", () => {
  const zeroChecks = humanEvidence();
  zeroChecks.details.finalCoverage = {
    state: "no-checks-completed",
    testedCount: 0,
    notTestedCount: 1,
    failedCount: 0,
    coverageGapCount: 1,
  };
  assert.throws(() => validateBoundArtifactEvidence(zeroChecks, expected), /did not complete any check/u);

  const driftedState = humanEvidence();
  driftedState.details.finalCoverage.state = "failed-with-report";
  assert.throws(() => validateBoundArtifactEvidence(driftedState, expected), /coverage state is invalid/u);
});

test("beginner evidence records a readable HTML export outcome, not only an export click", () => {
  const machineOnly = humanEvidence();
  machineOnly.details.readableExport.format = "json";
  assert.throws(() => validateBoundArtifactEvidence(machineOnly, expected), /not readable HTML/u);

  const notOpened = humanEvidence();
  notOpened.details.readableExport.outcome = "file-created";
  assert.throws(() => validateBoundArtifactEvidence(notOpened, expected), /not opened and observed as readable/u);
});

test("operating-system signing evidence is fully artifact and release bound", () => {
  const producer = {
    provider: "github-actions",
    repository: "teddashh/ai-security-scanner",
    workflow: ".github/workflows/windows-signing.yml",
    workflowRef: `teddashh/ai-security-scanner/.github/workflows/windows-signing.yml@${"01".repeat(20)}`,
    runId: "123456789",
    runAttempt: 1,
    job: "verify-authenticode",
    environment: "windows-code-signing",
  };
  const operatingSystemSigningPolicy = {
    allowedPublisherIdentities: ["CN=AI Security Scanner Release Signing, O=AI Defend Labs"],
    ...producer,
  };
  const signing = {
    schemaVersion: 1,
    evidenceType: "operating-system-code-signing",
    product: "ai-security-scanner",
    platform: "windows-x86_64",
    installerType: "nsis",
    releaseIdentity: {
      version: "0.1.8",
      tag: "v0.1.8",
      sourceCommit: "01".repeat(20),
    },
    artifact: { ...artifact },
    outcome: "passed",
    observedAt: "2026-08-30T12:00:00Z",
    details: {
      signatureScheme: "authenticode",
      signatureStatus: "Valid",
      artifactSha256: artifact.sha256,
      expectedPublisherIdentity: operatingSystemSigningPolicy.allowedPublisherIdentities[0],
      observedPublisherIdentity: operatingSystemSigningPolicy.allowedPublisherIdentities[0],
      verificationTool: "Get-AuthenticodeSignature",
      producer: { ...producer },
    },
  };
  assert.doesNotThrow(() => validateBoundArtifactEvidence(signing, {
    ...expected,
    evidenceType: "operating-system-code-signing",
    operatingSystemSigningPolicy,
  }));
  signing.releaseIdentity.sourceCommit = "ff".repeat(20);
  assert.throws(
    () => validateBoundArtifactEvidence(signing, {
      ...expected,
      evidenceType: "operating-system-code-signing",
      operatingSystemSigningPolicy,
    }),
    /release identity mismatch/u,
  );
});

test("Authenticode evidence cannot promote fixture strings without protected producer policy", () => {
  const producer = {
    provider: "github-actions",
    repository: "teddashh/ai-security-scanner",
    workflow: ".github/workflows/windows-signing.yml",
    workflowRef: `teddashh/ai-security-scanner/.github/workflows/windows-signing.yml@${"01".repeat(20)}`,
    runId: "123456789",
    runAttempt: 1,
    job: "verify-authenticode",
    environment: "windows-code-signing",
  };
  const signing = {
    schemaVersion: 1,
    evidenceType: "operating-system-code-signing",
    product: "ai-security-scanner",
    platform: "windows-x86_64",
    installerType: "nsis",
    releaseIdentity: { version: "0.1.8", tag: "v0.1.8", sourceCommit: "01".repeat(20) },
    artifact: { ...artifact },
    outcome: "passed",
    observedAt: "2026-08-30T12:00:00Z",
    details: {
      signatureScheme: "authenticode",
      signatureStatus: "Valid",
      artifactSha256: artifact.sha256,
      expectedPublisherIdentity: "CN=Fixture",
      observedPublisherIdentity: "CN=Fixture",
      verificationTool: "Get-AuthenticodeSignature",
      producer,
    },
  };
  const signingExpected = { ...expected, evidenceType: "operating-system-code-signing" };
  assert.throws(
    () => validateBoundArtifactEvidence(signing, signingExpected),
    /no configured protected Authenticode producer policy/u,
  );

  const policy = { allowedPublisherIdentities: ["CN=Real Publisher"], ...producer };
  assert.throws(
    () => validateBoundArtifactEvidence(signing, { ...signingExpected, operatingSystemSigningPolicy: policy }),
    /not in the bounded release allowlist/u,
  );
  signing.details.expectedPublisherIdentity = "CN=Real Publisher";
  signing.details.observedPublisherIdentity = "CN=Real Publisher";
  signing.details.producer.job = "fixture-job";
  assert.throws(
    () => validateBoundArtifactEvidence(signing, { ...signingExpected, operatingSystemSigningPolicy: policy }),
    /protected producer job differs/u,
  );
  signing.details.producer.job = producer.job;
  signing.details.artifactSha256 = "ff".repeat(32);
  assert.throws(
    () => validateBoundArtifactEvidence(signing, { ...signingExpected, operatingSystemSigningPolicy: policy }),
    /not bound to the installer digest/u,
  );
});
