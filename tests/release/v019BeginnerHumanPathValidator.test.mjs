import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, link, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const validatorName = "validate-v019-beginner-human-path.mjs";
const evidenceName = "human-path-qualification-windows-x86_64-nsis.json";
const portableSources = [
  validatorName,
  "artifact-evidence.mjs",
  "utc-timestamp.mjs",
];

function validEvidence() {
  return {
    schemaVersion: 1,
    evidenceType: "beginner-human-path",
    product: "ai-security-scanner",
    platform: "windows-x86_64",
    installerType: "nsis",
    releaseIdentity: {
      version: "0.1.9",
      tag: "v0.1.9",
      sourceCommit: "5c95572f54220adbd170d9bfb5af3159c56708ef",
    },
    artifact: {
      file: "ai-security-scanner_0.1.9_x64-setup.exe",
      bytes: 40_186_968,
      sha256: "f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e",
    },
    outcome: "passed",
    observedAt: "2026-09-07T16:30:00.123456789Z",
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
      firstReportElapsedSeconds: 420,
      firstReportWallClockElapsedSeconds: 720,
      excludedOperatingSystemRestartSeconds: 300,
      totalJourneyElapsedSeconds: 1_200,
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
        state: "partial",
        testedCount: 1,
        notTestedCount: 1,
        failedCount: 0,
        coverageGapCount: 1,
      },
      localhostReport: {
        target: "127.0.0.1:9001",
        taskExecutionState: "executed",
        outcome: "closed",
        findingCount: 0,
        durableReportId: "11111111-2222-4333-8444-555555555555",
        durableReportState: "saved",
      },
    },
  };
}

async function portableFixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), "v019-beginner-validator-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "redacted-output"));
  await Promise.all(portableSources.map((file) => copyFile(
    path.join(projectRoot, "scripts", "release", file),
    path.join(root, file),
  )));
  return root;
}

async function writeEvidence(root, evidence) {
  const contents = `${JSON.stringify(evidence, null, 2)}\n`;
  await writeFile(path.join(root, "redacted-output", evidenceName), contents, "utf8");
  return Buffer.from(contents);
}

function runValidator(root, args = []) {
  return spawnSync(process.execPath, [path.join(root, validatorName), ...args], {
    cwd: root,
    encoding: "utf8",
  });
}

function failedSummary(result, expectedCode) {
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  const summary = JSON.parse(result.stderr);
  assert.deepEqual(summary, {
    lane: "BEGINNER",
    localValidator: "failed",
    evidenceClaim: "not-accepted-locally",
    errorCode: expectedCode,
  });
}

test("parameterless v0.1.9 beginner validator accepts one exact passing record and emits only a safe summary", async (t) => {
  const root = await portableFixture(t);
  const bytes = await writeEvidence(root, validEvidence());
  const result = runValidator(root);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const summary = JSON.parse(result.stdout);
  assert.deepEqual(summary, {
    lane: "BEGINNER",
    localValidator: "passed",
    evidenceFile: evidenceName,
    evidenceBytes: bytes.length,
    evidenceSha256: createHash("sha256").update(bytes).digest("hex"),
  });
  assert.doesNotMatch(result.stdout, /Windows 11|11111111-2222|participantProfile/u);
});

test("v0.1.9 beginner validator rejects the wrong release or installer identity", async (t) => {
  const root = await portableFixture(t);
  const mutations = [
    (evidence) => { evidence.releaseIdentity.sourceCommit = "01".repeat(20); },
    (evidence) => { evidence.artifact.file = "another-installer.exe"; },
    (evidence) => { evidence.artifact.bytes += 1; },
    (evidence) => { evidence.artifact.sha256 = "ab".repeat(32); },
  ];
  for (const mutate of mutations) {
    const evidence = validEvidence();
    mutate(evidence);
    await writeEvidence(root, evidence);
    failedSummary(runValidator(root), "EVIDENCE_SCHEMA_INVALID");
  }
});

test("v0.1.9 beginner validator rejects noncanonical or impossible timestamps", async (t) => {
  const root = await portableFixture(t);
  for (const observedAt of ["2026-02-30T12:00:00Z", "2026-09-07T12:00:00"]) {
    const evidence = validEvidence();
    evidence.observedAt = observedAt;
    await writeEvidence(root, evidence);
    failedSummary(runValidator(root), "EVIDENCE_SCHEMA_INVALID");
  }
});

test("v0.1.9 beginner validator rejects every extra redacted-output entry", async (t) => {
  const root = await portableFixture(t);
  await writeEvidence(root, validEvidence());
  await writeFile(path.join(root, "redacted-output", "notes.txt"), "not importable\n", "utf8");

  failedSummary(runValidator(root), "REDACTED_OUTPUT_INVENTORY_INVALID");
});

test("v0.1.9 beginner validator rejects a multiply linked canonical record", async (t) => {
  const root = await portableFixture(t);
  await writeEvidence(root, validEvidence());
  try {
    await link(
      path.join(root, "redacted-output", evidenceName),
      path.join(root, "private-copy.json"),
    );
  } catch (error) {
    if (["EPERM", "ENOSYS", "EACCES"].includes(error?.code)) {
      t.skip(`hard links unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  failedSummary(runValidator(root), "EVIDENCE_FILE_INVALID");
});

test("v0.1.9 beginner validator rejects assisted and nonpassing records", async (t) => {
  const root = await portableFixture(t);

  const assisted = validEvidence();
  assisted.details.facilitatorTookControl = true;
  await writeEvidence(root, assisted);
  failedSummary(runValidator(root), "EVIDENCE_SCHEMA_INVALID");

  const nonpassing = validEvidence();
  nonpassing.outcome = "failed";
  await writeEvidence(root, nonpassing);
  failedSummary(runValidator(root), "EVIDENCE_SCHEMA_INVALID");
});

test("v0.1.9 beginner validator rejects command-line path or identity overrides", async (t) => {
  const root = await portableFixture(t);
  await writeEvidence(root, validEvidence());

  failedSummary(runValidator(root, ["--dir", "somewhere-else"]), "ARGUMENT_OVERRIDE_REJECTED");
});

test("v0.1.9 beginner handoff freezes the two-payload observer contract without shipping a passing record", async () => {
  const handoff = await readFile(
    path.join(projectRoot, "docs", "release", "v0.1.9-windows-beginner-handoff.zh-TW.md"),
    "utf8",
  );
  for (const required of [
    "Clean BEGINNER guest payload",
    "Observer payload",
    "5c95572f54220adbd170d9bfb5af3159c56708ef",
    "34096606710",
    "10010021177",
    "sha256:758e86e59ef2f033847f67009173196d320a2e04d5e9c0f1e2369fb3a3b238fb",
    "f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e",
    "請安裝 ai-security-scanner，並用它檢查這台電腦的 127.0.0.1:9001。",
    "Participant 一啟動 installer，Codex／facilitator 立即切換為 observe-only",
    "validate-v019-beginner-human-path.mjs",
    "v0.1.9-windows-external-candidate-identity.json",
  ]) {
    assert.match(handoff, new RegExp(required.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }
  assert.doesNotMatch(handoff, /"evidenceType"\s*:\s*"beginner-human-path"/u);
  assert.doesNotMatch(handoff, /CANDIDATE_HANDOFF_|REQUESTED_LANE|V0\.1\.9_RELEASE_URL/u);

  const identity = JSON.parse(await readFile(
    path.join(projectRoot, "docs", "release", "v0.1.9-windows-external-candidate-identity.json"),
    "utf8",
  ));
  assert.equal(identity.notImportableEvidence, true);
  assert.equal(identity.releaseIdentity.sourceCommit, "5c95572f54220adbd170d9bfb5af3159c56708ef");
  assert.deepEqual(identity.windowsNsis, {
    platform: "windows-x86_64",
    architecture: "x86_64",
    installerType: "nsis",
    file: "ai-security-scanner_0.1.9_x64-setup.exe",
    bytes: 40_186_968,
    sha256: "f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e",
    downloadUrl:
      "https://github.com/teddashh/ai-security-scanner/releases/download/v0.1.9/ai-security-scanner_0.1.9_x64-setup.exe",
  });
  assert.equal(identity.scope.mayModifyPublishedRelease, false);
});
