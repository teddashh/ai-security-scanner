import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS,
  WINDOWS_INSTALLED_LIFECYCLE_RECORDS,
  summarizeWindowsInstalledLifecycleEvidence,
  validateWindowsInstalledLifecycleEvidence,
  verifyWindowsInstalledLifecycleEvidenceDirectory,
  verifyWindowsInstalledLifecycleEvidenceFile,
} from "../../scripts/release/windows-installed-lifecycle-evidence.mjs";

const commit = "01".repeat(20);
const artifact = {
  file: "ai-security-scanner_0.1.9_x64-setup.exe",
  bytes: 4096,
  sha256: "ab".repeat(32),
};
const runtimeManifest = {
  file: "managed-runtime-windows-x86_64.manifest.json",
  bytes: 2048,
  sha256: "cd".repeat(32),
  managementContractRevision: "2026-08-29.1",
};

function relatedArtifact(contract) {
  if (!contract.relatedArtifactRole) return null;
  return {
    role: contract.relatedArtifactRole,
    version: "0.1.8",
    tag: "v0.1.8",
    file: "ai-security-scanner_0.1.8_x64-setup.exe",
    bytes: 3072,
    sha256: "ef".repeat(32),
  };
}

function completedJourney(contract) {
  if (contract.rowId === "WL-12c") {
    return {
      disposition: "all-data-removal",
      installedDesktopUsed: false,
      target: null,
      taskExecutionState: "not-applicable",
      targetOutcome: null,
      durableReportId: null,
      durableReportState: null,
      projectReopened: false,
      export: null,
      finalCoverage: null,
    };
  }
  return {
    disposition: "completed",
    installedDesktopUsed: true,
    target: "127.0.0.1:9001",
    taskExecutionState: "executed",
    targetOutcome: "reachable",
    durableReportId: "11111111-2222-4333-8444-555555555555",
    durableReportState: "saved",
    projectReopened: true,
    export: {
      format: "html",
      file: `report-${contract.rowId.toLowerCase()}.html`,
      bytes: 1024,
      sha256: "12".repeat(32),
      outcome: "exported-and-opened-readable",
    },
    finalCoverage: {
      state: "complete",
      testedCount: 1,
      notTestedCount: 0,
      failedCount: 0,
      coverageGapCount: 0,
    },
  };
}

function passingRecord(contract) {
  const startedAt = "2026-09-06T12:00:00Z";
  const endedAt = "2026-09-06T12:30:00Z";
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
      version: "0.1.9",
      tag: "v0.1.9",
      sourceCommit: commit,
      releaseChannel: "prerelease",
    },
    artifact: { ...artifact },
    runtimeManifest: { ...runtimeManifest },
    relatedArtifact: relatedArtifact(contract),
    environment: {
      profileId: "reference-windows-x86-64",
      windowsEdition: "Windows 11 Pro",
      windowsVersion: "24H2",
      windowsBuild: "26100",
      architecture: "x86_64",
      accountPrivilege: "standard-user",
      uacState: "enabled",
      virtualizationCapability: "available",
      cases: contract.cases.map((caseId, index) => ({
        caseId,
        snapshotId: `${contract.rowId.toLowerCase()}-snapshot-${index + 1}`,
        initialState: `Frozen initial state for ${caseId}`,
      })),
    },
    harness: {
      kind: "checked-in-version-pinned",
      repository: "teddashh/ai-security-scanner",
      sourceCommit: commit,
      path: "scripts/release/qualify-windows-installed-lifecycle.ps1",
      sha256: "34".repeat(32),
      contractVersion: 1,
    },
    execution: {
      startedAt,
      endedAt,
      excludedOperatingSystemRestartSeconds: contract.rowId === "WL-03" ? 300 : 0,
      secureDesktopControl: "not-present",
      localhostStartControl: contract.rowId === "WL-12c" ? "not-applicable" : "human",
      administratorCredentialSharedWithAgent: false,
      visibleDecisions: [],
      visibleWarnings: [],
      visibleErrors: [],
      retryCount: 0,
      interruptions: [],
    },
    outcome: "passed",
    reasonCode: null,
    reason: null,
    checks: contract.checks.map(({ caseId, id }) => ({
      caseId,
      id,
      state: "passed",
      observedAt: "2026-09-06T12:15:00Z",
      detail: `Observed ${id}`,
    })),
    installedAppJourney: completedJourney(contract),
    cleanup: {
      planInspected: true,
      allDataRemovalConfirmedByOwner: contract.rowId === "WL-12c",
      outcome: "completed",
      ambiguousOrUnrelatedStatePreserved: true,
      unresolvedObligations: [],
    },
    observedAt: "2026-09-06T12:31:00Z",
  };
}

function notObservedRecord(contract) {
  const record = passingRecord(contract);
  record.relatedArtifact = null;
  record.environment = null;
  record.harness = null;
  record.execution = null;
  record.outcome = "not-observed";
  record.reasonCode = "not-scheduled";
  record.reason = "This exact row was not scheduled.";
  record.checks = record.checks.map((item) => ({
    ...item,
    state: "not-observed",
    observedAt: null,
    detail: "Required observation was not scheduled.",
  }));
  record.installedAppJourney = null;
  record.cleanup = null;
  return record;
}

test("the public registry has exactly the 15 documented rows and only canonical lifecycle boundaries", () => {
  assert.deepEqual(
    WINDOWS_INSTALLED_LIFECYCLE_RECORDS.map(({ rowId }) => rowId),
    ["WL-01", "WL-02", "WL-03", "WL-04", "WL-05", "WL-06", "WL-07", "WL-08", "WL-09", "WL-10", "WL-11", "WL-12a", "WL-12b", "WL-12c", "WL-13"],
  );
  assert.equal(new Set(WINDOWS_INSTALLED_LIFECYCLE_RECORDS.map(({ path: file }) => file)).size, 15);
  assert.deepEqual(
    [...new Set(WINDOWS_INSTALLED_LIFECYCLE_RECORDS.map(({ boundary }) => boundary))].sort(),
    [
      "installer_runtime_cache_seed",
      "installer_same_version_repair",
      "packaged_component_auto_recovery",
      "runtime_reconciliation",
    ].sort(),
  );
});

test("one passing row is strict and bound to the exact installer and runtime manifest", () => {
  const record = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0]);
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(record, {
    version: "0.1.9",
    tag: "v0.1.9",
    commit,
    releaseChannel: "prerelease",
    artifact,
    runtimeManifest,
  }));

  const wrongArtifact = structuredClone(record);
  wrongArtifact.artifact.sha256 = "ff".repeat(32);
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(wrongArtifact, { artifact }),
    /differs from the expected exact bytes/u,
  );

  const extraField = structuredClone(record);
  extraField.unreviewedClaim = true;
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(extraField),
    /fields are not the Windows installed-lifecycle schema-v1 set/u,
  );

  const wrongBoundary = structuredClone(record);
  wrongBoundary.boundary = "runtime_reconciliation";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(wrongBoundary),
    /boundary does not match/u,
  );
});

test("ordered cases and checks cannot impersonate another row or hide an unpassed requirement", () => {
  const record = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[5]);
  [record.checks[0], record.checks[1]] = [record.checks[1], record.checks[0]];
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(record),
    /checks are incomplete, out of order/u,
  );

  const incomplete = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[8]);
  incomplete.checks.at(-1).state = "not-observed";
  incomplete.checks.at(-1).observedAt = null;
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(incomplete),
    /passing outcome has an unpassed required check/u,
  );
});

test("not-observed N-1 upgrade and downgrade records remain representable without fabricated related artifacts", () => {
  for (const rowId of ["WL-10", "WL-11"]) {
    const contract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find((item) => item.rowId === rowId);
    assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(notObservedRecord(contract)));
  }
});

test("failed and inconclusive outcomes must agree with their exact check states", () => {
  const contract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0];
  const failed = passingRecord(contract);
  failed.outcome = "failed";
  failed.reasonCode = "product-behavior-failed";
  failed.reason = "The installed application did not complete the required row.";
  failed.checks[0].state = "failed";
  failed.installedAppJourney = null;
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(failed));

  const dishonestFailure = structuredClone(failed);
  dishonestFailure.checks[0].state = "passed";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(dishonestFailure),
    /failed outcome has no failed required check/u,
  );

  const inconclusive = passingRecord(contract);
  inconclusive.outcome = "inconclusive";
  inconclusive.reasonCode = "evidence-chain-incomplete";
  inconclusive.reason = "One required observation was not retained.";
  inconclusive.checks[0].state = "not-observed";
  inconclusive.checks[0].observedAt = null;
  inconclusive.installedAppJourney = null;
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(inconclusive));

  inconclusive.checks[1].state = "failed";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(inconclusive),
    /inconclusive outcome has a product failure/u,
  );
});

test("aggregate becomes verified only when all 15 exact row-boundary records pass", () => {
  const all = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.map(passingRecord);
  assert.deepEqual(summarizeWindowsInstalledLifecycleEvidence(all), {
    state: "verified",
    requiredCount: 15,
    presentCount: 15,
    passedCount: 15,
    failedCount: 0,
    inconclusiveCount: 0,
    notObservedCount: 0,
    missingKeys: [],
  });

  const partial = summarizeWindowsInstalledLifecycleEvidence(all.slice(0, -1));
  assert.equal(partial.state, "partial");
  assert.equal(partial.missingKeys.length, 1);

  const failed = structuredClone(all);
  failed[0].outcome = "failed";
  failed[0].reasonCode = "product-behavior-failed";
  failed[0].reason = "The first row failed.";
  failed[0].checks[0].state = "failed";
  failed[0].installedAppJourney = null;
  assert.equal(summarizeWindowsInstalledLifecycleEvidence(failed).state, "failed");

  assert.equal(summarizeWindowsInstalledLifecycleEvidence([]).state, "not-observed");
  assert.equal(
    summarizeWindowsInstalledLifecycleEvidence(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.map(notObservedRecord)).state,
    "not-observed",
  );
});

test("aggregate rejects duplicate keys and records from a different candidate", () => {
  const first = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0]);
  assert.throws(
    () => summarizeWindowsInstalledLifecycleEvidence([first, structuredClone(first)]),
    /duplicate Windows installed-lifecycle record/u,
  );

  const second = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[1]);
  second.artifact.sha256 = "ff".repeat(32);
  assert.throws(
    () => summarizeWindowsInstalledLifecycleEvidence([first, second]),
    /belongs to a different exact candidate/u,
  );
});

test("file and directory verifiers accept only bounded canonical record paths", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "windows-lifecycle-evidence-"));
  try {
    const contract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0];
    const canonical = WINDOWS_INSTALLED_LIFECYCLE_RECORDS[0];
    const directory = path.join(temporary, path.dirname(canonical.path));
    await mkdir(directory, { recursive: true });
    const file = path.join(temporary, canonical.path);
    await writeFile(file, `${JSON.stringify(passingRecord(contract), null, 2)}\n`);
    const record = await verifyWindowsInstalledLifecycleEvidenceFile(file, { artifact, runtimeManifest });
    assert.equal(record.rowId, "WL-01");
    const verified = await verifyWindowsInstalledLifecycleEvidenceDirectory(temporary, { artifact, runtimeManifest });
    assert.equal(verified.records.length, 1);
    assert.equal(verified.summary.state, "partial");

    await writeFile(path.join(temporary, "unexpected.json"), "{}\n");
    await assert.rejects(
      () => verifyWindowsInstalledLifecycleEvidenceDirectory(temporary),
      /unexpected lifecycle evidence path/u,
    );
    await rm(path.join(temporary, "unexpected.json"));

    await symlink(file, path.join(temporary, "linked.json"));
    await assert.rejects(
      () => verifyWindowsInstalledLifecycleEvidenceDirectory(temporary),
      /contains a symlink/u,
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
