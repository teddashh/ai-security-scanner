import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES,
  WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS,
  WINDOWS_INSTALLED_LIFECYCLE_RECORDS,
  WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY,
  summarizeWindowsInstalledLifecycleEvidence,
  validateWindowsInstalledLifecycleEvidence,
  verifyWindowsInstalledLifecycleEvidenceDirectory,
  verifyWindowsInstalledLifecycleEvidenceFile,
} from "../../scripts/release/windows-installed-lifecycle-evidence.mjs";
import { WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY } from "../../scripts/release/windows-localhost-fixture.mjs";

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
    targetOutcome: contract.rowId === "WL-13" ? "reachable" : "closed",
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
      path: contract.rowId === "WL-13"
        ? WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.path
        : "scripts/release/qualify-windows-installed-lifecycle.ps1",
      sha256: contract.rowId === "WL-13"
        ? WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.sha256
        : "34".repeat(32),
      contractVersion: 1,
      fixtureRuntime: contract.rowId === "WL-13"
        ? structuredClone(WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY)
        : null,
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

test("lifecycle evidence accepts only real canonical UTC timestamps at nanosecond order", () => {
  const valid = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0]);
  valid.execution.startedAt = "2026-09-06T12:00:00.000000001Z";
  valid.checks.forEach((check) => {
    check.observedAt = "2026-09-06T12:00:00.000000002+00:00";
  });
  valid.execution.endedAt = "2026-09-06T12:00:00.000000003Z";
  valid.observedAt = "2026-09-06T12:00:00.000000004Z";
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(valid));

  const reversed = structuredClone(valid);
  reversed.execution.startedAt = "2026-09-06T12:00:00.000000002Z";
  reversed.execution.endedAt = "2026-09-06T12:00:00.000000001Z";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(reversed),
    /ends before it starts/u,
  );

  for (const observedAt of [
    "2026-02-30T12:00:00Z",
    "09/06/2026 12:00:00Z",
    "2026-09-06T12:00:00",
    "2026-09-06T12:00:00Z\0",
  ]) {
    const invalid = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0]);
    invalid.observedAt = observedAt;
    assert.throws(
      () => validateWindowsInstalledLifecycleEvidence(invalid),
      /canonical UTC timestamp|real UTC instant/u,
    );
  }
});

test("WL-13 is bound to the exact approved Windows fixture runtime", () => {
  const contract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find(({ rowId }) => rowId === "WL-13");
  const record = passingRecord(contract);
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(record));

  const absent = structuredClone(record);
  absent.harness.fixtureRuntime = null;
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(absent),
    /WL-13 has no approved fixed fixture runtime/u,
  );

  const mismatched = structuredClone(record);
  mismatched.harness.fixtureRuntime.version = "v24.16.0";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(mismatched),
    /differs from the approved fixed runtime policy/u,
  );

  const wrongPath = structuredClone(record);
  wrongPath.harness.path = "scripts/release/another-fixture.mjs";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(wrongPath),
    /exact reviewed localhost fixture path/u,
  );

  const wrongDigest = structuredClone(record);
  wrongDigest.harness.sha256 = "ff".repeat(32);
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(wrongDigest),
    /localhost fixture digest differs from policy/u,
  );

  const closed = structuredClone(record);
  closed.installedAppJourney.targetOutcome = "closed";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(closed),
    /WL-13 must observe the real reachable Windows-host fixture/u,
  );

  const reordered = structuredClone(record);
  const runtime = reordered.harness.fixtureRuntime;
  reordered.harness.fixtureRuntime = {
    executable: {
      sha256: runtime.executable.sha256,
      bytes: runtime.executable.bytes,
      file: runtime.executable.file,
    },
    architecture: runtime.architecture,
    platform: runtime.platform,
    distribution: {
      sha256: runtime.distribution.sha256,
      bytes: runtime.distribution.bytes,
      file: runtime.distribution.file,
    },
    version: runtime.version,
    name: runtime.name,
  };
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(reordered, {
    harness: { fixtureRuntime: structuredClone(WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY) },
  }));
});

test("protected-policy mode rejects observed rows without an approved checked-in harness", () => {
  const contract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find(({ rowId }) => rowId === "WL-01");
  const observed = passingRecord(contract);
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(observed, {
      requireApprovedHarness: true,
      harnesses: WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES,
    }),
    /WL-01 has no approved checked-in lifecycle harness policy/u,
  );

  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(notObservedRecord(contract), {
    requireApprovedHarness: true,
    harnesses: WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES,
  }));
});

test("protected-policy mode pins the complete approved WL-13 harness identity", () => {
  const contract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find(({ rowId }) => rowId === "WL-13");
  const record = passingRecord(contract);
  record.harness = structuredClone(WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES["WL-13"]);
  const expected = {
    requireApprovedHarness: true,
    harnesses: WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES,
  };
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(record, expected));

  const mutations = [
    ["repository", (value) => { value.harness.repository = "example/other"; }],
    ["source commit", (value) => { value.harness.sourceCommit = "ff".repeat(20); }],
    ["path", (value) => { value.harness.path = "scripts/release/other-fixture.mjs"; }],
    ["script digest", (value) => { value.harness.sha256 = "ff".repeat(32); }],
    ["contract version", (value) => { value.harness.contractVersion = 2; }],
    ["Node version", (value) => { value.harness.fixtureRuntime.version = "v24.16.0"; }],
    ["Node archive filename", (value) => { value.harness.fixtureRuntime.distribution.file = "node-other.zip"; }],
    ["Node archive bytes", (value) => { value.harness.fixtureRuntime.distribution.bytes += 1; }],
    ["Node archive digest", (value) => { value.harness.fixtureRuntime.distribution.sha256 = "ff".repeat(32); }],
    ["Node executable filename", (value) => { value.harness.fixtureRuntime.executable.file = "other.exe"; }],
    ["Node executable bytes", (value) => { value.harness.fixtureRuntime.executable.bytes += 1; }],
    ["Node executable digest", (value) => { value.harness.fixtureRuntime.executable.sha256 = "ff".repeat(32); }],
  ];
  for (const [label, mutate] of mutations) {
    const changed = structuredClone(record);
    mutate(changed);
    assert.throws(
      () => validateWindowsInstalledLifecycleEvidence(changed, expected),
      undefined,
      label,
    );
  }
});

test("protected-policy mode pins the related installer version, role, and exact bytes", () => {
  const contract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find(({ rowId }) => rowId === "WL-10");
  const record = passingRecord(contract);
  const policy = {
    role: "n-minus-one-upgrade-source",
    version: "0.1.8",
    tag: "v0.1.8",
    file: record.relatedArtifact.file,
    bytes: record.relatedArtifact.bytes,
    sha256: record.relatedArtifact.sha256,
  };
  const expected = {
    requireApprovedRelatedArtifact: true,
    relatedArtifacts: { "WL-10": policy },
  };
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(record, expected));

  const wrongVersion = structuredClone(record);
  wrongVersion.relatedArtifact.version = "0.1.7";
  wrongVersion.relatedArtifact.tag = "v0.1.7";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(wrongVersion, expected),
    /related artifact version differs from policy/u,
  );
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(record, {
      requireApprovedRelatedArtifact: true,
      relatedArtifacts: {},
    }),
    /WL-10 has no approved related installer artifact policy/u,
  );
});

test("protected-policy mode keeps truthful not-observed rows policy-free and inert", () => {
  for (const rowId of ["WL-10", "WL-11", "WL-13"]) {
    const contract = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find((item) => item.rowId === rowId);
    assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(notObservedRecord(contract), {
      requireApprovedHarness: true,
      harnesses: WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES,
      requireApprovedRelatedArtifact: true,
      relatedArtifacts: {},
    }), rowId);
  }
});

test("the WL-13 localhost fixture identity is rejected from every other lifecycle row", () => {
  const record = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0]);
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(record));

  const fixtureRuntime = structuredClone(record);
  fixtureRuntime.harness.fixtureRuntime = structuredClone(WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY);
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(fixtureRuntime),
    /must not claim the WL-13-only fixture runtime/u,
  );

  const fixturePath = structuredClone(record);
  fixturePath.harness.path = WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.path;
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(fixturePath),
    /must not claim the WL-13-only localhost fixture path/u,
  );

  const fixtureDigest = structuredClone(record);
  fixtureDigest.harness.sha256 = WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.sha256;
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(fixtureDigest),
    /must not claim the WL-13-only localhost fixture digest/u,
  );
});

test("the JSON schema mirrors the inverse WL-13 reachable requirement", async () => {
  const schema = JSON.parse(await readFile(
    new URL("../../docs/release/windows-installed-lifecycle-evidence.schema.json", import.meta.url),
    "utf8",
  ));
  const condition = schema.allOf.find((entry) => (
    entry.if?.allOf?.some((part) => part.properties?.rowId?.const === "WL-13")
    && entry.if?.allOf?.some((part) => part.properties?.outcome?.const === "passed")
    && entry.then?.properties?.installedAppJourney?.allOf?.some(
      (part) => part.properties?.targetOutcome?.const === "reachable",
    )
  ));
  assert.ok(condition, "schema must require passed WL-13 evidence to report reachable");
});

test("the JSON schema reserves every WL-13 fixture coordinate to WL-13", async () => {
  const schema = JSON.parse(await readFile(
    new URL("../../docs/release/windows-installed-lifecycle-evidence.schema.json", import.meta.url),
    "utf8",
  ));
  const condition = schema.allOf.find((entry) => (
    entry.if?.properties?.rowId?.not?.const === "WL-13"
  ));
  const objectHarness = condition?.then?.properties?.harness?.oneOf?.find((entry) => (
    Array.isArray(entry.allOf)
  ));
  const inverse = objectHarness?.allOf?.find((entry) => entry.properties?.fixtureRuntime);

  assert.deepEqual(inverse?.properties, {
    path: { not: { const: WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.path } },
    sha256: { not: { const: WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.sha256 } },
    fixtureRuntime: { const: null },
  });
});

test("the JSON schema mirrors the canonical UTC timestamp boundary", async () => {
  const schema = JSON.parse(await readFile(
    new URL("../../docs/release/windows-installed-lifecycle-evidence.schema.json", import.meta.url),
    "utf8",
  ));
  const dateTime = schema.$defs?.dateTime;
  const pattern = new RegExp(dateTime?.pattern, "u");

  assert.equal(dateTime?.format, "date-time");
  assert.equal(pattern.test("2026-09-06T12:00:00.123456789Z"), true);
  assert.equal(pattern.test("2026-09-06T12:00:00+00:00"), true);
  assert.equal(pattern.test("2000-02-29T12:00:00Z"), true);
  assert.equal(pattern.test("2024-02-29T12:00:00Z"), true);
  assert.equal(pattern.test("2400-02-29T12:00:00Z"), true);
  for (const invalid of [
    "2026-02-30T12:00:00Z",
    "2026-04-31T12:00:00Z",
    "2023-02-29T12:00:00Z",
    "2100-02-29T12:00:00Z",
    "09/06/2026 12:00:00Z",
    "2026-09-06T12:00:00",
    "2026-09-06T12:00:00-04:00",
    "2026-09-06T12:00:00Z\0",
  ]) assert.equal(pattern.test(invalid), false, invalid);
});

test("reachable is reserved for the exact WL-13 fixture boundary", () => {
  const record = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0]);
  record.installedAppJourney.targetOutcome = "reachable";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(record),
    /cannot claim the fixture-only reachable outcome/u,
  );
});

test("an explicitly authorized agent may control localhost Start only for an applicable lifecycle row", () => {
  const agentOperated = passingRecord(WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS[0]);
  agentOperated.execution.localhostStartControl = "agent-with-explicit-user-authorization";
  assert.doesNotThrow(() => validateWindowsInstalledLifecycleEvidence(agentOperated));

  const unknownControl = structuredClone(agentOperated);
  unknownControl.execution.localhostStartControl = "agent-with-implied-authorization";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(unknownControl),
    /localhost Start control is invalid/u,
  );

  const unclaimedStart = structuredClone(agentOperated);
  unclaimedStart.execution.localhostStartControl = "not-applicable";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(unclaimedStart),
    /Start was not controlled by a human or an explicitly authorized agent/u,
  );

  const destructiveRow = passingRecord(
    WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find(({ rowId }) => rowId === "WL-12c"),
  );
  destructiveRow.execution.localhostStartControl = "agent-with-explicit-user-authorization";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(destructiveRow),
    /WL-12c incorrectly claims a localhost Start action/u,
  );

  for (const outcome of ["failed", "inconclusive"]) {
    const nonPassingDestructiveRow = passingRecord(
      WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find(({ rowId }) => rowId === "WL-12c"),
    );
    nonPassingDestructiveRow.outcome = outcome;
    nonPassingDestructiveRow.reasonCode = outcome === "failed"
      ? "cleanup-failed"
      : "required-observation-unavailable";
    nonPassingDestructiveRow.reason = `WL-12c ${outcome} after execution.`;
    nonPassingDestructiveRow.installedAppJourney = null;
    nonPassingDestructiveRow.checks[0].state = outcome === "failed" ? "failed" : "not-observed";
    if (outcome === "inconclusive") nonPassingDestructiveRow.checks[0].observedAt = null;
    nonPassingDestructiveRow.execution.localhostStartControl = "agent-with-explicit-user-authorization";
    assert.throws(
      () => validateWindowsInstalledLifecycleEvidence(nonPassingDestructiveRow),
      /WL-12c incorrectly claims a localhost Start action/u,
    );

    nonPassingDestructiveRow.execution.localhostStartControl = "not-applicable";
    nonPassingDestructiveRow.cleanup.allDataRemovalConfirmedByOwner = false;
    assert.throws(
      () => validateWindowsInstalledLifecycleEvidence(nonPassingDestructiveRow),
      /WL-12c has no explicit owner confirmation/u,
    );
  }

  const agentSecureDesktop = structuredClone(agentOperated);
  agentSecureDesktop.execution.secureDesktopControl = "agent-with-explicit-user-authorization";
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(agentSecureDesktop),
    /secure-desktop control is invalid/u,
  );

  const sharedCredential = structuredClone(agentOperated);
  sharedCredential.execution.administratorCredentialSharedWithAgent = true;
  assert.throws(
    () => validateWindowsInstalledLifecycleEvidence(sharedCredential),
    /exposed an administrator credential to the agent/u,
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

    await symlink(
      directory,
      path.join(temporary, "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await assert.rejects(
      () => verifyWindowsInstalledLifecycleEvidenceDirectory(temporary),
      /contains a symlink/u,
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
