import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES,
  WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS,
} from "../../scripts/release/windows-installed-lifecycle-evidence.mjs";
import {
  V019_WL13_EVIDENCE_POLICY,
  validateV019Wl13ObservationAtRoot,
} from "../../scripts/release/validate-v019-wl13-observation.mjs";

const WL13_CONTRACT = WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS.find(({ rowId }) => rowId === "WL-13");
const RECORD_RELATIVE_PATH = "redacted-output/windows-installed-lifecycle/wl-13/runtime_reconciliation.json";
const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const VALIDATOR_RELATIVE_PATH = "scripts/release/validate-v019-wl13-observation.mjs";
const PORTABLE_SOURCE_FILES = [
  "validate-v019-wl13-observation.mjs",
  "windows-installed-lifecycle-evidence.mjs",
  "windows-localhost-fixture.mjs",
  "lib.mjs",
  "utc-timestamp.mjs",
];

function completedJourney() {
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
      file: "wl-13-report.html",
      bytes: 2_048,
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

function wl13Record(outcome) {
  const checks = WL13_CONTRACT.checks.map(({ caseId, id }, index) => {
    let state = "passed";
    if (outcome === "failed" && index === 1) state = "failed";
    if (outcome === "failed" && index > 1) state = "not-observed";
    if (outcome === "inconclusive" && index > 0) state = "not-observed";
    return {
      caseId,
      id,
      state,
      observedAt: state === "not-observed" ? null : "2026-09-07T14:05:00Z",
      detail: state === "not-observed"
        ? "The required observation was unavailable."
        : `Recorded the bounded WL-13 check as ${state}.`,
    };
  });

  return {
    schemaVersion: 1,
    evidenceType: "windows-installed-app-lifecycle",
    product: "ai-security-scanner",
    rowId: "WL-13",
    boundary: "runtime_reconciliation",
    platform: "windows-x86_64",
    architecture: "x86_64",
    installerType: "nsis",
    releaseIdentity: {
      version: V019_WL13_EVIDENCE_POLICY.version,
      tag: V019_WL13_EVIDENCE_POLICY.tag,
      sourceCommit: V019_WL13_EVIDENCE_POLICY.commit,
      releaseChannel: V019_WL13_EVIDENCE_POLICY.releaseChannel,
    },
    artifact: structuredClone(V019_WL13_EVIDENCE_POLICY.artifact),
    runtimeManifest: structuredClone(V019_WL13_EVIDENCE_POLICY.runtimeManifest),
    relatedArtifact: null,
    environment: {
      profileId: "wl-13-disposable-windows-x86-64",
      windowsEdition: "Windows 11 Pro",
      windowsVersion: "24H2",
      windowsBuild: "26100",
      architecture: "x86_64",
      accountPrivilege: "standard-user",
      uacState: "enabled",
      virtualizationCapability: "available",
      cases: [{
        caseId: "windows-host-loopback-fixture",
        snapshotId: "wl-13-clean-snapshot-1",
        initialState: "Clean disposable OPERATOR guest with no product installation.",
      }],
    },
    harness: structuredClone(WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES["WL-13"]),
    execution: {
      startedAt: "2026-09-07T14:00:00Z",
      endedAt: "2026-09-07T14:10:00Z",
      excludedOperatingSystemRestartSeconds: 0,
      secureDesktopControl: "not-present",
      localhostStartControl: "human",
      administratorCredentialSharedWithAgent: false,
      visibleDecisions: [],
      visibleWarnings: [],
      visibleErrors: [],
      retryCount: 0,
      interruptions: [],
    },
    outcome,
    reasonCode: outcome === "failed"
      ? "product-behavior-failed"
      : outcome === "inconclusive"
        ? "required-observation-unavailable"
        : null,
    reason: outcome === "failed"
      ? "The installed application did not report the bounded fixture as reachable."
      : outcome === "inconclusive"
        ? "A required local observation could not be completed."
        : null,
    checks,
    installedAppJourney: outcome === "passed" ? completedJourney() : null,
    cleanup: {
      planInspected: true,
      allDataRemovalConfirmedByOwner: false,
      outcome: "completed",
      ambiguousOrUnrelatedStatePreserved: true,
      unresolvedObligations: [],
    },
    observedAt: "2026-09-07T14:11:00Z",
  };
}

async function createHandoffRoot(t, record = wl13Record("passed")) {
  const root = await mkdtemp(path.join(os.tmpdir(), "assm-v019-wl13-validator-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = path.join(root, "redacted-output", "windows-installed-lifecycle", "wl-13");
  await mkdir(directory, { recursive: true });
  const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
  await writeFile(path.join(directory, "runtime_reconciliation.json"), bytes, { flag: "wx" });
  return { root, bytes };
}

async function assertPolicyRejected(t, patch) {
  const record = wl13Record("passed");
  patch(record);
  const { root } = await createHandoffRoot(t, record);
  await assert.rejects(
    validateV019Wl13ObservationAtRoot(root),
    (error) => error?.safeCode === "WL13_RECORD_POLICY_INVALID"
      && error.message === "WL-13 local validation failed",
  );
}

test("v0.1.9 WL-13 local policy freezes the exact candidate, artifact, and runtime manifest", () => {
  assert.deepEqual(
    {
      rowId: V019_WL13_EVIDENCE_POLICY.rowId,
      boundary: V019_WL13_EVIDENCE_POLICY.boundary,
      platform: V019_WL13_EVIDENCE_POLICY.platform,
      architecture: V019_WL13_EVIDENCE_POLICY.architecture,
      installerType: V019_WL13_EVIDENCE_POLICY.installerType,
      version: V019_WL13_EVIDENCE_POLICY.version,
      tag: V019_WL13_EVIDENCE_POLICY.tag,
      commit: V019_WL13_EVIDENCE_POLICY.commit,
      releaseChannel: V019_WL13_EVIDENCE_POLICY.releaseChannel,
      artifact: V019_WL13_EVIDENCE_POLICY.artifact,
      runtimeManifest: V019_WL13_EVIDENCE_POLICY.runtimeManifest,
      requireApprovedHarness: V019_WL13_EVIDENCE_POLICY.requireApprovedHarness,
    },
    {
      rowId: "WL-13",
      boundary: "runtime_reconciliation",
      platform: "windows-x86_64",
      architecture: "x86_64",
      installerType: "nsis",
      version: "0.1.9",
      tag: "v0.1.9",
      commit: "5c95572f54220adbd170d9bfb5af3159c56708ef",
      releaseChannel: "prerelease",
      artifact: {
        file: "ai-security-scanner_0.1.9_x64-setup.exe",
        bytes: 40_186_968,
        sha256: "f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e",
      },
      runtimeManifest: {
        file: "managed-runtime-windows-x86_64.manifest.json",
        bytes: 3_724,
        sha256: "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a",
        managementContractRevision: "2026-08-29.1",
      },
      requireApprovedHarness: true,
    },
  );
  assert.deepEqual(
    V019_WL13_EVIDENCE_POLICY.harnesses,
    WINDOWS_APPROVED_LIFECYCLE_HARNESS_POLICIES,
  );
});

test("parameterless WL-13 validator accepts truthful passed, failed, and inconclusive records", async (t) => {
  for (const outcome of ["passed", "failed", "inconclusive"]) {
    await t.test(outcome, async (t) => {
      const { root, bytes } = await createHandoffRoot(t, wl13Record(outcome));
      const summary = await validateV019Wl13ObservationAtRoot(root);
      assert.deepEqual(summary, {
        lane: "WINDOWS-INSTALLED-LIFECYCLE",
        localValidator: "passed",
        rowId: "WL-13",
        boundary: "runtime_reconciliation",
        recordOutcome: outcome,
        evidenceFile: RECORD_RELATIVE_PATH,
        evidenceBytes: bytes.length,
        evidenceSha256: createHash("sha256").update(bytes).digest("hex"),
      });
      assert.deepEqual(Object.keys(summary), [
        "lane",
        "localValidator",
        "rowId",
        "boundary",
        "recordOutcome",
        "evidenceFile",
        "evidenceBytes",
        "evidenceSha256",
      ]);
    });
  }
});

test("WL-13 local wrapper does not turn an unattempted row into a validated observation", async (t) => {
  const record = wl13Record("inconclusive");
  record.outcome = "not-observed";
  const { root } = await createHandoffRoot(t, record);
  await assert.rejects(
    validateV019Wl13ObservationAtRoot(root),
    (error) => error?.safeCode === "WL13_RECORD_POLICY_INVALID"
      && error.message === "WL-13 local validation failed",
  );
});

test("parameterless WL-13 command runs from the documented portable scripts/release layout", async (t) => {
  const { root, bytes } = await createHandoffRoot(t);
  const portableScripts = path.join(root, "scripts", "release");
  await mkdir(portableScripts, { recursive: true });
  await Promise.all(PORTABLE_SOURCE_FILES.map((file) => copyFile(
    path.join(PROJECT_ROOT, "scripts", "release", file),
    path.join(portableScripts, file),
  )));

  const result = spawnSync(process.execPath, [path.join(root, VALIDATOR_RELATIVE_PATH)], {
    cwd: os.tmpdir(),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    lane: "WINDOWS-INSTALLED-LIFECYCLE",
    localValidator: "passed",
    rowId: "WL-13",
    boundary: "runtime_reconciliation",
    recordOutcome: "passed",
    evidenceFile: RECORD_RELATIVE_PATH,
    evidenceBytes: bytes.length,
    evidenceSha256: createHash("sha256").update(bytes).digest("hex"),
  });
  assert.doesNotMatch(result.stdout, /Windows 11|11111111-2222|Recorded the bounded/u);
});

test("WL-13 validator rejects every changed approved-harness coordinate", async (t) => {
  const cases = [
    ["source commit", (record) => { record.harness.sourceCommit = "0".repeat(40); }],
    ["path", (record) => { record.harness.path = "scripts/release/not-the-approved-fixture.mjs"; }],
    ["digest", (record) => { record.harness.sha256 = "0".repeat(64); }],
    ["fixture runtime", (record) => { record.harness.fixtureRuntime.executable.sha256 = "0".repeat(64); }],
  ];
  for (const [name, patch] of cases) {
    await t.test(name, (t) => assertPolicyRejected(t, patch));
  }
});

test("WL-13 validator rejects changed candidate bytes, runtime manifest, and timestamps", async (t) => {
  const cases = [
    ["candidate artifact", (record) => { record.artifact.bytes += 1; }],
    ["runtime manifest", (record) => { record.runtimeManifest.sha256 = "0".repeat(64); }],
    ["timestamp", (record) => { record.observedAt = "2026-09-07T13:59:59Z"; }],
  ];
  for (const [name, patch] of cases) {
    await t.test(name, (t) => assertPolicyRejected(t, patch));
  }
});

test("WL-13 validator rejects any extra redacted-output inventory", async (t) => {
  const { root } = await createHandoffRoot(t);
  await writeFile(path.join(root, "redacted-output", "unexpected.txt"), "must be rejected\n", { flag: "wx" });
  await assert.rejects(
    validateV019Wl13ObservationAtRoot(root),
    (error) => error?.safeCode === "REDACTED_OUTPUT_INVENTORY_INVALID"
      && error.message === "WL-13 local validation failed",
  );
});

test("WL-13 command line rejects path and policy overrides without exposing a local path", () => {
  const script = path.join(PROJECT_ROOT, VALIDATOR_RELATIVE_PATH);
  const result = spawnSync(process.execPath, [script, "override.json"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.deepEqual(JSON.parse(result.stderr), {
    lane: "WINDOWS-INSTALLED-LIFECYCLE",
    localValidator: "failed",
    rowId: "WL-13",
    boundary: "runtime_reconciliation",
    errorCode: "ARGUMENT_OVERRIDE_REJECTED",
  });
  assert.equal(result.stderr.includes("override.json"), false);
  assert.equal(result.stderr.includes(script), false);
});

test("WL-13 command reports a missing bundled validator module without leaking a path or stack", async (t) => {
  const { root } = await createHandoffRoot(t);
  const portableScripts = path.join(root, "scripts", "release");
  await mkdir(portableScripts, { recursive: true });
  const wrapper = path.join(portableScripts, "validate-v019-wl13-observation.mjs");
  await copyFile(path.join(PROJECT_ROOT, VALIDATOR_RELATIVE_PATH), wrapper);

  const result = spawnSync(process.execPath, [wrapper], {
    cwd: os.tmpdir(),
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.deepEqual(JSON.parse(result.stderr), {
    lane: "WINDOWS-INSTALLED-LIFECYCLE",
    localValidator: "failed",
    rowId: "WL-13",
    boundary: "runtime_reconciliation",
    errorCode: "VALIDATOR_MODULE_UNAVAILABLE",
  });
  assert.equal(result.stderr.includes(root), false);
  assert.equal(result.stderr.includes("ERR_MODULE_NOT_FOUND"), false);
  assert.equal(result.stderr.includes(" at "), false);
});

test("WL-13 handoff freezes the portable runtime and lane-only output without a passing record", async () => {
  const handoff = await readFile(
    path.join(PROJECT_ROOT, "docs", "release", "v0.1.9-windows-wl13-handoff.zh-TW.md"),
    "utf8",
  );
  for (const required of [
    "5c95572f54220adbd170d9bfb5af3159c56708ef",
    "f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e",
    "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a",
    "bd47e26b6c8024eb3461176637d7fce3e8370561",
    "de31dceede3f1aafcdc222d9c91f68913d69e077baa3a663577d62ac0354973a",
    "node-v24.15.0-win-x64.zip",
    "cc5149eabd53779ce1e7bdc5401643622d0c7e6800ade18928a767e940bb0e62",
    "3331e1ffe19874215472217c5e94f5a0c6d8e18c4ac7111d3937aa0ad5e9b4a5",
    "private-diagnostic/wl-13/windows-localhost-fixture-receipt.json",
    RECORD_RELATIVE_PATH,
    "validate-v019-wl13-observation.mjs",
    "v0.1.9-windows-external-candidate-identity.json",
    "managed-runtime-windows-x86_64.manifest.json",
    "SHA256SUMS.txt",
    "release-assets.json",
    "START-HERE.zh-TW.md",
    "BUNDLE-SHA256SUMS.txt",
    "windows-external-qualification-plan.zh-TW.md",
    "manifest 覆蓋它自身以外的每一份 regular payload file",
    "C:\\assm-v019-wl13",
    "不可逐字貼給模型",
    "不得把 HTML、Technical details、raw target evidence、畫面內容或 logs 放進模型",
    "不要從本文件複製一份假 passing JSON",
  ]) {
    assert.match(handoff, new RegExp(required.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }
  assert.doesNotMatch(handoff, /candidate-handoff\.json/u);
  assert.doesNotMatch(handoff, /"evidenceType"\s*:\s*"windows-installed-app-lifecycle"/u);
});
