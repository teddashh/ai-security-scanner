#!/usr/bin/env node

import { lstat, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { isSemver, runMain } from "./lib.mjs";
import { WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY } from "./windows-localhost-fixture.mjs";

const MAX_RECORD_BYTES = 256 * 1024;
const MAX_TEXT = 500;
const MAX_LIST_ITEMS = 20;
const MAX_INSTALLER_BYTES = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const PRODUCT = "ai-security-scanner";
const PLATFORM = "windows-x86_64";
const ARCHITECTURE = "x86_64";
const INSTALLER_TYPE = "nsis";
const RUNTIME_MANIFEST_FILE = "managed-runtime-windows-x86_64.manifest.json";
export const WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY = Object.freeze({
  path: "scripts/release/windows-localhost-fixture.mjs",
  sha256: "de31dceede3f1aafcdc222d9c91f68913d69e077baa3a663577d62ac0354973a",
});

function check(caseId, id) {
  return Object.freeze({ caseId, id });
}

const ROW_CONTRACTS = Object.freeze([
  Object.freeze({
    rowId: "WL-01",
    boundary: "installer_runtime_cache_seed",
    cases: Object.freeze(["clean-install"]),
    checks: Object.freeze([
      check("clean-install", "candidate-installer-reverified-before-launch"),
      check("clean-install", "installer-private-runtime-cache-seed-observed"),
      check("clean-install", "installed-runtime-manifest-matched-release"),
      check("clean-install", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-02",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["wsl-absent-no-reboot"]),
    checks: Object.freeze([
      check("wsl-absent-no-reboot", "wsl-absent-or-disabled-observed"),
      check("wsl-absent-no-reboot", "product-defined-wsl-preparation-used"),
      check("wsl-absent-no-reboot", "terminal-and-manual-wsl-administration-not-used"),
      check("wsl-absent-no-reboot", "setup-completed-without-restart"),
      check("wsl-absent-no-reboot", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-03",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["wsl-absent-restart-required"]),
    checks: Object.freeze([
      check("wsl-absent-restart-required", "wsl-absent-or-disabled-observed"),
      check("wsl-absent-restart-required", "product-defined-wsl-preparation-used"),
      check("wsl-absent-restart-required", "terminal-and-manual-wsl-administration-not-used"),
      check("wsl-absent-restart-required", "required-windows-restart-observed"),
      check("wsl-absent-restart-required", "durable-setup-state-survived-restart"),
      check("wsl-absent-restart-required", "preparation-resumed-automatically"),
      check("wsl-absent-restart-required", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-04",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["unrelated-wsl-present"]),
    checks: Object.freeze([
      check("unrelated-wsl-present", "unrelated-wsl-baseline-captured"),
      check("unrelated-wsl-present", "unrelated-wsl-registration-and-storage-unchanged"),
      check("unrelated-wsl-present", "product-runtime-created-separately"),
      check("unrelated-wsl-present", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-05",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["healthy-product-runtime"]),
    checks: Object.freeze([
      check("healthy-product-runtime", "healthy-product-runtime-ownership-verified"),
      check("healthy-product-runtime", "verified-current-runtime-reused-or-reconciled"),
      check("healthy-product-runtime", "unowned-state-not-modified"),
      check("healthy-product-runtime", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-06",
    boundary: "packaged_component_auto_recovery",
    cases: Object.freeze([
      "damaged-with-repair-source",
      "damaged-without-repair-source",
      "legacy-runtime",
      "n-minus-one-ghost",
    ]),
    checks: Object.freeze([
      check("damaged-with-repair-source", "corrupt-packaged-bytes-rejected-before-execution"),
      check("damaged-with-repair-source", "verified-repair-source-used-for-bounded-recovery"),
      check("damaged-with-repair-source", "recovery-returned-to-selected-project"),
      check("damaged-without-repair-source", "corrupt-packaged-bytes-rejected-before-execution"),
      check("damaged-without-repair-source", "only-dependent-tasks-became-unavailable"),
      check("damaged-without-repair-source", "projects-reports-and-unsigned-exports-remained-usable"),
      check("legacy-runtime", "current-generation-created-side-by-side"),
      check("legacy-runtime", "legacy-generation-retained-until-replacement-worked"),
      check("n-minus-one-ghost", "registry-and-name-not-treated-as-ownership-proof"),
      check("n-minus-one-ghost", "missing-binaries-or-manifest-registration-repaired"),
      check("n-minus-one-ghost", "unknown-old-runtime-left-untouched"),
      check("n-minus-one-ghost", "manual-wsl-cleanup-not-required"),
      check("damaged-with-repair-source", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-07",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["ambiguous-similarly-named-runtime"]),
    checks: Object.freeze([
      check("ambiguous-similarly-named-runtime", "ambiguous-runtime-baseline-captured"),
      check("ambiguous-similarly-named-runtime", "ambiguous-runtime-not-adopted-modified-or-removed"),
      check("ambiguous-similarly-named-runtime", "unique-isolated-generation-created"),
      check("ambiguous-similarly-named-runtime", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-08",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["interrupted-install", "interrupted-runtime-preparation"]),
    checks: Object.freeze([
      check("interrupted-install", "interruption-injected-at-reviewed-install-milestone"),
      check("interrupted-install", "installer-state-resumed-or-recovered-safely"),
      check("interrupted-runtime-preparation", "interruption-injected-at-reviewed-runtime-milestone"),
      check("interrupted-runtime-preparation", "durable-generation-reused-or-deliberately-replaced"),
      check("interrupted-runtime-preparation", "permanent-false-ready-or-repairing-state-absent"),
      check("interrupted-runtime-preparation", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-09",
    boundary: "installer_same_version_repair",
    cases: Object.freeze(["same-version-repair", "interrupted-same-version-repair"]),
    checks: Object.freeze([
      check("same-version-repair", "verified-binaries-resources-and-registration-repaired"),
      check("same-version-repair", "runtime-projects-evidence-exports-settings-and-identity-preserved"),
      check("interrupted-same-version-repair", "last-runnable-binary-set-retained-or-restored"),
      check("interrupted-same-version-repair", "repair-resumed-idempotently"),
      check("interrupted-same-version-repair", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-10",
    boundary: "runtime_reconciliation",
    relatedArtifactRole: "n-minus-one-upgrade-source",
    cases: Object.freeze(["n-minus-one-upgrade"]),
    checks: Object.freeze([
      check("n-minus-one-upgrade", "n-minus-one-installer-identity-reverified"),
      check("n-minus-one-upgrade", "projects-case-database-evidence-identity-and-preferences-preserved"),
      check("n-minus-one-upgrade", "unrelated-wsl-state-preserved"),
      check("n-minus-one-upgrade", "candidate-upgrade-completed"),
      check("n-minus-one-upgrade", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-11",
    boundary: "runtime_reconciliation",
    relatedArtifactRole: "downgrade-target",
    cases: Object.freeze(["compatible-downgrade", "incompatible-downgrade"]),
    checks: Object.freeze([
      check("compatible-downgrade", "downgrade-target-installer-identity-reverified"),
      check("compatible-downgrade", "newer-case-data-not-rewritten-in-place"),
      check("compatible-downgrade", "supported-data-reopened-and-exported"),
      check("incompatible-downgrade", "downgrade-refused-before-binary-or-data-mutation"),
      check("incompatible-downgrade", "previous-supported-version-reopened-and-exported-unchanged-project"),
      check("compatible-downgrade", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-12a",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["app-only-uninstall"]),
    checks: Object.freeze([
      check("app-only-uninstall", "target-contact-stopped-before-uninstall-completed"),
      check("app-only-uninstall", "application-binaries-and-registration-removed"),
      check("app-only-uninstall", "projects-and-managed-scan-tools-preserved"),
      check("app-only-uninstall", "same-candidate-reinstalled"),
      check("app-only-uninstall", "same-project-reopened-and-exported"),
      check("app-only-uninstall", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-12b",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["remove-scan-tools-keep-projects"]),
    checks: Object.freeze([
      check("remove-scan-tools-keep-projects", "target-contact-stopped-before-uninstall-completed"),
      check("remove-scan-tools-keep-projects", "only-exact-product-owned-disposable-tools-removed"),
      check("remove-scan-tools-keep-projects", "projects-evidence-exports-settings-and-identity-preserved"),
      check("remove-scan-tools-keep-projects", "same-candidate-reinstalled"),
      check("remove-scan-tools-keep-projects", "verified-runtime-rebuilt-through-product"),
      check("remove-scan-tools-keep-projects", "installed-desktop-journey-completed"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-12c",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["explicit-all-data-uninstall"]),
    checks: Object.freeze([
      check("explicit-all-data-uninstall", "owner-confirmed-exact-all-data-removal"),
      check("explicit-all-data-uninstall", "target-contact-stopped-before-uninstall-completed"),
      check("explicit-all-data-uninstall", "only-exact-product-owned-data-removed"),
      check("explicit-all-data-uninstall", "ambiguous-and-unrelated-state-preserved-and-disclosed"),
      check("explicit-all-data-uninstall", "exact-removal-verified"),
    ]),
  }),
  Object.freeze({
    rowId: "WL-13",
    boundary: "runtime_reconciliation",
    cases: Object.freeze(["windows-host-loopback-fixture"]),
    checks: Object.freeze([
      check("windows-host-loopback-fixture", "bounded-fixture-listened-on-windows-host-127-0-0-1-9001"),
      check("windows-host-loopback-fixture", "installed-app-reported-reachable"),
      check("windows-host-loopback-fixture", "fixture-observed-real-connection"),
      check("windows-host-loopback-fixture", "hidden-host-or-port-expansion-absent"),
      check("windows-host-loopback-fixture", "installed-desktop-journey-completed"),
    ]),
  }),
]);

export const WINDOWS_INSTALLED_LIFECYCLE_CONTRACTS = ROW_CONTRACTS;

export const WINDOWS_INSTALLED_LIFECYCLE_RECORDS = Object.freeze(
  ROW_CONTRACTS.map((contract) => Object.freeze({
    rowId: contract.rowId,
    boundary: contract.boundary,
    key: `${contract.rowId}/${contract.boundary}`,
    path: `${contract.rowId.toLowerCase()}/${contract.boundary}.json`,
  })),
);

const CONTRACT_BY_ROW = new Map(ROW_CONTRACTS.map((contract) => [contract.rowId, contract]));
const RECORD_BY_PATH = new Map(WINDOWS_INSTALLED_LIFECYCLE_RECORDS.map((record) => [record.path, record]));
const FAILURE_REASONS = new Set([
  "product-behavior-failed",
  "data-preservation-failed",
  "integrity-failed",
  "unsafe-target-contact-observed",
  "cleanup-failed",
]);
const INCONCLUSIVE_REASONS = new Set([
  "environment-failure",
  "evidence-chain-incomplete",
  "lab-reset-failed",
  "required-observation-unavailable",
]);
const NOT_OBSERVED_REASONS = new Set([
  "not-scheduled",
  "reviewed-harness-missing",
  "reference-environment-unavailable",
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} fields are not the Windows installed-lifecycle schema-v1 set`,
  );
}

function text(value, label, maximum = MAX_TEXT) {
  assert(
    typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\0\r\n]/u.test(value),
    `${label} must be non-empty, single-line text of at most ${maximum} characters`,
  );
}

function textList(value, label) {
  assert(Array.isArray(value) && value.length <= MAX_LIST_ITEMS, `${label} must contain at most ${MAX_LIST_ITEMS} entries`);
  for (const [index, item] of value.entries()) text(item, `${label}[${index}]`);
}

function digest(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{64}$/u.test(value), `${label} must be a lowercase SHA-256`);
}

function integer(value, minimum, maximum, label) {
  assert(Number.isSafeInteger(value) && value >= minimum && value <= maximum, `${label} is outside its integer bound`);
}

function timestamp(value, label) {
  assert(typeof value === "string" && value.length <= 64, `${label} must be a bounded timestamp`);
  const parsed = Date.parse(value);
  assert(Number.isFinite(parsed), `${label} is invalid`);
  return parsed;
}

function flatFile(value, label) {
  text(value, label, 255);
  assert(
    path.posix.basename(value) === value && path.win32.basename(value) === value && value !== "." && value !== "..",
    `${label} must be one flat filename`,
  );
}

function safeRelativePath(value, label) {
  text(value, label, 512);
  assert(
    !path.isAbsolute(value) && !value.includes("\\") && !value.startsWith("/") &&
      value.split("/").every((component) => component && component !== "." && component !== ".."),
    `${label} must be a canonical safe relative path`,
  );
}

function validateReleaseIdentity(identity, expected, label) {
  exactKeys(identity, ["version", "tag", "sourceCommit", "releaseChannel"], label);
  assert(isSemver(identity.version) && identity.tag === `v${identity.version}`, `${label} version/tag is invalid`);
  assert(/^[0-9a-f]{40}$/u.test(identity.sourceCommit), `${label} sourceCommit must be a full lowercase Git object ID`);
  assert(["prerelease", "stable"].includes(identity.releaseChannel), `${label} release channel is invalid`);
  if (expected.version) assert(identity.version === expected.version, `${label} version differs from the expected candidate`);
  if (expected.tag) assert(identity.tag === expected.tag, `${label} tag differs from the expected candidate`);
  if (expected.commit) assert(identity.sourceCommit === expected.commit, `${label} commit differs from the expected candidate`);
  if (expected.releaseChannel) assert(identity.releaseChannel === expected.releaseChannel, `${label} channel differs from the expected candidate`);
}

function validateArtifact(artifact, expected, label, maximumBytes = MAX_INSTALLER_BYTES) {
  exactKeys(artifact, ["file", "bytes", "sha256"], label);
  flatFile(artifact.file, `${label} file`);
  integer(artifact.bytes, 1, maximumBytes, `${label} bytes`);
  digest(artifact.sha256, `${label} sha256`);
  if (expected) {
    assert(
      artifact.file === expected.file && artifact.bytes === expected.bytes && artifact.sha256 === expected.sha256,
      `${label} differs from the expected exact bytes`,
    );
  }
}

function validateRuntimeManifest(manifest, expected, label) {
  exactKeys(manifest, ["file", "bytes", "sha256", "managementContractRevision"], label);
  assert(manifest.file === RUNTIME_MANIFEST_FILE, `${label} file is not the Windows runtime manifest`);
  integer(manifest.bytes, 1, MAX_MANIFEST_BYTES, `${label} bytes`);
  digest(manifest.sha256, `${label} sha256`);
  text(manifest.managementContractRevision, `${label} management contract revision`, 64);
  if (expected) {
    for (const field of ["file", "bytes", "sha256", "managementContractRevision"]) {
      if (expected[field] !== undefined) {
        assert(manifest[field] === expected[field], `${label} ${field} differs from the expected candidate`);
      }
    }
  }
}

function validateRelatedArtifact(value, contract, currentVersion, expected, outcome) {
  if (!contract.relatedArtifactRole) {
    assert(value === null, `${contract.rowId} must not claim a related installer artifact`);
    return;
  }
  if (outcome === "not-observed") {
    assert(value === null, `${contract.rowId} not-observed outcome must not claim a related installer artifact`);
    return;
  }
  exactKeys(value, ["role", "version", "tag", "file", "bytes", "sha256"], `${contract.rowId} related artifact`);
  assert(value.role === contract.relatedArtifactRole, `${contract.rowId} related artifact role is invalid`);
  assert(isSemver(value.version) && value.tag === `v${value.version}`, `${contract.rowId} related artifact version/tag is invalid`);
  assert(value.version !== currentVersion, `${contract.rowId} related artifact cannot be the candidate version`);
  validateArtifact(
    { file: value.file, bytes: value.bytes, sha256: value.sha256 },
    expected,
    `${contract.rowId} related artifact`,
  );
}

function validateEnvironment(environment, contract) {
  exactKeys(
    environment,
    [
      "profileId", "windowsEdition", "windowsVersion", "windowsBuild", "architecture",
      "accountPrivilege", "uacState", "virtualizationCapability", "cases",
    ],
    `${contract.rowId} environment`,
  );
  for (const field of ["profileId", "windowsEdition", "windowsVersion", "windowsBuild"]) {
    text(environment[field], `${contract.rowId} environment ${field}`);
  }
  assert(environment.architecture === ARCHITECTURE, `${contract.rowId} environment architecture is invalid`);
  assert(["standard-user", "administrator"].includes(environment.accountPrivilege), `${contract.rowId} account privilege is invalid`);
  assert(["enabled", "disabled"].includes(environment.uacState), `${contract.rowId} UAC state is invalid`);
  assert(["available", "unavailable"].includes(environment.virtualizationCapability), `${contract.rowId} virtualization capability is invalid`);
  assert(Array.isArray(environment.cases), `${contract.rowId} environment cases must be an array`);
  assert(
    JSON.stringify(environment.cases.map((item) => item?.caseId)) === JSON.stringify(contract.cases),
    `${contract.rowId} environment cases are incomplete or out of order`,
  );
  const snapshots = new Set();
  for (const item of environment.cases) {
    exactKeys(item, ["caseId", "snapshotId", "initialState"], `${contract.rowId}/${item?.caseId} environment case`);
    text(item.snapshotId, `${contract.rowId}/${item.caseId} snapshot ID`);
    text(item.initialState, `${contract.rowId}/${item.caseId} initial state`);
    assert(!snapshots.has(item.snapshotId), `${contract.rowId} reuses one snapshot across distinct cases`);
    snapshots.add(item.snapshotId);
  }
}

function validateFixtureRuntime(runtime, label) {
  exactKeys(runtime, ["name", "version", "platform", "architecture", "distribution", "executable"], label);
  exactKeys(runtime.distribution, ["file", "bytes", "sha256"], `${label} distribution`);
  exactKeys(runtime.executable, ["file", "bytes", "sha256"], `${label} executable`);
  assert(
    fixtureRuntimeEquals(runtime, WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY),
    `${label} differs from the approved fixed runtime policy`,
  );
}

function fixtureRuntimeEquals(left, right) {
  if (left === null || right === null) return left === right;
  return (
    ["name", "version", "platform", "architecture"].every((field) => left?.[field] === right?.[field])
    && ["file", "bytes", "sha256"].every(
      (field) => left?.distribution?.[field] === right?.distribution?.[field],
    )
    && ["file", "bytes", "sha256"].every(
      (field) => left?.executable?.[field] === right?.executable?.[field],
    )
  );
}

function validateHarness(harness, expected, contract, label) {
  exactKeys(harness, ["kind", "repository", "sourceCommit", "path", "sha256", "contractVersion", "fixtureRuntime"], label);
  assert(harness.kind === "checked-in-version-pinned", `${label} kind is invalid`);
  assert(harness.repository === "teddashh/ai-security-scanner", `${label} repository is invalid`);
  assert(/^[0-9a-f]{40}$/u.test(harness.sourceCommit), `${label} sourceCommit is invalid`);
  safeRelativePath(harness.path, `${label} path`);
  assert(harness.path.startsWith("scripts/release/"), `${label} must be checked in under scripts/release`);
  digest(harness.sha256, `${label} sha256`);
  assert(harness.contractVersion === 1, `${label} contract version is unsupported`);
  assert(harness.fixtureRuntime === null || typeof harness.fixtureRuntime === "object", `${label} fixtureRuntime is invalid`);
  if (harness.fixtureRuntime !== null) validateFixtureRuntime(harness.fixtureRuntime, `${label} fixture runtime`);
  if (contract.rowId === "WL-13") {
    assert(harness.fixtureRuntime !== null, "WL-13 has no approved fixed fixture runtime");
    assert(harness.path === WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.path, "WL-13 did not use the exact reviewed localhost fixture path");
    assert(harness.sha256 === WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.sha256, "WL-13 localhost fixture digest differs from policy");
  }
  if (expected) {
    for (const field of ["repository", "sourceCommit", "path", "sha256", "contractVersion"]) {
      if (expected[field] !== undefined) assert(harness[field] === expected[field], `${label} ${field} differs from policy`);
    }
    if (expected.fixtureRuntime !== undefined) {
      assert(
        fixtureRuntimeEquals(harness.fixtureRuntime, expected.fixtureRuntime),
        `${label} fixtureRuntime differs from policy`,
      );
    }
  }
}

function validateExecution(execution, outcome, label) {
  exactKeys(
    execution,
    [
      "startedAt", "endedAt", "excludedOperatingSystemRestartSeconds", "secureDesktopControl",
      "localhostStartControl", "administratorCredentialSharedWithAgent", "visibleDecisions",
      "visibleWarnings", "visibleErrors", "retryCount", "interruptions",
    ],
    label,
  );
  const startedAt = timestamp(execution.startedAt, `${label} startedAt`);
  const endedAt = timestamp(execution.endedAt, `${label} endedAt`);
  assert(endedAt >= startedAt, `${label} ends before it starts`);
  integer(execution.excludedOperatingSystemRestartSeconds, 0, 86_400, `${label} excluded restart seconds`);
  assert(["human", "not-present", "not-observed"].includes(execution.secureDesktopControl), `${label} secure-desktop control is invalid`);
  assert(
    ["human", "agent-with-explicit-user-authorization", "not-applicable", "not-observed"]
      .includes(execution.localhostStartControl),
    `${label} localhost Start control is invalid`,
  );
  assert(execution.administratorCredentialSharedWithAgent === false, `${label} exposed an administrator credential to the agent`);
  for (const field of ["visibleDecisions", "visibleWarnings", "visibleErrors", "interruptions"]) {
    textList(execution[field], `${label} ${field}`);
  }
  integer(execution.retryCount, 0, 100, `${label} retry count`);
  if (outcome === "passed") {
    assert(execution.secureDesktopControl !== "not-observed", `${label} did not resolve secure-desktop control`);
  }
  return { startedAt, endedAt };
}

function validateChecks(checks, contract, outcome, executionRange) {
  assert(Array.isArray(checks), `${contract.rowId} checks must be an array`);
  assert(
    JSON.stringify(checks.map((item) => [item?.caseId, item?.id])) ===
      JSON.stringify(contract.checks.map((item) => [item.caseId, item.id])),
    `${contract.rowId} checks are incomplete, out of order, or from another row/boundary`,
  );
  for (const [index, item] of checks.entries()) {
    exactKeys(item, ["caseId", "id", "state", "observedAt", "detail"], `${contract.rowId} check ${index + 1}`);
    assert(["passed", "failed", "not-observed"].includes(item.state), `${contract.rowId}/${item.id} state is invalid`);
    text(item.detail, `${contract.rowId}/${item.id} detail`);
    if (item.state === "not-observed") {
      assert(item.observedAt === null, `${contract.rowId}/${item.id} unobserved check claims an observation time`);
    } else {
      const observedAt = timestamp(item.observedAt, `${contract.rowId}/${item.id} observedAt`);
      assert(
        executionRange && observedAt >= executionRange.startedAt && observedAt <= executionRange.endedAt,
        `${contract.rowId}/${item.id} observation time falls outside row execution`,
      );
    }
  }
  const states = checks.map(({ state }) => state);
  if (outcome === "passed") {
    assert(states.every((state) => state === "passed"), `${contract.rowId} passing outcome has an unpassed required check`);
  } else if (outcome === "failed") {
    assert(states.includes("failed"), `${contract.rowId} failed outcome has no failed required check`);
  } else if (outcome === "inconclusive") {
    assert(!states.includes("failed") && states.includes("not-observed"), `${contract.rowId} inconclusive outcome has a product failure or no evidence gap`);
  } else {
    assert(states.every((state) => state === "not-observed"), `${contract.rowId} not-observed outcome claims an observed check`);
  }
}

function validateCoverage(coverage, label) {
  exactKeys(coverage, ["state", "testedCount", "notTestedCount", "failedCount", "coverageGapCount"], label);
  assert(["complete", "partial"].includes(coverage.state), `${label} state is invalid`);
  for (const field of ["testedCount", "notTestedCount", "failedCount", "coverageGapCount"]) {
    integer(coverage[field], 0, 1_000_000, `${label} ${field}`);
  }
  if (coverage.state === "complete") {
    assert(
      coverage.testedCount > 0 && coverage.notTestedCount === 0 && coverage.failedCount === 0 && coverage.coverageGapCount === 0,
      `${label} complete state contradicts its counts`,
    );
  } else {
    assert(
      coverage.testedCount > 0 && coverage.notTestedCount + coverage.failedCount + coverage.coverageGapCount > 0,
      `${label} partial state has no completed check or disclosed gap`,
    );
  }
}

function validateInstalledJourney(journey, contract) {
  exactKeys(
    journey,
    [
      "disposition", "installedDesktopUsed", "target", "taskExecutionState", "targetOutcome",
      "durableReportId", "durableReportState", "projectReopened", "export", "finalCoverage",
    ],
    `${contract.rowId} installed-app journey`,
  );
  if (contract.rowId === "WL-12c") {
    assert(journey.disposition === "all-data-removal", "WL-12c journey disposition is invalid");
    assert(journey.installedDesktopUsed === false, "WL-12c must not claim a post-removal desktop journey");
    assert(journey.target === null && journey.taskExecutionState === "not-applicable" && journey.targetOutcome === null, "WL-12c must not claim a post-removal task");
    assert(journey.durableReportId === null && journey.durableReportState === null, "WL-12c must not claim a deleted report");
    assert(journey.projectReopened === false && journey.export === null && journey.finalCoverage === null, "WL-12c must end by proving removal, not reopen/export");
    return;
  }
  assert(journey.disposition === "completed", `${contract.rowId} did not complete the installed-app journey`);
  assert(journey.installedDesktopUsed === true, `${contract.rowId} used no real installed desktop`);
  assert(journey.target === "127.0.0.1:9001", `${contract.rowId} used the wrong localhost target`);
  assert(journey.taskExecutionState === "executed", `${contract.rowId} did not execute the localhost task`);
  assert(["reachable", "closed", "timed_out", "unreachable"].includes(journey.targetOutcome), `${contract.rowId} target outcome is invalid`);
  assert(
    typeof journey.durableReportId === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(journey.durableReportId),
    `${contract.rowId} has no canonical durable report ID`,
  );
  assert(journey.durableReportState === "saved", `${contract.rowId} report was not durably saved`);
  assert(journey.projectReopened === true, `${contract.rowId} did not reopen the project`);
  exactKeys(journey.export, ["format", "file", "bytes", "sha256", "outcome"], `${contract.rowId} export`);
  assert(journey.export.format === "html" && journey.export.outcome === "exported-and-opened-readable", `${contract.rowId} export was not opened as readable HTML`);
  flatFile(journey.export.file, `${contract.rowId} export filename`);
  integer(journey.export.bytes, 1, 16 * 1024 * 1024, `${contract.rowId} export bytes`);
  digest(journey.export.sha256, `${contract.rowId} export sha256`);
  validateCoverage(journey.finalCoverage, `${contract.rowId} final coverage`);
  if (["timed_out", "unreachable"].includes(journey.targetOutcome)) {
    assert(journey.finalCoverage.state === "partial", `${contract.rowId} incomplete target outcome claims complete coverage`);
  }
  if (contract.rowId === "WL-13") {
    assert(journey.targetOutcome === "reachable", "WL-13 must observe the real reachable Windows-host fixture");
  } else {
    assert(journey.targetOutcome !== "reachable", `${contract.rowId} cannot claim the fixture-only reachable outcome`);
  }
}

function validateCleanup(cleanup, contract, outcome) {
  exactKeys(
    cleanup,
    ["planInspected", "allDataRemovalConfirmedByOwner", "outcome", "ambiguousOrUnrelatedStatePreserved", "unresolvedObligations"],
    `${contract.rowId} cleanup`,
  );
  assert(typeof cleanup.planInspected === "boolean", `${contract.rowId} cleanup planInspected must be boolean`);
  assert(typeof cleanup.allDataRemovalConfirmedByOwner === "boolean", `${contract.rowId} cleanup confirmation must be boolean`);
  assert(typeof cleanup.ambiguousOrUnrelatedStatePreserved === "boolean", `${contract.rowId} cleanup preservation must be boolean`);
  assert(["completed", "not-required", "retained-with-obligations", "not-observed"].includes(cleanup.outcome), `${contract.rowId} cleanup outcome is invalid`);
  textList(cleanup.unresolvedObligations, `${contract.rowId} cleanup unresolved obligations`);
  if (["completed", "not-required"].includes(cleanup.outcome)) {
    assert(cleanup.unresolvedObligations.length === 0, `${contract.rowId} completed cleanup retains unresolved obligations`);
  }
  if (cleanup.outcome === "retained-with-obligations") {
    assert(cleanup.unresolvedObligations.length > 0, `${contract.rowId} retained cleanup has no disclosed obligation`);
  }
  if (outcome === "passed") {
    assert(cleanup.planInspected === true, `${contract.rowId} passing row did not inspect its exact cleanup plan`);
    assert(cleanup.ambiguousOrUnrelatedStatePreserved === true, `${contract.rowId} passing row did not preserve ambiguous/unrelated state`);
    assert(cleanup.outcome !== "not-observed", `${contract.rowId} passing row did not observe cleanup`);
    if (contract.rowId === "WL-12c") {
      assert(cleanup.allDataRemovalConfirmedByOwner === true, "WL-12c has no explicit owner confirmation");
      assert(cleanup.outcome === "completed", "WL-12c did not prove exact product-data removal");
    } else {
      assert(cleanup.allDataRemovalConfirmedByOwner === false, `${contract.rowId} incorrectly claims all-data removal authority`);
    }
  }
}

function validateReason(outcome, reasonCode, reason, label) {
  if (outcome === "passed") {
    assert(reasonCode === null && reason === null, `${label} passing outcome must not carry a failure reason`);
    return;
  }
  text(reason, `${label} reason`);
  const allowed = outcome === "failed"
    ? FAILURE_REASONS
    : outcome === "inconclusive"
      ? INCONCLUSIVE_REASONS
      : NOT_OBSERVED_REASONS;
  assert(allowed.has(reasonCode), `${label} reasonCode is invalid for ${outcome}`);
}

export function validateWindowsInstalledLifecycleEvidence(evidence, expected = {}) {
  exactKeys(
    evidence,
    [
      "schemaVersion", "evidenceType", "product", "rowId", "boundary", "platform", "architecture",
      "installerType", "releaseIdentity", "artifact", "runtimeManifest", "relatedArtifact", "environment",
      "harness", "execution", "outcome", "reasonCode", "reason", "checks", "installedAppJourney",
      "cleanup", "observedAt",
    ],
    expected.label ?? "Windows installed-lifecycle evidence",
  );
  const label = expected.label ?? `${evidence.rowId ?? "unknown"} Windows installed-lifecycle evidence`;
  assert(evidence.schemaVersion === 1, `${label} schemaVersion must be 1`);
  assert(evidence.evidenceType === "windows-installed-app-lifecycle", `${label} evidenceType is invalid`);
  assert(evidence.product === PRODUCT, `${label} product is invalid`);
  const contract = CONTRACT_BY_ROW.get(evidence.rowId);
  assert(contract, `${label} rowId is unsupported`);
  assert(evidence.boundary === contract.boundary, `${label} boundary does not match ${contract.rowId}`);
  assert(evidence.platform === PLATFORM && evidence.architecture === ARCHITECTURE, `${label} platform/architecture is invalid`);
  assert(evidence.installerType === INSTALLER_TYPE, `${label} installer type is not the reviewed NSIS contract`);
  if (expected.rowId) assert(evidence.rowId === expected.rowId, `${label} row differs from its canonical path`);
  if (expected.boundary) assert(evidence.boundary === expected.boundary, `${label} boundary differs from its canonical path`);
  if (expected.platform) assert(evidence.platform === expected.platform, `${label} platform differs from expected`);
  if (expected.architecture) assert(evidence.architecture === expected.architecture, `${label} architecture differs from expected`);
  if (expected.installerType) assert(evidence.installerType === expected.installerType, `${label} installer type differs from expected`);

  validateReleaseIdentity(evidence.releaseIdentity, expected, `${label} release identity`);
  validateArtifact(evidence.artifact, expected.artifact, `${label} artifact`);
  validateRuntimeManifest(evidence.runtimeManifest, expected.runtimeManifest, `${label} runtime manifest`);
  assert(["passed", "failed", "inconclusive", "not-observed"].includes(evidence.outcome), `${label} outcome is invalid`);
  validateRelatedArtifact(
    evidence.relatedArtifact,
    contract,
    evidence.releaseIdentity.version,
    expected.relatedArtifacts?.[contract.rowId],
    evidence.outcome,
  );
  validateReason(evidence.outcome, evidence.reasonCode, evidence.reason, label);
  const recordObservedAt = timestamp(evidence.observedAt, `${label} observedAt`);

  let executionRange = null;
  if (evidence.outcome === "not-observed") {
    assert(evidence.environment === null, `${label} not-observed outcome claims an environment`);
    assert(evidence.harness === null, `${label} not-observed outcome claims a harness execution`);
    assert(evidence.execution === null, `${label} not-observed outcome claims an execution`);
    assert(evidence.installedAppJourney === null, `${label} not-observed outcome claims an installed journey`);
    assert(evidence.cleanup === null, `${label} not-observed outcome claims cleanup`);
    assert(evidence.relatedArtifact === null, `${label} not-observed outcome claims a related artifact execution`);
  } else {
    validateEnvironment(evidence.environment, contract);
    validateHarness(evidence.harness, expected.harness, contract, `${label} harness`);
    executionRange = validateExecution(evidence.execution, evidence.outcome, `${label} execution`);
    assert(recordObservedAt >= executionRange.endedAt, `${label} observedAt precedes execution completion`);
    validateCleanup(evidence.cleanup, contract, evidence.outcome);
    if (contract.rowId === "WL-12c") {
      assert(evidence.execution.localhostStartControl === "not-applicable", "WL-12c incorrectly claims a localhost Start action");
      assert(evidence.cleanup.allDataRemovalConfirmedByOwner === true, "WL-12c has no explicit owner confirmation");
    } else {
      assert(evidence.cleanup.allDataRemovalConfirmedByOwner === false, `${contract.rowId} incorrectly claims all-data removal authority`);
    }
    if (evidence.outcome === "passed") {
      validateInstalledJourney(evidence.installedAppJourney, contract);
      if (evidence.installedAppJourney.targetOutcome === "reachable") {
        assert(
          evidence.harness.fixtureRuntime !== null,
          `${contract.rowId} reachable journey has no approved fixed fixture runtime`,
        );
      }
      if (contract.rowId !== "WL-12c") {
        assert(
          ["human", "agent-with-explicit-user-authorization"]
            .includes(evidence.execution.localhostStartControl),
          `${contract.rowId} Start was not controlled by a human or an explicitly authorized agent`,
        );
      }
    } else {
      assert(evidence.installedAppJourney === null, `${label} non-passing outcome must preserve partial progress in checks, not claim a completed journey`);
    }
  }
  validateChecks(evidence.checks, contract, evidence.outcome, executionRange);
  return evidence;
}

export async function verifyWindowsInstalledLifecycleEvidenceFile(file, expected = {}) {
  const metadata = await lstat(file);
  assert(
    metadata.isFile() && !metadata.isSymbolicLink() && metadata.size > 0 && metadata.size <= MAX_RECORD_BYTES,
    `${file} must be one bounded regular non-symlink lifecycle record`,
  );
  let evidence;
  try {
    evidence = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`${file} is not valid lifecycle JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return validateWindowsInstalledLifecycleEvidence(evidence, { ...expected, label: expected.label ?? file });
}

function lifecycleIdentity(record) {
  return {
    product: record.product,
    platform: record.platform,
    architecture: record.architecture,
    installerType: record.installerType,
    releaseIdentity: record.releaseIdentity,
    artifact: record.artifact,
    runtimeManifest: record.runtimeManifest,
  };
}

export function summarizeWindowsInstalledLifecycleEvidence(records) {
  assert(Array.isArray(records), "Windows installed-lifecycle records must be an array");
  const outcomes = new Map();
  let expectedIdentity = null;
  for (const record of records) {
    validateWindowsInstalledLifecycleEvidence(record);
    const key = `${record.rowId}/${record.boundary}`;
    assert(!outcomes.has(key), `duplicate Windows installed-lifecycle record: ${key}`);
    outcomes.set(key, record.outcome);
    const identity = lifecycleIdentity(record);
    if (expectedIdentity === null) expectedIdentity = identity;
    else assert(JSON.stringify(identity) === JSON.stringify(expectedIdentity), `${key} belongs to a different exact candidate`);
  }
  const missingKeys = WINDOWS_INSTALLED_LIFECYCLE_RECORDS
    .map(({ key }) => key)
    .filter((key) => !outcomes.has(key));
  const passedCount = [...outcomes.values()].filter((state) => state === "passed").length;
  const failedCount = [...outcomes.values()].filter((state) => state === "failed").length;
  const inconclusiveCount = [...outcomes.values()].filter((state) => state === "inconclusive").length;
  const notObservedCount = [...outcomes.values()].filter((state) => state === "not-observed").length;
  let state = "partial";
  if (failedCount > 0) state = "failed";
  else if (missingKeys.length === 0 && passedCount === WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length) state = "verified";
  else if (records.length === 0 || (passedCount === 0 && inconclusiveCount === 0 && failedCount === 0)) state = "not-observed";
  return {
    state,
    requiredCount: WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length,
    presentCount: records.length,
    passedCount,
    failedCount,
    inconclusiveCount,
    notObservedCount,
    missingKeys,
  };
}

async function inventory(directory, root = directory, files = []) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    const metadata = await lstat(absolute);
    assert(!metadata.isSymbolicLink(), `lifecycle evidence contains a symlink: ${absolute}`);
    if (metadata.isDirectory()) {
      await inventory(absolute, root, files);
    } else {
      assert(metadata.isFile(), `lifecycle evidence contains a special file: ${absolute}`);
      files.push(path.relative(root, absolute).split(path.sep).join("/"));
      assert(files.length <= WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length, "lifecycle evidence contains too many files");
    }
  }
  return files;
}

export async function verifyWindowsInstalledLifecycleEvidenceDirectory(directory, expected = {}) {
  const root = path.resolve(directory);
  const metadata = await lstat(root);
  assert(metadata.isDirectory() && !metadata.isSymbolicLink(), `${root} must be one real lifecycle evidence directory`);
  const actualPaths = await inventory(root);
  for (const relative of actualPaths) {
    assert(RECORD_BY_PATH.has(relative), `unexpected lifecycle evidence path: ${relative}`);
  }
  const records = [];
  for (const contract of WINDOWS_INSTALLED_LIFECYCLE_RECORDS) {
    if (!actualPaths.includes(contract.path)) continue;
    records.push(await verifyWindowsInstalledLifecycleEvidenceFile(path.join(root, contract.path), {
      ...expected,
      rowId: contract.rowId,
      boundary: contract.boundary,
      label: contract.path,
    }));
  }
  return { records, summary: summarizeWindowsInstalledLifecycleEvidence(records) };
}

async function main() {
  const [command, target, ...extra] = process.argv.slice(2);
  assert(extra.length === 0 && target, "usage: windows-installed-lifecycle-evidence.mjs <validate|validate-directory> <path>");
  if (command === "validate") {
    const record = await verifyWindowsInstalledLifecycleEvidenceFile(path.resolve(target));
    process.stdout.write(`Validated ${record.rowId}/${record.boundary}: ${record.outcome}.\n`);
    return;
  }
  if (command === "validate-directory") {
    const { summary } = await verifyWindowsInstalledLifecycleEvidenceDirectory(path.resolve(target));
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return;
  }
  throw new Error("usage: windows-installed-lifecycle-evidence.mjs <validate|validate-directory> <path>");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runMain(main);
