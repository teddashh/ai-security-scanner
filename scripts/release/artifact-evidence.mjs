import { lstat, readFile } from "node:fs/promises";

const MAX_EVIDENCE_BYTES = 1024 * 1024;
const MAX_OBSERVED_ITEMS = 20;
const MAX_OBSERVED_TEXT = 500;
const MAX_USER_DECISIONS = 3;
const FIRST_REPORT_TIMING_BASIS =
  "installer-launch-to-first-durable-report-excluding-os-shutdown-to-desktop";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} fields are not the artifact-evidence schema-v1 set`,
  );
}

function boundedText(value, label) {
  assert(
    typeof value === "string" && value.length > 0 && value.length <= MAX_OBSERVED_TEXT && !/[\0\r\n]/u.test(value),
    `${label} must be non-empty, single-line, and at most ${MAX_OBSERVED_TEXT} characters`,
  );
}

function boundedTextList(value, label, maximum = MAX_OBSERVED_ITEMS) {
  assert(Array.isArray(value) && value.length <= maximum, `${label} must contain at most ${maximum} entries`);
  for (const [index, item] of value.entries()) boundedText(item, `${label}[${index}]`);
}

function validateHumanDetails(details, label) {
  exactKeys(
    details,
    [
      "participantProfile",
      "participantBuiltProduct",
      "participantContributedToProduct",
      "participantRehearsedSetup",
      "facilitatorTookControl",
      "facilitatorDictatedOperationalSteps",
      "facilitatorAdministeredWsl",
      "terminalOpened",
      "typedCommandCount",
      "windowsVersion",
      "firstReportTimingBasis",
      "firstReportElapsedSeconds",
      "firstReportWallClockElapsedSeconds",
      "excludedOperatingSystemRestartSeconds",
      "totalJourneyElapsedSeconds",
      "userDecisions",
      "visibleErrors",
      "installed",
      "launched",
      "minimumLocalhostScanStarted",
      "beginnerReportViewed",
      "projectReopened",
      "readableReportExported",
      "readableExport",
      "finalCoverage",
      "localhostReport",
    ],
    `${label} beginner details`,
  );
  assert(
    details.participantProfile === "windows-beginner-no-security-or-linux-experience",
    `${label} did not use the fixed beginner participant profile`,
  );
  assert(details.participantBuiltProduct === false, `${label} participant built the product`);
  assert(details.participantContributedToProduct === false, `${label} participant contributed to the product`);
  assert(details.participantRehearsedSetup === false, `${label} participant rehearsed the setup`);
  assert(details.facilitatorTookControl === false, `${label} facilitator took control during the human path`);
  assert(
    details.facilitatorDictatedOperationalSteps === false,
    `${label} facilitator dictated operational steps during the human path`,
  );
  assert(
    details.facilitatorAdministeredWsl === false,
    `${label} facilitator administered WSL during the human path`,
  );
  assert(details.terminalOpened === false, `${label} participant had to open Terminal`);
  assert(details.typedCommandCount === 0, `${label} participant had to type a command`);
  boundedText(details.windowsVersion, `${label} Windows version`);
  assert(
    details.firstReportTimingBasis === FIRST_REPORT_TIMING_BASIS,
    `${label} first-report timing does not measure installer launch to durable report with only OS restart downtime excluded`,
  );
  assert(
    Number.isSafeInteger(details.firstReportElapsedSeconds) &&
      details.firstReportElapsedSeconds > 0 &&
      details.firstReportElapsedSeconds <= 600,
    `${label} did not produce the first durable report within ten minutes`,
  );
  assert(
    Number.isSafeInteger(details.excludedOperatingSystemRestartSeconds) &&
      details.excludedOperatingSystemRestartSeconds >= 0,
    `${label} excluded OS restart duration is invalid`,
  );
  assert(
    Number.isSafeInteger(details.firstReportWallClockElapsedSeconds) &&
      details.firstReportWallClockElapsedSeconds ===
        details.firstReportElapsedSeconds + details.excludedOperatingSystemRestartSeconds,
    `${label} first-report wall-clock duration does not reconcile with its sole restart exclusion`,
  );
  assert(
    Number.isSafeInteger(details.totalJourneyElapsedSeconds) &&
      details.totalJourneyElapsedSeconds >= details.firstReportWallClockElapsedSeconds,
    `${label} total journey duration must include the first report without applying the ten-minute bound to reopen/export`,
  );
  boundedTextList(details.userDecisions, `${label} user decisions`, MAX_USER_DECISIONS);
  const allowedDecisions = ["install", "approve-windows-prompt", "start-localhost-scan"];
  assert(
    details.userDecisions.every((decision) => allowedDecisions.includes(decision)) &&
      new Set(details.userDecisions).size === details.userDecisions.length &&
      details.userDecisions[0] === "install" &&
      details.userDecisions.at(-1) === "start-localhost-scan",
    `${label} first-value decisions are incomplete, duplicated, or outside the fixed beginner path`,
  );
  if (details.excludedOperatingSystemRestartSeconds > 0) {
    assert(
      details.userDecisions.includes("approve-windows-prompt"),
      `${label} excluded Windows restart time without recording the Windows approval decision`,
    );
  }
  boundedTextList(details.visibleErrors, `${label} visible errors`);
  for (const step of [
    "installed",
    "launched",
    "minimumLocalhostScanStarted",
    "beginnerReportViewed",
    "projectReopened",
    "readableReportExported",
  ]) {
    assert(details[step] === true, `${label} beginner path is incomplete at ${step}`);
  }
  exactKeys(details.readableExport, ["format", "outcome"], `${label} readable export`);
  assert(details.readableExport.format === "html", `${label} beginner export was not readable HTML`);
  assert(
    details.readableExport.outcome === "exported-and-opened-readable",
    `${label} beginner export was not opened and observed as readable`,
  );

  exactKeys(
    details.finalCoverage,
    ["state", "testedCount", "notTestedCount", "failedCount", "coverageGapCount"],
    `${label} final coverage`,
  );
  assert(
    ["complete", "partial", "no-checks-completed"].includes(details.finalCoverage.state),
    `${label} final coverage state is invalid`,
  );
  assert(
    details.finalCoverage.state !== "no-checks-completed",
    `${label} first-value path did not complete any check`,
  );
  for (const field of ["testedCount", "notTestedCount", "failedCount", "coverageGapCount"]) {
    assert(
      Number.isSafeInteger(details.finalCoverage[field]) && details.finalCoverage[field] >= 0,
      `${label} final coverage ${field} is invalid`,
    );
  }
  if (details.finalCoverage.state === "complete") {
    assert(
      details.finalCoverage.testedCount > 0 &&
        details.finalCoverage.notTestedCount === 0 &&
        details.finalCoverage.failedCount === 0 &&
        details.finalCoverage.coverageGapCount === 0,
      `${label} complete coverage contradicts its counts`,
    );
  } else {
    assert(
      details.finalCoverage.notTestedCount +
        details.finalCoverage.failedCount +
        details.finalCoverage.coverageGapCount > 0,
      `${label} incomplete coverage state has no disclosed gap`,
    );
  }

  exactKeys(
    details.localhostReport,
    ["target", "taskExecutionState", "outcome", "findingCount", "durableReportId", "durableReportState"],
    `${label} localhost report`,
  );
  assert(details.localhostReport.target === "127.0.0.1:9001", `${label} did not observe the fixed localhost target`);
  assert(
    details.localhostReport.taskExecutionState === "executed",
    `${label} localhost task was not actually executed`,
  );
  assert(
    ["reachable", "closed", "timed_out", "unreachable"].includes(details.localhostReport.outcome),
    `${label} localhost report outcome is invalid`,
  );
  assert(
    Number.isSafeInteger(details.localhostReport.findingCount) && details.localhostReport.findingCount >= 0,
    `${label} localhost report finding count is invalid`,
  );
  assert(
    typeof details.localhostReport.durableReportId === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(
        details.localhostReport.durableReportId,
      ),
    `${label} localhost report has no durable report ID`,
  );
  assert(
    details.localhostReport.durableReportState === "saved",
    `${label} localhost report was not durably saved`,
  );
  if (["timed_out", "unreachable"].includes(details.localhostReport.outcome)) {
    assert(details.finalCoverage.state !== "complete", `${label} incomplete localhost outcome claims complete coverage`);
  }
}

function validateVerificationDetails(details, label) {
  exactKeys(details, ["provider", "verificationTool"], `${label} verification details`);
  boundedText(details.provider, `${label} verification provider`);
  boundedText(details.verificationTool, `${label} verification tool`);
}

function validateOperatingSystemSigningDetails(details, label, expected) {
  exactKeys(
    details,
    [
      "signatureScheme",
      "signatureStatus",
      "artifactSha256",
      "expectedPublisherIdentity",
      "observedPublisherIdentity",
      "verificationTool",
      "producer",
    ],
    `${label} operating-system signing details`,
  );
  assert(details.signatureScheme === "authenticode", `${label} signature scheme is not Authenticode`);
  assert(details.signatureStatus === "Valid", `${label} Authenticode status is not Valid`);
  assert(details.artifactSha256 === expected.artifact.sha256, `${label} signing result is not bound to the installer digest`);
  boundedText(details.expectedPublisherIdentity, `${label} expected publisher identity`);
  boundedText(details.observedPublisherIdentity, `${label} observed publisher identity`);
  assert(
    details.expectedPublisherIdentity === details.observedPublisherIdentity,
    `${label} observed Authenticode publisher differs from the expected publisher`,
  );
  assert(
    details.verificationTool === "Get-AuthenticodeSignature",
    `${label} Authenticode verification tool is not the fixed Windows verifier`,
  );

  const policy = expected.operatingSystemSigningPolicy;
  assert(policy && typeof policy === "object", `${label} has no configured protected Authenticode producer policy`);
  assert(
    Array.isArray(policy.allowedPublisherIdentities) &&
      policy.allowedPublisherIdentities.length > 0 &&
      policy.allowedPublisherIdentities.length <= 8 &&
      policy.allowedPublisherIdentities.includes(details.expectedPublisherIdentity),
    `${label} publisher identity is not in the bounded release allowlist`,
  );
  for (const [index, publisher] of policy.allowedPublisherIdentities.entries()) {
    boundedText(publisher, `${label} publisher allowlist[${index}]`);
  }
  assert(
    new Set(policy.allowedPublisherIdentities).size === policy.allowedPublisherIdentities.length,
    `${label} publisher allowlist contains duplicates`,
  );
  exactKeys(
    details.producer,
    ["provider", "repository", "workflow", "workflowRef", "runId", "runAttempt", "job", "environment"],
    `${label} protected producer`,
  );
  for (const field of ["provider", "repository", "workflow", "workflowRef", "runId", "job", "environment"]) {
    boundedText(details.producer[field], `${label} producer ${field}`);
  }
  assert(/^[1-9][0-9]{0,19}$/u.test(details.producer.runId), `${label} producer run ID is invalid`);
  assert(
    Number.isSafeInteger(details.producer.runAttempt) &&
      details.producer.runAttempt >= 1 &&
      details.producer.runAttempt <= 100,
    `${label} producer run attempt is invalid`,
  );
  for (const field of ["provider", "repository", "workflow", "workflowRef", "runId", "runAttempt", "job", "environment"]) {
    assert(details.producer[field] === policy[field], `${label} protected producer ${field} differs from release policy`);
  }
}

export function validateBoundArtifactEvidence(evidence, expected) {
  const label = expected.label ?? expected.evidenceType;
  exactKeys(
    evidence,
    [
      "schemaVersion",
      "evidenceType",
      "product",
      "platform",
      "installerType",
      "releaseIdentity",
      "artifact",
      "outcome",
      "observedAt",
      "details",
    ],
    label,
  );
  assert(evidence.schemaVersion === 1, `${label} schemaVersion must be 1`);
  assert(evidence.evidenceType === expected.evidenceType, `${label} evidence type is invalid`);
  assert(evidence.product === "ai-security-scanner", `${label} product is invalid`);
  assert(
    evidence.platform === expected.platform && evidence.installerType === expected.installerType,
    `${label} platform/installer identity mismatch`,
  );
  exactKeys(evidence.releaseIdentity, ["version", "tag", "sourceCommit"], `${label} release identity`);
  assert(
    evidence.releaseIdentity.version === expected.version &&
      evidence.releaseIdentity.tag === expected.tag &&
      evidence.releaseIdentity.sourceCommit === expected.commit,
    `${label} release identity mismatch`,
  );
  exactKeys(evidence.artifact, ["file", "bytes", "sha256"], `${label} artifact identity`);
  assert(
    evidence.artifact.file === expected.artifact.file &&
      evidence.artifact.bytes === expected.artifact.bytes &&
      evidence.artifact.sha256 === expected.artifact.sha256,
    `${label} artifact identity mismatch`,
  );
  assert(evidence.outcome === "passed", `${label} outcome did not pass`);
  assert(
    typeof evidence.observedAt === "string" && !Number.isNaN(Date.parse(evidence.observedAt)),
    `${label} observedAt is invalid`,
  );
  if (expected.evidenceType === "beginner-human-path") {
    validateHumanDetails(evidence.details, label);
  } else if (expected.evidenceType === "operating-system-code-signing") {
    validateOperatingSystemSigningDetails(evidence.details, label, expected);
  } else if (expected.evidenceType === "apple-notarization") {
    validateVerificationDetails(evidence.details, label);
  } else {
    throw new Error(`${label} uses an unsupported artifact evidence type`);
  }
  return evidence;
}

export async function verifyBoundArtifactEvidenceFile(file, expected) {
  const metadata = await lstat(file);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), `${file} must be a regular non-symlink evidence file`);
  assert(metadata.size > 0 && metadata.size <= MAX_EVIDENCE_BYTES, `${file} evidence size is invalid`);
  const evidence = JSON.parse(await readFile(file, "utf8"));
  return validateBoundArtifactEvidence(evidence, { ...expected, label: expected.label ?? file });
}
