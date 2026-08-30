import assert from "node:assert/strict";
import test from "node:test";

import { validateEvidence } from "../../scripts/validate-usability-evidence.mjs";

const taskIds = [
  "install_and_start",
  "create_case",
  "prepare_runtime",
  "connect_aws",
  "confirm_scope",
  "run_assessment",
  "interpret_coverage",
  "prepare_handoff",
  "inspect_cleanup",
];

const artifactRoles = [
  "consent-record",
  "observer-notes",
  "interaction-record",
  "case-export",
  "cloud-audit-cleanup",
];

function validEvidence() {
  return {
    schemaVersion: "1.0.0",
    studyId: "advanced-aws-iam-naive/v1",
    sessionId: "session-test-001",
    product: {
      name: "ai-security-scanner",
      version: "0.1.1",
      sourceCommit: "a".repeat(40),
      installerSha256: `sha256:${"b".repeat(64)}`,
      os: "linux",
      osVersion: "Test Linux 1",
      architecture: "x86_64",
      runtimeProvider: "managed_local",
    },
    participant: {
      pseudonymousId: "participant-001",
      adult: true,
      consentRecorded: true,
      priorProductExposure: "none",
      securityBackground: "none",
      cloudIamExperience: "cannot-create-or-explain-role",
      synthetic: false,
    },
    facilitator: {
      pseudonymousId: "facilitator-001",
      relationship: "project-maintainer",
      conflictDisclosed: true,
    },
    session: {
      mode: "observed-live",
      startedAt: "2026-08-24T14:00:00Z",
      endedAt: "2026-08-24T15:00:00Z",
      cleanInstall: true,
      emptyDataDirectory: true,
      disposableAwsAccount: true,
      promptVersion: "advanced-aws-iam-naive/v1",
    },
    tasks: taskIds.map((id, index) => ({
      id,
      startedAt: `2026-08-24T14:${String(index).padStart(2, "0")}:00Z`,
      endedAt: `2026-08-24T14:${String(index).padStart(2, "0")}:30Z`,
      outcome: "completed",
      attempts: 1,
      assistance: [],
      observations: [{
        at: `2026-08-24T14:${String(index).padStart(2, "0")}:15Z`,
        location: `task ${id}`,
        severity: "note",
        detail: `Participant completed ${id} through the product interface.`,
      }],
    })),
    artifacts: artifactRoles.map((role, index) => ({
      role,
      sha256: `sha256:${String(index + 1).padStart(64, "0")}`,
      sizeBytes: index + 1,
      capturedAt: "2026-08-24T15:01:00Z",
      redacted: role !== "consent-record",
      containsSecrets: false,
      retentionReference: `private study vault item ${index + 1}`,
    })),
    comprehension: {
      unknownIsNotGreen: true,
      coverageStatesExplained: true,
      noComplianceClaim: true,
      nextExpertIdentified: true,
      participantWords: "The scanner cannot know about an account unless it has a source for it.",
    },
    cleanup: {
      bootstrapCredentialCleared: true,
      scannerIdentityInspected: true,
      oldSessionsAndKeysReviewed: true,
      runtimeCleanupInspected: true,
      secretExposureObserved: false,
    },
    decision: {
      outcome: "pass",
      decidedAt: "2026-08-24T15:03:00Z",
      evaluatorId: "facilitator-001",
      rationale: "All required tasks and comprehension checks completed without operational help.",
      unresolvedBlockers: [],
    },
    attestations: {
      participantConfirmedAt: "2026-08-24T15:01:00Z",
      facilitatorAttestedAt: "2026-08-24T15:02:00Z",
      recordCreatedAt: "2026-08-24T15:04:00Z",
    },
  };
}

test("accepts a complete, version-bound live-session record", () => {
  assert.equal(validateEvidence(validEvidence()).decision.outcome, "pass");
});

test("rejects a pass with a duplicated required task", () => {
  const evidence = validEvidence();
  evidence.tasks[8].id = evidence.tasks[7].id;
  assert.throws(() => validateEvidence(evidence), /duplicate task ID/u);
});

test("rejects a pass after facilitator takeover", () => {
  const evidence = validEvidence();
  evidence.tasks[3].assistance.push({
    at: "2026-08-24T14:03:10Z",
    category: "takeover",
    detail: "Facilitator used the keyboard to configure authorization.",
  });
  assert.throws(() => validateEvidence(evidence), /cannot include operational instruction or takeover/u);
});

test("requires an observed secret exposure to fail", () => {
  const evidence = validEvidence();
  evidence.cleanup.secretExposureObserved = true;
  evidence.cleanup.bootstrapCredentialCleared = false;
  evidence.decision.outcome = "inconclusive";
  evidence.decision.unresolvedBlockers = ["A credential appeared in an application log."];
  assert.throws(() => validateEvidence(evidence), /secret exposure must produce a failed decision/u);
});

test("retains an honest failed session with blocked tasks", () => {
  const evidence = validEvidence();
  evidence.tasks[3].outcome = "blocked";
  evidence.tasks[4].outcome = "blocked";
  evidence.decision.outcome = "fail";
  evidence.decision.rationale = "The participant could not understand the AWS authorization screen.";
  evidence.decision.unresolvedBlockers = ["AWS authorization wording did not explain the next action."];
  assert.equal(validateEvidence(evidence).decision.outcome, "fail");
});
