# IAM-naive first-run usability study

Status: required product-completion evidence; no completed session is recorded yet

This study answers one narrow question from the product specification: can a person who can sign in
as an administrator, but does not understand cloud IAM or security scanners, complete the first
assessment without a maintainer taking over?

Automated tests, a maintainer walkthrough, screenshots made by a contributor, and a synthetic demo
case do not answer that question. They may be used to prepare the build, but they must never be
recorded as a participant session.

## Participant

Use an adult volunteer who:

- has not contributed to `ai-security-scanner` and has not seen its setup instructions before;
- self-reports no professional security role and no ability to create or explain a cloud IAM role;
- can use the test computer and can sign in to the bounded test cloud account as its administrator;
- has given informed consent to observation and to the stated evidence-retention policy.

Use a pseudonymous participant ID. Do not put a name, email address, cloud identifier, credential,
session token, raw finding, or other personal or customer data in the repository.

## Test system

The session must use a clean supported desktop installation, not a source checkout. Record the exact
product version, 40-character source commit, installer SHA-256, operating system, architecture, and
managed-runtime provider. The test cloud account must contain no production data and must be safe to
delete after the session.

The candidate build must start with an empty application data directory. A facilitator may prepare
the disposable cloud account and operating-system screen recording before the clock starts, but may
not preconfigure the application, its managed runtime, a scanning role, or a case.

## Neutral prompt

Give the participant only this prompt:

> Install and open ai-security-scanner. Create a security assessment case for this test AWS account,
> connect it using the access you have, scan what the product says is appropriate, then show what was
> checked, what remains unknown, and what you would send to a security professional.

The participant may use help that ships in the application. The facilitator may repeat the prompt,
ask the participant to think aloud, or resolve a laboratory/recording failure. Any other help must be
timestamped and categorized in the evidence. Taking the mouse or keyboard, dictating IAM steps, or
running a command for the participant makes the affected task assisted and prevents a passing result.

## Required tasks

Record every task, including failures and retries, with the stable IDs below:

1. `install_and_start` — install the candidate and reach the real local application.
2. `create_case` — create a non-demo case and complete the relevant questionnaire.
3. `prepare_runtime` — make the product-managed isolated runtime ready using product UI.
4. `connect_aws` — choose the AWS source and enter the administrator bootstrap path without exposing
   administrator material to a scanner.
5. `confirm_scope` — identify and approve the intended read-only/configuration scope; do not approve
   an unrelated asset or active external target.
6. `run_assessment` — let the automatically selected cloud engines reach honest terminal states.
7. `interpret_coverage` — correctly distinguish scanned, incomplete, not authorized, and unknown.
8. `prepare_handoff` — preview/export a case package and identify an appropriate independent expert.
9. `inspect_cleanup` — find the product's bootstrap/runtime cleanup status and complete required
   cleanup for the disposable account.

Do not silently omit a task because a prior task failed. Mark dependent tasks `blocked` and state the
dependency.

## Evidence capture

Create one JSON file conforming to
[`session-evidence.schema.json`](session-evidence.schema.json). Preserve, outside the public
repository when necessary:

- the consent record;
- timestamped observer notes;
- a screen recording or equivalent timestamped interaction record;
- the exported case package;
- the product logs after structured redaction; and
- cloud audit/cleanup evidence proving which principal and account were used.

The public session record contains the artifact role, byte length, SHA-256, capture time, redaction
state, and a non-secret retention reference. A hash proves only that the referenced bytes did not
change after capture. It does not prove that a human participated or that an observation is true;
participant confirmation plus independent facilitator attestation remain necessary.

If the screen or logs expose a credential, stop, revoke it, record a critical observation without
copying the secret, and fail the session. Never commit the affected artifact.

## Decision rule

A session passes only when:

- it is an observed live session with a qualifying, non-synthetic participant;
- all nine tasks are recorded and completed without takeover or operational instruction;
- the installed build and evidence are bound to the exact release-candidate commit;
- the participant can explain that no finding is not the same as complete coverage, identifies at
  least one unknown/incomplete state when present, and does not interpret NIST/ISO references as a
  certification;
- the bootstrap credential boundary and cleanup both succeed without a secret-exposure event; and
- both participant confirmation and facilitator attestation are recorded after the session.

If the participant cannot finish, the result is `fail`, not a missing record. If the lab, recording,
or provider is unavailable, use `inconclusive` and repeat with a fresh session ID. Every observed
blocking issue remains in `unresolvedBlockers` until a later product change and new session resolve
it; editing an old result into a pass is prohibited.

Run the structural validator while preparing records:

```sh
npm run validate:usability-evidence -- --evidence path/to/session.json
```

For a product-completion candidate, validate the evidence directory against the exact checked-out
commit and require at least one honest pass:

```sh
npm run validate:usability-evidence -- \
  --evidence-dir docs/usability/evidence \
  --require-current-pass
```

Until that second command succeeds on real evidence, documentation and release notes must say that
IAM-naive first-run usability remains unverified.
