# Advanced AWS usability study for an IAM-naive participant

Status: Advanced feature-specific protocol; no completed AWS session is recorded yet

Normative status: subordinate to the [canonical product specification](../product-spec.md). This document evaluates only the optional AWS journey. It is not the universal first-run path, is not product-completion evidence, and cannot block localhost, website, internal-network, source-code, reporting, or another independently qualified platform/feature.

## The actual beginner release path

The release-critical beginner protocol is the installed-Windows localhost journey in [canonical specification sections 3 and 15](../product-spec.md#3-ten-minute-first-value-gate). It is intentionally not duplicated as a second product specification.

For clarity, an observer records this exact candidate-bound path:

1. install the Windows candidate;
2. enter the main screen without administering scan infrastructure;
3. press the combined **Scan this computer at 127.0.0.1:9001** action;
4. receive a saved master report from at least one executed quick task within the canonical time budget;
5. reopen the same project; and
6. export a readable report.

The qualifying participant did not build, contribute to, or rehearse the product. The facilitator may observe but may not take over, dictate operational steps, administer WSL, or create a result through the CLI. A modeled test, maintainer walkthrough, browser demo, process-start observation, or `no checks completed` report is not a pass.

That localhost record is the universal Windows beginner acceptance evidence. The rest of this file is a separate Advanced AWS feature study.

## AWS study question

Can a person who can use the test computer and sign in to a disposable AWS account—but does not understand IAM or security scanners—connect one supported read-only account, start the intended assessment, understand partial coverage, and prepare a useful report without a maintainer taking over?

This study must not ask whether the participant can invent IAM roles, copy role ARNs, diagnose provider internals, or operate the managed runtime. If organizational setup is absent, the product should produce one clear IT handoff and keep other scan paths available; that is a valid unconfigured-path outcome, not a product-wide failure.

## Participant

Use an adult volunteer who:

- has not contributed to `ai-security-scanner` and has not rehearsed these instructions;
- self-reports no professional security role and cannot create or explain a cloud IAM role;
- can use the test computer and the provider's normal sign-in page; and
- has given informed consent to observation and the stated evidence-retention policy.

Use a pseudonymous participant ID. Do not put a name, email address, cloud identifier, credential, session token, raw finding, or other personal/customer data in the repository.

## Test system and variants

Use an installed candidate, not a source checkout. Record the exact product version, 40-character source commit, installer SHA-256, operating system, architecture, and study variant. The test AWS account contains no production data and is safe to disconnect/delete after the session.

Run one of two clearly identified variants:

1. **Configured AWS path.** The disposable account has the product-supported organizational/deployer setup. The participant should use one official short-lived sign-in and choose one displayed account. No secret, role ARN, account ID, or engine setting is pasted into the beginner UI.
2. **Unconfigured handoff path.** No supported organizational setup exists. The participant should understand the concise IT handoff, return to other product work, and never be trapped in cloud/runtime repair. This variant can qualify the handoff UX, but it does not qualify AWS scanning.

The facilitator may prepare the disposable account and recording before the clock starts. The facilitator may not preconfigure the participant's application, select targets, enter provider identifiers, approve scope, repair infrastructure, or run commands during the session.

## Neutral prompts

For the configured variant, give only this prompt:

> Use ai-security-scanner to check this test AWS account with read-only access. Show what was tested, what was not tested, what needs attention first, and the report you would share with someone who can help.

For the unconfigured variant, give only this prompt:

> Find out whether this test AWS account is ready to connect. If it is not, show what you would send to IT and then return to another scan you could start now.

The participant may use help shipped in the application. The facilitator may repeat the prompt, ask the participant to think aloud, or resolve a laboratory/recording failure. Any other help is timestamped and categorized. Taking the mouse/keyboard, dictating operational steps, or running a command makes the affected task assisted and prevents an unassisted pass.

## Required tasks

The checked-in evidence schema still uses the following legacy stable IDs. They are evidence coordinates, not UI labels or a required nine-screen journey:

1. `install_and_start` — reach the installed candidate. This may reuse the same exact candidate as the core localhost record; it does not make AWS part of universal first run.
2. `create_case` — open Advanced, choose AWS, and create/select the AWS project without mistaking cloud setup for required product setup.
3. `prepare_runtime` — observe that scan-tool preparation happens automatically behind the task. Any participant action involving scan infrastructure is a blocking observation.
4. `connect_aws` — complete official sign-in for the configured variant; never paste a secret, role ARN, account ID, or engine setting.
5. `confirm_scope` — understand one displayed read-only account and start once; no duplicate consent or hidden permission step follows.
6. `run_assessment` — observe available AWS checks continue independently when one optional engine/source fails.
7. `interpret_coverage` — distinguish tested, not tested, failed, timed out, and excluded coverage; do not interpret no findings as complete safety.
8. `prepare_handoff` — preview/export the master report and identify a reasonable next helper/action.
9. `inspect_cleanup` — understand what access remains, disconnect when offered, and leave unrelated projects/results intact. It is not a task to clean up WSL or runtime internals.

For the unconfigured variant, record the successful IT handoff and return to another scan as observations. Mark the feature-study step `blocked`, while recording every corresponding product scan task as `not_tested` (or `failed`/`timed_out` only when it actually reached that outcome); never mark either layer completed merely because no scan could start. The current schema cannot call that a passing AWS scan. A future feature-scoped schema may represent a separate handoff-only pass without changing the universal product gate.

Seeing or operating WSL, Podman, a gateway, engine manifests, runtime ownership, or Repair diagnostics is a critical UX observation; it is never a required participant task.

## Evidence capture

Create one redacted JSON record conforming to [`session-evidence.schema.json`](session-evidence.schema.json) where the schema can represent the observation. Preserve outside the public repository when necessary:

- the consent record;
- timestamped observer notes;
- a screen recording or equivalent timestamped interaction record;
- the exported report; and
- provider audit/disconnect evidence for the disposable account.

The public record contains artifact role, byte length, SHA-256, capture time, redaction state, and a non-secret retention reference. A hash proves only that bytes did not change; it does not prove that a human participated or that the observation is true. Participant confirmation and independent facilitator attestation remain necessary.

If the screen or logs expose a credential, stop, revoke it, record a critical observation without copying the secret, and fail the session. Never commit the affected artifact.

## Decision rules

### Configured AWS pass

The configured AWS feature passes only when:

- the live session uses a qualifying participant and exact installed candidate;
- all nine applicable tasks finish without takeover or operational instruction;
- one displayed account is connected through the official short-lived path with no secret/manual identifier form;
- one Start action records the exact scope without a second consent ceremony;
- an optional engine failure still leaves an understandable partial master report;
- the participant can explain coverage gaps and does not interpret NIST/ISO/AIDEFEND references as certification; and
- disconnect/cleanup status is understandable without infrastructure knowledge.

### Unconfigured handoff outcome

The unconfigured handoff passes only when the participant:

- recognizes that organizational setup is missing;
- produces one concise non-secret IT handoff;
- is not told to repair WSL/runtime or paste provider identifiers; and
- returns to an unaffected local/network/code path.

This result is positive usability evidence for the handoff only; it does not qualify AWS scanning and is not encoded as a configured AWS pass by the current validator.

If the participant cannot finish, record `fail`; do not omit the session. If the lab, recording, or provider is unavailable, record `inconclusive` and repeat with a fresh session ID. Never edit an old result into a pass.

## Validator scope

The existing schema/validator can check the configured AWS record structure and the legacy task IDs listed above:

```sh
npm run validate:usability-evidence -- --evidence path/to/session.json
```

Any `--require-current-pass` result for records governed by this file applies only to the configured Advanced AWS feature. It must not be described as the Windows localhost human-path pass or used as a universal product/release gate. The current validator does not encode the handoff-only variant or feature scope in its schema; update it before relying on either distinction in automation.

Until a real configured AWS session passes, documentation may say that Advanced AWS usability is unverified. It must not say that this prevents users from installing or using independently qualified non-cloud capabilities.
