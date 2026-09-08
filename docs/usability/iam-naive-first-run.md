# AWS usability research: IAM-naive participant

Status: research protocol; no completed AWS session is recorded.

This document records how to study the optional AWS experience with a participant who does not understand IAM. It is not a product roadmap, release condition, compliance requirement, or universal beginner journey. Product priorities come from the [product specification](../product-spec.md). Run this study only when the product owner chooses to investigate the AWS path.

## Research question

Can a person who can use the computer and sign in to a disposable AWS account—but does not understand IAM or security scanners—connect supported read-only access, start a useful assessment, understand partial coverage, and prepare a report without a maintainer taking over?

The study should reveal product friction, not test whether the participant can invent IAM roles, copy role ARNs, diagnose provider internals, or operate scan infrastructure.

## Participant and test account

Use an adult volunteer who:

- has not contributed to or rehearsed the product;
- has no professional security or IAM experience;
- can use the test computer and AWS sign-in; and
- consents to observation and the stated evidence-retention policy.

Use a pseudonymous participant ID and a disposable AWS account with no production data. Never place a participant name, email, cloud identifier, credential, session token, raw finding, or customer data in the repository.

## Study variants

Choose and record one variant:

1. **Configured path:** supported organizational setup already exists. The participant uses the official short-lived sign-in and selects the displayed account.
2. **Unconfigured handoff:** supported setup does not exist. Observe whether the product explains the missing prerequisite, creates a concise non-secret request for IT, and lets the participant return to another useful scan.

The facilitator may prepare the disposable account and recording. During the session, the facilitator must not choose targets, enter provider identifiers, approve scope, repair infrastructure, or operate the product for the participant. Record any help that becomes necessary.

## Neutral prompt

Configured path:

> Use ai-security-scanner to check this test AWS account with read-only access. Show what was tested, what needs attention first, what was not tested, and the report you would share with someone who can help.

Unconfigured handoff:

> Find out whether this test AWS account can be connected. If it cannot, show what you would send to IT, then return to another scan you can start now.

## Observations to record

The evidence schema uses these stable task IDs. They are research coordinates, not prescribed screens:

1. `install_and_start` — reach the application.
2. `create_case` — choose AWS and create or select the project.
3. `prepare_runtime` — observe whether scan-tool preparation stays out of the user's way.
4. `connect_aws` — use the official sign-in without pasting secrets or manual provider identifiers.
5. `confirm_scope` — understand the displayed read-only account and start the scan.
6. `run_assessment` — observe useful checks and the effect of an optional scanner failure.
7. `interpret_coverage` — distinguish tested, not tested, failed, timed out, and excluded work.
8. `prepare_handoff` — identify the priority result, next action, and report to share.
9. `inspect_cleanup` — understand remaining access and disconnect it when offered.

Also record unnecessary fields, unclear language, dead ends, facilitator help, time to first useful result, whether the participant understood the top finding, and whether the report supported a sensible next action.

Seeing or operating WSL, containers, gateways, engine manifests, runtime ownership, or repair diagnostics is a usability problem to record; it is never a participant task.

## Evidence handling

Where the schema can represent the observation, create a redacted record conforming to [`session-evidence.schema.json`](session-evidence.schema.json). Keep consent, recordings, exported reports, and provider audit evidence outside the public repository when necessary. Public records may contain only non-secret metadata, hashes, timestamps, redaction state, and a retention reference.

If a screen or log exposes a credential, stop the study, revoke the credential, and record the incident without copying the secret.

The structural validator is:

```sh
npm run validate:usability-evidence -- --evidence path/to/session.json
```

Validator success means only that the research record has the expected shape. It does not establish usability, product quality, release readiness, or compliance.

## Interpreting results

Summarize observed behavior directly:

- what the participant completed without help;
- the first useful security result and how long it took;
- whether scope, coverage gaps, priority, impact, and next action were understood;
- where the participant hesitated or needed help; and
- specific product changes suggested by the evidence.

An unconfigured handoff can demonstrate that the fallback experience works, but it is not evidence that an AWS scan ran. A failed or incomplete session remains useful research data; do not edit it into a pass. Product decisions based on the study belong to the product owner.
