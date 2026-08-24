# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, case evidence, scan authorization, a user's host, or a third-party target.

Use GitHub's private vulnerability reporting feature for this repository. Include:

- the affected commit or release;
- operating system and runtime provider;
- a minimal reproduction that does not include real credentials, findings, customer names, domains, or IP addresses;
- the trust boundary crossed and likely impact;
- whether the issue can trigger a network request, container execution, evidence disclosure, or credential persistence.

Do not test a report against infrastructure you do not own or have explicit permission to assess.

## Supported versions

The project is currently pre-release. Security fixes are applied to the active development branch until the first supported release line is published. Every release will publish a support deadline and a scanner-knowledge cutoff. An expired release must show a visible warning and must not imply that its findings reflect current vulnerability knowledge.

## Sensitive design invariants

- Administrative bootstrap material must never enter a third-party engine, adapter, log, crash report, command line, environment variable, or Docker metadata.
- External active scanning must fail closed without a matching, unexpired asset scope grant.
- Raw evidence must be treated as sensitive even when scanning is read-only.
- Export signatures attest only to package integrity after export, not scan correctness, completeness, identity, compliance, or forensic chain of custody.
- “Unknown” and “not connected” must never be converted into “passed.”
- No remediation command may be executed by the product or an included AI skill.

The full model is in [docs/threat-model.md](docs/threat-model.md).
