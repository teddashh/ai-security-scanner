# Security policy

Normative status: this file governs vulnerability reporting and summarizes security invariants. The [canonical product specification](docs/product-spec.md) controls product behavior, recovery, and warning-versus-hard-block decisions. A control here may stop the exact destructive, untrusted-code, prohibited-contact, or signed-output operation; it must not turn an optional engine or disposable-runtime problem into a product-wide gate.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, case evidence, scan authorization, a user's host, or a third-party target.

Use GitHub's private vulnerability reporting feature for this repository. Include:

- the affected commit or release;
- operating system and, only if known, whether the app used Managed scan tools, Docker, or Podman;
- a minimal reproduction that does not include real credentials, findings, customer names, domains, or IP addresses;
- the trust boundary crossed and likely impact;
- whether the issue can trigger a network request, container execution, evidence disclosure, or credential persistence.

Do not test a report against infrastructure you do not own or have explicit permission to assess.

## Supported versions

The project is currently pre-release. Security fixes are applied to the active development branch until the first supported release line is published. Every offered artifact publishes its support window, and every admitted engine records the applicable engine, rules, feed, or database knowledge date. An expired artifact or stale engine input must show a visible, scoped warning; neither may imply that unrelated findings share one global freshness date.

## Sensitive design invariants

- Administrative bootstrap material must never enter a third-party engine, adapter, log, crash report, command line, environment variable, or Docker metadata.
- External active contact must not start without a matching, unexpired asset scope grant. For the ordinary exact low-impact path, the combined **Start** action records that grant inline; it is not a second consent page. The operation-scoped refusal must leave unrelated targets, local checks, saved reports, and exports available.
- Raw evidence must be treated as sensitive even when scanning is read-only.
- Export signatures attest only to package integrity after export, not scan correctness, completeness, identity, compliance, or forensic chain of custody.
- “Unknown” and “not connected” must never be converted into “passed.”
- No remediation command may be executed by the product or an included AI skill.

The full model is in [docs/threat-model.md](docs/threat-model.md).
