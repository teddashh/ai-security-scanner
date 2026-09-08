# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, scan evidence, authorization records, a user's host, or a third-party target.

Use GitHub's private vulnerability reporting feature for this repository. Include:

- the affected commit or product version;
- the operating system and relevant scan path;
- a minimal reproduction without real credentials, findings, customer names, domains, or IP addresses;
- the trust boundary crossed and likely impact; and
- whether the issue can trigger network contact, process or container execution, evidence disclosure, or credential persistence.

Do not test a report against infrastructure you do not own or have explicit permission to assess.

## Operating safety

- Never send credentials or administrative bootstrap material to a scanner, adapter, log, crash report, command line, environment variable, or container metadata unless the product explicitly documents that exact secure flow.
- Never actively contact an external target without a matching user-approved scope.
- Treat raw evidence and reports as sensitive data, even when a scan is read-only.
- Store local case data with protected per-user filesystem permissions. The application does not claim additional encryption at rest.
- Preserve the distinction between `no findings`, `not tested`, `failed`, `timed out`, and `unknown`.
- A report signature or checksum establishes integrity only; it does not establish correctness, completeness, identity, or compliance.
- Do not execute remediation commands through the product or its included AI skill.

Scanner failures should be contained to the affected check whenever safe. A hard stop is appropriate when continuing would contact an unauthorized target, execute untrusted code, expose sensitive data, or cause an irreversible destructive action.

See the [threat model](docs/threat-model.md) for the detailed trust boundaries.
