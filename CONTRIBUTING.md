# Contributing

Contributions should make the product faster to understand, easier to start, and more useful after the first scan. Read the [product specification](docs/product-spec.md) before changing user-visible behavior.

## Product priorities

Use these priorities when choosing and reviewing work:

1. A beginner can quickly start a meaningful scan and understand the result.
2. Scanner integrations stay close to upstream behavior and data.
3. The product combines engine output into one clear, professional report.
4. Versioning, release timing, publication, and compliance positioning are product-owner decisions. Do not expand work into those areas unless the owner explicitly requests it.

A connectivity check, process launch, or empty report is not meaningful scan value. Product-facing work should help the user discover a real exposure, vulnerability, secret, risky configuration, or other actionable security signal—or clearly explain why a requested check could not run.

## Product changes

Prefer the shortest complete beginner journey:

- ask only for information needed to start the selected scan;
- provide useful defaults and keep advanced controls out of the primary path;
- show what was scanned, the most important results, their impact, and the next action;
- distinguish no findings from checks that did not run; and
- preserve saved work and allow unaffected checks to continue when one scanner fails.

Test rendered behavior and a real user path where practical. Source-text assertions and schema checks can support that evidence, but they do not replace exercising the interaction they describe.

## Scanner integrations

Keep adapters thin. Let the upstream scanner own detection, rule behavior, severities, and scanner-specific evidence. Product code should concentrate on:

- converting the user's approved target and options into typed scanner input;
- launching without shell interpolation and with bounded resources;
- preserving upstream identifiers, versions, evidence, and raw output references;
- translating execution outcomes into consistent task and coverage states; and
- normalizing results for the shared report without inventing findings.

Avoid duplicating upstream detection logic or maintaining product-specific rewrites of titles, severity, and remediation when the upstream scanner already supplies them.

An engine contribution should include its official source and license, a supported version or digest, input and permission requirements, a typed launcher, redacted fixtures, parser tests, and honest completed/partial/failed/timed-out/cancelled behavior. An unavailable scanner should leave sibling checks usable and its coverage visibly untested.

## Professional reporting

All scanners feed one report model. A report contribution should improve the shared presentation of:

- scope and checks actually run;
- prioritized findings with evidence and impact;
- recommended next actions;
- coverage gaps, failures, and exclusions; and
- technical details available when needed.

Framework mappings may enrich a report, but they do not replace findings and should not control whether a scan can run.

## Verification

Run checks proportional to the changed boundary. Common commands include:

```bash
npm run test:frontend
npm run test:component
npm run typecheck
npm run build
cargo fmt --all -- --check
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
cargo test --locked --workspace --no-default-features --features cli
```

For a small copy or documentation change, focused tests and link checks are enough. For a changed scan path, exercise the affected input, execution, saved result, and report flow. Release packaging, signing, publication, and compliance work are outside ordinary contribution scope unless explicitly requested by the product owner.

## Data and scope safety

- Never commit credentials, tokens, customer findings, personal data, internal addresses, or real scan reports.
- Use synthetic, redacted fixtures and reserved example domains or address ranges.
- Never contact a target without the user's explicit scope authorization.
- Do not execute remediation commands.
- Explain new network, process, filesystem, credential, or data-retention behavior in the pull request.

Keep each change focused and rewrite obsolete guidance where it lives instead of adding contradictory correction sections.
