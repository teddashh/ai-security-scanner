# Development status

[繁體中文](development-status.zh-TW.md) · [Documentation](README.md)

_Updated 2026-10-03._

This page summarizes current engineering status for contributors. It is not a product specification
or release declaration. [The product specification](product-spec.md) remains the source of truth for
product behavior, and the [current product review](product-audit.md) tracks the broader user journey.

## At a glance

- The current release, [v0.3.1](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.3.1), is on the stable channel for Linux, macOS, and Windows. See the [release record](release/v0.3.1.md) for exact installer and updater observations.
- The released desktop includes Prowler failure headlines, approved AWS report grouping, reconnect-and-rescan, blocked-scan continuations, Semgrep `1.174.0-4`, and explicit kube-bench/KICS incomplete-coverage handling.
- A fresh owner-signed-in Microsoft 365 live rerun remains unobserved. Garak and Agentic Radar remain non-runnable; these records are not additional advertised capabilities.
- The paired repository [Agent Skills](getting-started.md#use-with-an-agent-skill) install the
  desktop release, check that a computer can scan, guide a scan in the app, and save its report;
  the Linux source build is documented there for changing the product.
- The engine catalog contains 25 records: 23 integrated, runnable engines and 2 experimental
  integrations that remain non-runnable.
- Repository, website/API, infrastructure, cloud, Microsoft 365, and Kubernetes paths use bounded
  upstream checks and feed one product-owned report.
- Report presentation distinguishes measured zero findings from an asset that was not measured, and
  keeps compact document identity in printed headers and footers.
- The shared HTML exporter on main contains wide check tables within their scroll areas, stacks report cards at tablet widths, and wraps long technical identifiers. This source fix is not included in the published v0.3.1 installer; its original delivery observations remain in the release record.
- Main also recognizes the native `microsoft365` provider value when displaying identity assets, so they retain their Microsoft 365 platform instead of appearing as public websites and IP addresses. This source fix is not included in v0.3.1.
- The offline adapter refresh pipeline produces reviewable proposals; deterministic generation is the
  default, AI edits require explicit opt-in and digest attribution, and the person running it chooses
  whether to open a pull request while the pipeline executes no commands.
- Native report, case, coverage, route, permission, and engine-task vocabularies are bound to their Rust
  wire contracts; unknown permissions and tasks cannot claim authorization, execution, or coverage.
- No model endpoint or hosted provider was contacted while developing the experimental AI paths.

The owner has selected result integrity, engine build/patch maintenance, and experimental integrations before **v0.4.0 stable**. Result-integrity work now separates Greenbone tasks by exact grant, freezes task grant membership for resume, rejects malformed or unevaluated Kubescape output as complete coverage, and streams large reports within the 512 MiB evidence budget. This is development work; it is not included in the frozen v0.3.1 installer. The Gitleaks fixture rebuild and complete recipe/patch audit are finished. ZAP now has an explicit passive website choice, per-grant dispatch and native per-request pacing; Garak and Agentic Radar activation remain in progress; v0.4.0 has not been packaged or published.

## AI integration work

| Integration | Implemented | Current fail-closed boundary |
| --- | --- | --- |
| Garak | A thin adapter preserves probe identifiers and failure counts without inventing severity. | No managed image, exact model-endpoint scope grant, or product-owned credential path exists. |
| Agentic Radar | Its workflow graph is normalized as observations rather than unsupported vulnerability findings; incomplete machine output fails closed. | No managed image or typed framework-selection path exists; the machine-output contract is absent from an accepted upstream release. |
| MCP Armor | One exact MCP configuration file can be selected from an immutable repository snapshot and checked by a restricted, model-free configuration launcher. The local image produced a complete two-check report and an excessive-permission finding from a synthetic fixture with networking disabled. | The image is published, digest-pinned, and dispatchable, but not default-enabled. It runs with networking disabled over one approved MCP configuration snapshot; it does not start or contact an MCP server or load a model. |
| Augustus | Research-only, pure-data 14-rule preflight contracts and rejection fixtures define the required endpoint, cost, request, deadline, sandbox, and output boundaries. | No production catalog entry, adapter, launcher, provider connection, credential path, or dispatch path exists yet. |

Garak and Agentic Radar remain `runnable: false`. Research artifacts and local image identifiers are
not substitutes for a published digest or an authorized runtime path.

## Other experimental engine integrations

Not every experimental record is an AI integration. A verified upstream artifact can exist before the
product is able to dispatch it; the catalog blockers, not the artifact, decide whether a record is a
current scan capability.

| Integration | Implemented | Current fail-closed boundary |
| --- | --- | --- |
| ZAP | The reviewed `zap_passive_v1` profile derives a passive-only plan from one exact frozen grant. Native network add-on 0.29.0 paces every HTTP request, including keep-alive requests, at 5/s with five spider threads and a 10-second request timeout. The orchestrator mounts and hashes the private plan, and saves its digest for recovery and cleanup. Website Advanced and mixed-environment website settings explicitly select it; Nuclei remains the default. | Dispatchable on main; absent from frozen v0.3.1 installers. Crawl is bounded to two minutes, depth five and 100 children per page; response processing is bounded to two minutes. No authentication, form submission, active attack jobs or other origins. Empty unobserved-site reports are incomplete. |

## Grype repository scan

The current catalog pins Grype to `0.117.0-4`. A controlled Linux repository scan recorded 81 Grype
findings (10 critical, 32 high, 33 medium, 6 low), with Grype completed and exit code 0. The full run
recorded 192 findings, 8 completed checks, and 2 not executed: Agentic Radar had no runnable release,
and MCP Armor had no selected MCP configuration. These are results for that fixture, not promised
counts for other repositories. See [the exact pin and recorded result](engine-catalog.md#grype-repository-support).

## Recorded verification baseline

The October 4 ZAP integration passed 2,092 Rust tests, 798 frontend tests (six explicit skips), 518 component tests, formatting, Clippy, and the production build. Controlled native amd64 scans verified frozen hostname resolution, origin boundaries, keep-alive request pacing and cancellation; the report regression preserves all native alert instances. This verifies the current source and controlled fixtures, not a published v0.4.0 installer.

The October 3 source-readiness audit recorded 2,072 passing Rust tests, 798 frontend tests (six explicit skips), 515 component tests, 89 CI contracts and 202 release contracts. Formatting, Clippy, production build, engine admission and release identity passed. The v0.3.1 preparation also passed the full release self-test and the three gateway identity/security tests. Exact installer observations are recorded separately in [v0.3.1](release/v0.3.1.md); source tests do not substitute for installation or human-path evidence.


The following test counts are the successful local baseline recorded on September 19, 2026; they
are not a new test run for this documentation update:

- Rust core and CLI: 1,752 tests.
- Frontend unit tests: 696 tests.
- Component rendering: 322 tests across 20 files.
- CI document and contract tests: 81 tests.
- Engine catalog validation: 8 tests.
- TypeScript type checking, Rust formatting, and Clippy: passed.

CI document and contract tests: 83 tests passed on September 20, 2026, including the adapter refresh
CLI missing-value regression (`node --test tests/ci/*.test.mjs`).

CI document and contract tests: 84 tests passed on September 21, 2026 (`node --test tests/ci/*.test.mjs`),
including the beginner HTML locale contract and the published MCP Armor distribution decision.

CI document and contract tests: 89 tests include four scoped engine-publication selection checks
added on October 3, 2026. Two workflow checks run in the release-contract suite after dependency
installation. Native Semgrep image verification runs separately before publication.

CI document and contract tests: 85 tests passed on October 1, 2026 (`node --test tests/ci/*.test.mjs`),
including the check that the gateway image's startup smoke expects the status schema the gateway writes.

After removing credential-shaped text from an upstream test fixture, the MCP Armor image was rebuilt,
published, and pinned. Its offline synthetic smoke test produced one finding, two completed checks, no
warning, and `complete: true` under `network=none`.

## Current blockers

- Garak and Agentic Radar remain non-runnable while their catalog blockers exist.

These blockers describe fail-closed admission state; they do not authorize a publication or release
plan. Publication, packaging, signing, versioning, and compliance posture remain product-owner
decisions.
Real endpoint scans require explicit scope and must never infer authorization or accept credentials
through chat or command arguments.

## Supporting records

- [Engine catalog](engine-catalog.md)
- [MCP Armor research decision](research/mcp-armor-evaluation.md)
- [Agentic Radar research decision](research/agentic-radar-evaluation.md)
- [Augustus research decision](research/augustus-evaluation.md)
- [Product doctrine](PRODUCT-DOCTRINE.md)

CI document and contract tests: 91 tests now include exact old-image/new-candidate separation and rejection of executable inputs hidden in publication history. Engine maintenance records actual hashes for the former uncovered baseline, reviews six downstream exception families and has verified the fresh Gitleaks native amd64 recipe and redacted synthetic scan. Signed Gitleaks `8.30.1-2` is now published and catalog-pinned, after verifying anonymous access, exact source/workflow provenance and both platform SBOM attestations.
