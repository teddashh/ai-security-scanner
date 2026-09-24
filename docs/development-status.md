# Development status

_Updated 2026-09-21._

This page summarizes current engineering status for contributors. It is not a product specification
or release declaration. [The product specification](product-spec.md) remains the source of truth for
product behavior, and the [current product review](product-audit.md) tracks the broader user journey.

## At a glance

- The current candidate is multi-OS: Linux, macOS, and Windows. Its commit-bound QC set offers
  Windows MSI and NSIS (unsigned; SmartScreen may warn), macOS Universal `.dmg` (not notarized),
  and Linux x86-64 `.deb`. Linux AppImage and `.rpm` are not offered. Public release is **HOLD**;
  these candidate bytes are not a published GitHub Release. See the [candidate record and
  testing disclosures](releasing.md#current-candidate-and-publication-hold).
- The latest published release, [v0.2.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.2.0),
  remains an earlier Linux `.deb`-only build; it does not describe the current multi-OS candidate.
- The Linux source build-to-scan path is available through the paired repository
  [Agent Skills](getting-started.md#use-with-an-agent-skill), using the same product interfaces.
- The engine catalog contains 25 records: 22 integrated, runnable engines and 3 experimental
  integrations that remain non-runnable.
- Repository, website/API, infrastructure, cloud, Microsoft 365, and Kubernetes paths use bounded
  upstream checks and feed one product-owned report.
- Report presentation distinguishes measured zero findings from an asset that was not measured, and
  keeps compact document identity in printed headers and footers.
- The offline adapter refresh pipeline produces reviewable proposals; deterministic generation is the
  default, AI edits require explicit opt-in and digest attribution, and the person running it chooses
  whether to open a pull request while the pipeline executes no commands.
- Native report, case, coverage, route, permission, and engine-task vocabularies are bound to their Rust
  wire contracts; unknown permissions and tasks cannot claim authorization, execution, or coverage.
- No model endpoint or hosted provider was contacted while developing the experimental AI paths.

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
| ZAP | A thin adapter normalizes the pinned upstream JSON report, preserving alert identity, upstream severity, remediation, and per-instance evidence. The product builds the bounded passive automation plan the pinned command reads, confining the crawl to one approved origin and routing every request through the managed-network gateway; a run against a site linking off-site requested only the approved origin. The pinned upstream image was verified by digest and observed completing a passive crawl under a read-only root filesystem, a dropped-capability non-root user, and a hard memory limit. | No scope-grant profile exists for a ZAP passive website scan, so no run could be authorized against a website; the generated automation plan is not yet delivered into a run; and ZAP enforces no requests-per-second limit of its own, which the managed gateway cannot substitute for because it bounds connections rather than requests: measured against a keep-alive site, one ZAP run held the connection bound while sending 114 requests per second. |

## Grype repository scan

The current catalog pins Grype to `0.117.0-4`. A controlled Linux repository scan recorded 81 Grype
findings (10 critical, 32 high, 33 medium, 6 low), with Grype completed and exit code 0. The full run
recorded 192 findings, 8 completed checks, and 2 not executed: Agentic Radar had no runnable release,
and MCP Armor had no selected MCP configuration. These are results for that fixture, not promised
counts for other repositories. See [the exact pin and recorded result](engine-catalog.md#grype-repository-support).

## Recorded verification baseline

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

After removing credential-shaped text from an upstream test fixture, the MCP Armor image was rebuilt,
published, and pinned. Its offline synthetic smoke test produced one finding, two completed checks, no
warning, and `complete: true` under `network=none`.

## Current blockers

- Garak, Agentic Radar, and ZAP remain non-runnable while their catalog blockers exist.

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
