# Agentic Radar

Catalogued but not runnable. Agentic Radar would statically inventory the agents, tools and MCP servers in one repository snapshot (`repository` asset, input profile `repository_working_tree`, permission `local_artifact_read`) and the workflow relationships between them. Its output is inventory only, never findings. The adapter, a research patch and research fixtures exist; no image has been built and the engine has never run in this product.

| Item | Value |
| --- | --- |
| Upstream | [splx-ai/agentic-radar](https://github.com/splx-ai/agentic-radar) 0.14.1 (catalog `source_ref` `v0.14.1`), revision `65a7e4bd01e2034c7cb52e9620eeed287688cc53`, Apache-2.0 |
| Image | None. Catalog `image` is null; the plan's `final_artifact` (`ghcr.io/teddashh/ai-security-scanner-engine-agentic-radar`) keeps a null tag and digest (`publish_state` `managed_artifact_not_published`). |
| Build inputs | None. `engines/images/agentic-radar/plan.json` is the only file: `build_recipe` null, `dockerfile.emitted` false with a reason. |
| Launcher | None (`wrapper.entrypoint` null). Recorded strategy: accept one immutable repository snapshot and one typed supported-framework selection, keep execution offline, emit the reviewed JSON envelope, and pass only that artifact to the adapter. |
| Wrapper | Research patch `docs/research/patches/agentic-radar-0.14.1-machine-json.patch` (SHA-256 `d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72`), applied nowhere in the product |
| Adapter | `extract_agentic_radar_inventory` and `agentic_radar_reject_vulnerability_claims` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | None |

## Local build and update entry

There is no Dockerfile or published runnable product image. The existing plan and research describe a proposed integration; there is no completed build recipe to repeat yet.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Release gate.** Catalog `status` `experimental`, `compatibility.runnable` false, and three blockers repeated in the plan:
  - "no packaged image: the pinned source and local machine-output patch have never been built or tested as a product image, or published"
  - "no typed framework-selection path exists to freeze one of the five supported analyzers and verify that the reported framework matches the reviewed request"
  - "the machine-output contract requires a local patch that is not part of an accepted upstream release"
- **Enforcement.** `validate_release_contract` (`src-tauri/src/registry.rs`) requires the blockers and forbids default enablement. `EngineManifest::release_blocker` (`src-tauri/src/domain.rs`) keeps the engine out of the default plan, makes an explicit request record `engine_release_unavailable`, and stops the container runtime and orchestrator from running it. The frontend never routes it (`localInputEngineIds` in `src/localInputProfiles.ts`).
- **Network and resources.** Catalog: networking disabled; 1024 MB memory, 2048 MB disk, 1000 CPU millis, 128 pids, 1800 s.
- **Invocation.** Planned command `--engine agentic-radar --workspace /workspace --output /output`. "Required execution boundary before dispatch" in `docs/research/agentic-radar-evaluation.md` allows only the static `scan ... --export-graph-json` path: never `test` or `--harden-prompts`, no credential variables, no network, and a working directory outside the snapshot, because the CLI loads `.env` at import.
- **Output.** `/output/agentic-radar.json`, the patched envelope: `schema_version` `1`, `scanner_version`, `framework`, `status` (`workflow_found` or `no_supported_workflow`), `complete`, `warnings` (`code` `analyzer_diagnostic` plus `message`) and `graph` with `nodes`, `edges`, `agents` and `tools`.
- **Mapping.** Inventory observations only; nothing becomes a finding.
  - The document is read only with schema `1`, scanner `0.14.1`, one of the five framework identifiers accepted by `extract_agentic_radar_inventory`, a known status and all four graph arrays; otherwise nothing is normalized.
  - Nodes and tools of type `agent`, `basic`, `tool`, `custom_tool`, `mcp_server` or `default` become `WorkflowComponent` observations deduplicated by type and name, because upstream repeats tool records and its array order is not stable. An `agents` entry replaces the same-named `agent` component and adds a bounded `llm` model identifier and `is_guardrail`. Edges become `WorkflowRelationship` (`start`, `end`, bounded `condition`), deduplicated by content.
  - No other record field is read. Descriptions and prompts, which in the research fixtures carry system prompts, commands, URLs and headers, are never copied.
  - Every node, tool and agent must carry an empty `vulnerabilities` array; a non-empty one is ignored and a missing one reported, both with a warning (`agentic_radar_reject_vulnerability_claims`). Upstream's generic category warnings carry no stable rule id, severity or per-result evidence (catalog notice).
- **Failed, partial, not tested.** Any warning makes the run partial and keeps the partial graph: `complete` disagreeing with `warnings`, each upstream `analyzer_diagnostic` (shown as "Agentic Radar reported incomplete workflow inventory: <message>"), `workflow_found` disagreeing with a node count above two, a malformed record, or a vulnerability claim. A `no_supported_workflow` envelope with no nodes and no warnings is complete with no observations.

## Downstream changes

- **Machine-output patch** (`d32c61e4…`, generated from local research commit `1a3e4d81e3b122a69a529f1553a0b7239b64750d` on top of the pin; three upstream files and one nine-test file). It wraps the existing graph in the envelope above; makes the empty-workflow case exit 0 on the JSON path only (unpatched 0.14.1 exits 1 when it sees two nodes or fewer, and HTML keeps that); records analyzer diagnostics as warnings with `complete` false, stripping CPython object addresses; and turns off one analyzer's hosted vulnerability assessment for JSON export. Before and after file hashes are in the evaluation's "Local patch evaluation" section.
- Not submitted upstream: the issue and pull request drafts in `docs/research/agentic-radar-upstream-drafts.md` wait for owner authorization. The recorded replacement condition is "an upstream release with an equivalent documented and tested machine-output contract"; no review date is recorded as [section 6](../engine-maintenance.md#6-downstream-patch-exception) asks.

## Lessons from real runs

- 2026-09-25: every local-project scan planned Agentic Radar and listed it as not tested, so a run whose other checks all completed read "Partly completed", and a repeat scan from Progress planned 10 checks where the first had planned 8 -> settled skips counted as unfinished work, and the backend default selection kept release-blocked engines -> settled skips (the not-included reason now reads "This version of the app does not include this check.") no longer make a run partial (efb1314), and the default plan leaves release-blocked engines out (fbcbdd0). An explicit request still records `engine_release_unavailable`.

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Fresh audit, not a rebase.** The evaluation says a new upstream revision "requires a fresh audit rather than rebasing these hashes by assumption". First check whether upstream now ships an equivalent machine-output contract; if it does, drop the patch. A changed patch needs a new `AGENTIC_RADAR_RESEARCH_PATCH_SHA256` in `tests/ci/product-document-contract.test.mjs` (which also requires the hash in the evaluation), and new hashes in the evaluation, the fixture README and the drafts.
- **Before packaging.** Clearing the blockers is owner-authorized product work: an image whose launcher enforces the execution boundary above, a typed framework-selection path that freezes one framework and checks it against the envelope's `framework`, and an accepted upstream contract or a complete section 6 record. Emitting a Dockerfile while the plan stays `managed_artifact_not_published` sends it through `validateUnpublishedManagedBuild` in `scripts/validate-engine-catalog.mjs`, which hard-codes MCP Armor's entrypoint, so the validator needs an Agentic Radar branch.
- **Source.** The validator fails with "managed build source is not pinned by engines/upstreams.lock.json" unless the `splx-ai/agentic-radar` entry in `engines/upstreams.lock.json` equals the catalog `source_revision`. The revision is also in the plan, catalog `provenance`, `THIRD_PARTY.md`, `docs/engine-catalog.md`, the evaluation, the fixture README, the drafts and the registry assertions in `src-tauri/tests/adapter_fixtures.rs`. `0.14.1` is hard-coded in `extract_agentic_radar_inventory`, the contract test and the patch file name. `engines/upstream-refresh-policy.json` marks the engine `experimental`, so an `npm run upstream:refresh` proposal is never PR-eligible.
- **Output shape.** Re-check the envelope fields, the two statuses, the framework identifiers, the node types and every graph field the adapter reads (`node_type`, `name`, `llm`, `is_guardrail`, `start`, `end`, `condition`, `vulnerabilities`). A new node type is dropped with a warning; a new framework identifier drops the whole document.
- **Tests.** `docs/research/fixtures/agentic-radar/` holds six fixtures, one per framework plus the empty state, generated on 2026-09-13 by the patched pin from upstream examples with loopback-only networking (provenance in its `README.md`). `AGENTIC_RADAR_RESEARCH_FIXTURES` pins each file's hash, framework, status and completeness. The adapter tests from `agentic_radar_normalizes_only_the_static_workflow_graph` to `agentic_radar_never_promotes_generic_vulnerability_claims_to_findings` in `src-tauri/tests/adapter_fixtures.rs` include those files directly, so regenerate them with the new revision rather than editing them. A changed warning sentence needs its Chinese form in `src/engineWarningPresentation.ts` (`tests/frontend/warningPresentation.test.ts`).
- **Hard-coded tag.** None yet; the plan keeps a null tag and digest. `support_until` is 2026-12-12.
- **Compare with raw output.** In a patched `agentic-radar.json`, each distinct (`node_type`, `name`) in `graph.nodes` and `graph.tools`, each agent, and each distinct (`start`, `end`, `condition`) edge should appear once in the inventory. `complete` false or any `warnings` entry should show as incomplete coverage, and nothing from a `vulnerabilities` array should appear in the report.
