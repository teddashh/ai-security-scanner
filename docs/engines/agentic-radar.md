# Agentic Radar

The managed integration is published and optionally dispatchable in v0.4.0. It statically inventories agents, tools, MCP servers and workflow relationships in one immutable repository snapshot. Inventory supplements the security checks and never produces findings or a successful security-scan claim.

| Item | Value |
| --- | --- |
| Upstream | [splx-ai/agentic-radar](https://github.com/splx-ai/agentic-radar/tree/65a7e4bd01e2034c7cb52e9620eeed287688cc53) 0.14.1, revision `65a7e4bd01e2034c7cb52e9620eeed287688cc53`, Apache-2.0 |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-agentic-radar:0.14.1-1@sha256:2a8d16b9ff5ac7974b0aea8e6504219e0da295b804d01f51da0b4267d7cdafae`; verified anonymous amd64/arm64 image bytes, signed provenance and four SBOMs. |
| Recipe | [Dockerfile](../../engines/images/agentic-radar/Dockerfile), repository-root context; no host preparation. Plan binds the archive, patch, launcher, bases and both dependency locks. |
| Launcher | Dedicated [Go launcher](../../engines/images/agentic-radar/launcher/main.go), `/usr/local/bin/ai-security-scanner-agentic-radar-entrypoint`; does not change the published MCP Armor launcher. |
| Exception | [Machine-output patch](../research/patches/agentic-radar-0.14.1-machine-json.patch), SHA-256 `d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72`; complete owned audit in [PATCHES.md](../../engines/images/agentic-radar/PATCHES.md). No contribution has been submitted. |
| Adapter | Existing `extract_agentic_radar_inventory` and `agentic_radar_reject_vulnerability_claims`; normalized schema remains adapter 0.2.5. |
| Publication | [Dedicated workflow](../../.github/workflows/engine-image-agentic-radar.yml), immutable candidate, amd64/arm64 manifests, native amd64 smoke, provenance and per-platform SBOM. |

## Local build and update entry

Use the repository-root build command in the [image build index](image-build-index.md). The source archive SHA-256 is `433fe72ee2d31135730b781ef812d50c2abeaeb1ec217e90d2f6acf0d455f713`; archive epoch is `1764257310`. Build source is the pinned revision, rather than a research checkout or mutable release tag.

The Go toolchain and Dockerfile frontend are pinned by digest. Python is `3.11.16-slim`, index `sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7`. `requirements.lock` admits 30 hash-verified binary wheel packages for Linux amd64/arm64. `build-requirements.lock` admits six wheel-build/test packages in a separate prefix; they are excluded from the runtime. The native wheel is built without dependency resolution or build isolation, after nine patch tests pass. Do not add an optional agent framework, Torch or Transformers to conceal static-parser omissions. Native parser imports, including OpenAI, remain pinned runtime dependencies; no hosted assessment is called in the admitted path.

The image retains upstream and product licenses, the patch, audit, locks and Dockerfile. Its final user is `65532:65532`. Run it with a read-only root filesystem, no network, dropped capabilities, bounded tmpfs and a read-only workspace. The launcher enforces the workspace mount, one valid local-artifact grant, one snapshot digest, a fresh private output and exact paths. No shell command or caller-provided native flags are accepted.

## How it is wired

- **Publication boundary.** The admitted catalog is integrated and runnable, with no blockers and default enablement off. Its immutable image is independently verified against the exact publication source and signed evidence; later candidates retain the unavailable-image boundary until verified.
- **Typed selection.** The optional repository selector accepts only `langgraph`, `crewai`, `n8n`, `openai-agents` or `autogen`; no automatic framework guessing. The backend verifies the connected immutable snapshot before saving the selection. Its typed metadata and exact `ai-security-scanner:agentic-radar-framework` identifier must agree. With no selection, the default plan omits inventory. The launcher independently compares the native envelope's framework with the frozen request. The same selection is available in project and mixed-environment routes.
- **Network and resources.** Catalog: networking disabled; 1024 MB memory, 2048 MB disk, 1000 CPU millis, 128 pids, 1800 s.
- **Invocation.** Fixed launcher command `--engine agentic-radar --workspace /workspace --output /output`. "Required execution boundary before dispatch" in `docs/research/agentic-radar-evaluation.md` allows only the static `scan ... --export-graph-json` path: never `test` or `--harden-prompts`, no credential variables, no network, and a working directory outside the snapshot, with `PYTHON_DOTENV_DISABLED=1`, because the upstream CLI loads `.env` at import. The isolated Python process receives a fresh fixed environment, not inherited credentials. Its native export deadline is ten minutes within the catalog’s thirty-minute outer limit.
- **Output.** `/output/agentic-radar.json`, the patched envelope: `schema_version` `1`, `scanner_version`, `framework`, `status` (`workflow_found` or `no_supported_workflow`), `complete`, `warnings` (`code` `analyzer_diagnostic` plus `message`) and `graph` with `nodes`, `edges`, `agents` and `tools`.
- **Mapping.** Inventory observations only; nothing becomes a finding.
  - The document is read only with schema `1`, scanner `0.14.1`, one of the five framework identifiers accepted by `extract_agentic_radar_inventory`, a known status and all four graph arrays; otherwise nothing is normalized.
  - Nodes and tools of type `agent`, `basic`, `tool`, `custom_tool`, `mcp_server` or `default` become `WorkflowComponent` observations deduplicated by type and name, because upstream repeats tool records and its array order is not stable. An `agents` entry replaces the same-named `agent` component and adds a bounded `llm` model identifier and `is_guardrail`. Edges become `WorkflowRelationship` (`start`, `end`, bounded `condition`), deduplicated by content.
  - No other record field is read. Descriptions and prompts, which in the research fixtures carry system prompts, commands, URLs and headers, are never copied.
  - Every node, tool and agent must carry an empty `vulnerabilities` array; a non-empty one is ignored and a missing one reported, both with a warning (`agentic_radar_reject_vulnerability_claims`). Upstream's generic category warnings carry no stable rule id, severity or per-result evidence (catalog notice).
- **Failed, partial, not tested.** Any warning makes the run partial and keeps the partial graph: `complete` disagreeing with `warnings`, each upstream `analyzer_diagnostic` (shown as "Agentic Radar reported incomplete workflow inventory: <message>"), `workflow_found` disagreeing with a node count above two, a malformed record, or a vulnerability claim. A `no_supported_workflow` envelope with no nodes and no warnings is complete with no observations.

## Downstream changes

The retained patch wraps the native parser graph in schema 1, names the scanner and framework, records diagnostics and an explicit empty state, and disables hosted assessment only for static JSON export. It changes three upstream files and adds a nine-test file; native parsing and the default HTML path retain their behavior. The sequential pre/post hashes, owners, contribution rationale and removal condition are in `plan.json` and [PATCHES.md](../../engines/images/agentic-radar/PATCHES.md). Reviewed 2026-10-04; next review 2026-11-01. Local issue/PR drafts remain unsent. Remove the patch when a documented upstream static contract provides equivalent version, framework, empty-state and completeness semantics without hosted calls.

## Native validation — 2026-10-04

The fresh local amd64 image `aiss-agentic-radar-local:0.14.1-1` is `sha256:6388c14f2ba1084ae0425551e899e8ced456138174ba34749a8fbbe8a1f4aeb9`. Seven controlled runs used the same image with uid 65532, read-only rootfs, network disabled, no capabilities, 128 pids, 1 GiB memory and one CPU. Input files came from the pinned upstream examples and were read as data; no target program or MCP service was executed.

| Native input | Nodes / edges / agents / tools | Outcome |
| --- | --- | --- |
| LangGraph MCP example | 3 / 0 / 0 / 1 | Complete inventory |
| CrewAI example | 4 / 3 / 0 / 0 | Incomplete inventory; five native diagnostics retained |
| n8n example | 20 / 13 / 0 / 9 | Complete inventory |
| OpenAI Agents example | 4 / 3 / 1 / 0 | Complete inventory |
| AutoGen example | 4 / 3 / 1 / 0 | Complete inventory |
| Empty LangGraph directory | 0 / 0 / 0 / 0 | Explicit `no_supported_workflow`; no security result |
| LangGraph plus controlled `.env` and execution canary | 3 / 0 / 0 / 1 | Same graph; `.env` ignored, target code not executed |

All graph vulnerability arrays were empty. LangGraph and the isolation case retained raw SHA-256 `a7d8f53d6aaa83b75810e3209801dc13411d84013e5608f8959f6678eff7f51b`; CrewAI retained `24d77e25a8a01b8e3f7172986494b24c98a0548d658dce2fb77df2f46a63f0ea`. Launcher scope, selector, output, symlink and writable-input refusal tests passed. This is native amd64 execution evidence; it does not claim arm64 runtime validation or publication.

## Lessons from real runs

- **2026-10-04, shared terminal report.** The all-engine report audit must explicitly select the native framework before planning this optional inventory engine. Its graph belongs in inventory, with no security finding or security-completion claim. Adding n8n to the full save/reopen/export path exposed missing Traditional Chinese translations for workflow and model redaction markers; the shared HTML report now names those withheld values in the selected language.

- 2026-09-25: every local-project scan planned the then-unavailable engine. Settled skips counted as unfinished work, making otherwise complete scans look partial. Default plans now omit unavailable engines; explicit requests still record `engine_release_unavailable`. Keep optional inventory outside security-success accounting.
- 2026-10-04: the upstream CLI loads dotenv at import. An external working directory alone is insufficient protection against dotenv search or inherited settings; isolated Python, a fixed environment and `PYTHON_DOTENV_DISABLED=1` are required and exercised with a controlled override/canary. CrewAI's native diagnostics remain incomplete inventory; installing or executing a target framework is not an appropriate fix.

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

1. Audit the new upstream revision and CLI before rebasing the patch. Look for a documented native static envelope and offline mode; remove the exception when equivalent. Recompute source archive SHA, epoch, patch hash and sequential file hashes. Record the reason, owners, removal condition and next review date; do not invent an upstream acceptance or issue.
2. Move source pins in catalog, upstream lock, plan and source notices together. The adapter accepts scanner `0.14.1`; the launcher enforces the same version. A changed normalized contract requires the adapter procedure. Current update policy still treats this integration as experimental and cannot automatically release a proposal.
3. Regenerate both hash-required binary-wheel locks from primary package metadata for Python 3.11 and both Linux architectures. Check native import closure and upstream version constraints; keep build/test dependencies out of the runtime. Change Dockerfile, plan input hashes and validator contract together. Never float a dependency or bypass an unavailable wheel.
4. Re-run nine patched upstream tests, Go launcher boundary tests, all five static frameworks, the empty directory and dotenv/code-execution isolation. Preserve CrewAI diagnostics. Compare raw graph IDs/types/relationships with typed observations; generic vulnerability claims, prompts, descriptions, URLs, headers and commands must not become findings or exposed inventory text. Existing six research fixtures remain pinned historical data; regenerate, rather than hand-edit, if upstream semantics change.
5. Use a fresh immutable image tag whenever bytes change; update the dedicated workflow, catalog-validator contract, plan, notices and this page. Verify anonymous index and both platform pulls, exact publication source/workflow, SBOM and signed evidence before admitting the digest. Never rewrite historical scan provenance or old image bytes. Current support date is 2026-12-12.


## Publication verification — 2026-10-04

[Workflow 37177664415](https://github.com/teddashh/ai-security-scanner/actions/runs/37177664415) published `0.14.1-1` from product source `b11307cf182a888b5e2e1b1d9c0434be4a9778c0`. Index: `sha256:2a8d16b9ff5ac7974b0aea8e6504219e0da295b804d01f51da0b4267d7cdafae`. amd64: `sha256:a2b615c2ec3450ffe687cf87be7f83cd97c231e40bc1732d62a2d5b4710d50e3`. arm64: `sha256:df33eca07e4b00d7ffa3309dd80a587ae0f79029d93c08578a7cfe7087ae3f10`.

The downloaded `agentic-radar-image-evidence-37177664415-1` passed the fixed publication verifier: 14 root inventory entries, ten nested entries, five verified attestations, four SBOMs and managed smoke receipt `sha256:c0baf0707963294e13904c0b01b0499a8b509d821da1da76fbfdc3e995690b98`. Independent anonymous registry reads hashed every index, platform manifest, configuration and 23 distinct layer blobs; source/patch labels, architecture, entrypoint and non-root user matched. All seven controlled offline cases were repeated with the published image and retained the same graph counts, completeness and diagnostics. CrewAI raw SHA-256 for that run is `f78ad926bbfc7fbaa54e810ac0afa61f6bf1c880c4c900f797ca3f7835d68a17`; native transient graph identifiers may differ between executions. No native arm64 runtime result is claimed.
