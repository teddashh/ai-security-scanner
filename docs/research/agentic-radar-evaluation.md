# Agentic Radar integration decision

Normative status: this is a pinned research decision, subordinate to the
[canonical product specification](../product-spec.md). It records the admissible output and safety
boundary for one audited Agentic Radar revision. It does not admit an engine, authorize packaging
or publication, or make this inventory-only analysis a completed security check.

Decision: consume Agentic Radar's static workflow graph as typed inventory observations. Do not turn
its tool-category warnings or agent-mitigation assessments into findings. The pinned revision
already has a JSON graph exporter, so the product does not need a second graph builder. The retained
narrow orchestration patch only supplies a versioned, fail-closed machine envelope around that same
parser-produced graph. At the original research checkpoint the product record remained experimental and fixture-bound. Owner-authorized integration on 2026-10-04 added a locally tested managed image and typed framework selection; catalog admission still waits for independently verified publication. See the current [engine notebook](../engines/agentic-radar.md).

This static review is pinned to
[`splx-ai/agentic-radar@65a7e4bd01e2034c7cb52e9620eeed287688cc53`](https://github.com/splx-ai/agentic-radar/tree/65a7e4bd01e2034c7cb52e9620eeed287688cc53)
(version 0.14.1). Its checked-in license is Apache-2.0
([package metadata](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/pyproject.toml#L1-L18),
[license text](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/LICENSE#L1-L3)).
The upstream source remains `RESEARCH / NOT_DISTRIBUTED`: it is not an installer component,
container image, or transitive release dependency. The separate product catalog record is only
experimental, non-runnable integration metadata backed by retained fixtures.

The Step 2a source audit was rechecked on 2026-09-13 from the existing ignored shallow checkout at
`.upstreams/splx-ai/agentic-radar`. Its retained research commit has the pinned upstream revision as
its exact parent. Every upstream claim and permalink in the audited path below refers to those
parent bytes, not to the later local patch. No upstream code was executed and no target was
contacted during this recheck.

## Audited machine-readable path

The earlier assumption that this revision can emit only HTML is incorrect. Agentic Radar added
graph JSON in version 0.12.0
([changelog](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/CHANGELOG.md#L37-L43)).
At the pinned revision:

- `scan` accepts LangGraph, CrewAI, n8n, OpenAI Agents, and AutoGen as explicit framework values
  ([CLI enum](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L42-L47),
  [analyzer selection](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L107-L133)).
- `--export-graph-json` is an upstream CLI option. After analysis, the CLI sanitizes the graph,
  writes `graph.model_dump_json(indent=2)`, and exits before applying the generic vulnerability
  mapper
  ([option](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L79-L105),
  [control flow](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L136-L163)).
- The exported in-memory model contains `name`, `nodes`, `edges`, `agents`, and `tools`. Nodes carry
  a node type, name, optional description and label, optional tool category, and a vulnerability
  list; edges carry start, end, and an optional condition; agent metadata carries name, model,
  system prompt, guardrail status, and optional mitigation assessments
  ([model](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/graph.py#L7-L74)).
  There is no schema version, scanner version, or framework field in this JSON. The future launcher
  must preserve the selected framework as trusted invocation metadata rather than infer it from
  target-controlled output.
- The framework analyzers all converge on that model: LangGraph collects graph nodes, inferred
  agents, tools, and MCP servers
  ([LangGraph](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/langgraph/analyze.py#L27-L133));
  CrewAI collects agents, tasks, tools, MCP servers, and inferred connections
  ([CrewAI](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/crewai/analyze.py#L22-L72));
  n8n reads workflow JSON and converts nodes and connections
  ([n8n](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/n8n/analyze.py#L16-L52));
  OpenAI Agents collects agents, tools, guardrails, and MCP servers
  ([OpenAI Agents](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/openai_agents/analyze.py#L23-L41));
  and AutoGen collects models, function tools, MCP adapters, agents, and teams
  ([AutoGen](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/autogen/agentchat/analyze.py#L27-L56)).
- The HTML path constructs a separate `ReportData` object containing project and framework names,
  timestamp, a rendered graph string, aggregate counts, agents, tools, MCP servers, hardened prompts,
  scanner version, and a local JavaScript dependency path. It passes that object plus the generic
  vulnerability definitions into Jinja
  ([report assembly](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/report/report.py#L19-L104)).
  That presentation object is not the adapter input: parsing it would couple the product to HTML and
  would reintroduce the generic warnings deliberately excluded by the upstream graph JSON path.

## Normalization decision

The fixture-bound adapter may derive only inventory observations from the exported graph:

- one component observation for each distinct agent, tool, custom tool, basic workflow node, or MCP
  server in the union of `nodes` and `tools`;
- one relationship observation for each edge, retaining its start, end, and condition; and
- optional component attributes that the graph states directly, such as tool category, model name,
  and guardrail status.

The duplicate `tools` collection must enrich or confirm a component, not create a second copy. The
adapter must not put system prompts, free-form descriptions, MCP parameters, vulnerability text, or
mitigation explanations into the typed observation. The exact JSON remains a sensitive raw artifact
with a bounded pointer for each derived observation; normal export redaction continues to govern
whether that artifact is shared.

This uses the existing [adapter contract](../../src-tauri/src/adapter.rs#L111-L133), which keeps
scanner-authored inventory separate because inventory alone is not evidence of a vulnerability.
Agentic Radar observations therefore cannot create a finding, a priority item, a “no problems”
asset state, or first meaningful value by themselves. They may supplement the independent source
security checks already selected for an AI application.

## Why the reported vulnerabilities are not findings

The checked-in vulnerability map has 11 entries: four match a tool category and seven match a tool
name. Every entry is a tool rule. Its vulnerability objects contain only `name`, `description`,
`security_framework_mapping`, and `remediation`; they have no stable rule identifier, severity, or
per-occurrence source evidence
([mapping data](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/mapper/vulnerabilities.json#L1)).
The mapper attaches those warnings whenever a node or tool has the matching name or category
([matching logic](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/mapper/mapper.py#L25-L54)).
That is useful design guidance, but the presence of an LLM, web-search tool, code interpreter,
document loader, or named retriever is not evidence that an exploitable weakness exists.

The JSON path already exits before that mapper runs, so these tool warnings should not appear in a
captured graph. The adapter must still ignore a future graph that places them in a `vulnerabilities`
array rather than silently promoting them to findings.

OpenAI Agents has a separate concern: its analyzer calls an LLM-based mitigation assessment before
returning the graph
([call site](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/openai_agents/analyze.py#L23-L41)).
That path constructs an OpenAI client and can send guardrail code and system prompts to a hosted
model when credentials are available
([hosted analysis](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/openai_agents/parsing/vulnerabilities.py#L142-L210)).
Its generated mitigation levels and explanations are also excluded from findings and typed
observations.

## Required execution boundary before dispatch

Only the static `scan ... --export-graph-json` path is in scope. The future launcher must:

- never invoke `test` or `--harden-prompts`; both are active or hosted-AI paths, not source inventory
  ([commands](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L197-L254),
  [hardening path](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L164-L175));
- run without credential variables, outside the selected snapshot as its working directory, and
  without network access. This matters because the CLI loads `.env` at import time
  ([initialization](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L37-L39));
- accept only the explicitly selected framework and bounded read-only snapshot; and
- treat malformed, missing, or structurally inconsistent JSON as incomplete coverage, never as a
  clean result.

The pinned CLI exits with code 1 when it sees no more than two graph nodes instead of emitting an
explicit machine-readable empty result
([no-workflow branch](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L144-L159)).
That cannot be translated into a successful clean scan. Any runnable integration must retain the
product's non-zero-exit boundary and show this case as incomplete until the upstream output contract
can distinguish “no supported workflow found” from execution failure.

## Intended upstream issue and pull request

The issue should ask upstream to document and version the existing JSON contract rather than add a
second graph builder. It should record four machine-consumer gaps: the output omits framework and
scanner version, the no-workflow case has no JSON state, analyzer diagnostics are not represented as
structured completeness data, and OpenAI Agents may perform hosted analysis before static JSON
export. The existing CLI tests exercise HTML output for the five frameworks but do not cover
`--export-graph-json`
([tests](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/tests/cli_test.py#L30-L100)).

A narrow pull request should stay in output and orchestration code: add a versioned JSON envelope
with framework and scanner version, emit an explicit empty-workflow state with a successful process
exit, capture analyzer diagnostics as structured warnings with fail-closed completeness, ensure JSON
export does not initialize hosted-model analysis, and add fixture-backed CLI tests for all five
framework values. It must serialize the same parser-produced graph and must not change parsers,
vulnerability matching, severity, evidence, or remediation logic. Until that contract is available
and pinned, any product record based on the local equivalent must remain experimental,
non-runnable, fixture-bound, and without a packaged artifact.

## Local patch evaluation

On 2026-09-13, that minimal patch was evaluated against the pinned source in the ignored research
checkout. The exact [`agentic-radar-0.14.1-machine-json.patch`](patches/agentic-radar-0.14.1-machine-json.patch)
has SHA-256 `d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72`.
It was generated from local research commit
`1a3e4d81e3b122a69a529f1553a0b7239b64750d`, whose parent is the audited upstream commit.

The patch changes only these behaviors:

- wraps the existing parser-produced graph in schema version `1`, scanner version, selected
  framework, `workflow_found` or `no_supported_workflow` status, a `complete` boolean, and
  structured warnings;
- emits the empty-workflow state with process exit 0 only for the JSON path, while preserving the
  existing HTML exit-1 behavior;
- captures non-empty analyzer diagnostic lines only for the JSON path, sets `complete` to false
  whenever any are present, and removes volatile CPython object addresses without changing the
  remaining diagnostic text; and
- makes OpenAI Agents vulnerability assessment optional, retaining its existing default for HTML
  while disabling it for static JSON export.

The reviewed source-file hashes are:

| File | Upstream SHA-256 | Patched SHA-256 |
| --- | --- | --- |
| `agentic_radar/analysis/openai_agents/analyze.py` | `9d608a2c18ee308fb3e3322d0a01541310eb63f5027de7eed6d68a9a8aa70cdc` | `8e6b284e2ff65ace79887f2e69c0c3ac318dff6679b7dae369f88338ac7c914c` |
| `agentic_radar/cli.py` | `a9ff61e626b21ba58ea677b15834d0986609c4ba8d5a6ebff593b689c8ada0a2` | `e982af1348d006811bfd8efa1f0d2b521bc7cd0914e1df4f587a53ed2a7c7914` |
| `agentic_radar/graph.py` | `760e6badf7b0d61af20a62a4bf0eb3bac67d04d9d39f1cefdb8aa2ffc5030b0d` | `2928ce0926aa819a589995ada093199fffe1da960f6d4a295d24051eb49f7fa7` |

The added focused test file has SHA-256
`980292e25b4b4b66f85fa04dc90964b296c688551446fec96637edbbedfdfdb4`. Its nine tests cover all
five framework selectors, the exact versioned envelope, bypass of generic vulnerability mapping,
the explicit empty state, diagnostic capture and fail-closed completeness, preservation of the HTML
failure behavior, and the OpenAI Agents no-hosted-assessment branch. Ruff and focused formatting
checks passed, mypy reported no issues in 90 source files, and all nine focused tests passed. The
tests used in-memory graphs and temporary output directories; they did not execute Agentic Radar
against a project or contact a target.

This patch is retained as research evidence only. It has not been merged upstream, packaged,
published, or applied to a runnable product image. The product catalog records an experimental,
non-runnable integration whose adapter is fixture-bound to this contract; that record does not
promote the patch to product code or authorize execution. Its replacement condition is an upstream
release with an equivalent documented and tested machine-output contract. A new upstream revision
requires a fresh audit rather than rebasing these hashes by assumption.

The prepared [upstream issue and pull request drafts](agentic-radar-upstream-drafts.md) remain local
and may be submitted only after their recorded preflight and explicit authorization.

## Controlled fixture result

The patched static JSON path was then exercised against one checked-in benign example for each of
the five supported frameworks, plus an empty temporary directory. All six invocations ran without
credential variables inside a network namespace that exposed only loopback. The complete raw
outputs, hashes, input paths, and field-level review are retained in the
[Agentic Radar research fixture manifest](fixtures/agentic-radar/README.md).

The repeated controlled run confirmed the fail-closed envelope: CrewAI still emits
`workflow_found`, but its five analyzer diagnostics are now structured warnings and force
`complete: false` while the partial graph remains available. The other four framework examples and
the empty-workflow case emitted `complete: true` with empty warning arrays. `workflow_found` remains
only a structural upstream status; a future adapter must use `complete` independently and preserve
warnings as coverage diagnostics.

The CrewAI graph's node and edge array order varied between two isolated invocations because its
in-memory graph uses sets. This does not change completeness or graph membership, but it confirms
that a future adapter must identify and deduplicate observations by stable content rather than array
position.

## Step 2b / Step 2c convergence audit

The 2026-09-13 read-only audit found one converged evidence chain; no duplicate implementation is
needed:

- The pinned revision is identical in this decision, the fixture manifest, upstream drafts, engine
  catalog, unpublished build-plan record, and upstream lock. Local research commit
  `1a3e4d81e3b122a69a529f1553a0b7239b64750d` has that revision as its exact parent. The retained
  patch digest is identical in this decision, the fixture manifest, upstream drafts, and CI
  contract.
- The catalog record is `experimental`, not default-enabled, and `runnable: false`; it has no image,
  network destinations, or wrapper entrypoint. Its unpublished plan has no artifact tag, digest,
  Dockerfile, or entrypoint. The catalog and plan retain the same three blockers.
- Adapter version `0.1.4` agrees with the catalog and adapter provenance. The adapter admits only
  schema `1`, scanner `0.14.1`, the five reviewed framework identifiers, and the two reviewed
  structural statuses. It emits only typed workflow-component and workflow-relationship
  observations, deduplicates by bounded content, excludes sensitive free text, and never emits a
  finding. Structured warnings preserve the partial graph while clearing completeness; injected
  vulnerability claims are ignored and also clear completeness.
- The six retained fixtures cover all five frameworks plus the explicit empty state. Their hashes,
  structure, and completeness relation remain pinned: CrewAI retains five diagnostics and is
  incomplete; the other five documents carry no warnings. Inventory completion is not a security
  result and cannot create a no-problems claim.
- The issue and pull-request drafts use the same pin and patch digest, retain the unresolved
  `#ISSUE` placeholder, and require an explicitly authorized live duplicate search, maintainer
  acceptance, rebase, and fresh upstream checks before submission. The local patch commit is not in
  any locally known remote-tracking ref. This audit made no network request and makes no claim about
  the live issue tracker.

Step 2b and Step 2c are therefore already present and internally consistent. Do not add a second
catalog entry, adapter, patch, fixture family, or draft. Those three blockers describe the historical research checkpoint. The owner subsequently authorized v0.4.0 integration. As of 2026-10-04, the offline image, typed selection and complete owned downstream-exception record are implemented and native-tested; dispatch remains blocked until public image evidence is verified. Upstream acceptance is not claimed and drafts remain unsent.
