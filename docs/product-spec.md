# ai-security-scanner product specification

Status: implementation specification

Audience: product, desktop, runtime, adapter, security, and release maintainers

Last updated: 2026-08-24

This document defines the intended complete product. It is not a statement that any feature is already implemented, tested, secure, or released. A requirement remains planned until the repository contains implementation and verification evidence for it.

## 1. Product definition

`ai-security-scanner` is a local-first desktop security assessment case system for people who do not know which security tools to run or how to interpret their output.

The user creates an assessment case rather than launching an isolated scan. A case records:

- what environments and data sources were considered;
- which assets were discovered;
- what the user authorized the product to inspect;
- which engines ran, partially ran, failed, or were not run;
- every finding and its original evidence;
- which areas remain unknown or unexamined;
- what changed when the same case is run again.

The product integrates existing open-source engines. Its product value is the shared case lifecycle, asset and evidence model, coverage ledger, plain-language explanation, expert handoff package, and reliable re-verification—not a claim that its own scanner is more authoritative than the upstream engines.

## 2. Product promise

For every reported result, `ai-security-scanner` must be able to answer:

1. Which asset was examined?
2. What evidence was observed?
3. Which engine, rules, database, adapter, and versions produced it?
4. What part of the environment was not examined or could not be examined?
5. What type of professional should the user ask for help?
6. On a later run, did the same issue disappear, remain, newly appear, or become unverifiable?

The product promises traceable preliminary evidence. It does not promise that an organization is secure.

## 3. Target users

### 3.1 Primary user

An owner, operator, developer, or administrator who controls an environment but is not a security specialist. They may understand how to sign in as an administrator while not understanding IAM roles, scanner selection, CVE prioritization, or compliance frameworks.

### 3.2 Handoff recipient

An independent security professional, cloud specialist, identity specialist, application security specialist, or infrastructure operator chosen by the user. The product must not steer the user to a single vendor.

### 3.3 Maintainer

A contributor who adds or updates an engine adapter, engine manifest, control mapping, explanation, release bundle, or AI-assisted setup workflow.

## 4. Non-goals and prohibited claims

`ai-security-scanner` is not:

- an ISO 27001 audit;
- a NIST CSF certification or conformance decision;
- a guarantee that all assets were discovered;
- a guarantee that every finding is a confirmed vulnerability;
- a replacement for a qualified security professional;
- an automatic remediation system;
- a cloud service that silently uploads findings or credentials;
- a single numeric “security score.”

The user interface and exports must not label a finding or an environment as “ISO compliant,” “ISO non-compliant,” “NIST passed,” “NIST failed,” or “fully scanned.” NIST CSF and ISO 27001 references are navigation coordinates to potentially related controls only.

## 5. Product principles

1. **Local first.** Credentials, raw evidence, normalized findings, and case history remain on the user's device unless the user explicitly exports them.
2. **Unknown is not green.** Missing visibility, missing authorization, engine failure, and no findings are different states.
3. **Complete results, simple first view.** The first view prioritizes a small set of issues; it never deletes or hides the full result set.
4. **Many engines, selective execution.** The product may support many engines while a case runs only those applicable to its assets and authorized scope.
5. **Read to assess, never write to remediate.** Scanner credentials are short-lived and read-only. The product gives advice and references but does not change the target environment.
6. **Versioned evidence.** Every run records the exact engine, image digest, rule or vulnerability database, adapter, and mapping versions used.
7. **Recoverable execution.** A laptop sleep, API rate limit, network interruption, or individual engine crash does not erase all progress.
8. **AI assistance is optional defense in depth.** Repository skills may guide setup and cleanup, but programmatic authorization, isolation, and credential restrictions remain mandatory.

## 6. Complete case lifecycle

### 6.1 Create a case

The user creates a named case. The case questionnaire collects at least:

- organization size and operating context;
- whether the environment may contain personally identifiable information (PII) or protected health information (PHI);
- AWS, Azure, GCP, and Microsoft 365 usage;
- known domains, IP ranges, source repositories, container images, and Kubernetes clusters;
- whether the user wants configuration assessment, local artifact analysis, low-impact external checks, or active external vulnerability tests.

These answers select engines, influence plain-language impact and priority, and identify missing sources. They must not be converted into a compliance score.

### 6.2 Connect data sources

The preferred connection method is provider-native, short-lived, least-privilege, read-only authorization.

If a user can only begin with an administrative login, the product may offer the isolated bootstrap flow defined in [architecture.md](architecture.md) and [threat-model.md](threat-model.md). Administrative credentials may only be used to create and verify a dedicated scanning role. They must never be passed to a scanner, adapter, container, AI model, command line, log, crash report, clipboard integration, or persistent store.

### 6.3 Discover candidate assets

The product discovers candidate assets only from connected, attributable sources such as:

- cloud organizations, tenants, subscriptions, accounts, projects, and resource APIs;
- DNS, certificate transparency records, load balancers, and provider-owned public endpoints;
- IAM trust relationships;
- source repositories, Terraform state, and Kubernetes configuration supplied by the user;
- billing data explicitly supplied or connected by the user.

A candidate is not automatically an authorized target. The product must not claim to find an unrelated environment for which it has no source.

### 6.4 Confirm the scan contract

The user confirms ownership and allowed activity per asset or bounded asset group. Scope grants distinguish at least:

- inventory and configuration reads;
- local source, artifact, image, or cluster configuration analysis;
- passive public-data discovery;
- low-impact direct connectivity checks;
- active external vulnerability tests.

Active engines such as Nuclei and Greenbone must not run against an external target without an explicit, recorded grant covering the target and activity. This authorization control is a product requirement, not a project-management gate.

### 6.5 Dispatch and run engines

The orchestrator selects engines from the approved engine catalog based on the case's assets, data sources, and scope grants. Users do not need to choose between individual scanners unless they enter an advanced view.

Each engine runs independently and reports one of:

- `pending`;
- `running`;
- `completed`;
- `partial`;
- `failed`;
- `not_executed`;
- `cancelled`.

The application must expose useful progress, failure reasons, retryability, and the last durable checkpoint. A partial or failed engine cannot be represented as a successful green result.

### 6.6 Normalize and explain

Adapters preserve raw output and translate it into the canonical model described in [architecture.md](architecture.md). Normalization must retain:

- stable asset identity;
- original tool identity and version;
- original rule, check, template, advisory, or vulnerability identifier;
- evidence and evidence hash;
- source severity and normalized severity;
- confidence and verification state;
- scan time and scope;
- related findings without destructively deleting duplicates;
- potentially related NIST CSF and ISO 27001 controls;
- plain-language risk, likely impact, suggested next step, official references, and recommended expert type.

The home view may show the highest-priority items first. The complete list must remain available under categories such as `prioritize`, `needs_confirmation`, and `observe`.

### 6.7 Handoff

The user can export a portable case package. It must include:

- case identity and timestamps;
- scope grants and coverage ledger;
- assets and asset relationships;
- complete findings, not only prioritized findings;
- raw evidence or explicit references to intentionally excluded evidence;
- evidence hashes;
- engine, rule, database, adapter, mapping, and digest versions;
- run status and error information;
- plain-language report and expert-oriented machine-readable data;
- an explicit statement that the package is preliminary scanner evidence, not an audit or forensic conclusion.

A local signature may establish package integrity after export. It must not be described as proof that the scan was complete, correct, or performed by a legally identified entity.

### 6.8 Verify

The user can re-run an existing case using its previous scope as the starting point. The product compares stable asset and finding identities and reports:

- `resolved`: previously observed and no longer reproduced under comparable conditions;
- `persistent`: reproduced again, with an `evidence_changed` indicator when its evidence or severity materially changed;
- `new`: not present in the selected baseline;
- `unverifiable`: comparison is invalid because scope, authorization, engine availability, or required evidence changed.

The product must not label a finding resolved merely because the responsible engine did not run.

## 7. Coverage ledger

Coverage is a first-class product object, not a paragraph added to a report. At minimum, an environment or asset area can be:

- `discovered_authorized_scanned`;
- `discovered_not_authorized`;
- `authorized_scan_incomplete`;
- `source_connected_no_asset_discovered`;
- `source_not_connected_unknown`;
- `not_applicable`, with a recorded reason.

The last two states must never use the same icon, wording, color, or score. “No evidence of an asset from a connected source” is not equivalent to “the product had no source from which it could know.”

## 8. Main desktop views

The application has six primary views:

1. **Cases** — create, open, archive, and select a verification baseline.
2. **Assets and coverage** — questionnaire, connected sources, candidate assets, scope grants, and unknown areas.
3. **Scan progress** — overall run, per-engine progress, checkpoints, errors, retry, resume, and cancel.
4. **Findings** — prioritized summary, complete result list, evidence, explanations, related controls, and expert type.
5. **Case export** — package contents, redaction choices, sensitivity warning, integrity metadata, and export destination.
6. **Verification comparison** — resolved, persistent, new, and unverifiable results, including evidence changes on persistent findings.

Asset relationship graphs, raw engine logs, and detailed provenance belong in an advanced evidence view and the expert package, not the default newcomer dashboard.

## 9. Finding workflow

A user-visible finding may have one of these handling states:

- `unreviewed`;
- `expert_review_requested`;
- `confirmed`;
- `false_positive`;
- `remediation_reported`;
- `verified_resolved`.

Changing a workflow state does not alter the original evidence. A false-positive decision records who or what made the decision, when, why, and whether it expires.

The product must not provide an “execute remediation,” “copy and run,” or equivalent control. Suggestions may explain impact, preconditions, verification, rollback considerations, official documentation, and the professional role needed to make the change.

## 10. Engine coverage required for the complete product

The complete product supports the engine families listed as `Required` in [engine-catalog.md](engine-catalog.md):

- cloud inventory;
- cloud configuration and IAM;
- Microsoft 365 and Entra configuration;
- external attack surface and explicitly authorized active testing;
- source code and secret scanning;
- infrastructure-as-code analysis;
- container, package vulnerability, and SBOM analysis;
- Kubernetes configuration and benchmark analysis.

Support means the engine participates in the full case lifecycle: manifest, licensing decision, installation or retrieval, runtime isolation, progress reporting, normalized evidence, coverage accounting, export, and re-verification. Merely cloning a repository or exposing its raw report does not satisfy support.

## 11. Local data and privacy requirements

- No credential or finding telemetry is enabled by default.
- The product must not upload a case, raw evidence, asset identifier, credential, or report without a specific user export action.
- Application logs must use structured redaction before persistence.
- Raw evidence is treated as highly sensitive because it may provide an attacker with an ordered map of weaknesses.
- The user can delete a case and its content-addressed evidence from local storage.
- Export shows exactly what will leave the application and offers redaction without silently changing the source case.

## 12. Repository AI skills

The repository must contain Claude- and Codex-compatible skills or equivalent checked-in guidance that can:

- inspect prerequisites and supported runtime providers;
- install or retrieve the pinned product dependencies;
- start the application and a selected case workflow;
- explain setup and engine errors in plain language;
- inspect what temporary containers, files, roles, and credentials were created;
- perform or guide cleanup using product-supported commands;
- refuse to widen scan scope or execute remediation without the same explicit product authorization.

Skills are helpers. A skill's behavior is not a substitute for backend enforcement.

## 13. Release and update behavior

Each application release carries an engine compatibility manifest. Engines and rule databases may follow upstream regularly, but a particular case must resolve to an exact version and digest.

The application must:

- never resolve an engine from an unpinned `latest` tag;
- display the knowledge date and support status used by a report;
- distinguish “update available” from “current case is invalid”;
- warn when a pinned engine or ruleset is past its declared support date;
- preserve old provenance so historical cases remain explainable;
- generate an SBOM and third-party notice set for each distributed bundle;
- obey the redistribution decision recorded for every engine and data feed.

## 14. Implementation order

The implementation should proceed continuously in this dependency order without treating intermediate slices as the finished product:

1. Case domain model, local storage, evidence store, and coverage ledger.
2. Engine registry, runtime-provider abstraction, durable job orchestration, and progress events.
3. Provider-native credentials and the isolated administrative bootstrap broker.
4. Assessment, source connectors, candidate discovery, and scan contracts.
5. Adapter SDK, canonical finding model, raw evidence preservation, and engine integrations.
6. Explanation, prioritization, control mapping, and expert-role guidance.
7. Six-view desktop workflow and recovery UX.
8. Portable case export, redaction, integrity metadata, and schema exporters.
9. Same-case re-verification and comparison.
10. Repository skills, packaged runtime, updater, SBOM, notices, and platform releases.

Local static-analysis engines are useful for exercising the adapter pipeline early; cloud, Microsoft 365, and external engines still remain required parts of the complete product.

## 15. Definition of product completion

The product is complete only when all of the following have implementation and verification evidence:

- A supported clean desktop can install and start the app without separately installing each engine's Python, PowerShell, database, or CLI dependencies.
- A user can create, close, reopen, and delete a local assessment case.
- AWS, Azure, GCP, Microsoft 365, external assets, source code, IaC, containers, and Kubernetes can each enter the case lifecycle through their required engine families.
- Preferred read-only authorization and the isolated administrative bootstrap flow enforce their credential boundaries.
- Candidate assets, grants, unknown areas, and scan states produce accurate coverage records.
- Active external testing cannot start outside an explicitly recorded grant.
- Every required engine records exact provenance and can complete, partially complete, fail, cancel, and resume without falsifying coverage.
- Full raw findings survive normalization; related results can be grouped without destructive loss.
- Plain-language results never claim NIST or ISO compliance and never offer automatic write remediation.
- Cases remain local by default and can be exported with explicit contents, evidence hashes, and sensitivity warnings.
- A comparable second run produces trustworthy resolved, persistent, new, and unverifiable outcomes and identifies changed evidence on persistent findings.
- Claude/Codex repository skills install, start, inspect, and clean up through supported product interfaces.
- Every distributed component has a reviewed manifest entry, license disposition, pinned artifact, SBOM entry, and required notices or source offer.
- Supported platform installers and the managed runtime path behave as documented.

Passing a subset of these requirements is progress, not a claim that the complete product has shipped.
