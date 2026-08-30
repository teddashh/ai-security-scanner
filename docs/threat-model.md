# ai-security-scanner threat model

Status: design-time threat model

Last updated: 2026-08-30

Normative status: this threat model is subordinate to the [canonical product specification](product-spec.md). It may require an operation-scoped safety control, but cannot turn optional-engine, mapping, signing, updater, or disposable-runtime failure into a product-wide gate unless the specification's hard-block rule permits it.

This document defines threats and required controls for the intended product. It does not assert that the controls are implemented or that the product has passed a security review. Risk acceptance requires an explicit repository decision; silence is not acceptance.

## 1. Scope

This threat model covers:

- the Tauri desktop UI and Rust backend;
- local case and evidence storage;
- provider authorization and the administrative bootstrap broker;
- engine retrieval, manifests, adapters, containers, and local processes;
- cloud, Microsoft 365, local artifact, Kubernetes, and external-target scans;
- normalized findings, control mappings, exports, and re-verification;
- repository Claude/Codex skills that assist installation and operation.

It considers a single human user on one workstation. Shared-workstation authorization and a multi-user server deployment require separate threat models.

## 2. Security objectives

1. **Credential containment:** no third-party engine can obtain administrative credentials or credentials broader than its approved task.
2. **Scope containment:** an engine cannot expand a user-approved target set or scan activity.
3. **Evidence integrity:** raw evidence and provenance cannot be silently replaced, dropped, or confused with another case.
4. **Coverage honesty:** missing, partial, failed, or unknown work cannot appear as a pass.
5. **Local confidentiality:** the product does not transmit credentials or case data without an explicit user action.
6. **Supply-chain accountability:** every product-distributed or product-downloaded executable, engine image, ruleset, template set, and database is traceable to a pinned artifact and an operation-scoped release disposition. OS-owned facilities such as the verified Windows `System32\\wsl.exe` boundary remain governed by platform trust rather than being misrepresented as project artifacts.
7. **Safe failure:** interruption or partial cleanup is visible and recoverable.
8. **Non-remediation:** the product cannot use scanner authority to change the assessed environment.
9. **Outcome continuity:** product-owned reversible failure is repaired automatically, ambiguous objects are preserved beside a new isolated object, and optional failure leaves independent work plus an honest partial report available.
10. **Operation-scoped blocking:** a control blocks only the exact destructive, untrusted-execution, prohibited-contact, or untrustworthy-signature operation that creates the concrete harm.

## 3. Protected assets

| Asset | Sensitivity | Examples |
|---|---|---|
| Administrative bootstrap credential | Critical | administrator password, privileged OAuth session, root API key |
| Scan credential | Critical | STS token, Reader token, service principal, temporary certificate |
| Asset inventory | High | account IDs, tenant IDs, private IPs, resource names, topology |
| Raw scanner evidence | High | vulnerable endpoint, secret location, misconfiguration details |
| Normalized findings and priority | High | ordered path to the environment's weaknesses |
| Scope grant and identity record | High | ownership assertions, approved targets, authorization history |
| Case history | High | remediation history, accepted false positives, old evidence |
| Engine and update artifacts | High integrity | binaries, images, rules, templates, vulnerability databases |
| Control mappings and explanations | Medium integrity | NIST/ISO relationships, applicable AIDEFEND relationships, and plain-language advice |
| Export integrity key | High integrity | local signing key, when used |

## 4. Threat actors

- A malicious or careless local user trying to scan a target they do not own.
- Malware running as the desktop user and searching memory, files, logs, sockets, or clipboard data.
- A local administrator or root attacker. The product cannot fully protect secrets from a hostile operating-system administrator.
- A compromised, malicious, or abandoned upstream engine, image, package, template, rule feed, or registry.
- A malicious target returning crafted banners, filenames, JSON, HTML, archives, or extremely large responses.
- An engine adapter with excessive privileges or an exploitable parser.
- A recipient who modifies an exported report or misrepresents it as an audit.
- An AI agent or prompt-injected finding that attempts to widen scope, reveal secrets, run commands, or upload data.
- An honest user who mistakes incomplete coverage, stale rules, a scan failure, or a local signature for a security guarantee.

## 5. Trust boundaries

### Boundary A: UI to backend

All UI input is untrusted. Tauri commands validate identifiers, state transitions, paths, scope grants, and target syntax in Rust. A disabled button is not an authorization control.

### Boundary A2: signed installer to Windows WSL servicing

The signed installer resolves the Windows-owned `System32\wsl.exe`, rejects reparse points, detects
prerequisites, and may invoke only the fixed product-defined Microsoft WSL installation/update action
through normal UAC with a cleared environment and a bounded deadline. The webview cannot supply an
executable, arguments, working directory, environment, verb, or servicing operation. Restart state
and the in-progress generation are durable so the application resumes automatically. Failure,
cancellation, or timeout does not roll back application binaries or hide projects/reports; only
runtime-dependent tasks wait for bounded Retry. The main workspace opens while product-owned scan
tools prepare in the background, and a beginner is never instructed to administer WSL.

### Boundary B: backend to bootstrap broker

Administrative bootstrap is a distinct process and protocol. The case service sends a fixed provider operation and receives only status, non-secret identity metadata, cleanup obligations, and a capability reference for the resulting read-only credential.

### Boundary B2: backend to provider inventory API

Live discovery may use only the installed case/source/provider/profile/engine-bound read-only capability. Hosts, operations, fields, pagination paths, response sizes, record counts, retries, and wall time are fixed in the backend. Every response page is synced as a private SHA-256-addressed artifact before pagination inspection or canonical parsing. Continuation URLs are untrusted provider output and must match the exact provider host, resource path, API version, and query-key allowlist. Credentials and cursors never enter the case record, frontend, process environment, arguments, or logs.

### Boundary C: backend to runtime provider

The runtime provider exposes bounded job operations. Neither the UI nor AI skills receive the daemon socket or arbitrary run flags.

### Boundary D: runtime to third-party engine

An engine is untrusted third-party code. Its filesystem, network, credentials, resources, outputs, and lifetime are constrained independently of its upstream reputation.

### Boundary E: engine output to canonical data

Engine output, target responses, and repository contents are attacker-controlled input. Parsers enforce schemas and sizes; renderers escape content; no output becomes executable syntax.

### Boundary F: local case to export

An export is an explicit disclosure boundary. Redaction creates a derived package while leaving the original local case unchanged.

### Boundary G: case data to AI assistance

Repository skills and external models are separate trust domains. Raw findings and credentials do not automatically cross into an AI context.

## 6. Credential architecture

Cloud/provider authorization is an Advanced target path. It is never a prerequisite for localhost,
website, public/internal network, local source, saved-report, or unsigned-export work. Missing,
expired, or rejected provider authorization affects only the exact provider target/task and appears
as a coverage gap in the same master report as any successful sibling work.

### 6.1 Preferred authorization

The preferred flow keeps the user's password in the provider's own authentication surface and grants a short-lived, least-privilege, read-only role suitable for the selected engines.

The product should provide versioned provider templates and deep links for AWS, Azure, GCP, and Microsoft 365. Each template declares the exact APIs and data it permits.

### 6.2 Administrative bootstrap fallback

The fallback exists to accommodate a newcomer who only knows how to authenticate as an administrator. It is not the default scanner credential flow.

The broker protocol is:

1. Display the operations the broker will perform and the identity provider it will contact.
2. Obtain administrative authentication in the broker, preferably through the provider's browser or device flow.
3. Create a dedicated, named, time-bounded scan identity or role with the minimum read permissions required by the frozen run plan.
4. Verify the read-only identity using non-mutating calls.
5. Transfer only an opaque capability for the read-only credential to the credential service.
6. Destroy all broker references to the administrative authentication and exit.
7. Record created identities and required cleanup without recording secrets.
8. Guide the user through revoking old sessions, access keys, service principals, or temporary roles as applicable and changing the original password when it was exposed to the broker.

The broker must:

- be a separate small binary with no adapter or plugin loading;
- reject arbitrary provider actions;
- never invoke a shell;
- never receive a Docker or Podman socket;
- disable core dumps and diagnostic secret capture where the platform permits;
- keep secrets out of arguments, environment variables, logs, metrics, clipboard APIs, and crash reports;
- use locked memory where supported and overwrite buffers on release, while documenting that these measures do not defeat a privileged local attacker;
- allow network access only to the declared provider authentication and IAM endpoints;
- have a bounded lifetime and fail closed if the read-only role cannot be verified;
- return unresolved cleanup items visibly after a partial failure.

Changing a login password is not sufficient cleanup. Access keys, OAuth grants, sessions, service principals, and created roles must be enumerated and handled separately.

### 6.3 Scan credentials

Scan credentials are held by an ephemeral credential service and referenced through non-serializable capability handles. A handle is bound to:

- one case and scan run;
- one provider or connector;
- an allowed engine set;
- a resolved target set;
- read-only operations;
- an expiry.

Adapters receive the shortest usable credential representation through a protected process channel or engine-specific temporary mount. They never receive the bootstrap credential. Temporary mounts and files are removed on completion, cancellation, process crash reconciliation, and next launch.

## 7. External scan authorization model

External activity is divided into increasing levels:

1. `passive_public_discovery`: query public registries, DNS resolvers, and certificate transparency data without directly probing the target service.
2. `low_impact_external`: connect to an approved target for bounded service, TLS, or HTTP metadata checks.
3. `active_external`: execute approved vulnerability checks or templates that may exercise application behavior.

For direct-contact levels, the backend stores:

- canonical host, IP, CIDR, port, and protocol bounds;
- the user's asserted authority;
- the approved activity level;
- rate, concurrency, and time-window limits;
- the exact template or check policy;
- approval and expiry timestamps.

After the requested run/task is persisted but before direct target contact, task preflight resolves hostnames and guards against DNS rebinding, redirects, cloud metadata ranges, loopback, link-local, private ranges outside the approved scope, and IPv4/IPv6 representation tricks. The explicit `127.0.0.1:9001` Windows-host route is allowed only by its dedicated local-service contract. Redirects and newly resolved addresses do not inherit approval automatically. A preflight rejection affects that task and remains visible in the master report rather than aborting the run record.

Shared hosting, CDNs, SaaS endpoints, and outsourced infrastructure remain residual legal and operational risks even when the user controls a domain. The product records the assertion; it cannot prove legal authority.

Active template collections require policy classification. Destructive, denial-of-service, credential-stuffing, fuzzing, file-upload, headless-browser, or out-of-band callbacks are denied unless an explicit future policy reviews and enables the exact operation. Installing Nuclei does not authorize every Nuclei template. Refusing such an operation does not block local analysis, low-impact tasks, saved reports, or other engines.

## 8. Threats and required controls

| ID | Threat | Impact | Required controls |
|---|---|---|---|
| T-01 | Secrets appear in CLI arguments, environment, logs, history, or crash output. | Credential theft. | Opaque handles, protected channels, structured redaction before persistence, no secret command arguments, core-dump controls, secret test fixtures. |
| T-02 | Administrative credential reaches a scanner container. | Full cloud or tenant compromise through a third-party engine. | Separate broker binary; scanner plan can resolve only read-only capability handles; invariant tests reject admin profiles in engine manifests. |
| T-03 | A frontend flaw invokes privileged runtime operations. | Host takeover. | No runtime socket in UI; typed backend allowlist; capability-based job API; CSP and Tauri permission minimization. |
| T-04 | A container mounts the daemon socket or broad host directories. | Container-to-host compromise and data theft. | Manifest validation; deny socket/privileged/host namespace flags; narrow read-only mounts; dedicated workdir; release review for exceptions. |
| T-05 | Upstream image or binary is replaced. | Malicious code executes with scan access. | Pin cryptographic digest, verify configured signatures/provenance, approved download source, SBOM, no `latest`, compatibility manifest; block only that artifact and record its task as not tested while admitted siblings continue. |
| T-06 | Rules, templates, or vulnerability databases change independently of the engine. | Irreproducible or malicious findings. | Pin and record data artifact versions and hashes; treat feeds as separate third parties; show knowledge date. |
| T-07 | A stale engine silently misses current issues. | False reassurance. | Support dates, update status, visible knowledge date, expired-engine warning, no claim that absence of findings means safety. |
| T-08 | Malicious banner or repository text injects HTML, shell, SQL, path, or prompt content. | Code execution, UI compromise, or AI tool misuse. | Schema and size validation; escaping; parameterized SQL; no shell interpolation; normalized text treated as data; prompt-isolation rules. |
| T-09 | Malicious engine writes outside its job directory through traversal or links. | Host file overwrite or disclosure. | Canonical path validation, archive extraction policy, reject escape symlinks/device files, isolated mounts, atomic evidence ingest. |
| T-10 | User scans an unauthorized target. | Legal exposure and harm to third parties. | Backend scope grants, resolved target allowlists, tiered activity, expiry, rate limits, immutable run plan, event record. |
| T-11 | Target redirects or rebinds to a sensitive/internal service. | SSRF, metadata credential theft, unintended internal scan. | Re-resolve and compare target, deny metadata/link-local/loopback unless explicitly scoped, redirect policy, IP and protocol pinning. |
| T-12 | Aggressive scan overloads target or local workstation. | Service outage or local denial of service. | Per-engine rate/concurrency limits, resource quotas, timeouts, backpressure, pause/cancel, active-template policy. |
| T-13 | Engine hangs, laptop sleeps, API rate-limits, network disconnects, or a lifecycle event is lost. | Lost progress, permanent stale UI, or false completion. | Durable checkpoints, heartbeat/deadline, bounded retry, per-task terminal states, partial coverage; events are hints and startup/focus/resume/watchdog polling reconciles authoritative state. |
| T-14 | Credentials or findings remain in orphaned containers or temporary files. | Post-run secret and evidence exposure. | Dedicated ephemeral volumes, termination cleanup, startup orphan reconciliation, visible cleanup failures, capability revocation, and exact typed runtime provenance in durable checkpoints. |
| T-15 | Product or plugin silently uploads findings. | Disclosure of the user's attack map. | No default telemetry, outbound allowlists, explicit export boundary, code review of connectors, network-denied components by default. |
| T-16 | Export recipient modifies or truncates a package. | Misleading expert handoff. | Deterministic manifest, per-file hashes, optional signature, verification command, explicit redaction/exclusion list. |
| T-17 | User treats a local signature as proof of scan correctness or identity. | False evidentiary assurance. | UI and package wording limit signature to post-export integrity; separate `integrity` from `result confidence`. |
| T-18 | No findings, failed engine, or unknown source appears green. | False reassurance. | Independent coverage ledger; state-specific presentation; zero findings cannot set coverage; `unverifiable` comparison state. |
| T-19 | Normalization incorrectly merges distinct findings. | A real issue is hidden. | Preserve every source finding and evidence; no automatic cross-engine merge; one active presentation group per finding; append-only create/remove events; versioned fingerprint; expert access to raw results. |
| T-20 | Normalization double-counts corroborating evidence. | Inflated risk and unusable report. | One user-facing issue can reference multiple source findings; prioritization records corroboration separately. |
| T-21 | Automated NIST, ISO, or AIDEFEND mapping implies audit status, control implementation, certification, or official endorsement; AIDEFEND is also attached to findings with no AI-system applicability. | Misrepresentation and bad decisions. | Relationship-only mapping enum; no pass/fail/score field; reviewed, versioned rationale; explicit AIDEFEND applicability; attribution and non-endorsement notice; mapping failure removes only the relationship and never blocks findings, master report, or scanning. |
| T-22 | AI agent follows prompt injection in a finding or widens a scan. | Data exfiltration, unauthorized scanning, or host changes. | Treat evidence as untrusted data; no secrets in model context; AI calls same backend authorization; no runtime socket; no remediation command. |
| T-23 | Remediation advice is executed automatically or mistaken for endorsed code. | Production outage or permission escalation. | No execute/copy-run controls, no write credential in scan runtime, advisory wording, official reference and expert-role guidance. |
| T-24 | Demo findings are mistaken for real scans. | False product or environment claims. | Persistent Demo badge and provenance, synthetic namespaces, export marker, no demo-to-real state transition. |
| T-25 | Case IDs, asset IDs, or blob references cross cases. | Confidentiality breach and incorrect comparison. | Case-scoped queries, foreign-key constraints, capability-bound case ID, authorization checks, no user-controlled blob paths. |
| T-26 | Export redaction omits an unknown sensitive field. | Sensitive disclosure. | Data-classification metadata, allowlisted export schemas, group title/rationale/actor redaction, preview and manifest, engine raw output excluded by default when not safely redacted. |
| T-27 | Update rollback or registry outage makes historical cases unexplained. | Lost reproducibility. | Persist resolved manifests and provenance in the case; cache only legally allowed artifacts; distinguish unavailable artifact from resolved finding. |
| T-28 | License-incompatible component is redistributed. | Forced takedown or license violation. | Per-artifact license disposition, release deny-by-default, notices/source offer, SBOM, manual review of feeds and multi-component stacks. |
| T-29 | A forged update manifest redirects the desktop to attacker-controlled code. | Local code execution and case-data compromise. | Fixed HTTPS endpoint; allowlist for the exact GitHub repository/tag asset path; embedded updater public key; verify the selected current-platform payload, URL, digest, and detached signature before install; invalid material blocks only that update. Cross-platform completeness is publication policy. Compatible downgrade preserves/read-opens data; incompatible downgrade refuses before mutation. |
| T-30 | A forged provider prompt sends the user to a credential-phishing site. | Provider account compromise. | Backend provider-host allowlist; frontend URL revalidation; OS-browser opening only through a Tauri capability scoped to the exact AWS, Microsoft, and Google HTTPS host families; no general URL or path opener permission. |
| T-31 | A later provider bootstrap overwrites an earlier cleanup journal. | Orphaned privileged resources and unrecoverable cleanup obligations. | One private ledger per validated operation ID; immutable provider/resource binding; immediate atomic journal updates; explicit retryable cleanup surface. |
| T-32 | A provider response redirects pagination, floods records, or becomes partial after some pages. | SSRF, resource exhaustion, or falsely complete inventory. | No redirects; exact continuation allowlists; per-page/aggregate/time/record limits; one bounded safe retry; raw-page-first storage; explicit connected-empty, failed, cancelled, partial, and needs-reauthorization states. |

## 9. Supply-chain policy

An engine is not trusted because it is popular or open source. Admission to a distributed release requires:

- exact upstream repository and pinned source revision;
- artifact version, digest, and retrieval source;
- signature or provenance verification where upstream provides it;
- engine, template, feed, and database licenses reviewed separately;
- derived framework metadata pinned to its exact source, hash, version, license, attribution, and recorded modifications;
- adapter fixture tests and malformed-output tests;
- declared provider APIs, network destinations, mounts, credentials, and resource needs;
- known security-reporting channel and maintenance status;
- rollback and end-of-support behavior;
- release SBOM and required license/source materials.

Research checkouts under `.upstreams` are untrusted reference material. Their presence does not admit code into a release.

These are engine admission/publication controls, not product-wide readiness. Missing, stale, or unverifiable evidence prevents distribution or execution of the exact affected artifact. It must not stop an already installed trusted build from opening projects, running unaffected admitted engines, producing a partial master report, or exporting readable unsigned results. A publication channel may withhold its exact untrusted artifact without fate-sharing unrelated platforms or ordinary development work.

## 10. Evidence and export security

Raw evidence is more sensitive than many credentials because it can remain useful after a credential expires. The local data directory requires user-only filesystem permissions. The product should support encryption at rest with an operating-system-protected key before claiming protection on shared or lost devices; until implemented, documentation must state the local-disk exposure.

Export defaults should exclude raw engine logs unless the user selects an expert package or the adapter marks the artifact safe. The export preview identifies PII, PHI context, internal addresses, account identifiers, email addresses, secrets, and raw vulnerability evidence by sensitivity class.

Once the user exports a package to an arbitrary location, confidentiality depends on that destination. The application cannot guarantee secure email, cloud drive, or third-party handling.

The optional local bundle-signing private key is opened by handle from a private, non-reparse final
product namespace. The implementation must demonstrate protection against a foreign writer replacing
that final namespace or key; unusual but non-exploitable ancestor ACLs are diagnostics, not automatic
product-wide blockers. Key identity/rotation is durable and explicit so an old identity is not
silently replaced. Any stronger ACL shape, predecessor chain, continuity anchor, or recovery
transaction must first satisfy the canonical complexity budget with a reproducible replacement risk.
A key or identity mismatch hard-blocks only production of the requested signed bundle and immediately
offers an unsigned readable export. It never blocks scanning, reopening, reports, or existing
integrity-only verification of independently valid bundles.

## 11. AI skill security

Repository skills may:

- inspect supported prerequisites and runtime health;
- call approved installation, case, run, export, and cleanup interfaces;
- explain redacted diagnostics;
- list created temporary resources and cleanup obligations.

They must not:

- ask the user to paste a credential into model chat;
- read raw credential memory or provider caches;
- upload findings to an external model by default;
- interpret target-controlled content as instructions;
- approve scope on behalf of the user;
- enable active templates, widen CIDRs, or follow redirects outside scope;
- execute a remediation or arbitrary shell command from a finding;
- connect directly to the Docker/Podman socket.

## 12. Security-relevant failure behavior

- If the broker cannot confirm cleanup, the case displays unresolved credential cleanup steps and blocks those credentials from reuse.
- If evidence normalization fails, raw evidence is retained and the result is marked unnormalized; it is not dropped.
- If an engine cannot be verified or its license disposition is blocked, only that engine is unavailable, coverage reflects `not_tested`, and independent tasks plus the master report continue.
- If export hashing fails, no signed or “verified” package is produced; readable unsigned export remains available when its own bounded serialization succeeds.
- If local signing identity preparation fails during startup, scanning remains available and the
  failure is logged; a signed export still fails closed until the identity is repaired or explicitly
  rotated after confirmed key loss.
- If an embedded bundle signing identity is missing, malformed, has an unsupported schema, or does
  not match the manifest signer, bundles that declare that identity schema do not verify.
- If a historical observation lacks its immutable finding snapshot, the optional framework section records
  that limitation and does not reconstruct mappings or prose from the mutable current finding; the underlying historical finding/report remains available.
- If a relationship cannot resolve an exact evidence-record ID, artifact ID and hash, engine-run ID,
  and engine ID, or either the relationship or that execution lacks matching verified-current mapping
  provenance, the relationship is reported as unavailable or mismatched rather than exact. A current
  catalog digest is insufficient unless the coordinate, title, relationship, rationale, evidence
  engine, and AIDEFEND applicability condition also match one exact catalog entry. Historical catalog
  identities without an authenticated local snapshot remain unverified and unavailable. Same-engine
  executions are never pooled.
- Legacy or unanswered AI context remains unknown; it is not converted to an AIDEFEND
  not-applicable statement.
- If a connected source returns no assets, the source inventory remains incomplete/unknown; zero
  returned inventory is not treated as proof that the source is empty. Framework relationships do
  not define scan coverage.
- If a runtime provider cannot enforce a manifest boundary, the affected engine does not run through that provider; unaffected tasks continue and a partial/no-checks master report is saved.
- If product-owned disposable runtime state is corrupt, bounded automatic repair or side-by-side replacement runs. If ownership is ambiguous, the old object is preserved and a uniquely named generation is created; no name-only mutation is allowed.
- If a lifecycle event is missed, authoritative startup/focus/resume/watchdog polling reconciles the durable journal within the canonical refresh bound or exposes Retry/offline-with-last-known-data.
- If a re-scan lacks comparable scope or engine completion, the result is `unverifiable`.

## 13. Residual risks

The following cannot be eliminated by this design:

- A hostile root or administrator on the workstation can inspect process memory and local files.
- A user can lie about ownership or legal authority.
- A read-only scan can still expose sensitive metadata and can trigger provider rate limits.
- A correctly pinned upstream engine can contain an unknown vulnerability or malicious logic.
- Scanner findings can be false positives and scanners can miss real problems.
- Public-data discovery cannot reveal assets for which no connected source or public trace exists.
- External targets, CDNs, and shared hosting can make technical ownership differ from legal authorization.
- A recipient can misuse a legitimately exported package.

The product must describe these as limits, not hide them behind a disclaimer or a score.

## 14. Verification plan

Implementation should eventually provide evidence for at least:

- the exact-candidate installed-Windows beginner path: install, combined `127.0.0.1:9001` Start, master report, reopen, and readable export within the canonical budget, without maintainer takeover or Terminal;
- a real-boundary optional-engine/gateway failure that preserves a successful sibling and produces an honest partial report;
- a deliberately lost lifecycle event corrected by startup/focus/resume/watchdog reconciliation;
- unit tests for state transitions, scope canonicalization, coverage, fingerprints, redaction, and comparison;
- broker tests proving administrative credentials cannot enter engine plans or persisted structures;
- runtime escape and forbidden-mount tests;
- adapter fuzzing and malicious-output fixtures;
- SSRF, redirect, DNS rebinding, IPv4/IPv6 normalization, and metadata-address tests;
- cancellation and crash-recovery tests that detect orphaned credentials, containers, and files;
- dependency, image, signature, license, and SBOM checks for release artifacts;
- export traversal, hash, signature, truncation, and redaction tests;
- UI tests that distinguish demo, partial, failed, unknown, no-findings, and verified states;
- mapping tests that reject unsupported AIDEFEND coordinates, missing attribution, and relationships on non-applicable scanner results;
- manual security review before making security or isolation claims.

Modeled, unit, and CI checks support but never substitute for the exact-candidate human path. Listing a control or test here is not proof that it passes. Before adding a new hard block, durable state, recovery transaction, or global qualification, the review must identify the reproducible harm, show why preservation/isolation/warning is insufficient, measure blocked user work, and meet the canonical complexity budget.
