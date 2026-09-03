# ai-security-scanner canonical product specification

Status: canonical product specification and sole source of truth for product behavior

Audience: product, design, desktop, runtime, engine, reporting, security, test, and release contributors

Last updated: 2026-09-03

This specification defines the intended product. It does not claim that every requirement is already implemented or verified. Implementation status and gaps belong in the [product audit](product-audit.md) and issue tracker, not in this document.

When another repository document, test, release script, or current implementation conflicts with this specification, this specification controls the product decision. Architecture, runtime, threat-model, engine, and release documents may add implementation detail, but may not add a user-visible gate or change a user outcome without first changing this document. README files remain marketing and quick-start material; they are not a competing specification.

### Document authority

| Repository material | Authority |
| --- | --- |
| This canonical product specification | The only authority for intended product behavior, user outcomes, warning-versus-blocking decisions, and acceptance policy |
| [Product audit](product-audit.md) | Evidence and implementation status at its stated baseline; it identifies gaps but does not add intended behavior |
| Architecture, runtime, threat-model, engine, provider, usability, security, and release documents | Subordinate implementation detail; their body text must be corrected when it conflicts with this specification |
| English and Traditional Chinese READMEs | Marketing, availability, and quick-start guidance; not a product contract |
| `docs/release/v*.md` | Historical, non-normative records of what an earlier candidate claimed or planned |
| Code, tests, schemas, workflows, and skills | Current implementation contracts and tooling; they reveal or prevent drift but never override this specification |

A precedence banner is not enough to preserve alignment. When a subordinate body or machine-readable contract contradicts this specification, the contradiction is a defect and must be fixed in the same workline.

## 1. Product north star

`ai-security-scanner` helps a Windows beginner go from “What should I check?” to a useful, understandable security report without learning Linux or selecting scanner engines.

The north-star outcome is:

> Install the app, choose something you own, start a scan quickly, and receive an honest list of what was tested, what was not tested, what was found, and what to do next.

The product integrates established open-source tools. Its value is the guided workflow, safe isolation, orchestration, normalization, coverage disclosure, plain-language prioritization, and reusable report—not the number of infrastructure proofs shown to the user.

### 1.1 Primary user

The primary user is a Windows owner, developer, small-business operator, or IT generalist who:

- has little or no security-scanning experience;
- may never have used WSL, Linux, Podman, containers, gateways, manifests, or scanner CLIs;
- can identify a website, IP range, code project, or account they are allowed to assess;
- wants useful next steps, not an engineering contract.

Security professionals and maintainers are secondary users. Their technical needs are served through progressive disclosure and exports; they do not define the first-run journey.

“Beginner” is an experience assumption, not a permanent eligibility class. Readiness is evaluated per selected job: the user can continue independently, needs a named account/tenant administrator or specialist for one bounded handoff, or the specific job is not currently supported. Needing help for one advanced source never blocks another admitted task, an existing project, or report/export access.

### 1.2 Core jobs

The product must make these jobs simple:

1. Check a service on this computer, including `127.0.0.1:9001`.
2. Check a website or API already online.
3. Check public IP addresses or domains.
4. Check an internal network such as an approved `/24`.
5. Check a local project or GitHub repository.
6. Check an AI application and its supporting code/configuration.
7. Check advanced sources such as cloud accounts, IaC, container images, and Kubernetes.
8. Understand and share one report, even when some checks fail.
9. Reopen a saved project and compare a later scan with an earlier one.

### 1.3 Non-goals

The product is not:

- a penetration-test replacement or an aggressive exploitation tool by default;
- an automatic remediation system;
- a guarantee that every asset or weakness was discovered;
- an ISO/IEC 27001 audit, NIST certification, AIDEFEND assessment, or compliance decision;
- a single security or compliance score;
- a cloud service that silently uploads code, credentials, evidence, or findings;
- a reason to make a beginner administer WSL, Podman, containers, gateways, or engine manifests;
- required to support every target or engine before the useful supported paths can ship.

## 2. Governing product rules

The following rules apply across installer, desktop, runtime, engines, reports, exports, tests, and release automation.

1. **Outcome before infrastructure proof.** The app opens and the user's work remains accessible while disposable infrastructure is checked or repaired in the background.
2. **Isolation instead of obstruction.** Safety is achieved with isolation, preservation, bounded actions, recovery, and disclosure. Blocking is the last resort.
3. **Product-owned and reversible means automatic.** The product may automatically repair, replace, or rebuild its verified disposable runtime, caches, helpers, and temporary files.
4. **Ambiguous ownership means preserve and continue.** If an old runtime cannot be proven to belong to this product, do not modify or delete it. Create a new uniquely named isolated runtime and continue.
5. **User data is not disposable runtime.** Cases, findings, evidence, exports, selected source snapshots, and user project files must be preserved unless the user explicitly requests their deletion.
6. **Independent work fails independently.** One target, engine, export enhancement, or optional integration must not abort unrelated work.
7. **Partial results are a successful product outcome.** A partial report clearly distinguishes tested, not tested, failed, timed out, and cancelled work.
8. **No silent scope reduction.** Requested and executed hosts, ports, protocols, paths, stages, and engines are visible before scanning and in the report. Limits never become an implicit narrower scan.
9. **Fast evidence first.** Quick discovery produces an early useful result; full inventory and deeper checks may continue in the background.
10. **Frameworks are references, not gates.** NIST, ISO 27001, and AIDEFEND relationships are derived from findings and evidence. They neither start nor prevent a scan.
11. **Repair means the product repairs.** A Repair action triggers bounded automatic reconciliation. It does not send a beginner into a second technical setup journey.
12. **Human path is the first acceptance test.** Modeled tests and CI support, but never replace, a person installing the app and obtaining a report.

### 2.1 Unified safety decision

| Situation | Required behavior | User-visible treatment |
| --- | --- | --- |
| An operation could irreversibly modify or delete data not clearly owned by this product | Stop before mutation | Hard block, identify the exact risk, and offer a non-destructive path |
| The object is verified product-owned disposable state and the change is reversible or rebuildable | Repair or rebuild automatically | Background progress; no technical action required |
| Ownership is uncertain | Preserve it and create a separate uniquely named product-owned object | Brief notice after continuity is restored; no deletion instructions |
| An optional engine or feature fails | Continue independent work | Partial report with failure and coverage gap |
| Requested scope cannot be fully covered | Automatically batch exact equivalent work; otherwise require an explicit revised/partial-scope choice | Before-start scope summary and report gap; never label complete |
| Internal state is stale or contradictory | Re-read authoritative state and reconcile within a bounded time | “Checking status” briefly, then Continue, Retry, or report—not a permanent state |
| A verified application/update/engine package fails integrity verification | Do not execute that package | Disable only that package or update; keep installed safe functions available |

## 3. Ten-minute first-value gate

The first P0 beginner-ready and stable-release gate is a real installed-Windows journey, not a source-checkout test. A clearly labeled public testing prerelease may be used to obtain this evidence before the gate passes; it is not a claim that the beginner journey is qualified.

### 3.1 Reference journey

On a supported reference Windows machine, a first-time user must be able to:

1. install `ai-security-scanner`;
2. open the main screen immediately;
3. see one primary **Scan this computer at 127.0.0.1:9001** action, with an optional edit affordance beside it;
4. press that action once to select the use case, accept the displayed low-impact scope, and start;
5. let the product prepare its managed runtime automatically in the background;
6. receive a beginner master report for the exact target.

The report is useful whether the service is reachable, closed, times out, or later checks are partial. Passing this first-value gate requires at least one localhost quick task to execute and durably report one of those observed outcomes. An honest `no checks completed` report is still required when setup fails, but it does not count as a first-value pass. The product must not represent “closed,” “unreachable,” “not tested,” or “engine failed” as secure.

### 3.2 Time and interaction budget

- On the release reference Windows machine and network, wall-clock time from installer launch to the first saved report is at most ten minutes, including managed-runtime download/preparation and a WSL installation/update that Windows can complete without reboot. This same bound applies when prerequisites were already ready.
- With WSL absent, the signed installer performs the fixed product-defined detection/preparation action. The user may see a Windows elevation or restart prompt because those are operating-system trust boundaries; the user must not open Terminal or type a command. After restart, the app resumes product-runtime creation without exposing a generic elevation helper.
- If Windows requires a restart, setup state survives it and the app resumes automatically on the next launch. Only the interval from OS shutdown initiation until the user returns to the desktop is excluded from the ten-minute measurement; combined active pre/post-restart elapsed time remains within ten minutes. Active user interaction across both launches is at most three decisions: install, approve the Windows prompt when needed, and press the combined localhost scan action.
- Runtime/image download bytes, current stage, and a bounded time range are visible, but WSL distro names, providers, VHDs, engines, manifests, and gateways are hidden under Technical details.
- The workspace, saved projects, and existing reports remain accessible while preparation is pending or unavailable.

### 3.3 First-value acceptance record

Every Windows candidate promoted as beginner-ready or stable must preserve a redacted passing human-path record bound to the exact candidate. The participant is a qualifying Windows beginner who did not build the product, contribute to it, or rehearse its setup; the facilitator may observe but may not take over, dictate operational steps, or administer WSL. The record includes installer identity, Windows version, timings, decisions, visible errors, final coverage, and report outcome. It must not contain target data, credentials, or raw evidence. A maintainer walkthrough, CI simulation, or synthetic declaration cannot be substituted for this record.

A technically qualified Windows artifact may be offered earlier as a **public testing prerelease** so users can test the real installer. Its release page and machine-readable metadata must prominently identify every unobserved human path, installed-app lifecycle, data-preservation path, and unverified OS signature. It must not be described as beginner-ready, recommended, stable, signed, or fully qualified. A failed human path blocks beginner-ready/stable promotion until corrected and retested; it does not block an honestly labeled testing prerelease, unrelated source work, or another independently qualified platform.

## 4. Beginner journey and information architecture

### 4.1 Main journey

1. **Choose what to check.** Use human use cases, not engine or infrastructure names.
2. **Review one concise scope summary.** Show the target, contact method, default limits, expected duration range, and anything intentionally excluded.
3. **Start.** Selecting a local folder or entering an exact low-impact target and pressing Start records the user's intent; it is not followed by a duplicate permission ceremony.
4. **Watch understandable progress.** Show the user task, elapsed time, estimate range, last confirmed activity, and Cancel. Put engine details in a disclosure.
5. **Read one master report.** Open the report as soon as any durable result is available. Update it as later stages finish.
6. **Act or share.** Give prioritized next steps and a readable HTML/print export first; expert formats remain available.

Project name is generated from the target and date and can be edited. Company/team name and organizational questionnaire fields are optional and never block a local, website, code, or network scan.

Questionnaire answers are context, not evidence, authorization, or engine selection by themselves. They may recommend assets or sources for a future frozen run, order observed findings and evidence gaps, adapt business-impact explanations, and suggest an appropriate expert type. A context factor affects priority only when retained finding or asset evidence supports that factor, and the reason remains visible. Questionnaire answers never fabricate a finding, asset fact, severity, confidence, tested status, or framework result; silently widen a run; select more intrusive activity; or treat a PII, PHI, or other business label as proof that a check ran.

### 4.2 Primary navigation

The default desktop has no more than four primary destinations:

- **New scan**
- **Projects**
- **Report**
- **Settings**

Setup, progress, export, and comparison are contextual states within a project, not permanently competing top-level destinations. Advanced cloud setup, engine details, provenance, raw evidence, and diagnostic logs are progressively disclosed.

### 4.3 Language and accessibility

- English and Traditional Chinese are complete product languages. A language change updates the whole UI, including runtime and error states.
- English README and Traditional Chinese README remain separately complete and cross-linked.
- First-layer copy uses short sentences and use cases. Terms such as WSL, Podman, gateway, checkpoint, manifest, provenance, digest, and runtime ownership appear only in Technical details or maintainer documents.
- Keyboard navigation, visible focus, skip links, screen-reader labels, reduced motion, contrast, zoom, and responsive layouts are release requirements for the primary journey.
- Color is never the only indicator of severity, completion, or coverage.

## 5. Managed runtime and Windows lifecycle

### 5.1 Boundary and ownership model

The managed runtime is disposable product infrastructure. Cases, evidence, user-selected source files, and exports live outside it. Rebuilding a runtime must not delete or migrate case data.

Every new runtime receives:

- a unique generation ID and OS registration name;
- a private product data directory;
- a small durable ownership record created before mutable runtime contents;
- a recorded registration/storage path and product generation ID;
- bounded lifecycle operations and a reconciliation journal.

A name match alone is never ownership proof. Exact ownership proof is required before modifying or deleting an existing runtime, not before creating a different isolated runtime.

One durable preparation operation owns one generation identity. Retry, app relaunch, and Windows restart reuse that same safe in-progress generation; they do not allocate a new WSL registration on every attempt. A replacement allocates another generation only after reconciliation decides the prior generation is unusable or ownership is ambiguous.

### 5.2 Automatic preparation

The signed install flow detects Windows/WSL prerequisites and records the outcome before it exits. When WSL installation or update is required, the signed installer invokes only a fixed, product-defined Microsoft WSL servicing action through normal UAC, records restart-required state, and arranges a safe resume. No webview value may select the executable, arguments, working directory, environment, or elevation behavior. WSL servicing failure, cancellation, or timeout does not roll back application binaries or prevent the main shell from opening; it makes only runtime-dependent tasks temporarily unavailable with Retry. Such a build cannot pass first-value promotion until corrected, but the installed workspace and reports remain usable. After installation/restart, the application opens directly to the main shell and prepares the product runtime in the background; there is no later manual setup action. Runtime preparation can resume verified downloads and creation after interruption. It may automatically:

- create or repair verified product directories and permissions;
- resume or restart verified downloads;
- start, stop, replace, or rebuild a verified disposable runtime;
- mark a corrupt product-owned generation inactive and retain it until a verified replacement works;
- create a fresh generation when recovery is slower or less certain than replacement;
- clean verified temporary state after the replacement is working.

If an installed managed-runtime file or manifest fails package verification, the product never executes it. It performs a bounded repair from the signed installer payload or another already verified product cache, then reinitializes the runtime manager or relaunches automatically into the same selected project. If no verified repair source is available, only dependent scan tasks become unavailable; projects, reports, unsigned exports, and unaffected capabilities continue.

The product never uses global `wsl --shutdown`, never edits unrelated WSL distributions, and never unregisters a distribution without exact deletion authority.

### 5.3 Runtime decision table

| Observed Windows/runtime state | Product decision | Preservation promise | User experience |
| --- | --- | --- | --- |
| Clean install; WSL ready; no product runtime | Create a new unique generation and start it | No unrelated WSL state touched | Background “Preparing scan tools” |
| Clean install; WSL absent/disabled/outdated | Use the supported Windows enable/update flow; persist restart state | Existing applications and distros untouched | Windows prompt if required; automatic resume, no Terminal |
| One or more unrelated WSL distros | Ignore them and create the product generation | Unrelated registrations and storage byte-for-byte unchanged | No warning unless a real resource conflict exists |
| Healthy verified current product runtime | Reuse it | Cases remain outside runtime | Ready without ceremony |
| Healthy verified older product runtime | Prefer side-by-side current generation; migrate only disposable cache when simpler | Old generation retained until new one works | Background upgrade; scan/report access continues |
| Verified product runtime partly corrupt | Repair bounded state or rebuild a new generation | Case/evidence data untouched; corrupt generation retained until replacement works | Automatic recovery; brief plain-language status |
| Name resembles the product but ownership is ambiguous | Do not adopt, edit, export, unregister, or delete it; choose a new unique name | Ambiguous distro and storage unchanged | Continue automatically; optional post-recovery notice |
| Ghost app registration, missing binaries/manifest/ownership record | Treat registry metadata as insufficient proof; repair app registration and create a new generation | Unknown old runtime untouched | Continue automatically; no manual WSL cleanup |
| Install/runtime creation interrupted or Windows restarted | Reconcile the durable journal; resume safe steps or abandon the incomplete generation and create a new one | Never infer deletion authority from an interrupted intent | “Continuing setup” with timeout and fallback |
| Verified disposable generation cannot be stopped or removed now | Mark cleanup pending and use another generation when possible | Do not delete uncertain/live files | Scan continues if an isolated generation is available; cleanup retries later |
| No supported runtime can be created after bounded automatic attempts | Keep the app and all projects usable; disable only checks requiring it | All user data preserved | Explain what cannot run, offer Retry and diagnostic export |

### 5.4 Reconciliation and bounded states

- Lifecycle events are hints; the durable journal and current OS inventory are authoritative.
- Startup begins an authoritative refresh within one second of backend/UI readiness. Window focus/resume and a watchdog do the same. Each refresh either reconciles within ten seconds or visibly transitions to Retry/offline-with-last-known-data; it never leaves an unbounded spinner.
- Every long-running, restartable, or side-effecting non-terminal operation records a deadline, heartbeat/stale threshold, operation ID, last milestone, and deterministic timeout outcome. Task-specific values are part of its contract and are shown as an estimate/stale state rather than hidden constants.
- A missed event cannot leave the UI permanently Ready, Repairing, Running, or “Finish one Windows setup step.”
- After a deadline, the product automatically retries a safe step, reuses or deliberately replaces its durable generation, or marks the affected capability unavailable. It never waits indefinitely or allocates a new generation on every poll/relaunch.
- **Repair** runs this reconciliation and returns to the prior user task. Technical diagnostics are optional; Repair never makes the user administer WSL.

### 5.5 Backup, reset, upgrade, and downgrade

- Case database and evidence migrations are versioned, transactional, and preceded by a bounded application-data backup when they change durable user data.
- A failed data migration leaves the prior bytes readable by the prior version and offers a non-destructive export/recovery path.
- Runtime upgrades are side-by-side. The current generation becomes active only after it starts and passes a functional scan-tool probe.
- Retries reuse their durable generation. After a replacement works, automatically clean only obsolete generations with exact product ownership. Retain at most the active generation, one verified rollback generation, and any generation referenced by a durable unfinished checkpoint. Ambiguous generations are never included in automatic garbage collection.
- Downgrade never rewrites newer case data in place. It opens supported data read-only, uses a compatible backup, or explains the limitation while preserving all bytes.
- Same-version **Repair installation** replaces verified application binaries/resources and repairs product registration while preserving runtime, projects, findings, evidence, exports, settings, and signing identity. Interrupted Repair retains or restores the last runnable binary set and resumes idempotently.
- **Reset scan tools** removes and rebuilds only runtime generations with exact product ownership. Ambiguous objects remain untouched and are listed in an optional diagnostic summary.
- Resetting runtime must not delete cases, evidence, exports, settings unrelated to runtime, or user source files.

### 5.6 Uninstall promise

The Windows uninstaller offers three clear choices:

1. **Remove the app only (default).** Remove application binaries and registration. Preserve projects, findings, evidence, exports, settings, and managed data for reinstall.
2. **Remove the app and scan tools; keep my projects.** Remove exactly verified runtime generations, images, helpers, and disposable caches. Preserve projects, findings, evidence, exports, preferences, and signing identity.
3. **Remove the app and all ai-security-scanner data.** After an explicit data-loss confirmation, remove cases/evidence and only exactly verified product-owned runtime/data paths.

“Scan tools” means disposable product runtime, images, helpers, and caches; it never includes case/user data. If an object is ambiguous, every uninstall choice preserves it and reports that it was not removed. The uninstaller never recursively deletes a broad application-data parent, never deletes by name alone, and records what was retained. A separate Settings action may perform the same exact scan-tool reset while preserving projects.

Before any uninstall choice completes, it stops dispatch and performs a bounded stop of every verified product runtime so target contact ceases. A runtime that cannot be stopped or removed is retained and explicitly reported; the uninstaller never claims it was removed. After app-only uninstall, reinstall reopens and exports the same project. After scan-tools removal, reinstall creates a verified runtime and the same project can scan, reopen, and export. The all-data path ends by verifying exact removal rather than reopening deleted projects.

Normal N-1 upgrade must preserve projects, case database, evidence, signing identity, preferences, and unrelated WSL distros. Reinstall after a ghost registration must not require manual cleanup.

## 6. Target types and honest scan semantics

Every run has a **Target Coverage Contract** with two run-bound views:

- **Requested:** what the user selected or approved, frozen before the run starts.
- **Executed:** an append-only record of the exact hosts/URLs/files/accounts, address range coverage, ports, protocols, paths, stages, engines, limits, timestamps, and outcomes actually observed. It updates the live report as work finishes and becomes immutable when the run ends.

Any difference is a first-class coverage gap shown before Start when known and in the report after execution. A percentage without the denominator and dimensions is insufficient.

### 6.1 Target semantics

| User choice | Default quick behavior | Full/deep behavior | Never implied |
| --- | --- | --- | --- |
| Local service `127.0.0.1:9001` | Contact that Windows host and exact port; record reachable/closed/timeout; if HTTP-like, perform bounded protocol identification | Optional service-specific checks after the quick result | Other ports, other hosts, or “secure” because closed/unreachable |
| Website/API URL | Use the exact scheme, hostname, explicit/default port, and path; bounded HTTP/TLS checks; do not follow an out-of-scope redirect | Optional same-host crawling and approved templates with disclosed limits | Whole domain, all subdomains, all APIs, authenticated workflows |
| Public IP | Quick discovery on a displayed port preset | Full displayed port range and deeper checks selected by the user | Ports that were not attempted |
| Public domain/hostname | Resolve and retain the observed addresses, then check the exact host scope and displayed ports | Optional explicit subdomain discovery and deeper checks | Neighboring domains, undisclosed subdomains, only HTTPS/443 unless shown |
| Internal host or `/24` | Detect likely local ranges, let the user choose when ambiguous, and perform displayed low-impact discovery across the exact address set | Full inventory and optional deeper approved checks | A hidden sample of hosts/ports or every corporate network |
| Local source folder | Create a read-only bounded snapshot of the selected folder and run applicable code/secret/dependency/configuration checks | Optional broader history/dependency analysis with separate disclosure | Upload, edits, pushes, unselected folders, or live-secret verification |
| GitHub repository | For public repos, create a pinned read-only snapshot; for private repos, use official short-lived authorization and the selected repository only | Optional history, dependency, and branch coverage explicitly selected | Organization-wide access, writes, issue/PR changes, or all branches by default |
| AI application | Scan selected code, dependencies, secrets, prompts/configuration/deployment files, and classify which findings have AI-system relevance | Optional deployed endpoint or cloud checks as separately scoped targets | Model safety testing, jailbreak resistance, or AIDEFEND implementation unless actually tested |
| IaC | Scan the selected immutable project snapshot | Optional module/plan context supplied by the user | Live cloud configuration |
| Container image | Scan the selected exported image/digest without running it | Optional SBOM and deeper package/configuration checks | Registry-wide or running-workload coverage |
| Kubernetes | Scan supplied manifests or an explicitly connected read-only cluster scope | Optional node/workload checks with separately stated reach | All clusters, namespaces, nodes, or runtime behavior |
| Cloud account | In Advanced mode, use official short-lived read-only authorization for one displayed account/project/subscription/tenant | Inventory first, then applicable configuration/identity checks | Organization-wide coverage or compliance certification |

### 6.2 Scope and authorization UX

- Choosing a local folder is authorization to read the product-created snapshot for that run.
- Localhost needs no ownership checkbox: entering or accepting the exact target and pressing the combined Start action is the low-impact confirmation.
- An internal host or `/24` Start action carries one concise inline assertion that the user owns/administers that network or is authorized to test it. A public target carries the equivalent ownership/authorization assertion. Record actor, time, target, and limits, and reuse the assertion for unchanged target/activity instead of adding a second step or hidden checkbox.
- Active, intrusive, credentialed, scope-expanding, or third-party testing requires a separate explicit confirmation that names the additional activity and scope.
- The product must never contact an external target merely to validate a form field or ownership claim.
- Network rate, concurrency, timeouts, and port/address limits use conservative presets. Advanced users can lower them. Any automatic reduction remains visible.

### 6.3 Internal network selection

For a single credible non-VPN local network, the product prefills the likely `/24` and lets the user edit it. With multiple credible adapters, it shows recognizable choices such as Wi-Fi, Ethernet, or VPN rather than route-table terminology. Detection failure falls back to localhost and a simple manual target field; it does not block the app.

### 6.4 Source capability view

For advanced sources, source selection and reporting expose a versioned capability view across the dimensions applicable to that source, including inventory, identity and access, network exposure, storage exposure, logging, and secret/configuration state. Each cell is `supported`, `partial`, `unavailable`, or `unknown` and names its exact account/project/subscription/tenant scope, relevant engine/profile, and known limitation. Providers and source types need not be symmetrical.

This view describes available product capability only. It never claims that a particular run obtained evidence. Actual run coverage derives exclusively from that run's frozen Requested contract and append-only Executed outcomes. A missing, partial, stale, or unknown capability becomes a visible limitation for its dependent task and roadmap; it is not a product-wide, release-wide, compliance, or development gate.

## 7. Phased scanning model

Each target progresses independently through three stages.

### 7.1 Quick discovery

Goal: provide the first durable, useful result quickly.

- confirms basic reachability or validates the selected local snapshot;
- uses the smallest honest host/port/file set shown before Start;
- starts the master report as soon as the first result or failure is durable;
- aims for a useful update within two minutes after runtime readiness.

### 7.2 Full inventory

Goal: enumerate the complete approved target dimensions supported by the selected preset.

- covers the displayed hosts, ports, files, dependencies, assets, or account resources;
- runs in the background after quick discovery unless the user cancels;
- continuously updates coverage and ETA range;
- records truncation, API pagination/rate limits, unreachable segments, and unsupported dimensions.

### 7.3 Deep checks

Goal: perform slower, more specific, or more active checks.

- starts only when the target and activity are authorized;
- can be selected before the run; selecting additional depth or scope later creates a new linked child run with its own frozen authorization and Requested contract rather than mutating a running run;
- is never required to deliver the quick or inventory report;
- may run for a long time, but always has progress, heartbeat, cancellation, timeout, and partial results.

If a target is too large for one invocation, the product automatically creates exact bounded batches when batching preserves the requested semantics. If work must be omitted or semantics would change, it offers a truthful explicit choice: change the range, change the depth, or proceed with a named partial subset. It never silently samples or truncates.

## 8. Engine orchestration and recovery

### 8.1 Unit of independence

The durable unit of work is the smallest independently retryable target-stage-engine task. If one engine invocation covers independent ports, hosts, repositories, pages, or batches whose results can survive separately, each unit is a durable task or append-only subtask with its own coverage outcome. Planning creates the run and all known task outcomes before disposable runtime preflight. Preflight, image availability, gateway setup, credentials, timeouts, and execution are evaluated per task or per genuinely shared dependency group—not as one global gate.

An unavailable engine is a task outcome, not a reason to erase the run. If at least one task can run, it starts. If no task can run after bounded automatic reconciliation, the product still saves a report showing the requested scope, failure reasons, and next action.

### 8.2 Task states

Every planned task ends in exactly one user-meaningful outcome:

- `tested_complete`
- `tested_partial`
- `failed`
- `timed_out`
- `cancelled`
- `not_tested`

Queueing, preparing, pulling, running, normalizing, and cleaning are transient technical phases, not additional final meanings. “No findings” is valid only for a tested task and never substitutes for `not_tested`.

### 8.3 Failure behavior

- Engine catalog or image failure disables that engine task only.
- Gateway failure disables only tasks that need that gateway.
- Missing cloud authorization disables only the relevant cloud task/account.
- A malformed local snapshot disables only tasks that use it.
- Normalization failure retains bounded raw evidence and marks the task partial or failed.
- Mapping failure leaves findings intact and marks only framework relationships unavailable.
- Signing failure leaves scanning and unsigned/readable export available.
- Updater or release-provenance failure prevents applying the affected update/package, not opening the installed app or using unaffected engines.

### 8.4 Timeout, cancel, retry, and restart

- Every task has a displayed deadline or estimate range and emits durable heartbeats.
- Cancel stops new dispatch immediately and terminates active target contact/revokes the task's gateway lease before, or within a task-contract bound explicitly shown with, acknowledgement. Only non-contacting resource/file cleanup may continue in the background; pending cleanup does not suppress already saved results.
- Retry targets only failed, timed-out, or not-tested work by default. Completed sibling results remain unchanged.
- A retry creates a new attempt linked to the prior one. It never overwrites evidence.
- Successful work units remain durable when a later sibling unit fails. Retry schedules only the unfinished/failed units unless the user explicitly requests a full rerun.
- On app restart, durable tasks are reconciled with live workers/resources. Resumable tasks show Continue; otherwise the product safely starts a new attempt and preserves the previous attempt as interrupted.
- Exact historical engine/runtime versions remain attached to evidence. Inability to reproduce an old execution environment may prevent byte-equivalent resume, but must not prevent a new current-version attempt or access to historical results.
- Events accelerate UI updates; bounded polling on startup, focus, resume, and stale heartbeat converges to the authoritative durable state.

### 8.5 Engine lifecycle disclosure

Every catalog entry exposes its support state, runnable state, exact admitted artifact when one exists, knowledge/support dates, maintenance owner, update procedure, and any publication, licensing, compatibility, or deprecation reason. Experimental, unavailable, stale, or deprecated engines never appear as generally available. Their state affects only dependent tasks and capability cells; it does not block unrelated engines, ordinary product development, or an independently supported release channel.

## 9. Findings and evidence model

### 9.1 Normalized finding

Each finding retains:

- affected target/asset and location;
- source engine, rule/check identifier, version, and run attempt;
- a versioned stable comparison key derived from target, check, and location coordinates, excluding mutable presentation fields such as title, severity, confidence, and guidance;
- evidence reference and integrity hash where available;
- original severity plus normalized severity;
- confidence and verification state as separate values, with the source and known limits of the confidence judgment;
- plain-language risk and likely impact;
- the smallest practical next step and an appropriate expert type;
- remediation and false-positive workflow history;
- applicable framework relationships with rationale and version.

### 9.2 Severity, confidence, and priority

- Severity describes potential impact, not certainty.
- Confidence describes the strength of evidence, not impact.
- The original source severity/value is retained. An unrecognized or absent severity is shown as `unknown / needs review`; it is never silently normalized to Informational, Low, green, or passed.
- Confidence provenance and limitations are visible in the finding detail; a normalized label never implies certainty that the source did not establish.
- Priority is a transparent ordering using severity, confidence, exposure, exploitability, and user context. The UI explains why an item is early; it does not expose a pseudo-precise security score.
- A low-confidence critical item remains visibly critical and needs confirmation; it is not silently demoted away.

### 9.3 Deduplication and false positives

- Exact duplicate observations from one task may be collapsed while preserving every evidence reference.
- Cross-engine findings may be related or grouped for presentation, but are not destructively merged unless a stable, reviewed equivalence rule exists. Every underlying finding, source identifier, attempt, and evidence reference remains independently addressable.
- Automatic correlation, when offered, is a non-mutating suggestion with its basis, rule version, and uncertainty visible. The user can accept, dismiss, expand, or later ungroup it. A generic asset-plus-CVE match is only one possible signal, and similar output from two engines is not described as independent corroboration unless the retained evidence sources are demonstrably independent.
- Accepted active groups may reduce repetition in the beginner report, but the report keeps the original finding count and lets the user expand every member observed in the selected run. A group member not observed in that run is labeled as case history and remains independently addressable in case data and technical export; it is never inserted into the selected-run finding list. Removing a group changes presentation only and restores the independent list without deleting evidence or history.
- Upstream finding identifiers and evidence references are retained beside the normalized comparison key. A changed key version or insufficient coordinates makes a comparison `unverifiable`; the product never guesses that two findings are the same.
- A false-positive decision records actor, time, rationale, scope, and optional expiry. It never deletes original evidence and does not automatically suppress materially changed future evidence.
- Remediation advice never runs commands or changes the target automatically in the beginner product. Prefer reviewed rule-specific bounded guidance; when unavailable, label the generic expert-review fallback rather than presenting boilerplate as a verified fix.

### 9.4 Re-scan comparison

The user selects one terminal prior run as the baseline for a new comparison. The new run stores that baseline link with its requested scope before dispatch. When the comparison run becomes terminal, the product reports each prior/current finding as:

- `resolved` only when the responsible comparable check completed and no longer reproduced it;
- `persistent` when it reproduced, with evidence/severity/confidence changes disclosed;
- `new` when it was not present in the selected baseline;
- `unverifiable` when target scope, task completion, engine identity, evidence, or another required comparison condition is not comparable.

An unrun, failed, timed-out, or cancelled responsible task can never resolve a finding. Comparison persistence is idempotent and reconciled after restart. Advanced multi-baseline analytics may be deferred, but this honest single-baseline contract is part of reopening and checking fixes.

## 10. Beginner master report

Every run—including complete, partial, failed, timed-out, or cancelled runs—produces the same versioned beginner master report. This report is the default Results view and the default readable export.

### 10.1 Required first layer

Without opening Technical details, a user must be able to answer:

1. **What did I ask to scan?** Requested targets, stage, and limits.
2. **What was actually tested?** Exact completed target dimensions and time.
3. **What was not tested?** Not-tested, failed, timed-out, cancelled, excluded, truncated, or unavailable dimensions and why.
4. **What was found?** Prioritized findings with severity and confidence.
5. **What should I do next?** Plain-language, bounded next actions and suggested expert type.
6. **Is the report still changing?** Live/partial/final state and last durable update.

The report summary uses `complete`, `partial`, or `no checks completed`; it never uses a failed engine to turn the whole run into an opaque “Failed” page.

### 10.2 Coverage section

Coverage is shown by target and dimension, not merely engine count. It includes:

- requested and observed hosts, services, ports, URLs/paths, files/branches, accounts/resources, or other target-specific dimensions;
- quick discovery, inventory, and deep-stage status;
- tested complete, tested partial, failed, timed out, cancelled, not tested, and deliberately excluded counts;
- exact automatic reductions or limits;
- why a gap exists and whether Retry, Expand scan, Connect source, or Expert review is appropriate.

### 10.3 Technical evidence

Technical details include engine identity/version, image digest if used, command contract, runtime provider, timestamps, exit status, redacted scanner message, evidence hashes, cleanup state, and diagnostic log. These details support expert review and are collapsed by default.

### 10.4 Framework relationships

Findings/evidence may reference:

- NIST Cybersecurity Framework;
- ISO/IEC 27001 controls;
- the selected AIDEFEND framework version for applicable AI-system or AI-generated-artifact findings.

Relationships are navigational aids with a short rationale and mapping version. Missing mappings do not delete findings, and mapping failures do not block reports. The report states prominently:

> These references do not establish certification, compliance, control implementation, control effectiveness, endorsement, or a pass/fail result.

The product must not display “NIST passed,” “ISO compliant,” “AIDEFEND implemented,” or an aggregate compliance score. AIDEFEND references are an independent, unofficial mapping unless the framework owner states otherwise.

### 10.5 Export, redaction, signing, and verification

- Readable HTML/print and machine-readable master-report JSON are the default exports and work for partial runs.
- An export preview identifies sensitive fields, included evidence, exclusions, and redactions.
- Raw evidence is excluded by default when safe redaction cannot be guaranteed.
- Redaction replaces sensitive target labels with stable per-export aliases such as `Asset 1` and `Area 2`, preserving finding/evidence/coverage relationships without revealing the original identifiers.
- A locally signed portable case bundle and independent integrity verification are supported product capabilities. Failure to prepare the local integrity identity never blocks scanning or unsigned readable exports.
- A signed-export request may fail closed if its key cannot be trusted; the UI immediately offers an unsigned export with an explicit integrity limitation.
- Bundle verification proves hashes/signature consistency only. It never asserts that scanning was complete, correct, authorized, compliant, or performed by a legally identified person.
- Findings-only formats that cannot express coverage are paired with a mandatory coverage sidecar/manifest and warning. They are not disabled merely because another task failed.

## 11. Error, progress, and recovery UX

### 11.1 Plain-language error contract

Every user-visible error answers:

1. What could not be completed?
2. What useful work or data is already safe?
3. What will the product try automatically?
4. What can the user do next?

The first layer names the user task, not the failing component. For example, “The website check could not start; your code check is still running” replaces “egress gateway exited.” Stable diagnostic code, component name, command result, and redacted log remain under Technical details.

Warning/danger messages with a recovery action remain visible until the user dismisses them or the condition resolves; they are also retained in the project activity/diagnostic record. A transient auto-expiring toast alone is not an accessible error channel. Recovery is keyboard and screen-reader operable in both product languages.

### 11.2 Progress contract

Long work shows:

- current user task/stage;
- elapsed time and reasonable range, explicitly labeled as an estimate;
- completed and total known work, plus discovery that may change the total;
- last durable heartbeat;
- Cancel and background behavior;
- whether a partial report is already available.

If no durable heartbeat arrives within the task's recorded stale threshold, the product checks authoritative state automatically. Tests may inject shorter deadlines/heartbeats, but must prove the same deadline transition to Retry, partial, or terminal state. A local timer that only changes copy is insufficient.

### 11.3 No ghost data or demo fallback

In the installed native app, failure to load real data must never substitute synthetic demo cases. The UI preserves the last known real snapshot, marks it temporarily unavailable to refresh, and retries. Demo data appears only after an explicit demo action or in a clearly labeled browser development preview.

## 12. Case data, persistence, and migrations

- The case database, evidence, and export identity are outside disposable runtime generations.
- Case/run/task state changes and user-visible lifecycle events are committed atomically or made idempotently reconcilable.
- The durable event journal records meaningful transitions and supports missed-event recovery. A UI-derived timestamp list must not be labeled a complete event log.
- Schema migrations are ordered, transactional, restart-safe, and tested from N-1 with real serialized cases—not only empty schemas.
- Before a migration that can rewrite or drop durable user data, create and verify a bounded backup. Do not delete it until the new version reopens and exports the case.
- A single malformed case must not hide every other case. Quarantine the unreadable record, preserve its bytes, and show a recovery/export option.
- Reopening a project restores targets, requested scope, reports, coverage, findings, workflow state, and prior attempts. Expired authorization becomes a target-specific next action, not project loss.
- Optimistic concurrency conflicts trigger reload/merge guidance; they do not silently replace newer data.
- Applying the same execution checkpoint twice is idempotent only when the complete immutable report content—including exact artifact and finding sets, severity, confidence, evidence linkage, and normalized guidance—is equal. A regression fixture must first prove the existing changed/omitted-payload failure. The implementation then uses the smallest exact comparison, which may be one canonical payload hash rather than another field-by-field state machine. A changed or omitted finding conflicts for that task without blocking unrelated tasks.

## 13. Privacy, authorization, and destructive boundaries

### 13.1 Local-first privacy

- Code, credentials, raw evidence, findings, and cases stay on the device unless the user explicitly connects a source or exports data.
- Network requests are attributable to a selected target, provider sign-in, engine/image/update retrieval, or an explicitly documented product service.
- Credentials are short-lived, scoped, held in protected memory/storage appropriate to the provider, redacted from arguments/logs, and never passed to unrelated engines.
- The desktop webview, ordinary GUI fields, CLI, repository skill, agent interface, adapters, logs, and product-owned files never request, receive, or persist a provider password, long-lived access key, refresh token, client secret, administrator credential, or root secret. Provider sign-in stays on the provider-hosted surface.
- When a dedicated read-only identity must be created, an explicit Advanced action may invoke the separately packaged fixed-action bootstrap broker. Only that isolated broker may temporarily consume provider-issued administrative authorization; it never passes that authority to the scanner and returns only a case-, source-, engine-, target-, permission-, and expiry-bound read-only capability. This provider mutation requires its own exact disclosure and confirmation, but is never a prerequisite for non-cloud work.
- Password rotation is neither scanner authorization nor sufficient cleanup. The scanner and agent surfaces do not rotate credentials. Bootstrap cleanup is limited to the exact identities, roles, grants, keys, certificates, and sessions created or recorded by that operation; an unresolved item remains visible without blocking unrelated work.
- Technical logs exclude target names, asset identifiers, filesystem paths, credentials, raw evidence, and unbounded scanner output by default.

### 13.2 External scanning policy

- Passive public information may be gathered without contacting the target, but its sources and limits are disclosed.
- Low-impact direct checks require an exact target and the user's ownership/authorization assertion.
- Active or potentially disruptive checks require a separate explicit activity grant, conservative defaults, rate/concurrency/time bounds, and an obvious Cancel action.
- Redirects, DNS results, discovered neighbors, organization members, repositories, accounts, subdomains, or CIDR expansion never silently widen direct-contact scope.
- The product refuses clearly prohibited or unbounded targets/activities, explains why, and keeps local/reporting features available.

### 13.3 Destructive actions

Product-wide or workflow-wide hard blocking is reserved for an imminent irreversible mutation of user data or data not proven to be disposable product state. Before deletion the product resolves the exact target and explains recoverability.

An exact operation may also be blocked when continuing that operation would execute an untrusted package, contact a prohibited/undisclosed target, or claim a cryptographic signature that cannot be produced or verified. These operation-scoped blocks never disable unrelated installed functions, projects, reports, unsigned exports, or admitted engines.

Examples requiring explicit confirmation include deleting cases/evidence, purging all application data, or starting an active test beyond prior scope. Examples that should be automatic include rebuilding a verified disposable runtime, clearing a verified cache, retrying a download, or creating a new isolated runtime beside an ambiguous one.

## 14. Architecture constraints

The simplest architecture that meets the product rules is preferred.

### 14.1 Minimal durable product model

The shared durable model consists of:

- Project/case
- Target and requested coverage contract
- Scan run
- Target-stage-engine task and attempt
- Finding
- Evidence reference
- Coverage outcome
- Master report
- User-meaningful event

Infrastructure objects such as WSL distributions, Podman machines, gateways, image manifests, recovery receipts, ACL proofs, and release attestations remain behind runtime/release interfaces. They do not become parallel user lifecycle state machines.

### 14.2 Reconciliation model

- Durable database state is authoritative for user work.
- Live workers and runtime resources are observations reconciled into it.
- Frontend events are hints; startup/focus/resume/watchdog reloads make event loss safe.
- Shared dependencies are represented only where failure truly affects the same task group. They do not create global readiness for unrelated work.
- Long-running, restartable, externally side-effecting, or irreversible commands are idempotent or carry an idempotency key and persist the relevant transition before an irreversible side effect. Read-only and short in-process actions do not acquire lifecycle machinery without concrete evidence that it is needed.

### 14.3 Supply-chain boundary

Engine digests, provenance, release manifests, Authenticode, updater signatures, and artifact verification are important admission/publication controls. They apply at these boundaries:

- whether to publish or install a particular application package;
- whether to execute a particular engine image/helper;
- whether to apply a particular update;
- whether to call an export cryptographically signed.

They must not prevent an already installed trusted build from opening projects, displaying reports, exporting unsigned readable data, or running unaffected admitted engines.

### 14.4 Optional agent interfaces

Agent assistance is an optional transport over bounded typed product operations, not a separate authority, scanner implementation, or prerequisite for the desktop journey. It may guide installation/status inspection, explain redacted failures, and request an already supported export or exact cleanup inspection. It may not receive credentials, approve or widen scope, contact a new target, invoke an upstream scanner or arbitrary shell as a substitute for a product adapter, or remediate a target. Human authorization in the desktop/provider flow remains controlling, and failures stay task-scoped.

A universal MCP assessment-lifecycle server is not promised by this specification. If a future release advertises one, it follows the same typed backend, authorization, privacy, evidence, and degradation contracts. Its absence never blocks desktop development or publication of a channel that does not advertise that interface.

## 15. Test strategy

### 15.1 Order of evidence

1. **Real human path on installed Windows.** First value, understandable scope, partial report, recovery, and export.
2. **Rendered interaction/E2E tests.** Primary flows, lost events, restarts, accessibility, and bilingual behavior.
3. **Integration tests.** Installer/runtime fixtures, per-engine degradation, persistence/migration, reports, and exports.
4. **Unit/contract tests.** Parsers, normalization, fingerprints, mappings, redaction, provenance, and safety invariants.

Passing levels 2–4 never authorizes a claim that level 1 passed.

### 15.2 Required Windows qualification paths

One qualifying beginner human path on the exact installed candidate is mandatory before a Windows artifact is called beginner-ready or stable: clean Windows → combined localhost Start → master report → reopen → readable export. A public testing prerelease may be used to obtain that real-world evidence while its missing observation remains prominently disclosed. Signed bundle creation and independent verification are qualified on the real installed application as a separate integration/operator path; signer failure cannot invalidate the beginner path. A targeted additional human session is required only when a changed UI decision cannot be evaluated in the core path.

Real Windows integration/operator qualification—not a separate novice session for every fixture—covers:

- WSL absent, including restart when required;
- unrelated existing WSL distro;
- healthy existing product runtime;
- damaged/legacy product runtime;
- ambiguous similarly named runtime;
- N-1 ghost install with missing binaries/manifest;
- interrupted install/runtime setup and restart;
- same-version installer Repair and interrupted Repair;
- normal N-1 upgrade and supported downgrade/read-only fallback;
- app-only uninstall, remove-scan-tools/keep-projects, and explicit all-data uninstall.

Every successful install, Repair, runtime, compatible upgrade, and compatible downgrade qualification reaches the mandatory `127.0.0.1:9001` report, reopens the project, and exports a readable report. The only temporary exception is while Windows awaits an explicit required restart. An incompatible downgrade passes its safety qualification only when it refuses before changing binaries or data and the previously installed supported version then reopens/exports the unchanged project. The all-data uninstall path ends by proving exact removal rather than scanning. Automated fixtures may drive these scenarios, but retained evidence must come from the real installer/app/runtime boundary rather than a synthetic CLI-only shortcut.

### 15.3 Risk-focused automated qualification

Automated fixtures must target observed failure modes:

- lost progress/finish events and stale UI reconciliation;
- one engine/gateway/image failure with a successful sibling;
- cancellation and restart with partial evidence retained;
- exact requested-versus-executed scope disclosure;
- `/24` with 40 ports is automatically split into exact batches or requires an early explicit revised-scope choice; it never reaches the gateway as one over-budget unit or silently uses a smaller port list;
- ambiguous runtime preservation plus unique side-by-side creation;
- interrupted data/runtime migration;
- malformed single case without global data loss;
- partial-run master report and export;
- signing/mapping/updater failure isolated from scanning;
- no native snapshot-to-demo fallback;
- one corrupted installed managed-runtime file is never executed; bounded verified repair/reinitialization or automatic relaunch returns to the same project, or only dependent tasks become unavailable;
- one work unit succeeds and a later sibling fails without losing the earlier evidence;
- captured local work resumes while an unrelated cloud/network sibling becomes unauthorized;
- exporting run 1 after run 2 never borrows run-2 coverage;
- exact checkpoint replay is idempotent, while an omitted/changed finding conflicts only for that task;
- one shared target corpus passes through UI intake, Rust scope, launcher, and gateway, plus a packaged Windows route test proves `127.0.0.1:9001` means the Windows host rather than the scanner container.
- unknown/absent source severity remains visibly `needs review`, confidence provenance is shown, exact duplicates preserve every evidence reference, and related cross-engine observations remain reversible.

Source-text/regex tests can guard wiring but are not UX, installer, or recovery qualification.

## 16. Release acceptance and gate policy

### 16.1 Product acceptance

A beginner-ready or stable release is acceptable only when:

- the ten-minute first-value human path passes on the reference Windows setup;
- requested and executed scope are both visible and no tested gap is silently green;
- one optional engine failure still produces a useful partial report;
- app restart and one deliberately dropped event converge to truthful state;
- projects reopen and a readable partial/complete report exports;
- ambiguous runtime state is preserved while a new isolated generation continues;
- bilingual primary paths and baseline accessibility pass;
- no known path risks deleting unrelated/user data without explicit confirmation;
- the Windows candidate has a passing human-path record for the exact promoted build; beginner-ready/stable promotion cannot waive it with modeled CI evidence. A public testing prerelease remains explicitly outside this claim until the record exists.

### 16.2 Warning versus hard block

| Condition | Warning/degradation | Hard block allowed |
| --- | --- | --- |
| One engine unavailable, unqualified, or missing | Yes; skip that task and report gap | Only execution of that engine package |
| Runtime/gateway unavailable for some tasks | Yes; run independent tasks and save report | Only affected tasks after bounded auto-repair |
| Framework mapping missing/stale | Yes; findings remain | Never blocks scan/report |
| Export signing identity unavailable | Yes; offer unsigned readable export | Only the requested signed-export operation |
| Update signature/provenance invalid | Continue current version | Applying that update |
| Windows Authenticode unavailable | A public testing prerelease may offer the technically qualified artifact with a prominent “Authenticode not verified” warning | Stable or signed/recommended distribution of that Windows artifact |
| Platform artifact missing | Other platforms/channels may proceed with explicit support matrix | The missing platform artifact only |
| Scope partially unsupported or too large | Offer honest subset or revised scope | Starting undisclosed or prohibited activity |
| Product-owned disposable runtime corrupt | Automatic rebuild | Only mutation if ownership cannot be proven; side-by-side creation still proceeds |
| Ambiguous or unrelated data would be deleted/modified | Preserve and continue elsewhere | Exact destructive operation |
| Case/evidence deletion requested | Preview and backup/export option | Deletion until explicit confirmation |

Release workflows are separated into ordinary product CI, engine admission, platform installer qualification, and publication/signing policy. A publication requirement must not be smuggled into local scan readiness or ordinary documentation/UI CI.

## 17. Complexity budget

Every proposal that adds a gate, state, abstraction, recovery transaction, exact-hash coupling, or qualification must document:

1. a concrete reproducible harm it prevents;
2. evidence that the harm is plausible in a supported human path;
3. why isolation, preservation, warning, retry, or side-by-side replacement is insufficient;
4. which user jobs it delays or blocks and for how long;
5. new states, transitions, tests, maintenance owner, and removal condition;
6. how failure degrades without hiding results or harming data.

The proposal is rejected when the expected avoided harm is not greater than user friction and maintenance cost, or when a simpler reversible design provides the same protection. Name-only ownership, global readiness, unbounded waits, and exact release coupling across unrelated features are presumptively outside budget.

An implementation may add a hard block only when the safety decision in section 2.1 permits it and an acceptance test demonstrates both the harmful case and the non-harmful path that continues.

## 18. Scenario acceptance matrix

| Scenario | Minimum accepted outcome |
| --- | --- |
| Fresh Windows, WSL not enabled | No Terminal commands; supported Windows prompt/restart only; setup resumes and first-value report completes |
| Existing unrelated WSL distro | Distro/storage unchanged; new unique product runtime; scan completes |
| Healthy product runtime | Reused without Repair ceremony; scan starts |
| Old or partly damaged product runtime | Automatic side-by-side replacement or bounded repair; cases preserved |
| Similar name, ownership unknown | Old object untouched; unique new runtime; optional notice after continuity |
| Ghost install/missing manifest | Registry/name not treated as ownership; fresh isolated runtime; no manual removal |
| Install/setup closed or rebooted midway | Durable reconciliation resumes or safely abandons generation; no permanent preparing state |
| `127.0.0.1:9001` | Exact-port tested/closed/unreachable result and master report; no hidden port expansion |
| Public domain or website | Exact requested/executed hosts, addresses, ports, protocol, paths, redirects, and gaps disclosed |
| Internal `/24` | Exact address/port set and estimate shown; quick result first; incomplete hosts/ports explicit |
| GitHub repo/local code | Read-only selected snapshot; no push/upload; applicable code/secret/dependency results and gaps |
| AI application | Actual code/config/dependency checks named; only applicable AIDEFEND relationships; no model-safety claim |
| Some engines unavailable | Available siblings run; one partial master report; failed/not-tested tasks explicit |
| Cancel/fail/retry/restart | Saved results remain; cleanup background; retry only unfinished work; UI reconciles truthfully |
| Save/reopen/export/verify | Same project/report restored; readable partial export works; verification means integrity only |
| Compare with an earlier run | Explicit terminal baseline; resolved only after a comparable completed task; persistent/new/unverifiable remain honest after restart |
| N-1 upgrade | User data, identity, settings, unrelated WSL preserved; first-value scan still works |
| Same-version Repair | Binaries/resources/registration repaired; runtime and all user data preserved; interrupted Repair retains a runnable version |
| Downgrade | Compatible downgrade provides read-only reopen/export; incompatible downgrade refuses before mutation and the prior supported version reopens unchanged data |
| App-only uninstall | Target contact stops; binaries removed; managed/user data preserved; reinstall reopens/exports the same project |
| Remove app and scan tools | Target contact stops; verified disposable runtime/cache removed; projects, evidence, exports, settings, and signer preserved; reinstall rebuilds tools and completes a scan |
| Remove all product data | Exact confirmation; verified product data removed; ambiguous/unrelated data retained and disclosed |

## 19. Delivery order

Implementation follows user value and risk:

1. First-value path, non-destructive runtime isolation, durable reconciliation, per-task degradation, and no fake/demo state.
2. Staged scan value, honest scope, beginner master report, partial exports, simplified primary UX, and separation of fast product CI from engine/platform/publication qualification.
3. Advanced cloud/AI/Kubernetes depth, signed expert workflows, additional platform hardening, and optional specialist formats.

No later-stage feature or publication qualification may delay correction of a P0 first-value, permanent-state, data-safety, or all-or-nothing failure.
