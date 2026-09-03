# ai-security-scanner whole-repository product audit

Status: completed static product-design, UX, architecture, and specification audit

Documentation follow-up: the tracked current product-behavior documents have been reconciled to the canonical specification on this integration workline. Historical release-line notes are explicitly non-normative, and a low-cost CI contract check now verifies document authority, the highest-risk outcome-first decisions, and local links. A future contradiction remains a defect to remove, not an alternative requirement. Evidence that describes the pre-rewrite documents is explicitly pinned to the audit baseline below.

Audit baseline: `7e0f0de548bebf64dcfdc41d9b000f9e7a16fc4b` (`origin/main` at audit start)

Evidence convention: unless a reference includes another commit explicitly or is labeled as a post-audit documentation status, every unqualified `path:line` reference resolves against the audit baseline above. This keeps the report reproducible as implementation lines move.

Audit branch: `codex/v0.1.8-integration`

Date: 2026-08-29

Companion source of truth: [Canonical product specification](product-spec.md)

## 1. Executive verdict

The repository contains substantial work on isolation, evidence preservation, redaction, per-engine reporting, bilingual UI, and reproducible release artifacts. Those are useful foundations. The product nevertheless fails its primary beginner job because the same design error appears at every layer:

> The system tries to prove that the whole environment and every dependency are exactly correct before it accepts and preserves useful user work.

This premise produces a predictable chain:

- the installed app discovers WSL work only after installation;
- first launch can replace the product with runtime setup;
- ambiguous runtime ownership becomes a manual WSL task instead of a side-by-side runtime;
- global provider validation/reservation, static-input validation, gateway setup, or runtime readiness can block the whole scan before a run is saved, even though several missing-engine and post-dispatch failures already degrade per engine;
- one missed event can leave the UI in Ready/Repair/Running while no authoritative poll corrects it;
- partial evidence is fragmented or discarded even though the domain model can represent it;
- report, mapping, signing, and release proofs are treated as completion machinery rather than independent enhancements;
- modeled CI evidence is much stronger than evidence that a novice can install, scan, and understand a report.

The result is not “too secure.” It is less safe and less useful: users are pushed into destructive manual WSL advice, real data can be replaced on screen by demo data, the ordinary uninstaller can recursively remove app data without owning the runtime lifecycle, and failed preflight leaves no durable record that explains what happened.

The product direction should therefore retain isolation and exact deletion boundaries while removing global readiness, name-reclamation, version-specific recovery, and all-or-nothing execution. The rewritten canonical specification makes a target-stage-engine task the unit of failure, a beginner master report the unit of value, and side-by-side isolation the default recovery tool.

## 2. Method, scope, and limits

This was a read-only behavior audit followed by documentation-only rewriting. It inspected the entire repository at the stated baseline, including:

- `README.md`, `README.zh-TW.md`, product/architecture/runtime/threat/usability/release documents;
- React navigation, first-run, coverage, progress, findings, export, verification, localization, accessibility, and service adapters;
- Tauri commands, case service, storage, job manager, orchestration, external scope, runtime, gateway, export, mappings, and updater;
- Windows NSIS install/upgrade/uninstall and WSL/Podman lifecycle;
- engine catalog and external launcher behavior;
- SQLite persistence, restart/retry/reconciliation, finding normalization, report generation, and export formats;
- frontend, Rust, release, Windows qualification, AIDEFEND, and usability test/workflow structure.

The audit used `git`, `rg`, file/line inspection, and repository statistics. It did **not** install software, start an external or localhost scan, modify WSL, create/delete a runtime, rebuild an installer, invoke a release workflow, or claim that a modeled path worked on a real Windows machine. Findings that require runtime confirmation are explicitly written as acceptance tests, not as completed verification.

The scale of the current design is itself relevant evidence. Four runtime/execution files contain more than 46,000 lines (`managed_runtime.rs`, `managed_network.rs`, `case_service.rs`, and `commands.rs`), while the version-specific ghost qualification is more than 3,000 lines. Complexity is not automatically a defect, but here it correlates with duplicate state machines and recovery paths that still send the beginner to Terminal.

### 2.1 Priority and disposition

- **P0:** prevents first value, can create permanent false state, or risks user/unrelated data.
- **P1:** materially reduces scan value, report honesty, recovery, or primary UX.
- **P2:** advanced-path, maintainability, or release hardening after P0/P1.
- **Remove:** mechanism whose job is better served by preservation, isolation, or a smaller existing path.

Disposition is one of **Keep**, **Simplify**, **Merge**, **Automatic**, **Warning/degrade**, **Remove**, or **Defer/Advanced**.

## 3. The systemic error across layers

| Layer | Current expression of the premise | Evidence | Outcome-first replacement |
| --- | --- | --- | --- |
| Canonical requirements | Old spec led with case/provenance machinery and put packaged runtime last in implementation order | Baseline `7e0f0de:docs/product-spec.md:13-38,83-149,345-386` | Ten-minute installed-Windows first value is the first product gate |
| Installer | WSL is not prepared with installation; generic upgrades depend on successful prior uninstall | `src-tauri/windows/nsis/installer.nsi:332-426,601-691` | Detect/prepare prerequisites in the signed install flow; replace binaries while preserving data |
| First launch | Main shell is replaced by runtime setup and automatic setup is attempted once | `src/runtimeFirstLaunch.ts:25-31,41-51`; `src/App.tsx:541-565,1327-1351` | Open the product; prepare disposable tools in the background |
| Runtime ownership | Deterministic-name collision fails closed to manual WSL removal | `src-tauri/src/managed_runtime.rs:3106-3153`; `src/components/RuntimeSetupAssistant.tsx:183-191` | Preserve ambiguous object; allocate a unique new generation |
| Scan readiness | Whole plan must pass provider, input, runtime, and gateway checks before persistence | `src-tauri/src/commands.rs:1062-1083,1190-1209,1257-1277,2405-2433`; `src-tauri/src/case_service.rs:1843-1852` | Persist the run first; preflight and fail target-stage-engine tasks independently |
| Execution | External launcher makes multiple ports transactional and deletes earlier output after a later failure | `engines/images/external-launcher/main.go:218-283,355-371` | Durable per-unit/batch outcomes and partial evidence |
| State/UI | One post-subscription reconciliation; later status depends on events; timer does not reload truth | `src/App.tsx:601-683`; `src/pages/ProgressPage.tsx:713-723`; `src/scanActivity.ts:159-165,219-232` | Events are hints; startup/focus/resume/watchdog poll authoritative state |
| Persistence | One undecodable case aborts listing/recovery of all cases | `src-tauri/src/storage.rs:300-315`; `src-tauri/src/case_service.rs:1944-1947`; `src-tauri/src/lib.rs:155-178` | Quarantine one record and keep healthy cases available |
| Reporting | Findings, coverage, progress, HTML, framework JSON, and expert bundle are separate centers | `src/pages/FindingsPage.tsx:71-116`; `src/pages/ExportPage.tsx:179-264,499-516`; `src-tauri/src/case_service.rs:5952-6205` | One beginner master report for complete and partial runs |
| Export/signing | Bundle creation requires local signing identity; partial runs disable some formats | `src-tauri/src/export.rs:181-249`; `src/exportFormatEligibility.ts:9-26` | Readable unsigned export always; signing/format limitations affect only the requested enhancement |
| CI/release | Ordinary frontend CI runs release validation; release assembly fate-shares long global qualifications | `.github/workflows/ci.yml:16-35`; `.github/workflows/release.yml:650-810` | Separate product CI, engine admission, platform qualification, and publication policy |
| Human acceptance | At the audit baseline, the required study was unfinished and started with a nine-task AWS/IAM flow | Baseline `7e0f0de:docs/usability/iam-naive-first-run.md:1-11,36-67,90-124` | First study is install → localhost → master report in ten minutes; cloud is feature-specific |

## 4. Inventory of user-visible gates

These gates either stop a user job or incorrectly turn an independent limitation into a product-wide blocker.

| Gate | User job blocked | Current evidence | Required disposition |
| --- | --- | --- | --- |
| Prior install/uninstaller/ghost shape must match supported installer paths | Install/upgrade | `src-tauri/windows/nsis/installer.nsi:332-426,963-1099` | Simplify to version-neutral binary replacement/data preservation |
| WSL prerequisite checked after install | First launch/scan | `src-tauri/src/managed_runtime.rs:2433-2441,2534-2617` | Automatic signed Windows preparation |
| Full-screen runtime first launch | Enter product | `src/runtimeFirstLaunch.ts:25-31`; `src/App.tsx:1327-1351` | Remove overlay gate |
| Ambiguous deterministic WSL name | Prepare runtime | `src-tauri/src/managed_runtime.rs:3136-3145` | Preserve and create unique runtime |
| Point-in-time `runtime_health.available` | Start any scan | `src-tauri/src/commands.rs:1257-1277` | Remove global readiness; queue and reconcile |
| Duplicate ownership/permission ceremony | Add local/network target | `src/pages/CoveragePage.tsx:379-419,1940-1969` | One inline Start assertion for public/internal targets; reuse unchanged target/activity; no second ceremony |
| All provider demands valid | Start mixed scan | `src-tauri/src/commands.rs:927-953,1062-1083` | Per affected task |
| All static inputs and gateway artifacts valid | Persist run | `src-tauri/src/commands.rs:3844-3916`; `src-tauri/src/case_service.rs:1846-1852` | Persist then mark per-task outcome |
| Any resume grant/input/runtime mismatch | Resume independent work | `src-tauri/src/case_service.rs:2221-2424`; `src-tauri/src/commands.rs:1212-1254` | Resume compatible tasks; terminate others honestly |
| Pending exact cleanup | Cancel/finalize | `src-tauri/src/commands.rs:2565-2574` | Stop target contact within the task bound, acknowledge cancel, and leave only non-contacting cleanup as a background obligation |
| Signing identity required for case bundle | Export handoff | `src-tauri/src/export.rs:181-249` | Offer unsigned readable/bundle fallback |
| Every engine must complete for OCSF/OSCAL | Export saved data | `src/exportFormatEligibility.ts:9-26`; `src/pages/ExportPage.tsx:234-245` | Coverage sidecar plus warning |
| All platform updater entries present | Apply current-platform update | `src/services/appUpdater.ts:28-59,77-136` | Validate current platform; cross-platform completeness is publication policy |
| Authenticode/publication and global qualification | Publish any release artifact | `.github/workflows/release.yml:92-108,802-810` | Channel/platform-scoped publication gate; never local scan readiness |

The only legitimate hard blocks in these areas are the exact destructive operation on unproven/user data, execution of an untrusted package, undisclosed/prohibited external activity, or a requested signed artifact whose signer cannot be trusted. The rest should be automatic, isolated, or degraded.

### 4.1 Target and lifecycle coverage check

This compact inventory records the current semantics for paths not all represented by a separate finding. It is not a claim that those paths passed end-to-end testing.

| Path | Current implemented semantic and evidence | Gap / disposition | Verifiable acceptance |
| --- | --- | --- | --- |
| Localhost, website, public IP/domain | Intake preserves explicit URL scheme/port/path, but the target grammar and loopback meaning diverge later | Merge under A09; preserve exact redirect and host-route semantics | Shared corpus plus packaged `127.0.0.1:9001` Windows-host route test (`src/caseForm.ts:126-163`; `src-tauri/src/external_scope.rs:57-82,551-558`) |
| Internal host or `/24` | Same external-target model, guided preset, late endpoint budget | Simplify/stage under A08–A11; one inline assertion and exact batching | `/24 × 40` ports is exact-batched or revised before Start, never truncated (`src/pages/CoveragePage.tsx:949-967,1735-1740`; `src-tauri/src/managed_network.rs:433-447`) |
| Network rate, concurrency, timeout | UI and Rust share activity-class maxima, but effective values are under Advanced; gateway takes aggregate minima and caps connect timeout separately | Keep conservative preset/enforcement; disclose requested/effective pacing before Start and per run, never late-clamp invisibly | Lowered values are honored end to end; request rate, concurrency, connect/overall timeout, and any effective cap appear in scope/report (`src/pages/CoveragePage.tsx:292-295,916-966,1855-1860,2089`; `src-tauri/src/external_scope.rs:115-145`; `src-tauri/src/managed_network.rs:415-447,488-491`) |
| Local source / GitHub repository | Product captures a bounded local working-tree snapshot; GitHub URL/official connector is not an end-to-end path | Keep local read-only semantics; implement bounded GitHub snapshot or narrow the claim | Selected local snapshot remains unchanged; selected GitHub revision is pinned/read-only with no write permission (`src/pages/CoveragePage.tsx:181-213`; `src/caseForm.ts:252-255`) |
| AI application | Maps to the same repository snapshot and generic code/secret/dependency checks | Keep useful checks; disclose untested model behavior and make AIDEFEND only a finding relationship | Report names tested code/config dimensions and explicitly excludes jailbreak/model-safety claims (`src/useCases.ts:92-108,202-224`) |
| IaC | Bounded local Terraform/CloudFormation/JSON/YAML working-tree profile | Keep and simplify wording; no live-cloud implication | Exact selected snapshot and applicable file/check gaps appear in report (`src/pages/CoveragePage.tsx:215-226,265-267`) |
| Container image | Requires one exported digest-bound OCI layout and does not run/login to the image | Keep; do not imply registry or running-workload coverage | Exported layout stays unchanged and requested digest/coverage is reported (`src/pages/CoveragePage.tsx:227-238,268`) |
| Kubernetes | Accepts exported manifests or bounded node snapshot; normal path is not a live-cluster scan | Keep snapshot paths; move any credentialed live cluster to Advanced | Report distinguishes manifest/node snapshot from live cluster coverage (`src/useCases.ts:137-144`; `src/pages/CoveragePage.tsx:239-261,269-270`) |
| Cloud account | Provider login/discovery and manual/deployer-assisted identifiers share the Coverage journey | Defer manual bootstrap to Advanced; never block local/network/code | Non-cloud use never enters provider setup; configured provider scopes one read-only account (`src/components/ProviderAuthorizationPanel.tsx:103-148,1415-1627`) |
| Upgrade, ghost install, Repair | Installer is uninstall-first and contains predecessor-specific ghost machinery; packaged component failure can require reinstall | Replace with version-neutral binary repair and side-by-side runtime; see A18/A19 | Same-version Repair, N-1/ghost, and interruption preserve case/signing identity and old/ambiguous runtime bytes; only a verified compatible runtime reuses identity, otherwise a new generation runs (`src-tauri/windows/nsis/installer.nsi:332-426,963-1099`) |
| Downgrade and uninstall | Silent downgrade aborts; uninstaller has one broad delete-data checkbox and no runtime lifecycle hook | Preserve newer data/read-only export on downgrade; provide three exact uninstall choices | Downgrade never rewrites newer bytes; each uninstall choice proves exact preservation/removal (`src-tauri/windows/nsis/installer.nsi:471-509,582-599,836-944`) |

## 5. Findings

### A01 — Windows preparation is a second product after installation

- **Priority / disposition:** P0 — Automatic and simplify.
- **Problem:** NSIS prepares ordinary installer dependencies but does not prepare WSL. Runtime startup checks WSL only after installation and aborts before download; UI/manual guidance can require Terminal. A path/argument-constrained UAC flow exists but is compiled as test-only and waits forever for the servicing process, leaving duplicate “safe in tests / manual in product” behavior rather than a production-ready repair path.
- **Evidence:** `src-tauri/windows/nsis/installer.nsi:601-691`; `src-tauri/src/managed_runtime.rs:817-886,2433-2441,2534-2617,8947-9186,9273-9296`, including unbounded wait at `9160`; baseline `7e0f0de:docs/managed-runtime.md:195-215`; `src/components/RuntimeSetupAssistant.tsx:183-191,295-303`.
- **Real user impact:** A beginner believes installation finished, then meets WSL terminology, a separate repair project, restart/reopen loops, and destructive-sounding backup/removal instructions.
- **Wrong design belief:** Avoiding any product-initiated Windows servicing action is treated as more important than completing a normal signed installation.
- **Simpler behavior:** Use the signed installer for the exact product-defined Microsoft WSL install/update action under normal UAC, persist restart state, resume automatically, and call it “preparing scan tools.” No webview value selects executable/arguments/environment. Replace the test-only flow with a deadline, cancellation/restart outcome, and durable progress rather than reusing it unchanged.
- **Acceptance test:** Fresh Windows without WSL reaches the main UI and a `127.0.0.1:9001` master report without Terminal. At most one normal administrator approval is required; an OS-required reboot resumes automatically; a hung servicing process reaches Retry rather than waiting indefinitely.

### A02 — Ambiguous runtime ownership blocks instead of isolating

- **Priority / disposition:** P0 — Automatic; remove manual name reclamation.
- **Problem:** Runtime names are deterministic. A matching current-generation WSL registration without the exact expected proof fails closed, and the UI asks the novice to inspect/back up/remove it manually.
- **Evidence:** `src-tauri/src/managed_runtime.rs:8931-8945,3106-3153`; `src/components/RuntimeSetupAssistant.tsx:183-191,295-303`; baseline `7e0f0de:docs/managed-runtime.md:109-125`.
- **Real user impact:** An unrelated, copied, ghost, or interrupted distro can permanently prevent first value; following the advice can damage data the product deliberately refused to identify.
- **Wrong design belief:** The product must reclaim one deterministic name before it can operate.
- **Simpler behavior:** Never adopt or delete by name. Preserve the ambiguous registration and storage, allocate a unique per-install/generation name and provider home, then continue. Disclose the retained object only after service is restored.
- **Acceptance test:** Pre-create an unrelated distro using the expected name. Its registration GUID, `BasePath`, VHD hash, and sentinel remain unchanged; no unregister/export/import is invoked; a uniquely named product runtime completes the localhost scan.

### A03 — First launch hides the product and has no real ten-minute first value

- **Priority / disposition:** P0 — Remove gate; simplify journey.
- **Problem:** With no cases/runtime, the entire app shell is replaced by a setup screen. Product creation then requires project/company fields, coverage steps, another authorization step, and a separate progress view. There is no one-action localhost starter despite URL parsing preserving port `9001`.
- **Evidence:** `src/runtimeFirstLaunch.ts:25-31`; `src/App.tsx:1327-1351`; `src/components/RuntimeFirstLaunch.tsx:81-100,147-165`; `src/pages/CasesPage.tsx:676-689,957-966,1120-1125`; `src/pages/CoveragePage.tsx:336-450`; `src/caseForm.ts:126-163`; baseline README promise at `7e0f0de:README.md:23-27`.
- **Real user impact:** Users cannot understand the product or preserve their chosen target while a long internal task runs; the advertised three-step flow is not the real flow.
- **Wrong design belief:** Infrastructure must be fully ready before the user may enter the workspace.
- **Simpler behavior:** Always open New scan/Projects/Report. Provide “Scan a service on this computer,” prefill `127.0.0.1:9001`, auto-name the project, make organization optional, and prepare tools behind the selected task.
- **Acceptance test:** A novice using the installed build reaches a saved localhost report within the canonical ten-minute budget and never sees WSL, provider, gateway, manifest, or engine vocabulary.

### A04 — Whole-plan readiness prevents partial value before a run exists

- **Priority / disposition:** P0 — Simplify to per-task degradation.
- **Problem:** Before the run is persisted, provider demands are validated and then reserved, static input/gateway artifacts are checked at multiple layers, and one shared runtime readiness check can reject the plan. The planner can represent missing/unavailable engines as `not_executed`, and the orchestrator already converts several post-dispatch runtime/network/pull failures into per-engine reports, but the desktop preflight still prevents partial value for the global dependencies.
- **Evidence:** `src-tauri/src/case_service.rs:1633-1705,1818-1819,1843-1852`; `src-tauri/src/commands.rs:927-953,1062-1083,1190-1209,1257-1277,2405-2433,3766-3917`; independent post-dispatch failure at `src-tauri/src/orchestrator.rs:387-431`.
- **Real user impact:** One expired cloud capability or gateway defect stops local Gitleaks/Semgrep work, creates no durable scan, and leaves no honest partial report or event trail.
- **Wrong design belief:** Readiness is a property of the entire case and a failed dependency should never become a failed ScanRun.
- **Simpler behavior:** Persist the requested run and task plan first. Preflight each target-stage-engine task or true shared group, dispatch runnable work, and mark blocked work `not_tested`/`failed` with exact coverage.
- **Acceptance test:** In a mixed local-repository/network or repository/cloud case, break only the gateway/capability. Local engines finish, the affected task records a reason, and one partial master report opens.

### A05 — Event-driven status can remain permanently false

- **Priority / disposition:** P0 — Merge and automatically reconcile.
- **Problem:** The frontend performs one authoritative read after subscribing, then relies on events; subscription failure tells the user to reopen. The 30-second progress timer updates a clock but not the snapshot. Runtime controller state is process-local while backend, setup, and presentation define overlapping phases. Runtime operations can wait ten minutes (or legacy recovery for an hour), surface only the last server error, and show only broad “a few minutes” phases.
- **Evidence:** `src/App.tsx:601-683`; `src/pages/ProgressPage.tsx:713-723`; `src/scanActivity.ts:159-165,219-232`; `src/pages/CasesPage.tsx:289-296,1211-1218`; runtime limits/error detail at `src-tauri/src/managed_runtime.rs:41-48,6311-6331`; first-launch copy at `src/components/RuntimeSetupAssistant.tsx:88-91,128-139`; state duplication at `src-tauri/src/managed_runtime.rs:608-772`, `src-tauri/src/state.rs:22-57`, and `src/runtimeSetupPresentation.ts:13-44`.
- **Real user impact:** Missed events, sleep, restart, or a transient probe naturally produce Ready → Repair → Ready loops and stale Running states.
- **Wrong design belief:** Additional state projections and event subscriptions make state authoritative.
- **Simpler behavior:** One durable operation record with ID, stage, elapsed time/range, heartbeat/stale threshold, deadline, cancel boundary, retry, and timestamp. Events are hints. Startup, focus, resume, and watchdog reload/reconcile authoritative state on the canonical one-second/ten-second refresh contract; task-specific long deadlines remain visible and testable.
- **Acceptance test:** Drop progress/finished events, sleep/resume, hang a readiness probe, and kill the app in each setup/scan phase. Reopen/focus begins refresh within one second and reaches authoritative data or visible Retry/offline state within ten seconds; injected shortened task deadlines prove transition to Retry/partial/terminal—never indefinite Running/Ready/Repair.

### A06 — Native data-load failure silently becomes demo data

- **Priority / disposition:** P0 — Remove.
- **Problem:** Native snapshot IPC/DB failure returns a synthetic demo result, and the loading screen describes this as intended behavior.
- **Evidence:** `src/services/scanner.ts:313-321`; `src/App.tsx:1076-1085`.
- **Real user impact:** Real projects appear to vanish and be replaced by fake projects; a user may act on or export the wrong data.
- **Wrong design belief:** Showing any working screen is preferable to preserving truth.
- **Simpler behavior:** Demo data exists only after an explicit demo action or labeled browser preview. Native failure retains the last known real snapshot, marks refresh unavailable, and retries.
- **Acceptance test:** Inject one native snapshot failure with existing projects. No demo record appears; old data remains visibly stale; recovery returns to the same selected project.

### A07 — Ordinary uninstall can delete user data without owning runtime cleanup

- **Priority / disposition:** P0 — Redesign lifecycle before release testing.
- **Problem:** NSIS offers one “Delete app data” checkbox, deletes `%APPDATA%`/`%LOCALAPPDATA%` recursively, and has no managed-runtime hook. Exact runtime uninstall is CLI-only, while release qualification manually invokes it before NSIS, so the real human path is not tested.
- **Evidence:** `src-tauri/windows/nsis/installer.nsi:471-509,836-944`; `src-tauri/tauri.conf.json:56-60`; `src-tauri/src/bin/cli.rs:2090-2123`; desktop command registration `src-tauri/src/lib.rs:188-227`; modeled cleanup `scripts/release/qualify-windows-nsis-ghost-recovery.ps1:2648-2685`.
- **Real user impact:** A user can lose cases/evidence while a WSL/VHD runtime is left registered, or believe everything was removed when it was not.
- **Wrong design belief:** Recursive directory deletion is equivalent to application lifecycle cleanup.
- **Simpler behavior:** Offer three choices: app only (default); app plus exactly verified scan tools while keeping projects/settings/signing identity; or app plus all product data after explicit confirmation and backup/export option. Retain/disclose ambiguous state. A Settings action performs the same exact scan-tool reset.
- **Acceptance test:** Exercise all three choices across healthy, active, ghost, and ambiguous runtimes. App-only preserves all managed/user data; scan-tools removal preserves every project/evidence/export/preference/signing key; all-data never deletes before confirmation; unrelated/ambiguous WSL remains byte-for-byte unchanged.

### A08 — Repeated consent is friction without additional safety

- **Priority / disposition:** P1 — Simplify and merge.
- **Problem:** Adding a target is explicitly defined as not authorizing it; local folder snapshots still need a separate permission action; ownership checkbox/reference can be requested again; network setup handles targets one by one.
- **Evidence:** `src/pages/CoveragePage.tsx:379-419,478-486,1940-1969,1999-2015`.
- **Real user impact:** Even a user-installed local security scanner cannot scan the selected folder or exact home target until they discover a consent ceremony hidden in a different step.
- **Wrong design belief:** A second checkbox proves safer intent.
- **Simpler behavior:** Selecting a local folder authorizes read-only analysis of its product snapshot. Localhost needs no checkbox. For an internal `/24` or public target, the single Start action contains one concise inline ownership/authorization assertion and records target/activity/time; it is reused for unchanged scope. Separate confirmation is reserved for active, credentialed, expanded, or otherwise higher-impact activity.
- **Acceptance test:** Source code is folder → scope summary → Start; internal `/24` and a low-impact public target each use one inline Start assertion; backend retains the exact contract without a second hidden permission step.

### A09 — Target validation and localhost meaning are implemented four ways

- **Priority / disposition:** P0 for Windows-host loopback routing required by first value; P1 for the remaining grammar merge.
- **Problem:** Frontend intake and Rust external scope accept `localhost`, while the external launcher and gateway reject it; each layer has a different grammar. `127.0.0.1` also requires an explicit host-to-runtime routing semantic to mean “this Windows computer.”
- **Evidence:** `src/caseForm.ts:126-163`; `src-tauri/src/external_scope.rs:57-82,551-558`; `engines/images/external-launcher/main.go:446-454`; `src-tauri/src/bin/egress_gateway.rs:538-568,716-734`.
- **Real user impact:** A target can be created and approved, then fail only during execution. “localhost” may mean the scanner container rather than the user's host.
- **Wrong design belief:** Independent validators will remain equivalent and infrastructure-local loopback matches user intent.
- **Simpler behavior:** One shared canonical target corpus/contract. Product UI uses `127.0.0.1:9001` with an explicit host-loopback route and report semantics. Until that exists, reject unsupported aliases before saving.
- **Acceptance test:** The same target corpus runs through frontend, Rust scope, launcher, and gateway; every accepted target has one end-to-end meaning. A packaged Windows route test proves `127.0.0.1:9001` reaches the Windows host service rather than the scanner container.

### A10 — Scope can be reduced or rejected after the user thinks it is valid

- **Priority / disposition:** P1 — Automatic batching plus explicit disclosure.
- **Problem:** Guided CIDR presets truncate a common port list to fit a 10,000-endpoint budget, while advanced readiness omits the same calculation. A `/24` × 40 ports passes visible setup but exceeds the gateway limit. Exact ports/protocols and pacing are collapsed under Advanced settings. UI/Rust share nominal activity maxima, but the gateway takes aggregate minimum limits and separately caps connect timeout, so requested/effective behavior is not one first-layer contract.
- **Evidence:** `src/coverageGuidance.ts:41-57`; `src/pages/CoveragePage.tsx:292-295,916-966,949-967,1735-1740,1797-1861,1960-1962,2089`; `src-tauri/src/external_scope.rs:115-145`; `src-tauri/src/commands.rs:3804-3812,3920-3962`; `src-tauri/src/managed_network.rs:415-447,488-491`.
- **Real user impact:** Users believe they requested a useful `/24` scan but may receive a hidden smaller preset or a late infrastructure failure.
- **Wrong design belief:** A safe preset makes every accepted custom scope executable, and collapsed detail is sufficient disclosure.
- **Simpler behavior:** Compute the exact requested host × port work before Start, show it with a human-readable conservative pacing preset, and batch it automatically into independent reported units or ask for a smaller explicit contract. Advanced users may lower rate/concurrency/timeouts; every runtime clamp becomes an effective value in the report.
- **Acceptance test:** `/24` × 40 ports becomes exact batches or an early computed choice; every report names the hosts/ports attempted and omitted. Lowered rate/concurrency/timeouts are honored through gateway/engine, and requested versus effective connect/overall timeout is visible. No limit silently changes the scan.

### A11 — Internal discovery and duration do not support quick value

- **Priority / disposition:** P1 — Automatic and staged.
- **Problem:** Local network detection takes one candidate and still requires “Use target”; ambiguity falls back to manual CIDR. Product copy says it will not discover private addresses, and the network model exposes a fixed four-hour engine ceiling instead of quick discovery → inventory → depth.
- **Evidence:** `src/pages/CasesPage.tsx:752-754,840-897`; `src/useCases.ts:190-200`; `src/networkScanEstimate.ts:13-16,47-95`.
- **Real user impact:** A home user must understand CIDR/route choices and can start a long scan without receiving an early useful result.
- **Wrong design belief:** Avoiding helpful bounded discovery is safer than making the approved scope understandable.
- **Simpler behavior:** Prefill a single credible Wi-Fi/Ethernet `/24`, offer human labels when multiple adapters exist, then run quick displayed ports before full inventory/deep checks.
- **Acceptance test:** Single-NIC home Windows prefills the correct editable `/24`; multi-NIC shows recognizable choices; first durable discovery arrives quickly and full work continues with an estimate.

### A12 — Partial evidence is discarded inside one engine and resume fate-shares siblings

- **Priority / disposition:** P1 — Simplify execution granularity.
- **Problem:** HTTPX/Nuclei expand one grant into per-port units but write one final file and delete it unless all units finish. Resume also aborts on one missing grant, engine, target, authorization, or runtime even when another captured task is valid.
- **Evidence:** `engines/images/external-launcher/main.go:218-283,355-371`; `src-tauri/src/orchestrator.rs:516-533`; `src-tauri/src/case_service.rs:2221-2424`; `src-tauri/src/commands.rs:1212-1254`.
- **Real user impact:** A valid finding from port 443 disappears if 8443 fails; an expired cloud grant prevents adapting already captured local evidence.
- **Wrong design belief:** Multi-unit engines and mixed resumes are transactional all-or-nothing operations.
- **Simpler behavior:** Persist per-port/batch/task artifacts and completion coordinates. Generalize the existing per-engine release-incompatible outcome to scope, input, runtime, and authorization blockers.
- **Acceptance test:** Unit A succeeds and B fails: A's evidence remains, B is incomplete, report is partial, and Retry targets B. Captured local evidence resumes even when an unrelated cloud grant expires.

### A13 — There is no single truthful beginner report

- **Priority / disposition:** P1 — Merge and make default.
- **Problem:** Findings has honest incomplete copy, but coverage, run status, export, and framework relationships live elsewhere. Export defaults to specialist case bundle. Historical HTML selects findings by run but uses the mutable current coverage ledger.
- **Evidence:** `src/pages/FindingsPage.tsx:71-116`; `src/pages/ExportPage.tsx:179-264,499-516`; HTML generation `src-tauri/src/case_service.rs:5957-5985,6197-6204`; framework mismatch detection already exists at `src-tauri/src/exporters/framework_report.rs:701-711,758-785`.
- **Real user impact:** A beginner cannot answer “what was/wasn't scanned?” in one place, and an old run export can appear to have later coverage.
- **Wrong design belief:** Separate technically complete views add up to one understandable product.
- **Simpler behavior:** One versioned master report is the Results view and default HTML/JSON export for complete, partial, failed, cancelled, and timed-out runs. Persist run-bound coverage snapshots; label any current-ledger comparison explicitly.
- **Acceptance test:** All terminal outcomes render the same schema. Export run 1 after run 2 and verify run-2 coverage is never represented as run-1 coverage.

### A14 — Default redaction destroys report relationships

- **Priority / disposition:** P1 — Simplify redaction.
- **Problem:** The UI promotes readable HTML and enables redaction by default, but standard redaction gives every asset/coverage row the same placeholder, making tested and incomplete targets indistinguishable.
- **Evidence:** `src/pages/ExportPage.tsx:188-194,262-264`; `src-tauri/src/export.rs:981-1015`; `src-tauri/src/case_service.rs:5978-5985`.
- **Real user impact:** A privacy-preserving report is no longer actionable or internally consistent.
- **Wrong design belief:** Redaction requires removing relational structure.
- **Simpler behavior:** Generate deterministic per-export aliases (“Asset 1,” “Area 2”) and preserve finding/evidence/coverage linkage while removing original identifiers.
- **Acceptance test:** A two-asset redacted report distinguishes both aliases and links their findings/coverage correctly; sentinel names/paths remain absent.

### A15 — Signing and specialist formats gate preservation of available results

- **Priority / disposition:** P1 — Warning/degrade.
- **Problem:** Portable bundle creation loads/creates the signing identity before building output. OCSF/OSCAL are disabled unless all engines completed, even though partial findings can be saved with a coverage manifest.
- **Evidence:** `src-tauri/src/export.rs:181-249`; `src/exportFormatEligibility.ts:9-26`; `src/pages/ExportPage.tsx:234-245,329-354`; tests encode the gate at `tests/frontend/exportFormatEligibility.test.ts:49-86`.
- **Real user impact:** A local key defect or unrelated failed engine can prevent the user from preserving data they already have.
- **Wrong design belief:** Integrity enhancement or limited external schema is a prerequisite for useful export.
- **Simpler behavior:** Always offer readable unsigned HTML/JSON. Signed request may fail closed but immediately offers unsigned fallback. Findings-only formats include/link a mandatory coverage sidecar and explicit limitation.
- **Acceptance test:** Break signing and one engine: readable partial exports still work, specialist export cannot imply missing checks passed, and only signed output is unavailable.

### A16 — One malformed case can hide every healthy case

- **Priority / disposition:** P1 — Automatic isolation.
- **Problem:** `list_cases` deserializes every JSON document and returns on the first error; startup recovery uses that list and propagates failure. Database migration covers the current SQL shape/revision but does not isolate a bad document, and the legacy test uses a current serialized `AssessmentCase`, so it does not qualify actual document drift/corruption.
- **Evidence:** `src-tauri/src/storage.rs:88-164,283-315,636-674`; `src-tauri/src/case_service.rs:1944-1947`; `src-tauri/src/lib.rs:155-178`.
- **Real user impact:** One corrupt/old row prevents the entire application from opening, exporting, or repairing healthy projects.
- **Wrong design belief:** All cases can safely share one decode fate.
- **Simpler behavior:** Build list summaries from indexed columns, quarantine/preserve an unreadable document, continue healthy recovery, and offer raw recovery/export for the exact bad case. Make data migrations transactional with verified backup.
- **Acceptance test:** One valid and one malformed case start normally; the valid project opens; the malformed bytes remain unchanged and are identified without deletion.

### A17 — Runtime recovery code is larger and more dangerous than side-by-side isolation

- **Priority / disposition:** Remove.
- **Problem:** A large legacy transaction still exports, hashes, imports, quarantines, terminates, unregisters, and deletes WSL/provider state even though current startup already treats legacy observation as nonblocking. Commands and baseline documentation preserved two competing recovery models; the subordinate documentation is now aligned, but the executable recovery surface remains.
- **Evidence:** nonblocking legacy observation at `src-tauri/src/managed_runtime.rs:2523-2530,4963-4979`; destructive transaction `src-tauri/src/managed_runtime.rs:3726-4179` including unregister at `4026-4034,4111-4119`; command surface `1131-1163`; baseline conflicts at `7e0f0de:docs/managed-runtime.md:109-125` and `7e0f0de:README.md:236-242`.
- **Real user impact:** More data-sensitive paths, states, receipts, and tests remain available even though retaining the old object and creating a new one is safer and simpler.
- **Wrong design belief:** A prior runtime must be migrated/reclaimed rather than preserved.
- **Simpler behavior:** Remove export/import/quarantine/replacement and automatic legacy deletion. Retain old state, create unique current runtime, and offer optional advanced cleanup only when exact ownership exists.
- **Acceptance test:** Existing, ghost, ambiguous, and malformed legacy objects remain byte-for-byte unchanged while the current scan works; command trace contains no legacy export/import/unregister.

### A18 — Version-specific ghost and uninstall-first upgrade machinery does not scale

- **Priority / disposition:** P0 for ghost/stale registration that blocks install or Repair; P1 for general upgrade/downgrade hardening — Remove version-specific branches and simplify.
- **Problem:** Runtime and NSIS hard-code v0.1.7/v0.1.8 identities/receipts. Generic silent upgrade uninstalls first and aborts on missing uninstaller/surviving executable; name/publisher matching acknowledges possible false matches. Silent downgrade aborts without a data-preserving reopen/export contract.
- **Evidence:** `src-tauri/src/managed_runtime.rs:87-106`; `src-tauri/windows/nsis/installer.nsi:197-227,332-426,582-599,963-1099`.
- **Real user impact:** Every release invites another bespoke predecessor state machine; stale registry or missing uninstall binaries can block a safe reinstall.
- **Wrong design belief:** Every historical install shape needs an exact migration proof before replacing application binaries.
- **Simpler behavior:** Verify the exact product install directory, atomically replace binaries, preserve application data, repair stale registration, and delegate disposable runtime compatibility to version-neutral side-by-side generations. Same-version Repair follows the same preservation contract; downgrade opens newer data read-only/exports it or refuses only that operation without rewriting bytes.
- **Acceptance test:** Clean, same-version Repair, N-1, N-2, ghost registry, missing executable/uninstaller/manifest, interrupted Repair/copy, and downgrade all use version-neutral paths. The last runnable binary set, cases, evidence, settings, and signing identity are preserved. A verified compatible runtime may be reused; otherwise old/ambiguous runtime bytes stay unchanged and a unique generation is created. Downgrade never rewrites newer case data.

### A19 — One packaged-component verification defect disables managed scanning for the process

- **Priority / disposition:** P0 — Automatic repair; operation-scoped hard block only.
- **Integration status:** When the packaged component is missing or rejected, the current source first tries only the exact private installed copy selected by the current desktop build's independently embedded manifest SHA-256. That copy must pass the current management-contract, private-namespace, canonical-path, manifest, size, and per-file digest checks before it can reinitialize the manager; rejected packaged bytes are never used as the recovery source. On Windows, admission additionally requires exact protected current-user DACLs on `versions`, the manifest-derived install directories, manifest, and payload and rejects reparse points and hard links. Immediately before each private installed-bundle driver launch, the Windows guard rejects entries absent from the launch-time inventory, re-hashes every listed file through its retained handle, pins the checked canonical ancestor directory objects and stable listed-file identities, and holds those handles through process exit/output drain. Listed-file handles deny write/delete sharing; directory handles deny rename/delete of the checked directory objects but do not prevent same-user creation of a new child after the pre-launch inventory. A fresh NSIS install now also invokes one feature-gated, zero-input coordinator after installing binaries and registration but before first desktop launch. It ignores environment path overrides, rejects command-line path overrides, resolves only the real direct `managed-runtime` sibling of the installed CLI, requires that manifest to equal the digest embedded when the Windows CLI was built, acquires the fixed private-data lease, and uses the ordinary verify/copy/atomic-commit installation path without downloading an image or executing Podman, WSL, or a scan. Every helper absence, rejection, timeout, or malformed result is non-fatal; stale-registration, same-version Repair, and upgrade overlays skip seeding so existing private runtime bytes remain unchanged. Exact abandoned UUID staging directories do not consume the installed-version bound and are removed on the next locked install attempt, while similar unknown siblings are retained. The recovery warning contains only a fixed boundary/source, the admitted digest, and the original typed package-failure reason. If the exact copy is absent or fails verification, the product keeps the existing redacted, terminal, non-retryable admission outcome and leaves compatibility providers, independent checks, projects, reports, and exports available. This remains a bounded verified-cache slice, not complete A19: successful fresh NSIS seeding can provide the copy before first launch, but MSI, an unsuccessful/interrupted seed, registration overlays, installed-resource replacement, an authenticated same-version repair source, out-of-process repair/relaunch, same-user directory-write isolation, and installed-Windows artifact qualification remain open.
- **Problem:** If the packaged managed-runtime manifest/bundle fails startup verification and the exact private copy is unavailable or ineligible, the manager remains unavailable for the process. Execution falls back to user-installed compatibility providers, while scanner-issue UI directs a beginner to fetch/reinstall the latest release; the current cache slice does not repair the damaged application resource.
- **Evidence:** Admission and receipt at `admit_packaged_managed_runtime_with_recovery_digest` / `PackagedManagedRuntimeAdmission::recovery_receipt` in `src-tauri/src/managed_runtime.rs`; startup diagnostic in `src-tauri/src/lib.rs`; manager installation/fallback in `src-tauri/src/state.rs`; hidden coordinator and build-anchor tests in `src-tauri/src/bin/cli.rs`; fresh-only dispatch in `src-tauri/windows/nsis/installer.nsi`; staged-manifest-before-sidecar ordering in CI/release; source/provenance and mutation checks in `scripts/release/validate-windows-nsis-template.mjs`; recovery, abandoned-staging, and Windows pre-spawn guard tests in `managed_runtime::tests`; reinstall guidance at `src/components/RuntimeSetupAssistant.tsx:108-126,224-242`. These are source checks; the updated Windows NSIS initial-status qualification contract has not yet produced exact-candidate evidence.
- **Real user impact:** Without an eligible exact private copy, one missing/corrupt product-owned component can disable every managed engine until the user diagnoses versions and reinstalls, even though projects and the installer/cache may otherwise be intact.
- **Wrong design belief:** Failing integrity verification requires disabling the whole manager for the process and transferring recovery to the user.
- **Simpler behavior:** Never execute the unverified component. Repair it from a verified signed installer payload or bounded verified cache, then reopen/reinitialize the manager or automatically relaunch the app while preserving the selected project. If repair fails, disable only dependent tasks and keep reports/other functions available.
- **Acceptance tests:** With an exact verified same-version source available, corrupt or remove one packaged runtime file in an installed Windows fixture. The file is never executed; bounded automatic recovery or Repair/relaunch must restore an admitted component and return to the same project. Separately, make every eligible repair source absent, tampered, or wrong-version: none is executed, only dependent tasks become unavailable, and the same project plus its partial report and unsigned export remain usable. A safe fallback in the second fixture is not evidence that the required repair path in the first fixture exists.

### A20 — Runtime security qualification exceeds the useful trust boundary

- **Priority / disposition:** P2 — Simplify, retaining the final-namespace hard boundary.
- **Problem:** Runtime open verifies and holds the full ancestor chain to volume/share roots, rejecting unsupported/conditional ACEs and broad modeled grants rather than focusing on the private final product namespace.
- **Evidence:** `src-tauri/src/managed_runtime.rs:2174-2185,11976-11985,12239-12474`; baseline `7e0f0de:docs/managed-runtime.md:145-160`.
- **Real user impact:** The code rejects ACE classes commonly associated with domain, EDR, backup, or redirected-profile policy, so it may disable scanning even if a protected final directory can be safely created. This user impact is an inference pending the proposed real Windows policy fixture, not a verified field failure.
- **Wrong design belief:** Every ancestor must match a narrow model to isolate the product directory.
- **Simpler behavior:** Reject reparse/replacement attacks and foreign write authority at the final product namespace; treat unusual non-exploitable ancestors as diagnostics. Add a hard block only with a demonstrated path to replacing the final namespace.
- **Acceptance test:** Benign corporate/backup ACEs still scan; a reparse point or writable foreign principal on the product directory remains blocked.

### A21 — Navigation, progress, and transient errors expose the implementation lifecycle

- **Priority / disposition:** P1 — Merge; defer specialist views.
- **Problem:** Seven permanent primary views mirror case setup/progress/export/verification phases, the sidebar exposes runtime provider, and progress uses engine names without a reliable ETA or durable event log. Every toast, including actionable warning/error messages, expires after 5.2 seconds.
- **Evidence:** `src/components/AppShell.tsx:24-37,250-343`; `src/pages/ProgressPage.tsx:1102-1138`; `src/scanActivity.ts:126-217`; transient toast timer `src/App.tsx:306-310`.
- **Real user impact:** A novice must decide among Coverage, Progress, Results, Share, and Check fixes before understanding the one current next action; keyboard, screen-reader, or slower readers can lose recovery instructions.
- **Wrong design belief:** Exposing each subsystem/state makes the workflow clear.
- **Simpler behavior:** New scan, Projects, Report, Settings. Show contextual next action, user task, elapsed/estimate/heartbeat, and partial-report availability; keep engines/runtime under Technical details. Actionable warnings/errors persist until resolved/dismissed and remain in activity history.
- **Acceptance test:** Without instruction, novice participants identify start, result, and download locations; first-layer progress contains no provider/gateway/checkpoint terms. Keyboard and screen-reader users can complete the same English/Traditional Chinese recovery action after waiting longer than 5.2 seconds.

### A22 — Product claims exceed GitHub and AI scanning semantics

- **Priority / disposition:** P1 — Implement or narrow claims; Advanced for live integrations.
- **Problem:** Use cases promise repository/AI scanning, but guided input is a local folder/read-only snapshot; no native GitHub URL/official connector path appears in the coverage profiles. AI application currently maps generic code checks plus applicable AIDEFEND references, not model-safety behavior.
- **Evidence:** definitions/copy `src/useCases.ts:92-108,202-224`; local snapshot profiles `src/pages/CoveragePage.tsx:181-271,412-419`; repository construction `src/caseForm.ts:252-255`.
- **Real user impact:** A user expects to paste a GitHub repository or assess AI behavior and instead gets a folder picker or generic source scan.
- **Wrong design belief:** A marketing category and framework mapping make the target integration real.
- **Simpler behavior:** Add a bounded read-only GitHub snapshot flow or state “local folder” precisely. AI report must name actual code/secret/dependency/config checks and never imply jailbreak/model-safety or AIDEFEND implementation testing.
- **Acceptance test:** Public/private selected GitHub repo becomes a pinned read-only snapshot with no writes; AI report lists exact tested dimensions and explicit untested model/runtime dimensions.

### A23 — Cloud setup remains inside the shared journey instead of isolated Advanced

- **Priority / disposition:** P2 — Defer/Advanced.
- **Problem:** Provider setup requires IT handoff JSON, official login, discovery, and manual account/role/tenant/client/subscription identifiers. Cloud cards are folded on the Start page, but they still enter the same shared Coverage journey rather than a separately supported Advanced path. The repository ships no deployer-neutral OAuth client identity.
- **Evidence:** folded placement `src/pages/StartPage.tsx:236-239,367-378`; setup `src/components/ProviderAuthorizationPanel.tsx:103-148,1415-1627`; baseline `7e0f0de:docs/provider-authorization.md:3-11,88-160`.
- **Real user impact:** A non-cloud user encounters enterprise IAM ceremony; a cloud beginner cannot complete setup without IT/deployer work.
- **Wrong design belief:** A technically bounded IAM flow belongs in the universal beginner journey.
- **Simpler behavior:** Keep cloud in Advanced. With organization configuration, show one official sign-in and automatic inventory. Without it, generate one concise IT handoff; never affect local/network/code first value.
- **Acceptance test:** Non-cloud journey never sees provider setup. Configured cloud login requires no pasted secret/manual UUID form; unconfigured path clearly hands off without blocking other scans.

### A24 — Framework/provenance and release validation are coupled to ordinary product work

- **Priority / disposition:** P1 — Separate layers; keep mappings as warnings.
- **Problem:** Old canonical spec devoted core product detail to exact AIDEFEND/provenance/signing contracts. Ordinary frontend CI runs engine and release validators/self-test/evidence before frontend tests/build; Windows CI rebuilds a release-equivalent managed runtime/NSIS. Public release preflight and assembly fate-share global platform qualifications.
- **Evidence:** baseline `7e0f0de:docs/product-spec.md:151-227`; `.github/workflows/ci.yml:16-35,53-121`; `.github/workflows/release.yml:92-108,650-810`; mapping behavior/non-certification foundation `src-tauri/src/exporters/framework_report.rs:14-20,304-320,373-381`.
- **Real user impact:** UI/docs/product changes inherit unrelated release/image/provenance failures; mapping/signing issues appear more important than scan value.
- **Wrong design belief:** Maximum global qualification is one universal definition of product correctness.
- **Simpler behavior:** Separate product CI, engine admission, platform installer qualification, and publication. Mapping failure removes only relationships; Authenticode/provenance block only the affected signed/stable artifact claim, update, or engine. A technically qualified public testing prerelease may disclose missing Authenticode without claiming it passed.
- **Acceptance test:** A docs/UI change runs fast product checks without installer build; an AIDEFEND mapping failure leaves findings/report usable; an engine admission failure disables only that engine; invalid update never applies.

### A25 — Release evidence does not qualify the human path

- **Priority / disposition:** P0 acceptance strategy — Replace the primary gate, retain narrow data-risk tests.
- **Problem:** The only specified human study has no completed session and uses a nine-task AWS/IAM journey. Release does not enforce it; unit tests build a self-declared in-memory human record. Meanwhile N-1/ghost scripts silently install, seed synthetic CLI cases, manually clean runtime, and can occupy separate six-hour jobs.
- **Evidence:** baseline `7e0f0de:docs/usability/iam-naive-first-run.md:1-11,36-67,90-124`; `scripts/validate-usability-evidence.mjs:423-459`; `tests/usability/evidenceValidator.test.mjs:26-117`; `.github/workflows/release.yml:123-135,650-810`; `scripts/release/qualify-windows-nsis-upgrade.ps1:736-1095`; ghost cleanup `scripts/release/qualify-windows-nsis-ghost-recovery.ps1:2648-2685`.
- **Real user impact:** CI can prove exact modeled artifacts while a real novice remains stuck before scan or report.
- **Wrong design belief:** More machine-generated proof can substitute for a person completing the core job.
- **Simpler behavior:** Primary acceptance is installed Windows → main UI → `127.0.0.1:9001` → master report → reopen/export, observed and timed. Narrow automation remains for concrete data-loss, ambiguous-runtime, lost-event, and partial-engine risks. AWS is separate feature acceptance.
- **Acceptance test:** Preserve one redacted real-human record bound to the exact installed candidate. The participant did not build/contribute/rehearse, the facilitator does not take over, no Terminal/Linux knowledge is used, and first value arrives within ten minutes. CI simulations are reported separately and never labeled a human pass.

### A26 — Runtime/update history retains unrelated global coupling

- **Priority / disposition:** P2 — Simplify.
- **Problem:** Up to 32 runtime versions may be retained; reopening without an exact digest fails when multiple verified candidates exist; no general desktop cleanup exists. The updater requires all eleven platform entries even for one current-platform update.
- **Evidence:** `src-tauri/src/managed_runtime.rs:35,2219-2291,2760-2779`; desktop command list `src-tauri/src/lib.rs:188-227`; `src/services/appUpdater.ts:28-59,77-136`.
- **Real user impact:** Normal upgrades accumulate opaque state and unrelated Linux/macOS publication can hide a valid Windows update.
- **Wrong design belief:** Current-platform operation depends on retaining every historic payload and complete simultaneous platform publication.
- **Simpler behavior:** Keep current plus one rollback and any version actively referenced by a durable checkpoint; garbage-collect verified unused generations. Verify signature/URL/digest for the selected platform; keep cross-platform completeness in publication policy.
- **Acceptance test:** Multiple upgrades retain only justified versions and never block a new scan; signed Windows-only update is offered on Windows while invalid Windows payload is blocked without affecting current operation.

### A27 — Checkpoint replay may not prove the immutable finding payload

- **Priority / disposition:** P2 investigation — Add no architecture until a focused regression reproduces the gap.
- **Problem:** Static inspection indicates replay detection compares artifacts and finding identity tuples without obviously comparing the exact finding set or severity/confidence/title/remediation snapshot. The risk is plausible from the omitted set, but this audit did not execute a reproducer.
- **Evidence:** `src-tauri/src/case_service.rs:5273-5317,10789-10797`; immutable fields at `src-tauri/src/domain.rs:955-970`.
- **Real user impact:** If the focused fixture confirms it, adapter nondeterminism or stale replay could be accepted as idempotent and silently change/omit meaning.
- **Wrong design belief:** Identity coordinates may be treated as proof of full immutable content.
- **Simpler behavior:** First add one exact changed/omitted-payload fixture. Only if it fails, use the smallest equality fix—exact immutable sets or one canonical execution-report payload hash—rather than another field-by-field state machine.
- **Acceptance test:** Exact replay is idempotent; omitted finding or severity/confidence-only change is a conflict while unrelated tasks continue.

### A28 — Finding normalization is useful but too generic for trustworthy cross-engine decisions

- **Priority / disposition:** P1 — Keep the evidence model; simplify and make provenance explicit.
- **Problem:** Adapters build stable engine/rule/asset/location fingerprints, preserve evidence IDs, and keep severity/confidence separate. Exact same-fingerprint records merge evidence, but unknown severities fall to Informational, priority initially follows severity, and remediation text is generic. The UI supports severity/confidence/workflow and false-positive expiry, yet the model does not make a cross-engine equivalence rule or confidence provenance obvious to the beginner.
- **Evidence:** normalization/deduplication `src-tauri/src/adapters/mod.rs:2106-2178,2190-2239,2361-2417`; finding UI/workflow `src/pages/FindingsPage.tsx:343-370,723-779`.
- **Real user impact:** Distinct engines can look like duplicate truth, unknown source severity can look safely informational, confidence lacks an understandable basis, and boilerplate remediation does not tell a novice what smallest action to take.
- **Wrong design belief:** A stable hash and normalized label are sufficient to make findings comparable and actionable.
- **Simpler behavior:** Keep versioned fingerprints, upstream IDs, every evidence reference, separate severity/confidence, and expiring false-positive history. Relate cross-engine observations instead of destructively merging them unless a reviewed equivalence rule exists; show confidence source/limits; label unknown severity as unknown/review rather than low risk; replace generic advice with rule-specific bounded guidance where supported.
- **Acceptance test:** Two exact duplicates preserve both evidence references; two related cross-engine findings remain reversible; unknown severity is not green; confidence origin is visible; an expired false-positive does not suppress changed future evidence; remediation never executes a command.

### A29 — Baseline README first layers read like release and infrastructure contracts

- **Priority / disposition:** P1 — Rewrite first layer; move contracts to linked detail.
- **Problem:** At the audit baseline, both READMEs began with clearer benefits, but their first practical layer quickly became candidate/AuthentiCode status, detailed authorization contracts, managed-runtime/WSL behavior, catalog promises, and release evidence. Several statements also described runtime-before-work and duplicate authorization that the canonical journey removes. The English and Traditional Chinese README bodies are now rewritten; remaining product work is to make the implemented UI and installable journey match them.
- **Evidence:** baseline `7e0f0de:README.md:42-58,60-124,236-250`; baseline `7e0f0de:README.zh-TW.md:42-58,60-124,236-250`.
- **Real user impact:** A prospective beginner meets internal release/runtime policy before a download and successful first scan, while the advertised flow differs from the actual UI.
- **Wrong design belief:** Showing completeness, boundaries, and qualification machinery is the strongest first-page value proposition.
- **Simpler behavior:** Keep first-layer English/Traditional Chinese content to outcome, plain-language use cases, current download/quick start, three-step first scan, one example report, and language link. Move authorization, WSL ownership, engine manifests/provenance, qualification, and release blockers to second-level linked docs; keep limitations near the claim they qualify.
- **Acceptance test:** A reader with no repository context can choose/download/start and understand the first report from either README. Before expanding technical detail, no WSL ownership, manifest, provenance, or global release-gate vocabulary appears; both languages describe the same implemented journey.

## 6. Controls worth keeping

The rewrite is not a request to remove all safeguards. These mechanisms directly support user outcomes and should remain, with technical detail progressively disclosed:

- **Unknown is not green.** Existing incomplete/zero-finding copy is honest: `src/pages/FindingsPage.tsx:71-116`.
- **Partial export warning.** Active/incomplete runs can already be exported with a warning: `src/pages/ExportPage.tsx:48-57,385-394`.
- **Case/evidence deletion separation.** Exact case record and evidence deletion confirmation: `src/pages/CasesPage.tsx:740-749,1221-1230`; backend exact-path checks `src-tauri/src/case_service.rs:872-930`.
- **Atomic revision-CAS persistence.** Case write and event commit: `src-tauri/src/storage.rs:189-280`.
- **Finding/evidence separation.** Severity and confidence are distinct, evidence is engine/run bound, workflow history does not replace evidence, and grouping is reversible: `src-tauri/src/domain.rs:761-970`; reconciliation preserves stable fingerprints and run snapshots at `src-tauri/src/case_service.rs:5348-5423`.
- **Explainable contextual priority.** Case context can adjust ordering without changing severity, confidence, evidence, or authorization: `src-tauri/src/prioritization.rs:1-58`.
- **Per-engine post-dispatch failure reports.** Runtime/network/pull preflight can return failed execution reports: `src-tauri/src/orchestrator.rs:387-431`.
- **Exact DNS/address freezing without silent truncation.** `src-tauri/src/external_scope.rs:418-449`.
- **Honest duration language.** Estimate is explicitly minimum/conservative rather than false ETA: `src/networkScanEstimate.ts:47-95`.
- **Non-certification wording and AIDEFEND applicability.** `src-tauri/src/exporters/framework_report.rs:14-20,304-320,373-381`.
- **Integrity is not correctness.** Bundle verification limitation: `src-tauri/src/commands.rs:2717-2739`; self-asserted signature limitation `src-tauri/src/export.rs:365-378`.
- **Isolation defaults.** Rootless runtime, read-only inputs, no-new-privileges, bounded resources, exact egress scope, credential redaction, and no deletion by name alone remain valid.
- **Accessibility foundations.** Skip link, focus visibility, reduced motion: `src/components/AppShell.tsx:183-187`; `src/styles.css:87-100,3068-3075`.
- **Bilingual parity tests.** `tests/frontend/i18n.test.ts:32-44`.
- **Visible pause/cancel/resume controls.** `src/pages/ProgressPage.tsx:903-918,945-972`; authoritative event-loss reconciliation remains an open P0 in A05.
- **Gitleaks as an independently pinned engine.** The catalog uses a bounded Gitleaks adapter/image rather than making repository code choose arbitrary commands: `docs/engine-catalog.md:70`; `engines/catalog.json:1697-1805`.
- **VibeScan integration decision.** The repository correctly borrows its plain-language vibe-coding journey without distributing a revision whose arbitrary plugin commands, recursive cleanup, swallowed errors, and false pass mapping conflict with the product boundary: `docs/research/vibescan-evaluation.md:1-54`. This is a concrete irreversible-data/execution risk, not a speculative gate.

## 7. Disposition matrix

### Keep

- rootless isolated engine execution and exact egress scope;
- immutable evidence identity and source engine/version attribution;
- local-first storage, bounded redaction, and credential separation;
- unknown/incomplete distinct from no findings;
- per-engine terminal outcomes and preserved raw evidence;
- explicit active/external scope limits;
- case persistence, revision CAS, comparison, and integrity-only verification;
- NIST/ISO/AIDEFEND relationships with strong non-certification wording.

### Simplify or merge

- runtime health, setup, repair, and presentation into one durable reconciled operation;
- project creation, target selection, permission, and Start into one use-case journey;
- setup/progress/findings/export into one contextual project and master report;
- requested versus executed scope into one target coverage contract;
- engine, port, batch, retry, and resume into one target-stage-engine task model;
- installer upgrades into version-neutral binary replacement plus data preservation;
- redaction into stable aliases rather than repeated `[redacted]` rows;
- product CI, engine admission, platform qualification, and publication into separate policies.

### Change to automatic or warning

- WSL preparation, verified runtime repair, download resume, startup reconciliation, and stale-event reload;
- internal subnet suggestion and bounded batching;
- product-owned component repair;
- optional engine/gateway/mapping/signing/updater failures as task/feature warnings or degradation, while hard-blocking only the exact untrusted engine/update or untrustworthy signed-export operation;
- unreadable case isolation instead of global startup failure;
- framework-relationship and specialist-format limitations as mapping/format notices that do not redefine scan coverage.

### Remove / stop investing

- full-screen runtime-before-work first launch;
- native error → demo fallback;
- global scan readiness and pre-persist whole-plan runtime/gateway checks;
- manual WSL backup/removal as normal recovery;
- deterministic-name reclamation;
- legacy WSL export/import/quarantine/unregister replacement transaction;
- per-version v0.1.7/v0.1.8 ghost receipts and future predecessor-specific branches;
- duplicate frontend/backend/launcher/gateway target grammars;
- test-only prerequisite state that the product cannot invoke;
- separate framework report as the beginner product center;
- global platform completeness as a current-platform updater safety rule;
- a 3,007-line ghost qualification as a universal release blocker after side-by-side preservation replaces migration.

### Defer or place in Advanced

- manual cleanup of preserved ambiguous runtimes;
- manual provider IDs/role ARNs/tenant UUIDs and cloud bootstrap;
- OCSF/OSCAL and other specialist finding-only exports;
- exhaustive runtime provenance display and historical payload management;
- automatic finding-correlation suggestions and multi-baseline/analytics comparison workflows; keep the honest single-baseline comparison as a core project capability. Existing reversible manual groups remain optional presentation metadata, and accepted groups may simplify report handoff without becoming a first-value requirement;
- deep AI model/jailbreak testing until a real engine and target semantic exist;
- cross-platform/global release evidence packaging unrelated to the current supported beginner path.

## 8. Implementation sequence

### First batch — P0 first value, permanent state, and data safety

This is a P0 program, not one monolithic implementation goal. Start with one narrow vertical goal:

1. Open the main shell and remove native snapshot-to-demo fallback, preserving last-known real data with Retry.
2. Add the combined `127.0.0.1:9001` Start action and an explicit Windows-host loopback route using one shared target corpus across UI, Rust scope, launcher, and gateway.
3. Persist the run/task before runtime/gateway preflight, execute the localhost quick task when possible, and always create the same real/partial/no-checks master-report skeleton.
4. Reopen that project/report and reconcile a deliberately dropped event from authoritative state.

Acceptance for this first vertical goal is an installed Windows path with prerequisites ready: one actual localhost quick task reaches reachable/closed/timeout and a saved report within ten minutes, survives reopen, and never displays demo data. A zero-completed-task report is required fallback evidence but cannot pass first value.

Proceed in parallel or immediately afterward with the remaining P0 safety tracks; they must all pass before calling the Windows artifact beginner-ready or stable. A public testing prerelease may expose a technically qualified exact installer with the missing paths prominently disclosed:

1. Move fixed WSL detection/preparation into the signed install/resume flow; cover no-WSL and restart without Terminal or an installation rollback.
2. Replace deterministic-name/manual WSL collision handling with unique side-by-side runtime creation; do not execute legacy export/import/unregister. Removal of the legacy migration transaction remains open.
3. **A19 cache slice implemented in source on the integration line:** a missing or rejected packaged component is never executed. A fresh NSIS install attempts to pre-seed the exact build-anchored private copy before first desktop launch without making cache availability an installation gate; registration overlays preserve existing private bytes. The current desktop build may re-admit only that exact digest-anchored, fully verified copy; Windows source checks its exact installed-tree DACLs, performs a launch-time closed-inventory check, and pins the listed payload objects across process execution. Otherwise the failure produces no Repair/Retry loop and disables only dependent work while the shell and independent outcomes remain usable. MSI/failure paths, an authenticated same-version repair source, out-of-process installed-resource repair/relaunch, same-user directory-write isolation, and installed-Windows artifact qualification remain open.
4. **Implemented on the integration line:** the NSIS installer now uses a version-neutral ghost/stale-registration and same-version Repair path that replaces product binaries and registration without requiring an old uninstaller or inspecting runtime ownership.
5. Add authoritative startup/focus/resume/watchdog reconciliation for all scan/runtime operations; bound preparing/running states and stop target contact promptly on Cancel.
6. **Implemented in source on the integration line:** NSIS now offers app only; app plus verified scan tools while keeping projects; or all product data after a second irreversible confirmation. The fixed product coordinator stops exact target contact first, preserves ambiguous state, uses a pinned/leased bounded data root, and returns a redacted retained-state receipt. Source validation is not Windows installer qualification.
7. Replace the AWS/self-declared usability-evidence contract with the exact-candidate installed-Windows localhost beginner protocol. Bind it only to promotion of that Windows artifact; keep ordinary development/CI unblocked.

Focused fixtures currently cover lost-event reconciliation, transient stopped runtimes, ambiguous names, corrupt packaged components, gateway-dependent engine failure with an offline sibling, incomplete uninstall inventory, missing-root lease races, and linked runtime state. Windows junction fixtures are checked in but were not executed on the Linux implementation host. The version-neutral N-1 ghost source path has a static fixture for missing binaries, uninstaller, manifest, and ownership proof. No-WSL/restart, all three real uninstaller choices, data preservation/reinstall, and an installed localhost completion remain Windows acceptance work; they must not be described as qualified before those exact human paths run.

### Second batch — P1 scan value, partial results, report, and primary UX

1. Introduce the target-stage-engine task/outcome model for start, timeout, cancel, retry, restart, and resume.
2. Add requested-versus-executed coverage and quick discovery → full inventory → deep scan.
3. Preserve per-port/batch evidence and automatically batch `/24` work without silent truncation.
4. Build the beginner master report and make HTML/JSON the default results/export.
5. Persist run-bound coverage; add stable redaction aliases; make signing/mappings/specialist formats independent enhancements.
6. Merge navigation to New scan, Projects, Report, Settings; remove duplicate consent and expose plain-language progress/ETA/heartbeat.
7. Isolate malformed cases and qualify N-1 user-data migration/reopen/export.
8. Align GitHub and AI use-case claims with actual end-to-end target semantics.
9. Make severity/confidence provenance, finding identity, false-positive expiry, and rule-specific bounded remediation understandable without destructive cross-engine merging.
10. Keep the now-rewritten README first layers aligned while rewriting remaining UI copy around outcomes/use cases/quick start; runtime/release contracts stay in linked detail.
11. Separate fast product/docs CI from engine admission, platform installer qualification, and publication/signing policy.

### Third batch — P2 advanced features and release hardening

1. Move cloud bootstrap/manual identifiers and specialist formats to Advanced.
2. Simplify final-namespace ACL qualification based on demonstrated replacement risk.
3. Bound retained runtime versions and current-platform updater validation.
4. Run the checkpoint replay reproducer; add one canonical payload equality mechanism only if it proves a real gap. Keep multi-baseline/manual comparison analytics Advanced while preserving basic single-baseline comparison.
5. Harden optional cross-platform publication evidence without fate-sharing unrelated channels/artifacts.
6. Expand targeted human studies to cloud, internal `/24`, GitHub/private repo, and AI application only when those UI decisions need human evidence after the first-value path passes.

## 9. Acceptance of the rewritten specification

The canonical specification now explicitly defines:

- the novice Windows north star and non-goals;
- the full beginner journey and four-destination information architecture;
- the ten-minute installed-Windows `127.0.0.1:9001` first-value gate;
- isolation/ownership/repair/upgrade/reset/uninstall behavior and a clean/existing/legacy/ambiguous/ghost/interrupted decision table;
- honest semantics for localhost, websites, public domains/IPs, internal `/24`, GitHub/source, AI, IaC, images, Kubernetes, and cloud;
- quick discovery, full inventory, and deep-check stages;
- per-task failure/timeout/cancel/retry/restart with partial results;
- one beginner master report with requested/executed coverage, findings, severity/confidence, next steps, evidence, mappings, and non-certification wording;
- privacy, authorization, external scan, and destructive-action boundaries;
- human-first testing, warning-versus-hard-block policy, and a complexity budget.

Architecture, managed-runtime, threat-model, provider, engine-catalog, release, cloud-usability,
README, contributing, security, third-party, mapping, and research references have received an
outcome-first consistency pass. Their body text now defers product decisions to the canonical
specification instead of defining competing readiness, recovery, framework, engine, or release
rules. Historical release notes preserve what an old version claimed or did, but are labeled
non-normative and must not be copied into current implementation. The repository's focused
document-contract test checks those authority declarations, high-risk product decisions, and local
links on every ordinary CI run. Baseline contradictions remain audit evidence through commit-pinned
citations; they are not current requirements. Machine-readable contracts and production code still
reveal implementation gaps; those gaps cannot silently redefine the intended behavior.

This audit does not assert those requirements are implemented. It makes their absence explicit and gives the next goal a bounded P0 starting set.

## 10. Validation performed and not performed

Performed for this audit:

- repository branch/HEAD/worktree inspection;
- whole-repository static search and file/line evidence review;
- cross-check of canonical spec against frontend, backend, runtime, installer, reporting, storage, tests, and workflows;
- current subordinate-document authority, outcome-invariant, historical-label, and local-link checks;
- all low-cost `tests/ci/*.test.mjs` checks, including the document contract and agent-skill parity;
- Markdown structure/content checks and `git diff --check` after writing (recorded in the final handoff).

Intentionally not performed:

- dependency installation or full frontend/Rust suites;
- Windows/macOS/Linux build;
- installer or managed-runtime build/qualification;
- WSL, Podman, VHD, gateway, or runtime mutation;
- localhost, internal, public, cloud, repository, or AI scan;
- release workflow, release publication, tag, or merge;
- hash, signature, provenance, or human-usability claims.

The missing runtime/human tests are not a gap hidden by this report; they are the first acceptance evidence required by the next implementation goal.
