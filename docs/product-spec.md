# ai-security-scanner product specification

Status: canonical product behavior

This document is the sole source of truth for product behavior. Architecture, implementation, test, and operational documents may explain how, but they do not change the user outcome defined here.

A precedence banner is not enough to preserve alignment: a conflicting subordinate document or implementation is a defect to fix, not an alternative product direction.

## 1. Product direction

`ai-security-scanner` helps a beginner run a real security check and understand what to do next without first learning scanner tools, Linux, containers, or security terminology.

Four principles control product decisions:

1. A beginner quickly completes a meaningful scan and understands the result.
2. Scanner integrations stay as close to upstream behavior as practical.
3. All results become one professional, product-owned report instead of disconnected tool reports or framework views.
4. Versioning, publication, certification, and compliance positioning belong to the product owner. Existing work is preserved, but it is not an engineering priority or product prerequisite unless the owner explicitly asks.

The product succeeds when a user can say:

> I selected something I own, the product actually checked it for security problems, and I can see what matters, what to do, and what was not checked.

### 1.1 Primary user

The primary user is a Windows owner, developer, small-business operator, or IT generalist who:

- has little or no security-scanning experience;
- can identify a website, code project, service, or system they may assess;
- wants useful next actions rather than scanner output;
- may never have used WSL, Podman, containers, scanner engines, or a CLI.

Experts are secondary users. Their evidence and controls remain available through progressive disclosure and exports, but they do not define the first-run journey.

### 1.2 Core jobs

The product makes these jobs simple:

1. Check a website or API for common low-impact security problems.
2. Check a local project for risky code, exposed secrets, vulnerable dependencies, and unsafe configuration.
3. Check an explicitly selected local, public, or internal service.
4. Understand one prioritized report even when some checks do not finish.
5. Save, share, reopen, and compare results.
6. Add cloud, infrastructure-code, container, and Kubernetes sources only when needed.

The product is not a security guarantee, an aggressive penetration test by default, an automatic remediation system, a raw-scanner dashboard, or a compliance opinion. It never makes a beginner administer runtime infrastructure merely to use the product.

## 2. First meaningful value

### 2.1 What counts

A first result is meaningful only when at least one security-relevant check actually ran against the selected target or its selected read-only snapshot.

A meaningful result is one of:

- an evidence-backed security problem with an actionable next step;
- an evidence-backed statement that completed checks observed no problem in their exact scope, with important limits and a sensible next step;
- a partial report that preserves completed security checks and explains which checks could not run and how to continue.

A DNS lookup, ping, socket connection, open/closed port observation, runtime health check, target validation, or scanner download is preparation or inventory. By itself it is not a vulnerability scan, a security finding, or first meaningful value.

### 2.2 Recommended first paths

The home screen leads with two choices:

- **Check a website** — enter one complete URL and run a conservative, reviewed web-security profile.
- **Check a project folder** — choose one local folder and run a read-only code profile.

Other target types are secondary. A localhost connection test may remain as a diagnostic labeled exactly as a connection test; it must not be a primary scan action.

### 2.3 Interaction and time

The beginner path has three decisions:

1. Choose what to check.
2. Enter a URL or choose a folder.
3. Review the exact target and press **Start scan**.

The product derives a useful name from the URL or folder. Naming a project, adding an organization, choosing engines, or visiting a project-management screen is not required before the first scan.

The quick profile aims to show a durable security-relevant update within minutes. The UI shows an honest time range. Longer inventory and deeper checks may continue after the first useful result.

If tools need preparation, the product explains download size, expected wait, and any operating-system action in ordinary language. Preparation runs in the background, resumes after interruption, and never hides saved reports.
After preparation succeeds in the same uninterrupted UI context, the product
continues the same reviewed scan without asking for a second Start. It does not
reuse that request after the user leaves the page, changes projects, cancels
setup, starts other scan work, or restarts the app. If Windows or the app must
restart, the project returns to Review with its one eligible target selected;
the user reviews it and presses **Start scan** again instead of the product
persisting an automatic target-contact instruction across restart.

## 3. Beginner journey

### 3.1 Home and target setup

Without technical detail, Home answers what can be checked, which choice is recommended, what result it provides, and roughly how long it takes. Cards name outcomes rather than engines and have one primary action.

Setup asks only for the selected target:

- a website: one complete `http://` or `https://` URL;
- a project: one local folder selection;
- a public or internal system: an exact host, domain, or bounded range plus a concise ownership/authorization confirmation;
- an advanced source: only the information required by that source.

Validation is immediate, specific, and non-contacting. The product does not probe an external target merely to validate a form value.

### 3.2 Review and Start

One focused review shows:

- the exact target or snapshot;
- included security checks in plain language;
- expected time and important request or resource limits;
- the most important exclusions;
- one **Start scan** action.

Optional depth, rate, template, and engine controls are collapsed. Unchanged authorization is not requested twice.

### 3.3 Progress

Progress leads with what is happening, the first useful result, completed/remaining/attention-needed checks, elapsed time and range, supported controls, and one obvious **View results** action.

Scanner logs and runtime details remain collapsed. A completed useful check updates the report immediately; it does not wait for every independent check.

Tool preparation progress appears in the main content, including on narrow
screens. An expected missing-runtime response becomes this preparation state,
not a contradictory scan-failed message.

### 3.4 Results and export

Results open to the unified report. Important problems and next actions appear before technical metrics. A readable HTML report has one primary save action; JSON and specialist formats remain secondary.

## 4. Real scan semantics

### 4.1 Website and API

The recommended quick profile checks one exact URL origin: scheme, host, and port. The path the user entered is retained as context, but the profile may request a small fixed set of reviewed paths on that origin. Review states this before Start. A user authorized for only one path must not use the origin-wide profile.

The default profile performs a bounded set of GET requests for common exposed files, debug endpoints, and unsafe published configuration. Its scanner, pinned template revision, exact template IDs, rate, concurrency, request budget, and timeout are product defaults rather than beginner inputs.

It does not crawl other hosts, follow redirects, authenticate, submit forms or payloads, use exploit steps, or imply coverage of every page and API workflow. A zero-match result means only that the displayed fixed checks did not match.

### 4.2 Local project

The recommended profile creates a bounded read-only snapshot of the chosen folder and runs applicable upstream checks for:

- exposed secrets, with values masked in presentation;
- risky code patterns;
- vulnerable dependencies when supported manifests exist;
- unsafe application, deployment, and infrastructure configuration.

The product does not modify, build, execute, upload, commit, or push the project. Unsupported languages and missing manifests are visible limits, not clean results.

### 4.3 Local service

A connection observation answers only whether one address and port accepted a TCP connection, refused it, or did not answer in time. It is labeled **Connection test** and never becomes a vulnerability finding.

A local-service security scan identifies an applicable protocol and runs at least one protocol-aware security check. Otherwise the report says only connectivity was observed and offers a suitable real scan.

### 4.4 Public, internal, AI, and advanced targets

Public and internal scans contact only displayed approved targets and ports. Quick discovery identifies services; meaningful value begins when a service-aware or vulnerability check completes. Larger ranges are split into visible bounded work without silent sampling or truncation.

An AI application scan checks selected code, dependencies, secrets, prompts, configuration, and deployment files the product can inspect. It does not imply model-behavior or jailbreak testing unless those activities ran.

Cloud, IaC, container, and Kubernetes paths use exact selected scopes and read-only inputs by default. They remain advanced and never add setup to an unrelated website or project scan.

## 5. Scanner integration and execution

### 5.1 Stay close to upstream

The product prefers established upstream scanners over reimplementing detection. An integration:

- uses the scanner's documented interface;
- preserves upstream rule IDs, versions, severity, locations, and evidence;
- normalizes presentation without changing the underlying result;
- limits wrapper logic to scope, isolation, input preparation, parsing, cancellation, and resource bounds;
- pins versions when needed, then updates deliberately;
- tests against representative real upstream output.

Patches and forks are last resorts. Each maintained patch has a narrow reason, an upstream reference when available, and a removal plan. Safety controls belong around the scanner rather than in a long-lived fork whenever possible.

### 5.2 Independent outcomes

Each target/check task ends as queued, running, completed, completed with partial evidence, not applicable, could not run, or cancelled.

One unavailable scanner does not discard another scanner's findings. The task plan is saved before execution so failure still produces a useful explanation. Retry reruns compatible unfinished work unless the user starts a new scan with changed scope.

### 5.3 Runtime

Disposable scanner infrastructure is an implementation detail. The product prepares and repairs its runtime automatically, preserves ambiguous or unrelated system objects, and does not instruct beginners to run generic WSL, container, or cleanup commands.

Runtime availability affects only dependent checks. Existing projects, results, exports, and independent checks remain usable.

## 6. Unified professional report

Every run produces one report model used by live Results, final Results, reopen, preview, and readable export. It is professional because it is consistent, evidence-based, prioritized, and actionable—not because it mirrors an external framework.

### 6.1 First layer

Without opening technical details, the user can answer:

1. What needs attention first?
2. What could happen if I ignore it?
3. What is the smallest practical next step?
4. How can I verify the fix?
5. What exactly was checked and not checked?
6. Is the scan still running or final?

Each priority item shows severity, confidence, affected target/location, plain-language impact, next action, and verification guidance. Priority is transparent ordering, not a pseudo-precise score.

Reachability inventory such as an open port or responding HTTP service appears in a separate **Observed services — not vulnerabilities** section. It is not counted as a problem, placed in remediation priorities, or given a fix workflow merely because it shares the saved-result pipeline.

That section leads with the number of observed services, affected targets, and
a small representative sample. The complete inventory and evidence remain
available in a collapsed detail rather than displacing actual problems.

### 6.2 No-problem and partial results

“No problems observed” is limited to checks and scope that completed. It never means “secure.” Connection failure, missing input, scanner failure, cancellation, and untested scope are not green or passed.

A partial report preserves completed findings and places consequential missing coverage beside the relevant result, with one plain next action such as Retry, choose a folder, narrow the target, or ask a named specialist.

### 6.3 Evidence and one presentation system

The report retains original scanner identity, rule ID, version, severity, location, evidence reference, timestamps, and check outcome. Raw evidence, diagnostics, hashes, runtime detail, and advanced filters are collapsed by default.

Related findings may be grouped for presentation, but original observations remain accessible. Unknown severity or confidence stays unknown. Machine-readable exports derive from the same report model rather than becoming separate interpretations.

External framework references, when the product team wants them, are optional context after the actionable report. They do not start, block, rank, or complete a scan and do not define the roadmap.

## 7. Recovery, data, and safety

Errors say what could not happen, what work was preserved, whether the user must act, and one recommended next step. Technical detail is optional.

Events are refresh hints, not truth. Startup, focus, resume, and periodic refresh reconcile durable state. Cases, targets, runs, findings, reports, and export history survive restart. One damaged case is isolated; demo data never substitutes for failed native data.

Safety rules are concise:

- Network scans require an exact target and confirmation of ownership or permission.
- Local folders use bounded read-only snapshots; originals are not changed.
- Intrusive, credentialed, or scope-expanding activity requires a separate explicit choice.
- Credentials use official short-lived authorization where possible, never a generic password field.
- Cases and evidence stay local unless the user connects a source or exports them.
- Secrets, credentials, tokens, and personal data are redacted from normal presentation and logs.
- Cancel stops new target contact promptly and preserves completed results.
- The product never applies remediation automatically.
- Deletion identifies exact product-owned data and requires confirmation; unrelated or ambiguously owned data is preserved.

English and Traditional Chinese are first-class. Keyboard, screen-reader, focus, non-color status, and narrow-screen behavior cover the whole primary path.

## 8. Product acceptance and priorities

The strongest evidence is an observed user journey with an actual supported scanner and controlled target or fixture. Automated tests protect parsing, scope, adapter output, persistence, progress, reporting, and export, but do not replace the actual security-check result.

A beginner-path change is complete when the maintained product demonstrates:

1. URL or folder selection without unnecessary fields;
2. one focused Review and Start step;
3. at least one real security-relevant upstream check;
4. a durable unified report with an actionable result;
5. clear partial/no-problem language;
6. reopen and readable export without losing findings.

Connectivity-only fixtures prove connectivity handling, not vulnerability scanning. Component counts, build success, runtime health, and documentation do not prove first value.

Unless the product owner directs otherwise, work is ordered by user value:

1. Make website and local-project first scans short, real, and reliable.
2. Remove naming, project-management, runtime, and navigation detours before Start.
3. Deliver the unified actionable report as checks finish.
4. Improve recovery, speed, scanner coverage, and upstream currency for those paths.
5. Expand advanced targets without regressing the first two paths.

Version labels, publication ceremony, certification, framework mapping, and compliance positioning are outside this priority order unless the product owner explicitly requests them. Existing implementation and evidence in those areas remain intact.
