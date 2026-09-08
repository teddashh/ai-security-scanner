# ai-security-scanner beginner-first product audit

Reviewed state: current working tree on 2026-09-08

Product source of truth: [Product specification](product-spec.md)

This is a product audit, not a delivery-policy review. It evaluates whether a
beginner can reach a real security result quickly and understand it. No target
was contacted and no scan was executed for this audit.

## 1. Current verdict

The product direction is now materially closer to its real job:

- Home leads with only the two shortest meaningful paths: checking a website or
  a project folder. Other sources and the localhost utility are secondary.
- Website setup takes one URL; a fixed Nuclei profile is ready for review.
- Local setup opens the folder picker immediately. One action creates the scan
  project and attaches its private snapshot; the displayed name is optional and
  can be derived from the folder.
- Tool preparation starts only after the user presses **Start scan** and the
  backend says the required runtime is unavailable. Its progress and cancel
  action stay in the main content on narrow screens; the expected transition no
  longer appears as a scan failure first.
- **My scans** opens active work at Progress, finished work at Results, and only
  an unstarted project at Review.
- A running scan can expose **View results** as soon as it has a saved security
  result; independent checks do not have to finish first.
- A TCP connection, open port, or responding HTTP service is no longer presented
  as a vulnerability or remediation priority.
- Live Results, saved reports, reopen, preview, and export share the product's
  report concepts instead of exposing disconnected scanner dashboards.

The remaining evidence gap is practical rather than documentary: this review did
not run an installed desktop build against a controlled website or project and
carry its real result through reopen and HTML export.

## 2. Decision criteria

Only four product decisions govern this audit:

1. A beginner quickly completes a meaningful security scan and understands the
   result.
2. Scanner integrations stay close to documented upstream behavior.
3. Scanner output becomes one professional report using product-owned
   prioritization, explanation, correlation, and presentation.
4. Product-owner delivery decisions remain outside this audit.

A meaningful scan requires a security, vulnerability, secret, dependency,
configuration, or exposure check. Form validation, tool setup, process success,
DNS, reachability, and one TCP connection do not qualify by themselves.

## 3. Current beginner journey

| Step | Implemented behavior | Remaining friction or limit |
| --- | --- | --- |
| Home | Website and **Code or AI project** scans are the two primary choices. Public or internal systems and other sources are under **More ways to scan**. The localhost tool is under **Connection utility (not a security scan)**. | A beginner chooses between two familiar starting points without hiding AI-project support. |
| Target | A website needs one complete URL. A local route opens the matching folder picker on the same page. Project naming is optional and safely derived when omitted. | Browser preview cannot read a real local folder; the desktop app is required. |
| Review | The exact target, important limits, included checks, and one Start action appear before technical controls. | A website quick scan is origin-wide; it is unsuitable when permission covers only one path. |
| Start | The app first attempts the requested scan. Runtime preparation begins only when that exact attempt returns `runtime_unavailable`, then resumes the same reviewed request after matching setup in the same UI context. If Windows restarts, the one eligible saved target is restored for review and the user presses Start again. | The real first-use preparation delay was not measured here. |
| Progress | Useful saved security results can be opened while other work continues. Runtime and scanner details stay secondary. | No real native run was observed here, so time to the first result is not established. |
| Results | Security problems lead with impact and next action. Reachability inventory has a separate neutral summary, three representative items, and a collapsed complete list. | Report usefulness still depends on a real applicable scanner completing against the selected target. |
| Reopen/export | My scans routes active work to Progress, terminal work to Results, and unstarted work to Review. Cases, reports, and export history are durable; readable HTML is the primary share format. | The revised full path was not exercised in an installed desktop app during this audit. |

## 4. Website quick scan

The guided public-website route now selects a fixed upstream Nuclei profile
instead of treating reachability metadata as the scan result. The user enters a
URL, reviews one explicit boundary, and uses one **Confirm and start** action.
They do not need to choose an engine, paste template IDs, provide a written
ticket, or complete a second ownership form.

The profile is intentionally concrete:

- engine: Nuclei;
- templates revision:
  `nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012`;
- 13 fixed templates for exposed credentials, published configuration, debug
  endpoints, source maps, status pages, metrics, and container build files;
- 3 requests per second, concurrency 2, and a 10-second request timeout;
- a displayed maximum of 19 GET requests for the fixed set;
- no redirects, login, form submission, file upload, fuzzing, callback,
  credential attack, denial of service, or exploit flow.

The target is the exact `scheme://host:port` origin. The entered path is retained
as context, while the reviewed templates request their own fixed paths on that
origin. Review states this before Start and tells a path-only-authorized user not
to use this profile. A zero-match result means only that these displayed checks
did not match; it is not a statement that the whole website is safe.

Private/internal website routes and general IP/domain routes keep their separate
bounded choices. The public-website shortcut does not silently broaden those
other paths.

## 5. Local-project scan

The product has a meaningful model for local work: create a bounded read-only
snapshot and run applicable upstream secret, code, dependency, and configuration
checks without modifying, building, executing, uploading, committing, or pushing
the project.

The current setup implements the short path directly: **choose what to check →
choose its folder → review and start**. The folder picker appears on the setup
page for source, AI, infrastructure-code, exported container-image, and
Kubernetes routes. In the desktop app, the same submit action creates the scan
project and attaches the exact snapshot. If snapshot creation fails, the product
keeps the created project and says the folder was not attached. During a large
copy, the form is locked against request changes, its purpose is stated plainly,
and the user may leave without being pulled back when copying finishes. If the
user remains on setup, Review opens so the folder can be retried without losing
the project.

No local project was scanned in this audit. Source wiring and automated fixtures
therefore do not establish that a beginner receives a useful first finding,
accurate unsupported-language or missing-manifest limits, and a readable export
from a real folder.

## 6. Results and report quality

The report layer now makes the important semantic distinction:

- Nuclei and other applicable detector matches can become security findings.
- Naabu `open_port` and httpx `reachable_http_service` records remain observed
  service evidence.
- Observed services are not included in problem counts, top priorities,
  remediation steps, or finding workflows.
- Their neutral next step is to confirm whether the service is expected and
  choose an applicable security check.
- Results summarizes their count and affected assets, shows at most three
  representative rows, and keeps the full evidence-bearing inventory collapsed.

For actual findings, the first layer presents what needs attention, affected
target, severity and confidence basis, impact, next action, verification, and
important untested scope. Original engine identity, rule ID, evidence, location,
and provenance remain available beneath that explanation.

Completed findings are preserved when sibling checks fail or continue. “No
problems observed” is limited to checks and scope that completed. A connection
test, setup success, cancellation, missing input, or scanner failure cannot turn
into a green security conclusion.

The built-in localhost utility follows the same rule in Results and HTML export:
Results says **Connection test only — no vulnerability scan ran**, while HTML
keeps **Connection test only** and **No vulnerability scan ran** visible before
technical detail. Both direct the user to a real website, project, or
protocol-aware check.

## 7. Upstream alignment

The useful product boundary is now explicit:

- upstream scanners own detection behavior, identifiers, versions, severity,
  evidence, and detector-specific remediation;
- adapters translate typed scope, invoke the documented interface, enforce
  bounded execution, and normalize results;
- the shared report owns cross-engine ordering, deduplication, correlation,
  beginner explanation, and presentation;
- safety and resource controls surround a scanner without becoming a replacement
  detection engine.

The fixed website profile follows this model: it selects reviewed upstream
templates and parameters; it does not reimplement their detectors.

## 8. Honest current limits

- First-use runtime preparation is correctly demand-triggered, but its real wait
  and time to first security result were not measured here.
- The curated website profile is origin-wide and cannot honor path-only permission.
- This audit did not execute a controlled target, observe a real scanner result,
  restart the installed app, or verify the resulting HTML export.
- Browser, component, adapter, and report tests can protect the interaction and
  data contracts; they cannot substitute for that observed native journey.

The current source is substantially more beginner-directed and more accurate
about what constitutes a finding. The exact installed-app experience against a
controlled website and a real local folder remains unobserved in this review;
that is an evidence statement, not a version or publication decision.
