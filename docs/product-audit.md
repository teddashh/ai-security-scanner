# Beginner product review

Reviewed: current source on 2026-09-10
Product behavior: [product-spec.md](product-spec.md)

This review asks whether a beginner can run useful upstream security checks and
understand one combined result. It does not decide versions, packaging,
publication, signing, certification, or compliance.

## Product outcome

One IT scan project accepts three common asset groups:

- repository folders;
- complete website or API URLs;
- approved internal systems identified by one exact hostname or IP address.

The user reviews the selected assets once and presses **Start scan** once. Each
scanner receives only the assets assigned to it. Completed sibling results stay
available when another check is unavailable or fails. Results and readable HTML
use the same unified report instead of sending the user to separate scanner
dashboards.

## Beginner path

| Step | Primary behavior |
| --- | --- |
| Choose | **Scan my IT environment** is the combined path. Website-only and project-folder choices remain shortcuts into the same project model. |
| Add targets | Add repeatable folders, URLs, and exact internal hosts. At least one of these scan-ready assets is required; inventory-only ranges may accompany it but cannot create a resultless project by themselves. Internal hosts start with common TCP ports; Advanced may replace them with up to 64 exact ports. No vendor, model, scanner, or rule selection is required. |
| Review | Show every target, the applicable security-check category, exact network boundary, important limits, and one Start action. |
| Run | Repository tools receive private read-only snapshots, Nuclei receives only selected website origins, and Greenbone receives only selected internal hosts and ports. |
| Read | Every selected asset is shown as problems found, no problems in completed checks, incomplete or failed, or not tested. Findings lead with impact and next action; upstream evidence remains available. |
| Continue | Saved projects, results, comparisons, and exports retain asset identity and incomplete coverage. |

Inventory and connectivity remain supporting facts. An open port, responding
HTTP service, successful process, or prepared runtime is not presented as a
vulnerability scan. A valid inventory CIDR is retained when a scan-ready asset
is also selected, while an inventory-only submission stays in setup with a
plain-language prompt focused on the first exact-host field. Malformed CIDRs
still receive their specific validation error before that scan-readiness check.

The collapsed project-details section is optional in storage as well as in the
screen. If the user does not choose an organization size, the case records
`Not provided`; it no longer silently invents the 2–49-person band. Existing
cases with a selected size retain their saved band.

Each of the three primary Home choices leads with the outcome and one maintained
timing target: a useful result within minutes after local tools are ready.
Scanner names, inventory boundaries, and per-route timing qualifications no
longer compete with the choice. The same single sentence appears in focused
Review and active Progress; exact scope and engine detail remain in the later
review or collapsed technical sections. Numeric ETAs remain unset until a
controlled installed run supplies measurements. Durable counts and per-check
outcomes continue updating in Progress, while Results and every export format
remain closed until the selected run reaches a terminal outcome. The terminal
report then shows concise per-asset results and keeps technical evidence in
collapsed detail.
Advanced paths without a maintained target and the localhost connection utility
keep the no-estimate presentation. The live activity card also names the saved
asset or assets bound to the current check. It prefers the run-bound report label
when recorded, does not show a queued sibling while another check is running,
and never substitutes an unknown technical asset ID for a missing label. A
compact first-layer summary separates fully checked, remaining, and
attention-needed assets, alongside completed, remaining, and attention-needed
checks. When a run is terminal, uncovered assets move to attention rather than
continuing to look active.

## What the common paths actually run

### Repositories

Selected folders are copied to bounded private read-only snapshots. Applicable
upstream tools inspect them for secret patterns, risky code, vulnerable
dependencies, infrastructure configuration, and component inventory. The app
does not modify, build, execute, upload, commit, or push the project.

The main repository route now uses Gitleaks and TruffleHog for secrets, 1,620
pinned upstream Semgrep security rules for risky code, Trivy and Grype for
recognized vulnerable dependencies, Checkov's upstream all-framework detection,
KICS for infrastructure configuration, and the shared report layer. Scanner
adapters preserve upstream identifiers and evidence instead of reimplementing
detectors.

The next managed Trivy image source is prepared to add checksum-pinned offline
JAR identification without replacing upstream detection logic. Trivy's
non-overlapping `filesystem` and `rootfs` library-package profiles preserve
both lockfile analysis and individual package archive or binary analysis. An
embedded Java index resolves otherwise unidentified JARs; the existing standard
database still performs vulnerability matching. Both JSON artifacts enter the
same adapter and retain separate raw provenance.

This source change is not deployed. The catalog still pins the published
`0.74.0-3` image, which has no Java index and covers repository/IaC package
manifests but not dependencies discoverable only from JAR contents. Its current
user-facing limitation remains correct until the product owner chooses a new
immutable image coordinate and activation. The OCI profile remains OS-only;
Grype continues to provide complementary OCI language-package coverage.

Repository ignore rules continue to prune ordinary ignored files and generated
directories, while common secret-bearing files such as `.env` variants, private
keys, registry/auth configuration, and `*.tfvars` remain available to the
upstream secret scanners. Ignored dependency, build, cache, and VCS trees are
not reopened.

### Websites

The beginner website path runs an exact pinned Nuclei automatic profile against
the displayed URL origin. The launcher mechanically admits 4,674 bounded
read-only templates from the pinned upstream snapshot; Nuclei performs its own
technology detection and selects matching checks. The pool includes 1,266 CVE
templates and 1,233 High or Critical templates.

It does not authenticate, submit forms or request bodies, follow redirects,
use out-of-band callbacks, run exploit-oriented checks, or expand to another
host. A completed scan does not imply that all 4,674 eligible templates ran;
upstream applicability determines the executed subset.

### Internal systems

The user enters one exact hostname or IP address. The default ports are 22, 23,
25, 80, 443, 445, 3389, 5900, 8080, and 8443; Advanced may replace them with up
to 64 exact TCP ports for that same host.

The product passes that scope to a pinned Greenbone Community Feed profile.
The launcher derives the profile from current, non-deprecated remote
`gather_info` VTs. Greenbone's upstream service detection, dependencies,
required keys, and required ports decide which checks apply. Product or vendor
names come from upstream evidence; they never choose a product-owned branch.

This profile supplies no credentials and excludes local security checks,
brute-force and default-account checks, policy/compliance families, Nmap NSE,
alternative port scanners, and active/destructive/denial categories. It never
adds a neighboring host or an undisclosed port.

Greenbone's result API does not provide a complete list of every scheduled VT
that actually executed. Positive findings retain their upstream OID, family,
severity, evidence, and solution. A zero-finding completion therefore means
only that the applicability-driven scan returned no findings for the displayed
ports; it does not mean that every VT ran or that the device is secure.

A host that Greenbone reports as not responding, and scanner errors on a host,
both appear as incomplete coverage for that host with a next action; neither is
presented as a clean result. An alarm whose pinned feed entry has no parseable
severity stays `Unknown`, with the missing upstream rating stated directly.

Previously saved single-service HTTPS, SSH, RDP, VNC, SMTP, and Telnet records
remain runnable with their original boundaries. They are compatibility data,
not the new setup model, and are not silently widened.

### Advanced Kubernetes node snapshots

The kube-bench build source no longer contains the product-authored six-check
benchmark that reused upstream CIS identifiers with different meanings. Its
next managed image is prepared to run the checksum-bound, unmodified upstream
CIS 1.11 node profile: all 26 upstream checks, identifiers, verdicts, evidence,
and remediation remain scanner-owned.

The thin offline adapter accepts five explicit files plus their original mode,
owner, group, and source path, and captured kubelet and kube-proxy command
lines. It validates the complete immutable inventory, replays only the `ps` and
`stat` forms used by that upstream profile, and never executes captured text.
Only the kubelet and kube-proxy configuration YAML is parsed. Metadata-only
files use non-secret placeholders; credentials, private keys, and real
certificates remain out of scope.

This source change is not deployed. The catalog still pins the published
`0.16.0-3` image with the older schema-1 six-check profile, and current UI copy
continues to describe that released boundary. The host reader accepts both the
released schema 1 and the strictly validated schema 2 so the eventual immutable
image switch does not erase existing cases. Image versioning, publication, and
activation remain product-owner decisions.

## Report behavior

The first layer answers:

1. What was selected?
2. Which assets have security problems?
3. What matters first and why?
4. What should be done next and how can the fix be checked?
5. Which requested work did not complete or was not applicable?

The report preserves upstream engine, rule or OID, original severity, location,
evidence, and remediation underneath the shared explanation. Product-owned
prioritization, deduplication, correlation, localization, and presentation stay
in this report layer rather than scanner wrappers.

Finding narrative now gives the result, possible impact, next action, rollback,
and verification directly. Specialist type remains a separate handoff field.
Unknown severity says the scanner did not rate the problem without handing the
interpretation back to the reader. Results stay closed while work is active;
terminal runs with unfinished coverage are labeled **Completed with gaps**.
Formal report terms and technical task records appear once, at the report end,
and HTML export uses the same ordering. Stored findings from older runs are
normalized into this contract when the authoritative report is built.

The supported CLI now follows the same rule. `doctor` reports runtime, engine,
cleanup, and checkpoint state directly. Planning, discovery, grouping, deletion,
engine retrieval, and cleanup responses use structured outcome fields instead of
appending defensive notice paragraphs.

Active product guidance now follows the same contract. Progress, runtime setup,
provider authorization, coverage entry, scan lifecycle, and application actions
state the current outcome and the next useful action without repeating
non-events, saved-state reassurance, implementation language, or responsibility
transfer. Required authorization and exact scope boundaries remain concise and
specific.

Report production now has one lifecycle value: **Final**. The report builder
rejects queued, preparing, running, or paused work; desktop snapshots include
reports only for terminal runs; every export path applies the same boundary.
Active work is represented only by Progress. Result, coverage, verification,
setup, and export copy state the recorded outcome and next action directly, and
older stored defensive prose is normalized before presentation.

The remaining desktop copy now follows the same direct contract. Saved-data,
update, setup, project, preview, verification, export, and correlation failures
name the outcome and next action without first-person excuses, delay language,
non-event reassurance, or implementation detail. Export integrity is one compact
fact; formal terms remain at the report end. Product guidance describes the app,
scan, or selected state rather than speaking as an AI assistant.

Observed services are listed separately from security problems. They do not
increase problem counts or receive remediation merely because a port answered.
"No problems" applies only to completed security checks and always keeps the
stated scope visible.

## Remaining product work

The high-value remaining gaps are:

1. Exercise a controlled installed-desktop mixed scan with repositories,
   internal hosts, and websites through progress, reopen, and readable export,
   after the user explicitly authorizes any missing runtime installation and
   provides exact authorization for owned network targets. A headless
   fixture-backed integration now proves the atomic three-way routing,
   orchestrator/adapters, partial sibling preservation, durable reopen, and
   shared HTML export; it does not count as a real scanner or installed-UI run.
2. Measure time to first useful finding and remove any remaining beginner input
   that does not change target scope or result quality. The known
   inventory-only creation dead end was removed in `d2599a1`, and the hidden
   organization-size guess was removed in `77c54fc`. `a94131a` makes the
   unmeasured minutes-level timing target visible without inventing a numeric
   ETA, `282d3fb` carries it through Review, and `4ad0759` preserves it during
   active Progress without treating the full run as complete. `00dc9a1` also
   surfaces the current check's saved asset labels, and `083040c` adds explicit
   asset/check completion, remaining, and attention counts. `137db23` keeps all
   active work in Progress, opens Results and Export only for terminal runs, and
   removes live-report caveats from the primary path. `cd0adda` gives Home,
   Review, and Progress one shared concise timing target and moves scanner and
   scope qualifications out of the primary choices. `b8bf318` makes the terminal
   report direct, moves formal terms to the end, and normalizes superseded stored
   narrative. `cbd6481` applies the direct-response contract to the CLI, and
   `502b70a` applies it to active Progress, setup, authorization, lifecycle,
   coverage, and application guidance. `acac84a` removes the live-report state
   from the Rust and TypeScript contracts, gates report construction and export
   on terminal work, and applies direct result wording throughout the shared
   report surfaces. `5dbdeff` completes the visible-copy sweep across the app
   shell, project setup, provider access, Progress, Results, verification, and
   export. The full sequence still needs observation in a controlled
   installed-desktop walkthrough.
3. Make an explicit product-owner decision before widening GCP Prowler beyond
   its reviewed four-check permission and endpoint closure. The other advanced
   AWS cloud paths do not hide a comparable product-authored security subset:
   ScoutSuite already delegates to its complete upstream IAM service, while
   CloudQuery's seven tables and Steampipe's fixed SQL are inventory evidence,
   not vulnerability checks.

The kube-bench and Trivy source replacements are complete but not deployed.
Immutable image versioning, publication, and activation remain owner-controlled
decisions rather than implied follow-up work.

Tests protect interaction, routing, parsing, and report contracts. They support
these product outcomes; passing a test suite does not make a narrow scanner
integration complete.
