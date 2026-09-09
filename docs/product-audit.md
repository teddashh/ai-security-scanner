# Beginner product review

Reviewed: current source on 2026-09-08
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
| Add targets | Add repeatable folders, URLs, and exact internal hosts. Internal hosts start with common TCP ports; Advanced may replace them with up to 64 exact ports. No vendor, model, scanner, or rule selection is required. |
| Review | Show every target, the applicable security-check category, exact network boundary, important limits, and one Start action. |
| Run | Repository tools receive private read-only snapshots, Nuclei receives only selected website origins, and Greenbone receives only selected internal hosts and ports. |
| Read | Every selected asset is shown as problems found, no problems in completed checks, incomplete or failed, or not tested. Findings lead with impact and next action; upstream evidence remains available. |
| Continue | Saved projects, results, comparisons, and exports retain asset identity and incomplete coverage. |

Inventory and connectivity remain supporting facts. An open port, responding
HTTP service, successful process, or prepared runtime is not presented as a
vulnerability scan.

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
severity keeps `Unknown` severity for human review.

Previously saved single-service HTTPS, SSH, RDP, VNC, SMTP, and Telnet records
remain runnable with their original boundaries. They are compatibility data,
not the new setup model, and are not silently widened.

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

Observed services are listed separately from security problems. They do not
increase problem counts or receive remediation merely because a port answered.
"No problems" applies only to completed security checks and always keeps the
stated scope visible.

## Remaining product work

The high-value remaining gaps are:

1. Continue removing product-owned subsets from advanced cloud and Kubernetes
   paths where the current scanner invocation is narrower than upstream.
2. Add the pinned Java vulnerability database needed before Trivy can safely
   enable JAR scanning without turning an otherwise useful repository run into
   a fatal error. Grype already covers recognized repository language packages.
3. Exercise a controlled installed-desktop mixed scan with repositories,
   internal hosts, and websites through progress, reopen, and readable export.
4. Measure time to first useful finding and remove any remaining beginner input
   that does not change target scope or result quality.

Tests protect interaction, routing, parsing, and report contracts. They support
these product outcomes; passing a test suite does not make a narrow scanner
integration complete.
