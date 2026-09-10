# Current product review

Reviewed: 2026-09-10

Canonical behavior: [Product specification](product-spec.md)

## Product outcome

The desktop app provides one primary IT-environment path and two single-target shortcuts:

- combine multiple repository folders, website URLs, and approved internal systems in one scan;
- check one website or API origin;
- check one local project folder.

The user reviews the exact assets once and starts one run. Applicable scanners receive only their assigned assets. Completed sibling outcomes survive an independent check failure. Terminal results, reopen, comparison, and readable HTML export use the same report model.

## Beginner journey

| Stage | Current behavior |
| --- | --- |
| Home | Leads with IT environment, website, and project-folder outcomes. Advanced sources and localhost connectivity remain secondary. |
| Setup | Accepts repeatable folders, complete URLs, and exact internal hosts. Internal hosts receive common ports by default; Advanced can replace them with up to 64 exact ports. |
| Review | Groups exact assets, assigns applicable security checks, shows network boundaries, and provides one Start action. |
| Progress | Shows the active asset and check, confirmed problem count, completed, remaining, and attention-needed work. Tool preparation uses the same view. |
| Results | Opens only for terminal runs and gives every selected asset one result state. Problems, actions, coverage, and observed services remain distinct. |
| Export | Produces readable HTML and specialist formats from the terminal report model. |

Inventory-only input remains in Setup until a scan-ready asset is selected. The localhost TCP utility reports only connectivity. Results require a security-relevant upstream check or a terminal record that identifies the untested work.

## Repository checks

The app creates a bounded private snapshot and runs applicable upstream tools:

- Gitleaks and TruffleHog for secrets;
- Semgrep for risky code patterns;
- Trivy and Grype for vulnerable dependencies;
- Checkov and KICS for infrastructure configuration;
- Syft for component inventory.

Adapters preserve upstream identifiers, severity, locations, evidence, and remediation. Repository ignore rules remove generated, dependency, build, cache, and VCS trees while retaining common secret-bearing source files for secret inspection.

The prepared Trivy source adds checksum-pinned offline JAR identification through Trivy's standard Java index and vulnerability database. The published catalog image remains `0.74.0-3`; activating the prepared image requires a new immutable image release.

## Website checks

The website path runs pinned Nuclei automatic scan against the confirmed origin. Nuclei performs upstream technology detection and chooses matching vulnerability and exposure templates from the pinned read-only snapshot. Each selected website receives its own engine run, so one website failure does not remove another website's result.

The adapter distinguishes a completed non-match from an empty or failed execution record. Positive findings preserve the upstream template ID, severity, evidence, and remediation.

## Internal-system checks

Each internal system is one exact hostname or IP address with confirmed ports. The generic Greenbone profile derives current, non-deprecated, unauthenticated remote `gather_info` VTs from the pinned Community Feed. Greenbone controls service detection, product detection, dependencies, prerequisites, severity, evidence, and solution.

Only `alarm` records become vulnerability findings. Unrated alarms remain **Unknown**. Scanner errors and non-responsive hosts become incomplete asset coverage with a direct next action. Informational `log` records remain technical evidence. Saved legacy single-service profiles retain their original host, protocol, and port boundaries.

The updated Greenbone launcher source carries typed result semantics. The published immutable image still contains the earlier launcher; a new image coordinate activates the updated output contract.

## Advanced sources

Infrastructure files, Kubernetes manifests, exported container images, cloud accounts, and live clusters remain available as secondary sources. Each uses its selected artifact, resource, account, subscription, project, or cluster scope.

Prepared source updates for kube-bench replace the former six-check subset with the unmodified upstream CIS 1.11 node profile. The published catalog still points to `0.16.0-3`; a new immutable image coordinate activates the updated profile.

The Maester source preserves upstream `Investigate` as a no-verdict control instead of a failed finding. The published Maester image predates that wrapper update; a new immutable image coordinate activates it.

GCP Prowler currently uses its reviewed four-check permission and endpoint closure. Widening that profile requires one coordinated product decision covering checks, permissions, assets, endpoints, and report wording.

## Unified report

The first layer answers:

1. Which assets have problems?
2. What matters first and what is the impact?
3. What is the smallest next action and how is the fix verified?
4. Which checks completed for each asset?
5. Which requested work is incomplete or untested?

Findings retain scanner provenance under the product explanation. Cross-engine ordering, grouping, deduplication, localization, and framework references belong to the shared report layer. Observed services appear in their own non-vulnerability section. Formal report terms and technical records appear at the end.

Terminal runs include completed, completed with gaps, no checks completed, failed, and cancelled outcomes. Runs without a comparable completed check remain visible in Results and Export but are not offered as verification baselines.

## Current acceptance work

The next installed-product acceptance uses the published desktop installer to complete one controlled mixed IT-environment run through Setup, Review, Progress, Results, reopen, and readable HTML export. It records time from asset entry to the first useful security result.

Image-source updates enter a release only after their new immutable coordinates are published and selected in the engine catalog. GCP Prowler remains at its current reviewed scope until the wider product contract is selected.
