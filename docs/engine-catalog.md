# ai-security-scanner engine catalog

Status: v0.2.0 catalog companion and research inventory; 19 artifacts are currently runnable. The ScubaGear and Maester wrapper-hardened images were published and independently verified at `1.8.0-3` and `2.0.0-3`, then withdrawn from the catalog when their wrappers changed; `-4` is awaiting publication.

Last updated: 2026-09-04

Normative status: this catalog is subordinate to the [canonical product specification](product-spec.md). Engine admission may block execution of that engine artifact only; it does not define whole-product scan readiness, reporting, or release acceptance.

This document explains the v0.2.0 planned engine set and records supporting repositories named in the product design. The machine-readable [`engines/catalog.json`](../engines/catalog.json) is authoritative for an engine's exact source revision, image digest, integration status, runnable state, blockers, provider applicability, knowledge window, and license disposition. It is not authoritative for product-wide readiness: this prose never upgrades a non-runnable entry, proves publication, or turns that entry into a gate for sibling engines and the beginner master report.

Cataloged-engine license identifiers and dispositions summarize the exact pinned artifacts recorded by the catalog and engine plans. Research-only identifiers were observed from upstream repository metadata on 2026-08-24 and still require evaluation before use. Every different source revision, dependency set, plugin, rule, template, feed, database, or image requires a new disposition rather than inheriting an earlier release decision.

## 1. Catalog states

- **Planned:** the v0.2.0 plan intends to support this engine or engine family through the full case lifecycle. This planning label does not make its availability a global product or release gate.
- **Integrated and runnable:** the catalog records `status: integrated`, `compatibility.runnable: true`, no blockers, an exact `sha256:` artifact digest, and a completed `allow` or `source_offer` disposition. Validation rejects execution/distribution of an exact entry that lacks those conditions; the product may still ship with an explicit support matrix and that task reports `not_tested` while independent work continues.
- **ALLOW:** the engineering plan records `allow` for the exact project-managed artifact with its license texts, notices, and dependency obligations; this is not blanket legal advice.
- **SOURCE_OFFER:** the engineering plan records copyleft corresponding-source material and a source-offer path for the exact project-managed artifact.
- **UPSTREAM_PINNED:** the product retrieves an exact verified upstream image by digest rather than republishing it as a project-managed image. Its license and notices still apply.
- **Research:** the repository remains available for evaluation but is not a v0.2.0 adapter commitment.
- **Blocked or non-runnable:** the catalog condition prevents execution, distribution, or promotion of that exact engine artifact only, regardless of any friendlier wording in this document. Independent tasks and readable reports continue.

An upstream source checkout is research material. It does not make an engine installed, integrated, safe, supported, or redistributable.

### Product orchestration contract

Planning persists the run and known target-stage-engine tasks before image, runtime, gateway, credential, or engine preflight. Each entry therefore resolves independently to runnable or a named `not_tested`/failed outcome. Quick discovery may open the report before inventory/deep engines finish. One missing, stale, incompatible, unlicensed, unpublished, or failed engine never erases sibling results or prevents the same complete/partial/no-checks master report and readable unsigned export. Requested and executed engines, hosts, ports, paths, and stages remain explicit; the catalog cannot silently substitute a narrower upstream profile.

### Provider applicability disclosure

The machine-readable `engines/catalog.json` field `supported_providers` is authoritative for this
release line. A non-empty list requires an exact provider match on the asset; a missing provider is never
guessed. An empty list means provider-agnostic, not “all cloud providers.”

| v0.2.0 engine images | Declared providers and released scope |
|---|---|
| CloudQuery, Steampipe, ScoutSuite, Cloudsplaining | AWS only |
| Prowler | AWS, Azure, and GCP, limited to the exact-scope narrow-IAM contracts below |
| ScubaGear, Maester | Microsoft 365 only |
| Local artifact, external-target, container, and Kubernetes engines | Provider-agnostic |

Prowler accepts exactly one selected native asset and one complete, case-scoped ephemeral credential
profile. The launcher validates that credential against the selected native identifier before invoking
only the matching narrow IAM profile; bootstrap credentials never enter the engine.

| Provider | Exact asset | Launcher profile | Credential consumer | Fixed provider endpoint closure |
|---|---|---|---|---|
| AWS | One `cloud_account` identified by `aws_account_id` | `aws_iam_service_exact_account` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`; STS identity must equal the selected account | `iam.amazonaws.com:443`, `sts.us-east-1.amazonaws.com:443`, `ec2.us-east-1.amazonaws.com:443`, `organizations.us-east-1.amazonaws.com:443` |
| Azure | One `subscription` identified by `azure_subscription_id` | `azure_iam_service_static_token_exact_subscription` | `AZURE_ACCESS_TOKEN`; ARM must return the selected subscription in `Enabled` state | `management.azure.com:443` |
| GCP | One `project` identified by `gcp_project_id` | `gcp_iam_four_checks_exact_project` | `GOOGLE_OAUTH_ACCESS_TOKEN`; exact-project `testIamPermissions` must prove the required reads and deny pinned mutations, then Cloud Resource Manager must return the selected project in `ACTIVE` state and allow `getIamPolicy` | `cloudresourcemanager.googleapis.com:443` |

Azure static-token and GCP exact-project execution come from six
ai-security-scanner downstream runtime patches, bound to the patch applier and runtime-source pre/post
SHA-256 values in the packaging plan; they are not native Prowler 5.39.1 behavior. No other cloud
engine in this release acquires Azure or GCP coverage from Prowler's support: CloudQuery, Steampipe,
ScoutSuite, and Cloudsplaining remain explicitly AWS-only.

## 2. Catalog engine families

Each planned catalog entry is admitted independently through the same manifest, pinned-artifact, runtime-policy, adapter, raw-output retention, canonical normalization, coverage-event, export-provenance, re-verification, and release-disposition contract. The final column below is a readable packaging summary; the current catalog record wins only for that engine's artifact facts if source and prose differ. The canonical product specification still controls user outcomes and release acceptance.

| Domain | Engine / repository | Pinned license record | v0.2.0 integration mode | Required authorization and boundary | Release disposition |
|---|---|---|---|---|---|
| Cloud inventory | [CloudQuery](https://github.com/cloudquery/cloudquery) | MPL-2.0 | Managed OCI image with exact public CLI, AWS source plugin, and file destination source closure | Short-lived AWS read-only capability; fixed API and table allowlists | SOURCE_OFFER |
| Cloud inventory | [Steampipe](https://github.com/turbot/steampipe) | AGPL-3.0-only | Managed OCI image with independently pinned AWS plugin/FDW components | Short-lived AWS read-only capability; fixed query and API allowlists | SOURCE_OFFER |
| Cloud configuration | [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | Managed OCI image with exact AWS-account, Azure-subscription, and GCP-project narrow-IAM profiles; Azure/GCP behavior is supplied by six hash-bound downstream runtime patches | One complete short-lived provider credential for exactly one selected native asset; fixed provider endpoint closure; no bootstrap credential enters the engine | ALLOW |
| Cloud configuration | [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | GPL-2.0-only | Managed OCI image built from pinned source | Short-lived AWS read-only capability and fixed endpoint closure | SOURCE_OFFER |
| AWS IAM | [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | BSD-3-Clause | Managed OCI image over bounded IAM evidence | AWS IAM read only or explicit local policy input | ALLOW |
| Microsoft 365 | [ScubaGear](https://github.com/cisagov/ScubaGear) | CC0-1.0 | Managed PowerShell/OCI image that retains source criticality and leaves unknown values unknown; the published image was withdrawn when the wrapper changed and is awaiting republication | Short-lived Microsoft Graph/service-specific read-only permission set | ALLOW |
| Microsoft 365 | [Maester](https://github.com/maester365/maester) | MIT | Managed PowerShell/OCI image that retains source severity and leaves unknown values unknown; the published image was withdrawn when the wrapper changed and is awaiting republication | Short-lived Microsoft Graph read-only permission set | ALLOW |
| External surface | [Naabu](https://github.com/projectdiscovery/naabu) | MIT | Published bounded-launcher managed OCI revision | `low_impact_external` grant, concrete target allowlist, and rate limits | ALLOW |
| External surface | [httpx](https://github.com/projectdiscovery/httpx) | MIT | Published bounded-launcher managed OCI revision | `low_impact_external` grant plus redirect and resolved-IP enforcement | ALLOW |
| Active external testing | [Nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Published bounded-launcher managed OCI revision with an exact allowlisted template snapshot | `active_external` grant, target allowlist, rate/time limits, and denied template classes | ALLOW |
| Network vulnerability | [OpenVAS Scanner](https://github.com/greenbone/openvas-scanner) and pinned Greenbone feed data | GPL-2.0-only plus feed GPL/ODbL terms | Managed `openvasd` OCI image with scanner source and a digest-pinned feed snapshot | `active_external` grant, exact per-target relay, and target/rate limits | SOURCE_OFFER |
| Source analysis | [Semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1-or-later | Managed OCI image built from the open source closure with a small offline project rule pack | Explicit read-only local source scope; no engine network path | SOURCE_OFFER |
| Secret scanning | [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Project-managed OCI image built from pinned source with a fixed offline launcher | Explicit repository/path scope; findings marked highly sensitive | ALLOW |
| Secret scanning | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | AGPL-3.0 | Managed OCI image built from pinned source; filesystem mode only | Explicit source scope; verification, update, and engine network paths disabled | SOURCE_OFFER |
| Infrastructure as code | [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Managed OCI image with read-only IaC mount | Explicit local/repository scope; external integrations disabled | ALLOW |
| Infrastructure as code | [KICS](https://github.com/Checkmarx/kics) | Apache-2.0 | Exact verified upstream OCI image pulled by digest | Explicit local/repository scope | UPSTREAM_PINNED |
| Dependency and OS-package vulnerability | [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Managed OCI image with an immutable standard vulnerability database and fixed library (repository/IaC) or OS (OCI layout) profiles | Explicit backend-attested filesystem or OCI-layout scope; JAR-only discovery, OCI language packages, IaC misconfiguration, secrets, and licenses excluded; all update paths disabled | ALLOW |
| Container package vulnerability | [Grype](https://github.com/anchore/grype) | Apache-2.0 | Managed OCI image with a checksum-pinned offline vulnerability database and OS/language package cataloging, including JARs | Exactly one backend-validated OCI image layout; automatic DB and application updates disabled | ALLOW |
| SBOM | [Syft](https://github.com/anchore/syft) | Apache-2.0 | Managed OCI image producing a preserved SBOM artifact | Explicit artifact scope and read-only inputs | ALLOW |
| Kubernetes posture | [Kubescape](https://github.com/kubescape/kubescape) | Apache-2.0 | Managed OCI image with checksum-pinned offline framework inputs | Explicit local manifest scope; submission and host scanning disabled | ALLOW |
| Kubernetes CIS | [kube-bench](https://github.com/aquasecurity/kube-bench) | Apache-2.0 | Managed OCI image over an immutable, digest-verified node configuration snapshot | Explicit snapshot scope; no privileged live-host mounts | ALLOW |

Coverage follows the fixed managed profile, not the broad upstream product
name. For repository and IaC working-tree snapshots, a completed Trivy run
establishes vulnerability coverage for recognized language-package manifests,
including supported Java manifests such as `pom.xml`. It does not establish
coverage for dependencies discoverable only from JAR archive contents. For a
validated single-image OCI layout, Trivy covers recognized OS packages; Grype
supplies the complementary offline OS/language-package and JAR archive path.
IaC-misconfiguration, secret, and license coverage are never inferred from a
Trivy run.

### 2.1 Greenbone components

The Greenbone upstream family contains independently licensed programs and data. The v0.2.0 managed image intentionally uses only the scanner and exact feed inputs listed here; naming the broader family does not pull its other services into the release:

| Component | Official repository | Known license | Status |
|---|---|---|---|
| Scanner | [greenbone/openvas-scanner](https://github.com/greenbone/openvas-scanner) | GPL-2.0-only | Included as pinned `openvasd`; complete source and project patches ship in the image |
| Manager | [greenbone/gvmd](https://github.com/greenbone/gvmd) | AGPL-3.0 | Not used or distributed by the v0.2.0 direct-scanner architecture |
| Web interface/API client | [greenbone/gsa](https://github.com/greenbone/gsa) | AGPL-3.0 | Not used or distributed; the local desktop supplies the case interface |
| Scanner protocol daemon | [greenbone/ospd-openvas](https://github.com/greenbone/ospd-openvas) | AGPL-3.0 | Not used or distributed by the direct `openvasd` integration |
| Feed synchronization | [greenbone/greenbone-feed-sync](https://github.com/greenbone/greenbone-feed-sync) | GPL-3.0 | Not used or distributed at runtime; the build imports one digest-pinned feed artifact containing upstream checksum/signature files |

The v0.2.0 Greenbone image includes one digest-pinned Community Feed snapshot, its executable NASL source, data, declared GPL/ODbL license texts, exact revision, checksum manifest, and upstream detached signature. It performs no live feed download. A newer or different feed remains a new artifact and requires a fresh pin, terms decision, evidence set, and support window; source-code license alone never decides feed distribution.

## 3. Research repositories mentioned in the design

Research entries should be cloned or tracked for evaluation as requested, but must not silently become release dependencies.

| Area | Repository | Known upstream license | Candidate use | Research status / issue |
|---|---|---|---|---|
| Compliance queries | [Powerpipe](https://github.com/turbot/powerpipe) | AGPL-3.0 | Steampipe-based dashboards and control query packs | Research; mods and redistribution need separate review |
| Microsoft 365 | [Monkey365](https://github.com/silverhack/monkey365) | Apache-2.0 | Additional M365/Azure assessment evidence | Research; overlap and permissions need evaluation |
| External discovery | [OWASP Amass](https://github.com/owasp-amass/amass) | NOASSERTION in repository metadata | Candidate domain and relationship discovery | Research; manual license determination required |
| Host configuration | [OpenSCAP](https://github.com/OpenSCAP/openscap) | LGPL-2.1 | SCAP content and host posture | Research; content licenses and platform access required |
| Host/SIEM | [Wazuh](https://github.com/wazuh/wazuh) | NOASSERTION in repository metadata | Host configuration or longer-lived telemetry | Research; architecture may exceed local snapshot product; manual license review |
| Host configuration | [Lynis](https://github.com/CISOfy/lynis) | GPL-3.0 | Linux host audit | Research; remote/host execution and GPL review |
| Infrastructure as code | [tfsec](https://github.com/aquasecurity/tfsec) | MIT | Terraform-specific checks | Research; evaluate overlap and upstream maintenance direction |
| Finding management | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | BSD-3-Clause | Importer, deduplication, and workflow design reference | Research/reference; not a bundled server by default |
| Asset graph | [Cartography](https://github.com/cartography-cncf/cartography) | Apache-2.0 | Expert asset and relationship data | Research; graph database weight and overlap need evaluation |
| AWS IAM graph | [PMapper](https://github.com/nccgroup/PMapper) | AGPL-3.0 | AWS privilege path evidence | Research; permissions and AGPL review |
| Identity paths | [BloodHound CE](https://github.com/SpecterOps/BloodHound) | Apache-2.0 | AD/Entra attack-path evidence for expert packages | Research; deployment complexity and data sensitivity |
| Entra identity | [ROADtools](https://github.com/dirkjanm/ROADtools) | MIT | Entra discovery and relationship evidence | Research; permission and safe-query profiles required |
| Kubernetes posture | [kubeaudit](https://github.com/Shopify/kubeaudit) | MIT | Additional Kubernetes manifest checks | Research; upstream repository is archived |
| Runtime security | [Falco](https://github.com/falcosecurity/falco) | Apache-2.0 | Container runtime telemetry | Research; continuous monitoring is outside current snapshot case lifecycle unless bounded |
| TLS | [testssl.sh](https://github.com/testssl/testssl.sh) | GPL-2.0 | TLS configuration checks | Research; direct-contact scope and GPL review |
| External discovery | [Subfinder](https://github.com/projectdiscovery/subfinder) | MIT | Candidate subdomain discovery | Research; provider API keys and passive/active source classification |
| Web application testing | [OWASP ZAP](https://github.com/zaproxy/zaproxy) | Apache-2.0 | Authorized web and API testing | Research; active/crawling policy and resource requirements |
| Dependency vulnerabilities | [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Local dependency and lockfile analysis | Research; overlap with Trivy/Grype needs evaluation |
| Web server testing | [Nikto](https://github.com/sullo/nikto) | NOASSERTION in repository metadata | Authorized web server configuration checks | Research; manual license and active-test policy review |

## 4. Supporting standards and runtime repositories

These are not scanning engines but are part of the design or implementation research.

| Project | Official repository | Known license | v0.2.0 relationship / caution |
|---|---|---|---|
| OCSF schema | [ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema) | Apache-2.0 | Export/interchange coordinate implemented by project-owned mapping code; not the internal persistence model and not a compliance conclusion |
| OSCAL | [usnistgov/OSCAL](https://github.com/usnistgov/OSCAL) | NIST publication terms | Assessment/control exchange coordinate implemented by project-owned mapping code; no formal assessment plan or audit is inferred |
| AIDEFEND AI Defense Framework | [edward-playground/aidefense-framework](https://github.com/edward-playground/aidefense-framework/tree/e10c1678ee49f03f8fb0c97d446ba3fbc3543655) | CC-BY-4.0 for framework content/data | Selected metadata derived from version `1.20260805` is pinned, attributed, and modified into a project-reviewed relationship input for applicable AI-system findings only. It is not a scanner, audit, certification, control-implementation result, or official affiliation/endorsement. |
| Tauri | [tauri-apps/tauri](https://github.com/tauri-apps/tauri) | Apache-2.0 / MIT | Desktop shell and command boundary; exact dependencies appear in generated release notices/SBOMs |
| Podman | [containers/podman](https://github.com/containers/podman) | Apache-2.0 | Packaged rootless managed-runtime client; first setup retrieves an exact pinned Podman machine image |
| QEMU and DTC | [qemu-project/qemu](https://gitlab.com/qemu-project/qemu), [qemu-project/dtc](https://gitlab.com/qemu-project/dtc) | GPL-2.0-only; GPL-2.0-or-later AND BSD-2-Clause | Linux managed-runtime emulator built from checksum-pinned source with corresponding-source records |
| gvisor-tap-vsock and vfkit | [containers/gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock), [crc-org/vfkit](https://github.com/crc-org/vfkit) | Apache-2.0 | Pinned platform helpers inventoried by file in the managed-runtime evidence |
| Moby | [moby/moby](https://github.com/moby/moby) | Apache-2.0 | Research only; not used by the packaged runtime and does not grant Docker Desktop redistribution rights |
| Docker CLI and Compose | [docker/cli](https://github.com/docker/cli), [docker/compose](https://github.com/docker/compose) | Apache-2.0 | Optional user-installed compatibility path; neither is bundled nor required |

Docker Desktop is a separately licensed product, is not bundled, and is not required. The target packaged path uses a versioned private Podman machine: QEMU on Linux, Apple Virtualization.framework through vfkit on macOS, and the WSL 2 capability detected/prepared by the signed installer on Windows. Exact per-platform files, first-setup downloads, source revisions, license expressions, sizes, and hashes belong in the managed-runtime manifest and generated release evidence. Those details remain Technical details; the intended Windows preparation is automatic and never asks a beginner to administer WSL. The current Windows installer/runtime path has not yet reached that behavior; [audit finding A01](product-audit.md#a01--windows-preparation-is-a-second-product-after-installation) tracks the implementation gap.

## 5. Integration modes

### 5.1 Separate CLI or OCI adapter

This is the default. The upstream engine remains a separate executable work. The project supplies a narrow adapter and manifest, passes read-only inputs, and ingests outputs through the adapter protocol.

Process separation is an engineering boundary, not a blanket license exemption. Redistribution obligations still apply to every shipped artifact.

### 5.2 Project-owned wrapper image

Where upstream has no suitable image, the project may build a wrapper image from a pinned source release. The image recipe, exact source, patches, license texts, corresponding-source obligations, dependencies, and SBOM must be published. A wrapper does not change the upstream license.

### 5.3 On-demand retrieval

If redistribution is not approved or an engine is too large for the default installer, the application may retrieve an exact pinned digest from an approved upstream location as product-owned background preparation. It shows size/stage and any legally required terms, but does not add a generic technical consent or setup ceremony. It must never retrieve `latest`. Failure disables only that engine task, preserves the run, and records the coverage gap. Dynamic download does not eliminate license obligations.

### 5.4 Bundled/offline artifact

An offline bundle may include only engines, rules, feeds, and databases with an approved redistribution disposition. The bundle carries notices, source or source offer where required, artifact hashes, and an SBOM.

### 5.5 Host-native adapter

A host binary is acceptable only when it can be installed, isolated, upgraded, and removed through the managed product path. Requiring a newcomer to independently configure Python or PowerShell is not a completed desktop experience.

## 6. Authorization profiles

Manifests select from explicit profiles rather than arbitrary credentials:

- `cloud_inventory_readonly`;
- `cloud_security_audit_readonly`;
- `m365_configuration_readonly`;
- `repository_readonly`;
- `artifact_readonly`;
- `kubernetes_manifest_readonly`;
- `kubernetes_cluster_readonly`;
- `passive_public_discovery`;
- `low_impact_external`;
- `active_external`.

No scanner profile accepts `admin`, `owner`, `global_administrator`, unrestricted Docker socket access, or a general shell capability. Administrative authority exists only in the bootstrap broker's fixed role-creation protocol.

## 7. Engine admission checklist

An engine cannot be marked supported until all items have evidence:

- upstream repository and maintainer identity recorded;
- exact source revision, version, artifact digest, and retrieval source pinned;
- engine, dependencies, image, rules, templates, feeds, and databases reviewed for license and redistribution;
- required notices, corresponding source, or source offer prepared;
- supported OS and CPU architectures recorded;
- provider APIs, outbound domains, targets, mounts, credentials, and resource limits declared;
- adapter protocol implemented with malformed-output and size-limit tests;
- representative raw fixtures and normalization fixtures checked in where redistribution permits;
- progress, partial, failure, cancellation, retry, and cleanup behavior implemented;
- coverage records emitted without equating zero findings to success;
- raw evidence preserved and hashed;
- re-verification identity and adapter migrations defined;
- any supplied NIST/ISO relationships and applicable AIDEFEND relationships versioned and reviewed rather than guessed at runtime; an engine may run without them and reports the mapping gap;
- SBOM generated for distributed artifacts;
- end-of-support and replacement behavior documented.

## 8. Maintenance policy

Each manifest records an owner, knowledge date, support-until date, and update procedure. Upstream changes may be adopted continuously, but a case always records an exact version set.

An unsupported or expired engine remains visible in historical provenance. A merely stale but still trusted engine may run only with an explicit knowledge-date warning according to product policy. A concretely untrusted/incompatible artifact may be blocked from its new task. Either way, other engines continue and the report marks exact executed/not-tested coverage; it must not silently present current-looking green results.

Adding many repositories is encouraged only when each adapter enters the same case, coverage, evidence, export, and re-verification model. A clone plus a button is not an integration.

Engine catalog, fixture, provenance, and affected-platform checks are engine-admission/publication evidence. They do not replace the exact-candidate installed-Windows beginner path and do not run as an unconditional blocker for an unrelated UI/docs change. Any proposal that makes one engine or its evidence a wider gate must meet the canonical complexity budget with a reproduced harm and proof that operation-scoped admission plus partial reporting is insufficient.
