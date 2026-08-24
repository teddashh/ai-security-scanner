# ai-security-scanner engine catalog

Status: target catalog and research inventory

Last updated: 2026-08-24

This catalog records the engines and supporting repositories named in the product design. It does not claim that an adapter exists, that an engine has been tested, or that redistribution is approved.

License identifiers below were observed from the upstream repository's default-branch license metadata on 2026-08-24. The exact pinned commit, subcomponents, plugins, rules, templates, feeds, databases, trademarks, images, and binary distribution terms must be reviewed before a release artifact is built. `Pending` is deliberately not an approval.

## 1. Catalog states

- **Required:** the complete product must support this engine or engine family through the full case lifecycle.
- **Research:** the repository was named in the design and should remain available for evaluation, but it is not a complete-product adapter commitment.
- **Pending license review:** adapter research and local invocation may proceed, but the project has not approved bundling or redistribution.
- **Blocked:** the project has identified a condition that prevents use in a release until resolved.

An upstream source checkout is research material. It does not make an engine installed, integrated, safe, supported, or redistributable.

## 2. Required engine families

Every Required entry must eventually provide a manifest, pinned artifact, runtime policy, adapter, raw-output retention, canonical normalization, coverage events, export provenance, re-verification behavior, and release license disposition.

| Domain | Engine / repository | Known upstream license | Planned integration mode | Required authorization and boundary | Redistribution status |
|---|---|---|---|---|---|
| Cloud inventory | [CloudQuery](https://github.com/cloudquery/cloudquery) | MPL-2.0 | Separate CLI/OCI adapter; pin core and every provider plugin independently | Short-lived provider read-only capability; provider API allowlist | Pending; plugins require separate review |
| Cloud inventory | [Steampipe](https://github.com/turbot/steampipe) | AGPL-3.0 | Separate CLI/OCI adapter; query output converted to assets/evidence | Short-lived provider read-only capability; plugins and mods separately pinned | Pending AGPL, plugin, and mod review |
| Cloud configuration | [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | Separate CLI/OCI adapter with provider-specific run profiles | Short-lived read-only/security-audit role; no bootstrap credential | Pending image and rules review |
| Cloud configuration | [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | GPL-2.0-only | Separate CLI/OCI adapter | Short-lived cloud read-only capability | Pending GPL distribution review |
| AWS IAM | [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | BSD-3-Clause | Separate CLI/OCI adapter over read-only IAM input or exported policies | AWS IAM read only or explicit local policy input | Pending artifact review |
| Microsoft 365 | [ScubaGear](https://github.com/cisagov/ScubaGear) | CC0-1.0 | PowerShell adapter in a constrained Windows or OCI runtime | Short-lived Microsoft Graph/service-specific read-only permission set | Pending dependency and trademark review |
| Microsoft 365 | [Maester](https://github.com/maester365/maester) | MIT | PowerShell adapter in a constrained Windows or OCI runtime | Short-lived Microsoft Graph read-only permission set; test modules pinned | Pending dependency/module review |
| External surface | [Naabu](https://github.com/projectdiscovery/naabu) | MIT | Standalone Go binary or OCI adapter | `low_impact_external` grant, concrete target allowlist, rate limits | Pending binary/image review |
| External surface | [httpx](https://github.com/projectdiscovery/httpx) | MIT | Standalone Go binary or OCI adapter | `low_impact_external` grant, redirect and resolved-IP enforcement | Pending binary/image review |
| Active external testing | [Nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Standalone Go binary or OCI adapter; template policy supplied separately | `active_external` grant, target allowlist, rate/time limits, denied template classes | Pending binary/image review |
| Active external rules | [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | Separately pinned data artifact selected by an allowlist policy | Same grant as Nuclei; no automatic enablement of destructive or out-of-band templates | Pending template-by-template policy review |
| Network vulnerability | [OpenVAS Scanner](https://github.com/greenbone/openvas-scanner) and Greenbone family | GPL-2.0 scanner; mixed GPL/AGPL family | Managed multi-service runtime; not a single-process adapter | `active_external` grant, dedicated data volumes, target/rate limits | Pending multi-component and feed review |
| Source analysis | [Semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1-or-later | Separate CLI/OCI adapter with read-only repository mount | Explicit local source scope; no network unless a reviewed rules source is enabled | Pending LGPL and rules review |
| Secret scanning | [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Standalone binary or OCI adapter with read-only repository mount | Explicit repository/path scope; findings marked highly sensitive | Pending binary/image and rule review |
| Secret scanning | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | AGPL-3.0 | Separate CLI/OCI adapter with source-specific profile | Explicit source scope; verification network calls disabled unless separately approved | Pending AGPL and verification-mode review |
| Infrastructure as code | [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Separate CLI/OCI adapter with read-only IaC mount | Explicit local/repository scope; external integrations disabled by default | Pending image, dependency, and policy review |
| Infrastructure as code | [KICS](https://github.com/Checkmarx/kics) | Apache-2.0 | Separate CLI/OCI adapter with read-only IaC mount | Explicit local/repository scope | Pending image and query-pack review |
| Container/package/SBOM | [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Separate CLI/OCI adapter; image, filesystem, package, and SBOM profiles | Explicit artifact scope; DB retrieval separately pinned and licensed | Pending image and database review |
| Container vulnerability | [Grype](https://github.com/anchore/grype) | Apache-2.0 | Separate CLI/OCI adapter over image, directory, or Syft SBOM | Explicit artifact scope; vulnerability DB separately pinned | Pending image and database review |
| SBOM | [Syft](https://github.com/anchore/syft) | Apache-2.0 | Separate CLI/OCI adapter producing a preserved SBOM artifact | Explicit artifact scope; read-only inputs | Pending image and cataloger review |
| Kubernetes posture | [Kubescape](https://github.com/kubescape/kubescape) | Apache-2.0 | Separate CLI/OCI adapter; manifest-only and live-cluster profiles | Read-only cluster role or explicit local manifests; framework data pinned | Pending image/framework review |
| Kubernetes CIS | [kube-bench](https://github.com/aquasecurity/kube-bench) | Apache-2.0 | Separate OCI adapter; configuration/remote-job profile preferred over broad host mounts | Explicit cluster/node scope; host-mount exceptions require threat review | Pending image/config review |

### 2.1 Greenbone components

“Greenbone/OpenVAS” is not one redistributable image. At minimum, a supported design must evaluate and pin:

| Component | Official repository | Known license | Status |
|---|---|---|---|
| Scanner | [greenbone/openvas-scanner](https://github.com/greenbone/openvas-scanner) | GPL-2.0 | Required family; pending review |
| Manager | [greenbone/gvmd](https://github.com/greenbone/gvmd) | AGPL-3.0 | Required family; pending review |
| Web interface/API client | [greenbone/gsa](https://github.com/greenbone/gsa) | AGPL-3.0 | Evaluate whether the desktop app needs this component |
| Scanner protocol daemon | [greenbone/ospd-openvas](https://github.com/greenbone/ospd-openvas) | AGPL-3.0 | Required if selected deployment architecture needs it |
| Feed synchronization | [greenbone/greenbone-feed-sync](https://github.com/greenbone/greenbone-feed-sync) | GPL-3.0 | Required family; feed terms remain separate |

The Greenbone Community Feed and other data feeds require an independent terms and redistribution review. Source-code license alone is not a feed-distribution decision.

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

| Project | Official repository | Known license | Intended use / caution |
|---|---|---|---|
| OCSF schema | [ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema) | Apache-2.0 | Export/interchange mapping; not the only internal persistence model |
| OSCAL | [usnistgov/OSCAL](https://github.com/usnistgov/OSCAL) | NOASSERTION in repository metadata | Assessment/control exchange; NIST terms need manual review |
| Tauri | [tauri-apps/tauri](https://github.com/tauri-apps/tauri) | Apache-2.0 / MIT dual licensing in upstream files | Desktop shell and command boundary |
| Moby | [moby/moby](https://github.com/moby/moby) | Apache-2.0 | Candidate managed runtime component; does not grant Docker Desktop redistribution rights |
| Podman | [containers/podman](https://github.com/containers/podman) | Apache-2.0 | Candidate managed or compatibility runtime provider |
| Docker CLI | [docker/cli](https://github.com/docker/cli) | Apache-2.0 | Existing-engine compatibility provider only after runtime review |
| Docker Compose | [docker/compose](https://github.com/docker/compose) | Apache-2.0 | Multi-service engine support where appropriate |

Docker Desktop is a separately licensed product. The project must not infer redistribution permission from the Moby, CLI, or Compose repositories. Windows and macOS also require a Linux virtualization strategy; copying container binaries into a Tauri bundle does not solve that requirement.

## 5. Integration modes

### 5.1 Separate CLI or OCI adapter

This is the default. The upstream engine remains a separate executable work. The project supplies a narrow adapter and manifest, passes read-only inputs, and ingests outputs through the adapter protocol.

Process separation is an engineering boundary, not a blanket license exemption. Redistribution obligations still apply to every shipped artifact.

### 5.2 Project-owned wrapper image

Where upstream has no suitable image, the project may build a wrapper image from a pinned source release. The image recipe, exact source, patches, license texts, corresponding-source obligations, dependencies, and SBOM must be published. A wrapper does not change the upstream license.

### 5.3 On-demand retrieval

If redistribution is not approved or an engine is too large for the default installer, the application may retrieve an exact pinned digest from an approved upstream location after informed user consent. It must never retrieve `latest`. Dynamic download does not eliminate license obligations.

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
- NIST/ISO relationships versioned and reviewed rather than guessed at runtime;
- SBOM generated for distributed artifacts;
- end-of-support and replacement behavior documented.

## 8. Maintenance policy

Each manifest records an owner, knowledge date, support-until date, and update procedure. Upstream changes may be adopted continuously, but a case always records an exact version set.

An unsupported or expired engine remains visible in historical provenance. It may be blocked from new cases or run with an explicit stale-knowledge warning according to project policy; it must not silently present current-looking green results.

Adding many repositories is encouraged only when each adapter enters the same case, coverage, evidence, export, and re-verification model. A clone plus a button is not an integration.
