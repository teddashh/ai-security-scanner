# Third-party inventory for ai-security-scanner

Status: pre-release inventory; not a final NOTICE file

Last updated: 2026-08-24

`ai-security-scanner` is designed to orchestrate many independent upstream projects. This file records projects named by the product design and the license identifier observed from each upstream repository. It does **not** state that a component is currently compiled, installed, bundled, tested, supported, or legally approved for redistribution.

The exact license is the license attached to the pinned source revision and distributed artifact, including its dependencies, images, plugins, rules, templates, feeds, and databases. Every release must regenerate this inventory from its resolved engine manifests and SBOM.

The `ai-security-scanner` repository currently carries the Apache License 2.0 in the root `LICENSE` file. That license covers this project's own work only and does not replace, relicense, or override any third-party terms recorded here.

## Review labels

- `PENDING`: known upstream license, but exact artifact and redistribution review is not complete.
- `MANUAL`: repository metadata did not provide an unambiguous SPDX identifier or the project has special terms requiring manual review.
- `MULTI`: the named product is a stack with independently licensed components and data.
- `RESEARCH`: tracked for evaluation; not a committed release dependency.
- `ARCHIVED`: upstream is archived and requires a maintenance/replacement decision.

No `PENDING`, `MANUAL`, `MULTI`, or `RESEARCH` entry may be interpreted as release approval.

## Required product engine inventory

| Component | Official source | Observed license | Intended relationship | Review |
|---|---|---|---|---|
| CloudQuery | [cloudquery/cloudquery](https://github.com/cloudquery/cloudquery) | MPL-2.0 | Separate CLI/OCI engine; provider plugins tracked separately | PENDING |
| Steampipe | [turbot/steampipe](https://github.com/turbot/steampipe) | AGPL-3.0 | Separate CLI/OCI engine; plugins and mods tracked separately | PENDING |
| Prowler | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | Separate CLI/OCI engine | PENDING |
| ScoutSuite | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) | GPL-2.0-only | Separate CLI/OCI engine | PENDING |
| Cloudsplaining | [salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) | BSD-3-Clause | Separate CLI/OCI engine | PENDING |
| ScubaGear | [cisagov/ScubaGear](https://github.com/cisagov/ScubaGear) | CC0-1.0 | Separate PowerShell/OCI engine | PENDING |
| Maester | [maester365/maester](https://github.com/maester365/maester) | MIT | Separate PowerShell/OCI engine and test modules | PENDING |
| Naabu | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) | MIT | Separate binary/OCI engine | PENDING |
| httpx | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) | MIT | Separate binary/OCI engine | PENDING |
| Nuclei | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Separate binary/OCI engine | PENDING |
| Nuclei Templates | [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | Separately pinned rules/template data | PENDING |
| OpenVAS Scanner | [greenbone/openvas-scanner](https://github.com/greenbone/openvas-scanner) | GPL-2.0 | Greenbone multi-service engine component | MULTI |
| Greenbone Vulnerability Manager | [greenbone/gvmd](https://github.com/greenbone/gvmd) | AGPL-3.0 | Greenbone multi-service engine component | MULTI |
| Greenbone Security Assistant | [greenbone/gsa](https://github.com/greenbone/gsa) | AGPL-3.0 | Optional Greenbone UI/API component under evaluation | MULTI |
| OSPd OpenVAS | [greenbone/ospd-openvas](https://github.com/greenbone/ospd-openvas) | AGPL-3.0 | Greenbone multi-service engine component | MULTI |
| Greenbone Feed Sync | [greenbone/greenbone-feed-sync](https://github.com/greenbone/greenbone-feed-sync) | GPL-3.0 | Greenbone feed retrieval component; feed terms separate | MULTI |
| Semgrep | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1-or-later | Separate CLI/OCI engine; rules tracked separately | PENDING |
| Gitleaks | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Separate binary/OCI engine | PENDING |
| TruffleHog | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | AGPL-3.0 | Separate CLI/OCI engine | PENDING |
| Checkov | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Separate CLI/OCI engine; policies tracked separately | PENDING |
| KICS | [Checkmarx/kics](https://github.com/Checkmarx/kics) | Apache-2.0 | Separate CLI/OCI engine; query packs tracked separately | PENDING |
| Trivy | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Separate CLI/OCI engine; vulnerability DB tracked separately | PENDING |
| Grype | [anchore/grype](https://github.com/anchore/grype) | Apache-2.0 | Separate CLI/OCI engine; vulnerability DB tracked separately | PENDING |
| Syft | [anchore/syft](https://github.com/anchore/syft) | Apache-2.0 | Separate CLI/OCI engine | PENDING |
| Kubescape | [kubescape/kubescape](https://github.com/kubescape/kubescape) | Apache-2.0 | Separate CLI/OCI engine; framework data tracked separately | PENDING |
| kube-bench | [aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) | Apache-2.0 | Separate CLI/OCI engine; benchmark config tracked separately | PENDING |

## Research inventory

| Component | Official source | Observed license | Candidate relationship | Review |
|---|---|---|---|---|
| Powerpipe | [turbot/powerpipe](https://github.com/turbot/powerpipe) | AGPL-3.0 | Compliance query and dashboard research | RESEARCH |
| Monkey365 | [silverhack/monkey365](https://github.com/silverhack/monkey365) | Apache-2.0 | Microsoft 365/Azure assessment research | RESEARCH |
| OWASP Amass | [owasp-amass/amass](https://github.com/owasp-amass/amass) | NOASSERTION | External discovery research | MANUAL / RESEARCH |
| OpenSCAP | [OpenSCAP/openscap](https://github.com/OpenSCAP/openscap) | LGPL-2.1 | Host posture and SCAP research | RESEARCH |
| Wazuh | [wazuh/wazuh](https://github.com/wazuh/wazuh) | NOASSERTION | Host/SIEM research | MANUAL / RESEARCH |
| Lynis | [CISOfy/lynis](https://github.com/CISOfy/lynis) | GPL-3.0 | Linux host posture research | RESEARCH |
| tfsec | [aquasecurity/tfsec](https://github.com/aquasecurity/tfsec) | MIT | Terraform scanner research | RESEARCH |
| DefectDojo | [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | BSD-3-Clause | Import/deduplication/workflow reference | RESEARCH |
| Cartography | [cartography-cncf/cartography](https://github.com/cartography-cncf/cartography) | Apache-2.0 | Asset graph research | RESEARCH |
| PMapper | [nccgroup/PMapper](https://github.com/nccgroup/PMapper) | AGPL-3.0 | AWS IAM path research | RESEARCH |
| BloodHound CE | [SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) | Apache-2.0 | AD/Entra path research | RESEARCH |
| ROADtools | [dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) | MIT | Entra identity research | RESEARCH |
| kubeaudit | [Shopify/kubeaudit](https://github.com/Shopify/kubeaudit) | MIT | Kubernetes posture research | ARCHIVED / RESEARCH |
| Falco | [falcosecurity/falco](https://github.com/falcosecurity/falco) | Apache-2.0 | Runtime security research | RESEARCH |
| testssl.sh | [testssl/testssl.sh](https://github.com/testssl/testssl.sh) | GPL-2.0 | TLS assessment research | RESEARCH |
| Subfinder | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | MIT | External discovery research | RESEARCH |
| OWASP ZAP | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) | Apache-2.0 | Authorized web/API testing research | RESEARCH |
| OSV-Scanner | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Dependency scanner research | RESEARCH |
| Nikto | [sullo/nikto](https://github.com/sullo/nikto) | NOASSERTION | Authorized web-server assessment research | MANUAL / RESEARCH |

## Supporting standards and runtime inventory

| Component | Official source | Observed license | Intended relationship | Review |
|---|---|---|---|---|
| OCSF schema | [ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema) | Apache-2.0 | Interchange/export schema | PENDING version and notice review |
| OSCAL | [usnistgov/OSCAL](https://github.com/usnistgov/OSCAL) | NOASSERTION | Assessment/control exchange | MANUAL NIST terms review |
| Tauri | [tauri-apps/tauri](https://github.com/tauri-apps/tauri) | Apache-2.0 / MIT | Desktop framework | PENDING dependency SBOM review |
| Moby | [moby/moby](https://github.com/moby/moby) | Apache-2.0 | Managed-runtime research | PENDING packaging review |
| Podman | [containers/podman](https://github.com/containers/podman) | Apache-2.0 | Managed/compatibility runtime research | PENDING packaging review |
| Docker CLI | [docker/cli](https://github.com/docker/cli) | Apache-2.0 | Compatibility runtime client | PENDING packaging review |
| Docker Compose | [docker/compose](https://github.com/docker/compose) | Apache-2.0 | Multi-service engine orchestration | PENDING packaging review |

## Docker Desktop is separate

[Docker Desktop licensing](https://docs.docker.com/subscription/desktop-license/) is not the same as the Apache-2.0 licenses on Moby, Docker CLI, or Docker Compose. `ai-security-scanner` must not bundle, redistribute, or require an enterprise user to use Docker Desktop based only on those repository licenses.

The runtime implementation for Windows and macOS also requires Linux virtualization and platform integration. A release must identify the exact runtime product and terms it distributes or invokes.

## Rules, feeds, plugins, and databases

The following are separate third-party artifacts even when an engine downloads them automatically:

- Nuclei templates and any private/community template packs;
- Steampipe and CloudQuery provider plugins;
- Powerpipe or Steampipe compliance mods;
- Greenbone Community Feed and related vulnerability/test data;
- Trivy and Grype vulnerability databases;
- Semgrep rules;
- Checkov policies and KICS queries;
- Kubescape framework/control data;
- kube-bench benchmark configuration;
- language package indexes and advisory databases used by any engine.

The engine manifest must record each artifact's source, license, version or date, digest, update method, redistribution decision, and support window. An engine's source license does not automatically license its downloaded data.

## General obligations by license family

This section is an engineering checklist, not legal advice.

### Permissive licenses

MIT, BSD-3-Clause, and Apache-2.0 generally permit redistribution with preservation of copyright, license, attribution, and applicable NOTICE material. Apache-2.0 also contains patent and NOTICE provisions. Dependency licenses still apply.

### CC0

CC0-1.0 is a public-domain dedication/fallback license. Retaining provenance and the upstream license text is still project policy.

### MPL-2.0

MPL-2.0 has file-level source obligations for covered files and modifications. A distributed binary or image requires a corresponding-source path and required notices for covered code.

### LGPL-2.1

LGPL obligations depend on whether the project links, modifies, or merely distributes a separate executable. Distribution still requires the license and applicable source/relinking obligations. The release review must examine the actual wrapper and artifact, not rely on the words “separate process.”

### GPL-2.0 and GPL-3.0

Distribution requires the applicable GPL materials, complete corresponding source or a compliant source offer, notices, and license-compatible treatment of modifications. Packaging multiple programs as an aggregate does not remove obligations for the GPL programs.

### AGPL-3.0

AGPL includes GPL distribution obligations and a network-interaction source provision for modified covered software used over a network. Running an AGPL component locally or in a separate container is not a blanket exception. Each actual integration and modification must be reviewed.

### NOASSERTION and special terms

`NOASSERTION` means the automated repository metadata was not sufficient. It does not mean no license or unrestricted use. These components remain non-redistributable until a human reviews the pinned revision and records a decision.

## Release compliance requirements

Before publishing any installer, image bundle, offline archive, or update pack:

1. Resolve every included artifact to a source revision, version, and digest.
2. Generate an SBOM for the desktop application, broker, runtime, images, adapters, and bundled data.
3. Re-evaluate licenses from the pinned artifacts rather than copying this table unchanged.
4. Produce required license texts, attribution, NOTICE files, corresponding source, patches, and source offers.
5. Verify trademarks and naming restrictions separately from copyright licenses.
6. Confirm whether each artifact is bundled, built by the project, or downloaded on demand.
7. Confirm that on-demand download terms allow the proposed use; downloading later is not a license bypass.
8. Record the decision in the engine manifest and release evidence.
9. Block release packaging for unresolved `MANUAL`, `MULTI`, or incompatible entries while allowing non-distributive adapter development to continue.

This file must be updated whenever a required engine, runtime component, ruleset, feed, database, plugin, or license changes.
