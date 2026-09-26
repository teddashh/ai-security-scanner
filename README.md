# ai-security-scanner

[Project website](https://teddashh.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Releases](https://github.com/teddashh/ai-security-scanner/releases)

Security checks across repositories, websites, and internal systems, through a desktop app or an Agent Skill for Claude Code and Codex. Select the targets, confirm authorization for network checks, and start one scan. Established upstream scanners provide the detection; thin adapters and output converters bring their results into one standardized, prioritized report.

## Start here

The current candidate is **multi-OS: Linux, macOS, and Windows**. Public release is **HOLD**; these candidate installers have not been published as a GitHub Release. The [commit-bound QC run for `56d3b3f`](https://github.com/teddashh/ai-security-scanner/actions/runs/35513091476) records:

| Platform | Candidate installers |
| --- | --- |
| Windows x86-64 | MSI and NSIS offered; **unsigned**, so SmartScreen may warn |
| macOS Universal | `.dmg` offered; **not notarized** |
| Linux x86-64 | Debian `.deb` offered; AppImage and `.rpm` **not offered** |

See the [candidate disclosures](docs/releasing.md#current-candidate-and-publication-hold) for recorded testing limits. The latest published release, [v0.2.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.2.0), is an earlier **Linux `.deb`-only** build. To build current `main` yourself, including the Grype repository fix, use the [Agent Skill workflow](docs/getting-started.md#use-with-an-agent-skill).

Open the app and choose one path:

- **Scan my environment** combines multiple project folders, websites, and approved internal systems in one run.
- **Check a website** scans one exact web origin with a reviewed Nuclei profile.
- **Check code or an AI project** scans a read-only local snapshot for secrets, vulnerable dependencies, risky code, and unsafe configuration.

Follow **New scan → Scan setup → Start scan → Scan progress → Results**. From Results, select **Save or share report** to open **Share results**, then **Save HTML report**. See the [step-by-step path to an HTML report](docs/getting-started.md#from-new-scan-to-an-html-report), including how to reopen a scan from **My scans**.

## Use with Claude Code or Codex

Agent Skills are a first-class way to build and operate the product from a source checkout. Both agents use the same operating instructions and the product's desktop/typed CLI interfaces:

| Agent | Repository skill |
| --- | --- |
| Claude Code | [ai-security-scanner](.claude/skills/ai-security-scanner/SKILL.md) |
| Codex | [ai-security-scanner](.codex/skills/ai-security-scanner/SKILL.md) |

Open this checkout in either agent and ask:

> Use the ai-security-scanner skill to build this checkout, help me select a local project folder, run its applicable security checks, and save the final HTML report.

The skill guides **build → target selection and authorization → scan → final report**. You choose the scope; the product selects applicable upstream checks. See [setup and build commands](docs/getting-started.md#use-with-an-agent-skill).

## One report for every selected asset

The report leads with:

- assets with confirmed problems;
- the highest-priority findings and their impact;
- the smallest practical next action and a way to verify the fix;
- completed checks and untested work for each asset;
- original scanner identifiers, severity, evidence, and remediation in technical details.

Completed results remain available when an independent check fails. Reports can be reopened, compared with later runs, and exported as readable HTML or structured data.

## Integrated tools

The current runnable engine set integrates 22 upstream projects. The catalog separately retains experimental, non-dispatchable AI contracts; those are not current scan capabilities. See [Development status](docs/development-status.md). The product runs only the tools that apply to each selected asset, keeps their original identifiers, severity, evidence, and remediation, then organizes every completed result in the same report.

**Selected assets and authorization → thin adapters → upstream scanners → output converters → one standardized report organized by asset**

Detection rules remain upstream. Product-owned prioritization, deduplication, and plain-language guidance live in the shared report layer.

### Repositories, dependencies, and infrastructure as code

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Semgrep](https://github.com/semgrep/semgrep) | Static analysis for risky code patterns using a pinned upstream security rule snapshot. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Offline secret-pattern scanning with secret values redacted from normal evidence. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Offline filesystem secret detection; network verification is disabled. |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerable packages in recognized repository manifests and single-image OCI layouts using pinned offline data. |
| [Grype](https://github.com/anchore/grype) | Vulnerable packages in repository snapshots and single-image OCI layouts using pinned offline data. |
| [Checkov](https://github.com/bridgecrewio/checkov) | Applicable infrastructure and configuration checks across the selected read-only snapshot. |
| [KICS](https://github.com/Checkmarx/kics) | Infrastructure-as-code misconfiguration checks from the upstream query pack. |
| [Syft](https://github.com/anchore/syft) | Software component inventory and preserved SBOM output; inventory is not a vulnerability result. |

The current source catalog pins the Grype image to **`0.117.0-4`**, digest `sha256:56b0d675…`. It can scan local repository dependencies for known vulnerabilities; a controlled repository scan recorded **81 Grype findings**. That is a fixture result, not an expected count for every project. See the [exact pin and recorded result](docs/engine-catalog.md#grype-repository-support).

### Websites and internal systems

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Technology-aware, bounded read-only HTTP security checks from a pinned [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) snapshot. |
| [Greenbone OpenVAS Scanner](https://github.com/greenbone/openvas-scanner) | Service-aware remote checks from a pinned Community Feed for exact approved hosts and ports. |
| [Naabu](https://github.com/projectdiscovery/naabu) | Selected TCP-port reachability and exposure discovery; an open port is not a vulnerability finding. |
| [httpx](https://github.com/projectdiscovery/httpx) | Bounded HTTP reachability and status metadata; it is not a vulnerability scanner. |

### Cloud and Microsoft 365

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Prowler](https://github.com/prowler-cloud/prowler) | Narrow, exact-asset IAM configuration profiles for AWS, Azure, and GCP. |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | A reduced AWS IAM assessment rather than full ScoutSuite coverage. |
| [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | Excessive-permission analysis over bounded AWS IAM evidence. |
| [CloudQuery](https://github.com/cloudquery/cloudquery) | A fixed AWS IAM inventory; returned rows remain inventory rather than security findings. |
| [Steampipe](https://github.com/turbot/steampipe) | AWS IAM user inventory; inventory fields do not become findings. |
| [ScubaGear](https://github.com/cisagov/ScubaGear) | A fixed Microsoft 365 security-baseline configuration profile. |
| [Maester](https://github.com/maester365/maester) | A fixed Microsoft 365 security-configuration test profile. |

### Kubernetes

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Kubescape](https://github.com/kubescape/kubescape) | Offline configuration checks over explicitly selected local Kubernetes manifests. |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS checks over an immutable node-configuration snapshot, without a privileged live-host mount. |

### MCP configuration

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [MCP Armor](https://github.com/aira-security/mcp-armor) | Static checks over one approved MCP configuration snapshot for hardcoded credentials and excessive tool permissions, without starting or contacting an MCP server or loading a model. |

Discovery, inventory, SBOM generation, and the localhost TCP utility remain clearly separated from vulnerability findings. The complete pinned versions, licenses, profiles, and execution boundaries are recorded in the [engine catalog](docs/engine-catalog.md).

Exact scan boundaries and profile behavior are documented in [Scanning scope](docs/scanning-scope.md).

## Data and authorization

Cases, findings, and evidence stay on the device until an external source is connected or a report is exported. Local folders are copied into bounded read-only snapshots. Network scanners contact only the targets and ports confirmed on Review.

Use network scanning only for assets you own or are authorized to assess. The app does not apply remediation automatically.

## Documentation

- [Getting started](docs/getting-started.md)
- [Scanning scope](docs/scanning-scope.md)
- [Results and exports](docs/results-and-exports.md)
- [Documentation index](docs/README.md)
- [Development status](docs/development-status.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Development

Development requires Node.js 24 or newer, Rust 1.98, and the platform dependencies required by Tauri.

```sh
npm ci
npm run typecheck
npm run test:frontend
npm run test:component
npm run build
cargo test --locked --workspace --no-default-features --features cli
npm run tauri dev
```

`npm run dev` opens a browser preview with sample data. Desktop scanning runs through the Tauri application.

`npm run upstream:refresh -- --engine <id>` produces an offline adapter refresh proposal bundle, and `npm run upstream:propose -- --bundle <path>` re-validates it. `mechanical` is the default deterministic path; the optional AI path is selected explicitly with `--provider cli --ai-cli <executable>`. `--open-pr` or `--no-open-pr` records whether the change should be sent back to this repository. These commands print commands for a human to run and never execute them. The full procedure is in [Engine maintenance](docs/engine-maintenance.md).

## License

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party engines and data retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
