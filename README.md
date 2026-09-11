# ai-security-scanner

[Project website](https://teddashh.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Releases](https://github.com/teddashh/ai-security-scanner/releases)

One desktop app for security checks across repositories, websites, and internal systems. Select the assets, start one scan, and receive one prioritized report with findings, affected assets, evidence, and next actions.

## Start here

Download the installer for your operating system from [GitHub Releases](https://github.com/teddashh/ai-security-scanner/releases):

| Platform | Installer |
| --- | --- |
| Windows x86-64 | NSIS `.exe` or `.msi` |
| macOS | Universal `.dmg` |
| Linux x86-64 | Debian `.deb` |

Open the app and choose one path:

- **Scan my IT environment** combines multiple project folders, websites, and approved internal systems in one run.
- **Check a website** scans one exact web origin with a reviewed Nuclei profile.
- **Check a project folder** scans a read-only local snapshot for secrets, vulnerable dependencies, risky code, and unsafe configuration.

Review the exact assets and network boundaries, then select **Start scan**. Results open when the run finishes.

## One report for every selected asset

The report leads with:

- assets with confirmed problems;
- the highest-priority findings and their impact;
- the smallest practical next action and a way to verify the fix;
- completed checks and untested work for each asset;
- original scanner identifiers, severity, evidence, and remediation in technical details.

Completed results remain available when an independent check fails. Reports can be reopened, compared with later runs, and exported as readable HTML or structured data.

## Integrated tools

The current engine catalog integrates 21 upstream projects. The product runs only the tools that apply to each selected asset, keeps their original identifiers, severity, evidence, and remediation, then organizes every completed result in the same report.

**Selected assets → applicable upstream tools → thin adapters → one prioritized report organized by asset**

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

## License

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party engines and data retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
