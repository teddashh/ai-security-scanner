# ai-security-scanner

[Project website](https://teddashh.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Downloads](https://github.com/teddashh/ai-security-scanner/releases)

Find security problems in your code, websites and company systems. Get one report that explains what needs attention, why it matters and what to do next.

Choose what to check in the desktop app. It selects suitable security tools and brings their results together. You can start with one folder or website, or check several parts of your IT environment at once.

## Run your first scan

1. [Download v0.4.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0) for Windows, macOS or Linux and [follow the install steps](docs/getting-started.md#install). The app prepares its scanning tools; you do not need to install Docker.
2. Open the app and choose **Scan my environment**, **Check a website**, or **Check code or an AI project**. Add the folders, URLs or internal systems you want to check.
3. Review the listed targets and checks. Confirm that you may scan any network targets, then start the scan in the app window.
4. When the scan ends, open **Results**. Choose **Save or share report**, then **Save HTML report** to save a report you can open in a browser.

The first scan may take longer while tools download. Later scans can use those tools again. The [walkthrough](docs/getting-started.md#from-new-scan-to-an-html-report) shows each screen.

## What can it check?

| What you choose | What you learn |
| --- | --- |
| Project folders, including AI projects | Whether supported files contain exposed passwords or keys, risky code, vulnerable software packages or unsafe settings. Your project is copied for inspection, not run or changed. |
| Websites and APIs | Whether the approved website has known vulnerabilities or exposed information. Checks stay within the address and limits shown before you start. |
| Internal systems | Which services are available on the approved hosts and ports, and which security problems the applicable checks find. An open port alone is not a vulnerability. |
| Cloud accounts and Microsoft 365 | What the supported account and access checks find. AWS, Azure and GCP currently cover selected identity and permission settings; they do not provide a complete cloud audit. |
| Deployment files, containers and Kubernetes | Whether supported files or container contents have known package vulnerabilities or unsafe settings. Available checks depend on the input you provide. |

Optional AI checks can map supported workflows, inspect MCP configuration, or test one approved model endpoint. The model test sends 54 fixed prompts and may incur provider charges; you review those limits before starting. See [what each scan covers](docs/scanning-scope.md).

## A report you can act on

Start with the problems that need attention first. Each includes the affected system or file, why the problem matters and a practical next step. Technical details retain the scanner's original evidence, rating and recommendation for whoever will investigate or make the fix.

The report also tells you what was checked and what was not. If one check fails, completed results remain available. “No problems found” applies to the completed checks, not every possible risk. The app suggests fixes; it does not make them for you.

You can reopen reports, compare compatible scans and share an English or Traditional Chinese HTML copy. Unredacted exports can include the original scanner reports as ZIP attachments at the end. See [how to read and share results](docs/results-and-exports.md).

### See an example

[Open the example report](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html), or [choose another language or disclosure level](https://teddashh.github.io/ai-security-scanner/sample-reports.html).

These examples use simulated data: 62 findings and 42 inventory observations across all 25 tools. They show the report format, not the security of a real company. Inventory is listed separately from security problems. [How the examples were made](docs/samples/v0.4.0/README.md).

## Get help from Claude Code or Codex

An assistant running on your computer can help install the app, check setup, explain findings and save the report. You select the targets and start, pause or resume scans in the desktop app.

Open this repository in your assistant and ask:

> Use the ai-security-scanner skill to install the app, guide me through my first scan and save the final HTML report.

Use the [Claude Code skill](.claude/skills/ai-security-scanner/SKILL.md) or the [Codex skill](.codex/skills/ai-security-scanner/SKILL.md). An assistant running elsewhere can provide instructions and download links. It cannot install the app on your computer. [Assistant setup](docs/getting-started.md#use-with-an-agent-skill).

## Your data and access

Projects, findings and evidence are stored on your computer. Local code checks do not upload or execute your project. Website and cloud checks contact the services you approve. Saving an HTML report creates a local file; you decide whether to share it.

Cloud sign-in and cloud permissions are separate. A login can expire while the permissions created during setup remain. Microsoft 365 has an optional [cleanup script](cloud-setup/README.md#english-quick-reference) that waits for a selected scan, saves its report, and removes the recorded setup changes. AWS also has a [temporary-access mode and matching cleanup](cloud-setup/README.md#aws-專用存取與清理). Keep the cleanup window open; an expired administrator sign-in may need renewing. These are optional workflows, not yet the desktop default, and do not remove older, unrecorded AWS or Azure permissions.

## The tools behind the report

The app brings together 25 open-source tools. Each keeps its own detection rules; the app organizes their results and explains what to do next. [Read the tool guide](https://teddashh.github.io/ai-security-scanner/scanner-guide.html) for uses, limits and versions.

<details>
<summary>Tool-by-tool technical reference</summary>

### Repositories, dependencies, and infrastructure as code

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Semgrep](https://github.com/semgrep/semgrep) | Static analysis for risky code patterns using 1,493 pinned legacy upstream rules plus four product rules. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Offline secret-pattern scanning with secret values redacted from normal evidence. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Offline filesystem secret detection; network verification is disabled. |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerable packages in recognized repository manifests and single-image OCI layouts using pinned offline data. |
| [Grype](https://github.com/anchore/grype) | Vulnerable packages in repository snapshots and single-image OCI layouts using pinned offline data. |
| [Checkov](https://github.com/bridgecrewio/checkov) | Applicable infrastructure and configuration checks across the selected read-only snapshot. |
| [KICS](https://github.com/Checkmarx/kics) | Infrastructure-as-code misconfiguration checks from the upstream query pack. |
| [Syft](https://github.com/anchore/syft) | Software component inventory and preserved SBOM output; inventory is not a vulnerability result. |

The released catalog pins the Grype image to **`0.117.0-4`**, digest `sha256:56b0d675…`. It can scan local repository dependencies for known vulnerabilities; a controlled repository scan recorded **81 Grype findings**. That is a fixture result, not an expected count for every project. See the [exact pin and recorded result](docs/engine-catalog.md#grype-repository-support).

### Websites and internal systems

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Technology-aware, bounded read-only HTTP security checks from a pinned [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) snapshot. |
| [ZAP](https://github.com/zaproxy/zaproxy) | Optional page-crawling and upstream passive response checks for one approved origin. |
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

### AI workflows and MCP configuration

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Agentic Radar](https://github.com/splx-ai/agentic-radar) | Optional offline workflow inventory for LangGraph, CrewAI, n8n, OpenAI Agents, and AutoGen in one approved repository snapshot. It does not execute the workflow or contact a model. |
| [Garak](https://github.com/NVIDIA/garak) | Optional model behavior checks against one approved HTTPS chat API/model with 54 native DAN/ANSI prompts, one-shot local keys and explicit inference limits/provider charges. |
| [MCP Armor](https://github.com/aira-security/mcp-armor) | Static checks over one approved MCP configuration snapshot for hardcoded credentials and excessive tool permissions, without starting or contacting an MCP server or loading a model. |

Discovery, inventory, SBOM generation, and the localhost TCP utility remain clearly separated from vulnerability findings. The complete pinned versions, licenses, profiles, and execution boundaries are recorded in the [engine catalog](docs/engine-catalog.md).

Exact scan boundaries and profile behavior are documented in [Scanning scope](docs/scanning-scope.md).

Tools still under evaluation are tracked separately and are not available for scans.


</details>

## More information

- [Getting started](docs/getting-started.md)
- [Scan coverage](docs/scanning-scope.md)
- [Reading and sharing results](docs/results-and-exports.md)
- [Current development status](docs/development-status.md)
- [Changes in v0.4.0](docs/release/v0.4.0.md) · [Earlier changes in v0.3.1](docs/release/v0.3.1.md)
- [Contributing](CONTRIBUTING.md) · [Contributors](CONTRIBUTORS.md) · [Security policy](SECURITY.md)

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
