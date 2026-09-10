# ai-security-scanner

[繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Releases](https://github.com/teddashh/ai-security-scanner/releases)

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

## What runs

| Selected asset | Security checks |
| --- | --- |
| Project folder | Gitleaks, TruffleHog, Semgrep, Trivy, Grype, Checkov, and KICS inspect an isolated read-only snapshot when applicable. |
| Website or API | Nuclei detects the site's technology and selects matching read-only checks from the pinned upstream template snapshot. |
| Internal system | Greenbone detects exposed services on the approved host and ports, then applies matching remote checks from the pinned Community Feed. |
| Infrastructure, cloud, container, or Kubernetes source | The applicable upstream profile runs against the exact selected source and scope. |

Inventory and the localhost TCP utility are supporting tools. They describe assets or connectivity; security findings come from the applicable security checks.

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
