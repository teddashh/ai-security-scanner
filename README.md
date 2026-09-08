# ai-security-scanner

[繁體中文](README.zh-TW.md)

## Find security problems without learning a collection of tools

`ai-security-scanner` is a desktop scanner for developers, small teams, and IT owners who want useful findings and clear next steps.

Choose the repositories, internal systems, endpoints, and websites you own or are allowed to assess. The app runs the applicable checks and keeps the results in one report that shows which assets need attention.

## What should I scan first?

### Scan one IT environment

Use one compact setup to add multiple repository folders, complete website or API URLs, and approved internal systems. For each internal system, enter one exact hostname or IP address. Common TCP ports are ready by default; an optional Advanced control lets you replace them with up to 64 exact ports. Review one plan and press Start once.

Internal systems are not divided into vendor-specific paths. The app passes the exact approved host and ports to a pinned Greenbone Community Feed profile. Greenbone detects the exposed products and services, applies the upstream remote checks whose prerequisites match, and returns the findings. Network appliances, servers, workstations, and other TCP-speaking systems all use this same upstream-driven path.

The default profile does not use credentials, expand to neighboring hosts, try default passwords, run denial-of-service checks, or perform local authenticated patch inspection. A completed zero-finding run means Greenbone returned no findings from its applicability-driven checks on the displayed ports. It does not mean that every feed test ran or that the whole device is secure.

When you need to check only one item, use a quick shortcut into the same project model:

- **Website or API.** Enter one exact public `http://` or `https://` URL. Nuclei identifies the website technology and selects matching read-only vulnerability and exposure checks from 4,674 eligible templates in the pinned upstream snapshot. The profile is limited to 10 requests per second, 5 concurrent requests, and a 10-second per-request timeout.

  The scan boundary is the entire `scheme://host:port` origin, not only the path entered in the URL. The path is retained as context while applicable upstream templates may request other paths on that origin. Do not use this quick profile if you are authorized to test only a specific path. It does not sign in, submit forms or request bodies, follow redirects, use out-of-band callbacks, or run exploit-oriented checks, and it does not replace a penetration test. Because Nuclei selects templates from detected technology, completion does not mean all 4,674 templates ran.

- **Local code or AI project.** Choose a project folder. The app scans a private read-only snapshot for applicable risky code patterns, exposed secrets, vulnerable dependencies, and configuration problems.

  Common secret-bearing files such as `.env`, private keys, and `*.tfvars` remain available to the secret scanners even when ignored by Git; ignored dependency, build, and cache directories stay excluded. The app does not upload or modify the project, push changes, or test detected credentials against live services.

- **Infrastructure artifact or container image.** Choose infrastructure-as-code files, Kubernetes manifests, or an exported container image. The app checks the exact selected artifact for applicable configuration, package, and known-vulnerability issues.

  It does not deploy infrastructure or run the container image. Live cloud and cluster checks are separate advanced paths with their own scope.

Supported cloud accounts, infrastructure artifacts, and other specialist sources remain available when you need them.

## Inventory and connectivity are not vulnerability scans

The collapsed **Test local service connection at 127.0.0.1:9001** utility makes one payload-free TCP connection attempt. It tells you only whether that exact port accepted, refused, or timed out.

That shortcut does not check vulnerabilities, HTTP behavior, other ports, or the rest of the computer. Asset inventory, an open port, or a responding service can help select a later check, but none is a vulnerability result. Likewise, “reachable,” “closed,” and “no findings” never mean “secure.” The report names the checks that actually ran.

## Start in three steps

1. **Install the app.** Download a desktop installer from [GitHub Releases](https://github.com/teddashh/ai-security-scanner/releases).
2. **Build the scan project.** Add the repositories, websites, and exact approved internal hosts you want to check—or use a single-target shortcut. Review the exact assets and ports, then press Start once.
3. **Use the unified report.** Every selected asset is shown as problems found, no problems in completed checks, incomplete or failed, or not tested. Start with the assets that need attention and keep every stated limit with the result.

For the most useful first result, select real assets you understand and run their applicable security checks. Use the collapsed localhost utility only when you specifically need a port-connectivity check.

## How to read the result

Every report answers these practical questions:

- **What did I ask to scan?** The selected target and limits.
- **What was actually tested?** The checks and target dimensions that completed.
- **What was not tested?** Failed, unavailable, excluded, timed-out, or cancelled work.
- **Which assets have problems?** Prioritized findings with severity, confidence, and affected item.
- **What should I do next?** A bounded action and the type of expert to involve when needed.

A report may be complete, partial, or contain no completed checks. Completed work is kept even if another check fails. Projects and reports can be reopened, compared with later scans, and exported as readable HTML or structured data.

## Data and authorization

Projects, findings, and evidence stay on your device unless you deliberately connect an external source or export them. The app does not automatically remediate a target.

Only scan systems you own or are authorized to assess. Case data relies on your operating-system account and disk protection; the app does not add its own encryption at rest.

## Browser preview

The browser preview is only for exploring the interface. It uses clearly labeled sample data and never runs a scanner or contacts a target.

```sh
npm ci
npm run dev
```

Open the local address printed by Vite. Node.js 24 or newer is required.

## Development

Source development requires Node.js 24 or newer, Rust 1.98, and Tauri's platform dependencies for desktop builds.

```sh
npm ci
npm run typecheck
npm run test:frontend
npm run test:component
npm run build
cargo test --workspace --no-default-features --features cli
npm run tauri dev
```

## License

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party tools and data retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
