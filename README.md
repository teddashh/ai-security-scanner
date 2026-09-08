# ai-security-scanner

[繁體中文](README.zh-TW.md)

## Find security problems without learning a collection of tools

`ai-security-scanner` is a desktop scanner for developers, small teams, and IT owners who want useful findings and clear next steps.

Choose something you own or are allowed to assess. The app guides the setup, runs the applicable checks, and keeps the results in one understandable report.

## What should I scan first?

### A website or API

Enter one exact public `http://` or `https://` URL. The beginner path runs a fixed, pinned Nuclei profile of 13 checks for common exposed files and debug or status endpoints. It sends at most 19 GET requests, limited to 3 requests per second, 2 concurrent requests, and a 10-second timeout.

The scan boundary is the entire `scheme://host:port` origin, not only the path entered in the URL. The path is retained as context while the profile requests its own fixed detector paths. Do not use this quick profile if you are authorized to test only a specific path. It does not sign in, submit forms, follow redirects, or exploit findings, and it does not replace a penetration test.

### A local code or AI project

Choose a project folder. The app scans a private read-only snapshot for applicable risky code patterns, exposed secrets, vulnerable dependencies, and configuration problems.

It does not upload or modify the project, push changes, or test detected credentials against live services.

### Infrastructure files or a container image

Choose infrastructure-as-code files, Kubernetes manifests, or an exported container image. The app checks the exact selected artifact for applicable configuration, package, and known-vulnerability issues.

It does not deploy infrastructure or run the container image. Live cloud and cluster checks are separate advanced paths with their own scope.

Public IPs, approved internal networks, and supported cloud accounts are also available when you are ready to define their exact scope.

## Connectivity is not a vulnerability scan

The collapsed **Test local service connection at 127.0.0.1:9001** utility makes one payload-free TCP connection attempt. It tells you only whether that exact port accepted, refused, or timed out.

That shortcut does not check vulnerabilities, HTTP behavior, other ports, or the rest of the computer. Likewise, “reachable,” “closed,” and “no findings” never mean “secure.” The report names the checks that actually ran.

## Start in three steps

1. **Install the app.** Download a desktop installer from [GitHub Releases](https://github.com/teddashh/ai-security-scanner/releases).
2. **Choose and start a check.** Select a website, local project, configuration artifact, image, network, or account. Review the exact target and limits, then press Start.
3. **Use the report.** Begin with the highest-priority findings, follow the suggested next action, and review anything the scan could not test.

For the most useful first result, scan a real website, project, or artifact you understand. Use the collapsed localhost utility only when you specifically need a port-connectivity check.

## How to read the result

Every report answers five practical questions:

- **What did I ask to scan?** The selected target and limits.
- **What was actually tested?** The checks and target dimensions that completed.
- **What was not tested?** Failed, unavailable, excluded, timed-out, or cancelled work.
- **What was found?** Prioritized findings with severity, confidence, and affected item.
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
