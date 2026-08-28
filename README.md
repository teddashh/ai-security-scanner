# ai-security-scanner

[繁體中文說明](README.zh-TW.md)

## Find security problems without becoming a security-tool expert

**Check your website, public IPs, internal systems, AI apps and agents, source code, infrastructure as code, cloud, containers, and Kubernetes from one desktop app.** Start with what you want to protect—not a wall of scanner names—and get a clear list of what needs attention.

`ai-security-scanner` brings proven open-source security tools into one guided workflow. It chooses checks that fit your situation, turns technical output into useful next steps, keeps the evidence together, and lets you verify what changed after a fix.

### What can you check?

- **A live website or API** — uncover exposed services and known vulnerabilities.
- **External IP addresses or domains** — understand what is reachable from the internet.
- **An internal IT environment** — check selected systems or configuration snapshots.
- **An AI app or agent you are building** — check vibe-coded and AI-assisted software, with applicable AIDEFEND references in the results.
- **Source code** — find risky patterns and exposed secrets locally without changing your files.
- **Infrastructure as code** — catch cloud and deployment mistakes before they ship.
- **AWS, Azure, GCP, or Microsoft 365** — review assets, configuration, identity, and permissions.
- **Container images** — find vulnerable packages and create a software inventory (SBOM).
- **Kubernetes** — review workload configuration and node security posture.

### From “what should I check?” to “what should I fix?” in three steps

1. **Choose your goal.** Pick the situation that matches what you want to inspect.
2. **Add your target.** Select a project, enter a website or IP, or connect a cloud account with read-only access.
3. **Run the check.** See the most important findings first, open the evidence when you need it, and re-run after a fix to confirm the difference.

### Why use ai-security-scanner?

- **One clear workflow:** no need to install, learn, and reconcile a toolbox full of scanners.
- **Results written for humans:** understand the problem, the affected asset, and the next useful action.
- **Your data stays with you:** scan projects and detailed results remain on your computer unless you export them.
- **Always know where you stand:** see what was checked, what is still waiting, and where more information is needed.
- **Frameworks without the paperwork wall:** relate applicable findings to NIST CSF, ISO 27001, and AIDEFEND while keeping the result focused on what to fix.
- **Easy to share and verify:** export a clear report and compare results after a fix.

## Try the guided demo

See how a website check moves from setup to a prioritized fix list using ready-made sample results. It runs in your browser, so you can explore the complete experience right away. [Open the browser demo instructions](#browser-demo).

## Want the details?

<!-- Release line: v0.1.7. -->

> **Project status:** `v0.1.7` is a Windows-first public pre-release shaped by a full hands-on app walkthrough. Setup is simpler, network scans accept an IP or domain, live progress is more dependable, and a stopped scan tells you what happened.

Most people can start with the product flow above. If you are evaluating deployment, permissions, isolation, integrations, or release evidence, use these references:

- [Product specification](docs/product-spec.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Provider authorization](docs/provider-authorization.md)
- [Managed local runtime](docs/managed-runtime.md)
- [Engine catalog](docs/engine-catalog.md)
- [Release pipeline and evidence](docs/release/README.md)

The remaining sections keep the complete operating and engineering details in one place without making them the product introduction.

### What the product is—and what results mean

`ai-security-scanner` is a local-first desktop application that turns a security check into a repeatable case. Tell it what you want to inspect, confirm the exact scope, run the applicable open-source engines in an isolated local environment, review the evidence in plain language, export a handoff package, and compare a later verification run with the original result.

It does **not** promise that an organization is secure, replace a qualified security professional, or produce an ISO 27001, NIST, or AIDEFEND certification score. A framework reference is a coordinate for discussion, not a compliance conclusion. “No finding” is also not the same as “everything was checked.”

### Detailed use-case guide

You do not need to choose scanner names. Choose the situation that sounds like yours. This detailed view explains what to prepare and how each check is bounded:

| Use case | What you bring | What the product does—and its boundary |
| --- | --- | --- |
| A website or API that is already online | An exact URL, proof that you may test it, and the allowed scan intensity | Checks approved reachable services and vulnerabilities with target/rate limits. It does not test business logic or replace a penetration test. |
| External IP addresses or domains | Exact public IPs/domains, ownership or authorization evidence, and exclusions | Checks only the approved targets. It does not expand into neighboring addresses or call an unreachable target secure. |
| An internal IT environment | Exact internal targets or configuration snapshots, a reachable test location, limits, and IT-owner approval | Runs bounded checks against approved systems or analyzes attached evidence. It does not sweep an undefined private network, install agents, or change devices. |
| An AI app or agent you are building | A read-only local project or repository snapshot explicitly identified as an AI application | Checks code, secrets, dependencies, and related deployment files locally; applicable findings also receive selected AIDEFEND relationship coordinates. It does not upload or change files and does not claim framework compliance. |
| Source code you have written | A read-only local project or repository snapshot | Checks code and secret patterns locally, masks detected secret values in results, and never changes project files. It does not upload code or verify discovered secrets against live services. |
| Infrastructure as code | Terraform, CloudFormation, Kubernetes YAML, or another local IaC project | Checks selected files for risky defaults and configuration mistakes. It does not deploy or modify them. |
| AWS, Azure, GCP, or Microsoft 365 | One exact account, subscription, project, or tenant plus permission to assess it | Uses a provider-hosted, short-lived, read-only sign-in path. It does not ask a scanner for administrator access or change cloud settings. |
| A container image | One exact local image artifact or OCI layout with a fixed digest | Finds known vulnerable packages and produces an SBOM with pinned offline data. It does not run the image, log in to a registry, or scan an ambiguous `latest` tag. |
| Kubernetes configuration | Selected manifests or an approved immutable node-configuration snapshot | Checks workload posture and the bounded node CIS profile. It does not request cluster-admin access, mount a live host, or provide continuous runtime monitoring. |

Choosing a use case prepares the next setup screen; it never authorizes a scan. The application still requires exact targets, ownership, allowed activity, and limits before contacting a system. Other areas stay available in the same case, so this simpler start does not reduce product scope.

### What a complete case looks like

1. Choose what you want to check and create a case.
2. Add an exact local artifact, target list, or provider source.
3. Confirm ownership and what kind of contact is allowed for each target.
4. Let the application choose only the engines that match those assets and permissions.
5. Keep raw evidence and normalized findings together in the local case.
6. Review urgent items without hiding the complete finding list.
7. See the difference between scanned, incomplete, not authorized, not applicable, and unknown coverage.
8. Export a local handoff package for an independent security professional.
9. Re-run the same case after remediation and compare resolved, persistent, new, changed, and unverifiable results.

A source that was checked and contained no assets is different from a source that was never connected. The coverage ledger preserves that distinction and never paints unknown coverage green.

### Privacy, credentials, and scan authorization

- Case data and raw evidence stay on the workstation unless the user explicitly exports them.
- Scanner engines never receive administrator credentials.
- Cloud access prefers the provider's official short-lived, read-only authorization flow. Any administrative bootstrap work runs in a separate one-shot broker and is not passed to scanners.
- Public and internal targets require a traceable, asset-level authorization record. Discovery is not silently treated as permission for active testing.
- Engines run rootless in isolated containers with read-only inputs, no Docker socket, no host root, limited resources, and narrowly declared network destinations.
- The product offers explanations and verification guidance, not one-click remediation.
- AI integrations may explain status or use the constrained local CLI. They cannot widen scope, receive secrets, authorize a target, or bypass the same product controls.

Read the [threat model](docs/threat-model.md), [provider authorization contract](docs/provider-authorization.md), and [security policy](SECURITY.md) before using the project with sensitive systems. Report vulnerabilities according to `SECURITY.md`, not in a public issue.

### Managed isolated runtime

Installed desktop packages carry a pinned, product-managed Podman machine client and platform helpers. The user does not separately install Docker, Podman, Python, PowerShell modules, vulnerability databases, or individual engine CLIs.

The installed desktop app prepares its private scan tools automatically on first launch, before the scan workspace appears. It verifies the packaged runtime and checks the computer **before** downloading the checksum-locked machine image, then initializes a private rootless machine while showing progress. Downloads can be cancelled and resumed. The application does not modify the system `PATH` or use a package manager.

On Windows, an already-ready WSL 2 setup requires no click. If the automatic read-only check proves that WSL must be installed or updated, the first-launch screen shows one clear action and Windows asks for administrator approval once. ai-security-scanner runs only Microsoft's trusted `wsl.exe` with the fixed action needed; it never receives or stores the administrator password. If Windows needs a restart, the app stops before the roughly 257 MB machine-image download. Reopen ai-security-scanner after restarting and setup continues automatically. Manual Microsoft commands remain under **Other ways**.

| Desktop host | Managed provider | Host prerequisite |
| --- | --- | --- |
| Linux x86-64 | Rootless Podman machine with packaged QEMU | None; KVM is used when available, otherwise slower QEMU software emulation is used. |
| macOS Intel or Apple silicon | Rootless Podman machine with Apple virtualization | A supported macOS release with Apple virtualization support. |
| Windows x86-64 | Rootless Podman machine with WSL | WSL 2. If it is unavailable or outdated, one explicit Windows approval lets the app prepare it; a required restart remains a visible user action. |

Docker or a user-installed Podman can be selected only as an explicitly labeled compatibility provider; they are not required or silently mixed with managed runs. See the [managed runtime contract](docs/managed-runtime.md) for lifecycle, recovery, verification, and exact cleanup behavior.

### Included assessment families

The required `v0.2.0` catalog covers these end-to-end engine families:

- cloud inventory: CloudQuery and Steampipe;
- cloud configuration and identity: Prowler, ScoutSuite, and Cloudsplaining;
- Microsoft 365: ScubaGear and Maester;
- external surface and network vulnerability checks: Naabu, httpx, Nuclei, and Greenbone;
- source code and secrets: Semgrep, Gitleaks, and TruffleHog;
- infrastructure as code: Checkov and KICS;
- container packages and SBOMs: Trivy, Grype, and Syft; and
- Kubernetes posture: Kubescape and kube-bench.

Each engine is a separately licensed process or container with a pinned artifact, rules/data provenance, permission profile, parser, evidence path, coverage behavior, export mapping, and verification path. The machine-readable [`engines/catalog.json`](engines/catalog.json) is authoritative for whether an engine is integrated, runnable, applicable to a provider, within its knowledge window, and approved for a particular distribution mode. A repository URL or friendly sentence never upgrades a blocked catalog entry.

See the [engine catalog guide](docs/engine-catalog.md) and [third-party inventory](THIRD_PARTY.md). Third-party code, images, templates, rules, feeds, and vulnerability databases keep their own licenses and are not relicensed by this project.

### Demo mode

Running the Vite interface in a browser shows a clearly marked synthetic demo. It does not start a scanner and it does not represent a real assessment. Native desktop builds use the Rust local case service and managed runtime.

### Browser demo

With Node.js 24 or newer:

```sh
npm ci
npm run dev
```

Open the local URL printed by Vite.

### Local development

Source-checkout prerequisites:

- Node.js 24 or newer;
- Rust 1.98, matching the release and CI toolchain; and
- Tauri's platform build dependencies when compiling the desktop shell.

Install dependencies and verify the web interface:

```sh
npm ci
npm run test:frontend
npm run typecheck
npm run build
```

Run the Rust core and CLI suite without desktop system libraries:

```sh
cargo test --workspace --no-default-features --features cli
```

Start the browser demo:

```sh
npm run dev
```

Start a native desktop development build after installing Tauri's platform packages:

```sh
npm run tauri dev
```

### Local CLI

Every desktop installer places `ai-security-scanner-cli` beside the application executable. It is intentionally not added to `PATH`. Live scan controls stay in the desktop process so its authorization capability and worker state cannot diverge from a second process. The CLI handles local planning, inspection, export, verification records, managed-runtime lifecycle, and exact cleanup.

Inspect readiness from a source checkout:

```sh
cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- doctor
```

For an unpackaged CLI, stage the exact target runtime and pass it explicitly:

```sh
node runtime/vendor-managed-runtime.mjs \
  --target x86_64-unknown-linux-gnu \
  --output runtime/staged/managed-runtime

cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- \
  --managed-runtime-bundle runtime/staged/managed-runtime \
  runtime managed install
```

See [the CLI and agent skill](.codex/skills/ai-security-scanner/SKILL.md) for constrained operational workflows. That skill cannot handle credentials, approve or widen scope, contact an unapproved target, or perform remediation.

### Repository layout

```text
src/                         React desktop interface
src-tauri/                   Rust/Tauri local case service and CLI
engines/catalog.json         Authoritative versioned engine registry
mappings/                    Versioned control and export mappings
bootstrap/                   Fixed provider read-only bootstrap definitions
docs/product-spec.md         Final requirements and completion criteria
docs/architecture.md         Process boundaries, domain model, IPC, and runtime design
docs/threat-model.md         Credential, scanner, evidence, export, and AI boundaries
docs/usability/              Real-person study protocol and evidence schema
.upstreams/                  Local shallow research clones; ignored by Git
```

### Release and evidence status

`v0.1.7` is the Windows-first public testing preview for the planned `v0.2.0` release. It carries the Candidate 11 improvements produced through a hands-on Windows app walkthrough: first launch recognizes what is already installed, prepared scans start from the action the user chose, public and internal network checks accept an IP or domain, and live activity cannot lose the events emitted while a scan is starting. A stopped check keeps its saved evidence, shows a useful next step, and can export a redacted diagnostic. Project imports also fail open when ignore rules cannot be trusted, so files are retained rather than silently omitted. The app still waits for an explicit Start action before contacting a target.

The release workflow builds native Linux, universal macOS, and Windows installers, observes an installed desktop startup on each platform, and then runs a fresh-host managed-runtime lifecycle and fixed isolated-container qualification. A finalized candidate also contains checksums, CycloneDX and SPDX SBOMs, notices, updater signatures, platform qualification records, and GitHub build provenance.

Manual workflow dispatch from `main` is preflight-only: it cannot create a tag or public GitHub Release. A tagged preview publishes with GitHub's **Pre-release** label and does not replace the latest stable release. Apple Developer ID/notarization and Windows Authenticode are not configured, so operating systems may still show an unidentified-developer warning; Tauri updater signing is a separate integrity control and does not claim OS publisher identity.

Before the stable `v0.2.0` publication, the project still requires:

1. a genuine observed first-run study with a qualifying IAM-naive adult participant, using a clean supported desktop installation and a disposable cloud account;
2. passing, redacted evidence validated against the exact candidate commit; and
3. formal QC and code review after that product study.

Automated tests, contributor walkthroughs, and generated evidence cannot substitute for the participant. See the [study protocol](docs/usability/iam-naive-first-run.md) and [release pipeline](docs/release/README.md).

### Documentation

- [Product specification](docs/product-spec.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Provider authorization](docs/provider-authorization.md)
- [Engine catalog](docs/engine-catalog.md)
- [Managed local runtime](docs/managed-runtime.md)
- [Release and signed updater](docs/release/README.md)
- [IAM-naive first-run study](docs/usability/iam-naive-first-run.md)
- [Third-party inventory](THIRD_PARTY.md)
- [Contributing](CONTRIBUTING.md)

### Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and follow the repository's scope, evidence, fixture, license, and security-boundary requirements. The project-owned source is licensed under [Apache-2.0](LICENSE). Third-party components retain their own licenses.
