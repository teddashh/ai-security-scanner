# ai-security-scanner

`ai-security-scanner` is a local-first desktop workspace for repeatable security assessment cases. It discovers candidate assets, records explicit scan scope, dispatches appropriate open-source engines, preserves evidence, translates findings into plain language, exports a handoff package, and compares a later verification run with the original case.

It does **not** promise that an organization is secure. It does **not** produce an ISO 27001 or NIST audit score. Framework references are coordinates that help a user and a security professional discuss a finding; they are not compliance conclusions.

> Release line: v0.1.1. This source tree contains the case model, local persistence, engine registry, CLI, six-view desktop interface, managed runtime, and clearly labeled synthetic demo data. v0.1.1 is the post-release security and consistency repair line: engine images, rulesets, feeds, and their immutable pins remain the reviewed v0.1.0 set, while the built-in adapter contract advances to v0.1.1. [`engines/catalog.json`](engines/catalog.json) is authoritative for each engine's integration status, runnable state, provider applicability, immutable artifact, adapter, knowledge window, and license disposition. Source text alone does not prove that a GitHub Release or engine image was published; published artifacts carry the signed evidence described in the [release documentation](docs/release/README.md). An engine is runnable only after its manifest, runtime, parser, evidence path, coverage behavior, export, and verification path work end to end.

## Product flow

1. Create an assessment case and describe the organization and data types.
2. Connect inventory sources using provider-hosted read-only authorization where possible.
3. Discover candidate assets from sources that were actually connected.
4. Confirm asset ownership and the allowed scan mode per asset.
5. Automatically run only the engines applicable to those assets and permissions.
6. Preserve raw evidence and normalize every result into the canonical finding model.
7. Show a short priority view without hiding the complete finding list, and let a reviewer group related findings without merging them.
8. Export a local evidence package for any chosen security professional.
9. Re-run the same case after remediation and compare resolved, persistent, new, changed, and unverifiable results.

The coverage ledger deliberately distinguishes “a source was checked and nothing was found” from “no source was connected, so the state is unknown,” and from a reasoned questionnaire declaration that an area is not applicable. Unknown or not-applicable scope is never presented as a green result. Known targets entered during case creation remain untrusted candidates, and requested assessment activities remain intent—not scan authorization.

## Required engine families

The v0.1.0 engine catalog covers:

- Cloud inventory: CloudQuery, Steampipe
- Cloud configuration and IAM: Prowler, ScoutSuite, Cloudsplaining
- Microsoft 365: ScubaGear, Maester
- External attack surface: Naabu, httpx, Nuclei, Greenbone
- Code and secrets: Semgrep, Gitleaks, TruffleHog
- Infrastructure as code: Checkov, KICS
- Containers and SBOM: Trivy, Grype, Syft
- Kubernetes: Kubescape, kube-bench

Each third-party tool remains an independently licensed process or container. See [the engine catalog](docs/engine-catalog.md) and [third-party inventory](THIRD_PARTY.md). A public Git repository is not, by itself, permission to redistribute every binary, image, feed, template, database, or trademark.

## Repository layout

```text
src/                         React desktop UI (six primary views)
src-tauri/                   Rust/Tauri local case service and CLI
engines/catalog.json         Versioned engine registry metadata
docs/product-spec.md         Final product requirements and completion criteria
docs/architecture.md         Process boundaries, domain model, IPC, and runtime design
docs/threat-model.md         Credential, scanner, evidence, export, and AI boundaries
docs/engine-catalog.md       Required and research engine inventory
THIRD_PARTY.md               License and redistribution review ledger
.upstreams/                  Local shallow clones; intentionally ignored by Git
```

## Local development

Prerequisites for a source checkout:

- Node.js 24+
- Rust 1.98 (the release and CI toolchain)
- Tauri platform dependencies for desktop compilation

Supported desktop installers include the release-pinned `managed_local` runtime, so an end user
does not separately install Docker, Podman, Python, PowerShell modules, databases, or individual
engine CLIs. A developer may still use an existing Docker or Podman installation as an explicitly
labeled compatibility provider.

Every installer also places `ai-security-scanner-cli` beside the desktop executable, and each
GitHub Release publishes a separately downloadable copy for every supported platform. Installers
do not add the CLI to `PATH`. Live scan controls remain in the desktop process so its capability
session and worker state cannot diverge from a second process; the CLI handles local planning,
inspection, export, verification records, managed-runtime lifecycle, and exact cleanup.

Install and build the web interface:

```bash
npm install
npm run typecheck
npm run build
```

Run the core and CLI test suite without desktop system libraries:

```bash
cargo test --workspace --no-default-features --features cli
```

Inspect local runtime readiness:

```bash
cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- doctor
```

Create, inspect, and remove a reversible handoff group (the canonical findings and evidence are never deleted):

```bash
cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- finding group \
  --case-id CASE_ID --title "Related access observations" \
  --finding-id FINDING_A,FINDING_B \
  --rationale "Review the shared access path together" \
  --grouped-by "local reviewer"
cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- finding groups CASE_ID
cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- finding ungroup \
  --case-id CASE_ID --group-id GROUP_ID \
  --removed-by "local reviewer" --reason "relationship disproven"
```

For a source checkout, first stage the exact host runtime and pass its location explicitly to the
unpackaged CLI (installed desktop releases resolve their packaged resource automatically):

```bash
node runtime/vendor-managed-runtime.mjs \
  --target x86_64-unknown-linux-gnu \
  --output runtime/staged/managed-runtime
cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- \
  --managed-runtime-bundle runtime/staged/managed-runtime \
  runtime managed install
cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- \
  --managed-runtime-bundle runtime/staged/managed-runtime \
  runtime managed start
```

See [the managed runtime contract](docs/managed-runtime.md) for supported platforms, immutable
vendor locks, lifecycle, recovery, and exact cleanup behavior.

Start the desktop development build after installing Tauri's platform packages:

```bash
npm run tauri dev
```

The browser-only Vite view intentionally switches to a bannered synthetic demo. Demo output is labeled as demo data and never presented as an actual scan.

## Security boundaries

- No scanner engine is allowed to receive administrative credentials.
- Provider read-only authorization is preferred. The administrative fallback belongs in a separate bootstrap broker that may only create and validate a short-lived read-only scan role, then destroy high-privilege material and guide revocation of sessions and keys.
- Active external tools require an explicit asset-level authorization record. Discovery and low-impact connection are not silently treated as permission for active testing.
- Engine processes run without a Docker socket, without host root, with a read-only root filesystem and narrowly scoped mounts and network destinations.
- Findings and raw evidence remain local unless the user explicitly exports them.
- AI skills may explain, inspect status, and call the same constrained CLI. They cannot bypass scope, receive secrets, run unauthorized scans, or perform remediation.
- The product offers advice and verification guidance, never one-click remediation.

Please report security issues according to [SECURITY.md](SECURITY.md), not in a public issue.

## Documentation

- [Product specification](docs/product-spec.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Engine catalog](docs/engine-catalog.md)
- [Managed local runtime](docs/managed-runtime.md)
- [Release and signed updater](docs/release/README.md)
- [Third-party inventory](THIRD_PARTY.md)
- [Contributing](CONTRIBUTING.md)

## License

The project-owned source code is licensed under Apache-2.0. Third-party engines, templates, feeds, rules, and vulnerability databases retain their own licenses and are not relicensed by this repository.
