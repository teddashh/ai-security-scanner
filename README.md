# ai-security-scanner

[繁體中文](README.zh-TW.md)

## Find what needs attention—and know what to do next

`ai-security-scanner` is a desktop security scanner for people who do not want to learn a collection of security tools first.

Choose what you want to protect. The app prepares the checks, starts with a quick useful result, and builds one report that explains:

- what you asked it to scan;
- what it actually tested;
- what it could not test;
- what it found; and
- what you can do next.

If one check cannot run, the other checks keep going. The report stays honest about the gap instead of hiding it or throwing away the useful results.

## What can I check?

- **A service on this computer** — start with an exact address such as `127.0.0.1:9001`.
- **A website or API** — check an exact live URL for common exposure and known weaknesses.
- **Public IP addresses or domains** — see which selected services are reachable from the internet.
- **A home or office network** — check an approved internal host or range such as a `/24`.
- **Source code or a local read-only copy of a repository** — find risky code, exposed secrets, vulnerable dependencies, and configuration mistakes without changing the project.
- **An AI application** — check the selected code, dependencies, secrets, and related deployment files, while clearly stating that model behavior was not tested.
- **Advanced sources** — connect an AWS, Azure, Google Cloud, or Microsoft 365 account, or inspect infrastructure as code, an exported container image, or Kubernetes configuration when you need those paths.

## One simple flow

1. **Choose what to protect.** Pick the use case that sounds like your situation.
2. **Review and start.** See the exact target and limits in plain language, then start the check once.
3. **Use the report.** Fix the most important items first, share a readable report, and scan again to compare the result.

The first result should arrive quickly. More complete inventory and deeper checks can continue in the background. You can cancel, reopen the project, and keep every result that was already saved.

## Results that do not pretend

A report can be complete, partial, or contain no completed checks. It never treats “not tested,” “unreachable,” or a failed scanner as secure.

NIST CSF, ISO/IEC 27001, and AIDEFEND references help you understand how a finding relates to a framework. They do not mean that the product certified your organization or proved compliance.

## Current availability

The newest build you can install is the **v0.1.8 public testing prerelease** on the [GitHub Releases page](https://github.com/teddashh/ai-security-scanner/releases). It is offered so the real installer can be tested. It is not a stable or beginner-ready release.

It stays a prerelease because the [release policy](docs/release/README.md) and the product specification let a build be called stable only after a qualifying Windows beginner has completed the installed first-scan journey on that exact build, and after Windows Authenticode signing is verified. Neither record exists yet. The release page and the `release-metadata.json` file published next to the installers list every observed and unobserved path for each artifact.

Before installing:

- Windows may show an **Unknown publisher** warning because Authenticode signing has not been verified;
- the complete first-time setup and localhost-report journey has not been observed on this exact build by an independent beginner; and
- the release page says exactly what was and was not tested. Please report the screen or step where you get stuck.

Every installer is built from the tagged source by the release workflow and published with SHA-256 checksums, SBOMs, and a GitHub build attestation that `gh attestation verify` can check.

If you only want to explore the interface, use the browser demo below. It does not perform a real security assessment.

### Explore the browser demo

The browser demo uses clearly labeled sample data. It does not run security scanners or contact a target.

With Node.js 24 or newer:

```sh
npm ci
npm run dev
```

Open the local address printed by Vite.

## Your data and your scope

Projects, findings, and evidence stay on your device unless you deliberately connect a source or export them. The product does not change scanned source files or automatically apply fixes.

Case data and evidence rely on your operating-system account and disk protections; the app does not add encryption at rest. Anyone with access to your account, an administrator account, or an unprotected disk may be able to read them.

Only scan systems you own or are authorized to assess. The app records the exact selected scope, uses conservative defaults, and must disclose any host, port, path, file, account, stage, or check it did not cover.

## Developer and technical information

The [canonical product specification](docs/product-spec.md) is the sole source of truth for intended product behavior. The [product audit](docs/product-audit.md) is a commit-pinned baseline audit and implementation sequence, not a second specification or a live status dashboard. Other technical documents are subordinate implementation references.

### Local development

Source-checkout prerequisites:

- Node.js 24 or newer;
- Rust 1.98; and
- Tauri's platform dependencies when building the native desktop app.

Run the low-cost web checks:

```sh
npm ci
npm run typecheck
npm run test:frontend
npm run test:component
npm run build
```

Run the Rust core and CLI tests without desktop system libraries:

```sh
cargo test --workspace --no-default-features --features cli
```

Start a native development build after installing Tauri's platform dependencies:

```sh
npm run tauri dev
```

These source-development commands do not prove that the installed Windows beginner journey passed.

### Documentation

- [Canonical product specification](docs/product-spec.md)
- [Whole-repository product audit](docs/product-audit.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Managed runtime implementation reference](docs/managed-runtime.md)
- [Provider authorization implementation reference](docs/provider-authorization.md)
- [Engine catalog](docs/engine-catalog.md)
- [Release, qualification, and publication policy](docs/release/README.md)
- [Windows external qualification plan](docs/release/windows-external-qualification-plan.md) ([Traditional Chinese](docs/release/windows-external-qualification-plan.zh-TW.md))
- [Engine image supply chain](docs/release/engine-image-supply-chain.md)
- [Engine maintenance](docs/engine-maintenance.md)
- [Security policy](SECURITY.md)
- [Third-party inventory](THIRD_PARTY.md)
- [Contributing](CONTRIBUTING.md)

Dated engineering records describe the commit they were written at, not current status:

- [v0.1.8 foreground QC handover](docs/release/v0.1.8-foreground-qc-handover.md)
- [User-facing honesty audit handover](docs/honesty-audit-handover.md)
- [Engine alignment handover (Traditional Chinese)](docs/engine-alignment-handover.zh-TW.md)

### Repository layout

```text
src/                         React desktop interface
src-tauri/                   Rust/Tauri local case service and CLI
engines/catalog.json         Versioned engine registry
engines/images/              Managed engine image sources and publication records
mappings/                    Versioned framework mappings
runtime/                     Managed runtime and gateway manifests
scripts/release/             Release, qualification, and publication tooling
tests/                       Frontend, component, engine, and release contract tests
docs/product-spec.md         Canonical product behavior
docs/product-audit.md        Baseline audit and implementation sequence
```

### License

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party tools and data retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
