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
- **Source code or a GitHub repository** — find risky code, exposed secrets, vulnerable dependencies, and configuration mistakes without changing the project.
- **An AI application** — check the selected code, dependencies, secrets, prompts, and deployment files, while clearly stating what model behavior was not tested.
- **Advanced sources** — connect a cloud account, or inspect infrastructure as code, an exported container image, or Kubernetes configuration when you need those paths.

## One simple flow

1. **Choose what to protect.** Pick the use case that sounds like your situation.
2. **Review and start.** See the exact target and limits in plain language, then start the check once.
3. **Use the report.** Fix the most important items first, share a readable report, and scan again to compare the result.

The first result should arrive quickly. More complete inventory and deeper checks can continue in the background. You can cancel, reopen the project, and keep every result that was already saved.

## Results that do not pretend

A report can be complete, partial, or contain no completed checks. It never treats “not tested,” “unreachable,” or a failed scanner as secure.

NIST CSF, ISO/IEC 27001, and AIDEFEND references help you understand how a finding relates to a framework. They do not mean that the product certified your organization or proved compliance.

## Current availability

The repository is in active development. **There is currently no installer we recommend to beginners for testing the new experience.** The `v0.1.8` source line still contains implementation gaps against the rewritten product specification, so a version number or source checkout is not an install recommendation.

When a qualified installer is ready, it will appear on the [GitHub Releases page](https://github.com/teddashh/ai-security-scanner/releases) with a plain statement of the supported platform and what was actually tested. Until then:

- use the browser demo below only to explore the interface;
- do not treat the demo as a real security assessment; and
- follow development through the [canonical product specification](docs/product-spec.md) and [product audit](docs/product-audit.md).

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

Only scan systems you own or are authorized to assess. The app records the exact selected scope, uses conservative defaults, and must disclose any host, port, path, file, account, stage, or check it did not cover.

## Developer and technical information

The [canonical product specification](docs/product-spec.md) is the sole source of truth for intended product behavior. The [product audit](docs/product-audit.md) records where the current implementation still differs. Other technical documents are subordinate implementation references.

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
- [Security policy](SECURITY.md)
- [Third-party inventory](THIRD_PARTY.md)
- [Contributing](CONTRIBUTING.md)

### Repository layout

```text
src/                         React desktop interface
src-tauri/                   Rust/Tauri local case service and CLI
engines/catalog.json         Versioned engine registry
mappings/                    Versioned framework mappings
docs/product-spec.md         Canonical product behavior
docs/product-audit.md        Current implementation gaps and evidence
```

### License

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party tools and data retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
