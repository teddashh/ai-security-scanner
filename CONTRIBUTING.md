# Contributing

Contributions are welcome, especially complete engine adapters and test fixtures that improve handoff quality without weakening safety boundaries.

## Before opening a change

Read the [product specification](docs/product-spec.md), [architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [engine catalog](docs/engine-catalog.md). A scanner button or raw report import alone is not an integration.

An engine contribution must include:

1. an engine manifest with official source, license, supported version or digest, rule/database revision, resource and network requirements, and distribution mode;
2. a preflight check and a command plan that does not invoke a shell;
3. explicit asset kinds and required scope permissions;
4. a parser that preserves raw evidence and emits canonical findings;
5. redacted fixtures and adapter contract tests;
6. completed, partial, failed, and not-executed behavior;
7. coverage ledger behavior when the engine cannot run;
8. export and repeat-run comparison behavior;
9. third-party notices and any separate rule, feed, plugin, or database terms.

Active external engines also require tests proving that execution fails closed without an asset-level authorization record.

## Development checks

```bash
npm install
npm run typecheck
npm run build
cargo fmt --all -- --check
cargo test --workspace --no-default-features --features cli
```

Desktop builds additionally require Tauri's platform dependencies.

## Fixture safety

Never commit real credentials, tokens, customer findings, internal addresses, personal data, or scan reports. Fixtures must be synthetic, redacted, and visibly marked. Reserved example domains and address ranges are preferred.

## Commit and pull request scope

Keep changes focused. Explain which case-lifecycle stages the change affects, what was tested, any license implications, and any new network or filesystem access. Do not hide a safety-relevant behavior change inside a formatting or dependency update.
