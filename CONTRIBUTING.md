# Contributing

Contributions are welcome, especially complete engine adapters and test fixtures that improve handoff quality without weakening safety boundaries.

The [canonical product specification](docs/product-spec.md) is the sole source of truth for user-visible behavior. Architecture, threat, provider, engine, mapping, maintenance, and release documents are subordinate implementation references. A change must not reintroduce a full-screen setup gate, global readiness, silent scope reduction, all-or-nothing execution, or framework/supply-chain coupling that conflicts with it.

## Before opening a change

Read the [product specification](docs/product-spec.md), [product audit](docs/product-audit.md), [architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [engine catalog](docs/engine-catalog.md). A scanner button or raw report import alone is not an integration.

For product-facing changes, explain how the change preserves:

- the four primary destinations: New scan, Projects, Report, and Settings;
- persistence of the requested run/tasks before disposable dependency preflight;
- independent per-task failure and the complete/partial/no-checks beginner master report;
- event-as-hint plus startup/focus/resume/watchdog reconciliation;
- operation-scoped engine, mapping, signing, update, and publication controls;
- the exact-candidate installed-Windows beginner path and ten-minute first-value gate.

A proposed hard block, durable state, recovery transaction, or global qualification must include the canonical complexity-budget evidence: concrete reproducible harm, why preservation/isolation/warning cannot address it, delayed user work, maintenance owner, tests, and removal condition. Exact irreversible mutation of non-product/user data and execution of an untrusted artifact remain legitimate operation-scoped blocks.

An engine contribution must include:

1. an engine manifest with official source, license, supported version or digest, rule/database revision, resource and network requirements, and distribution mode;
2. a task-local preflight check, performed after the run/task is persisted, and a command plan that does not invoke a shell;
3. explicit asset kinds and required scope permissions;
4. a parser that preserves raw evidence and emits canonical findings;
5. redacted fixtures and adapter contract tests;
6. completed, partial, failed, timed-out, cancelled, and `not_tested` behavior;
7. coverage ledger behavior when the engine cannot run;
8. export and repeat-run comparison behavior;
9. third-party notices and any separate rule, feed, plugin, or database terms.

Active external engines also require tests proving that execution fails closed without an asset-level authorization record.

An engine's admission failure blocks only execution/distribution of that exact artifact. Fixtures must also prove that an unavailable engine leaves sibling tasks running, records `not_tested` coverage, and produces the same partial master report. NIST, ISO 27001, and AIDEFEND relationships are optional finding/evidence references; missing mappings cannot block engine execution or the underlying report.

## Proportional development checks

For a source change that affects the corresponding full frontend/backend boundaries, the baseline commands are:

```bash
npm install
npm run typecheck
npm run build
cargo fmt --all -- --check
cargo test --workspace --no-default-features --features cli
```

Desktop builds additionally require Tauri's platform dependencies.

Run checks proportional to the changed boundary. A documentation or UI-copy change must not require engine publication, installer construction, or three-platform release qualification. Engine admission, platform installer qualification, and publication/signing are separate lanes. When a change affects the beginner journey, modeled CI supports but cannot replace the exact-candidate installed-Windows human acceptance record required for promotion.

## Fixture safety

Never commit real credentials, tokens, customer findings, internal addresses, personal data, or scan reports. Fixtures must be synthetic, redacted, and visibly marked. Reserved example domains and address ranges are preferred.

## Commit and pull request scope

Keep changes focused. Explain which case-lifecycle stages the change affects, what was tested, any license implications, and any new network or filesystem access. Do not hide a safety-relevant behavior change inside a formatting or dependency update.

When changing a subordinate normative document, update contradictory body text in the same change; a precedence banner alone is not sufficient. If implementation still differs from the canonical specification, label it as a current implementation gap rather than restating it as intended behavior.
