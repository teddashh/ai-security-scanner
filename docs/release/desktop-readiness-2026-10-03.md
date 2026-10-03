# Desktop release delivery — 2026-10-03

[繁體中文](desktop-readiness-2026-10-03.zh-TW.md) · [Release record](v0.3.1.md)

On 2026-10-03 the owner accepted **v0.3.1 on the stable channel** and authorized installer preparation, qualification, publication, and English/Traditional Chinese marketing updates. All three delivery steps are complete: [v0.3.1](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.3.1) is published as stable/latest from frozen source `6b61e9ef72f90174ef7310f80e766aba61c9428d`.

## Previous published desktop baseline

[v0.3.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.3.0) was built from `dddd491b87f90c9cebc5f946d9e2070f36742f21`, not current main. Before the v0.3.1 publication on 2026-10-03, both the GitHub release API and `/releases/latest` identified it as latest with `prerelease: false`. Its published `release-metadata.json` retains `releaseChannel: prerelease`, and its release notes retain the original testing disclosures. This distinction does not change any frozen bytes or qualification observations.

Offered installers are Linux x86-64 Debian, macOS Universal DMG, and Windows x86-64 MSI and NSIS. The published `latest.json` has macOS and Windows NSIS updater targets. Debian and MSI have no artifact-scoped updater. Windows installers are unsigned; macOS is not notarized. See [Release operations](../releasing.md#current-release) for the exact existing disclosures.

## Completed work included in v0.3.1

| Change | Evidence and scope |
| --- | --- |
| Prowler failure headlines | `41e1a4b`: replayed all 14 captured AWS failures; retained all 31 report findings and stable identities. Headlines use the actual failed condition. |
| Approved AWS report grouping | `a458800`: 31 underlying findings appear as 13 report cards. Original evidence, identifiers and actions remain available. Rendered Results and English/Chinese HTML were checked at desktop and narrow widths. |
| Reconnect and blocked continuations | `d60b9b4`, `801a500`: expired read-only connections lead to reconnect; blocked Start/Retry and raw Markdown presentation were corrected. |
| Microsoft 365 integration | Published, pinned ScubaGear `1.8.0-8` and Maester `2.0.0-9`, revised setup and the four approved PIM read permissions. The owner's fresh live rerun remains unobserved. |
| Semgrep combined pack | `b0c4ed4`: published and pinned `1.174.0-4`, with 1,493 legacy upstream rules plus four product rules. Native dual-architecture and managed scans, source/notices, signatures and publication evidence passed. See the [publication record](../engines/semgrep-publication-2026-10-03.md). |
| Image maintenance notes | The [build and update notebook](../engines/image-build-index.md) covers all 25 engine records, their build inputs, rules/data preparation, coupled edits, patches and pitfalls. |

CI, CodeQL and Pages passed for `b0c4ed4a17111987e3debed90778dcdbb4896acd`: [CI 37141380758](https://github.com/teddashh/ai-security-scanner/actions/runs/37141380758), [CodeQL 37141380723](https://github.com/teddashh/ai-security-scanner/actions/runs/37141380723), [Pages 37141379990](https://github.com/teddashh/ai-security-scanner/actions/runs/37141379990). This earlier source baseline verifies the published Semgrep pin; exact v0.3.1 installer evidence is recorded below.

## Coverage fixes found during this review

The shared adapter contract advances from `0.2.2` to `0.2.3`, because unchanged upstream output now produces a different completion warning. Fields and findings retain their existing shapes; all catalog entries use the same contract. Engine images and detection rules are unchanged.

- **kube-bench:** the real CIS 1.11 fixture has 15 PASS, 6 FAIL and 5 WARN checks. WARN means manual review or a check that could not run. The adapter now discloses incomplete automated coverage once, keeps all six failures with their upstream ratings and evidence, and prevents WARN-only reports from claiming a clean result. A PASS-only result remains complete.
- **KICS:** positive `files_failed_to_scan` or `queries_failed_to_execute` counters now withhold completion, even when there are no findings. A malformed declared counter does the same. Valid sibling findings keep their identities, severity and source coordinates. Missing counters in historical reports remain supported, and inline ignored lines alone do not imply a failed check.

Local verification passed on 2026-10-03: 2,072 Rust tests (including real-fixture normalization, the mixed all-engine report in both locales, persistence and the typed node lifecycle), 798 frontend tests with six explicit skips, 515 rendered component tests, 89 CI contracts and 202 release contracts. Rust formatting, all-target CLI Clippy, TypeScript/production build, engine catalog/input validation, and release-policy validation also passed. These are development checks, not installation acceptance for a new desktop candidate.

The coverage implementation is [source commit f0126c0](https://github.com/teddashh/ai-security-scanner/commit/f0126c0791337d258f10b0d68367b78a3660e0fa). Catalog adapter provenance binds to that commit; engine image coordinates and publication-source revisions remain unchanged.

## v0.3.1 version identity

The application, lockfiles, Tauri bundle and managed-gateway product identity are coordinated at 0.3.1 stable. The gateway image remains the published `0.3.0-1` digest and source revision. Runtime and qualification validation retain the exact gateway publication pin independently of the desktop version; a desktop patch does not rebuild unchanged gateway bytes. A future gateway publication must update both `src-tauri/src/gateway_release.rs` and `scripts/release/platform-qualification.mjs` alongside its manifest.

## Completed delivery steps

1. **Version and channel:** coordinated desktop metadata is 0.3.1 stable, with `release.target: 0.3.1`. Exact source CI [37148020161](https://github.com/teddashh/ai-security-scanner/actions/runs/37148020161) and CodeQL [37148020167](https://github.com/teddashh/ai-security-scanner/actions/runs/37148020167) passed.
2. **Installers and actual execution:** candidate [37148617398](https://github.com/teddashh/ai-security-scanner/actions/runs/37148617398), attempt 1, passed all four installer lanes. The downloaded immutable candidate and finalized files verified. A separate exact Debian extracted-layout exercise completed real Gitleaks and Semgrep checks in the app-private runtime, retained four findings and six raw artifacts, saved redacted English/Chinese HTML through the desktop, and preserved identities after reopening. The fresh-runner lane separately installed the Debian package. This automated exercise does not change the human-path `not-observed` records.
3. **Publish frozen bytes:** promotion [37153378798](https://github.com/teddashh/ai-security-scanner/actions/runs/37153378798), attempt 1, passed normal `release-publication` environment approval and published without rebuilding at 2026-10-03 21:05:59 UTC. The public tag points to the frozen source, GitHub reports stable/latest, and all 49 public assets were downloaded anonymously and matched their frozen SHA-256 and lengths.

Exact artifact IDs, digests, installer checksums, updater targets, platform observations and the additional local exercise are in the bilingual [v0.3.1 release record](v0.3.1.md). Current product READMEs, documentation/engine/release introductions, getting-started guides and website copy are updated in English and Traditional Chinese. Website viewport checks at 390, 768 and 1440 pixels in both languages passed without horizontal overflow; language switching, localized metadata and documentation destinations were checked.

## Separate follow-ups

The Microsoft 365 live rerun remains unobserved: the owner runs the updated Windows setup, signs in, and starts verification in the app. Development does not sign in for them or reuse private credentials. The release does not claim that fresh live path passed.

The local exported HTML report has horizontal scrolling at 768 pixels; its 390- and 1440-pixel layouts fit. The content remains available, and tablet-width report layout is recorded for later improvement.

Garak, Agentic Radar and ZAP remain explicitly non-runnable experimental integrations. Their future activation, other engines' next-rebuild maintenance items, OS signing/notarization, and new lifecycle studies are not silently added to this release's scope. Existing disclosures remain accurate, and the product owner decides release positioning.
