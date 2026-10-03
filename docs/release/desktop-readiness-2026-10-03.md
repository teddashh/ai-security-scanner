# Desktop release readiness — 2026-10-03

On 2026-10-03 the owner accepted **v0.3.1 on the stable channel** and authorized installer preparation, qualification, publication, and English/Traditional Chinese marketing updates. The coordinated version files and bilingual release notes are being prepared. The current published installer remains v0.3.0 until the frozen v0.3.1 candidate is verified and promoted.

## Published desktop baseline

[v0.3.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.3.0) was built from `dddd491b87f90c9cebc5f946d9e2070f36742f21`, not current main. On 2026-10-03, both the GitHub release API and `/releases/latest` identify it as the latest release with `prerelease: false`. Its published `release-metadata.json` retains `releaseChannel: prerelease`, and its release notes retain the original testing disclosures. This distinction does not change any frozen bytes or qualification observations.

Offered installers are Linux x86-64 Debian, macOS Universal DMG, and Windows x86-64 MSI and NSIS. The published `latest.json` has macOS and Windows NSIS updater targets. Debian and MSI have no artifact-scoped updater. Windows installers are unsigned; macOS is not notarized. See [Release operations](../releasing.md#current-release) for the exact existing disclosures.

## Completed main work for the next desktop

| Change | Evidence and scope |
| --- | --- |
| Prowler failure headlines | `41e1a4b`: replayed all 14 captured AWS failures; retained all 31 report findings and stable identities. Headlines use the actual failed condition. |
| Approved AWS report grouping | `a458800`: 31 underlying findings appear as 13 report cards. Original evidence, identifiers and actions remain available. Rendered Results and English/Chinese HTML were checked at desktop and narrow widths. |
| Reconnect and blocked continuations | `d60b9b4`, `801a500`: expired read-only connections lead to reconnect; blocked Start/Retry and raw Markdown presentation were corrected. |
| Microsoft 365 integration | Published, pinned ScubaGear `1.8.0-8` and Maester `2.0.0-9`, revised setup and the four approved PIM read permissions. The owner's fresh live rerun remains unobserved. |
| Semgrep combined pack | `b0c4ed4`: published and pinned `1.174.0-4`, with 1,493 legacy upstream rules plus four product rules. Native dual-architecture and managed scans, source/notices, signatures and publication evidence passed. See the [publication record](../engines/semgrep-publication-2026-10-03.md). |
| Image maintenance notes | The [build and update notebook](../engines/image-build-index.md) covers all 25 engine records, their build inputs, rules/data preparation, coupled edits, patches and pitfalls. |

CI, CodeQL and Pages passed for `b0c4ed4a17111987e3debed90778dcdbb4896acd`: [CI 37141380758](https://github.com/teddashh/ai-security-scanner/actions/runs/37141380758), [CodeQL 37141380723](https://github.com/teddashh/ai-security-scanner/actions/runs/37141380723), [Pages 37141379990](https://github.com/teddashh/ai-security-scanner/actions/runs/37141379990). That verifies the published Semgrep pin and source baseline; it is not installer acceptance for the next desktop.

## Coverage fixes found during this review

The shared adapter contract advances from `0.2.2` to `0.2.3`, because unchanged upstream output now produces a different completion warning. Fields and findings retain their existing shapes; all catalog entries use the same contract. Engine images and detection rules are unchanged.

- **kube-bench:** the real CIS 1.11 fixture has 15 PASS, 6 FAIL and 5 WARN checks. WARN means manual review or a check that could not run. The adapter now discloses incomplete automated coverage once, keeps all six failures with their upstream ratings and evidence, and prevents WARN-only reports from claiming a clean result. A PASS-only result remains complete.
- **KICS:** positive `files_failed_to_scan` or `queries_failed_to_execute` counters now withhold completion, even when there are no findings. A malformed declared counter does the same. Valid sibling findings keep their identities, severity and source coordinates. Missing counters in historical reports remain supported, and inline ignored lines alone do not imply a failed check.

Local verification passed on 2026-10-03: 2,072 Rust tests (including real-fixture normalization, the mixed all-engine report in both locales, persistence and the typed node lifecycle), 798 frontend tests with six explicit skips, 515 rendered component tests, 89 CI contracts and 202 release contracts. Rust formatting, all-target CLI Clippy, TypeScript/production build, engine catalog/input validation, and release-policy validation also passed. These are development checks, not installation acceptance for a new desktop candidate.

The coverage implementation is [source commit f0126c0](https://github.com/teddashh/ai-security-scanner/commit/f0126c0791337d258f10b0d68367b78a3660e0fa). Catalog adapter provenance binds to that commit; engine image coordinates and publication-source revisions remain unchanged.

## v0.3.1 preparation

The application, lockfiles, Tauri bundle and managed-gateway product identity are coordinated at 0.3.1 stable. The gateway image remains the published `0.3.0-1` digest and source revision. Runtime and qualification validation retain the exact gateway publication pin independently of the desktop version; a desktop patch does not rebuild unchanged gateway bytes. A future gateway publication must update both `src-tauri/src/gateway_release.rs` and `scripts/release/platform-qualification.mjs` alongside its manifest.

## Remaining delivery work

1. Owner decision recorded: v0.3.1, stable. Update the coordinated desktop version files and finish the bilingual release notes. The already-published `v0.3.0` tag is immutable and cannot identify new installer bytes.
2. Finish changed-boundary validation, push the exact candidate source to main, and check its CI and CodeQL results.
3. Run **Release desktop installers** on that exact main source. Verify the offered installer set and its frozen checksums, runtime manifests, notices, updater payloads and qualification observations.
4. Check the installed candidate with isolated test data: controlled project scan, terminal Results, saved report, reopen and readable HTML export. Preserve the owner's live app and cases. Record platform limits from what the exact candidate actually demonstrated.
5. Promote the frozen candidate through the existing publication workflow when its delivery checks are complete. Publish those bytes without rebuilding and verify the public release assets. The workflow's `release-publication` environment remains the external publication boundary.

The Microsoft 365 live rerun is a separate, explicit follow-up: the owner runs the updated Windows setup, signs in, and starts verification in the app. Development does not sign in for them or reuse private credentials. Packaging can proceed while that follow-up is pending; the release must not claim the latest live Microsoft 365 path passed.

Garak, Agentic Radar and ZAP remain explicitly non-runnable experimental integrations. Their future activation, other engines' next-rebuild maintenance items, OS signing/notarization, and new lifecycle studies are not silently added to this release's scope. Existing disclosures remain accurate, and the product owner decides release positioning.
