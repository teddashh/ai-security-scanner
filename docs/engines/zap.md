# OWASP ZAP

Crawls one approved website origin and applies ZAP's upstream passive scan rules to the responses it observes, with no attack payloads, under the profile `zap_passive_v1`. It is experimental and cannot run: catalog `compatibility.runnable` is false and three blockers remain.

| Item | Value |
| --- | --- |
| Upstream | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) 2.17.0, revision `2665d972f6d587ba4773a95053ac39af3fdf8df9`; rule pack `pscanrules-75.0.0` |
| Image | Official upstream `ghcr.io/zaproxy/zaproxy:2.17.0`, verified on 2026-09-23 with `docker buildx imagetools inspect` and its OCI labels (`attested_match`). The digest is pinned in `engines/catalog.json` and `engines/images/zap/plan.json` |
| Build inputs | None. `engines/images/zap/plan.json` only (`build_recipe` null, no Dockerfile) |
| Launcher | None. Upstream entrypoint `/zap/zap.sh` with `-Xmx1200m -cmd -silent -dir /tmp/zaphome -autorun /run/ai-security-scanner/zap-plan.yaml`. The plan comes from `build_zap_passive_plan` in `src-tauri/src/zap_work_plan.rs` |
| Adapter | `extract_zap`, `zap_severity` and `zap_confidence` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | None (official image) |

## Local build and update entry

There is no local Dockerfile. This integration uses the catalog’s digest-pinned upstream image; update acquisition/provenance and the product invocation together. The existing execution blockers remain in force.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Why it cannot run.** `PinnedImage::from_manifest` (`src-tauri/src/container_runtime.rs`) refuses any manifest with a `release_blocker()` (`src-tauri/src/domain.rs`). Catalog `compatibility.blocked_by` and `plan.json` `blockers`: no scope-grant profile exists for a ZAP website scan; the generated plan is not delivered into a run; ZAP enforces no requests-per-second limit and the gateway bounds connections, not requests.
- **Plan.** `build_zap_passive_plan(approved_origin, gateway, bounds, report_dir, report_file_stem)` emits one context `approved` with `includePaths` `\Q<origin>\E.*`, the gateway in `env.configs` (`network.connection.socksProxy.enabled`, `.host`, `.port`, `.version` 5, `.dns` true), `failOnError` true, and four jobs: `passiveScan-config` (in scope only, at most 100 alerts per rule), `spider` (`postForm` and `processForm` false; depth at most 20, children 100, 60 minutes, 5 threads), `passiveScan-wait` (at most 60 minutes), and `report` with template `traditional-json`. An origin with userinfo, a query, a fragment or `\E` is refused. The plan is JSON, at most 64 KiB, which ZAP's SnakeYAML parser accepts (bf89765). The job set is a closed enum, so active scan jobs cannot be added.
- **Mount.** `ContainerPlanBuilder::with_zap_plan_file` mounts the plan read-only at `/run/ai-security-scanner/zap-plan.yaml` with the label `ai.security-scanner.zap-plan-sha256`, only for the ZAP manifest and only as the argument of `-autorun` (423dc8b). Only tests call it today.
- **Output.** The catalog expects `/output/zap.json` (`adapter_state` `workspace_unreleased`).
- **Mapping.** `extract_zap` reads `site[].alerts[]`. An alert needs `pluginid`, `alert`, a string `riskcode` (0 to 3: Informational, Low, Medium, High), a string `confidence` (0 to 4: False Positive, Low, Medium, High, Confirmed) and `instances[]`; an instance needs `uri`. Each instance is its own finding (identity `zap-alert-instance:<alertRef or pluginid>:<instance id or index>`) with `desc` and `solution` as plain text, `otherinfo` verbatim, references, CWE, and tags `zap-risk-code:`, `zap-confidence-code:`, `zap-method:`, `zap-param:`, `zap-alert-ref:`, `wasc:`, `zap-instance-id:` and `zap-evidence:`. A malformed alert or instance is skipped with a warning; an empty alert array is a zero-finding result, not a security claim.

## Downstream changes

No upstream code is patched. The command and plan carry three workarounds:

- **`-Xmx1200m`** (9361a40): `zap.sh` sizes the heap from host memory and ignores the container memory limit. Remove when upstream honours the limit.
- **`-dir /tmp/zaphome`** (6843579): uid 65532 has no passwd entry, so Java's `user.home` is `?` and ZAP aborts; `-e HOME` does not help.
- **Gateway in the plan** (bf89765): ZAP ignores `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, so the SOCKS settings are a required argument of the plan builder.

## Lessons from real runs

- 2026-09-24: against a three-page site with a login form, Nuclei reported 13 findings, all on `/`; ZAP crawled the same site in 11 seconds, reached six URLs, and found a missing anti-CSRF token, a missing clickjacking header and a debug comment -> ZAP recorded as an experimental engine (9361a40).
- 2026-09-24: under the product's runtime flags ZAP stopped with "Unable to create home directory: /zap/?/.ZAP/" -> `-dir /tmp/zaphome`; it then exited 0 in 12 seconds (6843579).
- 2026-09-24: with every proxy variable aimed at a dead port, all 44 requests still reached the target -> gateway pinned in the plan. Spider `requestwait`, the same key on the command line and the network add-on's rate-limit rules were accepted and ignored, leaving about 170 to 230 requests/s against a 10/s cap -> rate blocker (bf89765).
- 2026-09-24: through the gateway at 5 connections/s, a keep-alive site took 124 requests over 5 connections (114 requests/s); a site that closes each connection gave 5 of 124 pages while ZAP exited 0 reporting "found 123 URLs" -> the blocker names both halves (28b1843).
- 2026-09-25: a destination outside the policy was closed silently and ZAP logged "Malformed reply from SOCKS server" -> the gateway answers with reply 2 (1a2dbb2).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **New upstream image.** Verify the digest and OCI source labels as `plan.json` `verified_upstream_artifact.verification` records, then update `plan.json` (`source`, `verified_upstream_artifact`, `final_artifact`) and the catalog (`image`, `source_revision`, `engine_version`, `rule_version`, the add-on versions in the notices, `provenance.engine` and `provenance.rules`). The revision link is also in `THIRD_PARTY.md` and `docs/engine-catalog.md`.
- **Re-check the workarounds and plan keys.** Heap sizing, `user.home`, proxy variables, the ignored rate keys, the `socksProxy` keys, the job types and the `traditional-json` template.
- **Output shape.** `site[].alerts[]` with `pluginid`, `alertRef`, `alert`, `riskcode`, `confidence`, `desc`, `solution`, `reference`, `cweid`, `wascid`, and `instances[]` with `uri`, `method`, `param`, `evidence`, `otherinfo`, `id`.
- **Before wiring a run,** align the report file: the golden test `representative_plan_serializes_to_exact_expected_json` uses `reportDir` `/output` with `reportFile` `zap-report`, while the catalog and plan expect `/output/zap.json`.
- **Tests.** `src-tauri/src/zap_work_plan.rs` (golden plan); the ZAP tests in `container_runtime.rs`, such as `zap_plan_must_be_the_autorun_argument`, `zap_plan_file_is_rejected_for_a_non_zap_manifest`, `zap_manifest_that_names_the_plan_requires_the_generated_file` and `oversized_zap_plan_is_rejected`; `src-tauri/tests/adapter_fixtures.rs` with `fixtures/adapters/zap.json` and `malformed-zap.json` (`zap_preserves_alert_identity_severity_remediation_and_instance_evidence`, `malformed_zap_alert_is_contained_while_valid_instances_survive`, `empty_zap_alert_array_is_a_zero_finding_result_without_a_security_claim`); unit tests `zap_plain_text_separates_boundaries_and_decodes_entities` and `zap_evidence_tag_value_preserves_markup_and_marks_truncation`.
- **Hard-coded version.** `2.17.0` appears in catalog `image.tag`, `engine_version` and `provenance.engine.version` (`source_ref` `v2.17.0`), `plan.json` (`verified_upstream_artifact.tag`, `final_artifact.tag`), `THIRD_PARTY.md`, the `@version` of both ZAP fixtures and this page; the match in `Cargo.lock` is an unrelated crate. `support_until` is 2026-11-05.
- **Compare with raw output.** As in 9361a40, run the pinned image under the product's constraints (read-only root, non-root user, all capabilities dropped, no-new-privileges, memory limit, plan on a read-only mount, report on the output mount) with a generated plan against `<local-test-origin>`. Every `instances[]` entry should be one finding with the alert's `pluginid`, title, severity from `riskcode` and the instance `uri` (without query) as location.
