# OWASP ZAP

Crawls one approved website origin and applies ZAP's upstream passive scan rules to the responses it observes, with no attack payloads, under the profile `zap_passive_v1`. It is included in v0.4.0, explicitly selectable in website Advanced and mixed-environment website settings. Nuclei remains the recommended default.

| Item | Value |
| --- | --- |
| Upstream | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) 2.17.0, revision `2665d972f6d587ba4773a95053ac39af3fdf8df9`; rule pack `pscanrules-75.0.0` |
| Image | Official upstream `ghcr.io/zaproxy/zaproxy:2.17.0`, re-inspected and exercised on native amd64 on 2026-10-04 with `docker buildx imagetools inspect` and its OCI labels (`attested_match`). The digest is pinned in `engines/catalog.json` and `engines/images/zap/plan.json` |
| Build inputs | None. `engines/images/zap/plan.json` only (`build_recipe` null, no Dockerfile) |
| Launcher | None. The official image has no Entrypoint and Cmd `["bash"]`; the product explicitly invokes `/zap/zap.sh` with `-Xmx1200m -cmd -silent -dir /tmp/zaphome -autorun /run/ai-security-scanner/zap-plan.yaml`. The plan comes from `build_zap_passive_plan` in `src-tauri/src/zap_work_plan.rs` |
| Adapter | `extract_zap`, `zap_severity` and `zap_confidence` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | None (official image) |

## Local build and update entry

There is no local Dockerfile. This integration uses the catalog’s digest-pinned upstream image; update acquisition/provenance and the product invocation together. The reviewed passive profile is dispatchable without a downstream image build.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Authorization.** `zap_passive_v1` binds one HTTP/HTTPS origin, single port, pinned upstream revision, 5 requests/s, five threads and 10-second timeout. Backend authorization and orchestration both enforce it; Nuclei and generic grants cannot substitute.
- **Plan.** `build_zap_passive_plan(approved_origin, gateway, bounds, report_dir, report_file_stem)` emits one context `approved` with `includePaths` `\Q<origin>\E.*`, the gateway in `env.configs` (`network.connection.socksProxy.enabled`, `.host`, `.port`, `.version` 5, `.dns` true only for hostnames), `failOnError` and `failOnWarning` true, and four jobs: `passiveScan-config` (in scope only, at most 100 alerts per rule), `spider` (`postForm` and `processForm` false; depth at most 20, children 100, 60 minutes, 5 threads), `passiveScan-wait` (at most 60 minutes), and `report` with template `traditional-json`. An origin with userinfo, a query, a fragment or `\E` is refused. The plan is JSON, at most 64 KiB, which ZAP's SnakeYAML parser accepts (bf89765). The job set is a closed enum, so active scan jobs cannot be added.
- **Mount.** `ContainerPlanBuilder::with_zap_plan_file` mounts the plan read-only at `/run/ai-security-scanner/zap-plan.yaml` with the label `ai.security-scanner.zap-plan-sha256`, only for the ZAP manifest and only as the argument of `-autorun` (423dc8b). The orchestrator calls it for each exact ZAP task and persists the plan digest in the execution checkpoint for ownership-checked cleanup.
- **Output.** The catalog expects `/output/zap.json` (`adapter_state` `released`).
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


## Reviewed request and crawl bounds

The pinned image's network add-on 0.29.0 uses `network.ratelimit.rules.rule(0).description`, `.enabled`, `.matchStr`, `.regex`, `.reqsPerSec` and `.groupBy`. Set one enabled `.*` regex rule with `groupBy=RULE` and `reqsPerSec=5`. Earlier experiments used different keys; their measurements remain incident history, not a limitation of the correct native rule. See the [native rate options](https://raw.githubusercontent.com/zaproxy/zap-extensions/network-v0.29.0/addOns/network/src/main/java/org/zaproxy/addon/network/internal/ratelimit/RateLimitOptions.java) and [native pacing implementation](https://raw.githubusercontent.com/zaproxy/zap-extensions/network-v0.29.0/addOns/network/src/main/java/org/zaproxy/addon/network/internal/ratelimit/RateLimiterImpl.java). Integer interval rounding means arbitrary non-divisor rates cannot be substituted for the reviewed five-per-second profile without a fresh wire measurement.

`network.connection.timeoutInSecs=10` binds the upstream HTTP timeout. Use SOCKS DNS only for domains: gateway-owned frozen DNS must handle domain names, while IPv4/IPv6 literals require `socksProxy.dns=false` because the gateway's address policy rejects literals encoded as arbitrary SOCKS domain names. All traffic still passes through the exact gateway. No proxy credentials are supplied.

The closed Automation Framework plan contains only passiveScan-config, spider, passiveScan-wait and traditional-json report. Spider bounds: depth five, 100 children per page, two minutes and five threads, with form processing/submission disabled. Passive wait is two minutes; warnings and errors fail closed. Empty site arrays disclose that no website response was observed instead of claiming a clean check. Native rule IDs, risk, confidence, evidence and remediation remain unchanged.

Controlled native amd64 verification on 2026-10-04 reached 104 pages over one keep-alive connection, maximum five requests per wall-clock second and average 4.999/s. Seven upstream passive alert IDs were present; no other-origin request or POST reached the isolated fixture. The minimum observed wire gap was 0.1904 seconds due to scheduling/network jitter, so this is not a strict rolling-window claim. The plan and report SHA-256 records, raw response report and fixture request log are retained in the local verification cache. An arm64 image pin does not constitute an arm64 runtime observation.

The final hostname run used the current production builder, gateway-owned frozen DNS and warning/error failure settings. It sent 106 GET requests through one keep-alive connection, maximum five per wall-clock second, with no other-origin request, POST or direct bypass. Finite-window timing was 5.007 requests/s with a 0.154-second minimum wire gap; the contract is the upstream five-per-second pacer, not a strict rolling-window rate. The generated plan has SHA-256 `32d388f2955eef88c2090319ca390cb46ba1a61ef34c0798a52c48402e058776`; the unchanged native report has SHA-256 `9ad7ccd903108ef007db38126e923750f01065e0d775b9c8961f111be6b20a0f` and is retained at `src-tauri/tests/fixtures/adapters/native-zap-2.17.0.json`. All 27 instances across eight upstream rule IDs reach the adapter with their native severity. A separate cancellation run stopped after 20 requests: none followed cancellation and no completed report was produced. These controlled fixtures used no owner target or credential.

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **New upstream image.** Verify the digest and OCI source labels as `plan.json` `verified_upstream_artifact.verification` records, then update `plan.json` (`source`, `verified_upstream_artifact`, `final_artifact`) and the catalog (`image`, `source_revision`, `engine_version`, `rule_version`, the add-on versions in the notices, `provenance.engine` and `provenance.rules`). The revision link is also in `THIRD_PARTY.md` and `docs/engine-catalog.md`.
- **Re-check the workarounds and plan keys.** Heap sizing, `user.home`, proxy variables, the exact `network.ratelimit.rules.rule(0).*` keys, the `socksProxy` keys, the job types and the `traditional-json` template.
- **Output shape.** `site[].alerts[]` with `pluginid`, `alertRef`, `alert`, `riskcode`, `confidence`, `desc`, `solution`, `reference`, `cweid`, `wascid`, and `instances[]` with `uri`, `method`, `param`, `evidence`, `otherinfo`, `id`.
- **Production output.** The orchestrator writes `reportDir` `/output` and `reportFile` `zap`, matching `/output/zap.json`. The generic builder's golden test uses a different caller-selected stem deliberately.
- **Authorization and recovery.** Keep the native pinned revision, closed `zap_passive_v1` profile, one HTTP/HTTPS origin and single port, 5 requests/s, five threads and 10-second timeout together in backend and frontend. ZAP must not consume a Nuclei or generic active grant. Each grant has its own task membership and saved automation-plan digest; changed grants never silently widen retries.
- **Tests.** `src-tauri/src/zap_work_plan.rs` (golden plan); the ZAP tests in `container_runtime.rs`, such as `zap_plan_must_be_the_autorun_argument`, `zap_plan_file_is_rejected_for_a_non_zap_manifest`, `zap_manifest_that_names_the_plan_requires_the_generated_file` and `oversized_zap_plan_is_rejected`; `src-tauri/tests/adapter_fixtures.rs` with `fixtures/adapters/zap.json` and `malformed-zap.json` (`zap_preserves_alert_identity_severity_remediation_and_instance_evidence`, `malformed_zap_alert_is_contained_while_valid_instances_survive`, `empty_zap_alert_array_is_a_zero_finding_result_without_a_security_claim`); unit tests `zap_plain_text_separates_boundaries_and_decodes_entities` and `zap_evidence_tag_value_preserves_markup_and_marks_truncation`.
- **Hard-coded version.** `2.17.0` appears in catalog `image.tag`, `engine_version` and `provenance.engine.version` (`source_ref` `v2.17.0`), `plan.json` (`verified_upstream_artifact.tag`, `final_artifact.tag`), `THIRD_PARTY.md`, the `@version` of both ZAP fixtures and this page; the match in `Cargo.lock` is an unrelated crate. `support_until` is 2026-11-05.
- **Compare with raw output.** As in 9361a40, run the pinned image under the product's constraints (read-only root, non-root user, all capabilities dropped, no-new-privileges, memory limit, plan on a read-only mount, report on the output mount) with a generated plan against `<local-test-origin>`. Every `instances[]` entry should be one finding with the alert's `pluginid`, title, severity from `riskcode` and the instance `uri` (without query) as location.

The hostname verification used the same pinned native image and a gateway-owned frozen DNS record: 106 GET requests, maximum five per wall-clock second, observed mean 5.007/s and minimum wire gap 0.154s. Same-origin redirects remained in scope; links and redirects to another port were not contacted and forms were not submitted. Cancelling a separate crawl after 20 requests left no further requests and no completed report. These finite-window wire observations include transport jitter; the native limiter is the request-pacing control, and no strict rolling-window claim is made. The native hostname JSON is retained unchanged as `src-tauri/tests/fixtures/adapters/native-zap-2.17.0.json` (SHA-256 `9ad7ccd903108ef007db38126e923750f01065e0d775b9c8961f111be6b20a0f`).
