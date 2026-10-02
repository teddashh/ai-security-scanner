# Cloudsplaining

Downloads the IAM authorization details of one authorized AWS account and runs Cloudsplaining's policy risk scan over them, under the fixed profile `aws-iam-us-east-1`. Findings are excessive-permission risks per policy and principal.

| Item | Value |
| --- | --- |
| Upstream | [salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) 0.9.1, revision `75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7` |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-cloudsplaining:0.9.1-6` (`plan_kind: managed_source_image`, BSD-3-Clause). The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/cloudsplaining/`: `Dockerfile`, `Dockerfile.dockerignore`, `plan.json`. The dependency lock is upstream's own `uv.lock` inside the checksum-pinned source archive. |
| Launcher | `runCloudsplaining` and `copyBoundedRegularFile` in `engines/images/cloud-launcher/main.go` ([shared launcher](cloud-launcher.md)) |
| Wrapper | None |
| Adapter | `extract_cloudsplaining` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-cloud.yml`, matrix entry `cloudsplaining` (no image smoke step) |

## How it is wired

- **Input.** One `cloud_account` asset with exactly one `aws_account_id`, granted `inventory_read` and `configuration_read`, and the AWS session triple expiring in 5 to 60 minutes. This is the only engine whose identity preflight uses the global STS endpoint (`awsSTSEndpointForEngine`), because its network closure is `iam.amazonaws.com:443` and `sts.amazonaws.com:443` only. Provider traffic goes through the launcher's CONNECT bridge to the managed gateway.
- **Invocation.** Two fixed steps:
  1. `/opt/cloudsplaining/bin/cloudsplaining download --output <tmp>/authorization`. Exit 0 or 1 is accepted; success means a bounded regular `<tmp>/authorization/default.json` exists.
  2. `cloudsplaining scan --input-file <tmp>/authorization/default.json --output <tmp>/report --skip-open-report`. A non-zero exit fails the run.
- **Output.** `copyBoundedRegularFile` copies `<tmp>/report/iam-findings-default.json` (at most 512 MiB) to `/output/cloudsplaining.json` with mode 0600. The downloaded authorization details and the rest of the scan output stay in the `/tmp` tmpfs and are removed when the launcher exits.
- **Mapping.** `extract_cloudsplaining` requires one JSON object with a root `links` object (and `links` on every `PrivilegeEscalation` category) and walks `customer_managed_policies`, `inline_policies` and `aws_managed_policies`:
  - Each policy needs a boolean `is_excluded`; `true` is skipped because Cloudsplaining already applied the exclusions.
  - Each policy needs the six categories in `CLOUDSPLAINING_RISKS` (`PrivilegeEscalation`, `DataExfiltration`, `ResourceExposure`, `ServiceWildcard`, `CredentialsExposure`, `InfrastructureModification`), each with `severity`, `description` and a `findings` array. `PrivilegeEscalation` entries are `{type, actions}` objects; the others are strings.
  - One finding per entry: rule id is the category name, severity is the category's own `severity` (missing reads Unknown with a warning), title `<risk>: <identity> in policy <policy>`, location `<policy> :: <identity>`, description from the category. Policy context keeps at most 32 `AttachedTo` principals per kind and 32 actions.
  - The document has no account identifier, so findings attach to the single authorized asset.
  - Above 10,000 valid entries, admission runs Critical, High, Medium, Unknown, Low, then Informational, with a warning stating how many were retained and how many remain only in raw evidence.
- **Failed or partial.** A launcher refusal, a download exit other than 0 or 1, a missing `default.json`, a failed scan or a failed copy makes the container exit 126, and the run fails without normalizing. The run is partial when a section, policy, category or entry does not match the pinned shape, `links` is missing, or the record bound is reached; valid sibling findings are kept.

## Downstream changes

- No source patches; upstream's `uv.lock` is used as is (`uv sync --frozen --no-dev --no-editable`).
- The launcher accepts exit status 1 from `download` when the bounded `default.json` exists (`runCloudsplaining`: "Cloudsplaining 0.9.1 historically returns one after a successful download"). Re-check this on every new version and drop it when a successful download returns 0.

## Lessons from real runs

- 2026-09-05: Cloudsplaining returned zero findings on real output -> the parser looked for risk names at the document root, while Cloudsplaining keeps them inside each policy object -> walk the policy sections, honour `is_excluded`, take upstream severity, and build the fixture from upstream's example output; the control mapping moved from `iam-privesc` to `PrivilegeEscalation` (da6729a).
- 2026-09-08: severities came from a product-authored per-risk table (for example `PrivilegeEscalation` high, `InfrastructureModification` low) instead of Cloudsplaining -> read `severity` from each category object, emit one finding per entry, and admit by severity under the record bound (f4cde33).
- 2026-10-02: a live AWS run failed on its first provider call -> botocore read the gateway's `socks5h://` URL as an HTTP proxy -> launcher CONNECT bridge (e4571df, published in 9f6a976, pinned in eba1c22).
- 2026-10-02: on a live account the scan finished but the run failed -> the launcher renamed the result from the `/tmp` tmpfs into `/output`, a separate mount, which fails across filesystems -> copy the bounded result instead (a56f0fb, published as `0.9.1-6` in dfe8af1, pinned in bad4485).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Build.** New source archive URL and `ADD --checksum`, `SOURCE_REVISION`, the upstream `uv.lock` SHA-256 (Dockerfile `RUN` line, label and `plan.json` `dependency_lock`), and the `cloudsplaining, version 0.9.1` assertion in the Dockerfile.
- **CLI and files.** Re-check `download --output`, `scan --input-file --output --skip-open-report`, the download exit status, the file names `default.json` and `iam-findings-default.json`, and whether the new version calls any endpoint outside `iam.amazonaws.com` and `sts.amazonaws.com`. A new endpoint must change the catalog and plan network closures together (the validator compares them) and possibly `awsSTSEndpointForEngine`.
- **Output shape.** Re-check `links`, the three policy sections, `is_excluded`, the six categories with `severity`, `description` and `findings`, the `PrivilegeEscalation` entry shape and `AttachedTo`. The category list is `CLOUDSPLAINING_RISKS` in `src-tauri/src/adapters/mod.rs` (its comment names 0.9.1).
- **Mapping.** All six category names are keys in `mappings/control-mappings.json`; a renamed category needs a mapping change and a `mapping_version` bump.
- **Tests.** Fixture `src-tauri/tests/fixtures/adapters/cloudsplaining.json` and the 14 `cloudsplaining_*` tests in `src-tauri/tests/adapter_fixtures.rs` (for example `cloudsplaining_risks_are_read_from_policies_not_the_document_root`, `cloudsplaining_severity_is_read_from_the_category_object`, `cloudsplaining_schema_drift_is_partial_without_erasing_valid_siblings`, `cloudsplaining_record_bound_keeps_late_high_findings_before_early_low_rows`); `aws_iam_policy_context_is_bounded_untrusted_cloudsplaining_evidence` in `src-tauri/src/adapter.rs`; `standard_redaction_rebuilds_cloudsplaining_prose_without_short_name_leaks` in `src-tauri/src/export.rs`; launcher tests `TestEngineResultIsCopiedIntoTheOutputMount` and `TestAWSIdentityEndpointMatchesEachReleasedNetworkClosure`.
- **Hard-coded values.** `0.9.1-6` appears in `CLOUD_ENGINE_MATRIX`, catalog `image.tag`, plan `final_artifact.tag` and the Dockerfile version label. `0.9.1` also appears in the Dockerfile version assertion and in comments in `runCloudsplaining` and above `CLOUDSPLAINING_RISKS`. The demo manifest in `src/data/demo.ts` lists 0.8.2, which is not the pin. `support_until` is 2026-11-22.
- **Compare with raw output.** In the run's raw `cloudsplaining.json`, count the entries in every category `findings` array of each policy whose `is_excluded` is false. The normalized count on the account should match unless the record bound warning appears. Spot-check that each finding's severity equals its category's `severity`.
- **Publishing.** The next push that touches `engines/images/cloudsplaining/` needs a new tag; see [publishing a changed image](cloud-launcher.md#publishing-a-changed-image).
