# ScoutSuite

Runs ScoutSuite's AWS IAM rules against one authorized AWS account under the fixed profile `aws-iam-us-east-1-json`. The image is built from pinned source with a hash-locked, JSON-only dependency set.

| Item | Value |
| --- | --- |
| Upstream | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) 5.14.0, revision `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d` |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-scoutsuite:5.14.0-6` (`plan_kind: managed_source_image`, GPL-2.0-only with source offer). The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/scoutsuite/`: `Dockerfile`, `Dockerfile.dockerignore`, `requirements.in`, `requirements.lock`, `scoutsuite-json-only.patch`, `prepare_source.py`, `scout_entry.py`, `SOURCE-OFFER.md`, `plan.json` |
| Launcher | `runScoutSuite` in `engines/images/cloud-launcher/main.go` ([shared launcher](cloud-launcher.md)) |
| Wrapper | `scout_entry.py`, installed as `/opt/scoutsuite/bin/scout`; it only calls `ScoutSuite.__main__.run_from_cli` |
| Adapter | `extract_scoutsuite` and `scoutsuite_rule_key` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-cloud.yml`, matrix entry `scoutsuite` (no image smoke step) |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/scoutsuite/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One `cloud_account` asset with exactly one `aws_account_id`, granted `inventory_read` and `configuration_read`, and the AWS session triple expiring in 5 to 60 minutes. The launcher verifies the account with `GetCallerIdentity` at `sts.us-east-1.amazonaws.com`. Provider traffic goes through the launcher's CONNECT bridge to the managed gateway, which allows `iam.amazonaws.com`, `sts.us-east-1.amazonaws.com` and `ec2.us-east-1.amazonaws.com` on port 443.
- **Invocation.** `/opt/scoutsuite/bin/scout aws --services iam --no-browser --force --report-dir <tmp>/scoutsuite-report --report-name scoutsuite --result-format json --max-workers 4`.
- **Output.** ScoutSuite writes its report under the `/tmp` tmpfs. The launcher reads `scoutsuite-results/scoutsuite_results_scoutsuite.js` (at most 512 MiB), strips the `scoutsuite_results =` prefix, requires valid JSON, and writes `/output/scoutsuite.json` (mode 0600, exclusive create). Nothing else reaches `/output`.
- **Mapping.** `extract_scoutsuite` walks the root `findings` object, or else `services`, and keeps each object whose `flagged_items` is above 0 (or whose `status` or `result` reads as a failure):
  - rule id: the object key under `services.<service>.findings`, because ScoutSuite does not repeat it inside the object (`scoutsuite_rule_key`). Objects under `filters` are never admitted. A flagged object whose key cannot be recovered is dropped without a warning.
  - title `description`, severity `level` through `parse_severity` (`danger` -> High, `warning` -> Medium), location `path` (the rule's path pattern, one finding per rule, not per flagged item), `rationale` and `remediation` as scanner details.
  - ScoutSuite's finding objects carry no account field, so findings attach to the single authorized asset. The flagged resource list stays in the raw artifact.
- **Failed or partial.** A launcher refusal, a non-zero `scout` exit, a missing result file or invalid JSON makes the container exit 126, and the run fails without normalizing. The run is partial on parse warnings, an artifact over 16 MiB (`MAX_ARTIFACT_BYTES`), or 10,000 records.

## Downstream changes

- **JSON-only source edit.** `prepare_source.py` checks the SHA-256 of `ScoutSuite/output/result_encoder.py`, `ScoutSuite/__main__.py` and `requirements.txt`, then makes the `sqlitedict` and `ScoutSuite.core.server` imports lazy and drops `sqlitedict`, `cherrypy` and `cherrypy-cors` from `requirements.txt`. Each replacement must match exactly once. The fixed profile only writes JSON, so the SQLite and web-server dependencies are not shipped. `scoutsuite-json-only.patch` is the reviewable form of the same edit: the Dockerfile checks its hash and ships it in `/usr/share/source/scoutsuite`, but the build uses the preparer. On 2026-10-03, applying the patch to the pinned source and running the preparer independently produced byte-identical results for all three files. Plan `build_recipe.patch_audit` retains those pre/post hashes, upstream references, contribution rationale, owners, fixtures and removal condition; recheck by 2026-11-01 and on every update. The general upstream server mode needs a dependency-group decision before this minimal profile can become native.
- **Dependency lock.** `requirements.in` lists the runtime-only dependencies of the IAM profile. `requirements.lock` was generated with `uv 0.11.0 pip compile requirements.in --python 3.11 --python-platform manylinux --generate-hashes --no-build --exclude-newer 2026-08-24T00:00:00Z` and is installed with `--require-hashes --no-build --no-deps`. The ScoutSuite package itself is copied into site-packages rather than pip-installed.

## Lessons from real runs

- 2026-09-05: ScoutSuite returned zero findings on real output -> the parser required an `id`, `rule_id` or `key` field that ScoutSuite never writes, and `danger` (125 of ScoutSuite's 197 default AWS rules) was unmapped -> rule identity from the pointer scoped to `findings`, `danger` -> High, and fixtures built from upstream's committed example output (da6729a).
- 2026-10-02: a live AWS run failed on its first provider call -> botocore read the gateway's `socks5h://` URL as an HTTP proxy -> launcher CONNECT bridge (e4571df, published in 9f6a976, pinned in eba1c22).
- 2026-10-02: ScoutSuite then completed on a live AWS account (a56f0fb). Its tag still moved to `5.14.0-6` because the shared launcher changed (dfe8af1, pinned in bad4485).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Source edit.** Any upstream change to the three edited files fails `prepare_source.py` on its `EXPECTED` hashes. Regenerate `REPLACEMENTS` and `scoutsuite-json-only.patch` together, and update the patch hash in the Dockerfile `RUN` line and `plan.json` `source_patch`.
- **Lock.** Re-run the `uv pip compile` command above with a new `--exclude-newer` date. The lock hash sits in the Dockerfile `RUN` line, its label and `plan.json` `dependency_lock`.
- **Output shape.** Re-check the `scout` flags above, the result path `scoutsuite-results/scoutsuite_results_<report-name>.js` with its `scoutsuite_results =` prefix, and the `services.<service>.findings.<rule key>` layout with `flagged_items`, `level`, `description`, `path`, `rationale` and `remediation`.
- **Mapping.** `mappings/control-mappings.json` keys three ScoutSuite rules: `s3-bucket-world-policy-star`, `iam-password-policy-no-uppercase-required` and `iam-ec2-role-without-instances`. Each must be a rule the `--services iam` profile emits; a content change needs a `mapping_version` bump.
- **Tests.** Fixture `src-tauri/tests/fixtures/adapters/scoutsuite.json` (built from upstream's example output), `scoutsuite_rule_identity_survives_being_stored_only_as_a_parent_key` and `native_fixtures_normalize_without_inventing_inventory_findings` in `src-tauri/tests/adapter_fixtures.rs`, and `src-tauri/tests/all_engine_report_audit.rs`. The workflow has no ScoutSuite smoke step; the build stage's `scout --version` assertion is the only check that the packaged CLI starts.
- **Hard-coded values.** `5.14.0-6` appears in `CLOUD_ENGINE_MATRIX`, catalog `image.tag`, plan `final_artifact.tag` and the Dockerfile version label. `5.14.0` also appears in the Dockerfile (archive name, `Scout Suite 5.14.0` assertion), `SOURCE-OFFER.md`, `src/data/demo.ts` and the fixture. `support_until` is 2026-11-22.
- **Input closure.** Current plan `build_recipe.local_inputs` hashes `prepare_source.py`, `scout_entry.py`, `requirements.in` and `Dockerfile.dockerignore`. The source-offer notice remains an explicit documentation exclusion from the executable-input gate, while still changing image bytes. Any change to these files needs a new artifact tag; current hashes do not prove the content of an older published image.
- **Compare with raw output.** In the run's raw `scoutsuite.json`, list the keys under `services.iam.findings` whose `flagged_items` is above 0. Each should be one finding on the account, with severity High for `danger` and Medium for `warning`; any missing key is a rule the adapter dropped.
- **Publishing.** The next push that touches `engines/images/scoutsuite/` needs a new tag; see [publishing a changed image](cloud-launcher.md#publishing-a-changed-image).
