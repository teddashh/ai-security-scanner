# KICS

Runs KICS's bundled queries over a `repository` or `iac_project` snapshot with the upstream `checkmarx/kics` image, unchanged. KICS picks the platforms, such as Terraform, CloudFormation, Kubernetes and Dockerfile, from the files present; its secret queries run too, and no severity is excluded.

| Item | Value |
| --- | --- |
| Upstream | [Checkmarx/kics](https://github.com/Checkmarx/kics) 2.1.20 (`source_ref` `v2.1.20`), revision `e1f23cad9640f55b963f22a116b04906b8c16ac6`. The queries are the ones in the image at that revision (`provenance.rules`). |
| Image | `checkmarx/kics:v2.1.20` on Docker Hub (`plan_kind: upstream_image`, Apache-2.0). The digest is pinned in `engines/catalog.json`. Plan `verified_upstream_artifact`: `docker_buildx_imagetools_inspect_and_oci_labels`, `attested_match`, 2026-08-24, entrypoint `/app/bin/kics`. |
| Build inputs | None. `engines/images/kics/` holds only `plan.json` (`dockerfile.emitted: false`, `build_recipe: null`). The desktop pulls the image by digest (`distribution_mode: pull_pinned_image`). |
| Launcher | None: upstream `/app/bin/kics` receives the catalog `command` (`wrapper.required: false`). The [local launcher](local-launcher.md) is not used. |
| Adapter | `extract_kics` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | None. `upstreamImageOnlyIds` in `scripts/validate-engine-catalog.mjs` keeps KICS from being counted as a project-managed image. |

## Local build and update entry

There is no local Dockerfile. This integration uses the catalog’s digest-pinned upstream image; update acquisition/provenance and the product invocation together.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One asset: a `repository` (`repository_working_tree`) or an `iac_project` (`iac_working_tree`). No launcher checks the profile; the host routes by the catalog contracts. Networking is disabled. Catalog resources: 1024 MB memory, 1024 MB disk, 1000 CPU millis, 3600 s.
- **Invocation.** `kics scan --path /workspace --report-formats json --output-path /output --output-name kics --no-progress --silent --no-color --ignore-on-exit results`.
  - `--ignore-on-exit results` keeps findings from setting the exit code (60 for Critical down to 20 for Info, `ResultsExitCode` in upstream `internal/console/helpers/exit_handler.go`). An engine error still exits 126.
  - No `--type`, `--exclude-*` or `--disable-secrets` flag is passed. BOM queries (severity TRACE) need `--bom`, which is off.
  - `--disable-full-descriptions` is not passed, and `NewClient` (upstream `pkg/scan/client.go`) always runs a version check. With networking disabled both calls fail and fall back: descriptions stay the query defaults ("Using default descriptions" in `pkg/scan/post_scan.go`), and the version is treated as latest.
- **Output.** `/output/kics.json` (`<output-path>/<output-name>.json`, upstream `pkg/report/json.go`). The top level holds `queries` and counters such as `files_scanned`, `files_failed_to_scan`, `queries_failed_to_execute`, `lines_ignored` and `total_counter`.
- **Mapping.** `extract_kics` makes one record per `queries[].files[]` item:
  - Rule id `query_id` (exact). The adapter accepts any short non-empty text; it does not check for a UUID. Title `query_name`, else `KICS query <id>`.
  - Severity `severity` through `parse_severity`: Critical, High, Medium and Low map directly, `INFO` is Informational, a missing value Unknown. Confidence is derived (`DeterministicPolicyEvaluation`); evidence kind Configuration.
  - Location `<file_name>:line=<line or search_line>:resource=resource:<resource_name>,similarity:<similarity_id or old_similarity_id>`; a missing `file_name` becomes `iac-resource`. The report hides the similarity key and an `n/a` resource (`src-tauri/src/finding_narrative.rs`, `src/findingNarrative.ts`).
  - Description from the query `description`, CWE from `cwe` (`cwe_identifiers`), links from `query_url` plus the manifest URLs. `search_key`, `expected_value`, `actual_value` and `remediation` stay in the raw artifact only.
- **Failed or partial.** A non-zero exit fails the run. These make it partial, keeping valid rows:
  - a document that is not JSON, or no `queries` array;
  - a query that is not an object, or has no valid `query_id` or no `files` array;
  - a file entry that is not an object;
  - 10,000 records.

  Positive `files_failed_to_scan` or `queries_failed_to_execute` counters make the run partial, even with an empty `queries` array. A declared counter that is not a non-negative integer also withholds completion. Missing counters remain supported for historical reports. Lines skipped by inline `kics-scan` comments (`lines_ignored`) do not by themselves imply a failed check. Valid sibling findings keep their identities, severity and evidence. `{"queries":[]}` with no reported failures remains a finished run with nothing found.

## Downstream changes

None. The image is the upstream release image by digest, with no Dockerfile, launcher or patch.

## Lessons from real runs

- 2026-09-05: the KICS control mapping never matched -> it was keyed on `e24efb0e`, the shape of KICS's `description_id`, while findings carry the 36-character query UUID -> re-keyed to the query id of "S3 Bucket Object Not Encrypted" (a5e76de).
- 2026-09-05: KICS findings carried no advisory link -> `references_from` did not read `query_url` -> it does now (a60d38a).
- 2026-09-26: on a real 47-finding project scan, fifteen cards told the reader to confirm that a query UUID was no longer reported -> the verification sentence named the source rule, and KICS rules are UUIDs -> when the rule is a UUID and the finding has a title, the sentence names the title (6a60d50).
- 2026-10-03: release review found that positive file/query failure counters could leave even an empty report complete -> adapter contract 0.2.3 records the coverage gap while keeping valid sibling findings. Regression cases cover empty and populated reports, malformed counters and ordinary ignored lines; no image change.
- 2026-09-27: a real project report printed "infra/main.tf · line 1 · n/a" -> KICS writes `n/a` when a result has no resource -> the report and Results leave that label out; the technical details keep the location as written (d53ca4e).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Image.** Inspect the new `checkmarx/kics` tag: digest, OCI labels, the source revision they name, and the entrypoint. Then update together:
  - catalog `image.tag` and `image.digest`, `engine_version`, `source_revision`, `rule_version`, `provenance.engine` and `provenance.rules`;
  - plan `source`, `verified_upstream_artifact` (with `verified_at`) and `final_artifact`.

  The validator requires `final_artifact` to equal the catalog image, plan `source.revision` to equal `source_revision`, plan `command` to equal the catalog's, and `source_association: attested_match` for a runnable engine. [Checkov](checkov.md)'s upstream image recorded `attested_mismatch` and is built from source instead.
- **CLI and output shape.** At the new revision, re-check the flags in `internal/console/assets/scan-flags.json`, `ResultsExitCode` and `EngineErrorCode`, the report file name, and the `pkg/model/summary.go` fields the adapter reads: `query_id`, `query_name`, `severity`, `description`, `cwe`, `query_url`, and `files[].{file_name,line,search_line,resource_name,similarity_id,old_similarity_id}`. Read upstream with `git -C .upstreams/Checkmarx/kics show <revision>:<path>`; `engines/upstreams.lock.json` records that checkout at `015905d9…` on `master`, not at the pin.
- **Mapping.** `mappings/control-mappings.json` has one exact entry, `5fb49a69-8d46-4495-a2f8-9c8c622b2b6e`; confirm it still exists in `assets/queries/terraform/aws/s3_bucket_object_not_encrypted/metadata.json`. `engine_rule_identifiers_have_the_shape_their_engine_actually_emits` (`src-tauri/src/adapters/control_mapping.rs`) requires KICS entries to be UUIDs. KICS and Checkov findings on one resource are never grouped (`configuration_rule_ids_are_never_correlated_across_engines` in `src-tauri/src/correlation.rs`).
- **Tests.**
  - In `src-tauri/tests/adapter_fixtures.rs` (fixture `kics.json`): `kics_failed_checks_withhold_completion_and_keep_completed_sibling_findings`, `kics_preserves_valid_files_but_withholds_completion_for_malformed_declared_shapes`, `kics_and_trivy_keep_distinct_upstream_resources_and_secret_coordinates`, `repo_adapters_accept_their_explicit_empty_result_shapes_without_warnings`, `engine_supplied_advisory_links_survive_and_unsafe_ones_do_not`, `upstream_rule_details_are_retained_as_evidence_without_replacing_product_recommendations` and `the_action_a_finding_asks_for_matches_the_kind_of_problem_it_reports`.
  - `every_detector_places_its_finding_on_its_mapped_control` in `src-tauri/tests/all_engine_report_audit.rs`, `local_case_lifecycle_preserves_scope_evidence_and_comparison_truth` in `src-tauri/tests/local_case_lifecycle.rs`, and `an_opaque_source_rule_gives_way_to_the_finding_title` in `src-tauri/src/finding_narrative.rs`.
  - `src/engineWarningPresentation.ts` translates the adapter's warnings by exact text (`tests/frontend/warningPresentation.test.ts`); change both together.
  - The fixture holds only `queries`; its query has no `cwe` or `description`, and its file has an `asset_id` KICS never writes.
  - Nothing runs the image in CI. Before pinning, scan a repository holding Terraform, CloudFormation, Kubernetes manifests and a Dockerfile, and check the exit code and `kics.json`.
- **Hard-coded values.** `v2.1.20` appears in catalog `image.tag` and `provenance.engine.source_ref` and in plan `verified_upstream_artifact` and `final_artifact`, which also hold the digest; `2.1.20` also appears in catalog `engine_version` and `provenance.engine.version`. No script, test or workflow names either. Find them with `grep -rn "2.1.20" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams --exclude-dir=.engine-cache`. `support_until` is 2026-11-22.
- **Compare with raw output.**
  - Count with `jq '([.queries[].files[]] | length), .total_counter' kics.json`; the two numbers should match.
  - List with `jq -r '.queries[] | .query_id as $q | .files[] | [$q, .file_name, .line, .resource_name, .similarity_id] | @tsv' kics.json | sort | uniq -c`; identical rows merge into one finding.
  - Read `jq '{files_scanned, files_failed_to_scan, queries_total, queries_failed_to_execute, lines_ignored}' kics.json` to compare the adapter coverage disclosure with the upstream counters.
- **Publishing.** Nothing is built or published. Changing the pin is a catalog and plan edit.
