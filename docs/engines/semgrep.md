# Semgrep

Runs Semgrep Community Edition static analysis over a `repository` snapshot with a pinned offline rule pack. The current source builds that pack from the security rules of `returntocorp/semgrep-rules`. The image the catalog pins is older and still runs four product-written rules; see **What the pin runs** below.

| Item | Value |
| --- | --- |
| Upstream | [semgrep/semgrep](https://github.com/semgrep/semgrep) revision `a0c13f304151e531c7e7c00838076211a07a790c` (`source_ref` `develop`); the build asserts `semgrep --version` is `1.174.0`. Rules: [returntocorp/semgrep-rules](https://github.com/returntocorp/semgrep-rules) `947bf05744d4c95153173a24879f30b3ba1a65aa`. |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-semgrep:1.174.0-3` (`plan_kind: managed_build`, `LGPL-2.1-or-later AND LicenseRef-Semgrep-Rules-License-1.0`, `SOURCE-OFFER.md`). The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/semgrep/`: `Dockerfile`, `submodules.lock` (36 source archives, the rules repository among them), `build_rule_pack.py`, `test_rule_pack.py`, `testdata/insecure.py`, `SOURCE-OFFER.md`, `plan.json`. The archives are fetched by `node scripts/prepare-offline-engine-data.mjs semgrep` into `.engine-cache/offline/semgrep-submodules/`. The build also uses the shared launcher. |
| Launcher | [Local launcher](local-launcher.md): `verifySemgrepRulePack` and the `semgrep` branch of `planInvocation` |
| Adapter | `extract_semgrep` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-local-k8s.yml`, matrix entry `semgrep` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/semgrep/Dockerfile) and context `.`.

Prepare the host cache first: `node scripts/prepare-offline-engine-data.mjs semgrep`. This prepares current source inputs, whose upstream rule license blocks public distribution; the [legacy combination review](semgrep-combination-review.md) is a separate local experiment.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **What the pin runs.** The plan's `publication` names commit 2641850 (run 33196902246). At that commit the Dockerfile copied `engines/images/semgrep/rules.yml`, and the launcher passed `--config /opt/ai-security-scanner/semgrep/rules.yml`. That file held four product rules: `ai-security-scanner.python.dynamic-code-execution`, `.python.shell-true`, `.javascript.child-process-exec` and `.generic.private-key`. ef1c653 (2026-09-08) deleted it and added the upstream pack. Since then the catalog `rule_version`, notice and provenance and the plan all describe a 1,620-rule image that has never been published. 9ee5257 scheduled rebuilds for Trivy, kube-bench, Maester and Greenbone, but not Semgrep.
- **Input.** One `repository` asset (`repository_working_tree`, no marker); the launcher refuses every other profile. Networking is disabled. Catalog resources: 2048 MB memory, 2048 MB disk, 2000 CPU millis, 3600 s.
- **Invocation.** After `verifySemgrepRulePack`, the launcher runs `semgrep scan --json --output /output/semgrep.json --config /opt/ai-security-scanner/semgrep/rules --metrics=off --disable-version-check --no-rewrite-rule-ids --oss-only --jobs 2 --max-memory 2048 --timeout 10 --timeout-threshold 3 --max-target-bytes 10000000 /workspace`, with `SEMGREP_ENABLE_VERSION_CHECK=0` and `SEMGREP_SEND_METRICS=off`. `--no-rewrite-rule-ids` keeps each rule's bare YAML `id` as its `check_id`.
- **Output.** Semgrep writes `/output/semgrep.json`; the launcher accepts exactly one JSON value.
- **Mapping.** `extract_semgrep` reads `results[]`:
  - Rule id `check_id` (required). Title `extra.message`, else `Semgrep rule <id>`.
  - Severity `extra.severity` through `parse_severity`: `ERROR` High, `WARNING` Medium, `INFO` Informational.
  - Confidence `extra.metadata.confidence`, else derived (`UnverifiedPatternOrDetectorMatch`).
  - Location `<path>:line=<n>:column=<n>` from `path`, `start.line` and `start.col`. Description `extra.metadata.description`, fix `extra.fix`, CWE `extra.metadata.cwe`, plus links through `references_from`.
- **Failed or partial.** A refused profile or rule pack, a non-zero exit or invalid JSON fails the run. These make it partial, while keeping the valid results:
  - a non-empty `errors` array (the warning is a fixed sentence; the error details stay in the raw artifact);
  - a missing `errors` or `results` array;
  - a result without `check_id`.

## Downstream changes

- **Local combination proposal (2026-10-02).** The [legacy + four-rule review](semgrep-combination-review.md) records acquisition/license exceptions, collision-free IDs with original-source provenance, three separate CE executions, overlap and remaining integration work. It changes no production lock, image pin or detector body.
- **Published source attachment correction (2026-10-02).** Inspecting the actual pinned digest found newer upstream rules under `semgrep/tests/semgrep-rules/` in `/usr/share/source/semgrep-source.tar.gz`, despite the runtime loading only four own rules. Its attached license is Semgrep Rules License v1.0. See the [exact artifact hashes and local source-assembly fix](semgrep-combination-review.md#published-source-attachment-inspection). A runtime-only inventory does not establish the contents or distribution terms of the whole image.
- **No source patches.** Semgrep is built unmodified from the pinned revision. Its git submodules come from `submodules.lock` (path, repository, revision, SHA-256, size, archive), and each archive's size and digest are checked before extraction.
- **Offline security rule pack** (`build_rule_pack.py`). Engine networking is disabled, so the rules are embedded. From the rules archive the builder keeps every `.yaml`/`.yml` file that:
  - is not a test file;
  - lies under a `security` or `secrets` directory or under `ai/ai-best-practices/`;
  - is not under `apex/`.

  Every rule must declare `category: security`. Exactly 1603 files and 1620 rules, at most 1 MiB per file and 16 MiB per pack. Output: `rules/`, `RULES.sha256` and `PACK-METADATA.json` (schema `ai-security-scanner.semgrep-rule-pack/v1`). The counts and the manifest digest are repeated in the launcher constants and the Dockerfile labels. The pack changes with every rules revision.
- **`apex/` exclusion.** Semgrep CE 1.174.0 needs an unavailable proprietary parser plugin to load those rules (comment in `is_selected_rule_path`). Drop the exclusion when the pinned CE version can load them.

## Lessons from real runs

- 2026-09-05: readers saw only "Semgrep rule ai-security-scanner.python.shell-true" -> the adapter read `extra.metadata.shortlink` and never `extra.message` -> the title is now `extra.message` (a60d38a).
- 2026-09-17: the Semgrep publish job failed with "version tag is already bound to a different source commit or workflow" although its inputs had not changed -> the guard bound a tag to the commit that first published it -> reuse is now allowed when the plan's recorded SHA-256 inputs match (415ab1b).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Choose the final rule profile first.** `mappings/control-mappings.json` has four exact `ai-security-scanner.*` entries. The upstream-only recipe on `main` drops those product IDs; the [legacy + product candidate](semgrep-combination-review.md) retains all four unchanged. Do not re-key existing product mappings simply because upstream rules are added. File-qualified upstream IDs need their own reviewed mappings; shared CWE/category does not establish identical detector behavior or exact mapping proof. Native `extra.metadata.cwe` can still reach standardized categories through the existing `cwe_derived_controls` fallback. If approved mapping content changes, update its version and the corresponding `control_mapping.rs` tests together. Check source bytes/IDs against the actual selected pack; catalog claims alone are insufficient.
- **Build.** New source archive and `ADD --checksum`, `SEMGREP_GIT_COMMIT`, the `--version` assertion (two places), every `submodules.lock` line, and `SOURCE_DATE_EPOCH`. `prepareSemgrepSubmodules` in `scripts/prepare-offline-engine-data.mjs` requires exactly 36 archives.
  - Alpine pins: dddd491 records that the Alpine 3.23 index now serves `pcre2` 10.49-r0 and `python3` 3.12.15-r0 and keeps only the newest build. The Dockerfile still pins `pcre2-dev`/`pcre2-static` `10.47-r0` and `python3` `3.12.14-r0` (build and runtime stages). Check every pin with `apk add --simulate` on the pinned base before building.
- **Rules.** A new rules revision changes the `tests/semgrep-rules` lock line, `EXPECTED_CONFIG_FILE_COUNT` and `EXPECTED_RULE_COUNT`, the launcher's `semgrepRuleManifestSHA256` and `semgrepRuleFileCount`, the Dockerfile labels `rules-revision`, `rules-count` and `rules-manifest-sha256`, the catalog `rule_version` and notice, and `docs/engine-catalog.md`. Run `python3 engines/images/semgrep/test_rule_pack.py` after preparing the archives; CI does not run it.
- **Output shape.** Re-check `results[].check_id`, `extra.message`, `extra.severity`, `extra.metadata.{confidence,description,cwe}`, `extra.fix`, `start.{line,col}` and the top-level `errors` array.
- **Tests.**
  - `src-tauri/tests/adapter_fixtures.rs`: `semgrep_reads_the_fixture_confidence_verbatim`, `semgrep_without_a_source_confidence_is_an_unverified_low_confidence_match`, `semgrep_lossy_rule_ids_never_gain_mapping_proof`, `semgrep_preserves_valid_findings_but_withholds_completion_for_errors_and_bad_rows`, `semgrep_findings_carry_the_engines_explanation_not_just_its_rule_id`.
  - Fixtures `semgrep.json` and `semgrep-lossy-rule-ids.json` still use the product rule ids (`semgrep-empty.json` has no results), as do `src-tauri/src/exporters/framework_report.rs`, `scripts/validate-aidefend-snapshot.mjs` and `tests/frontend/controlMappingRationalePresentation.test.ts`.
  - Launcher tests `TestSemgrepUsesThePinnedOfflineRulePackWithResourceBounds` and `TestSemgrepRulePackManifestRejectsTamperingAndUninventoriedFiles`.
  - The Dockerfile smoke (`RUN --network=none` over `testdata/insecure.py`) requires `errors == []` and the ids `dangerous-subprocess-use-audit` and `subprocess-shell-true`. The workflow smoke only checks that the output parses.
- **Hard-coded values.** `1.174.0-3` is in the workflow matrix, catalog `image.tag`, plan `final_artifact.tag`, the Dockerfile version label, `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs` and `tests/release/verifyPublicationArtifact.test.mjs`. Find them with `grep -rn "1.174.0-3" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams --exclude-dir=.engine-cache`. `support_until` is 2026-11-22; after that date every run carries the stale-knowledge warning (`stale_knowledge_warning` in `src-tauri/src/case_service.rs`).
- **Compare with raw output.** `jq '.results | length, (.errors | length)' semgrep.json`: the finding count should equal the first number unless the same rule fired twice at one path, line and column, and the second should be 0 for a complete run. Spot-check that each `check_id` and `extra.message` reached the finding unchanged.
- **Publishing.** The guard can reuse a tag only if the plan at the publishing commit binds that tag and records the same input digests. The plan at 2641850 binds `1.174.0-2`, and the inputs have changed since, so the next build needs a new tag. `build_rule_pack.py` and `submodules.lock` have no plan digest (`uncovered_baseline` in `engines/image-input-hash-policy.json`), so the guard cannot see a change to them alone.
