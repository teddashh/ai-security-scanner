# garak

Catalogued but not runnable. garak would send NVIDIA garak's adversarial probe suite to one approved AI model endpoint (`ai_model_endpoint` asset, permission `active_external_testing`) and report, per probe and detector, how many attempts the detector judged as failures. Only the catalog record, the plan and the adapter exist: no image has been built and garak has never run in this product.

| Item | Value |
| --- | --- |
| Upstream | [NVIDIA/garak](https://github.com/NVIDIA/garak) 0.17.0 (catalog `source_ref` `v0.17.0`), revision `93aa9cdec309ec4170559676f1826ea2a679920c`, Apache-2.0 |
| Image | None. Catalog `image` is null; the plan's `final_artifact` (`ghcr.io/teddashh/ai-security-scanner-engine-garak`) keeps a null tag and digest (`publish_state` `managed_artifact_not_published`). |
| Build inputs | None. `engines/images/garak/plan.json` is the only file: `build_recipe` null, `dockerfile.emitted` false with a reason. |
| Launcher | None (`wrapper.entrypoint` null). Recorded strategy: accept only the model endpoint named in the scope grant, refuse every other destination, and hand the adapter only the run's own `report.jsonl`. |
| Wrapper | None |
| Adapter | `extract_garak`, `garak_target`, `garak_probe_contexts` and `garak_counts_sentence` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | None |

## How it is wired

- **Release gate.** Catalog `status` `experimental`, `compatibility.runnable` false, and three blockers repeated in the plan:
  - "no packaged image: the pinned source has never been built, tested, or published for this product"
  - "no scope-grant path exists for an AI model endpoint, so no run could be authorized against one"
  - "no credential path exists for a model endpoint that requires a key"
- **Enforcement.** `validate_release_contract` in `src-tauri/src/registry.rs` requires at least one blocker and refuses `default_enabled` for a non-runnable release. `EngineManifest::release_blocker` (`src-tauri/src/domain.rs`) keeps garak out of the default plan (`default_plan_includes_manifest`), makes an explicit request record `engine_release_unavailable`, and stops `PinnedImage::from_manifest` (`src-tauri/src/container_runtime.rs`) and `src-tauri/src/orchestrator.rs` from running it.
- **Input.** An `ai_model_endpoint` asset whose grant names a hostname over `https` (`direct_network_contract`). The second blocker records that no scope-grant path exists for such an asset yet.
- **Network and resources.** Catalog `execution.network` is `managed_allowlist` to "authorized target model endpoint". The manifest is `active_external`, so `container_runtime.rs` refuses to start it without a managed network policy ([egress gateway](egress-gateway.md)). Resources: 2048 MB memory, 4096 MB disk, 2000 CPU millis, 256 pids, 3600 s.
- **Invocation.** Planned command `--engine garak --scope /run/ai-security-scanner/scope.json --output /output`; nothing implements it yet.
- **Output.** `/output/report.jsonl` (`application/x-ndjson`), garak's own run log. The generic parser reads at most 10,000 rows, skips malformed lines with a warning, and reads a one-line report as a JSON document.
- **Mapping.** Only rows with `entry_type` `eval` carry a verdict.
  - Each needs `probe`, `detector` and a non-negative integer `fails`; otherwise a warning is raised and the row skipped. A pair with `fails` 0 is coverage, not a finding.
  - Rule id `probe/detector`; title "garak probe P: detector D judged F of E attempts as failures", E being `total_evaluated`. When `total_evaluated` is below `fails`, the ratio is dropped and a warning raised.
  - Severity Unknown with basis `AdversarialProbeFailureRate`, because garak publishes none. Confidence basis `UnverifiedPatternOrDetectorMatch`, evidence kind `ExternalValidation`, family `ModelBehavior`.
  - Location `plugins.target_type:plugins.target_name` from the `start_run setup` row (the older `plugins.model_type` and `plugins.model_name` are accepted), else "model endpoint".
  - Scanner details: the counts, including `nones` (not judged) and `total_processed`, plus the probe's `goal` and its first user-role prompt (one line, at most 240 characters) from the first `attempt` rows with that `probe_classname`. Model replies are never read.
- **Failed, partial, not tested.** Any adapter warning makes the run partial. A report with no `eval` row warns "garak output contained no eval rows, so no probe result was evaluated", so zero findings means a clean result only when eval rows exist.

## Downstream changes

None. Nothing is built or patched.

## Lessons from real runs

None yet: garak has never run in this product, and 31362f4 and e79eaea record that no scan was run and no endpoint was contacted. These adapter rules came from review:

- 2026-09-12: severity stays Unknown, clean pairs stay out of the findings, and the new `ModelBehavior` family keeps a model's answers from being routed to a restrict-or-patch-the-service screen (31362f4).
- 2026-09-13: a finding named a failing probe with no context -> eval rows carry only a verdict -> the probe's goal and first prompt come from the attempt rows, never from the failing attempt or the reply (ebbef00).
- 2026-09-13: OWASP LLM 2025 references by probe namespace (9032d96); see Mapping below.
- 2026-09-13: "50 of 10" was printed as a measurement and a one-line report was rejected as malformed -> no count check, and a JSONL-only guard -> the ratio is withheld with a warning, a one-line report reads as a document, and a report without eval rows is incomplete (e79eaea).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Before packaging.** Clearing the blockers is owner-authorized product work: an image whose launcher enforces the recorded strategy, a scope-grant path for `ai_model_endpoint` assets, and a credential path for keyed endpoints. Emitting a Dockerfile while the plan stays `managed_artifact_not_published` sends it through `validateUnpublishedManagedBuild` in `scripts/validate-engine-catalog.mjs`, which hard-codes MCP Armor's entrypoint and requires a source patch and disabled networking, so a garak build needs its own validator branch.
- **Source.** The validator fails with "managed build source is not pinned by engines/upstreams.lock.json" unless the `NVIDIA/garak` entry in `engines/upstreams.lock.json` equals the catalog `source_revision`. The revision is also in the plan `source`, catalog `provenance`, `THIRD_PARTY.md` and `docs/engine-catalog.md`. `engines/upstream-refresh-policy.json` marks garak `experimental`, so an `npm run upstream:refresh` proposal is never PR-eligible.
- **Output shape.** Re-check the `entry_type` values, the `eval` fields (`probe`, `detector`, `fails`, `total_evaluated`, `nones`, `total_processed`), the `attempt` fields (`probe_classname`, `goal`, `prompt.turns[].role` and `content.text`) and the `start_run setup` keys. A renamed eval field raises a warning; a renamed attempt or setup key silently drops the context or the location.
- **Tests.** Fixture `src-tauri/tests/fixtures/adapters/garak.jsonl` holds marked placeholder prompts and replies and declares `garak_version` `0.13.3.pre1`, not the pinned 0.17.0; replace it with a report from the pinned revision once one exists. Tests in `src-tauri/tests/adapter_fixtures.rs`: `garak_reports_probe_failure_rates_and_keeps_clean_probes_out_of_the_findings` (six findings, all Unknown, exact counts sentences, no reply text), `garak_maps_the_probe_namespace_to_owasp_llm_only_for_a_declared_ai_system` and `garak_withholds_completion_for_counts_that_cannot_be_true`. A changed warning sentence needs its Chinese form in `src/engineWarningPresentation.ts` (`tests/frontend/warningPresentation.test.ts`).
- **Mapping.** `mappings/control-mappings.json` has 11 `prefix` entries to OWASP LLM 2025: ten whole modules (`dan.`, `encoding.`, `latentinjection.`, `sysprompt_extraction.`, `leakreplay.`, `packagehallucination.`, `snowball.`, `misleading.`, `ansiescape.`, `web_injection.`) and one class, `divergence.Repeat/`, whose slash keeps `divergence.RepeatedToken` out. They apply only when the case declares an AI system. Module-wide entries rest on each module's docstring, verified at 93aa9cd; on a new revision re-read them and confirm every module and class still exists. Do not translate garak's own `owasp:` tags, which use 2023 numbering. The garak arm of `engine_rule_identifiers_have_the_shape_their_engine_actually_emits` (`src-tauri/src/adapters/control_mapping.rs`) accepts only `module.` or `module.Class/`. A content change needs a `mapping_version` bump.
- **Hard-coded tag.** None yet; the plan keeps a null tag and digest. `support_until` is 2026-12-11.
- **Compare with raw output.** In the raw `report.jsonl`, every `eval` row with `fails` above 0 should be one `probe/detector` finding stating `fails` of `total_evaluated`, rows with `fails` 0 should produce nothing, and the location should match the `start_run setup` row's target.
