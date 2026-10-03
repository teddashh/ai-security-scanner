# Semgrep legacy + product rule combination review

Local experiment, 2026-10-02. The owner selected a combination of the last rules snapshot before the license change and the existing four product rules for local evaluation. **No candidate image has been published or pinned.** This review complements [Semgrep maintenance](semgrep.md) and the [image build notebook](image-build-index.md).

## Exact inputs and selection

| Input | Reviewed value |
| --- | --- |
| Engine used for execution | Semgrep CE `1.174.0`, from `ghcr.io/teddashh/ai-security-scanner-engine-semgrep@sha256:6240c4ce08f9a5d7ead0914d907fae08704a1b783c3a7f8f405f978e9b596498`; direct CLI entrypoint, not a candidate managed launcher |
| Legacy rules revision | `semgrep/semgrep-rules@0f5a85ceab1b82b193d0eaa418784c932d237d68`, parent of the 2024-12-13 license-change commit `2a662d5bc191758d43719de5d7ee0ca84aed3870` |
| Archive | [Pinned codeload archive](https://codeload.github.com/semgrep/semgrep-rules/tar.gz/0f5a85ceab1b82b193d0eaa418784c932d237d68), 1,148,011 bytes, SHA-256 `a6bb2ee1a261da82a1263c1b32ad6f4535628742192c0bb1f68f13343c31bbcc` |
| Root license | [LICENSE at the exact revision](https://github.com/semgrep/semgrep-rules/blob/0f5a85ceab1b82b193d0eaa418784c932d237d68/LICENSE), SHA-256 `9600f388f17cb800a7a0ba8b55bc15c5b0ed047de8517f2d5e533becee9d0a18`; LGPL 2.1 plus Commons Clause |
| Product rules | Original `engines/images/semgrep/rules.yml` from publication source commit `2641850`, four rules, SHA-256 `2081a62359682db1ddd15eda7eed1f3931975870cef8f8dab7120ba86fe2e5f3`; IDs and detector bodies unchanged |
| Selection | Existing builder's security/secrets path and metadata-category selection; no test YAML or Apex; one explicitly proprietary rule excluded |
| Selected pack | **1,477 upstream files / 1,493 upstream rules**, plus one product file / four rules: **1,478 config files / 1,497 unique runtime IDs** |
| Config manifest | SHA-256 `63678fc6790ebdeca2961080095611030b8e51f8b19ac228ee7e2c6862083040`; sorted config-path/hash records, byte-reproducible in two separate builds |

The current production-source builder still selects 1,620 rules from `947bf05744d4c95153173a24879f30b3ba1a65aa` under the [Semgrep Rules License](https://semgrep.dev/legal/rules-license/), which disallows distributing that pack. The catalog's published digest still runs four product rules. Neither was changed by this experiment.

## Per-file license exception and source attachment

The old repository's root license is not the entire license story. [java/lang/security/audit/xss/no-direct-response-writer.yaml](https://github.com/semgrep/semgrep-rules/blob/0f5a85ceab1b82b193d0eaa418784c932d237d68/java/lang/security/audit/xss/no-direct-response-writer.yaml) declares proprietary terms in its metadata. Its SHA-256 is `44f00a2b33815116facd15a58b4d360418c7940c2cbdde671856f042d4f5498f`. The local builder excludes its one rule and records the path, source hash and reason. The remaining explicit per-file license annotations in the selected files are Commons Clause/LGPL; unexpected annotations stop the experiment's builder.

The exclusion must cover **both runtime configs and distributed source attachments**. The production Dockerfile currently makes a complete Semgrep source tarball after extracting all submodule archives. Merely omitting a runtime rule would leave the proprietary file in that full tarball. The preview retains only the selected original rule files in its `source/` directory and never copies the entire input rules archive into an image or attachment. A future production build still needs a reviewed corresponding-source assembly; this preview does not provide the complete Semgrep engine source closure.

Combining product rules does not remove the upstream pack's Commons Clause restrictions. Preserve license text and attribution separately for upstream rules and product rules. Publication or paid/service distribution requires an owner decision based on these exact terms; this test is technical evidence, not a distribution clearance.

## IDs and provenance

The initial legacy selection had **62 bare IDs occurring in multiple files**. Within-file IDs were unique. Passing all files with `--no-rewrite-rule-ids` without resolving these collisions can confuse attribution or lose rules/results.

The preview uses `<upstream file path without extension, with dots>.<original id>` as the upstream runtime ID. For example:

```text
source:     python/lang/security/audit/eval-detected.yaml
original:   eval-detected
runtime:    python.lang.security.audit.eval-detected.eval-detected
```

It changes only the ID text and adds a dated modification comment. Every selected original file is retained byte-for-byte. `RULE-PROVENANCE.json` records each runtime ID's original ID, source path, repository/revision and original-file SHA-256; it lives outside `rules/`. The four product IDs retain their existing names. A round-trip check restores all upstream ID lines and compares the full original bytes, including CRLF files. Native patterns, options, severity, confidence, messages, metadata and fixes are unchanged.

This is a config-ID customization, not an upstream rule update. A future report must retain original source IDs as well as runtime IDs. Product-rule mappings keep their existing keys; newly qualified upstream IDs need their own reviewed mappings rather than borrowing a product rule's mapping because a CWE overlaps.

## Execution and comparison

Six synthetic files cover Python dynamic and constant eval/shell calls, JavaScript dynamic and constant child-process calls, a TypeScript call, a Dockerfile without USER, a privileged Kubernetes pod, and a private-key header with **no real key material**. No code or shell command in these files is executed.

Each run uses network off, read-only root/input mounts, dropped capabilities, no-new-privileges, two CPUs, 2 GiB memory, 256 PIDs and a 512 MiB temporary filesystem. The container runs under the host UID for the writable synthetic-output mount, matching the desktop's Unix UID mapping. CE is invoked with:

```text
scan --json --output /output/<pass>.json --config <config-directory>
--metrics=off --disable-version-check --no-rewrite-rule-ids --oss-only
--jobs 2 --max-memory 2048 --timeout 10 --timeout-threshold 3
--max-target-bytes 10000000 /workspace
```

| Pass | Applicable rules run on these fixtures | Native matches | Exit / errors |
| --- | --- | --- | --- |
| Product only | 4 | 10 | 0 / empty |
| Legacy upstream only | 693 | 12 | 0 / empty |
| Combined | 697 | 22 | 0 / empty |

The complete JSON result objects from the combined pass equal the multiset union of the two separate passes, including native IDs, messages, ratings, locations, metadata and fixes. No result was overwritten or suppressed by combination. Five exact path/line/column coordinates occur in both passes. The JavaScript call is also observed by both, but the columns differ; source-coordinate equality alone is not a sufficient grouping rule.

The adapter smoke uses the real shared normalizer with a synthetic manifest labeled as a local candidate, with no claimed candidate image digest. It checks finding count, warnings, source IDs, snapshot-relative line/column locations, severity mapping and raw-artifact SHA-256. It produced **22 normalized findings with no warnings**; every result retained its source ID, snapshot-relative line/column, native severity mapping, bounded title and raw-artifact hash. Existing display titles are bounded at 512 characters; two fixture messages exceed that bound, while complete native messages remain in the raw JSON.

The legacy pack emits upstream warnings about include/exclude path patterns whose interpretation may change in a future Semgrepignore version. These warnings are preserved in logs. Do not edit upstream path patterns merely to silence them; re-check effective file selection when upgrading CE.

These runs load the combined configuration and exercise the applicable rules for six fixtures. They do **not** prove every selected rule/language works on representative real projects, both image architectures, the production launcher/manifest, or source-package distribution.

## Overlap review

These are observed similarities and differences, not approved suppression or grouping rules. All source records stay available.

| Product rule | Related upstream rule IDs (original short IDs) | Observed difference / report decision to review |
| --- | --- | --- |
| `ai-security-scanner.python.dynamic-code-execution` | `eval-detected`, `exec-detected` | Product fires on dynamic input and constant `eval("1 + 1")`; upstream fires only on the two dynamic fixture calls. Product ERROR/HIGH versus upstream WARNING/LOW. Broad construct detection is not proof that the constant call is exploitable. |
| `ai-security-scanner.python.shell-true` | `dangerous-subprocess-use-audit`, `subprocess-shell-true`, `dangerous-system-call-audit` | One dynamic subprocess call yields two upstream observations with different spans; the product also fires on a constant command. Keep the upstream `shell=True` fix and each source's confidence. Family/CWE alone must not suppress an observation. |
| `ai-security-scanner.javascript.child-process-exec` | `detect-child-process` | Product covers three fixture calls including the constant command and TypeScript; upstream matches the dynamic JavaScript call only, at a different column. Product WARNING/MEDIUM versus upstream ERROR/LOW. |
| `ai-security-scanner.generic.private-key` | `private-key` from `generic/secrets/gitleaks/private-key.yaml`; the separate `detected-private-key` rule does not match this fixture | Both observe the synthetic header. Product ERROR/HIGH versus upstream INFO/LOW. Neither proves a usable private key exists; preserve detector provenance and confirm actual key material before claiming exposure. |
| No related product rule | Dockerfile USER and four Kubernetes configuration checks | The legacy pack adds five fixture observations outside the four product-rule constructs. Preserve their individual upstream IDs and guidance. |

No changes to shared report grouping or severity/confidence policy were made for this experiment. A grouping proposal would need exact observation identity, spans, engine-run/asset binding and preservation of every contributing source, following the [report boundary](../engine-maintenance.md#3-common-professional-report-boundary).

## Repeat the local preview

The experiment is kept on the **local-only** branch `semgrep-combined-local`, in the sibling worktree `../ai-security-scanner-semgrep-local`. It is deliberately absent from `main`'s image build inputs because changing those inputs can automatically publish all six local/k8s engines. The branch contains:

- `engines/images/semgrep/preview_combined_pack.py`: strict acquisition/license checks, selection, collision-free IDs, original bytes, provenance and manifest.
- `product-rules.yml` and `product-LICENSE`: original published product-rule source and project license.
- `test_combined_preview.py`: reproducibility/provenance, rejected wrong archive, rejected changed product detector, and no overwrite of an existing pack.
- `run_combined_preview.py`: exact bounded Docker invocations, isolated anonymous image pull, all three passes, native JSON/log preservation and complete-result union check.
- `testdata/combination-review/`: six synthetic fixture files.
- `src-tauri/examples/semgrep_combination_smoke.rs`: normalization-only check; no scanner startup, live cases or credentials.

From that worktree:

```sh
# Save the pinned codeload archive above to a task-local path, then verify it.
legacy_archive=/absolute/path/to/semgrep-rules-0f5a85c.tar.gz
preview_output=/absolute/path/to/new-preview-directory
PYTHONDONTWRITEBYTECODE=1 python3 engines/images/semgrep/preview_combined_pack.py \
  --archive "$legacy_archive" \
  --product engines/images/semgrep/product-rules.yml --output "$preview_output"
PYTHONDONTWRITEBYTECODE=1 SEMGREP_LEGACY_ARCHIVE="$legacy_archive" \
  python3 engines/images/semgrep/test_combined_preview.py
```

To repeat all three passes with preserved JSON/logs and a full-result union check, use a new output directory. This script pulls only the pinned image with an empty task-local Docker config, then scans only its six checked-in synthetic fixtures:

```sh
experiment_output=/absolute/path/to/new-experiment-directory
PYTHONDONTWRITEBYTECODE=1 python3 engines/images/semgrep/run_combined_preview.py \
  --archive "$legacy_archive" --output "$experiment_output"
```

The script also places combined JSON in `adapter/semgrep.json` for the normalization check:

```sh
nice -n 10 cargo run --locked --offline -j4 \
  --no-default-features --features cli --example semgrep_combination_smoke \
  -- "$experiment_output/adapter/semgrep.json"
```

Before any production integration, resolve the complete-source attachment, pack/provenance packaging, launcher manifest/hash/file count, Dockerfile smoke IDs, selected profile disclosure, catalog rule/data dates, plan facts and local/k8s workflow reach. Re-check the current Alpine build pins and native build on each intended architecture. The published four-rule image stays in place until that work and the owner's publication decision are complete.
