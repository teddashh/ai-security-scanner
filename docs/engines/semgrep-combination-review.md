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

The builder on `main` still selects 1,620 rules from `947bf05744d4c95153173a24879f30b3ba1a65aa` under the [Semgrep Rules License](https://semgrep.dev/legal/rules-license/), which disallows distributing that pack. The catalog's published digest still runs four product rules. The local candidate now integrates the combination into its own Dockerfile, builder and launcher; `main` and the public pin remain unchanged.

## Published source attachment inspection

Inspection of the actual pinned image on 2026-10-02 found that its **source attachment already includes the newer upstream rules**, although runtime loads only the four product rules. A runtime-only license inventory therefore gave an incomplete picture. The included `semgrep-submodules.lock` identifies rules revision `947bf05744d4c95153173a24879f30b3ba1a65aa`, and the attached `semgrep/tests/semgrep-rules/LICENSE` names Semgrep Rules License v1.0. That license's distribution limitation applies to source copies too; do not describe this published artifact as containing no Semgrep-licensed rules.

| Inspected artifact | Exact evidence |
| --- | --- |
| Image | `sha256:6240c4ce08f9a5d7ead0914d907fae08704a1b783c3a7f8f405f978e9b596498` |
| `/usr/share/source/semgrep-source.tar.gz` | 35,283,032 bytes; SHA-256 `fda0997eb761a5bfb43b4b5ef879e2261d6f67966782efcacd019699053b0c16` |
| License inside that tarball | `semgrep/tests/semgrep-rules/LICENSE`, 92 bytes; SHA-256 `1a6466ae5f1c68631bbd13e3f1aa8f380d84219853c08f0456b853fccfacee1d` |
| Runtime four-rule file | SHA-256 `2081a62359682db1ddd15eda7eed1f3931975870cef8f8dab7120ba86fe2e5f3`; no runtime upstream `rules/` directory |
| Attached rule content | 2,191 YAML/YML files including tests/templates; `python/lang/security/audit/subprocess-shell-true.yaml`, 1,364 bytes, SHA-256 `753ba9d29d592b3d7f5086e671e424ee05138acbf75a39b663d92aa3275f5380`, byte-matches the exact `947bf...` source archive |

This finding is recorded for the owner's artifact/distribution decision. No published image was replaced or removed. Candidate testing does not resolve the existing public artifact.

## Per-file license exception and source attachment

The old repository's root license is not the entire license story. [java/lang/security/audit/xss/no-direct-response-writer.yaml](https://github.com/semgrep/semgrep-rules/blob/0f5a85ceab1b82b193d0eaa418784c932d237d68/java/lang/security/audit/xss/no-direct-response-writer.yaml) declares proprietary terms in its metadata. Its SHA-256 is `44f00a2b33815116facd15a58b4d360418c7940c2cbdde671856f042d4f5498f`. The local builder excludes its one rule and records the path, source hash and reason. The remaining explicit per-file license annotations in the selected files are Commons Clause/LGPL; unexpected annotations stop the experiment's builder.

The exclusion must cover **both runtime configs and distributed source attachments**. The Dockerfile on `main` makes a complete Semgrep source tarball after extracting all submodule archives. Merely omitting a runtime rule would leave the proprietary file in that full tarball. The local candidate checksum-verifies the rules input but skips full extraction into the compiler tree. `prepare_source_bundle.py` instead attaches the 1,477 selected original files with the exact legacy README/license, retains the engine and its 35 compiler/parser submodules, and includes the product source/license, builder, launcher source, Dockerfile, lock, provenance and an explicit source-profile record. An already-populated rule gitlink fails assembly. Neither the excluded rule nor the whole rules archive goes into the runtime image's attachment.

The attachment is an engine source tree with a deliberately selected rules profile, not an unmodified full rules checkout. Compilation prerequisites still require network access. Its deterministic Python tar/gzip writer normalizes headers and avoids relying on unsupported BusyBox `tar --sort` flags.

Intermediate build layers matter too. The input archive contains the excluded proprietary file even when final configs do not. The candidate uses a read-only BuildKit bind mount for that archive during selection, rather than `COPY` into a layer, so a future `mode=max` cache export cannot acquire a raw-archive layer. Docker documents that [build bind mounts are not persisted in the image or cache](https://docs.docker.com/build/cache/optimize/#use-bind-mounts). The native compiler cache receives only the 35 compiler/parser archives. Re-check cache exports as well as final image/source contents before publishing.

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

These initial runs load the combined configuration and exercise the applicable rules for six fixtures. They do **not** prove every selected rule/language works on representative real projects, both image architectures, or source-package distribution. Candidate integration checks are recorded separately below.

## Local build integration

The local-only worktree now uses one implementation in `build_rule_pack.py`; the old preview command delegates to it. The candidate lock pins the legacy archive and canonical upstream URL. The builder checks the exact archive/root license, unchanged product source and Apache license, selected per-file license annotations, ID round-trip, original sources and counts before packaging. The config manifest remains `63678fc6790ebdeca2961080095611030b8e51f8b19ac228ee7e2c6862083040`; provenance SHA-256 is `a5f8961abe75a57da4c752f39272baa64ac95ca4181e507c070772c54f5c09bf`.

The candidate launcher verifies the 1,478-file manifest and the provenance digest before executing CE. Runtime configs, provenance, upstream notice, product notice and source attachment have distinct image paths; provenance stays outside `rules/`. The candidate has a local-only label and no newly assigned publication version. Public catalog, plan, workflow, mappings and artifact pins are unchanged.

The Dockerfile separates the 35 compiler/parser inputs from the rules archive. A generated compiler-only lock feeds the native build; rule-only updates can preserve the compiler cache. Source assembly and launcher changes do not sit in the native compiler's parent layers. Opam initialization, compiler switch, dependencies and core compilation have separate cache steps. `OPAMJOBS=4` bounds dependency builds, and upstream `make core` runs with `DUNE_JOBS=4` ([Dune's documented setting](https://dune.readthedocs.io/en/stable/reference/config/jobs.html)), preserving the Makefile's tree-sitter environment. Launcher builds use `GOMAXPROCS=4`; fixture scans use two jobs.

Keep the native dependency pins visible when updating the engine: this revision's Makefile selects opam-repository `78d29aba187e8362b8ab86c189790c0af9153d4b`, OCaml 5.3.0 and Semgrep's compiler fork `aaaacf27f74fd87eb5b9887fb9995bee4cedb979`; platform-specific dependency locks and `validate-compiler-sha.sh` stay upstream-owned. Its `scripts/build-static-libcurl.sh` downloads curl **8.5.0**, SHA-256 `05fc17ff25b793a437a0906e0484b82172a9f4de02be5ed447e0cab8c3475add`, and builds a minimal static library because the Alpine archive pulls unsupported optional link dependencies. Updating Alpine `curl-dev` does not update that separately compiled curl. Do not replace this upstream hook with the system static library without checking the link behavior and upstream change.

That hook also installs `openssl-libs-static` and `zlib-static` from Alpine without explicit version arguments. Both the amd64 build and ARM64 attempt acquired **3.5.9-r0** and **1.3.2-r0**, respectively. Record their actual acquired versions on the next build; the pinned source/base and Dockerfile's visible APK list do not freeze those hook-installed packages.

The 36-record submodule lock is not the whole dependency inventory. Upstream opam `pin-depends` also retrieves source revisions, including `semgrep/pcre2-ocaml@e88c082341e4ff278eed892c17032df83b26e585` and `semgrep/ocaml-tree-sitter-core@c4baff8d83b2e1f83f247acb11d0c9dafa5e48f7`. The latter differs from the `libs/ocaml-tree-sitter-core` submodule revision `2dc9e0c738086df1ce4de93723302d9560d5b76c`. Both build logs show these pins; preserve their separate roles/revisions rather than treating a repository name as one dependency version.

Fresh inspection of the pinned Alpine 3.23 amd64 repository required these exact updates: `curl-dev` 8.22.0-r0, `pcre2-dev`/`pcre2-static` 10.49-r0, `python3` 3.12.15-r0 in both stages, `rsync` 3.5.0-r0 and `xz-static` 5.8.4-r0. Both package-install stages passed in the actual local build. Re-check repository availability next time; these values are observations, not a move-to-latest policy.

Local integration completed on **2026-10-03**. Ten Python pack/source tests passed, including reproducibility, detector-byte restoration, refused unpinned/changed inputs, refused changed originals, and refused full-rule source checkout. Go launcher tests passed in the pinned Go toolchain. The engine compiled natively for amd64 with the upstream compiler SHA check passing and CE version `1.174.0`; its network-off Dockerfile fixture smoke produced 22 results without errors. The final cache-safety rebuild reused every native compilation stage.

| Candidate check | Verified outcome |
| --- | --- |
| Local tag / image ID | `aiss-local/semgrep-combined:review` / `sha256:c3491ec47dd433fae864a68d83b550e14b84029608493127e2bb0db9c5acb877`; local Docker image, not a public registry pin |
| Direct product / upstream / combined | 10 / 12 / 22 results, errors empty |
| Fixed managed launcher | 22 results; complete result objects equal the separate-pass multiset union |
| Altered product rule / altered provenance / extra rule | Each refused with exit 126 before scanner output; no result file |
| Real shared normalizer on managed JSON | 22 native results → 22 findings, warnings empty; source IDs, relative coordinates, bounded titles, severities and raw-artifact hash preserved |
| Actual runtime source attachment | 33,033,800 bytes; SHA-256 `d30bdcb4e694505a6c1cc1b16477de9525947a844eae648108ce971a8a9db0b0`; exactly 1,477 selected original files in the rules gitlink, exact legacy notice and source profile, excluded file/whole rules archive absent |
| Attached Dockerfile / launcher source | SHA-256 `14b6a917ef9e576e3b58c7e636fe883de51e26c79e1f7acbc1afdaebf5e1e1a6` / `ddd5775990c5ecff62a356a5480e4dd88afe9521e2f00ee94c03cedcc9592794` |

Evidence is retained locally under `~/.cache/aiss-semgrep-combined/`: `native-build-v2.log`, `native-build-final.log`, `managed-verification/verification.json`, each native JSON/log, `managed-adapter-verification.json`, `candidate-source-inspection.json`, `published-source-inspection.json` and `published-rules-inspection.json`. This is one native architecture and six synthetic files, not all-language/project coverage or distribution clearance. ARM64 work is recorded separately below. No public image, catalog pin or live scan changed.

The revised verification runner was rechecked natively on amd64 after the ARM64 attempt. With explicit image architecture/entrypoint checks, `--pull never`, a `noexec` mode-1777 tmpfs and a 512 MiB file-size bound, the same image again produced **10 / 12 / 22 / 22** results with empty errors. Complete combined/managed result objects equal the separate-pass union, and all three tamper cases again returned 126 before output. The real normalizer again produced **22 findings with no warnings**, retaining IDs, locations, severity and raw evidence. Evidence: `managed-verification-native-v2/verification.json`, its native JSON/logs and `managed-native-v2-adapter.log`; managed JSON SHA-256 `861140fd126a1ad251f89198302034e3c945c091896fe2f05b2f8b4f5ed2f5bb`.

## ARM64 local validation attempt

Attempted on 2026-10-03 on an **amd64 host**. The default Docker builder supports only amd64; the host has no ARM64 `binfmt_misc` registration. A separate task-owned `docker-container` builder used the same official BuildKit digest as the existing image workflow: `moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8` (BuildKit v0.32.2). Its `buildkit-qemu-aarch64` is v10.2.3, SHA-256 `239ff153cde81b6a6ab2c48eef9cff234751caa8e9d841363eace8db51e000e8`.

BuildKit can invoke its [bundled user-mode emulator](https://github.com/moby/buildkit/blob/master/docs/multi-platform.md) without registering a host interpreter. This helper has upstream [child-process execution](https://github.com/tonistiigi/binfmt/blob/master/patches/buildkit-direct-execve-v10.2/0001-linux-user-have-execve-call-qemu-via-proc-self-exe-t.patch) and [script-interpreter support](https://github.com/tonistiigi/binfmt/blob/master/patches/buildkit-direct-execve-v10.2/0004-linux-user-support-loading-scripts-with-shebang.patch). Its [BuildKit-specific documentation](https://github.com/tonistiigi/binfmt#buildkit-target) says not to install it into kernel `binfmt_misc`. No global interpreter or other project's builder was changed.

The builder was limited to four CPUs, 8 GiB memory and reduced CPU shares; CPU affinity was also constrained to four allowed host CPUs, and `nproc` inside it returned four. An explicit ARM64 Alpine `RUN --network=none` printed `aarch64` and executed a child shell, although `buildx inspect` did not list ARM64 among native worker platforms. Test actual execution before treating that platform list as the final capability check.

| ARM64 attempt | Observed result |
| --- | --- |
| Build/runtime APK installs | Passed with candidate pins |
| Launcher | Native-host Go tests passed; cross-compiled ELF machine 183 (AArch64), SHA-256 `70d9f2a3d3e55dd59d6c4a111b9a6c0e1919d269f25d53ee191463e929024f16` |
| Config manifest / provenance / source attachment | All byte-match the amd64 artifacts; same 1,478 configs and selected-originals source profile |
| Compiler switch / static curl | OCaml 5.3.0 switch and static curl completed; upstream locked dependency installation started |
| Actual ARM64 launcher preflight | Exit 126 before scanner execution: `workspace mount is writable; refusing to scan` |
| Kernel mount / attempted write | `/workspace` reported `ro`; an attempted write to the synthetic fixture mount failed with `Read-only file system` |
| Full engine/image/scan | Build stopped after the incompatible safety preflight; no completed ARM64 image or managed scan |

A minimal Go `statfs` probe compared a read-only and writable task directory in the same container boundaries:

| Probe | Read-only mount flags | Writable mount flags |
| --- | --- | --- |
| Native amd64 | 4129; read-only bit present | 4128; read-only bit absent |
| ARM64 through the exact BuildKit helper | **0; read-only bit absent** | **0; read-only bit absent** |

This helper cannot represent the mount property required by the managed launcher's existing check. [QEMU v10.2.3 source](https://github.com/qemu/qemu/blob/v10.2.3/linux-user/syscall.c#L10568-L10597) has an `_STATFS_F_FLAGS` compile-time guard that writes zero when absent; that path is consistent with the observation, but the exact helper's compiler configuration was not independently recovered. This is an emulation limitation, not evidence that the mount was writable or that a native ARM64 run fails. The product's read-only check and detector/launcher code were kept intact.

The managed verification script therefore requires a **native host matching the image architecture**. It accepts only the two local review tags, checks Linux architecture and the fixed managed entrypoint, uses `--pull never`, and records host/image architecture. Its scan containers now also use a `noexec`, mode-1777 temporary filesystem and a 512 MiB file-size bound. Native ARM64 build, managed execution and performance remain unverified.

Evidence is retained under `~/.cache/aiss-semgrep-combined/`: `arm64-build.log`, `arm64-input-export.log`, `arm64-input-inspection.json`, `arm64-launcher-input-preflight/valid-inputs.log`, `arm64-readonly-probe.log`, `statfs-comparison.json` and the minimal `statfs-probes.Dockerfile`/binaries. The task's build was stopped by its own client PID, and its builder was stopped with completed cache retained. No public artifact or live scan changed.

## Overlap review

These are observed similarities and differences, not approved suppression or grouping rules. All source records stay available. Rating pairs below mean **native severity / native confidence**, for example `ERROR / LOW`; `LOW` is not a lowered severity. The existing adapter maps `ERROR` to High, `WARNING` to Medium and `INFO` to Informational while preserving the separate source confidence.

| Product rule | Related upstream rule IDs (original short IDs) | Observed difference / report decision to review |
| --- | --- | --- |
| `ai-security-scanner.python.dynamic-code-execution` | `eval-detected`, `exec-detected` | Product fires on dynamic input and constant `eval("1 + 1")`; upstream fires only on the two dynamic fixture calls. Product ERROR/HIGH versus upstream WARNING/LOW. Broad construct detection is not proof that the constant call is exploitable. |
| `ai-security-scanner.python.shell-true` | `dangerous-subprocess-use-audit`, `subprocess-shell-true`, `dangerous-system-call-audit` | One dynamic subprocess call yields two upstream observations with different spans; the product also fires on a constant command. Keep the upstream `shell=True` fix and each source's confidence. Family/CWE alone must not suppress an observation. |
| `ai-security-scanner.javascript.child-process-exec` | `detect-child-process` | Product covers three fixture calls including the constant command and TypeScript; upstream matches the dynamic JavaScript call only, at a different column. Product WARNING/MEDIUM versus upstream ERROR/LOW. |
| `ai-security-scanner.generic.private-key` | `private-key` from `generic/secrets/gitleaks/private-key.yaml`; the separate `detected-private-key` rule does not match this fixture | Both observe the synthetic header. Product ERROR/HIGH versus upstream INFO/LOW. Neither proves a usable private key exists; preserve detector provenance and confirm actual key material before claiming exposure. |
| No related product rule | Dockerfile USER and four Kubernetes configuration checks | The legacy pack adds five fixture observations outside the four product-rule constructs. Preserve their individual upstream IDs and guidance. |

No changes to shared report grouping or severity/confidence policy were made for this experiment. A grouping proposal would need exact observation identity, spans, engine-run/asset binding and preservation of every contributing source, following the [report boundary](../engine-maintenance.md#3-common-professional-report-boundary).

## Repeat the local preview

The experiment is kept on the **local-only** branch `semgrep-combined-local`, image integration commit `afdafb00dd3df3cab67566a33d4bc9c385f99c71` and verification-script commit `11967e8d5190553551d00559e77ca06343d9ebf0`, in the sibling worktree `../ai-security-scanner-semgrep-local`. The latter changes only the test runner, not Dockerfile, detector, launcher or source-attachment bytes. It is deliberately absent from `main`'s image build inputs because changing those inputs can automatically publish all six local/k8s engines. The branch contains:

- `engines/images/semgrep/build_rule_pack.py`: shared candidate/preview acquisition and license checks, collision-free IDs, original bytes, provenance and manifest; `preview_combined_pack.py` delegates to it.
- `prepare_source_bundle.py`, `test_source_bundle.py` and candidate `SOURCE-OFFER.md`: selected original sources, unchanged compiler/parser closure, reproducible attachment and rejected unintended source files.
- Candidate `Dockerfile`, `submodules.lock` and shared launcher: local-only integration, separate compiler/rule stages, exact runtime config/provenance verification, and bounded native build.
- `product-rules.yml` and `product-LICENSE`: original published product-rule source and project license.
- `test_combined_preview.py`: reproducibility/provenance, rejected wrong archive, rejected changed product detector, and no overwrite of an existing pack.
- `run_combined_preview.py`: exact bounded Docker invocations, isolated anonymous image pull, all three passes, native JSON/log preservation and complete-result union check.
- `run_managed_combination.py`: local candidate only, no pull; repeats the separate/combined passes, compares full native results with the fixed launcher, and checks altered configs/provenance or extra rules are refused before output.
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

To build and test the local candidate from the same worktree, use an empty task-local Docker config. These commands load only a local amd64 image:

```sh
anonymous_docker=/absolute/path/to/new-empty-docker-config
mkdir -p "$anonymous_docker"
printf '{}\n' > "$anonymous_docker/config.json"
DOCKER_CONFIG="$anonymous_docker" node scripts/prepare-offline-engine-data.mjs semgrep
DOCKER_CONFIG="$anonymous_docker" nice -n 10 docker buildx build \
  --builder default --platform linux/amd64 --progress plain --load \
  -t aiss-local/semgrep-combined:review -f engines/images/semgrep/Dockerfile .
managed_output=/absolute/path/to/new-managed-verification-directory
PYTHONDONTWRITEBYTECODE=1 python3 engines/images/semgrep/run_managed_combination.py \
  --archive "$legacy_archive" --output "$managed_output"
```

Before publication, reconcile selected-profile disclosure, catalog rule/data dates, source/notice records, plan facts, new build-input coverage and local/k8s workflow reach. Public release guards intentionally still describe the old published artifact; this local candidate does not claim those records bind it. Re-check native builds on each intended architecture and decide how to handle the already-published restricted source attachment. Publication remains an owner decision after these exact artifacts and results can be reviewed.

To repeat the candidate on a **native Linux ARM64 host**, use a task-owned builder. The known helper above cannot validate managed execution on amd64. Run only one heavy build or scan at a time:

```sh
case "$(uname -s)/$(uname -m)" in
  Linux/aarch64|Linux/arm64) ;;
  *) printf 'Managed ARM64 validation requires a native ARM64 host.\n' >&2; exit 1 ;;
esac
arm_builder=aiss-semgrep-arm64-review
task_cpuset=$(python3 -c 'import os; print(",".join(map(str, sorted(os.sched_getaffinity(0))[-4:])))')
DOCKER_CONFIG="$anonymous_docker" docker buildx create \
  --name "$arm_builder" --driver docker-container \
  --driver-opt image=moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8 \
  --driver-opt memory=8g --driver-opt cpu-period=100000 \
  --driver-opt cpu-quota=400000 --driver-opt cpu-shares=256 \
  --driver-opt "cpuset-cpus=$task_cpuset" --bootstrap
DOCKER_CONFIG="$anonymous_docker" nice -n 10 docker buildx build \
  --builder "$arm_builder" --platform linux/arm64 --progress plain --load \
  -t aiss-local/semgrep-combined-arm64:review \
  -f engines/images/semgrep/Dockerfile .
arm_output=/absolute/path/to/new-arm64-verification-directory
PYTHONDONTWRITEBYTECODE=1 python3 engines/images/semgrep/run_managed_combination.py \
  --archive "$legacy_archive" --output "$arm_output" \
  --image aiss-local/semgrep-combined-arm64:review
# Stop only this task's builder after its builds finish; retain its cache.
DOCKER_CONFIG="$anonymous_docker" docker buildx stop "$arm_builder"
```

If reusing an existing task builder, inspect its pinned image and resource limits instead of recreating it blindly. Keep build logs, source inspection, native JSON, normalization and the recorded execution architecture together.
