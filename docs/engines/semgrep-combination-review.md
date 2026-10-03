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

This helper cannot represent the mount property required by the managed launcher's existing check. [QEMU v10.2.3 source](https://github.com/qemu/qemu/blob/v10.2.3/linux-user/syscall.c) has an `_STATFS_F_FLAGS` compile-time guard that writes zero when absent; that path is consistent with the observation, but the exact helper's compiler configuration was not independently recovered. This is an emulation limitation, not evidence that the mount was writable or that a native ARM64 run fails. The product's read-only check and detector/launcher code were kept intact.

The managed verification script therefore requires a **native host matching the image architecture**. It accepts only the two local review tags, checks Linux architecture and the fixed managed entrypoint, uses `--pull never`, and records host/image architecture. Its scan containers now also use a `noexec`, mode-1777 temporary filesystem and a 512 MiB file-size bound. Native ARM64 build, managed execution and performance remain unverified.

Evidence is retained under `~/.cache/aiss-semgrep-combined/`: `arm64-build.log`, `arm64-input-export.log`, `arm64-input-inspection.json`, `arm64-launcher-input-preflight/valid-inputs.log`, `arm64-readonly-probe.log`, `statfs-comparison.json` and the minimal `statfs-probes.Dockerfile`/binaries. The task's build was stopped by its own client PID, and its builder was stopped with completed cache retained. No public artifact or live scan changed.

### Follow-up: local glibc helper

On 2026-10-03 a separate **local testing helper** was built on the amd64 host using glibc, whose actual headers define `_STATFS_F_FLAGS`. No Semgrep detector, Dockerfile, managed launcher or read-only guard was changed. The helper is not installed into `binfmt_misc`, copied into an engine image, or substituted into BuildKit. The native-only candidate runner remains native-only.

| Helper build input | Exact observed input |
| --- | --- |
| QEMU release archive | [10.2.3](https://download.qemu.org/qemu-10.2.3.tar.xz), 141,095,748 bytes; observed SHA-256 `2aa0e420e4ea89ea34a833f4c4eced96a35b51a9ee8568b232692729b60b064d` |
| Child execution / script support | Seven patches from [tonistiigi/binfmt at `e41434f`](https://github.com/tonistiigi/binfmt/tree/e41434fefad6aee7b01fbe5efc1c4b6f6c735fff/patches/buildkit-direct-execve-v10.2), applied in filename order |
| Host compiler / libc | GCC 15.2.0 (`gcc-15` 15.2.0-16ubuntu1); glibc 2.43 (`libc6-dev` 2.43-2ubuntu2.4) |
| Host static libraries | GLib 2.88.0 (2.88.0-1ubuntu0.1), PCRE2 10.46 (10.46-1build1), sysprof capture 50.0-1 |
| Python / build tools | Python 3.14.4; archive-provided Meson 1.9.0 / pycotap 1.3.1; task-local Ninja 1.13.0 wheel SHA-256 `fb46acf6b93b8dd0322adc3a4945452a4e774b75b91293bafcc7b7f8e6517dfa` |
| Resulting helper | Static PIE Linux amd64 `qemu-aarch64`, version 10.2.3; SHA-256 `bcaf5c26953814a0f3033101140fb342eb049d054d35fb3cb07a49d36a188406` |

The release archive's hash records the acquired bytes; it is not an independently verified upstream checksum. The extracted linux-user source excludes `roms/`, which is unnecessary for this target and contains an absolute symlink refused by Python's `data` extraction filter. The filter remains enabled for extracted files.

One upstream patch needed a **context-only** adjustment: QEMU 10.2.3 removed the unused `regs` argument from `loader_exec`. In patch `0004-linux-user-support-loading-scripts-with-shebang.patch`, replace the two context lines containing `struct target_pt_regs *regs, struct image_info *infop,` / `struct linux_binprm *bprm)` with `struct image_info *infop, struct linux_binprm *bprm)`, and change that hunk's old/new line counts from 7 to 6. Its actual additions/deletions remain identical. Original patch SHA-256: `e803d8145ce49a31669048e046d8226be2b074cdb08014cc03f21ab56743ae98`; adjusted SHA-256: `20978f806121bb6ffe50015a0efb840e437e742ae518accd54b50ce5fd1e9553`. Apply with `patch --batch --fuzz=0 -p1`; do not force a rejected hunk. No statfs code or flag values were patched.

After acquiring/extracting those exact sources and patches, create a task-local Python environment for Ninja, keep its `pip --report`, and build out of tree. Inspect the allowed host CPU set and use four of those CPUs; this host allowed CPUs 20–23. The actual configure/build recipe was:

```sh
# qemu_source is the extracted, patched QEMU 10.2.3 directory.
# helper_tools is a task-local venv containing Ninja 1.13.0.
# Run from a new task-local build directory, under nice/ionice and four-CPU affinity.
"$qemu_source/configure" --python=/usr/bin/python3 \
  --ninja="$helper_tools/bin/ninja" --target-list=aarch64-linux-user \
  --static --disable-system --disable-docs --disable-tools \
  --disable-guest-agent --disable-debug-info --disable-werror \
  --disable-capstone --disable-gcrypt --disable-gnutls --disable-nettle \
  --disable-curl --disable-slirp --disable-plugins --disable-rust
"$helper_tools/bin/ninja" -j4 qemu-aarch64
```

Before using it with scanner inputs, compare the actual mount flags and child execution on both read-only and writable disposable task mounts. The new helper returned **4129 / 4128**, matching native amd64, and correctly distinguished the read-only bit. An ARM64 child shell's attempted write failed with `Read-only file system` on the read-only mount; creation/removal succeeded on the writable control. This is measured helper behavior; the original BuildKit helper's exact compilation configuration is still unknown.

Build inputs, each downloaded patch/blob hash, the context adjustment, resulting patched-source hashes and probe logs are retained under `~/.cache/aiss-semgrep-combined/qemu-helper-glibc/`: `patch-inputs.json`, `context-adjustment.json`, `python-tools.json`, `build-manifest.json`, `build.sh`, `build.log`, `probe.py` and `probe-verification.json`. Static-glibc linker warnings about NSS/DNS remain in the build log; this helper is bounded to local network-off tests and has no portability or publication claim. A rebuild can change its binary hash when host packages change; re-run both mount controls and child-execution tests before accepting a replacement hash.

### ARM64 launcher boundaries with the local helper

The separate private `run_arm64_runtime_probe.py` uses the exact **already-published ARM64 CE manifest** `sha256:0e80059911abc48d4aab405cbcc621104c7de0b9a212dede830636940b85d66c`, with the candidate pack and cross-compiled launcher bound read-only. It pulls nothing, creates no image, checks the Linux ARM64 manifest/entrypoint and exact helper/launcher/probe-file hashes, and scans only the six synthetic fixtures. This is a runtime probe with reused CE binaries, not the completed new ARM64 candidate build.

| Actual ARM64 launcher control | Observed result |
| --- | --- |
| Changed product config | Exit 126, release digest mismatch, no output |
| Changed provenance | Exit 126, release digest mismatch, no output |
| Extra rule in a copied rules tree | Exit 126, outside immutable manifest, no output |
| Writable disposable workspace | Exit 126, writable workspace refused, no output |
| Valid configs/provenance and read-only workspace | Reached child invocation; a deliberately substituted boundary fixture printed its marker and exited 23, which the launcher propagated as a failure with no evidence output |

The last control tests input acceptance and child-process status propagation; the substituted fixture performs no security check. Boundary results remain in `arm64-managed-runtime-probe-v3/boundary-verification.json` even if a later actual scan fails.

Two fixture-wiring details matter when repeating this probe. To add a rule under an already read-only **bind-mounted** pack, materialize a separate full rules tree containing the extra file and bind that existing directory. Binding one new file onto a nonexistent child can fail at Docker setup with 125, before the launcher runs; that is not a launcher rejection. Also, a non-executable-child control through this helper returned `errno 0`, so it does not establish native exec-error fidelity. The final valid-input control uses a real executed shell fixture with explicit exit 23 instead. Neither limitation was fixed by weakening product checks.

An initial direct four-product-rule ARM64 scan completed with **10 results and empty errors**. The separate full-upstream pass hit its **600-second outer test timeout** during per-file rule checks, without a result JSON; the harness removed only its own named container. Combined/managed passes in that first attempt did not run. Evidence: `arm64-runtime-probe/product/semgrep.json`, per-pass logs and `arm64-runtime-probe.log`. Do not describe this as an ARM64 complete-result union pass.

The subsequent **single managed ARM64 run completed successfully**. Its outer allowance was 3,600 seconds, matching the managed launcher's existing one-hour limit; Semgrep's two jobs, 10-second per-rule timeout with threshold 3, 2 GiB ceiling and target-size limit remained unchanged. Containers retained two CPUs, 2 GiB memory, network off, a read-only root/workspace/configs, caller UID, dropped capabilities, no-new-privileges, 256 PIDs, a 512 MiB file-size cap and a 512 MiB noexec temporary filesystem.

| Subsequent actual scan / report check | Verified result |
| --- | --- |
| ARM64 CE through the candidate's fixed managed launcher | **22 results, `errors=[]`**, CE 1.174.0 |
| Complete result objects | Exact multiset equality with the verified amd64 managed JSON, SHA-256 `861140fd126a1ad251f89198302034e3c945c091896fe2f05b2f8b4f5ed2f5bb`; that baseline already equals the separate 10-product + 12-upstream union |
| Real shared normalizer on actual ARM64 JSON | **22 findings, no warnings**; all source IDs, snapshot-relative coordinates, native severity mapping, bounded titles and raw-evidence SHA preserved; two full messages remain beyond the 512-character display-title bound |
| Actual ARM64 managed JSON SHA-256 | `9459c3647238f9709c5d28b1141e2149afbe9eaf8eada9f641eec039dae33996` |
| Verification record SHA-256 | `934eb1b06a28593a5bfb8c8b7b50ad295ce986fb8f1340db0c1b5fe55ecafd55` |

This proves the candidate inputs/launcher can produce the same complete fixture results with the **reused published ARM64 CE binary under this helper**. It does not prove the stopped new ARM64 image build completed, native ARM64 execution/performance, or broad project/language coverage. No public artifact or live case changed.

Evidence is retained under `~/.cache/aiss-semgrep-combined/`: `arm64-managed-runtime-probe-v3/verification.json`, its boundary record, actual managed JSON and individual logs; `arm64-managed-runtime-probe-v3.log`; `arm64-managed-runtime-probe-v3-adapter.log`. The private runtime-probe implementation is commit **`0a350e4812b17a0389c8dc1bbd0e3a41d56eb356`**; it changes only the experimental runner and is not pushed. The Dockerfile, detector, launcher and attached-source inputs remain unchanged.

To repeat the successful comparison in that private worktree, keep the exact helper, exported ARM64 launcher and minimal statfs probe together. The runner accepts only their recorded hashes and the pinned successful amd64 reference. Pull the fixed public ARM64 manifest separately with a **new empty** task-local Docker config if absent; the runner itself uses `--pull never`. Use a fresh output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 nice -n 10 python3 \
  engines/images/semgrep/run_arm64_runtime_probe.py \
  --archive /absolute/path/to/semgrep-rules-0f5a85c.tar.gz \
  --output /absolute/path/to/new-arm64-runtime-probe \
  --helper /absolute/path/to/qemu-helper-glibc/qemu-aarch64 \
  --launcher /absolute/path/to/arm64-input-export/ai-security-scanner-engine-entrypoint \
  --statfs /absolute/path/to/statfs-probes/statfs-arm64 \
  --mode managed \
  --reference /absolute/path/to/managed-verification-native-v2/managed/semgrep.json
```

`--mode boundaries` repeats only the mount/input/child-status controls and makes no security-scan claim. `--mode all` still uses 600 seconds per pass; its initial full-upstream emulated pass is the timeout recorded above, not a successfully repeated four-pass ARM64 union. Never relabel either mode as a fresh or native image build.

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

The experiment is kept on the **local-only** branch `semgrep-combined-local`, image integration commit `afdafb00dd3df3cab67566a33d4bc9c385f99c71`, native verification-script commit `11967e8d5190553551d00559e77ca06343d9ebf0` and ARM64 runtime-probe commit `0a350e4812b17a0389c8dc1bbd0e3a41d56eb356`, in the sibling worktree `../ai-security-scanner-semgrep-local`. The latter two change only test runners, not Dockerfile, detector, launcher or source-attachment bytes. It is deliberately absent from `main`'s image build inputs because changing those inputs can automatically publish all six local/k8s engines. The branch contains:

- `engines/images/semgrep/build_rule_pack.py`: shared candidate/preview acquisition and license checks, collision-free IDs, original bytes, provenance and manifest; `preview_combined_pack.py` delegates to it.
- `prepare_source_bundle.py`, `test_source_bundle.py` and candidate `SOURCE-OFFER.md`: selected original sources, unchanged compiler/parser closure, reproducible attachment and rejected unintended source files.
- Candidate `Dockerfile`, `submodules.lock` and shared launcher: local-only integration, separate compiler/rule stages, exact runtime config/provenance verification, and bounded native build.
- `product-rules.yml` and `product-LICENSE`: original published product-rule source and project license.
- `test_combined_preview.py`: reproducibility/provenance, rejected wrong archive, rejected changed product detector, and no overwrite of an existing pack.
- `run_combined_preview.py`: exact bounded Docker invocations, isolated anonymous image pull, all three passes, native JSON/log preservation and complete-result union check.
- `run_managed_combination.py`: local candidate only, no pull; repeats the separate/combined passes, compares full native results with the fixed launcher, and checks altered configs/provenance or extra rules are refused before output.
- `run_arm64_runtime_probe.py`: separate reused-binary/QEMU probe, exact helper/launcher/statfs/reference hashes, mount and input controls, actual managed results compared with the verified amd64 baseline; explicitly not a new/native ARM64 candidate build.
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

## Fresh native amd64 and ARM64 builds (2026-10-03)

Publication preparation is isolated on the
[semgrep-release-20261003 branch](https://github.com/teddashh/ai-security-scanner/tree/semgrep-release-20261003).
[Run 37127986459](https://github.com/teddashh/ai-security-scanner/actions/runs/37127986459)
built fresh complete images on native amd64 and ARM64 runners from
`6fa7709c9617c05cc87d7c0096d7ee84594d829e`. Both jobs succeeded. They checked
the production-version label, attached source/licenses/rebuild inputs, four
complete fixture passes and four actual launcher refusal controls. The
publication job was skipped; no image, rule cache or source archive was uploaded.

Both architectures produced product/upstream/combined/managed counts of
**10/12/22/22**, empty errors and the exact complete-result multiset union.
Changed configs, changed provenance, an extra config and a writable workspace
each exited 126 before output. The downloaded native result multisets also
match each other and the separately verified local amd64 results.

The attached source is identical on both architectures: 33,033,850 bytes,
SHA-256 `3282013b050f79b3f417f488433a050fda219da99edc66c1a6520414842156cd`.
It retains the 1,477 selected originals and exact notices/rebuild inputs without
the excluded proprietary file or unfiltered rules archive. The real shared
normalizer turned the fresh ARM64 artifact into 22 findings without warnings,
preserving native IDs, locations, severity mapping, bounded titles and raw hashes.

| Native CI architecture | Installed-filesystem receipt SHA-256 | Verification JSON SHA-256 |
| --- | --- | --- |
| amd64 | `8bc02b97a361030ef8141165c90aa636922e18f7641d9819486dfb276e5d076b` | `9b83d3e6395474a7975aba6252f1930ee39ff7a121f366fcc9d35f210db32ed1` |
| arm64 | `cdf2e196bf1f3e7983ade54ebdcb60933f8ff7cde76585f3876661ca35674c62` | `a3fbff4930e83db58b4097f6509194e0385fc049b93f2d2296e0e712924ba9b1` |

These are verification receipts, not public release digests. The separately
built local amd64 filesystem differs from CI amd64 despite equal source
attachments and scan results. Do not infer byte-identical builds from pinned
source alone. The prepared publication path compares each candidate platform's
filesystem against that run's actual native verification before signing and
immutable-tag promotion.

The preparation branch also limits automatic publication to explicitly new
tags, isolates native Semgrep failures from selected sibling publications and
extends downloadable-artifact checks to the native receipts and complete result
union. Thirteen Python tests, 91 CI contracts, 19 publication-artifact verifier
tests and all 200 release contracts passed. Current main image pins and published
receipts remain unchanged; applicability of the legacy Commons Clause to the
owner's business model still needs an answer before publication.
