# Gitleaks

Runs Gitleaks' `dir` scan over a `repository` snapshot with upstream's default rule configuration. The scanned project cannot suppress results, and the launcher rejects any report that still holds a secret value. Git history is not scanned.

| Item | Value |
| --- | --- |
| Upstream | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 (`source_ref` `v8.30.1`), revision `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`. Rules: upstream `config/gitleaks.toml` at that revision, SHA-256 `e163e53b…` (catalog `rule_version`). |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-gitleaks:8.30.1-2` (`plan_kind: managed_build`, `MIT AND Apache-2.0`). The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/gitleaks/`: `Dockerfile`, `plan.json`, `patches/0001-add-scanner-owned-ignore-policy.patch`, `PATCHES.md`, `launcher/` (`go.mod`, `main.go`, `main_test.go`) and `testdata/` (`fixture.txt`, `.gitleaks.toml`, `.gitleaksignore`, `README.md`). The build pins the source archive with `ADD --checksum`, checks `go.sum`, `config/gitleaks.toml` and the patch by SHA-256, then runs `git apply --check`, `go mod verify` and `go test ./cmd/...`. The runtime is `FROM scratch`. |
| Launcher | Its own: `engines/images/gitleaks/launcher/main.go`, entrypoint `/usr/local/bin/ai-security-scanner-gitleaks-entrypoint`. It is not the [local launcher](local-launcher.md). |
| Adapter | `extract_gitleaks` and `gitleaks_location` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-image-gitleaks.yml`. Changes to `plan.json`, `testdata/**` or `*.md` do not trigger it. |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/gitleaks/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

The 2026-10-03 recipe restores the launcher fixture copy and builds cleanly. Native amd64 execution against the read-only synthetic repository, with networking disabled, produced one `generic-api-key` finding with every secret redacted. Replacement `8.30.1-2` was published by [workflow 37171537552](https://github.com/teddashh/ai-security-scanner/actions/runs/37171537552), from source `a27f2bc8d48c15b4b73e91f7a16e33b905ec430c`. Anonymous tag/index and both platform digests were verified; provenance and both SPDX/CycloneDX platform attestations match the exact source and workflow. The catalog now selects this replacement. Native amd64 meaningful execution is observed; the arm64 source build and supply-chain evidence are verified, without a native arm64 runtime observation for this rebuild.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One `repository` asset; the catalog contract is the only routing, and the launcher reads no input marker. The arguments must be exactly `--workspace /workspace --output /output`. Both must be real directories, and `/workspace` must be mounted read-only (`statfs`). Networking is disabled. Catalog resources: 512 MB memory, 512 MB disk, 1000 CPU millis, 3600 s.
- **Invocation.** The launcher first checks `/opt/ai-security-scanner/gitleaks/gitleaks.toml` against `configSHA256` and requires that `/output/gitleaks.json` does not exist. It then runs this command with a fixed environment and a one-hour limit:

  `gitleaks dir --config <that file> --ignore-gitleaks-allow --no-source-ignore --exit-code 0 --redact=100 --max-decode-depth 5 --max-archive-depth 0 --report-format json --report-path /output/gitleaks.json --no-banner --no-color /workspace`

  - `--config` outranks a target `.gitleaks.toml`.
  - `--no-source-ignore` (the patch) skips every `.gitleaksignore`.
  - `--ignore-gitleaks-allow` still reports lines marked `gitleaks:allow`.
  - With `--exit-code 0`, findings do not read as a failure.
  - Archives are not opened. Encoded text is decoded up to five levels deep.
  - Gitleaks' stdout and stderr are captured (8 MiB) but never printed, so a failure reports only `Gitleaks execution failed: <exit status>`.
- **Output.** `validateRedactedEvidence` requires one JSON array of 2 bytes to 512 MiB, with nothing after it, in which every element has `Secret` equal to `REDACTED`. Otherwise the report is deleted, and the launcher prints `managed Gitleaks launcher: <reason>` and exits 126. An accepted report is set to mode 0600.
- **Mapping.** `extract_gitleaks`, one finding per element:
  - Rule id `RuleID` (exact). Title `Description`, else `Potential secret detected by <rule>`.
  - Location from `gitleaks_location`: `File` with `/workspace` stripped (else `repository`), plus `:line=`, `:column=` and a validated `:commit=`. `Secret` and `Match` are never read.
  - Severity Unknown with basis `SecretPatternMatch`, because Gitleaks rates nothing. Confidence is derived (`UnverifiedPatternOrDetectorMatch`).
  - Tag `secret-value:redacted`; `merge_finding` marks the finding redacted.
- **Failed or partial.** A launcher refusal or a non-zero exit fails the run. These make it partial:
  - a report that is not a JSON array (no findings are read);
  - an element that is not an object, or that has no `RuleID`.

## Downstream changes

- **`0001-add-scanner-owned-ignore-policy.patch`** (`cmd/root.go`).
  - What: adds `--no-source-ignore`. When it is set, `Detector` loads no `.gitleaksignore` from `--gitleaks-ignore-path` (default `.`, the launcher's working directory `/workspace`), from a folder at that path, or from the scan source.
  - Why: a scanned project must not narrow the product's coverage with its own ignore file.
  - Where the digest is pinned: the Dockerfile, plan `build_recipe.source_patch`, the image label `io.ai-security-scanner.patch-sha256` and the validator. The patch ships in the image under `/usr/share/source/`.
  - Removal: once upstream offers an equivalent switch. [PATCHES.md](../../engines/images/gitleaks/PATCHES.md) and plan `build_recipe.patch_audit` record the pinned source reference, contribution rationale, source pre/post hashes, behavior fixtures, owners, removal condition and 2026-11-01 review deadline. No upstream submission is claimed.
- **Launcher policy** (not a patch): fixed config, inline allow comments ignored, `--exit-code 0`, and full redaction.

## Lessons from real runs

- 2026-08-26: the first patch skipped only the scan source's `.gitleaksignore`, but the default ignore path `.` is the working directory `/workspace`, so the same file could still load -> every ignore path now sits behind `--no-source-ignore`; `8.30.1-1` was published from this commit (77233a2).
- 2026-09-05: findings carried `source-severity:high`, a rating Gitleaks never gives -> the adapter hard-coded it -> derived severity (b8b989a), changed from High to Unknown in 97093ae.
- 2026-09-19: an end-to-end scan reported no secrets and could not tell a working scanner from a broken one -> the target used the AWS documentation example pair, which upstream's allowlist ignores -> synthetic fixture and `TestFixtureContainsDetectableSyntheticSecret` (e2ce26f).
- 2026-09-20: the fixture had to avoid GitHub push protection (GH013) and the new test could not see `testdata/` -> a non-AWS synthetic token, with `testdata/` mounted beside the launcher in the workflow and copied in the Dockerfile (b48ec90). d894a6a reverted the Dockerfile copy to keep the recorded Dockerfile digest.

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Keep the fixture in the build.** The launcher test reads `../testdata/fixture.txt`. Copy `testdata/` to `/src/testdata` before `go test ./...`; workflow-mounted tests alone cannot prove this Dockerfile stage. This omission was fixed and the clean native build verified on 2026-10-03.
- **Build.** Update in step:
  - the archive URL and checksum, and `SOURCE_DATE_EPOCH`;
  - the `go.sum` digest;
  - the `config/gitleaks.toml` digest, which also appears in `configSHA256`, the catalog `rule_version` and `provenance.rules`, and the image label;
  - `-X github.com/zricethezav/gitleaks/v8/version.Version`.

  Rebase the patch so `git apply --check` passes and update its digest. `immutableLauncherInputs` and `immutableDockerfileInputs` in `scripts/validate-engine-catalog.mjs` repeat these lines exactly.
- **Re-check upstream.** Before rebasing the patch, check whether upstream now offers an equivalent switch (section 6). Also re-check:
  - the ignore-file loading in `cmd/root.go` `Detector`, and the config precedence (`--config` first);
  - `Redact` in `report/finding.go`, which sets `Secret` to `REDACTED` at 100 and replaces it in `Match`;
  - the JSON finding shape: `Line` is `json:"-"` at this pin. Make sure no new field carries the secret.
- **Output shape.** `RuleID`, `Description`, `File`, `StartLine`, `StartColumn`, `Commit` and `Secret`.
- **Mapping.** `mappings/control-mappings.json` has one exact entry, `generic-api-key`. Confirm the rule still exists in the new default config.
- **Tests.**
  - The four launcher tests in `launcher/main_test.go`.
  - `gitleaks_keeps_same_rule_findings_at_distinct_source_coordinates_without_secrets` in `src-tauri/tests/adapter_fixtures.rs`, with the fixture `gitleaks.json`.
  - The workflow smoke checks the `version` output, then that the report is an array with at least one finding, every `Secret` is `REDACTED`, a `generic-api-key` finding is present, and the synthetic raw value is absent. Keep fixture values synthetic and non-AWS.
- **Hard-coded values.** The replacement tag `8.30.1-2` appears in:
  - the workflow `IMAGE_TAG`;
  - catalog `image.tag`, plan `final_artifact.tag` and the Dockerfile label;
  - `scripts/validate-engine-catalog.mjs`.

  `8.30.1` also appears in the workflow version check, the Dockerfile ldflag, the catalog `engine_version` and `provenance.engine`, `PATCHES.md` and `THIRD_PARTY.md`. Find them with `grep -rn "8.30.1" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams --exclude-dir=.engine-cache`. `support_until` is 2026-11-22.
- **Compare with raw output.** Run `jq -r '.[] | [.RuleID, .File, .StartLine, .StartColumn] | @tsv' gitleaks.json | sort | uniq -c`. Each distinct row should be one finding: rows that share a rule and coordinates merge. Also check `jq 'all(.[]; .Secret == "REDACTED")' gitleaks.json`, and never paste `Match`.
- **Publishing.** The plan at the publishing commit 77233a2 is `upstream_image` for `ghcr.io/gitleaks/gitleaks:v8.30.1`; the managed plan arrived in 3257057. The guard therefore can never reuse `8.30.1-1`, whatever the Dockerfile bytes, and the next push that triggers the workflow needs a new tag. The 2026-10-03 replacement plan hashes the actual `launcher/go.mod` and embedded patch notice. The publishing commit retains historical `previous_artifact`/`previous_publication` independently of the new build inputs; the final pin commit replaces that temporary state with verified `publication` evidence.

- 2026-10-03: restored fixture copying, bound the launcher module/patch notice, reviewed the unchanged ignore-policy patch, and published `8.30.1-2` at index `sha256:95313654f9c37115a906629a82113ba6e1c729950be70909da8362e9482b477e`. Native local and workflow output matched SHA-256 `0bd143d1b9535a15bbd4b97e9399918e1bcaa1b5334ba1c7963423f2cd6765f9`. The previous immutable tag remains historical and was not replaced.
