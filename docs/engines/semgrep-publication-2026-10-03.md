# Semgrep combined-pack publication preparation — 2026-10-03

This record describes the prepared `1.174.0-4` recipe. It does not claim that
the version has been published. The catalog and published-plan receipts still
name `1.174.0-3`; change them only after actual publication evidence exists.

The owner authorized advancing publication on October 3. The remaining license
fact is whether the scanner is freely provided or offered as a paid product or
service whose value derives substantially from these rules. The legacy
[Commons Clause notice](https://github.com/semgrep/semgrep-rules/blob/0f5a85ceab1b82b193d0eaa418784c932d237d68/LICENSE)
restricts the latter. Combining four Apache-2.0 product rules does not remove
that restriction. No rule archive is committed to the repository.

## Recipe and update coupling

- CE stays at `a0c13f304151e531c7e7c00838076211a07a790c`, version `1.174.0`.
  The legacy rule snapshot stays at `0f5a85ceab1b82b193d0eaa418784c932d237d68`;
  a new image build does not make that December 2024 rule knowledge current.
- The pack has 1,493 upstream rules plus four original product rules, 1,497
  unique IDs in 1,478 config files. Qualified upstream IDs retain original
  IDs/paths/hashes in provenance; all detector bodies and native ratings remain
  unchanged. Existing product control mappings keep their four keys.
- The manifest is `63678fc6790ebdeca2961080095611030b8e51f8b19ac228ee7e2c6862083040`;
  provenance is `a5f8961abe75a57da4c752f39272baa64ac95ca4181e507c070772c54f5c09bf`.
  Both hashes are launcher inputs, not values derived from a downloaded file
  at runtime. An updated pack needs a new reviewed inventory and fixtures.
- The source attachment holds the engine, 35 compiler/parser submodules, the
  1,477 selected original rule files, notices, pack and rebuild inputs. The
  explicitly proprietary `no-direct-response-writer.yaml` and the unfiltered
  rules archive are absent. The raw input archive is a read-only BuildKit bind
  for pack generation, never a copied layer. Preserve that boundary when
  changing source assembly or cache exports.
- APK versions, upstream opam/OCaml/static-curl hooks and secondary source
  acquisitions are recorded in the [combination review](semgrep-combination-review.md)
  and [image build index](image-build-index.md). Recheck availability rather
  than silently replacing exact versions. Compiler stages are independent of
  rule-pack/source-attachment changes.

## Native verification and publication workflow

`engine-images-local-k8s.yml` declares its six entries in `LOCAL_ENGINE_MATRIX`.
Automatic runs select entries whose explicitly assigned tag differs from their
recorded published tag. Shared launcher edits therefore do not assign new tags
to sibling engines. Manual runs require one engine; `verify` is the default.

Semgrep verification uses `ubuntu-24.04` for amd64 and `ubuntu-24.04-arm` for
arm64. Both build a complete image and load it locally. The fixed launcher is
tested in the pinned Go toolchain. Native compilation uses four jobs; scans
use two CPUs, 2 GiB, no networking, read-only root/input, dropped capabilities,
256 PIDs and a 512 MiB temporary filesystem. Each fixture pass has a 600-second
outer deadline. No fixture code, real key material or remediation is executed.

`run_managed_combination.py` checks architecture, entrypoint and version label,
then verifies the attached originals, licenses and rebuild inputs. The compressed
attachment is bounded at 128 MiB and its contents at 1 GiB; an individual member
is bounded at 128 MiB because the unchanged generated Julia parser is about
70 MiB. Verification streams the attachment rather than extracting it.

Each native receipt must show product/upstream/combined/managed counts
**10/12/22/22**, empty scan errors, and equality of the complete result multiset.
Changed rules, changed provenance, an extra config and a writable workspace
must each exit 126 before writing output. A refusal before the launcher starts
does not satisfy these controls.

`verify_image_payload.py` hashes regular-file bytes, links, permissions and
ownership from an unstarted image export. It excludes only Docker's injected
hostname, hosts, resolver and `.dockerenv` files and ignores tar timestamps.
The resulting receipt binds the entire installed filesystem to the native
test, including runtime code, rules, source attachment and licenses.

Before signing/promotion, publication anonymously pulls each platform digest
and recomputes that receipt. It also checks the native receipts' source commit,
version, architecture, full-result union and four refusal controls. Existing
per-platform SBOMs, attestations, immutable-tag guard and downloadable evidence
remain in the publication path. A different payload fails before promotion.

Verification mode publishes no image, exports no build cache and disables the
automatic Docker build-record upload. Its explicit artifacts contain only
receipt JSON, synthetic scan results and logs; selected rules, source tarballs
and copied source directories are excluded from artifact upload paths.

```sh
gh workflow run engine-images-local-k8s.yml --ref <review-branch> \
  -f engine=semgrep -f mode=verify
```

After both actual native runs pass and license applicability is established,
use the approved publication path on main. Read its signed manifest before
updating the catalog, plan, verifier contracts and notices. All six current
plans record the shared launcher source hash; updating those records does not
mean the five sibling images were rebuilt. Keep their historical publication
receipts unchanged. Record the final index/platform digests, evidence run,
source commit, source attachment hash and product normalizer result here.
