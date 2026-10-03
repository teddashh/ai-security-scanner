# Semgrep combined-pack publication — 2026-10-03

This record describes published `1.174.0-4`, verified and signed in
[run 37138219098](https://github.com/teddashh/ai-security-scanner/actions/runs/37138219098) from project source
`94af3e7c5f28fe5f442525a7b0d3aab88b5632ba`. The catalog and plan now pin the
actual public index and platform digests. Earlier local and verification-only
receipts below remain historical evidence, distinct from this publication.

The owner authorized advancing publication on October 3. This operation
distributes the image publicly without a fee, preserving the legacy
[Commons Clause notice](https://github.com/semgrep/semgrep-rules/blob/0f5a85ceab1b82b193d0eaa418784c932d237d68/LICENSE)
and complete selected sources. The notice restricts paid products or services
whose value derives entirely or substantially from these rules. Combining four
Apache-2.0 product rules does not remove that restriction. Future paid use
requires a separate owner decision; this publication does not establish the
product's business model. No rule archive is committed to the repository.

## Recipe and update coupling

- CE stays at `a0c13f304151e531c7e7c00838076211a07a790c`, version `1.174.0`.
  The legacy rule snapshot stays at `0f5a85ceab1b82b193d0eaa418784c932d237d68`;
  that commit's upstream timestamp is `2024-12-13T09:04:54Z`. A new image build
  does not make that December 2024 rule knowledge current.
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
to sibling engines. Manual runs require one engine; `verify` is the default and
currently supports Semgrep. A failed Semgrep native check is refused by the
first step of its publication job, before registry mutation; selected sibling
publication jobs remain independent.

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

The downloaded-artifact verifier also requires the two native receipts, four
native scan JSON files per architecture, refusal logs and published filesystem
receipts in its exact inventory. It recomputes the complete result multiset
union and managed-artifact hash, and refuses resealed evidence with an incorrect
architecture, source commit, source selection or filesystem receipt.

After both actual native runs pass, use the approved free public distribution
path on main. Read its signed manifest before
updating the catalog, plan, verifier contracts and notices. All six current
plans record the shared launcher source hash; updating those records does not
mean the five sibling images were rebuilt. Keep their historical publication
receipts unchanged. Record the final index/platform digests, evidence run,
source commit, source attachment hash and product normalizer result here.

## Completed local production-recipe checks

The amd64 build completed with all native compiler stages cached. Its local
image ID is `sha256:f9adc8dc432a927a4f33f46e9ed3cc5fbeee086ac2ccc8072859158b4103e679`.
The actual fixed-launcher verification returned **10/12/22/22**, empty errors,
the full-result multiset union and all four exit-126/no-output refusals.

The attached source is 33,033,850 bytes, SHA-256
`3282013b050f79b3f417f488433a050fda219da99edc66c1a6520414842156cd`.
The verified filesystem payload has 9,496 recorded members, SHA-256
`7eb1b29834a13116ae520f22313161e439b76b4b4e346e2e27223f2c9506a23d`.
Repeating the filesystem receipt and the streaming source check gave identical
receipts. These identify this local recipe build, not a public release digest.

The real shared Rust normalizer produced **22 findings with no warnings** and
kept native IDs, locations, severity mapping, bounded titles and raw evidence
hashes. Two native messages exceeded the existing 512-character display bound;
their complete messages remain in the raw JSON. Thirteen Python tests,
91 CI contract tests, Rust formatting and the signed-image evidence self-test
passed. No live application, sign-in, credential or scan state was changed.

[Run 37127986459](https://github.com/teddashh/ai-security-scanner/actions/runs/37127986459)
completed **successfully** for source
`6fa7709c9617c05cc87d7c0096d7ee84594d829e` in verification mode. Both fresh
native builds returned 10/12/22/22, empty errors, the complete result union and
all four actual launcher refusals. The publication job was skipped. No image,
rule cache, source attachment or build-record artifact was published.

| Native CI architecture | Filesystem payload SHA-256 | Managed JSON SHA-256 | Verification JSON SHA-256 |
| --- | --- | --- | --- |
| amd64 | `8bc02b97a361030ef8141165c90aa636922e18f7641d9819486dfb276e5d076b` | `e8c6f9e0896b0a5eaeb190ecbed187db3a928fb0808b10a94ba6581b940520c8` | `9b83d3e6395474a7975aba6252f1930ee39ff7a121f366fcc9d35f210db32ed1` |
| arm64 | `cdf2e196bf1f3e7983ade54ebdcb60933f8ff7cde76585f3876661ca35674c62` | `1e89fbcf6a09ee3124e996a50f6d633707fe7e4d82019641aa66855ca050dd51` | `a3fbff4930e83db58b4097f6509194e0385fc049b93f2d2296e0e712924ba9b1` |

The actual amd64 and ARM64 complete result multisets match each other and the
local amd64 results. Both source attachments match the local attachment hash
above. Normalizing the fresh ARM64 artifact again produced 22 findings without
warnings. The raw JSON hashes differ because run-level data varies; result
comparison uses complete result objects, not an entire-file hash comparison.

The CI amd64 filesystem differs from the separately built local amd64 one.
Pinned inputs and equal scan results do not establish byte-identical builds.
Publication must compare against its own immediately verified platform receipts
and reuse those staged caches; a cache miss or changed filesystem fails before
promotion. The later publication completed and its signed public image
evidence is recorded below. The updated artifact verifier passed all
19 tests, including six native-evidence drift cases; all 200 release contract
tests also passed.

## Completed public distribution

[Run 37138219098](https://github.com/teddashh/ai-security-scanner/actions/runs/37138219098) completed successfully.
Anonymous pulls and both installed-filesystem receipts match the native
verifications from that same run. Downloaded evidence was independently checked
with the artifact verifier: four per-platform SBOMs, five cryptographically
verified Sigstore attestations, source/run/workflow identities, exact file
inventory and checksums, full-result unions and all four refusal controls.

Index digest: `sha256:3f1a10c7bce32eae912479c5744dbb653bdfa9a4cbd3d53afd2e0a435b10fb59`.

| Platform | Published manifest digest | Native / public filesystem SHA-256 | Verification JSON SHA-256 |
| --- | --- | --- | --- |
| linux/amd64 | `sha256:974a9bf30c7d0cd973893a12186b054ae48a692367c174d8514fe667fb150e41` | `21fb6e6abf9a85456ecaf860fc2a29fef6359f4df66b0366a9397f4969a3ff5b` | `0cf04c936456917d409e0ee6e631fed4407904557cc03f198a1ac327ddffeaae` |
| linux/arm64 | `sha256:27a6f8d42f7bbea1ee62e4a662fd4c4b591de45ac947c90c22e1f9e29438f979` | `529fca787dee01941f133806352c1a855a337921e0140764032029175dc75b0d` | `12c0e173d8d452783326a6d1efc1cb0c0a6de3df5a17d162c2fddbfee22d9bf6` |

Evidence artifact: `semgrep-image-evidence-37138219098-1`;
root checksum receipt: `sha256:ea90c34c1273b9dca7991d8d61b0e035357fa44337a65466b48901cc8a8c91dd`.
The selected source attachment remains 33,033,850 bytes with SHA-256
`3282013b050f79b3f417f488433a050fda219da99edc66c1a6520414842156cd`.
Both actual builds acquired upstream hook packages `openssl-libs-static`
3.5.9-r0 and `zlib-static` 1.3.2-r0.

The current Semgrep plan now covers every tracked executable input, including
rule/source builders, product rules/license, submodule lock and verification
helpers. Its two historical uncovered-input exceptions were removed. The shared
launcher hash was updated in all six current consuming plans; the five sibling
image tags, digests and historical publication receipts are unchanged.

The dependency-free CI suite has 89 tests; its two YAML workflow checks moved
to the dependency-installed release suite, which passed all 202 tests. This
corrects the first main CI failure caused by importing YAML before installation.

A separate anonymous local pull of the public index also matched the amd64
installed-filesystem receipt. Its fixed launcher scanned the same six synthetic
fixtures with networking disabled, read-only root/input, two CPUs, 2 GiB,
256 PIDs and 512 MiB of temporary storage. It returned 22 complete results,
identical to the native CI result multiset. The shared Rust normalizer produced
22 findings without warnings and preserved native IDs, locations, severity,
bounded titles and raw evidence hashes. The local raw JSON SHA-256 is
`08758043fa5f50ac98776f1ba9b714455a2fcea694963fc9ea97a00724b6acf5`.
