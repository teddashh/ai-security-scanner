# Managed engine image supply-chain evidence

Every project-managed engine image publication uses the shared immutable-version guard and
`.github/actions/engine-image-evidence` action. A new build is pushed only to a run-unique
`candidate-<source-revision>-<run-id>-<attempt>` tag. The human-readable version tag is created
only after the candidate digest is publicly readable, smoke-tested, and signed. It covers all 19 managed
images: CloudQuery, Prowler, Cloudsplaining, ScoutSuite, Steampipe, Naabu, httpx, Nuclei,
Greenbone, ScubaGear, Maester, Semgrep, TruffleHog, Trivy, Grype, Kubescape, kube-bench, Checkov,
and Syft. Gitleaks and KICS retain their separately verified upstream-image provenance instead of
being represented as project-built images.

## Immutable version contract

Before any publishing build, the guard reads the requested GHCR version tag through the registry
API and fails closed on authentication, transport, response, digest, or index-shape ambiguity.

- An absent version tag authorizes a build only under the run-unique candidate tag. The workflow
  proves anonymous digest access and runs the managed smoke contract against that digest, creates
  signed evidence, verifies the signed provenance online, and only then promotes the candidate
  digest to the previously absent version tag.
- An existing version tag must resolve to an exact two-manifest `linux/amd64` + `linux/arm64`
  index. `gh attestation verify` must find SLSA provenance signed by the same repository workflow,
  on a GitHub-hosted runner, for the exact executing source commit. A same-commit manual retry
  reuses that digest and repeats anonymous smoke/evidence verification without rebuilding or
  rewriting the tag.
- An existing tag with a different source commit, workflow identity, digest, malformed index, or
  missing/unverifiable provenance is rejected before mutation. The maintainer must choose a new
  version tag; deleting or retargeting the old version is not a recovery mechanism.
- Promotion checks the version tag a second time after evidence. If another publisher created a
  different binding, promotion refuses it. After promotion, the workflow logs out and anonymously
  resolves the human-readable tag back to the exact attested digest.

A failure before promotion can leave a candidate tag, but it cannot claim or alter the managed
version. A retry gets a new candidate tag. A failure after promotion is safely retryable because
the signed same-commit digest is reused.

Workflow/action/evidence-helper-only commits do not automatically republish images. Those changes
are validated by CI and become active on the next image-input publication or an explicit manual
dispatch. Automatic publication path filters contain only actual image inputs (Dockerfiles,
launchers, pinned offline build data, and equivalent recipe inputs). This prevents a guard rollout
or evidence-only refactor from forcing unrelated immutable version bumps. Manual dispatch remains
available and intentionally evaluates the complete configured matrix.

## Evidence contract

BuildKit's inline `provenance` and `sbom` exporters stay disabled. Enabling either exporter would
add descriptors to the image index and therefore change the digest consumed by a frozen case.
Instead, publication creates evidence after the candidate or safely reused index digest is final
and before a new version tag is promoted:

1. The registry's exact index bytes are checked against the selected digest (the guarded reuse
   digest or `docker/build-push-action` candidate output), then the `linux/amd64` and `linux/arm64`
   manifest digests are read from that index. Any extra manifest is rejected.
2. A digest-pinned Syft 1.51.0 container scans each platform manifest from the public registry and
   writes both SPDX 2.3 JSON and CycloneDX JSON. The evidence helper rejects an SBOM unless its
   described container checksum is the exact platform digest.
3. `actions/attest` creates one SLSA build-provenance attestation for the index and an SPDX plus a
   CycloneDX SBOM attestation for each platform manifest. The five Sigstore statements are stored
   in GitHub's attestation API and pushed to GHCR as OCI referrers. Neither operation changes the
   subject image digest.
4. The helper decodes every signed DSSE statement, checks its subject, digest, predicate type, and
   exact SBOM predicate, then records the bundle hash and GitHub attestation URL in
   `<engine>-image-supply-chain.json`.
5. The workflow uses `gh attestation verify` against the index and both platform manifests before
   uploading the downloadable evidence directory. A failed verification prevents publication
   evidence from being preserved as a successful artifact.

The evidence `sourceRevision` is the exact repository commit used by the workflow that built those
immutable image bytes. A retry may reuse an existing digest only at that same source revision. A
later desktop adapter revision does not auto-trigger image publication, rewrite this historical
build identity, or claim that an unchanged image was republished.

The downloadable manifest follows
[`engine-image-supply-chain.schema.json`](engine-image-supply-chain.schema.json). Workflow
artifacts retain the manifest, four SBOM files, five Sigstore bundles, and `SHA256SUMS.txt` for 90
days. The signed SBOM predicates and provenance remain independently retrievable through both the
GitHub attestation API and GHCR OCI referrers; the workflow artifact is a convenience copy, not the
only evidence store.

The self-test uses a synthetic exact two-platform index, multi-platform SBOMs, and Sigstore
envelopes. It proves the manifest has five exact attestations, rejects a wrong source revision,
extra platform, wrong image digest, or SPDX checksum mismatch, and verifies cloud changed-input
selection keeps full manual dispatch while narrowing an engine-only push:

```sh
node scripts/engine-image-evidence.mjs self-test
```

## Consumer verification

Use the immutable index digest printed by the publication workflow:

```sh
image=ghcr.io/teddashh/ai-security-scanner-engine-checkov
index_digest=sha256:REPLACE_WITH_PUBLISHED_INDEX_DIGEST

gh attestation verify "oci://${image}@${index_digest}" \
  --repo teddashh/ai-security-scanner
```

Resolve a platform digest from the immutable index, then verify either signed SBOM format:

```sh
amd64_digest="$(
  docker buildx imagetools inspect --raw "${image}@${index_digest}" |
    jq -er '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest'
)"

gh attestation verify "oci://${image}@${amd64_digest}" \
  --repo teddashh/ai-security-scanner \
  --predicate-type https://spdx.dev/Document/v2.3

gh attestation verify "oci://${image}@${amd64_digest}" \
  --repo teddashh/ai-security-scanner \
  --predicate-type https://cyclonedx.org/bom
```

To recover the signed SPDX predicate as JSON even after the workflow artifact expires, add
`--format json` and extract
`.[].verificationResult.statement.predicate` from the successful verification result.
