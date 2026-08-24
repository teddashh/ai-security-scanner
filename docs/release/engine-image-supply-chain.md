# Managed engine image supply-chain evidence

Every project-managed engine image publication uses the shared
`.github/actions/engine-image-evidence` action. The action runs only after Buildx has published and
the workflow has proved that the immutable digest is publicly readable. It covers all 19 managed
images: CloudQuery, Prowler, Cloudsplaining, ScoutSuite, Steampipe, Naabu, httpx, Nuclei,
Greenbone, ScubaGear, Maester, Semgrep, TruffleHog, Trivy, Grype, Kubescape, kube-bench, Checkov,
and Syft. Gitleaks and KICS retain their separately verified upstream-image provenance instead of
being represented as project-built images.

## Evidence contract

BuildKit's inline `provenance` and `sbom` exporters stay disabled. Enabling either exporter would
add descriptors to the image index and therefore change the digest consumed by a frozen case.
Instead, publication creates evidence after the index digest is final:

1. The registry's exact index bytes are checked against the digest returned by
   `docker/build-push-action`, then the `linux/amd64` and `linux/arm64` manifest digests are read
   from that index.
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

The downloadable manifest follows
[`engine-image-supply-chain.schema.json`](engine-image-supply-chain.schema.json). Workflow
artifacts retain the manifest, four SBOM files, five Sigstore bundles, and `SHA256SUMS.txt` for 90
days. The signed SBOM predicates and provenance remain independently retrievable through both the
GitHub attestation API and GHCR OCI referrers; the workflow artifact is a convenience copy, not the
only evidence store.

The self-test uses synthetic multi-platform SBOMs and Sigstore envelopes. It proves the manifest
has five exact attestations and rejects a wrong image digest or an SPDX checksum mismatch:

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
