# Engine maintenance procedure

Normative status: this is a subordinate engine-admission/publication reference. The [canonical product specification](product-spec.md) controls user-visible behavior, partial results, and release acceptance. Nothing here creates whole-product readiness or a blocker for unaffected engines, ordinary product CI, reports, or unsigned exports.

This is the release-reviewed update procedure referenced by every engine compatibility record. The `maintenance_owner` named in the catalog owns the evidence for the steps below; an upstream project name is not a substitute for a product maintainer.

## Date semantics

- `knowledge_date` is the newest date represented by the exact engine, rules, templates, feed, database, or fixed provider-plugin closure shipped by that catalog entry. It is not the application build date unless those dates genuinely coincide.
- `support_until` is the last date on which maintainers claim that exact pinned closure is supported. It must be a real calendar date on or after `knowledge_date` and is normally limited to a 90-day maintenance window.
- Every new scan freezes both dates into each engine-run record. Historical records with no dates remain readable and are labeled as legacy records.
- An expired closure remains attributable and reproducible. If execution is still available, the backend and UI emit an explicit stale-knowledge warning; completion never becomes a claim of current security.

## Update procedure

1. Resolve the exact upstream tag and 40-character source revision. Update `engines/upstreams.lock.json` and verify the local working copy and acquisition URL resolve to that revision.
2. Review engine, dependency, image, rules, template, feed, database, trademark, and redistribution terms. Update `THIRD_PARTY.md`, notices, source offers, and the catalog license disposition before publishing an artifact.
3. Pin every build input and base image. Builds may not use floating tags, runtime plugin downloads, mutable rule sources, or a shell-expanded target.
4. Rebuild the exact architectures declared for this engine artifact. Produce an SBOM, source archive or source offer where required, provenance attestation, and its immutable digest. Do not make an unrelated platform/application artifact part of this engine's admission identity.
5. Run the engine through its product wrapper with representative bounded fixtures. Exercise valid output, malformed output, output-size limits, cancellation, cleanup, and—where applicable—the exact managed-egress policy. A direct engine invocation is not integration evidence.
6. Verify anonymous inspection and pull of every public image and feed artifact. Confirm its labels, entrypoint, non-root user, architecture manifests, embedded source association, and hardened smoke command.
7. Update the adapter fixture and version when the output contract changes. Preserve old adapter provenance so existing cases remain explainable.
8. Set the entry-specific `knowledge_date` from the verified knowledge closure and set `support_until` according to the maintained window. Copy both values into the corresponding packaging plan; never bulk-date an older closure merely because a new application release was built.
9. Run catalog validation, adapter/integration fixtures, and this engine's publication self-tests. Attach the image, feed, SBOM, source, smoke, and attestation evidence to the engine release record. Platform installer qualification and product publication are separate lanes and run only when the affected product/channel requires them.

An engine-image publication revision identifies the exact tree that built those immutable image
bytes. An application adapter revision identifies the exact normalizer source. They advance
independently when adapter hardening does not change an engine image, ruleset, feed, or wrapper.

## Expiry and replacement

The catalog keeps expired versions visible for historical provenance. A replacement gets a new immutable digest and dates; it never rewrites an existing case. If an update cannot satisfy licensing, source association, adapter, platform, or scope constraints, only that engine task stays `not_tested` with a concrete blocker rather than falling back to an unpinned or broader implementation. The run is already persisted, admitted siblings continue, and the beginner master report discloses the coverage gap.

Mapping maintenance is independent: missing or stale NIST/ISO/AIDEFEND relationships remove only those optional links, never engine findings or execution. Likewise, image provenance/signing failure blocks publication or execution of the exact untrusted image, not an already installed trusted build or unaffected engines.

Engine publication evidence does not replace the exact-candidate installed-Windows human path. A proposal that adds a cross-engine, cross-platform, or product-wide maintenance gate must meet the canonical complexity budget and prove why operation-scoped admission plus graceful degradation cannot prevent the reproduced harm.
