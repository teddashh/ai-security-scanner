# Engine artifact trust reference

This document describes the trust boundary for engine artifacts. It supports safe scanner execution and upstream traceability; it does not select product priorities or initiate artifact distribution. Current product direction comes from the [product specification](../product-spec.md).

The machine-readable [engine catalog](../../engines/catalog.json), upstream lock, and managed-runtime manifest are authoritative for current sources, revisions, image digests, runnable state, and blockers. Workflow artifacts are authoritative for a particular build. This narrative does not duplicate their changing coordinates.

## Independent trust units

Each immutable engine digest is evaluated independently. Missing or invalid evidence makes only that exact artifact unavailable. It does not disable already admitted engines, block the workspace, remove saved results, or prevent an honest combined report from marking the affected check as not tested.

Use an official upstream binary or image by immutable digest when it meets the product's execution boundary. A project-managed image contains pinned upstream bytes plus only the thin launcher needed to:

- serialize an already authorized typed input;
- enforce target, mount, network, resource, timeout, and cleanup limits;
- preserve raw upstream output; and
- return a structured execution status.

Detection logic, rule identifiers, native severity, evidence, and remediation remain upstream-owned. Product wording, deduplication, prioritization, and cross-engine reporting belong to the shared report layer.

## Immutable artifact identity

A project-managed build uses a run-unique candidate reference. A human-readable tag is never overwritten or used as proof by itself. Admission is bound to:

- the exact source revision and workflow identity;
- the immutable multi-platform index digest and its platform digests;
- the expected operating systems and architectures;
- the launcher, entrypoint, user, labels, and bounded smoke behavior;
- the applicable source, licenses, notices, and source-offer material; and
- the exact catalog entry that consumes the artifact.

A retry may reuse an existing artifact only when those identities match. A conflicting tag, digest, source, workflow, platform set, or provenance record is rejected rather than repaired by retargeting the old name.

## Evidence model

Evidence is created for the final immutable digest and does not modify that digest. For each offered platform it records:

1. the exact index and platform-manifest digests;
2. source and workflow provenance;
3. SPDX and CycloneDX inventories tied to the platform manifest;
4. a bounded smoke receipt for the declared launcher contract;
5. public retrieval state when public retrieval is claimed; and
6. checksums for the downloadable evidence files.

Signed provenance and SBOM statements prove their own subject and predicate. They do not prove scanner correctness, target coverage, finding quality, or beginner usability. A source test does not substitute for executing the built artifact, and an image smoke test does not substitute for a meaningful product scan.

The repository's schemas and verification scripts define the exact record format:

- [engine-image-supply-chain.schema.json](engine-image-supply-chain.schema.json)
- `scripts/engine-image-evidence.mjs`
- `scripts/release/verify-publication-artifact.mjs`

Historical run IDs, temporary candidate coordinates, withdrawn digests, and step-by-step adoption instructions are intentionally not maintained here. Exact historical facts remain in the corresponding signed workflow evidence and repository history.

## Admission into the product

An engine is runnable only when its catalog record names the same immutable artifact accepted by the applicable evidence and license disposition. Admission changes one engine at a time. It never copies a sibling matrix result, infers a digest from a tag, or turns source-only tests into artifact evidence.

At runtime:

- an admitted artifact still receives only the user's selected scope and the product's bounded profile;
- a missing or rejected artifact produces an explicit task-local unavailable or not-tested outcome;
- completed sibling checks and previously saved evidence remain usable; and
- the report identifies the scanner, upstream version, artifact digest, selected profile, result, and coverage gap.

## When the product owner requests artifact distribution

Only for the exact artifact operation the product owner places in scope:

1. resolve every input to an official source revision and immutable digest;
2. run the repository's build, smoke, inventory, and evidence workflow;
3. verify the downloaded evidence in a fresh directory against the exact run, attempt, repository, source revision, and digest;
4. review applicable license texts, notices, corresponding source, and source offers;
5. update only the matching engine plan and catalog record from normalized verifier output;
6. validate the engine catalog and the affected execution/report path; and
7. retain the evidence coordinates required to reproduce the decision.

These steps protect the artifact being handled. They do not create work for other engines or determine a version number, channel, publication date, signing posture, or product claim.

## Product boundary

Artifact verification answers whether particular bytes match their recorded source and are eligible for the requested execution. The product's value is still a beginner reaching a real upstream security result quickly and receiving one professional report that explains what matters, what to do next, and what was not tested.
