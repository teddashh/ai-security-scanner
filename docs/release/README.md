# Release, qualification, and publication policy

Normative status: subordinate to the [canonical product specification](../product-spec.md), especially sections 3, 15, and 16. This document may describe how release work is organized, but it cannot add a product-wide gate, turn publication evidence into scan readiness, or block an independently qualified platform, channel, feature, or engine.

Implementation status: this is the target release policy. The release workflow now records installer siblings independently, treats updater creation as optional, and finalizes only the exact artifacts whose own evidence is usable. One latency limitation remains: the shared build matrix must finish before downstream platform qualification starts. That wait does not change any installer outcome and is P1 workflow optimization, not a product or publication gate. Other implementation gaps remain tracked in [audit findings A24–A26](../product-audit.md#a24--frameworkprovenance-and-release-validation-are-coupled-to-ordinary-product-work).

## Release rule in one sentence

Qualify the exact thing being offered, block only the unsafe or unqualified thing, and keep unrelated development, installed features, platforms, engines, and channels moving.

Release work has four independent layers:

| Layer | Question it answers | What failure may block | What it must not block |
| --- | --- | --- | --- |
| Product CI | Does the changed source satisfy fast shared code and document checks? | Merging the affected broken change | Local use of an already installed build; unrelated publication evidence |
| Engine admission | Is this exact engine package allowed to execute? | Admission or execution of that engine package | Other admitted engines, projects, reports, and partial exports |
| Platform qualification | Does this exact installer work on this platform and preserve its data? | That platform/installer artifact | Another independently qualified platform or installer |
| Publication/channel policy | May this exact artifact be offered through this channel? | That artifact in that channel | Source work, local scans, existing safe installs, or another channel |

No layer may be used as a substitute for the installed human path. A public testing prerelease can expose an exact technically qualified installer to obtain that evidence, but it must disclose the missing observation and cannot claim beginner-ready or stable status. No global “release ready” bit may erase the narrower outcome of a qualified platform or admitted engine.

## 1. Product CI

Product CI gives fast feedback on ordinary source changes. It covers the checks relevant to the changed product surface, such as formatting, type checking, focused frontend/Rust tests, document links, schemas, and low-cost static validation.

Product CI follows these rules:

- A documentation-only change does not build Windows, macOS, and Linux installers.
- A UI change does not wait for every engine image to be published.
- A framework-mapping failure affects mapping output, not findings, scanning, or unrelated UI work.
- Source-text and modeled tests may guard contracts, but they do not claim that an installer, runtime, recovery path, or novice journey worked.
- A release-only check belongs in platform qualification, engine admission, or publication—not in the default product feedback loop merely because it is strict.

Shared-code failures may affect more than one platform when concrete evidence shows the same code path is broken. Scope follows the demonstrated impact, not a default all-platform fate share.

## 2. Engine admission

Each engine is admitted independently. Admission binds the exact executable or image, version/digest, launcher contract, license/notice data, allowed inputs and network behavior, result adapter, and a focused functional check.

If admission fails:

- that engine remains unavailable or at its last admitted version;
- the planner/report must show the resulting coverage gap;
- other engines continue;
- existing cases and historical evidence remain readable; and
- an installed safe version of the application remains usable.

Engine provenance, signatures, SBOMs, and immutable digests are execution/publication controls for that engine. They are not prerequisites for opening the desktop, creating a project, running an unrelated admitted engine, or exporting already saved results.

Detailed engine-image evidence belongs in [engine-image-supply-chain.md](engine-image-supply-chain.md). The machine-readable catalog remains the implementation record of what is currently admitted; it does not override the product's graceful-degradation rule.

## 3. Platform installer qualification

Qualification is bound to one exact source commit, installer bytes, platform, architecture, installer format, and channel. Evidence from MSI cannot stand in for NSIS, and a Linux result cannot stand in for Windows.

Every platform qualification must verify only claims made for that artifact, including as applicable:

- installation, application launch, and application-only removal;
- preservation of projects and user data across Repair/upgrade/uninstall choices;
- installed file identity and the expected helper/runtime resources;
- a real supported product task rather than only CLI help or process survival;
- reopen and readable export from the installed application; and
- cleanup claims for exact product-owned disposable state.

### Windows beginner qualification

Every Windows artifact promoted as beginner-ready or stable requires the exact-candidate human record defined by the canonical specification:

1. install the candidate;
2. enter the main screen;
3. use the combined `127.0.0.1:9001` Start action;
4. receive a saved master report from at least one executed quick task;
5. reopen the project; and
6. export a readable report.

The participant must be a qualifying beginner and the facilitator may observe but not take over. Modeled records, contributor walkthroughs, source checkouts, CLI-created cases, and a process that merely remains open do not pass this path. A technically qualified Windows installer may be offered first as a public testing prerelease only when the release page and artifact metadata explicitly state that this path has not been observed and that the artifact is not beginner-ready or stable.

Separate real-Windows integration/operator fixtures cover WSL absent/restart, unrelated WSL, healthy/damaged/ambiguous/ghost/interrupted runtime, Repair, N-1 upgrade, supported downgrade behavior, and the three uninstall choices. Those fixtures do not require a new novice session unless they change a user decision in the core path.

Lifecycle evidence must name the boundary it actually exercised. Use separate records for
`installer_runtime_cache_seed`, `installer_same_version_repair`,
`packaged_component_auto_recovery`, and `runtime_reconciliation`; success at one boundary cannot
qualify any other. For a fresh Windows NSIS candidate, an exact `initial_status` of
`installed,false` before desktop launch or an explicit lifecycle install is supporting evidence for
`installer_runtime_cache_seed` only. It proves that the installer-produced private copy was present
and admitted; it does not inject packaged corruption or prove cache re-admission, installed-resource
replacement, or an out-of-process Repair. Reopening a digest-anchored private runtime copy proves
only that bounded cache path. The startup recovery warning is diagnostic, not a durable repair
receipt: it may record only the fixed boundary/source, the admitted manifest digest, and the stable
packaged-failure reason. Windows source-level DACL/launch-handle tests support that cache boundary
but do not replace qualification against the signed installed artifact.

The current NSIS N-1 and registered-WSL ghost fixtures are supporting data-preservation evidence only. They use a seeded case and CLI export to prove retained bytes; they do not prove the canonical installed-desktop `127.0.0.1:9001` report, reopen, and readable-export journey. NSIS and MSI may therefore be offered only as clearly labeled public testing prereleases while their exact-artifact human/lifecycle evidence is absent. They remain ineligible for beginner-ready or stable promotion until the applicable real app path passes. Commit-bound QC retains the same missing observations without making public-provenance claims.

### Feature-specific qualification

Cloud, deep AI, Kubernetes, specialist exports, or another Advanced feature has its own qualification. A failed or unfinished AWS/IAM usability study blocks only the AWS feature claim or the artifact/channel that explicitly promises it. It cannot block localhost, website, internal-network, source-code, reporting, or another platform.

The existing [IAM-naive study](../usability/iam-naive-first-run.md) is therefore an Advanced AWS protocol, not universal first-run or product-completion evidence.

### Honest unsupported observations

If a runner cannot exercise a capability—for example, because its hosted environment lacks required virtualization—the record says `not_observed` or `not_tested`. It may limit that platform's published capability statement, but it is never converted to a pass and never blocks an independently qualified artifact.

## 4. Publication and channel policy

Publication answers whether a particular artifact may be offered through a particular channel. It does not redefine product behavior.

For each artifact, the publication record identifies:

- version, source commit, platform, architecture, installer format, and channel;
- installer filename, byte length, and checksum;
- qualification result and exactly which user path was observed;
- available OS signing/notarization, updater signature, provenance, SBOM, and notices;
- supported and untested capabilities; and
- known limitations that affect that artifact.

Rules are scoped:

- A missing or invalid Windows Authenticode signature may withhold that Windows artifact from a channel that requires Authenticode. It does not block Linux/macOS artifacts, source work, or an already installed trusted build.
- Missing Apple signing/notarization affects only the applicable macOS channel.
- An invalid updater signature blocks applying that update. The current installed version continues to open, scan with admitted engines, show reports, and export readable data.
- A missing platform artifact is marked unavailable in the support matrix. It does not prevent publication of another independently qualified platform.
- A checksum, signature, or provenance failure blocks only the affected bytes and claims. It does not become managed-runtime readiness.
- A public testing prerelease may expose a technically qualified artifact while human, lifecycle, data-preservation, or OS-signing evidence is missing, but every gap must remain explicit in release notes and artifact metadata. Beginner-ready and stable channels may not waive those requirements.

A release index may list several platform artifacts for convenience. The index represents independent outcomes; it must not require an unrelated absent platform entry merely to validate or update the current platform.

## 5. Warning and blocking matrix

| Condition | Required outcome | Scope of any block |
| --- | --- | --- |
| One engine package fails admission | Keep it unavailable; report coverage gap | That engine package only |
| Optional framework mapping is missing or stale | Findings/report remain; mapping unavailable warning | No scan or report block |
| Signing identity for an export is unavailable | Offer unsigned readable export | Requested signed export only |
| One platform installer lacks or fails its human/integration path | It may remain an explicitly limited public testing prerelease | Beginner-ready/stable promotion of that platform/installer only |
| One platform artifact is not built | Mark platform unavailable | Missing platform only |
| AWS/IAM study is missing or fails | Do not claim the Advanced AWS path is qualified | AWS feature claim only |
| Update signature/digest is invalid | Keep current installed version | That update payload only |
| OS publisher signing is absent | Public testing prerelease may warn; do not claim signed/recommended status | Stable or another channel that requires publisher signing |
| Proven shared-core data-loss defect | Stop every artifact demonstrated to contain the defect | Evidence-based affected artifacts |
| Documentation-only change | Run low-cost document/static checks | No installer/release qualification |

Only an imminent irreversible change to user/unrelated data, execution of untrusted bytes, prohibited target contact, or a false cryptographic claim permits a hard block at the corresponding operation boundary.

## 6. Candidate and release flow

The intended sequence is:

1. identify the exact source commit and requested platform/channel artifacts;
2. run ordinary product CI appropriate to the change;
3. admit only the engines claimed by those artifacts;
4. build each platform artifact independently;
5. qualify each exact installer on its real platform;
6. retain the exact-candidate human record when promoting a Windows beginner-ready or stable artifact, or prominently disclose its absence for a testing prerelease;
7. apply that channel's signing, integrity, notices, and provenance policy to each artifact; and
8. publish only the artifacts that passed, with an explicit support/coverage matrix.

An artifact is never described as qualified merely because another artifact, a source build, or a synthetic CLI fixture passed. A failed artifact remains absent or clearly unavailable; it does not force qualified siblings to fail.

Numeric release tags and package versions must agree. Manual `main` dispatches may create commit-bound QC artifacts but do not themselves create a public release. Publication privileges belong only to the narrowly scoped publication step after the exact artifact has been reverified.

### Current automation gap

The checked-in workflow now compiles once per platform, bundles each installer sibling independently,
collects only bundle steps that actually succeeded, and finalizes each qualified installer separately.
Updater signing is attempted only for an eligible artifact. Missing key material, payload, or signature
falls back to an installer-only artifact; it cannot discard a valid installer sibling. Collection stages
each optional updater pair transactionally, and `latest.json` contains only payloads reverified against
the embedded updater public key and their exact inline signatures.
The installed updater is offered only for AppImage, the macOS app archive, and NSIS; DEB, RPM, and
MSI installers never appear as updater targets.

The source workflow stages and verifies the managed-runtime manifest before building Windows
sidecars, and the Windows CLI is compiled with the dedicated installer-cache feature so its embedded
digest is tied to those staged bytes. The pinned NSIS source validator checks this build order, the
fresh-install-only zero-input dispatch, exact terminal envelopes, non-fatal failure behavior, and
patch provenance. The Windows NSIS qualification contract now requires the pre-desktop initial
runtime status to be `installed`; MSI and Linux remain `not_installed`. Until a new exact-candidate
Windows record is actually produced, these are source wiring and evidence requirements—not a claim
that cache seeding or packaged-component recovery passed on an installed artifact.

Manual commit-bound QC may explicitly opt into the two long Windows NSIS data-preservation fixtures.
They run on separate fresh Windows runners, are allowed to fail without changing sibling outcomes,
and are skipped by default and for tag publication. If both exact records are present, they are
retained only as supporting preservation evidence; missing or one-sided records remain
`not-observed` and never delay ordinary development or qualify public Windows lifecycle behavior.

There is not yet a protected same-run producer for the exact-candidate Windows beginner record,
real installed-app lifecycle record, or Authenticode verification record with an approved publisher
identity and protected run/job identity. `v0.1.8` therefore accepts no generic observation or
promotion artifact namespace and makes no claim that those paths passed. A technically qualified
Windows installer may still be offered as a public testing prerelease when the finalizer records
`not-observed`/`not-configured`, the release page lists the affected installer and gaps, and public
provenance is created for the exact bytes. Those gaps continue to block beginner-ready and stable
promotion, not testing, another platform, source work, or an installed product.

The `v0.1.8` source line is not currently a recommended beginner installer. This status is an honest
artifact/channel gap, not a product-wide gate.

## 7. Release artifacts and verification

Publish only evidence that was actually produced. Depending on the artifact/channel, that can include:

- the installer and its checksum;
- a readable support and qualification summary;
- platform-scoped qualification evidence;
- updater payload/signature when that update path is supported;
- CycloneDX/SPDX SBOMs and third-party notices;
- artifact-scoped build provenance; and
- release notes and known limitations.

A checksum proves only that downloaded bytes match the listed digest. A build attestation binds bytes to a workflow identity. An updater signature authorizes a payload for an installed app. OS code signing/notarization supplies the applicable publisher/platform trust signal. None proves scan completeness, finding correctness, authorization, compliance, or human usability.

When `SHA256SUMS.txt` and a GitHub attestation are actually supplied, a user can verify them with the platform's checksum tool and:

```sh
gh attestation verify ./downloaded-installer --repo teddashh/ai-security-scanner
```

The release page must say when an attestation or OS signature is absent rather than presenting the command as universally available.

## 8. Historical release notes

Release-line files preserve what a candidate/release claimed or planned at that time. They are historical, non-normative records and cannot reintroduce current runtime, consent, recovery, or global-release requirements. A section labeled **superseded** records a design that must not be copied into current code, tests, workflows, or user guidance; use the canonical specification and current implementation references instead:

- [v0.1.1](v0.1.1.md)
- [v0.1.2](v0.1.2.md)
- [v0.1.3](v0.1.3.md)
- [v0.1.4](v0.1.4.md)
- [v0.1.5](v0.1.5.md)
- [v0.1.6](v0.1.6.md)
- [v0.1.7](v0.1.7.md)
- [v0.1.8](v0.1.8.md)
- [v0.2.0](v0.2.0.md)

Where a historical note conflicts with the canonical product specification, the conflicting behavior is identified in that note as superseded rather than left as an apparently reusable requirement. Current implementation gaps remain in the product audit until code and real-boundary evidence close them.
