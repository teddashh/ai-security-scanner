# Release operations

[Documentation](README.md)

The product owner selects the version, channel, source commit, supported installer set, and publication time. Release automation builds, qualifies, freezes, verifies, attests, and publishes that exact decision.

## Current candidate and publication HOLD

The current candidate is **multi-OS: Linux, macOS, and Windows**. [Actions run 35513091476](https://github.com/teddashh/ai-security-scanner/actions/runs/35513091476) finalized the exact source `56d3b3f469b9fd9bb090f404b0230e7667d5d884` with `publicationMode: commit-bound-qc`. Its `release-finalized` artifact contains the authoritative `release-metadata.json`, installer bytes, checksums and disclosures. This record applies to that commit, not automatically to later source changes.

**Public release is HOLD.** Keep `public_release_candidate: false`; do not run promotion, create a tag, or create a GitHub Release while HOLD remains in effect. Finalized QC artifacts are available for review, not published release downloads or a GA declaration. A formal release must cover all three operating systems.

| Platform | Offered in this QC set | Disclosure |
| --- | --- | --- |
| Windows x86-64 | MSI and NSIS | **Unsigned**; SmartScreen may warn. Technical qualification passed; Windows lifecycle and data-preservation observations are absent. |
| macOS Universal | `.dmg` | **Not notarized**; OS signing is not configured. Installer qualification passed; managed-runtime execution was not observed on the qualification host. |
| Linux x86-64 | Debian `.deb` | Technical qualification passed. AppImage and `.rpm` are **not offered** because their technical qualification was not observed. |

For both Windows installers, metadata retains `windows-lifecycle-not-observed` and `windows-data-preservation-not-observed`; a passing installer qualification is not evidence of those lifecycle checks. The exact-candidate beginner human path is `not-observed` for every offered installer. Updater signatures, where present, do not establish OS signing or Apple notarization. Public provenance has not been created for this commit-bound QC set. These are disclosures, not newly added release gates.

The latest **published** release, [v0.2.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.2.0), remains an earlier **Linux x86-64 Debian `.deb`-only** build; that historical release did not offer Windows or macOS installers. Do not use its offering to describe the current multi-OS candidate, or invent public download URLs for the unpublished candidate bytes.

## Release identity

Use one numeric SemVer across `package.json`, `package-lock.json`, `src-tauri/tauri.conf.json`, the Rust package, and release-owned runtime manifests. Each public version uses a new immutable `vX.Y.Z` tag.

`package.json` also records:

- `release.channel`: `prerelease` or `stable`;
- `release.target`: the next product version under development.

## Prepare main

Before candidate creation:

1. Finish the release notes and current documentation.
2. Run the repository validation, frontend, component, Rust, build, release-policy, and release-evidence suites required by the changed boundaries.
3. Commit the coordinated version and channel update.
4. Push the exact candidate commit to protected `main`.

## Build and qualify without publication

For an owner-requested QC build, **Release desktop installers** uses:

- `public_release_candidate: false`, retaining commit-bound QC while public release is on HOLD;
- the optional `windows_data_preservation` input only when the owner requests the supported N-1 Windows upgrade and ambiguous-runtime recovery fixtures. The current QC set records those observations as absent.

The workflow defines four qualification lanes. A lane can finalize as `not-offered`; use the exact run's metadata, rather than the lane list, to determine its offered installers.

| Qualification | Fresh runner | Installed artifact |
| --- | --- | --- |
| Linux x86-64 | Ubuntu 24.04 | Debian package |
| macOS Universal | macOS 15 Intel | DMG application |
| Windows x86-64 | Windows Server 2025 | MSI |
| Windows x86-64 | Windows Server 2025 | NSIS installer |

Each lane records what it actually observed: installation, application and companion layout, desktop startup, supported managed-runtime operations, runtime/container evidence, and removal of test state. Its JSON qualification record binds those observations to the version, source commit and artifact digest. A passing installer check does not imply that runtime execution or Windows lifecycle checks were observed; the current macOS and Windows limitations are listed above.

The finalized QC set records offered artifacts and their qualification evidence, checksums, runtime manifests, notices, SBOMs and limitations. The workflow summary identifies the run, artifact and source commit. Finalization does not lift HOLD.

## Future promotion reference: inactive during HOLD

Publication remains a separate product-owner decision. After the owner lifts HOLD and authorizes a public candidate, **Promote frozen desktop release candidate** consumes five values from that preparation run:

- candidate run ID;
- candidate run attempt;
- candidate artifact ID;
- candidate artifact SHA-256;
- exact source commit.

Supply the four external-evidence values together when an accepted Windows external-evidence bundle belongs to the release. Leave all four empty when the release does not use that bundle.

The promotion workflow revalidates the candidate lock and checksums, assembles the public files without rebuilding, creates build-provenance attestations, and waits for approval in the `release-publication` environment. Approval publishes the exact files under the immutable version tag. A stable channel becomes the latest release; a prerelease channel is marked as prerelease.

## Verify publication

Confirm the GitHub Release contains the intended installers, `SHA256SUMS.txt`, release index, runtime manifests, SBOMs, notices, release notes, and platform qualification records. Match the published tag and source commit to the frozen candidate summary.

Installed-product acceptance continues with the published installer and the beginner path in [Getting started](getting-started.md).
