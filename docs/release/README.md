# Release pipeline

The release workflow builds native Tauri installers from either a manual `main` preflight or a
strict stable-version tag. Manual dispatch is preflight-only: it must resolve to `refs/heads/main`,
receives no publication privileges, creates no tag or GitHub Release, and preserves the finalized
candidate as the `release-finalized` workflow artifact. Only an exact tag push can publish. A tag
such as `v0.2.0` must exactly match the versions in `package.json`, `package-lock.json`,
`src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json`; a mismatch stops before packaging.

## Produced installers

| Release target | GitHub runner | Tauri bundles |
|---|---|---|
| Linux x86-64 | Ubuntu 24.04 | AppImage, Debian package, RPM |
| macOS universal | macOS 14 | DMG containing Intel and Apple-silicon code |
| Windows x86-64 | Windows Server 2022 | MSI and NSIS executable |

Every installer includes three first-party Tauri external binaries:
`ai-security-scanner-egress-gateway`, which enforces managed engine egress, and
`ai-security-scanner-bootstrap-broker`, which performs isolated one-shot administrative
bootstrap work without exposing administrator material to the desktop or scanner containers, plus
`ai-security-scanner-cli`, the local casework, status, export, and exact-cleanup interface used by
the checked-in Codex and Claude skills. Live scan control remains capability-mediated in the desktop.
Tauri strips each compilation target suffix and installs all three beside the main desktop executable
with exactly those basenames (`.exe` on Windows), matching their runtime locator contracts.

The build emits a Tauri v2 updater payload and minisign signature for every supported installed
bundle type: Linux AppImage, Debian package, RPM package, universal macOS app, Windows NSIS, and
Windows MSI. Tauri produces the AppImage, macOS, NSIS, and MSI signatures during bundling; the
release workflow signs the already-built `.deb` and `.rpm` bytes with the same updater identity.
`latest.json` contains base fallback keys plus the installer-specific keys used by updater plugin
2.10.x. Each installed bundle therefore downloads a payload its updater can actually install.
Both macOS architecture keys intentionally reference the same signed universal app payload.
Tauri names the source macOS updater archive `ai-security-scanner.app.tar.gz`; collection renames
that already-signed byte stream and its matching signature to the versioned public asset name so
the release index stays unambiguous without invalidating the signature.

Before any build artifact can reach the publish job, the platform runner performs an installed
startup observation against a freshly produced package: Ubuntu installs the Debian package and
starts it under a temporary X server, macOS mounts the DMG, copies its app, and starts the copied
executable, and Windows silently installs the MSI, starts the installed executable, then removes
the package. Each runner also proves that all three companion executables were installed and that
the local casework CLI can render its help without starting a scan. An app that exits during the
observation window fails that platform build. This is
separate from source compilation and provides release-specific install/start evidence; it is not
a claim that every end-user machine or every security assessment will behave identically.

The build-runner observation is preserved, then a separate qualification matrix starts on fresh
GitHub-hosted `ubuntu-24.04`, `macos-15-intel`, and `windows-2025` machines. Each job downloads only its
named `release-<platform>` artifact and independently installs the Debian package, DMG, or MSI. It
locates the installed desktop, all three companion executables, and the packaged managed-runtime
manifest; the installed manifest must byte-hash to the release copy. Every CLI operation uses a
new private data directory. Every platform must prove this exact sequence:

1. initial `not_installed` status;
2. managed payload install and independent `installed` status;
3. real managed machine start and `running` status;
4. the built-in fixed Gitleaks container qualification (immutable catalog digest, no network,
   read-only root, all capabilities dropped, no-new-privileges, zero credentials, and exact
   container cleanup);
5. real machine stop and `stopped` status; and
6. forced uninstall with the exact machine-image cache purged, final `not_installed` status,
   package removal, and private-directory removal. Windows additionally inventories WSL through
   the real absolute System32 executable resolved from the operating-system directory API, captures
   its output as bounded raw bytes, strictly decodes UTF-8 or UTF-16LE, and proves the deterministic
   exact managed distribution is no longer registered after uninstall. Malformed inventory is a
   qualification failure, never evidence of absence.

The Linux qualification separately resolves `bin/qemu-img` from the installed managed-runtime
manifest, proves its regular executable file size and SHA-256, binds it to the exact QEMU component
and version, and runs create/resize/JSON-info against a disposable qcow2 file by that absolute path.
It independently binds `bin/qemu-system-x86_64.real` to the same component and manifest, then
requires its exact device inventory to contain `vhost-user-fs-pci`, which Podman's explicit
application-data VirtioFS mount needs.
It also resolves `bin/virtiofsd` from that manifest, binds its digest to the exact component and
version, rejects a non-x86-64 ELF or any host interpreter dependency, and executes its version probe
by absolute path. It does not install or resolve host QEMU or VirtioFS packages. On every platform,
qualification also proves after start that the exact private-XDG `machine{,.pub}` Ed25519 identity
exists with bounded single-link current-user protection and that both fixed staging names are absent.
After uninstall, the exact release-digest provider-home directory itself must be absent; an existing
but empty directory does not satisfy this check.

Before Windows starts the machine, qualification also proves that the fixed Podman runtime,
configuration, WSL data, SSH-identity-parent, and image-cache directories already have protected,
current-user-only inheritable DACLs. Podman therefore never gets an opportunity to create those
security-sensitive namespace ancestors with the administrator token's ambient default owner.

The macOS qualification independently derives the stable `/tmp/assm1-<32-hex-namespace>` short
home from the canonical state root, installed manifest digest, and effective uid. It requires a
fresh real current-user `0700` directory after start, checks the 103-byte Podman socket-path budget,
requires the directory to survive ordinary stop, and requires it to be absent after uninstall.

The universal macOS package is still built on `macos-14`, while its independent qualification runs
the Intel slice on `macos-15-intel`. That fresh job must start the packaged AppleHV machine and run
the same fixed container probe as Linux and Windows. There is no host-limited or skipped release
state: if the hosted runner cannot complete the real lifecycle, the qualification and release fail.
This is exact release evidence from the recorded runner image, not a promise about future hosted
runner capabilities or every end-user Mac.

Each runner emits one strict `platform-qualification-<platform>.json`. The record is bound to the
exact version, candidate tag, 40-character source commit, source artifact name, installer bytes and
SHA-256, hosted runner label and machine-image version, installed/release runtime-manifest SHA-256,
all released managed machine-image URLs/digests/sizes, ordered raw CLI status documents, desktop
startup result, fixed container result, and cleanup results. Unknown fields,
missing operations, caller-selected commands/images, inconsistent status phases, digest changes,
and a false cleanup claim fail closed. Finalization requires all three records; the global checksum
index and GitHub provenance attestation cover them like every other published release file.

The workflow compiles all three real companion executables before every desktop build; no placeholder binary is kept
in Git. For a local native desktop check, run:

```sh
npm ci
npm run desktop:check
```

For an explicit target (including a Linux-hosted Windows GNU cross-check), run:

```sh
npm run desktop:prepare-sidecar -- --target x86_64-pc-windows-gnu
cargo check --locked --package ai-security-scanner --features desktop --target x86_64-pc-windows-gnu
```

Generated target-suffixed sidecars live under the ignored `src-tauri/binaries/` directory.

## Supply-chain evidence

Each GitHub Release contains:

- installer files and separately downloadable platform copies of all three first-party companion executables;
- `SHA256SUMS.txt` covering every published file except itself, plus platform checksum files;
- a CycloneDX JSON SBOM and an SPDX JSON SBOM generated from the locked source dependency graph;
- explicit SBOM entries with the digest and role of each platform companion executable;
- `THIRD_PARTY_NOTICES.txt`, `ENGINE_NOTICES.md`, and machine-readable engine notices;
- `release-metadata.json` and `release-assets.json` for automated consumers;
- strict `platform-qualification-<platform>.json` evidence for Linux, macOS, and Windows;
- the signed updater payloads, their detached `.sig` files, and `latest.json`;
- the project license and release notes; and
- a GitHub build-provenance attestation over every published file.

Release-line details are recorded in the source tree. See the current
[`v0.2.0` product-completion notes](v0.2.0.md) and the historical
[`v0.1.1` security and consistency repair notes](v0.1.1.md).

All third-party engines remain separately acquired artifacts. No engine image, ruleset, feed,
provider plugin, or vulnerability database is embedded in these desktop installers. A runnable
catalog entry is not a redistribution claim.

GitHub Actions are pinned to full commit SHAs. The release uses only the repository-scoped token,
with read-only permissions by default. The assemble job verifies updater signatures, creates the
release index and checksums, independently reverifies both, then uploads the finalized candidate
without publication privileges. Only the exact-tag publish job receives `contents: write`,
`attestations: write`, and `id-token: write`; it downloads that single candidate and reverifies its
complete `SHA256SUMS.txt` and `release-assets.json` coverage before attesting or publishing.

## Signing and updater status

The pipeline deliberately reports the current state without implying controls that are absent:

- Apple Developer ID signing is not configured.
- Apple notarization is not configured.
- Windows Authenticode signing is not configured.
- Tauri updater artifacts are generated and signed with a dedicated updater key held only in the
  repository Actions secret `TAURI_SIGNING_PRIVATE_KEY`.

Consequently, operating systems can still show an unidentified-developer warning. The updater
signature proves that an update payload matches the public key embedded in the installed app; it
does not provide Apple Developer ID, notarization, or Windows Authenticode trust. Release metadata
and notes preserve that distinction.

The desktop checks the fixed HTTPS GitHub Release endpoint. It never accepts a downgrade, an
unsigned payload, a caller-supplied endpoint, or a caller-supplied public key. Installation starts
only after a user selects the visible update action. A successful installation relaunches the app;
historical cases retain their exact engine, adapter, ruleset, and runtime provenance.

## Creating a release

First run the local metadata validator and normal implementation checks. Dispatch the release
workflow from `main` before creating a tag:

```sh
npm run release:validate -- --tag v0.2.0
gh workflow run release.yml --ref main
```

The preflight executes the same Linux, universal macOS, and Windows build matrix, preserves its
desktop startup observations, and then runs the independent hosted qualification matrix described
above. Wait for that dispatch to succeed, record
its immutable `headSha`, and retain or download its `release-finalized` artifact. Tag that exact
commit—not a later `main` tip:

```sh
git tag -a v0.2.0 <preflight-head-sha> -m "ai-security-scanner v0.2.0"
git push origin v0.2.0
```

The tag run rebuilds from the same commit rather than reusing preflight binaries. The GitHub Release
is created only after all three platform builds, all three strict platform qualifications, both
SBOMs, notices, checksum verification, signed updater-manifest assembly, finalized-candidate
reverification, and provenance attestation succeed.
It is published directly as a non-draft stable release; a failed preflight creates no tag or public
release, and a failed tag prerequisite leaves no partial GitHub Release.

## Verifying a downloaded artifact

Download the desired installer and `SHA256SUMS.txt` into the same directory. On Linux or macOS:

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing
gh attestation verify ./ai-security-scanner-installer-file --repo teddashh/ai-security-scanner
```

On Windows, compare `Get-FileHash -Algorithm SHA256` with the matching checksum entry, then use
the same `gh attestation verify` command. Checksums detect file changes; the GitHub attestation
binds the file digest to the repository workflow identity. Neither mechanism is a substitute for
OS code signing, whose absence remains explicit above.

## Managed engine image publication

The project-managed cloud, external-target, Microsoft 365, local artifact, container, Kubernetes,
Greenbone, Checkov, and Syft publication workflows build linux/amd64 plus linux/arm64 indexes,
preserve the immutable public digest, and invoke the common signed-evidence contract documented in
[`engine-image-supply-chain.md`](engine-image-supply-chain.md). Each published index has SLSA
build provenance; each platform manifest has independently signed SPDX and CycloneDX SBOMs. The
attestations remain available from GitHub and as GHCR referrers, while a 90-day workflow artifact
provides convenient copies of the SBOMs, Sigstore bundles, hashes, and evidence manifest.

Gitleaks and KICS are the two explicit upstream-pinned exceptions: the catalog acquires their
verified upstream images by immutable digest and the project does not republish them as managed
GHCR images. This distinction is part of the catalog and release validation contract.

These workflows intentionally keep BuildKit's automatic provenance and SBOM flags disabled. The
external attestations bind to already-final image and platform digests, so adding supply-chain
evidence cannot silently change a digest frozen into an assessment case. Engine release plans
must still independently record the resulting immutable digest and applicable dependency notices.
