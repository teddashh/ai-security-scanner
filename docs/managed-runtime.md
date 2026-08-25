# Release-managed local runtime

`ai-security-scanner` can run containerized engines on a clean workstation without asking the
user to install Docker, Podman, QEMU, or a system service. Docker and user-installed Podman remain
explicit compatibility providers; they are not silently mixed with managed runs.

## Runtime contract

- A release carries an immutable, platform-specific Podman machine client bundle in the app
  resources directory. Every bundled file has an exact size and SHA-256 in `manifest.json`.
- The app verifies the resource bundle before copying it to a versioned directory under its own
  local application-data directory. It never changes the system `PATH`, invokes a package manager,
  enables an operating-system feature, or requests administrator privileges.
- The VM image is downloaded from the exact HTTPS URL pinned in the release manifest. Bounded
  resumable downloads are accepted only from approved GitHub release hosts and are committed only
  after the locked size and SHA-256 match.
- Desktop first-run setup exposes one authoritative operation at a time. Its `install`, `download`,
  `init`, `start`, and `verify` phases are queryable, and the download phase reports the exact
  received bytes, locked total bytes, and derived percentage after every bounded chunk. A separate
  cancel command sets an atomic cancellation request without waiting for the lifecycle lock.
- Cancellation retains the private `*.download-part` regular file. The next setup validates its
  length, requests the exact remaining suffix with HTTP `Range`, rejects a mismatched
  `Content-Range`, and restarts from zero if the approved server returns a complete response instead.
  Only a size- and SHA-256-verified complete image is atomically promoted into the runtime cache.
- Each release uses its own persistent private provider home, XDG directories, `containers.conf`,
  machine name, image cache, and lifecycle lock. Machine names use the deterministic
  `assm1-<host>-<architecture>-<12-hex-image-id>` form and remain within Podman's 30-byte limit on
  every supported host and architecture. Managed commands clear the inherited environment and use
  absolute, already-verified executable paths. On Windows they also disable current-directory
  executable lookup, so Go helper resolution remains inside the constrained managed `PATH`.
- On macOS only, managed commands set `HOME`, `USERPROFILE`, and their working directory to the
  stable `/tmp/assm1-<32-hex-namespace>` directory. The namespace hashes the canonical managed
  state root, exact release-manifest digest, and effective uid. The app creates or reopens that
  exact entry only when it is a real current-user directory with mode `0700`; links, foreign
  ownership, or permissive modes fail closed. XDG configuration, identities, images, and all other
  durable provider data remain under the persistent private provider home. Even with a maximum
  30-byte machine name, Podman 5.8.2's longest `$HOME/.podman/*-ignition.sock` alias is 96 bytes,
  below its 103-byte Unix-socket path ceiling.
- The macOS short home is stable and remains present across start, ordinary stop, and update so a
  live vfkit/gvproxy process cannot lose its socket aliases. Uninstall removes only that exact
  owned namespace after `machine rm` succeeds or inventory proves the exact machine is absent. It
  removes only an absent or empty real `.podman` directory and then the empty home itself; links,
  unexpected children, or an unsafe replacement abort cleanup instead of broadening removal.
- On Windows, Podman can report `machine rm` success after an underlying WSL unregister failure.
  Before deleting the release-private provider home, installation, or requested image cache, the
  app therefore obtains the Windows root from the bounded operating-system directory API, never an
  inherited `SystemRoot`, and runs its absolute canonical `SystemRoot\System32\wsl.exe` with a
  cleared minimal environment, fixed provider working directory, bounded deadline/output, and
  `--list --quiet`.
  It strictly accepts only bounded UTF-8 or UTF-16LE distribution names. If the deterministic exact
  `podman-assm1-win-x64-<12-hex-image-id>` distribution remains, the app unregisters only that
  exact owned name and inventories again. Execution, decoding, unregister, or final-absence proof
  failure retains provider, installation, and cache state for a safe retry; no prefix or wildcard
  WSL removal is permitted.
- Before first initialization, the app generates Podman 5.8.2's exact private-XDG
  `data/containers/podman/machine/machine{,.pub}` identity itself as an unencrypted OpenSSH Ed25519
  pair. It uses operating-system randomness and RustCrypto parsing/encoding, not a host
  `ssh-keygen`, shell, inherited `PATH`, or external secret. Both halves are bounded, single-link
  current-user files, durably staged, and atomically published. On Unix the private half must have
  mode `0400` or `0600`; the non-secret public half may additionally use `0444` or `0644`. On
  Windows both files have a protected current-user-only DACL from the first written byte, and
  cleanup deletes through the already-verified handle. An interrupted hard-link publication is
  recoverable only when the fixed staging name and its exact destination are the same regular
  two-link file; every other hard link fails closed. A valid existing pair is reused without
  changing its permissions; a
  regular partial/corrupt pair can be repaired before initialization, while a non-regular entry or
  any mismatch after a machine exists fails closed instead of silently rotating its trusted key.
  Once uninstall removes or proves absence of the exact machine, it removes that release's exact
  private provider home as well, so the SSH identity and provider configuration do not survive a
  successful uninstall.
- On Windows the app-created `managed-runtime` namespace and its provider directories use protected,
  inheritable, current-user-only DACLs. The caller-selected data-directory root is never rewritten.
  Each manager also retains a no-delete-share handle to the verified, non-reparse state root for its
  lifetime, preventing a permissive parent directory from replacing that namespace mid-operation;
  an unsafe pre-existing namespace is rejected rather than silently repaired.
- Command execution errors use fixed operation labels and never echo command arguments. Inventory
  and version probes retain 30-second bounds, stop/removal retain 90-second bounds, and first-time
  initialization plus start/readiness each receive separate 10-minute deadlines for cold AppleHV
  boots.
- Runtime preflight and execution checkpoints persist typed command provenance: runtime version,
  release-manifest SHA-256, and machine-image SHA-256. Resume and cleanup can therefore reopen the
  exact older installation after an app update instead of guessing from `PATH`.

The current platform providers are:

| Host | Provider | Release payload | Host prerequisite |
| --- | --- | --- | --- |
| Linux x86-64 | rootless Podman machine + QEMU | Podman, gvproxy, static x86-64 QEMU emulator, `qemu-img`, and firmware | None. `/dev/kvm` is used when available; otherwise the native launcher selects QEMU TCG, which is slower. |
| macOS Intel/Apple silicon | rootless Podman machine + AppleHV | Universal Podman, vfkit, and gvproxy | A supported macOS release with Apple virtualization support. |
| Windows x86-64 | rootless Podman machine + WSL | Podman, gvproxy, and win-sshproxy | WSL 2 must already be available. The app never enables Windows optional features. |

## Lifecycle

The desktop starts the managed machine on demand before engine execution and prefers it over
compatibility runtimes.

The desktop invokes `setup_managed_runtime` in a blocking worker while independently polling
`get_managed_runtime_setup_status`; `cancel_managed_runtime_setup` only signals that worker and
returns the current status immediately. This separation keeps the window responsive and makes a
single active setup observable without starting a competing setup operation.

The standalone development CLI exposes the same durable lifecycle:

```text
ai-security-scanner-cli runtime managed status
ai-security-scanner-cli runtime managed install
ai-security-scanner-cli runtime managed start
ai-security-scanner-cli runtime managed stop
ai-security-scanner-cli runtime managed update
ai-security-scanner-cli runtime managed qualify
ai-security-scanner-cli runtime managed uninstall
```

`stop` and `uninstall` refuse to interrupt active engine containers. `--force` is an explicit
override. `uninstall --purge-image-cache` additionally removes only the exact managed image-cache
file. Update proves and starts the new payload first, while retaining older verified versions so a
durable cleanup checkpoint can still resolve its exact manifest identity.

For an unpackaged CLI build, use
`--managed-runtime-bundle /absolute/path/to/managed-runtime` or set
`AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE`. Without a bundle override, the CLI searches only its
known packaged resource locations and then reopens a single verified private installation. Multiple
installed versions require a durable exact manifest digest and otherwise fail closed.

`qualify` has no image, command, network, or credential arguments. It starts the verified managed
runtime, retrieves the release-fixed Gitleaks digest, and executes the built-in qualification
fixture through the same container-plan path used by scans. That plan has a read-only root,
drop-all capabilities, no-new-privileges, no credentials, and `network=none`; the image pull occurs
before the isolated container starts. Success is emitted only after the expected empty JSON report
is hashed and the created container is removed by its immutable runtime ID. The machine-readable
result binds the runtime manifest and machine-image digests, engine image, scope digest, report and
capture digests, exit status, and cleanup outcome. This proves release-runtime execution and
cleanup, not assessment coverage.

## Engine output exhaustion protection

Every engine plan carries an aggregate output-byte limit (512 MiB by default, with bounded
configuration). The runtime combines three controls:

- the container receives one exact `RLIMIT_FSIZE` (`--ulimit fsize=N:N`), limiting an individual
  regular file;
- container runtime logs are disabled with `--log-driver=none`;
- stdout, stderr, and the recursive bind-mounted output tree share one in-process byte budget. Pipe
  capture is bounded, and the container is stopped and killed if bytes, file count, directory depth,
  symlinks, or special objects violate the contract.

An aggregate breach returns an explicit error that scan coverage is incomplete. The recursive
monitor is not an operating-system filesystem quota, so a rapidly writing process may transiently
cross the aggregate threshold between checks; the per-file kernel limit remains in force and the
monitor checks every 25 ms before stopping the owned container.

## Release staging

The release workflow runs the pinned vendor tool before Tauri packaging:

```text
node runtime/vendor-managed-runtime.mjs \
  --target x86_64-unknown-linux-gnu \
  --output runtime/staged/managed-runtime
```

The tool reads `runtime/upstreams.lock.json`, enforces approved HTTPS origins, verifies every
download by locked size and SHA-256, extracts without a shell, selects client files by exact content
identity, and publishes the completed directory atomically. Linux QEMU is built for the locked
`linux/amd64` platform from the locked QEMU and DTC sources in the pinned container builder. The
vendor step rejects each of the launcher, real emulator, and `qemu-img` unless it is static ELF64,
little-endian x86-64, and it functionally proves `qemu-img` create/resize/JSON-info before staging.
The native launcher probes KVM and changes only Podman's exact `-accel kvm -cpu host` arguments to
`tcg/max` when KVM is unusable. The locked Linux build contract retains the x86_64 SeaBIOS, OVMF,
and device firmware while excluding eight foreign-architecture firmware images that the
x86_64-only emulator cannot use. Tauri maps the completed directory to
`$RESOURCE/managed-runtime/`.

The cheap lock-only validation used during development is:

```text
node runtime/vendor-managed-runtime.mjs --target x86_64-unknown-linux-gnu --verify-lock-only
node runtime/vendor-managed-runtime.mjs --target universal-apple-darwin --verify-lock-only
node runtime/vendor-managed-runtime.mjs --target x86_64-pc-windows-msvc --verify-lock-only
```

Source and binary identities are intentionally updated only through the lock file. A version bump
must replace all affected URLs, sizes, SHA-256 values, source revisions, helper binaries, and machine
images together.
