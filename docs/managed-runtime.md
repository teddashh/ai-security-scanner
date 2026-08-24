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
- Each release uses its own private `HOME`, XDG directories, `containers.conf`, machine name, image
  cache, and lifecycle lock. Managed commands clear the inherited environment and use absolute,
  already-verified executable paths.
- Runtime preflight and execution checkpoints persist typed command provenance: runtime version,
  release-manifest SHA-256, and machine-image SHA-256. Resume and cleanup can therefore reopen the
  exact older installation after an app update instead of guessing from `PATH`.

The current platform providers are:

| Host | Provider | Release payload | Host prerequisite |
| --- | --- | --- | --- |
| Linux x86-64 | rootless Podman machine + QEMU | Podman, gvproxy, static QEMU and firmware | None. `/dev/kvm` is used when available; otherwise the native launcher selects QEMU TCG, which is slower. |
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
identity, and publishes the completed directory atomically. Linux QEMU is built from the locked QEMU
and DTC sources in the pinned container builder; its native launcher probes KVM and changes only
Podman's exact `-accel kvm -cpu host` arguments to `tcg/max` when KVM is unusable. Tauri maps the
completed directory to `$RESOURCE/managed-runtime/`.

The cheap lock-only validation used during development is:

```text
node runtime/vendor-managed-runtime.mjs --target x86_64-unknown-linux-gnu --verify-lock-only
node runtime/vendor-managed-runtime.mjs --target universal-apple-darwin --verify-lock-only
node runtime/vendor-managed-runtime.mjs --target x86_64-pc-windows-msvc --verify-lock-only
```

Source and binary identities are intentionally updated only through the lock file. A version bump
must replace all affected URLs, sizes, SHA-256 values, source revisions, helper binaries, and machine
images together.
