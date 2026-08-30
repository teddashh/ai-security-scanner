# Release-managed local runtime

Normative status: this is a subordinate current-implementation/runtime reference. The [canonical product specification](product-spec.md) controls user-visible setup, isolation, recovery, Repair, upgrade, and uninstall behavior. Deterministic-name reclamation, manual WSL action, or fail-closed wording here cannot add a product gate contrary to that specification.

`ai-security-scanner` can run containerized engines on a clean workstation without asking the
user to install Docker, Podman, QEMU, or a system service. Docker and user-installed Podman remain
explicit compatibility providers; they are not silently mixed with managed runs.

## Runtime contract

- A release carries an immutable, platform-specific Podman machine client bundle in the app
  resources directory. Every bundled file has an exact size and SHA-256 in `manifest.json`.
- The app verifies the resource bundle before copying it to a versioned directory under its own
  local application-data directory. It never changes the system `PATH`, invokes a package manager,
  requests elevation, enables Windows optional features, or runs Windows servicing commands.
  Scanner engines and the managed runtime remain rootless.
- A fresh installed desktop with no existing cases enters a first-launch scan-tool installation
  phase whenever the release-managed runtime has not been prepared yet. It starts this
  product-owned lifecycle operation automatically; an already-ready host reaches the scan workspace
  without a setup click. Existing cases and results are never hidden by runtime setup or failure: a
  stopped or missing runtime starts in the background while the workspace remains available. Failed
  or cancelled attempts are never repeated automatically in the same process.
- On Windows, first launch resolves the trusted `SystemRoot\System32\wsl.exe` boundary and runs
  bounded, read-only `--status` and `-l --quiet` probes, matching the inventory command used by the
  pinned Podman WSL provider. The probe requests UTF-8 output while retaining bounded UTF-16LE
  compatibility for older inbox WSL builds. A failed prerequisite check stops
  before any VM-image bytes are downloaded. It records one stable `failure_reason` and paired
  `next_action`: install WSL, enable its optional components, update WSL, restart Windows, or retry
  the check. Console output is accepted only as bounded UTF-8 or UTF-16LE; mixed or unsafe bytes are
  never interpolated into UI errors. Install, enable, and update outcomes lead to one link to
  Microsoft's official WSL setup and one safe recheck. No elevation or servicing action is exposed
  through the webview. The app never restarts Windows automatically. Reopening the app after a
  Microsoft-requested restart repeats the read-only check and continues the private runtime setup
  automatically.
- The VM image is downloaded from the exact HTTPS URL pinned in the release manifest. Bounded
  resumable downloads are accepted only from approved GitHub release hosts and are committed only
  after the locked size and SHA-256 match.
- Desktop first-run setup exposes one authoritative operation at a time. Its `install`,
  `prerequisite`, `download`, `init`, `start`, and `verify` phases are queryable, and the download phase reports the exact
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
- On Linux only, managed commands set `XDG_RUNTIME_DIR` to a stable
  `/tmp/assm1-<32-hex-namespace>` directory while `HOME`, configuration, identities, images, and
  every other durable provider path remain under the release-private provider home. The namespace
  uses a Linux-specific domain-separated hash of the canonical managed state root, exact release
  manifest digest, and effective uid. The app creates or reopens only that exact `/tmp` child when
  it is a real current-user directory with mode `0700`, verified through an `O_NOFOLLOW` directory
  handle. An immutable private `storage.conf`, selected through the exact
  `CONTAINERS_STORAGE_CONF` path, pins containers/storage's `runroot` to
  `provider-home/run/containers` and `graphroot` to `provider-home/data/containers/storage`.
  The pinned containers/storage and containers/common libraries resolve defaults before applying
  those private overrides, so they may eagerly leave only empty `containers` (mode `0700`) and
  `libpod` (mode `01700`) scaffolds beside Podman's socket-budgeted `podman` namespace. Runtime and
  image state still remain in the persistent private provider home. A link, foreign owner,
  permissive mode, non-canonical temporary base, or changed object fails closed. With a maximum
  30-byte machine name, Podman 5.8.2's longest
  `$XDG_RUNTIME_DIR/podman/*-gvproxy.sock` path is 94 bytes, below its 103-byte Unix-socket budget.
- The Linux short runtime remains stable across start, ordinary stop, and update. After exact
  machine removal, uninstall accepts only the pinned Podman `podman` child and the exact empty
  `containers` and `libpod` scaffolds. Each scaffold must be a real current-user directory with
  its exact observed mode, opened without following links and rechecked by device and inode before
  descriptor-relative removal; a nonempty directory or any other entry fails closed. From the
  `podman` child, cleanup may remove only the exact `virtiofschar0.pid`, `virtiofschar0`, and
  `gvproxy.log` basenames. The pid must be a
  current-user, single-link, mode-`0600` regular file whose exclusive `flock` becomes available
  within a bounded wait; only that proof permits removal of a matching current-user, single-link,
  mode-`0700` Unix socket. A socket without its exact pid-lock proof, a still-live lock, or any
  other unsafe type fails closed. The log must likewise be a current-user, single-link,
  non-executable regular file with an expected umask-derived mode. Cleanup then requires the Podman
  directory and short root to be empty before removing those exact directories and syncing `/tmp`.
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
  accepts an absent or empty real `.podman` directory, or the single exact
  `<deterministic-machine>-ignition.sock` pathname left by pinned Podman 5.8.2's first-boot
  ignition server. That one pathname is removed through the verified directory handle only after
  no-follow inspection proves it is a current-user, single-link Unix socket and a second identity
  check is unchanged. The pinned SSH client also eagerly creates `.ssh/known_hosts` before selecting
  its machine-only host-key callback. Uninstall accepts `.ssh` only as a real current-user mode-
  `0700` directory containing exactly one current-user, single-link, mode-`0600`, zero-byte regular
  `known_hosts` file. Both objects are opened without following links and rechecked by device,
  inode, ownership, mode, link count, and size as applicable before descriptor-relative removal.
  Cleanup is not recursive: another root basename, an additional child, a nonempty or hard-linked
  `known_hosts`, a link, foreign ownership, a wrong mode or type, or an unsafe directory replacement
  aborts cleanup before the unsafe object is removed.
- On Windows, Podman can leave its underlying WSL distribution behind after an interrupted setup or
  even after reporting `machine rm` success. The app obtains the Windows root from the bounded
  operating-system directory API, never an inherited `SystemRoot`, and runs its absolute canonical
  `SystemRoot\System32\wsl.exe` with a cleared minimal environment, fixed provider working
  directory, bounded deadlines/output, and strictly decoded bounded UTF-8 or UTF-16LE inventory.
  Ordinary uninstall never treats a surviving distribution or one-shot initialization journal as
  deletion authority: it stops and retains the provider, installation, and requested cache state.
- First-launch replacement has a separate durable recovery transaction. It begins only when the
  deterministic WSL name has exactly one registry registration whose canonical storage is inside a
  release-private provider home bound to the current or another fully verified installed manifest.
  The app records an immutable intent, checks free space without opening the running VHD, terminates
  that exact distribution, then proves the stopped `ext4.vhdx` is a real non-reparse, one-link,
  nonempty file. It exports a tar archive, synchronizes and atomically publishes it, records bounded
  size and SHA-256, imports it under a generated quarantine name and isolated private directory,
  and proves the import through both inventory and the unique registry `BasePath`.
- Immediately before unregistering the original, the app rehashes the archive, reproves the
  quarantine registration and storage, terminates and reproves the unchanged original, and confirms
  both exact names in a fresh inventory. Only that transaction may run `wsl --unregister`, and only
  for the proven original or generated quarantine name. It then proves inventory and registry
  absence before deleting an exact provider directory. The replacement runtime must start and its
  server must become ready before the temporary bootable quarantine is removed. The opaque archive,
  intent, backup proof, and import proof remain; interrupted export, import, replacement, and cleanup
  resume idempotently from those records. An ownership ambiguity fails closed to Microsoft's manual
  backup/removal guidance. Recovery and cleanup never use the global `wsl --shutdown` operation.
- After absence is proven, deletion of a verified provider home retries Win32 sharing violations
  every 100 ms for at most 10 seconds so a released `ext4.vhdx` can be removed; every other deletion
  error fails immediately.
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
  inheritable, current-user-only DACLs, with one narrowly scoped WSL compatibility exception. The
  exact `data/containers/podman/machine/wsl/wsldist` directory has a protected DACL, a
  non-defaulted current-user owner, and exactly two explicit object-and-container-inheritable full
  control grants: the current user and LocalSystem. WSL's system service needs that access while it
  imports and operates the distribution; no ancestor, identity, configuration, cache, or runtime
  directory receives the LocalSystem grant. The caller-selected data-directory root is never
  rewritten. Before creating or accepting that namespace, the app opens the canonical local
  ancestor chain without following reparse points and rejects an untrusted owner or any
  malformed/unsupported ACL. Untrusted namespace-replacement grants remain forbidden except for
  capability SIDs on the exact `FOLDERID_LocalAppData` directory and its `AppData` parent. Those two
  ordinary Windows profile layers are accepted only when the caller's canonical chain contains the
  OS-resolved LocalAppData object. Each manager retains no-delete-share handles for that complete
  verified chain and the non-reparse state-root object for its lifetime; the capability exception
  never extends to the app data directory or a managed descendant. An unsafe parent or pre-existing
  namespace is rejected rather than silently repaired.
- Every private Windows file creation additionally pins and verifies its canonical immediate parent
  before `CREATE_NEW`. The parent must retain that exact protected current-user-only inheritable
  DACL; otherwise creation fails before any staging entry exists. The new child is then read back by
  its exclusive handle and must have the exact protected, non-inheritable current-user-only DACL.
- Command execution errors use fixed operation labels and never echo command arguments. Inventory
  and version probes retain 30-second bounds, stop/removal retain 90-second bounds, and first-time
  initialization plus start/readiness each receive separate 10-minute deadlines for cold AppleHV
  boots.
- Runtime preflight and execution checkpoints persist typed command provenance: runtime version,
  release-manifest SHA-256, and machine-image SHA-256. Resume and cleanup can therefore reopen the
  exact older installation after an app update instead of guessing from `PATH`.
- Runtime preflight reads Docker's native security-options array or Podman's typed
  `Host.Security` object according to the selected provider. Managed Podman must report both
  rootless execution and seccomp; malformed, oversized, or incomplete security information fails
  closed instead of being retained as an unverified display string.
- On Linux, first initialization mounts the canonical application-data directory at the identical
  absolute path inside the QEMU machine. All execution workspaces are immutable snapshots below
  that directory. Podman runs each engine with the desktop user's exact non-root uid/gid and an
  explicit `keep-id` user namespace, so private `0700` case artifacts remain traversable without
  widening their host permissions. The release bundles the static `virtiofsd` helper required for
  this mount; it never falls back to a host-installed helper.

The current platform providers are:

| Host | Provider | Release payload | Host prerequisite |
| --- | --- | --- | --- |
| Linux x86-64 | rootless Podman machine + QEMU | Podman, gvproxy, static x86-64 QEMU emulator, `qemu-img`, `virtiofsd`, and firmware | None. `/dev/kvm` is used when available; otherwise the native launcher selects QEMU TCG, which is slower. |
| macOS Intel/Apple silicon | rootless Podman machine + AppleHV | Universal Podman, vfkit, and gvproxy | A supported macOS release with Apple virtualization support. |
| Windows x86-64 | rootless Podman machine + WSL | Podman, gvproxy, and win-sshproxy | WSL 2. The app checks it without elevation on first launch. If unavailable or outdated, the UI links to Microsoft's setup once and rechecks automatically on the next launch. |

## Lifecycle

The desktop starts the managed machine on demand before engine execution and prefers it over
compatibility runtimes.

On first desktop launch, the UI reads both runtime health and setup status before automatically
invoking `setup_managed_runtime`. The command runs in a blocking worker while the responsive window
independently polls `get_managed_runtime_setup_status`; `cancel_managed_runtime_setup` only signals
that worker and returns the current status immediately. The automatic path verifies product-owned
files, performs read-only host checks, downloads pinned runtime content, and starts the private
machine. It does not request elevation, enable Windows optional features, or run Windows servicing
commands. A missing or outdated WSL installation therefore becomes one clear link to Microsoft's
official setup and one safe recheck instead of a repeating in-app Repair action.

The legacy prerequisite-repair implementation remains backend-internal for compatibility testing,
but it is not registered as a desktop webview command and is not reachable from the current UI.

The setup-status JSON uses `phase: "prerequisite"` while checking Windows. A failed Windows check
returns one of `windows_wsl_not_installed`, `windows_wsl_optional_feature_disabled`,
`windows_wsl_update_required`, `windows_restart_required`, or `windows_wsl_command_failed` in
`failure_reason`, paired with `install_wsl`, `enable_wsl_optional_features`, `update_wsl`,
`restart_windows`, or `retry_wsl_check` in `next_action`. Both fields are `null` outside a failed
setup. Human-facing clients localize those stable values and keep the bounded diagnostic in an
optional technical-details view. `prerequisite_repair_active` remains in the serialized status for
backward compatibility; the current desktop UI never starts that operation.

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
before the isolated container starts. A cold pinned-image pull has a separate 10-minute deadline;
preflight, inspection, and container-control commands retain their 30-second deadline. All direct
command execution and deadline failures identify a fixed operation label; the local error wrapper
never constructs those messages from the image reference, container identity, or other command
arguments. Success is emitted only after the expected empty JSON report is hashed and the created
container is removed by its immutable runtime ID. The machine-readable result binds the runtime
manifest and machine-image digests, engine image, scope digest, report and capture digests, exit
status, and cleanup outcome. This proves release-runtime execution and cleanup, not assessment
coverage.

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
`linux/amd64` platform from the locked QEMU and DTC sources in the pinned container builder;
`virtiofsd` is independently built from its locked source and Cargo graph with a digest-pinned Rust
builder. The vendor step rejects each of the launcher, real emulator, `qemu-img`, and `virtiofsd`
unless it is static ELF64, little-endian x86-64. It verifies both helper versions and functionally
proves `qemu-img` create/resize/JSON-info before staging. The exact QEMU build enables vhost-user
support and must expose `vhost-user-fs-pci` both before installation and from the staged real
emulator; this is a lock-driven capability contract, not a host-QEMU fallback.
The native launcher probes KVM and changes only Podman's exact `-accel kvm -cpu host` arguments to
`tcg/max` when KVM is unusable. The locked Linux build contract retains the x86_64 SeaBIOS, OVMF,
and device firmware while excluding eight foreign-architecture firmware images that the
x86_64-only emulator cannot use. Tauri maps the completed directory to
`$RESOURCE/managed-runtime/`.

Manifest schema 3 records the lock-sourced `management_contract_revision` alongside the pinned
upstream payload. This revision identifies the product-side lifecycle and ownership rules that
interpret those bytes. Version 0.1.8 uses `2026-08-29.1`; its reviewed Windows x86-64 manifest is
`a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a`. The current application fails
closed on any other schema-3 contract. It can still reopen a strict schema-2 installed manifest
only when the revision field is absent, preserving the public v0.1.7 identity for the bounded N-1
recovery proof; a schema-2 manifest is never accepted as the current bundled v0.1.8 resource.

A schema number, revision, or formatting-only edit must not be used to manufacture a provider
identity. Changing the revision requires a reviewed change to the product-side runtime management
contract plus release evidence from a real platform build.

The cheap lock-only validation used during development is:

```text
node runtime/vendor-managed-runtime.mjs --target x86_64-unknown-linux-gnu --verify-lock-only
node runtime/vendor-managed-runtime.mjs --target universal-apple-darwin --verify-lock-only
node runtime/vendor-managed-runtime.mjs --target x86_64-pc-windows-msvc --verify-lock-only
```

Source and binary identities are intentionally updated only through the lock file. A version bump
must replace all affected URLs, sizes, SHA-256 values, source revisions, helper binaries, and machine
images together.
