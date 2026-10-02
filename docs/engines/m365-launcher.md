# Microsoft 365 launcher

`ai-security-scanner-m365-launcher` is the entrypoint of both Microsoft 365 images, [ScubaGear](scubagear.md) and [Maester](maester.md). It is project-owned Go with no detection logic: it checks what the desktop runtime mounted, then replaces itself with one fixed PowerShell script. The same directory holds `prepare_source.py`, which both Dockerfiles use to unpack the pinned upstream source and PowerShell modules.

| Item | Value |
| --- | --- |
| Source | `engines/images/m365-launcher/main.go`, `go.mod` (Go 1.25.0, standard library only), `NOTICE.md` |
| Build | `launcher` stage of each engine Dockerfile (digest-pinned `golang:1.25.0-alpine3.22`, `CGO_ENABLED=0`, `-trimpath`), installed as `/usr/local/bin/ai-security-scanner-m365-launcher`, the image `ENTRYPOINT` |
| Source preparer | `engines/images/m365-launcher/prepare_source.py`, one `CONTRACTS` entry per engine: revision, archive digest, `source_date_epoch`, selected paths, module pins, manifest version |
| Tests | `engines/images/m365-launcher/main_test.go`, run by the publish workflow (the Docker build copies only `go.mod` and `main.go`) |
| Recorded in | both engine plans: `wrapper.launcher_sha256` (`main.go`) and `build_recipe.source_preparer` (`prepare_source.py`) |
| Publish workflow | `.github/workflows/engine-images-m365.yml`; every run builds both images |

## What it enforces

- **Arguments.** Exactly `--engine scubagear|maester --scope /run/ai-security-scanner/scope.json --output /output`, nothing positional. `/output` must be a directory, not a symlink.
- **Scope** (`loadScope`). A regular file of at most 4 MiB, not a symlink, strict JSON with no unknown fields or trailing data. `schema_version` `1`, `engine_id` equal to `--engine`, exactly one asset of kind `tenant` with provider `microsoft365` and no region, 1 to 128 identifiers, 1 to 16 grants. Grants may only be `inventory_read` or `configuration_read` and both must be present; an `expires_at` must be in the future; `external_scope` must be empty or null.
- **Credential channel** (`validateCredentials`). `/run/ai-security-scanner/credentials.json`, at most 256 KiB, strict JSON: `schema_version` `1.0.0`, exactly one entry, key `MSGRAPH_ACCESS_TOKEN`, a value of at most 128 KiB without NUL, CR or LF, source `ephemeral_scan_role` or `external_read_only_grant`, and `expires_at` after now and at most 65 minutes ahead (`maximumTokenLife`; plan `credential_max_lifetime_minutes`). The host already stops using the token at its expiry or one hour after sign-in, whichever comes first (`bounded_expiry`, `SCANNER_CREDENTIAL_USE_LIMIT` in `src-tauri/src/source_authorization/provider.rs`). The token stays in the file; each wrapper reads it into a SecureString.
- **Environment** (`childEnvironment`). Rebuilt from scratch. Only the proxy keys pass through (`AI_SECURITY_SCANNER_PROXY`, and `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` in both cases), each at most 4096 bytes without NUL, CR or LF. Fixed values: `HOME=/tmp/ai-security-scanner-home`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME` and `XDG_DATA_HOME` under `/tmp/ai-security-scanner-*`, `LANG` and `LC_ALL` `C.UTF-8`, `PATH`, `PSModulePath=/opt/ai-security-scanner/modules:/opt/microsoft/powershell/7/Modules`, `TERM=dumb`, PowerShell and .NET telemetry and update checks off, and `SCUBAGEAR_SKIP_VERSION_CHECK=1` for ScubaGear only. The Dockerfile `ENV` block does not reach a managed run: add a variable here, and mirror it in the Dockerfiles for `--entrypoint pwsh` replays.
- **Proxy spelling** (`dotnetProxy`). The host sets every proxy variable to `socks5h://<gateway-ip>:1080`. .NET ignores `socks5h` and would connect directly, so the launcher rewrites `ALL_PROXY`, `HTTP_PROXY` and `HTTPS_PROXY` (both cases) to `socks5://<gateway-ip>:1080` and leaves `AI_SECURITY_SCANNER_PROXY` as it was. .NET's SOCKS5 client still sends the host name, and the gateway resolves it against the allowlist. A gateway that is not `socks5h`, not an IP literal, not port 1080, or carries a user, path, query or fragment is refused.
- **Runtime directories** (`prepareRuntimeDirectories`). Creates HOME and the three XDG directories with mode 0700 on the empty `/tmp` tmpfs, after every check and before PowerShell starts.
- **Invocation** (`fixedInvocation`). `syscall.Exec` of `/opt/microsoft/powershell/7/pwsh -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File /opt/ai-security-scanner/run-<engine>.ps1`. No shell, and nothing from the scope reaches the command line.
- **Refusal.** Prints `microsoft 365 engine launcher: <reason>` to stderr and exits 126. The host treats any nonzero exit as a failed engine run and adapts nothing (`src-tauri/src/orchestrator.rs`).

## Host side

- **Container** (`src-tauri/src/container_runtime.rs`). Read-only root, `--cap-drop=ALL`, `no-new-privileges`, a non-root user, `/tmp` as a `noexec,nosuid,nodev` tmpfs sized from the catalog's `estimated_disk_mb`, `/workspace` read-only as the working directory, `/output` writable, scope and credential files mounted read-only, the managed network and the proxy variables set to the gateway.
- **Sign-in** (`verify_microsoft365_token_with_identity` in `provider.rs`). The token must carry all 17 read permissions and no write permission, its organization must match the configured tenant, and three live probes must answer: `auditLogs/directoryAudits`, `policies/authorizationPolicy`, and the built-in Directory Readers role definition read by key (`MICROSOFT_DIRECTORY_READERS_ROLE_ID`).
- **Discovery** (`capture_microsoft365` in `src-tauri/src/source_authorization/discovery.rs`). Reads only `organization` and expects exactly one.
- **Allowed engines.** A Microsoft 365 authorization runs only `maester`, `scubagear` and provider discovery (`src-tauri/src/source_authorization.rs`), with eight credential checkouts per authorization (`DEFAULT_PROVIDER_CHECKOUT_LIMIT`).

## Tests

- `main_test.go`: one read-only tenant is accepted; several tenants, a wrong provider, an admin grant, active external scope and a missing grant are refused; a wrong key, an expired token, a two-hour token, an unverified source and two entries are refused; the invocation never carries the token, the proxy rewrite is present, and malformed gateways are refused; runtime directories exist before PowerShell starts; symlinks and oversized files are refused.
- The publish workflow requires an empty `gofmt -d main.go main_test.go` and a passing `go test ./...` in the pinned Go image before either image is built. After publication its smoke contract checks the image user `65532:65532` and entrypoint, refusal of a missing `/output` (`inspect evidence output:`), scope (`read immutable scope:`) and credential file (`read protected credential channel:`), at least five dependency notices, and the lock's module version.
- `scripts/validate-engine-catalog.mjs` requires the current launcher and preparer hashes in both plans, the 65-minute window, the Graph-only destination, the workflow's `gofmt`, `go test` and smoke-contract strings, and the launcher tests before any image build.
- Each image build checks the wrapper's single `Connect-MgGraph` call against the pinned module's `AccessTokenParameterSet` (ScubaGear in a Dockerfile `RUN`, Maester in its Pester specification).

## Publishing

- The workflow runs on pushes to `main` that touch `engines/images/m365-launcher/**`, `engines/images/scubagear/**` or `engines/images/maester/**` (each `plan.json` excepted), and on manual dispatch. Every run builds both matrix entries.
- Tags are immutable. The guard (`publicationPreflight` in `scripts/engine-image-evidence.mjs`) builds when the tag is absent. When it exists, the guard reuses the image only if the plan at the publishing commit binds that tag and records the same input hashes.
- Releases publish first and pin second (9f6a976 then eba1c22; 31ae95d then 6104099). The publishing commit's plan still names the previous tag, so the reuse path always fails. Any later change under these paths, notices and Markdown included, needs new tags for both engines; otherwise the unchanged engine's job fails at the guard. A manual dispatch at an already-pinned commit fails the same way.
- From the first change to a recorded input (Dockerfile, lock, preparer, launcher, wrapper) until the pin commit, `npm run validate:engines` fails because the files and the matrix tags run ahead of the plans. The pin commit restores it.
- No plan records `go.mod` (a shared module definition in `engines/image-input-hash-policy.json`) or `main_test.go` (the `_test.go` rule).

## Lessons from real runs

- 2026-10-02: every Microsoft 365 sign-in was refused. Cause: Graph rejects `$top` on role definitions with `Request_UnsupportedQuery`, and the fake matched any `/roleManagement/` path. Fix: c0f66f6 reads the built-in Directory Readers definition by key and pins the exact request in the fake.
- 2026-10-02: a signed-in tenant had no applicable checks. Cause: discovery also listed users, and a tenant with more than 700 users ran past the page limit, so the source failed. Fix: c0f66f6 reads only the organization; no engine scans a user.
- 2026-10-02: every Graph call from both images failed at the proxy. Cause: .NET ignores `socks5h` and connects directly. Fix: e4571df hands .NET `socks5://`; checked without a credential, Graph then answered 401 through both images.
- 2026-10-02: Maester exited 1 before testing. Cause: HOME on the fresh tmpfs did not exist, so the Graph SDK could not save its context. Fix: 95936ac creates the runtime directories for both engines.
