//! Lifecycle and supply-chain boundary for the product-managed container runtime.
//!
//! The desktop application never installs a system service, edits the user's PATH,
//! or invokes an operating-system package manager. A release carries a small,
//! platform-specific Podman machine client bundle. This module verifies and copies
//! that bundle into the application's private data directory, downloads the exact
//! Podman machine image declared by the release manifest, and owns one rootless VM.
//! Docker and a user-installed Podman remain compatibility providers elsewhere.

use crate::error::{AppError, AppResult};
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_RANGE, RANGE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey, rand_core::OsRng};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const MANIFEST_SCHEMA_VERSION: &str = "2";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_BUNDLE_FILES: usize = 128;
const MAX_INSTALLED_VERSIONS: usize = 32;
const MAX_BUNDLE_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MACHINE_IMAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_COMMAND_DIAGNOSTIC_CHARS: usize = 4096;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MACHINE_INIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MACHINE_START_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MACHINE_STOP_TIMEOUT: Duration = Duration::from_secs(90);
#[cfg(windows)]
const WINDOWS_WSL_PROVIDER_DELETE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(windows)]
const WINDOWS_WSL_PROVIDER_DELETE_POLL: Duration = Duration::from_millis(100);
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);
const DOWNLOAD_CHUNK_BYTES: usize = 128 * 1024;
const MACHINE_PREFIX: &str = "assm1";
const MAX_MACHINE_NAME_BYTES: usize = 30;
const MACHINE_IMAGE_ID_HEX_CHARS: usize = 12;
const MAX_WSL_DISTRIBUTIONS: usize = 1024;
const MAX_WSL_DISTRIBUTION_NAME_BYTES: usize = 256;
const MAX_SSH_PRIVATE_KEY_BYTES: u64 = 16 * 1024;
const MAX_SSH_PUBLIC_KEY_BYTES: u64 = 4 * 1024;
const PODMAN_MACHINE_IDENTITY_NAME: &str = "machine";
const PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY: &str = "wsldist";
const MANAGED_SSH_KEY_COMMENT: &str = "ai-security-scanner-managed-runtime";
#[cfg(unix)]
const LINUX_SHORT_RUNTIME_BASE: &str = "/tmp";
#[cfg(unix)]
const LINUX_SHORT_RUNTIME_PREFIX: &str = "assm1-";
#[cfg(unix)]
const LINUX_SHORT_RUNTIME_DIGEST_HEX_CHARS: usize = 32;
#[cfg(unix)]
const PODMAN_LINUX_MAX_SOCKET_PATH_BYTES: usize = 103;
#[cfg(unix)]
const PODMAN_LINUX_RUNTIME_DIRECTORY: &str = "podman";
#[cfg(unix)]
const PODMAN_LINUX_EAGER_STORAGE_DIRECTORY: &str = "containers";
#[cfg(unix)]
const PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY: &str = "libpod";
#[cfg(unix)]
const PODMAN_GVPROXY_SOCKET_SUFFIX: &str = "-gvproxy.sock";
#[cfg(unix)]
const PODMAN_GVPROXY_LOG_NAME: &str = "gvproxy.log";
#[cfg(unix)]
const PODMAN_VIRTIOFS_SOCKET_NAME: &str = "virtiofschar0";
#[cfg(unix)]
const PODMAN_VIRTIOFS_PID_NAME: &str = "virtiofschar0.pid";
#[cfg(unix)]
const LINUX_VIRTIOFS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const LINUX_VIRTIOFS_CLEANUP_POLL: Duration = Duration::from_millis(25);
#[cfg(unix)]
const MACOS_SHORT_HOME_BASE: &str = "/tmp";
#[cfg(unix)]
const MACOS_SHORT_HOME_PREFIX: &str = "assm1-";
#[cfg(unix)]
const MACOS_SHORT_HOME_DIGEST_HEX_CHARS: usize = 32;
#[cfg(unix)]
const PODMAN_MACOS_MAX_SOCKET_PATH_BYTES: usize = 103;
#[cfg(unix)]
const PODMAN_IGNITION_SOCKET_SUFFIX: &str = "-ignition.sock";
#[cfg(unix)]
const PODMAN_MACOS_SSH_DIRECTORY: &str = ".ssh";
#[cfg(unix)]
const PODMAN_MACOS_KNOWN_HOSTS_FILE: &str = "known_hosts";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperatingSystem {
    Linux,
    Macos,
    Windows,
}

impl ManagedOperatingSystem {
    fn current() -> Option<Self> {
        if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else if cfg!(target_os = "windows") {
            Some(Self::Windows)
        } else {
            None
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }

    fn machine_name_key(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "win",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedArchitecture {
    X86_64,
    Aarch64,
}

impl ManagedArchitecture {
    fn current() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
            Self::Aarch64 => "aarch64",
        }
    }

    fn machine_name_key(self) -> &'static str {
        match self {
            Self::X86_64 => "x64",
            Self::Aarch64 => "arm64",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedMachineProvider {
    Applehv,
    Qemu,
    Wsl,
}

impl ManagedMachineProvider {
    fn argument(self) -> &'static str {
        match self {
            Self::Applehv => "applehv",
            Self::Qemu => "qemu",
            Self::Wsl => "wsl",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeSource {
    pub repository_url: String,
    pub source_revision: String,
    pub license_spdx: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeFile {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimeArtifactDelivery {
    BundledFile,
    RuntimeDownload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeComponentArtifact {
    pub delivery: ManagedRuntimeArtifactDelivery,
    /// Bundle-relative path for `bundled_file`, exact HTTPS URL for
    /// `runtime_download`.
    pub locator: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeSourceArchive {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeComponent {
    pub id: String,
    pub name: String,
    pub version: String,
    pub repository_url: String,
    pub source_revision: String,
    pub license_spdx: String,
    pub relationship: String,
    pub artifacts: Vec<ManagedRuntimeComponentArtifact>,
    #[serde(default)]
    pub source_archive: Option<ManagedRuntimeSourceArchive>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedMachineImage {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedTarget {
    pub operating_system: ManagedOperatingSystem,
    pub architecture: ManagedArchitecture,
    pub provider: ManagedMachineProvider,
    pub machine_image: ManagedMachineImage,
    #[serde(default)]
    pub prerequisite: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedMachineResources {
    pub cpus: u8,
    pub memory_mb: u32,
    pub disk_size_gb: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeManifest {
    pub schema_version: String,
    pub bundle_id: String,
    pub runtime_version: String,
    pub driver_path: String,
    pub files: Vec<ManagedRuntimeFile>,
    pub components: Vec<ManagedRuntimeComponent>,
    pub targets: Vec<ManagedTarget>,
    pub resources: ManagedMachineResources,
    pub source: ManagedRuntimeSource,
}

#[derive(Debug, Clone)]
pub struct LoadedManagedRuntimeManifest {
    manifest: ManagedRuntimeManifest,
    encoded: Arc<[u8]>,
    sha256: String,
}

impl LoadedManagedRuntimeManifest {
    pub fn parse(bytes: &[u8]) -> AppResult<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(AppError::Runtime(
                "managed runtime manifest is empty or oversized".into(),
            ));
        }
        let manifest: ManagedRuntimeManifest = serde_json::from_slice(bytes).map_err(|error| {
            AppError::Runtime(format!("managed runtime manifest is malformed: {error}"))
        })?;
        validate_manifest(&manifest)?;
        Ok(Self {
            manifest,
            encoded: Arc::from(bytes),
            sha256: sha256_bytes(bytes),
        })
    }

    pub fn read(path: &Path) -> AppResult<Self> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AppError::NotAvailable(format!(
                "managed runtime release manifest is unavailable: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_MANIFEST_BYTES
        {
            return Err(AppError::NotAuthorized(
                "managed runtime release manifest must be a bounded regular file".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        Self::parse(&bytes)
    }

    pub fn manifest(&self) -> &ManagedRuntimeManifest {
        &self.manifest
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    fn target(&self) -> AppResult<&ManagedTarget> {
        let operating_system = ManagedOperatingSystem::current().ok_or_else(|| {
            AppError::NotAvailable("managed runtime does not support this operating system".into())
        })?;
        let architecture = ManagedArchitecture::current().ok_or_else(|| {
            AppError::NotAvailable("managed runtime does not support this CPU architecture".into())
        })?;
        self.manifest
            .targets
            .iter()
            .find(|target| {
                target.operating_system == operating_system && target.architecture == architecture
            })
            .ok_or_else(|| {
                AppError::NotAvailable(format!(
                    "managed runtime release has no payload for {} {}",
                    operating_system.key(),
                    architecture.key()
                ))
            })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimePhase {
    NotInstalled,
    Installed,
    Stopped,
    Starting,
    Running,
    Corrupt,
    Unsupported,
}

impl ManagedRuntimePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::Installed => "installed",
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Corrupt => "corrupt",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedRuntimeStatus {
    pub provider: String,
    pub phase: ManagedRuntimePhase,
    pub available: bool,
    pub runtime_version: String,
    pub manifest_sha256: String,
    pub machine_image_sha256: Option<String>,
    pub operating_system: Option<ManagedOperatingSystem>,
    pub architecture: Option<ManagedArchitecture>,
    pub machine_provider: Option<ManagedMachineProvider>,
    pub prerequisite: Option<String>,
    pub detail: String,
}

/// Observable lifecycle of one first-run managed-runtime setup attempt.
///
/// This is deliberately separate from [`ManagedRuntimeStatus`]: runtime status
/// describes durable machine truth, while setup status describes the one
/// currently active (or most recently finished) setup operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimeSetupPhase {
    Idle,
    Install,
    Prerequisite,
    Download,
    Init,
    Start,
    Verify,
    Completed,
    Failed,
    Cancelled,
}

/// Stable setup failure categories for UI localization and automation.
///
/// These values deliberately describe only conclusions the product can prove
/// from read-only prerequisite checks. They never imply that the product
/// enabled a Windows feature or elevated itself.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManagedRuntimeSetupFailureReason {
    #[serde(rename = "windows_wsl_not_installed")]
    WslNotInstalled,
    #[serde(rename = "windows_wsl_optional_feature_disabled")]
    WslOptionalFeatureDisabled,
    #[serde(rename = "windows_wsl_update_required")]
    WslUpdateRequired,
    #[serde(rename = "windows_restart_required")]
    RestartRequired,
    #[serde(rename = "windows_wsl_command_failed")]
    WslCommandFailed,
}

/// Stable next actions paired with [`ManagedRuntimeSetupFailureReason`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimeSetupNextAction {
    InstallWsl,
    EnableWslOptionalFeatures,
    UpdateWsl,
    RestartWindows,
    RetryWslCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedRuntimeSetupStatus {
    pub phase: ManagedRuntimeSetupPhase,
    pub active: bool,
    pub cancel_requested: bool,
    pub received_bytes: u64,
    pub total_bytes: Option<u64>,
    /// Percentage derived from the exact byte counters. It is `None` before
    /// the locked image size is known and always lies in `0..=100`.
    pub progress_percent: Option<f64>,
    /// Existing verified regular-file bytes reused by this setup attempt.
    pub resumed_from_bytes: u64,
    pub can_cancel: bool,
    pub can_retry: bool,
    /// Machine-readable failure category. `None` outside a failed setup.
    pub failure_reason: Option<ManagedRuntimeSetupFailureReason>,
    /// Machine-readable user action. `None` outside a failed setup.
    pub next_action: Option<ManagedRuntimeSetupNextAction>,
    pub detail: String,
}

impl Default for ManagedRuntimeSetupStatus {
    fn default() -> Self {
        Self {
            phase: ManagedRuntimeSetupPhase::Idle,
            active: false,
            cancel_requested: false,
            received_bytes: 0,
            total_bytes: None,
            progress_percent: None,
            resumed_from_bytes: 0,
            can_cancel: false,
            can_retry: true,
            failure_reason: None,
            next_action: None,
            detail: "managed runtime setup has not started".into(),
        }
    }
}

/// Process-local coordinator for desktop setup. Its mutex is held only for
/// small status mutations; cancellation uses an atomic flag so a second Tauri
/// command can interrupt the bounded download loop without waiting on runtime
/// lifecycle locks.
#[derive(Debug, Default)]
pub struct ManagedRuntimeSetupController {
    status: Mutex<ManagedRuntimeSetupStatus>,
    cancel_requested: AtomicBool,
}

impl ManagedRuntimeSetupController {
    pub fn status(&self) -> AppResult<ManagedRuntimeSetupStatus> {
        self.status
            .lock()
            .map(|status| public_managed_runtime_setup_status(status.clone()))
            .map_err(|_| {
                AppError::Internal("managed runtime setup status lock was poisoned".into())
            })
    }

    pub fn begin(&self) -> AppResult<()> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        if status.active {
            return Err(AppError::InvalidRequest(
                "managed runtime setup is already active".into(),
            ));
        }
        self.cancel_requested.store(false, Ordering::Release);
        *status = ManagedRuntimeSetupStatus {
            phase: ManagedRuntimeSetupPhase::Install,
            active: true,
            cancel_requested: false,
            received_bytes: 0,
            total_bytes: None,
            progress_percent: None,
            resumed_from_bytes: 0,
            can_cancel: true,
            can_retry: false,
            failure_reason: None,
            next_action: None,
            detail: "installing and verifying the release-managed runtime payload".into(),
        };
        Ok(())
    }

    pub fn request_cancel(&self) -> AppResult<ManagedRuntimeSetupStatus> {
        self.cancel_requested.store(true, Ordering::Release);
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        if status.active {
            status.cancel_requested = true;
            status.detail =
                "cancellation requested; downloaded partial bytes will be retained for resume"
                    .into();
        } else {
            // A stale cancel must never poison the next setup attempt.
            self.cancel_requested.store(false, Ordering::Release);
        }
        Ok(public_managed_runtime_setup_status(status.clone()))
    }

    fn set_phase(
        &self,
        phase: ManagedRuntimeSetupPhase,
        detail: impl Into<String>,
    ) -> AppResult<()> {
        self.check_cancelled()?;
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        status.phase = phase;
        status.detail = detail.into();
        drop(status);
        self.check_cancelled()
    }

    fn report_download(&self, received: u64, total: u64, resumed_from: u64) -> AppResult<()> {
        if received > total {
            return Err(AppError::Runtime(
                "managed runtime download progress exceeded its locked size".into(),
            ));
        }
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        status.phase = ManagedRuntimeSetupPhase::Download;
        status.received_bytes = received;
        status.total_bytes = Some(total);
        status.progress_percent = Some(if total == 0 {
            100.0
        } else {
            received as f64 * 100.0 / total as f64
        });
        status.resumed_from_bytes = resumed_from;
        status.detail = if resumed_from > 0 {
            format!("resuming managed runtime image download at {received} of {total} bytes")
        } else {
            format!("downloading managed runtime image: {received} of {total} bytes")
        };
        drop(status);
        self.check_cancelled()
    }

    fn check_cancelled(&self) -> AppResult<()> {
        if self.cancel_requested.load(Ordering::Acquire) {
            return Err(setup_cancelled_error());
        }
        Ok(())
    }

    fn finish_completed(&self, detail: impl Into<String>) -> AppResult<()> {
        self.finish(ManagedRuntimeSetupPhase::Completed, detail.into())
    }

    fn finish_failed(&self, detail: impl Into<String>) -> AppResult<()> {
        self.finish(ManagedRuntimeSetupPhase::Failed, detail.into())
    }

    fn record_failure(
        &self,
        reason: ManagedRuntimeSetupFailureReason,
        action: ManagedRuntimeSetupNextAction,
        detail: impl Into<String>,
    ) -> AppResult<()> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        status.failure_reason = Some(reason);
        status.next_action = Some(action);
        status.detail = detail.into();
        Ok(())
    }

    fn finish_cancelled(&self) -> AppResult<()> {
        self.finish(
            ManagedRuntimeSetupPhase::Cancelled,
            "managed runtime setup was cancelled; partial download retained for retry".into(),
        )
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn finish_worker_failure(&self, detail: impl Into<String>) -> AppResult<()> {
        self.finish_failed(detail)
    }

    fn finish(&self, phase: ManagedRuntimeSetupPhase, detail: String) -> AppResult<()> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        status.phase = phase;
        status.active = false;
        status.cancel_requested = false;
        status.can_cancel = false;
        status.can_retry = phase != ManagedRuntimeSetupPhase::Completed;
        if phase != ManagedRuntimeSetupPhase::Failed {
            status.failure_reason = None;
            status.next_action = None;
        }
        if phase != ManagedRuntimeSetupPhase::Failed || status.failure_reason.is_none() {
            status.detail = detail;
        }
        self.cancel_requested.store(false, Ordering::Release);
        Ok(())
    }
}

/// Keeps the serialized/Tauri status contract internally consistent while a
/// worker is unwinding a classified failure. `record_failure` intentionally
/// stores the recovery pair before returning its error so `finish_failed` can
/// preserve it, but a concurrent poll must not observe that pair while the
/// public phase is still `prerequisite` (or while cancellation wins the race).
fn public_managed_runtime_setup_status(
    mut status: ManagedRuntimeSetupStatus,
) -> ManagedRuntimeSetupStatus {
    let has_complete_failed_recovery = status.phase == ManagedRuntimeSetupPhase::Failed
        && status.failure_reason.is_some()
        && status.next_action.is_some();
    if !has_complete_failed_recovery {
        status.failure_reason = None;
        status.next_action = None;
    }
    status
}

fn setup_cancelled_error() -> AppError {
    AppError::InvalidRequest(
        "managed runtime setup was cancelled; partial download was retained for resume".into(),
    )
}

#[derive(Debug, Clone)]
pub struct ManagedRuntimeCommand {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    working_directory: PathBuf,
    runtime_version: String,
    manifest_sha256: String,
    machine_image_sha256: String,
}

impl ManagedRuntimeCommand {
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    pub fn environment(&self) -> &BTreeMap<OsString, OsString> {
        &self.environment
    }

    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    pub fn runtime_version(&self) -> &str {
        &self.runtime_version
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn machine_image_sha256(&self) -> &str {
        &self.machine_image_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedStopMode {
    OnlyIfIdle,
    Force,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedUninstallOptions {
    pub stop_mode: ManagedStopMode,
    pub remove_machine_image_cache: bool,
}

impl Default for ManagedUninstallOptions {
    fn default() -> Self {
        Self {
            stop_mode: ManagedStopMode::OnlyIfIdle,
            remove_machine_image_cache: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedRuntimeUpdateResult {
    pub status: ManagedRuntimeStatus,
    pub superseded_installations: Vec<String>,
}

#[derive(Debug)]
struct ManagedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedCommandOperation {
    MachineInitialization,
    MachineInventory,
    MachineStart,
    MachineStop,
    MachineRemoval,
    WslDistributionInventory,
    WslDistributionRemoval,
    ActiveContainerInventory,
    VersionPreflight,
}

impl ManagedCommandOperation {
    fn label(self) -> &'static str {
        match self {
            Self::MachineInitialization => "managed runtime machine initialization",
            Self::MachineInventory => "managed runtime machine inventory",
            Self::MachineStart => "managed runtime machine start",
            Self::MachineStop => "managed runtime machine stop",
            Self::MachineRemoval => "managed runtime machine removal",
            Self::WslDistributionInventory => "managed Windows WSL distribution inventory",
            Self::WslDistributionRemoval => "managed Windows WSL distribution removal",
            Self::ActiveContainerInventory => "managed runtime active-container inventory",
            Self::VersionPreflight => "managed runtime version preflight",
        }
    }
}

trait ManagedCommandRunner: Send + Sync {
    fn output(
        &self,
        command: &ManagedRuntimeCommand,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<ManagedCommandOutput>;
}

#[derive(Debug, Default)]
struct DirectManagedCommandRunner;

const MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

impl ManagedCommandRunner for DirectManagedCommandRunner {
    fn output(
        &self,
        command: &ManagedRuntimeCommand,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<ManagedCommandOutput> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed runtime command deadline exceeded the platform range",
            )
        })?;
        let mut process = Command::new(&command.binary);
        process
            .args(args)
            .env_clear()
            .envs(command.environment.iter())
            .current_dir(&command.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut process_tree = ManagedCommandProcessTree::prepare(&mut process)?;
        let mut child = process.spawn()?;
        if let Err(error) = process_tree.attach(&child) {
            return Err(managed_command_error_with_cleanup(
                error,
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        if Instant::now() >= deadline {
            return Err(managed_command_error_with_cleanup(
                managed_command_deadline_error(),
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        if let Err(error) = process_tree.start(&child) {
            return Err(managed_command_error_with_cleanup(
                error,
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        if Instant::now() >= deadline {
            return Err(managed_command_error_with_cleanup(
                managed_command_deadline_error(),
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("managed runtime stdout pipe was unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("managed runtime stderr pipe was unavailable"))?;
        let captured = Arc::new(AtomicU64::new(0));
        let oversized = Arc::new(AtomicBool::new(false));
        let mut stdout_capture = spawn_bounded_capture(
            stdout,
            captured.clone(),
            oversized.clone(),
            MAX_COMMAND_OUTPUT_BYTES,
        );
        let mut stderr_capture = spawn_bounded_capture(
            stderr,
            captured,
            oversized.clone(),
            MAX_COMMAND_OUTPUT_BYTES,
        );

        let mut terminated = false;
        let process_result = loop {
            if oversized.load(Ordering::Acquire) {
                terminated = true;
                break Err(managed_command_error_with_cleanup(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "managed runtime command output exceeded its aggregate limit",
                    ),
                    process_tree.terminate_and_wait(&mut child),
                ));
            }
            if Instant::now() >= deadline {
                terminated = true;
                break Err(managed_command_error_with_cleanup(
                    managed_command_deadline_error(),
                    process_tree.terminate_and_wait(&mut child),
                ));
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if Instant::now() >= deadline {
                        terminated = true;
                        break Err(managed_command_error_with_cleanup(
                            managed_command_deadline_error(),
                            process_tree.terminate_and_wait(&mut child),
                        ));
                    }
                    if !status.success() {
                        terminated = true;
                        if let Err(error) = process_tree.terminate_and_wait(&mut child) {
                            break Err(io::Error::new(
                                error.kind(),
                                format!(
                                    "managed runtime command exited unsuccessfully and its process tree could not be cleaned up: {error}"
                                ),
                            ));
                        }
                    }
                    break Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    terminated = true;
                    break Err(managed_command_error_with_cleanup(
                        error,
                        process_tree.terminate_and_wait(&mut child),
                    ));
                }
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(25)),
            );
        };
        let drain_deadline = if terminated {
            Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT
        } else {
            deadline
        };
        let capture_result = finish_managed_command_captures(
            &mut stdout_capture,
            &mut stderr_capture,
            drain_deadline,
            &mut terminated,
            oversized.as_ref(),
            &process_tree,
            &mut child,
        );
        if oversized.load(Ordering::Acquire) {
            let mut error = if terminated {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "managed runtime command output exceeded its aggregate limit",
                )
            } else {
                managed_command_error_with_cleanup(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "managed runtime command output exceeded its aggregate limit",
                    ),
                    process_tree.terminate_and_wait(&mut child),
                )
            };
            if let Err(process_error) = &process_result {
                error = io::Error::new(
                    error.kind(),
                    format!("{error}; command completion diagnostic: {process_error}"),
                );
            }
            if let Err(capture_error) = &capture_result {
                error = io::Error::new(
                    error.kind(),
                    format!("{error}; output-capture diagnostic: {capture_error}"),
                );
            }
            return Err(error);
        }
        let (status, stdout, stderr) = match (process_result, capture_result) {
            (Err(process_error), Err(capture_error)) => {
                return Err(io::Error::new(
                    process_error.kind(),
                    format!(
                        "{process_error}; managed runtime output capture also failed: {capture_error}"
                    ),
                ));
            }
            (Err(process_error), Ok(_)) => return Err(process_error),
            (Ok(_), Err(capture_error)) => return Err(capture_error),
            (Ok(status), Ok((stdout, stderr))) => (status, stdout, stderr),
        };
        if status.success()
            && let Err(error) = process_tree.preserve_descendants()
        {
            return Err(managed_command_error_with_cleanup(
                error,
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        Ok(ManagedCommandOutput {
            status,
            stdout,
            stderr,
        })
    }
}

fn managed_command_deadline_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "managed runtime command exceeded its deadline",
    )
}

fn managed_command_error_with_cleanup(primary: io::Error, cleanup: io::Result<()>) -> io::Error {
    managed_command_error_with_optional_cleanup(primary, cleanup.err())
}

fn managed_command_error_with_optional_cleanup(
    primary: io::Error,
    cleanup: Option<io::Error>,
) -> io::Error {
    match cleanup {
        Some(cleanup) => io::Error::new(
            primary.kind(),
            format!("{primary}; managed runtime process-tree cleanup also failed: {cleanup}"),
        ),
        None => primary,
    }
}

struct ManagedMemoryCapture {
    result: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ManagedMemoryCapture {
    #[cfg(all(test, unix))]
    fn finish_by(&mut self, deadline: Instant) -> io::Result<Vec<u8>> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.result.recv_timeout(remaining) {
            Ok(result) => self.finish_received(result),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "managed runtime output pipes did not close before the bounded drain deadline",
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => self.finish_disconnected(),
        }
    }

    fn try_finish(&mut self) -> Option<io::Result<Vec<u8>>> {
        match self.result.try_recv() {
            Ok(result) => Some(self.finish_received(result)),
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(self.finish_disconnected()),
        }
    }

    fn finish_received(&mut self, result: io::Result<Vec<u8>>) -> io::Result<Vec<u8>> {
        let worker = self.worker.take().ok_or_else(|| {
            io::Error::other("managed runtime output capture worker was already consumed")
        })?;
        match worker.join() {
            Ok(()) => result,
            Err(_) => match result {
                Ok(_) => Err(io::Error::other(
                    "managed runtime output capture thread failed",
                )),
                Err(error) => Err(io::Error::new(
                    error.kind(),
                    format!("{error}; managed runtime output capture thread also failed"),
                )),
            },
        }
    }

    fn finish_disconnected(&mut self) -> io::Result<Vec<u8>> {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        Err(io::Error::other(
            "managed runtime output capture thread failed",
        ))
    }
}

fn record_managed_capture_error(primary: &mut Option<io::Error>, stream: &str, error: io::Error) {
    let error = io::Error::new(
        error.kind(),
        format!("managed runtime {stream} capture failed: {error}"),
    );
    *primary = Some(match primary.take() {
        Some(primary) => io::Error::new(
            primary.kind(),
            format!("{primary}; additional capture failure: {error}"),
        ),
        None => error,
    });
}

#[allow(clippy::too_many_arguments)]
fn finish_managed_command_captures(
    stdout_capture: &mut ManagedMemoryCapture,
    stderr_capture: &mut ManagedMemoryCapture,
    initial_deadline: Instant,
    process_tree_terminated: &mut bool,
    oversized: &AtomicBool,
    process_tree: &ManagedCommandProcessTree,
    child: &mut Child,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut stdout = None;
    let mut stderr = None;
    let mut stdout_complete = false;
    let mut stderr_complete = false;
    let mut primary_error = None;
    let mut drain_deadline = initial_deadline;
    let mut post_kill = *process_tree_terminated;

    loop {
        let mut stdout_failed = false;
        if !stdout_complete && let Some(result) = stdout_capture.try_finish() {
            stdout_complete = true;
            match result {
                Ok(output) => stdout = Some(output),
                Err(error) => {
                    record_managed_capture_error(&mut primary_error, "stdout", error);
                    stdout_failed = true;
                }
            }
        }
        if stdout_failed && !post_kill {
            let cleanup = process_tree.terminate_and_wait(child);
            *process_tree_terminated = true;
            post_kill = true;
            drain_deadline = Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT;
            if let Some(error) = primary_error.take() {
                primary_error = Some(managed_command_error_with_cleanup(error, cleanup));
            }
        }

        let mut stderr_failed = false;
        if !stderr_complete && let Some(result) = stderr_capture.try_finish() {
            stderr_complete = true;
            match result {
                Ok(output) => stderr = Some(output),
                Err(error) => {
                    record_managed_capture_error(&mut primary_error, "stderr", error);
                    stderr_failed = true;
                }
            }
        }
        if stderr_failed && !post_kill {
            let cleanup = process_tree.terminate_and_wait(child);
            *process_tree_terminated = true;
            post_kill = true;
            drain_deadline = Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT;
            if let Some(error) = primary_error.take() {
                primary_error = Some(managed_command_error_with_cleanup(error, cleanup));
            }
        }

        if oversized.load(Ordering::Acquire) && !post_kill {
            if let Err(error) = process_tree.terminate_and_wait(child) {
                record_managed_capture_error(&mut primary_error, "output-limit cleanup", error);
            }
            *process_tree_terminated = true;
            post_kill = true;
            drain_deadline = Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT;
        }

        if stdout_complete && stderr_complete {
            break;
        }

        let now = Instant::now();
        if now >= drain_deadline {
            let timeout = || {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed runtime output pipes did not close before the bounded drain deadline",
                )
            };
            if !post_kill {
                if !stdout_complete {
                    record_managed_capture_error(&mut primary_error, "stdout", timeout());
                }
                if !stderr_complete {
                    record_managed_capture_error(&mut primary_error, "stderr", timeout());
                }
                let cleanup = process_tree.terminate_and_wait(child);
                *process_tree_terminated = true;
                post_kill = true;
                drain_deadline = Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT;
                if let Some(error) = primary_error.take() {
                    primary_error = Some(managed_command_error_with_cleanup(error, cleanup));
                }
                continue;
            }
            if !stdout_complete {
                record_managed_capture_error(
                    &mut primary_error,
                    "stdout post-termination drain",
                    timeout(),
                );
            }
            if !stderr_complete {
                record_managed_capture_error(
                    &mut primary_error,
                    "stderr post-termination drain",
                    timeout(),
                );
            }
            break;
        }
        thread::sleep(
            drain_deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(5)),
        );
    }

    match primary_error {
        Some(error) => Err(error),
        None => Ok((
            stdout.ok_or_else(|| io::Error::other("managed runtime stdout capture was empty"))?,
            stderr.ok_or_else(|| io::Error::other("managed runtime stderr capture was empty"))?,
        )),
    }
}

fn spawn_bounded_capture<R>(
    mut reader: R,
    captured: Arc<AtomicU64>,
    oversized: Arc<AtomicBool>,
    maximum: u64,
) -> ManagedMemoryCapture
where
    R: Read + Send + 'static,
{
    let (sender, result) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0_u8; 16 * 1024];
        let capture = (|| {
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let previous = captured.fetch_add(read as u64, Ordering::AcqRel);
                let remaining = maximum.saturating_sub(previous) as usize;
                output.extend_from_slice(&buffer[..read.min(remaining)]);
                if read > remaining {
                    oversized.store(true, Ordering::Release);
                }
            }
            Ok(output)
        })();
        let _ = sender.send(capture);
    });
    ManagedMemoryCapture {
        result,
        worker: Some(worker),
    }
}

struct ManagedCommandProcessTree {
    #[cfg(unix)]
    process_group: Option<i32>,
    #[cfg(windows)]
    job: std::os::windows::io::OwnedHandle,
    preserved: bool,
}

impl ManagedCommandProcessTree {
    fn prepare(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
            Ok(Self {
                process_group: None,
                preserved: false,
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };
            use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

            command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
            let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if raw_job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = unsafe { OwnedHandle::from_raw_handle(raw_job.cast()) };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = unsafe {
                SetInformationJobObject(
                    std::os::windows::io::AsRawHandle::as_raw_handle(&job).cast(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::addr_of!(limits).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                job,
                preserved: false,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = command;
            Ok(Self { preserved: false })
        }
    }

    fn attach(&mut self, child: &Child) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.process_group = Some(i32::try_from(child.id()).map_err(|_| {
                io::Error::other("managed runtime child process ID exceeded the platform range")
            })?);
            Ok(())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            let assigned = unsafe {
                AssignProcessToJobObject(
                    self.job.as_raw_handle().cast(),
                    child.as_raw_handle().cast(),
                )
            };
            if assigned == 0 {
                let error = io::Error::last_os_error();
                Err(io::Error::new(
                    error.kind(),
                    format!(
                        "managed runtime child could not join its containment job, possibly because of an incompatible outer job: {error}"
                    ),
                ))
            } else {
                Ok(())
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Ok(())
        }
    }

    fn start(&self, child: &Child) -> io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
            use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            };
            use windows_sys::Win32::System::Threading::{
                OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
            };

            let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if raw_snapshot == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let snapshot = unsafe { OwnedHandle::from_raw_handle(raw_snapshot.cast()) };
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..THREADENTRY32::default()
            };
            if unsafe { Thread32First(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut primary_thread = None;
            loop {
                if entry.th32OwnerProcessID == child.id() {
                    if primary_thread.replace(entry.th32ThreadID).is_some() {
                        return Err(io::Error::other(
                            "managed runtime suspended child had more than one initial thread",
                        ));
                    }
                }
                if unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                        break;
                    }
                    return Err(error);
                }
            }
            let primary_thread = primary_thread.ok_or_else(|| {
                io::Error::other("managed runtime suspended child primary thread was unavailable")
            })?;
            let raw_thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, primary_thread) };
            if raw_thread.is_null() {
                return Err(io::Error::last_os_error());
            }
            let thread = unsafe { OwnedHandle::from_raw_handle(raw_thread.cast()) };
            let previous_suspend_count = unsafe { ResumeThread(thread.as_raw_handle().cast()) };
            if previous_suspend_count == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            if previous_suspend_count != 1 {
                return Err(io::Error::other(format!(
                    "managed runtime child had unexpected suspend count {previous_suspend_count}"
                )));
            }
        }
        #[cfg(not(windows))]
        let _ = child;
        Ok(())
    }

    fn terminate_and_wait(&self, child: &mut Child) -> io::Result<()> {
        let mut cleanup_errors = Vec::new();
        let mut cleanup_error_kind = None;
        #[cfg(unix)]
        if let Some(process_group) = self.process_group
            && unsafe { libc::kill(-process_group, libc::SIGKILL) } != 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                cleanup_error_kind.get_or_insert(error.kind());
                cleanup_errors.push(format!("process-group termination failed: {error}"));
            }
        }
        #[cfg(windows)]
        if unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(
                std::os::windows::io::AsRawHandle::as_raw_handle(&self.job).cast(),
                1,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            cleanup_error_kind.get_or_insert(error.kind());
            cleanup_errors.push(format!("containment-job termination failed: {error}"));
        }
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = child.kill() {
                    cleanup_error_kind.get_or_insert(error.kind());
                    cleanup_errors.push(format!("direct-child termination failed: {error}"));
                }
            }
            Err(error) => {
                cleanup_error_kind.get_or_insert(error.kind());
                cleanup_errors.push(format!("direct-child status check failed: {error}"));
                if let Err(error) = child.kill() {
                    cleanup_error_kind.get_or_insert(error.kind());
                    cleanup_errors.push(format!("direct-child termination failed: {error}"));
                }
            }
        }
        if let Err(error) = child.wait() {
            cleanup_error_kind.get_or_insert(error.kind());
            cleanup_errors.push(format!("direct-child wait failed: {error}"));
        }
        match cleanup_error_kind {
            Some(kind) => Err(io::Error::new(kind, cleanup_errors.join("; "))),
            None => Ok(()),
        }
    }

    fn preserve_descendants(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::JobObjects::{
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };
            let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            let configured = unsafe {
                SetInformationJobObject(
                    std::os::windows::io::AsRawHandle::as_raw_handle(&self.job).cast(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::addr_of!(limits).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.preserved = true;
        Ok(())
    }
}

impl Drop for ManagedCommandProcessTree {
    fn drop(&mut self) {
        #[cfg(unix)]
        if !self.preserved
            && let Some(process_group) = self.process_group
        {
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
        }
    }
}

trait ManagedArtifactDownloader: Send + Sync {
    fn acquire(
        &self,
        image: &ManagedMachineImage,
        destination: &Path,
        progress: &mut dyn FnMut(u64, u64, u64) -> AppResult<()>,
    ) -> AppResult<()>;
}

#[derive(Debug, Default)]
struct HttpsManagedArtifactDownloader;

impl HttpsManagedArtifactDownloader {
    fn new() -> AppResult<Self> {
        Ok(Self)
    }

    fn client() -> AppResult<Client> {
        Client::builder()
            .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
            .timeout(DOWNLOAD_TOTAL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.error("too many managed runtime artifact redirects");
                }
                if attempt.url().scheme() != "https" || !allowed_download_host(attempt.url()) {
                    return attempt.error("managed runtime artifact redirect was not approved");
                }
                attempt.follow()
            }))
            .user_agent(concat!("ai-security-scanner/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                AppError::Runtime(format!(
                    "managed runtime HTTPS client could not be initialized: {error}"
                ))
            })
    }

    fn response(client: &Client, image: &ManagedMachineImage, offset: u64) -> AppResult<Response> {
        let mut request = client.get(&image.url).header(ACCEPT_ENCODING, "identity");
        if offset > 0 {
            request = request.header(RANGE, format!("bytes={offset}-"));
        }
        let response = request.send().map_err(|error| {
            AppError::Runtime(format!("managed runtime image download failed: {error}"))
        })?;
        if !response.status().is_success() {
            return Err(AppError::Runtime(format!(
                "managed runtime image server returned HTTP {}",
                response.status()
            )));
        }
        Ok(response)
    }
}

impl ManagedArtifactDownloader for HttpsManagedArtifactDownloader {
    fn acquire(
        &self,
        image: &ManagedMachineImage,
        destination: &Path,
        progress: &mut dyn FnMut(u64, u64, u64) -> AppResult<()>,
    ) -> AppResult<()> {
        let mut existing = regular_file_length_or_zero(destination)?;
        if existing > image.size_bytes {
            return Err(AppError::NotAuthorized(
                "partial managed runtime image exceeds its locked size".into(),
            ));
        }
        if existing == image.size_bytes {
            if verify_file_hash_size(
                destination,
                image.size_bytes,
                &image.sha256,
                "completed managed runtime partial image",
            )
            .is_ok()
            {
                progress(existing, image.size_bytes, existing)?;
                return Ok(());
            }
            // A complete-length prefix with the wrong digest can never be
            // resumed safely. Truncate only this exact private partial and
            // reacquire the locked object from byte zero.
            let mut file = open_private_download_file(destination, false)?;
            file.flush()?;
            file.sync_all()?;
            existing = 0;
        }
        progress(existing, image.size_bytes, existing)?;
        // reqwest's blocking client owns a small internal async runtime. Keep
        // that runtime scoped to this inherently blocking operation so merely
        // opening or inspecting a manager is safe in an async application.
        let client = Self::client()?;
        let mut response = Self::response(&client, image, existing)?;
        let resumed = existing > 0 && response.status() == reqwest::StatusCode::PARTIAL_CONTENT;
        if resumed {
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            validate_resume_content_range(content_range, existing, image.size_bytes)?;
        }

        let mut file = open_private_download_file(destination, resumed)?;
        let mut written = if resumed { existing } else { 0 };
        let resumed_from = if resumed { existing } else { 0 };
        if !resumed {
            // A server may legally ignore Range and return the full object. The
            // partial is then truncated and the observable counters restart at
            // zero instead of pretending old bytes were reused.
            progress(0, image.size_bytes, 0)?;
        }
        written = write_download_body(
            &mut response,
            &mut file,
            written,
            image.size_bytes,
            resumed_from,
            progress,
        )?;
        if written != image.size_bytes {
            return Err(AppError::Runtime(format!(
                "managed runtime image is incomplete: received {written} of {} bytes",
                image.size_bytes
            )));
        }
        Ok(())
    }
}

fn validate_resume_content_range(value: &str, offset: u64, total: u64) -> AppResult<()> {
    let invalid = || {
        AppError::Runtime(
            "managed runtime image server returned an invalid resume Content-Range".into(),
        )
    };
    let (unit, value) = value.split_once(' ').ok_or_else(invalid)?;
    let (range, declared_total) = value.split_once('/').ok_or_else(invalid)?;
    let (start, end) = range.split_once('-').ok_or_else(invalid)?;
    let start = start.parse::<u64>().map_err(|_| invalid())?;
    let end = end.parse::<u64>().map_err(|_| invalid())?;
    let declared_total = declared_total.parse::<u64>().map_err(|_| invalid())?;
    if unit != "bytes"
        || start != offset
        || end != total.checked_sub(1).ok_or_else(invalid)?
        || declared_total != total
    {
        return Err(invalid());
    }
    Ok(())
}

fn write_download_body<R: Read>(
    reader: &mut R,
    file: &mut File,
    mut written: u64,
    total: u64,
    resumed_from: u64,
    progress: &mut dyn FnMut(u64, u64, u64) -> AppResult<()>,
) -> AppResult<u64> {
    let mut buffer = [0_u8; DOWNLOAD_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            AppError::Runtime(format!(
                "managed runtime image download was interrupted: {error}"
            ))
        })?;
        if read == 0 {
            break;
        }
        written = written
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Runtime("managed runtime image size overflowed".into()))?;
        if written > total || written > MAX_MACHINE_IMAGE_BYTES {
            return Err(AppError::NotAuthorized(
                "managed runtime image exceeded its locked size".into(),
            ));
        }
        file.write_all(&buffer[..read])?;
        if let Err(error) = progress(written, total, resumed_from) {
            // Cancellation and observer failures retain a durable prefix; the
            // next setup sends Range from this exact regular-file length.
            file.flush()?;
            file.sync_all()?;
            return Err(error);
        }
    }
    file.flush()?;
    file.sync_all()?;
    Ok(written)
}

pub struct ManagedRuntimeManager {
    state_root: PathBuf,
    /// Keeps the verified state-root object open for the manager lifetime.
    /// Windows namespace replacement through an ancestor's FILE_DELETE_CHILD
    /// is prevented separately by validating the canonical ancestor ACL chain.
    #[cfg(windows)]
    _state_root_guard: File,
    resource_root: PathBuf,
    loaded: LoadedManagedRuntimeManifest,
    commands: Arc<dyn ManagedCommandRunner>,
    downloader: Arc<dyn ManagedArtifactDownloader>,
}

impl std::fmt::Debug for ManagedRuntimeManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedRuntimeManager")
            .field("state_root", &self.state_root)
            .field("resource_root", &self.resource_root)
            .field("manifest_sha256", &self.loaded.sha256)
            .finish_non_exhaustive()
    }
}

impl ManagedRuntimeManager {
    pub fn open(
        app_local_data_directory: &Path,
        resource_root: &Path,
        manifest_path: &Path,
    ) -> AppResult<Self> {
        let state_root = app_local_data_directory.join("managed-runtime");
        ensure_private_directory(app_local_data_directory)?;
        #[cfg(windows)]
        let (state_root, state_root_guard) =
            open_or_create_windows_managed_private_directory_guard(&state_root, true)
                .map_err(windows_managed_namespace_error)?;
        #[cfg(not(windows))]
        ensure_managed_private_directory(&state_root)?;
        let resource_root = canonical_real_directory(resource_root, "managed runtime resource")?;
        verify_regular_file(manifest_path, "managed runtime release manifest")?;
        let canonical_manifest = manifest_path.canonicalize()?;
        if canonical_manifest != resource_root.join("manifest.json") {
            return Err(AppError::NotAuthorized(
                "managed runtime manifest must be the release bundle's canonical manifest.json"
                    .into(),
            ));
        }
        let loaded = LoadedManagedRuntimeManifest::read(&canonical_manifest)?;
        let downloader = Arc::new(HttpsManagedArtifactDownloader::new()?);
        let manager = Self {
            state_root,
            #[cfg(windows)]
            _state_root_guard: state_root_guard,
            resource_root,
            loaded,
            commands: Arc::new(DirectManagedCommandRunner),
            downloader,
        };
        manager.verify_resource_bundle()?;
        Ok(manager)
    }

    /// Reconstructs a trusted command context using only a complete, previously
    /// installed private payload. This is used by the standalone CLI, which has
    /// no Tauri resource-directory API. Ambiguous installations fail closed
    /// unless the durable caller supplies the exact manifest SHA-256.
    pub fn open_installed(
        app_local_data_directory: &Path,
        expected_manifest_sha256: Option<&str>,
    ) -> AppResult<Self> {
        if let Some(expected) = expected_manifest_sha256 {
            validate_sha256(expected, "managed runtime expected manifest digest")?;
        }
        let state_root = app_local_data_directory.join("managed-runtime");
        #[cfg(windows)]
        let (state_root, state_root_guard) =
            open_or_create_windows_managed_private_directory_guard(&state_root, true)
                .map_err(windows_managed_namespace_error)?;
        #[cfg(not(windows))]
        ensure_managed_private_directory(&state_root)?;
        let versions_root =
            canonical_real_directory(&state_root.join("versions"), "managed runtime versions")?;
        let mut entries = fs::read_dir(&versions_root)?.collect::<Result<Vec<_>, _>>()?;
        if entries.len() > MAX_INSTALLED_VERSIONS {
            return Err(AppError::NotAuthorized(format!(
                "managed runtime has more than {MAX_INSTALLED_VERSIONS} installed payloads"
            )));
        }
        entries.sort_by_key(|entry| entry.file_name());
        let mut candidates = Vec::new();
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(AppError::NotAuthorized(
                    "managed runtime versions directory contains a symlink".into(),
                ));
            }
            if !metadata.is_dir() {
                continue;
            }
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".installing-")
            {
                continue;
            }
            let manifest_path = path.join("manifest.json");
            if !manifest_path.exists() {
                return Err(AppError::NotAuthorized(
                    "managed runtime installation has no release manifest".into(),
                ));
            }
            let loaded = LoadedManagedRuntimeManifest::read(&manifest_path)?;
            if expected_manifest_sha256.is_some_and(|expected| expected != loaded.sha256()) {
                continue;
            }
            let expected_name = installation_directory_name(&loaded);
            if entry.file_name() != OsStr::new(&expected_name) {
                return Err(AppError::NotAuthorized(
                    "managed runtime installation directory does not match its manifest identity"
                        .into(),
                ));
            }
            candidates.push((path, loaded));
        }
        if candidates.len() != 1 {
            return Err(AppError::NotAvailable(match expected_manifest_sha256 {
                Some(_) => {
                    "the exact managed runtime installation was not found in private state".into()
                }
                None => "managed runtime installation is absent or ambiguous; an exact manifest digest is required"
                    .into(),
            }));
        }
        let (resource_root, loaded) = candidates.pop().expect("one candidate");
        let downloader = Arc::new(HttpsManagedArtifactDownloader::new()?);
        let manager = Self {
            state_root,
            #[cfg(windows)]
            _state_root_guard: state_root_guard,
            resource_root: canonical_real_directory(
                &resource_root,
                "managed runtime installed resource",
            )?,
            loaded,
            commands: Arc::new(DirectManagedCommandRunner),
            downloader,
        };
        manager.verify_installation()?;
        Ok(manager)
    }

    #[cfg(test)]
    fn with_backends(
        state_root: PathBuf,
        resource_root: PathBuf,
        loaded: LoadedManagedRuntimeManifest,
        commands: Arc<dyn ManagedCommandRunner>,
        downloader: Arc<dyn ManagedArtifactDownloader>,
    ) -> AppResult<Self> {
        #[cfg(windows)]
        let (state_root, state_root_guard) =
            open_or_create_windows_managed_private_directory_guard(&state_root, true)
                .map_err(windows_managed_namespace_error)?;
        #[cfg(not(windows))]
        ensure_managed_private_directory(&state_root)?;
        let resource_root = canonical_real_directory(&resource_root, "managed runtime resource")?;
        let manager = Self {
            state_root,
            #[cfg(windows)]
            _state_root_guard: state_root_guard,
            resource_root,
            loaded,
            commands,
            downloader,
        };
        manager.verify_resource_bundle()?;
        Ok(manager)
    }

    pub fn manifest(&self) -> &ManagedRuntimeManifest {
        self.loaded.manifest()
    }

    pub fn manifest_sha256(&self) -> &str {
        self.loaded.sha256()
    }

    pub fn install(&self) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        self.install_locked()?;
        let target = self.loaded.target()?;
        Ok(self.status_value(
            ManagedRuntimePhase::Installed,
            false,
            Some(target),
            "managed runtime payload is installed and verified; start initializes its rootless machine"
                .into(),
        ))
    }

    /// Installs the release payload, acquires the exact VM image, initializes
    /// the rootless machine if necessary, and waits for a live server preflight.
    pub fn start(&self) -> AppResult<ManagedRuntimeCommand> {
        let _lock = self.lock()?;
        self.start_locked(None)
    }

    /// Runs the same lifecycle as [`Self::start`] while publishing a
    /// queryable, cancellable first-run setup state. Only one setup may be
    /// active for a controller at a time. Ordinary on-demand starts remain
    /// backward-compatible and do not overwrite setup history.
    pub fn setup(
        &self,
        controller: &ManagedRuntimeSetupController,
    ) -> AppResult<ManagedRuntimeStatus> {
        controller.begin()?;
        let result: AppResult<ManagedRuntimeStatus> = (|| {
            let _lock = self.lock()?;
            let command = self.start_locked(Some(controller))?;
            let target = self.loaded.target()?;
            let version = self.server_version(&command)?;
            Ok(self.status_value(
                ManagedRuntimePhase::Running,
                true,
                Some(target),
                format!("managed rootless Podman {version} is available"),
            ))
        })();

        match result {
            Ok(status) => {
                controller.finish_completed(format!(
                    "managed rootless runtime {} is running and verified",
                    status.runtime_version
                ))?;
                Ok(status)
            }
            Err(_error) if controller.cancel_requested.load(Ordering::Acquire) => {
                controller.finish_cancelled()?;
                Err(setup_cancelled_error())
            }
            Err(error) => {
                controller.finish_failed(error.to_string())?;
                Err(error)
            }
        }
    }

    fn start_locked(
        &self,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<ManagedRuntimeCommand> {
        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Install,
                "installing and verifying the release-managed runtime payload",
            )?;
        }
        self.install_locked()?;
        let target = self.loaded.target()?;
        let command = self.runtime_command(target)?;
        if target.operating_system == ManagedOperatingSystem::Windows {
            if let Some(setup) = setup {
                setup.set_phase(
                    ManagedRuntimeSetupPhase::Prerequisite,
                    "checking whether Windows has WSL 2 ready for the isolated scanner",
                )?;
            }
            self.require_windows_wsl_prerequisite_locked(target, &command, setup)?;
        }
        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Download,
                "preparing the exact release-locked managed runtime image download",
            )?;
        }
        let image = self.acquire_machine_image_locked(target, setup)?;
        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Init,
                "initializing the private rootless managed runtime machine",
            )?;
        }
        let machine_name = machine_name(target);
        let machines = self.list_machines(&command)?;
        if let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) {
            self.require_existing_machine_ssh_identity_locked()?;
            self.prove_machine(machine, target)?;
        } else {
            self.prepare_machine_ssh_identity_locked()?;
            self.initialize_machine(&command, target, &image, &machine_name)?;
        }
        if let Some(setup) = setup {
            setup.check_cancelled()?;
        }

        let machines = self.list_machines(&command)?;
        let machine = machines
            .iter()
            .find(|machine| machine.name == machine_name)
            .ok_or_else(|| {
                AppError::Runtime(
                    "managed runtime did not report the machine after initialization".into(),
                )
            })?;
        self.prove_machine(machine, target)?;
        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Start,
                "starting the private rootless managed runtime machine",
            )?;
        }
        if !machine.running {
            let output = self.run_command(
                ManagedCommandOperation::MachineStart,
                &command,
                ["machine", "start", "--quiet", machine_name.as_str()],
                MACHINE_START_TIMEOUT,
            )?;
            require_success("managed runtime machine start", &output)?;
        }
        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Verify,
                "verifying the managed runtime server is ready",
            )?;
        }
        self.wait_for_server(&command, MACHINE_START_TIMEOUT, setup)?;
        Ok(command)
    }

    /// Proves the Windows-owned WSL boundary before downloading the release
    /// machine image. The check is intentionally read-only: this product never
    /// requests elevation, installs WSL, enables optional features, or updates
    /// Windows on the user's behalf.
    fn require_windows_wsl_prerequisite_locked(
        &self,
        target: &ManagedTarget,
        managed_command: &ManagedRuntimeCommand,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<()> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(());
        }
        if target.provider != ManagedMachineProvider::Wsl {
            return Err(AppError::NotAuthorized(
                "managed Windows runtime target did not use the WSL provider".into(),
            ));
        }

        let directories = match windows_system_directories() {
            Ok(directories) => directories,
            Err(_) => {
                return fail_windows_wsl_prerequisite(
                    setup,
                    WindowsWslPrerequisiteFailure::command_failed(None),
                );
            }
        };
        let wsl_binary = directories.system32.join("wsl.exe");
        match fs::symlink_metadata(&wsl_binary) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return fail_windows_wsl_prerequisite(
                    setup,
                    WindowsWslPrerequisiteFailure::not_installed(None),
                );
            }
            Err(_) => {
                return fail_windows_wsl_prerequisite(
                    setup,
                    WindowsWslPrerequisiteFailure::command_failed(None),
                );
            }
            Ok(_) => {}
        }
        let command =
            match windows_wsl_inventory_command_with_directories(managed_command, &directories) {
                Ok(command) => command,
                Err(_) => {
                    return fail_windows_wsl_prerequisite(
                        setup,
                        WindowsWslPrerequisiteFailure::command_failed(None),
                    );
                }
            };

        // `--status` catches an unavailable WSL 2 kernel or Windows feature
        // before Podman can begin importing the release image. `--list
        // --quiet` exercises the same read-only inventory boundary Podman uses
        // during machine initialization, without requiring a pre-existing
        // distribution.
        for arguments in [
            &[OsString::from("--status")][..],
            &[OsString::from("--list"), OsString::from("--quiet")][..],
        ] {
            let output = match self.commands.output(&command, arguments, COMMAND_TIMEOUT) {
                Ok(output) => output,
                Err(_) => {
                    return fail_windows_wsl_prerequisite(
                        setup,
                        WindowsWslPrerequisiteFailure::command_failed(None),
                    );
                }
            };
            if !output.status.success() {
                return fail_windows_wsl_prerequisite(
                    setup,
                    classify_windows_wsl_prerequisite_failure(&output),
                );
            }
        }
        Ok(())
    }

    pub fn stop(&self, mode: ManagedStopMode) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        if !self.install_directory().exists() {
            return self.status_locked();
        }
        let target = self.loaded.target()?;
        let command = self.runtime_command(target)?;
        let machine_name = machine_name(target);
        let machines = self.list_machines(&command)?;
        let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) else {
            return Ok(self.status_value(
                ManagedRuntimePhase::Installed,
                false,
                Some(target),
                "managed runtime payload is verified; its rootless machine has not been initialized"
                    .into(),
            ));
        };
        self.prove_machine(machine, target)?;
        if machine.running {
            if mode == ManagedStopMode::OnlyIfIdle {
                let containers = self.running_containers(&command)?;
                if !containers.is_empty() {
                    return Err(AppError::InvalidRequest(format!(
                        "managed runtime still has {} running engine container(s); cancel the scan or request an explicit forced stop",
                        containers.len()
                    )));
                }
            }
            let output = self.run_command(
                ManagedCommandOperation::MachineStop,
                &command,
                ["machine", "stop", machine_name.as_str()],
                MACHINE_STOP_TIMEOUT,
            )?;
            require_success("managed runtime machine stop", &output)?;
            self.wait_for_machine_stopped(&command, &machine_name, MACHINE_STOP_TIMEOUT)?;
        }
        Ok(self.status_value(
            ManagedRuntimePhase::Stopped,
            false,
            Some(target),
            "managed runtime machine is stopped".into(),
        ))
    }

    pub fn uninstall(&self, options: ManagedUninstallOptions) -> AppResult<ManagedRuntimeStatus> {
        #[cfg(windows)]
        let (provider_delete_timeout, provider_delete_poll) = (
            WINDOWS_WSL_PROVIDER_DELETE_TIMEOUT,
            WINDOWS_WSL_PROVIDER_DELETE_POLL,
        );
        #[cfg(not(windows))]
        let (provider_delete_timeout, provider_delete_poll) = (Duration::ZERO, Duration::ZERO);
        self.uninstall_with_windows_provider_delete_timing(
            options,
            provider_delete_timeout,
            provider_delete_poll,
        )
    }

    fn uninstall_with_windows_provider_delete_timing(
        &self,
        options: ManagedUninstallOptions,
        provider_delete_timeout: Duration,
        provider_delete_poll: Duration,
    ) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        let target = self.loaded.target()?;
        let install = self.install_directory();
        let provider_home = self.provider_home();
        if private_entry_exists(&install)? || private_entry_exists(&provider_home)? {
            // Repair a corrupted release payload from the verified application
            // resources before invoking it for owned-machine cleanup. This also
            // lets a retry safely prove and remove provider state left by an
            // interrupted older uninstall after its client was deleted.
            self.install_locked()?;
            let command = self.runtime_command(target)?;
            let machine_name = machine_name(target);
            let machines = self.list_machines(&command)?;
            if machines.len() > 1 || machines.iter().any(|machine| machine.name != machine_name) {
                return Err(AppError::NotAuthorized(
                    "managed runtime release-private provider reported an unexpected machine; refusing to remove its state"
                        .into(),
                ));
            }
            if let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) {
                self.prove_machine(machine, target)?;
                if machine.running {
                    if options.stop_mode == ManagedStopMode::OnlyIfIdle
                        && !self.running_containers(&command)?.is_empty()
                    {
                        return Err(AppError::InvalidRequest(
                            "managed runtime has active engine containers; uninstall requires cancellation or an explicit forced stop"
                                .into(),
                        ));
                    }
                    let output = self.run_command(
                        ManagedCommandOperation::MachineStop,
                        &command,
                        ["machine", "stop", machine_name.as_str()],
                        MACHINE_STOP_TIMEOUT,
                    )?;
                    require_success("managed runtime machine stop", &output)?;
                }
                let output = self.run_command(
                    ManagedCommandOperation::MachineRemoval,
                    &command,
                    ["machine", "rm", "--force", machine_name.as_str()],
                    MACHINE_STOP_TIMEOUT,
                )?;
                require_success("managed runtime machine removal", &output)?;
            }
            self.prove_windows_wsl_distribution_absent_locked(target, &command, &machine_name)?;
            self.remove_temporary_command_state_after_machine_removal_locked(target)?;
            if private_entry_exists(&provider_home)? {
                remove_provider_home_after_machine_removal(
                    &provider_home,
                    &self.state_root.join("provider-home"),
                    provider_delete_timeout,
                    provider_delete_poll,
                )?;
            }
            remove_private_tree(&install, &self.versions_root())?;
        }
        if options.remove_machine_image_cache {
            let image = self.machine_image_path(target);
            if private_entry_exists(&image)? {
                remove_private_tree(&image, &self.image_cache_root())?;
            }
        }
        self.status_locked()
    }

    /// An application update installs and proves the new release payload first.
    /// Old verified payloads remain on disk as rollback material and are returned
    /// to the caller for an explicit later cleanup operation.
    pub fn update(&self) -> AppResult<ManagedRuntimeUpdateResult> {
        let _command = self.start()?;
        let current = self.install_directory();
        let mut superseded = Vec::new();
        if let Ok(entries) = fs::read_dir(self.versions_root()) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path != current && path.is_dir() {
                    superseded.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        superseded.sort();
        Ok(ManagedRuntimeUpdateResult {
            status: self.status()?,
            superseded_installations: superseded,
        })
    }

    pub fn status(&self) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        self.status_locked()
    }

    pub fn runtime_command_if_running(&self) -> AppResult<Option<ManagedRuntimeCommand>> {
        let _lock = self.lock()?;
        if !self.verify_installation().is_ok() {
            return Ok(None);
        }
        let target = self.loaded.target()?;
        let command = self.runtime_command(target)?;
        let machine_name = machine_name(target);
        let machines = self.list_machines(&command)?;
        let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) else {
            return Ok(None);
        };
        self.prove_machine(machine, target)?;
        if !machine.running || self.server_version(&command).is_err() {
            return Ok(None);
        }
        Ok(Some(command))
    }

    fn status_locked(&self) -> AppResult<ManagedRuntimeStatus> {
        let target = match self.loaded.target() {
            Ok(target) => target,
            Err(error) => {
                return Ok(self.status_value(
                    ManagedRuntimePhase::Unsupported,
                    false,
                    None,
                    error.to_string(),
                ));
            }
        };
        if !self.install_directory().exists() {
            return Ok(self.status_value(
                ManagedRuntimePhase::NotInstalled,
                false,
                Some(target),
                "managed runtime payload has not been installed for this application release"
                    .into(),
            ));
        }
        if let Err(error) = self.verify_installation() {
            return Ok(self.status_value(
                ManagedRuntimePhase::Corrupt,
                false,
                Some(target),
                error.to_string(),
            ));
        }
        let command = self.runtime_command(target)?;
        let machines = self.list_machines(&command)?;
        let machine_name = machine_name(target);
        let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) else {
            return Ok(self.status_value(
                ManagedRuntimePhase::Installed,
                false,
                Some(target),
                "managed runtime payload is verified; its rootless machine has not been initialized"
                    .into(),
            ));
        };
        if let Err(error) = self.prove_machine(machine, target) {
            return Ok(self.status_value(
                ManagedRuntimePhase::Corrupt,
                false,
                Some(target),
                error.to_string(),
            ));
        }
        if !machine.running {
            return Ok(self.status_value(
                ManagedRuntimePhase::Stopped,
                false,
                Some(target),
                "managed runtime machine is stopped".into(),
            ));
        }
        match self.server_version(&command) {
            Ok(version) => Ok(self.status_value(
                ManagedRuntimePhase::Running,
                true,
                Some(target),
                format!("managed rootless Podman {version} is available"),
            )),
            Err(error) => Ok(self.status_value(
                ManagedRuntimePhase::Starting,
                false,
                Some(target),
                error.to_string(),
            )),
        }
    }

    fn status_value(
        &self,
        phase: ManagedRuntimePhase,
        available: bool,
        target: Option<&ManagedTarget>,
        detail: String,
    ) -> ManagedRuntimeStatus {
        ManagedRuntimeStatus {
            provider: "managed_local".into(),
            phase,
            available,
            runtime_version: self.loaded.manifest.runtime_version.clone(),
            manifest_sha256: self.loaded.sha256.clone(),
            machine_image_sha256: target.map(|target| target.machine_image.sha256.clone()),
            operating_system: target
                .map(|target| target.operating_system)
                .or_else(ManagedOperatingSystem::current),
            architecture: target
                .map(|target| target.architecture)
                .or_else(ManagedArchitecture::current),
            machine_provider: target.map(|target| target.provider),
            prerequisite: target.and_then(|target| target.prerequisite.clone()),
            detail,
        }
    }

    fn install_locked(&self) -> AppResult<()> {
        self.loaded.target()?;
        self.verify_resource_bundle()?;
        ensure_managed_private_directory(&self.versions_root())?;
        let destination = self.install_directory();
        if private_entry_exists(&destination)? {
            match self.verify_installation() {
                Ok(()) => return Ok(()),
                Err(_) => {
                    remove_private_tree(&destination, &self.versions_root())?;
                    sync_directory(&self.versions_root())?;
                }
            }
        }
        let staging = self
            .versions_root()
            .join(format!(".installing-{}", Uuid::new_v4()));
        ensure_managed_private_directory(&staging)?;
        let result = (|| {
            for entry in &self.loaded.manifest.files {
                let source = safe_join(&self.resource_root, &entry.path)?;
                let target = safe_join(&staging, &entry.path)?;
                if let Some(parent) = target.parent() {
                    ensure_private_directory_tree(&staging, parent)?;
                }
                copy_verified_file(&source, &target, entry)?;
            }
            let manifest_path = staging.join("manifest.json");
            let mut manifest_file = create_private_file(&manifest_path)?;
            manifest_file.write_all(&self.loaded.encoded)?;
            manifest_file.flush()?;
            manifest_file.sync_all()?;
            // Windows refuses to rename a directory while a child file is
            // still open without delete sharing. Close the manifest handle
            // before the atomic directory commit on every platform.
            drop(manifest_file);
            fs::rename(&staging, &destination).map_err(|error| {
                AppError::Runtime(format!(
                    "managed runtime payload could not be committed atomically: {error}"
                ))
            })?;
            sync_directory(&self.versions_root())?;
            self.verify_installation()
        })();
        if result.is_err() && staging.exists() {
            let _ = remove_private_tree(&staging, &self.versions_root());
        }
        result
    }

    fn verify_resource_bundle(&self) -> AppResult<()> {
        verify_bundle_files(&self.resource_root, &self.loaded.manifest.files)
    }

    fn verify_installation(&self) -> AppResult<()> {
        let root = canonical_real_directory(&self.install_directory(), "managed runtime install")?;
        verify_installed_permissions(&root, &self.loaded.manifest.files)?;
        verify_bundle_files(&root, &self.loaded.manifest.files)?;
        let installed_manifest = LoadedManagedRuntimeManifest::read(&root.join("manifest.json"))?;
        if installed_manifest.sha256 != self.loaded.sha256 {
            return Err(AppError::NotAuthorized(
                "installed managed runtime manifest differs from this application release".into(),
            ));
        }
        Ok(())
    }

    fn runtime_command(&self, target: &ManagedTarget) -> AppResult<ManagedRuntimeCommand> {
        self.verify_installation()?;
        let install =
            canonical_real_directory(&self.install_directory(), "managed runtime install")?;
        let binary = safe_join(&install, &self.loaded.manifest.driver_path)?;
        verify_regular_file(&binary, "managed runtime driver")?;
        let provider_root = self.state_root.join("provider-home");
        ensure_managed_private_directory(&provider_root)?;
        let provider_home = self.provider_home();
        let config = provider_home.join("config");
        let data = provider_home.join("data");
        let cache = provider_home.join("cache");
        let persistent_run = provider_home.join("run");
        for directory in [&provider_home, &config, &data, &cache, &persistent_run] {
            ensure_managed_private_directory(directory)?;
        }
        let containers = config.join("containers");
        ensure_managed_private_directory(&containers)?;
        if target.operating_system == ManagedOperatingSystem::Windows {
            // Pinned Podman 5.8.2 GetMachineDirs uses os.MkdirAll before every
            // machine operation. On an administrator token, those defaulted
            // children can be owned by TokenOwner (Administrators), not
            // TokenUser. Pre-create the complete fixed WSL namespace with the
            // product's protected current-user-only descriptor before Podman
            // can create any ancestor with ambient Windows defaults. WSL's
            // service boundary additionally needs LocalSystem access only on
            // the distribution-storage subtree; keep every ancestor and the
            // adjacent image cache current-user-only.
            let provider = target.provider.argument();
            ensure_private_directory_tree(&persistent_run, &persistent_run.join("podman"))?;
            ensure_private_directory_tree(
                &config,
                &containers.join("podman").join("machine").join(provider),
            )?;
            ensure_private_directory_tree(
                &data,
                &data
                    .join("containers")
                    .join("podman")
                    .join("machine")
                    .join(provider)
                    .join("cache"),
            )?;
            let machine_provider_data = data
                .join("containers")
                .join("podman")
                .join("machine")
                .join(provider);
            ensure_managed_wsl_distribution_storage_directory(
                &machine_provider_data.join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY),
            )?;
        }
        self.write_containers_config(&containers.join("containers.conf"), &install, target)?;

        let storage_config = containers.join("storage.conf");
        if target.operating_system == ManagedOperatingSystem::Linux {
            // Pinned containers/storage otherwise derives RunRoot as
            // $XDG_RUNTIME_DIR/containers. Keep that durable storage state out
            // of Linux's socket-length-bounded short runtime while retaining
            // the conventional release-private rootless subpaths.
            let storage_runroot = persistent_run.join("containers");
            let storage_graphroot = data.join("containers").join("storage");
            ensure_private_directory_tree(&persistent_run, &storage_runroot)?;
            ensure_private_directory_tree(&data, &storage_graphroot)?;
            self.write_containers_storage_config(
                &storage_config,
                &storage_runroot,
                &storage_graphroot,
            )?;
        }

        let command_home = self.command_home(target)?;
        let runtime_directory = self.runtime_directory(target, &persistent_run)?;
        let windows_directories = if target.operating_system == ManagedOperatingSystem::Windows {
            Some(windows_system_directories()?)
        } else {
            None
        };
        let mut environment = BTreeMap::new();
        let home_value = command_home.as_os_str().to_owned();
        environment.insert(OsString::from("HOME"), home_value.clone());
        environment.insert(OsString::from("USERPROFILE"), home_value);
        environment.insert(
            OsString::from("XDG_CONFIG_HOME"),
            config.as_os_str().to_owned(),
        );
        environment.insert(OsString::from("XDG_DATA_HOME"), data.as_os_str().to_owned());
        environment.insert(
            OsString::from("XDG_CACHE_HOME"),
            cache.as_os_str().to_owned(),
        );
        environment.insert(
            OsString::from("XDG_RUNTIME_DIR"),
            runtime_directory.as_os_str().to_owned(),
        );
        environment.insert(OsString::from("APPDATA"), config.as_os_str().to_owned());
        environment.insert(OsString::from("LOCALAPPDATA"), data.as_os_str().to_owned());
        environment.insert(
            OsString::from("CONTAINERS_CONF"),
            containers.join("containers.conf").into_os_string(),
        );
        if target.operating_system == ManagedOperatingSystem::Linux {
            environment.insert(
                OsString::from("CONTAINERS_STORAGE_CONF"),
                storage_config.into_os_string(),
            );
        }
        environment.insert(
            OsString::from("CONTAINERS_MACHINE_PROVIDER"),
            OsString::from(target.provider.argument()),
        );
        environment.insert(
            OsString::from("PATH"),
            managed_path(&install, target, windows_directories.as_ref())?,
        );
        if let Some(directories) = &windows_directories {
            let system_root = directories.system_root.as_os_str().to_owned();
            environment.insert(OsString::from("SystemRoot"), system_root.clone());
            environment.insert(OsString::from("WINDIR"), system_root);
        }
        environment.insert(OsString::from("LANG"), OsString::from("C.UTF-8"));
        environment.insert(OsString::from("LC_ALL"), OsString::from("C.UTF-8"));
        apply_platform_command_environment(&mut environment, target.operating_system);

        Ok(ManagedRuntimeCommand {
            binary,
            environment,
            working_directory: command_home,
            runtime_version: self.loaded.manifest.runtime_version.clone(),
            manifest_sha256: self.loaded.sha256.clone(),
            machine_image_sha256: target.machine_image.sha256.clone(),
        })
    }

    fn prove_windows_wsl_distribution_absent_locked(
        &self,
        target: &ManagedTarget,
        managed_command: &ManagedRuntimeCommand,
        machine_name: &str,
    ) -> AppResult<()> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(());
        }
        if target.provider != ManagedMachineProvider::Wsl {
            return Err(AppError::NotAuthorized(
                "managed Windows runtime target did not use the WSL provider".into(),
            ));
        }
        let command = windows_wsl_inventory_command(managed_command)?;
        let output = self.run_command(
            ManagedCommandOperation::WslDistributionInventory,
            &command,
            ["--list", "--quiet"],
            COMMAND_TIMEOUT,
        )?;
        require_success("managed Windows WSL distribution inventory", &output)?;
        let expected = format!("podman-{machine_name}");
        let mut distributions = parse_windows_wsl_distribution_inventory(&output.stdout)?;
        if distributions
            .iter()
            .any(|distribution| distribution.eq_ignore_ascii_case(&expected))
        {
            let output = self.run_command(
                ManagedCommandOperation::WslDistributionRemoval,
                &command,
                ["--unregister", expected.as_str()],
                MACHINE_STOP_TIMEOUT,
            )?;
            require_success("managed Windows WSL distribution removal", &output)?;
            let output = self.run_command(
                ManagedCommandOperation::WslDistributionInventory,
                &command,
                ["--list", "--quiet"],
                COMMAND_TIMEOUT,
            )?;
            require_success("managed Windows WSL distribution inventory", &output)?;
            distributions = parse_windows_wsl_distribution_inventory(&output.stdout)?;
        }
        if distributions
            .iter()
            .any(|distribution| distribution.eq_ignore_ascii_case(&expected))
        {
            return Err(AppError::Runtime(
                "managed Windows WSL distribution remained registered after machine removal; retaining provider, installation, and image-cache state"
                    .into(),
            ));
        }
        Ok(())
    }

    fn provider_home(&self) -> PathBuf {
        self.state_root
            .join("provider-home")
            .join(&self.loaded.sha256[..16])
    }

    fn canonical_application_data_root(&self) -> AppResult<PathBuf> {
        let application_data = self.state_root.parent().ok_or_else(|| {
            AppError::Internal("managed runtime state has no application-data parent".into())
        })?;
        let application_data =
            canonical_real_directory(application_data, "managed runtime application data")?;
        let state_root = canonical_real_directory(&self.state_root, "managed runtime state")?;
        if state_root.parent() != Some(application_data.as_path()) {
            return Err(AppError::NotAuthorized(
                "managed runtime state escaped its canonical application-data root".into(),
            ));
        }
        Ok(application_data)
    }

    fn machine_application_data_volume(
        &self,
        target: &ManagedTarget,
    ) -> AppResult<Option<OsString>> {
        match target.operating_system {
            ManagedOperatingSystem::Linux => {
                let application_data = self.canonical_application_data_root()?;
                Ok(Some(linux_machine_volume_spec(&application_data)?))
            }
            // Podman's AppleHV defaults already project /Users, /private, and
            // /var/folders. WSL projects Windows drives below /mnt and ignores
            // podman-machine --volume. Neither platform accepts the Linux
            // source:target contract used by the QEMU provider here.
            ManagedOperatingSystem::Macos | ManagedOperatingSystem::Windows => Ok(None),
        }
    }

    fn runtime_directory(
        &self,
        target: &ManagedTarget,
        persistent_run: &Path,
    ) -> AppResult<PathBuf> {
        if target.operating_system != ManagedOperatingSystem::Linux {
            return Ok(persistent_run.to_path_buf());
        }
        #[cfg(unix)]
        {
            let runtime = self.linux_short_runtime_directory()?;
            let socket = linux_podman_gvproxy_socket_path(&runtime, &machine_name(target));
            use std::os::unix::ffi::OsStrExt;
            if socket.as_os_str().as_bytes().len() > PODMAN_LINUX_MAX_SOCKET_PATH_BYTES {
                return Err(AppError::NotAuthorized(
                    "managed runtime Linux gvproxy socket exceeds Podman's safe path budget".into(),
                ));
            }
            ensure_linux_short_runtime_directory_at(
                &runtime,
                Path::new(LINUX_SHORT_RUNTIME_BASE),
                effective_uid(),
            )?;
            Ok(runtime)
        }
        #[cfg(not(unix))]
        Err(AppError::NotAvailable(
            "managed runtime Linux command isolation is unavailable on this host".into(),
        ))
    }

    #[cfg(unix)]
    fn linux_short_runtime_directory(&self) -> AppResult<PathBuf> {
        let state_root = canonical_real_directory(&self.state_root, "managed runtime state")?;
        Ok(linux_short_runtime_path(
            Path::new(LINUX_SHORT_RUNTIME_BASE),
            &state_root,
            &self.loaded.sha256,
            effective_uid(),
        ))
    }

    fn command_home(&self, target: &ManagedTarget) -> AppResult<PathBuf> {
        if target.operating_system != ManagedOperatingSystem::Macos {
            return Ok(self.provider_home());
        }
        #[cfg(unix)]
        {
            let state_root = canonical_real_directory(&self.state_root, "managed runtime state")?;
            // SAFETY: geteuid has no preconditions and does not dereference memory.
            let effective_uid = unsafe { libc::geteuid() };
            let home = macos_short_home_path(
                Path::new(MACOS_SHORT_HOME_BASE),
                &state_root,
                &self.loaded.sha256,
                effective_uid,
            );
            ensure_macos_short_home_directory(&home, effective_uid)?;
            let socket_alias = macos_podman_ignition_socket_alias(&home, &machine_name(target));
            use std::os::unix::ffi::OsStrExt;
            if socket_alias.as_os_str().as_bytes().len() > PODMAN_MACOS_MAX_SOCKET_PATH_BYTES {
                return Err(AppError::NotAuthorized(
                    "managed runtime macOS socket alias exceeds Podman's safe path budget".into(),
                ));
            }
            Ok(home)
        }
        #[cfg(not(unix))]
        Err(AppError::NotAvailable(
            "managed runtime macOS command isolation is unavailable on this host".into(),
        ))
    }

    fn remove_temporary_command_state_after_machine_removal_locked(
        &self,
        target: &ManagedTarget,
    ) -> AppResult<()> {
        match target.operating_system {
            ManagedOperatingSystem::Linux => {
                #[cfg(unix)]
                {
                    let runtime = self.linux_short_runtime_directory()?;
                    remove_linux_short_runtime_directory_at(
                        &runtime,
                        Path::new(LINUX_SHORT_RUNTIME_BASE),
                        effective_uid(),
                    )
                }
                #[cfg(not(unix))]
                Err(AppError::NotAvailable(
                    "managed runtime Linux command cleanup is unavailable on this host".into(),
                ))
            }
            ManagedOperatingSystem::Macos => {
                #[cfg(unix)]
                {
                    let state_root =
                        canonical_real_directory(&self.state_root, "managed runtime state")?;
                    let effective_uid = effective_uid();
                    let home = macos_short_home_path(
                        Path::new(MACOS_SHORT_HOME_BASE),
                        &state_root,
                        &self.loaded.sha256,
                        effective_uid,
                    );
                    remove_macos_short_home_directory(&home, effective_uid, &machine_name(target))
                }
                #[cfg(not(unix))]
                Err(AppError::NotAvailable(
                    "managed runtime macOS command cleanup is unavailable on this host".into(),
                ))
            }
            ManagedOperatingSystem::Windows => Ok(()),
        }
    }

    /// Podman 5.8.2 resolves `define.DefaultIdentityName` beneath its XDG data
    /// home as `containers/podman/machine/machine`. The managed command sets
    /// that XDG root to this release-private provider home.
    fn machine_ssh_identity_path(&self) -> PathBuf {
        self.provider_home()
            .join("data")
            .join("containers")
            .join("podman")
            .join("machine")
            .join(PODMAN_MACHINE_IDENTITY_NAME)
    }

    /// Called only while the manager's lifecycle lock is held. An existing VM
    /// already trusts this exact public key, so a missing or inconsistent pair
    /// must fail closed instead of silently rotating the identity.
    fn require_existing_machine_ssh_identity_locked(&self) -> AppResult<()> {
        match inspect_managed_ssh_identity(&self.machine_ssh_identity_path())? {
            ManagedSshIdentityState::Valid => Ok(()),
            ManagedSshIdentityState::Absent | ManagedSshIdentityState::Invalid => {
                Err(AppError::NotAuthorized(
                    "managed runtime machine SSH identity is missing or inconsistent; refusing to rotate the key of an initialized machine"
                        .into(),
                ))
            }
        }
    }

    /// Called only while the manager's lifecycle lock is held and before
    /// `podman machine init`. Regular partial/corrupt files are safe to repair
    /// because no exact managed machine exists yet; non-regular entries always
    /// fail closed.
    fn prepare_machine_ssh_identity_locked(&self) -> AppResult<()> {
        let identity = self.machine_ssh_identity_path();
        let parent = identity.parent().ok_or_else(|| {
            AppError::Internal("managed runtime SSH identity has no parent".into())
        })?;
        let data_root = self.provider_home().join("data");
        ensure_private_directory_tree(&data_root, parent)?;
        cleanup_managed_ssh_identity_temporaries(&identity)?;

        match inspect_managed_ssh_identity(&identity)? {
            ManagedSshIdentityState::Valid => return Ok(()),
            ManagedSshIdentityState::Absent => {}
            ManagedSshIdentityState::Invalid => {
                remove_repairable_managed_ssh_identity(&identity)?;
            }
        }

        generate_managed_ssh_identity(&identity)?;
        match inspect_managed_ssh_identity(&identity)? {
            ManagedSshIdentityState::Valid => Ok(()),
            ManagedSshIdentityState::Absent | ManagedSshIdentityState::Invalid => {
                Err(AppError::Runtime(
                    "managed runtime SSH identity did not verify after atomic publication".into(),
                ))
            }
        }
    }

    fn write_containers_config(
        &self,
        path: &Path,
        install: &Path,
        target: &ManagedTarget,
    ) -> AppResult<()> {
        let helper = install.join("bin");
        let config = format!(
            "[engine]\nhelper_binaries_dir = [{}]\n\n[machine]\ncpus = {}\ndisk_size = {}\nmemory = {}\nprovider = {}\n",
            toml_string(&helper)?,
            self.loaded.manifest.resources.cpus,
            self.loaded.manifest.resources.disk_size_gb,
            self.loaded.manifest.resources.memory_mb,
            toml_scalar(target.provider.argument())
        );
        write_private_atomic(path, config.as_bytes())
    }

    fn write_containers_storage_config(
        &self,
        path: &Path,
        runroot: &Path,
        graphroot: &Path,
    ) -> AppResult<()> {
        let config = format!(
            "[storage]\nrunroot = {}\ngraphroot = {}\n",
            toml_string(runroot)?,
            toml_string(graphroot)?,
        );
        write_private_atomic(path, config.as_bytes())
    }

    fn acquire_machine_image_locked(
        &self,
        target: &ManagedTarget,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<PathBuf> {
        ensure_managed_private_directory(&self.image_cache_root())?;
        let destination = self.machine_image_path(target);
        if private_entry_exists(&destination)? {
            if verify_file_hash_size(
                &destination,
                target.machine_image.size_bytes,
                &target.machine_image.sha256,
                "cached managed runtime machine image",
            )
            .is_ok()
            {
                if let Some(setup) = setup {
                    setup.report_download(
                        target.machine_image.size_bytes,
                        target.machine_image.size_bytes,
                        target.machine_image.size_bytes,
                    )?;
                }
                return Ok(destination);
            }
            remove_private_tree(&destination, &self.image_cache_root())?;
            sync_directory(&self.image_cache_root())?;
        }
        let partial = destination.with_extension("download-part");
        match fs::symlink_metadata(&partial) {
            Ok(metadata) if !metadata.is_file() => {
                remove_private_tree(&partial, &self.image_cache_root())?;
                sync_directory(&self.image_cache_root())?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut verified = false;
        for attempt in 0..2 {
            let mut progress = |received, total, resumed_from| match setup {
                Some(setup) => setup.report_download(received, total, resumed_from),
                None => Ok(()),
            };
            self.downloader
                .acquire(&target.machine_image, &partial, &mut progress)?;
            match verify_file_hash_size(
                &partial,
                target.machine_image.size_bytes,
                &target.machine_image.sha256,
                "downloaded managed runtime machine image",
            ) {
                Ok(()) => {
                    verified = true;
                    break;
                }
                Err(_) if attempt == 0 => {
                    remove_private_tree(&partial, &self.image_cache_root())?;
                    sync_directory(&self.image_cache_root())?;
                    if let Some(setup) = setup {
                        setup.report_download(0, target.machine_image.size_bytes, 0)?;
                    }
                }
                Err(error) => return Err(error),
            }
        }
        if !verified {
            return Err(AppError::Runtime(
                "managed runtime machine image could not be verified".into(),
            ));
        }
        fs::rename(&partial, &destination).map_err(|error| {
            AppError::Runtime(format!(
                "managed runtime machine image could not be committed: {error}"
            ))
        })?;
        sync_directory(&self.image_cache_root())?;
        Ok(destination)
    }

    fn initialize_machine(
        &self,
        command: &ManagedRuntimeCommand,
        target: &ManagedTarget,
        image: &Path,
        machine_name: &str,
    ) -> AppResult<()> {
        let image = image.to_str().ok_or_else(|| {
            AppError::Runtime(
                "managed runtime machine image path is not representable for Podman".into(),
            )
        })?;
        let cpus = self.loaded.manifest.resources.cpus.to_string();
        let memory = self.loaded.manifest.resources.memory_mb.to_string();
        let disk = self.loaded.manifest.resources.disk_size_gb.to_string();
        let mut args = vec![
            OsString::from("machine"),
            OsString::from("init"),
            OsString::from("--cpus"),
            OsString::from(cpus),
            OsString::from("--memory"),
            OsString::from(memory),
            OsString::from("--disk-size"),
            OsString::from(disk),
            OsString::from("--rootful=false"),
        ];
        if let Some(volume) = self.machine_application_data_volume(target)? {
            args.extend([OsString::from("--volume"), volume]);
        }
        args.extend([
            OsString::from("--image"),
            OsString::from(image),
            OsString::from(machine_name),
        ]);
        let output = self.run_command_args(
            ManagedCommandOperation::MachineInitialization,
            command,
            &args,
            MACHINE_INIT_TIMEOUT,
        )?;
        require_success("managed runtime machine initialization", &output)
    }

    fn list_machines(&self, command: &ManagedRuntimeCommand) -> AppResult<Vec<MachineListEntry>> {
        let output = self.run_command(
            ManagedCommandOperation::MachineInventory,
            command,
            ["machine", "list", "--format", "json"],
            COMMAND_TIMEOUT,
        )?;
        require_success("managed runtime machine inventory", &output)?;
        serde_json::from_slice(&output.stdout).map_err(|error| {
            AppError::Runtime(format!(
                "managed runtime returned malformed machine inventory: {error}"
            ))
        })
    }

    fn prove_machine(&self, machine: &MachineListEntry, target: &ManagedTarget) -> AppResult<()> {
        let expected_name = machine_name(target);
        let expected_provider = target.provider.argument();
        if machine.name != expected_name
            || !machine.vm_type.eq_ignore_ascii_case(expected_provider)
            || machine.cpus != self.loaded.manifest.resources.cpus as u64
            || machine.memory != self.loaded.manifest.resources.memory_mb as u64 * 1024 * 1024
            || machine.disk_size
                != self.loaded.manifest.resources.disk_size_gb as u64 * 1024 * 1024 * 1024
        {
            return Err(AppError::NotAuthorized(format!(
                "managed runtime machine {expected_name} does not match the frozen provider and resource contract"
            )));
        }
        Ok(())
    }

    fn running_containers(&self, command: &ManagedRuntimeCommand) -> AppResult<Vec<String>> {
        let output = self.run_command(
            ManagedCommandOperation::ActiveContainerInventory,
            command,
            ["ps", "--format", "{{.Names}}"],
            COMMAND_TIMEOUT,
        )?;
        require_success("managed runtime active-container inventory", &output)?;
        let text = bounded_utf8(&output.stdout, "managed runtime container inventory")?;
        let mut containers = Vec::new();
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if line.len() > 256 || line.contains(['\0', '\r', '\n']) {
                return Err(AppError::Runtime(
                    "managed runtime returned an invalid container name".into(),
                ));
            }
            containers.push(line.to_owned());
        }
        Ok(containers)
    }

    fn wait_for_server(
        &self,
        command: &ManagedRuntimeCommand,
        timeout: Duration,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<()> {
        let deadline = Instant::now() + timeout;
        let mut last_error = None;
        while Instant::now() < deadline {
            if let Some(setup) = setup {
                setup.check_cancelled()?;
            }
            match self.server_version(command) {
                Ok(_) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
            thread::sleep(Duration::from_millis(250));
        }
        Err(last_error.unwrap_or_else(|| {
            AppError::Runtime("managed runtime server did not become ready".into())
        }))
    }

    fn server_version(&self, command: &ManagedRuntimeCommand) -> AppResult<String> {
        let output = self.run_command(
            ManagedCommandOperation::VersionPreflight,
            command,
            ["version", "--format", "{{.Server.Version}}"],
            COMMAND_TIMEOUT,
        )?;
        require_success("managed runtime version preflight", &output)?;
        let version = bounded_utf8(&output.stdout, "managed runtime version")?
            .trim()
            .to_owned();
        if version.is_empty() || version.len() > 128 || version.contains(['\0', '\r', '\n']) {
            return Err(AppError::Runtime(
                "managed runtime returned an invalid server version".into(),
            ));
        }
        Ok(version)
    }

    fn wait_for_machine_stopped(
        &self,
        command: &ManagedRuntimeCommand,
        machine_name: &str,
        timeout: Duration,
    ) -> AppResult<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let machines = self.list_machines(command)?;
            match machines.iter().find(|machine| machine.name == machine_name) {
                None => return Ok(()),
                Some(machine) if !machine.running => return Ok(()),
                Some(_) => thread::sleep(Duration::from_millis(250)),
            }
        }
        Err(AppError::Runtime(
            "managed runtime machine did not confirm it stopped before the deadline".into(),
        ))
    }

    fn run_command<const N: usize>(
        &self,
        operation: ManagedCommandOperation,
        command: &ManagedRuntimeCommand,
        args: [&str; N],
        timeout: Duration,
    ) -> AppResult<ManagedCommandOutput> {
        let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
        self.run_command_args(operation, command, &args, timeout)
    }

    fn run_command_args(
        &self,
        operation: ManagedCommandOperation,
        command: &ManagedRuntimeCommand,
        args: &[OsString],
        timeout: Duration,
    ) -> AppResult<ManagedCommandOutput> {
        self.commands
            .output(command, args, timeout)
            .map_err(|error| {
                AppError::Runtime(format!("{} could not execute: {error}", operation.label()))
            })
    }

    fn lock(&self) -> AppResult<ManagedRuntimeLock> {
        ensure_managed_private_directory(&self.state_root)?;
        ManagedRuntimeLock::acquire(&self.state_root.join("lifecycle.lock"))
    }

    fn versions_root(&self) -> PathBuf {
        self.state_root.join("versions")
    }

    fn install_directory(&self) -> PathBuf {
        self.versions_root()
            .join(installation_directory_name(&self.loaded))
    }

    fn image_cache_root(&self) -> PathBuf {
        self.state_root.join("machine-images")
    }

    fn machine_image_path(&self, target: &ManagedTarget) -> PathBuf {
        self.image_cache_root()
            .join(format!("{}.zst", target.machine_image.sha256))
    }
}

#[cfg(unix)]
fn verify_installed_permissions(root: &Path, files: &[ManagedRuntimeFile]) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let root_mode = fs::symlink_metadata(root)?.permissions().mode() & 0o777;
    if root_mode != 0o700 {
        return Err(AppError::NotAuthorized(
            "managed runtime install directory permissions are not private and traversable".into(),
        ));
    }
    let mut directories = BTreeSet::new();
    for entry in files {
        let path = safe_join(root, &entry.path)?;
        let expected_mode = if entry.executable { 0o500 } else { 0o400 };
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != expected_mode
        {
            return Err(AppError::NotAuthorized(format!(
                "managed runtime installed file permissions differ from the release contract: {}",
                entry.path
            )));
        }
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == root {
                break;
            }
            directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    for directory in directories {
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(AppError::NotAuthorized(
                "managed runtime install contains a non-private or non-traversable directory"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_installed_permissions(_root: &Path, _files: &[ManagedRuntimeFile]) -> AppResult<()> {
    Ok(())
}

struct ManagedRuntimeLock {
    file: File,
}

impl ManagedRuntimeLock {
    fn acquire(path: &Path) -> AppResult<Self> {
        let file = open_nofollow_lock_file(path)?;
        let contention = fs2::lock_contended_error();
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(Self { file }),
                Err(error)
                    if error.kind() == contention.kind()
                        && error.raw_os_error() == contention.raw_os_error() =>
                {
                    if Instant::now() >= deadline {
                        return Err(AppError::Runtime(
                            "managed runtime lifecycle is busy past its bounded deadline".into(),
                        ));
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(AppError::Runtime(format!(
                        "managed runtime lifecycle lock failed: {error}"
                    )));
                }
            }
        }
    }
}

impl Drop for ManagedRuntimeLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[derive(Debug, Deserialize)]
struct MachineListEntry {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "VMType")]
    vm_type: String,
    #[serde(rename = "CPUs")]
    cpus: u64,
    #[serde(
        rename = "Memory",
        deserialize_with = "deserialize_u64_string_or_number"
    )]
    memory: u64,
    #[serde(
        rename = "DiskSize",
        deserialize_with = "deserialize_u64_string_or_number"
    )]
    disk_size: u64,
}

fn deserialize_u64_string_or_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Number(u64),
        String(String),
    }
    match Value::deserialize(deserializer)? {
        Value::Number(value) => Ok(value),
        Value::String(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

fn validate_manifest(manifest: &ManagedRuntimeManifest) -> AppResult<()> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(AppError::Runtime(format!(
            "unsupported managed runtime manifest schema {}",
            manifest.schema_version
        )));
    }
    validate_identifier(&manifest.bundle_id, "managed runtime bundle id")?;
    validate_version(&manifest.runtime_version)?;
    validate_relative_path(&manifest.driver_path)?;
    if manifest.files.is_empty() || manifest.files.len() > MAX_BUNDLE_FILES {
        return Err(AppError::Runtime(
            "managed runtime manifest has an invalid file count".into(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut total = 0_u64;
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        if !paths.insert(file.path.as_str()) {
            return Err(AppError::Runtime(format!(
                "managed runtime manifest repeats file {}",
                file.path
            )));
        }
        if file.size_bytes == 0 || file.size_bytes > MAX_BUNDLE_FILE_BYTES {
            return Err(AppError::Runtime(format!(
                "managed runtime file {} has an invalid size",
                file.path
            )));
        }
        total = total
            .checked_add(file.size_bytes)
            .ok_or_else(|| AppError::Runtime("managed runtime bundle size overflowed".into()))?;
        validate_sha256(&file.sha256, "managed runtime file digest")?;
    }
    if total > MAX_BUNDLE_BYTES {
        return Err(AppError::Runtime(
            "managed runtime bundle exceeds its maximum size".into(),
        ));
    }
    let driver = manifest
        .files
        .iter()
        .find(|file| file.path == manifest.driver_path)
        .ok_or_else(|| {
            AppError::Runtime("managed runtime driver is absent from the file manifest".into())
        })?;
    if !driver.executable {
        return Err(AppError::Runtime(
            "managed runtime driver is not declared executable".into(),
        ));
    }
    if manifest.targets.is_empty() || manifest.targets.len() > 8 {
        return Err(AppError::Runtime(
            "managed runtime manifest has an invalid target count".into(),
        ));
    }
    let mut target_keys = BTreeSet::new();
    for target in &manifest.targets {
        if !target_keys.insert((target.operating_system, target.architecture)) {
            return Err(AppError::Runtime(
                "managed runtime manifest repeats an operating-system target".into(),
            ));
        }
        match (target.operating_system, target.provider) {
            (ManagedOperatingSystem::Macos, ManagedMachineProvider::Applehv)
            | (ManagedOperatingSystem::Linux, ManagedMachineProvider::Qemu)
            | (ManagedOperatingSystem::Windows, ManagedMachineProvider::Wsl) => {}
            _ => {
                return Err(AppError::Runtime(
                    "managed runtime target uses an unsupported provider combination".into(),
                ));
            }
        }
        validate_machine_image(&target.machine_image)?;
        if let Some(prerequisite) = &target.prerequisite {
            validate_bounded_text(prerequisite, 1024, "managed runtime prerequisite")?;
        }
    }
    if manifest.components.is_empty() || manifest.components.len() > 32 {
        return Err(AppError::Runtime(
            "managed runtime manifest has an invalid component inventory".into(),
        ));
    }
    let mut component_ids = BTreeSet::new();
    let mut covered_files = BTreeSet::new();
    let mut covered_downloads = BTreeSet::new();
    for component in &manifest.components {
        validate_identifier(&component.id, "managed runtime component id")?;
        if !component_ids.insert(component.id.as_str()) {
            return Err(AppError::Runtime(
                "managed runtime component inventory repeats an id".into(),
            ));
        }
        validate_bounded_text(&component.name, 128, "managed runtime component name")?;
        validate_version(&component.version)?;
        validate_https_url(&component.repository_url, false)?;
        validate_bounded_text(
            &component.source_revision,
            128,
            "managed runtime component source revision",
        )?;
        validate_bounded_text(
            &component.license_spdx,
            128,
            "managed runtime component license",
        )?;
        validate_bounded_text(
            &component.relationship,
            512,
            "managed runtime component relationship",
        )?;
        if component.artifacts.is_empty() || component.artifacts.len() > MAX_BUNDLE_FILES + 8 {
            return Err(AppError::Runtime(format!(
                "managed runtime component {} has an invalid artifact inventory",
                component.id
            )));
        }
        for artifact in &component.artifacts {
            validate_sha256(
                &artifact.sha256,
                "managed runtime component artifact digest",
            )?;
            if artifact.size_bytes == 0 || artifact.size_bytes > MAX_MACHINE_IMAGE_BYTES {
                return Err(AppError::Runtime(
                    "managed runtime component artifact has an invalid size".into(),
                ));
            }
            match artifact.delivery {
                ManagedRuntimeArtifactDelivery::BundledFile => {
                    validate_relative_path(&artifact.locator)?;
                    let file = manifest
                        .files
                        .iter()
                        .find(|file| file.path == artifact.locator)
                        .ok_or_else(|| {
                            AppError::Runtime(format!(
                                "component {} references an unknown bundled file {}",
                                component.id, artifact.locator
                            ))
                        })?;
                    if file.sha256 != artifact.sha256 || file.size_bytes != artifact.size_bytes {
                        return Err(AppError::Runtime(format!(
                            "component {} bundled-file identity does not match {}",
                            component.id, artifact.locator
                        )));
                    }
                    covered_files.insert(artifact.locator.as_str());
                }
                ManagedRuntimeArtifactDelivery::RuntimeDownload => {
                    validate_https_url(&artifact.locator, true)?;
                    let image = manifest
                        .targets
                        .iter()
                        .map(|target| &target.machine_image)
                        .find(|image| image.url == artifact.locator)
                        .ok_or_else(|| {
                            AppError::Runtime(format!(
                                "component {} references an unknown runtime download",
                                component.id
                            ))
                        })?;
                    if image.sha256 != artifact.sha256 || image.size_bytes != artifact.size_bytes {
                        return Err(AppError::Runtime(format!(
                            "component {} runtime-download identity does not match its target",
                            component.id
                        )));
                    }
                    covered_downloads.insert(artifact.locator.as_str());
                }
            }
        }
        if let Some(source) = &component.source_archive {
            validate_https_url(&source.url, false)?;
            validate_sha256(&source.sha256, "managed runtime component source digest")?;
            if source.size_bytes == 0 || source.size_bytes > MAX_MACHINE_IMAGE_BYTES {
                return Err(AppError::Runtime(
                    "managed runtime component source archive has an invalid size".into(),
                ));
            }
        }
    }
    if manifest
        .files
        .iter()
        .any(|file| !covered_files.contains(file.path.as_str()))
        || manifest
            .targets
            .iter()
            .any(|target| !covered_downloads.contains(target.machine_image.url.as_str()))
    {
        return Err(AppError::Runtime(
            "managed runtime component inventory does not cover every distributed file and runtime download"
                .into(),
        ));
    }
    if !(1..=32).contains(&manifest.resources.cpus)
        || !(2048..=65_536).contains(&manifest.resources.memory_mb)
        || !(20..=1024).contains(&manifest.resources.disk_size_gb)
    {
        return Err(AppError::Runtime(
            "managed runtime machine resources are outside supported bounds".into(),
        ));
    }
    validate_https_url(&manifest.source.repository_url, false)?;
    validate_bounded_text(
        &manifest.source.source_revision,
        128,
        "managed runtime source revision",
    )?;
    validate_bounded_text(
        &manifest.source.license_spdx,
        128,
        "managed runtime license",
    )?;
    Ok(())
}

fn validate_machine_image(image: &ManagedMachineImage) -> AppResult<()> {
    validate_https_url(&image.url, true)?;
    validate_sha256(&image.sha256, "managed runtime machine image digest")?;
    if image.size_bytes == 0 || image.size_bytes > MAX_MACHINE_IMAGE_BYTES {
        return Err(AppError::Runtime(
            "managed runtime machine image has an invalid locked size".into(),
        ));
    }
    Ok(())
}

fn validate_https_url(value: &str, download: bool) -> AppResult<()> {
    let url = Url::parse(value)
        .map_err(|_| AppError::Runtime("managed runtime URL is malformed".into()))?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || (download && !allowed_download_host(&url))
    {
        return Err(AppError::NotAuthorized(
            "managed runtime URL is not an approved credential-free HTTPS origin".into(),
        ));
    }
    Ok(())
}

fn allowed_download_host(url: &Url) -> bool {
    matches!(
        url.host_str()
            .map(|host| host.to_ascii_lowercase())
            .as_deref(),
        Some("github.com")
            | Some("objects.githubusercontent.com")
            | Some("release-assets.githubusercontent.com")
    )
}

fn validate_identifier(value: &str, label: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::Runtime(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_version(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
    {
        return Err(AppError::Runtime(
            "managed runtime version is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> AppResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::Runtime(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_bounded_text(value: &str, maximum: usize, label: &str) -> AppResult<()> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value.contains(['\0', '\r', '\n'])
        || value.chars().any(|character| character.is_control())
    {
        return Err(AppError::Runtime(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> AppResult<()> {
    if value.is_empty() || value.len() > 1024 || value.contains(['\\', '\0', '\r', '\n']) {
        return Err(AppError::Runtime(
            "managed runtime bundle path is invalid".into(),
        ));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AppError::Runtime(
            "managed runtime bundle path must remain relative".into(),
        ));
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> AppResult<PathBuf> {
    validate_relative_path(relative)?;
    Ok(root.join(relative))
}

fn verify_bundle_files(root: &Path, files: &[ManagedRuntimeFile]) -> AppResult<()> {
    let canonical_root = canonical_real_directory(root, "managed runtime bundle")?;
    for entry in files {
        let path = safe_join(&canonical_root, &entry.path)?;
        verify_file_hash_size(
            &path,
            entry.size_bytes,
            &entry.sha256,
            "managed runtime bundle file",
        )?;
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&canonical_root) {
            return Err(AppError::NotAuthorized(
                "managed runtime bundle file escaped its resource root".into(),
            ));
        }
    }
    Ok(())
}

fn copy_verified_file(
    source: &Path,
    destination: &Path,
    entry: &ManagedRuntimeFile,
) -> AppResult<()> {
    verify_regular_file(source, "managed runtime release file")?;
    let mut input = File::open(source)?;
    let mut output = create_private_file(destination)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Runtime("managed runtime file size overflowed".into()))?;
        if copied > entry.size_bytes {
            return Err(AppError::NotAuthorized(format!(
                "managed runtime file {} exceeded its locked size",
                entry.path
            )));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    output.flush()?;
    output.sync_all()?;
    let digest = hex::encode(hasher.finalize());
    if copied != entry.size_bytes || !digest.eq_ignore_ascii_case(&entry.sha256) {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime file {} failed its size or SHA-256 check",
            entry.path
        )));
    }
    // FILE_SHARE_NONE keeps a Windows private file unavailable while it is
    // populated. Close that handle before updating path-based attributes.
    drop(output);
    set_installed_permissions(destination, entry.executable)?;
    Ok(())
}

fn verify_file_hash_size(path: &Path, size: u64, digest: &str, label: &str) -> AppResult<()> {
    verify_regular_file(path, label)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.len() != size {
        return Err(AppError::NotAuthorized(format!(
            "{label} has a size that differs from the release manifest"
        )));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != size {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed while it was being opened"
        )));
    }
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Runtime(format!("{label} size overflowed while hashing")))?;
        if copied > size {
            return Err(AppError::NotAuthorized(format!(
                "{label} grew beyond its locked size while hashing"
            )));
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hex::encode(hasher.finalize());
    if copied != size || !actual.eq_ignore_ascii_case(digest) {
        return Err(AppError::NotAuthorized(format!(
            "{label} failed its SHA-256 check"
        )));
    }
    Ok(())
}

fn verify_regular_file(path: &Path, label: &str) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| AppError::NotAvailable(format!("{label} is unavailable: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::NotAuthorized(format!(
            "{label} must be a real regular file"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedSshIdentityState {
    Absent,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedSshIdentityFileState {
    Absent,
    Bounded(ManagedSshIdentityFileSnapshot),
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedSshIdentityFileKind {
    Private,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManagedSshIdentityFileSnapshot {
    size: u64,
    #[cfg(windows)]
    identity: WindowsFileIdentity,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsFileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsFileInformation {
    identity: WindowsFileIdentity,
    size: u64,
    number_of_links: u32,
    attributes: u32,
}

#[cfg(windows)]
struct WindowsCurrentUserSid {
    storage: Vec<u32>,
}

#[cfg(windows)]
impl WindowsCurrentUserSid {
    fn as_ptr(&self) -> windows_sys::Win32::Security::PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
struct WindowsLocalSystemSid {
    storage: Vec<u32>,
}

#[cfg(windows)]
impl WindowsLocalSystemSid {
    fn as_ptr(&self) -> windows_sys::Win32::Security::PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsManagedDirectoryAclPolicy {
    CurrentUserOnly,
    CurrentUserAndLocalSystem,
}

#[cfg(windows)]
struct WindowsCurrentUserOnlyAcl {
    raw: *mut windows_sys::Win32::Security::ACL,
}

#[cfg(windows)]
impl WindowsCurrentUserOnlyAcl {
    fn as_ptr(&self) -> *const windows_sys::Win32::Security::ACL {
        self.raw
    }
}

#[cfg(windows)]
impl Drop for WindowsCurrentUserOnlyAcl {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;

        // SAFETY: SetEntriesInAclW allocated this ACL with LocalAlloc.
        unsafe {
            LocalFree(self.raw.cast());
        }
    }
}

#[cfg(windows)]
fn windows_current_user_sid() -> io::Result<WindowsCurrentUserSid> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::Security::{
        CopySid, GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut raw_token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a process pseudo-handle and raw_token
    // points to writable storage for the newly opened token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a uniquely owned kernel handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

    let mut required = 0_u32;
    // SAFETY: the null/zero probe is the documented way to obtain the required
    // TOKEN_USER buffer size; required points to initialized writable storage.
    let probe = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut required,
        )
    };
    let probe_error = io::Error::last_os_error();
    if probe != 0
        || required < std::mem::size_of::<TOKEN_USER>() as u32
        || probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(if probe_error.raw_os_error().is_some() {
            probe_error
        } else {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an invalid current-user token size",
            )
        });
    }
    let mut token_information =
        vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: token_information is pointer-aligned and has at least required
    // writable bytes; the token handle remains valid for the call.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            token_information.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful TokenUser query initialized a TOKEN_USER at the
    // start of the suitably aligned buffer.
    let token_user = unsafe { &*token_information.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: the SID pointer belongs to the live token-information buffer.
    if token_user.User.Sid.is_null() || unsafe { IsValidSid(token_user.User.Sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid current-user SID",
        ));
    }
    // SAFETY: IsValidSid established that the SID pointer is valid.
    let sid_length = unsafe { GetLengthSid(token_user.User.Sid) };
    if sid_length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty current-user SID",
        ));
    }
    let mut storage = vec![0_u32; (sid_length as usize).div_ceil(std::mem::size_of::<u32>())];
    // SAFETY: storage is DWORD-aligned and contains at least sid_length bytes;
    // the source SID remains live in token_information for the call.
    if unsafe { CopySid(sid_length, storage.as_mut_ptr().cast(), token_user.User.Sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsCurrentUserSid { storage })
}

#[cfg(windows)]
fn windows_local_system_sid() -> io::Result<WindowsLocalSystemSid> {
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, IsValidSid, IsWellKnownSid, SECURITY_MAX_SID_SIZE, WinLocalSystemSid,
    };

    let mut storage =
        vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<u32>())];
    let mut length = u32::try_from(storage.len() * std::mem::size_of::<u32>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows SID buffer is too large",
        )
    })?;
    // SAFETY: storage is DWORD-aligned and exposes length writable bytes;
    // WinLocalSystemSid does not require a domain SID.
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sid = WindowsLocalSystemSid { storage };
    // SAFETY: CreateWellKnownSid initialized the SID in storage and storage
    // remains live for both validation calls.
    if length == 0
        || length as usize > sid.storage.len() * std::mem::size_of::<u32>()
        || unsafe { IsValidSid(sid.as_ptr()) } == 0
        || unsafe { IsWellKnownSid(sid.as_ptr(), WinLocalSystemSid) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid LocalSystem SID",
        ));
    }
    Ok(sid)
}

#[cfg(windows)]
fn windows_current_user_only_acl(
    user: &WindowsCurrentUserSid,
) -> io::Result<WindowsCurrentUserOnlyAcl> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, EqualSid,
        GetAce, GetAclInformation, GetLengthSid, IsValidAcl, IsValidSid, NO_INHERITANCE,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            // TRUSTEE_W reuses this field for a SID when TrusteeForm is
            // TRUSTEE_IS_SID; no UTF-16 string is read in that form.
            ptstrName: user.as_ptr().cast(),
        },
    };
    let mut raw = std::ptr::null_mut::<ACL>();
    // SAFETY: explicit is fully initialized, user remains live, and raw is
    // writable output storage. A null old ACL requests a fresh one-entry ACL.
    let status =
        unsafe { SetEntriesInAclW(1, &raw const explicit, std::ptr::null(), &raw mut raw) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a null current-user ACL",
        ));
    }
    let acl = WindowsCurrentUserOnlyAcl { raw };
    // Validate the provider-built ACL before it is ever attached to a security
    // descriptor. This distinguishes ACL construction from filesystem
    // inheritance behavior and keeps malformed policy from reaching CreateFileW.
    // SAFETY: acl owns the live SetEntriesInAclW allocation.
    if unsafe { IsValidAcl(acl.raw) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows built an invalid current-user ACL",
        ));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: acl is valid and information is writable storage of the declared size.
    if unsafe {
        GetAclInformation(
            acl.raw,
            (&raw mut information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if information.AceCount != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user ACL does not contain exactly one access rule",
        ));
    }
    let mut raw_ace = std::ptr::null_mut::<c_void>();
    // SAFETY: the valid ACL reports one ACE, so index zero exists.
    if unsafe { GetAce(acl.raw, 0, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetAce returned a pointer to at least an ACE_HEADER in the live ACL.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || header.AceFlags != 0
        || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user ACL contains an unexpected access rule",
        ));
    }
    // SAFETY: the ACE type and size establish its fixed ACCESS_ALLOWED_ACE prefix.
    let allowed = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let ace_sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
    // SAFETY: the fixed prefix is bounded by a valid ACL and user owns a valid SID.
    if allowed.Mask != FILE_ALL_ACCESS
        || unsafe { IsValidSid(ace_sid) } == 0
        || unsafe { EqualSid(ace_sid, user.as_ptr()) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user ACL was built for the wrong principal",
        ));
    }
    // SAFETY: both SIDs were validated above.
    let user_sid_length = unsafe { GetLengthSid(user.as_ptr()) } as usize;
    let expected_ace_size = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        .checked_sub(std::mem::size_of::<u32>())
        .and_then(|prefix| prefix.checked_add(user_sid_length))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Windows ACE size overflowed"))?;
    if usize::from(header.AceSize) != expected_ace_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user ACL contains a malformed SID boundary",
        ));
    }
    Ok(acl)
}

#[cfg(windows)]
fn windows_file_information(file: &File) -> io::Result<WindowsFileInformation> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a valid handle and information is a correctly sized,
    // writable BY_HANDLE_FILE_INFORMATION output buffer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsFileInformation {
        identity: WindowsFileIdentity {
            volume_serial_number: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        },
        size: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
        number_of_links: information.nNumberOfLinks,
        attributes: information.dwFileAttributes,
    })
}

#[cfg(windows)]
fn windows_owner_dacl_security_descriptor(file: &File) -> io::Result<Vec<usize>> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorLength, IsValidSecurityDescriptor,
        OWNER_SECURITY_INFORMATION,
    };

    struct LocalSecurityDescriptor(*mut c_void);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut raw_descriptor = std::ptr::null_mut();
    // SAFETY: file owns a live filesystem handle; all unused optional outputs
    // are null and raw_descriptor is writable output storage. GetSecurityInfo
    // returns the descriptor in LocalAlloc storage owned by this function.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            requested,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut raw_descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if raw_descriptor.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a null file security descriptor",
        ));
    }
    let descriptor_guard = LocalSecurityDescriptor(raw_descriptor);
    // SAFETY: a successful GetSecurityInfo returned this live descriptor.
    if unsafe { IsValidSecurityDescriptor(descriptor_guard.0) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid file security descriptor",
        ));
    }
    // SAFETY: IsValidSecurityDescriptor established a valid descriptor.
    let required = unsafe { GetSecurityDescriptorLength(descriptor_guard.0) } as usize;
    if required == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty file security descriptor",
        ));
    }
    let mut descriptor = vec![0_usize; required.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: descriptor is pointer-aligned and provides at least required
    // writable bytes; descriptor_guard owns that many readable source bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            descriptor_guard.0.cast::<u8>(),
            descriptor.as_mut_ptr().cast::<u8>(),
            required,
        );
    }
    Ok(descriptor)
}

#[cfg(windows)]
fn verify_windows_current_user_only_dacl(file: &File) -> io::Result<()> {
    verify_windows_current_user_only_dacl_with_ace_flags(file, 0)
}

#[cfg(windows)]
fn verify_windows_current_user_only_dacl_with_ace_flags(
    file: &File,
    expected_ace_flags: u8,
) -> io::Result<()> {
    verify_windows_managed_directory_dacl_with_ace_flags(
        file,
        expected_ace_flags,
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly,
    )
}

#[cfg(windows)]
fn verify_windows_wsl_distribution_storage_dacl_with_ace_flags(
    file: &File,
    expected_ace_flags: u8,
) -> io::Result<()> {
    verify_windows_managed_directory_dacl_with_ace_flags(
        file,
        expected_ace_flags,
        WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem,
    )
}

#[cfg(windows)]
fn verify_windows_managed_directory_dacl_with_ace_flags(
    file: &File,
    expected_ace_flags: u8,
    policy: WindowsManagedDirectoryAclPolicy,
) -> io::Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, EqualSid,
        GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidAcl, IsValidSid, PSID,
        SE_DACL_PROTECTED, SE_SELF_RELATIVE,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
    };

    let user = windows_current_user_sid()?;
    let local_system = if policy == WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem {
        let local_system = windows_local_system_sid()?;
        // SAFETY: both SID wrappers own valid, live SID storage.
        if unsafe { EqualSid(user.as_ptr(), local_system.as_ptr()) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed WSL storage cannot use LocalSystem as its interactive owner",
            ));
        }
        Some(local_system)
    } else {
        None
    };
    let mut descriptor = windows_owner_dacl_security_descriptor(file)?;
    let security_descriptor = descriptor.as_mut_ptr().cast::<c_void>();

    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: security_descriptor contains the valid descriptor returned by
    // GetKernelObjectSecurity and the output pointers are writable.
    if unsafe {
        GetSecurityDescriptorOwner(
            security_descriptor,
            &raw mut owner,
            &raw mut owner_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file has no Windows owner SID",
        ));
    }
    // SAFETY: owner points inside the live descriptor buffer.
    if unsafe { IsValidSid(owner) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file has an invalid Windows owner SID",
        ));
    }
    // SAFETY: owner and user are valid SIDs backed by live aligned storage.
    if unsafe { EqualSid(owner, user.as_ptr()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file owner is not the current Windows user",
        ));
    }
    // Product-created private entries always provide an explicit TokenUser
    // owner. Keep that provenance check separate from the actual SID check so
    // a default TokenOwner (commonly Administrators on hosted runners) cannot
    // be mistaken for an app-owned namespace.
    if owner_defaulted != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file owner was supplied by the Windows default mechanism",
        ));
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: security_descriptor is valid and both output pointers are writable.
    if unsafe {
        GetSecurityDescriptorControl(security_descriptor, &raw mut control, &raw mut revision)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if revision != SECURITY_DESCRIPTOR_REVISION
        || control & (SE_DACL_PROTECTED | SE_SELF_RELATIVE)
            != (SE_DACL_PROTECTED | SE_SELF_RELATIVE)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file DACL is not a protected self-relative revision-1 descriptor",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut::<ACL>();
    // SAFETY: security_descriptor is valid and all output pointers are writable.
    if unsafe {
        GetSecurityDescriptorDacl(
            security_descriptor,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a non-null DACL returned from the valid descriptor may be passed
    // to IsValidAcl.
    if dacl_present == 0
        || dacl_defaulted != 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file does not have an explicit valid DACL",
        ));
    }

    let mut acl_information = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid and acl_information is a correctly sized writable
    // ACL_SIZE_INFORMATION output buffer.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let expected_ace_count = match policy {
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly => 1,
        WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem => 2,
    };
    if acl_information.AceCount != expected_ace_count {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("file DACL must contain exactly {expected_ace_count} explicit access rule(s)"),
        ));
    }

    let mut saw_current_user = false;
    let mut saw_local_system = false;
    for ace_index in 0..acl_information.AceCount {
        let mut raw_ace = std::ptr::null_mut::<c_void>();
        // SAFETY: ace_index is bounded by the count reported by the valid DACL
        // and raw_ace is writable output storage.
        if unsafe { GetAce(dacl, ace_index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returned a pointer to at least an ACE_HEADER in the live DACL.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags != expected_ace_flags
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file DACL contains an unexpected access rule",
            ));
        }
        // SAFETY: the ACE type and minimum size establish the ACCESS_ALLOWED_ACE
        // fixed prefix, which is contained in the valid DACL.
        let allowed = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let ace_sid: PSID = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        // SAFETY: ace_sid points to the SID payload of a valid, sufficiently large ACE.
        if allowed.Mask != FILE_ALL_ACCESS || unsafe { IsValidSid(ace_sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file DACL does not grant only the expected private access",
            ));
        }
        // SAFETY: IsValidSid established that ace_sid is a valid SID.
        let sid_length = unsafe { GetLengthSid(ace_sid) } as usize;
        let expected_ace_size = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            .checked_sub(std::mem::size_of::<u32>())
            .and_then(|prefix| prefix.checked_add(sid_length))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Windows ACE size overflowed")
            })?;
        if usize::from(header.AceSize) != expected_ace_size {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file DACL contains a malformed SID boundary",
            ));
        }

        // SAFETY: ace_sid and the expected principal SIDs are valid and live.
        if unsafe { EqualSid(ace_sid, user.as_ptr()) } != 0 {
            if saw_current_user {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "file DACL contains a duplicate current-user access rule",
                ));
            }
            saw_current_user = true;
            continue;
        }
        let matches_local_system = local_system
            .as_ref()
            // SAFETY: both SIDs are valid and live for the comparison.
            .is_some_and(|system| unsafe { EqualSid(ace_sid, system.as_ptr()) } != 0);
        if matches_local_system {
            if saw_local_system {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "file DACL contains a duplicate LocalSystem access rule",
                ));
            }
            saw_local_system = true;
            continue;
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file DACL grants access to an unexpected Windows principal",
        ));
    }
    if !saw_current_user
        || (policy == WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem
            && !saw_local_system)
        || (policy == WindowsManagedDirectoryAclPolicy::CurrentUserOnly && saw_local_system)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file DACL does not contain the exact expected Windows principal set",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_managed_ssh_identity_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(windows)]
fn open_windows_managed_ssh_cleanup_file(path: &Path, delete_access: bool) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
    };

    let mut options = OpenOptions::new();
    let access = if delete_access {
        FILE_GENERIC_READ | DELETE
    } else {
        FILE_GENERIC_READ
    };
    // The staging handle denies new delete/write opens. The destination handle
    // shares delete so it remains compatible with the already-open staging
    // handle when both names refer to the same hard-linked file object.
    let sharing = if delete_access {
        FILE_SHARE_READ
    } else {
        FILE_SHARE_READ | FILE_SHARE_DELETE
    };
    options
        .read(true)
        .access_mode(access)
        .share_mode(sharing)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(windows)]
fn mark_windows_file_handle_for_deletion(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: file was opened through the exact staging name with DELETE
    // access; disposition is a fully initialized input buffer of the declared
    // size. Deletion is applied to that opened link when the handle closes.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::addr_of!(disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn mark_windows_managed_ssh_staging_handle_for_deletion(file: &File) -> AppResult<()> {
    mark_windows_file_handle_for_deletion(file)?;
    Ok(())
}

#[cfg(windows)]
fn windows_managed_ssh_identity_handle_information(
    file: &File,
    label: &str,
) -> AppResult<WindowsFileInformation> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let information = windows_file_information(file).map_err(|error| {
        AppError::NotAuthorized(format!("{label} could not be verified by handle: {error}"))
    })?;
    if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(AppError::NotAuthorized(format!(
            "{label} must be a real regular file"
        )));
    }
    Ok(information)
}

#[cfg(windows)]
fn verify_windows_managed_ssh_identity_handle(
    file: &File,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<ManagedSshIdentityFileSnapshot> {
    let information = windows_managed_ssh_identity_handle_information(file, label)?;
    if information.number_of_links != 1 {
        return Err(AppError::NotAuthorized(format!(
            "{label} must not be hard-linked"
        )));
    }
    if kind == ManagedSshIdentityFileKind::Private {
        verify_windows_current_user_only_dacl(file).map_err(|error| {
            AppError::NotAuthorized(format!(
                "{label} has unsafe Windows ownership or permissions: {error}"
            ))
        })?;
    }
    Ok(ManagedSshIdentityFileSnapshot {
        size: information.size,
        identity: information.identity,
    })
}

#[cfg(unix)]
fn managed_ssh_identity_mode_is_safe(kind: ManagedSshIdentityFileKind, mode: u32) -> bool {
    match kind {
        ManagedSshIdentityFileKind::Private => matches!(mode, 0o400 | 0o600),
        ManagedSshIdentityFileKind::Public => matches!(mode, 0o400 | 0o444 | 0o600 | 0o644),
    }
}

fn managed_ssh_public_key_path(private_key_path: &Path) -> PathBuf {
    let mut path = private_key_path.as_os_str().to_os_string();
    path.push(".pub");
    PathBuf::from(path)
}

fn managed_ssh_identity_temporary_paths(private_key_path: &Path) -> AppResult<(PathBuf, PathBuf)> {
    let parent = private_key_path
        .parent()
        .ok_or_else(|| AppError::Internal("managed runtime SSH identity has no parent".into()))?;
    Ok((
        parent.join(".machine.private-key-new"),
        parent.join(".machine.public-key-new"),
    ))
}

fn inspect_managed_ssh_identity_file(
    path: &Path,
    maximum: u64,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<ManagedSshIdentityFileState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AppError::NotAuthorized(format!(
                    "{label} must be a real regular file"
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                // SAFETY: geteuid has no preconditions and does not dereference memory.
                let effective_uid = unsafe { libc::geteuid() };
                if metadata.uid() != effective_uid || metadata.nlink() != 1 {
                    return Err(AppError::NotAuthorized(format!(
                        "{label} must be owned by the current user and must not be hard-linked"
                    )));
                }
                let mode = metadata.permissions().mode() & 0o777;
                if !managed_ssh_identity_mode_is_safe(kind, mode) {
                    return Err(AppError::NotAuthorized(format!(
                        "{label} has unsafe permissions"
                    )));
                }
            }
            #[cfg(windows)]
            let snapshot = {
                let file = open_windows_managed_ssh_identity_file(path).map_err(|error| {
                    AppError::NotAuthorized(format!(
                        "{label} could not be opened without following links: {error}"
                    ))
                })?;
                verify_windows_managed_ssh_identity_handle(&file, label, kind)?
            };
            #[cfg(not(windows))]
            let snapshot = ManagedSshIdentityFileSnapshot {
                size: metadata.len(),
            };
            if snapshot.size == 0 || snapshot.size > maximum {
                return Ok(ManagedSshIdentityFileState::Invalid);
            }
            Ok(ManagedSshIdentityFileState::Bounded(snapshot))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(ManagedSshIdentityFileState::Absent)
        }
        Err(error) => Err(error.into()),
    }
}

fn read_managed_ssh_identity_file(
    path: &Path,
    expected: ManagedSshIdentityFileSnapshot,
    maximum: u64,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<Zeroizing<Vec<u8>>> {
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    let mut file = open_windows_managed_ssh_identity_file(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "{label} could not be opened without following links: {error}"
        ))
    })?;
    #[cfg(not(windows))]
    let mut file = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "{label} could not be opened without following links: {error}"
        ))
    })?;
    let expected_size = expected.size;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() != expected_size
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed while it was being verified"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.nlink() != 1 {
            return Err(AppError::NotAuthorized(format!(
                "{label} ownership or link count changed while it was being verified"
            )));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if !managed_ssh_identity_mode_is_safe(kind, mode) {
            return Err(AppError::NotAuthorized(format!(
                "{label} permissions changed or are unsafe"
            )));
        }
    }
    #[cfg(windows)]
    let windows_before = {
        let snapshot = verify_windows_managed_ssh_identity_handle(&file, label, kind)?;
        if snapshot != expected {
            return Err(AppError::NotAuthorized(format!(
                "{label} changed while it was being verified"
            )));
        }
        snapshot
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_size || bytes.len() as u64 > maximum {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed while it was being read"
        )));
    }
    let after = file.metadata()?;
    if !after.is_file() || after.len() != expected_size || after.len() != metadata.len() {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed while it was being read"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        let mode = after.permissions().mode() & 0o777;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.uid() != effective_uid
            || after.nlink() != 1
            || !managed_ssh_identity_mode_is_safe(kind, mode)
        {
            return Err(AppError::NotAuthorized(format!(
                "{label} changed while it was being read"
            )));
        }
    }
    #[cfg(windows)]
    {
        let windows_after = verify_windows_managed_ssh_identity_handle(&file, label, kind)?;
        if windows_after != windows_before {
            return Err(AppError::NotAuthorized(format!(
                "{label} changed while it was being read"
            )));
        }
    }
    Ok(bytes)
}

fn inspect_managed_ssh_identity(private_key_path: &Path) -> AppResult<ManagedSshIdentityState> {
    let public_key_path = managed_ssh_public_key_path(private_key_path);
    let private_state = inspect_managed_ssh_identity_file(
        private_key_path,
        MAX_SSH_PRIVATE_KEY_BYTES,
        "managed runtime SSH private key",
        ManagedSshIdentityFileKind::Private,
    )?;
    let public_state = inspect_managed_ssh_identity_file(
        &public_key_path,
        MAX_SSH_PUBLIC_KEY_BYTES,
        "managed runtime SSH public key",
        ManagedSshIdentityFileKind::Public,
    )?;
    let (private_snapshot, public_snapshot) = match (private_state, public_state) {
        (ManagedSshIdentityFileState::Absent, ManagedSshIdentityFileState::Absent) => {
            return Ok(ManagedSshIdentityState::Absent);
        }
        (
            ManagedSshIdentityFileState::Bounded(private_snapshot),
            ManagedSshIdentityFileState::Bounded(public_snapshot),
        ) => (private_snapshot, public_snapshot),
        _ => return Ok(ManagedSshIdentityState::Invalid),
    };

    let private_bytes = read_managed_ssh_identity_file(
        private_key_path,
        private_snapshot,
        MAX_SSH_PRIVATE_KEY_BYTES,
        "managed runtime SSH private key",
        ManagedSshIdentityFileKind::Private,
    )?;
    let public_bytes = read_managed_ssh_identity_file(
        &public_key_path,
        public_snapshot,
        MAX_SSH_PUBLIC_KEY_BYTES,
        "managed runtime SSH public key",
        ManagedSshIdentityFileKind::Public,
    )?;
    let Ok(private_key) = PrivateKey::from_openssh(private_bytes.as_slice()) else {
        return Ok(ManagedSshIdentityState::Invalid);
    };
    let Ok(public_text) = std::str::from_utf8(public_bytes.as_slice()) else {
        return Ok(ManagedSshIdentityState::Invalid);
    };
    let Ok(public_key) = PublicKey::from_openssh(public_text) else {
        return Ok(ManagedSshIdentityState::Invalid);
    };
    if private_key.is_encrypted()
        || private_key.algorithm() != Algorithm::Ed25519
        || public_key.algorithm() != Algorithm::Ed25519
        || private_key.public_key().key_data() != public_key.key_data()
    {
        return Ok(ManagedSshIdentityState::Invalid);
    }
    Ok(ManagedSshIdentityState::Valid)
}

#[cfg(windows)]
fn remove_windows_verified_managed_ssh_identity_file_if_present(
    path: &Path,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    let file = match open_windows_managed_ssh_cleanup_file(path, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AppError::NotAuthorized(format!(
                "{label} could not be opened for verified cleanup: {error}"
            )));
        }
    };
    let information = windows_managed_ssh_identity_handle_information(&file, label)?;
    if information.number_of_links != 1 {
        return Err(AppError::NotAuthorized(format!(
            "{label} must not be hard-linked"
        )));
    }
    if kind == ManagedSshIdentityFileKind::Private {
        verify_windows_current_user_only_dacl(&file).map_err(|error| {
            AppError::NotAuthorized(format!(
                "{label} has unsafe Windows ownership or permissions: {error}"
            ))
        })?;
    }
    let before_delete = windows_file_information(&file)?;
    if before_delete != information {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed during verified cleanup"
        )));
    }
    mark_windows_managed_ssh_staging_handle_for_deletion(&file)?;
    drop(file);
    Ok(())
}

#[cfg(windows)]
fn cleanup_windows_managed_ssh_identity_staging_file(
    staging: &Path,
    destination: &Path,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    let staging_file = match open_windows_managed_ssh_cleanup_file(staging, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AppError::NotAuthorized(format!(
                "{label} could not be opened for verified cleanup: {error}"
            )));
        }
    };
    let staging_information =
        windows_managed_ssh_identity_handle_information(&staging_file, label)?;
    match staging_information.number_of_links {
        1 => {
            if kind == ManagedSshIdentityFileKind::Private {
                verify_windows_current_user_only_dacl(&staging_file).map_err(|error| {
                    AppError::NotAuthorized(format!(
                        "{label} has unsafe Windows ownership or permissions: {error}"
                    ))
                })?;
            }
            let before_delete = windows_file_information(&staging_file)?;
            if before_delete != staging_information {
                return Err(AppError::NotAuthorized(format!(
                    "{label} changed during verified cleanup"
                )));
            }
            mark_windows_managed_ssh_staging_handle_for_deletion(&staging_file)?;
            drop(staging_file);
            Ok(())
        }
        2 => {
            let destination_label = format!("{label} exact published destination");
            let destination_file = open_windows_managed_ssh_cleanup_file(destination, false)
                .map_err(|error| {
                    AppError::NotAuthorized(format!(
                        "{label} must not be hard-linked outside its exact destination: {error}"
                    ))
                })?;
            let destination_information = windows_managed_ssh_identity_handle_information(
                &destination_file,
                &destination_label,
            )?;
            if destination_information.number_of_links != 2
                || destination_information.identity != staging_information.identity
            {
                return Err(AppError::NotAuthorized(format!(
                    "{label} must not be hard-linked outside its exact destination"
                )));
            }
            if kind == ManagedSshIdentityFileKind::Private {
                for (file, checked_label) in [
                    (&staging_file, label),
                    (&destination_file, destination_label.as_str()),
                ] {
                    verify_windows_current_user_only_dacl(file).map_err(|error| {
                        AppError::NotAuthorized(format!(
                            "{checked_label} has unsafe Windows ownership or permissions: {error}"
                        ))
                    })?;
                }
            }
            let staging_before_delete = windows_file_information(&staging_file)?;
            let destination_before_delete = windows_file_information(&destination_file)?;
            if staging_before_delete != staging_information
                || destination_before_delete != destination_information
            {
                return Err(AppError::NotAuthorized(format!(
                    "{label} changed during verified crash recovery"
                )));
            }
            mark_windows_managed_ssh_staging_handle_for_deletion(&staging_file)?;
            // The destination handle shares delete with the staging handle.
            // Close both so NTFS can remove only the link used to open staging.
            drop(destination_file);
            drop(staging_file);
            Ok(())
        }
        _ => Err(AppError::NotAuthorized(format!(
            "{label} must not be hard-linked"
        ))),
    }
}

#[cfg(unix)]
fn cleanup_unix_managed_ssh_identity_staging_file(
    staging: &Path,
    destination: &Path,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let open = |path: &Path| {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        options.open(path)
    };
    let staging_file = match open(staging) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AppError::NotAuthorized(format!(
                "{label} could not be opened for verified cleanup: {error}"
            )));
        }
    };
    let staging_metadata = staging_file.metadata()?;
    let effective_uid = unsafe { libc::geteuid() };
    let staging_mode = staging_metadata.permissions().mode() & 0o777;
    if !staging_metadata.is_file() || staging_metadata.uid() != effective_uid {
        return Err(AppError::NotAuthorized(format!(
            "{label} is unsafe for verified cleanup"
        )));
    }
    match staging_metadata.nlink() {
        1 => {
            if !managed_ssh_identity_mode_is_safe(kind, staging_mode) {
                return Err(AppError::NotAuthorized(format!(
                    "{label} is unsafe for verified cleanup"
                )));
            }
            remove_regular_file(staging)
        }
        2 => {
            let destination_file = open(destination).map_err(|error| {
                AppError::NotAuthorized(format!(
                    "{label} must not be hard-linked outside its exact destination: {error}"
                ))
            })?;
            let destination_metadata = destination_file.metadata()?;
            let destination_mode = destination_metadata.permissions().mode() & 0o777;
            if !destination_metadata.is_file()
                || destination_metadata.dev() != staging_metadata.dev()
                || destination_metadata.ino() != staging_metadata.ino()
                || destination_metadata.nlink() != 2
                || destination_metadata.uid() != effective_uid
                || !managed_ssh_identity_mode_is_safe(kind, staging_mode)
                || !managed_ssh_identity_mode_is_safe(kind, destination_mode)
            {
                return Err(AppError::NotAuthorized(format!(
                    "{label} must not be hard-linked outside its exact destination"
                )));
            }
            let before_delete = fs::symlink_metadata(staging)?;
            if before_delete.dev() != staging_metadata.dev()
                || before_delete.ino() != staging_metadata.ino()
                || before_delete.nlink() != 2
            {
                return Err(AppError::NotAuthorized(format!(
                    "{label} changed during verified crash recovery"
                )));
            }
            fs::remove_file(staging)?;
            drop(destination_file);
            drop(staging_file);
            Ok(())
        }
        _ => Err(AppError::NotAuthorized(format!(
            "{label} must not be hard-linked"
        ))),
    }
}

fn cleanup_managed_ssh_identity_staging_file(
    staging: &Path,
    destination: &Path,
    maximum: u64,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    #[cfg(windows)]
    {
        let _ = maximum;
        cleanup_windows_managed_ssh_identity_staging_file(staging, destination, label, kind)
    }
    #[cfg(unix)]
    {
        let _ = maximum;
        cleanup_unix_managed_ssh_identity_staging_file(staging, destination, label, kind)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = destination;
        remove_verified_managed_ssh_identity_file_if_present(staging, maximum, label, kind)
    }
}

fn remove_repairable_managed_ssh_identity(private_key_path: &Path) -> AppResult<()> {
    let public_key_path = managed_ssh_public_key_path(private_key_path);
    remove_verified_managed_ssh_identity_file_if_present(
        private_key_path,
        MAX_SSH_PRIVATE_KEY_BYTES,
        "managed runtime SSH private key",
        ManagedSshIdentityFileKind::Private,
    )?;
    remove_verified_managed_ssh_identity_file_if_present(
        &public_key_path,
        MAX_SSH_PUBLIC_KEY_BYTES,
        "managed runtime SSH public key",
        ManagedSshIdentityFileKind::Public,
    )?;
    let parent = private_key_path
        .parent()
        .ok_or_else(|| AppError::Internal("managed runtime SSH identity has no parent".into()))?;
    sync_directory(parent)
}

fn remove_verified_managed_ssh_identity_file_if_present(
    path: &Path,
    maximum: u64,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    #[cfg(windows)]
    {
        let _ = maximum;
        remove_windows_verified_managed_ssh_identity_file_if_present(path, label, kind)
    }
    #[cfg(not(windows))]
    {
        match inspect_managed_ssh_identity_file(path, maximum, label, kind)? {
            ManagedSshIdentityFileState::Absent => Ok(()),
            ManagedSshIdentityFileState::Bounded(_) | ManagedSshIdentityFileState::Invalid => {
                remove_regular_file(path)
            }
        }
    }
}

fn cleanup_managed_ssh_identity_temporaries(private_key_path: &Path) -> AppResult<()> {
    let (private_temporary, public_temporary) =
        managed_ssh_identity_temporary_paths(private_key_path)?;
    cleanup_managed_ssh_identity_staging_file(
        &private_temporary,
        private_key_path,
        MAX_SSH_PRIVATE_KEY_BYTES,
        "managed runtime SSH private-key staging file",
        ManagedSshIdentityFileKind::Private,
    )?;
    cleanup_managed_ssh_identity_staging_file(
        &public_temporary,
        &managed_ssh_public_key_path(private_key_path),
        MAX_SSH_PUBLIC_KEY_BYTES,
        "managed runtime SSH public-key staging file",
        ManagedSshIdentityFileKind::Public,
    )
}

fn write_managed_ssh_identity_temporary(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn publish_managed_ssh_identity_file(temporary: &Path, destination: &Path) -> AppResult<()> {
    // A same-directory hard link publishes fully written bytes atomically and
    // fails if an unexpected destination entry (including a symlink) appeared.
    fs::hard_link(temporary, destination).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime SSH identity could not be published without replacing an existing entry: {error}"
        ))
    })?;
    remove_regular_file(temporary)
}

fn generate_managed_ssh_identity(private_key_path: &Path) -> AppResult<()> {
    let parent = private_key_path
        .parent()
        .ok_or_else(|| AppError::Internal("managed runtime SSH identity has no parent".into()))?;
    let public_key_path = managed_ssh_public_key_path(private_key_path);
    if private_entry_exists(private_key_path)? || private_entry_exists(&public_key_path)? {
        return Err(AppError::NotAuthorized(
            "managed runtime SSH identity destination appeared before publication".into(),
        ));
    }
    let (private_temporary, public_temporary) =
        managed_ssh_identity_temporary_paths(private_key_path)?;
    cleanup_managed_ssh_identity_temporaries(private_key_path)?;

    let mut private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|_| {
        AppError::Runtime("managed runtime Ed25519 SSH identity generation failed".into())
    })?;
    private_key.set_comment(MANAGED_SSH_KEY_COMMENT);
    let private_encoding = private_key.to_openssh(LineEnding::LF).map_err(|_| {
        AppError::Runtime("managed runtime OpenSSH private key encoding failed".into())
    })?;
    let mut public_encoding = private_key.public_key().to_openssh().map_err(|_| {
        AppError::Runtime("managed runtime OpenSSH public key encoding failed".into())
    })?;
    public_encoding.push('\n');
    if private_encoding.is_empty()
        || private_encoding.len() as u64 > MAX_SSH_PRIVATE_KEY_BYTES
        || public_encoding.is_empty()
        || public_encoding.len() as u64 > MAX_SSH_PUBLIC_KEY_BYTES
    {
        return Err(AppError::Runtime(
            "managed runtime generated an unexpectedly sized SSH identity".into(),
        ));
    }

    let mut public_published = false;
    let result = (|| {
        write_managed_ssh_identity_temporary(&private_temporary, private_encoding.as_bytes())?;
        write_managed_ssh_identity_temporary(&public_temporary, public_encoding.as_bytes())?;
        // Publish the public half first. A crash can therefore leave only a
        // non-secret partial pair, which the next locked setup safely repairs.
        publish_managed_ssh_identity_file(&public_temporary, &public_key_path)?;
        public_published = true;
        publish_managed_ssh_identity_file(&private_temporary, private_key_path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = cleanup_managed_ssh_identity_staging_file(
            &private_temporary,
            private_key_path,
            MAX_SSH_PRIVATE_KEY_BYTES,
            "managed runtime SSH private-key staging file",
            ManagedSshIdentityFileKind::Private,
        );
        let _ = cleanup_managed_ssh_identity_staging_file(
            &public_temporary,
            &public_key_path,
            MAX_SSH_PUBLIC_KEY_BYTES,
            "managed runtime SSH public-key staging file",
            ManagedSshIdentityFileKind::Public,
        );
        if public_published && !private_entry_exists(private_key_path).unwrap_or(true) {
            let _ = remove_verified_managed_ssh_identity_file_if_present(
                &public_key_path,
                MAX_SSH_PUBLIC_KEY_BYTES,
                "managed runtime SSH public key",
                ManagedSshIdentityFileKind::Public,
            );
        }
        let _ = sync_directory(parent);
    }
    result
}

fn machine_name(target: &ManagedTarget) -> String {
    let name = format!(
        "{MACHINE_PREFIX}-{}-{}-{}",
        target.operating_system.machine_name_key(),
        target.architecture.machine_name_key(),
        &target.machine_image.sha256[..MACHINE_IMAGE_ID_HEX_CHARS]
    );
    debug_assert!(name.len() <= MAX_MACHINE_NAME_BYTES);
    name
}

fn linux_machine_volume_spec(application_data: &Path) -> AppResult<OsString> {
    if !application_data.is_absolute() {
        return Err(AppError::NotAuthorized(
            "managed runtime application-data mount must be absolute".into(),
        ));
    }
    let rendered = application_data.to_str().ok_or_else(|| {
        AppError::NotAvailable(
            "managed runtime application-data mount is not representable for Podman".into(),
        )
    })?;
    if rendered.contains([':', ',', '\n', '\r', '\0']) {
        return Err(AppError::NotAuthorized(
            "managed runtime application-data mount contains unsupported volume syntax".into(),
        ));
    }
    Ok(OsString::from(format!("{rendered}:{rendered}")))
}

fn installation_directory_name(loaded: &LoadedManagedRuntimeManifest) -> String {
    format!(
        "{}-{}-{}",
        loaded.manifest.bundle_id,
        loaded.manifest.runtime_version,
        &loaded.sha256[..16]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsWslPrerequisiteFailure {
    reason: ManagedRuntimeSetupFailureReason,
    action: ManagedRuntimeSetupNextAction,
    exit_code: Option<i32>,
}

impl WindowsWslPrerequisiteFailure {
    fn not_installed(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::WslNotInstalled,
            action: ManagedRuntimeSetupNextAction::InstallWsl,
            exit_code,
        }
    }

    fn optional_feature_disabled(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled,
            action: ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures,
            exit_code,
        }
    }

    fn update_required(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::WslUpdateRequired,
            action: ManagedRuntimeSetupNextAction::UpdateWsl,
            exit_code,
        }
    }

    fn restart_required(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::RestartRequired,
            action: ManagedRuntimeSetupNextAction::RestartWindows,
            exit_code,
        }
    }

    fn command_failed(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::WslCommandFailed,
            action: ManagedRuntimeSetupNextAction::RetryWslCheck,
            exit_code,
        }
    }

    fn detail(self) -> String {
        let status = self
            .exit_code
            .map(|code| format!(" The read-only WSL check exited with code {code}."))
            .unwrap_or_default();
        match self.reason {
            ManagedRuntimeSetupFailureReason::WslNotInstalled => format!(
                "Windows Subsystem for Linux (WSL 2) is not installed.{status} Install WSL 2 in Windows, then retry. ai-security-scanner did not change Windows settings."
            ),
            ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled => format!(
                "Windows has not made the features required by WSL 2 available.{status} Enable Windows Subsystem for Linux and Virtual Machine Platform, restart Windows if prompted, then retry. ai-security-scanner did not change Windows settings."
            ),
            ManagedRuntimeSetupFailureReason::WslUpdateRequired => format!(
                "WSL 2 needs an update before the isolated scanner can start.{status} Update WSL in Windows, then retry. ai-security-scanner did not install the update."
            ),
            ManagedRuntimeSetupFailureReason::RestartRequired => format!(
                "Windows must restart to finish preparing WSL 2.{status} Restart Windows, reopen ai-security-scanner, then retry."
            ),
            ManagedRuntimeSetupFailureReason::WslCommandFailed => format!(
                "Windows could not confirm that WSL 2 is ready.{status} Open Windows Terminal, run `wsl.exe --status`, resolve the reported Windows issue, then retry. ai-security-scanner did not change Windows settings."
            ),
        }
    }
}

fn fail_windows_wsl_prerequisite(
    setup: Option<&ManagedRuntimeSetupController>,
    failure: WindowsWslPrerequisiteFailure,
) -> AppResult<()> {
    let detail = failure.detail();
    if let Some(setup) = setup {
        setup.record_failure(failure.reason, failure.action, detail.clone())?;
    }
    Err(AppError::NotAvailable(detail))
}

fn classify_windows_wsl_prerequisite_failure(
    output: &ManagedCommandOutput,
) -> WindowsWslPrerequisiteFailure {
    let diagnostic = [output.stdout.as_slice(), output.stderr.as_slice()]
        .into_iter()
        .filter_map(safe_command_diagnostic)
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    let exit_code = output.status.code();

    // WSL retains these symbolic names and hexadecimal codes outside its
    // localized prose. Prefer narrowly actionable classifications and fall
    // back to a generic, read-only retry action for every unknown result.
    if diagnostic_contains_any(
        &diagnostic,
        &[
            "ERROR_SUCCESS_REBOOT_REQUIRED",
            "ERROR_SUCCESS_RESTART_REQUIRED",
            "0X80070BC2",
            "0X80070BC3",
            // Inbox WSL can surface this after CBS stages WSL features but a
            // real Windows restart has not completed the transaction.
            "0XC004000D",
        ],
    ) {
        WindowsWslPrerequisiteFailure::restart_required(exit_code)
    } else if diagnostic_contains_any(
        &diagnostic,
        &[
            "WSL_E_WSL_NOT_INSTALLED",
            "WSL_E_NOT_INSTALLED",
            "WSL_NOT_INSTALLED",
            "AKA.MS/WSLINSTALL",
        ],
    ) {
        WindowsWslPrerequisiteFailure::not_installed(exit_code)
    } else if diagnostic_contains_any(
        &diagnostic,
        &[
            "WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED",
            "WSL_E_VIRTUAL_MACHINE_PLATFORM_REQUIRED",
            "HCS_E_HYPERV_NOT_INSTALLED",
            "0X8007019E",
            "0X8004032D",
            "0X80370102",
        ],
    ) {
        WindowsWslPrerequisiteFailure::optional_feature_disabled(exit_code)
    } else if diagnostic_contains_any(
        &diagnostic,
        &[
            "WSL_E_KERNEL_UPDATE_REQUIRED",
            "WSL_E_WSL2_KERNEL_NOT_FOUND",
            "WSL_E_PLUGIN_REQUIRES_UPDATE",
            "WSL_E_VERSION_OUTDATED",
            "WSL_E_WSL2_NEEDED",
            "WSL_E_INVALID_USAGE",
            "INVALID COMMAND LINE OPTION: --STATUS",
            "0X800701BC",
        ],
    ) {
        WindowsWslPrerequisiteFailure::update_required(exit_code)
    } else {
        WindowsWslPrerequisiteFailure::command_failed(exit_code)
    }
}

fn diagnostic_contains_any(diagnostic: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| diagnostic.contains(needle))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsSystemDirectories {
    system_root: PathBuf,
    system32: PathBuf,
}

#[cfg(any(windows, test))]
fn verified_windows_system_directories(system_root: &Path) -> AppResult<WindowsSystemDirectories> {
    if !system_root.is_absolute() {
        return Err(AppError::NotAuthorized(
            "Windows system directory API did not return an absolute directory".into(),
        ));
    }
    let system_root = canonical_real_directory(system_root, "Windows SystemRoot")?;
    let system32 =
        canonical_real_directory(&system_root.join("System32"), "Windows SystemRoot System32")?;
    if !system32.starts_with(&system_root) {
        return Err(AppError::NotAuthorized(
            "Windows System32 directory escaped the canonical Windows root".into(),
        ));
    }
    Ok(WindowsSystemDirectories {
        system_root,
        system32,
    })
}

#[cfg(windows)]
fn windows_system_directories() -> AppResult<WindowsSystemDirectories> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    const MAX_WINDOWS_DIRECTORY_UTF16_CODE_UNITS: usize = 32_768;
    let mut encoded = vec![0_u16; MAX_WINDOWS_DIRECTORY_UTF16_CODE_UNITS];
    let length = unsafe {
        GetSystemWindowsDirectoryW(
            encoded.as_mut_ptr(),
            u32::try_from(encoded.len()).expect("Windows directory buffer fits u32"),
        )
    };
    if length == 0 {
        return Err(AppError::NotAvailable(format!(
            "Windows system directory API failed: {}",
            io::Error::last_os_error()
        )));
    }
    let length = usize::try_from(length).map_err(|_| {
        AppError::NotAvailable("Windows system directory length exceeded this platform".into())
    })?;
    if length >= encoded.len() || encoded[length] != 0 || encoded[..length].contains(&0) {
        return Err(AppError::NotAvailable(
            "Windows system directory API returned an invalid or oversized path".into(),
        ));
    }
    verified_windows_system_directories(&PathBuf::from(OsString::from_wide(&encoded[..length])))
}

#[cfg(not(windows))]
fn windows_system_directories() -> AppResult<WindowsSystemDirectories> {
    Err(AppError::NotAvailable(
        "Windows system directory API is unavailable on this host".into(),
    ))
}

fn windows_wsl_inventory_command(
    managed_command: &ManagedRuntimeCommand,
) -> AppResult<ManagedRuntimeCommand> {
    let directories = windows_system_directories()?;
    windows_wsl_inventory_command_with_directories(managed_command, &directories)
}

fn windows_wsl_inventory_command_with_directories(
    managed_command: &ManagedRuntimeCommand,
    directories: &WindowsSystemDirectories,
) -> AppResult<ManagedRuntimeCommand> {
    let system_root = &directories.system_root;
    let system32 = &directories.system32;
    let binary = system32.join("wsl.exe");
    if !binary.is_absolute() {
        return Err(AppError::NotAuthorized(
            "Windows WSL inventory executable was not absolute".into(),
        ));
    }
    verify_regular_file(&binary, "Windows System32 wsl.exe")?;
    let working_directory = canonical_real_directory(
        &managed_command.working_directory,
        "managed Windows WSL inventory working",
    )?;
    let path = std::env::join_paths([system32.clone()])
        .map_err(|_| AppError::Runtime("managed Windows WSL inventory PATH is invalid".into()))?;
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("SystemRoot"),
        system_root.as_os_str().to_owned(),
    );
    environment.insert(OsString::from("WINDIR"), system_root.as_os_str().to_owned());
    environment.insert(OsString::from("PATH"), path);
    environment.insert(
        OsString::from("NoDefaultCurrentDirectoryInExePath"),
        OsString::from("1"),
    );

    Ok(ManagedRuntimeCommand {
        binary,
        environment,
        working_directory,
        runtime_version: managed_command.runtime_version.clone(),
        manifest_sha256: managed_command.manifest_sha256.clone(),
        machine_image_sha256: managed_command.machine_image_sha256.clone(),
    })
}

fn parse_windows_wsl_distribution_inventory(bytes: &[u8]) -> AppResult<Vec<String>> {
    let decoded = decode_windows_command_text(bytes, "managed Windows WSL distribution inventory")?;

    if decoded.contains(['\0', '\u{feff}']) {
        return Err(AppError::Runtime(
            "managed Windows WSL distribution inventory contained an invalid code point".into(),
        ));
    }
    let mut distributions = Vec::new();
    let mut lines = decoded.split('\n').peekable();
    while let Some(encoded_line) = lines.next() {
        if encoded_line.is_empty() && lines.peek().is_none() {
            break;
        }
        let line = encoded_line.strip_suffix('\r').unwrap_or(encoded_line);
        if line.is_empty()
            || line.len() > MAX_WSL_DISTRIBUTION_NAME_BYTES
            || line.trim() != line
            || line.chars().any(|character| {
                character.is_control()
                    || matches!(character, '\u{2028}' | '\u{2029}')
                    || unicode_code_point_is_noncharacter(character)
            })
        {
            return Err(AppError::Runtime(
                "managed Windows WSL distribution inventory contained an invalid name".into(),
            ));
        }
        if distributions.len() == MAX_WSL_DISTRIBUTIONS {
            return Err(AppError::Runtime(
                "managed Windows WSL distribution inventory contained too many names".into(),
            ));
        }
        distributions.push(line.to_owned());
    }
    Ok(distributions)
}

/// Decodes the encodings emitted by Windows console applications when their
/// output is redirected to a pipe. WSL commonly uses UTF-16LE for localized
/// text, sometimes without a BOM; modern builds may emit UTF-8 instead.
fn decode_windows_command_text(bytes: &[u8], label: &str) -> AppResult<String> {
    if bytes.len() as u64 > MAX_COMMAND_OUTPUT_BYTES {
        return Err(AppError::Runtime(format!("{label} was oversized")));
    }
    if let Some(encoded) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        std::str::from_utf8(encoded)
            .map(str::to_owned)
            .map_err(|_| AppError::Runtime(format!("{label} was not valid UTF-8")))
    } else if let Some(encoded) = bytes.strip_prefix(&[0xff, 0xfe]) {
        decode_windows_utf16le(encoded, label)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        Err(AppError::Runtime(format!(
            "{label} used unsupported UTF-16BE"
        )))
    } else if let Ok(decoded) = std::str::from_utf8(bytes) {
        if decoded.contains('\0') {
            decode_windows_utf16le(bytes, label)
        } else {
            Ok(decoded.to_owned())
        }
    } else {
        decode_windows_utf16le(bytes, label)
    }
}

fn decode_windows_utf16le(bytes: &[u8], label: &str) -> AppResult<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(AppError::Runtime(format!(
            "{label} had invalid UTF-16LE length"
        )));
    }
    let code_units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&code_units)
        .map_err(|_| AppError::Runtime(format!("{label} was not valid UTF-16LE")))
}

fn unicode_code_point_is_noncharacter(character: char) -> bool {
    let code_point = character as u32;
    (0xfdd0..=0xfdef).contains(&code_point) || code_point & 0xfffe == 0xfffe
}

fn require_success(operation: &str, output: &ManagedCommandOutput) -> AppResult<()> {
    if output.status.success() {
        return Ok(());
    }
    let detail = safe_command_diagnostic(&output.stderr)
        .or_else(|| safe_command_diagnostic(&output.stdout))
        .unwrap_or_else(|| "No readable diagnostic was returned.".into());
    Err(AppError::Runtime(format!(
        "{operation} failed with status {}: {}",
        output.status, detail
    )))
}

/// Returns a bounded single-line diagnostic or `None` when the child output
/// cannot be decoded without replacement characters or unsafe controls. Raw
/// bytes are never interpolated into an application error.
fn safe_command_diagnostic(bytes: &[u8]) -> Option<String> {
    if !windows_command_text_has_known_encoding(bytes) {
        return None;
    }
    let decoded = decode_windows_command_text(bytes, "managed runtime command diagnostic").ok()?;
    let mut sanitized = String::new();
    let mut previous_was_space = true;
    for (retained, character) in decoded.chars().enumerate() {
        if retained == MAX_COMMAND_DIAGNOSTIC_CHARS {
            break;
        }
        if character == '\u{fffd}'
            || character == '\u{feff}'
            || unicode_code_point_is_noncharacter(character)
            || (character.is_control() && !character.is_whitespace())
        {
            return None;
        }
        if character.is_whitespace() {
            if !previous_was_space {
                sanitized.push(' ');
                previous_was_space = true;
            }
        } else {
            sanitized.push(character);
            previous_was_space = false;
        }
    }
    let sanitized = sanitized.trim().to_owned();
    (!sanitized.is_empty()).then_some(sanitized)
}

fn windows_command_text_has_known_encoding(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) || bytes.starts_with(&[0xff, 0xfe]) {
        return true;
    }
    if bytes.starts_with(&[0xfe, 0xff]) || !bytes.len().is_multiple_of(2) {
        return std::str::from_utf8(bytes).is_ok_and(|text| !text.contains('\0'));
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return !text.contains('\0') || looks_like_unmarked_utf16le_console_text(bytes);
    }
    looks_like_unmarked_utf16le_console_text(bytes)
}

fn looks_like_unmarked_utf16le_console_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let pairs = bytes.len() / 2;
    let odd_nuls = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|byte| **byte == 0)
        .count();
    let even_nuls = bytes.iter().step_by(2).filter(|byte| **byte == 0).count();
    let has_utf16_ascii_signal = odd_nuls > 0 && odd_nuls * 8 >= pairs && even_nuls * 8 < pairs;
    let has_mixed_ascii_prefix = bytes
        .split(|byte| !byte.is_ascii_graphic() && *byte != b' ')
        .any(|run| run.len() >= 8);
    has_utf16_ascii_signal && !has_mixed_ascii_prefix
}

fn bounded_utf8<'a>(bytes: &'a [u8], label: &str) -> AppResult<&'a str> {
    if bytes.len() as u64 > MAX_COMMAND_OUTPUT_BYTES {
        return Err(AppError::Runtime(format!("{label} was oversized")));
    }
    std::str::from_utf8(bytes)
        .map_err(|_| AppError::Runtime(format!("{label} was not valid UTF-8")))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(unix)]
fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn linux_short_runtime_path(
    base: &Path,
    canonical_state_root: &Path,
    manifest_sha256: &str,
    effective_uid: libc::uid_t,
) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let state_bytes = canonical_state_root.as_os_str().as_bytes();
    let mut digest = Sha256::new();
    digest.update(b"ai-security-scanner-linux-xdg-runtime-v1\0");
    digest.update(effective_uid.to_be_bytes());
    digest.update((state_bytes.len() as u64).to_be_bytes());
    digest.update(state_bytes);
    digest.update((manifest_sha256.len() as u64).to_be_bytes());
    digest.update(manifest_sha256.as_bytes());
    let encoded = hex::encode(digest.finalize());
    base.join(format!(
        "{LINUX_SHORT_RUNTIME_PREFIX}{}",
        &encoded[..LINUX_SHORT_RUNTIME_DIGEST_HEX_CHARS]
    ))
}

#[cfg(unix)]
fn linux_podman_gvproxy_socket_path(runtime: &Path, machine_name: &str) -> PathBuf {
    runtime
        .join(PODMAN_LINUX_RUNTIME_DIRECTORY)
        .join(format!("{machine_name}{PODMAN_GVPROXY_SOCKET_SUFFIX}"))
}

#[cfg(unix)]
fn verify_linux_temporary_base(base: &Path) -> AppResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(base)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux temporary base must be a real directory".into(),
        ));
    }
    if base.canonicalize()? != base {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux temporary base must be canonical".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(base).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux temporary base could not be opened without following links: {error}"
        ))
    })?;
    let opened = directory.metadata()?;
    if !opened.is_dir() || opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux temporary base changed while it was being verified".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_linux_short_runtime_directory_at(
    path: &Path,
    base: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::os::unix::fs::DirBuilderExt;

    verify_linux_temporary_base(base)?;
    if path.parent() != Some(base) {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short-runtime path escaped its exact temporary base".into(),
        ));
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    verify_linux_short_runtime_directory(path, effective_uid)
}

#[cfg(unix)]
fn verify_linux_short_runtime_directory(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    drop(open_verified_linux_short_runtime_directory(
        path,
        effective_uid,
    )?);
    Ok(())
}

#[cfg(unix)]
fn open_verified_linux_short_runtime_directory(
    path: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short runtime must be a real directory".into(),
        ));
    }
    if metadata.uid() != effective_uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short runtime has unsafe ownership or permissions".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux short runtime could not be opened without following links: {error}"
        ))
    })?;
    let opened = directory.metadata()?;
    if !opened.is_dir()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short runtime changed while it was being verified".into(),
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn verify_linux_podman_runtime_directory(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o7777;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || mode & 0o700 != 0o700
        || mode & !0o755 != 0
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux Podman runtime directory is unsafe".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux Podman runtime directory could not be opened without following links: {error}"
        ))
    })?;
    let opened = directory.metadata()?;
    if !opened.is_dir()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != mode
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux Podman runtime directory changed while it was being verified"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn remove_expected_linux_gvproxy_log(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mode = metadata.mode() & 0o7777;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || mode & 0o600 != 0o600
        || mode & !0o666 != 0
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux gvproxy log is not an expected current-user single-link regular file"
                .into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux gvproxy log could not be opened without following links: {error}"
        ))
    })?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.nlink() != 1
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != mode
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux gvproxy log changed while it was being verified".into(),
        ));
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(unix)]
fn open_expected_linux_virtiofs_pid(path: &Path, effective_uid: libc::uid_t) -> AppResult<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux virtiofsd pid is not an expected current-user single-link mode-0600 regular file"
                .into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux virtiofsd pid could not be opened without following links: {error}"
        ))
    })?;
    verify_opened_linux_virtiofs_pid(path, &file, &metadata, effective_uid)?;
    Ok(file)
}

#[cfg(unix)]
fn verify_opened_linux_virtiofs_pid(
    path: &Path,
    file: &File,
    expected: &fs::Metadata,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::os::unix::fs::MetadataExt;

    let current = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || current.dev() != expected.dev()
        || current.ino() != expected.ino()
        || current.nlink() != 1
        || current.uid() != effective_uid
        || current.mode() & 0o7777 != 0o600
        || !opened.is_file()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
        || opened.nlink() != 1
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != 0o600
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux virtiofsd pid changed while it was being verified".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn wait_for_unlocked_linux_virtiofs_pid(
    path: &Path,
    effective_uid: libc::uid_t,
    timeout: Duration,
) -> AppResult<Option<File>> {
    use std::os::fd::AsRawFd;

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let file = open_expected_linux_virtiofs_pid(path, effective_uid)?;
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: file owns a valid descriptor; flock neither retains the pointer nor
        // accesses memory. The acquired lock remains held by this File until cleanup.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            verify_opened_linux_virtiofs_pid(path, &file, &metadata, effective_uid)?;
            return Ok(Some(file));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(error.into());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(AppError::Runtime(
                "managed runtime Linux virtiofsd remained live after exact machine removal".into(),
            ));
        }
        thread::sleep(LINUX_VIRTIOFS_CLEANUP_POLL.min(deadline.saturating_duration_since(now)));
    }
}

#[cfg(unix)]
fn verify_linux_virtiofs_socket(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux virtiofsd socket is not the expected current-user single-link mode-0700 Unix socket"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn remove_expected_linux_virtiofs_residue(
    podman: &Path,
    effective_uid: libc::uid_t,
    timeout: Duration,
) -> AppResult<()> {
    let pid_path = podman.join(PODMAN_VIRTIOFS_PID_NAME);
    let socket_path = podman.join(PODMAN_VIRTIOFS_SOCKET_NAME);
    let Some(pid_file) = wait_for_unlocked_linux_virtiofs_pid(&pid_path, effective_uid, timeout)?
    else {
        if private_entry_exists(&socket_path)? {
            return Err(AppError::NotAuthorized(
                "managed runtime Linux virtiofsd socket had no exact pid-lock ownership proof"
                    .into(),
            ));
        }
        return Ok(());
    };

    match fs::symlink_metadata(&socket_path) {
        Ok(_) => {
            verify_linux_virtiofs_socket(&socket_path, effective_uid)?;
            fs::remove_file(&socket_path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let expected = pid_file.metadata()?;
    verify_opened_linux_virtiofs_pid(&pid_path, &pid_file, &expected, effective_uid)?;
    fs::remove_file(&pid_path)?;
    Ok(())
}

#[cfg(unix)]
fn linux_runtime_child_stat(
    parent: &File,
    basename: &std::ffi::CStr,
) -> AppResult<Option<libc::stat>> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent owns a live directory descriptor, basename is a
    // NUL-terminated relative name, and metadata points to writable storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            basename.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager runtime directory could not be inspected without following links: {error}"
        )));
    }
    // SAFETY: successful fstatat initialized every field of metadata.
    Ok(Some(unsafe { metadata.assume_init() }))
}

#[cfg(unix)]
fn linux_runtime_opened_stat(directory: &File) -> AppResult<libc::stat> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory owns a live descriptor and metadata points to writable storage.
    if unsafe { libc::fstat(directory.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager runtime directory descriptor could not be inspected: {error}"
        )));
    }
    // SAFETY: successful fstat initialized every field of metadata.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn remove_expected_empty_linux_runtime_directory(
    parent_path: &Path,
    parent: &File,
    basename: &str,
    expected_mode: libc::mode_t,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    if basename.is_empty() || basename.contains(['/', '\0']) {
        return Err(AppError::Internal(
            "managed runtime Linux eager runtime basename is invalid".into(),
        ));
    }
    let c_basename = CString::new(basename.as_bytes()).map_err(|_| {
        AppError::Internal(
            "managed runtime Linux eager runtime basename was not representable".into(),
        )
    })?;
    let Some(expected) = linux_runtime_child_stat(parent, &c_basename)? else {
        return Ok(());
    };
    if expected.st_mode & libc::S_IFMT != libc::S_IFDIR
        || expected.st_uid != effective_uid
        || expected.st_mode & 0o7777 != expected_mode
    {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory has unsafe type, ownership, or permissions"
        )));
    }

    // SAFETY: parent is a verified directory descriptor and c_basename is a
    // fixed relative child name. O_NOFOLLOW rejects a link replacement.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c_basename.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory could not be opened without following links: {error}"
        )));
    }
    // SAFETY: openat returned a fresh owned descriptor that is transferred to File.
    let directory = unsafe { File::from_raw_fd(raw) };
    let opened = linux_runtime_opened_stat(&directory)?;
    if opened.st_mode & libc::S_IFMT != libc::S_IFDIR
        || opened.st_dev != expected.st_dev
        || opened.st_ino != expected.st_ino
        || opened.st_uid != effective_uid
        || opened.st_mode & 0o7777 != expected_mode
    {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory changed while it was opened"
        )));
    }
    if fs::read_dir(parent_path.join(basename))?
        .next()
        .transpose()?
        .is_some()
    {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory was not empty after machine removal"
        )));
    }

    let current = linux_runtime_child_stat(parent, &c_basename)?.ok_or_else(|| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory disappeared during verification"
        ))
    })?;
    let reopened = linux_runtime_opened_stat(&directory)?;
    if current.st_dev != expected.st_dev
        || current.st_ino != expected.st_ino
        || current.st_mode != expected.st_mode
        || current.st_uid != expected.st_uid
        || reopened.st_dev != current.st_dev
        || reopened.st_ino != current.st_ino
        || reopened.st_uid != effective_uid
        || reopened.st_mode & 0o7777 != expected_mode
    {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory changed during exact cleanup"
        )));
    }
    // SAFETY: parent remains the verified short-runtime descriptor and the
    // exact child was proved to be the same empty directory through its live descriptor.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), c_basename.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::Runtime(format!(
            "managed runtime Linux eager {basename} directory could not be removed: {error}"
        )));
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn remove_linux_short_runtime_directory_at(
    path: &Path,
    base: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    verify_linux_temporary_base(base)?;
    if path.parent() != Some(base) {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short-runtime cleanup escaped its exact temporary base".into(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let short_directory = open_verified_linux_short_runtime_directory(path, effective_uid)?;

    let podman = path.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !matches!(
            entry.file_name().to_str(),
            Some(PODMAN_LINUX_RUNTIME_DIRECTORY)
                | Some(PODMAN_LINUX_EAGER_STORAGE_DIRECTORY)
                | Some(PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY)
        ) {
            return Err(AppError::NotAuthorized(
                "managed runtime Linux short runtime contained an unexpected entry after machine removal"
                    .into(),
            ));
        }
    }
    match fs::symlink_metadata(&podman) {
        Ok(_) => {
            verify_linux_podman_runtime_directory(&podman, effective_uid)?;
            for entry in fs::read_dir(&podman)? {
                let entry = entry?;
                if !matches!(
                    entry.file_name().to_str(),
                    Some(PODMAN_GVPROXY_LOG_NAME)
                        | Some(PODMAN_VIRTIOFS_SOCKET_NAME)
                        | Some(PODMAN_VIRTIOFS_PID_NAME)
                ) {
                    return Err(AppError::NotAuthorized(
                        "managed runtime Linux Podman runtime directory contained an unexpected entry after machine removal"
                            .into(),
                    ));
                }
            }
            remove_expected_linux_virtiofs_residue(
                &podman,
                effective_uid,
                LINUX_VIRTIOFS_CLEANUP_TIMEOUT,
            )?;
            remove_expected_linux_gvproxy_log(
                &podman.join(PODMAN_GVPROXY_LOG_NAME),
                effective_uid,
            )?;
            if fs::read_dir(&podman)?.next().transpose()?.is_some() {
                return Err(AppError::NotAuthorized(
                    "managed runtime Linux Podman runtime directory was not empty after exact log cleanup"
                        .into(),
                ));
            }
            fs::remove_dir(&podman)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Pinned containers/storage v1.62.0 and containers/common eagerly create
    // these exact roots from XDG_RUNTIME_DIR before the release-private
    // storage.conf and containers.conf overrides are applied. Neither may
    // contain state: accept only the observed exact modes and empty real dirs.
    remove_expected_empty_linux_runtime_directory(
        path,
        &short_directory,
        PODMAN_LINUX_EAGER_STORAGE_DIRECTORY,
        0o700,
        effective_uid,
    )?;
    remove_expected_empty_linux_runtime_directory(
        path,
        &short_directory,
        PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY,
        0o1700,
        effective_uid,
    )?;
    if fs::read_dir(path)?.next().transpose()?.is_some() {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short runtime was not empty after machine removal".into(),
        ));
    }
    fs::remove_dir(path)?;
    sync_directory(base)
}

#[cfg(unix)]
fn macos_short_home_path(
    base: &Path,
    canonical_state_root: &Path,
    manifest_sha256: &str,
    effective_uid: libc::uid_t,
) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let state_bytes = canonical_state_root.as_os_str().as_bytes();
    let mut digest = Sha256::new();
    digest.update(b"ai-security-scanner-macos-command-home-v1\0");
    digest.update(effective_uid.to_be_bytes());
    digest.update((state_bytes.len() as u64).to_be_bytes());
    digest.update(state_bytes);
    digest.update((manifest_sha256.len() as u64).to_be_bytes());
    digest.update(manifest_sha256.as_bytes());
    let encoded = hex::encode(digest.finalize());
    base.join(format!(
        "{MACOS_SHORT_HOME_PREFIX}{}",
        &encoded[..MACOS_SHORT_HOME_DIGEST_HEX_CHARS]
    ))
}

#[cfg(unix)]
fn macos_podman_ignition_socket_alias(home: &Path, machine_name: &str) -> PathBuf {
    home.join(".podman")
        .join(format!("{machine_name}{PODMAN_IGNITION_SOCKET_SUFFIX}"))
}

#[cfg(unix)]
fn ensure_macos_short_home_directory(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }

    verify_macos_short_home_directory(path, effective_uid)
}

#[cfg(unix)]
fn verify_macos_short_home_directory(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    drop(open_verified_macos_short_home_directory(
        path,
        effective_uid,
    )?);
    Ok(())
}

#[cfg(unix)]
fn open_verified_macos_short_home_directory(
    path: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command home must be a real directory".into(),
        ));
    }
    if metadata.uid() != effective_uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command home has unsafe ownership or permissions".into(),
        ));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime macOS command home could not be opened without following links: {error}"
        ))
    })?;
    let opened = directory.metadata()?;
    if !opened.is_dir()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command home changed while it was being verified".into(),
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_verified_macos_socket_alias_directory(
    path: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS socket-alias directory is unsafe".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime macOS socket-alias directory could not be opened without following links: {error}"
        ))
    })?;
    verify_opened_macos_socket_alias_directory(path, &directory, &metadata, effective_uid)?;
    Ok(directory)
}

#[cfg(unix)]
fn verify_opened_macos_socket_alias_directory(
    path: &Path,
    directory: &File,
    expected: &fs::Metadata,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::os::unix::fs::MetadataExt;

    let current = fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if current.file_type().is_symlink()
        || !current.is_dir()
        || current.dev() != expected.dev()
        || current.ino() != expected.ino()
        || current.uid() != effective_uid
        || current.mode() & 0o7777 != 0o700
        || !opened.is_dir()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS socket-alias directory changed while it was being verified"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn macos_socket_alias_stat(directory: &File, basename: &std::ffi::CStr) -> AppResult<libc::stat> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory owns a live directory descriptor, basename is a
    // NUL-terminated relative name, and metadata points to writable storage.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            basename.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS ignition socket could not be inspected without following links: {error}"
        )));
    }
    // SAFETY: successful fstatat initialized every field of metadata.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn remove_expected_macos_ignition_socket_alias(
    aliases: &Path,
    effective_uid: libc::uid_t,
    machine_name: &str,
) -> AppResult<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    if machine_name.is_empty()
        || machine_name.len() > MAX_MACHINE_NAME_BYTES
        || !machine_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS machine name is invalid for exact socket cleanup".into(),
        ));
    }
    let expected_basename = format!("{machine_name}{PODMAN_IGNITION_SOCKET_SUFFIX}");
    let expected_c_basename = CString::new(expected_basename.as_bytes()).map_err(|_| {
        AppError::Internal(
            "managed runtime macOS ignition socket basename was not representable".into(),
        )
    })?;
    let directory = open_verified_macos_socket_alias_directory(aliases, effective_uid)?;

    let mut entries = fs::read_dir(aliases)?;
    let first = entries.next().transpose()?.map(|entry| entry.file_name());
    if entries.next().transpose()?.is_some()
        || first
            .as_ref()
            .is_some_and(|name| name != OsStr::new(&expected_basename))
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS socket-alias directory contained an unexpected entry after machine removal"
                .into(),
        ));
    }

    verify_opened_macos_socket_alias_directory(
        aliases,
        &directory,
        &directory.metadata()?,
        effective_uid,
    )?;
    if first.is_some() {
        let expected = macos_socket_alias_stat(&directory, &expected_c_basename)?;
        if expected.st_mode & libc::S_IFMT != libc::S_IFSOCK
            || expected.st_uid != effective_uid
            || expected.st_nlink != 1
            || expected.st_mode & 0o7000 != 0
        {
            return Err(AppError::NotAuthorized(
                "managed runtime macOS ignition socket is not an expected current-user single-link Unix socket"
                    .into(),
            ));
        }
        let current = macos_socket_alias_stat(&directory, &expected_c_basename)?;
        if current.st_dev != expected.st_dev
            || current.st_ino != expected.st_ino
            || current.st_mode != expected.st_mode
            || current.st_uid != expected.st_uid
            || current.st_nlink != expected.st_nlink
        {
            return Err(AppError::NotAuthorized(
                "managed runtime macOS ignition socket changed while it was being verified".into(),
            ));
        }
        // SAFETY: directory is the verified .podman descriptor and the fixed
        // relative basename was checked twice with AT_SYMLINK_NOFOLLOW.
        if unsafe { libc::unlinkat(directory.as_raw_fd(), expected_c_basename.as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            return Err(AppError::Runtime(format!(
                "managed runtime macOS ignition socket could not be removed: {error}"
            )));
        }
    }

    verify_opened_macos_socket_alias_directory(
        aliases,
        &directory,
        &directory.metadata()?,
        effective_uid,
    )?;
    if fs::read_dir(aliases)?.next().transpose()?.is_some() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS socket-alias directory changed during exact cleanup".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn macos_runtime_child_stat(
    parent: &File,
    basename: &std::ffi::CStr,
    label: &str,
) -> AppResult<Option<libc::stat>> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent owns a live directory descriptor, basename is a
    // NUL-terminated relative name, and metadata points to writable storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            basename.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS {label} could not be inspected without following links: {error}"
        )));
    }
    // SAFETY: successful fstatat initialized every field of metadata.
    Ok(Some(unsafe { metadata.assume_init() }))
}

#[cfg(unix)]
fn macos_runtime_opened_stat(file: &File, label: &str) -> AppResult<libc::stat> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file owns a live descriptor and metadata points to writable storage.
    if unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS {label} descriptor could not be inspected: {error}"
        )));
    }
    // SAFETY: successful fstat initialized every field of metadata.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn verify_exact_macos_known_hosts_entry(ssh_directory: &Path) -> AppResult<()> {
    let mut entries = fs::read_dir(ssh_directory)?;
    let first = entries.next().transpose()?.map(|entry| entry.file_name());
    if first.as_deref() != Some(OsStr::new(PODMAN_MACOS_KNOWN_HOSTS_FILE))
        || entries.next().transpose()?.is_some()
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory did not contain exactly the expected empty known_hosts file"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn remove_expected_macos_known_hosts(
    home_path: &Path,
    home: &File,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let ssh_basename = CString::new(PODMAN_MACOS_SSH_DIRECTORY).map_err(|_| {
        AppError::Internal("managed runtime macOS SSH directory name was invalid".into())
    })?;
    let known_hosts_basename = CString::new(PODMAN_MACOS_KNOWN_HOSTS_FILE).map_err(|_| {
        AppError::Internal("managed runtime macOS known_hosts filename was invalid".into())
    })?;
    let Some(expected_directory) = macos_runtime_child_stat(home, &ssh_basename, "SSH directory")?
    else {
        return Ok(());
    };
    if expected_directory.st_mode & libc::S_IFMT != libc::S_IFDIR
        || expected_directory.st_uid != effective_uid
        || expected_directory.st_mode & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory has unsafe type, ownership, or permissions".into(),
        ));
    }

    // SAFETY: home is a verified command-home descriptor and ssh_basename is
    // the fixed relative .ssh child. O_NOFOLLOW rejects a link replacement.
    let raw_directory = unsafe {
        libc::openat(
            home.as_raw_fd(),
            ssh_basename.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_directory < 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS SSH directory could not be opened without following links: {error}"
        )));
    }
    // SAFETY: openat returned a fresh owned descriptor that is transferred to File.
    let directory = unsafe { File::from_raw_fd(raw_directory) };
    let opened_directory = macos_runtime_opened_stat(&directory, "SSH directory")?;
    if opened_directory.st_mode & libc::S_IFMT != libc::S_IFDIR
        || opened_directory.st_dev != expected_directory.st_dev
        || opened_directory.st_ino != expected_directory.st_ino
        || opened_directory.st_uid != effective_uid
        || opened_directory.st_mode & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory changed while it was opened".into(),
        ));
    }

    let ssh_directory = home_path.join(PODMAN_MACOS_SSH_DIRECTORY);
    verify_exact_macos_known_hosts_entry(&ssh_directory)?;
    let expected_file =
        macos_runtime_child_stat(&directory, &known_hosts_basename, "known_hosts file")?
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "managed runtime macOS known_hosts file disappeared during verification".into(),
                )
            })?;
    if expected_file.st_mode & libc::S_IFMT != libc::S_IFREG
        || expected_file.st_uid != effective_uid
        || expected_file.st_nlink != 1
        || expected_file.st_mode & 0o7777 != 0o600
        || expected_file.st_size != 0
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS known_hosts file is not the expected current-user, single-link, mode-0600 empty regular file"
                .into(),
        ));
    }

    // SAFETY: directory is the verified .ssh descriptor and the basename is
    // fixed. O_NOFOLLOW prevents opening a symlink replacement.
    let raw_file = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            known_hosts_basename.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_file < 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS known_hosts file could not be opened without following links: {error}"
        )));
    }
    // SAFETY: openat returned a fresh owned descriptor that is transferred to File.
    let file = unsafe { File::from_raw_fd(raw_file) };
    let opened_file = macos_runtime_opened_stat(&file, "known_hosts file")?;
    if opened_file.st_mode & libc::S_IFMT != libc::S_IFREG
        || opened_file.st_dev != expected_file.st_dev
        || opened_file.st_ino != expected_file.st_ino
        || opened_file.st_uid != effective_uid
        || opened_file.st_nlink != 1
        || opened_file.st_mode & 0o7777 != 0o600
        || opened_file.st_size != 0
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS known_hosts file changed while it was opened".into(),
        ));
    }

    verify_exact_macos_known_hosts_entry(&ssh_directory)?;
    let current_file =
        macos_runtime_child_stat(&directory, &known_hosts_basename, "known_hosts file")?
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "managed runtime macOS known_hosts file disappeared during exact cleanup"
                        .into(),
                )
            })?;
    let reopened_file = macos_runtime_opened_stat(&file, "known_hosts file")?;
    let current_directory = macos_runtime_child_stat(home, &ssh_basename, "SSH directory")?
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "managed runtime macOS SSH directory disappeared during exact cleanup".into(),
            )
        })?;
    let reopened_directory = macos_runtime_opened_stat(&directory, "SSH directory")?;
    if current_file.st_dev != expected_file.st_dev
        || current_file.st_ino != expected_file.st_ino
        || current_file.st_mode != expected_file.st_mode
        || current_file.st_uid != expected_file.st_uid
        || current_file.st_nlink != expected_file.st_nlink
        || current_file.st_size != 0
        || reopened_file.st_dev != current_file.st_dev
        || reopened_file.st_ino != current_file.st_ino
        || reopened_file.st_mode != current_file.st_mode
        || reopened_file.st_uid != effective_uid
        || reopened_file.st_nlink != 1
        || reopened_file.st_size != 0
        || current_directory.st_dev != expected_directory.st_dev
        || current_directory.st_ino != expected_directory.st_ino
        || current_directory.st_mode != expected_directory.st_mode
        || current_directory.st_uid != expected_directory.st_uid
        || reopened_directory.st_dev != current_directory.st_dev
        || reopened_directory.st_ino != current_directory.st_ino
        || reopened_directory.st_uid != effective_uid
        || reopened_directory.st_mode & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH residue changed during exact cleanup".into(),
        ));
    }

    // SAFETY: directory is the verified .ssh descriptor, and the exact file
    // was proved unchanged through its still-live no-follow descriptor.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), known_hosts_basename.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::Runtime(format!(
            "managed runtime macOS known_hosts file could not be removed: {error}"
        )));
    }
    directory.sync_all()?;
    if fs::read_dir(&ssh_directory)?.next().transpose()?.is_some() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory changed after exact known_hosts cleanup".into(),
        ));
    }
    let final_directory = macos_runtime_child_stat(home, &ssh_basename, "SSH directory")?
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "managed runtime macOS SSH directory disappeared before exact removal".into(),
            )
        })?;
    let final_opened_directory = macos_runtime_opened_stat(&directory, "SSH directory")?;
    if final_directory.st_dev != expected_directory.st_dev
        || final_directory.st_ino != expected_directory.st_ino
        || final_directory.st_mode != expected_directory.st_mode
        || final_directory.st_uid != expected_directory.st_uid
        || final_opened_directory.st_dev != final_directory.st_dev
        || final_opened_directory.st_ino != final_directory.st_ino
        || final_opened_directory.st_uid != effective_uid
        || final_opened_directory.st_mode & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory changed before exact removal".into(),
        ));
    }
    // SAFETY: home is the verified command-home descriptor and .ssh is still
    // the same empty directory held open above.
    if unsafe { libc::unlinkat(home.as_raw_fd(), ssh_basename.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::Runtime(format!(
            "managed runtime macOS SSH directory could not be removed: {error}"
        )));
    }
    home.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn remove_macos_short_home_directory(
    path: &Path,
    effective_uid: libc::uid_t,
    machine_name: &str,
) -> AppResult<()> {
    remove_macos_short_home_directory_at(
        path,
        Path::new(MACOS_SHORT_HOME_BASE),
        effective_uid,
        machine_name,
    )
}

#[cfg(unix)]
fn remove_macos_short_home_directory_at(
    path: &Path,
    base: &Path,
    effective_uid: libc::uid_t,
    machine_name: &str,
) -> AppResult<()> {
    if path.parent() != Some(base) {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command-home cleanup escaped its exact temporary base".into(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let home = open_verified_macos_short_home_directory(path, effective_uid)?;
    let base = base.canonicalize()?;
    let base_metadata = fs::symlink_metadata(&base)?;
    if !base_metadata.is_dir() || base_metadata.file_type().is_symlink() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS temporary base is not a real directory".into(),
        ));
    }

    // Complete the root whitelist before deleting either recognized provider
    // residue. This prevents an unknown peer entry from being hidden by a
    // partial cleanup of .podman or .ssh.
    for entry in fs::read_dir(path)? {
        let name = entry?.file_name();
        if name != OsStr::new(".podman") && name != OsStr::new(PODMAN_MACOS_SSH_DIRECTORY) {
            return Err(AppError::NotAuthorized(
                "managed runtime macOS command home contained an unexpected entry after machine removal"
                    .into(),
            ));
        }
    }
    let aliases = path.join(".podman");
    match fs::symlink_metadata(&aliases) {
        Ok(_) => {
            remove_expected_macos_ignition_socket_alias(&aliases, effective_uid, machine_name)?;
            fs::remove_dir(&aliases)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Pinned Podman 5.8.2's Go SSH backend creates this empty file before it
    // selects the insecure host-key callback used only for machine connections.
    // Accept only the exact observed empty artifact; it is never provider state.
    remove_expected_macos_known_hosts(path, &home, effective_uid)?;
    if fs::read_dir(path)?.next().transpose()?.is_some() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command home contained an unexpected entry after machine removal"
                .into(),
        ));
    }
    fs::remove_dir(path)?;
    sync_directory(&base)
}

fn managed_path(
    install: &Path,
    target: &ManagedTarget,
    windows_directories: Option<&WindowsSystemDirectories>,
) -> AppResult<OsString> {
    let bin = install.join("bin");
    let rendered = bin.to_str().ok_or_else(|| {
        AppError::Runtime("managed runtime install path is not representable".into())
    })?;
    let path = match target.operating_system {
        ManagedOperatingSystem::Windows => {
            let system32 = &windows_directories
                .ok_or_else(|| {
                    AppError::Internal(
                        "managed Windows PATH did not receive verified system directories".into(),
                    )
                })?
                .system32;
            std::env::join_paths([PathBuf::from(rendered), system32.clone()])
                .map_err(|_| AppError::Runtime("managed Windows runtime PATH is invalid".into()))?
        }
        ManagedOperatingSystem::Linux | ManagedOperatingSystem::Macos => std::env::join_paths([
            PathBuf::from(rendered),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .map_err(|_| AppError::Runtime("managed runtime PATH is invalid".into()))?,
    };
    Ok(path)
}

fn apply_platform_command_environment(
    environment: &mut BTreeMap<OsString, OsString>,
    operating_system: ManagedOperatingSystem,
) {
    let key = OsString::from("NoDefaultCurrentDirectoryInExePath");
    if operating_system == ManagedOperatingSystem::Windows {
        // Go's os/exec honors this process environment switch on Windows and
        // therefore never searches the private current directory ahead of the
        // already constrained managed PATH for helper executables.
        environment.insert(key, OsString::from("1"));
    } else {
        environment.remove(&key);
    }
}

fn toml_string(path: &Path) -> AppResult<String> {
    let value = path.to_str().ok_or_else(|| {
        AppError::Runtime("managed runtime helper path is not representable".into())
    })?;
    Ok(toml_scalar(value))
}

fn toml_scalar(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(windows)]
fn windows_well_known_sid(
    kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> io::Result<WindowsCurrentUserSid> {
    use windows_sys::Win32::Security::{CreateWellKnownSid, IsValidSid, SECURITY_MAX_SID_SIZE};

    let mut storage =
        vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<u32>())];
    let mut length = (storage.len() * std::mem::size_of::<u32>()) as u32;
    // SAFETY: storage is aligned and contains length writable bytes; these
    // well-known SID kinds do not require a domain SID.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateWellKnownSid initialized the SID in storage.
    if unsafe { IsValidSid(storage.as_mut_ptr().cast()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid well-known SID",
        ));
    }
    Ok(WindowsCurrentUserSid { storage })
}

#[cfg(windows)]
fn windows_managed_namespace_error(error: io::Error) -> AppError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        AppError::NotAuthorized(format!(
            "managed runtime Windows namespace is replaceable or unsafe: {error}"
        ))
    } else {
        error.into()
    }
}

#[cfg(windows)]
fn windows_trusted_installer_sid() -> io::Result<WindowsCurrentUserSid> {
    use windows_sys::Win32::Security::IsValidSid;

    // S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464.
    // TrustedInstaller commonly owns/protects Windows volume-root ancestors.
    let subauthorities = [
        80_u32,
        956_008_885,
        3_418_522_649,
        1_831_038_044,
        1_853_292_631,
        2_271_478_464,
    ];
    let byte_length = 8 + subauthorities.len() * std::mem::size_of::<u32>();
    let mut storage = vec![0_u32; byte_length.div_ceil(std::mem::size_of::<u32>())];
    let bytes = unsafe {
        // SAFETY: storage is live, aligned, and byte_length is within its allocation.
        std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), byte_length)
    };
    bytes[0] = 1;
    bytes[1] = subauthorities.len() as u8;
    bytes[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 5]);
    for (index, value) in subauthorities.into_iter().enumerate() {
        let offset = 8 + index * std::mem::size_of::<u32>();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let sid = WindowsCurrentUserSid { storage };
    // SAFETY: the storage above contains a complete aligned SID encoding.
    if unsafe { IsValidSid(sid.as_ptr()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the built-in TrustedInstaller SID encoding is invalid",
        ));
    }
    Ok(sid)
}

#[cfg(windows)]
fn windows_sid_is_trusted_for_managed_namespace(
    sid: windows_sys::Win32::Security::PSID,
    trusted: &[WindowsCurrentUserSid],
) -> bool {
    use windows_sys::Win32::Security::{EqualSid, IsValidSid};

    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return false;
    }
    trusted
        .iter()
        // SAFETY: sid and each trusted SID were validated and remain live.
        .any(|candidate| unsafe { EqualSid(sid, candidate.as_ptr()) } != 0)
}

#[cfg(windows)]
fn windows_basic_ace_sid(
    raw_ace: *mut std::ffi::c_void,
    ace_size: usize,
) -> io::Result<windows_sys::Win32::Security::PSID> {
    use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, GetLengthSid, IsValidSid, PSID};
    use windows_sys::Win32::System::SystemServices::SID_REVISION;

    let sid_offset = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        .checked_sub(std::mem::size_of::<u32>())
        .expect("ACCESS_ALLOWED_ACE contains SidStart");
    let minimum_sid_bytes = 8_usize;
    if ace_size < sid_offset + minimum_sid_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed runtime namespace ancestor has a truncated basic ACE",
        ));
    }
    // Read only the bounded SID header before asking Win32 to validate it.
    // SAFETY: the checks above establish that both header bytes are inside the ACE.
    let sid_bytes = unsafe { raw_ace.cast::<u8>().add(sid_offset) };
    let revision = unsafe { *sid_bytes };
    let subauthority_count = usize::from(unsafe { *sid_bytes.add(1) });
    let sid_length = minimum_sid_bytes
        .checked_add(
            subauthority_count
                .checked_mul(std::mem::size_of::<u32>())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Windows SID size overflowed")
                })?,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Windows SID size overflowed"))?;
    if revision != SID_REVISION as u8
        || sid_offset
            .checked_add(sid_length)
            .is_none_or(|expected| expected != ace_size)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed runtime namespace ancestor has a malformed bounded SID",
        ));
    }
    let sid: PSID = sid_bytes.cast();
    // SAFETY: the SID header-derived length was proven to be exactly bounded by the ACE.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed runtime namespace ancestor has an invalid basic ACE SID",
        ));
    }
    // SAFETY: IsValidSid established that the embedded SID is readable.
    if unsafe { GetLengthSid(sid) } as usize != sid_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed runtime namespace ancestor has a malformed basic ACE",
        ));
    }
    Ok(sid)
}

#[cfg(windows)]
fn verify_windows_managed_namespace_ancestor_handle(
    directory: &File,
    allow_trusted_installer_anchor: bool,
) -> io::Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        GENERIC_MAPPING, GetAce, GetAclInformation, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, INHERIT_ONLY_ACE, IsValidAcl, MapGenericMask,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ALL_ACCESS, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };

    let mut trusted = vec![
        windows_current_user_sid()?,
        windows_well_known_sid(WinLocalSystemSid)?,
        windows_well_known_sid(WinBuiltinAdministratorsSid)?,
    ];
    if allow_trusted_installer_anchor {
        trusted.push(windows_trusted_installer_sid()?);
    }
    let mut descriptor = windows_owner_dacl_security_descriptor(directory)?;
    let security_descriptor = descriptor.as_mut_ptr().cast::<c_void>();

    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: security_descriptor is the live descriptor returned by the kernel.
    if unsafe {
        GetSecurityDescriptorOwner(
            security_descriptor,
            &raw mut owner,
            &raw mut owner_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if !windows_sid_is_trusted_for_managed_namespace(owner, &trusted) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime namespace ancestor has an untrusted Windows owner",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut::<ACL>();
    // SAFETY: security_descriptor is valid and all output pointers are writable.
    if unsafe {
        GetSecurityDescriptorDacl(
            security_descriptor,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if dacl_present == 0 || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime namespace ancestor has no valid Windows DACL",
        ));
    }

    let mut acl_information = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid and acl_information is writable storage of the declared size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let dangerous = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    for index in 0..acl_information.AceCount {
        let mut raw_ace = std::ptr::null_mut::<c_void>();
        // SAFETY: index is bounded by the ACE count returned for this valid ACL.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returned at least an ACE_HEADER inside the live ACL.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if header.AceFlags & (INHERIT_ONLY_ACE as u8) != 0 {
            continue;
        }
        let ace_type = u32::from(header.AceType);
        let ace_size = usize::from(header.AceSize);
        match ace_type {
            ACCESS_ALLOWED_ACE_TYPE => {
                let sid = windows_basic_ace_sid(raw_ace, ace_size)?;
                // SAFETY: the validated basic ACE contains the fixed Mask field.
                let mut mask = unsafe { (*raw_ace.cast::<ACCESS_ALLOWED_ACE>()).Mask };
                // SAFETY: mask and mapping are initialized writable/readable values.
                unsafe { MapGenericMask(&raw mut mask, &raw const mapping) };
                if mask & dangerous != 0
                    && !windows_sid_is_trusted_for_managed_namespace(sid, &trusted)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "managed runtime namespace ancestor grants replacement rights to an untrusted Windows principal",
                    ));
                }
                // Ordinary Users/AppPackages read/execute rules are harmless
                // and remain compatible with LocalAppData/runner temp roots.
            }
            ACCESS_DENIED_ACE_TYPE => {
                // A basic deny ACE cannot grant replacement rights, but still
                // require its encoded SID/size to be structurally exact.
                let _ = windows_basic_ace_sid(raw_ace, ace_size)?;
            }
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "managed runtime namespace ancestor has a conditional or object allow ACE",
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "managed runtime namespace ancestor has an unsupported Windows ACE",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_real_directory_security_handle(path: &Path) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    };

    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains a NUL code unit",
        ));
    }
    encoded.push(0);
    // No FILE_SHARE_DELETE: keep this exact ancestor object pinned while the
    // remaining chain and managed child are opened and verified.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a uniquely owned handle.
    let directory = unsafe { File::from_raw_handle(raw) };
    let information = windows_file_information(&directory)?;
    if information.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime namespace ancestor is not a real directory",
        ));
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_windows_managed_namespace_ancestor(
    path: &Path,
    allow_trusted_installer_anchor: bool,
) -> io::Result<File> {
    let directory = open_windows_real_directory_security_handle(path)?;
    verify_windows_managed_namespace_ancestor_handle(&directory, allow_trusted_installer_anchor)?;
    Ok(directory)
}

#[cfg(windows)]
fn verify_windows_managed_namespace_ancestor_chain(
    canonical_parent: &Path,
) -> io::Result<Vec<File>> {
    let mut guards = Vec::new();
    for ancestor in canonical_parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        guards.push(open_windows_managed_namespace_ancestor(
            ancestor,
            ancestor.parent().is_none(),
        )?);
    }
    if guards.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows managed namespace has no canonical ancestor chain",
        ));
    }
    Ok(guards)
}

#[cfg(windows)]
fn open_or_create_windows_managed_private_directory_guard(
    path: &Path,
    verify_ancestor_chain: bool,
) -> io::Result<(PathBuf, File)> {
    open_or_create_windows_managed_directory_guard(
        path,
        verify_ancestor_chain,
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly,
    )
}

#[cfg(windows)]
fn open_or_create_windows_managed_wsl_distribution_storage_guard(
    path: &Path,
) -> io::Result<(PathBuf, File)> {
    open_or_create_windows_managed_directory_guard(
        path,
        false,
        WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem,
    )
}

#[cfg(windows)]
fn open_or_create_windows_managed_directory_guard(
    path: &Path,
    verify_ancestor_chain: bool,
    policy: WindowsManagedDirectoryAclPolicy,
) -> io::Result<(PathBuf, File)> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{FALSE, INVALID_HANDLE_VALUE, TRUE};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
        InitializeAcl, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

    let user = windows_current_user_sid()?;
    let local_system = if policy == WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem {
        let local_system = windows_local_system_sid()?;
        // SAFETY: both SID wrappers own valid, live SID storage.
        if unsafe { windows_sys::Win32::Security::EqualSid(user.as_ptr(), local_system.as_ptr()) }
            != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed WSL storage cannot use LocalSystem as its interactive owner",
            ));
        }
        Some(local_system)
    } else {
        None
    };
    let mut acl_bytes = std::mem::size_of::<ACL>();
    let mut append_ace_size = |sid: windows_sys::Win32::Security::PSID| -> io::Result<()> {
        // SAFETY: each pointer comes from a validated SID wrapper that remains live.
        let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
        let ace_bytes = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            .checked_sub(std::mem::size_of::<u32>())
            .and_then(|size| size.checked_add(sid_length))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Windows ACE size overflowed")
            })?;
        acl_bytes = acl_bytes.checked_add(ace_bytes).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Windows ACL size overflowed")
        })?;
        Ok(())
    };
    append_ace_size(user.as_ptr())?;
    if let Some(local_system) = local_system.as_ref() {
        append_ace_size(local_system.as_ptr())?;
    }
    let acl_bytes = acl_bytes
        .checked_add(std::mem::size_of::<u32>() - 1)
        .map(|size| size & !(std::mem::size_of::<u32>() - 1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Windows ACL size overflowed"))?;
    let acl_length = u32::try_from(acl_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Windows ACL is too large"))?;
    let mut acl = vec![0_u32; acl_bytes.div_ceil(std::mem::size_of::<u32>())];
    // SAFETY: acl is DWORD-aligned and has acl_length writable bytes.
    if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_length, ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    // SAFETY: the ACL was initialized and user owns a valid SID. The ACE
    // applies to this directory and is inherited by its child files/directories.
    if unsafe {
        AddAccessAllowedAceEx(
            acl.as_mut_ptr().cast(),
            ACL_REVISION,
            inheritance,
            FILE_ALL_ACCESS,
            user.as_ptr(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if let Some(local_system) = local_system.as_ref() {
        // SAFETY: the ACL remains initialized and local_system owns a valid
        // SID. This second inheritable ACE is present only for WSL's
        // distribution-storage service boundary.
        if unsafe {
            AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                inheritance,
                FILE_ALL_ACCESS,
                local_system.as_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    // SAFETY: descriptor is correctly sized writable storage.
    if unsafe {
        InitializeSecurityDescriptor(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is initialized and user remains live through directory creation.
    if unsafe {
        SetSecurityDescriptorOwner(
            std::ptr::addr_of_mut!(descriptor).cast(),
            user.as_ptr(),
            FALSE,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor and ACL are initialized and remain live through creation.
    if unsafe {
        SetSecurityDescriptorDacl(
            std::ptr::addr_of_mut!(descriptor).cast(),
            TRUE,
            acl.as_ptr().cast(),
            FALSE,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is initialized; protection prevents parent ACEs from
    // being merged into the app-created namespace.
    if unsafe {
        SetSecurityDescriptorControl(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::addr_of_mut!(descriptor).cast(),
        bInheritHandle: FALSE,
    };

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows managed private directory has no parent",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows managed private directory has no final component",
        )
    })?;
    let canonical_parent = if parent.as_os_str().is_empty() {
        Path::new(".").canonicalize()?
    } else {
        parent.canonicalize()?
    };
    // Validate every canonical ancestor through the volume/share root. A
    // protected child DACL alone cannot stop FILE_DELETE_CHILD granted by any
    // ancestor from redirecting the caller-supplied namespace path.
    let _ancestor_guards = if verify_ancestor_chain {
        verify_windows_managed_namespace_ancestor_chain(&canonical_parent)?
    } else {
        Vec::new()
    };
    let exact_path = canonical_parent.join(file_name);
    let mut encoded = exact_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains a NUL code unit",
        ));
    }
    encoded.push(0);
    // SAFETY: encoded is NUL-terminated; attributes and all descriptor backing
    // storage remain live for this call.
    let created = unsafe { CreateDirectoryW(encoded.as_ptr(), &raw const attributes) };
    if created == 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }

    // Open the exact final component without traversing a junction and without
    // sharing delete while ownership, type, and DACL are verified by handle.
    // SAFETY: encoded remains NUL-terminated and live for this call.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a uniquely owned directory handle.
    let directory = unsafe { File::from_raw_handle(raw) };
    let information = windows_file_information(&directory)?;
    if information.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime path is not a real directory",
        ));
    }
    let inheritance =
        u8::try_from(inheritance).expect("Windows inheritance flags fit in an ACE header");
    match policy {
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly => {
            verify_windows_current_user_only_dacl_with_ace_flags(&directory, inheritance)?;
        }
        WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem => {
            verify_windows_wsl_distribution_storage_dacl_with_ace_flags(&directory, inheritance)?;
        }
    }
    Ok((exact_path, directory))
}

#[cfg(windows)]
fn ensure_windows_managed_private_directory(path: &Path) -> io::Result<()> {
    drop(open_or_create_windows_managed_private_directory_guard(
        path, false,
    )?);
    Ok(())
}

#[cfg(windows)]
fn ensure_windows_managed_wsl_distribution_storage_directory(path: &Path) -> io::Result<()> {
    drop(open_or_create_windows_managed_wsl_distribution_storage_guard(path)?);
    Ok(())
}

fn ensure_managed_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        ensure_windows_managed_private_directory(path)
    }
    #[cfg(not(windows))]
    {
        ensure_private_directory(path)
    }
}

fn ensure_managed_wsl_distribution_storage_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        ensure_windows_managed_wsl_distribution_storage_directory(path)
    }
    #[cfg(not(windows))]
    {
        ensure_managed_private_directory(path)
    }
}

fn ensure_private_directory_tree(root: &Path, destination: &Path) -> AppResult<()> {
    if !destination.starts_with(root) {
        return Err(AppError::NotAuthorized(
            "managed runtime directory escaped its staging root".into(),
        ));
    }
    let relative = destination.strip_prefix(root).map_err(|_| {
        AppError::NotAuthorized("managed runtime directory escaped its staging root".into())
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(AppError::NotAuthorized(
                "managed runtime directory contains an unsafe component".into(),
            ));
        };
        current.push(component);
        ensure_managed_private_directory(&current)?;
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime path is not a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn canonical_real_directory(path: &Path, label: &str) -> AppResult<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::NotAvailable(format!("{label} directory is unavailable: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(format!(
            "{label} directory must be a real directory"
        )));
    }
    path.canonicalize().map_err(AppError::from)
}

#[cfg(windows)]
fn create_windows_private_file(path: &Path) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{FALSE, INVALID_HANDLE_VALUE, TRUE};
    use windows_sys::Win32::Security::{
        CONTAINER_INHERIT_ACE, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

    let user = windows_current_user_sid()?;
    let creation_acl = windows_current_user_only_acl(&user)?;

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    // SAFETY: descriptor is correctly sized writable storage and revision is
    // the version supported by InitializeSecurityDescriptor.
    if unsafe {
        InitializeSecurityDescriptor(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor was initialized and user owns a valid SID which stays
    // live until CreateFileW returns.
    if unsafe {
        SetSecurityDescriptorOwner(
            std::ptr::addr_of_mut!(descriptor).cast(),
            user.as_ptr(),
            FALSE,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor and ACL are initialized and remain live through the
    // CreateFileW call.
    if unsafe {
        SetSecurityDescriptorDacl(
            std::ptr::addr_of_mut!(descriptor).cast(),
            TRUE,
            creation_acl.as_ptr(),
            FALSE,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is initialized; setting SE_DACL_PROTECTED prevents
    // permissive inheritable parent ACEs from being merged into this DACL.
    if unsafe {
        SetSecurityDescriptorControl(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::addr_of_mut!(descriptor).cast(),
        bInheritHandle: FALSE,
    };

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows private file path has no parent",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows private file path has no file name",
        )
    })?;
    // Rust's Windows canonicalize returns an absolute verbatim path. Resolve
    // only the existing parent because CREATE_NEW requires the final file to be
    // absent, then append the exact final component. This preserves long-path
    // support and avoids interpreting a relative path in CreateFileW.
    let canonical_parent = if parent.as_os_str().is_empty() {
        Path::new(".").canonicalize()?
    } else {
        parent.canonicalize()?
    };
    // A Windows filesystem can replace a caller-provided creation DACL with
    // inherited ACEs even while reporting successful descriptor application.
    // Pin and verify the exact immediate parent before creating any entry so
    // an unsafe namespace fails closed with no transient secret file.
    let parent_guard = open_windows_real_directory_security_handle(&canonical_parent)?;
    let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    verify_windows_current_user_only_dacl_with_ace_flags(
        &parent_guard,
        u8::try_from(inheritance).expect("Windows inheritance flags fit in an ACE header"),
    )?;
    let creation_path = canonical_parent.join(file_name);
    let mut encoded = creation_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains a NUL code unit",
        ));
    }
    encoded.push(0);
    // SAFETY: encoded is NUL-terminated; attributes points to a live descriptor
    // whose SID and ACL storage also remain live for the call.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            FILE_SHARE_NONE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a uniquely owned file handle.
    let file = unsafe { File::from_raw_handle(raw) };
    let secure = (|| {
        let information = windows_file_information(&file)?;
        if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || information.number_of_links != 1
            || information.size != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "new Windows private file is not an empty unlinked regular file",
            ));
        }
        verify_windows_current_user_only_dacl(&file)
    })();
    if let Err(error) = secure {
        let cleanup = mark_windows_file_handle_for_deletion(&file);
        drop(file);
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => io::Error::new(
                error.kind(),
                format!(
                    "{error}; empty Windows private staging file cleanup also failed: {cleanup}"
                ),
            ),
        });
    }
    // Keep the no-share-delete parent handle live through the child's strict
    // readback so its checked namespace component cannot be swapped mid-create.
    drop(parent_guard);
    Ok(file)
}

fn create_private_file(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        create_windows_private_file(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    }
}

fn open_private_download_file(path: &Path, append: bool) -> AppResult<File> {
    if path.exists() {
        verify_regular_file(path, "managed runtime partial download")?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn open_nofollow_lock_file(path: &Path) -> AppResult<File> {
    if path.exists() {
        verify_regular_file(path, "managed runtime lifecycle lock")?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AppError::NotAuthorized(
            "managed runtime lifecycle lock is not a regular file".into(),
        ));
    }
    Ok(file)
}

fn regular_file_length_or_zero(path: &Path) -> AppResult<u64> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AppError::NotAuthorized(
                    "managed runtime partial download is not a regular file".into(),
                ));
            }
            Ok(metadata.len())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn set_installed_permissions(path: &Path, executable: bool) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }),
        )?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(!executable);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> AppResult<()> {
    if bytes.len() > 64 * 1024 {
        return Err(AppError::Runtime(
            "managed runtime configuration is oversized".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Runtime("managed runtime configuration has no parent".into()))?;
    ensure_managed_private_directory(parent)?;
    if path.exists() {
        verify_regular_file(path, "managed runtime configuration")?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.len() > 64 * 1024 {
            return Err(AppError::NotAuthorized(
                "managed runtime configuration is unexpectedly oversized".into(),
            ));
        }
        let mut existing = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?
            .take(64 * 1024 + 1)
            .read_to_end(&mut existing)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(AppError::NotAuthorized(
            "managed runtime immutable configuration differs from its release contract".into(),
        ));
    }
    let temporary = parent.join(format!(".config-{}", Uuid::new_v4()));
    let result = (|| {
        let mut file = create_private_file(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        // Windows cannot rename a file while its FILE_SHARE_NONE writer is open.
        drop(file);
        fs::rename(&temporary, path)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = remove_regular_file(&temporary);
    }
    result
}

fn remove_regular_file(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AppError::NotAuthorized(
                    "managed runtime refused to remove a non-regular file".into(),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn private_entry_exists(path: &Path) -> AppResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn private_tree_removal_parent(path: &Path, expected_parent: &Path) -> AppResult<PathBuf> {
    let parent = canonical_real_directory(expected_parent, "managed runtime versions")?;
    let requested_parent = path
        .parent()
        .ok_or_else(|| {
            AppError::NotAuthorized("managed runtime removal path has no parent".into())
        })?
        .canonicalize()?;
    if requested_parent != parent {
        return Err(AppError::NotAuthorized(
            "managed runtime payload removal escaped its private parent".into(),
        ));
    }
    Ok(parent)
}

/// Removes one exact backend-owned entry without following a symlink. A
/// corrupted install/cache path may itself be a file or symlink; refusing to
/// unlink that directory entry would permanently wedge verified repair.
fn remove_private_tree(path: &Path, expected_parent: &Path) -> AppResult<()> {
    let parent = private_tree_removal_parent(path, expected_parent)?;
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        let _ = metadata;
        remove_windows_private_entry_tree(path, WindowsPrivateFileDeletePolicy::Immediate)?;
        sync_directory(&parent)?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        if !metadata.is_dir() {
            fs::remove_file(path)?;
            sync_directory(&parent)?;
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let canonical = path.canonicalize()?;
        if canonical.parent() != Some(parent.as_path()) {
            return Err(AppError::NotAuthorized(
                "managed runtime payload removal escaped the versions directory".into(),
            ));
        }
        #[cfg(unix)]
        make_tree_owner_writable(&canonical)?;
        fs::remove_dir_all(canonical)?;
        sync_directory(&parent)?;
        Ok(())
    }
}

fn remove_provider_home_after_machine_removal(
    path: &Path,
    expected_parent: &Path,
    timeout: Duration,
    poll: Duration,
) -> AppResult<()> {
    #[cfg(windows)]
    {
        remove_provider_home_after_machine_removal_with_timing(path, expected_parent, timeout, poll)
    }
    #[cfg(not(windows))]
    {
        let _ = (timeout, poll);
        remove_private_tree(path, expected_parent)
    }
}

#[cfg(windows)]
fn remove_provider_home_after_machine_removal_with_timing(
    path: &Path,
    expected_parent: &Path,
    timeout: Duration,
    poll: Duration,
) -> AppResult<()> {
    if poll.is_zero() {
        return Err(AppError::Internal(
            "managed Windows WSL provider deletion poll interval was zero".into(),
        ));
    }
    let parent = private_tree_removal_parent(path, expected_parent)?;
    let _ = fs::symlink_metadata(path)?;
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        AppError::Internal("managed Windows WSL provider deletion deadline overflowed".into())
    })?;
    remove_windows_private_entry_tree(
        path,
        WindowsPrivateFileDeletePolicy::RetrySharingViolation { deadline, poll },
    )?;
    sync_directory(&parent)
}

#[cfg(unix)]
fn make_tree_owner_writable(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    // Make each directory traversable before attempting read_dir or descent;
    // corruption may have removed every permission bit.
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            // remove_dir_all unlinks a child symlink rather than following it;
            // do not chmod or canonicalize its target.
            continue;
        }
        if metadata.is_dir() {
            make_tree_owner_writable(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WindowsPrivateFileDeletePolicy {
    Immediate,
    RetrySharingViolation { deadline: Instant, poll: Duration },
}

#[cfg(windows)]
fn remove_windows_private_entry_tree(
    path: &Path,
    delete_policy: WindowsPrivateFileDeletePolicy,
) -> AppResult<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let metadata = fs::symlink_metadata(path)?;
    let attributes = metadata.file_attributes();
    let directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;

    if directory && !reparse {
        set_windows_entry_readonly_nofollow(path, false)?;
        for entry in fs::read_dir(path)? {
            remove_windows_private_entry_tree(&entry?.path(), delete_policy)?;
        }
        set_windows_entry_readonly_nofollow(path, false)?;
        fs::remove_dir(path)?;
    } else {
        // FILE_FLAG_OPEN_REPARSE_POINT ensures the attribute update targets
        // the link/junction entry itself. DeleteFileW/RemoveDirectoryW then
        // unlink that entry rather than traversing its target.
        if directory {
            set_windows_entry_readonly_nofollow(path, false)?;
            fs::remove_dir(path)?;
        } else {
            remove_windows_private_file(path, delete_policy)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_error_is_sharing_violation(error: &io::Error) -> bool {
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32)
}

#[cfg(windows)]
fn remove_windows_private_file(
    path: &Path,
    delete_policy: WindowsPrivateFileDeletePolicy,
) -> AppResult<()> {
    loop {
        match set_windows_entry_readonly_nofollow(path, false) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error)
                if windows_error_is_sharing_violation(&error)
                    && matches!(
                        delete_policy,
                        WindowsPrivateFileDeletePolicy::RetrySharingViolation { .. }
                    ) =>
            {
                let WindowsPrivateFileDeletePolicy::RetrySharingViolation { deadline, poll } =
                    delete_policy
                else {
                    unreachable!("sharing-violation retry policy was matched above")
                };
                let now = Instant::now();
                if now >= deadline {
                    return Err(AppError::Runtime(format!(
                        "managed Windows WSL provider storage remained in use after its bounded release wait; retaining remaining provider, installation, and image-cache state for a safe retry: {error}"
                    )));
                }
                thread::sleep(poll.min(deadline.saturating_duration_since(now)));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(windows)]
fn set_windows_entry_readonly_nofollow(path: &Path, readonly: bool) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileBasicInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING, SetFileInformationByHandle,
    };

    let encoded = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: `encoded` is NUL-terminated and lives for the call. The returned
    // owned handle is closed exactly once below.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` was returned by CreateFileW and is now uniquely owned.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut information = FILE_BASIC_INFO::default();
    // SAFETY: the handle is valid and the output buffer has the declared size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileBasicInfo,
            (&raw mut information).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let has_readonly = information.FileAttributes & FILE_ATTRIBUTE_READONLY != 0;
    if has_readonly == readonly {
        return Ok(());
    }
    if readonly {
        information.FileAttributes &= !FILE_ATTRIBUTE_NORMAL;
        information.FileAttributes |= FILE_ATTRIBUTE_READONLY;
    } else {
        information.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
        if information.FileAttributes == 0 {
            information.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        }
    }
    // SAFETY: the handle was opened with FILE_WRITE_ATTRIBUTES and the input
    // buffer is a fully initialized FILE_BASIC_INFO value.
    if unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle(),
            FileBasicInfo,
            (&raw const information).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sync_directory(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn success(stdout: impl Into<Vec<u8>>) -> ManagedCommandOutput {
        ManagedCommandOutput {
            status: ExitStatus::from_raw(0),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    fn failure(stderr: impl Into<Vec<u8>>) -> ManagedCommandOutput {
        #[cfg(unix)]
        let status = ExitStatus::from_raw(1 << 8);
        #[cfg(windows)]
        let status = ExitStatus::from_raw(1);
        ManagedCommandOutput {
            status,
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }

    fn utf16le(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[cfg(unix)]
    fn direct_unix_test_command(
        working_directory: &Path,
        environment: BTreeMap<OsString, OsString>,
    ) -> ManagedRuntimeCommand {
        ManagedRuntimeCommand {
            binary: PathBuf::from("/bin/sh"),
            environment,
            working_directory: working_directory.to_path_buf(),
            runtime_version: "test".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
        }
    }

    #[cfg(unix)]
    fn assert_unix_process_is_reaped(pid: i32) {
        let reap_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let gone = unsafe { libc::kill(pid, 0) } == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            if gone {
                return;
            }
            assert!(
                Instant::now() < reap_deadline,
                "managed runtime descendant survived process-group termination"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    #[test]
    fn direct_command_zero_deadline_cannot_report_a_fast_exit_as_success() {
        let temp = TempDir::new().expect("temporary root");
        let command = direct_unix_test_command(temp.path(), BTreeMap::new());
        let started = Instant::now();

        let error = DirectManagedCommandRunner
            .output(
                &command,
                &[OsString::from("-c"), OsString::from("exit 0")],
                Duration::ZERO,
            )
            .expect_err("a zero-deadline command must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("command exceeded its deadline"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn command_cleanup_failure_preserves_the_primary_error_kind() {
        let error = managed_command_error_with_cleanup(
            managed_command_deadline_error(),
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture cleanup denial",
            )),
        );

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("fixture cleanup denial"));
        assert!(error.to_string().contains("cleanup also failed"));
    }

    #[cfg(windows)]
    fn set_windows_permissive_inheritable_dacl(path: &Path) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::TRUE;
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, InitializeAcl,
            InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, SECURITY_DESCRIPTOR,
            SECURITY_MAX_SID_SIZE, SetFileSecurityW, SetSecurityDescriptorDacl, WinWorldSid,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

        let mut everyone =
            vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<u32>())];
        let mut everyone_size = (everyone.len() * std::mem::size_of::<u32>()) as u32;
        // SAFETY: everyone is an aligned writable buffer of everyone_size bytes;
        // WinWorldSid does not require a domain SID.
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinWorldSid,
                    std::ptr::null_mut(),
                    everyone.as_mut_ptr().cast(),
                    &raw mut everyone_size,
                )
            },
            0,
            "create Everyone SID: {}",
            io::Error::last_os_error()
        );
        let acl_bytes = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            - std::mem::size_of::<u32>()
            + everyone_size as usize;
        let mut acl = vec![0_u32; acl_bytes.div_ceil(std::mem::size_of::<u32>())];
        // SAFETY: acl is DWORD-aligned and provides at least acl_bytes writable bytes.
        assert_ne!(
            unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_bytes as u32, ACL_REVISION) },
            0,
            "initialize permissive parent ACL: {}",
            io::Error::last_os_error()
        );
        // SAFETY: acl is initialized and everyone contains a valid SID.
        assert_ne!(
            unsafe {
                AddAccessAllowedAceEx(
                    acl.as_mut_ptr().cast(),
                    ACL_REVISION,
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                    FILE_ALL_ACCESS,
                    everyone.as_mut_ptr().cast(),
                )
            },
            0,
            "add permissive inheritable parent ACE: {}",
            io::Error::last_os_error()
        );

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        // SAFETY: descriptor is correctly sized writable storage.
        assert_ne!(
            unsafe {
                InitializeSecurityDescriptor(
                    std::ptr::addr_of_mut!(descriptor).cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                )
            },
            0,
            "initialize permissive parent descriptor: {}",
            io::Error::last_os_error()
        );
        // SAFETY: descriptor and acl are initialized and remain live for SetFileSecurityW.
        assert_ne!(
            unsafe {
                SetSecurityDescriptorDacl(
                    std::ptr::addr_of_mut!(descriptor).cast(),
                    TRUE,
                    acl.as_ptr().cast(),
                    0,
                )
            },
            0,
            "attach permissive parent DACL: {}",
            io::Error::last_os_error()
        );
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        assert!(!encoded.contains(&0), "fixture path contains NUL");
        encoded.push(0);
        // SAFETY: encoded is NUL-terminated and descriptor references the live ACL.
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    encoded.as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    std::ptr::addr_of_mut!(descriptor).cast(),
                )
            },
            0,
            "set permissive parent DACL: {}",
            io::Error::last_os_error()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_manager_rejects_a_replaceable_data_root_without_rewriting_its_acl() {
        let temp = TempDir::new().expect("temporary root");
        let data_root = temp.path().join("user-selected-data-root");
        fs::create_dir(&data_root).expect("data root");
        set_windows_permissive_inheritable_dacl(&data_root);

        let before_handle =
            open_windows_real_directory_security_handle(&data_root).expect("open data root");
        let before = windows_owner_dacl_security_descriptor(&before_handle)
            .expect("snapshot permissive data-root ACL");
        drop(before_handle);

        let state_root = data_root.join("managed-runtime");
        let error = ManagedRuntimeManager::open(
            &data_root,
            temp.path(),
            &temp.path().join("unreachable-manifest.json"),
        )
        .expect_err("replaceable caller-owned data root must fail closed in the constructor");
        assert!(matches!(error, AppError::NotAuthorized(_)));
        assert!(!state_root.exists());

        let after_handle =
            open_windows_real_directory_security_handle(&data_root).expect("reopen data root");
        let after = windows_owner_dacl_security_descriptor(&after_handle)
            .expect("snapshot data-root ACL after rejection");
        assert_eq!(
            after, before,
            "constructor rejection must not rewrite the caller-owned data root"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_state_root_guard_pins_a_canonical_protected_directory() {
        use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        };

        let temp = TempDir::new().expect("temporary root");
        let data_root = temp.path().join("ordinary-data-root");
        fs::create_dir(&data_root).expect("ordinary data root");
        let requested_state_root = data_root.join("managed-runtime");

        let (canonical_state_root, guard) =
            open_or_create_windows_managed_private_directory_guard(&requested_state_root, true)
                .expect("create canonical protected state-root guard");

        assert_eq!(
            canonical_state_root,
            requested_state_root
                .canonicalize()
                .expect("canonical state root")
        );
        let information = windows_file_information(&guard).expect("guard information");
        assert_ne!(information.attributes & FILE_ATTRIBUTE_DIRECTORY, 0);
        assert_eq!(information.attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0);
        verify_windows_current_user_only_dacl_with_ace_flags(
            &guard,
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        )
        .expect("guarded state root has the exact protected DACL");
    }

    #[cfg(windows)]
    #[test]
    fn windows_runtime_command_precreates_the_exact_private_podman_machine_namespace() {
        use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        assert_eq!(target.operating_system, ManagedOperatingSystem::Windows);

        fixture
            .manager
            .runtime_command(target)
            .expect("prepare managed command namespace");

        assert!(
            fixture.commands.calls().is_empty(),
            "namespace must be complete before the first provider command"
        );
        let provider_home = fixture.manager.provider_home();
        let identity_parent = fixture
            .manager
            .machine_ssh_identity_path()
            .parent()
            .expect("identity parent")
            .to_path_buf();
        let config = provider_home.join("config");
        let data = provider_home.join("data");
        let machine_provider_data = data
            .join("containers")
            .join("podman")
            .join("machine")
            .join(target.provider.argument());
        let expected = [
            provider_home.clone(),
            provider_home.join("cache"),
            provider_home.join("run"),
            provider_home.join("run").join("podman"),
            config.clone(),
            config.join("containers"),
            config.join("containers").join("podman"),
            config.join("containers").join("podman").join("machine"),
            config
                .join("containers")
                .join("podman")
                .join("machine")
                .join(target.provider.argument()),
            data.clone(),
            data.join("containers"),
            data.join("containers").join("podman"),
            identity_parent,
            machine_provider_data.clone(),
            machine_provider_data.join("cache"),
        ];
        let inheritance = u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            .expect("inheritance flags fit in an ACE header");
        for directory in expected {
            let handle = open_windows_real_directory_security_handle(&directory)
                .unwrap_or_else(|error| panic!("open {}: {error}", directory.display()));
            verify_windows_current_user_only_dacl_with_ace_flags(&handle, inheritance)
                .unwrap_or_else(|error| panic!("verify {}: {error}", directory.display()));
        }

        let distribution_storage =
            machine_provider_data.join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY);
        let distribution_storage_handle =
            open_windows_real_directory_security_handle(&distribution_storage)
                .unwrap_or_else(|error| panic!("open {}: {error}", distribution_storage.display()));
        verify_windows_wsl_distribution_storage_dacl_with_ace_flags(
            &distribution_storage_handle,
            inheritance,
        )
        .unwrap_or_else(|error| panic!("verify {}: {error}", distribution_storage.display()));
        assert!(
            verify_windows_current_user_only_dacl_with_ace_flags(
                &distribution_storage_handle,
                inheritance,
            )
            .is_err(),
            "WSL distribution storage must have the narrow LocalSystem exception"
        );
        assert!(
            !private_entry_exists(&distribution_storage.join(machine_name(target))).unwrap(),
            "the product must leave the per-machine import target for WSL to create"
        );
    }

    #[cfg(unix)]
    #[test]
    fn direct_command_timeout_bounds_inherited_pipes_and_terminates_the_process_group() {
        let temp = TempDir::new().expect("temporary root");
        let pid_file = temp.path().join("descendant.pid");
        let command = direct_unix_test_command(
            temp.path(),
            BTreeMap::from([(OsString::from("PID_FILE"), pid_file.as_os_str().to_owned())]),
        );
        let args = [
            OsString::from("-c"),
            OsString::from(
                "/bin/sleep 30 & child=$!; printf '%s' \"$child\" > \"$PID_FILE\"; wait",
            ),
        ];
        let started = Instant::now();

        let error = DirectManagedCommandRunner
            .output(&command, &args, Duration::from_millis(250))
            .expect_err("inherited pipes must not outlive the command deadline");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("command exceeded its deadline"));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "bounded post-kill drain must return promptly"
        );
        let pid = fs::read_to_string(pid_file)
            .expect("descendant pid")
            .parse::<i32>()
            .expect("numeric descendant pid");
        assert_unix_process_is_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn direct_command_bounds_a_pipe_inherited_after_the_leader_exits() {
        let temp = TempDir::new().expect("temporary root");
        let pid_file = temp.path().join("descendant.pid");
        let command = direct_unix_test_command(
            temp.path(),
            BTreeMap::from([(OsString::from("PID_FILE"), pid_file.as_os_str().to_owned())]),
        );
        let args = [
            OsString::from("-c"),
            OsString::from("/bin/sleep 30 & child=$!; printf '%s' \"$child\" > \"$PID_FILE\""),
        ];
        let started = Instant::now();

        let error = DirectManagedCommandRunner
            .output(&command, &args, Duration::from_millis(250))
            .expect_err("a successful leader must not leave inherited pipes unbounded");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("output pipes did not close"));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "inherited-pipe cleanup must remain bounded"
        );
        let pid = fs::read_to_string(pid_file)
            .expect("descendant pid")
            .parse::<i32>()
            .expect("numeric descendant pid");
        assert_unix_process_is_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn managed_memory_capture_never_joins_a_pipe_with_a_live_writer() {
        use std::os::unix::net::UnixStream;

        let (reader, writer) = UnixStream::pair().expect("capture pipe pair");
        let mut capture = spawn_bounded_capture(
            reader,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(false)),
            1024,
        );
        let started = Instant::now();

        let error = capture
            .finish_by(Instant::now() + Duration::from_millis(100))
            .expect_err("live inherited writer must hit the bounded drain deadline");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(writer);
        assert_eq!(
            capture
                .finish_by(Instant::now() + Duration::from_secs(1))
                .expect("capture must join after its writer closes"),
            Vec::<u8>::new()
        );
        assert!(capture.worker.is_none());
    }

    #[derive(Default)]
    struct FakeCommands {
        calls: Mutex<Vec<Vec<String>>>,
        commands: Mutex<Vec<ManagedRuntimeCommand>>,
        timeouts: Mutex<Vec<Duration>>,
        outputs: Mutex<VecDeque<ManagedCommandOutput>>,
    }

    impl FakeCommands {
        fn push(&self, output: ManagedCommandOutput) {
            self.outputs.lock().expect("outputs").push_back(output);
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().expect("calls").clone()
        }

        #[cfg(windows)]
        fn commands(&self) -> Vec<ManagedRuntimeCommand> {
            self.commands.lock().expect("commands").clone()
        }

        fn timeouts(&self) -> Vec<Duration> {
            self.timeouts.lock().expect("timeouts").clone()
        }
    }

    impl ManagedCommandRunner for FakeCommands {
        fn output(
            &self,
            command: &ManagedRuntimeCommand,
            args: &[OsString],
            timeout: Duration,
        ) -> io::Result<ManagedCommandOutput> {
            self.calls.lock().expect("calls").push(
                args.iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            );
            self.commands
                .lock()
                .expect("commands")
                .push(command.clone());
            self.timeouts.lock().expect("timeouts").push(timeout);
            self.outputs
                .lock()
                .expect("outputs")
                .pop_front()
                .ok_or_else(|| io::Error::other("no fake output"))
        }
    }

    struct FakeDownloader {
        bytes: Vec<u8>,
        calls: Mutex<usize>,
    }

    impl ManagedArtifactDownloader for FakeDownloader {
        fn acquire(
            &self,
            image: &ManagedMachineImage,
            destination: &Path,
            progress: &mut dyn FnMut(u64, u64, u64) -> AppResult<()>,
        ) -> AppResult<()> {
            *self.calls.lock().expect("calls") += 1;
            let mut file = open_private_download_file(destination, false)?;
            file.write_all(&self.bytes)?;
            file.sync_all()?;
            progress(self.bytes.len() as u64, image.size_bytes, 0)?;
            Ok(())
        }
    }

    struct Fixture {
        manager: ManagedRuntimeManager,
        // Drop the manager's Windows namespace guard before TempDir removes
        // the fixture tree.
        _temp: TempDir,
        commands: Arc<FakeCommands>,
        #[cfg(windows)]
        downloader: Arc<FakeDownloader>,
        image: Vec<u8>,
    }

    #[cfg(all(unix, target_os = "linux"))]
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Ok(runtime) = self.manager.linux_short_runtime_directory() {
                let _ = remove_linux_short_runtime_directory_at(
                    &runtime,
                    Path::new(LINUX_SHORT_RUNTIME_BASE),
                    effective_uid(),
                );
            }
        }
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().expect("temp");
        let resources = temp.path().join("resources");
        let app_data = temp.path().join("app-data");
        fs::create_dir(&app_data).expect("app data");
        let state = app_data.join("managed-runtime");
        fs::create_dir(&resources).expect("resources");
        let bin = resources.join("bin");
        fs::create_dir(&bin).expect("bin");
        let driver = bin.join("podman");
        fs::write(&driver, b"managed-podman-driver").expect("driver");
        let image = b"pinned-machine-image".to_vec();
        let operating_system = ManagedOperatingSystem::current().expect("supported test OS");
        let architecture = ManagedArchitecture::current().expect("supported test arch");
        let provider = match operating_system {
            ManagedOperatingSystem::Linux => ManagedMachineProvider::Qemu,
            ManagedOperatingSystem::Macos => ManagedMachineProvider::Applehv,
            ManagedOperatingSystem::Windows => ManagedMachineProvider::Wsl,
        };
        let manifest = ManagedRuntimeManifest {
            schema_version: "2".into(),
            bundle_id: "podman-machine".into(),
            runtime_version: "5.8.2".into(),
            driver_path: "bin/podman".into(),
            files: vec![ManagedRuntimeFile {
                path: "bin/podman".into(),
                sha256: sha256_bytes(b"managed-podman-driver"),
                size_bytes: b"managed-podman-driver".len() as u64,
                executable: true,
            }],
            components: vec![
                ManagedRuntimeComponent {
                    id: "podman".into(),
                    name: "Podman remote client".into(),
                    version: "5.8.2".into(),
                    repository_url: "https://github.com/containers/podman".into(),
                    source_revision: "5b263b5".into(),
                    license_spdx: "Apache-2.0".into(),
                    relationship: "Bundled rootless machine client".into(),
                    artifacts: vec![ManagedRuntimeComponentArtifact {
                        delivery: ManagedRuntimeArtifactDelivery::BundledFile,
                        locator: "bin/podman".into(),
                        sha256: sha256_bytes(b"managed-podman-driver"),
                        size_bytes: b"managed-podman-driver".len() as u64,
                    }],
                    source_archive: None,
                },
                ManagedRuntimeComponent {
                    id: "podman-machine-os".into(),
                    name: "Podman machine OS".into(),
                    version: "5.8.2".into(),
                    repository_url: "https://github.com/containers/podman-machine-os".into(),
                    source_revision: "08298cbc1d1d5440fb0f071470b35abc37d31050".into(),
                    license_spdx: "Apache-2.0".into(),
                    relationship: "Pinned VM image downloaded on first setup".into(),
                    artifacts: vec![ManagedRuntimeComponentArtifact {
                        delivery: ManagedRuntimeArtifactDelivery::RuntimeDownload,
                        locator: "https://github.com/podman-container-tools/podman-machine-os/releases/download/v5.8.2/machine.zst".into(),
                        sha256: sha256_bytes(&image),
                        size_bytes: image.len() as u64,
                    }],
                    source_archive: None,
                },
            ],
            targets: vec![ManagedTarget {
                operating_system,
                architecture,
                provider,
                machine_image: ManagedMachineImage {
                    url: "https://github.com/podman-container-tools/podman-machine-os/releases/download/v5.8.2/machine.zst".into(),
                    sha256: sha256_bytes(&image),
                    size_bytes: image.len() as u64,
                },
                prerequisite: None,
            }],
            resources: ManagedMachineResources {
                cpus: 2,
                memory_mb: 4096,
                disk_size_gb: 40,
            },
            source: ManagedRuntimeSource {
                repository_url: "https://github.com/containers/podman".into(),
                source_revision: "5b263b5".into(),
                license_spdx: "Apache-2.0".into(),
            },
        };
        let encoded = serde_json::to_vec(&manifest).expect("manifest");
        let loaded = LoadedManagedRuntimeManifest::parse(&encoded).expect("loaded");
        let commands = Arc::new(FakeCommands::default());
        let downloader = Arc::new(FakeDownloader {
            bytes: image.clone(),
            calls: Mutex::new(0),
        });
        let manager = ManagedRuntimeManager::with_backends(
            state,
            resources,
            loaded,
            commands.clone(),
            downloader.clone(),
        )
        .expect("manager");
        Fixture {
            _temp: temp,
            manager,
            commands,
            #[cfg(windows)]
            downloader,
            image,
        }
    }

    fn machine_json(manager: &ManagedRuntimeManager, running: bool) -> Vec<u8> {
        let target = manager.loaded.target().expect("target");
        serde_json::to_vec(&serde_json::json!([{
            "Name": machine_name(target),
            "Running": running,
            "VMType": target.provider.argument(),
            "CPUs": 2,
            "Memory": (4096_u64 * 1024 * 1024).to_string(),
            "DiskSize": (40_u64 * 1024 * 1024 * 1024).to_string()
        }]))
        .expect("json")
    }

    #[cfg(windows)]
    fn push_windows_wsl_absent(commands: &FakeCommands) {
        commands.push(success(Vec::new()));
    }

    #[cfg(not(windows))]
    fn push_windows_wsl_absent(_commands: &FakeCommands) {}

    #[cfg(windows)]
    fn push_windows_wsl_ready(commands: &FakeCommands) {
        commands.push(success(utf16le(
            "Default Version: 2\r\nKernel version: 6.6.87.2\r\n",
        )));
        commands.push(success(Vec::new()));
    }

    #[cfg(not(windows))]
    fn push_windows_wsl_ready(_commands: &FakeCommands) {}

    #[cfg(windows)]
    fn windows_fixture_vhd_path(
        manager: &ManagedRuntimeManager,
        target: &ManagedTarget,
    ) -> PathBuf {
        manager
            .provider_home()
            .join("data")
            .join("containers")
            .join("podman")
            .join("machine")
            .join(target.provider.argument())
            .join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY)
            .join(machine_name(target))
            .join("ext4.vhdx")
    }

    #[cfg(windows)]
    fn open_without_windows_delete_sharing(path: &Path) -> File {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .expect("open fixture without delete sharing")
    }

    #[test]
    fn machine_names_are_deterministic_unique_and_within_podman_limit() {
        let image = ManagedMachineImage {
            url: "https://github.com/podman-container-tools/podman-machine-os/releases/download/v5.8.2/machine.zst".into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .into(),
            size_bytes: 1,
        };
        let operating_systems = [
            (ManagedOperatingSystem::Linux, ManagedMachineProvider::Qemu),
            (
                ManagedOperatingSystem::Macos,
                ManagedMachineProvider::Applehv,
            ),
            (ManagedOperatingSystem::Windows, ManagedMachineProvider::Wsl),
        ];
        let architectures = [ManagedArchitecture::X86_64, ManagedArchitecture::Aarch64];
        let mut names = BTreeSet::new();

        for (operating_system, provider) in operating_systems {
            for architecture in architectures {
                let target = ManagedTarget {
                    operating_system,
                    architecture,
                    provider,
                    machine_image: image.clone(),
                    prerequisite: None,
                };
                let name = machine_name(&target);
                assert_eq!(name, machine_name(&target));
                assert!(name.is_ascii());
                assert!(name.len() <= MAX_MACHINE_NAME_BYTES, "{name}");
                assert!(names.insert(name));
            }
        }

        assert_eq!(names.iter().map(String::len).max(), Some(30));
        assert!(names.contains("assm1-linux-arm64-0123456789ab"));
        assert!(names.contains("assm1-macos-arm64-0123456789ab"));
        assert!(names.contains("assm1-win-x64-0123456789ab"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_short_runtime_is_domain_separated_private_and_socket_bounded() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        let temp = TempDir::new().expect("temporary root");
        let base = temp.path().join("short-runtimes");
        let first_state = temp.path().join("first-state");
        let second_state = temp.path().join("second-state");
        for directory in [&base, &first_state, &second_state] {
            ensure_private_directory(directory).expect("private directory");
        }
        let first_state = canonical_real_directory(&first_state, "first test state").unwrap();
        let second_state = canonical_real_directory(&second_state, "second test state").unwrap();
        let effective_uid = effective_uid();
        let first_manifest = "a".repeat(64);
        let second_manifest = "b".repeat(64);

        let runtime = linux_short_runtime_path(&base, &first_state, &first_manifest, effective_uid);
        assert_eq!(
            runtime,
            linux_short_runtime_path(&base, &first_state, &first_manifest, effective_uid)
        );
        assert_ne!(
            runtime,
            linux_short_runtime_path(&base, &second_state, &first_manifest, effective_uid)
        );
        assert_ne!(
            runtime,
            linux_short_runtime_path(&base, &first_state, &second_manifest, effective_uid)
        );
        assert_ne!(
            runtime,
            linux_short_runtime_path(
                &base,
                &first_state,
                &first_manifest,
                effective_uid.wrapping_add(1)
            )
        );
        assert_ne!(
            runtime,
            macos_short_home_path(&base, &first_state, &first_manifest, effective_uid),
            "Linux and macOS temporary namespaces must use different hash domains"
        );
        assert_eq!(runtime.parent(), Some(base.as_path()));
        assert_eq!(
            runtime.file_name().unwrap().as_bytes().len(),
            LINUX_SHORT_RUNTIME_PREFIX.len() + LINUX_SHORT_RUNTIME_DIGEST_HEX_CHARS
        );

        ensure_linux_short_runtime_directory_at(&runtime, &base, effective_uid)
            .expect("create short runtime");
        ensure_linux_short_runtime_directory_at(&runtime, &base, effective_uid)
            .expect("reuse short runtime");
        let metadata = fs::symlink_metadata(&runtime).unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), effective_uid);
        assert_eq!(metadata.mode() & 0o7777, 0o700);

        let production_runtime = linux_short_runtime_path(
            Path::new(LINUX_SHORT_RUNTIME_BASE),
            &first_state,
            &first_manifest,
            effective_uid,
        );
        let longest_socket = linux_podman_gvproxy_socket_path(
            &production_runtime,
            &"m".repeat(MAX_MACHINE_NAME_BYTES),
        );
        assert_eq!(longest_socket.as_os_str().as_bytes().len(), 94);
        assert!(longest_socket.as_os_str().as_bytes().len() <= PODMAN_LINUX_MAX_SOCKET_PATH_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn linux_short_runtime_cleanup_is_exact_and_unsafe_entries_fail_closed() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::os::unix::net::UnixListener;

        let temp = TempDir::new().expect("temporary root");
        let base = temp.path().join("short-runtimes");
        let state = temp.path().join("state");
        ensure_private_directory(&base).unwrap();
        ensure_private_directory(&state).unwrap();
        let state = canonical_real_directory(&state, "test state").unwrap();
        let effective_uid = effective_uid();

        let runtime = linux_short_runtime_path(&base, &state, &"a".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&runtime, &base, effective_uid).unwrap();
        for (basename, mode) in [
            (PODMAN_LINUX_EAGER_STORAGE_DIRECTORY, 0o700),
            (PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY, 0o1700),
        ] {
            let directory = runtime.join(basename);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
        }
        let podman = runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o750)).unwrap();
        let log = podman.join(PODMAN_GVPROXY_LOG_NAME);
        fs::write(&log, b"pinned gvproxy log\n").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
        let virtiofs_pid = podman.join(PODMAN_VIRTIOFS_PID_NAME);
        fs::write(&virtiofs_pid, b"12345\n").unwrap();
        fs::set_permissions(&virtiofs_pid, fs::Permissions::from_mode(0o600)).unwrap();
        let virtiofs_socket = podman.join(PODMAN_VIRTIOFS_SOCKET_NAME);
        let listener = UnixListener::bind(&virtiofs_socket).unwrap();
        drop(listener);
        fs::set_permissions(&virtiofs_socket, fs::Permissions::from_mode(0o700)).unwrap();
        remove_linux_short_runtime_directory_at(&runtime, &base, effective_uid)
            .expect("remove exact Podman, gvproxy, and unlocked virtiofsd residue");
        assert!(!private_entry_exists(&runtime).unwrap());

        let unexpected = linux_short_runtime_path(&base, &state, &"b".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&unexpected, &base, effective_uid).unwrap();
        let podman = unexpected.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(podman.join("unexpected.sock"), b"must remain").unwrap();
        let error = remove_linux_short_runtime_directory_at(&unexpected, &base, effective_uid)
            .expect_err("unexpected Podman entry must fail closed");
        assert!(error.to_string().contains("unexpected entry"));
        assert_eq!(
            fs::read(podman.join("unexpected.sock")).unwrap(),
            b"must remain"
        );
        assert!(unexpected.is_dir());

        let legacy_storage_runtime =
            linux_short_runtime_path(&base, &state, &"1".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&legacy_storage_runtime, &base, effective_uid)
            .unwrap();
        let legacy_storage = legacy_storage_runtime.join("containers");
        fs::create_dir(&legacy_storage).unwrap();
        fs::set_permissions(&legacy_storage, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(legacy_storage.join("must-remain"), b"legacy storage state").unwrap();
        let error =
            remove_linux_short_runtime_directory_at(&legacy_storage_runtime, &base, effective_uid)
                .expect_err("legacy containers/storage state must never be removed recursively");
        assert!(error.to_string().contains("was not empty"));
        assert_eq!(
            fs::read(legacy_storage.join("must-remain")).unwrap(),
            b"legacy storage state"
        );

        let linked_eager_runtime =
            linux_short_runtime_path(&base, &state, &"2".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&linked_eager_runtime, &base, effective_uid)
            .unwrap();
        let outside_eager = temp.path().join("outside-eager-runtime");
        ensure_private_directory(&outside_eager).unwrap();
        fs::write(outside_eager.join("must-remain"), b"outside eager state").unwrap();
        symlink(
            &outside_eager,
            linked_eager_runtime.join(PODMAN_LINUX_EAGER_STORAGE_DIRECTORY),
        )
        .unwrap();
        let error =
            remove_linux_short_runtime_directory_at(&linked_eager_runtime, &base, effective_uid)
                .expect_err("an exact-name eager-runtime symlink must fail closed");
        assert!(error.to_string().contains("unsafe type"));
        assert_eq!(
            fs::read(outside_eager.join("must-remain")).unwrap(),
            b"outside eager state"
        );

        let wrong_mode_runtime =
            linux_short_runtime_path(&base, &state, &"3".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&wrong_mode_runtime, &base, effective_uid).unwrap();
        let wrong_mode_libpod = wrong_mode_runtime.join(PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY);
        fs::create_dir(&wrong_mode_libpod).unwrap();
        fs::set_permissions(&wrong_mode_libpod, fs::Permissions::from_mode(0o700)).unwrap();
        let error =
            remove_linux_short_runtime_directory_at(&wrong_mode_runtime, &base, effective_uid)
                .expect_err("libpod without its exact sticky mode must fail closed");
        assert!(error.to_string().contains("unsafe type"));
        assert!(wrong_mode_libpod.is_dir());

        let linked_log_runtime =
            linux_short_runtime_path(&base, &state, &"c".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&linked_log_runtime, &base, effective_uid).unwrap();
        let podman = linked_log_runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        let outside = temp.path().join("outside-log");
        fs::write(&outside, b"outside remains").unwrap();
        symlink(&outside, podman.join(PODMAN_GVPROXY_LOG_NAME)).unwrap();
        assert!(
            remove_linux_short_runtime_directory_at(&linked_log_runtime, &base, effective_uid)
                .is_err()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"outside remains");
        assert!(
            fs::symlink_metadata(podman.join(PODMAN_GVPROXY_LOG_NAME))
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let hard_link_runtime =
            linux_short_runtime_path(&base, &state, &"d".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&hard_link_runtime, &base, effective_uid).unwrap();
        let podman = hard_link_runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        let outside = temp.path().join("outside-hard-link");
        fs::write(&outside, b"hard link remains").unwrap();
        fs::hard_link(&outside, podman.join(PODMAN_GVPROXY_LOG_NAME)).unwrap();
        assert!(
            remove_linux_short_runtime_directory_at(&hard_link_runtime, &base, effective_uid)
                .is_err()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"hard link remains");
        assert_eq!(
            fs::symlink_metadata(podman.join(PODMAN_GVPROXY_LOG_NAME))
                .unwrap()
                .nlink(),
            2
        );

        let locked_runtime =
            linux_short_runtime_path(&base, &state, &"e".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&locked_runtime, &base, effective_uid).unwrap();
        let podman = locked_runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        let pid = podman.join(PODMAN_VIRTIOFS_PID_NAME);
        fs::write(&pid, b"12345\n").unwrap();
        fs::set_permissions(&pid, fs::Permissions::from_mode(0o600)).unwrap();
        let locked_pid = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pid)
            .unwrap();
        // SAFETY: locked_pid owns a valid descriptor for this test fixture.
        assert_eq!(
            unsafe { libc::flock(locked_pid.as_raw_fd(), libc::LOCK_EX) },
            0
        );
        let started = Instant::now();
        let error = remove_expected_linux_virtiofs_residue(
            &podman,
            effective_uid,
            Duration::from_millis(50),
        )
        .expect_err("a live virtiofsd pid lock must not be removed");
        assert!(error.to_string().contains("remained live"));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(pid.is_file());
        drop(locked_pid);
        remove_linux_short_runtime_directory_at(&locked_runtime, &base, effective_uid)
            .expect("cleanup succeeds after the exact pid lock is released");

        let unproven_socket_runtime =
            linux_short_runtime_path(&base, &state, &"f".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&unproven_socket_runtime, &base, effective_uid)
            .unwrap();
        let podman = unproven_socket_runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        let socket = podman.join(PODMAN_VIRTIOFS_SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            remove_expected_linux_virtiofs_residue(
                &podman,
                effective_uid,
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert!(socket.exists());
        drop(listener);

        let permissive = linux_short_runtime_path(&base, &state, &"e".repeat(64), effective_uid);
        fs::create_dir(&permissive).unwrap();
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            ensure_linux_short_runtime_directory_at(&permissive, &base, effective_uid).is_err()
        );
        assert!(
            remove_linux_short_runtime_directory_at(&permissive, &base, effective_uid).is_err()
        );

        let linked = linux_short_runtime_path(&base, &state, &"0".repeat(64), effective_uid);
        let outside_directory = temp.path().join("outside-directory");
        ensure_private_directory(&outside_directory).unwrap();
        symlink(&outside_directory, &linked).unwrap();
        assert!(ensure_linux_short_runtime_directory_at(&linked, &base, effective_uid).is_err());
        assert!(remove_linux_short_runtime_directory_at(&linked, &base, effective_uid).is_err());
        assert!(
            fs::symlink_metadata(&linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(outside_directory.is_dir());

        let escaped = base.join("nested").join("assm1-escaped");
        assert!(ensure_linux_short_runtime_directory_at(&escaped, &base, effective_uid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn macos_short_home_is_stable_private_and_keeps_the_longest_socket_alias_bounded() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        let temp = TempDir::new().expect("temporary root");
        let base = temp.path().join("short-homes");
        let first_state = temp.path().join("first-state");
        let second_state = temp.path().join("second-state");
        for directory in [&base, &first_state, &second_state] {
            ensure_private_directory(directory).expect("private directory");
        }
        let first_state = canonical_real_directory(&first_state, "first test state").unwrap();
        let second_state = canonical_real_directory(&second_state, "second test state").unwrap();
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        let first_manifest = "a".repeat(64);
        let second_manifest = "b".repeat(64);

        let home = macos_short_home_path(&base, &first_state, &first_manifest, effective_uid);
        assert_eq!(
            home,
            macos_short_home_path(&base, &first_state, &first_manifest, effective_uid)
        );
        assert_ne!(
            home,
            macos_short_home_path(&base, &second_state, &first_manifest, effective_uid)
        );
        assert_ne!(
            home,
            macos_short_home_path(&base, &first_state, &second_manifest, effective_uid)
        );
        assert_eq!(home.parent(), Some(base.as_path()));
        assert_eq!(
            home.file_name().unwrap().as_bytes().len(),
            MACOS_SHORT_HOME_PREFIX.len() + MACOS_SHORT_HOME_DIGEST_HEX_CHARS
        );

        ensure_macos_short_home_directory(&home, effective_uid).expect("create short home");
        ensure_macos_short_home_directory(&home, effective_uid).expect("reuse short home");
        let metadata = fs::symlink_metadata(&home).unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), effective_uid);
        assert_eq!(metadata.mode() & 0o7777, 0o700);

        let production_home = macos_short_home_path(
            Path::new(MACOS_SHORT_HOME_BASE),
            &first_state,
            &first_manifest,
            effective_uid,
        );
        let longest_alias = macos_podman_ignition_socket_alias(
            &production_home,
            &"m".repeat(MAX_MACHINE_NAME_BYTES),
        );
        assert_eq!(longest_alias.as_os_str().as_bytes().len(), 96);
        assert!(longest_alias.as_os_str().as_bytes().len() <= PODMAN_MACOS_MAX_SOCKET_PATH_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn macos_short_home_cleanup_is_exact_and_unsafe_preexisting_entries_fail_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::os::unix::net::UnixListener;

        let temp = TempDir::new().expect("temporary root");
        let base = temp.path().join("s");
        let state = temp.path().join("state");
        ensure_private_directory(&base).unwrap();
        ensure_private_directory(&state).unwrap();
        let state = canonical_real_directory(&state, "test state").unwrap();
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        let machine_name = "m";
        let seed_known_hosts = |home: &Path, contents: &[u8], mode: u32| {
            let ssh_directory = home.join(PODMAN_MACOS_SSH_DIRECTORY);
            ensure_private_directory(&ssh_directory).unwrap();
            let known_hosts = ssh_directory.join(PODMAN_MACOS_KNOWN_HOSTS_FILE);
            fs::write(&known_hosts, contents).unwrap();
            fs::set_permissions(&known_hosts, fs::Permissions::from_mode(mode)).unwrap();
            known_hosts
        };

        let home = macos_short_home_path(&base, &state, &"a".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&home, effective_uid).unwrap();
        let aliases = home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        remove_macos_short_home_directory_at(&home, &base, effective_uid, machine_name)
            .expect("remove empty exact home after machine removal");
        assert!(!private_entry_exists(&home).unwrap());

        let socket_home = macos_short_home_path(&base, &state, &"d".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&socket_home, effective_uid).unwrap();
        let aliases = socket_home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let exact_socket = macos_podman_ignition_socket_alias(&socket_home, machine_name);
        let listener = UnixListener::bind(&exact_socket).unwrap();
        drop(listener);
        remove_macos_short_home_directory_at(&socket_home, &base, effective_uid, machine_name)
            .expect("remove exact stale pinned-Podman ignition socket and short home");
        assert!(!private_entry_exists(&socket_home).unwrap());

        let ssh_home = macos_short_home_path(&base, &state, &"1".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&ssh_home, effective_uid).unwrap();
        let known_hosts = seed_known_hosts(&ssh_home, b"", 0o600);
        let metadata = fs::symlink_metadata(&known_hosts).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), 0);
        remove_macos_short_home_directory_at(&ssh_home, &base, effective_uid, machine_name)
            .expect("remove exact pinned-Podman empty known_hosts residue and short home");
        assert!(!private_entry_exists(&ssh_home).unwrap());

        let combined_home = macos_short_home_path(&base, &state, &"ab".repeat(32), effective_uid);
        ensure_macos_short_home_directory(&combined_home, effective_uid).unwrap();
        let combined_aliases = combined_home.join(".podman");
        ensure_private_directory(&combined_aliases).unwrap();
        let combined_socket = macos_podman_ignition_socket_alias(&combined_home, machine_name);
        let listener = UnixListener::bind(&combined_socket).unwrap();
        drop(listener);
        seed_known_hosts(&combined_home, b"", 0o600);
        remove_macos_short_home_directory_at(&combined_home, &base, effective_uid, machine_name)
            .expect("remove both exact pinned-Podman residue namespaces");
        assert!(!private_entry_exists(&combined_home).unwrap());

        let unexpected = macos_short_home_path(&base, &state, &"d".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&unexpected, effective_uid).unwrap();
        let aliases = unexpected.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let outside = temp.path().join("outside-socket-target");
        fs::write(&outside, b"must remain").unwrap();
        symlink(&outside, aliases.join("owned-alias.sock")).unwrap();

        // Ordinary stop/update does not invoke cleanup; the stable namespace
        // and any live socket aliases remain available until machine removal.
        assert!(unexpected.is_dir());
        let error =
            remove_macos_short_home_directory_at(&unexpected, &base, effective_uid, machine_name)
                .expect_err("unexpected alias entry must fail closed");
        assert!(error.to_string().contains("unexpected entry"));
        assert_eq!(fs::read(&outside).unwrap(), b"must remain");
        assert!(unexpected.is_dir());

        let linked_alias_home =
            macos_short_home_path(&base, &state, &"e".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&linked_alias_home, effective_uid).unwrap();
        let aliases = linked_alias_home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let exact_alias = macos_podman_ignition_socket_alias(&linked_alias_home, machine_name);
        symlink(&outside, &exact_alias).unwrap();
        let error = remove_macos_short_home_directory_at(
            &linked_alias_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an exact-name symlink must not be treated as Podman's socket residue");
        assert!(error.to_string().contains("single-link Unix socket"));
        assert!(
            fs::symlink_metadata(&exact_alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"must remain");

        let regular_alias_home =
            macos_short_home_path(&base, &state, &"f".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&regular_alias_home, effective_uid).unwrap();
        let aliases = regular_alias_home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let exact_alias = macos_podman_ignition_socket_alias(&regular_alias_home, machine_name);
        fs::write(&exact_alias, b"must remain").unwrap();
        assert!(
            remove_macos_short_home_directory_at(
                &regular_alias_home,
                &base,
                effective_uid,
                machine_name,
            )
            .is_err()
        );
        assert_eq!(fs::read(&exact_alias).unwrap(), b"must remain");

        let extra_entry_home = macos_short_home_path(&base, &state, &"0".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&extra_entry_home, effective_uid).unwrap();
        let aliases = extra_entry_home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let exact_socket = macos_podman_ignition_socket_alias(&extra_entry_home, machine_name);
        let listener = UnixListener::bind(&exact_socket).unwrap();
        drop(listener);
        fs::write(aliases.join("unexpected"), b"must remain").unwrap();
        assert!(
            remove_macos_short_home_directory_at(
                &extra_entry_home,
                &base,
                effective_uid,
                machine_name,
            )
            .is_err()
        );
        assert!(private_entry_exists(&exact_socket).unwrap());
        assert_eq!(
            fs::read(aliases.join("unexpected")).unwrap(),
            b"must remain"
        );

        let root_extra_home = macos_short_home_path(&base, &state, &"2".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&root_extra_home, effective_uid).unwrap();
        let root_extra_aliases = root_extra_home.join(".podman");
        ensure_private_directory(&root_extra_aliases).unwrap();
        fs::write(root_extra_home.join("unexpected"), b"must remain").unwrap();
        let error = remove_macos_short_home_directory_at(
            &root_extra_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an unknown root entry must fail before recognized residue is removed");
        assert!(error.to_string().contains("unexpected entry"));
        assert!(root_extra_aliases.is_dir());
        assert_eq!(
            fs::read(root_extra_home.join("unexpected")).unwrap(),
            b"must remain"
        );

        let linked_ssh_home = macos_short_home_path(&base, &state, &"3".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&linked_ssh_home, effective_uid).unwrap();
        let outside_ssh_directory = temp.path().join("outside-ssh-directory");
        ensure_private_directory(&outside_ssh_directory).unwrap();
        fs::write(
            outside_ssh_directory.join("must-remain"),
            b"outside ssh state",
        )
        .unwrap();
        symlink(
            &outside_ssh_directory,
            linked_ssh_home.join(PODMAN_MACOS_SSH_DIRECTORY),
        )
        .unwrap();
        let error = remove_macos_short_home_directory_at(
            &linked_ssh_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an exact-name .ssh symlink must fail closed");
        assert!(error.to_string().contains("unsafe type"));
        assert_eq!(
            fs::read(outside_ssh_directory.join("must-remain")).unwrap(),
            b"outside ssh state"
        );

        let linked_known_hosts_home =
            macos_short_home_path(&base, &state, &"4".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&linked_known_hosts_home, effective_uid).unwrap();
        let linked_known_hosts_directory = linked_known_hosts_home.join(PODMAN_MACOS_SSH_DIRECTORY);
        ensure_private_directory(&linked_known_hosts_directory).unwrap();
        symlink(
            &outside,
            linked_known_hosts_directory.join(PODMAN_MACOS_KNOWN_HOSTS_FILE),
        )
        .unwrap();
        let error = remove_macos_short_home_directory_at(
            &linked_known_hosts_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an exact-name known_hosts symlink must fail closed");
        assert!(error.to_string().contains("empty regular file"));
        assert_eq!(fs::read(&outside).unwrap(), b"must remain");

        let hardlinked_known_hosts_home =
            macos_short_home_path(&base, &state, &"5".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&hardlinked_known_hosts_home, effective_uid).unwrap();
        let hardlinked_known_hosts_directory =
            hardlinked_known_hosts_home.join(PODMAN_MACOS_SSH_DIRECTORY);
        ensure_private_directory(&hardlinked_known_hosts_directory).unwrap();
        let outside_hardlink = temp.path().join("outside-known-hosts-hardlink");
        fs::write(&outside_hardlink, b"").unwrap();
        fs::set_permissions(&outside_hardlink, fs::Permissions::from_mode(0o600)).unwrap();
        let hardlinked_known_hosts =
            hardlinked_known_hosts_directory.join(PODMAN_MACOS_KNOWN_HOSTS_FILE);
        fs::hard_link(&outside_hardlink, &hardlinked_known_hosts).unwrap();
        let error = remove_macos_short_home_directory_at(
            &hardlinked_known_hosts_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("a multiply-linked known_hosts file must fail closed");
        assert!(error.to_string().contains("single-link"));
        assert!(hardlinked_known_hosts.is_file());
        assert!(outside_hardlink.is_file());

        let nonempty_known_hosts_home =
            macos_short_home_path(&base, &state, &"6".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&nonempty_known_hosts_home, effective_uid).unwrap();
        let nonempty_known_hosts =
            seed_known_hosts(&nonempty_known_hosts_home, b"must remain", 0o600);
        let error = remove_macos_short_home_directory_at(
            &nonempty_known_hosts_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("a nonempty known_hosts file must fail closed");
        assert!(error.to_string().contains("empty regular file"));
        assert_eq!(fs::read(nonempty_known_hosts).unwrap(), b"must remain");

        let wrong_mode_known_hosts_home =
            macos_short_home_path(&base, &state, &"7".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&wrong_mode_known_hosts_home, effective_uid).unwrap();
        let wrong_mode_known_hosts = seed_known_hosts(&wrong_mode_known_hosts_home, b"", 0o644);
        let error = remove_macos_short_home_directory_at(
            &wrong_mode_known_hosts_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("known_hosts without exact mode 0600 must fail closed");
        assert!(error.to_string().contains("mode-0600"));
        assert!(wrong_mode_known_hosts.is_file());

        let extra_ssh_entry_home =
            macos_short_home_path(&base, &state, &"8".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&extra_ssh_entry_home, effective_uid).unwrap();
        let exact_known_hosts = seed_known_hosts(&extra_ssh_entry_home, b"", 0o600);
        let extra_ssh_entry = extra_ssh_entry_home
            .join(PODMAN_MACOS_SSH_DIRECTORY)
            .join("unexpected");
        fs::write(&extra_ssh_entry, b"must remain").unwrap();
        let error = remove_macos_short_home_directory_at(
            &extra_ssh_entry_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an extra .ssh entry must fail closed");
        assert!(error.to_string().contains("exactly the expected"));
        assert!(exact_known_hosts.is_file());
        assert_eq!(fs::read(extra_ssh_entry).unwrap(), b"must remain");

        let permissive_ssh_home =
            macos_short_home_path(&base, &state, &"9".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&permissive_ssh_home, effective_uid).unwrap();
        let permissive_known_hosts = seed_known_hosts(&permissive_ssh_home, b"", 0o600);
        let permissive_ssh_directory = permissive_ssh_home.join(PODMAN_MACOS_SSH_DIRECTORY);
        fs::set_permissions(&permissive_ssh_directory, fs::Permissions::from_mode(0o755)).unwrap();
        let error = remove_macos_short_home_directory_at(
            &permissive_ssh_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("a permissive .ssh directory must fail closed");
        assert!(error.to_string().contains("unsafe type"));
        assert!(permissive_known_hosts.is_file());

        let permissive = macos_short_home_path(&base, &state, &"b".repeat(64), effective_uid);
        fs::create_dir(&permissive).unwrap();
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755)).unwrap();
        let error = ensure_macos_short_home_directory(&permissive, effective_uid)
            .expect_err("permissive preexisting directory must fail closed");
        assert!(
            error
                .to_string()
                .contains("unsafe ownership or permissions")
        );
        assert!(
            remove_macos_short_home_directory_at(&permissive, &base, effective_uid, machine_name)
                .is_err()
        );
        assert!(permissive.is_dir());

        let linked = macos_short_home_path(&base, &state, &"c".repeat(64), effective_uid);
        let outside_directory = temp.path().join("outside-directory");
        ensure_private_directory(&outside_directory).unwrap();
        symlink(&outside_directory, &linked).unwrap();
        assert!(ensure_macos_short_home_directory(&linked, effective_uid).is_err());
        assert!(
            remove_macos_short_home_directory_at(&linked, &base, effective_uid, machine_name)
                .is_err()
        );
        assert!(
            fs::symlink_metadata(&linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(outside_directory.is_dir());
    }

    fn tamper_installed_driver(manager: &ManagedRuntimeManager) {
        let installed = manager.install_directory().join("bin/podman");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&installed, fs::Permissions::from_mode(0o600))
                .expect("make test payload writable");
        }
        fs::write(installed, b"tampered-runtime").expect("tamper installed payload");
    }

    #[test]
    fn manifest_rejects_traversal_duplicate_targets_and_unapproved_downloads() {
        let fixture = fixture();
        let mut manifest = fixture.manager.loaded.manifest.clone();
        manifest.files[0].path = "../podman".into();
        let bytes = serde_json::to_vec(&manifest).expect("manifest");
        assert!(LoadedManagedRuntimeManifest::parse(&bytes).is_err());

        let mut manifest = fixture.manager.loaded.manifest.clone();
        manifest.targets.push(manifest.targets[0].clone());
        let bytes = serde_json::to_vec(&manifest).expect("manifest");
        assert!(LoadedManagedRuntimeManifest::parse(&bytes).is_err());

        let mut manifest = fixture.manager.loaded.manifest.clone();
        manifest.targets[0].machine_image.url = "https://example.com/machine.zst".into();
        let bytes = serde_json::to_vec(&manifest).expect("manifest");
        assert!(LoadedManagedRuntimeManifest::parse(&bytes).is_err());
    }

    #[test]
    fn install_is_private_hash_verified_and_idempotent() {
        let fixture = fixture();
        let first = fixture.manager.install().expect("install");
        assert_eq!(first.phase, ManagedRuntimePhase::Installed);
        let installed = fixture.manager.install_directory().join("bin/podman");
        verify_file_hash_size(
            &installed,
            b"managed-podman-driver".len() as u64,
            &sha256_bytes(b"managed-podman-driver"),
            "test driver",
        )
        .expect("verified");
        fixture.manager.install().expect("idempotent");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(installed)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o500
            );
        }
    }

    #[test]
    fn windows_wsl_inventory_parser_accepts_strict_utf8_and_utf16le_only() {
        assert!(
            parse_windows_wsl_distribution_inventory(b"")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            parse_windows_wsl_distribution_inventory(
                b"\xef\xbb\xbfpodman-assm1-win-x64-0123456789ab\r\nUbuntu\n"
            )
            .unwrap(),
            ["podman-assm1-win-x64-0123456789ab", "Ubuntu"]
        );
        let utf16 = utf16le("podman-assm1-win-x64-0123456789ab\r\nUbuntu\r\n");
        assert_eq!(
            parse_windows_wsl_distribution_inventory(&utf16).unwrap(),
            ["podman-assm1-win-x64-0123456789ab", "Ubuntu"]
        );
        let mut utf16_with_bom = vec![0xff, 0xfe];
        utf16_with_bom.extend_from_slice(&utf16);
        assert_eq!(
            parse_windows_wsl_distribution_inventory(&utf16_with_bom).unwrap(),
            ["podman-assm1-win-x64-0123456789ab", "Ubuntu"]
        );
        for malformed in [
            vec![0xfe, 0xff, 0, b'A'],
            vec![0xff, 0xfe, b'A'],
            b" podman-assm1-win-x64-0123456789ab\n".to_vec(),
            b"podman-assm1-win-x64-0123456789ab\0\n".to_vec(),
            b"podman-assm1-win-x64-0123456789ab\n\n".to_vec(),
        ] {
            assert!(parse_windows_wsl_distribution_inventory(&malformed).is_err());
        }
        assert!(
            parse_windows_wsl_distribution_inventory(
                &vec!["A"; MAX_WSL_DISTRIBUTIONS + 1].join("\n").into_bytes(),
            )
            .is_err()
        );
        assert!(
            parse_windows_wsl_distribution_inventory(&vec![
                b'A';
                MAX_COMMAND_OUTPUT_BYTES as usize + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn windows_console_diagnostics_decode_utf16le_and_reject_mixed_garbage() {
        let localized =
            "Windows 子系統尚未就緒。\r\nError code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n";
        assert_eq!(
            safe_command_diagnostic(&utf16le(localized)).as_deref(),
            Some("Windows 子系統尚未就緒。 Error code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED")
        );
        let mut bom = vec![0xff, 0xfe];
        bom.extend_from_slice(&utf16le(localized));
        assert!(
            safe_command_diagnostic(&bom)
                .expect("UTF-16LE BOM diagnostic")
                .contains("Windows 子系統")
        );
        assert_eq!(
            safe_command_diagnostic(b"plain UTF-8 diagnostic\r\nsecond line").as_deref(),
            Some("plain UTF-8 diagnostic second line")
        );

        let mut mixed = b"Error command C:\\Windows\\System32\\wsl.exe: ".to_vec();
        mixed.extend_from_slice(&utf16le("子系統尚未就緒"));
        assert!(safe_command_diagnostic(&mixed).is_none());
        assert!(safe_command_diagnostic(b"unsafe\0control").is_none());

        let output = failure(mixed);
        let error = require_success("managed runtime machine initialization", &output)
            .expect_err("mixed console encodings must fail without raw output");
        let message = error.to_string();
        assert!(message.contains("No readable diagnostic was returned"));
        assert!(!message.contains("wsl.exe"));
        assert!(!message.contains(['\0', '\u{fffd}']));
    }

    #[test]
    fn windows_wsl_prerequisite_classifier_maps_stable_codes_to_actions() {
        let cases = [
            (
                "錯誤碼: Wsl/WSL_E_WSL_NOT_INSTALLED",
                ManagedRuntimeSetupFailureReason::WslNotInstalled,
                ManagedRuntimeSetupNextAction::InstallWsl,
            ),
            (
                "請執行 wsl.exe --install。https://aka.ms/wslinstall",
                ManagedRuntimeSetupFailureReason::WslNotInstalled,
                ManagedRuntimeSetupNextAction::InstallWsl,
            ),
            (
                "錯誤碼: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED",
                ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled,
                ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures,
            ),
            (
                "錯誤: 0x800701bc",
                ManagedRuntimeSetupFailureReason::WslUpdateRequired,
                ManagedRuntimeSetupNextAction::UpdateWsl,
            ),
            (
                "Error code: Wsl/WSL_E_INVALID_USAGE",
                ManagedRuntimeSetupFailureReason::WslUpdateRequired,
                ManagedRuntimeSetupNextAction::UpdateWsl,
            ),
            (
                "Error: ERROR_SUCCESS_REBOOT_REQUIRED",
                ManagedRuntimeSetupFailureReason::RestartRequired,
                ManagedRuntimeSetupNextAction::RestartWindows,
            ),
            (
                "Error code: Wsl/Service/E_UNEXPECTED",
                ManagedRuntimeSetupFailureReason::WslCommandFailed,
                ManagedRuntimeSetupNextAction::RetryWslCheck,
            ),
        ];

        for (diagnostic, reason, action) in cases {
            let output = failure(utf16le(diagnostic));
            let classified = classify_windows_wsl_prerequisite_failure(&output);
            assert_eq!(classified.reason, reason, "{diagnostic}");
            assert_eq!(classified.action, action, "{diagnostic}");
            assert_eq!(classified.exit_code, Some(1));
        }
    }

    #[test]
    fn windows_wsl_prerequisite_failure_persists_machine_readable_recovery() {
        let controller = ManagedRuntimeSetupController::default();
        controller.begin().expect("begin setup");
        controller
            .set_phase(
                ManagedRuntimeSetupPhase::Prerequisite,
                "checking Windows WSL 2",
            )
            .expect("prerequisite phase");
        let failure = WindowsWslPrerequisiteFailure::update_required(Some(1));
        let error = fail_windows_wsl_prerequisite(Some(&controller), failure)
            .expect_err("missing prerequisite");

        // The worker has recorded the classified pair internally so the
        // terminal failure can preserve it, but concurrent Tauri polling must
        // not receive recovery fields before the public phase becomes failed.
        let unwinding = controller.status().expect("unwinding status");
        assert_eq!(unwinding.phase, ManagedRuntimeSetupPhase::Prerequisite);
        assert!(unwinding.active);
        assert_eq!(unwinding.failure_reason, None);
        assert_eq!(unwinding.next_action, None);
        let encoded_unwinding =
            serde_json::to_value(&unwinding).expect("serialize unwinding setup status");
        assert_eq!(encoded_unwinding["failure_reason"], serde_json::Value::Null);
        assert_eq!(encoded_unwinding["next_action"], serde_json::Value::Null);

        controller
            .finish_failed(error.to_string())
            .expect("finish failed setup");

        let status = controller.status().expect("failed status");
        assert_eq!(status.phase, ManagedRuntimeSetupPhase::Failed);
        assert!(!status.active);
        assert!(status.can_retry);
        assert_eq!(
            status.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::WslUpdateRequired)
        );
        assert_eq!(
            status.next_action,
            Some(ManagedRuntimeSetupNextAction::UpdateWsl)
        );
        assert!(status.detail.contains("needs an update"));
        assert!(!status.detail.contains("operation is not available yet"));
        let encoded = serde_json::to_value(&status).expect("serialize setup status");
        assert_eq!(encoded["phase"], "failed");
        assert_eq!(encoded["failure_reason"], "windows_wsl_update_required");
        assert_eq!(encoded["next_action"], "update_wsl");

        controller.begin().expect("retry begins cleanly");
        let retried = controller.status().expect("retry status");
        assert_eq!(retried.phase, ManagedRuntimeSetupPhase::Install);
        assert_eq!(retried.failure_reason, None);
        assert_eq!(retried.next_action, None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_setup_checks_wsl_before_machine_image_download() {
        let fixture = fixture();
        fixture.commands.push(failure(utf16le(
            "此應用程式需要適用於 Linux 的 Windows 子系統選用元件。\r\nError code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n",
        )));
        let setup = ManagedRuntimeSetupController::default();

        let error = fixture
            .manager
            .setup(&setup)
            .expect_err("unavailable WSL must stop setup before download");

        assert!(error.to_string().contains("Windows settings"));
        assert_eq!(*fixture.downloader.calls.lock().expect("downloads"), 0);
        assert_eq!(
            fixture.commands.calls(),
            vec![vec![String::from("--status")]]
        );
        let status = setup.status().expect("failed setup status");
        assert_eq!(status.phase, ManagedRuntimeSetupPhase::Failed);
        assert_eq!(status.received_bytes, 0);
        assert_eq!(status.total_bytes, None);
        assert_eq!(
            status.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled)
        );
        assert_eq!(
            status.next_action,
            Some(ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures)
        );
        assert!(!status.detail.contains("wsl.exe"));
        assert!(!status.detail.contains(['\0', '\u{fffd}']));
    }

    #[test]
    fn windows_wsl_command_uses_verified_system_directories_not_managed_environment() {
        let temp = TempDir::new().expect("temporary root");
        let system_root = temp.path().join("trusted-windows-root");
        let system32 = system_root.join("System32");
        let working_directory = temp.path().join("provider-home");
        fs::create_dir(&system_root).expect("Windows root");
        fs::create_dir(&system32).expect("System32");
        fs::create_dir(&working_directory).expect("provider home");
        fs::write(system32.join("wsl.exe"), b"fixture wsl").expect("fixture wsl.exe");
        let directories =
            verified_windows_system_directories(&system_root).expect("verified directories");
        let managed_command = ManagedRuntimeCommand {
            binary: temp.path().join("managed-podman"),
            environment: BTreeMap::from([
                (
                    OsString::from("SystemRoot"),
                    OsString::from("C:\\attacker-controlled"),
                ),
                (
                    OsString::from("PATH"),
                    OsString::from("C:\\attacker-controlled\\System32"),
                ),
            ]),
            working_directory: working_directory.clone(),
            runtime_version: "test".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
        };

        let command =
            windows_wsl_inventory_command_with_directories(&managed_command, &directories)
                .expect("trusted WSL command");

        assert_eq!(command.binary, directories.system32.join("wsl.exe"));
        assert_eq!(
            command.environment.get(OsStr::new("SystemRoot")),
            Some(&directories.system_root.as_os_str().to_owned())
        );
        assert_eq!(
            command.environment.get(OsStr::new("WINDIR")),
            command.environment.get(OsStr::new("SystemRoot"))
        );
        let path = command
            .environment
            .get(OsStr::new("PATH"))
            .expect("trusted PATH");
        assert_eq!(
            std::env::split_paths(path).collect::<Vec<_>>(),
            [directories.system32]
        );
        assert_eq!(
            command.working_directory,
            working_directory
                .canonicalize()
                .expect("canonical provider home")
        );
        assert_eq!(command.environment.len(), 4);
    }

    #[test]
    fn corrupted_install_is_replaced_from_verified_release_resources() {
        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        let installed = fixture.manager.install_directory().join("bin/podman");
        tamper_installed_driver(&fixture.manager);

        fixture.manager.install().expect("repair install");

        assert_eq!(
            fs::read(installed).expect("repaired driver"),
            b"managed-podman-driver"
        );
        fixture
            .manager
            .verify_installation()
            .expect("repaired installation verifies");
    }

    #[test]
    fn corrupted_machine_image_cache_is_removed_and_downloaded_again() {
        let fixture = fixture();
        let target = fixture.manager.loaded.target().expect("target");
        let cached = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("initial image");
        fs::write(&cached, vec![b'x'; fixture.image.len()]).expect("tamper cache");

        let repaired = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("repair image");

        assert_eq!(repaired, cached);
        assert_eq!(fs::read(repaired).expect("repaired image"), fixture.image);
    }

    #[cfg(unix)]
    #[test]
    fn exact_install_symlink_is_unlinked_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        let install = fixture.manager.install_directory();
        fs::remove_dir_all(&install).expect("remove test install");
        let outside = fixture._temp.path().join("outside-install-target");
        fs::create_dir(&outside).expect("outside directory");
        fs::write(outside.join("keep"), b"outside").expect("outside marker");
        symlink(&outside, &install).expect("corrupt install symlink");

        fixture.manager.install().expect("repair symlink");

        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"outside");
        assert!(
            !fs::symlink_metadata(&install)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fixture
            .manager
            .verify_installation()
            .expect("repaired install");
    }

    #[cfg(unix)]
    #[test]
    fn exact_image_symlink_is_unlinked_and_redownloaded() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        let target = fixture.manager.loaded.target().expect("target");
        let cached = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("initial image");
        fs::remove_file(&cached).expect("remove cached image");
        let outside = fixture._temp.path().join("outside-image");
        fs::write(&outside, b"outside").expect("outside image");
        symlink(&outside, &cached).expect("corrupt cache symlink");

        let repaired = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("repair image symlink");

        assert_eq!(fs::read(outside).unwrap(), b"outside");
        assert_eq!(fs::read(repaired).unwrap(), fixture.image);
    }

    #[cfg(unix)]
    #[test]
    fn non_traversable_install_directories_are_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        let install = fixture.manager.install_directory();
        fs::set_permissions(install.join("bin"), fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&install, fs::Permissions::from_mode(0o000)).unwrap();

        fixture.manager.install().expect("repair directory modes");

        fixture
            .manager
            .verify_installation()
            .expect("repaired install");
        assert_eq!(
            fs::metadata(install).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(windows)]
    #[test]
    fn readonly_windows_payload_tree_can_be_removed_for_repair() {
        let fixture = fixture();
        let versions = fixture.manager.versions_root();
        let install = versions.join("readonly-repair-fixture");
        let nested = install.join("nested");
        fs::create_dir_all(&nested).expect("create readonly fixture");
        let payload = nested.join("payload.dat");
        fs::write(&payload, b"payload").expect("write readonly fixture");

        for path in [&payload, &nested, &install] {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(path, permissions).unwrap();
        }

        remove_private_tree(&install, &versions).expect("remove readonly tree");
        assert!(!private_entry_exists(&install).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn readonly_windows_top_level_cache_file_can_be_removed_for_repair() {
        let fixture = fixture();
        let cache = fixture.manager.image_cache_root();
        ensure_private_directory(&cache).unwrap();
        let payload = cache.join("readonly-top-level.zst");
        fs::write(&payload, b"corrupt cache").unwrap();
        set_windows_entry_readonly_nofollow(&payload, true).unwrap();

        remove_private_tree(&payload, &cache).expect("remove readonly cache file");
        assert!(!private_entry_exists(&payload).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn readonly_windows_child_symlink_is_unlinked_without_touching_target() {
        use std::os::windows::fs::symlink_file;

        let fixture = fixture();
        let versions = fixture.manager.versions_root();
        ensure_private_directory(&versions).unwrap();
        let install = versions.join("readonly-link-repair-fixture");
        fs::create_dir(&install).unwrap();
        let outside = fixture._temp.path().join("outside-readonly-target");
        fs::write(&outside, b"outside remains").unwrap();
        let link = install.join("payload-link");
        symlink_file(&outside, &link).expect("create file symlink");
        set_windows_entry_readonly_nofollow(&link, true).unwrap();

        remove_private_tree(&install, &versions).expect("remove tree with readonly link");
        assert!(!private_entry_exists(&install).unwrap());
        assert_eq!(fs::read(&outside).unwrap(), b"outside remains");
    }

    #[cfg(windows)]
    #[test]
    fn windows_provider_delete_retry_classifies_only_sharing_violations() {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

        assert!(windows_error_is_sharing_violation(
            &io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION as i32)
        ));
        assert!(!windows_error_is_sharing_violation(
            &io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_provider_delete_accepts_a_concurrent_not_found() {
        let fixture = fixture();
        let missing = fixture
            .manager
            .versions_root()
            .join("already-released.vhdx");
        ensure_private_directory(&fixture.manager.versions_root()).unwrap();

        remove_windows_private_file(
            &missing,
            WindowsPrivateFileDeletePolicy::RetrySharingViolation {
                deadline: Instant::now() + Duration::from_secs(1),
                poll: Duration::from_millis(10),
            },
        )
        .expect("a concurrently removed exact entry is already clean");
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_waits_for_exact_windows_wsl_vhd_release() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let vhd = windows_fixture_vhd_path(&fixture.manager, target);
        fs::create_dir(vhd.parent().expect("VHD parent")).expect("create WSL distribution root");
        fs::write(&vhd, b"fixture VHD").expect("write fixture VHD");
        let locked_vhd = open_without_windows_delete_sharing(&vhd);
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(250));
            drop(locked_vhd);
        });
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);

        let result = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default());
        release.join().expect("release fixture VHD handle");
        let status = result.expect("uninstall after bounded VHD release wait");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!private_entry_exists(&fixture.manager.provider_home()).unwrap());
        assert!(!private_entry_exists(&fixture.manager.install_directory()).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_provider_delete_timeout_retains_install_and_image_cache() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let image = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("cache exact machine image");
        let provider_home = fixture.manager.provider_home();
        let vhd = windows_fixture_vhd_path(&fixture.manager, target);
        fs::create_dir(vhd.parent().expect("VHD parent")).expect("create WSL distribution root");
        fs::write(&vhd, b"fixture VHD").expect("write fixture VHD");
        let locked_vhd = open_without_windows_delete_sharing(&vhd);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        let started = Instant::now();

        let error = fixture
            .manager
            .uninstall_with_windows_provider_delete_timing(
                ManagedUninstallOptions {
                    stop_mode: ManagedStopMode::Force,
                    remove_machine_image_cache: true,
                },
                Duration::from_millis(150),
                Duration::from_millis(25),
            )
            .expect_err("an unreleased VHD must stop provider deletion at its deadline");

        assert!(error.to_string().contains("remained in use"));
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(private_entry_exists(&provider_home).unwrap());
        assert!(private_entry_exists(&vhd).unwrap());
        assert!(private_entry_exists(&fixture.manager.install_directory()).unwrap());
        assert_eq!(fs::read(image).unwrap(), fixture.image);
        assert_eq!(fixture.commands.calls().len(), 2);
        drop(locked_vhd);
    }

    #[test]
    fn corrupted_install_does_not_wedge_uninstall() {
        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        tamper_installed_driver(&fixture.manager);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("repair then uninstall");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
    }

    #[test]
    fn uninstall_removes_private_provider_state_retains_cache_and_later_purge_removes_it() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        #[cfg(target_os = "linux")]
        let linux_runtime = {
            use std::os::unix::fs::PermissionsExt;

            let runtime = fixture
                .manager
                .linux_short_runtime_directory()
                .expect("Linux short runtime");
            let podman = runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
            fs::create_dir(&podman).expect("Podman runtime directory");
            fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
            let log = podman.join(PODMAN_GVPROXY_LOG_NAME);
            fs::write(&log, b"pinned gvproxy residue\n").unwrap();
            fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
            runtime
        };
        let identity = fixture.manager.machine_ssh_identity_path();
        let image = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
            fixture
                .manager
                .acquire_machine_image_locked(target, None)
                .expect("cache exact machine image")
        };
        let (private_temporary, _) = managed_ssh_identity_temporary_paths(&identity).unwrap();
        fs::write(&private_temporary, b"interrupted-staging-secret").unwrap();
        assert!(identity.is_file());
        assert!(managed_ssh_public_key_path(&identity).is_file());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("uninstall release-private state");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
        #[cfg(target_os = "linux")]
        assert!(!private_entry_exists(&linux_runtime).unwrap());
        assert!(!private_entry_exists(&identity).unwrap());
        assert!(!private_entry_exists(&managed_ssh_public_key_path(&identity)).unwrap());
        assert!(!private_entry_exists(&private_temporary).unwrap());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);

        let calls_before_purge = fixture.commands.calls().len();
        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions {
                stop_mode: ManagedStopMode::OnlyIfIdle,
                remove_machine_image_cache: true,
            })
            .expect("purge retained image cache without reinstalling the runtime");
        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!private_entry_exists(&image).unwrap());
        assert_eq!(fixture.commands.calls().len(), calls_before_purge);
    }

    #[test]
    fn uninstall_removes_the_exact_stopped_machine_before_private_state() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        #[cfg(target_os = "linux")]
        let linux_runtime_after_machine_removal = {
            use std::os::unix::fs::PermissionsExt;

            let runtime = fixture
                .manager
                .linux_short_runtime_directory()
                .expect("Linux short runtime");
            let podman = runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
            fs::create_dir(&podman).expect("Podman runtime directory");
            fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
            let log = podman.join(PODMAN_GVPROXY_LOG_NAME);
            fs::write(&log, b"pinned gvproxy residue after machine stop\n").unwrap();
            fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
            runtime
        };
        let identity = fixture.manager.machine_ssh_identity_path();
        let image = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
            fixture
                .manager
                .acquire_machine_image_locked(target, None)
                .expect("cache exact machine image")
        };
        #[cfg(windows)]
        let canonical_provider_home = fixture
            .manager
            .provider_home()
            .canonicalize()
            .expect("canonical provider home");
        let expected_machine = machine_name(target);
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        push_windows_wsl_absent(&fixture.commands);

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("remove exact stopped machine");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
        #[cfg(target_os = "linux")]
        assert!(!private_entry_exists(&linux_runtime_after_machine_removal).unwrap());
        assert!(!private_entry_exists(&identity).unwrap());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);
        let calls = fixture.commands.calls();
        assert_eq!(calls[0], ["machine", "list", "--format", "json"]);
        assert_eq!(
            calls[1],
            ["machine", "rm", "--force", expected_machine.as_str()]
        );
        #[cfg(windows)]
        {
            assert_eq!(calls[2], ["--list", "--quiet"]);
            let commands = fixture.commands.commands();
            let wsl = &commands[2];
            assert!(wsl.binary.is_absolute());
            assert_eq!(wsl.binary.file_name(), Some(OsStr::new("wsl.exe")));
            assert_eq!(
                wsl.binary.parent().and_then(Path::file_name),
                Some(OsStr::new("System32"))
            );
            assert_eq!(wsl.working_directory, canonical_provider_home);
            assert_eq!(wsl.environment.len(), 4);
            assert_eq!(
                wsl.environment
                    .get(OsStr::new("NoDefaultCurrentDirectoryInExePath")),
                Some(&OsString::from("1"))
            );
        }
    }

    #[test]
    fn uninstall_machine_removal_failure_retains_provider_install_and_cache() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        #[cfg(target_os = "linux")]
        let linux_runtime = fixture
            .manager
            .linux_short_runtime_directory()
            .expect("Linux short runtime");
        let identity = fixture.manager.machine_ssh_identity_path();
        let image = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
            fixture
                .manager
                .acquire_machine_image_locked(target, None)
                .expect("cache exact machine image")
        };
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(failure(b"exact removal failed"));

        let error = fixture
            .manager
            .uninstall(ManagedUninstallOptions {
                stop_mode: ManagedStopMode::Force,
                remove_machine_image_cache: true,
            })
            .expect_err("nonzero machine removal must retain all private state");

        assert!(error.to_string().contains("exact removal failed"));
        assert!(fixture.manager.install_directory().exists());
        assert!(fixture.manager.provider_home().exists());
        #[cfg(target_os = "linux")]
        assert!(private_entry_exists(&linux_runtime).unwrap());
        assert!(identity.is_file());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);
        assert_eq!(fixture.commands.calls().len(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_retains_all_state_when_exact_wsl_distribution_survives_remediation() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let image = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
            fixture
                .manager
                .acquire_machine_image_locked(target, None)
                .expect("cache exact machine image")
        };
        let expected_distribution = format!("podman-{}", machine_name(target));
        let listed = utf16le(&format!("{expected_distribution}\r\n"));
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        let mut first_inventory = success(listed.clone());
        first_inventory.stderr = b"WSL update notice".to_vec();
        fixture.commands.push(first_inventory);
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(listed));

        let error = fixture
            .manager
            .uninstall(ManagedUninstallOptions {
                stop_mode: ManagedStopMode::Force,
                remove_machine_image_cache: true,
            })
            .expect_err("a still-registered exact WSL distro must retain all private state");

        assert!(error.to_string().contains("remained registered"));
        assert!(fixture.manager.install_directory().exists());
        assert!(fixture.manager.provider_home().exists());
        assert!(identity.is_file());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);
        let calls = fixture.commands.calls();
        assert_eq!(calls[2], ["--list", "--quiet"]);
        assert_eq!(calls[3], ["--unregister", expected_distribution.as_str()]);
        assert_eq!(calls[4], ["--list", "--quiet"]);
        let commands = fixture.commands.commands();
        for command in &commands[2..=4] {
            assert_eq!(command.binary, commands[2].binary);
            assert_eq!(command.environment, commands[2].environment);
            assert_eq!(command.working_directory, commands[2].working_directory);
        }
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_unregisters_only_the_exact_orphaned_wsl_distribution_then_proves_absence() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let expected_distribution = format!("podman-{}", machine_name(target));
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(utf16le(&format!(
            "Ubuntu\r\n{expected_distribution}\r\n"
        ))));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(utf16le("Ubuntu\r\n")));

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("exact orphan remediation and absence proof");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
        let calls = fixture.commands.calls();
        assert_eq!(calls[3], ["--unregister", expected_distribution.as_str()]);
        assert_eq!(calls[4], ["--list", "--quiet"]);
        assert!(
            calls
                .iter()
                .flatten()
                .all(|argument| !argument.contains("podman-*") && !argument.contains("assm1-*"))
        );
    }

    #[test]
    fn uninstall_recovers_stale_provider_state_after_the_install_payload_was_lost() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        remove_private_tree(
            &fixture.manager.install_directory(),
            &fixture.manager.versions_root(),
        )
        .expect("simulate interrupted older uninstall");
        assert!(!fixture.manager.install_directory().exists());
        assert!(fixture.manager.provider_home().exists());
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("restore the verified client and clean stale provider state");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
        assert_eq!(
            fixture.commands.calls().len(),
            if cfg!(windows) { 2 } else { 1 }
        );
    }

    #[test]
    fn uninstall_rejects_an_unexpected_machine_before_removing_provider_state() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let identity = fixture.manager.machine_ssh_identity_path();
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        fixture.commands.push(success(
            serde_json::to_vec(&serde_json::json!([{
                "Name": "unexpected-private-machine",
                "Running": false,
                "VMType": target.provider.argument(),
                "CPUs": 2,
                "Memory": (4096_u64 * 1024 * 1024).to_string(),
                "DiskSize": (40_u64 * 1024 * 1024 * 1024).to_string()
            }]))
            .unwrap(),
        ));

        let error = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect_err("unexpected machine must fail closed");

        assert!(error.to_string().contains("unexpected machine"));
        assert!(fixture.manager.install_directory().exists());
        assert!(fixture.manager.provider_home().exists());
        assert!(identity.is_file());
        assert_eq!(fixture.commands.calls().len(), 1);
    }

    #[test]
    fn installed_runtime_reopens_by_exact_manifest_and_ambiguity_fails_closed() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let expected_digest = fixture.manager.manifest_sha256().to_owned();
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("app data parent")
            .to_path_buf();

        let reopened = ManagedRuntimeManager::open_installed(&app_data, Some(&expected_digest))
            .expect("reopen exact installation");
        assert_eq!(reopened.manifest_sha256(), expected_digest);

        let mut alternate_manifest = fixture.manager.loaded.manifest.clone();
        alternate_manifest.runtime_version = "5.8.1".into();
        let alternate_bytes = serde_json::to_vec(&alternate_manifest).expect("alternate manifest");
        let alternate = LoadedManagedRuntimeManifest::parse(&alternate_bytes).expect("alternate");
        let alternate_root = fixture
            .manager
            .versions_root()
            .join(installation_directory_name(&alternate));
        fs::create_dir(&alternate_root).expect("alternate root");
        fs::create_dir(alternate_root.join("bin")).expect("alternate bin");
        fs::write(alternate_root.join("manifest.json"), alternate_bytes)
            .expect("alternate manifest file");
        fs::write(alternate_root.join("bin/podman"), b"managed-podman-driver")
            .expect("alternate driver");

        let error = ManagedRuntimeManager::open_installed(&app_data, None)
            .expect_err("ambiguous install must fail closed");
        assert!(error.to_string().contains("exact manifest digest"));
        let exact = ManagedRuntimeManager::open_installed(&app_data, Some(&expected_digest))
            .expect("exact installation remains resolvable");
        assert_eq!(exact.manifest_sha256(), expected_digest);
    }

    #[test]
    fn changed_release_file_is_never_installed() {
        let fixture = fixture();
        fs::write(
            fixture.manager.resource_root.join("bin/podman"),
            b"tampered-driver",
        )
        .expect("tamper");
        assert!(fixture.manager.install().is_err());
        assert!(!fixture.manager.install_directory().exists());
    }

    #[test]
    fn start_acquires_exact_image_initializes_rootless_machine_and_preflights() {
        let fixture = fixture();
        push_windows_wsl_ready(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture.commands.push(success(Vec::new()));
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        let command = fixture.manager.start().expect("start");
        assert_eq!(command.runtime_version(), "5.8.2");
        let calls = fixture.commands.calls();
        let platform_probe_calls = if cfg!(windows) { 2 } else { 0 };
        if cfg!(windows) {
            assert_eq!(calls[0], ["--status"]);
            assert_eq!(calls[1], ["--list", "--quiet"]);
        }
        assert_eq!(
            calls[platform_probe_calls],
            ["machine", "list", "--format", "json"]
        );
        let init = &calls[platform_probe_calls + 1];
        assert_eq!(&init[..2], ["machine", "init"]);
        assert!(init.contains(&"--rootful=false".into()));
        assert!(init.contains(&"--image".into()));
        assert!(!init.contains(&"--provider".into()));
        let target = fixture.manager.loaded.target().expect("target");
        let volume_values = init
            .windows(2)
            .filter_map(|arguments| (arguments[0] == "--volume").then_some(arguments[1].clone()))
            .collect::<Vec<_>>();
        if target.operating_system == ManagedOperatingSystem::Linux {
            let application_data = fixture
                .manager
                .canonical_application_data_root()
                .expect("canonical application data");
            assert_eq!(
                volume_values,
                [linux_machine_volume_spec(&application_data)
                    .expect("Linux volume")
                    .to_string_lossy()
                    .into_owned()]
            );
        } else {
            assert!(volume_values.is_empty());
        }
        assert!(
            !init
                .iter()
                .any(|argument| argument == "sudo" || argument == "sh")
        );
        assert_eq!(
            calls[platform_probe_calls + 3][..3],
            ["machine", "start", "--quiet"]
        );
        assert_eq!(
            calls[platform_probe_calls + 4],
            ["version", "--format", "{{.Server.Version}}"]
        );
        let mut expected_timeouts = vec![];
        if cfg!(windows) {
            expected_timeouts.extend([COMMAND_TIMEOUT, COMMAND_TIMEOUT]);
        }
        expected_timeouts.extend([
            COMMAND_TIMEOUT,
            MACHINE_INIT_TIMEOUT,
            COMMAND_TIMEOUT,
            MACHINE_START_TIMEOUT,
            COMMAND_TIMEOUT,
        ]);
        assert_eq!(fixture.commands.timeouts(), expected_timeouts);
        let cached = fixture
            .manager
            .machine_image_path(fixture.manager.loaded.target().expect("target"));
        assert_eq!(fs::read(cached).expect("cached"), fixture.image);

        let identity = fixture.manager.machine_ssh_identity_path();
        let private_bytes = Zeroizing::new(fs::read(&identity).expect("private identity"));
        let private_key =
            PrivateKey::from_openssh(private_bytes.as_slice()).expect("OpenSSH private key");
        let public_text =
            fs::read_to_string(managed_ssh_public_key_path(&identity)).expect("public identity");
        let public_key = PublicKey::from_openssh(&public_text).expect("OpenSSH public key");
        assert_eq!(private_key.algorithm(), Algorithm::Ed25519);
        assert!(!private_key.is_encrypted());
        assert_eq!(public_key.algorithm(), Algorithm::Ed25519);
        assert_eq!(private_key.public_key().key_data(), public_key.key_data());
        assert_eq!(private_key.comment(), MANAGED_SSH_KEY_COMMENT);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&identity).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(managed_ssh_public_key_path(&identity))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn machine_application_data_volume_is_linux_only() {
        let fixture = fixture();
        let mut target = fixture.manager.loaded.target().expect("target").clone();

        target.operating_system = ManagedOperatingSystem::Macos;
        target.provider = ManagedMachineProvider::Applehv;
        assert_eq!(
            fixture
                .manager
                .machine_application_data_volume(&target)
                .expect("macOS volume policy"),
            None
        );

        target.operating_system = ManagedOperatingSystem::Windows;
        target.provider = ManagedMachineProvider::Wsl;
        assert_eq!(
            fixture
                .manager
                .machine_application_data_volume(&target)
                .expect("Windows volume policy"),
            None
        );
    }

    #[test]
    fn managed_ssh_identity_is_reused_and_partial_regular_pair_is_safely_repaired() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let public_identity = managed_ssh_public_key_path(&identity);

        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        let first_private = fs::read(&identity).expect("first private key");
        let first_public = fs::read(&public_identity).expect("first public key");
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("reuse valid identity");
        }
        assert_eq!(fs::read(&identity).unwrap(), first_private);
        assert_eq!(fs::read(&public_identity).unwrap(), first_public);

        fs::remove_file(&public_identity).expect("make partial pair");
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("repair partial identity before init");
        }
        assert_eq!(
            inspect_managed_ssh_identity(&identity).expect("inspect repaired pair"),
            ManagedSshIdentityState::Valid
        );
        assert!(private_entry_exists(&public_identity).unwrap());
    }

    #[test]
    fn initialized_machine_rejects_an_inconsistent_ssh_identity_without_rotating_it() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        let private_before = fs::read(&identity).expect("private key before failure");
        fs::write(
            managed_ssh_public_key_path(&identity),
            b"not-an-openssh-public-key\n",
        )
        .expect("corrupt public half");
        push_windows_wsl_ready(&fixture.commands);
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));

        let error = fixture
            .manager
            .start()
            .expect_err("initialized machine identity mismatch must fail closed");

        assert!(error.to_string().contains("refusing to rotate"));
        assert_eq!(fs::read(&identity).unwrap(), private_before);
        assert_eq!(
            fixture.commands.calls().len(),
            if cfg!(windows) { 3 } else { 1 }
        );
    }

    #[cfg(unix)]
    #[test]
    fn initialized_machine_rejects_an_overexposed_private_ssh_key_without_changing_its_mode() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644))
            .expect("overexpose private key");
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));

        let error = fixture
            .manager
            .start()
            .expect_err("initialized machine must reject an overexposed private key");

        assert!(error.to_string().contains("unsafe permissions"));
        assert_eq!(
            fs::metadata(&identity).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(fixture.commands.calls().len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn windows_managed_ssh_identity_refuses_a_permissive_parent_before_creation() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let identity_parent = identity.parent().expect("identity parent");
        ensure_private_directory_tree(
            &fixture.manager.provider_home().join("data"),
            identity_parent,
        )
        .expect("identity directory");
        set_windows_permissive_inheritable_dacl(identity_parent);

        let inherited_probe = identity_parent.join("inherited-acl-probe");
        fs::write(&inherited_probe, b"probe").expect("create inherited ACL probe");
        let probe = File::open(&inherited_probe).expect("open inherited ACL probe");
        assert!(
            verify_windows_current_user_only_dacl(&probe).is_err(),
            "ordinary child must demonstrate that the parent DACL is permissive"
        );
        drop(probe);
        fs::remove_file(&inherited_probe).expect("remove inherited ACL probe");

        let error = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect_err("permissive identity parent must fail closed")
        };

        let public_identity = managed_ssh_public_key_path(&identity);
        let (private_temporary, public_temporary) =
            managed_ssh_identity_temporary_paths(&identity).expect("temporary paths");
        assert!(error.to_string().contains("DACL"));
        for unexpected in [
            &identity,
            &public_identity,
            &private_temporary,
            &public_temporary,
        ] {
            assert!(
                !private_entry_exists(unexpected).expect("inspect rejected identity path"),
                "unsafe parent must not receive any identity entry: {}",
                unexpected.display()
            );
        }
        let parent = open_windows_real_directory_security_handle(identity_parent)
            .expect("reopen permissive parent");
        assert!(
            verify_windows_current_user_only_dacl_with_ace_flags(
                &parent,
                u8::try_from(
                    windows_sys::Win32::Security::OBJECT_INHERIT_ACE
                        | windows_sys::Win32::Security::CONTAINER_INHERIT_ACE,
                )
                .expect("inheritance flags")
            )
            .is_err(),
            "the rejected parent DACL must not be repaired as a side effect"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_managed_ssh_identity_rejects_ntfs_hard_links_without_repairing_them() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        ensure_private_directory_tree(
            &fixture.manager.provider_home().join("data"),
            identity.parent().expect("identity parent"),
        )
        .expect("identity directory");
        let outside = fixture._temp.path().join("outside-hard-linked-identity");
        fs::write(&outside, b"outside-remains").expect("outside file");
        fs::hard_link(&outside, &identity).expect("NTFS identity hard link");

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect_err("identity hard link must fail closed before repair");

        assert!(error.to_string().contains("must not be hard-linked"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-remains");
        assert_eq!(fs::read(&identity).unwrap(), b"outside-remains");
        let outside_file = File::open(&outside).expect("open outside file");
        assert_eq!(
            windows_file_information(&outside_file)
                .expect("outside handle information")
                .number_of_links,
            2
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn managed_ssh_identity_recovers_a_public_publish_crash_link() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let parent = identity.parent().expect("identity parent");
        ensure_private_directory_tree(&fixture.manager.provider_home().join("data"), parent)
            .expect("identity directory");
        let (_, public_temporary) = managed_ssh_identity_temporary_paths(&identity).unwrap();
        let public_identity = managed_ssh_public_key_path(&identity);
        let mut staging = create_private_file(&public_temporary).expect("public staging file");
        staging
            .write_all(b"interrupted-publication")
            .expect("write public staging");
        staging.sync_all().expect("sync public staging");
        drop(staging);
        fs::hard_link(&public_temporary, &public_identity)
            .expect("simulate public hard-link publication before staging unlink");

        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("recover public publication crash");
        }

        assert!(!private_entry_exists(&public_temporary).unwrap());
        assert_eq!(
            inspect_managed_ssh_identity(&identity).expect("inspect recovered identity"),
            ManagedSshIdentityState::Valid
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn managed_ssh_identity_recovers_a_private_publish_crash_link() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let parent = identity.parent().expect("identity parent");
        ensure_private_directory_tree(&fixture.manager.provider_home().join("data"), parent)
            .expect("identity directory");
        let (private_temporary, _) = managed_ssh_identity_temporary_paths(&identity).unwrap();
        let mut staging = create_private_file(&private_temporary).expect("private staging file");
        staging
            .write_all(b"interrupted-private-publication")
            .expect("write private staging");
        staging.sync_all().expect("sync private staging");
        drop(staging);
        fs::hard_link(&private_temporary, &identity)
            .expect("simulate private hard-link publication before staging unlink");

        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("recover private publication crash");
        }

        assert!(!private_entry_exists(&private_temporary).unwrap());
        assert_eq!(
            inspect_managed_ssh_identity(&identity).expect("inspect recovered identity"),
            ManagedSshIdentityState::Valid
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn managed_ssh_identity_rejects_a_hard_linked_staging_file_without_mutating_it() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let parent = identity.parent().expect("identity parent");
        ensure_private_directory_tree(&fixture.manager.provider_home().join("data"), parent)
            .expect("identity directory");
        let (private_temporary, _) = managed_ssh_identity_temporary_paths(&identity).unwrap();
        let outside = fixture._temp.path().join("outside-staging-hard-link");
        fs::write(&outside, b"outside-remains").expect("outside file");
        fs::hard_link(&outside, &private_temporary).expect("staging hard link");

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect_err("hard-linked staging file must fail closed");

        assert!(error.to_string().contains("must not be hard-linked"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-remains");
        assert_eq!(fs::read(&private_temporary).unwrap(), b"outside-remains");
    }

    #[cfg(unix)]
    #[test]
    fn managed_ssh_identity_rejects_symlinks_without_touching_the_target() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        ensure_private_directory_tree(
            &fixture.manager.provider_home().join("data"),
            identity.parent().expect("identity parent"),
        )
        .expect("identity directory");
        let outside = fixture._temp.path().join("outside-identity");
        fs::write(&outside, b"outside-remains").expect("outside file");
        symlink(&outside, &identity).expect("identity symlink");

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect_err("identity symlink must fail closed");

        assert!(error.to_string().contains("real regular file"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-remains");
        assert!(
            fs::symlink_metadata(&identity)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn managed_ssh_identity_rejects_hard_links_without_mutating_the_other_name() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        ensure_private_directory_tree(
            &fixture.manager.provider_home().join("data"),
            identity.parent().expect("identity parent"),
        )
        .expect("identity directory");
        let outside = fixture._temp.path().join("outside-hard-linked-identity");
        fs::write(&outside, b"outside-remains").expect("outside file");
        let mode_before = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        fs::hard_link(&outside, &identity).expect("identity hard link");

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect_err("identity hard link must fail closed");

        assert!(error.to_string().contains("must not be hard-linked"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-remains");
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            mode_before
        );
        assert_eq!(fs::metadata(&outside).unwrap().nlink(), 2);
    }

    #[test]
    fn observable_setup_reaches_verified_completed_state() {
        let fixture = fixture();
        push_windows_wsl_ready(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture.commands.push(success(Vec::new()));
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));
        let setup = ManagedRuntimeSetupController::default();

        let runtime = fixture.manager.setup(&setup).expect("observable setup");
        assert!(runtime.available);
        assert_eq!(runtime.phase, ManagedRuntimePhase::Running);
        let setup_status = setup.status().expect("setup status");
        assert_eq!(setup_status.phase, ManagedRuntimeSetupPhase::Completed);
        assert!(!setup_status.active);
        assert!(!setup_status.can_retry);
        assert_eq!(setup_status.received_bytes, fixture.image.len() as u64);
        assert_eq!(setup_status.total_bytes, Some(fixture.image.len() as u64));
        assert_eq!(setup_status.progress_percent, Some(100.0));
        assert_eq!(setup_status.failure_reason, None);
        assert_eq!(setup_status.next_action, None);
    }

    #[test]
    fn wrong_machine_contract_fails_closed() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        let inventory = serde_json::to_vec(&serde_json::json!([{
            "Name": machine_name(target),
            "Running": false,
            "VMType": target.provider.argument(),
            "CPUs": 99,
            "Memory": (4096_u64 * 1024 * 1024).to_string(),
            "DiskSize": (40_u64 * 1024 * 1024 * 1024).to_string()
        }]))
        .expect("json");
        push_windows_wsl_ready(&fixture.commands);
        fixture.commands.push(success(inventory));
        assert!(fixture.manager.start().is_err());
    }

    #[test]
    fn idle_stop_refuses_to_interrupt_a_container_and_force_is_explicit() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, true)));
        fixture.commands.push(success(b"engine-one\n".to_vec()));
        let error = fixture
            .manager
            .stop(ManagedStopMode::OnlyIfIdle)
            .expect_err("must refuse");
        assert!(error.to_string().contains("running engine"));

        fixture
            .commands
            .push(success(machine_json(&fixture.manager, true)));
        fixture.commands.push(success(Vec::new()));
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        let status = fixture
            .manager
            .stop(ManagedStopMode::Force)
            .expect("force stop");
        assert_eq!(status.phase, ManagedRuntimePhase::Stopped);
    }

    #[test]
    fn command_environment_is_private_and_does_not_inherit_container_hosts() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        let command = fixture.manager.runtime_command(target).expect("command");
        let command_home = PathBuf::from(
            command
                .environment
                .get(OsStr::new("HOME"))
                .expect("command HOME"),
        );
        assert_eq!(
            command.environment.get(OsStr::new("USERPROFILE")),
            command.environment.get(OsStr::new("HOME"))
        );
        assert_eq!(command.working_directory, command_home);
        assert!(
            command
                .environment
                .contains_key(OsStr::new("XDG_CONFIG_HOME"))
        );
        assert!(
            command
                .environment
                .contains_key(OsStr::new("XDG_DATA_HOME"))
        );
        assert!(!command.environment.contains_key(OsStr::new("DOCKER_HOST")));
        assert!(
            !command
                .environment
                .contains_key(OsStr::new("CONTAINER_HOST"))
        );
        let xdg_data_home = PathBuf::from(
            command
                .environment
                .get(OsStr::new("XDG_DATA_HOME"))
                .expect("XDG data home"),
        );
        assert_eq!(
            fixture.manager.machine_ssh_identity_path(),
            xdg_data_home.join("containers/podman/machine/machine")
        );
        let xdg_runtime_directory = PathBuf::from(
            command
                .environment
                .get(OsStr::new("XDG_RUNTIME_DIR"))
                .expect("XDG runtime directory"),
        );
        if target.operating_system == ManagedOperatingSystem::Linux {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                use std::os::unix::fs::MetadataExt;

                assert_eq!(
                    xdg_runtime_directory,
                    fixture
                        .manager
                        .linux_short_runtime_directory()
                        .expect("deterministic Linux short runtime")
                );
                assert_eq!(xdg_runtime_directory.parent(), Some(Path::new("/tmp")));
                verify_linux_short_runtime_directory(&xdg_runtime_directory, effective_uid())
                    .expect("private Linux short runtime");
                let socket =
                    linux_podman_gvproxy_socket_path(&xdg_runtime_directory, &machine_name(target));
                assert!(socket.as_os_str().as_bytes().len() <= PODMAN_LINUX_MAX_SOCKET_PATH_BYTES);
                assert!(
                    !private_entry_exists(&xdg_runtime_directory.join("containers")).unwrap(),
                    "containers/storage state must not be created in the socket-bounded runtime"
                );

                let provider_home = fixture.manager.provider_home();
                let storage_config = provider_home
                    .join("config")
                    .join("containers")
                    .join("storage.conf");
                assert_eq!(
                    command
                        .environment
                        .get(OsStr::new("CONTAINERS_STORAGE_CONF"))
                        .map(OsString::as_os_str),
                    Some(storage_config.as_os_str())
                );
                let storage_runroot = provider_home.join("run").join("containers");
                let storage_graphroot = provider_home
                    .join("data")
                    .join("containers")
                    .join("storage");
                assert_eq!(
                    fs::read_to_string(&storage_config).expect("private storage config"),
                    format!(
                        "[storage]\nrunroot = {}\ngraphroot = {}\n",
                        toml_string(&storage_runroot).unwrap(),
                        toml_string(&storage_graphroot).unwrap(),
                    )
                );
                let storage_metadata = fs::symlink_metadata(&storage_config).unwrap();
                assert!(storage_metadata.is_file());
                assert!(!storage_metadata.file_type().is_symlink());
                assert_eq!(storage_metadata.uid(), effective_uid());
                assert_eq!(storage_metadata.mode() & 0o7777, 0o600);
                for directory in [storage_runroot, storage_graphroot] {
                    let metadata = fs::symlink_metadata(&directory).unwrap();
                    assert!(metadata.is_dir());
                    assert!(!metadata.file_type().is_symlink());
                    assert_eq!(metadata.uid(), effective_uid());
                    assert_eq!(metadata.mode() & 0o7777, 0o700);
                }
            }
        } else {
            assert!(
                !command
                    .environment
                    .contains_key(OsStr::new("CONTAINERS_STORAGE_CONF"))
            );
            assert_eq!(
                xdg_runtime_directory,
                fixture.manager.provider_home().join("run")
            );
        }
        if target.operating_system == ManagedOperatingSystem::Macos {
            assert_ne!(command_home, fixture.manager.provider_home());
            #[cfg(unix)]
            assert!(command_home.starts_with(MACOS_SHORT_HOME_BASE));
        } else {
            assert_eq!(command_home, fixture.manager.provider_home());
        }
        let windows_lookup_guard = command
            .environment
            .get(OsStr::new("NoDefaultCurrentDirectoryInExePath"));
        if target.operating_system == ManagedOperatingSystem::Windows {
            assert_eq!(
                windows_lookup_guard.map(OsString::as_os_str),
                Some(OsStr::new("1"))
            );
            assert_eq!(
                command.environment.get(OsStr::new("WINDIR")),
                command.environment.get(OsStr::new("SystemRoot"))
            );
            let system_root = PathBuf::from(
                command
                    .environment
                    .get(OsStr::new("SystemRoot"))
                    .expect("trusted Windows root"),
            );
            let managed_paths = std::env::split_paths(
                command
                    .environment
                    .get(OsStr::new("PATH"))
                    .expect("managed PATH"),
            )
            .collect::<Vec<_>>();
            assert_eq!(managed_paths.last(), Some(&system_root.join("System32")));
        } else {
            assert!(windows_lookup_guard.is_none());
        }
        for value in command.environment.values() {
            assert!(!value.to_string_lossy().contains('\n'));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_storage_configuration_is_immutable() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        let command = fixture.manager.runtime_command(target).expect("command");
        let storage_config = PathBuf::from(
            command
                .environment
                .get(OsStr::new("CONTAINERS_STORAGE_CONF"))
                .expect("Linux storage config"),
        );
        fs::write(&storage_config, b"[storage]\nrunroot = \"tampered\"\n")
            .expect("tamper storage config");

        let error = fixture
            .manager
            .runtime_command(target)
            .expect_err("immutable storage config mismatch must fail closed");

        assert!(
            error
                .to_string()
                .contains("immutable configuration differs")
        );
        assert_eq!(
            fs::read(&storage_config).unwrap(),
            b"[storage]\nrunroot = \"tampered\"\n"
        );
    }

    #[test]
    fn current_directory_helper_lookup_is_disabled_only_for_windows_commands() {
        let key = OsString::from("NoDefaultCurrentDirectoryInExePath");
        let mut environment = BTreeMap::new();

        apply_platform_command_environment(&mut environment, ManagedOperatingSystem::Windows);
        assert_eq!(environment.get(&key), Some(&OsString::from("1")));

        for operating_system in [ManagedOperatingSystem::Linux, ManagedOperatingSystem::Macos] {
            apply_platform_command_environment(&mut environment, operating_system);
            assert!(!environment.contains_key(&key));
            apply_platform_command_environment(&mut environment, ManagedOperatingSystem::Windows);
        }
    }

    #[test]
    fn command_execution_errors_use_fixed_operation_labels_without_arguments() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        let command = fixture.manager.runtime_command(target).expect("command");
        let operations = [
            ManagedCommandOperation::MachineInitialization,
            ManagedCommandOperation::MachineInventory,
            ManagedCommandOperation::MachineStart,
            ManagedCommandOperation::MachineStop,
            ManagedCommandOperation::MachineRemoval,
            ManagedCommandOperation::WslDistributionInventory,
            ManagedCommandOperation::WslDistributionRemoval,
            ManagedCommandOperation::ActiveContainerInventory,
            ManagedCommandOperation::VersionPreflight,
        ];
        let mut labels = BTreeSet::new();

        for operation in operations {
            assert!(labels.insert(operation.label()));
            let error = fixture
                .manager
                .run_command(
                    operation,
                    &command,
                    ["--credential=must-not-appear"],
                    COMMAND_TIMEOUT,
                )
                .expect_err("empty fake output queue must fail");
            let message = error.to_string();
            assert!(message.contains(operation.label()));
            assert!(!message.contains("must-not-appear"));
        }
    }

    #[test]
    fn setup_controller_rejects_parallel_attempts_and_allows_retry_after_cancel() {
        let controller = ManagedRuntimeSetupController::default();
        controller.begin().expect("first setup");
        let error = controller.begin().expect_err("parallel setup rejected");
        assert!(error.to_string().contains("already active"));

        let requested = controller.request_cancel().expect("request cancellation");
        assert!(requested.active);
        assert!(requested.cancel_requested);
        assert!(controller.check_cancelled().is_err());
        controller.finish_cancelled().expect("finish cancelled");
        let cancelled = controller.status().expect("cancelled status");
        assert_eq!(cancelled.phase, ManagedRuntimeSetupPhase::Cancelled);
        assert!(!cancelled.active);
        assert!(cancelled.can_retry);

        controller.begin().expect("retry starts");
        assert_eq!(
            controller.status().expect("retry status").phase,
            ManagedRuntimeSetupPhase::Install
        );
    }

    #[test]
    fn resume_content_range_must_match_exact_locked_suffix() {
        validate_resume_content_range("bytes 131072-262460/262461", 131_072, 262_461)
            .expect("exact range");
        for invalid in [
            "bytes 0-262460/262461",
            "bytes 131072-200000/262461",
            "bytes 131072-262460/999999",
            "items 131072-262460/262461",
            "garbage",
        ] {
            assert!(
                validate_resume_content_range(invalid, 131_072, 262_461).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn chunk_progress_cancel_retains_partial_and_next_attempt_resumes_exactly() {
        let temp = tempfile::tempdir().expect("temp");
        let partial = temp.path().join("machine.download-part");
        let total = (DOWNLOAD_CHUNK_BYTES * 2 + 317) as u64;
        let bytes = (0..total)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let controller = ManagedRuntimeSetupController::default();
        controller.begin().expect("begin download");
        controller
            .report_download(0, total, 0)
            .expect("initial progress");

        let mut first_observations = Vec::new();
        let mut requested_cancel = false;
        let mut first_reader = io::Cursor::new(bytes.as_slice());
        let mut first_file = open_private_download_file(&partial, false).expect("partial file");
        let error = write_download_body(
            &mut first_reader,
            &mut first_file,
            0,
            total,
            0,
            &mut |received, observed_total, resumed_from| {
                first_observations.push((received, observed_total, resumed_from));
                if !requested_cancel {
                    requested_cancel = true;
                    controller.request_cancel()?;
                }
                controller.report_download(received, observed_total, resumed_from)
            },
        )
        .expect_err("cancel stops bounded chunk loop");
        assert!(error.to_string().contains("cancelled"));
        drop(first_file);
        let retained = fs::metadata(&partial).expect("partial metadata").len();
        assert_eq!(retained, DOWNLOAD_CHUNK_BYTES as u64);
        assert_eq!(
            first_observations,
            vec![(DOWNLOAD_CHUNK_BYTES as u64, total, 0)]
        );
        let cancelled_progress = controller.status().expect("progress status");
        assert_eq!(cancelled_progress.received_bytes, retained);
        assert_eq!(cancelled_progress.total_bytes, Some(total));
        assert_eq!(cancelled_progress.resumed_from_bytes, 0);
        controller.finish_cancelled().expect("finish cancellation");

        controller.begin().expect("begin resume");
        controller
            .report_download(retained, total, retained)
            .expect("resume progress");
        let mut resumed_observations = Vec::new();
        let mut remainder = io::Cursor::new(&bytes[retained as usize..]);
        let mut resumed_file = open_private_download_file(&partial, true).expect("append partial");
        let written = write_download_body(
            &mut remainder,
            &mut resumed_file,
            retained,
            total,
            retained,
            &mut |received, observed_total, resumed_from| {
                resumed_observations.push((received, observed_total, resumed_from));
                controller.report_download(received, observed_total, resumed_from)
            },
        )
        .expect("resume completes");
        drop(resumed_file);
        assert_eq!(written, total);
        assert_eq!(fs::read(&partial).expect("resumed bytes"), bytes);
        assert_eq!(
            resumed_observations,
            vec![
                ((DOWNLOAD_CHUNK_BYTES * 2) as u64, total, retained),
                (total, total, retained),
            ]
        );
        let resumed = controller.status().expect("resumed status");
        assert_eq!(resumed.received_bytes, total);
        assert_eq!(resumed.progress_percent, Some(100.0));
        assert_eq!(resumed.resumed_from_bytes, retained);
    }
}
