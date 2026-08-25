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
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;

const MANIFEST_SCHEMA_VERSION: &str = "2";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_BUNDLE_FILES: usize = 128;
const MAX_INSTALLED_VERSIONS: usize = 32;
const MAX_BUNDLE_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MACHINE_IMAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: u64 = 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MACHINE_START_TIMEOUT: Duration = Duration::from_secs(180);
const MACHINE_STOP_TIMEOUT: Duration = Duration::from_secs(90);
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);
const DOWNLOAD_CHUNK_BYTES: usize = 128 * 1024;
const MACHINE_PREFIX: &str = "ass-managed-v1";

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
    Download,
    Init,
    Start,
    Verify,
    Completed,
    Failed,
    Cancelled,
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
            .map(|status| status.clone())
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
        Ok(status.clone())
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
        status.detail = detail;
        self.cancel_requested.store(false, Ordering::Release);
        Ok(())
    }
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

impl ManagedCommandRunner for DirectManagedCommandRunner {
    fn output(
        &self,
        command: &ManagedRuntimeCommand,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<ManagedCommandOutput> {
        let mut process = Command::new(&command.binary);
        process
            .args(args)
            .env_clear()
            .envs(command.environment.iter())
            .current_dir(&command.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            process.creation_flags(0x0800_0000);
        }
        let mut child = process.spawn()?;
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
        let stdout_capture = spawn_bounded_capture(
            stdout,
            captured.clone(),
            oversized.clone(),
            MAX_COMMAND_OUTPUT_BYTES,
        );
        let stderr_capture = spawn_bounded_capture(
            stderr,
            captured,
            oversized.clone(),
            MAX_COMMAND_OUTPUT_BYTES,
        );

        let deadline = Instant::now() + timeout;
        let process_result = loop {
            if let Some(status) = child.try_wait()? {
                break Ok(status);
            }
            if oversized.load(Ordering::Acquire) {
                let _ = child.kill();
                let _ = child.wait();
                break Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "managed runtime command output exceeded its aggregate limit",
                ));
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed runtime command exceeded its deadline",
                ));
            }
            thread::sleep(Duration::from_millis(25));
        };
        let stdout = join_bounded_capture(stdout_capture)?;
        let stderr = join_bounded_capture(stderr_capture)?;
        let status = process_result?;
        if oversized.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed runtime command output exceeded its aggregate limit",
            ));
        }
        Ok(ManagedCommandOutput {
            status,
            stdout,
            stderr,
        })
    }
}

fn spawn_bounded_capture<R>(
    mut reader: R,
    captured: Arc<AtomicU64>,
    oversized: Arc<AtomicBool>,
    maximum: u64,
) -> thread::JoinHandle<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0_u8; 16 * 1024];
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
    })
}

fn join_bounded_capture(handle: thread::JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| io::Error::other("managed runtime output capture thread failed"))?
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
        ensure_private_directory(&state_root)?;
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
        ensure_private_directory(&state_root)?;
        let resource_root = canonical_real_directory(&resource_root, "managed runtime resource")?;
        let manager = Self {
            state_root,
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
            self.prove_machine(machine, target)?;
        } else {
            self.initialize_machine(&command, &image, &machine_name)?;
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
        let _lock = self.lock()?;
        if private_entry_exists(&self.install_directory())? {
            // Repair a corrupted release payload from the verified application
            // resources before invoking it for owned-machine cleanup. A damaged
            // client must not permanently wedge either retry or uninstall.
            self.install_locked()?;
            let target = self.loaded.target()?;
            let command = self.runtime_command(target)?;
            let machine_name = machine_name(target);
            let machines = self.list_machines(&command)?;
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
                        &command,
                        ["machine", "stop", machine_name.as_str()],
                        MACHINE_STOP_TIMEOUT,
                    )?;
                    require_success("managed runtime machine stop", &output)?;
                }
                let output = self.run_command(
                    &command,
                    ["machine", "rm", "--force", machine_name.as_str()],
                    MACHINE_STOP_TIMEOUT,
                )?;
                require_success("managed runtime machine removal", &output)?;
            }
            remove_private_tree(&self.install_directory(), &self.versions_root())?;
            if options.remove_machine_image_cache {
                let image = self.machine_image_path(target);
                if private_entry_exists(&image)? {
                    remove_private_tree(&image, &self.image_cache_root())?;
                }
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
        ensure_private_directory(&self.versions_root())?;
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
        ensure_private_directory(&staging)?;
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
        ensure_private_directory(&provider_root)?;
        let home = provider_root.join(&self.loaded.sha256[..16]);
        let config = home.join("config");
        let data = home.join("data");
        let cache = home.join("cache");
        let run = home.join("run");
        for directory in [&home, &config, &data, &cache, &run] {
            ensure_private_directory(directory)?;
        }
        let containers = config.join("containers");
        ensure_private_directory(&containers)?;
        self.write_containers_config(&containers.join("containers.conf"), &install, target)?;

        let mut environment = BTreeMap::new();
        let home_value = home.as_os_str().to_owned();
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
            run.as_os_str().to_owned(),
        );
        environment.insert(OsString::from("APPDATA"), config.as_os_str().to_owned());
        environment.insert(OsString::from("LOCALAPPDATA"), data.as_os_str().to_owned());
        environment.insert(
            OsString::from("CONTAINERS_CONF"),
            containers.join("containers.conf").into_os_string(),
        );
        environment.insert(
            OsString::from("CONTAINERS_MACHINE_PROVIDER"),
            OsString::from(target.provider.argument()),
        );
        environment.insert(OsString::from("PATH"), managed_path(&install, target)?);
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            environment.insert(OsString::from("SystemRoot"), system_root);
        }
        environment.insert(OsString::from("LANG"), OsString::from("C.UTF-8"));
        environment.insert(OsString::from("LC_ALL"), OsString::from("C.UTF-8"));

        Ok(ManagedRuntimeCommand {
            binary,
            environment,
            working_directory: home,
            runtime_version: self.loaded.manifest.runtime_version.clone(),
            manifest_sha256: self.loaded.sha256.clone(),
            machine_image_sha256: target.machine_image.sha256.clone(),
        })
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

    fn acquire_machine_image_locked(
        &self,
        target: &ManagedTarget,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<PathBuf> {
        ensure_private_directory(&self.image_cache_root())?;
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
        let args = vec![
            OsString::from("machine"),
            OsString::from("init"),
            OsString::from("--cpus"),
            OsString::from(cpus),
            OsString::from("--memory"),
            OsString::from(memory),
            OsString::from("--disk-size"),
            OsString::from(disk),
            OsString::from("--rootful=false"),
            OsString::from("--image"),
            OsString::from(image),
            OsString::from(machine_name),
        ];
        let output = self
            .commands
            .output(command, &args, MACHINE_START_TIMEOUT)
            .map_err(|error| {
                AppError::Runtime(format!(
                    "managed runtime machine initialization could not execute: {error}"
                ))
            })?;
        require_success("managed runtime machine initialization", &output)
    }

    fn list_machines(&self, command: &ManagedRuntimeCommand) -> AppResult<Vec<MachineListEntry>> {
        let output = self.run_command(
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
        let output =
            self.run_command(command, ["ps", "--format", "{{.Names}}"], COMMAND_TIMEOUT)?;
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
        command: &ManagedRuntimeCommand,
        args: [&str; N],
        timeout: Duration,
    ) -> AppResult<ManagedCommandOutput> {
        let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
        self.commands
            .output(command, &args, timeout)
            .map_err(|error| {
                AppError::Runtime(format!(
                    "managed runtime command could not execute: {error}"
                ))
            })
    }

    fn lock(&self) -> AppResult<ManagedRuntimeLock> {
        ensure_private_directory(&self.state_root)?;
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

fn machine_name(target: &ManagedTarget) -> String {
    format!(
        "{MACHINE_PREFIX}-{}-{}-{}",
        target.operating_system.key(),
        target.architecture.key(),
        &target.machine_image.sha256[..12]
    )
}

fn installation_directory_name(loaded: &LoadedManagedRuntimeManifest) -> String {
    format!(
        "{}-{}-{}",
        loaded.manifest.bundle_id,
        loaded.manifest.runtime_version,
        &loaded.sha256[..16]
    )
}

fn require_success(operation: &str, output: &ManagedCommandOutput) -> AppResult<()> {
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail: String = detail.chars().take(4096).collect();
    Err(AppError::Runtime(format!(
        "{operation} failed with status {}: {}",
        output.status,
        detail.trim()
    )))
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

fn managed_path(install: &Path, target: &ManagedTarget) -> AppResult<OsString> {
    let bin = install.join("bin");
    let rendered = bin.to_str().ok_or_else(|| {
        AppError::Runtime("managed runtime install path is not representable".into())
    })?;
    let path = match target.operating_system {
        ManagedOperatingSystem::Windows => {
            let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
                AppError::NotAvailable("Windows SystemRoot is unavailable".into())
            })?;
            let system32 = PathBuf::from(system_root).join("System32");
            std::env::join_paths([PathBuf::from(rendered), system32])
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
        ensure_private_directory(&current)?;
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

fn create_private_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
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
    ensure_private_directory(parent)?;
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

/// Removes one exact backend-owned entry without following a symlink. A
/// corrupted install/cache path may itself be a file or symlink; refusing to
/// unlink that directory entry would permanently wedge verified repair.
fn remove_private_tree(path: &Path, expected_parent: &Path) -> AppResult<()> {
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
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        let _ = metadata;
        remove_windows_private_entry_tree(path)?;
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
fn remove_windows_private_entry_tree(path: &Path) -> AppResult<()> {
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
            remove_windows_private_entry_tree(&entry?.path())?;
        }
        set_windows_entry_readonly_nofollow(path, false)?;
        fs::remove_dir(path)?;
    } else {
        // FILE_FLAG_OPEN_REPARSE_POINT ensures the attribute update targets
        // the link/junction entry itself. DeleteFileW/RemoveDirectoryW then
        // unlink that entry rather than traversing its target.
        set_windows_entry_readonly_nofollow(path, false)?;
        if directory {
            fs::remove_dir(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_windows_entry_readonly_nofollow(path: &Path, readonly: bool) -> AppResult<()> {
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
        return Err(io::Error::last_os_error().into());
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
        return Err(io::Error::last_os_error().into());
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
        return Err(io::Error::last_os_error().into());
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

    #[derive(Default)]
    struct FakeCommands {
        calls: Mutex<Vec<Vec<String>>>,
        outputs: Mutex<VecDeque<ManagedCommandOutput>>,
    }

    impl FakeCommands {
        fn push(&self, output: ManagedCommandOutput) {
            self.outputs.lock().expect("outputs").push_back(output);
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().expect("calls").clone()
        }
    }

    impl ManagedCommandRunner for FakeCommands {
        fn output(
            &self,
            _command: &ManagedRuntimeCommand,
            args: &[OsString],
            _timeout: Duration,
        ) -> io::Result<ManagedCommandOutput> {
            self.calls.lock().expect("calls").push(
                args.iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            );
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
        _temp: TempDir,
        manager: ManagedRuntimeManager,
        commands: Arc<FakeCommands>,
        image: Vec<u8>,
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
            downloader,
        )
        .expect("manager");
        Fixture {
            _temp: temp,
            manager,
            commands,
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

    #[test]
    fn corrupted_install_does_not_wedge_uninstall() {
        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        tamper_installed_driver(&fixture.manager);
        fixture.commands.push(success(b"[]".to_vec()));

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("repair then uninstall");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
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
        assert_eq!(calls[0], ["machine", "list", "--format", "json"]);
        let init = &calls[1];
        assert_eq!(&init[..2], ["machine", "init"]);
        assert!(init.contains(&"--rootful=false".into()));
        assert!(init.contains(&"--image".into()));
        assert!(!init.contains(&"--provider".into()));
        assert!(
            !init
                .iter()
                .any(|argument| argument == "sudo" || argument == "sh")
        );
        assert_eq!(calls[3][..3], ["machine", "start", "--quiet"]);
        assert_eq!(calls[4], ["version", "--format", "{{.Server.Version}}"]);
        let cached = fixture
            .manager
            .machine_image_path(fixture.manager.loaded.target().expect("target"));
        assert_eq!(fs::read(cached).expect("cached"), fixture.image);
    }

    #[test]
    fn observable_setup_reaches_verified_completed_state() {
        let fixture = fixture();
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
        let command = fixture
            .manager
            .runtime_command(fixture.manager.loaded.target().expect("target"))
            .expect("command");
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
        for value in command.environment.values() {
            assert!(!value.to_string_lossy().contains('\n'));
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
