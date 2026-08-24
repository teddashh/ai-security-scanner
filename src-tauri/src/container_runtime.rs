use crate::artifact_store::{CapturePaths, RunDirectories};
use crate::domain::EngineManifest;
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration as StdDuration;
use zeroize::Zeroizing;

const CONTAINER_SCOPE_PATH: &str = "/run/ai-security-scanner/scope.json";
const CONTAINER_CREDENTIAL_PATH: &str = "/run/ai-security-scanner/credentials.json";
const CONTAINER_WORKSPACE_PATH: &str = "/workspace";
const CONTAINER_OUTPUT_PATH: &str = "/output";
const MAX_SCOPE_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CREDENTIAL_DOCUMENT_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProvider {
    Docker,
    Podman,
}

impl RuntimeProvider {
    fn program_name(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePreflight {
    pub provider: RuntimeProvider,
    pub server_version: String,
    pub security_options: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedImage {
    repository: String,
    digest: String,
}

impl PinnedImage {
    pub fn from_manifest(manifest: &EngineManifest) -> AppResult<Self> {
        let image = manifest.image.as_ref().ok_or_else(|| {
            AppError::Runtime(format!(
                "engine {} has no container image configured",
                manifest.id
            ))
        })?;
        Self::new(
            &image.repository,
            image.digest.as_deref().unwrap_or_default(),
        )
    }

    pub fn new(repository: &str, digest: &str) -> AppResult<Self> {
        let repository = repository.trim();
        if repository.is_empty()
            || repository.len() > 2048
            || repository.starts_with('-')
            || repository.contains('@')
            || repository.chars().any(char::is_whitespace)
            || repository.contains(['\n', '\r', '\0'])
        {
            return Err(AppError::Runtime(
                "container image repository is invalid".into(),
            ));
        }
        if !valid_sha256_digest(digest) {
            return Err(AppError::Runtime(format!(
                "container image {repository} must include a sha256 digest"
            )));
        }
        Ok(Self {
            repository: repository.to_owned(),
            digest: digest.to_ascii_lowercase(),
        })
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn reference(&self) -> String {
        format!("{}@{}", self.repository, self.digest)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub memory_mb: u32,
    pub pids: u32,
    pub cpu_millis: u32,
    pub tmpfs_mb: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 1024,
            pids: 256,
            cpu_millis: 1000,
            tmpfs_mb: 64,
        }
    }
}

impl ResourceLimits {
    fn validate(&self) -> AppResult<()> {
        if !(128..=262_144).contains(&self.memory_mb) {
            return Err(AppError::InvalidRequest(
                "container memory limit must be between 128 MiB and 256 GiB".into(),
            ));
        }
        if !(16..=16_384).contains(&self.pids) {
            return Err(AppError::InvalidRequest(
                "container pids limit must be between 16 and 16384".into(),
            ));
        }
        if !(50..=64_000).contains(&self.cpu_millis) {
            return Err(AppError::InvalidRequest(
                "container CPU limit must be between 50 and 64000 millicores".into(),
            ));
        }
        if !(16..=4096).contains(&self.tmpfs_mb) {
            return Err(AppError::InvalidRequest(
                "container tmpfs limit must be between 16 MiB and 4 GiB".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkPolicy {
    Disabled,
    Managed {
        network_name: String,
        policy_id: String,
        allowed_destinations: Vec<String>,
    },
}

impl NetworkPolicy {
    pub fn managed(
        network_name: impl Into<String>,
        policy_id: impl Into<String>,
        allowed_destinations: Vec<String>,
    ) -> AppResult<Self> {
        let policy = Self::Managed {
            network_name: network_name.into(),
            policy_id: policy_id.into(),
            allowed_destinations,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn allowed_destinations(&self) -> &[String] {
        match self {
            Self::Disabled => &[],
            Self::Managed {
                allowed_destinations,
                ..
            } => allowed_destinations,
        }
    }

    pub fn policy_id(&self) -> Option<&str> {
        match self {
            Self::Disabled => None,
            Self::Managed { policy_id, .. } => Some(policy_id),
        }
    }

    fn validate(&self) -> AppResult<()> {
        let Self::Managed {
            network_name,
            policy_id,
            allowed_destinations,
        } = self
        else {
            return Ok(());
        };
        if !valid_runtime_name(network_name) {
            return Err(AppError::InvalidRequest(
                "managed container network name is invalid".into(),
            ));
        }
        if policy_id.is_empty()
            || policy_id.len() > 128
            || !policy_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            })
        {
            return Err(AppError::InvalidRequest(
                "managed network policy id is invalid".into(),
            ));
        }
        if allowed_destinations.is_empty() {
            return Err(AppError::InvalidRequest(
                "managed network policy must have an explicit destination allowlist".into(),
            ));
        }
        for destination in allowed_destinations {
            let trimmed = destination.trim();
            if trimmed.is_empty()
                || trimmed == "*"
                || trimmed.contains(['\n', '\r', '\0'])
                || trimmed.chars().any(char::is_whitespace)
            {
                return Err(AppError::InvalidRequest(format!(
                    "invalid network destination in policy {policy_id}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    EphemeralScanRole,
    ExternalReadOnlyGrant,
}

pub struct ScannerCredential {
    environment_key: String,
    value: Zeroizing<String>,
    expires_at: DateTime<Utc>,
    source: CredentialSource,
}

impl fmt::Debug for ScannerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannerCredential")
            .field("environment_key", &self.environment_key)
            .field("value", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("source", &self.source)
            .finish()
    }
}

impl ScannerCredential {
    #[cfg(test)]
    pub(crate) fn ephemeral_read_only(
        environment_key: impl Into<String>,
        value: impl Into<String>,
        expires_at: DateTime<Utc>,
        source: CredentialSource,
    ) -> AppResult<Self> {
        Self::from_vault(
            environment_key,
            Zeroizing::new(value.into()),
            expires_at,
            source,
        )
    }

    pub(crate) fn from_vault(
        environment_key: impl Into<String>,
        value: Zeroizing<String>,
        expires_at: DateTime<Utc>,
        source: CredentialSource,
    ) -> AppResult<Self> {
        let environment_key = environment_key.into();
        if !valid_environment_key(&environment_key) {
            return Err(AppError::InvalidRequest(format!(
                "invalid scanner credential environment key: {environment_key}"
            )));
        }
        let upper = environment_key.to_ascii_uppercase();
        if upper.contains("ADMIN") || upper.contains("BROKER") || upper.contains("ROOT_PASSWORD") {
            return Err(AppError::NotAuthorized(format!(
                "admin or bootstrap broker credential cannot enter a scanner container: {environment_key}"
            )));
        }
        if value.is_empty() {
            return Err(AppError::InvalidRequest(
                "scanner credential value cannot be empty".into(),
            ));
        }
        if expires_at <= Utc::now() {
            return Err(AppError::NotAuthorized(
                "scanner credential is already expired".into(),
            ));
        }
        Ok(Self {
            environment_key,
            value,
            expires_at,
            source,
        })
    }

    pub fn environment_key(&self) -> &str {
        &self.environment_key
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn source(&self) -> CredentialSource {
        self.source
    }

    fn expose_value(&self) -> &str {
        self.value.as_str()
    }
}

#[derive(Default)]
pub struct ScannerCredentialSet {
    credentials: Vec<ScannerCredential>,
}

impl fmt::Debug for ScannerCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannerCredentialSet")
            .field(
                "environment_keys",
                &self
                    .credentials
                    .iter()
                    .map(ScannerCredential::environment_key)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ScannerCredentialSet {
    pub(crate) fn new(credentials: Vec<ScannerCredential>) -> AppResult<Self> {
        let mut keys = BTreeSet::new();
        for credential in &credentials {
            if !keys.insert(credential.environment_key()) {
                return Err(AppError::InvalidRequest(format!(
                    "duplicate scanner credential environment key: {}",
                    credential.environment_key()
                )));
            }
        }
        Ok(Self { credentials })
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub fn environment_keys(&self) -> impl Iterator<Item = &str> {
        self.credentials
            .iter()
            .map(ScannerCredential::environment_key)
    }

    fn validate_fresh(&self) -> AppResult<()> {
        let now = Utc::now();
        for credential in &self.credentials {
            if credential.expires_at <= now {
                return Err(AppError::NotAuthorized(format!(
                    "scanner credential {} expired before execution",
                    credential.environment_key
                )));
            }
        }
        Ok(())
    }

    fn write_envelope(&self, path: &Path) -> AppResult<()> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            schema_version: &'static str,
            credentials: Vec<Entry<'a>>,
        }

        #[derive(Serialize)]
        struct Entry<'a> {
            key: &'a str,
            value: &'a str,
            expires_at: DateTime<Utc>,
            source: CredentialSource,
        }

        let envelope = Envelope {
            schema_version: "1.0.0",
            credentials: self
                .credentials
                .iter()
                .map(|credential| Entry {
                    key: credential.environment_key(),
                    value: credential.expose_value(),
                    expires_at: credential.expires_at(),
                    source: credential.source(),
                })
                .collect(),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|error| {
            AppError::Internal(format!("credential envelope could not be encoded: {error}"))
        })?);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                AppError::Runtime(format!(
                    "protected credential channel could not be created: {error}"
                ))
            })?;
        restrict_secret_file(path, false)?;
        file.write_all(bytes.as_slice())?;
        file.sync_all()?;
        restrict_secret_file(path, true)?;
        Ok(())
    }
}

struct SecretFileGuard {
    path: PathBuf,
    sha256: String,
    cleaned: bool,
}

impl fmt::Debug for SecretFileGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretFileGuard")
            .field("path", &self.path)
            .field("sha256", &self.sha256)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl SecretFileGuard {
    fn create(control_dir: &Path, credentials: &ScannerCredentialSet) -> AppResult<Option<Self>> {
        credentials.validate_fresh()?;
        if credentials.is_empty() {
            return Ok(None);
        }
        validate_mount_directory(control_dir, "credential control")?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| AppError::Internal("operating system random source failed".into()))?;
        let path = control_dir.join(format!("credentials-{}.json", hex::encode(nonce)));
        credentials.write_envelope(&path)?;
        let path = canonical_mount_path(&path, "credential channel")?;
        let sha256 =
            hash_bounded_control_file(&path, MAX_CREDENTIAL_DOCUMENT_BYTES, "credential channel")?;
        Ok(Some(Self {
            path,
            sha256,
            cleaned: false,
        }))
    }

    fn validate_integrity(&self) -> AppResult<()> {
        let current = hash_bounded_control_file(
            &self.path,
            MAX_CREDENTIAL_DOCUMENT_BYTES,
            "credential channel",
        )?;
        if current != self.sha256 {
            return Err(AppError::NotAuthorized(
                "credential channel changed after creation".into(),
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> AppResult<()> {
        if self.cleaned {
            return Ok(());
        }
        secure_remove_secret_file(&self.path)?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for SecretFileGuard {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = secure_remove_secret_file(&self.path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRunPlan {
    engine_id: String,
    container_name: String,
    image: PinnedImage,
    runtime_args: Vec<String>,
    workspace: PathBuf,
    output: PathBuf,
    scope_file: PathBuf,
    scope_sha256: String,
    credential_control_dir: PathBuf,
    network_policy: NetworkPolicy,
}

impl ContainerRunPlan {
    pub fn engine_id(&self) -> &str {
        &self.engine_id
    }

    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    pub fn image(&self) -> &PinnedImage {
        &self.image
    }

    pub fn runtime_args(&self) -> &[String] {
        &self.runtime_args
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn output(&self) -> &Path {
        &self.output
    }

    pub fn scope_file(&self) -> &Path {
        &self.scope_file
    }

    pub fn scope_sha256(&self) -> &str {
        &self.scope_sha256
    }

    fn credential_control_dir(&self) -> &Path {
        &self.credential_control_dir
    }

    pub fn network_policy(&self) -> &NetworkPolicy {
        &self.network_policy
    }
}

pub struct ContainerPlanBuilder<'a> {
    manifest: &'a EngineManifest,
    image: &'a PinnedImage,
    directories: &'a RunDirectories,
    scope_file: &'a Path,
    limits: &'a ResourceLimits,
    network_policy: &'a NetworkPolicy,
    credential_set: &'a ScannerCredentialSet,
    engine_run_id: &'a str,
    attempt: u32,
}

impl<'a> ContainerPlanBuilder<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest: &'a EngineManifest,
        image: &'a PinnedImage,
        directories: &'a RunDirectories,
        scope_file: &'a Path,
        limits: &'a ResourceLimits,
        network_policy: &'a NetworkPolicy,
        credential_set: &'a ScannerCredentialSet,
        engine_run_id: &'a str,
        attempt: u32,
    ) -> Self {
        Self {
            manifest,
            image,
            directories,
            scope_file,
            limits,
            network_policy,
            credential_set,
            engine_run_id,
            attempt,
        }
    }

    pub fn build(&self) -> AppResult<ContainerRunPlan> {
        let manifest_image = PinnedImage::from_manifest(self.manifest)?;
        if manifest_image != *self.image {
            return Err(AppError::EngineRegistry(format!(
                "run-plan image does not match the pinned manifest image for {}",
                self.manifest.id
            )));
        }
        self.limits.validate()?;
        self.network_policy.validate()?;
        self.credential_set.validate_fresh()?;
        validate_static_manifest_command(&self.manifest.command)?;
        validate_mount_directory(&self.directories.workspace, "workspace")?;
        validate_mount_directory(&self.directories.output, "output")?;
        validate_mount_directory(&self.directories.control, "control")?;
        validate_mount_file(self.scope_file, "scope document")?;
        let manifest_requires_network =
            self.manifest.active_external || !self.manifest.network_destinations.is_empty();
        match (manifest_requires_network, self.network_policy) {
            (true, NetworkPolicy::Disabled) => {
                return Err(AppError::NotAuthorized(format!(
                    "engine {} requires an enforced managed network policy",
                    self.manifest.id
                )));
            }
            (false, NetworkPolicy::Managed { .. }) => {
                return Err(AppError::NotAuthorized(format!(
                    "engine {} did not declare any network access",
                    self.manifest.id
                )));
            }
            _ => {}
        }

        let container_name =
            planned_container_name(&self.manifest.id, self.engine_run_id, self.attempt)?;
        let workspace = canonical_mount_path(&self.directories.workspace, "workspace")?;
        let output = canonical_mount_path(&self.directories.output, "output")?;
        let credential_control_dir = canonical_mount_path(&self.directories.control, "control")?;
        let scope_file = canonical_mount_path(self.scope_file, "scope document")?;
        let scope_sha256 = hash_control_file(&scope_file)?;
        let mut runtime_args = vec![
            "run".into(),
            "--name".into(),
            container_name.clone(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges:true".into(),
            "--user=65532:65532".into(),
            "--pids-limit".into(),
            self.limits.pids.to_string(),
            "--memory".into(),
            format!("{}m", self.limits.memory_mb),
            "--cpus".into(),
            format!("{:.3}", self.limits.cpu_millis as f64 / 1000.0),
            "--tmpfs".into(),
            format!("/tmp:rw,noexec,nosuid,nodev,size={}m", self.limits.tmpfs_mb),
            "--workdir".into(),
            CONTAINER_WORKSPACE_PATH.into(),
            "--mount".into(),
            bind_mount(&workspace, CONTAINER_WORKSPACE_PATH, true)?,
            "--mount".into(),
            bind_mount(&output, CONTAINER_OUTPUT_PATH, false)?,
            "--mount".into(),
            bind_mount(&scope_file, CONTAINER_SCOPE_PATH, true)?,
            "--label".into(),
            format!("ai.security-scanner.engine={}", self.manifest.id),
            "--label".into(),
            format!("ai.security-scanner.engine-run={}", self.engine_run_id),
        ];

        match self.network_policy {
            NetworkPolicy::Disabled => {
                runtime_args.extend(["--network".into(), "none".into()]);
            }
            NetworkPolicy::Managed {
                network_name,
                policy_id,
                ..
            } => {
                runtime_args.extend(["--network".into(), network_name.clone()]);
                runtime_args.extend([
                    "--label".into(),
                    format!("ai.security-scanner.network-policy={policy_id}"),
                ]);
            }
        }

        runtime_args.push(self.image.reference());
        runtime_args.extend(self.manifest.command.iter().cloned());

        Ok(ContainerRunPlan {
            engine_id: self.manifest.id.clone(),
            container_name,
            image: self.image.clone(),
            runtime_args,
            workspace,
            output,
            scope_file,
            scope_sha256,
            credential_control_dir,
            network_policy: self.network_policy.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOutcome {
    pub exit_code: Option<i32>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupOutcome {
    pub removed: bool,
    pub detail: String,
}

#[derive(Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

pub trait ContainerRuntime: Send + Sync {
    fn preflight(&self) -> AppResult<RuntimePreflight>;
    fn verify_network(&self, policy: &NetworkPolicy) -> AppResult<()>;
    fn pull(&self, image: &PinnedImage) -> AppResult<()>;
    fn run(
        &self,
        plan: &ContainerRunPlan,
        credentials: &ScannerCredentialSet,
        cancellation: &CancellationToken,
        capture: &CapturePaths,
    ) -> AppResult<RuntimeOutcome>;
    fn cleanup(&self, container_name: &str) -> AppResult<CleanupOutcome>;
}

#[derive(Debug, Clone)]
pub struct ProcessContainerRuntime {
    provider: RuntimeProvider,
    binary: PathBuf,
}

impl ProcessContainerRuntime {
    pub fn new(provider: RuntimeProvider, binary: impl Into<PathBuf>) -> Self {
        Self {
            provider,
            binary: binary.into(),
        }
    }

    pub fn detect() -> AppResult<Self> {
        let mut errors = Vec::new();
        for provider in [RuntimeProvider::Docker, RuntimeProvider::Podman] {
            let runtime = Self::new(provider, provider.program_name());
            match runtime.preflight() {
                Ok(_) => return Ok(runtime),
                Err(error) => errors.push(format!("{}: {error}", provider.program_name())),
            }
        }
        Err(AppError::Runtime(format!(
            "no usable Docker or Podman service detected ({})",
            errors.join("; ")
        )))
    }

    fn direct_output<I, S>(&self, args: I) -> AppResult<std::process::Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(&self.binary);
        command.args(args);
        apply_runtime_environment(&mut command);
        command.output().map_err(|error| {
            AppError::Runtime(format!(
                "{} could not be executed directly: {error}",
                self.binary.display()
            ))
        })
    }
}

impl ContainerRuntime for ProcessContainerRuntime {
    fn preflight(&self) -> AppResult<RuntimePreflight> {
        let version = self.direct_output(["version", "--format", "{{.Server.Version}}"])?;
        if !version.status.success() {
            return Err(process_failure("runtime version preflight", &version));
        }
        let server_version = String::from_utf8_lossy(&version.stdout).trim().to_owned();
        if server_version.is_empty() {
            return Err(AppError::Runtime(
                "container runtime returned an empty server version".into(),
            ));
        }

        let info = self.direct_output(["info", "--format", "{{json .SecurityOptions}}"])?;
        if !info.status.success() {
            return Err(process_failure("runtime security preflight", &info));
        }
        Ok(RuntimePreflight {
            provider: self.provider,
            server_version,
            security_options: String::from_utf8_lossy(&info.stdout).trim().to_owned(),
        })
    }

    fn verify_network(&self, policy: &NetworkPolicy) -> AppResult<()> {
        let NetworkPolicy::Managed {
            network_name,
            policy_id,
            ..
        } = policy
        else {
            return Ok(());
        };
        policy.validate()?;
        let output = self.direct_output([
            "network",
            "inspect",
            "--format",
            "{{ index .Labels \"ai.security-scanner.policy-id\" }}",
            network_name,
        ])?;
        if !output.status.success() {
            return Err(process_failure("managed network preflight", &output));
        }
        let actual = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if actual != *policy_id {
            return Err(AppError::NotAuthorized(format!(
                "container network {network_name} is not bound to policy {policy_id}"
            )));
        }
        Ok(())
    }

    fn pull(&self, image: &PinnedImage) -> AppResult<()> {
        let output = self.direct_output(["pull", image.reference().as_str()])?;
        if !output.status.success() {
            return Err(process_failure("pinned image pull", &output));
        }
        Ok(())
    }

    fn run(
        &self,
        plan: &ContainerRunPlan,
        credentials: &ScannerCredentialSet,
        cancellation: &CancellationToken,
        capture: &CapturePaths,
    ) -> AppResult<RuntimeOutcome> {
        validate_run_plan_integrity(plan)?;
        credentials.validate_fresh()?;
        if cancellation.is_cancelled() {
            return Ok(RuntimeOutcome {
                exit_code: None,
                cancelled: true,
            });
        }
        let mut secret = SecretFileGuard::create(plan.credential_control_dir(), credentials)?;
        let runtime_args = runtime_args_with_secret(plan, secret.as_ref())?;
        let execution = (|| -> AppResult<RuntimeOutcome> {
            let stdout = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&capture.stdout)?;
            let stderr = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&capture.stderr)?;
            let mut command = Command::new(&self.binary);
            command.args(&runtime_args);
            apply_runtime_environment(&mut command);
            command.stdout(Stdio::from(stdout));
            command.stderr(Stdio::from(stderr));
            let mut child = command.spawn().map_err(|error| {
                AppError::Runtime(format!("container run could not start: {error}"))
            })?;

            loop {
                if cancellation.is_cancelled() {
                    let _ =
                        self.direct_output(["stop", "--time", "5", plan.container_name.as_str()]);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(RuntimeOutcome {
                        exit_code: None,
                        cancelled: true,
                    });
                }
                if let Some(status) = child.try_wait().map_err(|error| {
                    AppError::Runtime(format!("container process could not be observed: {error}"))
                })? {
                    return Ok(RuntimeOutcome {
                        exit_code: status.code(),
                        cancelled: false,
                    });
                }
                thread::sleep(StdDuration::from_millis(50));
            }
        })();
        let secret_cleanup = secret.as_mut().map_or(Ok(()), SecretFileGuard::cleanup);
        match (execution, secret_cleanup) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(execution), Err(cleanup)) => Err(AppError::Runtime(format!(
                "{execution}; protected credential cleanup also failed: {cleanup}"
            ))),
        }
    }

    fn cleanup(&self, container_name: &str) -> AppResult<CleanupOutcome> {
        if !valid_runtime_name(container_name) {
            return Err(AppError::InvalidRequest(
                "container cleanup name is invalid".into(),
            ));
        }
        let output = self.direct_output(["rm", "--force", container_name])?;
        if output.status.success() {
            return Ok(CleanupOutcome {
                removed: true,
                detail: "container removed".into(),
            });
        }
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("no such container") || stderr.contains("no container with name") {
            return Ok(CleanupOutcome {
                removed: false,
                detail: "container was already absent".into(),
            });
        }
        Err(process_failure("container cleanup", &output))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeCall {
    Preflight,
    VerifyNetwork(String),
    Pull(String),
    Run(String),
    Cleanup(String),
}

#[derive(Debug, Clone)]
pub struct FakeRunBehavior {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_files: BTreeMap<String, Vec<u8>>,
}

impl Default for FakeRunBehavior {
    fn default() -> Self {
        Self {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_files: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
pub struct FakeContainerRuntime {
    calls: Mutex<Vec<RuntimeCall>>,
    behavior: Mutex<FakeRunBehavior>,
    fail_preflight: AtomicBool,
    fail_network: AtomicBool,
    fail_pull: AtomicBool,
    fail_cleanup: AtomicBool,
}

impl FakeContainerRuntime {
    pub fn set_behavior(&self, behavior: FakeRunBehavior) {
        *self.behavior.lock().expect("fake behavior lock") = behavior;
    }

    pub fn set_fail_preflight(&self, fail: bool) {
        self.fail_preflight.store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_network(&self, fail: bool) {
        self.fail_network.store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_pull(&self, fail: bool) {
        self.fail_pull.store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_cleanup(&self, fail: bool) {
        self.fail_cleanup.store(fail, Ordering::SeqCst);
    }

    pub fn calls(&self) -> Vec<RuntimeCall> {
        self.calls.lock().expect("fake calls lock").clone()
    }
}

impl ContainerRuntime for FakeContainerRuntime {
    fn preflight(&self) -> AppResult<RuntimePreflight> {
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::Preflight);
        if self.fail_preflight.load(Ordering::SeqCst) {
            return Err(AppError::Runtime("fake preflight failure".into()));
        }
        Ok(RuntimePreflight {
            provider: RuntimeProvider::Docker,
            server_version: "fake-1.0".into(),
            security_options: "fake-seccomp".into(),
        })
    }

    fn verify_network(&self, policy: &NetworkPolicy) -> AppResult<()> {
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::VerifyNetwork(
                policy.policy_id().unwrap_or("disabled").into(),
            ));
        if self.fail_network.load(Ordering::SeqCst) {
            return Err(AppError::NotAuthorized(
                "fake managed network rejected".into(),
            ));
        }
        Ok(())
    }

    fn pull(&self, image: &PinnedImage) -> AppResult<()> {
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::Pull(image.reference()));
        if self.fail_pull.load(Ordering::SeqCst) {
            return Err(AppError::Runtime("fake pull failure".into()));
        }
        Ok(())
    }

    fn run(
        &self,
        plan: &ContainerRunPlan,
        credentials: &ScannerCredentialSet,
        cancellation: &CancellationToken,
        capture: &CapturePaths,
    ) -> AppResult<RuntimeOutcome> {
        validate_run_plan_integrity(plan)?;
        credentials.validate_fresh()?;
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::Run(plan.container_name.clone()));
        if cancellation.is_cancelled() {
            return Ok(RuntimeOutcome {
                exit_code: None,
                cancelled: true,
            });
        }
        let behavior = self.behavior.lock().expect("fake behavior lock").clone();
        fs::write(&capture.stdout, &behavior.stdout)?;
        fs::write(&capture.stderr, &behavior.stderr)?;
        for (relative, bytes) in behavior.output_files {
            let path = safe_fake_output_path(&plan.output, &relative)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, bytes)?;
        }
        Ok(RuntimeOutcome {
            exit_code: behavior.exit_code,
            cancelled: false,
        })
    }

    fn cleanup(&self, container_name: &str) -> AppResult<CleanupOutcome> {
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::Cleanup(container_name.into()));
        if self.fail_cleanup.load(Ordering::SeqCst) {
            return Err(AppError::Runtime("fake cleanup failure".into()));
        }
        Ok(CleanupOutcome {
            removed: true,
            detail: "fake container removed".into(),
        })
    }
}

fn validate_static_manifest_command(command: &[String]) -> AppResult<()> {
    if command.is_empty() || command.len() > 128 {
        return Err(AppError::EngineRegistry(
            "engine command must contain between 1 and 128 static argv tokens".into(),
        ));
    }
    let program = Path::new(&command[0])
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        program.as_str(),
        "sh" | "bash"
            | "zsh"
            | "fish"
            | "dash"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    ) {
        return Err(AppError::EngineRegistry(format!(
            "engine command may not invoke a shell: {}",
            command[0]
        )));
    }
    for token in command {
        if token.is_empty() || token.len() > 4096 || token.contains('\0') {
            return Err(AppError::EngineRegistry(
                "engine command contains an invalid argv token".into(),
            ));
        }
        let lower = token.to_ascii_lowercase();
        let dynamic_placeholder = lower.contains("${")
            || lower.contains("$(")
            || lower.contains("{{")
            || lower.contains("<target")
            || lower.contains("{target")
            || lower.contains("{secret")
            || lower.contains("%target%")
            || lower.contains("%secret%");
        let shell_operator = matches!(token.as_str(), ";" | "&&" | "||" | "|" | ">" | ">>" | "<")
            || token.contains('`');
        if dynamic_placeholder || shell_operator {
            return Err(AppError::EngineRegistry(
                "engine command must be static argv and may not interpolate targets or secrets"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_mount_directory(path: &Path, label: &str) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "{label} mount {} is unavailable: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::Runtime(format!(
            "{label} mount must be a real directory, not a symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_mount_file(path: &Path, label: &str) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "{label} mount {} is unavailable: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(format!(
            "{label} mount must be a real file, not a symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

fn canonical_mount_path(path: &Path, label: &str) -> AppResult<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    let rendered = canonical.to_string_lossy();
    if rendered.contains([',', '\n', '\r', '\0']) {
        return Err(AppError::Runtime(format!(
            "{label} mount contains characters unsupported by the container runtime"
        )));
    }
    Ok(canonical)
}

fn validate_run_plan_integrity(plan: &ContainerRunPlan) -> AppResult<()> {
    validate_mount_directory(&plan.workspace, "workspace")?;
    validate_mount_directory(&plan.output, "output")?;
    validate_mount_directory(&plan.credential_control_dir, "credential control")?;
    validate_mount_file(&plan.scope_file, "scope document")?;
    let current_scope_sha256 = hash_control_file(&plan.scope_file)?;
    if current_scope_sha256 != plan.scope_sha256 {
        return Err(AppError::NotAuthorized(
            "scope document changed after the immutable run plan was built".into(),
        ));
    }
    Ok(())
}

fn hash_control_file(path: &Path) -> AppResult<String> {
    hash_bounded_control_file(path, MAX_SCOPE_DOCUMENT_BYTES, "scope document")
}

fn hash_bounded_control_file(path: &Path, max_bytes: u64, label: &str) -> AppResult<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(format!(
            "{label} must remain a regular file"
        )));
    }
    if metadata.len() > max_bytes {
        return Err(AppError::Runtime(format!(
            "{label} exceeds the {max_bytes} byte limit"
        )));
    }
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn runtime_args_with_secret(
    plan: &ContainerRunPlan,
    secret: Option<&SecretFileGuard>,
) -> AppResult<Vec<String>> {
    let image_reference = plan.image.reference();
    let image_index = plan
        .runtime_args
        .iter()
        .position(|argument| argument == &image_reference)
        .ok_or_else(|| {
            AppError::Runtime("container run plan lost its pinned image reference".into())
        })?;
    let mut arguments = plan.runtime_args.clone();
    if let Some(secret) = secret {
        secret.validate_integrity()?;
        let mount = bind_mount(&secret.path, CONTAINER_CREDENTIAL_PATH, true)?;
        arguments.splice(image_index..image_index, ["--mount".into(), mount]);
    }
    Ok(arguments)
}

fn secure_remove_secret_file(path: &Path) -> AppResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(
            "protected credential channel is not a regular file".into(),
        ));
    }
    restrict_secret_file(path, false)?;
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(0))?;
    let zeros = Zeroizing::new(vec![0_u8; 16 * 1024]);
    let mut remaining = metadata.len();
    while remaining > 0 {
        let count = usize::try_from(remaining.min(zeros.len() as u64))
            .map_err(|_| AppError::Internal("credential cleanup length overflow".into()))?;
        file.write_all(&zeros[..count])?;
        remaining -= count as u64;
    }
    file.set_len(0)?;
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_secret_file(path: &Path, readonly: bool) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if readonly { 0o400 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_secret_file(path: &Path, readonly: bool) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(readonly);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn bind_mount(source: &Path, destination: &str, read_only: bool) -> AppResult<String> {
    let source = source
        .to_str()
        .ok_or_else(|| AppError::Runtime("container bind mount path is not valid UTF-8".into()))?;
    let suffix = if read_only { ",readonly" } else { "" };
    Ok(format!("type=bind,src={source},dst={destination}{suffix}"))
}

pub(crate) fn planned_container_name(
    engine_id: &str,
    engine_run_id: &str,
    attempt: u32,
) -> AppResult<String> {
    if attempt == 0 || !valid_runtime_name(engine_id) || !valid_runtime_name(engine_run_id) {
        return Err(AppError::InvalidRequest(
            "engine id, run id, or attempt is invalid for a container name".into(),
        ));
    }
    let run_fragment: String = engine_run_id.chars().take(20).collect();
    let name = format!("ass-{engine_id}-{run_fragment}-a{attempt}");
    if name.len() > 128 {
        return Err(AppError::InvalidRequest(
            "generated container name exceeds runtime limits".into(),
        ));
    }
    Ok(name)
}

fn valid_runtime_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn valid_environment_key(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_uppercase())
        && characters.all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
    })
}

fn apply_runtime_environment(command: &mut Command) {
    const ALLOWED: &[&str] = &[
        "PATH",
        "HOME",
        "USERPROFILE",
        "SystemRoot",
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "XDG_RUNTIME_DIR",
        "CONTAINER_HOST",
    ];
    command.env_clear();
    for key in ALLOWED {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

fn process_failure(operation: &str, output: &std::process::Output) -> AppError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail: String = stderr.chars().take(2048).collect();
    AppError::Runtime(format!(
        "{operation} failed with status {}: {}",
        output.status,
        detail.trim()
    ))
}

fn safe_fake_output_path(root: &Path, relative: &str) -> AppResult<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(AppError::Runtime(
            "fake runtime output path must remain relative".into(),
        ));
    }
    Ok(root.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_store::{ArtifactContext, ArtifactStore};
    use crate::domain::{
        AssetKind, DistributionMode, EngineCategory, ImageReference, ManifestStatus, ScanPermission,
    };
    use chrono::Duration;

    fn manifest(command: Vec<String>) -> EngineManifest {
        EngineManifest {
            schema_version: "1".into(),
            id: "scanner".into(),
            display_name: "Scanner".into(),
            category: EngineCategory::CodeAndSecrets,
            description: "test".into(),
            repository_url: "https://example.invalid/scanner".into(),
            homepage_url: None,
            license_spdx: "Apache-2.0".into(),
            distribution_mode: DistributionMode::PullPinnedImage,
            image: Some(ImageReference {
                repository: "registry.example/scanner".into(),
                tag: None,
                digest: Some(format!("sha256:{}", "a".repeat(64))),
                signature_identity: None,
            }),
            source_revision: None,
            engine_version: Some("1.0".into()),
            rule_version: Some("1".into()),
            adapter_version: "1".into(),
            supported_asset_kinds: vec![AssetKind::Repository],
            required_permissions: vec![ScanPermission::LocalArtifactRead],
            active_external: false,
            default_enabled: false,
            estimated_memory_mb: 512,
            estimated_disk_mb: 512,
            network_destinations: vec![],
            output_formats: vec!["json".into()],
            command,
            status: ManifestStatus::Experimental,
            notices: vec![],
        }
    }

    fn plan_fixture(
        command: Vec<String>,
    ) -> (
        tempfile::TempDir,
        ArtifactStore,
        RunDirectories,
        PathBuf,
        EngineManifest,
        PinnedImage,
    ) {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let directories = store
            .prepare_run(
                &ArtifactContext {
                    case_id: "case-1".into(),
                    scan_run_id: "run-1".into(),
                    engine_run_id: "engine-run-1".into(),
                },
                1,
            )
            .expect("directories");
        let scope = store
            .write_control_json(
                &directories,
                "scope.json",
                &serde_json::json!({"assets": []}),
            )
            .expect("scope")
            .path;
        let manifest = manifest(command);
        let image = PinnedImage::from_manifest(&manifest).expect("image");
        (temp, store, directories, scope, manifest, image)
    }

    #[test]
    fn image_digest_is_mandatory() {
        let mut manifest = manifest(vec!["scanner".into()]);
        manifest.image.as_mut().expect("image").digest = None;
        let error = PinnedImage::from_manifest(&manifest).expect_err("digest rejected");
        assert!(error.to_string().contains("sha256 digest"));
    }

    #[test]
    fn image_reference_cannot_be_interpreted_as_a_runtime_option() {
        let error = PinnedImage::new(
            "--platform=host/repository",
            &format!("sha256:{}", "a".repeat(64)),
        )
        .expect_err("option-like repository rejected");
        assert!(error.to_string().contains("repository is invalid"));
    }

    #[test]
    fn plan_image_must_match_the_manifest_digest() {
        let (_temp, _store, directories, scope, manifest, _image) =
            plan_fixture(vec!["scanner".into()]);
        let other_image = PinnedImage::new(
            "registry.example/scanner",
            &format!("sha256:{}", "b".repeat(64)),
        )
        .expect("other pinned image");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &other_image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("manifest mismatch rejected");
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn plan_has_hardening_and_only_fixed_mounts() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into(), "--json".into()]);
        let credentials = ScannerCredentialSet::new(vec![
            ScannerCredential::ephemeral_read_only(
                "AWS_SESSION_TOKEN",
                "do-not-put-this-in-argv",
                Utc::now() + Duration::minutes(10),
                CredentialSource::EphemeralScanRole,
            )
            .expect("credential"),
        ])
        .expect("credential set");
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &credentials,
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");

        assert!(plan.runtime_args.contains(&"--read-only".into()));
        assert!(plan.runtime_args.contains(&"--cap-drop=ALL".into()));
        assert!(
            plan.runtime_args
                .contains(&"--security-opt=no-new-privileges:true".into())
        );
        assert!(plan.runtime_args.contains(&"--pids-limit".into()));
        assert!(plan.runtime_args.contains(&"--memory".into()));
        assert!(plan.runtime_args.contains(&"--cpus".into()));
        assert_eq!(
            plan.runtime_args
                .iter()
                .filter(|argument| argument.as_str() == "--mount")
                .count(),
            3
        );
        assert!(
            plan.runtime_args
                .iter()
                .all(|argument| !argument.contains("do-not-put-this-in-argv"))
        );
        assert!(!plan.runtime_args.iter().any(|argument| argument == "--env"));
    }

    #[test]
    fn credentials_use_a_short_lived_read_only_mount_not_process_environment() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into(), "--json".into()]);
        let credentials = ScannerCredentialSet::new(vec![
            ScannerCredential::ephemeral_read_only(
                "AWS_SESSION_TOKEN",
                "protected-session-value",
                Utc::now() + Duration::minutes(10),
                CredentialSource::EphemeralScanRole,
            )
            .expect("credential"),
        ])
        .expect("credential set");
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &credentials,
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        let mut secret = SecretFileGuard::create(plan.credential_control_dir(), &credentials)
            .expect("secret channel")
            .expect("nonempty channel");
        let arguments = runtime_args_with_secret(&plan, Some(&secret)).expect("runtime args");

        assert_eq!(
            arguments
                .iter()
                .filter(|argument| argument.as_str() == "--mount")
                .count(),
            4
        );
        assert!(arguments.iter().all(|argument| {
            !argument.contains("protected-session-value") && argument != "--env"
        }));
        assert!(
            fs::read_to_string(&secret.path)
                .expect("credential envelope")
                .contains("protected-session-value")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&secret.path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
        let secret_path = secret.path.clone();
        secret.cleanup().expect("secret cleanup");
        assert!(!secret_path.exists());
    }

    #[test]
    fn scope_document_cannot_change_after_plan_creation() {
        let (_temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let credentials = ScannerCredentialSet::default();
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &credentials,
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        fs::remove_file(&scope).expect("remove original scope");
        fs::write(&scope, br#"{"assets":[{"id":"unauthorized"}]}"#).expect("replace scope");
        let capture = store.prepare_capture(&directories).expect("capture");

        let error = FakeContainerRuntime::default()
            .run(&plan, &credentials, &CancellationToken::default(), &capture)
            .expect_err("changed scope rejected");
        assert!(error.to_string().contains("scope document changed"));
    }

    #[test]
    fn shell_and_dynamic_target_commands_are_rejected() {
        let (_temp, _store, directories, scope, manifest, image) = plan_fixture(vec![
            "sh".into(),
            "-c".into(),
            "scanner --target ${TARGET}".into(),
        ]);
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("shell rejected");
        assert!(error.to_string().contains("may not invoke a shell"));
    }

    #[test]
    fn networked_engine_requires_managed_policy() {
        let (_temp, _store, directories, scope, mut manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        manifest.active_external = true;
        manifest.network_destinations = vec!["authorized target".into()];
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("network rejected");
        assert!(error.to_string().contains("managed network policy"));
    }

    #[test]
    fn offline_engine_cannot_be_given_extra_network_access() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let policy =
            NetworkPolicy::managed("ass-egress", "policy-1", vec!["unexpected.example".into()])
                .expect("policy syntax");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &policy,
            &ScannerCredentialSet::default(),
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("undeclared network rejected");
        assert!(error.to_string().contains("did not declare"));
    }

    #[test]
    fn admin_or_broker_credentials_have_no_scanner_api() {
        let error = ScannerCredential::ephemeral_read_only(
            "BROKER_ADMIN_PASSWORD",
            "secret",
            Utc::now() + Duration::minutes(10),
            CredentialSource::EphemeralScanRole,
        )
        .expect_err("credential rejected");
        assert!(
            error
                .to_string()
                .contains("cannot enter a scanner container")
        );
    }
}
