//! Isolated, interactive bootstrap execution.
//!
//! This module is intentionally backend-only. Operator configuration is
//! non-secret and serde-enabled, while authorization codes, refresh tokens,
//! client secrets, session credentials, and the verified scanner
//! authorization have no serde representation and remain in zeroizing memory.

use super::{
    BootstrapProvider, BootstrapRequest, CleanupAttemptOutcome, CleanupLedger, CleanupState,
    CreatedBootstrapResources, ExactCleanupItem, create_bootstrap_plan, create_cleanup_ledger,
    record_cleanup_attempt, validate_cleanup_ledger,
};
use crate::error::{AppError, AppResult};
use crate::source_authorization::VerifiedProviderAuthorization;
use crate::source_authorization::provider::{
    AwsNativeAuthorizationConfig, AwsRoleCredentials, AwsSigningCredentials,
    DeviceAuthorizationPrompt, GcpNativeAuthorizationConfig, MicrosoftNativeAuthorizationConfig,
    PollAuthorization, ProviderHttp, ProviderHttpMethod, aws_query_encode, aws_signed_request,
    aws_simulation_decisions, bearer_get, bearer_header, begin_aws_native_authorization,
    decode_success_json, ensure_status, execute_json, form_request, json_request, oauth_error,
    poll_aws_role_credentials, random_bytes, request, serializable_json_request,
    verify_bootstrap_aws_credentials, verify_bootstrap_azure_token, verify_bootstrap_gcp_token,
    verify_bootstrap_microsoft365_token, xml_first,
};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_POLL_ATTEMPTS: usize = 180;
const MICROSOFT_GRAPH_ROOT: &str = "https://graph.microsoft.com/v1.0";
const MICROSOFT_ARM_ROOT: &str = "https://management.azure.com";
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const PARTIAL_LEDGER_SCHEMA_VERSION: &str = "1.0.0-partial";
const COMPLETE_LEDGER_SCHEMA_VERSION: &str = "1.0.0";
const MAX_CLEANUP_LEDGER_BYTES: u64 = 1024 * 1024;
const MAX_CLEANUP_LEDGER_FILES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapOperatorConfig {
    Aws {
        administrator: AwsNativeAuthorizationConfig,
    },
    Azure {
        authorization: MicrosoftNativeAuthorizationConfig,
    },
    Gcp {
        authorization: GcpNativeAuthorizationConfig,
        project_id: String,
    },
    Microsoft365 {
        authorization: MicrosoftNativeAuthorizationConfig,
    },
}

/// Non-secret coordinates captured before the first mutation. They bind an
/// interrupted journal to the exact provider tenancy where its IDs exist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapMutationProviderContext {
    Aws {
        account_id: String,
        region: String,
    },
    Azure {
        tenant_id: String,
        subscription_id: String,
    },
    Gcp {
        organization_id: String,
        project_id: String,
    },
    Microsoft365 {
        tenant_id: String,
    },
}

impl BootstrapMutationProviderContext {
    fn provider(&self) -> BootstrapProvider {
        match self {
            Self::Aws { .. } => BootstrapProvider::Aws,
            Self::Azure { .. } => BootstrapProvider::Azure,
            Self::Gcp { .. } => BootstrapProvider::Gcp,
            Self::Microsoft365 { .. } => BootstrapProvider::Microsoft365,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapExecutionRequest {
    pub schema_version: String,
    pub bootstrap: BootstrapRequest,
    pub operator: BootstrapOperatorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapBrokerCommand {
    Plan {
        request: BootstrapRequest,
    },
    Execute {
        execution: BootstrapExecutionRequest,
        cleanup_ledger_path: String,
    },
    Cleanup {
        operator: BootstrapOperatorConfig,
        case_id: String,
        operation_id: String,
        cleanup_ledger_path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PkceAuthorizationPrompt {
    pub provider: BootstrapProvider,
    pub authorization_url: String,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
    pub safety_notice: String,
}

/// The callback code is deliberately non-serializable and redacted.
pub struct PkceAuthorizationCallback {
    pub authorization_code: Zeroizing<String>,
    pub returned_state: Zeroizing<String>,
}

impl fmt::Debug for PkceAuthorizationCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PkceAuthorizationCallback([REDACTED])")
    }
}

/// Implemented by the broker binary (real wall clock and loopback callback)
/// and by deterministic provider HTTP fixtures.
pub trait BootstrapInteraction {
    fn present_device_authorization(&self, prompt: &DeviceAuthorizationPrompt) -> AppResult<()>;
    fn complete_pkce_authorization(
        &self,
        prompt: &PkceAuthorizationPrompt,
    ) -> AppResult<PkceAuthorizationCallback>;
    fn wait(&self, seconds: u64) -> AppResult<()>;
    fn now(&self) -> DateTime<Utc>;
}

/// Secret-bearing execution result. Only the cleanup ledger may be persisted;
/// the authorization must immediately cross the protected one-shot pipe.
pub struct BootstrapExecutionResult {
    pub authorization: VerifiedProviderAuthorization,
    pub cleanup_ledger: CleanupLedger,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapMutationCleanupItem {
    pub exact_resource_id: String,
    pub provider_api_method: String,
    pub provider_api_endpoint: String,
    pub cleanup_semantics: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapMutationItemState {
    Pending,
    Attempting,
    RetryableFailure,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapMutationCleanupProgress {
    pub item_id: String,
    pub state: BootstrapMutationItemState,
    pub attempts: u32,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_provider_status: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapMutationRecoveryState {
    #[default]
    Pending,
    InProgress,
    RetryableFailure,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct BootstrapMutationRecovery {
    #[serde(default)]
    pub state: BootstrapMutationRecoveryState,
    #[serde(default)]
    pub items: Vec<BootstrapMutationCleanupProgress>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Durable, secret-free journal written before and after every provider
/// mutation. If execution is interrupted, it contains only exact resources
/// already returned by the provider—never a wildcard or discovery pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapMutationLedger {
    pub schema_version: String,
    pub case_id: String,
    pub provider: BootstrapProvider,
    pub provider_context: BootstrapMutationProviderContext,
    pub created_at: DateTime<Utc>,
    pub items: Vec<BootstrapMutationCleanupItem>,
    pub safety_notice: String,
    /// SHA-256 over all immutable journal fields. Recovery refuses legacy or
    /// modified partial journals rather than guessing at a cleanup target.
    #[serde(default)]
    pub immutable_sha256: String,
    #[serde(default)]
    pub recovery: BootstrapMutationRecovery,
}

impl BootstrapMutationLedger {
    fn new(
        case_id: &str,
        provider_context: BootstrapMutationProviderContext,
        now: DateTime<Utc>,
    ) -> Self {
        let provider = provider_context.provider();
        let mut ledger = Self {
            schema_version: PARTIAL_LEDGER_SCHEMA_VERSION.into(),
            case_id: case_id.into(),
            provider,
            provider_context,
            created_at: now,
            items: Vec::new(),
            safety_notice: "Bootstrap was interrupted or is in progress. Reauthenticate in the isolated broker and clean only the exact resource IDs below. This file contains no credentials.".into(),
            immutable_sha256: String::new(),
            recovery: BootstrapMutationRecovery::default(),
        };
        // Serialization of this fixed tuple cannot fail for these field types.
        ledger.immutable_sha256 = ledger
            .derive_immutable_sha256()
            .expect("partial bootstrap journal fields serialize");
        ledger
    }

    fn record(&mut self, path: &Path, item: BootstrapMutationCleanupItem) -> AppResult<()> {
        validate_partial_item_shape(&item)?;
        validate_partial_provider_item(self.provider, &item)?;
        if self.recovery.state != BootstrapMutationRecoveryState::Pending
            || !self.recovery.items.is_empty()
        {
            return Err(AppError::NotAuthorized(
                "bootstrap mutation journal cannot grow after cleanup recovery starts".into(),
            ));
        }
        self.items.push(item);
        validate_partial_target_relationships(self.provider, &self.items)?;
        validate_partial_context_targets(&self.provider_context, &self.items)?;
        self.immutable_sha256 = self.derive_immutable_sha256()?;
        write_secret_free_atomic_json(path, self)
    }

    fn initialize(&self, path: &Path) -> AppResult<()> {
        write_secret_free_atomic_json(path, self)
    }

    fn derive_immutable_sha256(&self) -> AppResult<String> {
        let encoded = serde_json::to_vec(&(
            &self.schema_version,
            &self.case_id,
            self.provider,
            &self.provider_context,
            self.created_at,
            &self.items,
            &self.safety_notice,
        ))
        .map_err(|_| AppError::Internal("partial cleanup integrity could not be derived".into()))?;
        Ok(hex::encode(Sha256::digest(encoded)))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapCleanupStatus {
    Pending,
    InProgress,
    RetryableFailure,
    WaitingForCredentialExpiry,
    Completed,
}

/// Credential-free projection safe for the desktop and CLI. Exact resource
/// IDs and endpoints deliberately remain inside the protected ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapCleanupObligationSummary {
    pub operation_id: String,
    pub provider: BootstrapProvider,
    pub case_id: String,
    pub schema_version: String,
    pub status: BootstrapCleanupStatus,
    pub total_items: usize,
    pub pending_items: usize,
    pub in_progress_items: usize,
    pub retryable_items: usize,
    pub waiting_items: usize,
    pub completed_items: usize,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "ledger_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapCleanupResult {
    Complete {
        summary: BootstrapCleanupObligationSummary,
    },
    Partial {
        summary: BootstrapCleanupObligationSummary,
    },
}

impl BootstrapCleanupResult {
    pub fn summary(&self) -> &BootstrapCleanupObligationSummary {
        match self {
            Self::Complete { summary } | Self::Partial { summary } => summary,
        }
    }
}

impl fmt::Debug for BootstrapExecutionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapExecutionResult")
            .field("authorization", &"[REDACTED]")
            .field("cleanup_ledger", &self.cleanup_ledger)
            .finish()
    }
}

pub fn execute_bootstrap(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    execution: BootstrapExecutionRequest,
    cleanup_ledger_path: &Path,
) -> AppResult<BootstrapExecutionResult> {
    if execution.schema_version != "1.0.0" {
        return Err(AppError::InvalidRequest(
            "unsupported bootstrap execution protocol version".into(),
        ));
    }
    let now = interaction.now();
    create_bootstrap_plan(execution.bootstrap.clone(), now)?;
    if execution.bootstrap.expires_at <= now
        || execution.bootstrap.expires_at > now + Duration::hours(1)
    {
        return Err(AppError::InvalidRequest(
            "bootstrap scanner credential lifetime must be at most one hour".into(),
        ));
    }
    match (&execution.bootstrap.provider, &execution.operator) {
        (BootstrapProvider::Aws, BootstrapOperatorConfig::Aws { administrator }) => execute_aws(
            http,
            interaction,
            execution.bootstrap,
            administrator.clone(),
            cleanup_ledger_path,
        ),
        (BootstrapProvider::Azure, BootstrapOperatorConfig::Azure { authorization }) => {
            execute_azure(
                http,
                interaction,
                execution.bootstrap,
                authorization.clone(),
                cleanup_ledger_path,
            )
        }
        (
            BootstrapProvider::Gcp,
            BootstrapOperatorConfig::Gcp {
                authorization,
                project_id,
            },
        ) => execute_gcp(
            http,
            interaction,
            execution.bootstrap,
            authorization.clone(),
            project_id.clone(),
            cleanup_ledger_path,
        ),
        (
            BootstrapProvider::Microsoft365,
            BootstrapOperatorConfig::Microsoft365 { authorization },
        ) => execute_microsoft365(
            http,
            interaction,
            execution.bootstrap,
            authorization.clone(),
            cleanup_ledger_path,
        ),
        _ => Err(AppError::InvalidRequest(
            "bootstrap operator configuration does not match the requested provider".into(),
        )),
    }
}

pub fn execute_bootstrap_cleanup(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    operator: BootstrapOperatorConfig,
    expected_case_id: &str,
    expected_operation_id: &str,
    cleanup_ledger_path: &Path,
) -> AppResult<BootstrapCleanupResult> {
    let operation_id = operation_id_from_cleanup_path(cleanup_ledger_path)?;
    if operation_id != expected_operation_id || !valid_cleanup_identifier(expected_case_id) {
        return Err(AppError::NotAuthorized(
            "cleanup ledger path is not bound to the requested case and operation".into(),
        ));
    }
    match read_cleanup_document(cleanup_ledger_path, expected_case_id)? {
        CleanupDocument::Complete(mut ledger) => {
            match (&ledger.provider, operator) {
                (BootstrapProvider::Aws, BootstrapOperatorConfig::Aws { administrator }) => {
                    cleanup_aws(
                        http,
                        interaction,
                        &mut ledger,
                        administrator,
                        cleanup_ledger_path,
                    )?;
                }
                (BootstrapProvider::Azure, BootstrapOperatorConfig::Azure { authorization }) => {
                    cleanup_azure(
                        http,
                        interaction,
                        &mut ledger,
                        authorization,
                        cleanup_ledger_path,
                    )?;
                }
                (
                    BootstrapProvider::Gcp,
                    BootstrapOperatorConfig::Gcp {
                        authorization,
                        project_id,
                    },
                ) => cleanup_gcp(
                    http,
                    interaction,
                    &mut ledger,
                    authorization,
                    &project_id,
                    cleanup_ledger_path,
                )?,
                (
                    BootstrapProvider::Microsoft365,
                    BootstrapOperatorConfig::Microsoft365 { authorization },
                ) => cleanup_microsoft365(
                    http,
                    interaction,
                    &mut ledger,
                    authorization,
                    cleanup_ledger_path,
                )?,
                _ => {
                    return Err(AppError::InvalidRequest(
                        "cleanup operator configuration does not match the ledger provider".into(),
                    ));
                }
            }
            super::write_cleanup_ledger(cleanup_ledger_path, &ledger)?;
            Ok(BootstrapCleanupResult::Complete {
                summary: complete_cleanup_summary(&operation_id, &ledger),
            })
        }
        CleanupDocument::Partial(mut ledger) => {
            cleanup_partial_mutation_ledger(
                http,
                interaction,
                &mut ledger,
                operator,
                cleanup_ledger_path,
            )?;
            validate_partial_mutation_ledger(&ledger)?;
            write_secret_free_atomic_json(cleanup_ledger_path, &ledger)?;
            Ok(BootstrapCleanupResult::Partial {
                summary: partial_cleanup_summary(&operation_id, &ledger),
            })
        }
    }
}

enum CleanupDocument {
    Complete(CleanupLedger),
    Partial(BootstrapMutationLedger),
}

fn read_cleanup_document(path: &Path, expected_case_id: &str) -> AppResult<CleanupDocument> {
    operation_id_from_cleanup_path(path)?;
    let bytes = read_bounded_regular_file(path)?;
    let header: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::InvalidRequest("cleanup ledger is malformed".into()))?;
    let schema = header
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AppError::InvalidRequest("cleanup ledger schema is missing".into()))?;
    match schema {
        COMPLETE_LEDGER_SCHEMA_VERSION => {
            let ledger: CleanupLedger = serde_json::from_slice(&bytes)
                .map_err(|_| AppError::InvalidRequest("cleanup ledger is malformed".into()))?;
            validate_cleanup_ledger(&ledger)?;
            if ledger.case_id != expected_case_id {
                return Err(AppError::NotAuthorized(
                    "cleanup ledger belongs to a different case".into(),
                ));
            }
            Ok(CleanupDocument::Complete(ledger))
        }
        PARTIAL_LEDGER_SCHEMA_VERSION => {
            let ledger: BootstrapMutationLedger = serde_json::from_slice(&bytes).map_err(|_| {
                AppError::InvalidRequest("partial cleanup ledger is malformed".into())
            })?;
            validate_partial_mutation_ledger(&ledger)?;
            if ledger.case_id != expected_case_id {
                return Err(AppError::NotAuthorized(
                    "partial cleanup ledger belongs to a different case".into(),
                ));
            }
            Ok(CleanupDocument::Partial(ledger))
        }
        _ => Err(AppError::InvalidRequest(
            "cleanup ledger schema is unsupported".into(),
        )),
    }
}

pub fn list_bootstrap_cleanup_obligations(
    root: &Path,
    expected_case_id: &str,
) -> AppResult<Vec<BootstrapCleanupObligationSummary>> {
    if !valid_cleanup_identifier(expected_case_id) {
        return Err(AppError::InvalidRequest(
            "cleanup case identifier is invalid".into(),
        ));
    }
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "bootstrap cleanup root must be a real directory".into(),
        ));
    }
    let mut paths = Vec::<(String, PathBuf)>::new();
    for entry in fs::read_dir(root)? {
        if paths.len() >= MAX_CLEANUP_LEDGER_FILES {
            return Err(AppError::InvalidRequest(
                "bootstrap cleanup ledger listing exceeds its fixed bound".into(),
            ));
        }
        let entry = entry?;
        let file_type = entry.file_type()?;
        let filename = entry
            .file_name()
            .into_string()
            .map_err(|_| AppError::InvalidRequest("cleanup ledger filename is invalid".into()))?;
        if filename.starts_with(".cleanup-") && filename.ends_with(".tmp") {
            if file_type.is_symlink() {
                return Err(AppError::NotAuthorized(
                    "bootstrap cleanup root contains a symlink".into(),
                ));
            }
            continue;
        }
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(AppError::NotAuthorized(
                "bootstrap cleanup root contains a non-regular entry".into(),
            ));
        }
        let operation_id = operation_id_from_cleanup_filename(&filename)?;
        paths.push((operation_id, entry.path()));
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0));
    paths
        .into_iter()
        .map(
            |(operation_id, path)| match read_cleanup_document(&path, expected_case_id)? {
                CleanupDocument::Complete(ledger) => {
                    Ok(complete_cleanup_summary(&operation_id, &ledger))
                }
                CleanupDocument::Partial(ledger) => {
                    Ok(partial_cleanup_summary(&operation_id, &ledger))
                }
            },
        )
        .collect()
}

pub fn bootstrap_cleanup_obligation_summary(
    path: &Path,
    expected_case_id: &str,
    expected_operation_id: &str,
) -> AppResult<BootstrapCleanupObligationSummary> {
    let operation_id = operation_id_from_cleanup_path(path)?;
    if operation_id != expected_operation_id {
        return Err(AppError::NotAuthorized(
            "cleanup ledger filename does not match the requested operation".into(),
        ));
    }
    match read_cleanup_document(path, expected_case_id)? {
        CleanupDocument::Complete(ledger) => Ok(complete_cleanup_summary(&operation_id, &ledger)),
        CleanupDocument::Partial(ledger) => Ok(partial_cleanup_summary(&operation_id, &ledger)),
    }
}

fn valid_cleanup_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn operation_id_from_cleanup_filename(filename: &str) -> AppResult<String> {
    let operation_id = filename
        .strip_prefix("cleanup-")
        .and_then(|value| value.strip_suffix(".json"))
        .ok_or_else(|| AppError::InvalidRequest("cleanup ledger filename is invalid".into()))?;
    if !valid_cleanup_identifier(operation_id) {
        return Err(AppError::InvalidRequest(
            "cleanup ledger operation identifier is invalid".into(),
        ));
    }
    Ok(operation_id.into())
}

fn operation_id_from_cleanup_path(path: &Path) -> AppResult<String> {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppError::InvalidRequest("cleanup ledger filename is invalid".into()))?;
    operation_id_from_cleanup_filename(filename)
}

fn read_bounded_regular_file(path: &Path) -> AppResult<Vec<u8>> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::InvalidRequest("cleanup ledger path has no parent".into()))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "cleanup ledger parent must be a real directory".into(),
        ));
    }
    if let Some(case_root) = parent.parent() {
        let case_metadata = fs::symlink_metadata(case_root)?;
        if case_metadata.file_type().is_symlink() || !case_metadata.is_dir() {
            return Err(AppError::NotAuthorized(
                "cleanup ledger case root must be a real directory".into(),
            ));
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_CLEANUP_LEDGER_BYTES
    {
        return Err(AppError::InvalidRequest(
            "cleanup ledger must be a bounded regular file, not a symlink".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file: File = options.open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_CLEANUP_LEDGER_BYTES {
        return Err(AppError::InvalidRequest(
            "cleanup ledger changed while it was being opened".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_CLEANUP_LEDGER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CLEANUP_LEDGER_BYTES {
        return Err(AppError::InvalidRequest(
            "cleanup ledger exceeds its fixed size bound".into(),
        ));
    }
    Ok(bytes)
}

fn complete_cleanup_summary(
    operation_id: &str,
    ledger: &CleanupLedger,
) -> BootstrapCleanupObligationSummary {
    let completed_items = ledger
        .items
        .iter()
        .filter(|item| item.state == CleanupState::Completed)
        .count();
    let retryable_items = ledger
        .items
        .iter()
        .filter(|item| item.state == CleanupState::RetryableFailure)
        .count();
    let waiting_items = ledger
        .items
        .iter()
        .filter(|item| item.state == CleanupState::WaitingForCredentialExpiry)
        .count();
    let pending_items = ledger
        .items
        .iter()
        .filter(|item| item.state == CleanupState::Pending)
        .count();
    let status = if completed_items == ledger.items.len() {
        BootstrapCleanupStatus::Completed
    } else if retryable_items > 0 {
        BootstrapCleanupStatus::RetryableFailure
    } else if waiting_items > 0 && pending_items == 0 {
        BootstrapCleanupStatus::WaitingForCredentialExpiry
    } else {
        BootstrapCleanupStatus::Pending
    };
    BootstrapCleanupObligationSummary {
        operation_id: operation_id.into(),
        provider: ledger.provider,
        case_id: ledger.case_id.clone(),
        schema_version: ledger.schema_version.clone(),
        status,
        total_items: ledger.items.len(),
        pending_items,
        in_progress_items: 0,
        retryable_items,
        waiting_items,
        completed_items,
        created_at: ledger.created_at,
    }
}

fn partial_cleanup_summary(
    operation_id: &str,
    ledger: &BootstrapMutationLedger,
) -> BootstrapCleanupObligationSummary {
    let (pending_items, in_progress_items, retryable_items, completed_items) =
        if ledger.recovery.items.is_empty() {
            (ledger.items.len(), 0, 0, 0)
        } else {
            (
                ledger
                    .recovery
                    .items
                    .iter()
                    .filter(|item| item.state == BootstrapMutationItemState::Pending)
                    .count(),
                ledger
                    .recovery
                    .items
                    .iter()
                    .filter(|item| item.state == BootstrapMutationItemState::Attempting)
                    .count(),
                ledger
                    .recovery
                    .items
                    .iter()
                    .filter(|item| item.state == BootstrapMutationItemState::RetryableFailure)
                    .count(),
                ledger
                    .recovery
                    .items
                    .iter()
                    .filter(|item| item.state == BootstrapMutationItemState::Completed)
                    .count(),
            )
        };
    let status = match ledger.recovery.state {
        BootstrapMutationRecoveryState::Pending => BootstrapCleanupStatus::Pending,
        BootstrapMutationRecoveryState::InProgress => BootstrapCleanupStatus::InProgress,
        BootstrapMutationRecoveryState::RetryableFailure => {
            BootstrapCleanupStatus::RetryableFailure
        }
        BootstrapMutationRecoveryState::Completed => BootstrapCleanupStatus::Completed,
    };
    BootstrapCleanupObligationSummary {
        operation_id: operation_id.into(),
        provider: ledger.provider,
        case_id: ledger.case_id.clone(),
        schema_version: ledger.schema_version.clone(),
        status,
        total_items: ledger.items.len(),
        pending_items,
        in_progress_items,
        retryable_items,
        waiting_items: 0,
        completed_items,
        created_at: ledger.created_at,
    }
}

fn partial_item_id(item: &BootstrapMutationCleanupItem) -> AppResult<String> {
    let encoded = serde_json::to_vec(item)
        .map_err(|_| AppError::Internal("partial cleanup item ID could not be derived".into()))?;
    Ok(format!(
        "partial-cleanup-item-{}",
        &hex::encode(Sha256::digest(encoded))[..24]
    ))
}

fn validate_partial_item_shape(item: &BootstrapMutationCleanupItem) -> AppResult<()> {
    if item.exact_resource_id.is_empty()
        || item.exact_resource_id.len() > 4096
        || item.provider_api_endpoint.is_empty()
        || item.provider_api_endpoint.len() > 8192
        || item.cleanup_semantics.is_empty()
        || item.cleanup_semantics.len() > 2048
        || !matches!(item.provider_api_method.as_str(), "DELETE" | "POST")
        || item.provider_api_endpoint.contains('*')
        || item.exact_resource_id.contains('*')
        || item
            .exact_resource_id
            .chars()
            .chain(item.provider_api_endpoint.chars())
            .chain(item.cleanup_semantics.chars())
            .any(char::is_control)
    {
        return Err(AppError::NotAuthorized(
            "bootstrap mutation journal refused an inexact cleanup target".into(),
        ));
    }
    let endpoint = Url::parse(&item.provider_api_endpoint)
        .map_err(|_| AppError::NotAuthorized("partial cleanup endpoint is malformed".into()))?;
    if endpoint.scheme() != "https"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.port().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(AppError::NotAuthorized(
            "partial cleanup endpoint is not an exact HTTPS provider endpoint".into(),
        ));
    }
    Ok(())
}

fn validate_partial_mutation_ledger(ledger: &BootstrapMutationLedger) -> AppResult<()> {
    if ledger.schema_version != PARTIAL_LEDGER_SCHEMA_VERSION
        || !valid_cleanup_identifier(&ledger.case_id)
        || ledger.provider != ledger.provider_context.provider()
        || !valid_partial_provider_context(&ledger.provider_context)
        || ledger.items.len() > MAX_CLEANUP_LEDGER_FILES
        || ledger.safety_notice.is_empty()
        || ledger.safety_notice.len() > 2048
        || ledger.safety_notice.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(
            "partial cleanup ledger header is inconsistent".into(),
        ));
    }
    if ledger.immutable_sha256.len() != 64
        || !ledger
            .immutable_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || ledger.derive_immutable_sha256()? != ledger.immutable_sha256
    {
        return Err(AppError::NotAuthorized(
            "partial cleanup ledger immutable fields were modified or lack integrity metadata"
                .into(),
        ));
    }
    let mut item_ids = BTreeSet::new();
    for item in &ledger.items {
        validate_partial_item_shape(item)?;
        validate_partial_provider_item(ledger.provider, item)?;
        if !item_ids.insert(partial_item_id(item)?) {
            return Err(AppError::NotAuthorized(
                "partial cleanup ledger contains a duplicate exact target".into(),
            ));
        }
    }
    validate_partial_target_relationships(ledger.provider, &ledger.items)?;
    validate_partial_context_targets(&ledger.provider_context, &ledger.items)?;
    if ledger.recovery.items.is_empty() {
        let pristine = ledger.recovery.state == BootstrapMutationRecoveryState::Pending
            && ledger.recovery.updated_at.is_none();
        let empty_completed = ledger.items.is_empty()
            && ledger.recovery.state == BootstrapMutationRecoveryState::Completed
            && ledger.recovery.updated_at.is_some();
        if !pristine && !empty_completed {
            return Err(AppError::NotAuthorized(
                "partial cleanup recovery state was modified".into(),
            ));
        }
        return Ok(());
    }
    if ledger.recovery.items.len() != ledger.items.len() {
        return Err(AppError::NotAuthorized(
            "partial cleanup recovery target set was modified".into(),
        ));
    }
    let mut progress_ids = BTreeSet::new();
    for progress in &ledger.recovery.items {
        if !item_ids.contains(&progress.item_id) || !progress_ids.insert(progress.item_id.clone()) {
            return Err(AppError::NotAuthorized(
                "partial cleanup recovery target was modified".into(),
            ));
        }
        let state_is_consistent = match progress.state {
            BootstrapMutationItemState::Pending => {
                progress.attempts == 0
                    && progress.last_attempt_at.is_none()
                    && progress.last_provider_status.is_none()
            }
            BootstrapMutationItemState::Attempting
            | BootstrapMutationItemState::RetryableFailure
            | BootstrapMutationItemState::Completed => {
                progress.attempts > 0
                    && progress.last_attempt_at.is_some()
                    && progress
                        .last_provider_status
                        .as_ref()
                        .is_some_and(|status| {
                            !status.is_empty()
                                && status.len() <= 256
                                && !status.chars().any(char::is_control)
                        })
            }
        };
        if !state_is_consistent {
            return Err(AppError::NotAuthorized(
                "partial cleanup attempt state was modified".into(),
            ));
        }
    }
    let expected_state = partial_recovery_state(&ledger.recovery.items);
    if ledger.recovery.state != expected_state || ledger.recovery.updated_at.is_none() {
        return Err(AppError::NotAuthorized(
            "partial cleanup aggregate state was modified".into(),
        ));
    }
    Ok(())
}

fn valid_partial_provider_context(context: &BootstrapMutationProviderContext) -> bool {
    match context {
        BootstrapMutationProviderContext::Aws { account_id, region } => {
            account_id.len() == 12
                && account_id.bytes().all(|byte| byte.is_ascii_digit())
                && !region.is_empty()
                && region.len() <= 64
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }
        BootstrapMutationProviderContext::Azure {
            tenant_id,
            subscription_id,
        } => Uuid::parse_str(tenant_id).is_ok() && Uuid::parse_str(subscription_id).is_ok(),
        BootstrapMutationProviderContext::Gcp {
            organization_id,
            project_id,
        } => {
            !organization_id.is_empty()
                && organization_id.bytes().all(|byte| byte.is_ascii_digit())
                && valid_gcp_project_id(project_id)
        }
        BootstrapMutationProviderContext::Microsoft365 { tenant_id } => {
            Uuid::parse_str(tenant_id).is_ok()
        }
    }
}

fn partial_recovery_state(
    items: &[BootstrapMutationCleanupProgress],
) -> BootstrapMutationRecoveryState {
    if items
        .iter()
        .all(|item| item.state == BootstrapMutationItemState::Completed)
    {
        BootstrapMutationRecoveryState::Completed
    } else if items
        .iter()
        .any(|item| item.state == BootstrapMutationItemState::Attempting)
    {
        BootstrapMutationRecoveryState::InProgress
    } else if items
        .iter()
        .any(|item| item.state == BootstrapMutationItemState::RetryableFailure)
    {
        BootstrapMutationRecoveryState::RetryableFailure
    } else {
        BootstrapMutationRecoveryState::Pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PartialProviderTarget {
    AwsStack {
        region: String,
        account_id: String,
        stack_id: String,
    },
    MicrosoftApplication {
        object_id: String,
    },
    MicrosoftServicePrincipal {
        object_id: String,
    },
    MicrosoftPassword {
        application_object_id: String,
        key_id: String,
    },
    AzureRoleAssignment {
        subscription_id: String,
        assignment_id: String,
    },
    MicrosoftAppRoleAssignment {
        service_principal_object_id: String,
        assignment_id: String,
    },
    GcpServiceAccount {
        project_id: String,
        email: String,
        unique_id: String,
    },
    GcpOrganizationBinding {
        organization_id: String,
        email: String,
        role: String,
    },
    GcpServiceAccountKey {
        project_id: String,
        email: String,
        key_id: String,
    },
}

fn valid_provider_path_segment(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}

fn validate_partial_provider_item(
    provider: BootstrapProvider,
    item: &BootstrapMutationCleanupItem,
) -> AppResult<PartialProviderTarget> {
    match provider {
        BootstrapProvider::Aws => parse_partial_aws_target(item),
        BootstrapProvider::Azure => parse_partial_microsoft_target(item, true),
        BootstrapProvider::Microsoft365 => parse_partial_microsoft_target(item, false),
        BootstrapProvider::Gcp => parse_partial_gcp_target(item),
    }
}

fn parse_partial_aws_target(
    item: &BootstrapMutationCleanupItem,
) -> AppResult<PartialProviderTarget> {
    if item.provider_api_method != "POST" {
        return Err(AppError::NotAuthorized(
            "AWS partial cleanup operation is not allowlisted".into(),
        ));
    }
    let arn = item.exact_resource_id.splitn(6, ':').collect::<Vec<_>>();
    if arn.len() != 6
        || arn[0] != "arn"
        || arn[1] != "aws"
        || arn[2] != "cloudformation"
        || arn[3].is_empty()
        || !arn[3]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || arn[4].len() != 12
        || !arn[4].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AppError::NotAuthorized(
            "AWS partial cleanup stack ARN is malformed".into(),
        ));
    }
    let stack_resource = arn[5]
        .strip_prefix("stack/")
        .ok_or_else(|| AppError::NotAuthorized("AWS cleanup target is not a stack ARN".into()))?;
    let (stack_name, provider_stack_id) = stack_resource.split_once('/').ok_or_else(|| {
        AppError::NotAuthorized("AWS cleanup stack ARN lacks an exact provider ID".into())
    })?;
    if !valid_provider_path_segment(stack_name, 128)
        || provider_stack_id.is_empty()
        || provider_stack_id.len() > 256
        || provider_stack_id.chars().any(char::is_control)
    {
        return Err(AppError::NotAuthorized(
            "AWS partial cleanup stack identity is malformed".into(),
        ));
    }
    let expected_endpoint = format!(
        "https://cloudformation.{}.amazonaws.com/?Action=DeleteStack&StackName={stack_name}&Version=2010-05-15",
        arn[3]
    );
    if item.provider_api_endpoint != expected_endpoint {
        return Err(AppError::NotAuthorized(
            "AWS partial cleanup endpoint is outside the exact DeleteStack allowlist".into(),
        ));
    }
    Ok(PartialProviderTarget::AwsStack {
        region: arn[3].into(),
        account_id: arn[4].into(),
        stack_id: item.exact_resource_id.clone(),
    })
}

fn parse_partial_microsoft_target(
    item: &BootstrapMutationCleanupItem,
    azure: bool,
) -> AppResult<PartialProviderTarget> {
    let endpoint = item.provider_api_endpoint.as_str();
    if let Some(rest) = endpoint.strip_prefix(&format!("{MICROSOFT_GRAPH_ROOT}/applications/")) {
        if let Some(application_id) = rest.strip_suffix("/removePassword") {
            if item.provider_api_method != "POST"
                || !valid_provider_path_segment(application_id, 256)
                || !valid_provider_path_segment(&item.exact_resource_id, 256)
                || endpoint
                    != format!(
                        "{MICROSOFT_GRAPH_ROOT}/applications/{application_id}/removePassword"
                    )
            {
                return Err(AppError::NotAuthorized(
                    "Microsoft partial password cleanup target is malformed".into(),
                ));
            }
            return Ok(PartialProviderTarget::MicrosoftPassword {
                application_object_id: application_id.into(),
                key_id: item.exact_resource_id.clone(),
            });
        }
        if item.provider_api_method == "DELETE"
            && valid_provider_path_segment(rest, 256)
            && item.exact_resource_id == rest
            && endpoint == format!("{MICROSOFT_GRAPH_ROOT}/applications/{rest}")
        {
            return Ok(PartialProviderTarget::MicrosoftApplication {
                object_id: rest.into(),
            });
        }
    }
    if let Some(rest) = endpoint.strip_prefix(&format!("{MICROSOFT_GRAPH_ROOT}/servicePrincipals/"))
    {
        if let Some((service_principal_id, assignment_id)) = rest.split_once("/appRoleAssignments/")
        {
            if azure
                || item.provider_api_method != "DELETE"
                || !valid_provider_path_segment(service_principal_id, 256)
                || !valid_provider_path_segment(assignment_id, 256)
                || item.exact_resource_id != assignment_id
                || endpoint
                    != format!(
                        "{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{service_principal_id}/appRoleAssignments/{assignment_id}"
                    )
            {
                return Err(AppError::NotAuthorized(
                    "Microsoft app-role cleanup target is malformed".into(),
                ));
            }
            return Ok(PartialProviderTarget::MicrosoftAppRoleAssignment {
                service_principal_object_id: service_principal_id.into(),
                assignment_id: assignment_id.into(),
            });
        }
        if item.provider_api_method == "DELETE"
            && valid_provider_path_segment(rest, 256)
            && item.exact_resource_id == rest
            && endpoint == format!("{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{rest}")
        {
            return Ok(PartialProviderTarget::MicrosoftServicePrincipal {
                object_id: rest.into(),
            });
        }
    }
    if azure
        && let Some(rest) = endpoint.strip_prefix(&format!("{MICROSOFT_ARM_ROOT}/subscriptions/"))
        && let Some((subscription_id, assignment_and_version)) =
            rest.split_once("/providers/Microsoft.Authorization/roleAssignments/")
        && let Some(assignment_id) = assignment_and_version.strip_suffix("?api-version=2022-04-01")
        && item.provider_api_method == "DELETE"
        && valid_provider_path_segment(subscription_id, 256)
        && valid_provider_path_segment(assignment_id, 256)
        && item.exact_resource_id == assignment_id
        && endpoint
            == format!(
                "{MICROSOFT_ARM_ROOT}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}?api-version=2022-04-01"
            )
    {
        return Ok(PartialProviderTarget::AzureRoleAssignment {
            subscription_id: subscription_id.into(),
            assignment_id: assignment_id.into(),
        });
    }
    Err(AppError::NotAuthorized(
        "Microsoft partial cleanup operation is not allowlisted".into(),
    ))
}

fn parse_partial_gcp_target(
    item: &BootstrapMutationCleanupItem,
) -> AppResult<PartialProviderTarget> {
    if let Some(rest) = item
        .provider_api_endpoint
        .strip_prefix("https://iam.googleapis.com/v1/projects/")
        && let Some((project_id, account_and_key)) = rest.split_once("/serviceAccounts/")
    {
        if let Some((email, key_id)) = account_and_key.split_once("/keys/") {
            if item.provider_api_method == "DELETE"
                && valid_gcp_project_id(project_id)
                && valid_gcp_service_account_email(email, project_id)
                && valid_provider_path_segment(key_id, 256)
                && item.exact_resource_id == key_id
                && item.provider_api_endpoint
                    == format!(
                        "https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{email}/keys/{key_id}"
                    )
            {
                return Ok(PartialProviderTarget::GcpServiceAccountKey {
                    project_id: project_id.into(),
                    email: email.into(),
                    key_id: key_id.into(),
                });
            }
        } else if item.provider_api_method == "DELETE"
            && valid_gcp_project_id(project_id)
            && valid_gcp_service_account_email(account_and_key, project_id)
            && !item.exact_resource_id.is_empty()
            && item
                .exact_resource_id
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            && item.provider_api_endpoint
                == format!(
                    "https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{account_and_key}"
                )
        {
            return Ok(PartialProviderTarget::GcpServiceAccount {
                project_id: project_id.into(),
                email: account_and_key.into(),
                unique_id: item.exact_resource_id.clone(),
            });
        }
    }
    let resource = item
        .exact_resource_id
        .strip_prefix("organizations/")
        .and_then(|value| value.split_once(":serviceAccount:"));
    if let Some((organization_id, member_and_role)) = resource
        && let Some((email, role)) = member_and_role.rsplit_once(':')
        && item.provider_api_method == "POST"
        && !organization_id.is_empty()
        && organization_id.bytes().all(|byte| byte.is_ascii_digit())
        && valid_provider_path_segment(email, 320)
        && role.starts_with("roles/")
        && role.len() <= 256
        && role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && item.provider_api_endpoint
            == format!(
                "https://cloudresourcemanager.googleapis.com/v3/organizations/{organization_id}:setIamPolicy"
            )
    {
        return Ok(PartialProviderTarget::GcpOrganizationBinding {
            organization_id: organization_id.into(),
            email: email.into(),
            role: role.into(),
        });
    }
    Err(AppError::NotAuthorized(
        "GCP partial cleanup operation is not allowlisted".into(),
    ))
}

fn valid_gcp_project_id(value: &str) -> bool {
    (6..=30).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_gcp_service_account_email(email: &str, project_id: &str) -> bool {
    email
        .strip_suffix(&format!("@{project_id}.iam.gserviceaccount.com"))
        .is_some_and(|account| {
            (6..=30).contains(&account.len())
                && account
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn validate_partial_target_relationships(
    provider: BootstrapProvider,
    items: &[BootstrapMutationCleanupItem],
) -> AppResult<()> {
    let targets = items
        .iter()
        .map(|item| validate_partial_provider_item(provider, item))
        .collect::<AppResult<Vec<_>>>()?;
    let valid = match provider {
        BootstrapProvider::Aws => targets.len() <= 1,
        BootstrapProvider::Azure | BootstrapProvider::Microsoft365 => {
            let applications = targets
                .iter()
                .filter_map(|target| match target {
                    PartialProviderTarget::MicrosoftApplication { object_id } => Some(object_id),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let principals = targets
                .iter()
                .filter_map(|target| match target {
                    PartialProviderTarget::MicrosoftServicePrincipal { object_id } => {
                        Some(object_id)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let dependent_targets_match = targets.iter().all(|target| match target {
                PartialProviderTarget::MicrosoftPassword {
                    application_object_id,
                    ..
                } => applications.contains(&application_object_id),
                PartialProviderTarget::MicrosoftAppRoleAssignment {
                    service_principal_object_id,
                    ..
                } => principals.contains(&service_principal_object_id),
                PartialProviderTarget::AzureRoleAssignment { .. } => !principals.is_empty(),
                _ => true,
            });
            applications.len() <= 1
                && principals.len() <= 1
                && targets
                    .iter()
                    .filter(|target| {
                        matches!(target, PartialProviderTarget::MicrosoftPassword { .. })
                    })
                    .count()
                    <= 1
                && dependent_targets_match
        }
        BootstrapProvider::Gcp => {
            let accounts = targets
                .iter()
                .filter_map(|target| match target {
                    PartialProviderTarget::GcpServiceAccount {
                        project_id, email, ..
                    } => Some((project_id, email)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            accounts.len() <= 1
                && targets.iter().all(|target| match target {
                    PartialProviderTarget::GcpOrganizationBinding { email, .. }
                    | PartialProviderTarget::GcpServiceAccountKey { email, .. } => accounts
                        .iter()
                        .any(|(_, account_email)| account_email == &email),
                    _ => true,
                })
        }
    };
    if !valid {
        return Err(AppError::NotAuthorized(
            "partial cleanup target relationships are inconsistent".into(),
        ));
    }
    Ok(())
}

fn validate_partial_context_targets(
    context: &BootstrapMutationProviderContext,
    items: &[BootstrapMutationCleanupItem],
) -> AppResult<()> {
    let provider = context.provider();
    let matches = items.iter().all(|item| {
        let Ok(target) = validate_partial_provider_item(provider, item) else {
            return false;
        };
        match (context, target) {
            (
                BootstrapMutationProviderContext::Aws { account_id, region },
                PartialProviderTarget::AwsStack {
                    account_id: target_account,
                    region: target_region,
                    ..
                },
            ) => *account_id == target_account && *region == target_region,
            (
                BootstrapMutationProviderContext::Azure {
                    subscription_id, ..
                },
                PartialProviderTarget::AzureRoleAssignment {
                    subscription_id: target_subscription,
                    ..
                },
            ) => *subscription_id == target_subscription,
            (BootstrapMutationProviderContext::Azure { .. }, target) => matches!(
                target,
                PartialProviderTarget::MicrosoftApplication { .. }
                    | PartialProviderTarget::MicrosoftServicePrincipal { .. }
                    | PartialProviderTarget::MicrosoftPassword { .. }
            ),
            (
                BootstrapMutationProviderContext::Gcp {
                    organization_id,
                    project_id: _,
                },
                PartialProviderTarget::GcpOrganizationBinding {
                    organization_id: target_organization,
                    ..
                },
            ) => *organization_id == target_organization,
            (
                BootstrapMutationProviderContext::Gcp { project_id, .. },
                PartialProviderTarget::GcpServiceAccount {
                    project_id: target_project,
                    ..
                }
                | PartialProviderTarget::GcpServiceAccountKey {
                    project_id: target_project,
                    ..
                },
            ) => *project_id == target_project,
            (BootstrapMutationProviderContext::Microsoft365 { .. }, target) => matches!(
                target,
                PartialProviderTarget::MicrosoftApplication { .. }
                    | PartialProviderTarget::MicrosoftServicePrincipal { .. }
                    | PartialProviderTarget::MicrosoftPassword { .. }
                    | PartialProviderTarget::MicrosoftAppRoleAssignment { .. }
            ),
            _ => false,
        }
    });
    if !matches {
        return Err(AppError::NotAuthorized(
            "partial cleanup target does not match its immutable provider tenancy".into(),
        ));
    }
    Ok(())
}

fn cleanup_partial_mutation_ledger(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut BootstrapMutationLedger,
    operator: BootstrapOperatorConfig,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    validate_partial_mutation_ledger(ledger)?;
    validate_partial_operator_context(&ledger.provider_context, &operator)?;
    if ledger.items.is_empty() {
        ledger.recovery.state = BootstrapMutationRecoveryState::Completed;
        ledger.recovery.updated_at = Some(interaction.now());
        write_secret_free_atomic_json(cleanup_ledger_path, ledger)?;
        return Ok(());
    }
    initialize_partial_recovery(ledger, cleanup_ledger_path, interaction.now())?;
    match (ledger.provider, operator) {
        (BootstrapProvider::Aws, BootstrapOperatorConfig::Aws { administrator }) => {
            cleanup_partial_aws(
                http,
                interaction,
                ledger,
                administrator,
                cleanup_ledger_path,
            )
        }
        (BootstrapProvider::Azure, BootstrapOperatorConfig::Azure { authorization }) => {
            cleanup_partial_microsoft(
                http,
                interaction,
                ledger,
                authorization,
                true,
                cleanup_ledger_path,
            )
        }
        (
            BootstrapProvider::Microsoft365,
            BootstrapOperatorConfig::Microsoft365 { authorization },
        ) => cleanup_partial_microsoft(
            http,
            interaction,
            ledger,
            authorization,
            false,
            cleanup_ledger_path,
        ),
        (
            BootstrapProvider::Gcp,
            BootstrapOperatorConfig::Gcp {
                authorization,
                project_id,
            },
        ) => cleanup_partial_gcp(
            http,
            interaction,
            ledger,
            authorization,
            &project_id,
            cleanup_ledger_path,
        ),
        _ => Err(AppError::InvalidRequest(
            "cleanup operator configuration does not match the partial ledger provider".into(),
        )),
    }
}

fn validate_partial_operator_context(
    context: &BootstrapMutationProviderContext,
    operator: &BootstrapOperatorConfig,
) -> AppResult<()> {
    let matches = match (context, operator) {
        (
            BootstrapMutationProviderContext::Aws { account_id, region },
            BootstrapOperatorConfig::Aws { administrator },
        ) => administrator.account_id == *account_id && administrator.region == *region,
        (
            BootstrapMutationProviderContext::Azure {
                tenant_id,
                subscription_id,
            },
            BootstrapOperatorConfig::Azure { authorization },
        ) => {
            authorization.tenant_id == *tenant_id
                && authorization.subscription_id.as_deref() == Some(subscription_id.as_str())
        }
        (
            BootstrapMutationProviderContext::Gcp {
                organization_id,
                project_id,
            },
            BootstrapOperatorConfig::Gcp {
                authorization,
                project_id: operator_project_id,
            },
        ) => authorization.organization_id == *organization_id && operator_project_id == project_id,
        (
            BootstrapMutationProviderContext::Microsoft365 { tenant_id },
            BootstrapOperatorConfig::Microsoft365 { authorization },
        ) => authorization.tenant_id == *tenant_id,
        _ => false,
    };
    if !matches {
        return Err(AppError::NotAuthorized(
            "cleanup operator does not match the partial ledger provider tenancy".into(),
        ));
    }
    Ok(())
}

fn initialize_partial_recovery(
    ledger: &mut BootstrapMutationLedger,
    path: &Path,
    now: DateTime<Utc>,
) -> AppResult<()> {
    if !ledger.recovery.items.is_empty() {
        return Ok(());
    }
    ledger.recovery.items = ledger
        .items
        .iter()
        .map(|item| {
            Ok(BootstrapMutationCleanupProgress {
                item_id: partial_item_id(item)?,
                state: BootstrapMutationItemState::Pending,
                attempts: 0,
                last_attempt_at: None,
                last_provider_status: None,
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    ledger.recovery.state = partial_recovery_state(&ledger.recovery.items);
    ledger.recovery.updated_at = Some(now);
    validate_partial_mutation_ledger(ledger)?;
    write_secret_free_atomic_json(path, ledger)
}

fn partial_item_is_completed(
    ledger: &BootstrapMutationLedger,
    item: &BootstrapMutationCleanupItem,
) -> AppResult<bool> {
    let item_id = partial_item_id(item)?;
    ledger
        .recovery
        .items
        .iter()
        .find(|progress| progress.item_id == item_id)
        .map(|progress| progress.state == BootstrapMutationItemState::Completed)
        .ok_or_else(|| AppError::NotAuthorized("partial cleanup progress item is missing".into()))
}

fn record_partial_attempt_start(
    ledger: &mut BootstrapMutationLedger,
    path: &Path,
    item: &BootstrapMutationCleanupItem,
    now: DateTime<Utc>,
) -> AppResult<()> {
    let item_id = partial_item_id(item)?;
    let progress = ledger
        .recovery
        .items
        .iter_mut()
        .find(|progress| progress.item_id == item_id)
        .ok_or_else(|| {
            AppError::NotAuthorized("partial cleanup progress item is missing".into())
        })?;
    if progress.state == BootstrapMutationItemState::Completed {
        return Err(AppError::InvalidRequest(
            "completed partial cleanup item cannot be attempted again".into(),
        ));
    }
    progress.attempts = progress
        .attempts
        .checked_add(1)
        .ok_or_else(|| AppError::Internal("partial cleanup attempt counter overflowed".into()))?;
    progress.state = BootstrapMutationItemState::Attempting;
    progress.last_attempt_at = Some(now);
    progress.last_provider_status = Some("attempt_started".into());
    ledger.recovery.state = partial_recovery_state(&ledger.recovery.items);
    ledger.recovery.updated_at = Some(now);
    validate_partial_mutation_ledger(ledger)?;
    write_secret_free_atomic_json(path, ledger)
}

fn record_partial_attempt_result(
    ledger: &mut BootstrapMutationLedger,
    path: &Path,
    item: &BootstrapMutationCleanupItem,
    outcome: CleanupAttemptOutcome,
    provider_status: &str,
    now: DateTime<Utc>,
) -> AppResult<()> {
    if provider_status.is_empty()
        || provider_status.len() > 256
        || provider_status.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(
            "partial cleanup provider status is invalid".into(),
        ));
    }
    let item_id = partial_item_id(item)?;
    let progress = ledger
        .recovery
        .items
        .iter_mut()
        .find(|progress| progress.item_id == item_id)
        .ok_or_else(|| {
            AppError::NotAuthorized("partial cleanup progress item is missing".into())
        })?;
    if progress.state != BootstrapMutationItemState::Attempting {
        return Err(AppError::NotAuthorized(
            "partial cleanup result has no durable attempt start".into(),
        ));
    }
    progress.state = match outcome {
        CleanupAttemptOutcome::Succeeded | CleanupAttemptOutcome::ProviderResourceAlreadyAbsent => {
            BootstrapMutationItemState::Completed
        }
        CleanupAttemptOutcome::RetryableFailure => BootstrapMutationItemState::RetryableFailure,
    };
    progress.last_attempt_at = Some(now);
    progress.last_provider_status = Some(provider_status.into());
    ledger.recovery.state = partial_recovery_state(&ledger.recovery.items);
    ledger.recovery.updated_at = Some(now);
    validate_partial_mutation_ledger(ledger)?;
    write_secret_free_atomic_json(path, ledger)
}

fn partial_execution_order(ledger: &BootstrapMutationLedger) -> AppResult<Vec<usize>> {
    let mut ordered = ledger
        .items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let target = validate_partial_provider_item(ledger.provider, item)?;
            let priority = match target {
                PartialProviderTarget::AzureRoleAssignment { .. }
                | PartialProviderTarget::MicrosoftAppRoleAssignment { .. }
                | PartialProviderTarget::GcpOrganizationBinding { .. } => 10,
                PartialProviderTarget::MicrosoftPassword { .. }
                | PartialProviderTarget::GcpServiceAccountKey { .. } => 20,
                PartialProviderTarget::MicrosoftServicePrincipal { .. }
                | PartialProviderTarget::GcpServiceAccount { .. } => 30,
                PartialProviderTarget::MicrosoftApplication { .. } => 40,
                PartialProviderTarget::AwsStack { .. } => 10,
            };
            Ok((priority, index))
        })
        .collect::<AppResult<Vec<_>>>()?;
    ordered.sort_by_key(|(priority, index)| (*priority, *index));
    Ok(ordered.into_iter().map(|(_, index)| index).collect())
}

fn cleanup_partial_aws(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut BootstrapMutationLedger,
    administrator: AwsNativeAuthorizationConfig,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    let target = ledger
        .items
        .first()
        .map(parse_partial_aws_target)
        .transpose()?
        .ok_or_else(|| AppError::InvalidRequest("AWS partial cleanup has no target".into()))?;
    let PartialProviderTarget::AwsStack {
        region, account_id, ..
    } = target
    else {
        return Err(AppError::NotAuthorized(
            "AWS partial cleanup target is invalid".into(),
        ));
    };
    if administrator.region != region || administrator.account_id != account_id {
        return Err(AppError::NotAuthorized(
            "AWS cleanup administrator does not match the exact stack account and region".into(),
        ));
    }
    let (prompt, mut pending) =
        begin_aws_native_authorization(http, administrator.clone(), interaction.now())?;
    interaction.present_device_authorization(&prompt)?;
    let admin_role = poll_aws_until_complete(http, interaction, &mut pending)?;
    let credentials = AwsSigningCredentials {
        access_key_id: admin_role.access_key_id,
        secret_access_key: admin_role.secret_access_key,
        session_token: admin_role.session_token,
    };
    verify_aws_bootstrap_permissions(http, &administrator, &credentials, interaction.now())?;
    for index in partial_execution_order(ledger)? {
        let item = ledger.items[index].clone();
        if partial_item_is_completed(ledger, &item)? {
            continue;
        }
        let PartialProviderTarget::AwsStack { stack_id, .. } = parse_partial_aws_target(&item)?
        else {
            return Err(AppError::NotAuthorized(
                "AWS partial cleanup target changed".into(),
            ));
        };
        record_partial_attempt_start(ledger, cleanup_ledger_path, &item, interaction.now())?;
        let endpoint = format!(
            "https://cloudformation.{}.amazonaws.com/",
            administrator.region
        );
        let body = aws_form_body(vec![
            ("Action".into(), "DeleteStack".into()),
            ("Version".into(), "2010-05-15".into()),
            // CloudFormation accepts the exact stack ARN. Do not fall back to
            // a name lookup even though the recorded endpoint also binds it.
            ("StackName".into(), stack_id),
        ]);
        let result = provider_cleanup_response(
            aws_signed_request(
                ProviderHttpMethod::Post,
                &endpoint,
                "cloudformation",
                &administrator.region,
                body,
                &credentials,
                interaction.now(),
            )
            .and_then(|request| http.execute(request)),
            &[200],
        );
        record_partial_attempt_result(
            ledger,
            cleanup_ledger_path,
            &item,
            result.0,
            result.1,
            interaction.now(),
        )?;
    }
    drop(credentials);
    Ok(())
}

fn cleanup_partial_microsoft(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut BootstrapMutationLedger,
    authorization: MicrosoftNativeAuthorizationConfig,
    azure: bool,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    use crate::source_authorization::ProviderSourceProfile;
    let expected_profile = if azure {
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken
    } else {
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken
    };
    if authorization.profile != expected_profile || azure != authorization.subscription_id.is_some()
    {
        return Err(AppError::InvalidRequest(
            "Microsoft cleanup authorization profile does not match the partial ledger provider"
                .into(),
        ));
    }
    if azure {
        let expected_subscriptions = ledger
            .items
            .iter()
            .filter_map(|item| match parse_partial_microsoft_target(item, true) {
                Ok(PartialProviderTarget::AzureRoleAssignment {
                    subscription_id, ..
                }) => Some(subscription_id),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if expected_subscriptions.len() > 1
            || expected_subscriptions
                .iter()
                .next()
                .is_some_and(|subscription| {
                    authorization.subscription_id.as_deref() != Some(subscription.as_str())
                })
        {
            return Err(AppError::NotAuthorized(
                "Azure cleanup authorization does not match the exact subscription".into(),
            ));
        }
    }
    let purpose = if azure {
        MicrosoftAdminPurpose::Azure
    } else {
        MicrosoftAdminPurpose::Microsoft365
    };
    let mut admin =
        microsoft_admin_device_authorization(http, interaction, &authorization, purpose)?;
    let arm_token = if azure {
        let refresh = admin.refresh_token.take().ok_or_else(|| {
            AppError::NotAuthorized("Azure cleanup requires a new in-memory refresh token".into())
        })?;
        let arm = microsoft_refresh_resource_token(
            http,
            &authorization,
            refresh,
            "https://management.azure.com/.default",
        )?;
        let subscription = authorization.subscription_id.as_deref().ok_or_else(|| {
            AppError::InvalidRequest("Azure cleanup subscription is missing".into())
        })?;
        verify_azure_administrator_permissions(http, &arm.access_token, subscription)?;
        Some(arm)
    } else {
        None
    };
    for index in partial_execution_order(ledger)? {
        let item = ledger.items[index].clone();
        if partial_item_is_completed(ledger, &item)? {
            continue;
        }
        let target = parse_partial_microsoft_target(&item, azure)?;
        let token = if matches!(target, PartialProviderTarget::AzureRoleAssignment { .. }) {
            &arm_token
                .as_ref()
                .ok_or_else(|| {
                    AppError::NotAuthorized("Azure cleanup ARM token is unavailable".into())
                })?
                .access_token
        } else {
            &admin.graph_token
        };
        record_partial_attempt_start(ledger, cleanup_ledger_path, &item, interaction.now())?;
        let cleanup_request = match target {
            PartialProviderTarget::MicrosoftPassword { key_id, .. } => serializable_json_request(
                ProviderHttpMethod::Post,
                &item.provider_api_endpoint,
                &MicrosoftRemovePassword { key_id: &key_id },
                vec![bearer_header(token)],
            ),
            PartialProviderTarget::MicrosoftApplication { .. }
            | PartialProviderTarget::MicrosoftServicePrincipal { .. }
            | PartialProviderTarget::AzureRoleAssignment { .. }
            | PartialProviderTarget::MicrosoftAppRoleAssignment { .. } => request(
                ProviderHttpMethod::Delete,
                &item.provider_api_endpoint,
                vec![bearer_header(token)],
                Zeroizing::new(Vec::new()),
            ),
            _ => Err(AppError::NotAuthorized(
                "Microsoft partial cleanup operation changed".into(),
            )),
        };
        let result = provider_cleanup_response(
            cleanup_request.and_then(|request| http.execute(request)),
            &[200, 204],
        );
        record_partial_attempt_result(
            ledger,
            cleanup_ledger_path,
            &item,
            result.0,
            result.1,
            interaction.now(),
        )?;
    }
    drop(arm_token);
    drop(admin);
    Ok(())
}

fn cleanup_partial_gcp(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut BootstrapMutationLedger,
    authorization: GcpNativeAuthorizationConfig,
    project_id: &str,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    let targets = ledger
        .items
        .iter()
        .map(parse_partial_gcp_target)
        .collect::<AppResult<Vec<_>>>()?;
    let (recorded_project, service_account_email) = targets
        .iter()
        .find_map(|target| match target {
            PartialProviderTarget::GcpServiceAccount {
                project_id, email, ..
            } => Some((project_id.clone(), email.clone())),
            _ => None,
        })
        .ok_or_else(|| AppError::NotAuthorized("GCP partial cleanup account is missing".into()))?;
    let organizations = targets
        .iter()
        .filter_map(|target| match target {
            PartialProviderTarget::GcpOrganizationBinding {
                organization_id, ..
            } => Some(organization_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if recorded_project != project_id
        || organizations.len() > 1
        || organizations
            .iter()
            .next()
            .is_some_and(|organization| organization != &authorization.organization_id)
    {
        return Err(AppError::NotAuthorized(
            "GCP cleanup authorization does not match the exact organization and project".into(),
        ));
    }
    validate_gcp_operator_config(&authorization, project_id)?;
    let admin = gcp_admin_pkce_authorization(http, interaction, &authorization)?;
    verify_gcp_administrator_permissions(
        http,
        &admin.access_token,
        &authorization.organization_id,
        project_id,
    )?;
    for index in partial_execution_order(ledger)? {
        let item = ledger.items[index].clone();
        if partial_item_is_completed(ledger, &item)? {
            continue;
        }
        let target = parse_partial_gcp_target(&item)?;
        record_partial_attempt_start(ledger, cleanup_ledger_path, &item, interaction.now())?;
        let result = match target {
            PartialProviderTarget::GcpOrganizationBinding {
                organization_id,
                email,
                role,
            } => {
                if email != service_account_email {
                    return Err(AppError::NotAuthorized(
                        "GCP cleanup binding member changed".into(),
                    ));
                }
                match remove_gcp_organization_roles(
                    http,
                    &admin.access_token,
                    &organization_id,
                    &email,
                    &[role],
                ) {
                    Ok(()) => (CleanupAttemptOutcome::Succeeded, "binding_removed"),
                    Err(_) => (CleanupAttemptOutcome::RetryableFailure, "provider_error"),
                }
            }
            PartialProviderTarget::GcpServiceAccount {
                email, unique_id, ..
            } => match verify_and_delete_partial_gcp_service_account(
                http,
                &admin.access_token,
                &item.provider_api_endpoint,
                &email,
                &unique_id,
            ) {
                Ok(result) => result,
                Err(error) => {
                    record_partial_attempt_result(
                        ledger,
                        cleanup_ledger_path,
                        &item,
                        CleanupAttemptOutcome::RetryableFailure,
                        "identity_mismatch",
                        interaction.now(),
                    )?;
                    return Err(error);
                }
            },
            PartialProviderTarget::GcpServiceAccountKey { .. } => provider_cleanup_response(
                request(
                    ProviderHttpMethod::Delete,
                    &item.provider_api_endpoint,
                    vec![bearer_header(&admin.access_token)],
                    Zeroizing::new(Vec::new()),
                )
                .and_then(|request| http.execute(request)),
                &[200, 204],
            ),
            _ => {
                return Err(AppError::NotAuthorized(
                    "GCP partial cleanup operation changed".into(),
                ));
            }
        };
        record_partial_attempt_result(
            ledger,
            cleanup_ledger_path,
            &item,
            result.0,
            result.1,
            interaction.now(),
        )?;
    }
    drop(admin);
    Ok(())
}

fn verify_and_delete_partial_gcp_service_account(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    endpoint: &str,
    expected_email: &str,
    expected_unique_id: &str,
) -> AppResult<(CleanupAttemptOutcome, &'static str)> {
    let response = match bearer_get(endpoint, token).and_then(|request| http.execute(request)) {
        Ok(response) => response,
        Err(_) => {
            return Ok((CleanupAttemptOutcome::RetryableFailure, "provider_error"));
        }
    };
    if response.status == 404 {
        return Ok((
            CleanupAttemptOutcome::ProviderResourceAlreadyAbsent,
            "not_found",
        ));
    }
    let account: GcpServiceAccountCreated = decode_success_json(
        &response,
        &[200],
        "Google exact service account cleanup verification",
    )?;
    if account.email != expected_email || account.unique_id != expected_unique_id {
        return Err(AppError::NotAuthorized(
            "Google cleanup endpoint no longer resolves to the recorded exact service account ID"
                .into(),
        ));
    }
    Ok(provider_cleanup_response(
        request(
            ProviderHttpMethod::Delete,
            endpoint,
            vec![bearer_header(token)],
            Zeroizing::new(Vec::new()),
        )
        .and_then(|request| http.execute(request)),
        &[200, 204],
    ))
}

fn cleanup_aws(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut CleanupLedger,
    administrator: AwsNativeAuthorizationConfig,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    let CreatedBootstrapResources::Aws {
        stack_id,
        stack_name,
        role_arn,
        role_name,
    } = &ledger.resources
    else {
        return Err(AppError::InvalidRequest(
            "AWS cleanup resources are malformed".into(),
        ));
    };
    let stack_id = stack_id.clone();
    let stack_name = stack_name.clone();
    let role_arn = role_arn.clone();
    let role_name = role_name.clone();
    let arn_account = stack_id.split(':').nth(4).unwrap_or_default();
    let arn_region = stack_id.split(':').nth(3).unwrap_or_default();
    if arn_account != administrator.account_id || arn_region != administrator.region {
        return Err(AppError::NotAuthorized(
            "AWS cleanup administrator configuration does not match the exact stack account and region"
                .into(),
        ));
    }
    let (prompt, mut pending) =
        begin_aws_native_authorization(http, administrator.clone(), interaction.now())?;
    interaction.present_device_authorization(&prompt)?;
    let admin_role = poll_aws_until_complete(http, interaction, &mut pending)?;
    let credentials = AwsSigningCredentials {
        access_key_id: admin_role.access_key_id,
        secret_access_key: admin_role.secret_access_key,
        session_token: admin_role.session_token,
    };
    verify_aws_bootstrap_permissions(http, &administrator, &credentials, interaction.now())?;
    let item_ids = ledger
        .items
        .iter()
        .filter(|item| item.state != CleanupState::Completed)
        .map(|item| item.item_id.clone())
        .collect::<Vec<_>>();
    for item_id in item_ids {
        let item = ledger
            .items
            .iter()
            .find(|item| item.item_id == item_id)
            .cloned()
            .ok_or_else(|| AppError::Internal("cleanup item disappeared".into()))?;
        if item.provider_api_method == "LOCAL_TIME_BOUND"
            && item
                .not_before
                .is_some_and(|not_before| interaction.now() < not_before)
        {
            continue;
        }
        let result = match item.obligation.as_str() {
            "delete_stack" => {
                let endpoint = format!(
                    "https://cloudformation.{}.amazonaws.com/",
                    administrator.region
                );
                let body = aws_form_body(vec![
                    ("Action".into(), "DeleteStack".into()),
                    ("Version".into(), "2010-05-15".into()),
                    ("StackName".into(), stack_name.clone()),
                ]);
                provider_cleanup_response(
                    http.execute(aws_signed_request(
                        ProviderHttpMethod::Post,
                        &endpoint,
                        "cloudformation",
                        &administrator.region,
                        body,
                        &credentials,
                        interaction.now(),
                    )?),
                    &[200],
                )
            }
            "verify_role_absent" => {
                if item.exact_resource_id != role_arn {
                    return Err(AppError::NotAuthorized(
                        "AWS cleanup role target does not match the exact stack output".into(),
                    ));
                }
                let body = aws_form_body(vec![
                    ("Action".into(), "GetRole".into()),
                    ("Version".into(), "2010-05-08".into()),
                    ("RoleName".into(), role_name.clone()),
                ]);
                match http.execute(aws_signed_request(
                    ProviderHttpMethod::Post,
                    "https://iam.amazonaws.com/",
                    "iam",
                    "us-east-1",
                    body,
                    &credentials,
                    interaction.now(),
                )?) {
                    Ok(response)
                        if response.status == 404
                            || (response.status == 400
                                && response
                                    .body()
                                    .windows(b"NoSuchEntity".len())
                                    .any(|window| window == b"NoSuchEntity")) =>
                    {
                        (
                            CleanupAttemptOutcome::ProviderResourceAlreadyAbsent,
                            "not_found",
                        )
                    }
                    Ok(response) if response.status == 200 => (
                        CleanupAttemptOutcome::RetryableFailure,
                        "role_still_present",
                    ),
                    Ok(_) | Err(_) => (CleanupAttemptOutcome::RetryableFailure, "provider_error"),
                }
            }
            "confirm_all_short_lived_scanner_sessions_expired" => {
                local_expiry_cleanup_result(&item, interaction.now())
            }
            _ => {
                return Err(AppError::NotAuthorized(
                    "AWS cleanup ledger contains an unrecognized obligation".into(),
                ));
            }
        };
        record_cleanup_attempt_durable(
            ledger,
            cleanup_ledger_path,
            &item_id,
            result.0,
            result.1,
            interaction.now(),
        )?;
    }
    drop(credentials);
    Ok(())
}

fn cleanup_azure(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut CleanupLedger,
    authorization: MicrosoftNativeAuthorizationConfig,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    let CreatedBootstrapResources::Azure {
        tenant_id,
        subscription_id,
        ..
    } = &ledger.resources
    else {
        return Err(AppError::InvalidRequest(
            "Azure cleanup resources are malformed".into(),
        ));
    };
    if authorization.tenant_id != *tenant_id
        || authorization.subscription_id.as_deref() != Some(subscription_id.as_str())
    {
        return Err(AppError::NotAuthorized(
            "Azure cleanup operator configuration does not match the ledger tenant and subscription"
                .into(),
        ));
    }
    let mut admin = microsoft_admin_device_authorization(
        http,
        interaction,
        &authorization,
        MicrosoftAdminPurpose::Azure,
    )?;
    let refresh = admin.refresh_token.take().ok_or_else(|| {
        AppError::NotAuthorized("Azure cleanup requires an in-memory refresh token".into())
    })?;
    let arm = microsoft_refresh_resource_token(
        http,
        &authorization,
        refresh,
        "https://management.azure.com/.default",
    )?;
    run_microsoft_cleanup_items(
        http,
        interaction,
        ledger,
        &admin.graph_token,
        Some(&arm.access_token),
        cleanup_ledger_path,
    )?;
    drop(arm);
    drop(admin);
    Ok(())
}

fn cleanup_microsoft365(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut CleanupLedger,
    authorization: MicrosoftNativeAuthorizationConfig,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    let CreatedBootstrapResources::Microsoft365 { tenant_id, .. } = &ledger.resources else {
        return Err(AppError::InvalidRequest(
            "Microsoft 365 cleanup resources are malformed".into(),
        ));
    };
    if authorization.tenant_id != *tenant_id {
        return Err(AppError::NotAuthorized(
            "Microsoft 365 cleanup operator configuration does not match the ledger tenant".into(),
        ));
    }
    let admin = microsoft_admin_device_authorization(
        http,
        interaction,
        &authorization,
        MicrosoftAdminPurpose::Microsoft365,
    )?;
    run_microsoft_cleanup_items(
        http,
        interaction,
        ledger,
        &admin.graph_token,
        None,
        cleanup_ledger_path,
    )?;
    drop(admin);
    Ok(())
}

fn run_microsoft_cleanup_items(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut CleanupLedger,
    graph_token: &Zeroizing<String>,
    arm_token: Option<&Zeroizing<String>>,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    let item_ids = ledger
        .items
        .iter()
        .filter(|item| item.state != CleanupState::Completed)
        .map(|item| item.item_id.clone())
        .collect::<Vec<_>>();
    for item_id in item_ids {
        let item = ledger
            .items
            .iter()
            .find(|item| item.item_id == item_id)
            .cloned()
            .ok_or_else(|| AppError::Internal("cleanup item disappeared".into()))?;
        if item.provider_api_method == "LOCAL_TIME_BOUND"
            && item
                .not_before
                .is_some_and(|not_before| interaction.now() < not_before)
        {
            continue;
        }
        let result = if item.provider_api_method == "LOCAL_TIME_BOUND" {
            local_expiry_cleanup_result(&item, interaction.now())
        } else {
            let is_arm = item.provider_api_endpoint.starts_with(MICROSOFT_ARM_ROOT);
            let token = if is_arm {
                arm_token.ok_or_else(|| {
                    AppError::NotAuthorized(
                        "Microsoft 365 ledger unexpectedly contains an Azure cleanup target".into(),
                    )
                })?
            } else {
                graph_token
            };
            let request = match item.provider_api_method.as_str() {
                "DELETE" => request(
                    ProviderHttpMethod::Delete,
                    &item.provider_api_endpoint,
                    vec![bearer_header(token)],
                    Zeroizing::new(Vec::new()),
                ),
                "POST" if item.obligation == "remove_temporary_password" => {
                    serializable_json_request(
                        ProviderHttpMethod::Post,
                        &item.provider_api_endpoint,
                        &MicrosoftRemovePassword {
                            key_id: &item.exact_resource_id,
                        },
                        vec![bearer_header(token)],
                    )
                }
                _ => {
                    return Err(AppError::NotAuthorized(
                        "Microsoft cleanup ledger contains an unrecognized operation".into(),
                    ));
                }
            }?;
            provider_cleanup_response(http.execute(request), &[200, 204])
        };
        record_cleanup_attempt_durable(
            ledger,
            cleanup_ledger_path,
            &item_id,
            result.0,
            result.1,
            interaction.now(),
        )?;
    }
    Ok(())
}

fn cleanup_gcp(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    ledger: &mut CleanupLedger,
    authorization: GcpNativeAuthorizationConfig,
    project_id: &str,
    cleanup_ledger_path: &Path,
) -> AppResult<()> {
    let CreatedBootstrapResources::Gcp {
        organization_id,
        project_id: ledger_project_id,
        service_account_email,
        bound_role_names,
        ..
    } = &ledger.resources
    else {
        return Err(AppError::InvalidRequest(
            "GCP cleanup resources are malformed".into(),
        ));
    };
    if authorization.organization_id != *organization_id || project_id != ledger_project_id {
        return Err(AppError::NotAuthorized(
            "GCP cleanup operator configuration does not match the ledger organization and project"
                .into(),
        ));
    }
    let organization_id = organization_id.clone();
    let service_account_email = service_account_email.clone();
    let bound_role_names = bound_role_names.clone();
    let admin = gcp_admin_pkce_authorization(http, interaction, &authorization)?;
    verify_gcp_administrator_permissions(http, &admin.access_token, &organization_id, project_id)?;
    let binding_result = remove_gcp_organization_roles(
        http,
        &admin.access_token,
        &organization_id,
        &service_account_email,
        &bound_role_names,
    );
    let item_ids = ledger
        .items
        .iter()
        .filter(|item| item.state != CleanupState::Completed)
        .map(|item| item.item_id.clone())
        .collect::<Vec<_>>();
    for item_id in item_ids {
        let item = ledger
            .items
            .iter()
            .find(|item| item.item_id == item_id)
            .cloned()
            .ok_or_else(|| AppError::Internal("cleanup item disappeared".into()))?;
        if item.provider_api_method == "LOCAL_TIME_BOUND"
            && item
                .not_before
                .is_some_and(|not_before| interaction.now() < not_before)
        {
            continue;
        }
        let result = if item.obligation.starts_with("remove_iam_binding_") {
            if binding_result.is_ok() {
                (CleanupAttemptOutcome::Succeeded, "binding_removed")
            } else {
                (CleanupAttemptOutcome::RetryableFailure, "provider_error")
            }
        } else if item.obligation.starts_with("delete_service_account_key_")
            || item.obligation == "delete_service_account"
        {
            let response = request(
                ProviderHttpMethod::Delete,
                &item.provider_api_endpoint,
                vec![bearer_header(&admin.access_token)],
                Zeroizing::new(Vec::new()),
            )
            .and_then(|request| http.execute(request));
            provider_cleanup_response(response, &[200, 204])
        } else if item.provider_api_method == "LOCAL_TIME_BOUND" {
            local_expiry_cleanup_result(&item, interaction.now())
        } else {
            return Err(AppError::NotAuthorized(
                "GCP cleanup ledger contains an unrecognized operation".into(),
            ));
        };
        record_cleanup_attempt_durable(
            ledger,
            cleanup_ledger_path,
            &item_id,
            result.0,
            result.1,
            interaction.now(),
        )?;
    }
    drop(admin);
    Ok(())
}

fn provider_cleanup_response(
    response: AppResult<crate::source_authorization::provider::ProviderHttpResponse>,
    successes: &[u16],
) -> (CleanupAttemptOutcome, &'static str) {
    match response {
        Ok(response) if successes.contains(&response.status) => {
            (CleanupAttemptOutcome::Succeeded, "succeeded")
        }
        Ok(response) if response.status == 404 => (
            CleanupAttemptOutcome::ProviderResourceAlreadyAbsent,
            "not_found",
        ),
        Ok(_) | Err(_) => (CleanupAttemptOutcome::RetryableFailure, "provider_error"),
    }
}

fn record_cleanup_attempt_durable(
    ledger: &mut CleanupLedger,
    cleanup_ledger_path: &Path,
    item_id: &str,
    outcome: CleanupAttemptOutcome,
    provider_status: &str,
    now: DateTime<Utc>,
) -> AppResult<()> {
    record_cleanup_attempt(ledger, item_id, outcome, provider_status, now)?;
    super::write_cleanup_ledger(cleanup_ledger_path, ledger)
}

fn local_expiry_cleanup_result(
    item: &ExactCleanupItem,
    now: DateTime<Utc>,
) -> (CleanupAttemptOutcome, &'static str) {
    if item.not_before.is_some_and(|not_before| now >= not_before) {
        (CleanupAttemptOutcome::Succeeded, "expiry_elapsed")
    } else {
        (CleanupAttemptOutcome::RetryableFailure, "expiry_pending")
    }
}

fn execute_aws(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    bootstrap: BootstrapRequest,
    administrator: AwsNativeAuthorizationConfig,
    cleanup_ledger_path: &Path,
) -> AppResult<BootstrapExecutionResult> {
    if bootstrap.scan_identity_name.len() > 60 {
        return Err(AppError::InvalidRequest(
            "AWS scan identity name exceeds the pinned CloudFormation role-name limit".into(),
        ));
    }
    let mut journal = BootstrapMutationLedger::new(
        &bootstrap.case_id,
        BootstrapMutationProviderContext::Aws {
            account_id: administrator.account_id.clone(),
            region: administrator.region.clone(),
        },
        interaction.now(),
    );
    journal.initialize(cleanup_ledger_path)?;
    let (prompt, mut pending) =
        begin_aws_native_authorization(http, administrator.clone(), interaction.now())?;
    interaction.present_device_authorization(&prompt)?;
    let admin_role = poll_aws_until_complete(http, interaction, &mut pending)?;
    let admin_credentials = AwsSigningCredentials {
        access_key_id: admin_role.access_key_id,
        secret_access_key: admin_role.secret_access_key,
        session_token: admin_role.session_token,
    };
    verify_aws_bootstrap_permissions(http, &administrator, &admin_credentials, interaction.now())?;

    let external_id = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>()?.as_slice()),
    );
    let stack_name = format!(
        "{}-{}",
        bootstrap.scan_identity_name,
        &hex::encode(Sha256::digest(bootstrap.case_id.as_bytes()))[..10]
    );
    let stack_id = aws_create_stack(
        http,
        &administrator,
        &admin_credentials,
        &stack_name,
        &bootstrap.scan_identity_name,
        &administrator.role_arn,
        &external_id,
        interaction.now(),
    )?;
    journal.record(
        cleanup_ledger_path,
        BootstrapMutationCleanupItem {
            exact_resource_id: stack_id.clone(),
            provider_api_method: "POST".into(),
            provider_api_endpoint: format!(
                "https://cloudformation.{}.amazonaws.com/?Action=DeleteStack&StackName={}&Version=2010-05-15",
                administrator.region, stack_name
            ),
            cleanup_semantics: "DeleteStack for this exact stack, then verify the exact role ARN is absent".into(),
        },
    )?;
    let role_arn = aws_wait_for_stack(
        http,
        interaction,
        &administrator,
        &admin_credentials,
        &stack_id,
    )?;
    let scanner = aws_assume_scan_role(
        http,
        &administrator,
        &admin_credentials,
        &role_arn,
        &external_id,
        bootstrap.expires_at,
        interaction.now(),
    )?;
    drop(external_id);
    drop(admin_credentials);
    let admin_material_destroyed_at = interaction.now();

    let scanner_config = AwsNativeAuthorizationConfig {
        start_url: administrator.start_url,
        region: administrator.region,
        account_id: administrator.account_id,
        role_name: bootstrap.scan_identity_name.clone(),
        role_arn: role_arn.clone(),
    };
    let scanner_expiry =
        DateTime::<Utc>::from_timestamp_millis(scanner.expiration).ok_or_else(|| {
            AppError::NotAuthorized("AWS scanner credential expiry is invalid".into())
        })?;
    let authorization = verify_bootstrap_aws_credentials(
        http,
        &scanner_config,
        scanner.access_key_id,
        scanner.secret_access_key,
        scanner.session_token,
        scanner_expiry,
        interaction.now(),
    )?;
    let credential_expires_at = authorization.verification().credential_expires_at;
    let resources = CreatedBootstrapResources::Aws {
        stack_id,
        stack_name,
        role_arn,
        role_name: bootstrap.scan_identity_name,
    };
    let cleanup_ledger = create_cleanup_ledger(
        &bootstrap.case_id,
        resources,
        credential_expires_at,
        admin_material_destroyed_at,
        interaction.now(),
    )?;
    super::write_cleanup_ledger(cleanup_ledger_path, &cleanup_ledger)?;
    Ok(BootstrapExecutionResult {
        authorization,
        cleanup_ledger,
    })
}

fn poll_aws_until_complete(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    pending: &mut crate::source_authorization::provider::AwsPendingDeviceAuthorization,
) -> AppResult<AwsRoleCredentials> {
    for _ in 0..MAX_POLL_ATTEMPTS {
        match poll_aws_role_credentials(http, pending, interaction.now())? {
            PollAuthorization::Complete(credentials) => return Ok(credentials),
            PollAuthorization::Pending {
                retry_after_seconds,
            } => interaction.wait(retry_after_seconds)?,
        }
    }
    Err(AppError::NotAuthorized(
        "AWS device authorization did not complete within the bounded polling window".into(),
    ))
}

fn verify_aws_bootstrap_permissions(
    http: &dyn ProviderHttp,
    config: &AwsNativeAuthorizationConfig,
    credentials: &AwsSigningCredentials,
    now: DateTime<Utc>,
) -> AppResult<()> {
    let required = [
        "cloudformation:CreateStack",
        "cloudformation:DescribeStacks",
        "cloudformation:DeleteStack",
        "iam:CreateRole",
        "iam:GetRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "sts:AssumeRole",
    ];
    let mut fields = vec![
        ("Action".to_owned(), "SimulatePrincipalPolicy".to_owned()),
        ("Version".to_owned(), "2010-05-08".to_owned()),
        ("PolicySourceArn".to_owned(), config.role_arn.clone()),
    ];
    for (index, action) in required.iter().enumerate() {
        fields.push((
            format!("ActionNames.member.{}", index + 1),
            (*action).into(),
        ));
    }
    let body = aws_form_body(fields);
    let response = http.execute(aws_signed_request(
        ProviderHttpMethod::Post,
        "https://iam.amazonaws.com/",
        "iam",
        "us-east-1",
        body,
        credentials,
        now,
    )?)?;
    ensure_status(
        &response,
        &[200],
        "AWS bootstrap administrator permission simulation",
    )?;
    let xml = std::str::from_utf8(response.body())
        .map_err(|_| AppError::NotAuthorized("AWS IAM returned non-UTF-8 XML".into()))?;
    let decisions = aws_simulation_decisions(xml)?;
    for action in required {
        if decisions.get(action).map(String::as_str) != Some("allowed") {
            return Err(AppError::NotAuthorized(format!(
                "AWS administrator cannot perform required bootstrap operation {action}"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn aws_create_stack(
    http: &dyn ProviderHttp,
    config: &AwsNativeAuthorizationConfig,
    credentials: &AwsSigningCredentials,
    stack_name: &str,
    role_name: &str,
    trusted_principal_arn: &str,
    external_id: &Zeroizing<String>,
    now: DateTime<Utc>,
) -> AppResult<String> {
    let template = include_str!("../../../bootstrap/aws-readonly-cloudformation.yaml");
    let body = aws_form_body(vec![
        ("Action".into(), "CreateStack".into()),
        ("Version".into(), "2010-05-15".into()),
        ("StackName".into(), stack_name.into()),
        (
            "Capabilities.member.1".into(),
            "CAPABILITY_NAMED_IAM".into(),
        ),
        ("OnFailure".into(), "DELETE".into()),
        ("EnableTerminationProtection".into(), "false".into()),
        ("TemplateBody".into(), template.into()),
        (
            "Parameters.member.1.ParameterKey".into(),
            "ScanRoleName".into(),
        ),
        (
            "Parameters.member.1.ParameterValue".into(),
            role_name.into(),
        ),
        (
            "Parameters.member.2.ParameterKey".into(),
            "TrustedPrincipalArn".into(),
        ),
        (
            "Parameters.member.2.ParameterValue".into(),
            trusted_principal_arn.into(),
        ),
        (
            "Parameters.member.3.ParameterKey".into(),
            "ExternalId".into(),
        ),
        (
            "Parameters.member.3.ParameterValue".into(),
            external_id.as_str().into(),
        ),
    ]);
    let endpoint = format!("https://cloudformation.{}.amazonaws.com/", config.region);
    let response = http.execute(aws_signed_request(
        ProviderHttpMethod::Post,
        &endpoint,
        "cloudformation",
        &config.region,
        body,
        credentials,
        now,
    )?)?;
    ensure_status(&response, &[200], "AWS CloudFormation stack creation")?;
    let xml = std::str::from_utf8(response.body())
        .map_err(|_| AppError::NotAuthorized("AWS CloudFormation returned non-UTF-8 XML".into()))?;
    let stack_id = xml_first(xml, "StackId")?;
    if !stack_id.starts_with(&format!(
        "arn:aws:cloudformation:{}:{}:stack/{stack_name}/",
        config.region, config.account_id
    )) {
        return Err(AppError::NotAuthorized(
            "AWS CloudFormation returned a different stack identity".into(),
        ));
    }
    Ok(stack_id)
}

fn aws_wait_for_stack(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    config: &AwsNativeAuthorizationConfig,
    credentials: &AwsSigningCredentials,
    stack_id: &str,
) -> AppResult<String> {
    let endpoint = format!("https://cloudformation.{}.amazonaws.com/", config.region);
    for _ in 0..MAX_POLL_ATTEMPTS {
        let body = aws_form_body(vec![
            ("Action".into(), "DescribeStacks".into()),
            ("Version".into(), "2010-05-15".into()),
            ("StackName".into(), stack_id.into()),
        ]);
        let response = http.execute(aws_signed_request(
            ProviderHttpMethod::Post,
            &endpoint,
            "cloudformation",
            &config.region,
            body,
            credentials,
            interaction.now(),
        )?)?;
        ensure_status(&response, &[200], "AWS CloudFormation stack status")?;
        let xml = std::str::from_utf8(response.body()).map_err(|_| {
            AppError::NotAuthorized("AWS CloudFormation returned non-UTF-8 XML".into())
        })?;
        let status = xml_first(xml, "StackStatus")?;
        if status == "CREATE_COMPLETE" {
            let role_arn = cloudformation_output(xml, "ScanRoleArn")?;
            if !role_arn.starts_with(&format!("arn:aws:iam::{}:role/", config.account_id)) {
                return Err(AppError::NotAuthorized(
                    "AWS stack output returned a role outside the configured account".into(),
                ));
            }
            return Ok(role_arn);
        }
        if status.ends_with("FAILED") || status.contains("ROLLBACK") || status == "DELETE_COMPLETE"
        {
            return Err(AppError::NotAuthorized(format!(
                "AWS CloudFormation bootstrap stack entered terminal state {status}"
            )));
        }
        interaction.wait(5)?;
    }
    Err(AppError::NotAvailable(
        "AWS CloudFormation stack did not finish within the bounded polling window".into(),
    ))
}

fn aws_assume_scan_role(
    http: &dyn ProviderHttp,
    config: &AwsNativeAuthorizationConfig,
    credentials: &AwsSigningCredentials,
    role_arn: &str,
    external_id: &Zeroizing<String>,
    requested_expiry: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<AwsRoleCredentials> {
    let remaining = (requested_expiry - now).num_seconds().clamp(900, 3600);
    let session_name = format!(
        "ai-security-scanner-{}",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let body = aws_form_body(vec![
        ("Action".into(), "AssumeRole".into()),
        ("Version".into(), "2011-06-15".into()),
        ("RoleArn".into(), role_arn.into()),
        ("RoleSessionName".into(), session_name),
        ("DurationSeconds".into(), remaining.to_string()),
        ("ExternalId".into(), external_id.as_str().into()),
    ]);
    let endpoint = format!("https://sts.{}.amazonaws.com/", config.region);
    let response = http.execute(aws_signed_request(
        ProviderHttpMethod::Post,
        &endpoint,
        "sts",
        &config.region,
        body,
        credentials,
        now,
    )?)?;
    ensure_status(&response, &[200], "AWS dedicated scanner role assumption")?;
    let xml = std::str::from_utf8(response.body())
        .map_err(|_| AppError::NotAuthorized("AWS STS returned non-UTF-8 XML".into()))?;
    let expiration = DateTime::parse_from_rfc3339(&xml_first(xml, "Expiration")?)
        .map_err(|_| AppError::NotAuthorized("AWS STS returned invalid credential expiry".into()))?
        .with_timezone(&Utc);
    if expiration <= now || expiration > requested_expiry || expiration > now + Duration::hours(1) {
        return Err(AppError::NotAuthorized(
            "AWS STS returned an out-of-policy scanner credential lifetime".into(),
        ));
    }
    Ok(AwsRoleCredentials {
        access_key_id: Zeroizing::new(xml_first(xml, "AccessKeyId")?),
        secret_access_key: Zeroizing::new(xml_first(xml, "SecretAccessKey")?),
        session_token: Zeroizing::new(xml_first(xml, "SessionToken")?),
        expiration: expiration.timestamp_millis(),
    })
}

fn aws_form_body(mut fields: Vec<(String, String)>) -> Zeroizing<Vec<u8>> {
    fields.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Zeroizing::new(
        fields
            .into_iter()
            .map(|(key, value)| format!("{}={}", aws_query_encode(&key), aws_query_encode(&value)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes(),
    )
}

fn cloudformation_output(xml: &str, expected_key: &str) -> AppResult<String> {
    for member in xml.split("<member>").skip(1) {
        let member = member.split("</member>").next().unwrap_or_default();
        if xml_first(member, "OutputKey").ok().as_deref() == Some(expected_key) {
            return xml_first(member, "OutputValue");
        }
    }
    Err(AppError::NotAuthorized(format!(
        "AWS CloudFormation output {expected_key} is missing"
    )))
}

fn execute_azure(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    bootstrap: BootstrapRequest,
    authorization: MicrosoftNativeAuthorizationConfig,
    cleanup_ledger_path: &Path,
) -> AppResult<BootstrapExecutionResult> {
    use crate::source_authorization::ProviderSourceProfile;
    if authorization.profile != ProviderSourceProfile::AzureTenantReadOnlyAccessToken
        || authorization.subscription_id.is_none()
    {
        return Err(AppError::InvalidRequest(
            "Azure bootstrap requires the exact Azure provider profile and subscription".into(),
        ));
    }
    let subscription_id = authorization.subscription_id.clone().unwrap_or_default();
    let mut journal = BootstrapMutationLedger::new(
        &bootstrap.case_id,
        BootstrapMutationProviderContext::Azure {
            tenant_id: authorization.tenant_id.clone(),
            subscription_id: subscription_id.clone(),
        },
        interaction.now(),
    );
    journal.initialize(cleanup_ledger_path)?;
    let mut admin = microsoft_admin_device_authorization(
        http,
        interaction,
        &authorization,
        MicrosoftAdminPurpose::Azure,
    )?;
    let refresh_token = admin.refresh_token.take().ok_or_else(|| {
        AppError::NotAuthorized(
            "Microsoft public client did not issue the in-memory refresh token required for Azure bootstrap"
                .into(),
        )
    })?;
    let arm_token = microsoft_refresh_resource_token(
        http,
        &authorization,
        refresh_token,
        "https://management.azure.com/.default",
    )?;
    verify_azure_administrator_permissions(http, &arm_token.access_token, &subscription_id)?;

    let application = create_microsoft_application(
        http,
        &admin.graph_token,
        &bootstrap.scan_identity_name,
        bootstrap.expires_at,
        Vec::new(),
    )?;
    journal.record(
        cleanup_ledger_path,
        microsoft_cleanup_item(
            application.object_id.clone(),
            "DELETE",
            format!(
                "{MICROSOFT_GRAPH_ROOT}/applications/{}",
                application.object_id
            ),
            "Delete this exact application object",
        ),
    )?;
    let service_principal = create_microsoft_service_principal(
        http,
        &admin.graph_token,
        &application.application_client_id,
    )?;
    journal.record(
        cleanup_ledger_path,
        microsoft_cleanup_item(
            service_principal.object_id.clone(),
            "DELETE",
            format!(
                "{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{}",
                service_principal.object_id
            ),
            "Delete this exact service principal object",
        ),
    )?;
    verify_graph_service_principal(
        http,
        &admin.graph_token,
        &service_principal.object_id,
        &application.application_client_id,
    )?;
    let password = add_microsoft_temporary_password(
        http,
        &admin.graph_token,
        &application.object_id,
        bootstrap.expires_at,
    )?;
    journal.record(
        cleanup_ledger_path,
        microsoft_cleanup_item(
            password.key_id.clone(),
            "POST",
            format!(
                "{MICROSOFT_GRAPH_ROOT}/applications/{}/removePassword",
                application.object_id
            ),
            "Remove only this exact password key ID",
        ),
    )?;
    let reader_assignment_id = Uuid::new_v4().to_string();
    let security_reader_assignment_id = Uuid::new_v4().to_string();
    put_azure_role_assignment(
        http,
        &arm_token.access_token,
        &subscription_id,
        &reader_assignment_id,
        &service_principal.object_id,
        "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    )?;
    journal.record(
        cleanup_ledger_path,
        microsoft_cleanup_item(
            reader_assignment_id.clone(),
            "DELETE",
            format!("{MICROSOFT_ARM_ROOT}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments/{reader_assignment_id}?api-version=2022-04-01"),
            "Delete this exact Reader role assignment",
        ),
    )?;
    put_azure_role_assignment(
        http,
        &arm_token.access_token,
        &subscription_id,
        &security_reader_assignment_id,
        &service_principal.object_id,
        "39bc4728-0917-49c7-9d2c-d95423bc2eb4",
    )?;
    journal.record(
        cleanup_ledger_path,
        microsoft_cleanup_item(
            security_reader_assignment_id.clone(),
            "DELETE",
            format!("{MICROSOFT_ARM_ROOT}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments/{security_reader_assignment_id}?api-version=2022-04-01"),
            "Delete this exact Security Reader role assignment",
        ),
    )?;
    let scanner_token = microsoft_client_credentials_token(
        http,
        &authorization.tenant_id,
        &application.application_client_id,
        &password.secret_text,
        "https://management.azure.com/.default",
    )?;
    remove_microsoft_password(
        http,
        &admin.graph_token,
        &application.object_id,
        &password.key_id,
    )?;
    drop(password.secret_text);
    drop(arm_token);
    drop(admin);
    let admin_material_destroyed_at = interaction.now();

    let authorization_result = verify_bootstrap_azure_token(
        http,
        &authorization,
        service_principal.object_id.clone(),
        authorization.tenant_id.clone(),
        scanner_token.access_token,
        scanner_token.expires_in,
        interaction.now(),
    )?;
    let scanner_expiry = authorization_result.verification().credential_expires_at;
    let resources = CreatedBootstrapResources::Azure {
        tenant_id: authorization.tenant_id,
        subscription_id,
        application_object_id: application.object_id,
        application_client_id: application.application_client_id,
        service_principal_object_id: service_principal.object_id,
        reader_role_assignment_id: reader_assignment_id,
        security_reader_role_assignment_id: security_reader_assignment_id,
        temporary_password_key_id: password.key_id,
    };
    let cleanup_ledger = create_cleanup_ledger(
        &bootstrap.case_id,
        resources,
        scanner_expiry,
        admin_material_destroyed_at,
        interaction.now(),
    )?;
    super::write_cleanup_ledger(cleanup_ledger_path, &cleanup_ledger)?;
    Ok(BootstrapExecutionResult {
        authorization: authorization_result,
        cleanup_ledger,
    })
}

fn execute_gcp(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    bootstrap: BootstrapRequest,
    authorization: GcpNativeAuthorizationConfig,
    project_id: String,
    cleanup_ledger_path: &Path,
) -> AppResult<BootstrapExecutionResult> {
    validate_gcp_operator_config(&authorization, &project_id)?;
    let mut journal = BootstrapMutationLedger::new(
        &bootstrap.case_id,
        BootstrapMutationProviderContext::Gcp {
            organization_id: authorization.organization_id.clone(),
            project_id: project_id.clone(),
        },
        interaction.now(),
    );
    journal.initialize(cleanup_ledger_path)?;
    let admin = gcp_admin_pkce_authorization(http, interaction, &authorization)?;
    verify_gcp_administrator_permissions(
        http,
        &admin.access_token,
        &authorization.organization_id,
        &project_id,
    )?;
    let account_id = format!(
        "ai-security-scanner-{}",
        &hex::encode(Sha256::digest(bootstrap.case_id.as_bytes()))[..10]
    );
    let service_account = create_gcp_service_account(
        http,
        &admin.access_token,
        &project_id,
        &account_id,
        &bootstrap.scan_identity_name,
    )?;
    journal.record(
        cleanup_ledger_path,
        BootstrapMutationCleanupItem {
            exact_resource_id: service_account.unique_id.clone(),
            provider_api_method: "DELETE".into(),
            provider_api_endpoint: format!(
                "https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{}",
                service_account.email
            ),
            cleanup_semantics:
                "Delete this exact service account after removing its exact organization bindings"
                    .into(),
        },
    )?;
    verify_gcp_token_creator_permission(
        http,
        &admin.access_token,
        &project_id,
        &service_account.email,
    )?;
    let roles = gcp_read_only_roles();
    attach_gcp_organization_roles(
        http,
        &admin.access_token,
        &authorization.organization_id,
        &service_account.email,
        &roles,
    )?;
    for role in &roles {
        journal.record(
            cleanup_ledger_path,
            BootstrapMutationCleanupItem {
                exact_resource_id: format!(
                    "organizations/{}:serviceAccount:{}:{role}",
                    authorization.organization_id, service_account.email
                ),
                provider_api_method: "POST".into(),
                provider_api_endpoint: format!(
                    "https://cloudresourcemanager.googleapis.com/v3/organizations/{}:setIamPolicy",
                    authorization.organization_id
                ),
                cleanup_semantics: "Read the current etag, remove only this exact member from this exact unconditional role binding, and set the preserved policy".into(),
            },
        )?;
    }
    let scanner_token = generate_gcp_service_account_token(
        http,
        &admin.access_token,
        &service_account.email,
        bootstrap.expires_at,
        interaction.now(),
    )?;
    drop(admin);
    let admin_material_destroyed_at = interaction.now();
    let remaining = (scanner_token.expire_time - interaction.now()).num_seconds();
    if remaining <= 0 || remaining > 3600 {
        return Err(AppError::NotAuthorized(
            "Google returned an invalid scanner token expiry".into(),
        ));
    }
    let authorization_result = verify_bootstrap_gcp_token(
        http,
        &authorization,
        service_account.email.clone(),
        service_account.unique_id.clone(),
        scanner_token.access_token,
        u32::try_from(remaining).map_err(|_| {
            AppError::NotAuthorized("Google scanner token expiry overflowed".into())
        })?,
        interaction.now(),
    )?;
    let scanner_expiry = authorization_result.verification().credential_expires_at;
    let resources = CreatedBootstrapResources::Gcp {
        organization_id: authorization.organization_id,
        project_id,
        service_account_email: service_account.email,
        service_account_unique_id: service_account.unique_id,
        bound_role_names: roles,
        created_key_ids: Vec::new(),
    };
    let cleanup_ledger = create_cleanup_ledger(
        &bootstrap.case_id,
        resources,
        scanner_expiry,
        admin_material_destroyed_at,
        interaction.now(),
    )?;
    super::write_cleanup_ledger(cleanup_ledger_path, &cleanup_ledger)?;
    Ok(BootstrapExecutionResult {
        authorization: authorization_result,
        cleanup_ledger,
    })
}

struct GcpAdminSession {
    access_token: Zeroizing<String>,
}

impl fmt::Debug for GcpAdminSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GcpAdminSession([REDACTED])")
    }
}

fn validate_gcp_operator_config(
    config: &GcpNativeAuthorizationConfig,
    project_id: &str,
) -> AppResult<()> {
    if config.public_client_id.len() < 20
        || !config
            .public_client_id
            .ends_with(".apps.googleusercontent.com")
        || config
            .public_client_id
            .to_ascii_lowercase()
            .contains("example")
        || config.organization_id.is_empty()
        || !config
            .organization_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(AppError::InvalidRequest(
            "GCP bootstrap requires a real Desktop OAuth client and numeric organization ID".into(),
        ));
    }
    let redirect = Url::parse(&config.redirect_uri)
        .map_err(|_| AppError::InvalidRequest("GCP loopback redirect URI is invalid".into()))?;
    if redirect.scheme() != "http"
        || !matches!(
            redirect.host_str(),
            Some("127.0.0.1") | Some("::1") | Some("[::1]")
        )
        || redirect.port().is_none()
        || redirect.query().is_some()
        || redirect.fragment().is_some()
    {
        return Err(AppError::InvalidRequest(
            "GCP bootstrap requires an exact random-port loopback redirect URI".into(),
        ));
    }
    let project_valid = (6..=30).contains(&project_id.len())
        && project_id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && project_id
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && project_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !project_valid {
        return Err(AppError::InvalidRequest(
            "GCP bootstrap project ID is malformed".into(),
        ));
    }
    Ok(())
}

fn gcp_admin_pkce_authorization(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    config: &GcpNativeAuthorizationConfig,
) -> AppResult<GcpAdminSession> {
    let verifier_bytes = random_bytes::<48>()?;
    let state_bytes = random_bytes::<32>()?;
    let verifier = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes.as_slice()),
    );
    let state = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_bytes.as_slice()),
    );
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let scope = "openid email https://www.googleapis.com/auth/cloud-platform";
    let mut authorization_url = Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
        .map_err(|_| AppError::Internal("Google authorization endpoint is invalid".into()))?;
    authorization_url
        .query_pairs_mut()
        .append_pair("client_id", &config.public_client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", scope)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state.as_str())
        .append_pair("access_type", "online")
        .append_pair("include_granted_scopes", "false")
        .append_pair("prompt", "consent");
    let prompt = PkceAuthorizationPrompt {
        provider: BootstrapProvider::Gcp,
        authorization_url: authorization_url.into(),
        redirect_uri: config.redirect_uri.clone(),
        expires_at: interaction.now() + Duration::minutes(10),
        safety_notice: "Open only the accounts.google.com URL. The isolated broker uses a deployment-owned Desktop OAuth client and never accepts a Google password or client secret.".into(),
    };
    let callback = interaction.complete_pkce_authorization(&prompt)?;
    if interaction.now() >= prompt.expires_at
        || callback.returned_state.as_str() != state.as_str()
        || callback.authorization_code.is_empty()
        || callback.authorization_code.len() > 16 * 1024
    {
        return Err(AppError::NotAuthorized(
            "Google bootstrap PKCE callback is expired or has an invalid state binding".into(),
        ));
    }
    let token: BootstrapOAuthToken = execute_json(
        http,
        form_request(
            ProviderHttpMethod::Post,
            GOOGLE_TOKEN_ENDPOINT,
            &[
                ("client_id", config.public_client_id.as_str()),
                ("code", callback.authorization_code.as_str()),
                ("code_verifier", verifier.as_str()),
                ("grant_type", "authorization_code"),
                ("redirect_uri", config.redirect_uri.as_str()),
            ],
            Vec::new(),
        )?,
        &[200],
        "Google bootstrap PKCE token exchange",
    )?;
    require_bootstrap_token_lifetime(token.expires_in)?;
    if !token
        .scope
        .split_ascii_whitespace()
        .any(|granted| granted == "https://www.googleapis.com/auth/cloud-platform")
    {
        return Err(AppError::NotAuthorized(
            "Google administrator token is missing cloud-platform scope".into(),
        ));
    }
    #[derive(Deserialize)]
    struct UserInfo {
        sub: String,
        email: Option<String>,
    }
    let user: UserInfo = execute_json(
        http,
        bearer_get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            &token.access_token,
        )?,
        &[200],
        "Google bootstrap administrator identity",
    )?;
    if user.sub.is_empty()
        || user
            .email
            .as_deref()
            .is_none_or(|email| !email.contains('@'))
    {
        return Err(AppError::NotAuthorized(
            "Google returned an incomplete administrator identity".into(),
        ));
    }
    Ok(GcpAdminSession {
        access_token: token.access_token,
    })
}

#[derive(Deserialize)]
struct GcpTestIamPermissionsResponse {
    #[serde(default)]
    permissions: Vec<String>,
}

fn verify_gcp_administrator_permissions(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    organization_id: &str,
    project_id: &str,
) -> AppResult<()> {
    let organization_required = [
        "resourcemanager.organizations.getIamPolicy",
        "resourcemanager.organizations.setIamPolicy",
    ];
    let project_required = ["iam.serviceAccounts.create", "iam.serviceAccounts.delete"];
    verify_gcp_permissions_at(
        http,
        token,
        &format!(
            "https://cloudresourcemanager.googleapis.com/v3/organizations/{organization_id}:testIamPermissions"
        ),
        &organization_required,
        "Google organization bootstrap permission probe",
    )?;
    verify_gcp_permissions_at(
        http,
        token,
        &format!(
            "https://cloudresourcemanager.googleapis.com/v3/projects/{project_id}:testIamPermissions"
        ),
        &project_required,
        "Google project bootstrap permission probe",
    )
}

fn verify_gcp_permissions_at(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    endpoint: &str,
    required: &[&str],
    operation: &str,
) -> AppResult<()> {
    let response: GcpTestIamPermissionsResponse = execute_json(
        http,
        json_request(
            ProviderHttpMethod::Post,
            endpoint,
            &serde_json::json!({"permissions": required}),
            vec![bearer_header(token)],
        )?,
        &[200],
        operation,
    )?;
    let held = response.permissions.into_iter().collect::<BTreeSet<_>>();
    for permission in required {
        if !held.contains(*permission) {
            return Err(AppError::NotAuthorized(format!(
                "Google administrator cannot perform required bootstrap operation {permission}"
            )));
        }
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GcpServiceAccountCreate<'a> {
    account_id: &'a str,
    service_account: GcpServiceAccountDescription<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GcpServiceAccountDescription<'a> {
    display_name: &'a str,
    description: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpServiceAccountCreated {
    name: String,
    email: String,
    unique_id: String,
}

fn create_gcp_service_account(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    project_id: &str,
    account_id: &str,
    display_name: &str,
) -> AppResult<GcpServiceAccountCreated> {
    let endpoint = format!("https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts");
    let account: GcpServiceAccountCreated = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &endpoint,
            &GcpServiceAccountCreate {
                account_id,
                service_account: GcpServiceAccountDescription {
                    display_name,
                    description: "Temporary read-only ai-security-scanner assessment identity",
                },
            },
            vec![bearer_header(token)],
        )?,
        &[200],
        "Google dedicated service account creation",
    )?;
    let expected_email = format!("{account_id}@{project_id}.iam.gserviceaccount.com");
    if account.email != expected_email
        || account.unique_id.is_empty()
        || !account.unique_id.bytes().all(|byte| byte.is_ascii_digit())
        || !account
            .name
            .ends_with(&format!("/serviceAccounts/{expected_email}"))
    {
        return Err(AppError::NotAuthorized(
            "Google returned a different service account identity".into(),
        ));
    }
    Ok(account)
}

fn verify_gcp_token_creator_permission(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    project_id: &str,
    service_account_email: &str,
) -> AppResult<()> {
    let encoded_email: String =
        url::form_urlencoded::byte_serialize(service_account_email.as_bytes()).collect();
    verify_gcp_permissions_at(
        http,
        token,
        &format!(
            "https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{encoded_email}:testIamPermissions"
        ),
        &[
            "iam.serviceAccounts.get",
            "iam.serviceAccounts.getAccessToken",
        ],
        "Google service-account impersonation permission probe",
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpIamPolicy {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    bindings: Vec<GcpIamBinding>,
    etag: String,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GcpIamBinding {
    role: String,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    condition: Option<serde_json::Value>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GcpGetIamPolicyRequest {
    options: GcpGetIamPolicyOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GcpGetIamPolicyOptions {
    requested_policy_version: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GcpSetIamPolicyRequest<'a> {
    policy: &'a GcpIamPolicy,
    update_mask: &'static str,
}

fn attach_gcp_organization_roles(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    organization_id: &str,
    service_account_email: &str,
    roles: &[String],
) -> AppResult<()> {
    let get_endpoint = format!(
        "https://cloudresourcemanager.googleapis.com/v3/organizations/{organization_id}:getIamPolicy"
    );
    let mut policy: GcpIamPolicy = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &get_endpoint,
            &GcpGetIamPolicyRequest {
                options: GcpGetIamPolicyOptions {
                    requested_policy_version: 3,
                },
            },
            vec![bearer_header(token)],
        )?,
        &[200],
        "Google organization IAM policy read",
    )?;
    if policy.etag.is_empty() || policy.etag.len() > 4096 {
        return Err(AppError::NotAuthorized(
            "Google organization IAM policy is missing an etag".into(),
        ));
    }
    let member = format!("serviceAccount:{service_account_email}");
    for role in roles {
        if let Some(binding) = policy
            .bindings
            .iter_mut()
            .find(|binding| binding.role == *role && binding.condition.is_none())
        {
            if !binding.members.contains(&member) {
                binding.members.push(member.clone());
                binding.members.sort();
                binding.members.dedup();
            }
        } else {
            policy.bindings.push(GcpIamBinding {
                role: role.clone(),
                members: vec![member.clone()],
                condition: None,
                extra: BTreeMap::new(),
            });
        }
    }
    policy
        .bindings
        .sort_by(|left, right| left.role.cmp(&right.role));
    let set_endpoint = format!(
        "https://cloudresourcemanager.googleapis.com/v3/organizations/{organization_id}:setIamPolicy"
    );
    let response = http.execute(serializable_json_request(
        ProviderHttpMethod::Post,
        &set_endpoint,
        &GcpSetIamPolicyRequest {
            policy: &policy,
            update_mask: "bindings,etag",
        },
        vec![bearer_header(token)],
    )?)?;
    let returned: GcpIamPolicy =
        decode_success_json(&response, &[200], "Google organization IAM policy update")?;
    for role in roles {
        if !returned.bindings.iter().any(|binding| {
            binding.role == *role
                && binding.condition.is_none()
                && binding.members.contains(&member)
        }) {
            return Err(AppError::NotAuthorized(format!(
                "Google IAM policy did not retain exact scanner binding {role}"
            )));
        }
    }
    Ok(())
}

fn remove_gcp_organization_roles(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    organization_id: &str,
    service_account_email: &str,
    roles: &[String],
) -> AppResult<()> {
    let get_endpoint = format!(
        "https://cloudresourcemanager.googleapis.com/v3/organizations/{organization_id}:getIamPolicy"
    );
    let mut policy: GcpIamPolicy = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &get_endpoint,
            &GcpGetIamPolicyRequest {
                options: GcpGetIamPolicyOptions {
                    requested_policy_version: 3,
                },
            },
            vec![bearer_header(token)],
        )?,
        &[200],
        "Google cleanup organization IAM policy read",
    )?;
    if policy.etag.is_empty() || policy.etag.len() > 4096 {
        return Err(AppError::NotAuthorized(
            "Google cleanup IAM policy is missing an etag".into(),
        ));
    }
    let member = format!("serviceAccount:{service_account_email}");
    let roles = roles.iter().cloned().collect::<BTreeSet<_>>();
    let mut changed = false;
    for binding in &mut policy.bindings {
        if binding.condition.is_none() && roles.contains(&binding.role) {
            let before = binding.members.len();
            binding.members.retain(|candidate| candidate != &member);
            changed |= binding.members.len() != before;
        }
    }
    policy.bindings.retain(|binding| {
        !(binding.condition.is_none()
            && roles.contains(&binding.role)
            && binding.members.is_empty())
    });
    if !changed {
        return Ok(());
    }
    let set_endpoint = format!(
        "https://cloudresourcemanager.googleapis.com/v3/organizations/{organization_id}:setIamPolicy"
    );
    let returned: GcpIamPolicy = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &set_endpoint,
            &GcpSetIamPolicyRequest {
                policy: &policy,
                update_mask: "bindings,etag",
            },
            vec![bearer_header(token)],
        )?,
        &[200],
        "Google cleanup organization IAM policy update",
    )?;
    if returned.bindings.iter().any(|binding| {
        binding.condition.is_none()
            && roles.contains(&binding.role)
            && binding.members.contains(&member)
    }) {
        return Err(AppError::NotAuthorized(
            "Google cleanup IAM policy retained an exact scanner binding".into(),
        ));
    }
    Ok(())
}

fn gcp_read_only_roles() -> Vec<String> {
    [
        "roles/browser",
        "roles/iam.securityReviewer",
        "roles/cloudasset.viewer",
        "roles/logging.viewer",
        "roles/monitoring.viewer",
        "roles/serviceusage.serviceUsageViewer",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GcpGenerateAccessTokenRequest {
    delegates: Vec<String>,
    scope: Vec<String>,
    lifetime: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpGeneratedAccessToken {
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    access_token: Zeroizing<String>,
    expire_time: DateTime<Utc>,
}

fn generate_gcp_service_account_token(
    http: &dyn ProviderHttp,
    admin_token: &Zeroizing<String>,
    service_account_email: &str,
    requested_expiry: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<GcpGeneratedAccessToken> {
    let lifetime = (requested_expiry - now).num_seconds().clamp(1, 3600);
    let encoded_email: String =
        url::form_urlencoded::byte_serialize(service_account_email.as_bytes()).collect();
    let endpoint = format!(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{encoded_email}:generateAccessToken"
    );
    let token: GcpGeneratedAccessToken = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &endpoint,
            &GcpGenerateAccessTokenRequest {
                delegates: Vec::new(),
                scope: vec!["https://www.googleapis.com/auth/cloud-platform.read-only".into()],
                lifetime: format!("{lifetime}s"),
            },
            vec![bearer_header(admin_token)],
        )?,
        &[200],
        "Google dedicated service account token generation",
    )?;
    if token.access_token.is_empty()
        || token.access_token.len() > 128 * 1024
        || token.expire_time <= now
        || token.expire_time > requested_expiry
        || token.expire_time > now + Duration::hours(1)
    {
        return Err(AppError::NotAuthorized(
            "Google returned an invalid or longer-than-one-hour scanner token".into(),
        ));
    }
    Ok(token)
}

fn execute_microsoft365(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    bootstrap: BootstrapRequest,
    authorization: MicrosoftNativeAuthorizationConfig,
    cleanup_ledger_path: &Path,
) -> AppResult<BootstrapExecutionResult> {
    use crate::source_authorization::ProviderSourceProfile;
    if authorization.profile != ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken
        || authorization.subscription_id.is_some()
    {
        return Err(AppError::InvalidRequest(
            "Microsoft 365 bootstrap requires the exact Microsoft 365 provider profile".into(),
        ));
    }
    let mut journal = BootstrapMutationLedger::new(
        &bootstrap.case_id,
        BootstrapMutationProviderContext::Microsoft365 {
            tenant_id: authorization.tenant_id.clone(),
        },
        interaction.now(),
    );
    journal.initialize(cleanup_ledger_path)?;
    let admin = microsoft_admin_device_authorization(
        http,
        interaction,
        &authorization,
        MicrosoftAdminPurpose::Microsoft365,
    )?;
    let graph_resource = microsoft_graph_resource_service_principal(http, &admin.graph_token)?;
    let required_permissions = microsoft365_application_permissions();
    let role_ids = resolve_graph_app_role_ids(&graph_resource, &required_permissions)?;
    let required_resource_access = role_ids
        .values()
        .map(|id| MicrosoftRequiredResourceAccessEntry {
            id: id.clone(),
            access_type: "Role",
        })
        .collect::<Vec<_>>();
    let application = create_microsoft_application(
        http,
        &admin.graph_token,
        &bootstrap.scan_identity_name,
        bootstrap.expires_at,
        vec![MicrosoftRequiredResourceAccess {
            resource_app_id: "00000003-0000-0000-c000-000000000000".into(),
            resource_access: required_resource_access,
        }],
    )?;
    journal.record(
        cleanup_ledger_path,
        microsoft_cleanup_item(
            application.object_id.clone(),
            "DELETE",
            format!(
                "{MICROSOFT_GRAPH_ROOT}/applications/{}",
                application.object_id
            ),
            "Delete this exact application object",
        ),
    )?;
    let service_principal = create_microsoft_service_principal(
        http,
        &admin.graph_token,
        &application.application_client_id,
    )?;
    journal.record(
        cleanup_ledger_path,
        microsoft_cleanup_item(
            service_principal.object_id.clone(),
            "DELETE",
            format!(
                "{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{}",
                service_principal.object_id
            ),
            "Delete this exact service principal object",
        ),
    )?;
    verify_graph_service_principal(
        http,
        &admin.graph_token,
        &service_principal.object_id,
        &application.application_client_id,
    )?;
    let password = add_microsoft_temporary_password(
        http,
        &admin.graph_token,
        &application.object_id,
        bootstrap.expires_at,
    )?;
    journal.record(
        cleanup_ledger_path,
        microsoft_cleanup_item(
            password.key_id.clone(),
            "POST",
            format!(
                "{MICROSOFT_GRAPH_ROOT}/applications/{}/removePassword",
                application.object_id
            ),
            "Remove only this exact password key ID",
        ),
    )?;
    let mut assignment_ids = Vec::with_capacity(role_ids.len());
    for permission in &required_permissions {
        let role_id = role_ids.get(permission).ok_or_else(|| {
            AppError::NotAuthorized(format!(
                "Microsoft Graph resource is missing required application role {permission}"
            ))
        })?;
        let assignment_id = assign_microsoft_graph_app_role(
            http,
            &admin.graph_token,
            &service_principal.object_id,
            &graph_resource.id,
            role_id,
        )?;
        journal.record(
            cleanup_ledger_path,
            microsoft_cleanup_item(
                assignment_id.clone(),
                "DELETE",
                format!("{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{}/appRoleAssignments/{assignment_id}", service_principal.object_id),
                "Delete this exact Microsoft Graph app-role assignment",
            ),
        )?;
        assignment_ids.push(assignment_id);
    }
    let scanner_token = microsoft_client_credentials_token(
        http,
        &authorization.tenant_id,
        &application.application_client_id,
        &password.secret_text,
        "https://graph.microsoft.com/.default",
    )?;
    remove_microsoft_password(
        http,
        &admin.graph_token,
        &application.object_id,
        &password.key_id,
    )?;
    drop(password.secret_text);
    drop(admin);
    let admin_material_destroyed_at = interaction.now();
    let authorization_result = verify_bootstrap_microsoft365_token(
        http,
        &authorization,
        service_principal.object_id.clone(),
        authorization.tenant_id.clone(),
        scanner_token.access_token,
        scanner_token.expires_in,
        required_permissions,
        interaction.now(),
    )?;
    let scanner_expiry = authorization_result.verification().credential_expires_at;
    let resources = CreatedBootstrapResources::Microsoft365 {
        tenant_id: authorization.tenant_id,
        application_object_id: application.object_id,
        application_client_id: application.application_client_id,
        service_principal_object_id: service_principal.object_id,
        temporary_password_key_id: password.key_id,
        app_role_assignment_ids: assignment_ids,
        oauth_grant_ids: Vec::new(),
        directory_role_assignment_ids: Vec::new(),
    };
    let cleanup_ledger = create_cleanup_ledger(
        &bootstrap.case_id,
        resources,
        scanner_expiry,
        admin_material_destroyed_at,
        interaction.now(),
    )?;
    super::write_cleanup_ledger(cleanup_ledger_path, &cleanup_ledger)?;
    Ok(BootstrapExecutionResult {
        authorization: authorization_result,
        cleanup_ledger,
    })
}

#[derive(Clone, Copy)]
enum MicrosoftAdminPurpose {
    Azure,
    Microsoft365,
}

struct MicrosoftAdminSession {
    graph_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
}

impl fmt::Debug for MicrosoftAdminSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MicrosoftAdminSession([REDACTED])")
    }
}

#[derive(Deserialize)]
struct MicrosoftDeviceCodeResponse {
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    device_code: Zeroizing<String>,
    user_code: String,
    verification_uri: String,
    expires_in: u32,
    interval: u32,
}

#[derive(Deserialize)]
struct BootstrapOAuthToken {
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    access_token: Zeroizing<String>,
    expires_in: u32,
    #[serde(default)]
    scope: String,
    #[serde(default, deserialize_with = "deserialize_optional_zeroizing_string")]
    refresh_token: Option<Zeroizing<String>>,
}

impl fmt::Debug for BootstrapOAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapOAuthToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

fn microsoft_admin_device_authorization(
    http: &dyn ProviderHttp,
    interaction: &dyn BootstrapInteraction,
    config: &MicrosoftNativeAuthorizationConfig,
    purpose: MicrosoftAdminPurpose,
) -> AppResult<MicrosoftAdminSession> {
    validate_microsoft_operator_config(config)?;
    let required = match purpose {
        MicrosoftAdminPurpose::Azure => vec!["Application.ReadWrite.All", "Directory.Read.All"],
        MicrosoftAdminPurpose::Microsoft365 => vec![
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "Directory.Read.All",
        ],
    };
    let mut scopes = vec!["openid", "profile", "offline_access"];
    scopes.extend(required.iter().copied());
    let scope = scopes.join(" ");
    let device_endpoint = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode",
        config.tenant_id
    );
    let device: MicrosoftDeviceCodeResponse = execute_json(
        http,
        form_request(
            ProviderHttpMethod::Post,
            &device_endpoint,
            &[
                ("client_id", config.public_client_id.as_str()),
                ("scope", scope.as_str()),
            ],
            Vec::new(),
        )?,
        &[200],
        "Microsoft bootstrap device authorization",
    )?;
    if device.expires_in == 0
        || device.expires_in > 900
        || device.interval == 0
        || device.interval > 30
    {
        return Err(AppError::NotAuthorized(
            "Microsoft returned an unsafe bootstrap device authorization lifetime".into(),
        ));
    }
    let prompt = DeviceAuthorizationPrompt {
        provider: match purpose {
            MicrosoftAdminPurpose::Azure => BootstrapProvider::Azure,
            MicrosoftAdminPurpose::Microsoft365 => BootstrapProvider::Microsoft365,
        },
        verification_uri: device.verification_uri,
        verification_uri_complete: None,
        user_code: device.user_code,
        expires_at: interaction.now() + Duration::seconds(i64::from(device.expires_in)),
        poll_interval_seconds: u64::from(device.interval),
        safety_notice: "Sign in only at microsoft.com. The isolated broker uses a deployment-owned public client; no administrator password or client secret is accepted.".into(),
    };
    interaction.present_device_authorization(&prompt)?;
    let token_endpoint = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        config.tenant_id
    );
    let mut token = None;
    for _ in 0..MAX_POLL_ATTEMPTS {
        if interaction.now() >= prompt.expires_at {
            break;
        }
        let response = http.execute(form_request(
            ProviderHttpMethod::Post,
            &token_endpoint,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", config.public_client_id.as_str()),
                ("device_code", device.device_code.as_str()),
            ],
            Vec::new(),
        )?)?;
        if response.status == 400 && oauth_error(&response)? == "authorization_pending" {
            interaction.wait(prompt.poll_interval_seconds)?;
            continue;
        }
        token = Some(decode_success_json::<BootstrapOAuthToken>(
            &response,
            &[200],
            "Microsoft bootstrap device token exchange",
        )?);
        break;
    }
    let token = token.ok_or_else(|| {
        AppError::NotAuthorized(
            "Microsoft administrator did not complete device authorization in time".into(),
        )
    })?;
    require_bootstrap_token_lifetime(token.expires_in)?;
    let granted = token
        .scope
        .split_ascii_whitespace()
        .map(|scope| scope.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    for scope in required {
        if !granted.contains(&scope.to_ascii_lowercase()) {
            return Err(AppError::NotAuthorized(format!(
                "Microsoft administrator token is missing required bootstrap scope {scope}"
            )));
        }
    }
    let identity = microsoft_admin_identity(http, &token.access_token)?;
    if identity.tenant_id != config.tenant_id {
        return Err(AppError::NotAuthorized(
            "Microsoft administrator signed into a different tenant".into(),
        ));
    }
    let applications_endpoint =
        format!("{MICROSOFT_GRAPH_ROOT}/applications?%24top=1&%24select=id");
    let applications = http.execute(bearer_get(&applications_endpoint, &token.access_token)?)?;
    ensure_status(
        &applications,
        &[200],
        "Microsoft application administration permission probe",
    )?;
    Ok(MicrosoftAdminSession {
        graph_token: token.access_token,
        refresh_token: token.refresh_token,
    })
}

fn validate_microsoft_operator_config(
    config: &MicrosoftNativeAuthorizationConfig,
) -> AppResult<()> {
    if Uuid::parse_str(&config.tenant_id).is_err()
        || Uuid::parse_str(&config.public_client_id).is_err()
        || config.tenant_id == "00000000-0000-0000-0000-000000000000"
        || config.public_client_id == "00000000-0000-0000-0000-000000000000"
    {
        return Err(AppError::InvalidRequest(
            "Microsoft bootstrap requires a real tenant and deployment-owned public client ID"
                .into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct MicrosoftAdminIdentity {
    tenant_id: String,
}

#[derive(Deserialize)]
struct MicrosoftMeResponse {
    id: String,
}

#[derive(Deserialize)]
struct MicrosoftOrganizationsResponse {
    value: Vec<MicrosoftOrganizationResponse>,
}

#[derive(Deserialize)]
struct MicrosoftOrganizationResponse {
    id: String,
}

fn microsoft_admin_identity(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
) -> AppResult<MicrosoftAdminIdentity> {
    let me: MicrosoftMeResponse = execute_json(
        http,
        bearer_get(&format!("{MICROSOFT_GRAPH_ROOT}/me?%24select=id"), token)?,
        &[200],
        "Microsoft bootstrap administrator identity",
    )?;
    let organizations: MicrosoftOrganizationsResponse = execute_json(
        http,
        bearer_get(
            &format!("{MICROSOFT_GRAPH_ROOT}/organization?%24select=id"),
            token,
        )?,
        &[200],
        "Microsoft bootstrap tenant identity",
    )?;
    let tenant_id = organizations
        .value
        .into_iter()
        .next()
        .map(|organization| organization.id)
        .ok_or_else(|| {
            AppError::NotAuthorized("Microsoft returned no tenant organization".into())
        })?;
    if Uuid::parse_str(&me.id).is_err() || Uuid::parse_str(&tenant_id).is_err() {
        return Err(AppError::NotAuthorized(
            "Microsoft returned malformed administrator identity".into(),
        ));
    }
    Ok(MicrosoftAdminIdentity { tenant_id })
}

fn microsoft_refresh_resource_token(
    http: &dyn ProviderHttp,
    config: &MicrosoftNativeAuthorizationConfig,
    refresh_token: Zeroizing<String>,
    scope: &str,
) -> AppResult<BootstrapOAuthToken> {
    let endpoint = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        config.tenant_id
    );
    let token: BootstrapOAuthToken = execute_json(
        http,
        form_request(
            ProviderHttpMethod::Post,
            &endpoint,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", config.public_client_id.as_str()),
                ("refresh_token", refresh_token.as_str()),
                ("scope", scope),
            ],
            Vec::new(),
        )?,
        &[200],
        "Microsoft bootstrap resource token exchange",
    )?;
    drop(refresh_token);
    require_bootstrap_token_lifetime(token.expires_in)?;
    Ok(token)
}

#[derive(Deserialize)]
struct AzurePermissionsResponse {
    value: Vec<AzurePermission>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzurePermission {
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    not_actions: Vec<String>,
}

fn verify_azure_administrator_permissions(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    subscription_id: &str,
) -> AppResult<()> {
    if Uuid::parse_str(subscription_id).is_err() {
        return Err(AppError::InvalidRequest(
            "Azure subscription identifier is malformed".into(),
        ));
    }
    let endpoint = format!(
        "{MICROSOFT_ARM_ROOT}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    );
    let permissions: AzurePermissionsResponse = execute_json(
        http,
        bearer_get(&endpoint, token)?,
        &[200],
        "Azure bootstrap administrator permission probe",
    )?;
    let required = [
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleAssignments/delete",
    ];
    for action in required {
        let allowed = permissions.value.iter().any(|permission| {
            permission
                .actions
                .iter()
                .any(|pattern| azure_action_matches(pattern, action))
                && !permission
                    .not_actions
                    .iter()
                    .any(|pattern| azure_action_matches(pattern, action))
        });
        if !allowed {
            return Err(AppError::NotAuthorized(format!(
                "Azure administrator cannot perform required bootstrap operation {action}"
            )));
        }
    }
    Ok(())
}

fn azure_action_matches(pattern: &str, action: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let action = action.to_ascii_lowercase();
    pattern == "*"
        || pattern == action
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| action.starts_with(prefix))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftApplicationCreate<'a> {
    display_name: &'a str,
    sign_in_audience: &'static str,
    required_resource_access: Vec<MicrosoftRequiredResourceAccess>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftRequiredResourceAccess {
    resource_app_id: String,
    resource_access: Vec<MicrosoftRequiredResourceAccessEntry>,
}

#[derive(Serialize)]
struct MicrosoftRequiredResourceAccessEntry {
    id: String,
    #[serde(rename = "type")]
    access_type: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftApplicationCreated {
    id: String,
    app_id: String,
}

struct MicrosoftApplicationIdentity {
    object_id: String,
    application_client_id: String,
}

fn create_microsoft_application(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    display_name: &str,
    _expires_at: DateTime<Utc>,
    required_resource_access: Vec<MicrosoftRequiredResourceAccess>,
) -> AppResult<MicrosoftApplicationIdentity> {
    let body = MicrosoftApplicationCreate {
        display_name,
        sign_in_audience: "AzureADMyOrg",
        required_resource_access,
    };
    let created: MicrosoftApplicationCreated = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &format!("{MICROSOFT_GRAPH_ROOT}/applications"),
            &body,
            vec![bearer_header(token)],
        )?,
        &[201],
        "Microsoft dedicated application creation",
    )?;
    if Uuid::parse_str(&created.id).is_err() || Uuid::parse_str(&created.app_id).is_err() {
        return Err(AppError::NotAuthorized(
            "Microsoft returned malformed application identifiers".into(),
        ));
    }
    Ok(MicrosoftApplicationIdentity {
        object_id: created.id,
        application_client_id: created.app_id,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftServicePrincipalCreate<'a> {
    app_id: &'a str,
    account_enabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftServicePrincipalCreated {
    id: String,
    app_id: String,
}

struct MicrosoftServicePrincipalIdentity {
    object_id: String,
}

fn create_microsoft_service_principal(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    application_client_id: &str,
) -> AppResult<MicrosoftServicePrincipalIdentity> {
    let created: MicrosoftServicePrincipalCreated = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &format!("{MICROSOFT_GRAPH_ROOT}/servicePrincipals"),
            &MicrosoftServicePrincipalCreate {
                app_id: application_client_id,
                account_enabled: true,
            },
            vec![bearer_header(token)],
        )?,
        &[201],
        "Microsoft dedicated service principal creation",
    )?;
    if Uuid::parse_str(&created.id).is_err() || created.app_id != application_client_id {
        return Err(AppError::NotAuthorized(
            "Microsoft returned a different service principal identity".into(),
        ));
    }
    Ok(MicrosoftServicePrincipalIdentity {
        object_id: created.id,
    })
}

fn verify_graph_service_principal(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    principal_id: &str,
    application_client_id: &str,
) -> AppResult<()> {
    let endpoint =
        format!("{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{principal_id}?%24select=id,appId");
    let principal: MicrosoftServicePrincipalCreated = execute_json(
        http,
        bearer_get(&endpoint, token)?,
        &[200],
        "Microsoft dedicated service principal identity verification",
    )?;
    if principal.id != principal_id || principal.app_id != application_client_id {
        return Err(AppError::NotAuthorized(
            "Microsoft service principal identity changed after creation".into(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftAddPassword<'a> {
    password_credential: MicrosoftPasswordCredential<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftPasswordCredential<'a> {
    display_name: &'static str,
    end_date_time: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftPasswordCreated {
    key_id: String,
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    secret_text: Zeroizing<String>,
}

fn add_microsoft_temporary_password(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    application_object_id: &str,
    expires_at: DateTime<Utc>,
) -> AppResult<MicrosoftPasswordCreated> {
    let end_date_time = expires_at.to_rfc3339();
    let password: MicrosoftPasswordCreated = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &format!("{MICROSOFT_GRAPH_ROOT}/applications/{application_object_id}/addPassword"),
            &MicrosoftAddPassword {
                password_credential: MicrosoftPasswordCredential {
                    display_name: "ai-security-scanner-one-shot",
                    end_date_time: &end_date_time,
                },
            },
            vec![bearer_header(token)],
        )?,
        &[200],
        "Microsoft temporary application password creation",
    )?;
    if Uuid::parse_str(&password.key_id).is_err()
        || password.secret_text.is_empty()
        || password.secret_text.len() > 32 * 1024
    {
        return Err(AppError::NotAuthorized(
            "Microsoft returned an invalid temporary application password".into(),
        ));
    }
    Ok(password)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftRemovePassword<'a> {
    key_id: &'a str,
}

fn remove_microsoft_password(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    application_object_id: &str,
    key_id: &str,
) -> AppResult<()> {
    let response = http.execute(serializable_json_request(
        ProviderHttpMethod::Post,
        &format!("{MICROSOFT_GRAPH_ROOT}/applications/{application_object_id}/removePassword"),
        &MicrosoftRemovePassword { key_id },
        vec![bearer_header(token)],
    )?)?;
    ensure_status(
        &response,
        &[204],
        "Microsoft temporary application password removal",
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AzureRoleAssignmentCreate<'a> {
    properties: AzureRoleAssignmentPropertiesCreate<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AzureRoleAssignmentPropertiesCreate<'a> {
    role_definition_id: String,
    principal_id: &'a str,
    principal_type: &'static str,
}

fn put_azure_role_assignment(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    subscription_id: &str,
    assignment_id: &str,
    principal_id: &str,
    role_definition_id: &str,
) -> AppResult<()> {
    let endpoint = format!(
        "{MICROSOFT_ARM_ROOT}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}?api-version=2022-04-01"
    );
    let response = http.execute(serializable_json_request(
        ProviderHttpMethod::Put,
        &endpoint,
        &AzureRoleAssignmentCreate {
            properties: AzureRoleAssignmentPropertiesCreate {
                role_definition_id: format!(
                    "/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_definition_id}"
                ),
                principal_id,
                principal_type: "ServicePrincipal",
            },
        },
        vec![bearer_header(token)],
    )?)?;
    ensure_status(
        &response,
        &[200, 201],
        "Azure exact read-only role assignment",
    )
}

fn microsoft_client_credentials_token(
    http: &dyn ProviderHttp,
    tenant_id: &str,
    client_id: &str,
    client_secret: &Zeroizing<String>,
    scope: &str,
) -> AppResult<BootstrapOAuthToken> {
    let endpoint = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let token: BootstrapOAuthToken = execute_json(
        http,
        form_request(
            ProviderHttpMethod::Post,
            &endpoint,
            &[
                ("client_id", client_id),
                ("client_secret", client_secret.as_str()),
                ("grant_type", "client_credentials"),
                ("scope", scope),
            ],
            Vec::new(),
        )?,
        &[200],
        "Microsoft dedicated scanner token exchange",
    )?;
    require_bootstrap_token_lifetime(token.expires_in)?;
    Ok(token)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftGraphResourceServicePrincipal {
    id: String,
    app_id: String,
    app_roles: Vec<MicrosoftGraphAppRole>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftGraphAppRole {
    id: String,
    value: Option<String>,
    is_enabled: bool,
    #[serde(default)]
    allowed_member_types: Vec<String>,
}

fn microsoft_graph_resource_service_principal(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
) -> AppResult<MicrosoftGraphResourceServicePrincipal> {
    #[derive(Deserialize)]
    struct ListResponse {
        value: Vec<MicrosoftGraphResourceServicePrincipal>,
    }
    let endpoint = format!(
        "{MICROSOFT_GRAPH_ROOT}/servicePrincipals?%24filter=appId%20eq%20%2700000003-0000-0000-c000-000000000000%27&%24select=id,appId,appRoles"
    );
    let response: ListResponse = execute_json(
        http,
        bearer_get(&endpoint, token)?,
        &[200],
        "Microsoft Graph resource application role discovery",
    )?;
    let resource = response.value.into_iter().next().ok_or_else(|| {
        AppError::NotAuthorized("Microsoft Graph resource service principal is missing".into())
    })?;
    if resource.app_id != "00000003-0000-0000-c000-000000000000"
        || Uuid::parse_str(&resource.id).is_err()
    {
        return Err(AppError::NotAuthorized(
            "Microsoft Graph returned a different resource service principal".into(),
        ));
    }
    Ok(resource)
}

fn resolve_graph_app_role_ids(
    resource: &MicrosoftGraphResourceServicePrincipal,
    required: &[String],
) -> AppResult<BTreeMap<String, String>> {
    let mut resolved = BTreeMap::new();
    for role in &resource.app_roles {
        let Some(value) = &role.value else { continue };
        if role.is_enabled
            && role
                .allowed_member_types
                .iter()
                .any(|member_type| member_type == "Application")
            && required.contains(value)
            && (Uuid::parse_str(&role.id).is_err()
                || resolved.insert(value.clone(), role.id.clone()).is_some())
        {
            return Err(AppError::NotAuthorized(
                "Microsoft Graph returned ambiguous application role identifiers".into(),
            ));
        }
    }
    if resolved.len() != required.len() {
        return Err(AppError::NotAuthorized(
            "Microsoft Graph resource is missing one or more pinned read-only application roles"
                .into(),
        ));
    }
    Ok(resolved)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftAppRoleAssignmentCreate<'a> {
    principal_id: &'a str,
    resource_id: &'a str,
    app_role_id: &'a str,
}

#[derive(Deserialize)]
struct MicrosoftAppRoleAssignmentCreated {
    id: String,
}

fn assign_microsoft_graph_app_role(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    service_principal_id: &str,
    graph_resource_principal_id: &str,
    app_role_id: &str,
) -> AppResult<String> {
    let created: MicrosoftAppRoleAssignmentCreated = execute_json(
        http,
        serializable_json_request(
            ProviderHttpMethod::Post,
            &format!(
                "{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{service_principal_id}/appRoleAssignments"
            ),
            &MicrosoftAppRoleAssignmentCreate {
                principal_id: service_principal_id,
                resource_id: graph_resource_principal_id,
                app_role_id,
            },
            vec![bearer_header(token)],
        )?,
        &[201],
        "Microsoft Graph exact read-only application role assignment",
    )?;
    if created.id.is_empty() || created.id.len() > 2048 || created.id.chars().any(char::is_control)
    {
        return Err(AppError::NotAuthorized(
            "Microsoft Graph returned an invalid app-role assignment identifier".into(),
        ));
    }
    Ok(created.id)
}

fn microsoft365_application_permissions() -> Vec<String> {
    [
        "AdministrativeUnit.Read.All",
        "Application.Read.All",
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Domain.Read.All",
        "Group.Read.All",
        "IdentityRiskEvent.Read.All",
        "Organization.Read.All",
        "Policy.Read.All",
        "Reports.Read.All",
        "RoleManagement.Read.Directory",
        "SecurityEvents.Read.All",
        "User.Read.All",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn require_bootstrap_token_lifetime(expires_in: u32) -> AppResult<()> {
    if expires_in == 0 || expires_in > 3600 {
        return Err(AppError::NotAuthorized(
            "provider issued an invalid or longer-than-one-hour bootstrap token".into(),
        ));
    }
    Ok(())
}

fn microsoft_cleanup_item(
    exact_resource_id: String,
    method: &str,
    endpoint: String,
    semantics: &str,
) -> BootstrapMutationCleanupItem {
    BootstrapMutationCleanupItem {
        exact_resource_id,
        provider_api_method: method.into(),
        provider_api_endpoint: endpoint,
        cleanup_semantics: semantics.into(),
    }
}

fn write_secret_free_atomic_json<T: Serialize>(path: &Path, value: &T) -> AppResult<()> {
    let parent = path.parent().ok_or_else(|| {
        AppError::InvalidRequest("bootstrap cleanup ledger path has no parent directory".into())
    })?;
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent)?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            AppError::InvalidRequest("bootstrap cleanup ledger filename is invalid".into())
        })?;
    if filename.is_empty() || filename.contains('/') || filename.contains('\\') {
        return Err(AppError::InvalidRequest(
            "bootstrap cleanup ledger filename is invalid".into(),
        ));
    }
    let destination = parent.join(filename);
    if fs::symlink_metadata(&destination).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(AppError::InvalidRequest(
            "bootstrap cleanup ledger destination must not be a symlink".into(),
        ));
    }
    let temporary = parent.join(format!(
        ".{filename}.{}.{}.tmp",
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let encoded = serde_json::to_vec_pretty(value)
        .map_err(|_| AppError::Internal("bootstrap cleanup ledger could not be encoded".into()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &destination)?;
    Ok(())
}

fn deserialize_zeroizing_string<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn deserialize_optional_zeroizing_string<'de, D>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_authorization::provider::{ProviderHttpRequest, ProviderHttpResponse};
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct PolicyFixture {
        responses: Mutex<Vec<ProviderHttpResponse>>,
        request_bodies: Mutex<Vec<serde_json::Value>>,
    }

    impl PolicyFixture {
        fn new(responses: Vec<ProviderHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().rev().collect()),
                request_bodies: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProviderHttp for PolicyFixture {
        fn execute(&self, request: ProviderHttpRequest) -> AppResult<ProviderHttpResponse> {
            if !request.sensitive_body().is_empty() {
                let body = serde_json::from_slice(request.sensitive_body())
                    .map_err(|_| AppError::Internal("fixture request was not JSON".into()))?;
                self.request_bodies.lock().unwrap().push(body);
            }
            self.responses
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| AppError::Internal("fixture response queue exhausted".into()))
        }
    }

    struct NoInteraction(DateTime<Utc>);

    impl BootstrapInteraction for NoInteraction {
        fn present_device_authorization(
            &self,
            _prompt: &DeviceAuthorizationPrompt,
        ) -> AppResult<()> {
            Err(AppError::Internal(
                "empty cleanup must not request provider authorization".into(),
            ))
        }

        fn complete_pkce_authorization(
            &self,
            _prompt: &PkceAuthorizationPrompt,
        ) -> AppResult<PkceAuthorizationCallback> {
            Err(AppError::Internal(
                "empty cleanup must not request PKCE authorization".into(),
            ))
        }

        fn wait(&self, _seconds: u64) -> AppResult<()> {
            Err(AppError::Internal("empty cleanup must not wait".into()))
        }

        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[test]
    fn broker_execution_schema_has_no_secret_input_fields() {
        let value = json!({
            "operation":"execute",
            "execution":{
                "schema_version":"1.0.0",
                "bootstrap":{
                    "schema_version":"1.0.0",
                    "case_id":"case-1",
                    "provider":"azure",
                    "scan_identity_name":"ai-security-scanner-case-1",
                    "capabilities":["inventory"],
                    "expires_at":"2099-01-01T00:00:00Z"
                },
                "operator":{
                    "provider":"azure",
                    "authorization":{
                        "tenant_id":"11111111-1111-4111-8111-111111111111",
                        "public_client_id":"22222222-2222-4222-8222-222222222222",
                        "profile":"azure_tenant_read_only_access_token",
                        "subscription_id":"33333333-3333-4333-8333-333333333333",
                        "client_secret":"must-never-enter-broker-json"
                    }
                }
            },
            "cleanup_ledger_path":"/tmp/cleanup.json"
        });
        assert!(serde_json::from_value::<BootstrapBrokerCommand>(value).is_err());
    }

    #[test]
    fn partial_journal_is_exact_secret_free_and_user_only() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("cleanup.json");
        let mut ledger = BootstrapMutationLedger::new(
            "case-1",
            BootstrapMutationProviderContext::Aws {
                account_id: "123456789012".into(),
                region: "us-east-1".into(),
            },
            Utc::now(),
        );
        ledger.initialize(&path).unwrap();
        ledger
            .record(
                &path,
                BootstrapMutationCleanupItem {
                    exact_resource_id: "arn:aws:cloudformation:us-east-1:123456789012:stack/exact/id".into(),
                    provider_api_method: "POST".into(),
                    provider_api_endpoint: "https://cloudformation.us-east-1.amazonaws.com/?Action=DeleteStack&StackName=exact&Version=2010-05-15".into(),
                    cleanup_semantics: "delete exact stack".into(),
                },
            )
            .unwrap();
        let encoded = fs::read_to_string(&path).unwrap();
        assert!(encoded.contains("stack/exact/id"));
        assert!(!encoded.to_ascii_lowercase().contains("token"));
        assert!(!encoded.to_ascii_lowercase().contains("secret"));
        assert!(
            ledger
                .record(
                    &path,
                    BootstrapMutationCleanupItem {
                        exact_resource_id: "*".into(),
                        provider_api_method: "DELETE".into(),
                        provider_api_endpoint: "https://example.invalid/*".into(),
                        cleanup_semantics: "unsafe".into(),
                    },
                )
                .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn gcp_policy_update_preserves_etag_conditions_and_unknown_fields() {
        let policy = json!({
            "version":3,
            "etag":"BwYFIo=",
            "bindings":[
                {
                    "role":"roles/browser",
                    "members":["user:owner@example.com"],
                    "condition":{"title":"keep","expression":"request.time < timestamp('2099-01-01T00:00:00Z')"}
                }
            ],
            "auditConfigs":[{"service":"allServices"}]
        });
        let returned = json!({
            "version":3,
            "etag":"BwYFIp=",
            "bindings":[
                {
                    "role":"roles/browser",
                    "members":["user:owner@example.com"],
                    "condition":{"title":"keep","expression":"request.time < timestamp('2099-01-01T00:00:00Z')"}
                },
                {
                    "role":"roles/browser",
                    "members":["serviceAccount:scan@fixture.iam.gserviceaccount.com"]
                }
            ],
            "auditConfigs":[{"service":"allServices"}]
        });
        let fixture = PolicyFixture::new(vec![
            ProviderHttpResponse::new(200, serde_json::to_vec(&policy).unwrap()),
            ProviderHttpResponse::new(200, serde_json::to_vec(&returned).unwrap()),
        ]);
        attach_gcp_organization_roles(
            &fixture,
            &Zeroizing::new("admin-token".into()),
            "123456789012",
            "scan@fixture.iam.gserviceaccount.com",
            &["roles/browser".into()],
        )
        .unwrap();
        let bodies = fixture.request_bodies.lock().unwrap();
        let set = bodies.last().unwrap();
        assert_eq!(set["policy"]["etag"], "BwYFIo=");
        assert_eq!(set["policy"]["auditConfigs"][0]["service"], "allServices");
        assert_eq!(set["updateMask"], "bindings,etag");
        assert_eq!(set["policy"]["bindings"][0]["condition"]["title"], "keep");
    }

    #[test]
    fn microsoft_app_roles_are_dynamic_exact_and_application_only() {
        let required = vec!["Directory.Read.All".into(), "Policy.Read.All".into()];
        let resource = MicrosoftGraphResourceServicePrincipal {
            id: Uuid::new_v4().to_string(),
            app_id: "00000003-0000-0000-c000-000000000000".into(),
            app_roles: vec![
                MicrosoftGraphAppRole {
                    id: Uuid::new_v4().to_string(),
                    value: Some("Directory.Read.All".into()),
                    is_enabled: true,
                    allowed_member_types: vec!["Application".into()],
                },
                MicrosoftGraphAppRole {
                    id: Uuid::new_v4().to_string(),
                    value: Some("Policy.Read.All".into()),
                    is_enabled: true,
                    allowed_member_types: vec!["Application".into()],
                },
                MicrosoftGraphAppRole {
                    id: Uuid::new_v4().to_string(),
                    value: Some("Directory.ReadWrite.All".into()),
                    is_enabled: true,
                    allowed_member_types: vec!["Application".into()],
                },
            ],
        };
        let resolved = resolve_graph_app_role_ids(&resource, &required).unwrap();
        assert_eq!(
            resolved.keys().cloned().collect::<BTreeSet<_>>(),
            required.into_iter().collect()
        );
        assert!(!resolved.contains_key("Directory.ReadWrite.All"));
    }

    #[test]
    fn azure_admin_action_matching_is_bounded_to_provider_patterns() {
        assert!(azure_action_matches(
            "Microsoft.Authorization/roleAssignments/*",
            "Microsoft.Authorization/roleAssignments/write"
        ));
        assert!(azure_action_matches(
            "*",
            "Microsoft.Authorization/roleAssignments/delete"
        ));
        assert!(!azure_action_matches(
            "Microsoft.Resources/deployments/*",
            "Microsoft.Authorization/roleAssignments/write"
        ));
    }

    fn partial_fixture_items(provider: BootstrapProvider) -> Vec<BootstrapMutationCleanupItem> {
        let application = "11111111-1111-4111-8111-111111111111";
        let principal = "22222222-2222-4222-8222-222222222222";
        let password = "33333333-3333-4333-8333-333333333333";
        match provider {
            BootstrapProvider::Aws => vec![BootstrapMutationCleanupItem {
                exact_resource_id: "arn:aws:cloudformation:us-east-1:123456789012:stack/exact-stack/44444444-4444-4444-8444-444444444444".into(),
                provider_api_method: "POST".into(),
                provider_api_endpoint: "https://cloudformation.us-east-1.amazonaws.com/?Action=DeleteStack&StackName=exact-stack&Version=2010-05-15".into(),
                cleanup_semantics: "delete this exact stack".into(),
            }],
            BootstrapProvider::Azure => vec![
                microsoft_cleanup_item(
                    application.into(),
                    "DELETE",
                    format!("{MICROSOFT_GRAPH_ROOT}/applications/{application}"),
                    "delete exact application",
                ),
                microsoft_cleanup_item(
                    principal.into(),
                    "DELETE",
                    format!("{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{principal}"),
                    "delete exact principal",
                ),
                microsoft_cleanup_item(
                    password.into(),
                    "POST",
                    format!("{MICROSOFT_GRAPH_ROOT}/applications/{application}/removePassword"),
                    "remove exact password",
                ),
                microsoft_cleanup_item(
                    "55555555-5555-4555-8555-555555555555".into(),
                    "DELETE",
                    format!(
                        "{MICROSOFT_ARM_ROOT}/subscriptions/66666666-6666-4666-8666-666666666666/providers/Microsoft.Authorization/roleAssignments/55555555-5555-4555-8555-555555555555?api-version=2022-04-01"
                    ),
                    "delete exact assignment",
                ),
            ],
            BootstrapProvider::Microsoft365 => vec![
                microsoft_cleanup_item(
                    application.into(),
                    "DELETE",
                    format!("{MICROSOFT_GRAPH_ROOT}/applications/{application}"),
                    "delete exact application",
                ),
                microsoft_cleanup_item(
                    principal.into(),
                    "DELETE",
                    format!("{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{principal}"),
                    "delete exact principal",
                ),
                microsoft_cleanup_item(
                    password.into(),
                    "POST",
                    format!("{MICROSOFT_GRAPH_ROOT}/applications/{application}/removePassword"),
                    "remove exact password",
                ),
                microsoft_cleanup_item(
                    "77777777-7777-4777-8777-777777777777".into(),
                    "DELETE",
                    format!(
                        "{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{principal}/appRoleAssignments/77777777-7777-4777-8777-777777777777"
                    ),
                    "delete exact app role",
                ),
            ],
            BootstrapProvider::Gcp => vec![
                BootstrapMutationCleanupItem {
                    exact_resource_id: "123456789012345678901".into(),
                    provider_api_method: "DELETE".into(),
                    provider_api_endpoint: "https://iam.googleapis.com/v1/projects/scanner1/serviceAccounts/scanner1@scanner1.iam.gserviceaccount.com".into(),
                    cleanup_semantics: "delete exact service account".into(),
                },
                BootstrapMutationCleanupItem {
                    exact_resource_id: "organizations/987654321012:serviceAccount:scanner1@scanner1.iam.gserviceaccount.com:roles/browser".into(),
                    provider_api_method: "POST".into(),
                    provider_api_endpoint: "https://cloudresourcemanager.googleapis.com/v3/organizations/987654321012:setIamPolicy".into(),
                    cleanup_semantics: "remove exact unconditional binding member".into(),
                },
            ],
        }
    }

    fn write_partial_fixture(path: &Path, provider: BootstrapProvider) -> BootstrapMutationLedger {
        let provider_context = match provider {
            BootstrapProvider::Aws => BootstrapMutationProviderContext::Aws {
                account_id: "123456789012".into(),
                region: "us-east-1".into(),
            },
            BootstrapProvider::Azure => BootstrapMutationProviderContext::Azure {
                tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                subscription_id: "66666666-6666-4666-8666-666666666666".into(),
            },
            BootstrapProvider::Gcp => BootstrapMutationProviderContext::Gcp {
                organization_id: "987654321012".into(),
                project_id: "scanner1".into(),
            },
            BootstrapProvider::Microsoft365 => BootstrapMutationProviderContext::Microsoft365 {
                tenant_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            },
        };
        let mut ledger = BootstrapMutationLedger::new("case-1", provider_context, Utc::now());
        ledger.initialize(path).unwrap();
        for item in partial_fixture_items(provider) {
            ledger.record(path, item).unwrap();
        }
        validate_partial_mutation_ledger(&ledger).unwrap();
        ledger
    }

    #[test]
    fn every_provider_partial_journal_survives_interruption_retry_and_completion() {
        let directory = tempdir().unwrap();
        for (index, provider) in [
            BootstrapProvider::Aws,
            BootstrapProvider::Azure,
            BootstrapProvider::Gcp,
            BootstrapProvider::Microsoft365,
        ]
        .into_iter()
        .enumerate()
        {
            let operation_id = format!("provider-{index}");
            let path = directory
                .path()
                .join(format!("cleanup-{operation_id}.json"));
            let mut ledger = write_partial_fixture(&path, provider);
            initialize_partial_recovery(&mut ledger, &path, Utc::now()).unwrap();

            let first_item = ledger.items[0].clone();
            record_partial_attempt_start(&mut ledger, &path, &first_item, Utc::now()).unwrap();
            let attempting =
                bootstrap_cleanup_obligation_summary(&path, "case-1", &operation_id).unwrap();
            assert_eq!(attempting.status, BootstrapCleanupStatus::InProgress);

            record_partial_attempt_result(
                &mut ledger,
                &path,
                &first_item,
                CleanupAttemptOutcome::RetryableFailure,
                "provider_error",
                Utc::now(),
            )
            .unwrap();

            // Simulate an application restart by discarding the in-memory
            // value and reparsing only the bounded durable file.
            ledger = match read_cleanup_document(&path, "case-1").unwrap() {
                CleanupDocument::Partial(ledger) => ledger,
                CleanupDocument::Complete(_) => panic!("expected partial ledger"),
            };
            assert_eq!(ledger.recovery.items[0].attempts, 1);
            for item in ledger.items.clone() {
                if partial_item_is_completed(&ledger, &item).unwrap() {
                    continue;
                }
                record_partial_attempt_start(&mut ledger, &path, &item, Utc::now()).unwrap();
                record_partial_attempt_result(
                    &mut ledger,
                    &path,
                    &item,
                    CleanupAttemptOutcome::Succeeded,
                    "succeeded",
                    Utc::now(),
                )
                .unwrap();
            }
            let completed =
                bootstrap_cleanup_obligation_summary(&path, "case-1", &operation_id).unwrap();
            assert_eq!(completed.status, BootstrapCleanupStatus::Completed);
            assert_eq!(completed.completed_items, completed.total_items);
            assert!(completed.total_items > 0);
        }
        let summaries = list_bootstrap_cleanup_obligations(directory.path(), "case-1").unwrap();
        assert_eq!(summaries.len(), 4);
        assert!(
            summaries
                .iter()
                .all(|summary| summary.status == BootstrapCleanupStatus::Completed)
        );
        let encoded = serde_json::to_string(&summaries).unwrap();
        assert!(!encoded.contains("exact_resource_id"));
        assert!(!encoded.contains("provider_api_endpoint"));
    }

    #[test]
    fn partial_journal_tamper_fails_closed_even_with_recomputed_integrity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("cleanup-tamper.json");
        let mut ledger = write_partial_fixture(&path, BootstrapProvider::Aws);

        ledger.items[0].provider_api_endpoint =
            "https://cloudformation.us-east-1.amazonaws.com/?Action=DeleteStack&StackName=other&Version=2010-05-15".into();
        assert!(validate_partial_mutation_ledger(&ledger).is_err());

        // A plain checksum is not treated as authority: even if a local
        // modifier recomputes it, the provider-specific exact grammar wins.
        ledger.immutable_sha256 = ledger.derive_immutable_sha256().unwrap();
        write_secret_free_atomic_json(&path, &ledger).unwrap();
        assert!(bootstrap_cleanup_obligation_summary(&path, "case-1", "tamper").is_err());

        let mut microsoft = BootstrapMutationLedger::new(
            "case-1",
            BootstrapMutationProviderContext::Microsoft365 {
                tenant_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            },
            Utc::now(),
        );
        let orphan_assignment = partial_fixture_items(BootstrapProvider::Microsoft365)
            .pop()
            .unwrap();
        assert!(microsoft.record(&path, orphan_assignment).is_err());
    }

    #[test]
    fn cleanup_listing_rejects_wrong_names_symlinks_and_oversized_files() {
        let wrong_name = tempdir().unwrap();
        fs::write(wrong_name.path().join("cleanup-bad!.json"), b"{}").unwrap();
        assert!(list_bootstrap_cleanup_obligations(wrong_name.path(), "case-1").is_err());

        let oversized = tempdir().unwrap();
        let oversized_path = oversized.path().join("cleanup-large.json");
        let file = File::create(&oversized_path).unwrap();
        file.set_len(MAX_CLEANUP_LEDGER_BYTES + 1).unwrap();
        assert!(list_bootstrap_cleanup_obligations(oversized.path(), "case-1").is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = tempdir().unwrap();
            let target = linked.path().join("target");
            fs::write(&target, b"{}").unwrap();
            symlink(&target, linked.path().join("cleanup-linked.json")).unwrap();
            assert!(list_bootstrap_cleanup_obligations(linked.path(), "case-1").is_err());
        }
    }

    #[test]
    fn partial_exact_target_allowlists_reject_cross_provider_and_wildcards() {
        for provider in [
            BootstrapProvider::Aws,
            BootstrapProvider::Azure,
            BootstrapProvider::Gcp,
            BootstrapProvider::Microsoft365,
        ] {
            let items = partial_fixture_items(provider);
            for item in &items {
                validate_partial_provider_item(provider, item).unwrap();
            }
            assert!(
                validate_partial_provider_item(
                    provider,
                    &BootstrapMutationCleanupItem {
                        exact_resource_id: "*".into(),
                        provider_api_method: "DELETE".into(),
                        provider_api_endpoint: "https://example.invalid/*".into(),
                        cleanup_semantics: "wildcard".into(),
                    },
                )
                .is_err()
            );
        }
        let aws_item = partial_fixture_items(BootstrapProvider::Aws).pop().unwrap();
        assert!(validate_partial_provider_item(BootstrapProvider::Azure, &aws_item).is_err());
    }

    #[test]
    fn execute_cleanup_parses_and_completes_an_exact_empty_partial_journal() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("cleanup-empty.json");
        let ledger = BootstrapMutationLedger::new(
            "case-1",
            BootstrapMutationProviderContext::Aws {
                account_id: "123456789012".into(),
                region: "us-east-1".into(),
            },
            Utc::now(),
        );
        ledger.initialize(&path).unwrap();
        let fixture = PolicyFixture::new(Vec::new());
        let result = execute_bootstrap_cleanup(
            &fixture,
            &NoInteraction(Utc::now()),
            BootstrapOperatorConfig::Aws {
                administrator: AwsNativeAuthorizationConfig {
                    start_url: "https://company.awsapps.com/start".into(),
                    region: "us-east-1".into(),
                    account_id: "123456789012".into(),
                    role_name: "AdministratorAccess".into(),
                    role_arn: "arn:aws:iam::123456789012:role/AdministratorAccess".into(),
                },
            },
            "case-1",
            "empty",
            &path,
        )
        .unwrap();
        assert_eq!(result.summary().status, BootstrapCleanupStatus::Completed);
        assert_eq!(result.summary().total_items, 0);
        assert!(
            execute_bootstrap_cleanup(
                &fixture,
                &NoInteraction(Utc::now()),
                BootstrapOperatorConfig::Aws {
                    administrator: AwsNativeAuthorizationConfig {
                        start_url: "https://company.awsapps.com/start".into(),
                        region: "us-east-1".into(),
                        account_id: "123456789012".into(),
                        role_name: "AdministratorAccess".into(),
                        role_arn: "arn:aws:iam::123456789012:role/AdministratorAccess".into(),
                    },
                },
                "other-case",
                "empty",
                &path,
            )
            .is_err()
        );
    }
}
