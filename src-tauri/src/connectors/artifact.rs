//! Validation and bounded reading for source-connector snapshot artifacts.
//!
//! A connector never accepts a path from a command argument. The only path it
//! will read is the relative, backend-owned artifact reference stored on the
//! `DataSource`. The path is still treated as untrusted because case files may
//! be imported or modified outside the application.

use crate::discovery::DiscoveryError;
use crate::domain::DataSource;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Take, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// The sole `DataSource.metadata` key from which connectors accept a path.
///
/// This object is written by the backend artifact-ingestion boundary, never by
/// a scanner container or by a frontend-provided free-form path.
pub const SNAPSHOT_ARTIFACT_METADATA_KEY: &str = "ai_security_scanner.canonical_connector_artifact";

/// Backend-only metadata for one bounded live provider capture. The raw page
/// references in this set are immutable and hash-verified before a connector
/// can parse them. Provider credentials and pagination cursors never enter the
/// source record.
pub const LIVE_PROVIDER_ARTIFACT_METADATA_KEY: &str =
    "ai_security_scanner.live_provider_artifact_set";

pub const SNAPSHOT_REFERENCE_SCHEMA: &str = "ai-security-scanner.connector-artifact/v1";
pub const LIVE_PROVIDER_ARTIFACT_SET_SCHEMA: &str =
    "ai-security-scanner.live-provider-artifact-set/v1";
pub const MAX_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_LIVE_PROVIDER_PAGES: usize = 24;
const MAX_REFERENCE_TEXT: usize = 512;

/// Non-secret reference to an immutable, already-preserved source response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotArtifactReference {
    pub schema_version: String,
    /// Canonical artifact-store path, relative to the connector artifact root.
    pub canonical_relative_path: String,
    pub artifact_id: String,
    pub profile: String,
    pub observed_at: DateTime<Utc>,
    /// Optional integrity expectation recorded when the backend ingested the
    /// artifact. When present, connector reads fail closed on a mismatch.
    pub sha256: Option<String>,
}

impl SnapshotArtifactReference {
    pub fn new(
        canonical_relative_path: impl Into<String>,
        artifact_id: impl Into<String>,
        profile: impl Into<String>,
        observed_at: DateTime<Utc>,
        sha256: Option<String>,
    ) -> Self {
        Self {
            schema_version: SNAPSHOT_REFERENCE_SCHEMA.into(),
            canonical_relative_path: canonical_relative_path.into(),
            artifact_id: artifact_id.into(),
            profile: profile.into(),
            observed_at,
            sha256,
        }
    }

    /// Stores the reference using the backend-reserved metadata key.
    pub fn insert_into(self, source: &mut DataSource) -> Result<(), DiscoveryError> {
        let value = serde_json::to_value(self).map_err(|error| {
            DiscoveryError::Connector(format!(
                "could not serialize connector artifact reference: {error}"
            ))
        })?;
        source
            .metadata
            .insert(SNAPSHOT_ARTIFACT_METADATA_KEY.into(), value);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderArtifactPage {
    pub sequence: u16,
    pub operation: String,
    pub http_status: u16,
    /// Set only after the already-persisted body passed the capture client's
    /// minimal operation/pagination response contract. The connector performs
    /// the independent asset parse later.
    pub parser_eligible: bool,
    pub artifact: SnapshotArtifactReference,
}

/// Durable manifest written only after every listed raw response page has
/// reached stable storage. Non-success response bodies may be retained for an
/// honest failure record, but connectors parse only successful pages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderArtifactSet {
    pub schema_version: String,
    pub capture_id: String,
    pub profile: String,
    pub operation: String,
    pub observed_at: DateTime<Utc>,
    pub complete: bool,
    pub pages: Vec<LiveProviderArtifactPage>,
}

impl LiveProviderArtifactSet {
    pub fn insert_into(self, source: &mut DataSource) -> Result<(), DiscoveryError> {
        let value = serde_json::to_value(self).map_err(|error| {
            DiscoveryError::Connector(format!(
                "could not serialize live provider artifact set: {error}"
            ))
        })?;
        source
            .metadata
            .insert(LIVE_PROVIDER_ARTIFACT_METADATA_KEY.into(), value);
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ReadSnapshot {
    pub reference: SnapshotArtifactReference,
    pub bytes: Vec<u8>,
}

/// Ingests one source file explicitly selected through the application's file
/// dialog into the backend-owned artifact root.
///
/// There is intentionally no destination-path parameter. The backend chooses
/// a collision-resistant staging and final name, creates both without
/// overwriting, and returns the only relative path connectors will later read.
pub(crate) fn ingest_selected_source(
    root: &Path,
    selected_source_path: &Path,
    profile: &str,
    observed_at: DateTime<Utc>,
    allowed_profiles: &[&str],
) -> Result<SnapshotArtifactReference, DiscoveryError> {
    validate_short_token("parser profile", profile)?;
    if !allowed_profiles.contains(&profile) {
        return Err(DiscoveryError::Connector(format!(
            "parser profile {} is not allowed for this source kind",
            safe_text(profile)
        )));
    }

    let bytes = read_selected_source_file(selected_source_path)?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let nonce = Uuid::new_v4().simple().to_string();
    let artifact_id = format!("source-snapshot-{nonce}");
    let staging_name = format!(".connector-ingest-{nonce}.staging");
    let final_name = format!("connector-snapshot-{}-{nonce}.json", &sha256[..16]);
    let staging_path = root.join(&staging_name);
    let final_path = root.join(&final_name);

    let mut staging = create_private_new_file(&staging_path)?;
    let result = (|| -> Result<(), DiscoveryError> {
        staging.write_all(&bytes).map_err(|error| {
            DiscoveryError::Connector(format!("connector snapshot staging write failed: {error}"))
        })?;
        staging.sync_all().map_err(|error| {
            DiscoveryError::Connector(format!("connector snapshot staging sync failed: {error}"))
        })?;
        drop(staging);

        // `hard_link` has create-new semantics for the destination and never
        // overwrites an existing file. Staging and final remain on the same
        // backend-owned filesystem.
        fs::hard_link(&staging_path, &final_path).map_err(|error| {
            DiscoveryError::Connector(format!(
                "connector snapshot finalization failed without overwriting: {error}"
            ))
        })?;
        set_private_file_permissions(&final_path)?;
        fs::remove_file(&staging_path).map_err(|error| {
            DiscoveryError::Connector(format!(
                "connector snapshot staging cleanup failed: {error}"
            ))
        })?;
        Ok(())
    })();

    if let Err(error) = result {
        // Best-effort rollback. Paths are backend-generated concrete names and
        // neither removal follows a directory supplied by the caller.
        let _ = fs::remove_file(&staging_path);
        let _ = fs::remove_file(&final_path);
        return Err(error);
    }

    Ok(SnapshotArtifactReference::new(
        final_name,
        artifact_id,
        profile,
        observed_at,
        Some(sha256),
    ))
}

/// Persists an exact provider HTTP response body under its SHA-256 address.
/// The caller supplies neither a destination nor a filename. A repeated body
/// reuses the already-verified regular file, while each capture retains its own
/// observation time and parser profile in the reference.
pub(crate) fn ingest_provider_response(
    root: &Path,
    bytes: &[u8],
    profile: &str,
    observed_at: DateTime<Utc>,
    allowed_profiles: &[&str],
) -> Result<SnapshotArtifactReference, DiscoveryError> {
    validate_short_token("parser profile", profile)?;
    if !allowed_profiles.contains(&profile) {
        return Err(DiscoveryError::Connector(format!(
            "parser profile {} is not allowed for this source kind",
            safe_text(profile)
        )));
    }
    if bytes.is_empty() || bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(DiscoveryError::Connector(format!(
            "provider response must contain between 1 and {MAX_SNAPSHOT_BYTES} bytes"
        )));
    }

    let sha256 = hex::encode(Sha256::digest(bytes));
    let nonce = Uuid::new_v4().simple().to_string();
    let artifact_id = format!("provider-response-sha256-{sha256}");
    let staging_path = root.join(format!(".provider-response-{nonce}.staging"));
    let final_name = format!("provider-response-{sha256}.raw");
    let final_path = root.join(&final_name);
    let mut staging = create_private_new_file(&staging_path)?;
    let result = (|| -> Result<(), DiscoveryError> {
        staging.write_all(bytes).map_err(|error| {
            DiscoveryError::Connector(format!("provider response staging write failed: {error}"))
        })?;
        staging.sync_all().map_err(|error| {
            DiscoveryError::Connector(format!("provider response staging sync failed: {error}"))
        })?;
        drop(staging);

        match fs::hard_link(&staging_path, &final_path) {
            Ok(()) => set_private_file_permissions(&final_path)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_bounded_regular_file(&final_path)?;
                if existing.len() != bytes.len()
                    || Sha256::digest(&existing) != Sha256::digest(bytes)
                {
                    return Err(DiscoveryError::Connector(
                        "content-addressed provider artifact failed collision verification".into(),
                    ));
                }
                set_private_file_permissions(&final_path)?;
            }
            Err(error) => {
                return Err(DiscoveryError::Connector(format!(
                    "provider response finalization failed without overwriting: {error}"
                )));
            }
        }
        fs::remove_file(&staging_path).map_err(|error| {
            DiscoveryError::Connector(format!("provider response staging cleanup failed: {error}"))
        })?;
        Ok(())
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(&staging_path);
        return Err(error);
    }

    Ok(SnapshotArtifactReference::new(
        final_name,
        artifact_id,
        profile,
        observed_at,
        Some(sha256),
    ))
}

pub(crate) fn prepare_artifact_root(root: impl AsRef<Path>) -> Result<PathBuf, DiscoveryError> {
    let supplied = root.as_ref();
    let metadata = fs::symlink_metadata(supplied).map_err(|error| {
        DiscoveryError::Connector(format!(
            "connector artifact root could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DiscoveryError::Connector(
            "connector artifact root must be a real directory, not a symlink".into(),
        ));
    }
    supplied.canonicalize().map_err(|error| {
        DiscoveryError::Connector(format!(
            "connector artifact root could not be canonicalized: {error}"
        ))
    })
}

pub(crate) fn read_source_snapshot(
    root: &Path,
    source: &DataSource,
    allowed_profiles: &[&str],
) -> Result<ReadSnapshot, DiscoveryError> {
    reject_secret_fields(&Value::Object(
        source.metadata.clone().into_iter().collect(),
    ))?;

    let value = source
        .metadata
        .get(SNAPSHOT_ARTIFACT_METADATA_KEY)
        .ok_or_else(|| {
            DiscoveryError::Connector(format!(
                "source {} has no backend-created canonical connector artifact reference",
                source.id
            ))
        })?
        .clone();
    let reference: SnapshotArtifactReference = serde_json::from_value(value).map_err(|error| {
        DiscoveryError::Connector(format!(
            "source {} has an invalid connector artifact reference: {error}",
            source.id
        ))
    })?;
    read_snapshot_reference(root, reference, allowed_profiles)
}

pub(crate) fn read_snapshot_reference(
    root: &Path,
    reference: SnapshotArtifactReference,
    allowed_profiles: &[&str],
) -> Result<ReadSnapshot, DiscoveryError> {
    let bytes = inspect_snapshot_reference(root, &reference, allowed_profiles)?;

    Ok(ReadSnapshot { reference, bytes })
}

/// Performs the complete immutable-reference check without changing the
/// artifact store. The bounded bytes are returned so the normal connector read
/// path can reuse the exact same validation and integrity boundary.
pub(crate) fn inspect_snapshot_reference(
    root: &Path,
    reference: &SnapshotArtifactReference,
    allowed_profiles: &[&str],
) -> Result<Vec<u8>, DiscoveryError> {
    validate_reference(reference, allowed_profiles)?;
    let path = resolve_without_symlinks(root, &reference.canonical_relative_path)?;
    let bytes = read_bounded_regular_file(&path)?;

    if let Some(expected) = reference.sha256.as_deref() {
        let expected = expected.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DiscoveryError::Connector(
                "connector artifact reference contains an invalid SHA-256 value".into(),
            ));
        }
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != expected {
            return Err(DiscoveryError::Connector(format!(
                "connector artifact {} failed its SHA-256 integrity check",
                reference.artifact_id
            )));
        }
    }

    Ok(bytes)
}

fn validate_reference(
    reference: &SnapshotArtifactReference,
    allowed_profiles: &[&str],
) -> Result<(), DiscoveryError> {
    if reference.schema_version != SNAPSHOT_REFERENCE_SCHEMA {
        return Err(DiscoveryError::Connector(format!(
            "unsupported connector artifact reference schema {}",
            safe_text(&reference.schema_version)
        )));
    }
    validate_short_token("artifact identifier", &reference.artifact_id)?;
    validate_short_token("parser profile", &reference.profile)?;
    if !allowed_profiles.contains(&reference.profile.as_str()) {
        return Err(DiscoveryError::Connector(format!(
            "parser profile {} is not allowed for this source kind",
            safe_text(&reference.profile)
        )));
    }
    validate_relative_path(&reference.canonical_relative_path)
}

fn validate_short_token(label: &str, value: &str) -> Result<(), DiscoveryError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_REFERENCE_TEXT
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'/' || byte == b'\\')
    {
        return Err(DiscoveryError::Connector(format!(
            "connector artifact {label} is invalid"
        )));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), DiscoveryError> {
    if value.is_empty() || value.len() > 4_096 {
        return Err(DiscoveryError::Connector(
            "connector artifact path is empty or too long".into(),
        ));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
        })
    {
        return Err(DiscoveryError::Connector(
            "connector artifact path must be a normalized relative path".into(),
        ));
    }
    Ok(())
}

fn resolve_without_symlinks(root: &Path, relative: &str) -> Result<PathBuf, DiscoveryError> {
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return Err(DiscoveryError::Connector(
                "connector artifact path contains a disallowed component".into(),
            ));
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            DiscoveryError::Connector(format!(
                "connector artifact path could not be inspected: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(DiscoveryError::Connector(
                "connector artifact path contains a symlink".into(),
            ));
        }
    }

    let canonical = current.canonicalize().map_err(|error| {
        DiscoveryError::Connector(format!(
            "connector artifact path could not be canonicalized: {error}"
        ))
    })?;
    if !canonical.starts_with(root) {
        return Err(DiscoveryError::Connector(
            "connector artifact resolved outside its artifact root".into(),
        ));
    }
    Ok(canonical)
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, DiscoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "connector artifact could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DiscoveryError::Connector(
            "connector artifact must be a regular file, not a link or device".into(),
        ));
    }
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(DiscoveryError::Connector(format!(
            "connector artifact exceeds the {} byte limit",
            MAX_SNAPSHOT_BYTES
        )));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file: File = options.open(path).map_err(|error| {
        DiscoveryError::Connector(format!("connector artifact could not be opened: {error}"))
    })?;
    let opened_metadata = file.metadata().map_err(|error| {
        DiscoveryError::Connector(format!(
            "connector artifact metadata could not be read: {error}"
        ))
    })?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(DiscoveryError::Connector(
            "connector artifact changed or exceeded its byte limit while opening".into(),
        ));
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    let mut reader: Take<File> = file.take(MAX_SNAPSHOT_BYTES + 1);
    reader.read_to_end(&mut bytes).map_err(|error| {
        DiscoveryError::Connector(format!("connector artifact could not be read: {error}"))
    })?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(DiscoveryError::Connector(
            "connector artifact exceeded its byte limit while reading".into(),
        ));
    }
    Ok(bytes)
}

fn read_selected_source_file(path: &Path) -> Result<Vec<u8>, DiscoveryError> {
    validate_selected_source_path(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "selected connector source could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DiscoveryError::Connector(
            "selected connector source must be a regular file, not a symlink or device".into(),
        ));
    }
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(DiscoveryError::Connector(format!(
            "selected connector source exceeds the {} byte limit",
            MAX_SNAPSHOT_BYTES
        )));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "selected connector source could not be opened without following links: {error}"
        ))
    })?;
    let opened_metadata = file.metadata().map_err(|error| {
        DiscoveryError::Connector(format!(
            "selected connector source metadata could not be read: {error}"
        ))
    })?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(DiscoveryError::Connector(
            "selected connector source changed or exceeded its byte limit while opening".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    let mut reader = file.take(MAX_SNAPSHOT_BYTES + 1);
    reader.read_to_end(&mut bytes).map_err(|error| {
        DiscoveryError::Connector(format!(
            "selected connector source could not be read: {error}"
        ))
    })?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(DiscoveryError::Connector(
            "selected connector source exceeded its byte limit while reading".into(),
        ));
    }
    Ok(bytes)
}

fn validate_selected_source_path(path: &Path) -> Result<(), DiscoveryError> {
    if !path.is_absolute() {
        return Err(DiscoveryError::Connector(
            "selected connector source path must be the absolute path returned by the file dialog"
                .into(),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(DiscoveryError::Connector(
            "selected connector source path contains traversal components".into(),
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::Normal(name) => {
                current.push(name);
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    DiscoveryError::Connector(format!(
                        "selected connector source path could not be inspected: {error}"
                    ))
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(DiscoveryError::Connector(
                        "selected connector source path contains a symlink".into(),
                    ));
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(DiscoveryError::Connector(
                    "selected connector source path contains traversal components".into(),
                ));
            }
        }
    }
    Ok(())
}

fn create_private_new_file(path: &Path) -> Result<File, DiscoveryError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "connector snapshot staging file could not be created without overwrite: {error}"
        ))
    })?;
    if let Err(error) = set_private_file_permissions(path) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

fn set_private_file_permissions(path: &Path) -> Result<(), DiscoveryError> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            DiscoveryError::Connector(format!(
                "connector snapshot permissions could not be restricted: {error}"
            ))
        })?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)
            .map_err(|error| {
                DiscoveryError::Connector(format!(
                    "connector snapshot permissions could not be inspected: {error}"
                ))
            })?
            .permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).map_err(|error| {
            DiscoveryError::Connector(format!(
                "connector snapshot permissions could not be restricted: {error}"
            ))
        })?;
    }
    Ok(())
}

/// Serialized source metadata is non-secret by contract. Fail closed instead
/// of allowing an imported case to turn a connector into a credential store.
fn reject_secret_fields(value: &Value) -> Result<(), DiscoveryError> {
    match value {
        Value::Object(values) => {
            for (key, child) in values {
                if is_secret_key(key) {
                    return Err(DiscoveryError::Connector(format!(
                        "source metadata contains forbidden secret-like field {}",
                        safe_text(key)
                    )));
                }
                reject_secret_fields(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_secret_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let segments = normalized
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "secret_key"
            | "private_key"
            | "api_key"
            | "access_key"
            | "access_key_id"
            | "token"
            | "access_token"
            | "id_token"
            | "oauth_token"
            | "auth_token"
            | "client_secret"
            | "session_token"
            | "refresh_token"
            | "bearer_token"
            | "authorization"
            | "cookie"
            | "cookies"
    ) || segments.iter().any(|segment| {
        matches!(
            *segment,
            "password" | "passwd" | "secret" | "token" | "credential" | "credentials"
        )
    })
}

fn safe_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
}
