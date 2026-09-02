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
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

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
const MAX_PROVIDER_ARTIFACT_RECOVERY_SLOTS: usize = 4;
const PROVIDER_ARTIFACT_COLLISION_ERROR: &str =
    "content-addressed provider artifact failed collision verification";
const PROVIDER_ARTIFACT_RECOVERY_EXHAUSTED_ERROR: &str =
    "bounded provider artifact recovery slots were exhausted";

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
/// a collision-resistant final name, creates it without overwriting, and
/// returns the only relative path connectors will later read.
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
    let final_name = format!("connector-snapshot-{}-{nonce}.json", &sha256[..16]);
    let final_path = root.join(&final_name);

    let mut final_file = create_private_new_file(&final_path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "connector snapshot final file could not be created without overwrite: {error}"
        ))
    })?;
    let result = (|| -> Result<(), DiscoveryError> {
        final_file.write_all(&bytes).map_err(|error| {
            DiscoveryError::Connector(format!("connector snapshot final write failed: {error}"))
        })?;
        final_file.sync_all().map_err(|error| {
            DiscoveryError::Connector(format!("connector snapshot final sync failed: {error}"))
        })?;
        Ok(())
    })();

    if let Err(error) = result {
        // Retain the incomplete product-owned file. After the handle closes a
        // permissive custom parent could replace its pathname, so path-based
        // rollback could delete an unrelated object. No reference is returned.
        drop(final_file);
        return Err(error);
    }
    drop(final_file);

    Ok(SnapshotArtifactReference::new(
        final_name,
        artifact_id,
        profile,
        observed_at,
        Some(sha256),
    ))
}

struct ProviderArtifactAuthorityDirectory {
    #[cfg(unix)]
    directory: File,
    #[cfg(unix)]
    root: PathBuf,
    #[cfg(unix)]
    identity: (u64, u64, u32),
}

fn open_provider_artifact_authority_directory(
    root: &Path,
) -> Result<ProviderArtifactAuthorityDirectory, DiscoveryError> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(root).map_err(|error| {
            DiscoveryError::Connector(format!(
                "provider artifact authority could not be inspected: {error}"
            ))
        })?;
        // SAFETY: geteuid has no preconditions and does not mutate process state.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != effective_uid
        {
            return Err(DiscoveryError::Connector(
                "provider artifact authority must be a current-user real directory".into(),
            ));
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = options.open(root).map_err(|error| {
            DiscoveryError::Connector(format!(
                "provider artifact authority could not be pinned without following links: {error}"
            ))
        })?;
        let opened = directory.metadata().map_err(|error| {
            DiscoveryError::Connector(format!(
                "pinned provider artifact authority could not be inspected: {error}"
            ))
        })?;
        let identity = (metadata.dev(), metadata.ino(), metadata.uid());
        if !opened.is_dir()
            || (opened.dev(), opened.ino(), opened.uid()) != identity
            || opened.uid() != effective_uid
        {
            return Err(DiscoveryError::Connector(
                "provider artifact authority changed while it was being pinned".into(),
            ));
        }
        Ok(ProviderArtifactAuthorityDirectory {
            directory,
            root: root.to_path_buf(),
            identity,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Ok(ProviderArtifactAuthorityDirectory {})
    }
}

#[cfg(unix)]
fn verify_provider_artifact_authority_directory(
    authority: &ProviderArtifactAuthorityDirectory,
) -> Result<(), DiscoveryError> {
    let path_metadata = fs::symlink_metadata(&authority.root).map_err(|error| {
        DiscoveryError::Connector(format!(
            "provider artifact authority path could not be reinspected: {error}"
        ))
    })?;
    let opened = authority.directory.metadata().map_err(|error| {
        DiscoveryError::Connector(format!(
            "pinned provider artifact authority could not be reinspected: {error}"
        ))
    })?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || !opened.is_dir()
        || (
            path_metadata.dev(),
            path_metadata.ino(),
            path_metadata.uid(),
        ) != authority.identity
        || (opened.dev(), opened.ino(), opened.uid()) != authority.identity
    {
        return Err(DiscoveryError::Connector(
            "provider artifact authority changed while it was pinned".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_fresh_provider_artifact_open_file(
    authority: &ProviderArtifactAuthorityDirectory,
    path: &Path,
    file: &File,
) -> Result<(), DiscoveryError> {
    if path.parent() != Some(authority.root.as_path()) {
        return Err(DiscoveryError::Connector(
            "fresh provider artifact escaped its pinned authority".into(),
        ));
    }
    verify_provider_artifact_authority_directory(authority)?;
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "fresh provider artifact path could not be reinspected: {error}"
        ))
    })?;
    let opened = file.metadata().map_err(|error| {
        DiscoveryError::Connector(format!(
            "fresh provider artifact handle could not be reinspected: {error}"
        ))
    })?;
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.nlink(),
            metadata.uid(),
            metadata.size(),
        )
    };
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    let effective_uid = unsafe { libc::geteuid() };
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || !opened.is_file()
        || identity(&path_metadata) != identity(&opened)
        || opened.nlink() != 1
        || opened.uid() != effective_uid
        || opened.permissions().mode() & 0o777 != 0o600
    {
        return Err(DiscoveryError::Connector(
            "fresh provider artifact is not the pinned current-user single-link file".into(),
        ));
    }
    verify_provider_artifact_authority_directory(authority)
}

#[cfg(not(unix))]
fn verify_fresh_provider_artifact_open_file(
    _authority: &ProviderArtifactAuthorityDirectory,
    _path: &Path,
    _file: &File,
) -> Result<(), DiscoveryError> {
    Ok(())
}

/// Persists an exact provider HTTP response body under a backend-owned name.
/// The caller supplies neither a destination nor a filename. A repeated body
/// normally reuses the already-verified SHA-256-addressed regular file. If an
/// earlier interrupted write left different bytes at that address, the
/// collision is preserved for forensic safety and this capture is published
/// under one of a fixed number of private recovery slots. Exact matching slots
/// are reused, while different bytes are preserved and advance to the next
/// slot, so repeated collisions cannot grow storage without bound.
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
    let authority = open_provider_artifact_authority_directory(root)?;

    let sha256 = hex::encode(Sha256::digest(bytes));
    let artifact_id = format!("provider-response-sha256-{sha256}");
    let canonical_name = format!("provider-response-{sha256}.raw");
    let final_path = root.join(&canonical_name);
    let final_name;
    match create_private_new_file(&final_path) {
        Ok(mut final_file) => {
            let result = (|| -> Result<(), DiscoveryError> {
                final_file.write_all(bytes).map_err(|error| {
                    DiscoveryError::Connector(format!(
                        "provider response final write failed: {error}"
                    ))
                })?;
                final_file.sync_all().map_err(|error| {
                    DiscoveryError::Connector(format!(
                        "provider response final sync failed: {error}"
                    ))
                })?;
                verify_fresh_provider_artifact_open_file(&authority, &final_path, &final_file)?;
                sync_provider_artifact_authority_directory(&authority)?;
                verify_fresh_provider_artifact_open_file(&authority, &final_path, &final_file)?;
                Ok(())
            })();
            if let Err(error) = result {
                // Retain the incomplete or not-yet-namespace-durable private
                // product file rather than risk deleting a replacement
                // through a permissive parent. A retry re-verifies the same
                // object and reattempts both durability barriers.
                drop(final_file);
                return Err(error);
            }
            final_name = canonical_name;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            match verify_and_restrict_matching_provider_artifact(
                &final_path,
                root,
                bytes,
                &authority,
            ) {
                Ok(()) => final_name = canonical_name,
                Err(error) if is_provider_artifact_content_collision(&error) => {
                    final_name = publish_bounded_provider_recovery_artifact(
                        root, &sha256, bytes, &authority,
                    )?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => {
            return Err(DiscoveryError::Connector(format!(
                "provider response final file could not be created without overwrite: {error}"
            )));
        }
    }

    Ok(SnapshotArtifactReference::new(
        final_name,
        artifact_id,
        profile,
        observed_at,
        Some(sha256),
    ))
}

fn publish_bounded_provider_recovery_artifact(
    root: &Path,
    sha256: &str,
    bytes: &[u8],
    authority: &ProviderArtifactAuthorityDirectory,
) -> Result<String, DiscoveryError> {
    for slot in 1..=MAX_PROVIDER_ARTIFACT_RECOVERY_SLOTS {
        let final_name = provider_recovery_artifact_name(sha256, slot);
        let final_path = root.join(&final_name);
        match create_private_new_file(&final_path) {
            Ok(file) => {
                write_open_provider_recovery_artifact(file, bytes, authority, &final_path)?;
                return Ok(final_name);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                match verify_and_restrict_matching_provider_artifact(
                    &final_path,
                    root,
                    bytes,
                    authority,
                ) {
                    Ok(()) => return Ok(final_name),
                    Err(error) if is_provider_artifact_content_collision(&error) => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => {
                return Err(DiscoveryError::Connector(format!(
                    "provider response recovery slot could not be created without overwrite: {error}"
                )));
            }
        }
    }

    Err(DiscoveryError::Connector(
        PROVIDER_ARTIFACT_RECOVERY_EXHAUSTED_ERROR.into(),
    ))
}

fn provider_recovery_artifact_name(sha256: &str, slot: usize) -> String {
    format!("provider-response-{sha256}-recovered-{slot}.raw")
}

fn write_open_provider_recovery_artifact(
    mut file: File,
    bytes: &[u8],
    authority: &ProviderArtifactAuthorityDirectory,
    path: &Path,
) -> Result<(), DiscoveryError> {
    let result = (|| -> Result<(), DiscoveryError> {
        file.write_all(bytes).map_err(|error| {
            DiscoveryError::Connector(format!("provider response recovery write failed: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            DiscoveryError::Connector(format!("provider response recovery sync failed: {error}"))
        })?;
        verify_fresh_provider_artifact_open_file(authority, path, &file)?;
        sync_provider_artifact_authority_directory(authority)?;
        verify_fresh_provider_artifact_open_file(authority, path, &file)?;
        Ok(())
    })();
    if let Err(error) = result {
        // Retain the incomplete or not-yet-namespace-durable fixed-slot file
        // rather than risk a pathname-based delete through a permissive
        // custom parent. A retry reuses matching bytes and reattempts both
        // barriers; only a proven content collision advances the bounded slot.
        drop(file);
        return Err(error);
    }
    Ok(())
}

fn is_provider_artifact_content_collision(error: &DiscoveryError) -> bool {
    matches!(
        error,
        DiscoveryError::Connector(message) if message == PROVIDER_ARTIFACT_COLLISION_ERROR
    )
}

fn verify_provider_artifact_contents(
    existing: &[u8],
    expected: &[u8],
) -> Result<(), DiscoveryError> {
    if existing.len() != expected.len() || Sha256::digest(existing) != Sha256::digest(expected) {
        return Err(DiscoveryError::Connector(
            PROVIDER_ARTIFACT_COLLISION_ERROR.into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_and_restrict_matching_provider_artifact(
    path: &Path,
    authority_root: &Path,
    expected: &[u8],
    authority: &ProviderArtifactAuthorityDirectory,
) -> Result<(), DiscoveryError> {
    crate::managed_runtime::
        verify_then_sync_and_repair_canonical_or_verify_private_product_file_dacl(
            path,
            authority_root,
            |file| verify_provider_artifact_open_file(file, expected),
            |file| {
                sync_provider_artifact_open_file(file)?;
                sync_provider_artifact_authority_directory(authority)
            },
            |error| {
                DiscoveryError::Connector(format!(
                    "matching provider artifact could not be safely verified or restricted: {error}"
                ))
            },
        )
}

fn verify_provider_artifact_open_file(
    file: &mut File,
    expected: &[u8],
) -> Result<(), DiscoveryError> {
    let existing = read_bounded_open_file(file)?;
    verify_provider_artifact_contents(&existing, expected)
}

#[cfg(test)]
thread_local! {
    static TEST_PROVIDER_ARTIFACT_REUSE_SYNC_FAILURE_AFTER: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
    static TEST_PROVIDER_ARTIFACT_PARENT_SYNC_FAILURES: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

fn sync_provider_artifact_open_file(file: &File) -> Result<(), DiscoveryError> {
    #[cfg(test)]
    if TEST_PROVIDER_ARTIFACT_REUSE_SYNC_FAILURE_AFTER.with(|remaining| match remaining.get() {
        None => false,
        Some(0) => {
            remaining.set(None);
            true
        }
        Some(current) => {
            remaining.set(Some(current - 1));
            false
        }
    }) {
        return Err(DiscoveryError::Connector(
            "matching provider artifact durability barrier failed: injected sync failure".into(),
        ));
    }

    file.sync_all().map_err(|error| {
        DiscoveryError::Connector(format!(
            "matching provider artifact durability barrier failed: {error}"
        ))
    })
}

#[cfg(test)]
fn fail_next_provider_artifact_reuse_sync() {
    fail_provider_artifact_reuse_sync_after(0);
}

#[cfg(test)]
fn fail_provider_artifact_reuse_sync_after(successful_barriers: usize) {
    TEST_PROVIDER_ARTIFACT_REUSE_SYNC_FAILURE_AFTER.with(|remaining| {
        assert_eq!(
            remaining.replace(Some(successful_barriers)),
            None,
            "provider artifact sync failure injection was already armed"
        );
    });
}

fn sync_provider_artifact_authority_directory(
    authority: &ProviderArtifactAuthorityDirectory,
) -> Result<(), DiscoveryError> {
    #[cfg(unix)]
    verify_provider_artifact_authority_directory(authority)?;

    #[cfg(test)]
    if TEST_PROVIDER_ARTIFACT_PARENT_SYNC_FAILURES.with(|remaining| {
        let current = remaining.get();
        if current == 0 {
            false
        } else {
            remaining.set(current - 1);
            true
        }
    }) {
        return Err(DiscoveryError::Connector(
            "provider artifact authority durability barrier failed: injected parent sync failure"
                .into(),
        ));
    }

    #[cfg(unix)]
    {
        authority.directory.sync_all().map_err(|error| {
            DiscoveryError::Connector(format!(
                "provider artifact authority durability barrier failed: {error}"
            ))
        })?;
        verify_provider_artifact_authority_directory(authority)?;
    }
    #[cfg(not(unix))]
    let _ = authority;
    Ok(())
}

#[cfg(test)]
fn fail_next_provider_artifact_parent_sync() {
    TEST_PROVIDER_ARTIFACT_PARENT_SYNC_FAILURES.with(|remaining| {
        assert_eq!(
            remaining.replace(1),
            0,
            "provider artifact parent sync failure injection was already armed"
        );
    });
}

#[cfg(unix)]
fn verify_and_restrict_matching_provider_artifact(
    path: &Path,
    authority_root: &Path,
    expected: &[u8],
    authority: &ProviderArtifactAuthorityDirectory,
) -> Result<(), DiscoveryError> {
    verify_provider_artifact_authority_directory(authority)?;
    let parent = path.parent().ok_or_else(|| {
        DiscoveryError::Connector("matching provider artifact has no parent".into())
    })?;
    if parent.canonicalize().map_err(|error| {
        DiscoveryError::Connector(format!(
            "matching provider artifact parent could not be resolved: {error}"
        ))
    })? != authority_root.canonicalize().map_err(|error| {
        DiscoveryError::Connector(format!(
            "provider artifact authority could not be resolved: {error}"
        ))
    })? {
        return Err(DiscoveryError::Connector(
            "matching provider artifact escaped its authority root".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "matching provider artifact could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DiscoveryError::Connector(
            "matching provider artifact must be a real regular file".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "matching provider artifact could not be opened without following links: {error}"
        ))
    })?;
    let opened = file.metadata().map_err(|error| {
        DiscoveryError::Connector(format!(
            "matching provider artifact handle could not be inspected: {error}"
        ))
    })?;
    let stable_snapshot = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.nlink(),
            metadata.uid(),
            metadata.size(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if stable_snapshot(&metadata) != stable_snapshot(&opened)
        || opened.nlink() != 1
        // SAFETY: geteuid has no preconditions and does not mutate process state.
        || opened.uid() != unsafe { libc::geteuid() }
    {
        return Err(DiscoveryError::Connector(
            "matching provider artifact is not the current user's single-link opened file".into(),
        ));
    }
    let existing = read_bounded_open_file(&mut file)?;
    verify_provider_artifact_contents(&existing, expected)?;
    let verified_handle = file.metadata().map_err(|error| {
        DiscoveryError::Connector(format!(
            "verified provider artifact handle could not be reinspected: {error}"
        ))
    })?;
    let verified_path = fs::symlink_metadata(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "verified provider artifact path could not be reinspected: {error}"
        ))
    })?;
    if stable_snapshot(&verified_handle) != stable_snapshot(&opened)
        || stable_snapshot(&verified_path) != stable_snapshot(&opened)
    {
        return Err(DiscoveryError::Connector(
            "matching provider artifact changed during content verification".into(),
        ));
    }
    sync_provider_artifact_open_file(&file)?;
    sync_provider_artifact_authority_directory(authority)?;
    restrict_existing_file_handle_to_owner(&file)?;
    sync_provider_artifact_open_file(&file)?;
    let restricted_handle = file.metadata().map_err(|error| {
        DiscoveryError::Connector(format!(
            "restricted provider artifact handle could not be reinspected: {error}"
        ))
    })?;
    let restricted_path = fs::symlink_metadata(path).map_err(|error| {
        DiscoveryError::Connector(format!(
            "restricted provider artifact path could not be reinspected: {error}"
        ))
    })?;
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.nlink(),
            metadata.uid(),
            metadata.size(),
        )
    };
    if identity(&restricted_handle) != identity(&opened)
        || identity(&restricted_path) != identity(&opened)
        || restricted_handle.permissions().mode() & 0o777 != 0o600
    {
        return Err(DiscoveryError::Connector(
            "matching provider artifact changed during handle-based permission restriction".into(),
        ));
    }
    Ok(())
}

#[cfg(all(not(windows), not(unix)))]
fn verify_and_restrict_matching_provider_artifact(
    _path: &Path,
    _authority_root: &Path,
    _expected: &[u8],
    _authority: &ProviderArtifactAuthorityDirectory,
) -> Result<(), DiscoveryError> {
    Err(DiscoveryError::Connector(
        "safe existing-artifact permission verification is unavailable on this platform".into(),
    ))
}

#[cfg(all(test, windows))]
fn verify_and_restrict_matching_provider_artifact_in_isolated_root(
    path: &Path,
    expected: &[u8],
    product_root: &Path,
) -> Result<(), DiscoveryError> {
    crate::managed_runtime::verify_then_sync_and_repair_isolated_product_file_dacl(
        path,
        product_root,
        |file| verify_provider_artifact_open_file(file, expected),
        sync_provider_artifact_open_file,
        |error| DiscoveryError::Connector(error.to_string()),
    )
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
    let mut file: File = options.open(path).map_err(|error| {
        DiscoveryError::Connector(format!("connector artifact could not be opened: {error}"))
    })?;
    read_bounded_open_file(&mut file)
}

fn read_bounded_open_file(file: &mut File) -> Result<Vec<u8>, DiscoveryError> {
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
    let mut reader = file.take(MAX_SNAPSHOT_BYTES + 1);
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

fn create_private_new_file(path: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        crate::managed_runtime::create_current_user_only_product_file(path)
    }
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    #[cfg(not(windows))]
    let file = options.open(path)?;
    #[cfg(not(windows))]
    if let Err(error) = restrict_existing_file_handle_to_owner(&file) {
        drop(file);
        return Err(std::io::Error::other(error.to_string()));
    }
    #[cfg(not(windows))]
    Ok(file)
}

#[cfg(not(windows))]
fn restrict_existing_file_handle_to_owner(file: &File) -> Result<(), DiscoveryError> {
    #[cfg(unix)]
    {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                DiscoveryError::Connector(format!(
                    "connector snapshot permissions could not be restricted: {error}"
                ))
            })?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_collision_proof_rejects_different_bytes() {
        let error = verify_provider_artifact_contents(b"expected", b"different")
            .expect_err("different bytes must not authorize artifact reuse");
        assert!(error.to_string().contains("collision verification"));
    }

    #[test]
    fn partial_content_addressed_provider_file_does_not_poison_a_later_retry() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"complete provider response";
        let canonical = provider_artifact_path(temporary.path(), expected);
        let mut partial = create_private_new_file(&canonical).expect("partial artifact fixture");
        partial
            .write_all(b"partial")
            .expect("write partial fixture");
        partial.sync_all().expect("sync partial fixture");
        drop(partial);

        let reference = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("a fresh recovery artifact should allow the retry to succeed");
        let recovered_name = reference.canonical_relative_path.clone();
        let repeated = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("the verified recovery artifact should be reused");

        assert_ne!(
            reference.canonical_relative_path,
            canonical.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(repeated.canonical_relative_path, recovered_name);
        assert_eq!(fs::read(&canonical).unwrap(), b"partial");
        assert_eq!(
            fs::read(temporary.path().join(recovered_name)).unwrap(),
            expected
        );
        assert_eq!(
            fs::read_dir(temporary.path()).unwrap().count(),
            2,
            "a repeated response must not append another recovery artifact"
        );
    }

    #[cfg(any(unix, windows))]
    fn provider_artifact_path(root: &Path, expected: &[u8]) -> PathBuf {
        root.join(format!(
            "provider-response-{}.raw",
            hex::encode(Sha256::digest(expected))
        ))
    }

    fn write_private_test_artifact(path: &Path, bytes: &[u8]) {
        let mut file = create_private_new_file(path).expect("private artifact fixture");
        file.write_all(bytes).expect("write artifact fixture");
        file.sync_all().expect("sync artifact fixture");
    }

    #[test]
    fn matching_canonical_reuse_requires_a_successful_durability_barrier() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"matching canonical response after an uncertain sync";
        let canonical = provider_artifact_path(temporary.path(), expected);
        write_private_test_artifact(&canonical, expected);
        fail_next_provider_artifact_reuse_sync();

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("matching bytes without a completed durability barrier must fail");

        assert!(error.to_string().contains("durability barrier failed"));
        assert_eq!(fs::read(&canonical).unwrap(), expected);
        assert_eq!(
            fs::read_dir(temporary.path()).unwrap().count(),
            1,
            "a failed matching reuse must not publish a recovery artifact"
        );

        let retried = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("the same canonical file may be reused after a real barrier succeeds");
        assert_eq!(
            retried.canonical_relative_path,
            canonical.file_name().unwrap().to_string_lossy()
        );
    }

    #[test]
    fn matching_recovery_reuse_sync_failure_does_not_advance_a_slot() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"matching recovery response after an uncertain sync";
        let sha256 = hex::encode(Sha256::digest(expected));
        let canonical = provider_artifact_path(temporary.path(), expected);
        write_private_test_artifact(&canonical, b"preserved canonical collision");
        let recovery_name = provider_recovery_artifact_name(&sha256, 1);
        let recovery = temporary.path().join(&recovery_name);
        write_private_test_artifact(&recovery, expected);
        fail_next_provider_artifact_reuse_sync();

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("a recovery-slot sync failure must fail instead of advancing");

        assert!(error.to_string().contains("durability barrier failed"));
        assert_eq!(
            fs::read(&canonical).unwrap(),
            b"preserved canonical collision"
        );
        assert_eq!(fs::read(&recovery).unwrap(), expected);
        assert!(
            !temporary
                .path()
                .join(provider_recovery_artifact_name(&sha256, 2))
                .exists(),
            "a non-content durability error must not advance to another slot"
        );

        let retried = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("the same recovery slot may be reused after a real barrier succeeds");
        assert_eq!(retried.canonical_relative_path, recovery_name);
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 2);
    }

    #[test]
    fn fresh_canonical_parent_sync_failure_reuses_the_same_object_on_retry() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"fresh canonical response with uncertain namespace durability";
        let canonical = provider_artifact_path(temporary.path(), expected);
        fail_next_provider_artifact_parent_sync();

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("fresh canonical publication must fail when its parent sync fails");

        assert!(
            error
                .to_string()
                .contains("authority durability barrier failed")
        );
        assert_eq!(fs::read(&canonical).unwrap(), expected);
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);

        let retried = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("retry reuses and re-syncs the same canonical object");
        assert_eq!(
            retried.canonical_relative_path,
            canonical.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);
    }

    #[test]
    fn fresh_recovery_parent_sync_failure_reuses_slot_one_on_retry() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"fresh recovery response with uncertain namespace durability";
        let sha256 = hex::encode(Sha256::digest(expected));
        let canonical = provider_artifact_path(temporary.path(), expected);
        write_private_test_artifact(&canonical, b"preserved canonical collision");
        let recovery_name = provider_recovery_artifact_name(&sha256, 1);
        let recovery = temporary.path().join(&recovery_name);
        fail_next_provider_artifact_parent_sync();

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("fresh recovery publication must fail when its parent sync fails");

        assert!(
            error
                .to_string()
                .contains("authority durability barrier failed")
        );
        assert_eq!(
            fs::read(&canonical).unwrap(),
            b"preserved canonical collision"
        );
        assert_eq!(fs::read(&recovery).unwrap(), expected);
        assert!(
            !temporary
                .path()
                .join(provider_recovery_artifact_name(&sha256, 2))
                .exists(),
            "a parent-sync failure must not advance recovery slots"
        );

        let retried = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("retry reuses and re-syncs the same recovery slot");
        assert_eq!(retried.canonical_relative_path, recovery_name);
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 2);
    }

    #[test]
    fn matching_canonical_parent_sync_failure_is_not_reported_as_success() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"matching canonical response with uncertain namespace durability";
        let canonical = provider_artifact_path(temporary.path(), expected);
        write_private_test_artifact(&canonical, expected);
        #[cfg(unix)]
        fs::set_permissions(&canonical, fs::Permissions::from_mode(0o666))
            .expect("permissive canonical fixture mode");
        fail_next_provider_artifact_parent_sync();

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("matching canonical reuse must fail when its parent sync fails");

        assert!(
            error
                .to_string()
                .contains("authority durability barrier failed")
        );
        assert_eq!(fs::read(&canonical).unwrap(), expected);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
            0o666,
            "a parent-sync failure must return before permission hardening"
        );
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);

        let retried = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("matching canonical retry reattempts both durability barriers");
        assert_eq!(
            retried.canonical_relative_path,
            canonical.file_name().unwrap().to_string_lossy()
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
            0o600,
            "a successful retry hardens the same canonical object"
        );
    }

    #[test]
    fn matching_recovery_parent_sync_failure_does_not_advance_a_slot() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"matching recovery response with uncertain namespace durability";
        let sha256 = hex::encode(Sha256::digest(expected));
        let canonical = provider_artifact_path(temporary.path(), expected);
        write_private_test_artifact(&canonical, b"preserved canonical collision");
        let recovery_name = provider_recovery_artifact_name(&sha256, 1);
        let recovery = temporary.path().join(&recovery_name);
        write_private_test_artifact(&recovery, expected);
        #[cfg(unix)]
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o666))
            .expect("permissive recovery fixture mode");
        fail_next_provider_artifact_parent_sync();

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("matching recovery reuse must fail when its parent sync fails");

        assert!(
            error
                .to_string()
                .contains("authority durability barrier failed")
        );
        assert_eq!(fs::read(&recovery).unwrap(), expected);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&recovery).unwrap().permissions().mode() & 0o777,
            0o666,
            "a parent-sync failure must return before recovery-slot hardening"
        );
        assert!(
            !temporary
                .path()
                .join(provider_recovery_artifact_name(&sha256, 2))
                .exists(),
            "a matching parent-sync failure must not advance recovery slots"
        );

        let retried = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("matching recovery retry reattempts both durability barriers");
        assert_eq!(retried.canonical_relative_path, recovery_name);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&recovery).unwrap().permissions().mode() & 0o777,
            0o600,
            "a successful retry hardens the same recovery slot"
        );
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 2);
    }

    #[test]
    fn provider_recovery_slots_are_bounded_and_preserve_every_collision() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"provider response with exhausted recovery slots";
        let sha256 = hex::encode(Sha256::digest(expected));
        let canonical = provider_artifact_path(temporary.path(), expected);
        let mut preserved = Vec::<(PathBuf, Vec<u8>)>::new();

        let canonical_bytes = b"preserved canonical collision".to_vec();
        write_private_test_artifact(&canonical, &canonical_bytes);
        preserved.push((canonical, canonical_bytes));
        for slot in 1..=MAX_PROVIDER_ARTIFACT_RECOVERY_SLOTS {
            let path = temporary
                .path()
                .join(provider_recovery_artifact_name(&sha256, slot));
            let bytes = format!("preserved recovery collision {slot}").into_bytes();
            write_private_test_artifact(&path, &bytes);
            preserved.push((path, bytes));
        }
        let mut names_before = fs::read_dir(temporary.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names_before.sort();

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("exhausted recovery slots must fail closed");

        assert!(
            error
                .to_string()
                .contains(PROVIDER_ARTIFACT_RECOVERY_EXHAUSTED_ERROR)
        );
        let mut names_after = fs::read_dir(temporary.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names_after.sort();
        assert_eq!(names_after, names_before, "exhaustion must not add a file");
        for (path, bytes) in preserved {
            assert_eq!(
                fs::read(path).unwrap(),
                bytes,
                "every collision must remain byte-exact"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_matching_collision_restricts_the_verified_open_file() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"matching provider response";
        let artifact = provider_artifact_path(temporary.path(), expected);
        fs::write(&artifact, expected).expect("pre-existing provider artifact");
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o666))
            .expect("permissive fixture mode");

        ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("matching collision");

        assert_eq!(fs::read(&artifact).unwrap(), expected);
        assert_eq!(
            fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_permission_hardening_requires_a_second_file_sync() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"matching provider response requiring durable permission hardening";
        let artifact = provider_artifact_path(temporary.path(), expected);
        fs::write(&artifact, expected).expect("pre-existing provider artifact");
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o666))
            .expect("permissive fixture mode");
        fail_provider_artifact_reuse_sync_after(1);

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("post-hardening file sync failure must prevent successful reuse");

        assert!(error.to_string().contains("durability barrier failed"));
        assert_eq!(fs::read(&artifact).unwrap(), expected);
        assert_eq!(
            fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
            0o600,
            "permission hardening occurred but has not yet crossed its durability barrier"
        );
        assert_eq!(
            fs::read_dir(temporary.path()).unwrap().count(),
            1,
            "a post-hardening sync error must not publish a recovery artifact"
        );

        let retried = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("retry reestablishes both file barriers around idempotent hardening");
        assert_eq!(
            retried.canonical_relative_path,
            artifact.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(
            fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_content_mismatch_is_preserved_while_a_fresh_artifact_is_published() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"expected provider response";
        let artifact = provider_artifact_path(temporary.path(), expected);
        fs::write(&artifact, b"different existing bytes").expect("pre-existing colliding artifact");
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o666))
            .expect("permissive fixture mode");

        let reference = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("content mismatch should use a fresh backend-owned artifact");
        let repeated = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("the verified recovery artifact should be reused");

        assert_ne!(
            reference.canonical_relative_path,
            artifact.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(
            repeated.canonical_relative_path,
            reference.canonical_relative_path
        );
        assert_eq!(
            fs::read(temporary.path().join(&reference.canonical_relative_path)).unwrap(),
            expected
        );
        assert_eq!(fs::read(&artifact).unwrap(), b"different existing bytes");
        assert_eq!(
            fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
            0o666
        );
        assert_eq!(
            fs::read_dir(temporary.path()).unwrap().count(),
            2,
            "a repeated Unix collision must not append another recovery artifact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_recovery_slot_hardlink_is_rejected_without_mutating_the_external_alias() {
        let temporary = tempfile::tempdir().expect("provider artifact parent");
        let artifact_root = temporary.path().join("artifacts");
        fs::create_dir(&artifact_root).expect("provider artifact root");
        let expected = b"provider response behind a recovery hardlink";
        let sha256 = hex::encode(Sha256::digest(expected));
        let canonical = provider_artifact_path(&artifact_root, expected);
        fs::write(&canonical, b"different canonical bytes").expect("canonical collision");
        let outside = temporary.path().join("outside-recovery-alias.raw");
        fs::write(&outside, expected).expect("outside hardlink object");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o666))
            .expect("permissive outside mode");
        let recovery = artifact_root.join(provider_recovery_artifact_name(&sha256, 1));
        fs::hard_link(&outside, &recovery).expect("recovery hardlink alias");

        let error = ingest_provider_response(
            &artifact_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("a multi-link recovery slot must fail before trying another slot");

        assert!(error.to_string().contains("single-link"));
        assert_eq!(fs::read(&outside).unwrap(), expected);
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o666,
            "the external recovery alias mode must remain unchanged"
        );
        assert!(
            !artifact_root
                .join(provider_recovery_artifact_name(&sha256, 2))
                .exists(),
            "a non-content security failure must not advance to another slot"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_multilink_collision_is_rejected_without_chmod_on_the_external_alias() {
        let temporary = tempfile::tempdir().expect("provider artifact root");
        let expected = b"matching hard-linked provider response";
        let artifact = provider_artifact_path(temporary.path(), expected);
        let outside = temporary.path().join("outside-alias.raw");
        fs::write(&outside, expected).expect("outside hardlink object");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o666))
            .expect("permissive outside mode");
        fs::hard_link(&outside, &artifact).expect("artifact hardlink alias");

        let error = ingest_provider_response(
            temporary.path(),
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("a multi-link collision must fail before handle chmod");

        assert!(error.to_string().contains("single-link"));
        assert_eq!(fs::read(&outside).unwrap(), expected);
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o666,
            "the external alias mode must remain unchanged"
        );
        assert_eq!(
            fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
            0o666,
            "the artifact alias must identify the same unchanged object"
        );
    }

    #[cfg(windows)]
    fn isolated_product_root() -> (
        tempfile::TempDir,
        PathBuf,
        crate::managed_runtime::PrivateProductDataDirectoryGuard,
    ) {
        let temporary = tempfile::tempdir().expect("isolated Windows artifact parent");
        let product_root = temporary.path().join("isolated-product-data");
        let guard =
            crate::managed_runtime::ensure_private_product_data_directory_for_isolated_test(
                &product_root,
            )
            .expect("isolated private product root");
        (temporary, product_root, guard)
    }

    #[cfg(windows)]
    fn write_private_fixture(path: &Path, bytes: &[u8]) {
        let mut file = create_private_new_file(path).expect("private connector artifact");
        file.write_all(bytes).expect("write connector artifact");
        file.sync_all().expect("sync connector artifact");
    }

    #[cfg(windows)]
    #[test]
    fn windows_fresh_connector_file_has_an_exact_current_user_only_dacl() {
        let (_temporary, product_root, _guard) = isolated_product_root();
        let connector_root = product_root.join("connector-snapshots");
        fs::create_dir(&connector_root).expect("connector root");
        let expected = b"private provider response";

        let reference = ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("finalize a fresh connector artifact");
        let artifact = connector_root.join(reference.canonical_relative_path);

        assert_eq!(fs::read(&artifact).unwrap(), expected);
        crate::managed_runtime::test_verify_current_user_only_product_file(&artifact)
            .expect("fresh connector artifact must have an exact private DACL");
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_information(&artifact)
                .expect("final connector file information")
                .3,
            1,
            "direct final creation must leave exactly one name"
        );
        assert!(
            fs::read_dir(&connector_root).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("staging")),
            "direct final creation must not publish through a staging path"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_repeated_ingest_under_a_permissive_custom_parent_is_verify_only() {
        let temporary = tempfile::tempdir().expect("custom artifact authority");
        let connector_root = temporary.path().join("custom-connector-snapshots");
        fs::create_dir(&connector_root).expect("custom connector root");
        crate::managed_runtime::set_test_world_writable_product_directory_dacl(&connector_root)
            .expect("grant replacement rights on the custom parent fixture");
        let expected = b"repeatable custom provider response";

        let first = ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("fresh custom-root ingest");
        let artifact = connector_root.join(&first.canonical_relative_path);
        crate::managed_runtime::test_verify_current_user_only_product_file(&artifact)
            .expect("fresh custom-root artifact has an exact private DACL");
        let descriptor_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .expect("custom artifact descriptor before repeat");
        let information_before =
            crate::managed_runtime::test_windows_product_file_information(&artifact)
                .expect("custom artifact information before repeat");

        let second = ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("matching custom-root collision is accepted without repair authority");

        assert_eq!(
            second.canonical_relative_path,
            first.canonical_relative_path
        );
        assert_eq!(fs::read(&artifact).unwrap(), expected);
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_information(&artifact).unwrap(),
            information_before,
            "verify-only reuse must preserve identity, size, links, and attributes"
        );
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .unwrap(),
            descriptor_before,
            "verify-only reuse must not rewrite the exact private descriptor"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_custom_collision_mismatch_preserves_original_and_publishes_recovery() {
        let temporary = tempfile::tempdir().expect("custom artifact authority");
        let connector_root = temporary.path().join("custom-connector-snapshots");
        fs::create_dir(&connector_root).expect("custom connector root");
        let expected = b"expected custom provider response";
        let artifact = provider_artifact_path(&connector_root, expected);
        write_private_fixture(&artifact, b"different existing bytes");
        let descriptor_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .expect("custom collision descriptor before proof");
        let information_before =
            crate::managed_runtime::test_windows_product_file_information(&artifact)
                .expect("custom collision information before proof");

        let reference = ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("custom collision mismatch should publish a fresh private artifact");

        assert_ne!(
            reference.canonical_relative_path,
            artifact.file_name().unwrap().to_string_lossy()
        );
        let recovered = connector_root.join(&reference.canonical_relative_path);
        assert_eq!(fs::read(&recovered).unwrap(), expected);
        crate::managed_runtime::test_verify_current_user_only_product_file(&recovered)
            .expect("recovery artifact must have an exact private DACL");
        let recovered_information_before =
            crate::managed_runtime::test_windows_product_file_information(&recovered)
                .expect("recovery artifact information before reuse");
        let recovered_descriptor_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&recovered)
                .expect("recovery artifact descriptor before reuse");

        let repeated = ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("a verified Windows recovery slot should be reused");

        assert_eq!(
            repeated.canonical_relative_path,
            reference.canonical_relative_path
        );
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_information(&recovered).unwrap(),
            recovered_information_before,
            "recovery reuse must preserve the exact file object"
        );
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&recovered)
                .unwrap(),
            recovered_descriptor_before,
            "recovery reuse must preserve the exact private descriptor"
        );
        assert_eq!(
            fs::read_dir(&connector_root).unwrap().count(),
            2,
            "a repeated Windows collision must not append another recovery artifact"
        );
        assert_eq!(fs::read(&artifact).unwrap(), b"different existing bytes");
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_information(&artifact).unwrap(),
            information_before,
            "failed custom collision proof must preserve the exact file object"
        );
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .unwrap(),
            descriptor_before,
            "failed custom collision proof must not rewrite its descriptor"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_unsafe_recovery_slot_is_rejected_without_advancing_or_repairing() {
        let temporary = tempfile::tempdir().expect("custom artifact authority");
        let connector_root = temporary.path().join("custom-connector-snapshots");
        fs::create_dir(&connector_root).expect("custom connector root");
        let expected = b"expected response behind an unsafe recovery slot";
        let sha256 = hex::encode(Sha256::digest(expected));
        let canonical = provider_artifact_path(&connector_root, expected);
        write_private_fixture(&canonical, b"different existing bytes");
        let recovery = connector_root.join(provider_recovery_artifact_name(&sha256, 1));
        write_private_fixture(&recovery, expected);
        crate::managed_runtime::set_test_world_readable_product_file_dacl(&recovery)
            .expect("make the recovery slot explicitly permissive");
        let information_before =
            crate::managed_runtime::test_windows_product_file_information(&recovery)
                .expect("unsafe recovery slot information before rejected reuse");
        let descriptor_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&recovery)
                .expect("unsafe recovery slot descriptor before rejected reuse");

        let error = ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("an unsafe recovery slot must fail closed instead of advancing");

        assert!(error.to_string().contains("safely verified"));
        assert_eq!(fs::read(&canonical).unwrap(), b"different existing bytes");
        assert_eq!(fs::read(&recovery).unwrap(), expected);
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_information(&recovery).unwrap(),
            information_before,
            "rejected recovery reuse must preserve the exact file object"
        );
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&recovery)
                .unwrap(),
            descriptor_before,
            "rejected recovery reuse must not repair its descriptor"
        );
        assert!(
            !connector_root
                .join(provider_recovery_artifact_name(&sha256, 2))
                .exists(),
            "a non-content security failure must not advance to the next recovery slot"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_read_only_helper_does_not_inherit_the_durability_write_requirement() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

        let temporary = tempfile::tempdir().expect("custom artifact authority");
        let connector_root = temporary.path().join("custom-connector-snapshots");
        fs::create_dir(&connector_root).expect("custom connector root");
        let expected = b"matching response behind a read-sharing blocker";
        let artifact = provider_artifact_path(&connector_root, expected);
        write_private_fixture(&artifact, expected);
        let blocker = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&artifact)
            .expect("read-only blocker");

        crate::managed_runtime::verify_then_repair_canonical_or_verify_private_product_file_dacl(
            &artifact,
            &connector_root,
            |file| verify_provider_artifact_open_file(file, expected),
            |error| DiscoveryError::Connector(error.to_string()),
        )
        .expect("the existing read-only helper must not require data-write access");

        let error = ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("durable reuse must fail while a write-capable pinned open is blocked");
        assert!(error.to_string().contains("safely verified"));
        assert_eq!(fs::read_dir(&connector_root).unwrap().count(), 1);

        drop(blocker);
        ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect("durable reuse succeeds after write-capable pinned access is available");
    }

    #[cfg(windows)]
    #[test]
    fn windows_custom_matching_permissive_artifact_is_rejected_without_repair() {
        let temporary = tempfile::tempdir().expect("custom artifact authority");
        let connector_root = temporary.path().join("custom-connector-snapshots");
        fs::create_dir(&connector_root).expect("custom connector root");
        let expected = b"matching but non-private custom response";
        let artifact = provider_artifact_path(&connector_root, expected);
        write_private_fixture(&artifact, expected);
        crate::managed_runtime::set_test_world_readable_product_file_dacl(&artifact)
            .expect("make custom artifact explicitly permissive");
        let descriptor_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .expect("custom descriptor before rejected reuse");

        let error = ingest_provider_response(
            &connector_root,
            expected,
            "test-provider",
            Utc::now(),
            &["test-provider"],
        )
        .expect_err("custom verify-only authority must not repair a permissive artifact");

        assert!(error.to_string().contains("safely verified"));
        assert_eq!(fs::read(&artifact).unwrap(), expected);
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .unwrap(),
            descriptor_before,
            "custom-root rejection must not rewrite the artifact descriptor"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_matching_canonical_provider_file_repairs_only_its_dacl() {
        let (_temporary, product_root, _guard) = isolated_product_root();
        let connector_root = product_root.join("connector-snapshots");
        fs::create_dir(&connector_root).expect("connector root");
        let artifact = connector_root.join("provider-response.raw");
        let expected = b"matching provider response";
        write_private_fixture(&artifact, expected);
        crate::managed_runtime::set_test_world_readable_product_file_dacl(&artifact)
            .expect("make fixture explicitly permissive");
        assert!(
            crate::managed_runtime::test_verify_current_user_only_product_file(&artifact).is_err(),
            "fixture must start with an unsafe explicit ACE"
        );
        let information_before =
            crate::managed_runtime::test_windows_product_file_information(&artifact)
                .expect("file identity before repair");

        verify_and_restrict_matching_provider_artifact_in_isolated_root(
            &artifact,
            expected,
            &product_root,
        )
        .expect("matching canonical artifact DACL repair");

        assert_eq!(fs::read(&artifact).unwrap(), expected);
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_information(&artifact).unwrap(),
            information_before,
            "DACL repair must preserve identity, bytes, links, and attributes"
        );
        crate::managed_runtime::test_verify_current_user_only_product_file(&artifact)
            .expect("matching artifact has the exact repaired DACL");
    }

    #[cfg(windows)]
    #[test]
    fn windows_canonical_sync_failure_returns_before_dacl_repair() {
        let (_temporary, product_root, _guard) = isolated_product_root();
        let connector_root = product_root.join("connector-snapshots");
        fs::create_dir(&connector_root).expect("connector root");
        let artifact = connector_root.join("provider-response.raw");
        let expected = b"matching canonical response with uncertain durability";
        write_private_fixture(&artifact, expected);
        crate::managed_runtime::set_test_world_readable_product_file_dacl(&artifact)
            .expect("make fixture explicitly permissive");
        let descriptor_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .expect("descriptor before injected sync failure");
        let information_before =
            crate::managed_runtime::test_windows_product_file_information(&artifact)
                .expect("identity before injected sync failure");
        fail_next_provider_artifact_reuse_sync();

        let error = verify_and_restrict_matching_provider_artifact_in_isolated_root(
            &artifact,
            expected,
            &product_root,
        )
        .expect_err("sync failure must stop canonical DACL repair");

        assert!(error.to_string().contains("durability barrier failed"));
        assert_eq!(fs::read(&artifact).unwrap(), expected);
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_information(&artifact).unwrap(),
            information_before,
            "sync failure must preserve the exact canonical file object"
        );
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .unwrap(),
            descriptor_before,
            "sync failure must return before canonical DACL repair"
        );

        verify_and_restrict_matching_provider_artifact_in_isolated_root(
            &artifact,
            expected,
            &product_root,
        )
        .expect("a later real barrier may authorize the bounded DACL repair");
        crate::managed_runtime::test_verify_current_user_only_product_file(&artifact)
            .expect("the later successful proof repairs the canonical DACL");
    }

    #[cfg(windows)]
    #[test]
    fn windows_content_mismatch_does_not_rewrite_an_existing_dacl() {
        let (_temporary, product_root, _guard) = isolated_product_root();
        let connector_root = product_root.join("connector-snapshots");
        fs::create_dir(&connector_root).expect("connector root");
        let artifact = connector_root.join("provider-response.raw");
        write_private_fixture(&artifact, b"existing bytes");
        crate::managed_runtime::set_test_world_readable_product_file_dacl(&artifact)
            .expect("make fixture explicitly permissive");
        let descriptor_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .expect("descriptor before rejected collision");

        let error = verify_and_restrict_matching_provider_artifact_in_isolated_root(
            &artifact,
            b"different bytes",
            &product_root,
        )
        .expect_err("content mismatch must fail before DACL repair");

        assert!(error.to_string().contains("collision verification"));
        assert_eq!(fs::read(&artifact).unwrap(), b"existing bytes");
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&artifact)
                .unwrap(),
            descriptor_before,
            "content mismatch must not mutate the existing descriptor"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_arbitrary_and_multilink_files_are_preserved_without_dacl_repair() {
        let (temporary, product_root, _guard) = isolated_product_root();
        let arbitrary_root = temporary.path().join("caller-selected-data");
        fs::create_dir(&arbitrary_root).expect("arbitrary root");
        let arbitrary = arbitrary_root.join("provider-response.raw");
        write_private_fixture(&arbitrary, b"matching bytes");
        crate::managed_runtime::set_test_world_readable_product_file_dacl(&arbitrary)
            .expect("make arbitrary fixture permissive");
        let arbitrary_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&arbitrary)
                .unwrap();

        assert!(
            verify_and_restrict_matching_provider_artifact_in_isolated_root(
                &arbitrary,
                b"matching bytes",
                &product_root,
            )
            .is_err()
        );
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&arbitrary)
                .unwrap(),
            arbitrary_before,
            "arbitrary roots must never receive ACL repair"
        );

        let connector_root = product_root.join("connector-snapshots");
        fs::create_dir(&connector_root).expect("connector root");
        let linked = connector_root.join("linked.raw");
        write_private_fixture(&linked, b"matching bytes");
        let second_name = connector_root.join("second-name.raw");
        fs::hard_link(&linked, &second_name).expect("second hard link");
        crate::managed_runtime::set_test_world_readable_product_file_dacl(&linked)
            .expect("make multi-link fixture permissive");
        let linked_before =
            crate::managed_runtime::test_windows_product_file_security_descriptor(&linked).unwrap();

        assert!(
            verify_and_restrict_matching_provider_artifact_in_isolated_root(
                &linked,
                b"matching bytes",
                &product_root,
            )
            .is_err()
        );
        assert_eq!(
            crate::managed_runtime::test_windows_product_file_security_descriptor(&linked).unwrap(),
            linked_before,
            "multi-link files must never receive ACL repair"
        );
    }
}
