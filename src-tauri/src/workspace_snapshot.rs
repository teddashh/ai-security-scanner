//! Immutable, content-addressed snapshots of a user-selected local working tree.
//!
//! The snapshot intentionally represents only working-tree contents. Every entry
//! named `.git` is excluded without being opened or followed, so Git history,
//! refs, hooks, credentials, and worktree pointers are never copied. The caller
//! must obtain `selected_source_directory` through a trusted backend selection
//! flow; no destination path is accepted from the frontend.

use crate::domain::{Asset, AssetIdentifier, LocalInputProfile};
use crate::error::{AppError, AppResult};
use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

pub const WORKSPACE_SNAPSHOT_SCHEMA: &str = "ai-security-scanner.workspace-snapshot/v1";
pub const WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA: &str =
    "ai-security-scanner.workspace-snapshot-reference/v1";
pub const WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY: &str =
    "ai_security_scanner.workspace_snapshot_reference";
pub const WORKING_TREE_SEMANTICS: &str = "working_tree_only";
pub const LOCAL_INPUT_PROFILE_FILENAME: &str = ".ai-security-scanner-input.json";
pub const LOCAL_INPUT_PROFILE_SCHEMA: &str = "ai-security-scanner.local-input/v1";

const SNAPSHOT_DIRECTORY: &str = "workspace-snapshots";
const TREE_DIRECTORY: &str = "tree";
const MANIFEST_FILENAME: &str = "manifest.json";
const STORAGE_ID_PREFIX: &str = "workspace-artifact-";
const SNAPSHOT_ID_PREFIX: &str = "workspace-snapshot-sha256-";
const ASSET_ID_PREFIX: &str = "asset-workspace-sha256-";
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const HARD_MAX_FILES: usize = 200_000;
const HARD_MAX_DIRECTORIES: usize = 100_000;
const HARD_MAX_TOTAL_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const HARD_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const HARD_MAX_DEPTH: usize = 64;
const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const OCI_IMAGE_LAYER_TAR_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_MAX_LAYERS: usize = 4_096;
const OCI_MAX_TAR_ENTRIES: usize = HARD_MAX_FILES;
const OCI_MAX_UNCOMPRESSED_LAYER_BYTES: u64 = HARD_MAX_FILE_BYTES;

/// Public API name retained for the snapshot boundary; engine manifests use
/// the same domain enum so the planner and resolver cannot drift.
pub type WorkspaceInputProfile = LocalInputProfile;

/// Explicit resource limits applied before and during every copy.
///
/// `max_depth` counts nested directories below the selected root. Root-level
/// files therefore have depth zero. `max_directories` excludes the selected
/// root itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotLimits {
    pub max_files: usize,
    pub max_directories: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_depth: usize,
}

impl Default for WorkspaceSnapshotLimits {
    fn default() -> Self {
        Self {
            max_files: 50_000,
            max_directories: 10_000,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_file_bytes: 512 * 1024 * 1024,
            max_depth: 32,
        }
    }
}

impl WorkspaceSnapshotLimits {
    fn validate(self) -> AppResult<Self> {
        if self.max_files == 0
            || self.max_total_bytes == 0
            || self.max_file_bytes == 0
            || self.max_files > HARD_MAX_FILES
            || self.max_directories > HARD_MAX_DIRECTORIES
            || self.max_total_bytes > HARD_MAX_TOTAL_BYTES
            || self.max_file_bytes > HARD_MAX_FILE_BYTES
            || self.max_depth > HARD_MAX_DEPTH
        {
            return Err(AppError::InvalidRequest(
                "workspace snapshot limits are zero or exceed the built-in safety ceiling".into(),
            ));
        }
        Ok(self)
    }
}

/// One deterministic manifest entry. Paths are normalized UTF-8 paths using
/// `/` separators and are relative to the copied tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotFile {
    pub relative_path: String,
    pub byte_length: u64,
    pub sha256: String,
}

/// Canonical manifest bytes are compact JSON serialization of this structure.
/// No timestamp, host path, random identifier, or filesystem metadata enters
/// the manifest, making its SHA-256 stable for identical working-tree content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotManifest {
    pub schema_version: String,
    pub content_semantics: String,
    #[serde(default, skip_serializing_if = "WorkspaceInputProfile::is_repository")]
    pub input_profile: WorkspaceInputProfile,
    pub excluded_entries: Vec<String>,
    pub directories: Vec<String>,
    pub files: Vec<WorkspaceSnapshotFile>,
    pub directory_count: usize,
    pub file_count: usize,
    pub total_bytes: u64,
}

/// Safe persisted locator. Storage paths are always derived by the backend
/// from `case_id` and this generated `storage_id`; callers cannot persist or
/// later inject an arbitrary host path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotReference {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "WorkspaceInputProfile::is_repository")]
    pub input_profile: WorkspaceInputProfile,
    pub storage_id: String,
    pub snapshot_id: String,
    pub sha256: String,
    pub directory_count: usize,
    pub file_count: usize,
    pub total_bytes: u64,
    pub working_tree_only: bool,
}

#[derive(Debug, Clone)]
pub struct WorkspaceSnapshot {
    pub reference: WorkspaceSnapshotReference,
    pub manifest: WorkspaceSnapshotManifest,
    pub asset: Asset,
}

/// A verified backend path suitable for a read-only container bind mount.
#[derive(Debug, Clone)]
pub struct ResolvedWorkspaceSnapshot {
    pub tree_path: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest: WorkspaceSnapshotManifest,
}

/// Copies a selected directory into a private backend-owned artifact location.
///
/// The final storage identity is reserved with create-new directory semantics,
/// and the complete staging directory is moved beneath that identity in one
/// rename. Thus an existing artifact is never overwritten and no reference is
/// returned until the complete payload has been atomically published.
pub fn create_workspace_snapshot(
    artifact_root: impl AsRef<Path>,
    case_id: &str,
    source_id: &str,
    selected_source_directory: impl AsRef<Path>,
    limits: WorkspaceSnapshotLimits,
) -> AppResult<WorkspaceSnapshot> {
    create_workspace_snapshot_with_profile(
        artifact_root,
        case_id,
        source_id,
        selected_source_directory,
        WorkspaceInputProfile::RepositoryWorkingTree,
        limits,
    )
}

/// Copies one explicitly typed local input into the same immutable snapshot
/// boundary used by repository scans. The profile is backend-authored and
/// content-addressed so a scanner cannot reinterpret a repository as an image,
/// node snapshot, or Kubernetes manifest set.
pub fn create_workspace_snapshot_with_profile(
    artifact_root: impl AsRef<Path>,
    case_id: &str,
    source_id: &str,
    selected_source_directory: impl AsRef<Path>,
    input_profile: WorkspaceInputProfile,
    limits: WorkspaceSnapshotLimits,
) -> AppResult<WorkspaceSnapshot> {
    validate_safe_id("case id", case_id)?;
    validate_safe_id("source id", source_id)?;
    let limits = limits.validate()?;
    let artifact_root = prepare_existing_directory(artifact_root.as_ref(), "artifact root")?;
    let selected_source = prepare_selected_source(selected_source_directory.as_ref())?;

    if selected_source.starts_with(&artifact_root) || artifact_root.starts_with(&selected_source) {
        return Err(AppError::InvalidRequest(
            "selected working tree and artifact root must not overlap".into(),
        ));
    }
    validate_selected_input_profile(&selected_source, input_profile)?;

    let case_directory = ensure_private_child_directory(&artifact_root, case_id)?;
    let snapshots_directory = ensure_private_child_directory(&case_directory, SNAPSHOT_DIRECTORY)?;
    let staging_id = format!(".workspace-staging-{}", Uuid::new_v4().simple());
    let staging_path = create_private_generated_directory(&snapshots_directory, &staging_id)?;
    let mut cleanup = SnapshotCleanup::new(staging_path.clone());
    let tree_path = staging_path.join(TREE_DIRECTORY);
    create_private_directory(&tree_path)?;

    let mut copy_state = CopyState::default();
    copy_directory(
        &selected_source,
        &tree_path,
        &[],
        0,
        &selected_source,
        limits,
        &mut copy_state,
    )?;
    validate_copied_input_files(&tree_path, &copy_state, input_profile)?;
    if !input_profile.is_repository() {
        write_input_profile_marker(&tree_path, input_profile, limits, &mut copy_state)?;
    }

    copy_state.directories.sort();
    copy_state.files.sort_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });
    let manifest = WorkspaceSnapshotManifest {
        schema_version: WORKSPACE_SNAPSHOT_SCHEMA.into(),
        content_semantics: WORKING_TREE_SEMANTICS.into(),
        input_profile,
        excluded_entries: vec![".git".into()],
        directory_count: copy_state.directories.len(),
        file_count: copy_state.files.len(),
        total_bytes: copy_state.total_bytes,
        directories: copy_state.directories,
        files: copy_state.files,
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
        AppError::Internal(format!(
            "workspace snapshot manifest could not be encoded: {error}"
        ))
    })?;
    if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(AppError::Runtime(
            "workspace snapshot manifest exceeded its safety limit".into(),
        ));
    }
    let snapshot_sha256 = sha256_bytes(&manifest_bytes);
    let manifest_path = staging_path.join(MANIFEST_FILENAME);
    write_private_readonly_file(&manifest_path, &manifest_bytes)?;
    sync_directory(&tree_path)?;
    sync_directory(&staging_path)?;
    make_snapshot_tree_readonly(&tree_path)?;

    let storage_id = format!("{STORAGE_ID_PREFIX}{}", Uuid::new_v4().simple());
    let final_container = create_private_generated_directory(&snapshots_directory, &storage_id)?;
    cleanup.track_final(final_container.clone());
    let final_payload = final_container.join("payload");
    fs::rename(&staging_path, &final_payload).map_err(|error| {
        AppError::Runtime(format!(
            "workspace snapshot could not be atomically finalized without overwrite: {error}"
        ))
    })?;
    cleanup.staging_moved();
    set_readonly_directory(&final_payload)?;
    set_readonly_directory(&final_container)?;
    sync_directory(&final_container)?;
    sync_directory(&snapshots_directory)?;

    let snapshot_id = format!("{SNAPSHOT_ID_PREFIX}{snapshot_sha256}");
    let reference = WorkspaceSnapshotReference {
        schema_version: WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA.into(),
        input_profile,
        storage_id,
        snapshot_id: snapshot_id.clone(),
        sha256: snapshot_sha256.clone(),
        directory_count: manifest.directory_count,
        file_count: manifest.file_count,
        total_bytes: manifest.total_bytes,
        working_tree_only: true,
    };
    let asset = snapshot_asset(source_id, &snapshot_id, &snapshot_sha256, input_profile);
    cleanup.disarm();

    Ok(WorkspaceSnapshot {
        reference,
        manifest,
        asset,
    })
}

/// Resolves and fully verifies a stored snapshot before execution.
///
/// The manifest hash, all directory names, every file size/hash, and aggregate
/// counts are checked. Symlinks and special files fail closed. The returned path
/// is never taken from persisted case data; it is derived from validated IDs.
pub fn resolve_workspace_snapshot(
    artifact_root: impl AsRef<Path>,
    case_id: &str,
    reference: &WorkspaceSnapshotReference,
) -> AppResult<ResolvedWorkspaceSnapshot> {
    validate_safe_id("case id", case_id)?;
    validate_reference(reference)?;
    let artifact_root = prepare_existing_directory(artifact_root.as_ref(), "artifact root")?;
    let case_directory = resolve_real_child_directory(&artifact_root, case_id)?;
    let snapshots_directory = resolve_real_child_directory(&case_directory, SNAPSHOT_DIRECTORY)?;
    let final_container =
        resolve_real_child_directory(&snapshots_directory, &reference.storage_id)?;
    let payload = resolve_real_child_directory(&final_container, "payload")?;
    let tree_path = resolve_real_child_directory(&payload, TREE_DIRECTORY)?;
    let manifest_path = resolve_real_regular_file(&payload, MANIFEST_FILENAME)?;
    let manifest_bytes = read_bounded_stable_file(&manifest_path, MAX_MANIFEST_BYTES)?;
    let actual_manifest_sha256 = sha256_bytes(&manifest_bytes);
    if actual_manifest_sha256 != reference.sha256 {
        return Err(AppError::Runtime(
            "workspace snapshot manifest failed its SHA-256 integrity check".into(),
        ));
    }
    let manifest: WorkspaceSnapshotManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            AppError::Runtime(format!("workspace snapshot manifest is invalid: {error}"))
        })?;
    validate_manifest(&manifest, reference)?;

    let verification_limits = WorkspaceSnapshotLimits {
        max_files: reference.file_count.max(1),
        max_directories: reference.directory_count,
        max_total_bytes: reference.total_bytes.max(1),
        max_file_bytes: reference.total_bytes.clamp(1, HARD_MAX_FILE_BYTES),
        max_depth: HARD_MAX_DEPTH,
    };
    let mut observed = VerificationState::default();
    verify_directory(
        &tree_path,
        &[],
        0,
        &tree_path,
        verification_limits,
        &mut observed,
    )?;
    observed.directories.sort();
    observed.files.sort_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });
    if observed.directories != manifest.directories || observed.files != manifest.files {
        return Err(AppError::Runtime(
            "workspace snapshot contents do not match the immutable manifest".into(),
        ));
    }
    validate_resolved_input_profile(&tree_path, reference.input_profile)?;

    Ok(ResolvedWorkspaceSnapshot {
        tree_path,
        manifest_path,
        manifest,
    })
}

#[derive(Default)]
struct CopyState {
    directories: Vec<String>,
    files: Vec<WorkspaceSnapshotFile>,
    total_bytes: u64,
}

#[derive(Default)]
struct VerificationState {
    directories: Vec<String>,
    files: Vec<WorkspaceSnapshotFile>,
    total_bytes: u64,
}

fn copy_directory(
    source_directory: &Path,
    destination_directory: &Path,
    relative_components: &[String],
    depth: usize,
    source_root: &Path,
    limits: WorkspaceSnapshotLimits,
    state: &mut CopyState,
) -> AppResult<()> {
    let before = inspect_real_directory(source_directory, source_root)?;
    let entries = sorted_directory_entries(
        source_directory,
        limits
            .max_files
            .saturating_add(limits.max_directories)
            .saturating_add(1),
    )?;
    for (name, source_path) in entries {
        if name.eq_ignore_ascii_case(".git") {
            continue;
        }
        let mut components = relative_components.to_vec();
        components.push(name.clone());
        let relative_path = normalized_relative_path(&components)?;
        let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
            AppError::Runtime(format!(
                "selected working-tree entry could not be inspected: {error}"
            ))
        })?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(AppError::InvalidRequest(format!(
                "selected working tree contains a symlink at {relative_path}"
            )));
        }
        if file_type.is_dir() {
            if depth >= limits.max_depth {
                return Err(AppError::InvalidRequest(format!(
                    "selected working tree exceeds the maximum directory depth at {relative_path}"
                )));
            }
            if state.directories.len() >= limits.max_directories {
                return Err(AppError::InvalidRequest(
                    "selected working tree exceeds the directory-count limit".into(),
                ));
            }
            let destination = destination_directory.join(&name);
            create_private_directory(&destination)?;
            state.directories.push(relative_path);
            copy_directory(
                &source_path,
                &destination,
                &components,
                depth + 1,
                source_root,
                limits,
                state,
            )?;
        } else if file_type.is_file() {
            if state.files.len() >= limits.max_files {
                return Err(AppError::InvalidRequest(
                    "selected working tree exceeds the file-count limit".into(),
                ));
            }
            let copied = copy_regular_file(
                &source_path,
                &destination_directory.join(&name),
                &relative_path,
                source_root,
                limits,
                state.total_bytes,
            )?;
            state.total_bytes = state
                .total_bytes
                .checked_add(copied.byte_length)
                .ok_or_else(|| {
                    AppError::Runtime("workspace snapshot byte count overflowed".into())
                })?;
            state.files.push(copied);
        } else {
            return Err(AppError::InvalidRequest(format!(
                "selected working tree contains a device, FIFO, or socket at {relative_path}"
            )));
        }
    }
    let after = inspect_real_directory(source_directory, source_root)?;
    if before != after {
        return Err(AppError::Runtime(
            "selected working-tree directory changed while it was being copied".into(),
        ));
    }
    Ok(())
}

fn copy_regular_file(
    source_path: &Path,
    destination_path: &Path,
    relative_path: &str,
    source_root: &Path,
    limits: WorkspaceSnapshotLimits,
    total_before: u64,
) -> AppResult<WorkspaceSnapshotFile> {
    ensure_canonical_inside(source_path, source_root)?;
    let path_metadata = fs::symlink_metadata(source_path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(AppError::InvalidRequest(format!(
            "selected working-tree entry is not a regular file at {relative_path}"
        )));
    }
    let mut source = open_readonly_nofollow(source_path).map_err(|error| {
        AppError::Runtime(format!(
            "selected working-tree file could not be opened without following links at {relative_path}: {error}"
        ))
    })?;
    let opened_metadata = source.metadata()?;
    if !opened_metadata.is_file() {
        return Err(AppError::InvalidRequest(format!(
            "selected working-tree entry is not a regular file at {relative_path}"
        )));
    }
    let initial = FileFingerprint::from_metadata(&opened_metadata);
    if initial != FileFingerprint::from_metadata(&path_metadata) {
        return Err(changed_file_error(relative_path));
    }
    if initial.byte_length > limits.max_file_bytes
        || initial.byte_length > limits.max_total_bytes.saturating_sub(total_before)
    {
        return Err(AppError::InvalidRequest(format!(
            "selected working-tree file exceeds its byte limit at {relative_path}"
        )));
    }

    let mut destination = create_private_new_file(destination_path)?;
    let mut digest = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read as u64).ok_or_else(|| {
            AppError::Runtime("workspace snapshot file byte count overflowed".into())
        })?;
        if copied > limits.max_file_bytes
            || copied > limits.max_total_bytes.saturating_sub(total_before)
        {
            return Err(AppError::InvalidRequest(format!(
                "selected working-tree file exceeded its byte limit while copying at {relative_path}"
            )));
        }
        destination.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
    }
    destination.sync_all()?;
    let after_copy = FileFingerprint::from_metadata(&source.metadata()?);
    if copied != initial.byte_length || initial != after_copy {
        return Err(changed_file_error(relative_path));
    }

    // A second read prevents a same-length content change from being accepted
    // merely because a platform exposes coarse modification timestamps.
    source.seek(SeekFrom::Start(0))?;
    let before_verify = FileFingerprint::from_metadata(&source.metadata()?);
    let mut verify_digest = Sha256::new();
    let mut verified_bytes = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        verified_bytes = verified_bytes.checked_add(read as u64).ok_or_else(|| {
            AppError::Runtime("workspace snapshot verification byte count overflowed".into())
        })?;
        if verified_bytes > limits.max_file_bytes {
            return Err(changed_file_error(relative_path));
        }
        verify_digest.update(&buffer[..read]);
    }
    let after_verify = FileFingerprint::from_metadata(&source.metadata()?);
    let final_path_metadata =
        fs::symlink_metadata(source_path).map_err(|_| changed_file_error(relative_path))?;
    let verified_digest = verify_digest.finalize();
    let copied_digest = digest.clone().finalize();
    if before_verify != after_verify
        || initial != after_verify
        || after_verify != FileFingerprint::from_metadata(&final_path_metadata)
        || verified_bytes != copied
        || verified_digest != copied_digest
    {
        return Err(changed_file_error(relative_path));
    }
    drop(destination);
    set_readonly_file(destination_path)?;

    Ok(WorkspaceSnapshotFile {
        relative_path: relative_path.into(),
        byte_length: copied,
        sha256: hex::encode(digest.finalize()),
    })
}

fn verify_directory(
    directory: &Path,
    relative_components: &[String],
    depth: usize,
    tree_root: &Path,
    limits: WorkspaceSnapshotLimits,
    state: &mut VerificationState,
) -> AppResult<()> {
    let before = inspect_real_directory(directory, tree_root)?;
    for (name, path) in sorted_directory_entries(
        directory,
        limits
            .max_files
            .saturating_add(limits.max_directories)
            .saturating_add(1),
    )? {
        let mut components = relative_components.to_vec();
        components.push(name.clone());
        let relative_path = normalized_relative_path(&components)?;
        if name.eq_ignore_ascii_case(".git") {
            return Err(AppError::Runtime(
                "stored working-tree snapshot contains excluded Git metadata".into(),
            ));
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(AppError::Runtime(
                "stored working-tree snapshot contains a symlink".into(),
            ));
        }
        if metadata.is_dir() {
            if depth >= limits.max_depth || state.directories.len() >= limits.max_directories {
                return Err(AppError::Runtime(
                    "stored working-tree snapshot exceeds its directory bounds".into(),
                ));
            }
            state.directories.push(relative_path);
            verify_directory(&path, &components, depth + 1, tree_root, limits, state)?;
        } else if metadata.is_file() {
            if state.files.len() >= limits.max_files {
                return Err(AppError::Runtime(
                    "stored working-tree snapshot exceeds its file bound".into(),
                ));
            }
            let remaining = limits.max_total_bytes.saturating_sub(state.total_bytes);
            let (sha256, byte_length) =
                hash_bounded_stable_file(&path, remaining.min(HARD_MAX_FILE_BYTES))?;
            state.total_bytes = state
                .total_bytes
                .checked_add(byte_length)
                .ok_or_else(|| AppError::Runtime("snapshot byte count overflowed".into()))?;
            state.files.push(WorkspaceSnapshotFile {
                relative_path,
                byte_length,
                sha256,
            });
        } else {
            return Err(AppError::Runtime(
                "stored working-tree snapshot contains an unsupported filesystem entry".into(),
            ));
        }
    }
    let after = inspect_real_directory(directory, tree_root)?;
    if before != after {
        return Err(AppError::Runtime(
            "stored workspace snapshot changed during verification".into(),
        ));
    }
    Ok(())
}

fn validate_reference(reference: &WorkspaceSnapshotReference) -> AppResult<()> {
    if reference.schema_version != WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA
        || !reference.working_tree_only
        || !valid_storage_id(&reference.storage_id)
        || !valid_sha256(&reference.sha256)
        || reference.snapshot_id != format!("{SNAPSHOT_ID_PREFIX}{}", reference.sha256)
        || reference.file_count > HARD_MAX_FILES
        || reference.directory_count > HARD_MAX_DIRECTORIES
        || reference.total_bytes > HARD_MAX_TOTAL_BYTES
    {
        return Err(AppError::InvalidRequest(
            "workspace snapshot reference is invalid or exceeds safety bounds".into(),
        ));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &WorkspaceSnapshotManifest,
    reference: &WorkspaceSnapshotReference,
) -> AppResult<()> {
    let totals_match = manifest.directory_count == manifest.directories.len()
        && manifest.file_count == manifest.files.len()
        && manifest.directory_count == reference.directory_count
        && manifest.file_count == reference.file_count
        && manifest.total_bytes == reference.total_bytes;
    if manifest.schema_version != WORKSPACE_SNAPSHOT_SCHEMA
        || manifest.content_semantics != WORKING_TREE_SEMANTICS
        || manifest.input_profile != reference.input_profile
        || manifest.excluded_entries != [".git"]
        || !totals_match
    {
        return Err(AppError::Runtime(
            "workspace snapshot manifest metadata is inconsistent".into(),
        ));
    }
    let mut previous_directory: Option<&str> = None;
    for directory in &manifest.directories {
        validate_normalized_relative_path(directory)?;
        if previous_directory.is_some_and(|previous| previous.as_bytes() >= directory.as_bytes()) {
            return Err(AppError::Runtime(
                "workspace snapshot manifest directories are not uniquely sorted".into(),
            ));
        }
        previous_directory = Some(directory);
    }
    let mut total_bytes = 0_u64;
    let mut previous_file: Option<&str> = None;
    for file in &manifest.files {
        validate_normalized_relative_path(&file.relative_path)?;
        if !valid_sha256(&file.sha256)
            || previous_file
                .is_some_and(|previous| previous.as_bytes() >= file.relative_path.as_bytes())
        {
            return Err(AppError::Runtime(
                "workspace snapshot manifest files are invalid or not uniquely sorted".into(),
            ));
        }
        total_bytes = total_bytes.checked_add(file.byte_length).ok_or_else(|| {
            AppError::Runtime("workspace snapshot manifest byte count overflowed".into())
        })?;
        previous_file = Some(&file.relative_path);
    }
    if total_bytes != manifest.total_bytes {
        return Err(AppError::Runtime(
            "workspace snapshot manifest aggregate byte count is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_selected_input_profile(
    selected_source: &Path,
    input_profile: WorkspaceInputProfile,
) -> AppResult<()> {
    match fs::symlink_metadata(selected_source.join(LOCAL_INPUT_PROFILE_FILENAME)) {
        Ok(_) => {
            return Err(AppError::InvalidRequest(format!(
                "selected local input contains the reserved backend marker {LOCAL_INPUT_PROFILE_FILENAME}"
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(AppError::InvalidRequest(format!(
                "selected local input marker path could not be inspected: {error}"
            )));
        }
    }

    if input_profile == WorkspaceInputProfile::KubernetesNodeSnapshot {
        let node_root = selected_source.join("node-snapshot");
        let metadata = fs::symlink_metadata(&node_root).map_err(|error| {
            AppError::InvalidRequest(format!(
                "Kubernetes node input must contain a node-snapshot directory: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AppError::InvalidRequest(
                "Kubernetes node input must contain a real node-snapshot directory".into(),
            ));
        }
    }
    Ok(())
}

fn validate_resolved_input_profile(
    tree_path: &Path,
    input_profile: WorkspaceInputProfile,
) -> AppResult<()> {
    let marker_path = tree_path.join(LOCAL_INPUT_PROFILE_FILENAME);
    if input_profile.is_repository() {
        return match fs::symlink_metadata(marker_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(AppError::Runtime(
                "repository snapshot contains a reserved local input profile marker".into(),
            )),
        };
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Marker {
        schema_version: String,
        input_profile: WorkspaceInputProfile,
    }

    let bytes = read_bounded_stable_file(&marker_path, 4 * 1024)?;
    let marker: Marker = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Runtime("local input profile marker is invalid".into()))?;
    if marker.schema_version != LOCAL_INPUT_PROFILE_SCHEMA || marker.input_profile != input_profile
    {
        return Err(AppError::Runtime(
            "local input profile marker conflicts with its backend reference".into(),
        ));
    }
    Ok(())
}

fn validate_copied_input_files(
    tree_path: &Path,
    state: &CopyState,
    input_profile: WorkspaceInputProfile,
) -> AppResult<()> {
    let has_extension = |extensions: &[&str]| {
        state.files.iter().any(|file| {
            Path::new(&file.relative_path)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extensions
                        .iter()
                        .any(|expected| extension.eq_ignore_ascii_case(expected))
                })
        })
    };
    match input_profile {
        WorkspaceInputProfile::RepositoryWorkingTree => Ok(()),
        WorkspaceInputProfile::IacWorkingTree if !has_extension(&["tf", "json", "yaml", "yml"]) => {
            Err(AppError::InvalidRequest(
                "infrastructure-as-code input contains no .tf, .json, .yaml, or .yml file".into(),
            ))
        }
        WorkspaceInputProfile::KubernetesManifests if !has_extension(&["json", "yaml", "yml"]) => {
            Err(AppError::InvalidRequest(
                "Kubernetes manifest input contains no .json, .yaml, or .yml file".into(),
            ))
        }
        WorkspaceInputProfile::ContainerImageOciLayout => validate_oci_image_layout(tree_path),
        WorkspaceInputProfile::KubernetesNodeSnapshot => {
            let profile_path = tree_path.join("node-snapshot/profile.json");
            let bytes = read_bounded_stable_file(&profile_path, 256 * 1024).map_err(|_| {
                AppError::InvalidRequest(
                    "Kubernetes node input requires node-snapshot/profile.json".into(),
                )
            })?;
            let profile: Value = serde_json::from_slice(&bytes).map_err(|_| {
                AppError::InvalidRequest(
                    "Kubernetes node snapshot profile.json is not valid JSON".into(),
                )
            })?;
            if profile.get("schema_version").and_then(Value::as_str) != Some("1.0.0")
                || profile.get("profile").and_then(Value::as_str)
                    != Some("cis-kubernetes-node-config")
            {
                return Err(AppError::InvalidRequest(
                    "Kubernetes node snapshot profile identity is invalid".into(),
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_oci_image_layout(tree_path: &Path) -> AppResult<()> {
    let layout = read_bounded_json(tree_path, "oci-layout", 64 * 1024)?;
    if layout.get("imageLayoutVersion").and_then(Value::as_str) != Some("1.0.0") {
        return Err(AppError::InvalidRequest(
            "OCI image layout must declare imageLayoutVersion 1.0.0".into(),
        ));
    }
    let index = read_bounded_json(tree_path, "index.json", 16 * 1024 * 1024)?;
    if index.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(AppError::InvalidRequest(
            "OCI image index must use schemaVersion 2".into(),
        ));
    }
    require_oci_json_media_type(&index, OCI_IMAGE_INDEX_MEDIA_TYPE, "image index")?;
    let manifests = index
        .get("manifests")
        .and_then(Value::as_array)
        .filter(|manifests| manifests.len() == 1)
        .ok_or_else(|| {
            AppError::InvalidRequest(
                "OCI image layout must select exactly one image manifest".into(),
            )
        })?;
    require_oci_descriptor_media_type(
        &manifests[0],
        &[OCI_IMAGE_MANIFEST_MEDIA_TYPE],
        "image manifest",
    )?;
    let mut referenced_blobs = BTreeSet::new();
    referenced_blobs.insert(oci_descriptor_digest(&manifests[0])?.to_owned());
    let manifest_bytes = verify_oci_descriptor(tree_path, &manifests[0], 16 * 1024 * 1024)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| AppError::InvalidRequest("OCI image manifest is not valid JSON".into()))?;
    if manifest.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(AppError::InvalidRequest(
            "OCI image manifest must use schemaVersion 2".into(),
        ));
    }
    require_oci_json_media_type(&manifest, OCI_IMAGE_MANIFEST_MEDIA_TYPE, "image manifest")?;
    let config = manifest.get("config").ok_or_else(|| {
        AppError::InvalidRequest("OCI image manifest has no config descriptor".into())
    })?;
    require_oci_descriptor_media_type(config, &[OCI_IMAGE_CONFIG_MEDIA_TYPE], "image config")?;
    referenced_blobs.insert(oci_descriptor_digest(config)?.to_owned());
    let config_bytes = verify_oci_descriptor(tree_path, config, 16 * 1024 * 1024)?;
    let config: Value = serde_json::from_slice(&config_bytes)
        .map_err(|_| AppError::InvalidRequest("OCI image config is not valid JSON".into()))?;
    validate_oci_platform(&config)?;
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .filter(|layers| layers.len() <= OCI_MAX_LAYERS)
        .ok_or_else(|| {
            AppError::InvalidRequest("OCI image layer inventory is invalid or unbounded".into())
        })?;
    let diff_ids = config
        .get("rootfs")
        .and_then(Value::as_object)
        .filter(|rootfs| rootfs.get("type").and_then(Value::as_str) == Some("layers"))
        .and_then(|rootfs| rootfs.get("diff_ids"))
        .and_then(Value::as_array)
        .filter(|diff_ids| diff_ids.len() == layers.len())
        .ok_or_else(|| {
            AppError::InvalidRequest(
                "OCI image config rootfs diff_ids do not match its layer inventory".into(),
            )
        })?;
    let mut tar_entries = 0_usize;
    for (layer, diff_id) in layers.iter().zip(diff_ids) {
        let media_type = require_oci_descriptor_media_type(
            layer,
            &[
                OCI_IMAGE_LAYER_TAR_MEDIA_TYPE,
                OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE,
            ],
            "image layer",
        )?;
        referenced_blobs.insert(oci_descriptor_digest(layer)?.to_owned());
        let bytes = verify_oci_descriptor(tree_path, layer, HARD_MAX_FILE_BYTES)?;
        let expected_diff_id = diff_id
            .as_str()
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .filter(|digest| valid_sha256(digest))
            .ok_or_else(|| {
                AppError::InvalidRequest(
                    "OCI image config contains an invalid layer diff_id".into(),
                )
            })?;
        validate_oci_layer_tar(&bytes, media_type, expected_diff_id, &mut tar_entries)?;
    }
    validate_exact_oci_blob_inventory(tree_path, &referenced_blobs)?;
    Ok(())
}

fn require_oci_json_media_type<'a>(
    value: &'a Value,
    expected: &str,
    kind: &str,
) -> AppResult<&'a str> {
    value
        .get("mediaType")
        .and_then(Value::as_str)
        .filter(|media_type| *media_type == expected)
        .ok_or_else(|| AppError::InvalidRequest(format!("OCI {kind} mediaType is invalid")))
}

fn require_oci_descriptor_media_type<'a>(
    descriptor: &'a Value,
    allowed: &[&str],
    kind: &str,
) -> AppResult<&'a str> {
    descriptor
        .get("mediaType")
        .and_then(Value::as_str)
        .filter(|media_type| allowed.contains(media_type))
        .ok_or_else(|| {
            AppError::InvalidRequest(format!("OCI {kind} descriptor mediaType is invalid"))
        })
}

fn oci_descriptor_digest(descriptor: &Value) -> AppResult<&str> {
    descriptor
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| valid_sha256(digest))
        .ok_or_else(|| AppError::InvalidRequest("OCI descriptor has an invalid digest".into()))
}

fn validate_oci_platform(config: &Value) -> AppResult<()> {
    for key in ["architecture", "os"] {
        let valid = config
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| {
                !value.is_empty()
                    && value.len() <= 64
                    && value.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'.' | b'-')
                    })
            });
        if !valid {
            return Err(AppError::InvalidRequest(format!(
                "OCI image config {key} is invalid"
            )));
        }
    }
    Ok(())
}

fn validate_oci_layer_tar(
    bytes: &[u8],
    media_type: &str,
    expected_diff_id: &str,
    total_entries: &mut usize,
) -> AppResult<()> {
    if media_type == OCI_IMAGE_LAYER_TAR_MEDIA_TYPE {
        if sha256_bytes(bytes) != expected_diff_id {
            return Err(AppError::InvalidRequest(
                "OCI image layer does not match its config diff_id".into(),
            ));
        }
        inspect_oci_tar(Cursor::new(bytes), total_entries)?;
        return Ok(());
    }

    let reader =
        DigestingBoundedReader::new(MultiGzDecoder::new(bytes), OCI_MAX_UNCOMPRESSED_LAYER_BYTES);
    let reader = inspect_oci_tar(reader, total_entries)?;
    let (actual_diff_id, _) = reader.finish()?;
    if actual_diff_id != expected_diff_id {
        return Err(AppError::InvalidRequest(
            "OCI image layer does not match its config diff_id".into(),
        ));
    }
    Ok(())
}

fn inspect_oci_tar<R: Read>(reader: R, total_entries: &mut usize) -> AppResult<R> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive.entries().map_err(|_| {
        AppError::InvalidRequest("OCI image layer is not a valid tar archive".into())
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|_| {
            AppError::InvalidRequest("OCI image layer contains an invalid tar entry".into())
        })?;
        *total_entries = total_entries.checked_add(1).ok_or_else(|| {
            AppError::InvalidRequest("OCI image layer entry count overflowed".into())
        })?;
        if *total_entries > OCI_MAX_TAR_ENTRIES || entry.size() > HARD_MAX_FILE_BYTES {
            return Err(AppError::InvalidRequest(
                "OCI image layer tar inventory exceeds its safety bound".into(),
            ));
        }
        let path = entry.path().map_err(|_| {
            AppError::InvalidRequest("OCI image layer contains an invalid tar path".into())
        })?;
        if path.as_os_str().is_empty()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(AppError::InvalidRequest(
                "OCI image layer contains a path outside its root".into(),
            ));
        }
        io::copy(&mut entry, &mut io::sink()).map_err(|_| {
            AppError::InvalidRequest("OCI image layer tar payload is invalid or unbounded".into())
        })?;
    }
    let mut reader = archive.into_inner();
    io::copy(&mut reader, &mut io::sink()).map_err(|_| {
        AppError::InvalidRequest("OCI image layer tar trailer is invalid or unbounded".into())
    })?;
    Ok(reader)
}

struct DigestingBoundedReader<R> {
    inner: R,
    digest: Sha256,
    bytes_read: u64,
    limit: u64,
}

impl<R> DigestingBoundedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes_read: 0,
            limit,
        }
    }

    fn finish(self) -> AppResult<(String, u64)> {
        Ok((hex::encode(self.digest.finalize()), self.bytes_read))
    }
}

impl<R: Read> Read for DigestingBoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.bytes_read);
        let request = buffer
            .len()
            .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(buffer.len()));
        let read = self.inner.read(&mut buffer[..request])?;
        if u64::try_from(read).unwrap_or(u64::MAX) > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OCI image layer exceeds its uncompressed byte limit",
            ));
        }
        self.digest.update(&buffer[..read]);
        self.bytes_read = self.bytes_read.saturating_add(read as u64);
        Ok(read)
    }
}

fn validate_exact_oci_blob_inventory(root: &Path, expected: &BTreeSet<String>) -> AppResult<()> {
    let blob_root = root.join("blobs").join("sha256");
    ensure_canonical_inside(&blob_root, root).map_err(|_| {
        AppError::InvalidRequest("OCI image blob directory is missing or unsafe".into())
    })?;
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&blob_root).map_err(|_| {
        AppError::InvalidRequest("OCI image blob directory cannot be enumerated".into())
    })? {
        let entry = entry.map_err(|_| {
            AppError::InvalidRequest("OCI image blob directory contains an invalid entry".into())
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            AppError::InvalidRequest("OCI image blob name is not valid UTF-8".into())
        })?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| AppError::InvalidRequest("OCI image blob cannot be inspected".into()))?;
        if !valid_sha256(&name) || !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AppError::InvalidRequest(
                "OCI image blob inventory contains an unsafe entry".into(),
            ));
        }
        actual.insert(name);
    }
    if &actual != expected {
        return Err(AppError::InvalidRequest(
            "OCI image layout contains missing or unreferenced blobs".into(),
        ));
    }
    Ok(())
}

fn read_bounded_json(root: &Path, relative_path: &str, max_bytes: u64) -> AppResult<Value> {
    let path = root.join(relative_path);
    ensure_canonical_inside(&path, root).map_err(|_| {
        AppError::InvalidRequest(format!(
            "local input is missing a safe regular {relative_path}"
        ))
    })?;
    let bytes = read_bounded_stable_file(&path, max_bytes).map_err(|_| {
        AppError::InvalidRequest(format!(
            "local input is missing a bounded regular {relative_path}"
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        AppError::InvalidRequest(format!("local input {relative_path} is not valid JSON"))
    })
}

fn verify_oci_descriptor(root: &Path, descriptor: &Value, max_bytes: u64) -> AppResult<Vec<u8>> {
    let digest = oci_descriptor_digest(descriptor)?;
    let expected_size = descriptor
        .get("size")
        .and_then(Value::as_u64)
        .filter(|size| *size > 0 && *size <= max_bytes)
        .ok_or_else(|| AppError::InvalidRequest("OCI descriptor has an invalid size".into()))?;
    let blob_path = root.join("blobs").join("sha256").join(digest);
    ensure_canonical_inside(&blob_path, root).map_err(|_| {
        AppError::InvalidRequest("OCI descriptor blob is missing or escaped the layout".into())
    })?;
    let bytes = read_bounded_stable_file(&blob_path, max_bytes).map_err(|_| {
        AppError::InvalidRequest("OCI descriptor blob is not a bounded regular file".into())
    })?;
    if bytes.len() as u64 != expected_size || sha256_bytes(&bytes) != digest {
        return Err(AppError::InvalidRequest(
            "OCI descriptor size or SHA-256 does not match its blob".into(),
        ));
    }
    Ok(bytes)
}

fn write_input_profile_marker(
    tree_path: &Path,
    input_profile: WorkspaceInputProfile,
    limits: WorkspaceSnapshotLimits,
    state: &mut CopyState,
) -> AppResult<()> {
    #[derive(Serialize)]
    struct Marker {
        schema_version: &'static str,
        input_profile: WorkspaceInputProfile,
    }

    let mut bytes = serde_json::to_vec(&Marker {
        schema_version: LOCAL_INPUT_PROFILE_SCHEMA,
        input_profile,
    })?;
    bytes.push(b'\n');
    let byte_length = u64::try_from(bytes.len())
        .map_err(|_| AppError::Runtime("local input profile marker length overflowed".into()))?;
    let total_bytes = state
        .total_bytes
        .checked_add(byte_length)
        .ok_or_else(|| AppError::Runtime("workspace snapshot byte count overflowed".into()))?;
    if state.files.len() >= limits.max_files || total_bytes > limits.max_total_bytes {
        return Err(AppError::InvalidRequest(
            "local input profile marker would exceed snapshot limits".into(),
        ));
    }
    write_private_readonly_file(&tree_path.join(LOCAL_INPUT_PROFILE_FILENAME), &bytes)?;
    state.files.push(WorkspaceSnapshotFile {
        relative_path: LOCAL_INPUT_PROFILE_FILENAME.into(),
        byte_length,
        sha256: sha256_bytes(&bytes),
    });
    state.total_bytes = total_bytes;
    Ok(())
}

fn snapshot_asset(
    source_id: &str,
    snapshot_id: &str,
    sha256: &str,
    input_profile: WorkspaceInputProfile,
) -> Asset {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "workspace_snapshot_id".into(),
        Value::String(snapshot_id.into()),
    );
    metadata.insert(
        "workspace_snapshot_sha256".into(),
        Value::String(sha256.into()),
    );
    if !input_profile.is_repository() {
        metadata.insert(
            "local_input_profile".into(),
            serde_json::to_value(input_profile).expect("local input profile serializes"),
        );
    }
    Asset {
        id: format!("{ASSET_ID_PREFIX}{sha256}"),
        kind: input_profile.asset_kind(),
        name: format!(
            "Local {} snapshot {}",
            input_profile.display_name(),
            &sha256[..12]
        ),
        provider: None,
        region: None,
        identifiers: vec![AssetIdentifier {
            namespace: "ai-security-scanner:workspace-snapshot-sha256".into(),
            value: sha256.into(),
        }],
        discovered_from: vec![source_id.into()],
        candidate: true,
        owner_confirmed: false,
        internet_exposed: None,
        contains_sensitive_data: None,
        metadata,
    }
}

fn prepare_existing_directory(path: &Path, label: &str) -> AppResult<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::InvalidRequest(format!("{label} could not be inspected: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::InvalidRequest(format!(
            "{label} must be a real directory, not a symlink"
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::InvalidRequest(format!("{label} could not be resolved: {error}"))
    })?;
    set_private_directory(&canonical)?;
    Ok(canonical)
}

fn prepare_selected_source(path: &Path) -> AppResult<PathBuf> {
    if !path.is_absolute()
        || path.to_str().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AppError::InvalidRequest(
            "selected working-tree path must be an absolute normalized UTF-8 path".into(),
        ));
    }
    reject_symlink_path_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::InvalidRequest(format!(
            "selected working-tree directory could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::InvalidRequest(
            "selected working-tree path must be a real directory, not a symlink".into(),
        ));
    }
    fs::canonicalize(path).map_err(|error| {
        AppError::InvalidRequest(format!(
            "selected working-tree directory could not be resolved: {error}"
        ))
    })
}

fn reject_symlink_path_components(path: &Path) -> AppResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !matches!(component, Component::Normal(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            AppError::InvalidRequest(format!(
                "selected working-tree path component could not be inspected: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(AppError::InvalidRequest(
                "selected working-tree path may not contain symlink components".into(),
            ));
        }
    }
    Ok(())
}

fn ensure_private_child_directory(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let child = parent.join(name);
    match fs::create_dir(&child) {
        Ok(()) => set_private_directory(&child)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&child)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::Runtime(
                    "backend artifact directory was replaced by an unsafe entry".into(),
                ));
            }
            set_private_directory(&child)?;
        }
        Err(error) => return Err(error.into()),
    }
    let canonical = fs::canonicalize(&child)?;
    if canonical.parent() != Some(parent) {
        return Err(AppError::Runtime(
            "backend artifact directory escaped its expected parent".into(),
        ));
    }
    Ok(canonical)
}

fn create_private_generated_directory(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let path = parent.join(name);
    fs::create_dir(&path).map_err(|error| {
        AppError::Runtime(format!(
            "backend-generated workspace artifact directory could not be reserved: {error}"
        ))
    })?;
    if let Err(error) = set_private_directory(&path) {
        let _ = fs::remove_dir(&path);
        return Err(error);
    }
    Ok(path)
}

fn create_private_directory(path: &Path) -> AppResult<()> {
    fs::create_dir(path).map_err(|error| {
        AppError::Runtime(format!(
            "private workspace snapshot directory could not be created: {error}"
        ))
    })?;
    set_private_directory(path)
}

fn resolve_real_child_directory(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let path = parent.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        AppError::Runtime(format!(
            "workspace snapshot directory is unavailable: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::Runtime(
            "workspace snapshot path contains a symlink or non-directory".into(),
        ));
    }
    let canonical = fs::canonicalize(&path)?;
    if canonical.parent() != Some(parent) {
        return Err(AppError::Runtime(
            "workspace snapshot directory escaped its expected parent".into(),
        ));
    }
    Ok(canonical)
}

fn resolve_real_regular_file(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let path = parent.join(name);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot manifest is not a regular file".into(),
        ));
    }
    ensure_canonical_inside(&path, parent)?;
    Ok(path)
}

fn sorted_directory_entries(
    directory: &Path,
    maximum_entries: usize,
) -> AppResult<Vec<(String, PathBuf)>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        if entries.len() >= maximum_entries {
            return Err(AppError::InvalidRequest(
                "workspace snapshot directory contains more entries than its safety bounds allow"
                    .into(),
            ));
        }
        let entry = entry?;
        let name = validate_entry_name(&entry.file_name())?;
        entries.push((name, entry.path()));
    }
    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    Ok(entries)
}

fn validate_entry_name(name: &std::ffi::OsStr) -> AppResult<String> {
    let Some(name) = name.to_str() else {
        return Err(AppError::InvalidRequest(
            "selected working tree contains a non-UTF-8 path".into(),
        ));
    };
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAX_COMPONENT_BYTES
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(
            "selected working tree contains an unsafe path component".into(),
        ));
    }
    Ok(name.into())
}

fn normalized_relative_path(components: &[String]) -> AppResult<String> {
    let path = components.join("/");
    if path.is_empty() || path.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(AppError::InvalidRequest(
            "selected working tree contains an empty or overlong relative path".into(),
        ));
    }
    Ok(path)
}

fn validate_normalized_relative_path(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > MAX_RELATIVE_PATH_BYTES
        || value.contains('\\')
        || Path::new(value).is_absolute()
        || value.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.len() > MAX_COMPONENT_BYTES
                || component.chars().any(char::is_control)
        })
    {
        return Err(AppError::Runtime(
            "workspace snapshot manifest contains an unsafe relative path".into(),
        ));
    }
    Ok(())
}

fn inspect_real_directory(path: &Path, root: &Path) -> AppResult<FileFingerprint> {
    ensure_canonical_inside(path, root)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::InvalidRequest(
            "selected working tree contains a symlinked or invalid directory".into(),
        ));
    }
    Ok(FileFingerprint::from_metadata(&metadata))
}

fn ensure_canonical_inside(path: &Path, root: &Path) -> AppResult<()> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::Runtime(format!(
            "workspace snapshot path could not be resolved: {error}"
        ))
    })?;
    if !canonical.starts_with(root) {
        return Err(AppError::InvalidRequest(
            "selected working-tree entry resolved outside its selected root".into(),
        ));
    }
    Ok(())
}

fn create_private_new_file(path: &Path) -> AppResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_CLOEXEC);
    let file = options.open(path).map_err(|error| {
        AppError::Runtime(format!(
            "private workspace snapshot file could not be created: {error}"
        ))
    })?;
    set_private_file(path)?;
    Ok(file)
}

fn write_private_readonly_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let mut file = create_private_new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    set_readonly_file(path)
}

fn open_readonly_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}

fn read_bounded_stable_file(path: &Path, maximum_bytes: u64) -> AppResult<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot contains a non-regular file".into(),
        ));
    }
    let mut file = open_readonly_nofollow(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot contains a non-regular file".into(),
        ));
    }
    let before = FileFingerprint::from_metadata(&opened_metadata);
    if before != FileFingerprint::from_metadata(&path_metadata)
        || before.byte_length > maximum_bytes
    {
        return Err(AppError::Runtime(
            "workspace snapshot file changed or exceeds its byte limit".into(),
        ));
    }
    let capacity = usize::try_from(before.byte_length.min(1024 * 1024)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = FileFingerprint::from_metadata(&file.metadata()?);
    let final_path_metadata = fs::symlink_metadata(path)?;
    if bytes.len() as u64 > maximum_bytes
        || before.byte_length != bytes.len() as u64
        || before != after
        || after != FileFingerprint::from_metadata(&final_path_metadata)
    {
        return Err(AppError::Runtime(
            "workspace snapshot file changed while it was being verified".into(),
        ));
    }
    Ok(bytes)
}

fn hash_bounded_stable_file(path: &Path, maximum_bytes: u64) -> AppResult<(String, u64)> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot contains a non-regular file".into(),
        ));
    }
    let mut file = open_readonly_nofollow(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot contains a non-regular file".into(),
        ));
    }
    let before = FileFingerprint::from_metadata(&opened_metadata);
    if before != FileFingerprint::from_metadata(&path_metadata)
        || before.byte_length > maximum_bytes
    {
        return Err(AppError::Runtime(
            "workspace snapshot file changed or exceeds its byte limit".into(),
        ));
    }

    let mut first_digest = Sha256::new();
    let first_length = hash_reader_bounded(&mut file, maximum_bytes, &mut first_digest)?;
    let after_first = FileFingerprint::from_metadata(&file.metadata()?);
    file.seek(SeekFrom::Start(0))?;
    let before_second = FileFingerprint::from_metadata(&file.metadata()?);
    let mut second_digest = Sha256::new();
    let second_length = hash_reader_bounded(&mut file, maximum_bytes, &mut second_digest)?;
    let after_second = FileFingerprint::from_metadata(&file.metadata()?);
    let final_path_metadata = fs::symlink_metadata(path)?;
    let first_digest = first_digest.finalize();
    let second_digest = second_digest.finalize();
    if before != after_first
        || after_first != before_second
        || before_second != after_second
        || after_second != FileFingerprint::from_metadata(&final_path_metadata)
        || first_length != before.byte_length
        || second_length != first_length
        || first_digest != second_digest
    {
        return Err(AppError::Runtime(
            "workspace snapshot file changed while it was being verified".into(),
        ));
    }
    Ok((hex::encode(first_digest), first_length))
}

fn hash_reader_bounded(
    reader: &mut File,
    maximum_bytes: u64,
    digest: &mut Sha256,
) -> AppResult<u64> {
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        byte_length = byte_length
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Runtime("snapshot byte count overflowed".into()))?;
        if byte_length > maximum_bytes {
            return Err(AppError::Runtime(
                "workspace snapshot file exceeds its byte limit".into(),
            ));
        }
        digest.update(&buffer[..read]);
    }
    Ok(byte_length)
}

fn validate_safe_id(label: &str, value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AppError::InvalidRequest(format!(
            "{label} contains unsafe path characters"
        )));
    }
    Ok(())
}

fn valid_storage_id(value: &str) -> bool {
    value.strip_prefix(STORAGE_ID_PREFIX).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn changed_file_error(relative_path: &str) -> AppError {
    AppError::Runtime(format!(
        "selected working-tree file changed while it was being copied at {relative_path}"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    byte_length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            byte_length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            modified_seconds: metadata.mtime(),
            #[cfg(unix)]
            modified_nanoseconds: metadata.mtime_nsec(),
            #[cfg(unix)]
            changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

struct SnapshotCleanup {
    staging: Option<PathBuf>,
    final_container: Option<PathBuf>,
    armed: bool,
}

impl SnapshotCleanup {
    fn new(staging: PathBuf) -> Self {
        Self {
            staging: Some(staging),
            final_container: None,
            armed: true,
        }
    }

    fn track_final(&mut self, final_container: PathBuf) {
        self.final_container = Some(final_container);
    }

    fn staging_moved(&mut self) {
        self.staging = None;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SnapshotCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(path) = self.staging.as_deref() {
            remove_private_tree(path);
        }
        if let Some(path) = self.final_container.as_deref() {
            remove_private_tree(path);
        }
    }
}

fn remove_private_tree(path: &Path) {
    make_tree_deletable(path);
    let _ = fs::remove_dir_all(path);
}

fn make_tree_deletable(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        let _ = fs::remove_file(path);
        return;
    }
    if metadata.is_dir() {
        let _ = set_private_directory(path);
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_tree_deletable(&entry.path());
            }
        }
    } else {
        let _ = set_private_file(path);
    }
}

fn make_snapshot_tree_readonly(path: &Path) -> AppResult<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            make_snapshot_tree_readonly(&entry.path())?;
        } else if metadata.is_file() {
            set_readonly_file(&entry.path())?;
        } else {
            return Err(AppError::Runtime(
                "staged workspace snapshot contains an unsupported entry".into(),
            ));
        }
    }
    set_readonly_directory(path)
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> AppResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_readonly_directory(path: &Path) -> AppResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_readonly_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> AppResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(path: &Path) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn set_readonly_file(path: &Path) -> AppResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_readonly_file(path: &Path) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> AppResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}
