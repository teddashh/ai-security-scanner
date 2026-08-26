use crate::domain::{RawArtifact, new_id};
use crate::error::{AppError, AppResult};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const HASH_BUFFER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_OUTPUT_FILES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactContext {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDirectories {
    pub root: PathBuf,
    pub workspace: PathBuf,
    pub output: PathBuf,
    pub control: PathBuf,
    pub raw: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePaths {
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFile {
    pub path: PathBuf,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
    max_output_files: usize,
}

/// Read and verify already-captured raw artifacts without changing the
/// filesystem. This is intentionally separate from [`ArtifactStore::open`],
/// which creates and restricts the artifact root for new executions.
///
/// The caller can use this before persisting a resume attempt, then call it
/// again immediately before consuming the artifacts to close the ordinary
/// time-of-check/time-of-use window as far as a portable path-based API can.
pub fn inspect_raw_artifacts(artifact_root: &Path, artifacts: &[RawArtifact]) -> AppResult<()> {
    let root_metadata = fs::symlink_metadata(artifact_root).map_err(|error| {
        AppError::Runtime(format!(
            "artifact root {} is unavailable: {error}",
            artifact_root.display()
        ))
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(AppError::Runtime(format!(
            "artifact root {} must be an existing non-symlink directory",
            artifact_root.display()
        )));
    }
    let root = fs::canonicalize(artifact_root).map_err(|error| {
        AppError::Runtime(format!(
            "artifact root {} could not be resolved: {error}",
            artifact_root.display()
        ))
    })?;

    for artifact in artifacts {
        let relative = normalized_artifact_relative_path(artifact)?;
        if artifact.sha256.len() != 64
            || !artifact
                .sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(AppError::Runtime(format!(
                "artifact {} has an invalid durable SHA-256 digest",
                artifact.id
            )));
        }
        if artifact.byte_length == u64::MAX {
            return Err(AppError::Runtime(format!(
                "artifact {} has an unsupported durable byte length",
                artifact.id
            )));
        }

        let mut path = root.clone();
        let component_count = relative.components().count();
        for (index, component) in relative.components().enumerate() {
            let Component::Normal(component) = component else {
                return Err(unsafe_artifact_path(artifact));
            };
            path.push(component);
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                AppError::Runtime(format!(
                    "artifact {} is not available for durable reconciliation: {error}",
                    artifact.id
                ))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(AppError::Runtime(format!(
                    "artifact {} path may not contain symlinks",
                    artifact.id
                )));
            }
            if index + 1 == component_count {
                if !metadata.is_file() {
                    return Err(AppError::Runtime(format!(
                        "artifact {} must be a regular non-symlink file",
                        artifact.id
                    )));
                }
                if metadata.len() != artifact.byte_length {
                    return Err(AppError::Runtime(format!(
                        "artifact {} byte length differs from its durable record",
                        artifact.id
                    )));
                }
            } else if !metadata.is_dir() {
                return Err(AppError::Runtime(format!(
                    "artifact {} path contains a non-directory component",
                    artifact.id
                )));
            }
        }

        let canonical = fs::canonicalize(&path).map_err(|error| {
            AppError::Runtime(format!(
                "artifact {} could not be resolved for durable reconciliation: {error}",
                artifact.id
            ))
        })?;
        if !canonical.starts_with(&root) {
            return Err(AppError::Runtime(format!(
                "artifact {} escapes the private artifact root",
                artifact.id
            )));
        }

        let file = open_readonly_no_follow(&path).map_err(|error| {
            AppError::Runtime(format!(
                "artifact {} could not be opened for durable reconciliation: {error}",
                artifact.id
            ))
        })?;
        let opened_metadata = file.metadata().map_err(|error| {
            AppError::Runtime(format!(
                "artifact {} metadata could not be read after opening: {error}",
                artifact.id
            ))
        })?;
        if opened_metadata.file_type().is_symlink() || !opened_metadata.is_file() {
            return Err(AppError::Runtime(format!(
                "artifact {} changed and is no longer a regular file",
                artifact.id
            )));
        }
        if opened_metadata.len() != artifact.byte_length {
            return Err(AppError::Runtime(format!(
                "artifact {} byte length differs from its durable record",
                artifact.id
            )));
        }

        let (observed_sha256, observed_length) =
            hash_opened_file_bounded(file, artifact.byte_length + 1).map_err(|error| {
                AppError::Runtime(format!(
                    "artifact {} could not be hashed for durable reconciliation: {error}",
                    artifact.id
                ))
            })?;
        if observed_length != artifact.byte_length {
            return Err(AppError::Runtime(format!(
                "artifact {} byte length changed while it was being inspected",
                artifact.id
            )));
        }
        if !observed_sha256.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(AppError::Runtime(format!(
                "artifact {} hash differs from its durable record",
                artifact.id
            )));
        }
    }

    Ok(())
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> AppResult<Self> {
        let root = root.as_ref();
        fs::create_dir_all(root)?;
        restrict_directory(root)?;
        let root = fs::canonicalize(root).map_err(|error| {
            AppError::Runtime(format!(
                "artifact root {} could not be resolved: {error}",
                root.display()
            ))
        })?;
        Ok(Self {
            root,
            max_output_files: DEFAULT_MAX_OUTPUT_FILES,
        })
    }

    #[cfg(test)]
    pub fn with_max_output_files(mut self, max_output_files: usize) -> Self {
        self.max_output_files = max_output_files;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn prepare_run(
        &self,
        context: &ArtifactContext,
        attempt: u32,
    ) -> AppResult<RunDirectories> {
        if attempt == 0 {
            return Err(AppError::InvalidRequest(
                "engine execution attempt must start at one".into(),
            ));
        }

        let case_id = safe_component("case id", &context.case_id)?;
        let scan_run_id = safe_component("scan run id", &context.scan_run_id)?;
        let engine_run_id = safe_component("engine run id", &context.engine_run_id)?;
        let root = self
            .root
            .join(case_id)
            .join(scan_run_id)
            .join(engine_run_id)
            .join(format!("attempt-{attempt}"));
        let directories = RunDirectories {
            workspace: root.join("workspace"),
            output: root.join("output"),
            control: root.join("control"),
            raw: root.join("raw"),
            root,
        };

        for directory in [
            &directories.root,
            &directories.workspace,
            &directories.output,
            &directories.control,
            &directories.raw,
        ] {
            fs::create_dir_all(directory)?;
            restrict_directory(directory)?;
            self.ensure_inside_root(directory)?;
        }

        Ok(directories)
    }

    pub fn prepare_capture(&self, directories: &RunDirectories) -> AppResult<CapturePaths> {
        self.ensure_inside_root(&directories.raw)?;
        let stdout = directories.raw.join("stdout.log");
        let stderr = directories.raw.join("stderr.log");
        create_private_file(&stdout)?;
        create_private_file(&stderr)?;
        Ok(CapturePaths { stdout, stderr })
    }

    pub fn write_control_json<T: Serialize>(
        &self,
        directories: &RunDirectories,
        name: &str,
        value: &T,
    ) -> AppResult<ControlFile> {
        let name = safe_filename(name)?;
        let path = directories.control.join(name);
        self.ensure_inside_root(&directories.control)?;
        let bytes = serde_json::to_vec(value).map_err(|error| {
            AppError::Runtime(format!("control document could not be encoded: {error}"))
        })?;
        let mut file = create_private_file(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        restrict_readonly_file(&path)?;
        Ok(ControlFile {
            path,
            sha256: sha256_bytes(&bytes),
            byte_length: bytes.len() as u64,
        })
    }

    pub fn finalize_capture(
        &self,
        context: &ArtifactContext,
        capture: &CapturePaths,
    ) -> AppResult<Vec<RawArtifact>> {
        Ok(vec![
            self.describe_file(context, &capture.stdout, "text/plain; charset=utf-8", true)?,
            self.describe_file(context, &capture.stderr, "text/plain; charset=utf-8", true)?,
        ])
    }

    pub fn collect_output_artifacts(
        &self,
        context: &ArtifactContext,
        directories: &RunDirectories,
    ) -> AppResult<Vec<RawArtifact>> {
        self.ensure_inside_root(&directories.output)?;
        let mut files = Vec::new();
        collect_regular_files(&directories.output, &mut files, self.max_output_files)?;
        files.sort();
        files
            .iter()
            .map(|path| self.describe_file(context, path, media_type_for_path(path), true))
            .collect()
    }

    pub fn describe_file(
        &self,
        context: &ArtifactContext,
        path: &Path,
        media_type: &str,
        contains_sensitive_data: bool,
    ) -> AppResult<RawArtifact> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AppError::Runtime(format!(
                "artifact {} could not be inspected: {error}",
                path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AppError::Runtime(format!(
                "artifact must be a regular file and not a symlink: {}",
                path.display()
            )));
        }

        let canonical = fs::canonicalize(path)?;
        self.ensure_inside_root(&canonical)?;
        let (sha256, byte_length) = hash_file(&canonical)?;
        let relative_path = canonical
            .strip_prefix(&self.root)
            .map_err(|_| {
                AppError::Runtime(format!(
                    "artifact escaped the private artifact root: {}",
                    canonical.display()
                ))
            })?
            .to_string_lossy()
            .replace('\\', "/");

        Ok(RawArtifact {
            id: new_id(),
            case_id: context.case_id.clone(),
            run_id: context.scan_run_id.clone(),
            engine_run_id: context.engine_run_id.clone(),
            relative_path,
            media_type: media_type.to_owned(),
            sha256,
            byte_length,
            created_at: Utc::now(),
            contains_sensitive_data,
        })
    }

    fn ensure_inside_root(&self, path: &Path) -> AppResult<()> {
        let canonical = fs::canonicalize(path).map_err(|error| {
            AppError::Runtime(format!(
                "artifact path {} could not be resolved: {error}",
                path.display()
            ))
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(AppError::Runtime(format!(
                "artifact path is outside the private artifact root: {}",
                path.display()
            )));
        }
        Ok(())
    }
}

fn collect_regular_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    max_files: usize,
) -> AppResult<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(AppError::Runtime(format!(
                "scanner output may not contain symlinks: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_regular_files(&path, files, max_files)?;
        } else if file_type.is_file() {
            files.push(path);
            if files.len() > max_files {
                return Err(AppError::Runtime(format!(
                    "scanner output exceeded the artifact limit of {max_files} files"
                )));
            }
        } else {
            return Err(AppError::Runtime(format!(
                "scanner output contains an unsupported filesystem entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn safe_component<'a>(label: &str, value: &'a str) -> AppResult<&'a str> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(format!(
            "{label} contains unsafe path characters"
        )));
    }
    Ok(value)
}

fn safe_filename(value: &str) -> AppResult<&str> {
    let path = Path::new(value);
    let mut components = path.components();
    let is_single_normal =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !is_single_normal || value.is_empty() || value.contains(['/', '\\', '\0']) {
        return Err(AppError::InvalidRequest(
            "control filename must be a single safe path component".into(),
        ));
    }
    Ok(value)
}

fn normalized_artifact_relative_path(artifact: &RawArtifact) -> AppResult<&Path> {
    let relative = Path::new(&artifact.relative_path);
    let slash_components_are_normal = !artifact.relative_path.is_empty()
        && !artifact.relative_path.contains(['\\', '\0'])
        && artifact
            .relative_path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..");
    if !slash_components_are_normal
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(unsafe_artifact_path(artifact));
    }
    Ok(relative)
}

fn unsafe_artifact_path(artifact: &RawArtifact) -> AppError {
    AppError::Runtime(format!(
        "artifact {} has an unsafe or non-normalized relative path",
        artifact.id
    ))
}

fn open_readonly_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn hash_opened_file_bounded(mut file: File, maximum_bytes: u64) -> std::io::Result<(String, u64)> {
    let mut digest = Sha256::new();
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut reader = (&mut file).take(maximum_bytes);
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        byte_length += read as u64;
    }
    Ok((hex::encode(digest.finalize()), byte_length))
}

fn create_private_file(path: &Path) -> AppResult<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            AppError::Runtime(format!(
                "private artifact file {} could not be created: {error}",
                path.display()
            ))
        })?;
    restrict_file(path)?;
    Ok(file)
}

fn hash_file(path: &Path) -> AppResult<(String, u64)> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        byte_length += read as u64;
    }
    Ok((hex::encode(digest.finalize()), byte_length))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn media_type_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => "application/json",
        "jsonl" | "ndjson" => "application/x-ndjson",
        "csv" => "text/csv",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "sarif" => "application/sarif+json",
        "spdx" => "application/spdx+json",
        "txt" | "log" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_readonly_file(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_readonly_file(path: &Path) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_artifact(relative_path: &str, bytes: &[u8]) -> RawArtifact {
        RawArtifact {
            id: "artifact-1".into(),
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: relative_path.into(),
            media_type: "application/octet-stream".into(),
            sha256: sha256_bytes(bytes),
            byte_length: bytes.len() as u64,
            created_at: Utc::now(),
            contains_sensitive_data: true,
        }
    }

    fn write_raw_artifact(root: &Path, relative_path: &str, bytes: &[u8]) {
        let path = root.join(relative_path);
        fs::create_dir_all(path.parent().expect("artifact parent")).expect("artifact directories");
        fs::write(path, bytes).expect("artifact bytes");
    }

    fn context() -> ArtifactContext {
        ArtifactContext {
            case_id: "case-1".into(),
            scan_run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
        }
    }

    #[test]
    fn capture_files_are_hashed_as_raw_artifacts() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let capture = store.prepare_capture(&directories).expect("capture files");
        fs::write(&capture.stdout, b"scanner stdout\n").expect("stdout");
        fs::write(&capture.stderr, b"scanner stderr\n").expect("stderr");

        let artifacts = store
            .finalize_capture(&context(), &capture)
            .expect("artifacts");

        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0].sha256, sha256_bytes(b"scanner stdout\n"));
        assert_eq!(artifacts[1].sha256, sha256_bytes(b"scanner stderr\n"));
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact.contains_sensitive_data)
        );
    }

    #[test]
    fn unsafe_identifiers_cannot_escape_artifact_root() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let mut bad = context();
        bad.case_id = "../outside".into();

        let error = store
            .prepare_run(&bad, 1)
            .expect_err("unsafe path rejected");
        assert!(error.to_string().contains("unsafe path"));
    }

    #[test]
    fn output_file_limit_is_enforced() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path())
            .expect("artifact store")
            .with_max_output_files(1);
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        fs::write(directories.output.join("one.json"), b"{}").expect("first");
        fs::write(directories.output.join("two.json"), b"{}").expect("second");

        let error = store
            .collect_output_artifacts(&context(), &directories)
            .expect_err("limit rejected");
        assert!(error.to_string().contains("artifact limit"));
    }

    #[test]
    fn captured_artifact_inspection_accepts_an_unchanged_regular_file() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let bytes = b"captured scanner evidence\n";
        write_raw_artifact(&root, "case-1/run-1/evidence.json", bytes);
        let artifact = raw_artifact("case-1/run-1/evidence.json", bytes);

        inspect_raw_artifacts(&root, &[artifact]).expect("valid artifact");
    }

    #[test]
    fn captured_artifact_inspection_rejects_a_missing_file() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        fs::create_dir(&root).expect("artifact root");
        let artifact = raw_artifact("case-1/run-1/missing.json", b"missing");

        let error = inspect_raw_artifacts(&root, &[artifact]).expect_err("missing file rejected");

        assert!(error.to_string().contains("not available"));
    }

    #[test]
    fn captured_artifact_inspection_requires_an_existing_root() {
        let temp = tempfile::tempdir().expect("temp directory");
        let missing_root = temp.path().join("missing-artifacts");

        let error = inspect_raw_artifacts(&missing_root, &[]).expect_err("missing root rejected");

        assert!(error.to_string().contains("artifact root"));
        assert!(
            !missing_root.exists(),
            "inspection must not create the root"
        );
    }

    #[test]
    fn captured_artifact_inspection_rejects_modified_bytes() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let artifact = raw_artifact("case-1/evidence.bin", b"trusted");
        write_raw_artifact(&root, "case-1/evidence.bin", b"altered");

        let error = inspect_raw_artifacts(&root, &[artifact]).expect_err("modified file rejected");

        assert!(error.to_string().contains("hash differs"));
    }

    #[test]
    fn captured_artifact_inspection_rejects_a_changed_byte_length() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let artifact = raw_artifact("case-1/evidence.bin", b"trusted");
        write_raw_artifact(&root, "case-1/evidence.bin", b"now longer");

        let error = inspect_raw_artifacts(&root, &[artifact]).expect_err("changed length rejected");

        assert!(error.to_string().contains("byte length differs"));
    }

    #[test]
    fn captured_artifact_inspection_rejects_non_normalized_or_traversing_paths() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        fs::create_dir(&root).expect("artifact root");

        for relative_path in [
            "../outside.bin",
            "case-1/./evidence.bin",
            "case-1//evidence.bin",
            "case-1/evidence.bin/",
            "/absolute/evidence.bin",
            "case-1\\evidence.bin",
        ] {
            let artifact = raw_artifact(relative_path, b"evidence");
            let error = inspect_raw_artifacts(&root, &[artifact])
                .expect_err("unsafe artifact path rejected");
            assert!(
                error.to_string().contains("unsafe or non-normalized"),
                "unexpected error for {relative_path}: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn captured_artifact_inspection_rejects_final_and_intermediate_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).expect("artifact root");
        fs::create_dir_all(&outside).expect("outside directory");
        fs::write(outside.join("evidence.bin"), b"evidence").expect("outside file");

        symlink(outside.join("evidence.bin"), root.join("final-link.bin")).expect("final symlink");
        let final_link = raw_artifact("final-link.bin", b"evidence");
        let final_error =
            inspect_raw_artifacts(&root, &[final_link]).expect_err("final symlink rejected");
        assert!(final_error.to_string().contains("symlink"));

        symlink(&outside, root.join("intermediate-link")).expect("intermediate symlink");
        let intermediate_link = raw_artifact("intermediate-link/evidence.bin", b"evidence");
        let intermediate_error = inspect_raw_artifacts(&root, &[intermediate_link])
            .expect_err("intermediate symlink rejected");
        assert!(intermediate_error.to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn captured_artifact_inspection_rejects_a_symlink_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp directory");
        let actual_root = temp.path().join("actual-artifacts");
        fs::create_dir(&actual_root).expect("actual artifact root");
        write_raw_artifact(&actual_root, "case-1/evidence.bin", b"evidence");
        let linked_root = temp.path().join("linked-artifacts");
        symlink(&actual_root, &linked_root).expect("artifact root symlink");
        let artifact = raw_artifact("case-1/evidence.bin", b"evidence");

        let error =
            inspect_raw_artifacts(&linked_root, &[artifact]).expect_err("symlink root rejected");

        assert!(error.to_string().contains("non-symlink directory"));
    }

    #[cfg(unix)]
    #[test]
    fn captured_artifact_inspection_does_not_change_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let directory = root.join("case-1");
        let file = directory.join("evidence.bin");
        write_raw_artifact(&root, "case-1/evidence.bin", b"evidence");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o751)).expect("root permissions");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o711))
            .expect("directory permissions");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).expect("file permissions");
        let artifact = raw_artifact("case-1/evidence.bin", b"evidence");

        inspect_raw_artifacts(&root, &[artifact]).expect("valid artifact");

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o751
        );
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o711
        );
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}
