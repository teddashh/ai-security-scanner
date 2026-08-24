use ai_security_scanner_lib::workspace_snapshot::{
    WorkspaceSnapshotLimits, WorkspaceSnapshotReference, create_workspace_snapshot,
    resolve_workspace_snapshot,
};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

fn roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("temporary directory");
    let artifact_root = temp.path().join("private-artifacts");
    let source = temp.path().join("TOP_SECRET_HOST_WORKTREE");
    fs::create_dir(&artifact_root).expect("artifact root");
    fs::create_dir(&source).expect("source root");
    (temp, artifact_root, source)
}

fn small_limits() -> WorkspaceSnapshotLimits {
    WorkspaceSnapshotLimits {
        max_files: 20,
        max_directories: 20,
        max_total_bytes: 2 * 1024 * 1024,
        max_file_bytes: 1024 * 1024,
        max_depth: 8,
    }
}

fn snapshot_entries(artifact_root: &Path, case_id: &str) -> Vec<String> {
    let path = artifact_root.join(case_id).join("workspace-snapshots");
    if !path.exists() {
        return Vec::new();
    }
    let mut names = fs::read_dir(path)
        .expect("read snapshot directory")
        .map(|entry| {
            entry
                .expect("snapshot entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn snapshot_is_deterministic_private_source_grounded_and_working_tree_only() {
    let (_temp, artifact_root, source) = roots();
    fs::create_dir(source.join("src")).unwrap();
    fs::write(source.join("README.md"), b"# safe working tree\n").unwrap();
    fs::write(source.join("src/main.rs"), b"fn main() {}\n").unwrap();
    fs::create_dir(source.join("empty-directory")).unwrap();
    fs::create_dir(source.join(".git")).unwrap();
    fs::write(
        source.join(".git/config"),
        b"credential = must-never-be-copied\n",
    )
    .unwrap();

    let first = create_workspace_snapshot(
        &artifact_root,
        "case-123",
        "source-456",
        &source,
        small_limits(),
    )
    .expect("first snapshot");
    let second = create_workspace_snapshot(
        &artifact_root,
        "case-123",
        "source-456",
        &source,
        small_limits(),
    )
    .expect("second snapshot");

    assert_eq!(first.reference.sha256, second.reference.sha256);
    assert_eq!(first.reference.snapshot_id, second.reference.snapshot_id);
    assert_eq!(first.manifest, second.manifest);
    assert_eq!(first.asset.id, second.asset.id);
    assert_ne!(first.reference.storage_id, second.reference.storage_id);
    assert_eq!(first.asset.discovered_from, ["source-456"]);
    assert!(first.asset.candidate);
    assert!(!first.asset.owner_confirmed);
    assert_eq!(
        first
            .asset
            .metadata
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["workspace_snapshot_id", "workspace_snapshot_sha256"]
    );
    assert_eq!(first.manifest.excluded_entries, [".git"]);
    assert_eq!(first.manifest.directory_count, 2);
    assert_eq!(first.manifest.file_count, 2);
    assert!(
        first
            .manifest
            .files
            .iter()
            .all(|file| !file.relative_path.starts_with(".git"))
    );

    let persisted = serde_json::to_string(&(first.reference.clone(), first.asset.clone())).unwrap();
    assert!(!persisted.contains("TOP_SECRET_HOST_WORKTREE"));
    assert!(!persisted.contains(source.to_string_lossy().as_ref()));
    assert!(!persisted.contains("must-never-be-copied"));

    let resolved = resolve_workspace_snapshot(&artifact_root, "case-123", &first.reference)
        .expect("snapshot resolves after full verification");
    assert_eq!(
        fs::read(resolved.tree_path.join("README.md")).unwrap(),
        b"# safe working tree\n"
    );
    assert!(!resolved.tree_path.join(".git").exists());
    assert_eq!(resolved.manifest, first.manifest);

    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&resolved.tree_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
        assert_eq!(
            fs::metadata(resolved.tree_path.join("README.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        assert_eq!(
            fs::metadata(&resolved.manifest_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_is_rejected_without_following_and_staging_is_rolled_back() {
    let (_temp, artifact_root, source) = roots();
    let outside = source.parent().unwrap().join("outside-secret.txt");
    fs::write(&outside, b"outside secret").unwrap();
    symlink(&outside, source.join("linked-secret")).unwrap();

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-symlink",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("symlink must fail closed");

    assert!(error.to_string().contains("symlink"));
    assert!(snapshot_entries(&artifact_root, "case-symlink").is_empty());
}

#[test]
fn byte_limits_fail_closed_and_remove_partial_staging() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("a-small.txt"), b"copied before the error").unwrap();
    fs::write(source.join("z-too-large.bin"), vec![7_u8; 65]).unwrap();
    let limits = WorkspaceSnapshotLimits {
        max_files: 10,
        max_directories: 10,
        max_total_bytes: 128,
        max_file_bytes: 64,
        max_depth: 4,
    };

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-oversize",
        "source-safe",
        &source,
        limits,
    )
    .expect_err("oversize file rejected");

    assert!(error.to_string().contains("byte limit"));
    assert!(snapshot_entries(&artifact_root, "case-oversize").is_empty());
}

#[test]
fn file_count_depth_and_zero_limits_are_enforced() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("one.txt"), b"one").unwrap();
    fs::write(source.join("two.txt"), b"two").unwrap();
    let one_file = WorkspaceSnapshotLimits {
        max_files: 1,
        ..small_limits()
    };
    let count_error = create_workspace_snapshot(
        &artifact_root,
        "case-count",
        "source-safe",
        &source,
        one_file,
    )
    .expect_err("file-count bound enforced");
    assert!(count_error.to_string().contains("file-count"));
    assert!(snapshot_entries(&artifact_root, "case-count").is_empty());

    let (_other_temp, other_artifact_root, other_source) = roots();
    fs::create_dir(other_source.join("nested")).unwrap();
    fs::write(other_source.join("nested/file.txt"), b"nested").unwrap();
    let flat_only = WorkspaceSnapshotLimits {
        max_depth: 0,
        ..small_limits()
    };
    let depth_error = create_workspace_snapshot(
        &other_artifact_root,
        "case-depth",
        "source-safe",
        &other_source,
        flat_only,
    )
    .expect_err("depth bound enforced");
    assert!(depth_error.to_string().contains("directory depth"));
    assert!(snapshot_entries(&other_artifact_root, "case-depth").is_empty());

    let invalid_limits = WorkspaceSnapshotLimits {
        max_files: 0,
        ..small_limits()
    };
    let limit_error = create_workspace_snapshot(
        &other_artifact_root,
        "case-invalid-limit",
        "source-safe",
        &other_source,
        invalid_limits,
    )
    .expect_err("zero safety bound rejected");
    assert!(limit_error.to_string().contains("built-in safety ceiling"));
}

#[cfg(unix)]
#[test]
fn socket_entry_is_rejected_without_opening_it() {
    use std::os::unix::net::UnixListener;

    let (_temp, artifact_root, source) = roots();
    let _listener = UnixListener::bind(source.join("scanner.sock")).unwrap();
    let error = create_workspace_snapshot(
        &artifact_root,
        "case-socket",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("socket rejected");

    assert!(error.to_string().contains("device, FIFO, or socket"));
    assert!(snapshot_entries(&artifact_root, "case-socket").is_empty());
}

#[cfg(unix)]
#[test]
fn non_utf8_entry_is_rejected_and_rolled_back() {
    let (_temp, artifact_root, source) = roots();
    let invalid_name = OsString::from_vec(vec![b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0xff]);
    fs::write(source.join(invalid_name), b"not representable").unwrap();

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-non-utf8",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("non-UTF-8 path rejected");

    assert!(error.to_string().contains("non-UTF-8"));
    assert!(snapshot_entries(&artifact_root, "case-non-utf8").is_empty());
}

#[test]
fn unsafe_ids_non_directory_sources_and_overlapping_roots_are_rejected() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("file.txt"), b"content").unwrap();

    let traversal = create_workspace_snapshot(
        &artifact_root,
        "../escape",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("traversal id rejected");
    assert!(traversal.to_string().contains("unsafe path"));
    assert!(!artifact_root.parent().unwrap().join("escape").exists());

    let selected_file = source.join("file.txt");
    let not_directory = create_workspace_snapshot(
        &artifact_root,
        "case-safe",
        "source-safe",
        &selected_file,
        small_limits(),
    )
    .expect_err("file cannot be selected as a tree");
    assert!(not_directory.to_string().contains("real directory"));

    let nested_artifact_root = source.join("artifact-child");
    fs::create_dir(&nested_artifact_root).unwrap();
    let overlap = create_workspace_snapshot(
        &nested_artifact_root,
        "case-safe",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("artifact/source overlap rejected");
    assert!(overlap.to_string().contains("must not overlap"));
}

#[cfg(unix)]
#[test]
fn a_symlinked_selected_root_is_rejected() {
    let (temp, artifact_root, source) = roots();
    let selected_link = temp.path().join("selected-link");
    symlink(&source, &selected_link).unwrap();

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-link-root",
        "source-safe",
        &selected_link,
        small_limits(),
    )
    .expect_err("symlink root rejected");
    assert!(error.to_string().contains("symlink"));
}

#[test]
fn resolver_rejects_tampered_content_and_injected_storage_ids() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("code.rs"), b"fn original() {}\n").unwrap();
    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-tamper",
        "source-safe",
        &source,
        small_limits(),
    )
    .unwrap();
    let resolved = resolve_workspace_snapshot(&artifact_root, "case-tamper", &snapshot.reference)
        .expect("initial verification");
    let copied = resolved.tree_path.join("code.rs");
    #[cfg(unix)]
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o600)).unwrap();
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(&copied).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&copied, permissions).unwrap();
    }
    fs::write(&copied, b"fn tampered() {}\n").unwrap();

    let tampered = resolve_workspace_snapshot(&artifact_root, "case-tamper", &snapshot.reference)
        .expect_err("content tampering rejected");
    assert!(tampered.to_string().contains("immutable manifest"));

    let mut injected: WorkspaceSnapshotReference = snapshot.reference;
    injected.storage_id = "../../outside".into();
    let injection = resolve_workspace_snapshot(&artifact_root, "case-tamper", &injected)
        .expect_err("injected storage path rejected");
    assert!(injection.to_string().contains("reference is invalid"));
}

#[cfg(unix)]
#[test]
fn concurrent_file_mutation_is_detected_and_failed_staging_is_removed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let (_temp, artifact_root, source) = roots();
    let changing = source.join("changing.bin");
    let file = FileBuilder::sized(&changing, 16 * 1024 * 1024);
    drop(file);
    let stop = Arc::new(AtomicBool::new(false));
    let mutations = Arc::new(AtomicUsize::new(0));
    let thread_stop = Arc::clone(&stop);
    let thread_mutations = Arc::clone(&mutations);
    let thread_path = changing.clone();
    let writer = std::thread::spawn(move || {
        let mut value = 0_u8;
        while !thread_stop.load(Ordering::Acquire) {
            let mut file = OpenOptions::new().write(true).open(&thread_path).unwrap();
            let offset = (thread_mutations.load(Ordering::Relaxed) % (1024 * 1024)) as u64;
            file.seek(SeekFrom::Start(offset)).unwrap();
            value = value.wrapping_add(1);
            file.write_all(&[value]).unwrap();
            file.sync_data().unwrap();
            thread_mutations.fetch_add(1, Ordering::Release);
        }
    });
    while mutations.load(Ordering::Acquire) < 4 {
        std::thread::yield_now();
    }

    let limits = WorkspaceSnapshotLimits {
        max_files: 2,
        max_directories: 1,
        max_total_bytes: 32 * 1024 * 1024,
        max_file_bytes: 32 * 1024 * 1024,
        max_depth: 1,
    };
    let mut detected = false;
    for _ in 0..3 {
        match create_workspace_snapshot(
            &artifact_root,
            "case-changing",
            "source-safe",
            &source,
            limits,
        ) {
            Err(error) if error.to_string().contains("changed while") => {
                detected = true;
                break;
            }
            Err(error) => panic!("unexpected mutation failure: {error}"),
            Ok(_) => {}
        }
    }
    stop.store(true, Ordering::Release);
    writer.join().unwrap();

    assert!(detected, "continuous content mutation must be detected");
    assert!(
        snapshot_entries(&artifact_root, "case-changing")
            .iter()
            .all(|name| !name.starts_with(".workspace-staging-"))
    );
}

#[cfg(unix)]
struct FileBuilder;

#[cfg(unix)]
impl FileBuilder {
    fn sized(path: &Path, bytes: u64) -> fs::File {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.set_len(bytes).unwrap();
        file
    }
}
