//! Cross-process ownership for destructive data-directory operations.
//!
//! SQLite serializes database writes, but it cannot coordinate the desktop's
//! in-memory workers and credential capabilities with a standalone CLI. The
//! desktop therefore owns one exclusive lease for its lifetime. Read-only CLI
//! inspection remains available; destructive CLI maintenance must acquire the
//! same lease and fails closed while the desktop is running.

use crate::error::{AppError, AppResult};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

const LEASE_FILENAME: &str = ".exclusive-process.lock";

#[derive(Debug)]
pub struct DataDirectoryExclusiveLease {
    _file: File,
    #[cfg(unix)]
    _sentinel: File,
    path: PathBuf,
}

impl DataDirectoryExclusiveLease {
    pub fn acquire(data_directory: &Path) -> AppResult<Self> {
        fs::create_dir_all(data_directory)?;
        let path = data_directory.join(LEASE_FILENAME);
        let sentinel = open_regular_lock_file(&path)?;
        #[cfg(unix)]
        let file = {
            let metadata = fs::symlink_metadata(data_directory)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::NotAuthorized(
                    "process lease data directory must be a real directory".into(),
                ));
            }
            File::open(data_directory)?
        };
        #[cfg(not(unix))]
        let file = sentinel;
        if let Err(error) = FileExt::try_lock_exclusive(&file) {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(AppError::NotAvailable(
                    "another ai-security-scanner desktop or destructive maintenance operation owns this local data directory; close that desktop or let the exact operation finish, then retry"
                        .into(),
                ));
            }
            return Err(error.into());
        }
        Ok(Self {
            _file: file,
            #[cfg(unix)]
            _sentinel: sentinel,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn open_regular_lock_file(path: &Path) -> AppResult<File> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AppError::NotAuthorized(
            "process lease path is not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_lease_blocks_a_second_process_and_releases_on_drop() {
        let temporary = tempfile::tempdir().unwrap();
        let first = DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
        assert_eq!(first.path(), temporary.path().join(LEASE_FILENAME));
        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(temporary.path()),
            Err(AppError::NotAvailable(_))
        ));
        drop(first);
        DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lease_refuses_a_symlink_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, temporary.path().join(LEASE_FILENAME)).unwrap();

        assert!(DataDirectoryExclusiveLease::acquire(temporary.path()).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn unlinking_the_sentinel_cannot_bypass_the_directory_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let first = DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
        fs::remove_file(first.path()).unwrap();

        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(temporary.path()),
            Err(AppError::NotAvailable(_))
        ));
    }
}
