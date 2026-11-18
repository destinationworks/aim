//! Cross-platform private file and directory operations.
//!
//! Secret files (keys, server config, databases) are created with mode `0600`
//! on Unix and an owner-only / SYSTEM DACL on Windows. Reads refuse symlinks
//! and check ownership and permissions on the opened handle rather than
//! re-checking by path.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use rand::RngCore;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as native;
#[cfg(windows)]
use windows as native;

pub use native::{
    create_private_dir, create_private_file, open_private_rw, open_read_nofollow,
    set_private_permissions, verify_dir_not_writable_by_others, verify_not_writable_by_others,
    verify_private_dir, verify_private_file,
};

fn refused(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg)
}

/// Ensures `path` and any missing parents exist, marking `path` private
/// (`0700` on Unix, protected current-user DACL on Windows).
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => set_private_permissions(path, true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                if !parent.exists() {
                    ensure_private_dir(parent)?;
                }
            }
            match create_private_dir(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    set_private_permissions(path, true)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// Reads a private file after opening with no-symlink flags and verifying
/// ownership and `0600` / private-DACL permissions on the open handle.
pub fn read_private_bytes(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut file = open_read_nofollow(path)
        .map_err(|e| format!("cannot open private file {}: {e}", path.display()))?;
    verify_private_file(&file).map_err(|e| {
        format!(
            "private file {} is not safely protected ({e}); make it readable only by you (chmod 600 on Unix)",
            path.display()
        )
    })?;
    read_bounded(&mut file, max_bytes).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

pub fn read_private_string(path: &Path, max_bytes: usize) -> Result<String, String> {
    let bytes = read_private_bytes(path, max_bytes)?;
    String::from_utf8(bytes).map_err(|_| format!("{} is not valid UTF-8", path.display()))
}

/// Reads a non-secret configuration or trust-anchor file while verifying that
/// neither the file nor its parent directory is writable by other non-admin users.
pub fn read_trusted_config_bytes(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    verify_dir_not_writable_by_others(parent).map_err(|e| {
        format!(
            "parent directory of {} is not safely protected ({e})",
            path.display()
        )
    })?;
    let mut file = native::open_trusted_read_nofollow(path)
        .map_err(|e| format!("cannot open trusted file {}: {e}", path.display()))?;
    verify_not_writable_by_others(&file).map_err(|e| {
        format!(
            "trusted file {} is not safely protected ({e})",
            path.display()
        )
    })?;
    read_bounded(&mut file, max_bytes).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Opens or creates a private lock file and acquires an exclusive OS lock held
/// until the returned `File` is dropped.
pub fn lock_file_exclusive(path: &Path) -> io::Result<File> {
    let file = open_private_rw(path)?;
    file.lock()?;
    Ok(file)
}

/// Reads an ordinary (non-secret) file without following symlinks on the leaf.
pub fn read_public_bytes(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut file =
        open_read_nofollow(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    read_bounded(&mut file, max_bytes).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn read_bounded(file: &mut File, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut limited = file.take((max_bytes as u64).saturating_add(1));
    limited.read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("exceeds {max_bytes} bytes"),
        ));
    }
    Ok(buf)
}

/// Writes `bytes` atomically to `path` with private permissions (`0600` /
/// protected Windows DACL). If `overwrite` is false, fails if `path` exists.
pub fn write_private_atomic(path: &Path, bytes: &[u8], overwrite: bool) -> Result<(), String> {
    write_atomic_inner(path, bytes, overwrite, true)
}

/// Writes `bytes` atomically to `path` with ordinary permissions (for public
/// certificates such as `ca.crt`).
pub fn write_public_atomic(path: &Path, bytes: &[u8], overwrite: bool) -> Result<(), String> {
    write_atomic_inner(path, bytes, overwrite, false)
}

fn write_atomic_inner(
    path: &Path,
    bytes: &[u8],
    overwrite: bool,
    private: bool,
) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        if private {
            ensure_private_dir(parent)
                .map_err(|e| format!("cannot create directory {}: {e}", parent.display()))?;
        } else {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create directory {}: {e}", parent.display()))?;
        }
    } else if private {
        verify_dir_not_writable_by_others(parent).map_err(|e| {
            format!(
                "parent directory {} is not safely protected ({e})",
                parent.display()
            )
        })?;
    }
    if !overwrite {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(format!(
                    "{} already exists (pass --force to overwrite)",
                    path.display()
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot inspect {}: {e}", path.display())),
        }
    } else if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("refusing to overwrite symlink {}", path.display()));
        }
    }

    let mut suffix = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    let tmp_name = format!(
        ".{}.tmp.{:016x}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("aim"),
        u64::from_le_bytes(suffix)
    );
    let tmp_path = parent.join(tmp_name);

    let write_res = (|| -> io::Result<()> {
        let mut file = if private {
            create_private_file(&tmp_path)?
        } else {
            native::create_public_file(&tmp_path)?
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        native::place_file(&tmp_path, path, overwrite)?;
        native::sync_directory(parent)?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    Ok(())
}

/// Checks that `file` has the same underlying inode/file-id as `path`.
pub fn same_file(file: &File, path: &Path) -> io::Result<bool> {
    let current = open_read_nofollow(path)?;
    Ok(native::identity(file)? == native::identity(&current)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_roundtrip_and_overwrite_guard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("secret.key");
        write_private_atomic(&path, b"aim1_test_key", false).unwrap();
        assert_eq!(read_private_string(&path, 128).unwrap(), "aim1_test_key");

        // Refuses overwrite when overwrite=false.
        assert!(write_private_atomic(&path, b"new", false).is_err());
        assert_eq!(read_private_string(&path, 128).unwrap(), "aim1_test_key");

        // Allows overwrite when overwrite=true.
        write_private_atomic(&path, b"aim1_rotated", true).unwrap();
        assert_eq!(read_private_string(&path, 128).unwrap(), "aim1_rotated");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_open_permissions_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        write_private_atomic(&path, b"aim1_secret", false).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_string(&path, 128).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_private_string(&link, 128).is_err());

        // Trusted config files allow 0644 (read by user, not writable by others),
        // but reject 0666 / writable by others and world-writable parent dirs.
        let cfg = dir.path().join("config.toml");
        write_public_atomic(&cfg, b"url = \"https://aim.example.internal/aim\"\n", false).unwrap();
        assert!(read_trusted_config_bytes(&cfg, 1024).is_ok());
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_trusted_config_bytes(&cfg, 1024).is_err());
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o644)).unwrap();

        let bad_dir = dir.path().join("open_dir");
        fs::create_dir(&bad_dir).unwrap();
        fs::set_permissions(&bad_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let in_bad_dir = bad_dir.join("ca.crt");
        write_public_atomic(&in_bad_dir, b"cert", false).unwrap();
        assert!(read_trusted_config_bytes(&in_bad_dir, 1024).is_err());
        assert!(write_private_atomic(&bad_dir.join("secret.key"), b"k", false).is_err());
    }
}
