use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::refused;

pub fn open_read_nofollow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(refused("not a regular file"));
    }
    Ok(file)
}

pub fn open_trusted_read_nofollow(path: &Path) -> io::Result<File> {
    open_read_nofollow(path)
}

pub fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub fn create_public_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub fn open_private_rw(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    verify_private_file(&file)?;
    Ok(file)
}

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

pub fn set_private_permissions(path: &Path, directory: bool) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.is_dir() != directory || (!directory && !meta.is_file()) {
        return Err(refused("unexpected entry type"));
    }
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(refused("belongs to another user"));
    }
    file.set_permissions(fs::Permissions::from_mode(if directory {
        0o700
    } else {
        0o600
    }))
}

pub fn verify_private_file(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(refused("must be a single-link regular file"));
    }
    // SAFETY: geteuid has no preconditions.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(refused("belongs to another user"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(refused("accessible to group or others"));
    }
    Ok(())
}

pub fn verify_private_dir(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(refused("not a private directory owned by this user"));
    }
    Ok(())
}

fn is_private_user_group(uid: u32, gid: u32) -> bool {
    if uid != gid || uid == 0 {
        return false;
    }
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result = std::ptr::null_mut();
    // SAFETY: grp, buf, and result are valid stack/heap allocations for getgrgid_r.
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return false;
    }
    if grp.gr_mem.is_null() {
        return true;
    }
    // Fail closed if any secondary member is listed on the group.
    // SAFETY: getgrgid_r populated gr_mem as a NULL-terminated pointer array on success.
    unsafe { (*grp.gr_mem).is_null() }
}

pub fn verify_dir_not_writable_by_others(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || (meta.uid() != euid && meta.uid() != 0) {
        return Err(refused("directory is owned by another user"));
    }
    let mode = meta.mode();
    if mode & 0o002 != 0 {
        return Err(refused("directory is world-writable"));
    }
    if mode & 0o020 != 0 && !is_private_user_group(meta.uid(), meta.gid()) {
        return Err(refused("directory is writable by group"));
    }
    Ok(())
}

pub fn verify_not_writable_by_others(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(refused("must be a single-link regular file"));
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(refused("belongs to another user"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(refused("writable by group or others"));
    }
    Ok(())
}

pub fn place_file(from: &Path, to: &Path, overwrite: bool) -> io::Result<()> {
    if overwrite {
        fs::rename(from, to)
    } else {
        fs::hard_link(from, to)?;
        fs::remove_file(from)
    }
}

pub fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub fn identity(file: &File) -> io::Result<(u64, u64)> {
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}
