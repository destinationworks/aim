use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CopySid, EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation,
    IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::refused;

struct LocalAlloc(*mut c_void);
impl Drop for LocalAlloc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn wide_abs(abs: &Path, reject_unc: bool) -> io::Result<Vec<u16>> {
    use std::path::{Component, Prefix};
    if abs.components().any(|part| match part {
        Component::Prefix(prefix) => match prefix.kind() {
            Prefix::DeviceNS(_) | Prefix::Verbatim(_) => true,
            Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _) => reject_unc,
            _ => false,
        },
        Component::Normal(name) => name.encode_wide().any(|c| c == b':' as u16),
        _ => false,
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "disallowed device, UNC, or alternate-stream path",
        ));
    }
    let value: Vec<u16> = abs.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    let mut extended = if value.starts_with(&[92, 92, 63, 92]) {
        value
    } else if value.starts_with(&[92, 92]) {
        [
            r"\\?\UNC\".encode_utf16().collect::<Vec<_>>(),
            value[2..].to_vec(),
        ]
        .concat()
    } else {
        [r"\\?\".encode_utf16().collect::<Vec<_>>(), value].concat()
    };
    extended.push(0);
    Ok(extended)
}

fn reject_reparse_ancestors(abs: &Path) -> io::Result<()> {
    for ancestor in abs
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                return Err(refused("reparse point in private path"));
            }
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn current_user_sid() -> io::Result<Vec<u8>> {
    unsafe {
        let mut raw = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Handle(raw);
        let mut needed = 0;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        if GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let length = GetLengthSid(user.User.Sid);
        let mut sid = vec![0u8; length as usize];
        if CopySid(length, sid.as_mut_ptr().cast(), user.User.Sid) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sid)
    }
}

fn private_descriptor(directory: bool) -> io::Result<LocalAlloc> {
    let mut sid = current_user_sid()?;
    unsafe {
        let mut raw_sid = null_mut();
        if ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut raw_sid) == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_guard = LocalAlloc(raw_sid.cast());
        let mut length = 0;
        while *raw_sid.add(length) != 0 {
            length += 1;
        }
        let sid_text = String::from_utf16(std::slice::from_raw_parts(raw_sid, length))
            .map_err(|_| refused("invalid current user SID"))?;
        let inheritance = if directory { "OICI" } else { "" };
        let text: Vec<u16> =
            format!("O:{sid_text}D:P(A;{inheritance};FA;;;{sid_text})(A;{inheritance};FA;;;SY)")
                .encode_utf16()
                .chain(Some(0))
                .collect();
        let mut descriptor = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(LocalAlloc(descriptor))
    }
}

fn open(
    path: &Path,
    access: u32,
    disposition: u32,
    directory: bool,
    private: bool,
    reject_unc: bool,
) -> io::Result<File> {
    let abs = std::path::absolute(path)?;
    reject_reparse_ancestors(&abs)?;
    let name = wide_abs(&abs, reject_unc)?;
    let descriptor = private.then(|| private_descriptor(directory)).transpose()?;
    let attributes = descriptor.as_ref().map(|d| SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: d.0,
        bInheritHandle: 0,
    });
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            attributes.as_ref().map_or(null(), |a| a as *const _),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    let meta = file.metadata()?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(refused("is a symbolic link or reparse point"));
    }
    if meta.is_dir() != directory || (!directory && !meta.is_file()) {
        return Err(refused("unexpected entry type"));
    }
    Ok(file)
}

pub fn open_read_nofollow(path: &Path) -> io::Result<File> {
    open(path, FILE_GENERIC_READ, OPEN_EXISTING, false, false, false)
}

pub fn open_trusted_read_nofollow(path: &Path) -> io::Result<File> {
    open(path, FILE_GENERIC_READ, OPEN_EXISTING, false, false, true)
}

pub fn create_private_file(path: &Path) -> io::Result<File> {
    let file = open(
        path,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        CREATE_NEW,
        false,
        true,
        true,
    )?;
    verify_private_file(&file)?;
    Ok(file)
}

pub fn create_public_file(path: &Path) -> io::Result<File> {
    open(
        path,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        CREATE_NEW,
        false,
        false,
        true,
    )
}

pub fn open_private_rw(path: &Path) -> io::Result<File> {
    let file = open(
        path,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        OPEN_ALWAYS,
        false,
        true,
        true,
    )?;
    verify_private_file(&file)?;
    Ok(file)
}

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let abs = std::path::absolute(path)?;
    reject_reparse_ancestors(&abs)?;
    let name = wide_abs(&abs, true)?;
    let descriptor = private_descriptor(true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_private_permissions(path: &Path, directory: bool) -> io::Result<()> {
    let file = open(
        path,
        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        OPEN_EXISTING,
        directory,
        false,
        true,
    )?;
    verify_security(&file, None)?;
    let descriptor = private_descriptor(directory)?;
    unsafe {
        let (mut present, mut defaulted) = (0, 0);
        let mut acl = null_mut();
        if GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) == 0
            || present == 0
            || acl.is_null()
        {
            return Err(refused("private DACL could not be constructed"));
        }
        let status = SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
    }
    verify_security(&file, Some(true))
}

fn verify_security(file: &File, private: Option<bool>) -> io::Result<()> {
    let mut user = current_user_sid()?;
    unsafe {
        let mut owner = null_mut();
        let mut acl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        let status = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _descriptor = LocalAlloc(descriptor);
        let owner_ok = !owner.is_null()
            && (EqualSid(owner, user.as_mut_ptr().cast()) != 0
                || (private == Some(false)
                    && (IsWellKnownSid(owner, WinLocalSystemSid) != 0
                        || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0)));
        if !owner_ok {
            return Err(refused("belongs to another user"));
        }
        let Some(private) = private else {
            return Ok(());
        };
        if acl.is_null() {
            return Err(refused("unrestricted file DACL"));
        }
        for index in 0..(*acl).AceCount as u32 {
            let mut pointer = null_mut();
            if GetAce(acl, index, &mut pointer) == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = &*pointer.cast::<ACE_HEADER>();
            if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 || header.AceType == 1 {
                continue;
            }
            if header.AceType != 0 || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>() {
                return Err(refused("unsupported private file access rule"));
            }
            let ace = &*pointer.cast::<ACCESS_ALLOWED_ACE>();
            let trustee = (&ace.SidStart as *const u32).cast_mut().cast();
            if EqualSid(trustee, user.as_mut_ptr().cast()) != 0
                || IsWellKnownSid(trustee, WinLocalSystemSid) != 0
                || IsWellKnownSid(trustee, WinBuiltinAdministratorsSid) != 0
            {
                continue;
            }
            let writes = 0x5000_0000
                | DELETE
                | WRITE_DAC
                | WRITE_OWNER
                | FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | FILE_DELETE_CHILD;
            let reads = 0xA000_0000 | FILE_READ_DATA | FILE_READ_EA | FILE_EXECUTE;
            if ace.Mask & (writes | if private { reads } else { 0 }) != 0 {
                return Err(refused(if private {
                    "accessible to other users"
                } else {
                    "can be changed by other users"
                }));
            }
        }
    }
    Ok(())
}

fn check_single_link(file: &File) -> io::Result<()> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.nNumberOfLinks != 1 {
        return Err(refused("must be a single-link regular file"));
    }
    Ok(())
}

pub fn verify_private_file(file: &File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(refused("not a regular file"));
    }
    check_single_link(file)?;
    verify_security(file, Some(true))
}

pub fn verify_private_dir(path: &Path) -> io::Result<()> {
    let file = open(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        OPEN_EXISTING,
        true,
        false,
        true,
    )?;
    verify_security(&file, Some(true))
}

pub fn verify_not_writable_by_others(file: &File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(refused("not a regular file"));
    }
    check_single_link(file)?;
    verify_security(file, Some(false))
}

pub fn verify_dir_not_writable_by_others(path: &Path) -> io::Result<()> {
    let file = open(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        OPEN_EXISTING,
        true,
        false,
        true,
    )?;
    verify_security(&file, Some(false))
}

pub fn place_file(from: &Path, to: &Path, overwrite: bool) -> io::Result<()> {
    let from_abs = std::path::absolute(from)?;
    let to_abs = std::path::absolute(to)?;
    let from_w = wide_abs(&from_abs, true)?;
    let to_w = wide_abs(&to_abs, true)?;
    let flags = if overwrite {
        MOVEFILE_REPLACE_EXISTING
    } else {
        0
    };
    if unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub fn identity(file: &File) -> io::Result<(u64, u64)> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let vol = info.dwVolumeSerialNumber as u64;
    let id = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
    Ok((vol, id))
}
