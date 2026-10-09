//! Protected local storage: a SYSTEM/Administrators-only directory and DPAPI-sealed keys.
//!
//! Threat model: another local (non-admin) user, or a stolen disk. Administrators and
//! SYSTEM are inside the trust boundary (they can load drivers and edit the firewall
//! anyway). DPAPI machine scope means the sealed key is useless on another machine.
use crate::WinError;
use std::{
    ffi::c_void,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
        },
        Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData, CryptUnprotectData,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    },
};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// Full control for SYSTEM and Administrators only; protected from inheritance.
const DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const SID_SYSTEM: &str = "S-1-5-18";
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
const DPAPI_ENTROPY: &[u8] = b"LoVPN client key v1";

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// `%ProgramData%\LoVPN`.
pub fn default_state_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("LoVPN")
}

/// Create (if needed), lock down and verify a private directory. Refuses a directory that
/// is a link/junction or is owned by anyone other than SYSTEM or Administrators, because
/// an owner can always rewrite its permissions.
pub fn ensure_private_dir(dir: &Path) -> Result<(), WinError> {
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| io_error("store-create", &e))?;
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| io_error("store-stat", &e))?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(WinError::new("store-not-a-plain-directory", 0));
    }
    let owner = owner_sid(dir)?;
    if owner != SID_SYSTEM && owner != SID_ADMINISTRATORS {
        return Err(WinError::new("store-unsafe-owner", 0));
    }
    apply_dacl(dir)
}

fn io_error(step: &'static str, error: &std::io::Error) -> WinError {
    WinError::new(
        step,
        error
            .raw_os_error()
            .map_or(0, |c| u32::try_from(c).unwrap_or(0)),
    )
}

fn owner_sid(path: &Path) -> Result<String, WinError> {
    let w = wide(path);
    let mut owner: *mut c_void = std::ptr::null_mut();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    // SAFETY: NUL-terminated path; out-pointers valid; the descriptor is freed below.
    let code = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(WinError::new("store-owner", code));
    }
    let result = sid_string(owner);
    // SAFETY: allocated by GetNamedSecurityInfoW, freed exactly once.
    unsafe { LocalFree(descriptor) };
    result
}

/// SID string of a valid SID pointer.
pub(crate) fn sid_string(sid: *mut c_void) -> Result<String, WinError> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID supplied by the caller; the string is freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(WinError::last("sid-to-string"));
    }
    let mut len = 0;
    // SAFETY: the API returns a NUL-terminated UTF-16 string.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` elements were just read.
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
    // SAFETY: allocated by ConvertSidToStringSidW, freed exactly once.
    unsafe { LocalFree(text.cast()) };
    Ok(value)
}

fn apply_dacl(dir: &Path) -> Result<(), WinError> {
    let sddl: Vec<u16> = DIR_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    // SAFETY: NUL-terminated SDDL; the descriptor is freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(WinError::last("store-sddl"));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut _ = std::ptr::null_mut();
    // SAFETY: `descriptor` is a valid self-relative descriptor; out-pointers are valid.
    let ok =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };
    let result = if ok == 0 || present == 0 {
        Err(WinError::last("store-dacl"))
    } else {
        let w = wide(dir);
        // SAFETY: valid path and DACL; owner/group/SACL are not changed.
        let code = unsafe {
            SetNamedSecurityInfoW(
                w.as_ptr().cast_mut(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(WinError::new("store-set-dacl", code))
        }
    };
    // SAFETY: allocated by the SDDL conversion, freed exactly once.
    unsafe { LocalFree(descriptor) };
    result
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).unwrap_or(0),
        pbData: data.as_ptr().cast_mut(),
    }
}

/// Seal bytes with DPAPI (machine scope, no UI).
pub fn seal(plain: &[u8]) -> Result<Vec<u8>, WinError> {
    let input = blob(plain);
    let entropy = blob(DPAPI_ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: input/entropy blobs point at live slices; output is freed below.
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(WinError::last("dpapi-seal"));
    }
    take(output)
}

/// Unseal DPAPI data. The result must be zeroized by the caller after use.
pub fn unseal(sealed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, WinError> {
    let input = blob(sealed);
    let entropy = blob(DPAPI_ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: as in `seal`.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(WinError::last("dpapi-unseal"));
    }
    take(output).map(zeroize::Zeroizing::new)
}

fn take(output: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, WinError> {
    if output.cbData == 0 || output.pbData.is_null() {
        // An empty result may carry a null pointer, which `from_raw_parts` forbids.
        if !output.pbData.is_null() {
            // SAFETY: allocated by the DPAPI call; freed once.
            unsafe { LocalFree(output.pbData.cast()) };
        }
        return Ok(Vec::new());
    }
    // SAFETY: the API returned `cbData` valid bytes at `pbData`.
    let data =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    // SAFETY: allocated by CryptProtectData/CryptUnprotectData; wiped then freed once.
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData.cast());
    }
    Ok(data)
}
