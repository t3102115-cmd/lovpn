//! Bounded, unprivileged public-profile imports. Not a privileged path resolver.
use crate::AppError;
use lovpn_config::{ClientConfig, MAX_CONFIG_BYTES};
use std::{fs::File, io::Read, path::Path};

pub fn load(path: &Path) -> Result<ClientConfig, AppError> {
    lovpn_config::parse(&read_text(path)?).map_err(Into::into)
}

/// Read a bounded, permission-checked public profile as text (not yet validated).
pub fn read_text(path: &Path) -> Result<String, AppError> {
    let invalid_file = || {
        AppError::new(
            "config.file",
            "Cannot read a regular public configuration file. Check its type, permissions and location. Symlinks are not accepted; no path or contents are included in this error.",
        )
    };
    let before = std::fs::symlink_metadata(path).map_err(|_| invalid_file())?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(invalid_file());
    }
    let file = open_no_follow(path).map_err(|_| invalid_file())?;
    let metadata = file.metadata().map_err(|_| invalid_file())?;
    if !metadata.is_file() {
        return Err(invalid_file());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(AppError::new(
                "config.permissions",
                "Configuration must not be writable by group or other users.",
            ));
        }
    }
    let mut contents = Vec::new();
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(|_| invalid_file())?;
    if contents.len() > MAX_CONFIG_BYTES {
        return Err(lovpn_config::ConfigError::TooLarge.into());
    }
    String::from_utf8(contents)
        .map_err(|_| AppError::new("config.encoding", "Configuration must be UTF-8 text."))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, open};
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    Ok(File::from(open(path, flags, Mode::empty())?))
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    // Documented Win32 FILE_FLAG_OPEN_REPARSE_POINT. Do not follow a final symlink.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
compile_error!("LoVPN currently targets Linux and Windows only");
