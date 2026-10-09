//! The service's local control channel: a named pipe that only the owning user, SYSTEM and
//! Administrators can open, whose callers are re-verified from their access token.
//!
//! - the DACL grants SYSTEM and Administrators full control and the owner read/write data
//!   but *not* the right to create pipe instances, so no one else can squat the name;
//! - the first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`; a listening
//!   instance always exists, so there is no window in which the name is free;
//! - remote clients are rejected by the kernel (`PIPE_REJECT_REMOTE_CLIENTS`).
use crate::{WinError, store};
use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle},
    sync::mpsc,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, RevertToSelf,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    },
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
    System::{
        IO::CancelIoEx,
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient,
            PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{GetCurrentThread, OpenThreadToken},
    },
};

/// A client has this long to send one complete request line.
const READ_DEADLINE: Duration = Duration::from_secs(5);

pub const DEFAULT_PIPE: &str = r"\\.\pipe\lovpn-client";
/// SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | FILE_READ_DATA:
/// open and talk, but no FILE_CREATE_PIPE_INSTANCE (which shares FILE_APPEND_DATA's bit).
const OWNER_RIGHTS: &str = "0x120083";

pub struct Listener {
    name: Vec<u16>,
    sddl: Vec<u16>,
    first: bool,
    /// Instance already listening for the next client.
    pending: Option<File>,
}

pub struct Connection {
    file: File,
}

/// Who is on the other end, from the access token the kernel attached to the connection.
pub struct Caller {
    pub sid: String,
    pub is_admin: bool,
}

impl Listener {
    /// `owner_sid` is the controlling user (the one who installed the service).
    pub fn new(pipe_name: &str, owner_sid: &str) -> Self {
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;{OWNER_RIGHTS};;;{owner_sid})");
        Self {
            name: pipe_name.encode_utf16().chain(std::iter::once(0)).collect(),
            sddl: sddl.encode_utf16().chain(std::iter::once(0)).collect(),
            first: true,
            pending: None,
        }
    }

    fn create_instance(&mut self) -> Result<File, WinError> {
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        // SAFETY: NUL-terminated SDDL; the descriptor is freed below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                self.sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(WinError::last("pipe-sddl"));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if self.first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // SAFETY: NUL-terminated name; `attributes` and its descriptor outlive the call.
        let handle: HANDLE = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                255,
                64 * 1024,
                96 * 1024,
                0,
                &attributes,
            )
        };
        let error = WinError::last("pipe-create");
        // SAFETY: allocated by the SDDL conversion, freed exactly once.
        unsafe { LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        self.first = false;
        // SAFETY: `handle` is a valid, exclusively owned pipe handle; File closes it.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    /// Block until a client connects. A fresh listening instance is created *before* the
    /// connected one is handed out, so the pipe name is never unowned.
    pub fn accept(&mut self) -> Result<Connection, WinError> {
        let listening = match self.pending.take() {
            Some(f) => f,
            None => self.create_instance()?,
        };
        // SAFETY: valid pipe handle; no OVERLAPPED, so the call blocks.
        let ok = unsafe { ConnectNamedPipe(listening.as_raw_handle(), std::ptr::null_mut()) };
        if ok == 0 && WinError::last("pipe-connect").win32 != ERROR_PIPE_CONNECTED {
            return Err(WinError::last("pipe-connect"));
        }
        self.pending = Some(self.create_instance()?);
        Ok(Connection { file: listening })
    }
}

impl Connection {
    /// One request line of at most `limit` bytes, within `READ_DEADLINE`. The accept loop is
    /// single-threaded, so a client that connects and stays silent must not hold it: a
    /// watchdog cancels the blocked read when the deadline passes.
    pub fn read_line(&mut self, limit: usize) -> Option<Vec<u8>> {
        let (done, expired) = mpsc::channel::<()>();
        let handle = self.file.as_raw_handle() as usize;
        let watchdog = std::thread::spawn(move || {
            if expired.recv_timeout(READ_DEADLINE) == Err(mpsc::RecvTimeoutError::Timeout) {
                // SAFETY: `read_line` joins this thread before returning, so the handle is
                // still open; cancelling pending I/O on it has no other precondition.
                unsafe { CancelIoEx(handle as HANDLE, std::ptr::null()) };
            }
        });
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        let result = loop {
            if line.len() > limit {
                break None;
            }
            match self.file.read(&mut byte) {
                Ok(1) if byte[0] == b'\n' => break Some(line),
                Ok(1) => line.push(byte[0]),
                _ => break None,
            }
        };
        let _ = done.send(());
        let _ = watchdog.join();
        result
    }

    pub fn write_line(&mut self, bytes: &[u8]) {
        let _ = self.file.write_all(bytes);
        let _ = self.file.write_all(b"\n");
        let _ = self.file.flush();
        // FlushFileBuffers on a pipe waits until the client has read everything; without
        // it DisconnectNamedPipe would discard the unread response.
        let _ = self.file.sync_all();
    }

    /// Identify the caller from the token the kernel attached to the connection.
    pub fn caller(&self) -> Result<Caller, WinError> {
        // SAFETY: valid, connected pipe handle.
        if unsafe { ImpersonateNamedPipeClient(self.file.as_raw_handle()) } == 0 {
            return Err(WinError::last("pipe-impersonate"));
        }
        let result = identify();
        // SAFETY: undoes the impersonation on this thread; no preconditions.
        unsafe { RevertToSelf() };
        result
    }
}

fn identify() -> Result<Caller, WinError> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the thread is impersonating; the token handle is closed through File below.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return Err(WinError::last("pipe-token"));
    }
    // SAFETY: `token` is a valid handle we own; File closes it on drop.
    let token = unsafe { File::from_raw_handle(token) };
    let mut needed = 0u32;
    // SAFETY: size query only; null buffer with zero length.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: the buffer is at least `needed` bytes and 8-byte aligned.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(WinError::last("pipe-token-user"));
    }
    // SAFETY: on success the buffer holds a TOKEN_USER whose SID lives in the same buffer.
    let sid = store::sid_string(unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;

    let mut admin = vec![0u64; 12]; // SECURITY_MAX_SID_SIZE is 68 bytes
    let mut size = 96u32;
    // SAFETY: the buffer is at least `size` bytes.
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            admin.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(WinError::last("pipe-admin-sid"));
    }
    let mut member = 0;
    // SAFETY: valid impersonation token and SID; `member` is a valid out-pointer.
    if unsafe {
        CheckTokenMembership(
            token.as_raw_handle(),
            admin.as_mut_ptr().cast(),
            &mut member,
        )
    } == 0
    {
        return Err(WinError::last("pipe-membership"));
    }
    Ok(Caller {
        sid,
        is_admin: member != 0,
    })
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: valid pipe handle; disconnecting releases the instance for reuse/close.
        unsafe { DisconnectNamedPipe(self.file.as_raw_handle()) };
    }
}
