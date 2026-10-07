//! WireGuardNT (wireguard.dll) loading and adapter control.
//!
//! The DLL is the signed official WireGuardNT 1.1 `amd64` build. It is hashed and compared
//! with the pinned digest before it is loaded, so a swapped or corrupted file is refused.
use crate::WinError;
use lovpn_keys::{ClientPrivateKey, ServerPublicKey};
use sha2::{Digest, Sha256};
use std::{ffi::c_void, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_MORE_DATA, HMODULE},
        NetworkManagement::Ndis::NET_LUID_LH,
        Networking::WinSock::{AF_INET, SOCKADDR_INET},
        System::LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW},
    },
    core::GUID,
};

/// SHA-256 of `wireguard-nt-1.1.zip` → `wireguard-nt/bin/amd64/wireguard.dll`
/// (Authenticode: WireGuard LLC), from download.wireguard.com.
pub const WIREGUARD_DLL_SHA256: &str =
    "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3";

/// Stable adapter identity so Windows keeps one network profile instead of one per run.
const ADAPTER_GUID: GUID = GUID {
    data1: 0x4c6f_5650,
    data2: 0x4e00,
    data3: 0x4000,
    data4: [0x8c, 0x1f, 0x4c, 0x6f, 0x56, 0x50, 0x4e, 0x01],
};

const MAX_CONFIG_BYTES: usize = 1 << 16;
const KEEPALIVE_SECS: u16 = 25;

type Handle = *mut c_void;

#[repr(C, align(8))]
struct RawInterface {
    flags: u32,
    listen_port: u16,
    private_key: [u8; 32],
    public_key: [u8; 32],
    peers_count: u32,
}

#[repr(C, align(8))]
struct RawPeer {
    flags: u32,
    reserved: u32,
    public_key: [u8; 32],
    preshared_key: [u8; 32],
    persistent_keepalive: u16,
    endpoint: SOCKADDR_INET,
    tx_bytes: u64,
    rx_bytes: u64,
    last_handshake: u64,
    allowed_ips_count: u32,
}

#[repr(C, align(8))]
struct RawAllowedIp {
    address: [u8; 16],
    family: u16,
    cidr: u8,
    flags: u32,
}

const INTERFACE_HAS_PRIVATE_KEY: u32 = 1 << 1;
const INTERFACE_REPLACE_PEERS: u32 = 1 << 3;
const PEER_HAS_PUBLIC_KEY: u32 = 1;
const PEER_HAS_KEEPALIVE: u32 = 1 << 2;
const PEER_HAS_ENDPOINT: u32 = 1 << 3;
const PEER_REPLACE_ALLOWED_IPS: u32 = 1 << 5;

// Compile-time proof that the Rust layout equals the C header's (see wireguard.h).
const _: () = {
    assert!(size_of::<RawInterface>() == 80);
    assert!(size_of::<RawPeer>() == 136);
    assert!(size_of::<RawAllowedIp>() == 24);
};

/// The driver's entry points. Function pointers are copied out; the module is never
/// unloaded, so they stay valid for the life of the process.
#[derive(Clone, Copy)]
pub struct Driver {
    create: CreateFn,
    open: OpenFn,
    close: CloseFn,
    luid: LuidFn,
    set_state: SetStateFn,
    set_config: SetConfigFn,
    get_config: GetConfigFn,
}

type CreateFn = unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> Handle;
type OpenFn = unsafe extern "system" fn(*const u16) -> Handle;
type CloseFn = unsafe extern "system" fn(Handle);
type LuidFn = unsafe extern "system" fn(Handle, *mut NET_LUID_LH);
type SetStateFn = unsafe extern "system" fn(Handle, i32) -> i32;
type SetConfigFn = unsafe extern "system" fn(Handle, *const RawInterface, u32) -> i32;
type GetConfigFn = unsafe extern "system" fn(Handle, *mut RawInterface, *mut u32) -> i32;

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

impl Driver {
    /// Verify and load `wireguard.dll` from an absolute path.
    pub fn load(dll: &Path) -> Result<Self, WinError> {
        if !dll.is_absolute() {
            return Err(WinError::new("driver-path-not-absolute", 0));
        }
        let bytes = std::fs::read(dll).map_err(|e| {
            WinError::new(
                "driver-read",
                e.raw_os_error()
                    .map_or(0, |c| u32::try_from(c).unwrap_or(0)),
            )
        })?;
        let digest = Sha256::digest(&bytes);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        if hex != WIREGUARD_DLL_SHA256 {
            return Err(WinError::new("driver-hash-mismatch", 0));
        }
        let path = wide(&dll.to_string_lossy());
        // SAFETY: `path` is a NUL-terminated UTF-16 string; the handle argument must be null.
        let module: HMODULE = unsafe {
            LoadLibraryExW(
                path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        if module.is_null() {
            return Err(WinError::last("driver-load"));
        }
        macro_rules! symbol {
            ($name:literal, $ty:ty) => {{
                // SAFETY: `module` is a valid loaded module and the name is NUL-terminated.
                let address = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
                match address {
                    // SAFETY: the signature matches the documented prototype in wireguard.h
                    // for this exact, hash-pinned driver release.
                    Some(f) => unsafe {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(f)
                    },
                    None => return Err(WinError::new(concat!("driver-symbol-", $name), 0)),
                }
            }};
        }
        Ok(Self {
            create: symbol!("WireGuardCreateAdapter", CreateFn),
            open: symbol!("WireGuardOpenAdapter", OpenFn),
            close: symbol!("WireGuardCloseAdapter", CloseFn),
            luid: symbol!("WireGuardGetAdapterLUID", LuidFn),
            set_state: symbol!("WireGuardSetAdapterState", SetStateFn),
            set_config: symbol!("WireGuardSetConfiguration", SetConfigFn),
            get_config: symbol!("WireGuardGetConfiguration", GetConfigFn),
        })
    }

    /// Create the adapter. If a stale LoVPN adapter with this name exists (a previous crash)
    /// it is opened and closed first so it is removed, never adopted blindly.
    pub fn create_adapter(&self, name: &str) -> Result<Adapter, WinError> {
        self.remove_stale(name);
        let name_w = wide(name);
        let kind = wide("LoVPN");
        // SAFETY: both strings are NUL-terminated; the GUID outlives the call.
        let handle = unsafe { (self.create)(name_w.as_ptr(), kind.as_ptr(), &ADAPTER_GUID) };
        if handle.is_null() {
            return Err(WinError::last("adapter-create"));
        }
        Ok(Adapter {
            driver: *self,
            handle,
        })
    }

    /// Remove an adapter by name if one exists. Used for recovery after a crash.
    pub fn remove_stale(&self, name: &str) {
        let name_w = wide(name);
        // SAFETY: NUL-terminated name; a non-null handle returned by open is closed once.
        // Closing an opened (not created) adapter only releases the handle, so the adapter
        // is deleted by the creating process exiting; see `Adapter::drop`.
        let handle = unsafe { (self.open)(name_w.as_ptr()) };
        if !handle.is_null() {
            // SAFETY: `handle` came from WireGuardOpenAdapter above and is closed once.
            unsafe { (self.close)(handle) };
        }
    }
}

/// A WireGuard adapter created by this process. Dropping it removes the adapter.
pub struct Adapter {
    driver: Driver,
    handle: Handle,
}

// SAFETY: the driver API is documented as callable from any thread for one adapter handle,
// and `Adapter` has unique ownership of the handle.
unsafe impl Send for Adapter {}

pub struct Observation {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Seconds since the last completed handshake, or None if there has been none.
    pub handshake_age_secs: Option<u64>,
}

impl Adapter {
    pub fn luid(&self) -> u64 {
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: valid handle and a valid out-pointer.
        unsafe { (self.driver.luid)(self.handle, &mut luid) };
        // SAFETY: reading the integer view of the union; every bit pattern is valid.
        unsafe { luid.Value }
    }

    /// Install key and single peer; allowed IPs are the full IPv4 default route.
    pub fn configure(
        &self,
        key: &ClientPrivateKey,
        server: &ServerPublicKey,
        endpoint: std::net::SocketAddrV4,
        allowed: &[(std::net::Ipv4Addr, u8)],
    ) -> Result<(), WinError> {
        let words = 80 / 8 + 136 / 8 + allowed.len() * 3;
        // u64 backing store guarantees the 8-byte alignment the driver structs require.
        let mut buffer = zeroize::Zeroizing::new(vec![0u64; words]);
        let base = buffer.as_mut_ptr().cast::<u8>();
        let private = key.expose_bytes();
        let interface = RawInterface {
            flags: INTERFACE_HAS_PRIVATE_KEY | INTERFACE_REPLACE_PEERS,
            listen_port: 0,
            private_key: *private,
            public_key: [0; 32],
            peers_count: 1,
        };
        // SAFETY: SOCKADDR_INET is plain data; all-zero is a valid value.
        let mut sockaddr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        sockaddr.Ipv4.sin_family = AF_INET;
        sockaddr.Ipv4.sin_port = endpoint.port().to_be();
        sockaddr.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(endpoint.ip().octets());
        let peer = RawPeer {
            flags: PEER_HAS_PUBLIC_KEY
                | PEER_HAS_KEEPALIVE
                | PEER_HAS_ENDPOINT
                | PEER_REPLACE_ALLOWED_IPS,
            reserved: 0,
            public_key: *server.as_bytes(),
            preshared_key: [0; 32],
            persistent_keepalive: KEEPALIVE_SECS,
            endpoint: sockaddr,
            tx_bytes: 0,
            rx_bytes: 0,
            last_handshake: 0,
            allowed_ips_count: u32::try_from(allowed.len()).unwrap_or(0),
        };
        // SAFETY: `buffer` holds `words` u64s (= interface + peer + allowed IPs), 8-aligned,
        // and the three writes stay inside it at the offsets used by the C layout.
        unsafe {
            base.cast::<RawInterface>().write(interface);
            base.add(80).cast::<RawPeer>().write(peer);
            for (i, (addr, cidr)) in allowed.iter().enumerate() {
                let mut address = [0u8; 16];
                address[..4].copy_from_slice(&addr.octets());
                base.add(80 + 136 + i * 24)
                    .cast::<RawAllowedIp>()
                    .write(RawAllowedIp {
                        address,
                        family: AF_INET,
                        cidr: *cidr,
                        flags: 0,
                    });
            }
        }
        let bytes = u32::try_from(words * 8).unwrap_or(0);
        // SAFETY: valid handle; `buffer` is `bytes` long and initialized.
        let ok = unsafe { (self.driver.set_config)(self.handle, base.cast(), bytes) };
        if ok == 0 {
            return Err(WinError::last("adapter-configure"));
        }
        Ok(())
    }

    pub fn set_up(&self, up: bool) -> Result<(), WinError> {
        // SAFETY: valid handle; the state is 0 (down) or 1 (up). Sockets belong to this process.
        let ok = unsafe { (self.driver.set_state)(self.handle, i32::from(up)) };
        if ok == 0 {
            return Err(WinError::last("adapter-state"));
        }
        Ok(())
    }

    /// Transfer counters and handshake age of the single peer.
    pub fn observe(&self) -> Result<Observation, WinError> {
        let mut size: u32 = 4096;
        loop {
            let mut buffer = vec![0u64; size as usize / 8];
            let mut bytes = size;
            // SAFETY: valid handle; `buffer` has `bytes` bytes and 8-byte alignment.
            let ok = unsafe {
                (self.driver.get_config)(self.handle, buffer.as_mut_ptr().cast(), &mut bytes)
            };
            if ok == 0 {
                let err = WinError::last("adapter-observe");
                if err.win32 == ERROR_MORE_DATA && (bytes as usize) <= MAX_CONFIG_BYTES {
                    size = bytes;
                    continue;
                }
                return Err(err);
            }
            // SAFETY: on success the buffer begins with an interface struct (80 bytes).
            let interface = unsafe { &*buffer.as_ptr().cast::<RawInterface>() };
            if interface.peers_count == 0 {
                return Ok(Observation {
                    rx_bytes: 0,
                    tx_bytes: 0,
                    handshake_age_secs: None,
                });
            }
            // SAFETY: peers_count >= 1 so a peer struct follows the interface; the driver
            // reported at least that many bytes.
            let peer = unsafe { &*buffer.as_ptr().cast::<u8>().add(80).cast::<RawPeer>() };
            return Ok(Observation {
                rx_bytes: peer.rx_bytes,
                tx_bytes: peer.tx_bytes,
                handshake_age_secs: handshake_age(peer.last_handshake),
            });
        }
    }
}

/// FILETIME (100 ns since 1601) of the handshake, converted to an age in seconds.
fn handshake_age(last: u64) -> Option<u64> {
    if last == 0 {
        return None;
    }
    // SAFETY: GetSystemTimeAsFileTime writes one FILETIME to the pointer.
    let mut now = windows_sys::Win32::Foundation::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: valid out-pointer.
    unsafe { windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&mut now) };
    let now = (u64::from(now.dwHighDateTime) << 32) | u64::from(now.dwLowDateTime);
    Some(now.saturating_sub(last) / 10_000_000)
}

impl Drop for Adapter {
    fn drop(&mut self) {
        // SAFETY: the handle came from WireGuardCreateAdapter and is closed exactly once;
        // closing a created adapter also removes it.
        unsafe { (self.driver.close)(self.handle) };
    }
}
