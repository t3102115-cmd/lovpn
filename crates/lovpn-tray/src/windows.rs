//! The Windows tray: one notification-area icon, a context menu and balloon notifications.
//!
//! A hidden window owns the icon. A worker thread polls the service (a blocking pipe call
//! must never run on the message thread) and wakes the window with a posted message; the
//! window thread alone touches the icon. Win32 is called through small wrappers so each
//! `unsafe` block states its own reason.
#![allow(unsafe_code)]
use crate::{
    icon,
    model::{Key, Tracker},
};
use lovpn_cli::client;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    ptr,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM},
    Graphics::Gdi::{CreateBitmap, DeleteObject},
    System::{LibraryLoader::GetModuleHandleW, Threading::CreateMutexW},
    UI::{
        Shell::{
            NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE,
            NIM_MODIFY, NIM_SETVERSION, NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW,
        },
        WindowsAndMessaging::{
            AppendMenuW, CW_USEDEFAULT, CreateIconIndirect, CreatePopupMenu, CreateWindowExW,
            DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW,
            GetCursorPos, GetMessageW, GetSystemMetrics, HICON, ICONINFO, MF_GRAYED, MF_SEPARATOR,
            MF_STRING, MSG, PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW,
            SM_CXSMICON, SetForegroundWindow, TPM_BOTTOMALIGN, TPM_RIGHTBUTTON, TrackPopupMenu,
            TranslateMessage, WM_APP, WM_COMMAND, WM_CONTEXTMENU, WM_DESTROY, WM_NULL, WNDCLASSW,
        },
    },
};

const WM_TRAY: u32 = WM_APP + 1;
const WM_STATE: u32 = WM_APP + 2;
const NIN_SELECT: u32 = 0x400;
const NIN_KEYSELECT: u32 = 0x401;
const ID_OPEN: usize = 1;
const ID_CONNECT: usize = 2;
const ID_DISCONNECT: usize = 3;
const ID_QUIT: usize = 4;
const POLL: Duration = Duration::from_secs(3);

/// What the worker hands to the window thread.
struct Shared {
    key: Key,
    message: Option<&'static str>,
}

static SHARED: Mutex<Shared> = Mutex::new(Shared {
    key: Key::Service,
    message: None,
});
static SOCKET: OnceLock<PathBuf> = OnceLock::new();
static TASKBAR_CREATED: OnceLock<u32> = OnceLock::new();
/// Icons built so far, per state, as raw handle values (only the window thread uses them).
static ICONS: Mutex<Vec<(Key, usize)>> = Mutex::new(Vec::new());

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Copy `text` into a fixed NUL-terminated UTF-16 field, truncating.
fn fill<const N: usize>(target: &mut [u16; N], text: &str) {
    for (slot, unit) in target.iter_mut().zip(text.encode_utf16().take(N - 1)) {
        *slot = unit;
    }
}

fn socket() -> &'static Path {
    SOCKET
        .get()
        .map_or(Path::new(r"\\.\pipe\lovpn-client"), |p| p.as_path())
}

fn icon_for(key: Key) -> HICON {
    let mut cache = ICONS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, handle)) = cache.iter().find(|(k, _)| *k == key) {
        return *handle as HICON;
    }
    // SAFETY: GetSystemMetrics has no preconditions.
    let size = usize::try_from(unsafe { GetSystemMetrics(SM_CXSMICON) })
        .unwrap_or(16)
        .clamp(16, 64);
    let mut color = icon::pixels(key, size);
    let side = i32::try_from(size).unwrap_or(16);
    // A 1-bpp mask has word-aligned rows; an all-zero mask is fine because the colour
    // bitmap carries its own alpha channel.
    let mask = vec![0u8; size.div_ceil(16) * 2 * size];
    // SAFETY: `color` holds size*size 32-bit pixels and `mask` covers every word-aligned
    // row of the 1-bpp bitmap; both outlive the calls (CreateBitmap copies the bits).
    let (hbm_color, hbm_mask) = unsafe {
        (
            CreateBitmap(side, side, 1, 32, color.as_mut_ptr().cast()),
            CreateBitmap(side, side, 1, 1, mask.as_ptr().cast()),
        )
    };
    let info = ICONINFO {
        fIcon: 1,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: hbm_mask,
        hbmColor: hbm_color,
    };
    // SAFETY: `info` is fully initialised and both bitmaps are valid GDI handles.
    let handle = unsafe { CreateIconIndirect(&info) };
    // SAFETY: CreateIconIndirect copied the bitmaps, so these handles are ours to delete.
    unsafe {
        DeleteObject(hbm_color.cast());
        DeleteObject(hbm_mask.cast());
    }
    cache.push((key, handle as usize));
    handle
}

fn notify_data(hwnd: HWND) -> NOTIFYICONDATAW {
    // SAFETY: NOTIFYICONDATAW is plain data for which all-zero is a valid initial value.
    let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    data.cbSize = u32::try_from(std::mem::size_of::<NOTIFYICONDATAW>()).unwrap_or(0);
    data.hWnd = hwnd;
    data.uID = 1;
    data
}

fn shell(command: u32, data: &NOTIFYICONDATAW) -> bool {
    // SAFETY: `data` is a fully initialised NOTIFYICONDATAW with the right cbSize.
    unsafe { Shell_NotifyIconW(command, data) != 0 }
}

fn show_icon(hwnd: HWND, key: Key, add: bool) {
    let mut data = notify_data(hwnd);
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = WM_TRAY;
    data.hIcon = icon_for(key);
    fill(&mut data.szTip, &format!("LoVPN: {}", key.title()));
    if add {
        data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        shell(NIM_ADD, &data);
        shell(NIM_SETVERSION, &data);
    } else {
        shell(NIM_MODIFY, &data);
    }
}

fn balloon(hwnd: HWND, text: &str) {
    let mut data = notify_data(hwnd);
    data.uFlags = NIF_INFO;
    data.dwInfoFlags = NIIF_INFO;
    fill(&mut data.szInfoTitle, "LoVPN");
    fill(&mut data.szInfo, text);
    shell(NIM_MODIFY, &data);
}

fn open_window() {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("lovpn-ui.exe")))
        .filter(|path| path.is_file());
    let _ = Command::new(sibling.unwrap_or_else(|| PathBuf::from("lovpn-ui.exe"))).spawn();
}

fn background(action: fn(&Path)) {
    std::thread::spawn(move || action(socket()));
}

fn current_key() -> Key {
    SHARED.lock().unwrap_or_else(|e| e.into_inner()).key
}

fn context_menu(hwnd: HWND) {
    let key = current_key();
    let flag = |enabled: bool| {
        if enabled {
            MF_STRING
        } else {
            MF_STRING | MF_GRAYED
        }
    };
    // SAFETY: plain Win32 menu calls on handles created here and destroyed below; the label
    // buffers live until each call returns (AppendMenuW copies the text).
    unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, wide(key.title()).as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        AppendMenuW(menu, MF_STRING, ID_OPEN, wide("Open LoVPN").as_ptr());
        AppendMenuW(
            menu,
            flag(key.can_connect()),
            ID_CONNECT,
            wide("Connect").as_ptr(),
        );
        AppendMenuW(
            menu,
            flag(key.can_disconnect()),
            ID_DISCONNECT,
            wide("Disconnect").as_ptr(),
        );
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        AppendMenuW(menu, MF_STRING, ID_QUIT, wide("Quit tray").as_ptr());
        let mut at = POINT { x: 0, y: 0 };
        GetCursorPos(&mut at);
        // The window must be foreground or the menu never closes when the user clicks away.
        SetForegroundWindow(hwnd);
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
            at.x,
            at.y,
            0,
            hwnd,
            ptr::null(),
        );
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
    }
}

extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_STATE => {
            let (key, text) = {
                let mut shared = SHARED.lock().unwrap_or_else(|e| e.into_inner());
                (shared.key, shared.message.take())
            };
            show_icon(hwnd, key, false);
            if let Some(text) = text {
                balloon(hwnd, text);
            }
            0
        }
        WM_TRAY => {
            // Version 4 packs the event in the low word of lparam.
            match (lparam & 0xffff) as u32 {
                WM_CONTEXTMENU => context_menu(hwnd),
                NIN_SELECT | NIN_KEYSELECT => open_window(),
                _ => {}
            }
            0
        }
        WM_COMMAND => {
            match wparam & 0xffff {
                ID_OPEN => open_window(),
                ID_CONNECT => background(|socket| {
                    let _ = client::connect(socket, None);
                }),
                ID_DISCONNECT => background(|socket| {
                    // Never releases the kill switch: that stays an explicit act in the window.
                    let _ = client::disconnect(socket, false);
                }),
                ID_QUIT => {
                    // SAFETY: hwnd is this thread's own window.
                    unsafe { DestroyWindow(hwnd) };
                }
                _ => {}
            }
            0
        }
        WM_DESTROY => {
            shell(NIM_DELETE, &notify_data(hwnd));
            // SAFETY: no arguments; ends this thread's message loop.
            unsafe { PostQuitMessage(0) };
            0
        }
        other if TASKBAR_CREATED.get() == Some(&other) => {
            // Explorer restarted and dropped every icon: add ours again.
            show_icon(hwnd, current_key(), true);
            0
        }
        // SAFETY: forwarding an unhandled message with the arguments we were given.
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

fn poll_loop(hwnd: usize) {
    let mut tracker = Tracker::default();
    let mut shown: Option<Key> = None;
    loop {
        let status: Option<Value> = client::status(socket()).ok().map(|report| report.data);
        let message = tracker.observe(Key::from_status(status.as_ref()));
        let settled = tracker.settled();
        if message.is_some() || (settled.is_some() && settled != shown) {
            {
                let mut shared = SHARED.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(key) = settled {
                    shared.key = key;
                }
                shared.message = message;
            }
            shown = settled;
            // SAFETY: PostMessageW may be called from any thread; a stale handle just fails.
            unsafe { PostMessageW(hwnd as HWND, WM_STATE, 0, 0) };
        }
        std::thread::sleep(POLL);
    }
}

pub fn run() -> ExitCode {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--socket", Some(path)) => {
                let _ = SOCKET.set(PathBuf::from(path));
            }
            _ => return ExitCode::from(2),
        }
    }
    // One tray per user session.
    // SAFETY: the name is a valid NUL-terminated string; the handle is kept for the process life.
    let _guard = unsafe { CreateMutexW(ptr::null(), 0, wide("Local\\LoVPN-Tray").as_ptr()) };
    // SAFETY: GetLastError has no preconditions.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return ExitCode::SUCCESS;
    }
    let class = wide("LoVPNTrayWindow");
    // SAFETY: standard window-class registration and window creation with valid pointers;
    // `class` outlives both calls and `window_proc` has the required signature.
    let hwnd = unsafe {
        let instance = GetModuleHandleW(ptr::null());
        let mut spec: WNDCLASSW = std::mem::zeroed();
        spec.lpfnWndProc = Some(window_proc);
        spec.hInstance = instance;
        spec.lpszClassName = class.as_ptr();
        if RegisterClassW(&spec) == 0 {
            return ExitCode::FAILURE;
        }
        let _ = TASKBAR_CREATED.set(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()));
        CreateWindowExW(
            0,
            class.as_ptr(),
            wide("LoVPN tray").as_ptr(),
            0,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            ptr::null(),
        )
    };
    if hwnd.is_null() {
        return ExitCode::FAILURE;
    }
    show_icon(hwnd, Key::Service, true);
    let handle = hwnd as usize;
    std::thread::spawn(move || poll_loop(handle));
    // SAFETY: a standard message loop on the thread that owns the window.
    unsafe {
        let mut message: MSG = std::mem::zeroed();
        while GetMessageW(&mut message, ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    for (_, handle) in ICONS.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
        // SAFETY: each handle came from CreateIconIndirect and is destroyed once.
        unsafe { DestroyIcon(handle as HICON) };
    }
    ExitCode::SUCCESS
}
