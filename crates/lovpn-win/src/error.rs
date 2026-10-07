use std::fmt;

/// A failed Win32 step. Carries only a static step name and the numeric Win32 error:
/// never paths, keys, addresses or OS-provided text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WinError {
    pub step: &'static str,
    pub win32: u32,
}

impl WinError {
    pub const fn new(step: &'static str, win32: u32) -> Self {
        Self { step, win32 }
    }

    /// The calling thread's last Win32 error, attributed to `step`.
    #[cfg(windows)]
    pub fn last(step: &'static str) -> Self {
        // SAFETY: GetLastError has no preconditions.
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Self::new(step, code)
    }

    pub const fn code(self) -> &'static str {
        "windows.step-failed"
    }
}

impl fmt::Display for WinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "A Windows networking step failed ({}, error {}). Changes were rolled back where possible; run diagnostics.",
            self.step, self.win32
        )
    }
}

impl std::error::Error for WinError {}
