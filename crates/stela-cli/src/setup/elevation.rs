//! Request Windows disk-write rights before asking for installer preferences,
//! and keep the window the elevated copy runs in readable when it finishes.
use anyhow::Result;

#[cfg(windows)]
static RELAUNCHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(not(windows))]
pub(super) fn relaunch() -> Result<bool> {
    Ok(false)
}

#[cfg(not(windows))]
pub(crate) fn hold_window(_: bool) {}

/// Windows closes a console window when its last process exits. The elevated
/// copy and a double-clicked stela.exe own theirs, so wait for a key there
/// before the result or error disappears; a terminal's shell keeps its window.
#[cfg(windows)]
pub(crate) fn hold_window(success: bool) {
    use std::{io::IsTerminal, sync::atomic::Ordering};
    use windows_sys::Win32::System::Console::GetConsoleProcessList;
    if RELAUNCHED.load(Ordering::Relaxed) || !std::io::stdin().is_terminal() {
        return;
    }
    let mut processes = [0u32; 2];
    // SAFETY: writes at most two process IDs into the local buffer.
    if unsafe { GetConsoleProcessList(processes.as_mut_ptr(), 2) } != 1 {
        return;
    }
    let prompt = if success {
        "Press any key to close this window."
    } else {
        "Setup did not finish. Press any key to close this window."
    };
    eprintln!("\n{}", console::style(prompt).for_stderr().dim());
    let _ = console::Term::stderr().read_key();
}

#[cfg(windows)]
pub(super) fn relaunch() -> Result<bool> {
    use anyhow::ensure;
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::{
        Shell::{IsUserAnAdmin, ShellExecuteW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    };
    // SAFETY: queries the calling process's token; no pointer arguments.
    if unsafe { IsUserAnAdmin() } != 0 {
        return Ok(false);
    }
    let exe: Vec<u16> = std::env::current_exe()?
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let cwd: Vec<u16> = std::env::current_dir()?
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let parameters = parameters(std::env::args_os().skip(1));
    let verb: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    // SAFETY: all strings are NUL-terminated and live through this synchronous
    // launch request. Windows owns the UAC consent dialog and the new console.
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            parameters.as_ptr(),
            cwd.as_ptr(),
            SW_SHOWNORMAL,
        )
    };
    ensure!(
        result as isize > 32,
        "administrator access was cancelled or unavailable; your USB was not changed"
    );
    RELAUNCHED.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(true)
}

#[cfg(windows)]
fn parameters(args: impl Iterator<Item = std::ffi::OsString>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut result = Vec::new();
    for arg in args {
        if !result.is_empty() {
            result.push(b' ' as u16);
        }
        result.push(b'"' as u16);
        let mut slashes = 0;
        for unit in arg.encode_wide() {
            if unit == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            result.extend(std::iter::repeat_n(
                b'\\' as u16,
                if unit == b'"' as u16 {
                    slashes * 2 + 1
                } else {
                    slashes
                },
            ));
            result.push(unit);
            slashes = 0;
        }
        result.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        result.push(b'"' as u16);
    }
    result.push(0);
    result
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn elevation_preserves_argument_quoting() {
        let arguments = [
            "setup",
            "--ipsw",
            "C:\\my images\\mac.ipsw",
            "a\"b",
            "C:\\tail\\",
            "--profile",
        ];
        let quoted = parameters(arguments.into_iter().map(Into::into));
        assert_eq!(
            String::from_utf16(&quoted[..quoted.len() - 1]).unwrap(),
            "\"setup\" \"--ipsw\" \"C:\\my images\\mac.ipsw\" \"a\\\"b\" \"C:\\tail\\\\\" \"--profile\""
        );
    }
}
