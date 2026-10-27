//! Anonymous host pages for code the tasks run natively: the oracle's
//! translated cases and the AMX kernels. They are POSIX mappings; on other
//! hosts, mapping reports the native runs as unsupported.
use anyhow::Result;
use std::ptr::NonNull;

#[cfg(not(unix))]
const UNSUPPORTED: &str =
    "UNSUPPORTED native code execution: it needs a host with POSIX memory mappings";

/// What a mapping's pages permit.
#[derive(Clone, Copy)]
pub enum Access {
    ReadWrite,
    ReadExecute,
}

#[cfg(unix)]
impl Access {
    fn protection(self) -> libc::c_int {
        match self {
            Self::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            Self::ReadExecute => libc::PROT_READ | libc::PROT_EXEC,
        }
    }
}

/// Map fresh zeroed pages, at exactly `address` when one is given, refusing
/// to replace a mapping there.
#[cfg(unix)]
pub fn map(address: Option<u64>, bytes: usize, access: Access) -> Result<NonNull<u8>> {
    use anyhow::{Context, bail, ensure};
    let hint = address.map_or(std::ptr::null_mut(), |address| address as *mut libc::c_void);
    // SAFETY: a hinted anonymous mapping never replaces existing memory; the
    // result is checked against the requested address before use.
    let pointer = unsafe {
        libc::mmap(
            hint,
            bytes,
            access.protection(),
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    ensure!(
        pointer != libc::MAP_FAILED,
        "{}",
        std::io::Error::last_os_error()
    );
    if let Some(address) = address
        && pointer as u64 != address
    {
        // SAFETY: release the mapping the kernel placed elsewhere.
        unsafe { libc::munmap(pointer, bytes) };
        bail!("{address:#x} is already mapped in this process");
    }
    NonNull::new(pointer.cast()).context("null mapping")
}

#[cfg(not(unix))]
pub fn map(_: Option<u64>, _: usize, _: Access) -> Result<NonNull<u8>> {
    anyhow::bail!(UNSUPPORTED)
}

/// Change the access of `bytes` from `pointer`.
///
/// # Safety
/// The pages must belong to a mapping from [`map`] that the caller owns.
#[cfg(unix)]
pub unsafe fn protect(pointer: *mut u8, bytes: usize, access: Access) -> Result<()> {
    // SAFETY: the caller passes pages of a mapping this process owns.
    let status = unsafe { libc::mprotect(pointer.cast(), bytes, access.protection()) };
    anyhow::ensure!(status == 0, "{}", std::io::Error::last_os_error());
    Ok(())
}

#[cfg(not(unix))]
pub unsafe fn protect(_: *mut u8, _: usize, _: Access) -> Result<()> {
    anyhow::bail!(UNSUPPORTED)
}

/// Release a whole mapping from [`map`].
///
/// # Safety
/// The caller owns the mapping, and nothing uses it afterwards.
pub unsafe fn unmap(pointer: *mut u8, bytes: usize) {
    // SAFETY: the caller owns the whole mapping.
    #[cfg(unix)]
    unsafe {
        libc::munmap(pointer.cast(), bytes)
    };
    // No other host maps pages.
    #[cfg(not(unix))]
    let _ = (pointer, bytes);
}
