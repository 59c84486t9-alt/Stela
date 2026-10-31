//! nouveau in a Linux environment: the initcalls that register it, DRM and the
//! subsystems beneath them (`build/initcalls.rs`).
use super::owner::Errno;
use core::{
    ffi::{c_int, c_void},
    ptr,
};

unsafe extern "C" {
    static stela_linux_nouveau_image: c_void;
    fn stela_linux_start(image: *const c_void, registry: *mut *mut c_void) -> c_int;
}

/// Bring Linux up as far as a device can bind, stopping at the first stage
/// that fails. Each environment does this once.
///
/// # Safety
/// In an entered Linux owner, on a Linux task, as initcalls may sleep.
pub unsafe fn start() -> Result<(), Errno> {
    let mut registry = ptr::null_mut();
    // SAFETY: the caller's contract; the image is the build's, and the
    // registry's state lasts as long as what it started.
    match unsafe { stela_linux_start(&raw const stela_linux_nouveau_image, &raw mut registry) } {
        0 => Ok(()),
        error => Err(error),
    }
}
