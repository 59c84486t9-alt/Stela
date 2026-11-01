//! What a client process does with Linux's files, by Linux's own descriptors
//! (`compat/linux/stela/file.h`).
//!
//! # Safety
//! Every function here runs entered in the owner, on a task: an ioctl may
//! sleep. A client's pointers stay valid for the call.
use super::owner::Errno;
use core::{
    ffi::{c_int, c_long, c_uint, c_void},
    ptr,
};

/// Physically contiguous memory the owner holds, in whole pages:
/// `stela_linux_run`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Run {
    pub physical: u64,
    pub bytes: u64,
}

/// A client's mapping of a file.
#[derive(Clone, Copy, Debug)]
pub struct Mapping(*mut c_void);

unsafe extern "C" {
    fn stela_linux_open(device: u32, flags: c_uint) -> c_int;
    fn stela_linux_export(runs: *const Run, count: usize) -> c_int;
    fn stela_linux_fd_close(fd: c_int);
    fn stela_linux_fd_dup(fd: c_int) -> c_int;
    fn stela_linux_fd_device(fd: c_int) -> c_long;
    fn stela_linux_ioctl(fd: c_int, request: c_uint, argument: *mut c_void) -> c_long;
    fn stela_linux_map(
        fd: c_int,
        space: *mut c_void,
        address: u64,
        size: usize,
        offset: u64,
        mapping: *mut *mut c_void,
    ) -> c_int;
    fn stela_linux_munmap(mapping: *mut c_void);
    fn stela_linux_refault(mapping: *mut c_void, address: u64, write: bool) -> bool;
    fn stela_linux_wait(word: *const c_uint, value: c_uint, nanoseconds: u64);
    fn stela_linux_wake();
}

/// Sleep while `word` holds `value`, for at most `nanoseconds`, or with no limit
/// at `u64::MAX`.
///
/// # Safety
/// See the module.
pub unsafe fn wait(word: *const c_uint, value: c_uint, nanoseconds: u64) {
    // SAFETY: the module's contract.
    unsafe { stela_linux_wait(word, value, nanoseconds) };
}

/// Wake every [`wait`] to look at its word again.
///
/// # Safety
/// See the module.
pub unsafe fn wake() {
    // SAFETY: the module's contract.
    unsafe { stela_linux_wake() };
}

/// Open Linux character device `device` with `flags`, for a descriptor or negative errno.
///
/// # Safety
/// See the module.
pub unsafe fn open(device: u32, flags: c_uint) -> Errno {
    // SAFETY: the module's contract.
    unsafe { stela_linux_open(device, flags) }
}

/// A dma-buf of `runs`, for a descriptor or a negative errno.
///
/// # Safety
/// See the module. The memory outlives the buffer.
pub unsafe fn export(runs: &[Run]) -> Errno {
    // SAFETY: the module's contract and this function's.
    unsafe { stela_linux_export(runs.as_ptr(), runs.len()) }
}

/// # Safety
/// See the module.
pub unsafe fn close(fd: c_int) -> Errno {
    // SAFETY: the module's contract.
    unsafe { stela_linux_fd_close(fd) };
    0
}

/// # Safety
/// See the module.
pub unsafe fn duplicate(fd: c_int) -> Errno {
    // SAFETY: the module's contract.
    unsafe { stela_linux_fd_dup(fd) }
}

/// The descriptor's device number, Linux's `dev_t`, or a negative errno.
///
/// # Safety
/// See the module.
pub unsafe fn device(fd: c_int) -> i64 {
    // SAFETY: the module's contract.
    unsafe { stela_linux_fd_device(fd) }
}

/// # Safety
/// See the module. `argument` is what `request` says it is.
pub unsafe fn control(fd: c_int, request: u32, argument: *mut c_void) -> i64 {
    // SAFETY: the module's contract and this function's.
    unsafe { stela_linux_ioctl(fd, request, argument) }
}

/// Map `size` bytes of the file at `offset` into `address`, every page present.
///
/// # Safety
/// See the module. `address` is the caller's to map.
pub unsafe fn map(fd: c_int, address: u64, size: usize, offset: u64) -> Result<Mapping, Errno> {
    let mut mapping = ptr::null_mut();
    // SAFETY: the module's contract and this function's. One address space
    // serves every client, so `space` carries nothing.
    let error =
        unsafe { stela_linux_map(fd, ptr::null_mut(), address, size, offset, &raw mut mapping) };
    if error == 0 {
        Ok(Mapping(mapping))
    } else {
        Err(error)
    }
}

/// # Safety
/// See the module. `mapping` is not used after this.
pub unsafe fn unmap(mapping: Mapping) {
    // SAFETY: the module's contract and this function's.
    unsafe { stela_linux_munmap(mapping.0) };
}

/// Install the page at `address` again, after Linux moved what it maps.
///
/// # Safety
/// See the module.
pub unsafe fn fault(mapping: Mapping, address: u64, write: bool) -> bool {
    // SAFETY: the module's contract.
    unsafe { stela_linux_refault(mapping.0, address, write) }
}
