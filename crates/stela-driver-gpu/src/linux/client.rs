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

const DRM_MAJOR: u32 = 226;
/// Linux's `MINORBITS`.
const MINOR_BITS: u32 = 20;

/// A client's mapping of a file.
#[derive(Clone, Copy, Debug)]
pub struct Mapping(*mut c_void);

unsafe extern "C" {
    fn stela_linux_open(device: u32, flags: c_uint) -> c_int;
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
}

/// Open DRM's character device `minor`, for a descriptor or a negative errno.
///
/// # Safety
/// See the module.
pub unsafe fn open(minor: u32) -> Errno {
    /// `O_RDWR`.
    const READ_WRITE: c_uint = 2;
    // SAFETY: the module's contract.
    unsafe { stela_linux_open(DRM_MAJOR << MINOR_BITS | minor, READ_WRITE) }
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
