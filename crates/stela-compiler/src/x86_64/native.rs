//! Running emitted code on the host in tests.
use crate::GuestState;

/// Run `code`, followed by a RET, on the host with RDI = `state`.
pub(crate) fn run(code: &[u8], state: &mut GuestState) {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PROT_READ_WRITE: i32 = 3;
    const PROT_READ_EXECUTE: i32 = 5;
    const MAP_PRIVATE: i32 = 2;
    const RET: u8 = 0xc3;
    let bytes = (code.len() + 1).next_multiple_of(4096);
    // SAFETY: private anonymous memory, RX after the copy and unmapped after
    // the call; the code touches only `state`.
    unsafe {
        let page = mmap(
            core::ptr::null_mut(),
            bytes,
            PROT_READ_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(page as usize, usize::MAX);
        core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
        page.cast::<u8>().add(code.len()).write(RET);
        assert_eq!(mprotect(page, bytes, PROT_READ_EXECUTE), 0);
        let entry: unsafe extern "sysv64" fn(*mut GuestState) = core::mem::transmute(page);
        entry(state);
        assert_eq!(munmap(page, bytes), 0);
    }
}
