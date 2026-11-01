//! Pages generated code runs from: llvmpipe's shaders. The heap is never
//! executable, so these lie in the host's page window, which every host
//! processor shares, each block with a page beneath it holding its owner.
use super::{PAGE, installed};
use crate::native_memory::SOURCE;
use alloc::boxed::Box;
use core::{mem, ptr};
use stela_drivers::bus::dma::memory::{CacheAttribute, PageSource, PinnedPages};

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_map_code(bytes: usize) -> *mut u8 {
    let Some(gpu) = installed() else {
        return ptr::null_mut();
    };
    let Ok(memory) = SOURCE.allocate(
        bytes + PAGE as usize,
        PAGE as usize,
        CacheAttribute::WriteBack,
    ) else {
        return ptr::null_mut();
    };
    let pages = memory.physical_pages().len();
    let Some(address) = gpu.window.reserve(pages) else {
        return ptr::null_mut();
    };
    let mapped = memory
        .physical_pages()
        .iter()
        .zip(0..)
        .all(|(&physical, page)| gpu.window.install_code(address + page * PAGE, physical));
    if !mapped {
        // A processor that kept the translation keeps the memory too.
        if gpu.window.remove(address, pages) {
            gpu.window.release(address, pages);
        } else {
            mem::forget(memory);
        }
        return ptr::null_mut();
    }
    // SAFETY: the page just mapped writable at `address`, this block's own.
    unsafe { (address as *mut *mut PinnedPages).write(Box::into_raw(Box::new(memory))) };
    (address + PAGE) as *mut u8
}

/// Unmaps what [`stela_libc_map_code`] returned.
///
/// # Safety
///
/// `code` is a live block of [`stela_libc_map_code`], and nothing runs in it.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_unmap_code(code: *mut u8) {
    let Some(gpu) = installed() else {
        return;
    };
    let address = code as u64 - PAGE;
    // SAFETY: the caller's block, whose first page holds the box.
    let memory = unsafe { Box::from_raw((address as *mut *mut PinnedPages).read()) };
    let pages = memory.physical_pages().len();
    // A processor that kept the translation keeps the memory too.
    if gpu.window.remove(address, pages) {
        gpu.window.release(address, pages);
    } else {
        mem::forget(memory);
    }
}
