//! The loader's reserved x86 arenas, each identity-mapped with an empty 4 KiB
//! page table.
use core::ptr::NonNull;

/// A reserved identity-mapped arena and its page count.
#[derive(Clone, Copy, Debug)]
pub struct BootArena {
    pub base: NonNull<u8>,
    pub pages: usize,
}
