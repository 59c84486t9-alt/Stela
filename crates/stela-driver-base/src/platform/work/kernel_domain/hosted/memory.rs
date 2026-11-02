//! Real anonymous host mappings, with model-frame identities only.
use super::HostedExecution;
use crate::bus::dma::memory::MemoryError;
use alloc::{sync::Arc, vec::Vec};
use core::{
    ffi::{c_int, c_void},
    mem::ManuallyDrop,
    ops::Range,
    ptr::NonNull,
};
const PAGE: usize = 4096;
unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        bytes: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, bytes: usize, protection: c_int) -> c_int;
    fn munmap(address: *mut c_void, bytes: usize) -> c_int;
    fn getpagesize() -> c_int;
}
/// A namespace-local model identity, never a physical/DMA address. Lookup must
/// additionally authenticate this exact allocation/execution owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct HostFrameId(u64);
impl HostFrameId {
    pub fn local_id(self) -> u64 {
        self.0
    }
}
struct Mapping {
    base: usize,
    bytes: usize,
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this guard owns exactly the successful mmap extent; no view
        // remains at final Allocation drop, or this is prepublication rollback.
        if unsafe { munmap(self.base as *mut c_void, self.bytes) } != 0 {
            // No free is reported. The OS mapping stays process-lifetime leaked.
            super::super::super::quarantine();
        }
    }
}
struct Allocation {
    mapping: ManuallyDrop<Mapping>,
    owner: Arc<HostedExecution>,
    usable: Range<usize>,
    guard: Range<usize>,
    alignment: usize,
    frames: Vec<HostFrameId>,
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if self.owner.check_process().is_ok() {
            // SAFETY: final Arc owns this mapping; safe views borrow/retain it.
            // The model source owner must separately join every raw C user.
            unsafe { ManuallyDrop::drop(&mut self.mapping) };
        } else {
            super::super::super::quarantine();
        }
    }
}
/// Counted host allocation, not native PageBacking, StackBacking, Provider,
/// PinnedPages or CpuMapping. Raw users must retain this actual allocation.
/// ```compile_fail
/// use stela_driver_base::platform::work::kernel_domain::{HostedDomain,HostedPages,StorageView};
/// fn no_native_projection(pages:&HostedPages) {
///     StorageView::<HostedDomain>::borrow_hosted(pages).native_pin();
/// }
/// ```
#[derive(Clone)]
pub struct HostedPages {
    allocation: Arc<Allocation>,
}
impl HostedPages {
    pub fn allocate(
        owner: &Arc<HostedExecution>,
        pages: usize,
        alignment: usize,
        guard_pages: usize,
    ) -> Result<Self, MemoryError> {
        owner
            .check_current()
            .map_err(|_| MemoryError::Unavailable)?;
        // This bounded producer currently binds the Linux mmap ABI only.
        if !cfg!(target_os = "linux") {
            return Err(MemoryError::Unavailable);
        }
        // SAFETY: immutable actual OS page-size query, without native effects.
        if unsafe { getpagesize() } != PAGE as c_int {
            return Err(MemoryError::Unavailable);
        }
        if alignment < PAGE || !alignment.is_power_of_two() {
            return Err(MemoryError::InvalidAlignment);
        }
        let bytes = pages
            .checked_mul(PAGE)
            .filter(|n| *n != 0)
            .ok_or(MemoryError::InvalidSize)?;
        let guards = guard_pages
            .checked_mul(PAGE)
            .ok_or(MemoryError::InvalidSize)?;
        let total = bytes
            .checked_add(guards)
            .and_then(|n| n.checked_add(alignment))
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or(MemoryError::InvalidSize)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(pages)
            .map_err(|_| MemoryError::OutOfMemory)?;
        let first = owner
            .reserve_frames(pages)
            .map_err(|_| MemoryError::Unavailable)?;
        for n in 0..pages {
            let n = u64::try_from(n).map_err(|_| MemoryError::InvalidSize)?;
            frames.push(HostFrameId(
                first.checked_add(n).ok_or(MemoryError::InvalidSize)?,
            ));
        }
        // SAFETY: Linux private anonymous mapping. A successful extent is owned
        // by Mapping immediately, before subsequent fallible checks/mprotect.
        let address = unsafe { mmap(core::ptr::null_mut(), total, 3, 2 | 0x20, -1, 0) };
        if address as isize == -1 {
            return Err(MemoryError::OutOfMemory);
        }
        let mapping = Mapping {
            base: address as usize,
            bytes: total,
        };
        let start = mapping
            .base
            .checked_add(guards)
            .and_then(|n| n.checked_add(alignment - 1))
            .map(|n| n & !(alignment - 1))
            .ok_or(MemoryError::InvalidSize)?;
        let end = start.checked_add(bytes).ok_or(MemoryError::InvalidSize)?;
        if end
            > mapping
                .base
                .checked_add(total)
                .ok_or(MemoryError::InvalidSize)?
        {
            return Err(MemoryError::InvalidSize);
        }
        let guard = start - guards..start;
        if guards != 0 {
            // SAFETY: page-aligned guard lies within this private fresh extent,
            // disjoint from usable bytes. No view has yet been published.
            if unsafe { mprotect(guard.start as *mut c_void, guards, 0) } != 0 {
                return Err(MemoryError::Unavailable);
            }
        }
        Ok(Self {
            allocation: Arc::new(Allocation {
                mapping: ManuallyDrop::new(mapping),
                owner: owner.clone(),
                usable: start..end,
                guard,
                alignment,
                frames,
            }),
        })
    }
    pub fn owner(&self) -> &Arc<HostedExecution> {
        &self.allocation.owner
    }
    pub fn bytes(&self) -> usize {
        self.allocation.usable.len()
    }
    pub fn alignment(&self) -> usize {
        self.allocation.alignment
    }
    pub fn page_shift(&self) -> u8 {
        12
    }
    pub fn guard(&self) -> Range<usize> {
        self.allocation.guard.clone()
    }
    pub fn model_frames(&self) -> &[HostFrameId] {
        &self.allocation.frames
    }
    pub fn same_allocation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.allocation, &other.allocation)
    }
    /// Observation only; this does not prove raw source/C/RCU users retired.
    pub fn has_other_views(&self) -> bool {
        Arc::strong_count(&self.allocation) != 1
    }
    pub fn cpu_address(&self, offset: usize, bytes: usize) -> Result<NonNull<u8>, MemoryError> {
        self.owner()
            .check_process()
            .map_err(|_| MemoryError::Unavailable)?;
        super::super::storage::check_range(self.bytes(), offset, bytes)?;
        let address = self
            .allocation
            .usable
            .start
            .checked_add(offset)
            .ok_or(MemoryError::InvalidSize)?;
        NonNull::new(address as *mut u8).ok_or(MemoryError::Unavailable)
    }
}
