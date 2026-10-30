//! Native RAM CPU views for the official RM kernel-mapping hooks.
//! This accepts canonical pins; it does not allocate RAM, create MMIO aliases,
//! pin guest pages, install GPU page tables or infer device addresses.
use super::memory;
use crate::bus::dma::memory::{CpuMapping, MemoryError, PinnedPages};
use core::{ffi::c_void, marker::PhantomData, marker::PhantomPinned, pin::Pin, ptr, ptr::NonNull};

/// An existing native RAM allocation, with its established CPU cache policy.
/// Pin before borrowing its opaque pointer for an original RM mapping call.
/// The pointer is valid only while this handle lives; C keeps no borrow of
/// this handle after that call. Each successful view independently keeps the
/// underlying pins, so the parent may then be dropped without freeing its RAM.
/// All calls and final releases obey the common heap/backing's execution rules.
/// No implicit DMA completion or IRQ-safe release is supplied.
pub struct Allocation {
    pages: PinnedPages,
    pub(super) origin: Option<super::services::Origin>,
    _owner: PhantomData<*mut ()>,
    _pin: PhantomPinned,
}

impl Allocation {
    pub fn new(pages: PinnedPages) -> Self {
        Self {
            pages,
            origin: None,
            _owner: PhantomData,
            _pin: PhantomPinned,
        }
    }

    pub(super) fn pages(&self) -> &PinnedPages {
        &self.pages
    }

    /// Allocation-private pointer accepted by `nv_alloc_kernel_mapping`.
    /// It must not be used as any other vendor allocation/import handle.
    ///
    /// # Safety
    /// Serialize native C/Rust access and exclude callback/interrupt reentry.
    /// Every call dereferencing this pointer must end before this pinned handle
    /// is dropped. CPU accesses through returned views require the owner's
    /// exclusive-access/coherence protocol; raw pointers do not supply it.
    /// Native page indices/offsets must use this allocation's page
    /// granule, matching the real backend's `os_page_shift` configuration.
    pub unsafe fn as_raw(self: Pin<&mut Self>) -> *mut c_void {
        // SAFETY: obtain a stable opaque pointer without moving the object.
        unsafe { self.get_unchecked_mut() as *mut Self }.cast()
    }

    fn mapping(
        &self,
        page_index: u64,
        page_offset: u32,
        bytes: u64,
    ) -> Result<CpuMapping, MemoryError> {
        let page_bytes = 1usize << self.pages.page_shift();
        if page_offset as usize >= page_bytes {
            return Err(MemoryError::InvalidSize);
        }
        let start = usize::try_from(page_index)
            .ok()
            .and_then(|index| index.checked_mul(page_bytes))
            .and_then(|start| start.checked_add(page_offset as usize))
            .ok_or(MemoryError::InvalidSize)?;
        let bytes = usize::try_from(bytes).map_err(|_| MemoryError::InvalidSize)?;
        let end = start
            .checked_add(bytes)
            .filter(|end| *end <= self.pages.logical_bytes())
            .ok_or(MemoryError::InvalidSize)?;
        // Keep the existing mapping/pin and cache attribute. Do not expose
        // whole-page padding beyond the allocation's exact logical payload.
        self.pages
            .cpu_mapping_range(self.pages.cache_attribute(), start..end)
    }
}

// CpuMapping is Rust-private; C sees only a unique opaque token. The common
// metadata wrapper must support its alignment, including on the UEFI ABI.
const _: () = assert!(align_of::<CpuMapping>() <= memory::ALIGNMENT);

fn map_with(
    allocation: &Allocation,
    page_index: u64,
    page_offset: u32,
    bytes: u64,
    allocate: impl FnOnce(u64) -> Option<NonNull<c_void>>,
) -> Option<(NonNull<c_void>, NonNull<CpuMapping>)> {
    let mapping = allocation.mapping(page_index, page_offset, bytes).ok()?;
    let address = mapping.address(0, mapping.bytes()).ok()?.cast();
    let token = allocate(size_of::<CpuMapping>() as u64)?.cast::<CpuMapping>();
    // SAFETY: the common metadata allocator supplied distinct aligned writable
    // storage for this exact type. The token owns its mapping/pin.
    unsafe { token.as_ptr().write(mapping) };
    Some((address, token))
}

/// # Safety
/// The C shim supplies a live pinned Allocation and writable output slot.
/// The owner excludes reentry and obeys the shared heap/backing context rules.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_map_ram(
    allocation: *mut c_void,
    page_index: u64,
    page_offset: u32,
    bytes: u64,
    private: *mut *mut c_void,
) -> *mut c_void {
    // SAFETY: the owner supplies this exclusively borrowed live opaque handle.
    let allocation = unsafe { &*allocation.cast::<Allocation>() };
    let Some((address, token)) = map_with(allocation, page_index, page_offset, bytes, |bytes| {
        memory::allocate(bytes).ok()
    }) else {
        return ptr::null_mut();
    };
    // SAFETY: the C shim checked its caller's writable output slot. Ownership
    // of this distinct token passes to exactly one matching unmap operation.
    unsafe { private.write(token.as_ptr().cast()) };
    address.as_ptr()
}

/// # Safety
/// Return a live view token once, after all CPU/device users stop. The owner
/// obeys the backing/global heap's process/deferred-context release rules.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_unmap_ram(private: *mut c_void) {
    if private.is_null() {
        return;
    }
    // SAFETY: the matching native caller exclusively owns this live token;
    // dropping CpuMapping releases the pin, then its metadata storage.
    unsafe {
        private.cast::<CpuMapping>().drop_in_place();
        memory::free(private);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::memory::{CacheAttribute, PageBacking};
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
        sync::Arc,
        vec::Vec,
    };
    use core::{
        alloc::Layout,
        sync::atomic::{AtomicUsize, Ordering},
    };

    unsafe extern "C" {
        fn nv_alloc_kernel_mapping(
            nv: *mut c_void,
            allocation: *mut c_void,
            page_index: u64,
            page_offset: u32,
            bytes: u64,
            private: *mut *mut c_void,
        ) -> *mut c_void;
        fn nv_free_kernel_mapping(
            nv: *mut c_void,
            allocation: *mut c_void,
            address: *mut c_void,
            private: *mut c_void,
        );
    }

    struct Backing {
        cpu: NonNull<u8>,
        physical: Vec<u64>,
        page_shift: u8,
        attribute: CacheAttribute,
        layout: Layout,
        released: Arc<AtomicUsize>,
    }

    // SAFETY: the model owns one zeroed aligned RAM allocation, immutable
    // mapping metadata and independent physical labels. No hardware uses it.
    // Only unsafe, externally serialized test accesses dereference CPU views.
    unsafe impl Send for Backing {}
    // SAFETY: shared references rely on the same argument as `Send` above.
    unsafe impl Sync for Backing {}
    // SAFETY: the model keeps the same allocation/layout/cache metadata
    // until the last pin ends; physical labels differ from VA.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            self.cpu
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            self.page_shift
        }
        fn cache_attribute(&self) -> CacheAttribute {
            self.attribute
        }
    }

    impl Drop for Backing {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::SeqCst);
            // SAFETY: the last pin is gone; return this model
            // allocation once, with its original layout.
            unsafe { dealloc(self.cpu.as_ptr(), self.layout) };
        }
    }

    fn backing(
        page_shift: u8,
        logical_bytes: usize,
        attribute: CacheAttribute,
        released: Arc<AtomicUsize>,
    ) -> (PinnedPages, NonNull<u8>) {
        let page_bytes = 1usize << page_shift;
        let pages = logical_bytes.div_ceil(page_bytes);
        let layout = Layout::from_size_align(pages * page_bytes, page_bytes).unwrap();
        // SAFETY: a nonzero checked model allocation, kept by Backing.
        let cpu = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let backing = Backing {
            cpu,
            // Non-contiguous model physical pages. The existing
            // canonical CPU mapping remains consecutive and independent.
            physical: (0..pages)
                .map(|index| 0x8000_0000 + (index * 2 * page_bytes) as u64)
                .collect(),
            page_shift,
            attribute,
            layout,
            released,
        };
        (
            PinnedPages::new(Box::new(backing), logical_bytes, page_bytes).unwrap(),
            cpu,
        )
    }

    #[test]
    fn original_c_views_keep_pins_after_parent_release() {
        let released = Arc::new(AtomicUsize::new(0));
        let (pages, cpu) = backing(
            12,
            3 * 4096,
            CacheAttribute::WriteBack,
            Arc::clone(&released),
        );
        let mut allocation = Box::pin(Allocation::new(pages));
        let (mut first, mut second) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: the handle is live/pinned; all native calls and CPU uses
        // here are synchronous, serialized and in a normal test context.
        let (a, b) = unsafe {
            let raw = allocation.as_mut().as_raw();
            let a = nv_alloc_kernel_mapping(ptr::null_mut(), raw, 1, 4090, 32, &mut first);
            let b = nv_alloc_kernel_mapping(ptr::null_mut(), raw, 2, 0, 20, &mut second);
            (a, b)
        };
        assert!(!first.is_null() && !second.is_null());
        assert_ne!(first, second, "independent view ownership tokens");
        // SAFETY: these checked ranges lie in the live model allocation.
        unsafe {
            assert_eq!(a, cpu.add(8186).as_ptr().cast());
            assert_eq!(b, cpu.add(8192).as_ptr().cast());
            a.cast::<u8>().write_bytes(0x6d, 32);
            assert_eq!(b.cast::<u8>().read(), 0x6d);
        }
        drop(allocation);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        // SAFETY: both tokens independently keep their ranges/pins, so the
        // parent is no longer needed. Return each token once after its uses.
        unsafe {
            nv_free_kernel_mapping(ptr::null_mut(), ptr::null_mut(), a, first);
            assert_eq!(released.load(Ordering::SeqCst), 0);
            assert_eq!(b.cast::<u8>().read(), 0x6d);
            nv_free_kernel_mapping(ptr::null_mut(), ptr::null_mut(), b, second);
        }
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn original_c_bounds_use_native_pages_and_exact_logical_length() {
        let released = Arc::new(AtomicUsize::new(0));
        let page_bytes = 16384;
        let logical_bytes = 2 * page_bytes + 37;
        let (pages, cpu) = backing(
            14,
            logical_bytes,
            CacheAttribute::Uncached,
            Arc::clone(&released),
        );
        let mut allocation = Box::pin(Allocation::new(pages));
        // SAFETY: live pinned native handle with serialized C calls.
        unsafe {
            let raw = allocation.as_mut().as_raw();
            for (index, offset, bytes) in [
                (u64::MAX, 0, 1),
                (0, page_bytes as u32, 1),
                (0, u32::MAX, 1),
                (0, 0, u64::MAX),
                (2, 37, 1),
                (2, 36, 2),
                (3, 0, 0),
            ] {
                let mut private = ptr::dangling_mut();
                assert!(
                    nv_alloc_kernel_mapping(
                        ptr::null_mut(),
                        raw,
                        index,
                        offset,
                        bytes,
                        &mut private
                    )
                    .is_null()
                );
                assert!(private.is_null(), "failure clears the output token");
            }
            let mut private = ptr::dangling_mut();
            assert!(
                nv_alloc_kernel_mapping(ptr::null_mut(), ptr::null_mut(), 0, 0, 1, &mut private)
                    .is_null()
            );
            assert!(private.is_null());
            assert!(
                nv_alloc_kernel_mapping(ptr::null_mut(), raw, 0, 0, 1, ptr::null_mut()).is_null()
            );

            // Cross a real native page boundary and end exactly at the
            // logical payload; whole-page tail padding is never exposed.
            let address = nv_alloc_kernel_mapping(
                ptr::null_mut(),
                raw,
                1,
                page_bytes as u32 - 11,
                48,
                &mut private,
            );
            assert_eq!(address, cpu.add(2 * page_bytes - 11).as_ptr().cast());
            assert!(!private.is_null());
            nv_free_kernel_mapping(ptr::null_mut(), raw, address, private);

            // An empty view at the logical end keeps a real pin and token;
            // it grants no byte access to the page padding.
            let address = nv_alloc_kernel_mapping(ptr::null_mut(), raw, 2, 37, 0, &mut private);
            assert_eq!(address, cpu.add(logical_bytes).as_ptr().cast());
            assert!(!private.is_null());
            nv_free_kernel_mapping(ptr::null_mut(), raw, address, private);
            nv_free_kernel_mapping(ptr::null_mut(), raw, ptr::null_mut(), ptr::null_mut());
        }
        drop(allocation);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn view_metadata_failure_does_not_leak_the_temporary_pin() {
        let released = Arc::new(AtomicUsize::new(0));
        let (pages, _) = backing(
            12,
            4096,
            CacheAttribute::WriteCombining,
            Arc::clone(&released),
        );
        let allocation = Allocation::new(pages);
        let mut called = false;
        assert!(
            map_with(&allocation, 0, 0, 17, |bytes| {
                called = true;
                assert_eq!(bytes, size_of::<CpuMapping>() as u64);
                None
            })
            .is_none()
        );
        assert!(called);
        let view = allocation.mapping(0, 0, 17).unwrap();
        assert_eq!(view.cache_attribute(), CacheAttribute::WriteCombining);
        drop(view);
        drop(allocation);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
}
