//! Per-device RAM services for the original NVIDIA allocation hooks. Binding
//! installs actual borrowed/retained platform resources, not a GPU initializer.
//! No global registry, fallback allocator, IRQ-context predicate or DMA identity
//! conversion is introduced. RM activation still requires its remaining native
//! services, including its original interrupt-allocation/context contract.
use super::{allocation::Allocation, firmware::FirmwareBinding, memory, page_geometry};
use crate::bus::{
    dma::{
        mapping::DmaDomain,
        memory::{CacheAttribute, MemoryError, PageGeometry, PageSource},
    },
    pci::Address,
};
use alloc::sync::Arc;
use core::{cell::Cell, ffi::c_void, marker::PhantomData, marker::PhantomPinned, pin::Pin, ptr};

/// Native vendor status ABI, checked against nvstatus.h by stela/services.h.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Status {
    Ok = 0,
    InvalidAddress = 0x1e,
    InvalidArgument = 0x1f,
    InvalidState = 0x40,
    NoMemory = 0x51,
    NotSupported = 0x56,
    OperatingSystem = 0x59,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    InvalidConfiguration,
    AlreadyBound,
    Native(u32),
    PageGeometry(page_geometry::Error),
}

/// Retained allocation provenance. DMA uses this actual attached domain and
/// compares opaque device keys BEFORE dereferencing any supplied dma_dev.
pub(super) struct Origin {
    pub device_key: *mut c_void,
    pub state: *mut c_void,
    pub domain: Arc<dyn DmaDomain>,
    pub address_limit: u64,
    pub count: u32,
    pub contiguous: bool,
    pub cache: u32,
}

/// A pinned device's real native RAM source and attached DMA domain. Calls are
/// serialized and nonreentrant in the source/domain/global heap's permitted
/// process/deferred context. This handle is neither Send nor Sync.
///
/// Keep the source, state and handle alive through all native callers and all
/// producer allocations/published DMA tokens and firmware tokens. Unbind refuses
/// until every allocation is freed, every DMA token is retired or quarantined,
/// and every firmware token is returned. Therefore
/// no map-capable old handle can legitimately survive a rebind/address reuse.
/// CPU-only views and consumed quarantine independently retain actual pins/domain
/// and may survive. Final releases still obey backing/domain/heap context rules.
pub struct MemoryServices<'a> {
    source: &'a dyn PageSource,
    domain: Arc<dyn DmaDomain>,
    requester: Address,
    page_shift: u8,
    geometry: PageGeometry,
    address_limit: u64,
    state: *mut c_void,
    allocations: Cell<usize>,
    mappings: Cell<usize>,
    pub(super) firmware: Option<FirmwareBinding<'a>>,
    pub(super) firmware_tokens: Cell<usize>,
    _owner: PhantomData<*mut ()>,
    _pin: PhantomPinned,
}

unsafe extern "C" {
    fn stela_nvidia_bind_memory(
        state: *mut c_void,
        services: *mut c_void,
        domain: u32,
        bus: u8,
        slot: u8,
        function: u8,
    ) -> u32;
    fn stela_nvidia_unbind_memory(state: *mut c_void, services: *mut c_void) -> u32;
}

impl<'a> MemoryServices<'a> {
    /// # Safety
    /// `domain` must be the real isolated DMA domain attached to exactly
    /// `requester`, with `address_limit` from that device's actual DMA policy.
    /// `page_shift` is the real native granule, matching the backend's global
    /// os_page_shift facts before RM runs; it is never a guest granule. The
    /// actual source must attest the exact installed PageGeometry; an unknown
    /// source, conflicting maximum or non-base configured shift is refused. The
    /// provider must establish the requested CPU cache policy or refuse it,
    /// without introducing incompatible aliases.
    pub unsafe fn new(
        source: &'a dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        requester: Address,
        page_shift: u8,
        address_limit: u64,
    ) -> Result<Self, ServiceError> {
        if requester.device >= 32
            || requester.function >= 8
            || !(12..usize::BITS as u8 - 1).contains(&page_shift)
            || address_limit < (1u64 << page_shift) - 1
        {
            return Err(ServiceError::InvalidConfiguration);
        }
        let geometry =
            page_geometry::check_source(source, page_shift).map_err(ServiceError::PageGeometry)?;
        Ok(Self {
            source,
            domain,
            requester,
            page_shift,
            geometry,
            address_limit,
            state: ptr::null_mut(),
            allocations: Cell::new(0),
            mappings: Cell::new(0),
            firmware: None,
            firmware_tokens: Cell::new(0),
            _owner: PhantomData,
            _pin: PhantomPinned,
        })
    }

    /// Attach an immutable firmware provider before pinning/binding. Its actual
    /// device-family attestation shares this service's requester/reset epoch.
    pub fn with_firmware(mut self, firmware: FirmwareBinding<'a>) -> Self {
        self.firmware = Some(firmware);
        self
    }

    /// Bind an initialized native nv_state_t's empty OS/DMA slots. C checks
    /// its actual PCI identity against the retained requester. This neither
    /// enables hardware nor creates a channel, IRQ route or GPU VA mapping.
    ///
    /// # Safety
    /// The state must be a live exclusively owned original nv_state_t with
    /// initialized PCI identity. Keep it and this pinned handle alive while any
    /// native caller can dereference either. Exclude all calls during bind.
    pub unsafe fn bind(self: Pin<&mut Self>, state: *mut c_void) -> Result<(), ServiceError> {
        // SAFETY: access pinned fields without moving the handle.
        let this = unsafe { self.get_unchecked_mut() };
        if !this.state.is_null() {
            return Err(ServiceError::AlreadyBound);
        }
        let raw = (this as *mut Self).cast();
        // SAFETY: the native owner establishes the original state/handle ABI
        // and excludes all callers while the C helper validates/binds slots.
        let status = unsafe {
            stela_nvidia_bind_memory(
                state,
                raw,
                u32::from(this.requester.segment),
                this.requester.bus,
                this.requester.device,
                this.requester.function,
            )
        };
        if status != 0 {
            return Err(ServiceError::Native(status));
        }
        this.state = state;
        Ok(())
    }

    /// # Safety
    /// Hardware is quiescent, all native allocation/mapping/IRQ workers are
    /// stopped and drained, all producer handles freed, every published DMA
    /// token retired or consumed into canonical quarantine, all firmware tokens
    /// returned after their CPU readers stop, and no new native
    /// call can start. Keep this pinned service/state live until this succeeds;
    /// dropping/reusing them while resources remain violates the bind contract.
    /// CPU-only views and consumed quarantine may remain. The real domain
    /// must remain attached while any retained lease or quarantine needs it.
    /// This method clears only the slots owned by this handle; it fabricates
    /// no device reset, retirement or completion proof.
    pub unsafe fn unbind(self: Pin<&mut Self>) -> Result<(), ServiceError> {
        // SAFETY: field access without moving the pinned handle.
        let this = unsafe { self.get_unchecked_mut() };
        if this.state.is_null() {
            return Err(ServiceError::Native(Status::InvalidState as u32));
        }
        if this.allocations.get() != 0
            || this.mappings.get() != 0
            || this.firmware_tokens.get() != 0
        {
            return Err(ServiceError::Native(Status::InvalidState as u32));
        }
        // SAFETY: the owner excludes callers; C compares exact installed slots.
        let status = unsafe { stela_nvidia_unbind_memory(this.state, (this as *mut Self).cast()) };
        if status != 0 {
            return Err(ServiceError::Native(status));
        }
        this.state = ptr::null_mut();
        Ok(())
    }
}

impl MemoryServices<'_> {
    pub(super) fn bound_to(&self, state: *mut c_void) -> bool {
        !state.is_null() && self.state == state
    }
    pub(super) fn can_map(&self) -> Result<(), Status> {
        if self.state.is_null() {
            return Err(Status::InvalidState);
        }
        self.mappings.get().checked_add(1).ok_or(Status::NoMemory)?;
        Ok(())
    }
    pub(super) fn mapped(&self) {
        // Serialized, no callback reentry; can_map checked before preparation.
        self.mappings.set(self.mappings.get() + 1);
    }
    pub(super) fn has_mapping(&self) -> bool {
        self.mappings.get() != 0 && !self.state.is_null()
    }
    pub(super) fn retired(&self) {
        // The unique validated token consumes one previously published entry.
        self.mappings.set(self.mappings.get() - 1);
    }
}

fn cache_attribute(cache: u32) -> Result<CacheAttribute, Status> {
    // Stable NV_MEMORY_* encodings, checked against the original header in C.
    const MEMORY_CACHED: u32 = 0;
    const MEMORY_UNCACHED: u32 = 1;
    const MEMORY_WRITECOMBINED: u32 = 2;
    match cache {
        MEMORY_CACHED => Ok(CacheAttribute::WriteBack),
        MEMORY_UNCACHED => Ok(CacheAttribute::Uncached),
        MEMORY_WRITECOMBINED => Ok(CacheAttribute::WriteCombining),
        _ => Err(Status::NotSupported),
    }
}

fn memory_error(error: MemoryError) -> Status {
    match error {
        MemoryError::OutOfMemory | MemoryError::OutsideReservation => Status::NoMemory,
        MemoryError::CacheAttributeUnavailable | MemoryError::Unavailable => Status::NotSupported,
        _ => Status::OperatingSystem,
    }
}

struct Request {
    count: u32,
    contiguous: bool,
    cache: u32,
    force_dma32: bool,
}

unsafe fn allocate_pages(
    services: &MemoryServices<'_>,
    key: *mut c_void,
    request: Request,
    ptes: *mut u64,
    private: *mut *mut c_void,
) -> Result<(), Status> {
    let Request {
        count,
        contiguous,
        cache,
        force_dma32,
    } = request;
    let page_bytes = 1usize << services.page_shift;
    let live_allocations = services
        .allocations
        .get()
        .checked_add(1)
        .ok_or(Status::NoMemory)?;
    let bytes = (count as usize)
        .checked_mul(page_bytes)
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(Status::InvalidArgument)?;
    let attribute = cache_attribute(cache)?;
    let pages = services
        .source
        .allocate(bytes, page_bytes, attribute)
        .map_err(memory_error)?;
    if pages.logical_bytes() != bytes
        || pages.bytes() != bytes
        || pages.page_shift() != services.page_shift
        || !services.geometry.supports(pages.page_shift())
        || pages.cache_attribute() != attribute
    {
        return Err(Status::OperatingSystem);
    }
    let physical = pages.physical_pages();
    if contiguous
        && !physical
            .windows(2)
            .all(|pair| pair[0] + page_bytes as u64 == pair[1])
    {
        return Err(Status::NoMemory);
    }
    if force_dma32
        && physical
            .iter()
            .any(|pa| pa + page_bytes as u64 - 1 > u64::from(u32::MAX))
    {
        return Err(Status::NoMemory);
    }
    let storage = memory::allocate(size_of::<Allocation>() as u64).map_err(|_| Status::NoMemory)?;
    let mut allocation = Allocation::new(pages);
    allocation.origin = Some(Origin {
        device_key: key,
        state: services.state,
        domain: Arc::clone(&services.domain),
        address_limit: services.address_limit,
        count,
        contiguous,
        cache,
    });
    // SAFETY: common heap storage is sufficient and aligned; the raw object
    // stays pinned until its one vendor free. No output has been published.
    unsafe { storage.cast::<Allocation>().as_ptr().write(allocation) };
    services.allocations.set(live_allocations);
    // All fallible operations and ownership accounting completed before the
    // first caller output changes. The object remains private until the end.
    // SAFETY: this new object is uniquely owned and its immutable pins are live.
    let allocation = unsafe { storage.cast::<Allocation>().as_ref() };
    let physical = allocation.pages().physical_pages();
    for (index, &address) in physical
        .iter()
        .take(if contiguous { 1 } else { physical.len() })
        .enumerate()
    {
        // SAFETY: caller supplies one PTE for contiguous allocations,
        // otherwise exactly count writable native u64 slots.
        unsafe { ptes.add(index).write(address) };
    }
    // SAFETY: writable native output; publish unique parent ownership last.
    unsafe { private.write(storage.as_ptr()) };
    Ok(())
}

const _: () = assert!(align_of::<Allocation>() <= memory::ALIGNMENT);

/// # Safety
/// The native C shim supplies its live bound service/state, validated pointer
/// slots, and the caller's complete native PTE capacity. Context rules above apply.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_alloc_pages(
    key: *mut c_void,
    state: *mut c_void,
    count: u32,
    page_size: u64,
    contiguous: u8,
    cache: u32,
    zeroed: u8,
    unencrypted: u8,
    node: i32,
    force_dma32: u8,
    ptes: *mut u64,
    private: *mut *mut c_void,
) -> Status {
    // SAFETY: C only forwards the OS handle installed by bind into this state.
    let services = unsafe { &*key.cast::<MemoryServices<'_>>() };
    if services.state != state || state.is_null() {
        return Status::InvalidState;
    }
    if count == 0 || contiguous > 1 || zeroed > 1 || unencrypted > 1 || force_dma32 > 1 {
        return Status::InvalidArgument;
    }
    if page_size == 0 {
        return Status::InvalidArgument;
    }
    if page_size != 1u64 << services.page_shift || unencrypted != 0 || node != -1 {
        return Status::NotSupported;
    }
    // Canonical PageBacking is initially zeroed. Extra zeroing when zeroed=0
    // is valid; it does not advertise encryption, NUMA or higher-order support.
    // SAFETY: validated policy and the shim's checked caller-owned outputs.
    match unsafe {
        allocate_pages(
            services,
            key,
            Request {
                count,
                contiguous: contiguous != 0,
                cache,
                force_dma32: force_dma32 != 0,
            },
            ptes,
            private,
        )
    } {
        Ok(()) => Status::Ok,
        Err(status) => status,
    }
}

/// # Safety
/// Return one live producer-owned Allocation, once, after parent C users stop.
/// Outstanding CPU views/DMA maps independently retain pins/domain. This cannot
/// be used for a manually supplied Allocation or another imported handle kind.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_free_pages(
    state: *mut c_void,
    count: u32,
    contiguous: u8,
    cache: u32,
    private: *mut c_void,
) -> Status {
    // SAFETY: the caller supplies the original allocation-kind live pointer.
    let allocation = unsafe { &*private.cast::<Allocation>() };
    let Some(origin) = allocation.origin.as_ref() else {
        return Status::NotSupported;
    };
    if origin.state != state
        || origin.count != count
        || u8::from(origin.contiguous) != contiguous
        || origin.cache != cache
    {
        return Status::InvalidArgument;
    }
    // SAFETY: the pinned binding must remain alive while any producer handle
    // or DMA token exists; unbind refuses this live allocation count.
    let services = unsafe { &*origin.device_key.cast::<MemoryServices<'_>>() };
    if services.state != state || services.allocations.get() == 0 {
        return Status::InvalidState;
    }
    services.allocations.set(services.allocations.get() - 1);
    // SAFETY: validated producer ownership; exactly one free, no live parent
    // C reference. CpuMapping/DmaMapping retain any outstanding actual pins.
    unsafe {
        private.cast::<Allocation>().drop_in_place();
        memory::free(private);
    }
    Status::Ok
}

#[cfg(test)]
mod tests;
