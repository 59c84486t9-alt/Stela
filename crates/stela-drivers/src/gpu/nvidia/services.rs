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

/// Native vendor status ABI, checked against nvstatus.h by stela_services.h.
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
mod tests {
    use super::*;
    use crate::bus::dma::{
        mapping::{Direction, DmaError, DomainMapping, quarantine_status},
        memory::{PageBacking, PinnedPages},
    };
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
        vec::Vec,
    };
    use core::{
        alloc::Layout,
        cell::Cell,
        ops::Range,
        ptr::NonNull,
        sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    };
    extern crate std;
    use self::std::sync::Mutex;

    unsafe extern "C" {
        fn stela_nvidia_state_layout(bytes: *mut u64, alignment: *mut u64);
        fn nv_requires_dma_remap(state: *mut c_void) -> u8;
        fn nv_alloc_pages(
            state: *mut c_void,
            count: u32,
            size: u64,
            contiguous: u8,
            cache: u32,
            zeroed: u8,
            unencrypted: u8,
            node: i32,
            ptes: *mut u64,
            private: *mut *mut c_void,
        ) -> u32;
        fn nv_free_pages(
            state: *mut c_void,
            count: u32,
            contiguous: u8,
            cache: u32,
            private: *mut c_void,
        ) -> u32;
        fn nv_dma_map_alloc(
            device: *mut c_void,
            count: u64,
            addresses: *mut u64,
            contiguous: u8,
            read_only: u8,
            private: *mut *mut c_void,
        ) -> u32;
        fn nv_dma_unmap_alloc(
            device: *mut c_void,
            count: u64,
            addresses: *mut u64,
            private: *mut *mut c_void,
        ) -> u32;
        fn nv_alloc_kernel_mapping(
            state: *mut c_void,
            allocation: *mut c_void,
            page_index: u64,
            page_offset: u32,
            bytes: u64,
            private: *mut *mut c_void,
        ) -> *mut c_void;
        fn nv_free_kernel_mapping(
            state: *mut c_void,
            allocation: *mut c_void,
            address: *mut c_void,
            private: *mut c_void,
        );
    }

    /// Exact original C type storage, with a zero PCI-identity fixture. This is
    /// test state, not device initialization. The production query returns only
    /// native layout facts and does not create a successful-looking GPU state.
    struct State {
        pointer: NonNull<u8>,
        layout: Layout,
    }
    impl State {
        fn new() -> Self {
            let (mut bytes, mut alignment) = (0, 0);
            // SAFETY: writable native integer slots accepted by the C query.
            unsafe { stela_nvidia_state_layout(&mut bytes, &mut alignment) };
            let layout = Layout::from_size_align(bytes as usize, alignment as usize).unwrap();
            // SAFETY: the original type's exact nonzero native layout.
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            Self { pointer, layout }
        }
        fn raw(&self) -> *mut c_void {
            self.pointer.as_ptr().cast()
        }
    }
    impl Drop for State {
        fn drop(&mut self) {
            // SAFETY: test callers and bindings stopped before this state ends.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    struct Backing {
        cpu: NonNull<u8>,
        physical: Vec<u64>,
        shift: u8,
        attribute: CacheAttribute,
        layout: Layout,
        released: Arc<AtomicUsize>,
    }
    // SAFETY: immutable metadata and independently owned model RAM; CPU access is
    // raw and externally serialized. No physical hardware uses these test labels.
    unsafe impl Send for Backing {}
    unsafe impl Sync for Backing {}
    // SAFETY: same zeroed allocation/mapping/cache metadata is retained through
    // the last real pin; physical labels are independent of CPU VA and IOVA.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            self.cpu
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            self.shift
        }
        fn cache_attribute(&self) -> CacheAttribute {
            self.attribute
        }
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::SeqCst);
            // SAFETY: the last pin owns this exact original model allocation.
            unsafe { dealloc(self.cpu.as_ptr(), self.layout) };
        }
    }

    struct Source {
        shift: Cell<u8>,
        geometry: PageGeometry,
        base: Cell<u64>,
        stride: Cell<usize>,
        cache_override: Cell<Option<CacheAttribute>>,
        fail: Cell<bool>,
        calls: Cell<usize>,
        released: Arc<AtomicUsize>,
    }
    impl Source {
        fn new(shift: u8) -> Self {
            page_geometry::tests::initialize_model(shift);
            Self {
                shift: Cell::new(shift),
                geometry: PageGeometry::base_only(shift).unwrap(),
                base: Cell::new(0x8000_0000),
                stride: Cell::new(2),
                cache_override: Cell::new(None),
                fail: Cell::new(false),
                calls: Cell::new(0),
                released: Arc::new(AtomicUsize::new(0)),
            }
        }
    }
    impl PageSource for Source {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            Ok(self.geometry)
        }
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            self.calls.set(self.calls.get() + 1);
            if self.fail.get() {
                return Err(MemoryError::OutOfMemory);
            }
            let shift = self.shift.get();
            let page_bytes = 1usize << shift;
            let count = bytes.div_ceil(page_bytes);
            let layout =
                Layout::from_size_align(count * page_bytes, alignment.max(page_bytes)).unwrap();
            // SAFETY: exclusively owned zeroed model RAM and checked layout.
            let cpu =
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
            let backing = Backing {
                cpu,
                physical: (0..count)
                    .map(|i| self.base.get() + (i * self.stride.get() * page_bytes) as u64)
                    .collect(),
                shift,
                attribute: self.cache_override.get().unwrap_or(attribute),
                layout,
                released: Arc::clone(&self.released),
            };
            PinnedPages::new(Box::new(backing), bytes, alignment.max(page_bytes))
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Map(Vec<u64>, Direction, u64),
        Device(u64, Range<usize>, Direction),
        Cpu(u64, Range<usize>, Direction),
        Unmap(u64),
    }
    const FAIL_MAP: u32 = 1;
    const FAIL_DEVICE: u32 = 2;
    const FAIL_CPU: u32 = 4;
    const FAIL_UNMAP: u32 = 8;
    struct Domain {
        events: Mutex<Vec<Event>>,
        failures: AtomicU32,
        next: AtomicU64,
        base: AtomicU64,
    }
    impl Domain {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                failures: AtomicU32::new(0),
                next: AtomicU64::new(0),
                base: AtomicU64::new(0x4000_0000),
            })
        }
        fn events(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }
        fn fails(&self, bit: u32) -> bool {
            self.failures.load(Ordering::SeqCst) & bit != 0
        }
    }
    // SAFETY: thread-safe model token/IOVA inventory, explicit visibility and
    // removal events. No identity mapping or successful physical operation claimed.
    unsafe impl DmaDomain for Domain {
        unsafe fn map(
            &self,
            pages: &PinnedPages,
            direction: Direction,
            limit: u64,
        ) -> Result<DomainMapping, DmaError> {
            self.events.lock().unwrap().push(Event::Map(
                pages.physical_pages().to_vec(),
                direction,
                limit,
            ));
            if self.fails(FAIL_MAP) {
                return Err(DmaError::MappingFailed);
            }
            let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(DomainMapping {
                id,
                address: self.base.load(Ordering::SeqCst) + id * 0x10_0000,
                bytes: pages.bytes(),
            })
        }
        unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
            self.events.lock().unwrap().push(Event::Unmap(mapping.id));
            if self.fails(FAIL_UNMAP) {
                Err(DmaError::InvalidationFailed)
            } else {
                Ok(())
            }
        }
        unsafe fn sync_for_device(
            &self,
            mapping: DomainMapping,
            range: Range<usize>,
            direction: Direction,
        ) -> Result<(), DmaError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Device(mapping.id, range, direction));
            if self.fails(FAIL_DEVICE) {
                Err(DmaError::VisibilityFailed)
            } else {
                Ok(())
            }
        }
        unsafe fn sync_for_cpu(
            &self,
            mapping: DomainMapping,
            range: Range<usize>,
            direction: Direction,
        ) -> Result<(), DmaError> {
            self.events
                .lock()
                .unwrap()
                .push(Event::Cpu(mapping.id, range, direction));
            if self.fails(FAIL_CPU) {
                Err(DmaError::VisibilityFailed)
            } else {
                Ok(())
            }
        }
    }

    fn bind<'a>(
        source: &'a Source,
        domain: &Arc<Domain>,
        state: &State,
    ) -> Pin<Box<MemoryServices<'a>>> {
        // SAFETY: one isolated model requester/domain, actual model native page
        // granule and explicit limit. No hardware or guest is accessed.
        let mut services = Box::pin(
            unsafe {
                MemoryServices::new(
                    source,
                    domain.clone(),
                    Address {
                        segment: 0,
                        bus: 0,
                        device: 0,
                        function: 0,
                    },
                    source.shift.get(),
                    u64::from(u32::MAX),
                )
            }
            .unwrap(),
        );
        // SAFETY: exact original C type storage with the model's initialized PCI
        // tuple, live/pinned service and serialized normal test context.
        unsafe { services.as_mut().bind(state.raw()).unwrap() };
        services
    }
    fn key(services: &MemoryServices<'_>) -> *mut c_void {
        (services as *const MemoryServices<'_>).cast_mut().cast()
    }

    #[test]
    fn original_ram_dma_and_cpu_views_hold_actual_resources_until_retirement() {
        let source = Source::new(12);
        let domain = Domain::new();
        let state = State::new();
        let mut services = bind(&source, &domain, &state);
        let mut addresses = [u64::MAX; 3];
        let mut allocation = ptr::null_mut();
        // SAFETY: bound exact C state, full native PTE capacity, serialized calls.
        unsafe {
            assert_eq!(nv_requires_dma_remap(state.raw()), 1);
            assert_eq!(
                nv_alloc_pages(
                    state.raw(),
                    3,
                    4096,
                    0,
                    0,
                    1,
                    0,
                    -1,
                    addresses.as_mut_ptr(),
                    &mut allocation
                ),
                0
            );
            assert_eq!(addresses, [0x8000_0000, 0x8000_2000, 0x8000_4000]);
            assert_eq!(
                (services.allocations.get(), services.mappings.get()),
                (1, 0)
            );
            assert_eq!(
                services.as_mut().unbind(),
                Err(ServiceError::Native(Status::InvalidState as u32))
            );
            assert_eq!(
                nv_requires_dma_remap(state.raw()),
                1,
                "busy unbind leaves native slots intact"
            );
            let mut cpu_private = ptr::null_mut();
            let cpu =
                nv_alloc_kernel_mapping(state.raw(), allocation, 0, 0, 3 * 4096, &mut cpu_private);
            assert!(!cpu.is_null() && !cpu_private.is_null());
            assert_ne!(cpu as u64, addresses[0]);
            assert_eq!(cpu.cast::<u8>().read(), 0);
            let mut dma_private = allocation;
            assert_eq!(
                nv_dma_map_alloc(
                    key(&services),
                    3,
                    addresses.as_mut_ptr(),
                    0,
                    1,
                    &mut dma_private
                ),
                0
            );
            assert_ne!(dma_private, allocation);
            assert_eq!(
                (services.allocations.get(), services.mappings.get()),
                (1, 1)
            );
            assert_eq!(
                services.as_mut().unbind(),
                Err(ServiceError::Native(Status::InvalidState as u32))
            );
            assert_eq!(addresses, [0x4010_0000, 0x4010_1000, 0x4010_2000]);
            assert_eq!(
                domain.events(),
                [
                    Event::Map(
                        vec![0x8000_0000, 0x8000_2000, 0x8000_4000],
                        Direction::ToDevice,
                        u64::from(u32::MAX)
                    ),
                    Event::Device(1, 0..12288, Direction::ToDevice)
                ]
            );
            assert_eq!(nv_free_pages(state.raw(), 3, 0, 0, allocation), 0);
            assert_eq!(
                (services.allocations.get(), services.mappings.get()),
                (0, 1)
            );
            assert_eq!(
                services.as_mut().unbind(),
                Err(ServiceError::Native(Status::InvalidState as u32))
            );
            assert_eq!(source.released.load(Ordering::SeqCst), 0);
            // The model has no device execution; actual quiescence is established
            // here before calling the original unsafe retirement boundary.
            assert_eq!(
                nv_dma_unmap_alloc(key(&services), 3, addresses.as_mut_ptr(), &mut dma_private),
                0
            );
            assert!(dma_private.is_null());
            assert_eq!(
                (services.allocations.get(), services.mappings.get()),
                (0, 0)
            );
            assert_eq!(
                source.released.load(Ordering::SeqCst),
                0,
                "CPU view retains its actual pin"
            );
            assert_eq!(
                domain.events()[2..],
                [
                    Event::Cpu(1, 0..12288, Direction::ToDevice),
                    Event::Unmap(1)
                ]
            );
            services.as_mut().unbind().unwrap();
            assert_eq!(nv_requires_dma_remap(state.raw()), 0);
            drop(services);
            nv_free_kernel_mapping(ptr::null_mut(), ptr::null_mut(), cpu, cpu_private);
            assert_eq!(source.released.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn failed_policies_and_provider_results_do_not_publish_ptes() {
        let source = Source::new(12);
        let domain = Domain::new();
        let state = State::new();
        let mut services = bind(&source, &domain, &state);
        // SAFETY: real bound test state; all failed requests have writable output
        // slots and sufficient PTE capacity. No returned handle escapes this test.
        unsafe {
            for (count, size, contiguous, cache, zeroed, unencrypted, node, expected) in [
                (0, 4096, 0, 0, 1, 0, -1, Status::InvalidArgument),
                (1, 0, 0, 0, 1, 0, -1, Status::InvalidArgument),
                (1, 8192, 0, 0, 1, 0, -1, Status::NotSupported),
                (1, 4096, 2, 0, 1, 0, -1, Status::InvalidArgument),
                (1, 4096, 0, 6, 1, 0, -1, Status::NotSupported),
                (1, 4096, 0, 0, 2, 0, -1, Status::InvalidArgument),
                (1, 4096, 0, 0, 1, 1, -1, Status::NotSupported),
                (1, 4096, 0, 0, 1, 0, 0, Status::NotSupported),
                (2, 4096, 1, 0, 1, 0, -1, Status::NoMemory),
            ] {
                let mut ptes = [0xa5a5; 2];
                let mut private = ptr::dangling_mut();
                assert_eq!(
                    nv_alloc_pages(
                        state.raw(),
                        count,
                        size,
                        contiguous,
                        cache,
                        zeroed,
                        unencrypted,
                        node,
                        ptes.as_mut_ptr(),
                        &mut private
                    ),
                    expected as u32
                );
                assert_eq!(
                    private,
                    ptr::dangling_mut(),
                    "failed allocation preserves its output owner"
                );
                assert_eq!(ptes, [0xa5a5; 2]);
            }
            for error in [0, 1, 2] {
                source.fail.set(error == 0);
                source
                    .cache_override
                    .set((error == 1).then_some(CacheAttribute::Uncached));
                source.shift.set(if error == 2 { 14 } else { 12 });
                let mut ptes = [0x1234];
                let mut private = ptr::null_mut();
                let expected = if error == 0 {
                    Status::NoMemory
                } else {
                    Status::OperatingSystem
                };
                assert_eq!(
                    nv_alloc_pages(
                        state.raw(),
                        1,
                        4096,
                        0,
                        0,
                        1,
                        0,
                        -1,
                        ptes.as_mut_ptr(),
                        &mut private
                    ),
                    expected as u32
                );
                assert!(private.is_null());
                assert_eq!(ptes, [0x1234]);
            }
            services.as_mut().unbind().unwrap();
        }
        assert!(domain.events().is_empty());
    }

    #[test]
    fn native_granule_cache_contiguity_and_force32_are_real_checks() {
        if page_geometry::tests::separate_model_process(
            "gpu::nvidia::services::tests::native_granule_cache_contiguity_and_force32_are_real_checks",
            14,
        ) {
            return;
        }
        let source = Source::new(14);
        source.stride.set(1);
        let domain = Domain::new();
        let state = State::new();
        let mut services = bind(&source, &domain, &state);
        // SAFETY: full native capacities and serialized bound original C state.
        unsafe {
            for cache in [0, 1, 2] {
                let mut ptes = [u64::MAX; 3];
                let mut allocation = ptr::null_mut();
                assert_eq!(
                    nv_alloc_pages(
                        state.raw(),
                        2,
                        16384,
                        1,
                        cache,
                        0,
                        0,
                        -1,
                        ptes.as_mut_ptr(),
                        &mut allocation
                    ),
                    0
                );
                assert_eq!(
                    ptes,
                    [0x8000_0000, u64::MAX, u64::MAX],
                    "contiguous output is one physical base"
                );
                assert_eq!(
                    (*allocation.cast::<Allocation>()).pages().cache_attribute(),
                    cache_attribute(cache).unwrap()
                );
                assert_eq!(
                    nv_free_pages(state.raw(), 1, 1, cache, allocation),
                    Status::InvalidArgument as u32
                );
                let mut dma_private = allocation;
                assert_eq!(
                    nv_dma_map_alloc(key(&services), 2, ptes.as_mut_ptr(), 1, 0, &mut dma_private),
                    0
                );
                let expected_iova = 0x4000_0000 + (u64::from(cache) + 1) * 0x10_0000;
                assert_eq!(
                    ptes,
                    [expected_iova, u64::MAX, u64::MAX],
                    "contiguous DMA output also has one native IOVA base"
                );
                assert_eq!(
                    nv_dma_unmap_alloc(key(&services), 2, ptes.as_mut_ptr(), &mut dma_private),
                    0
                );
                assert!(dma_private.is_null());
                assert_eq!(nv_free_pages(state.raw(), 2, 1, cache, allocation), 0);
            }
            source.base.set(0x1_0000_0000);
            let mut ptes = [0xa5a5];
            let mut allocation = ptr::null_mut();
            // Exercise the actual Rust callback's force32 policy without writing
            // guessed offsets into the opaque original nv_state_t.
            assert_eq!(
                stela_nvidia_alloc_pages(
                    key(&services),
                    state.raw(),
                    1,
                    16384,
                    0,
                    0,
                    1,
                    0,
                    -1,
                    1,
                    ptes.as_mut_ptr(),
                    &mut allocation
                ),
                Status::NoMemory
            );
            assert_eq!(ptes, [0xa5a5]);
            assert!(allocation.is_null());
            services.as_mut().unbind().unwrap();
        }
        assert_eq!(source.released.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn foreign_device_and_wrong_arrays_cannot_select_a_domain() {
        let source = Source::new(12);
        let domain = Domain::new();
        let state = State::new();
        let mut services = bind(&source, &domain, &state);
        // SAFETY: valid native storage/slots; deliberate foreign device is only
        // compared as an opaque key, never dereferenced by the adapter.
        unsafe {
            let mut addresses = [0; 2];
            let mut allocation = ptr::null_mut();
            assert_eq!(
                nv_alloc_pages(
                    state.raw(),
                    2,
                    4096,
                    0,
                    0,
                    1,
                    0,
                    -1,
                    addresses.as_mut_ptr(),
                    &mut allocation
                ),
                0
            );
            let physical = addresses;
            let mut private = allocation;
            assert_eq!(
                nv_dma_map_alloc(
                    ptr::dangling_mut(),
                    2,
                    addresses.as_mut_ptr(),
                    0,
                    0,
                    &mut private
                ),
                Status::InvalidArgument as u32
            );
            assert_eq!(
                nv_dma_map_alloc(
                    key(&services),
                    1,
                    addresses.as_mut_ptr(),
                    0,
                    0,
                    &mut private
                ),
                Status::InvalidArgument as u32
            );
            addresses[1] += 4096;
            assert_eq!(
                nv_dma_map_alloc(
                    key(&services),
                    2,
                    addresses.as_mut_ptr(),
                    0,
                    0,
                    &mut private
                ),
                Status::InvalidArgument as u32
            );
            assert!(domain.events().is_empty());
            assert_eq!(private, allocation);
            addresses = physical;
            assert_eq!(
                nv_dma_map_alloc(
                    key(&services),
                    2,
                    addresses.as_mut_ptr(),
                    0,
                    0,
                    &mut private
                ),
                0
            );
            let token = private;
            assert_eq!(
                nv_dma_unmap_alloc(ptr::dangling_mut(), 2, addresses.as_mut_ptr(), &mut private),
                Status::InvalidArgument as u32
            );
            assert_eq!(
                nv_dma_unmap_alloc(key(&services), 1, addresses.as_mut_ptr(), &mut private),
                Status::InvalidArgument as u32
            );
            assert_eq!(private, token);
            assert_eq!(
                nv_dma_unmap_alloc(key(&services), 2, addresses.as_mut_ptr(), &mut private),
                0
            );
            assert_eq!(nv_free_pages(state.raw(), 2, 0, 0, allocation), 0);
            services.as_mut().unbind().unwrap();
        }
        assert_eq!(source.released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unpublished_dma_failures_roll_back_without_mutating_outputs() {
        for failure in [FAIL_MAP, FAIL_DEVICE] {
            let source = Source::new(12);
            let domain = Domain::new();
            domain.failures.store(failure, Ordering::SeqCst);
            let state = State::new();
            let mut services = bind(&source, &domain, &state);
            // SAFETY: real model bindings and capacities. Any temporary mapping
            // remains unpublished, and the model records its actual removal.
            unsafe {
                let mut addresses = [0; 2];
                let mut allocation = ptr::null_mut();
                assert_eq!(
                    nv_alloc_pages(
                        state.raw(),
                        2,
                        4096,
                        0,
                        0,
                        1,
                        0,
                        -1,
                        addresses.as_mut_ptr(),
                        &mut allocation
                    ),
                    0
                );
                let before = addresses;
                let mut private = allocation;
                assert_eq!(
                    nv_dma_map_alloc(
                        key(&services),
                        2,
                        addresses.as_mut_ptr(),
                        0,
                        0,
                        &mut private
                    ),
                    Status::OperatingSystem as u32
                );
                assert_eq!(addresses, before);
                assert_eq!(private, allocation);
                assert_eq!(
                    (services.allocations.get(), services.mappings.get()),
                    (1, 0)
                );
                if failure == FAIL_DEVICE {
                    assert!(matches!(domain.events().last(), Some(Event::Unmap(1))));
                }
                assert_eq!(nv_free_pages(state.raw(), 2, 0, 0, allocation), 0);
                services.as_mut().unbind().unwrap();
            }
            assert_eq!(source.released.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn original_error_discard_path_consumes_failed_dma_into_visible_quarantine() {
        for failure in [FAIL_CPU, FAIL_UNMAP] {
            let source = Source::new(12);
            let domain = Domain::new();
            let state = State::new();
            let mut services = bind(&source, &domain, &state);
            let before = quarantine_status();
            // SAFETY: model device has no running accesses; actual quiescence is
            // established before retirement. Inject a real visibility/removal error.
            unsafe {
                let mut addresses = [0];
                let mut allocation = ptr::null_mut();
                assert_eq!(
                    nv_alloc_pages(
                        state.raw(),
                        1,
                        4096,
                        0,
                        0,
                        1,
                        0,
                        -1,
                        addresses.as_mut_ptr(),
                        &mut allocation
                    ),
                    0
                );
                let mut private = allocation;
                assert_eq!(
                    nv_dma_map_alloc(
                        key(&services),
                        1,
                        addresses.as_mut_ptr(),
                        0,
                        0,
                        &mut private
                    ),
                    0
                );
                assert_eq!(nv_free_pages(state.raw(), 1, 0, 0, allocation), 0);
                domain.failures.store(failure, Ordering::SeqCst);
                assert_eq!(
                    nv_dma_unmap_alloc(key(&services), 1, addresses.as_mut_ptr(), &mut private),
                    Status::OperatingSystem as u32
                );
                assert!(
                    private.is_null(),
                    "matches original caller's unconditional token discard"
                );
                assert_eq!(
                    source.released.load(Ordering::SeqCst),
                    0,
                    "uncertain real pins stay reserved"
                );
                let after = quarantine_status();
                assert!(after.mappings > before.mappings && after.bytes >= before.bytes + 4096);
                services.as_mut().unbind().unwrap();
            }
        }
    }

    #[test]
    fn binding_checks_original_pci_identity_and_existing_slot_ownership() {
        let source = Source::new(12);
        let domain = Domain::new();
        let state = State::new();
        // SAFETY: model policy only; the deliberately wrong requester must fail
        // original-C identity validation before any resource callback is possible.
        let mut wrong = Box::pin(
            unsafe {
                MemoryServices::new(
                    &source,
                    domain.clone(),
                    Address {
                        segment: 0,
                        bus: 1,
                        device: 0,
                        function: 0,
                    },
                    12,
                    u64::from(u32::MAX),
                )
            }
            .unwrap(),
        );
        unsafe {
            assert_eq!(
                wrong.as_mut().bind(state.raw()),
                Err(ServiceError::Native(Status::InvalidArgument as u32))
            );
        }
        let mut services = bind(&source, &domain, &state);
        // SAFETY: binding is already installed; calls are serialized and must
        // refuse replacement/duplicate ownership, leaving the existing slots intact.
        unsafe {
            assert_eq!(
                services.as_mut().bind(state.raw()),
                Err(ServiceError::AlreadyBound)
            );
            assert_eq!(
                wrong.as_mut().bind(state.raw()),
                Err(ServiceError::Native(Status::InvalidState as u32))
            );
            services.as_mut().unbind().unwrap();
            assert_eq!(nv_requires_dma_remap(state.raw()), 0);
        }
        assert_eq!(source.calls.get(), 0);
    }

    #[test]
    fn native_iova_alignment_and_address_limit_fail_before_publication() {
        if page_geometry::tests::separate_model_process(
            "gpu::nvidia::services::tests::native_iova_alignment_and_address_limit_fail_before_publication",
            14,
        ) {
            return;
        }
        for base in [0x4000_1000, 0x1_0000_0000] {
            let source = Source::new(14);
            let domain = Domain::new();
            domain.base.store(base, Ordering::SeqCst);
            let state = State::new();
            let mut services = bind(&source, &domain, &state);
            // SAFETY: exact original state and one native-page output. The model
            // returns a real token with an unsuitable IOVA, never an identity PA.
            unsafe {
                let mut addresses = [0];
                let mut allocation = ptr::null_mut();
                assert_eq!(
                    nv_alloc_pages(
                        state.raw(),
                        1,
                        16384,
                        0,
                        0,
                        1,
                        0,
                        -1,
                        addresses.as_mut_ptr(),
                        &mut allocation
                    ),
                    0
                );
                let physical = addresses;
                let mut private = allocation;
                assert_eq!(
                    nv_dma_map_alloc(
                        key(&services),
                        1,
                        addresses.as_mut_ptr(),
                        0,
                        0,
                        &mut private
                    ),
                    Status::InvalidAddress as u32
                );
                assert_eq!(addresses, physical);
                assert_eq!(private, allocation);
                assert_eq!(
                    (services.allocations.get(), services.mappings.get()),
                    (1, 0)
                );
                assert!(matches!(domain.events().last(), Some(Event::Unmap(1))));
                assert!(
                    !domain
                        .events()
                        .iter()
                        .any(|event| matches!(event, Event::Device(..)))
                );
                assert_eq!(nv_free_pages(state.raw(), 1, 0, 0, allocation), 0);
                services.as_mut().unbind().unwrap();
            }
            assert_eq!(source.released.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn failed_unpublished_rollback_quarantines_without_publishing_a_token() {
        let source = Source::new(12);
        let domain = Domain::new();
        domain
            .failures
            .store(FAIL_DEVICE | FAIL_UNMAP, Ordering::SeqCst);
        let state = State::new();
        let mut services = bind(&source, &domain, &state);
        let before = quarantine_status();
        // SAFETY: the IOVA never escapes, so no model device could use it. Actual
        // visibility and then actual rollback invalidation fail independently.
        unsafe {
            let mut addresses = [0];
            let mut allocation = ptr::null_mut();
            assert_eq!(
                nv_alloc_pages(
                    state.raw(),
                    1,
                    4096,
                    0,
                    0,
                    1,
                    0,
                    -1,
                    addresses.as_mut_ptr(),
                    &mut allocation
                ),
                0
            );
            let physical = addresses;
            let mut private = allocation;
            assert_eq!(
                nv_dma_map_alloc(
                    key(&services),
                    1,
                    addresses.as_mut_ptr(),
                    0,
                    0,
                    &mut private
                ),
                Status::OperatingSystem as u32
            );
            assert_eq!(addresses, physical);
            assert_eq!(private, allocation);
            assert_eq!(
                (services.allocations.get(), services.mappings.get()),
                (1, 0)
            );
            assert_eq!(nv_free_pages(state.raw(), 1, 0, 0, allocation), 0);
            assert_eq!(source.released.load(Ordering::SeqCst), 0);
            let after = quarantine_status();
            assert!(after.mappings > before.mappings && after.bytes >= before.bytes + 4096);
            services.as_mut().unbind().unwrap();
        }
    }

    #[test]
    fn unbound_and_null_original_requests_cannot_reach_a_provider() {
        let state = State::new();
        // SAFETY: exact zeroed test state and real writable slots. No service is
        // bound and null arguments are explicitly refused by these C entry points.
        unsafe {
            let mut addresses = [0xa5a5];
            let mut private = ptr::dangling_mut();
            assert_eq!(
                nv_alloc_pages(
                    state.raw(),
                    1,
                    4096,
                    0,
                    0,
                    1,
                    0,
                    -1,
                    addresses.as_mut_ptr(),
                    &mut private
                ),
                Status::NotSupported as u32
            );
            assert_eq!(private, ptr::dangling_mut());
            assert_eq!(addresses, [0xa5a5]);
            assert_eq!(
                nv_alloc_pages(
                    ptr::null_mut(),
                    1,
                    4096,
                    0,
                    0,
                    1,
                    0,
                    -1,
                    addresses.as_mut_ptr(),
                    &mut private
                ),
                Status::NotSupported as u32
            );
            assert_eq!(
                nv_alloc_pages(
                    state.raw(),
                    1,
                    4096,
                    0,
                    0,
                    1,
                    0,
                    -1,
                    ptr::null_mut(),
                    &mut private
                ),
                Status::InvalidArgument as u32
            );
            assert_eq!(
                nv_alloc_pages(
                    state.raw(),
                    1,
                    4096,
                    0,
                    0,
                    1,
                    0,
                    -1,
                    addresses.as_mut_ptr(),
                    ptr::null_mut()
                ),
                Status::InvalidArgument as u32
            );
            assert_eq!(
                nv_free_pages(state.raw(), 1, 0, 0, ptr::null_mut()),
                Status::InvalidArgument as u32
            );
            assert_eq!(
                nv_dma_map_alloc(
                    ptr::null_mut(),
                    1,
                    addresses.as_mut_ptr(),
                    0,
                    0,
                    ptr::null_mut()
                ),
                Status::NotSupported as u32
            );
            assert_eq!(
                nv_dma_unmap_alloc(ptr::null_mut(), 1, addresses.as_mut_ptr(), ptr::null_mut()),
                Status::NotSupported as u32
            );
        }
    }

    #[test]
    fn source_geometry_and_configured_native_base_must_match_the_installed_profile() {
        struct Unknown;
        impl PageSource for Unknown {
            fn allocate(
                &self,
                _: usize,
                _: usize,
                _: CacheAttribute,
            ) -> Result<PinnedPages, MemoryError> {
                panic!("unknown geometry must fail before allocation");
            }
        }
        let mut source = Source::new(12);
        let domain = Domain::new();
        let requester = Address {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
        };
        // SAFETY: isolated CPU-model domain/requester. Each mismatched or unknown
        // provider must fail before publishing any native state or allocation.
        unsafe {
            assert!(matches!(
                MemoryServices::new(&Unknown, domain.clone(), requester, 12, u64::MAX),
                Err(ServiceError::PageGeometry(page_geometry::Error::Source(
                    MemoryError::Unavailable
                )))
            ));
            assert!(matches!(
                MemoryServices::new(&source, domain.clone(), requester, 14, u64::MAX),
                Err(ServiceError::PageGeometry(page_geometry::Error::Conflict))
            ));
            source.geometry = PageGeometry::contiguous(12, 14).unwrap();
            assert!(matches!(
                MemoryServices::new(&source, domain.clone(), requester, 12, u64::MAX),
                Err(ServiceError::PageGeometry(
                    page_geometry::Error::UnsupportedGeometry
                ))
            ));
        }
        assert_eq!(source.calls.get(), 0);
        assert!(domain.events().is_empty());
    }
}
