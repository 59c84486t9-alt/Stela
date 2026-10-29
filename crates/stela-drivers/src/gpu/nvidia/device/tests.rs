//! CPU-only owned canonical resource/config/page models; no RM or hardware.
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DmaError, DomainMapping},
        memory::{CacheAttribute, MemoryError, PageBacking, PageGeometry, PinnedPages},
    },
    mmio::owned::{PhysicalSpan, ResourceBacking},
};
use alloc::vec::Vec;
use core::{
    cell::Cell,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
extern crate std;
std::thread_local! { static BUDGET: Cell<Option<usize>> = const {Cell::new(None)}; }
pub(super) fn reserve() -> Result<(), Error> {
    BUDGET.with(|b| match b.get() {
        Some(0) => Err(Error::OutOfMemory),
        Some(n) => {
            b.set(Some(n - 1));
            Ok(())
        }
        None => Ok(()),
    })
}
struct Counts {
    drops: [AtomicUsize; 5],
    context: AtomicBool,
    reads: AtomicUsize,
    lose_context: AtomicBool,
    lose_at: AtomicUsize,
    geometry_failure: AtomicUsize,
    geometry_calls: AtomicUsize,
    metadata_loss: AtomicUsize,
    recover_on_check: AtomicBool,
    writes: AtomicUsize,
    write_width: AtomicUsize,
    write_value: AtomicUsize,
    write_loss: AtomicBool,
}
impl Counts {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            drops: core::array::from_fn(|_| AtomicUsize::new(0)),
            context: AtomicBool::new(true),
            reads: AtomicUsize::new(0),
            lose_context: AtomicBool::new(false),
            lose_at: AtomicUsize::new(60),
            geometry_failure: AtomicUsize::new(0),
            geometry_calls: AtomicUsize::new(0),
            metadata_loss: AtomicUsize::new(0),
            recover_on_check: AtomicBool::new(false),
            writes: AtomicUsize::new(0),
            write_width: AtomicUsize::new(0),
            write_value: AtomicUsize::new(0),
            write_loss: AtomicBool::new(false),
        })
    }
    fn values(&self) -> [usize; 5] {
        core::array::from_fn(|i| self.drops[i].load(Ordering::SeqCst))
    }
}
struct Config {
    words: [u32; 16],
    counts: Arc<Counts>,
}
impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> u32 {
        self.counts.reads.fetch_add(1, Ordering::SeqCst);
        if usize::from(offset) == self.counts.lose_at.load(Ordering::SeqCst)
            && self.counts.lose_context.load(Ordering::SeqCst)
        {
            self.counts.context.store(false, Ordering::SeqCst);
        }
        self.words[usize::from(offset) / 4]
    }
    fn write32(&mut self, _: u16, value: u32) {
        self.record_write(4, value);
    }
    fn write16(&mut self, _: u16, value: u16) {
        self.record_write(2, u32::from(value));
    }
    fn write8(&mut self, _: u16, value: u8) {
        self.record_write(1, u32::from(value));
    }
}
impl Config {
    fn record_write(&self, width: usize, value: u32) {
        self.counts.writes.fetch_add(1, Ordering::SeqCst);
        self.counts.write_width.store(width, Ordering::SeqCst);
        self.counts
            .write_value
            .store(value as usize, Ordering::SeqCst);
        if self.counts.write_loss.load(Ordering::SeqCst) {
            self.counts.context.store(false, Ordering::SeqCst);
        }
    }
}
impl Drop for Config {
    fn drop(&mut self) {
        self.counts.drops[1].fetch_add(1, Ordering::SeqCst);
    }
}
struct Backing {
    span: PhysicalSpan,
    kind: ResourceKind,
    counts: Arc<Counts>,
}
// SAFETY: immutable distinct synthetic resource labels; never a native grant.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        self.kind
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.counts.drops[4].fetch_add(1, Ordering::SeqCst);
    }
}
struct Epoch {
    identity: Identity,
    bars: Apertures,
    counts: Arc<Counts>,
}
// SAFETY: all input callbacks/resources are bounded CPU-only models in this test.
unsafe impl Owner for Epoch {
    fn identity(&self) -> Identity {
        if self.counts.metadata_loss.load(Ordering::SeqCst) == 1 {
            self.counts.context.store(false, Ordering::SeqCst);
        }
        self.identity
    }
    fn apertures(&self) -> Apertures {
        if self.counts.metadata_loss.load(Ordering::SeqCst) == 2 {
            self.counts.context.store(false, Ordering::SeqCst);
        }
        let copy = |x: &Aperture| Aperture {
            index: x.index,
            resource: x.resource.clone(),
        };
        Apertures {
            registers: copy(&self.bars.registers),
            framebuffer: copy(&self.bars.framebuffer),
            instance: self.bars.instance.as_ref().map(copy),
        }
    }
    fn check_context(&self) -> Result<(), i32> {
        if self.counts.context.load(Ordering::SeqCst) {
            Ok(())
        } else {
            if self.counts.recover_on_check.swap(false, Ordering::SeqCst) {
                self.counts.context.store(true, Ordering::SeqCst);
            }
            Err(-77)
        }
    }
}
impl Drop for Epoch {
    fn drop(&mut self) {
        self.counts.drops[0].fetch_add(1, Ordering::SeqCst);
    }
}
struct Source(Arc<Counts>);
struct Page {
    pointer: NonNull<u8>,
    physical: [u64; 1],
    layout: Layout,
}
// SAFETY: exclusively allocated model bytes, immutable metadata, no hardware.
unsafe impl Send for Page {}
// SAFETY: only the CPU-model pin accesses these bytes, serialized here.
unsafe impl Sync for Page {}
// SAFETY: zeroed aligned CPU allocation with distinct model PA label, pinned to Drop.
unsafe impl PageBacking for Page {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: the pointer came from the matching allocation with this layout and is freed
        // once.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) }
    }
}
impl PageSource for Source {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        self.0.geometry_calls.fetch_add(1, Ordering::SeqCst);
        match self.0.geometry_failure.load(Ordering::SeqCst) {
            1 => return Err(MemoryError::Unavailable),
            2 => {
                self.0.context.store(false, Ordering::SeqCst);
                return Err(MemoryError::Unavailable);
            }
            3 => self.0.context.store(false, Ordering::SeqCst),
            _ => {}
        }
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        cache: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(
            (bytes, alignment, cache),
            (4096, 4096, CacheAttribute::WriteBack)
        );
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        let pointer =
                // SAFETY: the layout has a nonzero size.
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
        PinnedPages::new(
            Box::new(Page {
                pointer,
                physical: [0x8000_0000],
                layout,
            }),
            bytes,
            alignment,
        )
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.0.drops[2].fetch_add(1, Ordering::SeqCst);
    }
}
struct Domain(Arc<Counts>);
// SAFETY: model explicitly refuses all DMA; no fake successful map or IOVA.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        _: &crate::bus::dma::pages::DmaPages,
        _: Direction,
        _: u64,
    ) -> Result<DomainMapping, DmaError> {
        Err(DmaError::IommuUnavailable)
    }
    unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
        panic!("no DMA mappings")
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        panic!("no DMA mappings")
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        panic!("no DMA mappings")
    }
}
impl Drop for Domain {
    fn drop(&mut self) {
        self.0.drops[3].fetch_add(1, Ordering::SeqCst);
    }
}
type Inputs = (
    Box<Config>,
    Box<Epoch>,
    Box<Source>,
    Arc<Domain>,
    Arc<Counts>,
);
fn inputs() -> Inputs {
    super::super::page_geometry::tests::initialize_model(12);
    let counts = Counts::new();
    let aperture = |index, start, bytes, kind| Aperture {
        index,
        resource: Resource::new(Box::new(Backing {
            span: PhysicalSpan::new(start, bytes).unwrap(),
            kind,
            counts: counts.clone(),
        })),
    };
    let bars = Apertures {
        registers: aperture(0, 0x1_1000_0000, 0x1_0000, ResourceKind::Registers),
        framebuffer: aperture(
            2,
            0x2_2000_0000,
            0x20_0000,
            ResourceKind::PrefetchableMemory,
        ),
        instance: Some(aperture(
            4,
            0x3_3000_0000,
            0x1_0000,
            ResourceKind::Registers,
        )),
    };
    let identity = Identity {
        address: Address {
            segment: 3,
            bus: 0x42,
            device: 5,
            function: 0,
        },
        vendor: 0x10de,
        device: 0x2684,
        subsystem_vendor: 0x10de,
        subsystem: 0x1234,
        virtual_function: false,
    };
    let mut words = [0; 16];
    words[0] = 0x2684_10de;
    words[2] = 0x0300_0001;
    words[4] = 0x1000_0004;
    words[5] = 1;
    words[6] = 0x2000_000c;
    words[7] = 2;
    words[8] = 0x3000_0004;
    words[9] = 3;
    words[11] = 0x1234_10de;
    (
        Box::new(Config {
            words,
            counts: counts.clone(),
        }),
        Box::new(Epoch {
            identity,
            bars,
            counts: counts.clone(),
        }),
        Box::new(Source(counts.clone())),
        Arc::new(Domain(counts.clone())),
        counts,
    )
}
#[test]
fn original_state_identity_owned_pinning_and_known_retirement() {
    let (config, owner, source, domain, c) = inputs();
    let id = owner.identity;
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut d =
        unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }.unwrap();
    assert_eq!(d.identity(), Some(id));
    assert_eq!(c.reads.load(Ordering::SeqCst), 16);
    assert_eq!(c.writes.load(Ordering::SeqCst), 0);
    assert_eq!(c.values(), [0; 5]);
    let state = d.bundle.as_ref().unwrap().state.raw();
    let moved = Vec::from([d]);
    d = moved.into_iter().next().unwrap();
    assert_eq!(d.bundle.as_ref().unwrap().state.raw(), state);
    d.retire().unwrap();
    assert_eq!(d.identity(), None);
    assert_eq!(c.values(), [1, 1, 1, 1, 3]);
    assert_eq!(d.retire(), Err(Error::Retired));
    drop(d);
    assert_eq!(c.values(), [1, 1, 1, 1, 3]);
}
#[test]
fn mismatched_configuration_bar_roles_context_and_metadata_oom_do_not_bind() {
    for failure in 0..8 {
        let (mut config, mut owner, source, domain, c) = inputs();
        match failure {
            0 => config.words[0] ^= 1,
            1 => config.words[11] ^= 1,
            2 => config.words[4] ^= 0x10000,
            3 => owner.bars.framebuffer.index = 4,
            4 => owner.identity.virtual_function = true,
            5 => c.context.store(false, Ordering::SeqCst),
            6 | 7 => BUDGET.with(|b| b.set(Some(failure - 6))),
            _ => unreachable!(),
        }
        let result =
                // SAFETY: the model device, its pages and its domain belong to this test alone; no
                // other driver, worker or DMA touches them.
                unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) };
        BUDGET.with(|b| b.set(None));
        assert!(result.is_err());
        assert_eq!(
            c.values(),
            if failure == 5 {
                [0; 5]
            } else {
                [1, 1, 1, 1, 3]
            }
        );
    }
}
unsafe extern "C" {
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
}
#[test]
fn real_allocation_counter_refusal_retains_every_owner_and_can_retry() {
    let (config, owner, source, domain, c) = inputs();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut d =
        unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }.unwrap();
    let state = d.bundle.as_ref().unwrap().state.raw();
    let (mut pa, mut allocation) = (0, core::ptr::null_mut());
    assert_eq!(
        // SAFETY: `state` is this test's prepared device, and the out pointers are live locals.
        unsafe { nv_alloc_pages(state, 1, 4096, 0, 0, 1, 0, -1, &mut pa, &mut allocation) },
        0
    );
    assert_eq!(pa, 0x8000_0000);
    assert!(matches!(d.retire(), Err(Error::Services(_))));
    assert_eq!(c.values(), [0; 5]);
    assert!(d.identity().is_some());
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    assert_eq!(unsafe { nv_free_pages(state, 1, 0, 0, allocation) }, 0);
    d.retire().unwrap();
    assert_eq!(c.values(), [1, 1, 1, 1, 3]);
}
#[test]
fn drop_uncertainty_retains_whole_owned_bundle_without_extending_borrows() {
    let (config, owner, source, domain, c) = inputs();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut d =
        unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }.unwrap();
    c.context.store(false, Ordering::SeqCst);
    assert_eq!(d.retire(), Err(Error::Context(-77)));
    drop(d);
    assert_eq!(c.values(), [0; 5]); // Intentional permanent owned retention.
    c.context.store(true, Ordering::SeqCst);
    assert_eq!(c.values(), [0; 5]);
}

#[test]
fn lost_context_after_config_and_live_allocation_drop_keep_all_storage_alive() {
    let (config, owner, source, domain, c) = inputs();
    c.lose_context.store(true, Ordering::SeqCst);
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) },
        Err(Error::Context(-77))
    ));
    assert_eq!(c.reads.load(Ordering::SeqCst), 16);
    assert_eq!(c.values(), [0; 5]);
    let (config, owner, source, domain, c) = inputs();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut d =
        unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }.unwrap();
    let state = d.bundle.as_ref().unwrap().state.raw();
    let (mut pa, mut allocation) = (0, core::ptr::null_mut());
    assert_eq!(
        // SAFETY: `state` is this test's prepared device, and the out pointers are live locals.
        unsafe { nv_alloc_pages(state, 1, 4096, 0, 0, 1, 0, -1, &mut pa, &mut allocation) },
        0
    );
    assert!(matches!(d.retire(), Err(Error::Services(_))));
    drop(d);
    assert_eq!(c.values(), [0; 5]);
    // This test-only kept token is the allocation produced above.
    // Its successful real free after Drop exercises still-live State/services,
    // source and domain, rather than observing leaked bookkeeping.
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    assert_eq!(unsafe { nv_free_pages(state, 1, 0, 0, allocation) }, 0);
    assert_eq!(c.values(), [0; 5]);
}
#[test]
fn actual_configured_geometry_refusal_precedes_allocation_and_binding() {
    let (config, owner, source, domain, c) = inputs();
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { PreparedDevice::prepare(config, owner, source, domain, 13, u64::MAX) },
        Err(Error::Services(_))
    ));
    assert_eq!(c.reads.load(Ordering::SeqCst), 0);
    assert_eq!(c.values(), [1, 1, 1, 1, 3]);
}

#[test]
fn native_failure_and_provider_error_context_loss_retain_all_owned_inputs() {
    let (mut config, owner, source, domain, c) = inputs();
    config.words[0] ^= 1;
    c.lose_context.store(true, Ordering::SeqCst);
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) },
        Err(Error::Context(-77))
    ));
    assert_eq!(c.reads.load(Ordering::SeqCst), 16);
    assert_eq!(c.values(), [0; 5]);
    for failure in 1..=3 {
        let (config, owner, source, domain, c) = inputs();
        c.geometry_failure.store(failure, Ordering::SeqCst);
        BUDGET.with(|b| b.set(Some(2)));
        let result =
                // SAFETY: the model device, its pages and its domain belong to this test alone; no
                // other driver, worker or DMA touches them.
                unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) };
        BUDGET.with(|b| {
            assert_eq!(
                b.get(),
                Some(2),
                "no metadata allocation after provider loss"
            );
            b.set(None);
        });
        if failure == 1 {
            assert!(matches!(result, Err(Error::Services(_))));
            assert_eq!(c.values(), [1, 1, 1, 1, 3]);
        } else {
            assert!(matches!(result, Err(Error::Context(-77))));
            assert_eq!(c.values(), [0; 5]);
        }
        assert_eq!(c.reads.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn metadata_context_loss_precedes_provider_allocation_and_config_access() {
    for loss in 1..=2 {
        let (config, owner, source, domain, c) = inputs();
        c.metadata_loss.store(loss, Ordering::SeqCst);
        BUDGET.with(|b| b.set(Some(2)));
        assert!(matches!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) },
            Err(Error::Context(-77))
        ));
        BUDGET.with(|b| {
            assert_eq!(b.get(), Some(2));
            b.set(None);
        });
        assert_eq!(c.geometry_calls.load(Ordering::SeqCst), 0);
        assert_eq!(c.reads.load(Ordering::SeqCst), 0);
        assert_eq!(c.values(), [0; 5]);
    }
}

#[test]
fn every_config_read_loss_stops_before_the_next_actual_effect() {
    for word in 0..16 {
        for (mismatch, transient) in [(false, false), (true, false), (false, true), (true, true)] {
            let (mut config, owner, source, domain, c) = inputs();
            if mismatch {
                config.words[0] ^= 1;
            }
            c.lose_context.store(true, Ordering::SeqCst);
            c.lose_at.store(word * 4, Ordering::SeqCst);
            c.recover_on_check.store(transient, Ordering::SeqCst);
            assert!(matches!(
                // SAFETY: the model device, its pages and its domain belong to this test alone;
                // no other driver, worker or DMA touches them.
                unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) },
                Err(Error::Context(-77))
            ));
            assert_eq!(c.reads.load(Ordering::SeqCst), word + 1);
            assert_eq!(c.values(), [0; 5]);
        }
    }
}

unsafe extern "C" {
    fn os_pci_read_dword(handle: *mut c_void, offset: u32, out: *mut u32) -> u32;
    fn os_pci_write_byte(handle: *mut c_void, offset: u32, value: u8) -> u32;
    fn os_pci_write_word(handle: *mut c_void, offset: u32, value: u16) -> u32;
    fn os_pci_write_dword(handle: *mut c_void, offset: u32, value: u32) -> u32;
}
// Test-only projection; the public PreparedDevice exposes no C pointer.
fn handle(d: &mut PreparedDevice<Config>) -> *mut c_void {
    // SAFETY: the test only reads fields through this reference and never moves the pinned
    // bundle.
    let this = unsafe { d.bundle.as_mut().unwrap().as_mut().get_unchecked_mut() };
    // SAFETY: the PCI owner stays pinned inside the bundle, and this test holds the only
    // reference to it.
    unsafe { Pin::new_unchecked((&mut *this.pci.get()).as_mut().unwrap()).as_raw() }
}
#[test]
fn actual_pci_callback_failures_widths_and_latched_uncertainty() {
    let (config, owner, source, domain, c) = inputs();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut d =
        unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }.unwrap();
    // A context refusal before any effect can be retried in the valid context.
    c.context.store(false, Ordering::SeqCst);
    assert_eq!(d.retire(), Err(Error::Context(-77)));
    c.context.store(true, Ordering::SeqCst);
    d.retire().unwrap();
    assert_eq!(c.values(), [1, 1, 1, 1, 3]);
    for failure in 0..=2 {
        let (config, owner, source, domain, c) = inputs();
        let mut d =
                // SAFETY: the model device, its pages and its domain belong to this test alone; no
                // other driver, worker or DMA touches them.
                unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }
                    .unwrap();
        let h = handle(&mut d);
        // SAFETY: `h` is this test's model PCI handle, and `out` is a live local.
        assert_eq!(unsafe { os_pci_write_byte(h, 0x40, 0xa5) }, 0);
        assert_eq!(
            (
                c.write_width.load(Ordering::SeqCst),
                c.write_value.load(Ordering::SeqCst)
            ),
            (1, 0xa5)
        );
        // SAFETY: `h` is this test's model PCI handle, and `out` is a live local.
        assert_eq!(unsafe { os_pci_write_word(h, 0x42, 0x8abc) }, 0);
        assert_eq!(
            (
                c.write_width.load(Ordering::SeqCst),
                c.write_value.load(Ordering::SeqCst)
            ),
            (2, 0x8abc)
        );
        // SAFETY: `h` is this test's model PCI handle, and `out` is a live local.
        assert_eq!(unsafe { os_pci_write_dword(h, 0x44, 0x81234567) }, 0);
        assert_eq!(
            (
                c.write_width.load(Ordering::SeqCst),
                c.write_value.load(Ordering::SeqCst)
            ),
            (4, 0x81234567)
        );
        if failure == 0 {
            d.retire().unwrap();
            assert_eq!(c.values(), [1, 1, 1, 1, 3]);
            continue;
        }
        if failure == 1 {
            c.context.store(false, Ordering::SeqCst);
        } else {
            c.write_loss.store(true, Ordering::SeqCst);
            c.recover_on_check.store(true, Ordering::SeqCst);
        }
        // SAFETY: `h` is this test's model PCI handle, and `out` is a live local.
        assert_ne!(unsafe { os_pci_write_dword(h, 0x48, 0xabcdef01) }, 0);
        let reads = c.reads.load(Ordering::SeqCst);
        let writes = c.writes.load(Ordering::SeqCst);
        assert_eq!(writes, if failure == 1 { 3 } else { 4 });
        c.context.store(true, Ordering::SeqCst);
        let mut out = 0x12345678;
        // SAFETY: `h` is this test's model PCI handle, and `out` is a live local.
        assert_ne!(unsafe { os_pci_read_dword(h, 0, &mut out) }, 0);
        assert_eq!(out, u32::MAX); // Original C shim's explicit failed-read output.
        // SAFETY: `h` is this test's model PCI handle, and `out` is a live local.
        assert_ne!(unsafe { os_pci_write_dword(h, 0x48, 0) }, 0);
        assert_eq!(c.reads.load(Ordering::SeqCst), reads);
        assert_eq!(c.writes.load(Ordering::SeqCst), writes);
        assert_eq!(d.retire(), Err(Error::Context(-77)));
        drop(d);
        assert_eq!(c.values(), [0; 5]);
    }
}
