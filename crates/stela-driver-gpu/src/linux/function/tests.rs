//! DMA mapping, provider lifetime and PCI configuration fixtures.
extern crate std;
use super::*;
use crate::linux::pages::{Catalog, Entered, Provider, Request, Reservation};
use core::ops::Range;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use stela_driver_base::bus::dma::{
    mapping::DmaError,
    memory::{MemoryError, PageBacking, PinnedPages},
};

#[repr(align(65536))]
struct Buffer([u8; 65536]);
struct Backing {
    buffer: Box<Buffer>,
    physical: [u64; 16],
    drops: Arc<AtomicUsize>,
}
// SAFETY: exclusively owned aligned CPU storage and immutable symbolic
// physical labels; these fixtures never grant hardware access.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::from(&self.buffer.0[0])
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
impl Drop for Backing {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Source(Mutex<Option<PinnedPages>>);
// SAFETY: the isolated owner transfers one exact CPU-owned allocation. No
// atomic allocation, device, native physical address or reentry is modeled.
unsafe impl Provider for Source {
    fn validate(&self, request: Request) -> Result<(), MemoryError> {
        if request.order == 4 && !request.atomic {
            Ok(())
        } else {
            Err(MemoryError::Unavailable)
        }
    }
    fn allocate(&self, _: Request) -> Result<PinnedPages, MemoryError> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or(MemoryError::OutOfMemory)
    }
}
unsafe extern "C" {
    fn __alloc_pages_noprof(gfp: u32, order: u32, nid: i32, nodes: *mut c_void) -> *mut c_void;
    fn __free_pages(page: *mut c_void, order: u32);
    fn stela_linux_pages_finish();
}
struct Fixture {
    catalog: Catalog<Source>,
    entered: Option<Entered>,
    page: *mut c_void,
    drops: Arc<AtomicUsize>,
}
impl Fixture {
    fn new() -> Self {
        let drops = Arc::new(AtomicUsize::new(0));
        let backing = Box::new(Backing {
            buffer: Box::new(Buffer([0; 65536])),
            physical: core::array::from_fn(|index| index as u64 * PAGE_BYTES),
            drops: drops.clone(),
        });
        let cpu = backing.cpu_base();
        let pin = PinnedPages::new(backing, 65536, 65536).unwrap();
        // SAFETY: exact retained CPU-only model extent; symbolic PA labels
        // are never dereferenced and no DMA or external writers exist.
        let reservation = unsafe { Reservation::new(0, cpu, 16) }.unwrap();
        // SAFETY: the source owns precisely this reservation's CPU backing.
        let catalog =
            unsafe { Catalog::register(Source(Mutex::new(Some(pin))), reservation) }.unwrap();
        let entered = Entered::try_new().unwrap();
        // SAFETY: isolated entered owner, registered source of this exact order.
        let page = unsafe { __alloc_pages_noprof(0, 4, -1, core::ptr::null_mut()) };
        assert!(!page.is_null());
        Self {
            catalog,
            entered: Some(entered),
            page,
            drops,
        }
    }
    fn free_pages(&mut self) {
        if !self.page.is_null() {
            // SAFETY: this fixture's exact still-live Linux allocation, in
            // its entered owner. DMA allocation leases remain independent.
            unsafe { __free_pages(self.page, 4) };
            self.page = core::ptr::null_mut();
        }
        // SAFETY: the model owner is entered, quiescent and has no workers.
        unsafe { stela_linux_pages_finish() };
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.entered.is_some() {
            self.free_pages();
            self.entered.take();
        }
    }
}
fn isolated(name: &str) -> bool {
    if std::env::var_os("STELA_DMA_PIN_CHILD").is_some() {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env("STELA_DMA_PIN_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        std::string::String::from_utf8_lossy(&output.stdout),
        std::string::String::from_utf8_lossy(&output.stderr)
    );
    false
}

/// A function's configuration space as plain memory.
struct Config([u8; 256]);

impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> u32 {
        let at = usize::from(offset);
        u32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }
    fn write32(&mut self, offset: u16, value: u32) {
        let at = usize::from(offset);
        self.0[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn write16(&mut self, offset: u16, value: u16) {
        let at = usize::from(offset);
        self.0[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn write8(&mut self, offset: u16, value: u8) {
        self.0[usize::from(offset)] = value;
    }
}

#[test]
fn msi_programs_its_one_message_by_width() {
    const CAPABILITY: u16 = 0x60;
    for (width, data_at) in [(1 << 7, 0x6c), (0, 0x68)] {
        let mut config = Config([0; 256]);
        // Enabled, with a previous owner's multiple-message setting.
        config.write16(CAPABILITY + 2, width | 1 | 2 << 4);
        let msi = Msi::at(CAPABILITY);
        msi.program(&mut config, 0x1_fee0_1000, 0x51);
        assert_eq!(config.read16(CAPABILITY + 2), width | 2 << 4);
        assert_eq!(config.read32(CAPABILITY + 4), 0xfee0_1000);
        assert_eq!(config.read16(data_at), 0x51);
        msi.enable(&mut config);
        assert_eq!(config.read16(CAPABILITY + 2), width | 1);
        msi.disable(&mut config);
        assert_eq!(config.read16(CAPABILITY + 2), width);
    }
}

#[derive(Default)]
struct Identity {
    next: AtomicU64,
    unmapped: AtomicU64,
    fail_map: AtomicBool,
    fail_unmap: AtomicBool,
}

// SAFETY: bookkeeping over addresses nothing dereferences.
unsafe impl DmaDomain for Identity {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        _: Direction,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        if self.fail_map.load(Ordering::Relaxed) {
            return Err(DmaError::InvalidationFailed);
        }
        let address = pages.physical_pages()[0];
        assert!(address <= limit);
        Ok(DomainMapping {
            id: self.next.fetch_add(1, Ordering::Relaxed),
            address,
            bytes: pages.bytes(),
        })
    }
    unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
        self.unmapped.fetch_add(1, Ordering::Relaxed);
        if self.fail_unmap.load(Ordering::Relaxed) {
            return Err(DmaError::InvalidationFailed);
        }
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Ok(())
    }
}

#[test]
fn the_same_pages_can_be_mapped_twice() {
    if !isolated("linux::function::tests::the_same_pages_can_be_mapped_twice") {
        return;
    }
    let _fixture = Fixture::new();
    let domain = Arc::new(Identity::default());
    let mut mappings = Mappings {
        domain: domain.clone(),
        limit: u64::MAX >> 1,
        live: BTreeMap::new(),
    };
    let address = mappings.map(0x5010, 0x2000, Direction::ToDevice).unwrap();
    assert_eq!(address, Some(0x5010));
    assert_eq!(
        mappings.map(0x5010, 0x10, Direction::FromDevice).unwrap(),
        address
    );
    mappings.unmap(0x5010).unwrap();
    assert_eq!(domain.unmapped.load(Ordering::Relaxed), 1);
    assert!(mappings.live.contains_key(&0x5010));
    mappings.unmap(0x5010).unwrap();
    assert!(mappings.live.is_empty());
    mappings.unmap(0x5010).unwrap();
    assert_eq!(domain.unmapped.load(Ordering::Relaxed), 2);
}

#[test]
fn a_mapping_spans_every_page_it_touches() {
    if !isolated("linux::function::tests::a_mapping_spans_every_page_it_touches") {
        return;
    }
    let _fixture = Fixture::new();
    let domain = Arc::new(Identity::default());
    let mut mappings = Mappings {
        domain,
        limit: u64::MAX >> 1,
        live: BTreeMap::new(),
    };
    mappings
        .map(0x1ff0, 0x20, Direction::Bidirectional)
        .unwrap();
    let mapping = mappings.live[&0x1ff0][0].token;
    assert_eq!(mapping.bytes, 0x2000);
    assert_eq!(
        mappings.map(u64::MAX, 2, Direction::ToDevice).unwrap(),
        None
    );
    mappings.unmap(0x1ff0).unwrap();
}

fn mappings(domain: &Arc<Identity>) -> Mappings {
    Mappings {
        domain: domain.clone(),
        limit: u64::MAX >> 1,
        live: BTreeMap::new(),
    }
}

#[test]
fn unowned_page_refusal_releases_preflight_pins() {
    if !isolated("linux::function::tests::unowned_page_refusal_releases_preflight_pins") {
        return;
    }
    let mut fixture = Fixture::new();
    let domain = Arc::new(Identity::default());
    let mut mappings = mappings(&domain);
    // The first page is owned, the next lies outside the catalog.
    assert_eq!(
        mappings.map(0xf000, 0x2000, Direction::ToDevice).unwrap(),
        None
    );
    assert_eq!(domain.next.load(Ordering::Relaxed), 0);
    fixture.free_pages();
    assert_eq!(fixture.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn map_failure_quarantines_original_backing_and_domain() {
    if !isolated("linux::function::tests::map_failure_quarantines_original_backing_and_domain") {
        return;
    }
    let mut fixture = Fixture::new();
    let domain = Arc::new(Identity::default());
    domain.fail_map.store(true, Ordering::Relaxed);
    let mut mappings = mappings(&domain);
    let before = dma_quarantine_status();
    assert_eq!(
        mappings.map(0x5010, 0x2000, Direction::ToDevice),
        Err(DmaError::InvalidationFailed)
    );
    let after = dma_quarantine_status();
    assert_eq!(after.mappings, before.mappings + 1);
    assert_eq!(after.bytes, before.bytes + 0x3000);
    fixture.free_pages();
    drop(mappings);
    assert_eq!(fixture.drops.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&domain), 2);
    fixture.entered.take();
    assert_eq!(
        fixture.catalog.try_retire(),
        Err(crate::linux::pages::Error::Native(-16))
    );
}

#[test]
fn unmap_failure_retains_token_and_backing_until_successful_retry() {
    if !isolated(
        "linux::function::tests::unmap_failure_retains_token_and_backing_until_successful_retry",
    ) {
        return;
    }
    let mut fixture = Fixture::new();
    let domain = Arc::new(Identity::default());
    let mut mappings = mappings(&domain);
    let address = mappings
        .map(0x5010, 0x2000, Direction::ToDevice)
        .unwrap()
        .unwrap();
    let token = mappings.live[&address][0].token;
    domain.fail_unmap.store(true, Ordering::Relaxed);
    assert_eq!(mappings.unmap(address), Err(DmaError::InvalidationFailed));
    assert_eq!(mappings.live[&address][0].token, token);
    fixture.free_pages();
    assert_eq!(fixture.drops.load(Ordering::Relaxed), 0);
    domain.fail_unmap.store(false, Ordering::Relaxed);
    mappings.unmap(address).unwrap();
    assert!(mappings.live.is_empty());
    fixture.free_pages();
    assert_eq!(fixture.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn dropping_active_mappings_quarantines_original_backing_and_domain() {
    if !isolated(
        "linux::function::tests::dropping_active_mappings_quarantines_original_backing_and_domain",
    ) {
        return;
    }
    let mut fixture = Fixture::new();
    let domain = Arc::new(Identity::default());
    let mut mappings = mappings(&domain);
    mappings.map(0x5010, 0x2000, Direction::ToDevice).unwrap();
    drop(mappings);
    fixture.free_pages();
    assert_eq!(fixture.drops.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&domain), 2);
    fixture.entered.take();
    assert_eq!(
        fixture.catalog.try_retire(),
        Err(crate::linux::pages::Error::Native(-16))
    );
}

#[cfg(unix)]
mod fatal;

mod lifetime;
