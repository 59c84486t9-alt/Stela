//! Independent nonidentity IOMMU/cache peer over retained actual CPU storage.
//! Symbolic physical/IOVA labels grant no native hardware qualification.
use super::*;
use crate::bus::dma::{
    mapping::{DomainMapping, quarantine_status},
    memory::{PageBacking, PageGeometry},
    pages::DmaPages,
};
use alloc::{
    alloc::{alloc, dealloc},
    boxed::Box,
    collections::BTreeMap,
    vec,
    vec::Vec,
};
use core::{
    alloc::Layout,
    sync::atomic::{AtomicUsize, Ordering},
};
extern crate std;
use std::sync::Mutex;

#[derive(Default)]
struct Counts {
    pages: AtomicUsize,
    domains: AtomicUsize,
}
struct Backing {
    pointer: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
    shift: u8,
    attribute: CacheAttribute,
    counts: Arc<Counts>,
}
// SAFETY: fixture RAM has stable actual storage/immutable page metadata; tests
// serialize all raw CPU/device effects. No safe references to payload escape.
unsafe impl Send for Backing {}
// SAFETY: same serialized independent peer, no asynchronous or shared writers.
unsafe impl Sync for Backing {}
// SAFETY: owned aligned CPU RAM backs exactly these symbolic physical pages.
// Its complete mapping and reservation survive until the last real pin drops.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
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
        self.counts.pages.fetch_add(1, Ordering::SeqCst);
        // SAFETY: exact unique fixture allocation after final pin/CPU/DMA view.
        unsafe {
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}
struct Binding {
    token: DomainMapping,
    pages: DmaPages,
    direction: Direction,
    visible: Vec<u8>,
}
struct State {
    next_iova: u64,
    next_id: u64,
    next_physical: u64,
    geometry: Result<PageGeometry, MemoryError>,
    shift: u8,
    attribute: Option<CacheAttribute>,
    requests: Vec<(usize, usize, CacheAttribute)>,
    bindings: BTreeMap<u64, Binding>,
    maps: Vec<(DomainMapping, Direction, Vec<u64>)>,
    unmaps: Vec<DomainMapping>,
    syncs: Vec<(bool, DomainMapping, Range<usize>, Direction)>,
    coherent_reads: Vec<usize>,
    coherent: bool,
    fail_allocate: bool,
    short_allocate: bool,
    fail_map: bool,
    fail_unmap: bool,
    fail_sync: Option<(bool, bool)>,
}
struct Source {
    state: Arc<Mutex<State>>,
    counts: Arc<Counts>,
}
impl PageSource for Source {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        self.state.lock().unwrap().geometry
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        let mut s = self.state.lock().unwrap();
        s.requests.push((bytes, alignment, attribute));
        if s.fail_allocate {
            return Err(MemoryError::OutOfMemory);
        }
        let granule = 1usize << s.shift;
        let bytes = if s.short_allocate {
            bytes - granule
        } else {
            bytes
        };
        let capacity = bytes.next_multiple_of(granule);
        let layout = Layout::from_size_align(capacity, alignment.max(granule)).unwrap();
        // SAFETY: valid bounded fixture layout; null checked before use.
        let pointer = NonNull::new(unsafe { alloc(layout) }).ok_or(MemoryError::OutOfMemory)?;
        // SAFETY: unique unpublished allocation; deliberately nonzero payload
        // proves the region does not invent a zeroed-allocation guarantee.
        unsafe {
            pointer.as_ptr().write_bytes(0x5a, capacity);
        }
        let physical = (0..capacity / granule)
            .map(|index| s.next_physical + index as u64 * 2 * granule as u64)
            .collect();
        s.next_physical += (capacity as u64) * 2;
        PinnedPages::new(
            Box::new(Backing {
                pointer,
                layout,
                physical,
                shift: s.shift,
                attribute: s.attribute.unwrap_or(attribute),
                counts: self.counts.clone(),
            }),
            bytes,
            alignment.max(granule),
        )
    }
}
struct Domain {
    state: Arc<Mutex<State>>,
    counts: Arc<Counts>,
}
impl Drop for Domain {
    fn drop(&mut self) {
        assert!(
            self.state.lock().unwrap().bindings.is_empty(),
            "released remapper with live mappings"
        );
        self.counts.domains.fetch_add(1, Ordering::SeqCst);
    }
}
fn cpu(binding: &Binding, range: Range<usize>) -> NonNull<u8> {
    let pin = binding.pages.as_single().expect("single real reservation");
    pin.cpu_mapping(pin.cache_attribute())
        .unwrap()
        .address(range.start, range.len())
        .unwrap()
}
// SAFETY: exact private token, retained original pin/direction, unique IOVA
// reservations and acknowledged model removal; failures retain bindings. This
// independent peer executes actual CPU payload changes, not hardware IOTLBs.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let mut s = self.state.lock().unwrap();
        if s.fail_map {
            return Err(DmaError::MappingFailed);
        }
        let address = s.next_iova;
        let end = address
            .checked_add(pages.bytes() as u64)
            .ok_or(DmaError::AddressLimit)?;
        if end - 1 > limit {
            return Err(DmaError::AddressLimit);
        }
        let token = DomainMapping {
            id: s.next_id,
            address,
            bytes: pages.bytes(),
        };
        s.next_id += 1;
        s.next_iova = end;
        s.maps
            .push((token, direction, pages.physical_pages().to_vec()));
        s.bindings.insert(
            token.id,
            Binding {
                token,
                pages: pages.clone(),
                direction,
                visible: vec![0x11; pages.bytes()],
            },
        );
        Ok(token)
    }
    unsafe fn unmap(&self, token: DomainMapping) -> Result<(), DmaError> {
        let mut s = self.state.lock().unwrap();
        s.unmaps.push(token);
        if s.bindings.get(&token.id).is_none_or(|b| b.token != token) {
            return Err(DmaError::Unmapped);
        }
        if s.fail_unmap {
            return Err(DmaError::InvalidationFailed);
        }
        s.bindings.remove(&token.id);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        self.sync(token, range, direction, false)
    }
    unsafe fn sync_for_cpu(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        self.sync(token, range, direction, true)
    }
    unsafe fn read_coherent_u32(
        &self,
        token: DomainMapping,
        offset: usize,
        direction: Direction,
    ) -> Result<u32, DmaError> {
        let mut s = self.state.lock().unwrap();
        s.coherent_reads.push(offset);
        if !s.coherent {
            return Err(DmaError::CoherenceUnavailable);
        }
        let b = s.bindings.get(&token.id).ok_or(DmaError::Unmapped)?;
        if token != b.token || direction != b.direction {
            return Err(DmaError::MappingFailed);
        }
        let pointer = cpu(b, offset..offset + 4);
        // SAFETY: bounded aligned word from this exact retained token; fixture
        // coherence is independently enabled and all writers are serialized.
        Ok(u32::from_le(unsafe {
            pointer.as_ptr().cast::<u32>().read_volatile()
        }))
    }
}
impl Domain {
    fn sync(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        direction: Direction,
        for_cpu: bool,
    ) -> Result<(), DmaError> {
        let mut s = self.state.lock().unwrap();
        s.syncs.push((for_cpu, token, range.clone(), direction));
        if s.fail_sync == Some((for_cpu, false)) {
            return Err(DmaError::VisibilityFailed);
        }
        let after = s.fail_sync == Some((for_cpu, true));
        let b = s.bindings.get_mut(&token.id).ok_or(DmaError::Unmapped)?;
        if token != b.token || direction != b.direction || range.end > token.bytes {
            return Err(DmaError::InvalidRange);
        }
        let pointer = cpu(b, range.clone());
        // SAFETY: independent explicit cache peer copies only this token's
        // exact bounded range. Tests provide actual completed CPU/device turns.
        unsafe {
            if for_cpu {
                core::ptr::copy_nonoverlapping(
                    b.visible.as_ptr().add(range.start),
                    pointer.as_ptr(),
                    range.len(),
                );
            } else {
                core::ptr::copy_nonoverlapping(
                    pointer.as_ptr(),
                    b.visible.as_mut_ptr().add(range.start),
                    range.len(),
                );
            }
        }
        if after {
            Err(DmaError::VisibilityFailed)
        } else {
            Ok(())
        }
    }
    fn device_write(&self, address: u64, bytes: &[u8]) {
        let mut s = self.state.lock().unwrap();
        let coherent = s.coherent;
        let b = s
            .bindings
            .values_mut()
            .find(|b| {
                address >= b.token.address
                    && address + bytes.len() as u64 <= b.token.address + b.token.bytes as u64
            })
            .unwrap();
        assert!(matches!(
            b.direction,
            Direction::FromDevice | Direction::Bidirectional
        ));
        let offset = (address - b.token.address) as usize;
        b.visible[offset..offset + bytes.len()].copy_from_slice(bytes);
        if coherent {
            // SAFETY: peer translation resolves the actual original pin;
            // never dereference the numeric IOVA as a CPU pointer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    cpu(b, offset..offset + bytes.len()).as_ptr(),
                    bytes.len(),
                );
            }
        }
    }
    fn device_read(&self, address: u64, bytes: usize) -> Vec<u8> {
        let s = self.state.lock().unwrap();
        let b = s
            .bindings
            .values()
            .find(|b| {
                address >= b.token.address
                    && address + bytes as u64 <= b.token.address + b.token.bytes as u64
            })
            .unwrap();
        assert!(matches!(
            b.direction,
            Direction::ToDevice | Direction::Bidirectional
        ));
        let offset = (address - b.token.address) as usize;
        if !s.coherent {
            return b.visible[offset..offset + bytes].to_vec();
        }
        let mut result = vec![0; bytes];
        // SAFETY: same uniquely serialized peer translation and exact bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(
                cpu(b, offset..offset + bytes).as_ptr(),
                result.as_mut_ptr(),
                bytes,
            );
        }
        result
    }
}
struct Peer {
    source: Source,
    domain: Arc<Domain>,
    state: Arc<Mutex<State>>,
    counts: Arc<Counts>,
}
impl Peer {
    fn new(iova: u64) -> Self {
        let state = Arc::new(Mutex::new(State {
            next_iova: iova,
            next_id: 1,
            next_physical: 0x9000_0000,
            geometry: PageGeometry::base_only(12),
            shift: 12,
            attribute: None,
            requests: Vec::new(),
            bindings: BTreeMap::new(),
            maps: Vec::new(),
            unmaps: Vec::new(),
            syncs: Vec::new(),
            coherent_reads: Vec::new(),
            coherent: false,
            fail_allocate: false,
            short_allocate: false,
            fail_map: false,
            fail_unmap: false,
            fail_sync: None,
        }));
        let counts = Arc::new(Counts::default());
        Self {
            source: Source {
                state: state.clone(),
                counts: counts.clone(),
            },
            domain: Arc::new(Domain {
                state: state.clone(),
                counts: counts.clone(),
            }),
            state,
            counts,
        }
    }
    fn allocate(&self, bytes: usize, alignment: usize) -> Result<DmaRegion, Error> {
        DmaRegion::allocate(
            &self.source,
            self.domain.clone(),
            bytes,
            alignment,
            CacheAttribute::WriteBack,
            Direction::Bidirectional,
            u64::MAX,
        )
    }
}
fn retire(region: &mut DmaRegion) {
    // SAFETY: tests own all peer accesses; no engine, IRQ or callback can resume.
    unsafe { region.unmap() }.unwrap();
}

#[test]
fn nonidentity_aligned_view_uses_same_pin_offset_and_whole_original_retirement() {
    let p = Peer::new(0x1000);
    let mut r = p.allocate(8192, 8192).unwrap();
    assert_eq!(r.bytes(), 8192);
    assert_eq!(r.reserved_bytes(), 12288);
    assert_eq!(r.device_address(0, 8192), Ok(0x2000));
    assert_eq!(r.cache_attribute(), CacheAttribute::WriteBack);
    let cpu = r.cpu_address(0, 8).unwrap();
    assert_ne!(cpu.as_ptr() as u64, 0x2000);
    {
        let s = p.state.lock().unwrap();
        assert_eq!(s.requests, [(12288, 4096, CacheAttribute::WriteBack)]);
        assert_eq!(s.maps[0].0.address, 0x1000);
        assert_eq!(s.maps[0].2, [0x9000_0000, 0x9000_2000, 0x9000_4000]);
        let b = s.bindings.values().next().unwrap();
        assert_eq!(cpu.as_ptr(), self::cpu(b, 4096..4104).as_ptr());
    }
    // SAFETY: original CPU view is exclusively owned, not published to a device.
    unsafe {
        core::ptr::copy_nonoverlapping([1u8, 2, 3, 4, 5, 6, 7, 8].as_ptr(), cpu.as_ptr(), 8);
    }
    assert_eq!(p.domain.device_read(0x2000, 8), [0x11; 8]);
    r.sync_for_device(0..8).unwrap();
    assert_eq!(p.domain.device_read(0x2000, 8), [1, 2, 3, 4, 5, 6, 7, 8]);
    p.domain.device_write(0x2004, &[0xa1, 0xa2, 0xa3, 0xa4]);
    // SAFETY: modeled device transfer completed; exact range is now CPU-owned.
    unsafe { r.sync_for_cpu(4..8) }.unwrap();
    // SAFETY: exact completed CPU-owned word from the same view.
    assert_eq!(
        unsafe { cpu.as_ptr().add(4).cast::<u32>().read_unaligned() }.to_le(),
        0xa4a3_a2a1
    );
    {
        let s = p.state.lock().unwrap();
        assert_eq!(s.syncs[0].2, 4096..4104);
        assert_eq!(s.syncs[1].2, 4100..4104);
    }
    let domain: Arc<dyn DmaDomain> = p.domain.clone();
    assert!(r.belongs_to_domain(&domain));
    retire(&mut r);
    assert_eq!(r.device_address(0, 1), Err(Error::Dma(DmaError::Unmapped)));
    assert!(!r.belongs_to_domain(&domain));
    assert_eq!(
        p.state.lock().unwrap().unmaps[0],
        DomainMapping {
            id: 1,
            address: 0x1000,
            bytes: 12288
        }
    );
    assert_eq!(
        p.counts.pages.load(Ordering::SeqCst),
        0,
        "CPU pin survives removal"
    );
    assert_eq!(r.cpu_address(0, 8).unwrap(), cpu);
    drop(r);
    assert_eq!(p.counts.pages.load(Ordering::SeqCst), 1);
}

#[test]
fn every_4k_phase_selects_real_aligned_window_without_claiming_larger_granules() {
    for alignment in [1, 64, 4096, 8192, 16384, 65536] {
        for phase in (0..alignment.max(4096)).step_by(4096) {
            let p = Peer::new(0x10000 + phase as u64);
            let mut r = p.allocate(8192, alignment).unwrap();
            let address = r.device_address(0, r.bytes()).unwrap();
            assert!(address.is_multiple_of(alignment as u64));
            let s = p.state.lock().unwrap();
            let original = s.maps[0].0;
            let offset = (address - original.address) as usize;
            assert!(offset + r.bytes() <= original.bytes);
            assert_eq!(
                r.cpu_address(0, 1).unwrap(),
                cpu(s.bindings.get(&original.id).unwrap(), offset..offset + 1)
            );
            assert_eq!(s.requests[0].1, 4096, "no larger physical granule inferred");
            drop(s);
            retire(&mut r);
        }
    }
}

#[test]
fn layout_range_and_provider_refusals_precede_mapping_or_payload_effects() {
    for (bytes, alignment) in [
        (0, 4096),
        (1, 0),
        (1, 3),
        (usize::MAX, 4096),
        (isize::MAX as usize, 8192),
    ] {
        let p = Peer::new(0x1000);
        assert!(p.allocate(bytes, alignment).is_err());
        assert!(p.state.lock().unwrap().requests.is_empty());
        assert!(p.state.lock().unwrap().maps.is_empty());
    }
    let p = Peer::new(0x1000);
    p.state.lock().unwrap().geometry = Err(MemoryError::Unavailable);
    assert_eq!(
        p.allocate(8192, 8192).unwrap_err(),
        Error::Memory(MemoryError::Unavailable)
    );
    assert!(p.state.lock().unwrap().requests.is_empty());
    let p = Peer::new(0x1000);
    p.state.lock().unwrap().fail_allocate = true;
    assert_eq!(
        p.allocate(8192, 8192).unwrap_err(),
        Error::Memory(MemoryError::OutOfMemory)
    );
    assert!(p.state.lock().unwrap().maps.is_empty());
    let p = Peer::new(0x2000);
    p.state.lock().unwrap().short_allocate = true;
    assert_eq!(
        p.allocate(8192, 8192).unwrap_err(),
        Error::Memory(MemoryError::InvalidSize)
    );
    assert!(p.state.lock().unwrap().maps.is_empty());
    let p = Peer::new(0x1000);
    let mut r = p.allocate(8192, 8192).unwrap();
    for range in [
        8191..8193,
        Range { start: 5, end: 4 },
        usize::MAX..usize::MAX,
    ] {
        assert!(r.sync_for_device(range).is_err());
    }
    assert!(r.cpu_address(8192, 1).is_err());
    assert!(r.device_address(usize::MAX, 2).is_err());
    assert!(p.state.lock().unwrap().syncs.is_empty());
    retire(&mut r);
}

#[test]
fn wrong_cache_or_unadvertised_page_geometry_never_creates_a_mapping() {
    for geometry in [false, true] {
        let p = Peer::new(0x1000);
        if geometry {
            p.state.lock().unwrap().shift = 13;
        } else {
            p.state.lock().unwrap().attribute = Some(CacheAttribute::Uncached);
        }
        let error = p.allocate(8192, 8192).unwrap_err();
        assert_eq!(
            error,
            Error::Memory(if geometry {
                MemoryError::InvalidPageList
            } else {
                MemoryError::CacheAttributeUnavailable
            })
        );
        assert!(p.state.lock().unwrap().maps.is_empty());
        assert_eq!(p.counts.pages.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn fresh_insufficient_backing_removes_original_token_or_preserves_both_faults() {
    for fail in [false, true] {
        let p = Peer::new(0x1000);
        let pages = p
            .source
            .allocate(4096, 4096, CacheAttribute::WriteBack)
            .unwrap();
        p.state.lock().unwrap().fail_unmap = fail;
        let before = quarantine_status();
        let error = DmaRegion::map(
            pages,
            p.domain.clone(),
            4096,
            8192,
            Direction::Bidirectional,
            u64::MAX,
        )
        .unwrap_err();
        assert_eq!(
            error,
            if fail {
                Error::Cleanup {
                    rejected: LayoutError::InsufficientBacking,
                    failure: DmaError::InvalidationFailed,
                }
            } else {
                Error::Layout(LayoutError::InsufficientBacking)
            }
        );
        let s = p.state.lock().unwrap();
        assert_eq!(
            s.unmaps,
            [DomainMapping {
                id: 1,
                address: 0x1000,
                bytes: 4096
            }]
        );
        assert_eq!(s.bindings.len(), usize::from(fail));
        drop(s);
        assert_eq!(p.counts.pages.load(Ordering::SeqCst), usize::from(!fail));
        if fail {
            assert!(quarantine_status().mappings > before.mappings);
        }
    }
}

#[test]
fn whole_token_failed_unmap_retries_without_reuse_or_early_pin_release() {
    let p = Peer::new(0x1000);
    let mut r = p.allocate(8192, 8192).unwrap();
    p.state.lock().unwrap().fail_unmap = true;
    // SAFETY: peer engines/IRQ/work stopped; inject actual invalidation failure.
    assert_eq!(
        unsafe { r.unmap() },
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(r.device_address(0, 1), Ok(0x2000));
    assert_eq!(p.counts.pages.load(Ordering::SeqCst), 0);
    p.state.lock().unwrap().fail_unmap = false;
    retire(&mut r);
    let s = p.state.lock().unwrap();
    assert_eq!(s.unmaps.len(), 2);
    assert_eq!(s.unmaps[0], s.unmaps[1]);
    assert_eq!(s.maps.len(), 1);
    drop(s);
    drop(r);
    assert_eq!(p.counts.pages.load(Ordering::SeqCst), 1);
}

#[test]
fn sync_failures_before_or_after_real_cache_effects_keep_exact_region_owned() {
    for for_cpu in [false, true] {
        for after in [false, true] {
            let p = Peer::new(0x1000);
            let mut r = p.allocate(8192, 8192).unwrap();
            let pointer = r.cpu_address(0, 4).unwrap();
            // SAFETY: fresh unpublished CPU-owned word in retained fixture storage.
            unsafe {
                pointer.as_ptr().cast::<u32>().write(0x1234_5678u32.to_le());
            }
            p.domain.device_write(0x2000, &0x8765_4321u32.to_le_bytes());
            p.state.lock().unwrap().fail_sync = Some((for_cpu, after));
            let result = if for_cpu {
                // SAFETY: peer completed the actual modeled device write.
                unsafe { r.sync_for_cpu(0..4) }
            } else {
                r.sync_for_device(0..4)
            };
            assert_eq!(result, Err(Error::Dma(DmaError::VisibilityFailed)));
            assert_eq!(r.device_address(0, 4), Ok(0x2000));
            assert_eq!(p.counts.pages.load(Ordering::SeqCst), 0);
            if for_cpu {
                // SAFETY: exact completed fixture word; inspect cache operation's
                // before/after effect without treating an error as valid ownership.
                let word = unsafe { pointer.as_ptr().cast::<u32>().read() }.to_le();
                assert_eq!(word, if after { 0x8765_4321 } else { 0x1234_5678 });
            } else {
                assert_eq!(
                    p.domain.device_read(0x2000, 4),
                    if after {
                        0x1234_5678u32
                    } else {
                        0x8765_4321u32
                    }
                    .to_le_bytes()
                );
            }
            p.state.lock().unwrap().fail_sync = None;
            retire(&mut r);
        }
    }
}

#[test]
fn coherent_word_capability_is_actual_domain_specific_and_range_checked() {
    let p = Peer::new(0x1000);
    let mut r = p.allocate(8192, 8192).unwrap();
    assert_eq!(r.cache_attribute(), CacheAttribute::WriteBack);
    assert_eq!(
        r.read_coherent_u32(0),
        Err(Error::Dma(DmaError::CoherenceUnavailable))
    );
    p.state.lock().unwrap().coherent = true;
    p.domain.device_write(0x200c, &0xfeed_0001u32.to_le_bytes());
    assert_eq!(r.read_coherent_u32(12), Ok(0xfeed_0001));
    let reads = p.state.lock().unwrap().coherent_reads.len();
    for offset in [1, 8190, usize::MAX] {
        assert!(r.read_coherent_u32(offset).is_err());
    }
    assert_eq!(p.state.lock().unwrap().coherent_reads.len(), reads);
    let other = Peer::new(0x1000);
    let foreign: Arc<dyn DmaDomain> = other.domain.clone();
    assert!(
        !r.belongs_to_domain(&foreign),
        "matching numeric IOVA is not domain ownership"
    );
    retire(&mut r);
    let pages = p
        .source
        .allocate(4096, 4096, CacheAttribute::WriteBack)
        .unwrap();
    let mut transmit = DmaRegion::map(
        pages,
        p.domain.clone(),
        4096,
        4096,
        Direction::ToDevice,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(
        transmit.read_coherent_u32(0),
        Err(Error::Dma(DmaError::InvalidRange))
    );
    retire(&mut transmit);
}

#[test]
fn original_cache_and_nonzero_content_survive_direct_pin_mapping() {
    let p = Peer::new(0x2000);
    let pages = p
        .source
        .allocate(8192, 4096, CacheAttribute::Uncached)
        .unwrap();
    let mut r = DmaRegion::map(
        pages,
        p.domain.clone(),
        8192,
        8192,
        Direction::Bidirectional,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(r.cache_attribute(), CacheAttribute::Uncached);
    assert_eq!(
        r.reserved_bytes(),
        8192,
        "already aligned IOVA needs no hidden allocation"
    );
    // SAFETY: original fresh CPU-owned storage; mapping performs no payload write.
    assert_eq!(
        unsafe { r.cpu_address(0, 1).unwrap().as_ptr().read() },
        0x5a
    );
    retire(&mut r);
}

#[test]
fn rejected_mapping_or_limit_drops_unpublished_backing_and_active_drop_quarantines() {
    for map_error in [false, true] {
        let p = Peer::new(0x1000);
        p.state.lock().unwrap().fail_map = map_error;
        let limit = if map_error { u64::MAX } else { 0x1fff };
        assert!(
            DmaRegion::allocate(
                &p.source,
                p.domain.clone(),
                8192,
                8192,
                CacheAttribute::WriteBack,
                Direction::Bidirectional,
                limit
            )
            .is_err()
        );
        assert!(p.state.lock().unwrap().bindings.is_empty());
        assert_eq!(p.counts.pages.load(Ordering::SeqCst), 1);
    }
    let p = Peer::new(0x1000);
    let counts = p.counts.clone();
    let r = p.allocate(8192, 8192).unwrap();
    let before = quarantine_status();
    drop(p);
    drop(r);
    assert_eq!(counts.pages.load(Ordering::SeqCst), 0);
    assert_eq!(counts.domains.load(Ordering::SeqCst), 0);
    assert!(quarantine_status().mappings > before.mappings);
}
