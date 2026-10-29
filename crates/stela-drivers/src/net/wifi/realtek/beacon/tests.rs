use core::ptr::NonNull;
extern crate std;
use super::*;
use crate::bus::dma::{
    mapping::DomainMapping,
    memory::{CacheAttribute, PageBacking, PinnedPages},
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
    collections::BTreeMap,
    vec::Vec,
};
use core::{alloc::Layout, ops::Range};
use io::BeaconQueue;
use std::sync::Mutex;

struct Pages {
    pointer: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
}
// SAFETY: exclusively kept zeroed/aligned virtual RAM for a serialized
// hardware model, not privileged allocation or physical DMA proof.
unsafe impl Send for Pages {}
// SAFETY: no safe byte references or concurrent device access are exposed.
unsafe impl Sync for Pages {}
// SAFETY: `cpu_base` and `physical` describe the one kept, aligned test allocation for its
// whole life.
unsafe impl PageBacking for Pages {
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
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: the pointer came from the matching allocation with this layout and is freed
        // once.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}
pub(in crate::net::wifi::realtek) struct Source;
impl PageSource for Source {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let bytes_rounded = bytes.next_multiple_of(4096);
        let layout = Layout::from_size_align(bytes_rounded, alignment).unwrap();
        let pointer =
                // SAFETY: the layout has a nonzero size.
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
        let physical = (0..bytes_rounded / 4096)
            .map(|i| pointer.as_ptr() as u64 + i as u64 * 4096)
            .collect();
        PinnedPages::new(
            Box::new(Pages {
                pointer,
                layout,
                physical,
            }),
            bytes,
            alignment,
        )
    }
}
#[derive(Default)]
pub(in crate::net::wifi::realtek) struct Model {
    next: u64,
    pub(in crate::net::wifi::realtek) mappings: BTreeMap<u64, (PinnedPages, usize)>,
    pub(in crate::net::wifi::realtek) directions: BTreeMap<u64, Direction>,
    base: u32,
    pub(in crate::net::wifi::realtek) syncs: usize,
    pub(in crate::net::wifi::realtek) cpu_syncs: usize,
    unmaps: usize,
    drops: usize,
    fail_configure: bool,
    fail_kick: bool,
    pub(in crate::net::wifi::realtek) fail_unmap: bool,
    fail_cpu_sync: bool,
    pub(in crate::net::wifi::realtek) fail_cpu_sync_at: Option<usize>,
    pub(in crate::net::wifi::realtek) fail_sync_at: Option<usize>,
    pub(in crate::net::wifi::realtek) address_overflow: bool,
    packets: Vec<Vec<u8>>,
    buffers: Vec<Vec<u8>>,
}
pub(in crate::net::wifi::realtek) struct Domain(
    pub(in crate::net::wifi::realtek) Arc<Mutex<Model>>,
);
// SAFETY: pinned allocations are held, while IOVA translation
// and cache visibility are serialized model events, never hardware claims.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &crate::bus::dma::pages::DmaPages,
        direction: Direction,
        _limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let pages = pages.as_single().ok_or(DmaError::MappingFailed)?;
        let mut m = self.0.lock().unwrap();
        m.next += 0x10000;
        let address = if m.address_overflow {
            0x1_0000_0000 + m.next
        } else {
            0x1000_0000 + m.next
        };
        let ptr = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .unwrap()
            .address(0, pages.bytes())
            .unwrap()
            .as_ptr() as usize;
        assert_ne!(address, pages.physical_pages()[0]);
        m.mappings.insert(address, (pages.clone(), ptr));
        m.directions.insert(address, direction);
        Ok(DomainMapping {
            id: address,
            address,
            bytes: pages.bytes(),
        })
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        let mut m = self.0.lock().unwrap();
        m.unmaps += 1;
        if m.fail_unmap {
            return Err(DmaError::InvalidationFailed);
        }
        m.mappings.remove(&mapping.id).ok_or(DmaError::Unmapped)?;
        m.directions.remove(&mapping.id);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut m = self.0.lock().unwrap();
        assert_eq!(m.directions[&mapping.id], direction);
        assert!(m.mappings.contains_key(&mapping.id));
        assert!(range.end <= mapping.bytes);
        m.syncs += 1;
        if m.fail_sync_at == Some(m.syncs) {
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
        let mut m = self.0.lock().unwrap();
        assert_eq!(m.directions[&mapping.id], direction);
        assert!(matches!(
            direction,
            Direction::Bidirectional | Direction::FromDevice
        ));
        assert!(range.start < range.end && range.end <= mapping.bytes);
        m.cpu_syncs += 1;
        if m.fail_cpu_sync || m.fail_cpu_sync_at == Some(m.cpu_syncs) {
            Err(DmaError::VisibilityFailed)
        } else {
            Ok(())
        }
    }
}
struct ModelRegisters(Arc<Mutex<Model>>);
// SAFETY: modeled registers publish the model's native-DMA IOVA,
// resolve its pin and record the device's descriptor/payload read.
unsafe impl Registers for ModelRegisters {
    fn configure(&mut self, iova: u32) -> Result<(), Error> {
        let mut m = self.0.lock().unwrap();
        m.base = iova;
        if m.fail_configure {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }
    fn kick(&mut self) -> Result<(), Error> {
        let mut m = self.0.lock().unwrap();
        let (_, base) = m.mappings.get(&u64::from(m.base)).unwrap();
        let base = *base;
        assert_eq!(m.directions[&u64::from(m.base)], Direction::Bidirectional);
        // SAFETY: model DMA follows a mapping into the
        // live native allocation; serialized kick owns the device read.
        let bd = unsafe { core::slice::from_raw_parts(base as *const u8, 16) }.to_vec();
        let packet_iova = u32::from_le_bytes(bd[4..8].try_into().unwrap());
        let (_, packet_base) = m.mappings.get(&u64::from(packet_iova)).unwrap();
        assert_eq!(m.directions[&u64::from(packet_iova)], Direction::ToDevice);
        let length = u16::from_le_bytes(bd[8..10].try_into().unwrap()) as usize;
        let data_iova = u32::from_le_bytes(bd[12..16].try_into().unwrap());
        assert_eq!(data_iova, packet_iova + 48);
        let packet =
                // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
                // nothing accesses it concurrently.
                unsafe { core::slice::from_raw_parts(*packet_base as *const u8, length + 48) }
                    .to_vec();
        m.packets.push(packet);
        let updated_psb = u16::from_le_bytes(bd[2..4].try_into().unwrap()) & 0x7fff;
        m.buffers.push(bd);
        // Model a permitted device OWN writeback. The native slot must
        // return descriptor ownership through bidirectional visibility
        // before CPU reuse, even though it never reads the OWN field.
        // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
        // nothing accesses it concurrently.
        unsafe { ((base + 2) as *mut u16).write_volatile(updated_psb.to_le()) };
        if m.fail_kick {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }
}
impl Drop for ModelRegisters {
    fn drop(&mut self) {
        self.0.lock().unwrap().drops += 1;
    }
}
fn install(m: &Arc<Mutex<Model>>) -> Result<Beacon<ModelRegisters>, Error> {
    // SAFETY: synchronous stopped model with kept pins and separate
    // model IOVA addresses; no privileged DMA effects are claimed.
    unsafe {
        Beacon::install(
            ModelRegisters(m.clone()),
            &Source,
            Arc::new(Domain(m.clone())),
            FirmwareBand::Ghz2,
        )
    }
}
/// Cross-module integration fixture reuses this native queue, pin
/// allocator and domain model; no duplicate queue/descriptor substitute.
pub(in crate::net::wifi::realtek) struct Harness {
    model: Arc<Mutex<Model>>,
    queue: Beacon<ModelRegisters>,
}
impl Harness {
    pub(in crate::net::wifi::realtek) fn new() -> Self {
        let model = Arc::new(Mutex::new(Model::default()));
        let queue = install(&model).unwrap();
        Self { model, queue }
    }
    pub(in crate::net::wifi::realtek) fn packets(&self) -> Vec<Vec<u8>> {
        self.model.lock().unwrap().packets.clone()
    }
    pub(in crate::net::wifi::realtek) fn mappings(&self) -> usize {
        self.model.lock().unwrap().mappings.len()
    }
    pub(in crate::net::wifi::realtek) fn pending(&self) -> bool {
        self.queue.pending()
    }
    pub(in crate::net::wifi::realtek) unsafe fn stop(&mut self) {
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { self.queue.release_after_stop() }.unwrap();
    }
}
// SAFETY: same synchronous model proof as this module's queue fixture;
// forwarding keeps the native slot's ownership checks/lifetimes.
unsafe impl BeaconQueue for Harness {
    fn submit(&mut self, data: &[u8]) -> Result<(), io::Error> {
        self.queue.submit(data)
    }
    unsafe fn consumed(&mut self) -> Result<(), io::Error> {
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { self.queue.consumed() }
    }
    fn quarantine(&mut self) {
        self.queue.quarantine();
    }
}
#[test]
fn dma_uses_domain_iovas_and_reuse_requires_actual_source_completion_proof() {
    let m = Arc::new(Mutex::new(Model::default()));
    let mut queue = install(&m).unwrap();
    let data: Vec<u8> = (0..4096).map(|i| i as u8).collect();
    queue.enqueue(&data).unwrap();
    assert!(queue.pending());
    assert_eq!(queue.enqueue(&[0; 8]), Err(Error::Pending));
    {
        let state = m.lock().unwrap();
        assert_eq!(&state.packets[0][48..], data);
        assert_eq!(state.buffers[0][..4], [48, 0, 33, 128]);
        assert_eq!(state.base, 0x1001_0000);
        assert_eq!(state.syncs, 3);
    }
    // SAFETY: this model's kick read the complete mapped packet;
    // stands for Download's newly observed real BCN_VALID, not submit ACK.
    unsafe { queue.consumed() }.unwrap();
    assert_eq!(m.lock().unwrap().cpu_syncs, 1);
    assert!(!queue.pending());
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    assert_eq!(unsafe { queue.consumed() }, Err(io::Error::Queue));
    queue.enqueue(&[0xff; 8]).unwrap();
    assert_eq!(m.lock().unwrap().packets.len(), 2);
    // SAFETY: model has no asynchronous DMA, all reads and workers ended.
    unsafe { queue.release_after_stop() }.unwrap();
    assert_eq!(queue.enqueue(&data), Err(Error::Quarantined));
    drop(queue);
    let state = m.lock().unwrap();
    assert!(state.mappings.is_empty());
    assert_eq!(state.unmaps, 2);
    assert_eq!(state.drops, 1);
}
#[test]
fn publication_visibility_and_teardown_failures_retain_the_real_queue_owner() {
    for mode in 0..6 {
        let m = Arc::new(Mutex::new(Model::default()));
        {
            let mut s = m.lock().unwrap();
            match mode {
                0 => s.fail_configure = true,
                1 => s.fail_kick = true,
                2 => s.fail_sync_at = Some(2),
                3 => s.fail_sync_at = Some(3),
                4 => s.fail_unmap = true,
                _ => (),
            }
        }
        let installed = install(&m);
        if mode == 0 {
            assert!(matches!(installed, Err(Error::Register)));
        } else {
            let mut queue = installed.unwrap();
            if mode == 1 || mode == 2 || mode == 3 {
                assert!(queue.enqueue(&[1; 128]).is_err());
                assert!(queue.quarantined());
                assert!(queue.last_error().is_some());
            } else {
                queue.enqueue(&[1; 128]).unwrap();
                if mode == 4 {
                    assert_eq!(
                        // SAFETY: modeled device stopped; IOTLB removal fails.
                        unsafe { queue.release_after_stop() },
                        Err(Error::Dma(DmaError::InvalidationFailed))
                    );
                }
            }
            drop(queue);
        }
        let state = m.lock().unwrap();
        assert_eq!(state.drops, 0, "mode {mode}: active claim must stay live");
        assert!(state.mappings.contains_key(&0x1001_0000));
        if mode != 0 && mode != 2 {
            assert_eq!(state.mappings.len(), 2);
        } else {
            assert_eq!(state.mappings.len(), 1);
        }
    }
}
#[test]
fn unpublished_allocation_failures_and_high_iovas_do_not_claim_or_leak_a_queue() {
    for overflow in [false, true] {
        let m = Arc::new(Mutex::new(Model::default()));
        if overflow {
            m.lock().unwrap().address_overflow = true;
        } else {
            m.lock().unwrap().fail_sync_at = Some(1);
        }
        assert!(install(&m).is_err());
        let state = m.lock().unwrap();
        assert_eq!(state.base, 0);
        assert_eq!(state.drops, 1);
        assert!(state.mappings.is_empty());
    }
}
#[test]
fn failed_descriptor_completion_visibility_cannot_return_cpu_ownership() {
    let m = Arc::new(Mutex::new(Model::default()));
    let mut queue = install(&m).unwrap();
    queue.enqueue(&[0; 128]).unwrap();
    m.lock().unwrap().fail_cpu_sync = true;
    // SAFETY: synchronous modeled device finished its payload read and
    // descriptor writeback; visibility operation itself still fails.
    assert_eq!(unsafe { queue.consumed() }, Err(io::Error::Queue));
    assert!(queue.pending());
    assert!(queue.quarantined());
    assert_eq!(
        queue.last_error(),
        Some(Error::Dma(DmaError::VisibilityFailed))
    );
    assert_eq!(queue.enqueue(&[1; 128]), Err(Error::Quarantined));
    drop(queue);
    let state = m.lock().unwrap();
    assert_eq!(state.cpu_syncs, 1);
    assert_eq!(state.mappings.len(), 2);
    assert_eq!(state.drops, 0);
}
#[test]
fn source_packet_bounds_psb_rounding_multicast_and_band_fields_are_preserved() {
    for band in [FirmwareBand::Ghz2, FirmwareBand::Ghz5] {
        for (size, expected_psb) in [
            (8, 0x8001),
            (80, 0x8001),
            (81, 0x8002),
            (208, 0x8002),
            (209, 0x8003),
            (4096, 0x8021),
        ] {
            let mut data = vec![0; size];
            for multicast in [false, true] {
                data[4] = multicast.into();
                let (packet, buffer) = descriptors(&data, 0x1234_0000, band).unwrap();
                let w0 = u32::from_le_bytes(packet[..4].try_into().unwrap());
                assert_eq!(w0 & 0xffff, size as u32);
                assert_eq!((w0 >> 24) & 1, u32::from(multicast));
                assert_eq!(&packet[40..], &[0; 8]);
                assert_eq!(&packet[12..16], &[0, 5, 0, 0]);
                assert_eq!(&packet[32..36], &[0, 128, 0, 0]);
                let (rate_id, rate) = match band {
                    FirmwareBand::Ghz2 => (8, 0),
                    FirmwareBand::Ghz5 => (7, 4),
                };
                assert_eq!(&packet[4..8], &[0, 16, rate_id, 0]);
                assert_eq!(&packet[16..20], &[rate, 0, 0, 0]);
                assert_eq!(
                    u16::from_le_bytes(buffer[2..4].try_into().unwrap()),
                    expected_psb
                );
            }
        }
    }
    for size in [0, 1, 7, 4097] {
        assert_eq!(
            descriptors(&vec![0; size], 0x1000, FirmwareBand::Ghz2),
            Err(Error::InvalidLength)
        );
    }
    assert_eq!(
        descriptors(&[0; 8], u32::MAX - 54, FirmwareBand::Ghz2),
        Err(Error::Address)
    );
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_BEACON_ORACLE"]
fn every_length_band_and_multicast_descriptor_matches_unchanged_c_helpers() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_BEACON_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for band in [FirmwareBand::Ghz2, FirmwareBand::Ghz5] {
        for size in 8..=4096 {
            for multicast in [0, 1] {
                let mut data: Vec<u8> = (0..size).map(|i| i as u8).collect();
                data[4] = multicast;
                let (packet, buffer) = descriptors(&data, 0x1234_0000, band).unwrap();
                assert_eq!(
                    packet.as_slice(),
                    &trace[offset..offset + 48],
                    "{band:?} size={size} multicast={multicast}"
                );
                assert_eq!(
                    buffer.as_slice(),
                    &trace[offset + 48..offset + 64],
                    "{band:?} size={size} multicast={multicast}"
                );
                offset += 64;
            }
        }
    }
    assert_eq!(offset, trace.len());
}
