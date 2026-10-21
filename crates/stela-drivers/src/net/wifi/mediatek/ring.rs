// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
// Copyright (C) 2020-2023 MediaTek Inc.
//! PCIe WFDMA raw-command TX rings from mt76 dma.c. Descriptor/payload RAM
//! uses canonical native pins and IOMMU leases; no CPU or physical address is
//! substituted for a device IOVA. Completion here releases DMA ownership,
//! never implies an over-the-air packet acknowledgement or a ready radio.
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DmaMapping},
        memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
    },
    mmio::Mmio,
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering, fence},
};

pub mod rx;

const DESC_BYTES: usize = 16;
const DONE: u32 = 1 << 31;
const LAST: u32 = 1 << 30;
const MAX_COUNT: usize = 256;
const MAX_PAYLOAD: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Memory(MemoryError),
    Dma(DmaError),
    InvalidSize,
    Full,
    EmptyPayload,
    Poisoned,
    RegisterFailure,
    InvalidDeviceIndex,
    OwnershipMismatch,
    InvalidDeviceLength,
    UnsupportedDescriptor,
    ReceiveChainLimit,
}
impl From<MemoryError> for Error {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}
impl From<DmaError> for Error {
    fn from(e: DmaError) -> Self {
        Self::Dma(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek WFDMA TX: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Exactly one owned queue register block. Queue installation requires a
/// quiescent WFDMA engine; an acknowledged engine stop/reset is also required
/// before unmapping a ring. Queue register readback alone is not that proof.
///
/// # Safety
/// Implementors must own the actual selected PCI requester and mapped queue
/// registers for this object's lifetime. `device_index` must be an actual
/// volatile hardware read and `publish` an ordered MMIO doorbell after prior
/// DMA visibility operations; successful writes are completed register stores.
/// Errors may be uncertain and must never manufacture a completion index.
/// No competing firmware, OS, IRQ worker or reset path may access this queue.
pub unsafe trait QueueIo: 'static {
    fn configure(&mut self, address: u32, count: u16) -> Result<(), Error>;
    fn device_index(&mut self) -> Result<u16, Error>;
    fn publish(&mut self, head: u16) -> Result<(), Error>;
}

/// Native queue MMIO, retaining the actual owned BAR/requester context.
/// Construct it only after PCI ownership, full BAR bounds and UC mapping are
/// established. This is not a PCI function claim or an interrupt allocation.
pub struct MmioQueue {
    registers: Mmio,
    _owner: Arc<dyn core::any::Any>,
}
impl MmioQueue {
    /// # Safety
    /// `window` names the four actual uncached queue registers of the claimed
    /// requester. `owner` must retain the real exclusive PCI function claim
    /// and BAR mapping/reservation through its final Drop; the window remains
    /// mapped and excludes competing accesses for that entire lifetime.
    /// No unrelated token or owner whose Drop releases another reservation
    /// meets this contract. Uncertain ring Drop deliberately retains this Arc.
    pub unsafe fn from_window(window: NonNull<[u32; 4]>, owner: Arc<dyn core::any::Any>) -> Self {
        Self {
            registers: unsafe { Mmio::new(window.as_ptr().cast::<u32>() as u64) },
            _owner: owner,
        }
    }
}
// SAFETY: construction requires the actual exclusive mapped queue window;
// volatile accesses use the donor's exact four-register offsets.
unsafe impl QueueIo for MmioQueue {
    fn configure(&mut self, address: u32, count: u16) -> Result<(), Error> {
        self.registers.write32(8, 0);
        self.registers.write32(12, 0);
        self.registers.write32(4, u32::from(count));
        self.registers.write32(0, address);
        if self.registers.read32(4) != u32::from(count) || self.registers.read32(0) != address {
            return Err(Error::RegisterFailure);
        }
        Ok(())
    }
    fn device_index(&mut self) -> Result<u16, Error> {
        let index = self.registers.read32(12);
        u16::try_from(index).map_err(|_| Error::InvalidDeviceIndex)
    }
    fn publish(&mut self, head: u16) -> Result<(), Error> {
        self.registers.write32(8, u32::from(head));
        Ok(())
    }
}

struct Allocation {
    cpu: CpuMapping,
    dma: DmaMapping,
    published: bool,
    unmapped: bool,
}
impl Allocation {
    fn new(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        direction: Direction,
    ) -> Result<Self, Error> {
        // The unsafe installer requires actual hardware-coherent WB DMA for
        // this requester, with NoSnoop/ATS disabled. WB alone proves nothing.
        let pages = source.allocate(bytes, 4096, CacheAttribute::WriteBack)?;
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack)?;
        let dma = DmaMapping::map(domain, pages, direction, u32::MAX.into())?;
        Ok(Self {
            cpu,
            dma,
            published: false,
            unmapped: false,
        })
    }
    fn address(&self) -> Result<u32, Error> {
        u32::try_from(self.dma.address()?).map_err(|_| Error::OwnershipMismatch)
    }
    fn pointer(&self, at: usize, bytes: usize) -> Result<*mut u8, Error> {
        Ok(self.cpu.address(at, bytes)?.as_ptr())
    }
    fn write32(&self, at: usize, value: u32) -> Result<(), Error> {
        let ptr = self.pointer(at, 4)?.cast::<u32>();
        // SAFETY: bounded aligned qualified-coherent WB allocation, serialized ring owner, descriptor
        // is CPU-owned when written; no Rust reference aliases a device access.
        unsafe { ptr.write_volatile(value.to_le()) };
        Ok(())
    }
    fn read32(&self, at: usize) -> Result<u32, Error> {
        let ptr = self.pointer(at, 4)?.cast::<u32>();
        // SAFETY: bounded aligned qualified-coherent WB descriptor polling.
        Ok(u32::from_le(unsafe { ptr.read_volatile() }))
    }
    unsafe fn release(&mut self) -> Result<(), Error> {
        if self.unmapped {
            return Ok(());
        }
        // SAFETY: caller proves all queue access stopped and DMA completed/reset.
        unsafe { self.dma.unmap()? };
        self.published = false;
        self.unmapped = true;
        Ok(())
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.published && !self.unmapped {
            // SAFETY: unpublished allocations were never exposed to the requester;
            // unmap failures remain retained by DmaMapping's quarantine Drop.
            let _ = unsafe { self.dma.unmap() };
        }
    }
}
struct Slot {
    data: Allocation,
    pending: Option<(u64, usize)>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub cookie: u64,
    pub bytes: usize,
}

/// One raw WFDMA TX queue. Payload buffers and descriptors remain pinned and
/// mapped across all submissions and are quarantined on Drop until explicit
/// acknowledged quiescence. This queue reserves two entries as donor raw TX.
pub struct TxRing<Q: QueueIo> {
    io: Option<Q>,
    descriptors: Allocation,
    slots: Vec<Slot>,
    head: usize,
    tail: usize,
    queued: usize,
    poisoned: bool,
    released: bool,
}
impl<Q: QueueIo> TxRing<Q> {
    /// # Safety
    /// The caller must hold exclusive PCI/WFDMA ownership, with the actual TX
    /// engine disabled and idle before queue register mutation, and retain it
    /// through this ring's destruction/quarantine. `domain` must belong to that
    /// same requester. Ordinary WB DMA must be genuinely cache coherent for
    /// volatile completion polling on this exact platform/requester, with PCIe
    /// NoSnoop and ATS disabled. A WB cache attribute or compiler fence alone
    /// is not that proof. This qualification must remain true until acknowledged
    /// quiescence and final unmap, including every quarantined mapping.
    /// Polling mode must keep device IRQ sources masked and
    /// exclude every other submit/cleanup/reset owner.
    pub unsafe fn install(
        io: Q,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        count: usize,
    ) -> Result<Self, Error> {
        if !(4..=MAX_COUNT).contains(&count) || !count.is_power_of_two() {
            return Err(Error::InvalidSize);
        }
        let descriptors = Allocation::new(
            source,
            domain.clone(),
            count * DESC_BYTES,
            Direction::Bidirectional,
        )?;
        let mut slots = Vec::with_capacity(count);
        for i in 0..count {
            descriptors.write32(i * DESC_BYTES + 4, DONE)?;
            slots.push(Slot {
                data: Allocation::new(source, domain.clone(), MAX_PAYLOAD, Direction::ToDevice)?,
                pending: None,
            });
        }
        descriptors.dma.sync_for_device(0..count * DESC_BYTES)?;
        let base = descriptors.address()?;
        let mut ring = Self {
            io: Some(io),
            descriptors,
            slots,
            head: 0,
            tail: 0,
            queued: 0,
            poisoned: true,
            released: false,
        };
        // Construct the guard before the first potentially publishing store.
        // Any later error retains both Q's actual requester/BAR owner and DMA.
        ring.descriptors.published = true;
        ring.io
            .as_mut()
            .expect("retained queue")
            .configure(base, count as u16)?;
        if ring.io.as_mut().expect("retained queue").device_index()? != 0 {
            return Err(Error::InvalidDeviceIndex);
        }
        ring.poisoned = false;
        Ok(ring)
    }

    pub fn pending(&self) -> usize {
        self.queued
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    /// Submit one complete MCU/headerless-scatter transfer. `Ok` means queued,
    /// not completed; the caller must retain its command epoch until completion.
    pub fn submit(&mut self, cookie: u64, payload: &[u8]) -> Result<(), Error> {
        if self.poisoned || self.released {
            return Err(Error::Poisoned);
        }
        if payload.is_empty() {
            return Err(Error::EmptyPayload);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::InvalidSize);
        }
        if self.queued + 1 >= self.slots.len() - 1 {
            return Err(Error::Full);
        }
        let result = self.submit_inner(cookie, payload);
        if result.is_err() {
            self.poisoned = true
        }
        result
    }
    fn submit_inner(&mut self, cookie: u64, payload: &[u8]) -> Result<(), Error> {
        let slot = &mut self.slots[self.head];
        if slot.pending.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let pointer = slot.data.pointer(0, payload.len())?;
        // SAFETY: this slot is CPU-owned and contains distinct pinned RAM; the
        // borrowed caller bytes cannot alias this private allocation.
        unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), pointer, payload.len()) };
        slot.data.dma.sync_for_device(0..payload.len())?;
        // The first descriptor store can expose a prefetchable payload address.
        slot.data.published = true;
        slot.pending = Some((cookie, payload.len()));
        let at = self.head * DESC_BYTES;
        self.descriptors.write32(at, slot.data.address()?)?;
        self.descriptors.write32(at + 8, 0)?;
        self.descriptors.write32(at + 12, 0)?;
        self.descriptors
            .write32(at + 4, LAST | ((payload.len() as u32) << 16))?;
        self.descriptors.dma.sync_for_device(at..at + DESC_BYTES)?;
        self.queued += 1;
        self.head = (self.head + 1) % self.slots.len();
        fence(Ordering::SeqCst);
        self.io
            .as_mut()
            .expect("retained queue")
            .publish(self.head as u16)
    }
    /// Read the actual hardware DMA index and release at most one completed
    /// transfer. Enqueue or software head progression never grants CPU ownership.
    pub fn poll(&mut self) -> Result<Option<Completion>, Error> {
        if self.poisoned || self.released {
            return Err(Error::Poisoned);
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.poisoned = true
        }
        result
    }
    fn poll_inner(&mut self) -> Result<Option<Completion>, Error> {
        let count = self.slots.len();
        let actual = usize::from(self.io.as_mut().expect("retained queue").device_index()?);
        if actual >= count {
            return Err(Error::InvalidDeviceIndex);
        }
        let advanced = (actual + count - self.tail) % count;
        if advanced > self.queued {
            return Err(Error::InvalidDeviceIndex);
        }
        if advanced == 0 {
            return Ok(None);
        }
        fence(Ordering::SeqCst);
        let descriptor = self.tail * DESC_BYTES;
        // SAFETY: the observed actual hardware DMA index passed this entry,
        // completing descriptor fetch/writeback for this exact queue slot.
        unsafe {
            self.descriptors
                .dma
                .sync_for_cpu(descriptor..descriptor + DESC_BYTES)?
        };
        let slot = &mut self.slots[self.tail];
        let (cookie, bytes) = slot.pending.ok_or(Error::OwnershipMismatch)?;
        // Actual DMA index passed this slot; the requester has completed reads.
        unsafe { slot.data.dma.sync_for_cpu(0..bytes)? };
        slot.pending = None;
        self.tail = (self.tail + 1) % count;
        self.queued -= 1;
        Ok(Some(Completion { cookie, bytes }))
    }
    /// # Safety
    /// The actual owning controller must have disabled submissions and IRQs,
    /// drained workers, and observed acknowledged WFDMA idle/reset such that no
    /// current or stale device access can touch any queue or payload mapping.
    /// Software timeout, disabled PCI command bit or a write without readback
    /// is not this proof. Failed unmaps retain/quarantine remaining mappings.
    pub unsafe fn release_after_quiesce(&mut self) -> Result<(), Error> {
        self.poisoned = true;
        for slot in &mut self.slots {
            // SAFETY: caller's full hardware/worker quiescence covers every slot.
            unsafe { slot.data.release()? };
            slot.pending = None;
        }
        // SAFETY: the same quiescence covers descriptor fetch/writeback.
        unsafe { self.descriptors.release()? };
        self.queued = 0;
        self.released = true;
        Ok(())
    }
}

static QUARANTINED_QUEUES: AtomicU64 = AtomicU64::new(0);
/// Cumulative owned queue/BAR/requester contexts retained after uncertain
/// publication or Drop. This does not claim hardware reset or reclamation.
pub fn quarantined_queues() -> u64 {
    QUARANTINED_QUEUES.load(Ordering::Relaxed)
}
fn retain_queue<Q>(io: Option<Q>) {
    if let Some(io) = io {
        let _ = QUARANTINED_QUEUES.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            Some(n.saturating_add(1))
        });
        core::mem::forget(io);
    }
}
impl<Q: QueueIo> Drop for TxRing<Q> {
    fn drop(&mut self) {
        if self.descriptors.published && !self.released {
            retain_queue(self.io.take());
        }
    }
}

#[cfg(test)]
pub(in crate::net::wifi::mediatek) mod tests {
    extern crate std;
    use super::*;
    use crate::bus::dma::{
        mapping::DomainMapping,
        memory::{PageBacking, PinnedPages},
    };
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
        collections::BTreeMap,
    };
    use core::{alloc::Layout, ops::Range};
    use std::sync::Mutex;
    struct Pages {
        ptr: NonNull<u8>,
        layout: Layout,
        pages: Vec<u64>,
    }
    // SAFETY: model-owned aligned RAM; immutable allocation metadata. Only the
    // serialized state model uses raw pointers; this is not physical DMA proof.
    unsafe impl Send for Pages {}
    // SAFETY: same model allocation rule; no concurrently exposed Rust slices.
    unsafe impl Sync for Pages {}
    // SAFETY: model allocation retains its owned zeroed RAM and mapping until
    // Drop; modeled physical pages are distinct from modeled IOVA addresses.
    unsafe impl PageBacking for Pages {
        fn cpu_base(&self) -> NonNull<u8> {
            self.ptr
        }
        fn physical_pages(&self) -> &[u64] {
            &self.pages
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
            unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
        }
    }
    pub(in crate::net::wifi::mediatek) struct Source;
    impl PageSource for Source {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            assert_eq!(attribute, CacheAttribute::WriteBack);
            let n = bytes.next_multiple_of(4096);
            let layout = Layout::from_size_align(n, alignment).unwrap();
            let ptr =
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
            let pages = (0..n / 4096)
                .map(|i| ptr.as_ptr() as u64 + i as u64 * 4096)
                .collect();
            PinnedPages::new(Box::new(Pages { ptr, layout, pages }), bytes, alignment)
        }
    }
    #[derive(Default)]
    pub(in crate::net::wifi::mediatek) struct Memory {
        pub(in crate::net::wifi::mediatek) next: u64,
        pub(in crate::net::wifi::mediatek) mappings: BTreeMap<u64, (PinnedPages, usize, Direction)>,
        pub(in crate::net::wifi::mediatek) fail_unmap: bool,
        pub(in crate::net::wifi::mediatek) fail_unmap_at: Option<usize>,
        pub(in crate::net::wifi::mediatek) unmaps: usize,
        pub(in crate::net::wifi::mediatek) fail_sync_at: Option<usize>,
        pub(in crate::net::wifi::mediatek) syncs: Vec<(bool, u64, Range<usize>)>,
    }
    #[derive(Default)]
    pub(in crate::net::wifi::mediatek) struct State {
        pub(in crate::net::wifi::mediatek) memory: Arc<Mutex<Memory>>,
        pub(in crate::net::wifi::mediatek) base: u64,
        pub(in crate::net::wifi::mediatek) count: u16,
        pub(in crate::net::wifi::mediatek) head: u16,
        pub(in crate::net::wifi::mediatek) index: u16,
        pub(in crate::net::wifi::mediatek) queue_drops: usize,
        pub(in crate::net::wifi::mediatek) fail_publish: bool,
        pub(in crate::net::wifi::mediatek) fail_configure: bool,
        pub(in crate::net::wifi::mediatek) invalid_index: bool,
        pub(in crate::net::wifi::mediatek) completed: Vec<Vec<u8>>,
    }
    pub(in crate::net::wifi::mediatek) struct Domain(
        pub(in crate::net::wifi::mediatek) Arc<Mutex<Memory>>,
    );
    // SAFETY: this domain is a stateful test IOVA/page-pin map, not a claim of
    // privileged IOMMU effects. It retains pins and serializes every access.
    unsafe impl DmaDomain for Domain {
        unsafe fn map(
            &self,
            pages: &PinnedPages,
            direction: Direction,
            limit: u64,
        ) -> Result<DomainMapping, DmaError> {
            let mut s = self.0.lock().unwrap();
            s.next += 0x10000;
            let address = 0x10000000 + s.next;
            assert!(address + pages.bytes() as u64 - 1 <= limit);
            let pointer = pages
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap()
                .address(0, pages.bytes())
                .unwrap()
                .as_ptr() as usize;
            s.mappings
                .insert(address, (pages.clone(), pointer, direction));
            Ok(DomainMapping {
                id: address,
                address,
                bytes: pages.bytes(),
            })
        }
        unsafe fn unmap(&self, m: DomainMapping) -> Result<(), DmaError> {
            let mut s = self.0.lock().unwrap();
            s.unmaps += 1;
            if s.fail_unmap || s.fail_unmap_at == Some(s.unmaps) {
                return Err(DmaError::InvalidationFailed);
            }
            s.mappings.remove(&m.id).ok_or(DmaError::Unmapped)?;
            Ok(())
        }
        unsafe fn sync_for_device(
            &self,
            m: DomainMapping,
            range: Range<usize>,
            direction: Direction,
        ) -> Result<(), DmaError> {
            let mut s = self.0.lock().unwrap();
            assert_eq!(s.mappings[&m.id].2, direction);
            assert!(range.start <= range.end && range.end <= m.bytes);
            s.syncs.push((false, m.id, range));
            if s.fail_sync_at == Some(s.syncs.len()) {
                return Err(DmaError::VisibilityFailed);
            }
            Ok(())
        }
        unsafe fn sync_for_cpu(
            &self,
            m: DomainMapping,
            range: Range<usize>,
            direction: Direction,
        ) -> Result<(), DmaError> {
            let mut s = self.0.lock().unwrap();
            assert_eq!(s.mappings[&m.id].2, direction);
            assert!(range.start <= range.end && range.end <= m.bytes);
            s.syncs.push((true, m.id, range));
            if s.fail_sync_at == Some(s.syncs.len()) {
                return Err(DmaError::VisibilityFailed);
            }
            Ok(())
        }
    }
    pub(in crate::net::wifi::mediatek) struct Io(
        pub(in crate::net::wifi::mediatek) Arc<Mutex<State>>,
    );
    impl Drop for Io {
        fn drop(&mut self) {
            self.0.lock().unwrap().queue_drops += 1;
        }
    }
    // SAFETY: serialized test device queues; completions advance only when the
    // device model actually reads its separately mapped IOVA payload/descriptor.
    unsafe impl QueueIo for Io {
        fn configure(&mut self, address: u32, count: u16) -> Result<(), Error> {
            let mut s = self.0.lock().unwrap();
            s.base = u64::from(address);
            s.count = count;
            s.head = 0;
            s.index = 0;
            if s.fail_configure {
                return Err(Error::RegisterFailure);
            }
            Ok(())
        }
        fn device_index(&mut self) -> Result<u16, Error> {
            let s = self.0.lock().unwrap();
            Ok(if s.invalid_index { u16::MAX } else { s.index })
        }
        fn publish(&mut self, head: u16) -> Result<(), Error> {
            let mut s = self.0.lock().unwrap();
            s.head = head;
            if s.fail_publish {
                return Err(Error::RegisterFailure);
            }
            Ok(())
        }
    }
    fn setup(count: usize) -> (TxRing<Io>, Arc<Mutex<State>>) {
        let state = Arc::new(Mutex::new(State::default()));
        let domain: Arc<dyn DmaDomain> = Arc::new(Domain(state.lock().unwrap().memory.clone()));
        // SAFETY: no hardware; brand-new model queue is exclusively owned/idle.
        let ring = unsafe { TxRing::install(Io(state.clone()), &Source, domain, count) }.unwrap();
        (ring, state)
    }
    pub(in crate::net::wifi::mediatek) fn device_complete_one(state: &Arc<Mutex<State>>) {
        let mut s = state.lock().unwrap();
        assert_ne!(s.index, s.head);
        let ptr = s.memory.lock().unwrap().mappings[&s.base].1 + s.index as usize * DESC_BYTES;
        let descriptor = unsafe { core::slice::from_raw_parts(ptr as *const u32, 4) };
        let address = u64::from(u32::from_le(descriptor[0]));
        let ctrl = u32::from_le(descriptor[1]);
        assert_eq!(ctrl & (DONE | LAST), LAST);
        assert_eq!(descriptor[2], 0);
        assert_eq!(descriptor[3], 0);
        let len = (ctrl >> 16 & 0x3fff) as usize;
        let payload = s.memory.lock().unwrap().mappings[&address].1;
        assert_ne!(address, payload as u64);
        let bytes = unsafe { core::slice::from_raw_parts(payload as *const u8, len) }.to_vec();
        s.completed.push(bytes);
        s.index = (s.index + 1) % s.count;
    }
    #[test]
    fn actual_iova_payload_and_dma_index_ownership_survive_many_ring_wraps() {
        let (mut ring, state) = setup(8);
        for i in 0..70u64 {
            let bytes = vec![i as u8; 4096 - i as usize];
            ring.submit(i, &bytes).unwrap();
            assert_eq!(ring.pending(), 1);
            assert_eq!(ring.poll().unwrap(), None); // enqueue/head is not completion
            device_complete_one(&state);
            assert_eq!(
                ring.poll().unwrap(),
                Some(Completion {
                    cookie: i,
                    bytes: bytes.len()
                })
            );
            assert_eq!(state.lock().unwrap().completed.last(), Some(&bytes));
        }
        let s = state.lock().unwrap();
        assert_eq!(s.completed.len(), 70);
        assert_eq!(
            s.memory
                .lock()
                .unwrap()
                .syncs
                .iter()
                .filter(|v| v.0)
                .count(),
            140
        );
        drop(s);
        // SAFETY: model stopped consuming and every submission is completed.
        unsafe { ring.release_after_quiesce() }.unwrap();
        assert!(
            state
                .lock()
                .unwrap()
                .memory
                .lock()
                .unwrap()
                .mappings
                .is_empty()
        );
        assert_eq!(ring.submit(1, &[1]), Err(Error::Poisoned));
    }
    #[test]
    fn two_entry_reserve_and_bad_hardware_progress_fail_explicitly() {
        let (mut ring, state) = setup(4);
        ring.submit(1, &[1]).unwrap();
        ring.submit(2, &[2]).unwrap();
        assert_eq!(ring.submit(3, &[3]), Err(Error::Full));
        assert!(!ring.is_poisoned());
        state.lock().unwrap().index = 3;
        assert_eq!(ring.poll(), Err(Error::InvalidDeviceIndex));
        assert!(ring.is_poisoned());
        assert_eq!(ring.poll(), Err(Error::Poisoned));
        // SAFETY: explicit model stop prevents any future descriptor/payload reads.
        unsafe { ring.release_after_quiesce() }.unwrap();
    }
    #[test]
    fn failed_publication_keeps_pending_dma_and_retry_requires_quiescence() {
        let (mut ring, state) = setup(4);
        state.lock().unwrap().fail_publish = true;
        assert_eq!(ring.submit(7, &[0xa5; 4096]), Err(Error::RegisterFailure));
        assert_eq!(ring.pending(), 1);
        assert_eq!(ring.submit(8, &[1]), Err(Error::Poisoned));
        assert_eq!(
            state.lock().unwrap().memory.lock().unwrap().mappings.len(),
            5
        );
        // SAFETY: device model explicitly stopped before attempting teardown.
        state.lock().unwrap().memory.lock().unwrap().fail_unmap = true;
        assert_eq!(
            unsafe { ring.release_after_quiesce() },
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(
            state.lock().unwrap().memory.lock().unwrap().mappings.len(),
            5
        );
        state.lock().unwrap().memory.lock().unwrap().fail_unmap = false;
        unsafe { ring.release_after_quiesce() }.unwrap();
        assert!(
            state
                .lock()
                .unwrap()
                .memory
                .lock()
                .unwrap()
                .mappings
                .is_empty()
        );
    }
    #[test]
    fn dropping_active_queue_quarantines_descriptor_and_exposed_payload_pins() {
        let (mut ring, state) = setup(4);
        ring.submit(9, &[9]).unwrap();
        drop(ring);
        // Three never-published payload allocations unmap; active descriptor and
        // payload mappings retain their domain and pins through canonical Drop.
        assert_eq!(
            state.lock().unwrap().memory.lock().unwrap().mappings.len(),
            2
        );
        assert_eq!(state.lock().unwrap().queue_drops, 0);
        device_complete_one(&state);
        assert_eq!(state.lock().unwrap().completed[0], [9]);
    }
    #[test]
    fn visibility_failures_poison_without_releasing_unknown_ownership() {
        for fail_at in [2, 3, 4, 5] {
            let (mut ring, state) = setup(4);
            state.lock().unwrap().memory.lock().unwrap().fail_sync_at = Some(fail_at);
            let submit = ring.submit(11, &[11; 4096]);
            if fail_at <= 3 {
                assert_eq!(submit, Err(Error::Dma(DmaError::VisibilityFailed)));
            } else {
                submit.unwrap();
                device_complete_one(&state);
                assert_eq!(ring.poll(), Err(Error::Dma(DmaError::VisibilityFailed)));
                assert_eq!(ring.pending(), 1);
            }
            assert!(ring.is_poisoned());
            assert_eq!(ring.submit(12, &[12]), Err(Error::Poisoned));
            assert_eq!(
                state.lock().unwrap().memory.lock().unwrap().mappings.len(),
                5
            );
            // SAFETY: model is explicitly stopped before mappings are removed.
            unsafe { ring.release_after_quiesce() }.unwrap();
            assert!(
                state
                    .lock()
                    .unwrap()
                    .memory
                    .lock()
                    .unwrap()
                    .mappings
                    .is_empty()
            );
        }
    }
    #[test]
    fn partial_unmap_failure_can_finish_after_acknowledged_quiescence() {
        let (mut ring, state) = setup(4);
        ring.submit(20, &[20]).unwrap();
        state.lock().unwrap().memory.lock().unwrap().fail_unmap_at = Some(2);
        // SAFETY: hardware model stopped; injected invalidation error retains
        // the still-mapped resources for the explicit later retry.
        assert_eq!(
            unsafe { ring.release_after_quiesce() },
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(
            state.lock().unwrap().memory.lock().unwrap().mappings.len(),
            4
        );
        unsafe { ring.release_after_quiesce() }.unwrap();
        assert_eq!(ring.pending(), 0);
        assert!(
            state
                .lock()
                .unwrap()
                .memory
                .lock()
                .unwrap()
                .mappings
                .is_empty()
        );
    }
    #[test]
    fn uncertain_configuration_retains_only_the_published_descriptor_mapping() {
        let state = Arc::new(Mutex::new(State {
            fail_configure: true,
            ..State::default()
        }));
        let domain: Arc<dyn DmaDomain> = Arc::new(Domain(state.lock().unwrap().memory.clone()));
        // SAFETY: exclusive brand-new idle model. Configure fails after base
        // publication, making its descriptor mapping conservatively uncertain.
        assert!(matches!(
            unsafe { TxRing::install(Io(state.clone()), &Source, domain, 4) },
            Err(Error::RegisterFailure)
        ));
        assert_eq!(
            state.lock().unwrap().memory.lock().unwrap().mappings.len(),
            1
        );
        assert_eq!(state.lock().unwrap().queue_drops, 0);
    }
    #[test]
    fn requester_and_bar_owner_drop_only_after_full_quiescent_unmap() {
        let (mut ring, state) = setup(4);
        ring.submit(1, &[1]).unwrap();
        state.lock().unwrap().memory.lock().unwrap().fail_unmap_at = Some(2);
        // SAFETY: stopped model; partial invalidation fails and keeps Q alive.
        assert_eq!(
            unsafe { ring.release_after_quiesce() },
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(state.lock().unwrap().queue_drops, 0);
        unsafe { ring.release_after_quiesce() }.unwrap();
        assert_eq!(state.lock().unwrap().queue_drops, 0);
        drop(ring);
        assert_eq!(state.lock().unwrap().queue_drops, 1);
    }
}
