// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C single beacon TXBD for firmware reserved pages. Pinned rtw88
//! pci.c/tx.c are hardware references; allocations and IOVAs are native Stela.
//! Submission is not a DMA completion, radio transmission or firmware ALIVE.
use super::{
    io::{self, Bar},
    registers::*,
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CpuMapping, MemoryError, PageSource},
};
use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};

const PACKET_DESCRIPTOR: usize = 48;
const BUFFER_DESCRIPTOR: usize = 16;
const MAX_DATA: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Memory(MemoryError),
    Dma(DmaError),
    Register,
    InvalidLength,
    Address,
    Pending,
    NoPending,
    Quarantined,
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

/// Source management-rate configuration for the reserved-page descriptor.
/// This never tunes a radio; use the actual prior MAC configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareBand {
    Ghz2,
    Ghz5,
}

/// A specialized single beacon queue has no general TX ring read index.
///
/// # Safety
/// Implementations own the actual selected RTL8822C claim and UC BAR; reads
/// are actual volatile observations, writes ordered real MMIO. configure is
/// called only with acknowledged stopped DMA and no competing worker; kick
/// publishes actual BCN_WORK. Drop retains the real claim/BAR reservation for
/// its full lifetime. Never infer completion from configure/kick readback.
pub unsafe trait Registers {
    fn configure(&mut self, iova: u32) -> Result<(), Error>;
    fn kick(&mut self) -> Result<(), Error>;
}

// SAFETY: `Bar::new` binds the exclusive requester BAR; only the beacon
// base and work registers are accessed, without completion claims.
unsafe impl Registers for Bar {
    fn configure(&mut self, iova: u32) -> Result<(), Error> {
        self.write32(RTK_PCI_TXBD_DESA_BCNQ, iova);
        if self.read32(RTK_PCI_TXBD_DESA_BCNQ) != iova {
            return Err(Error::Register);
        }
        Ok(())
    }
    fn kick(&mut self) -> Result<(), Error> {
        let work = self.read8(RTK_PCI_TXBD_BCN_WORK);
        if work == u8::MAX {
            return Err(Error::Register);
        }
        self.write8(RTK_PCI_TXBD_BCN_WORK, work | BIT_PCI_BCNQ_FLAG);
        Ok(())
    }
}

pub(super) struct Allocation {
    pub(super) cpu: CpuMapping,
    pub(super) dma: DmaMapping,
    pub(super) published: bool,
    pub(super) unmapped: bool,
}
impl Allocation {
    pub(super) fn new(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        direction: Direction,
    ) -> Result<Self, Error> {
        let (cpu, dma) = crate::net::wifi::allocation::allocate_32bit::<Error>(
            source, domain, bytes, direction,
        )?;
        Ok(Self {
            cpu,
            dma,
            published: false,
            unmapped: false,
        })
    }
    pub(super) fn address(&self) -> Result<u32, Error> {
        u32::try_from(self.dma.address()?).map_err(|_| Error::Address)
    }
    pub(super) fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let ptr = self.cpu.address(offset, bytes.len())?;
        // SAFETY: bounded exclusive CPU-owned native WB RAM. Caller proves
        // prior device consumption before recycling any descriptor or payload.
        unsafe {
            ptr.as_ptr()
                .copy_from_nonoverlapping(bytes.as_ptr(), bytes.len())
        };
        Ok(())
    }
    pub(super) unsafe fn release(&mut self) -> Result<(), Error> {
        if !self.unmapped {
            // SAFETY: caller supplies acknowledged requester stop and drain.
            unsafe { self.dma.unmap()? };
            self.unmapped = true;
            self.published = false;
        }
        Ok(())
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.published && !self.unmapped {
            // SAFETY: no hardware was given this allocation; uncertain unmap
            // retains pins/domain in canonical DmaMapping's quarantine Drop.
            let _ = unsafe { self.dma.unmap() };
        }
    }
}

/// Exact source reserved-page packet descriptor and two TXBD segments. The
/// final eight packet-descriptor bytes remain zero as in the donor's 48-byte
/// memset; ordinary radio TX/crypto fields are deliberately not exposed here.
pub fn descriptors(
    data: &[u8],
    address: u32,
    band: FirmwareBand,
) -> Result<([u8; 48], [u8; 16]), Error> {
    if !(8..=MAX_DATA).contains(&data.len()) {
        return Err(Error::InvalidLength);
    }
    address
        .checked_add((PACKET_DESCRIPTOR + data.len() - 1) as u32)
        .ok_or(Error::Address)?;
    let mut packet = [0u8; PACKET_DESCRIPTOR];
    let (rate_id, rate) = match band {
        FirmwareBand::Ghz2 => (8, 0),
        FirmwareBand::Ghz5 => (7, 4),
    };
    // Broadcast is also multicast, so source's broadcast || multicast is
    // exactly the low bit of addr1[0], including opaque firmware payloads.
    for (word, value) in [
        (
            0,
            data.len() as u32 | 48 << 16 | u32::from(data[4] & 1) << 24 | 1 << 26 | 1 << 31,
        ),
        (1, 16 << 8 | rate_id << 16),
        (3, 1 << 8 | 1 << 10),
        (4, rate),
        (8, 1 << 15),
    ] {
        packet[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut buffer = [0u8; BUFFER_DESCRIPTOR];
    buffer[0..2].copy_from_slice(&48u16.to_le_bytes());
    let psb = ((PACKET_DESCRIPTOR + data.len()).div_ceil(128) as u16) | 0x8000;
    buffer[2..4].copy_from_slice(&psb.to_le_bytes());
    buffer[4..8].copy_from_slice(&address.to_le_bytes());
    buffer[8..10].copy_from_slice(&(data.len() as u16).to_le_bytes());
    buffer[12..16].copy_from_slice(&(address + 48).to_le_bytes());
    Ok((packet, buffer))
}

/// Owned single firmware beacon slot. Queue base/pins survive successful
/// packet consumption: only explicit acknowledged requester stop permits unmap.
pub struct Beacon<R: Registers> {
    io: Option<R>,
    descriptor: Allocation,
    payload: Allocation,
    band: FirmwareBand,
    configured: bool,
    pending: bool,
    poisoned: bool,
    last_error: Option<Error>,
}
impl<R: Registers> Beacon<R> {
    /// # Safety
    /// The real RTL8822C requester is stopped/drained, attached to `domain`,
    /// and `io` retains that exact PCI/BAR claim. Source allocations are real
    /// coherent WB DMA RAM on this requester, with NoSnoop/ATS disabled; WB
    /// alone is not coherence proof. No other engine/IRQ/reset worker touches
    /// this queue until acknowledged stop. `band` is prior MAC configuration.
    pub unsafe fn install(
        io: R,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        band: FirmwareBand,
    ) -> Result<Self, Error> {
        // Donor allocates coherent TXBD memory. Do not infer read-only DMA
        // from its lack of descriptor reads: the device may update OWN.
        let descriptor = Allocation::new(
            source,
            domain.clone(),
            BUFFER_DESCRIPTOR,
            Direction::Bidirectional,
        )?;
        let payload = Allocation::new(
            source,
            domain,
            PACKET_DESCRIPTOR + MAX_DATA,
            Direction::ToDevice,
        )?;
        let address = descriptor.address()?;
        let mut queue = Self {
            io: Some(io),
            descriptor,
            payload,
            band,
            configured: false,
            pending: false,
            poisoned: true,
            last_error: None,
        };
        queue.descriptor.write(0, &[0; BUFFER_DESCRIPTOR])?;
        queue.descriptor.dma.sync_for_device(0..BUFFER_DESCRIPTOR)?;
        fence(Ordering::Release);
        // Set before MMIO: a store/readback failure may already publish base.
        queue.descriptor.published = true;
        queue.configured = true;
        queue
            .io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .configure(address)?;
        queue.poisoned = false;
        Ok(queue)
    }
    pub fn pending(&self) -> bool {
        self.pending
    }
    pub fn quarantined(&self) -> bool {
        self.poisoned
    }
    pub fn last_error(&self) -> Option<Error> {
        self.last_error
    }
    pub fn enqueue(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        if self.pending {
            return Err(Error::Pending);
        }
        let (packet, buffer) = descriptors(data, self.payload.address()?, self.band)?;
        self.poisoned = true;
        let result = (|| {
            self.payload.write(0, &packet)?;
            self.payload.write(PACKET_DESCRIPTOR, data)?;
            self.payload
                .dma
                .sync_for_device(0..PACKET_DESCRIPTOR + data.len())?;
            // The configured descriptor page is device-visible coherent RAM.
            // Retain payload before placing its IOVA there, including if the
            // subsequent descriptor visibility operation fails before kick.
            self.payload.published = true;
            self.descriptor.write(0, &buffer)?;
            self.descriptor.dma.sync_for_device(0..BUFFER_DESCRIPTOR)?;
            fence(Ordering::Release);
            self.pending = true;
            self.io.as_mut().ok_or(Error::Quarantined)?.kick()
        })();
        match result {
            Ok(()) => {
                self.poisoned = false;
                Ok(())
            }
            Err(error) => {
                self.last_error = Some(error);
                Err(error)
            }
        }
    }
    /// Prepare a live idle slot for actual post-power HCI rebinding.
    /// # Safety
    /// Independent real requester stop/drain and exclusive workers. A completed
    /// payload is still retained; this does not authorize firmware retry/reset.
    pub(super) unsafe fn begin_hci_rebind(&mut self) -> Result<u32, Error> {
        if self.poisoned || self.pending || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            self.descriptor.dma.sync_for_cpu(0..BUFFER_DESCRIPTOR)?;
        }
        self.descriptor.write(0, &[0; BUFFER_DESCRIPTOR])?;
        self.descriptor.dma.sync_for_device(0..BUFFER_DESCRIPTOR)?;
        self.descriptor.address()
    }
    pub(super) fn finish_hci_rebind(&mut self) {
        self.poisoned = false;
    }
    /// # Safety
    /// The actual requester is stopped and all DMA/IRQ/submission workers
    /// drained, with no new access possible throughout both unmaps. BCN_VALID
    /// alone is only payload consumption and does not satisfy this contract.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        self.poisoned = true;
        // SAFETY: caller supplies complete requester stop and drained workers.
        unsafe {
            self.descriptor.release()?;
            self.payload.release()?;
        }
        self.pending = false;
        self.configured = false;
        self.poisoned = false;
        Ok(())
    }
}
// SAFETY: install binds real owned DMA pages/domain/registers; pending slot
// cannot be overwritten before source's actual new BCN_VALID proof. No Drop
// unmap exists for published buffers, and uncertain io ownership is retained.
unsafe impl<R: Registers> io::BeaconQueue for Beacon<R> {
    fn submit(&mut self, data: &[u8]) -> Result<(), io::Error> {
        self.enqueue(data).map_err(|_| io::Error::Queue)
    }
    unsafe fn consumed(&mut self) -> Result<(), io::Error> {
        if self.poisoned || !self.pending {
            return Err(io::Error::Queue);
        }
        self.poisoned = true;
        // SAFETY: caller supplies source's fresh BCN_VALID consumption proof;
        // no device access to this TXBD remains until the next explicit kick.
        if let Err(error) = unsafe { self.descriptor.dma.sync_for_cpu(0..BUFFER_DESCRIPTOR) } {
            self.last_error = Some(Error::Dma(error));
            return Err(io::Error::Queue);
        }
        fence(Ordering::Acquire);
        self.pending = false;
        self.poisoned = false;
        Ok(())
    }
    fn quarantine(&mut self) {
        self.poisoned = true;
    }
}
impl<R: Registers> Drop for Beacon<R> {
    fn drop(&mut self) {
        if self.configured
            && let Some(io) = self.io.take()
        {
            core::mem::forget(io);
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
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
    // SAFETY: exclusively retained zeroed/aligned virtual RAM for a serialized
    // hardware model, not privileged allocation or actual physical DMA proof.
    unsafe impl Send for Pages {}
    // SAFETY: no safe byte references or concurrent device access are exposed.
    unsafe impl Sync for Pages {}
    // SAFETY: `cpu_base` and `physical` describe the one retained, aligned test allocation for its
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
    // SAFETY: actual pinned allocations are retained, while IOVA translation
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
    // SAFETY: modeled registers publish the actual model's native-DMA IOVA,
    // resolve its retained pin and record the device's descriptor/payload read.
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
            // SAFETY: model DMA follows an actual retained mapping into the
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
        // SAFETY: synchronous stopped model with retained pins and separate
        // model IOVA addresses; no actual privileged DMA effects are claimed.
        unsafe {
            Beacon::install(
                ModelRegisters(m.clone()),
                &Source,
                Arc::new(Domain(m.clone())),
                FirmwareBand::Ghz2,
            )
        }
    }
    /// Cross-module integration fixture reuses this exact native queue, pin
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
    // forwarding retains the actual native slot's ownership checks/lifetimes.
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
        // SAFETY: this model's kick read the complete actual mapped packet;
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
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_BEACON_ORACLE").unwrap()).unwrap();
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
}
