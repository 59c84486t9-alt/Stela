// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Polled raw NHI rings, adapted from Linux nhi.c/nhi_regs.h.
//!
//! This initial transport uses the donor's NO_INTERRUPT raw-ring mode. It
//! deliberately keeps all published DMA leases until an explicitly proven
//! device quiescence, even after clearing the ring enable bit. Ring shutdown
//! register readback alone is not proof that posted DMA/IRQ work has drained.
use super::config::{Encoded, FRAME_BYTES, PacketType, Received};
use crate::bus::dma::{
    mapping::{Direction as DmaDirection, DmaDomain, DmaError, DmaMapping},
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering, fence},
};

pub const CAPABILITIES: usize = 0x39640;
const TX_DESCRIPTOR: usize = 0;
const RX_DESCRIPTOR: usize = 0x08000;
const TX_OPTIONS: usize = 0x19800;
const RX_OPTIONS: usize = 0x29800;
const ENABLE: u32 = 1 << 31;
const RAW: u32 = 1 << 30;
const DESCRIPTOR_BYTES: usize = 16;
const PAGE: usize = 4096;
const COMPLETED: u16 = 2;
const POSTED: u16 = 4;
const DESCRIPTOR_FLAGS_MASK: u16 = 15;
static QUARANTINED_RINGS: AtomicU64 = AtomicU64::new(0);

/// Rings dropped with a published DMA pointer and no proven final drain.
pub fn quarantined_rings() -> u64 {
    QUARANTINED_RINGS.load(Ordering::Relaxed)
}

/// Actual retained UC MMIO, or a stateful controller model.
///
/// # Safety
/// Accesses must operate on the specified live physical NHI and preserve real
/// readback/failure effects; `bytes` must describe the complete mapping. The
/// mapping and function reservation live while any retained Arc exists. No
/// other owner changes the NHI's power, reset, ring or interrupt state. Shared
/// access must obey the caller's platform serialization. Drop must not reclaim
/// hardware resources while a quarantined Arc retains this object.
pub unsafe trait Registers: Send + Sync {
    fn bytes(&self) -> usize;
    fn read32(&self, offset: usize) -> u32;
    fn write32(&self, offset: usize, value: u32);
}

/// A retained native mapping; the platform still owns PCI and mapping lifetime.
pub struct Mmio {
    base: NonNull<u8>,
    bytes: usize,
}
impl Mmio {
    /// # Safety
    /// The entire live UC mapping and exact NHI function are exclusively owned
    /// and retained until every Arc, including quarantined references, ends.
    pub unsafe fn new(base: NonNull<u8>, bytes: usize) -> Result<Self, Error> {
        if !(base.as_ptr() as usize).is_multiple_of(4)
            || bytes < CAPABILITIES + 4
            || (base.as_ptr() as usize).checked_add(bytes).is_none()
        {
            return Err(Error::Mapping);
        }
        Ok(Self { base, bytes })
    }
    fn pointer(&self, offset: usize) -> *mut u32 {
        assert!(
            offset.is_multiple_of(4) && offset.checked_add(4).is_some_and(|end| end <= self.bytes)
        );
        // SAFETY: retained bounded native mapping established by new().
        unsafe { self.base.as_ptr().add(offset).cast() }
    }
}
// SAFETY: new() requires retained exclusive hardware ownership and caller serialization.
unsafe impl Send for Mmio {}
// SAFETY: as for Send; volatile register operations preserve native effects.
unsafe impl Sync for Mmio {}
// SAFETY: new() establishes the physical mapping and reservation contract.
unsafe impl Registers for Mmio {
    fn bytes(&self) -> usize {
        self.bytes
    }
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: checked mapped aligned register.
        unsafe { self.pointer(offset).read_volatile() }
    }
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: checked mapped aligned register.
        unsafe { self.pointer(offset).write_volatile(value) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Tx,
    Rx,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Mapping,
    RegisterRead {
        offset: usize,
    },
    RegisterRejected {
        offset: usize,
        expected: u32,
        observed: u32,
    },
    InvalidConfig,
    Busy,
    Stopped,
    Full,
    WrongDirection,
    FrameLength,
    FrameFlags(u16),
    DescriptorAddress,
    TicketExhausted,
    Poisoned,
    Memory(MemoryError),
    Dma(DmaError),
}
impl From<MemoryError> for Error {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}
impl From<DmaError> for Error {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RingConfig {
    pub direction: Direction,
    pub hop: u16,
    pub entries: u16,
    /// Native DMA capability/IOMMU mask, not a CPU/physical-address mask.
    pub address_limit: u64,
}

struct Region {
    cpu: CpuMapping,
    dma: DmaMapping,
    published: bool,
}
impl Region {
    fn new(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        direction: DmaDirection,
        limit: u64,
    ) -> Result<Self, Error> {
        let pages = source.allocate(bytes, PAGE, CacheAttribute::WriteBack)?;
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack)?;
        let dma = DmaMapping::map(domain, pages, direction, limit)?;
        Ok(Self {
            cpu,
            dma,
            published: false,
        })
    }
    fn pointer<T>(&self, offset: usize) -> Result<*mut T, Error> {
        let pointer = self.cpu.address(offset, size_of::<T>())?;
        if !(pointer.as_ptr() as usize).is_multiple_of(align_of::<T>()) {
            return Err(Error::Mapping);
        }
        Ok(pointer.as_ptr().cast())
    }
    fn read32(&self, offset: usize) -> Result<u32, Error> {
        // SAFETY: checked retained DMA mapping; callers serialize CPU ownership.
        Ok(unsafe { self.pointer::<u32>(offset)?.read_volatile() })
    }
    fn write32(&self, offset: usize, value: u32) -> Result<(), Error> {
        // SAFETY: checked retained DMA mapping; unpublished/reclaimed slot.
        unsafe { self.pointer::<u32>(offset)?.write_volatile(value) };
        Ok(())
    }
    fn write64(&self, offset: usize, value: u64) -> Result<(), Error> {
        // SAFETY: checked retained DMA mapping; unpublished/reclaimed slot.
        unsafe { self.pointer::<u64>(offset)?.write_volatile(value) };
        Ok(())
    }
    /// # Safety
    /// No device access or pending IRQ/deferred operation can reference this region.
    unsafe fn release(&mut self) -> Result<(), Error> {
        // SAFETY: established by the caller, including IOTLB acknowledgement.
        unsafe { self.dma.unmap()? };
        Ok(())
    }
}
impl Drop for Region {
    fn drop(&mut self) {
        if !self.published && self.dma.address().is_ok() {
            // SAFETY: no device has ever received this region's address.
            // A failed unmap is retained by DmaMapping's observable quarantine.
            let _ = unsafe { self.dma.unmap() };
        }
    }
}

#[derive(Clone, Copy)]
struct Pending {
    ticket: u64,
    bytes: usize,
    kind: u8,
}
struct Slot {
    buffer: Region,
    pending: Option<Pending>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Running,
    Disabled,
    Fault,
    Released,
}

/// Exactly one owned NHI TX or RX ring. Methods and last release require
/// process/deferred context. No callback, allocation or final Drop runs in IRQ.
pub struct Ring<R: Registers> {
    registers: Arc<R>,
    config: RingConfig,
    descriptors: Region,
    slots: Vec<Slot>,
    head: u16,
    tail: u16,
    next_ticket: u64,
    descriptor_base: usize,
    options_base: usize,
    phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    pub direction: Direction,
    pub ticket: u64,
    pub bytes: usize,
    pub eof: u8,
    pub sof: u8,
    pub flags: u16,
    pub data: Vec<u8>,
}
impl Completion {
    pub fn received(&self) -> Result<Received<'_>, super::config::Error> {
        if self.direction != Direction::Rx {
            return Err(super::config::Error::UnexpectedReply);
        }
        Ok(Received {
            kind: PacketType::try_from(self.eof)?,
            sof: self.sof,
            bytes: &self.data,
        })
    }
}

impl<R: Registers> Ring<R> {
    /// Allocate an exact raw ring without enabling it or publishing DMA.
    ///
    /// # Safety
    /// The caller owns this exact NHI function/ring, has established D0 and
    /// memory decode, stopped/drained prior DMA and IRQ work, and masked its
    /// interrupt. Firmware/another connection manager cannot change it. The
    /// domain is attached to this requester, and ordinary WB DMA is genuinely
    /// coherent for volatile completion polling with PCIe No-Snoop disabled.
    /// No other engine accesses these newly allocated mappings before they are
    /// published. The complete native mapping/reservation outlives the Arc.
    pub unsafe fn new(
        registers: Arc<R>,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        config: RingConfig,
    ) -> Result<Self, Error> {
        if config.entries < 2 || registers.bytes() < CAPABILITIES + 4 {
            return Err(Error::InvalidConfig);
        }
        let capabilities = registers.read32(CAPABILITIES);
        if capabilities == u32::MAX {
            return Err(Error::RegisterRead {
                offset: CAPABILITIES,
            });
        }
        let hops = capabilities & 0x3ff; // Actual nhi_probe mask, not the header's older comment.
        if hops == 0 || u32::from(config.hop) >= hops {
            return Err(Error::InvalidConfig);
        }
        let descriptor_base = match config.direction {
            Direction::Tx => TX_DESCRIPTOR,
            Direction::Rx => RX_DESCRIPTOR,
        } + usize::from(config.hop) * 16;
        let options_base = match config.direction {
            Direction::Tx => TX_OPTIONS,
            Direction::Rx => RX_OPTIONS,
        } + usize::from(config.hop) * 32;
        if descriptor_base + 16 > registers.bytes() || options_base + 8 > registers.bytes() {
            return Err(Error::Mapping);
        }
        let old = registers.read32(options_base);
        if old == u32::MAX {
            return Err(Error::RegisterRead {
                offset: options_base,
            });
        }
        if old != 0 {
            return Err(Error::Busy);
        }
        let indices = registers.read32(descriptor_base + 8);
        if indices == u32::MAX {
            return Err(Error::RegisterRead {
                offset: descriptor_base + 8,
            });
        }
        // Software starts at descriptor zero. A stopped ring with stale
        // hardware-owned indices needs its owner's real reset, not a guessed
        // producer write that cannot reset the consumer half.
        if indices != 0 {
            return Err(Error::Busy);
        }
        let descriptors = Region::new(
            source,
            domain.clone(),
            usize::from(config.entries) * DESCRIPTOR_BYTES,
            DmaDirection::Bidirectional,
            config.address_limit,
        )?;
        let mut slots = Vec::with_capacity(usize::from(config.entries));
        let direction = match config.direction {
            Direction::Tx => DmaDirection::ToDevice,
            Direction::Rx => DmaDirection::FromDevice,
        };
        for _ in 0..config.entries {
            slots.push(Slot {
                buffer: Region::new(
                    source,
                    domain.clone(),
                    FRAME_BYTES,
                    direction,
                    config.address_limit,
                )?,
                pending: None,
            });
        }
        Ok(Self {
            registers,
            config,
            descriptors,
            slots,
            head: 0,
            tail: 0,
            next_ticket: 0,
            descriptor_base,
            options_base,
            phase: Phase::New,
        })
    }

    fn read(&self, offset: usize) -> Result<u32, Error> {
        let value = self.registers.read32(offset);
        if value == u32::MAX {
            return Err(Error::RegisterRead { offset });
        }
        Ok(value)
    }
    fn write_checked(&self, offset: usize, expected: u32) -> Result<(), Error> {
        self.registers.write32(offset, expected);
        // RX SOF/EOF masks legitimately contain all ones (raw mode ignores
        // them). Do not turn that exact register value into a false bus error.
        let observed = self.registers.read32(offset);
        if observed == u32::MAX && expected != u32::MAX {
            return Err(Error::RegisterRead { offset });
        }
        if observed != expected {
            return Err(Error::RegisterRejected {
                offset,
                expected,
                observed,
            });
        }
        Ok(())
    }
    fn write_producer(&self, next: u16) -> Result<(), Error> {
        let offset = self.descriptor_base + 8;
        self.registers.write32(
            offset,
            match self.config.direction {
                Direction::Tx => u32::from(next) << 16,
                Direction::Rx => u32::from(next),
            },
        );
        // The opposite half remains hardware-owned, including during disable.
        let observed = self.read(offset)?;
        let producer = match self.config.direction {
            Direction::Tx => observed >> 16,
            Direction::Rx => observed & 0xffff,
        };
        if producer != u32::from(next) {
            return Err(Error::RegisterRejected {
                offset,
                expected: u32::from(next),
                observed: producer,
            });
        }
        Ok(())
    }
    fn poison<T>(&mut self, error: Error) -> Result<T, Error> {
        self.phase = Phase::Fault;
        Err(error)
    }
    fn running(&self) -> Result<(), Error> {
        match self.phase {
            Phase::Running => Ok(()),
            Phase::Fault => Err(Error::Poisoned),
            _ => Err(Error::Stopped),
        }
    }

    pub fn start(&mut self) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::Busy);
        }
        let result = (|| {
            self.descriptors
                .dma
                .sync_for_device(0..usize::from(self.config.entries) * DESCRIPTOR_BYTES)?;
            let address = self.descriptors.dma.address()?;
            // Retain all resources on any uncertain write/enable acknowledgement.
            self.descriptors.published = true;
            self.write_checked(self.descriptor_base, address as u32)?;
            self.write_checked(self.descriptor_base + 4, (address >> 32) as u32)?;
            let size = u32::from(self.config.entries)
                | if self.config.direction == Direction::Rx {
                    (FRAME_BYTES as u32) << 16
                } else {
                    0
                };
            self.write_checked(self.descriptor_base + 12, size)?;
            self.write_checked(
                self.options_base + 4,
                if self.config.direction == Direction::Rx {
                    u32::MAX
                } else {
                    0
                },
            )?;
            self.write_checked(self.options_base, ENABLE | RAW)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.phase = Phase::Running;
                Ok(())
            }
            Err(error) => self.poison(error),
        }
    }

    pub fn transmit(&mut self, frame: &Encoded) -> Result<u64, Error> {
        if self.config.direction != Direction::Tx {
            return Err(Error::WrongDirection);
        }
        if frame.bytes.is_empty()
            || frame.bytes.len() > FRAME_BYTES
            || !frame.bytes.len().is_multiple_of(4)
        {
            return Err(Error::FrameLength);
        }
        self.post(Some(frame))
    }
    pub fn receive(&mut self) -> Result<u64, Error> {
        if self.config.direction != Direction::Rx {
            return Err(Error::WrongDirection);
        }
        self.post(None)
    }
    fn post(&mut self, frame: Option<&Encoded>) -> Result<u64, Error> {
        self.running()?;
        let next = (self.head + 1) % self.config.entries;
        if next == self.tail {
            return Err(Error::Full);
        }
        let ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(Error::TicketExhausted)?;
        let index = usize::from(self.head);
        let result = (|| {
            let slot = &mut self.slots[index];
            if slot.pending.is_some() {
                return Err(Error::Busy);
            }
            let (bytes, kind) = if let Some(frame) = frame {
                for (offset, value) in frame.bytes.iter().enumerate() {
                    // SAFETY: this slot is not in flight and the checked frame fits.
                    unsafe {
                        slot.buffer
                            .cpu
                            .address(offset, 1)?
                            .as_ptr()
                            .write_volatile(*value)
                    };
                }
                (frame.bytes.len(), frame.kind as u8)
            } else {
                (FRAME_BYTES, 0)
            };
            slot.buffer.dma.sync_for_device(0..bytes)?;
            let address = slot.buffer.dma.address()?;
            let base = index * DESCRIPTOR_BYTES;
            self.descriptors.write64(base, address)?;
            self.descriptors.write32(base + 12, 0)?;
            let value = (u32::from(POSTED) << 20)
                | if frame.is_some() {
                    bytes as u32 | (u32::from(kind) << 12) | (u32::from(kind) << 16)
                } else {
                    0
                };
            self.descriptors.write32(base + 8, value)?;
            self.descriptors
                .dma
                .sync_for_device(base..base + DESCRIPTOR_BYTES)?;
            // The descriptor can now expose this buffer. Failed publication
            // must retain both leases even if software cannot observe progress.
            slot.buffer.published = true;
            slot.pending = Some(Pending {
                ticket,
                bytes,
                kind,
            });
            fence(Ordering::SeqCst);
            self.write_producer(next)?;
            Ok(())
        })();
        if let Err(error) = result {
            return self.poison(error);
        }
        self.head = next;
        self.next_ticket = ticket;
        Ok(ticket)
    }

    pub fn poll(&mut self) -> Result<Option<Completion>, Error> {
        self.running()?;
        if self.tail == self.head {
            return Ok(None);
        }
        let index = usize::from(self.tail);
        let base = index * DESCRIPTOR_BYTES;
        let result = (|| {
            // WB/coherent ownership was required by new(). This is only a
            // volatile status observation; it does not grant payload ownership.
            let value = self.descriptors.read32(base + 8)?;
            let flags = (value >> 20) as u16;
            if flags & COMPLETED == 0 {
                return Ok(None);
            }
            fence(Ordering::SeqCst);
            // SAFETY: this exact descriptor has completed and is not reposted.
            unsafe {
                self.descriptors
                    .dma
                    .sync_for_cpu(base..base + DESCRIPTOR_BYTES)?
            };
            let slot = &mut self.slots[index];
            let pending = slot.pending.ok_or(Error::Busy)?;
            // Raw control mode does not define frame-mode CRC/overrun
            // semantics. Linux ctl.c preserves these descriptor bits and
            // checks the actual wire CRC instead. In particular POSTED shares
            // bit 0x4 with frame-mode BUFFER_OVERRUN and may remain set.
            if flags & !DESCRIPTOR_FLAGS_MASK != 0 {
                return Err(Error::FrameFlags(flags));
            }
            let actual_address = u64::from(self.descriptors.read32(base)?)
                | (u64::from(self.descriptors.read32(base + 4)?) << 32);
            if actual_address != slot.buffer.dma.address()? {
                return Err(Error::DescriptorAddress);
            }
            let (bytes, eof, sof) = if self.config.direction == Direction::Rx {
                let bytes = match value & 0xfff {
                    0 => 4096,
                    bytes => bytes as usize,
                };
                if bytes > FRAME_BYTES {
                    return Err(Error::FrameLength);
                }
                (
                    bytes,
                    ((value >> 12) & 15) as u8,
                    ((value >> 16) & 15) as u8,
                )
            } else {
                (pending.bytes, pending.kind, pending.kind)
            };
            // SAFETY: the completed descriptor transfers this buffer back to
            // the CPU; no new submission exists until after poll returns.
            unsafe { slot.buffer.dma.sync_for_cpu(0..pending.bytes)? };
            let mut data = Vec::new();
            if self.config.direction == Direction::Rx {
                data.reserve(bytes);
                for offset in 0..bytes {
                    // SAFETY: completed buffer, bounded retained CPU mapping.
                    data.push(unsafe {
                        slot.buffer.cpu.address(offset, 1)?.as_ptr().read_volatile()
                    });
                }
            }
            slot.pending = None;
            Ok(Some(Completion {
                direction: self.config.direction,
                ticket: pending.ticket,
                bytes,
                eof,
                sof,
                flags,
                data,
            }))
        })();
        match result {
            Ok(Some(completion)) => {
                self.tail = (self.tail + 1) % self.config.entries;
                Ok(Some(completion))
            }
            Ok(None) => Ok(None),
            Err(error) => self.poison(error),
        }
    }

    /// Stop new submissions and clear actual ring configuration. This does not
    /// reclaim DMA or infer posted-write/IRQ drain from register readback.
    pub fn disable(&mut self) -> Result<(), Error> {
        if self.phase == Phase::Released {
            return Err(Error::Stopped);
        }
        let result = (|| {
            self.write_checked(self.options_base, 0)?;
            self.write_checked(self.descriptor_base, 0)?;
            self.write_checked(self.descriptor_base + 4, 0)?;
            self.write_producer(0)?;
            self.write_checked(self.descriptor_base + 12, 0)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.phase = Phase::Disabled;
                Ok(())
            }
            Err(error) => self.poison(error),
        }
    }

    /// Reclaim only after acknowledged native device teardown; retry preserves
    /// all regions whose IOTLB removal has not yet succeeded.
    ///
    /// # Safety
    /// Ring DMA and posted writes are truly stopped/drained by the controller
    /// or a completed containing reset. Its interrupt and deferred callbacks
    /// are masked/drained. No current or future operation can reference any
    /// descriptor/frame. Final release runs in process/deferred context.
    pub unsafe fn release(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Disabled {
            return Err(Error::Busy);
        }
        for slot in &mut self.slots {
            if slot.buffer.dma.address().is_ok() {
                // SAFETY: caller proves all hardware/IRQ ownership ended.
                unsafe { slot.buffer.release()? };
            }
        }
        if self.descriptors.dma.address().is_ok() {
            // SAFETY: as for the frame regions; failed invalidation retains it.
            unsafe { self.descriptors.release()? };
        }
        self.phase = Phase::Released;
        Ok(())
    }
}

impl<R: Registers> Drop for Ring<R> {
    fn drop(&mut self) {
        if self.descriptors.published && self.phase != Phase::Released {
            let _ = QUARANTINED_RINGS.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            });
            // DmaMapping also retains each active domain/page lease. Preserve
            // the physical NHI reservation and MMIO owner alongside them.
            core::mem::forget(self.registers.clone());
        }
    }
}

#[cfg(test)]
mod tests {
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
    use core::{
        alloc::Layout,
        ops::Range,
        sync::atomic::{AtomicBool, AtomicUsize},
    };
    use std::sync::Mutex;

    struct Backing {
        pointer: NonNull<u8>,
        layout: Layout,
        pages: Vec<u64>,
        released: Arc<AtomicUsize>,
    }
    // SAFETY: immutable metadata points at retained exclusive model RAM; all
    // modeled hardware operations and CPU operations are serialized by tests.
    unsafe impl Send for Backing {}
    // SAFETY: as for Send; model RAM has no concurrent hardware writer.
    unsafe impl Sync for Backing {}
    // SAFETY: owns a real aligned allocation; host pointers serve only as the
    // model's physical identifiers, never physical hardware DMA addresses.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            self.pointer
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
    impl Drop for Backing {
        fn drop(&mut self) {
            // SAFETY: this is the exact retained allocation and final pin.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
            self.released.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Source {
        allocated: AtomicUsize,
        released: Arc<AtomicUsize>,
        fail_at: AtomicUsize,
    }
    impl Source {
        fn new() -> Self {
            Self {
                allocated: AtomicUsize::new(0),
                released: Arc::new(AtomicUsize::new(0)),
                fail_at: AtomicUsize::new(usize::MAX),
            }
        }
    }
    impl PageSource for Source {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            assert_eq!(attribute, CacheAttribute::WriteBack);
            let count = self.allocated.fetch_add(1, Ordering::Relaxed) + 1;
            if count == self.fail_at.load(Ordering::Relaxed) {
                return Err(MemoryError::OutOfMemory);
            }
            let length = bytes.next_multiple_of(PAGE);
            let layout = Layout::from_size_align(length, alignment).unwrap();
            // SAFETY: live allocation is owned by Backing until its final Drop.
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            let pages = (0..length / PAGE)
                .map(|index| pointer.as_ptr() as u64 + (index * PAGE) as u64)
                .collect();
            PinnedPages::new(
                Box::new(Backing {
                    pointer,
                    layout,
                    pages,
                    released: self.released.clone(),
                }),
                bytes,
                alignment,
            )
        }
    }

    struct Live {
        info: DomainMapping,
        cpu: CpuMapping,
        _pages: PinnedPages,
        direction: DmaDirection,
    }
    struct DomainState {
        next: u64,
        maps: BTreeMap<u64, Live>,
        sync: Vec<(bool, u64, Range<usize>)>,
        unmaps: usize,
    }
    struct Domain {
        state: Mutex<DomainState>,
        fail_visibility: AtomicBool,
        fail_unmap_at: AtomicUsize,
    }
    impl Domain {
        fn new() -> Self {
            Self {
                state: Mutex::new(DomainState {
                    next: 0x1000,
                    maps: BTreeMap::new(),
                    sync: Vec::new(),
                    unmaps: 0,
                }),
                fail_visibility: AtomicBool::new(false),
                fail_unmap_at: AtomicUsize::new(usize::MAX),
            }
        }
        fn pointer(&self, address: u64, bytes: usize) -> NonNull<u8> {
            let state = self.state.lock().unwrap();
            let (_, live) = state.maps.range(..=address).next_back().unwrap();
            let offset = usize::try_from(address - live.info.address).unwrap();
            live.cpu.address(offset, bytes).unwrap()
        }
        fn read32(&self, address: u64) -> u32 {
            // SAFETY: retained model allocation, aligned bounded access.
            unsafe {
                self.pointer(address, 4)
                    .cast::<u32>()
                    .as_ptr()
                    .read_volatile()
            }
        }
        fn write32(&self, address: u64, value: u32) {
            // SAFETY: serialized modeled device operation within the mapping.
            unsafe {
                self.pointer(address, 4)
                    .cast::<u32>()
                    .as_ptr()
                    .write_volatile(value)
            };
        }
        fn data(&self, address: u64, bytes: usize) -> Vec<u8> {
            let pointer = self.pointer(address, bytes);
            // SAFETY: test runs after publication and before a competing CPU write.
            unsafe { core::slice::from_raw_parts(pointer.as_ptr(), bytes).to_vec() }
        }
        fn write_data(&self, address: u64, bytes: &[u8]) {
            let pointer = self.pointer(address, bytes.len());
            for (index, value) in bytes.iter().enumerate() {
                // SAFETY: serialized modeled DMA within the retained frame.
                unsafe { pointer.as_ptr().add(index).write_volatile(*value) };
            }
        }
    }
    // SAFETY: this is a serialized synthetic domain with nonidentity IOVAs.
    // Every map retains real host RAM; failed unmap retains its reservation.
    unsafe impl DmaDomain for Domain {
        unsafe fn map(
            &self,
            pages: &PinnedPages,
            direction: DmaDirection,
            limit: u64,
        ) -> Result<DomainMapping, DmaError> {
            let mut state = self.state.lock().unwrap();
            let address = state.next;
            if address + pages.bytes() as u64 - 1 > limit {
                return Err(DmaError::AddressLimit);
            }
            state.next += pages.bytes() as u64;
            let info = DomainMapping {
                id: address,
                address,
                bytes: pages.bytes(),
            };
            assert_ne!(address, pages.physical_pages()[0]);
            let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
            state.maps.insert(
                address,
                Live {
                    info,
                    cpu,
                    _pages: pages.clone(),
                    direction,
                },
            );
            Ok(info)
        }
        unsafe fn unmap(&self, info: DomainMapping) -> Result<(), DmaError> {
            let mut state = self.state.lock().unwrap();
            state.unmaps += 1;
            if state.unmaps == self.fail_unmap_at.load(Ordering::Relaxed) {
                return Err(DmaError::InvalidationFailed);
            }
            assert_eq!(state.maps[&info.address].info, info);
            state.maps.remove(&info.address);
            Ok(())
        }
        unsafe fn sync_for_device(
            &self,
            info: DomainMapping,
            range: Range<usize>,
            direction: DmaDirection,
        ) -> Result<(), DmaError> {
            if self.fail_visibility.swap(false, Ordering::Relaxed) {
                return Err(DmaError::VisibilityFailed);
            }
            let mut state = self.state.lock().unwrap();
            assert_eq!(state.maps[&info.address].direction, direction);
            assert!(range.start <= range.end && range.end <= info.bytes);
            state.sync.push((true, info.address, range));
            Ok(())
        }
        unsafe fn sync_for_cpu(
            &self,
            info: DomainMapping,
            range: Range<usize>,
            direction: DmaDirection,
        ) -> Result<(), DmaError> {
            let mut state = self.state.lock().unwrap();
            assert_eq!(state.maps[&info.address].direction, direction);
            assert!(range.start <= range.end && range.end <= info.bytes);
            state.sync.push((false, info.address, range));
            Ok(())
        }
    }

    struct RegisterState {
        values: Vec<u32>,
        writes: Vec<(usize, u32)>,
        reject: Option<usize>,
        failed_read: Option<usize>,
    }
    struct Model {
        state: Mutex<RegisterState>,
        domain: Arc<Domain>,
    }
    impl Model {
        fn new(domain: Arc<Domain>) -> Self {
            let mut values = vec![0; (CAPABILITIES + PAGE) / 4];
            values[CAPABILITIES / 4] = 8;
            Self {
                state: Mutex::new(RegisterState {
                    values,
                    writes: Vec::new(),
                    reject: None,
                    failed_read: None,
                }),
                domain,
            }
        }
        fn descriptor_address(&self, direction: Direction, index: usize) -> u64 {
            let base = match direction {
                Direction::Tx => TX_DESCRIPTOR,
                Direction::Rx => RX_DESCRIPTOR,
            };
            let state = self.state.lock().unwrap();
            (u64::from(state.values[base / 4]) | (u64::from(state.values[base / 4 + 1]) << 32))
                + (index * DESCRIPTOR_BYTES) as u64
        }
        fn frame_address(&self, direction: Direction, index: usize) -> u64 {
            let descriptor = self.descriptor_address(direction, index);
            u64::from(self.domain.read32(descriptor))
                | u64::from(self.domain.read32(descriptor + 4)) << 32
        }
        fn finish(&self, direction: Direction, index: usize, data: &[u8], word: Option<u32>) {
            let descriptor = self.descriptor_address(direction, index);
            let old = self.domain.read32(descriptor + 8);
            let value = if let Some(value) = word {
                value
            } else if direction == Direction::Tx {
                old | (u32::from(COMPLETED) << 20)
            } else {
                (data.len() as u32) | (u32::from(COMPLETED) << 20) | (1 << 12)
            };
            if direction == Direction::Rx {
                self.domain
                    .write_data(self.frame_address(direction, index), data);
            }
            self.domain.write32(descriptor + 8, value);
        }
    }
    // SAFETY: all model register access is serialized under its mutex. It
    // implements hardware-owned index halves and publication observers.
    unsafe impl Registers for Model {
        fn bytes(&self) -> usize {
            self.state.lock().unwrap().values.len() * 4
        }
        fn read32(&self, offset: usize) -> u32 {
            let state = self.state.lock().unwrap();
            if state.failed_read == Some(offset) {
                u32::MAX
            } else {
                state.values[offset / 4]
            }
        }
        fn write32(&self, offset: usize, value: u32) {
            let mut state = self.state.lock().unwrap();
            state.writes.push((offset, value));
            if state.reject == Some(offset) {
                return;
            }
            let old = state.values[offset / 4];
            let direction = if offset == TX_DESCRIPTOR + 8 {
                Some(Direction::Tx)
            } else if offset == RX_DESCRIPTOR + 8 {
                Some(Direction::Rx)
            } else {
                None
            };
            state.values[offset / 4] = match direction {
                Some(Direction::Tx) => old & 0xffff | value & 0xffff_0000,
                Some(Direction::Rx) => old & 0xffff_0000 | value & 0xffff,
                None => value,
            };
            if let Some(direction) = direction {
                let options = match direction {
                    Direction::Tx => TX_OPTIONS,
                    Direction::Rx => RX_OPTIONS,
                };
                if state.values[options / 4] & ENABLE != 0 {
                    let index = match direction {
                        Direction::Tx => old >> 16,
                        Direction::Rx => old & 0xffff,
                    } as usize;
                    let base = match direction {
                        Direction::Tx => TX_DESCRIPTOR,
                        Direction::Rx => RX_DESCRIPTOR,
                    };
                    let descriptor_base = u64::from(state.values[base / 4])
                        | u64::from(state.values[base / 4 + 1]) << 32;
                    let descriptor = descriptor_base + (index * DESCRIPTOR_BYTES) as u64;
                    drop(state);
                    let word = self.domain.read32(descriptor + 8);
                    assert_eq!(
                        (word >> 20) as u16,
                        POSTED,
                        "producer published stale completion or interrupt flags"
                    );
                    assert_eq!(self.domain.read32(descriptor + 12), 0);
                    let sync = self.domain.state.lock().unwrap();
                    assert_eq!(
                        sync.sync.last(),
                        Some(&(
                            true,
                            descriptor_base,
                            index * DESCRIPTOR_BYTES..(index + 1) * DESCRIPTOR_BYTES
                        )),
                        "doorbell preceded descriptor visibility"
                    );
                }
            }
        }
    }

    fn ring(direction: Direction, entries: u16) -> (Source, Arc<Domain>, Arc<Model>, Ring<Model>) {
        let source = Source::new();
        let domain = Arc::new(Domain::new());
        let model = Arc::new(Model::new(domain.clone()));
        // SAFETY: exact exclusively owned stopped synthetic NHI, coherent host RAM,
        // no other engines or callbacks, modeled requester domain and UC registers.
        let ring = unsafe {
            Ring::new(
                model.clone(),
                &source,
                domain.clone(),
                RingConfig {
                    direction,
                    hop: 0,
                    entries,
                    address_limit: u64::MAX,
                },
            )
        }
        .unwrap();
        (source, domain, model, ring)
    }
    fn frame(seed: u32) -> Encoded {
        super::super::config::Request::write(
            super::super::config::Route::new(0).unwrap(),
            super::super::config::Address {
                port: 0,
                space: super::super::config::Space::Router,
                offset: 1,
                words: 1,
            },
            0,
            &[seed],
        )
        .unwrap()
        .frame()
        .clone()
    }
    fn release(ring: &mut Ring<Model>) {
        ring.disable().unwrap();
        // SAFETY: the synthetic device is stopped, no pending model operation,
        // posted DMA, interrupt or worker can reference any mapped allocation.
        unsafe { ring.release() }.unwrap();
    }

    #[test]
    fn tx_publication_full_wrap_and_completion_use_real_nonidentity_dma() {
        let (source, domain, model, mut ring) = ring(Direction::Tx, 4);
        ring.start().unwrap();
        for batch in 0..100u32 {
            for number in 0..3 {
                let packet = frame(batch * 3 + number);
                let index = usize::from(ring.head);
                let ticket = ring.transmit(&packet).unwrap();
                assert_eq!(ticket, u64::from(batch * 3 + number + 1));
                assert_eq!(
                    domain.data(
                        model.frame_address(Direction::Tx, index),
                        packet.bytes.len()
                    ),
                    packet.bytes
                );
            }
            assert_eq!(ring.transmit(&frame(999)), Err(Error::Full));
            for _ in 0..3 {
                let index = usize::from(ring.tail);
                model.finish(Direction::Tx, index, &[], None);
                let completion = ring.poll().unwrap().unwrap();
                assert_eq!(completion.bytes, 20);
            }
            assert!(ring.poll().unwrap().is_none());
        }
        release(&mut ring);
        drop(ring);
        assert!(domain.state.lock().unwrap().maps.is_empty());
        assert_eq!(
            source.released.load(Ordering::Relaxed),
            source.allocated.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn rx_wrap_copies_only_completed_payload_and_preserves_raw_markers() {
        let (source, domain, model, mut ring) = ring(Direction::Rx, 4);
        ring.start().unwrap();
        assert_eq!(model.read32(RX_DESCRIPTOR + 12), 4 | (256 << 16));
        assert_eq!(model.read32(RX_OPTIONS + 4), u32::MAX);
        for batch in 0..90u32 {
            for _ in 0..3 {
                ring.receive().unwrap();
            }
            assert_eq!(ring.receive(), Err(Error::Full));
            assert!(ring.poll().unwrap().is_none());
            for number in 0..3 {
                let bytes = frame(batch * 3 + number).bytes;
                let index = usize::from(ring.tail);
                model.finish(Direction::Rx, index, &bytes, None);
                let actual = ring.poll().unwrap().unwrap();
                assert_eq!(actual.data, bytes);
                assert_eq!((actual.eof, actual.sof), (1, 0));
            }
        }
        release(&mut ring);
        drop(ring);
        assert!(domain.state.lock().unwrap().maps.is_empty());
        assert_eq!(
            source.released.load(Ordering::Relaxed),
            source.allocated.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn invalid_capability_busy_or_short_mapping_refuses_before_allocation_or_writes() {
        for case in 0..6 {
            let source = Source::new();
            let domain = Arc::new(Domain::new());
            let model = Arc::new(Model::new(domain.clone()));
            {
                let mut state = model.state.lock().unwrap();
                match case {
                    0 => state.values[CAPABILITIES / 4] = u32::MAX,
                    1 => state.values[CAPABILITIES / 4] = 0,
                    2 => state.values[TX_OPTIONS / 4] = ENABLE,
                    3 => state.values.truncate(CAPABILITIES / 4),
                    4 => state.values[(TX_DESCRIPTOR + 8) / 4] = 1,
                    _ => state.values[(TX_DESCRIPTOR + 8) / 4] = 1 << 16,
                }
            }
            // SAFETY: exclusively owned synthetic mapping; tests deliberately
            // supply invalid reported bounds/state to exercise preflight.
            assert!(
                unsafe {
                    Ring::new(
                        model.clone(),
                        &source,
                        domain.clone(),
                        RingConfig {
                            direction: Direction::Tx,
                            hop: 0,
                            entries: 4,
                            address_limit: u64::MAX,
                        },
                    )
                }
                .is_err()
            );
            assert_eq!(source.allocated.load(Ordering::Relaxed), 0);
            assert!(model.state.lock().unwrap().writes.is_empty());
            assert!(domain.state.lock().unwrap().maps.is_empty());
        }
    }

    #[test]
    fn unpublished_allocation_failures_reclaim_prior_maps_and_pages() {
        for fail in 1..=5 {
            let source = Source::new();
            source.fail_at.store(fail, Ordering::Relaxed);
            let domain = Arc::new(Domain::new());
            let model = Arc::new(Model::new(domain.clone()));
            // SAFETY: same exclusive stopped synthetic NHI contract.
            assert!(
                unsafe {
                    Ring::new(
                        model.clone(),
                        &source,
                        domain.clone(),
                        RingConfig {
                            direction: Direction::Tx,
                            hop: 0,
                            entries: 4,
                            address_limit: u64::MAX,
                        },
                    )
                }
                .is_err()
            );
            assert_eq!(source.released.load(Ordering::Relaxed), fail - 1);
            assert!(domain.state.lock().unwrap().maps.is_empty());
            assert!(model.state.lock().unwrap().writes.is_empty());
        }
    }

    #[test]
    fn failed_enable_or_doorbell_never_reopens_and_quarantines_published_pins() {
        for offset in [TX_OPTIONS, TX_DESCRIPTOR + 8] {
            let (source, domain, model, mut ring) = ring(Direction::Tx, 4);
            model.state.lock().unwrap().reject = Some(offset);
            let result = if offset == TX_OPTIONS {
                ring.start()
            } else {
                ring.start().unwrap();
                ring.transmit(&frame(3)).map(|_| ())
            };
            assert!(matches!(result, Err(Error::RegisterRejected { .. })));
            let writes = model.state.lock().unwrap().writes.len();
            assert_eq!(ring.transmit(&frame(4)), Err(Error::Poisoned));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            let before = quarantined_rings();
            drop(ring);
            assert!(quarantined_rings() > before);
            assert!(!domain.state.lock().unwrap().maps.is_empty());
            assert!(
                source.released.load(Ordering::Relaxed) < source.allocated.load(Ordering::Relaxed)
            );
        }
    }

    #[test]
    fn invalid_rx_flags_address_or_length_cannot_authorize_buffer_reuse() {
        for case in 0..4 {
            let (_source, _domain, model, mut ring) = ring(Direction::Rx, 4);
            ring.start().unwrap();
            ring.receive().unwrap();
            let word = match case {
                0 => (u32::from(COMPLETED | 0x10) << 20) | 16,
                1 => (u32::from(COMPLETED | 0x20) << 20) | 16,
                2 => u32::from(COMPLETED) << 20,
                _ => (u32::from(COMPLETED) << 20) | 16,
            };
            model.finish(Direction::Rx, 0, &[0; 16], Some(word));
            if case == 3 {
                model
                    .domain
                    .write32(model.descriptor_address(Direction::Rx, 0), 0xdead_0000);
            }
            assert!(ring.poll().is_err());
            let writes = model.state.lock().unwrap().writes.len();
            assert_eq!(ring.receive(), Err(Error::Poisoned));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        }
    }

    #[test]
    fn failed_visibility_prevents_doorbell_and_final_unmap_failure_retains_retry() {
        let (_source, _domain, model, mut ring) = ring(Direction::Tx, 4);
        ring.start().unwrap();
        let writes = model.state.lock().unwrap().writes.len();
        model.domain.fail_visibility.store(true, Ordering::Relaxed);
        assert_eq!(
            ring.transmit(&frame(1)),
            Err(Error::Dma(DmaError::VisibilityFailed))
        );
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        release(&mut ring);

        let (source, domain, _model, mut ring) = self::ring(Direction::Rx, 4);
        ring.start().unwrap();
        ring.disable().unwrap();
        domain.fail_unmap_at.store(2, Ordering::Relaxed);
        // SAFETY: stopped empty synthetic device; no outstanding DMA/IRQ/work.
        assert_eq!(
            unsafe { ring.release() },
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(domain.state.lock().unwrap().maps.len(), 4);
        assert_eq!(source.released.load(Ordering::Relaxed), 0);
        // SAFETY: same proven quiescence, failed mapping remains reserved.
        unsafe { ring.release() }.unwrap();
        drop(ring);
        assert!(domain.state.lock().unwrap().maps.is_empty());
        assert_eq!(source.released.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn disable_ignores_hardware_consumer_but_checks_software_producer() {
        for direction in [Direction::Tx, Direction::Rx] {
            let (_source, _domain, model, mut ring) = self::ring(direction, 4);
            ring.start().unwrap();
            let base = if direction == Direction::Tx {
                TX_DESCRIPTOR
            } else {
                RX_DESCRIPTOR
            };
            model.state.lock().unwrap().values[(base + 8) / 4] = if direction == Direction::Tx {
                3
            } else {
                3 << 16
            };
            // The source-defined read-only consumer half survives every CPU write.
            release(&mut ring);
            assert_eq!(
                model.read32(base + 8),
                if direction == Direction::Tx {
                    3
                } else {
                    3 << 16
                }
            );
        }
    }

    #[test]
    fn raw_rx_preserves_posted_and_frame_mode_aliases_in_completed_descriptors() {
        for flags in 0..16u16 {
            let (_source, _domain, model, mut ring) = self::ring(Direction::Rx, 4);
            ring.start().unwrap();
            ring.receive().unwrap();
            model.finish(
                Direction::Rx,
                0,
                &[0x45; 16],
                Some((u32::from(flags | COMPLETED) << 20) | (1 << 12) | 16),
            );
            let completed = ring.poll().unwrap().unwrap();
            assert_eq!(completed.flags, flags | COMPLETED);
            assert_eq!(completed.data, vec![0x45; 16]);
            release(&mut ring);
        }
    }
}
