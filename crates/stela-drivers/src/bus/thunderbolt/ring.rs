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

    fn channel() -> (
        Source,
        Arc<Domain>,
        Arc<Model>,
        super::super::channel::Channel<Model>,
    ) {
        let source = Source::new();
        let domain = Arc::new(Domain::new());
        let model = Arc::new(Model::new(domain.clone()));
        // SAFETY: same synthetic ownership and coherent requester-domain contract;
        // neither physical firmware nor another actor owns either hop-zero ring.
        let channel = unsafe {
            super::super::channel::Channel::new(model.clone(), &source, domain.clone(), u64::MAX)
        }
        .unwrap();
        (source, domain, model, channel)
    }
    fn cfg_address() -> super::super::config::Address {
        super::super::config::Address {
            port: 2,
            space: super::super::config::Space::Router,
            offset: 19,
            words: 1,
        }
    }
    fn incoming(kind: PacketType, words: &[u32]) -> Encoded {
        let mut bytes = Vec::new();
        for word in words {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        let crc = super::super::config::crc32c(&bytes);
        bytes.extend_from_slice(&crc.to_be_bytes());
        Encoded { kind, bytes }
    }
    fn finish_rx(model: &Model, index: usize, frame: &Encoded) {
        model.finish(
            Direction::Rx,
            index,
            &frame.bytes,
            Some(
                (u32::from(COMPLETED) << 20)
                    | ((frame.kind as u32) << 12)
                    | (frame.bytes.len() as u32),
            ),
        );
    }
    fn channel_release(channel: &mut super::super::channel::Channel<Model>) {
        channel.disable().unwrap();
        // SAFETY: actual synthetic device/posted DMA/IRQ/work fully drained.
        unsafe { channel.release() }.unwrap();
    }

    #[test]
    fn configuration_channel_owns_actual_ring_dma_and_wraps_sequence_and_rings() {
        use super::super::{
            channel::{Error as ChannelError, Event},
            config::{Reply, Route},
        };
        let (source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let writes = &model.state.lock().unwrap().writes.clone();
        let rx_enable = writes
            .iter()
            .position(|(offset, value)| *offset == RX_OPTIONS && *value == ENABLE | RAW)
            .unwrap();
        let tx_enable = writes
            .iter()
            .position(|(offset, value)| *offset == TX_OPTIONS && *value == ENABLE | RAW)
            .unwrap();
        assert!(rx_enable < tx_enable);
        for cycle in 0..24u32 {
            let now = u64::from(cycle);
            let id = channel
                .read(Route::new(19).unwrap(), cfg_address(), now, now + 100)
                .unwrap();
            assert_eq!(id, now + 1);
            let before = model.state.lock().unwrap().writes.len();
            assert_eq!(
                channel.read(Route::new(20).unwrap(), cfg_address(), now, now + 100),
                Err(ChannelError::Busy)
            );
            assert_eq!(before, model.state.lock().unwrap().writes.len());
            let transmitted = domain.data(
                model.frame_address(Direction::Tx, (cycle % 10) as usize),
                16,
            );
            let address = u32::from_be_bytes(transmitted[8..12].try_into().unwrap());
            assert_eq!((address >> 27) & 3, cycle & 3);
            assert_eq!(&transmitted[..8], &[0, 0, 0, 0, 0, 0, 0, 19]);
            model.finish(Direction::Tx, (cycle % 10) as usize, &[], None);
            let reply = incoming(PacketType::Read, &[1 << 31, 19, address, cycle]);
            finish_rx(&model, (cycle % 10) as usize, &reply);
            assert_eq!(
                channel.poll(now).unwrap(),
                Some(Event::Completed {
                    request: id,
                    reply: Reply::Configuration {
                        upstream_port: 2,
                        data: vec![cycle]
                    }
                })
            );
        }
        channel_release(&mut channel);
        drop(channel);
        assert!(domain.state.lock().unwrap().maps.is_empty());
        assert_eq!(
            source.allocated.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn unrelated_corrupt_and_asynchronous_packets_do_not_finish_outstanding_request() {
        use super::super::{
            channel::{Error as ChannelError, Event},
            config::{Reply, Route},
        };
        let (_source, domain, model, mut channel) = channel();
        channel.start(1).unwrap();
        let id = channel
            .read(Route::new(19).unwrap(), cfg_address(), 1, 100)
            .unwrap();
        let transmitted = domain.data(model.frame_address(Direction::Tx, 0), 16);
        let address = u32::from_be_bytes(transmitted[8..12].try_into().unwrap());
        let wrong = incoming(PacketType::Read, &[1 << 31, 19, address ^ (1 << 27), 55]);
        finish_rx(&model, 0, &wrong);
        assert_eq!(
            channel.poll(2).unwrap(),
            Some(Event::Discarded(
                super::super::config::Error::UnexpectedReply
            ))
        );
        let mut corrupt = incoming(PacketType::Read, &[1 << 31, 19, address, 55]);
        corrupt.bytes[12] ^= 1;
        finish_rx(&model, 1, &corrupt);
        assert_eq!(
            channel.poll(3).unwrap(),
            Some(Event::Discarded(super::super::config::Error::Checksum))
        );
        let plug = incoming(PacketType::Event, &[0, 7, 6]);
        finish_rx(&model, 2, &plug);
        assert!(
            matches!(channel.poll(4).unwrap(),Some(Event::Plug(event)) if event.route.raw()==7 && event.port==6)
        );
        let plug_ack = domain.data(model.frame_address(Direction::Tx, 1), 16);
        assert_eq!(&plug_ack[..12], &[0, 0, 0, 0, 0, 0, 0, 7, 0x80, 0, 6, 7]);
        let notice = incoming(PacketType::Error, &[0, 8, 35 | (4 << 8)]);
        finish_rx(&model, 3, &notice);
        assert!(
            matches!(channel.poll(5).unwrap(),Some(Event::Notification(event)) if event.route.raw()==8 && event.code==35)
        );
        let notification_ack = domain.data(model.frame_address(Direction::Tx, 2), 12);
        assert_eq!(&notification_ack[..8], &[0, 0, 0, 0, 0, 0, 0, 8]);
        let before = model.state.lock().unwrap().writes.len();
        assert_eq!(
            channel.read(Route::new(1).unwrap(), cfg_address(), 6, 50),
            Err(ChannelError::Busy)
        );
        assert_eq!(before, model.state.lock().unwrap().writes.len());
        let upstream_error = incoming(PacketType::Error, &[1 << 31, 0, 15 | (9 << 8)]);
        finish_rx(&model, 4, &upstream_error);
        assert!(
            matches!(channel.poll(6).unwrap(),Some(Event::Completed { request,reply:Reply::ControllerError { route,port:9,code:15,.. } }) if request==id && route.raw()==0)
        );
        channel_release(&mut channel);
    }

    #[test]
    fn channel_timeout_cancel_and_clock_regression_never_reuse_ambiguous_dma() {
        use super::super::{channel::Error as ChannelError, config::Route};
        for case in 0..3 {
            let (_source, _domain, model, mut channel) = channel();
            channel.start(5).unwrap();
            let id = channel
                .read(Route::new(0).unwrap(), cfg_address(), 5, 10)
                .unwrap();
            let writes = model.state.lock().unwrap().writes.len();
            match case {
                0 => assert_eq!(channel.poll(10), Err(ChannelError::Timeout { request: id })),
                1 => assert_eq!(channel.cancel(), Ok(Some(id))),
                _ => assert_eq!(channel.poll(4), Err(ChannelError::ClockRegressed)),
            }
            assert_eq!(
                channel.read(Route::new(0).unwrap(), cfg_address(), 11, 30),
                Err(ChannelError::Poisoned)
            );
            assert_eq!(channel.poll(11), Err(ChannelError::Poisoned));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            channel_release(&mut channel);
        }
    }

    #[test]
    fn full_ack_ring_retains_event_and_defers_rx_until_actual_tx_completion() {
        use super::super::{channel::Event, config::Route};
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let id = channel
            .read(Route::new(19).unwrap(), cfg_address(), 0, 100)
            .unwrap();
        let sent = domain.data(model.frame_address(Direction::Tx, 0), 16);
        let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
        for index in 0..9 {
            let plug = incoming(PacketType::Event, &[0, 7, index as u32]);
            finish_rx(&model, index, &plug);
            let result = channel.poll(1).unwrap();
            if index < 8 {
                assert!(matches!(result, Some(Event::Plug(_))));
            } else {
                assert_eq!(result, None);
            }
        }
        let reply = incoming(PacketType::Read, &[1 << 31, 19, address, 77]);
        finish_rx(&model, 9, &reply);
        let before = model.state.lock().unwrap().writes.len();
        assert_eq!(channel.poll(2).unwrap(), None);
        assert_eq!(model.state.lock().unwrap().writes.len(), before);
        model.finish(Direction::Tx, 0, &[], None);
        assert!(matches!(channel.poll(3).unwrap(),Some(Event::Plug(event)) if event.port==8));
        assert!(
            matches!(channel.poll(4).unwrap(),Some(Event::Completed { request,.. }) if request==id)
        );
        channel_release(&mut channel);
    }

    #[test]
    fn channel_partial_final_invalidation_can_retry_after_one_ring_is_released() {
        let (source, domain, _model, mut channel) = channel();
        channel.start(0).unwrap();
        channel.disable().unwrap();
        domain.fail_unmap_at.store(12, Ordering::Relaxed);
        // SAFETY: no synthetic activity survives the containing final drain.
        assert_eq!(
            unsafe { channel.release() },
            Err(super::super::channel::Error::Ring(Error::Dma(
                DmaError::InvalidationFailed
            )))
        );
        // Repeating disable cannot touch an already-released TX ring or lose
        // the RX invalidation retry; both outcomes previously succeeded.
        channel.disable().unwrap();
        // SAFETY: the same acknowledged final synthetic drain still applies.
        unsafe { channel.release() }.unwrap();
        drop(channel);
        assert!(domain.state.lock().unwrap().maps.is_empty());
        assert_eq!(
            source.allocated.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
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

    #[test]
    fn inspector_reads_actual_router_adapter_and_capability_dma_without_control_adapter_zero() {
        use super::super::{
            config::Route,
            topology::{AdapterKind, AdapterObservation, Event, Inspector},
        };
        let (source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let mut inspector = Inspector::new(channel, 100, 64).unwrap();
        assert_eq!(
            inspector.begin(Route::new(1).unwrap(), 0),
            Err(super::super::topology::Error::RootRequired)
        );
        inspector.begin(Route::new(0).unwrap(), 0).unwrap();
        let mut adapter1 = vec![0; 8];
        adapter1[1] = 0x10;
        adapter1[2] = 1;
        adapter1[3] = 1 << 20;
        adapter1[4] = 19 | (67 << 20);
        adapter1[5] = 31 | (63 << 11);
        let mut adapter3 = vec![0; 8];
        adapter3[2] = 0xabcdef;
        adapter3[3] = 3 << 20;
        // (space,port,offset,words,reply-data/error). Every expected request is
        // decoded from the driver's actual mapped TX frame, not a mock RPC.
        type InspectStep = (u32, u32, u32, u32, Result<Vec<u32>, u32>);
        let steps: Vec<InspectStep> = vec![
            (
                2,
                0,
                0,
                5,
                Ok(vec![0x12348086, 0x20 | (3 << 14), 0, 0, 1 << 29]),
            ),
            (2, 0, 0x20, 2, Ok(vec![0x330, 0x12345678])),
            (2, 0, 0x30, 2, Ok(vec![0x02010500, 0xabcd])),
            (1, 1, 0, 8, Ok(adapter1)),
            (1, 1, 0x10, 1, Ok(vec![0x120])),
            (1, 1, 0x20, 1, Ok(vec![0x600])),
            (1, 2, 0, 8, Err(2)),
            (1, 3, 0, 8, Ok(adapter3)),
        ];
        let mut result = None;
        for (index, (space, port, offset, words, data)) in steps.into_iter().enumerate() {
            let sent = domain.data(model.frame_address(Direction::Tx, index % 10), 16);
            let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
            assert_eq!((address >> 25) & 3, space);
            assert_eq!((address >> 19) & 63, port);
            assert_eq!(address & 0x1fff, offset);
            assert_eq!((address >> 13) & 63, words);
            assert!(!(space == 1 && port == 0));
            model.finish(Direction::Tx, index % 10, &[], None);
            let response = match data {
                Ok(data) => {
                    let mut words = vec![1 << 31, 0, address & !(63 << 19)];
                    words.extend(data);
                    incoming(PacketType::Read, &words)
                }
                Err(code) => incoming(PacketType::Error, &[1 << 31, 0, code]),
            };
            finish_rx(&model, index % 10, &response);
            result = inspector.poll(index as u64 + 1).unwrap();
            if index < 7 {
                assert_eq!(result, None);
            }
        }
        let Some(Event::Inventory(inventory)) = result else {
            panic!("inventory")
        };
        assert_eq!(inventory.header.vendor(), 0x8086);
        assert_eq!(inventory.header.device(), 0x1234);
        assert_eq!(inventory.header.usb4_version(), 1);
        assert_eq!(inventory.capabilities.len(), 2);
        assert_eq!(inventory.capabilities[1].vendor_specific, Some(1));
        assert_eq!(inventory.capabilities[0].raw, vec![0x330, 0x12345678]);
        assert_eq!(inventory.adapters.len(), 3);
        let AdapterObservation::Present {
            header,
            capabilities,
            ..
        } = &inventory.adapters[0]
        else {
            panic!("adapter1")
        };
        assert_eq!(header.kind(), AdapterKind::Lane);
        assert_eq!((header.max_in_hop(), header.max_out_hop()), (31, 63));
        assert_eq!((header.nonflow_buffers(), header.total_buffers()), (19, 67));
        assert_eq!(
            capabilities.iter().map(|cap| cap.id).collect::<Vec<_>>(),
            vec![1, 6]
        );
        assert!(matches!(
            inventory.adapters[1],
            AdapterObservation::Unimplemented {
                port: 2,
                raw: 2,
                ..
            }
        ));
        assert!(
            matches!(&inventory.adapters[2],AdapterObservation::Present { header,.. } if header.kind()==AdapterKind::Unknown(0xabcdef))
        );
        let mut channel = inspector.into_channel();
        channel_release(&mut channel);
        drop(channel);
        assert!(domain.state.lock().unwrap().maps.is_empty());
        assert_eq!(
            source.allocated.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn inspector_rejects_capability_cycles_and_hotplug_stale_snapshot_before_new_reads() {
        use super::super::{
            config::Route,
            topology::{Error as InspectError, Event, Inspector},
        };
        for case in 0..3 {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let mut inspector = Inspector::new(channel, 100, 64).unwrap();
            inspector.begin(Route::new(0).unwrap(), 0).unwrap();
            if case == 2 {
                let event = incoming(PacketType::Event, &[0, 0, 1]);
                finish_rx(&model, 0, &event);
                assert!(matches!(inspector.poll(1).unwrap(), Some(Event::Plug(_))));
            }
            let sent = domain.data(model.frame_address(Direction::Tx, 0), 16);
            let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
            model.finish(Direction::Tx, 0, &[], None);
            let response = incoming(
                PacketType::Read,
                &[
                    1 << 31,
                    0,
                    address,
                    0x12348086,
                    if case == 1 { 4 } else { 0x20 },
                    0,
                    0,
                    1 << 29,
                ],
            );
            finish_rx(&model, if case == 2 { 1 } else { 0 }, &response);
            if case == 2 {
                assert_eq!(inspector.poll(2), Err(InspectError::TopologyChanged));
            } else if case == 1 {
                assert_eq!(inspector.poll(2), Err(InspectError::CapabilityOffset(4)));
            } else {
                assert_eq!(inspector.poll(2).unwrap(), None);
                let sent = domain.data(model.frame_address(Direction::Tx, 1), 16);
                let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
                model.finish(Direction::Tx, 1, &[], None);
                let response = incoming(PacketType::Read, &[1 << 31, 0, address, 0x320, 0]);
                finish_rx(&model, 1, &response);
                assert_eq!(inspector.poll(3), Err(InspectError::CapabilityLoop(0x20)));
            }
            let writes = model.state.lock().unwrap().writes.len();
            assert_eq!(inspector.poll(4).unwrap(), None);
            assert_eq!(writes, model.state.lock().unwrap().writes.len());
            let mut channel = inspector.into_channel();
            channel_release(&mut channel);
        }
    }

    #[test]
    fn inspector_refuses_exact_legacy_tmu_quirks_before_any_capability_or_adapter_access() {
        use super::super::{
            config::Route,
            topology::{Error as InspectError, Inspector},
        };
        for device in [0x1513u16, 0x151a] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let mut inspector = Inspector::new(channel, 100, 64).unwrap();
            inspector.begin(Route::new(0).unwrap(), 0).unwrap();
            let sent = domain.data(model.frame_address(Direction::Tx, 0), 16);
            let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
            model.finish(Direction::Tx, 0, &[], None);
            let reply = incoming(
                PacketType::Read,
                &[
                    1 << 31,
                    0,
                    address,
                    0x8086 | (u32::from(device) << 16),
                    0x20 | (3 << 14),
                    0,
                    0,
                    0,
                ],
            );
            finish_rx(&model, 0, &reply);
            assert_eq!(
                inspector.poll(1),
                Err(InspectError::LegacyTmuAccess {
                    vendor: 0x8086,
                    device
                })
            );
            assert_eq!(
                model.read32(TX_DESCRIPTOR + 8) >> 16,
                1,
                "no second request may be published"
            );
            let writes = model.state.lock().unwrap().writes.len();
            assert_eq!(inspector.poll(2).unwrap(), None);
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            let mut channel = inspector.into_channel();
            channel_release(&mut channel);
        }
    }

    #[test]
    fn inventory_tx_publication_deadline_does_not_move_when_dma_consumer_stalls() {
        use super::super::{
            channel::Error as ChannelError,
            config::Route,
            topology::{Error as InspectError, Inspector},
        };
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let mut inspector = Inspector::new(channel, 10, 64).unwrap();
        inspector.begin(Route::new(0).unwrap(), 0).unwrap();
        for index in 0..9 {
            let sent = domain.data(model.frame_address(Direction::Tx, index), 16);
            let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
            // The synthetic wire peer replies, but NHI never acknowledges any
            // TX DMA descriptor. Nine real transmitted slots fill the ring.
            let mut words = vec![1 << 31, 0, address & !(63 << 19)];
            if index == 0 {
                words.extend([0x12348086, 10 << 14, 0, 0, 1 << 29]);
            } else {
                words.extend([0; 8]);
            }
            finish_rx(&model, index, &incoming(PacketType::Read, &words));
            assert_eq!(inspector.poll(index as u64).unwrap(), None);
        }
        assert_eq!(model.read32(TX_DESCRIPTOR + 8) >> 16, 9);
        let writes = model.state.lock().unwrap().writes.len();
        for now in 9..18 {
            assert_eq!(inspector.poll(now).unwrap(), None);
        }
        assert_eq!(
            inspector.poll(18),
            Err(InspectError::PublicationTimeout {
                route: Route::new(0).unwrap(),
                port: 9,
                offset: 0
            })
        );
        assert_eq!(
            inspector.poll(19),
            Err(InspectError::Channel(ChannelError::Poisoned))
        );
        assert_eq!(
            inspector.begin(Route::new(0).unwrap(), 19),
            Err(InspectError::Channel(ChannelError::Poisoned))
        );
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = inspector.into_channel();
        channel_release(&mut channel);
    }

    struct HopOwner {
        target: super::super::hop::Target,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for HopOwner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: the model exclusively reserves this exact synthetic hop/router;
    // its Arc is the allocation lifetime, no other model actor reconfigures it.
    unsafe impl super::super::hop::Owner for HopOwner {
        fn target(&self) -> super::super::hop::Target {
            self.target
        }
    }
    fn hop_response(domain: &Domain, model: &Model, index: usize, data: &[u32]) -> Encoded {
        let word = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((word >> 12) & 15) as u8).unwrap();
        let sent = domain.data(
            model.frame_address(Direction::Tx, index),
            (word & 0xfff) as usize,
        );
        let route_hi = u32::from_be_bytes(sent[..4].try_into().unwrap());
        let route_lo = u32::from_be_bytes(sent[4..8].try_into().unwrap());
        let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
        assert_eq!((address >> 25) & 3, 0, "must use actual path config space");
        assert_eq!(address & 0x1fff, 16);
        assert_eq!((address >> 19) & 63, 1);
        assert_eq!((address >> 13) & 63, 2);
        let mut words = vec![route_hi | (1 << 31), route_lo, address & !(63 << 19)];
        words.extend_from_slice(data);
        incoming(kind, &words)
    }
    #[test]
    fn actual_hop_disable_pending_drain_and_flow_clear_preserve_usb4_vendor_ingress() {
        use super::super::{
            config::Route,
            hop::{Event, Target, Teardown, Words},
            topology::AdapterKind,
        };
        for (usb4, kind) in [
            (true, AdapterKind::Lane),
            (true, AdapterKind::PcieDown),
            (false, AdapterKind::PcieDown),
        ] {
            for clear_flow_control in [false, true] {
                let (_source, domain, model, mut channel) = channel();
                channel.start(0).unwrap();
                let dropped = Arc::new(AtomicUsize::new(0));
                let target = Target {
                    route: Route::new(0).unwrap(),
                    port: 1,
                    hop: 8,
                    kind,
                    usb4,
                    clear_flow_control,
                };
                let owner = Arc::new(HopOwner {
                    target,
                    dropped: dropped.clone(),
                });
                // SAFETY: this exact synthetic Owner and Channel share the same
                // exclusive NHI/model requester, reservation and reset epoch;
                // its observed adapter metadata is unchanged and channel idle.
                let mut teardown = unsafe { Teardown::new(channel, owner.clone(), 0) }.unwrap();
                assert_eq!(teardown.poll(0).unwrap(), None);
                let initial = [0x81012345, 0x1f5abcde];
                let disabled = [initial[0] & !(1 << 31), initial[1]];
                let drained = [disabled[0], disabled[1] & !(1 << 28)];
                let clear_mask = (1 << 25)
                    | (1 << 27)
                    | if kind == AdapterKind::Lane || !usb4 {
                        (1 << 24) | (1 << 26)
                    } else {
                        0
                    };
                let cleared = [drained[0], drained[1] & !clear_mask];
                let mut result = None;
                let steps = if clear_flow_control { 6 } else { 4 };
                for index in 0..steps {
                    let sent = domain.data(
                        model.frame_address(Direction::Tx, index),
                        if index == 1 || index == 4 { 24 } else { 16 },
                    );
                    if index == 1 || index == 4 {
                        let expected = if index == 1 { disabled } else { cleared };
                        let actual: Vec<_> = sent[12..20]
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|raw| u32::from_be_bytes(*raw))
                            .collect();
                        assert_eq!(actual, expected);
                    }
                    let data: &[u32] = match index {
                        0 => &initial,
                        1 | 4 => &[],
                        2 => &disabled,
                        3 => &drained,
                        5 => &cleared,
                        _ => unreachable!(),
                    };
                    let reply = hop_response(&domain, &model, index, data);
                    model.finish(Direction::Tx, index, &[], None);
                    finish_rx(&model, index, &reply);
                    result = teardown.poll(index as u64 + 1).unwrap();
                    if index < steps - 1 {
                        assert_eq!(result, None);
                    }
                }
                let Some(Event::Drained(receipt)) = result else {
                    panic!("drain receipt")
                };
                assert_eq!(receipt.before, Words { raw: initial });
                assert_eq!(
                    receipt.after,
                    Words {
                        raw: if clear_flow_control { cleared } else { drained }
                    }
                );
                assert_eq!(teardown.poll(20), Err(super::super::hop::Error::Stopped));
                let mut channel = teardown.into_channel();
                drop(owner);
                assert_eq!(dropped.load(Ordering::Relaxed), 1);
                channel_release(&mut channel);
            }
        }
    }

    #[test]
    fn uncertain_hop_pending_or_rejected_disable_retains_allocation_and_poisoned_channel() {
        use super::super::{
            channel::Error as ChannelError,
            config::Route,
            hop::{Error as HopError, Target, Teardown},
            topology::AdapterKind,
        };
        for reject in [false, true] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let dropped = Arc::new(AtomicUsize::new(0));
            let target = Target {
                route: Route::new(0).unwrap(),
                port: 1,
                hop: 8,
                kind: AdapterKind::Lane,
                usb4: true,
                clear_flow_control: true,
            };
            let owner = Arc::new(HopOwner {
                target,
                dropped: dropped.clone(),
            });
            let before = super::super::hop::quarantined_hops();
            // SAFETY: this exact synthetic Owner and Channel share the same
            // exclusive NHI/model requester, reservation and reset epoch;
            // its observed adapter metadata is unchanged and channel idle.
            let mut teardown = unsafe { Teardown::new(channel, owner.clone(), 0) }.unwrap();
            teardown.poll(0).unwrap();
            let initial = [1 << 31, 0x1f000000];
            for index in 0..2 {
                let reply = hop_response(
                    &domain,
                    &model,
                    index,
                    if index == 0 { &initial } else { &[] },
                );
                model.finish(Direction::Tx, index, &[], None);
                finish_rx(&model, index, &reply);
                assert_eq!(teardown.poll(index as u64 + 1).unwrap(), None);
            }
            let response = if reject { initial } else { [0, 1 << 28] };
            let reply = hop_response(&domain, &model, 2, &response);
            model.finish(Direction::Tx, 2, &[], None);
            finish_rx(&model, 2, &reply);
            if reject {
                assert_eq!(teardown.poll(3), Err(HopError::Readback));
            } else {
                assert_eq!(teardown.poll(3).unwrap(), None);
                assert_eq!(teardown.poll(500), Err(HopError::Timeout));
            }
            let writes = model.state.lock().unwrap().writes.len();
            assert_eq!(teardown.poll(501), Err(HopError::Poisoned));
            let mut channel = teardown.into_channel();
            assert!(super::super::hop::quarantined_hops() > before);
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            assert_eq!(
                channel.read(Route::new(0).unwrap(), cfg_address(), 501, 600),
                Err(ChannelError::Poisoned)
            );
            assert_eq!(writes, model.state.lock().unwrap().writes.len());
            channel_release(&mut channel);
        }
    }

    #[test]
    fn already_disabled_hop_is_observed_without_fabricated_flow_control_writes() {
        use super::super::{
            config::Route,
            hop::{Event, Target, Teardown},
            topology::AdapterKind,
        };
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let target = Target {
            route: Route::new(0).unwrap(),
            port: 1,
            hop: 8,
            kind: AdapterKind::Lane,
            usb4: true,
            clear_flow_control: true,
        };
        let owner = Arc::new(HopOwner {
            target,
            dropped: dropped.clone(),
        });
        // SAFETY: this exact synthetic Owner and Channel share the same
        // exclusive NHI/model requester, reservation and reset epoch;
        // its observed adapter metadata is unchanged and channel idle.
        let mut teardown = unsafe { Teardown::new(channel, owner.clone(), 0) }.unwrap();
        teardown.poll(0).unwrap();
        let words = [0x12345, 0x0f0abcde];
        let reply = hop_response(&domain, &model, 0, &words);
        model.finish(Direction::Tx, 0, &[], None);
        finish_rx(&model, 0, &reply);
        assert!(
            matches!(teardown.poll(1).unwrap(),Some(Event::Drained(receipt)) if receipt.before.raw==words && receipt.after.raw==words)
        );
        assert_eq!(model.read32(TX_DESCRIPTOR + 8) >> 16, 1);
        let mut channel = teardown.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
    struct IcmPci {
        device: u16,
        command: u32,
    }
    impl crate::bus::pci::ConfigSpace for IcmPci {
        fn read32(&self, offset: u16) -> u32 {
            match offset {
                0 => (u32::from(self.device) << 16) | 0x8086,
                4 => self.command,
                8 => 0x0c034000,
                0x0c => 0,
                _ => u32::MAX,
            }
        }
        fn write32(&mut self, _: u16, _: u32) {
            panic!("ICM must not alter PCI admission");
        }
    }
    fn icm(
        device: u16,
    ) -> (
        Source,
        Arc<Domain>,
        Arc<Model>,
        super::super::icm::Host<Model>,
    ) {
        let source = Source::new();
        let domain = Arc::new(Domain::new());
        let model = Arc::new(Model::new(domain.clone()));
        model.state.lock().unwrap().values[0x39944 / 4] = 0x80000001;
        model.state.lock().unwrap().values[0x3990c / 4] = 3 << 8;
        // SAFETY: exact synthetic requester/epoch owns stopped rings and coherent
        // mappings; firmware is the modeled ICM peer, never a ring programmer.
        let host = unsafe {
            super::super::icm::Host::new(
                &IcmPci { device, command: 6 },
                model.clone(),
                &source,
                domain.clone(),
                u64::MAX,
            )
        }
        .unwrap();
        (source, domain, model, host)
    }
    fn icm_release(host: &mut super::super::icm::Host<Model>) {
        host.disable().unwrap();
        // SAFETY: modeled physical DMA/IRQ/work is finally drained.
        unsafe { host.release() }.unwrap();
    }
    #[test]
    fn icm_actual_dma_driver_ready_and_raw_notification_wrap_rings() {
        use super::super::icm::{Event, Security};
        let (_source, domain, model, mut host) = icm(0x15e8);
        host.start(0).unwrap();
        let mut rx = 0;
        for index in 0..25 {
            let request = host.driver_ready(index * 2).unwrap();
            let txindex = index as usize % 10;
            let wire = domain.data(model.frame_address(Direction::Tx, txindex), 8);
            assert_eq!(wire, incoming(PacketType::IcmCommand, &[3]).bytes);
            let descriptor = domain.read32(model.descriptor_address(Direction::Tx, txindex) + 8);
            assert_eq!((descriptor >> 12) & 0xf, 11);
            assert_eq!((descriptor >> 16) & 0xf, 11);
            model.finish(Direction::Tx, txindex, &[], None);
            if index == 0 {
                let mut event = incoming(PacketType::IcmEvent, &[0x00fe_40fe, 0xdeadbeef]);
                let len = event.bytes.len();
                event.bytes[len - 4..].copy_from_slice(&[1, 2, 3, 4]);
                model.finish(
                    Direction::Rx,
                    rx,
                    &event.bytes,
                    Some((2 << 20) | (15 << 16) | (10 << 12) | (len as u32)),
                );
                match host.poll(1).unwrap().unwrap() {
                    Event::Notification(m) => {
                        assert_eq!(m.code, 0xfe);
                        assert_eq!(m.sof, 15);
                        assert_eq!(m.unverified_trailer, [1, 2, 3, 4]);
                    }
                    other => panic!("{other:?}"),
                }
                rx = (rx + 1) % 10;
                assert_eq!(host.driver_ready(1), Err(super::super::icm::Error::Busy));
            }
            let reply = incoming(
                PacketType::IcmResponse,
                &[0x01004003, 0x00920000, 0x12345678, 0xabcdef01],
            );
            finish_rx(&model, rx, &reply);
            rx = (rx + 1) % 10;
            match host.poll(index * 2 + 1).unwrap().unwrap() {
                Event::DriverReady {
                    request: id,
                    parameters,
                } => {
                    assert_eq!(id, request);
                    assert_eq!(parameters.security, Some(Security::Secure));
                    assert_eq!(parameters.protocol_version, Some(1));
                    assert_eq!(parameters.boot_acl_slots, Some(1));
                    assert!(parameters.runtime_pm);
                }
                other => panic!("{other:?}"),
            }
        }
        icm_release(&mut host);
    }
    #[test]
    fn icm_timeout_never_reuses_ambiguous_firmware_code() {
        use super::super::icm::Error;
        for (device, timeout) in [
            (0x1575, 5000),
            (0x15e8, 250),
            (0x1134, 250),
            (0x8a0d, 20000),
        ] {
            let (_source, _domain, model, mut host) = icm(device);
            host.start(100).unwrap();
            let id = host.driver_ready(100).unwrap();
            assert!(host.poll(100 + timeout - 1).unwrap().is_none());
            assert_eq!(
                host.poll(100 + timeout),
                Err(Error::Timeout { request: id })
            );
            assert_eq!(host.driver_ready(101 + timeout), Err(Error::Poisoned));
            let writes = model.state.lock().unwrap().writes.len();
            assert_eq!(host.poll(102 + timeout), Err(Error::Poisoned));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            icm_release(&mut host);
        }
    }
    #[test]
    fn icm_firmware_error_and_epoch_observation_loss_poison() {
        use super::super::icm::Error;
        for loss in [false, true] {
            let (_source, _domain, model, mut host) = icm(0x9a1b);
            host.start(0).unwrap();
            host.driver_ready(0).unwrap();
            finish_rx(
                &model,
                0,
                &incoming(PacketType::IcmResponse, &[0x01000103, 0, 0, 0]),
            );
            if loss {
                model.state.lock().unwrap().values[0x39944 / 4] = 0;
            }
            assert_eq!(
                host.poll(1),
                Err(if loss {
                    Error::FirmwareNotAuthenticated
                } else {
                    Error::FirmwareError(1)
                })
            );
            assert_eq!(host.driver_ready(2), Err(Error::Poisoned));
            icm_release(&mut host);
        }
    }
    #[test]
    fn icm_prerequisites_refuse_before_any_ring_programming() {
        use super::super::icm::{Error, Host};
        for (device, command, status, mode, expected) in [
            (0xdead, 6, 0x80000001, 3, Error::Unsupported),
            (0x1575, 2, 0x80000001, 3, Error::PciState),
            (0x1575, 6, 0x80000000, 3, Error::FirmwareNotRunning),
            (0x15e8, 6, 1, 3, Error::FirmwareNotAuthenticated),
            (0x1134, 6, 0x80000001, 0, Error::SafeMode),
            (0x1575, 6, 0x80000001, 2, Error::WrongMode(2)),
            (0x9a1b, 6, 1, 0, Error::FirmwareNotAuthenticated),
        ] {
            let source = Source::new();
            let domain = Arc::new(Domain::new());
            let model = Arc::new(Model::new(domain.clone()));
            model.state.lock().unwrap().values[0x39944 / 4] = status;
            model.state.lock().unwrap().values[0x3990c / 4] = mode << 8;
            // SAFETY: negative synthetic prerequisites cannot authorize any DMA.
            let result = unsafe {
                Host::new(
                    &IcmPci { device, command },
                    model.clone(),
                    &source,
                    domain,
                    u64::MAX,
                )
            };
            assert!(matches!(result,Err(error) if error==expected));
            assert!(model.state.lock().unwrap().writes.is_empty());
        }
        let (_source, _domain, model, mut host) = icm(0x8a0d);
        model.state.lock().unwrap().values[0x39944 / 4] = 0;
        host.start(0).unwrap();
        icm_release(&mut host);
    }
    #[test]
    fn icm_malformed_frame_keeps_request_pending_until_real_reply() {
        use super::super::icm::{Error, Event};
        let (_source, _domain, model, mut host) = icm(0x1575);
        host.start(0).unwrap();
        let id = host.driver_ready(0).unwrap();
        for (index, words, error) in [
            (0, vec![0x01000004, 0], Error::WrongCode),
            (1, vec![0x02000003, 0], Error::PacketCount),
            (2, vec![0x01000003], Error::Length),
        ] {
            finish_rx(&model, index, &incoming(PacketType::IcmResponse, &words));
            assert_eq!(
                host.poll(1 + index as u64),
                Ok(Some(Event::Discarded(error)))
            );
            assert_eq!(host.driver_ready(1 + index as u64), Err(Error::Busy));
        }
        finish_rx(
            &model,
            3,
            &incoming(PacketType::IcmResponse, &[0x01000003, 0]),
        );
        assert!(matches!(host.poll(4),Ok(Some(Event::DriverReady{request,..})) if request==id));
        icm_release(&mut host);
    }
    #[test]
    fn icm_tx_backpressure_never_publishes_a_ghost_request_and_release_retries() {
        use super::super::icm::{Error, Event};
        let (_source, domain, model, mut host) = icm(0x15e8);
        host.start(0).unwrap();
        // Firmware has replied but the modeled TX descriptor consumer is stalled.
        for i in 0..9 {
            let id = host.driver_ready(i * 2).unwrap();
            finish_rx(
                &model,
                i as usize,
                &incoming(PacketType::IcmResponse, &[0x01000003, 0, 0, 0]),
            );
            assert!(
                matches!(host.poll(i*2+1),Ok(Some(Event::DriverReady{request,..})) if request==id)
            );
        }
        let writes = model.state.lock().unwrap().writes.len();
        assert_eq!(host.driver_ready(20), Err(Error::Ring(super::Error::Full)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        model.finish(Direction::Tx, 0, &[], None);
        assert_eq!(host.poll(21), Ok(None));
        assert_eq!(host.driver_ready(22), Ok(10));
        host.disable().unwrap();
        domain.fail_unmap_at.store(12, Ordering::Relaxed);
        // SAFETY: final synthetic device/IRQ/work drain is complete, including
        // the active request. Failed invalidation retains its mapping for retry.
        assert!(unsafe { host.release() }.is_err());
        assert!(!domain.state.lock().unwrap().maps.is_empty());
        // SAFETY: the same exact drained reservation remains retained.
        unsafe { host.release() }.unwrap();
        assert!(domain.state.lock().unwrap().maps.is_empty());
    }
    struct AdapterOwner {
        target: super::super::adapter::Target,
        operation: super::super::adapter::Operation,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for AdapterOwner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: this fixture owns the actual synthetic adapter, unchanged capability
    // metadata and positive credit reservation, with no competing CM/link change.
    unsafe impl super::super::adapter::Owner for AdapterOwner {
        fn target(&self) -> super::super::adapter::Target {
            self.target
        }
        fn operation(&self) -> super::super::adapter::Operation {
            self.operation
        }
    }
    fn adapter_owner(
        operation: super::super::adapter::Operation,
    ) -> (Arc<AdapterOwner>, Arc<AtomicUsize>) {
        let dropped = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(AdapterOwner {
            target: super::super::adapter::Target {
                route: super::super::config::Route::new(0).unwrap(),
                port: 1,
                kind: super::super::topology::AdapterKind::Lane,
                usb4: true,
                phy_capability: Some(8),
                usb4_capability: Some(0x30),
            },
            operation,
            dropped: dropped.clone(),
        });
        (owner, dropped)
    }
    fn adapter_response(
        domain: &Domain,
        model: &Model,
        index: usize,
        offset: u16,
        data: &[u32],
    ) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let frame = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let address = u32::from_be_bytes(frame[8..12].try_into().unwrap());
        assert_eq!(address & 0x1fff, u32::from(offset));
        assert_eq!((address >> 25) & 3, 1);
        assert_eq!((address >> 13) & 63, 1);
        assert_eq!((address >> 19) & 63, 1);
        let mut reply = vec![
            u32::from_be_bytes(frame[..4].try_into().unwrap()) | (1 << 31),
            u32::from_be_bytes(frame[4..8].try_into().unwrap()),
            address & !(63 << 19),
        ];
        reply.extend_from_slice(data);
        incoming(kind, &reply)
    }
    #[test]
    fn adapter_lane_configured_and_credit_changes_use_actual_dma_ack_and_readback() {
        use super::super::adapter::{Control, Event, Operation};
        let before = 0x86454007;
        for (operation, offset, after) in [
            (Operation::LaneEnabled(true), 9, before & !(1 << 14)),
            (Operation::LaneEnabled(false), 9, before | (1 << 14)),
            (Operation::Usb4Configured(true), 0x43, before | (1 << 3)),
            (Operation::Usb4Configured(false), 0x43, before & !(1 << 3)),
            (Operation::NfcCredits(8), 4, (before & !0x3ff) | 15),
            (Operation::NfcCredits(-100), 4, before & !0x3ff),
        ] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let (owner, dropped) = adapter_owner(operation);
            // SAFETY: exact same synthetic requester, reset epoch, real adapter
            // metadata and exclusive credit/link reservation; channel is idle.
            let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
            assert!(control.poll(0).unwrap().is_none());
            let mut applied = None;
            for index in 0..3 {
                if index == 1 {
                    let frame = domain.data(model.frame_address(Direction::Tx, index), 20);
                    assert_eq!(u32::from_be_bytes(frame[12..16].try_into().unwrap()), after);
                }
                let data = match index {
                    0 => vec![before],
                    1 => vec![],
                    _ => vec![after],
                };
                let reply = adapter_response(&domain, &model, index, offset, &data);
                model.finish(Direction::Tx, index, &[], None);
                finish_rx(&model, index, &reply);
                let event = control.poll(index as u64 + 1).unwrap();
                if index < 2 {
                    assert!(event.is_none());
                } else {
                    let Some(Event::Applied(value)) = event else {
                        panic!("actual applied receipt")
                    };
                    applied = Some(value);
                }
            }
            let applied = applied.unwrap();
            assert_eq!(applied.before, before);
            assert_eq!(applied.after, after);
            let mut channel = control.into_channel();
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            // SAFETY: the fixture transfers its actual active reservation into
            // an independent synthetic CM lifetime through final modeled drain.
            unsafe { applied.retire() };
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
            channel_release(&mut channel);
        }
    }
    #[test]
    fn adapter_failed_readback_and_lost_write_ack_retain_exact_active_reservation() {
        use super::super::adapter::{Control, Error, Operation};
        for lost_ack in [false, true] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let (owner, dropped) = adapter_owner(Operation::NfcCredits(8));
            // SAFETY: same exact synthetic adapter/requester/reset and owned
            // positive allocation, with no independent firmware or link writer.
            let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
            control.poll(0).unwrap();
            let reply = adapter_response(&domain, &model, 0, 4, &[(100 << 20) | 7]);
            model.finish(Direction::Tx, 0, &[], None);
            finish_rx(&model, 0, &reply);
            control.poll(1).unwrap();
            if lost_ack {
                assert!(matches!(control.poll(500), Err(Error::Timeout)));
            } else {
                for index in 1..3 {
                    let data = if index == 1 {
                        vec![]
                    } else {
                        vec![(100 << 20) | 7]
                    };
                    let reply = adapter_response(&domain, &model, index, 4, &data);
                    model.finish(Direction::Tx, index, &[], None);
                    finish_rx(&model, index, &reply);
                    let result = control.poll(index as u64 + 1);
                    if index == 1 {
                        assert!(result.unwrap().is_none());
                    } else {
                        assert!(matches!(result, Err(Error::Readback)));
                    }
                }
            }
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(control.poll(501), Err(Error::Poisoned)));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            let mut channel = control.into_channel();
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
    }
    #[test]
    fn adapter_unconsumed_applied_receipt_quarantines_active_credits() {
        use super::super::adapter::{Control, Event, Operation};
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let (owner, dropped) = adapter_owner(Operation::NfcCredits(1));
        // SAFETY: same exact synthetic requester/epoch and actual allocation.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        control.poll(0).unwrap();
        for index in 0..3 {
            let data = match index {
                0 => vec![(100 << 20) | 7],
                1 => vec![],
                _ => vec![(100 << 20) | 8],
            };
            let reply = adapter_response(&domain, &model, index, 4, &data);
            model.finish(Direction::Tx, index, &[], None);
            finish_rx(&model, index, &reply);
            let event = control.poll(index as u64 + 1).unwrap();
            if index == 2 {
                assert!(matches!(event, Some(Event::Applied(_))));
                drop(event);
            }
        }
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
    #[test]
    fn adapter_zero_credit_and_capacity_rejection_never_write_adapter() {
        use super::super::adapter::{Control, Error, Event, Operation};
        for delta in [0, 100] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let (owner, dropped) = adapter_owner(Operation::NfcCredits(delta));
            // SAFETY: same exact synthetic requester/epoch; invalid allocation
            // is rejected against actual hardware capacity before any write.
            let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
            control.poll(0).unwrap();
            let reply = adapter_response(&domain, &model, 0, 4, &[(10 << 20) | 7]);
            model.finish(Direction::Tx, 0, &[], None);
            finish_rx(&model, 0, &reply);
            let result = control.poll(1);
            if delta == 0 {
                let Some(Event::Applied(applied)) = result.unwrap() else {
                    panic!("unchanged observation")
                };
                assert_eq!(applied.before, applied.after);
                drop(applied);
            } else {
                assert!(matches!(result, Err(Error::CreditsUnavailable)));
            }
            assert_eq!(
                model.read32(TX_DESCRIPTOR + 8) >> 16,
                1,
                "only the initial read was sent"
            );
            let mut channel = control.into_channel();
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
            channel_release(&mut channel);
        }
    }
    #[test]
    fn adapter_fixed_deadline_contains_write_publication_backpressure() {
        use super::super::{
            adapter::{Control, Error, Operation},
            config::{Address, Route, Space},
        };
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        // Fill eight actual TX descriptors; firmware replies while hardware's
        // TX consumer is stuck. The next read fills the last available slot.
        let address = Address {
            port: 1,
            space: Space::Port,
            offset: 4,
            words: 1,
        };
        for index in 0..8 {
            channel
                .read(Route::new(0).unwrap(), address, 0, 1000)
                .unwrap();
            let reply = adapter_response(&domain, &model, index, 4, &[(100 << 20) | 7]);
            finish_rx(&model, index, &reply);
            assert!(matches!(
                channel.poll(0),
                Ok(Some(super::super::channel::Event::Completed { .. }))
            ));
        }
        let (owner, dropped) = adapter_owner(Operation::NfcCredits(1));
        // SAFETY: same exact synthetic requester/epoch and positive allocation;
        // channel is idle even though its completed TX DMA has not drained.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        control.poll(0).unwrap();
        let reply = adapter_response(&domain, &model, 8, 4, &[(100 << 20) | 7]);
        finish_rx(&model, 8, &reply);
        assert!(control.poll(1).unwrap().is_none());
        let writes = model.state.lock().unwrap().writes.len();
        for now in [2, 100, 499] {
            assert!(control.poll(now).unwrap().is_none());
        }
        assert!(matches!(control.poll(500), Err(Error::Timeout)));
        assert!(matches!(control.poll(501), Err(Error::Poisoned)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            1,
            "no adapter write was published"
        );
        channel_release(&mut channel);
    }
    #[test]
    fn adapter_regressed_clock_and_changed_credit_capacity_never_claim_applied() {
        use super::super::adapter::{Control, Error, Operation};
        let (_source, _domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let (owner, dropped) = adapter_owner(Operation::LaneEnabled(true));
        // SAFETY: same exact idle synthetic requester/epoch.
        let mut control = unsafe { Control::new(channel, owner.clone(), 100) }.unwrap();
        let writes = model.state.lock().unwrap().writes.len();
        assert!(matches!(control.poll(99), Err(Error::ClockRegressed)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
        let (_source, domain, model, mut channel) = self::channel();
        channel.start(0).unwrap();
        let (owner, dropped) = adapter_owner(Operation::NfcCredits(8));
        // SAFETY: same exact synthetic requester/epoch and reserved allocation.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        control.poll(0).unwrap();
        for index in 0..3 {
            let data = match index {
                0 => vec![(100 << 20) | 7],
                1 => vec![],
                _ => vec![(10 << 20) | 15],
            };
            let reply = adapter_response(&domain, &model, index, 4, &data);
            model.finish(Direction::Tx, index, &[], None);
            finish_rx(&model, index, &reply);
            let result = control.poll(index as u64 + 1);
            if index < 2 {
                assert!(result.unwrap().is_none());
            } else {
                assert!(matches!(result, Err(Error::Readback)));
            }
        }
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
    struct RouterOwner {
        target: super::super::topology::Inventory,
        parent: Option<super::super::topology::Inventory>,
        policy: super::super::router::Policy,
        epoch: u64,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for RouterOwner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: fixtures reserve one exact synthetic NHI/domain/IMR epoch and
    // unchanged real model inventories. Policy is an explicit model input,
    // not a production platform/_OSC/security provider or Type-C inference.
    unsafe impl super::super::router::Owner for RouterOwner {
        fn identity(&self) -> super::super::domain::Identity {
            super::super::domain::Identity {
                nhi: crate::bus::pci::Address {
                    segment: 0,
                    bus: 1,
                    device: 2,
                    function: 0,
                },
                epoch: self.epoch,
            }
        }
        fn target(&self) -> &super::super::topology::Inventory {
            &self.target
        }
        fn parent(&self) -> Option<&super::super::topology::Inventory> {
            self.parent.as_ref()
        }
        fn policy(&self) -> super::super::router::Policy {
            self.policy
        }
    }
    fn router_adapter(
        port: u8,
        kind: u32,
        cap: Option<u16>,
    ) -> super::super::topology::AdapterObservation {
        use super::super::topology::{AdapterHeader, AdapterObservation, Capability};
        let mut raw = [0; 8];
        raw[2] = kind;
        raw[3] = u32::from(port) << 20;
        AdapterObservation::Present {
            port,
            header: AdapterHeader { raw },
            capabilities: cap
                .map(|offset| {
                    vec![Capability {
                        offset,
                        id: 6,
                        vendor_specific: None,
                        length: None,
                        next: 0,
                        raw: vec![6 << 8],
                    }]
                })
                .unwrap_or_default(),
        }
    }
    fn router_owner(route: u64, version: u8, mask: u32) -> RouterOwner {
        use super::super::{
            config::Route,
            router::{Decision, Policy},
            topology::{Inventory, Path, RouterHeader},
        };
        let path = Path::new(Route::new(route).unwrap()).unwrap();
        let header = RouterHeader {
            raw: [
                0x12348086,
                0x43808000 | (9 << 8),
                0xdeadbeef,
                0x10203040,
                (u32::from(version) << 29) | 0x00ab34cd,
            ],
        };
        let target = Inventory {
            path,
            upstream_port: if route == 0 { 0 } else { 1 },
            header,
            capabilities: vec![],
            adapters: vec![
                router_adapter(1, 1, Some(0x30)),
                router_adapter(2, 0x0e0101, Some(0x40)),
            ],
        };
        let parent = if route == 0 {
            None
        } else {
            let depth = path.depth() - 1;
            let shift = depth * 8;
            let raw = route & ((1u64 << shift) - 1);
            let upstream = if depth == 0 { 0 } else { 5 };
            let parent_path = Path::new(Route::new(raw).unwrap()).unwrap();
            let down = (route >> shift) as u8;
            Some(Inventory {
                path: parent_path,
                upstream_port: upstream,
                header: RouterHeader {
                    raw: [
                        0x56788086,
                        (5 << 14) | (u32::from(upstream) << 8) | (u32::from(depth) << 20),
                        raw as u32,
                        (raw >> 32) as u32 | (1 << 31),
                        1 << 29,
                    ],
                },
                capabilities: vec![],
                adapters: (1..=5)
                    .map(|port| {
                        router_adapter(
                            port,
                            match port {
                                1 | 2 | 5 => 1,
                                3 => {
                                    if mask & 4 != 0 {
                                        0x200101
                                    } else {
                                        0
                                    }
                                }
                                4 => {
                                    if mask & 8 != 0 {
                                        0x100101
                                    } else {
                                        0
                                    }
                                }
                                _ => unreachable!(),
                            },
                            if port == down && mask & 64 != 0 {
                                Some(0x30)
                            } else {
                                None
                            },
                        )
                    })
                    .collect(),
            })
        };
        RouterOwner {
            target,
            parent,
            policy: Policy {
                usb3: if mask & 1 != 0 {
                    Decision::Allowed
                } else {
                    Decision::Denied
                },
                pcie: if mask & 2 != 0 {
                    Decision::Allowed
                } else {
                    Decision::Denied
                },
            },
            epoch: 1,
            dropped: Arc::new(AtomicUsize::new(0)),
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RouterWrite {
        port: u8,
        space: u8,
        offset: u16,
        data: Vec<u32>,
    }
    struct RouterPeer {
        owner: Arc<RouterOwner>,
        regs: [u32; 8],
        hotplug: Vec<u32>,
        mask: u32,
        writes: Vec<RouterWrite>,
        setup_written: bool,
        valid_written: bool,
        ready_reads: u32,
        configured_reads: u32,
        hold_ready: bool,
        hold_configured: bool,
        reject_header: bool,
        override_upstream: Option<u8>,
    }
    impl RouterPeer {
        fn new(owner: Arc<RouterOwner>, mask: u32) -> Self {
            let mut regs = [0; 8];
            regs[..5].copy_from_slice(&owner.target.header.raw);
            regs[5] = 0x00d5001f;
            regs[6] = 0x1202 | if mask & 32 != 0 { 1 << 18 } else { 0 };
            let hotplug = (0..owner.target.header.max_port())
                .map(|i| match i {
                    0 => 0x92345678,
                    1 => 0xabcdef01,
                    _ => 0x98765430 + u32::from(i),
                })
                .collect();
            Self {
                owner,
                regs,
                hotplug,
                mask,
                writes: vec![],
                setup_written: false,
                valid_written: false,
                ready_reads: 0,
                configured_reads: 0,
                hold_ready: false,
                hold_configured: false,
                reject_header: false,
                override_upstream: None,
            }
        }
        fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
            let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
            let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
            let frame = domain.data(
                model.frame_address(Direction::Tx, index),
                (descriptor & 0xfff) as usize,
            );
            let mut words: Vec<u32> = frame[..frame.len() - 4]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| u32::from_be_bytes(*word))
                .collect();
            let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
            let address = words[2];
            let offset = (address & 0x1fff) as u16;
            let count = ((address >> 13) & 63) as usize;
            let port = ((address >> 19) & 63) as u8;
            let space = ((address >> 25) & 3) as u8;
            let target = route == self.owner.target.path.route().raw();
            let upstream = if target {
                self.owner.target.upstream_port
            } else {
                self.owner
                    .parent
                    .as_ref()
                    .expect("actual parent")
                    .upstream_port
            };
            let data = if kind == PacketType::Write {
                assert!(target, "setup must not program parent");
                let data = words[3..].to_vec();
                assert_eq!(data.len(), count);
                self.writes.push(RouterWrite {
                    port,
                    space,
                    offset,
                    data: data.clone(),
                });
                if space == 2 {
                    self.regs[usize::from(offset)..usize::from(offset) + count]
                        .copy_from_slice(&data);
                    if offset == 1 && self.reject_header {
                        self.regs[3] &= !(1 << 31);
                    }
                    if offset == 5 {
                        self.setup_written = true;
                        if data[0] & (1 << 31) != 0 {
                            self.valid_written = true;
                        }
                    }
                } else {
                    assert_eq!((space, offset, count), (1, 5, 1));
                    self.hotplug[usize::from(port) - 1] = data[0];
                }
                vec![]
            } else {
                assert_eq!(kind, PacketType::Read);
                if !target {
                    let parent = self.owner.parent.as_ref().unwrap();
                    assert_eq!(route, parent.path.route().raw());
                    assert_eq!(space, 1);
                    assert_eq!(offset, 0x42);
                    assert_eq!(count, 1);
                    vec![if self.mask & 16 != 0 { 1 << 9 } else { 0 }]
                } else if space == 2 {
                    if offset == 6 {
                        if self.setup_written {
                            self.ready_reads += 1;
                            if self.ready_reads >= 2 && !self.hold_ready {
                                self.regs[6] |= 1 << 24;
                            }
                        }
                        if self.valid_written {
                            self.configured_reads += 1;
                            if self.configured_reads >= 2 && !self.hold_configured {
                                self.regs[6] |= 1 << 25;
                            }
                        }
                    }
                    self.regs[usize::from(offset)..usize::from(offset) + count].to_vec()
                } else {
                    assert_eq!((space, offset, count), (1, 5, 1));
                    vec![self.hotplug[usize::from(port) - 1]]
                }
            };
            words.truncate(3);
            words[0] |= 1 << 31;
            words[2] = (address & !(63 << 19))
                | (u32::from(self.override_upstream.unwrap_or(upstream)) << 19);
            words.extend(data);
            incoming(kind, &words)
        }
    }
    fn drive_router(
        peer: &mut RouterPeer,
        domain: &Domain,
        model: &Model,
        setup: &mut super::super::router::Setup<Model>,
    ) -> super::super::router::Configured {
        use super::super::router::Event;
        assert!(setup.poll(0).unwrap().is_none());
        for n in 0..100 {
            let index = n % 10;
            let reply = peer.respond(domain, model, index);
            model.finish(Direction::Tx, index, &[], None);
            finish_rx(model, index, &reply);
            match setup.poll(n as u64 + 1).unwrap() {
                Some(Event::Configured(configured)) => return configured,
                Some(Event::Discarded(error)) => panic!("discarded {error:?}"),
                None => {}
            }
        }
        panic!("bounded router setup did not finish")
    }
    #[test]
    fn router_setup_actual_dma_root_child_policy_modes_and_hotplug_complete() {
        use super::super::router::Setup;
        for route in [0, 1, 0x201] {
            for mask in [0, 15, 47, 127] {
                let (_source, domain, model, mut channel) = channel();
                channel.start(0).unwrap();
                let owner = Arc::new(router_owner(route, 2, mask));
                let dropped = owner.dropped.clone();
                let mut peer = RouterPeer::new(owner.clone(), mask);
                // SAFETY: this exact model requester/domain/IMR/reset epoch owns
                // actual unchanged inventories and resolved native model policy.
                let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
                let configured = drive_router(&mut peer, &domain, &model, &mut setup);
                assert_eq!(configured.header.reported_route(), route);
                assert!(configured.header.enabled());
                assert_eq!(configured.header.raw[4] & 0xffff, 0x20ff);
                assert_eq!(configured.hotplug.len(), 2);
                assert_eq!(
                    configured.link_usb4,
                    if route == 0 {
                        None
                    } else {
                        Some(mask & 64 != 0 && mask & 16 == 0)
                    }
                );
                if route != 0 {
                    assert_ne!(configured.ready_status.unwrap() & (1 << 24), 0);
                    assert_ne!(configured.configured_status.unwrap() & (1 << 25), 0);
                    assert_ne!(peer.regs[5] & (1 << 31), 0);
                }
                let mut channel = setup.into_channel();
                drop(peer);
                drop(owner);
                assert_eq!(dropped.load(Ordering::Relaxed), 0);
                // SAFETY: actual synthetic configured state is transferred into an
                // independently retained model CM lifetime through final drain.
                unsafe { configured.retire() };
                assert_eq!(dropped.load(Ordering::Relaxed), 1);
                channel_release(&mut channel);
            }
        }
    }
    #[test]
    #[ignore = "requires hash-pinned unchanged full Linux USB4 router trace"]
    fn unchanged_linux_router_full_write_trace_matches_actual_dma_engine() {
        use super::super::router::Setup;
        use std::{env, fs};
        let trace = fs::read_to_string(
            env::var("STELA_THUNDERBOLT_ROUTER_ORACLE").expect("set router trace"),
        )
        .unwrap();
        let mut cases = 0;
        for line in trace.lines() {
            let f: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(f[0], "R");
            let n = |i: usize| f[i].parse::<u64>().unwrap();
            let route = n(1);
            let version = n(2) as u8;
            let mask = n(3) as u32;
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let owner = Arc::new(router_owner(route, version, mask));
            assert_eq!(
                owner.target.header.raw,
                (4..9).map(|i| n(i) as u32).collect::<Vec<_>>().as_slice()
            );
            let mut peer = RouterPeer::new(owner.clone(), mask);
            assert_eq!(peer.regs[5], n(9) as u32);
            assert_eq!(peer.regs[6], n(10) as u32);
            assert_eq!(peer.hotplug, [n(11) as u32, n(12) as u32]);
            // SAFETY: exact isolated model requester/epoch with actual retained
            // parent relationship and source-case resolved native model policy.
            let mut setup = unsafe { Setup::new(channel, owner, 0) }.unwrap();
            let configured = drive_router(&mut peer, &domain, &model, &mut setup);
            let count = n(13) as usize;
            let mut at = 14;
            let mut writes = vec![];
            for _ in 0..count {
                let (port, space, offset, len) = (
                    n(at) as u8,
                    n(at + 1) as u8,
                    n(at + 2) as u16,
                    n(at + 3) as usize,
                );
                at += 4;
                let data = (at..at + len).map(|i| n(i) as u32).collect();
                at += len;
                writes.push(RouterWrite {
                    port,
                    space,
                    offset,
                    data,
                });
            }
            assert_eq!(at, f.len());
            assert_eq!(
                peer.writes, writes,
                "source route={route:x} version={version} mask={mask}"
            );
            let mut channel = setup.into_channel();
            // SAFETY: independent model CM retains this actual configured lease
            // through complete synthetic teardown; no hardware provider claim.
            unsafe { configured.retire() };
            channel_release(&mut channel);
            cases += 1;
        }
        assert_eq!(cases, 768);
    }
    #[test]
    fn router_unresolved_policy_identity_and_parent_metadata_refuse_before_publication() {
        use super::super::{
            config::Route,
            router::{Decision, Setup},
            topology::{AdapterObservation, Path},
        };
        for case in 0..12 {
            let (_source, _domain, model, channel) = channel();
            let mut owner = router_owner(1, 2, 79);
            match case {
                0 => owner.policy.pcie = Decision::Unresolved,
                1 => owner.epoch = 0,
                2 => owner.parent = None,
                3 => {
                    owner.parent.as_mut().unwrap().path = Path::new(Route::new(2).unwrap()).unwrap()
                }
                4 => owner.parent.as_mut().unwrap().header.raw[3] &= !(1 << 31),
                5 => {
                    owner.parent.as_mut().unwrap().adapters[0] =
                        router_adapter(1, 0x200101, Some(0x30))
                }
                6 => owner.target.upstream_port = 2,
                7 => owner.target.header.raw[4] &= !(7 << 29),
                8 => {
                    if let AdapterObservation::Present { capabilities, .. } =
                        &mut owner.parent.as_mut().unwrap().adapters[0]
                    {
                        capabilities[0].offset = 8191;
                    }
                }
                9 => {
                    if let AdapterObservation::Present { capabilities, .. } =
                        &mut owner.target.adapters[0]
                    {
                        capabilities.push(capabilities[0].clone());
                    }
                }
                10 => owner.target.adapters[1] = router_adapter(2, 0x123456, Some(0x30)),
                11 => {}
                _ => unreachable!(),
            }
            let dropped = owner.dropped.clone();
            // SAFETY: this exact synthetic requester/epoch represents negative
            // metadata/prerequisites. No actual authority or write is fabricated.
            assert!(
                unsafe {
                    Setup::new(
                        channel,
                        Arc::new(owner),
                        if case == 11 { u64::MAX } else { 0 },
                    )
                }
                .is_err()
            );
            assert!(model.state.lock().unwrap().writes.is_empty());
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn router_policy_conflicts_changed_identity_and_upstream_never_enumerate() {
        use super::super::router::{Error, Setup};
        for (mask, conflict, identity, upstream) in [
            (0, 1 << 25, false, false),
            (0, 1 << 24, false, false),
            (0, 1 << 26, false, false),
            (95, 1 << 25, false, false),
            (79, 0, true, false),
            (79, 0, false, true),
        ] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let owner = Arc::new(router_owner(1, 2, mask));
            let dropped = owner.dropped.clone();
            let mut peer = RouterPeer::new(owner.clone(), mask);
            peer.regs[5] |= conflict;
            if identity {
                peer.regs[0] ^= 1 << 16;
            }
            if upstream {
                peer.override_upstream = Some(0);
            }
            // SAFETY: exact same negative synthetic ownership/inventory epoch.
            let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
            setup.poll(0).unwrap();
            let mut failed = false;
            for n in 0..10 {
                let reply = peer.respond(&domain, &model, n);
                model.finish(Direction::Tx, n, &[], None);
                finish_rx(&model, n, &reply);
                match setup.poll(n as u64 + 1) {
                    Err(Error::PolicyConflict(_)) if conflict != 0 => {
                        failed = true;
                        break;
                    }
                    Err(Error::ChangedInventory) if identity || upstream => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("unexpected policy/identity result"),
                }
            }
            assert!(failed);
            assert!(
                peer.writes.is_empty(),
                "no enumeration before actual policy preflight"
            );
            let mut channel = setup.into_channel();
            drop(peer);
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
            channel_release(&mut channel);
        }
    }
    #[test]
    fn router_ready_and_configured_deadlines_start_at_write_ack_and_never_extend() {
        use super::super::router::{Error, Setup};
        for configured_wait in [false, true] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let owner = Arc::new(router_owner(1, 2, 79));
            let dropped = owner.dropped.clone();
            let mut peer = RouterPeer::new(owner.clone(), 79);
            peer.hold_ready = !configured_wait;
            peer.hold_configured = configured_wait;
            // SAFETY: exact same isolated synthetic native reservation.
            let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
            setup.poll(0).unwrap();
            let mut ack = None;
            for n in 0..40 {
                let index = n % 10;
                let previous = peer.writes.len();
                let reply = peer.respond(&domain, &model, index);
                let reached = peer.writes.len() > previous
                    && peer.writes.last().is_some_and(|write| {
                        write.space == 2
                            && write.offset == 5
                            && ((write.data[0] & (1 << 31) != 0) == configured_wait)
                    });
                model.finish(Direction::Tx, index, &[], None);
                finish_rx(&model, index, &reply);
                assert!(setup.poll(n as u64 + 1).unwrap().is_none());
                if reached {
                    ack = Some((n as u64 + 1, (index + 1) % 10));
                    break;
                }
            }
            let (ack, index) = ack.expect("actual setup/configuration-valid write ACK");
            let reply = peer.respond(&domain, &model, index);
            model.finish(Direction::Tx, index, &[], None);
            finish_rx(&model, index, &reply);
            // Readback consumes nearly the whole window; entering wait must not
            // synthesize another now+500 deadline, even with no active request.
            assert!(setup.poll(ack + 499).unwrap().is_none());
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(setup.poll(ack + 500), Err(Error::Timeout)));
            assert!(matches!(setup.poll(ack + 501), Err(Error::Poisoned)));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            let mut channel = setup.into_channel();
            drop(peer);
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
    }
    #[test]
    fn router_lost_ack_rejected_enumeration_and_unconsumed_receipt_retain_owner() {
        use super::super::router::{Error, Setup};
        for mode in 0..3 {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let owner = Arc::new(router_owner(1, 2, 79));
            let dropped = owner.dropped.clone();
            let mut peer = RouterPeer::new(owner.clone(), 79);
            peer.reject_header = mode == 1;
            // SAFETY: exact same synthetic requester/epoch; published mutations
            // remain owned through ACK loss, rejected readback or receipt drop.
            let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
            if mode == 2 {
                let configured = drive_router(&mut peer, &domain, &model, &mut setup);
                drop(configured);
            } else {
                setup.poll(0).unwrap();
                let mut failed = false;
                for n in 0..20 {
                    let index = n % 10;
                    let previous = peer.writes.len();
                    let reply = peer.respond(&domain, &model, index);
                    if mode == 0 && peer.writes.len() > previous {
                        assert!(matches!(setup.poll(n as u64 + 501), Err(Error::Timeout)));
                        failed = true;
                        break;
                    }
                    model.finish(Direction::Tx, index, &[], None);
                    finish_rx(&model, index, &reply);
                    match setup.poll(n as u64 + 1) {
                        Err(Error::Readback) if mode == 1 => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("unexpected enumeration fault result"),
                    }
                }
                assert!(failed);
            }
            let mut channel = setup.into_channel();
            drop(peer);
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
    }
    #[test]
    fn router_full_tx_stage_deadline_clock_and_hotplug_cancel_are_explicit() {
        use super::super::{
            channel::Event,
            config::{Address, Route, Space},
            router::{Error, Setup},
        };
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        for index in 0..9 {
            channel
                .read(
                    Route::new(0).unwrap(),
                    Address {
                        port: 1,
                        space: Space::Port,
                        offset: 4,
                        words: 1,
                    },
                    0,
                    1000,
                )
                .unwrap();
            finish_rx(
                &model,
                index,
                &adapter_response(&domain, &model, index, 4, &[0]),
            );
            assert!(matches!(channel.poll(0), Ok(Some(Event::Completed { .. }))));
        }
        let owner = Arc::new(router_owner(0, 1, 0));
        // SAFETY: exact same synthetic owner, idle request engine; old completed
        // TX DMA is stalled and the real publication ring is physically full.
        let mut setup = unsafe { Setup::new(channel, owner, 0) }.unwrap();
        let writes = model.state.lock().unwrap().writes.len();
        for now in [0, 1, 499] {
            assert!(setup.poll(now).unwrap().is_none());
        }
        assert!(matches!(setup.poll(500), Err(Error::Timeout)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = setup.into_channel();
        channel_release(&mut channel);
        let (_source, _domain, model, mut channel) = self::channel();
        channel.start(0).unwrap();
        let owner = Arc::new(router_owner(0, 1, 0));
        // SAFETY: exact same idle synthetic requester/reset/native reservation.
        let mut setup = unsafe { Setup::new(channel, owner, 100) }.unwrap();
        let writes = model.state.lock().unwrap().writes.len();
        assert!(matches!(setup.poll(99), Err(Error::ClockRegressed)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = setup.into_channel();
        channel_release(&mut channel);
        for cancel in [false, true] {
            let (_source, domain, model, mut channel) = self::channel();
            channel.start(0).unwrap();
            let owner = Arc::new(router_owner(0, 1, 0));
            let dropped = owner.dropped.clone();
            let mut peer = RouterPeer::new(owner.clone(), 0);
            // SAFETY: same exact synthetic requester/epoch and native policy.
            let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
            setup.poll(0).unwrap();
            let reply = peer.respond(&domain, &model, 0);
            model.finish(Direction::Tx, 0, &[], None);
            finish_rx(&model, 0, &reply);
            setup.poll(1).unwrap();
            if cancel {
                assert!(matches!(setup.cancel(), Err(Error::Cancelled)));
            } else {
                finish_rx(&model, 1, &incoming(PacketType::Event, &[0, 0, 1]));
                assert!(matches!(setup.poll(2), Err(Error::Hotplug(_))));
            }
            assert!(matches!(setup.poll(3), Err(Error::Poisoned)));
            let mut channel = setup.into_channel();
            drop(peer);
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
    }
    #[test]
    fn router_parent_mode_read_error_never_becomes_a_guessed_tbt_link() {
        use super::super::router::{Error, Setup};
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let owner = Arc::new(router_owner(1, 2, 79));
        let dropped = owner.dropped.clone();
        let mut peer = RouterPeer::new(owner.clone(), 79);
        // SAFETY: same actual synthetic requester/epoch and reviewed parent
        // capability; failed hardware access cannot invent fallback ownership.
        let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
        setup.poll(0).unwrap();
        for n in 0..3 {
            let reply = if n < 2 {
                peer.respond(&domain, &model, n)
            } else {
                let sent = domain.data(model.frame_address(Direction::Tx, n), 16);
                assert_eq!(&sent[..8], &[0; 8]);
                let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
                assert_eq!(address & 0x1fff, 0x42);
                assert_eq!((address >> 25) & 3, 1);
                incoming(PacketType::Error, &[1 << 31, 0, 2])
            };
            model.finish(Direction::Tx, n, &[], None);
            finish_rx(&model, n, &reply);
            let result = setup.poll(n as u64 + 1);
            if n < 2 {
                assert!(result.unwrap().is_none());
            } else {
                assert!(matches!(result, Err(Error::Controller { code: 2, .. })));
            }
        }
        assert!(peer.writes.is_empty());
        let mut channel = setup.into_channel();
        drop(peer);
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
    #[derive(Default)]
    struct NativeCursor {
        tx: usize,
        rx: usize,
        now: u64,
    }
    fn configured_router(
        peer: &mut RouterPeer,
        domain: &Domain,
        model: &Model,
        setup: &mut super::super::router::Setup<Model>,
        cursor: &mut NativeCursor,
    ) -> super::super::router::Configured {
        use super::super::router::Event;
        assert!(setup.poll(cursor.now).unwrap().is_none());
        for _ in 0..100 {
            let reply = peer.respond(domain, model, cursor.tx % 10);
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(model, cursor.rx % 10, &reply);
            cursor.tx += 1;
            cursor.rx += 1;
            cursor.now += 1;
            match setup.poll(cursor.now).unwrap() {
                Some(Event::Configured(value)) => return value,
                Some(Event::Discarded(error)) => panic!("{error:?}"),
                None => {}
            }
        }
        panic!("actual source router setup did not finish")
    }
    struct LinkReservation {
        partners: super::super::link::Partners,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for LinkReservation {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: fixture owns actual reciprocal model lanes and both routers in
    // this same synthetic NHI reset/topology epoch. No production topology,
    // policy, power or attachment provider is fabricated by the driver.
    unsafe impl super::super::link::Reservation for LinkReservation {
        fn observed(&self) -> super::super::link::Partners {
            self.partners
        }
    }
    struct LinkFixture {
        _source: Source,
        domain: Arc<Domain>,
        model: Arc<Model>,
        channel: super::super::channel::Channel<Model>,
        parent: super::super::router::Configured,
        child: super::super::router::Configured,
        reservation: Arc<LinkReservation>,
        cursor: NativeCursor,
        dropped: [Arc<AtomicUsize>; 3],
    }
    fn link_inventory(owner: &mut RouterOwner, max: u8, primary: u8) {
        use super::super::topology::{AdapterObservation, Capability};
        owner.target.header.raw[1] =
            (owner.target.header.raw[1] & !(63 << 14)) | (u32::from(max) << 14);
        owner.target.adapters = (1..=max)
            .map(|port| {
                let mut adapter =
                    router_adapter(port, 1, if port == primary { Some(0x30) } else { None });
                if let AdapterObservation::Present { capabilities, .. } = &mut adapter {
                    capabilities.insert(
                        0,
                        Capability {
                            offset: 8,
                            id: 1,
                            vendor_specific: None,
                            length: None,
                            next: if port == primary { 0x30 } else { 0 },
                            raw: vec![1 << 8 | if port == primary { 0x30 } else { 0 }],
                        },
                    );
                }
                adapter
            })
            .collect();
    }
    fn add_path_usb3_adapter(inventory: &mut super::super::topology::Inventory, kind: u32) {
        use super::super::topology::AdapterObservation;
        let port = inventory.header.max_port() + 1;
        inventory.header.raw[1] = (inventory.header.raw[1] & !(63 << 14)) | (u32::from(port) << 14);
        let mut adapter = router_adapter(port, kind, Some(0x50));
        if let AdapterObservation::Present {
            header,
            capabilities,
            ..
        } = &mut adapter
        {
            header.raw[1] = 0x50;
            capabilities[0].id = 4;
            capabilities[0].raw[0] = 4 << 8;
        }
        inventory.adapters.push(adapter);
        for adapter in &mut inventory.adapters {
            if let AdapterObservation::Present { header, .. } = adapter {
                header.raw[5] = 127 | (127 << 11);
            }
        }
    }
    fn link_fixture(map: u8, mode: bool) -> LinkFixture {
        link_fixture_with_usb3(map, mode, false)
    }
    fn link_fixture_with_usb3(map: u8, mode: bool, usb3: bool) -> LinkFixture {
        use super::super::{link::Partners, router::Setup};
        let (source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let mut cursor = NativeCursor::default();
        let mask = 64 | if mode { 16 } else { 0 } | u32::from(usb3);
        let mut parent_owner = router_owner(0, 1, mask);
        link_inventory(
            &mut parent_owner,
            if map == 0 { 2 } else { 5 },
            if map == 0 { 1 } else { 2 },
        );
        if usb3 {
            add_path_usb3_adapter(&mut parent_owner.target, 0x200101);
        }
        let parent_owner = Arc::new(parent_owner);
        let parent_drop = parent_owner.dropped.clone();
        let mut peer = RouterPeer::new(parent_owner.clone(), mask);
        // SAFETY: exact same synthetic NHI/domain/IMR epoch and actual current
        // inventories with explicit model native policy; exclusive idle channel.
        let mut setup = unsafe { Setup::new(channel, parent_owner.clone(), cursor.now) }.unwrap();
        let parent = configured_router(&mut peer, &domain, &model, &mut setup, &mut cursor);
        channel = setup.into_channel();
        drop(peer);
        let route = if map == 0 { 1 } else { 2 };
        let mut child_owner = router_owner(route, 1, mask);
        link_inventory(&mut child_owner, if map == 0 { 2 } else { 3 }, 1);
        let mut current_parent = parent_owner.target.clone();
        current_parent.header = parent.header.clone();
        child_owner.parent = Some(current_parent);
        if usb3 {
            add_path_usb3_adapter(&mut child_owner.target, 0x200102);
        }
        let child_owner = Arc::new(child_owner);
        let child_drop = child_owner.dropped.clone();
        let mut peer = RouterPeer::new(child_owner.clone(), mask);
        // SAFETY: same actual synthetic requester/epoch and already configured
        // retained parent, exact current topology and native model policy.
        let mut setup = unsafe { Setup::new(channel, child_owner.clone(), cursor.now) }.unwrap();
        let child = configured_router(&mut peer, &domain, &model, &mut setup, &mut cursor);
        channel = setup.into_channel();
        drop(peer);
        drop(parent_owner);
        drop(child_owner);
        let reservation_drop = Arc::new(AtomicUsize::new(0));
        let reservation = Arc::new(LinkReservation {
            partners: Partners {
                identity: parent.identity,
                topology_epoch: 2,
                child: [1, if map == 0 { 2 } else { 3 }],
                parent: if map == 0 { [1, 2] } else { [2, 5] },
                observations: core::array::from_fn(|i| {
                    let ports = if map == 0 { [1, 2, 1, 2] } else { [1, 3, 2, 5] };
                    let routes = [child.route, child.route, parent.route, parent.route];
                    super::super::link::ObservedLane {
                        route: routes[i],
                        port: ports[i],
                        lane_index: (i % 2) as u8,
                        dual_port: ports[i ^ 1],
                        remote_route: routes[i ^ 2],
                        remote_port: ports[i ^ 2],
                    }
                }),
            },
            dropped: reservation_drop.clone(),
        });
        LinkFixture {
            _source: source,
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            cursor,
            dropped: [parent_drop, child_drop, reservation_drop],
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LinkWrite {
        index: usize,
        offset: u16,
        value: u32,
    }
    struct LinkPeer {
        partners: super::super::link::Partners,
        route: u64,
        mode: bool,
        phy: [[u32; 2]; 4],
        credits: [u32; 4],
        pc: [u32; 2],
        writes: Vec<LinkWrite>,
        bonding: bool,
        bond_reads: u32,
        hold_width: bool,
        reject: Option<(usize, u16)>,
        deny_bond: bool,
        port_wait_state: Option<u8>,
        secondary_reads: u32,
    }
    impl LinkPeer {
        fn new(
            partners: super::super::link::Partners,
            generation: u8,
            dual: bool,
            mode: bool,
            seed: u32,
        ) -> Self {
            let mut phy = [[0; 2]; 4];
            let mut credits = [0; 4];
            for i in 0..4 {
                let mut word = (0x104234ab ^ (seed * 0x01804109) ^ ((i as u32) * 0x01010001))
                    & !((15 << 16) | (63 << 20) | (15 << 26) | 0x30 | 0xc000);
                word |= (if generation == 2 { 8 } else { 4 }) << 16;
                word |= (if dual { 2 } else { 1 }) << 20;
                word |= 2 << 26;
                word |= 1 << 4;
                if dual && i == 2 {
                    word |= 1 << 15;
                }
                phy[i] = [
                    (if i % 2 == 0 { 0x130 } else { 0x100 })
                        | (2 << 20)
                        | ((if generation == 2 { 8 } else { 12 }) << 16)
                        | if mode { 1 << 31 } else { 0 },
                    word,
                ];
                credits[i] = ((64 + seed + i as u32) << 20) | (8 + (seed + i as u32) % 4);
            }
            Self {
                partners,
                route: u64::from(partners.parent[0]),
                mode,
                phy,
                credits,
                pc: [0x14050101 ^ (seed * 0x10001); 2],
                writes: vec![],
                bonding: false,
                bond_reads: 0,
                hold_width: false,
                reject: None,
                deny_bond: false,
                port_wait_state: None,
                secondary_reads: 0,
            }
        }
        fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
            let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
            let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
            let bytes = domain.data(
                model.frame_address(Direction::Tx, index),
                (descriptor & 0xfff) as usize,
            );
            let mut words: Vec<u32> = bytes[..bytes.len() - 4]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| u32::from_be_bytes(*word))
                .collect();
            let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
            let address = words[2];
            assert_eq!((address >> 25) & 3, 1);
            let port = ((address >> 19) & 63) as u8;
            let offset = (address & 0x1fff) as u16;
            let count = ((address >> 13) & 63) as usize;
            let lane = if route == self.route {
                self.partners
                    .child
                    .iter()
                    .position(|number| *number == port)
                    .unwrap()
            } else {
                assert_eq!(route, 0);
                2 + self
                    .partners
                    .parent
                    .iter()
                    .position(|number| *number == port)
                    .unwrap()
            };
            let data = if kind == PacketType::Write {
                assert_eq!(count, 1);
                let value = words[3];
                self.writes.push(LinkWrite {
                    index: lane,
                    offset,
                    value,
                });
                match offset {
                    9 => {
                        self.phy[lane][1] = if self.reject == Some((lane, offset)) {
                            value & !((3 << 4) | (1 << 15))
                        } else {
                            value
                        };
                        if lane == 2 && value & (1 << 15) != 0 {
                            self.bonding = true;
                            self.bond_reads = 0;
                        }
                    }
                    0x43 => {
                        assert!(lane == 0 || lane == 2);
                        self.pc[lane / 2] = if self.reject == Some((lane, offset)) {
                            value & !(1 << 3)
                        } else {
                            value
                        };
                    }
                    _ => panic!("unsupported actual link write"),
                }
                vec![]
            } else {
                assert_eq!(kind, PacketType::Read);
                if lane == 2 && offset == 9 && self.bonding {
                    self.bond_reads += 1;
                    if self.bond_reads >= 2 && !self.hold_width {
                        for i in 0..4 {
                            self.phy[i][1] = (self.phy[i][1] & !(63 << 20)) | (2 << 20);
                            self.credits[i] += 32 << 20;
                        }
                        self.bonding = false;
                    }
                }
                match (offset, count) {
                    (8, 2) => {
                        let mut data = self.phy[lane].to_vec();
                        if lane == 3 {
                            self.secondary_reads += 1;
                            if self.secondary_reads > 1
                                && let Some(state) = self.port_wait_state
                            {
                                data[1] = (data[1] & !(15 << 26)) | (u32::from(state) << 26);
                            }
                        }
                        data
                    }
                    (8, 1) => vec![self.phy[lane][0]],
                    (9, 1) => vec![self.phy[lane][1]],
                    (4, 1) => vec![self.credits[lane]],
                    (0x42, 1) => vec![
                        if self.deny_bond { 0 } else { 1 << 8 }
                            | if self.mode { 1 << 9 } else { 0 },
                    ],
                    (0x43, 1) => {
                        assert!(lane == 0 || lane == 2);
                        vec![self.pc[lane / 2]]
                    }
                    _ => panic!("unsupported actual link read"),
                }
            };
            words.truncate(3);
            words[0] |= 1 << 31;
            words[2] = (address & !(63 << 19))
                | if lane < 2 {
                    u32::from(self.partners.child[0]) << 19
                } else {
                    0
                };
            words.extend(data);
            incoming(kind, &words)
        }
    }
    fn drive_link(
        peer: &mut LinkPeer,
        domain: &Domain,
        model: &Model,
        activate: &mut super::super::link::Activate<Model>,
        cursor: &mut NativeCursor,
    ) -> super::super::link::Linked {
        use super::super::link::Event;
        assert!(activate.poll(cursor.now).unwrap().is_none());
        for _ in 0..150 {
            let reply = peer.respond(domain, model, cursor.tx % 10);
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(model, cursor.rx % 10, &reply);
            cursor.tx += 1;
            cursor.rx += 1;
            cursor.now += 1;
            match activate.poll(cursor.now).unwrap() {
                Some(Event::Linked(value)) => return *value,
                Some(Event::Discarded(error)) => panic!("{error:?}"),
                None => {}
            }
        }
        panic!("actual native link activation did not finish")
    }
    #[test]
    fn link_bonds_and_activates_both_actual_configured_routers_with_observed_nonadjacent_lanes() {
        use super::super::link::Activate;
        for map in 0..2 {
            for generation in [2, 3] {
                for dual in [false, true] {
                    for mode in [false, true] {
                        let LinkFixture {
                            domain,
                            model,
                            channel,
                            parent,
                            child,
                            reservation,
                            mut cursor,
                            dropped,
                            ..
                        } = link_fixture(map, mode);
                        let mut peer =
                            LinkPeer::new(reservation.partners, generation, dual, mode, 3);
                        // SAFETY: actual same model NHI/reset/topology epoch, both source-
                        // configured owners and observed reciprocal CL0 lanes/power grant.
                        let mut activate = unsafe {
                            Activate::new(channel, parent, child, reservation, cursor.now)
                        }
                        .unwrap();
                        let linked =
                            drive_link(&mut peer, &domain, &model, &mut activate, &mut cursor);
                        assert_eq!(linked.generation, generation);
                        assert_eq!(linked.link_usb4, !mode);
                        assert_eq!((linked.parent_width >> 20) & 63, 2);
                        assert_eq!((linked.child_width >> 20) & 63, 2);
                        assert!(linked.configured.iter().all(|word| word & (1 << 3) != 0));
                        assert_eq!(peer.writes.len(), if dual { 2 } else { 7 });
                        for (credit, index) in linked.credits.iter().zip([2, 3, 0, 1]) {
                            assert_eq!(credit.raw, peer.credits[index]);
                        }
                        let mut channel = activate.into_channel();
                        assert!(
                            dropped
                                .iter()
                                .all(|counter| counter.load(Ordering::Relaxed) == 0)
                        );
                        // SAFETY: both real synthetic configured/router/link reservations
                        // transfer into independently retained CM lifetime through drain.
                        unsafe { linked.retire() };
                        assert!(
                            dropped
                                .iter()
                                .all(|counter| counter.load(Ordering::Relaxed) == 1)
                        );
                        channel_release(&mut channel);
                    }
                }
            }
        }
    }
    #[test]
    #[ignore = "requires hash-pinned unchanged Gen2/3 Linux link trace"]
    fn unchanged_linux_link_bonding_credit_and_two_ended_write_trace_matches_actual_dma() {
        use super::super::link::Activate;
        use std::{env, fs};
        let trace =
            fs::read_to_string(env::var("STELA_THUNDERBOLT_LINK_ORACLE").expect("set link trace"))
                .unwrap();
        let mut cases = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(fields[0], "L");
            let n = |i: usize| fields[i].parse::<u32>().unwrap();
            let (map, generation, dual, mode, seed) =
                (n(1) as u8, n(2) as u8, n(3) != 0, n(4) != 0, n(5));
            let LinkFixture {
                domain,
                model,
                channel,
                parent,
                child,
                reservation,
                mut cursor,
                ..
            } = link_fixture(map, mode);
            let mut peer = LinkPeer::new(reservation.partners, generation, dual, mode, seed);
            for i in 0..4 {
                assert_eq!(peer.phy[i], [n(6 + i), n(10 + i)]);
                assert_eq!(peer.credits[i], n(14 + i));
            }
            assert_eq!(peer.pc, [n(18), n(19)]);
            // SAFETY: each isolated source fixture provides actual same native
            // requester/epochs, configured leases and observed reciprocal map.
            let mut activate =
                unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
            let linked = drive_link(&mut peer, &domain, &model, &mut activate, &mut cursor);
            assert_eq!(
                linked
                    .credits
                    .iter()
                    .map(|credit| credit.raw)
                    .collect::<Vec<_>>(),
                (20..24).map(n).collect::<Vec<_>>()
            );
            let count = n(24) as usize;
            let mut at = 25;
            let mut writes = vec![];
            for _ in 0..count {
                let side = n(at) as usize;
                let port = n(at + 1) as u8;
                let index = if side == 0 {
                    peer.partners
                        .child
                        .iter()
                        .position(|number| *number == port)
                        .unwrap()
                } else {
                    2 + peer
                        .partners
                        .parent
                        .iter()
                        .position(|number| *number == port)
                        .unwrap()
                };
                writes.push(LinkWrite {
                    index,
                    offset: n(at + 2) as u16,
                    value: n(at + 3),
                });
                at += 4;
            }
            assert_eq!(at, fields.len());
            assert_eq!(
                peer.writes, writes,
                "source map={map} gen={generation} dual={dual} mode={mode} seed={seed}"
            );
            let mut channel = activate.into_channel();
            // SAFETY: completed actual synthetic link/routers are transferred
            // to a retained independent model CM lifetime through final drain.
            unsafe { linked.retire() };
            channel_release(&mut channel);
            cases += 1;
        }
        assert_eq!(cases, 512);
    }
    #[test]
    fn link_unknown_epochs_partner_records_router_versions_and_policy_refuse_before_mutation() {
        use super::super::link::{Activate, Error};
        for case in 0..13 {
            let LinkFixture {
                domain,
                model,
                channel,
                mut parent,
                mut child,
                mut reservation,
                cursor,
                dropped,
                ..
            } = link_fixture(1, false);
            let observed = &mut Arc::get_mut(&mut reservation).unwrap().partners;
            match case {
                0 => observed.identity.epoch += 1,
                1 => observed.topology_epoch = 0,
                2 => observed.child[1] = 1,
                3 => observed.parent[0] = 1,
                4 => observed.parent[1] = 3,
                5 => observed.observations[0].remote_port = 5,
                6 => observed.observations[1].dual_port = 2,
                7 => observed.observations[2].lane_index = 1,
                8 => child.header.raw[4] = (child.header.raw[4] & !(7 << 29)) | (3 << 29),
                9 => parent.identity.epoch += 1,
                10 => child.setup_word = Some(1 << 24),
                11 => child.link_usb4 = None,
                12 => {}
                _ => unreachable!(),
            }
            let writes = model.state.lock().unwrap().writes.len();
            // SAFETY: all negative data is confined to this actual isolated
            // synthetic requester. No native provider/authority is fabricated.
            let result = unsafe {
                Activate::new(
                    channel,
                    parent,
                    child,
                    reservation,
                    if case == 12 { u64::MAX } else { cursor.now },
                )
            };
            assert!(matches!(
                result,
                Err(Error::Identity
                    | Error::Topology
                    | Error::Unsupported
                    | Error::Policy
                    | Error::ClockOverflow)
            ));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
            assert_eq!(dropped[1].load(Ordering::Relaxed), 0);
            assert_eq!(dropped[2].load(Ordering::Relaxed), 1);
            drop(domain);
        }
    }
    #[test]
    fn link_unknown_phy_modes_asymmetry_and_missing_bonding_support_never_write_link() {
        use super::super::link::{Activate, Error};
        for case in 0..8 {
            let LinkFixture {
                domain,
                model,
                channel,
                parent,
                child,
                reservation,
                mut cursor,
                ..
            } = link_fixture(1, false);
            let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
            match case {
                0 => peer.phy[0][1] = (peer.phy[0][1] & !(15 << 16)) | (2 << 16),
                1 => peer.phy[0][1] &= !(15 << 16),
                2 => peer.phy[1][1] = (peer.phy[1][1] & !(63 << 20)) | (4 << 20),
                3 => peer.phy[1][1] = (peer.phy[1][1] & !(63 << 20)) | (2 << 20),
                4 => peer.phy[0][1] = (peer.phy[0][1] & !(15 << 26)) | (3 << 26),
                5 => peer.phy[2][0] &= !(2 << 20),
                6 => peer.mode = true,
                7 => peer.deny_bond = true,
                _ => unreachable!(),
            }
            // SAFETY: exact same current synthetic configured leases/map; raw
            // unsupported PHY and contradictory mode observations cannot grant
            // a native transition or be replaced by successful defaults.
            let mut activate =
                unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
            activate.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..20 {
                let reply = peer.respond(&domain, &model, cursor.tx % 10);
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                match activate.poll(cursor.now) {
                    Err(Error::Unsupported | Error::ChangedLink | Error::NotCl0) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("unexpected preflight outcome"),
                }
            }
            assert!(failed);
            assert!(peer.writes.is_empty());
            let mut channel = activate.into_channel();
            channel_release(&mut channel);
        }
    }
    #[test]
    fn link_every_write_uncertainty_retains_both_routers_without_claiming_rollback() {
        use super::super::link::{Activate, Error};
        for target in 1..=7 {
            for failure in 0..3 {
                let LinkFixture {
                    domain,
                    model,
                    channel,
                    parent,
                    child,
                    reservation,
                    mut cursor,
                    dropped,
                    ..
                } = link_fixture(1, false);
                let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 1);
                // SAFETY: exact same model NHI/domain/epochs and observed reciprocal
                // CL0 lanes. Both configured owners remain real retained resources.
                let mut activate =
                    unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }
                        .unwrap();
                activate.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..100 {
                    let tx = cursor.tx % 10;
                    let rx = cursor.rx % 10;
                    let descriptor = domain.read32(model.descriptor_address(Direction::Tx, tx) + 8);
                    let is_write = ((descriptor >> 12) & 15) == PacketType::Write as u32;
                    if failure == 2 && is_write && peer.writes.len() + 1 == target {
                        let bytes = domain.data(model.frame_address(Direction::Tx, tx), 20);
                        let route = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
                        let address = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
                        let port = ((address >> 19) & 63) as u8;
                        let lane = if route == peer.route as u32 {
                            peer.partners
                                .child
                                .iter()
                                .position(|number| *number == port)
                                .unwrap()
                        } else {
                            2 + peer
                                .partners
                                .parent
                                .iter()
                                .position(|number| *number == port)
                                .unwrap()
                        };
                        peer.reject = Some((lane, (address & 0x1fff) as u16));
                    }
                    let mut reply = peer.respond(&domain, &model, tx);
                    if is_write && peer.writes.len() == target && failure == 0 {
                        assert!(matches!(
                            activate.poll(cursor.now + 501),
                            Err(Error::Timeout)
                        ));
                        cursor.now += 501;
                        failed = true;
                        break;
                    }
                    if is_write && peer.writes.len() == target && failure == 1 {
                        let bytes = domain.data(model.frame_address(Direction::Tx, tx), 16);
                        reply = incoming(
                            PacketType::Error,
                            &[
                                u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                                u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                                2,
                            ],
                        );
                    }
                    model.finish(Direction::Tx, tx, &[], None);
                    finish_rx(&model, rx, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    match activate.poll(cursor.now) {
                        Err(Error::Readback | Error::Controller { code: 2, .. }) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("unexpected partial-write outcome"),
                    }
                }
                assert!(failed, "target={target} failure={failure}");
                assert_eq!(peer.writes.len(), target);
                let writes = model.state.lock().unwrap().writes.len();
                assert!(matches!(
                    activate.poll(cursor.now + 1),
                    Err(Error::Poisoned)
                ));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
                let mut channel = activate.into_channel();
                assert!(
                    dropped
                        .iter()
                        .all(|counter| counter.load(Ordering::Relaxed) == 0),
                    "both configured ends and changed link reservation must remain held"
                );
                channel_release(&mut channel);
            }
        }
    }
    #[test]
    fn link_bond_window_includes_readback_and_port_locked_retries_never_extend_it() {
        use super::super::link::{Activate, Error};
        for locked in [false, true] {
            let LinkFixture {
                domain,
                model,
                channel,
                parent,
                child,
                reservation,
                mut cursor,
                dropped,
                ..
            } = link_fixture(1, false);
            let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
            peer.hold_width = true;
            // SAFETY: exact same real synthetic configured owners/observations;
            // delayed hardware or lock responses cannot replace actual readiness.
            let mut activate =
                unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
            activate.poll(cursor.now).unwrap();
            let mut ack = None;
            for _ in 0..200 {
                // A lock retry waits at least1ms before publishing the next
                // actual request. Do not fabricate a reply for an unused slot.
                if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                    if let Some(ack) = ack
                        && cursor.now + 1 >= ack + 99
                    {
                        break;
                    }
                    cursor.now += 1;
                    assert!(activate.poll(cursor.now).unwrap().is_none());
                    continue;
                }
                let before = peer.writes.len();
                let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                let bond_ack = peer.writes.len() > before
                    && peer.writes.last().is_some_and(|write| {
                        write.index == 2 && write.offset == 9 && write.value & (1 << 15) != 0
                    });
                if ack.is_some() && peer.bond_reads >= 1 && locked {
                    reply = incoming(PacketType::Error, &[1 << 31, 0, 15]);
                }
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now = if let Some(ack) = ack {
                    if locked { cursor.now + 1 } else { ack + 99 }
                } else {
                    cursor.now + 1
                };
                assert!(activate.poll(cursor.now).unwrap().is_none());
                if bond_ack {
                    ack = Some(cursor.now);
                }
                if let Some(ack) = ack
                    && ((!locked && peer.bond_reads >= 1) || (locked && cursor.now >= ack + 99))
                {
                    break;
                }
            }
            let ack = ack.expect("actual parent LB write ACK");
            assert!(peer.bond_reads >= if locked { 2 } else { 1 });
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(activate.poll(ack + 100), Err(Error::Timeout)));
            assert!(matches!(activate.poll(ack + 101), Err(Error::Poisoned)));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            assert_eq!(peer.writes.len(), 5);
            let mut channel = activate.into_channel();
            assert!(
                dropped
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 0)
            );
            channel_release(&mut channel);
        }
    }
    #[test]
    fn link_secondary_connection_wait_obeys_ten_source_reads_and_hundred_ms_spacing() {
        use super::super::link::{Activate, Error};
        let LinkFixture {
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            mut cursor,
            dropped,
            ..
        } = link_fixture(1, false);
        let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
        peer.port_wait_state = Some(1);
        // SAFETY: exact same actual synthetic partners/epochs; asynchronous
        // secondary connection loss is observed from real config DMA replies.
        let mut activate =
            unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        let mut tries = 0;
        for _ in 0..30 {
            let previous = peer.secondary_reads;
            let reply = peer.respond(&domain, &model, cursor.tx % 10);
            let waiting = peer.secondary_reads > previous && peer.secondary_reads > 1;
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.tx += 1;
            cursor.rx += 1;
            cursor.now += 1;
            assert!(activate.poll(cursor.now).unwrap().is_none());
            if waiting {
                tries += 1;
                let writes = model.state.lock().unwrap().writes.len();
                assert!(activate.poll(cursor.now + 99).unwrap().is_none());
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
                cursor.now += 100;
                let result = activate.poll(cursor.now);
                if tries == 10 {
                    assert!(matches!(result, Err(Error::NoConnection)));
                    break;
                }
                assert!(result.unwrap().is_none());
            }
        }
        assert_eq!(tries, 10);
        assert_eq!(peer.secondary_reads, 11);
        assert!(peer.writes.is_empty());
        let mut channel = activate.into_channel();
        assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
        assert_eq!(dropped[1].load(Ordering::Relaxed), 0);
        assert_eq!(dropped[2].load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
    #[test]
    fn link_receipt_storage_failure_refuses_before_publication_and_retains_active_routers() {
        use super::super::link::{Activate, Error};
        let LinkFixture {
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            cursor,
            dropped,
            ..
        } = link_fixture(1, false);
        let writes = model.state.lock().unwrap().writes.len();
        let unmaps = domain.state.lock().unwrap().unmaps;
        // SAFETY: the same actual model NHI/epoch and configured owners are
        // paired. The local null allocator deterministically refuses only this
        // receipt; no global allocator or other test thread is affected.
        let result = unsafe {
            Activate::new_without_storage(channel, parent, child, reservation, cursor.now)
        };
        assert!(matches!(result, Err(Error::Allocation)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        assert_eq!(domain.state.lock().unwrap().unmaps, unmaps);
        // Already-configured routers and live channel DMA remain quarantined.
        // The link reservation has never published a mutation and may retire.
        assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
        assert_eq!(dropped[1].load(Ordering::Relaxed), 0);
        assert_eq!(dropped[2].load(Ordering::Relaxed), 1);
    }
    #[test]
    fn link_full_publication_clock_revocation_and_unconsumed_success_keep_real_router_leases() {
        use super::super::{
            channel::Event,
            config::{Address, Route, Space},
            link::{Activate, Error},
        };
        let LinkFixture {
            domain,
            model,
            mut channel,
            parent,
            child,
            reservation,
            mut cursor,
            dropped,
            ..
        } = link_fixture(1, false);
        for _ in 0..9 {
            channel
                .read(
                    Route::new(0).unwrap(),
                    Address {
                        port: 1,
                        space: Space::Port,
                        offset: 4,
                        words: 1,
                    },
                    cursor.now,
                    cursor.now + 1000,
                )
                .unwrap();
            let reply = adapter_response(&domain, &model, cursor.tx % 10, 4, &[0]);
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.tx += 1;
            cursor.rx += 1;
            cursor.now += 1;
            assert!(matches!(
                channel.poll(cursor.now),
                Ok(Some(Event::Completed { .. }))
            ));
        }
        // SAFETY: same exact native model reservations and idle channel; nine
        // completed requests still occupy physically unconsumed TX descriptors.
        let mut activate =
            unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
        let writes = model.state.lock().unwrap().writes.len();
        for offset in [0, 1, 499] {
            assert!(activate.poll(cursor.now + offset).unwrap().is_none());
        }
        assert!(matches!(
            activate.poll(cursor.now + 500),
            Err(Error::Timeout)
        ));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = activate.into_channel();
        assert_eq!(dropped[2].load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
        for mode in 0..3 {
            let LinkFixture {
                domain,
                model,
                channel,
                parent,
                child,
                reservation,
                mut cursor,
                dropped,
                ..
            } = link_fixture(1, false);
            let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
            // SAFETY: same exact actual configured owners/observations/epochs.
            let mut activate =
                unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
            if mode == 0 {
                assert!(matches!(
                    activate.poll(cursor.now - 1),
                    Err(Error::ClockRegressed)
                ));
            } else if mode == 1 {
                activate.poll(cursor.now).unwrap();
                for _ in 0..100 {
                    let reply = peer.respond(&domain, &model, cursor.tx % 10);
                    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(activate.poll(cursor.now).unwrap().is_none());
                    if !peer.writes.is_empty() {
                        break;
                    }
                }
                assert!(matches!(activate.cancel(), Err(Error::Cancelled)));
            } else {
                let linked = drive_link(&mut peer, &domain, &model, &mut activate, &mut cursor);
                drop(linked);
            }
            let mut channel = activate.into_channel();
            assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
            assert_eq!(dropped[1].load(Ordering::Relaxed), 0);
            assert_eq!(
                dropped[2].load(Ordering::Relaxed),
                if mode == 0 { 1 } else { 0 }
            );
            channel_release(&mut channel);
        }
    }
    #[test]
    fn link_transient_port_lock_at_first_bond_readback_recovers_without_moving_window() {
        use super::super::link::{Activate, Event};
        let LinkFixture {
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            mut cursor,
            dropped,
            ..
        } = link_fixture(1, false);
        let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
        // SAFETY: same exact real synthetic native/router/link reservations;
        // temporary documented lock is a protocol response, not a new owner.
        let mut activate =
            unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        let mut locked = false;
        let mut result = None;
        for _ in 0..150 {
            if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                cursor.now += 1;
                assert!(activate.poll(cursor.now).unwrap().is_none());
                continue;
            }
            let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
            if peer.bond_reads == 1 && !locked {
                reply = incoming(PacketType::Error, &[1 << 31, 0, 15]);
                locked = true;
            }
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.tx += 1;
            cursor.rx += 1;
            cursor.now += 1;
            match activate.poll(cursor.now).unwrap() {
                Some(Event::Linked(linked)) => {
                    result = Some(linked);
                    break;
                }
                None => {}
                _ => panic!("unexpected link event"),
            }
        }
        assert!(locked);
        let linked = result.expect("actual both-ended transition after transient lock");
        let mut channel = activate.into_channel();
        // SAFETY: both actual model router/link leases transfer into retained
        // independent native CM lifetime through real synthetic final drain.
        unsafe { linked.retire() };
        assert!(
            dropped
                .iter()
                .all(|counter| counter.load(Ordering::Relaxed) == 1)
        );
        channel_release(&mut channel);
    }
    struct PathReservation {
        allocation: super::super::path::Allocation,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for PathReservation {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: model retains actual protected IDs/credits/permission on the exact
    // configured synthetic link. This supplies no production allocator/provider.
    unsafe impl super::super::path::Reservation for PathReservation {
        fn allocation(&self) -> super::super::path::Allocation {
            self.allocation
        }
    }
    struct PathFixture {
        domain: Arc<Domain>,
        model: Arc<Model>,
        channel: super::super::channel::Channel<Model>,
        linked: Box<super::super::link::Linked>,
        reservation: Arc<PathReservation>,
        cursor: NativeCursor,
        dropped: [Arc<AtomicUsize>; 4],
    }
    fn path_fixture(
        direction: super::super::path::Direction,
        credits: super::super::path::LaneCredits,
    ) -> PathFixture {
        use super::super::{link::Activate, path::Allocation, router::Decision};
        let LinkFixture {
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            mut cursor,
            dropped,
            ..
        } = link_fixture_with_usb3(1, false, true);
        let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 3);
        // SAFETY: exact model NHI, both actual configured owners, observed lanes.
        let mut activate =
            unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
        let linked = Box::new(drive_link(
            &mut peer,
            &domain,
            &model,
            &mut activate,
            &mut cursor,
        ));
        let channel = activate.into_channel();
        let (parent, child) = linked.retained_routers().unwrap();
        let allocation = Allocation {
            identity: linked.partners.identity,
            topology_epoch: linked.partners.topology_epoch,
            grant_epoch: 3,
            direction,
            usb3_down: parent.header.max_port(),
            usb3_up: child.header.max_port(),
            hops: [(8, 31), (31, 8)],
            lane_credits: credits,
            permission: Decision::Allowed,
        };
        let path_drop = Arc::new(AtomicUsize::new(0));
        let reservation = Arc::new(PathReservation {
            allocation,
            dropped: path_drop.clone(),
        });
        PathFixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            cursor,
            dropped: [
                dropped[0].clone(),
                dropped[1].clone(),
                dropped[2].clone(),
                path_drop,
            ],
        }
    }
    struct PathPeer {
        routes: [u64; 2],
        ports: [u8; 2],
        upstream: [u8; 2],
        headers: [[u32; 8]; 2],
        raw: [[u32; 2]; 2],
        reads: [usize; 2],
        disabled: [bool; 2],
        writes: Vec<(usize, u8, u16, [u32; 2])>,
        hold_pending: bool,
        hold_hop: [bool; 2],
        reject: Option<usize>,
        changed_header: bool,
        credit: u32,
    }
    impl PathPeer {
        fn new(
            linked: &super::super::link::Linked,
            allocation: super::super::path::Allocation,
            stale: bool,
            seed: u32,
        ) -> Self {
            use super::super::{path::Direction, topology::AdapterObservation};
            let (parent, child) = linked.retained_routers().unwrap();
            let (source, destination, ports) = match allocation.direction {
                Direction::Downstream => (
                    parent,
                    child,
                    [allocation.usb3_down, linked.partners.child[0]],
                ),
                Direction::Upstream => (
                    child,
                    parent,
                    [allocation.usb3_up, linked.partners.parent[0]],
                ),
            };
            let owners = [source, destination];
            let headers = core::array::from_fn(|i| {
                owners[i]
                    .retained_owner()
                    .target()
                    .adapters
                    .iter()
                    .find_map(|adapter| match adapter {
                        AdapterObservation::Present { port, header, .. } if *port == ports[i] => {
                            Some(header.raw)
                        }
                        _ => None,
                    })
                    .unwrap()
            });
            Self {
                routes: [source.route.raw(), destination.route.raw()],
                ports,
                upstream: [
                    source.retained_owner().target().upstream_port,
                    destination.retained_owner().target().upstream_port,
                ],
                headers,
                raw: core::array::from_fn(|i| {
                    [
                        (0x12345678 ^ (seed * 0x104001) ^ (i as u32 * 0x13579)) & !(1 << 31)
                            | if stale { 1 << 31 } else { 0 },
                        (0xabcdef12 ^ (seed * 0x104101) ^ (i as u32 * 0x13579))
                            | if stale { 1 << 28 } else { 0 },
                    ]
                }),
                reads: [0; 2],
                disabled: [false; 2],
                writes: vec![],
                hold_pending: false,
                hold_hop: [false; 2],
                reject: None,
                changed_header: false,
                credit: (100 << 20) | 8,
            }
        }
        fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
            let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
            let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
            let bytes = domain.data(
                model.frame_address(Direction::Tx, index),
                (descriptor & 0xfff) as usize,
            );
            let mut words: Vec<u32> = bytes[..bytes.len() - 4]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| u32::from_be_bytes(*word))
                .collect();
            let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
            let address = words[2];
            let port = ((address >> 19) & 63) as u8;
            let lane = self
                .routes
                .iter()
                .zip(self.ports)
                .position(|(r, p)| *r == route && p == port)
                .unwrap();
            let space = (address >> 25) & 3;
            let offset = address & 8191;
            let count = ((address >> 13) & 63) as usize;
            let data = if kind == PacketType::Write {
                assert_eq!((space, count), (0, 2));
                let value = [words[3], words[4]];
                self.writes.push((lane, port, offset as u16, value));
                if self.reject == Some(self.writes.len()) {
                    self.raw[lane] = [value[0] ^ (1 << 31), value[1]];
                } else {
                    self.raw[lane] = value;
                }
                self.disabled[lane] = self.raw[lane][0] & (1 << 31) == 0;
                if self.disabled[lane] {
                    self.reads[lane] = 0;
                }
                vec![]
            } else {
                assert_eq!(kind, PacketType::Read);
                match (space, offset, count) {
                    (1, 0, 8) => {
                        let mut data = self.headers[lane];
                        if self.changed_header {
                            data[2] ^= 1;
                        }
                        data.to_vec()
                    }
                    (1, 4, 1) => vec![self.credit],
                    (0, _, 2) => {
                        self.reads[lane] += 1;
                        if self.disabled[lane]
                            && self.reads[lane] >= 2
                            && !self.hold_pending
                            && !self.hold_hop[lane]
                        {
                            self.raw[lane][1] &= !(1 << 28);
                        }
                        self.raw[lane].to_vec()
                    }
                    _ => panic!("unexpected actual path read"),
                }
            };
            words.truncate(3);
            words[0] |= 1 << 31;
            words[2] = (address & !(63 << 19)) | (u32::from(self.upstream[lane]) << 19);
            words.extend(data);
            incoming(kind, &words)
        }
    }
    fn path_step(
        peer: &mut PathPeer,
        domain: &Domain,
        model: &Model,
        activate: &mut super::super::path::Activate<Model>,
        cursor: &mut NativeCursor,
    ) -> Result<Option<super::super::path::Event>, super::super::path::Error> {
        let producer = model.read32(TX_DESCRIPTOR + 8) >> 16;
        if producer as usize == cursor.tx % 10 {
            cursor.now += 1;
            return activate.poll(cursor.now);
        }
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        activate.poll(cursor.now)
    }
    fn drive_path(
        peer: &mut PathPeer,
        domain: &Domain,
        model: &Model,
        activate: &mut super::super::path::Activate<Model>,
        cursor: &mut NativeCursor,
    ) -> super::super::path::Active {
        use super::super::path::Event;
        activate.poll(cursor.now).unwrap();
        for _ in 0..100 {
            match path_step(peer, domain, model, activate, cursor).unwrap() {
                Some(Event::Active(value)) => return value,
                Some(Event::Discarded(error)) => panic!("{error:?}"),
                None => {}
            }
        }
        panic!("actual path did not activate")
    }
    #[test]
    fn path_actual_link_two_directions_credit_modes_stale_drain_and_retained_lifetime() {
        use super::super::path::{Activate, Direction, LaneCredits};
        for direction in [Direction::Downstream, Direction::Upstream] {
            for credits in [LaneCredits::LegacyBonded, LaneCredits::RouterAllocated(23)] {
                for stale in [false, true] {
                    let PathFixture {
                        domain,
                        model,
                        channel,
                        linked,
                        reservation,
                        mut cursor,
                        dropped,
                    } = path_fixture(direction, credits);
                    let mut peer = PathPeer::new(&linked, reservation.allocation, stale, 5);
                    let protocol = peer.raw[0];
                    // SAFETY: real model protected IDs/credits/permission and exact retained physical link.
                    let mut activate =
                        unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
                    let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
                    assert_eq!(peer.writes.len(), if stale { 4 } else { 2 });
                    assert_eq!(
                        active.words[0].raw[0] & (127 << 17),
                        protocol[0] & (127 << 17)
                    );
                    assert_eq!(
                        active.words[0].raw[1] & ((1 << 24) | (1 << 26)),
                        protocol[1] & ((1 << 24) | (1 << 26))
                    );
                    assert_eq!(
                        (active.words[1].raw[0] >> 17) & 127,
                        match credits {
                            LaneCredits::LegacyBonded => 32,
                            LaneCredits::RouterAllocated(n) => u32::from(n),
                        }
                    );
                    assert!(
                        dropped
                            .iter()
                            .all(|counter| counter.load(Ordering::Relaxed) == 0)
                    );
                    let mut channel = activate.into_channel();
                    // SAFETY: actual model complete path and all owners transfer into independently retained CM through final drain.
                    unsafe { active.retire() };
                    assert!(
                        dropped
                            .iter()
                            .all(|counter| counter.load(Ordering::Relaxed) == 1)
                    );
                    channel_release(&mut channel);
                }
            }
        }
    }
    #[test]
    fn path_invalid_actual_grants_hop_bounds_and_mapping_refuse_before_publication() {
        use super::super::path::{Activate, Direction, LaneCredits};
        for case in 0..13 {
            let PathFixture {
                model,
                channel,
                mut linked,
                reservation,
                cursor,
                dropped,
                ..
            } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
            let mut allocation = reservation.allocation;
            match case {
                0 => allocation.identity.epoch += 1,
                1 => allocation.topology_epoch += 1,
                2 => allocation.grant_epoch = 0,
                3 => allocation.permission = super::super::router::Decision::Unresolved,
                4 => allocation.permission = super::super::router::Decision::Denied,
                5 => allocation.usb3_down = linked.partners.parent[0],
                6 => allocation.usb3_up = linked.partners.child[0],
                7 => allocation.hops[0].0 = 9,
                8 => allocation.hops[0].1 = 128,
                9 => allocation.hops[1].0 = 30,
                10 => allocation.lane_credits = LaneCredits::RouterAllocated(128),
                11 => linked.link_usb4 = false,
                12 => linked.partners.topology_epoch += 1,
                _ => unreachable!(),
            }
            let replacement = Arc::new(PathReservation {
                allocation,
                dropped: dropped[3].clone(),
            });
            drop(reservation);
            let writes = model.state.lock().unwrap().writes.len();
            // SAFETY: same negative model pairing; invalid metadata must refuse without requests.
            assert!(unsafe { Activate::new(channel, linked, replacement, cursor.now) }.is_err());
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            assert!(
                dropped[..3]
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 0)
            );
            assert_eq!(dropped[3].load(Ordering::Relaxed), 2);
        }
    }
    #[test]
    fn path_each_disable_or_activation_write_failure_keeps_link_and_all_ids() {
        use super::super::path::{Activate, Direction, Error, LaneCredits};
        for target in 1..=4 {
            for failure in 0..3 {
                let PathFixture {
                    domain,
                    model,
                    channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                } = path_fixture(Direction::Upstream, LaneCredits::RouterAllocated(19));
                let mut peer = PathPeer::new(&linked, reservation.allocation, true, 1);
                if failure == 2 {
                    peer.reject = Some(target);
                }
                // SAFETY: exact protected model link, permission and resource reservation.
                let mut activate =
                    unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
                activate.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..100 {
                    let producer = model.read32(TX_DESCRIPTOR + 8) >> 16;
                    if producer as usize == cursor.tx % 10 {
                        cursor.now += 1;
                        assert!(activate.poll(cursor.now).unwrap().is_none());
                        continue;
                    }
                    let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                    if peer.writes.len() == target && failure == 0 {
                        assert!(matches!(
                            activate.poll(cursor.now + 501),
                            Err(Error::Timeout)
                        ));
                        cursor.now += 501;
                        failed = true;
                        break;
                    }
                    if peer.writes.len() == target && failure == 1 {
                        let bytes = domain.data(
                            model.frame_address(super::Direction::Tx, cursor.tx % 10),
                            16,
                        );
                        reply = incoming(
                            PacketType::Error,
                            &[
                                u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                                u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                                2,
                            ],
                        );
                    }
                    model.finish(super::Direction::Tx, cursor.tx % 10, &[], None);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    match activate.poll(cursor.now) {
                        Err(Error::Changed | Error::Readback | Error::Controller { .. }) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("unexpected path failure result"),
                    }
                }
                assert!(failed, "target={target} failure={failure}");
                assert_eq!(peer.writes.len(), target);
                let writes = model.state.lock().unwrap().writes.len();
                assert!(matches!(
                    activate.poll(cursor.now + 1),
                    Err(Error::Poisoned)
                ));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
                let mut channel = activate.into_channel();
                assert!(
                    dropped
                        .iter()
                        .all(|counter| counter.load(Ordering::Relaxed) == 0)
                );
                channel_release(&mut channel);
            }
        }
    }
    #[test]
    fn path_header_credit_refusal_and_stale_pending_deadline_cannot_claim_restoration() {
        use super::super::path::{Activate, Direction, Error, LaneCredits};
        for case in 0..3 {
            let PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
            let mut peer = PathPeer::new(&linked, reservation.allocation, true, 4);
            peer.changed_header = case == 0;
            peer.credit = if case == 1 {
                (32 << 20) | 8
            } else {
                peer.credit
            };
            peer.hold_pending = case == 2;
            // SAFETY: exact owned synthetic path with negative device effects.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
            activate.poll(cursor.now).unwrap();
            let mut failed = false;
            let mut disabled_ack = None;
            for _ in 0..600 {
                match path_step(&mut peer, &domain, &model, &mut activate, &mut cursor) {
                    Err(Error::Changed | Error::Credits | Error::Timeout) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {
                        if !peer.writes.is_empty() {
                            disabled_ack.get_or_insert(cursor.now);
                        }
                    }
                    _ => panic!("unexpected pending/refusal outcome"),
                }
            }
            assert!(failed);
            if case == 2 {
                assert_eq!(
                    cursor.now,
                    disabled_ack.expect("actual disable ACK") + 500,
                    "repeated pending reads must not extend the ACK-anchored drain window"
                );
            }
            assert_eq!(peer.writes.len(), usize::from(case == 2));
            let mut channel = activate.into_channel();
            assert!(
                dropped[..3]
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 0)
            );
            assert_eq!(dropped[3].load(Ordering::Relaxed), usize::from(case != 2));
            channel_release(&mut channel);
        }
    }
    #[test]
    #[ignore = "requires unchanged Linux two-hop path oracle trace"]
    fn unchanged_linux_path_usb3_complete_write_trace_matches_actual_dma() {
        use super::super::path::{Activate, Direction, LaneCredits};
        let text = std::fs::read_to_string(
            std::env::var("STELA_THUNDERBOLT_PATH_ORACLE").expect("set oracle trace path"),
        )
        .unwrap();
        let mut cases = 0;
        for line in text.lines() {
            let values: Vec<u32> = line
                .split_ascii_whitespace()
                .skip(1)
                .map(|s| s.parse().unwrap())
                .collect();
            let [direction, mode, stale, seed] = values[..4] else {
                panic!("oracle case header")
            };
            let direction = if direction == 0 {
                Direction::Downstream
            } else {
                Direction::Upstream
            };
            let credits = if mode == 0 {
                LaneCredits::LegacyBonded
            } else {
                LaneCredits::RouterAllocated((17 + seed % 31) as u8)
            };
            let PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = path_fixture(direction, credits);
            let mut peer = PathPeer::new(&linked, reservation.allocation, stale != 0, seed);
            peer.raw = [[values[4], values[5]], [values[6], values[7]]];
            let count = values[8] as usize;
            let expected: Vec<_> = values[9..9 + count * 5]
                .as_chunks::<5>()
                .0
                .iter()
                .map(|v| (v[0] as usize, v[1] as u8, v[2] as u16, [v[3], v[4]]))
                .collect();
            let final_words = &values[9 + count * 5..];
            assert_eq!(final_words.len(), 4);
            // SAFETY: same actual fixture link and independently protected model allocations/grants.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
            let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
            assert_eq!(peer.writes, expected, "case={cases}");
            assert_eq!(active.words[0].raw, final_words[..2], "case={cases}");
            assert_eq!(active.words[1].raw, final_words[2..], "case={cases}");
            let mut channel = activate.into_channel();
            // SAFETY: all native synthetic owners transfer across actual model final drain.
            unsafe { active.retire() };
            assert!(
                dropped
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 1)
            );
            channel_release(&mut channel);
            cases += 1;
        }
        assert_eq!(cases, 512);
    }
    #[test]
    fn path_publication_stall_clock_revocation_and_unconsumed_success_are_contained() {
        use super::super::{
            config::{Address, Route, Space},
            path::{Activate, Direction, Error, LaneCredits},
        };
        for mode in 0..5 {
            let PathFixture {
                domain,
                model,
                mut channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
            let mut peer = PathPeer::new(&linked, reservation.allocation, false, 2);
            if mode == 0 {
                for _ in 0..9 {
                    channel
                        .read(
                            Route::new(0).unwrap(),
                            Address {
                                port: 1,
                                space: Space::Port,
                                offset: 4,
                                words: 1,
                            },
                            cursor.now,
                            cursor.now + 1000,
                        )
                        .unwrap();
                    let reply = adapter_response(&domain, &model, cursor.tx % 10, 4, &[0]);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(
                        channel.poll(cursor.now),
                        Ok(Some(super::super::channel::Event::Completed { .. }))
                    ));
                }
            }
            // SAFETY: protected real synthetic link and idle channel; mode0 leaves physical TX DMA unconsumed.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
            if mode == 0 {
                let writes = model.state.lock().unwrap().writes.len();
                for delta in [0, 1, 499] {
                    assert!(activate.poll(cursor.now + delta).unwrap().is_none());
                }
                assert!(matches!(
                    activate.poll(cursor.now + 500),
                    Err(Error::Timeout)
                ));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            } else if mode == 1 {
                assert!(matches!(
                    activate.poll(cursor.now - 1),
                    Err(Error::ClockRegressed)
                ));
            } else if mode == 4 {
                let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
                drop(active);
            } else {
                activate.poll(cursor.now).unwrap();
                for _ in 0..20 {
                    assert!(
                        path_step(&mut peer, &domain, &model, &mut activate, &mut cursor)
                            .unwrap()
                            .is_none()
                    );
                    if !peer.writes.is_empty() {
                        break;
                    }
                }
                assert_eq!(peer.writes.len(), 1);
                if mode == 2 {
                    assert!(matches!(activate.cancel(), Err(Error::Cancelled)));
                } else {
                    let event = incoming(PacketType::Event, &[0, 0, 1]);
                    finish_rx(&model, cursor.rx % 10, &event);
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(activate.poll(cursor.now), Err(Error::Hotplug(_))));
                }
            }
            let mut channel = activate.into_channel();
            assert!(
                dropped[..3]
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 0)
            );
            assert_eq!(dropped[3].load(Ordering::Relaxed), usize::from(mode < 2));
            channel_release(&mut channel);
        }
    }
    struct BandwidthReservation {
        current: Arc<AtomicBool>,
        grant: super::super::usb3::Grant,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for BandwidthReservation {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: actual synthetic domain accounting and permission protect this
    // exact root/peer link and source floor/quantization throughout the phase.
    // When used by tunnel fixtures it also retains actual exclusive synthetic
    // CS0 endpoint control on both mapped adapters through final owner lifetime.
    // These fixtures implement no production accounting/policy/control service.
    unsafe impl super::super::usb3::Reservation for BandwidthReservation {
        fn is_current(&self) -> bool {
            self.current.load(Ordering::Acquire)
        }
        fn grant(&self) -> super::super::usb3::Grant {
            self.grant
        }
    }
    fn bandwidth_fixture(
        requested: super::super::usb3::Rates,
    ) -> (PathFixture, Arc<BandwidthReservation>, Arc<AtomicUsize>) {
        use super::super::{
            path::{Direction, LaneCredits},
            usb3::Grant,
        };
        let fixture = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
        let allocation = fixture.reservation.allocation;
        let dropped = Arc::new(AtomicUsize::new(0));
        let reservation = Arc::new(BandwidthReservation {
            current: Arc::new(AtomicBool::new(true)),
            grant: Grant {
                identity: allocation.identity,
                topology_epoch: allocation.topology_epoch,
                grant_epoch: allocation.grant_epoch,
                usb3_down: allocation.usb3_down,
                usb3_up: allocation.usb3_up,
                permission: allocation.permission,
                requested,
            },
            dropped: dropped.clone(),
        });
        (fixture, reservation, dropped)
    }
    struct BandwidthPeer {
        port: u8,
        header: [u32; 8],
        control: u32,
        consumed: u32,
        scale: u32,
        writes: Vec<(u16, u32)>,
        transition: Option<bool>,
        polls: usize,
        hold: [bool; 2],
        reject: Option<usize>,
    }
    impl BandwidthPeer {
        fn new(
            link: &super::super::link::Linked,
            grant: super::super::usb3::Grant,
            seed: u32,
        ) -> Self {
            use super::super::topology::AdapterObservation;
            let parent = link.retained_routers().unwrap().0;
            let header = parent
                .retained_owner()
                .target()
                .adapters
                .iter()
                .find_map(|a| match a {
                    AdapterObservation::Present { port, header, .. }
                        if *port == grant.usb3_down =>
                    {
                        Some(header.raw)
                    }
                    _ => None,
                })
                .unwrap();
            Self {
                port: grant.usb3_down,
                header,
                control: (0x12345678 ^ (seed * 0x10201)) & !(1 << 31),
                consumed: (seed % 256) | (((seed * 3) % 256) << 12),
                scale: (seed % 4) | 0x30000000,
                writes: vec![],
                transition: None,
                polls: 0,
                hold: [false; 2],
                reject: None,
            }
        }
        fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
            let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
            let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
            let bytes = domain.data(
                model.frame_address(Direction::Tx, index),
                (descriptor & 0xfff) as usize,
            );
            let mut words: Vec<u32> = bytes[..bytes.len() - 4]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|v| u32::from_be_bytes(*v))
                .collect();
            let address = words[2];
            assert_eq!((words[0], words[1]), (0, 0));
            assert_eq!((address >> 25) & 3, 1);
            assert_eq!(((address >> 19) & 63) as u8, self.port);
            let offset = (address & 8191) as u16;
            let data = if kind == PacketType::Write {
                assert_eq!((address >> 13) & 63, 1);
                let value = words[3];
                self.writes.push((offset, value));
                let reject = self.reject == Some(self.writes.len());
                match offset {
                    0x52 => {
                        let old = self.control;
                        self.control = if reject {
                            value ^ if self.writes.len() == 3 { 1 } else { 1 << 31 }
                        } else {
                            value
                        };
                        if (old ^ value) & (1 << 31) != 0 {
                            self.transition = Some(value & (1 << 31) != 0);
                            self.polls = 0;
                        }
                    }
                    0x53 => self.scale = if reject { value ^ 1 } else { value },
                    _ => panic!("unexpected source bandwidth write"),
                };
                vec![]
            } else {
                assert_eq!(kind, PacketType::Read);
                match offset {
                    0 => self.header.to_vec(),
                    0x51 => {
                        if let Some(set) = self.transition {
                            self.polls += 1;
                            if self.polls >= 2 && !self.hold[usize::from(!set)] {
                                self.consumed =
                                    (self.consumed & !(1 << 31)) | if set { 1 << 31 } else { 0 };
                                self.transition = None;
                            }
                        }
                        vec![self.consumed]
                    }
                    0x52 => vec![self.control],
                    0x53 => vec![self.scale],
                    _ => panic!("unexpected bandwidth read"),
                }
            };
            words.truncate(3);
            words[0] |= 1 << 31;
            words[2] &= !(63 << 19);
            words.extend(data);
            incoming(kind, &words)
        }
    }
    fn bandwidth_step(
        peer: &mut BandwidthPeer,
        domain: &Domain,
        model: &Model,
        allocate: &mut super::super::usb3::Allocate<Model>,
        cursor: &mut NativeCursor,
    ) -> Result<Option<super::super::usb3::Event>, super::super::usb3::Error> {
        if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
            cursor.now += 1;
            return allocate.poll(cursor.now);
        }
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        allocate.poll(cursor.now)
    }
    fn drive_bandwidth(
        peer: &mut BandwidthPeer,
        domain: &Domain,
        model: &Model,
        allocate: &mut super::super::usb3::Allocate<Model>,
        cursor: &mut NativeCursor,
    ) -> Box<super::super::usb3::Allocated> {
        use super::super::usb3::Event;
        allocate.poll(cursor.now).unwrap();
        for _ in 0..100 {
            match bandwidth_step(peer, domain, model, allocate, cursor).unwrap() {
                Some(Event::Allocated(value)) => return value,
                Some(Event::Discarded(error)) => panic!("{error:?}"),
                None => {}
            }
        }
        panic!("actual HCA transitions did not finish")
    }
    #[test]
    fn bandwidth_actual_hca_consumed_floor_scale_and_original_link_move_into_path() {
        use super::super::{
            path::Activate,
            usb3::{Allocate, Rates},
        };
        let (
            PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: 1,
            downstream: 18000,
        });
        let mut peer = BandwidthPeer::new(&linked, accounting.grant, 13);
        let mut path_peer = PathPeer::new(&linked, reservation.allocation, false, 3);
        // SAFETY: exact actual synthetic accounting/permission/link/controller.
        let mut allocate =
            unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
        let allocated = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
        assert!(allocated.allocated.upstream > 1);
        assert_eq!(allocated.allocated.downstream, 18000);
        assert_eq!(peer.writes.len(), 4);
        assert_eq!(peer.control >> 31, 0);
        assert_eq!(peer.consumed >> 31, 0);
        let channel = allocate.into_channel();
        // SAFETY: consume same protected grant/endpoint/link epoch; no copied ownership.
        let mut activate =
            unsafe { Activate::with_bandwidth(channel, allocated, reservation, cursor.now) }
                .unwrap();
        let active = drive_path(&mut path_peer, &domain, &model, &mut activate, &mut cursor);
        let mut channel = activate.into_channel();
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
        assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
        // SAFETY: complete actual synthetic path/bandwidth/link native lifetime transfer.
        unsafe { active.retire() };
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 1));
        assert_eq!(accounting_drop.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
    #[test]
    fn bandwidth_each_cmr_scale_allocation_clear_write_failure_retains_actual_accounting() {
        use super::super::usb3::{Allocate, Error, Rates};
        for target in 1..=4 {
            for failure in 0..3 {
                let (
                    PathFixture {
                        domain,
                        model,
                        channel,
                        linked,
                        reservation,
                        mut cursor,
                        dropped,
                    },
                    accounting,
                    accounting_drop,
                ) = bandwidth_fixture(Rates {
                    upstream: 10000,
                    downstream: 18000,
                });
                drop(reservation);
                let mut peer = BandwidthPeer::new(&linked, accounting.grant, 7);
                if failure == 2 {
                    peer.reject = Some(target);
                }
                // SAFETY: protected real synthetic CM grant and exact physical pairing.
                let mut allocate =
                    unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
                allocate.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..100 {
                    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                        cursor.now += 1;
                        assert!(allocate.poll(cursor.now).unwrap().is_none());
                        continue;
                    }
                    let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                    if peer.writes.len() == target && failure == 0 {
                        assert!(matches!(
                            allocate.poll(cursor.now + 1501),
                            Err(Error::Timeout)
                        ));
                        cursor.now += 1501;
                        failed = true;
                        break;
                    }
                    if peer.writes.len() == target && failure == 1 {
                        let bytes =
                            domain.data(model.frame_address(Direction::Tx, cursor.tx % 10), 16);
                        reply = incoming(
                            PacketType::Error,
                            &[
                                u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                                u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                                2,
                            ],
                        );
                    }
                    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    match allocate.poll(cursor.now) {
                        Err(Error::Readback | Error::Controller { .. }) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("unexpected bandwidth write outcome"),
                    }
                }
                assert!(failed, "write={target} failure={failure}");
                assert_eq!(peer.writes.len(), target);
                let writes = model.state.lock().unwrap().writes.len();
                assert!(matches!(
                    allocate.poll(cursor.now + 1),
                    Err(Error::Poisoned)
                ));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
                let mut channel = allocate.into_channel();
                assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
                assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
                channel_release(&mut channel);
            }
        }
    }
    #[test]
    fn bandwidth_both_hca_windows_start_at_ack_and_never_extend() {
        use super::super::usb3::{Allocate, Error, Rates};
        for clear in [false, true] {
            let (
                PathFixture {
                    domain,
                    model,
                    channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                },
                accounting,
                accounting_drop,
            ) = bandwidth_fixture(Rates {
                upstream: 1000,
                downstream: 2000,
            });
            drop(reservation);
            let mut peer = BandwidthPeer::new(&linked, accounting.grant, 9);
            peer.hold[usize::from(clear)] = true;
            // SAFETY: real synthetic owner with stalled device HCA transition.
            let mut allocate =
                unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
            allocate.poll(cursor.now).unwrap();
            let mut ack = None;
            let mut failed = false;
            let target = if clear { 4 } else { 1 };
            for _ in 0..2000 {
                match bandwidth_step(&mut peer, &domain, &model, &mut allocate, &mut cursor) {
                    Err(Error::Timeout) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {
                        if peer.writes.len() == target {
                            ack.get_or_insert(cursor.now);
                        }
                    }
                    _ => panic!("HCA stall claimed success"),
                }
            }
            assert!(failed);
            assert_eq!(cursor.now, ack.expect("actual source write ACK") + 1500);
            assert_eq!(peer.writes.len(), target);
            let mut channel = allocate.into_channel();
            assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
            assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
    }
    #[test]
    fn bandwidth_invalid_native_grants_and_storage_refuse_before_publication() {
        use super::super::usb3::{Allocate, Rates};
        for case in 0..11 {
            let (
                PathFixture {
                    model,
                    channel,
                    mut linked,
                    reservation,
                    cursor,
                    dropped,
                    ..
                },
                accounting,
                accounting_drop,
            ) = bandwidth_fixture(Rates {
                upstream: 1000,
                downstream: 2000,
            });
            drop(reservation);
            let mut grant = accounting.grant;
            match case {
                0 => grant.identity.epoch += 1,
                1 => grant.topology_epoch += 1,
                2 => grant.grant_epoch = 0,
                3 => grant.permission = super::super::router::Decision::Denied,
                4 => grant.permission = super::super::router::Decision::Unresolved,
                5 => grant.usb3_down = linked.partners.parent[0],
                6 => grant.usb3_up = linked.partners.child[0],
                7 => grant.requested.upstream = u32::MAX,
                8 => linked.link_usb4 = false,
                9 | 10 => {}
                _ => unreachable!(),
            };
            let replacement = Arc::new(BandwidthReservation {
                current: accounting.current.clone(),
                grant,
                dropped: accounting_drop.clone(),
            });
            drop(accounting);
            let writes = model.state.lock().unwrap().writes.len();
            // SAFETY: exact negative synthetic pairing; invalid metadata/storage must refuse.
            let result = unsafe {
                if case == 9 {
                    Allocate::new_without_storage(channel, linked, replacement, cursor.now)
                } else {
                    Allocate::new(
                        channel,
                        linked,
                        replacement,
                        if case == 10 { u64::MAX } else { cursor.now },
                    )
                }
            };
            assert!(result.is_err());
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
            assert_eq!(accounting_drop.load(Ordering::Relaxed), 2);
        }
    }
    #[test]
    fn bandwidth_busy_controller_encoding_and_unconsumed_receipts_keep_original_owners() {
        use super::super::usb3::{Allocate, Error, Rates};
        for case in 0..5 {
            let (
                PathFixture {
                    domain,
                    model,
                    channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                },
                accounting,
                accounting_drop,
            ) = bandwidth_fixture(Rates {
                upstream: 1000,
                downstream: 2000,
            });
            drop(reservation);
            let mut peer = BandwidthPeer::new(&linked, accounting.grant, 9);
            match case {
                0 => peer.control |= 1 << 31,
                1 => peer.consumed |= 1 << 31,
                2 => peer.header[2] ^= 1,
                3 => peer.scale = 63,
                4 => {}
                _ => unreachable!(),
            };
            // SAFETY: exact retained synthetic physical controller/accounting grant.
            let mut allocate =
                unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
            if case == 4 {
                let allocated =
                    drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
                drop(allocated);
            } else {
                allocate.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..50 {
                    match bandwidth_step(&mut peer, &domain, &model, &mut allocate, &mut cursor) {
                        Err(Error::Busy | Error::Changed | Error::Encoding) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("invalid controller state admitted"),
                    }
                }
                assert!(failed);
                assert_eq!(peer.writes.len(), usize::from(case == 3));
            }
            let mut channel = allocate.into_channel();
            assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
            assert_eq!(
                accounting_drop.load(Ordering::Relaxed),
                usize::from(case < 3)
            );
            channel_release(&mut channel);
        }
    }
    #[test]
    fn bandwidth_path_composition_wrong_permission_epoch_never_copies_authority() {
        use super::super::{
            path::Activate,
            usb3::{Allocate, Rates},
        };
        let (
            PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: 1000,
            downstream: 2000,
        });
        let mut peer = BandwidthPeer::new(&linked, accounting.grant, 0);
        // SAFETY: actual matching protected synthetic link and native grant.
        let mut allocate =
            unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
        let allocated = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
        let channel = allocate.into_channel();
        let mut allocation = reservation.allocation;
        allocation.grant_epoch += 1;
        let replacement = Arc::new(PathReservation {
            allocation,
            dropped: dropped[3].clone(),
        });
        drop(reservation);
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: metadata mismatch is a negative actual-model pairing; no request permitted.
        assert!(
            unsafe { Activate::with_bandwidth(channel, allocated, replacement, cursor.now) }
                .is_err()
        );
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
        assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
    }
    #[test]
    #[ignore = "requires unchanged Linux root USB3 bandwidth oracle"]
    fn unchanged_linux_usb3_bandwidth_complete_writes_and_rates_match_actual_dma() {
        use super::super::usb3::{Allocate, Rates};
        let text = std::fs::read_to_string(
            std::env::var("STELA_USB3_BANDWIDTH_ORACLE").expect("set oracle trace path"),
        )
        .unwrap();
        let mut cases = 0;
        for line in text.lines() {
            let v: Vec<u32> = line
                .split_ascii_whitespace()
                .skip(1)
                .map(|s| s.parse().unwrap())
                .collect();
            let count = v[8] as usize;
            let (
                PathFixture {
                    domain,
                    model,
                    channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                },
                accounting,
                accounting_drop,
            ) = bandwidth_fixture(Rates {
                upstream: v[1],
                downstream: v[2],
            });
            drop(reservation);
            let mut peer = BandwidthPeer::new(&linked, accounting.grant, v[0]);
            peer.consumed = v[3];
            peer.control = v[4];
            peer.scale = v[5];
            // SAFETY: exact protected actual synthetic accounting/permission/link fixture.
            let mut allocate =
                unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
            let allocated = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
            let expected: Vec<_> = v[9..9 + 2 * count]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| (v[0] as u16, v[1]))
                .collect();
            assert_eq!(peer.writes, expected, "case={cases}");
            assert_eq!(
                allocated.allocated,
                Rates {
                    upstream: v[6],
                    downstream: v[7]
                },
                "case={cases}"
            );
            assert_eq!(
                [peer.consumed, peer.control, peer.scale],
                v[9 + 2 * count..],
                "case={cases}"
            );
            let mut channel = allocate.into_channel();
            // SAFETY: native allocation and all original owners transfer through actual synthetic final drain.
            unsafe { allocated.retire() };
            assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 1));
            assert_eq!(accounting_drop.load(Ordering::Relaxed), 1);
            channel_release(&mut channel);
            cases += 1;
        }
        assert_eq!(cases, 512);
    }
    #[test]
    fn bandwidth_full_tx_clock_cancel_and_hotplug_never_release_native_owners() {
        use super::super::{
            config::{Address, Route, Space},
            usb3::{Allocate, Error, Rates},
        };
        for case in 0..4 {
            let (
                PathFixture {
                    domain,
                    model,
                    mut channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                },
                accounting,
                accounting_drop,
            ) = bandwidth_fixture(Rates {
                upstream: 1000,
                downstream: 2000,
            });
            drop(reservation);
            let mut peer = BandwidthPeer::new(&linked, accounting.grant, 9);
            if case == 0 {
                for _ in 0..9 {
                    channel
                        .read(
                            Route::new(0).unwrap(),
                            Address {
                                port: 1,
                                space: Space::Port,
                                offset: 4,
                                words: 1,
                            },
                            cursor.now,
                            cursor.now + 1000,
                        )
                        .unwrap();
                    let reply = adapter_response(&domain, &model, cursor.tx % 10, 4, &[0]);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(
                        channel.poll(cursor.now),
                        Ok(Some(super::super::channel::Event::Completed { .. }))
                    ));
                }
            }
            // SAFETY: exact physical model owners, idle software channel; case0 leaves real TX descriptors unconsumed.
            let mut allocate =
                unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
            if case == 0 {
                let writes = model.state.lock().unwrap().writes.len();
                for delta in [0, 1, 499] {
                    assert!(allocate.poll(cursor.now + delta).unwrap().is_none());
                }
                assert!(matches!(
                    allocate.poll(cursor.now + 500),
                    Err(Error::Timeout)
                ));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            } else if case == 1 {
                assert!(matches!(
                    allocate.poll(cursor.now - 1),
                    Err(Error::ClockRegressed)
                ));
            } else {
                allocate.poll(cursor.now).unwrap();
                for _ in 0..20 {
                    assert!(
                        bandwidth_step(&mut peer, &domain, &model, &mut allocate, &mut cursor)
                            .unwrap()
                            .is_none()
                    );
                    if !peer.writes.is_empty() {
                        break;
                    }
                }
                assert_eq!(peer.writes.len(), 1);
                if case == 2 {
                    assert!(matches!(allocate.cancel(), Err(Error::Cancelled)));
                } else {
                    finish_rx(
                        &model,
                        cursor.rx % 10,
                        &incoming(PacketType::Event, &[0, 0, 1]),
                    );
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(allocate.poll(cursor.now), Err(Error::Hotplug(_))));
                }
            }
            let mut channel = allocate.into_channel();
            assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
            assert_eq!(
                accounting_drop.load(Ordering::Relaxed),
                usize::from(case < 2)
            );
            channel_release(&mut channel);
        }
    }
    struct TunnelFixture {
        current: Arc<AtomicBool>,
        domain: Arc<Domain>,
        model: Arc<Model>,
        channel: super::super::channel::Channel<Model>,
        bandwidth: Box<super::super::usb3::Allocated>,
        down: Arc<PathReservation>,
        up: Arc<PathReservation>,
        cursor: NativeCursor,
        dropped: [Arc<AtomicUsize>; 6],
        band_writes: Vec<(u16, u32)>,
    }
    fn tunnel_fixture(credits: super::super::path::LaneCredits, seed: u32) -> TunnelFixture {
        use super::super::{
            path::Direction,
            usb3::{Allocate, Rates},
        };
        let wanted = [0, 1, 1023, 8191, 10000, 16384, 18000, 20000];
        let (
            PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: wanted[seed as usize % 8],
            downstream: wanted[(seed as usize / 8) % 8],
        });
        let mut allocation = reservation.allocation;
        allocation.lane_credits = credits;
        let down_drop = Arc::new(AtomicUsize::new(0));
        let up_drop = Arc::new(AtomicUsize::new(0));
        let down = Arc::new(PathReservation {
            allocation,
            dropped: down_drop.clone(),
        });
        allocation.direction = Direction::Upstream;
        let up = Arc::new(PathReservation {
            allocation,
            dropped: up_drop.clone(),
        });
        drop(reservation);
        let current = accounting.current.clone();
        let mut peer = BandwidthPeer::new(&linked, accounting.grant, seed);
        // SAFETY: actual protected native synthetic link/accounting/permission.
        let mut allocate =
            unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
        let bandwidth = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
        let channel = allocate.into_channel();
        TunnelFixture {
            current,
            domain,
            model,
            channel,
            bandwidth,
            down,
            up,
            cursor,
            dropped: [
                dropped[0].clone(),
                dropped[1].clone(),
                dropped[2].clone(),
                accounting_drop,
                down_drop,
                up_drop,
            ],
            band_writes: peer.writes,
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TunnelWrite {
        route: u64,
        port: u8,
        space: u8,
        offset: u16,
        data: Vec<u32>,
    }
    struct TunnelPeer {
        down: PathPeer,
        up: PathPeer,
        endpoints: [u32; 2],
        writes: Vec<TunnelWrite>,
        clear_valid: bool,
        reject: Option<usize>,
        fail_second_header: bool,
    }
    impl TunnelPeer {
        fn new(fixture: &TunnelFixture, stale: bool, seed: u32) -> Self {
            Self {
                down: PathPeer::new(
                    fixture.bandwidth.linked(),
                    fixture.down.allocation,
                    stale,
                    seed,
                ),
                up: PathPeer::new(
                    fixture.bandwidth.linked(),
                    fixture.up.allocation,
                    stale,
                    seed + 1,
                ),
                endpoints: [0; 2],
                writes: vec![],
                clear_valid: seed & 1 != 0,
                reject: None,
                fail_second_header: false,
            }
        }
        fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
            let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
            let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
            let bytes = domain.data(
                model.frame_address(Direction::Tx, index),
                (descriptor & 4095) as usize,
            );
            let words: Vec<u32> = bytes[..bytes.len() - 4]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|b| u32::from_be_bytes(*b))
                .collect();
            let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
            let address = words[2];
            let port = ((address >> 19) & 63) as u8;
            let space = ((address >> 25) & 3) as u8;
            let offset = (address & 8191) as u16;
            if kind == PacketType::Write {
                self.writes.push(TunnelWrite {
                    route,
                    port,
                    space,
                    offset,
                    data: words[3..].to_vec(),
                });
            }
            let reject = kind == PacketType::Write && self.reject == Some(self.writes.len());
            if space == 1 && offset == 0x50 {
                let endpoint = if route == self.down.routes[0] && port == self.down.ports[0] {
                    0
                } else {
                    assert_eq!((route, port), (self.up.routes[0], self.up.ports[0]));
                    1
                };
                let data = if kind == PacketType::Write {
                    assert!(matches!(words[3], 0xc0000000 | 0x40000000));
                    let value = if reject {
                        words[3] ^ (1 << 31)
                    } else {
                        words[3]
                    };
                    self.endpoints[endpoint] = if self.clear_valid {
                        value & !(1 << 30)
                    } else {
                        value
                    };
                    vec![]
                } else {
                    vec![self.endpoints[endpoint]]
                };
                let upstream = if endpoint == 0 {
                    self.down.upstream[0]
                } else {
                    self.up.upstream[0]
                };
                let mut reply = words[..3].to_vec();
                reply[0] |= 1 << 31;
                reply[2] = (address & !(63 << 19)) | (u32::from(upstream) << 19);
                reply.extend(data);
                return incoming(kind, &reply);
            }
            let down = self
                .down
                .routes
                .iter()
                .zip(self.down.ports)
                .any(|(r, p)| *r == route && p == port);
            let changed_second = !down && self.fail_second_header && self.down.writes.len() >= 4;
            let peer = if down { &mut self.down } else { &mut self.up };
            if reject {
                peer.reject = Some(peer.writes.len() + 1);
            }
            if changed_second {
                peer.changed_header = true;
            }
            peer.respond(domain, model, index)
        }
    }
    fn tunnel_step(
        peer: &mut TunnelPeer,
        domain: &Domain,
        model: &Model,
        engine: &mut super::super::usb3::ActivateTunnel<Model>,
        cursor: &mut NativeCursor,
    ) -> Result<Option<super::super::usb3::TunnelEvent>, super::super::usb3::Error> {
        if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
            cursor.now += 1;
            return engine.poll(cursor.now);
        }
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        engine.poll(cursor.now)
    }
    fn drive_tunnel(
        peer: &mut TunnelPeer,
        domain: &Domain,
        model: &Model,
        engine: &mut super::super::usb3::ActivateTunnel<Model>,
        cursor: &mut NativeCursor,
    ) -> Box<super::super::usb3::ActiveTunnel> {
        use super::super::usb3::TunnelEvent;
        engine.poll(cursor.now).unwrap();
        for _ in 0..200 {
            match tunnel_step(peer, domain, model, engine, cursor).unwrap() {
                Some(TunnelEvent::Active(value)) => return value,
                Some(TunnelEvent::Discarded(error)) => panic!("{error:?}"),
                None => {}
            }
        }
        panic!("actual source USB3 tunnel phase did not finish")
    }
    #[test]
    fn tunnel_both_real_paths_then_endpoints_use_one_bandwidth_link_and_retained_owners() {
        use super::super::{path::LaneCredits, usb3::ActivateTunnel};
        for credits in [LaneCredits::LegacyBonded, LaneCredits::RouterAllocated(23)] {
            for stale in [false, true] {
                for seed in [2, 3] {
                    let fixture = tunnel_fixture(credits, seed);
                    let mut peer = TunnelPeer::new(&fixture, stale, seed);
                    let TunnelFixture {
                        domain,
                        model,
                        channel,
                        bandwidth,
                        down,
                        up,
                        mut cursor,
                        dropped,
                        ..
                    } = fixture;
                    // SAFETY: actual synthetic CM also retains real exclusive endpoint CS0 authority, both path grants and one bandwidth/link.
                    let mut engine =
                        unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }
                            .unwrap();
                    let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
                    assert_eq!(peer.writes.len(), if stale { 10 } else { 6 });
                    let n = peer.writes.len();
                    assert_eq!(
                        (
                            peer.writes[n - 2].route,
                            peer.writes[n - 2].port,
                            peer.writes[n - 2].offset
                        ),
                        (0, 6, 0x50)
                    );
                    assert_eq!(
                        (
                            peer.writes[n - 1].route,
                            peer.writes[n - 1].port,
                            peer.writes[n - 1].offset
                        ),
                        (2, 4, 0x50)
                    );
                    assert!(active.endpoints.iter().all(|v| v & (1 << 31) != 0));
                    assert_eq!(active.endpoints, peer.endpoints);
                    assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
                    let mut channel = engine.into_channel();
                    // SAFETY: whole live native synthetic tunnel and all six owners transfer through actual final drain.
                    unsafe { active.retire() };
                    assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
                    channel_release(&mut channel);
                }
            }
        }
    }
    #[test]
    fn tunnel_all_ten_possible_writes_keep_both_paths_accounting_and_link_on_failure() {
        use super::super::{
            path::LaneCredits,
            usb3::{ActivateTunnel, Error},
        };
        for target in 1..=10 {
            for failure in 0..3 {
                let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
                let mut peer = TunnelPeer::new(&fixture, true, 2);
                if failure == 2 {
                    peer.reject = Some(target);
                }
                let TunnelFixture {
                    domain,
                    model,
                    channel,
                    bandwidth,
                    down,
                    up,
                    mut cursor,
                    dropped,
                    ..
                } = fixture;
                // SAFETY: exact protected actual synthetic endpoint authority and all owners.
                let mut engine =
                    unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }
                        .unwrap();
                engine.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..200 {
                    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                        cursor.now += 1;
                        assert!(engine.poll(cursor.now).unwrap().is_none());
                        continue;
                    }
                    let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                    if peer.writes.len() == target && failure == 0 {
                        cursor.now += 10001;
                        assert!(engine.poll(cursor.now).is_err());
                        failed = true;
                        break;
                    }
                    if peer.writes.len() == target && failure == 1 {
                        let bytes =
                            domain.data(model.frame_address(Direction::Tx, cursor.tx % 10), 16);
                        reply = incoming(
                            PacketType::Error,
                            &[
                                u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                                u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                                2,
                            ],
                        );
                    }
                    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    match engine.poll(cursor.now) {
                        Err(_) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("partial USB3 tunnel claimed success"),
                    }
                }
                assert!(failed, "write={target} failure={failure}");
                assert_eq!(peer.writes.len(), target);
                let writes = model.state.lock().unwrap().writes.len();
                assert!(matches!(engine.poll(cursor.now + 1), Err(Error::Poisoned)));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
                let mut channel = engine.into_channel();
                assert!(
                    dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0),
                    "all native owners retained write={target} failure={failure}"
                );
                channel_release(&mut channel);
            }
        }
    }
    #[test]
    fn tunnel_constructor_mismatch_and_both_storage_failures_retain_every_live_owner() {
        assert_ne!(
            core::mem::size_of::<super::super::path::Active>(),
            core::mem::size_of::<super::super::usb3::ActiveTunnel>(),
            "local size-selective null allocator must reach the second reservation"
        );
        use super::super::{
            path::{Direction, LaneCredits},
            usb3::ActivateTunnel,
        };
        for case in 0..10 {
            let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
            let TunnelFixture {
                model,
                channel,
                bandwidth,
                down,
                up,
                cursor,
                dropped,
                ..
            } = fixture;
            let mut allocation = up.allocation;
            match case {
                0 => allocation.identity.epoch += 1,
                1 => allocation.topology_epoch += 1,
                2 => allocation.grant_epoch += 1,
                3 => allocation.usb3_up = 1,
                4 => allocation.direction = Direction::Downstream,
                5 => allocation.hops[0].0 = 9,
                6 => allocation.permission = super::super::router::Decision::Denied,
                7..=9 => {}
                _ => unreachable!(),
            };
            let replacement = Arc::new(PathReservation {
                allocation,
                dropped: dropped[5].clone(),
            });
            drop(up);
            let writes = model.state.lock().unwrap().writes.len();
            // SAFETY: same negative actual synthetic native transaction. All protected wrappers must remain retained on failed construction.
            let result = unsafe {
                if case >= 8 {
                    ActivateTunnel::new_without_storage(
                        channel,
                        bandwidth,
                        down,
                        replacement,
                        cursor.now,
                        case == 9,
                    )
                } else {
                    ActivateTunnel::new(
                        channel,
                        bandwidth,
                        down,
                        replacement,
                        if case == 7 { u64::MAX } else { cursor.now },
                    )
                }
            };
            assert!(result.is_err());
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            assert!(dropped[..5].iter().all(|v| v.load(Ordering::Relaxed) == 0));
            assert_eq!(
                dropped[5].load(Ordering::Relaxed),
                1,
                "only old replaced model lease may drop"
            );
        }
    }
    #[test]
    fn tunnel_busy_endpoints_second_path_preflight_and_unconsumed_completion_retain_chain() {
        use super::super::{
            path::LaneCredits,
            usb3::{ActivateTunnel, Error},
        };
        for case in 0..4 {
            let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
            let mut peer = TunnelPeer::new(&fixture, true, 2);
            if case < 2 {
                peer.endpoints[case] = 1 << 31;
            }
            peer.fail_second_header = case == 2;
            let TunnelFixture {
                domain,
                model,
                channel,
                bandwidth,
                down,
                up,
                mut cursor,
                dropped,
                ..
            } = fixture;
            // SAFETY: actual same retained native controller and endpoint authority; negative wire states are explicit.
            let mut engine =
                unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
            if case == 3 {
                let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
                drop(active);
            } else {
                engine.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..200 {
                    match tunnel_step(&mut peer, &domain, &model, &mut engine, &mut cursor) {
                        Err(Error::Busy | Error::Path(_)) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("invalid endpoint/second path was admitted"),
                    }
                }
                assert!(failed);
                assert_eq!(peer.writes.len(), if case == 2 { 4 } else { 0 });
            }
            let mut channel = engine.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
    #[test]
    fn tunnel_clock_cancel_hotplug_and_full_endpoint_tx_never_release_active_resources() {
        use super::super::{
            config::{Address, Route, Space},
            path::LaneCredits,
            usb3::{ActivateTunnel, Error},
        };
        for case in 0..4 {
            let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
            let mut peer = TunnelPeer::new(&fixture, true, 2);
            let TunnelFixture {
                domain,
                model,
                mut channel,
                bandwidth,
                down,
                up,
                mut cursor,
                dropped,
                ..
            } = fixture;
            if case == 3 {
                for _ in 0..9 {
                    channel
                        .read(
                            Route::new(0).unwrap(),
                            Address {
                                port: 1,
                                space: Space::Port,
                                offset: 4,
                                words: 1,
                            },
                            cursor.now,
                            cursor.now + 1000,
                        )
                        .unwrap();
                    let reply = adapter_response(&domain, &model, cursor.tx % 10, 4, &[0]);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(
                        channel.poll(cursor.now),
                        Ok(Some(super::super::channel::Event::Completed { .. }))
                    ));
                }
            }
            // SAFETY: exact endpoint/native accounting/path authority; case3 has physically unconsumed TX slots.
            let mut engine =
                unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
            if case == 0 {
                assert!(matches!(
                    engine.poll(cursor.now - 1),
                    Err(Error::ClockRegressed)
                ));
            } else if case == 3 {
                let writes = model.state.lock().unwrap().writes.len();
                for delta in [0, 1, 499] {
                    assert!(engine.poll(cursor.now + delta).unwrap().is_none());
                }
                assert!(matches!(engine.poll(cursor.now + 500), Err(Error::Timeout)));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            } else {
                engine.poll(cursor.now).unwrap();
                for _ in 0..200 {
                    assert!(
                        tunnel_step(&mut peer, &domain, &model, &mut engine, &mut cursor)
                            .unwrap()
                            .is_none()
                    );
                    if peer.writes.len() == 8 {
                        break;
                    }
                }
                assert_eq!(peer.writes.len(), 8);
                if case == 1 {
                    assert!(matches!(engine.cancel(), Err(Error::Cancelled)));
                } else {
                    finish_rx(
                        &model,
                        cursor.rx % 10,
                        &incoming(PacketType::Event, &[0, 0, 1]),
                    );
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(
                        engine.poll(cursor.now),
                        Err(Error::Path(_) | Error::Hotplug(_))
                    ));
                }
            }
            let mut channel = engine.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
    #[test]
    #[ignore = "requires unchanged Linux full root USB3 activation oracle"]
    fn unchanged_linux_usb3_tunnel_full_bandwidth_paths_and_endpoint_writes_match_dma() {
        use super::super::{path::LaneCredits, usb3::ActivateTunnel};
        let text = std::fs::read_to_string(
            std::env::var("STELA_USB3_TUNNEL_ORACLE").expect("set source trace path"),
        )
        .unwrap();
        let mut cases = 0;
        for line in text.lines() {
            let v: Vec<u32> = line
                .split_ascii_whitespace()
                .skip(1)
                .map(|s| s.parse().unwrap())
                .collect();
            let [mode, stale, seed, count] = v[..4] else {
                panic!("source case header")
            };
            let credits = if mode == 0 {
                LaneCredits::LegacyBonded
            } else {
                LaneCredits::RouterAllocated((17 + seed % 15) as u8)
            };
            let fixture = tunnel_fixture(credits, seed);
            let mut peer = TunnelPeer::new(&fixture, stale != 0, seed);
            let rates = fixture.bandwidth.allocated;
            let TunnelFixture {
                domain,
                model,
                channel,
                bandwidth,
                down,
                up,
                mut cursor,
                dropped,
                band_writes,
                ..
            } = fixture;
            let mut actual: Vec<_> = band_writes
                .into_iter()
                .map(|(offset, value)| TunnelWrite {
                    route: 0,
                    port: 6,
                    space: 1,
                    offset,
                    data: vec![value],
                })
                .collect();
            // SAFETY: real protected synthetic accounting, BOTH path grants, exact native endpoint control and unchanged epochs.
            let mut engine =
                unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
            let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
            actual.extend(peer.writes);
            let mut expected = Vec::new();
            let mut at = 4;
            for _ in 0..count {
                let length = v[at + 4] as usize;
                expected.push(TunnelWrite {
                    route: u64::from(v[at]),
                    port: v[at + 1] as u8,
                    space: v[at + 2] as u8,
                    offset: v[at + 3] as u16,
                    data: v[at + 5..at + 5 + length].to_vec(),
                });
                at += 5 + length;
            }
            assert_eq!(actual, expected, "case={cases}");
            assert_eq!(active.endpoints, v[at..at + 2], "case={cases}");
            assert_eq!(
                [rates.upstream, rates.downstream],
                v[at + 2..],
                "case={cases}"
            );
            let mut channel = engine.into_channel();
            // SAFETY: complete live native model tunnel transfers through real synthetic final drain.
            unsafe { active.retire() };
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 1));
            channel_release(&mut channel);
            cases += 1;
        }
        assert_eq!(cases, 128);
    }
    struct StopFixture {
        domain: Arc<Domain>,
        model: Arc<Model>,
        channel: super::super::channel::Channel<Model>,
        active: Box<super::super::usb3::ActiveTunnel>,
        peer: TunnelPeer,
        cursor: NativeCursor,
        current: Arc<AtomicBool>,
        dropped: [Arc<AtomicUsize>; 6],
        activation: Vec<TunnelWrite>,
        bandwidth_peer: BandwidthPeer,
    }
    fn stop_fixture(credits: super::super::path::LaneCredits, seed: u32) -> StopFixture {
        use super::super::usb3::ActivateTunnel;
        let fixture = tunnel_fixture(credits, seed);
        let mut peer = TunnelPeer::new(&fixture, true, seed);
        let control = fixture.band_writes.last().unwrap().1;
        let scale = fixture
            .band_writes
            .iter()
            .find(|(offset, _)| *offset == 0x53)
            .unwrap()
            .1;
        let bandwidth_peer = BandwidthPeer {
            port: 6,
            header: peer.down.headers[0],
            control,
            scale,
            consumed: if seed & 1 == 0 { 0 } else { 1023 }
                | ((if seed.is_multiple_of(3) { 1023 } else { 255 }) << 12),
            writes: vec![],
            transition: None,
            polls: 0,
            hold: [false; 2],
            reject: None,
        };
        let TunnelFixture {
            domain,
            model,
            channel,
            bandwidth,
            down,
            up,
            mut cursor,
            current,
            dropped,
            band_writes,
        } = fixture;
        // SAFETY: complete actual synthetic control/accounting/path authority.
        let mut engine =
            unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
        let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
        let channel = engine.into_channel();
        let mut activation: Vec<_> = band_writes
            .into_iter()
            .map(|(offset, value)| TunnelWrite {
                route: 0,
                port: 6,
                space: 1,
                offset,
                data: vec![value],
            })
            .collect();
        activation.append(&mut peer.writes);
        peer.down.writes.clear();
        peer.up.writes.clear();
        for path in [&mut peer.down, &mut peer.up] {
            for i in 0..2 {
                path.raw[i][1] |= 1 << 28;
                path.disabled[i] = false;
                path.reads[i] = 0;
            }
        }
        StopFixture {
            domain,
            model,
            channel,
            active,
            peer,
            cursor,
            current,
            dropped,
            activation,
            bandwidth_peer,
        }
    }
    fn stop_step(
        peer: &mut TunnelPeer,
        domain: &Domain,
        model: &Model,
        engine: &mut super::super::usb3::StopTunnel<Model>,
        cursor: &mut NativeCursor,
    ) -> Result<Option<super::super::usb3::StopEvent>, super::super::usb3::Error> {
        if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
            cursor.now += 1;
            return engine.poll(cursor.now);
        }
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        engine.poll(cursor.now)
    }
    fn drive_stop(
        peer: &mut TunnelPeer,
        domain: &Domain,
        model: &Model,
        engine: &mut super::super::usb3::StopTunnel<Model>,
        cursor: &mut NativeCursor,
    ) -> Box<super::super::usb3::Stopped> {
        use super::super::usb3::StopEvent;
        engine.poll(cursor.now).unwrap();
        for _ in 0..200 {
            match stop_step(peer, domain, model, engine, cursor).unwrap() {
                Some(StopEvent::Stopped(value)) => return value,
                Some(StopEvent::Discarded(e)) => panic!("{e:?}"),
                None => {}
            }
        }
        panic!("normal actual tunnel stop did not finish")
    }
    fn release_step(
        peer: &mut BandwidthPeer,
        domain: &Domain,
        model: &Model,
        engine: &mut super::super::usb3::ReleaseUnused<Model>,
        cursor: &mut NativeCursor,
    ) -> Result<Option<super::super::usb3::TunnelEvent>, super::super::usb3::Error> {
        if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
            cursor.now += 1;
            return engine.poll(cursor.now);
        }
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        engine.poll(cursor.now)
    }
    fn drive_release(
        peer: &mut BandwidthPeer,
        domain: &Domain,
        model: &Model,
        engine: &mut super::super::usb3::ReleaseUnused<Model>,
        cursor: &mut NativeCursor,
    ) -> Box<super::super::usb3::ActiveTunnel> {
        use super::super::usb3::TunnelEvent;
        engine.poll(cursor.now).unwrap();
        for _ in 0..100 {
            match release_step(peer, domain, model, engine, cursor).unwrap() {
                Some(TunnelEvent::Active(value)) => return value,
                Some(TunnelEvent::Discarded(e)) => panic!("{e:?}"),
                None => {}
            }
        }
        panic!("source release-unused handshake did not finish")
    }
    #[test]
    fn teardown_normal_does_not_release_bandwidth_and_returns_local_owners_only_explicitly() {
        use super::super::{path::LaneCredits, usb3::StopTunnel};
        for unconsumed in [false, true] {
            let StopFixture {
                domain,
                model,
                channel,
                active,
                mut peer,
                mut cursor,
                dropped,
                ..
            } = stop_fixture(LaneCredits::LegacyBonded, 2);
            let residual = active.bandwidth_rates();
            // SAFETY: real exact synthetic native epoch/authority, host admission closed and independent endpoint lifetimes retained.
            let mut stop = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
            let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
            assert_eq!(peer.writes.len(), 6);
            assert!(
                peer.writes[..2]
                    .iter()
                    .all(|w| w.space == 1 && w.offset == 0x50 && w.data == [1 << 30])
            );
            assert_eq!(stopped.bandwidth_rates(), residual);
            assert!(stopped.endpoints.iter().all(|w| w & (1 << 31) == 0));
            assert!(
                stopped
                    .hops
                    .iter()
                    .all(|w| w.raw[0] & (1 << 31) == 0 && w.raw[1] & (1 << 28) == 0)
            );
            let mut channel = stop.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            if unconsumed {
                drop(stopped);
                assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            } else {
                let reusable = match stopped.into_reusable() {
                    Ok(value) => value,
                    Err(_) => panic!("live native guard refused"),
                };
                drop(reusable.paths);
                assert_eq!(dropped[4].load(Ordering::Relaxed), 1);
                assert_eq!(dropped[5].load(Ordering::Relaxed), 1);
                assert!(dropped[..4].iter().all(|v| v.load(Ordering::Relaxed) == 0));
                // SAFETY: residual accounting/link have actual independent native provider retirement/transfer, beyond local path proof.
                unsafe { reusable.residual.retire() };
                assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
            }
            channel_release(&mut channel);
        }
    }
    #[test]
    fn teardown_separate_release_unused_retains_900_floor_and_active_owner_chain() {
        use super::super::{
            path::LaneCredits,
            usb3::{ReleaseUnused, StopTunnel},
        };
        let StopFixture {
            domain,
            model,
            channel,
            active,
            mut peer,
            mut cursor,
            dropped,
            mut bandwidth_peer,
            ..
        } = stop_fixture(LaneCredits::RouterAllocated(23), 0);
        // SAFETY: actual protected native branch accounting explicitly reserves source consumed/900 floor; active paths stay retained.
        let mut release = unsafe { ReleaseUnused::new(channel, active, cursor.now) }.unwrap();
        let active = drive_release(
            &mut bandwidth_peer,
            &domain,
            &model,
            &mut release,
            &mut cursor,
        );
        assert!(active.bandwidth_rates().upstream >= 900);
        assert!(active.bandwidth_rates().downstream >= 900);
        assert_eq!(bandwidth_peer.writes.len(), 4);
        assert!(peer.endpoints.iter().all(|w| w & (1 << 31) != 0));
        let channel = release.into_channel();
        // SAFETY: same actual native epoch and submission/endpoint lifetime proof.
        let mut stop = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
        let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
        let mut channel = stop.into_channel();
        let reusable = match stopped.into_reusable() {
            Ok(v) => v,
            Err(_) => panic!("guard"),
        };
        assert!(reusable.residual.allocated.upstream >= 900);
        assert!(reusable.residual.allocated.downstream >= 900);
        drop(reusable.paths);
        // SAFETY: actual residual provider lifetime transfers independently.
        unsafe { reusable.residual.retire() };
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
        channel_release(&mut channel);
    }

    fn controller_error(domain: &Domain, model: &Model, cursor: &NativeCursor) -> Encoded {
        let bytes = domain.data(model.frame_address(Direction::Tx, cursor.tx % 10), 16);
        incoming(
            PacketType::Error,
            &[
                u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                2,
            ],
        )
    }
    #[test]
    fn teardown_each_endpoint_and_hop_disable_failure_retains_all_six_native_owners() {
        use super::super::{
            path::LaneCredits,
            usb3::{Error, StopTunnel},
        };
        for target in 1..=6 {
            for failure in 0..3 {
                let StopFixture {
                    domain,
                    model,
                    channel,
                    active,
                    mut peer,
                    mut cursor,
                    dropped,
                    ..
                } = stop_fixture(LaneCredits::LegacyBonded, 2);
                if failure == 2 {
                    peer.reject = Some(target);
                }
                // SAFETY: matching physical epoch/authority and independently closed native admission.
                let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
                engine.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..200 {
                    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                        cursor.now += 1;
                        assert!(engine.poll(cursor.now).unwrap().is_none());
                        continue;
                    }
                    let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                    if peer.writes.len() == target && failure == 0 {
                        cursor.now += 501;
                        assert!(matches!(engine.poll(cursor.now), Err(Error::Timeout)));
                        failed = true;
                        break;
                    }
                    if peer.writes.len() == target && failure == 1 {
                        reply = controller_error(&domain, &model, &cursor);
                    }
                    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    match engine.poll(cursor.now) {
                        Err(_) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("uncertain stop returned reusable owners"),
                    }
                }
                assert!(failed, "write={target} failure={failure}");
                assert_eq!(peer.writes.len(), target);
                let writes = model.state.lock().unwrap().writes.len();
                assert!(matches!(engine.poll(cursor.now + 1), Err(Error::Poisoned)));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
                let mut channel = engine.into_channel();
                assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
                channel_release(&mut channel);
            }
        }
    }
    #[test]
    fn teardown_release_unused_each_uncertain_write_retains_both_split_owner_halves() {
        use super::super::{
            path::LaneCredits,
            usb3::{Error, ReleaseUnused},
        };
        for target in 1..=4 {
            for failure in 0..3 {
                let StopFixture {
                    domain,
                    model,
                    channel,
                    active,
                    mut cursor,
                    dropped,
                    mut bandwidth_peer,
                    ..
                } = stop_fixture(LaneCredits::RouterAllocated(23), 2);
                if failure == 2 {
                    bandwidth_peer.reject = Some(target);
                }
                // SAFETY: actual native accounting and active endpoint authority across this adjustment.
                let mut engine =
                    unsafe { ReleaseUnused::new(channel, active, cursor.now) }.unwrap();
                engine.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..100 {
                    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                        cursor.now += 1;
                        assert!(engine.poll(cursor.now).unwrap().is_none());
                        continue;
                    }
                    let mut reply = bandwidth_peer.respond(&domain, &model, cursor.tx % 10);
                    if bandwidth_peer.writes.len() == target && failure == 0 {
                        cursor.now += 1501;
                        assert!(matches!(engine.poll(cursor.now), Err(Error::Timeout)));
                        failed = true;
                        break;
                    }
                    if bandwidth_peer.writes.len() == target && failure == 1 {
                        reply = controller_error(&domain, &model, &cursor);
                    }
                    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    match engine.poll(cursor.now) {
                        Err(_) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("uncertain release succeeded"),
                    }
                }
                assert!(failed, "write={target} failure={failure}");
                assert_eq!(bandwidth_peer.writes.len(), target);
                assert!(matches!(engine.poll(cursor.now + 1), Err(Error::Poisoned)));
                let mut channel = engine.into_channel();
                assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
                channel_release(&mut channel);
            }
        }
    }
    #[test]
    fn teardown_each_pending_drain_has_one_ack_anchored_deadline_including_already_disabled() {
        use super::super::{
            path::LaneCredits,
            usb3::{Error, StopTunnel},
        };
        for hop in 0..4 {
            for already_disabled in [false, true] {
                let StopFixture {
                    domain,
                    model,
                    channel,
                    active,
                    mut peer,
                    mut cursor,
                    dropped,
                    ..
                } = stop_fixture(LaneCredits::LegacyBonded, 2);
                let path = if hop < 2 {
                    &mut peer.down
                } else {
                    &mut peer.up
                };
                let lane = hop % 2;
                path.hold_hop[lane] = true;
                if already_disabled {
                    path.raw[lane][0] &= !(1 << 31);
                    path.disabled[lane] = true;
                }
                // SAFETY: exact unchanged physical owner chain; pending work is not assumed quiescent.
                let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
                engine.poll(cursor.now).unwrap();
                let prefix = if already_disabled { 2 + hop } else { 3 + hop };
                // Stop immediately after the actual disable ACK (or first disabled-state read).
                for _ in 0..200 {
                    assert!(
                        stop_step(&mut peer, &domain, &model, &mut engine, &mut cursor)
                            .unwrap()
                            .is_none()
                    );
                    let p = if hop < 2 { &peer.down } else { &peer.up };
                    if peer.writes.len() == prefix
                        && ((!already_disabled && p.disabled[lane] && p.reads[lane] == 0)
                            || (already_disabled && p.reads[lane] == 1))
                    {
                        break;
                    }
                }
                assert_eq!(peer.writes.len(), prefix);
                let anchor = cursor.now;
                for delta in [1, 49, 150, 499] {
                    cursor.now = anchor + delta - 1;
                    assert!(
                        stop_step(&mut peer, &domain, &model, &mut engine, &mut cursor)
                            .unwrap()
                            .is_none()
                    );
                    assert_eq!(cursor.now, anchor + delta);
                }
                assert!(matches!(engine.poll(anchor + 500), Err(Error::Timeout)));
                assert_eq!(peer.writes.len(), prefix);
                let mut channel = engine.into_channel();
                assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
                channel_release(&mut channel);
            }
        }
    }
    #[test]
    fn teardown_revocation_rejects_late_dma_and_owner_return_without_releasing_ids() {
        use super::super::{
            path::LaneCredits,
            usb3::{Error, StopTunnel},
        };
        for after_completion in [false, true] {
            let StopFixture {
                domain,
                model,
                channel,
                active,
                mut peer,
                mut cursor,
                current,
                dropped,
                ..
            } = stop_fixture(LaneCredits::LegacyBonded, 2);
            // SAFETY: exact admitted native epoch and closed host submissions, until deliberately revoked.
            let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
            if after_completion {
                let stopped = drive_stop(&mut peer, &domain, &model, &mut engine, &mut cursor);
                current.store(false, Ordering::Release);
                let (error, same) = match stopped.into_reusable() {
                    Err(v) => v,
                    Ok(_) => panic!("revoked owner return"),
                };
                assert!(matches!(error, Error::Revoked));
                drop(same);
            } else {
                engine.poll(cursor.now).unwrap();
                // Actual request published while current; real DMA reply arrives only after native revocation.
                let reply = peer.respond(&domain, &model, cursor.tx % 10);
                current.store(false, Ordering::Release);
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                let writes = model.state.lock().unwrap().writes.len();
                assert!(matches!(engine.poll(cursor.now + 1), Err(Error::Revoked)));
                current.store(true, Ordering::Release);
                assert!(matches!(engine.poll(cursor.now + 2), Err(Error::Poisoned)));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            }
            let mut channel = engine.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
    #[test]
    fn teardown_cancel_clock_null_storage_hotplug_and_revoked_constructor_keep_chain() {
        use super::super::{
            path::LaneCredits,
            usb3::{Error, StopTunnel},
        };
        for case in 0..6 {
            let StopFixture {
                domain,
                model,
                channel,
                active,
                mut peer,
                mut cursor,
                current,
                dropped,
                ..
            } = stop_fixture(LaneCredits::LegacyBonded, 2);
            let writes = model.state.lock().unwrap().writes.len();
            if case == 0 {
                current.store(false, Ordering::Release);
            }
            // SAFETY: actual paired native resources. Refusal cases must not publish or release anything.
            let result = unsafe {
                if case == 1 {
                    StopTunnel::new_without_storage(channel, active, cursor.now)
                } else {
                    StopTunnel::new(
                        channel,
                        active,
                        if case == 2 { u64::MAX } else { cursor.now },
                    )
                }
            };
            if case < 3 {
                assert!(matches!(
                    result,
                    Err(Error::Revoked | Error::Allocation | Error::ClockOverflow)
                ));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
                assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
                continue;
            }
            let mut engine = result.unwrap();
            if case == 3 {
                assert!(matches!(
                    engine.poll(cursor.now - 1),
                    Err(Error::ClockRegressed)
                ));
            } else {
                engine.poll(cursor.now).unwrap();
                for _ in 0..200 {
                    assert!(
                        stop_step(&mut peer, &domain, &model, &mut engine, &mut cursor)
                            .unwrap()
                            .is_none()
                    );
                    if peer.writes.len() == 2 {
                        break;
                    }
                }
                if case == 4 {
                    assert!(matches!(engine.cancel(), Err(Error::Cancelled)));
                } else {
                    finish_rx(
                        &model,
                        cursor.rx % 10,
                        &incoming(PacketType::Event, &[0, 0, 1]),
                    );
                    cursor.now += 1;
                    assert!(matches!(engine.poll(cursor.now), Err(Error::Hotplug(_))));
                }
            }
            let mut channel = engine.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
    #[test]
    fn teardown_live_guard_also_blocks_old_bandwidth_and_activation_admission_and_late_replies() {
        use super::super::{
            path::LaneCredits,
            usb3::{ActivateTunnel, Allocate, Error, Rates, ReleaseUnused},
        };
        for late in [false, true] {
            let (
                PathFixture {
                    domain,
                    model,
                    channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                },
                accounting,
                accounting_drop,
            ) = bandwidth_fixture(Rates {
                upstream: 10000,
                downstream: 18000,
            });
            drop(reservation);
            let current = accounting.current.clone();
            let mut peer = BandwidthPeer::new(&linked, accounting.grant, 2);
            if !late {
                current.store(false, Ordering::Release);
            }
            // SAFETY: exact physically admitted fixture; guard revocation is intentional.
            let result = unsafe { Allocate::new(channel, linked, accounting, cursor.now) };
            if late {
                let mut engine = result.unwrap();
                engine.poll(cursor.now).unwrap();
                let reply = peer.respond(&domain, &model, cursor.tx % 10);
                current.store(false, Ordering::Release);
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.now += 1;
                assert!(matches!(engine.poll(cursor.now), Err(Error::Revoked)));
                let mut channel = engine.into_channel();
                channel_release(&mut channel);
            } else {
                assert!(matches!(result, Err(Error::Revoked)));
            }
            assert!(dropped[..3].iter().all(|v| v.load(Ordering::Relaxed) == 0));
            assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
        }
        for late in [false, true] {
            let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
            let mut peer = TunnelPeer::new(&fixture, true, 2);
            let TunnelFixture {
                domain,
                model,
                channel,
                bandwidth,
                down,
                up,
                mut cursor,
                current,
                dropped,
                ..
            } = fixture;
            if !late {
                current.store(false, Ordering::Release);
            }
            // SAFETY: exact pair and real reservations, with native revocation explicitly modelled.
            let result = unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) };
            if late {
                let mut engine = result.unwrap();
                engine.poll(cursor.now).unwrap();
                let reply = peer.respond(&domain, &model, cursor.tx % 10);
                current.store(false, Ordering::Release);
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.now += 1;
                assert!(matches!(engine.poll(cursor.now), Err(Error::Revoked)));
                let mut channel = engine.into_channel();
                channel_release(&mut channel);
            } else {
                assert!(matches!(result, Err(Error::Revoked)));
            }
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        }
        for late in [false, true] {
            let StopFixture {
                domain,
                model,
                channel,
                active,
                mut bandwidth_peer,
                mut cursor,
                current,
                dropped,
                ..
            } = stop_fixture(LaneCredits::LegacyBonded, 2);
            if !late {
                current.store(false, Ordering::Release);
            }
            // SAFETY: actual active owner and exact native provider accounting authority.
            let result = unsafe { ReleaseUnused::new(channel, active, cursor.now) };
            if late {
                let mut engine = result.unwrap();
                engine.poll(cursor.now).unwrap();
                let reply = bandwidth_peer.respond(&domain, &model, cursor.tx % 10);
                current.store(false, Ordering::Release);
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.now += 1;
                assert!(matches!(engine.poll(cursor.now), Err(Error::Revoked)));
                let mut channel = engine.into_channel();
                channel_release(&mut channel);
            } else {
                assert!(matches!(result, Err(Error::Revoked)));
            }
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        }
    }

    #[test]
    #[ignore = "requires unchanged Linux complete USB3 stop/release oracle"]
    fn unchanged_linux_usb3_complete_activation_optional_release_and_stop_match_dma() {
        use super::super::{
            path::LaneCredits,
            usb3::{ReleaseUnused, StopTunnel},
        };
        let text = std::fs::read_to_string(
            std::env::var("STELA_USB3_STOP_ORACLE").expect("source trace path"),
        )
        .unwrap();
        let mut cases = 0;
        for line in text.lines() {
            let v: Vec<u32> = line
                .split_ascii_whitespace()
                .skip(1)
                .map(|s| s.parse().unwrap())
                .collect();
            let [mode, release, seed, count] = v[..4] else {
                panic!("source header")
            };
            let credits = if mode == 0 {
                LaneCredits::LegacyBonded
            } else {
                LaneCredits::RouterAllocated((17 + seed % 15) as u8)
            };
            let StopFixture {
                domain,
                model,
                mut channel,
                mut active,
                mut peer,
                mut cursor,
                dropped,
                mut activation,
                mut bandwidth_peer,
                ..
            } = stop_fixture(credits, seed);
            if release != 0 {
                // SAFETY: genuine model active receipt and retained native branch adjustment authority.
                let mut engine =
                    unsafe { ReleaseUnused::new(channel, active, cursor.now) }.unwrap();
                active = drive_release(
                    &mut bandwidth_peer,
                    &domain,
                    &model,
                    &mut engine,
                    &mut cursor,
                );
                channel = engine.into_channel();
                activation.extend(bandwidth_peer.writes.into_iter().map(|(offset, value)| {
                    TunnelWrite {
                        route: 0,
                        port: 6,
                        space: 1,
                        offset,
                        data: vec![value],
                    }
                }));
            }
            let rates = active.bandwidth_rates();
            // SAFETY: actual native guard, closed host admission and retained independent endpoint lifetimes.
            let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
            let stopped = drive_stop(&mut peer, &domain, &model, &mut engine, &mut cursor);
            activation.extend(peer.writes);
            let mut expected = Vec::new();
            let mut at = 4;
            for _ in 0..count {
                let length = v[at + 4] as usize;
                expected.push(TunnelWrite {
                    route: u64::from(v[at]),
                    port: v[at + 1] as u8,
                    space: v[at + 2] as u8,
                    offset: v[at + 3] as u16,
                    data: v[at + 5..at + 5 + length].to_vec(),
                });
                at += 5 + length;
            }
            assert_eq!(activation, expected, "case={cases}");
            assert_eq!(stopped.endpoints, v[at..at + 2], "case={cases}");
            assert_eq!(
                [rates.upstream, rates.downstream],
                v[at + 2..at + 4],
                "case={cases}"
            );
            let words: Vec<_> = stopped.hops.iter().flat_map(|w| w.raw).collect();
            assert_eq!(words, v[at + 4..], "case={cases}");
            let reusable = match stopped.into_reusable() {
                Ok(v) => v,
                Err(_) => panic!("model live epoch"),
            };
            drop(reusable.paths);
            // SAFETY: model provider independently completes residual accounting/link lifetime transfer.
            unsafe { reusable.residual.retire() };
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
            let mut channel = engine.into_channel();
            channel_release(&mut channel);
            cases += 1;
        }
        assert_eq!(cases, 128);
    }

    #[test]
    fn teardown_refuses_changed_owned_hops_before_disabling_them_and_full_tx_stays_bounded() {
        use super::super::{
            config::{Address, Route, Space},
            path::LaneCredits,
            usb3::{Error, StopTunnel},
        };
        for case in 0..5 {
            let StopFixture {
                domain,
                model,
                mut channel,
                active,
                mut peer,
                mut cursor,
                dropped,
                ..
            } = stop_fixture(LaneCredits::LegacyBonded, 2);
            if case < 4 {
                let p = if case < 2 {
                    &mut peer.down
                } else {
                    &mut peer.up
                };
                p.raw[case % 2][0] ^= 1; // actual next-HopID differs despite retained metadata.
            } else {
                for _ in 0..9 {
                    channel
                        .read(
                            Route::new(0).unwrap(),
                            Address {
                                port: 1,
                                space: Space::Port,
                                offset: 4,
                                words: 1,
                            },
                            cursor.now,
                            cursor.now + 1000,
                        )
                        .unwrap();
                    let reply = adapter_response(&domain, &model, cursor.tx % 10, 4, &[0]);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(
                        channel.poll(cursor.now),
                        Ok(Some(super::super::channel::Event::Completed { .. }))
                    ));
                }
            }
            // SAFETY: exact protected native owner pair; real wire state/progress is deliberately adverse.
            let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
            if case == 4 {
                let writes = model.state.lock().unwrap().writes.len();
                for delta in [0, 1, 150, 499] {
                    assert!(engine.poll(cursor.now + delta).unwrap().is_none());
                }
                assert!(matches!(engine.poll(cursor.now + 500), Err(Error::Timeout)));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            } else {
                engine.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..200 {
                    match stop_step(&mut peer, &domain, &model, &mut engine, &mut cursor) {
                        Err(Error::Changed) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("foreign owned hop was disabled"),
                    }
                }
                assert!(failed);
                assert_eq!(peer.writes.len(), 2 + case);
            }
            let mut channel = engine.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}
