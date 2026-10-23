// SPDX-License-Identifier: GPL-2.0-only
//! Independent source-only Raven/Vangogh MMIO/PTE/domain/PCM fixture.
//! Copyright (C) 2016, 2021, 2023 Advanced Micro Devices, Inc.
extern crate std;
use super::*;
use crate::bus::dma::{
    mapping::{DmaError, DomainMapping},
    memory::{MemoryError, PageBacking, PageGeometry, PinnedPages},
    pages::DmaPages,
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    cell::UnsafeCell,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicU64, AtomicUsize},
};
use std::sync::Mutex;
#[repr(align(4096))]
pub(super) struct Ram([u8; 65536]);
pub(super) struct Backing {
    pub(super) ram: Box<UnsafeCell<Ram>>,
    pub(super) physical: Vec<u64>,
    pub(super) drops: Arc<AtomicUsize>,
}
// SAFETY: isolated model owns its stable RAM; accesses are volatile and serialized.
unsafe impl Send for Backing {}
// SAFETY: no safe references into device-mutated RAM escape.
unsafe impl Sync for Backing {}
// SAFETY: actual retained aligned CPU allocation, scattered symbolic physical
// pages used solely by the independent domain, never as CPU pointers.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        // SAFETY: stable nonempty Box and UnsafeCell permit raw device accesses.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.ram.get()).0).cast()) }
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
pub(super) struct Source {
    next_allocation: AtomicU64,
    pub(super) drops: Arc<AtomicUsize>,
}
impl PageSource for Source {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert!(bytes <= 65536);
        assert_eq!(alignment, 4096);
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let allocation = self.next_allocation.fetch_add(1, Ordering::Relaxed);
        PinnedPages::new(
            Box::new(Backing {
                ram: Box::new(UnsafeCell::new(Ram([0xa5; 65536]))),
                physical: (0..bytes / 4096)
                    .map(|index| 0x9000_0000 + allocation * 0x100000 + index as u64 * 0x5000)
                    .collect(),
                drops: self.drops.clone(),
            }),
            bytes,
            alignment,
        )
    }
}
pub(super) struct Translation {
    pub(super) token: DomainMapping,
    pub(super) cpu: CpuMapping,
    pub(super) pages: DmaPages,
    pub(super) direction: DmaDirection,
    pub(super) device: bool,
}
// Deliberately independent literals: PS/Renoir offsets cannot be selected by
// the implementation and accidentally accepted by a shared profile model.
pub(super) fn layout(revision: u8, slot: usize) -> (usize, usize, usize, u32) {
    match (revision, slot) {
        (_, 0) => (0x2024, 0x240c, 0x2400, 1 << 28),
        (_, 1) => (0x2000, 0x2404, 0x2400, 1 << 27),
        (0, 2) => (0x206c, 0x280c, 0x2800, 1 << 26),
        (0, 3) => (0x2048, 0x2804, 0x2800, 1 << 25),
        (0x50, 2) => (0x20b4, 0x2820, 0x2814, 1 << 24),
        (0x50, 3) => (0x2090, 0x2818, 0x2814, 1 << 23),
        _ => panic!("unsupported independent model"),
    }
}
pub(super) struct Device {
    pub(super) identity: Identity,
    pub(super) words: Vec<u32>,
    pub(super) count: [u64; 4],
    pub(super) cursor: [usize; 4],
    pub(super) frames: [u64; 4],
    pub(super) output: [Vec<u8>; 4],
    pub(super) master: bool,
    pub(super) mappings: Vec<Translation>,
    pub(super) next: u64,
    pub(super) maps: usize,
    pub(super) unmaps: usize,
    pub(super) drains: usize,
    pub(super) coherent: usize,
    pub(super) writes: Vec<(usize, u32)>,
    pub(super) clock: Arc<AtomicU64>,
    pub(super) lost_read: Option<usize>,
    pub(super) ignore: Option<usize>,
    pub(super) reset_never: bool,
    pub(super) power_never: bool,
    pub(super) drain_fail: bool,
    pub(super) coherent_fail: bool,
    pub(super) unmap_fail: bool,
    pub(super) jump_write: Option<(usize, u32, u64)>,
    pub(super) posted: Vec<(u64, usize, u8)>,
    pub(super) defer_payload: bool,
    pub(super) race_copy: Option<(usize, usize, usize)>,
}
impl Device {
    pub(super) fn new(revision: u8) -> Self {
        let mut words = vec![0; 0x10400 / 4];
        if revision == 0 {
            words[0x1400 / 4] = 4;
            words[0x1420 / 4] = 2;
            words[0x1418 / 4] = 0x40;
        } else {
            words[0x1428 / 4] = 2;
        }
        Self {
            identity: Identity {
                vendor: 0x1022,
                device: 0x15e2,
                revision,
            },
            words,
            count: [0; 4],
            cursor: [0; 4],
            frames: [0; 4],
            output: core::array::from_fn(|_| Vec::new()),
            master: false,
            mappings: Vec::new(),
            next: 0,
            maps: 0,
            unmaps: 0,
            drains: 0,
            coherent: 0,
            writes: Vec::new(),
            clock: Arc::new(AtomicU64::new(0)),
            lost_read: None,
            ignore: None,
            reset_never: false,
            power_never: false,
            drain_fail: false,
            coherent_fail: false,
            unmap_fail: false,
            jump_write: None,
            posted: Vec::new(),
            defer_payload: false,
            race_copy: None,
        }
    }
    pub(super) fn quiet(&self) -> bool {
        (0..4).all(|slot| self.words[layout(self.identity.revision, slot).1 / 4] & 1 == 0)
    }
    pub(super) fn read(&mut self, offset: usize) -> u32 {
        assert!(!matches!(
            offset,
            0x1024 | 0x1028 | 0x102c | 0x1a00 | 0x1a04 | 0x1a0c
        ));
        if self.lost_read == Some(offset) {
            self.lost_read = None;
            return u32::MAX;
        }
        for slot in 0..4 {
            let ring = layout(self.identity.revision, slot).0;
            if offset == ring + 24 {
                return (self.count[slot] >> 32) as u32;
            }
            if offset == ring + 28 {
                return self.count[slot] as u32;
            }
        }
        self.words[offset / 4]
    }
    pub(super) fn write(&mut self, offset: usize, value: u32) {
        assert!(!matches!(
            offset,
            0x1024 | 0x1028 | 0x102c | 0x1a00 | 0x1a04 | 0x1a0c
        ));
        self.writes.push((offset, value));
        if self.ignore == Some(offset) {
            return;
        }
        let revision = self.identity.revision;
        let power = if revision == 0 { 0x141c } else { 0x1424 };
        if offset == power {
            assert_eq!(value, 1);
            if !self.power_never {
                self.words[(power + 4) / 4] = 0;
                if revision == 0 {
                    self.words[0x1418 / 4] = 0;
                }
            }
        } else if offset == 0x1000 {
            self.words[offset / 4] = if self.reset_never || value == 1 {
                0x10001
            } else {
                0
            };
            if value == 0 && !self.reset_never {
                for slot in 0..4 {
                    let (_, enable, ier, _) = layout(revision, slot);
                    self.words[enable / 4] = 0;
                    self.words[ier / 4] = 0;
                }
                self.count = [0; 4];
                self.cursor = [0; 4];
                self.words[0xc40 / 4] = 0;
            }
        } else if offset == 0xc40 {
            // The source names bit0 ACP_ATU_CACHE_INVALID; model the command
            // self-clearing. No false persistent enable latch is supplied.
            assert_eq!(value, 1);
            self.words[offset / 4] = 0;
        } else if offset == 0x1808 {
            self.words[offset / 4] &= !value;
        } else {
            for slot in 0..4 {
                let (_, enable, _, _) = layout(revision, slot);
                if offset == enable && value & 1 != 0 {
                    assert!(self.master);
                    assert_eq!(self.words[0xc04 / 4], 0x8205_0000);
                }
            }
            self.words[offset / 4] = value;
        }
        if let Some((at, requested, elapsed)) = self.jump_write
            && at == offset
            && requested == value
        {
            self.jump_write = None;
            self.clock.fetch_add(elapsed, Ordering::Relaxed);
        }
    }
    pub(super) fn advance(&mut self, slot: usize, frames: usize, sample_bytes: usize) {
        let (ring, enable, ier, irq) = layout(self.identity.revision, slot);
        if self.words[enable / 4] & 1 == 0 {
            return;
        }
        assert_eq!(self.words[ier / 4], 1);
        assert!(self.master);
        assert_eq!(self.words[0xc00 / 4], 2);
        assert_eq!(self.words[0xc04 / 4], 0x8205_0000);
        assert_eq!(self.words[0xc04 / 4], 0x8205_0000);
        assert_eq!(self.words[ring / 4], 0x0400_0000 + slot as u32 * 0x20000);
        assert_eq!(
            self.words[(ring + 12) / 4],
            0x0205_0500 + slot as u32 * 0x200
        );
        assert_eq!(self.words[(ring + 16) / 4], 0x100);
        assert_eq!(self.words[(ring + 20) / 4], 0x40);
        let bytes = self.words[(ring + 4) / 4] as usize;
        let period = self.words[(ring + 32) / 4] as usize;
        for _ in 0..frames {
            for channel in 0..2 {
                let sample = sample(self.frames[slot], channel).to_le_bytes();
                for byte in sample.iter().take(sample_bytes) {
                    let cursor = self.cursor[slot];
                    let pte = 0x10000 + slot * 0x100 + cursor / 4096 * 8;
                    let high = self.words[(pte + 4) / 4];
                    assert_ne!(high & 0x8000_0000, 0);
                    let address =
                        u64::from(self.words[pte / 4]) | (u64::from(high & 0x7fff_ffff) << 32);
                    let translation = self
                        .mappings
                        .iter()
                        .find(|mapping| {
                            address >= mapping.token.address
                                && address < mapping.token.address + mapping.token.bytes as u64
                        })
                        .unwrap();
                    assert!(translation.device);
                    let offset = (address - translation.token.address) as usize + cursor % 4096;
                    assert_eq!(
                        translation.pages.physical_pages()[offset / 4096],
                        translation.pages.physical_pages()[0] + (offset / 4096) as u64 * 0x5000
                    );
                    let pointer = translation.cpu.address(offset, 1).unwrap();
                    if slot.is_multiple_of(2) {
                        assert_eq!(translation.direction, DmaDirection::ToDevice);
                        // SAFETY: device only reads retained model RAM through actual programmed PTE/domain.
                        self.output[slot].push(unsafe { pointer.as_ptr().read_volatile() });
                    } else {
                        assert_eq!(translation.direction, DmaDirection::FromDevice);
                        if self.defer_payload {
                            self.posted.push((translation.token.id, offset, *byte));
                        } else {
                            // SAFETY: serialized independent device producer, retained actual CPU allocation.
                            unsafe { pointer.as_ptr().write_volatile(*byte) };
                        }
                    }
                    self.cursor[slot] = (cursor + 1) % bytes;
                    self.count[slot] += 1;
                    if self.cursor[slot].is_multiple_of(period) && !self.defer_payload {
                        self.words[0x1808 / 4] |= irq;
                    }
                }
            }
            self.frames[slot] += 1;
        }
    }
}
pub(super) fn sample(frame: u64, channel: usize) -> i32 {
    (frame.wrapping_mul(97) as i32)
        ^ if channel == 0 {
            0x1234_5600
        } else {
            -0x2345_6700
        }
}
pub(super) struct Model(Arc<Mutex<Device>>);
impl Registers for Model {
    fn region_bytes(&self) -> usize {
        0x10400
    }
    fn identity(&mut self) -> Result<Identity, Error> {
        Ok(self.0.lock().unwrap().identity)
    }
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.0.lock().unwrap().master = enabled;
        Ok(())
    }
    fn read32(&mut self, offset: usize) -> u32 {
        self.0.lock().unwrap().read(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.0.lock().unwrap().write(offset, value);
    }
}
pub(super) struct Domain(Arc<Mutex<Device>>);
// SAFETY: synchronous isolated domain, real owned CPU pages and symbolic
// nonidentity IOVAs; no physical DMA or native MMIO model grant is claimed.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: DmaDirection,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let mut device = self.0.lock().unwrap();
        device.next += 1;
        let token = DomainMapping {
            id: device.next,
            address: 0x1_8000_0000 + device.next * 0x20000,
            bytes: pages.bytes(),
        };
        if token.address + token.bytes as u64 - 1 > limit {
            return Err(DmaError::AddressLimit);
        }
        for existing in &device.mappings {
            assert!(
                !pages
                    .physical_pages()
                    .iter()
                    .any(|page| existing.pages.physical_pages().contains(page)),
                "independent allocations aliased physical pages"
            );
        }
        device.maps += 1;
        device.mappings.push(Translation {
            token,
            cpu: pages
                .as_single()
                .unwrap()
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap(),
            pages: pages.clone(),
            direction,
            device: false,
        });
        Ok(token)
    }
    unsafe fn unmap(&self, token: DomainMapping) -> Result<(), DmaError> {
        let mut device = self.0.lock().unwrap();
        assert!(device.quiet());
        assert!(!device.master);
        assert_eq!(device.words[0xc04 / 4] & 0x8000_0000, 0);
        assert!(device.posted.is_empty());
        if device.unmap_fail {
            return Err(DmaError::InvalidationFailed);
        }
        let index = device
            .mappings
            .iter()
            .position(|mapping| mapping.token == token)
            .unwrap();
        device.mappings.remove(index);
        device.unmaps += 1;
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        direction: DmaDirection,
    ) -> Result<(), DmaError> {
        let mut device = self.0.lock().unwrap();
        let mapping = device
            .mappings
            .iter_mut()
            .find(|mapping| mapping.token == token)
            .unwrap();
        assert_eq!(mapping.direction, direction);
        assert!(range.end <= token.bytes);
        mapping.device = true;
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        direction: DmaDirection,
    ) -> Result<(), DmaError> {
        let mut device = self.0.lock().unwrap();
        assert!(device.quiet());
        assert!(device.posted.is_empty());
        let mapping = device
            .mappings
            .iter_mut()
            .find(|mapping| mapping.token == token)
            .unwrap();
        assert_eq!(mapping.direction, direction);
        assert!(range.end <= token.bytes);
        mapping.device = false;
        Ok(())
    }
    unsafe fn read_coherent_u32(
        &self,
        token: DomainMapping,
        offset: usize,
        direction: DmaDirection,
    ) -> Result<u32, DmaError> {
        let mut device = self.0.lock().unwrap();
        if device.coherent_fail {
            return Err(DmaError::CoherenceUnavailable);
        }
        let mapping = device
            .mappings
            .iter()
            .find(|mapping| mapping.token == token)
            .unwrap();
        assert_eq!(direction, DmaDirection::FromDevice);
        assert_eq!(mapping.direction, direction);
        assert!(mapping.device);
        assert!(offset.is_multiple_of(4));
        assert!(offset + 4 <= token.bytes);
        let pointer = mapping.cpu.address(offset, 4).unwrap();
        // SAFETY: actual retained coherent RAM; one serialized model word read.
        let value = unsafe { pointer.as_ptr().cast::<u32>().read_volatile() };
        device.coherent += 1;
        if let Some((at, slot, frames)) = device.race_copy
            && device.coherent == at
        {
            device.race_copy = None;
            device.advance(slot, frames, 4);
        }
        Ok(u32::from_le(value))
    }
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let mut device = self.0.lock().unwrap();
        assert!(device.quiet());
        if device.drain_fail {
            return Err(DmaError::InvalidationFailed);
        }
        let pending = core::mem::take(&mut device.posted);
        for (id, offset, byte) in pending {
            let mapping = device
                .mappings
                .iter()
                .find(|mapping| mapping.token.id == id)
                .unwrap();
            let pointer = mapping.cpu.address(offset, 1).unwrap();
            // SAFETY: actual independent fabric completes queued bytes into retained RAM.
            unsafe { pointer.as_ptr().write_volatile(byte) };
        }
        device.drains += 1;
        Ok(())
    }
}
pub(super) struct Time(Arc<AtomicU64>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn relax(&self) {
        self.0.fetch_add(10, Ordering::Relaxed);
    }
}
pub(super) fn fixture(revision: u8) -> (Controller<Model, Time>, Arc<Mutex<Device>>, Source) {
    let device = Arc::new(Mutex::new(Device::new(revision)));
    let clock = device.lock().unwrap().clock.clone();
    // SAFETY: independent fixture's exact requester/domain, clock/board
    // model and controller are isolated and exclusively retained.
    let controller = unsafe {
        Controller::claim(
            Model(device.clone()),
            Time(clock),
            Arc::new(Domain(device.clone())),
            Config {
                acp_config: Some(8),
                dma_address_bits: 40,
                clock: Clock::External,
            },
        )
    }
    .unwrap();
    (
        controller,
        device,
        Source {
            next_allocation: AtomicU64::new(1),
            drops: Arc::new(AtomicUsize::new(0)),
        },
    )
}
pub(super) fn stereo() -> Format {
    Format {
        rate: 48_000,
        channels: 2,
        sample: Sample::Signed32,
        signal: Signal::I2s,
    }
}
