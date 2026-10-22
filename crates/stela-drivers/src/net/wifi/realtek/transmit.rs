// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C native TX ring bases and firmware-packet DMA transport.
//! Hardware consumer progress releases DMA only, never a command or air ACK.
use super::{
    beacon::{self, Allocation},
    fifo::Geometry,
    identity::{Chip, Profile},
};
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain},
        memory::PageSource,
    },
    mmio::Mmio,
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ptr::NonNull,
    sync::atomic::{Ordering, fence},
};

const H2C_COUNT: usize = 128;
const DESCRIPTOR: usize = 16;
const PACKET: usize = 48 + 32;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Resource(beacon::Error),
    Register,
    Removed,
    UnsupportedChip,
    IdentityChanged,
    FirmwareNotReady,
    InitialIndices,
    Index,
    CompletionBeyondPending,
    Full,
    Quarantined,
}
impl From<beacon::Error> for Error {
    fn from(e: beacon::Error) -> Self {
        Self::Resource(e)
    }
}

/// Source queues with ordinary host producer/device consumer indices. Beacon
/// is a separate reserved-page queue with its own BCN_VALID ownership proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Queue {
    Background,
    BestEffort,
    Video,
    Voice,
    Management,
    High,
    H2c,
}
const QUEUES: [Queue; 7] = [
    Queue::Background,
    Queue::BestEffort,
    Queue::Video,
    Queue::Voice,
    Queue::Management,
    Queue::High,
    Queue::H2c,
];
impl Queue {
    pub fn count(self) -> u16 {
        if self == Self::BestEffort { 256 } else { 128 }
    }
    fn registers(self) -> (usize, usize, usize) {
        match self {
            Self::Background => (0x330, 0x38a, 0x3ac),
            Self::BestEffort => (0x328, 0x388, 0x3a8),
            Self::Video => (0x320, 0x386, 0x3a4),
            Self::Voice => (0x318, 0x384, 0x3a0),
            Self::Management => (0x310, 0x380, 0x3b0),
            Self::High => (0x340, 0x38c, 0x3b8),
            Self::H2c => (0x1320, 0x1328, 0x132c),
        }
    }
}
/// # Safety
/// Exclusive actual selected RTL8822C register owner and retained UC BAR2.
/// Fresh volatile indices and actual ordered register stores, no synthesized
/// completion. Hardware remains awake; no competing reset/PS/submission worker.
pub unsafe trait Registers {
    fn profile(&self) -> Profile;
    fn verify_identity(&mut self) -> Result<(), Error>;
    fn firmware_ready(&mut self) -> Result<(), Error>;
    fn indices(&mut self, queue: Queue) -> Result<(u16, u16), Error>;
    fn configure(&mut self, queue: Queue, address: u32) -> Result<(), Error>;
    fn publish_h2c(&mut self, producer: u16) -> Result<(), Error>;
}
pub struct MmioRegisters {
    mmio: Mmio,
    profile: Profile,
    _owner: Arc<dyn core::any::Any>,
}
impl MmioRegisters {
    /// # Safety
    /// Exact profile's exclusive requester with UC BAR2 mapped at least 0x1330
    /// bytes, retained by the actual owner; domain binds this same requester.
    pub unsafe fn new(
        window: NonNull<u8>,
        bytes: usize,
        profile: Profile,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, Error> {
        if bytes < 0x1330 || window.as_ptr().addr() & 3 != 0 {
            return Err(Error::Register);
        }
        if profile.chip() != Chip::Rtl8822C {
            return Err(Error::UnsupportedChip);
        }
        Ok(Self {
            mmio: unsafe { Mmio::new(window.as_ptr() as u64) },
            profile,
            _owner: owner,
        })
    }
}
// SAFETY: unsafe constructor binds real retained requester/profile/UC BAR.
unsafe impl Registers for MmioRegisters {
    fn profile(&self) -> Profile {
        self.profile
    }
    fn verify_identity(&mut self) -> Result<(), Error> {
        let value = self.mmio.read32(0xf0);
        if value == u32::MAX {
            return Err(Error::Removed);
        }
        if value != self.profile.observed().sys_cfg1 {
            return Err(Error::IdentityChanged);
        }
        Ok(())
    }
    fn firmware_ready(&mut self) -> Result<(), Error> {
        let value = self.mmio.read16(0x80);
        if value == u16::MAX {
            return Err(Error::Removed);
        }
        if value & 0xcfff != 0xc078 {
            return Err(Error::FirmwareNotReady);
        }
        Ok(())
    }
    fn indices(&mut self, q: Queue) -> Result<(u16, u16), Error> {
        let value = self.mmio.read32(q.registers().2);
        if value == u32::MAX {
            return Err(Error::Removed);
        }
        Ok(((value & 0xfff) as u16, ((value >> 16) & 0xfff) as u16))
    }
    fn configure(&mut self, q: Queue, address: u32) -> Result<(), Error> {
        let (base, count, _) = q.registers();
        self.mmio.write16(count, q.count());
        self.mmio.write32(base, address);
        if self.mmio.read16(count) & 0xfff != q.count() || self.mmio.read32(base) != address {
            return Err(Error::Register);
        }
        Ok(())
    }
    fn publish_h2c(&mut self, producer: u16) -> Result<(), Error> {
        self.mmio.write16(0x132c, producer);
        Ok(())
    }
}

/// All seven indexed TX queues have real native descriptor backing, so engine
/// prefetch never addresses a placeholder ring. Only typed general-info H2C
/// publication is admitted here; radio DATA/keys/air reports remain separate.
pub struct Rings<R: Registers> {
    io: Option<R>,
    domain: Arc<dyn DmaDomain>,
    rings: Vec<Allocation>,
    pending: Vec<Option<Allocation>>,
    read: u16,
    write: u16,
    sequence: u16,
    configured: bool,
    used: bool,
    poisoned: bool,
}
impl<R: Registers> Rings<R> {
    /// # Safety
    /// Actual exact RTL8822C requester independently stopped/drained, every
    /// indexed TX producer/consumer reset to 0, firmware H2C sequence reset 0.
    /// Real coherent WB RAM, NoSnoop/ATS disabled, exclusive UC BAR/requester
    /// and domain. Full RX/beacon rings and HCI reset/start remain separate.
    /// No reset, deep-PS, key/radio retirement or competing worker during use.
    pub unsafe fn install(
        mut io: R,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if io.profile().chip() != Chip::Rtl8822C {
            return Err(Error::UnsupportedChip);
        }
        io.verify_identity()?;
        for q in QUEUES {
            if io.indices(q)? != (0, 0) {
                return Err(Error::InitialIndices);
            }
        }
        let mut rings = Vec::new();
        let mut pending = Vec::new();
        rings.try_reserve_exact(7).map_err(|_| {
            Error::Resource(beacon::Error::Memory(
                crate::bus::dma::memory::MemoryError::OutOfMemory,
            ))
        })?;
        pending.try_reserve_exact(H2C_COUNT).map_err(|_| {
            Error::Resource(beacon::Error::Memory(
                crate::bus::dma::memory::MemoryError::OutOfMemory,
            ))
        })?;
        for q in QUEUES {
            let a = Allocation::new(
                source,
                domain.clone(),
                usize::from(q.count()) * DESCRIPTOR,
                Direction::Bidirectional,
            )?;
            // Native mappings cover full pages. Clear/synchronize even the
            // unused page tail so hardware prefetch never sees heap content.
            a.write(0, &[0; 4096])?;
            a.dma
                .sync_for_device(0..a.dma.bytes())
                .map_err(beacon::Error::from)?;
            rings.push(a);
        }
        pending.resize_with(H2C_COUNT, || None);
        let mut s = Self {
            io: Some(io),
            domain,
            rings,
            pending,
            read: 0,
            write: 0,
            sequence: 0,
            configured: false,
            used: false,
            poisoned: true,
        };
        for (index, q) in QUEUES.into_iter().enumerate() {
            let address = s.rings[index].address()?;
            s.rings[index].published = true;
            s.configured = true;
            fence(Ordering::Release);
            s.io.as_mut()
                .ok_or(Error::Quarantined)?
                .configure(q, address)?;
        }
        s.poisoned = false;
        Ok(s)
    }
    pub fn quarantined(&self) -> bool {
        self.poisoned
    }
    pub fn pending(&self) -> usize {
        distance(self.read, self.write)
    }
    /// Queue source general-info packet; success is publication only. Geometry
    /// must belong to the actual exact profile. No firmware ACK is invented.
    pub fn general_info(
        &mut self,
        source: &dyn PageSource,
        geometry: Geometry,
    ) -> Result<(), Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        if geometry.profile() != self.io.as_ref().ok_or(Error::Quarantined)?.profile() {
            return Err(Error::IdentityChanged);
        }
        if self.pending() == H2C_COUNT - 1 {
            return Err(Error::Full);
        }
        self.used = true;
        let payload = general_info(geometry, self.sequence);
        // A reserved sequence is never rolled back after uncertain DMA/MMIO.
        self.sequence = self.sequence.wrapping_add(1);
        self.poisoned = true;
        let result = self.submit(source, &payload);
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    fn submit(&mut self, source: &dyn PageSource, payload: &[u8; 32]) -> Result<(), Error> {
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .verify_identity()?;
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .firmware_ready()?;
        let (host, device) = self
            .io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .indices(Queue::H2c)?;
        if host != self.write || device as usize >= H2C_COUNT {
            return Err(Error::Index);
        }
        if distance(self.read, device) > self.pending() {
            return Err(Error::CompletionBeyondPending);
        }
        let a = Allocation::new(source, self.domain.clone(), PACKET, Direction::ToDevice)?;
        let (packet, descriptor) = h2c_descriptors(a.address()?)?;
        a.write(0, &packet)?;
        a.write(48, payload)?;
        a.dma
            .sync_for_device(0..PACKET)
            .map_err(beacon::Error::from)?;
        let index = usize::from(self.write);
        let offset = index * DESCRIPTOR;
        if self.pending[index].is_some() {
            return Err(Error::CompletionBeyondPending);
        }
        // Once an IOVA enters an already configured coherent descriptor, the
        // real payload owner must survive even before consumer publication.
        self.pending[index] = Some(a);
        self.pending[index].as_mut().unwrap().published = true;
        self.rings[6].write(offset, &descriptor)?;
        self.rings[6]
            .dma
            .sync_for_device(offset..offset + DESCRIPTOR)
            .map_err(beacon::Error::from)?;
        self.write = ((index + 1) % H2C_COUNT) as u16;
        fence(Ordering::Release);
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .publish_h2c(self.write)
    }
    /// Fresh hardware consumer-index progress releases command DMA only.
    /// Neither emptiness nor release means command accepted/completed by MCU.
    pub fn reclaim_h2c(&mut self) -> Result<usize, Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        let result = self.reclaim();
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    fn reclaim(&mut self) -> Result<usize, Error> {
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .verify_identity()?;
        let (host, device) = self
            .io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .indices(Queue::H2c)?;
        if host != self.write || device as usize >= H2C_COUNT {
            return Err(Error::Index);
        }
        let count = distance(self.read, device);
        if count > self.pending() {
            return Err(Error::CompletionBeyondPending);
        }
        for _ in 0..count {
            let index = usize::from(self.read);
            let offset = index * DESCRIPTOR;
            // SAFETY: actual bounded hardware consumer advance consumed this
            // exact live descriptor/payload; independent full stop not needed
            // for this completed ToDevice buffer, but no air/FW ACK follows.
            unsafe { self.rings[6].dma.sync_for_cpu(offset..offset + DESCRIPTOR) }
                .map_err(beacon::Error::from)?;
            let a = self.pending[index]
                .as_mut()
                .ok_or(Error::CompletionBeyondPending)?;
            unsafe {
                a.release()?;
            }
            self.pending[index] = None;
            self.read = ((index + 1) % H2C_COUNT) as u16;
        }
        Ok(count)
    }
    /// # Safety
    /// Independently stopped/drained exact requester. Initial HCI only; any
    /// admitted command permanently refuses this path even after DMA reclaim,
    /// so command/key/station generations are never reset through it.
    pub(super) unsafe fn begin_hci_rebind(&mut self) -> Result<[u32; 7], Error> {
        if self.poisoned || self.used || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        let mut addresses = [0; 7];
        for (i, a) in self.rings.iter().enumerate() {
            unsafe { a.dma.sync_for_cpu(0..a.dma.bytes()) }.map_err(beacon::Error::from)?;
            for offset in (0..a.dma.bytes()).step_by(4096) {
                a.write(offset, &[0; 4096][..(a.dma.bytes() - offset).min(4096)])?;
            }
            a.dma
                .sync_for_device(0..a.dma.bytes())
                .map_err(beacon::Error::from)?;
            addresses[i] = a.address()?;
        }
        Ok(addresses)
    }
    pub(super) fn finish_hci_rebind(&mut self) {
        self.read = 0;
        self.write = 0;
        self.poisoned = false;
    }
    pub(super) fn initial_indices(&mut self) -> Result<(), Error> {
        for q in QUEUES {
            if self.io.as_mut().ok_or(Error::Quarantined)?.indices(q)? != (0, 0) {
                return Err(Error::InitialIndices);
            }
        }
        Ok(())
    }
    pub(super) fn profile(&self) -> Result<Profile, Error> {
        Ok(self.io.as_ref().ok_or(Error::Quarantined)?.profile())
    }
    /// # Safety
    /// Independent actual acknowledged requester stop/drain and all workers
    /// stopped through unmap. Index equality/reset writes are insufficient.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        self.poisoned = true;
        for a in &mut self.rings {
            unsafe {
                a.release()?;
            }
        }
        for a in self.pending.iter_mut().flatten() {
            unsafe {
                a.release()?;
            }
        }
        self.pending.clear();
        self.configured = false;
        Ok(())
    }
}
impl<R: Registers> Drop for Rings<R> {
    fn drop(&mut self) {
        if self.configured
            && let Some(io) = self.io.take()
        {
            core::mem::forget(io);
        }
    }
}
fn distance(read: u16, write: u16) -> usize {
    (usize::from(write) + H2C_COUNT - usize::from(read)) % H2C_COUNT
}
fn general_info(geometry: Geometry, sequence: u16) -> [u8; 32] {
    let mut p = [0; 32];
    p[..4].copy_from_slice(&0x000dff01u32.to_le_bytes());
    p[4..8].copy_from_slice(&(12u32 | (u32::from(sequence) << 16)).to_le_bytes());
    p[10] = (geometry.firmware_tx_page() - geometry.boundary()) as u8;
    p
}
fn h2c_descriptors(address: u32) -> Result<([u8; 48], [u8; 16]), Error> {
    address
        .checked_add((PACKET - 1) as u32)
        .ok_or(Error::Resource(beacon::Error::Address))?;
    let payload = address + 48;
    let mut p = [0; 48];
    p[..4].copy_from_slice(&32u32.to_le_bytes());
    p[4..8].copy_from_slice(&(19u32 << 8).to_le_bytes());
    let mut bd = [0; 16];
    bd[..2].copy_from_slice(&48u16.to_le_bytes());
    bd[2..4].copy_from_slice(&1u16.to_le_bytes());
    bd[4..8].copy_from_slice(&address.to_le_bytes());
    bd[8..10].copy_from_slice(&32u16.to_le_bytes());
    bd[12..16].copy_from_slice(&payload.to_le_bytes());
    Ok((p, bd))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{
        beacon::tests::{Domain, Model, Source},
        identity::Observed,
    };
    use super::*;
    use std::sync::Mutex;
    fn profile() -> Profile {
        Profile::select(Observed {
            vendor: 0x10ec,
            device: 0xc822,
            subsystem_vendor: 0x17aa,
            subsystem_device: 0x1234,
            pci_revision: 1,
            class: [2, 0x80, 0],
            sys_cfg1: 0,
        })
        .unwrap()
    }
    #[derive(Default)]
    struct Device {
        bases: [u32; 7],
        indices: [(u16, u16); 7],
        configure_count: usize,
        fail_configure: Option<usize>,
        fail_publish: bool,
        identity_changed: bool,
        not_ready: bool,
        drops: usize,
        packets: Vec<Vec<u8>>,
        descriptors: Vec<[u8; 16]>,
    }
    struct Io {
        device: Arc<Mutex<Device>>,
        memory: Arc<Mutex<Model>>,
    }
    fn index(q: Queue) -> usize {
        QUEUES.into_iter().position(|v| v == q).unwrap()
    }
    // SAFETY: serialized model's actual fresh indices and retained native
    // allocation IOVAs; no actual hardware or privileged DMA proof claimed.
    unsafe impl Registers for Io {
        fn profile(&self) -> Profile {
            profile()
        }
        fn verify_identity(&mut self) -> Result<(), Error> {
            if self.device.lock().unwrap().identity_changed {
                Err(Error::IdentityChanged)
            } else {
                Ok(())
            }
        }
        fn firmware_ready(&mut self) -> Result<(), Error> {
            if self.device.lock().unwrap().not_ready {
                Err(Error::FirmwareNotReady)
            } else {
                Ok(())
            }
        }
        fn indices(&mut self, q: Queue) -> Result<(u16, u16), Error> {
            Ok(self.device.lock().unwrap().indices[index(q)])
        }
        fn configure(&mut self, q: Queue, address: u32) -> Result<(), Error> {
            let mut d = self.device.lock().unwrap();
            d.bases[index(q)] = address;
            d.configure_count += 1;
            if d.fail_configure == Some(d.configure_count) {
                Err(Error::Register)
            } else {
                Ok(())
            }
        }
        fn publish_h2c(&mut self, producer: u16) -> Result<(), Error> {
            let mut d = self.device.lock().unwrap();
            let m = self.memory.lock().unwrap();
            let (_, base) = &m.mappings[&u64::from(d.bases[6])];
            let slot = usize::from(d.indices[6].0);
            let bytes =
                unsafe { core::slice::from_raw_parts((*base + slot * 16) as *const u8, 16) };
            let descriptor: [u8; 16] = bytes.try_into().unwrap();
            let address = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            assert_eq!(
                m.directions[&u64::from(d.bases[6])],
                Direction::Bidirectional
            );
            assert_eq!(m.directions[&u64::from(address)], Direction::ToDevice);
            let (_, packet) = &m.mappings[&u64::from(address)];
            d.packets
                .push(unsafe { core::slice::from_raw_parts(*packet as *const u8, 80) }.to_vec());
            d.descriptors.push(descriptor);
            d.indices[6].0 = producer;
            if d.fail_publish {
                Err(Error::Register)
            } else {
                Ok(())
            }
        }
    }
    impl Drop for Io {
        fn drop(&mut self) {
            self.device.lock().unwrap().drops += 1;
        }
    }
    fn install(
        memory: &Arc<Mutex<Model>>,
        device: &Arc<Mutex<Device>>,
    ) -> Result<Rings<Io>, Error> {
        unsafe {
            Rings::install(
                Io {
                    device: device.clone(),
                    memory: memory.clone(),
                },
                &Source,
                Arc::new(Domain(memory.clone())),
            )
        }
    }
    #[test]
    fn native_bases_and_real_dma_consumer_control_firmware_packet_lifetime() {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        let mut rings = install(&memory, &device).unwrap();
        let geometry = Geometry::for_profile(profile()).unwrap();
        assert_eq!(memory.lock().unwrap().mappings.len(), 7);
        for q in QUEUES {
            let m = memory.lock().unwrap();
            let d = device.lock().unwrap();
            let (pages, pointer) = &m.mappings[&u64::from(d.bases[index(q)])];
            assert_eq!(pages.bytes(), 4096);
            assert!(
                unsafe { core::slice::from_raw_parts(*pointer as *const u8, pages.bytes()) }
                    .iter()
                    .all(|b| *b == 0)
            );
        }
        for round in 0..3 {
            for _ in 0..127 {
                rings.general_info(&Source, geometry).unwrap();
            }
            assert_eq!(rings.general_info(&Source, geometry), Err(Error::Full));
            assert!(!rings.quarantined());
            assert_eq!(rings.pending(), 127);
            assert_eq!(rings.reclaim_h2c().unwrap(), 0);
            assert_eq!(memory.lock().unwrap().mappings.len(), 134);
            let producer = device.lock().unwrap().indices[6].0;
            device.lock().unwrap().indices[6].1 = producer;
            assert_eq!(rings.reclaim_h2c().unwrap(), 127);
            assert_eq!(rings.pending(), 0);
            assert_eq!(memory.lock().unwrap().mappings.len(), 7);
            assert_eq!(rings.read, ((round + 1) * 127 % 128) as u16);
        }
        let d = device.lock().unwrap();
        assert_eq!(d.packets.len(), 381);
        for (seq, packet) in d.packets.iter().enumerate() {
            assert_eq!(&packet[..4], &[32, 0, 0, 0]);
            assert_eq!(&packet[4..8], &[0, 19, 0, 0]);
            assert_eq!(&packet[8..48], &[0; 40]);
            assert_eq!(&packet[48..52], &[1, 255, 13, 0]);
            assert_eq!(
                &packet[52..56],
                &(12u32 | ((seq as u32) << 16)).to_le_bytes()
            );
            assert_eq!(packet[58], 56);
        }
        drop(d);
        rings.sequence = u16::MAX;
        rings.general_info(&Source, geometry).unwrap();
        rings.general_info(&Source, geometry).unwrap();
        assert_eq!(
            &device.lock().unwrap().packets[381][54..56],
            &u16::MAX.to_le_bytes()
        );
        assert_eq!(
            &device.lock().unwrap().packets[382][54..56],
            &0u16.to_le_bytes()
        );
        unsafe { rings.release_after_stop() }.unwrap();
        drop(rings);
        assert!(memory.lock().unwrap().mappings.is_empty());
        assert_eq!(device.lock().unwrap().drops, 1);
    }
    #[test]
    fn uncertain_initialization_and_completed_unmap_retain_pins_and_claim() {
        for operation in 1..=7 {
            let memory = Arc::new(Mutex::new(Model::default()));
            let device = Arc::new(Mutex::new(Device {
                fail_configure: Some(operation),
                ..Device::default()
            }));
            assert!(install(&memory, &device).is_err());
            assert_eq!(memory.lock().unwrap().mappings.len(), operation);
            assert_eq!(device.lock().unwrap().drops, 0);
        }
        for phase in 0..4 {
            let memory = Arc::new(Mutex::new(Model::default()));
            let device = Arc::new(Mutex::new(Device::default()));
            let mut rings = install(&memory, &device).unwrap();
            match phase {
                0 => memory.lock().unwrap().fail_sync_at = Some(9),
                1 => device.lock().unwrap().fail_publish = true,
                _ => (),
            }
            let sent = rings.general_info(&Source, Geometry::for_profile(profile()).unwrap());
            if phase < 2 {
                assert!(sent.is_err());
            } else {
                sent.unwrap();
                device.lock().unwrap().indices[6].1 = 1;
                if phase == 2 {
                    memory.lock().unwrap().fail_cpu_sync_at = Some(1);
                } else {
                    memory.lock().unwrap().fail_unmap = true;
                }
                assert!(rings.reclaim_h2c().is_err());
            }
            assert!(rings.quarantined());
            drop(rings);
            assert_eq!(device.lock().unwrap().drops, 0);
            assert_eq!(memory.lock().unwrap().mappings.len(), 8);
        }
    }
    #[test]
    fn invalid_indices_identity_readiness_and_unpublished_failures_cannot_publish() {
        for mode in 0..7 {
            let memory = Arc::new(Mutex::new(Model::default()));
            let device = Arc::new(Mutex::new(Device::default()));
            let mut rings = install(&memory, &device).unwrap();
            match mode {
                0 => device.lock().unwrap().indices[6].0 = 1,
                1 => device.lock().unwrap().indices[6].1 = 128,
                2 => device.lock().unwrap().indices[6].1 = 1,
                3 => device.lock().unwrap().identity_changed = true,
                4 => device.lock().unwrap().not_ready = true,
                5 => memory.lock().unwrap().fail_sync_at = Some(8),
                6 => memory.lock().unwrap().address_overflow = true,
                _ => (),
            }
            assert!(
                rings
                    .general_info(&Source, Geometry::for_profile(profile()).unwrap())
                    .is_err()
            );
            assert!(rings.quarantined());
            assert!(device.lock().unwrap().packets.is_empty());
            assert_eq!(memory.lock().unwrap().mappings.len(), 7);
            drop(rings);
            assert_eq!(device.lock().unwrap().drops, 0);
        }
        for mode in 0..3 {
            let memory = Arc::new(Mutex::new(Model::default()));
            let device = Arc::new(Mutex::new(Device::default()));
            match mode {
                0 => device.lock().unwrap().indices[2].1 = 1,
                1 => memory.lock().unwrap().address_overflow = true,
                2 => memory.lock().unwrap().fail_sync_at = Some(7),
                _ => (),
            }
            assert!(install(&memory, &device).is_err());
            assert_eq!(device.lock().unwrap().configure_count, 0);
            assert_eq!(device.lock().unwrap().drops, 1);
            assert!(memory.lock().unwrap().mappings.is_empty());
        }
    }
    #[test]
    fn impossible_completion_and_uncertain_stop_never_free_live_commands() {
        for mode in 0..3 {
            let memory = Arc::new(Mutex::new(Model::default()));
            let device = Arc::new(Mutex::new(Device::default()));
            let mut rings = install(&memory, &device).unwrap();
            rings
                .general_info(&Source, Geometry::for_profile(profile()).unwrap())
                .unwrap();
            if mode == 0 {
                device.lock().unwrap().indices[6].1 = 2;
                assert_eq!(rings.reclaim_h2c(), Err(Error::CompletionBeyondPending));
            }
            if mode == 1 {
                device.lock().unwrap().indices[6].0 = 9;
                assert_eq!(rings.reclaim_h2c(), Err(Error::Index));
            }
            if mode == 2 {
                memory.lock().unwrap().fail_unmap = true;
                assert!(unsafe { rings.release_after_stop() }.is_err());
            }
            assert!(rings.quarantined());
            drop(rings);
            assert_eq!(device.lock().unwrap().drops, 0);
            assert_eq!(memory.lock().unwrap().mappings.len(), 8);
        }
        assert!(h2c_descriptors(u32::MAX - 78).is_err());
        assert!(h2c_descriptors(u32::MAX - 79).is_ok());
    }
    #[test]
    #[ignore = "requires unchanged pinned C H2C firmware packet oracle"]
    fn every_sequence_full_packet_and_descriptors_match_unchanged_c() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRANSMIT_ORACLE").unwrap()).unwrap();
        let geometry = Geometry::for_profile(profile()).unwrap();
        let (packet, descriptor) = h2c_descriptors(0x12340000).unwrap();
        for sequence in 0..=u16::MAX {
            let offset = usize::from(sequence) * 96;
            assert_eq!(
                &trace[offset..offset + 48],
                packet,
                "sequence {sequence}: TXD"
            );
            assert_eq!(
                &trace[offset + 48..offset + 80],
                general_info(geometry, sequence),
                "sequence {sequence}: command"
            );
            assert_eq!(
                &trace[offset + 80..offset + 96],
                descriptor,
                "sequence {sequence}: TXBD"
            );
        }
        assert_eq!(trace.len(), 65536 * 96);
    }
}
