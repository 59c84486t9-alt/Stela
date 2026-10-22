// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C native PCIe RX buffer ring and borrowed raw descriptor facts.
//! Hardware producer/tag/visibility establishes DMA ownership only. Raw
//! decryption flags are not integrity, key, replay, MLME or radio-ready proof.
use super::{
    beacon::{self, Allocation},
    io::Bar,
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain},
    memory::PageSource,
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{Ordering, fence};

const COUNT: usize = 512;
const BUFFER: usize = 11454 + 24;
const DESCRIPTOR: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Resource(beacon::Error),
    Register,
    Removed,
    Index(u16),
    InitialIndices,
    Tag { expected: u16, observed: u16 },
    Quarantined,
    Packet(ParseError),
}
impl From<beacon::Error> for Error {
    fn from(e: beacon::Error) -> Self {
        Self::Resource(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Truncated,
    Rate(u8),
    DriverInfo(u8),
    MissingPhy,
    Length,
    Bounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Facts {
    pub crc_error: bool,
    pub icv_error: bool,
    pub encryption_raw: u8,
    /// Raw !SWDEC && ENC_TYPE != 0; never verified integrity or an installed key.
    pub hardware_decrypted: bool,
    pub phy_present: bool,
    pub firmware: bool,
    pub cam_id: u8,
    pub ppdu_count: u8,
    pub rate_raw: u8,
    pub bandwidth_raw: u8,
    pub tsf_low: u32,
}
#[derive(Debug)]
pub struct Packet<'a> {
    pub descriptor: &'a [u8; 24],
    pub shift: &'a [u8],
    pub driver_info: &'a [u8],
    /// Source packet bytes, including any FCS actually selected by MAC/RCR.
    /// This is not a validated/decrypted shared Wi-Fi MPDU.
    pub payload: &'a [u8],
    pub facts: Facts,
}
pub fn parse(buffer: &[u8]) -> Result<Packet<'_>, ParseError> {
    let descriptor: &[u8; 24] = buffer
        .get(..24)
        .ok_or(ParseError::Truncated)?
        .try_into()
        .unwrap();
    let word = |i: usize| u32::from_le_bytes(descriptor[i * 4..i * 4 + 4].try_into().unwrap());
    let w0 = word(0);
    let length = (w0 & 0x3fff) as usize;
    let driver_units = ((w0 >> 16) & 15) as u8;
    let shift = ((w0 >> 24) & 3) as usize;
    let enc = ((w0 >> 20) & 7) as u8;
    let phy = w0 & (1 << 26) != 0;
    let firmware = word(2) & (1 << 28) != 0;
    let rate = (word(3) & 0x7f) as u8;
    if rate >= 0x54 {
        return Err(ParseError::Rate(rate));
    }
    if driver_units != 0 && driver_units != 4 {
        return Err(ParseError::DriverInfo(driver_units));
    }
    if phy && driver_units == 0 {
        return Err(ParseError::MissingPhy);
    }
    if length > 11454 || (!firmware && length <= 4) {
        return Err(ParseError::Length);
    }
    let phy_start = 24 + shift;
    let payload_start = phy_start + usize::from(driver_units) * 8;
    let end = payload_start + length;
    if end > BUFFER || end > buffer.len() {
        return Err(ParseError::Bounds);
    }
    Ok(Packet {
        descriptor,
        shift: &buffer[24..phy_start],
        driver_info: &buffer[phy_start..payload_start],
        payload: &buffer[payload_start..end],
        facts: Facts {
            crc_error: w0 & (1 << 14) != 0,
            icv_error: w0 & (1 << 15) != 0,
            encryption_raw: enc,
            hardware_decrypted: w0 & (1 << 27) == 0 && enc != 0,
            phy_present: phy,
            firmware,
            cam_id: (word(1) & 0x7f) as u8,
            ppdu_count: ((word(2) >> 29) & 3) as u8,
            rate_raw: rate,
            bandwidth_raw: ((word(4) >> 4) & 3) as u8,
            tsf_low: word(5),
        },
    })
}

fn buffer_descriptor(address: u32) -> [u8; DESCRIPTOR] {
    let mut bytes = [0; DESCRIPTOR];
    bytes[..2].copy_from_slice(&(BUFFER as u16).to_le_bytes());
    bytes[4..].copy_from_slice(&address.to_le_bytes());
    bytes
}
fn available(consumer: u16, producer: u16) -> usize {
    (usize::from(producer) + COUNT - usize::from(consumer)) % COUNT
}

/// # Safety
/// Actual exclusive RTL8822C requester RX register block, retained claim/UC
/// BAR mapping for this object's full lifetime. Indices are fresh volatile
/// reads, writes ordered actual MMIO; no cached/manufactured completion.
/// Configuration requires acknowledged stopped/drained DMA and zero indices.
pub unsafe trait Registers {
    fn configure(&mut self, iova: u32, count: u16) -> Result<(), Error>;
    fn indices(&mut self) -> Result<(u16, u16), Error>;
    fn publish(&mut self, consumer: u16) -> Result<(), Error>;
}
// SAFETY: `Bar::new` binds the exclusive requester BAR.
unsafe impl Registers for Bar {
    fn configure(&mut self, iova: u32, count: u16) -> Result<(), Error> {
        self.write16(0x382, count);
        self.write32(0x338, iova);
        if self.read16(0x382) & 0xfff != count || self.read32(0x338) != iova {
            return Err(Error::Register);
        }
        Ok(())
    }
    fn indices(&mut self) -> Result<(u16, u16), Error> {
        let value = self.read32(0x3b4);
        if value == u32::MAX {
            return Err(Error::Removed);
        }
        Ok(((value & 0xfff) as u16, ((value >> 16) & 0xfff) as u16))
    }
    fn publish(&mut self, consumer: u16) -> Result<(), Error> {
        self.write16(0x3b4, consumer);
        Ok(())
    }
}

/// One source-sized native RX ring. Buffers/descriptor mappings and actual
/// register owner survive uncertain Drop. Call poll only in deferred context,
/// never from an IRQ handler or concurrently with reset/key/channel retirement.
pub struct Ring<R: Registers> {
    io: Option<R>,
    descriptor: Allocation,
    buffers: Vec<Allocation>,
    read: u16,
    tag: u16,
    configured: bool,
    used: bool,
    poisoned: bool,
}
impl<R: Registers> Ring<R> {
    /// # Safety
    /// Real selected RTL8822C is independently stopped/drained with actual
    /// zero producer/consumer indices and RX tag reset to zero. `io` owns that
    /// requester/UC BAR and `domain` isolates it. All allocations are real
    /// coherent WB DMA RAM with NoSnoop/ATS disabled (WB alone is insufficient).
    /// Full source HCI configuration before enabling engines remains required;
    /// this only installs the native RX ring. No competing worker may touch it.
    pub unsafe fn install(
        mut io: R,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if io.indices()? != (0, 0) {
            return Err(Error::InitialIndices);
        }
        let descriptor = Allocation::new(
            source,
            domain.clone(),
            COUNT * DESCRIPTOR,
            Direction::Bidirectional,
        )?;
        let mut buffers = Vec::new();
        buffers.try_reserve_exact(COUNT).map_err(|_| {
            Error::Resource(beacon::Error::Memory(
                crate::bus::dma::memory::MemoryError::OutOfMemory,
            ))
        })?;
        for _ in 0..COUNT {
            buffers.push(Allocation::new(
                source,
                domain.clone(),
                BUFFER,
                Direction::FromDevice,
            )?);
        }
        let mut ring = Self {
            io: Some(io),
            descriptor,
            buffers,
            read: 0,
            tag: 0,
            configured: false,
            used: false,
            poisoned: true,
        };
        for i in 0..COUNT {
            ring.reset_descriptor(i)?;
        }
        ring.descriptor
            .dma
            .sync_for_device(0..COUNT * DESCRIPTOR)
            .map_err(beacon::Error::from)?;
        fence(Ordering::Release);
        // A configuration store may expose every descriptor and payload,
        // even when its readback/return fails. Set retention beforehand.
        ring.descriptor.published = true;
        for buffer in &mut ring.buffers {
            buffer.published = true;
        }
        ring.configured = true;
        let address = ring.descriptor.address()?;
        ring.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .configure(address, COUNT as u16)?;
        ring.poisoned = false;
        Ok(ring)
    }
    pub fn quarantined(&self) -> bool {
        self.poisoned
    }
    pub fn consumer(&self) -> u16 {
        self.read
    }
    pub fn expected_tag(&self) -> u16 {
        self.tag
    }
    fn reset_descriptor(&mut self, index: usize) -> Result<(), Error> {
        self.buffers[index]
            .dma
            .sync_for_device(0..BUFFER)
            .map_err(beacon::Error::from)?;
        let bytes = buffer_descriptor(self.buffers[index].address()?);
        self.descriptor.write(index * DESCRIPTOR, &bytes)?;
        Ok(())
    }
    /// Deliver borrowed raw facts only while CPU owns the completed buffer.
    /// Callback cannot retain its borrow through rearm. A producer-index DMA
    /// event is not an actual radio integrity/key/replay/MLME acknowledgement.
    pub fn poll(
        &mut self,
        budget: usize,
        mut receive: impl FnMut(Packet<'_>),
    ) -> Result<usize, Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        self.used = true;
        self.poisoned = true;
        let result = self.poll_inner(budget.min(COUNT - 1), &mut receive);
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    fn poll_inner(
        &mut self,
        budget: usize,
        receive: &mut impl FnMut(Packet<'_>),
    ) -> Result<usize, Error> {
        let (consumer, producer) = self.io.as_mut().ok_or(Error::Quarantined)?.indices()?;
        if consumer != self.read {
            return Err(Error::Index(consumer));
        }
        if producer as usize >= COUNT {
            return Err(Error::Index(producer));
        }
        let count = available(self.read, producer);
        let count = count.min(budget);
        for _ in 0..count {
            let index = usize::from(self.read);
            let offset = index * DESCRIPTOR;
            // SAFETY: fresh actual producer advance transfers this descriptor
            // and corresponding buffer to CPU; no reuse until publish below.
            unsafe {
                self.descriptor
                    .dma
                    .sync_for_cpu(offset..offset + DESCRIPTOR)
            }
            .map_err(beacon::Error::from)?;
            let pointer = self
                .descriptor
                .cpu
                .address(offset + 2, 2)
                .map_err(beacon::Error::from)?;
            let observed = u16::from_le(unsafe { pointer.as_ptr().cast::<u16>().read_volatile() });
            if observed != self.tag {
                return Err(Error::Tag {
                    expected: self.tag,
                    observed,
                });
            }
            unsafe { self.buffers[index].dma.sync_for_cpu(0..BUFFER) }
                .map_err(beacon::Error::from)?;
            let pointer = self.buffers[index]
                .cpu
                .address(0, BUFFER)
                .map_err(beacon::Error::from)?;
            // SAFETY: bounded retained actual native allocation, now CPU-owned
            // after hardware completion/visibility; callback borrow ends before
            // descriptor/payload rearm or any new hardware ownership transfer.
            let bytes = unsafe { core::slice::from_raw_parts(pointer.as_ptr(), BUFFER) };
            receive(parse(bytes).map_err(Error::Packet)?);
            self.reset_descriptor(index)?;
            self.descriptor
                .dma
                .sync_for_device(offset..offset + DESCRIPTOR)
                .map_err(beacon::Error::from)?;
            self.read = ((index + 1) % COUNT) as u16;
            self.tag = (self.tag + 1) % 8192;
        }
        if count != 0 {
            fence(Ordering::Release);
            self.io
                .as_mut()
                .ok_or(Error::Quarantined)?
                .publish(self.read)?;
        }
        Ok(count)
    }
    /// # Safety
    /// Independently stopped/drained exact requester, all workers serialized.
    /// Initial HCI only: any prior poll permanently refuses this path, so it
    /// cannot silently reset a live station's RX/tag/security generation.
    pub(super) unsafe fn begin_hci_rebind(&mut self) -> Result<u32, Error> {
        if self.poisoned || self.used || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        unsafe { self.descriptor.dma.sync_for_cpu(0..COUNT * DESCRIPTOR) }
            .map_err(beacon::Error::from)?;
        for i in 0..COUNT {
            self.reset_descriptor(i)?;
        }
        self.descriptor
            .dma
            .sync_for_device(0..COUNT * DESCRIPTOR)
            .map_err(beacon::Error::from)?;
        Ok(self.descriptor.address()?)
    }
    pub(super) fn finish_hci_rebind(&mut self) {
        self.read = 0;
        self.tag = 0;
        self.poisoned = false;
    }
    pub(super) fn initial_indices(&mut self) -> Result<(), Error> {
        if self.io.as_mut().ok_or(Error::Quarantined)?.indices()? != (0, 0) {
            return Err(Error::InitialIndices);
        }
        Ok(())
    }
    /// # Safety
    /// Independent actual requester stop/drain and stopped submission/IRQ
    /// workers through every unmap; read indices, RX tags or register reset
    /// stores alone do not prove this. Failed invalidations retain ownership.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        self.poisoned = true;
        unsafe {
            self.descriptor.release()?;
        }
        for buffer in &mut self.buffers {
            unsafe {
                buffer.release()?;
            }
        }
        self.configured = false;
        self.poisoned = false;
        Ok(())
    }
}
impl<R: Registers> Drop for Ring<R> {
    fn drop(&mut self) {
        if self.configured
            && let Some(io) = self.io.take()
        {
            core::mem::forget(io);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::beacon::tests::{Domain, Model, Source};
    use super::*;
    use alloc::vec;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Device {
        base: u32,
        consumer: u16,
        producer: u16,
        configured: bool,
        drops: usize,
        fail_configure: bool,
        fail_publish: bool,
        removed: bool,
    }
    struct Io(Arc<Mutex<Device>>);
    // SAFETY: serialized device model observes native ring mappings and owns
    // its fresh modeled producer/consumer register state, with no real DMA.
    unsafe impl Registers for Io {
        fn configure(&mut self, base: u32, count: u16) -> Result<(), Error> {
            let mut d = self.0.lock().unwrap();
            assert_eq!(count, 512);
            d.base = base;
            d.configured = true;
            if d.fail_configure {
                Err(Error::Register)
            } else {
                Ok(())
            }
        }
        fn indices(&mut self) -> Result<(u16, u16), Error> {
            let d = self.0.lock().unwrap();
            if d.removed {
                Err(Error::Removed)
            } else {
                Ok((d.consumer, d.producer))
            }
        }
        fn publish(&mut self, consumer: u16) -> Result<(), Error> {
            let mut d = self.0.lock().unwrap();
            d.consumer = consumer;
            if d.fail_publish {
                Err(Error::Register)
            } else {
                Ok(())
            }
        }
    }
    impl Drop for Io {
        fn drop(&mut self) {
            self.0.lock().unwrap().drops += 1;
        }
    }
    struct Harness {
        memory: Arc<Mutex<Model>>,
        device: Arc<Mutex<Device>>,
        ring: Ring<Io>,
    }
    impl Harness {
        fn new() -> Self {
            let memory = Arc::new(Mutex::new(Model::default()));
            let device = Arc::new(Mutex::new(Device::default()));
            // SAFETY: synchronous stopped model, real native allocations with
            // distinct serialized IOVAs; no hardware/physical proof claimed.
            let ring = unsafe {
                Ring::install(
                    Io(device.clone()),
                    &Source,
                    Arc::new(Domain(memory.clone())),
                )
            }
            .unwrap();
            Self {
                memory,
                device,
                ring,
            }
        }
        fn descriptor(&self, index: usize) -> [u8; 8] {
            let d = self.device.lock().unwrap();
            let m = self.memory.lock().unwrap();
            let (_, base) = &m.mappings[&u64::from(d.base)];
            unsafe { core::slice::from_raw_parts((*base + index * 8) as *const u8, 8) }
                .try_into()
                .unwrap()
        }
        /// Model writes only device-owned buffers addressed by actual native
        /// RXBDs; completing producer is the final device publication event.
        fn complete(&self, packets: usize, first_tag: u16, packet: &[u8]) {
            let mut d = self.device.lock().unwrap();
            let m = self.memory.lock().unwrap();
            let (_, base) = &m.mappings[&u64::from(d.base)];
            assert_eq!(m.directions[&u64::from(d.base)], Direction::Bidirectional);
            for i in 0..packets {
                let index = (usize::from(d.producer) + i) % COUNT;
                let desc = *base + index * 8;
                let bytes = unsafe { core::slice::from_raw_parts(desc as *const u8, 8) };
                assert_eq!(&bytes[..4], &[214, 44, 0, 0]);
                let address = u32::from_le_bytes(bytes[4..].try_into().unwrap());
                let (_, buffer) = &m.mappings[&u64::from(address)];
                assert_eq!(m.directions[&u64::from(address)], Direction::FromDevice);
                assert!(packet.len() <= BUFFER);
                unsafe {
                    (*buffer as *mut u8).copy_from_nonoverlapping(packet.as_ptr(), packet.len());
                    ((desc + 2) as *mut u16)
                        .write_volatile(((first_tag + i as u16) % 8192).to_le());
                }
            }
            d.producer = ((usize::from(d.producer) + packets) % COUNT) as u16;
        }
    }
    fn packet(length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length + 24];
        bytes[..4].copy_from_slice(&(length as u32).to_le_bytes());
        for (i, b) in bytes[24..].iter_mut().enumerate() {
            *b = i as u8;
        }
        bytes
    }
    #[test]
    fn source_descriptor_fields_remain_raw_and_all_ranges_are_bounded() {
        let mut bytes = vec![0; 24 + 3 + 32 + 10];
        let w0: u32 = 10 | (1 << 14) | (1 << 15) | (4 << 16) | (7 << 20) | (3 << 24) | (1 << 26);
        bytes[..4].copy_from_slice(&w0.to_le_bytes());
        bytes[4..8].copy_from_slice(&127u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&(3u32 << 29).to_le_bytes());
        bytes[12..16].copy_from_slice(&83u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&48u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&0xfedcba98u32.to_le_bytes());
        let p = parse(&bytes).unwrap();
        assert_eq!(
            (p.shift.len(), p.driver_info.len(), p.payload.len()),
            (3, 32, 10)
        );
        assert!(p.facts.crc_error && p.facts.icv_error && p.facts.hardware_decrypted);
        assert_eq!(
            (
                p.facts.encryption_raw,
                p.facts.cam_id,
                p.facts.ppdu_count,
                p.facts.rate_raw,
                p.facts.bandwidth_raw,
                p.facts.tsf_low
            ),
            (7, 127, 3, 83, 3, 0xfedcba98)
        );
        for n in 0..bytes.len() {
            assert!(parse(&bytes[..n]).is_err());
        }
        for (word, expected) in [
            (10u32 | 1 << 16, ParseError::DriverInfo(1)),
            (10 | 1 << 26, ParseError::MissingPhy),
            (4, ParseError::Length),
            (11455, ParseError::Length),
        ] {
            bytes[..4].copy_from_slice(&word.to_le_bytes());
            assert_eq!(parse(&bytes).unwrap_err(), expected);
        }
        bytes[..4].copy_from_slice(&10u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&84u32.to_le_bytes());
        assert_eq!(parse(&bytes).unwrap_err(), ParseError::Rate(84));
        let mut c2h = packet(0);
        c2h[8..12].copy_from_slice(&(1u32 << 28).to_le_bytes());
        assert!(parse(&c2h).unwrap().facts.firmware);
        assert!(parse(&packet(11454)).is_ok());
        let mut oversized = vec![0; BUFFER + 32];
        oversized[..4].copy_from_slice(&(11454u32 | (4 << 16)).to_le_bytes());
        assert_eq!(parse(&oversized).unwrap_err(), ParseError::Bounds);
    }
    #[test]
    fn native_iovas_visibility_budget_wrap_and_tag_wrap_match_device_ownership() {
        let mut h = Harness::new();
        assert_eq!(h.memory.lock().unwrap().mappings.len(), 513);
        assert_ne!(
            u64::from(h.device.lock().unwrap().base),
            h.ring.descriptor.cpu.address(0, 1).unwrap().as_ptr() as u64
        );
        assert_eq!(
            h.ring.poll(100, |_| panic!("no producer advance")).unwrap(),
            0
        );
        let frame = packet(64);
        let mut received = 0;
        // More than 8192 packets crosses both the 512-slot ring and 13-bit tag.
        for _ in 0..18 {
            h.complete(511, h.ring.expected_tag(), &frame);
            let old_read = h.ring.consumer();
            assert_eq!(
                h.ring
                    .poll(7, |p| {
                        assert_eq!(p.payload, &frame[24..]);
                        received += 1;
                    })
                    .unwrap(),
                7
            );
            assert_eq!(h.ring.consumer(), (old_read + 7) % 512);
            assert_eq!(
                h.ring
                    .poll(usize::MAX, |p| {
                        assert_eq!(p.payload, &frame[24..]);
                        received += 1;
                    })
                    .unwrap(),
                504
            );
            assert_eq!(h.ring.consumer(), h.device.lock().unwrap().consumer);
            assert_eq!(&h.descriptor(usize::from(old_read))[..4], &[214, 44, 0, 0]);
        }
        assert_eq!(received, 9198);
        assert_eq!(h.ring.expected_tag(), 1006);
        assert_eq!(h.memory.lock().unwrap().cpu_syncs, received * 2);
        // SAFETY: model is synchronous, no outstanding writes/workers remain.
        unsafe { h.ring.release_after_stop() }.unwrap();
        assert!(h.memory.lock().unwrap().mappings.is_empty());
        assert_eq!(h.ring.poll(1, |_| {}), Err(Error::Quarantined));
        drop(h.ring);
        assert_eq!(h.device.lock().unwrap().drops, 1);
    }
    #[test]
    fn adverse_completion_errors_never_release_pins_or_claim_a_frame() {
        for mode in 0..8 {
            let mut h = Harness::new();
            let tag = if mode == 0 { 9 } else { 0 };
            h.complete(1, tag, &packet(if mode == 1 { 4 } else { 64 }));
            match mode {
                2 => h.device.lock().unwrap().consumer = 1,
                3 => h.device.lock().unwrap().producer = 512,
                4 => h.device.lock().unwrap().removed = true,
                5 => h.memory.lock().unwrap().fail_cpu_sync_at = Some(1),
                6 => h.memory.lock().unwrap().fail_cpu_sync_at = Some(2),
                7 => h.memory.lock().unwrap().fail_sync_at = Some(514),
                _ => (),
            }
            let mut frames = 0;
            assert!(h.ring.poll(1, |_| frames += 1).is_err(), "mode {mode}");
            assert_eq!(frames, usize::from(mode == 7));
            assert!(h.ring.quarantined());
            assert_eq!(h.ring.poll(1, |_| panic!()), Err(Error::Quarantined));
            assert_eq!(
                h.device.lock().unwrap().consumer,
                if mode == 2 { 1 } else { 0 }
            );
            drop(h.ring);
            assert_eq!(h.device.lock().unwrap().drops, 0);
            assert_eq!(h.memory.lock().unwrap().mappings.len(), 513);
        }
    }
    #[test]
    fn configuration_publish_unmap_and_callback_uncertainty_retain_actual_owner() {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device {
            fail_configure: true,
            ..Device::default()
        }));
        assert!(
            unsafe {
                Ring::install(
                    Io(device.clone()),
                    &Source,
                    Arc::new(Domain(memory.clone())),
                )
            }
            .is_err()
        );
        assert_eq!(device.lock().unwrap().drops, 0);
        assert_eq!(memory.lock().unwrap().mappings.len(), 513);
        for mode in 0..3 {
            let mut h = Harness::new();
            h.complete(1, 0, &packet(64));
            match mode {
                0 => {
                    h.device.lock().unwrap().fail_publish = true;
                    assert!(h.ring.poll(1, |_| {}).is_err());
                }
                1 => {
                    h.memory.lock().unwrap().fail_unmap = true;
                    assert!(unsafe { h.ring.release_after_stop() }.is_err());
                }
                _ => {
                    assert!(
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h
                            .ring
                            .poll(1, |_| panic!("model callback"))))
                        .is_err()
                    );
                }
            }
            assert!(h.ring.quarantined());
            drop(h.ring);
            assert_eq!(h.device.lock().unwrap().drops, 0);
            assert_eq!(h.memory.lock().unwrap().mappings.len(), 513);
        }
    }
    #[test]
    fn unpublished_errors_release_all_allocations_before_register_publication() {
        for mode in 0..4 {
            let memory = Arc::new(Mutex::new(Model::default()));
            let device = Arc::new(Mutex::new(Device::default()));
            match mode {
                0 => device.lock().unwrap().producer = 1,
                1 => memory.lock().unwrap().address_overflow = true,
                2 => memory.lock().unwrap().fail_sync_at = Some(256),
                3 => memory.lock().unwrap().fail_sync_at = Some(513),
                _ => unreachable!(),
            }
            assert!(
                unsafe {
                    Ring::install(
                        Io(device.clone()),
                        &Source,
                        Arc::new(Domain(memory.clone())),
                    )
                }
                .is_err()
            );
            assert_eq!(device.lock().unwrap().drops, 1);
            assert!(!device.lock().unwrap().configured);
            assert!(memory.lock().unwrap().mappings.is_empty());
        }
    }
    #[test]
    #[ignore = "requires unchanged pinned C RX descriptor/ring oracle"]
    fn raw_parser_rearm_tags_and_all_ring_indices_match_unchanged_c() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_RECEIVE_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        let word = |bytes: &[u8], i: usize| {
            u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap())
        };
        for case in 0..131072 {
            let input = &trace[offset..offset + 24];
            let output = &trace[offset + 24..offset + 80];
            let mut buffer = vec![0; BUFFER];
            buffer[..24].copy_from_slice(input);
            let native = parse(&buffer);
            assert_eq!(native.is_ok(), word(output, 0) == 0, "case {case}");
            if let Ok(p) = native {
                let f = p.facts;
                let actual = [
                    0,
                    p.payload.len() as u32,
                    f.crc_error.into(),
                    f.icv_error.into(),
                    p.driver_info.len() as u32,
                    p.shift.len() as u32,
                    f.phy_present.into(),
                    f.hardware_decrypted.into(),
                    f.cam_id.into(),
                    f.firmware.into(),
                    f.ppdu_count.into(),
                    f.rate_raw.into(),
                    f.bandwidth_raw.into(),
                    f.tsf_low,
                ];
                for (i, actual) in actual.into_iter().enumerate() {
                    assert_eq!(actual, word(output, i), "case {case}, field {i}");
                }
                assert_eq!(f.encryption_raw, ((word(input, 0) >> 20) & 7) as u8);
            }
            offset += 80;
        }
        for tag in 0..8192 {
            assert_eq!(buffer_descriptor(0x12340000), trace[offset..offset + 8]);
            assert_eq!(word(&trace[offset + 8..], 0), (tag + 1) % 8192);
            assert_eq!(word(&trace[offset + 8..], 1), 0);
            assert_eq!(word(&trace[offset + 8..], 2), (tag + 1) % 8192);
            assert_eq!(word(&trace[offset + 8..], 3), 1);
            offset += 24;
        }
        for consumer in 0..512 {
            for producer in 0..512 {
                assert_eq!(
                    available(consumer, producer) as u32,
                    word(&trace[offset..], 0)
                );
                offset += 4;
            }
        }
        assert_eq!(offset, trace.len());
    }
}
