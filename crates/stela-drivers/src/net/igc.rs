//! Intel I225 and I226 Ethernet controllers, as a polled raw Ethernet
//! [`Link`]: the 2.5GBASE-T controllers most current PC boards carry.
//!
//! Reset, NVM and PHY setup follow the pinned Linux `igc` shared code.
//! The declared boot-lifetime profile uses one polled receive/transmit queue,
//! ordinary Ethernet, autonegotiated 10/100/1000/2500 copper and no pause/EEE.
//! Management-owned PHYs, blank NVM, failed register reads and incomplete
//! reset/MDIO/semaphore exchanges fail before any new DMA ring is published.
mod hardware;

use super::{Link, LinkError, MAX_FRAME, Mac};
use crate::{
    Clock, Handoff,
    block::BlockError,
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::Function,
    },
    registers,
};
use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::{Ordering, fence};

const VENDOR: u16 = 0x8086;
/// The I220, I221, I225 and I226 parts with a programmed NVM (`igc_hw.h`).
const DEVICES: [u16; 14] = [
    0x15f2, 0x15f3, 0x15f7, 0x15f8, 0x3100, 0x3101, 0x3102, 0x5502, 0x5503, 0x0d9f, 0x125b, 0x125c,
    0x125d, 0x125e,
];

const STATUS: usize = 0x0008;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const RAL: usize = 0x5400;
const RAH: usize = 0x5404;
/// Queue 0's receive and transmit registers.
const RDBAL: usize = 0xc000;
const RDBAH: usize = 0xc004;
const RDLEN: usize = 0xc008;
const SRRCTL: usize = 0xc00c;
const RDH: usize = 0xc010;
const RDT: usize = 0xc018;
const RXDCTL: usize = 0xc028;
const TDBAL: usize = 0xe000;
const TDBAH: usize = 0xe004;
const TDLEN: usize = 0xe008;
const TDH: usize = 0xe010;
const TDT: usize = 0xe018;
const TXDCTL: usize = 0xe028;
/// The register file the driver touches.
const REGISTER_BYTES: u64 = 0x1_2018; // Includes EERD for validated programmed NVM.

const STATUS_LU: u32 = 1 << 1;
const RAH_AV: u32 = 1 << 31;
const RCTL_EN: u32 = 1 << 1;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT: u32 = 0xff << 4;
const TCTL_RTLC: u32 = 1 << 24;
const COLLISION_THRESHOLD: u32 = 15 << 4;
/// Packet buffer size in 1 KiB units, and one buffer per advanced descriptor.
const SRRCTL_BSIZEPKT: u32 = (BUFFER >> 10) as u32;
const SRRCTL_DESCTYPE_ADV_ONEBUF: u32 = 1 << 25;
const QUEUE_ENABLE: u32 = 1 << 25;
/// Prefetch 8, host 8 and write back every receive descriptor at once;
/// transmit descriptors are written back on their RS bit.
const RXDCTL_THRESHOLDS: u32 = 8 | 8 << 8 | 1 << 16;
const TXDCTL_THRESHOLDS: u32 = 8 | 1 << 8;

const RX_DD: u32 = 1 << 0;
const RX_EOP: u32 = 1 << 1;
const RX_RXE: u32 = 1 << 31;
const TX_DD: u32 = 1 << 0;
const TX_DTYP_DATA: u32 = 0x3 << 20;
const TX_EOP: u32 = 1 << 24;
const TX_IFCS: u32 = 1 << 25;
const TX_RS: u32 = 1 << 27;
const TX_DEXT: u32 = 1 << 29;
const TX_PAYLEN_SHIFT: u32 = 14;

/// Descriptors per ring: a multiple of eight, so the ring length is a
/// multiple of 128 bytes.
const DESCRIPTORS: usize = 32;
const DESCRIPTOR: usize = 16;
const BUFFER: usize = 2048;
const ETHERNET_HEADER: usize = 14;
/// igc_xmit_frame: TCTL.PSP still requires at least17 DMA bytes.
const MIN_TRANSMIT: usize = 17;
const _: () = assert!((DESCRIPTORS * DESCRIPTOR).is_multiple_of(128) && BUFFER >= MAX_FRAME);
const QUEUE_ENABLE_US: u64 = 20_000;
const TRANSMIT_WAIT_US: u64 = 100_000;

pub fn matches(function: &Function) -> bool {
    function.vendor == VENDOR && DEVICES.contains(&function.device) && function.class == [2, 0, 0]
}

/// The station address in receive address register 0, which the NVM
/// auto-read loads: RAL holds bytes 0-3, RAH bytes 4-5 and the valid bit.
fn station(low: u32, high: u32) -> Option<Mac> {
    if high == u32::MAX || low == u32::MAX || high & RAH_AV == 0 {
        return None;
    }
    let [a, b, c, d] = low.to_le_bytes();
    let [e, f, _, _] = high.to_le_bytes();
    Some(Mac([a, b, c, d, e, f])).filter(|mac| mac.0 != [0; 6] && mac.0[0] & 1 == 0)
}

/// An advanced data descriptor's command word and status for one frame in
/// one buffer.
fn transmit_words(length: usize) -> (u32, u32) {
    let length = length as u32;
    (
        TX_DTYP_DATA | TX_DEXT | TX_IFCS | TX_EOP | TX_RS | length,
        length << TX_PAYLEN_SHIFT,
    )
}

/// A written-back receive descriptor's frame length, if the descriptor is
/// done; `Some(None)` for a frame to drop: one with errors, or one longer
/// than a buffer (long packets are off, so it cannot fit).
fn received(status: u32, length: u16) -> Option<Option<usize>> {
    if status & RX_DD == 0 {
        return None;
    }
    let length = usize::from(length);
    let good = status & RX_EOP != 0 && status & RX_RXE == 0 && length > 0 && length <= MAX_FRAME;
    Some(good.then_some(length))
}

/// A descriptor ring and one buffer per descriptor.
struct Ring {
    descriptors: DmaBuffer,
    buffers: DmaBuffer,
}

impl Ring {
    fn new(dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Ok(Self {
            descriptors: dma.allocate(DESCRIPTORS * DESCRIPTOR, 4096)?,
            buffers: dma.allocate(DESCRIPTORS * BUFFER, 4096)?,
        })
    }

    fn buffer_address(&self, index: usize) -> u64 {
        self.buffers.physical() + (index * BUFFER) as u64
    }

    fn buffer(&mut self, index: usize) -> &mut [u8] {
        &mut self.buffers.bytes_mut()[index * BUFFER..(index + 1) * BUFFER]
    }

    /// Point the controller's base, length, head and tail registers at the
    /// ring.
    fn program(&self, device: &Mmio, base_low: usize, base_high: usize, length: usize) {
        let address = self.descriptors.physical();
        device.write32(length, (DESCRIPTORS * DESCRIPTOR) as u32);
        device.write32(base_high, (address >> 32) as u32);
        device.write32(base_low, address as u32);
    }
}

pub struct Igc {
    device: Mmio,
    receive: Ring,
    transmit: Ring,
    /// The next receive descriptor the controller fills.
    received: usize,
    /// Discard the rest of a split/oversized frame through its actual EOP.
    discarding: bool,
    /// An absent/failed MMIO function requires a fresh attachment.
    faulted: bool,
    /// The next free transmit descriptor, and the oldest one in flight.
    tail: usize,
    clean: usize,
    mac: Mac,
    clock: Clock,
    pub location: String,
    /// Actual internal PHY identifier, including its silicon revision.
    pub phy_identity: u32,
}

impl Igc {
    pub fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        if !matches(function) {
            return Err(BlockError::Unsupported(
                "not an Intel I225/I226 copper candidate",
            ));
        }
        let device = registers(handoff, function.bars()[0], 0, REGISTER_BYTES)?;
        function.enable_polled();
        let clock = handoff.clock;
        let mut hardware = hardware::Hardware::new(&device, &clock)?;
        let phy_identity = hardware.initialize()?;
        let mac = station(device.read32(RAL), device.read32(RAH)).ok_or(
            BlockError::Unsupported("Intel I225/I226 without a valid station address"),
        )?;
        let mut net = Self {
            device,
            receive: Ring::new(dma)?,
            transmit: Ring::new(dma)?,
            received: 0,
            discarding: false,
            faulted: false,
            tail: 0,
            clean: 0,
            mac,
            clock,
            location: format!("{}", function.address),
            phy_identity,
        };
        net.start_receive()?;
        net.start_transmit()?;
        Ok(net)
    }

    fn start_receive(&mut self) -> Result<(), BlockError> {
        let device = &self.device;
        device.write32(RCTL, 0);
        self.receive.program(device, RDBAL, RDBAH, RDLEN);
        device.write32(SRRCTL, SRRCTL_BSIZEPKT | SRRCTL_DESCTYPE_ADV_ONEBUF);
        device.write32(RDH, 0);
        device.write32(RDT, 0);
        device.write32(RXDCTL, RXDCTL_THRESHOLDS | QUEUE_ENABLE);
        if !self.clock.wait(QUEUE_ENABLE_US, || {
            let value = device.read32(RXDCTL);
            value != u32::MAX && value & QUEUE_ENABLE != 0
        }) {
            return Err(BlockError::Unsupported(
                "Intel I225/I226 receive queue did not enable",
            ));
        }
        for index in 0..DESCRIPTORS {
            self.offer_receive(index);
        }
        // Head equal to tail is an empty ring: the controller owns every
        // descriptor but the one before the head.
        fence(Ordering::SeqCst);
        self.device.write32(RDT, (DESCRIPTORS - 1) as u32);
        // Link has no multicast-list callback. Admit all multicast, as the
        // donor's IFF_ALLMULTI path does, so IPv6/other multicast reaches it.
        self.device
            .write32(RCTL, RCTL_EN | RCTL_MPE | RCTL_BAM | RCTL_SECRC);
        Ok(())
    }

    fn start_transmit(&mut self) -> Result<(), BlockError> {
        let device = &self.device;
        self.transmit.program(device, TDBAL, TDBAH, TDLEN);
        device.write32(TDT, 0);
        device.write32(TDH, 0);
        device.write32(TXDCTL, TXDCTL_THRESHOLDS | QUEUE_ENABLE);
        if !self.clock.wait(QUEUE_ENABLE_US, || {
            let value = device.read32(TXDCTL);
            value != u32::MAX && value & QUEUE_ENABLE != 0
        }) {
            return Err(BlockError::Unsupported(
                "Intel I225/I226 transmit queue did not enable",
            ));
        }
        let control = device.read32(TCTL);
        if control == u32::MAX {
            return Err(BlockError::Device { status: control });
        }
        let control = control & !TCTL_CT;
        device.write32(
            TCTL,
            control | TCTL_PSP | TCTL_RTLC | TCTL_EN | COLLISION_THRESHOLD,
        );
        Ok(())
    }

    /// Hand receive descriptor `index` its buffer; the zero header address
    /// also clears the previous write-back's status.
    fn offer_receive(&mut self, index: usize) {
        let address = self.receive.buffer_address(index);
        let base = index * DESCRIPTOR;
        self.receive.descriptors.write(base, address);
        self.receive.descriptors.write(base + 8, 0u64);
    }

    /// Retire transmit descriptors the controller has written back.
    fn reclaim(&mut self) -> bool {
        while self.clean != self.tail {
            let status: u32 = self.transmit.descriptors.read(self.clean * DESCRIPTOR + 12);
            if status & TX_DD == 0 {
                break;
            }
            self.clean = (self.clean + 1) % DESCRIPTORS;
        }
        (self.tail + 1) % DESCRIPTORS != self.clean
    }

    fn healthy(&mut self) -> Result<(), LinkError> {
        self.faulted |= self.device.read32(STATUS) == u32::MAX;
        if self.faulted {
            Err(LinkError::Adapter(format!(
                "Intel I225/I226 {} lost register access; reinitialization required",
                self.location
            )))
        } else {
            Ok(())
        }
    }
}

impl Link for Igc {
    fn mac(&self) -> Mac {
        self.mac
    }

    fn carrier(&mut self) -> bool {
        let status = self.device.read32(STATUS);
        self.faulted |= status == u32::MAX;
        !self.faulted && status & STATUS_LU != 0
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        self.healthy()?;
        if !(ETHERNET_HEADER..=MAX_FRAME).contains(&frame.len()) {
            return Err(LinkError::Invalid("invalid Ethernet frame length"));
        }
        if !self.reclaim() {
            let clock = self.clock;
            if !clock.wait(TRANSMIT_WAIT_US, || self.reclaim()) {
                return Err(LinkError::Adapter(format!(
                    "Intel I225/I226 {} transmit ring stalled",
                    self.location
                )));
            }
        }
        let index = self.tail;
        let length = frame.len().max(MIN_TRANSMIT);
        let buffer = self.transmit.buffer(index);
        buffer[..length].fill(0);
        buffer[..frame.len()].copy_from_slice(frame);
        let (command, status) = transmit_words(length);
        let base = index * DESCRIPTOR;
        let address = self.transmit.buffer_address(index);
        let descriptors = &mut self.transmit.descriptors;
        descriptors.write(base, address);
        descriptors.write(base + 8, command);
        descriptors.write(base + 12, status);
        self.tail = (index + 1) % DESCRIPTORS;
        fence(Ordering::SeqCst);
        self.device.write32(TDT, self.tail as u32);
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.healthy()?;
        loop {
            let index = self.received;
            let base = index * DESCRIPTOR;
            fence(Ordering::SeqCst);
            let status: u32 = self.receive.descriptors.read(base + 8);
            let length: u16 = self.receive.descriptors.read(base + 12);
            let Some(frame) = received(status, length) else {
                return Ok(None);
            };
            let discarded = self.discarding || status & RX_EOP == 0;
            self.discarding = status & RX_EOP == 0;
            let frame = frame
                .filter(|_| !discarded)
                .map(|length| self.receive.buffer(index)[..length].to_vec());
            self.offer_receive(index);
            self.received = (index + 1) % DESCRIPTORS;
            fence(Ordering::SeqCst);
            self.device.write32(RDT, index as u32);
            if frame.is_some() {
                return Ok(frame);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_station_address_is_receive_address_zero_when_valid() {
        let mac = station(0x7856_3412, RAH_AV | 0xbc9a);
        assert_eq!(mac, Some(Mac([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])));
        assert_eq!(station(0x7856_3412, 0xbc9a), None);
        assert_eq!(station(0, RAH_AV), None);
        assert_eq!(station(0x7856_3412, u32::MAX), None);
    }

    #[test]
    fn a_frame_is_one_advanced_data_descriptor_with_its_crc_inserted() {
        let (command, status) = transmit_words(60);
        assert_eq!(command, 0x2b30_003c);
        assert_eq!(status, 60 << 14);
        assert_eq!(status & TX_DD, 0);
    }

    #[test]
    fn written_back_frames_are_taken_or_dropped() {
        assert_eq!(received(0, 60), None);
        assert_eq!(received(RX_DD | RX_EOP, 60), Some(Some(60)));
        assert_eq!(received(RX_DD | RX_EOP | RX_RXE, 60), Some(None));
        assert_eq!(received(RX_DD, 60), Some(None));
        assert_eq!(received(RX_DD | RX_EOP, 4096), Some(None));
    }

    #[test]
    fn only_programmed_i225_and_i226_parts_match() {
        assert!(DEVICES.contains(&0x125c));
        assert!(!DEVICES.contains(&0x125f));
        assert!(!DEVICES.contains(&0x15fd));
    }

    #[test]
    fn packet_rings_wrap_and_fragment_tails_are_not_delivered_as_frames() {
        use crate::bus::dma::RegionAllocator;
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains live until all modeled DMA buffers drop.
        let mut dma = unsafe { RegionAllocator::new(start..start + (backing.len() * 8) as u64) };
        let mut registers = vec![0u32; REGISTER_BYTES as usize / 4];
        // SAFETY: the vector is this fixture's exclusive live MMIO model.
        let device = unsafe { Mmio::new(registers.as_mut_ptr() as u64) };
        let mut net = Igc {
            device,
            receive: Ring::new(&mut dma).unwrap(),
            transmit: Ring::new(&mut dma).unwrap(),
            received: 0,
            discarding: false,
            faulted: false,
            tail: 0,
            clean: 0,
            mac: Mac([2, 0, 0, 0, 0, 1]),
            clock: Clock {
                ticks_per_microsecond: 1,
            },
            location: "model".into(),
            phy_identity: 0x67c9dc01,
        };
        net.start_receive().unwrap();
        net.start_transmit().unwrap();
        assert_ne!(registers[RCTL / 4] & RCTL_MPE, 0);
        for sequence in 0..(DESCRIPTORS * 3) {
            let frame = vec![sequence as u8; 60 + sequence % 128];
            net.transmit(&frame).unwrap();
            let index = sequence % DESCRIPTORS;
            assert_eq!(&net.transmit.buffer(index)[..frame.len()], frame);
            assert_eq!(
                net.transmit.descriptors.read::<u64>(index * DESCRIPTOR),
                net.transmit.buffer_address(index)
            );
            assert_eq!(
                net.transmit.descriptors.read::<u32>(index * DESCRIPTOR + 8),
                transmit_words(frame.len()).0
            );
            // Actual modeled hardware writes completion into the same TD.
            net.transmit
                .descriptors
                .write(index * DESCRIPTOR + 12, TX_DD);
            net.receive.buffer(index)[..frame.len()].copy_from_slice(&frame);
            net.receive
                .descriptors
                .write(index * DESCRIPTOR + 8, RX_DD | RX_EOP);
            net.receive
                .descriptors
                .write(index * DESCRIPTOR + 12, frame.len() as u16);
            assert_eq!(net.receive().unwrap(), Some(frame));
            assert_eq!(registers[RDT / 4], index as u32);
        }
        for (index, status) in [(0, RX_DD), (1, RX_DD | RX_EOP), (2, RX_DD | RX_EOP)] {
            net.receive.buffer(index)[..60].fill(index as u8);
            net.receive
                .descriptors
                .write(index * DESCRIPTOR + 8, status);
            net.receive
                .descriptors
                .write(index * DESCRIPTOR + 12, 60u16);
        }
        assert_eq!(net.receive().unwrap(), Some(vec![2; 60]));
        assert_eq!(net.received, 3);
        registers[STATUS / 4] = u32::MAX;
        assert!(!net.carrier());
        registers[STATUS / 4] = STATUS_LU;
        assert!(!net.carrier());
        assert!(net.transmit(&[0; 60]).is_err());
        assert!(net.receive().is_err());
        assert!(station(u32::MAX, u32::MAX).is_none());
        assert_eq!(received(RX_DD | RX_EOP, 0), Some(None));
        assert_eq!(received(RX_DD | RX_EOP, (MAX_FRAME + 1) as u16), Some(None));
    }

    #[test]
    fn short_transmits_publish_the_psp_minimum_with_zeroed_padding_and_reject_bad_headers() {
        use crate::bus::dma::RegionAllocator;
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains live until all modeled DMA buffers drop.
        let mut dma = unsafe { RegionAllocator::new(start..start + (backing.len() * 8) as u64) };
        let mut registers = vec![0u32; REGISTER_BYTES as usize / 4];
        // SAFETY: the vector is this fixture's exclusive live MMIO model.
        let device = unsafe { Mmio::new(registers.as_mut_ptr() as u64) };
        let mut net = Igc {
            device,
            receive: Ring::new(&mut dma).unwrap(),
            transmit: Ring::new(&mut dma).unwrap(),
            received: 0,
            discarding: false,
            faulted: false,
            tail: 0,
            clean: 0,
            mac: Mac([2, 0, 0, 0, 0, 1]),
            clock: Clock {
                ticks_per_microsecond: 1,
            },
            location: "model".into(),
            phy_identity: 0x67c9dc01,
        };
        net.start_transmit().unwrap();
        // Reuse every ring buffer after nonzero old packets have occupied it.
        for sequence in 0..(DESCRIPTORS * 2) {
            let index = sequence % DESCRIPTORS;
            net.transmit.buffer(index).fill(0xa5);
            let length = 14 + sequence % 4;
            let frame = vec![sequence as u8; length];
            net.transmit(&frame).unwrap();
            assert_eq!(&net.transmit.buffer(index)[..length], frame);
            assert!(
                net.transmit.buffer(index)[length..17]
                    .iter()
                    .all(|&b| b == 0)
            );
            assert_eq!(
                net.transmit.descriptors.read::<u32>(index * DESCRIPTOR + 8),
                transmit_words(17).0
            );
            assert_eq!(
                net.transmit
                    .descriptors
                    .read::<u32>(index * DESCRIPTOR + 12),
                17 << TX_PAYLEN_SHIFT
            );
            net.transmit
                .descriptors
                .write(index * DESCRIPTOR + 12, TX_DD);
        }
        let tail = net.tail;
        let before = net.transmit.buffer(tail).to_vec();
        let descriptors = net.transmit.descriptors.bytes().to_vec();
        for length in 0..14 {
            assert!(net.transmit(&vec![0; length]).is_err());
            assert_eq!(net.tail, tail);
            assert_eq!(net.transmit.buffer(tail), before);
            assert_eq!(net.transmit.descriptors.bytes(), descriptors);
        }
    }
}
