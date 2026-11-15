// SPDX-License-Identifier: GPL-2.0-only
//! A client VMD (8086:a77f) with the hierarchy firmware leaves behind it in
//! RST mode: the CPU root port at e0:06.0 and its NVMe SSD at e1:00.0, and
//! the chipset SATA controller in RAID mode at e0:17.0 holding a firmware RAID
//! volume's member disks. The parent's mixed-width BARs, bus restriction and
//! the root port's and SSD's configuration words are those a client a77f
//! reads on hardware (device serials and opaque extended payloads omitted);
//! the SATA controller follows Intel's PCH SATA layout. Linux's VMD driver
//! enumerates all three and its NVMe driver takes the SSD.
extern crate std;
use super::test_support::{Backing, model_timer};
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DmaError, DomainMapping},
        pages::DmaPages,
    },
    pci::regs,
};
use alloc::{boxed::Box, collections::BTreeMap};
use core::ops::Range;
use std::sync::Mutex;

/// ECAM offsets below CFGBAR; the host's first bus, e0, is CFGBAR bus 0.
const ROOT_PORT: usize = 6 << 15;
const SATA: usize = 0x17 << 15;
const NVME: usize = 1 << 20;
const NVME_CLASS: [u8; 3] = [1, 8, 2];

/// The root port at e0:06.0, as read on hardware. Its primary bus number is
/// 0, not e0: client VMD firmware leaves it so, and PCI Express routes by the
/// secondary and subordinate numbers alone.
const ROOT_PORT_WORDS: &[(usize, u32)] = &[
    (0x0, 0xa74d_8086),
    (0x4, 0x0010_0507), // I/O, memory and Bus Master left on by firmware.
    (0x8, 0x0604_0000),
    (0xc, 0x0081_0000),
    (0x18, 0x00e1_e100),
    (0x1c, 0x0000_00f0),
    (0x20, 0x5000_5000),
    (0x24, 0x0001_fff1),
    (0x34, 0x0000_0040),
    (0x3c, 0x0002_0400),
    (0x40, 0x0142_8010),
    (0x44, 0x0000_8001),
    (0x48, 0x0010_002f),
    (0x4c, 0x0572_6844),
    (0x50, 0x3044_0cc2),
    (0x54, 0x0004_2580),
    (0x58, 0x0148_0000),
    (0x5c, 0x0000_0008),
    (0x64, 0x0003_0bf7),
    (0x68, 0x0000_04c0), // AtomicOp Requester Enable, as firmware left it.
    (0x6c, 0x0180_001e),
    (0x70, 0x001f_0004),
    (0x80, 0x0001_9005), // MSI enabled by firmware.
    (0x84, 0xfee0_1000),
    (0x90, 0x0000_a00d), // Bridge subsystem ID.
    (0xa0, 0xc803_0001),
    (0xd0, 0x0e00_8077),
    (0xd4, 0x4000_1842),
    (0xd8, 0x093f_0008),
    (0xe0, 0x00e3_7700),
    (0xe4, 0x1005_1005),
    (0xe8, 0x0083_8014),
    (0xec, 0x0000_a000),
    (0xf0, 0x0000_0770),
    (0xf4, 0x4000_0300),
    (0xf8, 0x0000_0f00),
    (0xfc, 0x4405_0004),
    (0x100, 0x2201_0001), // AER
    (0x150, 0x2801_001f), // PTM
    (0x154, 0x0000_0416),
    (0x158, 0x0000_0003),
    (0x200, 0x1501_001e), // L1 PM substates
    (0x220, 0x2001_000d), // ACS
    (0x280, 0xa301_0002), // Virtual channel
    (0xa30, 0xa901_0019), // Secondary PCI Express
    (0xa90, 0xa9c1_0025), // Data link feature
    (0xa9c, 0xedc1_0026), // 16 GT/s physical layer
    (0xedc, 0x0001_0027), // Lane margining
];

/// The NVMe SSD at e1:00.0, as read on hardware: Enable No Snoop set (its
/// reset value) and MSI-X left enabled by firmware.
const NVME_WORDS: &[(usize, u32)] = &[
    (0x0, 0x5017_15b7),
    (0x4, 0x0010_0406),
    (0x8, 0x0108_0201),
    (0x10, 0x5000_0004),
    (0x2c, 0x5017_15b7),
    (0x34, 0x0000_0080),
    (0x3c, 0x0000_0100),
    (0x80, 0x0003_9001),
    (0x84, 0x0000_0008),
    (0x90, 0x008a_b005),
    (0xb0, 0x8040_c011),
    (0xb4, 0x0000_3000),
    (0xb8, 0x0000_2000),
    (0xc0, 0x0002_0010),
    (0xc4, 0x1000_8f02),
    (0xc8, 0x0000_2830),
    (0xcc, 0x0045_f844),
    (0xd0, 0x1044_0142),
    (0xe4, 0x0011_0812),
    (0xe8, 0x0000_0400),
    (0xec, 0x0180_001e),
    (0xf0, 0x001e_0004),
    (0x100, 0x1b82_0001), // AER
    (0x118, 0x0000_00a0),
    (0x1b8, 0x3001_0018), // LTR
    (0x300, 0x9001_0019), // Secondary PCI Express
    (0x900, 0x9101_001e), // L1 PM substates
    (0x910, 0x9201_0025), // Data link feature
    (0x920, 0x9c01_0027), // Lane margining
    (0x9c0, 0x0001_0026), // 16 GT/s physical layer
];
const NVME_BAR_BYTES: u64 = 16 << 10;

/// The chipset SATA controller in RAID mode: a conventional function with
/// MSI, power management and the SATA capability, I/O BARs and its AHCI BAR
/// in MEMBAR1, which the firmware RAID driver left decoding and mastering.
/// It has no extended configuration space.
const SATA_WORDS: &[(usize, u32)] = &[
    (0x0, 0x2822_8086),
    (0x4, 0x02b0_0007),
    (0x8, 0x0104_0000),
    (0x10, 0x5010_0000),
    (0x14, 0x5010_2800),
    (0x18, 0x0000_3091),
    (0x1c, 0x0000_3081),
    (0x20, 0x0000_3061),
    (0x24, 0x5010_2000),
    (0x2c, 0x7d91_1462),
    (0x34, 0x0000_0080),
    (0x3c, 0x0000_01ff),
    (0x70, 0x0003_a801),
    (0x74, 0x0000_0008),
    (0x80, 0x0000_7005),
    (0xa8, 0x0010_0012),
    (0xac, 0x0000_0048),
    (0x100, 0xffff_ffff),
];

#[derive(Default)]
struct State {
    parent: BTreeMap<u16, u8>,
    child: BTreeMap<usize, u8>,
    /// Each sized BAR register's writable bits, by CFGBAR offset.
    sized: BTreeMap<usize, u32>,
    /// Every child write, by CFGBAR offset.
    writes: Vec<usize>,
}
impl State {
    fn read<K: Ord + Copy>(memory: &BTreeMap<K, u8>, keys: impl Iterator<Item = K>) -> u32 {
        keys.enumerate().fold(0, |value, (i, key)| {
            value | u32::from(*memory.get(&key).unwrap_or(&0xff)) << (i * 8)
        })
    }
    fn set_parent(&mut self, offset: u16, value: u32) {
        for i in 0..4 {
            self.parent.insert(offset + i, (value >> (i * 8)) as u8);
        }
    }
    fn set(&mut self, offset: usize, width: u8, value: u32) {
        for i in 0..usize::from(width) {
            self.child.insert(offset + i, (value >> (i * 8)) as u8);
        }
    }
    fn child(&self, offset: usize, width: u8) -> u32 {
        Self::read(&self.child, (0..usize::from(width)).map(|i| offset + i))
    }
    fn function(&mut self, base: usize, words: &[(usize, u32)]) {
        for offset in 0..4096 {
            self.child.insert(base + offset, 0);
        }
        for &(offset, value) in words {
            self.set(base + offset, 4, value);
        }
    }
    fn master(&self, base: usize) -> bool {
        self.child(base + 4, 2) & u32::from(regs::COMMAND_MASTER) != 0
    }
    fn decode(&self, base: usize) -> u32 {
        self.child(base + 4, 2) & u32::from(regs::COMMAND_IO | regs::COMMAND_MEMORY)
    }
}

/// The parent's BARs: a 64-bit CFGBAR of 32 buses, a 32-bit MEMBAR1 below
/// 4 GiB and a 64-bit MEMBAR2, none prefetchable.
const BARS: [(u64, u64, bool); 3] = [
    (0x62_2c00_0000, 32 << 20, false),
    (0x5000_0000, 32 << 20, false),
    (0x62_2f10_0000, 1 << 20, false),
];

struct Client(Arc<Mutex<State>>);
impl Client {
    fn new() -> Self {
        let mut state = State::default();
        for offset in 0..256 {
            state.parent.insert(offset, 0);
        }
        state.set_parent(0, 0xa77f_8086);
        state.set_parent(4, 0x0010_0402); // Memory decode, INTx disabled, capabilities.
        state.set_parent(8, 0x0104_0000);
        for (offset, value) in [
            (0x10, 0x2c00_0004),
            (0x14, 0x62),
            (0x18, 0x5000_0000),
            (0x1c, 0),
            (0x20, 0x2f10_0004),
            (0x24, 0x62),
            (0x2c, 0x0000_8086),
            (0x34, 0xe0),
            (0xe0, 0x0003_0001), // Power management, in D0.
        ] {
            state.set_parent(offset, value);
        }
        // VMCAP reports the bus restriction and VMCONFIG selects buses e0-ff.
        state.set_parent(crate::bus::vmd::VMCAP, 1);
        state.set_parent(crate::bus::vmd::VMCONFIG, 2 << 8);
        state.function(ROOT_PORT, ROOT_PORT_WORDS);
        state.function(NVME, NVME_WORDS);
        state.function(SATA, SATA_WORDS);
        state
            .sized
            .insert(NVME + 0x10, !(NVME_BAR_BYTES as u32 - 1));
        state.sized.insert(NVME + 0x14, u32::MAX);
        Self(Arc::new(Mutex::new(state)))
    }
}
// SAFETY: isolated configuration storage; no production permission.
unsafe impl Registers for Client {
    fn parent_read(&mut self, offset: u16, width: u8) -> Result<u32, Error> {
        let state = self.0.lock().unwrap();
        Ok(State::read(
            &state.parent,
            (0..u16::from(width)).map(|i| offset + i),
        ))
    }
    fn parent_write(&mut self, offset: u16, width: u8, value: u32) -> Result<(), Error> {
        let mut state = self.0.lock().unwrap();
        for i in 0..u16::from(width) {
            state.parent.insert(offset + i, (value >> (i * 8)) as u8);
        }
        Ok(())
    }
    fn bar(&self, index: u8) -> (u64, u64, bool) {
        BARS[usize::from(index / 2)]
    }
    fn shadow_read(&mut self, _: usize) -> Result<u64, Error> {
        Err(Error::Mapping)
    }
    fn child_read(&mut self, offset: usize, width: u8) -> Result<u32, Error> {
        Ok(self.0.lock().unwrap().child(offset, width))
    }
    fn child_write(&mut self, offset: usize, width: u8, value: u32) -> Result<(), Error> {
        let mut state = self.0.lock().unwrap();
        state.writes.push(offset);
        let value = match state.sized.get(&offset) {
            Some(&writable) if width == 4 => value & writable | state.child(offset, 4) & !writable,
            _ => value,
        };
        state.set(offset, width, value);
        Ok(())
    }
    fn table_read(&mut self, _: u64) -> Result<u32, Error> {
        Err(Error::Mapping)
    }
    fn table_write(&mut self, _: u64, _: u32) -> Result<(), Error> {
        Err(Error::Mapping)
    }
}

/// No DMA is issued here: the hierarchy lifecycle never maps through it.
struct Unused;
// SAFETY: refuses every operation; nothing is ever mapped.
unsafe impl DmaDomain for Unused {
    unsafe fn map(&self, _: &DmaPages, _: Direction, _: u64) -> Result<DomainMapping, DmaError> {
        Err(DmaError::MappingFailed)
    }
    unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
        Err(DmaError::InvalidationFailed)
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Err(DmaError::MappingFailed)
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Err(DmaError::MappingFailed)
    }
}

#[test]
fn a_client_vmd_in_rst_mode_attaches_its_nvme_and_leaves_the_raid_controller_stopped() {
    let model = Client::new();
    let state = Arc::clone(&model.0);
    let mut host = match Host::initialize(model) {
        Ok(host) => host,
        Err((error, _)) => panic!("host: {error:?}"),
    };
    assert_eq!(host.buses(), 0xe0..=0xff);
    assert_eq!(
        host.windows()[0],
        Window {
            cpu_start: 0x5000_0000,
            bus_start: 0x5000_0000,
            bytes: 32 << 20,
            prefetchable: false,
        }
    );
    let children = host.scan().unwrap();
    let found: Vec<_> = children
        .iter()
        .map(|child| {
            (
                child.address.bus,
                child.address.device,
                child.class,
                child.header,
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            (0xe0, 6, [6, 4, 0], 1),
            (0xe0, 0x17, [1, 4, 0], 0),
            (0xe1, 0, NVME_CLASS, 0),
        ]
    );
    let nvme = children[2].address;
    assert_eq!(host.memory_bar_bytes(nvme), Ok(NVME_BAR_BYTES));
    let bar = FirmwareBar {
        domain: host.domain,
        child: nvme,
        low: 0x5000_0004,
        high: 0,
        bus_start: 0x5000_0000,
        bytes: NVME_BAR_BYTES,
        window: host.windows[0],
        resource: Resource::new(Box::new(Backing {
            owner: Arc::new(()),
        })),
    };
    let raid_before: Vec<_> = (0..64)
        .map(|i| state.lock().unwrap().child(SATA + i * 4, 4))
        .collect();
    let (mut endpoint, mut returned) = Endpoint::new(host, Arc::new(Unused), model_timer());
    endpoint.discover(&bar, NVME_CLASS).unwrap();
    {
        let state = state.lock().unwrap();
        // Discovery stopped what firmware left mastering or signalling,
        // and the SSD's No Snoop, as the takeover does for visible functions.
        for base in [ROOT_PORT, SATA, NVME] {
            assert!(!state.master(base));
        }
        assert_eq!(state.child(ROOT_PORT + 0x82, 2) & 1, 0);
        assert_eq!(state.child(NVME + 0xb2, 2) & 0x8000, 0);
        assert_eq!(state.child(NVME + 0xc8, 2) & (1 << 11), 0);
    }
    endpoint.prepare().unwrap();
    endpoint.enable_dma().unwrap();
    {
        let state = state.lock().unwrap();
        for base in [ROOT_PORT, NVME] {
            assert!(state.master(base));
            assert_eq!(state.decode(base), u32::from(regs::COMMAND_MEMORY));
        }
        // The RAID controller is never driven: it stays stopped without
        // decode, and only its Command register was written.
        assert!(!state.master(SATA));
        assert_eq!(state.decode(SATA), 0);
        assert!(
            state
                .writes
                .iter()
                .filter(|offset| (SATA..SATA + 4096).contains(*offset))
                .all(|offset| *offset == SATA + 4)
        );
        for (i, before) in raid_before.iter().enumerate().skip(2) {
            assert_eq!(state.child(SATA + i * 4, 4), *before);
        }
    }
    endpoint.disable_dma().unwrap();
    // SAFETY: no engine, mapping or interrupt exists in this model.
    unsafe { endpoint.release() }.unwrap();
    // SAFETY: as above; nothing holds the domain or a mapping.
    assert!(unsafe { returned.take_after_retirement() }.is_some());
    let state = state.lock().unwrap();
    for base in [ROOT_PORT, SATA, NVME] {
        assert!(!state.master(base));
    }
}
