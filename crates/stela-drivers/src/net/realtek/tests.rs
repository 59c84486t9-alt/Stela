// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Stateful protocol model, with delayed command completion and real DMA rings
//! tested separately. The revision/analogue expectations are from the pinned
//! Linux sources; this is not a physical-device or RTL8139 emulator claim.
use super::*;
use alloc::{collections::BTreeMap, rc::Rc};
use core::cell::{Cell, RefCell};

#[derive(Clone, Default)]
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    fn now(&self) -> u64 {
        self.0.get()
    }
    fn delay(&self, us: u64) {
        self.0.set(self.0.get() + us)
    }
}
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    phy: BTreeMap<(u16, u16), u16>,
    ephy: [u16; 32],
    eri: BTreeMap<u16, u32>,
    mac: BTreeMap<u16, u16>,
    page: u16,
    pending: Option<(usize, u32, u64)>,
    reset_phy_at: Option<u64>,
    reset_mac_at: Option<u64>,
    writes: Vec<(usize, u32, u8)>,
    mdio_commands: usize,
}
struct Model {
    state: RefCell<State>,
    time: Time,
    fault: Option<usize>,
    fail_phy_at: usize,
    stuck_reset: bool,
    stuck_phy_reset: bool,
    command_readback: Option<u8>,
}
impl Model {
    fn ready(time: &Time) -> Self {
        let mut state = State {
            bytes: vec![0; 256],
            ..State::default()
        };
        for (reg, value) in [
            (0, 0x1140),
            (1, 0x7909),
            (2, 0x001c),
            (3, 0xc800),
            (9, 0x1b00),
            (15, 0x3000),
        ] {
            state.phy.insert((0, reg), value);
        }
        Self {
            state: RefCell::new(state),
            time: time.clone(),
            fault: None,
            fail_phy_at: usize::MAX,
            stuck_reset: false,
            stuck_phy_reset: false,
            command_readback: None,
        }
    }
    fn raw32(s: &State, o: usize) -> u32 {
        u32::from_le_bytes(s.bytes[o..o + 4].try_into().unwrap())
    }
    fn store32(s: &mut State, o: usize, v: u32) {
        s.bytes[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn complete(&self, s: &mut State) {
        if s.reset_phy_at.is_some_and(|t| self.time.now() >= t) && !self.stuck_phy_reset {
            s.phy.entry((0, 0)).and_modify(|v| *v &= !PHY_RESET);
            s.reset_phy_at = None;
        }
        if s.reset_mac_at.is_some_and(|t| self.time.now() >= t) && !self.stuck_reset {
            s.bytes[COMMAND] &= !RESET;
            s.reset_mac_at = None;
        }
        let Some((port, command, when)) = s.pending else {
            return;
        };
        if self.time.now() < when
            || self.fault == Some(port)
            || (port == PHY_ACCESS && s.mdio_commands >= self.fail_phy_at)
        {
            return;
        }
        s.pending = None;
        let write = command & ACCESS != 0;
        let value = match port {
            PHY_ACCESS => {
                let reg = ((command >> 16) & 31) as u16;
                if write {
                    if reg == PHY_PAGE {
                        s.page = command as u16;
                    } else {
                        s.phy.insert((s.page, reg), command as u16);
                        if s.page == 0 && reg == 0 && command as u16 & PHY_RESET != 0 {
                            s.reset_phy_at = Some(self.time.now() + 100);
                        }
                    }
                    command & !ACCESS
                } else {
                    let value = if reg == PHY_PAGE {
                        s.page
                    } else {
                        *s.phy.get(&(s.page, reg)).unwrap_or(&0)
                    };
                    (command & !0xffff) | ACCESS | u32::from(value)
                }
            }
            EPHY_ACCESS => {
                let reg = ((command >> 16) & 31) as usize;
                if write {
                    s.ephy[reg] = command as u16;
                    command & !ACCESS
                } else {
                    command | ACCESS | u32::from(s.ephy[reg])
                }
            }
            ERI_ADDRESS => {
                let reg = (command & 0xfff) as u16;
                if write {
                    let mut value = *s.eri.get(&reg).unwrap_or(&0);
                    let data = Self::raw32(s, ERI_DATA);
                    for byte in 0..4 {
                        if command & (1 << (12 + byte)) != 0 {
                            value = (value & !(0xff << (byte * 8))) | (data & (0xff << (byte * 8)));
                        }
                    }
                    s.eri.insert(reg, value);
                    command & !ACCESS
                } else {
                    Self::store32(s, ERI_DATA, *s.eri.get(&reg).unwrap_or(&0));
                    command | ACCESS
                }
            }
            CSI_ADDRESS => {
                // The source helper preserves the other config bytes at 70c.
                if !write {
                    Self::store32(s, CSI_DATA, 0x1278_5634);
                }
                if write {
                    command & !ACCESS
                } else {
                    command | ACCESS
                }
            }
            PHY_OCP => {
                if write {
                    command & !ACCESS
                } else {
                    command | ACCESS | 0x1234
                }
            }
            _ => panic!("unmodeled command port"),
        };
        Self::store32(s, port, value);
    }
}
impl Registers for Model {
    fn read8(&self, o: usize) -> u8 {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        if o == COMMAND && s.bytes[o] == ENABLE {
            return self.command_readback.unwrap_or(s.bytes[o]);
        }
        s.bytes[o]
    }
    fn read16(&self, o: usize) -> u16 {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        u16::from_le_bytes(s.bytes[o..o + 2].try_into().unwrap())
    }
    fn read32(&self, o: usize) -> u32 {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        Self::raw32(&s, o)
    }
    fn write8(&self, o: usize, v: u8) {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        s.writes.push((o, u32::from(v), 1));
        s.bytes[o] = v;
        if o == COMMAND && v & RESET != 0 {
            s.reset_mac_at = Some(self.time.now() + 300);
        }
    }
    fn write16(&self, o: usize, v: u16) {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        s.writes.push((o, u32::from(v), 2));
        s.bytes[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn write32(&self, o: usize, v: u32) {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        s.writes.push((o, v, 4));
        if matches!(
            o,
            PHY_ACCESS | EPHY_ACCESS | ERI_ADDRESS | CSI_ADDRESS | PHY_OCP
        ) {
            if o == PHY_ACCESS {
                s.mdio_commands += 1;
            }
            s.pending = Some((o, v, self.time.now() + 15));
        }
        if o == MAC_OCP {
            let reg = ((v & !ACCESS) >> 15) as u16;
            if v & ACCESS != 0 {
                s.mac.insert(reg, v as u16);
            } else {
                let data = u32::from(*s.mac.get(&reg).unwrap_or(&0));
                Self::store32(&mut s, o, data);
                return;
            }
        }
        Self::store32(&mut s, o, v);
    }
}
fn revision(version: u8) -> Revision {
    let xid = match version {
        2 => 0x008,
        3 => 0x040,
        4 => 0x100,
        5 => 0x180,
        6 => 0x980,
        17 => 0x380,
        18 => 0x3c8,
        19 => 0x3c0,
        20 => 0x3c2,
        21 => 0x3c3,
        22 => 0x3c4,
        23 => 0x3c9,
        24 => 0x3ca,
        34 => 0x2c8,
        _ => panic!("fixture revision"),
    };
    revision::detect(xid << 20).unwrap()
}
#[test]
fn exact_ordered_revision_fixtures_refuse_unknown_ancient_and_wrong_pci_family() {
    // Independent source-table cases include overlapping specific/generic masks.
    for (xid, version, fw) in [
        (0x3c8, 18, None),
        (0x3c9, 23, None),
        (0x3ca, 24, None),
        (0x3c0, 19, None),
        (0x3c2, 20, None),
        (0x3c3, 21, None),
        (0x3c4, 22, None),
        (0x2c1, 32, Some("rtl_nic/rtl8168e-1.fw")),
        (0x2c0, 33, Some("rtl_nic/rtl8168e-2.fw")),
        (0x2c8, 34, Some("rtl_nic/rtl8168e-3.fw")),
        (0x641, 63, Some("rtl_nic/rtl8125b-2.fw")),
        (0x649, 70, Some("rtl_nic/rtl8126a-2.fw")),
        (0x64a, 70, Some("rtl_nic/rtl8126a-3.fw")),
        (0x980, 6, None),
    ] {
        let r = revision::detect(xid << 20).unwrap();
        assert_eq!((r.version, r.firmware), (version, fw));
        assert_eq!(u32::from(r.xid), xid);
        if version >= 61 {
            assert!(!r.implemented());
        }
    }
    for xid in [0u32, 0x300, 0x7c8, 0x6c9, 0xfcf] {
        assert!(revision::detect(xid << 20).is_none());
    }
    assert!(revision::detect(u32::MAX).is_none());
    assert!(revision::pci_family(0x8169, revision(2)));
    assert!(!revision::pci_family(0x8168, revision(2)));
    assert!(!revision::pci_family(0x8125, revision(34)));
}
#[test]
fn every_implemented_phy_branch_executes_analogue_sequence_and_restarts_copper_aneg() {
    for version in [2, 3, 4, 5, 6, 17, 18, 19, 20, 21, 22, 23, 24, 34] {
        let time = Time::default();
        let model = Model::ready(&time);
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        let bytes = 0x801f_0000u32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        hw.configure_phy(Some(&script), version == 5).unwrap();
        let s = model.state.borrow();
        assert_eq!(s.page, 0, "version{version}");
        assert_eq!(s.phy[&(0, 4)], 0x1e1);
        assert_eq!(s.phy[&(0, 9)] & 0xfb00, 0x0200);
        assert_eq!(s.phy[&(0, 0)], 0x1200);
        let expected = match version {
            2 | 3 => ((1, 0x18), 0x65c7),
            4 => ((2, 1), 0x90d0),
            5 => ((1, 0x10), 0xf01b),
            6 => ((1, 0x18), 0x67c7),
            17 => ((1, 0x10), 0xf41b),
            18 => ((2, 0xc), 0x1ec8),
            19 => ((3, 0x12), 0xc096),
            20 => ((2, 6), 0x0761),
            21 | 22 => ((2, 6), 0x5461),
            23 | 24 => ((1, 0x1d), 0x3d98),
            34 => ((3, 9), 0xa20f),
            _ => unreachable!(),
        };
        assert_eq!(s.phy[&expected.0], expected.1, "version{version}");
        assert!(time.now() >= 70_000);
        assert!(
            s.writes
                .iter()
                .all(|(o, v, _)| *o != COMMAND || *v != u32::from(ENABLE))
        );
    }
}
#[test]
fn exact_phy_id_and_capability_validation_has_no_synthetic_success() {
    for (reg, value) in [(2, 0xffff), (3, 0xc910), (1, 0), (15, 0)] {
        let time = Time::default();
        let model = Model::ready(&time);
        model.state.borrow_mut().phy.insert((0, reg), value);
        let mut hw = Hardware::new(&model, &time, revision(18), 0);
        assert!(hw.configure_phy(None, false).is_err());
        assert!(!model.state.borrow().phy.contains_key(&(2, 0x0c)));
    }
}
#[test]
fn reset_mdio_ephy_eri_csi_faults_are_bounded_and_configuration_lock_restores() {
    for port in [PHY_ACCESS, EPHY_ACCESS, ERI_ADDRESS, CSI_ADDRESS] {
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.fault = Some(port);
        let hw = Hardware::new(&model, &time, revision(34), 3);
        let result = match port {
            PHY_ACCESS => hw.phy_read(2).map(|_| ()),
            EPHY_ACCESS => hw.ephy(1, 0, 1),
            ERI_ADDRESS => hw.eri_read(0xe0).map(|_| ()),
            CSI_ADDRESS => hw.latency(),
            _ => unreachable!(),
        };
        assert_eq!(result, Err(BlockError::Timeout));
        assert!(time.now() <= 10_000);
        if port != PHY_ACCESS {
            assert_eq!(hw.configure_mac(), Err(BlockError::Timeout));
            assert_eq!(model.read8(CONFIG_LOCK), 0);
        }
    }
    let time = Time::default();
    let mut model = Model::ready(&time);
    model.stuck_reset = true;
    let hw = Hardware::new(&model, &time, revision(2), 0);
    assert_eq!(hw.reset(), Err(BlockError::Timeout));
    assert_eq!(time.now(), 10_000);
    let time = Time::default();
    let mut model = Model::ready(&time);
    model.stuck_phy_reset = true;
    let hw = Hardware::new(&model, &time, revision(18), 0);
    assert_eq!(hw.phy_reset(), Err(BlockError::Timeout));
    assert!(time.now() < 700_000);
    // Fail partway through an analogue sequence, not only at its first ID read.
    for nth in [8, 14, 25] {
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.fail_phy_at = nth;
        let mut hw = Hardware::new(&model, &time, revision(19), 0);
        assert!(hw.configure_phy(None, false).is_err());
        assert!(time.now() < 100_000);
    }
}
#[test]
fn each_mac_revision_uses_its_real_ephy_and_fifo_configuration_before_dma() {
    for version in [2, 3, 4, 5, 6, 17, 18, 19, 20, 21, 22, 23, 24, 34] {
        let time = Time::default();
        let model = Model::ready(&time);
        let hw = Hardware::new(&model, &time, revision(version), 2);
        hw.reset().unwrap();
        hw.configure_mac().unwrap();
        let s = model.state.borrow();
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        assert_eq!(
            u16::from_le_bytes(s.bytes[CPLUS..CPLUS + 2].try_into().unwrap())
                & ((1 << 5) | (1 << 6)),
            0
        );
        assert!(
            !s.writes
                .iter()
                .any(|(reg, _, _)| matches!(*reg, TX_LOW | TX_HIGH | RX_LOW | RX_HIGH))
        );
        match version {
            18 => {
                assert_eq!(s.ephy[2], 0x1000);
                assert_eq!(s.ephy[7], 0x2000);
            }
            19 => {
                assert_eq!(s.ephy[3], 2);
                assert_eq!(s.bytes[DEBUG], 0x1e);
            }
            20 | 21 => assert_eq!(s.ephy[3], 0x20),
            24 => assert_eq!(s.bytes[DEBUG], 0x20),
            34 => {
                assert_eq!(s.ephy[0xc], 0x0200);
                assert_eq!(s.eri[&0xc8], 0x0010_0002);
                assert_eq!(s.eri[&0xe8], 0x0010_0006);
                assert_eq!(s.eri[&0xd0], 0x07ff_0060);
            }
            _ => (),
        }
        if version >= 18 {
            let writes: Vec<_> = s
                .writes
                .iter()
                .filter(|(reg, _, _)| *reg == CSI_ADDRESS)
                .collect();
            assert_eq!(writes[0].1, 0x0002_f70c);
            assert_eq!(writes[1].1, 0x8002_f70c);
            assert!(s.writes.contains(&(CSI_DATA, 0x2778_5634, 4)));
        }
    }
}
#[test]
fn register_validation_rejects_bad_addresses_without_io_and_mac_mcu_page_is_restored() {
    use firmware::ScriptIo;
    let time = Time::default();
    let model = Model::ready(&time);
    let mut hw = Hardware::new(&model, &time, revision(34), 0);
    assert!(hw.phy_read(32).is_err());
    assert!(hw.eri_read(1).is_err());
    assert!(hw.eri_write(0, 0, 0).is_err());
    assert!(hw.ephy(32, 0, 0).is_err());
    assert!(model.state.borrow().writes.is_empty());
    hw.write(true, 31, 0x0a00).unwrap();
    hw.write(true, 0x10, 0x55aa).unwrap();
    assert_eq!(hw.read(true, 0x10).unwrap(), 0x55aa);
    hw.restore();
    hw.write(true, 0, 0x1234).unwrap();
    assert_eq!(model.state.borrow().mac[&OCP_PHY_BASE], 0x1234);
}
#[test]
fn descriptor_publication_is_high_before_low_and_own_before_enable() {
    use crate::bus::dma::RegionAllocator;
    let mut backing = vec![0u64; 40_000];
    let base = backing.as_mut_ptr() as u64;
    // SAFETY: backing outlives all descriptor use and has no other accesses.
    let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
    let mut rx = Ring::new(&mut dma, true).unwrap();
    let mut tx = Ring::new(&mut dma, true).unwrap();
    rx.initialize(true);
    tx.initialize(false);
    let time = Time::default();
    let model = Model::ready(&time);
    let hw = Hardware::new(&model, &time, revision(18), 0);
    publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
    let s = model.state.borrow();
    let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
    assert!(at(TX_HIGH) < at(TX_LOW));
    assert!(at(RX_HIGH) < at(RX_LOW));
    assert!(at(RX_LOW) < at(COMMAND));
    for n in 0..DESCRIPTORS {
        assert_eq!(rx.descriptors.read::<u32>(n * DESCRIPTOR) & OWN, OWN);
    }
    drop(s);
    assert_eq!(model.read32(RX_CONFIG) & 0x3f, 0xe);
    assert_eq!(model.read16(INTERRUPT_MASK), 0);
}
#[test]
fn station_mac_rejects_multicast_zero_and_broadcast() {
    assert_eq!(station(0, 0), None);
    assert_eq!(station(1, 0), None);
    assert_eq!(station(u32::MAX, u32::MAX), None);
    assert_eq!(station(0x0504_0302, 0x0706), Some(Mac([2, 3, 4, 5, 6, 7])));
}

#[test]
fn generic_phy_identical_id_nbase_variant_is_refused_before_analogue_programming() {
    let time = Time::default();
    let model = Model::ready(&time);
    model.state.borrow_mut().phy.insert((0xa61, 0x13), 0x2000);
    let mut hw = Hardware::new(&model, &time, revision(18), 0);
    assert_eq!(
        hw.configure_phy(None, false),
        Err(Error::UnsupportedPhy(0x001cc800))
    );
    assert_eq!(model.state.borrow().page, 0);
    assert!(!model.state.borrow().phy.contains_key(&(2, 0xc)));
}
#[test]
fn firmware_catalog_binding_requires_exact_pci_xid_board_and_filename() {
    use resources::{Catalog, ErrorKind, Provenance, Resource, Target};
    let bytes = 0x801f0000u32.to_le_bytes().to_vec();
    // Fixed SHA-256 fixture; identity tests do not derive their expected digest
    // through the same Catalog validation implementation.
    let catalog_digest = [
        0x23, 0xc3, 0xcf, 0xd9, 0x9c, 0xa0, 0x28, 0xa0, 0xba, 0x72, 0xe8, 0x92, 0x40, 0xe4, 0xb4,
        0xf8, 0x93, 0xc1, 0xb4, 0x26, 0xa2, 0x1a, 0x6e, 0x89, 0x36, 0xfd, 0x43, 0x13, 0x6b, 0x13,
        0xc1, 0xba,
    ];
    let catalog = Catalog::from_handoff(vec![Resource {
        name: "rtl_nic/rtl8168e-3.fw",
        target: Target {
            driver: "realtek",
            hardware: "10ec:8168",
            revision: "xid-2c8",
            board: None,
        },
        provenance: Provenance {
            source: "synthetic-test",
            revision: "1",
            member: "rtl_nic/rtl8168e-3.fw",
            license: "MIT",
        },
        expected_length: 4,
        expected_sha256: catalog_digest,
        bytes,
    }])
    .unwrap();
    let image = load_firmware(&catalog, "10ec:8168", revision(34))
        .unwrap()
        .unwrap();
    assert_eq!(image.bytes(), &0x801f0000u32.to_le_bytes());
    assert!(matches!(
        load_firmware(&catalog, "10ec:8161", revision(34)),
        Err(Error::Firmware(resources::Error {
            kind: ErrorKind::WrongTarget,
            ..
        }))
    ));
    let mut other = revision(34);
    other.xid = 0x2c9;
    assert!(load_firmware(&catalog, "10ec:8168", other).is_err());
    assert!(
        load_firmware(&catalog, "10ec:8168", revision(18))
            .unwrap()
            .is_none()
    );
    other.firmware = Some("rtl_nic/rtl8168e-2.fw");
    assert!(matches!(
        load_firmware(&catalog, "10ec:8168", other),
        Err(Error::Firmware(resources::Error {
            kind: ErrorKind::Missing,
            ..
        }))
    ));
}
#[test]
fn link_speed_patch_uses_each_copper_speed_and_rejects_unknown_and_bus_faults() {
    for (speed, first, second) in [(0x10, 0x11, 5), (8, 0x1f, 5), (4, 0x1f, 0x3f)] {
        let time = Time::default();
        let model = Model::ready(&time);
        let hw = Hardware::new(&model, &time, revision(34), 0);
        link_patch(&hw, speed | 2).unwrap();
        let s = model.state.borrow();
        assert_eq!(s.eri[&0x1bc], first);
        assert_eq!(s.eri[&0x1dc], second);
        assert_eq!(s.eri[&0xdc] & 1, 1);
    }
    let time = Time::default();
    let model = Model::ready(&time);
    let hw = Hardware::new(&model, &time, revision(34), 0);
    assert!(link_patch(&hw, 2).is_err());
    assert!(model.state.borrow().writes.is_empty());
    let mut model = Model::ready(&time);
    model.fault = Some(ERI_ADDRESS);
    let hw = Hardware::new(&model, &time, revision(34), 0);
    assert_eq!(link_patch(&hw, 0x12), Err(BlockError::Timeout));
}

#[test]
fn mac34_station_replaces_stale_exgmac_before_dma_and_relocks_on_failure() {
    use crate::bus::dma::RegionAllocator;
    for fault in [false, true] {
        let mut backing = vec![0u64; 40_000];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all descriptor use and has no other accesses.
        let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.state.borrow_mut().eri.extend([
            (0xe0, u32::MAX),
            (0xe4, u32::MAX),
            (0xf0, u32::MAX),
            (0xf4, u32::MAX),
        ]);
        if fault {
            model.fault = Some(ERI_ADDRESS);
        }
        let hw = Hardware::new(&model, &time, revision(34), 0);
        let result = publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7]));
        let s = model.state.borrow();
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
        assert!(at(MAC4) < at(MAC0));
        assert!(at(MAC0) < at(ERI_ADDRESS));
        if fault {
            assert_eq!(result, Err(BlockError::Timeout));
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW | COMMAND))
            );
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(s.eri[&0xe0], 0x0504_0302);
            assert_eq!(s.eri[&0xe4], 0x0000_0706);
            assert_eq!(s.eri[&0xf0], 0x0302_0000);
            assert_eq!(s.eri[&0xf4], 0x0706_0504);
            let eri: Vec<_> = s
                .writes
                .iter()
                .enumerate()
                .filter(|(_, (r, _, _))| *r == ERI_ADDRESS)
                .map(|(i, (_, value, _))| (i, *value))
                .collect();
            assert_eq!(
                eri.iter().map(|(_, v)| *v).collect::<Vec<_>>(),
                [0x8000_f0e0, 0x8000_f0e4, 0x8000_f0f0, 0x8000_f0f4]
            );
            assert!(eri.last().unwrap().0 < at(TX_HIGH));
            assert!(at(RX_LOW) < at(COMMAND));
        }
    }
}

#[test]
fn dma_enable_readback_rejects_failed_bus_reads_and_missing_enable_bits() {
    use crate::bus::dma::RegionAllocator;
    for (command, expected) in [
        (u8::MAX, Err(BlockError::Device { status: 255 })),
        (0, Err(BlockError::Timeout)),
        (ENABLE, Ok(())),
    ] {
        let mut backing = vec![0u64; 40_000];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all descriptor use and has no other accesses.
        let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.command_readback = Some(command);
        let hw = Hardware::new(&model, &time, revision(18), 0);
        assert_eq!(publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])), expected);
    }
}

#[test]
fn rtl8211b_resume_clears_its_suspend_quirk_before_powerup_and_propagates_failure() {
    for (id, fail) in [(0xc912, false), (0xc912, true), (0xc800, false)] {
        let time = Time::default();
        let mut model = Model::ready(&time);
        {
            let mut s = model.state.borrow_mut();
            s.phy.insert((0, 3), id);
            s.phy.insert((0, 14), 0x0200);
            s.phy.insert((0, PHY_CONTROL), 0x1940);
        }
        if fail {
            // Page zero, ID high, ID low, then the RTL8211B quirk write.
            model.fail_phy_at = 4;
        }
        let mut hw = Hardware::new(&model, &time, revision(18), 0);
        let result = hw.configure_phy(None, false);
        let s = model.state.borrow();
        let writes: Vec<_> = s
            .writes
            .iter()
            .filter(|(r, v, _)| *r == PHY_ACCESS && *v & ACCESS != 0)
            .map(|(_, v, _)| (((v >> 16) & 31) as u16, *v as u16))
            .collect();
        if fail {
            assert_eq!(result, Err(Error::Device(BlockError::Timeout)));
            assert_eq!(s.phy[&(0, 14)], 0x0200);
            assert_eq!(s.phy[&(0, PHY_CONTROL)], 0x1940);
            assert!(!s.phy.contains_key(&(2, 0x0c)));
            assert_eq!(writes, [(PHY_PAGE, 0), (14, 0)]);
        } else {
            assert_eq!(result, Ok(()));
            if id == 0xc912 {
                assert_eq!(s.phy[&(0, 14)], 0);
                let at = |entry| writes.iter().position(|v| *v == entry).unwrap();
                assert!(at((14, 0)) < at((PHY_CONTROL, 0x1140)));
                assert!(at((PHY_CONTROL, 0x1140)) < at((0x1d, 0x0f00)));
                assert!(at((0x1d, 0x0f00)) < at((PHY_CONTROL, 0x9140)));
                assert!(at((PHY_CONTROL, 0x9140)) < at((PHY_CONTROL, 0x1200)));
            } else {
                assert_eq!(s.phy[&(0, 14)], 0x0200);
                assert!(!writes.iter().any(|(reg, _)| *reg == 14));
            }
            assert_eq!(s.phy[&(0, PHY_CONTROL)], 0x1200);
        }
    }
}
