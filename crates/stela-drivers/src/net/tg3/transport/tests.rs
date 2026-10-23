// SPDX-License-Identifier: GPL-2.0-only
//! Authored register models. UNRUN: source-only driver assignment.
use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::RefCell;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Config(u16, u32),
    ConfigWrite(u16, u32),
    ConfigWrite16(u16, u16),
    Read(u32, u32),
    Write(u32, u32),
    ApeRead(u32, u32),
    ApeWrite(u32, u32),
    Delay(u64),
}
#[derive(Default)]
struct Model {
    config: BTreeMap<u16, u32>,
    mac: BTreeMap<u32, u32>,
    ape: BTreeMap<u32, u32>,
    sram: BTreeMap<u32, u32>,
    phy: BTreeMap<u8, u16>,
    trace: Vec<Event>,
    function: u8,
    command: u32,
    busy_reads: usize,
    force_busy: bool,
    force_read_failure: bool,
    no_grant: bool,
    competing_grant: bool,
    stuck_stop: Option<u32>,
    io_count: usize,
    fail_at: Option<usize>,
    dropped: usize,
}
impl Model {
    fn event(&mut self, event: Event) -> Result<(), Error> {
        self.trace.push(event);
        self.io_count += 1;
        if self.fail_at == Some(self.io_count) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
}
struct Reg(Rc<RefCell<Model>>);
impl Drop for Reg {
    fn drop(&mut self) {
        self.0.borrow_mut().dropped += 1;
    }
}
#[derive(Clone)]
struct Timer(Rc<RefCell<Model>>);
impl Delay for Timer {
    fn delay_us(&mut self, us: u64) {
        self.0.borrow_mut().trace.push(Event::Delay(us));
    }
}
// SAFETY: a symbolic isolated test device only; no production address/authority.
unsafe impl Registers for Reg {
    fn function_number(&self) -> u8 {
        self.0.borrow().function
    }
    fn config_read32(&mut self, at: u16) -> Result<u32, Error> {
        let mut m = self.0.borrow_mut();
        let value = *m.config.get(&at).unwrap_or(&0);
        m.event(Event::Config(at, value))?;
        Ok(value)
    }
    fn config_write32(&mut self, at: u16, value: u32) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.event(Event::ConfigWrite(at, value))?;
        m.config.insert(at, value);
        Ok(())
    }
    fn config_write16(&mut self, at: u16, value: u16) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.event(Event::ConfigWrite16(at, value))?;
        let shift = (at & 2) * 8;
        let previous = *m.config.get(&(at & !3)).unwrap_or(&0);
        m.config.insert(
            at & !3,
            (previous & !(0xffff << shift)) | (u32::from(value) << shift),
        );
        Ok(())
    }
    fn read32(&mut self, at: u32) -> Result<u32, Error> {
        let mut m = self.0.borrow_mut();
        let value = if at == MEM_DATA {
            let window = *m.mac.get(&MEM_BASE).unwrap_or(&0);
            *m.sram.get(&window).unwrap_or(&0)
        } else if at == MAC_MI_COM && m.command != 0 {
            if m.force_busy || m.busy_reads > 0 {
                m.busy_reads = m.busy_reads.saturating_sub(1);
                m.command
            } else {
                let register = ((m.command >> 16) & 31) as u8;
                let data = if m.command & MI_READ != 0 {
                    u32::from(*m.phy.get(&register).unwrap_or(&0))
                } else {
                    let command = m.command;
                    m.phy.insert(register, command as u16);
                    command & 0xffff
                };
                (m.command & !(MI_START | 0xffff))
                    | data
                    | if m.force_read_failure {
                        MI_READ_FAILED
                    } else {
                        0
                    }
            }
        } else {
            *m.mac.get(&at).unwrap_or(&0)
        };
        m.event(Event::Read(at, value))?;
        Ok(value)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.event(Event::Write(at, value))?;
        if at == MEM_DATA {
            let window = *m.mac.get(&MEM_BASE).unwrap_or(&0);
            m.sram.insert(window, value);
        } else if at == MAC_MI_COM {
            m.command = value;
            m.busy_reads = 1;
        } else if m.stuck_stop != Some(at) {
            m.mac.insert(at, value);
        }
        Ok(())
    }
    fn ape_read32(&mut self, at: u32) -> Result<u32, Error> {
        let mut m = self.0.borrow_mut();
        let value = *m.ape.get(&at).unwrap_or(&0);
        m.event(Event::ApeRead(at, value))?;
        Ok(value)
    }
    fn ape_write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.event(Event::ApeWrite(at, value))?;
        let request = if (APE_LOCK_REQ..APE_LOCK_REQ + 32).contains(&at) {
            Some(APE_LOCK_REQ)
        } else if (APE_PER_LOCK_REQ..APE_PER_LOCK_REQ + 32).contains(&at) {
            Some(APE_PER_LOCK_REQ)
        } else {
            None
        };
        if let Some(base) = request {
            let grant = at - base
                + if base == APE_LOCK_REQ {
                    APE_LOCK_GRANT
                } else {
                    APE_PER_LOCK_GRANT
                };
            let value = if m.no_grant {
                0
            } else if m.competing_grant {
                value | 1
            } else {
                value
            };
            m.ape.insert(grant, value);
        } else {
            m.ape.insert(at, 0);
        }
        Ok(())
    }
}
fn model(asic: Asic, function: u8) -> (Hardware<Reg, Timer>, Rc<RefCell<Model>>) {
    let (device, revision, identity) = match asic {
        Asic::Bcm5761 => (0x1681u16, 0x0576_1000, 0xbc05_0fd3u32),
        Asic::Bcm5720 => (0x165f, 0x0572_0000, 0x5c0d_8b62),
        Asic::Bcm5762 => (0x1687, 0x0576_2000, 0x8580_3781),
    };
    let mut m = Model {
        function,
        ..Default::default()
    };
    m.config.insert(0, (u32::from(device) << 16) | 0x14e4);
    m.config.insert(8, 0x0200_0000);
    m.config.insert(MISC_HOST_CTRL, 0xf000_0000);
    m.config.insert(
        if asic == Asic::Bcm5761 {
            PRODID
        } else {
            GEN2_PRODID
        },
        revision,
    );
    m.phy.insert(2, ((identity >> 10) & 0xffff) as u16);
    m.phy
        .insert(3, (((identity >> 16) & 0xfc00) | (identity & 0x3ff)) as u16);
    m.phy.insert(7, 0xa55a);
    m.sram
        .insert(SRAM_CPMU_STATUS, (u32::from(function) << 30) | CPMU_STATUS);
    let m = Rc::new(RefCell::new(m));
    (Hardware::new(Reg(m.clone()), Timer(m.clone())), m)
}
fn identified(asic: Asic, function: u8) -> (Hardware<Reg, Timer>, Rc<RefCell<Model>>) {
    let (mut hardware, m) = model(asic, function);
    hardware.identify().unwrap();
    m.borrow_mut().trace.clear();
    (hardware, m)
}

#[test]
fn actual_config_revision_and_phy_oui_select_each_named_family() {
    for asic in [Asic::Bcm5761, Asic::Bcm5720, Asic::Bcm5762] {
        for function in 0..4 {
            let (mut hardware, _) = model(asic, function);
            let identity = hardware.identify().unwrap();
            assert_eq!(identity.asic, asic);
            assert_eq!(identity.function, function);
            assert_eq!(
                identity.phy_address,
                if asic == Asic::Bcm5720 {
                    function + 1
                } else {
                    1
                }
            );
            assert_ne!(hardware.read_phy_identity().unwrap() & 0xf, 0);
        }
    }
}

#[test]
fn a_candidate_id_cannot_authorize_wrong_asic_or_serdes() {
    let (mut hardware, m) = model(Asic::Bcm5720, 0);
    m.borrow_mut().config.insert(GEN2_PRODID, 0x0571_9000);
    assert_eq!(hardware.identify(), Err(Error::UnsupportedRevision));
    assert!(
        !m.borrow()
            .trace
            .iter()
            .any(|e| matches!(e, Event::Write(..) | Event::ApeWrite(..)))
    );
    let (mut hardware, m) = model(Asic::Bcm5720, 0);
    m.borrow_mut().mac.insert(SG_DIG_STATUS, SG_DIG_IS_SERDES);
    assert_eq!(hardware.identify(), Err(Error::UnsupportedMedia));
    assert_eq!(hardware.read_phy(2), Err(Error::Poisoned));
}

#[test]
fn mdio_takes_each_real_phy_grant_and_restores_autopoll_before_unlock() {
    for asic in [Asic::Bcm5761, Asic::Bcm5720, Asic::Bcm5762] {
        for function in 0..4 {
            let (mut hardware, m) = identified(asic, function);
            m.borrow_mut()
                .mac
                .insert(MAC_MI_MODE, MI_AUTO_POLL | 0xc0000);
            assert_eq!(hardware.read_phy(7), Ok(0xa55a));
            let m = m.borrow();
            let base = if asic == Asic::Bcm5761 {
                APE_LOCK_REQ
            } else {
                APE_PER_LOCK_REQ
            };
            let grant = if asic == Asic::Bcm5761 {
                APE_LOCK_GRANT
            } else {
                APE_PER_LOCK_GRANT
            };
            let offset = u32::from(PHY_LOCKS[usize::from(function)]) * 4;
            assert!(
                m.trace
                    .contains(&Event::ApeWrite(base + offset, APE_DRIVER))
            );
            assert_eq!(
                &m.trace[m.trace.len() - 4..],
                &[
                    Event::Write(MAC_MI_MODE, MI_AUTO_POLL | 0xc0000),
                    Event::Read(MAC_MI_MODE, MI_AUTO_POLL | 0xc0000),
                    Event::Delay(80),
                    Event::ApeWrite(grant + offset, APE_DRIVER),
                ]
            );
        }
    }
}

#[test]
fn lock_failure_is_bounded_and_never_issues_mdio() {
    for competing in [false, true] {
        let (mut hardware, m) = identified(Asic::Bcm5720, 2);
        m.borrow_mut().no_grant = !competing;
        m.borrow_mut().competing_grant = competing;
        assert_eq!(hardware.read_phy(2), Err(Error::ApeTimeout));
        assert_eq!(
            m.borrow()
                .trace
                .iter()
                .filter(|e| **e == Event::Delay(10))
                .count(),
            100
        );
        assert!(
            !m.borrow()
                .trace
                .iter()
                .any(|e| matches!(e, Event::Write(MAC_MI_COM, _)))
        );
        let events = m.borrow().trace.len();
        assert_eq!(hardware.read_phy(2), Err(Error::Poisoned));
        assert_eq!(m.borrow().trace.len(), events);
    }
}

#[test]
fn mdio_timeout_and_hardware_read_failure_are_sticky() {
    let (mut hardware, m) = identified(Asic::Bcm5762, 0);
    m.borrow_mut().force_busy = true;
    assert_eq!(hardware.read_phy(2), Err(Error::MdioTimeout));
    assert_eq!(
        m.borrow()
            .trace
            .iter()
            .filter(|e| **e == Event::Delay(10))
            .count(),
        5000
    );
    assert!(matches!(
        m.borrow().trace.last(),
        Some(Event::ApeWrite(_, APE_DRIVER))
    ));
    let (mut hardware, m) = identified(Asic::Bcm5762, 0);
    m.borrow_mut().force_read_failure = true;
    assert_eq!(hardware.read_phy(2), Err(Error::MdioReadFailed));
}

#[test]
fn every_successful_mdio_io_access_fault_poison_retains_owner() {
    let (mut hardware, m) = identified(Asic::Bcm5720, 1);
    m.borrow_mut().mac.insert(MAC_MI_MODE, MI_AUTO_POLL);
    let before = m.borrow().io_count;
    hardware.read_phy(7).unwrap();
    let count = m.borrow().io_count - before;
    for failing in 1..=count {
        let (mut hardware, m) = identified(Asic::Bcm5720, 1);
        m.borrow_mut().mac.insert(MAC_MI_MODE, MI_AUTO_POLL);
        let before = m.borrow().io_count;
        m.borrow_mut().fail_at = Some(before + failing);
        assert_eq!(hardware.read_phy(7), Err(Error::Access), "access {failing}");
        let events = m.borrow().trace.len();
        assert_eq!(hardware.write_phy(7, 0), Err(Error::Poisoned));
        assert_eq!(m.borrow().trace.len(), events);
        drop(hardware);
        assert_eq!(m.borrow().dropped, 0);
    }
}

#[test]
fn sram_data_all_ones_is_valid_and_window_is_restored_on_every_path() {
    let (mut hardware, m) = identified(Asic::Bcm5761, 0);
    hardware.write_sram(0x1000, u32::MAX).unwrap();
    assert_eq!(hardware.read_sram(0x1000), Ok(u32::MAX));
    assert_eq!(m.borrow().mac[&MEM_BASE], 0);
    let (mut hardware, m) = identified(Asic::Bcm5761, 0);
    let before = m.borrow().io_count;
    m.borrow_mut().fail_at = Some(before + 3); // Data read.
    assert_eq!(hardware.read_sram(0x1000), Err(Error::Access));
    assert_eq!(m.borrow().mac[&MEM_BASE], 0);
}

#[test]
fn firmware_requires_the_actual_inverted_bootcode_signature() {
    let (mut hardware, m) = identified(Asic::Bcm5761, 0);
    hardware.arm_firmware_handshake().unwrap();
    assert_eq!(m.borrow().sram[&FIRMWARE_MBOX], FIRMWARE_MAGIC);
    m.borrow_mut().sram.insert(FIRMWARE_MBOX, !FIRMWARE_MAGIC);
    hardware.wait_firmware().unwrap();
    let (mut hardware, _) = identified(Asic::Bcm5762, 0);
    assert_eq!(hardware.wait_firmware(), Err(Error::FirmwareTimeout));
    assert_eq!(hardware.failure(), Some(Error::FirmwareTimeout));
}

#[test]
fn engine_stop_observes_each_ack_and_never_counts_timeout_as_silent_success() {
    let (mut hardware, m) = identified(Asic::Bcm5720, 0);
    for at in STOP_RX
        .into_iter()
        .chain(STOP_TX)
        .chain([MAC_TX_MODE, HOSTCC_MODE, WDMAC_MODE])
    {
        m.borrow_mut().mac.insert(at, ENABLE | 0x100);
    }
    hardware.stop_engines().unwrap();
    assert!(hardware.engines_stopped());
    assert_eq!(hardware.read_phy(2), Err(Error::Stopped));
    assert!(
        m.borrow()
            .trace
            .contains(&Event::Write(FTQ_RESET, u32::MAX))
    );
    for stuck in STOP_RX
        .into_iter()
        .chain(STOP_TX)
        .chain([MAC_TX_MODE, HOSTCC_MODE, WDMAC_MODE])
    {
        let (mut hardware, m) = identified(Asic::Bcm5720, 0);
        m.borrow_mut().mac.insert(stuck, ENABLE);
        m.borrow_mut().stuck_stop = Some(stuck);
        assert_eq!(hardware.stop_engines(), Err(Error::StopTimeout(stuck)));
        assert!(!hardware.engines_stopped());
        drop(hardware);
        assert_eq!(m.borrow().dropped, 0);
    }
}

#[test]
fn bcm5720_internal_port_comes_from_signed_sram_then_live_fallback() {
    for signature_valid in [false, true] {
        let (mut hardware, m) = model(Asic::Bcm5720, 0);
        m.borrow_mut().sram.insert(
            SRAM_CPMU_STATUS,
            if signature_valid {
                (3 << 30) | CPMU_STATUS
            } else {
                0
            },
        );
        m.borrow_mut().mac.insert(CPMU_STATUS, 2 << 30);
        let identity = hardware.identify().unwrap();
        assert_eq!(identity.bdf_function, 0);
        assert_eq!(identity.function, if signature_valid { 3 } else { 2 });
        assert_eq!(identity.phy_address, identity.function + 1);
        m.borrow_mut().trace.clear();
        hardware.read_phy(7).unwrap();
        assert!(m.borrow().trace.contains(&Event::ApeWrite(
            APE_PER_LOCK_REQ + u32::from(PHY_LOCKS[usize::from(identity.function)]) * 4,
            APE_DRIVER
        )));
    }
}

#[test]
fn initial_mac_access_follows_observed_config_word_swap_and_sram_arbiter() {
    let (mut hardware, m) = model(Asic::Bcm5720, 1);
    hardware.identify().unwrap();
    let m = m.borrow();
    let config = m
        .trace
        .iter()
        .position(|e| *e == Event::ConfigWrite(MISC_HOST_CTRL, 0xf000_0000 | HOST_ACCESS))
        .unwrap();
    let first_mac = m
        .trace
        .iter()
        .position(|e| matches!(e, Event::Read(..) | Event::Write(..)))
        .unwrap();
    assert!(config < first_mac);
    let arbiter = m
        .trace
        .iter()
        .position(|e| *e == Event::Write(MEMARB_MODE, ENABLE))
        .unwrap();
    let sram = m
        .trace
        .iter()
        .position(|e| *e == Event::Write(MEM_BASE, SRAM_CPMU_STATUS))
        .unwrap();
    assert!(arbiter < sram);
    let allow = m
        .trace
        .iter()
        .position(|e| *e == Event::ConfigWrite(PCISTATE, ALLOW_APE))
        .unwrap();
    let first_ape = m
        .trace
        .iter()
        .position(|e| matches!(e, Event::ApeWrite(..)))
        .unwrap();
    assert!(allow < first_ape);
    assert_eq!(
        m.trace
            .iter()
            .filter(|e| matches!(e, Event::ApeWrite(..)))
            .count(),
        8
    );
}
