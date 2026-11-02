//! GL9755 native kept-configuration and dual-rail regressions.
use super::*;
use crate::{bus::dma::TestRegion, sdhci::model::*};
use alloc::vec;

struct State {
    denied_read: Option<u16>,
    denied: bool,
    after_denial: usize,
    config: [u8; 4096],
    writes: Vec<(u16, u32)>,
    ignored: Option<u16>,
    power: Vec<(u8, u64)>,
    ocp: bool,
    ocp_on_clear: bool,
    ocp_on_signal: bool,
    ocp_on_tuning: bool,
    power_off_pending: bool,
    contained: bool,
    failed_power_off: bool,
    failed_vdd2: bool,
    dma: bool,
    normal_power_off: bool,
}
struct Config(Rc<RefCell<State>>);
impl ConfigSpace for Config {
    fn read32(&self, at: u16) -> Result<u32, crate::bus::pci::ConfigError> {
        if self.0.borrow().denied_read == Some(at) {
            self.0.borrow_mut().denied = true;
            return Err(crate::bus::pci::ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::Ownership(
                    crate::bus::pci::assignment::Error::Closed,
                ),
            ));
        }

        if self.0.borrow().denied {
            self.0.borrow_mut().after_denial += 1;
        }
        let value = {
            let at = usize::from(at);
            u32::from_le_bytes(self.0.borrow().config[at..at + 4].try_into().unwrap())
        };
        Ok(value)
    }
    fn write32(&mut self, at: u16, value: u32) -> Result<(), crate::bus::pci::ConfigError> {
        if self.0.borrow().denied {
            self.0.borrow_mut().after_denial += 1;
        }
        let mut s = self.0.borrow_mut();
        s.writes.push((at, value));
        if s.ignored == Some(at) {
            return Ok(());
        }
        if (0x10..=0x24).contains(&at) {
            assert_eq!(s.config[4] & 6, 0, "split BAR write with live decode/DMA");
        } else if at != 0x114 && at != 0x800 {
            assert_eq!(s.config[0x800] & 1, 1, "protected PCI write without WT");
        }
        let at = usize::from(at);
        s.config[at..at + 4].copy_from_slice(&value.to_le_bytes());

        Ok(())
    }
    fn write16(&mut self, at: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
        if self.0.borrow().denied {
            self.0.borrow_mut().after_denial += 1;
        }
        let mut s = self.0.borrow_mut();
        assert!(matches!(at, 4 | 0x94));
        s.writes.push((at, u32::from(value)));
        if s.ignored == Some(at) {
            return Ok(());
        }
        if at == 0x94 {
            assert_eq!(
                s.config[0x800] & 1,
                1,
                "source WT stays open through power transition"
            );
        }
        if at == 0x94 && value & 3 == 3 {
            assert_eq!(s.config[4] & 6, 0, "power transition with live BAR/DMA");
        }
        if at == 0x94 && value & 3 == 0 && s.config[0x94] & 3 == 3 {
            s.config[0x10..0x28].fill(0);
            s.config[4] |= 2; // D0 soft reset can preserve/restore memory decode.
        }
        let at = usize::from(at);
        s.config[at..at + 2].copy_from_slice(&value.to_le_bytes());

        Ok(())
    }
    fn write8(&mut self, _: u16, _: u8) -> Result<(), crate::bus::pci::ConfigError> {
        if self.0.borrow().denied {
            self.0.borrow_mut().after_denial += 1;
        }
        panic!("unexpected PCI byte write");
    }

    fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
        if self.0.borrow().denied {
            self.0.borrow_mut().after_denial += 1;
        }
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }

    fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
        if self.0.borrow().denied {
            self.0.borrow_mut().after_denial += 1;
        }
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }
}
struct Port55 {
    card: Rc<RefCell<Hardware>>,
    state: Rc<RefCell<State>>,
    function: Function<Config>,
}
fn clock() -> Clock {
    Clock {
        ticks_per_microsecond: CLOCK_TICKS_PER_US,
    }
}
impl Registers for Port55 {
    fn check_authority(&mut self) -> Result<(), BlockError> {
        let dma = self.state.borrow().dma;
        pci::runtime_configuration(&mut self.function, dma)?;
        Ok(())
    }
    fn configuration(&mut self) -> Result<&mut dyn ConfigSpace, BlockError> {
        let dma = self.state.borrow().dma;
        pci::runtime_configuration(&mut self.function, dma)
    }
    fn dma_ready(&mut self) -> Result<(), BlockError> {
        let mut enabled = self.state.borrow().dma;
        pci::dma_grant(&mut self.function, &mut enabled)?;
        self.state.borrow_mut().dma = enabled;
        Ok(())
    }
    fn read8(&mut self, at: usize) -> u8 {
        assert!(
            !self.state.borrow().contained,
            "MMIO read after electrical fence"
        );
        let value = Port(self.card.clone()).read8(at);
        if at == POWER && self.state.borrow().power_off_pending {
            self.state.borrow_mut().contained = true;
        }
        value
    }
    fn read16(&mut self, at: usize) -> u16 {
        assert!(
            !self.state.borrow().contained,
            "MMIO read after electrical fence"
        );
        Port(self.card.clone()).read16(at)
    }
    fn read32(&mut self, at: usize) -> u32 {
        assert!(
            !self.state.borrow().contained,
            "MMIO read after electrical fence"
        );
        Port(self.card.clone()).read32(at)
    }
    fn write8(&mut self, at: usize, value: u8) {
        if at == POWER && value == 0 && self.state.borrow().normal_power_off {
            assert_eq!(
                self.function.config().read32(PLL).unwrap() & (DIRECT | SSC_ENABLE),
                0,
                "normal rail-off before vendor PLL stopped"
            );
        }
        assert!(
            !self.state.borrow().contained,
            "MMIO write after electrical fence"
        );
        if at == RESET && value & RESET_ALL != 0 {
            assert_ne!(
                self.read16(CLOCK) & CLOCK_STABLE,
                0,
                "reset before internal stable clock"
            );
            assert_eq!(
                self.read16(HOST_CONTROL2),
                1 << 12,
                "reset before v4 admission"
            );
        }
        if at == POWER {
            let mut s = self.state.borrow_mut();
            let now = clock().now_us();
            if value & VDD2 != 0 {
                let &(last, started) = s.power.last().unwrap();
                assert_eq!(last, value & 15, "VDD2 before actual VDD1");
                assert!(now.wrapping_sub(started) >= 5_000, "VDD1 rail settling");
            }
            s.power.push((value, now));
            if value == 0 && s.ocp {
                s.power_off_pending = true;
            }
            if value == 0 && s.failed_power_off && s.ocp || value & VDD2 != 0 && s.failed_vdd2 {
                return;
            }
        }
        Port(self.card.clone()).write8(at, value);
    }
    fn write16(&mut self, at: usize, value: u16) {
        assert!(
            !self.state.borrow().contained,
            "MMIO write after electrical fence"
        );
        Port(self.card.clone()).write16(at, value);
        let mut s = self.state.borrow_mut();
        if at == HOST_CONTROL2 && value & SIGNAL_180 != 0 && s.ocp_on_signal {
            s.ocp_on_signal = false;
            s.ocp = true;
            self.card.borrow_mut().latch_status(BUS_POWER);
        }
        if at == COMMAND && value >> 8 == 19 && s.ocp_on_tuning {
            s.ocp_on_tuning = false;
            s.ocp = true;
            self.card.borrow_mut().latch_status(BUS_POWER);
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        assert!(
            !self.state.borrow().contained,
            "MMIO write after electrical fence"
        );
        if at == INTERRUPT {
            let mut s = self.state.borrow_mut();
            if s.ocp_on_clear {
                s.ocp_on_clear = false;
                s.ocp = true;
                self.card.borrow_mut().latch_status(BUS_POWER);
            }
            if value & BUS_POWER != 0 {
                s.ocp = false;
            }
        }
        Port(self.card.clone()).write32(at, value);
    }
}
fn port() -> (Port55, Rc<RefCell<Hardware>>, Rc<RefCell<State>>) {
    let mut config = [0u8; 4096];
    for (at, value) in [
        (0, ID),
        (4, 0x0010_0403),
        (8, 0x0805_0100),
        (0x10, 0x9000_0004),
        (0x44, 0xe000_7000),
        (0x70, 1 << 19),
        (0x100, 0x0002_0001),
    ] {
        config[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    config[0x34] = 0x90;
    config[0x90] = 1;
    config[0x91] = 0xb0;
    config[0xb0] = 0x10;
    config[0xb2] = 2;
    let state = Rc::new(RefCell::new(State {
        denied_read: None,
        denied: false,
        after_denial: 0,
        config,
        writes: Vec::new(),
        ignored: None,
        power: Vec::new(),
        ocp: false,
        ocp_on_clear: false,
        ocp_on_signal: false,
        ocp_on_tuning: false,
        power_off_pending: false,
        contained: false,
        failed_power_off: false,
        failed_vdd2: false,
        dma: false,
        normal_power_off: false,
    }));
    let function = Function::new(
        crate::bus::pci::Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        Config(state.clone()),
    )
    .unwrap();
    let card = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    {
        let mut c = card.borrow_mut();
        c.version = 4;
        c.caps = (c.caps & !0xff00) | 200 << 8;
    }
    (
        Port55 {
            card: card.clone(),
            state: state.clone(),
            function,
        },
        card,
        state,
    )
}
fn initialize_port(p: &mut Port55) -> Result<(), BlockError> {
    // Distinct MMIO peer shares only the original card register namespace;
    // the original Function is passed to the production initialization.
    struct Mmio(Rc<RefCell<Hardware>>);
    impl Registers for Mmio {
        fn read8(&mut self, a: usize) -> u8 {
            Port(self.0.clone()).read8(a)
        }
        fn read16(&mut self, a: usize) -> u16 {
            Port(self.0.clone()).read16(a)
        }
        fn read32(&mut self, a: usize) -> u32 {
            Port(self.0.clone()).read32(a)
        }
        fn write8(&mut self, a: usize, v: u8) {
            if a == RESET && v & RESET_ALL != 0 {
                assert_ne!(self.read16(CLOCK) & CLOCK_STABLE, 0);
                assert_eq!(self.read16(HOST_CONTROL2), 1 << 12);
            }
            Port(self.0.clone()).write8(a, v);
        }
        fn write16(&mut self, a: usize, v: u16) {
            Port(self.0.clone()).write16(a, v);
        }
        fn write32(&mut self, a: usize, v: u32) {
            Port(self.0.clone()).write32(a, v);
        }
    }
    initialize(
        &mut p.function,
        &mut Mmio(p.card.clone()),
        clock(),
        crate::sdhci::model::minimum().as_ref(),
    )
}
fn host(
    dma: &mut dyn DmaAllocator,
    uhs: bool,
    adma: bool,
) -> (Host, Rc<RefCell<Hardware>>, Rc<RefCell<State>>) {
    let (mut p, card, state) = port();
    if uhs {
        let mut c = card.borrow_mut();
        c.caps2 = CAP_SDR50 | CAP_SDR104;
        c.uhs_functions = 0x1f;
        c.scr[2] = 0x80; // Card declares SD3 before requesting S18R/UHS.
        c.max_current = 200;
    }
    if adma {
        card.borrow_mut().caps |= CAP_ADMA2 | 1 << 27;
    }
    initialize_port(&mut p).unwrap();
    let host = Host::new(
        Box::new(p),
        clock(),
        crate::sdhci::model::minimum(),
        "GL9755 actual source register/card peer".into(),
        dma,
        Profile::Gli9755,
    )
    .unwrap();
    (host, card, state)
}

#[test]
fn native_gl9755_original_pci_phy_power_cycle_and_two_rails_precede_real_pio() {
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let (mut host, card, state) = host(&mut dma, false, false);
    let c = Config(state.clone());
    assert_eq!(c.read32(0x10).unwrap(), 0x9000_0004);
    assert_eq!(
        c.read32(0x44).unwrap(),
        0xc000_0000,
        "retain real CD/WP inversion"
    );
    assert_eq!(c.read32(0x48).unwrap() & (31 << 24), 31 << 24);
    assert_eq!(c.read32(0x70).unwrap(), 0xfc00_00b3);
    assert_eq!(c.read32(0x6c).unwrap(), 1 << 27 | 1 << 18);
    assert_eq!(c.read32(SSC).unwrap() & 0xf900_0000, 0xc900_0000);
    assert_eq!(c.read32(0x800).unwrap() & 1, 0);
    let mut disk = host.poll().unwrap().unwrap();
    let mut bytes = [0xa5; 1024];
    disk.read(5, &mut bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[5 * 512..7 * 512]);
    bytes.fill(0x69);
    disk.write(7, &bytes).unwrap();
    disk.flush().unwrap();
    assert_eq!(bytes, card.borrow().disk[7 * 512..9 * 512]);
    let mut port = Port(card.clone());
    assert_eq!(port.read8(POWER), VDD2 | POWER_330 | POWER_ON);
    assert_eq!(port.read32(SIGNAL_ENABLE), 0);
    assert_ne!(port.read32(INTERRUPT_ENABLE) & BUS_POWER, 0);
    assert_eq!(
        host.inner.borrow().max_current_ma,
        0,
        "GL9750 current workaround must not leak to55"
    );
    state.borrow_mut().normal_power_off = true;
    disk.shutdown(true).unwrap();
    assert_eq!(port.read8(POWER), 0);
    assert_eq!(port.read32(INTERRUPT_ENABLE) & BUS_POWER, 0);
}

#[test]
fn native_gl9755_uhs_standard_tuning_pci_pll_and_v4_dma_transfer_payloads() {
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let (mut host, card, state) = host(&mut dma, true, true);
    let mut disk = host.poll().unwrap().unwrap();
    assert_eq!(host.inner.borrow().sd_timing, Timing::Sdr104);
    assert_eq!(host.inner.borrow().actual_hz, 205_000_000);
    assert_eq!(
        card.borrow().tuning_commands,
        3,
        "independent card needs three actual CMD19 iterations"
    );
    let c = Config(state.clone());
    assert_eq!(c.read32(PLL).unwrap() & (0x73ff | DIRECT), 0x246 | DIRECT);
    assert_eq!(c.read32(SSC).unwrap() & 0xffff, 0x5a1d);
    let mut bytes = vec![0xa5; 65536];
    disk.read(3, &mut bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[3 * 512..3 * 512 + 65536]);
    bytes.fill(0x5c);
    disk.write(200, &bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[200 * 512..200 * 512 + 65536]);
    assert!(state.borrow().dma);
    assert_eq!(host.inner.borrow().descriptors.read::<u32>(12), 0);
}

#[test]
fn native_gl9755_overcurrent_removes_both_rails_preserves_cleanup_and_fences_aliases() {
    for failed_cleanup in [false, true] {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut host, card, state) = host(&mut dma, false, false);
        let mut disk = host.poll().unwrap().unwrap();
        let mut alias = disk.clone();
        state.borrow_mut().ocp = true;
        card.borrow_mut().latch_status(BUS_POWER);
        state.borrow_mut().failed_power_off = failed_cleanup;
        let commands = card.borrow().commands.len();
        let mut poison = [0xa5; 512];
        let primary = disk.read(0, &mut poison).unwrap_err();
        assert_eq!(poison, [0xa5; 512]);
        assert_eq!(commands, card.borrow().commands.len());
        assert!(matches!(primary, BlockError::Device { status } if status & BUS_POWER != 0));
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, primary);
        assert!(failure.quarantined);
        assert_eq!(failure.restoration.is_some(), failed_cleanup);
        if !failed_cleanup {
            assert_eq!(Port(card.clone()).read8(POWER), 0);
        }
        let writes = card.borrow().writes.len();
        assert_eq!(alias.flush_cache(), Err(BlockError::Unsupported(STALE)));
        assert_eq!(host.poll().err(), Some(primary));
        assert_eq!(writes, card.borrow().writes.len());
    }
}

#[test]
fn native_gl9755_refused_pci_pll_and_vdd2_ack_never_publish_card_commands() {
    for power in [false, true] {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut p, card, state) = port();
        initialize_port(&mut p).unwrap();
        if power {
            state.borrow_mut().failed_vdd2 = true;
        } else {
            state.borrow_mut().ignored = Some(PLL);
            state.borrow_mut().config[usize::from(PLL) + 1] |= 0x80;
        }
        assert!(
            Host::new(
                Box::new(p),
                clock(),
                crate::sdhci::model::minimum(),
                "refused55".into(),
                &mut dma,
                Profile::Gli9755
            )
            .is_err()
        );
        assert!(card.borrow().commands.is_empty());
        assert_eq!(Port(card.clone()).read8(POWER), 0);
        assert_eq!(Config(state).read32(0x800).unwrap() & 1, 0);
    }
}

#[test]
fn native_gl9755_runtime_original_requester_epoch_and_active_uhs2_refuse_before_writes() {
    let (mut p, card, state) = port();
    initialize_port(&mut p).unwrap();
    for mutation in [0, 1, 2] {
        let saved = state.borrow().config;
        match mutation {
            0 => state.borrow_mut().config[0] ^= 1,
            1 => state.borrow_mut().config[0x94] = 3,
            _ => state.borrow_mut().config[4] |= 4,
        }
        let writes = state.borrow().writes.len();
        assert!(p.configuration().is_err());
        assert_eq!(writes, state.borrow().writes.len());
        state.borrow_mut().config = saved;
    }
    Port(card.clone()).write16(HOST_CONTROL2, 1 << 8 | 1 << 12);
    let writes = card.borrow().writes.len();
    assert!(before_reset(&mut p, clock(), RESET_ALL).is_err());
    assert_eq!(writes, card.borrow().writes.len());
}

#[test]
fn native_gl9755_single_ocp_latch_at_w1c_boundary_cannot_be_lost_before_command() {
    for tuning in [false, true] {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut host, card, state) = host(&mut dma, tuning, false);
        let mut disk = host.poll().unwrap().unwrap();
        let commands = card.borrow().commands.len();
        state.borrow_mut().ocp_on_clear = true;
        let primary = if tuning {
            host.inner.borrow_mut().tune().unwrap_err()
        } else {
            let mut poison = [0xa5; 512];
            let primary = disk.read(0, &mut poison).unwrap_err();
            assert_eq!(poison, [0xa5; 512]);
            primary
        };
        assert!(matches!(primary, BlockError::Device { status } if status & BUS_POWER != 0));
        assert_eq!(
            card.borrow().commands.len(),
            commands,
            "no command after asynchronous latch at W1C"
        );
        assert!(
            state.borrow().contained,
            "one actual latch reached rail-off fence"
        );
        assert_eq!(Port(card.clone()).read8(POWER), 0);
        assert_ne!(
            Port(card.clone()).read32(INTERRUPT) & BUS_POWER,
            0,
            "actual Port W1C did not consume the power event"
        );
        assert_eq!(host.last_failure().unwrap().primary, primary);
    }
}

#[test]
fn gl9755_overcurrent_keeps_first_failure() {
    for tuning in [false, true] {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut host, card, state) = host(&mut dma, true, false);
        state.borrow_mut().ocp_on_signal = !tuning;
        state.borrow_mut().ocp_on_tuning = tuning;
        state.borrow_mut().failed_power_off = true;
        let primary = host.poll().err().unwrap();
        assert!(matches!(primary, BlockError::Device { status } if status & BUS_POWER != 0));
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, primary);
        assert!(failure.restoration.is_some());
        assert!(failure.quarantined);
        assert!(
            state.borrow().contained,
            "model rejects every later controller access"
        );
        assert_eq!(
            state
                .borrow()
                .power
                .iter()
                .rev()
                .take_while(|(v, _)| *v == 0)
                .count(),
            1,
            "no repeated cleanup hides the first failure"
        );
        assert_eq!(card.borrow().tuning_commands, usize::from(tuning));
        let reads = card.borrow().reads;
        let writes = card.borrow().writes.len();
        assert_eq!(host.poll().err(), Some(primary));
        assert_eq!(
            (card.borrow().reads, card.borrow().writes.len()),
            (reads, writes)
        );
    }
}

#[test]
fn gl9755_lost_pci_state_fences_without_mmio() {
    for mutation in 0..5 {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut host, card, state) = host(&mut dma, false, false);
        let mut disk = host.poll().unwrap().unwrap();
        match mutation {
            0 => state.borrow_mut().config[0] ^= 1,
            1 => state.borrow_mut().config[0x94] = 3,
            2 => state.borrow_mut().config[4] &= !2,
            3 => state.borrow_mut().config[4] |= 4,
            _ => {
                let mut s = state.borrow_mut();
                s.config[0xb1] = 0xe0;
                s.config[0xe0] = 5;
                s.config[0xe2] = 1;
            }
        }
        let reads = card.borrow().reads;
        let writes = card.borrow().writes.len();
        let primary = host.inner.borrow_mut().set_clock(50_000_000).unwrap_err();
        assert!(host.last_failure().unwrap().quarantined);
        assert_eq!(
            (card.borrow().reads, card.borrow().writes.len()),
            (reads, writes),
            "lost authority never authorizes cleanup on the stale BAR"
        );
        assert_eq!(disk.flush_cache(), Err(BlockError::Unsupported(STALE)));
        assert_eq!(host.poll().err(), Some(primary));
        assert_eq!(
            (card.borrow().reads, card.borrow().writes.len()),
            (reads, writes)
        );
    }
}

#[test]
#[ignore = "oracle: STELA_SDHCI_GLI55_ORACLE"]
fn unchanged_linux_gl9755_phy_pll_dual_rail_and_reset_functions_match_native() {
    extern crate std;
    let records = std::fs::read_to_string(
        std::env::var("STELA_SDHCI_GLI55_ORACLE").expect("pinned GL9755 source records"),
    )
    .unwrap();
    let mut count = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let number = |i: usize| fields[i].parse::<u32>().unwrap();
        let (mut p, card, state) = port();
        match fields[0] {
            "P" => {
                let seed = number(1);
                for at in [0x800, 0x44, 0x48, 0x64, 0x68, 0x6c, 0x70, 0x78] {
                    state.borrow_mut().config[at..at + 4].copy_from_slice(&seed.to_le_bytes());
                }
                initialize_port(&mut p).unwrap();
                for (i, at) in [0x800, 0x44, 0x48, 0x64, 0x68, 0x6c, 0x70, 0x78]
                    .into_iter()
                    .enumerate()
                {
                    assert_eq!(
                        p.function.config().read32(at).unwrap(),
                        number(i + 2),
                        "{line}"
                    );
                }
            }
            "C" => {
                let seed = number(1);
                for at in [0x800, 0x64, 0x68, 0x78] {
                    state.borrow_mut().config[at..at + 4].copy_from_slice(&seed.to_le_bytes());
                }
                let policy = (seed & !(1 << 26)) | number(2) << 26;
                state.borrow_mut().config[0x78..0x7c].copy_from_slice(&policy.to_le_bytes());
                let timing = match number(3) {
                    3 => Timing::Sdr12,
                    4 => Timing::Sdr25,
                    5 => Timing::Sdr50,
                    6 => Timing::Sdr104,
                    _ => unreachable!(),
                };
                let hz = number(4);
                // Shared MMC asks for208MHz; Linux clamps host hook to200MHz.
                let request = if hz == 200_000_000 && timing == Timing::Sdr104 {
                    208_000_000
                } else {
                    hz
                };
                let actual = set_clock(
                    &mut p,
                    clock(),
                    2,
                    200_000_000,
                    timing,
                    request,
                    crate::sdhci::model::minimum().as_ref(),
                )
                .unwrap();
                assert_eq!(actual, number(5), "{line}");
                assert_eq!(
                    p.function.config().read32(PLL).unwrap(),
                    number(6),
                    "{line}"
                );
                assert_eq!(
                    p.function.config().read32(SSC).unwrap(),
                    number(7),
                    "{line}"
                );
                assert_eq!(u32::from(p.read16(CLOCK)), number(8), "{line}");
            }
            "W" => {
                p.write32(INTERRUPT_ENABLE, 0x1234_5678);
                let off = number(2) != 0;
                set_power(
                    &mut p,
                    crate::sdhci::model::minimum().as_ref(),
                    if off { 0 } else { number(1) as u8 },
                )
                .unwrap();
                let state = state.borrow();
                let writes = number(3) as usize;
                assert_eq!(state.power.len(), writes, "{line}");
                let began = state.power[0].1;
                for (i, &(value, at)) in state.power.iter().enumerate() {
                    assert_eq!(u32::from(value), number(4 + 2 * i), "{line}");
                    assert!(
                        at.wrapping_sub(began) >= u64::from(number(5 + 2 * i)) * 1_000,
                        "{line}"
                    );
                }
                assert_eq!(p.read32(INTERRUPT_ENABLE), number(5 + 2 * writes), "{line}");
                assert_eq!(
                    p.read32(SIGNAL_ENABLE),
                    0,
                    "native polled source has no CPU IRQ route"
                );
            }
            "R" => {
                before_reset(&mut p, clock(), number(1) as u8).unwrap();
                assert_eq!(number(2), 1, "one source actual reset store");
                assert_eq!(
                    u32::from(p.read16(CLOCK)) & !u32::from(CLOCK_STABLE),
                    number(3) & !u32::from(CLOCK_STABLE),
                    "{line}"
                );
                assert_eq!(u32::from(p.read16(HOST_CONTROL2)), number(4), "{line}");
                p.write8(RESET, number(1) as u8);
                assert_eq!(p.read8(RESET), 0);
                assert_eq!(card.borrow().writes.last().unwrap().0, RESET);
            }
            _ => panic!("unqualified source record {line}"),
        }
        count += 1;
    }
    assert_eq!(count, 206);
}

#[test]
fn failed_d3_quiet_interval_never_reenters_d0_or_closes_the_window() {
    struct Failed;
    // SAFETY: test-only failure injection, no native timing grant.
    unsafe impl crate::bus::pci::power::Timer for Failed {
        fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
            Ok(())
        }
        fn wait_us(&self, _: u64) -> Result<(), crate::bus::pci::power::Error> {
            Err(crate::bus::pci::power::Error::Clock)
        }
    }
    let (mut p, card, state) = port();
    assert_eq!(
        initialize(&mut p.function, &mut Port(card), clock(), &Failed),
        Err(BlockError::PciPower(crate::bus::pci::power::Error::Clock))
    );
    let state = state.borrow();
    assert_eq!(
        state.writes.last(),
        Some(&(0x94, 3)),
        "no readback, D0 write or window cleanup follows failed minimum"
    );
    assert_eq!(state.config[0x94] & 3, 3);
    assert_eq!(state.config[0x800] & 1, 1);
}

#[test]
fn protected_config_denial_is_authority_and_stops_all_outer_cleanup() {
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let (mut host, card, state) = host(&mut dma, false, false);
    state.borrow_mut().denied_read = Some(PLL);
    let before = (card.borrow().reads, card.borrow().writes.len());
    let error = host.inner.borrow_mut().set_clock(50_000_000).unwrap_err();
    assert!(matches!(error, BlockError::Config(_)));
    assert_eq!(
        state.borrow().after_denial,
        0,
        "no protected-window close or outer permission observation"
    );
    assert_eq!(
        (card.borrow().reads, card.borrow().writes.len()),
        before,
        "no CLOCK/HOST_CONTROL2 power-off cleanup"
    );
    let before = state.borrow().writes.len();
    assert_eq!(host.poll().err(), Some(error));
    assert_eq!(state.borrow().writes.len(), before);
}
