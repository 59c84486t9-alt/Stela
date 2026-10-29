//! GL9767 native kept-configuration, ordinary SD and failure regressions.
use super::*;
use crate::{bus::dma::RegionAllocator, storage::sdhci::model::*};
use alloc::{collections::BTreeMap, vec};

struct State {
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
    failed_vdd1: bool,
    dma: bool,
    normal_power_off: bool,
    reset_delay_us: u64,
    reset_started: Option<u64>,
    fail_mmio_after: Option<usize>,
    unavailable: Option<usize>,
    lose_power_on_ocp_clock: bool,
    words: BTreeMap<usize, u32>,
    reset_ack_poll: Option<usize>,
    reset_reads: usize,
}
fn vendor_read(card: &Rc<RefCell<Hardware>>, state: &Rc<RefCell<State>>, at: usize) -> u32 {
    card.borrow_mut().reads += 1;
    let state = state.borrow();
    if state.unavailable == Some(at) {
        u32::MAX
    } else {
        *state.words.get(&at).unwrap_or(&0)
    }
}
fn vendor_write(card: &Rc<RefCell<Hardware>>, state: &Rc<RefCell<State>>, at: usize, value: u32) {
    card.borrow_mut().writes.push((at, 4, value));
    let mut state = state.borrow_mut();
    state.words.insert(at, value);
    if state.fail_mmio_after == Some(at) {
        state.unavailable = Some(at);
    }
}
struct Config(Rc<RefCell<State>>);
impl ConfigSpace for Config {
    fn read32(&self, at: u16) -> u32 {
        let mut state = self.0.borrow_mut();
        let index = usize::from(at);
        let value = u32::from_le_bytes(state.config[index..index + 4].try_into().unwrap());
        if at == 0x8e4
            && let Some(started) = state.reset_started
        {
            state.reset_reads += 1;
            let pending = if let Some(ack) = state.reset_ack_poll {
                state.reset_reads < ack
            } else {
                clock().now_us().wrapping_sub(started) < state.reset_delay_us
            };
            return (value & !1) | u32::from(pending);
        }
        value
    }
    fn write32(&mut self, at: u16, value: u32) {
        let mut s = self.0.borrow_mut();
        s.writes.push((at, value));
        if s.ignored == Some(at) {
            return;
        }
        if at == 0x8e4 {
            s.reset_started = Some(clock().now_us());
            s.reset_reads = 0;
        }
        if (0x10..=0x24).contains(&at) {
            assert_eq!(s.config[4] & 6, 0, "split BAR write with live decode/DMA");
        } else if at != 0x114 && at != 0x884 {
            assert_eq!(s.config[0x886] & 15, 2, "protected PCI write without VHS");
        }
        let at = usize::from(at);
        s.config[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn write16(&mut self, at: u16, value: u16) {
        let mut s = self.0.borrow_mut();
        assert!(matches!(at, 4 | 0x94));
        s.writes.push((at, u32::from(value)));
        if s.ignored == Some(at) {
            return;
        }
        if at == 0x94 {
            assert_eq!(s.config[0x886] & 15, 2, "source VHS power window");
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
    }
    fn write8(&mut self, _: u16, _: u8) {
        panic!("unexpected PCI byte write");
    }
}
struct Port67 {
    card: Rc<RefCell<Hardware>>,
    state: Rc<RefCell<State>>,
    function: Function<Config>,
}
fn clock() -> Clock {
    Clock {
        ticks_per_microsecond: CLOCK_TICKS_PER_US,
    }
}
impl Registers for Port67 {
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
        if at == POWER && value != 0 && self.state.borrow().power_off_pending {
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
        if at >= 0x500 {
            return vendor_read(&self.card, &self.state, at);
        }
        if self.state.borrow().unavailable == Some(at) {
            return u32::MAX;
        }
        let value = Port(self.card.clone()).read32(at);
        if at == INTERRUPT_ENABLE && self.state.borrow().power_off_pending && value & BUS_POWER != 0
        {
            self.state.borrow_mut().contained = true;
        }
        value
    }
    fn write8(&mut self, at: usize, value: u8) {
        if at == POWER && value == 0 && self.state.borrow().normal_power_off {
            assert_eq!(
                self.function.config().read32(PLL) & (DIRECT | SPREAD),
                0,
                "normal rail-off before vendor PLL stopped"
            );
            assert_eq!(
                self.function.config().read32(0x8a0) & (1 << 12),
                0,
                "normal rail-off before low-power negotiation restored"
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
            s.power.push((value, now));
            if value == 0 && s.ocp {
                s.power_off_pending = true;
            }
            if value == 0 && s.failed_power_off && s.ocp || value & POWER_ON != 0 && s.failed_vdd1 {
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
        if at == CLOCK && value == 0 && s.ocp && s.lose_power_on_ocp_clock {
            s.config[0x94] = 3;
            s.contained = true;
        }
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
        if at >= 0x500 {
            vendor_write(&self.card, &self.state, at, value);
            return;
        }
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
        if self.state.borrow().fail_mmio_after == Some(at) {
            self.state.borrow_mut().unavailable = Some(at);
        }
    }
}
fn port() -> (Port67, Rc<RefCell<Hardware>>, Rc<RefCell<State>>) {
    let mut config = [0u8; 4096];
    for (at, value) in [
        (0, ID),
        (4, 0x0010_0403),
        (8, 0x0805_0100),
        (0x10, 0x9000_0004),
        (0x44, 0xe000_7000),
        (0x70, 1 << 19),
        (0x8e4, 1),
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
        failed_vdd1: false,
        dma: false,
        normal_power_off: false,
        reset_delay_us: 0,
        reset_started: None,
        fail_mmio_after: None,
        unavailable: None,
        lose_power_on_ocp_clock: false,
        words: BTreeMap::new(),
        reset_ack_poll: None,
        reset_reads: 0,
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
        Port67 {
            card: card.clone(),
            state: state.clone(),
            function,
        },
        card,
        state,
    )
}
fn initialize_port(p: &mut Port67) -> Result<(), BlockError> {
    // Distinct MMIO peer shares only the original card register namespace;
    // the original Function is passed to the production initialization.
    struct Mmio(Rc<RefCell<Hardware>>, Rc<RefCell<State>>);
    impl Registers for Mmio {
        fn read8(&mut self, a: usize) -> u8 {
            Port(self.0.clone()).read8(a)
        }
        fn read16(&mut self, a: usize) -> u16 {
            Port(self.0.clone()).read16(a)
        }
        fn read32(&mut self, a: usize) -> u32 {
            if a >= 0x500 {
                vendor_read(&self.0, &self.1, a)
            } else {
                Port(self.0.clone()).read32(a)
            }
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
            if a >= 0x500 {
                vendor_write(&self.0, &self.1, a, v);
            } else {
                Port(self.0.clone()).write32(a, v);
            }
        }
    }
    initialize(
        &mut p.function,
        &mut Mmio(p.card.clone(), p.state.clone()),
        clock(),
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
        "GL9767 actual source register/card peer".into(),
        dma,
        Profile::Gli9767,
    )
    .unwrap();
    (host, card, state)
}

#[test]
fn native_gl9767_source_phy_reset_debounce_pio_and_shutdown_use_original_config() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: original model buffers remain alive for every card alias.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, state) = host(&mut dma, false, false);
    let config = Config(state.clone());
    assert_eq!(config.read32(0x8d0), 0x3000_700f);
    assert_eq!(config.read32(0x8e0), 1 << 21 | 3 << 9 | 3 << 6);
    assert_eq!(config.read32(0x90c), 3 << 29);
    assert_eq!(config.read32(0x95c), 1 << 25 | 15 << 11 | 3 << 7 | 3 << 5);
    assert_eq!(config.read32(0x964), 0x4b);
    assert_eq!(config.read32(VHS) & (15 << 16), 0);
    let mut disk = host.poll().unwrap().unwrap();
    let mut bytes = [0xa5; 1024];
    disk.read(7, &mut bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[7 * 512..9 * 512]);
    bytes.fill(0x78);
    disk.write(10, &bytes).unwrap();
    disk.flush().unwrap();
    assert_eq!(bytes, card.borrow().disk[10 * 512..12 * 512]);
    assert_eq!(
        *state.borrow().words.get(&HOST_OPERATION).unwrap() & (255 << 16),
        5 << 16 | 2 << 22
    );
    assert_eq!(
        Port(card.clone()).read8(POWER),
        POWER_330 | POWER_ON,
        "ordinary SD never enables UHS-II rail"
    );
    state.borrow_mut().normal_power_off = true;
    disk.shutdown(true).unwrap();
    assert_eq!(Port(card.clone()).read8(POWER), 0);
    assert_eq!(config.read32(0x944) & (1 << 5 | 1 << 8), 0);
    assert_ne!(Port(card.clone()).read32(INTERRUPT_ENABLE) & BUS_POWER, 0);
}

#[test]
fn native_gl9767_uhs_clock_negotiation_and_v4_dma_have_real_payloads() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: model RAM backs every descriptor and payload transfer.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, state) = host(&mut dma, true, true);
    let mut disk = host.poll().unwrap().unwrap();
    assert_eq!(host.inner.borrow().sd_timing, Timing::Sdr104);
    assert_eq!(host.inner.borrow().actual_hz, 205_000_000);
    assert_eq!(card.borrow().tuning_commands, 3);
    let config = Config(state.clone());
    assert_eq!(config.read32(PLL) & (0xf3ff | DIRECT), 0x246 | DIRECT);
    assert_eq!(config.read32(PLL) & (31 << 24), 31 << 24);
    assert_eq!(config.read32(SSC) >> 16, 0xf5c3);
    assert_eq!(config.read32(0x8a0) & (1 << 12), 0);
    let mut bytes = vec![0xa5; 65536];
    disk.read(3, &mut bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[3 * 512..3 * 512 + 65536]);
    bytes.fill(0x6e);
    disk.write(200, &bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[200 * 512..200 * 512 + 65536]);
    assert!(state.borrow().dma);
    state.borrow_mut().normal_power_off = true;
    disk.shutdown(true).unwrap();
    assert_eq!(config.read32(PLL) & (DIRECT | SPREAD), 0);
    assert_eq!(config.read32(0x8a0) & (1 << 12), 0);
}

#[test]
fn native_gl9767_active_sd_express_or_refused_pci_reset_never_starts_sd_commands() {
    for express in [false, true] {
        let (mut port, card, state) = port();
        if express {
            state.borrow_mut().config[0x940] = 2;
        } else {
            state.borrow_mut().ignored = Some(0x8e4);
        }
        assert!(initialize_port(&mut port).is_err());
        assert!(card.borrow().commands.is_empty());
        assert!(!card.borrow().writes.iter().any(|(at, _, _)| *at == RESET));
        assert_eq!(Config(state).read32(VHS) & (15 << 16), 0);
    }
}

#[test]
fn native_gl9767_observed_removal_changes_debounce_and_fences_every_old_alias() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: independent removable-card model keeps all original buffers.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, state) = host(&mut dma, false, false);
    let mut disk = host.poll().unwrap().unwrap();
    card.borrow_mut().present = false;
    assert!(host.poll().unwrap().is_none());
    assert_eq!(
        *state.borrow().words.get(&HOST_OPERATION).unwrap() & (255 << 16),
        63 << 16 | 3 << 22
    );
    let accesses = (card.borrow().reads, card.borrow().writes.len());
    assert_eq!(disk.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
}

#[test]
fn native_gl9767_delayed_pci_ahb_reset_ack_precedes_sdhci_reset_and_timeout_refuses_it() {
    for delay in [1, 2, 3, 4, 50_000] {
        let (mut port, card, state) = port();
        state.borrow_mut().reset_delay_us = delay;
        let result = initialize_port(&mut port);
        if delay <= 4 {
            result.unwrap();
            assert!(card.borrow().writes.iter().any(|(at, _, _)| *at == RESET));
        } else {
            assert_eq!(result, Err(BlockError::Timeout));
            assert!(!card.borrow().writes.iter().any(|(at, _, _)| *at == RESET));
        }
        assert_eq!(Config(state).read32(VHS) & (15 << 16), 0);
    }
}

#[test]
fn native_gl9767_pio_flush_and_reset_reject_express_or_lost_power_decode_without_controller_access()
{
    for mutation in 0..4 {
        for reset in [false, true] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: revoked original owner keeps every descriptor and payload range.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut host, card, state) = host(&mut dma, false, false);
            let mut disk = host.poll().unwrap().unwrap();
            let mut alias = disk.clone();
            match mutation {
                0 => state.borrow_mut().config[0x940] = 1,
                1 => state.borrow_mut().config[0x940] = 2,
                2 => state.borrow_mut().config[0x94] = 3,
                _ => state.borrow_mut().config[4] &= !2,
            }
            let accesses = (card.borrow().reads, card.borrow().writes.len());
            if reset {
                assert!(
                    host.inner
                        .borrow_mut()
                        .reset(RESET_COMMAND | RESET_DATA)
                        .is_err()
                );
            } else {
                let mut poison = [0xa5; 512];
                assert!(disk.read(0, &mut poison).is_err());
                assert_eq!(poison, [0xa5; 512]);
            }
            assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
            assert!(host.last_failure().unwrap().quarantined);
            assert_eq!(alias.flush_cache(), Err(BlockError::Unsupported(STALE)));
            assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
        }
    }
}

#[test]
fn native_gl9767_one_ocp_latch_at_command_clear_contains_power_once_and_preserves_failure() {
    for failure in [false, true] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all original RAM remains held after permanent overcurrent fencing.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, card, state) = host(&mut dma, false, false);
        let mut disk = host.poll().unwrap().unwrap();
        state.borrow_mut().ocp_on_clear = true;
        state.borrow_mut().failed_power_off = failure;
        let commands = card.borrow().commands.len();
        let mut poison = [0xa5; 512];
        let primary = disk.read(0, &mut poison).unwrap_err();
        assert!(matches!(primary, BlockError::Device { status } if status & BUS_POWER != 0));
        assert_eq!(poison, [0xa5; 512]);
        assert_eq!(commands, card.borrow().commands.len());
        assert!(state.borrow().contained);
        let retained = host.last_failure().unwrap();
        assert_eq!(retained.primary, primary);
        assert_eq!(retained.restoration.is_some(), failure);
        assert!(retained.quarantined);
        let accesses = (card.borrow().reads, card.borrow().writes.len());
        assert!(host.poll().is_err());
        assert_eq!(disk.flush_cache(), Err(BlockError::Unsupported(STALE)));
        assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
    }
}

#[test]
fn native_gl9767_absent_card_debounce_never_accepts_allones_after_effect_readback() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: vanished-controller admission keeps its original model RAM and aliases.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, state) = host(&mut dma, false, false);
    let mut disk = host.poll().unwrap().unwrap();
    card.borrow_mut().present = false;
    state.borrow_mut().fail_mmio_after = Some(HOST_OPERATION);
    assert!(host.poll().is_err());
    assert!(host.inner.borrow().medium.is_none());
    assert!(host.inner.borrow().fault.is_some());
    assert!(
        card.borrow()
            .writes
            .iter()
            .any(|(at, _, value)| *at == HOST_OPERATION && value & (255 << 16) == 255 << 16)
    );
    let accesses = (card.borrow().reads, card.borrow().writes.len());
    assert_eq!(disk.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert!(host.poll().is_err());
    assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
}

#[test]
fn native_gl9767_ocp_primary_survives_secondary_power_authority_loss_without_stale_mmio() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: the lost native power epoch keeps every original model DMA allocation.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, state) = host(&mut dma, false, false);
    let mut disk = host.poll().unwrap().unwrap();
    state.borrow_mut().ocp_on_clear = true;
    state.borrow_mut().lose_power_on_ocp_clock = true;
    let mut poison = [0xa5; 512];
    let primary = disk.read(0, &mut poison).unwrap_err();
    assert!(matches!(primary, BlockError::Device { status } if status & BUS_POWER != 0));
    assert_eq!(poison, [0xa5; 512]);
    let failure = host.last_failure().unwrap();
    assert_eq!(failure.primary, primary);
    assert!(matches!(
        failure.restoration,
        Some(BlockError::Unsupported(_))
    ));
    assert!(state.borrow().contained);
    let accesses = (card.borrow().reads, card.borrow().writes.len());
    assert_eq!(host.poll().err(), Some(primary));
    assert_eq!(disk.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
}

#[test]
#[ignore = "oracle: STELA_SDHCI_GLI67_ORACLE"]
fn unchanged_linux_gl9767_phy_clock_power_and_stronger_observed_reset_ack_match_native() {
    extern crate std;
    let records = std::fs::read_to_string(
        std::env::var("STELA_SDHCI_GLI67_ORACLE").expect("pinned GL9767 records"),
    )
    .unwrap();
    let mut cases = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let number = |i: usize| fields[i].parse::<u32>().unwrap();
        let (mut port, card, state) = port();
        match fields[0] {
            "P" => {
                let seed = number(1);
                let addresses = [
                    0x884, 0x888, 0x8a0, 0x8d0, 0x8e0, 0x90c, 0x938, 0x93c, 0x944, 0x948, 0x95c,
                    0x964,
                ];
                for at in addresses {
                    state.borrow_mut().config[at..at + 4].copy_from_slice(&seed.to_le_bytes());
                }
                state.borrow_mut().words.insert(HOST_OPERATION, seed);
                state.borrow_mut().words.insert(0x510, seed);
                card.borrow_mut().present = number(2) != 0;
                initialize_port(&mut port).unwrap();
                for (i, at) in addresses.into_iter().enumerate() {
                    assert_eq!(
                        port.function.config().read32(at as u16),
                        number(i + 3),
                        "{line}"
                    );
                }
                assert_eq!(port.read32(HOST_OPERATION), number(15), "{line}");
                assert_eq!(port.read32(0x510), number(16), "{line}");
            }
            "C" => {
                let seed = number(1);
                for at in [VHS, PLL, SSC, 0x8a0] {
                    let at = usize::from(at);
                    state.borrow_mut().config[at..at + 4].copy_from_slice(&seed.to_le_bytes());
                }
                let mailbox = (seed & !2) | number(2) << 1;
                state.borrow_mut().config[0x888..0x88c].copy_from_slice(&mailbox.to_le_bytes());
                let timing = match number(3) {
                    3 => Timing::Sdr12,
                    4 => Timing::Sdr25,
                    5 => Timing::Sdr50,
                    6 => Timing::Sdr104,
                    _ => unreachable!(),
                };
                let requested = if number(4) == 200_000_000 && timing == Timing::Sdr104 {
                    208_000_000
                } else {
                    number(4)
                };
                let actual =
                    set_clock(&mut port, clock(), 2, 200_000_000, timing, requested).unwrap();
                assert_eq!(actual, number(5), "{line}");
                assert_eq!(port.function.config().read32(PLL), number(6), "{line}");
                assert_eq!(port.function.config().read32(SSC), number(7), "{line}");
                assert_eq!(u32::from(port.read16(CLOCK)), number(8), "{line}");
                assert_eq!(port.function.config().read32(0x8a0), number(9), "{line}");
            }
            "W" => {
                port.write32(INTERRUPT_ENABLE, 0x1234_5678);
                state.borrow_mut().config[0x944..0x948].copy_from_slice(&0x55ffu32.to_le_bytes());
                set_power(&mut port, if number(2) != 0 { 0 } else { number(1) as u8 }).unwrap();
                let writes = number(3) as usize;
                assert_eq!(state.borrow().power.len(), writes, "{line}");
                for (i, &(value, _)) in state.borrow().power.iter().enumerate() {
                    assert_eq!(u32::from(value), number(4 + i), "{line}");
                }
                assert_eq!(port.read32(INTERRUPT_ENABLE), number(4 + writes), "{line}");
                assert_eq!(
                    port.function.config().read32(0x944),
                    number(5 + writes),
                    "{line}"
                );
                assert_eq!(
                    port.read32(SIGNAL_ENABLE),
                    0,
                    "native polling has no CPU IRQ route"
                );
            }
            "A" => {
                // The unchanged donor aliases PCI's int status with the out
                // register value: returnstatus0 makes its condition succeed.
                // Stela requires the register ACK and refuses poll6.
                assert_eq!((number(2), number(3)), (1, 1), "donor status alias {line}");
                state.borrow_mut().reset_ack_poll = Some(number(1) as usize);
                let result = initialize_port(&mut port);
                assert_eq!(result.is_ok(), number(1) <= 5);
                let reset_stores = card
                    .borrow()
                    .writes
                    .iter()
                    .filter(|(at, _, _)| *at == RESET)
                    .count();
                assert_eq!(reset_stores, usize::from(number(1) <= 5));
            }
            "D" => {
                state.borrow_mut().reset_ack_poll = Some(number(1) as usize);
                let result = pci_reset(port.function.config(), clock());
                let expected = fields[2].parse::<i32>().unwrap();
                assert_eq!(result.is_ok(), expected == 0, "{line}");
                assert_eq!(state.borrow().reset_reads, number(3) as usize, "{line}");
                assert_eq!(
                    number(4),
                    number(3),
                    "one source1us delay precedes each poll"
                );
            }
            _ => panic!("unqualified GL9767 source record {line}"),
        }
        cases += 1;
    }
    assert_eq!(cases, 218);
}
