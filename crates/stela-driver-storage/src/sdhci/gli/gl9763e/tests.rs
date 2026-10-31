//! GL9763E original-controller and embedded-MMC regressions.
use super::*;
use crate::{bus::dma::TestRegion, sdhci::model::*};
use alloc::{collections::BTreeMap, vec};

struct State {
    config: [u8; 4096],
    words: BTreeMap<usize, u32>,
    events: Vec<(u8, usize, u32)>,
    halt_stuck: bool,
    ignore_pci: Option<u16>,
    ignore_mmio: Option<usize>,
    ignore_mode: Option<u16>,
    lose_identity_on_pci: Option<u16>,
    cd_low: bool,
    dma: bool,
}
struct Config(Rc<RefCell<State>>);
impl ConfigSpace for Config {
    fn read32(&self, at: u16) -> u32 {
        let at = usize::from(at);
        u32::from_le_bytes(self.0.borrow().config[at..at + 4].try_into().unwrap())
    }
    fn write32(&mut self, at: u16, value: u32) {
        let mut s = self.0.borrow_mut();
        s.events.push((0, usize::from(at), value));
        if s.ignore_pci == Some(at) {
            return;
        }
        if at != VHS {
            assert_eq!(
                s.config[0x886] & 15,
                2,
                "protected PCI write outside original VHS window"
            );
        }
        let at = usize::from(at);
        s.config[at..at + 4].copy_from_slice(&value.to_le_bytes());
        if s.lose_identity_on_pci == Some(at as u16) {
            s.config[..4].fill(0xff);
        }
    }
    fn write16(&mut self, at: u16, value: u16) {
        assert_eq!(at, 4, "source uses word command stores only");
        let mut s = self.0.borrow_mut();
        s.events.push((0, usize::from(at), u32::from(value)));
        if s.ignore_pci == Some(at) {
            return;
        }
        let at = usize::from(at);
        s.config[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn write8(&mut self, _: u16, _: u8) {
        panic!("unexpected PCI byte store");
    }
}
struct Mmio {
    card: Rc<RefCell<Hardware>>,
    state: Rc<RefCell<State>>,
}
impl Registers for Mmio {
    fn read8(&mut self, at: usize) -> u8 {
        Port(self.card.clone()).read8(at)
    }
    fn read16(&mut self, at: usize) -> u16 {
        Port(self.card.clone()).read16(at)
    }
    fn read32(&mut self, at: usize) -> u32 {
        if at >= 0x200 {
            self.card.borrow_mut().reads += 1;
            return *self.state.borrow().words.get(&at).unwrap_or(&0);
        }
        let value = Port(self.card.clone()).read32(at);
        if at == PRESENT && self.state.borrow().cd_low {
            value & !(CARD_PRESENT | CARD_STABLE)
        } else {
            value
        }
    }
    fn write8(&mut self, at: usize, value: u8) {
        self.state
            .borrow_mut()
            .events
            .push((1, at, u32::from(value)));
        Port(self.card.clone()).write8(at, value);
    }
    fn write16(&mut self, at: usize, value: u16) {
        self.state
            .borrow_mut()
            .events
            .push((2, at, u32::from(value)));
        if self.state.borrow().ignore_mmio == Some(at)
            || at == HOST_CONTROL2 && self.state.borrow().ignore_mode == Some(value & UHS_MODE)
        {
            return;
        }
        Port(self.card.clone()).write16(at, value);
    }
    fn write32(&mut self, at: usize, value: u32) {
        let mut s = self.state.borrow_mut();
        s.events.push((3, at, value));
        if s.ignore_mmio == Some(at) || at == CQ_CONTROL && s.halt_stuck {
            return;
        }
        if at >= 0x200 {
            s.words.insert(at, value);
            self.card.borrow_mut().writes.push((at, 4, value));
            if at == CQ_CONTROL && value & 1 != 0 {
                let status = *s.words.get(&0x210).unwrap_or(&0);
                s.words.insert(0x210, status | 1);
            }
        } else {
            drop(s);
            Port(self.card.clone()).write32(at, value);
        }
    }
}
struct Owner {
    mmio: Mmio,
    function: Function<Config>,
}
impl Registers for Owner {
    fn check_authority(&mut self) -> Result<(), BlockError> {
        let dma = self.mmio.state.borrow().dma;
        pci::runtime_configuration(&mut self.function, dma)?;
        legacy_authority(&mut self.mmio)
    }
    fn configuration(&mut self) -> Result<&mut dyn ConfigSpace, BlockError> {
        let dma = self.mmio.state.borrow().dma;
        pci::runtime_configuration(&mut self.function, dma)
    }
    fn dma_ready(&mut self) -> Result<(), BlockError> {
        let mut enabled = self.mmio.state.borrow().dma;
        pci::dma_grant(&mut self.function, &mut enabled)?;
        self.mmio.state.borrow_mut().dma = enabled;
        Ok(())
    }
    fn read8(&mut self, at: usize) -> u8 {
        self.mmio.read8(at)
    }
    fn read16(&mut self, at: usize) -> u16 {
        self.mmio.read16(at)
    }
    fn read32(&mut self, at: usize) -> u32 {
        self.mmio.read32(at)
    }
    fn write8(&mut self, at: usize, v: u8) {
        self.mmio.write8(at, v);
    }
    fn write16(&mut self, at: usize, v: u16) {
        self.mmio.write16(at, v);
    }
    fn write32(&mut self, at: usize, v: u32) {
        self.mmio.write32(at, v);
    }
}
fn clock() -> Clock {
    Clock {
        ticks_per_microsecond: CLOCK_TICKS_PER_US,
    }
}
fn owner() -> (Owner, Rc<RefCell<Hardware>>, Rc<RefCell<State>>) {
    let mut config = [0u8; 4096];
    for (at, value) in [
        (0, ID),
        (4, 0x0010_0403),
        (8, 0x0805_0100),
        (0x100, 0x0002_0001),
        (0x960, 1 << 3),
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
        words: [(CQ_CFG, 1), (0x52c, 1 << 8)].into_iter().collect(),
        events: Vec::new(),
        halt_stuck: false,
        ignore_pci: None,
        ignore_mmio: None,
        ignore_mode: None,
        lose_identity_on_pci: None,
        cd_low: true,
        dma: false,
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
    let card = Rc::new(RefCell::new(Hardware::new(Kind::Mmc, true)));
    {
        let mut c = card.borrow_mut();
        c.version = 4;
        c.caps = CAP_330 | CAP_HIGH_SPEED | 200 << 8;
        c.wired_width = 8;
    }
    (
        Owner {
            mmio: Mmio {
                card: card.clone(),
                state: state.clone(),
            },
            function,
        },
        card,
        state,
    )
}

mod ddr;
mod fast;
mod hs;
mod retune;
fn initialize_owner(owner: &mut Owner) -> Result<(), BlockError> {
    initialize(&mut owner.function, &mut owner.mmio, clock())
}

#[test]
fn native_gl9763e_original_phy_idle_cqe_retirement_and_eight_pin_mmc_pio_are_real() {
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let (mut owner, card, state) = owner();
    card.borrow_mut().ext[202] = 0x50;
    initialize_owner(&mut owner).unwrap();
    let config = Config(state.clone());
    assert_eq!(config.read32(0x8e0) & (1 << 9), 1 << 9);
    assert_eq!(config.read32(0x960) & 8, 0);
    assert_eq!((config.read32(0x8a4) >> 19) & 0x3ff, 0x54);
    assert_eq!(config.read32(0x934) >> 28, 5);
    assert_eq!(config.read32(CFG) & (1 << 12), 1 << 12);
    assert_eq!(config.read32(VHS) & (15 << 16), 0);
    assert_eq!(*state.borrow().words.get(&CQ_CFG).unwrap() & 1, 0);
    assert_eq!(*state.borrow().words.get(&0x52c).unwrap() & (1 << 8), 0);
    {
        let state = state.borrow();
        let events = &state.events;
        let halt = events
            .iter()
            .position(|e| *e == (3, CQ_CONTROL, 1))
            .unwrap();
        let disable = events.iter().position(|e| *e == (3, CQ_CFG, 0)).unwrap();
        let reset = events
            .iter()
            .position(|e| *e == (1, RESET, u32::from(RESET_ALL)))
            .unwrap();
        assert!(halt < disable && disable < reset);
    }
    let mut host = Host::new(
        Box::new(owner),
        clock(),
        "GL9763E embedded MMC".into(),
        &mut dma,
        Profile::Gli9763e,
    )
    .unwrap();
    let mut disk = host.poll().unwrap().unwrap();
    assert_eq!(disk.info().kind, Kind::Mmc);
    assert_eq!(disk.info().bus_width, 8);
    assert_eq!(disk.info().clock_hz, 50_000_000);
    assert_eq!(
        card.borrow().ext[187],
        5,
        "actual 8-bit 52MHz/VCC3.3V power class"
    );
    assert!(
        !card
            .borrow()
            .commands
            .iter()
            .any(|(cmd, _, flags)| *cmd == 55 || *cmd == 8 && flags & 0x20 == 0)
    );
    assert_eq!(Port(card.clone()).read16(HOST_CONTROL2) & UHS_MODE, 1);
    let mut bytes = [0xa5; 1024];
    disk.read(3, &mut bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[3 * 512..5 * 512]);
    bytes.fill(0x7b);
    disk.write(6, &bytes).unwrap();
    disk.flush().unwrap();
    assert_eq!(bytes, card.borrow().disk[6 * 512..8 * 512]);
    let mut alias = disk.clone();
    disk.shutdown(true).unwrap();
    assert_eq!(alias.flush(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(Port(card).read8(POWER), 0);
}

#[test]
fn gl9763e_supply_and_adma_follow_card_state() {
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let (mut owner, card, state) = owner();
    {
        let mut c = card.borrow_mut();
        c.caps = CAP_180 | CAP_HIGH_SPEED | CAP_ADMA2 | 1 << 27 | 200 << 8;
        c.ocr_voltage = 1 << 7;
    }
    initialize_owner(&mut owner).unwrap();
    let mut host = Host::new(
        Box::new(owner),
        clock(),
        "GL9763E 1.8V MMC".into(),
        &mut dma,
        Profile::Gli9763e,
    )
    .unwrap();
    let mut disk = host.poll().unwrap().unwrap();
    assert_eq!(disk.info().signal_voltage, SignalVoltage::V1_8);
    assert_ne!(Port(card.clone()).read16(HOST_CONTROL2) & SIGNAL_180, 0);
    let mut bytes = vec![0xa5; 65536];
    disk.read(3, &mut bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[3 * 512..3 * 512 + 65536]);
    bytes.fill(0x68);
    disk.write(200, &bytes).unwrap();
    disk.flush().unwrap();
    assert_eq!(bytes, card.borrow().disk[200 * 512..200 * 512 + 65536]);
    assert!(state.borrow().dma);
    assert_eq!(host.inner.borrow().descriptors.read::<u32>(12), 0);
}

#[test]
fn native_gl9763e_unknown_firmware_cqe_work_and_refused_halt_never_start_legacy_commands() {
    for fault in 0..6 {
        let (mut owner, card, state) = owner();
        if fault == 0 {
            state.borrow_mut().halt_stuck = true;
        } else {
            state.borrow_mut().words.insert(
                [0, 0x228, 0x22c, 0x230, 0x234, 0x210][fault],
                if fault == 5 { 4 } else { 1 },
            );
        }
        assert!(initialize_owner(&mut owner).is_err());
        assert!(card.borrow().commands.is_empty());
        assert!(!card.borrow().writes.iter().any(|(at, _, _)| *at == RESET));
        assert!(
            !state
                .borrow()
                .events
                .iter()
                .any(|(kind, at, value)| *kind == 0 && *at == 4 && value & 4 != 0)
        );
    }
}

#[test]
fn native_gl9763e_revoked_pci_or_reenabled_queue_fences_published_mmc_before_commands() {
    for queue in [false, true] {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut owner, card, state) = owner();
        initialize_owner(&mut owner).unwrap();
        let mut host = Host::new(
            Box::new(owner),
            clock(),
            "revoked GL9763E".into(),
            &mut dma,
            Profile::Gli9763e,
        )
        .unwrap();
        let mut disk = host.poll().unwrap().unwrap();
        let commands = card.borrow().commands.len();
        if queue {
            state.borrow_mut().words.insert(CQ_CFG, 1);
        } else {
            state.borrow_mut().config[0x94] = 3;
        }
        let mut poison = [0xa5; 512];
        assert!(disk.read(0, &mut poison).is_err());
        assert_eq!(poison, [0xa5; 512]);
        assert_eq!(commands, card.borrow().commands.len());
        assert!(host.last_failure().unwrap().quarantined);
        let accesses = (card.borrow().reads, card.borrow().writes.len());
        assert!(host.poll().is_err());
        assert_eq!(disk.flush(), Err(BlockError::Unsupported(STALE)));
        assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
    }
}

#[test]
#[ignore = "oracle: STELA_SDHCI_GLI63E_ORACLE"]
fn unchanged_linux_gl9763e_phy_lpn_and_mmc_hs_signaling_match_native() {
    extern crate std;
    let path =
        std::env::var_os("STELA_SDHCI_GLI63E_ORACLE").expect("set STELA_SDHCI_GLI63E_ORACLE");
    let trace = std::fs::read_to_string(path).unwrap();
    let addresses = [VHS, 0x8e0, 0x960, 0x8a4, 0x934, 0x114, CFG];
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let number = |i: usize| fields[i].parse::<u32>().unwrap();
        let (mut owner, card, state) = owner();
        match fields[0] {
            "P" => {
                let seed = number(1);
                for at in addresses {
                    let at = usize::from(at);
                    state.borrow_mut().config[at..at + 4].copy_from_slice(&seed.to_le_bytes());
                }
                state.borrow_mut().words.insert(0x52c, seed);
                initialize_owner(&mut owner).unwrap();
                if number(2) != 0 {
                    low_power(owner.function.config(), true).unwrap();
                }
                for (i, at) in addresses.into_iter().enumerate() {
                    assert_eq!(owner.function.config().read32(at), number(3 + i), "{line}");
                }
                assert_eq!(owner.mmio.read32(0x52c), number(10), "{line}");
            }
            "S" => {
                Port(card.clone()).write16(HOST_CONTROL2, number(1) as u16);
                high_speed(&mut owner.mmio).unwrap();
                assert_eq!(
                    u32::from(Port(card).read16(HOST_CONTROL2)),
                    number(2),
                    "{line}"
                );
            }
            _ => panic!("unqualified GL9763E source record {line}"),
        }
        cases += 1;
    }
    assert_eq!(cases, 27);
}

#[test]
fn native_gl9763e_all_ones_vendor_state_is_valid_but_lost_identity_or_write_ack_is_not() {
    for fault in 0..3 {
        let (mut owner, card, state) = owner();
        for at in [VHS, 0x8e0, 0x960, 0x8a4, 0x934, 0x114, CFG] {
            let at = usize::from(at);
            state.borrow_mut().config[at..at + 4].fill(0xff);
        }
        state.borrow_mut().words.insert(0x52c, u32::MAX);
        if fault == 1 {
            state.borrow_mut().ignore_pci = Some(0x8a4);
        }
        if fault == 2 {
            state.borrow_mut().lose_identity_on_pci = Some(0x8e0);
        }
        assert_eq!(initialize_owner(&mut owner).is_ok(), fault == 0);
        if fault == 0 {
            assert_eq!(state.borrow().words[&0x52c], !(1 << 8));
        } else {
            assert!(!card.borrow().writes.iter().any(|(at, _, _)| *at == RESET));
        }
        assert!(card.borrow().commands.is_empty());
    }
}

#[test]
fn native_gl9763e_invalid_clock_is_refused_before_original_pci_or_controller_effects() {
    for ticks_per_microsecond in [0, u64::MAX, u64::MAX / (2 * 5_000_000) + 1] {
        let (mut owner, card, state) = owner();
        assert!(
            initialize(
                &mut owner.function,
                &mut owner.mmio,
                Clock {
                    ticks_per_microsecond
                }
            )
            .is_err()
        );
        assert!(state.borrow().events.is_empty());
        assert_eq!(card.borrow().reads, 0);
        assert!(card.borrow().writes.is_empty());
        assert_eq!(owner.function.config().read32(0), ID);
    }
}

#[test]
fn native_gl9763e_current_metadata_uses_the_vcc_supply_field() {
    for (capability, power, units) in [
        (CAP_330, POWER_330, 0x11),
        (CAP_300, POWER_300, 0x22),
        (CAP_180, POWER_180, 0x33),
    ] {
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let (mut owner, card, _) = owner();
        initialize_owner(&mut owner).unwrap();
        card.borrow_mut().caps = capability | CAP_HIGH_SPEED | 200 << 8;
        card.borrow_mut().max_current = 0x0033_2211;
        let host = Host::new(
            Box::new(owner),
            clock(),
            "actual VCC current field".into(),
            &mut dma,
            Profile::Gli9763e,
        )
        .unwrap();
        assert_eq!(Port(card).read8(POWER), power | POWER_ON);
        assert_eq!(host.inner.borrow().max_current_ma, units * 4);
    }
}
