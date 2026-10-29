//! GL9750 native card/register and source-oracle regressions.
use super::*;
use crate::{bus::dma::RegionAllocator, storage::sdhci::model::*};
use alloc::{collections::BTreeMap, vec};

struct Bank {
    words: BTreeMap<usize, u32>,
    writes: Vec<(usize, u32)>,
    wire: Vec<(u8, u32)>,
    ignore: Option<usize>,
    first_polarity_bad: bool,
    first_polarity_timeout: bool,
    timeout_reset_stuck: bool,
    both_polarities_timeout: bool,
    v4_stuck: bool,
    dma_allowed: bool,
    dma_granted: bool,
    dma_fail: bool,
    dma_retire_stuck: bool,
    dma_selection_stuck: bool,
    normal_power_off: bool,
    signal_at: Option<u64>,
}
struct PortModel {
    card: Rc<RefCell<Hardware>>,
    bank: Rc<RefCell<Bank>>,
}
impl PortModel {
    fn word(&self, at: usize) -> u32 {
        *self.bank.borrow().words.get(&at).unwrap_or(&0)
    }
    fn physical_hz(&mut self) -> u32 {
        let pll = self.word(PLL);
        if pll & DIRECT != 0 {
            match (pll & 0x3ff, (pll >> 12) & 7) {
                (0x246, 0) => 205_000_000,
                (0x244, 1) => 100_000_000,
                (0x244, 3) => 50_000_000,
                pair => panic!("unqualified physical PLL {pair:?}"),
            }
        } else {
            let clock = self.read16(CLOCK);
            let field = (clock >> 8) | (clock & 0xc0) << 2;
            200_000_000 / if field == 0 { 1 } else { u32::from(field) * 2 }
        }
    }
}
impl Registers for PortModel {
    fn dma_ready(&mut self) -> Result<(), BlockError> {
        let mut bank = self.bank.borrow_mut();
        assert!(bank.dma_allowed, "DMA grant outside admitted profile");
        if bank.dma_fail {
            return Err(BlockError::Unsupported(
                "modeled native PCI DMA grant uncertainty",
            ));
        }
        bank.dma_granted = true;
        Ok(())
    }
    fn read8(&mut self, at: usize) -> u8 {
        (self.read32(at & !3) >> (8 * (at & 3))) as u8
    }
    fn read16(&mut self, at: usize) -> u16 {
        (self.read32(at & !3) >> (8 * (at & 3))) as u16
    }
    fn read32(&mut self, at: usize) -> u32 {
        if at >= 0x500 {
            return self.word(at);
        }
        let mut port = Port(self.card.clone());
        match at {
            CLOCK => {
                u32::from(port.read16(CLOCK))
                    | u32::from(port.read8(TIMEOUT)) << 16
                    | u32::from(port.read8(RESET)) << 24
            }
            0xfc => u32::from(port.read16(VERSION)) << 16,
            MAX_CURRENT => {
                let value = port.read32(at);
                if value & 255 == 0 {
                    value | 0xc8
                } else {
                    value
                }
            }
            _ => port.read32(at),
        }
    }
    fn write8(&mut self, at: usize, value: u8) {
        if at == POWER && value == 0 && self.bank.borrow().normal_power_off {
            assert_eq!(
                self.word(PLL) & (DIRECT | SSC_ENABLE),
                0,
                "normal rail-off before vendor PLL stopped"
            );
        }
        if at == HOST_CONTROL
            && value & DMA_MASK == ADMA32
            && self.bank.borrow().dma_selection_stuck
        {
            self.card
                .borrow_mut()
                .writes
                .push((at, 1, u32::from(value)));
            return;
        }
        Port(self.card.clone()).write8(at, value);
    }
    fn write16(&mut self, at: usize, value: u16) {
        if at == HOST_CONTROL2 && value & (1 << 12) != 0 && self.bank.borrow().v4_stuck {
            return;
        }
        if at == HOST_CONTROL2 && value & SIGNAL_180 != 0 && self.read16(at) & SIGNAL_180 == 0 {
            self.bank.borrow_mut().signal_at = Some(
                Clock {
                    ticks_per_microsecond: 1,
                }
                .now_us(),
            );
        }
        if at == CLOCK
            && value & CLOCK_CARD != 0
            && self.read16(at) & CLOCK_CARD == 0
            && let Some(started) = self.bank.borrow().signal_at
        {
            assert!(
                Clock {
                    ticks_per_microsecond: 1
                }
                .now_us()
                    - started
                    >= 110_000 * CLOCK_TICKS_PER_US,
                "GL9750 lost source voltage settling margin"
            );
        }
        if at == COMMAND {
            let command = (value >> 8) as u8;
            let hz = self.physical_hz();
            self.bank.borrow_mut().wire.push((command, hz));
            let dma = self.read16(TRANSFER_MODE) & DMA != 0;
            if dma {
                assert!(
                    self.bank.borrow().dma_allowed && self.bank.borrow().dma_granted,
                    "DMA command before actual native grant"
                );
                if self.bank.borrow().dma_retire_stuck {
                    self.card.borrow_mut().reset_stuck = true;
                }
            }
            if command == 0 {
                assert!(hz <= 400_000);
            }
            if command == 19 {
                let inverted = self.word(MISC) & 8 != 0;
                self.card.borrow_mut().tuning_no_clock =
                    self.bank.borrow().first_polarity_bad && !inverted;
                self.card.borrow_mut().silent = (self.bank.borrow().both_polarities_timeout
                    || self.bank.borrow().first_polarity_timeout && !inverted)
                    .then_some(19);
                if self.bank.borrow().timeout_reset_stuck && !inverted {
                    self.card.borrow_mut().reset_stuck = true;
                }
            }
        }
        Port(self.card.clone()).write16(at, value);
    }
    fn write32(&mut self, at: usize, value: u32) {
        if at == ADMA_ADDRESS_HIGH {
            assert_ne!(
                self.read16(HOST_CONTROL2) & (1 << 13),
                0,
                "32bit DMA must not touch the unused high address register"
            );
        }
        if at >= 0x500 {
            let mut bank = self.bank.borrow_mut();
            bank.writes.push((at, value));
            if bank.ignore == Some(at) {
                return;
            }
            if at != WT {
                assert_ne!(
                    *bank.words.get(&WT).unwrap_or(&0) & 1,
                    0,
                    "protected write without real WT ownership"
                );
            }
            bank.words.insert(at, value);
        } else {
            Port(self.card.clone()).write32(at, value);
        }
    }
}
fn host(dma: &mut dyn DmaAllocator) -> (Host, Rc<RefCell<Hardware>>, Rc<RefCell<Bank>>) {
    let card = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    {
        let mut card = card.borrow_mut();
        card.caps = CAP_330 | CAP_HIGH_SPEED | 200 << 8;
        card.caps2 = CAP_SDR104 | CAP_SDR50_TUNING;
        card.uhs_functions = 15;
        card.scr[2] = 0x80;
    }
    let bank = Rc::new(RefCell::new(Bank {
        words: [
            (DRIVING, 0x7370_1200),
            (MISC, 0x0080_0000),
            (TUNING, 0x0040_0000),
            (PARAMETERS, 0x0000_0600),
            (PLL, 0x0040_0000),
            (SSC, 0x0000_bbb3),
            (BURST, 0x0003_0055),
        ]
        .into_iter()
        .collect(),
        writes: Vec::new(),
        wire: Vec::new(),
        ignore: None,
        first_polarity_bad: false,
        first_polarity_timeout: false,
        timeout_reset_stuck: false,
        both_polarities_timeout: false,
        v4_stuck: false,
        dma_allowed: false,
        dma_granted: false,
        dma_fail: false,
        dma_retire_stuck: false,
        dma_selection_stuck: false,
        normal_power_off: false,
        signal_at: None,
    }));
    let host = Host::new(
        Box::new(PortModel {
            card: card.clone(),
            bank: bank.clone(),
        }),
        Clock {
            ticks_per_microsecond: CLOCK_TICKS_PER_US,
        },
        "GL9750 native model".into(),
        dma,
        Profile::Gli9750,
    )
    .unwrap();
    (host, card, bank)
}

#[test]
fn native_gl9750_phy_pll_real_voltage_tuning_and_pio_block_io() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: payload and controller allocations outlive every card alias.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, bank) = host(&mut dma);
    let mut disk = host.poll().unwrap().unwrap();
    assert_eq!(disk.info().timing, Timing::Sdr104);
    assert_eq!(disk.info().clock_hz, 205_000_000);
    assert_eq!(disk.info().signal_voltage, SignalVoltage::V1_8);
    assert_eq!(host.inner.borrow().max_current_ma, 800);
    assert_eq!(card.borrow().tuning_commands, 3);
    let mut data = [0xa5; 1024];
    disk.read(11, &mut data).unwrap();
    assert_eq!(data, card.borrow().disk[11 * 512..13 * 512]);
    data.fill(0x76);
    disk.write(18, &data).unwrap();
    disk.flush().unwrap();
    assert_eq!(data, card.borrow().disk[18 * 512..20 * 512]);
    let bank = bank.borrow();
    assert!(
        bank.wire
            .iter()
            .filter(|(cmd, _)| matches!(cmd, 17 | 18 | 24 | 25))
            .all(|(_, hz)| *hz == 205_000_000)
    );
    assert_eq!(bank.words[&DRIVING] & 0xff00_0fff, 0x8c00_0fff);
    assert_eq!(bank.words[&BURST] & (3 << 16), 0);
    assert_eq!(bank.words[&WT] & 1, 0);
}

#[test]
fn native_gl9750_second_rx_polarity_requires_real_first_phase_retirement() {
    for timeout in [false, true] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: failed first-phase effects keep DMA/controller ownership.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, card, bank) = host(&mut dma);
        bank.borrow_mut().first_polarity_bad = !timeout;
        bank.borrow_mut().first_polarity_timeout = timeout;
        let mut disk = host.poll().unwrap().unwrap();
        assert_eq!(bank.borrow().words[&MISC] & 8, 8);
        assert_eq!(card.borrow().tuning_commands, if timeout { 3 } else { 6 });
        assert_eq!(
            card.borrow()
                .commands
                .iter()
                .filter(|(cmd, _, _)| *cmd == 12)
                .count(),
            usize::from(timeout)
        );
        let mut data = [0; 512];
        disk.read(3, &mut data).unwrap();
        assert_eq!(data, card.borrow().disk[1536..2048]);
    }
}

#[test]
fn native_gl9750_protected_register_failure_closes_window_and_fences_aliases() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: every old card and failed register epoch keeps original backing.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, _, bank) = host(&mut dma);
    let mut disk = host.poll().unwrap().unwrap();
    bank.borrow_mut().ignore = Some(MISC);
    // A subsequent reset must program a new baseline, so first perturb RX.
    bank.borrow_mut()
        .words
        .entry(MISC)
        .and_modify(|word| *word |= 8);
    let error = host
        .inner
        .borrow_mut()
        .reset(RESET_COMMAND | RESET_DATA)
        .unwrap_err();
    assert_eq!(bank.borrow().words[&WT] & 1, 0);
    let accesses = bank.borrow().writes.len();
    let mut poison = [0xa5; 512];
    assert_eq!(
        disk.read(0, &mut poison),
        Err(BlockError::Unsupported(STALE))
    );
    assert_eq!(poison, [0xa5; 512]);
    assert_eq!(host.poll().err(), Some(error));
    assert_eq!(bank.borrow().writes.len(), accesses);
}

#[test]
fn native_gl9750_phase_timeout_preserves_primary_and_failed_reset_without_reusing_aliases() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: quarantined controller and both stale aliases keep all backing.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, _, bank) = host(&mut dma);
    let mut disk = host.poll().unwrap().unwrap();
    let mut old = disk.clone();
    bank.borrow_mut().first_polarity_timeout = true;
    bank.borrow_mut().timeout_reset_stuck = true;
    host.inner.borrow_mut().tuned_at = None;
    let mut poison = [0xa5; 512];
    assert_eq!(disk.read(5, &mut poison), Err(BlockError::Timeout));
    assert_eq!(poison, [0xa5; 512]);
    let failure = host.last_failure().unwrap();
    assert_eq!(failure.primary, BlockError::Timeout);
    assert!(matches!(
        failure.retirement,
        Some(BlockError::Unsupported(_))
    ));
    assert!(failure.quarantined);
    let accesses = bank.borrow().writes.len();
    assert_eq!(old.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(host.poll().err(), Some(BlockError::Timeout));
    assert_eq!(bank.borrow().writes.len(), accesses);
}

#[test]
fn native_gl9750_both_polarity_timeouts_keep_timeout_and_each_card_stop_ack() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: both timed-out native/card tasks keep their original allocations.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, bank) = host(&mut dma);
    bank.borrow_mut().both_polarities_timeout = true;
    assert_eq!(host.poll().err(), Some(BlockError::Timeout));
    assert_eq!(host.last_failure().unwrap().primary, BlockError::Timeout);
    assert_eq!(
        card.borrow()
            .commands
            .iter()
            .filter(|(cmd, _, _)| *cmd == 19)
            .count(),
        2
    );
    assert_eq!(
        card.borrow()
            .commands
            .iter()
            .filter(|(cmd, _, _)| *cmd == 12)
            .count(),
        2
    );
    assert!(host.inner.borrow().medium.is_none());
    assert!(!card.borrow().voltage_started);
}

#[test]
fn native_gl9750_missing_v4_mode_ack_refuses_before_card_commands() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: rejected mode programming never publishes a controller command.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, bank) = host(&mut dma);
    bank.borrow_mut().v4_stuck = true;
    assert!(host.poll().is_err());
    assert!(card.borrow().commands.is_empty());
    assert!(host.inner.borrow().medium.is_none());
}

fn dma_host(
    dma: &mut dyn DmaAllocator,
    version: u16,
    address_capability: u32,
) -> (Host, Rc<RefCell<Hardware>>, Rc<RefCell<Bank>>) {
    let (host, card, bank) = host(dma);
    card.borrow_mut().version = version;
    card.borrow_mut().caps |= CAP_ADMA2 | address_capability;
    bank.borrow_mut().dma_allowed = true;
    (host, card, bank)
}

#[test]
fn native_gl9750_normal_shutdown_stops_actual_vendor_pll_before_card_rail_off() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: the original card and all aliases keep their model DMA RAM.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, bank) = host(&mut dma);
    let mut disk = host.poll().unwrap().unwrap();
    assert_ne!(*bank.borrow().words.get(&PLL).unwrap() & DIRECT, 0);
    bank.borrow_mut().normal_power_off = true;
    disk.shutdown(true).unwrap();
    assert_eq!(
        *bank.borrow().words.get(&PLL).unwrap() & (DIRECT | SSC_ENABLE),
        0
    );
    assert_eq!(Port(card).read8(POWER), 0);
    assert_eq!(host.inner.borrow().actual_hz, 0);
}

#[test]
fn native_gl9750_v4_adma_64bit_legacy_and_modern_capabilities_transfer_real_payloads() {
    for (version, capability, wide) in [(2, CAP_64, true), (4, 1 << 27, true), (4, CAP_64, false)] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: descriptor/payload pages remain live through every
        // modeled DMA effect and the card's completed flush.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, card, bank) = dma_host(&mut dma, version, capability);
        let mut disk = host.poll().unwrap().unwrap();
        if wide {
            assert_eq!(host.inner.borrow().dma_mode, Some(true));
        } else if start >= 1u64 << 32 {
            assert!(host.inner.borrow().dma_mode.is_none());
        }
        let mut bytes = vec![0xa5; 65536];
        disk.read(11, &mut bytes).unwrap();
        assert_eq!(bytes, card.borrow().disk[11 * 512..11 * 512 + 65536]);
        bytes.fill(0x6b);
        disk.write(200, &bytes).unwrap();
        disk.flush().unwrap();
        assert_eq!(bytes, card.borrow().disk[200 * 512..200 * 512 + 65536]);
        let engine = host.inner.borrow();
        if engine.dma_mode.is_some() {
            assert!(bank.borrow().dma_granted);
            assert_eq!(engine.descriptors.read::<u16>(0), 0x23);
            assert_eq!(
                engine.descriptors.read::<u16>(2),
                0,
                "64KiB source length encoding"
            );
            assert_eq!(
                engine.descriptors.read::<u32>(12),
                0,
                "v4 reserved descriptor high word"
            );
        } else {
            assert!(
                !bank.borrow().dma_granted,
                "unaddressable allocations must stay PIO"
            );
        }
    }
}

#[test]
fn native_gl9750_uncertain_dma_grant_never_posts_a_command_and_retains_failed_owner() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: no native grant failure can release the original DMA allocations.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, _, bank) = dma_host(&mut dma, 4, 1 << 27);
    let mut disk = host.poll().unwrap().unwrap();
    let mut old = disk.clone();
    bank.borrow_mut().dma_fail = true;
    let commands = bank.borrow().wire.len();
    let mut poison = [0xa5; 512];
    let primary = disk.read(3, &mut poison).unwrap_err();
    assert_eq!(poison, [0xa5; 512]);
    assert_eq!(bank.borrow().wire.len(), commands);
    assert!(host.last_failure().unwrap().quarantined);
    let accesses = bank.borrow().writes.len();
    assert_eq!(old.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(host.poll().err(), Some(primary));
    assert_eq!(bank.borrow().writes.len(), accesses);
}

#[test]
fn native_gl9750_ignored_dma_selection_cannot_publish_a_dma_command_or_output() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: ignored controller configuration keeps original descriptor and
    // payload allocations kept, and publishes no data command.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, bank) = dma_host(&mut dma, 4, 1 << 27);
    let mut disk = host.poll().unwrap().unwrap();
    let mut old = disk.clone();
    bank.borrow_mut().dma_selection_stuck = true;
    let commands = card.borrow().commands.len();
    let mut poison = [0xa5; 512];
    let error = disk.read(20, &mut poison).unwrap_err();
    assert_eq!(
        error,
        BlockError::Unsupported("GL9750 DMA selection did not acknowledge")
    );
    assert_eq!(poison, [0xa5; 512]);
    assert!(bank.borrow().dma_granted, "actual grant stage was reached");
    assert_eq!(
        card.borrow().commands.len(),
        commands,
        "stale SDMA/ADMA64 mode cannot receive a DMA command"
    );
    assert!(
        card.borrow()
            .writes
            .iter()
            .any(|(at, width, value)| *at == HOST_CONTROL
                && *width == 1
                && value & u32::from(DMA_MASK) == u32::from(ADMA32))
    );
    let writes = card.borrow().writes.len();
    assert_eq!(old.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(card.borrow().writes.len(), writes);
}

#[test]
fn native_gl9750_dma_error_and_failed_retirement_keep_primary_and_stale_output() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: failed DMA retirement keeps every descriptor/payload backing live.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, bank) = dma_host(&mut dma, 4, 1 << 27);
    let mut disk = host.poll().unwrap().unwrap();
    card.borrow_mut().data_error = true;
    bank.borrow_mut().dma_retire_stuck = true;
    let mut poison = [0xa5; 512];
    let primary = disk.read(8, &mut poison).unwrap_err();
    assert!(matches!(primary, BlockError::Device { .. }));
    assert_eq!(poison, [0xa5; 512]);
    let failure = host.last_failure().unwrap();
    assert_eq!(failure.primary, primary);
    assert!(failure.retirement.is_some());
    assert!(failure.quarantined);
    let accesses = bank.borrow().writes.len();
    assert_eq!(disk.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(host.poll().err(), Some(primary));
    assert_eq!(bank.borrow().writes.len(), accesses);
}

#[cfg(target_os = "linux")]
#[test]
fn native_gl9750_v4_adma32_uses_real_low_address_descriptor_and_payload_pages() {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            file: i32,
            offset: i64,
        ) -> *mut c_void;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    struct LowPages(*mut c_void, usize);
    impl Drop for LowPages {
        fn drop(&mut self) {
            // SAFETY: this exact anonymous mapping has no surviving model users.
            assert_eq!(unsafe { munmap(self.0, self.1) }, 0);
        }
    }
    // Linux x86-64 MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, PROT_READ|WRITE.
    // SAFETY: an independent test-only anonymous RAM region, no fixed address,
    // file, firmware mapping or real device access; the peer models identity DMA.
    let address = unsafe {
        mmap(
            core::ptr::null_mut(),
            1024 * 1024,
            3,
            2 | 0x20 | 0x40,
            -1,
            0,
        )
    };
    assert_ne!(address as isize, -1);
    let pages = LowPages(address, 1024 * 1024);
    let start = pages.0 as u64;
    assert!(start + pages.1 as u64 <= 1u64 << 32);
    // SAFETY: the mapped low-address RAM remains live through all
    // modeled command/data DMA, errors, aliases and final controller retirement.
    let mut dma = unsafe { RegionAllocator::new(start..start + pages.1 as u64) };
    let (mut host, card, bank) = dma_host(&mut dma, 4, 0);
    let mut disk = host.poll().unwrap().unwrap();
    assert_eq!(host.inner.borrow().dma_mode, Some(false));
    let mut bytes = [0xa5; 1024];
    disk.read(12, &mut bytes).unwrap();
    assert_eq!(bytes, card.borrow().disk[12 * 512..14 * 512]);
    bytes.fill(0x73);
    disk.write(12, &bytes).unwrap();
    disk.flush().unwrap();
    assert_eq!(bytes, card.borrow().disk[12 * 512..14 * 512]);
    assert!(bank.borrow().dma_granted);
    let mut engine = host.inner.borrow_mut();
    assert_eq!(engine.registers.read16(HOST_CONTROL2) & (3 << 12), 1 << 12);
    assert_eq!(engine.registers.read8(HOST_CONTROL) & DMA_MASK, ADMA32);
}

#[test]
fn native_gl9750_mmc_adma_cache_flush_and_poweroff_preserve_the_real_card_lifecycle() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: the MMC card and all aliases keep the modeled DMA RAM
    // until acknowledged power-off and controller retirement have completed.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, card, bank) = host(&mut dma);
    *card.borrow_mut() = Hardware::new(Kind::Mmc, true);
    card.borrow_mut().version = 4;
    card.borrow_mut().caps = CAP_330 | CAP_HIGH_SPEED | CAP_ADMA2 | 1 << 27 | 200 << 8;
    bank.borrow_mut().dma_allowed = true;
    let mut disk = host.poll().unwrap().unwrap();
    let mut old = disk.clone();
    assert_eq!(disk.info().kind, Kind::Mmc);
    assert_eq!(disk.info().bus_width, 4);
    assert_eq!(disk.info().clock_hz, 50_000_000);
    assert_eq!(disk.info().signal_voltage, SignalVoltage::V3_3);
    let mut bytes = [0x6c; 1024];
    disk.write(40, &bytes).unwrap();
    disk.flush().unwrap();
    bytes.fill(0xa5);
    disk.read(40, &mut bytes).unwrap();
    assert_eq!(bytes, [0x6c; 1024]);
    assert!(
        card.borrow()
            .commands
            .iter()
            .any(|(cmd, argument, _)| *cmd == 6 && *argument == 3 << 24 | 32 << 16 | 1 << 8)
    );
    disk.shutdown(true).unwrap();
    assert!(!card.borrow().command_after_notification);
    let accesses = bank.borrow().writes.len();
    assert_eq!(
        old.read(40, &mut bytes),
        Err(BlockError::Unsupported(STALE))
    );
    assert_eq!(old.flush(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(bank.borrow().writes.len(), accesses);
}

struct Configuration {
    bytes: [u8; 4096],
    writes: Vec<(u16, usize, u32)>,
    fail: Option<u8>,
    allow_dma: bool,
}
struct Config(Rc<RefCell<Configuration>>);
impl ConfigSpace for Config {
    fn read8(&self, at: u16) -> u8 {
        self.0.borrow().bytes[usize::from(at)]
    }
    fn read16(&self, at: u16) -> u16 {
        let at = usize::from(at);
        u16::from_le_bytes(self.0.borrow().bytes[at..at + 2].try_into().unwrap())
    }
    fn read32(&self, at: u16) -> u32 {
        let at = usize::from(at);
        u32::from_le_bytes(self.0.borrow().bytes[at..at + 4].try_into().unwrap())
    }
    fn write8(&mut self, _: u16, _: u8) {
        panic!("word/dword configuration stores required");
    }
    fn write16(&mut self, at: u16, value: u16) {
        let mut config = self.0.borrow_mut();
        config.writes.push((at, 2, u32::from(value)));
        assert!(matches!(at, 4 | 0x54));
        if at == 4 {
            assert!(value & 4 == 0 || config.allow_dma, "transient DMA grant");
            if config.fail == Some(6) && value & 4 != 0 {
                return;
            }
            if config.fail == Some(5) && value & 2 == 0 {
                return;
            }
        }
        if at == 0x54 {
            if value & 3 == 3 {
                assert_eq!(
                    config.bytes[4] & 6,
                    0,
                    "power transition with live BAR/DMA decoding"
                );
            }
            if config.fail == Some(1) && value & 3 == 3 || config.fail == Some(2) && value & 3 == 0
            {
                return;
            }
            if value & 3 == 0 && config.bytes[0x54] & 3 == 3 {
                config.bytes[0x10..0x28].fill(0); // D3hot-to-D0 soft reset.
                if config.fail == Some(3) {
                    config.bytes[0] ^= 1;
                }
            }
        }
        let at = usize::from(at);
        config.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn write32(&mut self, at: u16, value: u32) {
        let mut config = self.0.borrow_mut();
        config.writes.push((at, 4, value));
        assert!(matches!(at, 0x10..=0x24 | 0x114));
        if (0x10..=0x24).contains(&at) {
            assert_eq!(
                config.bytes[4] & 6,
                0,
                "BAR restoration before memory/DMA decode containment"
            );
        }
        if config.fail == Some(4) && at == 0x114 {
            return;
        }
        let at = usize::from(at);
        config.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}
fn configuration() -> (Function<Config>, Rc<RefCell<Configuration>>) {
    let mut bytes = [0u8; 4096];
    bytes[..4].copy_from_slice(&0x9750_17a0u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&0x403u16.to_le_bytes());
    bytes[6] = 0x10;
    bytes[8..12].copy_from_slice(&0x0805_0100u32.to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&0x9000_0004u32.to_le_bytes());
    bytes[0x34] = 0x50;
    bytes[0x50] = 1;
    bytes[0x51] = 0x60;
    bytes[0x60] = 0x10;
    bytes[0x62] = 2;
    bytes[0x100..0x104].copy_from_slice(&0x1402_0001u32.to_le_bytes());
    bytes[0x114..0x118].copy_from_slice(&4u32.to_le_bytes());
    bytes[0x140..0x144].copy_from_slice(&0x0001_0003u32.to_le_bytes());
    let config = Rc::new(RefCell::new(Configuration {
        bytes,
        writes: Vec::new(),
        fail: None,
        allow_dma: false,
    }));
    let function = Function::new(
        crate::bus::pci::Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        Config(config.clone()),
    )
    .unwrap();
    (function, config)
}

#[test]
fn native_gl9750_pci_dma_grant_uses_acknowledged_word_stores_and_never_regrants_changed_epoch() {
    let (mut function, state) = configuration();
    state.borrow_mut().allow_dma = true;
    let mut enabled = false;
    pci::dma_grant(&mut function, &mut enabled).unwrap();
    assert!(enabled);
    assert_eq!(function.config().read16(4), 0x407);
    assert_eq!(function.config().read16(6), 0x10, "adjacent W1C PCI status");
    let writes = state.borrow().writes.len();
    pci::dma_grant(&mut function, &mut enabled).unwrap();
    assert_eq!(state.borrow().writes.len(), writes);
    state.borrow_mut().bytes[4] &= !4;
    assert!(pci::dma_grant(&mut function, &mut enabled).is_err());
    assert_eq!(
        state.borrow().writes.len(),
        writes,
        "changed epoch cannot silently reenable DMA"
    );
    let (mut function, state) = configuration();
    state.borrow_mut().allow_dma = true;
    state.borrow_mut().fail = Some(6);
    let mut enabled = false;
    assert!(pci::dma_grant(&mut function, &mut enabled).is_err());
    assert!(!enabled);
    assert_eq!(function.config().read16(4), 0x403);
    let (mut function, state) = configuration();
    state.borrow_mut().allow_dma = true;
    state.borrow_mut().bytes[0x61] = 0xa0;
    state.borrow_mut().bytes[0xa0] = 5;
    state.borrow_mut().bytes[0xa2] = 1; // MSI is unexpectedly enabled.
    let mut enabled = false;
    assert!(pci::dma_grant(&mut function, &mut enabled).is_err());
    assert!(
        state.borrow().writes.is_empty(),
        "do not repair foreign IRQ ownership or grant DMA"
    );
}

#[test]
fn native_gl9750_actual_pci_power_cycle_restores_bars_and_masks_source_aer_event() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: PCI source model and native controller keep all allocation epochs.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (host, card, bank) = host(&mut dma);
    drop(host);
    let mut registers = PortModel {
        card,
        bank: bank.clone(),
    };
    let (mut function, config) = configuration();
    pci::setup(
        &mut function,
        &mut registers,
        Clock {
            ticks_per_microsecond: CLOCK_TICKS_PER_US,
        },
    )
    .unwrap();
    assert_eq!(function.config().read32(0x10), 0x9000_0004);
    assert_eq!(function.config().read16(4), 0x403);
    assert_eq!(function.config().read16(0x54), 0);
    assert_eq!(function.config().read32(0x114), 0x1004);
    assert_eq!(bank.borrow().words[&CFG2] & (31 << 24), 31 << 24);
    assert_eq!(bank.borrow().words[&WT] & 1, 0);
    assert!(config.borrow().writes.contains(&(0x54, 2, 3)));
    assert!(config.borrow().writes.contains(&(0x54, 2, 0)));
}

#[test]
fn native_gl9750_pci_failed_power_identity_and_aer_ack_are_explicit() {
    for failure in 1..=5 {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: failed admission publishes no DMA and preserves all model owners.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (host, card, bank) = host(&mut dma);
        drop(host);
        let mut registers = PortModel {
            card,
            bank: bank.clone(),
        };
        let (mut function, config) = configuration();
        config.borrow_mut().fail = Some(failure);
        assert!(
            pci::setup(
                &mut function,
                &mut registers,
                Clock {
                    ticks_per_microsecond: CLOCK_TICKS_PER_US
                }
            )
            .is_err()
        );
        if failure == 5 {
            assert!(
                config
                    .borrow()
                    .writes
                    .iter()
                    .all(|(at, _, _)| !(0x10..=0x24).contains(at)),
                "failed memory-disable ACK authorized BAR writes"
            );
        }
        assert!(
            bank.borrow().wire.is_empty(),
            "failed PCI admission must not identify media"
        );
        assert!(
            config
                .borrow()
                .writes
                .iter()
                .all(|(at, width, value)| *at != 4 || *width == 2 && value & 4 == 0)
        );
    }
}

#[test]
fn native_gl9750_embedded_aer_capability_cannot_authorize_configuration_writes() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: rejected capability inventories never enter controller effects.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (host, card, bank) = host(&mut dma);
    drop(host);
    let mut registers = PortModel {
        card,
        bank: bank.clone(),
    };
    let (mut function, config) = configuration();
    // Vendor body includes a forged AER header at0x108; length0x40
    // protects the entire body against becoming another capability header.
    config.borrow_mut().bytes[0x100..0x104].copy_from_slice(&0x1081_000bu32.to_le_bytes());
    config.borrow_mut().bytes[0x104..0x108].copy_from_slice(&0x0400_0000u32.to_le_bytes());
    config.borrow_mut().bytes[0x108..0x10c].copy_from_slice(&0x0002_0001u32.to_le_bytes());
    let writes = bank.borrow().writes.len();
    assert!(
        pci::setup(
            &mut function,
            &mut registers,
            Clock {
                ticks_per_microsecond: CLOCK_TICKS_PER_US
            }
        )
        .is_err()
    );
    assert!(config.borrow().writes.is_empty());
    assert_eq!(bank.borrow().writes.len(), writes);
}

fn seeded_registers(seed: u32) -> PortModel {
    let card = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    Port(card.clone()).write16(HOST_CONTROL2, TUNED_CLOCK);
    let bank = Rc::new(RefCell::new(Bank {
        words: [WT, DRIVING, PLL, SSC, SW, MISC, BURST, TUNING, PARAMETERS]
            .into_iter()
            .map(|at| (at, seed))
            .collect(),
        writes: Vec::new(),
        wire: Vec::new(),
        ignore: None,
        first_polarity_bad: false,
        first_polarity_timeout: false,
        timeout_reset_stuck: false,
        both_polarities_timeout: false,
        v4_stuck: false,
        dma_allowed: false,
        dma_granted: false,
        dma_fail: false,
        dma_retire_stuck: false,
        dma_selection_stuck: false,
        normal_power_off: false,
        signal_at: None,
    }));
    PortModel { card, bank }
}

#[test]
#[ignore = "oracle: STELA_SDHCI_GLI_ORACLE"]
fn unchanged_linux_gl9750_phy_clocks_and_two_polarity_tuning_match_native() {
    extern crate std;
    let records = std::fs::read_to_string(
        std::env::var_os("STELA_SDHCI_GLI_ORACLE").expect("set STELA_SDHCI_GLI_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in records.lines() {
        let (kind, values) = line.split_once(' ').unwrap();
        let values: Vec<i64> = values
            .split_whitespace()
            .map(|word| word.parse().unwrap())
            .collect();
        match kind {
            "P" => {
                let mut registers = seeded_registers(values[0] as u32);
                initialize(&mut registers).unwrap();
                for (index, at) in [WT, DRIVING, PLL, SSC, SW, MISC, BURST, TUNING, PARAMETERS]
                    .into_iter()
                    .enumerate()
                {
                    assert_eq!(
                        registers.word(at),
                        values[index + 1] as u32,
                        "{line}, offset={at:x}"
                    );
                }
                assert_eq!(registers.read16(HOST_CONTROL2), values[10] as u16, "{line}");
            }
            "C" => {
                let mut registers = seeded_registers(values[0] as u32);
                registers
                    .bank
                    .borrow_mut()
                    .words
                    .entry(MISC)
                    .and_modify(|word| *word = (*word & !(1 << 26)) | (values[1] as u32) << 26);
                let timing = [Timing::Sdr12, Timing::Sdr25, Timing::Sdr50, Timing::Sdr104]
                    [(values[2] - 3) as usize];
                let source_hz = values[3] as u32;
                // Linux MMC clamps the SD208 request to the 200MHz host before
                // invoking its hook; the donor then explicitly selects205MHz.
                let requested = if timing == Timing::Sdr104 && source_hz == 200_000_000 {
                    208_000_000
                } else {
                    source_hz
                };
                let actual = set_clock(
                    &mut registers,
                    Clock {
                        ticks_per_microsecond: CLOCK_TICKS_PER_US,
                    },
                    2,
                    200_000_000,
                    timing,
                    requested,
                )
                .unwrap();
                assert_eq!(actual, values[4] as u32, "{line}");
                assert_eq!(registers.word(PLL), values[5] as u32, "{line}");
                assert_eq!(registers.word(SSC), values[6] as u32, "{line}");
                assert_eq!(registers.read16(CLOCK), values[7] as u16, "{line}");
            }
            "T" => {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: each complete native card initialization keeps its
                // command/payload allocations through final retirement.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut host, card, bank) = host(&mut dma);
                card.borrow_mut().tuning_iterations = values[0] as usize;
                bank.borrow_mut().first_polarity_bad = values[1] == 1;
                bank.borrow_mut().first_polarity_timeout = values[1] == 2;
                bank.borrow_mut().both_polarities_timeout = values[1] == 3;
                let result = host.poll();
                assert_eq!(result.is_ok(), values[2] == 0, "{line}");
                if values[2] == -110 {
                    assert!(matches!(&result, Err(BlockError::Timeout)), "{line}");
                } else if values[2] != 0 {
                    assert!(matches!(&result, Err(BlockError::Unsupported(_))), "{line}");
                }
                assert_eq!(
                    card.borrow()
                        .commands
                        .iter()
                        .filter(|(cmd, _, _)| *cmd == 19)
                        .count(),
                    values[3] as usize,
                    "{line}"
                );
                if result.is_ok() {
                    assert_eq!(
                        u32::from(bank.borrow().words[&MISC] & 8 != 0),
                        values[4] as u32,
                        "{line}"
                    );
                }
            }
            _ => panic!("unknown source record {line}"),
        }
        cases += 1;
    }
    assert_eq!(cases, 320);
}
