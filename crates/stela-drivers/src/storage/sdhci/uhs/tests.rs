//! Card/controller models exercise UHS initialization and block I/O.
use super::*;
use crate::{bus::dma::RegionAllocator, storage::sdhci::model::*};
use alloc::vec;

fn host(
    dma: &mut dyn DmaAllocator,
    functions: u8,
    caps2: u32,
    pio: bool,
) -> (Host, Rc<RefCell<Hardware>>) {
    let chip = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    {
        let mut c = chip.borrow_mut();
        c.caps = CAP_330 | CAP_HIGH_SPEED | 208 << 8 | if pio { 0 } else { CAP_ADMA2 | CAP_64 };
        c.caps2 = caps2;
        c.max_current = 200; // 3.3-V VCC supply supports 800 mA.
        c.uhs_functions = functions;
        c.scr[2] = 0x80;
    }
    let host = Host::new(
        Box::new(Port(chip.clone())),
        Clock {
            ticks_per_microsecond: CLOCK_TICKS_PER_US,
        },
        "standard SDHCI UHS model".into(),
        dma,
        Profile::Standard,
    )
    .unwrap();
    (host, chip)
}

#[test]
fn native_sdr12_25_50_104_switch_voltage_and_complete_pio_adma_io() {
    for (functions, caps, timing, hz, tuned) in [
        (1, CAP_SDR50, Timing::Sdr12, 20_800_000, false),
        (3, CAP_SDR50, Timing::Sdr25, 34_666_666, false),
        (7, CAP_SDR50, Timing::Sdr50, 52_000_000, false),
        (
            7,
            CAP_SDR50 | CAP_SDR50_TUNING,
            Timing::Sdr50,
            52_000_000,
            true,
        ),
        (15, CAP_SDR104, Timing::Sdr104, 208_000_000, true),
        // SDR104 host support implies SDR50 even without that separate bit.
        (7, CAP_SDR104, Timing::Sdr50, 52_000_000, false),
    ] {
        for pio in [false, true] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives the host, card and all DMA effects.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut host, chip) = host(&mut dma, functions, caps, pio);
            let mut card = host.poll().unwrap().unwrap();
            assert_eq!(card.info().signal_voltage, SignalVoltage::V1_8);
            assert_eq!(card.info().timing, timing);
            assert_eq!(card.info().clock_hz, hz);
            assert_eq!(card.info().bus_width, 4);
            assert_eq!(chip.borrow().tuning_commands, if tuned { 3 } else { 0 });
            let mut bytes = [0xa5; 1024];
            card.read(7, &mut bytes).unwrap();
            assert_eq!(bytes, chip.borrow().disk[7 * 512..9 * 512]);
            bytes.fill(0x69);
            card.write(20, &bytes).unwrap();
            card.flush().unwrap();
            assert_eq!(chip.borrow().disk[20 * 512..22 * 512], bytes);
            let c = chip.borrow();
            assert!(c.commands.iter().any(|(cmd, argument, _)| *cmd == 41
                && argument & (1 << 24 | 1 << 28) == 1 << 24 | 1 << 28));
            assert_eq!(
                c.commands.iter().filter(|(cmd, _, _)| *cmd == 11).count(),
                1
            );
            assert!(
                c.writes
                    .iter()
                    .filter(|(at, _, value)| *at == POWER && value & u32::from(POWER_ON) != 0)
                    .all(|(_, _, value)| *value == u32::from(POWER_330 | POWER_ON))
            );
        }
    }
}

#[test]
fn native_voltage_pin_clock_and_enable_failures_power_off_before_fresh_identify() {
    for fault in [
        VoltageFault::DatHighBefore,
        VoltageFault::OneDatLowBefore,
        VoltageFault::Enable,
        VoltageFault::StopClock,
        VoltageFault::DatLowAfter,
        VoltageFault::OneDatLowAfter,
    ] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: every model allocation remains live through recovery and fresh I/O.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, chip) = host(&mut dma, 15, CAP_SDR104, false);
        chip.borrow_mut().voltage_fault = Some(fault);
        let primary = host.poll().err().unwrap();
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, primary);
        assert_eq!(failure.restoration, None);
        assert_eq!(failure.retirement, None);
        assert!(!failure.quarantined);
        assert!(!chip.borrow().voltage_started, "actual VCC removal");
        assert!(
            !chip.borrow().commands.iter().any(|(cmd, _, _)| *cmd == 2),
            "no publication after failed voltage transition"
        );
        chip.borrow_mut().voltage_fault = None;
        let mut fresh = host.poll().unwrap().unwrap();
        let mut bytes = [0; 512];
        fresh.read(2, &mut bytes).unwrap();
        assert_eq!(bytes, chip.borrow().disk[1024..1536]);
    }
}

#[test]
fn native_uhs_failed_poweroff_keeps_primary_and_cleanup_and_quarantines_owner() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: quarantined ownership keeps backing through every refused operation.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, chip) = host(&mut dma, 15, CAP_SDR104, false);
    chip.borrow_mut().voltage_fault = Some(VoltageFault::Enable);
    chip.borrow_mut().power_off_stuck = true;
    let primary = host.poll().err().unwrap();
    let failure = host.last_failure().unwrap();
    assert_eq!(failure.primary, primary);
    assert!(matches!(
        failure.restoration,
        Some(BlockError::Unsupported(_))
    ));
    assert!(failure.quarantined);
    let accesses = (chip.borrow().reads, chip.borrow().writes.len());
    assert_eq!(host.poll().err(), Some(primary));
    assert_eq!((chip.borrow().reads, chip.borrow().writes.len()), accesses);
}

#[test]
fn native_tuning_needs_real_ready_completion_and_hardware_selected_clock() {
    for fault in 0..6 {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains owned even on command/removal/reset uncertainty.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, chip) = host(&mut dma, 15, CAP_SDR104, false);
        match fault {
            0 => chip.borrow_mut().tuning_no_clock = true,
            1 => chip.borrow_mut().tuning_iterations = 41,
            2 => chip.borrow_mut().silent = Some(19),
            3 => chip.borrow_mut().fail_command = Some((19, 1 << 21)),
            4 => chip.borrow_mut().remove_command = Some(19),
            5 => chip.borrow_mut().tuning_start_stuck = true,
            _ => unreachable!(),
        }
        let primary = host.poll().err().unwrap();
        assert_eq!(host.last_failure().unwrap().primary, primary);
        assert!(!chip.borrow().voltage_started);
        assert!(chip.borrow().tuning_commands <= 40);
        assert!(host.inner.borrow().tuned_at.is_none());
        assert!(host.inner.borrow().medium.is_none());
        // Shared card-protocol unwinding preserves the original electrical
        // cleanup report rather than attempting a second retirement.
        assert_eq!(host.last_failure().unwrap().restoration, None);
    }
}

#[test]
fn native_cmd11_lost_response_after_electrical_effect_still_removes_card_power() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: the failed command keeps its original allocations through cleanup.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, chip) = host(&mut dma, 15, CAP_SDR104, false);
    chip.borrow_mut().silence_voltage_response = true;
    assert_eq!(host.poll().err(), Some(BlockError::Timeout));
    assert_eq!(host.last_failure().unwrap().primary, BlockError::Timeout);
    assert!(!chip.borrow().voltage_started);
    assert!(!chip.borrow().commands.iter().any(|(cmd, _, _)| *cmd == 2));
    chip.borrow_mut().silence_voltage_response = false;
    assert!(host.poll().unwrap().is_some());
}

#[test]
fn native_retuning_precedes_live_io_and_failed_retuning_permanently_fences_aliases() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: model/allocations outlive both old card aliases.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, chip) = host(&mut dma, 15, CAP_SDR104 | 1 << 8, false);
    let mut card = host.poll().unwrap().unwrap();
    let mut old = card.clone();
    host.inner.borrow_mut().tuned_at = Some(0);
    let before = chip.borrow().commands.len();
    let mut bytes = [0xa5; 512];
    card.read(3, &mut bytes).unwrap();
    assert_eq!(chip.borrow().commands[before].0, 19);
    assert_eq!(chip.borrow().tuning_commands, 6);
    host.inner.borrow_mut().tuned_at = Some(0);
    chip.borrow_mut().tuning_no_clock = true;
    bytes.fill(0xa5);
    let primary = card.read(4, &mut bytes).unwrap_err();
    assert_eq!(host.last_failure().unwrap().primary, primary);
    assert_eq!(bytes, [0xa5; 512]);
    let accesses = (
        chip.borrow().reads,
        chip.borrow().writes.len(),
        chip.borrow().commands.len(),
    );
    assert_eq!(
        card.read(4, &mut bytes),
        Err(BlockError::Unsupported(STALE))
    );
    assert_eq!(old.write(4, &bytes), Err(BlockError::Unsupported(STALE)));
    assert_eq!(old.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(
        (
            chip.borrow().reads,
            chip.borrow().writes.len(),
            chip.borrow().commands.len()
        ),
        accesses
    );
}

#[test]
fn native_unsupported_retune_modes_and_vendor_profiles_do_not_negotiate_unsupported_timing() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: one live model owns this region throughout negotiation.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, chip) = host(&mut dma, 15, CAP_SDR104 | CAP_SDR50_TUNING | 1 << 14, false);
    let card = host.poll().unwrap().unwrap();
    assert_eq!(card.info().timing, Timing::Sdr25);
    assert_eq!(chip.borrow().tuning_commands, 0);
    for profile in [
        Profile::Ene712,
        Profile::Ene714,
        Profile::IntelQuark,
        Profile::IntelMrst0,
        Profile::IntelMrstOther,
        Profile::O2Legacy,
    ] {
        let mut engine = host.inner.borrow_mut();
        engine.profile = profile;
        assert!(!engine.uhs_modes().available());
    }
}

#[test]
fn native_uhs_timing_write_without_acknowledgment_never_publishes_a_card() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: native command/data allocations remain live after failed setup.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, chip) = host(&mut dma, 15, CAP_SDR104, false);
    chip.borrow_mut().uhs_timing_stuck = true;
    let primary = host.poll().err().unwrap();
    assert_eq!(host.last_failure().unwrap().primary, primary);
    assert!(host.inner.borrow().medium.is_none());
    assert!(!chip.borrow().voltage_started);
    assert_eq!(chip.borrow().tuning_commands, 0);
}

#[test]
#[ignore = "oracle: STELA_SDHCI_UHS_ORACLE"]
fn unchanged_linux_uhs_signaling_and_tuning_decisions_match_native_operations() {
    extern crate std;
    let records = std::fs::read_to_string(
        std::env::var_os("STELA_SDHCI_UHS_ORACLE").expect("set STELA_SDHCI_UHS_ORACLE"),
    )
    .unwrap();
    let mut count = 0;
    for line in records.lines() {
        let (kind, values) = line.split_once(' ').unwrap();
        let values: Vec<i64> = values
            .split_whitespace()
            .map(|word| word.parse().unwrap())
            .collect();
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: the per-record controller and card retire before this live
        // allocation is dropped, including all source-modeled failure records.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, chip) = host(&mut dma, 15, CAP_SDR104, false);
        match kind {
            "T" => {
                let _card = host.poll().unwrap().unwrap();
                let mut engine = host.inner.borrow_mut();
                let clock = engine.registers.read16(CLOCK);
                engine.registers.write16(CLOCK, clock & !CLOCK_CARD);
                engine
                    .registers
                    .write16(HOST_CONTROL2, values[0] as u16 | SIGNAL_180);
                engine.registers.write16(CLOCK, clock);
                let timing = [Timing::Sdr12, Timing::Sdr25, Timing::Sdr50, Timing::Sdr104]
                    [values[1] as usize];
                engine.set_uhs_timing(timing).unwrap();
                assert_eq!(
                    engine.registers.read16(HOST_CONTROL2),
                    values[2] as u16,
                    "{line}"
                );
            }
            "C" => {
                chip.borrow_mut().tuning_iterations = values[0] as usize;
                chip.borrow_mut().tuning_no_clock = values[1] != 0;
                if values[2] != 0 {
                    chip.borrow_mut().silent = Some(19);
                }
                let result = host.poll();
                assert_eq!(result.is_ok(), values[3] == 0, "{line}");
                assert_eq!(
                    host.inner.borrow().tuned_at.is_some(),
                    values[3] == 0,
                    "{line}"
                );
                assert_eq!(
                    chip.borrow()
                        .commands
                        .iter()
                        .filter(|(cmd, _, _)| *cmd == 19)
                        .count(),
                    values[4] as usize,
                    "{line}"
                );
            }
            _ => panic!("unknown oracle record {line}"),
        }
        count += 1;
    }
    assert_eq!(count, 115);
}
