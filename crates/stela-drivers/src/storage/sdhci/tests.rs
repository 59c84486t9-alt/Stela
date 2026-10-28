//! Real controller/card-model initialization, data and lifecycle regressions.
use super::{model::*, *};
use crate::bus::dma::RegionAllocator;
mod hs;

fn host(
    dma: &mut dyn DmaAllocator,
    kind: Kind,
    sector: bool,
    pio: bool,
) -> (Host, Rc<RefCell<Hardware>>) {
    let model = Rc::new(RefCell::new(Hardware::new(kind, sector)));
    if pio {
        model.borrow_mut().caps &= !CAP_ADMA2;
    }
    let host = Host::new(
        Box::new(Port(model.clone())),
        Clock {
            ticks_per_microsecond: CLOCK_TICKS_PER_US,
        },
        "SDHCI native model".into(),
        dma,
        Profile::Standard,
    )
    .unwrap();
    (host, model)
}

#[test]
fn started_transfers_finish_at_later_looks_like_waited_ones() {
    for pio in [false, true] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing retains every native DMA descriptor and payload.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, model) = host(&mut dma, Kind::Sd, true, pio);
        let mut card = host.poll().unwrap().unwrap();
        let finish = |card: &mut Card, tag| loop {
            if let Some(finished) = card.finish(tag) {
                return finished;
            }
        };
        // Past one bounce buffer: two parts, each with STOP_TRANSMISSION.
        let bytes = 2 * TRANSFER_BYTES;
        let data = vec![0x3c; bytes];
        let tag = card
            .start(Command::Write {
                lba: 16,
                data: data.clone(),
                fua: false,
            })
            .unwrap();
        assert!(!card.room());
        assert_eq!(finish(&mut card, tag), Ok(None));
        assert!(card.room());
        assert_eq!(model.borrow().disk[16 * 512..16 * 512 + bytes], data[..]);
        let tag = card.start(Command::Read { lba: 15, bytes }).unwrap();
        let read = finish(&mut card, tag).unwrap().unwrap();
        assert_eq!(read, model.borrow().disk[15 * 512..15 * 512 + bytes]);
        assert_eq!(
            model
                .borrow()
                .commands
                .iter()
                .filter(|(cmd, _, _)| *cmd == 12)
                .count(),
            4
        );
    }
}

#[test]
fn native_sd_and_mmc_initialize_actual_registers_and_complete_pio_and_adma_io() {
    for kind in [Kind::Sd, Kind::Mmc] {
        for sector in [false, true] {
            for pio in [false, true] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: backing retains every native DMA descriptor and payload.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut host, model) = host(&mut dma, kind, sector, pio);
                let mut card = host.poll().unwrap().unwrap();
                assert_eq!(card.identity().transport, Transport::SdMmc);
                assert_eq!(card.identity().blocks, 4096);
                assert_eq!(card.info().kind, kind);
                assert_eq!(card.info().bus_width, 4);
                assert_eq!(card.info().clock_hz, 50_000_000);
                assert_eq!(card.identity().serial, "42-12345678");
                assert_eq!(
                    card.identity().model,
                    if kind == Kind::Sd { "STELA" } else { "STELA1" }
                );
                assert!(host.poll().unwrap().is_none());
                let mut bytes = vec![0xa5; 128 * 512];
                card.read(3, &mut bytes).unwrap();
                assert_eq!(bytes, model.borrow().disk[3 * 512..131 * 512]);
                bytes.fill(0x6e);
                card.write(200, &bytes).unwrap();
                card.flush().unwrap();
                assert_eq!(model.borrow().disk[200 * 512..328 * 512], bytes);
                let mut last = [0; 512];
                card.read(4095, &mut last).unwrap();
                assert_eq!(last, &model.borrow().disk[4095 * 512..]);
                let m = model.borrow();
                assert!(
                    m.commands.iter().any(|(cmd, arg, _)| *cmd == 17
                        && *arg == if sector { 4095 } else { 4095 * 512 })
                );
                assert_eq!(
                    m.writes.iter().find(|(at, _, _)| *at == COMMAND).unwrap().1,
                    2
                );
                assert!(m.commands.iter().any(|(cmd, _, _)| *cmd == 12));
                if kind == Kind::Mmc {
                    assert!(
                        m.commands
                            .iter()
                            .any(|(cmd, arg, _)| *cmd == 6 && *arg == 3 << 24 | 32 << 16 | 1 << 8)
                    );
                }
            }
        }
    }
}

#[test]
fn removed_and_replaced_card_never_revives_old_disk_or_clone() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: removal retains original descriptors and bounce allocations.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, model) = host(&mut dma, Kind::Sd, true, false);
    let mut old = host.poll().unwrap().unwrap();
    let mut clone = old.clone();
    model.borrow_mut().present = false;
    assert!(host.poll().unwrap().is_none());
    model.borrow_mut().replace();
    let mut fresh = host.poll().unwrap().unwrap();
    let before = (
        model.borrow().reads,
        model.borrow().writes.len(),
        model.borrow().commands.len(),
    );
    for stale in [&mut old, &mut clone] {
        let mut poison = [0x95; 512];
        assert_eq!(
            stale.read(0, &mut poison),
            Err(BlockError::Unsupported(STALE))
        );
        assert_eq!(poison, [0x95; 512]);
        assert_eq!(stale.write(0, &poison), Err(BlockError::Unsupported(STALE)));
        assert_eq!(stale.flush_cache(), Err(BlockError::Unsupported(STALE)));
    }
    assert_eq!(
        (
            model.borrow().reads,
            model.borrow().writes.len(),
            model.borrow().commands.len()
        ),
        before
    );
    let mut bytes = [0; 512];
    fresh.read(0, &mut bytes).unwrap();
    assert_eq!(bytes, [0x3c; 512]);
}

#[test]
fn failed_completion_reset_and_removal_fence_dma_before_any_reuse() {
    for fault in 0..5 {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: even uncertain DMA keeps every byte allocated through the test.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, model) = host(&mut dma, Kind::Sd, true, false);
        let mut card = host.poll().unwrap().unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => m.silent = Some(17),
                1 => m.data_error = true,
                2 => m.fail_after_data = true,
                3 => {
                    m.silent = Some(17);
                    m.reset_stuck = true;
                }
                4 => m.remove_command = Some(17),
                _ => unreachable!(),
            }
        }
        let mut poison = [0x95; 512];
        assert!(card.read(0, &mut poison).is_err());
        assert_eq!(poison, [0x95; 512]);
        let before = (
            model.borrow().reads,
            model.borrow().writes.len(),
            model.borrow().commands.len(),
        );
        assert_eq!(
            card.read(0, &mut poison),
            Err(BlockError::Unsupported(STALE))
        );
        assert_eq!(
            (
                model.borrow().reads,
                model.borrow().writes.len(),
                model.borrow().commands.len()
            ),
            before
        );
        if fault == 3 {
            assert!(host.poll().is_err());
            assert_eq!(
                (
                    model.borrow().reads,
                    model.borrow().writes.len(),
                    model.borrow().commands.len()
                ),
                before
            );
        }
    }
}

#[test]
fn invalid_geometry_readonly_and_missing_base_clock_refuse_before_commands() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: one modeled controller owns the whole live allocation region.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, model) = host(&mut dma, Kind::Sd, true, true);
    model.borrow_mut().writable = false;
    let mut card = host.poll().unwrap().unwrap();
    let commands = model.borrow().commands.len();
    assert_eq!(card.write(0, &[0; 512]), Err(BlockError::ReadOnly));
    assert!(matches!(
        card.read(0, &mut [0; 511]),
        Err(BlockError::Misaligned { .. })
    ));
    assert!(matches!(
        card.read(4096, &mut [0; 512]),
        Err(BlockError::OutOfRange { .. })
    ));
    assert_eq!(model.borrow().commands.len(), commands);
    model.borrow_mut().caps &= !(0xff << 8);
    model.borrow_mut().replace();
    assert!(host.poll().is_err());
    assert_eq!(model.borrow().commands.len(), commands);
}

#[test]
fn legacy_sd_and_mmc_bus_width_validation_do_not_invent_capabilities() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: both controllers retain disjoint descriptor and payload ranges.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut sd, model) = host(&mut dma, Kind::Sd, false, true);
    model.borrow_mut().legacy = true;
    model.borrow_mut().scr = [0, 1, 0, 0, 0, 0, 0, 0];
    let card = sd.poll().unwrap().unwrap();
    assert_eq!(card.info().bus_width, 1);
    let (mut mmc, model) = host(&mut dma, Kind::Mmc, true, true);
    model.borrow_mut().corrupt_bus_width = true;
    assert!(mmc.poll().is_err());
    assert!(mmc.inner.borrow().medium.is_none());
    assert!(
        model
            .borrow()
            .commands
            .iter()
            .all(|(cmd, _, _)| !matches!(*cmd, 17 | 18 | 24 | 25))
    );
}

#[test]
fn clock_divisors_never_exceed_requested_frequency_or_wrap_fields() {
    for version in [0, 1, 2, 3, 4, 5] {
        for base in [1_000_000, 25_000_000, 50_000_000, 100_000_000, 255_000_000] {
            for requested in [
                100_000, 400_000, 20_000_000, 25_000_000, 50_000_000, 52_000_000,
            ] {
                if let Ok((field, actual)) = clock_divisor(version, base, requested) {
                    let divisor = if field == 0 { 1 } else { u32::from(field) * 2 };
                    assert!(base.div_ceil(divisor) <= requested);
                    assert_eq!(actual, base / divisor);
                    assert!(field <= if version >= 2 { 1023 } else { 128 });
                }
            }
        }
    }
}

#[test]
fn empty_socket_is_retained_and_generation_overflow_never_wraps() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: the retained empty host and later card share one live fixture RAM.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, model) = host(&mut dma, Kind::Sd, true, true);
    model.borrow_mut().present = false;
    assert!(host.poll().unwrap().is_none());
    assert!(model.borrow().commands.is_empty());
    model.borrow_mut().replace();
    assert!(host.poll().unwrap().is_some());
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(generation_from(&counter), Ok(u64::MAX - 1));
    assert!(generation_from(&counter).is_err());
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
}

#[test]
#[ignore = "oracle: STELA_SDHCI_ORACLE"]
fn unchanged_linux_clock_divisors_and_card_capacity_match_native_decoders() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var_os("STELA_SDHCI_ORACLE").expect("set STELA_SDHCI_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let (kind, values) = line.split_once(' ').unwrap();
        let values: Vec<u64> = values
            .split_whitespace()
            .map(|word| word.parse().unwrap())
            .collect();
        match kind {
            "C" => {
                let (version, base, requested) =
                    (values[0] as u8, values[1] as u32, values[2] as u32);
                match clock_divisor(version, base, requested) {
                    Ok((field, actual)) => {
                        let encoded = (field & 0xff) << 8 | (field & 0x300) >> 2;
                        assert_eq!(
                            (u64::from(encoded), u64::from(actual)),
                            (values[3], values[4]),
                            "{line}"
                        );
                    }
                    Err(_) => assert!(values[4] > u64::from(requested), "{line}"),
                }
            }
            "S" => {
                let (structure, size, block) =
                    (values[0] as u32, values[1] as u32, values[2] as u32);
                let mut csd = 0u128;
                put(&mut csd, 126, 2, structure);
                put(&mut csd, 96, 8, 0x32);
                put(&mut csd, 84, 12, 0x414);
                put(&mut csd, 80, 4, block);
                put(&mut csd, 22, 4, block);
                if structure == 0 {
                    put(&mut csd, 62, 12, size);
                    put(&mut csd, 47, 3, 3);
                } else {
                    put(&mut csd, 48, 22, size);
                }
                let words = core::array::from_fn(|i| (csd >> ((3 - i) * 32)) as u32);
                assert_eq!(values[3], 0);
                let (blocks, hz) = protocol::capacity(Kind::Sd, words).unwrap();
                assert_eq!((blocks, u64::from(hz)), (values[4], values[5]), "{line}");
            }
            _ => panic!("unknown oracle record"),
        }
        cases += 1;
    }
    assert_eq!(cases, 948);
}

#[test]
fn sd_command_class_and_live_write_tab_follow_actual_card_authority() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: both fixtures retain disjoint buffers in this exclusive backing.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, model) = host(&mut dma, Kind::Sd, true, true);
    let mut card = host.poll().unwrap().unwrap();
    model.borrow_mut().writable = false;
    let before = model.borrow().commands.len();
    assert_eq!(card.write(0, &[0; 512]), Err(BlockError::ReadOnly));
    assert_eq!(model.borrow().commands.len(), before);
    model.borrow_mut().writable = true;
    model.borrow_mut().replace();
    put(&mut model.borrow_mut().csd, 84, 12, 1 << 2);
    let mut replacement = host.poll().unwrap().unwrap();
    assert!(replacement.identity().read_only);
    assert_eq!(replacement.write(0, &[0; 512]), Err(BlockError::ReadOnly));
}

#[test]
fn completed_host_data_does_not_override_actual_card_error_status() {
    for status in [1 << 18, 1 << 17, 1 << 3] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: device-completed DMA remains retained even when card status refuses it.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, model) = host(&mut dma, Kind::Sd, true, false);
        let mut card = host.poll().unwrap().unwrap();
        model.borrow_mut().card_status_error = Some((17, status));
        let mut bytes = [0x95; 512];
        assert!(
            matches!(card.read(0,&mut bytes),Err(BlockError::Device{status:actual}) if actual & status!=0)
        );
        assert_eq!(bytes, [0x95; 512]);
        assert_eq!(card.flush_cache(), Err(BlockError::Unsupported(STALE)));
    }
}

#[test]
fn mmc_bus_width_validation_checks_every_source_immutable_field() {
    for index in [
        160, 181, 192, 194, 196, 217, 221, 223, 224, 229, 230, 231, 232, 212, 213, 214, 215, 200,
        201, 202, 203, 236, 237, 238, 239, 253,
    ] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: failed validation keeps its native DMA allocations retained.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, model) = host(&mut dma, Kind::Mmc, true, true);
        model.borrow_mut().corrupt_bus_field = Some(index);
        assert!(host.poll().is_err(), "unchecked EXT_CSD field {index}");
        assert!(host.inner.borrow().medium.is_none());
    }
}

#[test]
fn mmc_power_off_notification_fences_aliases_without_post_notify_status_commands() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: notified cards keep all former payload/descriptor DMA retained.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, model) = host(&mut dma, Kind::Mmc, true, false);
    let mut card = host.poll().unwrap().unwrap();
    let mut clone = card.clone();
    card.shutdown(true).unwrap();
    let m = model.borrow();
    assert!(!m.command_after_notification);
    assert_eq!(
        m.commands.last().map(|(cmd, arg, _)| (*cmd, *arg)),
        Some((6, 3 << 24 | 34 << 16 | 3 << 8))
    );
    assert_eq!(
        m.writes
            .iter()
            .rev()
            .find(|(at, _, _)| *at == POWER)
            .map(|(_, _, value)| *value),
        Some(0)
    );
    let before = (m.reads, m.writes.len(), m.commands.len());
    drop(m);
    assert_eq!(clone.flush(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(
        (
            model.borrow().reads,
            model.borrow().writes.len(),
            model.borrow().commands.len()
        ),
        before
    );
    assert!(host.poll().unwrap().is_some());
    assert_eq!(card.flush(), Err(BlockError::Unsupported(STALE)));
}

#[test]
fn initial_card_clock_runs_before_cmd0_and_unqualified_1v8_hosts_refuse() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: both capability profiles retain disjoint fixture DMA allocations.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut host, model) = host(&mut dma, Kind::Sd, true, true);
    host.poll().unwrap().unwrap();
    assert!(model.borrow().initial_clock_seen.unwrap() >= 1000 * CLOCK_TICKS_PER_US);
    let unclocked = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    assert!(matches!(
        Host::new(
            Box::new(Port(unclocked.clone())),
            Clock {
                ticks_per_microsecond: 0
            },
            "uncalibrated".into(),
            &mut dma,
            Profile::Standard,
        ),
        Err(BlockError::Unsupported(_))
    ));
    assert!(unclocked.borrow().writes.is_empty());
    assert_eq!(unclocked.borrow().reads, 0);
    let model = Rc::new(RefCell::new(Hardware::new(Kind::Mmc, true)));
    model.borrow_mut().caps = CAP_180 | 100 << 8;
    assert!(matches!(
        Host::new(
            Box::new(Port(model.clone())),
            Clock {
                ticks_per_microsecond: CLOCK_TICKS_PER_US
            },
            "unqualified1.8V".into(),
            &mut dma,
            Profile::Standard,
        ),
        Err(BlockError::Unsupported(_))
    ));
    assert!(model.borrow().commands.is_empty());
    assert!(
        model
            .borrow()
            .writes
            .iter()
            .all(|(at, _, _)| !matches!(*at, POWER | HOST_CONTROL2 | COMMAND))
    );
}

#[test]
fn completed_data_with_perpetually_not_ready_card_retires_publication() {
    for reset_stuck in [false, true] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: non-ready/error paths never release the original DMA region.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, model) = host(&mut dma, Kind::Sd, true, false);
        let mut card = host.poll().unwrap().unwrap();
        model.borrow_mut().never_ready = true;
        model.borrow_mut().reset_stuck = reset_stuck;
        // Keep the admitted model's actual finite clock. Data completion is
        // observed first; repeated not-ready CMD13 responses must consume the
        // real five-second logical card-status budget before retirement.
        let clock = host.inner.borrow().clock;
        let started = clock.try_start().unwrap();
        let first = model.borrow().commands.len();
        let mut bytes = [0x95; 512];
        assert_eq!(card.read(0, &mut bytes), Err(BlockError::Timeout));
        assert!(clock.try_elapsed_us(started).unwrap() >= 5_000_000);
        assert!(
            model.borrow().commands[first..]
                .iter()
                .any(|(cmd, _, _)| *cmd == 17)
        );
        assert!(
            model.borrow().commands[first..]
                .iter()
                .filter(|(cmd, _, _)| *cmd == 13)
                .count()
                > 1
        );
        assert_eq!(host.last_failure().unwrap().primary, BlockError::Timeout);
        assert_eq!(bytes, [0x95; 512]);
        let before = (
            model.borrow().reads,
            model.borrow().writes.len(),
            model.borrow().commands.len(),
        );
        assert_eq!(
            card.read(0, &mut bytes),
            Err(BlockError::Unsupported(STALE))
        );
        assert_eq!(
            (
                model.borrow().reads,
                model.borrow().writes.len(),
                model.borrow().commands.len()
            ),
            before
        );
        if reset_stuck {
            assert!(host.poll().is_err());
            assert_eq!(
                (
                    model.borrow().reads,
                    model.borrow().writes.len(),
                    model.borrow().commands.len()
                ),
                before
            );
        }
    }
}

#[test]
fn mmc_reserved_specifications_refuse_and_legacy_cid_keeps_manufacturer24_bits() {
    for version in [5, 15] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: rejected card discovery retains its unexposed DMA allocations.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut host, model) = host(&mut dma, Kind::Mmc, true, true);
        put(&mut model.borrow_mut().csd, 122, 4, version);
        assert_eq!(
            host.poll().err(),
            Some(BlockError::Unsupported(
                "MMC reserved CSD specification version"
            ))
        );
        assert!(
            model
                .borrow()
                .commands
                .iter()
                .all(|(cmd, _, flags)| *cmd != 8 || flags & 0x20 == 0)
        );
    }
    for version in [0, 1] {
        for manufacturer in [0xaa1122, 0xaa3344] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: each legacy card owns this iteration's retained register/PIO RAM.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut host, model) = host(&mut dma, Kind::Mmc, false, true);
            {
                let mut m = model.borrow_mut();
                put(&mut m.csd, 122, 4, version);
                m.cid = 0;
                put(&mut m.cid, 104, 24, manufacturer);
                for (i, byte) in b"LEGACY1".iter().enumerate() {
                    put(&mut m.cid, 96 - i as u32 * 8, 8, u32::from(*byte));
                }
                put(&mut m.cid, 16, 24, 0x112233);
            }
            let card = host.poll().unwrap().unwrap();
            assert_eq!(card.identity().serial, format!("{manufacturer:06x}-112233"));
            assert_eq!(card.identity().model, "LEGACY1");
            assert_eq!(card.info().bus_width, 1);
        }
    }
}

#[test]
fn ene_exact_pci_profiles_apply_real_power_pio_and_ios_reset_sequences() {
    for device in [0x0550, 0x0551, 0x0750, 0x0751] {
        for kind in [Kind::Sd, Kind::Mmc] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: each real PIO engine owns this retained native DMA region.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let model = Rc::new(RefCell::new(Hardware::new(kind, true)));
            {
                let mut m = model.borrow_mut();
                // Physical device rules are independent of the driver's profile.
                // Advertised ADMA stays set: using it must actually fail here.
                m.single_power_write = true;
                m.dma_broken = true;
                m.reset_after_settings = device >= 0x0700;
            }
            let mut host = Host::new(
                Box::new(Port(model.clone())),
                Clock {
                    ticks_per_microsecond: CLOCK_TICKS_PER_US,
                },
                format!("ENE {device:04x}"),
                &mut dma,
                Profile::select(0x1524, device),
            )
            .unwrap();
            let mut card = host.poll().unwrap().unwrap();
            let mut bytes = [0xa5; 1024];
            card.read(3, &mut bytes).unwrap();
            assert_eq!(bytes, model.borrow().disk[3 * 512..5 * 512]);
            bytes.fill(0x3b);
            card.write(5, &bytes).unwrap();
            card.flush().unwrap();
            assert_eq!(bytes, model.borrow().disk[5 * 512..7 * 512]);
            let m = model.borrow();
            assert_eq!(host.info().capabilities & CAP_ADMA2, CAP_ADMA2);
            assert!(
                m.writes
                    .iter()
                    .all(|(at, _, value)| *at != TRANSFER_MODE || value & u32::from(DMA) == 0)
            );
            assert!(
                m.writes
                    .iter()
                    .all(|(at, _, _)| !matches!(*at, ADMA_ADDRESS | ADMA_ADDRESS_HIGH))
            );
            assert!(m.writes.iter().all(|(at, _, value)| *at != POWER
                || *value == 0
                || value & u32::from(POWER_ON) != 0));
            let resets = m
                .writes
                .iter()
                .filter(|(at, _, value)| {
                    *at == RESET && *value == u32::from(RESET_COMMAND | RESET_DATA)
                })
                .count();
            assert!(if device >= 0x0700 {
                resets >= 5
            } else {
                resets == usize::from(kind == Kind::Mmc)
            });
            drop(m);
            let mut old = card.clone();
            card.shutdown(true).unwrap();
            if device >= 0x0700 {
                assert!(
                    !model.borrow().settings_dirty,
                    "missing trailing power-off IOS reset"
                );
            }
            assert!(host.poll().unwrap().is_some());
            let before = (
                model.borrow().reads,
                model.borrow().writes.len(),
                model.borrow().commands.len(),
            );
            assert_eq!(old.flush_cache(), Err(BlockError::Unsupported(STALE)));
            assert_eq!(
                (
                    model.borrow().reads,
                    model.borrow().writes.len(),
                    model.borrow().commands.len()
                ),
                before
            );
        }
    }
    assert_eq!(Profile::select(0x1524, 0x0510), Profile::Standard);
    assert_eq!(Profile::select(0x1524, 0x0752), Profile::Standard);
    assert_eq!(Profile::select(0x1525, 0x0750), Profile::Standard);
}

#[test]
fn ene_failed_post_settings_reset_retires_old_aliases_and_pins_controller() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: uncertain device retirement retains all original payload memory.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let model = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    {
        let mut m = model.borrow_mut();
        m.single_power_write = true;
        m.dma_broken = true;
        m.reset_after_settings = true;
    }
    let mut host = Host::new(
        Box::new(Port(model.clone())),
        Clock {
            ticks_per_microsecond: CLOCK_TICKS_PER_US,
        },
        "ENE fault".into(),
        &mut dma,
        Profile::select(0x1524, 0x0750),
    )
    .unwrap();
    let mut old = host.poll().unwrap().unwrap();
    let mut clone = old.clone();
    model.borrow_mut().replace();
    model.borrow_mut().fail_settings_reset = true;
    assert!(host.poll().is_err());
    let m = model.borrow();
    let before = (m.reads, m.writes.len(), m.commands.len());
    drop(m);
    let mut bytes = [0x95; 512];
    assert_eq!(old.read(0, &mut bytes), Err(BlockError::Unsupported(STALE)));
    assert_eq!(bytes, [0x95; 512]);
    assert_eq!(clone.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert!(host.poll().is_err());
    assert_eq!(
        (
            model.borrow().reads,
            model.borrow().writes.len(),
            model.borrow().commands.len()
        ),
        before
    );
}

#[test]
fn intel_exact_profiles_apply_declared_wiring_without_hispd_or_broken_adma() {
    for device in [0x08a7, 0x0807, 0x0808, 0x084f] {
        for kind in [Kind::Sd, Kind::Mmc] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: each modeled Intel controller owns these live DMA pages.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let model = Rc::new(RefCell::new(Hardware::new(kind, true)));
            {
                let mut m = model.borrow_mut();
                m.adma_broken = device != 0x08a7;
                m.reject_high_speed_bit = true;
                m.wired_width = if device == 0x0807 { 8 } else { 4 };
                // The source board declaration supplies the authority even if
                // the raw controller's separate capability bit is absent.
                m.caps &= !CAP_8BIT;
                m.ext[202] = 0xb3;
            }
            let profile = Profile::select(0x8086, device);
            let mut host = Host::new(
                Box::new(Port(model.clone())),
                Clock {
                    ticks_per_microsecond: CLOCK_TICKS_PER_US,
                },
                format!("Intel {device:04x}"),
                &mut dma,
                profile,
            )
            .unwrap();
            let mut card = host.poll().unwrap().unwrap();
            let width = if device == 0x0807 && kind == Kind::Mmc {
                8
            } else {
                4
            };
            assert_eq!(card.info().bus_width, width);
            assert_eq!(card.info().clock_hz, 50_000_000);
            assert_eq!(host.info().capabilities & CAP_8BIT, 0);
            let mut bytes = [0xa5; 1024];
            card.read(5, &mut bytes).unwrap();
            assert_eq!(bytes, model.borrow().disk[5 * 512..7 * 512]);
            bytes.fill(0xb5);
            card.write(8, &bytes).unwrap();
            card.flush().unwrap();
            assert_eq!(bytes, model.borrow().disk[8 * 512..10 * 512]);
            let m = model.borrow();
            assert!(m.writes.iter().all(|(at,_,value)| *at != HOST_CONTROL || value & u32::from(HIGH_SPEED) == 0));
            assert_eq!(
                m.writes.iter().any(|(at, _, _)| *at == ADMA_ADDRESS),
                device == 0x08a7
            );
            if kind == Kind::Mmc {
                assert_eq!(
                    card.info().ext_csd.as_ref().unwrap()[183],
                    if width == 8 { 2 } else { 1 }
                );
                assert_eq!(
                    card.info().ext_csd.as_ref().unwrap()[187],
                    if width == 8 { 11 } else { 3 }
                );
                assert_eq!(card.info().ext_csd.as_ref().unwrap()[185], 1);
            }
            drop(m);
            card.shutdown(true).unwrap();
            assert!(host.poll().unwrap().is_some());
            for reported in 1..=8 {
                assert_eq!(
                    profile.slots(reported),
                    if matches!(device, 0x0808 | 0x084f) {
                        1
                    } else {
                        reported
                    }
                );
            }
        }
    }
    assert_eq!(Profile::select(0x8086, 0x0809), Profile::Standard);
    assert_eq!(Profile::select(0x8087, 0x0807), Profile::Standard);
}

#[test]
fn intel_wide_bus_crc_failure_never_publishes_or_revives_legacy_alias() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: CRC failure keeps both the former and attempted DMA state retained.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let model = Rc::new(RefCell::new(Hardware::new(Kind::Mmc, false)));
    {
        let mut m = model.borrow_mut();
        m.adma_broken = true;
        m.reject_high_speed_bit = true;
        m.wired_width = 4;
        put(&mut m.csd, 122, 4, 3);
    }
    let mut host = Host::new(
        Box::new(Port(model.clone())),
        Clock {
            ticks_per_microsecond: CLOCK_TICKS_PER_US,
        },
        "Intel faulty wiring".into(),
        &mut dma,
        Profile::select(0x8086, 0x0807),
    )
    .unwrap();
    let mut old = host.poll().unwrap().unwrap();
    assert_eq!(old.info().bus_width, 1);
    model.borrow_mut().replace();
    put(&mut model.borrow_mut().csd, 122, 4, 4);
    assert!(matches!(host.poll(),Err(BlockError::Device{status}) if status & (1<<21)!=0));
    assert!(host.inner.borrow().medium.is_none());
    let before = (
        model.borrow().reads,
        model.borrow().writes.len(),
        model.borrow().commands.len(),
    );
    let mut bytes = [0x95; 512];
    assert_eq!(old.read(0, &mut bytes), Err(BlockError::Unsupported(STALE)));
    assert_eq!(bytes, [0x95; 512]);
    assert_eq!(
        (
            model.borrow().reads,
            model.borrow().writes.len(),
            model.borrow().commands.len()
        ),
        before
    );
}
