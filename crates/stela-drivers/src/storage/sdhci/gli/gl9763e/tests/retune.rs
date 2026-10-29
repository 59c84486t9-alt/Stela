//! Explicit original-card tuning with downgrade/CMD21/restore and faults.
use super::*;

fn fast_card(
    dma: &mut dyn DmaAllocator,
    mode: u8,
) -> (Host, Card, Rc<RefCell<Hardware>>, Rc<RefCell<State>>) {
    let (mut owner, card, state) = owner();
    initialize_owner(&mut owner).unwrap();
    {
        let mut hardware = card.borrow_mut();
        hardware.ext[196] = match mode {
            0 => 0x13,
            3 => 0x51,
            4 => 3,
            _ => 0x53,
        };
        hardware.ext[184] = u8::from(mode == 2);
        hardware.mmc_fast_checks = mode != 4;
        hardware.caps |= CAP_ADMA2 | 1 << 27;
    }
    let mut host = Host::new(
        Box::new(owner),
        clock(),
        "explicit MMC retune".into(),
        dma,
        Profile::Gli9763e,
    )
    .unwrap();
    let disk = host.poll().unwrap().unwrap();
    (host, disk, card, state)
}

#[test]
fn explicit_hs200_and_hs400_retune_complete_real_cmd21_then_changed_adma_io() {
    for mode in [0, 1, 3] {
        let hs400 = mode != 0;
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all original-controller descriptor/payload ranges remain live.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (_host, mut disk, card, _) = fast_card(&mut dma, mode);
        let before = card.borrow().tuning_commands;
        if hs400 {
            card.borrow_mut().mmc_retune_phase = Some(0);
        }
        disk.retune().unwrap();
        assert_eq!(card.borrow().tuning_commands, before + 3);
        if hs400 {
            assert_eq!(card.borrow().mmc_retune_phase, Some(6));
        }
        assert_eq!(card.borrow().ext[183], if hs400 { 6 } else { 2 });
        assert_eq!(card.borrow().ext[185], if hs400 { 3 } else { 2 });
        assert_eq!(disk.info().clock_hz, 200_000_000);
        let mut bytes = vec![0xa5; 65536];
        disk.read(3, &mut bytes).unwrap();
        assert_eq!(bytes, card.borrow().disk[3 * 512..3 * 512 + 65536]);
        bytes.fill(0x4d);
        disk.write(200, &bytes).unwrap();
        disk.flush().unwrap();
        assert_eq!(bytes, card.borrow().disk[200 * 512..200 * 512 + 65536]);
        let mut alias = disk.clone();
        disk.shutdown(true).unwrap();
        let accesses = (card.borrow().reads, card.borrow().writes.len());
        assert_eq!(alias.retune(), Err(BlockError::Unsupported(STALE)));
        assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
    }
}

#[test]
fn retune_downgrade_tuning_restore_or_reset_failure_powers_off_and_fences_aliases() {
    for fault in 0..4 {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: failed controls keep every original owner and all DMA aliases.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (host, mut disk, card, state) = fast_card(&mut dma, 1);
        let mut alias = disk.clone();
        card.borrow_mut().mmc_retune_phase = Some(0);
        match fault {
            0 => state.borrow_mut().ignore_mode = Some(4),
            1 => card.borrow_mut().tuning_iterations = 41,
            2 => state.borrow_mut().ignore_mode = Some(7),
            _ => card.borrow_mut().mmc_timing_fault = Some((2, COMMAND_TIMEOUT, true)),
        }
        let commands = card.borrow().commands.len();
        assert!(disk.retune().is_err());
        assert_eq!(Port(card.clone()).read8(POWER), 0);
        assert!(host.last_failure().unwrap().quarantined);
        if fault == 3 {
            assert_eq!(host.last_failure().unwrap().primary, BlockError::Timeout);
            assert!(host.last_failure().unwrap().retirement.is_some());
        }
        assert!(
            !card.borrow().commands[commands..]
                .iter()
                .any(|(cmd, _, _)| matches!(cmd, 17 | 18 | 24 | 25))
        );
        let mut output = [0xa5; 512];
        let accesses = (card.borrow().reads, card.borrow().writes.len());
        assert!(alias.read(0, &mut output).is_err());
        assert_eq!(output, [0xa5; 512]);
        assert!(alias.retune().is_err());
        assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
    }
}

#[test]
fn retune_refuses_other_timings_without_switches_and_lost_authority_without_mmio() {
    for (mode, revoked) in [(2, false), (4, false), (1, true)] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: strobe/refused original epochs keep all model DMA memory.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (_host, mut disk, card, state) = fast_card(&mut dma, mode);
        if revoked {
            state.borrow_mut().config[..4].fill(0xff);
        }
        let accesses = (card.borrow().reads, card.borrow().writes.len());
        let commands = card.borrow().commands.len();
        assert!(disk.retune().is_err());
        assert_eq!(commands, card.borrow().commands.len());
        if revoked {
            assert_eq!(accesses, (card.borrow().reads, card.borrow().writes.len()));
        } else {
            let mut output = [0; 512];
            disk.read(3, &mut output).unwrap();
            assert_eq!(output, card.borrow().disk[3 * 512..4 * 512]);
        }
    }
}
