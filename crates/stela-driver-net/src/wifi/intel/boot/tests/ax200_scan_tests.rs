// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Post-MCC scan configuration on the original modeled native owner.
use super::{ax200_tests::*, *};
pub(super) fn finish_mcc<'a>(
    setup: Ax200Setup<'a, Model, ClockBios>,
    mut sequence: u16,
    mut entry: u16,
    source: &Source,
    domain: &Domain,
) -> (Ax200Mcc<'a, Model, ClockBios>, u16, u16) {
    let mut mcc = setup.begin_mcc().unwrap_or_else(|_| panic!("actual setup"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { mcc.advance(source) }.unwrap();
    for (country, source_id) in [(*b"US", 0x10), (*b"CN", 2)] {
        complete(
            &mcc.setup.lari.radio.initialized.boot,
            domain,
            entry,
            entry + 1,
            &command_packet(
                super::super::super::command::Id {
                    group: 1,
                    opcode: 0xc8,
                    version: 0,
                },
                sequence,
                &mcc_payload(country, source_id, 51),
            ),
        );
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { mcc.advance(source) }.unwrap();
        sequence += 1;
        entry += 1;
    }
    assert_eq!(mcc.phase(), Ax200MccPhase::PolicyRequired);
    (mcc, sequence, entry)
}
#[test]
fn reduced_scan_configuration_completes_real_ack_and_keeps_board_policy_required() {
    exercise(false);
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn ax200_scan_cfg5_uses_real_rx_tx_antennas_and_original_dma_epoch() {
    exercise(true);
}
fn exercise(actual: bool) {
    for case in 0..if actual { 7 } else { 10 } {
        let mut bytes = if actual {
            use sha2::{Digest, Sha256};
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name()))
                    .unwrap();
            assert_eq!(
                std::format!("{:x}", Sha256::digest(&bytes)),
                "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
            );
            bytes
        } else {
            setup_bytes()
        };
        if case >= 7 {
            let mut at = 88;
            while at < bytes.len() {
                let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
                if case == 7 && kind == 48 {
                    for version in bytes[at + 8..at + 8 + len].as_chunks_mut::<4>().0 {
                        if version[..2] == [0x0c, 1] {
                            version[2] = 4;
                        }
                    }
                }
                if (case == 8 && kind == 29 || case == 9 && kind == 30) && len == 8 {
                    let index = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap());
                    if index == if case == 8 { 1 } else { 0 } {
                        let mut word =
                            u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
                        word &= !(1 << if case == 8 { 24 } else { 2 });
                        bytes[at + 12..at + 16].copy_from_slice(&word.to_le_bytes());
                    }
                }
                at += 8 + len.next_multiple_of(4);
            }
        }
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let bios_drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let init = drive_nvm(boot, &source, &domain, &state);
        let (lari, sequence, entry) = finish_lari(init, &source, &domain, &bios_drops, None);
        let mut options = Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        });
        if case == 5 || case == 6 {
            options.clock.ticks_per_microsecond = 1;
            options.command_timeout_us = 1;
        }
        let (setup, sequence, entry) =
            finish_setup_with_options(lari, sequence, entry, &source, &domain, options);
        let (mcc, sequence, entry) = finish_mcc(setup, sequence, entry, &source, &domain);
        let mut scan = mcc
            .begin_scan_configuration()
            .unwrap_or_else(|_| panic!("actual MCC"));
        if case == 2 {
            *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
        }
        if case == 3 {
            let mut r = domain.records.lock().unwrap();
            // 8-byte wide header + 12-byte body fits the exact 20-byte TB0:
            // no remainder allocation. TB0 is sync N, descriptor is N+1.
            r.sync_fail = Some(r.syncs + 1);
        }
        let bell_before = state.lock().unwrap().registers[&0x460];
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        let result = unsafe { scan.advance(&source) };
        if case >= 7 {
            let expected = match case {
                7 => Ax200ScanConfigurationError::Version(4),
                8 => Ax200ScanConfigurationError::ReducedScanRequired,
                9 => Ax200ScanConfigurationError::MissingUmacScan,
                _ => unreachable!(),
            };
            assert_eq!(result, Err(expected));
            assert!(scan.payload().is_none());
            assert!(scan.ticket().is_none());
            assert_eq!(state.lock().unwrap().registers[&0x460], bell_before);
        } else if case == 2 {
            assert_eq!(
                result,
                Err(Ax200ScanConfigurationError::Boot(Error::RfKilled))
            );
        } else if case == 3 {
            assert_eq!(
                result,
                Err(Ax200ScanConfigurationError::Boot(Error::Dma(
                    dma::Error::Dma(crate::bus::dma::mapping::DmaError::VisibilityFailed)
                )))
            );
            let records = domain.records.lock().unwrap();
            assert_eq!(records.sync_fail, Some(records.syncs - 1));
            drop(records);
            // The original transport kept its pending command before the
            // uncertain descriptor store; no producer doorbell was issued.
            assert_eq!(
                scan.mcc.setup.lari.radio.initialized.boot.state,
                State::Poisoned
            );
            assert_eq!(state.lock().unwrap().registers[&0x460], bell_before);
        } else {
            assert_eq!(result.unwrap(), Ax200ScanConfigurationPhase::Waiting);
            assert_eq!(
                scan.payload().unwrap(),
                &[0, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0]
            );
            assert!(scan.response().is_none());
            let descriptor = device_read(
                &domain,
                scan.mcc
                    .setup
                    .lari
                    .radio
                    .initialized
                    .boot
                    .command
                    .region()
                    .address,
                usize::from(sequence & 31) * 256,
                256,
            );
            let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
            let id = super::super::super::command::Id {
                group: 1,
                opcode: 0x0c,
                version: 0,
            };
            let command = super::super::super::command::Command::encode(
                id,
                0,
                sequence,
                scan.payload().unwrap(),
            )
            .unwrap();
            assert_eq!(
                device_read(&domain, first, 0, command.bytes().len()),
                command.bytes()
            );
            let bell = state.lock().unwrap().registers[&0x460];
            // Deadline cases use a one-tick wait from creation.
            // Do not expect an extra pending poll to beat that elapsed deadline.
            if case < 5 {
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { scan.advance(&source) }.unwrap(),
                    Ax200ScanConfigurationPhase::Waiting
                );
                assert_eq!(state.lock().unwrap().registers[&0x460], bell);
            }
            if case == 5 {
                options.clock.delay(20);
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { scan.advance(&source) },
                    Err(Ax200ScanConfigurationError::Deadline)
                );
                assert!(scan.ticket().is_some());
                assert!(scan.response().is_none());
            } else if case == 4 {
                let mut s = state.lock().unwrap();
                s.fail = Some(s.ops.len() + 1);
                drop(s);
                assert!(scan.stop().is_err());
            } else {
                complete(
                    &scan.mcc.setup.lari.radio.initialized.boot,
                    &domain,
                    entry,
                    entry + 1,
                    &command_packet(
                        super::super::super::command::Id {
                            opcode: if case == 1 { 0xd } else { 0xc },
                            ..id
                        },
                        sequence,
                        &[0x96],
                    ),
                );
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                if case == 6 {
                    options.clock.delay(20);
                    assert_eq!(
                        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its
                        // sole simulated requester domain.
                        unsafe { scan.advance(&source) },
                        Err(Ax200ScanConfigurationError::Deadline)
                    );
                    assert!(scan.ticket().is_some());
                    assert!(scan.response().is_none());
                    let original = scan.first_error().unwrap().clone();
                    let ops = state.lock().unwrap().ops.len();
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    assert_eq!(unsafe { scan.advance(&source) }, Err(original));
                    assert_eq!(state.lock().unwrap().ops.len(), ops);
                    scan.stop().unwrap();
                    drop(scan);
                    assert!(domain.records.lock().unwrap().live.is_empty());
                    continue;
                }
                assert!(matches!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { scan.advance(&source) },
                    Err(Ax200ScanConfigurationError::Boot(Error::CommandReclaim(_)))
                ));
                assert!(scan.first_error().is_none());
                assert!(scan.response().is_none());
                domain.records.lock().unwrap().cpu_sync_fail = None;
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                let result = unsafe { scan.advance(&source) };
                if case == 1 {
                    assert_eq!(
                        result,
                        Err(Ax200ScanConfigurationError::Boot(
                            Error::InitializationResponse {
                                command: 0xd,
                                group: 1
                            }
                        ))
                    );
                } else {
                    assert_eq!(
                        result.unwrap(),
                        Ax200ScanConfigurationPhase::BoardPolicyRequired
                    );
                }
                assert_eq!(scan.response().unwrap().raw, [0x96]);
            }
        }
        if case != 0 {
            let original = scan.first_error().unwrap().clone();
            let ops = state.lock().unwrap().ops.len();
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            assert_eq!(unsafe { scan.advance(&source) }, Err(original));
            assert_eq!(state.lock().unwrap().ops.len(), ops);
        }
        if case == 3 || case == 4 {
            let live = domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(scan);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        } else {
            scan.stop().unwrap();
            drop(scan);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
        }
    }
}
