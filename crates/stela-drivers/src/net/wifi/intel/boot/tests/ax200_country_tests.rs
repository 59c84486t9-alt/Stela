// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Same-owner explicit OS country application; fixtures are not OS services.
use super::{ax200_scan_tests::finish_mcc, ax200_tests::*, *};
use crate::net::wifi::regulatory::database;
use core::sync::atomic::AtomicBool;
pub(super) struct Os {
    pub(super) drops: Arc<AtomicUsize>,
    pub(super) revoked: Arc<AtomicBool>,
    pub(super) unavailable: bool,
}
impl Drop for Os {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: explicit modeled OS source for this modeled native epoch, not physical
// location/OS authority. The shared fixture retains its own modeled pinned bytes.
unsafe impl CountryIo for Os {
    fn country(&mut self) -> Result<SelectedCountry, CountryIoError> {
        if self.unavailable {
            return Err(CountryIoError::Unavailable);
        }
        Ok(SelectedCountry {
            country: database::tests::country(),
            revision: 71,
        })
    }
    fn current(&mut self, revision: u64) -> Result<bool, CountryIoError> {
        Ok(revision == 71 && !self.revoked.load(Ordering::Relaxed))
    }
}
#[test]
fn country_application_preserves_dma_lifetimes_and_refusals() {
    for case in 0..10 {
        let bytes = setup_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let bios_drops = Arc::new(AtomicUsize::new(0));
        let os_drops = Arc::new(AtomicUsize::new(0));
        let revoked = Arc::new(AtomicBool::new(false));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let init = drive_nvm(boot, &source, &domain, &state);
        let (lari, sequence, entry) = finish_lari(init, &source, &domain, &bios_drops, None);
        let mut options = Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        });
        if case >= 8 {
            options.clock.ticks_per_microsecond = 1;
            options.command_timeout_us = 1;
        }
        let (setup, sequence, entry) =
            finish_setup_with_options(lari, sequence, entry, &source, &domain, options);
        let (mcc, mut sequence, mut entry) = finish_mcc(setup, sequence, entry, &source, &domain);
        let mut scan = mcc
            .begin_scan_configuration()
            .unwrap_or_else(|_| panic!("scan"));
        unsafe { scan.advance(&source) }.unwrap();
        complete(
            &scan.mcc.setup.lari.radio.initialized.boot,
            &domain,
            entry,
            entry + 1,
            &command_packet(
                super::super::super::command::Id {
                    group: 1,
                    opcode: 0xc,
                    version: 0,
                },
                sequence,
                &[],
            ),
        );
        unsafe { scan.advance(&source) }.unwrap();
        sequence += 1;
        entry += 1;
        // Genuine modeled absence of all optional board tables: no source
        // programming is required, and no copied board-policy receipt is used.
        scan.mcc.setup.lari.bios.io.board_case = Some(1);
        let mut board = scan
            .begin_board_policy()
            .unwrap_or_else(|_| panic!("board"));
        assert_eq!(
            unsafe { board.advance(&source) }.unwrap(),
            Ax200BoardPolicyPhase::CountryRequired
        );
        let os = Os {
            drops: os_drops.clone(),
            revoked: revoked.clone(),
            unavailable: case == 1,
        };
        let mut country = unsafe { board.begin_country(os) }.unwrap_or_else(|_| panic!("country"));
        let bell = state.lock().unwrap().registers[&0x460];
        if case == 0 {
            *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
        }
        if case == 2 {
            revoked.store(true, Ordering::Relaxed);
        }
        if case == 6 {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + 2);
        }
        let result = unsafe { country.advance(&source) };
        if case == 1 || case == 2 {
            assert_eq!(
                result,
                Err(if case == 1 {
                    Ax200CountryError::Platform(CountryIoError::Unavailable)
                } else {
                    Ax200CountryError::Revoked
                })
            );
            assert!(country.ticket().is_none());
            assert_eq!(state.lock().unwrap().registers[&0x460], bell);
        } else if case == 6 {
            assert!(matches!(
                result,
                Err(Ax200CountryError::Boot(Error::Dma(_)))
            ));
        } else {
            assert_eq!(result.unwrap(), Ax200CountryPhase::Waiting);
            assert_eq!(
                country.request().unwrap(),
                super::super::super::mcc::Request {
                    country: *b"US",
                    source: 9
                }
            );
            assert_eq!(
                country.country().unwrap().digest(),
                database::tests::country().digest()
            );
            let descriptor = device_read(
                &domain,
                country
                    .board
                    .scan
                    .mcc
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
            let encoded = super::super::super::command::Command::encode(
                super::super::super::mcc::Request::id(),
                0,
                sequence,
                &country.request().unwrap().bytes().unwrap(),
            )
            .unwrap();
            let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
            let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
            let mut emitted = device_read(&domain, first, 0, encoded.first_tb().len());
            emitted.extend(device_read(&domain, rest, 0, encoded.remainder().len()));
            assert_eq!(emitted, encoded.bytes());
            let ticket = country.ticket().unwrap().clone();
            if case == 7 {
                let mut s = state.lock().unwrap();
                s.fail = Some(s.ops.len() + 1);
                drop(s);
                assert!(country.stop().is_err());
            } else if case == 8 {
                options.clock.delay(20);
                assert_eq!(
                    unsafe { country.advance(&source) },
                    Err(Ax200CountryError::Deadline)
                );
                assert_eq!(country.ticket(), Some(&ticket));
            } else {
                let mut payload = mcc_payload(
                    if case == 3 { *b"CN" } else { *b"US" },
                    if case == 4 { 2 } else { 9 },
                    51,
                );
                if case == 5 {
                    payload[..4].copy_from_slice(&2u32.to_le_bytes());
                }
                complete(
                    &country.board.scan.mcc.setup.lari.radio.initialized.boot,
                    &domain,
                    entry,
                    entry + 1,
                    &command_packet(
                        super::super::super::mcc::Request::id().wire(),
                        sequence,
                        &payload,
                    ),
                );
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                if case == 9 {
                    options.clock.delay(20);
                    assert_eq!(
                        unsafe { country.advance(&source) },
                        Err(Ax200CountryError::Deadline)
                    );
                    assert_eq!(country.ticket(), Some(&ticket));
                } else {
                    assert!(matches!(
                        unsafe { country.advance(&source) },
                        Err(Ax200CountryError::Boot(Error::CommandReclaim(_)))
                    ));
                    assert_eq!(country.ticket(), Some(&ticket));
                    assert!(country.first_error().is_none());
                    domain.records.lock().unwrap().cpu_sync_fail = None;
                    let result = unsafe { country.advance(&source) };
                    match case {
                        0 => {
                            assert_eq!(result.unwrap(), Ax200CountryPhase::MacContextRequired);
                            assert_eq!(country.channels().len(), 51);
                            revoked.store(true, Ordering::Relaxed);
                            assert_eq!(
                                unsafe { country.advance(&source) },
                                Err(Ax200CountryError::Revoked)
                            );
                        }
                        3 => assert_eq!(
                            result,
                            Err(Ax200CountryError::CountryMismatch {
                                requested: *b"US",
                                returned: *b"CN"
                            })
                        ),
                        4 => assert_eq!(result, Err(Ax200CountryError::SourceMismatch(2))),
                        5 => assert_eq!(result, Err(Ax200CountryError::Rejected(2))),
                        _ => unreachable!(),
                    }
                    assert_eq!(country.response().unwrap().raw, payload);
                    assert!(country.profile().is_some());
                }
            }
        }
        let first = country.first_error().unwrap().clone();
        let operations = state.lock().unwrap().ops.len();
        assert_eq!(unsafe { country.advance(&source) }, Err(first));
        assert_eq!(state.lock().unwrap().ops.len(), operations);
        if case == 6 || case == 7 {
            let live = domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(country);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
            assert_eq!(os_drops.load(Ordering::Relaxed), 0);
        } else {
            country.stop().unwrap();
            drop(country);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
            assert_eq!(os_drops.load(Ordering::Relaxed), 1);
        }
    }
}
