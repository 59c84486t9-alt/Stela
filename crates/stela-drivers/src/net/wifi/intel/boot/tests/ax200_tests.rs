// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Retained AX200 owner, completed native command DMA and failure models.
use super::*;
use crate::net::wifi::intel::radio::{
    bios::service::{BiosIo, IoError, Object, Request},
    control::Kind,
};
pub(super) struct ClockBios {
    inner: RadioBios,
    clock_error: Option<IoError>,
    country_error: Option<IoError>,
}
// SAFETY: the original exact namespace model plus a real modeled EFI ECKV read.
unsafe impl BiosIo for ClockBios {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
        self.inner.evaluate(request)
    }
    fn variable(
        &mut self,
        variable: super::super::super::platform::Variable,
    ) -> Result<Vec<u8>, IoError> {
        use super::super::super::platform::Variable;
        if variable == Variable::Wrdd {
            return self
                .country_error
                .map_or_else(|| Ok(vec![0, 0x4e, 0x43, 0, 0]), Err);
        }
        if variable == Variable::Eckv {
            return self
                .clock_error
                .map_or_else(|| Ok(vec![0, 1, 0, 0, 0]), Err);
        }
        self.inner.variable(variable)
    }
}
pub(super) fn setup_bytes() -> Vec<u8> {
    let mut bytes = lari_bytes(false, 6);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            let versions = [
                0x18, 1, 12, 2, 0x77, 1, 6, 0, 4, 4, 1, 0, 0xc8, 1, 1, 5, 0x0c, 1, 5, 0,
            ];
            bytes.splice(at + 8 + len..at + 8 + len, versions);
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    for (index, mask) in [
        (0u32, (1u32 << 1) | (1 << 2)),
        (1, 1 << 18),
        (2, (1 << 10) | (1 << 11) | (1 << 25)),
    ] {
        bytes.extend(30u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(index.to_le_bytes());
        bytes.extend(mask.to_le_bytes());
    }
    bytes.extend(29u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend((1u32 << 9).to_le_bytes());
    bytes.extend(29u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((1u32 << 24).to_le_bytes());
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 23 {
            let word = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) | (3 << 20);
            bytes[at + 8..at + 12].copy_from_slice(&word.to_le_bytes());
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes
}
pub(super) fn finish_lari<'a>(
    init: UnifiedNvm<'a, Model>,
    source: &Source,
    domain: &Domain,
    bios_drops: &Arc<AtomicUsize>,
    clock_error: Option<IoError>,
) -> (LariRadio<'a, Model, ClockBios>, u16, u16) {
    let (cold, mut sequence, mut entry) = drive_cold_prefix(init, source, domain);
    let mut lari = unsafe {
        cold.begin_lari(ClockBios {
            inner: RadioBios {
                drops: bios_drops.clone(),
                unavailable: false,
                absent: false,
            },
            clock_error,
            country_error: None,
        })
    }
    .unwrap_or_else(|_| panic!("real cold prefix"));
    unsafe { lari.advance(source) }.unwrap();
    let commands: Vec<_> = lari.plan().unwrap().commands().map(|(id, _)| id).collect();
    for id in commands {
        complete(
            &lari.radio.initialized.boot,
            domain,
            entry,
            entry + 1,
            &command_packet(id, sequence, &[]),
        );
        unsafe { lari.advance(source) }.unwrap();
        sequence += 1;
        entry += 1;
    }
    assert_eq!(lari.phase(), LariPhase::RxQueueConfigurationRequired);
    (lari, sequence, entry)
}
#[test]
fn thermal_power_use_original_ax200_epoch_and_reclaimed_completions() {
    exercise_setup(false);
}
#[test]
#[ignore = "requires pinned unchanged AX200 firmware"]
fn actual_ax200_thermal_power_versions_and_capability_branches() {
    exercise_setup(true);
}
fn exercise_setup(actual: bool) {
    let bytes = if actual {
        use sha2::{Digest, Sha256};
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        let bytes =
            std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
        );
        bytes
    } else {
        setup_bytes()
    };
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
    let before = state.lock().unwrap().ops.len();
    let lari = *unsafe {
        lari.begin_ax200_setup(Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 0,
        }))
    }
    .err()
    .unwrap();
    assert_eq!(state.lock().unwrap().ops.len(), before);
    assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
    let mut setup = unsafe {
        lari.begin_ax200_setup(Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        }))
    }
    .unwrap_or_else(|_| panic!("AX200 source continuation"));
    assert_eq!(
        unsafe { setup.advance(&source) }.unwrap(),
        Ax200SetupPhase::Waiting(Kind::TemperatureThresholds)
    );
    let decisions = setup.decisions().unwrap();
    assert_eq!(decisions.receive_queues, 1);
    assert!(decisions.firmware_auxiliary_station && decisions.firmware_ltr);
    assert!(!decisions.dqa_command);
    assert!(!setup.thermal_command_acknowledged());
    for (index, (id, payload)) in [
        (
            super::super::super::command::Id {
                group: 4,
                opcode: 4,
                version: 0,
            },
            vec![0; 20],
        ),
        (
            super::super::super::command::Id {
                group: 0,
                opcode: 0x77,
                version: 0,
            },
            vec![0, 0x10, 0, 0],
        ),
    ]
    .iter()
    .enumerate()
    {
        let sequence = sequence + index as u16;
        let descriptor = device_read(
            &domain,
            setup.lari.radio.initialized.boot.command.region().address,
            usize::from(sequence & 31) * 256,
            256,
        );
        let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
        let encoded =
            super::super::super::command::Command::encode(*id, 0, sequence, payload).unwrap();
        let mut emitted = device_read(&domain, first, 0, encoded.bytes().len().min(20));
        if encoded.bytes().len() > 20 {
            let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
            emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
        }
        assert_eq!(emitted, encoded.bytes());
        let bell = state.lock().unwrap().registers[&0x460];
        unsafe { setup.advance(&source) }.unwrap();
        assert_eq!(state.lock().unwrap().registers[&0x460], bell);
        let mut response_id = *id;
        if response_id.group == 0 {
            response_id.group = 1;
        }
        complete(
            &setup.lari.radio.initialized.boot,
            &domain,
            entry + index as u16,
            entry + index as u16 + 1,
            &command_packet(response_id, sequence, &[]),
        );
        let mut r = domain.records.lock().unwrap();
        r.cpu_sync_fail = Some(r.cpu_syncs + 1);
        drop(r);
        assert!(matches!(
            unsafe { setup.advance(&source) },
            Err(Ax200SetupError::Boot(Error::CommandReclaim(_)))
        ));
        assert!(setup.first_error().is_none());
        assert_eq!(state.lock().unwrap().registers[&0x460], bell);
        domain.records.lock().unwrap().cpu_sync_fail = None;
        assert_eq!(
            unsafe { setup.advance(&source) }.unwrap(),
            if index == 0 {
                Ax200SetupPhase::Waiting(Kind::DevicePower)
            } else {
                Ax200SetupPhase::RegulatoryRequired
            }
        );
        assert!(setup.thermal_command_acknowledged());
    }
    assert_eq!(setup.responses().len(), 2);
    assert!(matches!(
        setup.platform_reads().last(),
        Some(super::super::super::radio::bios::service::Read::Uefi(
            super::super::super::platform::Variable::Eckv,
            Ok(_)
        ))
    ));
    // Completed setup must still surface a new real device failure.
    state.lock().unwrap().registers.insert(8, 1 << 29);
    assert!(matches!(
        unsafe { setup.advance(&source) },
        Err(Ax200SetupError::Boot(Error::DeviceError(_)))
    ));
    let first = setup.first_error().cloned();
    assert_eq!(unsafe { setup.advance(&source) }.err(), first);
    setup.stop().unwrap();
    drop(setup);
    assert!(domain.records.lock().unwrap().live.is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn thermal_power_errors_remain_sticky_and_uncertain_dma_keeps_both_owners() {
    for case in 0..7 {
        let bytes = setup_bytes();
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
        let (lari, sequence, entry) = finish_lari(
            init,
            &source,
            &domain,
            &bios_drops,
            (case == 0).then_some(IoError::Unavailable),
        );
        let before = state.lock().unwrap().ops.len();
        let mut options = Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        });
        if case == 3 || case == 6 {
            options.clock.ticks_per_microsecond = 1;
            options.command_timeout_us = 1;
        }
        let mut setup =
            unsafe { lari.begin_ax200_setup(options) }.unwrap_or_else(|_| panic!("AX200"));
        if case == 1 {
            *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
        }
        if case == 4 {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + 2);
        }
        let result = unsafe { setup.advance(&source) };
        match case {
            0 => {
                assert!(matches!(result, Err(Ax200SetupError::Platform(_))));
                assert_eq!(state.lock().unwrap().ops.len(), before);
            }
            1 => assert_eq!(result, Err(Ax200SetupError::Boot(Error::RfKilled))),
            2 => {
                result.unwrap();
                complete(
                    &setup.lari.radio.initialized.boot,
                    &domain,
                    entry,
                    entry + 1,
                    &command_packet(
                        super::super::super::command::Id {
                            group: 4,
                            opcode: 3,
                            version: 0,
                        },
                        sequence,
                        &[0xde, 0xad],
                    ),
                );
                assert_eq!(
                    unsafe { setup.advance(&source) },
                    Err(Ax200SetupError::Boot(Error::InitializationResponse {
                        command: 3,
                        group: 4
                    }))
                );
                assert_eq!(setup.responses()[0].raw, [0xde, 0xad]);
                assert!(!setup.thermal_command_acknowledged());
            }
            3 => {
                result.unwrap();
                options.clock.delay(20);
                assert_eq!(
                    unsafe { setup.advance(&source) },
                    Err(Ax200SetupError::Deadline(Kind::TemperatureThresholds))
                );
            }
            4 => assert!(matches!(result, Err(Ax200SetupError::Boot(Error::Dma(_))))),
            5 => {
                result.unwrap();
                let mut s = state.lock().unwrap();
                s.fail = Some(s.ops.len() + 1);
                drop(s);
                assert!(setup.stop().is_err());
            }
            6 => {
                result.unwrap();
                complete(
                    &setup.lari.radio.initialized.boot,
                    &domain,
                    entry,
                    entry + 1,
                    &command_packet(
                        super::super::super::command::Id {
                            group: 4,
                            opcode: 4,
                            version: 0,
                        },
                        sequence,
                        &[],
                    ),
                );
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                options.clock.delay(20);
                assert_eq!(
                    unsafe { setup.advance(&source) },
                    Err(Ax200SetupError::Deadline(Kind::TemperatureThresholds))
                );
                assert!(!setup.thermal_command_acknowledged());
                assert!(setup.responses().is_empty());
            }
            _ => unreachable!(),
        }
        let original = setup.first_error().unwrap().clone();
        let ops = state.lock().unwrap().ops.len();
        assert_eq!(unsafe { setup.advance(&source) }, Err(original.clone()));
        assert_eq!(setup.first_error(), Some(&original));
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        if case >= 3 {
            let live = domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(setup);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        } else {
            setup.stop().unwrap();
            drop(setup);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
        }
    }
}

pub(super) fn finish_setup<'a>(
    lari: LariRadio<'a, Model, ClockBios>,
    sequence: u16,
    entry: u16,
    source: &Source,
    domain: &Domain,
) -> (Ax200Setup<'a, Model, ClockBios>, u16, u16) {
    finish_setup_with_options(
        lari,
        sequence,
        entry,
        source,
        domain,
        Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        }),
    )
}
pub(super) fn finish_setup_with_options<'a>(
    lari: LariRadio<'a, Model, ClockBios>,
    mut sequence: u16,
    mut entry: u16,
    source: &Source,
    domain: &Domain,
    options: Ax200SetupOptions,
) -> (Ax200Setup<'a, Model, ClockBios>, u16, u16) {
    let mut setup =
        unsafe { lari.begin_ax200_setup(options) }.unwrap_or_else(|_| panic!("AX200 setup"));
    unsafe { setup.advance(source) }.unwrap();
    for (group, opcode) in [(4, 4), (1, 0x77)] {
        complete(
            &setup.lari.radio.initialized.boot,
            domain,
            entry,
            entry + 1,
            &command_packet(
                super::super::super::command::Id {
                    group,
                    opcode,
                    version: 0,
                },
                sequence,
                &[],
            ),
        );
        unsafe { setup.advance(source) }.unwrap();
        sequence += 1;
        entry += 1;
    }
    assert_eq!(setup.phase(), Ax200SetupPhase::RegulatoryRequired);
    (setup, sequence, entry)
}
pub(super) fn mcc_payload(country: [u8; 2], source: u8, count: usize) -> Vec<u8> {
    let mut b = vec![0; 20 + count * 4];
    b[..4].copy_from_slice(&0u32.to_le_bytes());
    b[4..6].copy_from_slice(&u16::from_be_bytes(country).to_le_bytes());
    b[6..8].copy_from_slice(&12u16.to_le_bytes());
    b[12] = source;
    b[16..20].copy_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        b[20 + i * 4..24 + i * 4]
            .copy_from_slice(&(if i == 0 { 0x0f09u32 } else { 0 }).to_le_bytes());
    }
    b
}
#[test]
fn mcc_actual_query_bios_selection_and_response_never_echo_requested_country() {
    exercise_mcc(false);
}
#[test]
#[ignore = "requires pinned unchanged AX200 firmware"]
fn mcc_actual_ax200_v5_response_is_retained_with_original_dma_epoch() {
    exercise_mcc(true);
}
fn exercise_mcc(actual: bool) {
    let bytes = if actual {
        use sha2::{Digest, Sha256};
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        let bytes =
            std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
        );
        bytes
    } else {
        setup_bytes()
    };
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
    let (setup, sequence, entry) = finish_setup(lari, sequence, entry, &source, &domain);
    let mut mcc = setup.begin_mcc().unwrap_or_else(|_| panic!("actual setup"));
    // The source explicitly sends MCC in RF-kill. It is not an RF grant.
    *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
    assert_eq!(
        unsafe { mcc.advance(&source) }.unwrap(),
        Ax200MccPhase::WaitingCurrent
    );
    for (i, (request, reply, source_id)) in [(*b"ZZ", *b"US", 0x10), (*b"CN", *b"JP", 2)]
        .iter()
        .enumerate()
    {
        let sequence = sequence + i as u16;
        let descriptor = device_read(
            &domain,
            mcc.setup
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
        let id = super::super::super::mcc::Request::id();
        let payload = super::super::super::mcc::Request {
            country: *request,
            source: *source_id,
        }
        .bytes()
        .unwrap();
        let encoded =
            super::super::super::command::Command::encode(id, 0, sequence, &payload).unwrap();
        let mut emitted = device_read(&domain, first, 0, 20);
        let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
        emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
        assert_eq!(emitted, encoded.bytes());
        let bell = state.lock().unwrap().registers[&0x460];
        unsafe { mcc.advance(&source) }.unwrap();
        assert_eq!(state.lock().unwrap().registers[&0x460], bell);
        complete(
            &mcc.setup.lari.radio.initialized.boot,
            &domain,
            entry + i as u16,
            entry + i as u16 + 1,
            &command_packet(
                super::super::super::command::Id {
                    group: 1,
                    opcode: 0xc8,
                    version: 0,
                },
                sequence,
                &mcc_payload(*reply, *source_id, 51),
            ),
        );
        let mut r = domain.records.lock().unwrap();
        r.cpu_sync_fail = Some(r.cpu_syncs + 1);
        drop(r);
        assert!(matches!(
            unsafe { mcc.advance(&source) },
            Err(Ax200MccError::Boot(Error::CommandReclaim(_)))
        ));
        assert_eq!(mcc.profiles().len(), i);
        assert!(mcc.first_error().is_none());
        domain.records.lock().unwrap().cpu_sync_fail = None;
        assert_eq!(
            unsafe { mcc.advance(&source) }.unwrap(),
            if i == 0 {
                Ax200MccPhase::WaitingBios
            } else {
                Ax200MccPhase::PolicyRequired
            }
        );
        assert_eq!(mcc.profiles().last().unwrap().country, *reply);
        assert_ne!(mcc.profiles().last().unwrap().country, *request);
    }
    assert_eq!(mcc.channels().len(), 51);
    assert_eq!(mcc.channels().iter().filter(|c| c.valid).count(), 1);
    assert_eq!(
        mcc.bios_country().unwrap(),
        super::super::super::radio::lari::Observation::Observed(
            super::super::super::radio::lari::Value {
                value: 0x434e,
                source: super::super::super::radio::lari::Source::Uefi,
                revision: 0
            }
        )
    );
    assert_eq!(mcc.responses().len(), 2);
    assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
    mcc.stop().unwrap();
    drop(mcc);
    assert!(domain.records.lock().unwrap().live.is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn mcc_rejected_responses_and_missing_bios_service_keep_original_evidence_and_owner() {
    for case in 0..5 {
        let bytes = setup_bytes();
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
        let (mut setup, sequence, entry) = finish_setup(lari, sequence, entry, &source, &domain);
        if case == 2 {
            setup.lari.bios.io.country_error = Some(IoError::Unavailable);
        }
        let mut mcc = setup.begin_mcc().unwrap_or_else(|_| panic!("setup"));
        if case == 4 {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + 2);
        }
        let result = unsafe { mcc.advance(&source) };
        if case == 4 {
            assert!(matches!(result, Err(Ax200MccError::Boot(Error::Dma(_)))));
        } else {
            result.unwrap();
            let raw = if case == 0 {
                vec![0xaa; 4]
            } else {
                mcc_payload(*b"US", 0x10, if case == 1 { 52 } else { 51 })
            };
            complete(
                &mcc.setup.lari.radio.initialized.boot,
                &domain,
                entry,
                entry + 1,
                &command_packet(
                    super::super::super::command::Id {
                        group: 1,
                        opcode: if case == 3 { 0xc9 } else { 0xc8 },
                        version: 0,
                    },
                    sequence,
                    &raw,
                ),
            );
            let result = unsafe { mcc.advance(&source) };
            match case {
                0 => assert!(matches!(result, Err(Ax200MccError::Schema(_)))),
                1 => assert!(matches!(result, Err(Ax200MccError::ChannelInventory(_)))),
                2 => assert!(matches!(result, Err(Ax200MccError::Platform(_)))),
                3 => assert!(matches!(
                    result,
                    Err(Ax200MccError::Boot(Error::InitializationResponse { .. }))
                )),
                _ => unreachable!(),
            }
            assert_eq!(mcc.responses().len(), 1);
            assert_eq!(mcc.responses()[0].raw, raw);
            if case == 2 {
                assert_eq!(mcc.profiles().len(), 1);
            } else {
                assert!(mcc.profiles().is_empty());
            }
        }
        let original = mcc.first_error().unwrap().clone();
        let ops = state.lock().unwrap().ops.len();
        assert_eq!(unsafe { mcc.advance(&source) }, Err(original));
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        if case == 4 {
            let live = domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(mcc);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        } else {
            mcc.stop().unwrap();
            drop(mcc);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
        }
    }
}
