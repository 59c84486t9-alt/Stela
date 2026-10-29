// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Original native MAC/PHY binding and finite response-envelope permissions.
use super::*;
use crate::net::wifi::regulatory::LegacyRate;
const BIND: Id = Id {
    group: 0,
    opcode: 0x2b,
    version: 0,
};
const ALL_COLD_RATES: usize = 0x15f;
mod mld_link_tests;
mod peer_tests;

fn binding_bytes(cdb_layout: bool) -> Vec<u8> {
    let mut bytes = power_bytes(5, true, false);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, [0x2b, 1, 2, 1, 0x2c, 1, 2, 0]);
            bytes[at + 4..at + 8].copy_from_slice(&((len + 8) as u32).to_le_bytes());
        }
        if kind == 30 && len == 8 && bytes[at + 8..at + 12] == 1u32.to_le_bytes() {
            let mut word = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
            word = (word & !(1 << 7)) | (u32::from(cdb_layout) << 7);
            bytes[at + 12..at + 16].copy_from_slice(&word.to_le_bytes());
        }
        at += 8 + if kind == 48 { len + 8 } else { len }.next_multiple_of(4);
    }
    bytes
}
fn quota_bytes(low_latency: bool, offload: bool, version: Option<u8>) -> Vec<u8> {
    let mut bytes = binding_bytes(true);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if (kind == 29 || kind == 30) && len == 8 && bytes[at + 8..at + 12] == 1u32.to_le_bytes() {
            let (bit, enabled) = if kind == 29 {
                (6, low_latency)
            } else {
                (12, offload)
            };
            let mut word = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
            word = (word & !(1 << bit)) | (u32::from(enabled) << bit);
            bytes[at + 12..at + 16].copy_from_slice(&word.to_le_bytes());
        }
        if kind == 48 {
            for command in bytes[at + 8..at + 8 + len].as_chunks_mut::<4>().0 {
                if command[..2] == [0x2c, 1] {
                    if let Some(version) = version {
                        command[2] = version;
                    } else {
                        command[0] = 0xfe;
                    }
                }
            }
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes
}
fn powered<'a>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    policy: &Arc<PolicyState>,
    short: bool,
) -> (Ax200TransmitPower<'a, Model, ClockBios, ScanOs>, u16, u16) {
    let (phy, sequence, entry) = ready_phy(catalog, empty, source, native, policy, short);
    let mut power = phy
        .begin_transmit_power(20)
        .unwrap_or_else(|_| panic!("power"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { power.advance(source) }.unwrap();
    complete_power(&power, native, entry, sequence, false);
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { power.advance(source) }.unwrap();
    // Publish real completed-buffer replenishment. The initial fixed pool's
    // credits are nearly exhausted by the cold command prefix; never
    // invent credits or complete against an unposted descriptor.
    let credits = boot(&power.phy.scan).credits;
    let replenished = power.replenish_completed_receive().unwrap();
    // MLD's earlier real MAC replenishment can leave fewer than one complete
    // eight-entry producer batch here. Zero newly published entries is valid;
    // existing credits must still cover the following command sequence.
    assert!(replenished.published.is_multiple_of(8));
    assert_eq!(replenished.device_credits, credits + replenished.published);
    assert!(replenished.device_credits >= 5);
    (power, sequence + 1, entry + 1)
}
fn authorize(policy: &PolicyState) {
    policy.allow_transmit.store(true, Ordering::SeqCst);
    policy.transmit_ceiling_mbm.store(2000, Ordering::SeqCst);
}
fn complete_binding(
    binding: &Ax200Binding<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    entry: u16,
    sequence: u16,
    command: &BindingCommand,
    payload: &[u8],
) {
    complete(
        boot(&binding.power.phy.scan),
        &native.domain,
        entry,
        entry + 1,
        &command_packet(command.id().wire(), sequence, payload),
    );
}
fn emitted_binding(binding: &Ax200Binding<'_, Model, ClockBios, ScanOs>, native: &Native) {
    let sequence = binding.ticket().unwrap().sequence();
    let command = binding
        .commands()
        .iter()
        .rev()
        .find(|command| match binding.phase() {
            Ax200BindingPhase::Waiting(kind) => command.kind() == kind,
            _ => false,
        })
        .unwrap();
    let encoded = Command::encode(command.id(), 0, sequence, command.bytes()).unwrap();
    let descriptor = device_read(
        &native.domain,
        boot(&binding.power.phy.scan).command.region().address,
        usize::from(sequence & 31) * 256,
        256,
    );
    let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
    let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
    let mut emitted = device_read(&native.domain, first, 0, encoded.first_tb().len());
    emitted.extend(device_read(
        &native.domain,
        rest,
        0,
        encoded.remainder().len(),
    ));
    assert_eq!(emitted, encoded.bytes());
}
fn finish_add(
    binding: &mut Ax200Binding<'_, Model, ClockBios, ScanOs>,
    source: &Source,
    native: &Native,
    sequence: &mut u16,
    entry: &mut u16,
) {
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { binding.advance(source) }.unwrap();
    for command in binding.commands().to_vec() {
        complete_binding(
            binding,
            native,
            *entry,
            *sequence,
            &command,
            if command.kind() == BindingCommandKind::Add {
                &[0; 4]
            } else {
                &[]
            },
        );
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { binding.advance(source) }.unwrap();
        *entry += 1;
        *sequence += 1;
    }
    assert_eq!(binding.phase(), Ax200BindingPhase::AuthenticationRequired);
}
#[test]
fn quota_cache_requires_actual_ack_reclaim_and_survives_same_original_owner_rebind() {
    let bytes = quota_bytes(true, false, Some(2));
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (power, mut sequence, mut entry) =
        powered(&catalog, &empty, &source, &native, &policy, false);
    authorize(&policy);
    // SAFETY: unchanged authored service and exclusive owner; no
    // revocation/revision reuse occurs across these two cold bindings.
    let mut binding = unsafe { power.begin_binding() }.unwrap_or_else(|_| panic!("binding"));
    finish_add(&mut binding, &source, &native, &mut sequence, &mut entry);
    binding.begin_remove().unwrap();
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { binding.advance(&source) }.unwrap();
    let commands = binding.commands()[2..].to_vec();
    assert_eq!(commands[0].kind(), BindingCommandKind::ClearQuotas);
    for command in commands {
        complete_binding(
            &binding,
            &native,
            entry,
            sequence,
            &command,
            if command.kind() == BindingCommandKind::Remove {
                &[0; 4]
            } else {
                &[]
            },
        );
        if command.kind() == BindingCommandKind::ClearQuotas {
            let mut records = native.domain.records.lock().unwrap();
            records.cpu_sync_fail = Some(records.cpu_syncs + 1);
            drop(records);
            assert!(matches!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { binding.advance(&source) },
                Err(Ax200BindingError::Boot(Error::CommandReclaim(_)))
            ));
            assert_eq!(binding.ticket().unwrap().sequence(), sequence);
            assert_eq!(
                binding.phase(),
                Ax200BindingPhase::Waiting(BindingCommandKind::ClearQuotas)
            );
            native.domain.records.lock().unwrap().cpu_sync_fail = None;
        }
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { binding.advance(&source) }.unwrap();
        entry += 1;
        sequence += 1;
    }
    let mut power = binding
        .into_transmit_power()
        .unwrap_or_else(|_| panic!("unbound"));
    power.replenish_completed_receive().unwrap();
    // SAFETY: the simulated device and its providers belong to this fixture alone; no other worker
    // touches them.
    let mut rebound = unsafe { power.begin_binding() }.unwrap_or_else(|_| panic!("rebind"));
    finish_add(&mut rebound, &source, &native, &mut sequence, &mut entry);
    rebound.begin_remove().unwrap();
    assert_eq!(
        rebound.commands()[2..]
            .iter()
            .map(BindingCommand::kind)
            .collect::<Vec<_>>(),
        [BindingCommandKind::Remove, BindingCommandKind::Power]
    );
    // Cache elision is checked after first quota ACK and
    // second ADD/power. Stop here without inventing wrapped RX completions.
    rebound.stop().unwrap();
}
#[test]
fn missing_quota_schema_refuses_before_binding_and_quota_fault_never_advances_remove() {
    for case in 0..4 {
        let bytes = quota_bytes(
            false,
            false,
            match case {
                0 => None,
                1 => Some(3),
                _ => Some(1),
            },
        );
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (power, mut sequence, mut entry) =
            powered(&catalog, &empty, &source, &native, &policy, case == 3);
        authorize(&policy);
        // SAFETY: same exclusive model with explicit finite-rate permission.
        let mut binding = unsafe { power.begin_binding() }.unwrap_or_else(|_| panic!("binding"));
        if case < 2 {
            let allocations = source.calls.load(Ordering::Relaxed);
            let bell = native.state.lock().unwrap().registers[&0x460];
            assert_eq!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { binding.advance(&source) },
                Err(if case == 0 {
                    Ax200BindingError::MissingApi
                } else {
                    Ax200BindingError::Version {
                        command: 0x2c,
                        version: 3,
                    }
                })
            );
            assert!(binding.commands().is_empty());
            assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
            assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        } else {
            finish_add(&mut binding, &source, &native, &mut sequence, &mut entry);
            binding.begin_remove().unwrap();
            if case == 2 {
                let mut records = native.domain.records.lock().unwrap();
                records.sync_fail = Some(records.syncs + 2);
                drop(records);
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                assert!(unsafe { binding.advance(&source) }.is_err());
            } else {
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { binding.advance(&source) }.unwrap();
                assert_eq!(
                    binding.phase(),
                    Ax200BindingPhase::Waiting(BindingCommandKind::ClearQuotas)
                );
                Clock {
                    ticks_per_microsecond: 1,
                }
                .delay(20);
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { binding.advance(&source) },
                    Err(Ax200BindingError::Deadline(BindingCommandKind::ClearQuotas))
                );
            }
            assert!(
                binding
                    .responses()
                    .iter()
                    .all(|response| response.command != 0x2c)
            );
        }
        let error = binding.first_error().unwrap().clone();
        let operations = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { binding.advance(&source) }, Err(error.clone()));
        assert_eq!(binding.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), operations);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        binding.stop().unwrap();
    }
}
#[test]
fn cold_binding_checks_every_rate_and_actual_limit_through_real_ack_power_and_unbind() {
    for layout in [false, true] {
        exercise(&binding_bytes(layout), layout);
    }
    for low_latency in [false, true] {
        for offload in [false, true] {
            exercise(&quota_bytes(low_latency, offload, Some(2)), true);
        }
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn actual_ax200_binding_schema_does_not_bypass_mld_mac_link_requirement() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let firmware = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    assert_eq!(
        firmware.command_version(1, 0x2b).unwrap().command_version,
        2
    );
    assert_eq!(
        firmware
            .command_version(1, 0x2b)
            .unwrap()
            .notification_version,
        1
    );
    assert!(firmware.supports_capability(39));
    assert!(firmware.supports_capability(44));
    ax200_mac_tests::assert_mld_mac_refusal(&bytes);
}
fn exercise(bytes: &[u8], layout: bool) {
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (power, mut sequence, mut entry) =
        powered(&catalog, &empty, &source, &native, &policy, false);
    authorize(&policy);
    // SAFETY: authored synchronous model approves only this native owner and
    // exact envelope, with explicit revocation followed by real unbind below.
    let mut binding = unsafe { power.begin_binding() }.unwrap_or_else(|_| panic!("binding"));
    let at_sync = policy.clone();
    native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
        assert_eq!(at_sync.held.load(Ordering::SeqCst), 1);
        assert_eq!(
            at_sync.transmit_rates.load(Ordering::SeqCst),
            ALL_COLD_RATES
        );
    }));
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { binding.advance(&source) }.unwrap(),
        Ax200BindingPhase::Waiting(BindingCommandKind::Add)
    );
    native.domain.records.lock().unwrap().device_sync_hook = None;
    let commands = binding.commands().to_vec();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].id(), BIND);
    assert_eq!(commands[0].bytes().len(), if layout { 28 } else { 24 });
    assert_eq!(
        &commands[0].bytes()[4..20],
        &[
            1, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255
        ]
    );
    assert!(commands[0].bytes()[20..].iter().all(|v| *v == 0));
    for command in commands {
        emitted_binding(&binding, &native);
        let payload = if command.kind() == BindingCommandKind::Add {
            &[0; 4][..]
        } else {
            &[][..]
        };
        complete_binding(&binding, &native, entry, sequence, &command, payload);
        let mut records = native.domain.records.lock().unwrap();
        records.cpu_sync_fail = Some(records.cpu_syncs + 1);
        drop(records);
        assert!(matches!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { binding.advance(&source) },
            Err(Ax200BindingError::Boot(Error::CommandReclaim(_)))
        ));
        assert!(binding.first_error().is_none());
        native.domain.records.lock().unwrap().cpu_sync_fail = None;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { binding.advance(&source) }.unwrap();
        entry += 1;
        sequence += 1;
    }
    assert_eq!(binding.phase(), Ax200BindingPhase::AuthenticationRequired);
    // A restriction cannot block control-plane teardown or invent a
    // successful status. No permission is acquired for REMOVE or its power.
    let acquired = policy.acquired.load(Ordering::SeqCst);
    native.revoked.store(true, Ordering::SeqCst);
    binding.begin_remove().unwrap();
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { binding.advance(&source) }.unwrap();
    let commands = binding.commands()[2..].to_vec();
    let firmware = crate::net::wifi::intel::firmware::Firmware::parse(bytes).unwrap();
    let offload = firmware.supports_capability(44);
    assert_eq!(commands.len(), if offload { 2 } else { 3 });
    let remove = usize::from(!offload);
    assert_eq!(commands[remove].kind(), BindingCommandKind::Remove);
    assert!(commands[remove].bytes()[8..20].iter().all(|v| *v == 255));
    if !offload {
        assert_eq!(commands[0].kind(), BindingCommandKind::ClearQuotas);
        assert_eq!(
            commands[0].id().wire(),
            Id {
                group: 1,
                opcode: 0x2c,
                version: 0
            }
        );
        let stride = if firmware.supports_api(38) { 16 } else { 12 };
        assert_eq!(commands[0].bytes().len(), 4 * stride);
        for slot in 0..4 {
            assert_eq!(
                &commands[0].bytes()[slot * stride..slot * stride + 4],
                &[255; 4]
            );
            assert!(
                commands[0].bytes()[slot * stride + 4..(slot + 1) * stride]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
    for command in commands {
        emitted_binding(&binding, &native);
        let payload = if command.kind() == BindingCommandKind::Remove {
            &[0; 4][..]
        } else {
            &[][..]
        };
        complete_binding(&binding, &native, entry, sequence, &command, payload);
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { binding.advance(&source) }.unwrap();
        entry += 1;
        sequence += 1;
    }
    assert_eq!(binding.phase(), Ax200BindingPhase::Unbound);
    assert_eq!(policy.acquired.load(Ordering::SeqCst), acquired);
    let mut power = binding
        .into_transmit_power()
        .unwrap_or_else(|_| panic!("original power"));
    assert_eq!(power.applied_limit().unwrap().effective_dbm(), 20);
    power.stop().unwrap();
    drop(power);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}
#[test]
fn binding_requires_entire_os_envelope_and_ceiling_before_any_dma_publication() {
    for case in 0..5 {
        let bytes = binding_bytes(true);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (power, _, _) = powered(&catalog, &empty, &source, &native, &policy, false);
        if case != 0 {
            authorize(&policy);
        }
        match case {
            1 => policy
                .deny_rate
                .store(LegacyRate::Ofdm24 as usize + 1, Ordering::SeqCst),
            2 => policy.transmit_ceiling_mbm.store(1999, Ordering::SeqCst),
            3 => policy.unavailable.store(true, Ordering::SeqCst),
            4 => native.revoked.store(true, Ordering::SeqCst),
            _ => (),
        }
        // SAFETY: no permissive production service; this model explicitly
        // denies the missing rate/ceiling/revoked permission before effects.
        let mut binding = unsafe { power.begin_binding() }.unwrap_or_else(|_| panic!("binding"));
        let allocations = source.calls.load(Ordering::Relaxed);
        let bell = native.state.lock().unwrap().registers[&0x460];
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { binding.advance(&source) },
            Err(match case {
                0..=2 => Ax200BindingError::Regulatory(regulatory::Error::OsDenied),
                3 => Ax200BindingError::Regulatory(regulatory::Error::OsUnavailable),
                _ => Ax200BindingError::Country(Ax200CountryError::Revoked),
            })
        );
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        assert!(binding.ticket().is_none());
        binding.stop().unwrap();
    }
}
#[test]
fn binding_status_failure_partial_power_failure_and_missing_ack_retain_original_epoch() {
    for case in 0..4 {
        let bytes = binding_bytes(false);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (power, sequence, entry) =
            powered(&catalog, &empty, &source, &native, &policy, case == 3);
        authorize(&policy);
        // SAFETY: scoped authored service as in exercise above.
        let mut binding = unsafe { power.begin_binding() }.unwrap_or_else(|_| panic!("binding"));
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { binding.advance(&source) }.unwrap();
        let command = binding.commands()[0].clone();
        let payload = match case {
            0 => &[1, 0, 0, 0][..],
            1 => &[0, 0][..],
            _ => &[0; 4][..],
        };
        if case == 3 {
            Clock {
                ticks_per_microsecond: 1,
            }
            .delay(20);
            assert_eq!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { binding.advance(&source) },
                Err(Ax200BindingError::Deadline(BindingCommandKind::Add))
            );
        } else {
            complete_binding(&binding, &native, entry, sequence, &command, payload);
            if case == 2 {
                policy.unavailable.store(true, Ordering::SeqCst);
            }
            assert_eq!(
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                unsafe { binding.advance(&source) },
                Err(match case {
                    0 => Ax200BindingError::Status(1),
                    1 => Ax200BindingError::ResponseLength(2),
                    _ => Ax200BindingError::Regulatory(regulatory::Error::OsUnavailable),
                })
            );
        }
        assert_eq!(binding.phase(), Ax200BindingPhase::Failed);
        let error = binding.first_error().unwrap().clone();
        let operations = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { binding.advance(&source) }, Err(error.clone()));
        assert_eq!(binding.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), operations);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if case == 2 {
            native.state.lock().unwrap().fail = Some(operations + 1);
            assert!(binding.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(binding);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            binding.stop().unwrap();
        }
    }
}
