// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Same-owner MAC0 ceiling programming; no binding or RF permission.
use super::*;
use crate::net::wifi::intel::command::{Command, Id};
const POWER: Id = Id {
    group: 0,
    opcode: 0x9f,
    version: 0,
};
mod binding_tests;

fn power_bytes(version: u8, reduced: bool, ack: bool) -> Vec<u8> {
    let mut bytes = phy_bytes(4, Some(2));
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, [0x9f, 1, version, 0]);
            bytes[at + 4..at + 8].copy_from_slice(&((len + 4) as u32).to_le_bytes());
        }
        if (kind == 29 || kind == 30) && len == 8 {
            let index = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap());
            let bit = match (kind, index) {
                (29, 1) => Some((13, reduced)),
                (30, 2) => Some((20, ack)),
                _ => None,
            };
            if let Some((bit, enabled)) = bit {
                let mut word = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
                word = (word & !(1 << bit)) | (u32::from(enabled) << bit);
                bytes[at + 12..at + 16].copy_from_slice(&word.to_le_bytes());
            }
        }
        at += 8 + if kind == 48 { len + 4 } else { len }.next_multiple_of(4);
    }
    bytes
}
fn ready_phy<'a>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    policy: &Arc<PolicyState>,
    short: bool,
) -> (Ax200Phy<'a, Model, ClockBios, ScanOs>, u16, u16) {
    let (scan, mut sequence, mut entry) = ready(catalog, empty, source, native, policy, short);
    let mut phy = scan
        .begin_phy_context(channel(1))
        .unwrap_or_else(|_| panic!("PHY"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { phy.advance(source) }.unwrap();
    for command in phy.commands().to_vec() {
        complete_phy(&phy, native, entry, sequence, command.id());
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { phy.advance(source) }.unwrap();
        sequence += 1;
        entry += 1;
    }
    assert_eq!(phy.phase(), Ax200PhyPhase::BindingRequired);
    (phy, sequence, entry)
}
fn complete_power(
    power: &Ax200TransmitPower<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    entry: u16,
    sequence: u16,
    wrong: bool,
) {
    let id = if wrong {
        Id {
            opcode: 0x9e,
            ..POWER
        }
    } else {
        POWER
    };
    complete(
        boot(&power.phy.scan),
        &native.domain,
        entry,
        entry + 1,
        &command_packet(id.wire(), sequence, &[0xaa]),
    );
}
fn emitted_power(power: &Ax200TransmitPower<'_, Model, ClockBios, ScanOs>, native: &Native) {
    let sequence = power.ticket().unwrap().sequence();
    let encoded = Command::encode(POWER, 0, sequence, power.command_bytes().unwrap()).unwrap();
    let descriptor = device_read(
        &native.domain,
        boot(&power.phy.scan).command.region().address,
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
#[test]
fn bounded_power_uses_source_schema_country_ceiling_real_dma_and_reclaim() {
    for version in [3, 4, 5] {
        for (reduced, ack, length) in [
            (false, false, 36),
            (false, true, 40),
            (true, false, 44),
            (true, true, 44),
        ] {
            for (requested, effective) in [(0, 0), (22, 22), (255, 30)] {
                let bytes = power_bytes(version, reduced, ack);
                exercise_power(&bytes, requested, effective, length);
            }
        }
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn actual_ax200_power5_schema_does_not_bypass_mld_mac_requirement() {
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
        firmware.command_version(1, 0x9f).unwrap().command_version,
        5
    );
    assert!(firmware.supports_api(45));
    ax200_mac_tests::assert_mld_mac_refusal(&bytes);
}
fn exercise_power(bytes: &[u8], requested: u8, effective: u8, length: usize) {
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (phy, sequence, entry) = ready_phy(&catalog, &empty, &source, &native, &policy, false);
    let mut power = phy
        .begin_transmit_power(requested)
        .unwrap_or_else(|_| panic!("power"));
    let policy_at_sync = policy.clone();
    let before = native.domain.records.lock().unwrap().syncs;
    native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
        assert_eq!(policy_at_sync.held.load(Ordering::SeqCst), 1);
    }));
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { power.advance(&source) }.unwrap(),
        Ax200TransmitPowerPhase::Waiting
    );
    native.domain.records.lock().unwrap().device_sync_hook = None;
    assert_eq!(native.domain.records.lock().unwrap().syncs, before + 3);
    assert!(power.applied_limit().is_none());
    assert_eq!(power.ticket().unwrap().sequence(), sequence);
    let bytes = power.command_bytes().unwrap();
    assert_eq!(bytes.len(), length);
    assert_eq!(&bytes[..8], &[0; 8]);
    assert_eq!(&bytes[8..10], &(u16::from(effective) * 8).to_le_bytes());
    assert!(bytes[10..].iter().all(|v| *v == 0));
    emitted_power(&power, &native);
    complete_power(&power, &native, entry, sequence, false);
    let mut records = native.domain.records.lock().unwrap();
    records.cpu_sync_fail = Some(records.cpu_syncs + 1);
    drop(records);
    assert!(matches!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { power.advance(&source) },
        Err(Ax200TransmitPowerError::Boot(Error::CommandReclaim(_)))
    ));
    assert!(power.applied_limit().is_none());
    assert!(power.first_error().is_none());
    native.domain.records.lock().unwrap().cpu_sync_fail = None;
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { power.advance(&source) }.unwrap(),
        Ax200TransmitPowerPhase::BindingRequired
    );
    let limit = power.applied_limit().unwrap();
    assert_eq!(limit.requested_dbm(), requested);
    assert_eq!(limit.effective_dbm(), effective);
    assert_eq!(limit.country_max_eirp_mbm(), 3000);
    assert_eq!(power.response().unwrap().raw, [0xaa]);
    power.stop().unwrap();
    drop(power);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}
#[test]
fn power_denial_and_unknown_abi_have_no_command_effects() {
    for case in 0..5 {
        let bytes = power_bytes(if case == 4 { 8 } else { 5 }, true, false);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (phy, _, _) = ready_phy(&catalog, &empty, &source, &native, &policy, false);
        let mut power = phy
            .begin_transmit_power(20)
            .unwrap_or_else(|_| panic!("power"));
        match case {
            0 => policy.deny_channel.store(1, Ordering::SeqCst),
            1 => policy.unavailable.store(true, Ordering::SeqCst),
            2 => policy
                .revoke_at_acquire
                .store(policy.acquired.load(Ordering::SeqCst) + 2, Ordering::SeqCst),
            3 => native.revoked.store(true, Ordering::SeqCst),
            _ => (),
        }
        let allocations = source.calls.load(Ordering::Relaxed);
        let bell = native.state.lock().unwrap().registers[&0x460];
        assert_eq!(
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            unsafe { power.advance(&source) },
            Err(match case {
                0 => Ax200TransmitPowerError::Regulatory(regulatory::Error::OsDenied),
                1 | 2 => Ax200TransmitPowerError::Regulatory(regulatory::Error::OsUnavailable),
                3 => Ax200TransmitPowerError::Country(Ax200CountryError::Revoked),
                _ => Ax200TransmitPowerError::Version(8),
            })
        );
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        assert!(power.applied_limit().is_none());
        assert!(power.ticket().is_none());
        power.stop().unwrap();
    }
}
#[test]
fn power_uncertain_publication_wrong_response_and_deadline_preserve_owners_and_first_error() {
    for case in 0..3 {
        let bytes = power_bytes(5, true, false);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (phy, sequence, entry) =
            ready_phy(&catalog, &empty, &source, &native, &policy, case == 2);
        let mut power = phy
            .begin_transmit_power(20)
            .unwrap_or_else(|_| panic!("power"));
        if case == 0 {
            let mut records = native.domain.records.lock().unwrap();
            records.sync_fail = Some(records.syncs + 2);
        }
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        let result = unsafe { power.advance(&source) };
        match case {
            0 => assert!(matches!(
                result,
                Err(Ax200TransmitPowerError::Boot(Error::Dma(_)))
            )),
            1 => {
                result.unwrap();
                complete_power(&power, &native, entry, sequence, true);
                assert!(matches!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { power.advance(&source) },
                    Err(Ax200TransmitPowerError::Boot(
                        Error::InitializationResponse { .. }
                    ))
                ));
                assert_eq!(power.response().unwrap().raw, [0xaa]);
            }
            _ => {
                result.unwrap();
                Clock {
                    ticks_per_microsecond: 1,
                }
                .delay(20);
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { power.advance(&source) },
                    Err(Ax200TransmitPowerError::Deadline)
                );
            }
        }
        assert_eq!(power.phase(), Ax200TransmitPowerPhase::Failed);
        assert!(power.applied_limit().is_none());
        assert!(power.command_bytes().is_some());
        let error = power.first_error().unwrap().clone();
        let operations = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { power.advance(&source) }, Err(error.clone()));
        assert_eq!(power.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), operations);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if case == 0 {
            native.state.lock().unwrap().fail = Some(operations + 1);
            assert!(power.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(power);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            power.stop().unwrap();
        }
    }
}
