// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Original AX200 command/RX/DMA ownership under a modeled genuine OS lease.
use super::{
    ax200_country_tests::Os,
    ax200_mac_tests::{self, Native},
    ax200_tests::*,
    *,
};
use crate::net::wifi::{
    Band, Channel,
    regulatory::{self, OsLease, OsPolicy},
    scan,
};
use core::sync::atomic::AtomicBool;
#[derive(Default)]
struct PolicyState {
    held: AtomicUsize,
    acquired: AtomicUsize,
    deny_channel: AtomicUsize,
    revoke_at_acquire: AtomicUsize,
    unavailable: AtomicBool,
}
struct ScanOs {
    country: Os,
    policy: Arc<PolicyState>,
}
// SAFETY: isolated authored model, delegated to the same original modeled OS
// source. No location/OS service or physical radio qualification is claimed.
unsafe impl CountryIo for ScanOs {
    fn country(&mut self) -> Result<SelectedCountry, CountryIoError> {
        self.country.country()
    }
    fn current(&mut self, revision: u64) -> Result<bool, CountryIoError> {
        self.country.current(revision)
    }
}
struct Lease<'a> {
    os: &'a mut ScanOs,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        assert_eq!(self.os.policy.held.fetch_sub(1, Ordering::SeqCst), 1);
    }
}
impl OsLease for Lease<'_> {
    fn revision(&self) -> u64 {
        71
    }
    fn allows(&mut self, operation: regulatory::Operation) -> bool {
        assert_eq!(self.os.policy.held.load(Ordering::SeqCst), 1);
        !self.os.country.revoked.load(Ordering::SeqCst)
            && matches!(operation, regulatory::Operation::Receive(ch) if usize::from(ch.number) != self.os.policy.deny_channel.load(Ordering::SeqCst))
    }
}
// SAFETY: synchronous modeled service with a unique mutable held lease through
// the actual modeled DMA publication; this is not a production OS attachment.
unsafe impl OsPolicy for ScanOs {
    type Lease<'a> = Lease<'a>;
    fn acquire(&mut self, _: regulatory::NativeContext) -> Option<Self::Lease<'_>> {
        let count = self.policy.acquired.fetch_add(1, Ordering::SeqCst) + 1;
        if self.policy.revoke_at_acquire.load(Ordering::SeqCst) == count {
            self.country.revoked.store(true, Ordering::SeqCst);
        }
        if self.policy.unavailable.load(Ordering::SeqCst)
            || self.country.revoked.load(Ordering::SeqCst)
        {
            return None;
        }
        assert_eq!(self.policy.held.fetch_add(1, Ordering::SeqCst), 0);
        Some(Lease { os: self })
    }
}
fn bytes() -> Vec<u8> {
    let mut bytes = ax200_mac_tests::firmware_bytes(0);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            let versions = [0x0d, 1, 15, 0, 0x0e, 1, 1, 0];
            bytes.splice(at + 8 + len..at + 8 + len, versions);
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes
}
fn ready<'a>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    policy: &Arc<PolicyState>,
    short_deadline: bool,
) -> (Ax200Scan<'a, Model, ClockBios, ScanOs>, u16, u16) {
    let os = ScanOs {
        country: Os {
            drops: native.os_drops.clone(),
            revoked: native.revoked.clone(),
            unavailable: false,
        },
        policy: policy.clone(),
    };
    let mut options = Ax200SetupOptions::new(Clock {
        ticks_per_microsecond: if short_deadline { 1 } else { 1_000_000 },
    });
    if short_deadline {
        options.command_timeout_us = 1;
    }
    let (country, mut sequence, mut entry) =
        ax200_mac_tests::country_ready_with_os(catalog, empty, source, native, options, os, true);
    let mut mac = country
        .begin_mac_context()
        .unwrap_or_else(|_| panic!("MAC"));
    unsafe { mac.advance(source) }.unwrap();
    for command in mac.commands().to_vec() {
        complete(
            &mac.country.board.scan.mcc.setup.lari.radio.initialized.boot,
            &native.domain,
            entry,
            entry + 1,
            &command_packet(command.id().wire(), sequence, &[]),
        );
        unsafe { mac.advance(source) }.unwrap();
        sequence += 1;
        entry += 1;
    }
    // SAFETY: both modeled OS interfaces above share this exact original
    // selection/database and synchronous native-owner fixture.
    let scan = unsafe { mac.begin_scan() }.unwrap_or_else(|_| panic!("scan"));
    (scan, sequence, entry)
}
fn channel(number: u16) -> Channel {
    Channel {
        band: Band::Ghz2,
        number,
        frequency_mhz: 2407 + number * 5,
    }
}
fn request(active: bool) -> scan::Request {
    scan::Request::new(
        vec![channel(1), channel(2)],
        if active {
            vec![b"owned".to_vec()]
        } else {
            vec![]
        },
        vec![221, 3, 0x12, 0x34, 0x56],
    )
    .unwrap()
}
fn boot<'b, 'a>(scan: &'b Ax200Scan<'a, Model, ClockBios, ScanOs>) -> &'b RomBoot<'a, Model> {
    &scan
        .mac
        .country
        .board
        .scan
        .mcc
        .setup
        .lari
        .radio
        .initialized
        .boot
}
fn ack(
    scan: &Ax200Scan<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    entry: u16,
    sequence: u16,
    abort: bool,
) {
    complete(
        boot(scan),
        &native.domain,
        entry,
        entry + 1,
        &command_packet(
            super::super::super::command::Id {
                group: 1,
                opcode: if abort { 0x0e } else { 0x0d },
                version: 0,
            },
            sequence,
            if abort { &[0, 0, 0, 0] } else { &[] },
        ),
    );
}
fn completion(uid: u32, status: u8, group: u8) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[..4].copy_from_slice(&uid.to_le_bytes());
    body[6] = status;
    body[7] = 3;
    command_packet(
        super::super::super::command::Id {
            group,
            opcode: 0x0f,
            version: 0,
        },
        0x8000,
        &body,
    )
}
#[test]
fn passive_umac15_holds_original_os_lease_at_real_dma_handoff_and_requires_actual_completion() {
    exercise_completion(false);
}
#[test]
#[ignore = "requires unchanged pinned AX200 firmware"]
fn actual_ax200_umac15_request_and_captured_scan_completion_schema() {
    exercise_completion(true);
}
fn exercise_completion(actual: bool) {
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
        bytes()
    };
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
    let before = native.domain.records.lock().unwrap().syncs;
    let policy_at_sync = policy.clone();
    native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
        assert_eq!(
            policy_at_sync.held.load(Ordering::SeqCst),
            1,
            "OS lease dropped before native DMA visibility"
        );
    }));
    assert_eq!(
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap(),
        Ax200ScanPhase::WaitingStart
    );
    native.domain.records.lock().unwrap().device_sync_hook = None;
    assert_eq!(policy.held.load(Ordering::SeqCst), 0);
    // One OS pair at admission, one at exact publication; never per-channel.
    assert_eq!(policy.acquired.load(Ordering::SeqCst), 2);
    assert_eq!(native.domain.records.lock().unwrap().syncs, before + 3);
    assert_eq!(scan.protocol_phase(), scan::Phase::Submitted);
    let payload = scan.command_bytes().unwrap();
    assert_eq!(payload.len(), 1940);
    assert_eq!(&payload[..8], &[0, 0, 0, 0, 6, 0, 0, 0]);
    assert_eq!(
        u16::from_le_bytes(payload[8..10].try_into().unwrap()),
        (1 << 11) | (1 << 1) | (1 << 7)
    );
    assert_eq!(&payload[12..20], &[10, 10, 2, 8, 10, 0, 44, 1]);
    assert_eq!(&payload[44..48], &[32, 2, 10, 2]);
    assert_eq!(
        &payload[48..64],
        &[0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 0]
    );
    assert!(payload[64..584].iter().all(|byte| *byte == 0));
    assert_eq!(&payload[584..596], &[0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&payload[616 + 26..616 + 31], &[221, 3, 0x12, 0x34, 0x56]);
    assert!(payload[1128..].iter().all(|byte| *byte == 0));
    // Verify bytes actually visible through the split device IOVA descriptor.
    let descriptor = device_read(
        &native.domain,
        boot(&scan).command.region().address,
        usize::from(sequence & 31) * 256,
        256,
    );
    let encoded = super::super::super::command::Command::encode(
        super::super::super::command::Id {
            group: 1,
            opcode: 0x0d,
            version: 0,
        },
        0,
        sequence,
        payload,
    )
    .unwrap();
    let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
    let remainder = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
    assert_eq!(
        device_read(&native.domain, first, 0, encoded.first_tb().len()),
        encoded.first_tb()
    );
    assert_eq!(
        device_read(&native.domain, remainder, 0, encoded.remainder().len()),
        encoded.remainder()
    );
    ack(&scan, &native, entry, sequence, false);
    assert_eq!(
        unsafe { scan.advance(&source) }.unwrap(),
        Ax200ScanPhase::Scanning
    );
    assert!(scan.completion().is_none());
    assert_eq!(
        unsafe { scan.advance(&source) }.unwrap(),
        Ax200ScanPhase::Scanning
    );
    complete(
        boot(&scan),
        &native.domain,
        entry + 1,
        entry + 2,
        &completion(0, 1, 0),
    );
    assert_eq!(
        unsafe { scan.advance(&source) }.unwrap(),
        Ax200ScanPhase::DrainRequired
    );
    assert_eq!(
        scan.completion().unwrap().outcome(),
        scan::Outcome::Completed
    );
    assert_eq!(scan.completion().unwrap().ebs_status(), 3);
    assert_eq!(scan.protocol_phase(), scan::Phase::Retiring);
    let bell = native.state.lock().unwrap().registers[&0x460];
    assert_eq!(
        unsafe { scan.start(request(false), 30_000_000, &source) },
        Err(Ax200ScanError::State)
    );
    assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
    scan.stop().unwrap();
    drop(scan);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
    assert_eq!(native.drops.load(Ordering::Relaxed), 1);
    assert_eq!(native.bios_drops.load(Ordering::Relaxed), 1);
    assert_eq!(native.os_drops.load(Ordering::Relaxed), 1);
}
#[test]
fn active_late_channel_denial_missing_os_and_between_guard_revocation_never_submit() {
    for case in 0..5 {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, _, _) = ready(&catalog, &empty, &source, &native, &policy, false);
        match case {
            1 => policy.deny_channel.store(2, Ordering::SeqCst),
            2 => policy.unavailable.store(true, Ordering::SeqCst),
            3 => policy.revoke_at_acquire.store(2, Ordering::SeqCst),
            4 => native.revoked.store(true, Ordering::SeqCst),
            _ => (),
        }
        let bell = native.state.lock().unwrap().registers[&0x460];
        let allocations = source.calls.load(Ordering::Relaxed);
        let error = unsafe { scan.start(request(case == 0), 30_000_000, &source) }.unwrap_err();
        assert_eq!(
            error,
            match case {
                0 => Ax200ScanError::ProbePowerRequired,
                1 => Ax200ScanError::Regulatory(regulatory::Error::OsDenied),
                2 | 3 => Ax200ScanError::Regulatory(regulatory::Error::OsUnavailable),
                _ => Ax200ScanError::Country(Ax200CountryError::Revoked),
            }
        );
        assert_eq!(scan.phase(), Ax200ScanPhase::NotStarted);
        assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
        assert!(scan.command_ticket().is_none());
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        assert_eq!(policy.held.load(Ordering::SeqCst), 0);
        scan.stop().unwrap();
    }
}
#[test]
fn cancel_revoke_and_abort_not_found_wait_for_original_scan_completion_even_in_rfkill() {
    for revoked in [false, true] {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        ack(&scan, &native, entry, sequence, false);
        unsafe { scan.advance(&source) }.unwrap();
        if revoked {
            native.revoked.store(true, Ordering::SeqCst);
        } else {
            scan.cancel().unwrap();
        }
        *native
            .state
            .lock()
            .unwrap()
            .registers
            .get_mut(&0x24)
            .unwrap() &= !0x08000000;
        assert_eq!(
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::WaitingAbort
        );
        complete(
            boot(&scan),
            &native.domain,
            entry + 1,
            entry + 2,
            &command_packet(
                super::super::super::command::Id {
                    group: 1,
                    opcode: 0x0e,
                    version: 0,
                },
                sequence + 1,
                &2u32.to_le_bytes(),
            ),
        );
        assert_eq!(
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::Cancelling
        );
        assert!(scan.completion().is_none());
        assert_eq!(scan.protocol_phase(), scan::Phase::Cancelling);
        assert_eq!(
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::Cancelling
        );
        complete(
            boot(&scan),
            &native.domain,
            entry + 2,
            entry + 3,
            &completion(0, 2, 0),
        );
        assert_eq!(
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::DrainRequired
        );
        assert_eq!(scan.completion().unwrap().outcome(), scan::Outcome::Aborted);
        if revoked {
            assert_eq!(
                scan.first_error(),
                Some(&Ax200ScanError::Country(Ax200CountryError::Revoked))
            );
        }
        scan.stop().unwrap();
    }
}
#[test]
fn wrong_uid_status_and_group_cannot_complete_or_release_original_scan() {
    for case in 0..5 {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        ack(&scan, &native, entry, sequence, false);
        unsafe { scan.advance(&source) }.unwrap();
        let mut packet = completion(
            if case == 0 { 1 } else { 0 },
            if case == 1 { 7 } else { 1 },
            u8::from(case == 2),
        );
        let body_len = match case {
            3 => 15,
            4 => 17,
            _ => 16,
        };
        packet[..4].copy_from_slice(&(4u32 + body_len as u32).to_le_bytes());
        complete(boot(&scan), &native.domain, entry + 1, entry + 2, &packet);
        let result = unsafe { scan.advance(&source) };
        match case {
            0 => assert_eq!(result, Err(Ax200ScanError::CompletionUid(1))),
            1 => assert_eq!(result, Err(Ax200ScanError::CompletionStatus(7))),
            3 | 4 => assert_eq!(result, Err(Ax200ScanError::CompletionLength(body_len))),
            _ => {
                assert_eq!(result.unwrap(), Ax200ScanPhase::Scanning);
                assert_eq!(scan.take_other_notification().unwrap().group, 1);
            }
        }
        assert!(scan.completion().is_none());
        if case != 2 {
            assert_eq!(
                scan.rejected_completion_packet().unwrap(),
                &packet[..8 + body_len]
            );
        }
        assert!(!native.domain.records.lock().unwrap().live.is_empty());
        drop(scan);
        assert_eq!(native.drops.load(Ordering::Relaxed), 0);
        assert_eq!(native.bios_drops.load(Ordering::Relaxed), 0);
        assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn native_scan_visibility_pending_and_reclaim_deadlines_retain_exact_original_owner() {
    for case in 0..4 {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(
            &catalog,
            &empty,
            &source,
            &native,
            &policy,
            case == 1 || case == 2,
        );
        let bell = native.state.lock().unwrap().registers[&0x460];
        if case == 0 {
            let mut r = native.domain.records.lock().unwrap();
            // Large UMAC body really has remainder syncN, TB0N+1, TFDN+2.
            r.sync_fail = Some(r.syncs + 2);
        }
        let result = unsafe { scan.start(request(false), 30_000_000, &source) };
        if case == 0 {
            assert_eq!(
                result,
                Err(Ax200ScanError::Boot(Error::Dma(dma::Error::Dma(
                    crate::bus::dma::mapping::DmaError::VisibilityFailed
                ))))
            );
            assert_eq!(scan.protocol_phase(), scan::Phase::Submitted);
            assert!(boot(&scan).hcmd.pending_is_present());
            assert_eq!(boot(&scan).state, State::Poisoned);
            assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        } else {
            result.unwrap();
            let original = scan.command_ticket().unwrap().clone();
            if case == 2 {
                ack(&scan, &native, entry, sequence, false);
                let mut r = native.domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
            }
            if case < 3 {
                assert_eq!(
                    unsafe { scan.advance(&source) },
                    Err(Ax200ScanError::Deadline)
                );
                assert_eq!(scan.command_ticket(), Some(&original));
                assert!(boot(&scan).hcmd.pending_is_present());
                assert!(scan.completion().is_none());
            } else {
                let mut state = native.state.lock().unwrap();
                state.fail = Some(state.ops.len() + 1);
                drop(state);
                assert!(scan.stop().is_err());
                assert!(scan.first_error().is_some());
            }
        }
        drop(scan);
        assert!(!native.domain.records.lock().unwrap().live.is_empty());
        assert_eq!(native.drops.load(Ordering::Relaxed), 0);
        assert_eq!(native.bios_drops.load(Ordering::Relaxed), 0);
        assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
    }
}
fn beacon_packet() -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[..2].copy_from_slice(&0x80u16.to_le_bytes());
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    frame[16..22].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame.extend([0, 4, b't', b'e', b's', b't', 3, 1, 1]);
    let mut payload = vec![0; 48];
    payload[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    payload[7] = 1 << 6;
    payload[12..16].copy_from_slice(&3u32.to_le_bytes()); // actual CRC/overrun OK
    payload[16..20].copy_from_slice(&(127u32 << 24).to_le_bytes());
    payload[28..32].copy_from_slice(&(3u32 << 14).to_le_bytes());
    payload[32..35].copy_from_slice(&[44, 56, 1]);
    payload.extend(frame);
    command_packet(
        super::super::super::command::Id {
            group: 0,
            opcode: 0xc1,
            version: 0,
        },
        0x8000,
        &payload,
    )
}
#[test]
fn actual_completed_mpdu_is_policy_checked_and_precedes_same_rb_scan_completion() {
    for revoked in [false, true] {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        ack(&scan, &native, entry, sequence, false);
        unsafe { scan.advance(&source) }.unwrap();
        let mut packet = beacon_packet();
        let original_packet_len =
            (u32::from_le_bytes(packet[..4].try_into().unwrap()) & 0x3fff) as usize + 4;
        let next = original_packet_len.next_multiple_of(64);
        let terminal = completion(0, 1, 0);
        let tail = packet.len() - next;
        packet[next..].copy_from_slice(&terminal[..tail]);
        complete(boot(&scan), &native.domain, entry + 1, entry + 2, &packet);
        // advance cannot move completion ahead of the preceding original MPDU.
        assert_eq!(
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::Scanning
        );
        assert!(scan.completion().is_none());
        if revoked {
            native.revoked.store(true, Ordering::SeqCst);
        }
        let observation = match scan.poll_result().unwrap() {
            ScanResultProgress::Observed(result) => result,
            _ => panic!("actual beacon missing"),
        };
        assert_eq!(
            observation.observed().raw_packet(),
            &packet[..original_packet_len]
        );
        if revoked {
            assert_eq!(
                observation.result().unwrap_err(),
                &Ax200ScanError::Country(Ax200CountryError::Revoked)
            );
        } else {
            let bss = observation.result().unwrap();
            assert_eq!(bss.ssid.as_deref(), Some(b"test".as_slice()));
            assert_eq!(bss.channel, channel(1));
            assert_eq!(bss.signal_dbm, Some(-44));
        }
        assert_eq!(
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::DrainRequired
        );
        scan.replenish_completed_receive().unwrap();
        // Immutable actual RX bytes survive rearming/writes to the old RB.
        assert_eq!(
            observation.observed().raw_packet(),
            &packet[..original_packet_len]
        );
        scan.stop().unwrap();
    }
}
#[test]
fn elapsed_scan_budget_submits_real_abort_and_abort_ack_does_not_disable_completion_deadline() {
    for timeout in [false, true] {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, true);
        unsafe {
            scan.start(
                request(false),
                if timeout { 1 } else { 30_000_000 },
                &source,
            )
        }
        .unwrap();
        if !timeout {
            scan.cancel().unwrap();
        }
        ack(&scan, &native, entry, sequence, false);
        assert_eq!(
            unsafe { scan.advance(&source) }.unwrap(),
            Ax200ScanPhase::WaitingAbort
        );
        assert_eq!(scan.protocol_phase(), scan::Phase::Cancelling);
        assert!(scan.completion().is_none());
        let original = scan.command_ticket().unwrap().clone();
        ack(&scan, &native, entry + 1, sequence + 1, true);
        assert_eq!(
            unsafe { scan.advance(&source) },
            Err(Ax200ScanError::Deadline)
        );
        assert_eq!(scan.phase(), Ax200ScanPhase::Failed);
        assert_eq!(scan.abort_response().unwrap().ticket, original);
        assert!(scan.command_ticket().is_none());
        assert!(scan.completion().is_none());
        assert_eq!(scan.protocol_phase(), scan::Phase::Cancelling);
        assert!(!native.domain.records.lock().unwrap().live.is_empty());
        assert_eq!(
            unsafe { scan.advance(&source) },
            Err(Ax200ScanError::Deadline)
        );
        scan.stop().unwrap();
        drop(scan);
        assert!(native.domain.records.lock().unwrap().live.is_empty());
        assert_eq!(native.os_drops.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn malformed_abort_reply_retains_actual_response_and_original_scan_lifetime() {
    for body in [vec![], vec![0; 3], vec![0; 5], 3u32.to_le_bytes().to_vec()] {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
        ack(&scan, &native, entry, sequence, false);
        unsafe { scan.advance(&source) }.unwrap();
        scan.cancel().unwrap();
        unsafe { scan.advance(&source) }.unwrap();
        complete(
            boot(&scan),
            &native.domain,
            entry + 1,
            entry + 2,
            &command_packet(
                super::super::super::command::Id {
                    group: 1,
                    opcode: 0x0e,
                    version: 0,
                },
                sequence + 1,
                &body,
            ),
        );
        let error = if body.len() == 4 {
            Ax200ScanError::AbortStatus(3)
        } else {
            Ax200ScanError::AbortResponseLength(body.len())
        };
        assert_eq!(unsafe { scan.advance(&source) }, Err(error.clone()));
        assert_eq!(scan.abort_response().unwrap().raw, body);
        assert_eq!(scan.first_error(), Some(&error));
        assert_eq!(scan.protocol_phase(), scan::Phase::Cancelling);
        assert!(scan.completion().is_none());
        scan.stop().unwrap();
    }
}
#[test]
fn actual_completion_wins_host_poll_deadline_but_still_requires_real_radio_rx_drain() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, true);
    unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
    scan.cancel().unwrap();
    ack(&scan, &native, entry, sequence, false);
    assert_eq!(
        unsafe { scan.advance(&source) }.unwrap(),
        Ax200ScanPhase::WaitingAbort
    );
    let mut packet = command_packet(
        super::super::super::command::Id {
            group: 1,
            opcode: 0x0e,
            version: 0,
        },
        sequence + 1,
        &0u32.to_le_bytes(),
    );
    let terminal = completion(0, 2, 0);
    packet[64..].copy_from_slice(&terminal[..4096 - 64]);
    complete(boot(&scan), &native.domain, entry + 1, entry + 2, &packet);
    assert_eq!(
        unsafe { scan.advance(&source) }.unwrap(),
        Ax200ScanPhase::DrainRequired
    );
    assert_eq!(scan.completion().unwrap().outcome(), scan::Outcome::Aborted);
    assert_eq!(scan.protocol_phase(), scan::Phase::Retiring);
    assert!(scan.first_error().is_none());
    assert!(!native.domain.records.lock().unwrap().live.is_empty());
    scan.stop().unwrap();
}
#[test]
fn prepublication_native_read_fault_remains_first_error_without_scan_submission() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, _, _) = ready(&catalog, &empty, &source, &native, &policy, false);
    native.state.lock().unwrap().fail_read = Some(8);
    let error = Ax200ScanError::Boot(Error::Access(power::AccessError::Unavailable));
    let bell = native.state.lock().unwrap().registers[&0x460];
    assert_eq!(
        unsafe { scan.start(request(false), 30_000_000, &source) },
        Err(error.clone())
    );
    assert_eq!(scan.first_error(), Some(&error));
    assert_eq!(scan.phase(), Ax200ScanPhase::Failed);
    assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
    native.state.lock().unwrap().fail_read = None;
    assert_eq!(
        unsafe { scan.start(request(false), 30_000_000, &source) },
        Err(error)
    );
    assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
    assert!(scan.command_ticket().is_none());
    scan.stop().unwrap();
}
#[test]
fn result_poll_native_fault_and_repaired_retry_return_the_same_original_error() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, sequence, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
    unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap();
    ack(&scan, &native, entry, sequence, false);
    unsafe { scan.advance(&source) }.unwrap();
    native.state.lock().unwrap().fail_read = Some(8);
    let error = Ax200ScanError::Boot(Error::Access(power::AccessError::Unavailable));
    assert_eq!(scan.poll_result().err(), Some(error.clone()));
    assert_eq!(scan.phase(), Ax200ScanPhase::Failed);
    native.state.lock().unwrap().fail_read = None;
    assert_eq!(scan.poll_result().err(), Some(error.clone()));
    assert_eq!(scan.first_error(), Some(&error));
    assert_eq!(scan.protocol_phase(), scan::Phase::Submitted);
    assert!(scan.completion().is_none());
    scan.stop().unwrap();
}
#[test]
fn prepublication_completed_rbs_and_backpressure_never_relabel_old_rx_as_new_scan() {
    for case in 0..3 {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, _, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        let old = beacon_packet();
        let mut unrelated = command_packet(
            super::super::super::command::Id {
                group: 0,
                opcode: 0x99,
                version: 0,
            },
            0x8000,
            &[],
        );
        if case == 2 {
            let header = unrelated[..8].to_vec();
            unrelated.fill(0);
            for at in (0..4096).step_by(64) {
                unrelated[at..at + 8].copy_from_slice(&header);
            }
        }
        if case != 0 {
            complete(boot(&scan), &native.domain, entry, entry + 1, &unrelated);
        }
        let index = entry + u16::from(case != 0);
        complete(
            boot(&scan),
            &native.domain,
            index,
            index + 1,
            if case == 2 { &unrelated } else { &old },
        );
        let bell = native.state.lock().unwrap().registers[&0x460];
        let allocations = source.calls.load(Ordering::Relaxed);
        let expected = if case == 2 {
            Ax200ScanError::ReceiveBackpressure { notifications: 128 }
        } else {
            Ax200ScanError::PreScanReceiveRequired
        };
        assert_eq!(
            unsafe { scan.start(request(false), 30_000_000, &source) },
            Err(expected)
        );
        assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
        assert!(scan.request().is_none());
        assert!(scan.command_ticket().is_none());
        assert_eq!(policy.acquired.load(Ordering::SeqCst), 0);
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        if case < 2 {
            let observed = match scan.poll_pre_scan_receive().unwrap() {
                MpduProgress::Observed(observed) => observed,
                _ => panic!("old raw MPDU was not retained"),
            };
            let length = (u32::from_le_bytes(old[..4].try_into().unwrap()) & 0x3fff) as usize + 4;
            assert_eq!(observed.raw_packet(), &old[..length]);
            assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
            assert!(scan.request().is_none());
        }
        let mut drained = 0;
        while scan.take_other_notification().is_some() {
            drained += 1;
        }
        assert_eq!(
            drained,
            match case {
                0 => 0,
                1 => 1,
                _ => 128,
            }
        );
        // Quiet original RX has now actually been observed. Only a fresh exact
        // request can enter Submitted; old captures remain raw historical data.
        assert_eq!(
            unsafe { scan.start(request(false), 30_000_000, &source) }.unwrap(),
            Ax200ScanPhase::WaitingStart
        );
        scan.stop().unwrap();
    }
}
#[test]
fn prepublication_second_rb_reserved_events_remain_canonical_and_block_admission() {
    for mcc in [false, true] {
        let bytes = bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (mut scan, _, entry) = ready(&catalog, &empty, &source, &native, &policy, false);
        let unrelated = command_packet(
            super::super::super::command::Id {
                group: 0,
                opcode: 0x99,
                version: 0,
            },
            0x8000,
            &[],
        );
        let reserved = if mcc {
            command_packet(
                super::super::super::command::Id {
                    group: 0,
                    opcode: 0xc9,
                    version: 0,
                },
                0x8000,
                &[],
            )
        } else {
            completion(0, 1, 0)
        };
        complete(boot(&scan), &native.domain, entry, entry + 1, &unrelated);
        complete(boot(&scan), &native.domain, entry + 1, entry + 2, &reserved);
        let bell = native.state.lock().unwrap().registers[&0x460];
        let allocations = source.calls.load(Ordering::Relaxed);
        let expected = if mcc {
            Ax200ScanError::Regulatory(regulatory::Error::HardwareUnavailable)
        } else {
            Ax200ScanError::StaleNotification
        };
        assert_eq!(
            unsafe { scan.start(request(false), 30_000_000, &source) },
            Err(expected.clone())
        );
        assert_eq!(boot(&scan).hcmd.notification_count(), 2);
        assert_eq!(scan.take_other_notification().unwrap().command, 0x99);
        assert!(scan.take_other_notification().is_none());
        assert!(matches!(
            scan.poll_pre_scan_receive().unwrap(),
            MpduProgress::Pending
        ));
        // Neither diagnostic path can consume the canonical event or reopen
        // admission, even though all unrelated traffic has actually drained.
        assert_eq!(boot(&scan).hcmd.notification_count(), 1);
        assert!(
            boot(&scan)
                .hcmd
                .has_matching(if mcc { 0xc9 } else { 0x0f }, 0)
        );
        assert_eq!(
            unsafe { scan.start(request(false), 30_000_000, &source) },
            Err(expected)
        );
        assert_eq!(scan.phase(), Ax200ScanPhase::NotStarted);
        assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
        assert!(scan.request().is_none());
        assert!(scan.command_ticket().is_none());
        assert_eq!(policy.acquired.load(Ordering::SeqCst), 0);
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
        scan.stop().unwrap();
    }
}
#[test]
fn pre_scan_raw_drain_native_fault_is_sticky_before_any_request_publication() {
    let bytes = bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (mut scan, _, _) = ready(&catalog, &empty, &source, &native, &policy, false);
    let bell = native.state.lock().unwrap().registers[&0x460];
    let allocations = source.calls.load(Ordering::Relaxed);
    native.state.lock().unwrap().fail_read = Some(8);
    let error = Ax200ScanError::Boot(Error::Access(power::AccessError::Unavailable));
    assert_eq!(scan.poll_pre_scan_receive().err(), Some(error.clone()));
    assert_eq!(scan.first_error(), Some(&error));
    assert_eq!(scan.phase(), Ax200ScanPhase::Failed);
    native.state.lock().unwrap().fail_read = None;
    assert_eq!(scan.poll_pre_scan_receive().err(), Some(error.clone()));
    assert_eq!(
        unsafe { scan.start(request(false), 30_000_000, &source) },
        Err(error.clone())
    );
    assert_eq!(scan.first_error(), Some(&error));
    assert_eq!(scan.protocol_phase(), scan::Phase::Idle);
    assert!(scan.request().is_none());
    assert!(scan.command_ticket().is_none());
    assert_eq!(policy.acquired.load(Ordering::SeqCst), 0);
    assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
    assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
    scan.stop().unwrap();
}

#[path = "ax200_scan_retirement_tests.rs"]
mod retirement_tests;
