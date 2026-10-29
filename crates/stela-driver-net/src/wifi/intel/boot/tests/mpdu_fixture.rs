// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

pub(super) fn exercise_mpdu_observations(
    radio: &mut ColdRadio<'_, Model>,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
) {
    use crate::wifi::intel::command::Id;
    let ax210 = radio.initialized.boot.profile.family() == Family::Ax210;
    radio.replenish_completed_receive().unwrap();
    let allocations = source.calls.load(Ordering::Relaxed);
    let maps = domain.records.lock().unwrap().maps;
    let mut preserved = None;
    let mut normalized_preserved = None;
    let wire_frame = |cycle: u8| {
        let mut bytes: Vec<_> = (0..45u8).map(|n| n.wrapping_add(cycle)).collect();
        bytes[..2].copy_from_slice(&0x4208u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&(u16::from(cycle) << 4).to_le_bytes());
        bytes[24..32].copy_from_slice(&[cycle + 1, 0, 0, 0x60, 0, 0, 0, 0]);
        bytes
    };
    let complete_payload = |radio: &ColdRadio<'_, Model>, payload: &[u8]| {
        let boot = &radio.initialized.boot;
        let slot = boot.read;
        let stride = if ax210 { 16 } else { 8 };
        let free = device_read(
            domain,
            boot.free.region().address,
            usize::from(slot) * stride,
            stride,
        );
        let vid = if ax210 {
            u16::from_le_bytes(free[..2].try_into().unwrap())
        } else {
            (u64::from_le_bytes(free.try_into().unwrap()) & 0xfff) as u16
        };
        let mut packet = command_packet(
            Id {
                group: 0,
                opcode: 0xc1,
                version: 0,
            },
            0x8000,
            payload,
        );
        let flags = u32::from_le_bytes(packet[..4].try_into().unwrap()) | (1 << 26);
        packet[..4].copy_from_slice(&flags.to_le_bytes());
        complete_from_free_slot(boot, domain, slot, vid, slot, &packet);
    };
    for cycle in 0..40u8 {
        let size = if ax210 { 64 } else { 48 };
        let mut payload = vec![0; size + 45];
        payload[..2].copy_from_slice(&45u16.to_le_bytes());
        payload[2] = 4 << 4; // 8 source-reported MIC/CRC bytes
        payload[3] = 0x20; // 2-byte pad after MAC + kept IV
        payload[7] = 1 << 6; // explicit band code 1 = 2.4 GHz
        payload[12..16].copy_from_slice(&0x0500026fu32.to_le_bytes());
        payload[16..20].copy_from_slice(&(127u32 << 24).to_le_bytes());
        let (rate, energy) = if ax210 { (36, 40) } else { (28, 32) };
        payload[rate..rate + 4].copy_from_slice(&(3u32 << 14).to_le_bytes());
        payload[energy..energy + 3].copy_from_slice(&[44, 56, 6]);
        payload[size..].copy_from_slice(&wire_frame(cycle));
        complete_payload(radio, &payload);
        let received = match radio.poll_mpdu_observation().unwrap() {
            MpduProgress::Observed(received) => received,
            _ => panic!("missing actual completed MPDU"),
        };
        assert_eq!(received.raw_mpdu(), &payload[size..]);
        assert_eq!(received.descriptor(), &payload[..size]);
        assert!(received.trailing().is_empty());
        assert_eq!(received.packet_flags() & (1 << 26), 1 << 26);
        assert_eq!(received.receive_queue(), 0);
        assert_eq!(received.metadata().status.station_id(), Some(5));
        assert_eq!(received.metadata().status.cipher_code(), 2);
        assert!(received.metadata().status.mic_ok_bit());
        assert!(!received.metadata().status.decrypted_bit());
        let normalized = received.normalize().unwrap();
        let mut expected = wire_frame(cycle)[..32].to_vec();
        expected.extend(&wire_frame(cycle)[34..37]);
        assert_eq!(normalized.frame().bytes(), expected);
        assert_eq!(normalized.frame().radio.frequency_mhz, 2437);
        assert_eq!(normalized.frame().security.key, None);
        assert_eq!(
            normalized.frame().security.integrity,
            crate::wifi::security::Integrity::Unknown
        );
        assert_eq!(
            normalized.frame().security.pn.unwrap().value(),
            u64::from(cycle) + 1
        );
        assert_eq!(normalized.key_index(), Some(1));
        assert!(normalized.crypto().decrypted);
        if cycle == 0 {
            preserved = Some(received);
            normalized_preserved = Some(normalized);
        }
        assert!(matches!(
            radio.poll_mpdu_observation().unwrap(),
            MpduProgress::Pending
        ));
        assert_eq!(radio.replenish_completed_receive().unwrap().returned, 1);
    }
    assert_eq!(preserved.unwrap().raw_mpdu(), wire_frame(0));
    let normalized = normalized_preserved.unwrap();
    let mut expected = wire_frame(0)[..32].to_vec();
    expected.extend(&wire_frame(0)[34..37]);
    assert_eq!(normalized.frame().bytes(), expected);
    assert_eq!(normalized.frame().security.pn.unwrap().value(), 1);
    // A malformed descriptor is held as a rejection, never
    // retagged as a frame or allowed to poison the control/RX owner.
    let size = if ax210 { 64 } else { 48 };
    let mut bad = vec![0; size];
    bad[..2].copy_from_slice(&1u16.to_le_bytes());
    complete_payload(radio, &bad);
    let rejected = match radio.poll_mpdu_observation().unwrap() {
        MpduProgress::Rejected(r) => r,
        _ => panic!("malformed frame was not rejected"),
    };
    assert_eq!(
        rejected.error(),
        crate::wifi::intel::receive::mpdu::Error::MpduLength {
            declared: 1,
            available: 0
        }
    );
    assert_eq!(&rejected.raw_packet()[8..], bad);
    assert_eq!(radio.initialized.boot.state, State::PnvmObserved);
    radio.replenish_completed_receive().unwrap();
    // Queue-capacity fixture: canonical packet capture, not forged
    // public diagnostic restoration. One-RB reservation is family-specific.
    let count = if ax210 { 128 } else { 65 };
    for n in 0..count {
        let raw = command_packet(
            Id {
                group: 2,
                opcode: 0xe0,
                version: 0,
            },
            0x8000,
            &[n as u8],
        );
        let packet = Packets::new(radio.initialized.boot.profile.family(), 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        radio
            .initialized
            .boot
            .hcmd
            .retain_notification(&packet)
            .unwrap();
    }
    let before = state.lock().unwrap().ops.len();
    let credits = radio.initialized.boot.credits;
    for _ in 0..3 {
        assert!(
            matches!(radio.poll_mpdu_observation().unwrap(),MpduProgress::Backpressure {notifications} if notifications==count)
        );
    }
    assert_eq!(state.lock().unwrap().ops.len(), before);
    assert_eq!(radio.initialized.boot.credits, credits);
    let mut notice = radio.take_firmware_notification().unwrap();
    assert_eq!(notice.raw, [0]);
    notice.command = 0xc1;
    notice.raw = vec![0; 64];
    assert!(matches!(
        radio.poll_mpdu_observation().unwrap(),
        MpduProgress::Pending
    ));
    for n in 1..count {
        let notification = radio.take_firmware_notification().unwrap();
        assert_eq!(
            (
                notification.command,
                notification.group,
                notification.sequence
            ),
            (0xe0, 2, 0x8000)
        );
        assert_eq!(notification.raw, [n as u8]);
    }
    let foreign = hcmd::CapturedNotification {
        epoch: Arc::new(()),
        bytes: rejected.raw_packet().to_vec(),
    };
    assert!(matches!(
        radio.initialized.boot.decode_captured_mpdu(foreign),
        Err(Error::ReceiveEpoch)
    ));
    assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
    assert_eq!(domain.records.lock().unwrap().maps, maps);
    // Failed CPU handoff cannot issue an MPDU receipt or release
    // mappings. Bus-master/reset stop below still owns teardown.
    complete_payload(radio, &vec![0; size]);
    let live = domain.records.lock().unwrap().live.len();
    {
        let mut r = domain.records.lock().unwrap();
        r.cpu_sync_fail = Some(r.cpu_syncs);
    }
    assert!(matches!(radio.poll_mpdu_observation(), Err(Error::Dma(_))));
    assert_eq!(radio.initialized.boot.state, State::Poisoned);
    assert_eq!(domain.records.lock().unwrap().live.len(), live);
    domain.records.lock().unwrap().cpu_sync_fail = None;
    let before = state.lock().unwrap().ops.len();
    assert!(matches!(radio.poll_mpdu_observation(), Err(Error::State)));
    assert_eq!(state.lock().unwrap().ops.len(), before);
}
