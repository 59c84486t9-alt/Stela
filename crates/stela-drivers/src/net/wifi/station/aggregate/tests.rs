use crate::net::wifi::station::{tests::*, *};
use crate::net::wifi::{
    Amsdu, Band,
    security::{
        self, Cipher, HardwareReplay, InstallOutcome, Integrity, KeyIdentity, KeyScope, KeySlot,
        PacketNumber, ReplaySeed, SecurityStatus, TransmitSeed,
        aggregate::{Error as GroupError, GroupSecurity, OrderedGroup, Shape},
    },
    station::phy::{Mode, Width},
};
use alloc::{rc::Rc, sync::Arc};
use core::cell::Cell;

fn current(controlled: bool) -> (Station, Arc<AssociationContext>) {
    let mut j = modern_join();
    if controlled {
        j.policy = PortPolicy::Controlled;
        let mut elements = modern_ies(false);
        ie(
            &mut elements,
            48,
            &[
                1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
            ],
        );
        j.request = wire::AssociationRequest::new_modern(
            0x11,
            10,
            elements,
            Band::Ghz5,
            Mode::Eht,
            Width::Mhz80,
        )
        .unwrap();
    }
    let mut s = Station::new(LOCAL).unwrap();
    let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
    let Action::Configure {
        context: Some(c),
        ticket,
        ..
    } = a
    else {
        panic!()
    };
    s.complete_configuration(ticket, Completion::Accepted, 3)
        .unwrap();
    (s, c)
}
fn install(scope: KeyScope, material: &[u8; 16]) -> (KeySlot, KeyIdentity) {
    // SAFETY: isolated synthetic slot has no physical/deferred users.
    let mut slot = unsafe { KeySlot::new(8).unwrap() };
    let group = matches!(scope, KeyScope::Group(_));
    let t = slot
        .begin_install(
            if group { 1 } else { 0 },
            Cipher::Ccmp128,
            material,
            ReplaySeed::ZERO,
            scope,
            if group {
                TransmitSeed::RECEIVE_ONLY
            } else {
                TransmitSeed::FIRMWARE_FRESH
            },
        )
        .unwrap();
    slot.complete_install(t, InstallOutcome::Accepted).unwrap();
    let k = slot.installed().unwrap();
    (slot, k)
}
fn frame(
    key: Option<KeyIdentity>,
    pn: Option<u64>,
    tid: Option<u8>,
    seq: u16,
    amsdu: bool,
    receiver: Mac,
    value: u8,
) -> Mpdu {
    let mut bytes = vec![0; if tid.is_some() { 26 } else { 24 }];
    let fc =
        0x0208u16 | if tid.is_some() { 0x80 } else { 0 } | if key.is_some() { 0x4000 } else { 0 };
    bytes[..2].copy_from_slice(&fc.to_le_bytes());
    bytes[4..10].copy_from_slice(&receiver.0);
    bytes[10..16].copy_from_slice(&AP.0);
    bytes[16..22].copy_from_slice(&[2, 0, 0, 0, 0, value]);
    bytes[22..24].copy_from_slice(&(seq << 4).to_le_bytes());
    if let Some(tid) = tid {
        bytes[24] = tid | if amsdu { 0x80 } else { 0 };
    }
    if amsdu {
        bytes.extend_from_slice(&receiver.0);
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, value]);
        bytes.extend_from_slice(&9u16.to_be_bytes());
    }
    bytes.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, value]);
    Mpdu::new(
        bytes,
        response(0xb0, &[0; 6]).radio,
        SecurityStatus {
            key,
            pn: pn.and_then(PacketNumber::new),
            decrypted: key.is_some(),
            integrity: if key.is_some() {
                Integrity::Verified
            } else {
                Integrity::Unknown
            },
            iv_stripped: key.is_some(),
            mic_stripped: key.is_some(),
            ..SecurityStatus::default()
        },
    )
    .unwrap()
}
struct SourceOwner(Rc<Cell<bool>>);
impl Drop for SourceOwner {
    fn drop(&mut self) {
        self.0.set(false);
    }
}
fn owned(
    c: &Arc<AssociationContext>,
    members: Vec<Mpdu>,
    shape: Shape,
) -> (OrderedGroup<SourceOwner>, Rc<Cell<bool>>) {
    let live = Rc::new(Cell::new(true));
    // SAFETY: pure source model keeps its current synthetic owner and
    // whole/group release. Adverse raw observations are checked by the gate.
    let g =
        unsafe { OrderedGroup::new(Arc::clone(c), members, shape, SourceOwner(Rc::clone(&live))) };
    (g, live)
}
fn split(key: Option<KeyIdentity>, pn: u64, tid: u8, seq: u16) -> Vec<Mpdu> {
    (0..3)
        .map(|i| {
            let mut f = frame(
                key,
                (i != 1).then_some(pn),
                Some(tid),
                seq,
                true,
                LOCAL,
                i + 1,
            );
            f.aggregation.amsdu = Some(Amsdu {
                index: u16::from(i),
                first: i == 0,
                last: i == 2,
            });
            f
        })
        .collect()
}
fn change_bytes(f: &Mpdu, mutate: impl FnOnce(&mut Vec<u8>)) -> Mpdu {
    let mut b = f.bytes().to_vec();
    mutate(&mut b);
    let mut new = Mpdu::new(b, f.radio.clone(), f.security).unwrap();
    new.aggregation = f.aggregation;
    new.fcs_error = f.fcs_error;
    new.monitor_only = f.monitor_only;
    new
}

#[test]
fn complete_split_parent_consumes_one_pn_and_preserves_absent_member_observation() {
    let (s, c) = current(true);
    let (mut slot, k) = install(KeyScope::Pairwise(AP), &[1; 16]);
    let frames = split(Some(k), 5, 3, 7);
    let (group, live) = owned(&c, frames, Shape::HardwareSplitAmsdu);
    let received = s.receive_ordered_group(&group, Some(&mut slot)).unwrap();
    assert_eq!(
        received.security(),
        GroupSecurity::Protected {
            key: k,
            pn: PacketNumber::new(5).unwrap()
        }
    );
    let members: Vec<_> = received.members().collect();
    assert_eq!(members.len(), 3);
    assert_eq!(members[1].mpdu().security.pn, None);
    assert_eq!(members[0].payload()[..6], LOCAL.0);
    assert_ne!(
        members[0].mpdu().bytes()[16..22],
        members[1].mpdu().bytes()[16..22]
    );
    assert!(live.get());
    assert!(matches!(
        s.receive_ordered_group(&group, Some(&mut slot)),
        Err(GroupError::Security(security::Error::Replay))
    ));
    assert!(!s.port_open(None, None)); // Replay authentication never opens port.
    drop(received);
    drop(group);
    assert!(!live.get());
}

#[test]
fn open_split_and_single_whole_amsdu_never_invent_key_pn_or_first_flag() {
    let (s, c) = current(false);
    let (group, _) = owned(&c, split(None, 0, 0, 2), Shape::HardwareSplitAmsdu);
    let r = s.receive_ordered_group(&group, None).unwrap();
    assert_eq!(r.security(), GroupSecurity::Open);
    assert_eq!(r.members().len(), 3);
    let mut f = frame(None, None, Some(0), 3, true, LOCAL, 4);
    f.aggregation.amsdu = Some(Amsdu {
        index: 0,
        first: false,
        last: true,
    });
    let (whole, _) = owned(&c, vec![f], Shape::WholeMpdu);
    let r = s.receive_ordered_group(&whole, None).unwrap();
    assert!(
        !r.members()
            .next()
            .unwrap()
            .mpdu()
            .aggregation
            .amsdu
            .unwrap()
            .first
    );
    let (controlled, c) = current(true);
    let (plain, _) = owned(
        &c,
        vec![frame(None, None, Some(0), 1, false, LOCAL, 1)],
        Shape::WholeMpdu,
    );
    assert!(controlled.receive_ordered_group(&plain, None).is_err());
}

#[test]
fn any_bad_member_is_atomic_and_keeps_original_source_owner() {
    for fault in 0..15 {
        let (s, c) = current(true);
        let (mut slot, k) = install(KeyScope::Pairwise(AP), &[2; 16]);
        let good = split(Some(k), 9, 2, 8);
        let mut bad = good.clone();
        match fault {
            0 => bad[2].security.integrity = Integrity::Unknown,
            1 => bad[2].security.decrypted = false,
            2 => bad[2].security.icv_error = true,
            3 => bad[2].security.tkip_mic_error = true,
            4 => bad[2].fcs_error = true,
            5 => bad[2].monitor_only = true,
            6 => bad[2].security.hardware_replay = HardwareReplay::Failed { layout: 1 },
            7 => bad[2].security.key = None,
            8 => bad[2].security.pn = PacketNumber::new(10),
            9 => bad[0].security.pn = None,
            10 => bad[2].aggregation.amsdu.as_mut().unwrap().last = false,
            11 => bad[2].aggregation.amsdu.as_mut().unwrap().first = true,
            12 => bad[2] = change_bytes(&bad[2], |b| b[24] = 0x83),
            13 => bad[2] = change_bytes(&bad[2], |b| b[22] = 0xa0),
            _ => bad[2] = change_bytes(&bad[2], |b| b[1] |= 4),
        }
        let (bad, live) = owned(&c, bad, Shape::HardwareSplitAmsdu);
        assert!(
            s.receive_ordered_group(&bad, Some(&mut slot)).is_err(),
            "fault{fault}"
        );
        assert!(live.get()); // Borrowed failure cannot drop real native owner.
        let (good, _) = owned(&c, good, Shape::HardwareSplitAmsdu);
        s.receive_ordered_group(&good, Some(&mut slot)).unwrap(); // SamePN still fresh.
    }
}

#[test]
fn current_association_peer_channel_and_key_scope_precede_replay_commit() {
    for fault in 0..6 {
        let (mut s, c) = current(true);
        let (mut slot, k) = install(KeyScope::Pairwise(AP), &[3; 16]);
        let good = split(Some(k), 7, 1, 5);
        let mut bad = good.clone();
        match fault {
            0 => bad[1].radio.channel = 40,
            1 => bad[1] = change_bytes(&bad[1], |b| b[10..16].fill(6)),
            2 => bad[1] = change_bytes(&bad[1], |b| b[4..10].fill(6)),
            3 => bad[1] = change_bytes(&bad[1], |b| b[1] = 0x41),
            4 => {
                s.disconnect().unwrap();
            }
            _ => {}
        }
        let other = current(true).1;
        let (bad, _) = owned(
            if fault == 5 { &other } else { &c },
            bad,
            Shape::HardwareSplitAmsdu,
        );
        assert!(s.receive_ordered_group(&bad, Some(&mut slot)).is_err());
        if fault != 4 {
            let (good, _) = owned(&c, good, Shape::HardwareSplitAmsdu);
            s.receive_ordered_group(&good, Some(&mut slot)).unwrap();
        }
    }
}

#[test]
fn malformed_shape_payload_bound_and_rfc1042_injection_never_consume_pn() {
    for fault in 0..6 {
        let (s, c) = current(true);
        let (mut slot, k) = install(KeyScope::Pairwise(AP), &[4; 16]);
        let good = split(Some(k), 8, 0, 1);
        let mut bad = good.clone();
        let mut shape = Shape::HardwareSplitAmsdu;
        match fault {
            0 => bad.clear(),
            1 => shape = Shape::WholeMpdu,
            2 => {
                bad.truncate(1);
            }
            3 => bad[1] = change_bytes(&bad[1], |b| b[24] &= !0x80),
            4 => {
                bad[0] = change_bytes(&bad[0], |b| {
                    b[26..32].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0])
                })
            }
            _ => bad[2] = change_bytes(&bad[2], |b| b.resize(7000, 0)),
        }
        let (bad, _) = owned(&c, bad, shape);
        assert!(s.receive_ordered_group(&bad, Some(&mut slot)).is_err());
        let (good, _) = owned(&c, good, Shape::HardwareSplitAmsdu);
        s.receive_ordered_group(&good, Some(&mut slot)).unwrap();
    }
}

#[test]
fn reinstalled_gtk_takes_per_queue_floors_from_the_os_rsc() {
    let (s, c) = current(true);
    let material = [9; 16];
    let (mut slot, k) = install(KeyScope::Group(AP), &material);
    for queue in 0..17 {
        let tid = (queue < 16).then_some(queue as u8);
        let f = frame(Some(k), Some(20 + queue), tid, 1, false, Mac([0xff; 6]), 1);
        let (g, _) = owned(&c, vec![f], Shape::WholeMpdu);
        s.receive_ordered_group(&g, Some(&mut slot)).unwrap();
    }
    slot.invalidate();
    // SAFETY: pure owner model has no remaining groups or device users.
    unsafe {
        slot.retire_after_drain();
    }
    // The OS supplies each queue's RSC from its authenticated key exchange.
    let rsc = core::array::from_fn(|queue| {
        PacketNumber::new(match queue {
            0 => 36,
            16 => 900,
            _ => 20 + queue as u64,
        })
        .unwrap()
    });
    let t = slot
        .begin_install(
            1,
            Cipher::Ccmp128,
            &material,
            ReplaySeed::per_queue(rsc),
            KeyScope::Group(AP),
            TransmitSeed::RECEIVE_ONLY,
        )
        .unwrap();
    slot.complete_install(t, InstallOutcome::Accepted).unwrap();
    let next = slot.installed().unwrap();
    let (s, c) = current(true); // New association context, sameAP.
    for queue in 0..17 {
        let tid = (queue < 16).then_some(queue as u8);
        // TID0 has advanced from its authenticated floor 36 to 37 before
        // non-QoS arrives. Management floor 900 must not govern data.
        let floor = match queue {
            0 => 36,
            16 => 37,
            _ => 20 + queue,
        };
        let f = frame(Some(next), Some(floor), tid, 1, false, Mac([0xff; 6]), 1);
        let (old, _) = owned(&c, vec![f], Shape::WholeMpdu);
        assert!(matches!(
            s.receive_ordered_group(&old, Some(&mut slot)),
            Err(GroupError::Security(security::Error::Replay))
        ));
        let f = frame(
            Some(next),
            Some(floor + 1),
            tid,
            2,
            false,
            Mac([0xff; 6]),
            1,
        );
        let (new, _) = owned(&c, vec![f], Shape::WholeMpdu);
        s.receive_ordered_group(&new, Some(&mut slot)).unwrap();
    }
}

#[test]
fn sequence_wrap_does_not_reset_parent_pn_and_retiring_key_revokes_the_group() {
    let (s, c) = current(true);
    let (mut slot, k) = install(KeyScope::Pairwise(AP), &[7; 16]);
    for (seq, pn) in [(4095, 5), (0, 6)] {
        let (g, _) = owned(&c, split(Some(k), pn, 4, seq), Shape::HardwareSplitAmsdu);
        s.receive_ordered_group(&g, Some(&mut slot)).unwrap();
    }
    let (old, live) = owned(&c, split(Some(k), 6, 4, 1), Shape::HardwareSplitAmsdu);
    assert!(matches!(
        s.receive_ordered_group(&old, Some(&mut slot)),
        Err(GroupError::Security(security::Error::Replay))
    ));
    slot.invalidate();
    assert!(s.receive_ordered_group(&old, Some(&mut slot)).is_err());
    assert!(live.get());
}
