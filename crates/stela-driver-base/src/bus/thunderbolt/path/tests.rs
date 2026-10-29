extern crate std;
use super::*;

use crate::bus::thunderbolt::config::PacketType;
use crate::bus::thunderbolt::ring::{self, TX_DESCRIPTOR, model::*};
use alloc::vec::Vec;

#[test]
fn path_link_two_directions_credit_modes_stale_drain_and_kept_lifetime() {
    use super::super::path::{Activate, Direction, LaneCredits};
    for direction in [Direction::Downstream, Direction::Upstream] {
        for credits in [LaneCredits::LegacyBonded, LaneCredits::RouterAllocated(23)] {
            for stale in [false, true] {
                let PathFixture {
                    domain,
                    model,
                    channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                } = path_fixture(direction, credits);
                let mut peer = PathPeer::new(&linked, reservation.allocation, stale, 5);
                let protocol = peer.raw[0];
                // SAFETY: real model protected IDs/credits/permission and exact physical link.
                let mut activate =
                    unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
                let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
                assert_eq!(peer.writes.len(), if stale { 4 } else { 2 });
                assert_eq!(
                    active.words[0].raw[0] & (127 << 17),
                    protocol[0] & (127 << 17)
                );
                assert_eq!(
                    active.words[0].raw[1] & ((1 << 24) | (1 << 26)),
                    protocol[1] & ((1 << 24) | (1 << 26))
                );
                assert_eq!(
                    (active.words[1].raw[0] >> 17) & 127,
                    match credits {
                        LaneCredits::LegacyBonded => 32,
                        LaneCredits::RouterAllocated(n) => u32::from(n),
                    }
                );
                assert!(
                    dropped
                        .iter()
                        .all(|counter| counter.load(Ordering::Relaxed) == 0)
                );
                let mut channel = activate.into_channel();
                // SAFETY: model complete path and all owners transfer into independently kept CM through final drain.
                unsafe { active.retire() };
                assert!(
                    dropped
                        .iter()
                        .all(|counter| counter.load(Ordering::Relaxed) == 1)
                );
                channel_release(&mut channel);
            }
        }
    }
}

#[test]
fn path_invalid_grants_hop_bounds_and_mapping_refuse_before_publication() {
    use super::super::path::{Activate, Direction, LaneCredits};
    for case in 0..13 {
        let PathFixture {
            model,
            channel,
            mut linked,
            reservation,
            cursor,
            dropped,
            ..
        } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
        let mut allocation = reservation.allocation;
        match case {
            0 => allocation.identity.epoch += 1,
            1 => allocation.topology_epoch += 1,
            2 => allocation.grant_epoch = 0,
            3 => allocation.permission = super::super::router::Decision::Unresolved,
            4 => allocation.permission = super::super::router::Decision::Denied,
            5 => allocation.usb3_down = linked.partners.parent[0],
            6 => allocation.usb3_up = linked.partners.child[0],
            7 => allocation.hops[0].0 = 9,
            8 => allocation.hops[0].1 = 128,
            9 => allocation.hops[1].0 = 30,
            10 => allocation.lane_credits = LaneCredits::RouterAllocated(128),
            11 => linked.link_usb4 = false,
            12 => linked.partners.topology_epoch += 1,
            _ => unreachable!(),
        }
        let replacement = Arc::new(PathReservation {
            allocation,
            dropped: dropped[3].clone(),
        });
        drop(reservation);
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: same negative model pairing; invalid metadata must refuse without requests.
        assert!(unsafe { Activate::new(channel, linked, replacement, cursor.now) }.is_err());
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        assert!(
            dropped[..3]
                .iter()
                .all(|counter| counter.load(Ordering::Relaxed) == 0)
        );
        assert_eq!(dropped[3].load(Ordering::Relaxed), 2);
    }
}

#[test]
fn path_each_disable_or_activation_write_failure_keeps_link_and_all_ids() {
    use super::super::path::{Activate, Direction, Error, LaneCredits};
    for target in 1..=4 {
        for failure in 0..3 {
            let PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = path_fixture(Direction::Upstream, LaneCredits::RouterAllocated(19));
            let mut peer = PathPeer::new(&linked, reservation.allocation, true, 1);
            if failure == 2 {
                peer.reject = Some(target);
            }
            // SAFETY: exact protected model link, permission and resource reservation.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
            activate.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..100 {
                let producer = model.read32(TX_DESCRIPTOR + 8) >> 16;
                if producer as usize == cursor.tx % 10 {
                    cursor.now += 1;
                    assert!(activate.poll(cursor.now).unwrap().is_none());
                    continue;
                }
                let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                if peer.writes.len() == target && failure == 0 {
                    assert!(matches!(
                        activate.poll(cursor.now + 501),
                        Err(Error::Timeout)
                    ));
                    cursor.now += 501;
                    failed = true;
                    break;
                }
                if peer.writes.len() == target && failure == 1 {
                    let bytes =
                        domain.data(model.frame_address(ring::Direction::Tx, cursor.tx % 10), 16);
                    reply = incoming(
                        PacketType::Error,
                        &[
                            u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                            2,
                        ],
                    );
                }
                model.finish(ring::Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                match activate.poll(cursor.now) {
                    Err(Error::Changed | Error::Readback | Error::Controller { .. }) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("unexpected path failure result"),
                }
            }
            assert!(failed, "target={target} failure={failure}");
            assert_eq!(peer.writes.len(), target);
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(
                activate.poll(cursor.now + 1),
                Err(Error::Poisoned)
            ));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            let mut channel = activate.into_channel();
            assert!(
                dropped
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 0)
            );
            channel_release(&mut channel);
        }
    }
}

#[test]
fn path_header_credit_refusal_and_stale_pending_deadline_cannot_claim_restoration() {
    use super::super::path::{Activate, Direction, Error, LaneCredits};
    for case in 0..3 {
        let PathFixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
        let mut peer = PathPeer::new(&linked, reservation.allocation, true, 4);
        peer.changed_header = case == 0;
        peer.credit = if case == 1 {
            (32 << 20) | 8
        } else {
            peer.credit
        };
        peer.hold_pending = case == 2;
        // SAFETY: exact owned synthetic path with negative device effects.
        let mut activate =
            unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        let mut failed = false;
        let mut disabled_ack = None;
        for _ in 0..600 {
            match path_step(&mut peer, &domain, &model, &mut activate, &mut cursor) {
                Err(Error::Changed | Error::Credits | Error::Timeout) => {
                    failed = true;
                    break;
                }
                Ok(None) => {
                    if !peer.writes.is_empty() {
                        disabled_ack.get_or_insert(cursor.now);
                    }
                }
                _ => panic!("unexpected pending/refusal outcome"),
            }
        }
        assert!(failed);
        if case == 2 {
            assert_eq!(
                cursor.now,
                disabled_ack.expect("actual disable ACK") + 500,
                "repeated pending reads must not extend the ACK-anchored drain window"
            );
        }
        assert_eq!(peer.writes.len(), usize::from(case == 2));
        let mut channel = activate.into_channel();
        assert!(
            dropped[..3]
                .iter()
                .all(|counter| counter.load(Ordering::Relaxed) == 0)
        );
        assert_eq!(dropped[3].load(Ordering::Relaxed), usize::from(case != 2));
        channel_release(&mut channel);
    }
}

#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_PATH_ORACLE"]
fn unchanged_linux_path_usb3_complete_write_trace_matches_dma() {
    use super::super::path::{Activate, Direction, LaneCredits};
    let text = std::fs::read_to_string(
        std::env::var("STELA_THUNDERBOLT_PATH_ORACLE").expect("set oracle trace path"),
    )
    .unwrap();
    let mut cases = 0;
    for line in text.lines() {
        let values: Vec<u32> = line
            .split_ascii_whitespace()
            .skip(1)
            .map(|s| s.parse().unwrap())
            .collect();
        let [direction, mode, stale, seed] = values[..4] else {
            panic!("oracle case header")
        };
        let direction = if direction == 0 {
            Direction::Downstream
        } else {
            Direction::Upstream
        };
        let credits = if mode == 0 {
            LaneCredits::LegacyBonded
        } else {
            LaneCredits::RouterAllocated((17 + seed % 31) as u8)
        };
        let PathFixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        } = path_fixture(direction, credits);
        let mut peer = PathPeer::new(&linked, reservation.allocation, stale != 0, seed);
        peer.raw = [[values[4], values[5]], [values[6], values[7]]];
        let count = values[8] as usize;
        let expected: Vec<_> = values[9..9 + count * 5]
            .as_chunks::<5>()
            .0
            .iter()
            .map(|v| (v[0] as usize, v[1] as u8, v[2] as u16, [v[3], v[4]]))
            .collect();
        let final_words = &values[9 + count * 5..];
        assert_eq!(final_words.len(), 4);
        // SAFETY: same fixture link and independently protected model allocations/grants.
        let mut activate =
            unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
        let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
        assert_eq!(peer.writes, expected, "case={cases}");
        assert_eq!(active.words[0].raw, final_words[..2], "case={cases}");
        assert_eq!(active.words[1].raw, final_words[2..], "case={cases}");
        let mut channel = activate.into_channel();
        // SAFETY: all native synthetic owners transfer across model final drain.
        unsafe { active.retire() };
        assert!(
            dropped
                .iter()
                .all(|counter| counter.load(Ordering::Relaxed) == 1)
        );
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 512);
}

#[test]
fn path_publication_stall_clock_revocation_and_unconsumed_success_are_contained() {
    use super::super::{
        config::{Address, Route, Space},
        path::{Activate, Direction, Error, LaneCredits},
    };
    for mode in 0..5 {
        let PathFixture {
            domain,
            model,
            mut channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
        let mut peer = PathPeer::new(&linked, reservation.allocation, false, 2);
        if mode == 0 {
            for _ in 0..9 {
                channel
                    .read(
                        Route::new(0).unwrap(),
                        Address {
                            port: 1,
                            space: Space::Port,
                            offset: 4,
                            words: 1,
                        },
                        cursor.now,
                        cursor.now + 1000,
                    )
                    .unwrap();
                let reply = adapter_response(&domain, &model, cursor.tx % 10, 4, &[0]);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                assert!(matches!(
                    channel.poll(cursor.now),
                    Ok(Some(super::super::channel::Event::Completed { .. }))
                ));
            }
        }
        // SAFETY: protected real synthetic link and idle channel; mode0 leaves physical TX DMA unconsumed.
        let mut activate =
            unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
        if mode == 0 {
            let writes = model.state.lock().unwrap().writes.len();
            for delta in [0, 1, 499] {
                assert!(activate.poll(cursor.now + delta).unwrap().is_none());
            }
            assert!(matches!(
                activate.poll(cursor.now + 500),
                Err(Error::Timeout)
            ));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        } else if mode == 1 {
            assert!(matches!(
                activate.poll(cursor.now - 1),
                Err(Error::ClockRegressed)
            ));
        } else if mode == 4 {
            let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
            drop(active);
        } else {
            activate.poll(cursor.now).unwrap();
            for _ in 0..20 {
                assert!(
                    path_step(&mut peer, &domain, &model, &mut activate, &mut cursor)
                        .unwrap()
                        .is_none()
                );
                if !peer.writes.is_empty() {
                    break;
                }
            }
            assert_eq!(peer.writes.len(), 1);
            if mode == 2 {
                assert!(matches!(activate.cancel(), Err(Error::Cancelled)));
            } else {
                let event = incoming(PacketType::Event, &[0, 0, 1]);
                finish_rx(&model, cursor.rx % 10, &event);
                cursor.rx += 1;
                cursor.now += 1;
                assert!(matches!(activate.poll(cursor.now), Err(Error::Hotplug(_))));
            }
        }
        let mut channel = activate.into_channel();
        assert!(
            dropped[..3]
                .iter()
                .all(|counter| counter.load(Ordering::Relaxed) == 0)
        );
        assert_eq!(dropped[3].load(Ordering::Relaxed), usize::from(mode < 2));
        channel_release(&mut channel);
    }
}
