extern crate std;
use super::*;

use crate::bus::thunderbolt::config::PacketType;
use crate::bus::thunderbolt::ring::{Direction, TX_DESCRIPTOR, model::*};
use alloc::vec::Vec;

#[test]
fn bandwidth_hca_consumed_floor_scale_and_original_link_move_into_path() {
    use super::super::{
        path::Activate,
        usb3::{Allocate, Rates},
    };
    let (
        PathFixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        },
        accounting,
        accounting_drop,
    ) = bandwidth_fixture(Rates {
        upstream: 1,
        downstream: 18000,
    });
    let mut peer = BandwidthPeer::new(&linked, accounting.grant, 13);
    let mut path_peer = PathPeer::new(&linked, reservation.allocation, false, 3);
    // SAFETY: synthetic accounting/permission/link/controller.
    let mut allocate = unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
    let allocated = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
    assert!(allocated.allocated.upstream > 1);
    assert_eq!(allocated.allocated.downstream, 18000);
    assert_eq!(peer.writes.len(), 4);
    assert_eq!(peer.control >> 31, 0);
    assert_eq!(peer.consumed >> 31, 0);
    let channel = allocate.into_channel();
    // SAFETY: consume same protected grant/endpoint/link epoch; no copied ownership.
    let mut activate =
        unsafe { Activate::with_bandwidth(channel, allocated, reservation, cursor.now) }.unwrap();
    let active = drive_path(&mut path_peer, &domain, &model, &mut activate, &mut cursor);
    let mut channel = activate.into_channel();
    assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
    assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
    // SAFETY: complete synthetic path/bandwidth/link native lifetime transfer.
    unsafe { active.retire() };
    assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 1));
    assert_eq!(accounting_drop.load(Ordering::Relaxed), 1);
    channel_release(&mut channel);
}

#[test]
fn bandwidth_each_cmr_scale_allocation_clear_write_failure_keeps_accounting() {
    use super::super::usb3::{Allocate, Error, Rates};
    for target in 1..=4 {
        for failure in 0..3 {
            let (
                PathFixture {
                    domain,
                    model,
                    channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                },
                accounting,
                accounting_drop,
            ) = bandwidth_fixture(Rates {
                upstream: 10000,
                downstream: 18000,
            });
            drop(reservation);
            let mut peer = BandwidthPeer::new(&linked, accounting.grant, 7);
            if failure == 2 {
                peer.reject = Some(target);
            }
            // SAFETY: protected real synthetic CM grant and exact physical pairing.
            let mut allocate =
                unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
            allocate.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..100 {
                if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                    cursor.now += 1;
                    assert!(allocate.poll(cursor.now).unwrap().is_none());
                    continue;
                }
                let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                if peer.writes.len() == target && failure == 0 {
                    assert!(matches!(
                        allocate.poll(cursor.now + 1501),
                        Err(Error::Timeout)
                    ));
                    cursor.now += 1501;
                    failed = true;
                    break;
                }
                if peer.writes.len() == target && failure == 1 {
                    let bytes = domain.data(model.frame_address(Direction::Tx, cursor.tx % 10), 16);
                    reply = incoming(
                        PacketType::Error,
                        &[
                            u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                            2,
                        ],
                    );
                }
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                match allocate.poll(cursor.now) {
                    Err(Error::Readback | Error::Controller { .. }) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("unexpected bandwidth write outcome"),
                }
            }
            assert!(failed, "write={target} failure={failure}");
            assert_eq!(peer.writes.len(), target);
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(
                allocate.poll(cursor.now + 1),
                Err(Error::Poisoned)
            ));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            let mut channel = allocate.into_channel();
            assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
            assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
    }
}

#[test]
fn bandwidth_both_hca_windows_start_at_ack_and_never_extend() {
    use super::super::usb3::{Allocate, Error, Rates};
    for clear in [false, true] {
        let (
            PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: 1000,
            downstream: 2000,
        });
        drop(reservation);
        let mut peer = BandwidthPeer::new(&linked, accounting.grant, 9);
        peer.hold[usize::from(clear)] = true;
        // SAFETY: real synthetic owner with stalled device HCA transition.
        let mut allocate =
            unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
        allocate.poll(cursor.now).unwrap();
        let mut ack = None;
        let mut failed = false;
        let target = if clear { 4 } else { 1 };
        for _ in 0..2000 {
            match bandwidth_step(&mut peer, &domain, &model, &mut allocate, &mut cursor) {
                Err(Error::Timeout) => {
                    failed = true;
                    break;
                }
                Ok(None) => {
                    if peer.writes.len() == target {
                        ack.get_or_insert(cursor.now);
                    }
                }
                _ => panic!("HCA stall claimed success"),
            }
        }
        assert!(failed);
        assert_eq!(cursor.now, ack.expect("actual source write ACK") + 1500);
        assert_eq!(peer.writes.len(), target);
        let mut channel = allocate.into_channel();
        assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
        assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}

#[test]
fn bandwidth_invalid_native_grants_and_storage_refuse_before_publication() {
    use super::super::usb3::{Allocate, Rates};
    for case in 0..11 {
        let (
            PathFixture {
                model,
                channel,
                mut linked,
                reservation,
                cursor,
                dropped,
                ..
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: 1000,
            downstream: 2000,
        });
        drop(reservation);
        let mut grant = accounting.grant;
        match case {
            0 => grant.identity.epoch += 1,
            1 => grant.topology_epoch += 1,
            2 => grant.grant_epoch = 0,
            3 => grant.permission = super::super::router::Decision::Denied,
            4 => grant.permission = super::super::router::Decision::Unresolved,
            5 => grant.usb3_down = linked.partners.parent[0],
            6 => grant.usb3_up = linked.partners.child[0],
            7 => grant.requested.upstream = u32::MAX,
            8 => linked.link_usb4 = false,
            9 | 10 => {}
            _ => unreachable!(),
        };
        let replacement = Arc::new(BandwidthReservation {
            current: accounting.current.clone(),
            grant,
            dropped: accounting_drop.clone(),
        });
        drop(accounting);
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: exact negative synthetic pairing; invalid metadata/storage must refuse.
        let result = unsafe {
            if case == 9 {
                Allocate::new_without_storage(channel, linked, replacement, cursor.now)
            } else {
                Allocate::new(
                    channel,
                    linked,
                    replacement,
                    if case == 10 { u64::MAX } else { cursor.now },
                )
            }
        };
        assert!(result.is_err());
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
        assert_eq!(accounting_drop.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn bandwidth_busy_controller_encoding_and_unconsumed_receipts_keep_original_owners() {
    use super::super::usb3::{Allocate, Error, Rates};
    for case in 0..5 {
        let (
            PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: 1000,
            downstream: 2000,
        });
        drop(reservation);
        let mut peer = BandwidthPeer::new(&linked, accounting.grant, 9);
        match case {
            0 => peer.control |= 1 << 31,
            1 => peer.consumed |= 1 << 31,
            2 => peer.header[2] ^= 1,
            3 => peer.scale = 63,
            4 => {}
            _ => unreachable!(),
        };
        // SAFETY: synthetic physical controller/accounting grant.
        let mut allocate =
            unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
        if case == 4 {
            let allocated = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
            drop(allocated);
        } else {
            allocate.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..50 {
                match bandwidth_step(&mut peer, &domain, &model, &mut allocate, &mut cursor) {
                    Err(Error::Busy | Error::Changed | Error::Encoding) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("invalid controller state admitted"),
                }
            }
            assert!(failed);
            assert_eq!(peer.writes.len(), usize::from(case == 3));
        }
        let mut channel = allocate.into_channel();
        assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
        assert_eq!(
            accounting_drop.load(Ordering::Relaxed),
            usize::from(case < 3)
        );
        channel_release(&mut channel);
    }
}

#[test]
fn bandwidth_path_composition_wrong_permission_epoch_never_copies_permission() {
    use super::super::{
        path::Activate,
        usb3::{Allocate, Rates},
    };
    let (
        PathFixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        },
        accounting,
        accounting_drop,
    ) = bandwidth_fixture(Rates {
        upstream: 1000,
        downstream: 2000,
    });
    let mut peer = BandwidthPeer::new(&linked, accounting.grant, 0);
    // SAFETY: matching protected synthetic link and native grant.
    let mut allocate = unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
    let allocated = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
    let channel = allocate.into_channel();
    let mut allocation = reservation.allocation;
    allocation.grant_epoch += 1;
    let replacement = Arc::new(PathReservation {
        allocation,
        dropped: dropped[3].clone(),
    });
    drop(reservation);
    let writes = model.state.lock().unwrap().writes.len();
    assert!(
        // SAFETY: metadata mismatch is a negative model pairing; no request permitted.
        unsafe { Activate::with_bandwidth(channel, allocated, replacement, cursor.now) }.is_err()
    );
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
    assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
}

#[test]
#[ignore = "oracle: STELA_USB3_BANDWIDTH_ORACLE"]
fn unchanged_linux_usb3_bandwidth_complete_writes_and_rates_match_dma() {
    use super::super::usb3::{Allocate, Rates};
    let text = std::fs::read_to_string(
        std::env::var("STELA_USB3_BANDWIDTH_ORACLE").expect("set oracle trace path"),
    )
    .unwrap();
    let mut cases = 0;
    for line in text.lines() {
        let v: Vec<u32> = line
            .split_ascii_whitespace()
            .skip(1)
            .map(|s| s.parse().unwrap())
            .collect();
        let count = v[8] as usize;
        let (
            PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: v[1],
            downstream: v[2],
        });
        drop(reservation);
        let mut peer = BandwidthPeer::new(&linked, accounting.grant, v[0]);
        peer.consumed = v[3];
        peer.control = v[4];
        peer.scale = v[5];
        // SAFETY: exact protected synthetic accounting/permission/link fixture.
        let mut allocate =
            unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
        let allocated = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
        let expected: Vec<_> = v[9..9 + 2 * count]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| (v[0] as u16, v[1]))
            .collect();
        assert_eq!(peer.writes, expected, "case={cases}");
        assert_eq!(
            allocated.allocated,
            Rates {
                upstream: v[6],
                downstream: v[7]
            },
            "case={cases}"
        );
        assert_eq!(
            [peer.consumed, peer.control, peer.scale],
            v[9 + 2 * count..],
            "case={cases}"
        );
        let mut channel = allocate.into_channel();
        // SAFETY: native allocation and all original owners transfer through synthetic final drain.
        unsafe { allocated.retire() };
        assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 1));
        assert_eq!(accounting_drop.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 512);
}

#[test]
fn bandwidth_full_tx_clock_cancel_and_hotplug_never_release_native_owners() {
    use super::super::{
        config::{Address, Route, Space},
        usb3::{Allocate, Error, Rates},
    };
    for case in 0..4 {
        let (
            PathFixture {
                domain,
                model,
                mut channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: 1000,
            downstream: 2000,
        });
        drop(reservation);
        let mut peer = BandwidthPeer::new(&linked, accounting.grant, 9);
        if case == 0 {
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
        // SAFETY: exact physical model owners, idle software channel; case0 leaves real TX descriptors unconsumed.
        let mut allocate =
            unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
        if case == 0 {
            let writes = model.state.lock().unwrap().writes.len();
            for delta in [0, 1, 499] {
                assert!(allocate.poll(cursor.now + delta).unwrap().is_none());
            }
            assert!(matches!(
                allocate.poll(cursor.now + 500),
                Err(Error::Timeout)
            ));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        } else if case == 1 {
            assert!(matches!(
                allocate.poll(cursor.now - 1),
                Err(Error::ClockRegressed)
            ));
        } else {
            allocate.poll(cursor.now).unwrap();
            for _ in 0..20 {
                assert!(
                    bandwidth_step(&mut peer, &domain, &model, &mut allocate, &mut cursor)
                        .unwrap()
                        .is_none()
                );
                if !peer.writes.is_empty() {
                    break;
                }
            }
            assert_eq!(peer.writes.len(), 1);
            if case == 2 {
                assert!(matches!(allocate.cancel(), Err(Error::Cancelled)));
            } else {
                finish_rx(
                    &model,
                    cursor.rx % 10,
                    &incoming(PacketType::Event, &[0, 0, 1]),
                );
                cursor.rx += 1;
                cursor.now += 1;
                assert!(matches!(allocate.poll(cursor.now), Err(Error::Hotplug(_))));
            }
        }
        let mut channel = allocate.into_channel();
        assert!(dropped[..3].iter().all(|n| n.load(Ordering::Relaxed) == 0));
        assert_eq!(
            accounting_drop.load(Ordering::Relaxed),
            usize::from(case < 2)
        );
        channel_release(&mut channel);
    }
}

#[test]
fn tunnel_both_real_paths_then_endpoints_use_one_bandwidth_link_and_kept_owners() {
    use super::super::{path::LaneCredits, usb3::ActivateTunnel};
    for credits in [LaneCredits::LegacyBonded, LaneCredits::RouterAllocated(23)] {
        for stale in [false, true] {
            for seed in [2, 3] {
                let fixture = tunnel_fixture(credits, seed);
                let mut peer = TunnelPeer::new(&fixture, stale, seed);
                let TunnelFixture {
                    domain,
                    model,
                    channel,
                    bandwidth,
                    down,
                    up,
                    mut cursor,
                    dropped,
                    ..
                } = fixture;
                // SAFETY: synthetic CM also keeps real exclusive endpoint CS0 permission, both path grants and one bandwidth/link.
                let mut engine =
                    unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }
                        .unwrap();
                let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
                assert_eq!(peer.writes.len(), if stale { 10 } else { 6 });
                let n = peer.writes.len();
                assert_eq!(
                    (
                        peer.writes[n - 2].route,
                        peer.writes[n - 2].port,
                        peer.writes[n - 2].offset
                    ),
                    (0, 6, 0x50)
                );
                assert_eq!(
                    (
                        peer.writes[n - 1].route,
                        peer.writes[n - 1].port,
                        peer.writes[n - 1].offset
                    ),
                    (2, 4, 0x50)
                );
                assert!(active.endpoints.iter().all(|v| v & (1 << 31) != 0));
                assert_eq!(active.endpoints, peer.endpoints);
                assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
                let mut channel = engine.into_channel();
                // SAFETY: whole live native synthetic tunnel and all six owners transfer through final drain.
                unsafe { active.retire() };
                assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
                channel_release(&mut channel);
            }
        }
    }
}

#[test]
fn tunnel_all_ten_possible_writes_keep_both_paths_accounting_and_link_on_failure() {
    use super::super::{
        path::LaneCredits,
        usb3::{ActivateTunnel, Error},
    };
    for target in 1..=10 {
        for failure in 0..3 {
            let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
            let mut peer = TunnelPeer::new(&fixture, true, 2);
            if failure == 2 {
                peer.reject = Some(target);
            }
            let TunnelFixture {
                domain,
                model,
                channel,
                bandwidth,
                down,
                up,
                mut cursor,
                dropped,
                ..
            } = fixture;
            // SAFETY: exact protected synthetic endpoint permission and all owners.
            let mut engine =
                unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
            engine.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..200 {
                if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                    cursor.now += 1;
                    assert!(engine.poll(cursor.now).unwrap().is_none());
                    continue;
                }
                let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                if peer.writes.len() == target && failure == 0 {
                    cursor.now += 10001;
                    assert!(engine.poll(cursor.now).is_err());
                    failed = true;
                    break;
                }
                if peer.writes.len() == target && failure == 1 {
                    let bytes = domain.data(model.frame_address(Direction::Tx, cursor.tx % 10), 16);
                    reply = incoming(
                        PacketType::Error,
                        &[
                            u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                            2,
                        ],
                    );
                }
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                match engine.poll(cursor.now) {
                    Err(_) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("partial USB3 tunnel claimed success"),
                }
            }
            assert!(failed, "write={target} failure={failure}");
            assert_eq!(peer.writes.len(), target);
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(engine.poll(cursor.now + 1), Err(Error::Poisoned)));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            let mut channel = engine.into_channel();
            assert!(
                dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0),
                "all native owners retained write={target} failure={failure}"
            );
            channel_release(&mut channel);
        }
    }
}

#[test]
fn tunnel_constructor_mismatch_and_both_storage_failures_keep_every_live_owner() {
    assert_ne!(
        core::mem::size_of::<super::super::path::Active>(),
        core::mem::size_of::<super::super::usb3::ActiveTunnel>(),
        "local size-selective null allocator must reach the second reservation"
    );
    use super::super::{
        path::{Direction, LaneCredits},
        usb3::ActivateTunnel,
    };
    for case in 0..10 {
        let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
        let TunnelFixture {
            model,
            channel,
            bandwidth,
            down,
            up,
            cursor,
            dropped,
            ..
        } = fixture;
        let mut allocation = up.allocation;
        match case {
            0 => allocation.identity.epoch += 1,
            1 => allocation.topology_epoch += 1,
            2 => allocation.grant_epoch += 1,
            3 => allocation.usb3_up = 1,
            4 => allocation.direction = Direction::Downstream,
            5 => allocation.hops[0].0 = 9,
            6 => allocation.permission = super::super::router::Decision::Denied,
            7..=9 => {}
            _ => unreachable!(),
        };
        let replacement = Arc::new(PathReservation {
            allocation,
            dropped: dropped[5].clone(),
        });
        drop(up);
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: same negative synthetic native transaction. All protected wrappers must remain held on failed construction.
        let result = unsafe {
            if case >= 8 {
                ActivateTunnel::new_without_storage(
                    channel,
                    bandwidth,
                    down,
                    replacement,
                    cursor.now,
                    case == 9,
                )
            } else {
                ActivateTunnel::new(
                    channel,
                    bandwidth,
                    down,
                    replacement,
                    if case == 7 { u64::MAX } else { cursor.now },
                )
            }
        };
        assert!(result.is_err());
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        assert!(dropped[..5].iter().all(|v| v.load(Ordering::Relaxed) == 0));
        assert_eq!(
            dropped[5].load(Ordering::Relaxed),
            1,
            "only old replaced model lease may drop"
        );
    }
}

#[test]
fn tunnel_busy_endpoints_second_path_preflight_and_unconsumed_completion_keep_chain() {
    use super::super::{
        path::LaneCredits,
        usb3::{ActivateTunnel, Error},
    };
    for case in 0..4 {
        let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
        let mut peer = TunnelPeer::new(&fixture, true, 2);
        if case < 2 {
            peer.endpoints[case] = 1 << 31;
        }
        peer.fail_second_header = case == 2;
        let TunnelFixture {
            domain,
            model,
            channel,
            bandwidth,
            down,
            up,
            mut cursor,
            dropped,
            ..
        } = fixture;
        // SAFETY: same native controller and endpoint permission; negative wire states are explicit.
        let mut engine =
            unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
        if case == 3 {
            let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
            drop(active);
        } else {
            engine.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..200 {
                match tunnel_step(&mut peer, &domain, &model, &mut engine, &mut cursor) {
                    Err(Error::Busy | Error::Path(_)) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("invalid endpoint/second path was admitted"),
                }
            }
            assert!(failed);
            assert_eq!(peer.writes.len(), if case == 2 { 4 } else { 0 });
        }
        let mut channel = engine.into_channel();
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
fn tunnel_clock_cancel_hotplug_and_full_endpoint_tx_never_release_active_resources() {
    use super::super::{
        config::{Address, Route, Space},
        path::LaneCredits,
        usb3::{ActivateTunnel, Error},
    };
    for case in 0..4 {
        let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
        let mut peer = TunnelPeer::new(&fixture, true, 2);
        let TunnelFixture {
            domain,
            model,
            mut channel,
            bandwidth,
            down,
            up,
            mut cursor,
            dropped,
            ..
        } = fixture;
        if case == 3 {
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
        // SAFETY: exact endpoint/native accounting/path permission; case3 has physically unconsumed TX slots.
        let mut engine =
            unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
        if case == 0 {
            assert!(matches!(
                engine.poll(cursor.now - 1),
                Err(Error::ClockRegressed)
            ));
        } else if case == 3 {
            let writes = model.state.lock().unwrap().writes.len();
            for delta in [0, 1, 499] {
                assert!(engine.poll(cursor.now + delta).unwrap().is_none());
            }
            assert!(matches!(engine.poll(cursor.now + 500), Err(Error::Timeout)));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        } else {
            engine.poll(cursor.now).unwrap();
            for _ in 0..200 {
                assert!(
                    tunnel_step(&mut peer, &domain, &model, &mut engine, &mut cursor)
                        .unwrap()
                        .is_none()
                );
                if peer.writes.len() == 8 {
                    break;
                }
            }
            assert_eq!(peer.writes.len(), 8);
            if case == 1 {
                assert!(matches!(engine.cancel(), Err(Error::Cancelled)));
            } else {
                finish_rx(
                    &model,
                    cursor.rx % 10,
                    &incoming(PacketType::Event, &[0, 0, 1]),
                );
                cursor.rx += 1;
                cursor.now += 1;
                assert!(matches!(
                    engine.poll(cursor.now),
                    Err(Error::Path(_) | Error::Hotplug(_))
                ));
            }
        }
        let mut channel = engine.into_channel();
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
#[ignore = "oracle: STELA_USB3_TUNNEL_ORACLE"]
fn unchanged_linux_usb3_tunnel_full_bandwidth_paths_and_endpoint_writes_match_dma() {
    use super::super::{path::LaneCredits, usb3::ActivateTunnel};
    let text = std::fs::read_to_string(
        std::env::var("STELA_USB3_TUNNEL_ORACLE").expect("set source trace path"),
    )
    .unwrap();
    let mut cases = 0;
    for line in text.lines() {
        let v: Vec<u32> = line
            .split_ascii_whitespace()
            .skip(1)
            .map(|s| s.parse().unwrap())
            .collect();
        let [mode, stale, seed, count] = v[..4] else {
            panic!("source case header")
        };
        let credits = if mode == 0 {
            LaneCredits::LegacyBonded
        } else {
            LaneCredits::RouterAllocated((17 + seed % 15) as u8)
        };
        let fixture = tunnel_fixture(credits, seed);
        let mut peer = TunnelPeer::new(&fixture, stale != 0, seed);
        let rates = fixture.bandwidth.allocated;
        let TunnelFixture {
            domain,
            model,
            channel,
            bandwidth,
            down,
            up,
            mut cursor,
            dropped,
            band_writes,
            ..
        } = fixture;
        let mut actual: Vec<_> = band_writes
            .into_iter()
            .map(|(offset, value)| TunnelWrite {
                route: 0,
                port: 6,
                space: 1,
                offset,
                data: vec![value],
            })
            .collect();
        // SAFETY: real protected synthetic accounting, BOTH path grants, native endpoint control and unchanged epochs.
        let mut engine =
            unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
        let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
        actual.extend(peer.writes);
        let mut expected = Vec::new();
        let mut at = 4;
        for _ in 0..count {
            let length = v[at + 4] as usize;
            expected.push(TunnelWrite {
                route: u64::from(v[at]),
                port: v[at + 1] as u8,
                space: v[at + 2] as u8,
                offset: v[at + 3] as u16,
                data: v[at + 5..at + 5 + length].to_vec(),
            });
            at += 5 + length;
        }
        assert_eq!(actual, expected, "case={cases}");
        assert_eq!(active.endpoints, v[at..at + 2], "case={cases}");
        assert_eq!(
            [rates.upstream, rates.downstream],
            v[at + 2..],
            "case={cases}"
        );
        let mut channel = engine.into_channel();
        // SAFETY: complete live native model tunnel transfers through real synthetic final drain.
        unsafe { active.retire() };
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 1));
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 128);
}

#[test]
fn teardown_normal_does_not_release_bandwidth_and_returns_local_owners_only_explicitly() {
    use super::super::{path::LaneCredits, usb3::StopTunnel};
    for unconsumed in [false, true] {
        let StopFixture {
            domain,
            model,
            channel,
            active,
            mut peer,
            mut cursor,
            dropped,
            ..
        } = stop_fixture(LaneCredits::LegacyBonded, 2);
        let residual = active.bandwidth_rates();
        // SAFETY: real synthetic native epoch/permission, host admission closed and independent endpoint lifetimes kept.
        let mut stop = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
        let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
        assert_eq!(peer.writes.len(), 6);
        assert!(
            peer.writes[..2]
                .iter()
                .all(|w| w.space == 1 && w.offset == 0x50 && w.data == [1 << 30])
        );
        assert_eq!(stopped.bandwidth_rates(), residual);
        assert!(stopped.endpoints.iter().all(|w| w & (1 << 31) == 0));
        assert!(
            stopped
                .hops
                .iter()
                .all(|w| w.raw[0] & (1 << 31) == 0 && w.raw[1] & (1 << 28) == 0)
        );
        let mut channel = stop.into_channel();
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        if unconsumed {
            drop(stopped);
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        } else {
            let reusable = match stopped.into_reusable() {
                Ok(value) => value,
                Err(_) => panic!("live native guard refused"),
            };
            drop(reusable.paths);
            assert_eq!(dropped[4].load(Ordering::Relaxed), 1);
            assert_eq!(dropped[5].load(Ordering::Relaxed), 1);
            assert!(dropped[..4].iter().all(|v| v.load(Ordering::Relaxed) == 0));
            // SAFETY: residual accounting/link have independent native provider retirement/transfer, beyond local path proof.
            unsafe { reusable.residual.retire() };
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
        }
        channel_release(&mut channel);
    }
}

#[test]
fn teardown_separate_release_unused_keeps_900_floor_and_active_owner_chain() {
    use super::super::{
        path::LaneCredits,
        usb3::{ReleaseUnused, StopTunnel},
    };
    let StopFixture {
        domain,
        model,
        channel,
        active,
        mut peer,
        mut cursor,
        dropped,
        mut bandwidth_peer,
        ..
    } = stop_fixture(LaneCredits::RouterAllocated(23), 0);
    // SAFETY: protected native branch accounting explicitly reserves source consumed/900 floor; active paths stay held.
    let mut release = unsafe { ReleaseUnused::new(channel, active, cursor.now) }.unwrap();
    let active = drive_release(
        &mut bandwidth_peer,
        &domain,
        &model,
        &mut release,
        &mut cursor,
    );
    assert!(active.bandwidth_rates().upstream >= 900);
    assert!(active.bandwidth_rates().downstream >= 900);
    assert_eq!(bandwidth_peer.writes.len(), 4);
    assert!(peer.endpoints.iter().all(|w| w & (1 << 31) != 0));
    let channel = release.into_channel();
    // SAFETY: same native epoch and submission/endpoint lifetime proof.
    let mut stop = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
    let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
    let mut channel = stop.into_channel();
    let reusable = match stopped.into_reusable() {
        Ok(v) => v,
        Err(_) => panic!("guard"),
    };
    assert!(reusable.residual.allocated.upstream >= 900);
    assert!(reusable.residual.allocated.downstream >= 900);
    drop(reusable.paths);
    // SAFETY: residual provider lifetime transfers independently.
    unsafe { reusable.residual.retire() };
    assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
    channel_release(&mut channel);
}

#[test]
fn teardown_each_endpoint_and_hop_disable_failure_keeps_all_six_native_owners() {
    use super::super::{
        path::LaneCredits,
        usb3::{Error, StopTunnel},
    };
    for target in 1..=6 {
        for failure in 0..3 {
            let StopFixture {
                domain,
                model,
                channel,
                active,
                mut peer,
                mut cursor,
                dropped,
                ..
            } = stop_fixture(LaneCredits::LegacyBonded, 2);
            if failure == 2 {
                peer.reject = Some(target);
            }
            // SAFETY: matching physical epoch/permission and independently closed native admission.
            let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
            engine.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..200 {
                if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                    cursor.now += 1;
                    assert!(engine.poll(cursor.now).unwrap().is_none());
                    continue;
                }
                let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                if peer.writes.len() == target && failure == 0 {
                    cursor.now += 501;
                    assert!(matches!(engine.poll(cursor.now), Err(Error::Timeout)));
                    failed = true;
                    break;
                }
                if peer.writes.len() == target && failure == 1 {
                    reply = controller_error(&domain, &model, &cursor);
                }
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                match engine.poll(cursor.now) {
                    Err(_) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("uncertain stop returned reusable owners"),
                }
            }
            assert!(failed, "write={target} failure={failure}");
            assert_eq!(peer.writes.len(), target);
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(engine.poll(cursor.now + 1), Err(Error::Poisoned)));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            let mut channel = engine.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}

#[test]
fn teardown_release_unused_each_uncertain_write_keeps_both_split_owner_halves() {
    use super::super::{
        path::LaneCredits,
        usb3::{Error, ReleaseUnused},
    };
    for target in 1..=4 {
        for failure in 0..3 {
            let StopFixture {
                domain,
                model,
                channel,
                active,
                mut cursor,
                dropped,
                mut bandwidth_peer,
                ..
            } = stop_fixture(LaneCredits::RouterAllocated(23), 2);
            if failure == 2 {
                bandwidth_peer.reject = Some(target);
            }
            // SAFETY: native accounting and active endpoint permission across this adjustment.
            let mut engine = unsafe { ReleaseUnused::new(channel, active, cursor.now) }.unwrap();
            engine.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..100 {
                if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                    cursor.now += 1;
                    assert!(engine.poll(cursor.now).unwrap().is_none());
                    continue;
                }
                let mut reply = bandwidth_peer.respond(&domain, &model, cursor.tx % 10);
                if bandwidth_peer.writes.len() == target && failure == 0 {
                    cursor.now += 1501;
                    assert!(matches!(engine.poll(cursor.now), Err(Error::Timeout)));
                    failed = true;
                    break;
                }
                if bandwidth_peer.writes.len() == target && failure == 1 {
                    reply = controller_error(&domain, &model, &cursor);
                }
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                match engine.poll(cursor.now) {
                    Err(_) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("uncertain release succeeded"),
                }
            }
            assert!(failed, "write={target} failure={failure}");
            assert_eq!(bandwidth_peer.writes.len(), target);
            assert!(matches!(engine.poll(cursor.now + 1), Err(Error::Poisoned)));
            let mut channel = engine.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}

#[test]
fn teardown_each_pending_drain_has_one_ack_anchored_deadline_including_already_disabled() {
    use super::super::{
        path::LaneCredits,
        usb3::{Error, StopTunnel},
    };
    for hop in 0..4 {
        for already_disabled in [false, true] {
            let StopFixture {
                domain,
                model,
                channel,
                active,
                mut peer,
                mut cursor,
                dropped,
                ..
            } = stop_fixture(LaneCredits::LegacyBonded, 2);
            let path = if hop < 2 {
                &mut peer.down
            } else {
                &mut peer.up
            };
            let lane = hop % 2;
            path.hold_hop[lane] = true;
            if already_disabled {
                path.raw[lane][0] &= !(1 << 31);
                path.disabled[lane] = true;
            }
            // SAFETY: exact unchanged physical owner chain; pending work is not assumed quiescent.
            let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
            engine.poll(cursor.now).unwrap();
            let prefix = if already_disabled { 2 + hop } else { 3 + hop };
            // Stop immediately after the disable ACK (or first disabled-state read).
            for _ in 0..200 {
                assert!(
                    stop_step(&mut peer, &domain, &model, &mut engine, &mut cursor)
                        .unwrap()
                        .is_none()
                );
                let p = if hop < 2 { &peer.down } else { &peer.up };
                if peer.writes.len() == prefix
                    && ((!already_disabled && p.disabled[lane] && p.reads[lane] == 0)
                        || (already_disabled && p.reads[lane] == 1))
                {
                    break;
                }
            }
            assert_eq!(peer.writes.len(), prefix);
            let anchor = cursor.now;
            for delta in [1, 49, 150, 499] {
                cursor.now = anchor + delta - 1;
                assert!(
                    stop_step(&mut peer, &domain, &model, &mut engine, &mut cursor)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(cursor.now, anchor + delta);
            }
            assert!(matches!(engine.poll(anchor + 500), Err(Error::Timeout)));
            assert_eq!(peer.writes.len(), prefix);
            let mut channel = engine.into_channel();
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}

#[test]
fn teardown_revocation_rejects_late_dma_and_owner_return_without_releasing_ids() {
    use super::super::{
        path::LaneCredits,
        usb3::{Error, StopTunnel},
    };
    for after_completion in [false, true] {
        let StopFixture {
            domain,
            model,
            channel,
            active,
            mut peer,
            mut cursor,
            current,
            dropped,
            ..
        } = stop_fixture(LaneCredits::LegacyBonded, 2);
        // SAFETY: exact admitted native epoch and closed host submissions, until revoked.
        let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
        if after_completion {
            let stopped = drive_stop(&mut peer, &domain, &model, &mut engine, &mut cursor);
            current.store(false, Ordering::Release);
            let (error, same) = match stopped.into_reusable() {
                Err(v) => v,
                Ok(_) => panic!("revoked owner return"),
            };
            assert!(matches!(error, Error::Revoked));
            drop(same);
        } else {
            engine.poll(cursor.now).unwrap();
            // Request published while current; real DMA reply arrives only after native revocation.
            let reply = peer.respond(&domain, &model, cursor.tx % 10);
            current.store(false, Ordering::Release);
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(&model, cursor.rx % 10, &reply);
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(engine.poll(cursor.now + 1), Err(Error::Revoked)));
            current.store(true, Ordering::Release);
            assert!(matches!(engine.poll(cursor.now + 2), Err(Error::Poisoned)));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        }
        let mut channel = engine.into_channel();
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
fn teardown_cancel_clock_null_storage_hotplug_and_revoked_constructor_keep_chain() {
    use super::super::{
        path::LaneCredits,
        usb3::{Error, StopTunnel},
    };
    for case in 0..6 {
        let StopFixture {
            domain,
            model,
            channel,
            active,
            mut peer,
            mut cursor,
            current,
            dropped,
            ..
        } = stop_fixture(LaneCredits::LegacyBonded, 2);
        let writes = model.state.lock().unwrap().writes.len();
        if case == 0 {
            current.store(false, Ordering::Release);
        }
        // SAFETY: paired native resources. Refusal cases must not publish or release anything.
        let result = unsafe {
            if case == 1 {
                StopTunnel::new_without_storage(channel, active, cursor.now)
            } else {
                StopTunnel::new(
                    channel,
                    active,
                    if case == 2 { u64::MAX } else { cursor.now },
                )
            }
        };
        if case < 3 {
            assert!(matches!(
                result,
                Err(Error::Revoked | Error::Allocation | Error::ClockOverflow)
            ));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
            continue;
        }
        let mut engine = result.unwrap();
        if case == 3 {
            assert!(matches!(
                engine.poll(cursor.now - 1),
                Err(Error::ClockRegressed)
            ));
        } else {
            engine.poll(cursor.now).unwrap();
            for _ in 0..200 {
                assert!(
                    stop_step(&mut peer, &domain, &model, &mut engine, &mut cursor)
                        .unwrap()
                        .is_none()
                );
                if peer.writes.len() == 2 {
                    break;
                }
            }
            if case == 4 {
                assert!(matches!(engine.cancel(), Err(Error::Cancelled)));
            } else {
                finish_rx(
                    &model,
                    cursor.rx % 10,
                    &incoming(PacketType::Event, &[0, 0, 1]),
                );
                cursor.now += 1;
                assert!(matches!(engine.poll(cursor.now), Err(Error::Hotplug(_))));
            }
        }
        let mut channel = engine.into_channel();
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
fn teardown_guard_blocks_old_admissions_and_late_replies() {
    use super::super::{
        path::LaneCredits,
        usb3::{ActivateTunnel, Allocate, Error, Rates, ReleaseUnused},
    };
    for late in [false, true] {
        let (
            PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            },
            accounting,
            accounting_drop,
        ) = bandwidth_fixture(Rates {
            upstream: 10000,
            downstream: 18000,
        });
        drop(reservation);
        let current = accounting.current.clone();
        let mut peer = BandwidthPeer::new(&linked, accounting.grant, 2);
        if !late {
            current.store(false, Ordering::Release);
        }
        // SAFETY: exact physically admitted fixture; guard revocation is intentional.
        let result = unsafe { Allocate::new(channel, linked, accounting, cursor.now) };
        if late {
            let mut engine = result.unwrap();
            engine.poll(cursor.now).unwrap();
            let reply = peer.respond(&domain, &model, cursor.tx % 10);
            current.store(false, Ordering::Release);
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.now += 1;
            assert!(matches!(engine.poll(cursor.now), Err(Error::Revoked)));
            let mut channel = engine.into_channel();
            channel_release(&mut channel);
        } else {
            assert!(matches!(result, Err(Error::Revoked)));
        }
        assert!(dropped[..3].iter().all(|v| v.load(Ordering::Relaxed) == 0));
        assert_eq!(accounting_drop.load(Ordering::Relaxed), 0);
    }
    for late in [false, true] {
        let fixture = tunnel_fixture(LaneCredits::LegacyBonded, 2);
        let mut peer = TunnelPeer::new(&fixture, true, 2);
        let TunnelFixture {
            domain,
            model,
            channel,
            bandwidth,
            down,
            up,
            mut cursor,
            current,
            dropped,
            ..
        } = fixture;
        if !late {
            current.store(false, Ordering::Release);
        }
        // SAFETY: exact pair and real reservations, with native revocation explicitly modelled.
        let result = unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) };
        if late {
            let mut engine = result.unwrap();
            engine.poll(cursor.now).unwrap();
            let reply = peer.respond(&domain, &model, cursor.tx % 10);
            current.store(false, Ordering::Release);
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.now += 1;
            assert!(matches!(engine.poll(cursor.now), Err(Error::Revoked)));
            let mut channel = engine.into_channel();
            channel_release(&mut channel);
        } else {
            assert!(matches!(result, Err(Error::Revoked)));
        }
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
    }
    for late in [false, true] {
        let StopFixture {
            domain,
            model,
            channel,
            active,
            mut bandwidth_peer,
            mut cursor,
            current,
            dropped,
            ..
        } = stop_fixture(LaneCredits::LegacyBonded, 2);
        if !late {
            current.store(false, Ordering::Release);
        }
        // SAFETY: active owner and native provider accounting permission.
        let result = unsafe { ReleaseUnused::new(channel, active, cursor.now) };
        if late {
            let mut engine = result.unwrap();
            engine.poll(cursor.now).unwrap();
            let reply = bandwidth_peer.respond(&domain, &model, cursor.tx % 10);
            current.store(false, Ordering::Release);
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.now += 1;
            assert!(matches!(engine.poll(cursor.now), Err(Error::Revoked)));
            let mut channel = engine.into_channel();
            channel_release(&mut channel);
        } else {
            assert!(matches!(result, Err(Error::Revoked)));
        }
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
    }
}

#[test]
#[ignore = "oracle: STELA_USB3_STOP_ORACLE"]
fn unchanged_linux_usb3_complete_activation_optional_release_and_stop_match_dma() {
    use super::super::{
        path::LaneCredits,
        usb3::{ReleaseUnused, StopTunnel},
    };
    let text = std::fs::read_to_string(
        std::env::var("STELA_USB3_STOP_ORACLE").expect("source trace path"),
    )
    .unwrap();
    let mut cases = 0;
    for line in text.lines() {
        let v: Vec<u32> = line
            .split_ascii_whitespace()
            .skip(1)
            .map(|s| s.parse().unwrap())
            .collect();
        let [mode, release, seed, count] = v[..4] else {
            panic!("source header")
        };
        let credits = if mode == 0 {
            LaneCredits::LegacyBonded
        } else {
            LaneCredits::RouterAllocated((17 + seed % 15) as u8)
        };
        let StopFixture {
            domain,
            model,
            mut channel,
            mut active,
            mut peer,
            mut cursor,
            dropped,
            mut activation,
            mut bandwidth_peer,
            ..
        } = stop_fixture(credits, seed);
        if release != 0 {
            // SAFETY: model active receipt and kept native branch adjustment permission.
            let mut engine = unsafe { ReleaseUnused::new(channel, active, cursor.now) }.unwrap();
            active = drive_release(
                &mut bandwidth_peer,
                &domain,
                &model,
                &mut engine,
                &mut cursor,
            );
            channel = engine.into_channel();
            activation.extend(bandwidth_peer.writes.into_iter().map(|(offset, value)| {
                TunnelWrite {
                    route: 0,
                    port: 6,
                    space: 1,
                    offset,
                    data: vec![value],
                }
            }));
        }
        let rates = active.bandwidth_rates();
        // SAFETY: native guard, closed host admission and kept independent endpoint lifetimes.
        let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
        let stopped = drive_stop(&mut peer, &domain, &model, &mut engine, &mut cursor);
        activation.extend(peer.writes);
        let mut expected = Vec::new();
        let mut at = 4;
        for _ in 0..count {
            let length = v[at + 4] as usize;
            expected.push(TunnelWrite {
                route: u64::from(v[at]),
                port: v[at + 1] as u8,
                space: v[at + 2] as u8,
                offset: v[at + 3] as u16,
                data: v[at + 5..at + 5 + length].to_vec(),
            });
            at += 5 + length;
        }
        assert_eq!(activation, expected, "case={cases}");
        assert_eq!(stopped.endpoints, v[at..at + 2], "case={cases}");
        assert_eq!(
            [rates.upstream, rates.downstream],
            v[at + 2..at + 4],
            "case={cases}"
        );
        let words: Vec<_> = stopped.hops.iter().flat_map(|w| w.raw).collect();
        assert_eq!(words, v[at + 4..], "case={cases}");
        let reusable = match stopped.into_reusable() {
            Ok(v) => v,
            Err(_) => panic!("model live epoch"),
        };
        drop(reusable.paths);
        // SAFETY: model provider independently completes residual accounting/link lifetime transfer.
        unsafe { reusable.residual.retire() };
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
        let mut channel = engine.into_channel();
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 128);
}

#[test]
fn teardown_refuses_changed_owned_hops_before_disabling_them_and_full_tx_stays_bounded() {
    use super::super::{
        config::{Address, Route, Space},
        path::LaneCredits,
        usb3::{Error, StopTunnel},
    };
    for case in 0..5 {
        let StopFixture {
            domain,
            model,
            mut channel,
            active,
            mut peer,
            mut cursor,
            dropped,
            ..
        } = stop_fixture(LaneCredits::LegacyBonded, 2);
        if case < 4 {
            let p = if case < 2 {
                &mut peer.down
            } else {
                &mut peer.up
            };
            p.raw[case % 2][0] ^= 1; // next-HopID differs despite kept metadata.
        } else {
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
        // SAFETY: exact protected native owner pair; real wire state/progress is adverse.
        let mut engine = unsafe { StopTunnel::new(channel, active, cursor.now) }.unwrap();
        if case == 4 {
            let writes = model.state.lock().unwrap().writes.len();
            for delta in [0, 1, 150, 499] {
                assert!(engine.poll(cursor.now + delta).unwrap().is_none());
            }
            assert!(matches!(engine.poll(cursor.now + 500), Err(Error::Timeout)));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        } else {
            engine.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..200 {
                match stop_step(&mut peer, &domain, &model, &mut engine, &mut cursor) {
                    Err(Error::Changed) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("foreign owned hop was disabled"),
                }
            }
            assert!(failed);
            assert_eq!(peer.writes.len(), 2 + case);
        }
        let mut channel = engine.into_channel();
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}
