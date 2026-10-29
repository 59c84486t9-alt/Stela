extern crate std;
use super::*;

use crate::bus::thunderbolt::config::PacketType;
use crate::bus::thunderbolt::ring::{Direction, TX_DESCRIPTOR, model::*};
use alloc::vec::Vec;

#[test]
fn link_bonds_and_activates_both_actual_configured_routers_with_observed_nonadjacent_lanes() {
    use super::super::link::Activate;
    for map in 0..2 {
        for generation in [2, 3] {
            for dual in [false, true] {
                for mode in [false, true] {
                    let LinkFixture {
                        domain,
                        model,
                        channel,
                        parent,
                        child,
                        reservation,
                        mut cursor,
                        dropped,
                        ..
                    } = link_fixture(map, mode);
                    let mut peer = LinkPeer::new(reservation.partners, generation, dual, mode, 3);
                    // SAFETY: same model NHI/reset/topology epoch, both source-
                    // configured owners and observed reciprocal CL0 lanes/power grant.
                    let mut activate =
                        unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }
                            .unwrap();
                    let linked = drive_link(&mut peer, &domain, &model, &mut activate, &mut cursor);
                    assert_eq!(linked.generation, generation);
                    assert_eq!(linked.link_usb4, !mode);
                    assert_eq!((linked.parent_width >> 20) & 63, 2);
                    assert_eq!((linked.child_width >> 20) & 63, 2);
                    assert!(linked.configured.iter().all(|word| word & (1 << 3) != 0));
                    assert_eq!(peer.writes.len(), if dual { 2 } else { 7 });
                    for (credit, index) in linked.credits.iter().zip([2, 3, 0, 1]) {
                        assert_eq!(credit.raw, peer.credits[index]);
                    }
                    let mut channel = activate.into_channel();
                    assert!(
                        dropped
                            .iter()
                            .all(|counter| counter.load(Ordering::Relaxed) == 0)
                    );
                    // SAFETY: both real synthetic configured/router/link reservations
                    // transfer into independently kept CM lifetime through drain.
                    unsafe { linked.retire() };
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
}

#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_LINK_ORACLE"]
fn unchanged_linux_link_bonding_credit_and_two_ended_write_trace_matches_actual_dma() {
    use super::super::link::Activate;
    use std::{env, fs};
    let trace =
        fs::read_to_string(env::var("STELA_THUNDERBOLT_LINK_ORACLE").expect("set link trace"))
            .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(fields[0], "L");
        let n = |i: usize| fields[i].parse::<u32>().unwrap();
        let (map, generation, dual, mode, seed) =
            (n(1) as u8, n(2) as u8, n(3) != 0, n(4) != 0, n(5));
        let LinkFixture {
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            mut cursor,
            ..
        } = link_fixture(map, mode);
        let mut peer = LinkPeer::new(reservation.partners, generation, dual, mode, seed);
        for i in 0..4 {
            assert_eq!(peer.phy[i], [n(6 + i), n(10 + i)]);
            assert_eq!(peer.credits[i], n(14 + i));
        }
        assert_eq!(peer.pc, [n(18), n(19)]);
        // SAFETY: each isolated source fixture provides same native
        // requester/epochs, configured leases and observed reciprocal map.
        let mut activate =
            unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
        let linked = drive_link(&mut peer, &domain, &model, &mut activate, &mut cursor);
        assert_eq!(
            linked
                .credits
                .iter()
                .map(|credit| credit.raw)
                .collect::<Vec<_>>(),
            (20..24).map(n).collect::<Vec<_>>()
        );
        let count = n(24) as usize;
        let mut at = 25;
        let mut writes = vec![];
        for _ in 0..count {
            let side = n(at) as usize;
            let port = n(at + 1) as u8;
            let index = if side == 0 {
                peer.partners
                    .child
                    .iter()
                    .position(|number| *number == port)
                    .unwrap()
            } else {
                2 + peer
                    .partners
                    .parent
                    .iter()
                    .position(|number| *number == port)
                    .unwrap()
            };
            writes.push(LinkWrite {
                index,
                offset: n(at + 2) as u16,
                value: n(at + 3),
            });
            at += 4;
        }
        assert_eq!(at, fields.len());
        assert_eq!(
            peer.writes, writes,
            "source map={map} gen={generation} dual={dual} mode={mode} seed={seed}"
        );
        let mut channel = activate.into_channel();
        // SAFETY: completed synthetic link/routers are transferred
        // to an independent model CM lifetime through final drain.
        unsafe { linked.retire() };
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 512);
}

#[test]
fn link_unknown_epochs_partner_records_router_versions_and_policy_refuse_before_mutation() {
    use super::super::link::{Activate, Error};
    for case in 0..13 {
        let LinkFixture {
            domain,
            model,
            channel,
            mut parent,
            mut child,
            mut reservation,
            cursor,
            dropped,
            ..
        } = link_fixture(1, false);
        let observed = &mut Arc::get_mut(&mut reservation).unwrap().partners;
        match case {
            0 => observed.identity.epoch += 1,
            1 => observed.topology_epoch = 0,
            2 => observed.child[1] = 1,
            3 => observed.parent[0] = 1,
            4 => observed.parent[1] = 3,
            5 => observed.observations[0].remote_port = 5,
            6 => observed.observations[1].dual_port = 2,
            7 => observed.observations[2].lane_index = 1,
            8 => child.header.raw[4] = (child.header.raw[4] & !(7 << 29)) | (3 << 29),
            9 => parent.identity.epoch += 1,
            10 => child.setup_word = Some(1 << 24),
            11 => child.link_usb4 = None,
            12 => {}
            _ => unreachable!(),
        }
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: all negative data is confined to this isolated
        // synthetic requester. No native provider/permission is invented.
        let result = unsafe {
            Activate::new(
                channel,
                parent,
                child,
                reservation,
                if case == 12 { u64::MAX } else { cursor.now },
            )
        };
        assert!(matches!(
            result,
            Err(Error::Identity
                | Error::Topology
                | Error::Unsupported
                | Error::Policy
                | Error::ClockOverflow)
        ));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
        assert_eq!(dropped[1].load(Ordering::Relaxed), 0);
        assert_eq!(dropped[2].load(Ordering::Relaxed), 1);
        drop(domain);
    }
}

#[test]
fn link_unknown_phy_modes_asymmetry_and_missing_bonding_support_never_write_link() {
    use super::super::link::{Activate, Error};
    for case in 0..8 {
        let LinkFixture {
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            mut cursor,
            ..
        } = link_fixture(1, false);
        let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
        match case {
            0 => peer.phy[0][1] = (peer.phy[0][1] & !(15 << 16)) | (2 << 16),
            1 => peer.phy[0][1] &= !(15 << 16),
            2 => peer.phy[1][1] = (peer.phy[1][1] & !(63 << 20)) | (4 << 20),
            3 => peer.phy[1][1] = (peer.phy[1][1] & !(63 << 20)) | (2 << 20),
            4 => peer.phy[0][1] = (peer.phy[0][1] & !(15 << 26)) | (3 << 26),
            5 => peer.phy[2][0] &= !(2 << 20),
            6 => peer.mode = true,
            7 => peer.deny_bond = true,
            _ => unreachable!(),
        }
        // SAFETY: same current synthetic configured leases/map; raw
        // unsupported PHY and contradictory mode observations cannot grant
        // a native transition or be replaced by successful defaults.
        let mut activate =
            unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        let mut failed = false;
        for _ in 0..20 {
            let reply = peer.respond(&domain, &model, cursor.tx % 10);
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.tx += 1;
            cursor.rx += 1;
            cursor.now += 1;
            match activate.poll(cursor.now) {
                Err(Error::Unsupported | Error::ChangedLink | Error::NotCl0) => {
                    failed = true;
                    break;
                }
                Ok(None) => {}
                _ => panic!("unexpected preflight outcome"),
            }
        }
        assert!(failed);
        assert!(peer.writes.is_empty());
        let mut channel = activate.into_channel();
        channel_release(&mut channel);
    }
}

#[test]
fn link_every_write_uncertainty_retains_both_routers_without_claiming_rollback() {
    use super::super::link::{Activate, Error};
    for target in 1..=7 {
        for failure in 0..3 {
            let LinkFixture {
                domain,
                model,
                channel,
                parent,
                child,
                reservation,
                mut cursor,
                dropped,
                ..
            } = link_fixture(1, false);
            let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 1);
            // SAFETY: same model NHI/domain/epochs and observed reciprocal
            // CL0 lanes. Both configured owners remain real kept resources.
            let mut activate =
                unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
            activate.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..100 {
                let tx = cursor.tx % 10;
                let rx = cursor.rx % 10;
                let descriptor = domain.read32(model.descriptor_address(Direction::Tx, tx) + 8);
                let is_write = ((descriptor >> 12) & 15) == PacketType::Write as u32;
                if failure == 2 && is_write && peer.writes.len() + 1 == target {
                    let bytes = domain.data(model.frame_address(Direction::Tx, tx), 20);
                    let route = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
                    let address = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
                    let port = ((address >> 19) & 63) as u8;
                    let lane = if route == peer.route as u32 {
                        peer.partners
                            .child
                            .iter()
                            .position(|number| *number == port)
                            .unwrap()
                    } else {
                        2 + peer
                            .partners
                            .parent
                            .iter()
                            .position(|number| *number == port)
                            .unwrap()
                    };
                    peer.reject = Some((lane, (address & 0x1fff) as u16));
                }
                let mut reply = peer.respond(&domain, &model, tx);
                if is_write && peer.writes.len() == target && failure == 0 {
                    assert!(matches!(
                        activate.poll(cursor.now + 501),
                        Err(Error::Timeout)
                    ));
                    cursor.now += 501;
                    failed = true;
                    break;
                }
                if is_write && peer.writes.len() == target && failure == 1 {
                    let bytes = domain.data(model.frame_address(Direction::Tx, tx), 16);
                    reply = incoming(
                        PacketType::Error,
                        &[
                            u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                            2,
                        ],
                    );
                }
                model.finish(Direction::Tx, tx, &[], None);
                finish_rx(&model, rx, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                match activate.poll(cursor.now) {
                    Err(Error::Readback | Error::Controller { code: 2, .. }) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("unexpected partial-write outcome"),
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
                    .all(|counter| counter.load(Ordering::Relaxed) == 0),
                "both configured ends and changed link reservation must remain held"
            );
            channel_release(&mut channel);
        }
    }
}

#[test]
fn link_bond_window_includes_readback_and_port_locked_retries_never_extend_it() {
    use super::super::link::{Activate, Error};
    for locked in [false, true] {
        let LinkFixture {
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            mut cursor,
            dropped,
            ..
        } = link_fixture(1, false);
        let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
        peer.hold_width = true;
        // SAFETY: same real synthetic configured owners/observations;
        // delayed hardware or lock responses cannot replace readiness.
        let mut activate =
            unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        let mut ack = None;
        for _ in 0..200 {
            // A lock retry waits at least1ms before publishing the next
            // request. Do not invent a reply for an unused slot.
            if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                if let Some(ack) = ack
                    && cursor.now + 1 >= ack + 99
                {
                    break;
                }
                cursor.now += 1;
                assert!(activate.poll(cursor.now).unwrap().is_none());
                continue;
            }
            let before = peer.writes.len();
            let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
            let bond_ack = peer.writes.len() > before
                && peer.writes.last().is_some_and(|write| {
                    write.index == 2 && write.offset == 9 && write.value & (1 << 15) != 0
                });
            if ack.is_some() && peer.bond_reads >= 1 && locked {
                reply = incoming(PacketType::Error, &[1 << 31, 0, 15]);
            }
            model.finish(Direction::Tx, cursor.tx % 10, &[], None);
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.tx += 1;
            cursor.rx += 1;
            cursor.now = if let Some(ack) = ack {
                if locked { cursor.now + 1 } else { ack + 99 }
            } else {
                cursor.now + 1
            };
            assert!(activate.poll(cursor.now).unwrap().is_none());
            if bond_ack {
                ack = Some(cursor.now);
            }
            if let Some(ack) = ack
                && ((!locked && peer.bond_reads >= 1) || (locked && cursor.now >= ack + 99))
            {
                break;
            }
        }
        let ack = ack.expect("actual parent LB write ACK");
        assert!(peer.bond_reads >= if locked { 2 } else { 1 });
        let writes = model.state.lock().unwrap().writes.len();
        assert!(matches!(activate.poll(ack + 100), Err(Error::Timeout)));
        assert!(matches!(activate.poll(ack + 101), Err(Error::Poisoned)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        assert_eq!(peer.writes.len(), 5);
        let mut channel = activate.into_channel();
        assert!(
            dropped
                .iter()
                .all(|counter| counter.load(Ordering::Relaxed) == 0)
        );
        channel_release(&mut channel);
    }
}

#[test]
fn link_secondary_connection_wait_obeys_ten_source_reads_and_hundred_ms_spacing() {
    use super::super::link::{Activate, Error};
    let LinkFixture {
        domain,
        model,
        channel,
        parent,
        child,
        reservation,
        mut cursor,
        dropped,
        ..
    } = link_fixture(1, false);
    let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
    peer.port_wait_state = Some(1);
    // SAFETY: same synthetic partners/epochs; asynchronous
    // secondary connection loss is observed from real config DMA replies.
    let mut activate =
        unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
    activate.poll(cursor.now).unwrap();
    let mut tries = 0;
    for _ in 0..30 {
        let previous = peer.secondary_reads;
        let reply = peer.respond(&domain, &model, cursor.tx % 10);
        let waiting = peer.secondary_reads > previous && peer.secondary_reads > 1;
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(&model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        assert!(activate.poll(cursor.now).unwrap().is_none());
        if waiting {
            tries += 1;
            let writes = model.state.lock().unwrap().writes.len();
            assert!(activate.poll(cursor.now + 99).unwrap().is_none());
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            cursor.now += 100;
            let result = activate.poll(cursor.now);
            if tries == 10 {
                assert!(matches!(result, Err(Error::NoConnection)));
                break;
            }
            assert!(result.unwrap().is_none());
        }
    }
    assert_eq!(tries, 10);
    assert_eq!(peer.secondary_reads, 11);
    assert!(peer.writes.is_empty());
    let mut channel = activate.into_channel();
    assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
    assert_eq!(dropped[1].load(Ordering::Relaxed), 0);
    assert_eq!(dropped[2].load(Ordering::Relaxed), 1);
    channel_release(&mut channel);
}

#[test]
fn link_receipt_storage_failure_refuses_before_publication_and_retains_active_routers() {
    use super::super::link::{Activate, Error};
    let LinkFixture {
        domain,
        model,
        channel,
        parent,
        child,
        reservation,
        cursor,
        dropped,
        ..
    } = link_fixture(1, false);
    let writes = model.state.lock().unwrap().writes.len();
    let unmaps = domain.state.lock().unwrap().unmaps;
    // SAFETY: the same model NHI/epoch and configured owners are
    // paired. The local null allocator deterministically refuses only this
    // receipt; no global allocator or other test thread is affected.
    let result =
        unsafe { Activate::new_without_storage(channel, parent, child, reservation, cursor.now) };
    assert!(matches!(result, Err(Error::Allocation)));
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    assert_eq!(domain.state.lock().unwrap().unmaps, unmaps);
    // Already-configured routers and live channel DMA remain quarantined.
    // The link reservation has never published a mutation and may retire.
    assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
    assert_eq!(dropped[1].load(Ordering::Relaxed), 0);
    assert_eq!(dropped[2].load(Ordering::Relaxed), 1);
}

#[test]
fn link_full_publication_clock_revocation_and_unconsumed_success_keep_real_router_leases() {
    use super::super::{
        channel::Event,
        config::{Address, Route, Space},
        link::{Activate, Error},
    };
    let LinkFixture {
        domain,
        model,
        mut channel,
        parent,
        child,
        reservation,
        mut cursor,
        dropped,
        ..
    } = link_fixture(1, false);
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
            Ok(Some(Event::Completed { .. }))
        ));
    }
    // SAFETY: same native model reservations and idle channel; nine
    // completed requests still occupy physically unconsumed TX descriptors.
    let mut activate =
        unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
    let writes = model.state.lock().unwrap().writes.len();
    for offset in [0, 1, 499] {
        assert!(activate.poll(cursor.now + offset).unwrap().is_none());
    }
    assert!(matches!(
        activate.poll(cursor.now + 500),
        Err(Error::Timeout)
    ));
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    let mut channel = activate.into_channel();
    assert_eq!(dropped[2].load(Ordering::Relaxed), 1);
    channel_release(&mut channel);
    for mode in 0..3 {
        let LinkFixture {
            domain,
            model,
            channel,
            parent,
            child,
            reservation,
            mut cursor,
            dropped,
            ..
        } = link_fixture(1, false);
        let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
        // SAFETY: same exact configured owners/observations/epochs.
        let mut activate =
            unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
        if mode == 0 {
            assert!(matches!(
                activate.poll(cursor.now - 1),
                Err(Error::ClockRegressed)
            ));
        } else if mode == 1 {
            activate.poll(cursor.now).unwrap();
            for _ in 0..100 {
                let reply = peer.respond(&domain, &model, cursor.tx % 10);
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                cursor.now += 1;
                assert!(activate.poll(cursor.now).unwrap().is_none());
                if !peer.writes.is_empty() {
                    break;
                }
            }
            assert!(matches!(activate.cancel(), Err(Error::Cancelled)));
        } else {
            let linked = drive_link(&mut peer, &domain, &model, &mut activate, &mut cursor);
            drop(linked);
        }
        let mut channel = activate.into_channel();
        assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
        assert_eq!(dropped[1].load(Ordering::Relaxed), 0);
        assert_eq!(
            dropped[2].load(Ordering::Relaxed),
            if mode == 0 { 1 } else { 0 }
        );
        channel_release(&mut channel);
    }
}

#[test]
fn link_transient_port_lock_at_first_bond_readback_recovers_without_moving_window() {
    use super::super::link::{Activate, Event};
    let LinkFixture {
        domain,
        model,
        channel,
        parent,
        child,
        reservation,
        mut cursor,
        dropped,
        ..
    } = link_fixture(1, false);
    let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 0);
    // SAFETY: same real synthetic native/router/link reservations;
    // temporary documented lock is a protocol response, not a new owner.
    let mut activate =
        unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
    activate.poll(cursor.now).unwrap();
    let mut locked = false;
    let mut result = None;
    for _ in 0..150 {
        if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
            cursor.now += 1;
            assert!(activate.poll(cursor.now).unwrap().is_none());
            continue;
        }
        let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
        if peer.bond_reads == 1 && !locked {
            reply = incoming(PacketType::Error, &[1 << 31, 0, 15]);
            locked = true;
        }
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(&model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        match activate.poll(cursor.now).unwrap() {
            Some(Event::Linked(linked)) => {
                result = Some(linked);
                break;
            }
            None => {}
            _ => panic!("unexpected link event"),
        }
    }
    assert!(locked);
    let linked = result.expect("actual both-ended transition after transient lock");
    let mut channel = activate.into_channel();
    // SAFETY: both model router/link leases transfer into kept
    // independent native CM lifetime through real synthetic final drain.
    unsafe { linked.retire() };
    assert!(
        dropped
            .iter()
            .all(|counter| counter.load(Ordering::Relaxed) == 1)
    );
    channel_release(&mut channel);
}
