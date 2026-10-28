// SPDX-License-Identifier: GPL-2.0-only
//! Actual mapped-DMA PCIe tunnel controls; no physical qualification claim.
use super::*;
use crate::bus::thunderbolt::{
    config::{Encoded, PacketType},
    ring::{Direction as RingDirection, TX_DESCRIPTOR, model::*},
};
use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize};

struct NativeReservation {
    grant: Grant,
    current: AtomicBool,
    dropped: Arc<AtomicUsize>,
}
// SAFETY: actual isolated symbolic requester, router/link, HopIDs, credits and
// endpoint authority are retained by this fixture; no native admission implied.
unsafe impl Reservation for NativeReservation {
    fn grant(&self) -> Grant {
        self.grant
    }
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Relaxed)
    }
}
impl Drop for NativeReservation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
struct Fixture {
    domain: Arc<Domain>,
    model: Arc<Model>,
    channel: Channel<Model>,
    linked: Box<Linked>,
    reservation: Arc<NativeReservation>,
    cursor: NativeCursor,
    dropped: [Arc<AtomicUsize>; 4],
}
fn fixture(credits: LaneCredits) -> Fixture {
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
    } = link_fixture_with_protocol(1, false, 0x100101);
    let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 3);
    // SAFETY: exact actual modeled configured routers and protected link.
    let mut activate =
        unsafe { link::Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
    let linked = Box::new(drive_link(
        &mut peer,
        &domain,
        &model,
        &mut activate,
        &mut cursor,
    ));
    let channel = activate.into_channel();
    let (parent, child) = linked.retained_routers().unwrap();
    let dropped_owner = Arc::new(AtomicUsize::new(0));
    let reservation = Arc::new(NativeReservation {
        grant: Grant {
            identity: linked.partners.identity,
            topology_epoch: linked.partners.topology_epoch,
            grant_epoch: 3,
            pcie_down: parent.header.max_port(),
            pcie_up: child.header.max_port(),
            hops: [[(8, 30), (30, 8)], [(8, 31), (31, 8)]],
            lane_credits: [credits; 2],
            permission: Decision::Allowed,
        },
        current: AtomicBool::new(true),
        dropped: dropped_owner.clone(),
    });
    Fixture {
        domain,
        model,
        channel,
        linked,
        reservation,
        cursor,
        dropped: [
            dropped[0].clone(),
            dropped[1].clone(),
            dropped[2].clone(),
            dropped_owner,
        ],
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Write {
    route: u64,
    port: u8,
    space: u8,
    offset: u16,
    data: Vec<u32>,
}
struct Peer {
    paths: [PathPeer; 2],
    endpoints: [Endpoint; 2],
    cs0: [u32; 2],
    writes: Vec<Write>,
    detect: [bool; 2],
    reject_write: Option<usize>,
}
impl Peer {
    fn new(f: &Fixture, stale: bool) -> Self {
        let grant = f.reservation.grant;
        let (parent, child) = f.linked.retained_routers().unwrap();
        Self {
            paths: [
                PathPeer::new(&f.linked, allocation(grant, 0), stale, 5),
                PathPeer::new(&f.linked, allocation(grant, 1), stale, 7),
            ],
            endpoints: [
                endpoint(
                    parent.retained_owner().target(),
                    grant.pcie_down,
                    AdapterKind::PcieDown,
                )
                .unwrap(),
                endpoint(
                    child.retained_owner().target(),
                    grant.pcie_up,
                    AdapterKind::PcieUp,
                )
                .unwrap(),
            ],
            cs0: [0; 2],
            writes: vec![],
            detect: [true; 2],
            reject_write: None,
        }
    }
    fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(RingDirection::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let frame = domain.data(
            model.frame_address(RingDirection::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let mut words: Vec<u32> = frame[..frame.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|w| u32::from_be_bytes(*w))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        let port = ((address >> 19) & 63) as u8;
        let space = ((address >> 25) & 3) as u8;
        let offset = (address & 8191) as u16;
        let count = ((address >> 13) & 63) as usize;
        if kind == PacketType::Write {
            self.writes.push(Write {
                route,
                port,
                space,
                offset,
                data: words[3..].to_vec(),
            });
        }
        let endpoint = self
            .endpoints
            .iter()
            .position(|e| e.route.raw() == route && e.port == port);
        if let Some(e) = endpoint.filter(|_| space == 1 && offset == 0x50) {
            assert_eq!(count, 1);
            let data = if kind == PacketType::Write {
                assert!(
                    words[3] == 0 || words[3] == ENABLE,
                    "actual Linux full CS0 word"
                );
                self.cs0[e] = if self.reject_write == Some(self.writes.len()) {
                    words[3] ^ ENABLE
                } else {
                    words[3]
                };
                vec![]
            } else {
                assert_eq!(kind, PacketType::Read);
                vec![self.cs0[e] | if self.detect[e] { 0 } else { 6 << 25 }]
            };
            words.truncate(3);
            words[0] |= 1 << 31;
            words[2] = (address & !(63 << 19)) | (u32::from(self.endpoints[e].upstream) << 19);
            words.extend(data);
            return incoming(kind, &words);
        }
        let p = self
            .paths
            .iter()
            .position(|p| {
                p.routes
                    .iter()
                    .zip(p.ports)
                    .any(|(r, n)| *r == route && n == port)
            })
            .expect("actual allocated path endpoint");
        let result = self.paths[p].respond(domain, model, index);
        if kind == PacketType::Write && self.reject_write == Some(self.writes.len()) {
            let i = self.paths[p]
                .routes
                .iter()
                .zip(self.paths[p].ports)
                .position(|(r, n)| *r == route && n == port)
                .unwrap();
            self.paths[p].raw[i][0] ^= ENABLE;
        }
        result
    }
}
fn activation_step(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    activate: &mut Activate<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<Event>, Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize != cursor.tx % 10 {
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(RingDirection::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
    }
    cursor.now += 1;
    activate.poll(cursor.now)
}
fn drive(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    activate: &mut Activate<Model>,
    cursor: &mut NativeCursor,
) -> Box<Active> {
    activate.poll(cursor.now).unwrap();
    for _ in 0..160 {
        match activation_step(peer, domain, model, activate, cursor).unwrap() {
            Some(Event::Active(a)) => return a,
            Some(Event::Discarded(e)) => panic!("{e:?}"),
            None => {}
        }
    }
    panic!("actual PCIe tunnel did not activate")
}
fn stop_step(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    stop: &mut Stop<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<StopEvent>, Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize != cursor.tx % 10 {
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(RingDirection::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
    }
    cursor.now += 1;
    stop.poll(cursor.now)
}
fn drive_stop(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    stop: &mut Stop<Model>,
    cursor: &mut NativeCursor,
) -> Stopped {
    stop.poll(cursor.now).unwrap();
    for _ in 0..160 {
        match stop_step(peer, domain, model, stop, cursor).unwrap() {
            Some(StopEvent::Stopped(s)) => return s,
            Some(StopEvent::Discarded(e)) => panic!("{e:?}"),
            None => {}
        }
    }
    panic!("actual PCIe tunnel did not stop")
}

#[test]
fn actual_pcie_tunnel_source_order_credits_priority_and_repeated_local_reuse() {
    for credits in [
        LaneCredits::LegacyBonded,
        LaneCredits::RouterAllocated(6),
        LaneCredits::RouterAllocated(23),
    ] {
        for stale in [false, true] {
            let f = fixture(credits);
            let mut peer = Peer::new(&f, stale);
            let Fixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = f;
            // SAFETY: same modeled link/requester and actual protected native reservation.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation.clone(), cursor.now) }.unwrap();
            let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
            let mut channel = activate.into_channel();
            assert_eq!(active.endpoints, [ENABLE; 2]);
            let endpoints: Vec<_> = peer
                .writes
                .iter()
                .filter(|w| w.space == 1)
                .map(|w| (w.route, w.data[0]))
                .collect();
            assert_eq!(
                endpoints,
                vec![(2, ENABLE), (0, ENABLE)],
                "Up enabled before Down"
            );
            for p in &peer.paths {
                for (i, words) in p.raw.iter().enumerate() {
                    assert_eq!(words[1] & 0xfff, 1 | (3 << 8));
                    if i == 1 {
                        assert_eq!(
                            (words[0] >> 17) & 127,
                            match credits {
                                LaneCredits::LegacyBonded => 32,
                                LaneCredits::RouterAllocated(n) => u32::from(n),
                            }
                        );
                    }
                }
            }
            let start = peer.writes.len();
            // SAFETY: host submission is closed; independent resources retained.
            let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
            let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
            channel = stop.into_channel();
            assert_eq!(stopped.endpoints, [0; 2]);
            assert!(
                stopped
                    .hops
                    .iter()
                    .all(|h| h.raw[0] & ENABLE == 0 && h.raw[1] & PENDING == 0)
            );
            assert_eq!(peer.writes[start].route, 0);
            assert_eq!(peer.writes[start + 1].route, 2);
            assert!(
                peer.writes[start..start + 2]
                    .iter()
                    .all(|w| w.space == 1 && w.data == [0])
            );
            assert_eq!(
                peer.writes.len() - start,
                6,
                "normal source stop does not clear FC or allocate NFC"
            );
            let reusable = match stopped.into_reusable() {
                Ok(r) => r,
                Err(_) => panic!("live local return"),
            };
            // SAFETY: exact original same-epoch link/real reservation returned by complete stop.
            let mut again =
                unsafe { Activate::new(channel, reusable.link, reusable.reservation, cursor.now) }
                    .unwrap();
            let active = drive(&mut peer, &domain, &model, &mut again, &mut cursor);
            let mut channel = again.into_channel();
            drop(reservation);
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
            // SAFETY: complete actual synthetic CM transfer through final device drain.
            unsafe { active.retire() };
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 1));
            channel_release(&mut channel);
        }
    }
}

fn fail_actual_write(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    cursor: &mut NativeCursor,
    target: usize,
    fault: usize,
    mut poll: impl FnMut(u64) -> Result<(), Error>,
) {
    if fault == 2 {
        peer.reject_write = Some(target);
    }
    poll(cursor.now).unwrap();
    for _ in 0..180 {
        if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
            cursor.now += 1;
            poll(cursor.now).unwrap();
            continue;
        }
        let before = peer.writes.len();
        let mut reply = peer.respond(domain, model, cursor.tx % 10);
        let selected = peer.writes.len() == target && peer.writes.len() != before;
        if selected && fault == 1 {
            reply = controller_error(domain, model, cursor);
        }
        model.finish(RingDirection::Tx, cursor.tx % 10, &[], None);
        cursor.tx += 1;
        if selected && fault == 0 {
            cursor.now += 501;
            assert!(matches!(
                poll(cursor.now),
                Err(Error::Timeout | Error::Path(path::Error::Timeout))
            ));
            return;
        }
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.rx += 1;
        cursor.now += 1;
        let result = poll(cursor.now);
        if result.is_err() {
            assert_eq!(peer.writes.len(), target);
            assert!(selected || fault == 2);
            return;
        }
    }
    panic!("injected real write failure did not fail");
}

#[test]
fn every_pcie_activation_write_lost_ack_controller_error_and_readback_refusal_retains_all_owners() {
    for target in 1..=10 {
        for fault in 0..3 {
            let f = fixture(LaneCredits::RouterAllocated(6));
            let mut peer = Peer::new(&f, true);
            let Fixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = f;
            // SAFETY: complete isolated model link, protected allocations and endpoint authority.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation.clone(), cursor.now) }.unwrap();
            fail_actual_write(
                &mut peer,
                &domain,
                &model,
                &mut cursor,
                target,
                fault,
                |now| activate.poll(now).map(|event| assert!(event.is_none())),
            );
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(
                activate.poll(cursor.now + 1),
                Err(Error::Poisoned)
            ));
            assert_eq!(writes, model.state.lock().unwrap().writes.len());
            let mut channel = activate.into_channel();
            drop(reservation);
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}

#[test]
fn every_pcie_stop_write_lost_ack_controller_error_and_readback_refusal_retains_all_owners() {
    for target in 1..=6 {
        for fault in 0..3 {
            let f = fixture(LaneCredits::LegacyBonded);
            let mut peer = Peer::new(&f, false);
            let Fixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = f;
            // SAFETY: same actual modeled lifetime and retained native authority.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation.clone(), cursor.now) }.unwrap();
            let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
            let channel = activate.into_channel();
            peer.writes.clear();
            // SAFETY: independent host submission and endpoint resources stay retained.
            let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
            fail_actual_write(
                &mut peer,
                &domain,
                &model,
                &mut cursor,
                target,
                fault,
                |now| stop.poll(now).map(|event| assert!(event.is_none())),
            );
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(stop.poll(cursor.now + 1), Err(Error::Poisoned)));
            assert_eq!(writes, model.state.lock().unwrap().writes.len());
            let mut channel = stop.into_channel();
            drop(reservation);
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}

#[test]
fn pcie_preflight_refuses_bad_grants_without_any_new_publication() {
    for fault in 0..9 {
        let Fixture {
            domain: _,
            model,
            channel,
            linked,
            mut reservation,
            cursor,
            dropped,
        } = fixture(LaneCredits::RouterAllocated(6));
        let owner = Arc::get_mut(&mut reservation).unwrap();
        match fault {
            0 => owner.current.store(false, Ordering::Relaxed),
            1 => owner.grant.identity.epoch += 1,
            2 => owner.grant.topology_epoch += 1,
            3 => owner.grant.grant_epoch = 0,
            4 => owner.grant.pcie_down = 1,
            5 => owner.grant.pcie_up = 1,
            6 => owner.grant.hops[1][1].1 = 9,
            7 => owner.grant.lane_credits[0] = LaneCredits::RouterAllocated(5),
            8 => owner.grant.permission = Decision::Denied,
            _ => unreachable!(),
        }
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: same model requester; intentionally invalid metadata is refused.
        let result = unsafe { Activate::new(channel, linked, reservation, cursor.now) };
        assert!(result.is_err());
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        assert_eq!(
            dropped[3].load(Ordering::Relaxed),
            1,
            "unused PCIe allocation releases, real live link remains quarantined"
        );
    }
}

#[test]
fn pcie_ltssm_detect_timeout_and_guard_revocation_never_publish_enable() {
    for fault in 0..4 {
        let f = fixture(LaneCredits::LegacyBonded);
        let mut peer = Peer::new(&f, false);
        peer.detect[usize::from(fault == 1)] = false;
        let Fixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        } = f;
        // SAFETY: same actual modeled CM link and retained endpoint control.
        let mut activate =
            unsafe { Activate::new(channel, linked, reservation.clone(), cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        for _ in 0..12 {
            activation_step(&mut peer, &domain, &model, &mut activate, &mut cursor).unwrap();
        }
        assert!(peer.writes.is_empty());
        if fault < 2 {
            assert!(matches!(
                activate.poll(cursor.now + 501),
                Err(Error::Timeout)
            ));
        } else if fault == 2 {
            reservation.current.store(false, Ordering::Relaxed);
            assert!(matches!(activate.poll(cursor.now + 1), Err(Error::Revoked)));
            reservation.current.store(true, Ordering::Relaxed);
        } else {
            assert!(matches!(
                activate.poll(cursor.now - 1),
                Err(Error::ClockRegressed)
            ));
        }
        assert!(matches!(
            activate.poll(cursor.now + 502),
            Err(Error::Poisoned)
        ));
        let mut channel = activate.into_channel();
        drop(reservation);
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
fn each_actual_pending_hop_and_changed_owned_hop_refuses_local_pcie_reuse() {
    for hop in 0..4 {
        for pending in [false, true] {
            let f = fixture(LaneCredits::RouterAllocated(23));
            let mut peer = Peer::new(&f, false);
            let Fixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = f;
            // SAFETY: same actual modeled requester, protected link and allocations.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation.clone(), cursor.now) }.unwrap();
            let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
            let channel = activate.into_channel();
            if pending {
                peer.paths[hop / 2].hold_hop[hop % 2] = true;
                peer.paths[hop / 2].raw[hop % 2][1] |= PENDING;
            } else {
                peer.paths[hop / 2].raw[hop % 2][0] ^= 1;
            }
            // SAFETY: admission closed and full independent resources retained.
            let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
            stop.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..700 {
                if let Err(error) = stop_step(&mut peer, &domain, &model, &mut stop, &mut cursor) {
                    assert!(matches!(error, Error::Changed | Error::Timeout));
                    failed = true;
                    break;
                }
            }
            assert!(failed);
            let mut channel = stop.into_channel();
            drop(reservation);
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}

#[test]
fn stopped_pcie_guard_revocation_and_unconsumed_completions_keep_exact_owners() {
    for revoked in [false, true] {
        let f = fixture(LaneCredits::LegacyBonded);
        let mut peer = Peer::new(&f, false);
        let Fixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        } = f;
        // SAFETY: same actual isolated CM lifetime and endpoint reservation.
        let mut activate =
            unsafe { Activate::new(channel, linked, reservation.clone(), cursor.now) }.unwrap();
        let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
        let mut channel = activate.into_channel();
        if revoked {
            // SAFETY: actual synthetic submission is closed through local stop.
            let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
            let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
            channel = stop.into_channel();
            reservation.current.store(false, Ordering::Relaxed);
            let stopped = match stopped.into_reusable() {
                Err((Error::Revoked, s)) => s,
                _ => panic!("native revoked guard must refuse"),
            };
            drop(stopped);
        } else {
            drop(active);
        }
        drop(reservation);
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
fn post_publication_native_revocation_or_actual_hotplug_never_releases_partial_pcie_paths() {
    for hotplug in [false, true] {
        let f = fixture(LaneCredits::RouterAllocated(6));
        let mut peer = Peer::new(&f, false);
        let Fixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        } = f;
        // SAFETY: actual isolated model requester and retained native authorities.
        let mut activate =
            unsafe { Activate::new(channel, linked, reservation.clone(), cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        for _ in 0..60 {
            if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                cursor.now += 1;
                activate.poll(cursor.now).unwrap();
                continue;
            }
            let reply = peer.respond(&domain, &model, cursor.tx % 10);
            model.finish(RingDirection::Tx, cursor.tx % 10, &[], None);
            cursor.tx += 1;
            cursor.now += 1;
            if !peer.writes.is_empty() {
                if hotplug {
                    finish_rx(
                        &model,
                        cursor.rx % 10,
                        &incoming(PacketType::Event, &[0, 0, 2]),
                    );
                } else {
                    reservation.current.store(false, Ordering::Relaxed);
                }
                let error = activate.poll(cursor.now);
                assert!(matches!(
                    error,
                    Err(Error::Revoked | Error::Hotplug(_) | Error::Path(path::Error::Hotplug(_)))
                ));
                break;
            }
            finish_rx(&model, cursor.rx % 10, &reply);
            cursor.rx += 1;
            activate.poll(cursor.now).unwrap();
        }
        assert_eq!(
            peer.writes.len(),
            1,
            "one actual path write preceded loss of admission"
        );
        reservation.current.store(true, Ordering::Relaxed);
        assert!(matches!(
            activate.poll(cursor.now + 1),
            Err(Error::Poisoned)
        ));
        let mut channel = activate.into_channel();
        drop(reservation);
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_PCIE_ORACLE"]
fn unchanged_linux_pcie_complete_write_transcript_matches_actual_native_dma() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_THUNDERBOLT_PCIE_ORACLE").expect("set PCIe trace"),
    )
    .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let n = |i: usize| fields[i].parse::<u32>().unwrap();
        assert_eq!(fields[0], "C");
        let credits = if n(1) == 0 {
            LaneCredits::LegacyBonded
        } else {
            LaneCredits::RouterAllocated((6 + n(3) % 26) as u8)
        };
        let f = fixture(credits);
        let mut peer = Peer::new(&f, n(2) != 0);
        for d in 0..2 {
            for h in 0..2 {
                peer.paths[d].raw[h] = [n(4 + d * 4 + h * 2), n(5 + d * 4 + h * 2)];
            }
        }
        let Fixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        } = f;
        // SAFETY: actual native model configured routers and reciprocal link,
        // exact protected source HopIDs/credits and retained endpoint authority.
        let mut activate =
            unsafe { Activate::new(channel, linked, reservation.clone(), cursor.now) }.unwrap();
        let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
        let channel = activate.into_channel();
        // SAFETY: modeled submission is closed and independent resources retained.
        let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
        let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
        let mut channel = stop.into_channel();
        let count = n(12) as usize;
        assert_eq!(peer.writes.len(), count);
        let mut at = 13;
        for actual in &peer.writes {
            assert_eq!(
                (
                    actual.route,
                    actual.port,
                    actual.space,
                    actual.offset,
                    actual.data.len()
                ),
                (
                    u64::from(n(at)),
                    n(at + 1) as u8,
                    n(at + 2) as u8,
                    n(at + 3) as u16,
                    n(at + 4) as usize
                )
            );
            at += 5;
            for word in &actual.data {
                assert_eq!(*word, n(at));
                at += 1;
            }
        }
        assert_eq!(stopped.endpoints, [n(at), n(at + 1)]);
        at += 2;
        for words in stopped.hops {
            assert_eq!(words.raw, [n(at), n(at + 1)]);
            at += 2;
        }
        assert_eq!(at, fields.len());
        let reusable = match stopped.into_reusable() {
            Ok(r) => r,
            Err(_) => panic!("actual local owner return"),
        };
        drop(reservation);
        // SAFETY: independent synthetic CM transfer retains the stopped actual link.
        unsafe { reusable.link.retire() };
        drop(reusable.reservation);
        assert!(dropped.iter().all(|v| v.load(Ordering::Relaxed) == 1));
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 128);
}
