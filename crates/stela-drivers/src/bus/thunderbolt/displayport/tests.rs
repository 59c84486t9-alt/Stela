// SPDX-License-Identifier: GPL-2.0-only
use super::*;
use crate::bus::thunderbolt::{
    config::{Encoded, PacketType},
    link,
    ring::{Direction as RingDirection, TX_DESCRIPTOR, model::*},
};
use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize};

struct Native {
    grant: Grant,
    current: AtomicBool,
    dropped: Arc<AtomicUsize>,
}
// SAFETY: actual isolated model display association and shared domain grants,
// retained through the real modeled router/link/DMA configuration sequence.
unsafe impl Reservation for Native {
    fn grant(&self) -> Grant {
        self.grant
    }
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Relaxed)
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
struct Fixture {
    domain: Arc<Domain>,
    model: Arc<Model>,
    channel: Channel<Model>,
    linked: Box<Linked>,
    owner: Arc<Native>,
    cursor: NativeCursor,
    dropped: [Arc<AtomicUsize>; 4],
}
fn fixture(credits: Credits, max_mbps: u32) -> Fixture {
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
    } = link_fixture_with_protocol(1, false, 0x0e0101);
    let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 3);
    // SAFETY: actual isolated modeled configured routers and reciprocal link.
    let mut link =
        unsafe { link::Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
    let linked = Box::new(drive_link(
        &mut peer,
        &domain,
        &model,
        &mut link,
        &mut cursor,
    ));
    let channel = link.into_channel();
    let (parent, child) = linked.retained_routers().unwrap();
    let native_drop = Arc::new(AtomicUsize::new(0));
    let owner = Arc::new(Native {
        grant: Grant {
            identity: linked.partners.identity,
            topology_epoch: linked.partners.topology_epoch,
            grant_epoch: 3,
            dp_in: parent.header.max_port(),
            dp_out: child.header.max_port(),
            hops: [[(9, 30), (30, 9)], [(8, 31), (31, 8)], [(8, 32), (32, 8)]],
            credits,
            max_mbps,
            permission: Decision::Allowed,
        },
        current: AtomicBool::new(true),
        dropped: native_drop.clone(),
    });
    Fixture {
        domain,
        model,
        channel,
        linked,
        owner,
        cursor,
        dropped: [
            dropped[0].clone(),
            dropped[1].clone(),
            dropped[2].clone(),
            native_drop,
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
    paths: [PathPeer; 3],
    endpoints: [Endpoint; 2],
    csr: [[u32; 8]; 2],
    credits: [u32; 2],
    writes: Vec<Write>,
    hold_handshake: bool,
    hold_dprx: bool,
    handshake_reads: usize,
    dprx_reads: usize,
    reject_write: Option<usize>,
}
impl Peer {
    fn new(f: &Fixture, stale: bool) -> Self {
        let grant = f.owner.grant;
        let (parent, child) = f.linked.retained_routers().unwrap();
        let mut csr = [[0; 8]; 2];
        csr[0] = [
            0x00123456, 0x789abcd1, 0, 0x00100220, 0x0020235a, 0, 0x0015005a, 0,
        ];
        csr[1] = [0x00567321, 0x13579bdf, 0, 0, 0x006023a5, 0, 0x004400a5, 0];
        Self {
            paths: core::array::from_fn(|i| {
                PathPeer::new(&f.linked, allocation(grant, i), stale, 5 + i as u32 * 2)
            }),
            endpoints: [
                endpoint(
                    parent.retained_owner().target(),
                    grant.dp_in,
                    AdapterKind::DisplayIn,
                )
                .unwrap(),
                endpoint(
                    child.retained_owner().target(),
                    grant.dp_out,
                    AdapterKind::DisplayOut,
                )
                .unwrap(),
            ],
            csr,
            credits: [(100 << 20) | 8; 2],
            writes: vec![],
            hold_handshake: false,
            hold_dprx: false,
            handshake_reads: 0,
            dprx_reads: 0,
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
        let writing = kind == PacketType::Write;
        if writing {
            self.writes.push(Write {
                route,
                port,
                space,
                offset,
                data: words[3..].to_vec(),
            });
        }
        let reject = writing && self.reject_write == Some(self.writes.len());
        let endpoint = self
            .endpoints
            .iter()
            .position(|e| e.route.raw() == route && e.port == port);
        let mut upstream = if route == 0 { 0 } else { 1 };
        let data = if space == 1 && offset == 4 {
            let lane = if (route, port) == (2, 1) {
                0
            } else {
                assert_eq!((route, port), (0, 2));
                1
            };
            assert_eq!(count, 1);
            if writing {
                self.credits[lane] = words[3] ^ u32::from(reject);
                vec![]
            } else {
                vec![self.credits[lane]]
            }
        } else if let Some(e) = endpoint.filter(|_| space == 1 && offset >= 0x50) {
            let at = usize::from(offset - 0x50);
            assert!(at + count <= 8);
            upstream = self.endpoints[e].upstream;
            if writing {
                assert_eq!(words[3..].len(), count);
                self.csr[e][at..at + count].copy_from_slice(&words[3..]);
                if reject {
                    if e == 1 && at == 6 {
                        self.hold_handshake = true;
                    } else if at == 0 {
                        self.csr[e][0] ^= ENABLE;
                    } else {
                        self.csr[e][at] ^= 1;
                    }
                }
                if e == 1 && at == 6 {
                    self.handshake_reads = 0;
                }
                vec![]
            } else {
                assert_eq!(kind, PacketType::Read);
                if e == 1 && at == 6 && self.csr[e][6] & CMHS != 0 {
                    self.handshake_reads += 1;
                    if self.handshake_reads >= 2 && !self.hold_handshake {
                        self.csr[e][6] &= !CMHS;
                    }
                }
                if e == 0 && at == 7 {
                    self.dprx_reads += 1;
                    if self.dprx_reads >= 2
                        && !self.hold_dprx
                        && self.csr.iter().all(|c| c[0] & ENABLE == ENABLE)
                    {
                        self.csr[0][7] |= 1 << 31;
                    }
                }
                self.csr[e][at..at + count].to_vec()
            }
        } else {
            let p =
                if space == 0 {
                    self.paths
                        .iter()
                        .enumerate()
                        .find_map(|(p, path)| {
                            path.routes.iter().zip(path.ports).enumerate().find_map(
                                |(i, (r, n))| {
                                    (*r == route && n == port && offset == f_hop(self, p, i))
                                        .then_some(p)
                                },
                            )
                        })
                        .expect("actual reserved DP hop")
                } else {
                    self.paths
                        .iter()
                        .position(|p| {
                            p.routes
                                .iter()
                                .zip(p.ports)
                                .any(|(r, n)| *r == route && n == port)
                        })
                        .expect("actual DP adapter header")
                };
            let result = self.paths[p].respond(domain, model, index);
            if reject {
                let i = self.paths[p]
                    .routes
                    .iter()
                    .zip(self.paths[p].ports)
                    .position(|(r, n)| *r == route && n == port)
                    .unwrap();
                self.paths[p].raw[i][0] ^= 1 << 31;
            }
            return result;
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] = (address & !(63 << 19)) | (u32::from(upstream) << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}
fn f_hop(_: &Peer, path: usize, hop: usize) -> u16 {
    if hop == 0 {
        if path == 0 { 18 } else { 16 }
    } else {
        60 + path as u16 * 2
    }
}
fn step(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    cursor: &mut NativeCursor,
    mut poll: impl FnMut(u64) -> Result<(), Error>,
) -> Result<(), Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize != cursor.tx % 10 {
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(RingDirection::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
    }
    cursor.now += 1;
    poll(cursor.now)
}
fn drive(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    activate: &mut Activate<Model>,
    cursor: &mut NativeCursor,
) -> Box<Active> {
    activate.poll(cursor.now).unwrap();
    let mut result = None;
    for _ in 0..260 {
        step(peer, domain, model, cursor, |now| {
            if let Some(Event::Active(a)) = activate.poll(now)? {
                result = Some(a);
            }
            Ok(())
        })
        .unwrap();
        if let Some(a) = result {
            return a;
        }
    }
    panic!("actual DP activation did not complete")
}
fn drive_stop(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    stop: &mut Stop<Model>,
    cursor: &mut NativeCursor,
) -> Stopped {
    stop.poll(cursor.now).unwrap();
    let mut result = None;
    for _ in 0..180 {
        step(peer, domain, model, cursor, |now| {
            if let Some(StopEvent::Stopped(s)) = stop.poll(now)? {
                result = Some(s);
            }
            Ok(())
        })
        .unwrap();
        if let Some(s) = result {
            return s;
        }
    }
    panic!("actual DP stop did not complete")
}

#[test]
fn actual_dp_cm_caps_video_nfc_aux_paths_dprx_and_normal_stop_keep_original_owner_chain() {
    for credits in [
        Credits::LegacyBonded,
        Credits::RouterAllocated {
            video: 17,
            aux: [3, 4],
        },
    ] {
        for stale in [false, true] {
            let f = fixture(credits, 8640);
            let mut peer = Peer::new(&f, stale);
            let Fixture {
                domain,
                model,
                channel,
                linked,
                owner,
                mut cursor,
                dropped,
            } = f;
            let initial = peer.csr;
            let initial_nfc = peer.credits[0];
            // SAFETY: exact actual modeled CM, GPU association and resource epoch.
            let mut activate =
                unsafe { Activate::new(channel, linked, owner.clone(), cursor.now) }.unwrap();
            let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
            let channel = activate.into_channel();
            assert_eq!(active.local_caps, [initial[0][4], initial[1][4]]);
            assert_eq!(active.remote_caps[1], initial[0][4]);
            assert_eq!(
                active.remote_caps[0] & 0x7f00,
                0x2100,
                "source preference2700x4 precedes5400x2"
            );
            assert_eq!(active.dprx & (1 << 31), 1 << 31);
            assert!(active.endpoints.iter().all(|w| w[0] & ENABLE == ENABLE));
            let nfc = match credits {
                Credits::LegacyBonded => 12,
                Credits::RouterAllocated { video, .. } => u32::from(video),
            };
            assert_eq!(peer.credits[0], initial_nfc + nfc);
            assert_eq!(
                (peer.paths[0].raw[1][0] >> 17) & 127,
                0,
                "video uses NFC, no fabricated FC credits"
            );
            assert_eq!(
                peer.paths[0].raw[1][1] & ((1 << 24) | (1 << 25) | (1 << 26) | (1 << 27)),
                0
            );
            let start = peer.writes.len();
            // SAFETY: modeled display submissions closed; independent payload lifetimes stay retained.
            let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
            let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
            let channel = stop.into_channel();
            assert_eq!(stopped.nfc, initial_nfc);
            assert!(
                stopped
                    .hops
                    .iter()
                    .all(|h| h.raw[0] & (1 << 31) == 0 && h.raw[1] & PENDING == 0)
            );
            assert!(stopped.endpoints.iter().all(|w| w[0] & ENABLE == 0));
            assert_eq!(peer.writes.len() - start, 10);
            assert_eq!(
                (peer.writes[start].route, peer.writes[start].offset),
                (0, 0x53)
            );
            assert_eq!(
                (peer.writes[start + 5].route, peer.writes[start + 5].offset),
                (2, 4),
                "video NFC returns before AUX teardown"
            );
            let reusable = match stopped.into_reusable() {
                Ok(r) => r,
                Err(_) => panic!("real guarded local reuse"),
            };
            // SAFETY: original actual link/reservation returned only after complete local stop.
            let mut again =
                unsafe { Activate::new(channel, reusable.link, reusable.reservation, cursor.now) }
                    .unwrap();
            let active = drive(&mut peer, &domain, &model, &mut again, &mut cursor);
            let mut channel = again.into_channel();
            drop(owner);
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
            // SAFETY: independent synthetic CM holds complete restored/retained ownership through final drain.
            unsafe { active.retire() };
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 1));
            channel_release(&mut channel);
        }
    }
}

fn inject_write_failure(
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
    for _ in 0..3400 {
        if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
            cursor.now += 1;
            poll(cursor.now).unwrap();
            continue;
        }
        let before = peer.writes.len();
        let mut reply = peer.respond(domain, model, cursor.tx % 10);
        let selected = peer.writes.len() != before && peer.writes.len() == target;
        // HPD clear is W1C/self-clearing and may immediately reassert. Its
        // observable negative is a controller rejection, never a fake sticky-bit
        // readback requirement that would discard a genuine new HPD event.
        let hpd = selected
            && peer
                .writes
                .last()
                .is_some_and(|w| w.space == 1 && w.offset == 0x53);
        if selected && (fault == 1 || (fault == 2 && hpd)) {
            reply = controller_error(domain, model, cursor);
        }
        model.finish(RingDirection::Tx, cursor.tx % 10, &[], None);
        cursor.tx += 1;
        cursor.now += 1;
        if selected && fault == 0 {
            cursor.now += 501;
            assert!(poll(cursor.now).is_err());
            return;
        }
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.rx += 1;
        if let Err(e) = poll(cursor.now) {
            assert_eq!(peer.writes.len(), target);
            assert!(selected || fault == 2, "{e:?}");
            return;
        }
    }
    panic!("actual DP write failure did not stop operation")
}

#[test]
fn each_actual_dp_activation_write_handles_ack_loss_controller_rejection_and_observable_readback_or_handshake_timeout()
 {
    for target in 1..=18 {
        for fault in 0..3 {
            let f = fixture(
                Credits::RouterAllocated {
                    video: 17,
                    aux: [3, 4],
                },
                8640,
            );
            let mut peer = Peer::new(&f, true);
            let Fixture {
                domain,
                model,
                channel,
                linked,
                owner,
                mut cursor,
                dropped,
            } = f;
            // SAFETY: same genuine modeled requester/link and protected resource chain.
            let mut activate =
                unsafe { Activate::new(channel, linked, owner.clone(), cursor.now) }.unwrap();
            inject_write_failure(
                &mut peer,
                &domain,
                &model,
                &mut cursor,
                target,
                fault,
                |now| activate.poll(now).map(|e| assert!(e.is_none())),
            );
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(
                activate.poll(cursor.now + 1),
                Err(Error::Poisoned)
            ));
            assert_eq!(writes, model.state.lock().unwrap().writes.len());
            let mut channel = activate.into_channel();
            drop(owner);
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}

#[test]
fn each_actual_dp_stop_write_retains_entire_payload_link_and_accounting_chain_on_uncertainty() {
    for target in 1..=10 {
        for fault in 0..3 {
            let f = fixture(Credits::LegacyBonded, 0);
            let mut peer = Peer::new(&f, false);
            let Fixture {
                domain,
                model,
                channel,
                linked,
                owner,
                mut cursor,
                dropped,
            } = f;
            // SAFETY: exact actual isolated modeled link/GPU association and native reservation.
            let mut activate =
                unsafe { Activate::new(channel, linked, owner.clone(), cursor.now) }.unwrap();
            let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
            let channel = activate.into_channel();
            peer.writes.clear();
            // SAFETY: actual modeled submissions closed; independent payload owners retained.
            let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
            inject_write_failure(
                &mut peer,
                &domain,
                &model,
                &mut cursor,
                target,
                fault,
                |now| stop.poll(now).map(|e| assert!(e.is_none())),
            );
            let mut channel = stop.into_channel();
            drop(owner);
            assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
            channel_release(&mut channel);
        }
    }
}

#[test]
fn unsupported_bandwidth_mode_and_invalid_observed_dp_caps_never_publish_handshake_or_fabricate_caps()
 {
    for fault in 0..3 {
        let f = fixture(Credits::LegacyBonded, 0);
        let mut peer = Peer::new(&f, false);
        peer.csr[0][4] |= match fault {
            0 => BW_MODE,
            1 => 15 << 8,
            2 => 7 << 12,
            _ => unreachable!(),
        };
        let Fixture {
            domain,
            model,
            channel,
            linked,
            owner,
            mut cursor,
            ..
        } = f;
        // SAFETY: same actual model; unsupported observed hardware capabilities are refused.
        let mut activate = unsafe { Activate::new(channel, linked, owner, cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        let mut rejected = false;
        for _ in 0..20 {
            let result = step(&mut peer, &domain, &model, &mut cursor, |now| {
                activate.poll(now).map(|e| assert!(e.is_none()))
            });
            if let Err(e) = result {
                assert_eq!(e, Error::Unsupported);
                rejected = true;
                break;
            }
        }
        assert!(rejected);
        assert!(peer.writes.is_empty());
        let mut channel = activate.into_channel();
        channel_release(&mut channel);
    }
}

#[test]
fn handshake_and_dprx_busy_replies_cannot_extend_fixed_overall_windows() {
    for handshake in [true, false] {
        let f = fixture(Credits::LegacyBonded, 0);
        let mut peer = Peer::new(&f, false);
        peer.hold_handshake = handshake;
        peer.hold_dprx = !handshake;
        let Fixture {
            domain,
            model,
            channel,
            linked,
            owner,
            mut cursor,
            dropped,
        } = f;
        // SAFETY: exact actual modeled link and protected native allocations.
        let mut activate =
            unsafe { Activate::new(channel, linked, owner.clone(), cursor.now) }.unwrap();
        activate.poll(cursor.now).unwrap();
        for _ in 0..160 {
            if if handshake {
                peer.handshake_reads >= 1
            } else {
                peer.dprx_reads >= 1
            } {
                break;
            }
            step(&mut peer, &domain, &model, &mut cursor, |now| {
                activate.poll(now).map(|e| assert!(e.is_none()))
            })
            .unwrap();
        }
        assert!(if handshake {
            peer.handshake_reads >= 1
        } else {
            peer.dprx_reads >= 1
        });
        let start = cursor.now;
        let mut timed_out = false;
        for _ in 0..140 {
            if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize != cursor.tx % 10 {
                let reply = peer.respond(&domain, &model, cursor.tx % 10);
                model.finish(RingDirection::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
            }
            cursor.now += 100;
            if let Err(e) = activate.poll(cursor.now) {
                assert_eq!(e, Error::Timeout);
                timed_out = true;
                break;
            }
        }
        assert!(timed_out);
        let duration = if handshake { HANDSHAKE_MS } else { DPRX_MS };
        assert!((duration - 100..=duration + 100).contains(&(cursor.now - start)));
        let mut channel = activate.into_channel();
        drop(owner);
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
fn nfc_underflow_and_each_pending_video_or_aux_hop_never_authorize_local_reuse() {
    for fault in 0..7 {
        let f = fixture(
            Credits::RouterAllocated {
                video: 17,
                aux: [3, 4],
            },
            0,
        );
        let mut peer = Peer::new(&f, false);
        let Fixture {
            domain,
            model,
            channel,
            linked,
            owner,
            mut cursor,
            dropped,
        } = f;
        // SAFETY: exact actual modeled link and full native ownership chain.
        let mut activate =
            unsafe { Activate::new(channel, linked, owner.clone(), cursor.now) }.unwrap();
        let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
        let channel = activate.into_channel();
        if fault == 6 {
            peer.credits[0] = (peer.credits[0] & !1023) | 8;
        } else {
            peer.paths[fault / 2].raw[fault % 2][1] |= PENDING;
            peer.paths[fault / 2].hold_hop[fault % 2] = true;
        }
        // SAFETY: host submissions closed; every independent payload owner retained.
        let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
        stop.poll(cursor.now).unwrap();
        let mut failed = false;
        for _ in 0..800 {
            if let Err(e) = step(&mut peer, &domain, &model, &mut cursor, |now| {
                stop.poll(now).map(|e| assert!(e.is_none()))
            }) {
                assert!(matches!(e, Error::Timeout | Error::Changed));
                failed = true;
                break;
            }
        }
        assert!(failed);
        let mut channel = stop.into_channel();
        drop(owner);
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
fn actual_dp_grant_rejection_revoked_or_unconsumed_receipts_preserve_exact_owners() {
    for invalid in 0..7 {
        let Fixture {
            domain: _,
            model,
            channel,
            linked,
            mut owner,
            cursor,
            ..
        } = fixture(
            Credits::RouterAllocated {
                video: 17,
                aux: [3, 4],
            },
            0,
        );
        let o = Arc::get_mut(&mut owner).unwrap();
        match invalid {
            0 => o.current.store(false, Ordering::Relaxed),
            1 => o.grant.identity.epoch += 1,
            2 => o.grant.hops[1][0].1 = o.grant.hops[0][0].1,
            3 => o.grant.hops[0][0].0 = 8,
            4 => {
                o.grant.credits = Credits::RouterAllocated {
                    video: 0,
                    aux: [3, 4],
                }
            }
            5 => o.grant.permission = Decision::Denied,
            6 => o.grant.dp_in = 1,
            _ => unreachable!(),
        }
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: intentionally invalid actual model metadata is refused before publication.
        assert!(unsafe { Activate::new(channel, linked, owner, cursor.now) }.is_err());
        assert_eq!(writes, model.state.lock().unwrap().writes.len());
    }
    for stopped in [false, true] {
        let f = fixture(Credits::LegacyBonded, 0);
        let mut peer = Peer::new(&f, false);
        let Fixture {
            domain,
            model,
            channel,
            linked,
            owner,
            mut cursor,
            dropped,
        } = f;
        // SAFETY: exact actual modeled resource and native display association.
        let mut activate =
            unsafe { Activate::new(channel, linked, owner.clone(), cursor.now) }.unwrap();
        let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
        let mut channel = activate.into_channel();
        if stopped {
            // SAFETY: model display submissions are closed and independent owners remain.
            let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
            let result = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
            channel = stop.into_channel();
            owner.current.store(false, Ordering::Relaxed);
            let result = match result.into_reusable() {
                Err((Error::Revoked, s)) => s,
                _ => panic!("actual admission revoked"),
            };
            drop(result);
        } else {
            drop(active);
        }
        drop(owner);
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 0));
        channel_release(&mut channel);
    }
}

#[test]
fn display_capability_budget_preserves_bits_and_never_invents_rate_or_lanes() {
    let input = 0x1500235a;
    let output = 0x060023a5;
    for budget in [
        1296, 2160, 2592, 4320, 5184, 6480, 8640, 12960, 17280, 25920,
    ] {
        let cap = limited_cap(input, output, budget).unwrap();
        assert_eq!(
            cap & !((15 << 8) | (7 << 12)),
            output & !((15 << 8) | (7 << 12))
        );
        assert!(rate(cap).unwrap() <= rate(input).unwrap());
        assert!(lanes(cap).unwrap() <= lanes(input).unwrap());
        assert!(rate(cap).unwrap() * lanes(cap).unwrap() * 8 / 10 <= budget);
    }
    assert!(limited_cap(input, output, 1295).is_err());
    assert!(limited_cap(input | (15 << 8), output, 25920).is_err());
    assert!(limited_cap(input, output | (7 << 12), 25920).is_err());
}

#[test]
#[ignore = "requires pinned unchanged Linux DP activation/stop transcript"]
fn unchanged_linux_dp_complete_write_transcript_matches_actual_native_dma() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_THUNDERBOLT_DP_ORACLE").expect("set DP trace"),
    )
    .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let n = |i: usize| fields[i].parse::<u32>().unwrap();
        assert_eq!(fields[0], "D");
        let credits = if n(1) == 0 {
            Credits::LegacyBonded
        } else {
            Credits::RouterAllocated {
                video: 17,
                aux: [3, 4],
            }
        };
        let f = fixture(credits, n(4));
        let mut peer = Peer::new(&f, n(2) != 0);
        for e in 0..2 {
            peer.csr[e][0] = n(5 + e * 2);
            peer.csr[e][1] = n(6 + e * 2);
            peer.csr[e][4] = n(9 + e);
        }
        for p in 0..3 {
            for h in 0..2 {
                peer.paths[p].raw[h] = [n(11 + p * 4 + h * 2), n(12 + p * 4 + h * 2)];
            }
        }
        let Fixture {
            domain,
            model,
            channel,
            linked,
            owner,
            mut cursor,
            dropped,
        } = f;
        // SAFETY: actual isolated modeled link, GPU association and source grants.
        let mut activate =
            unsafe { Activate::new(channel, linked, owner.clone(), cursor.now) }.unwrap();
        let active = drive(&mut peer, &domain, &model, &mut activate, &mut cursor);
        let channel = activate.into_channel();
        // SAFETY: actual model submissions closed and all independent owners held.
        let mut stop = unsafe { Stop::new(channel, active, cursor.now) }.unwrap();
        let stopped = drive_stop(&mut peer, &domain, &model, &mut stop, &mut cursor);
        let mut channel = stop.into_channel();
        assert_eq!(peer.writes.len(), n(23) as usize, "case {}", cases);
        let mut at = 24;
        for (i, actual) in peer.writes.iter().enumerate() {
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
                ),
                "case {} write {}",
                cases,
                i
            );
            at += 5;
            for word in &actual.data {
                assert_eq!(*word, n(at), "case {} write {} word {}", cases, i, at);
                at += 1;
            }
        }
        let footer = [
            peer.csr[0][5],
            peer.csr[1][5],
            stopped.endpoints[0][0],
            stopped.endpoints[0][1],
            stopped.endpoints[1][0],
            stopped.endpoints[1][1],
            stopped.nfc,
            peer.csr[0][7],
        ];
        for word in footer {
            assert_eq!(word, n(at), "case {} footer {}", cases, at);
            at += 1;
        }
        for words in stopped.hops {
            assert_eq!(words.raw, [n(at), n(at + 1)]);
            at += 2;
        }
        assert_eq!(at, fields.len());
        let reusable = match stopped.into_reusable() {
            Ok(r) => r,
            Err(_) => panic!("actual guarded local reuse"),
        };
        drop(owner);
        // SAFETY: independent synthetic CM retains this fully stopped original link.
        unsafe { reusable.link.retire() };
        drop(reusable.reservation);
        assert!(dropped.iter().all(|n| n.load(Ordering::Relaxed) == 1));
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 128);
}
