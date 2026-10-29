extern crate std;
use super::*;

use crate::bus::thunderbolt::config::PacketType;
use crate::bus::thunderbolt::ring::{Direction, model::*};

#[test]
fn router_setup_dma_root_child_policy_modes_and_hotplug_complete() {
    use super::super::router::Setup;
    for route in [0, 1, 0x201] {
        for mask in [0, 15, 47, 127] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let owner = Arc::new(router_owner(route, 2, mask));
            let dropped = owner.dropped.clone();
            let mut peer = RouterPeer::new(owner.clone(), mask);
            // SAFETY: this model requester/domain/IMR/reset epoch owns
            // unchanged inventories and resolved native model policy.
            let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
            let configured = drive_router(&mut peer, &domain, &model, &mut setup);
            assert_eq!(configured.header.reported_route(), route);
            assert!(configured.header.enabled());
            assert_eq!(configured.header.raw[4] & 0xffff, 0x20ff);
            assert_eq!(configured.hotplug.len(), 2);
            assert_eq!(
                configured.link_usb4,
                if route == 0 {
                    None
                } else {
                    Some(mask & 64 != 0 && mask & 16 == 0)
                }
            );
            if route != 0 {
                assert_ne!(configured.ready_status.unwrap() & (1 << 24), 0);
                assert_ne!(configured.configured_status.unwrap() & (1 << 25), 0);
                assert_ne!(peer.regs[5] & (1 << 31), 0);
            }
            let mut channel = setup.into_channel();
            drop(peer);
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            // SAFETY: synthetic configured state is transferred into an
            // independently kept model CM lifetime through final drain.
            unsafe { configured.retire() };
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
            channel_release(&mut channel);
        }
    }
}

#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_ROUTER_ORACLE"]
fn unchanged_linux_router_full_write_trace_matches_dma_engine() {
    use super::super::router::Setup;
    use std::{env, fs};
    let trace =
        fs::read_to_string(env::var("STELA_THUNDERBOLT_ROUTER_ORACLE").expect("set router trace"))
            .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let f: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(f[0], "R");
        let n = |i: usize| f[i].parse::<u64>().unwrap();
        let route = n(1);
        let version = n(2) as u8;
        let mask = n(3) as u32;
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let owner = Arc::new(router_owner(route, version, mask));
        assert_eq!(
            owner.target.header.raw,
            (4..9).map(|i| n(i) as u32).collect::<Vec<_>>().as_slice()
        );
        let mut peer = RouterPeer::new(owner.clone(), mask);
        assert_eq!(peer.regs[5], n(9) as u32);
        assert_eq!(peer.regs[6], n(10) as u32);
        assert_eq!(peer.hotplug, [n(11) as u32, n(12) as u32]);
        // SAFETY: exact isolated model requester/epoch with kept
        // parent relationship and source-case resolved native model policy.
        let mut setup = unsafe { Setup::new(channel, owner, 0) }.unwrap();
        let configured = drive_router(&mut peer, &domain, &model, &mut setup);
        let count = n(13) as usize;
        let mut at = 14;
        let mut writes = vec![];
        for _ in 0..count {
            let (port, space, offset, len) = (
                n(at) as u8,
                n(at + 1) as u8,
                n(at + 2) as u16,
                n(at + 3) as usize,
            );
            at += 4;
            let data = (at..at + len).map(|i| n(i) as u32).collect();
            at += len;
            writes.push(RouterWrite {
                port,
                space,
                offset,
                data,
            });
        }
        assert_eq!(at, f.len());
        assert_eq!(
            peer.writes, writes,
            "source route={route:x} version={version} mask={mask}"
        );
        let mut channel = setup.into_channel();
        // SAFETY: independent model CM keeps this configured lease
        // through complete synthetic teardown.
        unsafe { configured.retire() };
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 768);
}

#[test]
fn router_unresolved_policy_identity_and_parent_metadata_refuse_before_publication() {
    use super::super::{
        config::Route,
        router::{Decision, Setup},
        topology::{AdapterObservation, Path},
    };
    for case in 0..12 {
        let (_source, _domain, model, channel) = channel();
        let mut owner = router_owner(1, 2, 79);
        match case {
            0 => owner.policy.pcie = Decision::Unresolved,
            1 => owner.epoch = 0,
            2 => owner.parent = None,
            3 => owner.parent.as_mut().unwrap().path = Path::new(Route::new(2).unwrap()).unwrap(),
            4 => owner.parent.as_mut().unwrap().header.raw[3] &= !(1 << 31),
            5 => {
                owner.parent.as_mut().unwrap().adapters[0] = router_adapter(1, 0x200101, Some(0x30))
            }
            6 => owner.target.upstream_port = 2,
            7 => owner.target.header.raw[4] &= !(7 << 29),
            8 => {
                if let AdapterObservation::Present { capabilities, .. } =
                    &mut owner.parent.as_mut().unwrap().adapters[0]
                {
                    capabilities[0].offset = 8191;
                }
            }
            9 => {
                if let AdapterObservation::Present { capabilities, .. } =
                    &mut owner.target.adapters[0]
                {
                    capabilities.push(capabilities[0].clone());
                }
            }
            10 => owner.target.adapters[1] = router_adapter(2, 0x123456, Some(0x30)),
            11 => {}
            _ => unreachable!(),
        }
        let dropped = owner.dropped.clone();
        assert!(
            // SAFETY: this synthetic requester/epoch represents negative
            // metadata/prerequisites. No permission or write is invented.
            unsafe {
                Setup::new(
                    channel,
                    Arc::new(owner),
                    if case == 11 { u64::MAX } else { 0 },
                )
            }
            .is_err()
        );
        assert!(model.state.lock().unwrap().writes.is_empty());
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn router_policy_conflicts_changed_identity_and_upstream_never_enumerate() {
    use super::super::router::{Error, Setup};
    for (mask, conflict, identity, upstream) in [
        (0, 1 << 25, false, false),
        (0, 1 << 24, false, false),
        (0, 1 << 26, false, false),
        (95, 1 << 25, false, false),
        (79, 0, true, false),
        (79, 0, false, true),
    ] {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let owner = Arc::new(router_owner(1, 2, mask));
        let dropped = owner.dropped.clone();
        let mut peer = RouterPeer::new(owner.clone(), mask);
        peer.regs[5] |= conflict;
        if identity {
            peer.regs[0] ^= 1 << 16;
        }
        if upstream {
            peer.override_upstream = Some(0);
        }
        // SAFETY: same negative synthetic ownership/inventory epoch.
        let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
        setup.poll(0).unwrap();
        let mut failed = false;
        for n in 0..10 {
            let reply = peer.respond(&domain, &model, n);
            model.finish(Direction::Tx, n, &[], None);
            finish_rx(&model, n, &reply);
            match setup.poll(n as u64 + 1) {
                Err(Error::PolicyConflict(_)) if conflict != 0 => {
                    failed = true;
                    break;
                }
                Err(Error::ChangedInventory) if identity || upstream => {
                    failed = true;
                    break;
                }
                Ok(None) => {}
                _ => panic!("unexpected policy/identity result"),
            }
        }
        assert!(failed);
        assert!(
            peer.writes.is_empty(),
            "no enumeration before actual policy preflight"
        );
        let mut channel = setup.into_channel();
        drop(peer);
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
}

#[test]
fn router_ready_and_configured_deadlines_start_at_write_ack_and_never_extend() {
    use super::super::router::{Error, Setup};
    for configured_wait in [false, true] {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let owner = Arc::new(router_owner(1, 2, 79));
        let dropped = owner.dropped.clone();
        let mut peer = RouterPeer::new(owner.clone(), 79);
        peer.hold_ready = !configured_wait;
        peer.hold_configured = configured_wait;
        // SAFETY: same isolated synthetic native reservation.
        let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
        setup.poll(0).unwrap();
        let mut ack = None;
        for n in 0..40 {
            let index = n % 10;
            let previous = peer.writes.len();
            let reply = peer.respond(&domain, &model, index);
            let reached = peer.writes.len() > previous
                && peer.writes.last().is_some_and(|write| {
                    write.space == 2
                        && write.offset == 5
                        && ((write.data[0] & (1 << 31) != 0) == configured_wait)
                });
            model.finish(Direction::Tx, index, &[], None);
            finish_rx(&model, index, &reply);
            assert!(setup.poll(n as u64 + 1).unwrap().is_none());
            if reached {
                ack = Some((n as u64 + 1, (index + 1) % 10));
                break;
            }
        }
        let (ack, index) = ack.expect("actual setup/configuration-valid write ACK");
        let reply = peer.respond(&domain, &model, index);
        model.finish(Direction::Tx, index, &[], None);
        finish_rx(&model, index, &reply);
        // Readback consumes nearly the whole window; entering wait must not
        // synthesize another now+500 deadline, even with no active request.
        assert!(setup.poll(ack + 499).unwrap().is_none());
        let writes = model.state.lock().unwrap().writes.len();
        assert!(matches!(setup.poll(ack + 500), Err(Error::Timeout)));
        assert!(matches!(setup.poll(ack + 501), Err(Error::Poisoned)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = setup.into_channel();
        drop(peer);
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}

#[test]
fn router_lost_ack_rejected_enumeration_and_unconsumed_receipt_keep_owner() {
    use super::super::router::{Error, Setup};
    for mode in 0..3 {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let owner = Arc::new(router_owner(1, 2, 79));
        let dropped = owner.dropped.clone();
        let mut peer = RouterPeer::new(owner.clone(), 79);
        peer.reject_header = mode == 1;
        // SAFETY: same synthetic requester/epoch; published mutations
        // remain owned through ACK loss, rejected readback or receipt drop.
        let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
        if mode == 2 {
            let configured = drive_router(&mut peer, &domain, &model, &mut setup);
            drop(configured);
        } else {
            setup.poll(0).unwrap();
            let mut failed = false;
            for n in 0..20 {
                let index = n % 10;
                let previous = peer.writes.len();
                let reply = peer.respond(&domain, &model, index);
                if mode == 0 && peer.writes.len() > previous {
                    assert!(matches!(setup.poll(n as u64 + 501), Err(Error::Timeout)));
                    failed = true;
                    break;
                }
                model.finish(Direction::Tx, index, &[], None);
                finish_rx(&model, index, &reply);
                match setup.poll(n as u64 + 1) {
                    Err(Error::Readback) if mode == 1 => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {}
                    _ => panic!("unexpected enumeration fault result"),
                }
            }
            assert!(failed);
        }
        let mut channel = setup.into_channel();
        drop(peer);
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}

#[test]
fn router_full_tx_stage_deadline_clock_and_hotplug_cancel_are_explicit() {
    use super::super::{
        channel::Event,
        config::{Address, Route, Space},
        router::{Error, Setup},
    };
    let (_source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    for index in 0..9 {
        channel
            .read(
                Route::new(0).unwrap(),
                Address {
                    port: 1,
                    space: Space::Port,
                    offset: 4,
                    words: 1,
                },
                0,
                1000,
            )
            .unwrap();
        finish_rx(
            &model,
            index,
            &adapter_response(&domain, &model, index, 4, &[0]),
        );
        assert!(matches!(channel.poll(0), Ok(Some(Event::Completed { .. }))));
    }
    let owner = Arc::new(router_owner(0, 1, 0));
    // SAFETY: same synthetic owner, idle request engine; old completed
    // TX DMA is stalled and the real publication ring is physically full.
    let mut setup = unsafe { Setup::new(channel, owner, 0) }.unwrap();
    let writes = model.state.lock().unwrap().writes.len();
    for now in [0, 1, 499] {
        assert!(setup.poll(now).unwrap().is_none());
    }
    assert!(matches!(setup.poll(500), Err(Error::Timeout)));
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    let mut channel = setup.into_channel();
    channel_release(&mut channel);
    let (_source, _domain, model, mut channel) = self::channel();
    channel.start(0).unwrap();
    let owner = Arc::new(router_owner(0, 1, 0));
    // SAFETY: same idle synthetic requester/reset/native reservation.
    let mut setup = unsafe { Setup::new(channel, owner, 100) }.unwrap();
    let writes = model.state.lock().unwrap().writes.len();
    assert!(matches!(setup.poll(99), Err(Error::ClockRegressed)));
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    let mut channel = setup.into_channel();
    channel_release(&mut channel);
    for cancel in [false, true] {
        let (_source, domain, model, mut channel) = self::channel();
        channel.start(0).unwrap();
        let owner = Arc::new(router_owner(0, 1, 0));
        let dropped = owner.dropped.clone();
        let mut peer = RouterPeer::new(owner.clone(), 0);
        // SAFETY: same synthetic requester/epoch and native policy.
        let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
        setup.poll(0).unwrap();
        let reply = peer.respond(&domain, &model, 0);
        model.finish(Direction::Tx, 0, &[], None);
        finish_rx(&model, 0, &reply);
        setup.poll(1).unwrap();
        if cancel {
            assert!(matches!(setup.cancel(), Err(Error::Cancelled)));
        } else {
            finish_rx(&model, 1, &incoming(PacketType::Event, &[0, 0, 1]));
            assert!(matches!(setup.poll(2), Err(Error::Hotplug(_))));
        }
        assert!(matches!(setup.poll(3), Err(Error::Poisoned)));
        let mut channel = setup.into_channel();
        drop(peer);
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}

#[test]
fn router_parent_mode_read_error_never_becomes_a_guessed_tbt_link() {
    use super::super::router::{Error, Setup};
    let (_source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let owner = Arc::new(router_owner(1, 2, 79));
    let dropped = owner.dropped.clone();
    let mut peer = RouterPeer::new(owner.clone(), 79);
    // SAFETY: same synthetic requester/epoch and reviewed parent
    // capability; failed hardware access cannot invent fallback ownership.
    let mut setup = unsafe { Setup::new(channel, owner.clone(), 0) }.unwrap();
    setup.poll(0).unwrap();
    for n in 0..3 {
        let reply = if n < 2 {
            peer.respond(&domain, &model, n)
        } else {
            let sent = domain.data(model.frame_address(Direction::Tx, n), 16);
            assert_eq!(&sent[..8], &[0; 8]);
            let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
            assert_eq!(address & 0x1fff, 0x42);
            assert_eq!((address >> 25) & 3, 1);
            incoming(PacketType::Error, &[1 << 31, 0, 2])
        };
        model.finish(Direction::Tx, n, &[], None);
        finish_rx(&model, n, &reply);
        let result = setup.poll(n as u64 + 1);
        if n < 2 {
            assert!(result.unwrap().is_none());
        } else {
            assert!(matches!(result, Err(Error::Controller { code: 2, .. })));
        }
    }
    assert!(peer.writes.is_empty());
    let mut channel = setup.into_channel();
    drop(peer);
    drop(owner);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    channel_release(&mut channel);
}
