extern crate std;
use super::*;

use crate::bus::thunderbolt::ring::{Direction, TX_DESCRIPTOR, model::*};

#[test]
fn adapter_bounds_credit_clamp_and_owned_bit_preservation() {
    let target = Target {
        route: Route::new(0).unwrap(),
        port: 1,
        kind: AdapterKind::Lane,
        usb4: true,
        phy_capability: Some(8),
        usb4_capability: Some(0x30),
    };
    assert_eq!(
        target.address(Operation::LaneEnabled(true)).unwrap().offset,
        9
    );
    assert_eq!(
        target
            .address(Operation::Usb4Configured(true))
            .unwrap()
            .offset,
        0x43
    );
    assert_eq!(target.address(Operation::NfcCredits(1)).unwrap().offset, 4);
    let mut invalid = target;
    invalid.usb4_capability = Some(8191);
    assert_eq!(
        invalid.address(Operation::Usb4Configured(true)),
        Err(Error::Capability)
    );
    invalid = target;
    invalid.kind = AdapterKind::PcieUp;
    assert_eq!(
        invalid.address(Operation::NfcCredits(1)),
        Err(Error::Unsupported)
    );
    for before in [0, 0xffffffff, 0x12345678, 0xdeadbeef] {
        for operation in [
            Operation::LaneEnabled(true),
            Operation::LaneEnabled(false),
            Operation::Usb4Configured(true),
            Operation::Usb4Configured(false),
        ] {
            let (after, mask) = change(operation, before).unwrap();
            assert_eq!(before & !mask, after & !mask);
        }
    }
    let before = (100 << 20) | 0x40000 | 10;
    assert_eq!(
        change(Operation::NfcCredits(-100), before).unwrap().0,
        before & !NFC_MASK
    );
    assert_eq!(
        change(Operation::NfcCredits(90), before).unwrap().0,
        (before & !NFC_MASK) | 100
    );
    assert_eq!(
        change(Operation::NfcCredits(91), before),
        Err(Error::CreditsUnavailable)
    );
    assert_eq!(
        change(Operation::NfcCredits(i16::MAX), before),
        Err(Error::CreditsOverflow)
    );
    assert_eq!(
        change(Operation::NfcCredits(1), 0),
        Err(Error::CreditsUnavailable)
    );
}
#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_ADAPTER_ORACLE"]
fn unchanged_linux_adapter_controls_and_nfc_register_effects_match() {
    extern crate std;
    use std::{env, fs};
    let trace = fs::read_to_string(
        env::var("STELA_THUNDERBOLT_ADAPTER_ORACLE").expect("set adapter trace"),
    )
    .unwrap();
    let target = Target {
        route: Route::new(0).unwrap(),
        port: 1,
        kind: AdapterKind::Lane,
        usb4: true,
        phy_capability: Some(8),
        usb4_capability: Some(0x30),
    };
    let mut count = 0;
    for line in trace.lines() {
        let f: alloc::vec::Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(f[0], "A");
        let n = |i: usize| f[i].parse::<u32>().unwrap();
        let operation = match n(1) {
            0 => Operation::LaneEnabled(false),
            1 => Operation::LaneEnabled(true),
            2 => Operation::Usb4Configured(false),
            3 => Operation::Usb4Configured(true),
            _ => Operation::NfcCredits(f[2].parse().unwrap()),
        };
        let (after, _) = change(operation, n(3)).unwrap();
        assert_eq!(after, n(4));
        let writes = if operation == Operation::NfcCredits(0) {
            0
        } else {
            1
        };
        assert_eq!(writes, n(5));
        if writes != 0 {
            assert_eq!(u32::from(target.address(operation).unwrap().offset), n(6));
            assert_eq!(after, n(7));
        }
        count += 1;
    }
    assert_eq!(count, 7168);
}

#[test]
fn adapter_lane_configured_and_credit_changes_use_actual_dma_ack_and_readback() {
    use super::super::adapter::{Control, Event, Operation};
    let before = 0x86454007;
    for (operation, offset, after) in [
        (Operation::LaneEnabled(true), 9, before & !(1 << 14)),
        (Operation::LaneEnabled(false), 9, before | (1 << 14)),
        (Operation::Usb4Configured(true), 0x43, before | (1 << 3)),
        (Operation::Usb4Configured(false), 0x43, before & !(1 << 3)),
        (Operation::NfcCredits(8), 4, (before & !0x3ff) | 15),
        (Operation::NfcCredits(-100), 4, before & !0x3ff),
    ] {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let (owner, dropped) = adapter_owner(operation);
        // SAFETY: same synthetic requester, reset epoch, real adapter
        // metadata and exclusive credit/link reservation; channel is idle.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        assert!(control.poll(0).unwrap().is_none());
        let mut applied = None;
        for index in 0..3 {
            if index == 1 {
                let frame = domain.data(model.frame_address(Direction::Tx, index), 20);
                assert_eq!(u32::from_be_bytes(frame[12..16].try_into().unwrap()), after);
            }
            let data = match index {
                0 => vec![before],
                1 => vec![],
                _ => vec![after],
            };
            let reply = adapter_response(&domain, &model, index, offset, &data);
            model.finish(Direction::Tx, index, &[], None);
            finish_rx(&model, index, &reply);
            let event = control.poll(index as u64 + 1).unwrap();
            if index < 2 {
                assert!(event.is_none());
            } else {
                let Some(Event::Applied(value)) = event else {
                    panic!("actual applied receipt")
                };
                applied = Some(value);
            }
        }
        let applied = applied.unwrap();
        assert_eq!(applied.before, before);
        assert_eq!(applied.after, after);
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        // SAFETY: the fixture transfers its active reservation into
        // an independent synthetic CM lifetime through final modeled drain.
        unsafe { applied.retire() };
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
}

#[test]
fn adapter_failed_readback_and_lost_write_ack_retain_exact_active_reservation() {
    use super::super::adapter::{Control, Error, Operation};
    for lost_ack in [false, true] {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let (owner, dropped) = adapter_owner(Operation::NfcCredits(8));
        // SAFETY: same synthetic adapter/requester/reset and owned
        // positive allocation, with no independent firmware or link writer.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        control.poll(0).unwrap();
        let reply = adapter_response(&domain, &model, 0, 4, &[(100 << 20) | 7]);
        model.finish(Direction::Tx, 0, &[], None);
        finish_rx(&model, 0, &reply);
        control.poll(1).unwrap();
        if lost_ack {
            assert!(matches!(control.poll(500), Err(Error::Timeout)));
        } else {
            for index in 1..3 {
                let data = if index == 1 {
                    vec![]
                } else {
                    vec![(100 << 20) | 7]
                };
                let reply = adapter_response(&domain, &model, index, 4, &data);
                model.finish(Direction::Tx, index, &[], None);
                finish_rx(&model, index, &reply);
                let result = control.poll(index as u64 + 1);
                if index == 1 {
                    assert!(result.unwrap().is_none());
                } else {
                    assert!(matches!(result, Err(Error::Readback)));
                }
            }
        }
        let writes = model.state.lock().unwrap().writes.len();
        assert!(matches!(control.poll(501), Err(Error::Poisoned)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}

#[test]
fn adapter_unconsumed_applied_receipt_quarantines_active_credits() {
    use super::super::adapter::{Control, Event, Operation};
    let (_source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let (owner, dropped) = adapter_owner(Operation::NfcCredits(1));
    // SAFETY: same synthetic requester/epoch and allocation.
    let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
    control.poll(0).unwrap();
    for index in 0..3 {
        let data = match index {
            0 => vec![(100 << 20) | 7],
            1 => vec![],
            _ => vec![(100 << 20) | 8],
        };
        let reply = adapter_response(&domain, &model, index, 4, &data);
        model.finish(Direction::Tx, index, &[], None);
        finish_rx(&model, index, &reply);
        let event = control.poll(index as u64 + 1).unwrap();
        if index == 2 {
            assert!(matches!(event, Some(Event::Applied(_))));
            drop(event);
        }
    }
    let mut channel = control.into_channel();
    drop(owner);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    channel_release(&mut channel);
}

#[test]
fn adapter_zero_credit_and_capacity_rejection_never_write_adapter() {
    use super::super::adapter::{Control, Error, Event, Operation};
    for delta in [0, 100] {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let (owner, dropped) = adapter_owner(Operation::NfcCredits(delta));
        // SAFETY: same synthetic requester/epoch; invalid allocation
        // is rejected against hardware capacity before any write.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        control.poll(0).unwrap();
        let reply = adapter_response(&domain, &model, 0, 4, &[(10 << 20) | 7]);
        model.finish(Direction::Tx, 0, &[], None);
        finish_rx(&model, 0, &reply);
        let result = control.poll(1);
        if delta == 0 {
            let Some(Event::Applied(applied)) = result.unwrap() else {
                panic!("unchanged observation")
            };
            assert_eq!(applied.before, applied.after);
            drop(applied);
        } else {
            assert!(matches!(result, Err(Error::CreditsUnavailable)));
        }
        assert_eq!(
            model.read32(TX_DESCRIPTOR + 8) >> 16,
            1,
            "only the initial read was sent"
        );
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
}

#[test]
fn adapter_fixed_deadline_contains_write_publication_backpressure() {
    use super::super::{
        adapter::{Control, Error, Operation},
        config::{Address, Route, Space},
    };
    let (_source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    // Fill eight TX descriptors; firmware replies while hardware's
    // TX consumer is stuck. The next read fills the last available slot.
    let address = Address {
        port: 1,
        space: Space::Port,
        offset: 4,
        words: 1,
    };
    for index in 0..8 {
        channel
            .read(Route::new(0).unwrap(), address, 0, 1000)
            .unwrap();
        let reply = adapter_response(&domain, &model, index, 4, &[(100 << 20) | 7]);
        finish_rx(&model, index, &reply);
        assert!(matches!(
            channel.poll(0),
            Ok(Some(super::super::channel::Event::Completed { .. }))
        ));
    }
    let (owner, dropped) = adapter_owner(Operation::NfcCredits(1));
    // SAFETY: same synthetic requester/epoch and positive allocation;
    // channel is idle even though its completed TX DMA has not drained.
    let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
    control.poll(0).unwrap();
    let reply = adapter_response(&domain, &model, 8, 4, &[(100 << 20) | 7]);
    finish_rx(&model, 8, &reply);
    assert!(control.poll(1).unwrap().is_none());
    let writes = model.state.lock().unwrap().writes.len();
    for now in [2, 100, 499] {
        assert!(control.poll(now).unwrap().is_none());
    }
    assert!(matches!(control.poll(500), Err(Error::Timeout)));
    assert!(matches!(control.poll(501), Err(Error::Poisoned)));
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    let mut channel = control.into_channel();
    drop(owner);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        1,
        "no adapter write was published"
    );
    channel_release(&mut channel);
}

#[test]
fn adapter_regressed_clock_and_changed_credit_capacity_never_claim_applied() {
    use super::super::adapter::{Control, Error, Operation};
    let (_source, _domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let (owner, dropped) = adapter_owner(Operation::LaneEnabled(true));
    // SAFETY: same exact idle synthetic requester/epoch.
    let mut control = unsafe { Control::new(channel, owner.clone(), 100) }.unwrap();
    let writes = model.state.lock().unwrap().writes.len();
    assert!(matches!(control.poll(99), Err(Error::ClockRegressed)));
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    let mut channel = control.into_channel();
    drop(owner);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    channel_release(&mut channel);
    let (_source, domain, model, mut channel) = self::channel();
    channel.start(0).unwrap();
    let (owner, dropped) = adapter_owner(Operation::NfcCredits(8));
    // SAFETY: same synthetic requester/epoch and reserved allocation.
    let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
    control.poll(0).unwrap();
    for index in 0..3 {
        let data = match index {
            0 => vec![(100 << 20) | 7],
            1 => vec![],
            _ => vec![(10 << 20) | 15],
        };
        let reply = adapter_response(&domain, &model, index, 4, &data);
        model.finish(Direction::Tx, index, &[], None);
        finish_rx(&model, index, &reply);
        let result = control.poll(index as u64 + 1);
        if index < 2 {
            assert!(result.unwrap().is_none());
        } else {
            assert!(matches!(result, Err(Error::Readback)));
        }
    }
    let mut channel = control.into_channel();
    drop(owner);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    channel_release(&mut channel);
}
