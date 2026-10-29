// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! Software-CM adapter control from Linux switch.c/usb4.c.
//!
//! One owned register operation, not a link-pair or tunnel allocator. An
//! applied change keeps its reservation until explicit retirement.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    ring::{self, Registers},
    topology::{AdapterKind, Path},
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
const NFC_MASK: u32 = 0x3ff;
const LANE_DISABLED: u32 = 1 << 14;
const PORT_CONFIGURED: u32 = 1 << 3;
const TIMEOUT_MS: u64 = 500;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_reservations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub route: Route,
    pub port: u8,
    pub kind: AdapterKind,
    pub usb4: bool,
    pub phy_capability: Option<u16>,
    pub usb4_capability: Option<u16>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    LaneEnabled(bool),
    Usb4Configured(bool),
    NfcCredits(i16),
}
impl Target {
    fn address(self, operation: Operation) -> Result<Address, Error> {
        if self.port == 0
            || self.port >= 64
            || Path::new(self.route).is_err()
            || matches!(self.kind, AdapterKind::Inactive | AdapterKind::Unknown(_))
        {
            return Err(Error::Target);
        }
        let offset = match operation {
            Operation::LaneEnabled(_) => {
                if self.kind != AdapterKind::Lane {
                    return Err(Error::Unsupported);
                }
                self.phy_capability
                    .filter(|cap| *cap >= 8)
                    .and_then(|cap| cap.checked_add(1))
                    .ok_or(Error::Capability)?
            }
            Operation::Usb4Configured(_) => {
                if !self.usb4 || self.kind != AdapterKind::Lane {
                    return Err(Error::Unsupported);
                }
                self.usb4_capability
                    .filter(|cap| *cap >= 8)
                    .and_then(|cap| cap.checked_add(0x13))
                    .ok_or(Error::Capability)?
            }
            Operation::NfcCredits(_) => {
                if self.usb4 && self.kind != AdapterKind::Lane {
                    return Err(Error::Unsupported);
                }
                4
            }
        };
        if offset >= 8192 {
            return Err(Error::Capability);
        }
        Ok(Address {
            port: self.port,
            space: Space::Port,
            offset,
            words: 1,
        })
    }
}
/// Exact exclusive software-CM operation and active resource reservation.
///
/// # Safety
/// Metadata is from real unchanged router/adapter inventory in one live NHI
/// ownership/reset epoch. Firmware ICM and other actors cannot write this
/// adapter. The owner keeps router/power lifetime and the allocation
/// for the requested operation; positive NFC credits are reserved against all
/// other path/flow-control uses, not against the register's total.
/// Lane/configuration changes have link/topology and dependent-path
/// serialization. No endpoint DMA/IOMMU lifetime ends on this local receipt.
/// The owner may be dropped only after an unmutated operation, final restoration
/// or transfer of the active reservation. Quarantine keeps it forever.
pub unsafe trait Owner: Send + Sync {
    fn target(&self) -> Target;
    fn operation(&self) -> Operation;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Target,
    Unsupported,
    Capability,
    CreditsOverflow,
    CreditsUnavailable,
    ClockOverflow,
    ClockRegressed,
    Timeout,
    Poisoned,
    Stopped,
    UnexpectedReceipt,
    Readback,
    Controller {
        route: Route,
        port: u8,
        code: u8,
        raw: u32,
    },
    Hotplug(config::PlugEvent),
    Notification(config::NotificationError),
    Channel(channel::Error),
}
impl From<channel::Error> for Error {
    fn from(error: channel::Error) -> Self {
        Self::Channel(error)
    }
}
fn change(operation: Operation, before: u32) -> Result<(u32, u32), Error> {
    match operation {
        Operation::LaneEnabled(enable) => Ok((
            if enable {
                before & !LANE_DISABLED
            } else {
                before | LANE_DISABLED
            },
            LANE_DISABLED,
        )),
        Operation::Usb4Configured(configured) => Ok((
            if configured {
                before | PORT_CONFIGURED
            } else {
                before & !PORT_CONFIGURED
            },
            PORT_CONFIGURED,
        )),
        Operation::NfcCredits(delta) => {
            let current = (before & NFC_MASK) as i32;
            let next = (current + i32::from(delta)).max(0);
            if next > NFC_MASK as i32 {
                return Err(Error::CreditsOverflow);
            }
            // The donor's allocator supplies legal positive deltas. Also check
            // the observed capacity here; never spill into adjacent bits.
            let total = (before >> 20) & NFC_MASK;
            if delta > 0 && next > total as i32 {
                return Err(Error::CreditsUnavailable);
            }
            Ok(((before & !NFC_MASK) | (next as u32), NFC_MASK))
        }
    }
}
fn quarantine(owner: &Arc<dyn Owner>) {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
    core::mem::forget(owner.clone());
}
/// Read/write-ACK/readback result with its active reservation.
/// Drop quarantines a changed reservation; it never releases active credits or
/// router power because a local write completed.
pub struct Applied {
    pub target: Target,
    pub operation: Operation,
    pub before: u32,
    pub after: u32,
    owner: Option<Arc<dyn Owner>>,
    changed: bool,
}
impl Applied {
    /// # Safety
    /// The changed hardware state has been restored/reset with every
    /// dependent path/DMA/IRQ requirement satisfied, or the same active
    /// reservation has already been transferred to an independently kept
    /// native CM owner. This is not an endpoint or IOMMU drain primitive.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::adapter::Applied;
    /// fn release(applied: Applied) { applied.retire(); }
    /// ```
    pub unsafe fn retire(mut self) {
        self.owner.take();
    }
}
impl Drop for Applied {
    fn drop(&mut self) {
        if self.changed
            && let Some(owner) = &self.owner
        {
            quarantine(owner);
        }
    }
}
pub enum Event {
    Applied(Applied),
    Discarded(config::Error),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Read,
    Write(u32, u32),
    Verify(u32, u32),
    Done,
    Fault,
}
pub struct Control<R: Registers> {
    channel: Option<Channel<R>>,
    owner: Option<Arc<dyn Owner>>,
    target: Target,
    operation: Operation,
    address: Address,
    stage: Stage,
    expected: Option<u64>,
    deadline: u64,
    before: Option<u32>,
    published: bool,
    last_now: u64,
}
impl<R: Registers> Control<R> {
    /// # Safety
    /// Channel and Owner belong to the same physical NHI requester and
    /// unchanged ownership/reset epoch. The target/capabilities/allocation are
    /// current for that channel and have not been recycled. The software-CM
    /// channel is exclusively idle; the caller keeps all independent native
    /// topology, security, link and endpoint DMA/IOMMU reservations.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{adapter::{Control,Owner},channel::Channel,ring::Registers};
    /// fn pair<R:Registers>(channel:Channel<R>,owner:Arc<dyn Owner>){let _=Control::new(channel,owner,0);}
    /// ```
    pub unsafe fn new(channel: Channel<R>, owner: Arc<dyn Owner>, now: u64) -> Result<Self, Error> {
        let target = owner.target();
        let operation = owner.operation();
        let address = target.address(operation)?;
        let deadline = now.checked_add(TIMEOUT_MS).ok_or(Error::ClockOverflow)?;
        Ok(Self {
            channel: Some(channel),
            owner: Some(owner),
            target,
            operation,
            address,
            stage: Stage::Read,
            expected: None,
            deadline,
            before: None,
            published: false,
            last_now: now,
        })
    }
    fn channel(&mut self) -> &mut Channel<R> {
        self.channel.as_mut().expect("owned channel")
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = Stage::Fault;
        let _ = self.channel().cancel();
        Err(error)
    }
    /// After uncertainty the returned channel remains poisoned; Drop keeps
    /// the unresolved reservation if a write may have reached the adapter.
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("owned channel")
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        if self.expected.is_some() {
            return Ok(());
        }
        let target = self.target;
        let address = self.address;
        let deadline = self.deadline;
        let result = match self.stage {
            Stage::Read | Stage::Verify(..) => {
                self.channel().read(target.route, address, now, deadline)
            }
            Stage::Write(word, _) => {
                // Even a failed publication may have reached physical hardware.
                // Busy/full are known nonpublication; other errors keep owner.
                match self
                    .channel()
                    .write(target.route, address, &[word], now, deadline)
                {
                    Ok(id) => {
                        self.published = true;
                        Ok(id)
                    }
                    Err(
                        error @ (channel::Error::Ring(ring::Error::Full) | channel::Error::Busy),
                    ) => Err(error),
                    Err(error) => {
                        self.published = true;
                        Err(error)
                    }
                }
            }
            _ => return Err(Error::Stopped),
        };
        match result {
            Ok(id) => {
                self.expected = Some(id);
                Ok(())
            }
            Err(channel::Error::Ring(ring::Error::Full) | channel::Error::Busy) => Ok(()),
            Err(error) => self.fail(error.into()),
        }
    }
    fn receipt(&mut self, after: u32) -> Result<Option<Event>, Error> {
        let before = self.before.ok_or(Error::UnexpectedReceipt)?;
        self.stage = Stage::Done;
        Ok(Some(Event::Applied(Applied {
            target: self.target,
            operation: self.operation,
            before,
            after,
            owner: self.owner.take(),
            changed: self.published,
        })))
    }
    fn complete(&mut self, reply: Reply) -> Result<Option<Event>, Error> {
        let data = match reply {
            Reply::Configuration { data, .. } => data,
            Reply::ControllerError {
                route,
                port,
                code,
                raw,
                ..
            } => {
                return self.fail(Error::Controller {
                    route,
                    port,
                    code,
                    raw,
                });
            }
            Reply::Reset => return self.fail(Error::UnexpectedReceipt),
        };
        match self.stage {
            Stage::Read => {
                let [before] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                self.before = Some(*before);
                let (after, mask) = match change(self.operation, *before) {
                    Ok(value) => value,
                    Err(error) => return self.fail(error),
                };
                if self.operation == Operation::NfcCredits(0) {
                    return self.receipt(*before);
                }
                self.stage = Stage::Write(after, mask);
            }
            Stage::Write(after, mask) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.stage = Stage::Verify(after, mask);
            }
            Stage::Verify(expected, mask) => {
                let [actual] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                if actual & mask != expected & mask
                    || matches!(self.operation, Operation::NfcCredits(delta) if delta>0)
                        && (actual & NFC_MASK) > ((actual >> 20) & NFC_MASK)
                {
                    return self.fail(Error::Readback);
                }
                return self.receipt(*actual);
            }
            _ => return self.fail(Error::UnexpectedReceipt),
        }
        Ok(None)
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<Event>, Error> {
        match self.stage {
            Stage::Done => return Err(Error::Stopped),
            Stage::Fault => return Err(Error::Poisoned),
            _ => {}
        }
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if now >= self.deadline {
            return self.fail(Error::Timeout);
        }
        match self.channel().poll(now) {
            Err(error) => return self.fail(error.into()),
            Ok(Some(channel::Event::Completed { request, reply })) => {
                if self.expected != Some(request) {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.expected = None;
                if let Some(event) = self.complete(reply)? {
                    return Ok(Some(event));
                }
            }
            Ok(Some(channel::Event::Plug(event))) => return self.fail(Error::Hotplug(event)),
            Ok(Some(channel::Event::Notification(event))) => {
                return self.fail(Error::Notification(event));
            }
            Ok(Some(channel::Event::Discarded(error))) => return Ok(Some(Event::Discarded(error))),
            Ok(None) => {}
        }
        self.submit(now)?;
        Ok(None)
    }
}
impl<R: Registers> Drop for Control<R> {
    fn drop(&mut self) {
        if self.published
            && let Some(owner) = &self.owner
        {
            quarantine(owner);
        }
    }
}

#[cfg(test)]
mod tests {
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
}
