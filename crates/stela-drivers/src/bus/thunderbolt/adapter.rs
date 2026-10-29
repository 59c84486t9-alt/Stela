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
mod tests;
