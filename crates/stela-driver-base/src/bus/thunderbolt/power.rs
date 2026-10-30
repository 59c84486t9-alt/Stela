// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019 Intel Corporation
//! USB4 router wake programming and acknowledged sleep preparation.
//!
//! Register behavior follows Linux usb4_switch_set_wake/set_sleep at
//! cc9de5d4b5ab6459f5774946aa3195ad51236fa8. This does not stop tunnels,
//! suspend the NHI, release DMA, or invent platform wake/PM ownership.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    ring::{self, Registers},
    topology::{AdapterKind, AdapterObservation, Inventory},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

const PORT_WAKE: u32 = 7 << 16;
const ROUTER_WAKE: u32 = 7 << 1;
const REQUEST_MS: u64 = 500;
const JOB_MS: u64 = 20_000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

pub fn quarantined_reservations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wake {
    pub connect: bool,
    pub disconnect: bool,
    pub usb4: bool,
    pub usb3: bool,
    pub pcie: bool,
    pub displayport: bool,
    /// Runtime-PM policy; system-sleep port policy comes from Owner.
    pub runtime: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Wake(Wake),
    Sleep,
}
/// Exclusive CM/router power reservation, including every live tunnel.
///
/// # Safety
/// Inventory and per-port wake policy come from this physical router's
/// native platform, in one NHI/reset/topology lifetime. The owner
/// excludes firmware and competing CM configuration and keeps all router,
/// link, tunnel and wake resources through completion, failure and quarantine.
/// Sleep requires dependent tunnel/endpoint quiescence and the native
/// PM ordering grant before construction. No numeric metadata supplies those
/// rights. `is_current` checks the real admission state; an affirmative
/// snapshot must also pin the in-flight physical lifetime against reassignment.
/// This local operation never releases endpoint DMA/IRQ/IOMMU or NHI resources.
pub unsafe trait Owner: Send + Sync {
    fn inventory(&self) -> &Inventory;
    fn operation(&self) -> Operation;
    fn port_may_wakeup(&self, port: u8) -> bool;
    fn is_current(&self) -> bool;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Revoked,
    Unsupported,
    Inventory,
    Capability,
    Allocation,
    ClockOverflow,
    ClockRegressed,
    Timeout,
    Readback,
    UnexpectedReceipt,
    Cancelled,
    Poisoned,
    Stopped,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedWord {
    pub address: Address,
    pub before: u32,
    pub after: u32,
}
/// Keeps active wake/sleep ownership. Sleep-ready is a router-local
/// result, never a platform suspend, endpoint drain, or resource-release receipt.
pub struct Applied {
    pub operation: Operation,
    pub words: Vec<AppliedWord>,
    pub sleep_status: Option<u32>,
    owner: Option<Arc<dyn Owner>>,
    changed: bool,
}
impl Applied {
    /// # Safety
    /// State restoration/reset or an independent native PM/CM
    /// transfer has satisfied every router, tunnel, wake and DMA/IRQ lifetime.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::power::Applied;
    /// fn release(a: Applied) { a.retire(); }
    /// ```
    pub unsafe fn retire(mut self) {
        self.owner.take();
    }
}
fn quarantine(owner: &Arc<dyn Owner>) {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
    core::mem::forget(owner.clone());
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

#[derive(Clone, Copy)]
enum Kind {
    PortWake { upstream: bool, may_wakeup: bool },
    RouterWake,
    Sleep,
}
#[derive(Clone, Copy)]
struct Step {
    address: Address,
    kind: Kind,
}
fn plan(owner: &dyn Owner) -> Result<Vec<Step>, Error> {
    let inventory = owner.inventory();
    super::domain::Domain::validate(inventory).map_err(|_| Error::Inventory)?;
    if inventory.header.usb4_version() == 0 {
        return Err(Error::Unsupported);
    }
    let mut steps = Vec::new();
    steps
        .try_reserve_exact(inventory.adapters.len() + 1)
        .map_err(|_| Error::Allocation)?;
    if matches!(owner.operation(), Operation::Wake(_)) {
        // Source traversal is in physical adapter-number order, independent of
        // the caller's inventory storage order.
        for port in 1..=inventory.header.max_port() {
            let Some(AdapterObservation::Present {
                header,
                capabilities,
                ..
            }) = inventory.adapters.iter().find(|adapter| match adapter {
                AdapterObservation::Present { port: number, .. }
                | AdapterObservation::Unimplemented { port: number, .. } => *number == port,
            })
            else {
                continue;
            };
            if header.kind() != AdapterKind::Lane
                || (inventory.path.depth() == 0 && port == inventory.upstream_port)
            {
                continue;
            }
            let mut caps = capabilities.iter().filter(|cap| cap.id == 6);
            let Some(cap) = caps.next() else {
                continue;
            };
            if caps.next().is_some() || cap.offset < 8 {
                return Err(Error::Capability);
            }
            let offset = cap
                .offset
                .checked_add(0x13)
                .filter(|v| *v < 8192)
                .ok_or(Error::Capability)?;
            steps.push(Step {
                address: Address {
                    port,
                    space: Space::Port,
                    offset,
                    words: 1,
                },
                kind: Kind::PortWake {
                    upstream: port == inventory.upstream_port,
                    may_wakeup: owner.port_may_wakeup(port),
                },
            });
        }
        if inventory.path.depth() != 0 {
            steps.push(Step {
                address: Address {
                    port: 0,
                    space: Space::Router,
                    offset: 5,
                    words: 1,
                },
                kind: Kind::RouterWake,
            });
        }
    } else {
        steps.push(Step {
            address: Address {
                port: 0,
                space: Space::Router,
                offset: 5,
                words: 1,
            },
            kind: Kind::Sleep,
        });
    }
    Ok(steps)
}
fn change(kind: Kind, operation: Operation, before: u32) -> (u32, u32) {
    match (kind, operation) {
        (Kind::Sleep, Operation::Sleep) => (before | 1, 1),
        (Kind::RouterWake, Operation::Wake(wake)) => (
            (before & !ROUTER_WAKE)
                | (u32::from(wake.pcie) << 1)
                | (u32::from(wake.usb3) << 2)
                | (u32::from(wake.displayport) << 3),
            ROUTER_WAKE,
        ),
        (
            Kind::PortWake {
                upstream,
                may_wakeup,
            },
            Operation::Wake(wake),
        ) => {
            let configured = before & (1 << 3) != 0;
            let enabled = wake.runtime || may_wakeup;
            let bits = if upstream {
                1 << 18
            } else {
                (u32::from(wake.connect && enabled && !configured) << 16)
                    | (u32::from(wake.disconnect && enabled && configured) << 17)
                    | (u32::from(wake.usb4 && configured) << 18)
            };
            ((before & !PORT_WAKE) | bits, PORT_WAKE | (1 << 3))
        }
        _ => unreachable!("validated immutable power plan"),
    }
}
#[derive(Clone, Copy)]
enum Stage {
    Read,
    Write(u32, u32),
    Verify(u32, u32),
    SleepReady,
    Done,
    Fault,
}
pub struct Control<R: Registers> {
    channel: Option<Channel<R>>,
    owner: Option<Arc<dyn Owner>>,
    route: Route,
    operation: Operation,
    steps: Vec<Step>,
    words: Vec<AppliedWord>,
    index: usize,
    stage: Stage,
    before: u32,
    expected: Option<u64>,
    published: bool,
    last_now: u64,
    deadline: u64,
    job_deadline: u64,
}
impl<R: Registers> Control<R> {
    /// # Safety
    /// The exclusively idle Channel and Owner belong to the same live
    /// physical NHI/requester/reset/topology lifetime. All Owner preconditions
    /// and independent endpoint/PM resources remain held through final drain.
    pub unsafe fn new(channel: Channel<R>, owner: Arc<dyn Owner>, now: u64) -> Result<Self, Error> {
        if !owner.is_current() {
            return Err(Error::Revoked);
        }
        let steps = plan(&*owner)?;
        let mut words = Vec::new();
        words
            .try_reserve_exact(steps.len())
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            route: owner.inventory().path.route(),
            operation: owner.operation(),
            channel: Some(channel),
            owner: Some(owner),
            steps,
            words,
            index: 0,
            stage: Stage::Read,
            before: 0,
            expected: None,
            published: false,
            last_now: now,
            deadline: now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?,
            job_deadline: now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?,
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
    pub fn cancel(&mut self) -> Result<(), Error> {
        self.fail(Error::Cancelled)
    }
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("owned channel")
    }
    fn applied(&mut self, sleep_status: Option<u32>) -> Event {
        self.stage = Stage::Done;
        Event::Applied(Applied {
            operation: self.operation,
            words: core::mem::take(&mut self.words),
            sleep_status,
            owner: self.owner.take(),
            changed: self.published,
        })
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
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
                self.before = *before;
                let (after, mask) = change(self.steps[self.index].kind, self.operation, *before);
                self.stage = Stage::Write(after, mask);
            }
            Stage::Write(after, mask) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.words.push(AppliedWord {
                    address: self.steps[self.index].address,
                    before: self.before,
                    after,
                });
                self.stage = if matches!(self.operation, Operation::Sleep) {
                    Stage::SleepReady
                } else {
                    Stage::Verify(after, mask)
                };
            }
            Stage::Verify(after, mask) => {
                let [actual] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                if actual & mask != after & mask {
                    return self.fail(Error::Readback);
                }
                self.words[self.index].after = *actual;
                self.index += 1;
                if self.index == self.steps.len() {
                    return Ok(Some(self.applied(None)));
                }
                self.stage = Stage::Read;
            }
            Stage::SleepReady => {
                let [status] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                if status & 1 != 0 {
                    return Ok(Some(self.applied(Some(*status))));
                }
                // Fixed 500ms window from the real sleep-write ACK; an unset
                // ready bit never moves the window or reports success.
                return Ok(None);
            }
            _ => return self.fail(Error::UnexpectedReceipt),
        }
        let Some(deadline) = now.checked_add(REQUEST_MS) else {
            return self.fail(Error::ClockOverflow);
        };
        self.deadline = deadline;
        Ok(None)
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        if self.expected.is_some() {
            return Ok(());
        }
        let mut address = self.steps[self.index].address;
        if matches!(self.stage, Stage::SleepReady) {
            address.offset = 6;
        }
        let (route, deadline) = (self.route, self.deadline.min(self.job_deadline));
        let writing = matches!(self.stage, Stage::Write(..));
        let result = if let Stage::Write(after, _) = self.stage {
            self.channel()
                .write(route, address, &[after], now, deadline)
        } else {
            self.channel().read(route, address, now, deadline)
        };
        match result {
            Ok(id) => {
                self.expected = Some(id);
                self.published |= writing;
                Ok(())
            }
            Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => Ok(()),
            Err(error) => {
                self.published |= writing;
                self.fail(Error::Channel(error))
            }
        }
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<Event>, Error> {
        match self.stage {
            Stage::Done => return Err(Error::Stopped),
            Stage::Fault => return Err(Error::Poisoned),
            _ => {}
        }
        if !self.owner.as_ref().expect("live owner").is_current() {
            return self.fail(Error::Revoked);
        }
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if now >= self.deadline || now >= self.job_deadline {
            return self.fail(Error::Timeout);
        }
        if self.steps.is_empty() {
            return Ok(Some(self.applied(None)));
        }
        match self.channel().poll(now) {
            Err(error) => return self.fail(Error::Channel(error)),
            Ok(Some(channel::Event::Completed { request, reply })) => {
                if self.expected != Some(request) {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.expected = None;
                if let Some(event) = self.complete(reply, now)? {
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
