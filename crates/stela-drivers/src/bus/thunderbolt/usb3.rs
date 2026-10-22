// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Actual root USB3 bandwidth and two-direction tunnel activation/stop from Linux
//! usb4.c/path.c/tunnel.c/switch.c, with one genuine retained ownership chain.
//! Native accounting/permission/endpoint-control providers and host admission
//! remain explicit external requirements; no OS service is fabricated.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    domain::Identity,
    link::{self, Linked},
    ring::{self, Registers},
    router::Decision,
    topology::{AdapterHeader, AdapterKind, AdapterObservation, Inventory},
};
use alloc::{alloc::alloc, boxed::Box, sync::Arc};
use core::{
    alloc::Layout,
    sync::atomic::{AtomicU64, Ordering},
};
const CMR: u32 = 1 << 31;
const BANDWIDTH: u32 = 0x00ff_ffff;
const REQUEST_MS: u64 = 500;
const ACK_MS: u64 = 1500;
const JOB_MS: u64 = 20_000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_allocations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rates {
    pub upstream: u32,
    pub downstream: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub identity: Identity,
    pub topology_epoch: u64,
    pub grant_epoch: u64,
    pub usb3_down: u8,
    pub usb3_up: u8,
    pub permission: Decision,
    pub requested: Rates,
}
/// Actual exclusive native root bandwidth-accounting and permission reservation.
///
/// # Safety
/// This retains the real shared-domain accounting right for the requested rates,
/// existing consumed traffic and source quantization, with actual _OSC/security
/// permission and USB3↔primary-lane mapping for this exact Linked/requester/reset/
/// topology/grant epoch. The object is the actual reservation, not supplied
/// numeric quotas. Existing consumed rights cannot be removed or double charged.
/// It owns the root USB3 CMR/HCA transition, excludes firmware/other CM changes,
/// retains endpoint/router/power lifetimes, and serializes dependent path work.
/// Real DMA/IMR/IOMMU/IRQ ownership remains independently held through final drain.
/// Metadata stays protected until no mutation, real restore/reset or independent
/// retained ownership transfer. No production allocator/policy implementation or
/// fallback admission is provided by this trait. An integer grant alone is never
/// sufficient authority for implementing it.
/// When supplied to ActivateTunnel it ALSO retains actual exclusive CS0 PE/V
/// control authority for BOTH mapped USB3 endpoints through uncertain completion
/// and quarantine. That real platform grant is not implied by path IDs, matching
/// numbers or a bandwidth request; an implementation lacking it cannot be used
/// for endpoint activation.
pub unsafe trait Reservation: Send + Sync {
    fn grant(&self) -> Grant;
    /// Actual retained native reset/topology/permission guard, never numeric
    /// tuple equality or MMIO readiness. No permissive default is provided.
    /// A true snapshot alone is insufficient: this object must also retain real
    /// exclusive admission and in-flight lifetime so reset/reassignment cannot
    /// reuse its physical resource until those operations independently quiesce.
    fn is_current(&self) -> bool;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encoding {
    pub scale: u8,
    pub upstream: u16,
    pub downstream: u16,
}
fn decoded(value: u32, scale: u8) -> Result<u32, Error> {
    let bytes = u64::from(value)
        .checked_mul(512)
        .and_then(|v| v.checked_mul(1u64.checked_shl(u32::from(scale))?))
        .and_then(|v| v.checked_mul(8000))
        .ok_or(Error::Encoding)?;
    let rounded = bytes.checked_add(500_000).ok_or(Error::Encoding)? / 1_000_000;
    let value = u32::try_from(rounded).map_err(|_| Error::Encoding)?;
    if value > i32::MAX as u32 {
        return Err(Error::Encoding);
    }
    Ok(value)
}
fn encode(rates: Rates) -> Result<Encoding, Error> {
    if rates.upstream > i32::MAX as u32 || rates.downstream > i32::MAX as u32 {
        return Err(Error::Encoding);
    }
    for scale in 0..64u8 {
        let Some(unit) =
            512u64.checked_mul(1u64.checked_shl(u32::from(scale)).ok_or(Error::Encoding)?)
        else {
            return Err(Error::Encoding);
        };
        let units = |mbps: u32| (u64::from(mbps) * 125).div_ceil(unit);
        if units(rates.upstream.max(rates.downstream)) < 4096 {
            return Ok(Encoding {
                scale,
                upstream: units(rates.upstream) as u16,
                downstream: units(rates.downstream) as u16,
            });
        }
    }
    Err(Error::Encoding)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Revoked,
    Allocation,
    Identity,
    Topology,
    Permission,
    Capability,
    Unsupported,
    Busy,
    Encoding,
    ClockOverflow,
    ClockRegressed,
    Timeout,
    Changed,
    Readback,
    Cancelled,
    Poisoned,
    Stopped,
    UnexpectedReceipt,
    Controller {
        route: Route,
        port: u8,
        code: u8,
        raw: u32,
    },
    Hotplug(config::PlugEvent),
    Notification(config::NotificationError),
    Path(super::path::Error),
    Link(link::Error),
    Channel(channel::Error),
}
/// Actual root bandwidth allocation; both HCA transitions completed. This owns
/// its single original link and actual accounting reservation until real retire.
pub struct Allocated {
    pub requested: Rates,
    pub consumed: Rates,
    pub allocated: Rates,
    pub encoding: Encoding,
    link: Option<Box<Linked>>,
    reservation: Option<Arc<dyn Reservation>>,
    changed: bool,
}
impl Allocated {
    pub(super) fn is_current(&self) -> bool {
        self.reservation
            .as_ref()
            .is_some_and(|owner| owner.is_current())
    }
    pub(super) fn linked(&self) -> &Linked {
        self.link.as_ref().expect("retained link")
    }
    pub(super) fn protected_grant(&self) -> Grant {
        self.reservation
            .as_ref()
            .expect("retained accounting")
            .grant()
    }
    /// # Safety
    /// Real allocation/link restoration or reset and all independent endpoint/
    /// DMA/IRQ/power lifetimes are satisfied, or the actual allocation, link and
    /// both routers have independently retained native CM ownership. Clearing
    /// CMR/HCA never releases allocated bandwidth or proves endpoint quiescence.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::usb3::Allocated;
    /// fn release(a:Allocated){a.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        if let Some(link) = self.link.take() {
            unsafe { link.retire() };
        }
        self.reservation.take();
    }
}
fn retain_accounting(reservation: &Arc<dyn Reservation>) {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
    core::mem::forget(reservation.clone());
}
impl Drop for Allocated {
    fn drop(&mut self) {
        if self.changed
            && let Some(reservation) = &self.reservation
        {
            retain_accounting(reservation);
        }
    }
}

pub enum Event {
    Allocated(Box<Allocated>),
    Discarded(config::Error),
}
#[derive(Clone, Copy)]
struct Plan {
    route: Route,
    port: u8,
    upstream: u8,
    cap: u16,
    header: [u32; 8],
}
fn usb3_adapter(
    inventory: &Inventory,
    port: u8,
    kind: AdapterKind,
) -> Result<(&AdapterHeader, u16), Error> {
    let (header, capabilities) = inventory
        .adapters
        .iter()
        .find_map(|item| match item {
            AdapterObservation::Present {
                port: number,
                header,
                capabilities,
            } if *number == port && port != 0 => Some((header, capabilities)),
            _ => None,
        })
        .ok_or(Error::Topology)?;
    if header.kind() != kind {
        return Err(Error::Topology);
    }
    let mut capability = None;
    for cap in capabilities.iter().filter(|cap| cap.id == 4) {
        if capability.is_some() || cap.offset < 8 || cap.offset > 8188 {
            return Err(Error::Capability);
        }
        capability = Some(cap.offset);
    }
    Ok((header, capability.ok_or(Error::Capability)?))
}
fn plan(link: &Linked, grant: Grant) -> Result<Plan, Error> {
    let (parent, child) = link.retained_routers().map_err(Error::Link)?;
    let partners = link.protected_partners();
    if grant.identity != partners.identity
        || grant.topology_epoch != partners.topology_epoch
        || grant.grant_epoch == 0
        || link.partners != partners
    {
        return Err(Error::Identity);
    }
    if parent.route.raw() != 0 || !link.link_usb4 || !matches!(link.generation, 2 | 3) {
        return Err(Error::Unsupported);
    }
    if grant.permission != Decision::Allowed
        || parent.retained_owner().policy().usb3 != Decision::Allowed
        || child.retained_owner().policy().usb3 != Decision::Allowed
    {
        return Err(Error::Permission);
    }
    let (header, cap) = usb3_adapter(
        parent.retained_owner().target(),
        grant.usb3_down,
        AdapterKind::Usb3Down,
    )?;
    usb3_adapter(
        child.retained_owner().target(),
        grant.usb3_up,
        AdapterKind::Usb3Up,
    )?;
    encode(grant.requested)?;
    Ok(Plan {
        route: parent.route,
        port: grant.usb3_down,
        upstream: parent.retained_owner().target().upstream_port,
        cap,
        header: header.raw,
    })
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Inventory,
    Initial,
    Idle(u32),
    Set(u32),
    VerifySet,
    WaitSet,
    Consumed,
    ConsumedScale,
    Scale,
    VerifyScale,
    ReadAllocation,
    WriteAllocation(u32),
    VerifyAllocation(u32),
    ReadClear,
    Clear(u32),
    VerifyClear,
    WaitClear,
    Done,
    Fault,
}
#[derive(Clone, Copy)]
enum BandwidthMode {
    Allocate,
    ReleaseUnused,
}
/// Source consumed/max/scale/CS2 sequence with actual CMR/HCA hardware effects.
pub struct Allocate<R: Registers> {
    channel: Option<Channel<R>>,
    retained: Option<Box<Allocated>>,
    plan: Plan,
    stage: Stage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    last_now: u64,
    next_poll: u64,
    consumed_word: u32,
    mode: BandwidthMode,
}
impl<R: Registers> Allocate<R> {
    /// # Safety
    /// All three objects identify the exact same live physical NHI/reset/topology/
    /// protected grant epoch. Link metadata is current, Channel exclusively idle,
    /// and Reservation's actual native accounting/permission/mapping/lifetime
    /// requirements hold; numbers alone cannot prove physical authority.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,link::Linked,usb3::{Allocate,Reservation},ring::Registers};
    /// fn pair<R:Registers>(c:Channel<R>,l:Box<Linked>,r:Arc<dyn Reservation>){let _=Allocate::new(c,l,r,0);}
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        link: Box<Linked>,
        reservation: Arc<dyn Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        unsafe { Self::new_inner(channel, link, reservation, now, alloc) }
    }
    #[cfg(test)]
    pub(super) unsafe fn new_without_storage(
        channel: Channel<R>,
        link: Box<Linked>,
        reservation: Arc<dyn Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        unsafe fn refuse(_: Layout) -> *mut u8 {
            core::ptr::null_mut()
        }
        unsafe { Self::new_inner(channel, link, reservation, now, refuse) }
    }
    unsafe fn new_inner(
        channel: Channel<R>,
        link: Box<Linked>,
        reservation: Arc<dyn Reservation>,
        now: u64,
        allocate: unsafe fn(Layout) -> *mut u8,
    ) -> Result<Self, Error> {
        if !reservation.is_current() {
            retain_accounting(&reservation);
            return Err(Error::Revoked);
        }
        let grant = reservation.grant();
        let plan = plan(&link, grant)?;
        let encoding = encode(grant.requested)?;
        let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
        let job_deadline = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
        // Reserve the final bundle before any request. Both the original link
        // and actual accounting reservation stay in this same allocation on any
        // uncertain write/ACK/readback, and when composed into path programming.
        // SAFETY: alloc, or test-only null allocator, gets the exact Box layout.
        let storage = unsafe { allocate(Layout::new::<Allocated>()) }.cast::<Allocated>();
        if storage.is_null() {
            return Err(Error::Allocation);
        }
        let result = Allocated {
            requested: grant.requested,
            consumed: Rates {
                upstream: 0,
                downstream: 0,
            },
            allocated: Rates {
                upstream: 0,
                downstream: 0,
            },
            encoding,
            link: Some(link),
            reservation: Some(reservation),
            changed: false,
        };
        // SAFETY: fresh nonnull aligned exact-layout storage, uniquely initialized.
        let retained = unsafe {
            storage.write(result);
            Box::from_raw(storage)
        };
        Ok(Self {
            channel: Some(channel),
            retained: Some(retained),
            plan,
            stage: Stage::Inventory,
            expected: None,
            deadline,
            job_deadline,
            last_now: now,
            next_poll: now,
            consumed_word: 0,
            mode: BandwidthMode::Allocate,
        })
    }
    fn release_existing(
        channel: Channel<R>,
        retained: Box<Allocated>,
        plan: Plan,
        now: u64,
        deadline: u64,
        job_deadline: u64,
    ) -> Self {
        Self {
            channel: Some(channel),
            retained: Some(retained),
            plan,
            stage: Stage::Inventory,
            expected: None,
            deadline,
            job_deadline,
            last_now: now,
            next_poll: now,
            consumed_word: 0,
            mode: BandwidthMode::ReleaseUnused,
        }
    }
    fn channel(&mut self) -> &mut Channel<R> {
        self.channel.as_mut().expect("retained channel")
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        // Revocation does not certify that this previously admitted accounting
        // lifetime is safe to return, even if only a query was published here.
        if matches!(error, Error::Revoked) {
            self.retained.as_mut().expect("retained allocation").changed = true;
        }
        self.stage = Stage::Fault;
        let _ = self.channel().cancel();
        Err(error)
    }
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("retained channel")
    }
    pub fn cancel(&mut self) -> Result<(), Error> {
        match self.stage {
            Stage::Done => Err(Error::Stopped),
            Stage::Fault => Err(Error::Poisoned),
            _ => self.fail(Error::Cancelled),
        }
    }
    fn enter(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.next_poll = now;
        self.deadline = now
            .checked_add(REQUEST_MS)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        Ok(())
    }
    fn acknowledge(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.enter(stage, now)?;
        self.deadline = now
            .checked_add(ACK_MS)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        Ok(())
    }
    fn request(&self) -> Result<(Address, Option<[u32; 1]>), Error> {
        let (relative, words, data) = match self.stage {
            Stage::Inventory => {
                return Ok((
                    Address {
                        port: self.plan.port,
                        space: Space::Port,
                        offset: 0,
                        words: 8,
                    },
                    None,
                ));
            }
            Stage::Initial
            | Stage::VerifySet
            | Stage::ReadAllocation
            | Stage::VerifyAllocation(_)
            | Stage::ReadClear
            | Stage::VerifyClear => (2, 1, None),
            Stage::Idle(_) | Stage::WaitSet | Stage::Consumed | Stage::WaitClear => (1, 1, None),
            Stage::Set(value) | Stage::WriteAllocation(value) | Stage::Clear(value) => {
                (2, 1, Some([value]))
            }
            Stage::ConsumedScale | Stage::VerifyScale => (3, 1, None),
            Stage::Scale => (
                3,
                1,
                Some([u32::from(
                    self.retained
                        .as_ref()
                        .expect("retained allocation")
                        .encoding
                        .scale,
                )]),
            ),
            _ => return Err(Error::Stopped),
        };
        Ok((
            Address {
                port: self.plan.port,
                space: Space::Port,
                offset: self.plan.cap + relative,
                words,
            },
            data,
        ))
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        if !self
            .retained
            .as_ref()
            .is_some_and(|owner| owner.is_current())
        {
            return self.fail(Error::Revoked);
        }
        if self.expected.is_some() || now < self.next_poll {
            return Ok(());
        }
        let (address, data) = self.request()?;
        let route = self.plan.route;
        let deadline = self.deadline;
        let result = if let Some(data) = data {
            let result = self.channel().write(route, address, &data, now, deadline);
            if !matches!(
                result,
                Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full))
            ) {
                self.retained.as_mut().expect("retained allocation").changed = true;
            }
            result
        } else {
            self.channel().read(route, address, now, deadline)
        };
        match result {
            Ok(id) => {
                self.expected = Some(id);
                Ok(())
            }
            Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => Ok(()),
            Err(error) => self.fail(Error::Channel(error)),
        }
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
        if !self
            .retained
            .as_ref()
            .is_some_and(|owner| owner.is_current())
        {
            return self.fail(Error::Revoked);
        }
        let data = match reply {
            Reply::Configuration {
                upstream_port,
                data,
            } => {
                if upstream_port != self.plan.upstream {
                    return self.fail(Error::Changed);
                }
                data
            }
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
        let word = || {
            data.first()
                .copied()
                .filter(|_| data.len() == 1)
                .ok_or(Error::UnexpectedReceipt)
        };
        match self.stage {
            Stage::Inventory => {
                let header = AdapterHeader::parse(&data).map_err(|_| Error::UnexpectedReceipt)?;
                if header.kind() != AdapterKind::Usb3Down
                    || header.reported_port() != self.plan.port
                    || header.first_capability() != (self.plan.header[1] & 255) as u16
                {
                    return self.fail(Error::Changed);
                }
                self.enter(Stage::Initial, now)?;
            }
            Stage::Initial => {
                let raw = word()?;
                if raw & CMR != 0 {
                    return self.fail(Error::Busy);
                }
                self.enter(Stage::Idle(raw), now)?;
            }
            Stage::Idle(raw) => {
                if word()? & CMR != 0 {
                    return self.fail(Error::Busy);
                }
                self.enter(Stage::Set(raw | CMR), now)?;
            }
            Stage::Set(_) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.acknowledge(Stage::VerifySet, now)?;
            }
            Stage::VerifySet => {
                if word()? & CMR == 0 {
                    return self.fail(Error::Readback);
                }
                self.stage = Stage::WaitSet;
            }
            Stage::WaitSet => {
                if word()? & CMR != 0 {
                    self.enter(Stage::Consumed, now)?;
                } else {
                    self.next_poll = now.checked_add(1).ok_or(Error::ClockOverflow)?;
                }
            }
            Stage::Consumed => {
                self.consumed_word = word()?;
                if self.consumed_word & CMR == 0 {
                    return self.fail(Error::Changed);
                }
                self.enter(Stage::ConsumedScale, now)?;
            }
            Stage::ConsumedScale => {
                let scale = (word()? & 63) as u8;
                let consumed = Rates {
                    upstream: decoded(self.consumed_word & 4095, scale)?,
                    downstream: decoded((self.consumed_word >> 12) & 4095, scale)?,
                };
                let retained = self.retained.as_mut().expect("retained allocation");
                let rates = match self.mode {
                    BandwidthMode::Allocate => Rates {
                        upstream: retained.requested.upstream.max(consumed.upstream),
                        downstream: retained.requested.downstream.max(consumed.downstream),
                    },
                    BandwidthMode::ReleaseUnused => Rates {
                        upstream: consumed.upstream.max(900),
                        downstream: consumed.downstream.max(900),
                    },
                };
                retained.consumed = consumed;
                retained.allocated = rates;
                retained.encoding = encode(rates)?;
                self.enter(Stage::Scale, now)?;
            }
            Stage::Scale => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::VerifyScale, now)?;
            }
            Stage::VerifyScale => {
                if word()? & 63
                    != u32::from(
                        self.retained
                            .as_ref()
                            .expect("retained allocation")
                            .encoding
                            .scale,
                    )
                {
                    return self.fail(Error::Readback);
                }
                self.enter(Stage::ReadAllocation, now)?;
            }
            Stage::ReadAllocation => {
                let raw = word()?;
                if raw & CMR == 0 {
                    return self.fail(Error::Changed);
                }
                let encoding = self
                    .retained
                    .as_ref()
                    .expect("retained allocation")
                    .encoding;
                self.enter(
                    Stage::WriteAllocation(
                        (raw & !BANDWIDTH)
                            | u32::from(encoding.upstream)
                            | (u32::from(encoding.downstream) << 12),
                    ),
                    now,
                )?;
            }
            Stage::WriteAllocation(value) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::VerifyAllocation(value), now)?;
            }
            Stage::VerifyAllocation(value) => {
                if word()? & (BANDWIDTH | CMR) != value & (BANDWIDTH | CMR) {
                    return self.fail(Error::Readback);
                }
                self.enter(Stage::ReadClear, now)?;
            }
            Stage::ReadClear => {
                let raw = word()?;
                if raw & CMR == 0 {
                    return self.fail(Error::Changed);
                }
                self.enter(Stage::Clear(raw & !CMR), now)?;
            }
            Stage::Clear(_) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.acknowledge(Stage::VerifyClear, now)?;
            }
            Stage::VerifyClear => {
                if word()? & CMR != 0 {
                    return self.fail(Error::Readback);
                }
                self.stage = Stage::WaitClear;
            }
            Stage::WaitClear => {
                if word()? & CMR == 0 {
                    if !self.retained.as_ref().is_some_and(|b| b.is_current()) {
                        return self.fail(Error::Revoked);
                    }
                    self.stage = Stage::Done;
                    return Ok(Some(Event::Allocated(
                        self.retained.take().ok_or(Error::UnexpectedReceipt)?,
                    )));
                } else {
                    self.next_poll = now.checked_add(1).ok_or(Error::ClockOverflow)?;
                }
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
        if !self
            .retained
            .as_ref()
            .is_some_and(|owner| owner.is_current())
        {
            return self.fail(Error::Revoked);
        }
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if now >= self.deadline || now >= self.job_deadline {
            return self.fail(Error::Timeout);
        }
        match self.channel().poll(now) {
            Err(error) => return self.fail(Error::Channel(error)),
            Ok(Some(channel::Event::Completed { request, reply })) => {
                if self.expected != Some(request) {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.expected = None;
                match self.complete(reply, now) {
                    Ok(Some(event)) => return Ok(Some(event)),
                    Ok(None) => {}
                    Err(error) => return self.fail(error),
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

const ENDPOINT_ENABLE: u32 = (1 << 31) | (1 << 30);
const TUNNEL_MS: u64 = 30_000;
/// Both actual USB3 directions and enabled endpoints with one retained original
/// link/accounting chain. Native host admission/OS attachment remains external.
pub struct ActiveTunnel {
    pub endpoints: [u32; 2],
    path: Option<super::path::Active>,
    previous: Option<Box<super::path::Active>>,
    bandwidth: Option<Box<Allocated>>,
    pending: [Option<Arc<dyn super::path::Reservation>>; 2],
}
impl ActiveTunnel {
    fn bandwidth_ref(&self) -> &Allocated {
        if let Some(bandwidth) = &self.bandwidth {
            bandwidth
        } else if let Some(previous) = &self.previous {
            previous.bandwidth_ref()
        } else {
            self.path
                .as_ref()
                .expect("complete retained path chain")
                .bandwidth_ref()
        }
    }
    fn take_bandwidth(&mut self) -> Box<Allocated> {
        if let Some(bandwidth) = self.bandwidth.take() {
            bandwidth
        } else if let Some(previous) = &mut self.previous {
            previous.take_bandwidth()
        } else {
            self.path
                .as_mut()
                .expect("retained path chain")
                .take_bandwidth()
        }
    }
    fn put_bandwidth(&mut self, bandwidth: Box<Allocated>) {
        if let Some(previous) = &mut self.previous {
            previous.put_bandwidth(bandwidth);
        } else if let Some(path) = &mut self.path {
            path.put_bandwidth(bandwidth);
        } else {
            self.bandwidth = Some(bandwidth);
        }
    }
    pub fn bandwidth_rates(&self) -> Rates {
        self.bandwidth_ref().allocated
    }
    /// # Safety
    /// Real teardown/restoration/reset has satisfied BOTH directions, endpoint
    /// adapters, allocated bandwidth and all independent endpoint DMA/IRQ/power/
    /// native attachment lifetimes, or the entire live tunnel and every owner
    /// already have independently retained native CM ownership. A PE readback,
    /// local pending drain or CMR clearance cannot establish this proof.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::usb3::ActiveTunnel;
    /// fn release(t:ActiveTunnel){t.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        if let Some(path) = self.path.take() {
            unsafe { path.retire() };
        }
        if let Some(path) = self.previous.take() {
            unsafe { path.retire() };
        }
        if let Some(bandwidth) = self.bandwidth.take() {
            unsafe { bandwidth.retire() };
        }
        self.pending = [None, None];
    }
}
impl Drop for ActiveTunnel {
    fn drop(&mut self) {
        // Bandwidth is already a real live hardware mutation on entry. Preserve
        // even not-yet-programmed IDs through any intermediate partial failure.
        for reservation in self.pending.iter().flatten() {
            super::path::retain_reservation(reservation);
        }
    }
}
pub enum TunnelEvent {
    Active(Box<ActiveTunnel>),
    Discarded(config::Error),
}
#[derive(Clone, Copy)]
struct Endpoint {
    route: Route,
    port: u8,
    upstream: u8,
    cap: u16,
    header: [u32; 8],
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum TunnelStage {
    Header(usize),
    Disabled(usize),
    First,
    Second,
    Enable(usize),
    Verify(usize),
    Done,
    Fault,
}
/// Source USB3 Down path → Up path → Down endpoint → Up endpoint composition.
/// Reuses the real Channel/path cores; no duplicate allocator or authority.
pub struct ActivateTunnel<R: Registers> {
    channel: Option<Channel<R>>,
    path: Option<super::path::Activate<R>>,
    retained: Option<Box<ActiveTunnel>>,
    first_slot: Option<Box<core::mem::MaybeUninit<super::path::Active>>>,
    prepared: [Option<super::path::Prepared>; 2],
    endpoints: [Endpoint; 2],
    stage: TunnelStage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    last_now: u64,
}
impl<R: Registers> ActivateTunnel<R> {
    /// # Safety
    /// The actual bandwidth receipt, BOTH path allocations and idle Channel are
    /// one exact live NHI/reset/topology/permission generation. Real native
    /// accounting/_OSC/security/mapping/power/attachment lifetimes hold. In
    /// addition, bandwidth's Reservation retains actual exclusive CS0 endpoint
    /// control for BOTH adapters through final retirement or quarantine; neither
    /// path IDs nor matching numeric grants imply that authority. No firmware or
    /// other CM can enable/reuse the endpoints or paths. Pre-existing traffic is
    /// independently serialized and every prior ID is genuinely owned.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,path::Reservation,usb3::{Allocated,ActivateTunnel},ring::Registers};
    /// fn pair<R:Registers>(c:Channel<R>,a:Box<Allocated>,d:Arc<dyn Reservation>,u:Arc<dyn Reservation>){let _=ActivateTunnel::new(c,a,d,u,0);}
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        bandwidth: Box<Allocated>,
        down: Arc<dyn super::path::Reservation>,
        up: Arc<dyn super::path::Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        unsafe { Self::new_inner(channel, bandwidth, down, up, now, alloc) }
    }
    #[cfg(test)]
    pub(super) unsafe fn new_without_storage(
        channel: Channel<R>,
        bandwidth: Box<Allocated>,
        down: Arc<dyn super::path::Reservation>,
        up: Arc<dyn super::path::Reservation>,
        now: u64,
        second: bool,
    ) -> Result<Self, Error> {
        unsafe fn refuse(_: Layout) -> *mut u8 {
            core::ptr::null_mut()
        }
        unsafe fn refuse_receipt(layout: Layout) -> *mut u8 {
            if layout == Layout::new::<ActiveTunnel>() {
                core::ptr::null_mut()
            } else {
                unsafe { alloc(layout) }
            }
        }
        unsafe {
            Self::new_inner(
                channel,
                bandwidth,
                down,
                up,
                now,
                if second { refuse_receipt } else { refuse },
            )
        }
    }
    unsafe fn new_inner(
        channel: Channel<R>,
        bandwidth: Box<Allocated>,
        down: Arc<dyn super::path::Reservation>,
        up: Arc<dyn super::path::Reservation>,
        now: u64,
        allocate: unsafe fn(Layout) -> *mut u8,
    ) -> Result<Self, Error> {
        let checked = (|| {
            if !bandwidth.is_current() {
                return Err(Error::Revoked);
            }
            let grant = bandwidth.protected_grant();
            let link = bandwidth.linked();
            let (parent, child) = link.retained_routers().map_err(Error::Link)?;
            let allocations = [down.allocation(), up.allocation()];
            for (index, path) in allocations.iter().enumerate() {
                if path.identity != grant.identity
                    || path.topology_epoch != grant.topology_epoch
                    || path.grant_epoch != grant.grant_epoch
                    || path.usb3_down != grant.usb3_down
                    || path.usb3_up != grant.usb3_up
                    || path.permission != Decision::Allowed
                    || grant.permission != Decision::Allowed
                    || path.direction
                        != if index == 0 {
                            super::path::Direction::Downstream
                        } else {
                            super::path::Direction::Upstream
                        }
                {
                    return Err(Error::Identity);
                }
            }
            let prepared = [
                super::path::prepare(link, allocations[0]).map_err(Error::Path)?,
                super::path::prepare(link, allocations[1]).map_err(Error::Path)?,
            ];
            let (down_header, down_cap) = usb3_adapter(
                parent.retained_owner().target(),
                grant.usb3_down,
                AdapterKind::Usb3Down,
            )?;
            let (up_header, up_cap) = usb3_adapter(
                child.retained_owner().target(),
                grant.usb3_up,
                AdapterKind::Usb3Up,
            )?;
            let endpoints = [
                Endpoint {
                    route: parent.route,
                    port: grant.usb3_down,
                    upstream: parent.retained_owner().target().upstream_port,
                    cap: down_cap,
                    header: down_header.raw,
                },
                Endpoint {
                    route: child.route,
                    port: grant.usb3_up,
                    upstream: child.retained_owner().target().upstream_port,
                    cap: up_cap,
                    header: up_header.raw,
                },
            ];
            // Guard every later path-start addition before moving any resource.
            now.checked_add(TUNNEL_MS + 10_000)
                .ok_or(Error::ClockOverflow)?;
            let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
            let job_deadline = now.checked_add(TUNNEL_MS).ok_or(Error::ClockOverflow)?;
            // SAFETY: exact nonzero layouts, alloc or local null test allocator.
            let first = unsafe { allocate(Layout::new::<super::path::Active>()) }
                .cast::<core::mem::MaybeUninit<super::path::Active>>();
            if first.is_null() {
                return Err(Error::Allocation);
            }
            // SAFETY: uninitialized bytes are valid MaybeUninit; matching layout.
            let first = unsafe { Box::from_raw(first) };
            let result = unsafe { allocate(Layout::new::<ActiveTunnel>()) }
                .cast::<core::mem::MaybeUninit<ActiveTunnel>>();
            if result.is_null() {
                return Err(Error::Allocation);
            }
            // SAFETY: same exact-layout fresh unique allocation.
            let result = unsafe { Box::from_raw(result) };
            Ok((prepared, endpoints, deadline, job_deadline, first, result))
        })();
        let (prepared, endpoints, deadline, job_deadline, first, mut storage) = match checked {
            Ok(value) => value,
            Err(error) => {
                super::path::retain_reservation(&down);
                super::path::retain_reservation(&up);
                return Err(error);
            }
        };
        storage.as_mut().write(ActiveTunnel {
            endpoints: [0; 2],
            path: None,
            previous: None,
            bandwidth: Some(bandwidth),
            pending: [Some(down), Some(up)],
        });
        // SAFETY: initialized once above, before any path/endpoint publication.
        let retained = unsafe { storage.assume_init() };
        let [down_plan, up_plan] = prepared;
        Ok(Self {
            channel: Some(channel),
            path: None,
            retained: Some(retained),
            first_slot: Some(first),
            prepared: [Some(down_plan), Some(up_plan)],
            endpoints,
            stage: TunnelStage::Header(0),
            expected: None,
            deadline,
            job_deadline,
            last_now: now,
        })
    }
    fn is_current(&self) -> bool {
        if let Some(path) = &self.path {
            path.is_current()
        } else {
            self.retained
                .as_ref()
                .is_some_and(|tunnel| tunnel.bandwidth_ref().is_current())
        }
    }
    fn retained(&mut self) -> &mut ActiveTunnel {
        self.retained.as_mut().expect("retained tunnel transaction")
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = TunnelStage::Fault;
        if let Some(path) = &mut self.path {
            let _ = path.cancel();
        } else if let Some(channel) = &mut self.channel {
            let _ = channel.cancel();
        }
        Err(error)
    }
    pub fn cancel(&mut self) -> Result<(), Error> {
        match self.stage {
            TunnelStage::Done => Err(Error::Stopped),
            TunnelStage::Fault => Err(Error::Poisoned),
            _ => self.fail(Error::Cancelled),
        }
    }
    pub fn into_channel(mut self) -> Channel<R> {
        if let Some(path) = self.path.take() {
            path.into_channel()
        } else {
            self.channel.take().expect("retained channel")
        }
    }
    fn enter(&mut self, stage: TunnelStage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.deadline = now
            .checked_add(REQUEST_MS)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        Ok(())
    }
    fn start_path(&mut self, index: usize, now: u64) -> Result<(), Error> {
        let deadline = now
            .checked_add(REQUEST_MS)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        let job = now
            .checked_add(10_000)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        let prepared = self.prepared[index]
            .take()
            .ok_or(Error::UnexpectedReceipt)?;
        // Every check precedes ownership movement. The private path initializer
        // cannot fail after taking Channel/previous owners or allocate storage.
        let channel = self.channel.take().expect("retained transition channel");
        let reservation = self.retained().pending[index]
            .take()
            .expect("protected native path");
        let path = if index == 0 {
            let bandwidth = self
                .retained()
                .bandwidth
                .take()
                .expect("genuine bandwidth receipt");
            // SAFETY: constructor checked both protected plans/epochs/authority;
            // clocks were checked while all owners and Channel remained retained.
            unsafe {
                super::path::Activate::start_bandwidth(
                    channel,
                    bandwidth,
                    reservation,
                    prepared,
                    now,
                    deadline,
                    job,
                )
            }
        } else {
            let previous = self
                .retained()
                .previous
                .take()
                .expect("actual first path receipt");
            // SAFETY: actual first success remains in the preallocated wrapper;
            // opposite protected plan shares exact native grant and endpoint lease.
            unsafe {
                super::path::Activate::start_previous(
                    channel,
                    previous,
                    reservation,
                    prepared,
                    now,
                    deadline,
                    job,
                )
            }
        };
        self.path = Some(path);
        self.stage = if index == 0 {
            TunnelStage::First
        } else {
            TunnelStage::Second
        };
        Ok(())
    }
    fn request(&self) -> Result<(Endpoint, Address, Option<[u32; 1]>), Error> {
        let (index, header, data) = match self.stage {
            TunnelStage::Header(i) => (i, true, None),
            TunnelStage::Disabled(i) | TunnelStage::Verify(i) => (i, false, None),
            TunnelStage::Enable(i) => (i, false, Some([ENDPOINT_ENABLE])),
            _ => return Err(Error::Stopped),
        };
        let endpoint = self.endpoints[index];
        Ok((
            endpoint,
            Address {
                port: endpoint.port,
                space: Space::Port,
                offset: if header { 0 } else { endpoint.cap },
                words: if header { 8 } else { 1 },
            },
            data,
        ))
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        if !self.is_current() {
            return self.fail(Error::Revoked);
        }
        if self.expected.is_some() {
            return Ok(());
        }
        let (endpoint, address, data) = self.request()?;
        let deadline = self.deadline;
        let channel = self.channel.as_mut().expect("retained endpoint channel");
        let result = if let Some(data) = data {
            channel.write(endpoint.route, address, &data, now, deadline)
        } else {
            channel.read(endpoint.route, address, now, deadline)
        };
        match result {
            Ok(id) => {
                self.expected = Some(id);
                Ok(())
            }
            Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => Ok(()),
            Err(error) => self.fail(Error::Channel(error)),
        }
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<TunnelEvent>, Error> {
        if !self.is_current() {
            return self.fail(Error::Revoked);
        }
        let data = match reply {
            Reply::Configuration {
                upstream_port,
                data,
            } => {
                if upstream_port != self.request()?.0.upstream {
                    return self.fail(Error::Changed);
                }
                data
            }
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
            TunnelStage::Header(i) => {
                let header = AdapterHeader::parse(&data).map_err(|_| Error::UnexpectedReceipt)?;
                let expected = AdapterHeader {
                    raw: self.endpoints[i].header,
                };
                if header.kind() != expected.kind()
                    || header.reported_port() != self.endpoints[i].port
                    || header.first_capability() != expected.first_capability()
                {
                    return self.fail(Error::Changed);
                }
                self.enter(TunnelStage::Disabled(i), now)?;
            }
            TunnelStage::Disabled(i) => {
                let [raw] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                if raw & (1 << 31) != 0 {
                    return self.fail(Error::Busy);
                }
                if i == 0 {
                    self.enter(TunnelStage::Header(1), now)?;
                } else {
                    self.start_path(0, now)?;
                }
            }
            TunnelStage::Enable(i) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(TunnelStage::Verify(i), now)?;
            }
            TunnelStage::Verify(i) => {
                let [raw] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                // V is emitted exactly as the donor's write-valid control. Do
                // not invent a requirement that it persists in readable state.
                if raw & (1 << 31) == 0 {
                    return self.fail(Error::Readback);
                }
                self.retained().endpoints[i] = *raw;
                if i == 0 {
                    self.enter(TunnelStage::Enable(1), now)?;
                } else {
                    if !self.is_current() {
                        return self.fail(Error::Revoked);
                    }
                    self.stage = TunnelStage::Done;
                    return Ok(Some(TunnelEvent::Active(
                        self.retained.take().ok_or(Error::UnexpectedReceipt)?,
                    )));
                }
            }
            _ => return self.fail(Error::UnexpectedReceipt),
        }
        Ok(None)
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<TunnelEvent>, Error> {
        match self.stage {
            TunnelStage::Done => return Err(Error::Stopped),
            TunnelStage::Fault => return Err(Error::Poisoned),
            _ => {}
        }
        if !self.is_current() {
            return self.fail(Error::Revoked);
        }
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if now >= self.job_deadline {
            return self.fail(Error::Timeout);
        }
        if matches!(self.stage, TunnelStage::First | TunnelStage::Second) {
            match self.path.as_mut().expect("actual path engine").poll(now) {
                Err(error) => return self.fail(Error::Path(error)),
                Ok(Some(super::path::Event::Discarded(error))) => {
                    return Ok(Some(TunnelEvent::Discarded(error)));
                }
                Ok(Some(super::path::Event::Active(active))) => {
                    let path = self.path.take().expect("completed actual path engine");
                    self.channel = Some(path.into_channel());
                    if self.stage == TunnelStage::First {
                        let mut first = self
                            .first_slot
                            .take()
                            .expect("preallocated first-path wrapper");
                        first.as_mut().write(active);
                        // SAFETY: initialized exactly once with actual first success.
                        self.retained().previous = Some(unsafe { first.assume_init() });
                        if let Err(error) = self.start_path(1, now) {
                            return self.fail(error);
                        }
                    } else {
                        self.retained().path = Some(active);
                        if let Err(error) = self.enter(TunnelStage::Enable(0), now) {
                            return self.fail(error);
                        }
                    }
                }
                Ok(None) => {}
            }
            return Ok(None);
        }
        if now >= self.deadline {
            return self.fail(Error::Timeout);
        }
        match self
            .channel
            .as_mut()
            .expect("actual endpoint channel")
            .poll(now)
        {
            Err(error) => return self.fail(Error::Channel(error)),
            Ok(Some(channel::Event::Completed { request, reply })) => {
                if self.expected != Some(request) {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.expected = None;
                match self.complete(reply, now) {
                    Ok(Some(event)) => return Ok(Some(event)),
                    Ok(None) => {}
                    Err(error) => return self.fail(error),
                }
            }
            Ok(Some(channel::Event::Plug(event))) => return self.fail(Error::Hotplug(event)),
            Ok(Some(channel::Event::Notification(event))) => {
                return self.fail(Error::Notification(event));
            }
            Ok(Some(channel::Event::Discarded(error))) => {
                return Ok(Some(TunnelEvent::Discarded(error)));
            }
            Ok(None) => {}
        }
        if !matches!(self.stage, TunnelStage::First | TunnelStage::Second)
            && let Err(error) = self.submit(now)
        {
            return self.fail(error);
        }
        Ok(None)
    }
}

/// Separate source release-unused operation on a genuinely active tunnel.
/// Paths/endpoints stay active; max(consumed,900Mb/s) remains allocated.
pub struct ReleaseUnused<R: Registers> {
    core: Option<Allocate<R>>,
    tunnel: Option<Box<ActiveTunnel>>,
    done: bool,
    fault: bool,
}
impl<R: Registers> ReleaseUnused<R> {
    /// # Safety
    /// Same exact live physical Channel/tunnel and retained native guard. Real
    /// global accounting serializes this adjustment and retains consumed rights,
    /// the 900Mb/s floor, all path/endpoint authority and independent lifetimes.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,usb3::{ActiveTunnel,ReleaseUnused},ring::Registers};
    /// fn start<R:Registers>(c:Channel<R>,t:Box<ActiveTunnel>){let _=ReleaseUnused::new(c,t,0);}
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        mut tunnel: Box<ActiveTunnel>,
        now: u64,
    ) -> Result<Self, Error> {
        let bandwidth = tunnel.bandwidth_ref();
        if !bandwidth.is_current() {
            return Err(Error::Revoked);
        }
        let plan = plan(bandwidth.linked(), bandwidth.protected_grant())?;
        let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
        let job = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
        // Every fallible check precedes detachment. Both boxes remain owned
        // throughout the adjustment; neither Drop can return live path IDs.
        let bandwidth = tunnel.take_bandwidth();
        let core = Allocate::release_existing(channel, bandwidth, plan, now, deadline, job);
        Ok(Self {
            core: Some(core),
            tunnel: Some(tunnel),
            done: false,
            fault: false,
        })
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<TunnelEvent>, Error> {
        if self.done {
            return Err(Error::Stopped);
        }
        if self.fault {
            return Err(Error::Poisoned);
        }
        match self
            .core
            .as_mut()
            .expect("actual retained bandwidth engine")
            .poll(now)
        {
            Err(error) => {
                self.fault = true;
                Err(error)
            }
            Ok(Some(Event::Discarded(error))) => Ok(Some(TunnelEvent::Discarded(error))),
            Ok(Some(Event::Allocated(bandwidth))) => {
                let tunnel = self.tunnel.as_mut().expect("retained active paths");
                tunnel.put_bandwidth(bandwidth);
                if !tunnel.bandwidth_ref().is_current() {
                    self.fault = true;
                    return Err(Error::Revoked);
                }
                self.done = true;
                Ok(Some(TunnelEvent::Active(
                    self.tunnel.take().expect("complete actual owner chain"),
                )))
            }
            Ok(None) => Ok(None),
        }
    }
    pub fn cancel(&mut self) -> Result<(), Error> {
        if self.done {
            return Err(Error::Stopped);
        }
        if self.fault {
            return Err(Error::Poisoned);
        }
        self.fault = true;
        self.core.as_mut().expect("retained engine").cancel()
    }
    pub fn into_channel(mut self) -> Channel<R> {
        self.core.take().expect("retained engine").into_channel()
    }
}
/// Explicitly returned LOCAL path rights, after matching-epoch hardware stop.
/// Residual root bandwidth/accounting/permission and original link are retained.
/// This does not release native endpoint posted DMA/IRQ/IOMMU or redistribute a
/// branch's bandwidth. The real provider must independently retire those rights.
pub struct Reusable {
    pub residual: Box<Allocated>,
    /// Actual Down then Up allocations; these objects, not their numeric IDs,
    /// are the native allocator/credit/permission lifetime being returned.
    pub paths: [Arc<dyn super::path::Reservation>; 2],
}
/// Genuine local stopped observations. Drop quarantines the complete chain;
/// reusable rights are returned only by explicitly consuming this receipt.
pub struct Stopped {
    pub endpoints: [u32; 2],
    pub hops: [super::path::Words; 4],
    active: Option<Box<ActiveTunnel>>,
    epoch: Grant,
}
impl Stopped {
    pub fn bandwidth_rates(&self) -> Rates {
        self.active
            .as_ref()
            .expect("retained residual")
            .bandwidth_rates()
    }
    /// Return actual local reservations only after the live native guard is
    /// revalidated. Revocation keeps this exact receipt/owner chain recoverable.
    /// A true snapshot is backed by Reservation's actual exclusive in-flight
    /// lifetime; it cannot substitute for reset serialization or endpoint drain.
    pub fn into_reusable(mut self: Box<Self>) -> Result<Reusable, (Error, Box<Self>)> {
        let bandwidth = self
            .active
            .as_ref()
            .expect("retained complete stopped chain")
            .bandwidth_ref();
        if !bandwidth.is_current() || bandwidth.protected_grant() != self.epoch {
            return Err((Error::Revoked, self));
        }
        let mut active = self.active.take().expect("actual stopped chain");
        let path = active.path.take().expect("both actual path receipts");
        // SAFETY: this type is minted only after both PE0, four EN0/PENDING0
        // readbacks, exact owned-hop identity and matching live native epoch.
        // Independent endpoint/native attachment lifetime stays with residual.
        let (residual, paths) = unsafe { path.release_stopped() };
        Ok(Reusable { residual, paths })
    }
}
pub enum StopEvent {
    Stopped(Box<Stopped>),
    Discarded(config::Error),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum StopStage {
    Header(usize),
    DisableEndpoint(usize),
    VerifyEndpoint(usize),
    ReadHop(usize),
    DisableHop(usize, super::path::Words),
    Drain(usize),
    VerifyHop(usize),
    Done,
    Fault,
}
struct StopRequest {
    route: Route,
    upstream: u8,
    address: Address,
    data: Option<[u32; 2]>,
}
/// Exact normal USB3 deactivate: Down/Up endpoints, Down/Up paths, forward hops.
/// Does NOT call release-unused or manufacture a zero-bandwidth/global release.
pub struct StopTunnel<R: Registers> {
    channel: Option<Channel<R>>,
    active: Option<Box<ActiveTunnel>>,
    result: Option<Box<Stopped>>,
    epoch: Grant,
    endpoints: [Endpoint; 2],
    hops: [super::path::DrainHop; 4],
    stage: StopStage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    last_now: u64,
    next_poll: u64,
}
impl<R: Registers> StopTunnel<R> {
    /// # Safety
    /// Actual Channel, complete tunnel and native reset/topology/permission guard
    /// identify the same physical lifetime, exclusively idle and serialized.
    /// Native host submission admission is closed and all independent endpoint
    /// posted-DMA/IRQ/IOMMU/power resources stay retained. The local path drain
    /// cannot certify those independent lifetimes or authorize reset/reassignment.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,usb3::{ActiveTunnel,StopTunnel},ring::Registers};
    /// fn stop<R:Registers>(c:Channel<R>,t:Box<ActiveTunnel>){let _=StopTunnel::new(c,t,0);}
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        active: Box<ActiveTunnel>,
        now: u64,
    ) -> Result<Self, Error> {
        unsafe { Self::new_inner(channel, active, now, alloc) }
    }
    #[cfg(test)]
    pub(super) unsafe fn new_without_storage(
        channel: Channel<R>,
        active: Box<ActiveTunnel>,
        now: u64,
    ) -> Result<Self, Error> {
        unsafe fn refuse(_: Layout) -> *mut u8 {
            core::ptr::null_mut()
        }
        unsafe { Self::new_inner(channel, active, now, refuse) }
    }
    unsafe fn new_inner(
        channel: Channel<R>,
        active: Box<ActiveTunnel>,
        now: u64,
        allocate: unsafe fn(Layout) -> *mut u8,
    ) -> Result<Self, Error> {
        let bandwidth = active.bandwidth_ref();
        if !bandwidth.is_current() {
            return Err(Error::Revoked);
        }
        let epoch = bandwidth.protected_grant();
        let (parent, child) = bandwidth.linked().retained_routers().map_err(Error::Link)?;
        let up = active.path.as_ref().ok_or(Error::UnexpectedReceipt)?;
        let down = up.previous();
        let allocations = [down.protected_allocation(), up.protected_allocation()];
        for (i, path) in allocations.iter().enumerate() {
            if path.identity != epoch.identity
                || path.topology_epoch != epoch.topology_epoch
                || path.grant_epoch != epoch.grant_epoch
                || path.usb3_down != epoch.usb3_down
                || path.usb3_up != epoch.usb3_up
                || path.permission != Decision::Allowed
                || path.direction
                    != if i == 0 {
                        super::path::Direction::Downstream
                    } else {
                        super::path::Direction::Upstream
                    }
            {
                return Err(Error::Identity);
            }
        }
        let [d0, d1] = down.drain_hops().map_err(Error::Path)?;
        let [u0, u1] = up.drain_hops().map_err(Error::Path)?;
        let (dh, dc) = usb3_adapter(
            parent.retained_owner().target(),
            epoch.usb3_down,
            AdapterKind::Usb3Down,
        )?;
        let (uh, uc) = usb3_adapter(
            child.retained_owner().target(),
            epoch.usb3_up,
            AdapterKind::Usb3Up,
        )?;
        let endpoints = [
            Endpoint {
                route: parent.route,
                port: epoch.usb3_down,
                upstream: parent.retained_owner().target().upstream_port,
                cap: dc,
                header: dh.raw,
            },
            Endpoint {
                route: child.route,
                port: epoch.usb3_up,
                upstream: child.retained_owner().target().upstream_port,
                cap: uc,
                header: uh.raw,
            },
        ];
        let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
        let job_deadline = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
        // Reserve result storage before any normal-stop write; no late owner
        // allocation after partial disable or drain, and no allocation on return.
        let ptr = unsafe { allocate(Layout::new::<Stopped>()) }.cast::<Stopped>();
        if ptr.is_null() {
            return Err(Error::Allocation);
        }
        let result = unsafe {
            ptr.write(Stopped {
                endpoints: [0; 2],
                hops: [super::path::Words { raw: [0; 2] }; 4],
                active: None,
                epoch,
            });
            Box::from_raw(ptr)
        };
        Ok(Self {
            channel: Some(channel),
            active: Some(active),
            result: Some(result),
            epoch,
            endpoints,
            hops: [d0, d1, u0, u1],
            stage: StopStage::Header(0),
            expected: None,
            deadline,
            job_deadline,
            last_now: now,
            next_poll: now,
        })
    }
    fn is_current(&self) -> bool {
        self.active.as_ref().is_some_and(|t| {
            let b = t.bandwidth_ref();
            b.is_current() && b.protected_grant() == self.epoch
        })
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = StopStage::Fault;
        let _ = self
            .channel
            .as_mut()
            .expect("retained stop channel")
            .cancel();
        Err(error)
    }
    pub fn cancel(&mut self) -> Result<(), Error> {
        match self.stage {
            StopStage::Done => Err(Error::Stopped),
            StopStage::Fault => Err(Error::Poisoned),
            _ => self.fail(Error::Cancelled),
        }
    }
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("retained stop channel")
    }
    fn enter(&mut self, stage: StopStage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.next_poll = now;
        self.deadline = now
            .checked_add(REQUEST_MS)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        Ok(())
    }
    fn request(&self) -> Result<StopRequest, Error> {
        match self.stage {
            StopStage::Header(i) => {
                let e = self.endpoints[i];
                Ok(StopRequest {
                    route: e.route,
                    upstream: e.upstream,
                    address: Address {
                        port: e.port,
                        space: Space::Port,
                        offset: 0,
                        words: 8,
                    },
                    data: None,
                })
            }
            StopStage::DisableEndpoint(i) | StopStage::VerifyEndpoint(i) => {
                let e = self.endpoints[i];
                Ok(StopRequest {
                    route: e.route,
                    upstream: e.upstream,
                    address: Address {
                        port: e.port,
                        space: Space::Port,
                        offset: e.cap,
                        words: 1,
                    },
                    data: if matches!(self.stage, StopStage::DisableEndpoint(_)) {
                        Some([1 << 30, 0])
                    } else {
                        None
                    },
                })
            }
            StopStage::ReadHop(i)
            | StopStage::Drain(i)
            | StopStage::VerifyHop(i)
            | StopStage::DisableHop(i, _) => {
                let h = self.hops[i];
                Ok(StopRequest {
                    route: h.route,
                    upstream: h.upstream,
                    address: Address {
                        port: h.port,
                        space: Space::Hops,
                        offset: h.id * 2,
                        words: 2,
                    },
                    data: if let StopStage::DisableHop(_, words) = self.stage {
                        Some(words.raw)
                    } else {
                        None
                    },
                })
            }
            _ => Err(Error::Stopped),
        }
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        if !self.is_current() {
            return self.fail(Error::Revoked);
        }
        if self.expected.is_some() || now < self.next_poll {
            return Ok(());
        }
        let StopRequest {
            route,
            address,
            data,
            ..
        } = self.request()?;
        let deadline = self.deadline;
        let channel = self.channel.as_mut().expect("retained actual channel");
        let result = if let Some(data) = data {
            channel.write(
                route,
                address,
                &data[..usize::from(address.words)],
                now,
                deadline,
            )
        } else {
            channel.read(route, address, now, deadline)
        };
        match result {
            Ok(id) => {
                self.expected = Some(id);
                Ok(())
            }
            Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => Ok(()),
            Err(error) => self.fail(Error::Channel(error)),
        }
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<StopEvent>, Error> {
        if !self.is_current() {
            return self.fail(Error::Revoked);
        }
        let data = match reply {
            Reply::Configuration {
                upstream_port,
                data,
            } => {
                if upstream_port != self.request()?.upstream {
                    return self.fail(Error::Changed);
                }
                data
            }
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
            StopStage::Header(i) => {
                let actual = AdapterHeader::parse(&data).map_err(|_| Error::UnexpectedReceipt)?;
                let expected = AdapterHeader {
                    raw: self.endpoints[i].header,
                };
                if actual.kind() != expected.kind()
                    || actual.reported_port() != self.endpoints[i].port
                    || actual.first_capability() != expected.first_capability()
                {
                    return self.fail(Error::Changed);
                }
                self.enter(
                    if i == 0 {
                        StopStage::Header(1)
                    } else {
                        StopStage::DisableEndpoint(0)
                    },
                    now,
                )?;
            }
            StopStage::DisableEndpoint(i) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(StopStage::VerifyEndpoint(i), now)?;
            }
            StopStage::VerifyEndpoint(i) => {
                let [word] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                if word & (1 << 31) != 0 {
                    return self.fail(Error::Readback);
                }
                self.result
                    .as_mut()
                    .expect("preallocated stopped receipt")
                    .endpoints[i] = *word;
                self.enter(
                    if i == 0 {
                        StopStage::DisableEndpoint(1)
                    } else {
                        StopStage::ReadHop(0)
                    },
                    now,
                )?;
            }
            StopStage::ReadHop(i) | StopStage::Drain(i) | StopStage::VerifyHop(i) => {
                let raw: [u32; 2] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::UnexpectedReceipt)?;
                let words = super::path::Words { raw };
                if !self.hops[i].matches(words) {
                    return self.fail(Error::Changed);
                }
                match self.stage {
                    StopStage::ReadHop(i) => {
                        if raw[0] & (1 << 31) != 0 {
                            self.enter(
                                StopStage::DisableHop(
                                    i,
                                    super::path::Words {
                                        raw: [raw[0] & !(1 << 31), raw[1]],
                                    },
                                ),
                                now,
                            )?;
                        } else {
                            self.enter(
                                if raw[1] & (1 << 28) == 0 {
                                    StopStage::VerifyHop(i)
                                } else {
                                    StopStage::Drain(i)
                                },
                                now,
                            )?;
                        }
                    }
                    StopStage::Drain(i) | StopStage::VerifyHop(i) => {
                        if raw[0] & (1 << 31) != 0 {
                            return self.fail(Error::Readback);
                        }
                        if raw[1] & (1 << 28) != 0 {
                            self.stage = StopStage::Drain(i);
                            self.next_poll = now.checked_add(1).ok_or(Error::ClockOverflow)?;
                        } else if matches!(self.stage, StopStage::Drain(_)) {
                            self.stage = StopStage::VerifyHop(i);
                        } else {
                            self.result.as_mut().expect("actual stopped receipt").hops[i] = words;
                            if i < 3 {
                                self.enter(StopStage::ReadHop(i + 1), now)?;
                            } else {
                                if !self.is_current() {
                                    return self.fail(Error::Revoked);
                                }
                                let mut result =
                                    self.result.take().ok_or(Error::UnexpectedReceipt)?;
                                result.active = self.active.take();
                                self.stage = StopStage::Done;
                                return Ok(Some(StopEvent::Stopped(result)));
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
            StopStage::DisableHop(i, _) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(StopStage::Drain(i), now)?;
            }
            _ => return self.fail(Error::UnexpectedReceipt),
        }
        Ok(None)
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<StopEvent>, Error> {
        match self.stage {
            StopStage::Done => return Err(Error::Stopped),
            StopStage::Fault => return Err(Error::Poisoned),
            _ => {}
        }
        if !self.is_current() {
            return self.fail(Error::Revoked);
        }
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if now >= self.deadline || now >= self.job_deadline {
            return self.fail(Error::Timeout);
        }
        match self
            .channel
            .as_mut()
            .expect("retained actual stop channel")
            .poll(now)
        {
            Err(error) => return self.fail(Error::Channel(error)),
            Ok(Some(channel::Event::Completed { request, reply })) => {
                if self.expected != Some(request) {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.expected = None;
                match self.complete(reply, now) {
                    Ok(Some(event)) => return Ok(Some(event)),
                    Ok(None) => {}
                    Err(error) => return self.fail(error),
                }
            }
            Ok(Some(channel::Event::Plug(event))) => return self.fail(Error::Hotplug(event)),
            Ok(Some(channel::Event::Notification(event))) => {
                return self.fail(Error::Notification(event));
            }
            Ok(Some(channel::Event::Discarded(error))) => {
                return Ok(Some(StopEvent::Discarded(error)));
            }
            Ok(None) => {}
        }
        self.submit(now)?;
        Ok(None)
    }
}
