// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Two-ended Gen2/3 USB4-router link bonding and activation from Linux switch.c.
//! Both real configured router reservations survive partial failure. Native
//! partner discovery, policy, power and attachment are required, not fabricated.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    domain::Identity,
    ring::{self, Registers},
    router::{Configured, Decision},
    topology::{AdapterKind, AdapterObservation, Inventory},
};
use alloc::{alloc::alloc, boxed::Box, sync::Arc};
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, Ordering};
const TARGET_WIDTH: u32 = 3 << 4;
const BOND: u32 = 1 << 15;
const CONFIGURED: u32 = 1 << 3;
const REQUEST_MS: u64 = 500;
const JOB_MS: u64 = 20_000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_reservations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}
/// One protected native observation, retaining both actual partner relations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedLane {
    pub route: Route,
    pub port: u8,
    pub lane_index: u8,
    pub dual_port: u8,
    pub remote_route: Route,
    pub remote_port: u8,
}
/// Physical primary/secondary lane identities from actual protected topology,
/// including reciprocal remote and dual-lane relations. Not port adjacency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partners {
    pub identity: Identity,
    pub topology_epoch: u64,
    pub child: [u8; 2],
    pub parent: [u8; 2],
    /// Child primary/secondary, then parent primary/secondary observations.
    pub observations: [ObservedLane; 4],
}
/// Actual exclusive observed reciprocal link/power transition reservation.
///
/// # Safety
/// The partner map is from real native topology/DROM observations, including
/// both directions and lane0/lane1 membership, at the stated NHI reset and
/// topology epochs. It belongs to the exact two configured owners until final
/// restoration/reset or actual transfer, not a new tuple of chosen integers.
/// Native software CM owns both ends; policy, router lifetime, CL0/power and
/// dependent-path serialization are real and stable. No firmware CM may write
/// the link. Independent NHI/domain/IMR/power/endpoint DMA/IRQ/IOMMU resources
/// remain held through actual final drain. This does not implement a provider
/// for missing native discovery or _OSC/security/attachment services.
pub unsafe trait Reservation: Send + Sync {
    fn observed(&self) -> Partners;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Allocation,
    Identity,
    Topology,
    Unsupported,
    Capability,
    Policy,
    ClockOverflow,
    ClockRegressed,
    Timeout,
    NoConnection,
    NotCl0,
    Readback,
    ChangedLink,
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
    Channel(channel::Error),
}
impl From<channel::Error> for Error {
    fn from(error: channel::Error) -> Self {
        Self::Channel(error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credit {
    pub route: Route,
    pub port: u8,
    pub raw: u32,
}
impl Credit {
    pub fn nonflow(self) -> u16 {
        (self.raw & 1023) as u16
    }
    pub fn total(self) -> u16 {
        ((self.raw >> 20) & 1023) as u16
    }
}
/// Actual dual-width/configured observations plus both retained router leases.
/// This does not authorize tunnels or release any independent DMA resource.
pub struct Linked {
    pub partners: Partners,
    pub generation: u8,
    pub link_usb4: bool,
    pub credits: [Credit; 4],
    pub child_width: u32,
    pub parent_width: u32,
    pub configured: [u32; 2],
    routers: Option<(Configured, Configured)>,
    reservation: Option<Arc<dyn Reservation>>,
    changed: bool,
}
impl Linked {
    /// Read-only retained native ownership for a dependent local CM operation.
    pub(super) fn retained_routers(&self) -> Result<(&Configured, &Configured), Error> {
        let (parent, child) = self.routers.as_ref().ok_or(Error::Topology)?;
        validate_router(parent)?;
        validate_router(child)?;
        Ok((parent, child))
    }
    pub(super) fn protected_partners(&self) -> Partners {
        self.reservation
            .as_ref()
            .expect("retained link reservation")
            .observed()
    }
    /// # Safety
    /// Both real link states have been restored/reset with all dependent path,
    /// power and DMA/IRQ lifetimes satisfied, or both configured owners and the
    /// exact active link reservation are already independently retained by the
    /// native CM. Never substitute these local observations for endpoint drain.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::link::Linked;
    /// fn release(link:Linked){link.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        if let Some((parent, child)) = self.routers.take() {
            // SAFETY: caller proves actual restoration or both active transfers.
            unsafe {
                parent.retire();
                child.retire();
            }
        }
        self.reservation.take();
    }
}
fn quarantine(reservation: &Arc<dyn Reservation>) {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
    core::mem::forget(reservation.clone());
}
impl Drop for Linked {
    fn drop(&mut self) {
        if self.changed
            && let Some(reservation) = &self.reservation
        {
            quarantine(reservation);
        }
    }
}
pub enum Event {
    Linked(Box<Linked>),
    Discarded(config::Error),
}
#[derive(Clone, Copy)]
struct Lane {
    route: Route,
    port: u8,
    upstream: u8,
    phy: u16,
    usb4: Option<u16>,
}
struct Plan {
    partners: Partners,
    lanes: [Lane; 4],
    link_usb4: bool,
}
fn adapter(
    inventory: &Inventory,
    port: u8,
) -> Option<(
    &super::topology::AdapterHeader,
    &[super::topology::Capability],
)> {
    inventory.adapters.iter().find_map(|item| match item {
        AdapterObservation::Present {
            port: number,
            header,
            capabilities,
        } if *number == port => Some((header, capabilities.as_slice())),
        _ => None,
    })
}
fn lane(inventory: &Inventory, port: u8, primary: bool) -> Result<Lane, Error> {
    let (header, caps) = adapter(inventory, port).ok_or(Error::Topology)?;
    if port == 0 || header.kind() != AdapterKind::Lane {
        return Err(Error::Topology);
    }
    let mut phy = None;
    let mut usb4 = None;
    for cap in caps {
        let slot = match cap.id {
            1 => &mut phy,
            6 => &mut usb4,
            _ => continue,
        };
        let last = if cap.id == 1 { 8190 } else { 8192 - 0x14 };
        if slot.is_some() || cap.offset < 8 || cap.offset > last {
            return Err(Error::Capability);
        }
        *slot = Some(cap.offset);
    }
    if primary && usb4.is_none() {
        return Err(Error::Capability);
    }
    Ok(Lane {
        route: inventory.path.route(),
        port,
        upstream: inventory.upstream_port,
        phy: phy.ok_or(Error::Capability)?,
        usb4,
    })
}
fn validate_router(router: &Configured) -> Result<(), Error> {
    let owner = router.retained_owner();
    let target = owner.target();
    let policy = owner.policy();
    if owner.identity() != router.identity
        || router.route != target.path.route()
        || router.header.reported_route() != router.route.raw()
        || router.header.reported_depth() != target.path.depth()
        || router.header.reported_upstream() != target.upstream_port
        || !router.header.enabled()
    {
        return Err(Error::Identity);
    }
    if !matches!(router.header.usb4_version(), 1 | 2) {
        return Err(Error::Unsupported);
    }
    if router.header.raw[0] != target.header.raw[0]
        || router.header.max_port() != target.header.max_port()
        || router.header.first_capability() != target.header.first_capability()
        || router.header.usb4_version() != target.header.usb4_version()
    {
        return Err(Error::Topology);
    }
    if policy.usb3 == Decision::Unresolved || policy.pcie == Decision::Unresolved {
        return Err(Error::Policy);
    }
    if target.path.depth() != 0
        && (!router
            .ready_status
            .is_some_and(|word| word & (1 << 24) != 0)
            || !router
                .configured_status
                .is_some_and(|word| word & (1 << 25) != 0)
            || router.setup_word.is_none())
    {
        return Err(Error::Topology);
    }

    if let Some(word) = router.setup_word
        && ((policy.usb3 == Decision::Denied && word & (1 << 25) != 0)
            || (policy.pcie == Decision::Denied && word & ((1 << 24) | (1 << 26)) != 0))
    {
        return Err(Error::Policy);
    }

    Ok(())
}
impl Plan {
    fn new(
        parent: &Configured,
        child: &Configured,
        reservation: &dyn Reservation,
    ) -> Result<Self, Error> {
        validate_router(parent)?;
        validate_router(child)?;
        let partners = reservation.observed();
        if partners.identity != parent.identity
            || partners.identity != child.identity
            || partners.identity.epoch == 0
            || partners.topology_epoch == 0
        {
            return Err(Error::Identity);
        }
        let parent_inv = parent.retained_owner().target();
        let child_inv = child.retained_owner().target();
        let actual_parent = child.retained_owner().parent().ok_or(Error::Topology)?;
        let depth = child_inv.path.depth();
        if depth == 0 || depth > 5 || parent_inv.path.depth() + 1 != depth {
            return Err(Error::Topology);
        }
        let shift = (depth - 1) * 8;
        let mask = (1u64 << shift) - 1;
        if child.route.raw() & mask != parent.route.raw()
            || actual_parent.path.route() != parent.route
            || actual_parent.header.raw[0] != parent.header.raw[0]
            || actual_parent.header.max_port() != parent.header.max_port()
            || actual_parent.upstream_port != parent_inv.upstream_port
        {
            return Err(Error::Topology);
        }
        let down = (child.route.raw() >> shift) as u8;
        if partners.child[0] != child_inv.upstream_port
            || partners.parent[0] != down
            || partners.child[0] == partners.child[1]
            || partners.parent[0] == partners.parent[1]
            || partners.parent.contains(&parent_inv.upstream_port)
        {
            return Err(Error::Topology);
        }
        let ports = [
            partners.child[0],
            partners.child[1],
            partners.parent[0],
            partners.parent[1],
        ];
        let routes = [child.route, child.route, parent.route, parent.route];
        for i in 0..4 {
            let observed = partners.observations[i];
            if observed.route != routes[i]
                || observed.port != ports[i]
                || observed.lane_index != (i % 2) as u8
                || observed.dual_port != ports[i ^ 1]
                || observed.remote_route != routes[i ^ 2]
                || observed.remote_port != ports[i ^ 2]
            {
                return Err(Error::Topology);
            }
        }
        let lanes = [
            lane(child_inv, partners.child[0], true)?,
            lane(child_inv, partners.child[1], false)?,
            lane(parent_inv, partners.parent[0], true)?,
            lane(parent_inv, partners.parent[1], false)?,
        ];
        for (i, item) in lanes[2..].iter().enumerate() {
            let expected = lane(actual_parent, item.port, i == 0)?;
            if expected.phy != item.phy || expected.usb4 != item.usb4 {
                return Err(Error::Topology);
            }
        }
        let link_usb4 = child.link_usb4.ok_or(Error::Topology)?;
        Ok(Self {
            partners,
            lanes,
            link_usb4,
        })
    }
}
fn generation(word: u32) -> Result<u8, Error> {
    match (word >> 16) & 15 {
        8 => Ok(2),
        4 => Ok(3),
        _ => Err(Error::Unsupported),
    }
}
fn width(word: u32) -> Result<u32, Error> {
    let width = (word >> 20) & 63;
    if matches!(width, 1 | 2) {
        Ok(width)
    } else {
        Err(Error::Unsupported)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Preflight(usize),
    Mode(usize),
    BondPermission,
    Supported(usize),
    PortWait,
    PortExhausted,
    Width(usize),
    TargetRead(usize),
    Generation(usize, u32),
    TargetWrite(usize, u32),
    TargetVerify(usize, u32),
    BondRead,
    BondWrite(u32),
    BondVerify,
    WidthWait,
    Credit(usize),
    Speed,
    ChildWidth,
    ConfigureRead(usize),
    ConfigureWrite(usize, u32),
    ConfigureVerify(usize, u32),
    Done,
    Fault,
}
/// Native Gen2/3 bonding plus child→parent configured operations. Real monotonic
/// milliseconds use Channel's clock. No sleep or fictitious provider is supplied.
pub struct Activate<R: Registers> {
    channel: Option<Channel<R>>,
    result: Option<Box<Linked>>,
    plan: Plan,
    stage: Stage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    last_now: u64,
    next_poll: u64,
    port_tries: u8,
    generation: Option<u8>,
    initial_width: Option<u32>,
    credits: [Option<Credit>; 4],
    child_width: u32,
    parent_width: u32,
    configured: [u32; 2],
}
impl<R: Registers> Activate<R> {
    /// # Safety
    /// Channel, both retained Configured owners and reciprocal partner
    /// reservation identify the exact same physical NHI and native ownership/
    /// reset/topology epochs. All real authority/power/CL0/attachment/IMR/policy
    /// and dependent-path grants hold. Channel is exclusively idle. Partners
    /// are actual observed reciprocal lanes, never inferred adjacent numbers.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{link::{Activate,Reservation},router::Configured,channel::Channel,ring::Registers};
    /// fn pair<R:Registers>(c:Channel<R>,p:Configured,u:Configured,r:Arc<dyn Reservation>){let _=Activate::new(c,p,u,r,0);}
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        parent: Configured,
        child: Configured,
        reservation: Arc<dyn Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        // SAFETY: this entry point carries the exact physical pairing contract.
        unsafe { Self::new_inner(channel, parent, child, reservation, now, alloc) }
    }
    #[cfg(test)]
    pub(super) unsafe fn new_without_storage(
        channel: Channel<R>,
        parent: Configured,
        child: Configured,
        reservation: Arc<dyn Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        unsafe fn refuse(_: Layout) -> *mut u8 {
            core::ptr::null_mut()
        }
        // SAFETY: the model supplies the same physical pairing proof; allocation
        // refusal is local, deterministic and cannot affect another test thread.
        unsafe { Self::new_inner(channel, parent, child, reservation, now, refuse) }
    }
    unsafe fn new_inner(
        channel: Channel<R>,
        parent: Configured,
        child: Configured,
        reservation: Arc<dyn Reservation>,
        now: u64,
        allocate: unsafe fn(Layout) -> *mut u8,
    ) -> Result<Self, Error> {
        let plan = Plan::new(&parent, &child, &*reservation)?;
        let job_deadline = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
        let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
        // Reserve the final receipt AND both active owners before publication.
        // No link-owned allocation, vector growth or new owner bundle is needed
        // after mutation. A null allocation leaves both Configured drops subject
        // to their existing active-router quarantine contract.
        let layout = Layout::new::<Linked>();
        // SAFETY: allocate is alloc, or the test-only null allocator, and receives
        // exactly the nonzero layout used by the resulting Box's deallocator.
        let storage = unsafe { allocate(layout) }.cast::<Linked>();
        if storage.is_null() {
            return Err(Error::Allocation);
        }
        let receipt = Linked {
            partners: plan.partners,
            generation: 0,
            link_usb4: plan.link_usb4,
            credits: plan.lanes.map(|lane| Credit {
                route: lane.route,
                port: lane.port,
                raw: 0,
            }),
            child_width: 0,
            parent_width: 0,
            configured: [0; 2],
            routers: Some((parent, child)),
            reservation: Some(reservation),
            changed: false,
        };
        // SAFETY: storage is a fresh aligned allocation of Linked's exact layout.
        // Initialize it once before Box takes unique ownership. Incomplete private
        // metadata cannot escape Activate until every real receipt is validated.
        let result = unsafe {
            storage.write(receipt);
            Box::from_raw(storage)
        };
        Ok(Self {
            channel: Some(channel),
            result: Some(result),
            plan,
            stage: Stage::Preflight(0),
            expected: None,
            deadline,
            job_deadline,
            last_now: now,
            next_poll: now,
            port_tries: 0,
            generation: None,
            initial_width: None,
            credits: [None; 4],
            child_width: 0,
            parent_width: 0,
            configured: [0; 2],
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
        match self.stage {
            Stage::Done => Err(Error::Stopped),
            Stage::Fault => Err(Error::Poisoned),
            _ => self.fail(Error::Cancelled),
        }
    }
    /// Both routers remain quarantined after uncertainty, including when the
    /// channel moves out. No cleanup write certifies restoration or DMA drain.
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("owned channel")
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
    fn enter_width_wait(&mut self, now: u64) -> Result<(), Error> {
        self.enter(Stage::WidthWait, now)?;
        self.deadline = now
            .checked_add(100)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        Ok(())
    }
    fn next_lane(&mut self, index: usize, was_single: bool, now: u64) -> Result<(), Error> {
        if index < 3 {
            self.enter(Stage::Width(index + 1), now)
        } else if was_single {
            self.enter(Stage::BondRead, now)
        } else {
            self.enter_width_wait(now)
        }
    }
    fn request(&self) -> Result<(Lane, Address, Option<[u32; 1]>), Error> {
        let (index, offset, words, data) = match self.stage {
            Stage::Preflight(i) => (i, self.plan.lanes[i].phy, 2, None),
            Stage::Mode(i) => (
                i * 2,
                self.plan.lanes[i * 2].usb4.ok_or(Error::Capability)? + 0x12,
                1,
                None,
            ),
            Stage::BondPermission => (
                0,
                self.plan.lanes[0].usb4.ok_or(Error::Capability)? + 0x12,
                1,
                None,
            ),
            Stage::Supported(i) => (i * 2, self.plan.lanes[i * 2].phy, 1, None),
            Stage::PortWait => (3, self.plan.lanes[3].phy, 2, None),
            Stage::Width(i)
            | Stage::TargetRead(i)
            | Stage::Generation(i, _)
            | Stage::TargetVerify(i, _) => (i, self.plan.lanes[i].phy + 1, 1, None),
            Stage::TargetWrite(i, value) => (i, self.plan.lanes[i].phy + 1, 1, Some([value])),
            Stage::BondRead | Stage::BondVerify | Stage::WidthWait => {
                (2, self.plan.lanes[2].phy + 1, 1, None)
            }
            Stage::BondWrite(value) => (2, self.plan.lanes[2].phy + 1, 1, Some([value])),
            Stage::Credit(i) => {
                let index = [2, 3, 0, 1][i];
                (index, 4, 1, None)
            }
            Stage::Speed | Stage::ChildWidth => (0, self.plan.lanes[0].phy + 1, 1, None),
            Stage::ConfigureRead(end) | Stage::ConfigureVerify(end, _) => {
                let i = end * 2;
                (
                    i,
                    self.plan.lanes[i].usb4.ok_or(Error::Capability)? + 0x13,
                    1,
                    None,
                )
            }
            Stage::ConfigureWrite(end, value) => {
                let i = end * 2;
                (
                    i,
                    self.plan.lanes[i].usb4.ok_or(Error::Capability)? + 0x13,
                    1,
                    Some([value]),
                )
            }
            _ => return Err(Error::Stopped),
        };
        let lane = self.plan.lanes[index];
        Ok((
            lane,
            Address {
                port: lane.port,
                space: Space::Port,
                offset,
                words,
            },
            data,
        ))
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        if self.expected.is_some() || now < self.next_poll || self.stage == Stage::PortExhausted {
            return Ok(());
        }
        let (lane, address, data) = self.request()?;
        let deadline = self.deadline;
        let result = if let Some(data) = data {
            let result = self
                .channel()
                .write(lane.route, address, &data, now, deadline);
            if !matches!(
                result,
                Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full))
            ) {
                self.result.as_mut().expect("retained link owners").changed = true;
            }
            result
        } else {
            self.channel().read(lane.route, address, now, deadline)
        };
        match result {
            Ok(id) => {
                self.expected = Some(id);
                Ok(())
            }
            Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => Ok(()),
            Err(error) => self.fail(error.into()),
        }
    }
    fn receipt(&mut self) -> Result<Option<Event>, Error> {
        let [Some(a), Some(b), Some(c), Some(d)] = self.credits else {
            return Err(Error::UnexpectedReceipt);
        };
        let generation = self.generation.ok_or(Error::UnexpectedReceipt)?;
        let mut result = self.result.take().ok_or(Error::UnexpectedReceipt)?;
        result.generation = generation;
        result.credits = [a, b, c, d];
        result.child_width = self.child_width;
        result.parent_width = self.parent_width;
        result.configured = self.configured;
        self.stage = Stage::Done;
        Ok(Some(Event::Linked(result)))
    }

    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
        let data = match reply {
            Reply::Configuration {
                upstream_port,
                data,
            } => {
                let (lane, _, _) = self.request()?;
                if upstream_port != lane.upstream {
                    return self.fail(Error::ChangedLink);
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
                if matches!(self.stage, Stage::BondVerify | Stage::WidthWait) && code == 15 {
                    self.next_poll = now.checked_add(1).ok_or(Error::ClockOverflow)?;
                    return Ok(None);
                }
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
            Stage::Preflight(i) => {
                let [phy, value] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                if (phy >> 8) & 255 != 1 || ((phy >> 20) & 63) & 2 == 0 {
                    return self.fail(Error::Unsupported);
                }
                let generation = generation(*value)?;
                let width = width(*value)?;
                if (value >> 26) & 15 != 2 {
                    return self.fail(Error::NotCl0);
                }
                if self.generation.is_some_and(|known| known != generation)
                    || self.initial_width.is_some_and(|known| known != width)
                {
                    return self.fail(Error::ChangedLink);
                }
                self.generation = Some(generation);
                self.initial_width = Some(width);
                self.enter(
                    if i < 3 {
                        Stage::Preflight(i + 1)
                    } else {
                        Stage::Mode(0)
                    },
                    now,
                )?;
            }
            Stage::Mode(end) => {
                if (word()? & (1 << 9) == 0) != self.plan.link_usb4 {
                    return self.fail(Error::ChangedLink);
                }
                self.enter(
                    if end == 0 {
                        Stage::Mode(1)
                    } else {
                        Stage::BondPermission
                    },
                    now,
                )?;
            }
            Stage::BondPermission => {
                if word()? & (1 << 8) == 0 {
                    return self.fail(Error::Unsupported);
                }
                self.enter(Stage::Supported(0), now)?;
            }
            Stage::Supported(end) => {
                if ((word()? >> 20) & 63) & 2 == 0 {
                    return self.fail(Error::Unsupported);
                }
                self.enter(
                    if end == 0 {
                        Stage::Supported(1)
                    } else {
                        Stage::PortWait
                    },
                    now,
                )?;
            }
            Stage::PortWait => {
                let [_, value] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                self.port_tries += 1;
                match (value >> 26) & 15 {
                    2 => self.enter(Stage::Width(0), now)?,
                    0 | 7 => return self.fail(Error::NoConnection),
                    1 => {
                        self.enter(
                            if self.port_tries >= 10 {
                                Stage::PortExhausted
                            } else {
                                Stage::PortWait
                            },
                            now,
                        )?;
                        self.next_poll = now.checked_add(100).ok_or(Error::ClockOverflow)?;
                        self.deadline = self
                            .next_poll
                            .checked_add(REQUEST_MS)
                            .ok_or(Error::ClockOverflow)?
                            .min(self.job_deadline);
                    }
                    3..=6 => return self.fail(Error::NotCl0),
                    _ => return self.fail(Error::Unsupported),
                }
            }
            Stage::Width(i) => {
                if width(word()?)? == 1 {
                    self.enter(Stage::TargetRead(i), now)?;
                } else {
                    self.next_lane(i, false, now)?;
                }
            }
            Stage::TargetRead(i) => self.enter(Stage::Generation(i, word()?), now)?,
            Stage::Generation(i, original) => {
                if Some(generation(word()?)?) != self.generation {
                    return self.fail(Error::ChangedLink);
                }
                self.enter(
                    Stage::TargetWrite(i, (original & !TARGET_WIDTH) | TARGET_WIDTH),
                    now,
                )?;
            }
            Stage::TargetWrite(i, value) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::TargetVerify(i, value), now)?;
            }
            Stage::TargetVerify(i, value) => {
                if word()? & TARGET_WIDTH != value & TARGET_WIDTH {
                    return self.fail(Error::Readback);
                }
                self.next_lane(i, true, now)?;
            }
            Stage::BondRead => self.enter(Stage::BondWrite(word()? | BOND), now)?,
            Stage::BondWrite(_) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter_width_wait(now)?;
                self.stage = Stage::BondVerify;
            }
            Stage::BondVerify => {
                if word()? & BOND == 0 {
                    return self.fail(Error::Readback);
                }
                self.stage = Stage::WidthWait;
            }
            Stage::WidthWait => {
                let value = word()?;
                if width(value)? == 2 {
                    self.parent_width = value;
                    self.enter(Stage::Credit(0), now)?;
                } else {
                    self.next_poll = now.checked_add(1).ok_or(Error::ClockOverflow)?;
                }
            }
            Stage::Credit(i) => {
                let lane = self.plan.lanes[[2, 3, 0, 1][i]];
                self.credits[i] = Some(Credit {
                    route: lane.route,
                    port: lane.port,
                    raw: word()?,
                });
                self.enter(
                    if i < 3 {
                        Stage::Credit(i + 1)
                    } else {
                        Stage::Speed
                    },
                    now,
                )?;
            }
            Stage::Speed => {
                if Some(generation(word()?)?) != self.generation {
                    return self.fail(Error::ChangedLink);
                }
                self.enter(Stage::ChildWidth, now)?;
            }
            Stage::ChildWidth => {
                let value = word()?;
                if width(value)? != 2 {
                    return self.fail(Error::Readback);
                }
                self.child_width = value;
                self.enter(Stage::ConfigureRead(0), now)?;
            }
            Stage::ConfigureRead(end) => {
                self.enter(Stage::ConfigureWrite(end, word()? | CONFIGURED), now)?
            }
            Stage::ConfigureWrite(end, value) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::ConfigureVerify(end, value), now)?;
            }
            Stage::ConfigureVerify(end, value) => {
                let actual = word()?;
                if actual & CONFIGURED != value & CONFIGURED {
                    return self.fail(Error::Readback);
                }
                self.configured[end] = actual;
                if end == 0 {
                    self.enter(Stage::ConfigureRead(1), now)?;
                } else {
                    return self.receipt();
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
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if self.stage == Stage::PortExhausted && now >= self.next_poll {
            return self.fail(Error::NoConnection);
        }
        if now >= self.deadline || now >= self.job_deadline {
            return self.fail(Error::Timeout);
        }
        match self.channel().poll(now) {
            Err(error) => return self.fail(error.into()),
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
        if let Err(error) = self.submit(now) {
            return self.fail(error);
        }
        Ok(None)
    }
}
