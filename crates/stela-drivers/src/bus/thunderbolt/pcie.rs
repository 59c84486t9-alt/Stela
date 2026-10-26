// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! Two-direction PCIe tunnels over an actual retained adjacent USB4v1 link.
//!
//! Linux tunnel.c/path.c/switch.c protocol, using the existing native path and
//! Channel engines. Platform authorization, shared HopID/credit allocation and
//! endpoint DMA protection must be real; this module does not supply substitutes.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    domain::Identity,
    link::{self, Linked},
    path::{self, Direction, LaneCredits},
    ring::{self, Registers},
    router::Decision,
    topology::{AdapterHeader, AdapterKind, AdapterObservation, Inventory},
};
use alloc::{alloc::alloc, boxed::Box, sync::Arc};
use core::{
    alloc::Layout,
    mem::MaybeUninit,
    sync::atomic::{AtomicU64, Ordering},
};
const ENABLE: u32 = 1 << 31;
const PENDING: u32 = 1 << 28;
const REQUEST_MS: u64 = 500;
const JOB_MS: u64 = 30_000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_reservations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub identity: Identity,
    pub topology_epoch: u64,
    pub grant_epoch: u64,
    pub pcie_down: u8,
    pub pcie_up: u8,
    /// Downstream then upstream; each pair is (ingress HopID, outgoing HopID).
    pub hops: [[(u16, u16); 2]; 2],
    pub lane_credits: [LaneCredits; 2],
    pub permission: Decision,
}
/// Actual native CM reservation for both PCIe endpoints and both path directions.
///
/// # Safety
/// This owns actual input/output HopIDs, source-selected credits and physical
/// endpoint-to-lane mapping from the shared domain allocator in the exact
/// Linked/NHI/reset/topology epoch. It retains actual _OSC/security PCIe tunnel
/// authorization and requester DMA/IMR/IOMMU protection. Credit modes/limits
/// reflect real router VSEC allocation, and reserved credits cover all competing
/// users. Exclusive CS0 endpoint control, router/link/power and topology admission
/// stay held through failures/quarantine. Firmware/other CM cannot alter any of
/// these resources. `is_current` checks real state and pins in-flight lifetimes
/// against reset/reassignment; tuple equality is insufficient. Native host
/// submission and endpoint posted-DMA/IRQ/IOMMU teardown are independently owned.
/// Local PE0/PENDING0 never authorizes releasing those independent lifetimes.
pub unsafe trait Reservation: Send + Sync {
    fn grant(&self) -> Grant;
    fn is_current(&self) -> bool;
}
fn retain(owner: &Arc<dyn Reservation>) {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
    core::mem::forget(owner.clone());
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Revoked,
    Identity,
    Unsupported,
    Topology,
    Capability,
    Permission,
    Busy,
    Allocation,
    ClockOverflow,
    ClockRegressed,
    Timeout,
    Changed,
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
    Path(path::Error),
    Link(link::Error),
    Channel(channel::Error),
}
struct PathOwner {
    owner: Arc<dyn Reservation>,
    grant: Grant,
    allocation: path::Allocation,
}
// SAFETY: the private adapter carries the original actual combined reservation;
// fields are only the existing path engine's historical USB3-shaped metadata.
unsafe impl path::Reservation for PathOwner {
    fn allocation(&self) -> path::Allocation {
        self.allocation
    }
    fn is_current(&self) -> bool {
        self.owner.is_current() && self.owner.grant() == self.grant
    }
}
fn allocation(grant: Grant, index: usize) -> path::Allocation {
    path::Allocation {
        identity: grant.identity,
        topology_epoch: grant.topology_epoch,
        grant_epoch: grant.grant_epoch,
        direction: if index == 0 {
            Direction::Downstream
        } else {
            Direction::Upstream
        },
        usb3_down: grant.pcie_down,
        usb3_up: grant.pcie_up,
        hops: grant.hops[index],
        lane_credits: grant.lane_credits[index],
        permission: grant.permission,
    }
}
#[derive(Clone, Copy)]
pub(super) struct Endpoint {
    pub(super) route: Route,
    pub(super) port: u8,
    pub(super) upstream: u8,
    pub(super) cap: u16,
    pub(super) header: [u32; 8],
}
impl Endpoint {
    pub(super) fn address(self, header: bool) -> Address {
        Address {
            port: self.port,
            space: Space::Port,
            offset: if header { 0 } else { self.cap },
            words: if header { 8 } else { 1 },
        }
    }
    pub(super) fn matches(self, words: &[u32]) -> bool {
        AdapterHeader::parse(words).is_ok_and(|actual| {
            let expected = AdapterHeader { raw: self.header };
            actual.kind() == expected.kind()
                && actual.reported_port() == self.port
                && actual.first_capability() == expected.first_capability()
                && actual.max_in_hop() == expected.max_in_hop()
                && actual.max_out_hop() == expected.max_out_hop()
        })
    }
}
pub(super) fn endpoint(
    inventory: &Inventory,
    port: u8,
    kind: AdapterKind,
) -> Result<Endpoint, Error> {
    let (header, capabilities) = inventory
        .adapters
        .iter()
        .find_map(|entry| match entry {
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
    let mut capabilities = capabilities.iter().filter(|cap| cap.id == 4);
    let cap = capabilities.next().ok_or(Error::Capability)?;
    if capabilities.next().is_some() || cap.offset < 8 || cap.offset >= 8192 {
        return Err(Error::Capability);
    }
    Ok(Endpoint {
        route: inventory.path.route(),
        port,
        upstream: inventory.upstream_port,
        cap: cap.offset,
        header: header.raw,
    })
}
/// Both actual directions and enabled endpoints. Drop retains the combined
/// native reservation and complete original link/path chain through uncertainty.
pub struct Active {
    pub endpoints: [u32; 2],
    grant: Grant,
    owner: Option<Arc<dyn Reservation>>,
    path: Option<path::Active>,
    previous: Option<Box<path::Active>>,
    link: Option<Box<Linked>>,
    pending: [Option<Arc<dyn path::Reservation>>; 2],
}
impl Active {
    fn current(&self) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|o| o.is_current() && o.grant() == self.grant)
    }
    /// # Safety
    /// Real full restoration/reset or independent native CM transfer satisfies
    /// both directions, endpoint/PCI attachment, power and all DMA/IRQ lifetimes.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::pcie::Active;
    /// fn release(active: Active) { active.retire(); }
    /// ```
    pub unsafe fn retire(mut self) {
        if let Some(path) = self.path.take() {
            // SAFETY: this method's caller proves full restoration or retained
            // native transfer for both paths and the original link chain.
            unsafe { path.retire() };
        }
        if let Some(path) = self.previous.take() {
            // SAFETY: the same caller proof includes a partial first-path chain.
            unsafe { path.retire() };
        }
        if let Some(link) = self.link.take() {
            // SAFETY: the caller proof includes both actual routers/link even
            // when no path had started before ownership was transferred.
            unsafe { link.retire() };
        }
        self.pending = [None, None];
        self.owner.take();
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            retain(owner);
        }
    }
}
pub enum Event {
    Active(Box<Active>),
    Discarded(config::Error),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Header(usize),
    Detect(usize),
    First,
    Second,
    Enable(usize),
    Verify(usize),
    Done,
    Fault,
}
pub struct Activate<R: Registers> {
    channel: Option<Channel<R>>,
    path: Option<path::Activate<R>>,
    retained: Option<Box<Active>>,
    first_slot: Option<Box<MaybeUninit<path::Active>>>,
    prepared: [Option<path::Prepared>; 2],
    endpoints: [Endpoint; 2],
    stage: Stage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    last_now: u64,
}
pub(super) fn storage<T>() -> Result<Box<MaybeUninit<T>>, Error> {
    // SAFETY: a nonzero exact layout, initialized only before assume_init.
    let pointer = unsafe { alloc(Layout::new::<T>()) }.cast::<MaybeUninit<T>>();
    if pointer.is_null() {
        Err(Error::Allocation)
    } else {
        // SAFETY: fresh unique allocation has exactly T's size/alignment;
        // MaybeUninit<T> permits the currently uninitialized bytes.
        Ok(unsafe { Box::from_raw(pointer) })
    }
}
impl<R: Registers> Activate<R> {
    /// # Safety
    /// Idle Channel, actual Linked and Reservation belong to one exact physical
    /// requester/reset/topology lifetime. Every Reservation requirement holds;
    /// matching metadata never creates native security, DMA or allocator rights.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,link::Linked,pcie::{Activate,Reservation},ring::Registers};
    /// fn pair<R:Registers>(c:Channel<R>,l:Box<Linked>,r:Arc<dyn Reservation>){let _=Activate::new(c,l,r,0);}
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        link: Box<Linked>,
        owner: Arc<dyn Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        if !owner.is_current() {
            return Err(Error::Revoked);
        }
        let grant = owner.grant();
        if grant.permission != Decision::Allowed {
            return Err(Error::Permission);
        }
        let (parent, child) = link.retained_routers().map_err(Error::Link)?;
        // USB4v2 requires extended-encapsulation transitions, admitted separately.
        if parent.header.usb4_version() != 1 || child.header.usb4_version() != 1 {
            return Err(Error::Unsupported);
        }
        let endpoints = [
            endpoint(
                parent.retained_owner().target(),
                grant.pcie_down,
                AdapterKind::PcieDown,
            )?,
            endpoint(
                child.retained_owner().target(),
                grant.pcie_up,
                AdapterKind::PcieUp,
            )?,
        ];
        let allocations = [allocation(grant, 0), allocation(grant, 1)];
        let prepared = [
            path::prepare_pcie(&link, allocations[0]).map_err(Error::Path)?,
            path::prepare_pcie(&link, allocations[1]).map_err(Error::Path)?,
        ];
        now.checked_add(JOB_MS + 10_000)
            .ok_or(Error::ClockOverflow)?;
        let first_slot = storage::<path::Active>()?;
        let mut result = storage::<Active>()?;
        let pending: [Option<Arc<dyn path::Reservation>>; 2] = core::array::from_fn(|i| {
            Some(Arc::new(PathOwner {
                owner: owner.clone(),
                grant,
                allocation: allocations[i],
            }) as Arc<dyn path::Reservation>)
        });
        result.write(Active {
            endpoints: [0; 2],
            grant,
            owner: Some(owner),
            path: None,
            previous: None,
            link: Some(link),
            pending,
        });
        // SAFETY: the unique exact-layout slot was fully initialized above.
        let retained = unsafe { result.assume_init() };
        let [down, up] = prepared;
        Ok(Self {
            channel: Some(channel),
            path: None,
            retained: Some(retained),
            first_slot: Some(first_slot),
            prepared: [Some(down), Some(up)],
            endpoints,
            stage: Stage::Header(0),
            expected: None,
            deadline: now + REQUEST_MS,
            job_deadline: now + JOB_MS,
            last_now: now,
        })
    }
    fn current(&self) -> bool {
        self.retained.as_ref().is_some_and(|r| r.current())
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = Stage::Fault;
        if let Some(path) = &mut self.path {
            let _ = path.cancel();
        }
        if let Some(channel) = &mut self.channel {
            let _ = channel.cancel();
        }
        Err(error)
    }
    pub fn cancel(&mut self) -> Result<(), Error> {
        self.fail(Error::Cancelled)
    }
    pub fn into_channel(mut self) -> Channel<R> {
        if let Some(path) = self.path.take() {
            path.into_channel()
        } else {
            self.channel.take().expect("owned channel")
        }
    }
    fn enter(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.deadline = now
            .checked_add(REQUEST_MS)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        Ok(())
    }
    fn start_path(&mut self, index: usize, now: u64) -> Result<(), Error> {
        let channel = self.channel.take().ok_or(Error::UnexpectedReceipt)?;
        let prepared = self.prepared[index]
            .take()
            .ok_or(Error::UnexpectedReceipt)?;
        let retained = self.retained.as_mut().ok_or(Error::UnexpectedReceipt)?;
        let owner = retained.pending[index]
            .take()
            .ok_or(Error::UnexpectedReceipt)?;
        let deadline = now
            .checked_add(REQUEST_MS)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        let job = now
            .checked_add(10_000)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        // SAFETY: preflight protected both actual plans and retained all native
        // rights, link and first-path storage before the first publication.
        self.path = Some(unsafe {
            if index == 0 {
                path::Activate::start_pcie(
                    channel,
                    retained.link.take().ok_or(Error::UnexpectedReceipt)?,
                    owner,
                    prepared,
                    now,
                    deadline,
                    job,
                )
            } else {
                path::Activate::start_previous(
                    channel,
                    retained.previous.take().ok_or(Error::UnexpectedReceipt)?,
                    owner,
                    prepared,
                    now,
                    deadline,
                    job,
                )
            }
        });
        self.stage = if index == 0 {
            Stage::First
        } else {
            Stage::Second
        };
        Ok(())
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
        let index = match self.stage {
            Stage::Header(i) | Stage::Detect(i) | Stage::Enable(i) | Stage::Verify(i) => i,
            _ => return Err(Error::UnexpectedReceipt),
        };
        let data = checked_reply(reply, self.endpoints[index].upstream)?;
        match self.stage {
            Stage::Header(i) => {
                if !self.endpoints[i].matches(&data) {
                    return Err(Error::Changed);
                }
                self.enter(
                    if i == 0 {
                        Stage::Header(1)
                    } else {
                        Stage::Detect(0)
                    },
                    now,
                )?;
            }
            Stage::Detect(i) => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                if word & ENABLE != 0 {
                    return Err(Error::Busy);
                }
                if word & (15 << 25) != 0 {
                    return Ok(None);
                }
                if i == 0 {
                    self.enter(Stage::Detect(1), now)?;
                } else {
                    self.start_path(0, now)?;
                }
            }
            Stage::Enable(i) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(Stage::Verify(i), now)?;
            }
            Stage::Verify(i) => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                if word & ENABLE == 0 {
                    return Err(Error::Readback);
                }
                self.retained.as_mut().expect("actual tunnel").endpoints[i] = *word;
                if i == 1 {
                    self.enter(Stage::Enable(0), now)?;
                } else {
                    self.stage = Stage::Done;
                    return Ok(Some(Event::Active(
                        self.retained.take().ok_or(Error::UnexpectedReceipt)?,
                    )));
                }
            }
            _ => return Err(Error::UnexpectedReceipt),
        }
        Ok(None)
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<Event>, Error> {
        match self.stage {
            Stage::Done => return Err(Error::Stopped),
            Stage::Fault => return Err(Error::Poisoned),
            _ => {}
        }
        if !self.current() {
            return self.fail(Error::Revoked);
        }
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if now >= self.job_deadline {
            return self.fail(Error::Timeout);
        }
        if matches!(self.stage, Stage::First | Stage::Second) {
            let result = self.path.as_mut().expect("actual path engine").poll(now);
            match result {
                Err(error) => return self.fail(Error::Path(error)),
                Ok(Some(path::Event::Discarded(error))) => {
                    return Ok(Some(Event::Discarded(error)));
                }
                Ok(Some(path::Event::Active(path))) => {
                    self.channel = Some(
                        self.path
                            .take()
                            .expect("completed path engine")
                            .into_channel(),
                    );
                    if self.stage == Stage::First {
                        let mut slot = self.first_slot.take().ok_or(Error::UnexpectedReceipt)?;
                        slot.write(path);
                        // SAFETY: this preallocated unique exact-layout slot
                        // now contains the actual completed first path owner.
                        let previous = unsafe { slot.assume_init() };
                        self.retained
                            .as_mut()
                            .expect("retained transaction")
                            .previous = Some(previous);
                        if let Err(error) = self.start_path(1, now) {
                            return self.fail(error);
                        }
                    } else {
                        self.retained.as_mut().expect("retained transaction").path = Some(path);
                        if let Err(error) = self.enter(Stage::Enable(1), now) {
                            return self.fail(error);
                        }
                    }
                }
                Ok(None) => return Ok(None),
            }
        } else {
            if now >= self.deadline {
                return self.fail(Error::Timeout);
            }
            match self.channel.as_mut().expect("actual channel").poll(now) {
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
                    return Ok(Some(Event::Discarded(error)));
                }
                Ok(None) => {}
            }
        }
        if let Some(path) = &mut self.path {
            return match path.poll(now) {
                Ok(None) => Ok(None),
                Ok(Some(path::Event::Discarded(e))) => Ok(Some(Event::Discarded(e))),
                Ok(Some(path::Event::Active(_))) => self.fail(Error::UnexpectedReceipt),
                Err(e) => self.fail(Error::Path(e)),
            };
        }
        if self.expected.is_none() {
            let (index, header, data) = match self.stage {
                Stage::Header(i) => (i, true, None),
                Stage::Detect(i) | Stage::Verify(i) => (i, false, None),
                Stage::Enable(i) => (i, false, Some([ENABLE])),
                _ => return self.fail(Error::UnexpectedReceipt),
            };
            let endpoint = self.endpoints[index];
            let address = endpoint.address(header);
            let result = if let Some(data) = data {
                self.channel.as_mut().unwrap().write(
                    endpoint.route,
                    address,
                    &data,
                    now,
                    self.deadline,
                )
            } else {
                self.channel
                    .as_mut()
                    .unwrap()
                    .read(endpoint.route, address, now, self.deadline)
            };
            match result {
                Ok(id) => self.expected = Some(id),
                Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => {}
                Err(error) => return self.fail(Error::Channel(error)),
            }
        }
        Ok(None)
    }
}
pub(super) fn checked_reply(reply: Reply, upstream: u8) -> Result<alloc::vec::Vec<u32>, Error> {
    match reply {
        Reply::Configuration {
            upstream_port,
            data,
        } if upstream_port == upstream => Ok(data),
        Reply::Configuration { .. } => Err(Error::Changed),
        Reply::ControllerError {
            route,
            port,
            code,
            raw,
            ..
        } => Err(Error::Controller {
            route,
            port,
            code,
            raw,
        }),
        Reply::Reset => Err(Error::UnexpectedReceipt),
    }
}

/// Local stopped PCIe tunnel, retaining original power/authorization/link and
/// endpoint DMA/IRQ protection. A local stop never detaches a PCI requester.
pub struct Stopped {
    pub endpoints: [u32; 2],
    pub hops: [path::Words; 4],
    active: Box<Active>,
}
pub struct Reusable {
    pub link: Box<Linked>,
    pub reservation: Arc<dyn Reservation>,
}
impl Stopped {
    pub fn into_reusable(mut self) -> Result<Reusable, (Error, Self)> {
        if !self.active.current() {
            return Err((Error::Revoked, self));
        }
        // SAFETY: actual endpoint disable ACK/readback and all four owned hop
        // disabled/PENDING0 receipts are retained in this same live epoch.
        let link = unsafe {
            self.active
                .path
                .take()
                .expect("actual stopped paths")
                .release_direct_stopped()
        };
        let reservation = self.active.owner.take().expect("retained authorization");
        Ok(Reusable { link, reservation })
    }
}
pub enum StopEvent {
    Stopped(Stopped),
    Discarded(config::Error),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum StopStage {
    Header(usize),
    Disable(usize),
    VerifyEndpoint(usize),
    ReadHop(usize),
    DisableHop(usize, path::Words),
    Drain(usize),
    VerifyHop(usize),
    Done,
    Fault,
}
pub struct Stop<R: Registers> {
    channel: Option<Channel<R>>,
    active: Option<Box<Active>>,
    endpoints: [Endpoint; 2],
    hops: [path::DrainHop; 4],
    stopped_endpoints: [u32; 2],
    stopped_hops: [path::Words; 4],
    stage: StopStage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    last_now: u64,
}
impl<R: Registers> Stop<R> {
    /// # Safety
    /// The idle Channel and complete tunnel belong to one retained native epoch;
    /// native submission is closed and independent endpoint/DMA/IRQ/IOMMU/power
    /// lifetimes stay retained through both local stop and later reuse.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,pcie::{Active,Stop},ring::Registers};
    /// fn stop<R:Registers>(c:Channel<R>,a:Box<Active>){let _=Stop::new(c,a,0);}
    /// ```
    pub unsafe fn new(channel: Channel<R>, active: Box<Active>, now: u64) -> Result<Self, Error> {
        if !active.current() {
            return Err(Error::Revoked);
        }
        let up = active.path.as_ref().ok_or(Error::UnexpectedReceipt)?;
        let down = up.previous();
        let [d0, d1] = down.drain_hops().map_err(Error::Path)?;
        let [u0, u1] = up.drain_hops().map_err(Error::Path)?;
        let linked = up.linked();
        let (parent, child) = linked.retained_routers().map_err(Error::Link)?;
        let endpoints = [
            endpoint(
                parent.retained_owner().target(),
                active.grant.pcie_down,
                AdapterKind::PcieDown,
            )?,
            endpoint(
                child.retained_owner().target(),
                active.grant.pcie_up,
                AdapterKind::PcieUp,
            )?,
        ];
        let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
        let job_deadline = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
        Ok(Self {
            channel: Some(channel),
            active: Some(active),
            endpoints,
            hops: [d0, d1, u0, u1],
            stopped_endpoints: [0; 2],
            stopped_hops: [path::Words { raw: [0; 2] }; 4],
            stage: StopStage::Header(0),
            expected: None,
            deadline,
            job_deadline,
            last_now: now,
        })
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = StopStage::Fault;
        let _ = self.channel.as_mut().expect("actual channel").cancel();
        Err(error)
    }
    pub fn cancel(&mut self) -> Result<(), Error> {
        self.fail(Error::Cancelled)
    }
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("actual channel")
    }
    fn enter(&mut self, stage: StopStage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.deadline = now
            .checked_add(REQUEST_MS)
            .ok_or(Error::ClockOverflow)?
            .min(self.job_deadline);
        Ok(())
    }
    fn request(&self) -> (Route, u8, Address, Option<[u32; 2]>) {
        match self.stage {
            StopStage::Header(i) | StopStage::Disable(i) | StopStage::VerifyEndpoint(i) => {
                let e = self.endpoints[i];
                (
                    e.route,
                    e.upstream,
                    e.address(matches!(self.stage, StopStage::Header(_))),
                    if matches!(self.stage, StopStage::Disable(_)) {
                        Some([0; 2])
                    } else {
                        None
                    },
                )
            }
            StopStage::ReadHop(i)
            | StopStage::DisableHop(i, _)
            | StopStage::Drain(i)
            | StopStage::VerifyHop(i) => {
                let h = self.hops[i];
                (
                    h.route,
                    h.upstream,
                    Address {
                        port: h.port,
                        space: Space::Hops,
                        offset: h.id * 2,
                        words: 2,
                    },
                    if let StopStage::DisableHop(_, w) = self.stage {
                        Some(w.raw)
                    } else {
                        None
                    },
                )
            }
            _ => unreachable!("active stop stage"),
        }
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<StopEvent>, Error> {
        let data = checked_reply(reply, self.request().1)?;
        match self.stage {
            StopStage::Header(i) => {
                if !self.endpoints[i].matches(&data) {
                    return Err(Error::Changed);
                }
                self.enter(
                    if i == 0 {
                        StopStage::Header(1)
                    } else {
                        StopStage::Disable(0)
                    },
                    now,
                )?;
            }
            StopStage::Disable(i) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(StopStage::VerifyEndpoint(i), now)?;
            }
            StopStage::VerifyEndpoint(i) => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                if word & ENABLE != 0 {
                    return Err(Error::Readback);
                }
                self.stopped_endpoints[i] = *word;
                self.enter(
                    if i == 0 {
                        StopStage::Disable(1)
                    } else {
                        StopStage::ReadHop(0)
                    },
                    now,
                )?;
            }
            StopStage::DisableHop(i, _) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(StopStage::Drain(i), now)?;
            }
            StopStage::ReadHop(i) | StopStage::Drain(i) | StopStage::VerifyHop(i) => {
                let raw: [u32; 2] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::UnexpectedReceipt)?;
                let words = path::Words { raw };
                if !self.hops[i].matches(words) {
                    return Err(Error::Changed);
                }
                match self.stage {
                    StopStage::ReadHop(i) => self.enter(
                        if raw[0] & ENABLE != 0 {
                            StopStage::DisableHop(
                                i,
                                path::Words {
                                    raw: [raw[0] & !ENABLE, raw[1]],
                                },
                            )
                        } else if raw[1] & PENDING != 0 {
                            StopStage::Drain(i)
                        } else {
                            StopStage::VerifyHop(i)
                        },
                        now,
                    )?,
                    StopStage::Drain(i) | StopStage::VerifyHop(i) => {
                        if raw[0] & ENABLE != 0 {
                            return Err(Error::Readback);
                        }
                        if raw[1] & PENDING != 0 {
                            self.stage = StopStage::Drain(i);
                        } else if matches!(self.stage, StopStage::Drain(_)) {
                            self.stage = StopStage::VerifyHop(i);
                        } else {
                            self.stopped_hops[i] = words;
                            if i < 3 {
                                self.enter(StopStage::ReadHop(i + 1), now)?;
                            } else {
                                self.stage = StopStage::Done;
                                return Ok(Some(StopEvent::Stopped(Stopped {
                                    endpoints: self.stopped_endpoints,
                                    hops: self.stopped_hops,
                                    active: self.active.take().ok_or(Error::UnexpectedReceipt)?,
                                })));
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => return Err(Error::UnexpectedReceipt),
        }
        Ok(None)
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<StopEvent>, Error> {
        match self.stage {
            StopStage::Done => return Err(Error::Stopped),
            StopStage::Fault => return Err(Error::Poisoned),
            _ => {}
        }
        if !self.active.as_ref().is_some_and(|a| a.current()) {
            return self.fail(Error::Revoked);
        }
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if now >= self.deadline || now >= self.job_deadline {
            return self.fail(Error::Timeout);
        }
        match self.channel.as_mut().unwrap().poll(now) {
            Err(e) => return self.fail(Error::Channel(e)),
            Ok(Some(channel::Event::Completed { request, reply })) => {
                if self.expected != Some(request) {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.expected = None;
                match self.complete(reply, now) {
                    Ok(Some(e)) => return Ok(Some(e)),
                    Ok(None) => {}
                    Err(e) => return self.fail(e),
                }
            }
            Ok(Some(channel::Event::Plug(e))) => return self.fail(Error::Hotplug(e)),
            Ok(Some(channel::Event::Notification(e))) => return self.fail(Error::Notification(e)),
            Ok(Some(channel::Event::Discarded(e))) => return Ok(Some(StopEvent::Discarded(e))),
            Ok(None) => {}
        }
        if self.expected.is_none() {
            let (route, _, address, data) = self.request();
            let result = if let Some(data) = data {
                self.channel.as_mut().unwrap().write(
                    route,
                    address,
                    &data[..usize::from(address.words)],
                    now,
                    self.deadline,
                )
            } else {
                self.channel
                    .as_mut()
                    .unwrap()
                    .read(route, address, now, self.deadline)
            };
            match result {
                Ok(id) => self.expected = Some(id),
                Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => {}
                Err(e) => return self.fail(Error::Channel(e)),
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
