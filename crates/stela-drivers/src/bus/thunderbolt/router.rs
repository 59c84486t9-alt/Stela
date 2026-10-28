// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Native USB4 router enumeration, tunneling configuration and hotplug setup.
//!
//! Linux switch.c/usb4.c register algorithms, without Linux OS services. Actual
//! native CM/policy/DMA ownership is required; ready bits alone grant none.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    domain::Identity,
    ring::{self, Registers},
    topology::{AdapterKind, AdapterObservation, Inventory, RouterHeader},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
const CNS: u32 = 1 << 23;
const PTO: u32 = 1 << 24;
const UTO: u32 = 1 << 25;
const HCO: u32 = 1 << 26;
const CV: u32 = 1 << 31;
const HCI: u32 = 1 << 18;
const RR: u32 = 1 << 24;
const CR: u32 = 1 << 25;
const DHP: u32 = 1 << 31;
const TIMEOUT_MS: u64 = 500;
const JOB_MS: u64 = 60_000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_reservations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Unresolved,
    Denied,
    Allowed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub usb3: Decision,
    pub pcie: Decision,
}
/// Actual native authority and exclusive active router/link reservation.
///
/// # Safety
/// Identity, target/parent observations and policy belong to one live physical
/// NHI requester and unchanged ownership/reset epoch. Native platform services
/// positively granted software-CM ownership, actual attached DMA protection,
/// IMR/protected firmware DMA, power and configuration resources. Firmware ICM
/// and other actors cannot configure these routers. Allowed decisions represent
/// real stable native _OSC/security/authorization policy, including actual PCIe
/// DMA protection; no invented bool or Type-C event may supply these decisions.
/// The parent is already configured and the actual physical relationship and
/// capabilities remain current, protected against competing topology/link work.
/// The caller retains Channel/Ring native NHI power and DMA-attachment grants
/// independently until their real final drain; this local Owner may never
/// detach their domain or release live ring resources. All independent endpoint
/// DMA/IRQ/IOMMU lifetimes remain retained. Owner can end only before mutation, after real restoration/reset, or after completed
/// transfer into independent native CM ownership. Quarantine must retain it.
pub unsafe trait Owner: Send + Sync {
    fn identity(&self) -> Identity;
    fn target(&self) -> &Inventory;
    fn parent(&self) -> Option<&Inventory>;
    fn policy(&self) -> Policy;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Unsupported,
    Inventory,
    Parent,
    Capability,
    UnresolvedPolicy,
    PolicyConflict(u32),
    ClockOverflow,
    ClockRegressed,
    Timeout,
    Cancelled,
    Poisoned,
    Stopped,
    UnexpectedReceipt,
    ChangedInventory,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotplugWord {
    pub port: u8,
    pub before: u32,
    pub after: u32,
}
/// Completed actual register sequence, retaining the configured router's lease.
/// It establishes neither tunnels nor bonding nor endpoint/IOMMU drain.
pub struct Configured {
    pub identity: Identity,
    pub route: Route,
    pub header: RouterHeader,
    pub link_usb4: Option<bool>,
    pub setup_word: Option<u32>,
    pub ready_status: Option<u32>,
    pub configured_status: Option<u32>,
    pub hotplug: Vec<HotplugWord>,
    owner: Option<Arc<dyn Owner>>,
}
impl Configured {
    /// Read-only seam for another retained native CM operation in this module.
    pub(super) fn retained_owner(&self) -> &dyn Owner {
        &**self.owner.as_ref().expect("live configured reservation")
    }
    /// # Safety
    /// Real hardware restoration/reset has satisfied all dependent topology,
    /// path, power and DMA/IRQ requirements, or the exact configured reservation
    /// is already held by independent retained native CM ownership. This local
    /// setup receipt cannot certify endpoint/IOMMU teardown.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::router::Configured;
    /// fn release(configured: Configured) { configured.retire(); }
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
impl Drop for Configured {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            quarantine(owner);
        }
    }
}
pub enum Event {
    Configured(Configured),
    Discarded(config::Error),
}
#[derive(Clone)]
struct Plan {
    identity: Identity,
    target: Inventory,
    parent: Option<Inventory>,
    policy: Policy,
    parent_port: u8,
    parent_usb4_cap: Option<u16>,
    parent_usb3: bool,
    parent_pcie: bool,
    hotplug: Vec<u8>,
}
fn present(
    inventory: &Inventory,
    port: u8,
) -> Option<(
    &super::topology::AdapterHeader,
    &[super::topology::Capability],
)> {
    inventory.adapters.iter().find_map(|adapter| match adapter {
        AdapterObservation::Present {
            port: number,
            header,
            capabilities,
        } if *number == port => Some((header, capabilities.as_slice())),
        _ => None,
    })
}
fn validate_inventory(inventory: &Inventory) -> Result<(), Error> {
    let max = inventory.header.max_port();
    if inventory.adapters.len() != usize::from(max) || inventory.upstream_port > max {
        return Err(Error::Inventory);
    }
    let mut seen = 0u64;
    for adapter in &inventory.adapters {
        let port = match adapter {
            AdapterObservation::Present { port, .. }
            | AdapterObservation::Unimplemented { port, .. } => *port,
        };
        if port == 0 || port > max || seen & (1u64 << port) != 0 {
            return Err(Error::Inventory);
        }
        seen |= 1u64 << port;
    }
    if inventory.path.depth() != 0
        && !present(inventory, inventory.upstream_port)
            .is_some_and(|(header, _)| header.kind() == AdapterKind::Lane)
    {
        return Err(Error::Inventory);
    }
    Ok(())
}
impl Plan {
    fn new(owner: &dyn Owner) -> Result<Self, Error> {
        let identity = owner.identity();
        if identity.epoch == 0 || identity.nhi.device >= 32 || identity.nhi.function >= 8 {
            return Err(Error::Identity);
        }
        let target = owner.target().clone();
        validate_inventory(&target)?;
        if target.header.usb4_version() == 0 || target.path.depth() > 5 {
            return Err(Error::Unsupported);
        }
        let policy = owner.policy();
        if matches!(policy.usb3, Decision::Unresolved)
            || matches!(policy.pcie, Decision::Unresolved)
        {
            return Err(Error::UnresolvedPolicy);
        }
        let mut plan = Self {
            identity,
            target,
            parent: owner.parent().cloned(),
            policy,
            parent_port: 0,
            parent_usb4_cap: None,
            parent_usb3: false,
            parent_pcie: false,
            hotplug: Vec::new(),
        };
        if plan.target.path.depth() == 0 {
            if plan.parent.is_some() {
                return Err(Error::Parent);
            }
        } else {
            let parent = plan.parent.as_ref().ok_or(Error::Parent)?;
            validate_inventory(parent)?;
            let depth = plan.target.path.depth();
            let shift = (depth - 1) * 8;
            let mask = (1u64 << shift) - 1;
            if parent.path.depth() + 1 != depth
                || plan.target.path.route().raw() & mask != parent.path.route().raw()
                || !parent.header.enabled()
                || parent.header.reported_route() != parent.path.route().raw()
                || parent.header.reported_depth() != parent.path.depth()
                || parent.header.reported_upstream() != parent.upstream_port
            {
                return Err(Error::Parent);
            }
            plan.parent_port = (plan.target.path.route().raw() >> shift) as u8;
            if plan.parent_port == parent.upstream_port {
                return Err(Error::Parent);
            }
            let (header, capabilities) = present(parent, plan.parent_port).ok_or(Error::Parent)?;
            if header.kind() != AdapterKind::Lane {
                return Err(Error::Parent);
            }
            let caps: Vec<_> = capabilities.iter().filter(|cap| cap.id == 6).collect();
            if caps.len() > 1 {
                return Err(Error::Capability);
            }
            if let Some(cap) = caps.first() {
                if cap.offset < 8 || cap.offset > 8192 - 0x13 {
                    return Err(Error::Capability);
                }
                plan.parent_usb4_cap = Some(cap.offset);
            }
            for adapter in &parent.adapters {
                if let AdapterObservation::Present { header, .. } = adapter {
                    plan.parent_usb3 |= header.kind() == AdapterKind::Usb3Down;
                    plan.parent_pcie |= header.kind() == AdapterKind::PcieDown;
                }
            }
        }
        for adapter in &plan.target.adapters {
            if let AdapterObservation::Present {
                port,
                header,
                capabilities,
            } = adapter
            {
                let caps: Vec<_> = capabilities.iter().filter(|cap| cap.id == 6).collect();
                if caps.len() > 1 {
                    return Err(Error::Capability);
                }
                if let Some(cap) = caps.first() {
                    if cap.offset < 8 || cap.offset >= 8192 {
                        return Err(Error::Capability);
                    }
                    if !matches!(
                        header.kind(),
                        AdapterKind::Lane | AdapterKind::DisplayIn | AdapterKind::DisplayOut
                    ) {
                        return Err(Error::Unsupported);
                    }
                    plan.hotplug.push(*port);
                }
            }
        }
        Ok(plan)
    }
    fn enumerate(&self, before: &RouterHeader) -> RouterHeader {
        let mut header = before.clone();
        header.raw[1] = (header.raw[1] & !((63 << 8) | (7 << 20)))
            | (u32::from(self.target.upstream_port) << 8)
            | (u32::from(self.target.path.depth()) << 20);
        header.raw[2] = self.target.path.route().raw() as u32;
        header.raw[3] = (self.target.path.route().raw() >> 32) as u32 | (1 << 31);
        let cmuv = if before.usb4_version() < 2 {
            0x10
        } else {
            0x20
        };
        header.raw[4] = (header.raw[4] & !0xffff) | (cmuv << 8) | 0xff;
        header
    }
    fn setup_word(&self, before: u32, status: u32, link_usb4: bool) -> Result<u32, Error> {
        let usb3 = self.policy.usb3 == Decision::Allowed && link_usb4 && self.parent_usb3;
        let pcie = self.policy.pcie == Decision::Allowed && self.parent_pcie;
        let forbidden = (if usb3 { 0 } else { UTO }) | (if pcie { 0 } else { PTO | HCO });
        if before & forbidden != 0 {
            return Err(Error::PolicyConflict(before));
        }
        let mut value = before;
        let mut xhci = status & HCI != 0;
        if usb3 {
            value |= UTO;
            xhci = false;
        }
        if pcie {
            value |= PTO;
            if xhci {
                value |= HCO;
            }
        }
        Ok(value & !CNS)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Header,
    PreflightCapabilities,
    PreflightParentMode,
    PreflightSetup,
    Enumerate,
    VerifyHeader,
    Capabilities,
    ParentMode,
    SetupRead,
    SetupWrite,
    VerifySetup,
    WaitReady,
    ValidRead,
    ValidWrite,
    VerifyValid,
    WaitConfigured,
    HotplugRead(usize),
    HotplugWrite(usize),
    HotplugVerify(usize),
    Done,
    Fault,
}
/// A bounded real software-CM configuration sequence. Every stage retains one
/// deadline across publication retries; readiness loops retain a fixed500ms
/// window and the entire caller-driven job is bounded to60s. No sleeping here.
/// Every `now` is actual monotonic milliseconds from the same clock as Channel.
pub struct Setup<R: Registers> {
    channel: Option<Channel<R>>,
    owner: Option<Arc<dyn Owner>>,
    plan: Plan,
    stage: Stage,
    expected: Option<u64>,
    stage_deadline: u64,
    job_deadline: u64,
    last_now: u64,
    changed: bool,
    header: Option<RouterHeader>,
    status: u32,
    link_usb4: Option<bool>,
    setup_word: Option<u32>,
    valid_word: u32,
    ready_status: Option<u32>,
    configured_status: Option<u32>,
    hotplug_word: u32,
    hotplug: Vec<HotplugWord>,
}
impl<R: Registers> Setup<R> {
    /// # Safety
    /// Owner and Channel describe the exact same physical requester and native
    /// ownership/reset epoch; all Owner authority/DMA/IMR/power/policy grants
    /// are real and stable. The channel is exclusively idle. Inventory is the
    /// actual protected current topology, never merely matching numeric routes.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{router::{Owner,Setup},channel::Channel,ring::Registers};
    /// fn pair<R:Registers>(channel:Channel<R>,owner:Arc<dyn Owner>){let _=Setup::new(channel,owner,0);}
    /// ```
    pub unsafe fn new(channel: Channel<R>, owner: Arc<dyn Owner>, now: u64) -> Result<Self, Error> {
        let plan = Plan::new(&*owner)?;
        let job_deadline = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
        let stage_deadline = now.checked_add(TIMEOUT_MS).ok_or(Error::ClockOverflow)?;
        Ok(Self {
            channel: Some(channel),
            owner: Some(owner),
            plan,
            stage: Stage::Header,
            expected: None,
            stage_deadline,
            job_deadline,
            last_now: now,
            changed: false,
            header: None,
            status: 0,
            link_usb4: None,
            setup_word: None,
            valid_word: 0,
            ready_status: None,
            configured_status: None,
            hotplug_word: 0,
            hotplug: Vec::new(),
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
    /// Explicit policy/topology revocation poisons partial configuration.
    pub fn cancel(&mut self) -> Result<(), Error> {
        match self.stage {
            Stage::Done => Err(Error::Stopped),
            Stage::Fault => Err(Error::Poisoned),
            _ => self.fail(Error::Cancelled),
        }
    }
    /// Uncertain state remains poisoned and its changed reservation retained.
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("owned channel")
    }
    fn enter(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.stage_deadline =
            crate::bus::thunderbolt::stage_deadline(now, TIMEOUT_MS, self.job_deadline)
                .ok_or(Error::ClockOverflow)?;
        Ok(())
    }
    fn hotplug_or_done(&mut self, now: u64) -> Result<Option<Event>, Error> {
        if !self.plan.hotplug.is_empty() {
            self.enter(Stage::HotplugRead(0), now)?;
            return Ok(None);
        }
        self.receipt()
    }
    fn receipt(&mut self) -> Result<Option<Event>, Error> {
        self.stage = Stage::Done;
        Ok(Some(Event::Configured(Configured {
            identity: self.plan.identity,
            route: self.plan.target.path.route(),
            header: self.header.clone().ok_or(Error::UnexpectedReceipt)?,
            link_usb4: self.link_usb4,
            setup_word: self.setup_word,
            ready_status: self.ready_status,
            configured_status: self.configured_status,
            hotplug: core::mem::take(&mut self.hotplug),
            owner: self.owner.take(),
        })))
    }
    fn request(&self) -> Result<(Route, Address, Option<Vec<u32>>), Error> {
        let target = self.plan.target.path.route();
        let (route, port, space, offset, words, data) = match self.stage {
            Stage::Header | Stage::VerifyHeader => (target, 0, Space::Router, 0, 5, None),
            Stage::Enumerate => (
                target,
                0,
                Space::Router,
                1,
                4,
                Some(self.header.as_ref().ok_or(Error::UnexpectedReceipt)?.raw[1..].to_vec()),
            ),
            Stage::PreflightCapabilities
            | Stage::Capabilities
            | Stage::WaitReady
            | Stage::WaitConfigured => (target, 0, Space::Router, 6, 1, None),
            Stage::PreflightParentMode | Stage::ParentMode => (
                self.plan.parent.as_ref().ok_or(Error::Parent)?.path.route(),
                self.plan.parent_port,
                Space::Port,
                self.plan.parent_usb4_cap.ok_or(Error::Capability)? + 0x12,
                1,
                None,
            ),
            Stage::PreflightSetup
            | Stage::SetupRead
            | Stage::VerifySetup
            | Stage::ValidRead
            | Stage::VerifyValid => (target, 0, Space::Router, 5, 1, None),
            Stage::SetupWrite => (
                target,
                0,
                Space::Router,
                5,
                1,
                Some(alloc::vec![
                    self.setup_word.ok_or(Error::UnexpectedReceipt)?
                ]),
            ),
            Stage::ValidWrite => (
                target,
                0,
                Space::Router,
                5,
                1,
                Some(alloc::vec![self.valid_word]),
            ),
            Stage::HotplugRead(i) | Stage::HotplugVerify(i) => {
                (target, self.plan.hotplug[i], Space::Port, 5, 1, None)
            }
            Stage::HotplugWrite(i) => (
                target,
                self.plan.hotplug[i],
                Space::Port,
                5,
                1,
                Some(alloc::vec![self.hotplug_word & !DHP]),
            ),
            _ => return Err(Error::Stopped),
        };
        Ok((
            route,
            Address {
                port,
                space,
                offset,
                words,
            },
            data,
        ))
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        if self.expected.is_some() {
            return Ok(());
        }
        let (route, address, data) = self.request()?;
        let deadline = self.stage_deadline;
        let result = if let Some(data) = data {
            let result = self.channel().write(route, address, &data, now, deadline);
            if !matches!(
                result,
                Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full))
            ) {
                self.changed = true;
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
            Err(error) => self.fail(error.into()),
        }
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
        let data = match reply {
            Reply::Configuration {
                upstream_port,
                data,
            } => {
                let expected_upstream =
                    if matches!(self.stage, Stage::PreflightParentMode | Stage::ParentMode) {
                        self.plan
                            .parent
                            .as_ref()
                            .ok_or(Error::Parent)?
                            .upstream_port
                    } else {
                        self.plan.target.upstream_port
                    };
                if upstream_port != expected_upstream {
                    return self.fail(Error::ChangedInventory);
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
            Stage::Header => {
                let header = RouterHeader::parse(&data).map_err(|_| Error::UnexpectedReceipt)?;
                let observed = &self.plan.target.header;
                if header.raw[0] != observed.raw[0]
                    || header.max_port() != observed.max_port()
                    || header.usb4_version() != observed.usb4_version()
                    || header.first_capability() != observed.first_capability()
                {
                    return self.fail(Error::ChangedInventory);
                }
                self.header = Some(self.plan.enumerate(&header));
                self.enter(
                    if self.plan.parent.is_some() {
                        Stage::PreflightCapabilities
                    } else {
                        Stage::Enumerate
                    },
                    now,
                )?;
            }
            Stage::PreflightCapabilities => {
                self.status = word()?;
                self.link_usb4 = Some(false);
                self.enter(
                    if self.plan.parent_usb4_cap.is_some() {
                        Stage::PreflightParentMode
                    } else {
                        Stage::PreflightSetup
                    },
                    now,
                )?;
            }
            Stage::PreflightParentMode => {
                self.link_usb4 = Some(word()? & (1 << 9) == 0);
                self.enter(Stage::PreflightSetup, now)?;
            }
            Stage::PreflightSetup => {
                self.plan.setup_word(
                    word()?,
                    self.status,
                    self.link_usb4.ok_or(Error::UnexpectedReceipt)?,
                )?;
                self.enter(Stage::Enumerate, now)?;
            }
            Stage::Enumerate => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::VerifyHeader, now)?;
            }
            Stage::VerifyHeader => {
                let header = RouterHeader::parse(&data).map_err(|_| Error::UnexpectedReceipt)?;
                let expected = self.header.as_ref().ok_or(Error::UnexpectedReceipt)?;
                if header.max_port() != expected.max_port()
                    || header.usb4_version() != expected.usb4_version()
                    || header.first_capability() != expected.first_capability()
                {
                    return self.fail(Error::ChangedInventory);
                }
                let masks = [u32::MAX, (63 << 8) | (7 << 20), u32::MAX, u32::MAX, 0xffff];
                if header
                    .raw
                    .iter()
                    .zip(expected.raw.iter())
                    .zip(masks)
                    .any(|((actual, wanted), mask)| actual & mask != wanted & mask)
                {
                    return self.fail(Error::Readback);
                }
                if self.plan.parent.is_none() {
                    return self.hotplug_or_done(now);
                }
                self.enter(Stage::Capabilities, now)?;
            }
            Stage::Capabilities => {
                self.status = word()?;
                self.link_usb4 = Some(false);
                self.enter(
                    if self.plan.parent_usb4_cap.is_some() {
                        Stage::ParentMode
                    } else {
                        Stage::SetupRead
                    },
                    now,
                )?;
            }
            Stage::ParentMode => {
                self.link_usb4 = Some(word()? & (1 << 9) == 0);
                self.enter(Stage::SetupRead, now)?;
            }
            Stage::SetupRead => {
                let value = self.plan.setup_word(
                    word()?,
                    self.status,
                    self.link_usb4.ok_or(Error::UnexpectedReceipt)?,
                )?;
                self.setup_word = Some(value);
                self.enter(Stage::SetupWrite, now)?;
            }
            Stage::SetupWrite => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::VerifySetup, now)?;
            }
            Stage::VerifySetup => {
                if word()? & (UTO | PTO | HCO | CNS)
                    != self.setup_word.ok_or(Error::UnexpectedReceipt)? & (UTO | PTO | HCO | CNS)
                {
                    return self.fail(Error::Readback);
                }
                // The ACK started the donor's 500ms window; readback cannot
                // extend it before readiness polling begins.
                self.stage = Stage::WaitReady;
            }
            Stage::WaitReady => {
                let status = word()?;
                if status & RR != 0 {
                    self.ready_status = Some(status);
                    self.enter(Stage::ValidRead, now)?;
                }
            }
            Stage::ValidRead => {
                let before = word()?;
                if before & (UTO | PTO | HCO | CNS)
                    != self.setup_word.ok_or(Error::UnexpectedReceipt)? & (UTO | PTO | HCO | CNS)
                {
                    return self.fail(Error::Readback);
                }
                self.valid_word = before | CV;
                self.enter(Stage::ValidWrite, now)?;
            }
            Stage::ValidWrite => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::VerifyValid, now)?;
            }
            Stage::VerifyValid => {
                if word()? & (CV | UTO | PTO | HCO | CNS)
                    != self.valid_word & (CV | UTO | PTO | HCO | CNS)
                {
                    return self.fail(Error::Readback);
                }
                // Same fixed window beginning at configuration-valid ACK.
                self.stage = Stage::WaitConfigured;
            }
            Stage::WaitConfigured => {
                let status = word()?;
                if status & CR != 0 {
                    self.configured_status = Some(status);
                    return self.hotplug_or_done(now);
                }
            }
            Stage::HotplugRead(i) => {
                self.hotplug_word = word()?;
                self.enter(Stage::HotplugWrite(i), now)?;
            }
            Stage::HotplugWrite(i) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::HotplugVerify(i), now)?;
            }
            Stage::HotplugVerify(i) => {
                let after = word()?;
                if after & DHP != 0 {
                    return self.fail(Error::Readback);
                }
                self.hotplug.push(HotplugWord {
                    port: self.plan.hotplug[i],
                    before: self.hotplug_word,
                    after,
                });
                if i + 1 == self.plan.hotplug.len() {
                    return self.receipt();
                }
                self.enter(Stage::HotplugRead(i + 1), now)?;
            }
            _ => return self.fail(Error::UnexpectedReceipt),
        }
        Ok(None)
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<Event>, Error> {
        match self.stage {
            Stage::Fault => return Err(Error::Poisoned),
            Stage::Done => return Err(Error::Stopped),
            _ => {}
        }
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if now >= self.job_deadline || now >= self.stage_deadline {
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
impl<R: Registers> Drop for Setup<R> {
    fn drop(&mut self) {
        if self.changed
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

    use crate::bus::thunderbolt::config::PacketType;
    use crate::bus::thunderbolt::ring::{Direction, model::*};

    #[test]
    fn router_setup_actual_dma_root_child_policy_modes_and_hotplug_complete() {
        use super::super::router::Setup;
        for route in [0, 1, 0x201] {
            for mask in [0, 15, 47, 127] {
                let (_source, domain, model, mut channel) = channel();
                channel.start(0).unwrap();
                let owner = Arc::new(router_owner(route, 2, mask));
                let dropped = owner.dropped.clone();
                let mut peer = RouterPeer::new(owner.clone(), mask);
                // SAFETY: this exact model requester/domain/IMR/reset epoch owns
                // actual unchanged inventories and resolved native model policy.
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
                // SAFETY: actual synthetic configured state is transferred into an
                // independently retained model CM lifetime through final drain.
                unsafe { configured.retire() };
                assert_eq!(dropped.load(Ordering::Relaxed), 1);
                channel_release(&mut channel);
            }
        }
    }

    #[test]
    #[ignore = "oracle: STELA_THUNDERBOLT_ROUTER_ORACLE"]
    fn unchanged_linux_router_full_write_trace_matches_actual_dma_engine() {
        use super::super::router::Setup;
        use std::{env, fs};
        let trace = fs::read_to_string(
            env::var("STELA_THUNDERBOLT_ROUTER_ORACLE").expect("set router trace"),
        )
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
            // SAFETY: exact isolated model requester/epoch with actual retained
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
            // SAFETY: independent model CM retains this actual configured lease
            // through complete synthetic teardown; no hardware provider claim.
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
                3 => {
                    owner.parent.as_mut().unwrap().path = Path::new(Route::new(2).unwrap()).unwrap()
                }
                4 => owner.parent.as_mut().unwrap().header.raw[3] &= !(1 << 31),
                5 => {
                    owner.parent.as_mut().unwrap().adapters[0] =
                        router_adapter(1, 0x200101, Some(0x30))
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
            // SAFETY: this exact synthetic requester/epoch represents negative
            // metadata/prerequisites. No actual authority or write is fabricated.
            assert!(
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
            // SAFETY: exact same negative synthetic ownership/inventory epoch.
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
            // SAFETY: exact same isolated synthetic native reservation.
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
    fn router_lost_ack_rejected_enumeration_and_unconsumed_receipt_retain_owner() {
        use super::super::router::{Error, Setup};
        for mode in 0..3 {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let owner = Arc::new(router_owner(1, 2, 79));
            let dropped = owner.dropped.clone();
            let mut peer = RouterPeer::new(owner.clone(), 79);
            peer.reject_header = mode == 1;
            // SAFETY: exact same synthetic requester/epoch; published mutations
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
        // SAFETY: exact same synthetic owner, idle request engine; old completed
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
        // SAFETY: exact same idle synthetic requester/reset/native reservation.
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
            // SAFETY: same exact synthetic requester/epoch and native policy.
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
        // SAFETY: same actual synthetic requester/epoch and reviewed parent
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
}
