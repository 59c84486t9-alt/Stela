// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! Reserved two-hop protocol paths over an actual retained native USB4 link.
//! Linux path.c activation and tunnel.c settings; no tunnel/endpoint enable,
//! HopID allocator, bandwidth or platform authorization provider is fabricated.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    domain::Identity,
    link::{self, Linked},
    ring::{self, Registers},
    router::Decision,
    topology::{AdapterHeader, AdapterKind, AdapterObservation, Inventory},
};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};
const ENABLE: u32 = 1 << 31;
const PENDING: u32 = 1 << 28;
const REQUEST_MS: u64 = 500;
const JOB_MS: u64 = 10_000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_paths() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Downstream,
    Upstream,
}
/// Source lane credit choice. RouterAllocated is the actual source-selected
/// protocol reservation (USB3's max_usb3_credits in the public API), never the
/// register total or an unreserved caller estimate. PCIe additionally checks
/// its source six-credit minimum in the private protocol plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneCredits {
    LegacyBonded,
    RouterAllocated(u8),
}
impl LaneCredits {
    fn value(self) -> Result<u8, Error> {
        match self {
            Self::LegacyBonded => Ok(32),
            Self::RouterAllocated(value @ 1..=127) => Ok(value),
            _ => Err(Error::Credits),
        }
    }
}
/// Metadata of an independently protected real allocation; never authority by
/// itself. Hop pairs are (ingress HopID, outgoing HopID), source to destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    pub identity: Identity,
    pub topology_epoch: u64,
    pub grant_epoch: u64,
    pub direction: Direction,
    /// Public USB3 endpoint. The private PCIe adapter uses this historical
    /// storage field for its actual PCIe endpoint, selected by a private profile.
    pub usb3_down: u8,
    /// Opposite actual protocol endpoint, under the same private profile.
    pub usb3_up: u8,
    pub hops: [(u16, u16); 2],
    pub lane_credits: LaneCredits,
    pub permission: Decision,
}
/// Real protected native protocol path reservation, including permission/lifetimes.
///
/// # Safety
/// This object retains exclusive actual input AND output HopIDs on all four
/// ports, including any stale configuration at those IDs, from the shared native
/// domain allocator. They belong to the exact retained Linked/NHI/reset/topology
/// epoch and actual protocol-to-primary-lane mapping. Neither firmware nor another
/// CM can reuse them or modify the path. Permission is a real platform/_OSC and
/// security decision for these endpoints, with protected grant_epoch; it is not
/// an integer tuple assertion or a default authorization. Credit mode is from
/// actual router VSEC allocation support, and the source-sized lane credits are
/// reserved against every competing path, not merely compared to total buffers.
/// The native owner has serialized dependent paths/power/CL0, satisfies any real
/// preactivation bandwidth prerequisites and retains endpoint/DMA/IMR/IOMMU/IRQ
/// ownership independently. Stale-hop draining must not release any prior ID,
/// posted DMA, endpoint or attachment. Drop releases this reservation only after
/// no mutation, proven restoration/reset, independently retained transfer, or
/// a genuine same-epoch complete local path disable/pending drain. That last
/// proof returns only local HopID/flow-credit rights; independent endpoint DMA,
/// IRQ/IOMMU, link and residual bandwidth/permission lifetimes stay retained.
/// No production implementation of these missing native services is supplied.
pub unsafe trait Reservation: Send + Sync {
    fn allocation(&self) -> Allocation;
    /// Real retained native admission state, checked before publication and
    /// completion. It also pins this in-flight physical lifetime against reuse;
    /// integer tuple equality is never a native reset/topology guard.
    fn is_current(&self) -> bool;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Revoked,
    Identity,
    Topology,
    Permission,
    Unsupported,
    HopId,
    Credits,
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
    Link(link::Error),
    Channel(channel::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Words {
    pub raw: [u32; 2],
}
/// Active local path, retaining the original link and actual path allocation.
/// Neither this receipt nor a pending-bit observation authorizes endpoint enable
/// or finishes a protocol tunnel, security/attachment admission or endpoint teardown.
pub struct Active {
    pub allocation: Allocation,
    pub words: [Words; 2],
    link: Option<Backing>,
    reservation: Option<Arc<dyn Reservation>>,
    changed: bool,
    profile: Profile,
}
enum Backing {
    Direct(Box<Linked>),
    Bandwidth(Box<super::usb3::Allocated>),
    Previous(Box<Active>),
}
impl Backing {
    fn is_current(&self) -> bool {
        match self {
            Self::Direct(_) => true,
            Self::Bandwidth(b) => b.is_current(),
            Self::Previous(p) => p.is_current(),
        }
    }
    fn linked(&self) -> &Linked {
        match self {
            Self::Direct(link) => link,
            Self::Bandwidth(allocation) => allocation.linked(),
            Self::Previous(path) => path.link.as_ref().expect("retained first path").linked(),
        }
    }
    unsafe fn retire(self) {
        match self {
            // SAFETY: covered by this function's own safety contract.
            Self::Direct(link) => unsafe { link.retire() },
            // SAFETY: covered by this function's own safety contract.
            Self::Bandwidth(allocation) => unsafe { allocation.retire() },
            // SAFETY: covered by this function's own safety contract.
            Self::Previous(path) => unsafe { path.retire() },
        }
    }
}
impl Active {
    pub(super) fn linked(&self) -> &Linked {
        self.link.as_ref().expect("retained link chain").linked()
    }
    pub(super) fn is_current(&self) -> bool {
        self.link.as_ref().is_some_and(|link| link.is_current())
            && self
                .reservation
                .as_ref()
                .is_some_and(|owner| owner.is_current())
    }
    pub(super) fn protected_allocation(&self) -> Allocation {
        self.reservation
            .as_ref()
            .expect("retained native path")
            .allocation()
    }
    pub(super) fn previous(&self) -> &Active {
        let Some(Backing::Previous(previous)) = &self.link else {
            panic!("actual two-direction path chain")
        };
        previous
    }
    pub(super) fn bandwidth_ref(&self) -> &super::usb3::Allocated {
        match self.link.as_ref().expect("retained backing") {
            Backing::Bandwidth(b) => b,
            Backing::Previous(p) => p.bandwidth_ref(),
            Backing::Direct(_) => panic!("actual bandwidth-backed path"),
        }
    }
    pub(super) fn take_bandwidth(&mut self) -> Box<super::usb3::Allocated> {
        match self.link.as_mut().expect("retained backing") {
            Backing::Bandwidth(_) => {
                let Some(Backing::Bandwidth(b)) = self.link.take() else {
                    unreachable!()
                };
                b
            }
            Backing::Previous(p) => p.take_bandwidth(),
            Backing::Direct(_) => panic!("actual bandwidth-backed path"),
        }
    }
    pub(super) fn put_bandwidth(&mut self, bandwidth: Box<super::usb3::Allocated>) {
        match self.link.as_mut() {
            None => self.link = Some(Backing::Bandwidth(bandwidth)),
            Some(Backing::Previous(p)) => p.put_bandwidth(bandwidth),
            _ => panic!("unique removed bandwidth slot"),
        }
    }
    pub(super) fn drain_hops(&self) -> Result<[DrainHop; 2], Error> {
        let allocation = self.protected_allocation();
        let hops = plan_profile(
            self.link.as_ref().ok_or(Error::Topology)?.linked(),
            allocation,
            self.profile,
        )?;
        Ok(core::array::from_fn(|i| {
            let hop = hops[i];
            let expected = hop.program(Words { raw: [0; 2] }, i);
            DrainHop {
                route: hop.route,
                port: hop.input,
                upstream: hop.upstream,
                id: hop.ingress,
                expected,
                mask: [
                    !((1 << 31) | if hop.lane { 0 } else { 127 << 17 }),
                    !((1 << 28) | if hop.lane { 0 } else { (1 << 24) | (1 << 26) }),
                ],
            }
        }))
    }
    /// # Safety
    /// Exact same-epoch PCIe stop proved both endpoints disabled and all four
    /// hops disabled/PENDING0 in source normal-stop order. Source clear_fc=false
    /// retains FC bits; only the original local IDs/credits return to the same
    /// reservation. Independent endpoint DMA, IRQ/IOMMU and platform lifetimes
    /// remain with the returned real owners.
    pub(super) unsafe fn release_direct_stopped(mut self) -> Box<Linked> {
        let Some(Backing::Previous(mut down)) = self.link.take() else {
            panic!("actual two-path chain")
        };
        let Some(Backing::Direct(link)) = down.link.take() else {
            panic!("actual direct link owner")
        };
        self.reservation.take();
        down.reservation.take();
        link
    }
    /// # Safety
    /// Native DP stop proved both endpoints disabled, all six owned hops
    /// EN0/PENDING0 and actual video NFC returned in the same live epoch.
    /// Only original local rights return; independent GPU/DMA/IRQ stay held.
    pub(super) unsafe fn release_dp_stopped(mut self) -> Box<Linked> {
        let Some(Backing::Previous(mut aux)) = self.link.take() else {
            panic!("actual AUX return path")
        };
        let Some(Backing::Previous(mut video)) = aux.link.take() else {
            panic!("actual AUX forward path")
        };
        let Some(Backing::Direct(link)) = video.link.take() else {
            panic!("actual video/link chain")
        };
        self.reservation.take();
        aux.reservation.take();
        video.reservation.take();
        link
    }
    /// # Safety
    /// The containing stopped receipt proves matching live epoch, both PE0 and
    /// every actual hop disabled/PENDING0. Only LOCAL path IDs/flow credits may
    /// become reusable; independent endpoint DMA/IRQ/IOMMU and residual native
    /// permission/accounting remain retained by the returned bandwidth object.
    pub(super) unsafe fn release_stopped(
        mut self,
    ) -> (Box<super::usb3::Allocated>, [Arc<dyn Reservation>; 2]) {
        let Some(Backing::Previous(mut down)) = self.link.take() else {
            panic!("complete actual two-path chain")
        };
        let Some(Backing::Bandwidth(bandwidth)) = down.link.take() else {
            panic!("unique original bandwidth owner")
        };
        let down_owner = down
            .reservation
            .take()
            .expect("actual Down path allocation");
        let up_owner = self.reservation.take().expect("actual Up path allocation");
        (bandwidth, [down_owner, up_owner])
    }
    /// # Safety
    /// Actual path/link restoration or reset and all independent dependent DMA,
    /// IRQ/power lifetimes are satisfied, or the complete live path, both router
    /// owners and reciprocal link reservation are independently retained by the
    /// real native CM. This must never release an unknown prior owner's IDs.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::path::Active;
    /// fn release(path:Active){path.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        if let Some(link) = self.link.take() {
            // SAFETY: caller proves the actual full ownership transfer or drain.
            unsafe { link.retire() };
        }
        self.reservation.take();
    }
}
pub(super) fn retain_reservation(reservation: &Arc<dyn Reservation>) {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
    core::mem::forget(reservation.clone());
}
impl Drop for Active {
    fn drop(&mut self) {
        if self.changed
            && let Some(reservation) = &self.reservation
        {
            retain_reservation(reservation);
        }
    }
}

pub enum Event {
    Active(Active),
    Discarded(config::Error),
}
#[derive(Clone, Copy)]
struct Hop {
    route: Route,
    upstream: u8,
    input: u8,
    output: u8,
    ingress: u16,
    next: u16,
    lane: bool,
    credits: u8,
    header: [u32; 8],
    profile: Profile,
}
impl Hop {
    fn address(self, space: Space) -> Address {
        Address {
            port: self.input,
            space,
            offset: if space == Space::Hops {
                self.ingress * 2
            } else {
                0
            },
            words: if space == Space::Hops { 2 } else { 8 },
        }
    }
    fn program(self, before: Words, index: usize) -> Words {
        // Real tb_regs_hop bitfields, including counter=-1 with enable=0.
        // USB4 protocol-adapter credits/IFC/ISE are vendor-defined and retained.
        let credits = if self.lane {
            u32::from(self.credits) << 17
        } else {
            before.raw[0] & (127 << 17)
        };
        let video = matches!(self.profile, Profile::DisplayVideo(_));
        let ingress = if self.lane {
            if video { 0 } else { 1 << 24 }
        } else {
            before.raw[1] & ((1 << 24) | (1 << 26))
        };
        Words {
            raw: [
                u32::from(self.next) | (u32::from(self.output) << 11) | credits | ENABLE,
                (match self.profile {
                    Profile::Pcie => 1 | (3 << 8),
                    Profile::Usb3 => 2 | (3 << 8),
                    Profile::DisplayAux => 1 | (2 << 8),
                    Profile::DisplayVideo(_) => 1 | (1 << 8),
                }) | (2047 << 12)
                    | ingress
                    | if index == 0 && !video { 1 << 25 } else { 0 }
                    | (before.raw[1] & PENDING),
            ],
        }
    }
}
fn adapter(inventory: &Inventory, port: u8) -> Result<&AdapterHeader, Error> {
    inventory
        .adapters
        .iter()
        .find_map(|item| match item {
            AdapterObservation::Present {
                port: number,
                header,
                ..
            } if *number == port && port != 0 => Some(header),
            _ => None,
        })
        .ok_or(Error::Topology)
}
fn plan(link: &Linked, allocation: Allocation) -> Result<[Hop; 2], Error> {
    plan_profile(link, allocation, Profile::Usb3)
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Profile {
    Usb3,
    Pcie,
    DisplayAux,
    DisplayVideo(u16),
}
fn plan_profile(
    link: &Linked,
    allocation: Allocation,
    profile: Profile,
) -> Result<[Hop; 2], Error> {
    let (parent, child) = link.retained_routers().map_err(Error::Link)?;
    let partners = link.protected_partners();
    if allocation.identity != partners.identity
        || allocation.topology_epoch != partners.topology_epoch
        || allocation.grant_epoch == 0
        || link.partners != partners
    {
        return Err(Error::Identity);
    }
    if !link.link_usb4 || !matches!(link.generation, 2 | 3) {
        return Err(Error::Unsupported);
    }
    // Router::Policy owns USB3/PCIe only. DP authorization comes from its actual
    // separate native display reservation; no USB3/PCIe decision implies it.
    let policies = match profile {
        Profile::Usb3 => Some((
            parent.retained_owner().policy().usb3,
            child.retained_owner().policy().usb3,
        )),
        Profile::Pcie => Some((
            parent.retained_owner().policy().pcie,
            child.retained_owner().policy().pcie,
        )),
        Profile::DisplayAux | Profile::DisplayVideo(_) => None,
    };
    if allocation.permission != Decision::Allowed
        || policies.is_some_and(|(a, b)| a != Decision::Allowed || b != Decision::Allowed)
    {
        return Err(Error::Permission);
    }
    let parent_inventory = parent.retained_owner().target();
    let child_inventory = child.retained_owner().target();
    let down = adapter(parent_inventory, allocation.usb3_down)?;
    let up = adapter(child_inventory, allocation.usb3_up)?;
    let (down_kind, up_kind) = match profile {
        Profile::Pcie => (AdapterKind::PcieDown, AdapterKind::PcieUp),
        Profile::Usb3 => (AdapterKind::Usb3Down, AdapterKind::Usb3Up),
        Profile::DisplayAux | Profile::DisplayVideo(_) => {
            (AdapterKind::DisplayIn, AdapterKind::DisplayOut)
        }
    };
    if down.kind() != down_kind || up.kind() != up_kind {
        return Err(Error::Topology);
    }
    let credits = if let Profile::DisplayVideo(nfc) = profile {
        if nfc == 0 || nfc > 1023 || allocation.direction != Direction::Downstream {
            return Err(Error::Credits);
        }
        0
    } else {
        allocation.lane_credits.value()?
    };
    if profile == Profile::Pcie && credits < 6 {
        return Err(Error::Credits);
    }
    let (source, destination, inputs, outputs) = match allocation.direction {
        Direction::Downstream => (
            parent_inventory,
            child_inventory,
            [allocation.usb3_down, partners.child[0]],
            [partners.parent[0], allocation.usb3_up],
        ),
        Direction::Upstream => (
            child_inventory,
            parent_inventory,
            [allocation.usb3_up, partners.parent[0]],
            [partners.child[0], allocation.usb3_down],
        ),
    };
    let inventories = [source, destination];
    let mut hops = [None, None];
    for i in 0..2 {
        let inventory = inventories[i];
        let input = adapter(inventory, inputs[i])?;
        let output = adapter(inventory, outputs[i])?;
        let (ingress, next) = allocation.hops[i];
        if ingress < 8
            || ingress > input.max_in_hop()
            || next < 8
            || next > output.max_out_hop()
            || ingress >= 2048
            || next >= 2048
        {
            return Err(Error::HopId);
        }
        let endpoint_hop = if matches!(profile, Profile::DisplayVideo(_)) {
            9
        } else {
            8
        };
        if i == 0 && ingress != endpoint_hop
            || i == 1 && (next != endpoint_hop || ingress != allocation.hops[0].1)
        {
            return Err(Error::HopId);
        }
        let lane = input.kind() == AdapterKind::Lane;
        if (i == 1) != lane || (i == 0 && output.kind() != AdapterKind::Lane) {
            return Err(Error::Topology);
        }
        if lane {
            let actual = link
                .credits
                .iter()
                .find(|credit| credit.route == inventory.path.route() && credit.port == inputs[i])
                .ok_or(Error::Credits)?;
            let required = if let Profile::DisplayVideo(nfc) = profile {
                nfc
            } else {
                u16::from(credits)
            };
            if u32::from(actual.total()) < u32::from(actual.nonflow()) + u32::from(required) {
                return Err(Error::Credits);
            }
        }
        hops[i] = Some(Hop {
            route: inventory.path.route(),
            upstream: inventory.upstream_port,
            input: inputs[i],
            output: outputs[i],
            ingress,
            next,
            lane,
            credits: if lane { credits } else { 7 },
            header: input.raw,
            profile,
        });
    }
    Ok([
        hops[0].ok_or(Error::Topology)?,
        hops[1].ok_or(Error::Topology)?,
    ])
}
#[derive(Clone, Copy)]
pub(super) struct DrainHop {
    pub route: Route,
    pub port: u8,
    pub upstream: u8,
    pub id: u16,
    pub expected: Words,
    pub mask: [u32; 2],
}
impl DrainHop {
    pub fn matches(self, words: Words) -> bool {
        (0..2).all(|i| words.raw[i] & self.mask[i] == self.expected.raw[i] & self.mask[i])
    }
}
/// Private composition plan checked against the genuine protected link before
/// any first-path write. It carries no independent hardware authority.
pub(super) struct Prepared {
    allocation: Allocation,
    hops: [Hop; 2],
    profile: Profile,
}
pub(super) fn prepare(link: &Linked, allocation: Allocation) -> Result<Prepared, Error> {
    Ok(Prepared {
        allocation,
        hops: plan(link, allocation)?,
        profile: Profile::Usb3,
    })
}
pub(super) fn prepare_pcie(link: &Linked, allocation: Allocation) -> Result<Prepared, Error> {
    Ok(Prepared {
        allocation,
        hops: plan_profile(link, allocation, Profile::Pcie)?,
        profile: Profile::Pcie,
    })
}
pub(super) fn prepare_dp(
    link: &Linked,
    allocation: Allocation,
    nfc: Option<u16>,
) -> Result<Prepared, Error> {
    let profile = match nfc {
        Some(n) => Profile::DisplayVideo(n),
        None => Profile::DisplayAux,
    };
    Ok(Prepared {
        allocation,
        hops: plan_profile(link, allocation, profile)?,
        profile,
    })
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Inventory(usize),
    Credit,
    NfcWrite(u32),
    NfcVerify(u32),
    Initial(usize),
    Disable(usize, Words),
    Drain(usize),
    Prepare(usize),
    Write(usize, Words),
    Verify(usize, Words),
    Done,
    Fault,
}
/// Polled actual path programming. DP video additionally owns real lane NFC;
/// all profiles have no allocated counters, so no counter clear is fabricated.
pub struct Activate<R: Registers> {
    channel: Option<Channel<R>>,
    retained: Option<Active>,
    hops: [Hop; 2],
    stage: Stage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    last_now: u64,
    next_poll: u64,
}
impl<R: Registers> Activate<R> {
    /// # Safety
    /// The containing native CM owns the actual current link/allocator/security
    /// grant and preflighted this exact private plan and every clock addition.
    pub(super) unsafe fn start_pcie(
        channel: Channel<R>,
        link: Box<Linked>,
        reservation: Arc<dyn Reservation>,
        prepared: Prepared,
        now: u64,
        deadline: u64,
        job_deadline: u64,
    ) -> Self {
        Self::initialize(
            channel,
            Backing::Direct(link),
            reservation,
            prepared,
            now,
            deadline,
            job_deadline,
        )
    }
    /// # Safety
    /// The Channel, complete retained Linked and native allocation are the exact
    /// same physical NHI/reset/topology/grant epoch, exclusively idle/current.
    /// Reservation's real allocator, permission, mapping, bandwidth, credit and
    /// dependent-path lifetime obligations hold; matching numbers alone do not
    /// prove that pairing. No independent endpoint/attachment resource is retired.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,link::Linked,path::{Activate,Reservation},ring::Registers};
    /// fn pair<R:Registers>(c:Channel<R>,l:Box<Linked>,r:Arc<dyn Reservation>){let _=Activate::new(c,l,r,0);}
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        link: Box<Linked>,
        reservation: Arc<dyn Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        let allocation = reservation.allocation();
        Self::new_inner(channel, Backing::Direct(link), reservation, allocation, now)
    }
    /// Consume the exact completed root bandwidth handshake without cloning its
    /// original link or native accounting/permission ownership.
    ///
    /// # Safety
    /// All `new` physical pairing/grant requirements hold. This exact allocated
    /// bandwidth reservation belongs to the same protected endpoints, permission
    /// generation and source path allocation; no other tunnel consumes it.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,path::{Activate,Reservation},usb3::Allocated,ring::Registers};
    /// fn pair<R:Registers>(c:Channel<R>,a:Box<Allocated>,r:Arc<dyn Reservation>){let _=Activate::with_bandwidth(c,a,r,0);}
    /// ```
    pub unsafe fn with_bandwidth(
        channel: Channel<R>,
        bandwidth: Box<super::usb3::Allocated>,
        reservation: Arc<dyn Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        if !bandwidth.is_current() {
            retain_reservation(&reservation);
            return Err(Error::Revoked);
        }
        let path = reservation.allocation();
        let grant = bandwidth.protected_grant();
        if grant.identity != path.identity
            || grant.topology_epoch != path.topology_epoch
            || grant.grant_epoch != path.grant_epoch
            || grant.usb3_down != path.usb3_down
            || grant.usb3_up != path.usb3_up
            || grant.permission != Decision::Allowed
        {
            retain_reservation(&reservation);
            return Err(Error::Identity);
        }
        Self::new_inner(
            channel,
            Backing::Bandwidth(bandwidth),
            reservation,
            path,
            now,
        )
    }
    fn new_inner(
        channel: Channel<R>,
        link: Backing,
        reservation: Arc<dyn Reservation>,
        allocation: Allocation,
        now: u64,
    ) -> Result<Self, Error> {
        let prepared = (|| {
            let prepared = prepare(link.linked(), allocation)?;
            let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
            let job_deadline = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
            Ok((prepared, deadline, job_deadline))
        })();
        let (prepared, deadline, job_deadline) = match prepared {
            Ok(value) => value,
            Err(error) => {
                if !matches!(link, Backing::Direct(_)) {
                    retain_reservation(&reservation);
                }
                return Err(error);
            }
        };
        Ok(Self::initialize(
            channel,
            link,
            reservation,
            prepared,
            now,
            deadline,
            job_deadline,
        ))
    }
    /// # Safety
    /// The containing actual native CM has preflighted this exact protected
    /// plan, same physical pairing and endpoint authority, and checked all clock
    /// additions before moving ownership. This is not a public admission API.
    pub(super) unsafe fn start_bandwidth(
        channel: Channel<R>,
        bandwidth: Box<super::usb3::Allocated>,
        reservation: Arc<dyn Reservation>,
        prepared: Prepared,
        now: u64,
        deadline: u64,
        job_deadline: u64,
    ) -> Self {
        Self::initialize(
            channel,
            Backing::Bandwidth(bandwidth),
            reservation,
            prepared,
            now,
            deadline,
            job_deadline,
        )
    }
    /// # Safety
    /// Same exact physical/grant proof as start_bandwidth; the protected plan is
    /// the opposite direction and all real first-path/bandwidth owners remain
    /// inside previous. Its wrapper storage was reserved before first mutation.
    pub(super) unsafe fn start_previous(
        channel: Channel<R>,
        previous: Box<Active>,
        reservation: Arc<dyn Reservation>,
        prepared: Prepared,
        now: u64,
        deadline: u64,
        job_deadline: u64,
    ) -> Self {
        Self::initialize(
            channel,
            Backing::Previous(previous),
            reservation,
            prepared,
            now,
            deadline,
            job_deadline,
        )
    }
    fn initialize(
        channel: Channel<R>,
        link: Backing,
        reservation: Arc<dyn Reservation>,
        prepared: Prepared,
        now: u64,
        deadline: u64,
        job_deadline: u64,
    ) -> Self {
        // A prior actual bandwidth/path success makes the complete transaction
        // live already. Retain the new path reservation even if later preflight
        // or construction fails before its first own write.
        let changed = !matches!(link, Backing::Direct(_));
        Self {
            channel: Some(channel),
            retained: Some(Active {
                allocation: prepared.allocation,
                words: [Words { raw: [0; 2] }; 2],
                link: Some(link),
                reservation: Some(reservation),
                changed,
                profile: prepared.profile,
            }),
            hops: prepared.hops,
            stage: Stage::Inventory(0),
            expected: None,
            deadline,
            job_deadline,
            last_now: now,
            next_poll: now,
        }
    }
    fn channel(&mut self) -> &mut Channel<R> {
        self.channel.as_mut().expect("retained channel")
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
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
    fn request(&self) -> Result<(Hop, Address, Option<[u32; 2]>), Error> {
        let (index, space, data) = match self.stage {
            Stage::Inventory(i) => (i, Space::Port, None),
            Stage::Credit | Stage::NfcWrite(_) | Stage::NfcVerify(_) => {
                let hop = self.hops[1];
                return Ok((
                    hop,
                    Address {
                        port: hop.input,
                        space: Space::Port,
                        offset: 4,
                        words: 1,
                    },
                    if let Stage::NfcWrite(word) = self.stage {
                        Some([word, 0])
                    } else {
                        None
                    },
                ));
            }
            Stage::Initial(i) | Stage::Drain(i) | Stage::Prepare(i) | Stage::Verify(i, _) => {
                (i, Space::Hops, None)
            }
            Stage::Disable(i, words) | Stage::Write(i, words) => (i, Space::Hops, Some(words.raw)),
            _ => return Err(Error::Stopped),
        };
        let hop = self.hops[index];
        Ok((hop, hop.address(space), data))
    }
    pub(super) fn is_current(&self) -> bool {
        self.retained.as_ref().is_some_and(|path| path.is_current())
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        if !self.is_current() {
            return self.fail(Error::Revoked);
        }
        if self.expected.is_some() || now < self.next_poll {
            return Ok(());
        }
        let (hop, address, data) = self.request()?;
        let deadline = self.deadline;
        let result = if let Some(data) = data {
            let result = self.channel().write(
                hop.route,
                address,
                &data[..usize::from(address.words)],
                now,
                deadline,
            );
            if !matches!(
                result,
                Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full))
            ) {
                self.retained.as_mut().expect("retained allocation").changed = true;
            }
            result
        } else {
            self.channel().read(hop.route, address, now, deadline)
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
            Stage::Inventory(i) => {
                let actual = AdapterHeader::parse(&data).map_err(|_| Error::UnexpectedReceipt)?;
                let expected = AdapterHeader {
                    raw: self.hops[i].header,
                };
                if actual.kind() != expected.kind()
                    || actual.reported_port() != self.hops[i].input
                    || actual.max_in_hop() != expected.max_in_hop()
                    || actual.max_out_hop() != expected.max_out_hop()
                {
                    return self.fail(Error::Changed);
                }
                self.enter(
                    if i == 0 {
                        Stage::Inventory(1)
                    } else {
                        Stage::Credit
                    },
                    now,
                )?;
            }
            Stage::Credit => {
                let [raw] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                let required = if let Profile::DisplayVideo(nfc) = self.hops[1].profile {
                    u32::from(nfc)
                } else {
                    u32::from(self.hops[1].credits)
                };
                if (raw >> 20) & 1023 < (raw & 1023) + required {
                    return self.fail(Error::Credits);
                }
                if matches!(self.hops[1].profile, Profile::DisplayVideo(_)) {
                    self.enter(
                        Stage::NfcWrite((raw & !1023) | ((raw & 1023) + required)),
                        now,
                    )?;
                } else {
                    self.enter(Stage::Initial(0), now)?;
                }
            }
            Stage::NfcWrite(word) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::NfcVerify(word), now)?;
            }
            Stage::NfcVerify(expected) => {
                let [actual] = data.as_slice() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                if actual & 1023 != expected & 1023 || (actual & 1023) > ((actual >> 20) & 1023) {
                    return self.fail(Error::Readback);
                }
                self.enter(Stage::Initial(0), now)?;
            }
            Stage::Initial(_) | Stage::Drain(_) | Stage::Prepare(_) | Stage::Verify(_, _) => {
                let raw: [u32; 2] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::UnexpectedReceipt)?;
                let words = Words { raw };
                match self.stage {
                    Stage::Initial(i) => self.enter(
                        if raw[0] & ENABLE != 0 {
                            Stage::Disable(
                                i,
                                Words {
                                    raw: [raw[0] & !ENABLE, raw[1]],
                                },
                            )
                        } else {
                            Stage::Prepare(i)
                        },
                        now,
                    )?,
                    Stage::Drain(i) => {
                        if raw[0] & ENABLE != 0 {
                            return self.fail(Error::Changed);
                        }
                        if raw[1] & PENDING == 0 {
                            self.enter(Stage::Prepare(i), now)?;
                        } else {
                            self.next_poll = now.checked_add(1).ok_or(Error::ClockOverflow)?;
                        }
                    }
                    Stage::Prepare(i) => {
                        if raw[0] & ENABLE != 0 {
                            return self.fail(Error::Changed);
                        }
                        self.enter(Stage::Write(i, self.hops[i].program(words, i)), now)?;
                    }
                    Stage::Verify(i, programmed) => {
                        if raw[0] != programmed.raw[0]
                            || raw[1] & !PENDING != programmed.raw[1] & !PENDING
                        {
                            return self.fail(Error::Readback);
                        }
                        self.retained.as_mut().expect("retained allocation").words[i] = words;
                        if i == 0 {
                            self.enter(Stage::Initial(1), now)?;
                        } else {
                            if !self.is_current() {
                                return self.fail(Error::Revoked);
                            }
                            self.stage = Stage::Done;
                            return Ok(Some(Event::Active(
                                self.retained.take().ok_or(Error::UnexpectedReceipt)?,
                            )));
                        }
                    }
                    _ => unreachable!(),
                }
            }
            Stage::Disable(i, _) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::Drain(i), now)?;
            }
            Stage::Write(i, programmed) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.enter(Stage::Verify(i, programmed), now)?;
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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use crate::bus::thunderbolt::config::PacketType;
    use crate::bus::thunderbolt::ring::{self, TX_DESCRIPTOR, model::*};
    use alloc::vec::Vec;

    #[test]
    fn path_actual_link_two_directions_credit_modes_stale_drain_and_retained_lifetime() {
        use super::super::path::{Activate, Direction, LaneCredits};
        for direction in [Direction::Downstream, Direction::Upstream] {
            for credits in [LaneCredits::LegacyBonded, LaneCredits::RouterAllocated(23)] {
                for stale in [false, true] {
                    let PathFixture {
                        domain,
                        model,
                        channel,
                        linked,
                        reservation,
                        mut cursor,
                        dropped,
                    } = path_fixture(direction, credits);
                    let mut peer = PathPeer::new(&linked, reservation.allocation, stale, 5);
                    let protocol = peer.raw[0];
                    // SAFETY: real model protected IDs/credits/permission and exact retained physical link.
                    let mut activate =
                        unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
                    let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
                    assert_eq!(peer.writes.len(), if stale { 4 } else { 2 });
                    assert_eq!(
                        active.words[0].raw[0] & (127 << 17),
                        protocol[0] & (127 << 17)
                    );
                    assert_eq!(
                        active.words[0].raw[1] & ((1 << 24) | (1 << 26)),
                        protocol[1] & ((1 << 24) | (1 << 26))
                    );
                    assert_eq!(
                        (active.words[1].raw[0] >> 17) & 127,
                        match credits {
                            LaneCredits::LegacyBonded => 32,
                            LaneCredits::RouterAllocated(n) => u32::from(n),
                        }
                    );
                    assert!(
                        dropped
                            .iter()
                            .all(|counter| counter.load(Ordering::Relaxed) == 0)
                    );
                    let mut channel = activate.into_channel();
                    // SAFETY: actual model complete path and all owners transfer into independently retained CM through final drain.
                    unsafe { active.retire() };
                    assert!(
                        dropped
                            .iter()
                            .all(|counter| counter.load(Ordering::Relaxed) == 1)
                    );
                    channel_release(&mut channel);
                }
            }
        }
    }

    #[test]
    fn path_invalid_actual_grants_hop_bounds_and_mapping_refuse_before_publication() {
        use super::super::path::{Activate, Direction, LaneCredits};
        for case in 0..13 {
            let PathFixture {
                model,
                channel,
                mut linked,
                reservation,
                cursor,
                dropped,
                ..
            } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
            let mut allocation = reservation.allocation;
            match case {
                0 => allocation.identity.epoch += 1,
                1 => allocation.topology_epoch += 1,
                2 => allocation.grant_epoch = 0,
                3 => allocation.permission = super::super::router::Decision::Unresolved,
                4 => allocation.permission = super::super::router::Decision::Denied,
                5 => allocation.usb3_down = linked.partners.parent[0],
                6 => allocation.usb3_up = linked.partners.child[0],
                7 => allocation.hops[0].0 = 9,
                8 => allocation.hops[0].1 = 128,
                9 => allocation.hops[1].0 = 30,
                10 => allocation.lane_credits = LaneCredits::RouterAllocated(128),
                11 => linked.link_usb4 = false,
                12 => linked.partners.topology_epoch += 1,
                _ => unreachable!(),
            }
            let replacement = Arc::new(PathReservation {
                allocation,
                dropped: dropped[3].clone(),
            });
            drop(reservation);
            let writes = model.state.lock().unwrap().writes.len();
            // SAFETY: same negative model pairing; invalid metadata must refuse without requests.
            assert!(unsafe { Activate::new(channel, linked, replacement, cursor.now) }.is_err());
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            assert!(
                dropped[..3]
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 0)
            );
            assert_eq!(dropped[3].load(Ordering::Relaxed), 2);
        }
    }

    #[test]
    fn path_each_disable_or_activation_write_failure_keeps_link_and_all_ids() {
        use super::super::path::{Activate, Direction, Error, LaneCredits};
        for target in 1..=4 {
            for failure in 0..3 {
                let PathFixture {
                    domain,
                    model,
                    channel,
                    linked,
                    reservation,
                    mut cursor,
                    dropped,
                } = path_fixture(Direction::Upstream, LaneCredits::RouterAllocated(19));
                let mut peer = PathPeer::new(&linked, reservation.allocation, true, 1);
                if failure == 2 {
                    peer.reject = Some(target);
                }
                // SAFETY: exact protected model link, permission and resource reservation.
                let mut activate =
                    unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
                activate.poll(cursor.now).unwrap();
                let mut failed = false;
                for _ in 0..100 {
                    let producer = model.read32(TX_DESCRIPTOR + 8) >> 16;
                    if producer as usize == cursor.tx % 10 {
                        cursor.now += 1;
                        assert!(activate.poll(cursor.now).unwrap().is_none());
                        continue;
                    }
                    let mut reply = peer.respond(&domain, &model, cursor.tx % 10);
                    if peer.writes.len() == target && failure == 0 {
                        assert!(matches!(
                            activate.poll(cursor.now + 501),
                            Err(Error::Timeout)
                        ));
                        cursor.now += 501;
                        failed = true;
                        break;
                    }
                    if peer.writes.len() == target && failure == 1 {
                        let bytes = domain
                            .data(model.frame_address(ring::Direction::Tx, cursor.tx % 10), 16);
                        reply = incoming(
                            PacketType::Error,
                            &[
                                u32::from_be_bytes(bytes[..4].try_into().unwrap()) | (1 << 31),
                                u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                                2,
                            ],
                        );
                    }
                    model.finish(ring::Direction::Tx, cursor.tx % 10, &[], None);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    match activate.poll(cursor.now) {
                        Err(Error::Changed | Error::Readback | Error::Controller { .. }) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {}
                        _ => panic!("unexpected path failure result"),
                    }
                }
                assert!(failed, "target={target} failure={failure}");
                assert_eq!(peer.writes.len(), target);
                let writes = model.state.lock().unwrap().writes.len();
                assert!(matches!(
                    activate.poll(cursor.now + 1),
                    Err(Error::Poisoned)
                ));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
                let mut channel = activate.into_channel();
                assert!(
                    dropped
                        .iter()
                        .all(|counter| counter.load(Ordering::Relaxed) == 0)
                );
                channel_release(&mut channel);
            }
        }
    }

    #[test]
    fn path_header_credit_refusal_and_stale_pending_deadline_cannot_claim_restoration() {
        use super::super::path::{Activate, Direction, Error, LaneCredits};
        for case in 0..3 {
            let PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
            let mut peer = PathPeer::new(&linked, reservation.allocation, true, 4);
            peer.changed_header = case == 0;
            peer.credit = if case == 1 {
                (32 << 20) | 8
            } else {
                peer.credit
            };
            peer.hold_pending = case == 2;
            // SAFETY: exact owned synthetic path with negative device effects.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
            activate.poll(cursor.now).unwrap();
            let mut failed = false;
            let mut disabled_ack = None;
            for _ in 0..600 {
                match path_step(&mut peer, &domain, &model, &mut activate, &mut cursor) {
                    Err(Error::Changed | Error::Credits | Error::Timeout) => {
                        failed = true;
                        break;
                    }
                    Ok(None) => {
                        if !peer.writes.is_empty() {
                            disabled_ack.get_or_insert(cursor.now);
                        }
                    }
                    _ => panic!("unexpected pending/refusal outcome"),
                }
            }
            assert!(failed);
            if case == 2 {
                assert_eq!(
                    cursor.now,
                    disabled_ack.expect("actual disable ACK") + 500,
                    "repeated pending reads must not extend the ACK-anchored drain window"
                );
            }
            assert_eq!(peer.writes.len(), usize::from(case == 2));
            let mut channel = activate.into_channel();
            assert!(
                dropped[..3]
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 0)
            );
            assert_eq!(dropped[3].load(Ordering::Relaxed), usize::from(case != 2));
            channel_release(&mut channel);
        }
    }

    #[test]
    #[ignore = "requires unchanged Linux two-hop path oracle trace"]
    fn unchanged_linux_path_usb3_complete_write_trace_matches_actual_dma() {
        use super::super::path::{Activate, Direction, LaneCredits};
        let text = std::fs::read_to_string(
            std::env::var("STELA_THUNDERBOLT_PATH_ORACLE").expect("set oracle trace path"),
        )
        .unwrap();
        let mut cases = 0;
        for line in text.lines() {
            let values: Vec<u32> = line
                .split_ascii_whitespace()
                .skip(1)
                .map(|s| s.parse().unwrap())
                .collect();
            let [direction, mode, stale, seed] = values[..4] else {
                panic!("oracle case header")
            };
            let direction = if direction == 0 {
                Direction::Downstream
            } else {
                Direction::Upstream
            };
            let credits = if mode == 0 {
                LaneCredits::LegacyBonded
            } else {
                LaneCredits::RouterAllocated((17 + seed % 31) as u8)
            };
            let PathFixture {
                domain,
                model,
                channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = path_fixture(direction, credits);
            let mut peer = PathPeer::new(&linked, reservation.allocation, stale != 0, seed);
            peer.raw = [[values[4], values[5]], [values[6], values[7]]];
            let count = values[8] as usize;
            let expected: Vec<_> = values[9..9 + count * 5]
                .as_chunks::<5>()
                .0
                .iter()
                .map(|v| (v[0] as usize, v[1] as u8, v[2] as u16, [v[3], v[4]]))
                .collect();
            let final_words = &values[9 + count * 5..];
            assert_eq!(final_words.len(), 4);
            // SAFETY: same actual fixture link and independently protected model allocations/grants.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
            let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
            assert_eq!(peer.writes, expected, "case={cases}");
            assert_eq!(active.words[0].raw, final_words[..2], "case={cases}");
            assert_eq!(active.words[1].raw, final_words[2..], "case={cases}");
            let mut channel = activate.into_channel();
            // SAFETY: all native synthetic owners transfer across actual model final drain.
            unsafe { active.retire() };
            assert!(
                dropped
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 1)
            );
            channel_release(&mut channel);
            cases += 1;
        }
        assert_eq!(cases, 512);
    }

    #[test]
    fn path_publication_stall_clock_revocation_and_unconsumed_success_are_contained() {
        use super::super::{
            config::{Address, Route, Space},
            path::{Activate, Direction, Error, LaneCredits},
        };
        for mode in 0..5 {
            let PathFixture {
                domain,
                model,
                mut channel,
                linked,
                reservation,
                mut cursor,
                dropped,
            } = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
            let mut peer = PathPeer::new(&linked, reservation.allocation, false, 2);
            if mode == 0 {
                for _ in 0..9 {
                    channel
                        .read(
                            Route::new(0).unwrap(),
                            Address {
                                port: 1,
                                space: Space::Port,
                                offset: 4,
                                words: 1,
                            },
                            cursor.now,
                            cursor.now + 1000,
                        )
                        .unwrap();
                    let reply = adapter_response(&domain, &model, cursor.tx % 10, 4, &[0]);
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.tx += 1;
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(
                        channel.poll(cursor.now),
                        Ok(Some(super::super::channel::Event::Completed { .. }))
                    ));
                }
            }
            // SAFETY: protected real synthetic link and idle channel; mode0 leaves physical TX DMA unconsumed.
            let mut activate =
                unsafe { Activate::new(channel, linked, reservation, cursor.now) }.unwrap();
            if mode == 0 {
                let writes = model.state.lock().unwrap().writes.len();
                for delta in [0, 1, 499] {
                    assert!(activate.poll(cursor.now + delta).unwrap().is_none());
                }
                assert!(matches!(
                    activate.poll(cursor.now + 500),
                    Err(Error::Timeout)
                ));
                assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            } else if mode == 1 {
                assert!(matches!(
                    activate.poll(cursor.now - 1),
                    Err(Error::ClockRegressed)
                ));
            } else if mode == 4 {
                let active = drive_path(&mut peer, &domain, &model, &mut activate, &mut cursor);
                drop(active);
            } else {
                activate.poll(cursor.now).unwrap();
                for _ in 0..20 {
                    assert!(
                        path_step(&mut peer, &domain, &model, &mut activate, &mut cursor)
                            .unwrap()
                            .is_none()
                    );
                    if !peer.writes.is_empty() {
                        break;
                    }
                }
                assert_eq!(peer.writes.len(), 1);
                if mode == 2 {
                    assert!(matches!(activate.cancel(), Err(Error::Cancelled)));
                } else {
                    let event = incoming(PacketType::Event, &[0, 0, 1]);
                    finish_rx(&model, cursor.rx % 10, &event);
                    cursor.rx += 1;
                    cursor.now += 1;
                    assert!(matches!(activate.poll(cursor.now), Err(Error::Hotplug(_))));
                }
            }
            let mut channel = activate.into_channel();
            assert!(
                dropped[..3]
                    .iter()
                    .all(|counter| counter.load(Ordering::Relaxed) == 0)
            );
            assert_eq!(dropped[3].load(Ordering::Relaxed), usize::from(mode < 2));
            channel_release(&mut channel);
        }
    }
}
