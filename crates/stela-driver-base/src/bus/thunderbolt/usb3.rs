// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Root USB3 bandwidth and two-direction tunnel activation/stop from Linux
//! usb4.c/path.c/tunnel.c/switch.c, with one ownership chain.
//! Native accounting/permission/endpoint-control providers and host admission
//! remain explicit external requirements; no OS service is invented.
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
mod activation;
mod allocation;
mod stop;
use activation::*;
pub use activation::{ActivateTunnel, ActiveTunnel, TunnelEvent};
pub use allocation::Allocate;
pub use stop::{ReleaseUnused, Reusable, StopEvent, StopTunnel, Stopped};
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
/// Exclusive native root bandwidth-accounting and permission reservation.
///
/// # Safety
/// This keeps the real shared-domain accounting right for the requested rates,
/// existing consumed traffic and source quantization, with _OSC/security
/// permission and USB3↔primary-lane mapping for this exact Linked/requester/reset/
/// topology/grant epoch. The object is the reservation, not supplied
/// numeric quotas. Existing consumed rights cannot be removed or double charged.
/// It owns the root USB3 CMR/HCA transition, excludes firmware/other CM changes,
/// keeps endpoint/router/power lifetimes, and serializes dependent path work.
/// Real DMA/IMR/IOMMU/IRQ ownership remains independently held through final drain.
/// Metadata stays protected until no mutation, real restore/reset or independent
/// ownership transfer. No production allocator/policy implementation or
/// fallback admission is provided by this trait. An integer grant alone is never
/// sufficient permission for implementing it.
/// When supplied to ActivateTunnel it ALSO keeps exclusive CS0 PE/V
/// control permission for BOTH mapped USB3 endpoints through uncertain completion
/// and quarantine. That real platform grant is not implied by path IDs, matching
/// numbers or a bandwidth request; an implementation lacking it cannot be used
/// for endpoint activation.
pub unsafe trait Reservation: Send + Sync {
    fn grant(&self) -> Grant;
    /// Native reset/topology/permission guard, never numeric
    /// tuple equality or MMIO readiness. No permissive default is provided.
    /// A true snapshot alone is insufficient: this object must also keep real
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
/// Root bandwidth allocation; both HCA transitions completed. This owns
/// its single original link and accounting reservation until real retire.
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
    /// DMA/IRQ/power lifetimes are satisfied, or the allocation, link and
    /// both routers have independently kept native CM ownership. Clearing
    /// CMR/HCA never releases allocated bandwidth or proves endpoint quiescence.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::usb3::Allocated;
    /// fn release(a:Allocated){a.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        if let Some(link) = self.link.take() {
            // SAFETY: covered by this function's own safety contract.
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
#[cfg(test)]
mod tests;
