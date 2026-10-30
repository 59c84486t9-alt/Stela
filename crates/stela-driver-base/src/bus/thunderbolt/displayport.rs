// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! Ordinary DP tunneling over an owned adjacent USB4v1 Gen2/3 link.
//!
//! Source CM/capability exchange, video NFC and both AUX paths, endpoint enable,
//! DPRX completion and normal stop. Native GPU/connector association, bandwidth,
//! credits, HopIDs and protected platform lifetimes must already be owned.
pub use super::pcie::Error;
use super::{
    channel::Channel,
    domain::Identity,
    link::Linked,
    path::{self, Direction, LaneCredits},
    pcie::{Endpoint, checked_reply, endpoint, storage},
    ring::Registers,
    router::Decision,
    topology::{AdapterKind, RouterHeader},
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicU64, Ordering},
};
mod activate;
mod stop;
pub use activate::{Activate, Event};
pub use stop::{Reusable, Stop, StopEvent, Stopped};
const ENABLE: u32 = 3 << 30;
const PENDING: u32 = 1 << 28;
const REQUEST_MS: u64 = 500;
const JOB_MS: u64 = 60_000;
const HANDSHAKE_MS: u64 = 3000;
const DPRX_MS: u64 = 12_000;
const CMHS: u32 = 1 << 25;
const UF: u32 = 1 << 26;
const BW_MODE: u32 = 1 << 28;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_reservations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credits {
    /// Source bonded legacy policy: AUX=1, video=min(total-2,12).
    LegacyBonded,
    /// Source VSEC/shared-allocation reservations, not caller estimates.
    RouterAllocated { video: u16, aux: [u8; 2] },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub identity: Identity,
    pub topology_epoch: u64,
    pub grant_epoch: u64,
    pub dp_in: u8,
    pub dp_out: u8,
    /// Video downstream, AUX downstream, AUX upstream; source/destination pairs.
    pub hops: [[(u16, u16); 2]; 3],
    pub credits: Credits,
    /// Real reserved downstream Mb/s. Zero requires an exclusive native
    /// bandwidth right covering the full observed endpoint capabilities.
    pub max_mbps: u32,
    pub permission: Decision,
}
/// Native DP association, domain accounting and exact exclusive CM reservation.
///
/// # Safety
/// This keeps GPU/connector-to-DP-IN/OUT mapping, powered router/link,
/// all input/output HopIDs, source-selected video NFC/AUX credits and
/// shared domain bandwidth rights in this exact NHI/reset/topology epoch. It
/// excludes firmware/other CM mutations and resource reuse, including after
/// failure/quarantine. Permission is the native DP/_OSC decision. The
/// native GPU/connector/D0 and source VSEC accounting must not be inferred from
/// IDs, route/port numbers or requested rates. `is_current` reads real admission
/// state and keeps the in-flight physical lifetime against reassignment.
/// Independent GPU payload, endpoint DMA, IRQ/IOMMU and host display submission
/// lifetimes stay held; local tunnel/HPD/NFC completion cannot release them.
/// No production provider or permissive default is supplied by this trait.
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
struct PathOwner {
    owner: Arc<dyn Reservation>,
    grant: Grant,
    allocation: path::Allocation,
}
// SAFETY: the adapter keeps the original native grant and its real
// current guard; no path permission is created from the stored numeric metadata.
unsafe impl path::Reservation for PathOwner {
    fn allocation(&self) -> path::Allocation {
        self.allocation
    }
    fn is_current(&self) -> bool {
        self.owner.is_current() && self.owner.grant() == self.grant
    }
}
fn allocation(grant: Grant, index: usize) -> path::Allocation {
    let aux = match grant.credits {
        Credits::LegacyBonded => [1; 2],
        Credits::RouterAllocated { aux, .. } => aux,
    };
    path::Allocation {
        identity: grant.identity,
        topology_epoch: grant.topology_epoch,
        grant_epoch: grant.grant_epoch,
        direction: if index == 2 {
            Direction::Upstream
        } else {
            Direction::Downstream
        },
        usb3_down: grant.dp_in,
        usb3_up: grant.dp_out,
        hops: grant.hops[index],
        // Video has no flow-controlled initial credits; its real NFC allocation
        // is carried separately by the private video profile.
        lane_credits: LaneCredits::RouterAllocated(if index == 0 { 0 } else { aux[index - 1] }),
        permission: grant.permission,
    }
}
fn video_nfc(link: &Linked, credits: Credits) -> Result<u16, Error> {
    let (_, child) = link.retained_routers().map_err(Error::Link)?;
    let port = link.protected_partners().child[0];
    let actual = link
        .credits
        .iter()
        .find(|c| c.route == child.route && c.port == port)
        .ok_or(Error::Capability)?;
    let value = match credits {
        Credits::LegacyBonded => actual
            .total()
            .checked_sub(2)
            .ok_or(Error::Capability)?
            .min(12),
        Credits::RouterAllocated { video, aux } => {
            if aux.iter().any(|n| *n == 0 || *n > 127) {
                return Err(Error::Capability);
            }
            video
        }
    };
    if value == 0
        || value > 1023
        || u32::from(actual.nonflow()) + u32::from(value) > u32::from(actual.total())
    {
        return Err(Error::Capability);
    }
    Ok(value)
}
fn rate(cap: u32) -> Result<u32, Error> {
    match (cap >> 8) & 15 {
        0 => Ok(1620),
        1 => Ok(2700),
        2 => Ok(5400),
        3 => Ok(8100),
        _ => Err(Error::Unsupported),
    }
}
fn lanes(cap: u32) -> Result<u32, Error> {
    match (cap >> 12) & 7 {
        0 => Ok(1),
        1 => Ok(2),
        2 => Ok(4),
        _ => Err(Error::Unsupported),
    }
}
fn limited_cap(input: u32, output: u32, max_mbps: u32) -> Result<u32, Error> {
    let (input_rate, input_lanes, output_rate, output_lanes) =
        (rate(input)?, lanes(input)?, rate(output)?, lanes(output)?);
    if max_mbps == 0 || output_rate * output_lanes * 8 / 10 <= max_mbps {
        return Ok(output);
    }
    // Source preference order, including equal-bandwidth combinations.
    for (new_rate, new_lanes) in [
        (8100, 4),
        (5400, 4),
        (8100, 2),
        (2700, 4),
        (5400, 2),
        (8100, 1),
        (1620, 4),
        (5400, 1),
        (2700, 2),
        (1620, 2),
        (2700, 1),
        (1620, 1),
    ] {
        if new_rate <= input_rate
            && new_rate <= output_rate
            && new_lanes <= input_lanes
            && new_lanes <= output_lanes
            && new_rate * new_lanes * 8 / 10 <= max_mbps
        {
            let r = match new_rate {
                1620 => 0,
                2700 => 1,
                5400 => 2,
                8100 => 3,
                _ => unreachable!(),
            };
            let l = match new_lanes {
                1 => 0,
                2 => 1,
                4 => 2,
                _ => unreachable!(),
            };
            return Ok((output & !((15 << 8) | (7 << 12))) | (r << 8) | (l << 12));
        }
    }
    Err(Error::Capability)
}
fn titan(header: &RouterHeader) -> bool {
    // Original nhi.h hardware aliases, not an application/OEM exception.
    header.vendor() == 0x8086 && matches!(header.device(), 0x15e7 | 0x15ea | 0x15ef)
}
/// Completed CM exchange, all three paths, endpoint enables and DPRX.
/// This owns tunnel resources; it does not prove GPU scanout or physical display.
pub struct Active {
    pub endpoints: [[u32; 2]; 2],
    pub local_caps: [u32; 2],
    pub remote_caps: [u32; 2],
    pub dprx: u32,
    grant: Grant,
    video_nfc: u16,
    owner: Option<Arc<dyn Reservation>>,
    path: Option<path::Active>,
    previous: Option<Box<path::Active>>,
    link: Option<Box<Linked>>,
    pending: [Option<Arc<dyn path::Reservation>>; 3],
}
impl Active {
    fn current(&self) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|o| o.is_current() && o.grant() == self.grant)
    }
    /// # Safety
    /// Full restoration/reset or independent native CM transfer includes
    /// both routers, video NFC, all three paths, GPU/connector power and every
    /// independent endpoint payload/DMA/IRQ/IOMMU lifetime.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::displayport::Active;
    /// fn retire(a:Active){a.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        if let Some(path) = self.path.take() {
            // SAFETY: caller proves complete restoration/kept transfer of
            // the three-path/link chain and independent payload owners.
            unsafe { path.retire() };
        }
        if let Some(path) = self.previous.take() {
            // SAFETY: the same caller proof includes any partial earlier chain.
            unsafe { path.retire() };
        }
        if let Some(link) = self.link.take() {
            // SAFETY: caller proof keeps/restores the original active routers
            // even if CM/capability exchange failed before any path publication.
            unsafe { link.retire() };
        }
        self.pending = [None, None, None];
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

#[cfg(test)]
mod tests;
