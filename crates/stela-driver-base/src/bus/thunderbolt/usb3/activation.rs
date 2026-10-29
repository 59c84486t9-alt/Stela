// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Two-direction USB3 tunnel activation: path hops, endpoint enables and the
//! active tunnel.

use super::*;

pub(super) const ENDPOINT_ENABLE: u32 = (1 << 31) | (1 << 30);
pub(super) const TUNNEL_MS: u64 = 30_000;
/// Both USB3 directions and enabled endpoints with one original
/// link/accounting chain. Native host admission/OS attachment remains external.
pub struct ActiveTunnel {
    pub endpoints: [u32; 2],
    pub(super) path: Option<super::super::path::Active>,
    pub(super) previous: Option<Box<super::super::path::Active>>,
    pub(super) bandwidth: Option<Box<Allocated>>,
    pub(super) pending: [Option<Arc<dyn super::super::path::Reservation>>; 2],
}
impl ActiveTunnel {
    pub(super) fn bandwidth_ref(&self) -> &Allocated {
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
    pub(super) fn take_bandwidth(&mut self) -> Box<Allocated> {
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
    pub(super) fn put_bandwidth(&mut self, bandwidth: Box<Allocated>) {
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
    /// already have independently kept native CM ownership. A PE readback,
    /// local pending drain or CMR clearance cannot establish this proof.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::usb3::ActiveTunnel;
    /// fn release(t:ActiveTunnel){t.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        if let Some(path) = self.path.take() {
            // SAFETY: covered by this function's own safety contract.
            unsafe { path.retire() };
        }
        if let Some(path) = self.previous.take() {
            // SAFETY: covered by this function's own safety contract.
            unsafe { path.retire() };
        }
        if let Some(bandwidth) = self.bandwidth.take() {
            // SAFETY: covered by this function's own safety contract.
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
            super::super::path::retain_reservation(reservation);
        }
    }
}
pub enum TunnelEvent {
    Active(Box<ActiveTunnel>),
    Discarded(config::Error),
}
#[derive(Clone, Copy)]
pub(super) struct Endpoint {
    pub(super) route: Route,
    pub(super) port: u8,
    pub(super) upstream: u8,
    pub(super) cap: u16,
    pub(super) header: [u32; 8],
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TunnelStage {
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
/// Reuses the real Channel/path cores; no duplicate allocator or permission.
pub struct ActivateTunnel<R: Registers> {
    pub(super) channel: Option<Channel<R>>,
    pub(super) path: Option<super::super::path::Activate<R>>,
    pub(super) retained: Option<Box<ActiveTunnel>>,
    pub(super) first_slot: Option<Box<core::mem::MaybeUninit<super::super::path::Active>>>,
    pub(super) prepared: [Option<super::super::path::Prepared>; 2],
    pub(super) endpoints: [Endpoint; 2],
    pub(super) stage: TunnelStage,
    pub(super) expected: Option<u64>,
    pub(super) deadline: u64,
    pub(super) job_deadline: u64,
    pub(super) last_now: u64,
}
impl<R: Registers> ActivateTunnel<R> {
    /// # Safety
    /// The bandwidth receipt, BOTH path allocations and idle Channel are
    /// one live NHI/reset/topology/permission generation. Real native
    /// accounting/_OSC/security/mapping/power/attachment lifetimes hold. In
    /// addition, bandwidth's Reservation keeps exclusive CS0 endpoint
    /// control for BOTH adapters through final retirement or quarantine; neither
    /// path IDs nor matching numeric grants imply that permission. No firmware or
    /// other CM can enable/reuse the endpoints or paths. Pre-existing traffic is
    /// independently serialized and every prior ID is owned.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,path::Reservation,usb3::{Allocated,ActivateTunnel},ring::Registers};
    /// fn pair<R:Registers>(c:Channel<R>,a:Box<Allocated>,d:Arc<dyn Reservation>,u:Arc<dyn Reservation>){let _=ActivateTunnel::new(c,a,d,u,0);}
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        bandwidth: Box<Allocated>,
        down: Arc<dyn super::super::path::Reservation>,
        up: Arc<dyn super::super::path::Reservation>,
        now: u64,
    ) -> Result<Self, Error> {
        // SAFETY: covered by this function's own safety contract.
        unsafe { Self::new_inner(channel, bandwidth, down, up, now, alloc) }
    }
    #[cfg(test)]
    pub(super) unsafe fn new_without_storage(
        channel: Channel<R>,
        bandwidth: Box<Allocated>,
        down: Arc<dyn super::super::path::Reservation>,
        up: Arc<dyn super::super::path::Reservation>,
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
                // SAFETY: the caller passes a nonzero-size layout, as `alloc` requires.
                unsafe { alloc(layout) }
            }
        }
        // SAFETY: `refuse_receipt` follows `alloc`'s contract, and the caller upholds this
        // constructor's, which is `new_inner`'s.
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
    pub(super) unsafe fn new_inner(
        channel: Channel<R>,
        bandwidth: Box<Allocated>,
        down: Arc<dyn super::super::path::Reservation>,
        up: Arc<dyn super::super::path::Reservation>,
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
                            super::super::path::Direction::Downstream
                        } else {
                            super::super::path::Direction::Upstream
                        }
                {
                    return Err(Error::Identity);
                }
            }
            let prepared = [
                super::super::path::prepare(link, allocations[0]).map_err(Error::Path)?,
                super::super::path::prepare(link, allocations[1]).map_err(Error::Path)?,
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
            let first = unsafe { allocate(Layout::new::<super::super::path::Active>()) }
                .cast::<core::mem::MaybeUninit<super::super::path::Active>>();
            if first.is_null() {
                return Err(Error::Allocation);
            }
            // SAFETY: uninitialized bytes are valid MaybeUninit; matching layout.
            let first = unsafe { Box::from_raw(first) };
            // SAFETY: covered by this function's own safety contract.
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
                super::super::path::retain_reservation(&down);
                super::super::path::retain_reservation(&up);
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
    pub(super) fn is_current(&self) -> bool {
        if let Some(path) = &self.path {
            path.is_current()
        } else {
            self.retained
                .as_ref()
                .is_some_and(|tunnel| tunnel.bandwidth_ref().is_current())
        }
    }
    pub(super) fn retained(&mut self) -> &mut ActiveTunnel {
        self.retained.as_mut().expect("retained tunnel transaction")
    }
    pub(super) fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
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
    pub(super) fn enter(&mut self, stage: TunnelStage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.deadline = crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        Ok(())
    }
    pub(super) fn start_path(&mut self, index: usize, now: u64) -> Result<(), Error> {
        let deadline = crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        let job = crate::bus::thunderbolt::stage_deadline(now, 10_000, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
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
            // SAFETY: constructor checked both protected plans/epochs/permission;
            // clocks were checked while all owners and Channel remained kept.
            unsafe {
                super::super::path::Activate::start_bandwidth(
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
            // SAFETY: first success remains in the preallocated wrapper;
            // opposite protected plan shares native grant and endpoint lease.
            unsafe {
                super::super::path::Activate::start_previous(
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
    pub(super) fn request(&self) -> Result<(Endpoint, Address, Option<[u32; 1]>), Error> {
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
    pub(super) fn submit(&mut self, now: u64) -> Result<(), Error> {
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
    pub(super) fn complete(
        &mut self,
        reply: Reply,
        now: u64,
    ) -> Result<Option<TunnelEvent>, Error> {
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
                Ok(Some(super::super::path::Event::Discarded(error))) => {
                    return Ok(Some(TunnelEvent::Discarded(error)));
                }
                Ok(Some(super::super::path::Event::Active(active))) => {
                    let path = self.path.take().expect("completed actual path engine");
                    self.channel = Some(path.into_channel());
                    if self.stage == TunnelStage::First {
                        let mut first = self
                            .first_slot
                            .take()
                            .expect("preallocated first-path wrapper");
                        first.as_mut().write(active);
                        // SAFETY: initialized exactly once with first success.
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
