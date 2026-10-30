// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Stopping an active tunnel and releasing the bandwidth it no longer uses.

use super::*;

/// Separate source release-unused operation on an active tunnel.
/// Paths/endpoints stay active; max(consumed,900Mb/s) remains allocated.
pub struct ReleaseUnused<R: Registers> {
    pub(super) core: Option<Allocate<R>>,
    pub(super) tunnel: Option<Box<ActiveTunnel>>,
    pub(super) done: bool,
    pub(super) fault: bool,
}
impl<R: Registers> ReleaseUnused<R> {
    /// # Safety
    /// Same live physical Channel/tunnel and kept native guard. Real
    /// global accounting serializes this adjustment and keeps consumed rights,
    /// the 900Mb/s floor, all path/endpoint permission and independent lifetimes.
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
/// Residual root bandwidth/accounting/permission and original link are held.
/// This does not release native endpoint posted DMA/IRQ/IOMMU or redistribute a
/// branch's bandwidth. The real provider must independently retire those rights.
pub struct Reusable {
    pub residual: Box<Allocated>,
    /// Down then Up allocations; these objects, not their numeric IDs,
    /// are the native allocator/credit/permission lifetime being returned.
    pub paths: [Arc<dyn super::super::path::Reservation>; 2],
}
/// Local stopped observations. Drop quarantines the complete chain;
/// reusable rights are returned only by explicitly consuming this receipt.
pub struct Stopped {
    pub endpoints: [u32; 2],
    pub hops: [super::super::path::Words; 4],
    pub(super) active: Option<Box<ActiveTunnel>>,
    pub(super) epoch: Grant,
}
impl Stopped {
    pub fn bandwidth_rates(&self) -> Rates {
        self.active
            .as_ref()
            .expect("retained residual")
            .bandwidth_rates()
    }
    /// Return local reservations only after the live native guard is
    /// revalidated. Revocation keeps this exact receipt/owner chain recoverable.
    /// A true snapshot is backed by Reservation's exclusive in-flight
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
pub(super) enum StopStage {
    Header(usize),
    DisableEndpoint(usize),
    VerifyEndpoint(usize),
    ReadHop(usize),
    DisableHop(usize, super::super::path::Words),
    Drain(usize),
    VerifyHop(usize),
    Done,
    Fault,
}
pub(super) struct StopRequest {
    pub(super) route: Route,
    pub(super) upstream: u8,
    pub(super) address: Address,
    pub(super) data: Option<[u32; 2]>,
}
/// Exact normal USB3 deactivate: Down/Up endpoints, Down/Up paths, forward hops.
/// Does NOT call release-unused or manufacture a zero-bandwidth/global release.
pub struct StopTunnel<R: Registers> {
    pub(super) channel: Option<Channel<R>>,
    pub(super) active: Option<Box<ActiveTunnel>>,
    pub(super) result: Option<Box<Stopped>>,
    pub(super) epoch: Grant,
    pub(super) endpoints: [Endpoint; 2],
    pub(super) hops: [super::super::path::DrainHop; 4],
    pub(super) stage: StopStage,
    pub(super) expected: Option<u64>,
    pub(super) deadline: u64,
    pub(super) job_deadline: u64,
    pub(super) last_now: u64,
    pub(super) next_poll: u64,
}
impl<R: Registers> StopTunnel<R> {
    /// # Safety
    /// Channel, complete tunnel and native reset/topology/permission guard
    /// identify the same physical lifetime, exclusively idle and serialized.
    /// Native host submission admission is closed and all independent endpoint
    /// posted-DMA/IRQ/IOMMU/power resources stay held. The local path drain
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
        // SAFETY: covered by this function's own safety contract.
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
        // SAFETY: `refuse` follows `alloc`'s contract, and the caller upholds this constructor's,
        // which is `new_inner`'s.
        unsafe { Self::new_inner(channel, active, now, refuse) }
    }
    pub(super) unsafe fn new_inner(
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
                        super::super::path::Direction::Downstream
                    } else {
                        super::super::path::Direction::Upstream
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
        // SAFETY: `Stopped` is not zero-sized.
        let ptr = unsafe { allocate(Layout::new::<Stopped>()) }.cast::<Stopped>();
        if ptr.is_null() {
            return Err(Error::Allocation);
        }
        // SAFETY: covered by this function's own safety contract.
        let result = unsafe {
            ptr.write(Stopped {
                endpoints: [0; 2],
                hops: [super::super::path::Words { raw: [0; 2] }; 4],
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
    pub(super) fn is_current(&self) -> bool {
        self.active.as_ref().is_some_and(|t| {
            let b = t.bandwidth_ref();
            b.is_current() && b.protected_grant() == self.epoch
        })
    }
    pub(super) fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
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
    pub(super) fn enter(&mut self, stage: StopStage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.next_poll = now;
        self.deadline = crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        Ok(())
    }
    pub(super) fn request(&self) -> Result<StopRequest, Error> {
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
    pub(super) fn submit(&mut self, now: u64) -> Result<(), Error> {
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
    pub(super) fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<StopEvent>, Error> {
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
                let words = super::super::path::Words { raw };
                if !self.hops[i].matches(words) {
                    return self.fail(Error::Changed);
                }
                match self.stage {
                    StopStage::ReadHop(i) => {
                        if raw[0] & (1 << 31) != 0 {
                            self.enter(
                                StopStage::DisableHop(
                                    i,
                                    super::super::path::Words {
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
