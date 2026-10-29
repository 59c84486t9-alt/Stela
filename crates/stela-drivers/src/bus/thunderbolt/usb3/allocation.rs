// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Root USB3 bandwidth allocation: the request/acknowledge exchange with the
//! router.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
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
pub(super) enum BandwidthMode {
    Allocate,
    ReleaseUnused,
}
/// Source consumed/max/scale/CS2 sequence with CMR/HCA hardware effects.
pub struct Allocate<R: Registers> {
    pub(super) channel: Option<Channel<R>>,
    pub(super) retained: Option<Box<Allocated>>,
    pub(super) plan: Plan,
    pub(super) stage: Stage,
    pub(super) expected: Option<u64>,
    pub(super) deadline: u64,
    pub(super) job_deadline: u64,
    pub(super) last_now: u64,
    pub(super) next_poll: u64,
    pub(super) consumed_word: u32,
    pub(super) mode: BandwidthMode,
}
impl<R: Registers> Allocate<R> {
    /// # Safety
    /// All three objects identify the same live physical NHI/reset/topology/
    /// protected grant epoch. Link metadata is current, Channel exclusively idle,
    /// and Reservation's native accounting/permission/mapping/lifetime
    /// requirements hold; numbers alone cannot prove physical permission.
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
        // SAFETY: covered by this function's own safety contract.
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
        // SAFETY: `refuse` follows `alloc`'s contract, and the caller upholds this constructor's,
        // which is `new_inner`'s.
        unsafe { Self::new_inner(channel, link, reservation, now, refuse) }
    }
    pub(super) unsafe fn new_inner(
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
        // and accounting reservation stay in this same allocation on any
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
    pub(super) fn release_existing(
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
    pub(super) fn channel(&mut self) -> &mut Channel<R> {
        self.channel.as_mut().expect("retained channel")
    }
    pub(super) fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
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
    pub(super) fn enter(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.next_poll = now;
        self.deadline = crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        Ok(())
    }
    pub(super) fn acknowledge(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.enter(stage, now)?;
        self.deadline = crate::bus::thunderbolt::stage_deadline(now, ACK_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        Ok(())
    }
    pub(super) fn request(&self) -> Result<(Address, Option<[u32; 1]>), Error> {
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
    pub(super) fn submit(&mut self, now: u64) -> Result<(), Error> {
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
    pub(super) fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
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
