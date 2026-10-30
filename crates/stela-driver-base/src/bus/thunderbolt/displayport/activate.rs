// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019 Intel Corporation
//! Bringing up the paths and adapters of a Thunderbolt DisplayPort tunnel.
use super::*;
use crate::bus::thunderbolt::{
    channel,
    config::{self, Address, Reply, Space},
    ring,
};

pub enum Event {
    Active(Box<Active>),
    Discarded(config::Error),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Header(usize),
    Disabled(usize),
    ProbeMode,
    HandshakeRead,
    HandshakeWrite(u32),
    HandshakeWait,
    Local(usize),
    RemoteWrite(usize, u32),
    RemoteVerify(usize, u32),
    Path(usize),
    EnableRead(usize),
    EnableWrite(usize, [u32; 2]),
    EnableVerify(usize),
    Dprx,
    Done,
    Fault,
}
pub struct Activate<R: Registers> {
    channel: Option<Channel<R>>,
    path: Option<path::Activate<R>>,
    retained: Option<Box<Active>>,
    slots: [Option<Box<MaybeUninit<path::Active>>>; 2],
    prepared: [Option<path::Prepared>; 3],
    endpoints: [Endpoint; 2],
    titan_out: bool,
    stage: Stage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    wait_deadline: u64,
    next_poll: u64,
    last_now: u64,
}
impl<R: Registers> Activate<R> {
    /// # Safety
    /// Idle Channel, Linked and native Reservation identify one exact
    /// requester/reset/topology lifetime. Reservation's real display association,
    /// shared allocator/bandwidth/permission and independent payload proofs hold.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,link::Linked,displayport::{Activate,Reservation},ring::Registers};
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
        if grant.permission != Decision::Allowed || grant.max_mbps > i32::MAX as u32 {
            return Err(Error::Permission);
        }
        let (parent, child) = link.retained_routers().map_err(Error::Link)?;
        if parent.header.usb4_version() != 1 || child.header.usb4_version() != 1 {
            return Err(Error::Unsupported);
        }
        if grant.hops[0][0].1 == grant.hops[1][0].1 {
            return Err(Error::Identity);
        }
        let endpoints = [
            endpoint(
                parent.retained_owner().target(),
                grant.dp_in,
                AdapterKind::DisplayIn,
            )?,
            endpoint(
                child.retained_owner().target(),
                grant.dp_out,
                AdapterKind::DisplayOut,
            )?,
        ];
        if endpoints.iter().any(|e| e.cap > 8192 - 8) {
            return Err(Error::Capability);
        }
        let titan_out = titan(&child.header);
        let nfc = video_nfc(&link, grant.credits)?;
        let allocations = core::array::from_fn::<_, 3, _>(|i| allocation(grant, i));
        let prepared = [
            path::prepare_dp(&link, allocations[0], Some(nfc)).map_err(Error::Path)?,
            path::prepare_dp(&link, allocations[1], None).map_err(Error::Path)?,
            path::prepare_dp(&link, allocations[2], None).map_err(Error::Path)?,
        ];
        now.checked_add(JOB_MS + DPRX_MS + 3000)
            .ok_or(Error::ClockOverflow)?;
        let slots = [
            Some(storage::<path::Active>()?),
            Some(storage::<path::Active>()?),
        ];
        let mut result = storage::<Active>()?;
        let pending = core::array::from_fn(|i| {
            Some(Arc::new(PathOwner {
                owner: owner.clone(),
                grant,
                allocation: allocations[i],
            }) as Arc<dyn path::Reservation>)
        });
        result.write(Active {
            endpoints: [[0; 2]; 2],
            local_caps: [0; 2],
            remote_caps: [0; 2],
            dprx: 0,
            grant,
            video_nfc: nfc,
            owner: Some(owner),
            path: None,
            previous: None,
            link: Some(link),
            pending,
        });
        // SAFETY: exact-layout unique storage was fully initialized above.
        let retained = unsafe { result.assume_init() };
        let [a, b, c] = prepared;
        Ok(Self {
            channel: Some(channel),
            path: None,
            retained: Some(retained),
            slots,
            prepared: [Some(a), Some(b), Some(c)],
            endpoints,
            titan_out,
            stage: Stage::Header(0),
            expected: None,
            deadline: now + REQUEST_MS,
            job_deadline: now + JOB_MS,
            wait_deadline: 0,
            next_poll: now,
            last_now: now,
        })
    }
    fn current(&self) -> bool {
        self.retained.as_ref().is_some_and(|a| a.current())
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = Stage::Fault;
        if let Some(p) = &mut self.path {
            let _ = p.cancel();
        }
        if let Some(c) = &mut self.channel {
            let _ = c.cancel();
        }
        Err(error)
    }
    pub fn cancel(&mut self) -> Result<(), Error> {
        match self.stage {
            Stage::Done => Err(Error::Stopped),
            Stage::Fault => Err(Error::Poisoned),
            _ => self.fail(Error::Cancelled),
        }
    }
    pub fn into_channel(mut self) -> Channel<R> {
        if let Some(p) = self.path.take() {
            p.into_channel()
        } else {
            self.channel.take().expect("actual channel")
        }
    }
    fn enter(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.next_poll = now;
        self.deadline = crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        Ok(())
    }
    fn start_path(&mut self, index: usize, now: u64) -> Result<(), Error> {
        let deadline = crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        let job = crate::bus::thunderbolt::stage_deadline(now, 10_000, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        let channel = self.channel.take().ok_or(Error::UnexpectedReceipt)?;
        let prepared = self.prepared[index]
            .take()
            .ok_or(Error::UnexpectedReceipt)?;
        let active = self.retained.as_mut().ok_or(Error::UnexpectedReceipt)?;
        let owner = active.pending[index]
            .take()
            .ok_or(Error::UnexpectedReceipt)?;
        // SAFETY: current native grant, protected preflight plan and original
        // link/path chain; all clock/storage bounds precede mutation.
        self.path = Some(unsafe {
            if index == 0 {
                path::Activate::start_pcie(
                    channel,
                    active.link.take().ok_or(Error::UnexpectedReceipt)?,
                    owner,
                    prepared,
                    now,
                    deadline,
                    job,
                )
            } else {
                path::Activate::start_previous(
                    channel,
                    active.previous.take().ok_or(Error::UnexpectedReceipt)?,
                    owner,
                    prepared,
                    now,
                    deadline,
                    job,
                )
            }
        });
        self.stage = Stage::Path(index);
        Ok(())
    }
    fn request(&self) -> Result<(Endpoint, Address, Option<[u32; 2]>), Error> {
        let (i, offset, count, data) = match self.stage {
            Stage::Header(i) => (i, 0, 8, None),
            Stage::Disabled(i) | Stage::EnableRead(i) | Stage::EnableVerify(i) => (i, 0, 2, None),
            Stage::ProbeMode => (0, 4, 1, None),
            Stage::HandshakeRead | Stage::HandshakeWait => (1, 6, 1, None),
            Stage::HandshakeWrite(w) => (1, 6, 1, Some([w, 0])),
            Stage::Local(i) => (i, 4, 1, None),
            Stage::RemoteWrite(i, w) => (i, 5, 1, Some([w, 0])),
            Stage::RemoteVerify(i, _) => (i, 5, 1, None),
            Stage::EnableWrite(i, w) => (i, 0, 2, Some(w)),
            Stage::Dprx => (0, 7, 1, None),
            _ => return Err(Error::UnexpectedReceipt),
        };
        let e = self.endpoints[i];
        Ok((
            e,
            Address {
                port: e.port,
                space: Space::Port,
                offset: if matches!(self.stage, Stage::Header(_)) {
                    0
                } else {
                    e.cap + offset
                },
                words: count,
            },
            data,
        ))
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
        let data = checked_reply(reply, self.request()?.0.upstream)?;
        match self.stage {
            Stage::Header(i) => {
                if !self.endpoints[i].matches(&data) {
                    return Err(Error::Changed);
                }
                self.enter(
                    if i == 0 {
                        Stage::Header(1)
                    } else {
                        Stage::Disabled(0)
                    },
                    now,
                )?;
            }
            Stage::Disabled(i) => {
                let [word, _] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                if word & ENABLE != 0 {
                    return Err(Error::Busy);
                }
                self.enter(
                    if i == 0 {
                        Stage::Disabled(1)
                    } else {
                        Stage::ProbeMode
                    },
                    now,
                )?;
            }
            Stage::ProbeMode => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                if word & BW_MODE != 0 {
                    return Err(Error::Unsupported);
                }
                rate(*word)?;
                lanes(*word)?;
                self.wait_deadline =
                    crate::bus::thunderbolt::stage_deadline(now, HANDSHAKE_MS, self.job_deadline)
                        .ok_or(Error::ClockOverflow)?;
                self.enter(Stage::HandshakeRead, now)?;
            }
            Stage::HandshakeRead => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                self.enter(Stage::HandshakeWrite(*word | CMHS | UF), now)?;
            }
            Stage::HandshakeWrite(_) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(Stage::HandshakeWait, now)?;
            }
            Stage::HandshakeWait => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                self.enter(
                    if word & CMHS == 0 {
                        Stage::Local(0)
                    } else {
                        Stage::HandshakeWait
                    },
                    now,
                )?;
            }
            Stage::Local(i) => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                rate(*word)?;
                lanes(*word)?;
                if i == 0 && word & BW_MODE != 0 {
                    return Err(Error::Unsupported);
                }
                self.retained.as_mut().expect("actual tunnel").local_caps[i] = *word;
                if i == 0 {
                    self.enter(Stage::Local(1), now)?;
                } else {
                    let input = self.retained.as_ref().unwrap().local_caps[0];
                    self.enter(Stage::RemoteWrite(1, input), now)?;
                }
            }
            Stage::RemoteWrite(i, w) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(Stage::RemoteVerify(i, w), now)?;
            }
            Stage::RemoteVerify(i, expected) => {
                let [actual] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                if *actual != expected {
                    return Err(Error::Readback);
                }
                let active = self.retained.as_mut().unwrap();
                active.remote_caps[i] = *actual;
                if i == 1 {
                    let mut cap = limited_cap(
                        active.local_caps[0],
                        active.local_caps[1],
                        active.grant.max_mbps,
                    )?;
                    if self.titan_out {
                        cap |= 1 << 27;
                    }
                    self.enter(Stage::RemoteWrite(0, cap), now)?;
                } else {
                    self.start_path(0, now)?;
                }
            }
            Stage::EnableRead(i) => {
                let raw: [u32; 2] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::UnexpectedReceipt)?;
                if raw[0] & ENABLE != 0 {
                    return Err(Error::Busy);
                }
                self.enter(Stage::EnableWrite(i, [raw[0] | ENABLE, raw[1]]), now)?;
            }
            Stage::EnableWrite(i, _) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(Stage::EnableVerify(i), now)?;
            }
            Stage::EnableVerify(i) => {
                let raw: [u32; 2] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::UnexpectedReceipt)?;
                if raw[0] & ENABLE != ENABLE {
                    return Err(Error::Readback);
                }
                self.retained.as_mut().unwrap().endpoints[i] = raw;
                if i == 0 {
                    self.enter(Stage::EnableRead(1), now)?;
                } else {
                    self.wait_deadline =
                        crate::bus::thunderbolt::stage_deadline(now, DPRX_MS, self.job_deadline)
                            .ok_or(Error::ClockOverflow)?;
                    self.enter(Stage::Dprx, now)?;
                }
            }
            Stage::Dprx => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                if word & (1 << 31) != 0 {
                    self.retained.as_mut().unwrap().dprx = *word;
                    self.stage = Stage::Done;
                    return Ok(Some(Event::Active(
                        self.retained.take().ok_or(Error::UnexpectedReceipt)?,
                    )));
                }
                self.enter(Stage::Dprx, now)?;
                self.next_poll = now.checked_add(50).ok_or(Error::ClockOverflow)?;
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
        if matches!(
            self.stage,
            Stage::HandshakeRead | Stage::HandshakeWrite(_) | Stage::HandshakeWait | Stage::Dprx
        ) && now >= self.wait_deadline
        {
            return self.fail(Error::Timeout);
        }
        if let Stage::Path(i) = self.stage {
            match self.path.as_mut().unwrap().poll(now) {
                Err(e) => return self.fail(Error::Path(e)),
                Ok(Some(path::Event::Discarded(e))) => return Ok(Some(Event::Discarded(e))),
                Ok(Some(path::Event::Active(path))) => {
                    self.channel = Some(self.path.take().unwrap().into_channel());
                    if i < 2 {
                        let mut slot = self.slots[i].take().ok_or(Error::UnexpectedReceipt)?;
                        slot.write(path);
                        // SAFETY: exact-layout preallocated slot now contains the
                        // completed path and its unique prior owner chain.
                        let previous = unsafe { slot.assume_init() };
                        self.retained.as_mut().unwrap().previous = Some(previous);
                        if let Err(e) = self.start_path(i + 1, now) {
                            return self.fail(e);
                        }
                    } else {
                        self.retained.as_mut().unwrap().path = Some(path);
                        if let Err(e) = self.enter(Stage::EnableRead(0), now) {
                            return self.fail(e);
                        }
                    }
                }
                Ok(None) => return Ok(None),
            }
        } else {
            if now >= self.deadline {
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
                Ok(Some(channel::Event::Notification(e))) => {
                    return self.fail(Error::Notification(e));
                }
                Ok(Some(channel::Event::Discarded(e))) => return Ok(Some(Event::Discarded(e))),
                Ok(None) => {}
            }
        }
        if let Some(p) = &mut self.path {
            return match p.poll(now) {
                Ok(None) => Ok(None),
                Ok(Some(path::Event::Discarded(e))) => Ok(Some(Event::Discarded(e))),
                Ok(Some(path::Event::Active(_))) => self.fail(Error::UnexpectedReceipt),
                Err(e) => self.fail(Error::Path(e)),
            };
        }
        if self.expected.is_none() && now >= self.next_poll {
            let (e, address, data) = match self.request() {
                Ok(r) => r,
                Err(e) => return self.fail(e),
            };
            let deadline = self.deadline.min(
                if matches!(
                    self.stage,
                    Stage::HandshakeRead
                        | Stage::HandshakeWrite(_)
                        | Stage::HandshakeWait
                        | Stage::Dprx
                ) {
                    self.wait_deadline
                } else {
                    self.job_deadline
                },
            );
            let result = if let Some(data) = data {
                self.channel.as_mut().unwrap().write(
                    e.route,
                    address,
                    &data[..usize::from(address.words)],
                    now,
                    deadline,
                )
            } else {
                self.channel
                    .as_mut()
                    .unwrap()
                    .read(e.route, address, now, deadline)
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
