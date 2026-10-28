// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019 Intel Corporation
//! Tearing down a Thunderbolt DisplayPort tunnel: stopping its paths and releasing its adapters.
use super::*;
use crate::bus::thunderbolt::{
    channel,
    config::{self, Address, Reply, Space},
    ring,
};

pub struct Stopped {
    pub endpoints: [[u32; 2]; 2],
    pub hops: [path::Words; 6],
    pub nfc: u32,
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
        // SAFETY: same-epoch source-order HPD/endpoint disables and all six
        // owned hop EN0/PENDING0 receipts hold, with acknowledged video NFC
        // return after video drain and before the AUX direction drains.
        // Only original local rights return; independent GPU/DMA/IRQ stays held.
        let link = unsafe {
            self.active
                .path
                .take()
                .expect("actual stopped paths")
                .release_dp_stopped()
        };
        let reservation = self.active.owner.take().expect("actual native reservation");
        Ok(Reusable { link, reservation })
    }
}
pub enum StopEvent {
    Stopped(Stopped),
    Discarded(config::Error),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Header(usize),
    HpdRead,
    HpdWrite(u32),
    EndpointRead(usize),
    EndpointWrite(usize, [u32; 2]),
    EndpointVerify(usize),
    ReadHop(usize),
    DisableHop(usize, path::Words),
    Drain(usize),
    VerifyHop(usize),
    NfcRead,
    NfcWrite(u32),
    NfcVerify(u32),
    Done,
    Fault,
}
pub struct Stop<R: Registers> {
    channel: Option<Channel<R>>,
    active: Option<Box<Active>>,
    endpoints: [Endpoint; 2],
    hops: [path::DrainHop; 6],
    endpoints_after: [[u32; 2]; 2],
    hops_after: [path::Words; 6],
    nfc_after: u32,
    stage: Stage,
    expected: Option<u64>,
    deadline: u64,
    job_deadline: u64,
    last_now: u64,
}
impl<R: Registers> Stop<R> {
    /// # Safety
    /// Idle Channel and complete DP tunnel are one exact retained native epoch.
    /// GPU/host display submissions are closed. Actual independent GPU/connector,
    /// endpoint payload, DMA/IRQ/IOMMU and power lifetimes remain retained.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,displayport::{Active,Stop},ring::Registers};
    /// fn stop<R:Registers>(c:Channel<R>,a:Box<Active>){let _=Stop::new(c,a,0);}
    /// ```
    pub unsafe fn new(channel: Channel<R>, active: Box<Active>, now: u64) -> Result<Self, Error> {
        if !active.current() {
            return Err(Error::Revoked);
        }
        let au = active.path.as_ref().ok_or(Error::UnexpectedReceipt)?;
        let ad = au.previous();
        let video = ad.previous();
        let [v0, v1] = video.drain_hops().map_err(Error::Path)?;
        let [a0, a1] = ad.drain_hops().map_err(Error::Path)?;
        let [b0, b1] = au.drain_hops().map_err(Error::Path)?;
        let (parent, child) = au.linked().retained_routers().map_err(Error::Link)?;
        let endpoints = [
            endpoint(
                parent.retained_owner().target(),
                active.grant.dp_in,
                AdapterKind::DisplayIn,
            )?,
            endpoint(
                child.retained_owner().target(),
                active.grant.dp_out,
                AdapterKind::DisplayOut,
            )?,
        ];
        let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
        let job_deadline = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
        Ok(Self {
            channel: Some(channel),
            active: Some(active),
            endpoints,
            hops: [v0, v1, a0, a1, b0, b1],
            endpoints_after: [[0; 2]; 2],
            hops_after: [path::Words { raw: [0; 2] }; 6],
            nfc_after: 0,
            stage: Stage::Header(0),
            expected: None,
            deadline,
            job_deadline,
            last_now: now,
        })
    }
    fn fail<T>(&mut self, e: Error) -> Result<T, Error> {
        self.stage = Stage::Fault;
        let _ = self.channel.as_mut().expect("actual channel").cancel();
        Err(e)
    }
    pub fn cancel(&mut self) -> Result<(), Error> {
        match self.stage {
            Stage::Done => Err(Error::Stopped),
            Stage::Fault => Err(Error::Poisoned),
            _ => self.fail(Error::Cancelled),
        }
    }
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("actual channel")
    }
    fn enter(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.deadline = crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        Ok(())
    }
    fn request(
        &self,
    ) -> (
        crate::bus::thunderbolt::config::Route,
        u8,
        Address,
        Option<[u32; 2]>,
    ) {
        match self.stage {
            Stage::Header(i)
            | Stage::EndpointRead(i)
            | Stage::EndpointWrite(i, _)
            | Stage::EndpointVerify(i) => {
                let e = self.endpoints[i];
                let header = matches!(self.stage, Stage::Header(_));
                (
                    e.route,
                    e.upstream,
                    Address {
                        port: e.port,
                        space: Space::Port,
                        offset: if header { 0 } else { e.cap },
                        words: if header { 8 } else { 2 },
                    },
                    if let Stage::EndpointWrite(_, w) = self.stage {
                        Some(w)
                    } else {
                        None
                    },
                )
            }
            Stage::HpdRead | Stage::HpdWrite(_) => {
                let e = self.endpoints[0];
                (
                    e.route,
                    e.upstream,
                    Address {
                        port: e.port,
                        space: Space::Port,
                        offset: e.cap + 3,
                        words: 1,
                    },
                    if let Stage::HpdWrite(w) = self.stage {
                        Some([w, 0])
                    } else {
                        None
                    },
                )
            }
            Stage::NfcRead | Stage::NfcWrite(_) | Stage::NfcVerify(_) => {
                let h = self.hops[1];
                (
                    h.route,
                    h.upstream,
                    Address {
                        port: h.port,
                        space: Space::Port,
                        offset: 4,
                        words: 1,
                    },
                    if let Stage::NfcWrite(w) = self.stage {
                        Some([w, 0])
                    } else {
                        None
                    },
                )
            }
            Stage::ReadHop(i) | Stage::DisableHop(i, _) | Stage::Drain(i) | Stage::VerifyHop(i) => {
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
                    if let Stage::DisableHop(_, w) = self.stage {
                        Some(w.raw)
                    } else {
                        None
                    },
                )
            }
            _ => unreachable!("actual active stop stage"),
        }
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<StopEvent>, Error> {
        let data = checked_reply(reply, self.request().1)?;
        match self.stage {
            Stage::Header(i) => {
                if !self.endpoints[i].matches(&data) {
                    return Err(Error::Changed);
                }
                self.enter(
                    if i == 0 {
                        Stage::Header(1)
                    } else {
                        Stage::HpdRead
                    },
                    now,
                )?;
            }
            Stage::HpdRead => {
                let [w] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                self.enter(Stage::HpdWrite(*w | (1 << 9)), now)?;
            }
            Stage::HpdWrite(_) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(Stage::EndpointRead(0), now)?;
            }
            Stage::EndpointRead(i) => {
                let raw: [u32; 2] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::UnexpectedReceipt)?;
                self.enter(Stage::EndpointWrite(i, [raw[0] & !ENABLE, raw[1]]), now)?;
            }
            Stage::EndpointWrite(i, _) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(Stage::EndpointVerify(i), now)?;
            }
            Stage::EndpointVerify(i) => {
                let raw: [u32; 2] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::UnexpectedReceipt)?;
                if raw[0] & ENABLE != 0 {
                    return Err(Error::Readback);
                }
                self.endpoints_after[i] = raw;
                self.enter(
                    if i == 0 {
                        Stage::EndpointRead(1)
                    } else {
                        Stage::ReadHop(0)
                    },
                    now,
                )?;
            }
            Stage::DisableHop(i, _) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(Stage::Drain(i), now)?;
            }
            Stage::ReadHop(i) | Stage::Drain(i) | Stage::VerifyHop(i) => {
                let raw: [u32; 2] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::UnexpectedReceipt)?;
                let words = path::Words { raw };
                if !self.hops[i].matches(words) {
                    return Err(Error::Changed);
                }
                match self.stage {
                    Stage::ReadHop(i) => self.enter(
                        if raw[0] & (1 << 31) != 0 {
                            Stage::DisableHop(
                                i,
                                path::Words {
                                    raw: [raw[0] & !(1 << 31), raw[1]],
                                },
                            )
                        } else if raw[1] & PENDING != 0 {
                            Stage::Drain(i)
                        } else {
                            Stage::VerifyHop(i)
                        },
                        now,
                    )?,
                    Stage::Drain(i) | Stage::VerifyHop(i) => {
                        if raw[0] & (1 << 31) != 0 {
                            return Err(Error::Readback);
                        }
                        if raw[1] & PENDING != 0 {
                            self.stage = Stage::Drain(i);
                        } else if matches!(self.stage, Stage::Drain(_)) {
                            self.stage = Stage::VerifyHop(i);
                        } else {
                            self.hops_after[i] = words;
                            // Source tb_path_deactivate returns video NFC before
                            // advancing to either still-retained AUX direction.
                            if i == 1 {
                                self.enter(Stage::NfcRead, now)?;
                            } else if i < 5 {
                                self.enter(Stage::ReadHop(i + 1), now)?;
                            } else {
                                self.stage = Stage::Done;
                                return Ok(Some(StopEvent::Stopped(Stopped {
                                    endpoints: self.endpoints_after,
                                    hops: self.hops_after,
                                    nfc: self.nfc_after,
                                    active: self.active.take().ok_or(Error::UnexpectedReceipt)?,
                                })));
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
            Stage::NfcRead => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                let amount = u32::from(self.active.as_ref().unwrap().video_nfc);
                let current = word & 1023;
                if current < amount {
                    return Err(Error::Changed);
                }
                self.enter(Stage::NfcWrite((word & !1023) | (current - amount)), now)?;
            }
            Stage::NfcWrite(w) => {
                if !data.is_empty() {
                    return Err(Error::UnexpectedReceipt);
                }
                self.enter(Stage::NfcVerify(w), now)?;
            }
            Stage::NfcVerify(expected) => {
                let [actual] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                if actual & 1023 != expected & 1023 {
                    return Err(Error::Readback);
                }
                self.nfc_after = *actual;
                self.enter(Stage::ReadHop(2), now)?;
            }
            _ => return Err(Error::UnexpectedReceipt),
        }
        Ok(None)
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<StopEvent>, Error> {
        match self.stage {
            Stage::Done => return Err(Error::Stopped),
            Stage::Fault => return Err(Error::Poisoned),
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
            let channel = self.channel.as_mut().unwrap();
            let result = if let Some(data) = data {
                channel.write(
                    route,
                    address,
                    &data[..usize::from(address.words)],
                    now,
                    self.deadline,
                )
            } else {
                channel.read(route, address, now, self.deadline)
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
