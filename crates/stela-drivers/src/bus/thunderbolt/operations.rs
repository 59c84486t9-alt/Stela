// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019 Intel Corporation
//! Actual USB4 router operations, independent of firmware ICM proxy commands.
//!
//! Linux usb4_native_switch_op and DP resource/DROM helpers supply the register
//! protocol. Native CM/router/D0 ownership and dependent resources remain real
//! caller obligations. An unsupported opcode never becomes an allocation grant.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    pcie::checked_reply,
    ring::{self, Registers},
    topology::{AdapterKind, AdapterObservation, Inventory, RouterHeader},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
const OV: u32 = 1 << 31;
const ONS: u32 = 1 << 30;
const REQUEST_MS: u64 = 500;
const JOB_MS: u64 = 5000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    QueryDp {
        port: u8,
    },
    AllocateDp {
        port: u8,
    },
    DeallocateDp {
        port: u8,
    },
    /// Aligned source DROM block, at most16 DWORDs within its13-bit DWORD address.
    DromRead {
        dword_address: u16,
        words: u8,
    },
}
impl Operation {
    fn parameters(self) -> Result<(u16, u32, u8), Error> {
        match self {
            Self::QueryDp { port } => Ok((0x10, u32::from(port), 0)),
            Self::AllocateDp { port } => Ok((0x11, u32::from(port), 0)),
            Self::DeallocateDp { port } => Ok((0x12, u32::from(port), 0)),
            Self::DromRead {
                dword_address,
                words,
            } => {
                if words == 0 || words > 16 || u32::from(dword_address) + u32::from(words) > 8192 {
                    return Err(Error::Range);
                }
                Ok((
                    0x24,
                    (u32::from(words) << 15) | (u32::from(dword_address) << 2),
                    words,
                ))
            }
        }
    }
}
/// Exclusive physical native CM reservation of the real router operation engine.
///
/// # Safety
/// Inventory and operation belong to the actual owned configured router and NHI
/// requester/reset/topology epoch. Original configured router, D0/link, platform
/// authority, mailbox serialization and all independent GPU/DMA/IRQ/IOMMU owners
/// remain retained, including after errors. Firmware ICM/proxy and competing CM
/// actors cannot access this operation engine. DP operations refer to an actual
/// GPU/connector-to-DP-IN association. Allocation owns shared accounting before
/// submission; deallocation additionally proves the exact prior real allocation
/// and stopped dependent tunnels. No port number or opcode supplies those rights.
/// is_current observes real admission and pins in-flight lifetime against reuse.
pub unsafe trait Owner: Send + Sync {
    fn inventory(&self) -> &Inventory;
    fn operation(&self) -> Operation;
    fn is_current(&self) -> bool;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Revoked,
    Inventory,
    Unsupported,
    Range,
    Busy,
    Changed,
    Readback,
    ClockOverflow,
    ClockRegressed,
    Timeout,
    UnexpectedReceipt,
    ResourceBusy,
    ResourceStatus(u8),
    OperationUnsupported(u16),
    Cancelled,
    Poisoned,
    Stopped,
    Allocation,
    Transport(super::pcie::Error),
    Channel(channel::Error),
    Hotplug(config::PlugEvent),
    Notification(config::NotificationError),
}
pub fn quarantined_reservations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}
fn retain(owner: &Arc<dyn Owner>) {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
    core::mem::forget(owner.clone());
}
/// Completed actual native router command, retaining original physical owners.
/// Query status0 means available. Only status0 can produce allocation completion;
/// DROM bytes are actual returned control-channel words, not interpreted identity.
pub struct Completed {
    pub operation: Operation,
    pub status: u8,
    pub metadata: u32,
    pub data: Vec<u32>,
    owner: Option<Arc<dyn Owner>>,
    closed_read: bool,
}
impl Completed {
    /// # Safety
    /// Actual containing native CM retains the original read owner throughout
    /// this transfer. Only a fully acknowledged read-only DROM job may use it.
    pub(super) unsafe fn take_read_data(mut self) -> Option<Vec<u32>> {
        let owner = self.owner.as_ref()?;
        if !self.closed_read
            || !owner.is_current()
            || !matches!(owner.operation(), Operation::DromRead { words, .. } if usize::from(words) == self.data.len())
        {
            return None;
        }
        self.owner.take();
        Some(core::mem::take(&mut self.data))
    }
    /// # Safety
    /// Original physical owners and any actual allocated DP resource are restored
    /// or independently retained by the real native CM. A DP deallocation command
    /// alone never certifies independent GPU/payload/DMA/IRQ/IOMMU retirement.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::operations::Completed;
    /// fn retire(c:Completed){c.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        self.owner.take();
    }
}
impl Drop for Completed {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            retain(owner);
        }
    }
}
pub enum Event {
    Completed(Completed),
    Discarded(config::Error),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Header,
    Idle,
    MetadataWrite,
    MetadataVerify,
    Command,
    Wait,
    Status,
    Metadata,
    Data,
    Done,
    Fault,
}
pub struct Control<R: Registers> {
    channel: Option<Channel<R>>,
    owner: Option<Arc<dyn Owner>>,
    route: Route,
    header: RouterHeader,
    upstream: u8,
    operation: Operation,
    opcode: u16,
    input_metadata: u32,
    metadata: u32,
    status: u8,
    words: u8,
    data: Vec<u32>,
    stage: Stage,
    expected: Option<u64>,
    published: bool,
    read_only: bool,
    closed_read: bool,
    last_now: u64,
    deadline: u64,
    wait_deadline: u64,
    job_deadline: u64,
}
impl<R: Registers> Control<R> {
    /// # Safety
    /// Idle Channel and actual Owner identify the same live physical controller,
    /// configured router/reset/topology lifetime. Every Owner obligation holds.
    pub unsafe fn new(channel: Channel<R>, owner: Arc<dyn Owner>, now: u64) -> Result<Self, Error> {
        let mut control = Self::prepare(owner, now, Vec::new(), true)?;
        control.channel = Some(channel);
        Ok(control)
    }
    fn prepare(
        owner: Arc<dyn Owner>,
        now: u64,
        mut data: Vec<u32>,
        allocate: bool,
    ) -> Result<Self, Error> {
        if !owner.is_current() {
            return Err(Error::Revoked);
        }
        let inventory = owner.inventory();
        super::domain::Domain::validate(inventory).map_err(|_| Error::Inventory)?;
        if inventory.header.usb4_version() != 1 {
            return Err(Error::Unsupported);
        }
        let operation = owner.operation();
        let (opcode, metadata, words) = operation.parameters()?;
        if let Operation::QueryDp { port }
        | Operation::AllocateDp { port }
        | Operation::DeallocateDp { port } = operation
            && !inventory.adapters.iter().any(|a| matches!(a, AdapterObservation::Present{port:n,header,..} if *n==port && header.kind()==AdapterKind::DisplayIn))
        {
            return Err(Error::Inventory);
        }
        data.clear();
        if data.capacity() < usize::from(words) {
            if !allocate {
                return Err(Error::Allocation);
            }
            data.try_reserve_exact(usize::from(words))
                .map_err(|_| Error::Allocation)?;
        }
        let deadline = now.checked_add(REQUEST_MS).ok_or(Error::ClockOverflow)?;
        let job_deadline = now.checked_add(JOB_MS).ok_or(Error::ClockOverflow)?;
        Ok(Self {
            channel: None,
            route: inventory.path.route(),
            header: inventory.header.clone(),
            upstream: inventory.upstream_port,
            owner: Some(owner),
            operation,
            opcode,
            input_metadata: metadata,
            metadata: 0,
            status: 0,
            words,
            data,
            stage: Stage::Header,
            expected: None,
            published: false,
            read_only: false,
            closed_read: false,
            last_now: now,
            deadline,
            wait_deadline: 0,
            job_deadline,
        })
    }
    /// # Safety
    /// All new() requirements hold. Original native CM retains this exact DROM
    /// owner across blocks. Only a final OV0/status/metadata/data acknowledged
    /// read-status error may reuse this still-running channel; no transport,
    /// timeout, ONS, malformed receipt or revocation can use this profile.
    pub(super) unsafe fn read_only(
        channel: &mut Option<Channel<R>>,
        owner: Arc<dyn Owner>,
        now: u64,
        data: Vec<u32>,
    ) -> Result<Self, Error> {
        let mut control = Self::prepare(owner, now, data, false)?;
        if !matches!(control.operation, Operation::DromRead { .. }) {
            return Err(Error::Unsupported);
        }
        control.channel = Some(channel.take().ok_or(Error::UnexpectedReceipt)?);
        control.read_only = true;
        Ok(control)
    }
    /// # Safety
    /// Containing original native CM owner remains retained across this transfer.
    pub(super) unsafe fn retry_read(&mut self) -> Option<(Channel<R>, Vec<u32>)> {
        if !self.read_only
            || !self.closed_read
            || self.stage != Stage::Fault
            || self.status == 0
            || self.expected.is_some()
            || !self.current()
        {
            return None;
        }
        self.owner.take();
        self.published = false;
        Some((self.channel.take()?, core::mem::take(&mut self.data)))
    }
    fn current(&self) -> bool {
        self.owner.as_ref().is_some_and(|o| {
            o.is_current()
                && o.operation() == self.operation
                && o.inventory().path.route() == self.route
                && o.inventory().header == self.header
        })
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = Stage::Fault;
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
        self.channel.take().expect("actual channel")
    }
    fn enter(&mut self, stage: Stage, now: u64) -> Result<(), Error> {
        self.stage = stage;
        self.deadline = crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
            .ok_or(Error::ClockOverflow)?;
        Ok(())
    }
    fn request(&self) -> (Address, Option<u32>) {
        let (offset, words, data) = match self.stage {
            Stage::Header => (0, 5, None),
            Stage::Idle | Stage::Wait | Stage::Status => (26, 1, None),
            Stage::MetadataWrite => (25, 1, Some(self.input_metadata)),
            Stage::MetadataVerify | Stage::Metadata => (25, 1, None),
            Stage::Command => (26, 1, Some(u32::from(self.opcode) | OV)),
            Stage::Data => (9, self.words, None),
            _ => unreachable!("actual operation request stage"),
        };
        (
            Address {
                port: 0,
                space: Space::Router,
                offset,
                words,
            },
            data,
        )
    }
    fn finish(&mut self) -> Result<Option<Event>, Error> {
        self.closed_read = matches!(self.operation, Operation::DromRead { .. })
            && self.data.len() == usize::from(self.words);
        match self.operation {
            Operation::AllocateDp { .. } if self.status != 0 => return Err(Error::ResourceBusy),
            Operation::DeallocateDp { .. } | Operation::DromRead { .. } if self.status != 0 => {
                return Err(Error::ResourceStatus(self.status));
            }
            _ => {}
        }
        self.stage = Stage::Done;
        Ok(Some(Event::Completed(Completed {
            operation: self.operation,
            status: self.status,
            metadata: self.metadata,
            data: core::mem::take(&mut self.data),
            owner: self.owner.take(),
            closed_read: self.closed_read,
        })))
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
        let data = checked_reply(reply, self.upstream).map_err(Error::Transport)?;
        if self.stage == Stage::Header {
            let actual = RouterHeader::parse(&data).map_err(|_| Error::UnexpectedReceipt)?;
            if actual.raw[0] != self.header.raw[0]
                || actual.usb4_version() != self.header.usb4_version()
                || actual.max_port() != self.header.max_port()
                || actual.first_capability() != self.header.first_capability()
                || actual.reported_route() != self.route.raw()
                || actual.reported_depth() != self.header.reported_depth()
                || actual.reported_upstream() != self.upstream
                || !actual.enabled()
            {
                return Err(Error::Changed);
            }
            self.enter(Stage::Idle, now)?;
        } else if matches!(self.stage, Stage::MetadataWrite | Stage::Command) {
            if !data.is_empty() {
                return Err(Error::UnexpectedReceipt);
            }
            if self.stage == Stage::Command {
                self.wait_deadline =
                    crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
                        .ok_or(Error::ClockOverflow)?;
                self.enter(Stage::Wait, now)?;
            } else {
                self.enter(Stage::MetadataVerify, now)?;
            }
        } else if self.stage == Stage::Data {
            if data.len() != usize::from(self.words) {
                return Err(Error::UnexpectedReceipt);
            }
            self.data.extend_from_slice(&data);
            return self.finish();
        } else {
            let [word] = data.as_slice() else {
                return Err(Error::UnexpectedReceipt);
            };
            match self.stage {
                Stage::Idle => {
                    if word & OV != 0 {
                        return Err(Error::Busy);
                    }
                    self.enter(Stage::MetadataWrite, now)?;
                }
                Stage::MetadataVerify => {
                    if *word != self.input_metadata {
                        return Err(Error::Readback);
                    }
                    self.enter(Stage::Command, now)?;
                }
                Stage::Wait => {
                    if word & OV == 0 {
                        self.enter(Stage::Status, now)?;
                    }
                }
                Stage::Status => {
                    if word & OV != 0 {
                        return Err(Error::Changed);
                    }
                    if word & ONS != 0 {
                        return Err(Error::OperationUnsupported(self.opcode));
                    }
                    self.status = ((word >> 24) & 63) as u8;
                    self.enter(Stage::Metadata, now)?;
                }
                Stage::Metadata => {
                    self.metadata = *word;
                    if self.words != 0 {
                        self.enter(Stage::Data, now)?;
                    } else {
                        return self.finish();
                    }
                }
                _ => return Err(Error::UnexpectedReceipt),
            }
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
        if now >= self.deadline
            || now >= self.job_deadline
            || (matches!(self.stage, Stage::Wait | Stage::Status) && now >= self.wait_deadline)
        {
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
                    Err(e) => {
                        if self.read_only
                            && self.closed_read
                            && matches!(e, Error::ResourceStatus(_))
                        {
                            // The actual read-only command is closed: OV0 and
                            // final status/metadata/data ACKs precede finish().
                            // Keep public jobs terminal. Only the containing CM
                            // can take this private same-owner retry channel.
                            self.stage = Stage::Fault;
                            return Err(e);
                        }
                        return self.fail(e);
                    }
                }
            }
            Ok(Some(channel::Event::Plug(e))) => return self.fail(Error::Hotplug(e)),
            Ok(Some(channel::Event::Notification(e))) => return self.fail(Error::Notification(e)),
            Ok(Some(channel::Event::Discarded(e))) => return Ok(Some(Event::Discarded(e))),
            Ok(None) => {}
        }
        if self.expected.is_none() {
            let (address, data) = self.request();
            let deadline = if matches!(self.stage, Stage::Wait | Stage::Status) {
                self.deadline.min(self.wait_deadline)
            } else {
                self.deadline
            };
            let c = self.channel.as_mut().unwrap();
            let result = if let Some(w) = data {
                c.write(self.route, address, &[w], now, deadline)
            } else {
                c.read(self.route, address, now, deadline)
            };
            match result {
                Ok(id) => {
                    self.expected = Some(id);
                    self.published |= data.is_some();
                }
                Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => {}
                Err(e) => {
                    self.published |= data.is_some();
                    return self.fail(Error::Channel(e));
                }
            }
        }
        Ok(None)
    }
}
impl<R: Registers> Drop for Control<R> {
    fn drop(&mut self) {
        if self.published
            && let Some(owner) = &self.owner
        {
            retain(owner);
        }
    }
}

#[cfg(test)]
mod tests;
