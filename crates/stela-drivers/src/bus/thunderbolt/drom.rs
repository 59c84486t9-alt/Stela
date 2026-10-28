// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! Actual USB4 DROM acquisition and bounded source CRC/entry observations.
//! Parsed identifiers and lane hints never grant board, power or tunnel rights.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    operations,
    pcie::checked_reply,
    ring::{self, Registers},
    topology::{AdapterHeader, AdapterKind, AdapterObservation, Inventory, RouterHeader},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
const DATA_START: usize = 13;
const MAX_LEN: usize = 4095 + DATA_START;
const REQUEST_MS: u64 = 500;
const JOB_MS: u64 = 1_440_000;
/// Conservative complete native sequence budget, including per-request timeouts,
/// up to2046 source port entries, full bounded DROM and source retry budgets.
pub const MAX_DURATION_US: u64 = (JOB_MS + 5000) * 1000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

/// Actual configured router/CM lifetime, exclusively retained across every read.
/// # Safety
/// Inventory is the actual configured router in the same physical NHI requester,
/// reset/topology lifetime as Channel. Original router, D0/link, exclusive native
/// operation-engine/CM admission and independent DMA/IRQ/IOMMU owners remain held
/// through completion, failure and quarantine. Firmware/proxy or competing CM
/// cannot mutate the engine or inventory. is_current checks actual admission and
/// pins this in-flight physical lifetime against reuse. supports_duration checks
/// the real calibrated scheduler clock for the full requested microsecond budget;
/// no permissive production provider or default is supplied. Clock observations
/// passed to poll come from that same stable monotonic source, in milliseconds.
/// DROM bytes/identifiers/CRC and parsed ports provide no authority by themselves.
pub unsafe trait Owner: Send + Sync {
    fn inventory(&self) -> &Inventory;
    fn is_current(&self) -> bool;
    fn supports_duration(&self, microseconds: u64) -> bool;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Revoked,
    UnsupportedRevision(u8),
    UnsupportedRouter,
    Inventory,
    Allocation,
    TimerBudget { microseconds: u64 },
    ClockOverflow,
    ClockRegressed,
    Timeout,
    HeaderSize,
    ReservedLength,
    SizeChanged,
    Entry { offset: u16 },
    ProductLength { offset: u16 },
    LaneLength { port: u8 },
    DualPort { port: u8, dual: u8 },
    UidCrc { expected: u8, actual: u8 },
    PortChanged { port: u8 },
    UnexpectedReceipt,
    Cancelled,
    Poisoned,
    Stopped,
    Operation(operations::Error),
    Protocol(super::pcie::Error),
    Channel(channel::Error),
    Hotplug(config::PlugEvent),
    Notification(config::NotificationError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Crc32 {
    pub expected: u32,
    pub actual: u32,
}
impl Crc32 {
    pub fn matches(self) -> bool {
        self.expected == self.actual
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UidSource {
    Router,
    V1DromFallback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lane {
    pub link_number: u8,
    pub dual_port: Option<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Generic,
    Port {
        disabled: bool,
        extra: bool,
        adapter: Option<AdapterKind>,
        lane: Option<Lane>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port {
    pub disabled: bool,
    pub adapter: Option<AdapterKind>,
    pub lane: Option<Lane>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub offset: u16,
    pub length: u8,
    pub index: u8,
    pub kind: Kind,
}
/// Actual acquired bytes and source interpretations, not a native resource grant.
/// CRC32 mismatch is explicit while entries remain observable, as Linux warns
/// and continues. Version1 UID CRC failure is fatal; version3 uses actual CS7 UID.
pub struct Image {
    pub uid: u64,
    pub uid_source: UidSource,
    pub revision: u8,
    pub crc32: Crc32,
    pub product: (u16, u16),
    pub bytes: Vec<u8>,
    pub entries: Vec<Entry>,
    vendor_name: Option<usize>,
    device_name: Option<usize>,
}
impl Image {
    /// Effective source DROM software metadata. Missing entries remain None;
    /// neither this observation nor a dual-port hint grants a routed lifetime.
    pub fn port(&self, port: u8) -> Option<Port> {
        let mut observed: Option<Port> = None;
        for e in &self.entries {
            if e.index != port {
                continue;
            }
            if let Kind::Port {
                disabled,
                extra: false,
                adapter,
                lane,
            } = e.kind
            {
                let value = observed.get_or_insert(Port {
                    disabled: false,
                    adapter: None,
                    lane: None,
                });
                value.disabled = disabled;
                if adapter.is_some() {
                    value.adapter = adapter;
                }
                if let Some(mut lane) = lane {
                    if lane.dual_port.is_none() {
                        lane.dual_port = value.lane.and_then(|p| p.dual_port);
                    }
                    value.lane = Some(lane);
                }
            }
        }
        observed
    }
    pub fn entry_data(&self, index: usize) -> Option<&[u8]> {
        let e = self.entries.get(index)?;
        let start = usize::from(e.offset);
        self.bytes.get(start + 2..start + usize::from(e.length))
    }
    fn name(&self, index: Option<usize>) -> Option<&[u8]> {
        let data = self.entry_data(index?)?;
        Some(&data[..data.iter().position(|b| *b == 0).unwrap_or(data.len())])
    }
    pub fn vendor_name(&self) -> Option<&[u8]> {
        self.name(self.vendor_name)
    }
    pub fn device_name(&self) -> Option<&[u8]> {
        self.name(self.device_name)
    }
}
fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0xff;
    for b in data {
        crc ^= *b;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc & 0x80 != 0 { 7 } else { 0 };
        }
    }
    crc
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x82f63b78 } else { 0 };
        }
    }
    !crc
}
fn le16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}
fn parse(image: &mut Image, max_port: u8) -> Result<(), Error> {
    if image.bytes.len() < 16 {
        return Err(Error::HeaderSize);
    }
    let bytes = &image.bytes;
    let declared = usize::from(le16(bytes, 14) & 4095) + DATA_START;
    if declared != bytes.len() {
        return Err(Error::SizeChanged);
    }
    image.revision = bytes[13];
    let header = match image.revision {
        1 => {
            if bytes.len() < 22 {
                return Err(Error::HeaderSize);
            }
            let actual = crc8(&bytes[1..9]);
            if actual != bytes[0] {
                return Err(Error::UidCrc {
                    expected: bytes[0],
                    actual,
                });
            }
            if image.uid == 0 {
                image.uid = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
                image.uid_source = UidSource::V1DromFallback;
            }
            image.product = (le16(bytes, 16), le16(bytes, 18));
            22
        }
        3 => 16,
        other => return Err(Error::UnsupportedRevision(other)),
    };
    image.crc32 = Crc32 {
        expected: u32::from_le_bytes(bytes[9..13].try_into().unwrap()),
        actual: crc32(&bytes[DATA_START..]),
    };
    let mut at = header;
    while at < bytes.len() {
        if at + 2 > bytes.len() {
            return Err(Error::Entry { offset: at as u16 });
        }
        let length = usize::from(bytes[at]);
        if length < 2 || at + length > bytes.len() {
            return Err(Error::Entry { offset: at as u16 });
        }
        let flags = bytes[at + 1];
        let index = flags & 63;
        let port = flags & 128 != 0;
        let i = image.entries.len();
        if !port {
            match index {
                1 => image.vendor_name = Some(i),
                2 => image.device_name = Some(i),
                9 => {
                    if length < 8 {
                        return Err(Error::ProductLength { offset: at as u16 });
                    }
                    if image.product == (0, 0) {
                        image.product = (le16(bytes, at + 4), le16(bytes, at + 6));
                    }
                }
                _ => {}
            }
        }
        image.entries.push(Entry {
            offset: at as u16,
            length: length as u8,
            index,
            kind: if port {
                Kind::Port {
                    disabled: flags & 64 != 0,
                    extra: index > max_port,
                    adapter: None,
                    lane: None,
                }
            } else {
                Kind::Generic
            },
        });
        at += length;
    }
    Ok(())
}
fn retain(owner: &Arc<dyn Owner>) {
    let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
    core::mem::forget(owner.clone());
}
pub fn quarantined_reservations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}
pub struct Acquired {
    pub image: Image,
    owner: Option<Arc<dyn Owner>>,
}
impl Acquired {
    pub fn is_current(&self) -> bool {
        self.owner.as_ref().is_some_and(|o| o.is_current())
    }
    /// # Safety
    /// Actual configured-router/native CM owner and all independent platform,
    /// DMA/IRQ/IOMMU lifetimes are restored or independently retained. DROM
    /// observations alone cannot retire those owners or grant a tunnel.
    /// ```compile_fail
    /// use stela_drivers::bus::thunderbolt::drom::Acquired;
    /// fn retire(d:Acquired){d.retire();}
    /// ```
    pub unsafe fn retire(mut self) {
        self.owner.take();
    }
}
impl Drop for Acquired {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            retain(owner);
        }
    }
}
pub enum Event {
    Acquired(Acquired),
    Discarded(config::Error),
}
struct ReadOwner {
    source: Arc<dyn Owner>,
    header: RouterHeader,
    route: Route,
    operation: AtomicU32,
}
// SAFETY: private adapter retains the exact original actual CM owner. Only the
// source-derived bounded DROM span changes; metadata supplies no new authority.
unsafe impl operations::Owner for ReadOwner {
    fn inventory(&self) -> &Inventory {
        self.source.inventory()
    }
    fn operation(&self) -> operations::Operation {
        let value = self.operation.load(Ordering::Acquire);
        operations::Operation::DromRead {
            dword_address: value as u16,
            words: (value >> 16) as u8,
        }
    }
    fn is_current(&self) -> bool {
        self.source.is_current()
            && self.source.inventory().header == self.header
            && self.source.inventory().path.route() == self.route
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Uid,
    Probe,
    Body,
    Port(usize),
    Done,
    Fault,
}
#[derive(Clone, Copy)]
struct Block {
    address: usize,
    offset: usize,
    copy: usize,
    words: u8,
}
fn block(address: usize, size: usize) -> Block {
    let offset = address & 3;
    let n = (size + offset).min(64);
    Block {
        address,
        offset,
        copy: n - offset,
        words: n.div_ceil(4) as u8,
    }
}
pub struct Read<R: Registers> {
    channel: Option<Channel<R>>,
    control: Option<operations::Control<R>>,
    owner: Option<Arc<dyn Owner>>,
    read_owner: Arc<ReadOwner>,
    block_data: Option<Vec<u32>>,
    route: Route,
    header: RouterHeader,
    upstream: u8,
    max_port: u8,
    image: Option<Image>,
    stage: Stage,
    expected: Option<u64>,
    current_block: Option<Block>,
    address: usize,
    remaining: usize,
    retries: u8,
    last_now: u64,
    deadline: u64,
    job_deadline: u64,
    started: bool,
}
impl<R: Registers> Read<R> {
    /// # Safety
    /// Idle Channel and actual Owner are this exact physical configured router,
    /// original native CM/reset/topology lifetime. All Owner requirements hold.
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{channel::Channel,drom::{Read,Owner},ring::Registers};
    /// fn pair<R:Registers>(c:Channel<R>,o:Arc<dyn Owner>){let _=Read::new(c,o,0);}
    /// ```
    pub unsafe fn new(channel: Channel<R>, owner: Arc<dyn Owner>, now: u64) -> Result<Self, Error> {
        if !owner.is_current() {
            return Err(Error::Revoked);
        }
        if !owner.supports_duration(MAX_DURATION_US) {
            return Err(Error::TimerBudget {
                microseconds: MAX_DURATION_US,
            });
        }
        let inventory = owner.inventory();
        super::domain::Domain::validate(inventory).map_err(|_| Error::Inventory)?;
        if inventory.header.usb4_version() != 1 {
            return Err(Error::UnsupportedRouter);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_LEN)
            .map_err(|_| Error::Allocation)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(MAX_LEN / 2)
            .map_err(|_| Error::Allocation)?;
        now.checked_add(JOB_MS + 5000).ok_or(Error::ClockOverflow)?;
        let mut block_data = Vec::new();
        block_data
            .try_reserve_exact(16)
            .map_err(|_| Error::Allocation)?;
        let read_owner = Arc::new(ReadOwner {
            source: owner.clone(),
            header: inventory.header.clone(),
            route: inventory.path.route(),
            operation: AtomicU32::new(0),
        });

        Ok(Self {
            channel: Some(channel),
            control: None,
            route: inventory.path.route(),
            header: inventory.header.clone(),
            upstream: inventory.upstream_port,
            max_port: inventory.header.max_port(),
            owner: Some(owner),
            read_owner,
            block_data: Some(block_data),
            image: Some(Image {
                uid: 0,
                uid_source: UidSource::Router,
                revision: 0,
                crc32: Crc32 {
                    expected: 0,
                    actual: 0,
                },
                product: (0, 0),
                bytes,
                entries,
                vendor_name: None,
                device_name: None,
            }),
            stage: Stage::Uid,
            expected: None,
            current_block: None,
            address: 14,
            remaining: 2,
            retries: 3,
            last_now: now,
            deadline: now + REQUEST_MS,
            job_deadline: now + JOB_MS,
            started: false,
        })
    }
    fn current(&self) -> bool {
        self.owner.as_ref().is_some_and(|o| {
            o.is_current()
                && o.inventory().header == self.header
                && o.inventory().path.route() == self.route
        })
    }
    fn fail<T>(&mut self, e: Error) -> Result<T, Error> {
        self.stage = Stage::Fault;
        if let Some(c) = &mut self.control {
            let _ = c.cancel();
        }
        if let Some(c) = &mut self.channel {
            let _ = c.cancel();
        }
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
        let mut c = if let Some(c) = self.control.take() {
            c.into_channel()
        } else {
            self.channel.take().expect("actual DROM channel")
        };
        if self.stage == Stage::Fault {
            let _ = c.cancel();
        }
        c
    }
    fn start_block(&mut self, now: u64) -> Result<(), Error> {
        let plan = block(self.address, self.remaining);
        self.read_owner.operation.store(
            (plan.address as u32 / 4) | (u32::from(plan.words) << 16),
            Ordering::Release,
        );
        let data = self.block_data.take().ok_or(Error::UnexpectedReceipt)?;
        // SAFETY: original actual native CM owner remains in self.owner and the
        // preallocated private adapter across blocks. Prior block ownership is
        // closed before its immutable captured operation metadata can change.
        self.control = Some(
            unsafe {
                operations::Control::read_only(
                    &mut self.channel,
                    self.read_owner.clone(),
                    now,
                    data,
                )
            }
            .map_err(Error::Operation)?,
        );
        self.current_block = Some(plan);
        self.started = true;
        Ok(())
    }
    fn accept(&mut self, data: &[u32], now: u64) -> Result<Option<Event>, Error> {
        let plan = self.current_block.take().ok_or(Error::UnexpectedReceipt)?;
        if data.len() != usize::from(plan.words) {
            return Err(Error::UnexpectedReceipt);
        }
        let mut raw = [0u8; 64];
        for (i, w) in data.iter().enumerate() {
            raw[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let copied = &raw[plan.offset..plan.offset + plan.copy];
        if self.stage == Stage::Probe {
            let [a, b] = copied else {
                return Err(Error::UnexpectedReceipt);
            };
            let size = u16::from_le_bytes([*a, *b]);
            if size & 0xf000 != 0 {
                return Err(Error::ReservedLength);
            }
            let size = usize::from(size) + DATA_START;
            if !(16..=MAX_LEN).contains(&size) {
                return Err(Error::HeaderSize);
            }
            self.image.as_mut().unwrap().bytes.resize(size, 0);
            self.stage = Stage::Body;
            self.address = 0;
            self.remaining = size;
            self.retries = 3;
        } else {
            self.image.as_mut().unwrap().bytes[self.address..self.address + plan.copy]
                .copy_from_slice(copied);
            self.address += plan.copy;
            self.remaining -= plan.copy;
            if self.remaining == 0 {
                parse(self.image.as_mut().unwrap(), self.max_port)?;
                return self.next_port(0, now);
            }
        }
        Ok(None)
    }
    fn next_port(&mut self, from: usize, now: u64) -> Result<Option<Event>, Error> {
        let image = self.image.as_ref().unwrap();
        if let Some(index) = (from..image.entries.len()).find(|i| {
            matches!(
                image.entries[*i].kind,
                Kind::Port {
                    disabled: false,
                    extra: false,
                    ..
                }
            )
        }) {
            self.stage = Stage::Port(index);
            self.deadline =
                crate::bus::thunderbolt::stage_deadline(now, REQUEST_MS, self.job_deadline)
                    .ok_or(Error::ClockOverflow)?;
            return Ok(None);
        }
        if !self.current() {
            return Err(Error::Revoked);
        }
        self.stage = Stage::Done;
        Ok(Some(Event::Acquired(Acquired {
            image: self.image.take().ok_or(Error::UnexpectedReceipt)?,
            owner: self.owner.take(),
        })))
    }
    fn complete(&mut self, reply: Reply, now: u64) -> Result<Option<Event>, Error> {
        let data = checked_reply(reply, self.upstream).map_err(Error::Protocol)?;
        match self.stage {
            Stage::Uid => {
                let [low, high] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                self.image.as_mut().unwrap().uid = u64::from(*low) | (u64::from(*high) << 32);
                self.stage = Stage::Probe;
                self.start_block(now)?;
            }
            Stage::Port(index) => {
                let [word] = data.as_slice() else {
                    return Err(Error::UnexpectedReceipt);
                };
                let kind = AdapterHeader {
                    raw: [0, 0, *word, 0, 0, 0, 0, 0],
                }
                .kind();
                let image = self.image.as_mut().unwrap();
                let e = &mut image.entries[index];
                if let Some(expected) = self
                    .owner
                    .as_ref()
                    .unwrap()
                    .inventory()
                    .adapters
                    .iter()
                    .find_map(|a| match a {
                        AdapterObservation::Present { port, header, .. } if *port == e.index => {
                            Some(header.kind())
                        }
                        _ => None,
                    })
                    && expected != kind
                {
                    return Err(Error::PortChanged { port: e.index });
                }
                let lane = if kind == AdapterKind::Lane {
                    if e.length != 8 {
                        return Err(Error::LaneLength { port: e.index });
                    }
                    let at = usize::from(e.offset);
                    let flags = image.bytes[at + 2];
                    let dual = if flags & 128 != 0 {
                        let n = image.bytes[at + 3] & 63;
                        if n > self.max_port {
                            return Err(Error::DualPort {
                                port: e.index,
                                dual: n,
                            });
                        }
                        Some(n)
                    } else {
                        None
                    };
                    Some(Lane {
                        link_number: (flags >> 4) & 1,
                        dual_port: dual,
                    })
                } else {
                    None
                };
                e.kind = Kind::Port {
                    disabled: false,
                    extra: false,
                    adapter: Some(kind),
                    lane,
                };
                return self.next_port(index + 1, now);
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
        if let Some(control) = &mut self.control {
            match control.poll(now) {
                Ok(Some(operations::Event::Discarded(e))) => return Ok(Some(Event::Discarded(e))),
                Ok(Some(operations::Event::Completed(done))) => {
                    self.channel = Some(self.control.take().unwrap().into_channel());
                    // SAFETY: exact original actual CM owner remains in self.owner;
                    // private completed DROM read has all final ACK/OV0 receipts.
                    let Some(data) = (unsafe { done.take_read_data() }) else {
                        return self.fail(Error::Revoked);
                    };
                    let result = self.accept(&data, now);
                    let mut data = data;
                    data.clear();
                    self.block_data = Some(data);
                    match result {
                        Ok(Some(e)) => return Ok(Some(e)),
                        Err(e) => return self.fail(e),
                        Ok(None) => {
                            if matches!(self.stage, Stage::Probe | Stage::Body)
                                && let Err(e) = self.start_block(now)
                            {
                                return self.fail(e);
                            }
                            return Ok(None);
                        }
                    }
                }
                Err(e) => {
                    // SAFETY: original actual CM and adapter stay retained;
                    // only final acknowledged read-only status errors qualify.
                    let channel = unsafe { self.control.as_mut().unwrap().retry_read() };
                    if let Some((channel, mut data)) = channel {
                        self.control.take();
                        self.channel = Some(channel);
                        data.clear();
                        self.block_data = Some(data);
                        if self.retries > 0 {
                            self.retries -= 1;
                            return match self.start_block(now) {
                                Ok(()) => Ok(None),
                                Err(e) => self.fail(e),
                            };
                        }
                    }
                    return self.fail(Error::Operation(e));
                }
                Ok(None) => return Ok(None),
            }
        }
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
            Ok(Some(channel::Event::Notification(e))) => return self.fail(Error::Notification(e)),
            Ok(Some(channel::Event::Discarded(e))) => return Ok(Some(Event::Discarded(e))),
            Ok(None) => {}
        }
        if let Some(control) = &mut self.control {
            return match control.poll(now) {
                Ok(None) => Ok(None),
                Ok(Some(operations::Event::Discarded(e))) => Ok(Some(Event::Discarded(e))),
                Ok(Some(operations::Event::Completed(_))) => self.fail(Error::UnexpectedReceipt),
                Err(e) => self.fail(Error::Operation(e)),
            };
        }
        if self.expected.is_none() {
            let address = match self.stage {
                Stage::Uid => Address {
                    port: 0,
                    space: Space::Router,
                    offset: 7,
                    words: 2,
                },
                Stage::Port(i) => Address {
                    port: self.image.as_ref().unwrap().entries[i].index,
                    space: Space::Port,
                    offset: 2,
                    words: 1,
                },
                _ => return self.fail(Error::UnexpectedReceipt),
            };
            match self
                .channel
                .as_mut()
                .unwrap()
                .read(self.route, address, now, self.deadline)
            {
                Ok(id) => {
                    self.expected = Some(id);
                    self.started = true;
                }
                Err(channel::Error::Busy | channel::Error::Ring(ring::Error::Full)) => {}
                Err(e) => {
                    self.started = true;
                    return self.fail(Error::Channel(e));
                }
            }
        }
        Ok(None)
    }
}
impl<R: Registers> Drop for Read<R> {
    fn drop(&mut self) {
        if self.started
            && let Some(owner) = &self.owner
        {
            retain(owner);
        }
    }
}

#[cfg(test)]
mod tests;
