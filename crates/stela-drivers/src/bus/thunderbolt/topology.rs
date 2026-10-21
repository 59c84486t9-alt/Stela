// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Read-only router/adapter inventory over the actual native control channel.
//!
//! Layout and capability traversal follow Linux tb_regs.h/cap.c/switch.c.
//! Observation does not configure a router, grant authorization or create a
//! tunnel. Raw headers/capabilities are retained, including unknown adapters.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    ring::Registers,
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Route,
    Depth,
    RootRequired,
    Length,
    CapabilityOffset(u16),
    CapabilityLoop(u16),
    CapabilityHeader,
    CapabilityBudget,
    Busy,
    ClockOverflow,
    UnexpectedReceipt,
    TopologyChanged,
    Controller {
        route: Route,
        port: u8,
        code: u8,
        raw: u32,
    },
    Channel(channel::Error),
}
impl From<channel::Error> for Error {
    fn from(value: channel::Error) -> Self {
        Self::Channel(value)
    }
}

/// A downstream physical route uses contiguous one-byte adapter numbers1..63.
/// Config packets permit54bits, but physical TB/USB4 topologies are shallower.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path {
    route: Route,
    depth: u8,
}
impl Path {
    pub fn new(route: Route) -> Result<Self, Error> {
        let mut raw = route.raw();
        let mut depth = 0;
        while raw != 0 {
            let port = raw as u8;
            if port == 0 || port > 63 {
                return Err(Error::Route);
            }
            depth += 1;
            raw >>= 8;
        }
        if depth > 6 {
            return Err(Error::Depth);
        }
        Ok(Self { route, depth })
    }
    pub fn route(self) -> Route {
        self.route
    }
    pub fn depth(self) -> u8 {
        self.depth
    }
    pub fn downstream(self, port: u8, usb4_domain: bool) -> Result<Self, Error> {
        if port == 0 || port > 63 {
            return Err(Error::Route);
        }
        if self.depth >= if usb4_domain { 5 } else { 6 } {
            return Err(Error::Depth);
        }
        Self::new(
            Route::new(self.route.raw() | (u64::from(port) << (self.depth * 8)))
                .map_err(|_| Error::Route)?,
        )
    }
    pub fn is_descendant_of(self, parent: Self) -> bool {
        if self.depth <= parent.depth {
            return false;
        }
        let mask = if parent.depth == 0 {
            0
        } else {
            (1u64 << (parent.depth * 8)) - 1
        };
        self.route.raw() & mask == parent.route.raw()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterHeader {
    pub raw: [u32; 5],
}
impl RouterHeader {
    pub fn parse(words: &[u32]) -> Result<Self, Error> {
        Ok(Self {
            raw: words.try_into().map_err(|_| Error::Length)?,
        })
    }
    pub fn vendor(&self) -> u16 {
        self.raw[0] as u16
    }
    pub fn device(&self) -> u16 {
        (self.raw[0] >> 16) as u16
    }
    pub fn first_capability(&self) -> u16 {
        (self.raw[1] & 255) as u16
    }
    pub fn reported_upstream(&self) -> u8 {
        ((self.raw[1] >> 8) & 63) as u8
    }
    pub fn max_port(&self) -> u8 {
        ((self.raw[1] >> 14) & 63) as u8
    }
    pub fn reported_depth(&self) -> u8 {
        ((self.raw[1] >> 20) & 7) as u8
    }
    pub fn revision(&self) -> u8 {
        (self.raw[1] >> 24) as u8
    }
    pub fn reported_route(&self) -> u64 {
        u64::from(self.raw[2]) | (u64::from(self.raw[3] & 0x7fff_ffff) << 32)
    }
    pub fn enabled(&self) -> bool {
        self.raw[3] >> 31 != 0
    }
    pub fn usb4_version(&self) -> u8 {
        (self.raw[4] >> 29) as u8
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterKind {
    Inactive,
    Lane,
    Nhi,
    PcieDown,
    PcieUp,
    Usb3Down,
    Usb3Up,
    DisplayIn,
    DisplayOut,
    Unknown(u32),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterHeader {
    pub raw: [u32; 8],
}
impl AdapterHeader {
    pub fn parse(words: &[u32]) -> Result<Self, Error> {
        Ok(Self {
            raw: words.try_into().map_err(|_| Error::Length)?,
        })
    }
    pub fn kind(&self) -> AdapterKind {
        match self.raw[2] & 0xff_ffff {
            0 => AdapterKind::Inactive,
            1 => AdapterKind::Lane,
            2 => AdapterKind::Nhi,
            0x100101 => AdapterKind::PcieDown,
            0x100102 => AdapterKind::PcieUp,
            0x200101 => AdapterKind::Usb3Down,
            0x200102 => AdapterKind::Usb3Up,
            0x0e0101 => AdapterKind::DisplayIn,
            0x0e0102 => AdapterKind::DisplayOut,
            raw => AdapterKind::Unknown(raw),
        }
    }
    pub fn first_capability(&self) -> u16 {
        (self.raw[1] & 255) as u16
    }
    pub fn reported_port(&self) -> u8 {
        ((self.raw[3] >> 20) & 63) as u8
    }
    pub fn max_in_hop(&self) -> u16 {
        (self.raw[5] & 0x7ff) as u16
    }
    pub fn max_out_hop(&self) -> u16 {
        ((self.raw[5] >> 11) & 0x7ff) as u16
    }
    pub fn nonflow_buffers(&self) -> u16 {
        (self.raw[4] & 0x3ff) as u16
    }
    pub fn total_buffers(&self) -> u16 {
        ((self.raw[4] >> 20) & 0x3ff) as u16
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub offset: u16,
    pub id: u8,
    pub vendor_specific: Option<u8>,
    pub length: Option<u16>,
    pub next: u16,
    pub raw: Vec<u32>,
}
impl Capability {
    fn parse(offset: u16, words: &[u32], router: bool) -> Result<Self, Error> {
        if words.len() != if router { 2 } else { 1 } {
            return Err(Error::Length);
        }
        let word = words[0];
        let id = (word >> 8) as u8;
        let mut next = (word & 255) as u16;
        let mut vendor_specific = None;
        let mut length = None;
        if router {
            match id {
                3 => {}
                5 => {
                    vendor_specific = Some((word >> 16) as u8);
                    let short = (word >> 24) as u16;
                    if short != 0 {
                        length = Some(short);
                    } else {
                        if word & 255 != 0 {
                            return Err(Error::CapabilityHeader);
                        }
                        next = words[1] as u16;
                        length = Some((words[1] >> 16) as u16);
                        if length.is_some_and(|len| len < 2) {
                            return Err(Error::CapabilityHeader);
                        }
                        if next == u16::MAX {
                            next = 0;
                        }
                    }
                }
                _ => return Err(Error::CapabilityHeader),
            }
        }
        if let Some(length) = length
            && u32::from(offset) + u32::from(length) > 8192
        {
            return Err(Error::CapabilityHeader);
        }
        if next != 0 && (next < if router { 5 } else { 8 } || next >= 8192) {
            return Err(Error::CapabilityOffset(next));
        }
        Ok(Self {
            offset,
            id,
            vendor_specific,
            length,
            next,
            raw: words.to_vec(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterObservation {
    Present {
        port: u8,
        header: AdapterHeader,
        capabilities: Vec<Capability>,
    },
    /// Linux treats INVALID_CONFIG_SPACE for a port-header read as an absent
    /// adapter. The actual error and sending router/port remain attached.
    Unimplemented {
        port: u8,
        response_route: Route,
        response_port: u8,
        raw: u32,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    pub path: Path,
    pub upstream_port: u8,
    pub header: RouterHeader,
    pub capabilities: Vec<Capability>,
    pub adapters: Vec<AdapterObservation>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Inventory(Inventory),
    Plug(config::PlugEvent),
    Notification(config::NotificationError),
    Discarded(config::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Router,
    RouterCapability(u16),
    Adapter(u8),
    AdapterCapability { port: u8, offset: u16 },
}
struct Job {
    path: Path,
    expected: Option<u64>,
    stage: Stage,
    inventory: Option<Inventory>,
    seen: Vec<u16>,
    invalidated: bool,
}

/// Bounded read-only enumeration; all reads execute through Channel/Ring DMA.
/// Router/adapter capabilities are traversed once, with cycle/bounds checks.
/// Control adapter0 has no port config and is never read. Caller supplies an
/// actual reachable route; probing does not unlock or configure downstream
/// links. Legacy Light/Eagle Ridge TMU access side effects are not implemented.
pub struct Inspector<R: Registers> {
    channel: Channel<R>,
    job: Option<Job>,
    timeout: u64,
    capability_budget: u16,
    root_usb4: Option<bool>,
}
impl<R: Registers> Inspector<R> {
    pub fn new(channel: Channel<R>, timeout: u64, capability_budget: u16) -> Result<Self, Error> {
        if timeout == 0 {
            return Err(Error::ClockOverflow);
        }
        if capability_budget == 0 || capability_budget > 8192 {
            return Err(Error::CapabilityBudget);
        }
        Ok(Self {
            channel,
            job: None,
            timeout,
            capability_budget,
            root_usb4: None,
        })
    }
    pub fn into_channel(self) -> Channel<R> {
        self.channel
    }
    pub fn begin(&mut self, route: Route, now: u64) -> Result<(), Error> {
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        let path = Path::new(route)?;
        if path.depth() != 0 && self.root_usb4.is_none() {
            return Err(Error::RootRequired);
        }
        self.job = Some(Job {
            path,
            expected: None,
            stage: Stage::Router,
            inventory: None,
            seen: Vec::new(),
            invalidated: false,
        });
        if let Err(error) = self.submit(now) {
            self.job = None;
            return Err(error);
        }
        Ok(())
    }
    fn address(stage: Stage) -> Address {
        match stage {
            Stage::Router => Address {
                port: 0,
                space: Space::Router,
                offset: 0,
                words: 5,
            },
            Stage::RouterCapability(offset) => Address {
                port: 0,
                space: Space::Router,
                offset,
                words: 2,
            },
            Stage::Adapter(port) => Address {
                port,
                space: Space::Port,
                offset: 0,
                words: 8,
            },
            Stage::AdapterCapability { port, offset } => Address {
                port,
                space: Space::Port,
                offset,
                words: 1,
            },
        }
    }
    fn submit(&mut self, now: u64) -> Result<(), Error> {
        let deadline = now.checked_add(self.timeout).ok_or(Error::ClockOverflow)?;
        let job = self.job.as_mut().ok_or(Error::UnexpectedReceipt)?;
        if job.expected.is_some() {
            return Ok(());
        }
        let address = Self::address(job.stage);
        if address.offset != 0
            && (address.offset < if address.space == Space::Router { 5 } else { 8 }
                || u32::from(address.offset) + u32::from(address.words) > 8192)
        {
            return Err(Error::CapabilityOffset(address.offset));
        }
        match self.channel.read(job.path.route(), address, now, deadline) {
            Ok(id) => {
                job.expected = Some(id);
                Ok(())
            }
            // A prior response can arrive before its TX descriptor completes.
            // Keep this exact next stage and retry after real TX progress.
            Err(channel::Error::Ring(super::ring::Error::Full)) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    fn set_capability(job: &mut Job, stage: Stage, offset: u16, budget: u16) -> Result<(), Error> {
        if offset == 0 {
            return Err(Error::CapabilityOffset(0));
        }
        if job.seen.contains(&offset) {
            return Err(Error::CapabilityLoop(offset));
        }
        if job.seen.len() >= usize::from(budget) {
            return Err(Error::CapabilityBudget);
        }
        job.seen.push(offset);
        job.stage = stage;
        job.expected = None;
        Ok(())
    }
    fn next_adapter(job: &mut Job, port: u8) -> Result<bool, Error> {
        let inventory = job.inventory.as_ref().ok_or(Error::UnexpectedReceipt)?;
        if port >= inventory.header.max_port() {
            return Ok(true);
        }
        job.stage = Stage::Adapter(port + 1);
        job.expected = None;
        job.seen.clear();
        Ok(false)
    }
    fn complete(
        job: &mut Job,
        reply: Reply,
        budget: u16,
        usb4_domain: bool,
    ) -> Result<bool, Error> {
        if job.invalidated {
            return Err(Error::TopologyChanged);
        }
        let (upstream, data) = match reply {
            Reply::Configuration {
                upstream_port,
                data,
            } => (upstream_port, data),
            Reply::ControllerError {
                route,
                port,
                code,
                raw,
                ..
            } => {
                if let Stage::Adapter(number) = job.stage
                    && code == 2
                {
                    job.inventory
                        .as_mut()
                        .ok_or(Error::UnexpectedReceipt)?
                        .adapters
                        .push(AdapterObservation::Unimplemented {
                            port: number,
                            response_route: route,
                            response_port: port,
                            raw,
                        });
                    return Self::next_adapter(job, number);
                }
                return Err(Error::Controller {
                    route,
                    port,
                    code,
                    raw,
                });
            }
            Reply::Reset => return Err(Error::UnexpectedReceipt),
        };
        match job.stage {
            Stage::Router => {
                let header = RouterHeader::parse(&data)?;
                if job.path.depth()
                    > if usb4_domain || header.usb4_version() > 0 {
                        5
                    } else {
                        6
                    }
                {
                    return Err(Error::Depth);
                }
                if upstream > header.max_port() {
                    return Err(Error::Route);
                }
                let first = header.first_capability();
                job.inventory = Some(Inventory {
                    path: job.path,
                    upstream_port: upstream,
                    header,
                    capabilities: Vec::new(),
                    adapters: Vec::new(),
                });
                if first != 0 {
                    Self::set_capability(job, Stage::RouterCapability(first), first, budget)?;
                    Ok(false)
                } else {
                    Self::next_adapter(job, 0)
                }
            }
            Stage::RouterCapability(offset) => {
                let cap = Capability::parse(offset, &data, true)?;
                let next = cap.next;
                job.inventory
                    .as_mut()
                    .ok_or(Error::UnexpectedReceipt)?
                    .capabilities
                    .push(cap);
                if next != 0 {
                    Self::set_capability(job, Stage::RouterCapability(next), next, budget)?;
                    Ok(false)
                } else {
                    Self::next_adapter(job, 0)
                }
            }
            Stage::Adapter(port) => {
                let header = AdapterHeader::parse(&data)?;
                let first = header.first_capability();
                job.inventory
                    .as_mut()
                    .ok_or(Error::UnexpectedReceipt)?
                    .adapters
                    .push(AdapterObservation::Present {
                        port,
                        header,
                        capabilities: Vec::new(),
                    });
                job.seen.clear();
                if first != 0 {
                    Self::set_capability(
                        job,
                        Stage::AdapterCapability {
                            port,
                            offset: first,
                        },
                        first,
                        budget,
                    )?;
                    Ok(false)
                } else {
                    Self::next_adapter(job, port)
                }
            }
            Stage::AdapterCapability { port, offset } => {
                let cap = Capability::parse(offset, &data, false)?;
                let next = cap.next;
                let Some(AdapterObservation::Present { capabilities, .. }) = job
                    .inventory
                    .as_mut()
                    .ok_or(Error::UnexpectedReceipt)?
                    .adapters
                    .last_mut()
                else {
                    return Err(Error::UnexpectedReceipt);
                };
                capabilities.push(cap);
                if next != 0 {
                    Self::set_capability(
                        job,
                        Stage::AdapterCapability { port, offset: next },
                        next,
                        budget,
                    )?;
                    Ok(false)
                } else {
                    Self::next_adapter(job, port)
                }
            }
        }
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<Event>, Error> {
        let event = match self.channel.poll(now) {
            Ok(event) => event,
            Err(error) => {
                self.job = None;
                return Err(error.into());
            }
        };
        match event {
            Some(channel::Event::Completed { request, reply }) => {
                let mut job = self.job.take().ok_or(Error::UnexpectedReceipt)?;
                if job.expected != Some(request) {
                    return Err(Error::UnexpectedReceipt);
                }
                job.expected = None;
                if Self::complete(
                    &mut job,
                    reply,
                    self.capability_budget,
                    self.root_usb4.unwrap_or(false),
                )? {
                    let inventory = job.inventory.ok_or(Error::UnexpectedReceipt)?;
                    if inventory.path.depth() == 0 {
                        self.root_usb4 = Some(inventory.header.usb4_version() > 0);
                    }
                    return Ok(Some(Event::Inventory(inventory)));
                }
                self.job = Some(job);
            }
            Some(channel::Event::Plug(plug)) => {
                if let Some(job) = self.job.as_mut() {
                    job.invalidated = true;
                }
                return Ok(Some(Event::Plug(plug)));
            }
            Some(channel::Event::Notification(notice)) => {
                if let Some(job) = self.job.as_mut() {
                    job.invalidated = true;
                }
                return Ok(Some(Event::Notification(notice)));
            }
            Some(channel::Event::Discarded(error)) => return Ok(Some(Event::Discarded(error))),
            None => {}
        }
        if self
            .job
            .as_ref()
            .is_some_and(|job| job.invalidated && job.expected.is_none())
        {
            self.job = None;
            return Err(Error::TopologyChanged);
        }
        if self.job.as_ref().is_some_and(|job| job.expected.is_none())
            && let Err(error) = self.submit(now)
        {
            self.job = None;
            return Err(error);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_routes_validate_each_adapter_and_usb4_and_tb_depth_limits() {
        for raw in [0x100, 0x010002, 64, 255, 1 << 48] {
            assert!(Path::new(Route::new(raw).unwrap()).is_err());
        }
        let root = Path::new(Route::new(0).unwrap()).unwrap();
        let mut path = root;
        for port in 1..=6 {
            path = path.downstream(port, false).unwrap();
            assert_eq!(path.depth(), port);
            assert!(path.is_descendant_of(root));
        }
        assert_eq!(path.downstream(1, false), Err(Error::Depth));
        let usb4 = Path::new(Route::new(0x0504030201).unwrap()).unwrap();
        assert_eq!(usb4.downstream(1, true), Err(Error::Depth));
        assert!(path.is_descendant_of(usb4));
        assert!(!usb4.is_descendant_of(usb4));
        assert!(!usb4.is_descendant_of(Path::new(Route::new(2).unwrap()).unwrap()));
    }
    #[test]
    fn capability_long_short_bounds_and_raw_unknown_adapter_are_explicit() {
        let cap = Capability::parse(0x100, &[0x00060500, 2 << 16 | 0x200], true).unwrap();
        assert_eq!(
            (cap.id, cap.vendor_specific, cap.length, cap.next),
            (5, Some(6), Some(2), 0x200)
        );
        assert_eq!(
            Capability::parse(0x100, &[0x00060500, 2 << 16 | 0xffff], true)
                .unwrap()
                .next,
            0
        );
        assert_eq!(
            Capability::parse(0x100, &[0x00060500, 1 << 16], true),
            Err(Error::CapabilityHeader)
        );
        assert_eq!(
            Capability::parse(0x100, &[0x00060501, 2 << 16], true),
            Err(Error::CapabilityHeader)
        );
        assert_eq!(
            Capability::parse(0x100, &[0x00060500, 2 << 16 | 8192], true),
            Err(Error::CapabilityOffset(8192))
        );
        assert_eq!(
            Capability::parse(8191, &[0x02010500, 0], true),
            Err(Error::CapabilityHeader)
        );
        assert_eq!(
            Capability::parse(8, &[0x7e00, 0], true),
            Err(Error::CapabilityHeader)
        );
        assert_eq!(Capability::parse(8, &[0x7e00], false).unwrap().id, 0x7e);
        let mut job = Job {
            path: Path::new(Route::new(0).unwrap()).unwrap(),
            expected: None,
            stage: Stage::Router,
            inventory: None,
            seen: Vec::new(),
            invalidated: false,
        };
        Inspector::<super::super::ring::Mmio>::set_capability(
            &mut job,
            Stage::RouterCapability(32),
            32,
            1,
        )
        .unwrap();
        assert_eq!(
            Inspector::<super::super::ring::Mmio>::set_capability(
                &mut job,
                Stage::RouterCapability(33),
                33,
                1
            ),
            Err(Error::CapabilityBudget)
        );
        assert_eq!(
            Inspector::<super::super::ring::Mmio>::set_capability(
                &mut job,
                Stage::RouterCapability(32),
                32,
                1
            ),
            Err(Error::CapabilityLoop(32))
        );
    }
    #[test]
    #[ignore = "requires hash-pinned unchanged Linux topology helper trace"]
    fn unchanged_linux_router_adapter_bitfields_and_helpers_match() {
        extern crate std;
        use std::{env, fs};
        let trace = fs::read_to_string(
            env::var("STELA_THUNDERBOLT_TOPOLOGY_ORACLE").expect("set topology trace"),
        )
        .unwrap();
        let mut count = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(fields[0], "H");
            let values: Vec<u64> = fields[1..]
                .iter()
                .map(|field| field.parse().unwrap())
                .collect();
            assert_eq!(values.len(), 30);
            let raw: Vec<u32> = values[..13].iter().map(|value| *value as u32).collect();
            let router = RouterHeader::parse(&raw[..5]).unwrap();
            let adapter = AdapterHeader::parse(&raw[5..]).unwrap();
            let kind = match adapter.kind() {
                AdapterKind::Inactive => 0,
                AdapterKind::Lane => 1,
                AdapterKind::Nhi => 2,
                AdapterKind::PcieDown => 0x100101,
                AdapterKind::PcieUp => 0x100102,
                AdapterKind::Usb3Down => 0x200101,
                AdapterKind::Usb3Up => 0x200102,
                AdapterKind::DisplayIn => 0x0e0101,
                AdapterKind::DisplayOut => 0x0e0102,
                AdapterKind::Unknown(raw) => raw,
            };
            assert_eq!(
                &values[13..],
                &[
                    u64::from(router.vendor()),
                    u64::from(router.device()),
                    u64::from(router.first_capability()),
                    u64::from(router.reported_upstream()),
                    u64::from(router.max_port()),
                    u64::from(router.reported_depth()),
                    u64::from(router.revision()),
                    router.reported_route(),
                    u64::from(router.enabled()),
                    u64::from(router.usb4_version()),
                    u64::from(kind),
                    u64::from(adapter.first_capability()),
                    u64::from(adapter.reported_port()),
                    u64::from(adapter.max_in_hop()),
                    u64::from(adapter.max_out_hop()),
                    u64::from(adapter.nonflow_buffers()),
                    u64::from(adapter.total_buffers()),
                ],
                "{line}"
            );
            count += 1;
        }
        assert_eq!(count, 4096);
    }
}
