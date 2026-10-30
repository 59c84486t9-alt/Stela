// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Authors: Michael Jamet <michael.jamet@intel.com>
//          Mika Westerberg <mika.westerberg@linux.intel.com>
//! Firmware ICM host protocol, separate from software CM ownership.
//!
//! Linux icm.c/tb_msgs.h and ctl.c use command/response/event types11/12/10.
//! ICM RX trailers are preserved and explicitly unverified: the donor does
//! not check their CRC. No missing fragment or unknown security value becomes
//! a successful default. Timeout permanently refuses ambiguous request reuse.
use super::{
    config::{self, PacketType},
    ring::{self, Registers},
};
use crate::bus::{
    dma::{mapping::DmaDomain, memory::PageSource},
    pci::ConfigSpace,
};
use alloc::{sync::Arc, vec, vec::Vec};
const FW_STATUS: usize = 0x39944;
const OUTMAIL: usize = 0x3990c;
const EN: u32 = 1;
const AUTH: u32 = 1 << 31;
const ENTRIES: u16 = 10;
const DRIVER_READY: u8 = 3;
const MAX_PACKETS: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Alpine,
    Titan,
    IceLake,
    Maple,
}
impl Family {
    /// The ICM protocol `icm_probe` selects for this NHI identity, or None
    /// when its firmware runs no connection manager.
    pub fn of(vendor: u16, device: u16) -> Option<Self> {
        Self::select(vendor, device).ok()
    }
    fn select(vendor: u16, device: u16) -> Result<Self, Error> {
        if vendor != 0x8086 {
            return Err(Error::Unsupported);
        }
        match device {
            0x1575 | 0x1577 | 0x15bf | 0x15d2 | 0x15d9 => Ok(Self::Alpine),
            0x15e8 | 0x15eb => Ok(Self::Titan),
            0x8a0d | 0x8a17 | 0x9a1b | 0x9a1d | 0x9a1f | 0x9a21 | 0x463e | 0x466d | 0xa73e
            | 0xa76d | 0x7eb2 | 0x7ec2 | 0x7ec3 => Ok(Self::IceLake),
            0x1134 | 0x1137 => Ok(Self::Maple),
            _ => Err(Error::Unsupported),
        }
    }
    fn words(self) -> usize {
        if self == Self::Alpine { 2 } else { 4 }
    }
    fn timeout_ms(self) -> u64 {
        match self {
            Self::Alpine => 5000,
            Self::Titan | Self::Maple => 250,
            Self::IceLake => 20000,
        }
    }
    fn mode_required(self) -> bool {
        matches!(self, Self::Alpine | Self::Titan | Self::Maple)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareObservation {
    pub status: u32,
    pub mailbox_mode: Option<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Identity,
    PciState,
    Mapping,
    FirmwareRead,
    FirmwareNotRunning,
    FirmwareNotAuthenticated,
    SafeMode,
    WrongMode(u8),
    Frame,
    WrongType,
    WrongCode,
    PacketCount,
    PacketIndex,
    Length,
    DuplicateConflict,
    FirmwareError(u8),
    Busy,
    Stopped,
    Poisoned,
    InvalidDeadline,
    ClockRegressed,
    Timeout { request: u64 },
    IdentityExhausted,
    Ring(ring::Error),
    Config(config::Error),
}
impl From<ring::Error> for Error {
    fn from(value: ring::Error) -> Self {
        Self::Ring(value)
    }
}
impl From<config::Error> for Error {
    fn from(value: config::Error) -> Self {
        Self::Config(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: PacketType,
    pub sof: u8,
    pub code: u8,
    pub flags: u8,
    pub packet_id: u8,
    pub total_packets: u8,
    pub words: Vec<u32>,
    pub raw_wire: Vec<u8>,
    pub unverified_trailer: [u8; 4],
}
impl Message {
    pub fn decode(kind: PacketType, sof: u8, bytes: &[u8]) -> Result<Self, Error> {
        if !matches!(kind, PacketType::IcmResponse | PacketType::IcmEvent) {
            return Err(Error::WrongType);
        }
        if bytes.len() < 8 || bytes.len() > 256 || !bytes.len().is_multiple_of(4) {
            return Err(Error::Frame);
        }
        let (data, trailer) = bytes.split_at(bytes.len() - 4);
        let words: Vec<u32> = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_be_bytes(*word))
            .collect();
        let header = words[0];
        Ok(Self {
            kind,
            sof,
            code: header as u8,
            flags: (header >> 8) as u8,
            packet_id: (header >> 16) as u8,
            total_packets: (header >> 24) as u8,
            words,
            raw_wire: bytes.to_vec(),
            unverified_trailer: trailer.try_into().expect("checked trailer"),
        })
    }
}
/// Bounded exact-code response assembly. A terminal fragment alone cannot
/// complete a request; every declared slot must have been received unchanged.
pub struct Assembly {
    code: u8,
    words: usize,
    packets: Vec<Option<Message>>,
    complete: bool,
}
impl Assembly {
    pub fn new(code: u8, words: usize, packets: usize) -> Result<Self, Error> {
        if !(1..=63).contains(&words) {
            return Err(Error::Length);
        }
        if !(1..=MAX_PACKETS).contains(&packets) {
            return Err(Error::PacketCount);
        }
        Ok(Self {
            code,
            words,
            packets: vec![None; packets],
            complete: false,
        })
    }
    pub fn receive(&mut self, message: Message) -> Result<Option<Vec<Message>>, Error> {
        if self.complete {
            return Err(Error::Stopped);
        }
        if message.kind != PacketType::IcmResponse {
            return Err(Error::WrongType);
        }
        if message.code != self.code {
            return Err(Error::WrongCode);
        }
        if message.total_packets as usize != self.packets.len() {
            return Err(Error::PacketCount);
        }
        let index = usize::from(message.packet_id);
        if index >= self.packets.len() {
            return Err(Error::PacketIndex);
        }
        if message.words.len() != self.words {
            return Err(Error::Length);
        }
        if message.flags & 1 != 0 {
            return Err(Error::FirmwareError(message.flags));
        }
        if let Some(previous) = &self.packets[index] {
            if previous != &message {
                return Err(Error::DuplicateConflict);
            }
        } else {
            self.packets[index] = Some(message);
        }
        if self.packets.iter().all(Option::is_some) {
            self.complete = true;
            return Ok(Some(
                self.packets
                    .iter_mut()
                    .map(|packet| packet.take().expect("all packets present"))
                    .collect(),
            ));
        }
        Ok(None)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    None,
    User,
    Secure,
    DisplayOnly,
    UsbOnly,
    NoPcie,
    Unknown(u8),
}
impl Security {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::User,
            2 => Self::Secure,
            3 => Self::DisplayOnly,
            4 => Self::UsbOnly,
            5 => Self::NoPcie,
            raw => Self::Unknown(raw),
        }
    }
}
/// Firmware protocol parameters only; root config/link discovery and native
/// policy must still complete before any working CM/tunnel can be announced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverReady {
    pub family: Family,
    pub security: Option<Security>,
    pub protocol_version: Option<u8>,
    pub boot_acl_slots: Option<u8>,
    pub runtime_pm: bool,
    pub raw: Message,
}
impl DriverReady {
    pub fn parse(family: Family, raw: Message) -> Result<Self, Error> {
        if raw.kind != PacketType::IcmResponse || raw.code != DRIVER_READY {
            return Err(Error::WrongCode);
        }
        if raw.words.len() != family.words() {
            return Err(Error::Length);
        }
        if raw.packet_id != 0 || raw.total_packets != 1 {
            return Err(Error::PacketCount);
        }
        if raw.flags & 1 != 0 {
            return Err(Error::FirmwareError(raw.flags));
        }
        let info = (raw.words[1] >> 16) as u16;
        let (security, protocol_version, boot_acl_slots, runtime_pm) = match family {
            Family::Alpine => (
                Some(Security::from_raw((info & 15) as u8)),
                None,
                if info & (1 << 13) != 0 {
                    Some(((info >> 7) & 31) as u8)
                } else {
                    None
                },
                raw.flags & (1 << 6) != 0,
            ),
            Family::Titan | Family::Maple => (
                Some(Security::from_raw((info & 7) as u8)),
                Some(((info >> 4) & 7) as u8),
                Some(((info >> 7) & 63) as u8),
                raw.flags & (1 << 6) != 0,
            ),
            Family::IceLake => (None, Some(((info >> 4) & 7) as u8), None, true),
        };
        Ok(Self {
            family,
            security,
            protocol_version,
            boot_acl_slots,
            runtime_pm,
            raw,
        })
    }
}
/// Where an ICM event places a device: a route string, or, in Alpine
/// Ridge's FR events, the root link and depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    Route(u64),
    Link { link: u8, depth: u8 },
}
impl core::fmt::Display for Location {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Route(route) => write!(f, "route {route:#x}"),
            Self::Link { link, depth } => write!(f, "link {link} depth {depth}"),
        }
    }
}

/// A firmware event, as Linux's `icm_handle_notification` dispatches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    /// `ICM_LINK_INFO_*`: whether the firmware approved the device's PCIe
    /// tunnel, rejected it, or approved it from its boot ACL.
    DeviceConnected {
        location: Location,
        approved: bool,
        rejected: bool,
        boot: bool,
    },
    DeviceDisconnected {
        location: Location,
    },
    XDomainConnected,
    XDomainDisconnected,
    DpConfigChanged,
    Rtd3Veto,
    Other(u8),
}
impl Notification {
    /// Decode an event in `family`'s layout: Alpine Ridge's
    /// `icm_fr_event_device_*`, or the `icm_tr_event_device_*` that Titan
    /// Ridge, Ice Lake and Maple Ridge send.
    pub fn decode(family: Family, message: &Message) -> Result<Self, Error> {
        if message.kind != PacketType::IcmEvent {
            return Err(Error::WrongType);
        }
        let word = |index: usize| message.words.get(index).copied().ok_or(Error::Length);
        let route = |high: usize| {
            Ok::<_, Error>(Location::Route(
                u64::from(word(high)?) << 32 | u64::from(word(high + 1)?),
            ))
        };
        let link = |info: u32| Location::Link {
            link: (info & 7) as u8,
            depth: ((info >> 4) & 15) as u8,
        };
        let fr = family == Family::Alpine;
        Ok(match message.code {
            0x3 => {
                let (location, info) = if fr {
                    let info = word(5)? >> 16;
                    (link(info), info)
                } else {
                    (route(5)?, word(7)? >> 16)
                };
                Self::DeviceConnected {
                    location,
                    approved: info & (1 << 8) != 0,
                    rejected: info & (1 << 9) != 0,
                    boot: info & (1 << 10) != 0,
                }
            }
            0x4 => Self::DeviceDisconnected {
                location: if fr { link(word(1)? >> 16) } else { route(1)? },
            },
            0x6 => Self::XDomainConnected,
            0x7 => Self::XDomainDisconnected,
            0x8 => Self::DpConfigChanged,
            0xa => Self::Rtd3Veto,
            code => Self::Other(code),
        })
    }
}
impl core::fmt::Display for Notification {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeviceConnected {
                location,
                approved,
                rejected,
                boot,
            } => {
                let state = match (approved, rejected, boot) {
                    (_, true, _) => "rejected by the firmware",
                    (true, _, true) => "approved from the boot ACL",
                    (true, ..) => "approved",
                    _ => "awaiting approval",
                };
                write!(f, "device connected at {location}, {state}")
            }
            Self::DeviceDisconnected { location } => {
                write!(f, "device disconnected at {location}")
            }
            Self::XDomainConnected => f.write_str("host-to-host link connected"),
            Self::XDomainDisconnected => f.write_str("host-to-host link disconnected"),
            Self::DpConfigChanged => f.write_str("DisplayPort configuration changed"),
            Self::Rtd3Veto => f.write_str("runtime D3 veto changed"),
            Self::Other(code) => write!(f, "event {code:#x}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    DriverReady {
        request: u64,
        parameters: DriverReady,
    },
    Notification(Message),
    Discarded(Error),
}
struct Active {
    id: u64,
    deadline: u64,
    assembly: Assembly,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Running,
    Fault,
    Disabled,
    Released,
}
/// Firmware-ICM transport exclusively owns the host's hop-zero rings; firmware
/// owns router/link configuration. It cannot be composed with a software CM.
pub struct Host<R: Registers> {
    registers: Arc<R>,
    tx: ring::Ring<R>,
    rx: ring::Ring<R>,
    family: Family,
    authentication_required: bool,
    phase: Phase,
    observation: FirmwareObservation,
    active: Option<Active>,
    last_now: u64,
    next_id: u64,
    tx_released: bool,
    rx_released: bool,
}
impl<R: Registers> Host<R> {
    /// # Safety
    /// PCI config, Registers, PageSource and attached DmaDomain identify
    /// the same live physical requester and ownership/reset epoch. The native
    /// platform positively selected already-running firmware ICM, resolved
    /// power/IMR/mastering/protected firmware-DMA requirements and owns
    /// the host's NHI rings exclusively. Firmware may produce/consume packets,
    /// but cannot reprogram these host ring registers; no software CM exists.
    /// All Ring::new DMA/coherence/NoSnoop, prior drain and IRQ-mask grants hold.
    /// Firmware authentication/startup must already have completed; this bounded
    /// component observes current prerequisites and never starts unauthenticated
    /// firmware or changes platform authorization policy.
    /// ```compile_fail
    /// use stela_drivers::bus::{thunderbolt::{icm::Host, ring::Registers}, pci::ConfigSpace, dma::{memory::PageSource, mapping::DmaDomain}};
    /// use alloc::sync::Arc;
    /// extern crate alloc;
    /// fn pair<R: Registers>(pci: &impl ConfigSpace, registers: Arc<R>, source: &dyn PageSource, domain: Arc<dyn DmaDomain>) {
    ///     let _host = Host::new(pci, registers, source, domain, u64::MAX);
    /// }
    /// ```
    pub unsafe fn new(
        configuration: &impl ConfigSpace,
        registers: Arc<R>,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        address_limit: u64,
    ) -> Result<Self, Error> {
        let identity = configuration.read32(0);
        if identity == u32::MAX {
            return Err(Error::Identity);
        }
        let family = Family::select(identity as u16, (identity >> 16) as u16)?;
        // icm_probe selects the original Ice Lake protocol without the TGL
        // authentication gate; later integrated IDs use icm_tgl_is_supported.
        let authentication_required = !matches!((identity >> 16) as u16, 0x8a0d | 0x8a17);
        let command = configuration.read16(4);
        if command == u16::MAX || command & 6 != 6 {
            return Err(Error::PciState);
        }
        let class = configuration.read32(8) >> 8;
        if !matches!(class, 0x088000 | 0x0c0340) || configuration.read8(0x0e) & 0x7f != 0 {
            return Err(Error::Identity);
        }
        let observation = Self::firmware(&*registers, family, authentication_required)?;
        let config = |direction| ring::RingConfig {
            direction,
            hop: 0,
            entries: ENTRIES,
            address_limit,
        };
        // SAFETY: caller proves same requester/epoch and exclusive host rings;
        // firmware ICM is only the protocol peer, not another ring-programmer.
        let tx = unsafe {
            ring::Ring::new(
                registers.clone(),
                source,
                domain.clone(),
                config(ring::Direction::Tx),
            )?
        };
        // SAFETY: same ownership; neither ring has published any DMA yet.
        let rx = unsafe {
            ring::Ring::new(
                registers.clone(),
                source,
                domain,
                config(ring::Direction::Rx),
            )?
        };
        Ok(Self {
            registers,
            tx,
            rx,
            family,
            authentication_required,
            phase: Phase::New,
            observation,
            active: None,
            last_now: 0,
            next_id: 0,
            tx_released: false,
            rx_released: false,
        })
    }
    pub fn family(&self) -> Family {
        self.family
    }
    pub fn observation(&self) -> FirmwareObservation {
        self.observation
    }
    fn firmware(
        registers: &R,
        family: Family,
        authentication_required: bool,
    ) -> Result<FirmwareObservation, Error> {
        if registers.bytes() < FW_STATUS + 4 {
            return Err(Error::Mapping);
        }
        let status = registers.read32(FW_STATUS);
        if status == u32::MAX {
            return Err(Error::FirmwareRead);
        }
        let mailbox_mode = if family.mode_required() {
            let outmail = registers.read32(OUTMAIL);
            if outmail == u32::MAX {
                return Err(Error::FirmwareRead);
            }
            Some(((outmail >> 8) & 15) as u8)
        } else {
            None
        };
        if matches!(family, Family::Alpine | Family::Titan) && status & EN == 0 {
            return Err(Error::FirmwareNotRunning);
        }
        if authentication_required && status & AUTH == 0 {
            return Err(Error::FirmwareNotAuthenticated);
        }
        if family.mode_required() {
            match mailbox_mode.expect("source family reads mode") {
                0 => return Err(Error::SafeMode),
                3 => {}
                mode => return Err(Error::WrongMode(mode)),
            }
        }
        Ok(FirmwareObservation {
            status,
            mailbox_mode,
        })
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.phase = Phase::Fault;
        self.active = None;
        Err(error)
    }
    fn running(&self) -> Result<(), Error> {
        match self.phase {
            Phase::Running => Ok(()),
            Phase::Fault => Err(Error::Poisoned),
            _ => Err(Error::Stopped),
        }
    }
    fn observe(&mut self, now: u64) -> Result<(), Error> {
        self.running()?;
        if now < self.last_now {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = now;
        if let Some(active) = self.active.as_ref()
            && now >= active.deadline
        {
            return self.fail(Error::Timeout { request: active.id });
        }
        Ok(())
    }
    pub fn start(&mut self, now: u64) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::Busy);
        }
        let result = (|| {
            self.observation =
                Self::firmware(&*self.registers, self.family, self.authentication_required)?;
            self.rx.start()?;
            for _ in 1..ENTRIES {
                self.rx.receive()?;
            }
            self.tx.start()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.phase = Phase::Running;
                self.last_now = now;
                Ok(())
            }
            Err(error) => self.fail(error),
        }
    }
    pub fn driver_ready(&mut self, now: u64) -> Result<u64, Error> {
        self.observe(now)?;
        if self.active.is_some() {
            return Err(Error::Busy);
        }
        self.observation =
            match Self::firmware(&*self.registers, self.family, self.authentication_required) {
                Ok(value) => value,
                Err(error) => return self.fail(error),
            };
        let deadline = now
            .checked_add(self.family.timeout_ms())
            .ok_or(Error::InvalidDeadline)?;
        let id = self
            .next_id
            .checked_add(1)
            .ok_or(Error::IdentityExhausted)?;
        let assembly = Assembly::new(DRIVER_READY, self.family.words(), 1)?;
        let frame = config::encode(PacketType::IcmCommand, &[u32::from(DRIVER_READY)])?;
        if let Err(error) = self.tx.transmit(&frame) {
            return if error == ring::Error::Full {
                Err(error.into())
            } else {
                self.fail(error.into())
            };
        }
        self.active = Some(Active {
            id,
            deadline,
            assembly,
        });
        self.next_id = id;
        Ok(id)
    }
    pub fn poll(&mut self, now: u64) -> Result<Option<Event>, Error> {
        self.observe(now)?;
        self.observation =
            match Self::firmware(&*self.registers, self.family, self.authentication_required) {
                Ok(value) => value,
                Err(error) => return self.fail(error),
            };
        for _ in 0..ENTRIES {
            match self.tx.poll() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => return self.fail(error.into()),
            }
        }
        let completion = match self.rx.poll() {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(None),
            Err(error) => return self.fail(error.into()),
        };
        let result = (|| {
            let kind = PacketType::try_from(completion.eof)?;
            let message = Message::decode(kind, completion.sof, &completion.data)?;
            if kind == PacketType::IcmEvent {
                return Ok(Some(Event::Notification(message)));
            }
            let Some(active) = self.active.as_mut() else {
                return Err(Error::WrongCode);
            };
            if let Some(mut messages) = active.assembly.receive(message)? {
                let parameters = DriverReady::parse(self.family, messages.remove(0))?;
                let request = active.id;
                self.active = None;
                return Ok(Some(Event::DriverReady {
                    request,
                    parameters,
                }));
            }
            Ok(None)
        })();
        if let Err(error) = self.rx.receive() {
            return self.fail(error.into());
        }
        match result {
            Ok(event) => Ok(event),
            Err(error @ (Error::DuplicateConflict | Error::FirmwareError(_))) => self.fail(error),
            Err(error) => Ok(Some(Event::Discarded(error))),
        }
    }
    pub fn disable(&mut self) -> Result<(), Error> {
        if self.phase == Phase::Released {
            return Err(Error::Stopped);
        }
        self.active = None;
        let tx = if self.tx_released {
            Ok(())
        } else {
            self.tx.disable()
        };
        let rx = if self.rx_released {
            Ok(())
        } else {
            self.rx.disable()
        };
        match tx.and(rx) {
            Ok(()) => {
                self.phase = Phase::Disabled;
                Ok(())
            }
            Err(error) => self.fail(error.into()),
        }
    }
    /// # Safety
    /// Both host rings have final posted-DMA/IRQ/deferred drain as
    /// required by Ring::release; firmware cannot use them again. Process or
    /// deferred context only. This does not stop firmware-owned device tunnels.
    pub unsafe fn release(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Disabled {
            return Err(Error::Busy);
        }
        // SAFETY: the caller proves final drain of both rings.
        unsafe {
            ring::release_pair(
                (&mut self.tx, &mut self.tx_released),
                (&mut self.rx, &mut self.rx_released),
            )?;
        }
        self.phase = Phase::Released;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
