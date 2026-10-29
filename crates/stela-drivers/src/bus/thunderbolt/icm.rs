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
mod tests {

    use crate::bus::thunderbolt::ring::{self, Direction, model::*};

    use core::sync::atomic::Ordering;

    extern crate std;
    use super::*;
    fn message(code: u8, index: u8, count: u8, flags: u8, info: u16, words: usize) -> Message {
        let mut data = vec![0; words];
        data[0] = u32::from(code)
            | (u32::from(flags) << 8)
            | (u32::from(index) << 16)
            | (u32::from(count) << 24);
        if words > 1 {
            data[1] = u32::from(info) << 16;
        }
        let mut wire = Vec::new();
        for word in data {
            wire.extend_from_slice(&word.to_be_bytes());
        }
        wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        Message::decode(PacketType::IcmResponse, 15, &wire).unwrap()
    }
    #[test]
    fn icm_preserves_unverified_trailer_unknown_event_and_sof() {
        let mut raw = message(0xfe, 0xff, 0, 0xa4, 0xffff, 2);
        raw.kind = PacketType::IcmEvent;
        let decoded = Message::decode(raw.kind, raw.sof, &raw.raw_wire).unwrap();
        assert_eq!(raw, decoded);
        assert_eq!(decoded.unverified_trailer, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.sof, 15);
        for length in 0..=260 {
            let result = Message::decode(PacketType::IcmResponse, 0, &vec![0; length]);
            assert_eq!(
                result.is_ok(),
                (8..=256).contains(&length) && length % 4 == 0
            );
        }
        assert_eq!(
            Message::decode(PacketType::Read, 0, &[0; 8]),
            Err(Error::WrongType)
        );
    }
    #[test]
    fn icm_assembly_requires_all_fragments_and_is_single_use() {
        for count in 1..=MAX_PACKETS {
            let mut assembly = Assembly::new(3, 2, count).unwrap();
            for index in (0..count).rev() {
                let packet = message(3, index as u8, count as u8, 0, index as u16, 2);
                let result = assembly.receive(packet.clone()).unwrap();
                if index != 0 {
                    assert!(result.is_none());
                    assert!(assembly.receive(packet).unwrap().is_none());
                } else {
                    let complete = result.unwrap();
                    assert_eq!(complete.len(), count);
                    for (i, packet) in complete.iter().enumerate() {
                        assert_eq!(usize::from(packet.packet_id), i);
                    }
                    assert_eq!(assembly.receive(packet), Err(Error::Stopped));
                }
            }
        }
    }
    #[test]
    fn icm_assembly_refuses_conflicts_and_malformed_responses() {
        let mut assembly = Assembly::new(3, 2, 2).unwrap();
        assert_eq!(
            assembly.receive(message(4, 0, 2, 0, 0, 2)),
            Err(Error::WrongCode)
        );
        assert_eq!(
            assembly.receive(message(3, 0, 1, 0, 0, 2)),
            Err(Error::PacketCount)
        );
        assert_eq!(
            assembly.receive(message(3, 2, 2, 0, 0, 2)),
            Err(Error::PacketIndex)
        );
        assert_eq!(
            assembly.receive(message(3, 0, 2, 0, 0, 1)),
            Err(Error::Length)
        );
        assert_eq!(
            assembly.receive(message(3, 0, 2, 1, 0, 2)),
            Err(Error::FirmwareError(1))
        );
        assert!(
            assembly
                .receive(message(3, 0, 2, 0, 0, 2))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            assembly.receive(message(3, 0, 2, 0, 1, 2)),
            Err(Error::DuplicateConflict)
        );
        assert!(Assembly::new(3, 0, 1).is_err());
        assert!(Assembly::new(3, 64, 1).is_err());
        assert!(Assembly::new(3, 2, 0).is_err());
        assert!(Assembly::new(3, 2, 15).is_err());
    }
    #[test]
    fn icm_protocol_parameters_preserve_unsupported_and_unknown_values() {
        let alpine = DriverReady::parse(Family::Alpine, message(3, 0, 1, 64, 15, 2)).unwrap();
        assert_eq!(alpine.security, Some(Security::Unknown(15)));
        assert_eq!(alpine.boot_acl_slots, None);
        assert_eq!(alpine.protocol_version, None);
        assert!(alpine.runtime_pm);
        let info = (1 << 13) | (31 << 7) | 7;
        let alpine = DriverReady::parse(Family::Alpine, message(3, 0, 1, 0, info, 2)).unwrap();
        assert_eq!(alpine.boot_acl_slots, Some(31));
        for family in [Family::Titan, Family::Maple] {
            let parsed = DriverReady::parse(family, message(3, 0, 1, 0, 0xffff, 4)).unwrap();
            assert_eq!(parsed.security, Some(Security::Unknown(7)));
            assert_eq!(parsed.protocol_version, Some(7));
            assert_eq!(parsed.boot_acl_slots, Some(63));
            assert!(!parsed.runtime_pm);
        }
        let ice = DriverReady::parse(Family::IceLake, message(3, 0, 1, 0, 0xffff, 4)).unwrap();
        assert_eq!(ice.security, None);
        assert_eq!(ice.boot_acl_slots, None);
        assert!(ice.runtime_pm);
        assert_eq!(
            DriverReady::parse(Family::Titan, message(3, 0, 1, 1, 0, 4)),
            Err(Error::FirmwareError(1))
        );
    }
    #[test]
    #[ignore = "oracle: STELA_THUNDERBOLT_ICM_ORACLE"]
    fn unchanged_linux_icm_driver_ready_and_command_wire_agree() {
        use std::{env, fs};
        let trace =
            fs::read_to_string(env::var("STELA_THUNDERBOLT_ICM_ORACLE").expect("set ICM trace"))
                .unwrap();
        let mut count = 0;
        for line in trace.lines() {
            let f: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(f[0], "I");
            let n = |i: usize| f[i].parse::<u64>().unwrap();
            let family = match n(1) {
                0 => Family::Alpine,
                1 => Family::Titan,
                2 => Family::IceLake,
                3 => Family::Maple,
                _ => panic!("family"),
            };
            let parsed = DriverReady::parse(
                family,
                message(3, 0, 1, n(3) as u8, n(2) as u16, family.words()),
            )
            .unwrap();
            assert_eq!(
                parsed.security,
                if n(4) == 99 {
                    None
                } else {
                    Some(Security::from_raw(n(4) as u8))
                }
            );
            assert_eq!(
                parsed.protocol_version,
                if n(5) == 99 { None } else { Some(n(5) as u8) }
            );
            assert_eq!(
                parsed.boot_acl_slots,
                if n(6) == 999 { None } else { Some(n(6) as u8) }
            );
            assert_eq!(parsed.runtime_pm, n(7) != 0);
            assert_eq!(family.timeout_ms(), n(8));
            assert_eq!(
                n(9),
                if matches!(family, Family::Titan | Family::Maple) {
                    10
                } else {
                    3
                }
            );
            let command = config::encode(PacketType::IcmCommand, &[3]).unwrap();
            assert_eq!(n(10), command.kind as u64);
            assert_eq!(n(11), command.kind as u64);
            assert_eq!(n(12), command.bytes.len() as u64);
            let wire: Vec<u8> = f[13]
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(command.bytes, wire);
            count += 1;
        }
        assert_eq!(count, 4096);
    }

    #[test]
    fn icm_actual_dma_driver_ready_and_raw_notification_wrap_rings() {
        use super::super::icm::{Event, Security};
        let (_source, domain, model, mut host) = icm(0x15e8);
        host.start(0).unwrap();
        let mut rx = 0;
        for index in 0..25 {
            let request = host.driver_ready(index * 2).unwrap();
            let txindex = index as usize % 10;
            let wire = domain.data(model.frame_address(Direction::Tx, txindex), 8);
            assert_eq!(wire, incoming(PacketType::IcmCommand, &[3]).bytes);
            let descriptor = domain.read32(model.descriptor_address(Direction::Tx, txindex) + 8);
            assert_eq!((descriptor >> 12) & 0xf, 11);
            assert_eq!((descriptor >> 16) & 0xf, 11);
            model.finish(Direction::Tx, txindex, &[], None);
            if index == 0 {
                let mut event = incoming(PacketType::IcmEvent, &[0x00fe_40fe, 0xdeadbeef]);
                let len = event.bytes.len();
                event.bytes[len - 4..].copy_from_slice(&[1, 2, 3, 4]);
                model.finish(
                    Direction::Rx,
                    rx,
                    &event.bytes,
                    Some((2 << 20) | (15 << 16) | (10 << 12) | (len as u32)),
                );
                match host.poll(1).unwrap().unwrap() {
                    Event::Notification(m) => {
                        assert_eq!(m.code, 0xfe);
                        assert_eq!(m.sof, 15);
                        assert_eq!(m.unverified_trailer, [1, 2, 3, 4]);
                    }
                    other => panic!("{other:?}"),
                }
                rx = (rx + 1) % 10;
                assert_eq!(host.driver_ready(1), Err(super::super::icm::Error::Busy));
            }
            let reply = incoming(
                PacketType::IcmResponse,
                &[0x01004003, 0x00920000, 0x12345678, 0xabcdef01],
            );
            finish_rx(&model, rx, &reply);
            rx = (rx + 1) % 10;
            match host.poll(index * 2 + 1).unwrap().unwrap() {
                Event::DriverReady {
                    request: id,
                    parameters,
                } => {
                    assert_eq!(id, request);
                    assert_eq!(parameters.security, Some(Security::Secure));
                    assert_eq!(parameters.protocol_version, Some(1));
                    assert_eq!(parameters.boot_acl_slots, Some(1));
                    assert!(parameters.runtime_pm);
                }
                other => panic!("{other:?}"),
            }
        }
        icm_release(&mut host);
    }

    #[test]
    fn icm_timeout_never_reuses_ambiguous_firmware_code() {
        use super::super::icm::Error;
        for (device, timeout) in [
            (0x1575, 5000),
            (0x15e8, 250),
            (0x1134, 250),
            (0x8a0d, 20000),
        ] {
            let (_source, _domain, model, mut host) = icm(device);
            host.start(100).unwrap();
            let id = host.driver_ready(100).unwrap();
            assert!(host.poll(100 + timeout - 1).unwrap().is_none());
            assert_eq!(
                host.poll(100 + timeout),
                Err(Error::Timeout { request: id })
            );
            assert_eq!(host.driver_ready(101 + timeout), Err(Error::Poisoned));
            let writes = model.state.lock().unwrap().writes.len();
            assert_eq!(host.poll(102 + timeout), Err(Error::Poisoned));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            icm_release(&mut host);
        }
    }

    #[test]
    fn icm_firmware_error_and_epoch_observation_loss_poison() {
        use super::super::icm::Error;
        for loss in [false, true] {
            let (_source, _domain, model, mut host) = icm(0x9a1b);
            host.start(0).unwrap();
            host.driver_ready(0).unwrap();
            finish_rx(
                &model,
                0,
                &incoming(PacketType::IcmResponse, &[0x01000103, 0, 0, 0]),
            );
            if loss {
                model.state.lock().unwrap().values[0x39944 / 4] = 0;
            }
            assert_eq!(
                host.poll(1),
                Err(if loss {
                    Error::FirmwareNotAuthenticated
                } else {
                    Error::FirmwareError(1)
                })
            );
            assert_eq!(host.driver_ready(2), Err(Error::Poisoned));
            icm_release(&mut host);
        }
    }

    #[test]
    fn icm_prerequisites_refuse_before_any_ring_programming() {
        use super::super::icm::{Error, Host};
        for (device, command, status, mode, expected) in [
            (0xdead, 6, 0x80000001, 3, Error::Unsupported),
            (0x1575, 2, 0x80000001, 3, Error::PciState),
            (0x1575, 6, 0x80000000, 3, Error::FirmwareNotRunning),
            (0x15e8, 6, 1, 3, Error::FirmwareNotAuthenticated),
            (0x1134, 6, 0x80000001, 0, Error::SafeMode),
            (0x1575, 6, 0x80000001, 2, Error::WrongMode(2)),
            (0x9a1b, 6, 1, 0, Error::FirmwareNotAuthenticated),
        ] {
            let source = Source::new();
            let domain = Arc::new(Domain::new());
            let model = Arc::new(Model::new(domain.clone()));
            model.state.lock().unwrap().values[0x39944 / 4] = status;
            model.state.lock().unwrap().values[0x3990c / 4] = mode << 8;
            // SAFETY: negative synthetic prerequisites cannot authorize any DMA.
            let result = unsafe {
                Host::new(
                    &IcmPci { device, command },
                    model.clone(),
                    &source,
                    domain,
                    u64::MAX,
                )
            };
            assert!(matches!(result,Err(error) if error==expected));
            assert!(model.state.lock().unwrap().writes.is_empty());
        }
        let (_source, _domain, model, mut host) = icm(0x8a0d);
        model.state.lock().unwrap().values[0x39944 / 4] = 0;
        host.start(0).unwrap();
        icm_release(&mut host);
    }

    #[test]
    fn icm_malformed_frame_keeps_request_pending_until_real_reply() {
        use super::super::icm::{Error, Event};
        let (_source, _domain, model, mut host) = icm(0x1575);
        host.start(0).unwrap();
        let id = host.driver_ready(0).unwrap();
        for (index, words, error) in [
            (0, vec![0x01000004, 0], Error::WrongCode),
            (1, vec![0x02000003, 0], Error::PacketCount),
            (2, vec![0x01000003], Error::Length),
        ] {
            finish_rx(&model, index, &incoming(PacketType::IcmResponse, &words));
            assert_eq!(
                host.poll(1 + index as u64),
                Ok(Some(Event::Discarded(error)))
            );
            assert_eq!(host.driver_ready(1 + index as u64), Err(Error::Busy));
        }
        finish_rx(
            &model,
            3,
            &incoming(PacketType::IcmResponse, &[0x01000003, 0]),
        );
        assert!(matches!(host.poll(4),Ok(Some(Event::DriverReady{request,..})) if request==id));
        icm_release(&mut host);
    }

    #[test]
    fn icm_tx_backpressure_never_publishes_a_ghost_request_and_release_retries() {
        use super::super::icm::{Error, Event};
        let (_source, domain, model, mut host) = icm(0x15e8);
        host.start(0).unwrap();
        // Firmware has replied but the modeled TX descriptor consumer is stalled.
        for i in 0..9 {
            let id = host.driver_ready(i * 2).unwrap();
            finish_rx(
                &model,
                i as usize,
                &incoming(PacketType::IcmResponse, &[0x01000003, 0, 0, 0]),
            );
            assert!(
                matches!(host.poll(i*2+1),Ok(Some(Event::DriverReady{request,..})) if request==id)
            );
        }
        let writes = model.state.lock().unwrap().writes.len();
        assert_eq!(host.driver_ready(20), Err(Error::Ring(ring::Error::Full)));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        model.finish(Direction::Tx, 0, &[], None);
        assert_eq!(host.poll(21), Ok(None));
        assert_eq!(host.driver_ready(22), Ok(10));
        host.disable().unwrap();
        domain.fail_unmap_at.store(12, Ordering::Relaxed);
        // SAFETY: final synthetic device/IRQ/work drain is complete, including
        // the active request. Failed invalidation keeps its mapping for retry.
        assert!(unsafe { host.release() }.is_err());
        assert!(!domain.state.lock().unwrap().maps.is_empty());
        // SAFETY: the same exact drained reservation remains held.
        unsafe { host.release() }.unwrap();
        assert!(domain.state.lock().unwrap().maps.is_empty());
    }
}
