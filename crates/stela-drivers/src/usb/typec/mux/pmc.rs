// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2020 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! Intel PMC/IOM Type-C mux protocol from pinned intel_pmc_mux.c.
//! Real IPC and IOM resource providers are required. Port associations and
//! orientation overrides come from ACPI child properties, never guesses.
use super::{Mode, Orientation, Pin};
use crate::usb::typec::ucsi::{DataRole, Timer};
use alloc::vec::Vec;
pub mod scu;

pub const ACPI_HID: &str = "INTC105C";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IomKind {
    TigerLake,
    AlderLake,
    MeteorLake,
    LunarLake,
}
impl IomKind {
    pub fn from_hid(hid: &str) -> Option<Self> {
        match hid {
            "INTC1072" => Some(Self::TigerLake),
            "INTC1079" => Some(Self::AlderLake),
            "INTC107A" => Some(Self::MeteorLake),
            "INTC10EA" => Some(Self::LunarLake),
            _ => None,
        }
    }
    pub fn status_offset(self) -> usize {
        match self {
            Self::TigerLake => 0x560,
            Self::AlderLake | Self::MeteorLake => 0x160,
            Self::LunarLake => 0x150,
        }
    }
    pub fn status_stride(self) -> usize {
        if self == Self::LunarLake { 8 } else { 4 }
    }
    fn legacy_tbt(self) -> bool {
        matches!(self, Self::TigerLake | Self::AlderLake)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortConfiguration {
    pub usb2: u8,
    pub usb3: u8,
    pub hsl_orientation: Option<Orientation>,
    pub sbu_orientation: Option<Orientation>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfiguration,
    NoOrientation,
    NoRole,
    UnsupportedMode(Mode),
    Ipc(scu::Error),
    Iom(scu::RegisterError),
    InvalidIom(u32),
    Firmware {
        request: [u8; 8],
        bytes: u8,
        response: [u8; 4],
        fatal: bool,
    },
    NeedsInitialization,
}
/// One native IPC channel and the selected IOM resource. Implementations
/// must keep hardware ownership/mappings and return status/errors.
pub trait Backend {
    fn iom_kind(&self) -> IomKind;
    fn command(&mut self, message: &[u8]) -> Result<[u8; 4], scu::Error>;
    fn iom_status(&mut self, usb3: u8) -> Result<u32, scu::RegisterError>;
}
pub struct Native<R: scu::Registers, I: scu::Registers, C: Timer> {
    ipc: scu::Scu<R, C>,
    iom: I,
    kind: IomKind,
}
impl<R: scu::Registers, I: scu::Registers, C: Timer> Native<R, I, C> {
    pub fn new(ipc: scu::Scu<R, C>, iom: I, kind: IomKind) -> Self {
        Self { ipc, iom, kind }
    }
    pub fn ipc(&self) -> &scu::Scu<R, C> {
        &self.ipc
    }
}
impl<R: scu::Registers, I: scu::Registers, C: Timer> Backend for Native<R, I, C> {
    fn iom_kind(&self) -> IomKind {
        self.kind
    }
    fn command(&mut self, message: &[u8]) -> Result<[u8; 4], scu::Error> {
        let valid = message.first().is_some_and(|first| {
            first >> 4 != 0
                && match first & 15 {
                    0 | 1 | 4 => message.len() == 2,
                    2 => message.len() == 1,
                    3 => message.len() == 8,
                    _ => false,
                }
        });
        if !valid {
            return Err(scu::Error::InvalidArgument);
        }
        let mut reply = [0; 4];
        self.ipc.command(0xa7, 0, message, &mut reply)?;
        Ok(reply)
    }
    fn iom_status(&mut self, usb3: u8) -> Result<u32, scu::RegisterError> {
        if !(1..=15).contains(&usb3) {
            return Err(scu::RegisterError::Bounds {
                offset: self.kind.status_offset(),
            });
        }
        self.iom
            .read32(self.kind.status_offset() + usize::from(usb3 - 1) * self.kind.status_stride())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port {
    pub configuration: PortConfiguration,
    pub orientation: Orientation,
    /// Last accepted role request; IOM role stays in `iom_status`.
    pub role: Option<DataRole>,
    pub iom_status: u32,
}
impl Port {
    pub fn connected(self) -> bool {
        self.iom_status & (1 << 31) != 0
    }
    pub fn activity(self) -> u32 {
        (self.iom_status >> 6) & 15
    }
    pub fn hpd(self) -> bool {
        self.iom_status & (1 << 12) != 0
    }
    pub fn actual_role(self) -> DataRole {
        if self.iom_status & (1 << 10) != 0 {
            DataRole::Device
        } else {
            DataRole::Host
        }
    }
}
pub struct Pmc<B: Backend> {
    backend: B,
    kind: IomKind,
    ports: Vec<Port>,
    initialized: bool,
    fault: Option<Error>,
    last_reply: Option<CommandReceipt>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandReceipt {
    pub request: [u8; 8],
    pub bytes: u8,
    pub response: [u8; 4],
}
impl<B: Backend> Pmc<B> {
    pub fn new(backend: B, configurations: &[PortConfiguration]) -> Result<Self, Error> {
        if configurations.is_empty() || configurations.len() > 4 {
            return Err(Error::InvalidConfiguration);
        }
        let mut ports: Vec<Port> = Vec::new();
        for configuration in configurations {
            if configuration.usb2 > 15
                || !(1..=15).contains(&configuration.usb3)
                || ports
                    .iter()
                    .any(|port| port.configuration.usb3 == configuration.usb3)
            {
                return Err(Error::InvalidConfiguration);
            }
            ports.push(Port {
                configuration: *configuration,
                orientation: Orientation::None,
                role: None,
                iom_status: 0,
            });
        }
        let kind = backend.iom_kind();
        Ok(Self {
            backend,
            kind,
            ports,
            initialized: false,
            fault: None,
            last_reply: None,
        })
    }
    pub fn ports(&self) -> &[Port] {
        &self.ports
    }
    pub fn fault(&self) -> Option<Error> {
        self.fault
    }
    pub fn last_reply(&self) -> Option<CommandReceipt> {
        self.last_reply
    }
    pub fn poll_status(&mut self, index: usize) -> Result<Port, Error> {
        self.healthy()?;
        self.refresh(index)?;
        Ok(self.ports[index])
    }
    fn poison(&mut self, error: Error) -> Error {
        self.initialized = false;
        self.fault = Some(error);
        error
    }
    fn healthy(&self) -> Result<(), Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if !self.initialized {
            return Err(Error::NeedsInitialization);
        }
        Ok(())
    }
    fn refresh(&mut self, index: usize) -> Result<(), Error> {
        let port = self.ports.get(index).ok_or(Error::InvalidConfiguration)?;
        let status = self
            .backend
            .iom_status(port.configuration.usb3)
            .map_err(|error| self.poison(Error::Iom(error)))?;
        if status == u32::MAX {
            return Err(self.poison(Error::InvalidIom(status)));
        }
        self.ports[index].iom_status = status;
        Ok(())
    }
    pub fn initialize(&mut self) -> Result<(), Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if self.initialized {
            return Err(Error::InvalidConfiguration);
        }
        for index in 0..self.ports.len() {
            self.refresh(index)?;
            let port = &mut self.ports[index];
            if port.connected() {
                port.role = Some(port.actual_role());
            }
        }
        self.initialized = true;
        Ok(())
    }
    fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        debug_assert!(matches!(message.len(), 1 | 2 | 8));
        let mut request = [0; 8];
        request[..message.len()].copy_from_slice(message);
        for attempt in 0..3 {
            let response = match self.backend.command(message) {
                Ok(response) => response,
                Err(scu::Error::Busy(_)) if attempt < 2 => continue,
                Err(error @ scu::Error::Busy(_)) => return Err(Error::Ipc(error)),
                Err(error) => return Err(self.poison(Error::Ipc(error))),
            };
            let status = response[if message[0] & 15 < 2 { 2 } else { 1 }];
            self.last_reply = Some(CommandReceipt {
                request,
                bytes: message.len() as u8,
                response,
            });
            if status & 1 == 0 {
                return Ok(());
            }
            let error = Error::Firmware {
                request,
                bytes: message.len() as u8,
                response,
                fatal: status & 2 != 0,
            };
            if status & 2 != 0 {
                return Err(self.poison(error));
            }
            if attempt == 2 {
                return Err(error);
            }
        }
        unreachable!()
    }
    pub fn set_orientation(&mut self, index: usize, orientation: Orientation) -> Result<(), Error> {
        self.healthy()?;
        self.refresh(index)?;
        self.ports[index].orientation = orientation;
        Ok(())
    }
    fn hpd(&mut self, index: usize, status: u32) -> Result<(), Error> {
        let port = self.ports[index];
        let first = 4 | (port.configuration.usb3 << 4);
        if !port.hpd() && status & (1 << 7) != 0 && status & (1 << 8) != 0 {
            self.send(&[first, 0x10])?;
        }
        self.send(&[
            first,
            (if status & (1 << 7) != 0 { 0x10 } else { 0 })
                | (if status & (1 << 8) != 0 { 0x20 } else { 0 }),
        ])
    }
    fn disconnect(&mut self, index: usize) -> Result<(), Error> {
        let port = self.ports[index];
        if !port.connected() {
            return Ok(());
        }
        if port.hpd() {
            self.hpd(index, 0)?;
        }
        self.send(&[1 | (port.configuration.usb3 << 4), port.configuration.usb2])
    }
    fn connect(&mut self, index: usize, role: DataRole) -> Result<(), Error> {
        let port = self.ports[index];
        if port.orientation == Orientation::None {
            return Err(Error::NoOrientation);
        }
        if port.connected() {
            if port.actual_role() == role {
                return Ok(());
            }
            self.disconnect(index)?;
        }
        let effective = |override_value: Option<Orientation>| {
            override_value
                .filter(|value| *value != Orientation::None)
                .unwrap_or(port.orientation)
        };
        let hsl = effective(port.configuration.hsl_orientation) == Orientation::Reverse;
        let sbu = effective(port.configuration.sbu_orientation) == Orientation::Reverse;
        self.send(&[
            port.configuration.usb3 << 4,
            port.configuration.usb2
                | (u8::from(role == DataRole::Device) << 4)
                | (u8::from(hsl) << 5)
                | (u8::from(sbu) << 6),
        ])
    }
    pub fn set_role(&mut self, index: usize, role: Option<DataRole>) -> Result<(), Error> {
        self.healthy()?;
        self.refresh(index)?;
        if let Some(role) = role {
            self.connect(index, role)?;
        } else {
            self.disconnect(index)?;
        }
        self.ports[index].role = role;
        Ok(())
    }
    fn altmode(&mut self, index: usize, mode_type: u8, data: u32) -> Result<(), Error> {
        let mut message = [0; 8];
        message[0] = 3 | (self.ports[index].configuration.usb3 << 4);
        message[1] = mode_type << 4;
        message[4..8].copy_from_slice(&data.to_le_bytes());
        self.send(&message)
    }
    pub fn set_mode(&mut self, index: usize, mode: Mode) -> Result<(), Error> {
        self.healthy()?;
        self.refresh(index)?;
        let port = self.ports[index];
        if mode == Mode::Safe {
            if port.activity() == 4 {
                return Ok(());
            }
            return self.send(&[2 | (port.configuration.usb3 << 4)]);
        }
        if port.orientation == Orientation::None {
            return Err(Error::NoOrientation);
        }
        let role = port.role.ok_or(Error::NoRole)?;
        let common = (u32::from(port.orientation == Orientation::Reverse) << 1)
            | (u32::from(role == DataRole::Device) << 3);
        match mode {
            Mode::Usb | Mode::Usb3 => self.connect(index, role),
            Mode::DisplayPort(data) => {
                if data.status & (1 << 8) != 0 && data.status & (1 << 7) == 0 {
                    return Err(Error::UnsupportedMode(mode));
                }
                if matches!(port.activity(), 5 | 6) {
                    if port.hpd() && data.status & (1 << 7) != 0 && data.status & (1 << 8) == 0 {
                        return Ok(());
                    }
                    return self.hpd(index, data.status);
                }
                let pin = match data.pin {
                    Pin::C => 2,
                    Pin::D => 3,
                    Pin::E => 4,
                    Pin::F => 5,
                };
                let mut word = common | (pin << 8);
                if !self.kind.legacy_tbt() {
                    word |= ((data.configuration >> 2) & 7) << 25;
                    match (data.configuration >> 28) & 3 {
                        1 => word |= (1 << 22) | 4,
                        2 => word |= 1 << 22,
                        3 => word |= 1 << 18,
                        _ => {}
                    }
                }
                self.altmode(index, 1, word)?;
                if data.status & ((1 << 7) | (1 << 8)) != 0 {
                    self.hpd(index, data.status)?;
                }
                Ok(())
            }
            Mode::Thunderbolt {
                cable_mode,
                enter_vdo,
                device_mode,
            } => {
                if matches!(port.activity(), 7 | 13) {
                    return Ok(());
                }
                let mut word =
                    common | (((cable_mode >> 16) & 7) << 25) | (((cable_mode >> 19) & 3) << 28);
                if device_mode & (1 << 16) != 0 {
                    word |= 1 << 17;
                }
                if cable_mode & (1 << 21) != 0 {
                    word |= 1 << 18;
                }
                if cable_mode & (1 << 23) != 0 {
                    word |= 1 << 20;
                }
                if enter_vdo & (1 << 24) != 0 {
                    word |= if self.kind.legacy_tbt() { 4 } else { 1 << 22 };
                }
                if cable_mode & (1 << 22) != 0 {
                    word |= 4;
                }
                self.altmode(index, 2, word)
            }
            Mode::Usb4 {
                enter_usb,
                active_link_training,
            } => {
                if matches!(port.activity(), 7 | 13) {
                    return Ok(());
                }
                let mut word = common | (1 << 23) | (((enter_usb >> 21) & 7) << 25);
                if active_link_training {
                    word |= 1 << 20;
                }
                let cable = (enter_usb >> 19) & 3;
                if cable != 0 {
                    // Pinned source sets RETIMER for optical/retimer on every
                    // IOM generation; preserve its OR-condition result.
                    if cable == 3 {
                        word |= 1 << 18;
                    }
                    if cable == 1 || cable == 3 || self.kind.legacy_tbt() {
                        word |= 4;
                    }
                    if !self.kind.legacy_tbt() {
                        word |= 1 << 22;
                    }
                    word |= 1 << 28;
                }
                self.altmode(index, 2, word)
            }
            _ => Err(Error::UnsupportedMode(mode)),
        }
    }
}

#[cfg(test)]
mod tests;
