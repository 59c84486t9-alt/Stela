// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! TI TPS65981/82/86 and TPS65987/88 DH/DK physical PD controllers.
//!
//! Adapted from pinned Linux tipd/core.c and tps6598x.h. The platform supplies
//! the actual powered I²C target and exclusive controller ownership. This is
//! the ordinary TI register protocol, not Apple's CD321x guest/emulation path.
//! Unsupported silicon, modes, task results and patch failures remain errors.

use super::ucsi::{DataRole, PowerRole, Timer};
use crate::{
    bus::i2c::{self, Address, Bus, Operation},
    firmware::{Image, Provider, Requirement, Target},
};
use alloc::{format, string::String};

const CMD: u8 = 8;
const DATA: u8 = 9;
const STATUS: u8 = 0x1a;
const INVALID_CMD: u32 = 0x444d_4321;
const MASK: u64 = (1 << 3) | (1 << 24) | (1 << 25);

pub const DEVICE_TREE_COMPATIBLE: &str = "ti,tps6598x";
pub const I2C_DRIVER_ID: &str = "tps6598x";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    TimerBudget {
        microseconds: u64,
    },
    I2c {
        register: u8,
        write: bool,
        error: i2c::Error,
    },
    InvalidLength {
        register: u8,
        requested: usize,
        returned: usize,
    },
    InvalidArgument,
    NoVendor(u32),
    UnsupportedVersion(u32),
    Mode([u8; 4]),
    FirmwareRequired {
        vendor: u32,
        version: u32,
    },
    Firmware(crate::firmware::Error),
    PortConfiguration(u32),
    Busy(u32),
    InvalidCommand([u8; 4]),
    Timeout {
        command: [u8; 4],
    },
    TaskTimeout {
        command: [u8; 4],
    },
    Rejected {
        command: [u8; 4],
    },
    PatchResponse {
        command: [u8; 4],
        raw: [u8; 10],
    },
    RoleMismatch {
        status: u32,
    },
    TaskResult {
        command: [u8; 4],
        status: u8,
    },
    InvalidRegister {
        register: u8,
        value: u32,
    },
    NeedsInitialization,
    NeedsPlatformReset,
}

/// Retained verified-provider receipt; no firmware bytes or provider borrow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchReceipt {
    pub name: String,
    pub length: usize,
    pub sha256: [u8; 32],
    pub source: String,
    pub revision: String,
    pub member: String,
    pub license: String,
    pub target_driver: String,
    pub target_hardware: String,
    pub target_revision: String,
    pub target_board: Option<String>,
}
impl From<Image<'_>> for PatchReceipt {
    fn from(image: Image<'_>) -> Self {
        let provenance = image.provenance();
        let target = image.target();
        Self {
            name: image.name().into(),
            length: image.bytes().len(),
            sha256: image.sha256(),
            source: provenance.source.into(),
            revision: provenance.revision.into(),
            member: provenance.member.into(),
            license: provenance.license.into(),
            target_driver: target.driver.into(),
            target_hardware: target.hardware.into(),
            target_revision: target.revision.into(),
            target_board: target.board.map(Into::into),
        }
    }
}
/// These exact strings must come from this physical device's firmware/board
/// description; there is no fallback firmware name or interchangeable board.
pub struct FirmwareRequest<'a> {
    pub name: &'a str,
    pub board: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub vendor: u32,
    pub version: u32,
    pub system_configuration: u32,
    pub event_bytes: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub status: u32,
    pub data_status: u32,
    pub power_status: u16,
    /// Raw response status byte followed by the six PD identity VDOs.
    pub partner_identity: Option<[u8; 25]>,
}
impl Snapshot {
    pub fn connected(self) -> bool {
        self.status & 1 != 0
    }
    pub fn reversed(self) -> bool {
        self.status & (1 << 4) != 0
    }
    pub fn source(self) -> bool {
        self.status & (1 << 5) != 0
    }
    pub fn host(self) -> bool {
        self.status & (1 << 6) != 0
    }
    pub fn vconn_source(self) -> bool {
        self.status & (1 << 7) != 0
    }
    pub fn pd(self) -> bool {
        (self.power_status >> 2) & 3 == 3
    }
    pub fn displayport(self) -> bool {
        self.data_status & (1 << 8) != 0
    }
    pub fn thunderbolt(self) -> bool {
        self.data_status & (1 << 16) != 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub first: [u8; 11],
    pub second: [u8; 11],
    pub bytes: u8,
    pub snapshot: Snapshot,
}

/// Serialized PIO controller, with no automatic replay after uncertain effects.
/// A fault requires platform reset and fresh construction; no generic TPS reset
/// is invented (Linux's generic reset hook itself has no hardware operation).
pub struct Tps6598x<B: Bus, C: Timer> {
    bus: B,
    address: Address,
    timer: C,
    identity: Option<Identity>,
    snapshot: Option<Snapshot>,
    patch: Option<PatchReceipt>,
    ready: bool,
    fault: Option<Error>,
}
impl<B: Bus, C: Timer> Tps6598x<B, C> {
    pub fn new(bus: B, address: Address, timer: C) -> Self {
        Self {
            bus,
            address,
            timer,
            identity: None,
            snapshot: None,
            patch: None,
            ready: false,
            fault: None,
        }
    }
    pub fn identity(&self) -> Option<Identity> {
        self.identity
    }
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.snapshot
    }
    pub fn patch(&self) -> Option<&PatchReceipt> {
        self.patch.as_ref()
    }
    pub fn fault(&self) -> Option<&Error> {
        self.fault.as_ref()
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
    fn poison(&mut self, error: Error) -> Error {
        self.ready = false;
        self.fault = Some(error.clone());
        error
    }
    fn check_ready(&self) -> Result<(), Error> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if !self.ready {
            return Err(Error::NeedsInitialization);
        }
        Ok(())
    }
    fn read(&mut self, register: u8, bytes: &mut [u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > 64 {
            return Err(Error::InvalidArgument);
        }
        let mut response = [0; 65];
        self.bus
            .transaction(
                self.address,
                &mut [
                    Operation::Write(&[register]),
                    Operation::Read(&mut response[..bytes.len() + 1]),
                ],
            )
            .map_err(|error| Error::I2c {
                register,
                write: false,
                error,
            })?;
        if usize::from(response[0]) < bytes.len() || response[0] > 64 {
            return Err(Error::InvalidLength {
                register,
                requested: bytes.len(),
                returned: usize::from(response[0]),
            });
        }
        bytes.copy_from_slice(&response[1..bytes.len() + 1]);
        Ok(())
    }
    fn write(&mut self, register: u8, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > 64 {
            return Err(Error::InvalidArgument);
        }
        let mut request = [0; 66];
        request[0] = register;
        request[1] = bytes.len() as u8;
        request[2..bytes.len() + 2].copy_from_slice(bytes);
        self.bus
            .transaction(
                self.address,
                &mut [Operation::Write(&request[..bytes.len() + 2])],
            )
            .map_err(|error| Error::I2c {
                register,
                write: true,
                error,
            })
    }
    fn read32(&mut self, register: u8) -> Result<u32, Error> {
        let mut bytes = [0; 4];
        self.read(register, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn task(&mut self, command: [u8; 4], input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if !self.timer.supports_duration(1_000_000) {
            return Err(Error::TimerBudget {
                microseconds: 1_000_000,
            });
        }
        if input.len() > 64 || output.len() > 64 {
            return Err(Error::InvalidArgument);
        }
        let previous = self.read32(CMD)?;
        if previous != 0 && previous != INVALID_CMD {
            return Err(Error::Busy(previous));
        }
        if !input.is_empty() {
            self.write(DATA, input)?;
        }
        self.write(CMD, &command)?;
        let start = self.timer.start();
        loop {
            let value = self.read32(CMD)?;
            if value == INVALID_CMD {
                return Err(Error::InvalidCommand(command));
            }
            if self.timer.elapsed_us(start) >= 1_000_000 {
                return Err(Error::Timeout { command });
            }
            if value == 0 {
                break;
            }
            self.timer.delay_us(100);
        }
        let mut result = [0; 64];
        let length = output.len().max(1);
        self.read(DATA, &mut result[..length])?;
        match result[0] {
            1 => return Err(Error::TaskTimeout { command }),
            3 => return Err(Error::Rejected { command }),
            0 => {}
            status => return Err(Error::TaskResult { command, status }),
        }
        output.copy_from_slice(&result[..output.len()]);
        Ok(())
    }
    fn apply_patch(&mut self, image: Image<'_>) -> Result<(), Error> {
        self.patch = Some(image.into());
        let mut result = [0; 10];
        self.task(*b"PTCs", &[3], &mut result[..4])?;
        if result[1] == 0x80 {
            return Err(Error::PatchResponse {
                command: *b"PTCs",
                raw: result,
            });
        }
        for bytes in image.bytes().chunks(64) {
            self.task(*b"PTCd", bytes, &mut result)?;
            if result[1] != 0 || result[2] == 9 {
                return Err(Error::PatchResponse {
                    command: *b"PTCd",
                    raw: result,
                });
            }
        }
        self.task(*b"PTCc", &[], &mut result[..4])?;
        if result[2] != 0 || result[3] != 0 {
            return Err(Error::PatchResponse {
                command: *b"PTCc",
                raw: result,
            });
        }
        self.timer.delay_us(1_000_000);
        Ok(())
    }
    fn read_snapshot(&mut self) -> Result<Snapshot, Error> {
        let status = self.read32(STATUS)?;
        if status == u32::MAX {
            return Err(Error::InvalidRegister {
                register: STATUS,
                value: status,
            });
        }
        let data_status = self.read32(0x5f)?;
        if data_status == u32::MAX {
            return Err(Error::InvalidRegister {
                register: 0x5f,
                value: data_status,
            });
        }
        let mut power = [0; 2];
        self.read(0x3f, &mut power)?;
        let power_status = u16::from_le_bytes(power);
        let partner_identity = if status & 1 != 0 && (power_status >> 2) & 3 == 3 {
            let mut bytes = [0; 25];
            self.read(0x48, &mut bytes)?;
            Some(bytes)
        } else {
            None
        };
        Ok(Snapshot {
            status,
            data_status,
            power_status,
            partner_identity,
        })
    }
    /// Initializes only the generic TI family. Patch data is requested exactly
    /// for the observed vendor/version and platform-provided board/name.
    pub fn initialize(
        &mut self,
        provider: Option<&dyn Provider>,
        request: Option<FirmwareRequest<'_>>,
    ) -> Result<(), Error> {
        if self.fault.is_some() {
            return Err(Error::NeedsPlatformReset);
        }
        if self.ready {
            return Err(Error::InvalidArgument);
        }
        if !self.timer.supports_duration(1_000_000) {
            return Err(Error::TimerBudget {
                microseconds: 1_000_000,
            });
        }
        let result = self.initialize_inner(provider, request);
        result.map_err(|error| self.poison(error))
    }
    fn initialize_inner(
        &mut self,
        provider: Option<&dyn Provider>,
        request: Option<FirmwareRequest<'_>>,
    ) -> Result<(), Error> {
        let vendor = self.read32(0)?;
        if vendor == 0 || vendor == u32::MAX {
            return Err(Error::NoVendor(vendor));
        }
        let version = self.read32(0x0f)?;
        let event_bytes = match version >> 24 {
            0 => 8,
            0xf7 | 0xf9 => 11,
            _ => return Err(Error::UnsupportedVersion(version)),
        };
        let mode = self.read32(3)?.to_le_bytes();
        if &mode == b"PTCH" {
            let (Some(provider), Some(request)) = (provider, request) else {
                return Err(Error::FirmwareRequired { vendor, version });
            };
            let hardware = format!("vid-{vendor:08x}");
            let revision = format!("{version:08x}");
            let image = provider
                .load(Requirement {
                    name: request.name,
                    target: Target {
                        driver: "typec-tps6598x",
                        hardware: &hardware,
                        revision: &revision,
                        board: Some(request.board),
                    },
                    minimum_bytes: 1,
                })
                .map_err(Error::Firmware)?;
            self.apply_patch(image)?;
            let mode = self.read32(3)?.to_le_bytes();
            if &mode != b"APP " && &mode != b"APP1" {
                return Err(Error::Mode(mode));
            }
        } else if &mode != b"APP " && &mode != b"APP1" {
            return Err(Error::Mode(mode));
        }
        let system_configuration = self.read32(0x28)?;
        if system_configuration & 7 > 6 {
            return Err(Error::PortConfiguration(system_configuration));
        }
        self.identity = Some(Identity {
            vendor,
            version,
            system_configuration,
            event_bytes,
        });
        let snapshot = self.read_snapshot()?;
        self.write(0x16, &MASK.to_le_bytes())?;
        self.snapshot = Some(snapshot);
        self.ready = true;
        Ok(())
    }
    /// Poll the real event registers (or run after a deferred IRQ). Captured
    /// banks are acknowledged before sampling status, so a same-bit change
    /// during the sample remains latched for the next poll. No partial snapshot
    /// is published on failure; failed ACKs or later reads poison future work.
    pub fn poll(&mut self) -> Result<Option<Event>, Error> {
        self.check_ready()?;
        let result = self.poll_inner();
        result.map_err(|error| self.poison(error))
    }
    fn poll_inner(&mut self) -> Result<Option<Event>, Error> {
        let bytes = self.identity.ok_or(Error::NeedsInitialization)?.event_bytes;
        let mut first = [0; 11];
        let mut second = [0; 11];
        self.read(0x14, &mut first[..usize::from(bytes)])?;
        self.read(0x15, &mut second[..usize::from(bytes)])?;
        if first.iter().chain(second.iter()).all(|byte| *byte == 0) {
            return Ok(None);
        }
        self.write(0x18, &first[..usize::from(bytes)])?;
        self.write(0x19, &second[..usize::from(bytes)])?;
        let snapshot = self.read_snapshot()?;
        self.snapshot = Some(snapshot);
        Ok(Some(Event {
            first,
            second,
            bytes,
            snapshot,
        }))
    }
    pub fn request_data_role(&mut self, role: DataRole) -> Result<Snapshot, Error> {
        self.check_ready()?;
        let result = (|| {
            self.task(
                if role == DataRole::Host {
                    *b"SWDF"
                } else {
                    *b"SWUF"
                },
                &[],
                &mut [],
            )?;
            let snapshot = self.read_snapshot()?;
            self.snapshot = Some(snapshot);
            if snapshot.host() != (role == DataRole::Host) {
                return Err(Error::RoleMismatch {
                    status: snapshot.status,
                });
            }
            Ok(snapshot)
        })();
        self.finish_role_request(result)
    }
    pub fn request_power_role(&mut self, role: PowerRole) -> Result<Snapshot, Error> {
        self.check_ready()?;
        let result = (|| {
            self.task(
                if role == PowerRole::Source {
                    *b"SWSr"
                } else {
                    *b"SWSk"
                },
                &[],
                &mut [],
            )?;
            let snapshot = self.read_snapshot()?;
            self.snapshot = Some(snapshot);
            if snapshot.source() != (role == PowerRole::Source) {
                return Err(Error::RoleMismatch {
                    status: snapshot.status,
                });
            }
            Ok(snapshot)
        })();
        self.finish_role_request(result)
    }
    fn finish_role_request(&mut self, result: Result<Snapshot, Error>) -> Result<Snapshot, Error> {
        match result {
            Err(
                error @ (Error::Rejected { .. }
                | Error::TaskTimeout { .. }
                | Error::InvalidCommand(_)
                | Error::TaskResult { .. }
                | Error::RoleMismatch { .. }
                | Error::Busy(_)),
            ) => Err(error),
            Err(error) => Err(self.poison(error)),
            result => result,
        }
    }
    /// Disable event generation. Failure retains fault and requires platform
    /// reset; no shutdown success or release of controller ownership is implied.
    pub fn quiesce(&mut self) -> Result<(), Error> {
        self.check_ready()?;
        let result = self.write(0x16, &0u64.to_le_bytes());
        if let Err(error) = result {
            return Err(self.poison(error));
        }
        self.ready = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
