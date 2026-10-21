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
        let start = self.timer.now_us();
        loop {
            let value = self.read32(CMD)?;
            if value == INVALID_CMD {
                return Err(Error::InvalidCommand(command));
            }
            if self.timer.now_us().wrapping_sub(start) >= 1_000_000 {
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
    /// Poll the real event registers (or run after a deferred IRQ). Raw events
    /// and all status/identity reads are staged before either W1C. No partial
    /// snapshot is published on failure; uncertain ACKs poison future work.
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
        let snapshot = self.read_snapshot()?;
        self.write(0x18, &first[..usize::from(bytes)])?;
        self.write(0x19, &second[..usize::from(bytes)])?;
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
mod tests {
    extern crate std;
    use super::*;
    use crate::firmware::{Catalog, Provenance, Resource};
    use alloc::{boxed::Box, rc::Rc, vec::Vec};
    use core::cell::{Cell, RefCell};
    use sha2::{Digest, Sha256};

    struct Model {
        registers: Box<[[u8; 64]]>,
        lengths: [u8; 256],
        calls: usize,
        fail_at: usize,
        writes: Vec<(u8, Vec<u8>)>,
        commands: Vec<[u8; 4]>,
        patch: Vec<u8>,
        pending: Option<[u8; 4]>,
        busy: usize,
        hang: bool,
        invalid: bool,
        task_result: u8,
        second_result: u8,
        patch_fail: Option<[u8; 4]>,
        role_changes: bool,
    }
    impl Model {
        fn new(hardware: u8, mode: [u8; 4]) -> Self {
            let mut this = Self {
                registers: vec![[0; 64]; 256].into_boxed_slice(),
                lengths: [64; 256],
                calls: 0,
                fail_at: usize::MAX,
                writes: Vec::new(),
                commands: Vec::new(),
                patch: Vec::new(),
                pending: None,
                busy: 0,
                hang: false,
                invalid: false,
                task_result: 0,
                second_result: 0,
                patch_fail: None,
                role_changes: true,
            };
            this.set32(0, 0x451);
            this.set32(0x0f, (u32::from(hardware) << 24) | 0x1234);
            this.registers[3][..4].copy_from_slice(&mode);
            this.set32(0x28, 5);
            this.set32(STATUS, 0xe1);
            this.set32(0x5f, (1 << 8) | (1 << 16) | (1 << 5));
            this.registers[0x3f][..2].copy_from_slice(&12u16.to_le_bytes());
            this.registers[0x48][..25].fill(0x5a);
            this
        }
        fn set32(&mut self, register: u8, value: u32) {
            self.registers[usize::from(register)][..4].copy_from_slice(&value.to_le_bytes());
        }
        fn value(&self, register: u8) -> u32 {
            u32::from_le_bytes(
                self.registers[usize::from(register)][..4]
                    .try_into()
                    .unwrap(),
            )
        }
        fn complete(&mut self) {
            let Some(command) = self.pending.take() else {
                return;
            };
            let mut status = self.value(STATUS);
            if self.role_changes && self.task_result == 0 {
                match &command {
                    b"SWDF" => status |= 1 << 6,
                    b"SWUF" => status &= !(1 << 6),
                    b"SWSr" => status |= 1 << 5,
                    b"SWSk" => status &= !(1 << 5),
                    _ => {}
                }
            }
            if &command == b"PTCd" {
                let length = usize::from(self.lengths[usize::from(DATA)]);
                self.patch
                    .extend_from_slice(&self.registers[usize::from(DATA)][..length]);
            }
            self.registers[usize::from(DATA)].fill(0);
            self.registers[usize::from(DATA)][0] = self.task_result;
            self.registers[usize::from(DATA)][1] = self.second_result;
            if self.patch_fail == Some(command) {
                match &command {
                    b"PTCs" => self.registers[usize::from(DATA)][1] = 0x80,
                    b"PTCd" => self.registers[usize::from(DATA)][2] = 9,
                    b"PTCc" => self.registers[usize::from(DATA)][3] = 1,
                    _ => {}
                }
            } else if &command == b"PTCc" {
                self.registers[3][..4].copy_from_slice(b"APP ");
            }
            self.lengths[usize::from(DATA)] = 64;
            self.set32(STATUS, status);
            self.set32(CMD, 0);
        }
    }
    #[derive(Clone)]
    struct Device(Rc<RefCell<Model>>);
    impl Bus for Device {
        fn transaction(
            &mut self,
            address: Address,
            operations: &mut [Operation<'_>],
        ) -> Result<(), i2c::Error> {
            assert_eq!(address, Address::SevenBit(0x38));
            let mut model = self.0.borrow_mut();
            model.calls += 1;
            if model.fail_at == model.calls {
                return Err(i2c::ErrorKind::Aborted {
                    kind: i2c::AbortKind::DataNack,
                    source: 0x4321,
                }
                .into());
            }
            match operations {
                [Operation::Write(request), Operation::Read(response)] => {
                    assert_eq!(request.len(), 1);
                    let register = request[0];
                    assert!((2..=65).contains(&response.len()));
                    if register == CMD && model.pending.is_some() && !model.hang {
                        if model.invalid {
                            model.pending = None;
                            model.set32(CMD, INVALID_CMD);
                        } else if model.busy == 0 {
                            model.complete();
                        } else {
                            model.busy -= 1;
                        }
                    }
                    response[0] = model.lengths[usize::from(register)];
                    let bytes = response.len() - 1;
                    response[1..].copy_from_slice(&model.registers[usize::from(register)][..bytes]);
                }
                [Operation::Write(request)] => {
                    assert!(request.len() >= 3);
                    let register = request[0];
                    let bytes = &request[2..];
                    assert_eq!(usize::from(request[1]), bytes.len());
                    model.writes.push((register, bytes.to_vec()));
                    if register == 0x18 || register == 0x19 {
                        for (index, byte) in bytes.iter().enumerate() {
                            model.registers[usize::from(register - 4)][index] &= !byte;
                        }
                    } else {
                        model.registers[usize::from(register)][..bytes.len()]
                            .copy_from_slice(bytes);
                        model.lengths[usize::from(register)] = bytes.len() as u8;
                    }
                    if register == CMD {
                        let command = bytes.try_into().unwrap();
                        model.commands.push(command);
                        model.pending = Some(command);
                        model.busy = 2;
                    }
                }
                _ => panic!(
                    "TI register protocol needs a length-prefixed single write or atomic repeated-start read"
                ),
            }
            Ok(())
        }
    }
    #[derive(Default)]
    struct Time(Cell<u64>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn delay_us(&self, us: u64) {
            self.0.set(self.0.get().wrapping_add(us));
        }
    }
    fn make_controller(
        hardware: u8,
        mode: [u8; 4],
    ) -> (Tps6598x<Device, Time>, Rc<RefCell<Model>>) {
        let model = Rc::new(RefCell::new(Model::new(hardware, mode)));
        (
            Tps6598x::new(
                Device(model.clone()),
                Address::SevenBit(0x38),
                Time::default(),
            ),
            model,
        )
    }
    fn initialized(hardware: u8) -> (Tps6598x<Device, Time>, Rc<RefCell<Model>>) {
        let (mut controller, model) = make_controller(hardware, *b"APP ");
        controller.initialize(None, None).unwrap();
        (controller, model)
    }
    fn catalog(bytes: Vec<u8>, hardware: u8) -> Catalog {
        let revision = format!("{:08x}", (u32::from(hardware) << 24) | 0x1234);
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        Catalog::from_handoff(vec![Resource {
            name: "ti/board.bin",
            target: Target {
                driver: "typec-tps6598x",
                hardware: "vid-00000451",
                revision: &revision,
                board: Some("test-board"),
            },
            provenance: Provenance {
                source: "synthetic-stateful-model",
                revision: "1",
                member: "board.bin",
                license: "MIT",
            },
            expected_length: bytes.len(),
            expected_sha256: digest,
            bytes,
        }])
        .unwrap()
    }

    #[test]
    fn supported_silicon_initializes_and_observes_pd_identity_and_connection_state() {
        for hardware in [0, 0xf7, 0xf9] {
            let (controller, model) = initialized(hardware);
            assert!(controller.ready());
            let identity = controller.identity().unwrap();
            assert_eq!(identity.event_bytes, if hardware == 0 { 8 } else { 11 });
            let snapshot = controller.snapshot().unwrap();
            assert!(snapshot.connected());
            assert!(snapshot.host());
            assert!(snapshot.source());
            assert!(snapshot.vconn_source());
            assert!(snapshot.pd());
            assert!(snapshot.displayport());
            assert!(snapshot.thunderbolt());
            assert_eq!(snapshot.partner_identity, Some([0x5a; 25]));
            assert_eq!(model.borrow().value(0x16), MASK as u32);
        }
    }
    #[test]
    fn actual_roles_are_verified_and_partner_rejection_does_not_poison_idle_controller() {
        let (mut controller, model) = initialized(0xf7);
        assert!(
            !controller
                .request_data_role(DataRole::Device)
                .unwrap()
                .host()
        );
        assert!(
            !controller
                .request_power_role(PowerRole::Sink)
                .unwrap()
                .source()
        );
        let old = controller.snapshot();
        model.borrow_mut().task_result = 3;
        assert_eq!(
            controller.request_power_role(PowerRole::Source),
            Err(Error::Rejected { command: *b"SWSr" })
        );
        assert_eq!(controller.snapshot(), old);
        assert!(controller.ready());
        model.borrow_mut().task_result = 0;
        model.borrow_mut().role_changes = false;
        assert!(matches!(
            controller.request_data_role(DataRole::Host),
            Err(Error::RoleMismatch { .. })
        ));
        assert!(controller.ready());
        assert!(!controller.snapshot().unwrap().host());
        model.borrow_mut().role_changes = true;
        assert!(controller.request_data_role(DataRole::Host).unwrap().host());
    }
    #[test]
    fn firmware_upload_uses_verified_exact_resource_chunks_and_requires_actual_app_mode() {
        for bytes in [vec![0x5a; 1], (0..=255).collect(), vec![0x91; 257]] {
            let (mut controller, model) = make_controller(0xf9, *b"PTCH");
            let catalog = catalog(bytes.clone(), 0xf9);
            controller
                .initialize(
                    Some(&catalog),
                    Some(FirmwareRequest {
                        name: "ti/board.bin",
                        board: "test-board",
                    }),
                )
                .unwrap();
            drop(catalog);
            assert!(controller.ready());
            assert_eq!(model.borrow().patch, bytes);
            let receipt = controller.patch().unwrap();
            assert_eq!(receipt.length, bytes.len());
            assert_eq!(receipt.sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
            assert_eq!(receipt.name, "ti/board.bin");
            assert_eq!(receipt.target_board.as_deref(), Some("test-board"));
            let commands = &model.borrow().commands;
            assert_eq!(commands.first(), Some(b"PTCs"));
            assert_eq!(commands.last(), Some(b"PTCc"));
            assert_eq!(
                commands
                    .iter()
                    .filter(|command| *command == b"PTCd")
                    .count(),
                bytes.len().div_ceil(64)
            );
            assert!(controller.timer.now_us() >= 1_000_000);
        }
    }
    #[test]
    fn each_patch_protocol_failure_retains_owned_evidence_and_refuses_retry() {
        for command in [*b"PTCs", *b"PTCd", *b"PTCc"] {
            let (mut controller, model) = make_controller(0, *b"PTCH");
            model.borrow_mut().patch_fail = Some(command);
            let catalog = catalog(vec![0x5a; 65], 0);
            assert!(matches!(
                controller.initialize(
                    Some(&catalog),
                    Some(FirmwareRequest {
                        name: "ti/board.bin",
                        board: "test-board"
                    })
                ),
                Err(Error::PatchResponse { .. })
            ));
            drop(catalog);
            assert_eq!(controller.patch().unwrap().length, 65);
            assert!(!controller.ready());
            let calls = model.borrow().calls;
            assert_eq!(
                controller.initialize(None, None),
                Err(Error::NeedsPlatformReset)
            );
            assert_eq!(model.borrow().calls, calls);
        }
    }
    #[test]
    fn missing_wrong_firmware_and_unsupported_silicon_or_modes_do_not_initialize() {
        let (mut controller, _) = make_controller(0, *b"PTCH");
        assert!(matches!(
            controller.initialize(None, None),
            Err(Error::FirmwareRequired { .. })
        ));
        let (mut controller, model) = make_controller(0, *b"PTCH");
        let catalog = catalog(vec![1], 0xf7);
        assert!(matches!(
            controller.initialize(
                Some(&catalog),
                Some(FirmwareRequest {
                    name: "ti/board.bin",
                    board: "test-board"
                })
            ),
            Err(Error::Firmware(_))
        ));
        assert!(model.borrow().commands.is_empty());
        for mode in [*b"BOOT", *b"BIST", *b"DISC", *b"XXXX"] {
            let (mut controller, _) = make_controller(0, mode);
            assert_eq!(controller.initialize(None, None), Err(Error::Mode(mode)));
        }
        let (mut controller, _) = make_controller(0x12, *b"APP ");
        assert!(matches!(
            controller.initialize(None, None),
            Err(Error::UnsupportedVersion(_))
        ));
    }
    #[test]
    fn event_width_w1c_and_detach_publish_only_after_complete_observation() {
        for hardware in [0, 0xf7, 0xf9] {
            let (mut controller, model) = initialized(hardware);
            assert_eq!(controller.poll().unwrap(), None);
            {
                let mut model = model.borrow_mut();
                model.registers[0x14][0] = 8;
                model.registers[0x15][7] = 0x80;
                if hardware != 0 {
                    model.registers[0x14][10] = 1;
                }
                model.set32(STATUS, 0);
                model.set32(0x5f, 0);
                model.registers[0x3f][..2].fill(0);
            }
            let event = controller.poll().unwrap().unwrap();
            assert!(!event.snapshot.connected());
            assert_eq!(event.snapshot.partner_identity, None);
            assert_eq!(event.first[0], 8);
            assert_eq!(event.second[7], 0x80);
            let model = model.borrow();
            let acks: Vec<_> = model
                .writes
                .iter()
                .filter(|(register, _)| matches!(register, 0x18 | 0x19))
                .collect();
            assert_eq!(acks.len(), 2);
            assert_eq!(acks[0].1.len(), usize::from(event.bytes));
            assert!(
                model.registers[0x14][..usize::from(event.bytes)]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
    #[test]
    fn every_event_read_and_ack_failure_preserves_old_public_snapshot_and_blocks_replay() {
        let (mut baseline, model) = initialized(0xf7);
        model.borrow_mut().registers[0x14][0] = 8;
        let first = model.borrow().calls + 1;
        baseline.poll().unwrap();
        let last = model.borrow().calls;
        for fail_at in first..=last {
            let (mut controller, model) = initialized(0xf7);
            let old = controller.snapshot();
            model.borrow_mut().registers[0x14][0] = 8;
            model.borrow_mut().fail_at = fail_at;
            assert!(matches!(controller.poll(), Err(Error::I2c { .. })));
            assert_eq!(controller.snapshot(), old);
            assert!(!controller.ready());
            let calls = model.borrow().calls;
            assert!(controller.poll().is_err());
            assert_eq!(model.borrow().calls, calls);
        }
    }
    #[test]
    fn short_length_invalid_task_and_unresolved_task_are_explicit() {
        let (mut controller, model) = initialized(0);
        model.borrow_mut().lengths[usize::from(STATUS)] = 1;
        assert!(matches!(
            controller.request_data_role(DataRole::Device),
            Err(Error::InvalidLength { .. })
        ));
        assert!(!controller.ready());
        let (mut controller, model) = initialized(0);
        model.borrow_mut().invalid = true;
        assert_eq!(
            controller.request_data_role(DataRole::Device),
            Err(Error::InvalidCommand(*b"SWUF"))
        );
        assert!(controller.ready());
        let (mut controller, model) = initialized(0);
        model.borrow_mut().hang = true;
        assert_eq!(
            controller.request_data_role(DataRole::Device),
            Err(Error::Timeout { command: *b"SWUF" })
        );
        assert!(!controller.ready());
        let calls = model.borrow().calls;
        assert!(controller.request_data_role(DataRole::Device).is_err());
        assert_eq!(model.borrow().calls, calls);
    }
    #[test]
    fn quiesce_disables_real_events_and_all_initialization_io_errors_are_explicit() {
        let (mut baseline, model) = initialized(0);
        let calls = model.borrow().calls;
        baseline.quiesce().unwrap();
        assert!(!baseline.ready());
        assert_eq!(model.borrow().value(0x16), 0);
        for fail_at in 1..=calls {
            let (mut controller, model) = make_controller(0, *b"APP ");
            model.borrow_mut().fail_at = fail_at;
            assert!(matches!(
                controller.initialize(None, None),
                Err(Error::I2c { .. })
            ));
            assert!(!controller.ready());
            let calls = model.borrow().calls;
            assert!(controller.initialize(None, None).is_err());
            assert_eq!(model.borrow().calls, calls);
        }
    }

    #[test]
    fn unknown_task_results_and_failed_register_words_never_look_successful() {
        let (mut controller, model) = initialized(0);
        model.borrow_mut().task_result = 0xff;
        let old = controller.snapshot();
        assert_eq!(
            controller.request_data_role(DataRole::Device),
            Err(Error::TaskResult {
                command: *b"SWUF",
                status: 0xff
            })
        );
        assert_eq!(controller.snapshot(), old);
        assert!(controller.ready());
        let (mut controller, model) = make_controller(0, *b"APP ");
        model.borrow_mut().set32(STATUS, u32::MAX);
        assert_eq!(
            controller.initialize(None, None),
            Err(Error::InvalidRegister {
                register: STATUS,
                value: u32::MAX
            })
        );
        assert!(!controller.ready());
    }
    #[test]
    fn every_role_io_failure_preserves_old_observation_and_blocks_uncertain_replay() {
        let (mut baseline, model) = initialized(0xf9);
        let first = model.borrow().calls + 1;
        baseline.request_data_role(DataRole::Device).unwrap();
        let last = model.borrow().calls;
        for fail_at in first..=last {
            let (mut controller, model) = initialized(0xf9);
            let old = controller.snapshot();
            model.borrow_mut().fail_at = fail_at;
            assert!(matches!(
                controller.request_data_role(DataRole::Device),
                Err(Error::I2c { .. })
            ));
            assert_eq!(controller.snapshot(), old);
            assert!(!controller.ready());
            let calls = model.borrow().calls;
            assert!(controller.request_data_role(DataRole::Device).is_err());
            assert_eq!(model.borrow().calls, calls);
        }
    }
    #[test]
    #[ignore = "requires pinned unchanged Linux discrete Type-C C oracle trace"]
    fn unchanged_linux_tps_block_and_task_oracle() {
        let path = std::env::var("STELA_TYPEC_DISCRETE_ORACLE")
            .expect("STELA_TYPEC_DISCRETE_ORACLE trace path");
        let trace = std::fs::read_to_string(path).unwrap();
        let mut blocks = 0;
        let mut tasks = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            match fields[0] {
                "B" => {
                    let length: usize = fields[1].parse().unwrap();
                    assert_eq!(fields[2], "0");
                    assert_eq!(fields[3], "0");
                    let (mut controller, model) = make_controller(0, *b"APP ");
                    for (index, byte) in model.borrow_mut().registers[0x40].iter_mut().enumerate() {
                        *byte = index as u8;
                    }
                    let mut read = vec![0; length];
                    controller.read(0x40, &mut read).unwrap();
                    controller.write(0x40, &read).unwrap();
                    let model = model.borrow();
                    let wire = &model.writes.last().unwrap().1;
                    assert_eq!(wire.len() + 1, fields[4].parse::<usize>().unwrap());
                    assert_eq!(wire.len(), fields[5].parse::<usize>().unwrap());
                    assert_eq!(read[length - 1], fields[6].parse::<u8>().unwrap());
                    assert_eq!(wire[length - 1], fields[7].parse::<u8>().unwrap());
                    blocks += 1;
                }
                "T" => {
                    let kind: u8 = fields[1].parse().unwrap();
                    let expected: i32 = fields[2].parse().unwrap();
                    let (mut controller, model) = make_controller(0, *b"APP ");
                    {
                        let mut model = model.borrow_mut();
                        model.second_result = 0x42;
                        match kind {
                            0 => {}
                            1 => model.set32(CMD, 0x12345678),
                            2 => model.invalid = true,
                            3 => model.hang = true,
                            4 => model.task_result = 1,
                            5 => model.task_result = 3,
                            _ => panic!("unknown task oracle case"),
                        }
                    }
                    let mut bytes = [0xaa; 2];
                    let result = controller.task(*b"SWUF", &[1, 2, 3], &mut bytes);
                    match (expected, result) {
                        (0, Ok(())) => {
                            assert_eq!(bytes[0], fields[5].parse::<u8>().unwrap());
                            assert_eq!(bytes[1], fields[6].parse::<u8>().unwrap());
                        }
                        (-16, Err(Error::Busy(_)))
                        | (-22, Err(Error::InvalidCommand(_)))
                        | (-110, Err(Error::Timeout { .. } | Error::TaskTimeout { .. }))
                        | (-1, Err(Error::Rejected { .. })) => assert_eq!(bytes, [0xaa; 2]),
                        (_, other) => panic!("Linux task {expected}, Stela {other:?}"),
                    }
                    let model = model.borrow();
                    assert_eq!(model.commands.len(), fields[3].parse::<usize>().unwrap());
                    assert_eq!(
                        model.writes.iter().filter(|write| write.0 == DATA).count(),
                        fields[4].parse::<usize>().unwrap()
                    );
                    tasks += 1;
                }
                "C" => {}
                _ => panic!("unknown oracle record"),
            }
        }
        assert_eq!(blocks, 64);
        assert_eq!(tasks, 6);
    }
}
