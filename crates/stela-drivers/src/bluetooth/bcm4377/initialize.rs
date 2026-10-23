// SPDX-License-Identifier: MIT AND GPL-2.0-only
// Copyright (C) The Asahi Linux Contributors
// Copyright (C) 2021 Intel Corporation
// Copyright 2023 NXP
//! Source calibration/PTB and the generic firmware-node address setup boundary.
//! hci_bcm4377.c supplies MIT command/variant semantics; hci_sync.c supplies
//! GPL-2.0 property-address setup semantics. No Linux execution is required.
use super::*;
use crate::bluetooth::hci::{self, Response};
use sha2::{Digest, Sha256};

const CALIBRATION: &str = "brcm,taurus-cal-blob";
const BEAMFORMING: &str = "brcm,taurus-bf-cal-blob";
const ADDRESS: &str = "local-bd-address";
const CALIBRATION_OPCODE: u16 = 0xfd97;
const PTB_4377: u16 = 0xfd98;
const PTB_CHUNK: u16 = 0xfe0d;
const READ_ADDRESS: u16 = 0x1009;
const SET_ADDRESS: u16 = 0xfc01;
const COMMAND_US: u64 = 10_000_000;
const ATTEMPT_US: u64 = 120_000_000;
const PROPERTY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InitializationStage {
    #[default]
    Boot,
    Calibration,
    Ptb,
    ReadAddress,
    SetAddress,
    VerifyAddress,
    Complete,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyReceipt {
    pub name: &'static str,
    /// Original actual firmware-node property bytes, without normalization.
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropertyDiagnostic {
    Missing {
        name: &'static str,
    },
    Unavailable {
        name: &'static str,
    },
    /// Exact original length/hash, with no truncated raw value represented as
    /// a complete property and no >budget duplicate retained in the attempt.
    Rejected {
        name: &'static str,
        bytes: usize,
        sha256: [u8; 32],
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandReceipt {
    pub opcode: u16,
    pub packet_bytes: usize,
    /// Exact full packet hash computed before its publication attempt.
    pub packet_sha256: [u8; 32],
    /// None after a refused or uncertain effect; never guessed from an ACK.
    pub submission: Option<Submission>,
    /// Actual HCI return parameters, starting with status. Packet-transfer ACKs
    /// cannot populate this field. Original raw events remain in observations.
    pub returned: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PtbDisposition {
    Accepted,
    /// The donor deliberately ignores BCM4377 PTB status rejection. Retain it
    /// explicitly; this is not evidence of accepted regulatory/calibration data.
    Rejected {
        status: u8,
        returned: Vec<u8>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quirks {
    pub broken_extended_scan: bool,
    pub broken_mws_configuration: bool,
    pub broken_le_coded: bool,
    pub broken_extended_advertising_report_phy: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub chip: Chip,
    pub address: [u8; 6],
    pub property_address_applied: bool,
    pub ptb: PtbDisposition,
    /// Source feature/report quirks for subsequent host/guest HCI integration.
    /// This transport does not silently alter the original event bytes.
    pub quirks: Quirks,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Initialization {
    pub stage: InitializationStage,
    pub calibration: Option<PropertyReceipt>,
    pub property_diagnostics: Vec<PropertyDiagnostic>,
    pub ptb: Option<FirmwareReceipt>,
    pub ptb_disposition: Option<PtbDisposition>,
    pub address_property: Option<PropertyReceipt>,
    pub observed_address: Option<[u8; 6]>,
    pub verified_address: Option<[u8; 6]>,
    pub commands: Vec<CommandReceipt>,
    pub report: Option<Report>,
}
struct Engine<'a, P: Platform> {
    transport: &'a mut Transport<P>,
    deadline: u64,
    credits: u8,
    cursor: usize,
}
impl<P: Platform> Transport<P> {
    pub(super) fn initialize_inner(&mut self, provider: &dyn Provider) -> Result<Report> {
        self.snapshot.initialization = Some(Initialization::default());
        let deadline = self.platform().now_us().saturating_add(ATTEMPT_US);
        self.initialization_deadline = Some(deadline);
        self.start_inner(provider)?;
        Engine {
            transport: self,
            deadline,
            credits: 1,
            cursor: 0,
        }
        .run(provider)
    }
}
impl<P: Platform> Engine<'_, P> {
    fn attempt(&mut self) -> &mut Initialization {
        self.transport.snapshot.initialization.as_mut().unwrap()
    }
    fn bounded(&mut self, command: u64) -> Result<()> {
        let now = self.transport.platform().now_us();
        if now >= self.deadline {
            return Err(Error::Timeout(
                "complete Broadcom controller initialization",
            ));
        }
        if now >= command {
            return Err(Error::Timeout("actual Broadcom HCI response or credits"));
        }
        Ok(())
    }
    fn property(&mut self, name: &'static str) -> Result<PropertyReceipt> {
        self.bounded(self.deadline)?;
        let bytes = match self.transport.platform().property(name) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                self.attempt()
                    .property_diagnostics
                    .push(PropertyDiagnostic::Missing { name });
                self.bounded(self.deadline)?;
                return Err(Error::Unsupported(
                    "actual board-bound Broadcom firmware property",
                ));
            }
            Err(error) => {
                self.attempt()
                    .property_diagnostics
                    .push(PropertyDiagnostic::Unavailable { name });
                return Err(error);
            }
        };
        let sha256 = Sha256::digest(&bytes).into();
        // Record observed rejected metadata before either budget or shape
        // refusal. Original admitted bytes are stored by the calling stage.
        if bytes.is_empty() || bytes.len() > PROPERTY_BYTES {
            self.attempt()
                .property_diagnostics
                .push(PropertyDiagnostic::Rejected {
                    name,
                    bytes: bytes.len(),
                    sha256,
                });
            self.bounded(self.deadline)?;
            return Err(Error::Unsupported(
                "bounded nonempty Broadcom firmware property",
            ));
        }
        Ok(PropertyReceipt {
            name,
            sha256,
            bytes,
        })
    }
    fn command(&mut self, opcode: u16, parameters: &[u8]) -> Result<Vec<u8>> {
        self.bounded(self.deadline)?;
        let packet = hci::packet(opcode, parameters).map_err(|requirement| Error::Hci {
            requirement,
            bytes: parameters.into(),
        })?;
        let deadline = self
            .transport
            .platform()
            .now_us()
            .saturating_add(COMMAND_US);
        self.attempt().commands.push(CommandReceipt {
            opcode,
            packet_bytes: packet.len(),
            packet_sha256: Sha256::digest(&packet).into(),
            submission: None,
            returned: None,
        });
        let mut sent = false;
        loop {
            self.bounded(deadline)?;
            self.transport.service()?;
            let mut completed = None;
            // All actual packets remain in the transport-owned transcript on
            // every exit, including a later malformed event or MMIO failure.
            while self.cursor < self.transport.observations.packets.len() {
                let packet = &self.transport.observations.packets[self.cursor];
                self.cursor += 1;
                if packet.kind != Kind::Event {
                    continue;
                }
                let bytes = packet.bytes.clone();
                match hci::response(&bytes, opcode).map_err(|requirement| Error::Hci {
                    requirement,
                    bytes: bytes.clone(),
                })? {
                    Response::Credits(credits) => self.credits = credits,
                    Response::Complete { .. } | Response::Status { .. }
                        if !sent || completed.is_some() =>
                    {
                        return Err(Error::Hci {
                            requirement: "serialized nonduplicate Broadcom HCI response after actual publication",
                            bytes,
                        });
                    }
                    Response::Complete { credits, returned } => {
                        self.credits = credits;
                        self.attempt().commands.last_mut().unwrap().returned =
                            Some(returned.into());
                        completed = Some(returned.to_vec());
                    }
                    Response::Status { credits, status } => {
                        self.credits = credits;
                        if status != 0 {
                            let returned = bytes[2..].to_vec();
                            self.attempt().commands.last_mut().unwrap().returned =
                                Some(returned.clone());
                            completed = Some(returned);
                        }
                    }
                    Response::Other => {}
                }
            }
            self.bounded(deadline)?;
            if let Some(returned) = completed {
                return Ok(returned);
            }
            if !sent && self.credits != 0 {
                // The preceding drain rejects already-observed unsolicited
                // responses. Publish directly so no hidden pre-send service
                // can relabel an old event as a response to this new command.
                self.bounded(deadline)?;
                let submission = self.transport.enqueue_ring(1, &packet)?;
                self.attempt().commands.last_mut().unwrap().submission = Some(submission);
                self.credits -= 1;
                sent = true;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn accepted(&mut self, opcode: u16, parameters: &[u8]) -> Result<Vec<u8>> {
        let returned = self.command(opcode, parameters)?;
        if returned[0] != 0 {
            return Err(Error::Controller {
                opcode,
                status: returned[0],
                returned,
            });
        }
        Ok(returned)
    }
    fn run(&mut self, provider: &dyn Provider) -> Result<Report> {
        self.bounded(self.deadline)?;
        let chip = self.transport.chip;
        self.attempt().stage = InitializationStage::Calibration;
        if chip != Chip::Bcm4377 {
            let stepping = self.transport.identity.as_ref().unwrap().stepping.as_str();
            let beamforming = match chip {
                Chip::Bcm4378 => matches!(stepping, "b1" | "b3"),
                Chip::Bcm4387 => stepping == "c2",
                Chip::Bcm4388 => true,
                Chip::Bcm4377 => unreachable!(),
            };
            let property = self.property(if beamforming {
                BEAMFORMING
            } else {
                CALIBRATION
            })?;
            let count = property.bytes.len().div_ceil(230);
            self.attempt().calibration = Some(property);
            self.bounded(self.deadline)?;
            for index in 0..count {
                let mut parameters = [0; 233];
                parameters[0] = 3;
                parameters[1..3].copy_from_slice(&((count - index - 1) as u16).to_le_bytes());
                let original = &self
                    .transport
                    .snapshot
                    .initialization
                    .as_ref()
                    .unwrap()
                    .calibration
                    .as_ref()
                    .unwrap()
                    .bytes;
                let chunk = &original[index * 230..original.len().min((index + 1) * 230)];
                parameters[3..3 + chunk.len()].copy_from_slice(chunk);
                self.accepted(CALIBRATION_OPCODE, &parameters)?;
            }
        }
        self.attempt().stage = InitializationStage::Ptb;
        let image = self.transport.load_named(provider, "ptb")?;
        self.attempt().ptb = Some(image.into());
        self.bounded(self.deadline)?;
        if image.bytes().len() > PROPERTY_BYTES {
            return Err(Error::Unsupported(
                "Broadcom PTB exceeds declared 4MiB budget",
            ));
        }
        let disposition = if chip == Chip::Bcm4377 {
            let returned = self.command(PTB_4377, image.bytes())?;
            if returned[0] == 0 {
                PtbDisposition::Accepted
            } else {
                PtbDisposition::Rejected {
                    status: returned[0],
                    returned,
                }
            }
        } else {
            let count = image.bytes().len().div_ceil(207);
            for (index, chunk) in image.bytes().chunks(207).enumerate() {
                let mut parameters = [0; 209];
                parameters[..2].copy_from_slice(&((count - index - 1) as u16).to_le_bytes());
                parameters[2..2 + chunk.len()].copy_from_slice(chunk);
                self.accepted(PTB_CHUNK, &parameters)?;
            }
            PtbDisposition::Accepted
        };
        self.attempt().ptb_disposition = Some(disposition.clone());
        self.attempt().stage = InitializationStage::ReadAddress;
        let observed = self.read_address()?;
        self.attempt().observed_address = Some(observed);
        let mut address = observed;
        let mut applied = false;
        if !valid_address(chip, observed) {
            let property = self.property(ADDRESS)?;
            self.attempt().address_property = Some(property.clone());
            self.bounded(self.deadline)?;
            let selected: [u8; 6] = property.bytes.as_slice().try_into().map_err(|_| {
                Error::Unsupported("exact six-byte actual Broadcom address property")
            })?;
            if !valid_address(chip, selected) {
                return Err(Error::Unsupported(
                    "nonplaceholder actual Broadcom address property",
                ));
            }
            self.attempt().stage = InitializationStage::SetAddress;
            self.accepted(SET_ADDRESS, &selected)?;
            self.attempt().stage = InitializationStage::VerifyAddress;
            address = self.read_address()?;
            if address != selected {
                return Err(Error::Hci {
                    requirement: "actual Broadcom address readback equals the original property",
                    bytes: address.into(),
                });
            }
            applied = true;
        }
        self.bounded(self.deadline)?;
        self.attempt().verified_address = Some(address);
        let report = Report {
            chip,
            address,
            property_address_applied: applied,
            ptb: disposition,
            quirks: Quirks {
                broken_extended_scan: chip == Chip::Bcm4377,
                broken_mws_configuration: chip != Chip::Bcm4377,
                broken_le_coded: chip != Chip::Bcm4377,
                broken_extended_advertising_report_phy: chip != Chip::Bcm4377,
            },
        };
        self.attempt().stage = InitializationStage::Complete;
        self.attempt().report = Some(report.clone());
        Ok(report)
    }
    fn read_address(&mut self) -> Result<[u8; 6]> {
        let returned = self.accepted(READ_ADDRESS, &[])?;
        if returned.len() != 7 {
            return Err(Error::Hci {
                requirement: "exact Broadcom Read BD_ADDR return length",
                bytes: returned,
            });
        }
        Ok(returned[1..].try_into().unwrap())
    }
}
fn valid_address(chip: Chip, address: [u8; 6]) -> bool {
    address != [0; 6]
        && address != [0xff; 6]
        && !(address[..3] == [0x93, 0x76, 0] && address[4..] == chip.number().to_le_bytes())
}
