// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Endless Mobile, Inc.
//! Pinned btrtl USB register/ROM/security, exact-image download and version flow.
//! HCI synchronization, failure quarantine and owned observations are Stela glue.
use super::{
    Attempt, Configuration, ConfigurationEvidence, ContainerVersion, DownloadResponse, Error,
    Identity, LocalVersion, OwnedReport, Patch, Project, Result, UsbIdentity, V2Patch,
};
use crate::firmware::{ErrorKind as ResourceErrorKind, Provider, Requirement};
use crate::usb::bluetooth::{
    FirmwareReceipt, Hci, Io, Packet, State,
    command::{self, Response},
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
const READ_VERSION: u16 = 0x1001;
const READ_ADDRESS: u16 = 0x1009;
const REGISTER: u16 = 0xfc61;
const ROM: u16 = 0xfc6d;
const DOWNLOAD: u16 = 0xfc20;
const SUBVERSION: [u8; 5] = [0x10, 0x38, 4, 0x28, 0x80];
const REVISION: [u8; 5] = [0x10, 0x3a, 4, 0x28, 0x80];
const SECURITY: [u8; 5] = [0x10, 0xa4, 0xad, 0, 0xb0];
const COMMAND_US: u64 = 5_000_000;
const ATTEMPT_US: u64 = 120_000_000;

pub(super) fn run<B: Io>(hci: &mut Hci<B>, provider: &dyn Provider) -> Result<OwnedReport> {
    let usb = UsbIdentity::read(hci.binding.device());
    if usb.project().is_none() {
        return Err(Error::Unsupported("USB identity"));
    }
    hci.open()?;
    let deadline = hci.io.now_us().saturating_add(ATTEMPT_US);
    let mut engine = Engine {
        hci,
        pending: VecDeque::new(),
        deadline,
        attempt: Attempt::default(),
        credits: 1,
    };
    match engine.run(usb, provider) {
        Ok(r) => Ok(r),
        Err(cause) => {
            let cause = Error::Attempt {
                cause: Box::new(cause),
                observation: Box::new(engine.attempt),
            };
            if engine.hci.state() == State::Open
                && let Err(cleanup) = engine.hci.close()
            {
                return Err(Error::Cleanup {
                    cause: Box::new(cause),
                    cleanup,
                });
            }
            Err(cause)
        }
    }
}
struct Engine<'a, B: Io> {
    hci: &'a mut Hci<B>,
    pending: VecDeque<Vec<u8>>,
    deadline: u64,
    attempt: Attempt,
    /// HCI commands the controller will take now (one after reset).
    credits: u8,
}
impl<B: Io> Engine<'_, B> {
    fn command(&mut self, opcode: u16, parameters: &[u8]) -> Result<Vec<u8>> {
        if !self.pending.is_empty() {
            return Err(Error::protocol("stale command response", &self.pending[0]));
        }
        if self.hci.io.now_us() >= self.deadline {
            return Err(Error::Timeout("complete initialization attempt"));
        }
        let packet =
            command::packet(opcode, parameters).map_err(|why| Error::protocol(why, parameters))?;
        let deadline = core::cmp::min(
            self.deadline,
            self.hci.io.now_us().saturating_add(COMMAND_US),
        );
        let mut sent = false;
        loop {
            if !sent && self.credits > 0 {
                self.hci.submit_command(&packet)?;
                self.credits -= 1;
                sent = true;
            }
            for packet in self.hci.poll()? {
                match packet {
                    Packet::Event(e) => self.pending.push_back(e),
                    Packet::Acl(a) | Packet::Diagnostic(a) => {
                        return Err(Error::protocol("ACL while initializing firmware", &a));
                    }
                }
            }
            if self.pending.len() > 16 {
                return Err(Error::protocol("excess initialization events", &[]));
            }
            while let Some(e) = self.pending.pop_front() {
                match command::response(&e, opcode).map_err(|why| Error::protocol(why, &e))? {
                    Response::Credits(credits) => self.credits = credits,
                    Response::Complete { .. } | Response::Status { .. } if !sent => {
                        return Err(Error::protocol("command event before its command", &e));
                    }
                    Response::Complete { credits, returned } => {
                        self.credits = credits;
                        if returned[0] != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status: returned[0],
                                parameters: returned.to_vec(),
                            });
                        }
                        return Ok(returned.to_vec());
                    }
                    Response::Status { credits, status } => {
                        self.credits = credits;
                        if status != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status,
                                parameters: e[2..].to_vec(),
                            });
                        }
                    }
                    Response::Other => {
                        return Err(Error::protocol("unexpected initialization event", &e));
                    }
                }
            }
            if self.hci.io.now_us() >= deadline {
                return Err(Error::Timeout(if sent {
                    "genuine command completion"
                } else {
                    "genuine HCI command credits"
                }));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn register(&mut self, which: &[u8; 5]) -> Result<[u8; 2]> {
        let p = self.command(REGISTER, which)?;
        if p.len() != 3 {
            return Err(Error::protocol("register response length", &p));
        }
        Ok([p[1], p[2]])
    }
    fn run(&mut self, usb: UsbIdentity, provider: &dyn Provider) -> Result<OwnedReport> {
        let subversion = u16::from_le_bytes(self.register(&SUBVERSION)?);
        self.attempt.register_subversion = Some(subversion);
        let revision = if subversion == 0x8822 {
            let v = u16::from_le_bytes(self.register(&REVISION)?);
            self.attempt.register_revision = Some(v);
            Some(v)
        } else {
            None
        };
        let version = LocalVersion::parse(&self.command(READ_VERSION, &[])?)?;
        self.attempt.version = Some(version.clone());
        let rom = self.command(ROM, &[])?;
        if rom.len() != 2 {
            return Err(Error::protocol("ROM version response length", &rom));
        }
        self.attempt.rom_version = Some(rom[1]);
        let security = self.register(&SECURITY)?;
        self.attempt.security = Some(security);
        let identity = Identity::select(usb, version, subversion, revision, rom[1], security)?;
        self.attempt.identity = Some(identity.clone());
        let hardware = identity.usb.hardware_label();
        let revision = identity.revision_label();
        let target = identity.target(&hardware, &revision);
        // Both immutable requirements are observed before propagating any error.
        // A failed integrity/target/config parse is never optional absence.
        let firmware = provider.load(Requirement {
            name: identity.firmware_name(),
            target,
            minimum_bytes: if identity.project == Project::Rtl8852Bu {
                28
            } else {
                22
            },
        });
        let configuration = provider.load(Requirement {
            name: identity.configuration_name(),
            target,
            minimum_bytes: 6,
        });
        if let Ok(image) = firmware.as_ref() {
            self.attempt.firmware = Some(FirmwareReceipt::from(*image));
        }
        self.attempt.configuration = Some(
            configuration
                .as_ref()
                .map(|image| FirmwareReceipt::from(*image))
                .map_err(Clone::clone),
        );
        let firmware = firmware.map_err(Error::Resource)?;
        let (config, configuration) = match configuration {
            Ok(image) => (
                Some(Configuration::parse(image.bytes())?),
                ConfigurationEvidence::Supplied(image.into()),
            ),
            Err(error)
                if !identity.configuration_required()
                    && error.kind == ResourceErrorKind::Missing =>
            {
                (None, ConfigurationEvidence::OptionalMissing(error))
            }
            Err(error) => return Err(Error::Resource(error)),
        };
        let (container_version, stage) = if identity.project == Project::Rtl8852Bu {
            let patch = V2Patch::parse(
                firmware.bytes(),
                identity.project,
                identity.rom_version,
                identity.security[0],
            )?;
            let version = ContainerVersion::V2(patch.metadata.version);
            let stage = patch.stage(config.as_ref());
            self.attempt.v2 = Some(patch.metadata);
            (version, stage)
        } else {
            let patch = Patch::parse(firmware.bytes(), identity.project, identity.rom_version)?;
            (
                ContainerVersion::V1(patch.firmware_version),
                patch.stage(config.as_ref()),
            )
        };
        self.attempt.container_version = Some(container_version);
        for fragment in stage.fragments() {
            let mut p = Vec::with_capacity(fragment.data.len() + 1);
            p.push(fragment.index);
            p.extend_from_slice(fragment.data);
            let response = self.command(DOWNLOAD, &p)?;
            if response.len() != 2 {
                return Err(Error::protocol("download response length", &response));
            }
            self.attempt.download.push(DownloadResponse {
                sent_index: fragment.index,
                returned_index: response[1],
            });
        }
        // The donor uses the final download flag to transition the controller,
        // then rereads Local Version. It issues no separate/synthetic reset CC.
        let after = LocalVersion::parse(&self.command(READ_VERSION, &[])?)?;
        self.attempt.after = Some(after.clone());
        if after.manufacturer() != 0x005d
            || !(6..=14).contains(&after.hci_version())
            || !(6..=14).contains(&after.lmp_version())
            || after.lmp_subversion() == identity.version.lmp_subversion()
        {
            return Err(Error::protocol(
                "controller did not leave selected stock ROM firmware",
                &after.raw,
            ));
        }
        let p = self.command(READ_ADDRESS, &[])?;
        if p.len() != 7 {
            return Err(Error::protocol("BD_ADDR response length", &p));
        }
        let address: [u8; 6] = p[1..].try_into().unwrap();
        if address == [0; 6] || address == [0xff; 6] {
            return Err(Error::protocol("invalid controller address", &p));
        }
        Ok(OwnedReport {
            before: identity,
            after,
            address,
            firmware: Box::new(firmware.into()),
            configuration,
            container_version,
            v2: self.attempt.v2.take(),
            download: core::mem::take(&mut self.attempt.download),
        })
    }
}
