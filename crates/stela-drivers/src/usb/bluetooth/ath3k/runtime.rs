// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! Source ATH3012 post-rebind setup plus independently observed standard HCI
//! initialization. The raw uploader never constructs or upgrades this owner.
use crate::{
    firmware::Provider,
    usb::bluetooth::{
        self, Hci, Io, Packet, State,
        command::{self, Response},
        qca,
    },
};
use alloc::{boxed::Box, vec::Vec};
type Result<T> = core::result::Result<T, Error>;
const COMMAND_US: u64 = 5_000_000;
const ATTEMPT_US: u64 = 120_000_000;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub vendor_version: Option<qca::Version>,
    pub dfu: Option<Box<qca::OwnedReport>>,
    pub local_version: Option<[u8; 8]>,
    pub address: Option<[u8; 6]>,
    pub pending_command: Option<u16>,
    pub completed_commands: Vec<u16>,
    pub asynchronous: Vec<Packet>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirmwareEvidence {
    /// Donor treats unknown ROMs with nonzero upper bits as not requiring DFU.
    /// Actual vendor version and later HCI responses are retained, but the
    /// running image/provenance/authentication are unknown.
    RunningUnknown,
    Dfu(Box<qca::OwnedReport>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPolicy {
    pub simultaneous_discovery: bool,
    pub strict_duplicate_filter: bool,
    pub broken_enhanced_setup_sync_conn: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedReport {
    pub usb: super::UsbIdentity,
    pub vendor_version: qca::Version,
    pub firmware: FirmwareEvidence,
    pub local_version: [u8; 8],
    pub address: [u8; 6],
    pub completed_commands: Vec<u16>,
    pub asynchronous: Vec<Packet>,
    pub policy: HostPolicy,
}
#[derive(Debug)]
pub enum Error {
    Unsupported(&'static str),
    Protocol {
        requirement: &'static str,
        observed: Vec<u8>,
    },
    Usb(crate::block::BlockError),
    Transport(bluetooth::Error),
    Dfu(Box<qca::Error>),
    Controller {
        opcode: u16,
        status: u8,
        observed: Vec<u8>,
    },
    Timeout,
    Attempt {
        cause: Box<Error>,
        observation: Box<Attempt>,
    },
    Cleanup {
        cause: Box<Error>,
        cleanup: bluetooth::Error,
    },
}
impl Error {
    fn protocol(requirement: &'static str, observed: &[u8]) -> Self {
        Self::Protocol {
            requirement,
            observed: observed.to_vec(),
        }
    }
}
impl From<bluetooth::Error> for Error {
    fn from(e: bluetooth::Error) -> Self {
        Self::Transport(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ATH3012 runtime initialization {self:?}")
    }
}
impl core::error::Error for Error {}
/// Initialize only an actual source-listed bcdDevice>1 standard HCI attachment.
/// Raw upload evidence does not authorize this entry point or infer readiness.
pub fn initialize<B: Io>(hci: &mut Hci<B>, provider: &dyn Provider) -> Result<OwnedReport> {
    if !super::is_runtime_candidate(hci.binding.device()) {
        return Err(Error::Unsupported(
            "source ATH3012 runtime USB identity/revision",
        ));
    }
    hci.open()?;
    let start = hci.io.now_us();
    let mut engine = Engine {
        hci,
        start,
        credits: 1,
        attempt: Attempt::default(),
    };
    match engine.run(provider) {
        Ok(report) => Ok(report),
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
    start: u64,
    credits: u8,
    attempt: Attempt,
}
impl<B: Io> Engine<'_, B> {
    fn bounded(&self) -> Result<()> {
        if self.hci.io.now_us().wrapping_sub(self.start) >= ATTEMPT_US {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }
    fn asynchronous(&mut self, packet: Packet) -> Result<()> {
        if self.attempt.asynchronous.len() >= 64 {
            let (Packet::Event(b) | Packet::Acl(b) | Packet::Diagnostic(b)) = packet;
            return Err(Error::protocol(
                "bounded ATH3012 asynchronous initialization queue",
                &b,
            ));
        }
        self.attempt.asynchronous.push(packet);
        Ok(())
    }
    fn command(&mut self, opcode: u16) -> Result<Vec<u8>> {
        self.bounded()?;
        let start = self.hci.io.now_us();
        let mut sent = false;
        loop {
            self.bounded()?;
            if self.hci.io.now_us().wrapping_sub(start) >= COMMAND_US {
                return Err(Error::Timeout);
            }
            if !sent && self.credits != 0 {
                self.attempt.pending_command = Some(opcode);
                self.hci.submit_command(
                    &command::packet(opcode, &[]).map_err(|e| Error::protocol(e, &[]))?,
                )?;
                self.credits -= 1;
                sent = true;
            }
            let mut completed = None;
            for packet in self.hci.poll()? {
                let Packet::Event(event) = packet else {
                    self.asynchronous(packet)?;
                    continue;
                };
                match command::response(&event, opcode).map_err(|e| Error::protocol(e, &event))? {
                    Response::Credits(c) => self.credits = c,
                    Response::Complete { .. } | Response::Status { .. }
                        if !sent || completed.is_some() =>
                    {
                        return Err(Error::protocol(
                            "unsolicited/duplicate ATH3012 command event",
                            &event,
                        ));
                    }
                    Response::Complete { credits, returned } => {
                        self.credits = credits;
                        if returned[0] != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status: returned[0],
                                observed: returned.to_vec(),
                            });
                        }
                        completed = Some(returned.to_vec());
                    }
                    Response::Status { credits, status } => {
                        self.credits = credits;
                        if status != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status,
                                observed: event,
                            });
                        }
                    }
                    Response::Other => self.asynchronous(Packet::Event(event))?,
                }
            }
            if let Some(bytes) = completed {
                self.attempt.pending_command = None;
                self.attempt.completed_commands.push(opcode);
                return Ok(bytes);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn run(&mut self, provider: &dyn Provider) -> Result<OwnedReport> {
        self.bounded()?;
        let raw = self
            .hci
            .io
            .control_read(crate::usb::xhci::setup(0xc0, 9, 0, 0, 20))
            .map_err(Error::Usb)?;
        let version = qca::Version::parse(&raw)
            .map_err(|_| Error::protocol("ATH3012 vendor version exact length", &raw))?;
        self.attempt.vendor_version = Some(version.clone());
        let firmware = if version.profile().is_ok() {
            let report = qca::initialize_atheros(self.hci, provider, version.rom())
                .map_err(|e| Error::Dfu(Box::new(e)))?;
            self.attempt.dfu = Some(Box::new(report.clone()));
            FirmwareEvidence::Dfu(Box::new(report))
        } else if version.rom() & 0xffff0000 != 0 {
            FirmwareEvidence::RunningUnknown
        } else {
            return Err(Error::Unsupported(
                "unknown low ATH3012 ROM requires unsupported DFU layout",
            ));
        };
        let reset = self.command(0x0c03)?;
        if reset != [0] {
            return Err(Error::protocol("HCI reset exact completion", &reset));
        }
        let local = self.command(0x1001)?;
        let local_version: [u8; 8] = local
            .get(1..)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::protocol("HCI local version exact completion", &local))?;
        self.attempt.local_version = Some(local_version);
        let raw = self.command(0x1009)?;
        let address: [u8; 6] = raw
            .get(1..)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::protocol("HCI address exact completion", &raw))?;
        self.attempt.address = Some(address);
        if address == [0; 6] || address == [0xff; 6] {
            return Err(Error::protocol(
                "ATH3012 requires actual usable address",
                &address,
            ));
        }
        Ok(OwnedReport {
            usb: super::UsbIdentity::read(self.hci.binding.device()),
            vendor_version: version,
            policy: HostPolicy {
                simultaneous_discovery: true,
                strict_duplicate_filter: true,
                broken_enhanced_setup_sync_conn: matches!(firmware, FirmwareEvidence::Dfu(_)),
            },
            firmware,
            local_version,
            address,
            completed_commands: core::mem::take(&mut self.attempt.completed_commands),
            asynchronous: core::mem::take(&mut self.attempt.asynchronous),
        })
    }
}
#[cfg(test)]
mod tests;
