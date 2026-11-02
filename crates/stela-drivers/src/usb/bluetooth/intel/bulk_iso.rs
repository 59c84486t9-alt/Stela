// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Intel GfP2/GaP HCI ISO multiplexed on the legacy bulk endpoints.
//! Original btintel.c classifies received ACL frames by their real connection
//! handle. This owner requires initialized identity, LE features and
//! buffer-size responses; USB submission never substitutes for those responses.
use super::super::{
    Error as HciError, ErrorKind, Hci, InitializationReport, Io, Packet, State, command,
};
use crate::bluetooth::intel::{ControllerIdentity, TransportIdentity};
use alloc::{boxed::Box, vec::Vec};

const COMMAND_US: u64 = 5_000_000;
const ATTEMPT_US: u64 = 20_000_000;
const MAX_OBSERVED: usize = 32768;

#[derive(Clone, Debug)]
pub struct Report {
    pub usb: (u16, u16, u16),
    pub hardware_variant: u8,
    pub features: [u8; 8],
    /// Complete original successful LE Read Buffer Size V2 return parameters.
    pub buffers: [u8; 7],
    pub iso_mtu: u16,
    pub iso_packets: u8,
    pub command_credits: u8,
    /// Every original complete observation, including command responses.
    pub received: Vec<Packet>,
}
#[derive(Clone, Debug, Default)]
pub struct Attempt {
    pub pending_opcode: Option<u16>,
    /// Publication intents, including a command whose USB call failed.
    pub submitted: Vec<u16>,
    pub received: Vec<Packet>,
    pub features: Option<[u8; 8]>,
    pub buffers: Option<[u8; 7]>,
}
#[derive(Clone, Debug)]
pub struct ShutdownReport {
    pub usb: (u16, u16, u16),
    pub hardware_variant: u8,
    pub command_credits: u8,
    /// Complete observations, including the matching successful Reset.
    pub received: Vec<Packet>,
    pub transport_retired: bool,
}
#[derive(Debug)]
pub enum Error {
    Unsupported(&'static str),
    Protocol(&'static str),
    Controller {
        opcode: u16,
        status: u8,
    },
    Timeout,
    Transport(HciError),
    /// Attempted packet and conservative consumed allowance survive
    /// uncertain delivery. Only a stack completion can restore credit.
    Output {
        cause: HciError,
        packet: Vec<u8>,
    },
    Failed {
        cause: Box<Error>,
        attempt: Box<Attempt>,
        cleanup: Option<HciError>,
    },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Intel bulk ISO {self:?}")
    }
}
impl core::error::Error for Error {}
impl From<HciError> for Error {
    fn from(error: HciError) -> Self {
        Self::Transport(error)
    }
}

/// Original HCI bytes. ISO timestamp, sequence, SDU-length/status and
/// fragmentation fields remain for the host stack; this transport edits none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    Event(Vec<u8>),
    Acl(Vec<u8>),
    Iso(Vec<u8>),
    Diagnostic(Vec<u8>),
}

/// Exclusive pre-stack setup resets existing radio connections. The caller
/// supplies command allowance with no command already in flight. HCI
/// data credits and connection/codec policy belong to the eventual host stack.
pub struct Session<B: Io> {
    hci: Hci<B>,
    report: Report,
    shutdown: Option<ShutdownReport>,
}
impl<B: Io> Session<B> {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn start(mut hci: Hci<B>, command_credits: u8) -> Result<Self, Error> {
        let report = prepare(&mut hci, command_credits)?;
        Ok(Self {
            hci,
            report,
            shutdown: None,
        })
    }
    /// Historical observed capability, not physical radio or stream readiness.
    pub fn report(&self) -> &Report {
        &self.report
    }
    pub fn state(&self) -> State {
        self.hci.state()
    }
    pub fn shutdown_report(&self) -> Option<&ShutdownReport> {
        self.shutdown.as_ref()
    }
    /// Source btintel_shutdown_combined's mandatory real Reset phase followed
    /// by acknowledged native retirement. Caller owns command allowance
    /// and retires stack connections. The source LED-workaround USB aliases
    /// 8087:07dc/0a2a/0aa7 are excluded by current Intel initialization admission.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn shutdown(&mut self, credits: u8) -> Result<&ShutdownReport, Error> {
        let report = transact(&mut self.hci, credits, |engine, usb, hardware_variant| {
            if engine.command(0x0c03)?.as_slice() != [0] {
                return Err(Error::Protocol("shutdown Reset response length"));
            }
            Ok(ShutdownReport {
                usb,
                hardware_variant,
                command_credits: engine.credits,
                received: core::mem::take(&mut engine.attempt.received),
                transport_retired: false,
            })
        })?;
        // No live poll after the real matching completion: install all observed
        // bytes before any fallible close, preserving zero returned credits.
        self.shutdown = Some(report);
        self.hci.close()?;
        self.shutdown.as_mut().unwrap().transport_retired = true;
        Ok(self.shutdown.as_ref().unwrap())
    }
    pub fn initialization(&self) -> &super::OwnedReport {
        match self.hci.initialization().unwrap().unwrap() {
            InitializationReport::Intel(report) => report,
            _ => unreachable!(),
        }
    }
    /// Reset and re-read LE capabilities/buffers. The caller retires its
    /// host-stack connections/credits; no successful previous report is current
    /// after a failed attempt, as the native owner is terminal then.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn reset(&mut self, command_credits: u8) -> Result<&Report, Error> {
        self.report = prepare(&mut self.hci, command_credits)?;
        Ok(&self.report)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn submit_command(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.hci.open()?;
        if packet.len() >= 2 {
            let opcode = u16::from_le_bytes([packet[0], packet[1]]);
            if opcode == 0x0c03 || opcode >> 10 == 0x3f {
                return Err(Error::Unsupported(
                    "reset through reset(); vendor reinitialization requires a fresh raw owner",
                ));
            }
        }
        self.hci.submit_command(packet).map_err(Into::into)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn submit_acl(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.hci.open()?;
        if is_iso(&self.report, packet) {
            return Err(Error::Protocol(
                "Intel ISO handle requires typed ISO output",
            ));
        }
        self.hci.submit_acl(packet).map_err(Into::into)
    }
    /// One complete ISO header+data load in one real bulk OUT transfer. Credits
    /// are the stack's remaining ISO packet allowance. Validation is
    /// effect-free; an attempted USB delivery consumes one credit even on error.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn submit_iso(&mut self, packet: &[u8], credits: &mut u8) -> Result<(), Error> {
        self.hci.open()?;
        if !is_iso(&self.report, packet)
            || packet.len() != 4 + usize::from(u16::from_le_bytes([packet[2], packet[3]]))
        {
            return Err(Error::Protocol("complete Intel bulk ISO frame"));
        }
        if packet.len() - 4 > usize::from(self.report.iso_mtu)
            || packet.len() - 4 > super::super::MAX_ACL_PAYLOAD
        {
            return Err(Error::Unsupported(
                "observed ISO MTU and native packet budget",
            ));
        }
        if *credits == 0 || *credits > self.report.iso_packets {
            return Err(Error::Protocol(
                "actual available controller ISO packet credit",
            ));
        }
        let retained = packet.to_vec();
        *credits -= 1;
        self.hci
            .io
            .write_acl(packet)
            .map_err(|cause| Error::Output {
                cause: self.hci.fail(ErrorKind::Usb(cause)),
                packet: retained,
            })
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn poll(&mut self) -> Result<Vec<Received>, Error> {
        self.hci
            .poll()
            .map(|packets| {
                packets
                    .into_iter()
                    .map(|packet| match packet {
                        Packet::Event(bytes) => Received::Event(bytes),
                        Packet::Acl(bytes) if is_iso(&self.report, &bytes) => Received::Iso(bytes),
                        Packet::Acl(bytes) => Received::Acl(bytes),
                        Packet::Diagnostic(bytes) => Received::Diagnostic(bytes),
                    })
                    .collect()
            })
            .map_err(Into::into)
    }
    /// Acknowledged native transport retirement, without inferred power/PM.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn close(&mut self) -> Result<(), Error> {
        self.hci.close().map_err(Into::into)
    }
}

#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
fn profile<B: Io>(hci: &Hci<B>) -> Result<((u16, u16, u16), u8), Error> {
    hci.open()?;
    if !super::is_candidate(hci.binding().device()) {
        return Err(Error::Unsupported("source-admitted Intel USB identity"));
    }
    let Some(Ok(InitializationReport::Intel(report))) = hci.initialization() else {
        return Err(Error::Unsupported("retained initialized Intel USB owner"));
    };
    let ControllerIdentity::Tlv(after) = &report.after else {
        return Err(Error::Unsupported("Intel TLV bulk ISO profile"));
    };
    if !matches!(after.hardware_variant(), 0x18 | 0x1c) || !report.after.is_operational() {
        return Err(Error::Unsupported(
            "source Intel 0x18/0x1c operational profile",
        ));
    }
    let TransportIdentity::Usb(usb) = after.transport else {
        return Err(Error::Unsupported(
            "Intel bulk ISO requires actual USB transport",
        ));
    };
    let d = &hci.binding().device().descriptor;
    if usb
        != (
            u16::from_le_bytes([d[8], d[9]]),
            u16::from_le_bytes([d[10], d[11]]),
            u16::from_le_bytes([d[12], d[13]]),
        )
    {
        return Err(Error::Unsupported("same initialized Intel USB identity"));
    }
    if hci.events.since.is_some() || hci.acl.since.is_some() {
        return Err(Error::Unsupported("complete HCI framing before reset"));
    }
    Ok((usb, after.hardware_variant()))
}
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
fn prepare<B: Io>(hci: &mut Hci<B>, credits: u8) -> Result<Report, Error> {
    transact(hci, credits, |engine, usb, hardware_variant| {
        engine.run(usb, hardware_variant)
    })
}
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
fn transact<B: Io, T>(
    hci: &mut Hci<B>,
    credits: u8,
    run: impl FnOnce(&mut Engine<'_, B>, (u16, u16, u16), u8) -> Result<T, Error>,
) -> Result<T, Error> {
    let (usb, hardware_variant) = profile(hci)?;
    let start = hci.io.now_us();
    let mut engine = Engine {
        hci,
        start,
        credits,
        bytes: 0,
        attempt: Attempt::default(),
    };
    match run(&mut engine, usb, hardware_variant) {
        Ok(report) => Ok(report),
        Err(cause) => {
            let cleanup = if engine.hci.state() == State::Open {
                engine.hci.close().err()
            } else {
                None
            };
            Err(Error::Failed {
                cause: Box::new(cause),
                attempt: Box::new(engine.attempt),
                cleanup,
            })
        }
    }
}
struct Engine<'a, B: Io> {
    hci: &'a mut Hci<B>,
    start: u64,
    credits: u8,
    bytes: usize,
    attempt: Attempt,
}
impl<B: Io> Engine<'_, B> {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn check(&self, start: u64) -> Result<(), Error> {
        let now = self.hci.io.now_us();
        if now.wrapping_sub(self.start) >= ATTEMPT_US || now.wrapping_sub(start) >= COMMAND_US {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn command(&mut self, opcode: u16) -> Result<Vec<u8>, Error> {
        let start = self.hci.io.now_us();
        let packet = command::packet(opcode, &[]).map_err(Error::Protocol)?;
        self.attempt.pending_opcode = Some(opcode);
        let mut sent = false;
        loop {
            self.check(start)?;
            if !sent && self.credits != 0 {
                self.attempt.submitted.push(opcode);
                self.hci.submit_command(&packet)?;
                self.credits -= 1;
                sent = true;
            }
            let packets = self.hci.poll()?;
            let first = self.attempt.received.len();
            // Own the whole returned batch before parsing a fallible member;
            // malformed/duplicate responses cannot discard trailing evidence.
            for packet in packets {
                self.bytes += match &packet {
                    Packet::Event(b) | Packet::Acl(b) | Packet::Diagnostic(b) => b.len(),
                };
                self.attempt.received.push(packet);
            }
            if self.bytes > MAX_OBSERVED {
                return Err(Error::Protocol("bounded capability observations"));
            }
            let mut completion = None;
            for packet in &self.attempt.received[first..] {
                self.check(start)?;
                let Packet::Event(event) = packet else {
                    continue;
                };
                match command::response(event, opcode).map_err(Error::Protocol)? {
                    command::Response::Credits(credits) => self.credits = credits,
                    command::Response::Other => {}
                    command::Response::Complete { .. } | command::Response::Status { .. }
                        if !sent || completion.is_some() =>
                    {
                        return Err(Error::Protocol("one genuine in-flight command completion"));
                    }
                    command::Response::Status { credits, status } => {
                        self.credits = credits;
                        if status != 0 {
                            return Err(Error::Controller { opcode, status });
                        }
                    }
                    command::Response::Complete { credits, returned } => {
                        self.credits = credits;
                        if returned[0] != 0 {
                            return Err(Error::Controller {
                                opcode,
                                status: returned[0],
                            });
                        }
                        completion = Some(returned.to_vec());
                    }
                }
            }
            self.check(start)?;
            if let Some(returned) = completion {
                self.attempt.pending_opcode = None;
                return Ok(returned);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn run(&mut self, usb: (u16, u16, u16), hardware_variant: u8) -> Result<Report, Error> {
        if self.command(0x0c03)?.as_slice() != [0] {
            return Err(Error::Protocol("HCI Reset response length"));
        }
        let features: [u8; 9] = self
            .command(0x2003)?
            .try_into()
            .map_err(|_| Error::Protocol("LE feature response length"))?;
        let features: [u8; 8] = features[1..].try_into().unwrap();
        self.attempt.features = Some(features);
        if features[3] & 0x70 == 0 {
            return Err(Error::Unsupported("actual Intel controller ISO capability"));
        }
        let buffers: [u8; 7] = self
            .command(0x2060)?
            .try_into()
            .map_err(|_| Error::Protocol("LE buffer size V2 response length"))?;
        self.attempt.buffers = Some(buffers);
        let iso_mtu = u16::from_le_bytes([buffers[4], buffers[5]]);
        if iso_mtu == 0 || buffers[6] == 0 {
            return Err(Error::Unsupported("actual nonzero controller ISO buffers"));
        }
        Ok(Report {
            usb,
            hardware_variant,
            features,
            buffers,
            iso_mtu,
            iso_packets: buffers[6],
            command_credits: self.credits,
            received: core::mem::take(&mut self.attempt.received),
        })
    }
}
fn is_iso(report: &Report, header: &[u8]) -> bool {
    header.len() >= 4
        && matches!(report.hardware_variant, 0x18 | 0x1c)
        && report.features[3] & 0x70 != 0
        && u16::from_le_bytes([header[0], header[1]]) & 0x0fff >= 0x900
}

#[cfg(test)]
mod tests;
