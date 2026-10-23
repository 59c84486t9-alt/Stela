// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! Shared Intel secure-download engine over the actual PCIe HCI transport.
//! Original RFH, completion words, padding and every packet remain in the owned
//! transcript on success and failure; no USB identity or completion is invented.
use super::{Kind, Packet, Platform, State, Transport};
use crate::{bluetooth::intel, firmware::Provider};
use alloc::{boxed::Box, vec::Vec};

#[derive(Debug)]
pub struct Report {
    pub initialization: intel::OwnedReport,
    pub received: Vec<Packet>,
}
#[derive(Debug)]
pub struct Error {
    pub cause: Box<intel::Error>,
    pub received: Vec<Packet>,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Intel PCIe firmware: {}", self.cause)
    }
}
impl core::error::Error for Error {}

/// Initialize an already-started, exclusively owned real PCIe transport. The
/// controller's secure ROM authenticates the signed image; a Catalog hash alone
/// does not prove that authentication. Native MMIO/MSI-X attachment and deep
/// power/radio/profile qualification remain separate from this report.
pub fn initialize<P: Platform>(
    transport: &mut Transport<P>,
    provider: &dyn Provider,
    platform: intel::PlatformInputs,
) -> Result<Report, Error> {
    let mut io = Native {
        transport,
        received: Vec::new(),
        received_bytes: 0,
    };
    let result = intel::initialize_with_platform(&mut io, provider, platform);
    // send/poll/D0 service can receive complete packets and then fault before
    // returning its ordinary batch. Closing/resetting does not erase that queue.
    // Transfer it on every exit, including a failed physical cleanup.
    let pending: Vec<_> = io.transport.received.drain(..).collect();
    io.retain(&pending);
    match result {
        Ok(report) => Ok(Report {
            initialization: report.into(),
            received: io.received,
        }),
        Err(cause) => Err(Error {
            cause: Box::new(cause),
            received: io.received,
        }),
    }
}
struct Native<'a, P: Platform> {
    transport: &'a mut Transport<P>,
    received: Vec<Packet>,
    received_bytes: usize,
}
impl<P: Platform> Native<'_, P> {
    fn retain(&mut self, packets: &[Packet]) {
        self.received_bytes += packets
            .iter()
            .map(|packet| packet.bytes.len() + packet.padding.len() + 12)
            .sum::<usize>();
        self.received.extend(packets.iter().cloned());
    }
}
impl<P: Platform> intel::CommandIo for Native<'_, P> {
    fn identity(&self) -> Result<intel::TransportIdentity, intel::Error> {
        self.transport.active()?;
        Ok(intel::TransportIdentity::Pcie(self.transport.identity()))
    }
    fn now_us(&self) -> u64 {
        self.transport.platform.now_us()
    }
    fn submit_command(&mut self, bytes: &[u8]) -> Result<(), intel::Error> {
        self.transport.send(Kind::Command, bytes)?;
        Ok(())
    }
    fn events(&mut self) -> Result<Vec<Vec<u8>>, intel::Error> {
        let packets = self.transport.poll()?;
        self.retain(&packets);
        // Retain the complete final batch too. The underlying transport caps a
        // batch at128x4KiB, so a refused transcript remains finitely bounded.
        if self.received_bytes > 16 * 1024 * 1024 {
            return Err(intel::Error::Protocol("bounded PCIe firmware transcript"));
        }
        packets
            .into_iter()
            .filter_map(|packet| {
                if packet.diagnostic {
                    // Original vendor debug event97 is a source-defined side
                    // channel; its full packet stays in the retained transcript.
                    None
                } else if packet.kind == Kind::Event {
                    Some(Ok(packet.bytes))
                } else {
                    Some(Err(intel::Error::Protocol(
                        "non-command event during PCIe firmware initialization",
                    )))
                }
            })
            .collect()
    }
    fn validate_identity(&self, identity: &intel::ControllerIdentity) -> Result<(), intel::Error> {
        let matches = matches!(
            (self.transport.state(), identity),
            (State::Rom, intel::ControllerIdentity::Tlv(i)) if i.image_type == 1
        ) || matches!(
            (self.transport.state(), identity),
            (State::Iml, intel::ControllerIdentity::Tlv(i)) if i.image_type == 2
        ) || matches!(
            (self.transport.state(), identity),
            (State::Operational, intel::ControllerIdentity::Tlv(i)) if i.image_type == 3
        );
        if !matches {
            return Err(intel::Error::Protocol("PCIe GP0/HCI image-stage mismatch"));
        }
        Ok(())
    }
    fn intel_mode(&mut self, _bootloader: bool) -> Result<(), intel::Error> {
        // PCIe never changes framing: every real command retains its four-byte
        // Intel packet type. This only validates the live transport owner.
        self.transport.active().map_err(Into::into)
    }
    fn finish_boot(&mut self) -> Result<(), intel::Error> {
        match self.transport.state() {
            State::Iml => Ok(()),
            State::Operational => self.transport.enter_d0().map(|_| ()).map_err(Into::into),
            _ => Err(intel::Error::Protocol(
                "actual PCIe IML/OP after Intel boot",
            )),
        }
    }
    fn fail(&mut self, cause: intel::Error) -> intel::Error {
        match self.transport.close() {
            Ok(()) => cause,
            Err(cleanup) => intel::Error::PcieCleanup {
                cause: Box::new(cause),
                cleanup: Box::new(cleanup),
            },
        }
    }
}
