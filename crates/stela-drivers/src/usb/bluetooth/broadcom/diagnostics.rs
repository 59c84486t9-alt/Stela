// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! Broadcom LM_DIAG interface2 native bulk transport. These original USB
//! payloads are diagnostic records, without HCI ACL framing or synthetic reply.
use super::super::{
    Binding, Error as HciError, ErrorKind, Hci, InitializationReport, Io, Packet, State,
};
use crate::{
    block::BlockError,
    bus::dma::DmaAllocator,
    usb::xhci::{self, Endpoint},
};
use alloc::{boxed::Box, vec::Vec};

/// Original source HCI_MAX_FRAME_SIZE (HCI_MAX_ACL_SIZE1024 + four bytes).
pub const MAX_RECORD: usize = 1028;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pair {
    pub input: Endpoint,
    pub output: Endpoint,
}
impl Pair {
    pub fn endpoints(self) -> [Endpoint; 2] {
        [self.input, self.output]
    }
}
#[derive(Debug)]
pub enum Error {
    Unsupported(&'static str),
    Transport(HciError),
    Enable {
        enabled: bool,
        cause: Box<HciError>,
    },
    Record {
        record: Vec<u8>,
        cause: Box<HciError>,
    },
}
/// Exact receive boundary observed during acknowledged native retirement.
/// Stopped bytes are partial; Unknown supplies no byte count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetiredInput {
    pub outcome: xhci::TransferCancellation,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Retirement {
    pub input: Option<RetiredInput>,
    pub output_intent: Option<[u8; 2]>,
    pub output: Option<xhci::TransferCancellation>,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Broadcom diagnostic {self:?}")
    }
}
impl core::error::Error for Error {}
impl From<HciError> for Error {
    fn from(e: HciError) -> Self {
        Self::Transport(e)
    }
}

/// Same native function's independent bulk endpoints. Failed cancellation must
/// keep all uncertain DMA and forbid reuse, exactly like the HCI Io boundary.
pub trait DiagnosticIo: Io {
    fn start_diagnostics(
        &mut self,
        pair: Pair,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError>;
    fn read_diagnostic(&mut self) -> Result<Option<Vec<u8>>, BlockError>;
    fn write_diagnostic(&mut self, bytes: [u8; 2]) -> Result<(), BlockError>;
    fn diagnostic_retirement(&self) -> Option<&Retirement>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    Hci(Packet),
    Diagnostic(Vec<u8>),
}
pub struct Session<B: DiagnosticIo> {
    hci: Hci<B>,
    pair: Pair,
    last_delivery: Option<bool>,
    pending: Vec<Received>,
}
impl<B: DiagnosticIo> Session<B> {
    pub fn start(mut hci: Hci<B>, dma: &mut dyn DmaAllocator) -> Result<Self, Error> {
        let pair = plan(&hci)?;
        hci.io
            .start_diagnostics(pair, dma)
            .map_err(|cause| hci.fail(ErrorKind::Usb(cause)))?;
        Ok(Self {
            hci,
            pair,
            last_delivery: None,
            pending: Vec::new(),
        })
    }
    pub fn state(&self) -> State {
        self.hci.state()
    }
    pub fn pair(&self) -> Pair {
        self.pair
    }
    pub fn initialization(&self) -> &super::OwnedReport {
        match self.hci.initialization().unwrap().unwrap() {
            InitializationReport::Broadcom(r) => r,
            _ => unreachable!(),
        }
    }
    /// Historical completed native delivery. The source has no diagnostic-mode
    /// firmware acknowledgement; this does not claim a response/readiness state.
    pub fn last_delivery(&self) -> Option<bool> {
        self.last_delivery
    }
    /// Historical retirement metadata; no native I/O or ownership grant.
    pub fn retirement(&self) -> Option<&Retirement> {
        self.hci.io.diagnostic_retirement()
    }
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        self.hci.open()?;
        self.hci
            .io
            .write_diagnostic([0xf0, u8::from(enabled)])
            .map_err(|cause| Error::Enable {
                enabled,
                cause: Box::new(self.hci.fail(ErrorKind::Usb(cause))),
            })?;
        self.last_delivery = Some(enabled);
        Ok(())
    }
    pub fn submit_command(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.hci.submit_command(packet).map_err(Into::into)
    }
    pub fn submit_acl(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.hci.submit_acl(packet).map_err(Into::into)
    }
    /// At most one completed native diagnostic USB record, keeping its exact
    /// boundary including a zero-length completion. Ordinary HCI data
    /// observed before a later diagnostic failure remains explicitly drainable.
    pub fn poll(&mut self) -> Result<Vec<Received>, Error> {
        self.hci.open()?;
        for packet in self.hci.poll()? {
            self.pending.push(Received::Hci(packet));
        }
        if let Some(record) = self
            .hci
            .io
            .read_diagnostic()
            .map_err(|cause| self.hci.fail(ErrorKind::Usb(cause)))?
        {
            if record.len() > MAX_RECORD {
                return Err(Error::Record {
                    cause: Box::new(self.hci.fail(ErrorKind::TooLarge {
                        maximum: MAX_RECORD,
                        actual: record.len(),
                    })),
                    record,
                });
            }
            self.pending.push(Received::Diagnostic(record));
        }
        Ok(core::mem::take(&mut self.pending))
    }
    /// Already observed historical bytes only. This performs no native I/O and
    /// grants no permission to a retired generation.
    pub fn take_pending_observations(&mut self) -> Vec<Received> {
        core::mem::take(&mut self.pending)
    }
    pub fn close(&mut self) -> Result<(), Error> {
        self.hci.close().map_err(Into::into)
    }
}
pub(in crate::usb::bluetooth) fn plan<B: Io>(hci: &Hci<B>) -> Result<Pair, Error> {
    hci.open()?;
    let Some(Ok(InitializationReport::Broadcom(report))) = hci.initialization() else {
        return Err(Error::Unsupported(
            "retained initialized USB PatchRAM owner",
        ));
    };
    if super::UsbIdentity::read(hci.binding().device()) != report.before.usb {
        return Err(Error::Unsupported("same initialized Broadcom USB identity"));
    }
    plan_binding(hci.binding())
}
fn plan_binding(binding: &Binding) -> Result<Pair, Error> {
    if !super::is_candidate(binding.device()) || binding.interface() != 0 {
        return Err(Error::Unsupported("source Broadcom PatchRAM interface0"));
    }
    let d = binding.device();
    let interfaces = xhci::interfaces(&d.configuration);
    let settings: Vec<_> = interfaces
        .iter()
        .filter(|i| i.number == 2 && i.alternate == 0)
        .collect();
    if settings.len() != 1 {
        return Err(Error::Unsupported(
            "Broadcom current diagnostic interface2 alternate0",
        ));
    }
    let endpoints = &settings[0].endpoints;
    let inputs: Vec<_> = endpoints
        .iter()
        .filter(|e| e.attributes & 3 == 2 && e.address & 0x80 != 0)
        .copied()
        .collect();
    let outputs: Vec<_> = endpoints
        .iter()
        .filter(|e| e.attributes & 3 == 2 && e.address & 0x80 == 0)
        .copied()
        .collect();
    if inputs.len() != 1 || outputs.len() != 1 {
        return Err(Error::Unsupported("one native diagnostic bulk IN/OUT pair"));
    }
    let pair = Pair {
        input: inputs[0],
        output: outputs[0],
    };
    for ep in pair.endpoints() {
        if ep.address & 0x70 != 0
            || ep.address & 15 == 0
            || ep.companion.is_some()
            || match d.speed {
                xhci::FULL_SPEED => !matches!(ep.max_packet, 8 | 16 | 32 | 64),
                xhci::HIGH_SPEED => ep.max_packet != 512,
                _ => true,
            }
        {
            return Err(Error::Unsupported("legal USB2 diagnostic bulk endpoint"));
        }
        if interfaces
            .iter()
            .filter(|i| i.number != 2)
            .flat_map(|i| &i.endpoints)
            .any(|other| other.dci() == ep.dci())
        {
            return Err(Error::Unsupported(
                "diagnostic endpoint aliases another interface",
            ));
        }
    }
    Ok(pair)
}

#[cfg(test)]
mod tests;
