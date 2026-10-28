// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! USB2 CVSD and source-qualified queued wideband SCO for initialized Realtek profiles. This shares the
//! native endpoint/DMA, framing and terminal lifecycle owner with MT7925 media,
//! without its third interface or vendor setup. Pairing, codecs and profiles
//! remain with the Bluetooth stack. Stream quiescence is no physical suspend.
use super::super::mediatek::media as shared;
use crate::{
    bus::dma::DmaAllocator,
    usb::bluetooth::{Hci, InitializationReport},
};
pub use shared::{
    AirMode, Error, Lifecycle, Loss, MediaIo, OutputDisposition, OutputReceipt, Read, Received,
    Result, SetupReport, Voice,
};

pub struct Session<B: MediaIo>(shared::Session<B>);
/// Source ISO packetization. ALT6's empty services are real TDs, not timer
/// sleeps or fabricated packet completions, and the packet then takes one
/// service, as `__fill_isoc_descriptor_msbc` gives it one frame. The caller
/// toggles flow only once the entire bounded plan can be admitted to its
/// native owner.
pub(in crate::usb::bluetooth) fn output_lengths(
    packet: usize,
    service: usize,
    flow: Option<bool>,
) -> Result<alloc::vec::Vec<usize>> {
    if service == 0 || !(3..=258).contains(&packet) || (flow.is_some() && packet > service) {
        return Err(Error::Packet("SCO packet/service size"));
    }
    let idle = flow.map_or(0, |old| if old { 7 } else { 6 });
    let mut lengths = alloc::vec![0;idle];
    let mut remaining = packet;
    while remaining != 0 {
        let chunk = remaining.min(service);
        lengths.push(chunk);
        remaining -= chunk;
    }
    if lengths.len() > 32 {
        return Err(Error::Unsupported("bounded queued SCO services"));
    }
    Ok(lengths)
}
impl<B: MediaIo> Session<B> {
    /// Consume an exact, successfully initialized Realtek transport. No HCI
    /// command or synthetic credit is generated when entering this owner.
    /// Failure closes/quarantines the actual transport and cannot be retried.
    pub fn start(hci: Hci<B>) -> Result<Self> {
        shared::Session::start_realtek(hci).map(Self)
    }
    pub fn initialization(&self) -> &super::OwnedReport {
        match self.0.hci.initialization().unwrap().unwrap() {
            InitializationReport::Realtek(report) => report,
            _ => unreachable!(),
        }
    }
    pub fn lifecycle(&self) -> Lifecycle {
        self.0.lifecycle()
    }
    pub fn last_reset(&self) -> Option<&SetupReport> {
        self.0.last_reset()
    }
    /// Actual current SCO connection count and CVSD voice setting from the HCI
    /// stack select the source CVSD alternate. Use `set_wideband_voice` with
    /// an actual observed HCI MTU for source-qualified transparent/mSBC voice.
    pub fn set_voice(&mut self, voice: Voice, dma: &mut dyn DmaAllocator) -> Result<()> {
        self.0.set_voice(voice, dma)
    }
    /// Source-qualified transparent/mSBC voice. `sco_mtu` is the actual HCI
    /// synchronous payload MTU observed by the stack, not a descriptor guess.
    /// Queue output ahead and poll receipts; acceptance never credits delivery.
    pub fn set_wideband_voice(
        &mut self,
        connections: u8,
        sco_mtu: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<()> {
        self.0.set_wideband_voice(connections, sco_mtu, dma)
    }
    /// None is bounded backpressure without effects. Some(sequence) is queued;
    /// only a later Completed receipt establishes actual USB completion.
    pub fn queue_sco(&mut self, packet: &[u8]) -> Result<Option<u64>> {
        self.0.queue_sco(packet)
    }
    pub fn poll_sco_output(&mut self) -> Result<Option<OutputReceipt>> {
        self.0.poll_sco_output()
    }
    /// The stack owns genuine HCI command credits and command correlation.
    /// Ordinary Reset retires the old voice epoch and forwards its actual CC.
    pub fn submit_command(&mut self, packet: &[u8]) -> Result<()> {
        self.0.submit_command(packet)
    }
    pub fn submit_acl(&mut self, packet: &[u8]) -> Result<()> {
        self.0.submit_acl(packet)
    }
    pub fn submit_sco(&mut self, packet: &[u8]) -> Result<()> {
        self.0.submit(shared::Kind::Sco, packet)
    }
    pub fn poll(&mut self) -> Result<alloc::vec::Vec<Received>> {
        self.0.poll()
    }
    pub fn quiesce(&mut self) -> Result<()> {
        self.0.quiesce()
    }
    pub fn resume(&mut self) -> Result<()> {
        self.0.resume()
    }
    pub fn close(&mut self) -> Result<()> {
        self.0.close()
    }
}

#[cfg(test)]
mod tests;
