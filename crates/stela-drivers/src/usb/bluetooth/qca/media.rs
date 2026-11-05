// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! Source-checked QCA Rome/WCN USB SCO, queued wideband and explicit shutdown.
//! Uses the shared native USB media owner. No physical power/subsystem
//! reset, pairing/profile policy or HCI ISO transport is inferred.
use super::super::mediatek::media as shared;
use crate::{
    bus::dma::DmaAllocator,
    usb::bluetooth::{Hci, InitializationReport},
};
pub use shared::{
    AirMode, Error, Lifecycle, Loss, MediaIo, OutputDisposition, OutputReceipt, Read, Received,
    Result, SetupReport, Voice,
};

pub struct Session<B: MediaIo>(shared::Session<B>, Option<ShutdownReport>);
#[derive(Debug)]
pub struct ShutdownReport {
    pub completion: SetupReport,
    /// HCI observations in wire order, including the real reset CC.
    pub asynchronous: alloc::vec::Vec<Received>,
    pub output: alloc::vec::Vec<OutputReceipt>,
    /// Set only after media and base transport retirement both acknowledge.
    pub transport_retired: bool,
}
impl<B: MediaIo> Session<B> {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn start(hci: Hci<B>) -> Result<Self> {
        shared::Session::start_qca(hci).map(|session| Self(session, None))
    }
    pub fn initialization(&self) -> &super::OwnedReport {
        match self.0.hci.initialization().unwrap().unwrap() {
            InitializationReport::Qualcomm(r) => r,
            _ => unreachable!(),
        }
    }
    pub fn lifecycle(&self) -> Lifecycle {
        self.0.lifecycle()
    }
    pub fn last_reset(&self) -> Option<&SetupReport> {
        self.0.last_reset()
    }
    /// Historical reset/packet evidence also survives failed retirement.
    pub fn shutdown_report(&self) -> Option<&ShutdownReport> {
        self.1.as_ref()
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn set_voice(&mut self, voice: Voice, dma: &mut dyn DmaAllocator) -> Result<()> {
        self.0.set_voice(voice, dma)
    }
    /// HCI synchronous payload MTU from the stack. Source QCA prefers
    /// alt6, otherwise alt1; Realtek's alt3 exception never applies here.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn set_wideband_voice(
        &mut self,
        connections: u8,
        mtu: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<()> {
        self.0.set_wideband_voice(connections, mtu, dma)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn submit_command(&mut self, packet: &[u8]) -> Result<()> {
        self.0.submit_command(packet)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn submit_acl(&mut self, packet: &[u8]) -> Result<()> {
        self.0.submit_acl(packet)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn submit_sco(&mut self, packet: &[u8]) -> Result<()> {
        self.0.submit(shared::Kind::Sco, packet)
    }
    /// None is effect-free backpressure; Some(sequence) is acceptance only.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn queue_sco(&mut self, packet: &[u8]) -> Result<Option<u64>> {
        self.0.queue_sco(packet)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn poll_sco_output(&mut self) -> Result<Option<OutputReceipt>> {
        self.0.poll_sco_output()
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn poll(&mut self) -> Result<alloc::vec::Vec<Received>> {
        self.0.poll()
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn quiesce(&mut self) -> Result<()> {
        self.0.quiesce()
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn resume(&mut self) -> Result<()> {
        self.0.resume()
    }
    /// Source btusb_shutdown_qca sends ordinary HCI Reset, then native transport
    /// retirement is acknowledged. The caller owns current command
    /// credits and must have no other outstanding command. A zero allowance
    /// refuses without effects; failed completion/retirement is terminal.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn shutdown(&mut self, command_credits: u8) -> Result<&ShutdownReport> {
        if command_credits == 0 {
            return Err(Error::Packet(
                "actual available shutdown HCI credit required",
            ));
        }
        self.0.submit_command(&[3, 0x0c, 0])?;
        let completion = self.0.last_reset().unwrap().clone();
        let asynchronous = self.0.take_pending_observations();
        // Install Reset/packet evidence before any further fallible
        // output observation or teardown. No live input poll is needed here.
        self.1 = Some(ShutdownReport {
            completion,
            asynchronous,
            output: alloc::vec::Vec::new(),
            transport_retired: false,
        });
        for _ in 0..32 {
            let Some(receipt) = self.0.poll_sco_output()? else {
                break;
            };
            self.1.as_mut().unwrap().output.push(receipt);
        }
        self.0.close()?;
        self.1.as_mut().unwrap().transport_retired = true;
        Ok(self.1.as_ref().unwrap())
    }
    /// Raw transport close. Use shutdown for the source controller-reset phase.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn close(&mut self) -> Result<()> {
        self.0.close()
    }
}

#[cfg(test)]
mod tests;
