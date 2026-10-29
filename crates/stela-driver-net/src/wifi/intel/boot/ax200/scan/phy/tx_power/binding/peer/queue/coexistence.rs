// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2013-2014, 2018-2026 Intel Corporation
//! Original coexistence vif-change callback on one cold MLD link.
//! Real CI ACK/reclaim and RX profiles; no HCI or frame/RF grant.
use super::*;
use crate::wifi::intel::boot::coexistence::{CoexistenceError, channel_inhibition, next_antenna};
const CHANNEL_INHIBITION: Id = Id {
    group: 0,
    opcode: 0x5d,
    version: 0,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200CoexistencePhase {
    NotStarted,
    WaitingChannelInhibition,
    ManagementFramesRequired,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200CoexistenceError {
    Queue(Ax200ManagementQueueError),
    Boot(Error),
    Binding(Ax200BindingError),
    Coexistence(CoexistenceError),
    Deadline,
    State,
}
pub struct Ax200Coexistence<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> {
    pub(in crate::wifi::intel::boot) queue: Ax200ManagementQueue<'a, Q, B, O>,
    phase: Ax200CoexistencePhase,
    pending_ci: Option<[u8; 24]>,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    first_error: Option<Ax200CoexistenceError>,
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200ManagementQueue<'a, Q, B, O> {
    /// Run the source coexistence vif-change callback for this sole
    /// unassociated, non-HT station/link0/PHY0. Mandatory BT_CONFIG was already
    /// applied by ColdRadio; this continuation never sends a duplicate init.
    /// # Safety
    /// The original same-device providers, finite-rate restrictive revocation,
    /// exclusive DMA/requester and no-competing-worker contracts persist.
    /// No external BSS/SMPS/HT/coexistence mutation or forced-antenna policy may
    /// race this original callback owner. This does not authorize any frame.
    pub unsafe fn begin_mld_coexistence(self) -> Result<Ax200Coexistence<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200ManagementQueuePhase::ManagementFramesRequired
            || self.first_error.is_some()
            || self.ticket.is_some()
        {
            return Err(Box::new(self));
        }
        Ok(Ax200Coexistence {
            queue: self,
            phase: Ax200CoexistencePhase::NotStarted,
            pending_ci: None,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            first_error: None,
        })
    }
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Coexistence<'a, Q, B, O> {
    pub fn phase(&self) -> Ax200CoexistencePhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200CoexistenceError> {
        self.first_error.as_ref()
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    /// Cold management antenna choice from kept firmware/NVM and
    /// captured Wi-Fi BT profile. This observation grants no frame/RF lease.
    /// No management frame has yet run, so the post-NVM source initial toggle
    /// from index0 remains the current index; later TX completion must own any
    /// rotation rather than accepting an antenna supplied by a caller.
    pub fn management_antenna_mask(&mut self) -> Result<u8, Ax200CoexistenceError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        if self.phase != Ax200CoexistencePhase::ManagementFramesRequired {
            return Err(Ax200CoexistenceError::State);
        }
        let power = &mut self.queue.peer().binding.power;
        let nvm_ant = power.phy.scan.mac.initialized_nvm().information.tx_chains as u8;
        let band = power.channel().band;
        let boot = power.phy.boot();
        let sku = boot
            .firmware
            .phy_sku()
            .ok_or(Ax200CoexistenceError::State)?;
        let mut valid = ((sku >> 16) & 15) as u8;
        if nvm_ant != 0 {
            valid &= nvm_ant;
        }
        let index = next_antenna(valid, 0).map_err(Ax200CoexistenceError::Coexistence)?;
        boot.coexistence
            .management_antenna(band, valid, index)
            .map_err(Ax200CoexistenceError::Coexistence)
    }
    fn boot(&mut self) -> &mut RomBoot<'a, Q> {
        self.queue.peer().binding.power.phy.boot()
    }
    fn fail(&mut self, error: Ax200CoexistenceError) {
        self.first_error.get_or_insert(error);
        self.phase = Ax200CoexistencePhase::Failed;
    }
    /// Return only the original empty scheduler queue. The applied CI and
    /// profile remain private to its same RomBoot epoch.
    pub fn into_queue(self) -> Result<Ax200ManagementQueue<'a, Q, B, O>, Box<Self>> {
        if self.phase != Ax200CoexistencePhase::ManagementFramesRequired
            || self.first_error.is_some()
            || self.ticket.is_some()
        {
            return Err(Box::new(self));
        }
        Ok(self.queue)
    }
    pub fn stop(&mut self) -> Result<(), Ax200CoexistenceError> {
        let result = self.queue.stop().map_err(Ax200CoexistenceError::Queue);
        match &result {
            Ok(()) => self.phase = Ax200CoexistencePhase::Stopped,
            Err(error) => self.fail(error.clone()),
        }
        result
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Ax200CoexistenceError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        let result = self
            .queue
            .replenish_completed_receive()
            .map_err(Ax200CoexistenceError::Queue);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn poll_receive(&mut self) -> Result<MpduProgress, Ax200CoexistenceError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        if self.phase != Ax200CoexistencePhase::ManagementFramesRequired || self.ticket.is_some() {
            return Err(Ax200CoexistenceError::State);
        }
        let result = self
            .queue
            .poll_receive()
            .map_err(Ax200CoexistenceError::Queue);
        if let Err(error) = &result {
            self.fail(error.clone());
            return result;
        }
        if let Err(error) = self.boot().coexistence.check() {
            let error = Ax200CoexistenceError::Coexistence(error);
            self.fail(error.clone());
            return Err(error);
        }
        result
    }
    pub fn take_other_notification(&mut self) -> Option<FirmwareNotification> {
        if self.first_error.is_some() || self.ticket.is_some() {
            return None;
        }
        self.queue.take_other_notification()
    }
    /// # Safety
    /// Same fresh native page, policy and exclusive requester/domain contracts
    /// as begin_mld_coexistence. Both real policy leases span HCMD visibility.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200CoexistencePhase, Ax200CoexistenceError> {
        if let Some(error) = &self.first_error {
            return Err(error.clone());
        }
        // SAFETY: unchanged original native owner/page/provider contract.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(error, Ax200CoexistenceError::Boot(Error::CommandReclaim(_)))
            && !(self.phase == Ax200CoexistencePhase::NotStarted
                && matches!(
                    error,
                    Ax200CoexistenceError::Binding(Ax200BindingError::Regulatory(_))
                ))
        {
            self.fail(error.clone());
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200CoexistencePhase, Ax200CoexistenceError> {
        if self.phase == Ax200CoexistencePhase::Stopped
            || self.queue.phase != Ax200ManagementQueuePhase::ManagementFramesRequired
            || self.queue.first_error.is_some()
            || self.boot().state != State::PnvmObserved
        {
            return Err(Ax200CoexistenceError::State);
        }
        if let Some(ticket) = self.ticket.clone() {
            let progress = self.boot().poll_command(&ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200CoexistenceError::Deadline);
            }
            match progress.map_err(Ax200CoexistenceError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200CoexistenceError::Deadline);
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    if response.command != 0x5d || response.group != 1 {
                        return Err(Ax200CoexistenceError::Boot(Error::InitializationResponse {
                            command: response.command,
                            group: response.group,
                        }));
                    }
                    self.responses.push(response);
                    self.ticket = None;
                    self.deadline = None;
                    self.boot().coexistence.applied_ci = self.pending_ci.take().unwrap();
                    self.phase = Ax200CoexistencePhase::ManagementFramesRequired;
                }
            }
        }
        // Real packet dispatch keeps the canonical profile even if an outer
        // caller consumes mutable diagnostics. This cold no-HT/unassociated
        // state forces SMPS_AUTOMATIC (already AUTO), reduced TXP remains false
        // and RSSI monitoring stays disabled; the original source issues no
        // extra command, work item or management frame on any grading0..4.
        self.queue
            .peer()
            .binding
            .power
            .phy
            .capture_idle_receive()
            .map_err(|e| {
                Ax200CoexistenceError::Queue(Ax200ManagementQueueError::Peer(
                    Ax200LegacyPeerError::Phy(e),
                ))
            })?;
        let firmware = &self.boot().firmware;
        if !firmware.supports_capability(110)
            || firmware.supports_capability(40)
            || !firmware
                .command_version(1, 0x5d)
                .is_some_and(|v| v.command_version == 2 && v.notification_version == 0)
            || firmware
                .command_version(1, 0xce)
                .is_some_and(|v| !matches!(v.notification_version, 4 | 5))
        {
            return Err(Ax200CoexistenceError::Coexistence(
                CoexistenceError::Version,
            ));
        }
        self.boot()
            .coexistence
            .check()
            .map_err(Ax200CoexistenceError::Coexistence)?;
        let channel = self.queue.peer().binding.power.channel();
        let ci = channel_inhibition(channel).map_err(Ax200CoexistenceError::Coexistence)?;
        if self.boot().coexistence.applied_ci == ci {
            self.phase = Ax200CoexistencePhase::ManagementFramesRequired;
            return Ok(self.phase);
        }
        let peer = self.queue.peer();
        let options = peer
            .binding
            .power
            .phy
            .scan
            .mac
            .country
            .board
            .scan
            .mcc
            .setup
            .options;
        // SAFETY: same finite cold response/rate union, held through
        // CI publication. No new rate, calibration state or frame is enabled.
        self.ticket = Some(
            unsafe {
                admission::publish_legacy(
                    &mut peer.binding.power,
                    CHANNEL_INHIBITION,
                    &ci,
                    peer.peer.rates,
                    source,
                )
            }
            .map_err(Ax200CoexistenceError::Binding)?,
        );
        self.pending_ci = Some(ci);
        self.deadline = Some(options.clock.deadline(options.command_timeout_us));
        self.phase = Ax200CoexistencePhase::WaitingChannelInhibition;
        Ok(self.phase)
    }
}
