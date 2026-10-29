// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Source reduced SCAN_CFG5 through the AX200 command/DMA owner.
//! Configuration ACK does not start a scan or establish channel/RF permission.
use super::*;
use crate::net::wifi::intel::command::Id;
const UMAC_SCAN_CAPABILITY: u32 = 2;
const REDUCED_SCAN_CONFIGURATION_API: u32 = 56;
const SCAN_CONFIGURATION_VERSION: u8 = 5;
const SCAN_CONFIGURATION: Id = Id {
    group: 1,
    opcode: 0x0c,
    version: 0,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200ScanConfigurationPhase {
    NotStarted,
    Waiting,
    BoardPolicyRequired,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200ScanConfigurationError {
    Boot(Error),
    MissingUmacScan,
    ReducedScanRequired,
    MissingApi,
    Version(u8),
    MissingPhySku,
    NoTxAntennas,
    NoRxAntennas,
    InternalAuxiliaryStationRequired,
    Deadline,
    State,
}
pub struct Ax200ScanConfiguration<'a, Q: BootIo, B: BiosIo> {
    pub(in crate::net::wifi::intel::boot) mcc: Ax200Mcc<'a, Q, B>,
    phase: Ax200ScanConfigurationPhase,
    payload: Option<[u8; 12]>,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    response: Option<CommandResponse>,
    first_error: Option<Ax200ScanConfigurationError>,
}
impl<'a, Q: BootIo, B: BiosIo> Ax200Mcc<'a, Q, B> {
    pub fn begin_scan_configuration(self) -> Result<Ax200ScanConfiguration<'a, Q, B>, Box<Self>> {
        if self.phase != Ax200MccPhase::PolicyRequired
            || self.first_error.is_some()
            || self.setup.lari.radio.initialized.boot.state != State::PnvmObserved
        {
            return Err(Box::new(self));
        }
        Ok(Ax200ScanConfiguration {
            mcc: self,
            phase: Ax200ScanConfigurationPhase::NotStarted,
            payload: None,
            ticket: None,
            deadline: None,
            response: None,
            first_error: None,
        })
    }
}
impl<Q: BootIo, B: BiosIo> Ax200ScanConfiguration<'_, Q, B> {
    pub fn phase(&self) -> Ax200ScanConfigurationPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200ScanConfigurationError> {
        self.first_error.as_ref()
    }
    pub fn payload(&self) -> Option<&[u8; 12]> {
        self.payload.as_ref()
    }
    /// Original pending ticket, kept on timeout or uncertain CPU reclaim.
    /// A borrowed ticket cannot publish a command or reconstruct this owner.
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    pub fn response(&self) -> Option<&CommandResponse> {
        self.response.as_ref()
    }
    pub fn profiles(&self) -> &[crate::net::wifi::intel::mcc::Response] {
        self.mcc.profiles()
    }
    pub fn platform_reads(&self) -> &[service::Read] {
        self.mcc.platform_reads()
    }
    pub fn initialized_nvm(&self) -> &InitializedNvm {
        self.mcc.initialized_nvm()
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.mcc.take_firmware_notification()
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        self.mcc.replenish_completed_receive()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.mcc.stop() {
            Ok(()) => {
                self.phase = Ax200ScanConfigurationPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.first_error
                    .get_or_insert_with(|| Ax200ScanConfigurationError::Boot(error.clone()));
                self.phase = Ax200ScanConfigurationPhase::Failed;
                Err(error)
            }
        }
    }
    fn prepare(&self) -> Result<[u8; 12], Ax200ScanConfigurationError> {
        let fw = &self.mcc.setup.lari.radio.initialized.boot.firmware;
        if !fw.supports_capability(UMAC_SCAN_CAPABILITY) {
            return Err(Ax200ScanConfigurationError::MissingUmacScan);
        }
        if !fw.supports_api(REDUCED_SCAN_CONFIGURATION_API) {
            return Err(Ax200ScanConfigurationError::ReducedScanRequired);
        }
        let version = fw
            .command_version(1, SCAN_CONFIGURATION.opcode)
            .ok_or(Ax200ScanConfigurationError::MissingApi)?
            .command_version;
        if version != SCAN_CONFIGURATION_VERSION {
            return Err(Ax200ScanConfigurationError::Version(version));
        }
        if self
            .mcc
            .setup
            .decisions
            .as_ref()
            .is_none_or(|d| !d.firmware_auxiliary_station)
        {
            return Err(Ax200ScanConfigurationError::InternalAuxiliaryStationRequired);
        }
        let sku = fw
            .phy_sku()
            .ok_or(Ax200ScanConfigurationError::MissingPhySku)?;
        let nvm = &self.initialized_nvm().information;
        let mut tx = ((sku >> 16) & 0xf) as u8;
        let mut rx = ((sku >> 20) & 0xf) as u8;
        if nvm.tx_chains as u8 != 0 {
            tx &= nvm.tx_chains as u8;
        }
        if nvm.rx_chains as u8 != 0 {
            rx &= nvm.rx_chains as u8;
        }
        if tx == 0 {
            return Err(Ax200ScanConfigurationError::NoTxAntennas);
        }
        if rx == 0 {
            return Err(Ax200ScanConfigurationError::NoRxAntennas);
        }
        // Source cold defaults have no requested antenna override. Both flags,
        // broadcast station (deprecated in v5) and reserved byte remain zero.
        let mut bytes = [0; 12];
        bytes[4..8].copy_from_slice(&u32::from(tx).to_le_bytes());
        bytes[8..12].copy_from_slice(&u32::from(rx).to_le_bytes());
        Ok(bytes)
    }
    /// Publish source cold scan configuration and wait for RX/CPU reclaim.
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the kept
    /// native requester/domain under RomBoot's publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200ScanConfigurationPhase, Ax200ScanConfigurationError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: exact page-source contract forwarded from caller.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(
                error,
                Ax200ScanConfigurationError::Boot(Error::CommandReclaim(_))
            )
        {
            self.first_error = Some(error.clone());
            self.phase = Ax200ScanConfigurationPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200ScanConfigurationPhase, Ax200ScanConfigurationError> {
        if self.mcc.setup.lari.radio.initialized.boot.state != State::PnvmObserved {
            return Err(Ax200ScanConfigurationError::State);
        }
        if self.phase == Ax200ScanConfigurationPhase::BoardPolicyRequired {
            self.mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .poll_one_notification_buffer()
                .map_err(Ax200ScanConfigurationError::Boot)?;
            return Ok(self.phase);
        }
        if self.phase == Ax200ScanConfigurationPhase::NotStarted {
            let bytes = self.prepare()?;
            self.payload = Some(bytes);
            // SAFETY: bytes have no indirect resources, source RF-kill policy
            // remains enforced and the native command owner stays held.
            self.ticket = Some(
                unsafe {
                    self.mcc.setup.lari.radio.initialized.boot.submit_command(
                        SCAN_CONFIGURATION,
                        &bytes,
                        source,
                    )
                }
                .map_err(Ax200ScanConfigurationError::Boot)?,
            );
            self.deadline = Some(
                self.mcc
                    .setup
                    .options
                    .clock
                    .deadline(self.mcc.setup.options.command_timeout_us),
            );
            self.phase = Ax200ScanConfigurationPhase::Waiting;
            return Ok(self.phase);
        }
        let ticket = self
            .ticket
            .as_ref()
            .ok_or(Ax200ScanConfigurationError::State)?;
        let progress = self
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot
            .poll_command(ticket);
        if matches!(progress, Err(Error::CommandReclaim(_)))
            && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
        {
            return Err(Ax200ScanConfigurationError::Deadline);
        }
        match progress.map_err(Ax200ScanConfigurationError::Boot)? {
            CommandProgress::Pending => {
                if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                    return Err(Ax200ScanConfigurationError::Deadline);
                }
            }
            CommandProgress::Completed(response) => {
                let (command, group) = (response.command, response.group);
                self.response = Some(response);
                self.ticket = None;
                self.deadline = None;
                if command != SCAN_CONFIGURATION.opcode || group != SCAN_CONFIGURATION.group {
                    return Err(Ax200ScanConfigurationError::Boot(
                        Error::InitializationResponse { command, group },
                    ));
                }
                self.phase = Ax200ScanConfigurationPhase::BoardPolicyRequired;
            }
        }
        Ok(self.phase)
    }
}
