// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! OS/setup country input and same-epoch MCC application.
//! This keeps the pinned database; it issues no channel/TX/association grant.
use super::*;
use crate::wifi::{
    intel::mcc::{
        self,
        channel::{Inventory, Observation as ChannelObservation},
    },
    regulatory::database::Country,
};
use core::mem::ManuallyDrop;
const OS_MCC_SOURCE: u8 = 9;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountryIoError {
    Unavailable,
    BoundExceeded,
    Failed(u64),
}
/// Explicit country and content-pinned database from the normal OS/setup source.
/// The revision is provider provenance, never device or radio permission.
pub struct SelectedCountry {
    pub country: Country,
    pub revision: u64,
}
/// Native OS/setup policy service, independent of copied MCC/BIOS data.
/// # Safety
/// Implementors read the current authorized OS/setup selection applicable
/// to this physical function/platform, keeping its service/resources. `country`
/// returns that explicitly selected country's pinned database, never a
/// BIOS/default/MCC-observed guess. `current` observes whether that
/// original selection remains current, including revocation/location/database
/// changes. Revisions must not repeat after any relevant change. Missing service
/// support must return Unavailable, never a constructed fallback selection.
/// This configuration service grants no emission or association permission: the
/// shared regulatory HardwarePolicy/OsPolicy guards remain mandatory at
/// later native radio publication, with their revocation/drain contracts.
pub unsafe trait CountryIo: 'static {
    fn country(&mut self) -> Result<SelectedCountry, CountryIoError>;
    fn current(&mut self, revision: u64) -> Result<bool, CountryIoError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200CountryPhase {
    NotStarted,
    Waiting,
    MacContextRequired,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200CountryError {
    Boot(Error),
    Platform(CountryIoError),
    Schema(mcc::Error),
    Inventory(mcc::channel::InventoryMismatch),
    Revoked,
    CountryMismatch {
        requested: [u8; 2],
        returned: [u8; 2],
    },
    SourceMismatch(u8),
    Rejected(u32),
    Deadline,
    State,
}
pub struct Ax200Country<'a, Q: BootIo, B: BiosIo, O: CountryIo> {
    pub(in crate::wifi::intel::boot) board: Ax200BoardPolicy<'a, Q, B>,
    os: ManuallyDrop<O>,
    phase: Ax200CountryPhase,
    selection: Option<SelectedCountry>,
    request: Option<mcc::Request>,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    response: Option<CommandResponse>,
    profile: Option<mcc::Response>,
    channels: Vec<ChannelObservation>,
    first_error: Option<Ax200CountryError>,
}
/// Internal split of the original owner; no diagnostic can construct it.
pub(super) struct ScanPolicyParts<'s, 'a, Q: BootIo, B: BiosIo, O: CountryIo> {
    pub(super) board: &'s mut Ax200BoardPolicy<'a, Q, B>,
    pub(super) os: &'s mut O,
    pub(super) selection: &'s SelectedCountry,
    pub(super) channels: &'s [ChannelObservation],
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo> Ax200Country<'a, Q, B, O> {
    pub(super) fn scan_policy_parts(&mut self) -> Option<ScanPolicyParts<'_, 'a, Q, B, O>> {
        if self.phase != Ax200CountryPhase::MacContextRequired || self.first_error.is_some() {
            return None;
        }
        Some(ScanPolicyParts {
            board: &mut self.board,
            os: &mut self.os,
            selection: self.selection.as_ref()?,
            channels: &self.channels,
        })
    }
}
impl<'a, Q: BootIo, B: BiosIo> Ax200BoardPolicy<'a, Q, B> {
    /// Consume the completed native board owner and keep its OS source.
    /// # Safety
    /// `os` belongs to the exact physical function/platform already kept by
    /// this original owner. A diagnostic/other-device provider cannot satisfy it.
    pub unsafe fn begin_country<O: CountryIo>(
        self,
        os: O,
    ) -> Result<Ax200Country<'a, Q, B, O>, (Box<Self>, O)> {
        if self.phase() != Ax200BoardPolicyPhase::CountryRequired
            || self.first_error().is_some()
            || self.scan.mcc.setup.lari.radio.initialized.boot.state != State::PnvmObserved
        {
            return Err((Box::new(self), os));
        }
        Ok(Ax200Country {
            board: self,
            os: ManuallyDrop::new(os),
            phase: Ax200CountryPhase::NotStarted,
            selection: None,
            request: None,
            ticket: None,
            deadline: None,
            response: None,
            profile: None,
            channels: Vec::new(),
            first_error: None,
        })
    }
}
impl<Q: BootIo, B: BiosIo, O: CountryIo> Drop for Ax200Country<'_, Q, B, O> {
    fn drop(&mut self) {
        if self.board.scan.mcc.setup.lari.radio.initialized.boot.state == State::Stopped {
            // SAFETY: original native stop independently completed. This unique
            // provider has not been moved or dropped, including prior failures.
            unsafe { ManuallyDrop::drop(&mut self.os) };
        }
        // An uncertain native epoch also keeps the original OS service. The
        // nested native/BIOs owners independently enforce their quarantine.
    }
}
impl<Q: BootIo, B: BiosIo, O: CountryIo> Ax200Country<'_, Q, B, O> {
    pub fn phase(&self) -> Ax200CountryPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200CountryError> {
        self.first_error.as_ref()
    }
    pub fn country(&self) -> Option<&Country> {
        self.selection.as_ref().map(|s| &s.country)
    }
    pub fn selection_revision(&self) -> Option<u64> {
        self.selection.as_ref().map(|s| s.revision)
    }
    pub fn request(&self) -> Option<mcc::Request> {
        self.request
    }
    pub fn response(&self) -> Option<&CommandResponse> {
        self.response.as_ref()
    }
    pub fn profile(&self) -> Option<&mcc::Response> {
        self.profile.as_ref()
    }
    pub fn channels(&self) -> &[ChannelObservation] {
        &self.channels
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    pub fn platform_reads(&self) -> &[service::Read] {
        self.board.platform_reads()
    }
    pub fn initialized_nvm(&self) -> &InitializedNvm {
        self.board.initialized_nvm()
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.board.take_firmware_notification()
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        self.board.replenish_completed_receive()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.board.stop() {
            Ok(()) => {
                self.phase = Ax200CountryPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.first_error
                    .get_or_insert_with(|| Ax200CountryError::Boot(error.clone()));
                self.phase = Ax200CountryPhase::Failed;
                Err(error)
            }
        }
    }
    pub(super) fn check_selection(&mut self) -> Result<(), Ax200CountryError> {
        let selection = self.selection.as_ref().ok_or(Ax200CountryError::State)?;
        if !self
            .os
            .current(selection.revision)
            .map_err(Ax200CountryError::Platform)?
        {
            return Err(Ax200CountryError::Revoked);
        }
        Ok(())
    }
    /// Configure the firmware using the explicit OS selection.
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the native
    /// requester/domain under RomBoot's complete publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200CountryPhase, Ax200CountryError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: forwarded caller contract for this original native epoch.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(error, Ax200CountryError::Boot(Error::CommandReclaim(_)))
        {
            self.first_error = Some(error.clone());
            self.phase = Ax200CountryPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200CountryPhase, Ax200CountryError> {
        if self.board.scan.mcc.setup.lari.radio.initialized.boot.state != State::PnvmObserved {
            return Err(Ax200CountryError::State);
        }
        if self.phase == Ax200CountryPhase::NotStarted {
            let selection = self.os.country().map_err(Ax200CountryError::Platform)?;
            self.request = Some(mcc::Request {
                country: selection.country.alpha2(),
                source: OS_MCC_SOURCE,
            });
            self.selection = Some(selection);
            self.check_selection()?;
            let fw = &self
                .board
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .firmware;
            let version = fw
                .command_version(1, 0xc8)
                .ok_or(Ax200CountryError::Schema(mcc::Error::MissingApi))?
                .command_version;
            if version != 1 {
                return Err(Ax200CountryError::Schema(mcc::Error::Version(version)));
            }
            mcc::Response::layout(fw).map_err(Ax200CountryError::Schema)?;
            let bytes = self
                .request
                .unwrap()
                .bytes()
                .map_err(Ax200CountryError::Schema)?;
            // SAFETY: source MCC_UPDATE explicitly permits RF-kill; the chosen
            // country is OS input, never BIOS/firmware-derived permission.
            self.ticket = Some(
                unsafe {
                    self.board
                        .scan
                        .mcc
                        .setup
                        .lari
                        .radio
                        .initialized
                        .boot
                        .submit_command_with_policy(mcc::Request::id(), &bytes, source, true)
                }
                .map_err(Ax200CountryError::Boot)?,
            );
            let options = self.board.scan.mcc.setup.options;
            self.deadline = Some(options.clock.deadline(options.command_timeout_us));
            self.phase = Ax200CountryPhase::Waiting;
            return Ok(self.phase);
        }
        self.check_selection()?;
        if self.phase == Ax200CountryPhase::MacContextRequired {
            self.board
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .poll_one_notification_buffer()
                .map_err(Ax200CountryError::Boot)?;
            return Ok(self.phase);
        }
        let ticket = self.ticket.as_ref().ok_or(Ax200CountryError::State)?;
        let progress = self
            .board
            .scan
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
            return Err(Ax200CountryError::Deadline);
        }
        match progress.map_err(Ax200CountryError::Boot)? {
            CommandProgress::Pending => {
                if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                    return Err(Ax200CountryError::Deadline);
                }
            }
            CommandProgress::Completed(response) => {
                let (command, group) = (response.command, response.group);
                self.response = Some(response);
                self.ticket = None;
                self.deadline = None;
                if command != 0xc8 || group != 1 {
                    return Err(Ax200CountryError::Boot(Error::InitializationResponse {
                        command,
                        group,
                    }));
                }
                let profile = mcc::Response::decode(
                    &self
                        .board
                        .scan
                        .mcc
                        .setup
                        .lari
                        .radio
                        .initialized
                        .boot
                        .firmware,
                    &self.response.as_ref().unwrap().raw,
                )
                .map_err(Ax200CountryError::Schema)?;
                self.profile = Some(profile);
                let profile = self.profile.as_ref().unwrap();
                self.channels = profile
                    .channel_observations(Inventory::Extended)
                    .map_err(Ax200CountryError::Inventory)?;
                let requested = self.request.unwrap().country;
                if profile.country != requested {
                    return Err(Ax200CountryError::CountryMismatch {
                        requested,
                        returned: profile.country,
                    });
                }
                if !matches!(profile.status, 0 | 1) {
                    return Err(Ax200CountryError::Rejected(profile.status));
                }
                if profile.source != OS_MCC_SOURCE {
                    return Err(Ax200CountryError::SourceMismatch(profile.source));
                }
                self.check_selection()?;
                self.phase = Ax200CountryPhase::MacContextRequired;
            }
        }
        Ok(self.phase)
    }
}
