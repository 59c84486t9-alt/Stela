// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Owned on-device NVM unified initialization, after actual ALIVE and PNVM.
//! NVM observation is not regulatory permission, radio setup or association.
use super::super::nvm::{HardwareAddress, Information, Request};
use super::*;
use alloc::boxed::Box;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitializationPhase {
    NotStarted,
    ExtendedConfiguration,
    AccessComplete,
    InitNotification,
    NvmInformation,
    Observed,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitializationProgress {
    Pending(InitializationPhase),
    Observed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitializedNvm {
    pub information: Information,
    pub address: HardwareAddress,
    pub init_complete: FirmwareNotification,
    pub response: CommandResponse,
    /// Actual pre-ROM observation and explicit integration-mode receipt.
    /// NoIwlmei records coordination not performed, never a fabricated ACK.
    pub product_reset: Option<ProductResetObservation>,
}
pub struct UnifiedNvm<'a, Q: BootIo> {
    pub(super) boot: RomBoot<'a, Q>,
    phase: InitializationPhase,
    ticket: Option<CommandTicket>,
    init_complete: Option<FirmwareNotification>,
    receipt: Option<InitializedNvm>,
}
impl<'a, Q: BootIo> RomBoot<'a, Q> {
    /// Consume the exclusive queue owner for source unified initialization
    /// using the device's NVM. External NVM overrides require a separate actual
    /// resource/upload path and are not silently supplied by this method.
    pub fn initialize_on_device_nvm(self) -> UnifiedNvm<'a, Q> {
        UnifiedNvm {
            boot: self,
            phase: InitializationPhase::NotStarted,
            ticket: None,
            init_complete: None,
            receipt: None,
        }
    }
}
impl<'a, Q: BootIo> UnifiedNvm<'a, Q> {
    pub fn phase(&self) -> InitializationPhase {
        self.phase
    }
    pub fn receipt(&self) -> Option<&InitializedNvm> {
        self.receipt.as_ref()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.boot.stop()
    }
    pub fn into_parts(self) -> Result<(RomBoot<'a, Q>, InitializedNvm), Box<Self>> {
        if self.phase != InitializationPhase::Observed {
            return Err(Box::new(self));
        }
        Ok((self.boot, self.receipt.unwrap()))
    }
    /// Advance one source-backed command/notification phase. Pending responses
    /// and notifications retain their exact real queue/requester epoch.
    /// # Safety
    /// Source returns fresh exclusive native pages under the boot owner's
    /// actual retained requester/domain and coherent publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<InitializationProgress, Error> {
        // SAFETY: covered by this function's own safety contract.
        let result = unsafe { self.advance_inner(source) };
        if result.is_err() && !matches!(result, Err(Error::CommandReclaim(_))) {
            self.phase = InitializationPhase::Failed;
        }
        result
    }
    unsafe fn submit(&mut self, request: Request, source: &dyn PageSource) -> Result<(), Error> {
        // SAFETY: covered by this function's own safety contract.
        self.ticket = Some(unsafe {
            self.boot
                .submit_command_with_policy(request.id(), &request.payload(), source, true)
        }?);
        Ok(())
    }
    fn response(&mut self, request: Request) -> Result<Option<CommandResponse>, Error> {
        match self
            .boot
            .poll_command(self.ticket.as_ref().ok_or(Error::State)?)?
        {
            CommandProgress::Pending => Ok(None),
            CommandProgress::Completed(response) => {
                self.ticket = None;
                if response.group != request.id().group || response.command != request.id().opcode {
                    return Err(Error::InitializationResponse {
                        command: response.command,
                        group: response.group,
                    });
                }
                Ok(Some(response))
            }
        }
    }
    fn capture_init_complete(&mut self) {
        // Select actual canonical bytes without converting/restoring unrelated
        // traffic through caller-mutable public diagnostics.
        if self.init_complete.is_none() {
            self.init_complete = self.boot.take_matching_notification(4, 0);
        }
    }
    fn confirm_requester(&mut self) -> Result<(), Error> {
        let observed = self.boot.profile.observed();
        if self.boot.read_register(0x28)? != observed.hardware_revision
            || self.boot.read_register(0x9c)? != observed.radio_id
        {
            return Err(Error::IdentityChanged);
        }
        Ok(())
    }
    fn mac_words(&mut self, first: u32, second: u32) -> Result<[u32; 2], Error> {
        self.confirm_requester()?;
        // MAC CSRs contain arbitrary data. All-FF or A5/5A patterns here
        // are not control-register disappearance sentinels: the source
        // decodes an invalid strap and then tries the real OTP words.
        let words = [
            self.boot.io().read32(first)?,
            self.boot.io().read32(second)?,
        ];
        self.confirm_requester()?;
        Ok(words)
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<InitializationProgress, Error> {
        use InitializationPhase::*;
        match self.phase {
            NotStarted => {
                if self.boot.state != State::PnvmObserved {
                    return Err(Error::State);
                }
                // Qualify the exact response ABI before publishing even the
                // first command. Reading zero channels grants no RF authority.
                let v = self
                    .boot
                    .firmware
                    .command_version(12, 2)
                    .ok_or(super::super::nvm::Error::MissingApi)?;
                if !matches!(v.notification_version, 3..=5) {
                    return Err(super::super::nvm::Error::UnsupportedVersion(
                        v.notification_version,
                    )
                    .into());
                }
                if self.boot.firmware.supports_api(48) != (v.notification_version >= 4) {
                    return Err(super::super::nvm::Error::InconsistentApi.into());
                }
                // SAFETY: covered by this function's own safety contract.
                unsafe {
                    self.submit(Request::ExtendedConfiguration, source)?;
                }
                self.phase = ExtendedConfiguration;
            }
            ExtendedConfiguration => {
                if self.response(Request::ExtendedConfiguration)?.is_some() {
                    // SAFETY: covered by this function's own safety contract.
                    unsafe {
                        self.submit(Request::AccessComplete, source)?;
                    }
                    self.phase = AccessComplete;
                }
            }
            AccessComplete => {
                if self.response(Request::AccessComplete)?.is_some() {
                    self.phase = InitNotification;
                    self.capture_init_complete();
                }
            }
            InitNotification => {
                self.capture_init_complete();
                if self.init_complete.is_none() {
                    self.boot.poll_notification_buffers(true)?;
                    self.capture_init_complete();
                }
                if self.init_complete.is_some() {
                    // SAFETY: covered by this function's own safety contract.
                    unsafe {
                        self.submit(Request::GetInformation, source)?;
                    }
                    self.phase = NvmInformation;
                }
            }
            NvmInformation => {
                if let Some(response) = self.response(Request::GetInformation)? {
                    let information = Information::decode(&self.boot.firmware, &response.raw)?;
                    let strap = self.mac_words(0x388, 0x38c)?;
                    let decoded = HardwareAddress::decode(strap[0], strap[1]);
                    let otp = if HardwareAddress::valid(decoded) {
                        None
                    } else {
                        Some(self.mac_words(0x380, 0x384)?)
                    };
                    let address = HardwareAddress::select(strap, otp)?;
                    self.receipt = Some(InitializedNvm {
                        information,
                        address,
                        response,
                        init_complete: self.init_complete.take().ok_or(Error::State)?,
                        product_reset: self.boot.product_reset_observation(),
                    });
                    self.phase = Observed;
                }
            }
            Observed => return Ok(InitializationProgress::Observed),
            Failed => return Err(Error::State),
        }
        Ok(if self.phase == Observed {
            InitializationProgress::Observed
        } else {
            InitializationProgress::Pending(self.phase)
        })
    }
}
