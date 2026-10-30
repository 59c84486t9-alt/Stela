// SPDX-License-Identifier: MIT
//! Explicit native consumer initialization, separate from raw USB attachment.
//! The kept result owns metadata only and never extends a provider borrow.
use super::{Error, Hci, Io, ath3k, broadcom, intel, mediatek, qca, realtek};
use crate::firmware::Provider;
use alloc::boxed::Box;
use core::fmt;

/// Device-specific observed initialization evidence, never universal radio or
/// guest readiness. Inspect transport lifecycle separately before using HCI.
#[derive(Debug)]
pub enum InitializationReport {
    Atheros(ath3k::runtime::OwnedReport),
    Qualcomm(qca::OwnedReport),
    Broadcom(broadcom::OwnedReport),
    Intel(intel::OwnedReport),
    Realtek(realtek::OwnedReport),
    MediaTek(mediatek::OwnedReport),
}
/// Typed failure. Each initializer preserves exact resource/target errors,
/// HCI controller status, transport/cleanup errors and partial receipts.
#[derive(Debug)]
pub enum InitializationError {
    Atheros(ath3k::runtime::Error),
    UnsupportedDevice {
        vendor: u16,
        product: u16,
        revision: u16,
    },
    Qualcomm(qca::Error),
    Broadcom(broadcom::Error),
    Intel(intel::Error),
    Realtek(realtek::Error),
    MediaTek(mediatek::Error),
    Transport(Error),
}
impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native USB Bluetooth initialization {self:?}")
    }
}
impl core::error::Error for InitializationError {}

impl<B: Io> Hci<B> {
    /// Explicitly initialize an attached native controller against exact supplied
    /// resources. A provider/catalog is borrowed only for this call; the stored
    /// result owns identities and receipt metadata, never firmware bytes.
    ///
    /// Exactly one attempt is held per attachment. Repeated calls return
    /// that historical result without issuing commands or recording new resource
    /// requests, even with another provider/platform input. Failed candidates
    /// require a fresh generic rebind to retry. Unknown devices remain raw and
    /// unverified and return UnsupportedDevice without initializer commands.
    /// A kept success does not supersede subsequent transport lifecycle or
    /// establish image authenticity for RunningUnknown, radio or guest services.
    pub fn initialize_with_provider(
        &mut self,
        provider: &dyn Provider,
        platform: intel::PlatformInputs,
    ) -> Result<&InitializationReport, &InitializationError> {
        if self.initialization.is_none() {
            let result = self.initialize_once(provider, platform);
            self.initialization = Some(Box::new(result));
        }
        self.initialization().unwrap()
    }
    /// Historical result of the explicit native initialization attempt. None
    /// means no attempt, including every newly attached raw transport.
    pub fn initialization(&self) -> Option<Result<&InitializationReport, &InitializationError>> {
        self.initialization.as_deref().map(Result::as_ref)
    }
    fn initialize_once(
        &mut self,
        provider: &dyn Provider,
        platform: intel::PlatformInputs,
    ) -> Result<InitializationReport, InitializationError> {
        self.open().map_err(InitializationError::Transport)?;
        if ath3k::is_runtime_candidate(self.binding.device()) {
            return ath3k::runtime::initialize(self, provider)
                .map(InitializationReport::Atheros)
                .map_err(InitializationError::Atheros);
        }
        if qca::is_candidate(self.binding.device()) {
            return qca::initialize(self, provider)
                .map(InitializationReport::Qualcomm)
                .map_err(InitializationError::Qualcomm);
        }
        if broadcom::is_candidate(self.binding.device()) {
            return broadcom::initialize(self, provider)
                .map(InitializationReport::Broadcom)
                .map_err(InitializationError::Broadcom);
        }
        if realtek::is_candidate(self.binding.device()) {
            return realtek::initialize(self, provider)
                .map(InitializationReport::Realtek)
                .map_err(InitializationError::Realtek);
        }
        if mediatek::is_candidate(self.binding.device()) {
            return mediatek::initialize(self, provider)
                .map(InitializationReport::MediaTek)
                .map_err(InitializationError::MediaTek);
        }
        if !intel::is_candidate(self.binding.device()) {
            let descriptor = &self.binding.device().descriptor;
            return Err(InitializationError::UnsupportedDevice {
                vendor: u16::from_le_bytes([descriptor[8], descriptor[9]]),
                product: u16::from_le_bytes([descriptor[10], descriptor[11]]),
                revision: u16::from_le_bytes([descriptor[12], descriptor[13]]),
            });
        }
        intel::initialize_with_platform(self, provider, platform)
            .map(|report| InitializationReport::Intel(report.into()))
            .map_err(InitializationError::Intel)
    }
}
