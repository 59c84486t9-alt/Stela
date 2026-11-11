// SPDX-License-Identifier: GPL-2.0-or-later
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
        match *self {
            Self::UnsupportedDevice {
                vendor,
                product,
                revision,
            } => {
                write!(
                    f,
                    "unsupported USB Bluetooth controller {vendor:04x}:{product:04x} \
                     revision {revision:04x}"
                )?;
                if let Some(name) = vendor_name(vendor) {
                    write!(f, " ({name})")?;
                }
                f.write_str(": no vendor setup here takes it, so it stays off")
            }
            _ => write!(f, "native USB Bluetooth initialization {self:?}"),
        }
    }
}

/// The USB vendors whose IDs Bluetooth controllers commonly carry: chip
/// makers and the module makers whose IDs Linux btusb lists.
fn vendor_name(vendor: u16) -> Option<&'static str> {
    Some(match vendor {
        0x03f0 => "HP",
        0x043e => "LG",
        0x0489 => "Foxconn",
        0x04ca => "Lite-On",
        0x04f2 => "Chicony",
        0x050d => "Belkin",
        0x05ac => "Apple",
        0x0930 => "Toshiba",
        0x0a12 => "Cambridge Silicon Radio",
        0x0a5c => "Broadcom",
        0x0b05 => "ASUS",
        0x0bda => "Realtek",
        0x0cf3 => "Qualcomm Atheros",
        0x0e8d => "MediaTek",
        0x105b => "Foxconn",
        0x13d3 => "IMC Networks",
        0x1286 => "Marvell",
        0x2357 => "TP-Link",
        0x33fa => "Actions",
        0x413c => "Dell",
        0x8087 => "Intel",
        _ => return None,
    })
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
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
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

#[cfg(test)]
mod tests {
    use super::InitializationError;
    use alloc::string::ToString;

    #[test]
    fn an_unsupported_controller_is_named_by_its_ids_and_vendor() {
        let error = InitializationError::UnsupportedDevice {
            vendor: 0x0a12,
            product: 0x0001,
            revision: 0x8891,
        };
        assert_eq!(
            error.to_string(),
            "unsupported USB Bluetooth controller 0a12:0001 revision 8891 \
             (Cambridge Silicon Radio): no vendor setup here takes it, so it stays off"
        );
        let unknown = InitializationError::UnsupportedDevice {
            vendor: 0x1234,
            product: 0x5678,
            revision: 0x0100,
        };
        assert_eq!(
            unknown.to_string(),
            "unsupported USB Bluetooth controller 1234:5678 revision 0100: no vendor setup \
             here takes it, so it stays off"
        );
    }
}
