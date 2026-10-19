//! Host option study for firmware owned by Stela. This is an explicitly
//! unqualified experiment, not an attestation that every requested object can
//! be supplied. Evidence: restored classic arm64e file offsets in
//! `docs/research/stela-firmware-route.md`. No application/build keys.
use super::{Error, Result, plist::Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Route {
    #[default]
    Stock,
    /// Exercise the original global/Reduced Security path while leaving NOR
    /// flashing and recovery population disabled. SEP load remains mandatory
    /// when AppleSEPManager exists (R 0x2d428, 0x2d51c); do not claim otherwise.
    StelaFirmwareStudy,
}
impl Route {
    pub fn options(self, options: &mut Value) -> Result<()> {
        let Value::Dict(d) = options else {
            return Err(Error::Invalid("restore options dictionary"));
        };
        if self == Self::StelaFirmwareStudy {
            // R 0x26f3c/0x2eef8; R 0x2cf20; R 0x2b878 respectively.
            for key in ["FlashNOR", "InstallRecoveryOS", "RecoveryOSUnpack"] {
                d.insert(key.into(), Value::Boolean(false));
            }
            // R 0x3ccd0..0x3cdfc: Medium without roots selects the global.
            d.insert(
                "SelectMediumSecurityBootPolicy".into(),
                Value::Boolean(true),
            );
            d.insert("PreferPersonalizedManifest".into(), Value::Boolean(false));
        }
        Ok(())
    }
    /// Whether restored may flash the NOR firmware set. The study turns
    /// `FlashNOR` off, which leaves `load_sep_os` as `NORData`'s only
    /// consumer (R 0x2d51c..0x2d660, `docs/research/stela-firmware-route.md`).
    pub fn flashes_nor(self) -> bool {
        self == Self::Stock
    }
    pub fn allows(self, kind: &str) -> bool {
        self == Self::Stock
            || matches!(
                kind,
                "BuildIdentityDict"
                    | "RootTicket"
                    | "SourceBootObjectV4"
                    | "SourceBootObjectV5"
                    | "PersonalizedBootObjectV3"
                    | "SystemImageData"
                    | "SystemImageRootHash"
                    | "SystemImageCanonicalMetadata"
                    | "BootabilityBundle"
                    | "BootabilityBundleV2"
                    | "ReceiptManifest"
                    | "FDRTrustData"
                    | "URLAsset"
                    | "StreamedImageDecryptionKey"
                    | "RestoreAttestation"
                    | "HostSystemTime"
                    | "NORData"
            )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn study_changes_only_evidenced_host_choices_and_does_not_advertise_sep_success() {
        let mut options = Value::dict([
            ("FlashNOR", Value::Boolean(true)),
            ("InstallRecoveryOS", Value::Boolean(true)),
            ("RecoveryOSUnpack", Value::Boolean(true)),
            ("AllowUntetheredRestore", Value::Boolean(false)),
        ]);
        Route::StelaFirmwareStudy.options(&mut options).unwrap();
        for key in [
            "FlashNOR",
            "InstallRecoveryOS",
            "RecoveryOSUnpack",
            "PreferPersonalizedManifest",
        ] {
            assert!(!options.required(key).unwrap().boolean().unwrap());
        }
        assert!(
            options
                .required("SelectMediumSecurityBootPolicy")
                .unwrap()
                .boolean()
                .unwrap()
        );
        assert!(options.get("RecoveryOSMacDFUFactoryInstall").is_none());
        // Requests outside the study refuse when they arrive.
        assert!(Route::StelaFirmwareStudy.allows("NORData"));
        assert!(!Route::StelaFirmwareStudy.flashes_nor());
        assert!(!Route::StelaFirmwareStudy.allows("RecoveryOSLocalPolicy"));
        assert!(Route::StelaFirmwareStudy.allows("RootTicket"));
        assert!(Route::StelaFirmwareStudy.allows("HostSystemTime"));
        assert!(!Route::StelaFirmwareStudy.allows("Unknown"));
    }
}
