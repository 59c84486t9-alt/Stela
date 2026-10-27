//! Host option sets: Apple's stock restore, the recovery-only erase restore
//! of the stick SSD, and the study for firmware owned by Stela. The study is
//! an explicitly unqualified experiment, not an attestation that every
//! requested object can be supplied. Evidence: restored classic arm64e file offsets in
//! `docs/research/stela-firmware-route.md`. No application/build keys.
use super::{Error, Result, plist::Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Route {
    #[default]
    Stock,
    /// Apple's erase restore with its own development-board FDR failure
    /// policy. The caller must separately present a board whose
    /// `HWModelStr` ends in `DEV`; restored checks both that predicate and
    /// this option (26A434 R 0x10014fc84). Its FDR create/recover wrappers
    /// retain and log the original error before continuing. This is an
    /// explicit degraded compatibility profile, not factory provisioning.
    Development,
    /// Apple's erase restore without the macOS system image: the stick SSD
    /// gets its layout, xART and recoveryOS, and macOS is installed later
    /// from recoveryOS. restored fetches the image only in
    /// `restore_system_image`, whose body runs only when the host sends
    /// `AuthInstallRecoveryOSVariant` (R 0x100012ff4, 0x1000131ac ->
    /// 0x100027018), which this route withholds. `SystemImage` false
    /// (R 0x100014ec0, 0x100026ed4) tells the later steps there is no system
    /// volume. Evidence: `docs/research/small-installer-usb.md`.
    Recovery,
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
        if self == Self::Recovery {
            for key in ["SystemImage", "ShouldRestoreSystemImage"] {
                d.insert(key.into(), Value::Boolean(false));
            }
        }
        if self == Self::Recovery {
            // The recovery-only route withholds this overloaded option to
            // suppress SystemImageData. A full development install must keep
            // it even when InstallRecoveryOS is false: restored also uses it
            // to decide whether to restore the macOS system image.
            d.remove("AuthInstallRecoveryOSVariant");
        }
        if self == Self::Development {
            // Original restored checks this Boolean and the independent DEV
            // hardware-model suffix. Do not add FDRSkipSealing: that option
            // is separately AP-ticket-entitled.
            d.insert("FDRIgnoreDevBoardFailures".into(), Value::Boolean(true));
        }
        Ok(())
    }
    /// Whether restored may flash the NOR firmware set. The study turns
    /// `FlashNOR` off, which leaves `load_sep_os` as `NORData`'s only
    /// consumer (R 0x2d51c..0x2d660, `docs/research/stela-firmware-route.md`).
    pub fn flashes_nor(self) -> bool {
        self != Self::StelaFirmwareStudy
    }
    pub fn allows(self, kind: &str) -> bool {
        match self {
            Self::Stock | Self::Development => true,
            // A request for the image means restored took a route the
            // evidence says it cannot: refuse it rather than install macOS.
            Self::Recovery => !matches!(kind, "SystemImageData" | "RecoveryOSASRImage"),
            Self::StelaFirmwareStudy => matches!(
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
            ),
        }
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
    #[test]
    fn recovery_declines_the_system_image_up_front_and_refuses_it_if_asked() {
        let mut options = Value::dict([
            ("InstallRecoveryOS", Value::Boolean(true)),
            ("ShouldRestoreSystemImage", Value::Boolean(true)),
            (
                "AuthInstallRecoveryOSVariant",
                Value::from("macOS Customer"),
            ),
        ]);
        Route::Recovery.options(&mut options).unwrap();
        let flag = |key| options.required(key).unwrap().boolean().unwrap();
        assert!(!flag("SystemImage") && !flag("ShouldRestoreSystemImage"));
        assert!(flag("InstallRecoveryOS"));
        assert!(options.get("AuthInstallRecoveryOSVariant").is_none());
        assert!(!Route::Recovery.allows("SystemImageData"));
        assert!(!Route::Recovery.allows("RecoveryOSASRImage"));
        assert!(Route::Recovery.allows("RecoveryOSLocalPolicy"));
        assert!(Route::Recovery.flashes_nor());
    }

    #[test]
    fn development_route_selects_only_the_original_dev_board_fdr_policy() {
        let mut options = Value::dict([
            ("FlashNOR", Value::Boolean(true)),
            ("ShouldRestoreSystemImage", Value::Boolean(true)),
        ]);
        Route::Development.options(&mut options).unwrap();
        assert!(
            options
                .required("FDRIgnoreDevBoardFailures")
                .unwrap()
                .boolean()
                .unwrap()
        );
        assert!(options.get("FDRSkipSealing").is_none());
        assert!(options.get("FDRMemoryStorePath").is_none());
        assert!(Route::Development.allows("SystemImageData"));
        assert!(Route::Development.flashes_nor());
    }
}
