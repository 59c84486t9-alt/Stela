// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2015-2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
//! Exact PCIe AX200/AX201/AX210/AX211 firmware selection from
//! cfg/{22000,ax210,rf-hr,rf-gf}.c, pcie/drv.c and iwl_drv_get_fwname_pre at
//! the pinned Linux source revision.
//! These are observed identity records, not permission to program PCI or DMA.
use super::{
    firmware::{self, Family, Firmware},
    mcc::channel::Inventory,
};
use crate::firmware as resources;
use alloc::{boxed::Box, format, string::String};

const INTEL: u16 = 0x8086;
const AX200: u16 = 0x2723;
const AX210: u16 = 0x2725;
const MAC_QU: u32 = 0x33;
const MAC_CC: u32 = 0x34;
const MAC_QUZ: u32 = 0x35;
const MAC_SO: u32 = 0x37;
const MAC_TY: u32 = 0x42;
const MAC_SOF: u32 = 0x43;
const MAC_MA: u32 = 0x44;
const RF_HR2: u32 = 0x10a;
const RF_GF: u32 = 0x10d;
const CDB: u32 = 1 << 28;
/// `IWL_SUBDEVICE_BW_LIM`, which makes an integrated HR2 an 80 MHz AX203.
const BANDWIDTH_LIMITED: u16 = 0x0200;
/// The subdevice of AX231, whose radio configuration is not GF's.
const AX231: u16 = 0x0294;
const STEP_B: u32 = 1;
const STEP_C: u32 = 2;

/// The radio beside a MAC. It, not the MAC's family, decides the channel
/// table and part of the PHY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rf {
    Hr,
    Gf,
}

/// What a device's `iwl_mac_cfg` says of the platform around its MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    pub integrated: bool,
    /// `xtal_latency`, in microseconds.
    pub xtal_latency: u32,
    pub low_latency_xtal: bool,
    /// `ltr_delay`, which `SOC_FLAGS_LTR_APPLY_DELAY` encodes the same way.
    pub ltr_delay: u32,
    /// `imr_enabled`.
    pub imr: bool,
}

impl Platform {
    pub const AX200: Self = Self::discrete(0);
    pub const AX210: Self = Self::discrete(500);
    const LTR_200US: u32 = 1;
    const LTR_2500US: u32 = 2;
    const LTR_1820US: u32 = 3;

    const fn discrete(xtal_latency: u32) -> Self {
        Self {
            integrated: false,
            xtal_latency,
            low_latency_xtal: false,
            ltr_delay: 0,
            imr: false,
        }
    }
    const fn integrated(xtal_latency: u32, ltr_delay: u32) -> Self {
        Self {
            integrated: true,
            xtal_latency,
            low_latency_xtal: false,
            ltr_delay,
            imr: false,
        }
    }
    const fn long_latency() -> Self {
        Self {
            low_latency_xtal: true,
            ..Self::integrated(12000, Self::LTR_2500US)
        }
    }
    /// `iwl_set_soc_latency`'s flags, for firmware with UMAC scan version 2
    /// or later as every admitted image has.
    pub const fn soc_flags(self) -> u32 {
        !self.integrated as u32 | (self.low_latency_xtal as u32) << 1 | self.ltr_delay << 2
    }
}

/// `iwl_hw_card_ids` for the admitted families.
const fn device(id: u16) -> Option<(Family, Platform)> {
    Some(match id {
        AX200 => (Family::Ax200, Platform::AX200),
        AX210 => (Family::Ax210, Platform::AX210),
        0x02f0 | 0x06f0 => (
            Family::Ax200,
            Platform::integrated(500, Platform::LTR_200US),
        ),
        0x34f0 | 0x3df0 | 0x4df0 => (
            Family::Ax200,
            Platform::integrated(1820, Platform::LTR_1820US),
        ),
        0x43f0 | 0xa0f0 => (Family::Ax200, Platform::long_latency()),
        0x7af0 | 0x7f70 => (
            Family::Ax210,
            Platform::integrated(500, Platform::LTR_200US),
        ),
        0x51f0 | 0x54f0 => (Family::Ax210, Platform::long_latency()),
        0x7a70 | 0x51f1 => (
            Family::Ax210,
            Platform {
                imr: true,
                ..Platform::long_latency()
            },
        ),
        0x2729 | 0x7e40 => (Family::Ax210, Platform::integrated(0, 0)),
        _ => return None,
    })
}

/// `iwl_drv_get_fwname_pre` at the API `cfg/` asks for, with the PNVM Linux
/// finds beside the image.
fn images(mac: u32, step: u32, radio: u32) -> Option<(&'static str, Option<&'static str>)> {
    const TY: &str = "iwlwifi-ty-a0-gf-a0.pnvm";
    const SO: &str = "iwlwifi-so-a0-gf-a0.pnvm";
    const MA: &str = "iwlwifi-ma-b0-gf-a0.pnvm";
    Some(match (mac, step, radio) {
        (MAC_CC, _, RF_HR2) => ("iwlwifi-cc-a0-77.ucode", None),
        (MAC_QU, STEP_B, RF_HR2) => ("iwlwifi-Qu-b0-hr-b0-77.ucode", None),
        (MAC_QU, STEP_C, RF_HR2) => ("iwlwifi-Qu-c0-hr-b0-77.ucode", None),
        (MAC_QUZ, _, RF_HR2) => ("iwlwifi-QuZ-a0-hr-b0-77.ucode", None),
        (MAC_SO | MAC_SOF, _, RF_HR2) => ("iwlwifi-so-a0-hr-b0-89.ucode", None),
        (MAC_MA, STEP_B, RF_HR2) => ("iwlwifi-ma-b0-hr-b0-89.ucode", None),
        (MAC_TY, _, RF_GF) => ("iwlwifi-ty-a0-gf-a0-89.ucode", Some(TY)),
        (MAC_SO | MAC_SOF, _, RF_GF) => ("iwlwifi-so-a0-gf-a0-89.ucode", Some(SO)),
        (MAC_MA, STEP_B, RF_GF) => ("iwlwifi-ma-b0-gf-a0-89.ucode", Some(MA)),
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observed {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub pci_revision: u8,
    /// CSR_HW_REV and CSR_HW_RF_ID values, before normalization.
    pub hardware_revision: u32,
    pub radio_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    UnsupportedPci,
    FailedRead,
    UnsupportedMac(u32),
    UnsupportedRadio(u32),
    /// No firmware is released for this MAC step.
    UnsupportedStep(u32),
    BlankRadioRequiresOtp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    observed: Observed,
    family: Family,
    platform: Platform,
    radio: Rf,
    firmware: &'static str,
    pnvm: Option<&'static str>,
}

impl Profile {
    pub fn select(observed: Observed) -> Result<Self, IdentityError> {
        if observed.vendor != INTEL {
            return Err(IdentityError::UnsupportedPci);
        }
        let (family, platform) = device(observed.device).ok_or(IdentityError::UnsupportedPci)?;
        if observed.hardware_revision == u32::MAX || observed.radio_id == u32::MAX {
            return Err(IdentityError::FailedRead);
        }
        if observed.radio_id == 0 {
            // Linux derives an RF ID from WFPM CRF/OTP observations
            // here. No synthetic default may replace that missing path.
            return Err(IdentityError::BlankRadioRequiresOtp);
        }
        let mac = (observed.hardware_revision & 0xfff0) >> 4;
        let radio = (observed.radio_id & 0x00ff_f000) >> 12;
        let macs: &[u32] = match observed.device {
            AX200 => &[MAC_CC],
            AX210 => &[MAC_TY],
            _ if family == Family::Ax200 => &[MAC_QU, MAC_QUZ],
            _ => &[MAC_SO, MAC_SOF, MAC_MA],
        };
        if !macs.contains(&mac) {
            return Err(IdentityError::UnsupportedMac(mac));
        }
        let fitted = match radio {
            RF_HR2 => mac != MAC_TY,
            RF_GF => family == Family::Ax210,
            _ => false,
        };
        let another_product = platform.integrated
            && match radio {
                RF_HR2 => observed.subsystem_device & BANDWIDTH_LIMITED != 0,
                _ => observed.subsystem_device == AX231,
            };
        if !fitted || another_product || observed.radio_id & CDB != 0 {
            // A CDB radio chooses a distinct gf4 image, and AX203 and AX231
            // their own configurations. Each needs its own complete profile
            // before admission.
            return Err(IdentityError::UnsupportedRadio(observed.radio_id));
        }
        let (firmware, pnvm) = images(mac, observed.hardware_revision & 0xf, radio)
            .ok_or(IdentityError::UnsupportedStep(observed.hardware_revision))?;
        Ok(Self {
            observed,
            family,
            platform,
            radio: if radio == RF_GF { Rf::Gf } else { Rf::Hr },
            firmware,
            pnvm,
        })
    }

    pub fn observed(&self) -> Observed {
        self.observed
    }
    pub fn family(&self) -> Family {
        self.family
    }
    pub fn platform(&self) -> Platform {
        self.platform
    }
    pub fn radio(&self) -> Rf {
        self.radio
    }
    /// `bisr_workaround`, set for the standalone AX200 alone.
    pub fn bisr_workaround(&self) -> bool {
        self.observed.device == AX200
    }
    /// The channel table this radio answers with: `uhb_supported` belongs to
    /// the radio, so an HR radio on an AX210-family MAC has no 6 GHz rows.
    pub fn channel_inventory(&self) -> Inventory {
        match self.radio {
            Rf::Hr => Inventory::Extended,
            Rf::Gf => Inventory::UltraHighBand,
        }
    }
    pub fn firmware_request(&self) -> Request {
        self.request(self.firmware)
    }
    pub fn pnvm_request(&self) -> Option<Request> {
        self.pnvm.map(|name| self.request(name))
    }
    fn request(&self, name: &'static str) -> Request {
        let o = self.observed;
        Request {
            name,
            hardware: format!(
                "pci:{:04x}:{:04x}:{:04x}:{:04x}",
                o.vendor, o.device, o.subsystem_vendor, o.subsystem_device
            ),
            revision: format!(
                "pci-{:02x}-hw-{:08x}-rf-{:08x}",
                o.pci_revision, o.hardware_revision, o.radio_id
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: &'static str,
    pub hardware: String,
    pub revision: String,
}

impl Request {
    pub fn requirement(&self) -> resources::Requirement<'_> {
        resources::Requirement {
            name: self.name,
            target: resources::Target {
                driver: "wifi-intel",
                hardware: &self.hardware,
                revision: &self.revision,
                board: None,
            },
            // An image holds its header and one TLV; a PNVM holds one TLV.
            minimum_bytes: if self.name.ends_with(".ucode") {
                firmware::HEADER_BYTES + firmware::TLV_HEADER_BYTES
            } else {
                firmware::TLV_HEADER_BYTES
            },
        }
    }
}

#[derive(Debug)]
pub enum StageError {
    Resource {
        request: Request,
        error: Box<resources::Error>,
    },
    Firmware {
        request: Request,
        error: firmware::Error,
    },
}

/// Borrowed pre-ROM firmware only. Conditional PNVM/reduced-power resource
/// acquisition must follow current-epoch ALIVE SKU/source policy.
/// The image and its parsed bytes cannot be independently replaced:
/// ```compile_fail
/// use stela_drivers::{firmware::Image,net::wifi::intel::{firmware::Firmware,identity::Staged}};
/// fn forged<'a>(firmware:Firmware<'a>,source:Image<'a>)->Staged<'a> {
///     Staged { firmware,source }
/// }
/// ```
pub struct Staged<'a> {
    firmware: Firmware<'a>,
    source: resources::Image<'a>,
}

impl<'a> Staged<'a> {
    pub fn firmware(&self) -> &Firmware<'a> {
        &self.firmware
    }
    pub fn source(&self) -> resources::Image<'a> {
        self.source
    }
    pub(super) fn into_parts(self) -> (Firmware<'a>, resources::Image<'a>) {
        (self.firmware, self.source)
    }
}

pub fn stage<'a>(
    profile: &Profile,
    provider: &'a dyn resources::Provider,
) -> Result<Staged<'a>, StageError> {
    let request = profile.firmware_request();
    let source = provider
        .load(request.requirement())
        .map_err(|error| StageError::Resource {
            request: request.clone(),
            error: Box::new(error),
        })?;
    let firmware = Firmware::parse(source.bytes())
        .and_then(|fw| {
            fw.require_family(profile.family)?;
            Ok(fw)
        })
        .map_err(|error| StageError::Firmware { request, error })?;
    Ok(Staged { firmware, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmware::{Catalog, Provenance, Provider, Resource};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use sha2::{Digest, Sha256};

    fn observed(device: u16) -> Observed {
        Observed {
            vendor: INTEL,
            device,
            subsystem_vendor: INTEL,
            subsystem_device: 0x0084,
            pci_revision: 0x1a,
            hardware_revision: if device == AX200 { 0x340 } else { 0x420 },
            radio_id: if device == AX200 {
                RF_HR2 << 12
            } else {
                RF_GF << 12
            },
        }
    }
    fn firmware(api: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 88];
        bytes[4..8].copy_from_slice(&0x0a4c_5749u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&api.to_le_bytes());
        bytes.extend(29u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend((1u32 << 20).to_le_bytes());
        bytes
    }

    #[test]
    fn standalone_profiles_preserve_every_raw_binding_field_and_reject_unsupported_variants() {
        for device in [AX200, AX210] {
            let mut o = observed(device);
            o.hardware_revision |= 0xa000_0007;
            o.radio_id |= 0x0000_035a;
            let profile = Profile::select(o).unwrap();
            let request = profile.firmware_request();
            assert_eq!(profile.observed(), o);
            assert!(request.hardware.ends_with(":8086:0084"));
            assert!(request.revision.contains(&format!(
                "hw-{:08x}-rf-{:08x}",
                o.hardware_revision, o.radio_id
            )));
            for field in 0..4 {
                let mut bad = o;
                match field {
                    0 => bad.vendor = 0x1234,
                    1 => bad.hardware_revision = u32::MAX,
                    2 => bad.radio_id = 0,
                    _ => bad.radio_id = u32::MAX,
                };
                assert!(Profile::select(bad).is_err());
            }
        }
        let mut o = observed(AX210);
        o.radio_id |= CDB;
        assert!(matches!(
            Profile::select(o),
            Err(IdentityError::UnsupportedRadio(_))
        ));
        for device in [0x272b, 0x24fd] {
            assert_eq!(
                Profile::select(observed(device)).unwrap_err(),
                IdentityError::UnsupportedPci
            );
        }
    }

    fn integrated(device: u16, revision: u32, radio: u32, subsystem: u16) -> Observed {
        Observed {
            device,
            hardware_revision: revision,
            radio_id: radio << 12,
            subsystem_device: subsystem,
            ..observed(AX200)
        }
    }

    #[test]
    fn integrated_devices_name_their_mac_steps_image_and_platform() {
        for (device, revision, radio, ucode, pnvm, flags, latency) in [
            (
                0x06f0,
                0x331,
                RF_HR2,
                "iwlwifi-Qu-b0-hr-b0-77.ucode",
                None,
                4,
                500,
            ),
            (
                0x02f0,
                0x332,
                RF_HR2,
                "iwlwifi-Qu-c0-hr-b0-77.ucode",
                None,
                4,
                500,
            ),
            (
                0x34f0,
                0x354,
                RF_HR2,
                "iwlwifi-QuZ-a0-hr-b0-77.ucode",
                None,
                12,
                1820,
            ),
            (
                0xa0f0,
                0x332,
                RF_HR2,
                "iwlwifi-Qu-c0-hr-b0-77.ucode",
                None,
                10,
                12000,
            ),
            (
                0x7af0,
                0x370,
                RF_HR2,
                "iwlwifi-so-a0-hr-b0-89.ucode",
                None,
                4,
                500,
            ),
            (
                0x51f0,
                0x370,
                RF_GF,
                "iwlwifi-so-a0-gf-a0-89.ucode",
                Some("iwlwifi-so-a0-gf-a0.pnvm"),
                10,
                12000,
            ),
            (
                0x7e40,
                0x441,
                RF_GF,
                "iwlwifi-ma-b0-gf-a0-89.ucode",
                Some("iwlwifi-ma-b0-gf-a0.pnvm"),
                0,
                0,
            ),
        ] {
            let profile = Profile::select(integrated(device, revision, radio, 0x0070)).unwrap();
            assert_eq!(profile.firmware_request().name, ucode);
            assert_eq!(profile.pnvm_request().map(|request| request.name), pnvm);
            assert_eq!(profile.platform().soc_flags(), flags);
            assert_eq!(profile.platform().xtal_latency, latency);
            assert!(!profile.bisr_workaround());
        }
        assert!(
            Profile::select(integrated(0x7a70, 0x370, RF_GF, 0x0090))
                .unwrap()
                .platform()
                .imr
        );
    }

    #[test]
    fn a_radios_inventory_follows_the_radio_and_not_the_family() {
        let hr = Profile::select(integrated(0x7af0, 0x370, RF_HR2, 0x0070)).unwrap();
        let gf = Profile::select(integrated(0x7af0, 0x370, RF_GF, 0x0070)).unwrap();
        assert_eq!(hr.family(), gf.family());
        assert_eq!(hr.channel_inventory(), Inventory::Extended);
        assert_eq!(gf.channel_inventory(), Inventory::UltraHighBand);
    }

    #[test]
    fn products_without_a_profile_are_refused_by_name_of_what_differs() {
        let unsupported = |o: Observed| Profile::select(o).unwrap_err();
        assert!(matches!(
            unsupported(integrated(0x06f0, 0x332, RF_GF, 0x0070)),
            IdentityError::UnsupportedRadio(_)
        ));
        assert!(matches!(
            unsupported(integrated(0x06f0, 0x332, RF_HR2, 0x0274)),
            IdentityError::UnsupportedRadio(_)
        ));
        assert!(matches!(
            unsupported(integrated(0x7af0, 0x370, RF_GF, AX231)),
            IdentityError::UnsupportedRadio(_)
        ));
        assert_eq!(
            unsupported(integrated(0x06f0, 0x340, RF_HR2, 0x0070)),
            IdentityError::UnsupportedMac(MAC_CC)
        );
        assert_eq!(
            unsupported(integrated(0x06f0, 0x330, RF_HR2, 0x0070)),
            IdentityError::UnsupportedStep(0x330)
        );
        assert_eq!(
            unsupported(integrated(0x7e40, 0x440, RF_GF, 0x0070)),
            IdentityError::UnsupportedStep(0x440)
        );
    }

    struct Observing<'a> {
        catalog: &'a Catalog,
        names: RefCell<Vec<String>>,
    }
    impl Provider for Observing<'_> {
        fn load<'a>(
            &'a self,
            requirement: resources::Requirement<'_>,
        ) -> Result<resources::Image<'a>, resources::Error> {
            self.names.borrow_mut().push(requirement.name.into());
            self.catalog.load(requirement)
        }
    }

    #[test]
    fn pre_rom_staging_defers_conditional_pnvm_until_alive() {
        let profile = Profile::select(observed(AX210)).unwrap();
        let catalog = Catalog::from_handoff(vec![]).unwrap();
        let provider = Observing {
            catalog: &catalog,
            names: RefCell::new(Vec::new()),
        };
        assert!(
            matches!(stage(&profile,&provider),Err(StageError::Resource { request,.. }) if request.name=="iwlwifi-ty-a0-gf-a0-89.ucode")
        );
        assert_eq!(&*provider.names.borrow(), &["iwlwifi-ty-a0-gf-a0-89.ucode"]);
    }

    #[test]
    fn ax210_firmware_only_catalog_can_stage_before_sku_observation() {
        let profile = Profile::select(observed(AX210)).unwrap();
        let request = profile.firmware_request();
        let bytes = firmware(89);
        let hash = Sha256::digest(&bytes).into();
        let catalog = Catalog::from_handoff(vec![Resource {
            name: request.name,
            target: request.requirement().target,
            provenance: Provenance {
                source: "test",
                revision: "immutable",
                member: request.name,
                license: "BSD",
            },
            expected_length: bytes.len(),
            expected_sha256: hash,
            bytes,
        }])
        .unwrap();
        let provider = Observing {
            catalog: &catalog,
            names: RefCell::new(Vec::new()),
        };
        assert_eq!(
            stage(&profile, &provider).unwrap().firmware.api_version(),
            89
        );
        assert_eq!(&*provider.names.borrow(), &["iwlwifi-ty-a0-gf-a0-89.ucode"]);
    }
    #[test]
    fn catalog_identity_and_bytes_are_borrowed_without_variant_fallback() {
        let profile = Profile::select(observed(AX200)).unwrap();
        let request = profile.firmware_request();
        let bytes = firmware(77);
        let pointer = bytes.as_ptr();
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        let catalog = Catalog::from_handoff(vec![Resource {
            name: request.name,
            target: request.requirement().target,
            provenance: Provenance {
                source: "test",
                revision: "immutable",
                member: request.name,
                license: "BSD",
            },
            expected_length: bytes.len(),
            expected_sha256: hash,
            bytes,
        }])
        .unwrap();
        let staged = stage(&profile, &catalog).unwrap();
        assert_eq!(staged.source.bytes().as_ptr(), pointer);
        assert_eq!(staged.firmware.api_version(), 77);
        let mut different = profile.observed();
        different.radio_id ^= 1;
        let different = Profile::select(different).unwrap();
        assert!(
            matches!(stage(&different,&catalog),Err(StageError::Resource {error,..}) if error.kind==resources::ErrorKind::WrongTarget)
        );
    }
}
