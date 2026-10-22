// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2015-2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
//! Exact standalone PCIe AX200/AX210 firmware selection from cfg/{22000,ax210}.c,
//! pcie/drv.c and iwl_drv_get_fwname_pre at the pinned Linux source revision.
//! These are observed identity records, not permission to program PCI or DMA.
use super::firmware::{self, Family, Firmware};
use crate::firmware as resources;
use alloc::{boxed::Box, format, string::String};

const INTEL: u16 = 0x8086;
const AX200: u16 = 0x2723;
const AX210: u16 = 0x2725;
const MAC_CC: u32 = 0x34;
const MAC_TY: u32 = 0x42;
const RF_HR2: u32 = 0x10a;
const RF_GF: u32 = 0x10d;
const CDB: u32 = 1 << 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observed {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub pci_revision: u8,
    pub class: [u8; 3],
    /// Actual CSR_HW_REV and CSR_HW_RF_ID values, before normalization.
    pub hardware_revision: u32,
    pub radio_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    UnsupportedPci,
    FailedRead,
    UnsupportedMac(u32),
    UnsupportedRadio(u32),
    BlankRadioRequiresOtp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    observed: Observed,
    family: Family,
}

impl Profile {
    pub fn select(observed: Observed) -> Result<Self, IdentityError> {
        if observed.vendor != INTEL
            || !matches!(observed.device, AX200 | AX210)
            || observed.class != [0x02, 0x80, 0]
        {
            return Err(IdentityError::UnsupportedPci);
        }
        if observed.hardware_revision == u32::MAX || observed.radio_id == u32::MAX {
            return Err(IdentityError::FailedRead);
        }
        if observed.radio_id == 0 {
            // Linux derives an RF ID from actual WFPM CRF/OTP observations
            // here. No synthetic default may replace that missing path.
            return Err(IdentityError::BlankRadioRequiresOtp);
        }
        let mac = (observed.hardware_revision & 0xfff0) >> 4;
        let radio = (observed.radio_id & 0x00ff_f000) >> 12;
        let (family, expected_mac, expected_radio) = match observed.device {
            AX200 => (Family::Ax200, MAC_CC, RF_HR2),
            _ => (Family::Ax210, MAC_TY, RF_GF),
        };
        if mac != expected_mac {
            return Err(IdentityError::UnsupportedMac(mac));
        }
        if radio != expected_radio || (family == Family::Ax210 && observed.radio_id & CDB != 0) {
            // TY + GF CDB chooses a distinct gf4 image, not gf-a0. It needs
            // its own complete firmware/transport profile before admission.
            return Err(IdentityError::UnsupportedRadio(observed.radio_id));
        }
        Ok(Self { observed, family })
    }

    pub fn observed(&self) -> Observed {
        self.observed
    }
    pub fn family(&self) -> Family {
        self.family
    }
    pub fn firmware_request(&self) -> Request {
        self.request(self.family.firmware_name())
    }
    pub fn pnvm_request(&self) -> Option<Request> {
        (self.family == Family::Ax210).then(|| self.request("iwlwifi-ty-a0-gf-a0.pnvm"))
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
            minimum_bytes: if self.name.ends_with(".ucode") { 96 } else { 8 },
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
/// acquisition must follow actual current-epoch ALIVE SKU/source policy.
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
            class: [2, 0x80, 0],
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
            for field in 0..5 {
                let mut bad = o;
                match field {
                    0 => bad.class = [2, 0, 0],
                    1 => bad.vendor = 0x1234,
                    2 => bad.hardware_revision = u32::MAX,
                    3 => bad.radio_id = 0,
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
        for device in [0x06f0, 0x43f0, 0x272b, 0x24fd] {
            assert_eq!(
                Profile::select(observed(device)).unwrap_err(),
                IdentityError::UnsupportedPci
            );
        }
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
    fn pre_rom_staging_defers_conditional_pnvm_until_actual_alive() {
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
