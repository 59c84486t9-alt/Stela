// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2021-2026 Intel Corporation
//! Pure owned-observation/resource and packed-package contracts for Intel Wi-Fi
//! UEFI data from fw/uefi.{c,h} and PNVM source policy from fw/pnvm.c.
//! Actual GetVariable calls and permanent EBS/root-switch storage belong to boot.
//! Raw length/hash/provenance integrity does not authenticate a vendor signature
//! or grant redistribution rights, calibration validity or regulatory permission.
use super::{firmware::Family, identity::Profile};
use crate::firmware as resources;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use sha2::{Digest, Sha256};

pub const WIFI_GUID: &str = "92daaf2f-c02b-455b-b2ec-f5a3594f4aea";
pub const MAX_VARIABLE_BYTES: usize = 4 * 1024 * 1024 + 14;
const NOT_FOUND: u64 = (1 << 63) | 14;
const ORIGIN: &str = "UEFI GetVariable 92daaf2f-c02b-455b-b2ec-f5a3594f4aea";
const DATA_LICENSE: &str = "LicenseRef-Local-UEFI-Observation";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variable {
    OemPnvm,
    ReducedPower,
}
impl Variable {
    pub fn name(self) -> &'static str {
        match self {
            Self::OemPnvm => "UefiCnvWlanOemSignedPnvm",
            Self::ReducedPower => "UefiCnvWlanReducedPower",
        }
    }
    pub fn resource_name(self) -> &'static str {
        match self {
            Self::OemPnvm => "intel/uefi/UefiCnvWlanOemSignedPnvm.bin",
            Self::ReducedPower => "intel/uefi/UefiCnvWlanReducedPower.bin",
        }
    }
    pub fn requirement(self) -> resources::Requirement<'static> {
        resources::Requirement {
            name: self.resource_name(),
            target: resources::Target {
                driver: "wifi-intel",
                hardware: "uefi:92daaf2f-c02b-455b-b2ec-f5a3594f4aea",
                revision: self.name(),
                board: None,
            },
            minimum_bytes: 14,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Probe,
    Read,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Observation {
    #[default]
    NotCaptured,
    Absent {
        stage: Stage,
        status: u64,
        reported_bytes: Option<u64>,
    },
    Failed {
        stage: Stage,
        status: u64,
        reported_bytes: Option<u64>,
    },
    BoundExceeded {
        stage: Stage,
        status: u64,
        reported_bytes: u64,
    },
    Present {
        attributes: u32,
        bytes: u64,
        sha256: [u8; 32],
        probe_reported_bytes: Option<u64>,
    },
}
impl Observation {
    pub fn from_error(stage: Stage, status: u64, reported_bytes: Option<u64>) -> Self {
        if status == NOT_FOUND {
            Self::Absent {
                stage,
                status,
                reported_bytes,
            }
        } else {
            Self::Failed {
                stage,
                status,
                reported_bytes,
            }
        }
    }
    /// Bound a size observed from the real UEFI query *before* allocating.
    /// Zero is returned intact for an actual successful empty variable; it is
    /// never synthesized to represent an error or absence. No retries occur here.
    pub fn bounded_bytes(stage: Stage, status: u64, reported_bytes: u64) -> Result<usize, Self> {
        if reported_bytes > MAX_VARIABLE_BYTES as u64 {
            return Err(Self::BoundExceeded {
                stage,
                status,
                reported_bytes,
            });
        }
        Ok(reported_bytes as usize)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    pub oem_pnvm: Observation,
    pub reduced_power: Observation,
}
impl Observations {
    pub fn get(self, variable: Variable) -> Observation {
        match variable {
            Variable::OemPnvm => self.oem_pnvm,
            Variable::ReducedPower => self.reduced_power,
        }
    }
}

fn revision(sha: [u8; 32], attributes: u32) -> String {
    let digest: String = sha.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{digest};attributes:{attributes:08x}")
}
/// Temporary pre-EBS ownership only. Boot must move these bytes through its
/// canonical permanent firmware-handoff path before any root switch/EBS. This
/// object must never be mistaken for protected post-EBS firmware storage.
pub struct CapturedVariable {
    variable: Variable,
    observation: Observation,
    revision: String,
    bytes: Option<Vec<u8>>,
}
impl CapturedVariable {
    pub fn from_variable(
        variable: Variable,
        bytes: Vec<u8>,
        attributes: u32,
        probe_reported_bytes: Option<u64>,
    ) -> Result<Self, Observation> {
        Observation::bounded_bytes(Stage::Read, 0, bytes.len() as u64)?;
        let sha256 = Sha256::digest(&bytes).into();
        let observation = Observation::Present {
            attributes,
            bytes: bytes.len() as u64,
            sha256,
            probe_reported_bytes,
        };
        Ok(Self {
            variable,
            observation,
            revision: revision(sha256, attributes),
            bytes: Some(bytes),
        })
    }
    pub fn observation(&self) -> Observation {
        self.observation
    }
    /// Construct exactly one canonical resource, moving the original buffer
    /// without cloning it. Descriptor borrows need survive Catalog construction
    /// only; boot still owns conversion to permanent reserved-page resources.
    pub fn take_resource(&mut self) -> Option<resources::Resource<'_>> {
        let bytes = self.bytes.take()?;
        let Observation::Present { sha256, .. } = self.observation else {
            unreachable!("constructed from actual success")
        };
        Some(resources::Resource {
            name: self.variable.resource_name(),
            target: self.variable.requirement().target,
            provenance: resources::Provenance {
                source: ORIGIN,
                revision: &self.revision,
                member: self.variable.name(),
                license: DATA_LICENSE,
            },
            expected_length: bytes.len(),
            expected_sha256: sha256,
            bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    Size,
    Unobserved,
    Absent,
    FailedObservation,
    ObservationMismatch,
}
/// The donor's packed 14-byte wrapper. Header fields remain original metadata:
/// Linux consumes the actual returned variable length, not an invented total
/// size/revision/SKU-count whitelist. Bare TLV parsers validate its payload.
#[derive(Clone, Copy, Debug)]
pub struct Package<'a> {
    raw: &'a [u8],
    revision: u8,
    total_size: u32,
    skus: u8,
    reserved: [u32; 2],
}
impl<'a> Package<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PackageError> {
        if !(14..=MAX_VARIABLE_BYTES).contains(&bytes.len()) {
            return Err(PackageError::Size);
        }
        let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        Ok(Self {
            raw: bytes,
            revision: bytes[0],
            total_size: word(1),
            skus: bytes[5],
            reserved: [word(6), word(10)],
        })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn payload(self) -> &'a [u8] {
        &self.raw[14..]
    }
    pub fn revision(self) -> u8 {
        self.revision
    }
    pub fn declared_total_size(self) -> u32 {
        self.total_size
    }
    pub fn declared_skus(self) -> u8 {
        self.skus
    }
    pub fn reserved(self) -> [u32; 2] {
        self.reserved
    }
}
#[derive(Debug)]
pub enum LoadError {
    Package(PackageError),
    Resource(Box<resources::Error>),
}
/// Borrowed canonical image plus original package metadata. No UEFI read,
/// alternate Provider or image-byte copy happens in this post-EBS consumer.
#[derive(Debug)]
pub struct LoadedPackage<'a> {
    pub image: resources::Image<'a>,
    pub package: Package<'a>,
}
pub fn load<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<LoadedPackage<'a>, LoadError> {
    let (attributes, bytes, sha256) = match observation {
        Observation::Present {
            attributes,
            bytes,
            sha256,
            ..
        } => (attributes, bytes, sha256),
        Observation::NotCaptured => return Err(LoadError::Package(PackageError::Unobserved)),
        Observation::Absent { .. } => return Err(LoadError::Package(PackageError::Absent)),
        _ => return Err(LoadError::Package(PackageError::FailedObservation)),
    };
    let image = provider
        .load(variable.requirement())
        .map_err(|e| LoadError::Resource(Box::new(e)))?;
    let p = image.provenance();
    if image.bytes().len() as u64 != bytes
        || image.sha256() != sha256
        || p.source != ORIGIN
        || p.revision != revision(sha256, attributes)
        || p.member != variable.name()
        || p.license != DATA_LICENSE
    {
        return Err(LoadError::Package(PackageError::ObservationMismatch));
    }
    let package = Package::parse(image.bytes()).map_err(LoadError::Package)?;
    Ok(LoadedPackage { image, package })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PnvmSource {
    None,
    External,
    Bios { external_fallback: bool },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostAlivePlan {
    pub pnvm: PnvmSource,
    pub observe_reduced_power: bool,
    pub pnvm_completion_required: bool,
}
/// Pure source policy from an actual, valid current-epoch ALIVE SKU. It does
/// not convert an absent/failed BIOS observation into an empty/default image.
/// Fallback follows failure to acquire BIOS data, not failure to match a SKU
/// inside a successfully acquired BIOS image.
pub fn post_alive_plan(profile: &Profile, sku: [u32; 3]) -> PostAlivePlan {
    if sku == [0; 3] {
        return PostAlivePlan {
            pnvm: PnvmSource::None,
            observe_reduced_power: false,
            pnvm_completion_required: false,
        };
    }
    let external = profile.family() == Family::Ax210;
    let pnvm = if sku[2] != 0 {
        PnvmSource::Bios {
            external_fallback: external,
        }
    } else if external {
        PnvmSource::External
    } else {
        PnvmSource::None
    };
    PostAlivePlan {
        pnvm,
        observe_reduced_power: true,
        pnvm_completion_required: true,
    }
}

#[cfg(test)]
mod tests {
    use super::super::identity::Observed;
    use super::*;
    use resources::{Catalog, ErrorKind};
    fn profile(ax210: bool) -> Profile {
        Profile::select(Observed {
            vendor: 0x8086,
            device: if ax210 { 0x2725 } else { 0x2723 },
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
            class: [2, 0x80, 0],
            hardware_revision: if ax210 { 0x420 } else { 0x340 },
            radio_id: if ax210 { 0x10d000 } else { 0x10a000 },
        })
        .unwrap()
    }
    fn package() -> Vec<u8> {
        vec![
            7, 0x78, 0x56, 0x34, 0x12, 3, 1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb,
        ]
    }
    #[test]
    fn captured_resource_moves_bytes_once_and_checks_actual_observation() {
        for variable in [Variable::OemPnvm, Variable::ReducedPower] {
            let bytes = package();
            let original = bytes.as_ptr();
            let mut captured =
                CapturedVariable::from_variable(variable, bytes, 7, Some(123)).unwrap();
            let observation = captured.observation();
            let resource = captured.take_resource().unwrap();
            assert_eq!(resource.bytes.as_ptr(), original);
            assert_eq!(resource.target, variable.requirement().target);
            assert_eq!(resource.provenance.license, DATA_LICENSE);
            let catalog = Catalog::from_handoff(vec![resource]).unwrap();
            assert!(captured.take_resource().is_none());
            let loaded = load(variable, observation, &catalog).unwrap();
            assert_eq!(loaded.package.raw().as_ptr(), original);
            assert_eq!(loaded.package.payload(), [0xaa, 0xbb]);
            assert_eq!(loaded.package.revision(), 7);
            assert_eq!(loaded.package.declared_total_size(), 0x12345678);
            assert_eq!(loaded.package.declared_skus(), 3);
            assert_eq!(loaded.package.reserved(), [0x04030201, 0x08070605]);
            let Observation::Present {
                attributes,
                bytes,
                sha256,
                probe_reported_bytes,
            } = observation
            else {
                panic!()
            };
            for changed in [
                Observation::Present {
                    attributes: attributes ^ 1,
                    bytes,
                    sha256,
                    probe_reported_bytes,
                },
                Observation::Present {
                    attributes,
                    bytes: bytes + 1,
                    sha256,
                    probe_reported_bytes,
                },
                Observation::Present {
                    attributes,
                    bytes,
                    sha256: [0; 32],
                    probe_reported_bytes,
                },
            ] {
                assert!(matches!(
                    load(variable, changed, &catalog),
                    Err(LoadError::Package(PackageError::ObservationMismatch))
                ));
            }
            assert!(
                matches!(load(if variable==Variable::OemPnvm {Variable::ReducedPower} else {Variable::OemPnvm}, observation,&catalog),Err(LoadError::Resource(e)) if e.kind==ErrorKind::Missing)
            );
        }
    }
    #[test]
    fn errors_absence_bounds_empty_and_collision_are_distinct() {
        assert!(matches!(
            Observation::from_error(Stage::Probe, NOT_FOUND, None),
            Observation::Absent { .. }
        ));
        assert!(matches!(
            Observation::from_error(Stage::Read, (1 << 63) | 5, Some(99)),
            Observation::Failed {
                reported_bytes: Some(99),
                ..
            }
        ));
        assert!(matches!(
            Observation::bounded_bytes(Stage::Probe, 0, MAX_VARIABLE_BYTES as u64 + 1),
            Err(Observation::BoundExceeded { .. })
        ));
        assert_eq!(Observation::bounded_bytes(Stage::Probe, 0, 0), Ok(0));
        let empty = Catalog::from_handoff(vec![]).unwrap();
        for (observation, expected) in [
            (Observation::NotCaptured, PackageError::Unobserved),
            (
                Observation::from_error(Stage::Read, NOT_FOUND, None),
                PackageError::Absent,
            ),
            (
                Observation::from_error(Stage::Read, 9, None),
                PackageError::FailedObservation,
            ),
        ] {
            assert!(
                matches!(load(Variable::OemPnvm,observation,&empty),Err(LoadError::Package(e)) if e==expected)
            );
        }
        let mut captured =
            CapturedVariable::from_variable(Variable::OemPnvm, vec![], 7, None).unwrap();
        let observation = captured.observation();
        assert!(matches!(observation, Observation::Present { bytes: 0, .. }));
        let catalog = Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap();
        assert!(
            matches!(load(Variable::OemPnvm,observation,&catalog),Err(LoadError::Resource(e)) if matches!(e.kind,ErrorKind::Truncated{actual:0,..}))
        );
        for n in 0..14 {
            assert_eq!(Package::parse(&vec![0; n]).unwrap_err(), PackageError::Size);
        }
        let mut a = CapturedVariable::from_variable(Variable::OemPnvm, package(), 7, None).unwrap();
        let mut b = CapturedVariable::from_variable(Variable::OemPnvm, package(), 7, None).unwrap();
        assert!(
            matches!(Catalog::from_handoff(vec![a.take_resource().unwrap(),b.take_resource().unwrap()]),Err(e) if e.kind==ErrorKind::Duplicate)
        );
    }
    #[test]
    fn configured_platform_shadow_and_provenance_changes_refuse() {
        for field in 0..4 {
            let mut captured =
                CapturedVariable::from_variable(Variable::OemPnvm, package(), 7, None).unwrap();
            let observation = captured.observation();
            let mut resource = captured.take_resource().unwrap();
            match field {
                0 => resource.provenance.source = "configured",
                1 => resource.provenance.member = "other",
                2 => resource.provenance.license = "MIT",
                _ => resource.provenance.revision = "other",
            }
            let catalog = Catalog::from_handoff(vec![resource]).unwrap();
            assert!(matches!(
                load(Variable::OemPnvm, observation, &catalog),
                Err(LoadError::Package(PackageError::ObservationMismatch))
            ));
        }
        let mut a = CapturedVariable::from_variable(Variable::OemPnvm, package(), 7, None).unwrap();
        let mut different = package();
        different.push(0);
        let mut b = CapturedVariable::from_variable(Variable::OemPnvm, different, 7, None).unwrap();
        assert!(
            matches!(Catalog::from_handoff(vec![a.take_resource().unwrap(),b.take_resource().unwrap()]),Err(e) if e.kind==ErrorKind::Conflict)
        );
    }
    #[test]
    fn actual_sku_source_policy_has_no_default_image() {
        for ax210 in [false, true] {
            let p = profile(ax210);
            assert_eq!(
                post_alive_plan(&p, [0; 3]),
                PostAlivePlan {
                    pnvm: PnvmSource::None,
                    observe_reduced_power: false,
                    pnvm_completion_required: false
                }
            );
            assert_eq!(
                post_alive_plan(&p, [1, 2, 0]),
                PostAlivePlan {
                    pnvm: if ax210 {
                        PnvmSource::External
                    } else {
                        PnvmSource::None
                    },
                    observe_reduced_power: true,
                    pnvm_completion_required: true
                }
            );
            assert_eq!(
                post_alive_plan(&p, [1, 2, 3]),
                PostAlivePlan {
                    pnvm: PnvmSource::Bios {
                        external_fallback: ax210
                    },
                    observe_reduced_power: true,
                    pnvm_completion_required: true
                }
            );
        }
    }
}
