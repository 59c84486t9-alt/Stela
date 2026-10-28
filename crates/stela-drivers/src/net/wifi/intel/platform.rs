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

pub const WIFI_BT_GUID: &str = "e65d8884-d4af-4b20-8d03-772ecc3da531";
pub const WIFI_GUID: &str = "92daaf2f-c02b-455b-b2ec-f5a3594f4aea";
pub const MAX_VARIABLE_BYTES: usize = 4 * 1024 * 1024 + 14;
/// EFI_NOT_FOUND, the status of a variable the firmware does not have.
pub const NOT_FOUND: u64 = (1 << 63) | 14;
const DATA_LICENSE: &str = "LicenseRef-Local-UEFI-Observation";

/// The initial AX200/AX210 raw capture set. This describes observations only;
/// BIOS authority/GLAI, table revisions and firmware capabilities are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Variable {
    OemPnvm,
    ReducedPower,
    Step,
    Wrds,
    Ewrd,
    Wgds,
    Ppag,
    Wrdd,
    GeneralConfiguration,
    Wbem,
    Eckv,
    Wtas,
    Splc,
    PhyFilters,
    Sgom,
    Uats,
}
#[derive(Clone, Copy, Debug)]
pub struct VariableDescriptor {
    pub variable: Variable,
    pub name: &'static str,
    pub resource_name: &'static str,
    pub guid: &'static str,
    pub minimum_bytes: usize,
    /// Bounded native collection limit, not a schema-validity declaration.
    pub maximum_bytes: usize,
}
macro_rules! descriptor {
    ($variable:ident, $name:literal, $guid:ident, $minimum:expr, $maximum:expr) => {
        VariableDescriptor {
            variable: Variable::$variable,
            name: $name,
            resource_name: concat!("intel/uefi/", $name, ".bin"),
            guid: $guid,
            minimum_bytes: $minimum,
            maximum_bytes: $maximum,
        }
    };
}
/// Sole descriptor table for raw identity, lookup minima and collection bounds.
/// The 4096-byte native limits deliberately preserve a separate BoundExceeded
/// observation; they are not Linux limits or permission to treat data as absent.
pub const VARIABLE_DESCRIPTORS: [VariableDescriptor; 16] = [
    descriptor!(
        OemPnvm,
        "UefiCnvWlanOemSignedPnvm",
        WIFI_GUID,
        14,
        MAX_VARIABLE_BYTES
    ),
    descriptor!(
        ReducedPower,
        "UefiCnvWlanReducedPower",
        WIFI_GUID,
        14,
        MAX_VARIABLE_BYTES
    ),
    descriptor!(
        Step,
        "UefiCnvCommonSTEP",
        WIFI_BT_GUID,
        6,
        MAX_VARIABLE_BYTES
    ),
    descriptor!(Wrds, "UefiCnvWlanWRDS", WIFI_GUID, 49, 53),
    descriptor!(Ewrd, "UefiCnvWlanEWRD", WIFI_GUID, 141, 153),
    descriptor!(Wgds, "UefiCnvWlanWGDS", WIFI_GUID, 74, 98),
    descriptor!(Ppag, "UefiCnvWlanPPAG", WIFI_GUID, 27, 4096),
    descriptor!(Wrdd, "UefiCnvWlanWRDD", WIFI_GUID, 5, 4096),
    descriptor!(
        GeneralConfiguration,
        "UefiCnvWlanGeneralCfg",
        WIFI_GUID,
        129,
        4096
    ),
    descriptor!(Wbem, "UefiCnvWlanWBEM", WIFI_GUID, 5, 4096),
    descriptor!(Eckv, "UefiCnvCommonECKV", WIFI_BT_GUID, 5, 4096),
    descriptor!(Wtas, "UefiCnvWlanWTAS", WIFI_GUID, 38, 4096),
    descriptor!(Splc, "UefiCnvWlanSPLC", WIFI_GUID, 5, 4096),
    descriptor!(PhyFilters, "WPFC", WIFI_GUID, 17, 4096),
    descriptor!(Sgom, "UefiCnvWlanSarGeoOffsetMapping", WIFI_GUID, 339, 4096),
    descriptor!(Uats, "CnvUefiWlanUATS", WIFI_GUID, 339, 4096),
];
pub const RADIO_VARIABLE_COUNT: usize = VARIABLE_DESCRIPTORS.len() - Variable::Wrds as usize;
impl Variable {
    pub fn descriptor(self) -> &'static VariableDescriptor {
        &VARIABLE_DESCRIPTORS[self as usize]
    }
    pub fn name(self) -> &'static str {
        self.descriptor().name
    }
    pub fn resource_name(self) -> &'static str {
        self.descriptor().resource_name
    }
    pub fn guid(self) -> &'static str {
        self.descriptor().guid
    }
    pub fn maximum_bytes(self) -> usize {
        self.descriptor().maximum_bytes
    }
    pub fn bounded_bytes(
        self,
        stage: Stage,
        status: u64,
        reported_bytes: u64,
    ) -> Result<usize, Observation> {
        bounded_bytes(stage, status, reported_bytes, self.maximum_bytes())
    }
    fn origin(self) -> &'static str {
        if self.guid() == WIFI_BT_GUID {
            "UEFI GetVariable e65d8884-d4af-4b20-8d03-772ecc3da531"
        } else {
            "UEFI GetVariable 92daaf2f-c02b-455b-b2ec-f5a3594f4aea"
        }
    }
    pub fn requirement(self) -> resources::Requirement<'static> {
        resources::Requirement {
            name: self.resource_name(),
            target: resources::Target {
                driver: "wifi-intel",
                hardware: if self.guid() == WIFI_BT_GUID {
                    "uefi:e65d8884-d4af-4b20-8d03-772ecc3da531"
                } else {
                    "uefi:92daaf2f-c02b-455b-b2ec-f5a3594f4aea"
                },
                revision: self.name(),
                board: None,
            },
            minimum_bytes: self.descriptor().minimum_bytes,
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
        bounded_bytes(stage, status, reported_bytes, MAX_VARIABLE_BYTES)
    }
}
fn bounded_bytes(
    stage: Stage,
    status: u64,
    reported_bytes: u64,
    limit: usize,
) -> Result<usize, Observation> {
    if reported_bytes > limit as u64 {
        return Err(Observation::BoundExceeded {
            stage,
            status,
            reported_bytes,
        });
    }
    Ok(reported_bytes as usize)
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    pub oem_pnvm: Observation,
    pub reduced_power: Observation,
    pub step: Observation,
    /// Raw evidence only; never evaluated GLAI/device ACPI authority.
    pub radio: [Observation; RADIO_VARIABLE_COUNT],
}
impl Observations {
    pub fn set(&mut self, variable: Variable, observation: Observation) {
        match variable {
            Variable::OemPnvm => self.oem_pnvm = observation,
            Variable::ReducedPower => self.reduced_power = observation,
            Variable::Step => self.step = observation,
            variable => self.radio[variable as usize - Variable::Wrds as usize] = observation,
        }
    }
    pub fn get(self, variable: Variable) -> Observation {
        match variable {
            Variable::OemPnvm => self.oem_pnvm,
            Variable::ReducedPower => self.reduced_power,
            Variable::Step => self.step,
            variable => self.radio[variable as usize - Variable::Wrds as usize],
        }
    }
}

fn revision(sha: [u8; 32], attributes: u32) -> String {
    let digest: String = sha.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{digest};attributes:{attributes:08x}")
}
/// Capture metadata over owned temporary bytes or actual permanent mapped
/// slices. An owned Vec must pass through boot's permanent page handoff before
/// root switch/EBS; this type does not itself reserve or protect its storage.
pub struct CapturedVariable<B = Vec<u8>> {
    variable: Variable,
    observation: Observation,
    revision: String,
    bytes: Option<B>,
}
impl<B: AsRef<[u8]>> CapturedVariable<B> {
    pub fn from_variable(
        variable: Variable,
        bytes: B,
        attributes: u32,
        probe_reported_bytes: Option<u64>,
    ) -> Result<Self, Observation> {
        variable.bounded_bytes(Stage::Read, 0, bytes.as_ref().len() as u64)?;
        let sha256 = Sha256::digest(bytes.as_ref()).into();
        let observation = Observation::Present {
            attributes,
            bytes: bytes.as_ref().len() as u64,
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
    pub fn take_resource(&mut self) -> Option<resources::Resource<'_, B>> {
        let bytes = self.bytes.take()?;
        let Observation::Present { sha256, .. } = self.observation else {
            unreachable!("constructed from actual success")
        };
        Some(resources::Resource {
            name: self.variable.resource_name(),
            target: self.variable.requirement().target,
            provenance: resources::Provenance {
                source: self.variable.origin(),
                revision: &self.revision,
                member: self.variable.name(),
                license: DATA_LICENSE,
            },
            expected_length: bytes.as_ref().len(),
            expected_sha256: sha256,
            bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    Size,
    WrongVariable,
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
    Step(StepError),
    Resource(Box<resources::Error>),
}
/// Borrowed canonical image plus original package metadata. No UEFI read,
/// alternate Provider or image-byte copy happens in this post-EBS consumer.
#[derive(Debug)]
pub struct LoadedPackage<'a> {
    pub image: resources::Image<'a>,
    pub package: Package<'a>,
}
fn load_image<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<resources::Image<'a>, LoadError> {
    let (attributes, bytes, sha256) = match observation {
        Observation::Present {
            attributes,
            bytes,
            sha256,
            ..
        } => (attributes, bytes, sha256),
        Observation::NotCaptured => return Err(LoadError::Package(PackageError::Unobserved)),
        Observation::Absent {
            status: NOT_FOUND, ..
        } => return Err(LoadError::Package(PackageError::Absent)),
        _ => return Err(LoadError::Package(PackageError::FailedObservation)),
    };
    let requirement = variable.requirement();
    let image = provider
        .load(requirement)
        .map_err(|e| LoadError::Resource(Box::new(e)))?;
    let p = image.provenance();
    if image.name() != requirement.name
        || image.target() != requirement.target
        || image.bytes().len() as u64 != bytes
        || image.sha256() != sha256
        || p.source != variable.origin()
        || p.revision != revision(sha256, attributes)
        || p.member != variable.name()
        || p.license != DATA_LICENSE
    {
        return Err(LoadError::Package(PackageError::ObservationMismatch));
    }
    Ok(image)
}
/// Retain exact raw radio evidence without interpreting it or granting GLAI,
/// ACPI, vendor-authentication or fallback authority. PNVM and STEP have their
/// separate typed entry points and are refused by this radio-only interface.
pub fn load_radio_image<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<resources::Image<'a>, LoadError> {
    if matches!(
        variable,
        Variable::OemPnvm | Variable::ReducedPower | Variable::Step
    ) {
        return Err(LoadError::Package(PackageError::WrongVariable));
    }
    load_image(variable, observation, provider)
}
pub fn load<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<LoadedPackage<'a>, LoadError> {
    if !matches!(variable, Variable::OemPnvm | Variable::ReducedPower) {
        return Err(LoadError::Package(PackageError::WrongVariable));
    }
    let image = load_image(variable, observation, provider)?;
    let package = Package::parse(image.bytes()).map_err(LoadError::Package)?;
    Ok(LoadedPackage { image, package })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepError {
    Size,
    Revision(u8),
}
/// Raw6-byte STEP prefix from fw/uefi.h. Extra bytes and the source-ignored
/// step_mode remain metadata. No default mailbox is synthesized for failures.
#[derive(Clone, Copy, Debug)]
pub struct Step<'a> {
    raw: &'a [u8],
}
impl<'a> Step<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, StepError> {
        if !(6..=MAX_VARIABLE_BYTES).contains(&raw.len()) {
            return Err(StepError::Size);
        }
        if raw[0] != 1 {
            return Err(StepError::Revision(raw[0]));
        }
        Ok(Self { raw })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn step_mode(self) -> u8 {
        self.raw[1]
    }
    pub fn mailboxes(self) -> [u32; 2] {
        [
            u32::from_le_bytes([self.raw[0], self.raw[2], self.raw[3], self.raw[4]]),
            u32::from(self.raw[5]),
        ]
    }
}
#[derive(Debug)]
pub struct StepConfiguration<'a> {
    observation: Observation,
    value: StepValue<'a>,
}
#[derive(Debug)]
enum StepValue<'a> {
    Absent,
    Present {
        image: resources::Image<'a>,
        step: Step<'a>,
    },
}
impl<'a> StepConfiguration<'a> {
    pub fn observation(&self) -> Observation {
        self.observation
    }
    pub fn image(&self) -> Option<&resources::Image<'a>> {
        match &self.value {
            StepValue::Absent => None,
            StepValue::Present { image, .. } => Some(image),
        }
    }
    pub fn step(&self) -> Option<Step<'a>> {
        match self.value {
            StepValue::Absent => None,
            StepValue::Present { step, .. } => Some(step),
        }
    }
    pub fn mailboxes(&self) -> [u32; 2] {
        match self.value {
            StepValue::Absent => [0; 2],
            StepValue::Present { step, .. } => step.mailboxes(),
        }
    }
}

pub fn load_step<'a>(
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<StepConfiguration<'a>, LoadError> {
    if let Observation::Absent {
        status: NOT_FOUND, ..
    } = observation
    {
        return Ok(StepConfiguration {
            observation,
            value: StepValue::Absent,
        });
    }
    let image = load_image(Variable::Step, observation, provider)?;
    let step = Step::parse(image.bytes()).map_err(LoadError::Step)?;
    Ok(StepConfiguration {
        observation,
        value: StepValue::Present { image, step },
    })
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
    #[test]
    fn radio_descriptor_identities_minima_and_collection_bounds_are_exact() {
        let expected = [
            ("UefiCnvWlanWRDS", 49, 53, false),
            ("UefiCnvWlanEWRD", 141, 153, false),
            ("UefiCnvWlanWGDS", 74, 98, false),
            ("UefiCnvWlanPPAG", 27, 4096, false),
            ("UefiCnvWlanWRDD", 5, 4096, false),
            ("UefiCnvWlanGeneralCfg", 129, 4096, false),
            ("UefiCnvWlanWBEM", 5, 4096, false),
            ("UefiCnvCommonECKV", 5, 4096, true),
            ("UefiCnvWlanWTAS", 38, 4096, false),
            ("UefiCnvWlanSPLC", 5, 4096, false),
            ("WPFC", 17, 4096, false),
            ("UefiCnvWlanSarGeoOffsetMapping", 339, 4096, false),
            ("CnvUefiWlanUATS", 339, 4096, false),
        ];
        assert_eq!(expected.len(), RADIO_VARIABLE_COUNT);
        let mut observations = Observations::default();
        for (index, descriptor) in VARIABLE_DESCRIPTORS.iter().enumerate() {
            let variable = descriptor.variable;
            assert_eq!(variable as usize, index);
            assert_eq!(variable.descriptor().variable, variable);
            assert_eq!(observations.get(variable), Observation::NotCaptured);
            assert!(
                VARIABLE_DESCRIPTORS[..index]
                    .iter()
                    .all(|other| other.name != descriptor.name
                        && other.resource_name != descriptor.resource_name)
            );
            assert_eq!(
                variable.bounded_bytes(Stage::Probe, 5, descriptor.maximum_bytes as u64),
                Ok(descriptor.maximum_bytes)
            );
            assert_eq!(
                variable.bounded_bytes(Stage::Probe, 5, descriptor.maximum_bytes as u64 + 1),
                Err(Observation::BoundExceeded {
                    stage: Stage::Probe,
                    status: 5,
                    reported_bytes: descriptor.maximum_bytes as u64 + 1
                })
            );
            observations.set(
                variable,
                Observation::from_error(Stage::Read, 0x8000_0000_0000_0007, Some(index as u64)),
            );
            assert_eq!(
                observations.get(variable),
                Observation::Failed {
                    stage: Stage::Read,
                    status: 0x8000_0000_0000_0007,
                    reported_bytes: Some(index as u64)
                }
            );
            if index < Variable::Wrds as usize {
                continue;
            }
            let (name, minimum, maximum, common) = expected[index - Variable::Wrds as usize];
            assert_eq!(variable.name(), name);
            assert_eq!(variable.resource_name(), format!("intel/uefi/{name}.bin"));
            assert_eq!(
                variable.guid(),
                if common { WIFI_BT_GUID } else { WIFI_GUID }
            );
            assert_eq!(variable.requirement().minimum_bytes, minimum);
            assert_eq!(variable.maximum_bytes(), maximum);
            assert_eq!(variable.requirement().target.revision, name);
            assert_eq!(variable.requirement().target.board, None);
        }
    }

    #[test]
    fn radio_loader_refuses_package_and_step_variables_before_provider_access() {
        struct UnexpectedProvider;
        impl resources::Provider for UnexpectedProvider {
            fn load<'a>(
                &'a self,
                _: resources::Requirement<'_>,
            ) -> Result<resources::Image<'a>, resources::Error> {
                panic!("wrong variable must be refused before Provider access")
            }
        }
        for variable in [Variable::OemPnvm, Variable::ReducedPower, Variable::Step] {
            assert!(matches!(
                load_radio_image(variable, Observation::NotCaptured, &UnexpectedProvider),
                Err(LoadError::Package(PackageError::WrongVariable))
            ));
        }
    }

    #[test]
    fn raw_radio_bytes_stay_present_without_package_or_authority_inference() {
        for descriptor in &VARIABLE_DESCRIPTORS[Variable::Wrds as usize..] {
            let variable = descriptor.variable;
            let raw = vec![0xa5; descriptor.minimum_bytes + 1];
            let mut captured = CapturedVariable::from_variable(
                variable,
                raw,
                0x87,
                Some(descriptor.minimum_bytes as u64 + 1),
            )
            .unwrap();
            let observation = captured.observation();
            let resource = captured.take_resource().unwrap();
            let pointer = resource.bytes.as_ptr();
            let catalog = Catalog::from_handoff(vec![resource]).unwrap();
            let image = load_radio_image(variable, observation, &catalog).unwrap();
            assert_eq!(image.bytes().as_ptr(), pointer);
            assert_eq!(image.bytes().len(), descriptor.minimum_bytes + 1);
            assert_eq!(image.target(), variable.requirement().target);
            assert_eq!(image.provenance().source, variable.origin());
            assert_eq!(image.provenance().license, DATA_LICENSE);
            assert!(matches!(
                load(variable, observation, &catalog),
                Err(LoadError::Package(PackageError::WrongVariable))
            ));
            assert!(matches!(
                load_radio_image(variable, Observation::NotCaptured, &catalog),
                Err(LoadError::Package(PackageError::Unobserved))
            ));
            for length in [0, descriptor.minimum_bytes - 1] {
                let mut short = CapturedVariable::from_variable(
                    variable,
                    vec![0; length],
                    0,
                    Some(length as u64),
                )
                .unwrap();
                let observation = short.observation();
                assert!(
                    matches!(observation, Observation::Present { bytes, .. } if bytes == length as u64)
                );
                let catalog = Catalog::from_handoff(vec![short.take_resource().unwrap()]).unwrap();
                assert!(
                    matches!(load_radio_image(variable, observation, &catalog), Err(LoadError::Resource(error)) if error.kind == ErrorKind::Truncated { expected: descriptor.minimum_bytes, actual: length })
                );
            }
        }
    }
    #[test]
    fn custom_provider_cannot_redirect_an_observed_resource_name_or_target() {
        use resources::{Image, Provider, Requirement};
        struct Redirect<'a> {
            image: Image<'a>,
            expected: Requirement<'static>,
        }
        impl Provider for Redirect<'_> {
            fn load(&self, requirement: Requirement<'_>) -> Result<Image<'_>, resources::Error> {
                assert_eq!(requirement.name, self.expected.name);
                assert_eq!(requirement.target, self.expected.target);
                assert_eq!(requirement.minimum_bytes, self.expected.minimum_bytes);
                Ok(self.image)
            }
        }
        for variable in VARIABLE_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.variable)
        {
            for changed in 0..6 {
                let raw = if variable == Variable::Step {
                    vec![1, 0xfe, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb]
                } else if matches!(variable, Variable::OemPnvm | Variable::ReducedPower) {
                    package()
                } else {
                    vec![0; variable.descriptor().minimum_bytes]
                };
                let mut captured = CapturedVariable::from_variable(variable, raw, 7, None).unwrap();
                let observation = captured.observation();
                let mut resource = captured.take_resource().unwrap();
                match changed {
                    0 => {} // Exact custom-provider binding is accepted.
                    1 => resource.name = "redirected/raw.bin",
                    2 => resource.target.driver = "redirected",
                    3 => resource.target.hardware = "uefi:other",
                    4 => resource.target.revision = "other-observation",
                    _ => resource.target.board = Some("other-board"),
                }
                let redirected = Requirement {
                    name: resource.name,
                    target: resource.target,
                    minimum_bytes: variable.requirement().minimum_bytes,
                };
                let catalog = Catalog::from_handoff(vec![resource]).unwrap();
                let provider = Redirect {
                    image: catalog.load(redirected).unwrap(),
                    expected: variable.requirement(),
                };
                let result = if variable == Variable::Step {
                    load_step(observation, &provider).map(|_| ())
                } else if matches!(variable, Variable::OemPnvm | Variable::ReducedPower) {
                    load(variable, observation, &provider).map(|_| ())
                } else {
                    load_radio_image(variable, observation, &provider).map(|_| ())
                };
                if changed == 0 {
                    assert!(result.is_ok());
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(LoadError::Package(PackageError::ObservationMismatch))
                        ),
                        "{variable:?} field {changed}"
                    );
                }
            }
        }
    }
    #[test]
    fn borrowed_permanent_capture_keeps_the_actual_byte_pointer_and_provenance() {
        static RAW: [u8; 8] = [1, 0xfe, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb];
        let mut capture =
            CapturedVariable::from_variable(Variable::Step, &RAW[..], 0x87, Some(12)).unwrap();
        let observation = capture.observation();
        let catalog =
            Catalog::from_persistent_handoff(vec![capture.take_resource().unwrap()]).unwrap();
        assert!(capture.take_resource().is_none());
        let loaded = load_step(observation, &catalog).unwrap();
        assert_eq!(loaded.image().unwrap().bytes().as_ptr(), RAW.as_ptr());
        assert_eq!(
            loaded.image().unwrap().provenance().source,
            "UEFI GetVariable e65d8884-d4af-4b20-8d03-772ecc3da531"
        );
        assert_eq!(loaded.image().unwrap().provenance().license, DATA_LICENSE);
        assert_eq!(loaded.mailboxes(), [0x56341201, 0x78]);
        assert_eq!(loaded.observation(), observation);
    }
    fn profile(ax210: bool) -> Profile {
        Profile::select(Observed {
            vendor: 0x8086,
            device: if ax210 { 0x2725 } else { 0x2723 },
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
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
    #[test]
    fn step_uses_distinct_guid_actual_absence_and_full_observed_resource() {
        assert_eq!(Variable::Step.guid(), WIFI_BT_GUID);
        assert_ne!(
            Variable::Step.requirement().target.hardware,
            Variable::OemPnvm.requirement().target.hardware
        );
        assert_eq!(
            Observations::default().get(Variable::Step),
            Observation::NotCaptured
        );
        let catalog = Catalog::from_handoff(vec![]).unwrap();
        let absence = Observation::from_error(Stage::Probe, NOT_FOUND, None);
        let absent = load_step(absence, &catalog).unwrap();
        assert_eq!(absent.observation(), absence);
        assert_eq!(absent.mailboxes(), [0; 2]);
        assert!(absent.image().is_none());
        assert!(absent.step().is_none());
        for observation in [
            Observation::NotCaptured,
            Observation::from_error(Stage::Read, 9, None),
            Observation::Absent {
                stage: Stage::Read,
                status: 0,
                reported_bytes: None,
            },
        ] {
            assert!(load_step(observation, &catalog).is_err());
        }
        let bytes = vec![1, 0xfe, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb];
        let pointer = bytes.as_ptr();
        let mut captured =
            CapturedVariable::from_variable(Variable::Step, bytes, 7, Some(8)).unwrap();
        let observation = captured.observation();
        let catalog = Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap();
        let loaded = load_step(observation, &catalog).unwrap();
        assert_eq!(loaded.mailboxes(), [0x56341201, 0x78]);
        assert_eq!(loaded.step().unwrap().step_mode(), 0xfe);
        assert_eq!(
            loaded.step().unwrap().raw(),
            [1, 0xfe, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb]
        );
        assert_eq!(loaded.image().unwrap().bytes().as_ptr(), pointer);
        assert!(matches!(
            load(Variable::Step, observation, &catalog),
            Err(LoadError::Package(PackageError::WrongVariable))
        ));
        for n in 0..6 {
            assert_eq!(Step::parse(&vec![1; n]).unwrap_err(), StepError::Size);
        }
        for revision in [0, 2, 255] {
            assert_eq!(
                Step::parse(&[revision, 0, 0, 0, 0, 0]).unwrap_err(),
                StepError::Revision(revision)
            );
        }
        let mut captured =
            CapturedVariable::from_variable(Variable::Step, vec![1; 5], 7, None).unwrap();
        let observation = captured.observation();
        let catalog = Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap();
        assert!(
            matches!(load_step(observation,&catalog),Err(LoadError::Resource(e)) if matches!(e.kind,ErrorKind::Truncated{expected:6,actual:5}))
        );
    }
    #[test]
    #[ignore = "requires pinned unchanged Linux STEP helper trace; see THIRD_PARTY.md"]
    fn unchanged_linux_step_mailboxes_and_every_revision() {
        extern crate std;
        use core::fmt::Write;
        let trace =
            std::fs::read(std::env::var("STELA_IWLWIFI_STEP_ORACLE").expect("STEP trace")).unwrap();
        let digest: String = Sha256::digest(&trace)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "6841f423d0d5720aba4037c12811cd4a1cb58cf5252354777b58ab4160f26152"
        );
        let mut actual = String::new();
        for revision in 0..=255 {
            let bytes = [revision, 0xfe, 0x12, 0x34, 0x56, 0x78];
            match Step::parse(&bytes) {
                Ok(step) => {
                    let words = step.mailboxes();
                    writeln!(actual, "step {revision} ok {:x} {:x}", words[0], words[1]).unwrap();
                }
                Err(StepError::Revision(actual_revision)) => {
                    assert_eq!(actual_revision, revision);
                    writeln!(actual, "step {revision} invalid 0 0").unwrap();
                }
                other => panic!("unexpected STEP result {other:?}"),
            }
        }
        assert_eq!(actual.as_bytes(), trace);
    }
}
