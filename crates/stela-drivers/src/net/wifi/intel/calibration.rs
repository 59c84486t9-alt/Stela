// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2020-2026 Intel Corporation
//! ALIVE-selected canonical PNVM/reduced-power resource acquisition, matching
//! fw/pnvm.c and fw/uefi.c. Raw integrity never authenticates vendor data.
use super::{
    firmware::Family,
    identity::Profile,
    platform::{self, Observation, Observations, PnvmSource, Variable},
    pnvm,
};
use crate::firmware as resources;
use alloc::{boxed::Box, vec::Vec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Observation {
        variable: Variable,
        observation: Observation,
    },
    Package(platform::PackageError),
    Step(platform::StepError),
    Resource(Box<resources::Error>),
    Binding,
    Selection(pnvm::Error),
}
impl From<platform::LoadError> for Error {
    fn from(error: platform::LoadError) -> Self {
        match error {
            platform::LoadError::Package(e) => Self::Package(e),
            platform::LoadError::Step(e) => Self::Step(e),
            platform::LoadError::Resource(e) => Self::Resource(e),
        }
    }
}
impl From<pnvm::Error> for Error {
    fn from(value: pnvm::Error) -> Self {
        Self::Selection(value)
    }
}

/// Actual acquisition outcome, retained even when source policy allows an
/// unavailable BIOS variable or explicitly selects its external fallback.
#[derive(Clone, Copy, Debug)]
pub enum Source<'a> {
    NotRequired,
    Unavailable {
        observation: Observation,
    },
    Bios {
        observation: Observation,
        image: resources::Image<'a>,
    },
    External {
        image: resources::Image<'a>,
        bios_fallback: Option<Observation>,
    },
}
#[derive(Debug)]
pub struct Receipts<'a> {
    pub pnvm: Source<'a>,
    pub pnvm_version: Option<u32>,
    pub reduced_power: Source<'a>,
    pub transfer: Transfer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transfer {
    NotRequired,
    ScratchV2,
    NotUsedBeforeAx210,
}
pub(super) struct Prepared<'a> {
    pub receipts: Receipts<'a>,
    pub pnvm: Vec<pnvm::Chunk<'a>>,
    pub reduced_power: Vec<pnvm::Chunk<'a>>,
}

fn unavailable(variable: Variable, observation: Observation) -> Result<bool, Error> {
    match observation {
        Observation::Absent { status, .. } if status == (1 << 63) | 14 => Ok(true),
        Observation::Failed { status, .. } if status & (1 << 63) != 0 => Ok(true),
        // Linux cannot obtain a package payload from a successful variable
        // shorter than its packed header. Preserve that actual observation.
        Observation::Present { bytes, .. } if bytes < 14 => Ok(true),
        Observation::Present { .. } => Ok(false),
        _ => Err(Error::Observation {
            variable,
            observation,
        }),
    }
}
fn external<'a>(
    profile: &Profile,
    provider: &'a dyn resources::Provider,
) -> Result<resources::Image<'a>, Error> {
    let request = profile.pnvm_request().ok_or(Error::Binding)?;
    let requirement = request.requirement();
    let image = provider
        .load(requirement)
        .map_err(|e| Error::Resource(Box::new(e)))?;
    // A Provider implementation is allowed to be independently supplied;
    // never trust a redirected diagnostic/other-board image as this request.
    if image.name() != requirement.name || image.target() != requirement.target {
        return Err(Error::Binding);
    }
    Ok(image)
}
fn bios<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<platform::LoadedPackage<'a>, Error> {
    let loaded = platform::load(variable, observation, provider)?;
    let requirement = variable.requirement();
    if loaded.image.name() != requirement.name || loaded.image.target() != requirement.target {
        return Err(Error::Binding);
    }
    Ok(loaded)
}

/// Only the owning ROM epoch calls this with its private actually decoded SKU;
/// this helper grants no upload, signature, firmware status or radio authority.
pub(super) fn prepare<'a>(
    profile: &Profile,
    sku: [u32; 3],
    observations: Observations,
    provider: &'a dyn resources::Provider,
) -> Result<Prepared<'a>, Error> {
    let plan = platform::post_alive_plan(profile, sku);
    if !plan.pnvm_completion_required {
        return Ok(Prepared {
            receipts: Receipts {
                pnvm: Source::NotRequired,
                pnvm_version: None,
                reduced_power: Source::NotRequired,
                transfer: Transfer::NotRequired,
            },
            pnvm: Vec::new(),
            reduced_power: Vec::new(),
        });
    }
    let (source, data) = match plan.pnvm {
        PnvmSource::None => (Source::NotRequired, None),
        PnvmSource::External => {
            let image = external(profile, provider)?;
            (
                Source::External {
                    image,
                    bios_fallback: None,
                },
                Some(image.bytes()),
            )
        }
        PnvmSource::Bios { external_fallback } => {
            let observation = observations.oem_pnvm;
            if unavailable(Variable::OemPnvm, observation)? {
                if external_fallback {
                    let image = external(profile, provider)?;
                    (
                        Source::External {
                            image,
                            bios_fallback: Some(observation),
                        },
                        Some(image.bytes()),
                    )
                } else {
                    (Source::Unavailable { observation }, None)
                }
            } else {
                let loaded = bios(Variable::OemPnvm, observation, provider)?;
                (
                    Source::Bios {
                        observation,
                        image: loaded.image,
                    },
                    Some(loaded.package.payload()),
                )
            }
        }
    };
    let (pnvm, pnvm_version) = if let Some(data) = data {
        // A successfully acquired BIOS image that fails SKU/HW selection is
        // not acquisition absence and never silently switches to external.
        let selection = pnvm::Pnvm::parse(data)?.select(profile, sku)?;
        (selection.chunks().to_vec(), selection.version())
    } else {
        (Vec::new(), None)
    };
    let observation = observations.reduced_power;
    let (reduced_source, reduced_power) = if unavailable(Variable::ReducedPower, observation)? {
        (Source::Unavailable { observation }, Vec::new())
    } else {
        let loaded = bios(Variable::ReducedPower, observation, provider)?;
        let selection = pnvm::Pnvm::parse(loaded.package.payload())?.select_reduced_power(sku)?;
        (
            Source::Bios {
                observation,
                image: loaded.image,
            },
            selection.chunks().to_vec(),
        )
    };
    Ok(Prepared {
        receipts: Receipts {
            pnvm: source,
            pnvm_version,
            reduced_power: reduced_source,
            transfer: if profile.family() == Family::Ax210 {
                Transfer::ScratchV2
            } else {
                Transfer::NotUsedBeforeAx210
            },
        },
        pnvm,
        reduced_power,
    })
}

#[cfg(test)]
mod tests {
    use super::super::identity::Observed;
    use super::*;
    use resources::{Catalog, Provenance, Provider, Resource, Target};
    use sha2::{Digest, Sha256};
    #[test]
    fn only_actual_native_errors_absence_or_short_packages_allow_acquisition_fallback() {
        use platform::Stage;
        for observation in [
            Observation::NotCaptured,
            Observation::Absent {
                stage: Stage::Read,
                status: 0,
                reported_bytes: None,
            },
            Observation::Failed {
                stage: Stage::Read,
                status: 7,
                reported_bytes: None,
            },
            Observation::BoundExceeded {
                stage: Stage::Read,
                status: 0,
                reported_bytes: platform::MAX_VARIABLE_BYTES as u64 + 1,
            },
        ] {
            assert!(matches!(
                unavailable(Variable::OemPnvm, observation),
                Err(Error::Observation { .. })
            ));
        }
        for observation in [
            Observation::from_error(Stage::Probe, (1 << 63) | 14, None),
            Observation::from_error(Stage::Read, (1 << 63) | 7, None),
        ] {
            assert_eq!(unavailable(Variable::OemPnvm, observation), Ok(true));
        }
        for bytes in 0..=14 {
            let observation = Observation::Present {
                attributes: 7,
                bytes,
                sha256: [0; 32],
                probe_reported_bytes: None,
            };
            assert_eq!(unavailable(Variable::OemPnvm, observation), Ok(bytes < 14));
        }
    }
    #[test]
    fn redirected_external_filename_target_or_board_never_reaches_payload_selection() {
        struct Redirect<'a>(resources::Image<'a>);
        impl Provider for Redirect<'_> {
            fn load<'p>(
                &'p self,
                _: resources::Requirement<'_>,
            ) -> Result<resources::Image<'p>, resources::Error> {
                Ok(self.0)
            }
        }
        let profile = Profile::select(Observed {
            vendor: 0x8086,
            device: 0x2725,
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
            hardware_revision: 0x420,
            radio_id: 0x10d000,
        })
        .unwrap();
        for mode in 0..3 {
            let request = profile.pnvm_request().unwrap();
            let expected = request.requirement();
            let mut target = expected.target;
            let mut name = expected.name;
            if mode == 0 {
                name = "diagnostic.pnvm";
            }
            if mode == 1 {
                target = Target {
                    driver: "different-driver",
                    ..target
                };
            }
            if mode == 2 {
                target.board = Some("different-board");
            }
            let bytes = vec![0x5a; 16];
            let catalog = Catalog::from_handoff(vec![Resource {
                name,
                target,
                provenance: Provenance {
                    source: "test",
                    revision: "immutable",
                    member: name,
                    license: "LicenseRef-Local-Test-Fixture",
                },
                expected_length: bytes.len(),
                expected_sha256: Sha256::digest(&bytes).into(),
                bytes,
            }])
            .unwrap();
            let image = catalog
                .load(resources::Requirement {
                    name,
                    target,
                    minimum_bytes: 1,
                })
                .unwrap();
            let provider = Redirect(image);
            assert!(matches!(
                prepare(
                    &profile,
                    [0x610d0, 0, 0],
                    Observations::default(),
                    &provider
                ),
                Err(Error::Binding)
            ));
        }
    }
}
