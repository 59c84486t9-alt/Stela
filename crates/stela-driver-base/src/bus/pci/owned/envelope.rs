//! The original configuration custody stays parked through mapper callbacks.
use super::{
    OwnedConfig, UnpublishedConfig,
    grant::{DriverCustody, DriverGrant, Grant, PrepublicationCustody, PrepublicationGrant},
    region::{Region, retire_mapping},
};
use crate::bus::{
    mmio::owned::{Error as MappingError, Mapping, Resource},
    pci::{Address, ConfigError, EcamWindow, assignment::AdmissionClose},
};
use alloc::boxed::Box;
use core::mem::ManuallyDrop;

enum Phase<G> {
    Pending { grant: G, mapping: Option<Mapping> },
    Attached(Region<G>),
}

pub(super) struct Envelope<G> {
    // Default destruction leaves the whole original allocation in place. The
    // close handle denies admission without calling a custody or mapper method.
    phase: ManuallyDrop<Box<Option<Phase<G>>>>,
    close: Option<AdmissionClose>,
}

/// Allocate the configuration envelope before invoking the mapper.
#[must_use]
pub struct PreparedConfig<G>(Envelope<G>);

/// The original parked grant and any installed mapping, pending or attached.
#[must_use]
pub struct ConfigParts<G>(pub(super) Envelope<G>);

pub(super) fn promote<P: PrepublicationCustody + DriverCustody>(
    mut config: UnpublishedConfig,
    qualify: impl FnOnce(&mut P) -> Result<(), MappingError>,
) -> Result<OwnedConfig, (MappingError, ConfigParts<PrepublicationGrant>)> {
    // Allocate the destination before invoking the original source. Until
    // qualification succeeds, the original envelope keeps all inputs.
    let mut phase = Box::new(None);
    if let Err(error) = config.storage.region_mut().qualify_promotion(qualify) {
        if let Some(close) = &config.storage.close {
            close.close();
        }
        return Err((error, config.into_parts()));
    }
    let Some(Phase::Attached(region)) = config.storage.phase.take() else {
        unreachable!("original attached configuration")
    };
    *phase = Some(Phase::Attached(region.into_promoted::<P>()));
    let close = config.storage.close.take();
    // SAFETY: the old envelope is empty. The destination holds the same
    // source, mapping, operation state and sealed close projection.
    unsafe { ManuallyDrop::drop(&mut config.storage.phase) };
    Ok(OwnedConfig {
        storage: Envelope {
            phase: ManuallyDrop::new(phase),
            close,
        },
    })
}

impl<G> Envelope<G> {
    fn phase(&self) -> &Phase<G> {
        self.phase.as_ref().as_ref().expect("kept phase")
    }

    fn phase_mut(&mut self) -> &mut Phase<G> {
        self.phase.as_mut().as_mut().expect("kept phase")
    }

    pub(super) fn region(&self) -> &Region<G> {
        let Phase::Attached(region) = self.phase() else {
            unreachable!("configuration was attached")
        };
        region
    }

    pub(super) fn region_mut(&mut self) -> &mut Region<G> {
        let Phase::Attached(region) = self.phase_mut() else {
            unreachable!("configuration was attached")
        };
        region
    }
}

impl<G: Grant> Envelope<G> {
    pub(super) unsafe fn retire(&mut self) -> Result<(), MappingError> {
        if self.close.is_none() {
            return Ok(());
        }
        // SAFETY: the original source supplied complete user retirement.
        unsafe {
            match self.phase_mut() {
                Phase::Pending { grant, mapping } => retire_mapping(grant, mapping.as_mut()),
                Phase::Attached(region) => region.retire(),
            }
        }?;
        self.close.take().expect("armed close").dismiss();
        Ok(())
    }
}

impl<G> PreparedConfig<G> {
    /// Keep the same envelope when preparation ends before attachment.
    pub fn into_parts(self) -> ConfigParts<G> {
        ConfigParts(self.0)
    }

    fn grant(&self) -> &G {
        let Phase::Pending { grant, .. } = self.0.phase() else {
            unreachable!("configuration is pending")
        };
        grant
    }
}

pub(super) fn prepare<G: Grant>(grant: G) -> PreparedConfig<G> {
    let close = grant.state().admission_close().expect("preowned close");
    PreparedConfig(Envelope {
        phase: ManuallyDrop::new(Box::new(Some(Phase::Pending {
            grant,
            mapping: None,
        }))),
        close: Some(close),
    })
}

fn attach<G: Grant>(
    mut prepared: PreparedConfig<G>,
    mapping: Mapping,
) -> Result<Envelope<G>, (ConfigError, ConfigParts<G>)> {
    let Phase::Pending {
        grant,
        mapping: kept,
    } = prepared.0.phase_mut()
    else {
        unreachable!("configuration is pending")
    };
    let mapping = kept.insert(mapping);
    let geometry = match Region::validate_attachment(grant, mapping) {
        Ok(geometry) => geometry,
        Err(error) => {
            prepared.0.close.as_ref().expect("armed close").close();
            return Err((error, prepared.into_parts()));
        }
    };
    // The validation callbacks are complete. Transfer the owners within the
    // same allocation with no fallible work between removal and installation.
    let Some(Phase::Pending {
        grant,
        mapping: Some(mapping),
    }) = prepared.0.phase.take()
    else {
        unreachable!("original pending grant and mapping")
    };
    **prepared.0.phase = Some(Phase::Attached(Region::attached(grant, mapping, geometry)));
    Ok(prepared.0)
}

macro_rules! config_phase {
    ($grant:ty, $config:ident) => {
        impl PreparedConfig<$grant> {
            pub fn address(&self) -> Address {
                self.grant().custody().address()
            }

            pub fn window(&self) -> EcamWindow {
                self.grant().custody().window()
            }

            pub fn configuration_resource(&self) -> &Resource {
                self.grant().custody().resource()
            }

            pub fn attach(
                self,
                mapping: Mapping,
            ) -> Result<$config, (ConfigError, ConfigParts<$grant>)> {
                attach(self, mapping).map(|storage| $config { storage })
            }
        }

        impl ConfigParts<$grant> {
            /// # Safety
            /// The original source has stopped and joined every device, DMA,
            /// IRQ, config, raw pointer and callback user. An acknowledgement
            /// withdraws the mapping only and conveys no physical return.
            pub unsafe fn retire(&mut self) -> Result<(), MappingError> {
                // SAFETY: the caller supplied complete original retirement.
                unsafe { self.0.retire() }
            }
        }
    };
}
config_phase!(DriverGrant, OwnedConfig);
config_phase!(PrepublicationGrant, UnpublishedConfig);

#[cfg(any(test, feature = "test-support"))]
mod model;
