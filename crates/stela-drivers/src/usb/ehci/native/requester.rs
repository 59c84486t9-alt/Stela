//! Original requester preparation and its one-way private-domain transition.
use super::*;
use crate::bus::pci::requester::preparation::{self, PreparingRequester};

pub(super) enum Requester {
    Preparing(PreparingRequester),
    Bound {
        pci: Function<OwnedConfig>,
        attachment: preparation::Attachment,
    },
    Retired {
        pci: Function<OwnedConfig>,
    },
    Failed {
        _failure: preparation::Failure,
    },
    Consumed,
}
impl Requester {
    pub(super) fn function(&mut self) -> Result<&mut Function<OwnedConfig>, Error> {
        match self {
            Self::Preparing(preparing) => Ok(preparing.function_mut()),
            Self::Bound { pci, .. } => Ok(pci),
            Self::Retired { .. } | Self::Failed { .. } | Self::Consumed => Err(Error::Quarantined),
        }
    }
    pub(super) fn domain(&self) -> Result<Arc<dyn DmaDomain>, Error> {
        match self {
            Self::Bound { attachment, .. } => Ok(attachment.domain()),
            _ => Err(Error::Quarantined),
        }
    }
    /// # Safety
    /// Controller acknowledged full HALT/ASS0/PSS0, with device
    /// interrupts masked and no prior IRQ/work/firmware users or producers.
    /// During first attachment no Stela submissions or DMA allocations exist.
    /// The original BAR/configuration/root owners stay kept during this call.
    pub(super) unsafe fn bind(&mut self) -> Result<(), Error> {
        if let Self::Bound { attachment, .. } = self {
            // SAFETY: caller observed the owned controller's stop; runtime
            // drainage uses the same domain that owns its active DMA leases.
            return unsafe { attachment.domain().drain_posted_writes() }.map_err(Error::Dma);
        }
        let Self::Preparing(preparing) = core::mem::replace(self, Self::Consumed) else {
            return Err(Error::Quarantined);
        };
        // SAFETY: initial full HALT/ASS0/PSS0 acknowledged by Controller under
        // original PCI/BAR ownership; the cold attachment grant excludes prior
        // IRQ/work/firmware users and bypass. No new producer exists yet.
        let receipt = unsafe { preparing.acknowledge_quiescence() };
        match receipt.finalize() {
            Ok(bound) => {
                *self = Self::Bound {
                    pci: bound.requester.into_function(),
                    attachment: bound.attachment,
                };
                Ok(())
            }
            Err(failure) => {
                let error = Error::Preparation(failure.error);
                *self = Self::Failed { _failure: failure };
                Err(error)
            }
        }
    }
    pub(super) fn is_retired(&self) -> bool {
        matches!(self, Self::Retired { .. })
    }
    /// # Safety
    /// Full current-epoch halt, BME/IRQ/work exclusion, original payload
    /// drainage precede this call. Remaining mapped leases cause refusal;
    /// original configuration/BAR/root owners stay kept until retirement completes.
    pub(super) unsafe fn retire(&mut self) -> Result<(), Error> {
        match self {
            Self::Bound { pci, attachment } => {
                crate::bus::pci::requester::validate_stopped(pci)
                    .map_err(|error| Error::Preparation(preparation::Error::Claim(error)))?;
                // SAFETY: same paired stopped/drained owner and original
                // generation. Backend refuses remaining mapped leases before
                // retiring any context or configuration retention.
                unsafe { attachment.detach() }.map_err(Error::Dma)?;
            }
            _ => return Err(Error::Quarantined),
        }
        let Self::Bound { pci, .. } = core::mem::replace(self, Self::Consumed) else {
            unreachable!("same serialized attachment")
        };
        *self = Self::Retired { pci };
        Ok(())
    }
    pub(super) fn into_function(self) -> Result<Function<OwnedConfig>, Error> {
        match self {
            Self::Retired { pci } => Ok(pci),
            _ => {
                core::mem::forget(self);
                Err(Error::Quarantined)
            }
        }
    }
}
