//! Original requester preparation and its one-way private-domain transition.
use super::*;
use crate::bus::pci::requester::preparation::{self, PreparingRequester};

pub(super) enum Requester {
    Preparing(PreparingRequester),
    Bound {
        pci: Function<OwnedConfig>,
        domain: Arc<dyn DmaDomain>,
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
            Self::Failed { .. } | Self::Consumed => Err(Error::Quarantined),
        }
    }
    pub(super) fn domain(&self) -> Result<Arc<dyn DmaDomain>, Error> {
        match self {
            Self::Bound { domain, .. } => Ok(domain.clone()),
            _ => Err(Error::Quarantined),
        }
    }
    /// # Safety
    /// Controller acknowledged full HALT/ASS0/PSS0, with device
    /// interrupts masked and no prior IRQ/work/firmware users or producers.
    /// During first attachment no Stela submissions or DMA allocations exist.
    /// The original BAR/configuration/root owners stay kept during this call.
    pub(super) unsafe fn bind(&mut self) -> Result<(), Error> {
        if let Self::Bound { domain, .. } = self {
            // SAFETY: caller observed the owned controller's stop; runtime
            // drainage uses the same domain that owns its active DMA leases.
            return unsafe { domain.drain_posted_writes() }.map_err(Error::Dma);
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
                    domain: bound.domain,
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
    pub(super) fn into_function(self) -> Result<Function<OwnedConfig>, Error> {
        match self {
            Self::Bound { pci, .. } => Ok(pci),
            _ => {
                core::mem::forget(self);
                Err(Error::Quarantined)
            }
        }
    }
}
