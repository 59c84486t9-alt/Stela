//! The retained original VT-d/AMD root used during vendor cold preparation.
use super::*;
use alloc::boxed::Box;
use stela_drivers::bus::{dma::mapping::DmaError, pci::requester::preparation::Root};

struct VtdRoot {
    address: Address,
    unit: Arc<Unit<MmioRegisters>>,
}

// SAFETY: constructed only from the requester's selected original taken unit,
// under the mount's frozen routing epoch. The unit keeps its mapped registers,
// initial DMA backing and uncertain table resources. Engine/IRQ/work stop is
// the receipt producer's independent obligation; neither method infers it.
unsafe impl Root for VtdRoot {
    fn drain(&self) -> Result<(), DmaError> {
        self.unit.drain_initial_requester(requester(self.address))
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> Result<Box<dyn stela_drivers::bus::pci::requester::preparation::AttachmentBackend>, DmaError>
    {
        if binding.address() != self.address {
            return Err(DmaError::IommuUnavailable);
        }
        // SAFETY: the consuming current-epoch driver receipt supplies stop,
        // exclusion and the completed original root drain; binding is the
        // paired original configuration and this same retained unit.
        let claim = unsafe { RequesterClaim::from_binding(binding) }
            .map_err(|_| DmaError::MappingFailed)?;
        // SAFETY: same consumed receipt and original root/configuration epoch.
        let domain =
            unsafe { self.unit.attach_requester(claim) }.map_err(|_| DmaError::MappingFailed)?;
        Ok(Box::new(VtdAttachment {
            address: self.address,
            domain,
        }))
    }
}

struct VtdAttachment {
    address: Address,
    domain: crate::native_dma::vtd::BoundRequester<MmioRegisters>,
}
// SAFETY: this unique control owns the same actual domain and immutable
// RID/DID/generation as the consumed original binding. Backend detach blocks
// the context and completes invalidation before returning its retained claim.
// Old Arc references check that generation and cannot reach a replacement.
// The local owner closes admission and retains the whole claim on Drop;
// the shared projection has no configuration callback or local actor edge.
unsafe impl stela_drivers::bus::pci::requester::preparation::AttachmentBackend for VtdAttachment {
    fn irq_owner(
        &mut self,
        _requester: &stela_drivers::bus::pci::requester::RequesterId,
        _config: Option<&stela_drivers::bus::pci::owned::ConfigRetention>,
    ) -> Result<Option<Box<dyn stela_drivers::bus::irq::posted_msi::RouteOwner>>, DmaError> {
        // Explicit component prerequisite. The separate native producer delta
        // consumes the actual original all-unit mode/root owner and actual
        // source pairing; no numeric/BDF observer or empty success replaces it.
        Ok(None)
    }

    fn domain(&self) -> Arc<dyn DmaDomain> {
        self.domain.domain()
    }
    unsafe fn detach(
        &mut self,
    ) -> Result<(), stela_drivers::bus::pci::requester::preparation::DetachError> {
        // SAFETY: caller supplies current-epoch quiescence and payload/IRQ/work
        // drains with original owners kept. Backend refuses live mappings
        // before context effects.
        // This metadata-only preflight precedes every hardware effect. Actual
        // detach failures below are all uncertain, regardless of error variant.
        if self
            .domain
            .has_live_mappings()
            .map_err(stela_drivers::bus::pci::requester::preparation::DetachError::Unexposed)?
        {
            return Err(
                stela_drivers::bus::pci::requester::preparation::DetachError::Unexposed(
                    DmaError::MappingFailed,
                ),
            );
        }
        // SAFETY: caller retains the quiesced current epoch and joined IRQ/work;
        // the preflight above ruled out live payload mappings before detach.
        let claim = unsafe { self.domain.detach() }.map_err(|error| {
            output::arguments(format_args!(
                "HOST IOMMU VT-d detach {} refused: {error:?}\n",
                self.address
            ));
            DmaError::MappingFailed
        })?;
        drop(claim);
        Ok(())
    }
}

impl Remappers {
    pub(in crate::engine) fn preparation(
        &self,
        address: Address,
    ) -> Result<Box<dyn Root>, DmaError> {
        let rid = requester(address);
        if let Some(taken) = self
            .amd(address.segment, rid)
            .map_err(|_| DmaError::IommuUnavailable)?
        {
            return taken.preparation(address);
        }
        let taken = self
            .vtd(address.segment, rid)
            .map_err(|_| DmaError::IommuUnavailable)?
            .filter(|taken| taken.unit.allows(rid))
            .ok_or(DmaError::DrainUnavailable)?;
        Ok(Box::new(VtdRoot {
            address,
            unit: taken.unit.clone(),
        }))
    }
}
