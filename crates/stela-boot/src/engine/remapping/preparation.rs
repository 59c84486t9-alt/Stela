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
    unsafe fn bind(&self, binding: RequesterBinding) -> Result<Arc<dyn DmaDomain>, DmaError> {
        if binding.address() != self.address {
            return Err(DmaError::IommuUnavailable);
        }
        // SAFETY: the consuming current-epoch driver receipt supplies stop,
        // exclusion and the completed original root drain; binding is the
        // paired original configuration and this same retained unit.
        let claim = unsafe { RequesterClaim::from_binding(binding) }
            .map_err(|_| DmaError::MappingFailed)?;
        // SAFETY: same consumed receipt and original root/configuration epoch.
        unsafe { self.unit.attach_requester(claim) }
            .map(|domain| domain as Arc<dyn DmaDomain>)
            .map_err(|_| DmaError::MappingFailed)
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
