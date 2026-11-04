//! The retained original VT-d/AMD root used during vendor cold preparation.
use super::*;
use alloc::boxed::Box;
use stela_drivers::bus::pci::{owned::OwnedConfig, requester::preparation::Root};

struct VtdRoot {
    address: Address,
    unit: Arc<Unit<MmioRegisters>>,
    blocked: BlockedRequester<MmioRegisters>,
    _lines: native_mmio::InitialPciLines,
}

// SAFETY: constructed only from the requester's selected original taken unit,
// under the mount's frozen routing epoch. The unit keeps its mapped registers,
// initial DMA backing and uncertain table resources. Engine/IRQ/work stop is
// the receipt producer's independent obligation; neither method infers it.
unsafe impl Root for VtdRoot {
    fn drain(&self) -> Result<(), DmaError> {
        self.blocked.drain()
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
    pub(in crate::engine) fn forward_pci_bridges(&self, pci: &native_mmio::ContainedPci<'_>) {
        let Some(lines) = &self.initial_lines else {
            return;
        };
        let source = pci.source();
        let bridges = match pci.bridges() {
            Ok(bridges) if bridges.is_empty() => return,
            Ok(bridges) => bridges,
            Err(error) => {
                output::arguments(format_args!(
                    "HOST PCI bridge inventory unavailable: {error:?}\n"
                ));
                return;
            }
        };
        // SAFETY: this startup step precedes every driver and competing PCI
        // writer. The same complete blocked remappers and line owners are kept.
        if let Err(error) = unsafe { pci.recheck_stopped() } {
            output::arguments(format_args!(
                "HOST PCI bridge forwarding withheld: {error}\n"
            ));
            return;
        }
        for address in bridges {
            let rid = requester(address);
            let blocked = self
                .vtd(address.segment, rid)
                .map_err(|_| DmaError::IommuUnavailable)
                .and_then(|taken| {
                    let taken = taken.ok_or(DmaError::IommuUnavailable)?;
                    self.initial_requester(source, taken, rid)?
                        .ok_or(DmaError::DrainUnavailable)
                });
            let blocked = match blocked {
                Ok(blocked) => blocked,
                Err(error) => {
                    output::arguments(format_args!(
                        "HOST PCI bridge {address} blocked context unavailable: {error:?}\n"
                    ));
                    continue;
                }
            };
            // SAFETY: exact firmware-selected blocked RID, the original kept
            // line paths, checked stopped leaves and frozen topology. Other
            // reopened ports retain their own original blocked contexts.
            match unsafe { source.forward_cold_bridge(address, blocked, lines) } {
                Ok(()) => output::arguments(format_args!(
                    "HOST PCI bridge {address} forwarding restored with routing sealed\n"
                )),
                Err(error) => output::arguments(format_args!(
                    "HOST PCI bridge forwarding withheld: {error}\n"
                )),
            }
        }
    }

    pub(in crate::engine) fn preparation(
        &self,
        source: &native_mmio::Source,
        address: Address,
    ) -> Result<(OwnedConfig, Box<dyn Root>), PreparationError> {
        let rid = requester(address);
        if self
            .amd(address.segment, rid)
            .map_err(|_| DmaError::IommuUnavailable)?
            .is_some()
        {
            return Err(PreparationError::AmdConfiguration);
        }
        let taken = self
            .vtd(address.segment, rid)
            .map_err(|_| DmaError::IommuUnavailable)?
            .filter(|taken| taken.unit.allows(rid))
            .ok_or(DmaError::DrainUnavailable)?;
        let lines = self
            .initial_lines
            .as_ref()
            .ok_or(PreparationError::Interrupt(MappingError::Unavailable))?;
        lines.check(source).map_err(PreparationError::Interrupt)?;
        let blocked = self
            .initial_requester(source, taken, rid)?
            .ok_or(DmaError::DrainUnavailable)?;
        // SAFETY: this root is selected from the same fully contained fabric
        // and this slot's exact firmware route. Legacy probing is read-only
        // while this fabric is active, and AML's ECAM writers are excluded.
        let config = unsafe { source.promote_cold_config(address, &blocked, lines) }
            .map_err(PreparationError::Configuration)?;
        let root = Box::new(VtdRoot {
            address,
            unit: taken.unit.clone(),
            blocked,
            _lines: lines.clone(),
        });
        Ok((config, root))
    }
}
