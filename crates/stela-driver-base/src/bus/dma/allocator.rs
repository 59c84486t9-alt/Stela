//! Coherent legacy-driver allocations through a requester domain.
use super::{
    BufferMemory, DmaAllocator, DmaBuffer,
    mapping::{Direction, DmaDomain, DomainKind},
    memory::{CacheAttribute, MemoryError, PageGeometry, PageSource, PinnedPages},
    region::{self, DmaRegion},
};
use crate::block::BlockError;
use alloc::{sync::Arc as Domain, vec::Vec};
use triomphe::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationError {
    Region(region::Error),
    Metadata(MemoryError),
    LiveBuffers,
    /// Refusal before publication followed by uncertain mapping removal.
    Cleanup {
        rejected: region::Error,
        failure: region::Error,
    },
}

pub(super) struct Allocation {
    region: Option<DmaRegion>,
}

impl Allocation {
    pub(super) fn bus_address(&self) -> u64 {
        self.region
            .as_ref()
            .expect("live buffer retains its region")
            .device_address(0, 0)
            .expect("live buffer prevents retirement")
    }

    pub(super) fn cpu_address(&self, bytes: usize) -> *mut u8 {
        self.region
            .as_ref()
            .expect("live buffer retains its region")
            .cpu_address(0, bytes)
            .expect("allocation validated CPU extent")
            .as_ptr()
    }
}

/// Constrain the real provider's selection before it reserves RAM. A device
/// IOVA limit also constrains physical placement only for passthrough domains.
struct Below<'a> {
    source: &'a dyn PageSource,
    end: u64,
}
impl PageSource for Below<'_> {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        self.source.page_geometry()
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        self.source
            .allocate_below(bytes, alignment, attribute, self.end)
    }
}

/// Keeps all mappings allocated for one requester. Dropping the allocator
/// does not certify a device stop: outstanding mappings quarantine their pins.
/// Live buffers independently keep their CPU mapping and domain lease.
pub struct DomainAllocator<'a> {
    pages: &'a dyn PageSource,
    domain: Domain<dyn DmaDomain>,
    address_limit: u64,
    allocations: Vec<Arc<Allocation>>,
}

impl<'a> DomainAllocator<'a> {
    /// Adapt a real coherent requester to the legacy drivers' ordinary CPU
    /// load/store interface. A WB CPU mapping alone cannot check coherence.
    ///
    /// # Safety
    /// `domain` must be attached to the exclusively owned requester, whose
    /// previous DMA/IRQ/work was stopped and drained before this attachment.
    /// Its payload DMA must snoop the PageSource's WB CPU mappings,
    /// including writes observed while polling. NoSnoop/ATS/other bypass and
    /// incompatible cache aliases must be excluded by their real owners. The
    /// driver's descriptor publication and UC register operations must provide
    /// the platform's required coherent DMA ordering. The address limit comes
    /// from the controller's DMA capability, not its BAR width.
    /// Keep those owners and enter their required CPU/root/exclusion context
    /// for every allocation, buffer access and eventual retirement. PageSource
    /// must keep its real mapping in every such CPU context. No CPU pointer
    /// or copied page inventory can establish any of these requirements.
    pub unsafe fn new(
        pages: &'a dyn PageSource,
        domain: Domain<dyn DmaDomain>,
        address_limit: u64,
    ) -> Self {
        Self {
            pages,
            domain,
            address_limit,
            allocations: Vec::new(),
        }
    }

    fn allocate_buffer(
        &mut self,
        bytes: usize,
        align: usize,
    ) -> Result<DmaBuffer, AllocationError> {
        self.allocations
            .try_reserve(1)
            .map_err(|_| AllocationError::Metadata(MemoryError::OutOfMemory))?;
        // Reserve shared retention before installing a translation. The region
        // below remains the one canonical CPU/pin/alignment/domain mechanism.
        let mut allocation = Arc::try_new(Allocation { region: None })
            .map_err(|_| AllocationError::Metadata(MemoryError::OutOfMemory))?;
        let constrained = if self.domain.kind() == DomainKind::Passthrough {
            self.address_limit.checked_add(1).map(|end| Below {
                source: self.pages,
                end,
            })
        } else {
            None
        };
        let source = constrained
            .as_ref()
            .map_or(self.pages, |source| source as &dyn PageSource);
        let region = DmaRegion::allocate(
            source,
            self.domain.clone(),
            bytes,
            align,
            CacheAttribute::WriteBack,
            Direction::Bidirectional,
            self.address_limit,
        )
        .map_err(AllocationError::Region)?;
        let pointer = region
            .cpu_address(0, bytes)
            .expect("region validated logical extent");
        if !(pointer.as_ptr() as usize).is_multiple_of(align) {
            return Err(reject_unpublished(
                region,
                region::Error::Memory(MemoryError::InvalidAlignment),
            ));
        }
        // SAFETY: the original region owns this checked CPU extent and no
        // pointer/IOVA has escaped. Its requester cannot access this unpublished
        // allocation; constructor established coherent cache/context rules.
        unsafe { pointer.as_ptr().write_bytes(0, bytes) };
        if let Err(error) = region.sync_for_device(0..bytes) {
            return Err(reject_unpublished(region, error));
        }
        Arc::get_mut(&mut allocation)
            .expect("not yet shared")
            .region = Some(region);
        let buffer = DmaBuffer {
            memory: BufferMemory::Domain(allocation.clone()),
            bytes,
        };
        self.allocations.push(allocation);
        Ok(buffer)
    }

    /// Remove all remaining translations after the controller has stopped.
    /// A live buffer refuses before any unmap; failed unmaps remain retryable.
    /// This does not stop a controller or grant resource/controller retirement.
    ///
    /// # Safety
    /// All DMA to these buffers has completed; submissions, IRQ/work callbacks,
    /// posted writes and CPU users are drained and cannot restart. The kept
    /// domain/controller/root owners and their process context remain valid.
    pub unsafe fn retire(&mut self) -> Result<(), AllocationError> {
        if self
            .allocations
            .iter()
            .any(|allocation| Arc::strong_count(allocation) != 1)
        {
            return Err(AllocationError::LiveBuffers);
        }
        for allocation in &mut self.allocations {
            let allocation = Arc::get_mut(allocation).expect("checked unique buffer retention");
            if let Some(region) = &mut allocation.region {
                // SAFETY: caller proved quiescence; no buffer can keep this
                // mapping and its own domain keeps the translation owner live.
                unsafe { region.unmap() }.map_err(AllocationError::Region)?;
                allocation.region = None;
            }
        }
        self.allocations.clear();
        Ok(())
    }
}

impl DmaAllocator for DomainAllocator<'_> {
    fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
        self.allocate_buffer(bytes, align).map_err(BlockError::Dma)
    }
}

fn reject_unpublished(mut region: DmaRegion, rejected: region::Error) -> AllocationError {
    // SAFETY: neither the IOVA nor a buffer escaped this allocator. Failed
    // removal keeps the canonical region's pins/domain quarantined.
    match unsafe { region.unmap() } {
        Ok(()) => AllocationError::Region(rejected),
        Err(failure) => AllocationError::Cleanup { rejected, failure },
    }
}

#[cfg(test)]
mod tests;
