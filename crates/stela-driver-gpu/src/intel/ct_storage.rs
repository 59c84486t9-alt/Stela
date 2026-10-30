//! Owned Xe GuC CT RAM preparation. This does not install GGTT mappings,
//! register/enable firmware transport, route interrupts or establish coherent
//! concurrent firmware access. Those missing operations remain owner duties.
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
};
use alloc::sync::Arc;

// Xe_guc_ct.c: separate BOs; descriptors are 64 bytes at H2G offset 0
// and G2H offset 0x800. Commands start at 0x1000 in each BO.
const DESCRIPTOR_BYTES: usize = 16 * 4;
const COMMAND_OFFSET: usize = 4096;
pub const H2G_COMMAND_BYTES: usize = 4096;
pub const G2H_COMMAND_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Memory(MemoryError),
    Dma(DmaError),
    InvalidAllocation,
}

impl From<MemoryError> for StorageError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}
impl From<DmaError> for StorageError {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CtBuffer {
    HostToGuc,
    GucToHost,
}

/// Matches the four region selectors in the native CT I/O adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CtRegion {
    H2gDescriptor,
    H2gCommands,
    G2hDescriptor,
    G2hCommands,
}

struct Buffer {
    dma: Option<DmaMapping>,
    descriptor: CpuMapping,
    commands: CpuMapping,
}

impl Buffer {
    fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        command_bytes: usize,
        descriptor_offset: usize,
        address_limit: u64,
    ) -> Result<Self, StorageError> {
        let bytes = COMMAND_OFFSET + command_bytes;
        let pages = source.allocate(bytes, 4096, CacheAttribute::WriteBack)?;
        if pages.logical_bytes() != bytes || pages.cache_attribute() != CacheAttribute::WriteBack {
            return Err(StorageError::InvalidAllocation);
        }
        // Canonical PageSource/PageBacking owns zeroing, reservations, cache
        // attributes and the mapping. No allocator or physical address fallback.
        let descriptor = pages.cpu_mapping_range(
            CacheAttribute::WriteBack,
            descriptor_offset..descriptor_offset + DESCRIPTOR_BYTES,
        )?;
        let commands = pages.cpu_mapping_range(CacheAttribute::WriteBack, COMMAND_OFFSET..bytes)?;
        let dma = DmaMapping::map(domain, pages, Direction::Bidirectional, address_limit)?;
        Ok(Self {
            dma: Some(dma),
            descriptor,
            commands,
        })
    }

    fn mapping(&self) -> Result<&DmaMapping, DmaError> {
        self.dma.as_ref().ok_or(DmaError::Unmapped)
    }

    /// # Safety
    /// No device, GGTT binding, submission or IRQ worker may reference this
    /// allocation now or begin doing so during/after the removal.
    unsafe fn unmap(&mut self) -> Result<(), DmaError> {
        if let Some(mapping) = self.dma.as_mut() {
            // SAFETY: the private unpublished owner or public quiescent owner
            // establishes the complete device/worker stop requirement.
            unsafe { mapping.unmap()? };
            self.dma = None;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Storage {
    h2g: Option<Buffer>,
    g2h: Option<Buffer>,
}

impl Storage {
    fn buffer(&self, which: CtBuffer) -> &Buffer {
        match which {
            CtBuffer::HostToGuc => self.h2g.as_ref(),
            CtBuffer::GucToHost => self.g2h.as_ref(),
        }
        .expect("only complete CT storage is exposed")
    }

    fn region(&self, which: CtRegion) -> &CpuMapping {
        match which {
            CtRegion::H2gDescriptor => &self.buffer(CtBuffer::HostToGuc).descriptor,
            CtRegion::H2gCommands => &self.buffer(CtBuffer::HostToGuc).commands,
            CtRegion::G2hDescriptor => &self.buffer(CtBuffer::GucToHost).descriptor,
            CtRegion::G2hCommands => &self.buffer(CtBuffer::GucToHost).commands,
        }
    }

    /// # Safety
    /// Both allocations satisfy Buffer::unmap's complete quiescence contract.
    unsafe fn unmap(&mut self) -> Result<(), DmaError> {
        // Try both independent removals. A failed lease stays held for
        // retry, while successful removal never targets a reused token again.
        let h2g = self.h2g.as_mut().map_or(Ok(()), |buffer| {
            // SAFETY: the caller establishes quiescence for both buffers.
            unsafe { buffer.unmap() }
        });
        let g2h = self.g2h.as_mut().map_or(Ok(()), |buffer| {
            // SAFETY: the caller establishes quiescence for both buffers.
            unsafe { buffer.unmap() }
        });
        h2g.and(g2h)
    }
}

/// Storage whose DMA addresses have never been exposed by this API. Explicit
/// rollback can remove those mappings; Drop uses canonical DMA quarantine
/// because it cannot establish the domain's allowed process/deferred context.
/// CPU views expose raw pointers, never Rust buffer references.
pub struct UnpublishedCtStorage {
    storage: Storage,
}

impl UnpublishedCtStorage {
    pub fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        address_limit: u64,
    ) -> Result<Self, StorageError> {
        let mut result = Self {
            storage: Storage::default(),
        };
        let allocate = (|| -> Result<(), StorageError> {
            result.storage.h2g = Some(Buffer::allocate(
                source,
                Arc::clone(&domain),
                H2G_COMMAND_BYTES,
                0,
                address_limit,
            )?);
            result.storage.g2h = Some(Buffer::allocate(
                source,
                domain,
                G2H_COMMAND_BYTES,
                2048,
                address_limit,
            )?);
            Ok(())
        })();
        if let Err(error) = allocate {
            // Same process/deferred context as the successful map operation;
            // no device address was exposed, so no completion is invented.
            result.rollback()?;
            return Err(error);
        }
        Ok(result)
    }

    /// The borrowed canonical CPU mapping keeps its pin. Dereferencing a raw
    /// address requires exclusive CPU access and this storage's live lifetime.
    /// No device IOVA or GGTT address is available in the unpublished state.
    pub fn cpu_region(&self, region: CtRegion) -> &CpuMapping {
        self.storage.region(region)
    }

    /// Remove mappings that have never been exposed to the device. Call in
    /// the domain's allowed process/deferred context. Failed leases remain
    /// for retry; abandoning them invokes canonical quarantine.
    pub fn rollback(&mut self) -> Result<(), DmaError> {
        // SAFETY: only the unpublished type offers this safe operation, and
        // it has no API exposing an IOVA or installing a GGTT/device binding.
        unsafe { self.storage.unmap() }
    }

    /// Consume the unpublished state and complete the domain's DMA
    /// visibility operations before exposing any IOVA. This is a conservative
    /// publication boundary, not firmware registration or an enable ack. The
    /// owner can now install real GPU GGTT bindings and register/enable CT.
    /// Once addresses can escape, Drop never assumes device completion.
    pub fn publish(mut self) -> Result<PublishedCtStorage, StorageError> {
        let prepare = (|| -> Result<(), DmaError> {
            for which in [CtBuffer::HostToGuc, CtBuffer::GucToHost] {
                let mapping = self.storage.buffer(which).mapping()?;
                mapping.sync_for_device(0..mapping.bytes())?;
            }
            Ok(())
        })();
        if let Err(error) = prepare {
            self.rollback()?;
            return Err(error.into());
        }
        Ok(PublishedCtStorage {
            storage: self.storage,
        })
    }
}

/// Potentially published leases. `mapping().address()` is device IOVA, NEVER
/// GuC GGTT VA. Firmware registration requires separate real GGTT ownership.
/// Active CT access additionally needs concurrent DMA coherence, GT
/// power/forcewake, ordered MMIO and IRQ/fence ownership. This helper supplies
/// none of those services and must not be attached to CT callbacks as a proxy.
pub struct PublishedCtStorage {
    storage: Storage,
}

impl PublishedCtStorage {
    pub fn mapping(&self, buffer: CtBuffer) -> Result<&DmaMapping, DmaError> {
        self.storage.buffer(buffer).mapping()
    }

    /// Raw CPU views only. The owner must keep this storage while pointers
    /// are used, prove the device's real coherence/ownership protocol for each
    /// access and serialize CPU/firmware/IRQ users. No safe slice is exposed.
    /// DmaMapping::sync_for_cpu still requires its exclusive-completion
    /// contract; it cannot be used to pretend a concurrent GuC descriptor is
    /// quiescent. WB CPU cache policy alone does not prove device coherence.
    pub fn cpu_region(&self, region: CtRegion) -> &CpuMapping {
        self.storage.region(region)
    }

    /// # Safety
    /// Firmware CT is disabled/acknowledged, device accesses have
    /// ended, submissions and IRQ workers are stopped/drained, real GGTT
    /// bindings are removed with completed GT invalidation, and no future
    /// accesses can begin. Owner process/context restrictions still apply.
    /// Errors keep failed leases for retry; abandoning them quarantines the
    /// pages/domain. This method never manufactures completion proof.
    pub unsafe fn unmap_after_quiescence(&mut self) -> Result<(), DmaError> {
        // SAFETY: the caller establishes the complete hardware/worker stop.
        unsafe { self.storage.unmap() }
    }
}

#[cfg(test)]
mod tests;
