//! Owned system-RAM storage for amdgpu's CPU page-table writer.
//!
//! This module does not create a BO, GPU VM/root binding or GPU address space.
//! The canonical platform allocator and attached DMA domain supply all storage.
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
};
use alloc::sync::Arc;
use core::{ffi::c_void, marker::PhantomData};

/// AMDGPU_GPU_PAGE_SIZE in the amdgpu headers, independently of the
/// native CPU page size. These are ordinary system-memory leaf PTE updates.
pub const GPU_PAGE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Memory(MemoryError),
    Dma(DmaError),
    InvalidRange,
    MappingUnavailable,
}

/// An error after CPU stores may leave a modified, unpublished table. The real
/// owner must keep both table and source leases, then retry visibility or
/// tear down under GPU quiescence. No rollback or GPU flush is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateError {
    pub error: StorageError,
    pub written: u32,
}

/// Exact request to the existing CPU PTE loop. Flags and override selection
/// must come from the initialized GMC/VM policy, never a generic default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemPageUpdate {
    pub table_offset: usize,
    pub source_offset: usize,
    pub count: u32,
    pub flags: u64,
    pub override_pte: bool,
}

/// Exact invalid-entry policy selected by the initialized GMC/VM owner.
/// `flags` must encode an invalid entry for that table and generation;
/// clearing address bits alone does not invalidate a GPU translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemPageClear {
    pub table_offset: usize,
    pub count: u32,
    pub flags: u64,
}

/// Initialized GMC entry operations, borrowed for synchronous calls.
/// These functions must not unwind or keep the table pointer.
pub struct GmcCpuCallbacks<'a> {
    context: *mut c_void,
    override_flags: unsafe extern "C" fn(*mut c_void, u64, *mut u64),
    set_pte_pde: unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u64, u64),
    _borrow: PhantomData<&'a mut c_void>,
}

impl<'a> GmcCpuCallbacks<'a> {
    /// Borrow the device/VM owner's initialized generation callbacks.
    ///
    /// # Safety
    /// `context` and both callbacks must remain valid and exclusively borrowed
    /// for `'a`. They must implement the real GMC override and entry-write
    /// algorithms, including architecture-correct stores and flags. Every call
    /// must be synchronous, infallible for its prevalidated range, non-reentrant
    /// and non-unwinding. The override must resolve RAM/NUMA/coherency
    /// facts without treating domain IOVAs as CPU physical addresses. Callers
    /// must not supply placeholders or infer device initialization from PCI ID.
    pub unsafe fn borrow_initialized(
        context: *mut c_void,
        override_flags: unsafe extern "C" fn(*mut c_void, u64, *mut u64),
        set_pte_pde: unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u64, u64),
    ) -> Self {
        Self {
            context,
            override_flags,
            set_pte_pde,
            _borrow: PhantomData,
        }
    }
}

/// CPU and domain mappings from the same canonical reserved RAM allocation.
/// Dropping an active DMA lease uses canonical quarantine, keeping the real
/// pages and domain. Explicit release requires GPU quiescence and process or
/// deferred context; this type cannot prove those hardware conditions.
pub struct RamPageTable {
    cpu: CpuMapping,
    dma: DmaMapping,
}

impl RamPageTable {
    /// Allocate real table storage using the platform's existing page source
    /// and attached requester domain. `alignment`, cache policy and address
    /// limit must satisfy the device's requirements. Failure propagates
    /// the real service error; no identity-DMA or heap fallback exists.
    /// This does not publish or register the storage with a GPU.
    pub fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        address_limit: u64,
    ) -> Result<Self, StorageError> {
        if bytes == 0 || !bytes.is_multiple_of(size_of::<u64>()) || !alignment.is_power_of_two() {
            return Err(StorageError::InvalidRange);
        }
        let pages = source
            .allocate(bytes, alignment, attribute)
            .map_err(StorageError::Memory)?;
        if pages.logical_bytes() != bytes || pages.alignment() < alignment {
            return Err(StorageError::Memory(MemoryError::InvalidSize));
        }
        let cpu = pages
            .cpu_mapping_range(attribute, 0..bytes)
            .map_err(StorageError::Memory)?;
        let mut dma = DmaMapping::map(domain, pages, Direction::ToDevice, address_limit)
            .map_err(StorageError::Dma)?;
        if !dma
            .address()
            .map_err(StorageError::Dma)?
            .is_multiple_of(alignment as u64)
        {
            // SAFETY: this new mapping has not been exposed to any GPU owner.
            // Failure preserves the canonical quarantine instead of freeing it.
            unsafe { dma.unmap().map_err(StorageError::Dma)? };
            return Err(StorageError::InvalidRange);
        }
        Ok(Self { cpu, dma })
    }

    pub fn bytes(&self) -> usize {
        self.cpu.bytes()
    }

    /// Requester-domain IOVA, not a GPU VA or CPU physical address.
    /// Obtaining it does not establish GPU page-table binding or visibility.
    pub fn domain_address(&self) -> Result<u64, StorageError> {
        self.dma.address().map_err(StorageError::Dma)
    }

    /// Write bounded leaf PTEs with amdgpu's CPU loop, then perform the
    /// canonical DMA domain's CPU-to-device visibility operation.
    /// Success reports CPU entries written; it does not publish a GPU mapping.
    /// A DMA visibility error reports the written count and keeps ownership.
    ///
    /// # Safety
    /// The initialized GPU owns this table and `source` in exactly the
    /// same requester/domain. Its BO/VM reservations and reset/read exclusion
    /// must cover the entire update. All prior GPU/CPU users of this range must
    /// have finished; no concurrent writer or active Rust reference may alias
    /// the destination. The owner must validate table level/index and
    /// generation PTE flags, address-mask/aperture compatibility, source access
    /// rights and logical BO bounds. Source-data visibility and cache
    /// ownership transfers remain the source owner's responsibility. The
    /// callbacks must be that owner's initialized GMC operations. Domain IOVA,
    /// CPU physical pages and GPU VA must never be substituted for one another.
    /// Both table and source leases must remain held until PTE removal,
    /// GPU HDP/TLB publication/invalidation and hardware fence completion
    /// establish that no access remains. Required process/deferred context
    /// applies. This method supplies none of those VM, fence or TLB services.
    pub unsafe fn write_system_pages(
        &mut self,
        source: &DmaMapping,
        update: SystemPageUpdate,
        gmc: &mut GmcCpuCallbacks<'_>,
    ) -> Result<u32, UpdateError> {
        let fail = |error| UpdateError { error, written: 0 };
        self.dma.address().map_err(|e| fail(StorageError::Dma(e)))?;
        let source_base = source.address().map_err(|e| fail(StorageError::Dma(e)))?;
        let table_bytes = (update.count as usize)
            .checked_mul(size_of::<u64>())
            .ok_or_else(|| fail(StorageError::InvalidRange))?;
        let source_bytes = (update.count as usize)
            .checked_mul(GPU_PAGE_BYTES)
            .ok_or_else(|| fail(StorageError::InvalidRange))?;
        if !update.table_offset.is_multiple_of(size_of::<u64>())
            || !update.source_offset.is_multiple_of(GPU_PAGE_BYTES)
            || update
                .table_offset
                .checked_add(table_bytes)
                .is_none_or(|end| end > self.bytes())
            || update
                .source_offset
                .checked_add(source_bytes)
                .is_none_or(|end| end > source.bytes())
        {
            return Err(fail(StorageError::InvalidRange));
        }
        let address = source_base
            .checked_add(update.source_offset as u64)
            .ok_or_else(|| fail(StorageError::InvalidRange))?;
        if update.count == 0 {
            return Ok(0);
        }
        let table = self
            .cpu
            .address(update.table_offset, table_bytes)
            .map_err(|_| fail(StorageError::MappingUnavailable))?;
        // amdgpu_vm_cpu_update for a contiguous source, which has no pages_addr.
        let mut flags = update.flags;
        if update.override_pte {
            // SAFETY: the initialized GMC callback's contract covers these arguments.
            unsafe { (gmc.override_flags)(gmc.context, address, &mut flags) };
        }
        for index in 0..update.count {
            let entry = address + u64::from(index) * GPU_PAGE_BYTES as u64;
            // SAFETY: the mapping covers count entries from the checked offset;
            // the initialized GMC callback owns the architecture-correct store.
            unsafe { (gmc.set_pte_pde)(gmc.context, table.as_ptr().cast(), index, entry, flags) };
        }
        let written = update.count;
        if written != 0 {
            self.dma
                .sync_for_device(update.table_offset..update.table_offset + table_bytes)
                .map_err(|error| UpdateError {
                    error: StorageError::Dma(error),
                    written,
                })?;
        }
        Ok(written)
    }

    /// Replace bounded system-memory leaf PTEs with the initialized owner's
    /// invalid encoding, then make those CPU stores visible through the real
    /// DMA domain. Address bits are zero; `flags` supplies the GMC policy.
    /// No source-address override is run for an invalid entry.
    ///
    /// Success reports CPU entries written. It does not remove an existing GPU
    /// translation or authorize releasing its backing: GPU HDP/TLB invalidation
    /// and completion remain mandatory, even after successful DMA visibility.
    /// A visibility failure keeps modified entries and reports their count.
    ///
    /// # Safety
    /// The initialized VM owner must hold the same reservations, table
    /// level/index, reset and CPU-write exclusion as `write_system_pages`.
    /// `flags` must be that generation's invalid system-memory leaf encoding,
    /// with no valid/access bits, PRT/sparse marker or physical address bits.
    /// Sparse/fault mappings require their original separate VM path. The
    /// callbacks must belong to this initialized GMC and implement its
    /// entry stores.
    /// All old source/table leases and VM references must remain held until
    /// GPU HDP/TLB invalidation and hardware completion establish that
    /// stale translations and in-flight requests cannot access them. No new
    /// writer or submission may race the clear/publication/retirement sequence.
    /// Required process/deferred context applies. This operation itself proves
    /// neither GPU quiescence nor the absence of cached translations.
    pub unsafe fn clear_system_pages(
        &mut self,
        update: SystemPageClear,
        gmc: &mut GmcCpuCallbacks<'_>,
    ) -> Result<u32, UpdateError> {
        let fail = |error| UpdateError { error, written: 0 };
        self.dma.address().map_err(|e| fail(StorageError::Dma(e)))?;
        let table_bytes = (update.count as usize)
            .checked_mul(size_of::<u64>())
            .ok_or_else(|| fail(StorageError::InvalidRange))?;
        if !update.table_offset.is_multiple_of(size_of::<u64>())
            || update
                .table_offset
                .checked_add(table_bytes)
                .is_none_or(|end| end > self.bytes())
        {
            return Err(fail(StorageError::InvalidRange));
        }
        if update.count == 0 {
            return Ok(0);
        }
        let table = self
            .cpu
            .address(update.table_offset, table_bytes)
            .map_err(|_| fail(StorageError::MappingUnavailable))?;
        for index in 0..update.count {
            // SAFETY: the owner supplies the invalid-entry encoding and
            // initialized GMC store; preflight bounds every destination entry.
            unsafe {
                (gmc.set_pte_pde)(gmc.context, table.as_ptr().cast(), index, 0, update.flags)
            };
        }
        self.dma
            .sync_for_device(update.table_offset..update.table_offset + table_bytes)
            .map_err(|error| UpdateError {
                error: StorageError::Dma(error),
                written: update.count,
            })?;
        Ok(update.count)
    }

    /// Release only after removal from all GPU page directories/VM roots,
    /// GPU TLB invalidation, completion and drained users. A failed
    /// domain unmap keeps storage for retry; Drop quarantines it otherwise.
    ///
    /// # Safety
    /// All hardware accesses have finished and cannot restart; reservations,
    /// submissions and IRQ workers referencing the table are drained. The
    /// canonical domain/backing's process/deferred release rules must hold.
    pub unsafe fn unmap(&mut self) -> Result<(), StorageError> {
        // SAFETY: caller establishes complete GPU quiescence and release context.
        unsafe { self.dma.unmap().map_err(StorageError::Dma) }
    }
}

#[cfg(test)]
mod tests;
