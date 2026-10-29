//! WB memory for one AMD 4 KiB page table. This component
//! grants no remapper access and performs no implicit IOTLB acknowledgement.
use super::format::{FormatError, PageEntry, PhysicalAddress};
use crate::bus::dma::memory::{CacheAttribute, CpuMapping, MemoryError, PageSource};
use core::ptr::NonNull;

pub const TABLE_BYTES: usize = 4096;
pub const TABLE_ENTRIES: usize = TABLE_BYTES / size_of::<u64>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    Memory(MemoryError),
    Format(FormatError),
    EntryIndex,
    InvalidProvider,
}

/// Real cache/order publication for the current platform and remapping unit.
///
/// # Safety
/// An implementation must check IOMMU table-walk coherency and the
/// CPU/root/cache context, then perform the required coherent ordering or
/// checked cache maintenance for the entire WB CPU span. Success means
/// hardware can observe every preceding table store. No compiler-only fence,
/// CPU-pointer-as-PA inference or unsupported-success path satisfies this.
/// It cannot keep the borrowed pointer, modify entries, reenter their owner
/// or use this callback as an IOTLB invalidation/completion witness.
pub unsafe trait TableVisibility {
    /// # Safety
    /// `cpu..cpu+bytes` is held, aligned WB CPU RAM for this call. All
    /// software table writers are excluded; no access escapes this borrowing.
    unsafe fn publish(&self, cpu: NonNull<u8>, bytes: usize) -> Result<(), MemoryError>;
}

/// The CPU view keeps the complete original platform pin, even when only
/// the first 4 KiB of a larger native allocation is used by the table walker.
///
/// A consumer publishing this physical address must keep the table through
/// all hardware walks and acknowledged invalidation/reset. A live unit's Drop
/// must quarantine uncertain owners rather than release them. This memory
/// object does not know whether a caller programmed hardware with its address.
pub struct TablePage {
    cpu: CpuMapping,
    physical: PhysicalAddress,
    native_shift: u8,
    retained_bytes: usize,
}

impl TablePage {
    /// # Safety
    /// Each successful source allocation supplies fresh, currently zeroed CPU
    /// storage exclusively for this table's mutation until Drop. No cloned pin,
    /// other table, hardware writer or raw CPU writer may alias it. PageSource
    /// is a shared safe allocator interface and cannot itself attest this grant.
    /// The consumer separately keeps tables through live hardware ownership.
    pub unsafe fn allocate(source: &dyn PageSource, physical_bits: u8) -> Result<Self, TableError> {
        // Validate the device's width before any provider allocation.
        PhysicalAddress::new(0, physical_bits).map_err(TableError::Format)?;
        let geometry = source.page_geometry().map_err(TableError::Memory)?;
        let bytes = geometry.base_bytes();
        let pages = source
            .allocate(bytes, bytes, CacheAttribute::WriteBack)
            .map_err(TableError::Memory)?;
        if !geometry.supports(pages.page_shift())
            || pages.logical_bytes() != bytes
            || pages.bytes() < TABLE_BYTES
            || pages.cache_attribute() != CacheAttribute::WriteBack
        {
            return Err(TableError::InvalidProvider);
        }
        let physical = PhysicalAddress::new(pages.physical_pages()[0], physical_bits)
            .map_err(TableError::Format)?;
        if !physical.value().is_multiple_of(TABLE_BYTES as u64)
            || physical
                .value()
                .checked_add(TABLE_BYTES as u64)
                .is_none_or(|end| end > 1u64 << physical_bits)
        {
            return Err(TableError::InvalidProvider);
        }
        let cpu = pages
            .cpu_mapping_range(CacheAttribute::WriteBack, 0..TABLE_BYTES)
            .map_err(TableError::Memory)?;
        let address = cpu.address(0, TABLE_BYTES).map_err(TableError::Memory)?;
        if !(address.as_ptr() as usize).is_multiple_of(TABLE_BYTES) {
            return Err(TableError::InvalidProvider);
        }
        let native_shift = pages.page_shift();
        let retained_bytes = pages.bytes();
        // The producer grants fresh, currently zeroed bytes; do not clear a
        // second time after the real provider's allocation initialization.
        Ok(Self {
            cpu,
            physical,
            native_shift,
            retained_bytes,
        })
    }

    pub fn physical(&self) -> PhysicalAddress {
        self.physical
    }

    pub fn native_shift(&self) -> u8 {
        self.native_shift
    }

    /// Complete native pin, including every unused allocation tail kept by
    /// the CPU view. This is distinct from the 4 KiB hardware table extent.
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    fn pointer(&self, index: usize) -> Result<NonNull<u64>, TableError> {
        if index >= TABLE_ENTRIES {
            return Err(TableError::EntryIndex);
        }
        self.cpu
            .address(index * size_of::<u64>(), size_of::<u64>())
            .map(NonNull::cast)
            .map_err(TableError::Memory)
    }

    pub fn read(&self, index: usize) -> Result<u64, TableError> {
        // SAFETY: bounded aligned kept WB table word, no Rust data slice
        // aliases the hardware table. The consumer excludes software writers.
        Ok(u64::from_le(unsafe {
            self.pointer(index)?.as_ptr().read_volatile()
        }))
    }

    pub fn write(&mut self, index: usize, entry: PageEntry) -> Result<(), TableError> {
        // SAFETY: exclusive CPU mutation of a complete checked table word.
        // The live consumer owns cache publication and invalidation sequencing.
        unsafe {
            self.pointer(index)?
                .as_ptr()
                .write_volatile(entry.bits().to_le())
        };
        Ok(())
    }

    /// Clear every entry. This does not establish hardware retirement.
    pub fn clear(&mut self) {
        for index in 0..TABLE_ENTRIES {
            // Every index is inside the fixed page; no allocation or
            // platform callback can fail while zeroing an established table.
            self.write(index, PageEntry::EMPTY)
                .expect("bounded table clear");
        }
    }

    pub fn publish(&self, visibility: &impl TableVisibility) -> Result<(), TableError> {
        let cpu = self
            .cpu
            .address(0, TABLE_BYTES)
            .map_err(TableError::Memory)?;
        // SAFETY: the kept, aligned WB table span; &self excludes
        // safe software mutation until the real visibility operation returns.
        unsafe { visibility.publish(cpu, TABLE_BYTES) }.map_err(TableError::Memory)
    }
}

#[cfg(test)]
mod tests;
