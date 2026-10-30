//! Pinned buffers for AMD IOMMU tables and queues.
use super::*;
use crate::bus::dma::memory::CpuMapping;

/// A complete native pin; hardware uses only the checked logical prefix.
pub(super) struct Buffer {
    cpu: CpuMapping,
    pub(super) physical: u64,
    bytes: usize,
}
impl Buffer {
    pub(super) fn allocate(
        source: &impl ColdPlatform,
        bytes: usize,
        bits: u8,
    ) -> Result<Self, Error> {
        let geometry = source.page_geometry().map_err(Error::Memory)?;
        let request = bytes.max(geometry.base_bytes());
        let pages = source
            .allocate(request, geometry.base_bytes(), CacheAttribute::WriteBack)
            .map_err(Error::Memory)?;
        if !geometry.supports(pages.page_shift())
            || pages.logical_bytes() != request
            || pages.bytes() < bytes
            || pages.cache_attribute() != CacheAttribute::WriteBack
        {
            return Err(Error::Profile);
        }
        let physical = pages.physical_pages()[0];
        let step = 1usize << pages.page_shift();
        if !physical.is_multiple_of(4096)
            || physical
                .checked_add(bytes as u64)
                .is_none_or(|end| end > 1u64 << bits)
            || pages.physical_pages()[..bytes.div_ceil(step)]
                .iter()
                .enumerate()
                .any(|(index, &pa)| physical.checked_add((index * step) as u64) != Some(pa))
        {
            return Err(Error::Profile);
        }
        let cpu = pages
            .cpu_mapping_range(CacheAttribute::WriteBack, 0..bytes)
            .map_err(Error::Memory)?;
        let address = cpu.address(0, bytes).map_err(Error::Memory)?;
        if !(address.as_ptr() as usize).is_multiple_of(4096) {
            return Err(Error::Profile);
        }
        // SAFETY: ColdPlatform grants fresh zeroed exclusive WB RAM. Actual
        // table/ring cache maintenance completes before any PA is published.
        unsafe { source.publish(address, bytes) }.map_err(Error::Memory)?;
        Ok(Self {
            cpu,
            physical,
            bytes,
        })
    }
    pub(super) fn pointer(&self, offset: usize, bytes: usize) -> Result<NonNull<u8>, Error> {
        if offset.checked_add(bytes).is_none_or(|end| end > self.bytes) {
            return Err(Error::Mapping);
        }
        self.cpu.address(offset, bytes).map_err(Error::Memory)
    }
    pub(super) fn command(&self, offset: usize, command: Command) -> Result<(), Error> {
        let pointer = self.pointer(offset, COMMAND_BYTES)?.cast::<u32>();
        for (index, word) in command.words().into_iter().enumerate() {
            // SAFETY: exact bounded aligned slot. Serialized CPU producer never
            // overwrites a slot until matching completion plus head admission.
            unsafe { pointer.as_ptr().add(index).write_volatile(word.to_le()) };
        }
        Ok(())
    }
    pub(super) fn sequence(&self) -> Result<u64, Error> {
        // SAFETY: aligned coherent completion RAM kept for this exact unit;
        // hardware is sole writer after publication. No Rust reference aliases.
        Ok(u64::from_le(unsafe {
            self.pointer(0, 8)?.cast::<u64>().as_ptr().read_volatile()
        }))
    }
    pub(super) fn publish(&self, platform: &impl ColdPlatform) -> Result<(), Error> {
        // SAFETY: entire kept WB span, with serialized CPU producer.
        unsafe { platform.publish(self.pointer(0, self.bytes)?, self.bytes) }.map_err(Error::Memory)
    }
}
