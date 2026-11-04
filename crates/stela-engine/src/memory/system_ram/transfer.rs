//! Native coherent host/table-walker transfers through the canonical RAM owner.
use super::{Region, RegisteredSystemRam};
use crate::memory::{access, backing::AccessKind, domain::PublicationFault};
use stela_compiler::{TargetCpu, context::memory::MemoryStatus};

/// A page-table walk's view of one registered RAM owner.
/// Keeps only the last immutable extent, never descriptor values.
pub struct DescriptorReader<'a> {
    ram: &'a RegisteredSystemRam,
    last: Option<&'a Region>,
}

impl RegisteredSystemRam {
    /// Publish private host bytes through every reached backing's same writer
    /// owner. Whole physical geometry is checked before the first byte effect;
    /// a later terminal coherence failure reports the exact committed prefix.
    ///
    /// # Safety
    /// Source bytes are private and disjoint from registered RAM/native frames.
    /// The registration all-writer/owner contract remains live. This is host
    /// copyout, not a source instruction or a code-publication acknowledgement.
    pub unsafe fn publish_physical(
        &self,
        physical: u64,
        bytes: &[u8],
    ) -> Result<(), PublicationFault> {
        self.preflight(physical, bytes.len())
            .map_err(|status| PublicationFault {
                status,
                completed: 0,
            })?;
        let mut done = 0;
        while done < bytes.len() {
            let (region, offset) = self
                .region(physical + done as u64)
                .ok_or(PublicationFault {
                    status: MemoryStatus::Domain,
                    completed: done,
                })?;
            let count = (bytes.len() - done).min(region.bytes - offset);
            // SAFETY: preflight checks the whole immutable physical placement;
            // registration keeps the same native writer and private source.
            unsafe {
                self.system
                    .publish(&region.backing, offset, &bytes[done..done + count])
            }
            .map_err(|fault| PublicationFault {
                status: fault.status,
                completed: done + fault.completed,
            })?;
            done += count;
        }
        Ok(())
    }

    /// Read a single aligned descriptor through the canonical RAM owner.
    pub fn read_descriptor(&self, physical: u64) -> Result<u64, MemoryStatus> {
        self.descriptor_reader().read_descriptor(physical)
    }

    /// Read a succession of descriptors through this registered owner.
    pub fn descriptor_reader(&self) -> DescriptorReader<'_> {
        DescriptorReader {
            ram: self,
            last: None,
        }
    }

    pub fn update_descriptor(
        &self,
        physical: u64,
        old: u64,
        new: u64,
    ) -> Result<bool, MemoryStatus> {
        self.preflight(physical, 8)?;
        if !physical.is_multiple_of(8) {
            return Err(MemoryStatus::InvalidRequest);
        }
        let (region, offset) = self.region(physical).ok_or(MemoryStatus::Translation)?;
        region
            .backing
            .host_pointer(offset, 8, AccessKind::Write)
            .map_err(|_| MemoryStatus::Permission)?;
        // SAFETY: the registration closes every physical writer over
        // this exact WB backing; no external DMA/direct writer participates.
        unsafe {
            self.system
                .compare_update_descriptor(&region.backing, offset, old, new)
        }
    }
}

impl DescriptorReader<'_> {
    /// Read one aligned descriptor through its live canonical backing.
    pub fn read_descriptor(&mut self, physical: u64) -> Result<u64, MemoryStatus> {
        if !physical.is_multiple_of(8) {
            return Err(MemoryStatus::InvalidRequest);
        }
        self.ram.domain.check_execution()?;
        let last = self.last.and_then(|region| {
            // Registration rejects extents that wrap, so an address below
            // the base always gives an offset beyond the extent's end.
            let offset = usize::try_from(physical.wrapping_sub(region.source_pa)).ok()?;
            (offset < region.bytes).then_some((region, offset))
        });
        let (region, offset) = last
            .or_else(|| {
                let (region, offset) = self.ram.region(physical)?;
                self.last = Some(region);
                Some((region, offset))
            })
            .ok_or(MemoryStatus::Translation)?;
        let pointer = region
            .backing
            .host_pointer(offset, 8, AccessKind::Read)
            .map_err(|_| MemoryStatus::Domain)?;
        // SAFETY: registration aligns both ends of each extent to at least
        // eight bytes. The pointer covers one aligned doubleword in its
        // pinned, coherent backing, with no Rust reference into guest RAM.
        unsafe { access::read_part(pointer.as_ptr(), 8, TargetCpu::Baseline) }
            .map(|value| value as u64)
            .map_err(|_| MemoryStatus::Domain)
    }

    /// Publish through the same canonical owner as a standalone update.
    pub fn update_descriptor(
        &self,
        physical: u64,
        old: u64,
        new: u64,
    ) -> Result<bool, MemoryStatus> {
        self.ram.update_descriptor(physical, old, new)
    }
}
