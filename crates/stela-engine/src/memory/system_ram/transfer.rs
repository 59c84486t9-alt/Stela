//! Native coherent host/table-walker transfers through the canonical RAM owner.
use super::RegisteredSystemRam;
use crate::memory::{backing::AccessKind, domain::PublicationFault};
use stela_compiler::context::memory::MemoryStatus;

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

    pub(crate) fn read_descriptor(&self, physical: u64) -> Result<u64, MemoryStatus> {
        if !physical.is_multiple_of(8) {
            return Err(MemoryStatus::InvalidRequest);
        }
        let mut bytes = [0; 8];
        // SAFETY: private local staging, disjoint from every canonical backing.
        unsafe { self.read_physical(physical, &mut bytes) }?;
        Ok(u64::from_le_bytes(bytes))
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
