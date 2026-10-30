//! Native read footprints, including the separately owned system-RAM
//! CX16 alternative. Source permissions never grant its extra host rights.
use super::{
    AccessKind, Arc, DomainRole, MemoryDomain, MemoryStatus, ResolvedAccess, access, monitor,
};
use crate::memory::backing::MemoryBacking;

pub(super) struct PreparedRead {
    backing: Arc<MemoryBacking>,
    offset: usize,
    bytes: usize,
    native: access::system::Read,
}
impl PreparedRead {
    /// # Safety
    /// The caller keeps the resolved live mapping/native invocation. When
    /// this recipe writes back, the monitor's physical observer/load
    /// gate covers its entire aligned footprint, including every alias.
    pub(super) unsafe fn read_in_observer(&self) -> Result<u128, MemoryStatus> {
        // SAFETY: preparation established host rights/geometry; caller supplies
        // the physical gate and native target/control ownership.
        unsafe { self.native.read() }.map_err(|_| MemoryStatus::Unsupported)
    }
}
impl MemoryDomain {
    pub(super) fn prepare_read(
        &self,
        first: &ResolvedAccess,
        bytes: usize,
    ) -> Result<PreparedRead, MemoryStatus> {
        let pointer = first.host_ptr().as_ptr() as usize;
        if self.role != DomainRole::NativeSystemRam {
            // Legacy profiles keep their real read-only host contract.
            access::read_footprint(pointer, bytes, self.target)
                .map_err(|_| MemoryStatus::Unsupported)?;
        }
        let native = access::system::Read::prepare(pointer, bytes, self.target)
            .map_err(|_| MemoryStatus::Unsupported)?;
        let (address, footprint) = native.footprint();
        let offset = first
            .backing_offset()
            .checked_sub(pointer - address)
            .ok_or(MemoryStatus::Unsupported)?;
        let backing = Arc::clone(first.view().backing());
        backing
            .host_pointer(offset, footprint, AccessKind::Read)
            .map_err(|_| MemoryStatus::Unsupported)?;
        if native.writes_back() {
            if self.role != DomainRole::NativeSystemRam {
                return Err(MemoryStatus::Unsupported);
            }
            // This is a host footprint requirement, never guest write permission
            // or another source access. Failure is a platform refusal.
            backing
                .host_pointer(offset, footprint, AccessKind::Write)
                .map_err(|_| MemoryStatus::Unsupported)?;
        }
        Ok(PreparedRead {
            backing,
            offset,
            bytes: footprint,
            native,
        })
    }

    pub(super) fn read_part(
        &self,
        first: &ResolvedAccess,
        bytes: usize,
    ) -> Result<u128, MemoryStatus> {
        let read = self.prepare_read(first, bytes)?;
        if read.native.writes_back() {
            let range = monitor::WriteRange::new(
                Arc::clone(&read.backing),
                read.offset as u64,
                read.bytes as u64,
            )
            .map_err(|_| MemoryStatus::Domain)?;
            self.system
                .reservations
                .with_observer(&range, || {
                    // SAFETY: the canonical same-physical writer gate covers the
                    // entire preflighted RW footprint. No reservation is invalidated.
                    unsafe { read.read_in_observer() }
                })
                .map_err(|error| match error {
                    monitor::AccessError::Memory(status) => status,
                    monitor::AccessError::Monitor(_) => MemoryStatus::Domain,
                })
        } else {
            // SAFETY: this is the read-only SCA recipe; no host writer
            // effect requires an observer gate. Native invocation pins rights.
            unsafe { read.read_in_observer() }
        }
    }
}
