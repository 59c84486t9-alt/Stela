//! Host publication through the machine's existing physical writer domain.

use super::{
    AccessKind, Arc, MemoryBacking, MemoryStatus, MemorySystem, Ordering, access, monitor,
};
use stela_compiler::TargetCpu;

const HOST_QUANTITY_BYTES: usize = 8;

/// Failed host publication, including the prefix actually written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationFault {
    pub status: MemoryStatus,
    pub completed: usize,
}

impl std::fmt::Display for PublicationFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "host publication failed after {} bytes: {:?}",
            self.completed, self.status
        )
    }
}

impl std::error::Error for PublicationFault {}

impl MemorySystem {
    /// Publish private host bytes to physical backing, invalidating reservations.
    ///
    /// Logical guest permission and whole-operation checks belong to the caller.
    /// A host publisher may therefore update a guest read-only view when it owns
    /// writable host publication authority. Every actual fragment invalidates
    /// reservations, including same-value writes and ABA updates through aliases.
    /// Bounds, host rights and recipe failures decline before any byte is written.
    /// Later domain/access errors report the prefix actually published; this is
    /// a host copyout API, not a whole guest-instruction transaction.
    /// Empty publication still validates and binds physical coherence ownership.
    ///
    /// # Safety
    /// The caller must own authority to publish to this backing and prevalidate
    /// any higher-level operation. The complete host extent must remain live,
    /// pinned, readable and writable coherent Normal-WB RAM throughout the call.
    /// Source bytes must be private and disjoint from all shared guest RAM. No
    /// Rust references may alias the destination. All physical writers and
    /// reservations must use this same system and backing identity. Do not
    /// reenter this system or call while holding any of its monitor gates.
    /// Native host faults require a separate resumable adapter; this API does
    /// not catch them.
    pub unsafe fn publish(
        &self,
        backing: &Arc<MemoryBacking>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), PublicationFault> {
        let preflight_fault = |status| PublicationFault {
            status,
            completed: 0,
        };
        if self.failed.load(Ordering::Acquire) {
            return Err(preflight_fault(MemoryStatus::Domain));
        }
        self.reservations
            .check_execution()
            .map_err(|_| preflight_fault(MemoryStatus::Domain))?;
        backing
            .bind_coherence(&self.identity)
            .map_err(|_| preflight_fault(MemoryStatus::Domain))?;
        offset
            .checked_add(bytes.len())
            .filter(|end| *end <= backing.bytes())
            .ok_or_else(|| preflight_fault(MemoryStatus::Translation))?;
        if bytes.is_empty() {
            return Ok(());
        }
        let map_extent_error = |error| {
            preflight_fault(match error {
                super::super::backing::AccessError::PermissionDenied(_) => MemoryStatus::Permission,
                _ => MemoryStatus::Translation,
            })
        };
        let pointer = backing
            .host_pointer(offset, bytes.len(), AccessKind::Write)
            .map_err(map_extent_error)?;
        // Scalar XCHG reads the old value as well as writing the replacement.
        backing
            .host_pointer(offset, bytes.len(), AccessKind::Read)
            .map_err(map_extent_error)?;
        // The scalar read/write helpers share width and quantity validation.
        // Preflight every recipe before the first reservation or byte effect.
        for part in PublicationParts::new(pointer.as_ptr() as usize, bytes.len()) {
            access::read_footprint(part.address, part.bytes, TargetCpu::Baseline)
                .map_err(|_| preflight_fault(MemoryStatus::Unsupported))?;
        }
        for part in PublicationParts::new(pointer.as_ptr() as usize, bytes.len()) {
            let mut staging = [0; HOST_QUANTITY_BYTES];
            staging[..part.bytes].copy_from_slice(&bytes[part.offset..part.offset + part.bytes]);
            let value = u128::from(u64::from_le_bytes(staging));
            let range = monitor::WriteRange::new(
                Arc::clone(backing),
                (offset + part.offset) as u64,
                part.bytes as u64,
            )
            .map_err(|_| PublicationFault {
                status: MemoryStatus::Domain,
                completed: part.offset,
            })?;
            self.reservations
                .with_writer(&range, monitor::Invalidation::BeforeAttempt, || {
                    // SAFETY: whole host extent and scalar recipes were checked;
                    // the caller pins rights and lifetime, with private staging.
                    unsafe {
                        access::write_part(
                            part.address as *mut u8,
                            part.bytes,
                            value,
                            TargetCpu::Baseline,
                        )
                    }
                })
                .map_err(|error| PublicationFault {
                    status: match error {
                        monitor::AccessError::Monitor(_) => MemoryStatus::Domain,
                        monitor::AccessError::Memory(_) => MemoryStatus::Unsupported,
                    },
                    completed: part.offset,
                })?;
        }
        Ok(())
    }
}

struct PublicationPart {
    address: usize,
    offset: usize,
    bytes: usize,
}

struct PublicationParts {
    address: usize,
    remaining: usize,
    offset: usize,
}

impl PublicationParts {
    fn new(address: usize, bytes: usize) -> Self {
        Self {
            address,
            remaining: bytes,
            offset: 0,
        }
    }
}

impl Iterator for PublicationParts {
    type Item = PublicationPart;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let available = HOST_QUANTITY_BYTES - (self.address & (HOST_QUANTITY_BYTES - 1));
        let bytes = 1 << self.remaining.min(available).ilog2();
        let part = PublicationPart {
            address: self.address,
            offset: self.offset,
            bytes,
        };
        self.address += bytes;
        self.offset += bytes;
        self.remaining -= bytes;
        Some(part)
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "publication/tests.rs"]
mod tests;
