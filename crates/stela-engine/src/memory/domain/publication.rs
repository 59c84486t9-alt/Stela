//! Publishing host writes through the domain's physical writer.

use super::{
    AccessKind, Arc, MemoryBacking, MemoryStatus, MemorySystem, Ordering, access, monitor,
};
use alloc::vec::Vec;
use stela_compiler::TargetCpu;

const HOST_QUANTITY_BYTES: usize = 8;
/// Untracked publication takes one writer gate per page of this size.
const PUBLICATION_PAGE_BYTES: usize = 16 * 1024;

/// Failed host publication, including the prefix written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationFault {
    pub status: MemoryStatus,
    pub completed: usize,
}

impl core::fmt::Display for PublicationFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "host publication failed after {} bytes: {:?}",
            self.completed, self.status
        )
    }
}

impl core::error::Error for PublicationFault {}

impl MemorySystem {
    /// Conditionally update one aligned physical descriptor under its exact
    /// all-writer reservation gate. A comparison miss performs no store and
    /// does not invalidate reservations; a same-value successful write does.
    ///
    /// # Safety
    /// The backing allocation stays live, pinned, coherent write-back raw RAM,
    /// with no aliasing Rust references. For an admitted descriptor access, the
    /// caller owns the descriptor and every physical writer (including source
    /// and host aliases) uses this same system; there is no external DMA writer.
    /// This function checks coherence identity, alignment, bounds and rights
    /// before accessing descriptor bytes. Source/code publication remains the
    /// outer lifecycle owner's responsibility.
    pub(in crate::memory) unsafe fn compare_update_descriptor(
        &self,
        backing: &Arc<MemoryBacking>,
        offset: usize,
        expected: u64,
        replacement: u64,
    ) -> Result<bool, MemoryStatus> {
        self.reservations
            .check_execution()
            .map_err(|_| MemoryStatus::Domain)?;
        if self.failed.load(Ordering::Acquire) {
            return Err(MemoryStatus::Domain);
        }
        backing
            .bind_coherence(&self.identity)
            .map_err(|_| MemoryStatus::Domain)?;
        if !offset.is_multiple_of(HOST_QUANTITY_BYTES) {
            return Err(MemoryStatus::InvalidRequest);
        }
        let pointer = backing
            .host_pointer(offset, HOST_QUANTITY_BYTES, AccessKind::Read)
            .map_err(|_| MemoryStatus::Translation)?;
        backing
            .host_pointer(offset, HOST_QUANTITY_BYTES, AccessKind::Write)
            .map_err(|_| MemoryStatus::Permission)?;
        if !(pointer.as_ptr() as usize).is_multiple_of(HOST_QUANTITY_BYTES) {
            return Err(MemoryStatus::Unsupported);
        }
        access::read_footprint(
            pointer.as_ptr() as usize,
            HOST_QUANTITY_BYTES,
            TargetCpu::Baseline,
        )
        .map_err(|_| MemoryStatus::Unsupported)?;
        let range = monitor::WriteRange::new(
            Arc::clone(backing),
            offset as u64,
            HOST_QUANTITY_BYTES as u64,
        )
        .map_err(|_| MemoryStatus::Domain)?;
        let mut mutation = self.prepare_source_write(backing, offset, HOST_QUANTITY_BYTES)?;
        enum Attempt {
            Mismatch,
            Native,
        }
        let result = self
            .reservations
            .with_writer(&range, monitor::Invalidation::OnCommit, || {
                // SAFETY: exact aligned private read while the same physical gate
                // excludes every source/host/alias writer. No AtomicLoad16 needed.
                let observed = unsafe {
                    access::read_part(pointer.as_ptr(), HOST_QUANTITY_BYTES, TargetCpu::Baseline)
                }
                .map_err(|_| Attempt::Native)? as u64;
                if observed != expected {
                    return Err(Attempt::Mismatch);
                }
                mutation.attempting();
                // SAFETY: the same pinned exact extent; XCHG publishes one SCA
                // write for ungated ordinary readers while our writer gate is held.
                unsafe {
                    access::write_part(
                        pointer.as_ptr(),
                        HOST_QUANTITY_BYTES,
                        u128::from(replacement),
                        TargetCpu::Baseline,
                    )
                }
                .map_err(|_| Attempt::Native)?;
                mutation.complete();
                Ok(())
            });
        match result {
            Ok(()) => Ok(true),
            Err(monitor::AccessError::Memory(Attempt::Mismatch)) => Ok(false),
            Err(_) => Err(MemoryStatus::Domain),
        }
    }

    /// Publish private host bytes to the backing, invalidating reservations.
    ///
    /// Guest permissions and whole-operation checks are the caller's, so a host
    /// publisher with writable rights may update a guest read-only view. Every
    /// fragment invalidates reservations, including same-value writes and ABA
    /// updates through aliases. Bounds, rights and recipe failures are reported
    /// before any byte is written; later errors report the published prefix.
    /// This is a host copyout, not a guest-instruction transaction. An empty
    /// publication still validates and binds the coherence owner.
    ///
    /// # Safety
    /// The caller may publish to this backing and has validated the operation.
    /// The whole extent stays live, pinned, readable and writable coherent
    /// write-back RAM for the call. The source bytes are private and disjoint
    /// from shared guest RAM, and no Rust reference aliases the destination.
    /// Every physical writer and reservation uses this system and backing. Do
    /// not re-enter the system or call while holding a monitor gate. Host
    /// faults are not caught.
    pub unsafe fn publish(
        &self,
        backing: &Arc<MemoryBacking>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), PublicationFault> {
        // SAFETY: the same contract as `publish_tracked`.
        unsafe { self.publish_tracked(backing, offset, bytes, None) }
    }

    /// The same publication, recording source writes for the write session.
    pub(in crate::memory) unsafe fn publish_tracked(
        &self,
        backing: &Arc<MemoryBacking>,
        offset: usize,
        bytes: &[u8],
        mut receipts: Option<&mut Vec<super::SourceWriteReceipt>>,
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
        // Preflight every recipe before the first reservation or byte effect:
        // the edge parts, and one aligned quadword standing for the middle.
        let address = pointer.as_ptr() as usize;
        let (head, middle) = quadword_middle(address, bytes.len());
        let tail = head + middle;
        let edges = PublicationParts::new(address, head)
            .chain(PublicationParts::new(address + tail, bytes.len() - tail));
        let sample = (middle != 0).then_some(PublicationPart {
            address: address + head,
            offset: head,
            bytes: HOST_QUANTITY_BYTES,
        });
        for part in edges.chain(sample) {
            access::read_footprint(part.address, part.bytes, TargetCpu::Baseline)
                .map_err(|_| preflight_fault(MemoryStatus::Unsupported))?;
        }
        if let Some(receipts) = receipts.as_mut() {
            // Every later push is allocation-free, including partial publication.
            receipts
                .try_reserve(PublicationParts::new(pointer.as_ptr() as usize, bytes.len()).count())
                .map_err(|_| preflight_fault(MemoryStatus::Domain))?;
        }
        if receipts.is_none() && !backing.source_mutation.enabled() {
            // Untracked bytes of one page share one writer gate. It holds
            // every stripe of the page's granules and invalidates their
            // reservations before the first store, so an exclusive pair on
            // any of them completes wholly before the page or fails, as it
            // would against the page's granules written one by one.
            let mut start = 0;
            while start < bytes.len() {
                let end = ((offset + start) / PUBLICATION_PAGE_BYTES + 1) * PUBLICATION_PAGE_BYTES;
                let end = (end - offset).min(bytes.len());
                let range = monitor::WriteRange::new(
                    Arc::clone(backing),
                    (offset + start) as u64,
                    (end - start) as u64,
                )
                .map_err(|_| PublicationFault {
                    status: MemoryStatus::Domain,
                    completed: start,
                })?;
                let mut completed = start;
                self.reservations
                    .with_writer(&range, monitor::Invalidation::BeforeAttempt, || {
                        // SAFETY: whole host extent and scalar recipes were
                        // checked; the caller pins rights and lifetime.
                        unsafe {
                            write_page(
                                pointer.as_ptr().add(start),
                                &bytes[start..end],
                                &mut completed,
                            )
                        }
                    })
                    .map_err(|error| PublicationFault {
                        status: match error {
                            monitor::AccessError::Monitor(_) => MemoryStatus::Domain,
                            monitor::AccessError::Memory(_) => MemoryStatus::Unsupported,
                        },
                        completed,
                    })?;
                start = end;
            }
            return Ok(());
        }
        for part in PublicationParts::new(pointer.as_ptr() as usize, bytes.len()) {
            let mut mutation = self
                .prepare_source_write(backing, offset + part.offset, part.bytes)
                .map_err(|status| PublicationFault {
                    status,
                    completed: part.offset,
                })?;
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
                    mutation.attempting();
                    // SAFETY: whole host extent and scalar recipes were checked;
                    // the caller pins rights and lifetime, with private staging.
                    unsafe {
                        access::write_part(
                            part.address as *mut u8,
                            part.bytes,
                            value,
                            TargetCpu::Baseline,
                        )
                    }?;
                    if let Some(receipt) = mutation.complete()
                        && let Some(receipts) = receipts.as_mut()
                    {
                        receipts.push(receipt);
                    }
                    Ok::<_, access::AccessError>(())
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

/// The bytes before the first aligned host quadword of an extent, and the
/// bytes of the whole aligned quadwords after them.
fn quadword_middle(address: usize, bytes: usize) -> (usize, usize) {
    let head = (address.next_multiple_of(HOST_QUANTITY_BYTES) - address).min(bytes);
    (
        head,
        (bytes - head) / HOST_QUANTITY_BYTES * HOST_QUANTITY_BYTES,
    )
}

/// Write `bytes` at `target` under the caller's writer gate: edge parts as
/// scalar stores, the aligned middle as quadword MOVs, then one fence.
/// `completed` advances by the bytes written, for a fault's prefix.
///
/// # Safety
/// The whole extent is live, pinned, writable coherent write-back RAM whose
/// scalar recipes were checked, and the caller holds its writer gate.
unsafe fn write_page(
    target: *mut u8,
    bytes: &[u8],
    completed: &mut usize,
) -> Result<(), access::AccessError> {
    let address = target as usize;
    let (head, middle) = quadword_middle(address, bytes.len());
    let scalars = |from: usize, to: usize, completed: &mut usize| {
        for part in PublicationParts::new(address + from, to - from) {
            let at = from + part.offset;
            let mut staging = [0; HOST_QUANTITY_BYTES];
            staging[..part.bytes].copy_from_slice(&bytes[at..at + part.bytes]);
            let value = u128::from(u64::from_le_bytes(staging));
            // SAFETY: inside the caller's checked extent and gate.
            unsafe {
                access::write_part(
                    part.address as *mut u8,
                    part.bytes,
                    value,
                    TargetCpu::Baseline,
                )
            }?;
            *completed += part.bytes;
        }
        Ok(())
    };
    scalars(0, head, completed)?;
    // SAFETY: the aligned middle lies inside the caller's extent. An aligned
    // quadword MOV is single-copy atomic like the XCHG it replaces, and the
    // fence below orders the page as each XCHG ordered its part.
    let quadwords = unsafe { target.add(head) }.cast::<u64>();
    let (whole, _) = bytes[head..head + middle].as_chunks::<HOST_QUANTITY_BYTES>();
    for (index, quadword) in whole.iter().enumerate() {
        let value = u64::from_le_bytes(*quadword);
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(quadwords.add(index), value) };
    }
    *completed += middle;
    scalars(head + middle, bytes.len(), completed)?;
    core::sync::atomic::fence(Ordering::SeqCst);
    Ok(())
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
mod tests;
