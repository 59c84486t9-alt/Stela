//! Opt-in host writer binding for a fixed set of retained Normal-WB mappings.

use super::{
    OwnedMemory, PublishedReadOnlyRegion,
    backing::{AccessError, AccessPermissions, MemoryBacking, MemoryView},
    domain::{MappingAttributes, MemoryDomain, MemorySystem, PublicationFault},
    storage::StorageKind,
};
use std::sync::Arc;
use stela_compiler::{TargetCpu, context::memory::MemoryStatus};

/// Authoritative owner snapshot. Mapping attributes are never inferred from mmap.
pub struct SharedMemoryConfig {
    pub address_space: u64,
    pub system: Arc<MemorySystem>,
    pub target: TargetCpu,
    pub attributes: MappingAttributes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedBindingError {
    AddressSpaceUnusable,
    AlreadyBound,
    FileCopyOnWrite,
    SplitHostRights,
    IncompatibleStorage,
    Bounds,
    Backing(AccessError),
    Domain(MemoryStatus),
    SharedDomainBound,
}

impl std::fmt::Display for SharedBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shared memory binding failed: {self:?}")
    }
}
impl std::error::Error for SharedBindingError {}

/// One group/system, retained by its facades and returned immutable snapshot.
pub(super) struct SharedBinding {
    system: Arc<MemorySystem>,
    domain: Arc<MemoryDomain>,
}

impl std::fmt::Debug for SharedBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedBinding")
            .field("address_space", &self.domain.address_space())
            .finish_non_exhaustive()
    }
}

impl SharedBinding {
    pub(super) fn check(&self) -> Result<(), MemoryStatus> {
        self.domain.check_execution()
    }

    /// Source is independent private staging and backing is this group's slot.
    pub(super) fn publish(
        &self,
        backing: &Arc<MemoryBacking>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), PublicationFault> {
        // SAFETY: binding retains stable real storage and pins its current host
        // rights; facade methods prevalidate logical extent/authority. Bound raw
        // snapshots, allocation and protection changes are explicitly declined.
        // The unsafe binding caller owns all-writer admission and private sources.
        unsafe { self.system.publish(backing, offset, bytes) }
    }
}

impl OwnedMemory {
    /// Bind this fixed anonymous owner and optional guest-RO publisher aliases.
    ///
    /// File COW, split host protections and rebinding explicitly decline. Bound
    /// owners decline protection, allocation and raw snapshot APIs. The returned
    /// domain retains actual storage even after facade owners are dropped.
    /// This does not admit exclusive instructions or legacy direct-RAM writers.
    ///
    /// # Safety
    /// No native access/service may be in flight. The caller supplies the actual
    /// ASID, mapping attributes and checked host target, with coherent Normal-WB
    /// storage and pinned current host rights. Every physical writer/alias must
    /// participate in the same system/backing identity; incompatible direct-RAM
    /// execution and external inode/native writers are excluded. Sources passed
    /// to bound writer methods must be private/disjoint from all guest RAM. No
    /// existing untracked backing identity or retained access may own this storage.
    /// Guest storage must be disjoint from all live Rust references, guest state,
    /// registered source/code snapshots, native code, host stack and runtime
    /// metadata. Source-derived checked entry and
    /// effective policy validation are still required before guest prefix effects.
    pub unsafe fn bind_shared_memory(
        &mut self,
        config: SharedMemoryConfig,
        publishers: &mut [&mut PublishedReadOnlyRegion],
    ) -> Result<Arc<MemoryDomain>, SharedBindingError> {
        use SharedBindingError as E;
        if !self.usable {
            return Err(E::AddressSpaceUnusable);
        }
        if self.shared.is_some() || publishers.iter().any(|owner| owner.shared.is_some()) {
            return Err(E::AlreadyBound);
        }
        if !config.target.supported() {
            return Err(E::Domain(MemoryStatus::Unsupported));
        }
        if self.allocations.len() != self.regions.len() {
            return Err(E::SplitHostRights);
        }
        if self.allocations.is_empty() && publishers.is_empty() {
            return Err(E::IncompatibleStorage);
        }
        // All source metadata is checked before constructing any physical owner.
        for (allocation, region) in self.allocations.iter().zip(&self.regions) {
            match allocation.storage.kind() {
                StorageKind::PrivateFile => return Err(E::FileCopyOnWrite),
                StorageKind::Anonymous => {}
                _ => return Err(E::IncompatibleStorage),
            }
            if allocation.shared_backing.is_some() {
                return Err(E::AlreadyBound);
            }
            if allocation.base != region.guest_address
                || allocation.logical_bytes != region.virtual_bytes
                || allocation.bytes != region.mapped_bytes
            {
                return Err(E::SplitHostRights);
            }
            if allocation.storage.primary_base().as_ptr() as usize as u64 != allocation.base
                || allocation.storage.bytes() as u64 != allocation.bytes
                || allocation.storage.publisher_base().is_some()
                || region.writable && !region.readable
                || region.executable && !region.readable
            {
                return Err(E::IncompatibleStorage);
            }
        }
        for owner in publishers.iter() {
            if owner.shared_backing.is_some() {
                return Err(E::AlreadyBound);
            }
            if owner.storage.kind() != StorageKind::PublishedAliases
                || owner.storage.publisher_base().is_none()
                || owner.storage.primary_base().as_ptr() as usize as u64
                    != owner.region.guest_address
                || owner.storage.bytes() as u64 != owner.region.mapped_bytes
                || !owner.region.readable
                || owner.region.writable
                || owner.region.executable
            {
                return Err(E::IncompatibleStorage);
            }
        }
        let mut backings = Vec::with_capacity(self.allocations.len());
        let mut publisher_backings = Vec::with_capacity(publishers.len());
        let mut views = Vec::with_capacity(self.regions.len() + publishers.len());
        for (allocation, region) in self.allocations.iter().zip(&self.regions) {
            let permissions = AccessPermissions {
                readable: region.readable,
                writable: region.writable,
                executable: region.executable,
            };
            // SAFETY: actual retained anonymous extent/current rights checked;
            // caller owns external access exclusion and actual coherent WB profile.
            let backing = unsafe {
                MemoryBacking::new(
                    allocation.storage.primary_base(),
                    allocation.storage.bytes(),
                    permissions,
                    Arc::clone(&allocation.storage),
                )
            }
            .map_err(E::Backing)?;
            let view = MemoryView::new(
                Arc::clone(&backing),
                region.guest_address,
                0,
                usize::try_from(region.virtual_bytes).map_err(|_| E::Bounds)?,
                permissions,
            )
            .map_err(E::Backing)?;
            views.push((view, config.attributes));
            backings.push(backing);
        }
        for owner in publishers.iter() {
            let host_rights = AccessPermissions {
                readable: true,
                writable: true,
                executable: false,
            };
            // SAFETY: one real storage owns both equal private-file aliases. The
            // canonical backing uses writable publisher authority, not guestRO.
            let backing = unsafe {
                MemoryBacking::new(
                    owner.storage.publisher_base().expect("validated publisher"),
                    owner.storage.bytes(),
                    host_rights,
                    Arc::clone(&owner.storage),
                )
            }
            .map_err(E::Backing)?;
            let view = MemoryView::new(
                Arc::clone(&backing),
                owner.region.guest_address,
                0,
                usize::try_from(owner.region.virtual_bytes).map_err(|_| E::Bounds)?,
                AccessPermissions {
                    writable: false,
                    ..host_rights
                },
            )
            .map_err(E::Backing)?;
            views.push((view, config.attributes));
            publisher_backings.push(backing);
        }
        let domain = MemoryDomain::new_for_address_space(
            config.address_space,
            Arc::clone(&config.system),
            views,
            config.target,
        )
        .map_err(E::Domain)?;
        domain.check_execution().map_err(E::Domain)?;
        let shared = Arc::new(SharedBinding {
            system: config.system,
            domain,
        });
        // All fallible work is complete. Install exactly the arcs used by views.
        for (allocation, backing) in self.allocations.iter_mut().zip(backings) {
            allocation.shared_backing = Some(backing);
        }
        for (owner, backing) in publishers.iter_mut().zip(publisher_backings) {
            owner.shared_backing = Some(backing);
            owner.shared = Some(Arc::clone(&shared));
        }
        self.shared = Some(Arc::clone(&shared));
        Ok(Arc::clone(&shared.domain))
    }

    pub(super) fn write_shared(&self, address: u64, bytes: &[u8]) -> anyhow::Result<()> {
        let shared = self.shared.as_ref().expect("bound writer");
        shared.check().map_err(|status| PublicationFault {
            status,
            completed: 0,
        })?;
        for (start, count, source_offset) in self.access_spans(address, bytes.len()) {
            let allocation = self
                .allocations
                .iter()
                .find(|allocation| {
                    start >= allocation.base && start - allocation.base < allocation.logical_bytes
                })
                .expect("validated span retains allocation");
            let backing = allocation
                .shared_backing
                .as_ref()
                .expect("canonical bound backing");
            let backing_offset = usize::try_from(start - allocation.base)?;
            shared
                .publish(
                    backing,
                    backing_offset,
                    &bytes[source_offset..source_offset + count],
                )
                .map_err(|fault| PublicationFault {
                    status: fault.status,
                    // Both prefixes are bounded by the already validated source.
                    completed: source_offset + fault.completed,
                })?;
        }
        Ok(())
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "binding/tests.rs"]
pub(crate) mod tests;
