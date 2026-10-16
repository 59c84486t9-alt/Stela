//! Serialized host writer binding and lifecycle for retained Normal-WB mappings.

use super::{
    OwnedMemory, PublishedReadOnlyRegion,
    backing::{AccessError, AccessPermissions, MemoryBacking, MemoryView},
    domain::{MappingAttributes, MemoryDomain, MemorySystem, PublicationFault},
    storage::StorageKind,
};
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use stela_compiler::{TargetCpu, context::memory::MemoryStatus};

/// Opaque participation of a whole facade owner, without exposing mutation APIs.
pub struct SharedMemoryParticipant<'a> {
    owner: ParticipantOwner<'a>,
    address_space: u64,
}
enum ParticipantOwner<'a> {
    Owned(&'a mut OwnedMemory),
    Published(&'a mut PublishedReadOnlyRegion),
}
impl<'a> SharedMemoryParticipant<'a> {
    pub(crate) fn owned(owner: &'a mut OwnedMemory, address_space: u64) -> Self {
        Self {
            owner: ParticipantOwner::Owned(owner),
            address_space,
        }
    }
    pub(crate) fn published(owner: &'a mut PublishedReadOnlyRegion, address_space: u64) -> Self {
        Self {
            owner: ParticipantOwner::Published(owner),
            address_space,
        }
    }
}

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
    WrongAddressSpace,
    FileCopyOnWrite,
    SplitHostRights,
    IncompatibleStorage,
    Bounds,
    Backing(AccessError),
    Domain(MemoryStatus),
    SharedDomainBound,
}

impl core::fmt::Display for SharedBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "shared memory binding failed: {self:?}")
    }
}
impl core::error::Error for SharedBindingError {}

/// One group/system, retained by its facades and returned immutable snapshot.
// Only hosted shared-binding lifecycle reads the attributes back.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(super) struct SharedBinding {
    system: Arc<MemorySystem>,
    pub(super) domain: Arc<MemoryDomain>,
    pub(super) attributes: MappingAttributes,
}

impl core::fmt::Debug for SharedBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
        // rights; facade methods prevalidate current logical extent/authority.
        // The retained service loan excludes native access and rights changes.
        // The unsafe binding caller owns all-writer admission and private sources.
        let service = self
            .domain
            .service_loan()
            .map_err(|status| PublicationFault {
                status,
                completed: 0,
            })?;
        self.publish_in_service(&service, backing, offset, bytes)
    }

    fn publish_in_service(
        &self,
        loan: &super::domain::MemoryServiceLoan,
        backing: &Arc<MemoryBacking>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), PublicationFault> {
        if !loan.belongs_to(&self.domain) {
            return Err(PublicationFault {
                status: MemoryStatus::Domain,
                completed: 0,
            });
        }
        // SAFETY: same-domain service loan pins all current host rights and
        // canonical backing; caller validated logical extent/private source.
        unsafe { self.system.publish(backing, offset, bytes) }
    }
}

impl OwnedMemory {
    /// Bind complete facade participants without lending their private allocators
    /// or allowing publication outside the facade's declared field contract.
    ///
    /// # Safety
    /// Inherits bind_shared_memory's complete owner/alias/source contract.
    pub unsafe fn bind_shared_memory_participants(
        &mut self,
        config: SharedMemoryConfig,
        participants: &mut [SharedMemoryParticipant<'_>],
    ) -> Result<Arc<MemoryDomain>, SharedBindingError> {
        let mut owners = Vec::new();
        let mut publishers = Vec::new();
        for participant in participants {
            if participant.address_space != config.address_space {
                return Err(SharedBindingError::WrongAddressSpace);
            }
            match &mut participant.owner {
                ParticipantOwner::Owned(owner) => owners.push(&mut **owner),
                ParticipantOwner::Published(owner) => publishers.push(&mut **owner),
            }
        }
        // SAFETY: every opaque participant retains its actual facade owner.
        unsafe { self.bind_shared_memory_group(config, &mut owners, &mut publishers) }
    }

    /// Bind this fixed anonymous owner and optional guest-RO publisher aliases.
    ///
    /// File COW, split initial host protections and rebinding explicitly decline.
    /// Bound owners use serialized canonical lifecycle and snapshot APIs. The returned
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
        // SAFETY: caller supplies the complete existing binding contract.
        unsafe { self.bind_shared_memory_group(config, &mut [], publishers) }
    }

    /// Bind complete facade owners to the same system and actual storage.
    ///
    /// # Safety
    /// Inherits bind_shared_memory's contract for every owner and publisher.
    pub unsafe fn bind_shared_memory_group(
        &mut self,
        config: SharedMemoryConfig,
        facades: &mut [&mut OwnedMemory],
        publishers: &mut [&mut PublishedReadOnlyRegion],
    ) -> Result<Arc<MemoryDomain>, SharedBindingError> {
        let mut owners = Vec::with_capacity(facades.len() + 1);
        owners.push(self);
        owners.extend(facades.iter_mut().map(|owner| &mut **owner));
        use SharedBindingError as E;
        if owners.iter().any(|owner| !owner.usable) {
            return Err(E::AddressSpaceUnusable);
        }
        if owners.iter().any(|owner| owner.shared.is_some())
            || publishers.iter().any(|owner| owner.shared.is_some())
        {
            return Err(E::AlreadyBound);
        }
        if !crate::platform::cpu::admitted(config.target) {
            return Err(E::Domain(MemoryStatus::Unsupported));
        }
        if owners
            .iter()
            .any(|owner| owner.allocations.len() != owner.regions.len())
        {
            return Err(E::SplitHostRights);
        }
        if owners.iter().all(|owner| owner.allocations.is_empty()) && publishers.is_empty() {
            return Err(E::IncompatibleStorage);
        }
        // All source metadata is checked before constructing any physical owner.
        for (allocation, region) in owners
            .iter()
            .flat_map(|owner| owner.allocations.iter().zip(&owner.regions))
        {
            match allocation.storage.kind() {
                #[cfg(feature = "std")]
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
        let mut backings = Vec::with_capacity(
            owners
                .iter()
                .map(|owner| owner.allocations.len())
                .sum::<usize>(),
        );
        let mut publisher_backings = Vec::with_capacity(publishers.len());
        let mut views = Vec::with_capacity(
            owners
                .iter()
                .map(|owner| owner.regions.len())
                .sum::<usize>()
                + publishers.len(),
        );
        for (allocation, region) in owners
            .iter()
            .flat_map(|owner| owner.allocations.iter().zip(&owner.regions))
        {
            let permissions = AccessPermissions {
                readable: region.readable,
                writable: region.writable,
                executable: region.executable,
            };
            // SAFETY: actual anonymous owner/current rights checked. Binding
            // retains sole current-view authority; managed protection/publication
            // exclude native access through the same domain's real loans.
            let backing = unsafe {
                MemoryBacking::new_managed(
                    allocation.storage.primary_base(),
                    allocation.storage.bytes(),
                    AccessPermissions {
                        readable: allocation.maximum_readable,
                        writable: allocation.maximum_writable,
                        executable: allocation.maximum_executable,
                    },
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
            attributes: config.attributes,
        });
        // All fallible work is complete. Install exactly the arcs used by views.
        for (allocation, backing) in owners
            .iter_mut()
            .flat_map(|owner| owner.allocations.iter_mut())
            .zip(backings)
        {
            allocation.shared_backing = Some(backing);
        }
        for (owner, backing) in publishers.iter_mut().zip(publisher_backings) {
            owner.shared_backing = Some(backing);
            owner.shared = Some(Arc::clone(&shared));
        }
        for owner in owners {
            owner.shared = Some(Arc::clone(&shared));
        }
        Ok(Arc::clone(&shared.domain))
    }

    pub(super) fn write_shared(&self, address: u64, bytes: &[u8]) -> anyhow::Result<()> {
        let shared = self.shared.as_ref().expect("bound writer");
        shared.check().map_err(|status| PublicationFault {
            status,
            completed: 0,
        })?;
        let loan = shared
            .domain
            .service_loan()
            .map_err(|status| PublicationFault {
                status,
                completed: 0,
            })?;
        self.write_shared_in_service(&loan, address, bytes)
    }

    pub(in crate::memory) fn write_shared_in_service(
        &self,
        loan: &super::domain::MemoryServiceLoan,
        address: u64,
        bytes: &[u8],
    ) -> anyhow::Result<()> {
        let shared = self.shared.as_ref().ok_or(PublicationFault {
            status: MemoryStatus::Unsupported,
            completed: 0,
        })?;
        shared.check().map_err(|status| PublicationFault {
            status,
            completed: 0,
        })?;
        if !loan.belongs_to(&shared.domain) {
            return Err(PublicationFault {
                status: MemoryStatus::Domain,
                completed: 0,
            }
            .into());
        }
        self.validate_access(address, bytes.len(), true)?;
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
                .publish_in_service(
                    loan,
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

#[path = "binding/lifecycle.rs"]
#[cfg(feature = "std")]
mod lifecycle;

impl PublishedReadOnlyRegion {
    /// Check the actual canonical backing/domain association of a live helper.
    pub(crate) fn check_execution_thread<P: super::domain::DataPolicy>(
        &self,
        thread: &super::domain::MemoryThread<P>,
    ) -> Result<(), MemoryStatus> {
        let shared = self.shared.as_ref().ok_or(MemoryStatus::Unsupported)?;
        shared.check()?;
        if !thread.has_domain(&shared.domain) || self.shared_backing.is_none() {
            return Err(MemoryStatus::Domain);
        }
        Ok(())
    }
}

impl OwnedMemory {
    pub(crate) fn check_execution_thread<P: super::domain::DataPolicy>(
        &self,
        thread: &super::domain::MemoryThread<P>,
    ) -> Result<(), MemoryStatus> {
        let shared = self.shared.as_ref().ok_or(MemoryStatus::Unsupported)?;
        shared.check()?;
        if !thread.has_domain(&shared.domain)
            || self.allocations.iter().any(|a| a.shared_backing.is_none())
        {
            return Err(MemoryStatus::Domain);
        }
        Ok(())
    }
}
