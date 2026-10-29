//! Binding host mappings into a memory domain, and their lifecycle.

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

/// One group/system, kept by its facades and returned immutable snapshot.
#[cfg_attr(
    not(host_memory),
    expect(
        dead_code,
        reason = "only the host shared-binding lifecycle reads the attributes back"
    )
)]
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
        // SAFETY: the binding keeps stable storage and pins its current host
        // rights, and the facade methods validate the logical extent first. The
        // service borrow excludes native access and rights changes. The caller
        // of the unsafe binding ensures every writer participates and sources
        // are private.
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
        // SAFETY: the service borrow pins the host rights and the backing; the
        // caller validated the extent and the private source.
        unsafe { self.system.publish(backing, offset, bytes) }
    }
}

impl OwnedMemory {
    /// Bind this fixed anonymous owner and its optional read-only guest
    /// publisher aliases.
    ///
    /// File copy-on-write, split initial host protections and rebinding are
    /// refused. Bound owners use the serialized lifecycle and snapshot APIs,
    /// and the returned domain keeps the storage even after the facade owners
    /// are dropped. Exclusive instructions and direct-RAM writers are not
    /// supported.
    ///
    /// # Safety
    /// No native access or service may be in flight. The caller supplies the
    /// ASID, mapping attributes and checked host target, with coherent
    /// write-back storage and pinned host rights. Every physical writer and
    /// alias must participate in the same system and backing; direct-RAM
    /// execution and external file or native writers are excluded. Sources
    /// passed to the bound writer methods must be private and disjoint from
    /// guest RAM. No existing backing or access may already own this storage.
    /// Guest storage must be disjoint from live Rust references, guest state,
    /// registered source snapshots, native code, the host stack and runtime
    /// metadata. Checked entry and policy validation are still required before
    /// guest effects.
    pub unsafe fn bind_shared_memory(
        &mut self,
        config: SharedMemoryConfig,
        publishers: &mut [&mut PublishedReadOnlyRegion],
    ) -> Result<Arc<MemoryDomain>, SharedBindingError> {
        // SAFETY: caller supplies the complete existing binding contract.
        unsafe { self.bind_shared_memory_group(config, &mut [], publishers) }
    }

    /// Bind whole facade owners to the same system and storage.
    ///
    /// # Safety
    /// As for `bind_shared_memory`, for every owner and publisher.
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
            let kind = allocation.storage.kind();
            #[cfg(host_memory)]
            if kind == StorageKind::PrivateFile {
                return Err(E::FileCopyOnWrite);
            }
            if kind == StorageKind::PublishedAliases {
                return Err(E::IncompatibleStorage);
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
            // SAFETY: the anonymous owner and its current rights are checked.
            // The binding alone controls the current view; protection changes
            // and publication exclude native access through the domain's
            // borrows.
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
            // SAFETY: one storage owns both private-file aliases; the backing
            // uses the writable publisher's rights, not the read-only guest
            // view.
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
                    // Both prefixes are bounded by the validated source.
                    completed: source_offset + fault.completed,
                })?;
        }
        Ok(())
    }
}

#[cfg(host_memory)]
mod lifecycle;

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

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
pub(crate) mod tests;
