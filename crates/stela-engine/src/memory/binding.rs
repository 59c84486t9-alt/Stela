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

/// One group/system, retained by its facades and returned immutable snapshot.
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
pub(crate) mod tests {
    use super::*;
    use crate::memory::{
        AllocateDataRequest, DataInheritance, DataPermissions, DataPlacement, MemoryRegionSpec,
        backing::AccessKind, host_page_size,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    pub(crate) fn config(system: Arc<MemorySystem>, address_space: u64) -> SharedMemoryConfig {
        SharedMemoryConfig {
            address_space,
            system,
            target: TargetCpu::Baseline,
            attributes: MappingAttributes {
                tagged: false,
                shareable: true,
            },
        }
    }

    pub(crate) fn owned() -> (OwnedMemory, u64) {
        let mut memory = OwnedMemory::map(Vec::new()).unwrap();
        let rights = DataPermissions {
            readable: true,
            writable: true,
            executable: false,
        };
        let allocation = memory
            .allocate_data(AllocateDataRequest {
                placement: DataPlacement::Anywhere { hint: 0 },
                bytes: host_page_size().unwrap() as u64,
                alignment_mask: 0,
                current: rights,
                maximum: rights,
                alias_tag: 0,
                inheritance: DataInheritance::Copy,
            })
            .unwrap();
        (memory, allocation.guest_address)
    }

    fn free_address(bytes: usize) -> u64 {
        // SAFETY: temporary fresh allocation; no byte access or exposed references.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        let address = ptr as usize as u64;
        // SAFETY: `ptr` is the reservation `mmap` returned above, released once.
        unsafe { libc::munmap(ptr, bytes) };
        address
    }

    pub(crate) fn published() -> PublishedReadOnlyRegion {
        for _ in 0..32 {
            if let Ok(owner) =
                PublishedReadOnlyRegion::map(free_address(host_page_size().unwrap()), &[7; 32])
            {
                return owner;
            }
        }
        panic!("no free alias fixture address");
    }

    pub(crate) fn native(backing: &Arc<MemoryBacking>, offset: usize, bytes: usize) -> u128 {
        let ptr = backing
            .host_pointer(offset, bytes, AccessKind::Read)
            .unwrap();
        // SAFETY: real retained pinned Normal-WB storage; exact baseline-fitting part.
        unsafe { crate::memory::access::read_part(ptr.as_ptr(), bytes, TargetCpu::Baseline) }
            .unwrap()
    }

    #[test]
    fn bind_retains_actual_storage_after_facade_drop() {
        let (mut memory, base) = owned();
        memory.write(base, &[42]).unwrap();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        let domain = unsafe {
            memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 9), &mut [])
        }
        .unwrap();
        let backing = Arc::clone(memory.allocations[0].shared_backing.as_ref().unwrap());
        assert_eq!(domain.address_space(), Some(9));
        drop(memory);
        assert_eq!(native(&backing, 0, 1), 42);
        drop(backing);
        use stela_compiler::context::memory::{
            MemoryRequest, MemoryRequirements, profile_requirements,
        };
        let mut thread = domain.thread(Policy);
        let mut staging = [0u8; 1];
        let request = MemoryRequest {
            address: base,
            data: staging.as_mut_ptr(),
            bytes: 1,
            flags: 0,
            pc: 0x4000,
        };
        let entry = thread
            .prepare(MemoryRequirements {
                required_profile: profile_requirements::NATIVE_ACCESS,
                ..Default::default()
            })
            .unwrap();
        // SAFETY: a checked read with private staging; after the facade and backing
        // are dropped, only the domain owns the mapping.
        let status = unsafe { entry.with_view(|view| (view.callback)(view, &request)) };
        assert_eq!(status, MemoryStatus::Success as u32);
        assert_eq!(staging, [42]);
        assert!(domain.check_execution().is_ok());
    }

    #[test]
    fn bound_exact_write_preserves_neighbors_and_supports_lifecycle() {
        let (mut memory, base) = owned();
        memory.write(base, &[0xa5; 32]).unwrap();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 1), &mut []) }
            .unwrap();
        memory.write(base + 7, &[1, 2, 3, 4, 5]).unwrap();
        let backing = memory.allocations[0].shared_backing.as_ref().unwrap();
        for i in 0..32 {
            assert_eq!(
                native(backing, i, 1),
                if (7..12).contains(&i) {
                    (i - 6) as u128
                } else {
                    0xa5
                }
            );
        }
        assert_eq!(memory.read_snapshot(base, 1).unwrap(), [0xa5]);
        assert_eq!(
            memory.protect_data(base, host_page_size().unwrap() as u64, true, false),
            Ok(())
        );
        let rights = DataPermissions {
            readable: true,
            writable: true,
            executable: false,
        };
        assert!(
            memory
                .allocate_data(AllocateDataRequest {
                    placement: DataPlacement::Anywhere { hint: 0 },
                    bytes: 1,
                    alignment_mask: 0,
                    current: rights,
                    maximum: rights,
                    alias_tag: 0,
                    inheritance: DataInheritance::Copy
                })
                .is_ok()
        );
        assert_eq!(
            // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
            // reference reaches it.
            unsafe {
                memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 2), &mut [])
            }
            .err()
            .unwrap(),
            SharedBindingError::AlreadyBound
        );
    }

    #[test]
    fn guest_ro_publisher_uses_same_group_and_retains_both_aliases() {
        let (mut memory, _) = owned();
        let mut owner = published();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        let domain = unsafe {
            memory.bind_shared_memory(
                config(MemorySystem::new(16, 8).unwrap(), 3),
                &mut [&mut owner],
            )
        }
        .unwrap();
        let backing = Arc::clone(owner.shared_backing.as_ref().unwrap());
        assert!(Arc::ptr_eq(
            memory.shared.as_ref().unwrap(),
            owner.shared.as_ref().unwrap()
        ));
        owner.publish(5, &[8, 9]).unwrap();
        assert_eq!(native(&backing, 5, 2), 0x0908);
        assert_eq!(owner.read_snapshot(0, 1).unwrap(), [7]);
        assert!(owner.publish(32, &[1]).is_err());
        assert_eq!(native(&backing, 7, 1), 7);
        drop(owner);
        drop(memory);
        assert_eq!(native(&backing, 5, 2), 0x0908);
        assert!(domain.check_execution().is_ok());
    }

    #[test]
    fn whole_range_bounds_failure_has_no_prefix_effect() {
        let (mut memory, base) = owned();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 4), &mut []) }
            .unwrap();
        let end = base + host_page_size().unwrap() as u64;
        assert!(memory.write(end - 1, &[9, 10]).is_err());
        assert_eq!(
            native(
                memory.allocations[0].shared_backing.as_ref().unwrap(),
                host_page_size().unwrap() - 1,
                1
            ),
            0
        );
    }

    #[test]
    fn split_rights_and_private_file_decline_before_binding() {
        let (mut memory, base) = owned();
        // A one-page mapping cannot split, so represent a split view with private
        // metadata, without touching host protections.
        let original = memory.regions[0].clone();
        let mut second = original.clone();
        second.guest_address += 16;
        second.virtual_bytes -= 16;
        memory.regions[0].virtual_bytes = 16;
        memory.regions.push(second);
        assert_eq!(
            // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
            // reference reaches it.
            unsafe {
                memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 5), &mut [])
            }
            .err()
            .unwrap(),
            SharedBindingError::SplitHostRights
        );
        assert!(memory.shared.is_none());
        assert_eq!(memory.read_snapshot(base, 1).unwrap(), [0]);
        let page = host_page_size().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        use std::io::Write;
        file.write_all(&vec![0; page]).unwrap();
        const MAX_MAPPING_ATTEMPTS: usize = 32;
        // A parallel test can take an address right after `free_address` releases
        // it, so obtain the private file mapping first.
        let mut last_mapping_error = None;
        let mut mapped = (0..MAX_MAPPING_ATTEMPTS)
            .find_map(|_| {
                // SAFETY: each test file is private to this test and stays open for the mapping's
                // life.
                let mapped = unsafe {
                    OwnedMemory::map_files(vec![crate::memory::FileMemoryRegionSpec {
                        guest_address: free_address(page),
                        virtual_bytes: page as u64,
                        file: file.try_clone().unwrap(),
                        file_offset: 0,
                        readable: true,
                        writable: true,
                        executable: false,
                    }])
                };
                match mapped {
                    Ok(memory) => Some(memory),
                    Err(error) => {
                        last_mapping_error = Some(error);
                        None
                    }
                }
            })
            .unwrap_or_else(|| {
                panic!(
                    "private file mapping fixture exhausted {MAX_MAPPING_ATTEMPTS} attempts: {}",
                    last_mapping_error.unwrap()
                )
            });
        assert_eq!(
            // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
            // reference reaches it.
            unsafe {
                mapped.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 5), &mut [])
            }
            .err()
            .unwrap(),
            SharedBindingError::FileCopyOnWrite
        );
        assert!(mapped.shared.is_none());
    }

    #[test]
    fn maximum_authority_does_not_promote_current_ro_view() {
        let (mut memory, base) = owned();
        memory
            .protect_data(base, host_page_size().unwrap() as u64, true, false)
            .unwrap();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 6), &mut []) }
            .unwrap();
        assert!(memory.allocations[0].maximum_writable);
        let backing = Arc::clone(memory.allocations[0].shared_backing.as_ref().unwrap());
        assert!(backing.maximum_permissions().writable);
        assert!(memory.write(base, &[1]).is_err());
        assert_eq!(native(&backing, 0, 1), 0);
    }

    #[test]
    fn multi_span_failure_reports_total_completed_prefix() {
        let page = host_page_size().unwrap();
        let mut memory = None;
        for _ in 0..32 {
            let base = free_address(2 * page);
            let region = |guest_address| MemoryRegionSpec {
                guest_address,
                virtual_bytes: page as u64,
                initial_bytes: vec![0; page],
                readable: true,
                writable: true,
                executable: false,
            };
            if let Ok(owner) = OwnedMemory::map(vec![region(base), region(base + page as u64)]) {
                memory = Some((owner, base));
                break;
            }
        }
        let (mut memory, base) = memory.unwrap();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 7), &mut []) }
            .unwrap();
        // Inject an unexpected second-span coherence mismatch into private metadata.
        // Both pages remain live/valid; first span really executes native publication.
        let original_second = Arc::clone(memory.allocations[1].shared_backing.as_ref().unwrap());
        let (mut rival, _) = owned();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        let other = unsafe {
            rival.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 8), &mut [])
        }
        .unwrap();
        // This allocation has its own backing; corrupt only the destination slot to
        // exercise rejection.
        memory.allocations[1].shared_backing = Some(Arc::clone(
            rival.allocations[0].shared_backing.as_ref().unwrap(),
        ));
        let error = memory
            .write(base + page as u64 - 3, &[1, 2, 3, 4, 5])
            .unwrap_err();
        let fault = error.downcast_ref::<PublicationFault>().unwrap();
        assert_eq!(
            *fault,
            PublicationFault {
                status: MemoryStatus::Domain,
                completed: 3
            }
        );
        assert_eq!(
            native(
                memory.allocations[0].shared_backing.as_ref().unwrap(),
                page - 3,
                1
            ),
            1
        );
        assert_eq!(
            native(memory.allocations[1].shared_backing.as_ref().unwrap(), 0, 1),
            0
        );
        assert_eq!(native(&original_second, 0, 1), 0);
        drop(other);
    }

    #[test]
    fn aligned_native_observer_never_sees_torn_bound_word() {
        let (mut memory, base) = owned();
        let first = 0x5555_5555_aaaa_aaaa_u64;
        let second = !first;
        memory.write(base, &first.to_le_bytes()).unwrap();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 9), &mut []) }
            .unwrap();
        let backing = Arc::clone(memory.allocations[0].shared_backing.as_ref().unwrap());
        let done = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&done);
        let started = Arc::new(std::sync::Barrier::new(2));
        let reader_started = Arc::clone(&started);
        let reader = std::thread::spawn(move || {
            let mut observations = 1;
            let initial = native(&backing, 0, 8) as u64;
            assert!(initial == first || initial == second);
            reader_started.wait();
            while !stop.load(Ordering::Acquire) {
                let v = native(&backing, 0, 8) as u64;
                assert!(v == first || v == second);
                observations += 1;
            }
            observations
        });
        started.wait();
        for i in 0..10000 {
            memory
                .write(base, &if i % 2 == 0 { first } else { second }.to_le_bytes())
                .unwrap();
        }
        done.store(true, Ordering::Release);
        assert!(reader.join().unwrap() > 0);
    }

    struct Policy;
    impl crate::memory::domain::DataPolicy for Policy {
        fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn translate(&self, address: u64) -> Result<u64, MemoryStatus> {
            Ok(address)
        }
        fn check(&mut self, _: crate::memory::domain::DataAccess<'_>) -> Result<(), MemoryStatus> {
            Ok(())
        }
    }

    #[test]
    fn actual_service_borrow_excludes_native_and_competing_facade_operations() {
        let (mut memory, base) = owned();
        let (mut facade, other) = owned();
        // SAFETY: new owned anonymous write-back storage with every writer.
        let domain = unsafe {
            memory.bind_shared_memory_group(
                config(MemorySystem::new(16, 8).unwrap(), 72),
                &mut [&mut facade],
                &mut [],
            )
        }
        .unwrap();
        let mut thread = domain.thread(Policy);
        let outer = domain.execution_loan().unwrap();
        assert!(memory.service_memory(&mut thread).is_err());
        drop(outer);
        {
            let mut service = memory.service_memory(&mut thread).unwrap();
            assert!(domain.execution_loan().is_err());
            assert!(facade.read_snapshot(other, 1).is_err());
            assert!(facade.write(other, &[9]).is_err());
            assert!(service.read_snapshot(other, 1).is_err());
            assert!(service.write(other, &[9]).is_err());
            assert!(service.read_snapshot(u64::MAX, 2).is_err());
            service.write(base, &[4, 5, 6]).unwrap();
            assert_eq!(service.read_snapshot(base, 3).unwrap(), [4, 5, 6]);
            assert!(service.is_usable());
            assert_eq!(domain.generation().unwrap(), 0);
        }
        assert!(domain.execution_loan().is_ok());
        assert_eq!(memory.read_snapshot(base, 3).unwrap(), [4, 5, 6]);
        assert_eq!(facade.read_snapshot(other, 1).unwrap(), [0]);
    }

    #[test]
    fn service_borrow_requires_actual_domain_even_with_equal_namespace() {
        let (mut memory, base) = owned();
        let (mut other, _) = owned();
        // SAFETY: each test owns an independent software domain.
        let domain = unsafe {
            memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 73), &mut [])
        }
        .unwrap();
        // SAFETY: independent storage, deliberately with the same ASID.
        let other_domain = unsafe {
            other.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 73), &mut [])
        }
        .unwrap();
        let mut wrong_thread = other_domain.thread(Policy);
        assert!(matches!(
            memory.service_memory(&mut wrong_thread),
            Err(MemoryStatus::Domain)
        ));
        let wrong_service = other_domain.service_loan().unwrap();
        for bytes in [&[][..], &[9][..]] {
            let error = memory
                .write_shared_in_service(&wrong_service, base, bytes)
                .unwrap_err();
            let fault = error.downcast_ref::<PublicationFault>().unwrap();
            assert_eq!(fault.status, MemoryStatus::Domain);
            assert_eq!(fault.completed, 0);
        }
        assert_eq!(memory.read_snapshot(base, 1).unwrap(), [0]);
        assert!(domain.execution_loan().is_ok());
        drop(wrong_service);
        let (mut private, _) = owned();
        assert!(matches!(
            private.service_memory(&mut wrong_thread),
            Err(MemoryStatus::Unsupported)
        ));
    }

    #[test]
    fn service_failure_poison_cannot_restore_native_admission_on_drop() {
        let (mut memory, _) = owned();
        // SAFETY: new owned storage with serialized writers.
        let domain = unsafe {
            memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 74), &mut [])
        }
        .unwrap();
        let mut thread = domain.thread(Policy);
        {
            let mut service = memory.service_memory(&mut thread).unwrap();
            service.poison();
            assert!(!service.is_usable());
            assert!(service.read_snapshot(0, 0).is_err());
            assert!(service.write(0, &[]).is_err());
        }
        assert!(domain.execution_loan().is_err());
        assert!(memory.service_memory(&mut thread).is_err());
        assert!(!memory.is_usable());
    }

    #[test]
    fn checked_entry_declines_unavailable_source_capabilities_before_effects() {
        use stela_compiler::context::memory::{
            MemoryRequirements, host_caps, profile_requirements,
        };
        let (mut memory, base) = owned();
        // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
        // reference reaches it.
        let domain = unsafe {
            memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 10), &mut [])
        }
        .unwrap();
        let mut thread = domain.thread(Policy);
        for caps in [host_caps::CX16, host_caps::ATOMIC_LOAD16] {
            assert!(matches!(
                thread.prepare(MemoryRequirements {
                    required_host_caps: caps,
                    required_profile: profile_requirements::NATIVE_ACCESS,
                    ..Default::default()
                }),
                Err(MemoryStatus::Unsupported)
            ));
            assert_eq!(
                native(memory.allocations[0].shared_backing.as_ref().unwrap(), 0, 8),
                0
            );
        }
        assert!(
            thread
                .prepare(MemoryRequirements {
                    required_profile: profile_requirements::NATIVE_ACCESS,
                    ..Default::default()
                })
                .is_ok()
        );
        memory.write(base, &9u64.to_le_bytes()).unwrap();
    }
}
