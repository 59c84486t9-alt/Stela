//! Guest memory mappings.
//!
//! Guest code is data to the host: no guest mapping is ever host-executable.
//! Mappings are placed exactly at the requested address without replacing an
//! existing allocation, and may be bound into a physical memory domain.

mod access;
mod allocation;
pub mod backing;
mod binding;
pub mod domain;
mod mapping;
pub mod monitor;
pub mod policy;
mod protection;
mod published;
mod service;
pub mod system_ram;
pub use system_ram::{
    CanonicalRamService, RegisteredSystemRam, RegistrationError as SystemRamRegistrationError,
    ReservedSystemRamRange,
};
pub mod stage1;
mod storage;
pub mod tag_execution;
pub mod tag_store;
pub mod tag_transfer;
pub mod tags;

pub use allocation::{
    AllocateDataError, AllocateDataRequest, AllocationOperation, DataAllocation, DataInheritance,
    DataPermissions, DataPlacement, PendingDataAllocation,
};
pub use binding::{SharedBindingError, SharedMemoryConfig};
#[cfg(host_memory)]
pub use mapping::FileMemoryRegionSpec;
pub use protection::{DataProtectionLimit, ProtectionError};
pub use published::PublishedReadOnlyRegion;
pub use service::GuestServiceMemory;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use alloc::{rc::Rc, sync::Arc};
use anyhow::{Context, Result, bail, ensure};
use binding::SharedBinding;
use core::marker::PhantomData;
#[cfg(host_memory)]
use mapping::page_rounded;
#[cfg(host_memory)]
use protection::host_protection;
use serde::Serialize;
use storage::NativeStorage;

pub const MAX_IMAGE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// Virtual-space limit for file-backed mappings. Snapshot and write operations
/// keep the smaller MAX_IMAGE_MEMORY_BYTES limit.
pub const MAX_FILE_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// End of the lower canonical user range in the direct-RAM profile. It does not
/// define the guest's VM maximum.
pub const DIRECT_RAM_USER_END: u64 = 1 << 47;

#[derive(Debug, Clone)]
pub struct MemoryRegionSpec {
    pub guest_address: u64,
    pub virtual_bytes: u64,
    pub initial_bytes: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryRegion {
    pub guest_address: u64,
    /// Exact guest-visible extent. Allocation padding is not guest memory.
    pub virtual_bytes: u64,
    /// Host-page extent of this protection view; views never cross allocations.
    pub mapped_bytes: u64,
    pub initial_bytes: usize,
    pub readable: bool,
    pub writable: bool,
    /// Guest instruction-fetch permission, never host execute permission.
    pub executable: bool,
}

impl MemoryRegion {
    fn end(&self) -> u64 {
        // Construction checks addition and the native address range.
        self.guest_address + self.virtual_bytes
    }
}

#[derive(Debug)]
// The freestanding mount does not create host mappings.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
struct Allocation {
    shared_backing: Option<Arc<backing::MemoryBacking>>,
    storage: Arc<NativeStorage>,
    base: u64,
    bytes: u64,
    logical_bytes: u64,
    maximum_readable: bool,
    maximum_writable: bool,
    maximum_executable: bool,
    #[cfg_attr(
        not(host_memory),
        allow(dead_code, reason = "only host-memory protection reads it")
    )]
    executable: bool,
    alias_tag: u8,
    inheritance: DataInheritance,
}
/// Private, non-shareable mappings with retained native storage lifetimes.
///
/// Safe operations copy bytes; they never lend Rust references into memory that
/// native guest code may mutate. Callers executing native code remain responsible
/// for its unsafe execution contract and must keep this owner alive throughout.
/// Internal retained storage can outlive this logical owner; retention alone does
/// not pin host rights or admit concurrent/shared execution.
#[derive(Debug)]
pub struct OwnedMemory {
    shared: Option<Arc<SharedBinding>>,
    regions: Vec<MemoryRegion>,
    allocations: Vec<Allocation>,
    page_bytes: u64,
    usable: bool,
    _not_send_sync: PhantomData<Rc<()>>,
}

#[cfg(host_memory)]
pub fn host_page_size() -> Result<usize> {
    // SAFETY: sysconf has no pointer arguments or mutable Rust state.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page > 0, "cannot determine host page size");
    let page = usize::try_from(page)?;
    ensure!(page.is_power_of_two(), "unsupported host page size");
    Ok(page)
}

#[cfg(not(feature = "std"))]
pub fn host_page_size() -> Result<usize> {
    bail!("UNSUPPORTED guest memory: the freestanding build maps no host pages")
}

/// Hosts without POSIX mappings back no guest memory.
#[cfg(all(feature = "std", not(host_memory)))]
pub fn host_page_size() -> Result<usize> {
    bail!("UNSUPPORTED guest memory: it needs a host with POSIX memory mappings")
}

impl OwnedMemory {
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// False only if a failed host operation could not restore prior rights.
    /// Safe byte APIs then decline; native executors must also refuse resumption.
    pub fn is_usable(&self) -> bool {
        self.usable
    }

    fn validate_access(&self, address: u64, length: usize, write: bool) -> Result<()> {
        ensure!(
            self.usable,
            "guest address space is unusable after failed protection rollback"
        );
        ensure!(
            length as u64 <= MAX_IMAGE_MEMORY_BYTES,
            "guest access exceeds memory limit"
        );
        let end = address
            .checked_add(length as u64)
            .context("guest access address overflow")?;
        if length == 0 {
            return Ok(());
        }
        let mut cursor = address;
        for region in &self.regions {
            if region.end() <= cursor {
                continue;
            }
            ensure!(
                region.guest_address <= cursor,
                "guest access reaches unmapped memory"
            );
            ensure!(
                if write {
                    region.writable
                } else {
                    region.readable
                },
                "guest access violates region permissions"
            );
            cursor = region.end().min(end);
            if cursor == end {
                return Ok(());
            }
        }
        bail!("guest access reaches unmapped memory")
    }

    /// Validate one complete private data write without changing any bytes.
    /// Platform copyout owners select whether whole-range preflight is appropriate.
    pub fn validate_write(&self, address: u64, length: usize) -> Result<()> {
        self.validate_access(address, length, true)
    }

    pub fn read_snapshot(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.validate_access(address, length, false)?;
        if let Some(shared) = &self.shared {
            return shared
                .domain
                .service_loan()
                .map_err(SharedBindingError::Domain)?
                .snapshot(address, length)
                .map_err(SharedBindingError::Domain)
                .map_err(Into::into);
        }
        let mut bytes = vec![0; length];
        for (start, count, offset) in self.access_spans(address, length) {
            // SAFETY: all requested bytes belong to live readable regions, the
            // destination is independent, and this owner cannot cross threads.
            // Each copy stays within one mmap allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    start as usize as *const u8,
                    bytes.as_mut_ptr().add(offset),
                    count,
                )
            };
        }
        Ok(bytes)
    }

    /// Validate the entire write first, including crossings of adjacent regions.
    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        self.validate_access(address, bytes.len(), true)?;
        if self.shared.is_some() {
            return self.write_shared(address, bytes);
        }
        for (start, count, offset) in self.access_spans(address, bytes.len()) {
            // SAFETY: the exclusive owner validated every byte as writable;
            // callers cannot obtain references into these allocations safely.
            // Each copy stays within one mmap allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(offset),
                    start as usize as *mut u8,
                    count,
                )
            };
        }
        Ok(())
    }

    // Only called after validate_access has checked the end and permissions.
    fn access_spans(
        &self,
        address: u64,
        length: usize,
    ) -> impl Iterator<Item = (u64, usize, usize)> + '_ {
        let end = address + length as u64;
        self.regions.iter().filter_map(move |region| {
            let start = address.max(region.guest_address);
            let stop = end.min(region.end());
            (start < stop).then(|| (start, (stop - start) as usize, (start - address) as usize))
        })
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn spec(address: u64, size: u64) -> MemoryRegionSpec {
        MemoryRegionSpec {
            guest_address: address,
            virtual_bytes: size,
            initial_bytes: vec![7, 8, 9],
            readable: true,
            writable: true,
            executable: false,
        }
    }

    // The OS chooses a candidate; a racing allocation can only cause a safe
    // failure. No test assumes a hardcoded address is free.
    fn candidate(size: usize) -> u64 {
        // SAFETY: a temporary ordinary anonymous mapping.
        let pointer = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                size,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        let address = pointer as usize as u64;
        // SAFETY: release only the temporary allocation just created.
        assert_eq!(unsafe { libc::munmap(pointer, size) }, 0);
        address
    }

    fn allocate(
        mut make: impl FnMut(u64, u64) -> Vec<MemoryRegionSpec>,
        pages: usize,
    ) -> OwnedMemory {
        let page = host_page_size().unwrap();
        for _ in 0..32 {
            let address = candidate(page * pages);
            if let Ok(memory) = OwnedMemory::map(make(address, page as u64)) {
                return memory;
            }
        }
        panic!("cannot allocate test guest mapping after 32 attempts");
    }

    fn file_spec(address: u64, size: u64, file: File, offset: u64) -> FileMemoryRegionSpec {
        FileMemoryRegionSpec {
            guest_address: address,
            virtual_bytes: size,
            file,
            file_offset: offset,
            readable: true,
            writable: true,
            executable: false,
        }
    }

    fn backing_file(bytes: &[u8], size: u64) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.set_len(size).unwrap();
        file
    }

    fn allocate_files(
        mut make: impl FnMut(u64, u64) -> Vec<FileMemoryRegionSpec>,
        pages: usize,
    ) -> OwnedMemory {
        let page = host_page_size().unwrap();
        for _ in 0..32 {
            let address = candidate(page * pages);
            // SAFETY: callers provide exclusively owned temporary files, and no
            // test modifies or truncates them while the owners live.
            if let Ok(memory) = unsafe { OwnedMemory::map_files(make(address, page as u64)) } {
                return memory;
            }
        }
        panic!("cannot allocate test file mapping after 32 attempts");
    }

    #[test]
    fn page_protection_splits_views_preserves_bytes_and_original_ownership() {
        let page = host_page_size().unwrap();
        let mut memory = allocate(|base, p| vec![spec(base, 4 * p)], 4);
        let base = memory.regions()[0].guest_address;
        let mut expected = vec![0u8; 4 * page];
        expected[..3].copy_from_slice(&[7, 8, 9]);
        for offset in [page - 1, page, 3 * page, 4 * page - 1] {
            memory.write(base + offset as u64, &[42]).unwrap();
            expected[offset] = 42;
        }
        memory
            .protect_data(base + page as u64, 2 * page as u64, true, false)
            .unwrap();
        assert_eq!(memory.regions().len(), 3);
        assert_eq!(memory.allocations.len(), 1);
        assert_eq!(memory.read_snapshot(base, 4 * page).unwrap(), expected);
        assert!(memory.write(base + page as u64, &[1]).is_err());
        assert_eq!(os_protection(base), libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(os_protection(base + page as u64), libc::PROT_READ);
        memory
            .protect_data(base + 2 * page as u64, page as u64, false, false)
            .unwrap();
        assert_eq!(os_protection(base + 2 * page as u64), libc::PROT_NONE);
        assert!(memory.read_snapshot(base, 4 * page).is_err());
        memory
            .protect_data(base, 4 * page as u64, true, true)
            .unwrap();
        assert_eq!(memory.read_snapshot(base, 4 * page).unwrap(), expected);
        for index in 0..4 {
            assert_eq!(
                os_protection(base + (index * page) as u64),
                libc::PROT_READ | libc::PROT_WRITE
            );
        }
        assert_eq!(
            memory
                .regions()
                .iter()
                .map(|r| r.initial_bytes)
                .sum::<usize>(),
            3
        );
        assert_eq!(
            memory.regions().iter().map(|r| r.mapped_bytes).sum::<u64>(),
            4 * page as u64
        );
    }
    #[test]
    fn data_maximum_and_code_guard_reject_before_changing_os_permissions() {
        let page = host_page_size().unwrap();
        let mut memory = allocate(
            |base, p| {
                vec![
                    MemoryRegionSpec {
                        writable: false,
                        ..spec(base, p)
                    },
                    MemoryRegionSpec {
                        guest_address: base + 2 * p,
                        executable: true,
                        writable: false,
                        ..spec(base, p)
                    },
                ]
            },
            3,
        );
        let base = memory.regions()[0].guest_address;
        let old = memory.regions().to_vec();
        for (address, bytes, r, w, error) in [
            (
                base,
                page as u64,
                true,
                true,
                ProtectionError::MaximumProtection,
            ),
            (
                base,
                3 * page as u64,
                true,
                false,
                ProtectionError::UnmappedRange,
            ),
            (
                base + 2 * page as u64,
                page as u64,
                true,
                false,
                ProtectionError::ExecutableRegion,
            ),
            (
                base + 1,
                page as u64,
                true,
                false,
                ProtectionError::InvalidRange,
            ),
            (base, 0, true, false, ProtectionError::InvalidRange),
            (
                base,
                page as u64,
                false,
                true,
                ProtectionError::WriteWithoutRead,
            ),
        ] {
            assert_eq!(memory.protect_data(address, bytes, r, w), Err(error));
            assert_eq!(memory.regions(), old);
        }
        assert_eq!(os_protection(base), libc::PROT_READ);
        let mut explicit = (0..32)
            .find_map(|_| {
                let address = candidate(page);
                OwnedMemory::map_with_data_limits(
                    vec![MemoryRegionSpec {
                        writable: false,
                        ..spec(address, page as u64)
                    }],
                    vec![DataProtectionLimit {
                        guest_address: address,
                        readable: true,
                        writable: true,
                    }],
                )
                .ok()
            })
            .unwrap();
        let address = explicit.regions()[0].guest_address;
        explicit
            .protect_data(address, page as u64, true, true)
            .unwrap();
        explicit.write(address, &[11]).unwrap();
        explicit
            .protect_data(address, page as u64, true, false)
            .unwrap();
        assert_eq!(explicit.read_snapshot(address, 1).unwrap(), [11]);
    }
    #[test]
    fn protection_padding_remains_outside_logical_access_and_file_cow_is_preserved() {
        let page = host_page_size().unwrap();
        let mut source = backing_file(&[4, 5, 6], 3);
        let mut memory = allocate_files(
            |base, _| vec![file_spec(base, 3, source.try_clone().unwrap(), 0)],
            1,
        );
        let base = memory.regions()[0].guest_address;
        memory.protect_data(base, page as u64, true, false).unwrap();
        assert_eq!(memory.regions()[0].virtual_bytes, 3);
        assert!(memory.read_snapshot(base + 3, 1).is_err());
        memory.protect_data(base, page as u64, true, true).unwrap();
        memory.write(base, &[9]).unwrap();
        let mut original = [0; 3];
        source.seek(SeekFrom::Start(0)).unwrap();
        source.read_exact(&mut original).unwrap();
        assert_eq!(original, [4, 5, 6]);
    }
    #[test]
    fn partial_host_failure_restores_views_and_failed_restore_quarantines_safe_access() {
        let page = host_page_size().unwrap();
        let mut memory = allocate(|base, p| vec![spec(base, 2 * p)], 2);
        let base = memory.regions()[0].guest_address;
        let before = memory.regions().to_vec();
        let mut calls = 0;
        let error = memory
            .protect_data_with(
                base,
                2 * page as u64,
                true,
                false,
                |address, bytes, rights| {
                    calls += 1;
                    // SAFETY: this test owns all supplied pages. Simulate a host that
                    // changes only the first page before reporting an error.
                    let status = unsafe {
                        libc::mprotect(
                            address as usize as *mut _,
                            if calls == 1 { page } else { bytes as usize },
                            rights,
                        )
                    };
                    assert_eq!(status, 0);
                    if calls == 1 {
                        Err(Some(libc::ENOMEM))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        assert_eq!(
            error,
            ProtectionError::HostFailure {
                errno: Some(libc::ENOMEM),
                rollback_succeeded: true
            }
        );
        assert!(memory.is_usable());
        assert_eq!(memory.regions(), before);
        assert_eq!(os_protection(base), libc::PROT_READ | libc::PROT_WRITE);
        memory.write(base, &[42]).unwrap();
        let failure = memory.protect_data_with(base, page as u64, false, false, |_, _, _| {
            Err(Some(libc::EACCES))
        });
        assert_eq!(
            failure,
            Err(ProtectionError::HostFailure {
                errno: Some(libc::EACCES),
                rollback_succeeded: false
            })
        );
        assert!(!memory.is_usable());
        assert!(memory.read_snapshot(base, 1).is_err());
        assert!(memory.write(base, &[1]).is_err());
        assert_eq!(
            memory.protect_data(base, page as u64, true, true),
            Err(ProtectionError::AddressSpaceUnusable)
        );
    }

    #[test]
    fn publication_preserves_guest_permissions_and_logical_bounds() {
        let page = host_page_size().unwrap();
        let mut published = (0..32)
            .find_map(|_| PublishedReadOnlyRegion::map(candidate(page), &[7; 13]).ok())
            .unwrap();
        let address = published.region().guest_address;
        let alias = published.storage.publisher_base().unwrap().as_ptr() as usize as u64;
        assert_eq!(os_protection(address), libc::PROT_READ);
        assert_eq!(os_protection(alias), libc::PROT_READ | libc::PROT_WRITE);
        published.publish(4, &[1, 2, 3]).unwrap();
        assert_eq!(
            published.read_snapshot(0, 13).unwrap(),
            [7, 7, 7, 7, 1, 2, 3, 7, 7, 7, 7, 7, 7]
        );
        assert!(published.publish(13, &[1]).is_err());
        assert!(published.read_snapshot(usize::MAX, 2).is_err());
        assert_eq!(os_protection(address), libc::PROT_READ);
        assert_eq!(os_protection(alias), libc::PROT_READ | libc::PROT_WRITE);
        assert!(PublishedReadOnlyRegion::map(address, &[9; 13]).is_err());
        assert_eq!(published.read_snapshot(4, 3).unwrap(), [1, 2, 3]);
        drop(published);
        // A parallel test can take the released address immediately.
        let reused = (0..32)
            .find_map(|_| PublishedReadOnlyRegion::map(candidate(page), &[8; 13]).ok())
            .unwrap();
        assert_eq!(reused.read_snapshot(0, 13).unwrap(), [8; 13]);
    }

    #[test]
    fn file_offset_and_private_writes_preserve_original_file_bytes() {
        let page = host_page_size().unwrap();
        let mut bytes = vec![0xa5; page * 2];
        bytes[page..page + 3].copy_from_slice(&[1, 2, 3]);
        let mut file = backing_file(&bytes, bytes.len() as u64);
        let mut memory = allocate_files(
            |address, page| vec![file_spec(address, page, file.try_clone().unwrap(), page)],
            1,
        );
        let address = memory.regions()[0].guest_address;
        assert_eq!(memory.regions()[0].initial_bytes, page);
        assert_eq!(
            memory.allocations[0].storage.kind(),
            storage::StorageKind::PrivateFile
        );
        assert_eq!(memory.read_snapshot(address, 4).unwrap(), [1, 2, 3, 0xa5]);
        memory.write(address + 1, &[8, 9]).unwrap();
        assert_eq!(memory.read_snapshot(address, 4).unwrap(), [1, 8, 9, 0xa5]);
        file.seek(SeekFrom::Start(page as u64)).unwrap();
        let mut source = [0; 4];
        file.read_exact(&mut source).unwrap();
        assert_eq!(source, [1, 2, 3, 0xa5]);
    }

    #[test]
    fn file_partial_page_eof_keeps_logical_guest_bounds() {
        let page = host_page_size().unwrap();
        let mut bytes = vec![0x6b; page + 3];
        bytes[page..].copy_from_slice(&[4, 5, 6]);
        let file = backing_file(&bytes, bytes.len() as u64);
        let mut memory = allocate_files(
            |address, page| vec![file_spec(address, page + 3, file.try_clone().unwrap(), 0)],
            2,
        );
        let region = &memory.regions()[0];
        let address = region.guest_address;
        assert_eq!(region.mapped_bytes, 2 * page as u64);
        assert_eq!(
            memory.read_snapshot(address + page as u64, 3).unwrap(),
            [4, 5, 6]
        );
        assert!(memory.read_snapshot(address + page as u64 + 3, 1).is_err());
        assert!(memory.write(address + page as u64 + 3, &[1]).is_err());
        memory.write(address + page as u64 + 2, &[42]).unwrap();
        assert_eq!(
            memory.read_snapshot(address + page as u64 + 2, 1).unwrap(),
            [42]
        );
    }

    #[test]
    fn file_guest_code_and_noaccess_regions_never_receive_host_execute() {
        let page = host_page_size().unwrap() as u64;
        let file = backing_file(&[0x1f, 0x20, 0x03, 0xd5], page);
        let mut memory = allocate_files(
            |address, page| {
                let mut code = file_spec(address, page, file.try_clone().unwrap(), 0);
                code.writable = false;
                code.executable = true;
                let mut guard = file_spec(address + page, page, file.try_clone().unwrap(), 0);
                guard.readable = false;
                guard.writable = false;
                vec![code, guard]
            },
            2,
        );
        let address = memory.regions()[0].guest_address;
        assert_eq!(os_protection(address), libc::PROT_READ);
        assert_eq!(os_protection(address + page), libc::PROT_NONE);
        assert_eq!(
            memory.read_snapshot(address, 4).unwrap(),
            [0x1f, 0x20, 0x03, 0xd5]
        );
        assert!(memory.write(address, &[0]).is_err());
        assert!(memory.read_snapshot(address + page, 1).is_err());
        assert!(memory.write(address + page, &[0]).is_err());
        assert!(memory.write(address + page - 1, &[1, 2]).is_err());
        assert_eq!(memory.read_snapshot(address + page - 1, 1).unwrap(), [0]);
    }

    #[test]
    fn file_mapping_budget_is_separate_from_bounded_copy_access() {
        let page = host_page_size().unwrap();
        let bytes = MAX_IMAGE_MEMORY_BYTES + page as u64;
        let file = backing_file(&[], bytes);
        let memory = allocate_files(
            |address, _| vec![file_spec(address, bytes, file.try_clone().unwrap(), 0)],
            bytes as usize / page,
        );
        let address = memory.regions()[0].guest_address;
        assert_eq!(memory.regions()[0].virtual_bytes, bytes);
        assert_eq!(memory.read_snapshot(address + bytes - 1, 1).unwrap(), [0]);
        assert!(
            memory
                .read_snapshot(address, MAX_IMAGE_MEMORY_BYTES as usize + 1)
                .is_err()
        );
        // SAFETY: an empty mapping set has no backing-inode lifetime obligation.
        let empty = unsafe { OwnedMemory::map_files(vec![]) }.unwrap();
        assert!(empty.regions().is_empty() && empty.allocations.is_empty());
    }

    #[test]
    fn invalid_file_extents_offsets_types_and_access_decline_before_mapping() {
        let page = host_page_size().unwrap() as u64;
        let file = backing_file(&[1, 2, 3], page);
        let address = candidate(page as usize);
        for (base, bytes, offset) in [
            (0, page, 0),
            (address + 1, page, 0),
            (address, 0, 0),
            (DIRECT_RAM_USER_END, page, 0),
            (address, page, 1),
            (address, page + 1, 0),
            (address, page, page),
            (address, page, u64::MAX - page + 1),
        ] {
            // SAFETY: this test exclusively owns the unchanged temporary inode.
            assert!(
                unsafe {
                    OwnedMemory::map_files(vec![file_spec(
                        base,
                        bytes,
                        file.try_clone().unwrap(),
                        offset,
                    )])
                }
                .is_err()
            );
        }
        let mut rwx = file_spec(address, page, file.try_clone().unwrap(), 0);
        rwx.executable = true;
        // SAFETY: this test exclusively owns the unchanged temporary inode.
        assert!(unsafe { OwnedMemory::map_files(vec![rwx]) }.is_err());
        let mut write_only_memory = file_spec(address, page, file.try_clone().unwrap(), 0);
        write_only_memory.readable = false;
        // SAFETY: this test exclusively owns the unchanged temporary inode.
        assert!(unsafe { OwnedMemory::map_files(vec![write_only_memory]) }.is_err());
        // SAFETY: the non-regular descriptor is declined before mapping.
        assert!(
            unsafe {
                OwnedMemory::map_files(vec![file_spec(
                    address,
                    page,
                    File::open("/dev/null").unwrap(),
                    0,
                )])
            }
            .is_err()
        );
        let temporary = tempfile::NamedTempFile::new().unwrap();
        temporary.as_file().set_len(page).unwrap();
        let write_only_file = std::fs::OpenOptions::new()
            .write(true)
            .open(temporary.path())
            .unwrap();
        // SAFETY: this test exclusively owns the unchanged temporary inode.
        assert!(
            unsafe { OwnedMemory::map_files(vec![file_spec(address, page, write_only_file, 0)]) }
                .is_err()
        );
        // SAFETY: the cloned descriptors refer to one unchanged temporary inode.
        assert!(
            unsafe {
                OwnedMemory::map_files(vec![
                    file_spec(address, page, file.try_clone().unwrap(), 0),
                    file_spec(address, page, file.try_clone().unwrap(), 0),
                ])
            }
            .is_err()
        );
        let too_large = backing_file(&[], MAX_FILE_MEMORY_BYTES + page);
        // SAFETY: this test exclusively owns the unchanged sparse temporary inode.
        let error = unsafe {
            OwnedMemory::map_files(vec![file_spec(
                page,
                MAX_FILE_MEMORY_BYTES + page,
                too_large,
                0,
            )])
        }
        .unwrap_err();
        assert!(format!("{error:#}").contains("guest mappings exceed memory limit"));
    }

    #[test]
    fn file_collision_preserves_existing_mapping_and_source() {
        let occupied = allocate(|address, page| vec![spec(address, page)], 1);
        let region = &occupied.regions()[0];
        let file = backing_file(&[1, 2, 3], region.virtual_bytes);
        // SAFETY: this test exclusively owns the unchanged temporary inode.
        assert!(
            unsafe {
                OwnedMemory::map_files(vec![file_spec(
                    region.guest_address,
                    region.virtual_bytes,
                    file,
                    0,
                )])
            }
            .is_err()
        );
        assert_eq!(
            occupied.read_snapshot(region.guest_address, 3).unwrap(),
            [7, 8, 9]
        );
    }

    #[test]
    fn partial_file_mapping_failure_rolls_back_owned_ranges() {
        for _ in 0..32 {
            let occupied = allocate(|address, page| vec![spec(address + page, page)], 2);
            let page = occupied.regions()[0].virtual_bytes;
            let address = occupied.regions()[0].guest_address - page;
            let file = backing_file(&[1, 2, 3], page);
            // SAFETY: this test exclusively owns the unchanged temporary inode.
            let error = unsafe {
                OwnedMemory::map_files(vec![
                    file_spec(address, page, file.try_clone().unwrap(), 0),
                    file_spec(address + page, page, file.try_clone().unwrap(), 0),
                ])
            }
            .unwrap_err();
            assert_eq!(
                occupied.read_snapshot(address + page, 3).unwrap(),
                [7, 8, 9]
            );
            if !format!("{error:#}").contains(&format!("{:#x}", address + page)) {
                continue;
            }
            // SAFETY: the temporary inode remains unchanged until restored drops.
            if let Ok(restored) =
                unsafe { OwnedMemory::map_files(vec![file_spec(address, page, file, 0)]) }
            {
                assert_eq!(restored.read_snapshot(address, 3).unwrap(), [1, 2, 3]);
                return;
            }
        }
        panic!("cannot verify file mapping rollback after 32 attempts");
    }

    #[test]
    fn retained_file_descriptor_maps_original_inode_after_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache");
        let mut file = File::create(&path).unwrap();
        file.write_all(&[1, 2, 3]).unwrap();
        file.set_len(host_page_size().unwrap() as u64).unwrap();
        drop(file);
        let source = File::open(&path).unwrap();
        let memory = allocate_files(
            |address, page| vec![file_spec(address, page, source.try_clone().unwrap(), 0)],
            1,
        );
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, [4, 5, 6]).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        assert_eq!(
            memory
                .read_snapshot(memory.regions()[0].guest_address, 3)
                .unwrap(),
            [1, 2, 3]
        );
        assert_eq!(std::fs::read(path).unwrap(), [4, 5, 6]);
        // This shows only descriptor ownership; changes to the file itself still
        // need caller-side guards.
    }

    #[test]
    fn exact_address_zero_tail_and_exclusive_writes() {
        let mut memory = allocate(|address, page| vec![spec(address, page)], 1);
        let address = memory.regions()[0].guest_address;
        assert_eq!(memory.read_snapshot(address, 5).unwrap(), [7, 8, 9, 0, 0]);
        memory.write(address + 2, &[10, 11]).unwrap();
        assert_eq!(memory.read_snapshot(address, 5).unwrap(), [7, 8, 10, 11, 0]);
        assert!(
            memory
                .read_snapshot(address + memory.regions()[0].virtual_bytes - 1, 2)
                .is_err()
        );
        assert!(memory.read_snapshot(u64::MAX, 2).is_err());
    }

    #[test]
    fn collision_preserves_existing_mapping_and_bytes() {
        let memory = allocate(|address, page| vec![spec(address, page)], 1);
        let existing = &memory.regions()[0];
        assert!(
            OwnedMemory::map(vec![spec(existing.guest_address, existing.virtual_bytes)]).is_err()
        );
        assert_eq!(
            memory.read_snapshot(existing.guest_address, 4).unwrap(),
            [7, 8, 9, 0]
        );
    }

    #[test]
    fn partial_mapping_failure_rolls_back_all_owned_ranges() {
        for _ in 0..32 {
            let occupied = allocate(|address, page| vec![spec(address + page, page)], 2);
            let page = occupied.regions()[0].virtual_bytes;
            let address = occupied.regions()[0].guest_address - page;
            let error = OwnedMemory::map(vec![spec(address, page), spec(address + page, page)])
                .unwrap_err();
            assert_eq!(
                occupied.read_snapshot(address + page, 3).unwrap(),
                [7, 8, 9]
            );
            // A parallel allocation can acquire the first free page. Require
            // failure at the occupied second page to prove partial allocation.
            if !format!("{error:#}").contains(&format!("{:#x}", address + page)) {
                continue;
            }
            // Success proves the earlier range was released by rollback. A
            // racing allocation after rollback can only force a safe retry.
            if let Ok(restored) = OwnedMemory::map(vec![spec(address, page)]) {
                assert_eq!(restored.regions()[0].guest_address, address);
                return;
            }
        }
        panic!("cannot verify mapping rollback after 32 attempts");
    }

    #[test]
    fn reject_invalid_or_excessive_mapping_sets_before_allocation() {
        let page = host_page_size().unwrap() as u64;
        let address = candidate(page as usize);
        let mut invalid = vec![
            spec(0, page),
            spec(address + 1, page),
            spec(address, 0),
            spec(DIRECT_RAM_USER_END, page),
            spec(u64::MAX - page + 1, page),
            spec(address, MAX_IMAGE_MEMORY_BYTES + page),
        ];
        let mut oversized = spec(address, page);
        oversized.initial_bytes = vec![0; page as usize + 1];
        invalid.push(oversized);
        let mut rwx = spec(address, page);
        rwx.executable = true;
        invalid.push(rwx);
        let mut write_only = spec(address, page);
        write_only.readable = false;
        invalid.push(write_only);
        for item in invalid {
            assert!(OwnedMemory::map(vec![item]).is_err());
        }
        assert!(OwnedMemory::map(vec![spec(address, page), spec(address, page)]).is_err());
        assert!(
            OwnedMemory::map(vec![
                spec(address, MAX_IMAGE_MEMORY_BYTES),
                spec(address + MAX_IMAGE_MEMORY_BYTES, page)
            ])
            .is_err()
        );
    }

    #[test]
    fn partial_page_tail_is_mapped_but_outside_guest_bounds() {
        let mut memory = allocate(|address, page| vec![spec(address, page + 3)], 2);
        let region = &memory.regions()[0];
        let address = region.guest_address;
        let virtual_bytes = region.virtual_bytes;
        assert_eq!(region.mapped_bytes, 2 * host_page_size().unwrap() as u64);
        assert_eq!(
            memory
                .read_snapshot(address + virtual_bytes - 1, 1)
                .unwrap(),
            [0]
        );
        assert!(memory.read_snapshot(address + virtual_bytes, 1).is_err());
        assert!(memory.write(address + virtual_bytes, &[1]).is_err());
        memory.write(address + virtual_bytes - 1, &[42]).unwrap();
        assert_eq!(
            memory
                .read_snapshot(address + virtual_bytes - 1, 1)
                .unwrap(),
            [42]
        );
        assert!(
            OwnedMemory::map(vec![
                spec(address, virtual_bytes),
                spec(address + host_page_size().unwrap() as u64, 1)
            ])
            .is_err()
        );
    }

    #[test]
    fn adjacent_access_checks_every_region_before_mutating() {
        let mut memory = allocate(
            |address, page| {
                let mut second = spec(address + page, page);
                second.writable = false;
                vec![spec(address, page), second]
            },
            2,
        );
        let first = &memory.regions()[0];
        let boundary = first.guest_address + first.virtual_bytes;
        assert_eq!(memory.read_snapshot(boundary - 1, 4).unwrap(), [0, 7, 8, 9]);
        assert!(memory.write(boundary - 1, &[1, 2]).is_err());
        assert_eq!(memory.read_snapshot(boundary - 1, 4).unwrap(), [0, 7, 8, 9]);
    }

    #[test]
    fn adjacent_writable_regions_copy_across_allocation_boundary() {
        let mut memory = allocate(
            |address, page| vec![spec(address, page), spec(address + page, page)],
            2,
        );
        let boundary = memory.regions()[1].guest_address;
        memory.write(boundary - 2, &[1, 2, 3, 4]).unwrap();
        assert_eq!(memory.read_snapshot(boundary - 2, 4).unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    fn executable_guest_bytes_are_readonly_host_data() {
        let mut memory = allocate(
            |address, page| {
                let mut code = spec(address, page);
                code.writable = false;
                code.executable = true;
                vec![code]
            },
            1,
        );
        let address = memory.regions()[0].guest_address;
        assert_eq!(memory.read_snapshot(address, 3).unwrap(), [7, 8, 9]);
        assert!(memory.write(address, &[0]).is_err());
        assert_eq!(os_protection(address), libc::PROT_READ);
    }

    #[test]
    fn noaccess_guest_region_has_no_host_access() {
        let mut memory = allocate(
            |address, page| {
                let mut region = spec(address, page);
                region.readable = false;
                region.writable = false;
                vec![region]
            },
            1,
        );
        let address = memory.regions()[0].guest_address;
        assert!(memory.read_snapshot(address, 1).is_err());
        assert!(memory.write(address, &[0]).is_err());
        assert_eq!(os_protection(address), libc::PROT_NONE);
    }

    #[cfg(target_os = "linux")]
    fn os_protection(address: u64) -> i32 {
        for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next().unwrap().split_once('-').unwrap();
            if (u64::from_str_radix(start, 16).unwrap()..u64::from_str_radix(end, 16).unwrap())
                .contains(&address)
            {
                let permissions = fields.next().unwrap().as_bytes();
                return if permissions[0] == b'r' {
                    libc::PROT_READ
                } else {
                    0
                } | if permissions[1] == b'w' {
                    libc::PROT_WRITE
                } else {
                    0
                } | if permissions[2] == b'x' {
                    libc::PROT_EXEC
                } else {
                    0
                };
            }
        }
        panic!("test mapping not found in /proc/self/maps");
    }

    #[cfg(target_os = "macos")]
    fn os_protection(mut address: u64) -> i32 {
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn mach_vm_region(
                task: libc::mach_port_t,
                address: *mut u64,
                size: *mut u64,
                flavor: i32,
                info: *mut i32,
                count: *mut u32,
                object: *mut libc::mach_port_t,
            ) -> i32;
            fn mach_port_deallocate(task: u32, name: u32) -> i32;
        }
        // SDK mach/vm_region.h: VM_REGION_BASIC_INFO_64=9, packed-4
        // vm_region_basic_info_64 is nine i32 words; protection is first.
        let mut info = [0i32; 9];
        let mut count = info.len() as u32;
        let mut size = 0u64;
        let mut object = 0;
        // SAFETY: pointers reference correctly sized writable output storage.
        let result = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut address,
                &mut size,
                9,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if object != 0 {
            // SAFETY: release only the object-name right returned by the query.
            unsafe { mach_port_deallocate(mach_task_self_, object) };
        }
        assert_eq!(result, 0);
        assert_eq!(count, 9);
        info[0]
    }
}
