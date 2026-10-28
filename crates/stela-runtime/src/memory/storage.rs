//! Lifetime of native mappings, independent of guest views.

#[cfg(host_memory)]
use alloc::sync::Arc;
use core::ptr::NonNull;
#[cfg(host_memory)]
use std::fs::File;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StorageKind {
    #[cfg(host_memory)]
    Anonymous,
    #[cfg(host_memory)]
    PrivateFile,
    PublishedAliases,
}

/// One complete native mapping with one exclusive unmap obligation.
#[derive(Debug)]
pub(super) struct NativeMapping {
    base: NonNull<u8>,
    bytes: usize,
}

impl NativeMapping {
    /// Take over the unmap obligation of an existing native mapping.
    ///
    /// # Safety
    /// `base..base+bytes` must be a non-empty, whole, page-aligned live mapping
    /// whose unmap obligation the caller owns. The storage is coherent
    /// write-back RAM, never device memory or MMIO. No Rust reference to its
    /// bytes may escape. Raw accesses and protection changes need external
    /// synchronization, and every access must finish before rights are revoked,
    /// pages are remapped or the last owner is released. File mappings
    /// additionally require stable files. Adoption changes no rights.
    #[cfg(host_memory)]
    pub(super) unsafe fn adopt(base: NonNull<u8>, bytes: usize) -> Self {
        Self { base, bytes }
    }
}

// SAFETY: this owner only retains an immutable raw mapping descriptor and its
// unmap obligation. It provides no safe byte access/protection/remap operation;
// adoption requires stable storage and externally synchronized raw accesses.
unsafe impl Send for NativeMapping {}
// SAFETY: sharing the descriptor hands out no references or mutation rights;
// the mapping lives until the last owner drops.
unsafe impl Sync for NativeMapping {}

#[cfg(host_memory)]
impl Drop for NativeMapping {
    fn drop(&mut self) {
        // SAFETY: adoption transferred the unmap obligation for this exact
        // extent.
        unsafe { libc::munmap(self.base.as_ptr().cast(), self.bytes) };
    }
}

#[cfg(host_memory)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StorageError {
    AliasExtentMismatch,
    AliasesOverlap,
}

#[cfg(host_memory)]
impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "retained native storage failed: {self:?}")
    }
}
#[cfg(host_memory)]
impl core::error::Error for StorageError {}

/// One physical storage lifetime, optionally with its two native aliases. A
/// `MemoryBacking` holds this owner; this owner must never hold the backing,
/// which would form a reference cycle.
pub(super) struct NativeStorage {
    primary: NativeMapping,
    publisher: Option<NativeMapping>,
    #[cfg(host_memory)]
    _file: Option<File>,
    kind: StorageKind,
}

impl core::fmt::Debug for NativeStorage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeStorage")
            .field("primary", &self.primary_base())
            .field("publisher", &self.publisher_base())
            .field("bytes", &self.bytes())
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl NativeStorage {
    #[cfg(host_memory)]
    pub(super) fn anonymous(primary: NativeMapping) -> Arc<Self> {
        Arc::new(Self {
            primary,
            publisher: None,
            #[cfg(host_memory)]
            _file: None,
            kind: StorageKind::Anonymous,
        })
    }

    #[cfg(host_memory)]
    pub(super) fn private_file(primary: NativeMapping, file: File) -> Arc<Self> {
        Arc::new(Self {
            primary,
            publisher: None,
            _file: Some(file),
            kind: StorageKind::PrivateFile,
        })
    }

    /// Retain equal-sized guest/publisher aliases of the same private backing.
    ///
    /// # Safety
    /// If the checked lengths match and native ranges do not overlap, both
    /// mappings must alias the same complete physical byte extent of `file`,
    /// at the same offset. The file is private: no external writable
    /// descriptor or mapping can modify/truncate it. Address/length checks alone
    /// cannot establish physical alias identity. The guest alias stays read-only;
    /// publisher mutation obeys the enclosing serialized writer contract.
    #[cfg(host_memory)]
    pub(super) unsafe fn published_aliases(
        primary: NativeMapping,
        publisher: NativeMapping,
        file: File,
    ) -> Result<Arc<Self>, StorageError> {
        if primary.bytes != publisher.bytes {
            return Err(StorageError::AliasExtentMismatch);
        }
        let primary_start = primary.base.as_ptr() as usize;
        let publisher_start = publisher.base.as_ptr() as usize;
        // Adoption guarantees checked native range arithmetic.
        if primary_start < publisher_start + publisher.bytes
            && publisher_start < primary_start + primary.bytes
        {
            return Err(StorageError::AliasesOverlap);
        }
        Ok(Arc::new(Self {
            primary,
            publisher: Some(publisher),
            _file: Some(file),
            kind: StorageKind::PublishedAliases,
        }))
    }

    pub(super) fn primary_base(&self) -> NonNull<u8> {
        self.primary.base
    }

    pub(super) fn publisher_base(&self) -> Option<NonNull<u8>> {
        self.publisher.as_ref().map(|mapping| mapping.base)
    }

    pub(super) fn bytes(&self) -> usize {
        self.primary.bytes
    }

    pub(super) fn kind(&self) -> StorageKind {
        self.kind
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::super::{
        AllocateDataRequest, DataInheritance, DataPermissions, DataPlacement, OwnedMemory,
        PublishedReadOnlyRegion, host_page_size,
    };
    use super::*;
    use crate::memory::backing::{AccessKind, AccessPermissions, MemoryBacking, MemoryView};

    fn anonymous(bytes: usize) -> NativeMapping {
        // SAFETY: fresh private native allocation, without replacement or references.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        // SAFETY: a newly owned page extent of coherent write-back RAM.
        unsafe { NativeMapping::adopt(NonNull::new(pointer.cast()).unwrap(), bytes) }
    }

    #[cfg(target_os = "linux")]
    fn mapped(base: NonNull<u8>) -> bool {
        let mut resident = 0;
        // SAFETY: mincore only queries one page and writes to the private byte.
        let result = unsafe {
            libc::mincore(
                base.as_ptr().cast(),
                host_page_size().unwrap(),
                &mut resident,
            )
        };
        if result == 0 {
            true
        } else {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOMEM)
            );
            false
        }
    }

    #[cfg(target_os = "macos")]
    fn mapped(base: NonNull<u8>) -> bool {
        let address = base.as_ptr() as usize as u64;
        const VM_REGION_BASIC_INFO_64: i32 = 9;
        const VM_REGION_BASIC_INFO_WORDS: usize = 9;
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
        let mut found = address;
        let mut size = 0;
        let mut info = [0i32; VM_REGION_BASIC_INFO_WORDS];
        let mut count = info.len() as u32;
        let mut object = 0;
        // SAFETY: all outputs are correctly sized writable native query storage.
        let status = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut found,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if object != 0 {
            // SAFETY: release only the object-name right returned by this query.
            unsafe {
                mach_port_deallocate(mach_task_self_, object);
            }
        }
        status == 0 && found <= address && address - found < size
    }

    fn published() -> PublishedReadOnlyRegion {
        let page = host_page_size().unwrap();
        for _ in 0..32 {
            let candidate = anonymous(page);
            let address = candidate.base.as_ptr() as usize as u64;
            drop(candidate);
            if let Ok(region) = PublishedReadOnlyRegion::map(address, &[7; 13]) {
                return region;
            }
        }
        panic!("cannot allocate read-only alias fixture");
    }

    fn permissions() -> AccessPermissions {
        AccessPermissions {
            readable: true,
            writable: true,
            executable: false,
        }
    }

    #[test]
    fn native_mapping_releases_only_after_final_retained_owner() {
        let storage = NativeStorage::anonymous(anonymous(host_page_size().unwrap()));
        let base = storage.primary_base();
        let retained = Arc::clone(&storage);
        assert_eq!(storage.kind(), StorageKind::Anonymous);
        assert_eq!(storage.publisher_base(), None);
        drop(storage);
        assert!(mapped(base));
        // SAFETY: retained private RW raw storage; no guest execution or references.
        unsafe { base.as_ptr().write(0x5a) };
        assert_eq!(unsafe { retained.primary_base().as_ptr().read() }, 0x5a);
        drop(retained);
    }

    #[test]
    fn backing_keeps_dynamic_allocation_live_after_logical_owner_drop() {
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
        memory.write(allocation.guest_address, &[0x31]).unwrap();
        let storage = Arc::clone(&memory.allocations[0].storage);
        let base = storage.primary_base();
        // SAFETY: retained raw RW Normal-WB storage with private serialized access;
        // no rights changes or external accesses occur while backing exists.
        let backing =
            unsafe { MemoryBacking::new(base, storage.bytes(), permissions(), storage) }.unwrap();
        drop(memory);
        assert!(mapped(base));
        let pointer = backing.host_pointer(0, 1, AccessKind::Read).unwrap();
        assert_eq!(unsafe { pointer.as_ptr().read() }, 0x31);
        drop(backing);
    }

    #[test]
    fn canonical_backing_retains_both_publication_aliases_and_file() {
        let region = published();
        let storage = Arc::clone(&region.storage);
        let guest = storage.primary_base();
        let publisher = storage.publisher_base().unwrap();
        let retained_storage = Arc::downgrade(&storage);
        let descriptor = std::os::fd::AsRawFd::as_raw_fd(storage._file.as_ref().unwrap());
        assert_eq!(storage.kind(), StorageKind::PublishedAliases);
        // SAFETY: both private-file aliases are held together, host rights come
        // from the writable publisher, and the test performs no other byte or
        // rights operations.
        let backing =
            unsafe { MemoryBacking::new(publisher, storage.bytes(), permissions(), storage) }
                .unwrap();
        let readonly = AccessPermissions {
            writable: false,
            ..permissions()
        };
        let first = MemoryView::new(
            Arc::clone(&backing),
            guest.as_ptr() as usize as u64,
            0,
            13,
            readonly,
        )
        .unwrap();
        let alias = MemoryView::new(
            Arc::clone(&backing),
            publisher.as_ptr() as usize as u64,
            0,
            13,
            readonly,
        )
        .unwrap();
        assert!(Arc::ptr_eq(first.backing(), alias.backing()));
        drop(region);
        assert!(retained_storage.upgrade().is_some());
        assert!(mapped(guest) && mapped(publisher));
        assert_ne!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }, -1);
        let pointer = backing.host_pointer(0, 1, AccessKind::Write).unwrap();
        unsafe { pointer.as_ptr().write(0x42) };
        assert_eq!(unsafe { guest.as_ptr().read() }, 0x42);
        drop(first);
        drop(alias);
        assert!(retained_storage.upgrade().is_some());
        drop(backing);
        assert!(retained_storage.upgrade().is_none());
    }

    #[test]
    fn rejected_alias_extent_is_refused() {
        let page = host_page_size().unwrap();
        let primary = anonymous(page);
        let publisher = anonymous(2 * page);
        // SAFETY: this intentionally mismatched pair is rejected before admission;
        // both arguments still own independent complete private RAM mappings.
        let result = unsafe {
            NativeStorage::published_aliases(primary, publisher, tempfile::tempfile().unwrap())
        };
        assert_eq!(result.unwrap_err(), StorageError::AliasExtentMismatch);
    }

    #[test]
    fn unpublished_transaction_drop_releases_retained_storage() {
        let mut memory = OwnedMemory::map(Vec::new()).unwrap();
        let rights = DataPermissions {
            readable: true,
            writable: true,
            executable: false,
        };
        let mut pending = memory
            .begin_data_allocation(AllocateDataRequest {
                placement: DataPlacement::Anywhere { hint: 0 },
                bytes: host_page_size().unwrap() as u64,
                alignment_mask: 0,
                current: rights,
                maximum: rights,
                alias_tag: 0,
                inheritance: DataInheritance::Copy,
            })
            .unwrap();
        let base = NonNull::new(pending.allocation().guest_address as usize as *mut u8).unwrap();
        pending.write(0, &[1, 2]).unwrap();
        assert!(mapped(base));
        drop(pending);
        assert!(memory.allocations.is_empty() && memory.regions().is_empty());
    }
}
