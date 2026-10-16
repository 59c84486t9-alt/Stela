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
    // SAFETY: this complete page extent is newly owned coherent Normal-WB RAM.
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
    assert!(!mapped(base));
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
    assert!(!mapped(base));
}

#[test]
fn canonical_backing_retains_both_publication_aliases_and_file() {
    let region = published();
    let storage = Arc::clone(&region.storage);
    let guest = storage.primary_base();
    let publisher = storage.publisher_base().unwrap();
    let bytes = storage.bytes();
    let primary_retirement = Arc::clone(&storage.primary.retirement);
    let publisher_retirement = Arc::clone(&storage.publisher.as_ref().unwrap().retirement);
    let retained_storage = Arc::downgrade(&storage);
    let descriptor = std::os::fd::AsRawFd::as_raw_fd(storage._file.as_ref().unwrap());
    assert_eq!(storage.kind(), StorageKind::PublishedAliases);
    // SAFETY: same private-file aliases retained together; host authority uses
    // the RW publisher, and this test excludes all other byte/rights operations.
    let backing =
        unsafe { MemoryBacking::new(publisher, storage.bytes(), permissions(), storage) }.unwrap();
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
    assert!(primary_retirement.get().is_none() && publisher_retirement.get().is_none());
    assert!(mapped(guest) && mapped(publisher));
    assert_ne!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }, -1);
    let pointer = backing.host_pointer(0, 1, AccessKind::Write).unwrap();
    unsafe { pointer.as_ptr().write(0x42) };
    assert_eq!(unsafe { guest.as_ptr().read() }, 0x42);
    drop(first);
    drop(alias);
    assert!(retained_storage.upgrade().is_some());
    assert!(primary_retirement.get().is_none() && publisher_retirement.get().is_none());
    drop(backing);
    assert!(retained_storage.upgrade().is_none());
    // Another parallel test may immediately reuse either released address.
    // Observe THIS owner's actual successful unmaps and their exact extents,
    // rather than make a process-global post-release occupancy assertion.
    assert_eq!(
        primary_retirement.get(),
        Some(&MappingRetirement {
            base: guest.as_ptr() as usize,
            bytes,
            status: 0,
            os_error: None,
        })
    );
    assert_eq!(
        publisher_retirement.get(),
        Some(&MappingRetirement {
            base: publisher.as_ptr() as usize,
            bytes,
            status: 0,
            os_error: None,
        })
    );
}

#[test]
fn rejected_alias_extent_rolls_back_both_owned_mappings() {
    let page = host_page_size().unwrap();
    let primary = anonymous(page);
    let publisher = anonymous(2 * page);
    let first = primary.base;
    let second = publisher.base;
    // SAFETY: this intentionally mismatched pair is rejected before admission;
    // both arguments still own independent complete private RAM mappings.
    let result = unsafe {
        NativeStorage::published_aliases(primary, publisher, tempfile::tempfile().unwrap())
    };
    assert_eq!(result.unwrap_err(), StorageError::AliasExtentMismatch);
    assert!(!mapped(first) && !mapped(second));
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
    assert!(!mapped(base));
    assert!(memory.allocations.is_empty() && memory.regions().is_empty());
}
