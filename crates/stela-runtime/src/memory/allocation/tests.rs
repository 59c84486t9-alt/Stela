use super::*;

const GUEST_PAGE_BYTES: u64 = 16 * 1024;
const ALLOCATION_HINT: u64 = 1 << 32;
const ALIAS_TAG: u8 = 60;
const ALLOCATION_ATTEMPTS: usize = 32;
const READ_WRITE: DataPermissions = DataPermissions {
    readable: true,
    writable: true,
    executable: false,
};
const ALL_RIGHTS: DataPermissions = DataPermissions {
    executable: true,
    ..READ_WRITE
};

fn request(bytes: u64) -> AllocateDataRequest {
    AllocateDataRequest {
        placement: DataPlacement::Anywhere {
            hint: ALLOCATION_HINT,
        },
        bytes,
        alignment_mask: GUEST_PAGE_BYTES - 1,
        current: READ_WRITE,
        maximum: ALL_RIGHTS,
        alias_tag: ALIAS_TAG,
        inheritance: DataInheritance::Copy,
    }
}

fn empty() -> OwnedMemory {
    OwnedMemory::map(vec![]).unwrap()
}

fn fixed(address: u64, bytes: u64) -> AllocateDataRequest {
    AllocateDataRequest {
        placement: DataPlacement::Fixed(address),
        alignment_mask: 0,
        ..request(bytes)
    }
}

#[test]
fn observed_anywhere_shape_preserves_zero_bytes_rights_tag_and_inheritance() {
    let mut memory = empty();
    let size = 8 * GUEST_PAGE_BYTES;
    let allocation = memory.allocate_data(request(size)).unwrap();
    assert!(allocation.guest_address >= ALLOCATION_HINT);
    assert_eq!(allocation.guest_address & (GUEST_PAGE_BYTES - 1), 0);
    assert_eq!(allocation.virtual_bytes, size);
    assert_eq!(allocation.mapped_bytes, size);
    assert_eq!(allocation.maximum, ALL_RIGHTS);
    assert_eq!(allocation.alias_tag, ALIAS_TAG);
    assert_eq!(allocation.inheritance, DataInheritance::Copy);
    assert_eq!(
        memory.data_allocation_at(allocation.guest_address),
        Some(allocation)
    );
    assert_eq!(
        memory.data_allocation_at(allocation.guest_address + size),
        None
    );
    assert_eq!(
        memory
            .read_snapshot(allocation.guest_address, size as usize)
            .unwrap(),
        vec![0; size as usize]
    );
    assert_eq!(
        host_rights(allocation.guest_address),
        Some(libc::PROT_READ | libc::PROT_WRITE)
    );
    memory.write(allocation.guest_address, &[7, 9]).unwrap();
    memory
        .protect_data(allocation.guest_address, size, true, false)
        .unwrap();
    assert!(memory.write(allocation.guest_address, &[3]).is_err());
    assert_eq!(
        memory.read_snapshot(allocation.guest_address, 2).unwrap(),
        [7, 9]
    );
    assert_eq!(host_rights(allocation.guest_address), Some(libc::PROT_READ));
    assert_eq!(
        memory.data_allocation_at(allocation.guest_address),
        Some(allocation)
    );
    memory
        .protect_data(allocation.guest_address, size, true, true)
        .unwrap();
    assert!(!memory.regions()[0].executable);
}

#[test]
fn unpublished_initialization_applies_final_readonly_rights_on_commit() {
    let mut memory = empty();
    let mut transaction = memory
        .begin_data_allocation(AllocateDataRequest {
            current: DataPermissions {
                writable: false,
                ..READ_WRITE
            },
            ..request(GUEST_PAGE_BYTES)
        })
        .unwrap();
    let address = transaction.allocation().guest_address;
    transaction.write(3, &[0x21, 0x43]).unwrap();
    transaction.write(GUEST_PAGE_BYTES as usize, &[]).unwrap();
    assert_eq!(
        transaction.read_snapshot(0, 7).unwrap(),
        [0, 0, 0, 0x21, 0x43, 0, 0]
    );
    assert!(transaction.write(GUEST_PAGE_BYTES as usize, &[1]).is_err());
    assert!(transaction.read_snapshot(usize::MAX, 2).is_err());
    let allocation = transaction.publish().unwrap();
    assert_eq!(allocation.guest_address, address);
    assert_eq!(memory.regions()[0].initial_bytes, 5);
    assert_eq!(host_rights(address), Some(libc::PROT_READ));
    assert_eq!(memory.read_snapshot(address + 3, 2).unwrap(), [0x21, 0x43]);
    assert!(memory.write(address, &[1]).is_err());
}

#[test]
fn dropping_unpublished_mapping_and_owner_releases_exact_native_extent() {
    for _ in 0..ALLOCATION_ATTEMPTS {
        let mut memory = empty();
        let transaction = memory
            .begin_data_allocation(request(GUEST_PAGE_BYTES))
            .unwrap();
        let allocation = *transaction.allocation();
        drop(transaction);
        assert!(memory.regions().is_empty() && memory.allocations.is_empty());
        let Ok(reused) =
            memory.allocate_data(fixed(allocation.guest_address, allocation.virtual_bytes))
        else {
            continue;
        };
        assert_eq!(reused.guest_address, allocation.guest_address);
        drop(memory);
        let mut next_owner = empty();
        if next_owner
            .allocate_data(fixed(allocation.guest_address, allocation.virtual_bytes))
            .is_ok()
        {
            return;
        }
    }
    panic!("cannot prove release without a racing host allocation");
}

#[test]
fn fixed_collision_preserves_existing_source_and_all_metadata() {
    let mut memory = empty();
    let allocation = memory.allocate_data(request(GUEST_PAGE_BYTES)).unwrap();
    memory
        .write(allocation.guest_address, &[0x5a, 0xa5])
        .unwrap();
    let before = memory.regions().to_vec();
    assert_eq!(
        memory.allocate_data(fixed(allocation.guest_address, GUEST_PAGE_BYTES)),
        Err(AllocateDataError::AddressUnavailable)
    );
    assert_eq!(memory.regions(), before);
    assert_eq!(
        memory.read_snapshot(allocation.guest_address, 2).unwrap(),
        [0x5a, 0xa5]
    );
    assert_eq!(memory.allocations.len(), 1);
}

#[test]
fn allocation_cannot_replace_or_unseal_an_immutable_code_source() {
    for _ in 0..ALLOCATION_ATTEMPTS {
        let mut reservation = empty();
        let reserved = reservation
            .allocate_data(request(GUEST_PAGE_BYTES))
            .unwrap();
        drop(reservation);
        let Ok(mut memory) = OwnedMemory::map(vec![super::super::MemoryRegionSpec {
            guest_address: reserved.guest_address,
            virtual_bytes: GUEST_PAGE_BYTES,
            initial_bytes: vec![0x1f, 0x20, 0x03, 0xd5],
            readable: true,
            writable: false,
            executable: true,
        }]) else {
            continue;
        };
        let before = memory.regions().to_vec();
        assert_eq!(
            memory.allocate_data(fixed(reserved.guest_address, GUEST_PAGE_BYTES)),
            Err(AllocateDataError::AddressUnavailable)
        );
        assert_eq!(memory.regions(), before);
        assert_eq!(
            memory.read_snapshot(reserved.guest_address, 4).unwrap(),
            [0x1f, 0x20, 0x03, 0xd5]
        );
        assert_eq!(
            memory.protect_data(reserved.guest_address, GUEST_PAGE_BYTES, true, true),
            Err(super::super::ProtectionError::ExecutableRegion)
        );
        let maximum = memory
            .data_allocation_at(reserved.guest_address)
            .unwrap()
            .maximum;
        assert!(maximum.executable && maximum.readable && !maximum.writable);
        assert_eq!(host_rights(reserved.guest_address), Some(libc::PROT_READ));
        return;
    }
    panic!("cannot reserve a temporary code-source address without a race");
}

#[test]
fn failed_final_protection_rolls_back_new_mapping_without_changing_old_memory() {
    for _ in 0..ALLOCATION_ATTEMPTS {
        let mut memory = empty();
        let old = memory.allocate_data(request(GUEST_PAGE_BYTES)).unwrap();
        memory.write(old.guest_address, &[0x39]).unwrap();
        let before = memory.regions().to_vec();
        let transaction = memory
            .begin_data_allocation(request(2 * GUEST_PAGE_BYTES))
            .unwrap();
        let failed = *transaction.allocation();
        let page = memory_page();
        let error = transaction.publish_with(|base, _, _| {
            // SAFETY: change one owned page, then simulate a partial host failure.
            assert_eq!(
                unsafe {
                    libc::mprotect(
                        base as usize as *mut libc::c_void,
                        page as usize,
                        libc::PROT_READ,
                    )
                },
                0
            );
            Err(Some(libc::ENOMEM))
        });
        assert_eq!(
            error,
            Err(AllocateDataError::HostFailure {
                operation: AllocationOperation::Protect,
                errno: Some(libc::ENOMEM)
            })
        );
        assert_eq!(memory.regions(), before);
        assert!(memory.is_usable());
        assert_eq!(memory.read_snapshot(old.guest_address, 1).unwrap(), [0x39]);
        if memory
            .allocate_data(fixed(failed.guest_address, failed.virtual_bytes))
            .is_ok()
        {
            return;
        }
    }
    panic!("cannot prove protection-failure rollback without a racing allocation");
}

fn memory_page() -> u64 {
    super::super::host_page_size().unwrap() as u64
}

#[test]
fn invalid_ranges_masks_and_unsupported_rights_decline_before_mapping() {
    let mut memory = empty();
    let page = memory_page();
    let cases = [
        (request(0), AllocateDataError::InvalidRange),
        (request(u64::MAX), AllocateDataError::InvalidRange),
        (
            request(MAX_FILE_MEMORY_BYTES + page),
            AllocateDataError::ResourceLimit,
        ),
        (
            AllocateDataRequest {
                alignment_mask: 5,
                ..request(page)
            },
            AllocateDataError::UnsupportedAlignmentMask,
        ),
        (
            AllocateDataRequest {
                alignment_mask: u64::MAX,
                ..request(page)
            },
            AllocateDataError::UnsupportedAlignmentMask,
        ),
        (
            AllocateDataRequest {
                current: ALL_RIGHTS,
                ..request(page)
            },
            AllocateDataError::UnsupportedExecutable,
        ),
        (
            AllocateDataRequest {
                current: DataPermissions {
                    readable: false,
                    ..READ_WRITE
                },
                ..request(page)
            },
            AllocateDataError::UnsupportedWriteOnly,
        ),
        (
            AllocateDataRequest {
                maximum: DataPermissions {
                    writable: false,
                    ..ALL_RIGHTS
                },
                ..request(page)
            },
            AllocateDataError::MaximumProtection,
        ),
        (fixed(page + 1, page), AllocateDataError::InvalidAlignment),
        (fixed(0, page), AllocateDataError::AddressUnavailable),
        (
            AllocateDataRequest {
                placement: DataPlacement::Fixed(page),
                alignment_mask: 2 * page - 1,
                ..request(page)
            },
            AllocateDataError::AddressUnavailable,
        ),
        (
            AllocateDataRequest {
                placement: DataPlacement::Anywhere {
                    hint: DIRECT_RAM_USER_END,
                },
                ..request(page)
            },
            AllocateDataError::AddressUnavailable,
        ),
    ];
    for (request, expected) in cases {
        assert_eq!(memory.allocate_data(request), Err(expected));
        assert!(memory.regions().is_empty() && memory.allocations.is_empty());
    }
}

#[test]
fn exact_logical_extent_excludes_padding_and_sorted_ownership_survives_new_views() {
    let mut memory = empty();
    let allocation = memory.allocate_data(request(3)).unwrap();
    assert_eq!(allocation.virtual_bytes, 3);
    assert_eq!(allocation.mapped_bytes, memory_page());
    assert_eq!(
        memory.data_allocation_at(allocation.guest_address + 3),
        None
    );
    assert!(
        memory
            .read_snapshot(allocation.guest_address + 3, 1)
            .is_err()
    );
    let next = memory.allocate_data(request(GUEST_PAGE_BYTES)).unwrap();
    assert!(
        memory
            .allocations
            .windows(2)
            .all(|pair| pair[0].base < pair[1].base)
    );
    assert!(
        memory
            .regions()
            .windows(2)
            .all(|pair| pair[0].guest_address < pair[1].guest_address)
    );
    memory
        .protect_data(next.guest_address, GUEST_PAGE_BYTES, false, false)
        .unwrap();
    assert_eq!(host_rights(next.guest_address), Some(libc::PROT_NONE));
    assert!(memory.read_snapshot(next.guest_address, 1).is_err());
    assert_eq!(
        memory.read_snapshot(allocation.guest_address, 3).unwrap(),
        [0, 0, 0]
    );
}

#[test]
fn maximum_rights_are_exact_and_cannot_be_raised_by_later_protection() {
    let mut memory = empty();
    let readonly = DataPermissions {
        writable: false,
        executable: false,
        ..READ_WRITE
    };
    let allocation = memory
        .allocate_data(AllocateDataRequest {
            current: readonly,
            maximum: readonly,
            ..request(GUEST_PAGE_BYTES)
        })
        .unwrap();
    assert_eq!(
        memory.protect_data(allocation.guest_address, GUEST_PAGE_BYTES, true, true),
        Err(super::super::ProtectionError::MaximumProtection)
    );
    assert_eq!(host_rights(allocation.guest_address), Some(libc::PROT_READ));
    assert_eq!(
        memory
            .data_allocation_at(allocation.guest_address)
            .unwrap()
            .maximum,
        readonly
    );
}

#[cfg(target_os = "linux")]
fn host_rights(address: u64) -> Option<i32> {
    for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
        let mut fields = line.split_whitespace();
        let (begin, end) = fields.next().unwrap().split_once('-').unwrap();
        if !(u64::from_str_radix(begin, 16).unwrap()..u64::from_str_radix(end, 16).unwrap())
            .contains(&address)
        {
            continue;
        }
        let permissions = fields.next().unwrap().as_bytes();
        return Some(
            (if permissions[0] == b'r' {
                libc::PROT_READ
            } else {
                0
            }) | (if permissions[1] == b'w' {
                libc::PROT_WRITE
            } else {
                0
            }) | (if permissions[2] == b'x' {
                libc::PROT_EXEC
            } else {
                0
            }),
        );
    }
    None
}

#[cfg(target_os = "macos")]
fn host_rights(address: u64) -> Option<i32> {
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
    if status == 0 && found <= address && address - found < size {
        Some(info[0])
    } else {
        None
    }
}
