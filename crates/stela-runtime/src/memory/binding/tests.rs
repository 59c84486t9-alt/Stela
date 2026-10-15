use super::*;
use crate::memory::{
    AllocateDataError, AllocateDataRequest, DataInheritance, DataPermissions, DataPlacement,
    MemoryRegionSpec, ProtectionError, backing::AccessKind, host_page_size,
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
    unsafe { crate::memory::access::read_part(ptr.as_ptr(), bytes, TargetCpu::Baseline) }.unwrap()
}

#[test]
fn bind_retains_actual_storage_after_facade_drop() {
    let (mut memory, base) = owned();
    memory.write(base, &[42]).unwrap();
    let domain =
        unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 9), &mut []) }
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
    // SAFETY: exact checked read, private disjoint staging, and only the retained
    // domain owns the actual native mapping after both facade/backing drops.
    let status = unsafe { entry.with_view(|view| (view.callback)(view, &request)) };
    assert_eq!(status, MemoryStatus::Success as u32);
    assert_eq!(staging, [42]);
    assert!(domain.check_execution().is_ok());
}

#[test]
fn bound_exact_write_preserves_neighbors_and_private_api_declines() {
    let (mut memory, base) = owned();
    memory.write(base, &[0xa5; 32]).unwrap();
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
    assert!(memory.read_snapshot(base, 1).is_err());
    assert_eq!(
        memory.protect_data(base, host_page_size().unwrap() as u64, true, false),
        Err(ProtectionError::SharedDomainBound)
    );
    let rights = DataPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    assert_eq!(
        memory.allocate_data(AllocateDataRequest {
            placement: DataPlacement::Anywhere { hint: 0 },
            bytes: 1,
            alignment_mask: 0,
            current: rights,
            maximum: rights,
            alias_tag: 0,
            inheritance: DataInheritance::Copy
        }),
        Err(AllocateDataError::SharedDomainBound)
    );
    assert_eq!(
        unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 2), &mut []) }
            .err()
            .unwrap(),
        SharedBindingError::AlreadyBound
    );
}

#[test]
fn guest_ro_publisher_uses_same_group_and_retains_both_aliases() {
    let (mut memory, _) = owned();
    let mut owner = published();
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
    assert!(owner.read_snapshot(0, 1).is_err());
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
    // Initial one-page shape cannot split, so explicitly represent a split view
    // as a private metadata fault fixture without touching host protections.
    let original = memory.regions[0].clone();
    let mut second = original.clone();
    second.guest_address += 16;
    second.virtual_bytes -= 16;
    memory.regions[0].virtual_bytes = 16;
    memory.regions.push(second);
    assert_eq!(
        unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 5), &mut []) }
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
    let mut mapped = unsafe {
        OwnedMemory::map_files(vec![crate::memory::FileMemoryRegionSpec {
            guest_address: free_address(page),
            virtual_bytes: page as u64,
            file,
            file_offset: 0,
            readable: true,
            writable: true,
            executable: false,
        }])
    }
    .unwrap();
    assert_eq!(
        unsafe { mapped.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 5), &mut []) }
            .err()
            .unwrap(),
        SharedBindingError::FileCopyOnWrite
    );
    assert!(mapped.shared.is_none());
}

#[test]
fn current_ro_host_rights_are_not_promoted_from_logical_maximum() {
    let (mut memory, base) = owned();
    memory
        .protect_data(base, host_page_size().unwrap() as u64, true, false)
        .unwrap();
    unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 6), &mut []) }
        .unwrap();
    assert!(memory.allocations[0].maximum_writable);
    let backing = Arc::clone(memory.allocations[0].shared_backing.as_ref().unwrap());
    assert!(!backing.maximum_permissions().writable);
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
    unsafe { memory.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 7), &mut []) }
        .unwrap();
    // Inject an unexpected second-span coherence mismatch into private metadata.
    // Both pages remain live/valid; first span really executes native publication.
    let original_second = Arc::clone(memory.allocations[1].shared_backing.as_ref().unwrap());
    let (mut rival, _) = owned();
    let other =
        unsafe { rival.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 8), &mut []) }
            .unwrap();
    // This distinct physical allocation has exactly its own canonical backing.
    // Deliberately corrupt only the destination slot to exercise rejection.
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
fn checked_entry_declines_unavailable_source_capabilities_before_effects() {
    use stela_compiler::context::memory::{MemoryRequirements, host_caps, profile_requirements};
    let (mut memory, base) = owned();
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
