use super::*;
use crate::memory::binding::tests::{config, owned, published};
use crate::memory::{
    AllocateDataError, AllocateDataRequest, DataInheritance, DataPermissions, DataPlacement,
    host_page_size,
};

fn request(bytes: u64) -> AllocateDataRequest {
    let rights = DataPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    AllocateDataRequest {
        placement: DataPlacement::Anywhere { hint: 0 },
        bytes,
        alignment_mask: 0,
        current: rights,
        maximum: rights,
        alias_tag: 0,
        inheritance: DataInheritance::Copy,
    }
}

fn controls() -> crate::memory::policy::MemoryControls {
    use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
    MemoryControls::new(
        LowerAddressProfile::new(47, false).unwrap(),
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    )
}

#[test]
fn actual_service_guard_spans_allocation_copyout_and_data_protection() {
    let page = host_page_size().unwrap() as u64;
    let (mut owner, pointer) = owned();
    let (mut facade, other) = owned();
    // SAFETY: owned write-back storage with every writer.
    let domain = unsafe {
        owner.bind_shared_memory_group(
            config(MemorySystem::new(16, 8).unwrap(), 77),
            &mut [&mut facade],
            &mut [],
        )
    }
    .unwrap();
    let other_view = domain
        .registered_views()
        .into_iter()
        .find(|view| view.view.guest_base() == other)
        .unwrap()
        .view;
    let mut thread = domain.thread(controls());
    let address;
    {
        let mut service = owner.service_memory(&mut thread).unwrap();
        assert!(domain.execution_loan().is_err());
        {
            let unpublished = service.begin_data_allocation(request(page)).unwrap();
            assert!(domain.execution_loan().is_err());
            drop(unpublished);
        }
        assert_eq!(domain.generation().unwrap(), 0);
        assert!(domain.execution_loan().is_err());
        let mut pending = service.begin_data_allocation(request(page)).unwrap();
        address = pending.allocation().guest_address;
        pending.write(0, &[1, 2, 3]).unwrap();
        assert!(domain.execution_loan().is_err());
        let allocation = pending.publish().unwrap();
        assert_eq!(service.data_allocation_at(address), Some(allocation));
        assert_eq!(domain.generation().unwrap(), 1);
        service.write(pointer, &address.to_le_bytes()).unwrap();
        assert_eq!(service.read_snapshot(address, 3).unwrap(), [1, 2, 3]);
        service.protect_data(address, page, true, false).unwrap();
        assert_eq!(domain.generation().unwrap(), 2);
        assert!(service.write(address, &[9]).is_err());
        assert_eq!(service.read_snapshot(address, 3).unwrap(), [1, 2, 3]);
        assert!(service.regions().iter().any(|region| {
            region.guest_address == address && region.readable && !region.writable
        }));
        assert!(domain.execution_loan().is_err());
        assert!(other_view.is_current());
        assert!(facade.write(other, &[9]).is_err());
    }
    assert!(domain.execution_loan().is_ok());
    assert_eq!(
        owner.read_snapshot(pointer, 8).unwrap(),
        address.to_le_bytes()
    );
    assert_eq!(facade.read_snapshot(other, 1).unwrap(), [0]);
}

#[test]
fn supplied_guard_never_falls_back_to_private_or_other_domain_mapping() {
    let page = host_page_size().unwrap() as u64;
    let (mut owner, base) = owned();
    let (mut other, _) = owned();
    // SAFETY: new software domains with independent storage.
    let domain =
        unsafe { owner.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 78), &mut []) }
            .unwrap();
    // SAFETY: independent storage, with the same ASID.
    let other_domain =
        unsafe { other.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 78), &mut []) }
            .unwrap();
    let wrong = other_domain.service_loan().unwrap();
    let (mut private, private_base) = owned();
    for (memory, address) in [(&mut owner, base), (&mut private, private_base)] {
        assert!(matches!(
            memory.begin_data_allocation_in_service(request(page), &wrong),
            Err(AllocateDataError::SharedDomainBound)
        ));
        let mut host_calls = 0;
        assert_eq!(
            memory.protect_data_with_service(
                ProtectionChange {
                    address,
                    bytes: page,
                    readable: false,
                    writable: false
                },
                Some(&wrong),
                |_, _, _| {
                    host_calls += 1;
                    Ok(())
                }
            ),
            Err(ProtectionError::SharedDomainBound)
        );
        assert_eq!(host_calls, 0);
        assert_eq!(memory.regions().len(), 1);
        assert_eq!(memory.read_snapshot(address, 1).unwrap(), [0]);
    }
    assert_eq!(domain.generation().unwrap(), 0);
}

#[test]
fn borrowed_protection_rollback_renews_views_and_failed_rollback_quarantines() {
    let page = host_page_size().unwrap() as u64;
    for restore in [true, false] {
        let (mut owner, base) = owned();
        // SAFETY: new owned storage with every writer.
        let domain = unsafe {
            owner.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 79), &mut [])
        }
        .unwrap();
        let old = domain.registered_views()[0].view.clone();
        let loan = domain.service_loan().unwrap();
        let mut calls = 0;
        assert_eq!(
            owner.protect_data_with_service(
                ProtectionChange {
                    address: base,
                    bytes: page,
                    readable: true,
                    writable: false
                },
                Some(&loan),
                |_, _, _| {
                    calls += 1;
                    if calls == 1 || !restore {
                        Err(Some(libc::EACCES))
                    } else {
                        Ok(())
                    }
                }
            ),
            Err(ProtectionError::HostFailure {
                errno: Some(libc::EACCES),
                rollback_succeeded: restore,
            })
        );
        assert!(!old.is_current());
        assert!(domain.execution_loan().is_err());
        drop(loan);
        if restore {
            assert!(owner.is_usable());
            assert_eq!(domain.generation().unwrap(), 1);
            assert!(domain.execution_loan().is_ok());
            owner.write(base, &[9]).unwrap();
        } else {
            assert!(!owner.is_usable());
            assert!(domain.generation().is_err());
            assert!(domain.execution_loan().is_err());
            assert!(owner.write(base, &[9]).is_err());
        }
    }
}

#[test]
fn protection_retires_only_changed_views_preserves_backing_and_domain() {
    let page = host_page_size().unwrap() as u64;
    let (mut main, base) = owned();
    let (mut facade, other) = owned();
    main.write(base, &[42]).unwrap();
    // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
    // reference reaches it.
    let domain = unsafe {
        main.bind_shared_memory_group(
            config(MemorySystem::new(16, 8).unwrap(), 42),
            &mut [&mut facade],
            &mut [],
        )
    }
    .unwrap();
    let old = domain.registered_views();
    let changed = old
        .iter()
        .find(|view| view.view.guest_base() == base)
        .unwrap()
        .view
        .clone();
    let untouched = old
        .iter()
        .find(|view| view.view.guest_base() == other)
        .unwrap()
        .view
        .clone();
    let backing = main.allocations[0].shared_backing.as_ref().unwrap().id();
    main.protect_data(base, page, true, false).unwrap();
    assert!(!changed.is_current());
    assert!(untouched.is_current());
    assert_eq!(domain.generation().unwrap(), 1);
    assert!(Arc::ptr_eq(
        &domain,
        &facade.shared.as_ref().unwrap().domain
    ));
    assert_eq!(
        backing,
        main.allocations[0].shared_backing.as_ref().unwrap().id()
    );
    assert_eq!(main.read_snapshot(base, 1).unwrap(), [42]);
    assert!(main.write(base, &[9]).is_err());
    main.protect_data(base, page, true, true).unwrap();
    main.write(base, &[9]).unwrap();
    assert_eq!(main.read_snapshot(base, 1).unwrap(), [9]);
    assert_eq!(domain.generation().unwrap(), 2);
}

#[test]
fn native_loan_excludes_all_service_effects_until_pc_settlement_drop() {
    let page = host_page_size().unwrap() as u64;
    let (mut main, base) = owned();
    let mut publisher = published();
    // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
    // reference reaches it.
    let domain = unsafe {
        main.bind_shared_memory(
            config(MemorySystem::new(16, 8).unwrap(), 1),
            &mut [&mut publisher],
        )
    }
    .unwrap();
    let loan = domain.execution_loan().unwrap();
    assert!(main.read_snapshot(base, 1).is_err());
    assert!(main.write(base, &[42]).is_err());
    assert!(publisher.publish(0, &[42]).is_err());
    assert_eq!(
        main.protect_data(base, page, false, false),
        Err(ProtectionError::SharedDomainBound)
    );
    assert!(main.begin_data_allocation(request(page)).is_err());
    assert_eq!(domain.generation().unwrap(), 0);
    drop(loan);
    assert_eq!(main.read_snapshot(base, 1).unwrap(), [0]);
    assert_eq!(publisher.read_snapshot(0, 1).unwrap(), [7]);
}

#[test]
fn pending_allocation_excludes_entry_and_publishes_actual_128k_storage_once() {
    let (mut main, _) = owned();
    // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
    // reference reaches it.
    let domain =
        unsafe { main.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 1), &mut []) }
            .unwrap();
    let mut pending = main.begin_data_allocation(request(128 * 1024)).unwrap();
    let base = pending.allocation().guest_address;
    assert!(domain.execution_loan().is_err());
    pending.write(65_535, &[3, 4, 5]).unwrap();
    assert_eq!(pending.read_snapshot(65_535, 3).unwrap(), [3, 4, 5]);
    pending.publish().unwrap();
    assert_eq!(domain.generation().unwrap(), 1);
    assert!(domain.execution_loan().is_ok());
    assert_eq!(main.read_snapshot(base + 65_535, 3).unwrap(), [3, 4, 5]);
    assert_eq!(main.read_snapshot(base + 128 * 1024 - 1, 1).unwrap(), [0]);
    main.write(base, &[99]).unwrap();
    assert_eq!(main.read_snapshot(base, 1).unwrap(), [99]);
}

#[test]
fn pending_drop_preserves_generation_and_existing_views() {
    let (mut main, base) = owned();
    // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
    // reference reaches it.
    let domain =
        unsafe { main.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 1), &mut []) }
            .unwrap();
    {
        let _pending = main.begin_data_allocation(request(4096)).unwrap();
    }
    assert_eq!(domain.generation().unwrap(), 0);
    assert_eq!(main.regions().len(), 1);
    assert_eq!(main.read_snapshot(base, 1).unwrap(), [0]);
}

#[test]
fn rollback_rebuilds_generation_and_failed_rollback_poisons_same_system() {
    let (mut main, base) = owned();
    // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
    // reference reaches it.
    let domain =
        unsafe { main.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 1), &mut []) }
            .unwrap();
    let old = domain.registered_views()[0].view.clone();
    let mut calls = 0;
    let result = main.protect_data_with(
        base,
        host_page_size().unwrap() as u64,
        true,
        false,
        |_, _, _| {
            calls += 1;
            if calls == 1 {
                Err(Some(libc::EACCES))
            } else {
                Ok(())
            }
        },
    );
    assert_eq!(
        result,
        Err(ProtectionError::HostFailure {
            errno: Some(libc::EACCES),
            rollback_succeeded: true
        })
    );
    assert!(!old.is_current());
    assert_eq!(domain.generation().unwrap(), 1);
    main.write(base, &[42]).unwrap();
    let result = main.protect_data_with(
        base,
        host_page_size().unwrap() as u64,
        true,
        false,
        |_, _, _| Err(Some(libc::EACCES)),
    );
    assert_eq!(
        result,
        Err(ProtectionError::HostFailure {
            errno: Some(libc::EACCES),
            rollback_succeeded: false
        })
    );
    assert!(domain.check_execution().is_err());
    assert!(main.read_snapshot(base, 1).is_err());
    assert!(domain.execution_loan().is_err());
}

#[test]
fn split_view_reprotection_keeps_canonical_extent_and_permission_checks() {
    let page = host_page_size().unwrap() as u64;
    let mut main = OwnedMemory::map(vec![]).unwrap();
    let base = main.allocate_data(request(page * 3)).unwrap().guest_address;
    // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
    // reference reaches it.
    let domain =
        unsafe { main.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 1), &mut []) }
            .unwrap();
    main.protect_data(base + page, page, false, false).unwrap();
    assert_eq!(main.regions().len(), 3);
    assert!(main.read_snapshot(base + page - 1, 2).is_err());
    assert_eq!(main.read_snapshot(base, 1).unwrap(), [0]);
    assert_eq!(main.read_snapshot(base + page * 2, 1).unwrap(), [0]);
    main.protect_data(base + page, page, true, true).unwrap();
    assert_eq!(
        main.read_snapshot(base, (page * 3) as usize).unwrap(),
        vec![0; (page * 3) as usize]
    );
    assert_eq!(domain.generation().unwrap(), 2);
}

#[test]
fn public_retirement_fences_native_loans_and_invalidates_generation() {
    let (mut main, _) = owned();
    // SAFETY: the test owns this anonymous storage alone: no other backing, writer or Rust
    // reference reaches it.
    let domain =
        unsafe { main.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 1), &mut []) }
            .unwrap();
    let view = domain.registered_views()[0].view.clone();
    let native = domain.execution_loan().unwrap();
    assert!(domain.retire(&view).is_err());
    assert!(view.is_current());
    assert_eq!(domain.generation().unwrap(), 0);
    drop(native);
    domain.retire(&view).unwrap();
    assert!(!view.is_current());
    assert_eq!(domain.generation().unwrap(), 1);
}
