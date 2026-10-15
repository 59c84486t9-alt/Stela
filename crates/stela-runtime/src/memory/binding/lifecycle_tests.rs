use super::*;
use crate::memory::binding::tests::{config, owned, published};
use crate::memory::{
    AllocateDataRequest, DataInheritance, DataPermissions, DataPlacement, host_page_size,
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

#[test]
fn protection_retires_only_changed_views_preserves_backing_and_domain() {
    let page = host_page_size().unwrap() as u64;
    let (mut main, base) = owned();
    let (mut facade, other) = owned();
    main.write(base, &[42]).unwrap();
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
fn real_commpage_facades_join_once_and_clock_publication_preserves_static_bytes() {
    let _lock = crate::clock::TEST_CONTEXT_LOCK.lock().unwrap();
    let (mut main, _) = owned();
    let mut modern =
        crate::commpage::Context::new(42, crate::commpage::KernelPageSize::FourKiB).unwrap();
    let samples = vec![
        crate::clock::Snapshot {
            counter: 10,
            sleep_ticks: 1,
        },
        crate::clock::Snapshot {
            counter: 20,
            sleep_ticks: 2,
        },
        crate::clock::Snapshot {
            counter: 30,
            sleep_ticks: 3,
        },
    ];
    let mut clock = crate::clock::Context::new(
        42,
        Box::new(crate::clock::ReplaySource::new(samples).unwrap()),
    )
    .unwrap();
    let original_modern = modern.snapshot_bytes().unwrap();
    let original_clock = clock.snapshot_bytes(0, crate::clock::GUEST_BYTES).unwrap();
    let domain = unsafe {
        main.bind_shared_memory_participants(
            config(MemorySystem::new(16, 8).unwrap(), 42),
            &mut [
                modern.shared_memory_participant(),
                clock.shared_memory_participant(),
            ],
        )
    }
    .unwrap();
    assert_eq!(modern.snapshot_bytes().unwrap(), original_modern);
    assert_eq!(
        clock.snapshot_bytes(0, crate::clock::GUEST_BYTES).unwrap(),
        original_clock
    );
    assert_eq!(domain.registered_views().len(), 3);
    assert_eq!(clock.read_counter().unwrap(), 20);
    assert_eq!(clock.read_counter().unwrap(), 30);
    assert!(clock.read_counter().is_err());
    assert_eq!(clock.events().len(), 3);
    assert_eq!(domain.generation().unwrap(), 0);
    assert_eq!(modern.snapshot_bytes().unwrap(), original_modern);
    assert!(
        unsafe {
            main.bind_shared_memory_participants(
                config(MemorySystem::new(16, 8).unwrap(), 42),
                &mut [
                    modern.shared_memory_participant(),
                    clock.shared_memory_participant(),
                ],
            )
        }
        .is_err()
    );
}

#[test]
fn public_retirement_fences_native_loans_and_invalidates_generation() {
    let (mut main, _) = owned();
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
