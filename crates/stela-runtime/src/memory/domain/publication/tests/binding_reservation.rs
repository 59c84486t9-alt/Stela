//! Reservation behavior of bound mappings.
use super::super::super::{MappingAttributes, MemoryDomain, MemorySystem};
use crate::memory::{
    backing::MemoryView,
    binding::tests::{config, native, owned, published},
    monitor,
};
use std::sync::Arc;
use stela_compiler::TargetCpu;

#[test]
fn actual_service_write_invalidates_the_original_backing_reservation() {
    use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
    let (mut owner, base) = owned();
    let system = MemorySystem::new(16, 8).unwrap();
    // SAFETY: new owned anonymous storage with every writer.
    let domain =
        unsafe { owner.bind_shared_memory(config(Arc::clone(&system), 75), &mut []) }.unwrap();
    let mapping = &domain.registered_views()[0];
    let backing = Arc::clone(mapping.view.backing());
    let access = monitor::Access::new(
        Arc::clone(&backing),
        Arc::clone(&mapping.monitor),
        0,
        8,
        monitor::Shape::Scalar,
    )
    .unwrap();
    let mut reservation = system.reservations.thread();
    system
        .reservations
        .load(&mut reservation, &access, || {
            Ok::<_, ()>(native(&backing, 0, 8))
        })
        .unwrap();
    let mut actual_thread = domain.thread(MemoryControls::new(
        LowerAddressProfile::new(47, false).unwrap(),
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    ));
    {
        let mut service = owner.service_memory(&mut actual_thread).unwrap();
        service.validate_write(base, 8).unwrap();
        assert_eq!(service.read_snapshot(base, 8).unwrap(), [0; 8]);
        // Even a same-value write is a real physical writer effect.
        service.write(base, &0u64.to_le_bytes()).unwrap();
    }
    assert!(matches!(
        system
            .reservations
            .store(&mut reservation, &access, || Ok::<_, ()>(())),
        Ok(monitor::ConditionalWrite::Failed)
    ));
    assert_eq!(domain.generation().unwrap(), 0);
}

#[test]
fn bound_host_same_value_and_aba_invalidate_existing_system_reservation() {
    let (mut owner, base) = owned();
    let system = MemorySystem::new(16, 8).unwrap();
    let domain =
        unsafe { owner.bind_shared_memory(config(Arc::clone(&system), 11), &mut []) }.unwrap();
    let mapping = &domain.registered_views()[0];
    let backing = Arc::clone(mapping.view.backing());
    let access = monitor::Access::new(
        Arc::clone(&backing),
        Arc::clone(&mapping.monitor),
        0,
        8,
        monitor::Shape::Scalar,
    )
    .unwrap();
    let mut thread = system.reservations.thread();
    for aba in [false, true] {
        system
            .reservations
            .load(&mut thread, &access, || Ok::<_, ()>(native(&backing, 0, 8)))
            .unwrap();
        if aba {
            owner.write(base, &1u64.to_le_bytes()).unwrap();
        }
        owner.write(base, &0u64.to_le_bytes()).unwrap();
        assert_eq!(
            system
                .reservations
                .store(&mut thread, &access, || -> Result<(), ()> {
                    panic!("invalidated reservation must not write")
                })
                .unwrap(),
            monitor::ConditionalWrite::<()>::Failed
        );
    }
}

#[test]
fn guest_ro_publisher_invalidates_reservation_in_another_address_space() {
    let (mut owner, _) = owned();
    let mut publisher = published();
    let system = MemorySystem::new(16, 8).unwrap();
    let domain =
        unsafe { owner.bind_shared_memory(config(Arc::clone(&system), 12), &mut [&mut publisher]) }
            .unwrap();
    let backing = Arc::clone(publisher.shared_backing.as_ref().unwrap());
    let rights = crate::memory::backing::AccessPermissions {
        readable: true,
        writable: false,
        executable: false,
    };
    let alias = MemoryView::new(Arc::clone(&backing), 0x1000, 0, 32, rights).unwrap();
    let other = MemoryDomain::new_for_address_space(
        13,
        Arc::clone(&system),
        vec![(
            alias,
            MappingAttributes {
                tagged: false,
                shareable: true,
            },
        )],
        TargetCpu::Baseline,
    )
    .unwrap();
    let access = monitor::Access::new(
        Arc::clone(&backing),
        Arc::clone(&other.registered_views()[0].monitor),
        0,
        8,
        monitor::Shape::Scalar,
    )
    .unwrap();
    let mut thread = system.reservations.thread();
    system
        .reservations
        .load(&mut thread, &access, || Ok::<_, ()>(native(&backing, 0, 8)))
        .unwrap();
    publisher.publish(0, &[7; 8]).unwrap();
    assert_eq!(
        system
            .reservations
            .store(&mut thread, &access, || -> Result<(), ()> {
                panic!("alias writer must invalidate")
            })
            .unwrap(),
        monitor::ConditionalWrite::<()>::Failed
    );
    assert_ne!(domain.address_space(), other.address_space());
}

#[test]
fn canonical_snapshots_and_unrelated_mapping_changes_preserve_live_reservation() {
    let (mut owner, base) = owned();
    let (mut other_owner, other_base) = owned();
    let system = MemorySystem::new(16, 8).unwrap();
    let domain = unsafe {
        owner.bind_shared_memory_group(
            config(Arc::clone(&system), 14),
            &mut [&mut other_owner],
            &mut [],
        )
    }
    .unwrap();
    let views = domain.registered_views();
    let mapping = views
        .iter()
        .find(|mapping| mapping.view.guest_base() == base)
        .unwrap();
    let backing = Arc::clone(mapping.view.backing());
    let access = monitor::Access::new(
        Arc::clone(&backing),
        Arc::clone(&mapping.monitor),
        0,
        8,
        monitor::Shape::Scalar,
    )
    .unwrap();
    let mut thread = system.reservations.thread();
    system
        .reservations
        .load(&mut thread, &access, || Ok::<_, ()>(native(&backing, 0, 8)))
        .unwrap();
    assert_eq!(owner.read_snapshot(base, 8).unwrap(), [0; 8]);
    other_owner
        .protect_data(
            other_base,
            crate::memory::host_page_size().unwrap() as u64,
            true,
            false,
        )
        .unwrap();
    assert_eq!(
        system
            .reservations
            .store(&mut thread, &access, || Ok::<_, ()>(()))
            .unwrap(),
        monitor::ConditionalWrite::Stored(())
    );
    system
        .reservations
        .load(&mut thread, &access, || Ok::<_, ()>(native(&backing, 0, 8)))
        .unwrap();
    owner
        .protect_data(
            base,
            crate::memory::host_page_size().unwrap() as u64,
            true,
            false,
        )
        .unwrap();
    let current = domain.registered_views();
    let mapping = current
        .iter()
        .find(|mapping| mapping.view.guest_base() == base)
        .unwrap();
    let replacement = monitor::Access::new(
        Arc::clone(&backing),
        Arc::clone(&mapping.monitor),
        0,
        8,
        monitor::Shape::Scalar,
    )
    .unwrap();
    assert_eq!(
        system
            .reservations
            .store(&mut thread, &replacement, || -> Result<(), ()> {
                panic!("retired view reservation must not reach write")
            })
            .unwrap(),
        monitor::ConditionalWrite::Failed
    );
}
