//! Runs inside existing domain/publication test privacy, without exposing monitor internals.
use super::super::super::{MappingAttributes, MemoryDomain, MemorySystem};
use crate::memory::{
    backing::MemoryView,
    binding::tests::{config, native, owned, published},
    monitor,
};
use std::sync::Arc;
use stela_compiler::TargetCpu;

#[test]
fn bound_host_same_value_and_aba_invalidate_existing_system_reservation() {
    let (mut owner, base) = owned();
    let system = MemorySystem::new(16, 8).unwrap();
    let domain =
        unsafe { owner.bind_shared_memory(config(Arc::clone(&system), 11), &mut []) }.unwrap();
    let mapping = &domain.views[0];
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
        Arc::clone(&other.views[0].monitor),
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
