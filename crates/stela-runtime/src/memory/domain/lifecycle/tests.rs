use super::*;

#[test]
fn retained_execution_membership_requires_same_domain_system_and_health() {
    use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
    let system = MemorySystem::new(16, 8).unwrap();
    let domain = MemoryDomain::new_for_address_space(
        7,
        Arc::clone(&system),
        Vec::new(),
        TargetCpu::Baseline,
    )
    .unwrap();
    let other_domain = MemoryDomain::new_for_address_space(
        7,
        Arc::clone(&system),
        Vec::new(),
        TargetCpu::Baseline,
    )
    .unwrap();
    let policy = MemoryControls::new(
        LowerAddressProfile::new(44, false).unwrap(),
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    );
    let thread = domain.thread(policy);
    let same_domain_thread = domain.thread(policy);
    let other_thread = other_domain.thread(policy);
    let other_system = MemorySystem::new(16, 8).unwrap();
    let execution = thread.execution_loan().unwrap();
    assert_eq!(execution.check_thread_domain(&thread), Ok(()));
    assert_eq!(execution.check_thread_domain(&same_domain_thread), Ok(()));
    assert_eq!(execution.check_memory_system(&system), Ok(()));
    assert_eq!(
        execution.check_thread_domain(&other_thread),
        Err(MemoryStatus::Domain)
    );
    assert_eq!(
        execution.check_memory_system(&other_system),
        Err(MemoryStatus::Domain)
    );
    assert_eq!(domain.state.lock().unwrap().native_loans, 1);
    assert!(thread.observation_loan().is_err());
    // A retained identity is not a health bypass after the actual owner
    // publishes failure; checking does not change the invocation count.
    system.failed.store(true, Ordering::Release);
    assert_eq!(
        execution.check_thread_domain(&thread),
        Err(MemoryStatus::Domain)
    );
    assert_eq!(
        execution.check_memory_system(&system),
        Err(MemoryStatus::Domain)
    );
    assert_eq!(domain.state.lock().unwrap().native_loans, 1);
    drop(execution);
    assert_eq!(domain.state.lock().unwrap().native_loans, 0);
}

#[test]
fn retained_execution_order_serializes_same_machine_across_domains() {
    let system = MemorySystem::new(16, 8).unwrap();
    let first = MemoryDomain::new(Arc::clone(&system), Vec::new(), TargetCpu::Baseline).unwrap();
    let second = MemoryDomain::new(Arc::clone(&system), Vec::new(), TargetCpu::Baseline).unwrap();
    let first_execution = first.execution_loan().unwrap();
    let second_execution = second.execution_loan().unwrap();
    let first_order = first_execution.device_ram_order().unwrap();
    assert!(matches!(
        second_execution.device_ram_order(),
        Err(MemoryStatus::Domain)
    ));
    assert!(first.observation_loan().is_err());
    drop(first_order);
    let second_order = second_execution.device_ram_order().unwrap();
    assert!(matches!(
        first_execution.device_ram_order(),
        Err(MemoryStatus::Domain)
    ));
    drop(second_order);
    system.failed.store(true, Ordering::Release);
    assert!(matches!(
        first_execution.device_ram_order(),
        Err(MemoryStatus::Domain)
    ));
    assert_eq!(first.state.lock().unwrap().native_loans, 1);
    assert_eq!(second.state.lock().unwrap().native_loans, 1);
}

#[test]
fn exhausted_generation_rejects_retirement_without_revoking_view_or_reservation() {
    use crate::memory::binding::tests::{config, native, owned};
    use crate::system::{
        process_memory::{FixedProcessMemoryControls, ProcessMemoryFeatures, SourceNormalWbDomain},
        profile::BaseSpeAbsence,
    };
    const SOURCE_MMU_CACHE_ENABLED: u64 = 1 | (1 << 2);
    const SOURCE_LSE2: u64 = 1 << 32;
    const SOURCE_LOWER_BITS: u8 = 47;
    let (mut owner, base) = owned();
    let system = MemorySystem::new(16, 8).unwrap();
    // SAFETY: fixture owns actual anonymous storage and every source/writer
    // in this fresh untagged/shareable Normal-WB software address space.
    let domain =
        unsafe { owner.bind_shared_memory(config(Arc::clone(&system), 99), &mut []) }.unwrap();
    domain.generation.store(u64::MAX, Ordering::Release);
    domain.state.lock().unwrap().snapshot.generation = u64::MAX;
    let view = domain.registered_views()[0].clone();
    let backing = Arc::clone(view.view.backing());
    let access = monitor::Access::new(
        Arc::clone(&backing),
        Arc::clone(&view.monitor),
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
    // SAFETY: this fixture's explicit complete current source map is the
    // same fresh software machine throughout; no native invocation runs.
    let before =
        unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(&domain)) }.unwrap();
    let features = ProcessMemoryFeatures::from_id_registers(
        0,
        SOURCE_LSE2,
        0,
        0,
        BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
    )
    .unwrap();
    // SAFETY: same complete source declaration, independently captured for
    // the immutable fixed-control owner; no epoch number grants authority.
    let source =
        unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(&domain)) }.unwrap();
    let mut controls = FixedProcessMemoryControls::new(
        features,
        SOURCE_MMU_CACHE_ENABLED,
        u64::from(64 - SOURCE_LOWER_BITS),
        SOURCE_LOWER_BITS,
        source,
    )
    .unwrap();
    assert_eq!(domain.retire(&view.view), Err(MemoryStatus::Domain));
    assert_eq!(domain.generation().unwrap(), u64::MAX);
    assert!(view.view.is_current());
    controls.renew_source_resolved(before).unwrap();
    assert_eq!(owner.read_snapshot(base, 8).unwrap(), [0; 8]);
    assert_eq!(
        system
            .reservations
            .store(&mut reservation, &access, || Ok::<_, ()>(()))
            .unwrap(),
        monitor::ConditionalWrite::Stored(())
    );
}

#[test]
fn actual_thread_observation_pins_views_and_preserves_reservation_without_writers() {
    use crate::memory::binding::tests::{config, native, owned, published};
    use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
    let (mut owner, base) = owned();
    let mut publisher = published();
    let published_base = publisher.region().guest_address;
    let system = MemorySystem::new(16, 8).unwrap();
    // SAFETY: actual owned anonymous RAM and publisher aliases, serialized
    // through this single domain and all its existing physical writers.
    let domain =
        unsafe { owner.bind_shared_memory(config(Arc::clone(&system), 7), &mut [&mut publisher]) }
            .unwrap();
    let view = domain
        .registered_views()
        .into_iter()
        .find(|view| view.view.guest_base() == base)
        .unwrap();
    let backing = Arc::clone(view.view.backing());
    let access = monitor::Access::new(
        Arc::clone(&backing),
        Arc::clone(&view.monitor),
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
    let thread = domain.thread(MemoryControls::new(
        LowerAddressProfile::new(47, false).unwrap(),
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    ));
    let execution = thread.execution_loan().unwrap();
    assert!(thread.observation_loan().is_err());
    drop(execution);
    let observation = thread.observation_loan().unwrap();
    assert_eq!(observation.snapshot(base, 8).unwrap(), [0; 8]);
    assert_eq!(observation.snapshot(published_base, 32).unwrap(), [7; 32]);
    assert_eq!(
        observation.snapshot(base, crate::memory::MAX_IMAGE_MEMORY_BYTES as usize + 1),
        Err(MemoryStatus::InvalidRequest)
    );
    assert!(owner.write(base, &[9]).is_err());
    assert!(publisher.publish(0, &[9]).is_err());
    assert!(thread.execution_loan().is_err());
    drop(observation);
    assert_eq!(
        system
            .reservations
            .store(&mut reservation, &access, || Ok::<_, ()>(()))
            .unwrap(),
        monitor::ConditionalWrite::Stored(())
    );
    assert_eq!(domain.generation().unwrap(), 0);
    owner.write(base, &[9]).unwrap();
    assert_eq!(owner.read_snapshot(base, 1).unwrap(), [9]);
}
