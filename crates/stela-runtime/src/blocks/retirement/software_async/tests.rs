use super::*;

fn fresh() -> SoftwareAsyncDomain {
    // SAFETY: each test owns the whole declared software producer universe;
    // every constructor/injector below operates on this actual unique domain.
    unsafe { SoftwareAsyncDomain::fresh_software_pe() }
}

#[test]
fn registered_source_is_not_absent_when_its_pending_queue_is_empty() {
    for class in [
        SourceClass::Irq,
        SourceClass::Fiq,
        SourceClass::SError,
        SourceClass::Nmi,
        SourceClass::Debug,
    ] {
        let mut domain = fresh();
        let key = domain.register(class).unwrap();
        assert!(domain.pending.is_empty());
        assert!(matches!(
            domain.lease_no_sources(),
            Err(AsyncError::RegisteredProducer)
        ));
        drop(key);
        assert!(matches!(
            domain.lease_no_sources(),
            Err(AsyncError::RegisteredProducer)
        ));
    }
}

#[test]
fn injector_uses_the_actual_unique_registered_domain() {
    let mut first = fresh();
    let mut other = fresh();
    let key = first.register(SourceClass::Irq).unwrap();
    assert_eq!(other.inject(&key), Err(AsyncError::WrongProducer));
    assert!(other.pending.is_empty());
    first.inject(&key).unwrap();
    assert_eq!(first.pending.front().unwrap().source, key.id);
    assert_eq!(first.registered[&key.id], SourceClass::Irq);
    assert!(matches!(
        first.lease_no_sources(),
        Err(AsyncError::RegisteredProducer)
    ));
}

#[test]
fn a_fresh_exclusive_source_registry_can_be_borrowed_without_copying_it() {
    let mut domain = fresh();
    {
        let lease = domain.lease_no_sources().unwrap();
        assert_eq!(lease.domain.next_source, 0);
        assert!(lease.domain.registered.is_empty());
        assert!(lease.domain.pending.is_empty());
    }
    domain.next_source = u64::MAX;
    assert!(matches!(
        domain.register(SourceClass::Debug),
        Err(AsyncError::SequenceExhausted)
    ));
    assert!(domain.registered.is_empty());
    assert!(domain.pending.is_empty());
}
