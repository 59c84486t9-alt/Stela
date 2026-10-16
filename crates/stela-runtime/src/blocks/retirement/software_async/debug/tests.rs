use super::*;

mod domain_identity;
fn fresh() -> SoftwareAsyncDomain {
    unsafe { SoftwareAsyncDomain::fresh_software_pe() }
}
#[test]
fn unconnected_output_remains_real_registered_effect() {
    let mut domain = fresh();
    let source = domain.register_debug().unwrap();
    assert!(matches!(
        domain.lease_no_sources(),
        Err(AsyncError::RegisteredProducer)
    ));
    {
        let keys = [source];
        let mut lease = domain.lease_debug_sources(&keys).unwrap();
        let route = CtiRoute {
            output_slot: 0,
            target_slots: vec![],
        };
        let plan = lease.prepare_cross_halt(&route).unwrap();
        let receipt = lease.publish_cross_halt(plan).unwrap();
        assert_eq!(receipt.sequence, 1);
        assert_eq!(receipt.delivered_targets, 0);
        assert_eq!(lease.domain.cross_halt_outputs.len(), 1);
        assert_eq!(
            lease.domain.cross_halt_outputs[0].source,
            lease.keys[0].0.id
        );
        assert!(lease.domain.pending.is_empty());
    }
    assert!(matches!(
        domain.lease_no_sources(),
        Err(AsyncError::RegisteredProducer)
    ));
}
#[test]
fn configured_target_input_is_retained_and_not_discarded_as_editr() {
    let mut domain = fresh();
    let output = domain.register_debug().unwrap();
    let target = domain.register_debug().unwrap();
    let keys = [output, target];
    let mut lease = domain.lease_debug_sources(&keys).unwrap();
    let plan = lease
        .prepare_cross_halt(&CtiRoute {
            output_slot: 0,
            target_slots: vec![1],
        })
        .unwrap();
    lease.publish_cross_halt(plan).unwrap();
    assert_eq!(
        lease.domain.pending.front().unwrap().source,
        lease.keys[1].0.id
    );
    assert!(matches!(
        lease.next_editr(),
        Err(AsyncError::UnsupportedPending)
    ));
    assert_eq!(lease.domain.pending.len(), 1);
    assert_eq!(
        lease.qualify_normal_boundary(),
        Err(AsyncError::PendingEvent)
    );
}
#[test]
fn all_registered_producers_and_exact_input_source_remain_bound() {
    let mut domain = fresh();
    let source = domain.register_debug().unwrap();
    domain.enqueue_editr(&source, 0xd6bf03e0).unwrap();
    let keys = [source];
    {
        let mut lease = domain.lease_debug_sources(&keys).unwrap();
        let event = lease.next_editr().unwrap().unwrap();
        assert_eq!(event.word(), 0xd6bf03e0);
        assert_eq!(event.sequence(), 1);
        lease.consume_editr(&event).unwrap();
        assert_eq!(lease.consume_editr(&event), Err(AsyncError::SourceChanged));
        assert!(lease.domain.pending.is_empty());
    }
    let hidden = domain.register(SourceClass::Irq).unwrap();
    drop(hidden);
    assert!(matches!(
        domain.lease_debug_sources(&[]),
        Err(AsyncError::RegisteredProducer)
    ));
}
