//! Import admission owns publication capacity before touching wired memory.
use super::{MockBackend, Status, connect, release, service_on};
use crate::metal::service::{
    identity::ObjectTable,
    tests::{Stream, commit},
};
use core::num::{NonZeroU32, NonZeroU64};
use stela_contracts::gate::MemoryRange;

const RANGE: MemoryRange = MemoryRange {
    address: 0x8_0000_0000,
    bytes: 4096,
};

#[test]
fn a_full_table_refuses_import_before_native_ownership() {
    for pending_work in [false, true] {
        let mut service = service_on(MockBackend::new());
        let connection = connect(&mut service);
        service.connections.get_mut(&connection).unwrap().objects =
            ObjectTable::new(connection, service.epoch, NonZeroU32::MIN);
        let accepted = NonZeroU64::new(7).unwrap();
        let refused = NonZeroU64::new(8).unwrap();
        let memory = service.import(connection, &[RANGE], accepted).unwrap();
        if pending_work {
            commit(&mut service, connection, &Stream::default()).unwrap();
        }
        let next = service.device().backend().next;
        let destroyed = service.device().backend().destroyed.len();
        let allocated = service.device().current_allocated_size();
        assert_eq!(
            service
                .import(connection, &[RANGE], refused)
                .unwrap_err()
                .status,
            Status::OutOfMemory
        );
        let backend = service.device().backend();
        assert_eq!(
            backend.next, next,
            "refusal must not invoke the native importer"
        );
        assert_eq!(backend.destroyed.len(), destroyed);
        assert_eq!(backend.imports.len(), 1);
        assert_eq!(service.device().current_allocated_size(), allocated);
        assert_eq!(service.retired(), None);
        if pending_work {
            let backend = service.device().backend();
            let timeline = *backend.semaphores.keys().next().unwrap();
            backend.semaphores.insert(timeline, 1);
            assert!(service.signaled());
            assert_eq!(
                service.retired(),
                None,
                "unrelated completion cannot retire a refused import token"
            );
        }
        assert_eq!(release(&mut service, connection, memory.get()), Status::Ok);
        assert_eq!(service.retired(), Some(accepted));
        assert_eq!(service.retired(), None);
    }
}

#[test]
fn exhausted_creation_order_refuses_before_native_import() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    service.connections.get_mut(&connection).unwrap().made = u64::MAX;
    let next = service.device().backend().next;
    let error = service
        .import(connection, &[RANGE], NonZeroU64::MIN)
        .unwrap_err();
    assert_eq!(error.status, Status::OutOfMemory);
    let backend = service.device().backend();
    assert_eq!(backend.next, next);
    assert!(backend.imports.is_empty());
    assert!(backend.destroyed.is_empty());
    assert!(service.connections[&connection].objects.is_empty());
    assert_eq!(service.connections[&connection].made, u64::MAX);
    assert_eq!(service.retired(), None);
}

#[test]
fn exhausted_creation_order_releases_an_unpublished_object() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    service.connections.get_mut(&connection).unwrap().made = u64::MAX;
    let event = service.device().new_event().unwrap();
    let error = service
        .hold(connection, crate::metal::service::Object::Event(event))
        .unwrap_err();
    assert_eq!(error.status, Status::OutOfMemory);
    assert_eq!(service.connections[&connection].made, u64::MAX);
    assert!(service.connections[&connection].objects.is_empty());
    assert_eq!(service.device().backend().destroyed.len(), 1);
}
