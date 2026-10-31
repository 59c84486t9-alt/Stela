use super::{Memory, call, connect, cpu_buffer, service, status};
use crate::metal::{
    abi::StorageMode,
    device::{EventId, lifecycle::QuiesceStatus},
    error::Error,
    service::{
        ServiceHost, SharedService,
        wire::{Empty, EventValueRequest, Handle, Operation, Status, Value},
    },
};
use core::num::NonZeroU64;
use stela_contracts::gate::{GateService, MemoryRange};

#[test]
fn quiescing_closes_guest_admission_without_losing_a_healthy_device() {
    let mut service = service();
    let connection = connect(&mut service);
    let buffer = cpu_buffer(&mut service, connection, 8192, StorageMode::Shared);
    service.begin_quiesce();
    assert_eq!(service.connect().unwrap_err().status, Status::Invalid);
    assert_eq!(
        service
            .import(
                connection,
                &[MemoryRange {
                    address: 4096,
                    bytes: 4096
                }],
                NonZeroU64::new(2).unwrap()
            )
            .unwrap_err()
            .status,
        Status::Invalid
    );
    assert_eq!(service.device().backend().imports.len(), 1);
    assert_eq!(
        status(call::<_, Handle>(
            &mut service,
            connection,
            Operation::NewEvent,
            &Empty {},
            &mut Memory::default()
        )),
        Status::Closed
    );
    assert!(!service.device().is_lost());
    assert_eq!(service.quiesce_step(), QuiesceStatus::GpuIdle);
    assert_eq!(service.device().current_allocated_size(), 8192);
    assert_eq!(service.retired(), None);
    // Even after idle, the gate still owns the connection and its resources.
    let allocated: Value = call(
        &mut service,
        connection,
        Operation::AllocatedSize,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    assert_eq!(allocated.value, 8192);
    call::<_, Empty>(
        &mut service,
        connection,
        Operation::Release,
        &Handle {
            handle: buffer.handle,
        },
        &mut Memory::default(),
    )
    .unwrap();
    assert_eq!(service.retired(), Some(NonZeroU64::MIN));
    assert_eq!(service.retired(), None);
    service.disconnect(connection).unwrap();
}

#[test]
fn existing_event_signals_remain_available_while_work_drains() {
    let mut service = service();
    let connection = connect(&mut service);
    let event: Handle = call(
        &mut service,
        connection,
        Operation::NewEvent,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    let id = service.object::<EventId>(connection, event.handle).unwrap();
    let semaphore = service.device().event_semaphore(id).unwrap();
    let mut commands = service.device().new_command_buffer();
    commands
        .encode_wait_for_event(&mut service.device().resolver(), semaphore, 5)
        .unwrap();
    let serial = service.device().commit(commands).unwrap();
    assert_eq!(
        service.quiesce_step(),
        QuiesceStatus::Pending {
            completed: 0,
            submitted: serial
        }
    );
    call::<_, Empty>(
        &mut service,
        connection,
        Operation::SetEventSignaledValue,
        &EventValueRequest {
            event: event.handle,
            value: 5,
        },
        &mut Memory::default(),
    )
    .unwrap();
    assert_eq!(service.device().backend().semaphores[&semaphore.0], 5);
    assert_eq!(service.device().backend().idle_calls, 0);
    let backend = service.device().backend();
    let timeline = *backend.semaphores.keys().next().unwrap();
    backend.semaphores.insert(timeline, serial);
    assert_eq!(service.quiesce_step(), QuiesceStatus::GpuIdle);
    assert!(!service.device().is_lost());
}

#[test]
fn shared_quiesce_uses_the_serialized_service_stack() {
    let shared = SharedService::new(
        service(),
        ServiceHost {
            relax: || panic!("nothing waits"),
            stack: 0x4000,
            run: |stack, call| {
                assert_eq!(stack, 0x4000);
                call();
            },
        },
    );
    let connection = shared.connect().unwrap();
    shared.begin_quiesce();
    assert!(shared.connect().is_err());
    assert_eq!(shared.quiesce_step(), QuiesceStatus::GpuIdle);
    shared.disconnect(connection);
}

#[test]
fn failed_idle_does_not_close_the_connection_or_release_its_imports() {
    let mut service = service();
    let connection = connect(&mut service);
    cpu_buffer(&mut service, connection, 8192, StorageMode::Shared);
    service.device().backend().idle_error = Some(Error::DeviceLost);
    assert_eq!(
        service.quiesce_step(),
        QuiesceStatus::Unproven(Error::DeviceLost)
    );
    assert!(service.connections.contains_key(&connection));
    service.disconnect(connection).unwrap();
    assert_eq!(service.retired(), None);
    assert_eq!(service.device().backend().imports.len(), 1);
    assert_eq!(service.device().current_allocated_size(), 8192);
}
