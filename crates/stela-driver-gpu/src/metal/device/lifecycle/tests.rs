use super::{
    super::fixture::{TestDevice, device},
    QuiesceStatus,
};
use crate::metal::{
    abi::{CpuCacheMode, HazardTrackingMode, ResourceOptions, StorageMode},
    error::Error,
};
use core::num::NonZeroU64;
use stela_contracts::gate::MemoryRange;

fn options() -> ResourceOptions {
    ResourceOptions {
        cpu_cache_mode: CpuCacheMode::DefaultCache,
        storage_mode: StorageMode::Shared,
        hazard_tracking_mode: HazardTrackingMode::Default,
    }
}

fn import(device: &mut TestDevice) -> super::super::MemoryId {
    device
        .import_memory(
            &[MemoryRange {
                address: 0x8_0000_0000,
                bytes: 8192,
            }],
            NonZeroU64::MIN,
        )
        .unwrap()
}

fn submit(device: &mut TestDevice) -> u64 {
    let commands = device.new_command_buffer();
    device.commit(commands).unwrap()
}

#[test]
fn admission_closes_before_any_new_import_or_submission() {
    let mut device = device();
    let commands = device.new_command_buffer();
    let created = device.backend().next;
    device.begin_quiesce();
    assert!(device.is_quiescing());
    assert_eq!(
        device.commit(commands),
        Err(Error::Invalid("the device is quiescing"))
    );
    assert_eq!(
        device.import_memory(
            &[MemoryRange {
                address: 4096,
                bytes: 4096
            }],
            NonZeroU64::MIN
        ),
        Err(Error::Invalid("the device is quiescing"))
    );
    assert_eq!(device.backend().next, created);
    assert!(device.backend().submissions.is_empty());
    assert!(!device.is_lost());
}

#[test]
fn gpu_idle_requires_submission_completion_and_backend_acknowledgement() {
    let mut device = device();
    let memory = import(&mut device);
    let buffer = device.new_imported_buffer(memory, 8192, options()).unwrap();
    let serial = submit(&mut device);
    assert_eq!(
        device.quiesce_step(),
        QuiesceStatus::Pending {
            completed: 0,
            submitted: serial
        }
    );
    assert_eq!(device.backend().idle_calls, 0);
    assert_eq!(device.retired(), None);
    let timeline = device.timeline;
    device.backend().complete(timeline, serial);
    assert_eq!(device.quiesce_step(), QuiesceStatus::GpuIdle);
    assert_eq!(device.backend().idle_calls, 1);
    assert_eq!(device.quiesce_step(), QuiesceStatus::GpuIdle);
    assert_eq!(device.backend().idle_calls, 1);
    assert_eq!(
        device.current_allocated_size(),
        8192,
        "idle keeps resource ownership"
    );
    assert_eq!(device.retired(), None);
    device.destroy_buffer(buffer).unwrap();
    assert_eq!(device.retired(), Some(NonZeroU64::MIN));
    assert_eq!(device.retired(), None);
}

#[test]
fn failed_idle_keeps_imports_owned_even_when_the_timeline_completed() {
    let mut device = device();
    let memory = import(&mut device);
    let buffer = device.new_imported_buffer(memory, 8192, options()).unwrap();
    let serial = submit(&mut device);
    let timeline = device.timeline;
    device.backend().complete(timeline, serial);
    device.backend().idle_error = Some(Error::DeviceLost);
    assert_eq!(
        device.quiesce_step(),
        QuiesceStatus::Unproven(Error::DeviceLost)
    );
    device.destroy_buffer(buffer).unwrap();
    assert_eq!(device.backend().imports.len(), 1);
    assert!(device.backend().destroyed.is_empty());
    assert_eq!(device.current_allocated_size(), 8192);
    assert_eq!(device.retired(), None);
    device.backend().idle_error = None;
    assert_eq!(
        device.quiesce_step(),
        QuiesceStatus::Unproven(Error::DeviceLost)
    );
    assert_eq!(
        device.backend().idle_calls,
        1,
        "a failure cannot reopen the old identity"
    );
}

#[test]
fn lost_pending_work_never_becomes_an_idle_acknowledgement() {
    let mut device = device();
    let memory = import(&mut device);
    let serial = submit(&mut device);
    device.mark_lost();
    device.release_import(memory).unwrap();
    let timeline = device.timeline;
    device.backend().complete(timeline, serial);
    assert_eq!(
        device.quiesce_step(),
        QuiesceStatus::Unproven(Error::DeviceLost)
    );
    assert_eq!(device.backend().idle_calls, 0);
    assert_eq!(device.retired(), None);
    assert_eq!(device.backend().imports.len(), 1);
}

#[test]
fn a_failed_completion_query_is_unproven_without_releasing_imports() {
    let mut device = device();
    let memory = import(&mut device);
    submit(&mut device);
    device.release_import(memory).unwrap();
    device.backend().semaphore_error = Some(Error::OutOfMemory);
    assert_eq!(
        device.quiesce_step(),
        QuiesceStatus::Unproven(Error::OutOfMemory)
    );
    assert!(device.is_lost());
    assert_eq!(device.backend().idle_calls, 0);
    assert_eq!(device.retired(), None);
    assert_eq!(device.current_allocated_size(), 8192);
}
