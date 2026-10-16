//! Exclusive reservations through the memory-service callback.
use super::*;
use crate::memory::{
    backing::{AccessPermissions, MemoryBacking, MemoryView},
    domain::MappingAttributes,
};
use crate::system::events::EventDomain;
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
    sync::Arc,
};
use stela_compiler::context::memory::{
    MemoryOrder, MemoryRequest,
    exclusive::{
        EXCLUSIVE_FAILED, EXCLUSIVE_STORED, ExclusiveData, ExclusiveOperation, ExclusiveShape,
    },
};

const STORAGE_BYTES: usize = 64;
const SCA_BYTES: usize = 16;
const DATA_BASE: u64 = 0x4000;
const WORD_BYTES: u32 = 4;
const STORED_VALUE: u64 = 0x53c7_1a09;
const RIGHTS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}
// SAFETY: raw allocation owner lends no Rust references to the bytes.
unsafe impl Send for Storage {}
// SAFETY: every byte access in this fixture goes through the same coherent
// domain.
unsafe impl Sync for Storage {}
impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: this owner keeps its allocation and layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn reserved_memory() -> (Arc<MemoryDomain>, MemoryThread<MemoryControls>) {
    let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
    // SAFETY: nonempty valid layout retained by the matching storage owner.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let storage = Arc::new(Storage { pointer, layout });
    // SAFETY: stable raw storage, coherent single domain, no byte references.
    let backing = unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, RIGHTS, storage) }.unwrap();
    let view = MemoryView::new(backing, DATA_BASE, 0, STORAGE_BYTES, RIGHTS).unwrap();
    let policy = *memory(&domain()).policy_mut();
    let domain = MemoryDomain::new_for_address_space(
        ADDRESS_SPACE,
        MemorySystem::new(ERG_BYTES, MONITOR_STRIPES).unwrap(),
        vec![(
            view,
            MappingAttributes {
                tagged: false,
                shareable: true,
            },
        )],
        TargetCpu::Baseline,
    )
    .unwrap();
    let thread = domain.thread(policy);
    (domain, thread)
}

fn transfer_requirements() -> MemoryRequirements {
    MemoryRequirements {
        required_profile: profile_requirements::NATIVE_ACCESS,
        ..requirements()
    }
}

fn transfer(view: &mut MemoryContextView, operation: ExclusiveOperation) -> ExclusiveData {
    let write = operation == ExclusiveOperation::Store;
    let mut data = ExclusiveData {
        operation: operation as u32,
        order: MemoryOrder::Relaxed as u32,
        shape: ExclusiveShape::Scalar as u32,
        status: EXCLUSIVE_STORED,
        value: [if write { STORED_VALUE } else { 0 }, 0],
    };
    let request = MemoryRequest {
        address: DATA_BASE,
        data: std::ptr::from_mut(&mut data).cast(),
        bytes: WORD_BYTES,
        flags: flags::EXCLUSIVE | if write { flags::WRITE } else { 0 },
        pc: SOURCE_PC.0,
    };
    // SAFETY: complete initialized aligned ExclusiveData and valid request/view;
    // all staging is private and disjoint from retained native backing.
    let status = unsafe { (view.callback)(view, &request) };
    assert_eq!(MemoryStatus::from_code(status), Some(MemoryStatus::Success));
    data
}

enum Completion {
    Return,
    CallbackError,
    PreflightDecline,
    Unwind,
}

#[test]
fn reservation_survives_scoped_policy_return_error_decline_and_unwind() {
    let system = state();
    let registers = GuestState::default();
    let before = registers.clone();
    for completion in [
        Completion::Return,
        Completion::CallbackError,
        Completion::PreflightDecline,
        Completion::Unwind,
    ] {
        let events = EventDomain::new();
        let endpoint = events.register(false, None).unwrap();
        let (domain, mut thread) = reserved_memory();
        // This private component declares the retained source RAM mapping as
        // effective NormalWB, EL0 RW and InnerShareable; host WB is not proof.
        let controls = controls(&domain);
        thread.bind_events(&endpoint.producer()).unwrap();
        let baseline = *thread.policy_mut();
        let entry = controls
            .prepare(
                &boundary(),
                transfer_requirements(),
                &system,
                &registers,
                &mut thread,
                Some(&endpoint),
            )
            .unwrap();
        // SAFETY: a checked service call over stable RAM.
        let loaded =
            unsafe { entry.with_view(|view| transfer(view, ExclusiveOperation::Load)) }.unwrap();
        assert_eq!(loaded.value, [0; 2]);
        assert_eq!(*thread.policy_mut(), baseline);

        match completion {
            Completion::Return => {
                let entry = controls
                    .prepare(
                        &boundary(),
                        requirements(),
                        &system,
                        &registers,
                        &mut thread,
                        None,
                    )
                    .unwrap();
                assert_eq!(unsafe { entry.with_view(|_| ()) }, Ok(()));
            }
            Completion::CallbackError => {
                let entry = controls
                    .prepare(
                        &boundary(),
                        requirements(),
                        &system,
                        &registers,
                        &mut thread,
                        None,
                    )
                    .unwrap();
                assert_eq!(
                    unsafe { entry.with_view(|_| Err::<(), _>("callback")) },
                    Ok(Err("callback"))
                );
            }
            Completion::PreflightDecline => {
                let requirements = MemoryRequirements {
                    required_host_caps: u32::MAX,
                    ..super::requirements()
                };
                let entry = controls
                    .prepare(
                        &boundary(),
                        requirements,
                        &system,
                        &registers,
                        &mut thread,
                        None,
                    )
                    .unwrap();
                assert_eq!(
                    unsafe { entry.with_view::<()>(|_| panic!("preflight must decline")) },
                    Err(MemoryStatus::InvalidRequest)
                );
            }
            Completion::Unwind => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let entry = controls
                        .prepare(
                            &boundary(),
                            requirements(),
                            &system,
                            &registers,
                            &mut thread,
                            None,
                        )
                        .unwrap();
                    let _ = unsafe { entry.with_view(|_| panic!("outer callback unwind")) };
                }));
                assert!(result.is_err());
            }
        }
        assert_eq!(*thread.policy_mut(), baseline);
        assert_eq!(registers, before);
        let store_requirements = MemoryRequirements {
            required_flags: flags::EXCLUSIVE | flags::WRITE,
            ..transfer_requirements()
        };
        for expected_status in [EXCLUSIVE_STORED, EXCLUSIVE_FAILED] {
            let entry = controls
                .prepare(
                    &boundary(),
                    store_requirements,
                    &system,
                    &registers,
                    &mut thread,
                    Some(&endpoint),
                )
                .unwrap();
            let stored =
                unsafe { entry.with_view(|view| transfer(view, ExclusiveOperation::Store)) }
                    .unwrap();
            assert_eq!(stored.status, expected_status);
            assert_eq!(*thread.policy_mut(), baseline);
        }
    }
}
