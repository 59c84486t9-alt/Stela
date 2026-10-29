use super::super::backing::AccessPermissions;
use super::*;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;

mod callbacks;
mod checked_finalization {
    use super::*;

    fn reserve(
        thread: &mut MemoryThread<Policy>,
    ) -> monitor::Access<MemoryBacking, MemoryView, MappingAttributes> {
        let access = reservation_access(&thread.domain, 0);
        thread
            .domain
            .system
            .reservations
            .load(&mut thread.reservation, &access, || {
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
        access
    }

    fn fixture() -> (Arc<MemoryBacking>, Arc<MemoryDomain>, MemoryThread<Policy>) {
        let backing = backing();
        let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
        let thread = domain.thread(Policy::default());
        (backing, domain, thread)
    }

    #[test]
    fn checked_entry_returns_healthy_body_result() {
        let (_, _, mut thread) = fixture();
        let entry = thread.prepare(MemoryRequirements::default()).unwrap();
        // SAFETY: no native pointer is retained or accessed by this body.
        assert_eq!(unsafe { entry.with_checked_view(|_| 37) }, Ok(37));
    }

    #[test]
    fn callback_fault_clears_actual_reservation_and_preserves_fault() {
        let (backing, domain, mut thread) = fixture();
        let access = reserve(&mut thread);
        thread.policy.reject = Some(GUEST_BASE);
        let mut data = [0x7c];
        let request = MemoryRequest {
            address: GUEST_BASE,
            data: data.as_mut_ptr(),
            bytes: 1,
            flags: 0,
            pc: TEST_PC,
        };
        // SAFETY: valid synchronous ABI request and disjoint private staging.
        let result = unsafe {
            thread.with_checked_view(|context| {
                let status = (context.callback)(context, &request);
                (
                    status,
                    context.fault_address,
                    context.fault_pc,
                    context.completed_bytes,
                )
            })
        };
        assert_eq!(
            result,
            Ok((MemoryStatus::TagCheck as u32, GUEST_BASE, TEST_PC, 0))
        );
        assert_eq!(data, [0x7c]);
        assert_eq!(snapshot(&backing, 1), [0]);
        assert_eq!(
            domain.system.reservations.store(
                &mut thread.reservation,
                &access,
                || -> Result<(), MemoryStatus> { panic!("cleared reservation invoked store") }
            ),
            Ok(monitor::ConditionalWrite::<()>::Failed)
        );
    }

    #[test]
    fn local_alignment_fault_clears_actual_reservation() {
        let (_, domain, mut thread) = fixture();
        let access = reserve(&mut thread);
        // SAFETY: this body records a local fault without exposing ABI pointers.
        let result = unsafe {
            thread.with_checked_view(|context| {
                context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 3);
                (
                    context.fault_kind,
                    context.fault_address,
                    context.fault_pc,
                    context.completed_bytes,
                )
            })
        };
        assert_eq!(
            result,
            Ok((MemoryStatus::Alignment as u32, GUEST_BASE + 1, TEST_PC, 3))
        );
        assert_eq!(
            domain.system.reservations.store(
                &mut thread.reservation,
                &access,
                || -> Result<(), MemoryStatus> { panic!("local fault did not clear") }
            ),
            Ok(monitor::ConditionalWrite::<()>::Failed)
        );
    }

    #[test]
    fn retained_session_fault_preserves_prefix_and_clears_actual_reservation() {
        let (_, domain, mut thread) = fixture();
        let access = reserve(&mut thread);
        let session = thread.execution_session().unwrap();
        // SAFETY: a locally emitted checked fault with copied provenance.
        let result = unsafe {
            thread.with_checked_view_in(&session, |context| {
                context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 3);
                (
                    context.fault_kind,
                    context.fault_address,
                    context.fault_pc,
                    context.completed_bytes,
                )
            })
        };
        assert_eq!(
            result,
            Ok((MemoryStatus::Alignment as u32, GUEST_BASE + 1, TEST_PC, 3))
        );
        assert_eq!(domain.state.lock().unwrap().native_loans, 1);
        assert_eq!(
            domain.system.reservations.store(
                &mut thread.reservation,
                &access,
                || -> Result<(), MemoryStatus> { panic!("session fault did not clear") }
            ),
            Ok(monitor::ConditionalWrite::<()>::Failed)
        );
    }

    #[test]
    fn retained_session_final_failure_keeps_write_and_external_fault_evidence() {
        let (backing, domain, mut thread) = fixture();
        let session = thread.execution_session().unwrap();
        let mut data = [0x6b];
        let request = MemoryRequest {
            address: GUEST_BASE,
            data: data.as_mut_ptr(),
            bytes: 1,
            flags: flags::WRITE,
            pc: TEST_PC,
        };
        let mut evidence = None;
        // SAFETY: exact synchronous request and private disjoint staging.
        let result = unsafe {
            thread.with_checked_view_in(&session, |context| {
                let status = (context.callback)(context, &request);
                evidence = Some((status, context.completed_bytes));
                domain.system.failed.store(true, Ordering::Release);
                91
            })
        };
        assert_eq!(result, Err(MemoryStatus::Domain));
        assert_eq!(evidence, Some((MemoryStatus::Success as u32, 1)));
        assert_eq!(snapshot(&backing, 1), [0x6b]);
        assert!(session.check_thread(&thread).is_err());
    }

    #[test]
    fn post_body_health_failure_discards_result_without_rolling_back_write() {
        let (backing, domain, mut thread) = fixture();
        let mut data = [0x6b];
        let request = MemoryRequest {
            address: GUEST_BASE,
            data: data.as_mut_ptr(),
            bytes: 1,
            flags: flags::WRITE,
            pc: TEST_PC,
        };
        let mut prefix = None;
        // SAFETY: valid synchronous ABI request and disjoint private staging.
        let result = unsafe {
            thread.with_checked_view(|context| {
                let status = (context.callback)(context, &request);
                prefix = Some((status, context.completed_bytes));
                domain.system.failed.store(true, Ordering::Release);
                91
            })
        };
        assert_eq!(result, Err(MemoryStatus::Domain));
        assert_eq!(prefix, Some((MemoryStatus::Success as u32, 1)));
        assert_eq!(snapshot(&backing, 1), [0x6b]);
        assert_eq!(
            thread.prepare(MemoryRequirements::default()).err(),
            Some(MemoryStatus::Domain)
        );
    }

    #[test]
    fn local_alignment_late_failure_preserves_external_provenance() {
        let (_, domain, mut thread) = fixture();
        let mut fault = None;
        // SAFETY: this body records a local fault; it retains only copied scalars.
        let result = unsafe {
            thread.with_checked_view(|context| {
                context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 5);
                fault = Some((
                    context.fault_kind,
                    context.fault_address,
                    context.fault_pc,
                    context.completed_bytes,
                ));
                domain.system.failed.store(true, Ordering::Release);
                72
            })
        };
        assert_eq!(result, Err(MemoryStatus::Domain));
        assert_eq!(
            fault,
            Some((MemoryStatus::Alignment as u32, GUEST_BASE + 1, TEST_PC, 5))
        );
    }

    #[test]
    fn actual_monitor_failure_during_body_is_reported_by_post_body_health() {
        let (backing, domain, mut thread) = fixture();
        reserve(&mut thread);
        let range = monitor::WriteRange::new(backing, 0, 1).unwrap();
        // SAFETY: the body uses the real writer gate, catches its deliberate panic,
        // and records a local fault; no pointers or owner borrows escape.
        let result = unsafe {
            thread.with_checked_view(|context| {
                let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = domain.system.reservations.with_writer(
                        &range,
                        monitor::Invalidation::OnCommit,
                        || -> Result<(), MemoryStatus> {
                            panic!("deliberate real monitor failure")
                        },
                    );
                }));
                assert!(failure.is_err());
                context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 0);
                84
            })
        };
        assert_eq!(result, Err(MemoryStatus::Domain));
        assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
    }

    #[test]
    fn malformed_fault_status_fails_finalization() {
        let (_, _, mut thread) = fixture();
        assert_eq!(
            // SAFETY: The fixture retains the domain, callback, and backing for this call.
            // Only the fault sidecar is changed; no staging or view pointer escapes.
            unsafe {
                thread.with_checked_view(|context| {
                    context.fault_kind = u32::MAX;
                    19
                })
            },
            Err(MemoryStatus::Domain)
        );
    }

    #[test]
    fn legacy_result_does_not_assert_successful_finalization() {
        let (_, domain, mut thread) = fixture();
        assert_eq!(
            // SAFETY: The fixture retains the domain and callback. The closure accesses
            // no guest pointers and changes only the atomic failure flag.
            unsafe {
                thread.with_view(|_| {
                    domain.system.failed.store(true, Ordering::Release);
                    26
                })
            },
            26
        );
        assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
    }
}
mod exclusive;
mod quantities;
mod reservations;

const GUEST_BASE: u64 = 0x1000;
const STORAGE_BYTES: usize = 64;
const TEST_PC: u64 = 0x1234;
const TEST_ERG_BYTES: u64 = 16;
const TEST_STRIPES: usize = 4;
const RIGHTS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};
const ATTRIBUTES: MappingAttributes = MappingAttributes {
    tagged: false,
    shareable: true,
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}

// SAFETY: this owner retains raw storage without lending Rust references.
unsafe impl Send for Storage {}
// SAFETY: byte accesses go through the tested execution domain.
unsafe impl Sync for Storage {}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: the allocation and layout are owned here.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn backing() -> Arc<MemoryBacking> {
    let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
    // SAFETY: valid nonempty layout retained for its matching deallocation.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let storage = Arc::new(Storage { pointer, layout });
    // SAFETY: storage owns stable raw bytes and rights; no Rust references
    // alias them and tests access only through the native access boundary.
    unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, RIGHTS, storage) }.unwrap()
}

fn view(
    backing: &Arc<MemoryBacking>,
    offset: usize,
    bytes: usize,
    rights: AccessPermissions,
) -> Arc<MemoryView> {
    MemoryView::new(
        Arc::clone(backing),
        GUEST_BASE + offset as u64,
        offset,
        bytes,
        rights,
    )
    .unwrap()
}

fn domain(views: Vec<Arc<MemoryView>>) -> Arc<MemoryDomain> {
    MemoryDomain::new(
        MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
        views.into_iter().map(|view| (view, ATTRIBUTES)).collect(),
        TargetCpu::detect(),
    )
    .unwrap()
}

mod system_reads {
    use super::*;
    use stela_compiler::context::memory::{
        InstructionRequirements,
        exclusive::{ExclusiveData, ExclusiveOperation},
    };
    #[derive(Default)]
    struct ReadPolicy;
    impl DataPolicy for ReadPolicy {
        fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn validate_operation_execution(
            &self,
            _: MemoryOperationClass,
        ) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn validate_instructions(&self, _: InstructionRequirements) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn translate(&self, raw: u64) -> Result<u64, MemoryStatus> {
            Ok(raw)
        }
        fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
            Ok(())
        }
    }
    fn physical_fixture() -> (Arc<MemoryBacking>, Arc<MemoryDomain>) {
        // Synthetic software mapping authority tests actual native memory
        // recipes only. CPL0/source-CPU entry is separately qualified.
        assert!(TargetCpu::X86_64_V2.supported());
        let backing = backing();
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let views = vec![
            (
                MemoryView::new(Arc::clone(&backing), GUEST_BASE, 0, STORAGE_BYTES, readonly)
                    .unwrap(),
                ATTRIBUTES,
            ),
            (
                MemoryView::new(
                    Arc::clone(&backing),
                    GUEST_BASE + 0x1000,
                    0,
                    STORAGE_BYTES,
                    RIGHTS,
                )
                .unwrap(),
                ATTRIBUTES,
            ),
        ];
        let domain = MemoryDomain::construct_admitted(
            None,
            MemorySystem::new(16, 4).unwrap(),
            views,
            TargetCpu::X86_64_V2,
            DomainRole::NativeSystemRam,
        )
        .unwrap();
        (backing, domain)
    }
    fn exclusive(
        thread: &mut MemoryThread<ReadPolicy>,
        data: &mut ExclusiveData,
    ) -> (MemoryStatus, u64) {
        let write = data.operation == ExclusiveOperation::Store as u32;
        let request = MemoryRequest {
            address: GUEST_BASE + 0x1000,
            bytes: 16,
            data: core::ptr::from_mut(data).cast(),
            flags: flags::EXCLUSIVE | if write { flags::WRITE } else { 0 },
            pc: TEST_PC,
        };
        // SAFETY: retained exact native-capable fixture/storage/events and
        // initialized private staging. No production admission is asserted.
        unsafe {
            thread.with_checked_view(|view| {
                let status = (view.callback)(view, &request);
                (
                    MemoryStatus::from_code(status).unwrap(),
                    view.completed_bytes,
                )
            })
        }
        .unwrap()
    }
    #[test]
    fn cx16_source_read_only_alias_preserves_real_global_reservation() {
        let (backing, domain) = physical_fixture();
        assert!(matches!(
            domain
                .thread(ReadPolicy)
                .prepare(MemoryRequirements::default()),
            Err(MemoryStatus::Unsupported)
        ));
        let events = crate::system::events::EventDomain::new();
        let endpoint = events.register(false, None).unwrap();
        let mut writer = domain.thread(ReadPolicy);
        writer.bind_events(&endpoint.producer()).unwrap();
        let mut load = ExclusiveData {
            operation: ExclusiveOperation::Load as u32,
            shape: 1,
            ..Default::default()
        };
        assert_eq!(
            exclusive(&mut writer, &mut load),
            (MemoryStatus::Success, 16)
        );
        let mut reader = domain.thread(ReadPolicy);
        let mut bytes = [0xff; 16];
        let request = MemoryRequest {
            address: GUEST_BASE,
            bytes: 16,
            data: bytes.as_mut_ptr(),
            flags: 0,
            pc: TEST_PC,
        };
        // SAFETY: same retained real native fixture, read-only source view
        // and private destination. Fallback host writeback stays gated.
        let status =
            unsafe { reader.with_checked_view(|view| (view.callback)(view, &request)) }.unwrap();
        assert_eq!(status, MemoryStatus::Success as u32);
        assert_eq!(bytes, [0; 16]);
        assert_eq!(snapshot(&backing, STORAGE_BYTES), [0; STORAGE_BYTES]);
        let mut store = ExclusiveData {
            operation: ExclusiveOperation::Store as u32,
            shape: 1,
            value: [0x1234, 0x5678],
            ..Default::default()
        };
        assert_eq!(
            exclusive(&mut writer, &mut store),
            (MemoryStatus::Success, 16)
        );
        assert_eq!(
            store.status, 0,
            "observer must not invalidate the source reservation"
        );
        let mut expected = [0; STORAGE_BYTES];
        expected[..8].copy_from_slice(&0x1234u64.to_le_bytes());
        expected[8..16].copy_from_slice(&0x5678u64.to_le_bytes());
        assert_eq!(snapshot(&backing, STORAGE_BYTES), expected);
    }
    #[test]
    fn real_alias_writer_aba_still_invalidates_after_observer_read() {
        let (backing, domain) = physical_fixture();
        let events = crate::system::events::EventDomain::new();
        let endpoint = events.register(false, None).unwrap();
        let mut writer = domain.thread(ReadPolicy);
        writer.bind_events(&endpoint.producer()).unwrap();
        let mut load = ExclusiveData {
            operation: ExclusiveOperation::Load as u32,
            shape: 1,
            ..Default::default()
        };
        assert_eq!(exclusive(&mut writer, &mut load).0, MemoryStatus::Success);
        // This real host writer uses exactly the same physical monitor,
        // including the A->B->A case invisible to byte comparison.
        // SAFETY: The first sixteen bytes are pinned writable raw backing; these private
        // source arrays are disjoint. Both writes use the domain reservation gate.
        unsafe {
            domain.system.publish(&backing, 0, &[1; 16]).unwrap();
            domain.system.publish(&backing, 0, &[0; 16]).unwrap();
        }
        let mut store = ExclusiveData {
            operation: ExclusiveOperation::Store as u32,
            shape: 1,
            value: [7, 9],
            ..Default::default()
        };
        assert_eq!(exclusive(&mut writer, &mut store).0, MemoryStatus::Success);
        assert_eq!(store.status, 1);
        assert_eq!(snapshot(&backing, STORAGE_BYTES), [0; STORAGE_BYTES]);
    }
}

mod access_intent {
    use super::*;
    use stela_compiler::context::memory::{
        FaultAccess, InstructionRequirements, MemoryOrder,
        atomic::{AtomicData, AtomicOperation},
        exclusive::{ExclusiveData, ExclusiveOperation},
        ordered::{OrderedData, OrderedOperation},
    };

    #[derive(Default)]
    struct Directed {
        checked: Vec<DataRequest>,
        parts: Vec<(DataRequest, DataPart)>,
        deny_write: Option<u64>,
    }
    impl DataPolicy for Directed {
        fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn validate_operation_execution(
            &self,
            _: MemoryOperationClass,
        ) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn validate_instructions(&self, _: InstructionRequirements) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn translate(&self, raw: u64) -> Result<u64, MemoryStatus> {
            Ok(raw)
        }
        fn validate_data_request(&mut self, request: DataRequest) -> Result<(), MemoryStatus> {
            self.checked.push(request);
            Ok(())
        }
        fn translate_part(
            &mut self,
            request: DataRequest,
            part: DataPart,
        ) -> Result<u64, (MemoryStatus, u64)> {
            self.parts.push((request, part));
            if part.kind == AccessKind::Write && self.deny_write == Some(part.address) {
                Err((MemoryStatus::Permission, part.address))
            } else {
                Ok(part.address)
            }
        }
        fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
            Ok(())
        }
    }
    fn callback(thread: &mut MemoryThread<Directed>, request: MemoryRequest) -> MemoryFault {
        // SAFETY: every fixture retains initialized disjoint typed staging,
        // canonical backing, private context and exact request for this call.
        unsafe {
            thread.with_checked_view(|view| {
                (view.callback)(view, &request);
                MemoryFault {
                    status: MemoryStatus::from_code(view.fault_kind).unwrap(),
                    access: FaultAccess::from_code(view.fault_access).unwrap(),
                    address: view.fault_address,
                    pc: view.fault_pc,
                    completed_bytes: view.completed_bytes,
                }
            })
        }
        .unwrap()
    }
    #[test]
    fn dynamic_write_rights_preserve_original_request_and_exact_reached_prefix() {
        let backing = backing();
        let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
        let mut thread = domain.thread(Directed {
            deny_write: Some(GUEST_BASE + 16),
            ..Default::default()
        });
        let before = snapshot(&backing, STORAGE_BYTES);
        let mut bytes = [0x5a; 8];
        let fault = callback(
            &mut thread,
            MemoryRequest {
                address: GUEST_BASE + 13,
                data: bytes.as_mut_ptr(),
                bytes: 8,
                flags: flags::WRITE,
                pc: TEST_PC,
            },
        );
        assert_eq!(
            (fault.status, fault.address, fault.pc, fault.completed_bytes),
            (MemoryStatus::Permission, GUEST_BASE + 16, TEST_PC, 3)
        );
        let intent = DataRequest {
            address: GUEST_BASE + 13,
            bytes: 8,
            flags: flags::WRITE,
            pc: Some(TEST_PC),
            operation: DataOperation::Ordinary,
        };
        assert_eq!(thread.policy.checked, [intent]);
        assert_eq!(
            thread.policy.parts,
            (13..=16)
                .map(|offset| (
                    intent,
                    DataPart {
                        address: GUEST_BASE + offset,
                        bytes: 1,
                        kind: AccessKind::Write,
                    }
                ))
                .collect::<Vec<_>>()
        );
        let mut expected = before;
        expected[13..16].fill(0x5a);
        assert_eq!(snapshot(&backing, STORAGE_BYTES), expected);
    }
    #[test]
    fn cas_checks_dynamic_read_then_write_even_when_comparison_will_fail() {
        let backing = backing();
        let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
        let mut thread = domain.thread(Directed {
            deny_write: Some(GUEST_BASE),
            ..Default::default()
        });
        let before = snapshot(&backing, STORAGE_BYTES);
        let mut data = AtomicData {
            operation: AtomicOperation::CompareExchange as u32,
            compare: [1, 0],
            operand: [7, 0],
            ..Default::default()
        };
        let original = data;
        let fault = callback(
            &mut thread,
            MemoryRequest {
                address: GUEST_BASE,
                data: core::ptr::from_mut(&mut data).cast(),
                bytes: 8,
                flags: flags::ATOMIC | flags::WRITE,
                pc: TEST_PC,
            },
        );
        assert_eq!(
            (fault.status, fault.access, fault.completed_bytes),
            (MemoryStatus::Permission, FaultAccess::Write, 0)
        );
        assert_eq!(data, original);
        assert_eq!(snapshot(&backing, STORAGE_BYTES), before);
        assert_eq!(
            thread
                .policy
                .parts
                .iter()
                .map(|(request, part)| (request.operation, part.kind))
                .collect::<Vec<_>>(),
            [
                (DataOperation::Atomic, AccessKind::Read),
                (DataOperation::Atomic, AccessKind::Write)
            ]
        );
    }
    #[test]
    fn ordered_adaptation_retains_source_category_and_exclusive_direction() {
        let backing = backing();
        let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
        let mut thread = domain.thread(Directed::default());
        let events = crate::system::events::EventDomain::new();
        let endpoint = events.register(false, None).unwrap();
        thread.bind_events(&endpoint.producer()).unwrap();
        thread.check_event_endpoint(&endpoint).unwrap();
        let mut ordered = OrderedData {
            operation: OrderedOperation::Store as u32,
            order: MemoryOrder::Release as u32,
            value: [0x12, 0],
            ..Default::default()
        };
        let result = callback(
            &mut thread,
            MemoryRequest {
                address: GUEST_BASE,
                data: core::ptr::from_mut(&mut ordered).cast(),
                bytes: 8,
                flags: flags::ORDERED | flags::WRITE,
                pc: TEST_PC,
            },
        );
        assert_eq!(result.status, MemoryStatus::Success);
        let mut exclusive = ExclusiveData {
            operation: ExclusiveOperation::Load as u32,
            ..Default::default()
        };
        let result = callback(
            &mut thread,
            MemoryRequest {
                address: GUEST_BASE,
                data: core::ptr::from_mut(&mut exclusive).cast(),
                bytes: 8,
                flags: flags::EXCLUSIVE,
                pc: TEST_PC + 4,
            },
        );
        assert_eq!(result.status, MemoryStatus::Success);
        assert_eq!(exclusive.value, [0x12, 0]);
        exclusive = ExclusiveData {
            operation: ExclusiveOperation::Store as u32,
            value: [0x34, 0],
            ..Default::default()
        };
        let result = callback(
            &mut thread,
            MemoryRequest {
                address: GUEST_BASE,
                data: core::ptr::from_mut(&mut exclusive).cast(),
                bytes: 8,
                flags: flags::EXCLUSIVE | flags::WRITE,
                pc: TEST_PC + 8,
            },
        );
        assert_eq!(result.status, MemoryStatus::Success);
        assert_eq!(
            thread
                .policy
                .parts
                .iter()
                .map(|(request, part)| (request.operation, part.kind))
                .collect::<Vec<_>>(),
            [
                (DataOperation::Ordered, AccessKind::Write),
                (DataOperation::Exclusive, AccessKind::Read),
                (DataOperation::Exclusive, AccessKind::Write)
            ]
        );
        assert_eq!(
            thread
                .policy
                .checked
                .iter()
                .map(|request| request.pc)
                .collect::<Vec<_>>(),
            [Some(TEST_PC), Some(TEST_PC + 4), Some(TEST_PC + 8)]
        );
        assert_eq!(&snapshot(&backing, 8), &0x34u64.to_le_bytes());
    }
}

#[derive(Default)]
struct Policy {
    unavailable: bool,
    reject: Option<u64>,
    checked: Vec<(u64, usize)>,
    checked_flags: Vec<u32>,
}

impl DataPolicy for Policy {
    fn validate_execution(&self, _required_flags: u32) -> Result<(), MemoryStatus> {
        if self.unavailable {
            Err(MemoryStatus::Unsupported)
        } else {
            Ok(())
        }
    }
    fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus> {
        Ok(raw_address)
    }

    fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        self.checked.push((access.raw_address, access.bytes));
        self.checked_flags.push(access.flags);
        if self.reject == Some(access.raw_address) {
            Err(MemoryStatus::TagCheck)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct Outcome {
    status: u32,
    fault_kind: u32,
    fault_address: u64,
    fault_pc: u64,
    completed: u64,
}

fn invoke(
    thread: &mut MemoryThread<Policy>,
    address: u64,
    bytes: &mut [u8],
    flags: u32,
) -> Outcome {
    let request = MemoryRequest {
        address,
        data: bytes.as_mut_ptr(),
        bytes: bytes.len() as u32,
        flags,
        pc: TEST_PC,
    };
    // SAFETY: the synchronous callback receives valid ABI objects and private
    // staging disjoint from raw guest storage, with no retained pointers.
    unsafe {
        thread.with_view(|context| {
            let status = (context.callback)(context, &request);
            Outcome {
                status,
                fault_kind: context.fault_kind,
                fault_address: context.fault_address,
                fault_pc: context.fault_pc,
                completed: context.completed_bytes,
            }
        })
    }
}

fn snapshot(backing: &MemoryBacking, bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|offset| {
            let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
            // SAFETY: tests inspect after synchronous execution; no byte access
            // overlaps this exact live one-byte native read.
            unsafe { access::read_part(pointer.as_ptr(), 1, TargetCpu::Baseline) }.unwrap() as u8
        })
        .collect()
}

fn reservation_access(
    domain: &MemoryDomain,
    offset: u64,
) -> monitor::Access<MemoryBacking, MemoryView, MappingAttributes> {
    let registered = &domain.registered_views()[0];
    monitor::Access::new(
        Arc::clone(registered.view.backing()),
        Arc::clone(&registered.monitor),
        offset,
        1,
        monitor::Shape::Scalar,
    )
    .unwrap()
}
