use super::*;

use stela_compiler::context::memory::{
    MemoryOperationClass, MemoryOrder,
    exclusive::{EXCLUSIVE_FAILED, ExclusiveData, ExclusiveOperation, ExclusiveShape},
};

#[derive(Default)]
struct ExclusivePolicy {
    unavailable: bool,
    reject_tag: bool,
    checked: usize,
    validated: Option<std::sync::mpsc::Sender<()>>,
    block: Option<(std::sync::mpsc::Sender<()>, Arc<std::sync::Barrier>)>,
}

impl DataPolicy for ExclusivePolicy {
    fn validate_operation_execution(
        &self,
        class: MemoryOperationClass,
    ) -> Result<(), MemoryStatus> {
        if !self.unavailable && class == MemoryOperationClass::Exclusive {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        }
    }
    fn validate_execution(&self, required: u32) -> Result<(), MemoryStatus> {
        if let Some(validated) = &self.validated {
            validated.send(()).unwrap();
        }
        if required & !flags::KNOWN == 0 {
            Ok(())
        } else {
            Err(MemoryStatus::InvalidRequest)
        }
    }
    fn translate(&self, raw: u64) -> Result<u64, MemoryStatus> {
        Ok(raw)
    }
    fn check(&mut self, _access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        self.checked += 1;
        if let Some((entered, release)) = self.block.take() {
            entered.send(()).unwrap();
            release.wait();
        }
        if self.reject_tag {
            Err(MemoryStatus::TagCheck)
        } else {
            Ok(())
        }
    }
}

fn exclusive_bound(
    domain: &Arc<MemoryDomain>,
) -> (
    MemoryThread<ExclusivePolicy>,
    crate::system::events::EventEndpoint,
    crate::system::events::EventDomain,
) {
    let events = crate::system::events::EventDomain::new();
    let endpoint = events.register(false, None).unwrap();
    let mut thread = domain.thread(ExclusivePolicy::default());
    thread.bind_events(&endpoint.producer()).unwrap();
    thread.check_event_endpoint(&endpoint).unwrap();
    (thread, endpoint, events)
}

fn exclusive_data(op: ExclusiveOperation, shape: ExclusiveShape, value: u128) -> ExclusiveData {
    ExclusiveData {
        operation: op as u32,
        order: MemoryOrder::Relaxed as u32,
        shape: shape as u32,
        status: 0,
        value: [value as u64, (value >> u64::BITS) as u64],
    }
}

fn exclusive_invoke(
    thread: &mut MemoryThread<ExclusivePolicy>,
    address: u64,
    bytes: u32,
    data: &mut ExclusiveData,
    extra: u32,
) -> (MemoryStatus, u64, u64, u64) {
    let request = MemoryRequest {
        address,
        data: std::ptr::from_mut(data).cast(),
        bytes,
        flags: flags::EXCLUSIVE | extra,
        pc: TEST_PC,
    };
    let mut observed = (MemoryStatus::Success, 0, address, TEST_PC);
    // SAFETY: an aligned private payload and valid disjoint ABI objects; the
    // fixture keeps stable coherent storage and the bound PE.
    let finalized = unsafe {
        thread.with_checked_view(|view| {
            let status = (view.callback)(view, &request);
            observed = (
                MemoryStatus::from_code(status).unwrap(),
                view.completed_bytes,
                view.fault_address,
                view.fault_pc,
            );
            observed
        })
    };
    match finalized {
        Ok(result) => result,
        Err(status) => (status, observed.1, observed.2, observed.3),
    }
}

fn exclusive_wait(
    endpoint: &mut crate::system::events::EventEndpoint,
    events: &crate::system::events::EventDomain,
) -> bool {
    use crate::system::access::{ExceptionLevel, Profile, SecurityState};
    use crate::system::events::{Context, EventInstruction, Outcome, RetireReason};
    let context = Context::new(
        Profile {
            current_el: ExceptionLevel::El0,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        true,  // wfxt
        false, // twed
        false, // halted
        false, // n_twe
        false, // n_twi
    )
    .unwrap();
    let instruction =
        EventInstruction::decode(0xd503_205f, TEST_PC, &stela_compiler::GuestState::default())
            .unwrap();
    match endpoint
        .complete(
            events,
            instruction,
            context,
            false,
            || -> Result<u64, ()> { panic!("untimed WFE") },
        )
        .unwrap()
    {
        Outcome::Retired {
            reason: RetireReason::EventConsumed,
            ..
        } => true,
        Outcome::Trap(_) => false,
        other => panic!("unexpected WFE {other:?}"),
    }
}

#[test]
fn exclusive_service_layout_and_complete_25_matrix_reject_malformed_payloads() {
    use std::mem::{align_of, offset_of, size_of};
    use stela_compiler::context::memory::exclusive::*;
    assert_eq!(size_of::<ExclusiveData>(), EXCLUSIVE_DATA_BYTES);
    assert_eq!(align_of::<ExclusiveData>(), EXCLUSIVE_DATA_ALIGNMENT);
    assert_eq!(
        [
            offset_of!(ExclusiveData, operation),
            offset_of!(ExclusiveData, order),
            offset_of!(ExclusiveData, shape),
            offset_of!(ExclusiveData, status),
            offset_of!(ExclusiveData, value)
        ],
        [0, 4, 8, 12, 16]
    );
    let mut count = 0;
    for op in [
        ExclusiveOperation::Load,
        ExclusiveOperation::Store,
        ExclusiveOperation::Clear,
    ] {
        for shape in [ExclusiveShape::Scalar, ExclusiveShape::Pair] {
            for bytes in [0, 1, 2, 4, 8, 16, 32] {
                for order in [
                    MemoryOrder::Relaxed,
                    MemoryOrder::AcquireRcpc,
                    MemoryOrder::AcquireRcsc,
                    MemoryOrder::Release,
                    MemoryOrder::AcquireRelease,
                ] {
                    let mut data = exclusive_data(op, shape, 0);
                    data.order = order as u32;
                    let expected = if op == ExclusiveOperation::Clear {
                        bytes == 0
                            && shape == ExclusiveShape::Scalar
                            && order == MemoryOrder::Relaxed
                    } else {
                        shape.supports_width(bytes)
                            && match op {
                                ExclusiveOperation::Load => {
                                    matches!(order, MemoryOrder::Relaxed | MemoryOrder::AcquireRcsc)
                                }
                                ExclusiveOperation::Store => {
                                    matches!(order, MemoryOrder::Relaxed | MemoryOrder::Release)
                                }
                                _ => false,
                            }
                    };
                    assert_eq!(data.validate(bytes).is_some(), expected);
                    count += usize::from(expected);
                }
            }
        }
    }
    assert_eq!(count, 25);
    for field in 0..6 {
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        match field {
            0 => data.operation = u32::MAX,
            1 => data.order = u32::MAX,
            2 => data.shape = u32::MAX,
            3 => data.status = 1,
            4 => data.value[0] = 1,
            _ => data.value[1] = 1,
        }
        assert!(data.validate(4).is_none());
    }
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        1_u128 << 32,
    );
    assert!(store.validate(4).is_none());
    store.value = [0, 1];
    assert!(store.validate(8).is_none());
}

#[test]
fn exclusive_service_width4_load_store_clear_and_failed_store_are_real() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let (mut thread, mut endpoint, events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        0xaabbccdd,
    );
    store.order = MemoryOrder::Release as u32;
    let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
    assert_eq!(
        (result.0, result.1, store.status),
        (MemoryStatus::Success, 4, 0)
    );
    assert_eq!(&snapshot(&backing, 4), &0xaabbccdd_u32.to_le_bytes());
    assert!(exclusive_wait(&mut endpoint, &events));
    assert!(!exclusive_wait(&mut endpoint, &events));
    load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    load.order = MemoryOrder::AcquireRcsc as u32;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert_eq!(load.value, [0xaabbccdd, 0]);
    let mut clear = exclusive_data(ExclusiveOperation::Clear, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, 0, 0, &mut clear, 0).0,
        MemoryStatus::Success
    );
    assert!(!endpoint.is_set()); // local-only clear preserves the independent global mark.
    let checks = thread.policy.checked;
    store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        0x12345678,
    );
    let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
    assert_eq!(
        (result.0, result.1, store.status),
        (MemoryStatus::Success, 0, EXCLUSIVE_FAILED)
    );
    assert_eq!(thread.policy.checked, checks);
    assert!(endpoint.is_set());
    assert_eq!(&snapshot(&backing, 4), &0xaabbccdd_u32.to_le_bytes());
}

#[test]
fn exclusive_service_shared_same_value_aba_publication_invalidates_without_extra_owner() {
    let backing = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let first = MemoryDomain::new(
        system.clone(),
        vec![(view(&backing, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
        TargetCpu::detect(),
    )
    .unwrap();
    let alias = MemoryView::new(
        backing.clone(),
        GUEST_BASE + 0x1000,
        0,
        STORAGE_BYTES,
        RIGHTS,
    )
    .unwrap();
    let second = MemoryDomain::new(
        system.clone(),
        vec![(alias, ATTRIBUTES)],
        TargetCpu::detect(),
    )
    .unwrap();
    let (mut thread, mut endpoint, events) = exclusive_bound(&first);
    for values in [&[0_u8; 4][..], &[1_u8; 4][..], &[0_u8; 4][..]] {
        let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        assert_eq!(
            exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
            MemoryStatus::Success
        );
        // SAFETY: source is disjoint private bytes and the shared system owns the retained raw backing.
        unsafe { system.publish(&backing, 0, values) }.unwrap();
        assert!(exclusive_wait(&mut endpoint, &events));
        let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 9);
        let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
        assert_eq!(
            (result.0, result.1, store.status),
            (MemoryStatus::Success, 0, 1)
        );
    }
    let mut ordinary = second.thread(Policy::default());
    let mut data = [0x73; 4];
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert_eq!(
        invoke(&mut ordinary, GUEST_BASE + 0x1000, &mut data, flags::WRITE).status,
        MemoryStatus::Success as u32
    );
    let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE).0,
        MemoryStatus::Success
    );
    assert_eq!(store.status, 1);
}

#[test]
fn exclusive_service_pair8_packed_and_store_guest_write_only_are_supported() {
    let backing = backing();
    let alias = MemoryView::new(
        backing.clone(),
        GUEST_BASE + 0x1000,
        0,
        STORAGE_BYTES,
        AccessPermissions {
            readable: false,
            ..RIGHTS
        },
    )
    .unwrap();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS), alias]);
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Pair, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 8, &mut load, 0).0,
        MemoryStatus::Success
    );
    let value = 0x89abcdef01234567_u64;
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Pair,
        u128::from(value),
    );
    assert_eq!(
        exclusive_invoke(
            &mut thread,
            GUEST_BASE + 0x1000,
            8,
            &mut store,
            flags::WRITE
        )
        .0,
        MemoryStatus::Success
    );
    assert_eq!(store.status, 0);
    assert_eq!(&snapshot(&backing, 8), &value.to_le_bytes());
    load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Pair, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 8, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert_eq!(load.value, [value, 0]);
}

#[test]
fn exclusive_service_faults_and_declines_preserve_all_payload_bytes() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    for (address, flags, expected) in [
        (GUEST_BASE + 15, 0, MemoryStatus::Alignment),
        (GUEST_BASE + 0x4000, 0, MemoryStatus::Translation),
        (GUEST_BASE, flags::PAIR, MemoryStatus::InvalidRequest),
        (GUEST_BASE, flags::ATOMIC, MemoryStatus::InvalidRequest),
        (GUEST_BASE, flags::ORDERED, MemoryStatus::InvalidRequest),
    ] {
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        let before = data;
        let result = exclusive_invoke(&mut thread, address, 4, &mut data, flags);
        assert_eq!(
            (result.0, result.1, result.2, result.3),
            (expected, 0, address, TEST_PC)
        );
        assert_eq!(data, before);
    }
    thread.policy.unavailable = true;
    let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    let before = data;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
        MemoryStatus::Unsupported
    );
    assert_eq!(data, before);
    let req = MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_flags: flags::EXCLUSIVE,
        required_host_caps: 0,
        required_profile: stela_compiler::context::memory::profile_requirements::NATIVE_ACCESS,
        required_sp_alignment: SpAlignmentRequirement::Any,
        ..MemoryRequirements::default()
    };
    assert!(thread.prepare(req).is_err());
    thread.policy.unavailable = false;
    thread.policy.reject_tag = true;
    let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    let before = data;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, flags::TAG_CHECKED).0,
        MemoryStatus::TagCheck
    );
    assert_eq!(data, before);
    thread.policy.reject_tag = false;
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    thread.policy.reject_tag = true;
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        0xdeadbeef,
    );
    let before = store;
    assert_eq!(
        exclusive_invoke(
            &mut thread,
            GUEST_BASE,
            4,
            &mut store,
            flags::WRITE | flags::TAG_CHECKED
        )
        .0,
        MemoryStatus::TagCheck
    );
    assert_eq!(store, before);
    assert_eq!(snapshot(&backing, 4), [0; 4]);
    thread.policy.reject_tag = false;
    let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 9);
    let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
    assert_eq!(
        (result.0, result.1, store.status),
        (MemoryStatus::Success, 0, 1)
    );
    domain.system.failed.store(true, Ordering::Release);
    let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    let before = data;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
        MemoryStatus::Domain
    );
    assert_eq!(data, before);
}

fn exclusive_joined() -> (Arc<MemoryBacking>, Arc<MemoryDomain>, Arc<MemoryView>) {
    let backing = backing();
    let second = view(&backing, 2, STORAGE_BYTES - 2, RIGHTS);
    let alias = MemoryView::new(
        backing.clone(),
        GUEST_BASE + 0x1000,
        0,
        STORAGE_BYTES,
        RIGHTS,
    )
    .unwrap();
    let domain = domain(vec![view(&backing, 0, 2, RIGHTS), second.clone(), alias]);
    (backing, domain, second)
}

#[test]
fn exclusive_service_second_view_retirement_and_mapdead_gap_clear_actual_global_mark() {
    let (backing, domain, second) = exclusive_joined();
    let (mut thread, mut endpoint, events) = exclusive_bound(&domain);
    // The mapping is dead but its first-generation view is live, so the load
    // must be caught by the final retirement invalidation.
    domain
        .system
        .reservations
        .revoke_mapping(&domain.registered_views()[1].monitor)
        .unwrap();
    assert!(second.is_current());
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert!(!endpoint.is_set());
    domain.retire(&second).unwrap();
    assert!(exclusive_wait(&mut endpoint, &events));
    let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 7);
    assert_eq!(
        exclusive_invoke(
            &mut thread,
            GUEST_BASE + 0x1000,
            4,
            &mut store,
            flags::WRITE
        )
        .0,
        MemoryStatus::Success
    );
    assert_eq!(store.status, 1);
    assert_eq!(snapshot(&backing, 4), [0; 4]);
    load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE + 0x1000, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert_eq!(domain.retire(&second), Err(MemoryStatus::InvalidRequest));
    assert!(!endpoint.is_set());
    store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 7);
    assert_eq!(
        exclusive_invoke(
            &mut thread,
            GUEST_BASE + 0x1000,
            4,
            &mut store,
            flags::WRITE
        )
        .0,
        MemoryStatus::Success
    );
    assert_eq!(store.status, 0);
    assert_eq!(&snapshot(&backing, 4), &7_u32.to_le_bytes());
}

#[test]
fn exclusive_service_stale_second_view_is_rechecked_inside_gate() {
    let (backing, domain, second) = exclusive_joined();
    let physical = domain.resolve(GUEST_BASE, 4, AccessKind::Read).unwrap();
    let access = monitor::Access::new(
        backing,
        domain.registered_views()[0].monitor.clone(),
        0,
        4,
        monitor::Shape::Scalar,
    )
    .unwrap();
    domain.retire(&second).unwrap();
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    let mut native = false;
    let result = domain.system.reservations.load_with_scope(
        &mut thread.reservation,
        &access,
        monitor::ReservationScope::Global,
        || {
            physical.check_current()?;
            native = true;
            Ok::<_, MemoryStatus>(())
        },
    );
    assert_eq!(
        result,
        Err(monitor::AccessError::Memory(MemoryStatus::Domain))
    );
    assert!(!native);
}

#[test]
fn exclusive_service_inflight_load_refuses_retirement_until_original_finalization() {
    let (backing, domain, second) = exclusive_joined();
    let monitor = domain
        .registered_views()
        .into_iter()
        .find(|registered| Arc::ptr_eq(&registered.view, &second))
        .unwrap()
        .monitor;
    let generation = domain.generation().unwrap();
    let (mut thread, endpoint, events) = exclusive_bound(&domain);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new(std::sync::Barrier::new(2));
    thread.policy.block = Some((entered_tx, release.clone()));
    let load = std::thread::spawn(move || {
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0);
        (thread, endpoint, events, result)
    });
    entered_rx.recv().unwrap();
    let d = domain.clone();
    let retiring = second.clone();
    let (refusal_tx, refusal_rx) = std::sync::mpsc::channel();
    let retire = std::thread::spawn(move || {
        refusal_tx.send(d.retire(&retiring)).unwrap();
    });
    // The native borrow is still live inside the blocked callback, so service
    // admission must refuse instead of waiting on the callback's monitor gate.
    let refusal = refusal_rx.recv_timeout(std::time::Duration::from_secs(2));
    // Always release and join the load before asserting, even if a broken
    // retirement path waited on the gate.
    release.wait();
    let (mut thread, mut endpoint, events, result) = load.join().unwrap();
    retire.join().unwrap();
    assert_eq!(result.0, MemoryStatus::Success);
    assert_eq!(refusal.unwrap(), Err(MemoryStatus::Domain));
    assert!(second.is_current());
    assert!(monitor.is_live());
    assert_eq!(domain.generation().unwrap(), generation);
    assert!(!endpoint.is_set());
    // Finalization released the borrow, so the domain may now retire the view
    // and invalidate the alias reservation.
    domain.retire(&second).unwrap();
    assert!(!second.is_current());
    assert!(!monitor.is_live());
    assert_eq!(domain.generation().unwrap(), generation + 1);
    assert!(exclusive_wait(&mut endpoint, &events));
    assert!(!exclusive_wait(&mut endpoint, &events));
    let mut data = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 1);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE + 0x1000, 4, &mut data, flags::WRITE).0,
        MemoryStatus::Success
    );
    assert_eq!(data.status, 1);
    assert_eq!(snapshot(&backing, 4), [0; 4]);
}

#[test]
fn exclusive_service_contended_width4_has_one_actual_native_winner() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut joins = Vec::new();
    for value in [0x12345678_u128, 0x87654321] {
        let (mut thread, endpoint, events) = exclusive_bound(&domain);
        let barrier = barrier.clone();
        joins.push(std::thread::spawn(move || {
            let _owners = (endpoint, events);
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            barrier.wait();
            let mut store =
                exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, value);
            let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
            assert_eq!(result.0, MemoryStatus::Success);
            store.status
        }));
    }
    let statuses = joins
        .into_iter()
        .map(|j| j.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(statuses.iter().filter(|&&s| s == 0).count(), 1);
    let value = u32::from_le_bytes(snapshot(&backing, 4).try_into().unwrap());
    assert!([0x12345678, 0x87654321].contains(&value));
}

#[test]
fn exclusive_service_permission_and_raw_payload_fail_before_any_effect() {
    let backing = backing();
    let denied = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, denied)]);
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        0xfeedbeef,
    );
    let before = store;
    let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
    assert_eq!((result.0, result.1), (MemoryStatus::Permission, 0));
    assert_eq!(store, before);
    assert_eq!(thread.policy.checked, 0);
    for index in 0..6 {
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        match index {
            0 => data.operation = u32::MAX,
            1 => data.order = u32::MAX,
            2 => data.shape = u32::MAX,
            3 => data.status = 1,
            4 => data.value[0] = 1,
            _ => data.value[1] = 1,
        }
        let before = data;
        assert_eq!(
            exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
            MemoryStatus::InvalidRequest
        );
        assert_eq!(data, before);
    }
    let mut clear = exclusive_data(ExclusiveOperation::Clear, ExclusiveShape::Scalar, 0);
    let before = clear;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 0, &mut clear, 0).0,
        MemoryStatus::InvalidRequest
    );
    assert_eq!(clear, before);
    assert_eq!(snapshot(&backing, STORAGE_BYTES), vec![0; STORAGE_BYTES]);
}

#[test]
fn exclusive_service_poisoned_domain_refuses_retirement_before_mapping_effects() {
    let (backing, domain, second) = exclusive_joined();
    let monitor = domain
        .registered_views()
        .into_iter()
        .find(|registered| Arc::ptr_eq(&registered.view, &second))
        .unwrap()
        .monitor;
    let generation = domain.generation().unwrap();
    let (mut thread, endpoint, _events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert!(!endpoint.is_set());
    let before = snapshot(&backing, 4);
    domain.system.failed.store(true, Ordering::Release);
    assert_eq!(domain.retire(&second), Err(MemoryStatus::Domain));
    assert!(second.is_current());
    assert!(monitor.is_live());
    assert_eq!(domain.state.lock().unwrap().snapshot.generation, generation);
    assert!(!endpoint.is_set());
    assert_eq!(domain.retire(&second), Err(MemoryStatus::Domain));
    // A failed domain admits neither native execution nor service mutation, and
    // keeps its storage.
    assert!(domain.check_execution().is_err());
    assert!(domain.execution_loan().is_err());
    let mut declined = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    let untouched = declined;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut declined, 0).0,
        MemoryStatus::Domain
    );
    assert_eq!(declined, untouched);
    assert_eq!(snapshot(&backing, 4), before);
    assert!(!endpoint.is_set());
}

#[test]
fn exclusive_service_shifted_relative_erg_geometry_declines_before_prefix_only_for_transfers() {
    let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
    // SAFETY: the owner keeps the whole allocation, including the prefix.
    let raw = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let owner = Arc::new(Storage {
        pointer: raw,
        layout,
    });
    // SAFETY: shifted extent is live inside the real allocation and lifetime owner.
    let physical = unsafe {
        MemoryBacking::new(
            NonNull::new(raw.as_ptr().add(8)).unwrap(),
            STORAGE_BYTES - 8,
            RIGHTS,
            owner,
        )
    }
    .unwrap();
    let mapping = MemoryView::new(physical, GUEST_BASE + 8, 0, STORAGE_BYTES - 8, RIGHTS).unwrap();
    let domain = domain(vec![mapping]);
    let mut thread = domain.thread(ExclusivePolicy::default());
    let req = MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_flags: flags::EXCLUSIVE,
        required_host_caps: 0,
        required_profile: stela_compiler::context::memory::profile_requirements::NATIVE_ACCESS,
        required_sp_alignment: SpAlignmentRequirement::Any,
        ..MemoryRequirements::default()
    };
    assert!(matches!(
        thread.prepare(req),
        Err(MemoryStatus::Unsupported)
    ));
    let ordinary = MemoryRequirements {
        required_flags: 0,
        ..req
    };
    assert!(thread.prepare(ordinary).is_ok());
    let clear = MemoryRequirements {
        required_profile: 0,
        ..req
    };
    assert!(thread.prepare(clear).is_ok());
    assert_eq!(thread.policy.checked, 0);
}

#[test]
fn exclusive_service_callback_fault_late_failure_cannot_escape_checked_finalization() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let (mut thread, endpoint, events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let release = Arc::new(std::sync::Barrier::new(2));
    let d = domain.clone();
    let release_writer = release.clone();
    let b = backing.clone();
    let writer = std::thread::spawn(move || {
        let range = monitor::WriteRange::new(b, 0, 4).unwrap();
        d.system
            .reservations
            .with_writer(&range, monitor::Invalidation::OnCommit, || {
                held_tx.send(()).unwrap();
                release_writer.wait();
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
    });
    held_rx.recv().unwrap();
    let (validated_tx, validated_rx) = std::sync::mpsc::channel();
    thread.policy.validated = Some(validated_tx);
    let fault = std::thread::spawn(move || {
        let _owners = (endpoint, events);
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        let before = data;
        let result = exclusive_invoke(&mut thread, GUEST_BASE + 15, 4, &mut data, 0);
        (result, data, before)
    });
    // Failure becomes visible after the callback's initial owner health check,
    // while the old reservation's cleanup is behind the real writer gate.
    validated_rx.recv().unwrap();
    domain.system.failed.store(true, Ordering::Release);
    release.wait();
    writer.join().unwrap();
    let (result, data, before) = fault.join().unwrap();
    assert_eq!(
        (result.0, result.1, result.2, result.3),
        (MemoryStatus::Domain, 0, GUEST_BASE + 15, TEST_PC)
    );
    assert_eq!(data, before);
    assert_eq!(snapshot(&backing, 4), [0; 4]);
}

#[test]
fn exclusive_service_local_sp_fault_finalization_failure_discards_callback_result() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    let mut original = None;
    // SAFETY: this source-bound local-emitter analogue writes only diagnostic
    // fields; it does not invoke native code or lend guest RAM references.
    let result = unsafe {
        thread.with_checked_view(|view| {
            view.record(MemoryStatus::StackAlignment, GUEST_BASE + 1, TEST_PC, 0);
            original = Some((
                view.fault_kind,
                view.fault_address,
                view.fault_pc,
                view.completed_bytes,
            ));
            domain.system.failed.store(true, Ordering::Release);
            42_u32
        })
    };
    assert_eq!(result, Err(MemoryStatus::Domain));
    assert_eq!(
        original,
        Some((
            MemoryStatus::StackAlignment as u32,
            GUEST_BASE + 1,
            TEST_PC,
            0
        ))
    );
    assert_eq!(snapshot(&backing, 4), [0; 4]);
}

#[test]
fn exclusive_service_dedicated_tag_entry_cannot_bypass_typed_class_preflight() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let controls = crate::memory::policy::MemoryControls::new(
        crate::memory::policy::LowerAddressProfile::new(48, false).unwrap(),
        false,
        false,
        false,
        crate::memory::policy::TagCheckFaultMode::Ignore,
        false,
    );
    let mut thread = domain.thread(controls);
    for class in [
        flags::ATOMIC,
        flags::ORDERED,
        flags::EXCLUSIVE,
        flags::ATOMIC | flags::ORDERED | flags::EXCLUSIVE,
    ] {
        let req = MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: class,
            required_host_caps: 0,
            required_profile: 0,
            required_sp_alignment: SpAlignmentRequirement::Any,
            ..MemoryRequirements::default()
        };
        assert!(matches!(
            thread.prepare_tag(req, false),
            Err(MemoryStatus::InvalidRequest)
        ));
    }
}
