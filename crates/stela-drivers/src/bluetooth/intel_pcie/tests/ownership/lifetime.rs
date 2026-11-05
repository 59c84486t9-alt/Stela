//! Payload/translation retirement precedes release; every failure is sticky.
use super::*;
#[test]
fn nonidentity_descriptors_use_iovas_and_close_retires_all_owners() {
    if crate::model_test_process::isolate() {
        return;
    }
    let root = Arc::new(RootState::default());
    let (mut t, counts) = owned(root.clone());
    assert!(!t.ready());
    let m = t.memory();
    let ci = &m.pool.bytes()[memory::CI..];
    assert_eq!(
        u64::from_le_bytes(ci[16..24].try_into().unwrap()),
        m.pool.bus_address() + memory::TR_HEAD as u64
    );
    assert_eq!(
        u64::from_le_bytes(ci[112..120].try_into().unwrap()),
        m.fragment.bus_address()
    );
    assert!(m.pool.bus_address() >= 0x2_0000_0000);
    assert_ne!(m.pool.bus_address(), m.pool.bytes().as_ptr() as u64);
    root.events.lock().unwrap().clear();
    t.close().unwrap();
    assert_eq!(t.state(), State::Closed);
    assert!(!t.ready());
    assert!(t.memory.is_none());
    assert_eq!(
        *root.events.lock().unwrap(),
        [
            "reset",
            "reset",
            "domain drain",
            "unmap",
            "unmap",
            "unmap",
            "unmap",
            "unmap",
            "detach",
            "register retire"
        ]
    );
    assert!(root.live.lock().unwrap().is_empty());
    assert!(root.bound.lock().unwrap().is_none());
    assert_eq!(root.pages_dropped.load(Ordering::Relaxed), 5);
    assert_eq!(root.bars_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 1);
    let events = root.events.lock().unwrap().clone();
    assert!(matches!(t.start(), Err(Error::State(State::Closed))));
    assert!(matches!(t.poll(), Err(Error::State(State::Closed))));
    assert!(matches!(
        t.send(Kind::Command, &[3, 12, 0]),
        Err(Error::State(State::Closed))
    ));
    assert!(matches!(t.enter_d0(), Err(Error::State(State::Closed))));
    t.close().unwrap();
    drop(t);
    assert_eq!(*root.events.lock().unwrap(), events);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 1);
}
#[test]
fn drain_unmap_detach_and_register_failures_keep_uncertain_owners() {
    if crate::model_test_process::isolate() {
        return;
    }
    for phase in ["domain drain", "unmap", "detach", "register retire"] {
        let root = Arc::new(RootState::default());
        let (mut t, counts) = owned(root.clone());
        root.events.lock().unwrap().clear();
        *root.fail.lock().unwrap() = Some(phase);
        let error = t.close().expect_err("injected retirement failure");
        let events = root.events.lock().unwrap().clone();
        *root.fail.lock().unwrap() = None;
        assert_eq!(t.close(), Err(error));
        assert_eq!(*root.events.lock().unwrap(), events);
        assert_eq!(events.last(), Some(&phase));
        assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
        if phase == "domain drain" || phase == "unmap" {
            assert_eq!(root.live.lock().unwrap().len(), 5);
            assert_eq!(root.pages_dropped.load(Ordering::Relaxed), 0);
        }
        if phase != "register retire" {
            assert!(root.bound.lock().unwrap().is_some());
            assert_eq!(root.bars_dropped.load(Ordering::Relaxed), 0);
        }
        drop(t);
        assert_eq!(*root.events.lock().unwrap(), events);
        assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn dropping_active_owner_performs_no_destructor_stop_or_release() {
    if crate::model_test_process::isolate() {
        return;
    }
    let root = Arc::new(RootState::default());
    let (t, counts) = owned(root.clone());
    root.events.lock().unwrap().clear();
    drop(t);
    assert!(root.events.lock().unwrap().is_empty());
    assert_eq!(root.live.lock().unwrap().len(), 5);
    assert_eq!(root.pages_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
}

#[test]
fn foreign_configuration_seal_refuses_before_domain_drain_or_buffer_release() {
    if crate::model_test_process::isolate() {
        return;
    }
    let root = Arc::new(RootState::default());
    let (mut inputs, counts) = owned_inputs(root.clone());
    let (foreign, _) = fixture(Address {
        segment: 0,
        bus: 2,
        device: 3,
        function: 0,
    });
    inputs.retention = foreign.retain_epoch().unwrap();
    // SAFETY: deliberately foreign model seal exercises refusal. It cannot
    // grant production permission and every resource has isolated RAM backing.
    let mut t = unsafe { Owned::new(inputs) }.unwrap_or_else(|f| panic!("{:?}", f.error));
    root.events.lock().unwrap().clear();
    assert_eq!(
        t.close(),
        Err(native::Error::Requirement("current original BT configuration epoch").into())
    );
    assert!(!root.events.lock().unwrap().contains(&"domain drain"));
    assert_eq!(root.live.lock().unwrap().len(), 5);
    assert_eq!(root.pages_dropped.load(Ordering::Relaxed), 0);
    drop(t);
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
}
#[test]
fn configuration_unmap_failure_retains_closed_owner_after_detach() {
    if crate::model_test_process::isolate() {
        return;
    }
    let root = Arc::new(RootState::default());
    let (mut t, counts) = owned(root.clone());
    *root.fail_config.lock().unwrap() = Some(counts.clone());
    let error = t.close().expect_err("config mapping context failure");
    assert_eq!(
        error,
        native::Error::Mapping(crate::bus::mmio::owned::Error::Unavailable).into()
    );
    assert!(root.live.lock().unwrap().is_empty());
    assert!(root.bound.lock().unwrap().is_none());
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
    counts.fail_context_at.store(0, Ordering::Relaxed);
    assert_eq!(t.close(), Err(error));
    drop(t);
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
}

#[test]
fn partial_constructor_failure_keeps_prior_dma_allocations_and_native_owners() {
    if crate::model_test_process::isolate() {
        return;
    }
    let root = Arc::new(RootState::default());
    let (inputs, counts) = owned_inputs(root.clone());
    root.fail_map_at.store(3, Ordering::Relaxed);
    // SAFETY: same isolated fixture ownership; the third mapping fails before
    // publication and the first two must remain with their allocation owner.
    let failure = unsafe { Owned::new(inputs) }
        .err()
        .expect("third map failed");
    assert_eq!(root.live.lock().unwrap().len(), 2);
    assert_eq!(root.pages_dropped.load(Ordering::Relaxed), 1);
    drop(failure);
    assert_eq!(root.live.lock().unwrap().len(), 2);
    assert_eq!(root.pages_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
}

#[test]
fn failed_engine_stop_keeps_dma_and_original_native_graph() {
    if crate::model_test_process::isolate() {
        return;
    }
    let root = Arc::new(RootState::default());
    let (mut t, counts) = owned(root.clone());
    root.events.lock().unwrap().clear();
    root.fail_device_stop.store(true, Ordering::Relaxed);
    let error = t.close().expect_err("missing disconnect ACK");
    assert_eq!(t.state(), State::Failed);
    assert!(!root.events.lock().unwrap().contains(&"domain drain"));
    root.fail_device_stop.store(false, Ordering::Relaxed);
    assert_eq!(t.close(), Err(error));
    drop(t);
    assert_eq!(root.live.lock().unwrap().len(), 5);
    assert_eq!(root.pages_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
}

#[test]
fn core_and_post_core_unwind_never_reopen_owned_transport_or_retry_effects() {
    if crate::model_test_process::isolate() {
        return;
    }
    for (phase, nth) in [
        ("reset", 1),
        ("domain drain", 1),
        ("unmap", 2),
        ("detach", 1),
        ("register retire", 1),
    ] {
        let root = Arc::new(RootState::default());
        let (mut transport, counts) = owned(root.clone());
        root.events.lock().unwrap().clear();
        *root.panic_phase.lock().unwrap() = Some(phase);
        root.panic_nth.store(nth, Ordering::Relaxed);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| transport.close())).is_err(),
            "{phase}"
        );
        *root.panic_phase.lock().unwrap() = None;
        let events = root.events.lock().unwrap().clone();
        let unmaps = counts.unmaps.load(Ordering::Relaxed);
        let error = Error::Unsupported("interrupted owned Intel PCIe retirement");
        assert_eq!(transport.start(), Err(error.clone()));
        assert_eq!(transport.poll(), Err(error.clone()));
        assert_eq!(
            transport.send(Kind::Command, &[3, 12, 0]),
            Err(error.clone())
        );
        assert_eq!(transport.enter_d0(), Err(error.clone()));
        assert!(!transport.ready());
        assert!(
            transport
                .initialize_firmware(
                    &super::super::NeverFirmware,
                    crate::bluetooth::intel::PlatformInputs::default()
                )
                .is_err()
        );
        assert_eq!(transport.close(), Err(error));
        drop(transport);
        assert_eq!(*root.events.lock().unwrap(), events, "{phase}");
        assert_eq!(counts.unmaps.load(Ordering::Relaxed), unmaps, "{phase}");
        assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0, "{phase}");
    }
}
