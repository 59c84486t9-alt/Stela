//! Original-root sequencing and failure retention before private DMA admission.
use super::*;
#[test]
fn reset_and_original_drain_precede_private_binding() {
    if crate::model_test_process::isolate() {
        return;
    }
    let root = Arc::new(RootState::default());
    let (cold, counts) = cold(root.clone());
    let mut bound = cold
        .quiesce_and_bind()
        .unwrap_or_else(|f| panic!("{:?}", f.error));
    assert_eq!(
        *root.events.lock().unwrap(),
        ["reset", "original drain", "bind"]
    );
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
    // Keep the actual configuration owner through the attachment's detach.
    // A temporary Function here would quarantine its mapping after this read.
    let mut function = bound.requester.into_function();
    assert_eq!(function.config().read16(4) & 0x406, 0x402);
    // SAFETY: this model admits no mappings or asynchronous users.
    unsafe { bound.attachment.detach() }.unwrap();
    drop(bound.registers);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 1);
}
#[test]
fn abandoned_preparation_keeps_original_graph() {
    if crate::model_test_process::isolate() {
        return;
    }
    let root = Arc::new(RootState::default());
    let (cold, counts) = cold(root.clone());
    drop(cold);
    assert!(root.events.lock().unwrap().is_empty());
    assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
}
#[test]
fn failed_device_stop_or_boot_ack_never_reaches_root() {
    if crate::model_test_process::isolate() {
        return;
    }
    for no_stop in [false, true] {
        let root = Arc::new(RootState::default());
        let (requester, counts) = preparing(root.clone());
        let registers = Registers::new(root.clone());
        {
            let mut m = registers.model.lock().unwrap();
            m.stop_ack = !no_stop;
            m.reset_ack = no_stop;
            m.regs.insert(BOOT, 7);
        }
        // SAFETY: synchronous exclusively owned model, deliberately missing ACK.
        let cold = unsafe {
            native::cold::Cold::new(native::cold::Inputs {
                requester,
                registers,
                clock: CLOCK,
            })
        }
        .unwrap_or_else(|_| panic!("cold inputs"));
        let failure = cold.quiesce_and_bind().err().expect("device refused");
        assert!(matches!(
            failure.error,
            Error::Timeout(_) | Error::Protocol { .. }
        ));
        drop(failure);
        assert!(
            !root
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|e| ["original drain", "bind"].contains(e))
        );
        assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn failed_original_drain_or_bind_retains_registers_and_configuration() {
    if crate::model_test_process::isolate() {
        return;
    }
    for phase in ["original drain", "bind"] {
        let root = Arc::new(RootState::default());
        *root.fail.lock().unwrap() = Some(phase);
        let (cold, counts) = cold(root.clone());
        drop(cold.quiesce_and_bind().err().expect("root failure"));
        let expected = if phase == "bind" {
            vec!["reset", "original drain", "bind"]
        } else {
            vec!["reset", "original drain"]
        };
        assert_eq!(*root.events.lock().unwrap(), expected);
        assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn invalid_clock_or_bar_refuses_before_writes() {
    if crate::model_test_process::isolate() {
        return;
    }
    for bad_clock in [false, true] {
        let root = Arc::new(RootState::default());
        let (mut requester, _) = preparing(root.clone());
        if !bad_clock {
            requester.function_mut().config().write32(0x10, 0x2000_0000);
        }
        let clock = if bad_clock {
            crate::Clock {
                ticks_per_microsecond: 0,
            }
        } else {
            CLOCK
        };
        // SAFETY: invalid symbolic inputs cannot grant native permission.
        let (_, inputs) = unsafe {
            native::cold::Cold::new(native::cold::Inputs {
                requester,
                registers: Registers::new(root.clone()),
                clock,
            })
        }
        .err()
        .expect("invalid inputs");
        assert!(inputs.registers.model.lock().unwrap().writes.is_empty());
        assert!(root.events.lock().unwrap().is_empty());
    }
}

#[test]
fn register_read_or_effect_then_store_errors_refuse_root_transition() {
    if crate::model_test_process::isolate() {
        return;
    }
    for read_failure in [false, true] {
        let root = Arc::new(RootState::default());
        let (requester, counts) = preparing(root.clone());
        let registers = Registers::new(root.clone());
        {
            let mut m = registers.model.lock().unwrap();
            if read_failure {
                m.read_error = Some(BOOT);
            } else {
                m.write_error = Some((HW_MASK, 1));
            }
        }
        // SAFETY: exclusively owned synchronous model with injected MMIO failure.
        let cold = unsafe {
            native::cold::Cold::new(native::cold::Inputs {
                requester,
                registers,
                clock: CLOCK,
            })
        }
        .unwrap_or_else(|_| panic!("model inputs"));
        let failure = cold.quiesce_and_bind().err().expect("register failure");
        assert!(matches!(failure.error, Error::Native(_)));
        drop(failure);
        assert!(!root.events.lock().unwrap().contains(&"original drain"));
        assert_eq!(root.registers_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
    }
}
