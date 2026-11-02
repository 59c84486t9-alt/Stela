//! Faults pass through the same FIFO engine and original register/time owners.
use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};

mod peer;
use peer::*;
mod shutdown;

#[test]
fn every_constructor_register_frontier_keeps_exact_pending_call_and_both_owners() {
    let (baseline, control, _) = engine();
    let expected = control.borrow().attempts.clone();
    drop(baseline.shutdown().unwrap());
    assert_eq!(
        control.borrow().drops,
        3,
        "acknowledged shutdown returns the original providers"
    );
    for index in 1..=expected.len() {
        for mode in [
            Mode::Before,
            Mode::After,
            Mode::PanicBefore,
            Mode::PanicAfter,
        ] {
            let control = Rc::new(RefCell::new(Control::new()));
            control.borrow_mut().cut = Some(index);
            control.borrow_mut().mode = mode;
            let (registers, timer, _) = providers(&control);
            let result = catch_unwind(AssertUnwindSafe(|| {
                DesignWare::new(registers, timer, config())
            }));
            if mode.panics() {
                assert!(result.is_err());
            } else {
                let failure = result.unwrap().err().unwrap();
                assert_eq!(failure.error, ErrorKind::Access(cause()).into());
                let progress = failure.progress();
                assert_eq!(progress.accepted, (index - 1) as u64);
                assert_eq!(progress.pending, Some(expected[index - 1]));
            }
            let control = control.borrow();
            assert_eq!(control.attempts, expected[..index]);
            assert_eq!(control.effects.len(), index - usize::from(!mode.after()));
            assert_eq!(
                control.drops, 0,
                "failure/unwind is not provider retirement"
            );
        }
    }
}

#[test]
fn transaction_access_denial_and_unwind_allow_no_later_cleanup_or_shutdown_io() {
    let (mut baseline, control, _) = engine();
    let begin = control.borrow().attempts.len();
    transfer(&mut baseline).unwrap();
    let count = control.borrow().attempts.len() - begin;
    drop(baseline.shutdown().unwrap());
    for index in 1..=count {
        for mode in [
            Mode::Before,
            Mode::After,
            Mode::PanicBefore,
            Mode::PanicAfter,
        ] {
            let (mut engine, control, _) = engine();
            let begin = control.borrow().attempts.len();
            control.borrow_mut().cut = Some(begin + index);
            control.borrow_mut().mode = mode;
            let result = catch_unwind(AssertUnwindSafe(|| transfer(&mut engine)));
            let expected = if mode.panics() {
                assert!(result.is_err());
                ErrorKind::Interrupted.into()
            } else {
                result.unwrap().unwrap_err()
            };
            assert_eq!(engine.failure(), Some(expected));
            let progress = engine.progress();
            assert_eq!(progress.accepted, (begin + index - 1) as u64);
            assert_eq!(progress.pending, control.borrow().attempts.last().copied());
            let effects = control.borrow().effects.len();
            let attempts = control.borrow().attempts.len();
            assert_eq!(transfer(&mut engine), Err(expected));
            let failure = engine.shutdown().err().unwrap();
            assert_eq!(failure.error, expected);
            assert_eq!(failure.progress(), progress);
            assert_eq!(control.borrow().effects.len(), effects);
            assert_eq!(control.borrow().attempts.len(), attempts);
            assert_eq!(control.borrow().drops, 0);
        }
    }
}

#[test]
fn abort_primary_survives_clear_and_recovery_access_failure_or_unwind() {
    let (mut baseline, control, peer) = engine();
    peer.borrow_mut().fault_after = Some((1, ABRT_DATA_NACK));
    let primary = transfer(&mut baseline).unwrap_err().kind;
    assert_eq!(
        primary,
        ErrorKind::Aborted {
            kind: AbortKind::DataNack,
            source: ABRT_DATA_NACK
        }
    );
    let clear = control
        .borrow()
        .attempts
        .iter()
        .position(|access| {
            *access
                == Access::Read {
                    offset: CLR_TX_ABRT,
                }
        })
        .unwrap();
    drop(baseline.shutdown().unwrap());
    for frontier in [clear + 1, clear + 2] {
        for mode in [Mode::Before, Mode::After, Mode::PanicAfter] {
            let (mut engine, control, peer) = engine();
            peer.borrow_mut().fault_after = Some((1, ABRT_DATA_NACK));
            control.borrow_mut().cut = Some(frontier);
            control.borrow_mut().mode = mode;
            let result = catch_unwind(AssertUnwindSafe(|| transfer(&mut engine)));
            let expected = Error {
                kind: primary,
                recovery: if mode.panics() {
                    Recovery::Interrupted
                } else {
                    Recovery::Access(cause())
                },
            };
            if mode.panics() {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(expected));
            }
            assert_eq!(engine.failure(), Some(expected));
            let count = control.borrow().attempts.len();
            assert_eq!(transfer(&mut engine), Err(expected));
            assert_eq!(engine.shutdown().err().unwrap().error, expected);
            assert_eq!(control.borrow().attempts.len(), count);
            assert_eq!(control.borrow().drops, 0);
        }
    }
}

#[test]
fn timer_unwind_before_or_after_registers_is_not_permission_to_recover() {
    let (mut baseline, control, _) = engine();
    let begin = control.borrow().clock_calls;
    transfer(&mut baseline).unwrap();
    let count = control.borrow().clock_calls - begin;
    drop(baseline.shutdown().unwrap());
    for index in 1..=count {
        let (mut engine, control, _) = engine();
        let begin = control.borrow().clock_calls;
        control.borrow_mut().clock_cut = Some(begin + index);
        assert!(catch_unwind(AssertUnwindSafe(|| transfer(&mut engine))).is_err());
        let expected = ErrorKind::Interrupted.into();
        assert_eq!(engine.failure(), Some(expected));
        let calls = control.borrow().attempts.len();
        assert_eq!(transfer(&mut engine), Err(expected));
        assert_eq!(engine.shutdown().err().unwrap().error, expected);
        assert_eq!(control.borrow().attempts.len(), calls);
        assert_eq!(control.borrow().drops, 0);
    }
}

#[test]
fn constructor_clock_preflight_unwind_keeps_inputs_before_any_register_access() {
    let control = Rc::new(RefCell::new(Control::new()));
    control.borrow_mut().clock_cut = Some(1);
    let (registers, timer, _) = providers(&control);
    let cut = catch_unwind(AssertUnwindSafe(|| {
        let _result = DesignWare::new(registers, timer, config());
    }));
    assert!(cut.is_err());
    assert!(control.borrow().attempts.is_empty());
    assert_eq!(control.borrow().drops, 0);
}

#[test]
fn all_ones_is_an_observed_component_value_instead_of_an_access_refusal() {
    let control = Rc::new(RefCell::new(Control::new()));
    let (registers, timer, peer) = providers(&control);
    peer.borrow_mut().words[COMP_TYPE / 4] = u32::MAX;
    let failure = DesignWare::new(registers, timer, config()).err().unwrap();
    assert_eq!(failure.error.kind, ErrorKind::ComponentType(u32::MAX));
    assert_eq!(failure.progress().accepted, 1);
    assert_eq!(failure.progress().pending, None);
    assert_eq!(
        failure.progress().last,
        Some(AccessResult {
            access: Access::Read { offset: COMP_TYPE },
            read_value: Some(u32::MAX)
        })
    );
    assert_eq!(control.borrow().drops, 0);
}

#[test]
fn exhausted_progress_blocks_recovery_without_replacing_the_captured_abort() {
    let (mut baseline, control, peer) = engine();
    let begin = control.borrow().attempts.len();
    peer.borrow_mut().fault_after = Some((1, ABRT_DATA_NACK));
    let primary = transfer(&mut baseline).unwrap_err().kind;
    let clear = control
        .borrow()
        .attempts
        .iter()
        .position(|access| {
            *access
                == Access::Read {
                    offset: CLR_TX_ABRT,
                }
        })
        .unwrap();
    drop(baseline.shutdown().unwrap());
    let (mut engine, control, peer) = engine();
    peer.borrow_mut().fault_after = Some((1, ABRT_DATA_NACK));
    engine.state.progress.accepted = u64::MAX - (clear + 1 - begin) as u64;
    let error = transfer(&mut engine).unwrap_err();
    assert_eq!(error.kind, primary);
    assert_eq!(error.recovery, Recovery::ProgressExhausted);
    assert_eq!(engine.progress().accepted, u64::MAX);
    assert_eq!(
        engine.progress().pending,
        None,
        "no overflowing request was started"
    );
    let calls = control.borrow().attempts.len();
    assert_eq!(engine.shutdown().err().unwrap().error, error);
    assert_eq!(control.borrow().attempts.len(), calls);
    assert_eq!(control.borrow().drops, 0);
}
