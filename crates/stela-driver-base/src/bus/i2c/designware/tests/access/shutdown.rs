//! Consuming shutdown must retain the providers even when its callback unwinds.
use super::*;

#[test]
fn every_shutdown_register_frontier_retains_the_same_providers() {
    let (baseline, control, _) = engine();
    let begin = control.borrow().attempts.len();
    drop(baseline.shutdown().unwrap());
    let expected = control.borrow().attempts.clone();
    for index in begin + 1..=expected.len() {
        for mode in [
            Mode::Before,
            Mode::After,
            Mode::PanicBefore,
            Mode::PanicAfter,
        ] {
            let (engine, control, _) = engine();
            control.borrow_mut().cut = Some(index);
            control.borrow_mut().mode = mode;
            let result = catch_unwind(AssertUnwindSafe(|| engine.shutdown()));
            if mode.panics() {
                assert!(result.is_err());
            } else {
                let failure = result.unwrap().err().unwrap();
                assert_eq!(failure.error, ErrorKind::Access(cause()).into());
                assert_eq!(failure.progress().accepted, (index - 1) as u64);
                assert_eq!(failure.progress().pending, Some(expected[index - 1]));
            }
            assert_eq!(control.borrow().attempts, expected[..index]);
            assert_eq!(control.borrow().drops, 0);
        }
    }
}

#[test]
fn every_shutdown_clock_unwind_retains_the_same_providers_without_cleanup() {
    let (baseline, control, _) = engine();
    let begin = control.borrow().clock_calls;
    drop(baseline.shutdown().unwrap());
    let count = control.borrow().clock_calls - begin;
    assert_ne!(count, 0);
    for index in 1..=count {
        let (engine, control, _) = engine();
        let begin = control.borrow().clock_calls;
        control.borrow_mut().clock_cut = Some(begin + index);
        assert!(catch_unwind(AssertUnwindSafe(|| engine.shutdown())).is_err());
        assert_eq!(control.borrow().clock_calls, begin + index);
        assert_eq!(control.borrow().drops, 0);
    }
}
