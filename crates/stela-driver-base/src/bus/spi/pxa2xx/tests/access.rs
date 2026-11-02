//! Caught unwinds traverse the same original SSP FIFO/peripheral engine.
use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};
mod peers;
use peers::*;

#[derive(Clone, Copy)]
enum Phase {
    Initialize,
    Message,
    Release,
}
fn prepared(phase: Phase) -> (CountedController, Rc<RefCell<Hardware>>, Rc<Calls>) {
    let (mut controller, hardware, calls) = counted();
    if !matches!(phase, Phase::Initialize) {
        controller.initialize().unwrap();
    }
    (controller, hardware, calls)
}
fn run(controller: &mut CountedController, phase: Phase) -> Result<(), Error> {
    match phase {
        Phase::Initialize => controller.initialize(),
        Phase::Message => controller.message(device(), &mut [transfer(Some(&[1, 2]), None, 2, 8)]),
        Phase::Release => unreachable!(),
    }
}
fn access(observed: Access) -> super::super::Access {
    match observed {
        Access::Read(offset) => super::super::Access::Read { offset },
        Access::Write(offset, value) => super::super::Access::Write { offset, value },
    }
}

#[test]
fn every_register_unwind_keeps_exact_pending_access_and_prevents_later_io() {
    for phase in [Phase::Initialize, Phase::Message, Phase::Release] {
        let (mut baseline, hardware, _) = prepared(phase);
        let begin = hardware.borrow().log.len();
        if matches!(phase, Phase::Release) {
            drop(baseline.release().ok().unwrap());
        } else {
            run(&mut baseline, phase).unwrap();
        }
        let expected = hardware.borrow().log.clone();
        for ordinal in begin + 1..=expected.len() {
            for after in [false, true] {
                let (mut controller, hardware, calls) = prepared(phase);
                hardware.borrow_mut().unwind = Some((ordinal, after));
                if matches!(phase, Phase::Release) {
                    assert!(catch_unwind(AssertUnwindSafe(|| controller.release())).is_err());
                } else {
                    assert!(
                        catch_unwind(AssertUnwindSafe(|| run(&mut controller, phase))).is_err()
                    );
                    let error = controller.failure().unwrap();
                    assert_eq!(error.kind, ErrorKind::Interrupted);
                    let progress = controller.progress();
                    assert_eq!(progress.accepted, (ordinal - 1) as u64);
                    assert_eq!(progress.pending, Some(access(expected[ordinal - 1])));
                    assert_eq!(
                        run(&mut controller, phase).unwrap_err().kind,
                        ErrorKind::NeedsReset
                    );
                    assert_eq!(controller.failure(), Some(error));
                    assert!(controller.release().is_err());
                }
                assert_eq!(hardware.borrow().log, expected[..ordinal]);
                assert_eq!(hardware.borrow().drops, 0);
                assert_eq!(calls.drops.get(), 0);
            }
        }
    }
}

#[test]
fn each_timer_unwind_denies_later_transactions_and_keeps_both_providers() {
    for phase in [Phase::Initialize, Phase::Message, Phase::Release] {
        let (mut baseline, _, calls) = prepared(phase);
        let begin = calls.count.get();
        if matches!(phase, Phase::Release) {
            drop(baseline.release().ok().unwrap());
        } else {
            run(&mut baseline, phase).unwrap();
        }
        let count = calls.count.get() - begin;
        assert_ne!(count, 0);
        for ordinal in 1..=count {
            let (mut controller, hardware, calls) = prepared(phase);
            let cut = calls.count.get() + ordinal;
            calls.cut.set(Some(cut));
            if matches!(phase, Phase::Release) {
                assert!(catch_unwind(AssertUnwindSafe(|| controller.release())).is_err());
            } else {
                assert!(catch_unwind(AssertUnwindSafe(|| run(&mut controller, phase))).is_err());
                let progress = controller.progress();
                let io = hardware.borrow().log.len();
                assert_eq!(controller.failure().unwrap().kind, ErrorKind::Interrupted);
                assert_eq!(
                    run(&mut controller, phase).unwrap_err().kind,
                    ErrorKind::NeedsReset
                );
                assert_eq!(controller.progress(), progress);
                assert!(controller.release().is_err());
                assert_eq!(hardware.borrow().log.len(), io);
            }
            assert_eq!(calls.count.get(), cut);
            assert_eq!(calls.drops.get(), 0);
            assert_eq!(hardware.borrow().drops, 0);
        }
    }
}

#[test]
fn constructor_metadata_or_clock_unwind_keeps_original_inputs_before_effects() {
    for point in 0..4 {
        let (controller, hardware, calls) = counted();
        let (peer, time) = controller.release().ok().unwrap();
        if point < 2 {
            calls.cut.set(Some(calls.count.get() + point + 1));
        }
        let peer = MetadataPeer { peer, cut: point };
        let result = catch_unwind(AssertUnwindSafe(|| Controller::new(peer, time, 10_000)));
        assert!(result.is_err());
        assert!(hardware.borrow().log.is_empty());
        assert_eq!(hardware.borrow().drops, 0);
        assert_eq!(calls.drops.get(), 0);
    }
}

#[test]
fn actual_access_cause_and_returned_frontier_survive_later_needs_reset() {
    let (mut controller, hardware, calls) = counted();
    controller.initialize().unwrap();
    let begin = hardware.borrow().log.len();
    let accepted = controller.progress().accepted;
    hardware.borrow_mut().fail = Some((begin + 1, true));
    let error = run(&mut controller, Phase::Message).unwrap_err();
    let cause = IoError::Mmio(crate::bus::mmio::owned::Error::Unavailable);
    assert_eq!(error.io, Some(cause));
    assert_eq!(controller.progress().accepted, accepted);
    assert_eq!(
        controller.progress().pending,
        Some(access(hardware.borrow().log[begin]))
    );
    assert_eq!(
        run(&mut controller, Phase::Message).unwrap_err().io,
        Some(cause)
    );
    assert_eq!(controller.failure(), Some(error));
    assert!(controller.release().is_err());
    assert_eq!(hardware.borrow().log.len(), begin + 1);
    assert_eq!(hardware.borrow().drops, 0);
    assert_eq!(calls.drops.get(), 0);
}

#[test]
fn platform_preparation_bind_message_and_finalizer_use_the_same_provider_allocation() {
    let (original, hardware) = host(Profile::CannonLake);
    let (peer, time) = original.release().ok().unwrap();
    let addresses = Rc::new(RefCell::new(Vec::new()));
    let mut prepared = PreparedController::new(
        StablePeer {
            original: peer,
            addresses: addresses.clone(),
        },
        time,
        10_000,
    );
    prepared
        .configure(|peer| {
            peer.record();
            Ok::<_, ()>(())
        })
        .unwrap();
    let mut controller = prepared.bind().unwrap();
    controller.initialize().unwrap();
    controller
        .message(device(), &mut [transfer(Some(&[1, 2]), None, 2, 8)])
        .unwrap();
    let owners = controller
        .release_with(|peer| {
            peer.record();
            let hardware = peer.original.0.borrow();
            assert!(!hardware.active && hardware.tx.is_empty() && hardware.rx.is_empty());
            assert_eq!(hardware.registers[CR0 / 4] & ENABLE, 0);
            Ok::<_, ()>(())
        })
        .ok()
        .unwrap();
    let observed = addresses.borrow();
    assert!(observed.len() > 20);
    assert!(observed.iter().all(|address| *address == observed[0]));
    drop(owners);
    assert_eq!(hardware.borrow().drops, 1);
}

#[test]
fn exhausted_progress_does_not_start_an_unrecordable_register_access() {
    let (mut controller, hardware, _) = counted();
    controller.initialize().unwrap();
    // The counter belongs to this same private retained state; exhausting it
    // is not a source of an extra device operation or a retirement permit.
    controller.exhaust_progress();
    let before = hardware.borrow().log.len();
    let error = run(&mut controller, Phase::Message).unwrap_err();
    assert_eq!(error.kind, ErrorKind::ProgressExhausted);
    assert_eq!(controller.progress().accepted, u64::MAX);
    assert_eq!(controller.progress().pending, None);
    assert_eq!(hardware.borrow().log.len(), before);
    assert!(controller.release().is_err());
    assert_eq!(hardware.borrow().drops, 0);
}
