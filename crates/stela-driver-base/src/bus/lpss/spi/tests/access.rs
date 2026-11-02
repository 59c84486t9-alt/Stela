//! Same allocation across LPSS preparation, SSP service and platform retirement.
use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct CountedTime {
    original: Time,
    drops: Rc<Cell<usize>>,
}
impl Drop for CountedTime {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl crate::bus::i2c::Timer for CountedTime {
    fn now_us(&self) -> u64 {
        self.original.now_us()
    }
    fn relax(&self) {
        self.original.relax();
    }
}
impl Timer for CountedTime {
    fn calibrated(&self) -> bool {
        true
    }
}
type Inputs = (Model, CountedTime, Rc<RefCell<Hardware>>, Rc<Cell<usize>>);
fn inputs() -> Inputs {
    let (registers, time, hardware) = model(0xa0aa, 1 << 1 | 2 << 16);
    let drops = Rc::new(Cell::new(0));
    (
        registers,
        CountedTime {
            original: time,
            drops: drops.clone(),
        },
        hardware,
        drops,
    )
}

#[test]
fn every_preparation_unwind_keeps_original_registers_and_timer_before_or_after_effects() {
    let (registers, time, hardware, _) = inputs();
    // SAFETY: same isolated original LPSS/SSP peer and literal board timing.
    let baseline = unsafe { Spi::attach(registers, time, 1, 10_000) }.unwrap();
    let expected = hardware.borrow().log.clone();
    drop(baseline.shutdown().unwrap());
    for ordinal in 1..=expected.len() {
        for after in [false, true] {
            let (registers, time, hardware, timer_drops) = inputs();
            hardware.borrow_mut().unwind = Some((ordinal, after));
            // SAFETY: original isolated peer; only its actual access callback
            // is interrupted. No fabricated native completion or grant.
            let result = catch_unwind(AssertUnwindSafe(|| unsafe {
                Spi::attach(registers, time, 1, 10_000)
            }));
            assert!(result.is_err());
            assert_eq!(hardware.borrow().log, expected[..ordinal]);
            assert_eq!(hardware.borrow().drops, 0);
            assert_eq!(timer_drops.get(), 0);
        }
    }
}

#[test]
fn every_shutdown_unwind_keeps_both_providers_through_platform_reset() {
    let (registers, time, hardware, timer_drops) = inputs();
    // SAFETY: same stopped isolated peer and board clock/CS ownership.
    let baseline = unsafe { Spi::attach(registers, time, 1, 10_000) }.unwrap();
    let begin = hardware.borrow().log.len();
    drop(baseline.shutdown().unwrap());
    let expected = hardware.borrow().log.clone();
    assert_eq!(hardware.borrow().drops, 1);
    assert_eq!(timer_drops.get(), 1);
    for ordinal in begin + 1..=expected.len() {
        for after in [false, true] {
            let (registers, time, hardware, timer_drops) = inputs();
            // SAFETY: same independent original model and acknowledged setup.
            let spi = unsafe { Spi::attach(registers, time, 1, 10_000) }.unwrap();
            hardware.borrow_mut().unwind = Some((ordinal, after));
            assert!(catch_unwind(AssertUnwindSafe(|| spi.shutdown())).is_err());
            assert_eq!(hardware.borrow().log, expected[..ordinal]);
            assert_eq!(hardware.borrow().drops, 0);
            assert_eq!(timer_drops.get(), 0);
        }
    }
}

#[test]
#[expect(
    clippy::drop_non_drop,
    reason = "explicit abandonment verifies the original provider Drop witnesses stay unchanged"
)]
fn native_context_refusal_keeps_same_claim_mapping_timer_and_exact_platform_frontier() {
    use crate::bus::lpss::tests::{native_fixture_for, stop_fixture};
    use core::sync::atomic::Ordering;
    let (function, mapping, config, bar) = native_fixture_for(0xa0aa);
    let drops = Rc::new(Cell::new(0));
    let timer = CountedTime {
        original: Time(Rc::new(Cell::new(0))),
        drops: drops.clone(),
    };
    let before = bar.contexts.load(Ordering::Relaxed);
    // Claim validates the same mapping address once; deny its next actual
    // scalar access at the platform's CAPS read.
    bar.fail_context_at.store(before + 2, Ordering::Relaxed);
    // SAFETY: actual affine fixture function and UC RAM mapping, plus the same
    // external BAR grant. No physical or native startup admission is inferred.
    let failure = unsafe { Spi::attach_native(stop_fixture(function), mapping, timer, 1, 10_000) }
        .err()
        .unwrap();
    assert_eq!(failure.stage(), AttachStage::Controller);
    assert_eq!(
        failure.error,
        Error::Platform(super::super::super::Error::Mmio(
            crate::bus::mmio::owned::Error::Unavailable
        ))
    );
    let progress = failure.platform_progress().unwrap();
    assert_eq!(progress.accepted, 0);
    assert_eq!(
        progress.pending,
        Some(pxa2xx::Access::Read { offset: 0x2fc })
    );
    drop(failure);
    assert_eq!(bar.contexts.load(Ordering::Relaxed), before + 2);
    assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(drops.get(), 0);
}

#[test]
#[expect(
    clippy::drop_non_drop,
    reason = "explicit claim refusal abandonment verifies retention of every original provider"
)]
fn native_claim_denial_or_unwind_keeps_the_original_timer_with_both_native_graphs() {
    use crate::bus::lpss::tests::{native_fixture_for, stop_fixture};
    use core::sync::atomic::Ordering;
    for unwind in [false, true] {
        let (function, mapping, config, bar) = native_fixture_for(0xa0aa);
        let drops = Rc::new(Cell::new(0));
        let timer = CountedTime {
            original: Time(Rc::new(Cell::new(0))),
            drops: drops.clone(),
        };
        let cut = bar.contexts.load(Ordering::Relaxed) + 1;
        if unwind {
            bar.panic_context_at.store(cut, Ordering::Relaxed);
        } else {
            bar.fail_context_at.store(cut, Ordering::Relaxed);
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: same stopped affine RAM fixture and original external
            // BAR grant. Interrupt its actual native claim context callback.
            let failure =
                unsafe { Spi::attach_native(stop_fixture(function), mapping, timer, 1, 10_000) }
                    .err()
                    .unwrap();
            assert_eq!(failure.stage(), AttachStage::Claim);
            assert_eq!(failure.platform_progress(), None);
            assert_eq!(
                failure.error,
                Error::Platform(super::super::super::Error::Mmio(
                    crate::bus::mmio::owned::Error::Unavailable
                ))
            );
            drop(failure);
        }));
        assert_eq!(result.is_err(), unwind);
        assert_eq!(bar.contexts.load(Ordering::Relaxed), cut);
        assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(drops.get(), 0);
    }
}
