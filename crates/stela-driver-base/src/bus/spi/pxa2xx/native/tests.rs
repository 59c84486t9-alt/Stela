//! Actual owned RAM mapping/context callbacks, without physical admission.
use super::*;
use crate::bus::{
    lpss::tests::{native_fixture_for, stop_fixture},
    pci::requester::StoppedRequester,
};
use alloc::rc::Rc;
use core::{cell::Cell, sync::atomic::Ordering};
struct Platform {
    _requester: StoppedRequester,
    drops: Rc<Cell<usize>>,
}
impl Drop for Platform {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
fn description() -> Description {
    Description {
        profile: super::super::Profile::CannonLake,
        input_clock_hz: 50_000_000,
        chip_selects: 4,
    }
}

#[test]
#[expect(
    clippy::drop_non_drop,
    reason = "explicit refusal abandonment checks same original provider retention"
)]
fn claim_context_denial_and_unwind_keep_original_mapping_and_platform() {
    extern crate std;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    for unwind in [false, true] {
        let (function, mapping, config, bar) = native_fixture_for(0xa0aa);
        let drops = Rc::new(Cell::new(0));
        let platform = Platform {
            _requester: stop_fixture(function),
            drops: drops.clone(),
        };
        let cut = bar.contexts.load(Ordering::Relaxed) + 1;
        if unwind {
            bar.panic_context_at.store(cut, Ordering::Relaxed);
        } else {
            bar.fail_context_at.store(cut, Ordering::Relaxed);
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: same stopped affine RAM fixture and external BAR grant;
            // no physical clock, CS-pin or native startup grant is inferred.
            let failure = unsafe { NativeRegisters::claim(mapping, platform, description()) }
                .err()
                .unwrap();
            assert_eq!(
                failure.error,
                IoError::Mmio(crate::bus::mmio::owned::Error::Unavailable)
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

#[test]
#[expect(
    clippy::drop_non_drop,
    reason = "abandoning a live native provider must retain all original owners"
)]
fn scalar_all_ones_is_data_and_denied_context_preserves_the_owned_cause() {
    let (function, mapping, config, bar) = native_fixture_for(0xa0aa);
    let pointer = mapping.address(0x10, 4).unwrap().cast::<u32>();
    // SAFETY: same exclusively owned isolated RAM aperture, no child or
    // asynchronous users. This store supplies ordinary observable scalar data.
    unsafe { pointer.as_ptr().write_volatile(u32::MAX) };
    let drops = Rc::new(Cell::new(0));
    let platform = Platform {
        _requester: stop_fixture(function),
        drops: drops.clone(),
    };
    // SAFETY: same stopped affine fixture and model metadata/clock epoch.
    let mut registers =
        unsafe { NativeRegisters::claim(mapping, platform, description()) }.unwrap();
    assert_eq!(registers.read32(0x10), Ok(u32::MAX));
    let cut = bar.contexts.load(Ordering::Relaxed) + 1;
    bar.fail_context_at.store(cut, Ordering::Relaxed);
    assert_eq!(
        registers.write32(0x10, 1),
        Err(IoError::Mmio(crate::bus::mmio::owned::Error::Unavailable))
    );
    drop(registers);
    assert_eq!(bar.contexts.load(Ordering::Relaxed), cut);
    assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(bar.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(drops.get(), 0);
}

struct Time(Cell<u64>);
impl crate::bus::i2c::Timer for Time {
    fn now_us(&self) -> u64 {
        let now = self.0.get();
        self.0.set(now.wrapping_add(1));
        now
    }
}
impl super::super::Timer for Time {
    fn calibrated(&self) -> bool {
        true
    }
}

#[test]
#[expect(
    clippy::drop_non_drop,
    reason = "failed native retirement abandonment must not release its original platform"
)]
fn retirement_preserves_context_or_uncertain_unmap_cause_and_requires_actual_ack() {
    for scenario in 0..3 {
        let (function, mapping, config, bar) = native_fixture_for(0xa0aa);
        let drops = Rc::new(Cell::new(0));
        let platform = Platform {
            _requester: stop_fixture(function),
            drops: drops.clone(),
        };
        // SAFETY: original isolated stopped function and complete UC RAM
        // mapping. No physical clock/CS qualification is inferred.
        let registers =
            unsafe { NativeRegisters::claim(mapping, platform, description()) }.unwrap();
        let controller = super::super::Controller::new(registers, Time(Cell::new(0)), 100).unwrap();
        // This controller has published no SSP child or wire command. The
        // same production release path acknowledges that empty lifecycle.
        let (registers, _) = controller.release().ok().unwrap();
        let before = bar.contexts.load(Ordering::Relaxed);
        match scenario {
            1 => bar.fail_context_at.store(before + 1, Ordering::Relaxed),
            2 => bar.fail_unmap_after_effect.store(1, Ordering::Relaxed),
            _ => (),
        }
        // SAFETY: original production release returned this provider; no
        // pointer/view, child, callback or posted write was ever published.
        let result = unsafe { registers.retire() };
        if scenario == 0 {
            drop(result.ok().unwrap());
            assert_eq!(drops.get(), 1);
        } else {
            let failure = result.err().unwrap();
            assert_eq!(
                failure.error,
                if scenario == 1 {
                    crate::bus::mmio::owned::Error::Unavailable
                } else {
                    crate::bus::mmio::owned::Error::UnmapFailed
                }
            );
            drop(failure);
            assert_eq!(drops.get(), 0);
        }
        assert_eq!(bar.contexts.load(Ordering::Relaxed), before + 1);
        assert_eq!(
            bar.unmaps.load(Ordering::Relaxed),
            usize::from(scenario != 1)
        );
        assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
    }
}
