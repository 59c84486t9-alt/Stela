// SPDX-License-Identifier: GPL-2.0-or-later
//! Original-owner minimum denial/unwind controls; no physical permissions.
extern crate std;
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct MinimumFailure {
    inner: ModelPlatform,
    effects: Rc<Cell<usize>>,
    waits: usize,
    fail_at: usize,
    panic: bool,
}
impl MinimumFailure {
    fn effect(&self) {
        self.effects.set(self.effects.get() + 1);
    }
}
// SAFETY: delegates exclusively to the original synchronous RAM peer, with
// failure injection solely at its actual modeled minimum callback.
unsafe impl Platform for MinimumFailure {
    fn identity(&self) -> Identity {
        self.inner.identity()
    }
    fn read32(&mut self, at: usize) -> Result<u32> {
        self.effect();
        self.inner.read32(at)
    }
    fn write32(&mut self, at: usize, value: u32) -> Result<()> {
        self.effect();
        self.inner.write32(at, value)
    }
    fn write8(&mut self, at: usize, value: u8) -> Result<()> {
        self.effect();
        self.inner.write8(at, value)
    }
    fn now_us(&self) -> u64 {
        self.inner.now_us()
    }
    fn minimum_delay(&mut self, us: u64) -> Result<()> {
        self.waits += 1;
        if self.waits == self.fail_at {
            if self.panic {
                panic!("model minimum callback unwind");
            }
            return Err(Error::Native(native::Error::Minimum(
                crate::bus::pci::power::Error::Interrupted,
            )));
        }
        self.inner.minimum_delay(us)
    }
    fn arm_vector_zero(&mut self) -> Result<()> {
        self.effect();
        self.inner.arm_vector_zero()
    }
    fn retire_vector_zero(&mut self) -> Result<()> {
        self.effect();
        self.inner.retire_vector_zero()
    }
}

#[test]
fn minimum_denial_never_runs_cleanup_or_reopens_original_transport() {
    if crate::model_test_process::isolate() {
        return;
    }
    for fail_at in 1..=3 {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let model = Rc::new(RefCell::new(Model::new(0x4d76)));
        let effects = Rc::new(Cell::new(0));
        let platform = MinimumFailure {
            inner: ModelPlatform(model.clone()),
            effects: effects.clone(),
            waits: 0,
            fail_at,
            panic: false,
        };
        let mut transport = Transport::new(platform, &mut dma).unwrap();
        let expected = Error::Native(native::Error::Minimum(
            crate::bus::pci::power::Error::Interrupted,
        ));
        assert_eq!(transport.start(), Err(expected.clone()));
        assert_eq!(transport.fault(), Some(&expected));
        let before = effects.get();
        assert_eq!(transport.start(), Err(expected.clone()));
        assert_eq!(transport.close(), Err(expected));
        assert_eq!(effects.get(), before);
        assert!(!transport.retired);
        assert_eq!(model.borrow().retire_count, 0);
        drop(transport);
        assert_eq!(effects.get(), before);
        assert_eq!(model.borrow().dropped, 0);
    }
}
#[test]
fn minimum_unwind_leaves_effect_fence_before_drop_and_explicit_close() {
    if crate::model_test_process::isolate() {
        return;
    }
    for fail_at in 1..=3 {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let model = Rc::new(RefCell::new(Model::new(0x4d76)));
        let effects = Rc::new(Cell::new(0));
        let platform = MinimumFailure {
            inner: ModelPlatform(model.clone()),
            effects: effects.clone(),
            waits: 0,
            fail_at,
            panic: true,
        };
        let mut transport = Transport::new(platform, &mut dma).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| transport.start())).is_err());
        let before = effects.get();
        assert_eq!(transport.start(), Err(Error::MinimumInterrupted));
        assert_eq!(transport.close(), Err(Error::MinimumInterrupted));
        assert_eq!(effects.get(), before);
        assert!(!transport.retired);
        assert_eq!(model.borrow().retire_count, 0);
        drop(transport);
        assert_eq!(effects.get(), before);
        assert_eq!(model.borrow().dropped, 0);
    }
}

#[test]
fn retirement_minimum_denial_or_unwind_keeps_original_armed_platform() {
    if crate::model_test_process::isolate() {
        return;
    }
    for panic in [false, true] {
        for fail_at in 4..=5 {
            let mut backing = vec![0u64; 1024 * 1024];
            let mut dma = allocator(&mut backing);
            let model = Rc::new(RefCell::new(Model::new(0x4d76)));
            let effects = Rc::new(Cell::new(0));
            let platform = MinimumFailure {
                inner: ModelPlatform(model.clone()),
                effects: effects.clone(),
                waits: 0,
                fail_at,
                panic,
            };
            let mut transport = Transport::new(platform, &mut dma).unwrap();
            transport.start().unwrap();
            assert_eq!(transport.platform.waits, 3);
            assert_eq!(model.borrow().arm_count, 1);
            let expected = if panic {
                Error::MinimumInterrupted
            } else {
                Error::Native(native::Error::Minimum(
                    crate::bus::pci::power::Error::Interrupted,
                ))
            };
            let closed = catch_unwind(AssertUnwindSafe(|| transport.close()));
            if panic {
                assert!(closed.is_err());
            } else {
                assert_eq!(closed.unwrap(), Err(expected.clone()));
            }
            let before = effects.get();
            assert_eq!(transport.close(), Err(expected.clone()));
            assert_eq!(transport.poll().err(), Some(expected));
            assert!(!transport.ready());
            assert_eq!(effects.get(), before);
            assert!(!transport.retired);
            assert_eq!(model.borrow().retire_count, 0);
            drop(transport);
            assert_eq!(effects.get(), before);
            assert_eq!(model.borrow().dropped, 0);
        }
    }
}
