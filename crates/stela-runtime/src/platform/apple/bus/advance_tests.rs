//! Registration, failure-order and mutation controls for passive advancement.
use super::*;
use crate::platform::apple::interrupt::InterruptLatch;
use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

struct Poller {
    index: usize,
    calls: Rc<RefCell<Vec<usize>>>,
    deadline: Option<u64>,
    fail: bool,
}
impl MmioDevice for Poller {
    fn name(&self) -> &'static str {
        "poller"
    }
    fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        Ok(0)
    }
    fn write(&mut self, _: u64, _: Width, _: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
        Ok(())
    }
    fn advance(&mut self, _: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        self.calls.borrow_mut().push(self.index);
        if self.fail {
            Err(refuse(
                "poller",
                0,
                Width::Word,
                Direction::Read,
                "test refusal",
            ))
        } else {
            Ok(self.deadline)
        }
    }
}

struct Passive(u64);
impl MmioDevice for Passive {
    fn advance_policy(&self) -> AdvancePolicy {
        AdvancePolicy::Passive
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        "passive"
    }
    fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        Ok(self.0)
    }
    fn write(&mut self, _: u64, _: Width, value: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
        self.0 = value;
        Ok(())
    }
}
impl Lifecycle for Passive {
    fn check_lifecycle(&self, _: LifecycleState) -> Result<(), &'static str> {
        Ok(())
    }
    fn set_lifecycle(&mut self, state: LifecycleState, _: &mut Access<'_>) {
        if state.reset {
            self.0 = 0;
        }
    }
}

#[test]
fn polling_keeps_owner_order_aliases_idle_pollers_and_first_error() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let poller = |index, deadline, fail| -> Box<dyn MmioDevice> {
        Box::new(Poller {
            index,
            calls: Rc::clone(&calls),
            deadline,
            fail,
        })
    };
    let mut bus = Bus::new();
    bus.add(Box::new(Passive(7)));
    let first = bus.add(poller(1, None, false));
    bus.map(first, 0x1000, 8, 0).unwrap();
    bus.map(first, 0x2000, 8, 0).unwrap();
    let [passive, second, failing, last] = bus
        .install_many(
            [
                Box::new(Passive(8)) as Box<dyn MmioDevice>,
                poller(2, Some(50), false),
                poller(3, Some(10), true),
                poller(4, Some(1), false),
            ],
            [
                &[(0x3000, 8, 0)],
                &[(0x4000, 8, 0)],
                &[(0x5000, 8, 0)],
                &[(0x6000, 8, 0)],
            ],
        )
        .unwrap();
    assert_eq!(bus.advancing, [first, second, failing, last]);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 100, &mut latch);
    bus.write(0x3000, Width::Double, 42, &mut access).unwrap();
    assert_eq!(bus.read(0x3000, Width::Double, &mut access), Ok(42));
    assert!(bus.advance(&mut access).is_err());
    assert_eq!(*calls.borrow(), [1, 2, 3]);
    #[cfg(feature = "native-profile")]
    {
        let stats = bus.advance_statistics();
        assert_eq!((stats.owners, stats.active_owners), (6, 4));
        assert_eq!(
            (stats.passes, stats.completed_passes, stats.invocations),
            (1, 0, 3)
        );
    }
    bus.device_mut::<Poller>(failing).unwrap().fail = false;
    assert_eq!(bus.advance(&mut access), Ok(Some(1)));
    assert_eq!(*calls.borrow(), [1, 2, 3, 1, 2, 3, 4]);
    bus.lifecycle(passive).unwrap().set_lifecycle(
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: true,
            retention: false,
        },
        &mut access,
    );
    assert_eq!(bus.read(0x3000, Width::Double, &mut access), Ok(0));
    assert_eq!(bus.advance(&mut access), Ok(Some(1)));
    assert_eq!(*calls.borrow(), [1, 2, 3, 1, 2, 3, 4, 1, 2, 3, 4]);
    #[cfg(feature = "native-profile")]
    assert_eq!(bus.advance_statistics().invocations, 11);
}

#[test]
fn failed_batches_publish_no_polling_owner_and_empty_passes_complete() {
    let mut bus = Bus::new();
    let first = bus
        .install(Box::new(Passive(9)), &[(0x1000, 8, 0)])
        .unwrap();
    let calls = Rc::new(RefCell::new(vec![]));
    assert!(
        bus.install_many(
            [
                Box::new(Poller {
                    index: 1,
                    calls: Rc::clone(&calls),
                    deadline: None,
                    fail: false
                }) as Box<dyn MmioDevice>,
                Box::new(Passive(0))
            ],
            [&[(0x2000, 8, 0)], &[(0x1000, 8, 0)]],
        )
        .is_err()
    );
    assert_eq!(bus.devices.len(), 1);
    assert!(bus.advancing.is_empty());
    assert_eq!(bus.route(0x1000, Width::Word), Ok((first, 0)));
    assert!(bus.route(0x2000, Width::Word).is_err());
    let mut latch = InterruptLatch::new();
    assert_eq!(bus.advance(&mut Access::new(0, 1, &mut latch)), Ok(None));
    assert!(calls.borrow().is_empty());
    #[cfg(feature = "native-profile")]
    assert_eq!(
        bus.advance_statistics(),
        AdvanceStatistics {
            owners: 1,
            active_owners: 0,
            passes: 1,
            completed_passes: 1,
            invocations: 0,
        }
    );
}
