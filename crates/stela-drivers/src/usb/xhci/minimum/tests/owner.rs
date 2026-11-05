// SPDX-License-Identifier: MIT
//! Original owned register backend Drop and constructor effect controls.
use super::*;
struct Peer {
    drops: Rc<Cell<usize>>,
    effects: Rc<RefCell<Vec<(bool, usize, u32)>>>,
    running: Rc<Cell<bool>>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl Registers for Peer {
    fn read32(&mut self, at: usize) -> u32 {
        self.effects.borrow_mut().push((false, at, 0));
        match at {
            0 => 0x0100_0040,
            HCSPARAMS1 => 1 << 24 | 8,
            // The isolated peer reaches TestRegion at its 64-bit heap address.
            HCCPARAMS1 => 1,
            DBOFF => 0x1000,
            RTSOFF => 0x800,
            0x48 => 1,
            0x44 => {
                if self.running.get() {
                    0
                } else {
                    HCH
                }
            }
            _ => 0,
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.effects.borrow_mut().push((true, at, value));
        if at == 0x40 {
            self.running.set(value & RUN != 0);
        }
    }
}
struct AfterStart {
    running: Rc<Cell<bool>>,
    fixture: Rc<dyn Timer>,
    drops: Rc<Cell<usize>>,
}
// SAFETY: isolated owned current-thread fixture only. Exact register peer
// running transition injects refusal; no native elapsed-time authority.
unsafe impl Timer for AfterStart {
    fn check(&self) -> Result<(), Error> {
        assert_eq!(
            self.drops.get(),
            0,
            "backend released before timer callback"
        );
        if self.running.get() {
            Err(Error::Interrupted)
        } else {
            self.fixture.check()
        }
    }
    fn wait_us(&self, us: u64) -> Result<(), Error> {
        self.check()?;
        self.fixture.wait_us(us)
    }
}
#[test]
fn raw_constructor_keeps_original_backend_across_every_failure_and_abandonment() {
    for fault in 0..4 {
        let clock = Clock {
            ticks_per_microsecond: 1,
        };
        let drops = Rc::new(Cell::new(0));
        let effects = Rc::new(RefCell::new(Vec::new()));
        let running = Rc::new(Cell::new(false));
        let (timer, counts) = fault_timer();
        let timer = match fault {
            0 => crate::minimum_model::refusing(clock),
            1 => {
                counts.fault.set(Some(Error::Interrupted));
                timer
            }
            2 => Rc::new(AfterStart {
                running: running.clone(),
                fixture: timer,
                drops: drops.clone(),
            }) as Rc<dyn Timer>,
            _ => timer,
        };
        let mut dma = TestRegion::new(16 * 1024 * 8);
        let result = Controller::new(
            Box::new(Peer {
                drops: drops.clone(),
                effects: effects.clone(),
                running: running.clone(),
            }),
            clock,
            &mut dma,
            "owned protocol constructor".into(),
            timer,
        );
        match fault {
            0 => {
                assert!(matches!(result, Err(BlockError::PciPower(Error::Clock))));
                assert!(effects.borrow().is_empty());
            }
            1 => {
                assert!(matches!(
                    result,
                    Err(BlockError::PciPower(Error::Interrupted))
                ));
                assert_eq!(effects.borrow().last(), Some(&(true, 0x40, HCRST)));
                assert!(!running.get());
            }
            2 => {
                assert!(
                    matches!(result, Err(BlockError::PciPower(Error::Interrupted))),
                    "constructor error before start-phase source refusal: {:?}; effects: {:?}",
                    result.as_ref().err(),
                    effects.borrow()
                );
                assert!(running.get(), "final check must follow actual start");
            }
            _ => {
                assert!(result.is_ok());
                drop(result);
            }
        }
        assert_eq!(
            drops.get(),
            0,
            "original register owner must remain retained"
        );
    }
}
