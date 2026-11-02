use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Cut {
    original: Box<dyn Registers>,
    armed: Rc<Cell<bool>>,
    accesses: Rc<Cell<usize>>,
    after_write: bool,
}
impl Registers for Cut {
    fn read32(&mut self, offset: usize) -> u32 {
        self.accesses.set(self.accesses.get() + 1);
        self.original.read32(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.accesses.set(self.accesses.get() + 1);
        // The original model consumes actual published TDs at the slot's
        // interrupt-IN doorbell. All unrelated register effects still run.
        let cut = offset == 0x1004 && value == 3 && self.armed.replace(false);
        assert!(!cut || self.after_write, "before interrupt-IN publication");
        self.original.write32(offset, value);
        assert!(!cut, "after interrupt-IN publication");
    }
}

#[test]
fn completed_input_and_raw_report_survive_the_next_controller_callback_unwind() {
    for after_write in [false, true] {
        let mut dma = model::TestRegion::new(512 * 1024);
        let armed = Rc::new(Cell::new(false));
        let accesses = Rc::new(Cell::new(0));
        let (mut input, peer) = fixture_with_registers(&mut dma, |original, _| {
            Box::new(Cut {
                original,
                armed: armed.clone(),
                accesses: accesses.clone(),
                after_write,
            })
        });
        assert!(input.poll_hid().reports.is_empty());
        let report = vec![1, 0, 0, 4, 0, 0, 0, 0, 0];
        peer.borrow_mut().push_event(report.clone());
        armed.set(true);
        let interrupted = catch_unwind(AssertUnwindSafe(|| input.poll_hid()));
        assert!(interrupted.is_err());
        assert!(!armed.get(), "the next real doorbell reached the fault cut");
        assert_eq!(input.last_report(), report);
        let count = accesses.get();
        let pending = input.drain_pending();
        assert_eq!(accesses.get(), count, "drain performs no controller call");
        assert_eq!(
            pending.hid.inputs,
            [Input::Key {
                usage: 4,
                pressed: true
            }]
        );
        assert!(!pending.hid.events.is_empty());
        let [ReceivedReport::Data(frame)] = pending.hid.reports.as_slice() else {
            panic!("lost descriptor-decoded prefix")
        };
        assert_eq!(frame.bytes, report);
        let drained = input.drain_pending();
        assert!(drained.hid.inputs.is_empty());
        assert!(drained.hid.events.is_empty());
        assert!(drained.hid.reports.is_empty());
        assert_eq!(
            accesses.get(),
            count,
            "no retry after uncertain publication"
        );
        // The model is isolated and has no asynchronous DMA actor. Cancellation
        // below must still execute the controller's ordinary acknowledgement.
        let stopped = input.stop_hid().unwrap();
        assert_eq!(
            stopped.inputs,
            [Input::Key {
                usage: 4,
                pressed: false
            }]
        );
        assert!(
            stopped.reports.is_empty(),
            "the returned press is not replayed"
        );
    }
}

#[test]
fn acknowledged_stop_returns_the_undrained_prefix_before_its_release() {
    let mut dma = model::TestRegion::new(512 * 1024);
    let armed = Rc::new(Cell::new(false));
    let (mut input, peer) = fixture_with_registers(&mut dma, |original, _| {
        Box::new(Cut {
            original,
            armed: armed.clone(),
            accesses: Rc::new(Cell::new(0)),
            after_write: true,
        })
    });
    input.poll_hid();
    peer.borrow_mut()
        .push_event(vec![1, 0, 0, 4, 0, 0, 0, 0, 0]);
    armed.set(true);
    assert!(catch_unwind(AssertUnwindSafe(|| input.poll_hid())).is_err());
    let stopped = input.stop_hid().unwrap();
    assert_eq!(
        stopped.inputs,
        [
            Input::Key {
                usage: 4,
                pressed: true
            },
            Input::Key {
                usage: 4,
                pressed: false
            },
        ]
    );
    assert_eq!(stopped.reports.len(), 1);
    let next = input.stop_hid().unwrap();
    assert!(next.inputs.is_empty());
    assert!(next.events.is_empty());
    assert!(next.reports.is_empty());
}
