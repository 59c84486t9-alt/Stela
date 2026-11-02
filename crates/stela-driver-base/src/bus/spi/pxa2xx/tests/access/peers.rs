//! Clock and metadata cut points retain the original peer and timer services.
use super::super::*;
pub(super) struct Calls {
    pub(super) count: Cell<usize>,
    pub(super) cut: Cell<Option<usize>>,
    pub(super) drops: Cell<usize>,
}
pub(super) struct CountedTime {
    original: Time,
    calls: Rc<Calls>,
}
impl CountedTime {
    fn call(&self) {
        self.calls.count.set(self.calls.count.get() + 1);
        assert_ne!(
            self.calls.cut.get(),
            Some(self.calls.count.get()),
            "timer callback interrupted"
        );
    }
}
impl Drop for CountedTime {
    fn drop(&mut self) {
        self.calls.drops.set(self.calls.drops.get() + 1);
    }
}
impl crate::bus::i2c::Timer for CountedTime {
    fn check_duration(&self, us: u64) -> Result<(), crate::ClockError> {
        self.call();
        self.original.check_duration(us)
    }
    fn now_us(&self) -> u64 {
        self.call();
        self.original.now_us()
    }
    fn start(&self) -> u64 {
        self.call();
        self.original.start()
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        self.call();
        self.original.elapsed_us(start)
    }
    fn relax(&self) {
        self.call();
        self.original.relax();
    }
}
impl Timer for CountedTime {
    fn calibrated(&self) -> bool {
        self.call();
        true
    }
}
pub(super) type CountedController = Controller<Peer, CountedTime>;
pub(super) fn counted() -> (CountedController, Rc<RefCell<Hardware>>, Rc<Calls>) {
    let (controller, hardware) = host(Profile::CannonLake);
    let (peer, time) = controller.release().ok().unwrap();
    let calls = Rc::new(Calls {
        count: Cell::new(0),
        cut: Cell::new(None),
        drops: Cell::new(0),
    });
    let controller = Controller::new(
        peer,
        CountedTime {
            original: time,
            calls: calls.clone(),
        },
        10_000,
    )
    .unwrap();
    (controller, hardware, calls)
}
pub(super) struct MetadataPeer {
    pub(super) peer: Peer,
    pub(super) cut: usize,
}
// SAFETY: forwards the same isolated original FIFO/peripheral model. The
// metadata cut neither invents a device grant nor publishes another user.
unsafe impl Registers for MetadataPeer {
    fn description(&self) -> Description {
        assert_ne!(self.cut, 2, "description interrupted");
        self.peer.description()
    }
    fn bytes(&self) -> usize {
        assert_ne!(self.cut, 3, "bytes interrupted");
        self.peer.bytes()
    }
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        self.peer.read32(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        self.peer.write32(offset, value)
    }
}

pub(super) struct StablePeer {
    pub(super) original: Peer,
    pub(super) addresses: Rc<RefCell<Vec<usize>>>,
}
impl StablePeer {
    pub(super) fn record(&self) {
        self.addresses
            .borrow_mut()
            .push(core::ptr::from_ref(self).addr());
    }
}
// SAFETY: the same uniquely owned FIFO/peripheral peer. Numerical addresses
// record storage identity only; they supply no MMIO or native execution grant.
unsafe impl Registers for StablePeer {
    fn description(&self) -> Description {
        self.record();
        self.original.description()
    }
    fn bytes(&self) -> usize {
        self.record();
        self.original.bytes()
    }
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        self.record();
        self.original.read32(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        self.record();
        self.original.write32(offset, value)
    }
}
