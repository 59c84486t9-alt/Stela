//! The storage device of a disk in use that leaves the bus after boot and
//! comes back, polled as the guest's service turns poll it: the same device
//! is started again in steps and its disk goes on; another stays unused.
use super::super::{model::*, tests::controller, *};
use crate::block::BlockDevice;
use crate::bus::dma::TestRegion;
use alloc::collections::BTreeMap;

/// Polls one return takes at most: its settle second, a millisecond apart.
const POLLS: usize = 50_000;

/// The model time one poll may take: a service turn holds its processor
/// for a few milliseconds at most (each model clock read costs 100 us).
const POLL_US: u64 = 5000;

/// The model time the poll that retires the unplugged disk may take: it
/// stops the endpoints and disables the slot with controller commands.
const RETIRE_US: u64 = 20_000;

const SERIAL: &str = "0123456789AB";

/// A high-speed Bulk-Only disk with a serial number on root port 1, started
/// at boot, its disk in use, under its runtime owner polled after boot.
struct Booted {
    model: Rc<RefCell<Hardware>>,
    shared: Shared,
    host: Host,
    dma: TestRegion,
    disk: storage::UsbDisk,
    _clock: crate::test_clock::Guard,
}

#[derive(Default)]
struct Seen {
    removed: Vec<Device>,
    unused: Vec<(String, &'static str)>,
    failures: Vec<(String, BlockError)>,
    resumed: Vec<(String, usize)>,
}

impl Booted {
    fn new() -> Self {
        let clock = crate::test_clock::virtualize();
        let mut dma = TestRegion::new(1024 * 1024 * 8);
        let mut node = Node::bot_disk(HIGH_SPEED);
        node.serial = Some(SERIAL);
        let (mut c, model) = controller(&mut dma, 32, BTreeMap::from([(0, node)]));
        model.borrow_mut().root_status = Some(PP | CCS | PED | u32::from(HIGH_SPEED) << 10);
        let mut failures = Vec::new();
        let devices = c.enumerate(&mut dma, &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(devices[0].serial.as_deref(), Some(SERIAL));
        let shared = Rc::new(RefCell::new(c));
        let mut found = Found::default();
        bind::bind(&shared, devices[0].clone(), &mut dma, &mut found);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        let mut host = Host::new(shared.clone(), &devices, &mut dma, &mut failures);
        host.keep_storage(&found.storage);
        let disk = found.disks.pop().expect("the boot's disk");
        Self {
            model,
            shared,
            host,
            dma,
            disk,
            _clock: clock,
        }
    }

    fn plug(&mut self) {
        self.model.borrow_mut().root_status = Some(PP | CCS | CSC | u32::from(HIGH_SPEED) << 10);
    }

    fn unplug(&mut self) {
        self.model.borrow_mut().root_status = Some(PP | CSC);
    }

    /// Poll as a service turn does, each poll within `bound` of model
    /// time, until the host has nothing left to do.
    fn settle(&mut self, bound: u64) -> Seen {
        let firmware = crate::firmware::HandoffProvider::new(None);
        let mut seen = Seen::default();
        for _ in 0..POLLS {
            let clock = self.shared.borrow().clock;
            let begin = clock.try_start().unwrap();
            let changes = self.host.poll_after_boot(&mut self.dma, &firmware);
            let spent = clock.try_elapsed_us(begin).unwrap();
            assert!(spent <= bound, "one poll took {spent} us");
            let mut added = changes.added;
            let any = !(added.devices.is_empty()
                && changes.removed.is_empty()
                && added.unused.is_empty()
                && added.failures.is_empty()
                && added.resumed.is_empty());
            seen.removed.extend(changes.removed);
            seen.unused.append(&mut added.unused);
            seen.failures.append(&mut added.failures);
            seen.resumed.append(&mut added.resumed);
            if !any && !self.host.due() && !self.host.attachment_due() {
                return seen;
            }
            crate::test_clock::advance(clock, 1000);
        }
        panic!("the return never settled");
    }

    /// Unplug the disk and let its owner retire it; its disk then fails.
    fn leave(&mut self) {
        self.unplug();
        let gone = self.settle(RETIRE_US);
        assert_eq!(gone.removed.len(), 1);
        assert!(self.disk.read(1, &mut [0; 512]).is_err());
    }
}

/// A flaky stick drops off the bus and comes back on its port: the same
/// device is started again in steps, no poll holding its processor, and
/// the disk the boot uses reads what was written before it left.
#[test]
fn the_device_of_a_disk_in_use_that_comes_back_is_started_again_for_it() {
    let mut booted = Booted::new();
    booted.disk.write(1, &[0x5a; 512]).unwrap();
    booted.leave();
    booted.plug();
    let back = booted.settle(POLL_US);
    assert!(back.failures.is_empty(), "{:?}", back.failures);
    assert!(back.unused.is_empty(), "{:?}", back.unused);
    assert_eq!(back.resumed.len(), 1);
    assert_eq!(back.resumed[0].1, 1);
    let mut sector = [0; 512];
    booted.disk.read(1, &mut sector).unwrap();
    assert_eq!(sector, [0x5a; 512]);
    booted.disk.write(2, &[0xa5; 512]).unwrap();
    // It may leave and come back again.
    booted.leave();
    booted.plug();
    let again = booted.settle(POLL_US);
    assert_eq!(again.resumed.len(), 1, "{:?}", again.failures);
    booted.disk.read(2, &mut sector).unwrap();
    assert_eq!(sector, [0xa5; 512]);
}

/// Another storage device at the same port, here one with another serial
/// number, is not started: it is reported unused and the disk stays ended.
#[test]
fn another_storage_device_at_the_port_of_a_disk_in_use_stays_unused() {
    let mut booted = Booted::new();
    booted.leave();
    booted.model.borrow_mut().nodes.get_mut(&0).unwrap().serial = Some("ANOTHER");
    let (requests, commands) = {
        let model = booted.model.borrow();
        (model.requests.len(), model.nodes[&0].bot_commands().len())
    };
    booted.plug();
    let other = booted.settle(POLL_US);
    assert!(other.resumed.is_empty());
    assert!(
        other
            .unused
            .iter()
            .any(|(_, why)| *why == crate::usb::xhci::AFTER_BOOT),
        "{:?}",
        other.unused
    );
    // Only enumeration's descriptor reads reached it.
    let model = booted.model.borrow();
    assert!(
        model.requests[requests..]
            .iter()
            .all(|(_, _, request)| request[1] == GET_DESCRIPTOR),
        "{:x?}",
        &model.requests[requests..]
    );
    assert_eq!(model.nodes[&0].bot_commands().len(), commands);
    drop(model);
    assert!(booted.disk.read(1, &mut [0; 512]).is_err());
}
