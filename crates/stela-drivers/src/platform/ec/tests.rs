//! Independent EC peripheral model: staged command/data handshakes and RAM,
//! not a copy of the driver's wait loops.
use super::*;
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};

struct Peripheral {
    time: Rc<Cell<u64>>,
    locked: bool,
    lock_acquires: usize,
    lock_releases: usize,
    fail_acquire: bool,
    fail_release: bool,
    ram: [u8; 256],
    status: u8,
    command: u8,
    address: Option<u8>,
    output: u8,
    pending: Option<(u64, bool, u8)>,
    commands: Vec<u8>,
    queries: VecDeque<u8>,
    freeze: bool,
    freeze_output: bool,
    freeze_disable: bool,
    bad_ack: bool,
    fail_access: Option<usize>,
    accesses: usize,
    effect_failure: Option<usize>,
    access_times: Vec<u64>,
}
impl Peripheral {
    fn access(&mut self) -> Result<(), IoError> {
        assert!(
            self.locked,
            "register transaction outside firmware arbitration"
        );
        self.accesses += 1;
        self.access_times.push(self.time.get());
        if self.fail_access == Some(self.accesses) {
            return Err(IoError);
        }
        self.step();
        Ok(())
    }
    fn emit(&mut self, value: u8) {
        if !self.freeze_output {
            self.output = value;
            self.status |= OBF;
        }
    }
    fn step(&mut self) {
        if self.freeze {
            return;
        }
        let Some((due, command, value)) = self.pending else {
            return;
        };
        if self.time.get() < due {
            return;
        }
        self.pending = None;
        self.status &= !IBF;
        if command {
            self.command = value;
            self.address = None;
            match value {
                READ | WRITE => {}
                QUERY => {
                    let value = self.queries.pop_front().unwrap_or(0);
                    if self.queries.is_empty() {
                        self.status &= !SCI;
                    }
                    self.emit(value);
                }
                BURST_ENABLE => {
                    self.status |= BURST;
                    self.emit(if self.bad_ack { 0x91 } else { BURST_ACK });
                }
                BURST_DISABLE => {
                    self.status &= !BURST;
                }
                _ => panic!("unknown hardware command"),
            }
        } else {
            match (self.command, self.address) {
                (READ, None) => self.emit(self.ram[usize::from(value)]),
                (WRITE, None) => self.address = Some(value),
                (WRITE, Some(address)) => self.ram[usize::from(address)] = value,
                _ => panic!("unexpected input byte"),
            }
        }
    }
    fn input(&mut self, command: bool, value: u8) -> Result<(), IoError> {
        self.access()?;
        assert_eq!(self.status & IBF, 0, "overwrote unconsumed input");
        self.status |= IBF;
        self.pending = Some((self.time.get() + 3, command, value));
        if command {
            self.commands.push(value);
            if value == BURST_DISABLE && self.freeze_disable {
                self.freeze = true;
            }
        }
        if self.effect_failure == Some(self.accesses) {
            return Err(IoError);
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Model(Rc<RefCell<Peripheral>>);
impl Registers for Model {
    fn status(&mut self) -> Result<u8, IoError> {
        let mut m = self.0.borrow_mut();
        m.access()?;
        Ok(m.status)
    }
    fn read_data(&mut self) -> Result<u8, IoError> {
        let mut m = self.0.borrow_mut();
        m.access()?;
        assert_ne!(m.status & OBF, 0);
        m.status &= !OBF;
        if m.effect_failure == Some(m.accesses) {
            return Err(IoError);
        }
        Ok(m.output)
    }
    fn command(&mut self, value: u8) -> Result<(), IoError> {
        self.0.borrow_mut().input(true, value)
    }
    fn write_data(&mut self, value: u8) -> Result<(), IoError> {
        self.0.borrow_mut().input(false, value)
    }
}
struct Gate(Rc<RefCell<Peripheral>>);
impl FirmwareLock for Gate {
    fn acquire(&mut self, _: u64) -> Result<(), LockError> {
        let mut m = self.0.borrow_mut();
        m.lock_acquires += 1;
        if m.fail_acquire {
            return Err(LockError);
        }
        assert!(!m.locked);
        m.locked = true;
        Ok(())
    }
    fn release(&mut self) -> Result<(), LockError> {
        let mut m = self.0.borrow_mut();
        m.lock_releases += 1;
        assert!(m.locked);
        if m.fail_release {
            return Err(LockError);
        }
        m.locked = false;
        Ok(())
    }
}
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
type Controller = Ec<Model, Time, Gate>;
fn model(burst: bool) -> (Controller, Rc<RefCell<Peripheral>>) {
    let time = Rc::new(Cell::new(0));
    let m = Rc::new(RefCell::new(Peripheral {
        time: time.clone(),
        locked: false,
        lock_acquires: 0,
        lock_releases: 0,
        fail_acquire: false,
        fail_release: false,
        ram: core::array::from_fn(|i| i as u8 ^ 0xa5),
        status: 0,
        command: 0,
        address: None,
        output: 0,
        pending: None,
        commands: Vec::new(),
        queries: VecDeque::new(),
        freeze: false,
        freeze_output: false,
        freeze_disable: false,
        bad_ack: false,
        fail_access: None,
        accesses: 0,
        effect_failure: None,
        access_times: Vec::new(),
    }));
    let config = Config {
        timeout_us: 100,
        lock_timeout_us: 20,
        recovery_timeout_us: 30,
        polling_guard_us: 1,
        burst,
    };
    (
        Ec::new(Model(m.clone()), Time(time), Gate(m.clone()), config).unwrap(),
        m,
    )
}
#[test]
fn read_write_every_byte_and_multibyte_regions_use_real_commands() {
    for burst in [false, true] {
        let (mut ec, m) = model(burst);
        for address in 0..=255u8 {
            assert_eq!(ec.read(address).unwrap(), address ^ 0xa5);
            ec.write(address, address).unwrap();
            assert_eq!(ec.read(address).unwrap(), address);
        }
        for width in [8, 16, 32, 64] {
            let address = 256 - width / 8;
            let value = 0x0123_4567_89ab_cdefu64;
            ec.write_region(u64::from(address), width, value).unwrap();
            let mask = u64::MAX >> (64 - width);
            assert_eq!(
                ec.read_region(u64::from(address), width).unwrap(),
                value & mask
            );
        }
        assert!(!m.borrow().locked);
        assert_eq!(m.borrow().status & BURST, 0);
        assert_eq!(m.borrow().lock_acquires, m.borrow().lock_releases);
        assert_eq!(m.borrow().commands.contains(&BURST_ENABLE), burst);
    }
}
#[test]
fn query_preserves_actual_event_identity_and_zero_has_no_method() {
    let (mut ec, m) = model(false);
    m.borrow_mut().queries.extend([0x17, 0xa2]);
    m.borrow_mut().status |= SCI;
    assert!(ec.event_pending().unwrap());
    assert_eq!(ec.query().unwrap(), Some(0x17));
    assert_eq!(ec.query().unwrap(), Some(0xa2));
    assert_eq!(ec.query().unwrap(), None);
    assert_eq!(m.borrow().status & SCI, 0);
    assert!(!ec.event_pending().unwrap());
}
#[test]
fn invalid_regions_and_failed_firmware_lock_have_no_register_effect() {
    let (mut ec, m) = model(false);
    for (address, width) in [(256, 8), (255, 16), (u64::MAX, 8), (0, 7), (0, 128)] {
        assert_eq!(
            ec.read_region(address, width).unwrap_err().kind,
            ErrorKind::InvalidRegion
        );
        assert_eq!(
            ec.write_region(address, width, 0).unwrap_err().kind,
            ErrorKind::InvalidRegion
        );
    }
    assert_eq!(m.borrow().accesses, 0);
    m.borrow_mut().fail_acquire = true;
    assert_eq!(ec.write(4, 5).unwrap_err().kind, ErrorKind::FirmwareLock);
    assert_eq!(m.borrow().accesses, 0);
    assert_eq!(m.borrow().lock_releases, 0);
}
#[test]
fn another_owner_output_or_burst_is_not_consumed() {
    for status in [OBF, BURST] {
        let (mut ec, m) = model(false);
        m.borrow_mut().status = status;
        assert_eq!(ec.read(1).unwrap_err().kind, ErrorKind::Busy);
        assert!(m.borrow().commands.is_empty());
        assert_eq!(m.borrow().status, status);
        assert!(!ec.needs_reset());
        assert!(!m.borrow().locked);
    }
}
#[test]
fn prepublication_timeout_can_retry_but_uncertain_command_cannot() {
    let (mut ec, m) = model(false);
    m.borrow_mut().status = IBF;
    let error = ec.read(1).unwrap_err();
    assert!(!error.published);
    assert!(!ec.needs_reset());
    assert!(m.borrow().commands.is_empty());
    m.borrow_mut().status = 0;
    m.borrow_mut().freeze = true;
    let error = ec.write(1, 2).unwrap_err();
    assert!(error.published);
    assert!(ec.needs_reset());
    assert!(!m.borrow().locked);
    let accesses = m.borrow().accesses;
    assert_eq!(ec.read(1).unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(m.borrow().accesses, accesses);
}
#[test]
fn burst_bad_ack_is_disabled_and_original_error_retained() {
    let (mut ec, m) = model(true);
    m.borrow_mut().bad_ack = true;
    let error = ec.read_region(0, 16).unwrap_err();
    assert_eq!(error.kind, ErrorKind::BurstAcknowledgement(0x91));
    assert!(!error.burst_cleanup_failed);
    assert_eq!(
        m.borrow().commands.as_slice(),
        [BURST_ENABLE, BURST_DISABLE]
    );
    assert_eq!(m.borrow().status & BURST, 0);
    assert!(ec.needs_reset());
    assert!(!m.borrow().locked);
}
#[test]
fn failure_after_publishing_never_replays_or_returns_partial_region() {
    let (mut ec, m) = model(false);
    m.borrow_mut().freeze_output = true;
    let error = ec.read_region(1, 64).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Output));
    assert!(ec.needs_reset());
    assert_eq!(m.borrow().commands.as_slice(), [READ]);
}
#[test]
fn every_io_fault_and_firmware_unlock_failure_retains_failure() {
    let (mut baseline, m) = model(false);
    baseline.read(3).unwrap();
    let total = m.borrow().accesses;
    for fail in 1..=total {
        let (mut ec, m) = model(false);
        m.borrow_mut().fail_access = Some(fail);
        let error = ec.read(3).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Io);
        assert!(!m.borrow().locked);
        if error.published {
            assert!(ec.needs_reset());
        }
    }
    let (mut ec, m) = model(false);
    m.borrow_mut().fail_release = true;
    let error = ec.write(3, 4).unwrap_err();
    assert!(error.lock_release_failed);
    assert!(ec.needs_reset());
    assert_eq!(m.borrow().ram[3], 4);
    let acquisitions = m.borrow().lock_acquires;
    assert_eq!(ec.read(3).unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(m.borrow().lock_acquires, acquisitions);
}

#[test]
fn region_deadline_covers_all_bytes_and_failed_enable_is_cleaned_up() {
    let (mut ec, m) = model(false);
    ec.config.timeout_us = 20;
    let error = ec.read_region(0, 64).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Timeout(_)));
    assert!(m.borrow().time.get() < 30);
    assert!(ec.needs_reset());

    let (mut ec, m) = model(true);
    m.borrow_mut().freeze_output = true;
    let error = ec.read_region(0, 16).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Output));
    // BURST_ENABLE took effect but its response never reached OBF. The
    // acknowledged disable cleans the actual flag before releasing the lock.
    assert!(!error.burst_cleanup_failed);
    assert_eq!(m.borrow().status & BURST, 0);
    assert!(!m.borrow().locked);
    assert!(ec.needs_reset());
}

#[test]
fn failed_burst_disable_keeps_original_error_and_never_claims_reuse() {
    for bad_ack in [false, true] {
        let (mut ec, m) = model(true);
        m.borrow_mut().bad_ack = bad_ack;
        m.borrow_mut().freeze_disable = true;
        let error = ec.read_region(0, 16).unwrap_err();
        if bad_ack {
            assert_eq!(error.kind, ErrorKind::BurstAcknowledgement(0x91));
        } else {
            assert!(matches!(error.kind, ErrorKind::Timeout(_)));
        }
        assert!(error.burst_cleanup_failed);
        assert!(ec.needs_reset());
        assert_ne!(m.borrow().status & BURST, 0);
        assert!(!m.borrow().locked);
        let count = m.borrow().accesses;
        assert_eq!(ec.read(0).unwrap_err().kind, ErrorKind::NeedsReset);
        assert_eq!(m.borrow().accesses, count);
    }
}

#[test]
fn inherited_input_completion_is_not_mistaken_for_our_response() {
    let (mut ec, m) = model(false);
    // A pre-handoff firmware query is still in IBF and emits a byte later.
    // Exclusive ownership prevents new competing producers, not this old byte.
    m.borrow_mut().status = IBF;
    m.borrow_mut().queries.push_back(0x99);
    m.borrow_mut().pending = Some((3, true, QUERY));
    let error = ec.read(7).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Busy);
    assert!(!error.published);
    assert!(m.borrow().commands.is_empty());
    assert_eq!(m.borrow().output, 0x99);
    assert_ne!(m.borrow().status & OBF, 0);
    assert!(!ec.needs_reset());
}

#[test]
fn effect_then_error_keeps_guard_before_burst_cleanup_accesses() {
    // Exercise every command/input/output data access from a successful burst
    // region, with an error returned only AFTER that register's hardware effect.
    let (mut baseline, m) = model(true);
    baseline.config.polling_guard_us = 10;
    baseline.config.timeout_us = 500;
    baseline.read_region(0, 16).unwrap();
    let count = m.borrow().accesses;
    let mut effect_failures = 0;
    for failure in 1..=count {
        let (mut ec, m) = model(true);
        ec.config.polling_guard_us = 10;
        ec.config.timeout_us = 500;
        m.borrow_mut().effect_failure = Some(failure);
        // Status reads do not inject an effect-then-error failure.
        if let Err(error) = ec.read_region(0, 16) {
            effect_failures += 1;
            assert_eq!(error.kind, ErrorKind::Io);
            assert!(ec.needs_reset());
            let times = &m.borrow().access_times;
            if let Some(next) = times.get(failure) {
                assert!(
                    *next - times[failure - 1] >= 10,
                    "recovery accessed registers before guard after effect at {failure}"
                );
            }
            assert!(!m.borrow().locked);
        }
    }
    // Burst command/ACK, two READ command/address/data triples, disable command.
    assert_eq!(effect_failures, 9);
}
