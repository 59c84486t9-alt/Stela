//! The erratum's lower bound cannot be shortened by the nominal deadline.
extern crate std;
use super::*;
use crate::bus::pci::power::{Error as TimeError, Timer as MinimumTimer};
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Minimum {
    physical: Rc<Cell<u64>>,
    checks: Cell<usize>,
    waits: RefCell<Vec<u64>>,
    check_error: Cell<Option<TimeError>>,
    wait_error: Cell<Option<TimeError>>,
    panic_check: Cell<bool>,
    panic_wait: Cell<bool>,
}
impl Minimum {
    fn new(physical: Rc<Cell<u64>>) -> Rc<Self> {
        Rc::new(Self {
            physical,
            checks: Cell::new(0),
            waits: RefCell::new(Vec::new()),
            check_error: Cell::new(None),
            wait_error: Cell::new(None),
            panic_check: Cell::new(false),
            panic_wait: Cell::new(false),
        })
    }
}
// SAFETY: this isolated device model owns the actual modeled physical time.
// Success advances it by at least the requested interval. No nominal timeout,
// arbitrary Clock rate or production native capability is substituted.
unsafe impl MinimumTimer for Minimum {
    fn check(&self) -> Result<(), TimeError> {
        self.checks.set(self.checks.get() + 1);
        assert!(!self.panic_check.get(), "injected minimum admission unwind");
        self.check_error.get().map_or(Ok(()), Err)
    }
    fn wait_us(&self, us: u64) -> Result<(), TimeError> {
        self.check()?;
        self.waits.borrow_mut().push(us);
        assert!(!self.panic_wait.get(), "injected first quiet wait unwind");
        if let Some(error) = self.wait_error.get() {
            return Err(error);
        }
        self.physical.set(
            self.physical
                .get()
                .checked_add(us)
                .ok_or(TimeError::Clock)?,
        );
        Ok(())
    }
}
pub(super) fn minimum(physical: Rc<Cell<u64>>) -> Rc<dyn MinimumTimer> {
    Minimum::new(physical)
}

struct TrackedRegisters {
    inner: RegisterModel,
    drops: Rc<Cell<usize>>,
}
impl Registers for TrackedRegisters {
    fn read8(&mut self, at: u8) -> u8 {
        self.inner.read8(at)
    }
    fn write8(&mut self, at: u8, value: u8) {
        self.inner.write8(at, value);
    }
}
impl Drop for TrackedRegisters {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
struct TrackedTime {
    time: Rc<Cell<u64>>,
    drops: Rc<Cell<usize>>,
    panic_admission: bool,
    panic_start: Rc<Cell<bool>>,
}
impl Timer for TrackedTime {
    fn now_us(&self) -> u64 {
        self.time.get()
    }
    fn check_duration(&self, us: u64) -> Result<(), crate::ClockError> {
        assert!(!self.panic_admission, "injected nominal admission unwind");
        if us > u64::MAX / 2 {
            Err(crate::ClockError::DurationTooLong)
        } else {
            Ok(())
        }
    }
    fn start(&self) -> u64 {
        assert!(!self.panic_start.get(), "injected nominal start unwind");
        self.time.get()
    }
    fn relax(&self) {
        self.time.set(self.time.get() + 1);
    }
}
impl Drop for TrackedTime {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
struct Inputs {
    registers: TrackedRegisters,
    nominal: TrackedTime,
    info: ControllerInfo,
    config: Config,
    minimum: Rc<Minimum>,
    state: Rc<RefCell<Model>>,
    r_drops: Rc<Cell<usize>>,
    t_drops: Rc<Cell<usize>>,
}
fn inputs(vendor: u16, device: u16) -> Inputs {
    let time = Rc::new(Cell::new(0));
    let state = Rc::new(RefCell::new(Model::new(time.clone())));
    let r_drops = Rc::new(Cell::new(0));
    let t_drops = Rc::new(Cell::new(0));
    Inputs {
        registers: TrackedRegisters {
            inner: RegisterModel(state.clone()),
            drops: r_drops.clone(),
        },
        nominal: TrackedTime {
            time: time.clone(),
            drops: t_drops.clone(),
            panic_admission: false,
            panic_start: Rc::new(Cell::new(false)),
        },
        info: ControllerInfo::from_pci_id(vendor, device, 0).unwrap(),
        config: Config {
            timeout_us: 5000,
            poll_interval_us: 250,
        },
        minimum: Minimum::new(time),
        state,
        r_drops,
        t_drops,
    }
}
struct Tracked {
    host: Piix4<TrackedRegisters, TrackedTime>,
    minimum: Rc<Minimum>,
    state: Rc<RefCell<Model>>,
    r_drops: Rc<Cell<usize>>,
    t_drops: Rc<Cell<usize>>,
}
fn tracked() -> Tracked {
    let input = inputs(0x8086, 0x7113);
    let host = Piix4::new(
        input.registers,
        input.nominal,
        input.info,
        input.config,
        input.minimum.clone(),
    )
    .unwrap();
    Tracked {
        host,
        minimum: input.minimum,
        state: input.state,
        r_drops: input.r_drops,
        t_drops: input.t_drops,
    }
}

#[test]
fn unavailable_minimum_is_typed_and_performs_no_transaction_register_access() {
    let Tracked {
        mut host,
        minimum,
        state,
        r_drops,
        t_drops,
    } = tracked();
    let writes = state.borrow().writes.clone();
    minimum.check_error.set(Some(TimeError::Clock));
    let error = host
        .transaction(address(), Transaction::SendByte(1), false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Minimum(TimeError::Clock));
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(state.borrow().writes, writes);
    assert!(state.borrow().requests.is_empty());
    assert!(host.shutdown().is_err());
    assert_eq!((r_drops.get(), t_drops.get()), (0, 0));
    assert_eq!(Rc::strong_count(&minimum), 2);
}
#[test]
fn failed_or_unwound_post_start_minimum_never_reads_status_cleans_up_or_commits_output() {
    for panics in [false, true] {
        let Tracked {
            mut host,
            minimum,
            state,
            r_drops,
            t_drops,
        } = tracked();
        if panics {
            minimum.panic_wait.set(true);
        } else {
            minimum.wait_error.set(Some(TimeError::NotReady));
        }
        let mut output = 0xa5a5;
        if panics {
            assert!(
                catch_unwind(AssertUnwindSafe(|| host.transaction(
                    address(),
                    Transaction::ReadWord {
                        command: 0x22,
                        data: &mut output
                    },
                    false
                )))
                .is_err()
            );
        } else {
            let error = host
                .transaction(
                    address(),
                    Transaction::ReadWord {
                        command: 0x22,
                        data: &mut output,
                    },
                    false,
                )
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Minimum(TimeError::NotReady));
            assert_eq!(error.recovery, Recovery::Failed);
        }
        assert_eq!(output, 0xa5a5);
        assert_eq!(*minimum.waits.borrow(), vec![250]);
        let before = state.borrow().writes.clone();
        assert!(state.borrow().active_status_reads.is_empty());
        assert_eq!(state.borrow().requests.len(), 1);
        assert_eq!(
            before.last(),
            Some(&(HOST_CONTROL, PROTOCOL_WORD_DATA | START))
        );
        assert_eq!(
            host.transaction(address(), Transaction::SendByte(2), false)
                .unwrap_err()
                .kind,
            ErrorKind::NeedsReset
        );
        assert_eq!(state.borrow().writes, before);
        assert!(host.shutdown().is_err());
        assert_eq!((r_drops.get(), t_drops.get()), (0, 0));
        assert_eq!(Rc::strong_count(&minimum), 2);
    }
}
#[test]
fn whole_constructor_graph_precedes_both_nominal_and_genuine_callbacks() {
    for nominal in [false, true] {
        let mut input = inputs(0x8086, 0x7113);
        if nominal {
            input.nominal.panic_admission = true;
        } else {
            input.minimum.panic_check.set(true);
        }
        let r_drops = input.r_drops.clone();
        let t_drops = input.t_drops.clone();
        let minimum = input.minimum.clone();
        let state = input.state.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _host = Piix4::new(
                    input.registers,
                    input.nominal,
                    input.info,
                    input.config,
                    input.minimum,
                );
            }))
            .is_err()
        );
        assert!(state.borrow().writes.is_empty());
        assert_eq!((r_drops.get(), t_drops.get()), (0, 0));
        assert_eq!(Rc::strong_count(&minimum), 2);
    }
}
#[test]
fn pre_effect_nominal_start_unwind_prevents_retry_and_preserves_all_resources() {
    let Tracked {
        mut host,
        minimum,
        state,
        r_drops,
        t_drops,
    } = tracked();
    host.resources.timer.panic_start.set(true);
    let before = state.borrow().writes.clone();
    assert!(
        catch_unwind(AssertUnwindSafe(|| host.transaction(
            address(),
            Transaction::SendByte(1),
            false
        )))
        .is_err()
    );
    assert_eq!(state.borrow().writes, before);
    assert_eq!(
        host.transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err()
            .kind,
        ErrorKind::NeedsReset
    );
    assert!(host.shutdown().is_err());
    assert_eq!((r_drops.get(), t_drops.get()), (0, 0));
    assert_eq!(Rc::strong_count(&minimum), 2);
}
struct ExpiredNominal(Rc<Cell<u64>>);
impl Timer for ExpiredNominal {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        panic!("deadline already expired after START")
    }
}
struct ExpireAtStart {
    inner: RegisterModel,
    nominal: Rc<Cell<u64>>,
}
impl Registers for ExpireAtStart {
    fn read8(&mut self, at: u8) -> u8 {
        self.inner.read8(at)
    }
    fn write8(&mut self, at: u8, value: u8) {
        self.inner.write8(at, value);
        if at == HOST_CONTROL && value & START != 0 {
            self.nominal.set(10_000);
        }
    }
}
#[test]
fn expired_nominal_budget_cannot_truncate_either_chipset_first_wait() {
    for (vendor, device, expected) in [(0x8086, 0x7113, 250), (0x1166, 0x0201, 2000)] {
        let input = inputs(vendor, device);
        let state = input.state.clone();
        let minimum = input.minimum.clone();
        let nominal = Rc::new(Cell::new(0));
        let mut host = Piix4::new(
            ExpireAtStart {
                inner: RegisterModel(state.clone()),
                nominal: nominal.clone(),
            },
            ExpiredNominal(nominal),
            input.info,
            input.config,
            minimum.clone(),
        )
        .unwrap();
        let mut output = 0xa5a5;
        let error = host
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 0x22,
                    data: &mut output,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
        assert_eq!(output, 0xa5a5);
        assert_eq!(*minimum.waits.borrow(), vec![expected]);
        assert!(state.borrow().active_status_reads[0] >= expected);
        assert_eq!(state.borrow().requests.len(), 1);
        assert!(host.shutdown().is_err());
    }
}
#[test]
fn successful_idle_drop_releases_the_complete_original_graph() {
    let Tracked {
        mut host,
        minimum,
        state,
        r_drops,
        t_drops,
    } = tracked();
    host.transaction(address(), Transaction::SendByte(1), false)
        .unwrap();
    assert!(!state.borrow().pending);
    drop(host);
    assert_eq!((r_drops.get(), t_drops.get()), (1, 1));
    assert_eq!(Rc::strong_count(&minimum), 1);
}
