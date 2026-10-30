//! Independent ACP immediate-register and byte-addressed peripheral peers.
use super::*;
mod oracle;
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Clone, Copy, Debug)]
struct Access {
    at: usize,
    value: u32,
    write: bool,
    time: u64,
}
struct Hardware {
    manager: Manager,
    upper: u32,
    response: u64,
    status: u32,
    page: [u8; 2],
    memory: BTreeMap<(u8, u8, u16), u8>,
    commands: Vec<(u8, u16, Option<u8>)>,
    trace: Vec<Access>,
    time: Rc<Cell<u64>>,
    ready: bool,
    fail: Option<(usize, bool)>,
    late: Option<usize>,
    accesses: usize,
    response_bits: u32,
    response_at: Option<usize>,
    response_after: u64,
    delay_at: Option<usize>,
    active_delay: u64,
    response_pending: Option<u64>,
    response_read_stage: u8,
    stuck_busy: bool,
    stuck_valid: bool,
    drops: Rc<Cell<usize>>,
}
impl Hardware {
    fn new(manager: Manager) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            manager,
            upper: 0,
            response: 0,
            status: 0,
            page: [0; 2],
            memory: BTreeMap::new(),
            commands: Vec::new(),
            trace: Vec::new(),
            time: Rc::new(Cell::new(0)),
            ready: true,
            fail: None,
            late: None,
            accesses: 0,
            response_bits: 1,
            response_at: None,
            response_after: 0,
            delay_at: None,
            active_delay: 0,
            response_pending: None,
            response_read_stage: 0,
            stuck_busy: false,
            stuck_valid: false,
            drops: Rc::new(Cell::new(0)),
        }))
    }
    fn at(&self, offset: usize) -> usize {
        offset
            - match self.manager {
                Manager::First => 0,
                Manager::Second => 0xc00,
            }
    }
    fn before(&mut self) -> Result<(), IoError> {
        self.accesses += 1;
        if self.fail == Some((self.accesses, false)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn after(&mut self) -> Result<(), IoError> {
        if self.late == Some(self.accesses) {
            self.time.set(self.time.get().wrapping_add(100_000));
        }
        if self.fail == Some((self.accesses, true)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, at: usize) -> Result<u32, IoError> {
        self.before()?;
        let relative = self.at(at);
        let value = match relative {
            0x3000 | 0x3004 => u32::from(self.ready),
            0x3180 | 0x3188 | 0x3264 | 0x3268 | 0x3270 => 0,
            0x3240 => {
                if self
                    .response_pending
                    .is_some_and(|start| self.time.get().wrapping_sub(start) >= self.active_delay)
                {
                    self.status = 1;
                    self.response_pending = None;
                }
                if self.stuck_busy { 2 } else { self.status }
            }
            0x3238 => {
                assert_eq!(self.status & 1, 1, "response before observedVALID");
                assert_eq!(self.response_read_stage, 0, "upper response first");
                self.response_read_stage = 1;
                (self.response >> 32) as u32
            }
            0x323c => {
                assert_eq!(self.status & 1, 1);
                assert_eq!(self.response_read_stage, 1, "lower response after upper");
                self.response_read_stage = 2;
                self.response as u32
            }
            _ => panic!("unexpected ACP read {relative:x}"),
        };
        self.trace.push(Access {
            at,
            value,
            write: false,
            time: self.time.get(),
        });
        self.after()?;
        Ok(value)
    }
    fn write(&mut self, at: usize, value: u32) -> Result<(), IoError> {
        self.before()?;
        let relative = self.at(at);
        self.trace.push(Access {
            at,
            value,
            write: true,
            time: self.time.get(),
        });
        match relative {
            0x3230 => self.upper = value,
            0x3234 => {
                assert_eq!(self.status & 3, 0, "trigger with foreign/pending reply");
                let command = (self.upper >> 12) & 7;
                assert!(matches!(command, 2 | 3));
                let device = ((self.upper >> 8) & 15) as u8;
                let address = ((self.upper & 255) << 8 | value >> 24) as u16;
                let data = (value >> 7) as u8;
                self.commands
                    .push((device, address, (command == 3).then_some(data)));
                let byte = if command == 3 {
                    if (0x48..=0x49).contains(&address) {
                        self.page[usize::from(address - 0x48)] = data;
                    } else {
                        self.memory
                            .insert((self.page[0], self.page[1], address), data);
                    }
                    0
                } else {
                    *self
                        .memory
                        .get(&(self.page[0], self.page[1], address))
                        .unwrap_or(&0x97)
                };
                // Nonzero upper reply checks actual64bit packing without
                // treating unrelated upper bits as another ACK/data word.
                let ordinal = self.commands.len() - 1;
                let response_bits = if self.response_at.is_none_or(|at| at == ordinal) {
                    self.response_bits
                } else {
                    1
                };
                self.active_delay = if self.delay_at.is_none_or(|at| at == ordinal) {
                    self.response_after
                } else {
                    0
                };
                self.response =
                    0xa55a_1234_0000_0000 | u64::from(byte) << 7 | u64::from(response_bits);
                self.status = 2;
                self.response_read_stage = 0;
                self.response_pending = Some(self.time.get());
            }
            0x3240 => {
                assert_eq!(value, 1, "W1C must preserve unrelated status bits");
                assert_eq!(self.status & 1, 1);
                assert_eq!(
                    self.response_read_stage, 2,
                    "clear only after complete response"
                );
                if !self.stuck_valid {
                    self.status &= !1;
                }
            }
            _ => panic!("unexpected ACP write {relative:x}"),
        }
        self.after()
    }
}
struct RegistersPeer(Rc<RefCell<Hardware>>);
impl Drop for RegistersPeer {
    fn drop(&mut self) {
        let count = self.0.borrow().drops.clone();
        count.set(count.get() + 1);
    }
}
// SAFETY: this independent exclusive peer owns its complete modeled link and
// decodes effects independently of the controller's command helpers.
unsafe impl Registers for RegistersPeer {
    fn manager(&self) -> Manager {
        self.0.borrow().manager
    }
    fn bytes(&self) -> usize {
        0x4000
    }
    fn read32(&mut self, at: usize) -> Result<u32, IoError> {
        self.0.borrow_mut().read(at)
    }
    fn write32(&mut self, at: usize, value: u32) -> Result<(), IoError> {
        self.0.borrow_mut().write(at, value)
    }
}
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    // Unusable absolute quotient: all intervals must use origins.
    fn now_us(&self) -> u64 {
        panic!("absolute divided timer used")
    }
    fn start(&self) -> u64 {
        self.0.get()
    }
    fn elapsed_us(&self, origin: u64) -> u64 {
        self.0.get().wrapping_sub(origin)
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
fn controller(chip: &Rc<RefCell<Hardware>>, timeout: u64) -> Controller<RegistersPeer, Time> {
    Controller::new(
        RegistersPeer(chip.clone()),
        Time(chip.borrow().time.clone()),
        timeout,
    )
    .ok()
    .unwrap()
}
fn message(page: bool) -> Message {
    Message {
        device: 11,
        address: 0x38f8,
        page: page.then_some([0x12, 0xab]),
    }
}

#[test]
fn amd_immediate_two_managers_changed_page_payloads_and_exact_trigger_retirement() {
    for manager in [Manager::First, Manager::Second] {
        let chip = Hardware::new(manager);
        chip.borrow().time.set(u64::MAX - 7);
        chip.borrow_mut().response_after = 20;
        let mut host = controller(&chip, 100_000);
        let bytes: Vec<_> = (0..65).map(|v| v ^ 0x75).collect();
        host.write_registers(message(true), &bytes).unwrap();
        let mut output = [0xa5; 65];
        host.read_registers(message(true), &mut output).unwrap();
        assert_eq!(output.as_slice(), bytes.as_slice());
        assert_eq!(host.completed, 67);
        let owners = host.release().ok().unwrap();
        assert_eq!(chip.borrow().drops.get(), 0);
        drop(owners);
        assert_eq!(chip.borrow().drops.get(), 1);
        let h = chip.borrow();
        assert_eq!(h.commands.len(), 134);
        for (index, access) in h
            .trace
            .iter()
            .enumerate()
            .filter(|(_, a)| a.write && h.at(a.at) == 0x3234)
        {
            let before = &h.trace[index - 1];
            assert!(before.write && h.at(before.at) == 0x3230);
            assert!(matches!(before.value >> 12, 2 | 3));
            let status = &h.trace[index + 1];
            assert!(!status.write && h.at(status.at) == 0x3240);
            assert_eq!(status.value & 1, 0);
            let ack = h.trace[index + 1..]
                .iter()
                .find(|a| a.write && h.at(a.at) == 0x3240)
                .unwrap();
            assert_eq!(ack.value, 1);
            assert!(ack.time.wrapping_sub(access.time) >= 20);
        }
    }
}

#[test]
fn amd_immediate_ack_first_source_policy_nack_missing_and_page_failure_are_explicit() {
    for bits in [0, 1, 2, 3] {
        let chip = Hardware::new(Manager::First);
        chip.borrow_mut().response_bits = bits;
        let mut host = controller(&chip, 100_000);
        let mut output = [0xa5; 2];
        let result = host.read_registers(message(false), &mut output);
        if bits & 1 != 0 {
            result.unwrap();
            assert_eq!(output, [0x97; 2]);
            drop(host.release().ok().unwrap());
        } else {
            assert_eq!(
                result.unwrap_err().kind,
                if bits == 2 {
                    ErrorKind::Nack
                } else {
                    ErrorKind::Ignored
                }
            );
            assert_eq!(output, [0xa5; 2]);
            assert_eq!(chip.borrow().status, 0);
            assert!(host.release().is_err());
            assert_eq!(chip.borrow().drops.get(), 0);
        }
    }
    let chip = Hardware::new(Manager::First);
    chip.borrow_mut().response_bits = 2;
    let mut host = controller(&chip, 100_000);
    assert!(host.write_registers(message(true), &[1]).is_err());
    assert_eq!(chip.borrow().commands, vec![(11, 0x48, Some(0x12))]);
    assert_eq!(host.failure().unwrap().completed, 0);
}

#[test]
fn amd_immediate_foreign_busy_response_and_clear_timeouts_never_publish_or_replay() {
    for fault in 0..4 {
        let chip = Hardware::new(Manager::Second);
        {
            let mut h = chip.borrow_mut();
            match fault {
                0 => h.status = 1,
                1 => h.stuck_busy = true,
                2 => h.response_after = 2_000,
                _ => h.stuck_valid = true,
            }
        }
        let mut host = controller(&chip, 100_000);
        let mut output = [0xa5; 4];
        let error = host
            .read_registers(message(false), &mut output)
            .unwrap_err();
        assert_eq!(output, [0xa5; 4]);
        assert_eq!(
            error.kind,
            if fault == 0 {
                ErrorKind::ForeignResponse
            } else {
                ErrorKind::Timeout
            }
        );
        assert_eq!(error.issued, fault >= 2);
        let calls = chip.borrow().accesses;
        assert_eq!(
            host.read_registers(message(false), &mut output)
                .unwrap_err()
                .kind,
            ErrorKind::Faulted
        );
        assert_eq!(chip.borrow().accesses, calls);
        assert!(host.release().is_err());
        assert_eq!(chip.borrow().drops.get(), 0);
    }
}

#[test]
fn amd_immediate_each_access_fault_or_lateness_stages_output_and_keeps_original_owner() {
    let baseline = Hardware::new(Manager::First);
    controller(&baseline, 100_000)
        .read_registers(message(true), &mut [0; 3])
        .unwrap();
    let accesses = baseline.borrow().accesses;
    for at in 1..=accesses {
        for after in [false, true] {
            let chip = Hardware::new(Manager::First);
            chip.borrow_mut().fail = Some((at, after));
            let mut host = controller(&chip, 100_000);
            let mut output = [0xa5; 3];
            assert_eq!(
                host.read_registers(message(true), &mut output)
                    .unwrap_err()
                    .kind,
                ErrorKind::Io
            );
            assert_eq!(output, [0xa5; 3]);
            assert!(host.release().is_err());
            assert_eq!(chip.borrow().drops.get(), 0);
        }
        let chip = Hardware::new(Manager::First);
        chip.borrow_mut().late = Some(at);
        let mut host = controller(&chip, 100_000);
        let mut output = [0xa5; 3];
        assert_eq!(
            host.read_registers(message(true), &mut output)
                .unwrap_err()
                .kind,
            ErrorKind::Timeout
        );
        assert_eq!(output, [0xa5; 3]);
        assert!(host.release().is_err());
        assert_eq!(chip.borrow().drops.get(), 0);
    }
}

#[test]
fn amd_immediate_invalid_native_timers_and_lengths_refuse_before_register_effects() {
    struct NoIo;
    // SAFETY: no access is legal or provided; constructor must refuse first.
    unsafe impl Registers for NoIo {
        fn manager(&self) -> Manager {
            panic!("geometry before timer validation")
        }
        fn bytes(&self) -> usize {
            panic!("geometry before timer validation")
        }
        fn read32(&mut self, _: usize) -> Result<u32, IoError> {
            panic!("read")
        }
        fn write32(&mut self, _: usize, _: u32) -> Result<(), IoError> {
            panic!("write")
        }
    }
    for rate in [0, u64::MAX, u64::MAX / 2] {
        assert!(
            Controller::new(
                NoIo,
                crate::Clock {
                    ticks_per_microsecond: rate
                },
                100_000
            )
            .is_err()
        );
    }
    let chip = Hardware::new(Manager::First);
    let mut host = controller(&chip, 100_000);
    for (msg, bytes) in [
        (
            Message {
                device: 16,
                ..message(false)
            },
            vec![1],
        ),
        (message(false), vec![]),
        (
            Message {
                address: u16::MAX,
                ..message(false)
            },
            vec![1; 2],
        ),
    ] {
        assert_eq!(
            host.write_registers(msg, &bytes).unwrap_err().kind,
            ErrorKind::Length
        );
    }
    assert_eq!(chip.borrow().accesses, 0);
    drop(host.release().ok().unwrap());
    assert_eq!(chip.borrow().drops.get(), 1);
}

#[test]
fn amd_immediate_original_whole_budget_bounds_multiple_successful_byte_phases() {
    let chip = Hardware::new(Manager::Second);
    chip.borrow_mut().response_after = 200;
    let mut host = controller(&chip, 500);
    let mut output = [0xa5; 4];
    let error = host
        .read_registers(message(false), &mut output)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert_eq!(error.completed, 2);
    assert_eq!(chip.borrow().commands.len(), 3);
    assert_eq!(output, [0xa5; 4]);
    let trace = &chip.borrow().trace;
    let observations: Vec<_> = trace
        .iter()
        .filter(|a| !a.write && a.at == 0x3e40)
        .collect();
    assert!(observations.windows(2).all(|pair| {
        let elapsed = pair[1].time.wrapping_sub(pair[0].time);
        elapsed == 0 || elapsed == 10
    }));
    drop(host);
    assert_eq!(chip.borrow().drops.get(), 0);

    let chip = Hardware::new(Manager::First);
    chip.borrow_mut().ready = false;
    let mut host = controller(&chip, 100_000);
    assert_eq!(
        host.read_registers(message(false), &mut output)
            .unwrap_err()
            .kind,
        ErrorKind::Link
    );
    assert!(chip.borrow().commands.is_empty());
    assert!(host.release().is_err());
    assert_eq!(chip.borrow().drops.get(), 0);
}
