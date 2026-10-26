//! Whole-operation deadlines and opaque timer markers around the actual host.
use super::*;

struct OpaqueTime(Rc<Cell<u64>>);
impl Timer for OpaqueTime {
    fn now_us(&self) -> u64 {
        (u64::MAX - 15).wrapping_add(self.0.get().wrapping_mul(10)) / 10
    }
    fn start(&self) -> u64 {
        !self.0.get()
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        self.0.get().wrapping_sub(!start)
    }
    fn relax(&self) {
        self.0.set(self.0.get() + 1);
    }
}
#[test]
fn opaque_intervals_preserve_real_first_poll_and_complete_across_divided_rollover() {
    let (old, state) = controller(0x8086, 0x7113, 0);
    let Piix4 {
        registers,
        timer,
        info,
        config,
        ..
    } = old;
    let mut host = Piix4::new(registers, OpaqueTime(timer.0), info, config).unwrap();
    let mut value = 0xa5a5;
    host.transaction(
        address(),
        Transaction::ReadWord {
            command: 0x22,
            data: &mut value,
        },
        false,
    )
    .unwrap();
    assert_eq!(value, 0xabcd);
    assert_eq!(state.borrow().requests.len(), 1);
    assert!(state.borrow().active_status_reads[0] >= 250);
    assert_eq!(state.borrow().status, OTHER_STATUS);
    assert!(host.shutdown().is_ok());
}

struct Late {
    registers: RegisterModel,
    stage: u8,
    armed: Rc<Cell<bool>>,
    fired: bool,
}
impl Late {
    fn advance(&mut self, write: bool, at: u8, value: u8) {
        if !self.armed.get() || self.fired {
            return;
        }
        let h = self.registers.0.borrow();
        let trigger = match self.stage {
            0 => write && at == HOST_ADDRESS,
            1 => !write && at == HOST_DATA1,
            2 => !write && at == BLOCK_DATA && h.block_index == h.reply_block.len(),
            3 => write && at == HOST_CONTROL && value == 0 && !h.requests.is_empty() && !h.pending,
            _ => false,
        };
        if trigger {
            h.time.set(h.time.get() + 10_000);
            self.fired = true;
        }
    }
}
impl Registers for Late {
    fn read8(&mut self, at: u8) -> u8 {
        let value = self.registers.read8(at);
        self.advance(false, at, value);
        value
    }
    fn write8(&mut self, at: u8, value: u8) {
        self.registers.write8(at, value);
        self.advance(true, at, value);
    }
}
#[test]
fn preload_final_data_and_cleanup_are_inside_one_deadline_without_early_output_or_replay() {
    for stage in 0..4 {
        let (old, state) = controller(0x8086, 0x7113, 0);
        let Piix4 {
            registers,
            timer,
            info,
            config,
            ..
        } = old;
        let armed = Rc::new(Cell::new(false));
        let mut host = Piix4::new(
            Late {
                registers,
                stage,
                armed: armed.clone(),
                fired: false,
            },
            timer,
            info,
            config,
        )
        .unwrap();
        armed.set(true);
        let mut word = 0xa5a5;
        let mut block = Block::from_slice(&[0xa5, 0x5a]).unwrap();
        let request = if stage == 2 {
            Transaction::ReadBlock {
                command: 0x22,
                data: &mut block,
            }
        } else {
            Transaction::ReadWord {
                command: 0x22,
                data: &mut word,
            }
        };
        let error = host.transaction(address(), request, false).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
        assert_eq!(error.recovery, Recovery::Cleared);
        assert_eq!(word, 0xa5a5);
        assert_eq!(block.as_slice(), &[0xa5, 0x5a]);
        assert_eq!(state.borrow().requests.len(), usize::from(stage != 0));
        assert!(!state.borrow().pending);
        assert_eq!(state.borrow().status, OTHER_STATUS);
        assert!(host.shutdown().is_ok());
    }
}

#[test]
fn completion_observed_at_the_expired_boundary_is_not_reported_as_success() {
    let (old, state) = controller(0x8086, 0x7113, 0);
    let Piix4 {
        registers,
        timer,
        info,
        mut config,
        ..
    } = old;
    config.timeout_us = 250;
    state.borrow_mut().latency = 250;
    let mut host = Piix4::new(registers, timer, info, config).unwrap();
    let mut value = 0xa5a5;
    let error = host
        .transaction(
            address(),
            Transaction::ReadWord {
                command: 0x22,
                data: &mut value,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(value, 0xa5a5);
    assert_eq!(state.borrow().requests.len(), 1);
    assert!(!state.borrow().pending);
    assert!(
        host.shutdown().is_err(),
        "started timeout retains the original controller for reset"
    );
}
