use super::*;
use alloc::{rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};

const ALERT: u8 = 1 << 5;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Request {
    protocol: u8,
    address: u8,
    command: u8,
    word: u16,
    block: Vec<u8>,
}

/// Hardware model with an independent peripheral response, read-to-acquire
/// INUSE semaphore, W1C status and byte-by-byte SCL holding until BYTE_DONE is
/// acknowledged. The production driver is the only bus transaction engine.
struct Model {
    registers: [u8; 32],
    status: u8,
    time: Rc<Cell<u64>>,
    due: u64,
    latency: u64,
    requests: Vec<Request>,
    writes: Vec<(u8, u8)>,
    reply: Vec<u8>,
    reply_word: u16,
    count: usize,
    byte: usize,
    buffer: [u8; MAX_BLOCK],
    buffer_index: usize,
    staged_byte: Option<u8>,
    read: bool,
    block: bool,
    buffered: bool,
    active: bool,
    kill_at: Option<u64>,
    kills: usize,
    freeze: bool,
    freeze_kill: bool,
    kill_without_failed: bool,
    error: u8,
    error_byte: Option<usize>,
    premature_intr: Option<usize>,
    stuck_status: u8,
    refuse_buffer: bool,
    auxiliary_present: bool,
}

impl Model {
    fn new(time: Rc<Cell<u64>>, auxiliary_present: bool) -> Self {
        Self {
            registers: [0; 32],
            status: ALERT,
            time,
            due: 0,
            latency: 3,
            requests: Vec::new(),
            writes: Vec::new(),
            reply: vec![5, 6, 7],
            reply_word: 0x9876,
            count: 0,
            byte: 0,
            buffer: [0; MAX_BLOCK],
            buffer_index: 0,
            staged_byte: None,
            read: false,
            block: false,
            buffered: false,
            active: false,
            kill_at: None,
            kills: 0,
            freeze: false,
            freeze_kill: false,
            kill_without_failed: false,
            error: 0,
            error_byte: None,
            premature_intr: None,
            stuck_status: 0,
            refuse_buffer: false,
            auxiliary_present,
        }
    }

    fn complete(&mut self) {
        self.active = false;
        self.status &= !HOST_BUSY;
        if self.error == 0 {
            self.status |= INTR;
        } else {
            self.status |= self.error;
        }
    }

    fn step(&mut self) {
        let now = self.time.get();
        if self.kill_at.is_some_and(|at| now >= at) {
            self.kill_at = None;
            self.active = false;
            self.status &= !(HOST_BUSY | BYTE_DONE);
            if !self.kill_without_failed {
                self.status |= FAILED;
            }
        }
        if !self.active || self.freeze || now < self.due || self.status & BYTE_DONE != 0 {
            return;
        }
        if self.premature_intr == Some(self.byte) {
            self.active = false;
            self.status &= !HOST_BUSY;
            self.status |= INTR;
            return;
        }
        if self.error_byte == Some(self.byte) || (!self.block && self.error != 0) {
            self.status |= self.error;
            self.active = false;
            self.status &= !HOST_BUSY;
            return;
        }
        if !self.block {
            let [low, high] = self.reply_word.to_le_bytes();
            self.registers[usize::from(HOST_DATA0)] = low;
            self.registers[usize::from(HOST_DATA1)] = high;
            self.complete();
        } else if self.buffered {
            if self.read {
                self.registers[usize::from(HOST_DATA0)] = self.reply.len() as u8;
                for (to, &from) in self.buffer.iter_mut().zip(&self.reply) {
                    *to = from;
                }
            } else {
                self.requests.last_mut().unwrap().block = self.buffer[..self.count].to_vec();
            }
            self.complete();
        } else {
            if self.read {
                self.registers[usize::from(HOST_DATA0)] = self.reply.len() as u8;
                self.registers[usize::from(BLOCK_DATA)] =
                    self.reply.get(self.byte).copied().unwrap_or(0);
            } else {
                let byte = self
                    .staged_byte
                    .take()
                    .expect("write byte not supplied before ACK");
                self.requests.last_mut().unwrap().block.push(byte);
            }
            self.status |= BYTE_DONE;
        }
    }

    fn start(&mut self, value: u8) {
        assert!(
            !self.active && self.status & HOST_BUSY == 0,
            "START on busy bus"
        );
        assert!(self.status & INUSE != 0, "START without software semaphore");
        assert_eq!(value & 1, 0, "interrupt generation must remain disabled");
        assert_eq!(value & 0x80, 0, "unsupported PEC enabled");
        self.block = value & 0x1c == PROTOCOL_BLOCK;
        self.buffered = self.registers[usize::from(AUX_CONTROL)] & AUX_BUFFER != 0;
        self.read = self.registers[usize::from(HOST_ADDRESS)] & 1 != 0;
        self.count = if self.read {
            self.reply.len()
        } else {
            usize::from(self.registers[usize::from(HOST_DATA0)])
        };
        self.byte = 0;
        self.active = true;
        self.status |= HOST_BUSY;
        self.due = self.time.get() + self.latency;
        self.requests.push(Request {
            protocol: value & 0x1c,
            address: self.registers[usize::from(HOST_ADDRESS)],
            command: self.registers[usize::from(HOST_COMMAND)],
            word: u16::from_le_bytes([
                self.registers[usize::from(HOST_DATA0)],
                self.registers[usize::from(HOST_DATA1)],
            ]),
            block: Vec::new(),
        });
    }

    fn read(&mut self, offset: u8) -> u8 {
        self.step();
        assert!(self.auxiliary_present || !matches!(offset, AUX_CONTROL | AUX_STATUS));
        match offset {
            HOST_STATUS => {
                let status = self.status;
                self.status |= INUSE;
                status
            }
            HOST_CONTROL => {
                if self.registers[usize::from(AUX_CONTROL)] & AUX_BUFFER != 0 {
                    self.buffer_index = 0;
                }
                self.registers[usize::from(offset)] & 0x1f
            }
            BLOCK_DATA if self.buffered => {
                let value = self.buffer[self.buffer_index];
                self.buffer_index += 1;
                value
            }
            _ => self.registers[usize::from(offset)],
        }
    }

    fn write(&mut self, offset: u8, value: u8) {
        self.step();
        self.writes.push((offset, value));
        assert!(self.auxiliary_present || !matches!(offset, AUX_CONTROL | AUX_STATUS));
        match offset {
            HOST_STATUS => {
                let acknowledged = value & self.status & BYTE_DONE != 0;
                self.status &= !(value & !self.stuck_status & !HOST_BUSY);
                if acknowledged && self.active {
                    self.byte += 1;
                    if self.byte >= self.count {
                        self.complete();
                    } else {
                        if self.read && self.byte + 1 == self.count {
                            assert_ne!(
                                self.registers[usize::from(HOST_CONTROL)] & LAST_BYTE,
                                0,
                                "last-byte NACK was not armed before final byte"
                            );
                        }
                        self.due = self.time.get() + self.latency;
                    }
                }
            }
            HOST_CONTROL => {
                self.registers[usize::from(offset)] = value;
                if value & KILL != 0 {
                    self.kills += 1;
                    if !self.freeze_kill {
                        self.kill_at = Some(self.time.get() + self.latency);
                    }
                } else if value & START != 0 {
                    self.start(value);
                }
            }
            BLOCK_DATA => {
                if self.registers[usize::from(AUX_CONTROL)] & AUX_BUFFER != 0 {
                    self.buffer[self.buffer_index] = value;
                    self.buffer_index += 1;
                } else {
                    self.staged_byte = Some(value);
                }
                self.registers[usize::from(offset)] = value;
            }
            AUX_STATUS => self.registers[usize::from(offset)] &= !value,
            AUX_CONTROL if self.refuse_buffer => {
                self.registers[usize::from(offset)] = value & !AUX_BUFFER;
            }
            _ => self.registers[usize::from(offset)] = value,
        }
    }
}

#[derive(Clone)]
struct RegisterModel(Rc<RefCell<Model>>);

impl Registers for RegisterModel {
    fn read8(&mut self, offset: u8) -> u8 {
        self.0.borrow_mut().read(offset)
    }

    fn write8(&mut self, offset: u8, value: u8) {
        self.0.borrow_mut().write(offset, value);
    }
}

struct ModelTimer(Rc<Cell<u64>>);

impl Timer for ModelTimer {
    fn now_us(&self) -> u64 {
        self.0.get()
    }

    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}

type Controller = I801<RegisterModel, ModelTimer>;

fn config(buffer: bool) -> Config {
    Config {
        timeout_us: 1000,
        recovery_timeout_us: 100,
        use_block_buffer: buffer,
    }
}

fn model(device: u16) -> (RegisterModel, ModelTimer, ControllerInfo) {
    let info = ControllerInfo::from_pci_id(0x8086, device).unwrap();
    let time = Rc::new(Cell::new(0));
    (
        RegisterModel(Rc::new(RefCell::new(Model::new(
            time.clone(),
            info.block_buffer,
        )))),
        ModelTimer(time),
        info,
    )
}

fn new_controller(device: u16, buffer: bool) -> (Controller, Rc<RefCell<Model>>) {
    let (registers, timer, info) = model(device);
    let state = registers.0.clone();
    let controller = I801::new(registers, timer, info, HOST_ENABLED, config(buffer)).unwrap();
    (controller, state)
}

fn address() -> Address {
    Address::new(0x2c).unwrap()
}

#[test]
fn byte_word_and_process_call_protocols_match_the_wire_register_contract() {
    let (mut controller, state) = new_controller(0x7aa3, true);
    let mut byte = 0;
    let mut word = 0;
    for transaction in [
        Transaction::SendByte(0x11),
        Transaction::ReceiveByte(&mut byte),
        Transaction::WriteByte {
            command: 0x22,
            data: 0x33,
        },
        Transaction::WriteWord {
            command: 0x44,
            data: 0x5566,
        },
        Transaction::ReadWord {
            command: 0x77,
            data: &mut word,
        },
    ] {
        controller
            .transaction(address(), transaction, false)
            .unwrap();
    }
    assert_eq!(byte, 0x76);
    assert_eq!(word, 0x9876);
    controller
        .transaction(
            address(),
            Transaction::ProcessCall {
                command: 0x88,
                request: 0x1234,
                response: &mut word,
            },
            false,
        )
        .unwrap();
    assert_eq!(word, 0x9876);
    controller
        .transaction(
            address(),
            Transaction::ReadByte {
                command: 0x99,
                data: &mut byte,
            },
            false,
        )
        .unwrap();
    assert_eq!(byte, 0x76);
    let state = state.borrow();
    let requests = &state.requests;
    assert_eq!(
        (
            requests[0].protocol,
            requests[0].address,
            requests[0].command
        ),
        (4, 0x58, 0x11)
    );
    assert_eq!((requests[1].protocol, requests[1].address), (4, 0x59));
    assert_eq!(
        (
            requests[2].protocol,
            requests[2].command,
            requests[2].word as u8
        ),
        (8, 0x22, 0x33)
    );
    assert_eq!(
        (requests[3].protocol, requests[3].command, requests[3].word),
        (12, 0x44, 0x5566)
    );
    assert_eq!((requests[4].protocol, requests[4].address), (12, 0x59));
    assert_eq!(
        (requests[5].protocol, requests[5].address, requests[5].word),
        (16, 0x58, 0x1234)
    );
    assert_eq!(
        (
            requests[6].protocol,
            requests[6].address,
            requests[6].command
        ),
        (8, 0x59, 0x99)
    );
    assert_eq!(state.status, ALERT);
}

#[test]
fn block_transfers_preserve_all_lengths_in_byte_and_buffer_modes() {
    for (device, buffer) in [
        (0x2413, true),
        (0x2483, true),
        (0x24c3, true),
        (0x7aa3, true),
        (0x7aa3, false),
    ] {
        for count in 1..=MAX_BLOCK {
            let (mut controller, state) = new_controller(device, buffer);
            let bytes: Vec<_> = (0..count).map(|i| (i * 7 + 1) as u8).collect();
            state.borrow_mut().reply = bytes.clone();
            let mut result = Block::default();
            controller
                .transaction(
                    address(),
                    Transaction::ReadBlock {
                        command: 0x52,
                        data: &mut result,
                    },
                    false,
                )
                .unwrap();
            assert_eq!(result.as_slice(), bytes);
            controller
                .transaction(
                    address(),
                    Transaction::WriteBlock {
                        command: 0x53,
                        data: &bytes,
                    },
                    false,
                )
                .unwrap();
            let state = state.borrow();
            assert_eq!(state.requests.last().unwrap().block, bytes);
            assert_eq!(state.status, ALERT);
            assert_eq!(
                state.registers[usize::from(AUX_CONTROL)] & (AUX_CRC | AUX_BUFFER),
                0
            );
        }
    }
}

#[test]
fn stale_status_and_crc_are_cleared_without_acknowledging_alerts_or_other_owner() {
    let (registers, timer, info) = model(0x7aa3);
    let state = registers.0.clone();
    {
        let mut state = state.borrow_mut();
        state.status |= STATUS_FLAGS;
        state.registers[usize::from(AUX_STATUS)] = AUX_CRC_ERROR | 2;
        state.registers[usize::from(AUX_CONTROL)] = AUX_CRC | AUX_BUFFER | 4;
    }
    let mut controller = I801::new(registers, timer, info, HOST_ENABLED, config(true)).unwrap();
    assert_eq!(state.borrow().status, ALERT);
    assert_eq!(state.borrow().registers[usize::from(AUX_STATUS)], 2);
    assert_eq!(state.borrow().registers[usize::from(AUX_CONTROL)], 4);
    state.borrow_mut().status |= INUSE;
    let writes = state.borrow().writes.len();
    let error = controller
        .transaction(address(), Transaction::SendByte(1), false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Busy);
    assert_eq!(state.borrow().writes.len(), writes);
    assert_eq!(state.borrow().status, ALERT | INUSE);
}

#[test]
fn controller_errors_preserve_status_and_do_not_publish_read_outputs() {
    for (status, kind) in [
        (DEV_ERR, ErrorKind::Device),
        (BUS_ERR, ErrorKind::ArbitrationLost),
        (FAILED, ErrorKind::Failed),
    ] {
        let (mut controller, state) = new_controller(0x7aa3, true);
        state.borrow_mut().error = status;
        let mut value = 0xaaaa;
        let error = controller
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 4,
                    data: &mut value,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, kind);
        assert_eq!(error.status & ERROR_FLAGS, status);
        assert_eq!(error.recovery, Recovery::Cleared);
        assert_eq!(value, 0xaaaa);
        assert_eq!(state.borrow().status, ALERT);
        state.borrow_mut().error = 0;
        controller
            .transaction(address(), Transaction::SendByte(5), false)
            .unwrap();
    }
}

#[test]
fn timeouts_kill_only_our_transaction_and_failed_kills_poison_the_new_controller() {
    for kill_fails in [false, true] {
        let (mut controller, state) = new_controller(0x7aa3, true);
        {
            let mut state = state.borrow_mut();
            state.freeze = true;
            state.freeze_kill = kill_fails;
        }
        let error = controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
        assert_eq!(
            error.recovery,
            if kill_fails {
                Recovery::Failed
            } else {
                Recovery::Killed
            }
        );
        assert_eq!(state.borrow().kills, 1);
        assert!(state.borrow().time.get() <= 1100);
        if kill_fails {
            let writes = state.borrow().writes.len();
            assert_eq!(
                controller
                    .transaction(address(), Transaction::SendByte(2), false)
                    .unwrap_err()
                    .kind,
                ErrorKind::NeedsReset
            );
            assert_eq!(state.borrow().writes.len(), writes);
        } else {
            state.borrow_mut().freeze = false;
            controller
                .transaction(address(), Transaction::SendByte(2), false)
                .unwrap();
        }
    }
    let (mut controller, state) = new_controller(0x7aa3, true);
    state.borrow_mut().status |= HOST_BUSY;
    assert_eq!(
        controller
            .transaction(address(), Transaction::SendByte(3), false)
            .unwrap_err()
            .kind,
        ErrorKind::Busy
    );
    assert_eq!(state.borrow().kills, 0);
    assert_eq!(state.borrow().status & INUSE, 0);
}

#[test]
fn bad_block_counts_are_bounded_and_never_publish_partial_data() {
    for buffered in [false, true] {
        for length in [0, 33, 255] {
            let (mut controller, state) = new_controller(0x7aa3, buffered);
            state.borrow_mut().reply = vec![1; length];
            let mut block = Block::default();
            let error = controller
                .transaction(
                    address(),
                    Transaction::ReadBlock {
                        command: 8,
                        data: &mut block,
                    },
                    false,
                )
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::InvalidBlockLength(length));
            assert_eq!(block, Block::default());
            assert_eq!(
                error.recovery,
                if buffered {
                    Recovery::Cleared
                } else {
                    Recovery::Killed
                }
            );
            assert!(state.borrow().time.get() < 1100);
            assert_eq!(state.borrow().status, ALERT);
        }
    }
}

#[test]
fn premature_intr_mid_block_is_an_error_and_the_byte_bound_is_transaction_wide() {
    let (mut controller, state) = new_controller(0x2413, false);
    state.borrow_mut().premature_intr = Some(1);
    let mut block = Block::default();
    let error = controller
        .transaction(
            address(),
            Transaction::ReadBlock {
                command: 3,
                data: &mut block,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnexpectedCompletion);
    assert!(block.as_slice().is_empty());

    let (mut controller, state) = new_controller(0x2413, false);
    {
        let mut state = state.borrow_mut();
        state.latency = 40;
        state.reply = vec![7; 32];
    }
    let error = controller
        .transaction(
            address(),
            Transaction::ReadBlock {
                command: 3,
                data: &mut block,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::ByteDone));
    assert_eq!(error.recovery, Recovery::Killed);
    assert!(state.borrow().time.get() <= 1100);
}

#[test]
fn unsupported_pec_invalid_lengths_and_bad_configuration_never_start_io() {
    for address in [0, 7, 0x78, 0x80, 0xff] {
        assert_eq!(
            Address::new(address).unwrap_err().kind,
            ErrorKind::InvalidAddress
        );
    }
    for (host, kind) in [
        (0, ErrorKind::HostDisabled),
        (HOST_ENABLED | HOST_SMI, ErrorKind::FirmwareSmi),
        (HOST_ENABLED | HOST_I2C, ErrorKind::WrongProtocolMode),
    ] {
        let (registers, timer, info) = model(0x7aa3);
        let state = registers.0.clone();
        let error = I801::new(registers, timer, info, host, config(true))
            .err()
            .unwrap();
        assert_eq!(error.kind, kind);
        assert!(state.borrow().writes.is_empty());
    }
    let (mut controller, state) = new_controller(0x7aa3, true);
    let writes = state.borrow().writes.len();
    assert_eq!(
        controller
            .transaction(address(), Transaction::SendByte(1), true)
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedPec
    );
    for bytes in [&[][..], &[1; 33][..]] {
        assert_eq!(
            controller
                .transaction(
                    address(),
                    Transaction::WriteBlock {
                        command: 0,
                        data: bytes
                    },
                    false
                )
                .unwrap_err()
                .kind,
            ErrorKind::InvalidBlockLength(bytes.len())
        );
    }
    assert_eq!(state.borrow().writes.len(), writes);
    assert!(ControllerInfo::from_pci_id(0x8086, 0xffff).is_none());
    assert!(ControllerInfo::from_pci_id(0x1022, 0x7aa3).is_none());
    assert_eq!(
        ControllerInfo::from_pci_id(0x8086, 0x2413)
            .unwrap()
            .register_bytes(),
        16
    );
    assert!(
        !ControllerInfo::from_pci_id(0x8086, 0x2483)
            .unwrap()
            .has_block_buffer()
    );
}

#[test]
fn a_successful_wire_transfer_with_stuck_completion_status_is_still_an_error() {
    let (mut controller, state) = new_controller(0x7aa3, true);
    state.borrow_mut().stuck_status = INTR;
    let mut value = 0xaabb;
    let error = controller
        .transaction(
            address(),
            Transaction::ReadWord {
                command: 4,
                data: &mut value,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::StatusStuck);
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(value, 0xaabb);
    assert_eq!(state.borrow().status & INUSE, 0);
    assert_eq!(
        controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err()
            .kind,
        ErrorKind::NeedsReset
    );
}

#[test]
fn a_kill_without_the_required_failed_acknowledgement_is_not_accepted() {
    let (mut controller, state) = new_controller(0x7aa3, true);
    {
        let mut state = state.borrow_mut();
        state.freeze = true;
        state.kill_without_failed = true;
    }
    let error = controller
        .transaction(address(), Transaction::SendByte(1), false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(state.borrow().status & HOST_BUSY, 0);
    assert_eq!(state.borrow().status & INUSE, 0);
    assert!(state.borrow().time.get() <= 1100);
}

#[test]
fn a_device_error_after_a_partial_block_read_keeps_the_previous_output() {
    let (mut controller, state) = new_controller(0x2413, false);
    let mut result = Block::default();
    controller
        .transaction(
            address(),
            Transaction::ReadBlock {
                command: 1,
                data: &mut result,
            },
            false,
        )
        .unwrap();
    let previous = result.clone();
    {
        let mut state = state.borrow_mut();
        state.error = DEV_ERR;
        state.error_byte = Some(1);
        state.reply = vec![8, 9, 10];
    }
    let error = controller
        .transaction(
            address(),
            Transaction::ReadBlock {
                command: 2,
                data: &mut result,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Device);
    assert_eq!(result, previous);
    assert_eq!(state.borrow().status, ALERT);
}

#[test]
fn hardware_refusing_the_requested_block_buffer_mode_is_rejected_before_start() {
    let (mut controller, state) = new_controller(0x7aa3, true);
    state.borrow_mut().refuse_buffer = true;
    let mut block = Block::default();
    let error = controller
        .transaction(
            address(),
            Transaction::ReadBlock {
                command: 1,
                data: &mut block,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::BufferModeRejected);
    assert!(state.borrow().requests.is_empty());
    assert_eq!(state.borrow().status, ALERT);
    assert!(block.as_slice().is_empty());
}
