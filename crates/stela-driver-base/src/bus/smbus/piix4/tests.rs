use super::*;
mod timer;
use alloc::{rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};

/// Vendor/reserved bits are nonzero. They are neither an I801
/// INUSE semaphore nor BYTE_DONE; every status write is checked against W1C.
const OTHER_STATUS: u8 = 0xe0;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Request {
    protocol: u8,
    address: u8,
    command: u8,
    word: u16,
    block: Vec<u8>,
}

struct Model {
    registers: [u8; 9],
    status: u8,
    time: Rc<Cell<u64>>,
    completion_at: Option<u64>,
    latency: u64,
    requests: Vec<Request>,
    writes: Vec<(u8, u8)>,
    active_status_reads: Vec<u64>,
    reply_word: u16,
    reply_block: Vec<u8>,
    block_buffer: [u8; MAX_BLOCK],
    block_index: usize,
    block_resets: usize,
    pending: bool,
    freeze: bool,
    error: u8,
    late_error: u8,
    stuck_status: u8,
    missing_intr: bool,
}

impl Model {
    fn new(time: Rc<Cell<u64>>) -> Self {
        Self {
            registers: [0; 9],
            status: OTHER_STATUS,
            time,
            completion_at: None,
            latency: 400,
            requests: Vec::new(),
            writes: Vec::new(),
            active_status_reads: Vec::new(),
            reply_word: 0xabcd,
            reply_block: vec![4, 5, 6],
            block_buffer: [0; MAX_BLOCK],
            block_index: 0,
            block_resets: 0,
            pending: false,
            freeze: false,
            error: 0,
            late_error: 0,
            stuck_status: 0,
            missing_intr: false,
        }
    }

    fn step(&mut self) {
        if self.freeze || !self.completion_at.is_some_and(|at| self.time.get() >= at) {
            return;
        }
        self.completion_at = None;
        self.pending = false;
        self.status &= !HOST_BUSY;
        if self.error != 0 {
            self.status |= self.error;
            return;
        }
        let request = self.requests.last().unwrap();
        if request.address & 1 != 0 {
            if request.protocol == PROTOCOL_BLOCK {
                self.registers[usize::from(HOST_DATA0)] = self.reply_block.len() as u8;
                for (to, &from) in self.block_buffer.iter_mut().zip(&self.reply_block) {
                    *to = from;
                }
            } else {
                let [low, high] = self.reply_word.to_le_bytes();
                self.registers[usize::from(HOST_DATA0)] = low;
                self.registers[usize::from(HOST_DATA1)] = high;
            }
        }
        if !self.missing_intr {
            self.status |= INTR;
        }
    }

    fn read(&mut self, offset: u8) -> u8 {
        assert!(offset <= 8, "access outside the PIIX4 host window");
        if offset == HOST_STATUS && self.pending {
            self.active_status_reads.push(self.time.get());
        }
        self.step();
        match offset {
            HOST_STATUS => self.status,
            HOST_CONTROL => {
                self.block_index = 0;
                self.block_resets += 1;
                self.registers[usize::from(HOST_CONTROL)] & !START
            }
            BLOCK_DATA => {
                assert!(!self.pending, "read array before host completed");
                let byte = self.block_buffer[self.block_index];
                self.block_index += 1;
                byte
            }
            HOST_DATA0 => {
                self.status |= self.late_error;
                self.registers[usize::from(HOST_DATA0)]
            }
            _ => self.registers[usize::from(offset)],
        }
    }

    fn write(&mut self, offset: u8, value: u8) {
        assert!(offset <= 8, "access outside the PIIX4 host window");
        self.step();
        self.writes.push((offset, value));
        match offset {
            HOST_STATUS => {
                assert_eq!(
                    value & !STATUS_FLAGS,
                    0,
                    "non-W1C or I801-only bits written"
                );
                self.status &= !(value & !self.stuck_status);
            }
            HOST_CONTROL if value & START != 0 => {
                assert!(
                    !self.pending && self.status & HOST_BUSY == 0,
                    "START on a busy host"
                );
                assert_eq!(value & 3, 0, "interrupt/KILL must not be enabled");
                let protocol = value & 0x1c;
                let address = self.registers[usize::from(HOST_ADDRESS)];
                let block = if protocol == PROTOCOL_BLOCK && address & 1 == 0 {
                    let count = usize::from(self.registers[usize::from(HOST_DATA0)]);
                    assert!((1..=MAX_BLOCK).contains(&count));
                    self.block_buffer[..count].to_vec()
                } else {
                    Vec::new()
                };
                self.requests.push(Request {
                    protocol,
                    address,
                    command: self.registers[usize::from(HOST_COMMAND)],
                    word: u16::from_le_bytes([
                        self.registers[usize::from(HOST_DATA0)],
                        self.registers[usize::from(HOST_DATA1)],
                    ]),
                    block,
                });
                self.pending = true;
                self.completion_at = Some(self.time.get() + self.latency);
                self.status |= HOST_BUSY;
                self.registers[usize::from(offset)] = value;
            }
            BLOCK_DATA => {
                assert!(!self.pending, "write array while host owns it");
                self.block_buffer[self.block_index] = value;
                self.block_index += 1;
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

type Controller = Piix4<RegisterModel, ModelTimer>;

fn controller(vendor: u16, device: u16, revision: u8) -> (Controller, Rc<RefCell<Model>>) {
    let time = Rc::new(Cell::new(0));
    let state = Rc::new(RefCell::new(Model::new(time.clone())));
    let info = ControllerInfo::from_pci_id(vendor, device, revision).unwrap();
    let controller = Piix4::new(
        RegisterModel(state.clone()),
        ModelTimer(time),
        info,
        Config {
            timeout_us: 5000,
            poll_interval_us: 250,
        },
    )
    .unwrap();
    (controller, state)
}

fn address() -> Address {
    Address::new(0x2c).unwrap()
}

#[test]
fn simple_protocols_set_correct_direction_command_and_little_endian_data() {
    let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
    let (mut byte, mut word) = (0, 0);
    for transaction in [
        Transaction::SendByte(1),
        Transaction::ReceiveByte(&mut byte),
        Transaction::WriteByte {
            command: 2,
            data: 3,
        },
        Transaction::WriteWord {
            command: 4,
            data: 0x5678,
        },
        Transaction::ReadWord {
            command: 5,
            data: &mut word,
        },
    ] {
        controller
            .transaction(address(), transaction, false)
            .unwrap();
    }
    assert_eq!((byte, word), (0xcd, 0xabcd));
    controller
        .transaction(
            address(),
            Transaction::ReadByte {
                command: 6,
                data: &mut byte,
            },
            false,
        )
        .unwrap();
    let state = state.borrow();
    assert_eq!(state.requests[0].protocol, 4);
    assert_eq!(
        (state.requests[0].address, state.requests[0].command),
        (0x58, 1)
    );
    assert_eq!(
        (state.requests[1].protocol, state.requests[1].address),
        (4, 0x59)
    );
    assert_eq!(
        (
            state.requests[2].protocol,
            state.requests[2].command,
            state.requests[2].word as u8
        ),
        (8, 2, 3)
    );
    assert_eq!(
        (
            state.requests[3].protocol,
            state.requests[3].command,
            state.requests[3].word
        ),
        (12, 4, 0x5678)
    );
    assert_eq!(
        (state.requests[4].protocol, state.requests[4].address),
        (12, 0x59)
    );
    assert_eq!(
        (
            state.requests[5].protocol,
            state.requests[5].address,
            state.requests[5].command
        ),
        (8, 0x59, 6)
    );
    assert_eq!(state.status, OTHER_STATUS);
    assert_eq!(state.block_resets, 0);
}

#[test]
fn block_array_index_resets_preserve_every_length_and_successive_transactions() {
    for (vendor, device, revision) in [
        (0x8086, 0x7113, 0),
        (0x1002, 0x4385, 0x3f),
        (0x1002, 0x4385, 0x40),
        (0x1022, 0x780b, 0x41),
        (0x1022, 0x790b, 0x51),
    ] {
        let (mut controller, state) = controller(vendor, device, revision);
        for count in (1..=MAX_BLOCK).rev() {
            let bytes: Vec<_> = (0..count).map(|i| (i * 3 + count) as u8).collect();
            controller
                .transaction(
                    address(),
                    Transaction::WriteBlock {
                        command: 1,
                        data: &bytes,
                    },
                    false,
                )
                .unwrap();
            assert_eq!(state.borrow().requests.last().unwrap().block, bytes);
            state.borrow_mut().reply_block = bytes.clone();
            let mut result = Block::default();
            controller
                .transaction(
                    address(),
                    Transaction::ReadBlock {
                        command: 2,
                        data: &mut result,
                    },
                    false,
                )
                .unwrap();
            assert_eq!(result.as_slice(), bytes);
            assert_eq!(state.borrow().status, OTHER_STATUS);
        }
        assert_eq!(state.borrow().block_resets, MAX_BLOCK * 2);
    }
}

#[test]
fn a_preexisting_busy_owner_is_neither_reset_nor_reprogrammed() {
    let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
    state.borrow_mut().status |= HOST_BUSY;
    let writes = state.borrow().writes.len();
    let error = controller
        .transaction(address(), Transaction::SendByte(1), false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Busy);
    assert_eq!(error.recovery, Recovery::NotAttempted);
    assert_eq!(state.borrow().writes.len(), writes);
    assert!(state.borrow().requests.is_empty());
}

#[test]
fn device_and_failed_errors_preserve_status_without_publishing_outputs() {
    for (status, kind) in [(DEV_ERR, ErrorKind::Device), (FAILED, ErrorKind::Failed)] {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        state.borrow_mut().error = status;
        let mut value = 0x1234;
        let error = controller
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 1,
                    data: &mut value,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, kind);
        assert_eq!(error.status, OTHER_STATUS | status);
        assert_eq!(error.recovery, Recovery::Cleared);
        assert_eq!(value, 0x1234);
        assert_eq!(state.borrow().status, OTHER_STATUS);
        state.borrow_mut().error = 0;
        controller
            .transaction(address(), Transaction::SendByte(2), false)
            .unwrap();
    }
}

#[test]
fn collision_requires_platform_reset_even_if_the_busy_bit_clears() {
    let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
    state.borrow_mut().error = BUS_ERR;
    let error = controller
        .transaction(address(), Transaction::SendByte(1), false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::ArbitrationLost);
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(state.borrow().status & HOST_BUSY, 0);
    let writes = state.borrow().writes.len();
    assert_eq!(
        controller
            .transaction(address(), Transaction::SendByte(2), false)
            .unwrap_err()
            .kind,
        ErrorKind::NeedsReset
    );
    assert_eq!(state.borrow().writes.len(), writes);
    assert!(controller.shutdown().is_err());
}

#[test]
fn timeout_is_bounded_poisoned_and_does_not_apply_i801_kill_semantics() {
    let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
    state.borrow_mut().freeze = true;
    let error = controller
        .transaction(address(), Transaction::SendByte(1), false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(state.borrow().time.get(), 5000);
    assert_eq!(
        state.borrow().registers[usize::from(HOST_CONTROL)],
        PROTOCOL_BYTE | START
    );
    let writes = state.borrow().writes.len();
    assert_eq!(
        controller
            .transaction(address(), Transaction::SendByte(2), false)
            .unwrap_err()
            .kind,
        ErrorKind::NeedsReset
    );
    assert_eq!(state.borrow().writes.len(), writes);
}

#[test]
fn busy_clear_without_completion_is_not_reported_as_success() {
    let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
    state.borrow_mut().missing_intr = true;
    let error = controller
        .transaction(address(), Transaction::SendByte(1), false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(state.borrow().status, OTHER_STATUS);
}

#[test]
fn invalid_block_counts_and_late_errors_keep_previous_read_outputs() {
    let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
    let mut output = Block::default();
    controller
        .transaction(
            address(),
            Transaction::ReadBlock {
                command: 1,
                data: &mut output,
            },
            false,
        )
        .unwrap();
    let previous = output.clone();
    for count in [0, 33, 255] {
        state.borrow_mut().reply_block = vec![1; count];
        let error = controller
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 1,
                    data: &mut output,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidBlockLength(count));
        assert_eq!(error.recovery, Recovery::Cleared);
        assert_eq!(output, previous);
    }
    state.borrow_mut().late_error = DEV_ERR;
    let mut word = 0x4567;
    let error = controller
        .transaction(
            address(),
            Transaction::ReadWord {
                command: 1,
                data: &mut word,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Device);
    assert_eq!(word, 0x4567);
}

#[test]
fn a_stuck_w1c_completion_is_an_error_and_requires_reset() {
    let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
    state.borrow_mut().stuck_status = INTR;
    let mut word = 0x4567;
    let error = controller
        .transaction(
            address(),
            Transaction::ReadWord {
                command: 1,
                data: &mut word,
            },
            false,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::StatusStuck);
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(word, 0x4567);
}

#[test]
fn pci_revision_layout_boundaries_match_the_pinned_linux_paths() {
    let info =
        |vendor, device, revision| ControllerInfo::from_pci_id(vendor, device, revision).unwrap();
    assert_eq!(
        info(0x1002, 0x4385, 0x3f).base_registers(),
        BaseRegisters::LegacyPci
    );
    assert_eq!(
        info(0x1002, 0x4385, 0x40).base_registers(),
        BaseRegisters::Sb800
    );
    assert_eq!(
        info(0x1002, 0x4385, 0x40).port_selection(),
        PortSelection::Sb800Selectable
    );
    assert_eq!(
        (
            info(0x1022, 0x780b, 0x1e).main_ports(),
            info(0x1022, 0x780b, 0x1e).port_selection()
        ),
        (4, PortSelection::HudsonEarly)
    );
    assert_eq!(
        (
            info(0x1022, 0x780b, 0x1f).main_ports(),
            info(0x1022, 0x780b, 0x1f).port_selection()
        ),
        (2, PortSelection::DecodeEn)
    );
    assert_eq!(
        info(0x1022, 0x780b, 0x40).base_registers(),
        BaseRegisters::Sb800
    );
    assert_eq!(
        info(0x1022, 0x780b, 0x41).base_registers(),
        BaseRegisters::PmDecode
    );
    assert_eq!(
        info(0x1022, 0x790b, 0x48).base_registers(),
        BaseRegisters::Sb800
    );
    assert_eq!(
        info(0x1022, 0x790b, 0x49).base_registers(),
        BaseRegisters::PmDecode
    );
    assert_eq!(info(0x1022, 0x790b, 0x50).pm_access(), PmAccess::IndexedIo);
    assert_eq!(info(0x1022, 0x790b, 0x51).pm_access(), PmAccess::Mmio);
    assert_eq!(info(0x1d94, 0x790b, 0x51).pm_access(), PmAccess::IndexedIo);
    assert_eq!(
        info(0x1d94, 0x790b, 0).base_registers(),
        BaseRegisters::PmDecode
    );
    assert!(ControllerInfo::from_pci_id(0x8086, 0x7aa3, 0).is_none());
    assert!(ControllerInfo::from_pci_id(0x1022, 0xffff, 0).is_none());
}

#[test]
fn the_first_status_poll_obeys_piix4_and_csb5_errata_delays() {
    for (vendor, device, first) in [(0x8086, 0x7113, 250), (0x1166, 0x0201, 2000)] {
        let (mut controller, state) = controller(vendor, device, 0);
        controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap();
        assert_eq!(state.borrow().active_status_reads[0], first);
    }
}

#[test]
fn unsupported_protocols_and_invalid_write_lengths_do_not_touch_the_host() {
    let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
    let writes = state.borrow().writes.len();
    assert_eq!(
        controller
            .transaction(address(), Transaction::SendByte(1), true)
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedPec
    );
    let mut word = 0;
    assert_eq!(
        controller
            .transaction(
                address(),
                Transaction::ProcessCall {
                    command: 1,
                    request: 2,
                    response: &mut word
                },
                false
            )
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedTransaction
    );
    for data in [&[][..], &[0; 33][..]] {
        assert_eq!(
            controller
                .transaction(
                    address(),
                    Transaction::WriteBlock { command: 1, data },
                    false
                )
                .unwrap_err()
                .kind,
            ErrorKind::InvalidBlockLength(data.len())
        );
    }
    assert_eq!(state.borrow().writes.len(), writes);
}
