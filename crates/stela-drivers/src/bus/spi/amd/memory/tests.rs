use super::*;
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Clone)]
struct Time(Rc<Cell<u64>>);
impl crate::bus::i2c::Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
impl Timer for Time {
    fn calibrated(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Read8(usize),
    Write8(usize, u8),
    Read32(usize),
    Write32(usize, u32),
}
impl Access {
    fn offset(self) -> usize {
        match self {
            Self::Read8(at) | Self::Write8(at, _) | Self::Read32(at) | Self::Write32(at, _) => at,
        }
    }
}
#[derive(Clone, Debug)]
struct Wire {
    opcode: u8,
    chip: u8,
    hz: u32,
    tx: Vec<u8>,
    rx: usize,
    address32: bool,
}
struct State {
    registers: [u8; 0xc6],
    flash: [[u8; 256]; 4],
    profile: Profile,
    time: Time,
    accesses: Vec<Access>,
    wire: Vec<Wire>,
    pending: Option<(Wire, usize)>,
    cleared: bool,
    write_enabled: [bool; 4],
    initial_busy: bool,
    stuck: bool,
    fail: Option<(usize, bool)>,
    late: Option<usize>,
    address_writes: usize,
    ignore_address_write: Option<usize>,
    drops: usize,
}
impl State {
    fn word(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.registers[at..at + 4].try_into().unwrap())
    }
    fn store(&mut self, at: usize, value: u32) {
        self.registers[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn before(&mut self, access: Access) -> Result<(), IoError> {
        self.accesses.push(access);
        self.time.0.set(self.time.0.get().wrapping_add(1));
        if self.late == Some(self.accesses.len()) {
            self.time.0.set(self.time.0.get().wrapping_add(100_000));
        }
        if self.fail == Some((self.accesses.len(), false)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn after(&self) -> Result<(), IoError> {
        if self.fail == Some((self.accesses.len(), true)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn start(&mut self, opcode: u8) {
        assert!(!self.initial_busy && self.pending.is_none());
        assert!(self.cleared, "FIFO pointer not initialized");
        self.cleared = false;
        let tx = usize::from(self.registers[0x48]);
        let rx = usize::from(self.registers[0x4b]);
        assert!(tx + rx <= 70, "index FIFO overrun");
        let enable = self.word(0x20);
        let hz = match (enable >> 20) & 15 {
            0 => 66_660_000,
            1 => 33_330_000,
            2 => 22_220_000,
            3 => 16_660_000,
            4 => {
                assert_eq!(enable & 1, 1);
                100_000_000
            }
            5 => 800_000,
            7 => match (self.word(0x6c) >> 8) & 63 {
                4 => 50_000_000,
                50 => 4_000_000,
                63 => 3_170_000,
                _ => panic!("speed divisor"),
            },
            _ => panic!("speed selection"),
        };
        let wire = Wire {
            opcode,
            chip: self.registers[0x1d] & 3,
            hz,
            tx: self.registers[0x80..0x80 + tx].to_vec(),
            rx,
            address32: self.word(0x50) & 1 != 0,
        };
        self.wire.push(wire.clone());
        self.pending = Some((wire, 3));
    }
    fn progress(&mut self) -> u32 {
        if self.initial_busy || self.stuck {
            return 1 << 31;
        }
        let Some((wire, remaining)) = self.pending.take() else {
            return 0;
        };
        if remaining > 1 {
            self.pending = Some((wire, remaining - 1));
            return 1 << 31;
        }
        // Independent tiny memory peripheral: fixed opcode/address formats,
        // byte-addressed storage, WREN and completed program effects.
        let address_bytes = match wire.opcode {
            0x0c | 0x3c | 0xbc | 0x6c | 0xec => 4,
            0x03 | 0x0b | 0x3b | 0xbb | 0x6b | 0xeb | 0x02 => 3,
            0x84 => 2,
            _ => 0,
        };
        if wire.rx != 0 {
            assert!(wire.tx.len() >= address_bytes);
            assert!(wire.tx[address_bytes..].iter().all(|byte| *byte == 0xff));
            if self.profile == Profile::V2 {
                assert_eq!(
                    wire.address32,
                    matches!(wire.opcode, 0x0c | 0x3c | 0xbc | 0x6c | 0xec)
                );
            }
            let address = wire.tx[..address_bytes]
                .iter()
                .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
            for index in 0..wire.rx {
                self.registers[0x80 + wire.tx.len() + index] =
                    self.flash[usize::from(wire.chip)][(address + index) & 255];
            }
        } else if wire.opcode == 6 {
            self.write_enabled[usize::from(wire.chip)] = true;
        } else if matches!(wire.opcode, 2 | 0x84) {
            assert!(
                self.write_enabled[usize::from(wire.chip)],
                "program without WREN on this chip"
            );
            let address = wire.tx[..address_bytes]
                .iter()
                .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
            for (index, byte) in wire.tx[address_bytes..].iter().enumerate() {
                self.flash[usize::from(wire.chip)][(address + index) & 255] = *byte;
            }
            self.write_enabled[usize::from(wire.chip)] = false;
        }
        0
    }
}
struct Registers(Rc<RefCell<State>>);
impl Drop for Registers {
    fn drop(&mut self) {
        self.0.borrow_mut().drops += 1;
    }
}
// SAFETY: the fixture keeps its unique modeled bank and timer; no
// mappings, hardware, IRQ or DMA service is admitted by this test provider.
unsafe impl super::super::Registers for Registers {
    fn profile(&self) -> Profile {
        self.0.borrow().profile
    }
    fn read8(&mut self, at: usize) -> Result<u8, IoError> {
        let mut s = self.0.borrow_mut();
        s.before(Access::Read8(at))?;
        if at >= 0x80 {
            assert!(s.pending.is_none());
        }
        let value = s.registers[at];
        s.after()?;
        Ok(value)
    }
    fn write8(&mut self, at: usize, value: u8) -> Result<(), IoError> {
        let mut s = self.0.borrow_mut();
        s.before(Access::Write8(at, value))?;
        s.registers[at] = value;
        if at == 0x47 && value & 128 != 0 {
            s.registers[at] &= 127;
            let opcode = s.registers[0x45];
            s.start(opcode);
        }
        s.after()
    }
    fn read32(&mut self, at: usize) -> Result<u32, IoError> {
        let mut s = self.0.borrow_mut();
        s.before(Access::Read32(at))?;
        let busy = if at == s.profile.status() {
            s.progress()
        } else {
            0
        };
        let value = s.word(at) | busy;
        s.after()?;
        Ok(value)
    }
    fn write32(&mut self, at: usize, value: u32) -> Result<(), IoError> {
        let mut s = self.0.borrow_mut();
        s.before(Access::Write32(at, value))?;
        if at == 0x50 {
            s.address_writes += 1;
            if s.ignore_address_write == Some(s.address_writes) {
                return s.after();
            }
        }
        s.store(at, value);
        if at == 0 {
            s.store(0, value & !((1 << 16) | (1 << 20)));
            if value & (1 << 20) != 0 {
                s.cleared = true;
            }
            if value & (1 << 16) != 0 {
                s.start(value as u8);
            }
        }
        s.after()
    }
}
fn fixture(profile: Profile) -> (Controller<Registers, Time>, Rc<RefCell<State>>) {
    let time = Time(Rc::new(Cell::new(0)));
    let state = Rc::new(RefCell::new(State {
        registers: [0; 0xc6],
        flash: [core::array::from_fn(|i| (i as u8).wrapping_mul(7)); 4],
        profile,
        time: time.clone(),
        accesses: Vec::new(),
        wire: Vec::new(),
        pending: None,
        cleared: false,
        write_enabled: [false; 4],
        initial_busy: false,
        stuck: false,
        fail: None,
        late: None,
        address_writes: 0,
        ignore_address_write: None,
        drops: 0,
    }));
    state.borrow_mut().store(0x50, 0xa5a5_0000);
    state.borrow_mut().registers[0x1d] = 0x80;
    (
        Controller::new(Registers(state.clone()), time, 10_000)
            .ok()
            .unwrap(),
        state,
    )
}
fn device(chip: u8, hz: u32) -> MemoryDevice {
    MemoryDevice {
        device: Device {
            chip_select: chip,
            max_hz: hz,
            mode: Mode::Mode0,
        },
        transmit: Lanes::Quad,
        receive: Lanes::Quad,
    }
}
fn read(controller: &mut Controller<Registers, Time>, output: &mut [u8]) -> Result<u32, Error> {
    controller.memory(
        device(2, 65_000_000),
        &mut Operation {
            opcode: 0x0c,
            address: 0x0102_0035,
            address_bytes: 4,
            dummy_bytes: 1,
            max_hz: 0,
            data: Data::Read(output),
        },
    )
}

#[test]
fn all_read_protocols_addresses_payload_sizes_and_per_operation_rates_have_real_effects() {
    for profile in [Profile::V1, Profile::V2] {
        for opcode in [
            3, 0x0b, 0x3b, 0xbb, 0x6b, 0xeb, 0x0c, 0x3c, 0xbc, 0x6c, 0xec,
        ] {
            for bytes in [1, 7, 8, 9, 63, 64] {
                let (mut controller, state) = fixture(profile);
                let four = matches!(opcode, 0x0c | 0x3c | 0xbc | 0x6c | 0xec);
                let address = if four { 0x0102_0035 } else { 0x020035 };
                let mut output = vec![0xa5; bytes];
                let hz = controller
                    .memory(
                        device(3, 100_000_000),
                        &mut Operation {
                            opcode,
                            address,
                            address_bytes: if four { 4 } else { 3 },
                            dummy_bytes: if opcode == 3 { 0 } else { 1 },
                            max_hz: 65_000_000,
                            data: Data::Read(&mut output),
                        },
                    )
                    .unwrap();
                assert_eq!(hz, 50_000_000);
                for (index, byte) in output.iter().enumerate() {
                    assert_eq!(*byte, state.borrow().flash[3][(0x35 + index) & 255]);
                }
                let s = state.borrow();
                let wire = &s.wire[0];
                assert_eq!(
                    (wire.opcode, wire.chip, wire.hz, wire.rx),
                    (opcode, 3, 50_000_000, bytes)
                );
                assert_eq!(
                    wire.tx[..if four { 4 } else { 3 }],
                    if four {
                        vec![1, 2, 0, 0x35]
                    } else {
                        vec![2, 0, 0x35]
                    }
                );
                assert_eq!(s.word(0x50), 0xa5a5_0000, "original address epoch restored");
                assert_eq!(s.registers[0x1d] & 0xfc, 0x80);
                assert!(
                    s.accesses
                        .iter()
                        .any(|a| matches!(a,Access::Write8(at,value) if *at>=FIFO && *value==0x35))
                );
                drop(s);
                let (registers, _) = controller.release().ok().unwrap();
                drop(registers);
                assert_eq!(state.borrow().drops, 1);
            }
        }
    }
}

#[test]
fn write_enable_program_and_raw_command_share_the_original_controller_epoch() {
    for profile in [Profile::V1, Profile::V2] {
        let (mut controller, state) = fixture(profile);
        let mut output = [0; 8];
        read(&mut controller, &mut output).unwrap();
        controller
            .command(device(1, 50_000_000).device, 6, &[], &mut [])
            .unwrap();
        let payload = [0x6d; 64];
        controller
            .memory(
                device(1, 50_000_000),
                &mut Operation {
                    opcode: 2,
                    address: 0x123450,
                    address_bytes: 3,
                    dummy_bytes: 0,
                    max_hz: 100_000_000,
                    data: Data::Write(&payload),
                },
            )
            .unwrap();
        assert_eq!(&state.borrow().flash[1][0x50..0x90], &payload);
        for chip in [1usize, 2] {
            let mut data = [0xa5; 64];
            controller
                .memory(
                    device(chip as u8, 50_000_000),
                    &mut Operation {
                        opcode: 3,
                        address: 0x123450,
                        address_bytes: 3,
                        dummy_bytes: 0,
                        max_hz: 0,
                        data: Data::Read(&mut data),
                    },
                )
                .unwrap();
            assert_eq!(
                data,
                state.borrow().flash[chip][0x50..0x90],
                "chip-select isolation"
            );
            if chip == 2 {
                assert_ne!(data, payload, "another chip's write must not propagate");
            }
        }
        let before = state.borrow().wire.len();
        controller
            .memory(
                device(0, 50_000_000),
                &mut Operation {
                    opcode: 0xa0,
                    address: 0x0102_0304_0506_0708,
                    address_bytes: 8,
                    dummy_bytes: 0,
                    max_hz: 0,
                    data: Data::None,
                },
            )
            .unwrap();
        assert_eq!(state.borrow().wire[before].tx, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(state.borrow().word(0x50), 0xa5a5_0000);
    }
}

#[test]
fn actual_fifo_boundary_and_lane_or_argument_refusals_never_truncate_or_touch_hardware() {
    let (mut controller, state) = fixture(Profile::V2);
    let mut output = [0; 63];
    let mut operation = Operation {
        opcode: 0xec,
        address: 0x12345678,
        address_bytes: 4,
        dummy_bytes: 3,
        max_hz: 0,
        data: Data::Read(&mut output),
    };
    assert_eq!(operation.maximum_data_len(), 63);
    controller
        .memory(device(0, 50_000_000), &mut operation)
        .unwrap();
    assert_eq!(
        state.borrow().wire[0].tx.len() + state.borrow().wire[0].rx,
        70
    );
    let accesses = state.borrow().accesses.len();
    let mut output = [0xa5; 64];
    let mut operation = Operation {
        opcode: 0xec,
        address: 1,
        address_bytes: 4,
        dummy_bytes: 3,
        max_hz: 0,
        data: Data::Read(&mut output),
    };
    assert_eq!(
        controller
            .memory(device(0, 50_000_000), &mut operation)
            .unwrap_err()
            .kind,
        ErrorKind::Length
    );
    for mutation in 0..7 {
        let mut byte = [0xa5];
        let mut operation = Operation {
            opcode: 0xeb,
            address: 0x123456,
            address_bytes: 3,
            dummy_bytes: 1,
            max_hz: 0,
            data: Data::Read(&mut byte),
        };
        let mut target = device(0, 50_000_000);
        match mutation {
            0 => target.transmit = Lanes::Single,
            1 => target.receive = Lanes::Dual,
            2 => operation.address_bytes = 2,
            3 => operation.address_bytes = 9,
            4 => operation.max_hz = 799_999,
            5 => target.device.mode = Mode::Mode3,
            _ => target.device.chip_select = 4,
        }
        assert!(controller.memory(target, &mut operation).is_err());
    }
    let payload = [0x6d; 65];
    for (bytes, dummy) in [(1, 1), (65, 0)] {
        let mut operation = Operation {
            opcode: 2,
            address: 0x1234,
            address_bytes: 3,
            dummy_bytes: dummy,
            max_hz: 0,
            data: Data::Write(&payload[..bytes]),
        };
        assert!(
            controller
                .memory(device(0, 50_000_000), &mut operation)
                .is_err()
        );
    }
    assert_eq!(state.borrow().accesses.len(), accesses);
    assert!(controller.failure().is_none());
    assert!(controller.release().is_ok());
}

#[test]
fn every_uncertain_access_and_late_readback_retains_owners_and_unpublished_rx() {
    let (mut successful, state) = fixture(Profile::V2);
    read(&mut successful, &mut [0; 9]).unwrap();
    let accesses = state.borrow().accesses.len();
    for index in 1..=accesses {
        for after in [false, true] {
            let (mut controller, state) = fixture(Profile::V2);
            state.borrow_mut().fail = Some((index, after));
            let mut poison = [0xa5; 9];
            let error = read(&mut controller, &mut poison).unwrap_err();
            assert_eq!(poison, [0xa5; 9]);
            assert_eq!(error.kind, ErrorKind::Io);
            assert_eq!(
                error.offset,
                Some(state.borrow().accesses[index - 1].offset())
            );
            let count = state.borrow().accesses.len();
            assert_eq!(
                read(&mut controller, &mut poison).unwrap_err().kind,
                ErrorKind::NeedsReset
            );
            assert_eq!(state.borrow().accesses.len(), count);
            let controller = controller.release().err().unwrap();
            drop(controller);
            assert_eq!(state.borrow().drops, 0);
        }
        let (mut controller, state) = fixture(Profile::V2);
        state.borrow_mut().late = Some(index);
        let mut poison = [0xa5; 9];
        assert_eq!(
            read(&mut controller, &mut poison).unwrap_err().kind,
            ErrorKind::Timeout
        );
        assert_eq!(poison, [0xa5; 9]);
        assert!(controller.release().is_err());
    }
}

#[test]
fn ignored_initial_or_final_address_mode_never_publishes_received_bytes() {
    for write in [1, 2] {
        let (mut controller, state) = fixture(Profile::V2);
        state.borrow_mut().ignore_address_write = Some(write);
        let mut poison = [0xa5; 8];
        let error = read(&mut controller, &mut poison).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Readback);
        assert_eq!(error.triggered, write == 2);
        assert_eq!(poison, [0xa5; 8]);
        assert_eq!(state.borrow().wire.len(), usize::from(write == 2));
        assert!(
            state
                .borrow()
                .accesses
                .iter()
                .any(|a| matches!(a,Access::Write32(0x50,value) if value&1!=0))
        );
        assert!(controller.release().is_err());
    }
}

#[test]
fn initial_busy_is_bounded_and_a_counter_wrap_does_not_shorten_the_operation() {
    let (mut controller, state) = fixture(Profile::V2);
    state.borrow_mut().initial_busy = true;
    assert_eq!(
        read(&mut controller, &mut [0xa5; 8]).unwrap_err().kind,
        ErrorKind::Timeout
    );
    assert!(
        state
            .borrow()
            .accesses
            .iter()
            .all(|a| matches!(a, Access::Read32(0x4c)))
    );
    let (mut controller, state) = fixture(Profile::V2);
    state.borrow().time.0.set(u64::MAX - 8);
    let mut bytes = [0xa5; 8];
    read(&mut controller, &mut bytes).unwrap();
    assert_eq!(bytes[0], state.borrow().flash[2][0x35]);
    assert_eq!(state.borrow().wire.len(), 1);
}

#[test]
#[ignore = "oracle: STELA_AMD_SPI_MEMORY_TRACE"]
fn unchanged_linux_memory_wire_effects_and_frontend_frequency_limits_match_native() {
    extern crate std;
    let records = std::fs::read_to_string(
        std::env::var_os("STELA_AMD_SPI_MEMORY_TRACE").expect("set STELA_AMD_SPI_MEMORY_TRACE"),
    )
    .unwrap();
    let mut cases = 0;
    let mut admitted = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 20, "{line}");
        let number = |at: usize| fields[at].parse::<u64>().unwrap();
        let hex = |at: usize| -> Vec<u8> {
            if fields[at] == "-" {
                Vec::new()
            } else {
                (0..fields[at].len())
                    .step_by(2)
                    .map(|offset| u8::from_str_radix(&fields[at][offset..offset + 2], 16).unwrap())
                    .collect()
            }
        };
        let profile = match number(1) {
            1 => Profile::V1,
            2 => Profile::V2,
            _ => panic!("no HID2 source qualification"),
        };
        let (mut controller, state) = fixture(profile);
        state.borrow_mut().store(0x50, number(11) as u32);
        // The C peer begins with an already write-enabled memory peripheral;
        // the ordinary test above independently exercises WREN.
        state.borrow_mut().write_enabled[number(9) as usize] = true;
        let mut output = vec![0xa5; number(5) as usize];
        let payload = hex(17);
        let result = {
            let data = match number(6) {
                0 => Data::None,
                1 => Data::Read(&mut output),
                2 => Data::Write(&payload),
                _ => panic!("half-duplex memory direction"),
            };
            let lanes = |value: u64| match value {
                1 => Lanes::Single,
                2 => Lanes::Dual,
                4 => Lanes::Quad,
                _ => panic!("unsupported source lanes"),
            };
            let mut target = device(number(9) as u8, number(8) as u32);
            target.transmit = lanes(number(18));
            target.receive = lanes(number(19));
            controller.memory(
                target,
                &mut Operation {
                    opcode: number(2) as u8,
                    address: number(10),
                    address_bytes: number(3) as u8,
                    dummy_bytes: number(4) as u8,
                    max_hz: number(7) as u32,
                    data,
                },
            )
        };
        match fields[0] {
            "U" => {
                assert_eq!(result.unwrap_err().kind, ErrorKind::Configuration, "{line}");
                assert!(state.borrow().accesses.is_empty(), "{line}");
                assert!(controller.failure().is_none());
                assert!(output.iter().all(|byte| *byte == 0xa5));
            }
            "M" => {
                assert_eq!(u64::from(result.unwrap()), number(12), "{line}");
                let bank = state.borrow();
                assert_eq!(bank.wire.len(), 1);
                let wire = &bank.wire[0];
                assert_eq!(wire.opcode, number(2) as u8, "{line}");
                assert_eq!(wire.chip, number(9) as u8, "{line}");
                assert_eq!(wire.hz, number(12) as u32, "{line}");
                assert_eq!(wire.address32, number(13) != 0, "{line}");
                assert_eq!(wire.tx, hex(14), "{line}");
                if number(6) == 1 {
                    assert_eq!(wire.rx, number(5) as usize, "{line}");
                    assert_eq!(output, hex(15), "{line}");
                } else if number(6) == 2 {
                    let actual: Vec<_> = (0..number(5) as usize)
                        .map(|index| {
                            bank.flash[number(9) as usize][(number(10) as usize + index) & 255]
                        })
                        .collect();
                    assert_eq!(actual, hex(16), "{line}");
                }
                assert_eq!(bank.word(0x50), number(11) as u32, "original mode epoch");
                admitted += 1;
            }
            _ => panic!("unknown source record {line}"),
        }
        let (registers, _) = controller.release().ok().unwrap();
        drop(registers);
        assert_eq!(state.borrow().drops, 1);
        cases += 1;
    }
    assert_eq!((cases, admitted), (27000, 16576));
}
