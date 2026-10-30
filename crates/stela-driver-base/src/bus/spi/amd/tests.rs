use super::*;
mod timer;
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
#[derive(Clone, Debug, PartialEq, Eq)]
struct Wire {
    chip: u8,
    hz: u32,
    opcode: u8,
    tx: Vec<u8>,
    rx: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Read8(usize),
    Write8(usize, u8),
    Read32(usize),
    Write32(usize, u32),
}
struct State {
    bytes: [u8; 0xc6],
    memory: [u8; 256],
    time: Time,
    log: Vec<Access>,
    wire: Vec<Wire>,
    pending: Option<(Wire, usize)>,
    complete: usize,
    profile: Profile,
    cleared: bool,
    stuck: bool,
    initial_busy: bool,
    fail: Option<(usize, bool)>,
    late: Option<usize>,
    ignore: Option<usize>,
    drops: usize,
}
impl State {
    fn word(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
    }
    fn store(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn before(&mut self, access: Access) -> Result<(), IoError> {
        self.log.push(access);
        self.time.0.set(self.time.0.get().wrapping_add(1));
        if self.late == Some(self.log.len()) {
            self.time.0.set(self.time.0.get().wrapping_add(10_000));
        }
        if self.fail == Some((self.log.len(), false)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn after(&self) -> Result<(), IoError> {
        if self.fail == Some((self.log.len(), true)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn start(&mut self, opcode: u8) {
        assert!(
            !self.initial_busy && self.pending.is_none(),
            "configuration replayed a command"
        );
        assert!(self.cleared, "FIFO pointer was not initialized");
        self.cleared = false;
        let tx = usize::from(self.bytes[0x48]);
        let rx = usize::from(self.bytes[0x4b]);
        assert!(tx + rx < 70, "hardware FIFO overrun");
        let enable = self.word(0x20);
        let hz = match (enable >> 20) & 15 {
            0 => 66_660_000,
            1 => 33_330_000,
            2 => 22_220_000,
            3 => 16_660_000,
            4 => {
                assert_ne!(enable & 1, 0);
                100_000_000
            }
            5 => 800_000,
            7 => match (self.word(0x6c) >> 8) & 63 {
                4 => 50_000_000,
                50 => 4_000_000,
                63 => 3_170_000,
                _ => panic!("invalid actual divisor"),
            },
            _ => panic!("invalid speed encoding"),
        };
        let wire = Wire {
            chip: self.bytes[0x1d] & 3,
            hz,
            opcode,
            tx: self.bytes[0x80..0x80 + tx].to_vec(),
            rx,
        };
        self.wire.push(wire.clone());
        self.pending = Some((wire, 3));
    }
    fn status(&mut self) -> u32 {
        if self.initial_busy || (self.stuck && self.pending.is_some()) {
            return 1 << 31;
        }
        let Some((wire, delay)) = self.pending.take() else {
            return 0;
        };
        if delay != 0 {
            self.pending = Some((wire, delay - 1));
            return 1 << 31;
        }
        // An independent register peripheral: opcode02 writes from its first
        // TX address, opcode03 reads it. Device effects occur at completion.
        if wire.opcode == 2 && !wire.tx.is_empty() {
            for (index, byte) in wire.tx[1..].iter().enumerate() {
                self.memory[(usize::from(wire.tx[0]) + index) & 255] = *byte;
            }
        }
        for index in 0..wire.rx {
            self.bytes[0x80 + wire.tx.len() + index] = if wire.opcode == 3 && !wire.tx.is_empty() {
                self.memory[(usize::from(wire.tx[0]) + index) & 255]
            } else {
                wire.opcode.wrapping_add(index as u8) ^ 0xa5
            };
        }
        self.complete += 1;
        0
    }
}
struct Peer(Rc<RefCell<State>>);
impl Drop for Peer {
    fn drop(&mut self) {
        self.0.borrow_mut().drops += 1;
    }
}
// SAFETY: independent single-threaded register peer keeps its backing
// and models posted effects/failures, engine execution and every access width.
unsafe impl Registers for Peer {
    fn profile(&self) -> Profile {
        self.0.borrow().profile
    }
    fn read8(&mut self, offset: usize) -> Result<u8, IoError> {
        let mut s = self.0.borrow_mut();
        s.before(Access::Read8(offset))?;
        assert!(matches!(
            offset,
            0x1d | 0x45 | 0x47 | 0x48 | 0x4b | 0x80..=0xc5
        ));
        if offset >= 0x80 {
            assert!(s.pending.is_none(), "read before hardware completion");
        }
        let value = s.bytes[offset];
        s.after()?;
        Ok(value)
    }
    fn write8(&mut self, offset: usize, value: u8) -> Result<(), IoError> {
        let mut s = self.0.borrow_mut();
        s.before(Access::Write8(offset, value))?;
        assert!(matches!(
            offset,
            0x1d | 0x45 | 0x47 | 0x48 | 0x4b | 0x80..=0xc5
        ));
        assert!(
            !s.initial_busy && s.pending.is_none(),
            "hardware modified while busy"
        );
        if s.ignore != Some(offset) {
            s.bytes[offset] = value;
            if offset == 0x47 && value & 128 != 0 {
                assert_eq!(s.profile, Profile::V2);
                s.bytes[offset] &= !128;
                let opcode = s.bytes[0x45];
                s.start(opcode);
            }
        }
        s.after()
    }
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        let mut s = self.0.borrow_mut();
        s.before(Access::Read32(offset))?;
        assert!(matches!(offset, 0 | 0x20 | 0x4c | 0x6c));
        let is_status = (s.profile == Profile::V1 && offset == 0)
            || (s.profile == Profile::V2 && offset == 0x4c);
        let value = if is_status {
            let status = s.status();
            (s.word(offset) & !(1 << 31)) | status
        } else {
            s.word(offset)
        };
        s.after()?;
        Ok(value)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        let mut s = self.0.borrow_mut();
        s.before(Access::Write32(offset, value))?;
        assert!(matches!(offset, 0 | 0x20 | 0x6c));
        assert!(
            !s.initial_busy && s.pending.is_none(),
            "hardware modified while busy"
        );
        if s.ignore != Some(offset) {
            s.store(
                offset,
                if offset == 0 {
                    value & !((1 << 16) | (1 << 20))
                } else {
                    value
                },
            );
            if offset == 0 && value & (1 << 20) != 0 {
                s.cleared = true;
            }
            if offset == 0 && value & (1 << 16) != 0 {
                assert_eq!(s.profile, Profile::V1);
                s.start(value as u8);
            }
        }
        s.after()
    }
}
fn host(profile: Profile) -> (Controller<Peer, Time>, Rc<RefCell<State>>) {
    let time = Time(Rc::new(Cell::new(0)));
    let state = Rc::new(RefCell::new(State {
        bytes: [0; 0xc6],
        memory: [0x5a; 256],
        time: time.clone(),
        log: vec![],
        wire: vec![],
        pending: None,
        complete: 0,
        profile,
        cleared: false,
        stuck: false,
        initial_busy: false,
        fail: None,
        late: None,
        ignore: None,
        drops: 0,
    }));
    state.borrow_mut().bytes[0x1d] = 0xb0;
    state.borrow_mut().store(0x20, 0x8100_0010);
    state.borrow_mut().store(0x6c, 0xc000_00a3);
    let host = Controller::new(Peer(state.clone()), time, 10_000)
        .ok()
        .unwrap();
    (host, state)
}
fn device() -> Device {
    Device {
        chip_select: 2,
        max_hz: 4_000_000,
        mode: Mode::Mode0,
    }
}

#[test]
fn profiles_refuse_hid2_and_unknown_controller() {
    assert_eq!(Profile::from_acpi_id("AMDI0061"), Some(Profile::V1));
    assert_eq!(Profile::from_acpi_id("AMDI0062"), Some(Profile::V2));
    assert_eq!(Profile::from_acpi_id("AMDI0063"), None);
    assert_eq!(Profile::from_acpi_id("INT33C0"), None);
}
#[test]
fn unusable_native_clock_returns_original_owners_before_busy_register_access() {
    let (h, state) = host(Profile::V2);
    let (registers, timer) = h.release().ok().unwrap();
    drop(timer);
    state.borrow_mut().initial_busy = true;
    let (error, registers, clock) = Controller::new(
        registers,
        Clock {
            ticks_per_microsecond: 0,
        },
        10_000,
    )
    .err()
    .unwrap();
    assert_eq!(error, ErrorKind::Configuration);
    assert_eq!(clock.ticks_per_microsecond, 0);
    assert!(state.borrow().log.is_empty());
    assert_eq!(state.borrow().drops, 0);
    drop(registers);
    assert_eq!(state.borrow().drops, 1);
}
#[test]
fn both_engines_write_read_changed_payload_and_command_only_completion() {
    for profile in [Profile::V1, Profile::V2] {
        let (mut h, s) = host(profile);
        let mut tx = vec![37];
        tx.extend((0..64).map(|i| (i * 11 + 17) as u8));
        h.command(device(), 2, &tx, &mut []).unwrap();
        assert_eq!(
            s.borrow().complete,
            1,
            "TX-only publication waited for effect"
        );
        let mut rx = [0xa5; 64];
        h.command(device(), 3, &[37], &mut rx).unwrap();
        assert_eq!(rx, tx[1..]);
        h.command(device(), 6, &[], &mut []).unwrap();
        assert_eq!(s.borrow().complete, 3);
        assert_eq!(s.borrow().wire[0].chip, 2);
        assert_eq!(s.borrow().wire[0].hz, 4_000_000);
        assert_eq!(s.borrow().bytes[0x1d] & !3, 0xb0);
        assert_eq!(s.borrow().word(0x20) & !(15 << 20), 0x8100_0010);
        assert_eq!(s.borrow().word(0x6c) & !(63 << 8), 0xc000_00a3);
        drop(h.release().ok().unwrap());
        assert_eq!(s.borrow().drops, 1);
    }
}
#[test]
fn all_bounded_tx_rx_partitions_preserve_fifo_positions() {
    for profile in [Profile::V1, Profile::V2] {
        let (mut h, s) = host(profile);
        for tx_length in 0..70 {
            for rx_length in 0..70 - tx_length {
                let tx: Vec<_> = (0..tx_length).map(|i| (i * 37 + 91) as u8).collect();
                let mut rx = vec![0xe7; rx_length];
                h.command(device(), 0x90, &tx, &mut rx).unwrap();
                assert_eq!(s.borrow().wire.last().unwrap().tx, tx);
                assert_eq!(
                    rx,
                    (0..rx_length)
                        .map(|i| 0x90u8.wrapping_add(i as u8) ^ 0xa5)
                        .collect::<Vec<_>>()
                );
            }
        }
        assert_eq!(s.borrow().complete, 2485);
        drop(h.release().ok().unwrap());
    }
}
#[test]
fn source_frequency_bins_and_downward_transitions_preserve_other_fields() {
    let expected = [
        100_000_000,
        66_660_000,
        50_000_000,
        33_330_000,
        22_220_000,
        16_660_000,
        4_000_000,
        3_170_000,
        800_000,
    ];
    for profile in [Profile::V1, Profile::V2] {
        let (mut h, s) = host(profile);
        for (i, hz) in expected.into_iter().enumerate() {
            for limit in [
                hz,
                hz + 1,
                if i == 0 {
                    u32::MAX
                } else {
                    expected[i - 1] - 1
                },
            ] {
                h.command(
                    Device {
                        max_hz: limit,
                        ..device()
                    },
                    6,
                    &[],
                    &mut [],
                )
                .unwrap();
                assert_eq!(s.borrow().wire.last().unwrap().hz, hz);
            }
        }
        drop(h.release().ok().unwrap());
    }
}
#[test]
fn invalid_requests_have_no_accesses_or_owner_poisoning() {
    let (mut h, s) = host(Profile::V2);
    for mode in [Mode::Mode1, Mode::Mode2, Mode::Mode3] {
        assert_eq!(
            h.command(Device { mode, ..device() }, 0, &[], &mut [])
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedMode
        );
    }
    for bad in [
        Device {
            chip_select: 4,
            ..device()
        },
        Device {
            max_hz: 799_999,
            ..device()
        },
    ] {
        assert_eq!(
            h.command(bad, 0, &[], &mut []).unwrap_err().kind,
            ErrorKind::Configuration
        );
    }
    let mut rx = [0; 69];
    assert_eq!(
        h.command(device(), 0, &[1], &mut rx).unwrap_err().kind,
        ErrorKind::Length
    );
    assert_eq!(
        h.command(device(), 0, &[0; 70], &mut []).unwrap_err().kind,
        ErrorKind::Length
    );
    assert!(s.borrow().log.is_empty());
    assert!(h.failure().is_none());
    h.command(device(), 6, &[], &mut []).unwrap();
    drop(h.release().ok().unwrap());
}
#[test]
fn every_access_before_after_failure_keeps_first_diagnostic_output_and_owner() {
    for profile in [Profile::V1, Profile::V2] {
        let (mut h, baseline) = host(profile);
        h.command(device(), 0x90, &[4, 5, 6], &mut [0; 7]).unwrap();
        let accesses = baseline.borrow().log.len();
        drop(h.release().ok().unwrap());
        for ordinal in 1..=accesses {
            for after in [false, true] {
                let (mut h, s) = host(profile);
                s.borrow_mut().fail = Some((ordinal, after));
                let mut output = [0xe7; 7];
                let error = h
                    .command(device(), 0x90, &[4, 5, 6], &mut output)
                    .unwrap_err();
                assert_eq!(error.kind, ErrorKind::Io);
                assert_eq!(output, [0xe7; 7]);
                assert_eq!(s.borrow().log.len(), ordinal);
                assert_eq!(h.failure(), Some(error));
                assert_eq!(
                    h.command(device(), 6, &[], &mut []).unwrap_err().kind,
                    ErrorKind::NeedsReset
                );
                assert_eq!(s.borrow().log.len(), ordinal, "no implicit replay/cleanup");
                assert!(h.release().is_err());
                assert_eq!(s.borrow().drops, 0);
            }
        }
    }
}
#[test]
fn every_late_access_including_final_cleanup_refuses_caller_publication() {
    for profile in [Profile::V1, Profile::V2] {
        let (mut h, baseline) = host(profile);
        h.command(device(), 0x90, &[4, 5, 6], &mut [0; 7]).unwrap();
        let accesses = baseline.borrow().log.len();
        drop(h.release().ok().unwrap());
        for ordinal in 1..=accesses {
            let (mut h, s) = host(profile);
            s.borrow_mut().late = Some(ordinal);
            let mut output = [0xe7; 7];
            let error = h
                .command(device(), 0x90, &[4, 5, 6], &mut output)
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Timeout);
            assert_eq!(s.borrow().log.len(), ordinal);
            assert_eq!(output, [0xe7; 7]);
            drop(h);
            assert_eq!(s.borrow().drops, 0);
        }
    }
}
#[test]
fn initial_and_posttrigger_busy_deadlines_never_replay_or_release() {
    for profile in [Profile::V1, Profile::V2] {
        for initial in [false, true] {
            let (mut h, s) = host(profile);
            s.borrow_mut().stuck = true;
            s.borrow_mut().initial_busy = initial;
            let error = h.command(device(), 2, &[1, 9], &mut []).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Timeout);
            assert_eq!(error.triggered, !initial);
            assert_eq!(s.borrow().wire.len(), usize::from(!initial));
            if initial {
                assert!(
                    s.borrow()
                        .log
                        .iter()
                        .all(|a| matches!(a, Access::Read32(_)))
                );
            }
            assert!(h.release().is_err());
            assert_eq!(s.borrow().drops, 0);
        }
    }
}
#[test]
fn ignored_configuration_writes_cannot_trigger_wrong_wire_metadata() {
    for offset in [0x1d, 0x20, 0x6c, 0x45, 0x48, 0x4b] {
        let (mut h, s) = host(Profile::V2);
        s.borrow_mut().ignore = Some(offset);
        let mut output = [0xe7; 7];
        assert_eq!(
            h.command(device(), 0x90, &[4, 5, 6], &mut output)
                .unwrap_err()
                .kind,
            ErrorKind::Readback
        );
        assert_eq!(output, [0xe7; 7]);
        assert!(s.borrow().wire.is_empty());
        drop(h);
        assert_eq!(s.borrow().drops, 0);
    }
    let (mut h, state) = host(Profile::V1);
    state.borrow_mut().ignore = Some(0);
    assert_eq!(
        h.command(device(), 0x90, &[], &mut []).unwrap_err().kind,
        ErrorKind::Readback
    );
    assert!(state.borrow().wire.is_empty());
}
#[test]
fn wraparound_clock_and_explicit_release_drop_each_original_owner_once() {
    for profile in [Profile::V1, Profile::V2] {
        let (mut h, s) = host(profile);
        s.borrow().time.0.set(u64::MAX - 10);
        h.command(device(), 0x90, &[0; 5], &mut [0; 7]).unwrap();
        assert!(s.borrow().time.0.get() < 10_000);
        drop(h.release().ok().unwrap());
        assert_eq!(s.borrow().drops, 1);
        let (h, s) = host(profile);
        drop(h);
        assert_eq!(
            s.borrow().drops,
            0,
            "Drop never invents successful retirement"
        );
    }
}

#[test]
#[ignore = "oracle: STELA_AMD_SPI_TRACE"]
fn unchanged_linux_fifo_commands_match_all_4970_bounded_partitions() {
    extern crate std;
    let path = std::env::var("STELA_AMD_SPI_TRACE").expect("pinned oracle trace path");
    let trace = std::fs::read_to_string(path).unwrap();
    let hex = |s: &str| -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    };
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 13);
        let number = |i: usize| fields[i].parse::<usize>().unwrap();
        let profile = match number(0) {
            1 => Profile::V1,
            2 => Profile::V2,
            _ => panic!("source profile"),
        };
        let (mut h, state) = host(profile);
        let device = Device {
            chip_select: number(1) as u8,
            max_hz: number(2) as u32,
            mode: Mode::Mode0,
        };
        let tx: Vec<_> = (0..number(4)).map(|i| (i * 37 + 91) as u8).collect();
        let mut rx = vec![0xe7; number(5)];
        h.command(device, number(3) as u8, &tx, &mut rx).unwrap();
        assert_eq!(number(6), 0, "source protocol success");
        assert_eq!(number(7), tx.len() + rx.len() + 1);
        assert_eq!(
            state.borrow().wire,
            [Wire {
                chip: device.chip_select,
                hz: number(8) as u32,
                opcode: number(3) as u8,
                tx: hex(fields[9]),
                rx: rx.len(),
            }]
        );
        assert_eq!(rx, hex(fields[10]));
        assert_eq!(
            state.borrow().complete,
            1,
            "native also awaits TX-only completion"
        );
        assert_eq!(
            number(12),
            usize::from(!rx.is_empty()),
            "unchanged Linux TX-only wait limitation stays visible"
        );
        assert_eq!(
            number(11) & 3,
            if profile == Profile::V1 {
                usize::from(device.chip_select)
            } else {
                0
            }
        );
        assert_eq!(state.borrow().bytes[0x1d] & 3, number(11) as u8 & 3);
        assert_eq!(
            state.borrow().bytes[0x1d] & !3,
            0xb0,
            "native preserves upper selector bits"
        );
        drop(h.release().ok().unwrap());
        cases += 1;
    }
    assert_eq!(cases, 4970);
}
