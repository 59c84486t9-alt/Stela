use super::*;
use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};
mod timer;

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
    Read(usize),
    Write(usize, u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    chip: u8,
    mode: u8,
    bits: u8,
    hz: u32,
    tx: u32,
    rx: u32,
}
struct Hardware {
    registers: Vec<u32>,
    time: Time,
    description: Description,
    tx: VecDeque<u32>,
    rx: VecDeque<u32>,
    wire: Vec<Frame>,
    log: Vec<Access>,
    cs_log: Vec<(u8, bool, u64)>,
    selected: u8,
    active: bool,
    active_high: [bool; 4],
    select_at: u64,
    tail: usize,
    gated: bool,
    private: usize,
    select: usize,
    mask: u32,
    shift: u32,
    fail: Option<(usize, bool)>,
    late: Option<usize>,
    ignore: Option<usize>,
    error_after: Option<usize>,
    freeze: bool,
    spurious: bool,
    sticky: u32,
    drops: usize,
}
impl Hardware {
    fn tick(&mut self) {
        self.time.0.set(self.time.0.get().wrapping_add(1));
        if self.tail != 0 {
            self.tail -= 1;
        }
        if self.freeze || self.registers[0] & 128 == 0 || !self.active {
            return;
        }
        if let Some(value) = self.tx.pop_front() {
            assert!(self.rx.len() < 16, "actual receive FIFO overflow");
            let cr0 = self.registers[0];
            let cr1 = self.registers[1];
            let bits = ((cr0 & 15) + 1 + if cr0 & (1 << 20) != 0 { 16 } else { 0 }) as u8;
            let mask = u32::MAX >> (32 - bits);
            let received = if cr1 & 4 != 0 {
                value
            } else {
                value.rotate_left(1) ^ 0x5a5a_5a5a
            } & mask;
            self.wire.push(Frame {
                chip: self.selected,
                mode: ((cr1 >> 3) & 3) as u8,
                bits,
                hz: self.description.input_clock_hz / (1 + ((cr0 >> 8) & 4095)),
                tx: value & mask,
                rx: received,
            });
            self.rx.push_back(received);
            self.tail = 2;
            if self.error_after == Some(self.wire.len()) {
                self.sticky |= 1 << 7;
            }
        }
    }
    fn begin(&mut self, access: Access) -> Result<(), IoError> {
        self.log.push(access);
        self.tick();
        if self.late == Some(self.log.len()) {
            self.time.0.set(self.time.0.get().wrapping_add(10_000));
        }
        if self.fail == Some((self.log.len(), false)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn end(&self) -> Result<(), IoError> {
        if self.fail == Some((self.log.len(), true)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn status(&self) -> u32 {
        self.sticky
            | if !self.rx.is_empty() || self.spurious {
                8
            } else {
                0
            }
            | if !self.tx.is_empty() || self.tail != 0 {
                16
            } else {
                0
            }
            | if self.tx.len() < 16 { 4 } else { 0 }
            | ((self.tx.len().min(15) as u32) << 8)
    }
    fn apply_cs(&mut self) {
        let control = self.registers[(self.private + self.select) / 4];
        let selected = ((control & self.mask) >> self.shift) as u8;
        let high = control & 2 != 0;
        let active = high == self.active_high[usize::from(selected)];
        if active && (!self.active || selected != self.selected) {
            // The selector latches separately from the level. The
            // independent silicon peer requires at least two input cycles.
            assert!(
                self.time.0.get().wrapping_sub(self.select_at)
                    >= 2_000_000u64.div_ceil(u64::from(self.description.input_clock_hz)),
                "CS select/level glitch"
            );
        }
        if active != self.active || selected != self.selected {
            self.cs_log.push((selected, high, self.time.0.get()));
        }
        if !active && self.active {
            assert!(
                self.tx.is_empty() && self.tail == 0,
                "CS released before last serial bit"
            );
        }
        self.selected = selected;
        self.active = active;
    }
}
struct Peer(Rc<RefCell<Hardware>>);
impl Drop for Peer {
    fn drop(&mut self) {
        self.0.borrow_mut().drops += 1;
    }
}
// SAFETY: isolated original register/peripheral/timer backing. The peer models
// FIFO serial effects independently from the production transfer logic.
unsafe impl Registers for Peer {
    fn description(&self) -> Description {
        self.0.borrow().description
    }
    fn bytes(&self) -> usize {
        self.0.borrow().registers.len() * 4
    }
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        let mut h = self.0.borrow_mut();
        h.begin(Access::Read(offset))?;
        assert_eq!(offset & 3, 0);
        let value = match offset {
            8 => h.status(),
            0x10 => h.rx.pop_front().expect("read past actual receive FIFO"),
            _ => h.registers[offset / 4],
        };
        h.end()?;
        Ok(value)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        let mut h = self.0.borrow_mut();
        h.begin(Access::Write(offset, value))?;
        assert_eq!(offset & 3, 0);
        if h.ignore != Some(offset) {
            match offset {
                8 => h.sticky &= !value,
                0x10 => {
                    assert!(h.active, "serial data queued without actual CS");
                    assert_ne!(h.registers[0] & 128, 0, "SSP disabled");
                    assert_eq!(
                        h.registers[1] & (3 | 1 << 19 | 3 << 20),
                        0,
                        "PIO published IRQ or DMA service"
                    );
                    assert!(h.tx.len() < 16, "actual transmit FIFO overflow");
                    h.tx.push_back(value);
                }
                _ => {
                    if offset == 0 && value & 128 == 0 {
                        assert!(h.tx.is_empty() && h.tail == 0, "disabled in-flight engine");
                    }
                    if offset == h.private + h.select
                        && h.registers[offset / 4] & h.mask != value & h.mask
                    {
                        h.select_at = h.time.0.get();
                    }
                    h.registers[offset / 4] = value;
                    if offset == h.private + h.select && !h.gated {
                        h.apply_cs();
                    }
                    if offset == h.private + 0x38 && value & 3 == 3 {
                        h.apply_cs();
                    }
                }
            }
        }
        h.end()
    }
}
const PROFILES: [Profile; 6] = [
    Profile::LynxPoint,
    Profile::BayTrail,
    Profile::Braswell,
    Profile::Sunrisepoint,
    Profile::Broxton,
    Profile::CannonLake,
];
fn host(profile: Profile) -> (Controller<Peer, Time>, Rc<RefCell<Hardware>>) {
    let (private, select, shift, mask, cs, gated) = match profile {
        Profile::LynxPoint => (0x800, 0x18, 0, 0, 1, false),
        Profile::BayTrail => (0x400, 0x18, 0, 0, 1, false),
        Profile::Braswell => (0x400, 0x18, 2, 4, 2, false),
        Profile::Sunrisepoint => (0x200, 0x24, 0, 0, 1, false),
        Profile::Broxton | Profile::CannonLake => (0x200, 0x24, 8, 768, 4, true),
    };
    let description = Description {
        profile,
        input_clock_hz: 50_000_000,
        chip_selects: cs,
    };
    let time = Time(Rc::new(Cell::new(0)));
    let hardware = Rc::new(RefCell::new(Hardware {
        registers: vec![0; 0x900 / 4],
        time: time.clone(),
        description,
        tx: VecDeque::new(),
        rx: VecDeque::new(),
        wire: vec![],
        log: vec![],
        cs_log: vec![],
        selected: 0,
        active: false,
        active_high: [false; 4],
        select_at: 0,
        tail: 0,
        gated,
        private,
        select,
        shift,
        mask,
        fail: None,
        late: None,
        ignore: None,
        error_after: None,
        freeze: false,
        spurious: false,
        sticky: 1 << 30,
        drops: 0,
    }));
    hardware.borrow_mut().registers[(private + select) / 4] = 0x8000_0042;
    hardware.borrow_mut().registers[(private + 0x38) / 4] = 0x1234_5670;
    hardware.borrow_mut().registers[(private + 0xfc) / 4] = 15 << 9 | 2 << 4;
    (
        Controller::new(Peer(hardware.clone()), time, 10_000)
            .ok()
            .unwrap(),
        hardware,
    )
}
fn device() -> Device {
    Device {
        chip_select: 0,
        mode: Mode::Mode0,
        active_high: false,
        loopback: false,
    }
}
fn transfer<'a>(
    tx: Option<&'a [u8]>,
    rx: Option<&'a mut [u8]>,
    words: usize,
    bits: u8,
) -> Transfer<'a> {
    Transfer {
        tx,
        rx,
        words,
        bits_per_word: bits,
        max_hz: 4_000_000,
        delay_us: 0,
        cs_change: false,
        cs_change_delay_us: 0,
    }
}

#[test]
fn atom_firmware_selection_is_translated_without_underflow() {
    assert_eq!(Profile::BayTrail.firmware_chip_select(0), None);
    assert_eq!(Profile::BayTrail.firmware_chip_select(1), Some(0));
    assert_eq!(Profile::Braswell.firmware_chip_select(2), Some(1));
    assert_eq!(Profile::CannonLake.firmware_chip_select(2), Some(2));
}

#[test]
fn every_lpss_layout_initializes_defaults_private_cs_and_hardware_caps() {
    for profile in PROFILES {
        let (mut h, hw) = host(profile);
        hw.borrow_mut().rx.extend([9, 8, 7]);
        h.initialize().unwrap();
        let s = hw.borrow();
        assert_eq!(s.registers[0], 0x207);
        assert_eq!(s.registers[1], 7 << 10 | 7 << 6);
        assert_eq!(s.registers[0x28 / 4], 0);
        assert_eq!(s.registers[0x2c / 4], 0);
        assert_eq!(s.registers[(s.private + s.select) / 4] & 3, 3);
        assert!(s.rx.is_empty());
        assert_eq!(s.sticky, 1 << 30);
        assert_eq!(h.chip_selects(), s.description.chip_selects);
        drop(s);
        drop(h.release().ok().unwrap());
        assert_eq!(hw.borrow().drops, 1);
    }
}
#[test]
fn all_word_sizes_modes_full_duplex_and_null_directions_execute_serial_words() {
    for profile in PROFILES {
        let (mut h, hw) = host(profile);
        h.initialize().unwrap();
        for bits in 4..=32u8 {
            for mode in [Mode::Mode0, Mode::Mode1, Mode::Mode2, Mode::Mode3] {
                for direction in 0..3 {
                    let width = usize::from(bits.div_ceil(8).next_power_of_two());
                    let words = 37;
                    let tx: Vec<u8> = (0..words * width).map(|i| (i * 29 + 13) as u8).collect();
                    let mut rx = vec![0xe7; words * width];
                    let device = Device {
                        mode,
                        loopback: bits.is_multiple_of(2),
                        ..device()
                    };
                    h.message(
                        device,
                        &mut [transfer(
                            if direction == 1 { None } else { Some(&tx) },
                            if direction == 2 { None } else { Some(&mut rx) },
                            words,
                            bits,
                        )],
                    )
                    .unwrap();
                    let s = hw.borrow();
                    assert_eq!(s.wire.len(), words);
                    assert!(!s.active);
                    assert!(s.tx.is_empty() && s.rx.is_empty());
                    for (index, frame) in s.wire.iter().enumerate() {
                        let mut value = [0; 4];
                        if direction != 1 {
                            value[..width].copy_from_slice(&tx[index * width..(index + 1) * width]);
                        }
                        let value = u32::from_le_bytes(value) & (u32::MAX >> (32 - bits));
                        assert_eq!(frame.tx, value);
                        assert_eq!(frame.bits, bits);
                        assert_eq!(
                            frame.mode,
                            match mode {
                                Mode::Mode0 => 0,
                                Mode::Mode1 => 2,
                                Mode::Mode2 => 1,
                                Mode::Mode3 => 3,
                            }
                        );
                        assert_eq!(frame.hz, 50_000_000 / 13);
                        let expected = if device.loopback {
                            value
                        } else {
                            value.rotate_left(1) ^ 0x5a5a_5a5a
                        } & (u32::MAX >> (32 - bits));
                        if direction != 2 {
                            assert_eq!(
                                &rx[index * width..(index + 1) * width],
                                &expected.to_le_bytes()[..width]
                            );
                        }
                    }
                    drop(s);
                    let mut s = hw.borrow_mut();
                    s.log.clear();
                    s.wire.clear();
                    s.cs_log.clear();
                }
            }
        }
        drop(h.release().ok().unwrap());
    }
}
#[test]
fn cs_selection_latch_and_dynamic_gate_workaround_preserve_other_bits() {
    for profile in [Profile::Braswell, Profile::Broxton, Profile::CannonLake] {
        let (mut h, hw) = host(profile);
        h.initialize().unwrap();
        h.message(
            Device {
                chip_select: 1,
                ..device()
            },
            &mut [transfer(Some(&[9, 8, 7]), None, 3, 8)],
        )
        .unwrap();
        assert!(hw.borrow().wire.iter().all(|f| f.chip == 1));
        assert!(!hw.borrow().active);
        let s = hw.borrow();
        assert_eq!(
            s.registers[(s.private + s.select) / 4] & !(s.mask | 3),
            0x8000_0040
        );
        if s.gated {
            assert_eq!(s.registers[(s.private + 0x38) / 4], 0x1234_5670);
            assert!(
                s.log
                    .iter()
                    .any(|a| matches!(a,Access::Write(at,v)if *at==s.private+0x38&&v&3==3))
            );
        }
        drop(s);
        drop(h.release().ok().unwrap());
    }
}
#[test]
fn multi_transfer_cs_hold_changes_delay_and_zero_length_have_pin_effects() {
    let (mut h, hw) = host(Profile::CannonLake);
    h.initialize().unwrap();
    let mut first = transfer(Some(&[1, 2]), None, 2, 8);
    first.cs_change = true;
    first.delay_us = 5;
    first.cs_change_delay_us = 7;
    let mut last = transfer(None, None, 0, 8);
    last.cs_change = true;
    last.delay_us = 9;
    h.message(device(), &mut [first, last]).unwrap();
    assert!(hw.borrow().active);
    assert_eq!(hw.borrow().wire.len(), 2);
    assert!(hw.borrow().cs_log.len() >= 3);
    let before = hw.borrow().cs_log.len();
    h.message(device(), &mut [transfer(Some(&[3]), None, 1, 8)])
        .unwrap();
    assert_eq!(
        hw.borrow().cs_log.len(),
        before + 1,
        "same held device did not pulse CS before next message"
    );
    assert!(!hw.borrow().active);
    drop(h.release().ok().unwrap());
    assert_eq!(hw.borrow().drops, 1);
}
#[test]
fn every_message_access_failure_and_late_access_fences_output_and_original_owner() {
    for profile in [Profile::LynxPoint, Profile::CannonLake] {
        let (mut base, hw) = host(profile);
        base.initialize().unwrap();
        hw.borrow_mut().log.clear();
        base.message(
            device(),
            &mut [transfer(Some(&[1, 2, 3]), Some(&mut [0; 3]), 3, 8)],
        )
        .unwrap();
        let count = hw.borrow().log.len();
        drop(base.release().ok().unwrap());
        for ordinal in 1..=count {
            for kind in 0..3 {
                let (mut h, hw) = host(profile);
                h.initialize().unwrap();
                {
                    let mut s = hw.borrow_mut();
                    s.log.clear();
                    if kind == 2 {
                        s.late = Some(ordinal);
                    } else {
                        s.fail = Some((ordinal, kind == 1));
                    }
                }
                let mut output = [0xe7; 3];
                let error = h
                    .message(
                        device(),
                        &mut [transfer(Some(&[1, 2, 3]), Some(&mut output), 3, 8)],
                    )
                    .unwrap_err();
                assert_eq!(
                    error.kind,
                    if kind == 2 {
                        ErrorKind::Timeout
                    } else {
                        ErrorKind::Io
                    }
                );
                assert_eq!(output, [0xe7; 3]);
                assert_eq!(hw.borrow().log.len(), ordinal);
                let count = hw.borrow().log.len();
                assert_eq!(
                    h.message(device(), &mut [transfer(None, None, 0, 8)])
                        .unwrap_err()
                        .kind,
                    ErrorKind::NeedsReset
                );
                assert_eq!(hw.borrow().log.len(), count);
                assert_eq!(h.failure(), Some(error));
                assert!(h.release().is_err());
                assert_eq!(hw.borrow().drops, 0);
            }
        }
    }
}
#[test]
fn geometry_and_clock_refusals_precede_effects_and_hardware_cs_caps_narrow_board_grant() {
    let (mut h, hw) = host(Profile::CannonLake);
    hw.borrow_mut().registers[(0x200 + 0xfc) / 4] = 3 << 9;
    h.initialize().unwrap();
    assert_eq!(h.chip_selects(), 2);
    hw.borrow_mut().log.clear();
    for bits in [0, 3, 33, 255] {
        assert_eq!(
            h.message(device(), &mut [transfer(None, None, 1, bits)])
                .unwrap_err()
                .kind,
            ErrorKind::Configuration
        );
    }
    let mut t = transfer(None, None, 1, 8);
    t.max_hz = 1;
    assert_eq!(
        h.message(device(), &mut [t]).unwrap_err().kind,
        ErrorKind::Configuration
    );
    assert_eq!(
        h.message(device(), &mut [transfer(Some(&[1]), None, 2, 8)])
            .unwrap_err()
            .kind,
        ErrorKind::Length
    );
    assert_eq!(
        h.message(
            Device {
                chip_select: 2,
                ..device()
            },
            &mut [transfer(None, None, 0, 8)]
        )
        .unwrap_err()
        .kind,
        ErrorKind::Configuration
    );
    assert_eq!(
        h.message(
            Device {
                active_high: true,
                ..device()
            },
            &mut [transfer(None, None, 0, 8)]
        )
        .unwrap_err()
        .kind,
        ErrorKind::UnsupportedPolarity
    );
    assert!(hw.borrow().log.is_empty());
    assert!(h.failure().is_none());
    drop(h.release().ok().unwrap());
    let (h, hw) = host(Profile::LynxPoint);
    let (r, t) = h.release().ok().unwrap();
    drop(t);
    let (error, r, _) = Controller::new(
        r,
        Clock {
            ticks_per_microsecond: 0,
        },
        10_000,
    )
    .err()
    .unwrap();
    assert_eq!(error, ErrorKind::Configuration);
    assert!(hw.borrow().log.is_empty());
    drop(r);
    assert_eq!(hw.borrow().drops, 1);
}
#[test]
fn fifo_errors_stall_and_unexpected_receive_never_publish_or_replay() {
    for fault in 0..3 {
        let (mut h, hw) = host(Profile::CannonLake);
        h.initialize().unwrap();
        {
            let mut s = hw.borrow_mut();
            match fault {
                0 => s.freeze = true,
                1 => s.error_after = Some(2),
                _ => s.spurious = true,
            }
        }
        let mut output = [0xe7; 4];
        let error = h
            .message(
                device(),
                &mut [transfer(Some(&[1, 2, 3, 4]), Some(&mut output), 4, 8)],
            )
            .unwrap_err();
        assert_eq!(output, [0xe7; 4]);
        assert_eq!(
            error.kind,
            if fault == 0 {
                ErrorKind::Timeout
            } else {
                ErrorKind::Fifo
            }
        );
        drop(h);
        assert_eq!(hw.borrow().drops, 0);
    }
}

#[test]
fn initialization_failures_before_and_after_each_effect_keep_the_original_device() {
    for profile in PROFILES {
        let (mut h, hw) = host(profile);
        h.initialize().unwrap();
        let accesses = hw.borrow().log.len();
        drop(h.release().ok().unwrap());
        for ordinal in 1..=accesses {
            for after in [false, true] {
                let (mut h, hw) = host(profile);
                hw.borrow_mut().fail = Some((ordinal, after));
                let error = h.initialize().unwrap_err();
                assert_eq!(error.kind, ErrorKind::Io);
                assert_eq!(hw.borrow().log.len(), ordinal);
                assert_eq!(h.failure(), Some(error));
                assert_eq!(h.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
                assert_eq!(hw.borrow().log.len(), ordinal);
                drop(h);
                assert_eq!(hw.borrow().drops, 0);
            }
        }
    }
}

#[test]
#[ignore = "oracle: STELA_PXA2XX_SPI_TRACE"]
fn unchanged_linux_lpss_profiles_cs_clock_and_all_word_helpers_match_native_io() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_PXA2XX_SPI_TRACE").expect("pinned source trace"),
    )
    .unwrap();
    let hex = |s: &str| -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&s[at..at + 2], 16).unwrap())
            .collect()
    };
    let mut count = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split(',').collect();
        let num = |i: usize| fields[i].parse::<u32>().unwrap();
        let profile = PROFILES[num(1) as usize];
        if fields[0] == "P" {
            let layout = profile.layout();
            assert_eq!(layout.private, num(2) as usize);
            assert_eq!(layout.select, num(3) as usize);
            assert_eq!(layout.capabilities, fields[4] != "-1");
            assert_eq!(layout.rx, num(5));
            assert_eq!(layout.tx_low, num(6));
            assert_eq!(layout.tx_high, num(7));
            assert_eq!(layout.select_shift, num(8));
            assert_eq!(layout.select_mask, num(9));
            assert_eq!(layout.gated_cs, num(10) != 0);
        } else {
            assert_eq!(fields[0], "W");
            assert_eq!(fields.len(), 15);
            let bits = num(2) as u8;
            let mode = [Mode::Mode0, Mode::Mode1, Mode::Mode2, Mode::Mode3][num(3) as usize];
            let direction = num(4);
            let width = usize::from(bits.div_ceil(8).next_power_of_two());
            let mut tx = vec![0; 8 * width];
            let mut rx = vec![0xe7; 8 * width];
            for index in 0..8 {
                let value = 0x1234_5678u32 + (index as u32) * 0x10101;
                tx[index * width..(index + 1) * width]
                    .copy_from_slice(&value.to_le_bytes()[..width]);
            }
            let (mut h, hw) = host(profile);
            h.initialize().unwrap();
            let mut t = transfer(
                if direction == 1 { None } else { Some(&tx) },
                if direction == 2 { None } else { Some(&mut rx) },
                8,
                bits,
            );
            t.max_hz = num(5);
            h.message(
                Device {
                    chip_select: num(6) as u8,
                    mode,
                    loopback: bits.is_multiple_of(2),
                    ..device()
                },
                &mut [t],
            )
            .unwrap();
            let s = hw.borrow();
            assert_eq!(s.registers[0] | 128, num(7));
            assert_eq!(s.registers[1], num(8));
            assert_eq!(s.registers[0x48 / 4] & 255, num(9));
            assert_eq!(s.registers[0x44 / 4] & 65535, num(10));
            let expected_words: Vec<u32> = (0..64)
                .step_by(8)
                .map(|at| u32::from_str_radix(&fields[11][at..at + 8], 16).unwrap())
                .collect();
            assert_eq!(
                s.wire.iter().map(|f| f.tx).collect::<Vec<_>>(),
                expected_words
            );
            if direction != 2 {
                assert_eq!(rx, hex(fields[12]));
            }
            assert_eq!(s.registers[(s.private + s.select) / 4], num(13));
            assert_eq!(
                num(14),
                if num(6) != 0 { 40 } else { 0 },
                "unchanged source two-input-cycle delay service"
            );
            drop(s);
            drop(h.release().ok().unwrap());
        }
        count += 1;
    }
    assert_eq!(count, 5622);
}
