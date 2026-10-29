//! Independent SD host/card register model: width writes, FIFO and ADMA
//! payload effects, card states, command/response completion and removal faults.
use super::*;
use alloc::collections::{BTreeMap, VecDeque};
pub(super) const CLOCK_TICKS_PER_US: u64 = 1000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum VoltageFault {
    DatHighBefore,
    OneDatLowBefore,
    Enable,
    StopClock,
    DatLowAfter,
    OneDatLowAfter,
}

pub(super) struct Hardware {
    pub caps: u32,
    pub caps2: u32,
    pub max_current: u32,
    pub ocr_voltage: u32,
    pub uhs_functions: u8,
    pub voltage_fault: Option<VoltageFault>,
    pub power_off_stuck: bool,
    pub uhs_timing_stuck: bool,
    pub tuning_iterations: usize,
    pub tuning_no_clock: bool,
    pub tuning_start_stuck: bool,
    pub silence_voltage_response: bool,
    pub tuning_commands: usize,
    pub mmc_fast_checks: bool,
    pub mmc_ddr52_checks: bool,
    pub mmc_sdr_hs_checks: bool,
    pub mmc_power_fault: bool,
    pub mmc_retune_phase: Option<usize>,
    pub mmc_fast_status_fault: Option<u8>,
    pub mmc_timing_fault: Option<(u8, u32, bool)>,
    pub tuning_round: usize,
    pub voltage_started: bool,
    voltage_changed_at: Option<u64>,
    voltage_restart_at: Option<u64>,
    sd_function: u8,
    sd_current: u8,
    pub version: u16,
    pub present: bool,
    pub writable: bool,
    pub kind: Kind,
    pub high_capacity: bool,
    pub legacy: bool,
    pub cid: u128,
    pub csd: u128,
    pub ext: Vec<u8>,
    pub scr: [u8; 8],
    pub disk: Vec<u8>,
    pub commands: Vec<(u8, u32, u16)>,
    pub writes: Vec<(usize, usize, u32)>,
    pub reads: usize,
    pub fail_command: Option<(u8, u32)>,
    pub card_status_error: Option<(u8, u32)>,
    pub silent: Option<u8>,
    pub reset_stuck: bool,
    pub clock_stuck: bool,
    pub remove_command: Option<u8>,
    pub corrupt_bus_width: bool,
    pub corrupt_bus_field: Option<usize>,
    pub fail_after_data: bool,
    pub data_error: bool,
    pub never_ready: bool,
    pub command_after_notification: bool,
    pub initial_clock_seen: Option<u64>,
    pub single_power_write: bool,
    pub dma_broken: bool,
    pub adma_broken: bool,
    pub reject_high_speed_bit: bool,
    pub wired_width: u8,
    pub o2_chip: Option<Rc<RefCell<O2Chip>>>,
    pub o2_pll_stuck: bool,
    pub o2_cd_mismatch: bool,
    pll_sequence: u8,
    pll_locked: bool,
    pub reset_after_settings: bool,
    pub fail_settings_reset: bool,
    pub settings_dirty: bool,
    notified: bool,
    clock_started: Option<u64>,
    regs: BTreeMap<usize, u32>,
    status: u32,
    selected: bool,
    app: bool,
    rca: u16,
    fifo: VecDeque<u8>,
    outgoing: Vec<u8>,
    expected: usize,
    destination: usize,
    block: usize,
    transfer_read: bool,
    storage_write: bool,
}
impl Hardware {
    /// Independently latched asynchronous hardware status; ordinary Port W1C
    /// writes consume these exact bits, including events arriving at a store.
    pub(super) fn latch_status(&mut self, status: u32) {
        self.status |= status;
    }
    pub fn new(kind: Kind, high_capacity: bool) -> Self {
        let mut cid = 0u128;
        put(&mut cid, 120, 8, 0x42);
        for (i, byte) in b"STELA1".iter().enumerate() {
            put(&mut cid, 96 - i as u32 * 8, 8, u32::from(*byte));
        }
        put(
            &mut cid,
            if kind == Kind::Sd { 24 } else { 16 },
            32,
            0x12345678,
        );
        let mut csd = 0u128;
        put(
            &mut csd,
            126,
            2,
            if kind == Kind::Sd && !high_capacity {
                0
            } else {
                1
            },
        );
        if kind == Kind::Mmc {
            put(&mut csd, 122, 4, 4);
        }
        put(&mut csd, 96, 8, 0x32); //25MHz
        put(&mut csd, 84, 12, (1 << 2) | (1 << 4) | (1 << 10));
        put(&mut csd, 80, 4, 9);
        put(&mut csd, 22, 4, 9);
        if kind == Kind::Sd && high_capacity {
            put(&mut csd, 48, 22, 3);
        } else {
            put(&mut csd, 62, 12, 1023);
            put(&mut csd, 47, 3, 0);
        }
        let mut ext = vec![0; 512];
        ext[192] = 8;
        ext[194] = 2;
        ext[196] = 3;
        ext[212..216].copy_from_slice(&4096u32.to_le_bytes());
        ext[249..253].copy_from_slice(&1024u32.to_le_bytes());
        ext[33] = 1;
        let mut disk = vec![0u8; 4096 * 512];
        for (i, byte) in disk.iter_mut().enumerate() {
            *byte = (i ^ (i >> 8)) as u8;
        }
        Self {
            caps: CAP_330 | CAP_ADMA2 | CAP_64 | CAP_HIGH_SPEED | CAP_8BIT | 100 << 8,
            caps2: 0,
            max_current: 0,
            ocr_voltage: 3 << 20,
            uhs_functions: 0,
            voltage_fault: None,
            power_off_stuck: false,
            uhs_timing_stuck: false,
            tuning_iterations: 3,
            tuning_no_clock: false,
            tuning_start_stuck: false,
            silence_voltage_response: false,
            tuning_commands: 0,
            mmc_fast_checks: false,
            mmc_ddr52_checks: false,
            mmc_sdr_hs_checks: false,
            mmc_power_fault: false,
            mmc_retune_phase: None,
            mmc_fast_status_fault: None,
            mmc_timing_fault: None,
            tuning_round: 0,
            voltage_started: false,
            voltage_changed_at: None,
            voltage_restart_at: None,
            sd_function: 0,
            sd_current: 0,
            version: 2,
            present: true,
            writable: true,
            kind,
            high_capacity,
            legacy: false,
            cid,
            csd,
            ext,
            scr: [2, 5, 0, 0, 0, 0, 0, 0],
            disk,
            commands: Vec::new(),
            writes: Vec::new(),
            reads: 0,
            fail_command: None,
            card_status_error: None,
            silent: None,
            reset_stuck: false,
            clock_stuck: false,
            remove_command: None,
            corrupt_bus_width: false,
            corrupt_bus_field: None,
            fail_after_data: false,
            data_error: false,
            never_ready: false,
            command_after_notification: false,
            initial_clock_seen: None,
            single_power_write: false,
            dma_broken: false,
            adma_broken: false,
            reject_high_speed_bit: false,
            wired_width: 4,
            o2_chip: None,
            o2_pll_stuck: false,
            o2_cd_mismatch: false,
            pll_sequence: 0,
            pll_locked: false,
            reset_after_settings: false,
            fail_settings_reset: false,
            settings_dirty: false,
            notified: false,
            clock_started: None,
            regs: BTreeMap::new(),
            status: 0,
            selected: false,
            app: false,
            rca: 0,
            fifo: VecDeque::new(),
            outgoing: Vec::new(),
            expected: 0,
            destination: 0,
            block: 0,
            transfer_read: false,
            storage_write: false,
        }
    }
    pub fn replace(&mut self) {
        self.present = true;
        self.status |= CARD_INSERT | CARD_REMOVE;
        self.selected = false;
        self.rca = 0;
        self.disk.fill(0x3c);
    }
    fn reg(&self, at: usize) -> u32 {
        *self.regs.get(&(at & !3)).unwrap_or(&0)
    }
    fn word(&self, at: usize) -> u16 {
        (self.reg(at) >> (8 * (at & 3))) as u16
    }
    fn byte(&self, at: usize) -> u8 {
        (self.reg(at) >> (8 * (at & 3))) as u8
    }
    fn write(&mut self, at: usize, width: usize, value: u32) {
        let mask = if width == 4 {
            u32::MAX
        } else {
            (1u32 << (width * 8)) - 1
        };
        let shift = 8 * (at & 3);
        self.regs.insert(
            at & !3,
            self.reg(at) & !(mask << shift) | (value & mask) << shift,
        );
    }
    fn response(&mut self, value: u32) {
        self.regs.insert(RESPONSE, value);
    }
    fn long(&mut self, value: u128) {
        let raw = value >> 8;
        for i in 0..4 {
            self.regs.insert(RESPONSE + 4 * i, (raw >> (32 * i)) as u32);
        }
    }
    fn r1(&self) -> u32 {
        if self.selected { 4 << 9 | 1 << 8 } else { 0 }
    }
    fn issue(&mut self, value: u16) {
        let cmd = (value >> 8) as u8;
        let argument = self.reg(ARGUMENT);
        let mode = self.word(TRANSFER_MODE);
        self.commands.push((cmd, argument, value));
        if let Some(chip) = &self.o2_chip {
            let chip = chip.borrow();
            assert!(chip.ready, "O2 command before finite/ADMA/power setup");
            assert_eq!(chip.reg32(0x304) >> 16, 0x2510);
            assert_eq!(chip.reg32(0x354) & (1 << 16 | 15 << 20), 0);
            assert!(self.pll_locked, "O2 card command without physical PLL lock");
        }
        assert!(
            !self.reset_after_settings || !self.settings_dirty,
            "ENE command before post-settings reset"
        );
        assert!(
            !self.dma_broken || mode & DMA == 0,
            "ENE broken DMA was enabled"
        );
        assert!(
            !self.adma_broken || mode & DMA == 0 || self.byte(HOST_CONTROL) & DMA_MASK == 0,
            "broken Intel ADMA enabled"
        );
        if self.notified {
            self.command_after_notification = true;
            self.status |= COMMAND_TIMEOUT | 1 << 15;
            return;
        }
        if cmd == 0 {
            let start = self.clock_started.expect("CMD0 before enabling card clock");
            let now = Clock {
                ticks_per_microsecond: 1,
            }
            .now_us();
            assert!(
                now - start >= 1000 * CLOCK_TICKS_PER_US,
                "CMD0 before >=74 clocks/1ms after enabling f_init"
            );
            self.initial_clock_seen = Some(now - start);
        }

        assert_ne!(
            self.word(CLOCK) & CLOCK_CARD,
            0,
            "card command without stable clock"
        );
        assert_ne!(self.byte(POWER) & POWER_ON, 0, "card command without power");
        if self.version >= 4 && self.word(HOST_CONTROL2) & (1 << 12) != 0 {
            assert_ne!(
                self.word(CLOCK) & CLOCK_PLL,
                0,
                "v4.1 card command before actual PLL enable"
            );
        }
        self.status &= !(RESPONSE_END | DATA_END | READ_READY | WRITE_READY);
        if self.remove_command == Some(cmd) {
            self.present = false;
            self.status |= CARD_REMOVE;
            return;
        }
        if self.silent == Some(cmd) {
            return;
        }
        if let Some((failed, status)) = self.fail_command
            && failed == cmd
        {
            self.status |= status | 1 << 15;
            return;
        }
        let app = self.app;
        self.app = false;
        let mut data = None;
        self.response(self.r1());
        match cmd {
            0 => {
                self.selected = false;
                self.rca = 0;
                self.ext[183] = 0;
                self.ext[185] = 0;
            }
            8 if self.kind == Kind::Sd => {
                if self.legacy {
                    self.status |= COMMAND_TIMEOUT | 1 << 15;
                    return;
                }
                self.response(argument);
            }
            55 => {
                if self.kind == Kind::Mmc {
                    self.response(1 << 22);
                } else {
                    self.app = true;
                    self.response(self.r1() | 1 << 5);
                }
            }
            41 if app && self.kind == Kind::Sd => self.response(
                1 << 31
                    | if self.high_capacity { 1 << 30 } else { 0 }
                    | 3 << 20
                    | if self.uhs_functions != 0 && argument & (1 << 24) != 0 {
                        1 << 24
                    } else {
                        0
                    },
            ),
            1 if self.kind == Kind::Mmc => self.response(
                1 << 31 | if self.high_capacity { 1 << 30 } else { 0 } | self.ocr_voltage,
            ),
            2 => self.long(self.cid),
            3 => {
                self.rca = if self.kind == Kind::Sd {
                    0x1234
                } else {
                    (argument >> 16) as u16
                };
                self.response(if self.kind == Kind::Sd {
                    u32::from(self.rca) << 16
                } else {
                    0
                });
            }
            9 => {
                assert_eq!(argument, u32::from(self.rca) << 16);
                self.long(self.csd);
            }
            7 => {
                self.selected = true;
                self.response(self.r1());
                self.status |= DATA_END;
            }
            13 => {
                assert_eq!(argument, u32::from(self.rca) << 16);
                if self.mmc_sdr_hs_checks && self.ext[185] == 1 {
                    assert_ne!(self.byte(HOST_CONTROL) & HIGH_SPEED, 0);
                }
                if self.mmc_fast_checks && self.ext[185] != 0 {
                    let mode = match self.ext[185] & 15 {
                        1 if self.mmc_ddr52_checks && self.ext[183] == 6
                            || self.mmc_retune_phase == Some(1) =>
                        {
                            4
                        }
                        1 => 1,
                        2 => 3,
                        3 => 7,
                        _ => panic!("unsupported MMC timing"),
                    };
                    assert_eq!(self.word(HOST_CONTROL2) & UHS_MODE, mode);
                    if !self.mmc_ddr52_checks {
                        assert_ne!(self.word(HOST_CONTROL2) & SIGNAL_180, 0);
                    }
                    if self.ext[185] == 2
                        && let Some(fault) = self.mmc_fast_status_fault.take()
                    {
                        if fault == 8 {
                            self.response(self.r1() | (1 << 17) | (1 << 15));
                            self.status |= RESPONSE_END;
                            return;
                        }
                        if fault != 0 {
                            let error = match fault {
                                1 => 1 << 17,
                                2 => (1 << 17) | RESPONSE_END,
                                3 => 1 << 18,
                                4 => 1 << 19,
                                5 => (7 << 17) | RESPONSE_END,
                                6 => (1 << 17) | (1 << 21),
                                _ => (1 << 17) | COMMAND_TIMEOUT,
                            };
                            self.status |= error | (1 << 15);
                            return;
                        }
                        self.response(self.r1() | (1 << 7));
                        self.status |= RESPONSE_END;
                        return;
                    }
                }
                self.response(if self.never_ready { 7 << 9 } else { self.r1() });
            }
            51 if app && self.kind == Kind::Sd => data = Some(self.scr.to_vec()),
            6 if app && self.kind == Kind::Sd => {
                assert_eq!(argument, 2);
            }
            6 if self.kind == Kind::Sd => {
                let mut bytes = vec![0; 64];
                bytes[13] = if self.uhs_functions != 0 {
                    self.uhs_functions
                } else {
                    2
                };
                bytes[7] = 15;
                if argument >> 31 != 0 {
                    let speed = argument as u8 & 15;
                    if speed != 15 {
                        self.sd_function = speed;
                    }
                    let current = (argument >> 12) as u8 & 15;
                    if current != 15 {
                        self.sd_current = current;
                    }
                }
                bytes[15] = self.sd_current << 4;
                bytes[16] = self.sd_function;
                data = Some(bytes);
            }
            11 if self.kind == Kind::Sd => {
                assert_ne!(self.uhs_functions, 0);
                assert_eq!(self.word(HOST_CONTROL2) & SIGNAL_180, 0);
                self.voltage_started = true;
                if self.silence_voltage_response {
                    return;
                }
            }
            19 | 21
                if cmd == 19 && self.kind == Kind::Sd || cmd == 21 && self.kind == Kind::Mmc =>
            {
                assert_ne!(self.word(HOST_CONTROL2) & SIGNAL_180, 0);
                assert_ne!(self.word(HOST_CONTROL2) & EXECUTE_TUNING, 0);
                assert_eq!(self.word(TRANSFER_MODE), READ);
                if cmd == 21 {
                    assert_eq!(self.ext[185], 2);
                    assert_eq!(self.ext[183], 2);
                    assert_eq!(self.word(HOST_CONTROL2) & UHS_MODE, 3);
                    assert_eq!(self.word(BLOCK_SIZE), 128);
                    assert_eq!(
                        self.byte(HOST_CONTROL) & (BUS8 | HIGH_SPEED),
                        BUS8 | HIGH_SPEED
                    );
                } else {
                    assert_eq!(self.word(BLOCK_SIZE), 64);
                    assert_eq!(
                        self.byte(HOST_CONTROL) & (BUS4 | HIGH_SPEED),
                        BUS4 | HIGH_SPEED
                    );
                }
                self.tuning_commands += 1;
                self.tuning_round += 1;
                if self.tuning_round == self.tuning_iterations {
                    let control = self.word(HOST_CONTROL2) & !EXECUTE_TUNING;
                    self.write(
                        HOST_CONTROL2,
                        2,
                        u32::from(control | if self.tuning_no_clock { 0 } else { TUNED_CLOCK }),
                    );
                }
                // Hardware consumes the entire pattern. Ordinary RESPONSE_END,
                // DATA_END and FIFO access would be driver errors here.
                self.status |= READ_READY;
                return;
            }
            6 if self.kind == Kind::Mmc => {
                assert_eq!(argument >> 24, 3);
                let index = ((argument >> 16) & 255) as usize;
                if matches!(index, 183 | 185)
                    && let Some(phase) = self.mmc_retune_phase
                {
                    let expected = [(185, 1), (183, 2), (185, 2), (185, 1), (183, 6), (185, 3)];
                    assert_eq!((index, (argument >> 8) as u8), expected[phase]);
                    if phase == 0 {
                        assert_ne!(
                            self.word(CLOCK) & 0xff00,
                            0,
                            "HS400 downgrade before reduced clock"
                        );
                    }
                    self.mmc_retune_phase = Some(phase + 1);
                }
                if self.mmc_sdr_hs_checks && index == 183 {
                    assert_eq!(self.ext[185], 1, "width changed before card HS timing");
                    assert_ne!(self.byte(HOST_CONTROL) & HIGH_SPEED, 0);
                    let clock = self.word(CLOCK);
                    let encoded = (clock >> 8 & 255) | (clock & 0xc0) << 2;
                    let divisor = if encoded == 0 { 1 } else { encoded * 2 };
                    let hz = (self.caps >> 8 & 255) * 1_000_000 / u32::from(divisor);
                    assert!(hz >= 25_000_000, "width validated at identification clock");
                }
                if index == 187 && self.mmc_power_fault {
                    self.status |= COMMAND_TIMEOUT | 1 << 15;
                    return;
                }
                if index == 185
                    && let Some((timing, status, reset_stuck)) = self.mmc_timing_fault
                    && (argument >> 8) as u8 == timing
                {
                    self.reset_stuck = reset_stuck;
                    self.status |= status | 1 << 15;
                    return;
                }
                self.ext[index] = (argument >> 8) as u8;
                if index == 34 && self.ext[index] == 3 {
                    self.notified = true;
                }

                self.status |= DATA_END;
            }
            8 if self.kind == Kind::Mmc && !self.selected => self.response(1 << 22),
            8 if self.kind == Kind::Mmc => {
                let mut ext = self.ext.clone();
                if self.corrupt_bus_width && self.byte(HOST_CONTROL) & (BUS4 | BUS8) != 0 {
                    ext[212] ^= 1;
                }
                if self.byte(HOST_CONTROL) & (BUS4 | BUS8) != 0
                    && let Some(index) = self.corrupt_bus_field
                {
                    ext[index] ^= 1;
                }
                data = Some(ext);
            }
            16 => assert_eq!(argument, 512),
            17 | 18 | 24 | 25 => {
                assert!(self.selected);
                if self.voltage_started {
                    assert_ne!(self.word(HOST_CONTROL2) & SIGNAL_180, 0);
                    assert_eq!(
                        self.word(HOST_CONTROL2) & UHS_MODE,
                        u16::from(self.sd_function)
                    );
                    if self.sd_function == 3
                        || self.sd_function == 2 && self.caps2 & CAP_SDR50_TUNING != 0
                    {
                        assert_ne!(
                            self.word(HOST_CONTROL2) & TUNED_CLOCK,
                            0,
                            "data before hardware tuning"
                        );
                    }
                }
                self.destination = if self.high_capacity {
                    argument as usize * 512
                } else {
                    argument as usize
                };
                let length = usize::from(self.word(BLOCK_SIZE) & 0xfff)
                    * usize::from(self.word(BLOCK_COUNT));
                assert!(self.destination + length <= self.disk.len());
                if cmd == 17 || cmd == 18 {
                    data = Some(self.disk[self.destination..self.destination + length].to_vec());
                } else {
                    self.storage_write = true;
                    data = Some(Vec::new());
                }
            }
            12 => {
                assert_eq!(value & 0xc0, 0xc0);
                self.status |= DATA_END;
            }
            _ => panic!("unexpected SDHCI card command{cmd} app={app}"),
        }
        if let Some((failed, status)) = self.card_status_error
            && failed == cmd
        {
            self.response(self.r1() | status);
        }
        self.status |= RESPONSE_END;
        if let Some(data) = data {
            if self.kind == Kind::Mmc {
                if self.mmc_ddr52_checks && self.ext[183] == 6 {
                    assert_eq!(self.word(HOST_CONTROL2) & UHS_MODE, 4);
                    assert_ne!(self.word(HOST_CONTROL2) & SIGNAL_180, 0);
                }
                let host_width = if self.byte(HOST_CONTROL) & BUS8 != 0 {
                    8
                } else if self.byte(HOST_CONTROL) & BUS4 != 0 {
                    4
                } else {
                    1
                };
                let card_width = match self.ext[183] {
                    0 => 1,
                    1 => 4,
                    2 | 6 | 0x86 => 8,
                    _ => panic!("unmodeled card bus width"),
                };
                if host_width > self.wired_width || host_width != card_width {
                    self.status |= 1 << 21 | 1 << 15; // DATA_CRC interrupt
                    return;
                }
            }
            assert_ne!(value & 0x20, 0, "card payload without command data bit");
            self.expected =
                usize::from(self.word(BLOCK_SIZE) & 0xfff) * usize::from(self.word(BLOCK_COUNT));
            self.block = usize::from(self.word(BLOCK_SIZE) & 0xfff);
            self.transfer_read = mode & READ != 0;
            if self.transfer_read {
                assert_eq!(data.len(), self.expected);
            }
            if mode & DMA != 0 {
                self.adma(data);
            } else {
                self.fifo = data.into();
                self.outgoing.clear();
                self.status |= if self.transfer_read {
                    READ_READY
                } else {
                    WRITE_READY
                };
            }
        }
    }
    fn adma(&mut self, data: Vec<u8>) {
        let v4 = self.word(HOST_CONTROL2) & (1 << 12) != 0;
        let wide = if v4 {
            self.word(HOST_CONTROL2) & (1 << 13) != 0
        } else {
            self.byte(HOST_CONTROL) & DMA_MASK == ADMA64
        };
        if v4 {
            assert_eq!(
                self.byte(HOST_CONTROL) & DMA_MASK,
                ADMA32,
                "v4 must use ADMA32 selection plus independent64bit address control"
            );
        }
        let table = u64::from(self.reg(ADMA_ADDRESS))
            | if wide {
                u64::from(self.reg(ADMA_ADDRESS_HIGH)) << 32
            } else {
                0
            };
        assert!(table > 65536 && table.is_multiple_of(4));
        // SAFETY: fixture hardware consumes only the driver's descriptor DMA.
        let (attributes, length, low, high) = unsafe {
            (
                (table as *const u16).read_volatile(),
                ((table + 2) as *const u16).read_volatile(),
                ((table + 4) as *const u32).read_volatile(),
                if wide {
                    ((table + 8) as *const u32).read_volatile()
                } else {
                    0
                },
            )
        };
        assert_eq!(attributes, 0x23);
        if v4 && wide {
            assert_eq!(
                // SAFETY: same live 16-byte descriptor allocated by the driver.
                unsafe { ((table + 12) as *const u32).read_volatile() },
                0,
                "reserved v4 descriptor high word"
            );
        }
        let length = if length == 0 {
            65536
        } else {
            usize::from(length)
        };
        assert_eq!(length, self.expected);
        let address = u64::from(low) | u64::from(high) << 32;
        assert!(address > 65536 && address.is_multiple_of(4));
        if self.data_error {
            self.status |= 1 << 25 | 1 << 15;
            return;
        }
        if self.transfer_read {
            // SAFETY: descriptor grants this live device-write range.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, length);
            }
        } else {
            // SAFETY: descriptor grants this live device-read range.
            let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
            assert!(self.storage_write);
            self.disk[self.destination..self.destination + length].copy_from_slice(bytes);
        }
        self.expected = 0;
        self.write(BLOCK_COUNT, 2, 0);
        if self.fail_after_data {
            return;
        }
        self.status |= DATA_END;
    }
    fn data_progress(&mut self) {
        if self.expected == 0 {
            self.status |= DATA_END;
            return;
        }
        if self.expected.is_multiple_of(self.block) {
            self.status |= if self.transfer_read {
                READ_READY
            } else {
                WRITE_READY
            };
        }
    }
}
pub(super) fn put(value: &mut u128, start: u32, count: u32, bits: u32) {
    let mask = ((1u128 << count) - 1) << start;
    *value = *value & !mask | u128::from(bits) << start;
}
pub(super) struct Port(pub Rc<RefCell<Hardware>>);

/// Separate physical PCI configuration register bank. Writes are protected and
/// consumed in the silicon-required order, independently of driver helpers.
pub(super) struct O2Chip {
    bytes: [u8; 4096],
    pub slots: Vec<alloc::rc::Weak<RefCell<Hardware>>>,
    pub writes: Vec<(usize, usize, u32)>,
    pub reads: usize,
    pub ready: bool,
    step: usize,
    pub ignore_write: Option<usize>,
    pub read_fault_after_write: Option<usize>,
    fault_armed: bool,
}
impl O2Chip {
    pub fn new(device: u16) -> Self {
        let mut c = Self {
            bytes: [0; 4096],
            slots: Vec::new(),
            writes: Vec::new(),
            reads: 0,
            ready: false,
            step: 0,
            ignore_write: None,
            read_fault_after_write: None,
            fault_armed: false,
        };
        c.bytes[..4].copy_from_slice(&(0x1217u32 | u32::from(device) << 16).to_le_bytes());
        c.bytes[0xd3] = 0xd5;
        c.bytes[0xec] = 0x81;
        c.bytes[0xe0] = 0x20;
        c.bytes[0xf1] = 0x50;
        c.bytes[0x304..0x308].copy_from_slice(&0x9910_551au32.to_le_bytes());
        c.bytes[0x354..0x358].copy_from_slice(&(1u32 << 16 | 10 << 20 | 0x43).to_le_bytes());
        c
    }
    pub fn reg32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.bytes[at..at + 4].try_into().unwrap())
    }
    fn read(&mut self, at: usize, width: usize) -> u32 {
        self.reads += 1;
        let mut bytes = [0; 4];
        bytes[..width].copy_from_slice(&self.bytes[at..at + width]);
        let value = u32::from_le_bytes(bytes);
        if self.fault_armed && self.read_fault_after_write == Some(at) {
            self.fault_armed = false;
            value ^ 1
        } else {
            value
        }
    }
    fn write(&mut self, at: usize, width: usize, value: u32) {
        self.writes.push((at, width, value));
        if self.ignore_write == Some(at) {
            return;
        }
        if at != 0xd3 {
            assert_eq!(self.bytes[0xd3] & 0x80, 0, "O2 PCI write while locked");
        }
        if !self.ready && at != 0xd3 {
            let sequence = [
                (0xee, 1, 0x08),
                (0xec, 1, 0xa1),
                (0xe0, 1, 0x21),
                (0xe0, 1, 0x73),
                (0xe2, 1, 0x39),
                (0xe7, 1, 0x08),
                (0xf1, 1, 0x58),
            ];
            assert_eq!(
                (at, width, value),
                sequence[self.step],
                "O2 initial hardware sequence"
            );
            self.step += 1;
        }
        if matches!(at, 0x304 | 0x354) && self.reg32(at) != value {
            for slot in &self.slots {
                if let Some(slot) = slot.upgrade() {
                    assert_eq!(
                        slot.borrow().word(CLOCK) & CLOCK_CARD,
                        0,
                        "O2 clock source changed under card clock"
                    );
                }
            }
        }
        self.bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
        if at == 0xd3 && value & 0x80 != 0 && self.step == 7 {
            self.ready = true;
        }
        if self.read_fault_after_write == Some(at) {
            self.fault_armed = true;
        }
    }
}
pub(super) struct O2ConfigPort(pub Rc<RefCell<O2Chip>>);
impl Registers for O2ConfigPort {
    fn read8(&mut self, at: usize) -> u8 {
        self.0.borrow_mut().read(at, 1) as u8
    }
    fn read16(&mut self, at: usize) -> u16 {
        self.0.borrow_mut().read(at, 2) as u16
    }
    fn read32(&mut self, at: usize) -> u32 {
        self.0.borrow_mut().read(at, 4)
    }
    fn write8(&mut self, at: usize, value: u8) {
        self.0.borrow_mut().write(at, 1, u32::from(value));
    }
    fn write16(&mut self, at: usize, value: u16) {
        self.0.borrow_mut().write(at, 2, u32::from(value));
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.0.borrow_mut().write(at, 4, value);
    }
}
impl Registers for Port {
    fn read8(&mut self, at: usize) -> u8 {
        let mut m = self.0.borrow_mut();
        m.reads += 1;
        if at == RESET {
            if m.reset_stuck { 7 } else { 0 }
        } else {
            m.byte(at)
        }
    }
    fn read16(&mut self, at: usize) -> u16 {
        let mut m = self.0.borrow_mut();
        m.reads += 1;
        if at == VERSION {
            m.version
        } else if at == 0x1cc && m.o2_chip.is_some() {
            m.word(at) & !(1 << 14) | if m.pll_locked { 1 << 14 } else { 0 }
        } else if at == CLOCK {
            m.word(at)
                | if m.clock_stuck || m.word(at) & CLOCK_INTERNAL == 0 {
                    0
                } else {
                    CLOCK_STABLE
                }
        } else {
            m.word(at)
        }
    }
    fn read32(&mut self, at: usize) -> u32 {
        let mut m = self.0.borrow_mut();
        m.reads += 1;
        match at {
            CAPABILITIES => m.caps,
            CAPABILITIES2 => m.caps2,
            MAX_CURRENT => m.max_current,
            INTERRUPT => m.status,
            PRESENT => {
                let cd = if m.o2_chip.is_some() && (m.present != m.o2_cd_mismatch) {
                    1 << 18
                } else {
                    0
                };
                if m.present {
                    let dat = if m.voltage_started {
                        if m.voltage_restart_at.is_some() {
                            match m.voltage_fault {
                                Some(VoltageFault::DatLowAfter) => 0,
                                Some(VoltageFault::OneDatLowAfter) => DATA_LINES & !(1 << 23),
                                _ => DATA_LINES,
                            }
                        } else {
                            match m.voltage_fault {
                                Some(VoltageFault::DatHighBefore) => DATA_LINES,
                                Some(VoltageFault::OneDatLowBefore) => DATA_LINES & !DATA0,
                                _ => 0,
                            }
                        }
                    } else {
                        DATA_LINES
                    };
                    cd | CARD_PRESENT
                        | CARD_STABLE
                        | dat
                        | if m.writable { WRITE_ALLOWED } else { 0 }
                        | if m.expected > 0 {
                            if m.transfer_read {
                                DATA_AVAILABLE
                            } else {
                                SPACE_AVAILABLE
                            }
                        } else {
                            0
                        }
                } else {
                    cd
                }
            }
            0x1cc if m.o2_chip.is_some() => {
                m.reg(at) & !(1 << 14) | if m.pll_locked { 1 << 14 } else { 0 }
            }
            BUFFER => {
                assert!(m.transfer_read);
                let mut bytes = [0; 4];
                for byte in &mut bytes {
                    if m.expected == 0 {
                        break;
                    }
                    *byte = m.fifo.pop_front().expect("read past card data");
                    m.expected -= 1;
                }
                m.data_progress();
                u32::from_le_bytes(bytes)
            }
            _ => m.reg(at),
        }
    }
    fn write8(&mut self, at: usize, value: u8) {
        let mut m = self.0.borrow_mut();
        m.writes.push((at, 1, u32::from(value)));
        if at == RESET {
            if m.fail_settings_reset && m.settings_dirty {
                m.reset_stuck = true;
            }
            if !m.reset_stuck {
                m.settings_dirty = false;
                m.expected = 0;
                m.fifo.clear();
                m.status &= CARD_INSERT | CARD_REMOVE;
                if value & RESET_ALL != 0 {
                    m.regs.clear();
                }
            }
        } else {
            if at == POWER
                && value == 0
                && let Some(chip) = &m.o2_chip
            {
                assert_eq!(
                    chip.borrow().reg32(0x354) & (1 << 16),
                    0,
                    "O2 power-off before OPE clock restore"
                );
            }
            if at == POWER && m.single_power_write {
                assert!(
                    value == 0 || value & POWER_ON != 0,
                    "ENE split voltage/power write"
                );
            }
            if at == HOST_CONTROL && m.reject_high_speed_bit {
                assert_eq!(value & HIGH_SPEED, 0, "Intel NO_HISPD_BIT was violated");
            }
            if at == HOST_CONTROL && (m.byte(at) ^ value) & (BUS4 | BUS8 | HIGH_SPEED) != 0 {
                m.settings_dirty = true;
            }
            if at == POWER && value & POWER_ON == 0 {
                if m.power_off_stuck && m.voltage_started {
                    return;
                }
                m.notified = false;
                m.selected = false;
                m.voltage_started = false;
                m.voltage_changed_at = None;
                m.voltage_restart_at = None;
                m.sd_function = 0;
                m.sd_current = 0;
            }
            m.write(at, 1, u32::from(value));
        }
    }
    fn write16(&mut self, at: usize, value: u16) {
        let mut m = self.0.borrow_mut();
        m.writes.push((at, 2, u32::from(value)));
        if at == CLOCK && m.voltage_started {
            if value & CLOCK_CARD == 0 && m.voltage_fault == Some(VoltageFault::StopClock) {
                return;
            }
            if value & CLOCK_CARD != 0
                && m.word(CLOCK) & CLOCK_CARD == 0
                && m.word(HOST_CONTROL2) & SIGNAL_180 != 0
                && m.voltage_restart_at.is_none()
            {
                let now = Clock {
                    ticks_per_microsecond: 1,
                }
                .now_us();
                assert!(
                    now - m
                        .voltage_changed_at
                        .expect("clock restart before signal switch")
                        >= 10_000 * CLOCK_TICKS_PER_US,
                    "card clock restarted before voltage settles"
                );
                m.voltage_restart_at = Some(now);
            }
        }
        if at == HOST_CONTROL2 {
            if value & SIGNAL_180 != 0 && m.word(at) & SIGNAL_180 == 0 {
                if m.kind == Kind::Sd {
                    assert!(
                        m.voltage_started,
                        "SD host voltage changed without actual CMD11"
                    );
                }
                assert_eq!(
                    m.word(CLOCK) & CLOCK_CARD,
                    0,
                    "voltage changed under active card clock"
                );
                if m.voltage_fault == Some(VoltageFault::Enable) {
                    return;
                }
                m.voltage_changed_at = Some(
                    Clock {
                        ticks_per_microsecond: 1,
                    }
                    .now_us(),
                );
            }
            if (value ^ m.word(at)) & UHS_MODE != 0 {
                assert_eq!(
                    m.word(CLOCK) & CLOCK_CARD,
                    0,
                    "UHS mode changed under active card clock"
                );
                if m.uhs_timing_stuck {
                    return;
                }
            }
            if value & EXECUTE_TUNING != 0 && m.word(at) & EXECUTE_TUNING == 0 {
                if m.tuning_start_stuck {
                    return;
                }
                m.tuning_round = 0;
            }
        }
        m.write(at, 2, u32::from(value));
        if at == CLOCK {
            m.settings_dirty = true;
        }
        if at == CLOCK && value & CLOCK_CARD != 0 {
            m.clock_started = Some(
                Clock {
                    ticks_per_microsecond: 1,
                }
                .now_us(),
            );
        }
        if at == COMMAND {
            m.issue(value);
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        let mut m = self.0.borrow_mut();
        m.writes.push((at, 4, value));
        if at == 0x1cc && m.o2_chip.is_some() {
            if value & (1 << 12) != 0 {
                m.pll_sequence = 1;
                m.pll_locked = false;
            } else if m.pll_sequence == 1 {
                m.pll_sequence = 2;
            }
            if value & (1 << 18) != 0 {
                assert_eq!(m.pll_sequence, 2, "O2 PLL forced without reset/release");
                m.pll_sequence = 3;
                if !m.o2_pll_stuck {
                    m.pll_locked = true;
                }
            }
            m.write(at, 4, value & !(1 << 14));
        } else if at == INTERRUPT {
            m.status &= !value;
        } else if at == BUFFER {
            assert!(!m.transfer_read);
            for byte in value.to_le_bytes() {
                if m.expected == 0 {
                    break;
                }
                m.outgoing.push(byte);
                m.expected -= 1;
            }
            if m.expected == 0 && m.storage_write {
                let begin = m.destination;
                let bytes = m.outgoing.clone();
                m.disk[begin..begin + bytes.len()].copy_from_slice(&bytes);
            }
            m.data_progress();
        } else {
            m.write(at, 4, value);
        }
    }
}
