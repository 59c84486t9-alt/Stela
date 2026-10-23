//! Independent SD host/card register model: actual-width writes, FIFO and ADMA
//! payload effects, card states, command/response completion and removal faults.
use super::*;
use alloc::collections::{BTreeMap, VecDeque};
pub(super) const CLOCK_TICKS_PER_US: u64 = 1000;

pub(super) struct Hardware {
    pub caps: u32,
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
        assert!(
            !self.reset_after_settings || !self.settings_dirty,
            "ENE command before post-settings reset"
        );
        assert!(
            !self.dma_broken || mode & DMA == 0,
            "ENE broken DMA was enabled"
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
            41 if app && self.kind == Kind::Sd => {
                self.response(1 << 31 | if self.high_capacity { 1 << 30 } else { 0 } | 3 << 20)
            }
            1 if self.kind == Kind::Mmc => {
                self.response(1 << 31 | if self.high_capacity { 1 << 30 } else { 0 } | 3 << 20)
            }
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
                self.response(if self.never_ready { 7 << 9 } else { self.r1() });
            }
            51 if app && self.kind == Kind::Sd => data = Some(self.scr.to_vec()),
            6 if app && self.kind == Kind::Sd => {
                assert_eq!(argument, 2);
            }
            6 if self.kind == Kind::Sd => {
                let mut bytes = vec![0; 64];
                bytes[13] = 2;
                bytes[16] = if argument >> 31 != 0 { 1 } else { 0 };
                data = Some(bytes);
            }
            6 if self.kind == Kind::Mmc => {
                assert_eq!(argument >> 24, 3);
                let index = ((argument >> 16) & 255) as usize;
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
        let wide = self.byte(HOST_CONTROL) & DMA_MASK == ADMA64;
        let table = u64::from(self.reg(ADMA_ADDRESS))
            | if wide {
                u64::from(self.reg(ADMA_ADDRESS_HIGH)) << 32
            } else {
                0
            };
        assert!(table > 65536 && table.is_multiple_of(4));
        // SAFETY: fixture hardware consumes only the driver's retained descriptor DMA.
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
            // SAFETY: descriptor grants this exact live device-write range.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, length);
            }
        } else {
            // SAFETY: descriptor grants this exact live device-read range.
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
        } else if at == CLOCK {
            m.word(at) | if m.clock_stuck { 0 } else { CLOCK_STABLE }
        } else {
            m.word(at)
        }
    }
    fn read32(&mut self, at: usize) -> u32 {
        let mut m = self.0.borrow_mut();
        m.reads += 1;
        match at {
            CAPABILITIES => m.caps,
            CAPABILITIES2 => 0,
            INTERRUPT => m.status,
            PRESENT => {
                if m.present {
                    CARD_PRESENT
                        | CARD_STABLE
                        | DATA0
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
                    0
                }
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
            if at == POWER && m.single_power_write {
                assert!(
                    value == 0 || value & POWER_ON != 0,
                    "ENE split voltage/power write"
                );
            }
            if at == HOST_CONTROL && (m.byte(at) ^ value) & (BUS4 | BUS8 | HIGH_SPEED) != 0 {
                m.settings_dirty = true;
            }
            if at == POWER && value & POWER_ON == 0 {
                m.notified = false;
                m.selected = false;
            }
            m.write(at, 1, u32::from(value));
        }
    }
    fn write16(&mut self, at: usize, value: u16) {
        let mut m = self.0.borrow_mut();
        m.writes.push((at, 2, u32::from(value)));
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
        if at == INTERRUPT {
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
