extern crate std;
mod rts5229;

use super::*;
use crate::bus::pci::Address;
use alloc::{collections::BTreeMap, vec, vec::Vec};

// A peripheral/card model at the PCI/MMIO boundary. Numeric wire
// fields below are decoded independently of the driver helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    MissingEnd,
    MissingIdle,
    Crc7,
    Crc16,
    CrcTimeout,
    ResponseTimeout,
    Remove,
    Delink,
    MemoryStick,
    Overcurrent,
    Busy,
    AfterWrite,
}
#[derive(Clone, Debug)]
enum Effect {
    Config(u16, usize, u32),
    Register(u16, u8, u8),
    Command(u8, u32, u8),
    DataWrite(u32),
    Stop,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DelayPoint {
    HaimrPublication,
    StartAck,
    Completion,
    Status,
    Status1,
    BiprFailure,
    LastPpbuf,
    LastResponse,
    StopComplete,
    ConstructorStop,
}
struct CardModel {
    mmc: bool,
    state: u8,
    app: bool,
    width: u8,
    high_speed: bool,
    asleep: bool,
    pending_write: Option<u32>,
    ext: [u8; 512],
    blocks: BTreeMap<u32, [u8; 512]>,
    nonready: bool,
    transfer_speed: u8,
    status_error: u32,
    uhs_modes: u8,
    low_voltage: bool,
    bus_function: u8,
    current_function: u8,
    reject_switch: bool,
}
impl CardModel {
    fn new(mmc: bool) -> Self {
        let mut ext = [0; 512];
        ext[192] = 8;
        ext[196] = 2;
        ext[212..216].copy_from_slice(&8192u32.to_le_bytes());
        ext[33] = 1;
        ext[249..253].copy_from_slice(&4u32.to_le_bytes());
        ext[202] = 0xa4;
        Self {
            mmc,
            state: 0,
            app: false,
            width: 1,
            high_speed: false,
            asleep: false,
            pending_write: None,
            ext,
            blocks: BTreeMap::new(),
            nonready: false,
            transfer_speed: 0x32,
            status_error: 0,
            uhs_modes: 0,
            low_voltage: false,
            bus_function: 0,
            current_function: 0,
            reject_switch: false,
        }
    }
    fn block(&self, lba: u32) -> [u8; 512] {
        self.blocks.get(&lba).copied().unwrap_or_else(|| {
            core::array::from_fn(|i| (lba.wrapping_mul(19) as u8).wrapping_add((i * 7) as u8))
        })
    }
    fn csd(&self) -> [u8; 16] {
        let mut csd = if self.mmc {
            (3u128 << 126) | (4 << 122) | (1023 << 62)
        } else {
            (1 << 126) | (7 << 48)
        };
        csd |= (9 << 80) | (0x414 << 84) | (u128::from(self.transfer_speed) << 96) | 1;
        csd.to_be_bytes()
    }
    fn command(&mut self, opcode: u8, arg: u32, data: usize) -> (u32, Option<[u8; 16]>, Vec<u8>) {
        assert!(
            !self.asleep,
            "a notified MMC accepts no more commands until power cycle"
        );
        let app = core::mem::replace(&mut self.app, false);
        let mut bytes = Vec::new();
        let mut long = None;
        let illegal = 1 << 22;
        let status = match opcode {
            0 => {
                self.state = 0;
                self.width = 1;
                self.high_speed = false;
                self.low_voltage = false;
                self.bus_function = 0;
                0
            }
            8 if data == 0 => {
                if self.mmc {
                    illegal
                } else {
                    assert_eq!(arg, 0x1aa);
                    0x1aa
                }
            }
            55 => {
                if self.mmc {
                    illegal
                } else {
                    self.app = true;
                    (1 << 5) | 0x900
                }
            }
            41 if app && !self.mmc => {
                assert_ne!(arg & 0x0030_0000, 0);
                self.state = 1;
                0xc030_0000
                    | if self.uhs_modes != 0 && arg & (1 << 24) != 0 {
                        1 << 24
                    } else {
                        0
                    }
            }
            11 if !self.mmc => {
                assert_eq!(self.state, 1);
                assert_ne!(self.uhs_modes, 0);
                self.low_voltage = true;
                0
            }
            1 if self.mmc => {
                assert_ne!(arg & 0x0030_0000, 0);
                self.state = 1;
                0xc030_0000
            }
            2 => {
                assert_eq!(self.state, 1);
                self.state = 2;
                long = Some(*b"'\x12\x34NATIV\x11\x22\x33\x44\x55\x66\x77\x01");
                0
            }
            3 => {
                assert_eq!(self.state, 2);
                self.state = 3;
                if self.mmc {
                    assert_eq!(arg, 0x10000);
                    0x900
                } else {
                    0x10000
                }
            }
            9 => {
                assert_eq!(self.state, 3);
                assert_eq!(arg, 0x10000);
                long = Some(self.csd());
                0
            }
            7 => {
                assert_eq!(arg, 0x10000);
                self.state = 4;
                0x900
            }
            13 => {
                assert_eq!(self.state, 4);
                assert_eq!(arg, 0x10000);
                if self.status_error != 0 {
                    self.status_error
                } else if self.nonready {
                    0xe00
                } else {
                    0x900
                }
            }
            51 if app && !self.mmc => {
                assert_eq!(data, 8);
                bytes = vec![
                    2,
                    5,
                    if self.uhs_modes != 0 { 0x80 } else { 0 },
                    0,
                    0,
                    0,
                    0,
                    0,
                ];
                0x900
            }
            6 if app && !self.mmc => {
                assert_eq!(arg, 2);
                self.width = 4;
                0x900
            }
            6 if !self.mmc => {
                assert_eq!(data, 64);
                bytes = vec![0; 64];
                bytes[13] = if self.uhs_modes != 0 {
                    self.uhs_modes
                } else {
                    2
                };
                bytes[7] = 15; // all four current limits
                if arg & (1 << 31) != 0 {
                    let current = ((arg >> 12) & 15) as u8;
                    let speed = (arg & 15) as u8;
                    if current != 15 {
                        self.current_function = current;
                    }
                    if speed != 15 {
                        if self.low_voltage {
                            assert_ne!(self.uhs_modes & (1 << speed), 0);
                            self.bus_function = speed;
                        } else {
                            assert_eq!(speed, 1);
                            self.high_speed = true;
                        }
                    }
                    bytes[15] = self.current_function << 4;
                    bytes[16] = if self.reject_switch {
                        15
                    } else if self.low_voltage {
                        self.bus_function
                    } else {
                        1
                    };
                }
                0x900
            }
            19 if !self.mmc => {
                assert_eq!(self.state, 4);
                assert!(self.low_voltage);
                assert_eq!(data, 64);
                0x900
            }
            6 if self.mmc => {
                assert_eq!(arg >> 24, 3);
                let index = (arg >> 16 & 255) as usize;
                let value = (arg >> 8) as u8;
                self.ext[index] = value;
                if index == 183 {
                    assert_eq!(value, 1);
                    self.width = 4;
                }
                if index == 185 {
                    assert_eq!(value, 1);
                    self.high_speed = true;
                }
                if index == 34 && value == 3 {
                    self.asleep = true;
                }
                0x900
            }
            8 if self.mmc => {
                assert_eq!(data, 512);
                bytes = self.ext.to_vec();
                0x900
            }
            17 => {
                assert_eq!(self.state, 4);
                assert_eq!(data, 512);
                assert!(arg < 8192);
                bytes = self.block(arg).to_vec();
                0x900
            }
            24 => {
                assert_eq!(self.state, 4);
                assert_eq!(data, 0);
                assert!(arg < 8192);
                self.pending_write = Some(arg);
                0x900
            }
            _ => illegal,
        };
        (status, long, bytes)
    }
}
struct Transfer {
    mode: u8,
    opcode: u8,
    argument: u32,
    response: u8,
    bytes: usize,
    fault: Fault,
    polls: usize,
    effected: bool,
}
struct Chip {
    config: Vec<u8>,
    regs: Vec<u8>,
    phy: [u16; 256],
    bipr: u32,
    haimr: Option<u32>,
    haimr_busy: bool,
    haimr_effected: bool,
    haimr_result: u32,
    transfer: Option<Transfer>,
    card: CardModel,
    effects: Vec<Effect>,
    accesses: usize,
    next_fault: Fault,
    transfer_polls: usize,
    stuck_haimr: Option<u16>,
    wrong_echo: Option<u16>,
    stuck_phy: bool,
    stuck_stop: bool,
    deny_pci: Option<u16>,
    timeline: bool,
    partial_at: Option<u64>,
    toggled_at: Option<u64>,
    delay_on: Option<DelayPoint>,
    delay_us: u64,
    delayed: Vec<DelayPoint>,
    stop_observed: bool,
    wrong_restore: bool,
    dma_stops: Vec<usize>,
    last_mode: u8,
    last_opcode: u8,
    ocp_clear_at: Option<u64>,
    voltage_set_at: Option<u64>,
    bad_cmd11_low: bool,
    bad_cmd11_high: bool,
    deny_v18_phy: bool,
    tuning_windows: [u32; 3],
    tuning_attempts: usize,
    tuning_fault: Option<Fault>,
    tuning_rejection: Fault,
    tuning_late_timeout: bool,
}
impl Chip {
    fn new(mmc: bool, present: bool) -> Rc<RefCell<Self>> {
        let mut config = vec![0; 4096];
        config[..4].copy_from_slice(&0x5227_10ecu32.to_le_bytes());
        config[4..6].copy_from_slice(&7u16.to_le_bytes());
        config[6] = 0x10;
        config[8..12].copy_from_slice(&0xff00_0000u32.to_le_bytes());
        config[0x34] = 0x40;
        config[0x40] = 0x10;
        config[0x41] = 0x80;
        config[0x42] = 2;
        config[0x68..0x6a].copy_from_slice(&0x400u16.to_le_bytes());
        config[0x80] = 1;
        config[0x81] = 0x90;
        config[0x90] = 5;
        config[0x91] = 0xa0;
        config[0x92] = 1;
        config[0xa0] = 0x11;
        config[0xa3] = 0x80;
        config[0x100..0x104].copy_from_slice(&0x1402_0001u32.to_le_bytes());
        config[0x140..0x144].copy_from_slice(&0x1501_0003u32.to_le_bytes());
        config[0x150..0x154].copy_from_slice(&0x1601_0004u32.to_le_bytes());
        config[0x160..0x164].copy_from_slice(&0x1801_0018u32.to_le_bytes());
        config[0x180..0x184].copy_from_slice(&0x0001_001eu32.to_le_bytes());
        config[0x188] = 0xf;
        // Invalid board vendor settings select the source's physical defaults.
        config[0x727] = 1;
        let mut regs = vec![0; 0x4000];
        regs[0x3da5] = 2; // DAT0 released.
        Rc::new(RefCell::new(Self {
            config,
            regs,
            phy: [0; 256],
            bipr: if present { 1 << 16 } else { 0 },
            haimr: None,
            haimr_busy: false,
            haimr_effected: false,
            haimr_result: 0,
            transfer: None,
            card: CardModel::new(mmc),
            effects: Vec::new(),
            accesses: 0,
            next_fault: Fault::None,
            transfer_polls: 1,
            stuck_haimr: None,
            wrong_echo: None,
            stuck_phy: false,
            stuck_stop: false,
            deny_pci: None,
            timeline: false,
            partial_at: None,
            toggled_at: None,
            delay_on: None,
            delay_us: 0,
            delayed: Vec::new(),
            stop_observed: false,
            wrong_restore: false,
            dma_stops: Vec::new(),
            last_mode: 0,
            last_opcode: 0,
            ocp_clear_at: None,
            voltage_set_at: None,
            bad_cmd11_low: false,
            bad_cmd11_high: false,
            deny_v18_phy: false,
            tuning_windows: [u32::MAX; 3],
            tuning_attempts: 0,
            tuning_fault: None,
            tuning_rejection: Fault::Crc16,
            tuning_late_timeout: false,
        }))
    }
    fn delay_at(&mut self, point: DelayPoint) {
        if self.delay_on == Some(point) {
            self.delay_on = None;
            Clock {
                ticks_per_microsecond: 100,
            }
            .delay(self.delay_us);
            self.delayed.push(point);
        }
    }
    /// The counter the host's clock reads, virtual under `test_clock`.
    fn ticks() -> u64 {
        crate::test_clock::read().unwrap_or_else(|| {
            // SAFETY: RDTSC has no memory effects; x86-64 always has it.
            unsafe { core::arch::x86_64::_rdtsc() }
        })
    }
    fn low_voltage_phy(&self) -> u16 {
        if self.config[2..4] == [0x29, 0x52] {
            0x4c64
        } else {
            0x54a4
        }
    }
    fn complete(&mut self) {
        let Some(mut transfer) = self.transfer.take() else {
            return;
        };
        transfer.polls += 1;
        if transfer.polls < self.transfer_polls {
            self.transfer = Some(transfer);
            return;
        }
        if !transfer.effected {
            assert_eq!(self.regs[0x3d50] & 3, 0, "card must have full power");
            assert_eq!(self.regs[0x3e75] & 6, 6, "physical 3.3V gate");
            let rts522a = self.config[2..4] == [0x2a, 0x52];
            assert_eq!(
                self.phy[8],
                if self.card.low_voltage && transfer.opcode != 11 {
                    self.low_voltage_phy()
                } else if rts522a {
                    0x57e4
                } else {
                    0x4fe4
                },
                "qualified 3.3V PHY"
            );
            if rts522a {
                assert_eq!(self.regs[0x3c00] & 2, 0, "OCP analog powered");
                assert_eq!(self.regs[0x3d6a] & 12, 12, "OCP detector enabled");
                assert_eq!(self.regs[0x3d6b] & 7, 5, "800 OCP time");
                assert_eq!(self.regs[0x3d6d] & 7, 6, "800mA threshold");
                assert_eq!(self.regs[0x3d6c] & 15, 15, "10ms glitch");
                assert_eq!(self.regs[0x3e57] & 0x30, 0x30, "register ASPM off");
            }
            assert_eq!(self.regs[0x3d69] & 4, 4, "card clock on");
            assert_eq!(self.regs[0x3d55] & 4, 4, "SD outputs on");
            assert_eq!(self.regs[0x3d61], 0xaa);
            let revision_c = self.config[2..4] == [0x29, 0x52] && self.regs[0x3e90] & 15 == 2;
            assert_eq!(self.regs[0x3d62], if revision_c { 0xd9 } else { 0xe9 });
            assert_eq!(self.regs[0x3d5c] & 7, 2);
            assert_eq!(self.regs[0x3d52] & 15, 4);
            if transfer.mode != 15 {
                assert_eq!(self.regs[0x3d5b] & 1, 1, "PPBUF physically selected");
            }
            if self.timeline && transfer.mode == 8 && transfer.opcode == 0 {
                assert!(Self::ticks() - self.toggled_at.expect("initial clocks") >= 1000 * 1000);
            }
            let bus = self.regs[0x3da0] & 3;
            let width = match bus {
                0 => 1,
                1 => 4,
                2 => 8,
                _ => 0,
            };
            let n = u32::from(self.regs[0x3c0f]) + 2;
            let divider = self.regs[0x3c03] >> 4;
            assert!((1..=4).contains(&divider));
            let internal_hz = (n * 1_000_000) >> (divider - 1);
            let sdr_fast = self.regs[0x3da0] & 12 == 8;
            let card_hz = if self.regs[0x3da0] & 0xc0 == 0x80 {
                internal_hz / 128
            } else if sdr_fast {
                internal_hz
            } else {
                internal_hz / 2
            };
            assert_eq!(
                self.regs[0x3c2e],
                if sdr_fast { 0x21 } else { 0x24 },
                "actual timing clock routing"
            );
            assert_eq!(self.regs[0x3c02] & 1, 0, "SSC ungated after settling");
            if transfer.mode == 8 && transfer.opcode == 0 {
                assert!(card_hz <= 400_000);
            } else if self.card.low_voltage && transfer.opcode != 11 {
                let max = match self.card.bus_function {
                    0 => 25_000_000,
                    1 => 50_000_000,
                    2 => 100_000_000,
                    3 => 208_000_000,
                    _ => panic!("undeclared UHS function"),
                };
                assert!(card_hz <= max);
                if sdr_fast {
                    assert!(matches!(self.card.bus_function, 2 | 3));
                }
            } else if self.card.high_speed {
                assert!(
                    card_hz
                        <= if self.card.mmc {
                            52_000_000
                        } else {
                            50_000_000
                        }
                );
            } else {
                assert!(
                    card_hz
                        <= if self.card.transfer_speed == 0x0a {
                            10_000_000
                        } else {
                            25_000_000
                        }
                );
            }
            if card_hz > 25_000_000 && !self.card.low_voltage {
                assert!(
                    self.card.high_speed,
                    "physical fast clock requires card high-speed negotiation"
                );
                assert_eq!(self.regs[0x3da8] & 0x10, 0x10, "SD20 fast transmit phase");
                assert_eq!(self.regs[0x3da7] & 8, 8, "SD20 fast sample phase");
            }
            let data = if transfer.mode == 12 || transfer.mode == 15 {
                transfer.bytes
            } else {
                0
            };
            if data != 0 {
                assert_eq!(
                    self.regs[0x3da0] & 0xc0,
                    0,
                    "normal PIO read bypasses initial divider"
                );
            }
            if (data != 0 || transfer.mode == 1) && self.card.width != width {
                self.regs[0x3da3] = 0x40;
                self.regs[0x3db3] = 0x50;
                return;
            }
            if transfer.mode == 1 {
                let lba = self
                    .card
                    .pending_write
                    .take()
                    .expect("AUTO_WRITE3 requires prior CMD24");
                assert_eq!(transfer.bytes, 512);
                assert_eq!(transfer.response, 0);
                let bytes = self.regs[0x3a00..0x3c00].try_into().unwrap();
                self.card.blocks.insert(lba, bytes);
                self.effects.push(Effect::DataWrite(lba));
            } else {
                self.effects.push(Effect::Command(
                    transfer.opcode,
                    transfer.argument,
                    transfer.mode,
                ));
                let (status, long, bytes) =
                    self.card.command(transfer.opcode, transfer.argument, data);
                if transfer.opcode == 11 {
                    self.regs[0x3da5] = if self.bad_cmd11_low { 0x1e } else { 0 };
                }
                if transfer.opcode == 19 {
                    assert_eq!(
                        self.regs[0x3c2a] & 31,
                        if self.config[2..4] == [0x29, 0x52] {
                            27
                        } else {
                            20
                        }
                    );
                    assert_eq!(
                        transfer.mode, 15,
                        "actual hardware auto tuning, not PPBUF emulation"
                    );
                    let phase = self.regs[0x3c2b] & 31;
                    let window = self.tuning_windows[(self.tuning_attempts / 32).min(2)];
                    self.tuning_attempts += 1;
                    if window & (1 << phase) == 0 {
                        transfer.fault = self.tuning_rejection;
                    }
                    if let Some(fault) = self.tuning_fault.take() {
                        transfer.fault = fault;
                    }
                    if self.tuning_late_timeout {
                        self.tuning_late_timeout = false;
                        transfer.fault = Fault::ResponseTimeout;
                        self.delay_on = Some(DelayPoint::Status);
                        self.delay_us = 2_000_000;
                    }
                }
                if transfer.mode == 8 {
                    self.regs[0x3da9] = 0;
                    self.regs[0x3daa..0x3dae].copy_from_slice(&status.to_be_bytes());
                }
                if let Some(long) = long {
                    assert_eq!(transfer.response & 3, 2);
                    self.regs[0x3a00] = 0x3f;
                    self.regs[0x3a01..0x3a10].copy_from_slice(&long[..15]);
                }
                if !bytes.is_empty() {
                    assert_eq!(bytes.len(), transfer.bytes);
                    self.regs[0x3a00..0x3a00 + bytes.len()].copy_from_slice(&bytes);
                }
            }
            transfer.effected = true;
        }
        self.regs[0x3db3] = match transfer.fault {
            Fault::MissingEnd | Fault::AfterWrite => 0x80,
            Fault::MissingIdle => 0x40,
            _ => 0x60,
        };
        match transfer.fault {
            Fault::Crc7 => self.regs[0x3da3] |= 0x80,
            Fault::Crc16 => self.regs[0x3da3] |= 0x40,
            Fault::CrcTimeout => self.regs[0x3da3] |= 2,
            Fault::ResponseTimeout => self.regs[0x3da4] |= 1,
            Fault::Remove => self.bipr = (self.bipr & !(1 << 16)) | (1 << 25),
            Fault::Delink => self.bipr |= 1 << 24,
            Fault::MemoryStick => self.bipr |= 1 << 17,
            Fault::Overcurrent => {
                self.bipr |= 1 << 22;
                self.regs[0x3d6e] |= 6;
            }
            Fault::Busy => self.regs[0x3da5] &= !2,
            _ => {}
        }
        if matches!(
            transfer.fault,
            Fault::MissingEnd | Fault::MissingIdle | Fault::AfterWrite
        ) {
            self.transfer = Some(transfer);
        }
    }
    fn internal_read(&mut self, at: u16) -> u8 {
        let at = usize::from(at & 0x3fff);
        if at == 0x3da5
            && self.card.low_voltage
            && self.phy[8] == self.low_voltage_phy()
            && self.regs[0x3d69] & 4 != 0
        {
            self.regs[at] = (self.regs[at] & !0x1e) | if self.bad_cmd11_high { 0 } else { 0x1e };
        }
        if at == 0x3db3 {
            self.complete();
            if self.stop_observed {
                self.delay_at(DelayPoint::StopComplete);
            } else if !(self.last_mode == 8 && self.last_opcode == 24) {
                self.delay_at(DelayPoint::Completion);
            }
        }
        if at == 0x3da4 {
            self.delay_at(DelayPoint::Status);
        }
        if at == 0x3da3 {
            self.delay_at(DelayPoint::Status1);
        }
        if at == 0x3bff {
            self.delay_at(DelayPoint::LastPpbuf);
        }
        if at == 0x3dad {
            self.delay_at(DelayPoint::LastResponse);
        }
        if (0x3a00..0x3c00).contains(&at) {
            assert_eq!(
                self.regs[0x3db3] & 0x40,
                0x40,
                "CPU cannot read PPBUF before card completion"
            );
        }
        self.regs[at]
    }
    fn internal_write(&mut self, at: u16, mask: u8, value: u8) {
        let address = at | 0xc000;
        let at = usize::from(at);
        self.effects.push(Effect::Register(address, mask, value));
        self.regs[at] = (self.regs[at] & !mask) | (value & mask);
        if at == 0x3e3c && value & 0x80 != 0 && !self.stuck_phy {
            let index = usize::from(self.regs[0x3e3f]);
            if value & 1 == 0 {
                let bytes = self.phy[index].to_le_bytes();
                self.regs[0x3e3d..0x3e3f].copy_from_slice(&bytes);
            } else {
                self.phy[index] = u16::from_le_bytes([self.regs[0x3e3d], self.regs[0x3e3e]]);
                if index == 8
                    && self.phy[index] == self.low_voltage_phy()
                    && self.bipr & SD_EXIST != 0
                {
                    if self.deny_v18_phy {
                        return;
                    }
                    assert!(self.card.low_voltage, "CMD11 before1.8V PHY");
                    assert_eq!(
                        self.regs[0x3d69] & 4,
                        0,
                        "clock gated during voltage change"
                    );
                    self.voltage_set_at = Some(Self::ticks());
                }
            }
            self.regs[at] &= !0x80;
        }
        if at == 0x3d6a && mask & 3 == 3 {
            if value & 3 == 3 {
                assert_eq!(
                    self.regs[0x3d50] & 3,
                    3,
                    "socket off before OCP latch clear"
                );
                assert_eq!(self.regs[0x3e75] & 6, 0, "power gate off before OCP clear");
                self.ocp_clear_at = Some(Self::ticks());
                self.regs[0x3d6e] &= !6;
                self.bipr &= !(1 << 22);
            } else if value & 3 == 0 && self.ocp_clear_at.is_some() {
                assert!(
                    Self::ticks() - self.ocp_clear_at.take().expect("OCP clear pulse start")
                        >= 100 * 1000
                );
            }
        }
        if at == 0x3d69 && value & 4 != 0 && self.card.low_voltage {
            assert!(Self::ticks() - self.voltage_set_at.expect("PHY first") >= 10_000 * 1000);
        }
        if at == 0x3d50 {
            if value & 3 == 1 {
                if self.config[2..4] == [0x2a, 0x52] {
                    assert_eq!(self.regs[0x3d6a] & 12, 12, "OCP before partial power");
                    assert_eq!(self.regs[0x3c00] & 2, 0);
                }
                self.partial_at = Some(Self::ticks());
            }
            if value & 3 == 0 && self.timeline {
                assert!(
                    Self::ticks() - self.partial_at.expect("partial power first")
                        >= if self.config[2..4] == [0x29, 0x52] {
                            150
                        } else {
                            20_000
                        } * 1000
                );
            }
            if value & 3 == 3 {
                self.card.asleep = false;
                self.card.state = 0;
                self.card.pending_write = None;
                self.card.low_voltage = false;
                self.card.ext[34] = 0;
                self.regs[0x3da5] |= 2;
            }
        }
        if at == 0x3da5 && mask & 0x80 != 0 && value & 0x80 != 0 {
            self.toggled_at = Some(Self::ticks());
        }
        if at == 0x3d54 && value & 0x44 == 0x44 {
            self.effects.push(Effect::Stop);
            self.stop_observed = true;
            if !self.stuck_stop {
                self.transfer = None;
                self.regs[0x3db3] = 0;
                self.regs[0x3da3] = 0;
                self.regs[0x3da4] = 0;
                self.regs[0x3db6] = 0x80;
            }
        }
        if at == 0x3db3 && value & 0x80 != 0 {
            assert!(
                self.transfer.is_none(),
                "previous card transfer must retire"
            );
            assert_eq!(
                self.bipr & 0x7000_0000,
                0,
                "prior sticky completion must be acknowledged"
            );
            self.regs[0x3da3] = 0;
            self.regs[0x3da4] = 0;
            let argument = u32::from_be_bytes(self.regs[0x3daa..0x3dae].try_into().unwrap());
            let bytes = usize::from(u16::from_le_bytes([self.regs[0x3daf], self.regs[0x3db0]]));
            if value & 15 != 8 {
                assert_eq!(
                    u16::from_le_bytes([self.regs[0x3db1], self.regs[0x3db2]]),
                    1
                );
                assert!((1..=512).contains(&bytes));
            }
            self.stop_observed = false;
            self.last_mode = value & 15;
            self.last_opcode = self.regs[0x3da9] & 63;
            self.transfer = Some(Transfer {
                mode: value & 15,
                opcode: self.regs[0x3da9] & 63,
                argument,
                response: self.regs[0x3da1],
                bytes,
                fault: if (self.next_fault == Fault::AfterWrite && value & 15 != 1)
                    || (self.next_fault == Fault::Busy && self.regs[0x3da1] & 8 == 0)
                {
                    Fault::None
                } else {
                    core::mem::replace(&mut self.next_fault, Fault::None)
                },
                polls: 0,
                effected: false,
            });
            assert_eq!(
                self.regs[0x3db3] & 0x40,
                0,
                "HAIMR ACK cannot complete the card command"
            );
        }
    }
}
#[derive(Clone)]
struct Config(Rc<RefCell<Chip>>);
impl ConfigSpace for Config {
    fn read8(&self, at: u16) -> u8 {
        let mut c = self.0.borrow_mut();
        c.accesses += 1;
        c.config[usize::from(at)]
    }
    fn read16(&self, at: u16) -> u16 {
        let mut c = self.0.borrow_mut();
        c.accesses += 1;
        let at = usize::from(at);
        u16::from_le_bytes(c.config[at..at + 2].try_into().unwrap())
    }
    fn read32(&self, at: u16) -> u32 {
        let mut c = self.0.borrow_mut();
        c.accesses += 1;
        let at = usize::from(at);
        u32::from_le_bytes(c.config[at..at + 4].try_into().unwrap())
    }
    fn write8(&mut self, at: u16, value: u8) {
        let mut c = self.0.borrow_mut();
        c.accesses += 1;
        c.effects.push(Effect::Config(at, 1, u32::from(value)));
        if c.deny_pci != Some(at) {
            c.config[usize::from(at)] = value;
        }
    }
    fn write16(&mut self, at: u16, value: u16) {
        let mut c = self.0.borrow_mut();
        c.accesses += 1;
        c.effects.push(Effect::Config(at, 2, u32::from(value)));
        if c.deny_pci != Some(at) {
            c.config[usize::from(at)..usize::from(at) + 2].copy_from_slice(&value.to_le_bytes());
        }
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("no broad PCI stores across W1C status or source vendor setup");
    }
}
struct Mmio(Rc<RefCell<Chip>>);
impl Registers for Mmio {
    fn read32(&mut self, at: usize) -> u32 {
        let mut c = self.0.borrow_mut();
        c.accesses += 1;
        assert_eq!(
            c.config[4] & 6,
            2,
            "validated memory decode with DMA disabled"
        );
        match at {
            0x18 | 4 | 12 => 0,
            0x14 => {
                if c.delay_on == Some(DelayPoint::BiprFailure)
                    && c.last_mode == 12
                    && c.regs[0x3db3] & 0x40 != 0
                {
                    c.bipr |= 1 << 28;
                    c.delay_at(DelayPoint::BiprFailure);
                }
                c.bipr
            }
            0x10 => {
                if let Some(command) = c.haimr {
                    let address = ((command >> 16) & 0x3fff) as u16;
                    if c.haimr_busy {
                        c.haimr_busy = false;
                        return command;
                    }
                    let write = command & (1 << 30) != 0;
                    let value = command as u8;
                    if write && !c.haimr_effected {
                        c.haimr_effected = true;
                        c.internal_write(address, (command >> 8) as u8, value);
                        if address == 0x3db3 && value & 0x80 != 0 {
                            c.delay_at(DelayPoint::StartAck);
                        }
                    }
                    if c.stuck_haimr == Some(address | 0xc000) {
                        return command;
                    }
                    c.haimr_result = if write {
                        if c.wrong_echo == Some(address | 0xc000)
                            || (c.wrong_restore
                                && address == 0x3da0
                                && value & 0xc0 == 0x80
                                && command >> 8 & 0xc0 == 0xc0)
                        {
                            u32::from(value ^ 1)
                        } else {
                            u32::from(value)
                        }
                    } else {
                        u32::from(c.internal_read(address))
                    };
                    c.haimr = None;
                }
                c.haimr_result
            }
            _ => panic!("unknown actual MMIO read {at:x}"),
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        let mut c = self.0.borrow_mut();
        c.accesses += 1;
        assert_eq!(c.config[4] & 6, 2);
        match at {
            0x18 => assert_eq!(value, 0, "polled owner disables all interrupt generation"),
            4 | 12 => {
                assert_eq!(
                    value,
                    1 << 28,
                    "HCB/HDB must only stop, never start unowned DMA"
                );
                c.dma_stops.push(at);
                if at == 4 {
                    c.delay_at(DelayPoint::ConstructorStop);
                }
            }
            0x14 => {
                assert_eq!(
                    value & 0x000f_0000,
                    0,
                    "presence/WP not a writable interrupt grant"
                );
                c.bipr &= !(value & 0xffff_0000);
            }
            0x10 => {
                assert!(c.haimr.is_none(), "serialize HAIMR access");
                assert_ne!(value & (1 << 31), 0);
                c.haimr = Some(value);
                c.haimr_busy = true;
                c.haimr_effected = false;
                if (value >> 16 & 0x3fff) == 0x3db3 && value & (1 << 30) != 0 && value & 0x80 != 0 {
                    c.delay_at(DelayPoint::HaimrPublication);
                }
            }
            _ => panic!("unexpected MMIO write or fabricated DMA address {at:x}"),
        }
    }
}
fn function(chip: &Rc<RefCell<Chip>>) -> Function<Config> {
    Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        Config(chip.clone()),
    )
    .unwrap()
}
fn make_host(chip: &Rc<RefCell<Chip>>, timeline: bool) -> Result<Host, BlockError> {
    let mut function = function(chip);
    let admission = controller::admission(&mut function)?;
    super::super::pci::quiesce_pio(&mut function)?;
    let clock = Clock {
        ticks_per_microsecond: 1000,
    };
    function.power_up(&clock)?;
    let config = controller::Configuration::capture(&mut function, admission)?;
    super::super::pci::set_pio_command(&mut function, true)?;
    chip.borrow_mut().timeline = timeline;
    let engine = Engine::new(
        Box::new(function),
        Box::new(Mmio(chip.clone())),
        config,
        clock,
        "native RTS5227 model".into(),
    )?;
    Ok(Host {
        inner: Rc::new(RefCell::new(engine)),
    })
}
#[test]
fn invalid_operation_clock_refuses_before_original_controller_access() {
    for ticks_per_microsecond in [0, u64::MAX, u64::MAX / (2 * 5_000_000) + 1] {
        let chip = Chip::new(false, true);
        let mut function = function(&chip);
        let admission = controller::admission(&mut function).unwrap();
        super::super::pci::quiesce_pio(&mut function).unwrap();
        let config = controller::Configuration::capture(&mut function, admission).unwrap();
        super::super::pci::set_pio_command(&mut function, true).unwrap();
        let before = (
            chip.borrow().config.clone(),
            chip.borrow().effects.len(),
            chip.borrow().accesses,
        );
        assert!(
            Engine::new(
                Box::new(function),
                Box::new(Mmio(chip.clone())),
                config,
                Clock {
                    ticks_per_microsecond
                },
                "unadmitted RTSX clock".into()
            )
            .is_err()
        );
        assert_eq!(chip.borrow().config, before.0);
        assert_eq!(chip.borrow().effects.len(), before.1);
        assert_eq!(chip.borrow().accesses, before.2);
    }
}
fn inject(host: &Host, chip: &Rc<RefCell<Chip>>, fault: Fault) {
    // Fault waits run at 100 ticks per microsecond, so their deadlines
    // expire in fewer counter reads than setup's.
    host.inner.borrow_mut().clock = Clock {
        ticks_per_microsecond: 100,
    };
    chip.borrow_mut().next_fault = fault;
}
fn stale(card: &mut Card, chip: &Rc<RefCell<Chip>>) {
    let before = chip.borrow().accesses;
    let mut poison = [0xa5; 512];
    assert_eq!(
        card.read(0, &mut poison),
        Err(BlockError::Unsupported(STALE))
    );
    assert_eq!(poison, [0xa5; 512]);
    assert_eq!(
        card.write(0, &[0x62; 512]),
        Err(BlockError::Unsupported(STALE))
    );
    assert_eq!(card.flush_cache(), Err(BlockError::Unsupported(STALE)));
    assert_eq!(card.shutdown(true), Err(BlockError::Unsupported(STALE)));
    assert_eq!(
        chip.borrow().accesses,
        before,
        "retired aliases perform no PCI/MMIO"
    );
}

#[test]
fn native_empty_socket_insertion_ppbuf_read_write_and_removal_retire_aliases() {
    let chip = Chip::new(false, false);
    let mut host = make_host(&chip, false).unwrap();
    assert!(host.poll().unwrap().is_none());
    chip.borrow_mut().bipr |= (1 << 16) | (1 << 25);
    let mut card = host.poll().unwrap().unwrap();
    let mut alias = card.clone();
    assert_eq!(card.identity().blocks, 8192);
    assert_eq!(card.info().bus_width, 4);
    assert_eq!(card.info().clock_hz, 50_000_000);
    assert_eq!(chip.borrow().card.width, 4);
    let mut bytes = [0; 512];
    card.read(37, &mut bytes).unwrap();
    assert_eq!(bytes, chip.borrow().card.block(37));
    let written = core::array::from_fn::<_, 512, _>(|i| (i as u8).wrapping_mul(13));
    card.write(37, &written).unwrap();
    card.flush().unwrap();
    card.read(37, &mut bytes).unwrap();
    assert_eq!(bytes, written);
    let c = chip.borrow();
    assert_eq!(c.config[4] & 6, 2);
    assert_eq!(c.config[0x92] & 1, 0);
    assert_eq!(c.config[0xa3] & 0x80, 0);
    assert_eq!(c.config[0x70f], 0x5b);
    assert_eq!(c.phy[0], 0xba42);
    assert_eq!(&c.regs[0x3e44..0x3e48], &[0; 4]);
    assert_eq!(c.regs[0x3e4a] & 0xc0, 0xc0);
    assert!(
        c.effects
            .iter()
            .any(|effect| matches!(effect, Effect::Config(4, 2, 0x401)))
    );
    assert!(
        c.effects
            .iter()
            .any(|effect| matches!(effect, Effect::Config(4, 2, 0x403)))
    );
    assert_eq!(
        c.effects
            .iter()
            .filter(|effect| matches!(effect, Effect::DataWrite(37)))
            .count(),
        1
    );
    assert_eq!(
        c.effects
            .iter()
            .filter(|effect| matches!(effect, Effect::Command(24, 37, 8)))
            .count(),
        1
    );
    drop(c);
    chip.borrow_mut().bipr = 1 << 25;
    assert!(card.read(0, &mut bytes).is_err());
    assert!(host.poll().unwrap().is_none());
    stale(&mut card, &chip);
    stale(&mut alias, &chip);
    chip.borrow_mut().bipr = (1 << 16) | (1 << 25);
    let mut fresh = host.poll().unwrap().unwrap();
    assert_ne!(fresh.generation, alias.generation);
    fresh.read(37, &mut bytes).unwrap();
    assert_eq!(bytes, written);
    stale(&mut alias, &chip);
}
#[test]
fn native_mmc_real_width_ext_csd_cache_and_no_command_after_poweroff_notification() {
    let chip = Chip::new(true, true);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    assert_eq!(card.info().kind, Kind::Mmc);
    assert_eq!(card.info().clock_hz, 52_000_000);
    assert_eq!(card.info().bus_width, 4);
    assert_eq!(chip.borrow().card.ext[183], 1);
    assert_eq!(chip.borrow().card.ext[187], 4);
    assert_eq!(chip.borrow().card.ext[185], 1);
    assert_eq!(chip.borrow().card.ext[34], 1);
    let mut bytes = [0; 512];
    card.read(91, &mut bytes).unwrap();
    card.write(91, &[0x68; 512]).unwrap();
    card.flush().unwrap();
    assert_eq!(chip.borrow().card.ext[32], 1);
    card.shutdown(true).unwrap();
    let c = chip.borrow();
    let notify = c
        .effects
        .iter()
        .rposition(|e| matches!(e, Effect::Command(6, 0x0322_0300, 8)))
        .unwrap();
    assert!(
        !c.effects[notify + 1..]
            .iter()
            .any(|e| matches!(e, Effect::Command(..)))
    );
    assert_eq!(c.regs[0x3d50] & 3, 3);
    assert_eq!(c.regs[0x3d69] & 4, 0);
    assert_eq!(c.regs[0x3d55] & 12, 0);
    drop(c);
    stale(&mut card, &chip);
    let mut fresh = host.poll().unwrap().unwrap();
    assert_ne!(fresh.generation, card.generation);
    fresh.read(91, &mut bytes).unwrap();
    assert_eq!(bytes, [0x68; 512]);
}
#[test]
fn native_transfer_errors_and_suppressed_completion_retire_before_payload_reuse() {
    for fault in [
        Fault::MissingEnd,
        Fault::Crc7,
        Fault::Crc16,
        Fault::CrcTimeout,
        Fault::Remove,
        Fault::Delink,
        Fault::MemoryStick,
    ] {
        let chip = Chip::new(false, true);
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        inject(&host, &chip, fault);
        if fault == Fault::MissingEnd {
            chip.borrow_mut().delay_on = Some(DelayPoint::Completion);
            chip.borrow_mut().delay_us = 5_000_001;
        }
        let mut bytes = [0xa5; 512];
        assert!(card.read(11, &mut bytes).is_err(), "{fault:?}");
        assert_eq!(bytes, [0xa5; 512], "{fault:?}");
        stale(&mut card, &chip);
        if !matches!(fault, Fault::Delink | Fault::Remove | Fault::MemoryStick) {
            let mut fresh = host.poll().unwrap().unwrap();
            fresh.read(11, &mut bytes).unwrap();
            assert_eq!(bytes, chip.borrow().card.block(11));
        }
    }
    // The command CHECK requires both END and IDLE, unlike a data
    // read. An END-only response must not pass as command completion: a
    // cached MMC's cache flush is such a command.
    let chip = Chip::new(true, true);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    inject(&host, &chip, Fault::MissingIdle);
    chip.borrow_mut().delay_on = Some(DelayPoint::Completion);
    chip.borrow_mut().delay_us = 1_000_001;
    assert_eq!(card.flush_cache(), Err(BlockError::Timeout));
    stale(&mut card, &chip);
    // CMD24 accepted the write and the physical data changed, but no END
    // arrived. No successful write/flush or kept alias may be reported.
    let chip = Chip::new(false, true);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    inject(&host, &chip, Fault::AfterWrite);
    // Defer this delay until the data mode: CMD24's separate R1 phase must
    // complete first, and the physical PPBUF write must take effect.
    chip.borrow_mut().delay_on = Some(DelayPoint::Completion);
    chip.borrow_mut().delay_us = 5_000_001;
    assert_eq!(card.write(29, &[0xce; 512]), Err(BlockError::Timeout));
    assert_eq!(chip.borrow().card.block(29), [0xce; 512]);
    stale(&mut card, &chip);
    let mut fresh = host.poll().unwrap().unwrap();
    let mut bytes = [0; 512];
    fresh.read(29, &mut bytes).unwrap();
    assert_eq!(bytes, [0xce; 512]);
}
#[test]
fn native_physical_width_busy_readiness_and_failed_stop_are_not_success() {
    let chip = Chip::new(true, true);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    // A real card/controller/board width mismatch produces DATA CRC failure.
    chip.borrow_mut().card.width = 8;
    let mut bytes = [0xa5; 512];
    assert!(card.read(7, &mut bytes).is_err());
    assert_eq!(bytes, [0xa5; 512]);
    stale(&mut card, &chip);
    let mut card = host.poll().unwrap().unwrap();
    inject(&host, &chip, Fault::Busy);
    assert!(card.shutdown(true).is_err());
    stale(&mut card, &chip);
    let chip = Chip::new(false, true);
    let mut host = make_host(&chip, false).unwrap();
    // Request and recovery deadlines expire after a fixed number of
    // counter reads (`test_clock`), whatever the host's scheduling.
    let _virtual = crate::test_clock::virtualize();
    let setup_clock = Clock {
        ticks_per_microsecond: 1000,
    };
    host.inner.borrow_mut().clock = setup_clock;
    let mut card = host.poll().unwrap().unwrap();
    let status_before = chip
        .borrow()
        .effects
        .iter()
        .filter(|effect| matches!(effect, Effect::Command(13, ..)))
        .count();
    chip.borrow_mut().card.nonready = true;
    assert_eq!(card.read(0, &mut [0; 512]), Err(BlockError::Timeout));
    assert!(
        chip.borrow()
            .effects
            .iter()
            .filter(|effect| matches!(effect, Effect::Command(13, ..)))
            .count()
            > status_before,
        "the real card-status response must establish non-readiness"
    );
    let failure = host.last_failure().unwrap();
    assert_eq!(failure.primary, BlockError::Timeout);
    assert_eq!(failure.retirement, None);
    assert!(!failure.quarantined);
    assert!(host.inner.borrow().request_deadline.is_none());
    assert_eq!(
        host.inner.borrow().clock.ticks_per_microsecond,
        setup_clock.ticks_per_microsecond,
        "readiness and recovery share the host clock"
    );
    stale(&mut card, &chip);
    chip.borrow_mut().card.nonready = false;
    // The acknowledged Stop permits fresh identification; the failed
    // request's retirement failure stays recorded.
    let retired_generation = card.generation;
    let mut card = host.poll().unwrap().unwrap();
    assert_ne!(card.generation, retired_generation);
    card.read(7, &mut bytes).unwrap();
    assert_eq!(bytes, chip.borrow().card.block(7));
    inject(&host, &chip, Fault::MissingEnd);
    chip.borrow_mut().delay_on = Some(DelayPoint::Completion);
    chip.borrow_mut().delay_us = 5_000_001;
    chip.borrow_mut().stuck_stop = true;
    let stops = chip
        .borrow()
        .effects
        .iter()
        .filter(|e| matches!(e, Effect::Stop))
        .count();
    assert_eq!(card.read(0, &mut bytes), Err(BlockError::Timeout));
    assert!(
        chip.borrow()
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::Stop))
            .count()
            > stops
    );
    assert_eq!(
        host.last_failure().unwrap().retirement,
        Some(BlockError::Timeout)
    );
    stale(&mut card, &chip);
    let before = chip.borrow().accesses;
    assert!(host.poll().is_err());
    assert_eq!(
        chip.borrow().accesses,
        before,
        "failed retirement never reuses physical engine"
    );
}
#[test]
fn native_haimr_fault_after_effect_and_removed_pci_permanently_fence_public_io() {
    for stuck in [false, true] {
        let chip = Chip::new(false, true);
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        if stuck {
            chip.borrow_mut().stuck_haimr = Some(0xfdb3);
        } else {
            chip.borrow_mut().wrong_echo = Some(0xfdb3);
        }
        let mut bytes = [0xa5; 512];
        assert!(card.read(0, &mut bytes).is_err());
        assert_eq!(bytes, [0xa5; 512]);
        stale(&mut card, &chip);
        let before = chip.borrow().accesses;
        assert!(host.poll().is_err());
        assert_eq!(chip.borrow().accesses, before);
    }
    let chip = Chip::new(false, true);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    chip.borrow_mut().config[..4].fill(0xff);
    assert!(card.read(0, &mut [0; 512]).is_err());
    stale(&mut card, &chip);
    let before = chip.borrow().accesses;
    assert!(host.poll().is_err());
    assert_eq!(chip.borrow().accesses, before);
}
#[test]
fn native_card_power_and_clock_timeline_precedes_cmd0_and_delayed_card_completion() {
    let chip = Chip::new(false, true);
    chip.borrow_mut().transfer_polls = 3;
    let mut host = make_host(&chip, true).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    let mut bytes = [0; 512];
    card.read(3, &mut bytes).unwrap();
    assert_eq!(bytes, chip.borrow().card.block(3));
    let c = chip.borrow();
    assert!(c.partial_at.is_some());
    assert!(c.toggled_at.is_some());
    assert!(
        c.effects
            .iter()
            .any(|e| matches!(e, Effect::Register(0xfda5, 0xc0, 0x80)))
    );
    assert!(
        c.effects
            .iter()
            .any(|e| matches!(e, Effect::Command(0, 0, 8)))
    );
}
#[test]
fn native_board_vendor_profile_and_shared_memory_stick_gate_real_card_power() {
    let chip = Chip::new(false, true);
    {
        let mut c = chip.borrow_mut();
        c.config[0x724..0x728].copy_from_slice(&0x0200_0000u32.to_le_bytes());
        c.config[0x814..0x818].copy_from_slice(&(0x00c0_4000u32 | (2 << 5) | 0x10).to_le_bytes());
    }
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    assert_eq!(chip.borrow().regs[0x3d5a], 0x7f);
    assert_eq!(chip.borrow().regs[0x3d53] & 0x40, 0x40);
    assert_eq!(chip.borrow().regs[0x3f03] & 0x30, 0x30);
    chip.borrow_mut().bipr |= 1 << 17;
    assert!(card.read(0, &mut [0; 512]).is_err());
    assert_eq!(chip.borrow().regs[0x3d50] & 3, 3);
    stale(&mut card, &chip);
    let chip = Chip::new(true, true);
    {
        let mut c = chip.borrow_mut();
        c.config[0x727] = 0;
        c.config[0x814] = 0x10;
    }
    let mut host = make_host(&chip, false).unwrap();
    assert!(matches!(
        host.poll(),
        Err(BlockError::Unsupported(
            "RTSX board configuration does not wire MMC"
        ))
    ));
    assert!(
        !chip
            .borrow()
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Command(1, _, _)))
    );
}
#[test]
fn native_extended_capability_bodies_refuse_forged_l1ss_before_effects() {
    for (name, writes) in [
        (
            "AER interior",
            vec![(0x100, 0x11c1_0001u32), (0x11c, 0x0001_001e)],
        ),
        (
            "L1SS Control2 interior",
            vec![(0x180, 0x18c1_001e), (0x18c, 0x0001_001e)],
        ),
        (
            "vendor interior",
            vec![
                (0x100, 0x1081_000b),
                (0x104, 0x0200_0000),
                (0x108, 0x0001_001e),
            ],
        ),
        ("unknown body", vec![(0x100, 0x1401_0002)]),
        (
            "power budgeting interior",
            vec![(0x150, 0x1581_0004), (0x158, 0x0001_001e)],
        ),
        ("AER prefix extension", vec![(0x118, 1 << 11)]),
        ("unsupported version", vec![(0x100, 0x1403_0001)]),
        ("loop", vec![(0x180, 0x1001_001e)]),
        ("misaligned next", vec![(0x100, 0x1421_0001)]),
        ("zero interior header", vec![(0x140, 0)]),
        ("duplicate DSN", vec![(0x160, 0x1801_0003)]),
        (
            "truncated L1SS",
            vec![(0x160, 0xff41_0018), (0xff4, 0x0001_001e)],
        ),
        (
            "short vendor body",
            vec![(0x100, 0x0001_000b), (0x104, 0x0040_0000)],
        ),
        (
            "truncated vendor body",
            vec![(0x100, 0x0001_000b), (0x104, 0xfff0_0000)],
        ),
    ] {
        let chip = Chip::new(false, false);
        for (at, value) in writes {
            chip.borrow_mut().config[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut function = function(&chip);
        assert!(controller::admission(&mut function).is_err(), "{name}");
        assert!(
            chip.borrow().effects.is_empty(),
            "{name}: no power/interrupt/BAR writes"
        );
    }
    // A long, fully measured chain, not repeated fake two-byte
    // headers. The final L1SS includes Control2 through config byte4095.
    let chip = Chip::new(false, false);
    {
        let mut c = chip.borrow_mut();
        c.config[0x100..].fill(0);
        for at in (0x100..0xff0).step_by(8) {
            c.config[at..at + 4]
                .copy_from_slice(&(((at as u32 + 8) << 20) | 0x0001_000b).to_le_bytes());
            c.config[at + 4..at + 8].copy_from_slice(&0x0080_0000u32.to_le_bytes());
        }
        c.config[0xff0..0xff4].copy_from_slice(&0x0001_001eu32.to_le_bytes());
    }
    let mut function = function(&chip);
    let admitted = controller::admission(&mut function).unwrap();
    assert!(chip.borrow().effects.is_empty());
    controller::Configuration::capture(&mut function, admitted).unwrap();
}
#[test]
fn native_readonly_and_constructor_faults_never_publish_or_grant_dma() {
    let chip = Chip::new(false, true);
    chip.borrow_mut().bipr |= 1 << 19;
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    assert!(card.identity().read_only);
    let before = chip
        .borrow()
        .effects
        .iter()
        .filter(|e| matches!(e, Effect::Command(24, _, _)))
        .count();
    assert_eq!(card.write(1, &[0x85; 512]), Err(BlockError::ReadOnly));
    assert_eq!(
        chip.borrow()
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::Command(24, _, _)))
            .count(),
        before
    );
    let chip = Chip::new(false, true);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    assert!(!card.identity().read_only);
    chip.borrow_mut().bipr |= 1 << 19;
    assert_eq!(card.write(1, &[0x85; 512]), Err(BlockError::ReadOnly));
    assert!(
        !chip
            .borrow()
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Command(24, _, _)))
    );
    for denied in [0x50, 0x70f] {
        let chip = Chip::new(false, true);
        chip.borrow_mut().deny_pci = Some(denied);
        assert!(make_host(&chip, false).is_err());
        let c = chip.borrow();
        assert_eq!(c.config[4] & 4, 0);
        assert!(!c.effects.iter().any(|e| matches!(e, Effect::Command(..))));
    }
    let chip = Chip::new(false, true);
    chip.borrow_mut().stuck_phy = true;
    assert!(make_host(&chip, false).is_err());
    assert!(
        !chip
            .borrow()
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Command(..)))
    );
}
#[test]
fn native_card_below_source_initial_data_rate_refuses_before_overclocked_data() {
    let chip = Chip::new(false, true);
    chip.borrow_mut().card.transfer_speed = 0x0a; // CSD:10MHz
    let mut host = make_host(&chip, false).unwrap();
    assert!(matches!(
        host.poll(),
        Err(BlockError::Unsupported(
            "MMC/SD CSD transfer clock below host physical minimum"
        ))
    ));
    let c = chip.borrow();
    assert!(
        !c.effects
            .iter()
            .any(|e| matches!(e, Effect::Command(_, _, 12) | Effect::DataWrite(_)))
    );
    assert!(host.inner.borrow().medium.is_none());
}
#[test]
fn native_real_clock_late_publication_ack_completion_status_and_ppbuf_refuse_output() {
    for point in [
        DelayPoint::HaimrPublication,
        DelayPoint::StartAck,
        DelayPoint::Completion,
        DelayPoint::Status,
        DelayPoint::LastPpbuf,
    ] {
        let chip = Chip::new(false, true);
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        host.inner.borrow_mut().clock = Clock {
            ticks_per_microsecond: 100,
        };
        chip.borrow_mut().delay_on = Some(point);
        chip.borrow_mut().delay_us = 5_000_001;
        let start = chip.borrow().effects.len();
        let mut poison = [0xd6; 512];
        assert_eq!(
            card.read(19, &mut poison),
            Err(BlockError::Timeout),
            "{point:?}"
        );
        assert_eq!(poison, [0xd6; 512]);
        let c = chip.borrow();
        assert_eq!(c.delayed, [point]);
        assert!(
            !c.effects[start..]
                .iter()
                .any(|e| matches!(e, Effect::Command(13, _, _))),
            "no new readiness transaction after expired data request"
        );
        drop(c);
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, BlockError::Timeout);
        assert_eq!(failure.quarantined, point == DelayPoint::HaimrPublication);
        stale(&mut card, &chip);
        if failure.quarantined {
            let before = chip.borrow().accesses;
            assert!(host.poll().is_err());
            assert_eq!(chip.borrow().accesses, before);
        } else {
            host.inner.borrow_mut().clock = Clock {
                ticks_per_microsecond: 1000,
            };
            assert!(host.poll().unwrap().is_some());
        }
    }
}
#[test]
fn native_primary_crc_survives_late_or_failed_retirement_and_failed_initial_restore() {
    for late in [false, true] {
        let chip = Chip::new(false, true);
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        inject(&host, &chip, Fault::Crc16);
        if late {
            chip.borrow_mut().delay_on = Some(DelayPoint::StopComplete);
            chip.borrow_mut().delay_us = 1_000_001;
        } else {
            chip.borrow_mut().wrong_echo = Some(0xfd54);
        }
        let mut poison = [0xd6; 512];
        let primary = card.read(7, &mut poison).unwrap_err();
        assert!(matches!(primary, BlockError::Device { status } if status & 0x4000 != 0));
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, primary);
        assert!(failure.quarantined);
        if late {
            assert_eq!(failure.retirement, Some(BlockError::Timeout));
        } else {
            assert!(matches!(
                failure.retirement,
                Some(BlockError::Unsupported(_))
            ));
        }
        assert_eq!(poison, [0xd6; 512]);
        stale(&mut card, &chip);
        let before = chip.borrow().accesses;
        assert_eq!(host.poll().err(), Some(primary));
        assert_eq!(chip.borrow().accesses, before);
    }
    let chip = Chip::new(false, true);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    host.inner.borrow_mut().set_clock(400_000).unwrap();
    chip.borrow_mut().card.app = true;
    chip.borrow_mut().wrong_restore = true;
    inject(&host, &chip, Fault::Crc16);
    let result = host
        .inner
        .borrow_mut()
        .execute(SD_SEND_SCR, 0, Response::Status, Some(8));
    let primary = result.unwrap_err();
    assert!(matches!(primary, BlockError::Device { status } if status & 0x4000 != 0));
    let failure = host.last_failure().unwrap();
    assert_eq!(failure.primary, primary);
    assert!(matches!(
        failure.restoration,
        Some(BlockError::Unsupported(_))
    ));
    assert!(
        failure.retirement.is_none(),
        "uncertain restore HAIMR refuses another cleanup publication"
    );
    assert!(failure.quarantined);
    stale(&mut card, &chip);
}
#[test]
fn native_constructor_stop_budget_starts_before_first_mmio_publication() {
    let chip = Chip::new(false, true);
    chip.borrow_mut().delay_on = Some(DelayPoint::ConstructorStop);
    // Constructor uses100ms at clock1000; advance the real TSC by more
    // than that same interval using the model clock100 delay primitive.
    chip.borrow_mut().delay_us = 1_000_001;
    assert!(matches!(make_host(&chip, false), Err(BlockError::Timeout)));
    let c = chip.borrow();
    assert_eq!(c.delayed, [DelayPoint::ConstructorStop]);
    assert_eq!(
        c.dma_stops,
        [4],
        "late first stop cannot authorize HDB or later publication"
    );
    assert_eq!(c.config[4] & 4, 0);
    assert!(!c.effects.iter().any(|e| matches!(e, Effect::Command(..))));
}
#[test]
fn native_actual_wrong_ack_sd_error_and_transfer_failure_survive_same_read_deadline() {
    for mode in 0..4 {
        let chip = Chip::new(false, true);
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        host.inner.borrow_mut().clock = Clock {
            ticks_per_microsecond: 100,
        };
        let point = match mode {
            0 => {
                chip.borrow_mut().wrong_echo = Some(0xfdb3);
                DelayPoint::StartAck
            }
            1 => {
                chip.borrow_mut().next_fault = Fault::Crc16;
                DelayPoint::Status1
            }
            2 => {
                chip.borrow_mut().card.width = 8;
                DelayPoint::Completion
            }
            _ => DelayPoint::BiprFailure,
        };
        chip.borrow_mut().delay_on = Some(point);
        chip.borrow_mut().delay_us = 5_000_001;
        let start = chip.borrow().effects.len();
        let mut poison = [0xb7; 512];
        let primary = card.read(13, &mut poison).unwrap_err();
        assert_ne!(
            primary,
            BlockError::Timeout,
            "actual error cannot become only elapsed success refusal"
        );
        match mode {
            0 => assert_eq!(
                primary,
                BlockError::Unsupported("RTSX register write did not acknowledge")
            ),
            1 => assert!(matches!(primary, BlockError::Device { status } if status & 0x4000 != 0)),
            2 => {
                assert!(matches!(primary, BlockError::Device { status } if status & 0x10 != 0))
            }
            _ => {
                assert!(matches!(primary, BlockError::Device { status } if status & (1 << 28) != 0))
            }
        }
        assert_eq!(chip.borrow().delayed, [point]);
        assert_eq!(poison, [0xb7; 512]);
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, primary);
        assert_eq!(failure.quarantined, mode == 0);
        assert!(
            !chip.borrow().effects[start..]
                .iter()
                .any(|e| matches!(e, Effect::Command(13, _, _)))
        );
        if mode == 0 {
            assert!(
                !chip.borrow().effects[start..]
                    .iter()
                    .any(|e| matches!(e, Effect::Stop)),
                "rejected ACK never authorizes another HAIMR"
            );
            let before = chip.borrow().accesses;
            assert_eq!(host.poll().err(), Some(primary));
            assert_eq!(chip.borrow().accesses, before);
        }
        stale(&mut card, &chip);
    }
}
#[test]
fn native_observed_overcurrent_or_memory_stick_survives_failed_emergency_shutdown() {
    for overcurrent in [false, true] {
        for during in [false, true] {
            let chip = Chip::new(false, true);
            let mut host = make_host(&chip, false).unwrap();
            let mut card = host.poll().unwrap().unwrap();
            chip.borrow_mut().wrong_echo = Some(0xfd69);
            if during {
                chip.borrow_mut().next_fault = if overcurrent {
                    Fault::Overcurrent
                } else {
                    Fault::MemoryStick
                };
            } else {
                chip.borrow_mut().bipr |= (if overcurrent { 1 << 22 } else { 1 << 17 }) | (1 << 25);
            }
            let start = chip.borrow().effects.len();
            let mut poison = [0xb7; 512];
            let primary = card.read(3, &mut poison).unwrap_err();
            if overcurrent {
                assert!(
                    matches!(primary, BlockError::Device { status } if status & (1 << 22) != 0)
                );
            } else {
                assert!(
                    matches!(primary, BlockError::Unsupported(message) if message.contains("Memory Stick"))
                );
            }
            assert_eq!(poison, [0xb7; 512]);
            let failure = host.last_failure().unwrap();
            assert_eq!(failure.primary, primary);
            assert_eq!(
                failure.retirement,
                Some(BlockError::Unsupported(
                    "RTSX register write did not acknowledge"
                ))
            );
            assert!(failure.quarantined);
            assert!(
                !chip.borrow().effects[start..]
                    .iter()
                    .any(|e| matches!(e, Effect::Stop)),
                "failed emergency ACK refuses further cleanup publication"
            );
            stale(&mut card, &chip);
            let before = chip.borrow().accesses;
            assert_eq!(host.poll().err(), Some(primary));
            assert_eq!(chip.borrow().accesses, before);
        }
    }
}
#[test]
fn native_successful_memory_stick_poweroff_is_final_and_fresh_commands_retire_again() {
    for phase in 0..4 {
        let chip = Chip::new(false, true);
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        if phase == 3 {
            host.inner.borrow_mut().set_clock(400_000).unwrap();
            chip.borrow_mut().card.app = true;
        }
        if phase == 0 {
            chip.borrow_mut().bipr |= 1 << 17;
        } else {
            chip.borrow_mut().next_fault = Fault::MemoryStick;
        }
        let start = chip.borrow().effects.len();
        let mut poison = [0xb7; 512];
        let primary = match phase {
            2 => card.write(3, &[0x78; 512]).unwrap_err(),
            3 => host
                .inner
                .borrow_mut()
                .execute(SD_SEND_SCR, 0, Response::Status, Some(8))
                .unwrap_err(),
            _ => card.read(3, &mut poison).unwrap_err(),
        };
        assert!(
            matches!(primary, BlockError::Unsupported(message) if message.contains("Memory Stick"))
        );
        assert_eq!(poison, [0xb7; 512]);
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, primary);
        assert_eq!(failure.retirement, None);
        assert!(!failure.quarantined);
        assert_eq!(chip.borrow().regs[0x3d50] & 3, 3);
        assert!(
            !chip.borrow().effects[start..]
                .iter()
                .any(|e| matches!(e, Effect::Stop)),
            "completed emergency power-off is not followed by Stop"
        );
        assert!(
            matches!(
                chip.borrow().effects.last(),
                Some(Effect::Register(0xfd62, 0xff, 0xd5))
            ),
            "power-off is the last hardware publication, including initial divider restoration"
        );
        stale(&mut card, &chip);
        {
            let mut c = chip.borrow_mut();
            c.bipr = (c.bipr & !(1 << 17)) | (1 << 25);
        }
        let mut fresh = host.poll().unwrap().unwrap();
        chip.borrow_mut().next_fault = Fault::Crc16;
        let start = chip.borrow().effects.len();
        let primary = fresh.read(3, &mut poison).unwrap_err();
        assert!(matches!(primary, BlockError::Device { .. }));
        assert_eq!(host.last_failure().unwrap().primary, primary);
        assert!(
            chip.borrow().effects[start..]
                .iter()
                .any(|e| matches!(e, Effect::Stop)),
            "a fresh command owns its own actual retirement"
        );
        stale(&mut fresh, &chip);
    }
}
#[test]
fn native_completed_r1_error_survives_late_final_response_observation() {
    let chip = Chip::new(false, true);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    host.inner.borrow_mut().clock = Clock {
        ticks_per_microsecond: 100,
    };
    chip.borrow_mut().card.status_error = 1 << 21;
    chip.borrow_mut().delay_on = Some(DelayPoint::LastResponse);
    chip.borrow_mut().delay_us = 1_000_001;
    let primary = BlockError::Device { status: 1 << 21 };
    assert_eq!(card.read(0, &mut [0; 512]), Err(primary.clone()));
    assert_eq!(chip.borrow().delayed, [DelayPoint::LastResponse]);
    assert_eq!(host.last_failure().unwrap().primary, primary);
    stale(&mut card, &chip);
}
fn rts522a(mmc: bool, present: bool, revision: u8, l1ss: u8, rtd3: bool) -> Rc<RefCell<Chip>> {
    let chip = Chip::new(mmc, present);
    {
        let mut c = chip.borrow_mut();
        c.config[2..4].copy_from_slice(&0x522au16.to_le_bytes());
        c.config[0x188] = l1ss;
        // Nonzero unrelated bits prove that OOBS is a real PHY RMW.
        c.phy[1] = 0xa6b5;
        c.regs[0x3e90] = 0xb0 | revision;
        c.config[0x727] = 0;
        c.config[0x814] = u8::from(rtd3) << 1;
        // Keep the old registers nonzero to detect accidental RTS5227 writes.
        c.regs[0x3f46] = 0x91;
        c.regs[0x3e56] = 0xb7;
    }
    chip
}
#[test]
fn native_rts522a_real_silicon_revision_l1ss_board_and_electrical_profiles() {
    for revision in [0, 1, 15] {
        for l1ss in [0, 1, 2, 4, 8, 15] {
            for rtd3 in [false, true] {
                let chip = rts522a(false, true, revision, l1ss, rtd3);
                assert!(matches(&function(&chip)));
                let mut host = make_host(&chip, false).unwrap();
                let mut card = host.poll().unwrap().unwrap();
                let mut block = [0; 512];
                card.read(3, &mut block).unwrap();
                assert_eq!(block, chip.borrow().card.block(3));
                let c = chip.borrow();
                assert_eq!(c.phy[0], 0, "never RTS5227 RX sensitivity recipe");
                for (at, value) in [
                    (3, 0xc152),
                    (2, 0x0a1f),
                    (0x1a, 0x2546),
                    (0x1d, 4),
                    (0x1e, 0x5c7f),
                ] {
                    assert_eq!(c.phy[at], if revision == 0 { value } else { 0 });
                }
                assert_eq!(
                    c.phy[1],
                    if l1ss == 0 {
                        0xa6b5 | 0x200
                    } else {
                        0xa6b5 & !0x200
                    }
                );
                assert_eq!(c.phy[8], 0x57e4);
                assert_eq!(c.regs[0x3ea8], if l1ss == 0 { 0x83 } else { 3 });
                assert_eq!(c.regs[0x3ea9], if l1ss == 0 { 0xde } else { 0 });
                assert_eq!(c.regs[0x3f7c] & 0xf0, 0xf0);
                assert_eq!(c.regs[0x3f7e] & 1, u8::from(rtd3));
                assert_eq!(c.regs[0x3f78] & 0x30, if rtd3 { 0x30 } else { 0x20 });
                assert_eq!(c.regs[0x3f46], 0x91);
                assert_eq!(c.regs[0x3e56], 0xb7);
                assert_eq!(&c.regs[0x3e44..0x3e48], &[0x3c, 0x88, 0, 0]);
                assert_eq!(c.regs[0x3e8f], if l1ss & 8 != 0 { 0x78 } else { 0 });
                assert_eq!(c.regs[0x3e59] & 2, 2);
                assert_eq!(c.regs[0x3e55] & 4, 4);
                assert_eq!(c.regs[0x3e71] & 8, 8);
                assert_eq!(c.regs[0x3e58], 0x11);
                assert_eq!(c.config[4] & 6, 2, "PIO never enables bus mastering");
            }
        }
    }
}
#[test]
fn native_rts522a_mmc_empty_media_retirement_and_failed_ocp_ack() {
    for mmc in [false, true] {
        let chip = rts522a(mmc, false, 0, 8, true);
        let mut host = make_host(&chip, false).unwrap();
        assert!(host.poll().unwrap().is_none());
        assert_eq!(chip.borrow().regs[0x3d6a] & 12, 0);
        assert_eq!(chip.borrow().regs[0x3c00] & 2, 2);
        chip.borrow_mut().bipr |= (1 << 16) | (1 << 25);
        let mut card = host.poll().unwrap().unwrap();
        card.write(3, &[0x69; 512]).unwrap();
        card.flush().unwrap();
        let mut block = [0; 512];
        card.read(3, &mut block).unwrap();
        assert_eq!(block, [0x69; 512]);
        chip.borrow_mut().bipr = 1 << 25;
        assert!(card.read(0, &mut [0; 512]).is_err());
        stale(&mut card, &chip);
        chip.borrow_mut().bipr = (1 << 16) | (1 << 25);
        let mut fresh = host.poll().unwrap().unwrap();
        fresh.read(3, &mut block).unwrap();
        stale(&mut card, &chip);
        fresh.shutdown(true).unwrap();
        assert_eq!(chip.borrow().regs[0x3d6a] & 12, 0);
        assert_eq!(chip.borrow().regs[0x3c00] & 2, 2);
    }
    for wrong in [0xfd6a, 0xfc00, 0xfd50] {
        let chip = rts522a(false, true, 1, 0, false);
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        chip.borrow_mut().next_fault = Fault::Overcurrent;
        chip.borrow_mut().wrong_echo = Some(wrong);
        let mut poison = [0x91; 512];
        let start = chip.borrow().effects.len();
        let primary = card.read(3, &mut poison).unwrap_err();
        assert!(matches!(primary, BlockError::Device { status } if status & (1 << 22) != 0));
        assert_eq!(poison, [0x91; 512]);
        assert_eq!(host.overcurrent_status(), Some(6));
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, primary);
        assert!(failure.retirement.is_some());
        assert!(failure.quarantined);
        assert!(
            !chip.borrow().effects[start..]
                .iter()
                .any(|e| matches!(e, Effect::Stop))
        );
        stale(&mut card, &chip);
        let before = chip.borrow().accesses;
        assert_eq!(host.poll().err(), Some(primary));
        assert_eq!(chip.borrow().accesses, before);
    }
}
#[test]
fn native_rts522a_overcurrent_clears_actual_latch_after_poweroff_without_later_stop() {
    let chip = rts522a(false, true, 0, 15, false);
    let mut host = make_host(&chip, false).unwrap();
    let mut card = host.poll().unwrap().unwrap();
    chip.borrow_mut().next_fault = Fault::Overcurrent;
    let start = chip.borrow().effects.len();
    let mut poison = [0x91; 512];
    let primary = card.read(3, &mut poison).unwrap_err();
    assert!(matches!(primary, BlockError::Device { status } if status & (1 << 22) != 0));
    assert_eq!(poison, [0x91; 512]);
    assert_eq!(host.overcurrent_status(), Some(6));
    let c = chip.borrow();
    assert_eq!(c.regs[0x3d50] & 3, 3);
    assert_eq!(c.regs[0x3e75] & 6, 0);
    assert_eq!(c.regs[0x3d6e] & 6, 0);
    assert_eq!(c.bipr & (1 << 22), 0);
    assert!(
        !c.effects[start..]
            .iter()
            .any(|e| matches!(e, Effect::Stop | Effect::Command(13, _, _)))
    );
    drop(c);
    assert!(host.last_failure().unwrap().retirement.is_none());
    stale(&mut card, &chip);
}
#[test]
fn native_rts522a_unavailable_ltr_and_revision_access_failures_are_explicit() {
    let chip = rts522a(false, false, 1, 0, false);
    {
        let mut c = chip.borrow_mut();
        c.config[0x100..].fill(0);
        c.config[0x68..0x6a].fill(0);
    }
    let mut host = make_host(&chip, false).unwrap();
    assert!(host.poll().unwrap().is_none());
    assert_eq!(&chip.borrow().regs[0x3e44..0x3e48], &[0; 4]);
    assert_eq!(chip.borrow().regs[0x3e8f], 0);
    for at in [0xfe90, 0xff7e, 0xfe3c, 0xfd6b, 0xfd6d, 0xfd6c] {
        let chip = rts522a(false, true, 0, 15, false);
        chip.borrow_mut().stuck_haimr = Some(at);
        assert!(make_host(&chip, false).is_err());
        assert!(
            !chip
                .borrow()
                .effects
                .iter()
                .any(|e| matches!(e, Effect::Command(_, _, _)))
        );
        assert_eq!(chip.borrow().config[4] & 4, 0);
    }
    for device in [0x5209u16, 0x5249, 0x525a] {
        let chip = Chip::new(false, false);
        chip.borrow_mut().config[2..4].copy_from_slice(&device.to_le_bytes());
        assert!(!matches(&function(&chip)));
    }
    let chip = rts522a(false, false, 0, 0, false);
    chip.borrow_mut().config[0x0b] = 8;
    assert!(!matches(&function(&chip)));
}
#[test]
fn native_rts522a_actual_cmd11_modes_clocks_and_three_sweep_tuning() {
    for (function, hz, timing) in [
        (0, 25_000_000, Timing::Sdr12),
        (1, 50_000_000, Timing::Sdr25),
        (2, 100_000_000, Timing::Sdr50),
        (3, 208_000_000, Timing::Sdr104),
    ] {
        let chip = rts522a(false, true, 0, 15, false);
        chip.borrow_mut().card.uhs_modes = 1 << function;
        // Intersect three real sweeps; the stable window wraps across phase0.
        chip.borrow_mut().tuning_windows = [0xf000_001f, 0xe000_000f, 0xc000_0007];
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        assert_eq!(card.info().signal_voltage, SignalVoltage::V1_8);
        assert_eq!(card.info().timing, timing);
        assert_eq!(card.info().clock_hz, hz);
        let mut bytes = [0; 512];
        card.read(3, &mut bytes).unwrap();
        assert_eq!(bytes, chip.borrow().card.block(3));
        card.write(3, &[0x7e; 512]).unwrap();
        card.flush().unwrap();
        card.read(3, &mut bytes).unwrap();
        assert_eq!(bytes, [0x7e; 512]);
        let c = chip.borrow();
        assert_eq!(c.phy[0x11], 0x3c02);
        assert_eq!(c.phy[8], 0x54a4);
        assert_eq!(c.regs[0x3d5a], 0x99, "actual vendor1.8V drive index0");
        if function >= 2 {
            assert_eq!(c.tuning_attempts, 97);
            assert_eq!(c.regs[0x3c2a] & 31, 20, "RTS522A TX phase");
            assert_eq!(
                c.regs[0x3c2b] & 31,
                0,
                "middle of actual stable wrap window"
            );
            assert_eq!(
                c.card.current_function, 1,
                "400mA actual3.3V VCC current limit"
            );
        } else {
            assert_eq!(c.tuning_attempts, 0);
        }
        let cmd11 = c
            .effects
            .iter()
            .position(|e| matches!(e, Effect::Command(11, 0, 8)))
            .unwrap();
        let cid = c
            .effects
            .iter()
            .position(|e| matches!(e, Effect::Command(2, 0, 8)))
            .unwrap();
        assert!(cmd11 < cid);
        drop(c);
        card.shutdown(true).unwrap();
    }
}
#[test]
fn native_rts522a_voltage_or_tuning_failure_never_publishes_and_repower_uses_fresh_cmd0() {
    for fault in 0..5 {
        let chip = rts522a(false, true, 1, 0, false);
        chip.borrow_mut().card.uhs_modes = 8;
        match fault {
            0 => chip.borrow_mut().bad_cmd11_low = true,
            1 => chip.borrow_mut().bad_cmd11_high = true,
            2 => chip.borrow_mut().tuning_windows = [0; 3],
            3 => chip.borrow_mut().tuning_windows = [0xff, 0xff00, 0xff0000],
            _ => chip.borrow_mut().tuning_windows = [1; 3],
        }
        let mut host = make_host(&chip, false).unwrap();
        if fault == 4 {
            // Fault after the voltage transition, during tuning publication.
            chip.borrow_mut().wrong_echo = Some(0xfc2b);
        }
        assert!(host.poll().is_err());
        assert!(host.inner.borrow().medium.is_none());
        if fault <= 1 {
            assert_eq!(
                chip.borrow().regs[0x3d50] & 3,
                3,
                "failed electrical transition actually powers off"
            );
            assert_eq!(chip.borrow().regs[0x3e75] & 6, 0);
            assert!(
                !chip
                    .borrow()
                    .effects
                    .iter()
                    .any(|e| matches!(e, Effect::Command(2, _, _)))
            );
        }
        if fault == 4 {
            let before = chip.borrow().accesses;
            assert!(host.poll().is_err());
            assert_eq!(chip.borrow().accesses, before);
        } else {
            let start = chip.borrow().effects.len();
            {
                let mut c = chip.borrow_mut();
                c.bad_cmd11_low = false;
                c.bad_cmd11_high = false;
                c.tuning_windows = [u32::MAX; 3];
                c.tuning_attempts = 0;
            }
            let mut fresh = host.poll().unwrap().unwrap();
            fresh.flush().unwrap();
            assert!(
                chip.borrow().effects[start..]
                    .iter()
                    .any(|e| matches!(e, Effect::Command(0, _, _)))
            );
        }
    }
}
#[test]
fn native_rts522a_tuning_media_faults_or_unacknowledged_speed_do_not_become_phase_evidence() {
    for fault in [Fault::Remove, Fault::Delink, Fault::Overcurrent] {
        let chip = rts522a(false, true, 0, 15, false);
        chip.borrow_mut().card.uhs_modes = 8;
        chip.borrow_mut().tuning_fault = Some(fault);
        let mut host = make_host(&chip, false).unwrap();
        assert!(host.poll().is_err());
        assert_eq!(chip.borrow().tuning_attempts, 1);
        assert!(host.inner.borrow().medium.is_none());
        assert!(host.last_failure().is_some());
    }
    let chip = rts522a(false, true, 1, 0, false);
    chip.borrow_mut().card.uhs_modes = 8;
    chip.borrow_mut().card.reject_switch = true;
    let mut host = make_host(&chip, false).unwrap();
    assert_eq!(
        host.poll().err(),
        Some(BlockError::Unsupported(
            "SD UHS speed selection was not acknowledged"
        ))
    );
    assert_eq!(chip.borrow().tuning_attempts, 0);
    assert_eq!(chip.borrow().regs[0x3da0] & 12, 0);
    assert!(host.inner.borrow().medium.is_none());
}
#[test]
fn native_rts522a_actual_phase_timeouts_continue_only_after_acknowledged_idle_and_stop() {
    for rejection in [Fault::CrcTimeout, Fault::ResponseTimeout] {
        let chip = rts522a(false, true, 1, 15, false);
        chip.borrow_mut().card.uhs_modes = 8;
        chip.borrow_mut().tuning_windows = [0xf000_000f; 3];
        chip.borrow_mut().tuning_rejection = rejection;
        let mut host = make_host(&chip, false).unwrap();
        let mut card = host.poll().unwrap().unwrap();
        assert_eq!(chip.borrow().tuning_attempts, 97);
        assert_eq!(chip.borrow().regs[0x3c2b] & 31, 0);
        card.flush().unwrap();
        assert!(!host.inner.borrow().tuning_rejection_observed);
    }
    let chip = rts522a(false, true, 1, 15, false);
    chip.borrow_mut().card.uhs_modes = 8;
    chip.borrow_mut().tuning_windows = [0; 3];
    chip.borrow_mut().tuning_rejection = Fault::ResponseTimeout;
    chip.borrow_mut().stuck_stop = true;
    let mut host = make_host(&chip, false).unwrap();
    // A stuck CARD_STOP leaves a pending START in this model; inject that
    // independently for the first tuning transaction, not initialization.
    chip.borrow_mut().tuning_fault = Some(Fault::MissingEnd);
    assert!(host.poll().is_err());
    assert_eq!(chip.borrow().tuning_attempts, 1);
    assert!(host.inner.borrow().medium.is_none());
}
#[test]
fn native_rts522a_late_actual_timeout_status_is_fatal_not_another_phase() {
    let chip = rts522a(false, true, 1, 15, false);
    chip.borrow_mut().card.uhs_modes = 8;
    chip.borrow_mut().tuning_late_timeout = true;
    let mut host = make_host(&chip, false).unwrap();
    assert_eq!(host.poll().err(), Some(BlockError::Timeout));
    assert_eq!(chip.borrow().tuning_attempts, 1);
    assert!(!host.inner.borrow().tuning_rejection_observed);
    assert!(host.inner.borrow().medium.is_none());
}
