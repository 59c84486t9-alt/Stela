// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! The Wi-Fi side of an RTL8822C's Bluetooth arbiter: `rtw_coex_power_on_setting`,
//! `rtw_coex_init_hw_config` and the cases of `rtw_coex_run_coex` that do not
//! read Bluetooth's state from firmware. A chip with live Bluetooth on 2.4 GHz
//! takes the Wi-Fi-only schedule, and [`Run::bluetooth_unscheduled`] says so.
use super::{
    efuse::BoardData,
    features::Report,
    io::{self, Io},
    registers::*,
    rf::{self, Path, Registers},
};
use alloc::vec::Vec;

/// Coexistence registers of `reg.h`.
const REG_GPIO_MUXCFG: u32 = 0x40;
const REG_PAD_CTRL1: u32 = 0x64;
const REG_SYS_SDIO_CTRL: u32 = 0x70;
const REG_WIFI_BT_INFO: u32 = 0xaa;
const REG_QUEUE_CTRL: u32 = 0x4c6;
const REG_DUMMY_PAGE4_V1: u32 = 0x4fc;
const REG_BT_COEX_TABLE0: u32 = 0x6c0;
const REG_BT_COEX_TABLE1: u32 = 0x6c4;
const REG_BT_COEX_BRK_TABLE: u32 = 0x6c8;
const REG_BT_COEX_TABLE_H: u32 = 0x6cc;
const REG_BT_COEX_V2: u32 = 0x762;
const REG_BT_STAT_CTRL: u32 = 0x778;
const REG_BT_TDMA_TIME: u32 = 0x790;
const REG_IGN_GNT_BT1: u32 = 0x1860;
const REG_NOMASK_TXBT: u32 = 0x1ca7;
const REG_ANAPAR: u32 = 0x1c30;
const REG_RSTB_SEL: u32 = 0x1c38;
const REG_IGN_GNTBT4: u32 = 0x4160;
/// `BIT_BT_PTA_EN` and `BIT_PO_BT_PTA_PINS`.
const PTA_PINS: u32 = (1 << 5) | (1 << 9);
const PTA_WL_TX_ENABLE: u8 = 1 << 4;
const PTA_EDCCA_ENABLE: u8 = 1 << 5;
const GNT_BT_POLARITY: u16 = 1 << 12;
const BTCCA_CONTROL: u8 = 3;
/// `BIT_LTE_MUX_CTRL_PATH >> 24`.
const MUX_CONTROL_PATH: u8 = 1 << 2;
/// `BIT_FEN_BB_GLB_RST | BIT_FEN_BB_RSTB`.
const BASEBAND_ENABLE: u8 = 3;
const BCN_FUNCTION_ENABLE: u8 = 1 << 3;
const BT_INTERRUPT_ENABLE: u16 = 1 << 15;
/// `BIT_ANAPAR_BTPS >> 16`, `BIT_DAC_OFF_ENABLE`, `BIT_PI_IGNORE_GNT_BT` and
/// `BIT_NOMASK_TXBT_ENABLE`, each a one-bit field of the byte named.
const ANAPAR_BTPS: u8 = 1 << 6;
const DAC_OFF_ENABLE: u8 = 1 << 4;
const IGNORE_GNT_BT: u8 = 1 << 3;
const NOMASK_TXBT: u8 = 1 << 3;
/// `RF_MODOPT`'s value that `rtw8822c_coex_cfg_init` keeps a parameter error off with.
const RF_MODOPT: u8 = 1;
const RF_MODOPT_DEFAULT: u32 = 0x40000;
const RF_MASK: u32 = 0xfffff;

/// `COEX_SCBD_ACTIVE` and `COEX_SCBD_ONOFF`.
const SCORE_ACTIVE: u16 = 1 << 0;
const SCORE_ON: u16 = 1 << 1;
const SCORE_ALL: u16 = 0xffff;
/// `COEX_SCBD_FIX2M`.
const SCORE_FIX_2M: u16 = 1 << 10;
const SCORE_TDMA: u16 = 1 << 9;

/// `COEX_WLPRI_TX_RSP`, `COEX_WLPRI_TX_BEACON`, `COEX_WLPRI_TX_BEACONQ` and
/// `COEX_WLPRI_RX_CCK`.
const PRIORITY_TX_RESPONSE: u8 = 3;
const PRIORITY_TX_BEACON: u8 = 4;
const PRIORITY_TX_BEACON_QUEUE: u8 = 27;
const PRIORITY_RX_CCK: u8 = 28;

/// The arbiter's indirect registers.
const LTE_COEX_CTRL: u32 = 0x38;
const LTE_WL_TRX_CTRL: u32 = 0xa0;
const LTE_BT_TRX_CTRL: u32 = 0xa4;
const LTE_COEX_ENABLE: u32 = 1 << 7;
const LTECOEX_READY: u32 = 1 << 29;
/// `COEX_GNT_SET_HW_PTA`, `COEX_GNT_SET_SW_LOW` and `COEX_GNT_SET_SW_HIGH`.
const GRANT_PTA: u32 = 0;
const GRANT_LOW: u32 = 1;
const GRANT_HIGH: u32 = 3;

/// `H2C_CMD_COEX_TDMA_TYPE`, `H2C_CMD_QUERY_BT_INFO` and `H2C_CMD_BT_WIFI_CONTROL`.
const COMMAND_TDMA: u32 = 0x60;
const COMMAND_QUERY_BT: u32 = 0x61;
const COMMAND_BT_WIFI_CONTROL: u32 = 0x69;
/// `COEX_H2C69_WL_LEAKAP` and `PARA1_H2C69_DIS_5MS`.
const LEAK_AP: u32 = 0xc;
const DISABLE_5MS: u32 = 1;

/// `table_sant_8822c`'s first three cases, and `table_nsant_8822c`'s first.
const SHARED_TABLES: [u32; 3] = [0xffff_ffff, 0x5555_5555, 0x6655_5555];
const SEPARATE_TABLE: u32 = 0xffff_ffff;
/// `DEF_BRK_TABLE_VAL`.
const BREAK_TABLE: u32 = 0xf0ff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    Rf(rf::Error),
    /// The arbiter's indirect window stayed busy.
    ArbiterBusy,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Hardware(error)
    }
}

impl From<rf::Error> for Error {
    fn from(error: rf::Error) -> Self {
        Self::Rf(error)
    }
}

/// `COEX_WLINK_*`, as far as a lone station reaches them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    TwoGhz,
    FiveGhz,
}

/// What the Wi-Fi side is doing, which `rtw_coex_run_coex` schedules around.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Link {
    pub five_ghz: bool,
    pub connected: bool,
}

/// What a step of the arbiter leaves for the firmware mailbox.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Run {
    pub commands: Vec<(u32, u32)>,
    /// Bluetooth is alive on the 2.4 GHz link Wi-Fi uses, and only firmware's
    /// reports could schedule the two.
    pub bluetooth_unscheduled: bool,
}

/// An arbiter's state.
#[derive(Debug)]
pub struct Coex {
    /// `efuse->btcoex`: firmware reports a Bluetooth half beside this one.
    combined: bool,
    /// `efuse->share_ant`.
    shared: bool,
    /// `coex_stat->kt_ver`.
    version: u8,
    /// `coex_stat->score_board`, what this side last told Bluetooth.
    score: u16,
    /// `coex->stop_dm`: nothing to run on a chip alone.
    stopped: bool,
    /// `coex_stat->gnt_workaround_state`.
    workaround: Option<Mode>,
    /// `coex_dm->cur_table`'s pair.
    table: Option<[u32; 2]>,
}

impl Coex {
    /// `rtw_chip_efuse_info_setup`'s reading of `board`.
    pub fn new(board: &BoardData) -> Self {
        Self::of(board.rf_board_raw, board.bt_raw)
    }

    fn of(option: u8, bluetooth: u8) -> Self {
        Self {
            combined: option != 0xff && option & 0xe0 == 0x20,
            shared: bluetooth & 1 != 0,
            version: 0,
            score: 0,
            stopped: true,
            workaround: None,
            table: None,
        }
    }

    fn write8_set<I: Io>(io: &mut I, register: u32, bits: u8) -> Result<(), Error> {
        let value = io.read8(register)?;
        Ok(io.write8(register, value | bits)?)
    }

    fn write8_clear<I: Io>(io: &mut I, register: u32, bits: u8) -> Result<(), Error> {
        let value = io.read8(register)?;
        Ok(io.write8(register, value & !bits)?)
    }

    fn write8_bit<I: Io>(io: &mut I, register: u32, bit: u8, set: bool) -> Result<(), Error> {
        if set {
            Self::write8_set(io, register, bit)
        } else {
            Self::write8_clear(io, register, bit)
        }
    }

    /// `check_hw_ready` of the arbiter's window: `ltecoex_read_reg`'s budget.
    fn arbiter_ready<I: Io>(io: &mut I) -> Result<(), Error> {
        for _ in 0..1000 {
            if io.read32(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1)? & LTECOEX_READY != 0 {
                return Ok(());
            }
            io.delay_us(10);
        }
        Err(Error::ArbiterBusy)
    }

    /// `rtw_coex_write_indirect_reg`.
    fn arbiter_write<I: Io>(io: &mut I, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        Self::arbiter_ready(io)?;
        io.write32(
            REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1,
            0x800f_0000 | address,
        )?;
        let old = io.read32(REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1)?;
        let new = (old & !mask) | ((value << mask.trailing_zeros()) & mask);
        Self::arbiter_ready(io)?;
        io.write32(REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1, new)?;
        Ok(io.write32(
            REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1,
            0xc00f_0000 | address,
        )?)
    }

    /// `rtw_coex_set_gnt_bt` and `rtw_coex_set_gnt_wl`.
    fn grants<I: Io>(io: &mut I, bluetooth: u32, wifi: u32) -> Result<(), Error> {
        Self::arbiter_write(io, LTE_COEX_CTRL, 0xc000, bluetooth)?;
        Self::arbiter_write(io, LTE_COEX_CTRL, 0x0c00, bluetooth)?;
        Self::arbiter_write(io, LTE_COEX_CTRL, 0x3000, wifi)?;
        Self::arbiter_write(io, LTE_COEX_CTRL, 0x0300, wifi)
    }

    /// `rtw_coex_coex_ctrl_owner`; `btg_reg` is 8822B's alone.
    fn owner<I: Io>(io: &mut I, wifi: bool) -> Result<(), Error> {
        Self::write8_bit(io, REG_SYS_SDIO_CTRL + 3, MUX_CONTROL_PATH, wifi)
    }

    /// `rtw8822c_coex_cfg_rfe_type`: this side keeps LTE coexistence off.
    fn rfe<I: Io>(io: &mut I) -> Result<(), Error> {
        Self::arbiter_write(io, LTE_COEX_CTRL, LTE_COEX_ENABLE, 0)?;
        Self::arbiter_write(io, LTE_WL_TRX_CTRL, 0xffff, 0xffff)?;
        Self::arbiter_write(io, LTE_BT_TRX_CTRL, 0xffff, 0xffff)
    }

    /// `rtw8822c_coex_cfg_gnt_debug`.
    fn debug_pins<I: Io>(io: &mut I) -> Result<(), Error> {
        Self::write8_clear(io, REG_PAD_CTRL1 + 2, 1 << 4)?;
        Self::write8_clear(io, REG_PAD_CTRL1 + 3, 1 << 0)?;
        Self::write8_clear(io, REG_GPIO_MUXCFG + 2, 1 << 3)?;
        Self::write8_clear(io, REG_PAD_CTRL1 + 1, 1 << 7)?;
        Self::write8_clear(io, REG_SYS_SDIO_CTRL + 3, 1 << 3)
    }

    /// `rtw_coex_set_table`.
    fn tables<I: Io>(&mut self, io: &mut I, table: u32) -> Result<(), Error> {
        if self.table == Some([table; 2]) {
            return Ok(());
        }
        io.write32(REG_BT_COEX_TABLE0, table)?;
        io.write32(REG_BT_COEX_TABLE1, table)?;
        io.write32(REG_BT_COEX_BRK_TABLE, BREAK_TABLE)?;
        self.table = Some([table; 2]);
        Ok(())
    }

    /// `rtw_coex_table` of a shared-antenna case, or the only separate-antenna
    /// case this reaches.
    fn table_case<I: Io>(&mut self, io: &mut I, case: usize) -> Result<(), Error> {
        let table = if self.shared {
            SHARED_TABLES[case]
        } else {
            SEPARATE_TABLE
        };
        self.tables(io, table)
    }

    fn scoreboard<I: Io>(&mut self, io: &mut I, bits: u16, set: bool) -> Result<(), Error> {
        // rtw_coex_write_scbd: bit 1 stays set while this side runs.
        let value = if set {
            (self.score | 2) | bits
        } else {
            (self.score | 2) & !bits
        };
        if value != self.score {
            self.score = value;
            io.write16(REG_WIFI_BT_INFO, value | BT_INTERRUPT_ENABLE)?;
        }
        Ok(())
    }

    /// `rtw_coex_set_wl_pri_mask`.
    fn priority<I: Io>(io: &mut I, bit: u8, set: bool) -> Result<(), Error> {
        Self::write8_bit(
            io,
            REG_BT_COEX_TABLE_H + u32::from(bit / 8),
            1 << (bit % 8),
            set,
        )
    }

    /// `rtw_coex_power_on_setting`, the path going to Bluetooth.
    pub fn power_on<I: Io>(&mut self, io: &mut I) -> Result<(), Error> {
        self.stopped = true;
        Self::write8_set(io, REG_SYS_FUNC_EN, BASEBAND_ENABLE)?;
        let bluetooth_off = io.read16(REG_WIFI_BT_INFO)? & SCORE_ON == 0;
        Self::rfe(io)?;
        Self::owner(io, bluetooth_off)?;
        self.table = None;
        self.table_case(io, 1)?;
        // The "red x" workaround.
        io.write8(0xff1a, 0)?;
        Self::debug_pins(io)
    }

    /// `rtw8822c_coex_cfg_init`.
    fn hardware<I: Io>(io: &mut I, report: &Report) -> Result<(), Error> {
        Self::write8_set(io, REG_BCN_CTRL, BCN_FUNCTION_ENABLE)?;
        let time = io.read8(REG_BT_TDMA_TIME)?;
        io.write8(REG_BT_TDMA_TIME, (time & !0x3f) | 5)?;
        io.write8(REG_BT_STAT_CTRL, 1)?;
        let pins = io.read32(REG_GPIO_MUXCFG)?;
        io.write32(REG_GPIO_MUXCFG, pins | PTA_PINS)?;
        Self::write8_set(io, REG_QUEUE_CTRL, PTA_WL_TX_ENABLE)?;
        Self::write8_clear(io, REG_QUEUE_CTRL, PTA_EDCCA_ENABLE)?;
        let polarity = io.read16(REG_BT_COEX_V2)?;
        io.write16(REG_BT_COEX_V2, polarity | GNT_BT_POLARITY)?;
        Self::write8_clear(io, REG_DUMMY_PAGE4_V1, BTCCA_CONTROL)?;
        // SAFETY: `init`'s caller holds this epoch's report and quiet RF.
        let mut rf = unsafe { Registers::new(io, report) }?;
        Ok(rf.write(Path::B, RF_MODOPT, RF_MASK, RF_MODOPT_DEFAULT)?)
    }

    /// `__rtw_coex_init_hw_config`: a chip alone takes the antennas; one with a
    /// Bluetooth half starts with them on Bluetooth's schedule.
    ///
    /// # Safety
    /// As [`Self::power_on`], with firmware running.
    pub unsafe fn init<I: Io>(&mut self, io: &mut I, report: &Report) -> Result<Run, Error> {
        self.version = io.read8(0xf1)? >> 4;
        let bluetooth_off = io.read16(REG_WIFI_BT_INFO)? & SCORE_ON == 0;
        let mut run = Run::default();
        run.commands.push((
            COMMAND_BT_WIFI_CONTROL | (LEAK_AP << 8) | (DISABLE_5MS << 16),
            0,
        ));
        Self::write8_set(io, REG_BCN_CTRL, BCN_FUNCTION_ENABLE)?;
        Self::rfe(io)?;
        Self::hardware(io, report)?;
        Self::priority(io, PRIORITY_TX_RESPONSE, true)?;
        Self::priority(io, PRIORITY_TX_BEACON, true)?;
        Self::priority(io, PRIORITY_TX_BEACON_QUEUE, true)?;
        if self.combined && !bluetooth_off {
            Self::grants(io, GRANT_HIGH, GRANT_LOW)?;
        } else {
            Self::grants(io, GRANT_LOW, GRANT_HIGH)?;
        }
        Self::owner(io, true)?;
        self.stopped = !self.combined;
        self.scoreboard(io, SCORE_ACTIVE | SCORE_ON, true)?;
        self.table = None;
        self.table_case(io, 1)?;
        run.commands.push(Self::tdma_off());
        run.commands.push((COMMAND_QUERY_BT | (1 << 8), 0));
        Ok(run)
    }

    /// `rtw_fw_coex_tdma_type` of a case that schedules nothing.
    fn tdma_off() -> (u32, u32) {
        (COMMAND_TDMA, 0)
    }

    /// `rtw8822c_coex_cfg_gnt_fix` for `mode`.
    fn gnt_fix<I: Io>(&mut self, io: &mut I, report: &Report, mode: Mode) -> Result<(), Error> {
        if self.workaround == Some(mode) {
            return Ok(());
        }
        self.workaround = Some(mode);
        let five_ghz = mode == Mode::FiveGhz;
        let mut rf_1 = if self.version == 0 && five_ghz {
            0x40021
        } else {
            0x40000
        };
        if self.shared {
            rf_1 |= 1 << 13;
        }
        {
            // SAFETY: `run`'s caller holds this epoch's report and quiet RF.
            let mut rf = unsafe { Registers::new(io, report) }?;
            rf.write(Path::B, RF_MODOPT, RF_MASK, rf_1)?;
        }
        Self::write8_set(io, REG_ANAPAR + 2, ANAPAR_BTPS)?;
        Self::write8_clear(io, REG_RSTB_SEL + 1, DAC_OFF_ENABLE)?;
        Self::write8_set(io, REG_RSTB_SEL + 3, DAC_OFF_ENABLE)?;
        Self::write8_set(io, REG_IGN_GNTBT4, IGNORE_GNT_BT)?;
        if five_ghz || !self.shared {
            if self.version >= 3 {
                Self::write8_clear(io, REG_IGN_GNT_BT1, IGNORE_GNT_BT)?;
                Self::write8_set(io, REG_NOMASK_TXBT, NOMASK_TXBT)
            } else {
                Self::write8_set(io, REG_IGN_GNT_BT1, IGNORE_GNT_BT)
            }
        } else {
            Self::write8_clear(io, REG_IGN_GNT_BT1, IGNORE_GNT_BT)?;
            if self.version >= 3 {
                Self::write8_clear(io, REG_NOMASK_TXBT, NOMASK_TXBT)?;
            }
            Ok(())
        }
    }

    /// `rtw_coex_run_coex` for `link`, and the antenna path and scoreboard its
    /// notifiers set first. Nothing runs on a chip alone (`coex->stop_dm`).
    ///
    /// # Safety
    /// As [`Self::init`], with the radio's frames quiet.
    pub unsafe fn run<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        link: Link,
    ) -> Result<Run, Error> {
        let mut run = Run::default();
        if self.stopped {
            return Ok(run);
        }
        let bluetooth_off = io.read16(REG_WIFI_BT_INFO)? & SCORE_ON == 0;
        self.scoreboard(io, SCORE_ACTIVE | SCORE_ON, true)?;
        Self::owner(io, true)?;
        Self::priority(io, PRIORITY_RX_CCK, link.connected && !link.five_ghz)?;
        let mode = if link.five_ghz {
            // COEX_SET_ANT_5G, then rtw_coex_action_wl_under5g.
            Self::grants(io, GRANT_PTA, GRANT_HIGH)?;
            self.scoreboard(io, SCORE_FIX_2M, false)?;
            self.table_case(io, 0)?;
            Mode::FiveGhz
        } else {
            // COEX_SET_ANT_2G, then rtw_coex_action_wl_only or
            // rtw_coex_action_wl_not_connected.
            Self::grants(io, GRANT_PTA, GRANT_PTA)?;
            self.table_case(io, if link.connected { 2 } else { 1 })?;
            run.bluetooth_unscheduled = !bluetooth_off;
            Mode::TwoGhz
        };
        self.scoreboard(io, SCORE_TDMA, false)?;
        run.commands.push(Self::tdma_off());
        self.gnt_fix(io, report, mode)?;
        Ok(run)
    }

    /// `rtw_coex_power_off_setting`.
    pub fn power_off<I: Io>(&mut self, io: &mut I) -> Result<(), Error> {
        self.scoreboard(io, SCORE_ALL, false)?;
        io.write16(REG_WIFI_BT_INFO, BT_INTERRUPT_ENABLE)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::realtek::identity::{Profile, tests::profile};
    use alloc::collections::BTreeMap;

    /// Registers as bytes, and the arbiter's indirect window behind them.
    #[derive(Default)]
    struct Bus {
        bytes: BTreeMap<u32, u8>,
        arbiter: BTreeMap<u32, u32>,
    }

    impl Bus {
        fn get(&self, register: u32) -> u8 {
            self.bytes.get(&register).copied().unwrap_or(0)
        }
        fn word(&self, register: u32) -> u32 {
            u32::from_le_bytes([0, 1, 2, 3].map(|at| self.get(register + at)))
        }
    }

    // SAFETY: nothing here reaches hardware; this is a map of bytes.
    unsafe impl Io for Bus {
        fn profile(&self) -> Profile {
            profile()
        }
        fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
            Ok(self.get(register))
        }
        fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
            Ok(self.get(register) as u16 | (self.get(register + 1) as u16) << 8)
        }
        fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
            Ok(match register {
                REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1 => LTECOEX_READY,
                _ => self.word(register),
            })
        }
        fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
            self.bytes.insert(register, value);
            Ok(())
        }
        fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
            for (at, byte) in value.to_le_bytes().into_iter().enumerate() {
                self.bytes.insert(register + at as u32, byte);
            }
            Ok(())
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
            if register == REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1 {
                let address = value & 0xffff;
                if value >> 28 == 0x8 {
                    let held = self.arbiter.get(&address).copied().unwrap_or(0);
                    let read = REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1;
                    for (at, byte) in held.to_le_bytes().into_iter().enumerate() {
                        self.bytes.insert(read + at as u32, byte);
                    }
                } else {
                    let data = self.word(REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1);
                    self.arbiter.insert(address, data);
                }
                return Ok(());
            }
            for (at, byte) in value.to_le_bytes().into_iter().enumerate() {
                self.bytes.insert(register + at as u32, byte);
            }
            Ok(())
        }
        fn delay_us(&mut self, _: u64) {}
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            panic!("no beacon")
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            panic!("no beacon")
        }
        fn quarantine(&mut self) {}
    }

    #[test]
    fn a_boards_bytes_name_its_bluetooth_half_and_antennas() {
        let coex = Coex::of(0x20, 1);
        assert!(coex.combined && coex.shared);
        let coex = Coex::of(0xff, 0xfe);
        assert!(!coex.combined && !coex.shared);
    }

    #[test]
    fn power_on_hands_a_live_bluetooth_the_path_and_keeps_lte_coexistence_off() {
        let mut bus = Bus::default();
        bus.arbiter.insert(LTE_COEX_CTRL, LTE_COEX_ENABLE | 0x55);
        bus.write16(REG_WIFI_BT_INFO, SCORE_ON).unwrap();
        bus.write8(REG_SYS_SDIO_CTRL + 3, MUX_CONTROL_PATH).unwrap();
        let mut coex = Coex::of(0x20, 1);
        coex.power_on(&mut bus).unwrap();
        assert_eq!(bus.get(REG_SYS_FUNC_EN) & 3, 3);
        assert_eq!(bus.arbiter[&LTE_COEX_CTRL], 0x55);
        assert_eq!(bus.arbiter[&LTE_WL_TRX_CTRL], 0xffff);
        assert_eq!(bus.get(REG_SYS_SDIO_CTRL + 3) & MUX_CONTROL_PATH, 0);
        assert_eq!(bus.word(REG_BT_COEX_TABLE0), 0x5555_5555);
        assert_eq!(bus.word(REG_BT_COEX_BRK_TABLE), BREAK_TABLE);
    }

    #[test]
    fn a_separate_antenna_board_has_one_table_and_grants_fill_each_field() {
        let mut bus = Bus::default();
        let mut coex = Coex::of(0x20, 0);
        coex.table_case(&mut bus, 1).unwrap();
        assert_eq!(bus.word(REG_BT_COEX_TABLE1), SEPARATE_TABLE);
        Coex::grants(&mut bus, GRANT_LOW, GRANT_HIGH).unwrap();
        // GNT_BT low (0x1) over both of its fields, GNT_WL high (0x3) over its.
        assert_eq!(bus.arbiter[&LTE_COEX_CTRL], 0x7700);
    }

    #[test]
    fn the_scoreboard_and_priorities_land_on_their_bits() {
        let mut bus = Bus::default();
        let mut coex = Coex::of(0x20, 0);
        coex.scoreboard(&mut bus, SCORE_ACTIVE | SCORE_ON, true)
            .unwrap();
        assert_eq!(bus.word(REG_WIFI_BT_INFO) as u16, 3 | BT_INTERRUPT_ENABLE);
        Coex::priority(&mut bus, PRIORITY_TX_BEACON_QUEUE, true).unwrap();
        assert_eq!(bus.get(REG_BT_COEX_TABLE_H + 3), 1 << 3);
        Coex::priority(&mut bus, PRIORITY_RX_CCK, true).unwrap();
        Coex::priority(&mut bus, PRIORITY_TX_BEACON_QUEUE, false).unwrap();
        assert_eq!(bus.get(REG_BT_COEX_TABLE_H + 3), 1 << 4);
    }
}
