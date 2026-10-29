// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2007 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Exact copper PHY initialization branches from the pinned Linux igb PHY code.
use super::{Chip, RegisterIo, Timer, hardware::Hardware, registers::*};
use crate::block::BlockError;

impl<R: RegisterIo, T: Timer> Hardware<'_, R, T> {
    fn mdic(&self, register: u16, data: Option<u16>) -> Result<u16, BlockError> {
        let command = MDIC_PHY
            | (u32::from(register & 31) << 16)
            | data.map_or(MDIC_READ, |data| MDIC_WRITE | u32::from(data));
        self.io.write(MDIC, command);
        if !self
            .clock
            .wait(50_000, || self.io.read(MDIC) & MDIC_READY != 0)
        {
            return Err(BlockError::Timeout);
        }
        let value = self.io.read(MDIC);
        if value & MDIC_ERROR != 0 || value & MDIC_REGISTER_MASK != command & MDIC_REGISTER_MASK {
            return Err(BlockError::Device { status: value });
        }
        Ok(value as u16)
    }

    pub(super) fn read_phy(&mut self, register: u16) -> Result<u16, BlockError> {
        let mask = self.phy_mask();
        self.synchronized(mask, |hardware| {
            if register > 31 {
                if !hardware.chip.old_reset() {
                    return Err(BlockError::Unsupported(
                        "igb PHY register needs an unimplemented page path",
                    ));
                }
                hardware.mdic(PHY_PAGE_IGP, Some(register))?;
            }
            hardware.mdic(register & 31, None)
        })
    }

    pub(super) fn write_phy(&mut self, register: u16, value: u16) -> Result<(), BlockError> {
        let mask = self.phy_mask();
        self.synchronized(mask, |hardware| {
            if register > 31 {
                if !hardware.chip.old_reset() {
                    return Err(BlockError::Unsupported(
                        "igb PHY register needs an unimplemented page path",
                    ));
                }
                hardware.mdic(PHY_PAGE_IGP, Some(register))?;
            }
            hardware.mdic(register & 31, Some(value)).map(|_| ())
        })
    }

    fn hardware_reset_phy(&mut self) -> Result<(), BlockError> {
        if self.io.read(MANC) & MANC_BLOCK_PHY != 0 {
            return Err(BlockError::Unsupported("igb firmware blocks PHY reset"));
        }
        self.synchronized(self.phy_mask(), |hardware| {
            let control = hardware.io.read(CTRL);
            hardware.io.write(CTRL, control | CTRL_PHY_RST);
            hardware.io.read(STATUS);
            hardware.clock.delay(100);
            hardware.io.write(CTRL, control);
            hardware.io.read(STATUS);
            hardware.clock.delay(150);
            Ok(())
        })?;
        self.phy_configuration();
        Ok(())
    }

    fn software_reset_phy(&mut self) -> Result<(), BlockError> {
        let control = self.read_phy(PHY_CONTROL)?;
        self.write_phy(PHY_CONTROL, control | PHY_RESET)?;
        let clock = self.clock;
        let mut last = Ok(0);
        if !clock.wait(500_000, || {
            last = self.read_phy(PHY_CONTROL);
            match &last {
                Ok(value) => value & PHY_RESET == 0,
                Err(_) => true,
            }
        }) {
            return Err(BlockError::Timeout);
        }
        last.map(|_| ())
    }

    pub(super) fn configure_phy(&mut self) -> Result<(), BlockError> {
        if self.io.read(MANC) & MANC_BLOCK_PHY != 0 {
            return Err(BlockError::Unsupported("igb firmware blocks PHY reset"));
        }
        if !self.chip.old_reset() && self.io.read(MDICNFG) & (1 << 31) != 0 {
            return Err(BlockError::Unsupported(
                "igb external MDIO PHY is not implemented",
            ));
        }
        let high = self.read_phy(PHY_ID1)?;
        self.clock.delay(20);
        let low = self.read_phy(PHY_ID2)?;
        let id = (u32::from(high) << 16 | u32::from(low)) & !15;
        let revision = low & 15;
        let supported = match self.chip {
            Chip::I82575 | Chip::I82576 => matches!(id, PHY_IGP3 | PHY_M88 | PHY_I347),
            Chip::I82580 => id == PHY_82580,
            Chip::I350 => id == PHY_I350,
            Chip::I210 | Chip::I211 => id == PHY_I210,
        };
        if !supported {
            return Err(BlockError::Unsupported(
                "igb controller has an unsupported copper PHY",
            ));
        }
        let control = self.io.read(CTRL);
        self.io
            .write(CTRL, (control | CTRL_SLU) & !(CTRL_FRCSPD | CTRL_FRCDPX));
        let control = self.read_phy(PHY_CONTROL)?;
        self.write_phy(
            PHY_CONTROL,
            control & !(PHY_POWERDOWN | PHY_ISOLATE | PHY_LOOPBACK),
        )?;
        match id {
            PHY_IGP3 => {
                self.hardware_reset_phy()?;
                self.clock.delay(100_000);
                self.write_phy(PHY_PAGE_IGP, 0)?;
                let power = self.read_phy(25)?;
                self.write_phy(25, power & !2)?; // D0 LPLU off; preserve SmartSpeed policy
                let port = self.read_phy(18)?;
                self.write_phy(18, port | 0x1000)?; // automatic MDI/MDI-X
            }
            PHY_M88 => {
                let specific = self.read_phy(PHY_SPECIFIC)?;
                self.write_phy(PHY_SPECIFIC, (specific | (1 << 11) | 0x60) & !2)?;
                if revision < 4 {
                    let extended = self.read_phy(20)? | 0x70;
                    let extended = if revision == 2 {
                        (extended & !0x0e00) | 0x0800
                    } else {
                        (extended & !0x0f00) | 0x0100
                    };
                    self.write_phy(20, extended)?;
                }
                self.software_reset_phy()?;
            }
            PHY_I347 | PHY_I210 => {
                self.write_phy(PHY_PAGE_M88, 0)?;
                let specific = self.read_phy(PHY_SPECIFIC)?;
                let specific = (specific & !(0x7000 | 2)) | 0x5000 | 0x0800 | 0x60;
                self.write_phy(PHY_SPECIFIC, specific)?;
                self.software_reset_phy()?;
            }
            PHY_82580 | PHY_I350 => {
                self.hardware_reset_phy()?;
                let config = self.read_phy(22)?;
                self.write_phy(22, config | (1 << 15) | (3 << 10))?;
                let control2 = self.read_phy(18)?;
                self.write_phy(18, (control2 & !0x0600) | 0x0400)?;
            }
            _ => unreachable!(),
        }
        if !self.chip.old_reset() {
            self.io.write(
                PHPM,
                self.io.read(PHPM) & !(PHPM_LPLU | PHPM_LINK_DISCONNECT),
            );
        }
        self.write_phy(PHY_ADVERTISE, 0x01e1)?; // 10/100 half/full, no pause
        let gigabit = self.read_phy(PHY_GIGABIT)?;
        self.write_phy(PHY_GIGABIT, (gigabit & !0x1f00) | 0x0200)?; // 1000 full, automatic master/slave
        let control = self.read_phy(PHY_CONTROL)?;
        self.write_phy(
            PHY_CONTROL,
            (control & !(PHY_RESET | PHY_POWERDOWN | PHY_ISOLATE | PHY_LOOPBACK))
                | PHY_AUTONEG
                | PHY_RESTART,
        )
    }
}
