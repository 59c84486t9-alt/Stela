// SPDX-License-Identifier: GPL-2.0-only
//! Actual Renoir BAR offsets from rn_chip_offset_byte.h/rn_acp3x.h at the pin.
//! Copyright (C) 2020 Advanced Micro Devices, Inc.
#[cfg(test)]
pub(super) use super::super::acp_pdm::registers::DMA_ENABLE;
pub(super) use super::super::acp_pdm::registers::ERROR_IRQ;
pub(super) const POWER_CONTROL: usize = 0x141c;
pub(super) const POWER_STATUS: usize = 0x1420;
pub(super) const CLOCK: usize = 0x1424;
pub(super) const IRQ_ENABLE: usize = 0x1800;
pub(super) const IRQ_CONTROL: usize = 0x1804;
pub(super) const IRQ_STATUS: usize = 0x1808;
pub(super) const SRAM_TABLE: u32 = 0x0205_0000;
