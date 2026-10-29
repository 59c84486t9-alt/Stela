// SPDX-License-Identifier: GPL-2.0-only
//! ACP6x register facts adapted from AMD's Linux acp6x_chip_offset_byte.h and
//! acp6x.h at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (C) 2021 Advanced Micro Devices, Inc. All rights reserved.
#[cfg(test)]
pub(super) use super::super::acp_pdm::registers::DMA_ENABLE;
pub(super) const POWER_CONTROL: usize = 0x1024;
pub(super) const POWER_STATUS: usize = 0x1028;
pub(super) const CLOCK: usize = 0x102c;
pub(super) const PIN_CONFIG: usize = 0x1440;
pub(super) const IRQ_ENABLE: usize = 0x1a00;
pub(super) const IRQ_CONTROL: usize = 0x1a04;
pub(super) const IRQ_STATUS: usize = 0x1a0c;
pub(super) const SRAM_TABLE: u32 = 0x0380_0000;
