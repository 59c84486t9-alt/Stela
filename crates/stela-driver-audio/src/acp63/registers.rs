// SPDX-License-Identifier: GPL-2.0-only
//! ACP63 dedicated direct-PDM facts from pinned ps/acp63.h and acp63_chip_offset_byte.h.
//! Copyright (C) 2022, 2023, 2025 Advanced Micro Devices, Inc.
#[cfg(test)]
pub(crate) use super::super::acp_pdm::registers::DMA_ENABLE;
pub(crate) use super::super::acp_pdm::registers::ERROR_IRQ;
pub(crate) const POWER_CONTROL: usize = 0x1024;
pub(crate) const POWER_STATUS: usize = 0x1028;
pub(crate) const ZSC_CONTROL: usize = 0x1014;
pub(crate) const PIN_CONFIG: usize = 0x1440;
pub(crate) const IRQ_ENABLE: usize = 0x1a00;
pub(crate) const IRQ_CONTROL: usize = 0x1a04;
pub(crate) const IRQ_STATUS: usize = 0x1a0c;
pub(crate) const SRAM_TABLE: u32 = 0x0380_0000;
