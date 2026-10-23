// SPDX-License-Identifier: GPL-2.0-only
//! ACP63 dedicated direct-PDM facts from pinned ps/acp63.h and acp63_chip_offset_byte.h.
//! Copyright (C) 2022, 2023, 2025 Advanced Micro Devices, Inc.
#[cfg(test)]
pub(in crate::audio) use super::super::acp_pdm::registers::DMA_ENABLE;
pub(in crate::audio) use super::super::acp_pdm::registers::ERROR_IRQ;
pub(in crate::audio) const POWER_CONTROL: usize = 0x1024;
pub(in crate::audio) const POWER_STATUS: usize = 0x1028;
pub(in crate::audio) const ZSC_CONTROL: usize = 0x1014;
pub(in crate::audio) const PIN_CONFIG: usize = 0x1440;
pub(in crate::audio) const IRQ_ENABLE: usize = 0x1a00;
pub(in crate::audio) const IRQ_CONTROL: usize = 0x1a04;
pub(in crate::audio) const IRQ_STATUS: usize = 0x1a0c;
pub(in crate::audio) const SRAM_TABLE: u32 = 0x0380_0000;
