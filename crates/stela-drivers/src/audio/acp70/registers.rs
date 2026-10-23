// SPDX-License-Identifier: GPL-2.0-only
//! Dedicated ACP70/71/72 register facts from pinned ps/ and acp63_chip_offset_byte.h.
//! Copyright (C) 2022, 2023, 2025 Advanced Micro Devices, Inc.
pub(super) use super::super::acp63::registers::{
    ERROR_IRQ, IRQ_CONTROL, IRQ_ENABLE, IRQ_STATUS, PIN_CONFIG, POWER_CONTROL, POWER_STATUS,
    SRAM_TABLE, ZSC_CONTROL,
};
pub(super) const POWER_ON_REQUEST: u32 = 0x1f;
pub(super) const POWER_STATUS_MASK: u32 = 0xff;
pub(super) const PME_ENABLE: usize = 0x1400;
// The source's wake-enabled path needs the real SoundWire owner. Neither
// a low stream count nor a masked interrupt proves that manager is idle.
pub(super) const SOUNDWIRE_EXCLUSION: [usize; 6] = [0x3000, 0x3004, 0x3c00, 0x3c04, 0x1458, 0x1460];
