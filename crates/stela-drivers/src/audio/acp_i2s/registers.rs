// SPDX-License-Identifier: GPL-2.0-only
//! BAR-relative Raven/Vangogh facts from pinned AMD Linux raven/ and vangogh/.
//! Copyright (C) 2016, 2021, 2023 Advanced Micro Devices, Inc.
use super::{Generation, Port};
pub(super) const PAGE_BYTES: usize = 4096;
pub(super) const REGION_BYTES: usize = 0x10400;
pub(super) const PAGE_SIZE: usize = 0xc00;
pub(super) const PAGE_BASE: usize = 0xc04;
pub(super) const ATU_CONTROL: usize = 0xc40;
pub(super) const RESET: usize = 0x1000;
pub(super) const CONTROL: usize = 0x1004;
pub(super) const PIN_CONFIG: usize = 0x1400;
pub(super) const CLOCK: usize = 0x142c;
pub(super) const SPEAKER_MASTER: usize = 0x2414;
pub(super) const AUXILIARY_MASTER: usize = 0x241c;
pub(super) const IRQ_ENABLE: usize = 0x1800;
pub(super) const IRQ_CONTROL: usize = 0x1804;
pub(super) const IRQ_STATUS: usize = 0x1808;
pub(super) const SCRATCH: usize = 0x10000;
pub(super) const SRAM: u32 = 0x0205_0000;
pub(super) const PTE_VALID: u32 = 1 << 31;
pub(super) const RESET_ACK: u32 = 0x0001_0001;
pub(super) const SAMPLE_MASK: u32 = 0x38;
pub(super) const STREAM_ENABLE: u32 = 1;
pub(super) const TDM_ENABLE: u32 = 2;
pub(super) const FRAME_LENGTH: u32 = 0x100;
pub(super) const FIFO_SIZE: u32 = 0x100;
pub(super) const DMA_SIZE: u32 = 0x40;
pub(super) const ERROR_IRQ: u32 = 1 << 29;
pub(super) const POWER_MASK: u32 = 3;
pub(super) const POWER_ON: u32 = 1;
pub(super) const CLOCK_ON: u32 = 3;
pub(super) const PERIOD_MIN: usize = 1024;
pub(super) const PERIOD_MAX: usize = 8192;
pub(super) const BUFFER_MAX: usize = 65536;
pub(super) const PTE_SLOTS: usize = 32;
pub(super) const POWER_TIMEOUT_US: u64 = 500;
pub(super) const STREAM_TIMEOUT_US: u64 = 100_000;

#[derive(Clone, Copy)]
pub(super) struct StreamRegisters {
    pub(super) ring: usize,
    pub(super) enable: usize,
    pub(super) frame: usize,
    pub(super) ier: usize,
    pub(super) irq: u32,
    pub(super) pte: usize,
    pub(super) window: u32,
    pub(super) fifo: u32,
}
impl StreamRegisters {
    pub(super) fn size(self) -> usize {
        self.ring + 4
    }
    pub(super) fn fifo_address(self) -> usize {
        self.ring + 12
    }
    pub(super) fn fifo_size(self) -> usize {
        self.ring + 16
    }
    pub(super) fn dma_size(self) -> usize {
        self.ring + 20
    }
    pub(super) fn count_high(self) -> usize {
        self.ring + 24
    }
    pub(super) fn count_low(self) -> usize {
        self.ring + 28
    }
    pub(super) fn watermark(self) -> usize {
        self.ring + 32
    }
}
impl Generation {
    pub(super) fn power_control(self) -> usize {
        match self {
            Self::Raven => 0x141c,
            Self::Vangogh => 0x1424,
        }
    }
    pub(super) fn power_status(self) -> usize {
        match self {
            Self::Raven => 0x1420,
            Self::Vangogh => 0x1428,
        }
    }
    pub(super) fn pme(self) -> usize {
        match self {
            Self::Raven => 0x1418,
            Self::Vangogh => 0x1420,
        }
    }
    pub(super) fn pin_mode(self) -> u32 {
        match self {
            Self::Raven => 4,
            Self::Vangogh => 0,
        }
    }
    pub(super) fn stream(self, port: Port) -> StreamRegisters {
        let slot = port as usize;
        let auxiliary = slot >= 2;
        let tx = slot.is_multiple_of(2);
        let (ring, ier, irq) = if auxiliary {
            match self {
                Self::Raven => (
                    if tx { 0x206c } else { 0x2048 },
                    0x2800,
                    if tx { 26 } else { 25 },
                ),
                Self::Vangogh => (
                    if tx { 0x20b4 } else { 0x2090 },
                    0x2814,
                    if tx { 24 } else { 23 },
                ),
            }
        } else {
            (
                if tx { 0x2024 } else { 0x2000 },
                0x2400,
                if tx { 28 } else { 27 },
            )
        };
        StreamRegisters {
            ring,
            ier,
            irq: 1 << irq,
            enable: ier + if tx { 12 } else { 4 },
            frame: ier + if tx { 16 } else { 8 },
            pte: slot * 0x100,
            window: 0x0400_0000 + slot as u32 * 0x20000,
            fifo: SRAM + 0x500 + slot as u32 * 0x200,
        }
    }
    pub(super) fn irq_mask(self) -> u32 {
        self.stream(Port::SpeakerPlayback).irq
            | self.stream(Port::SpeakerCapture).irq
            | self.stream(Port::AuxiliaryPlayback).irq
            | self.stream(Port::AuxiliaryCapture).irq
    }
}
