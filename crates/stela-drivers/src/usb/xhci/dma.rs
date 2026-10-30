// SPDX-License-Identifier: GPL-2.0-only
// DMA aperture and segment padding follow pinned Linux xhci-pci.c,
// xhci.c and xhci-mem.c. Copyright (C) 2008 Intel Corp., Sarah Sharp.
//! Immutable controller constraints, checked before publishing pointers:
//! DMA aperture and ring overfetch, and Intel's reset settle time.
use super::*;

const INTEL: u16 = 0x8086;
/// Linux `xhci_reset`: Intel controllers need 1 ms after HCRST before any
/// register access (`XHCI_INTEL_HOST`).
const INTEL_RESET_SETTLE_US: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    bits: u8,
    overfetch: bool,
    intel: bool,
}

impl Profile {
    pub const SPEC: Self = Self {
        bits: 64,
        overfetch: false,
        intel: false,
    };

    pub fn pci(vendor: u16, device: u16) -> Self {
        let profile = match (vendor, device) {
            (0x1b21, 0x1142 | 0x1242 | 0x2142 | 0x3242) => Self {
                bits: 32,
                ..Self::SPEC
            },
            (0x1106, 0x3483) => Self {
                bits: 36,
                overfetch: true,
                ..Self::SPEC
            },
            (0x1d17, 0x9202 | 0x9203) => Self {
                overfetch: true,
                ..Self::SPEC
            },
            _ => Self::SPEC,
        };
        Self {
            intel: vendor == INTEL,
            ..profile
        }
    }

    /// How long to wait after setting HCRST before touching a register.
    pub fn reset_settle_us(self) -> u64 {
        match self.intel {
            true => INTEL_RESET_SETTLE_US,
            false => 0,
        }
    }

    pub fn capabilities(self, ac64: bool) -> Self {
        Self {
            bits: self.bits.min(if ac64 { 64 } else { 32 }),
            ..self
        }
    }

    pub fn segment_bytes(self) -> usize {
        RING_TRBS * TRB * if self.overfetch { 2 } else { 1 }
    }

    pub(super) fn maximum(self) -> u64 {
        if self.bits == 64 {
            u64::MAX
        } else {
            (1u64 << self.bits) - 1
        }
    }

    pub fn check(self, address: u64, bytes: usize) -> Result<(), BlockError> {
        let last = address.checked_add(bytes.saturating_sub(1) as u64);
        let maximum = if self.bits == 64 {
            u64::MAX
        } else {
            (1u64 << self.bits) - 1
        };
        if last.is_none_or(|last| last > maximum) {
            Err(BlockError::Unsupported(
                "xHCI DMA range outside controller aperture",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn allocate_memory(
        self,
        dma: &mut dyn DmaAllocator,
        bytes: usize,
        align: usize,
        native: Option<&Rc<memory::Native>>,
    ) -> Result<memory::Buffer, BlockError> {
        let buffer = if let Some(native) = native {
            native.allocate(bytes, align, self.maximum())?
        } else {
            dma.allocate(bytes, align)?.into()
        };
        if buffer.len() < bytes || !buffer.device_address().is_multiple_of(align as u64) {
            return Err(BlockError::Unsupported("invalid xHCI DMA allocation"));
        }
        self.check(buffer.device_address(), bytes)?;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests;
