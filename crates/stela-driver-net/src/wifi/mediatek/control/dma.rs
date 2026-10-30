// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2023 MediaTek Inc.
//! Polling WFDMA enablement from mt792x_dma.c. Installation of every queue,
//! its exact descriptor format and coherent DMA ownership precede this.
use super::{
    BUSY, BarIo, Control, DISABLE, Error, MT_MCU2HOST_SW_INT_ENA, MT_PCIE_MAC_INT_ENABLE,
    MT_UWFDMA0_GLO_CFG_EXT1, MT_WFDMA_DUMMY_CR, MT_WFDMA_NEED_REINIT, MT_WFDMA0_GLO_CFG,
    MT_WFDMA0_HOST_INT_ENA, MT_WFDMA0_INT_RX_PRI, MT_WFDMA0_INT_TX_PRI, MT_WFDMA0_PRI_DLY_INT_CFG0,
    MT_WFDMA0_RST_DRX_PTR, MT_WFDMA0_RST_DTX_PTR, MT_WFDMA0_RX_RING0_EXT_CTRL,
    MT_WFDMA0_TX_RING0_EXT_CTRL,
};
use crate::wifi::mediatek::identity::Chip;

const CONFIG: u32 = (1 << 6)
    | (1 << 12)
    | (1 << 30)
    | (1 << 28)
    | (3 << 4)
    | (1 << 11)
    | (1 << 13)
    | (1 << 15)
    | (1 << 21);
const ENABLE: u32 = 1 | (1 << 2);
const IRQ_MASKS: [u32; 3] = [
    MT_WFDMA0_HOST_INT_ENA,
    MT_PCIE_MAC_INT_ENABLE,
    MT_MCU2HOST_SW_INT_ENA,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaEnabled {
    pub global_config: u32,
    pub polling_interrupts_masked: bool,
}
impl<I: BarIo> Control<I> {
    /// Disable host WFDMA, PCIe MAC and MCU software interrupt enables.
    /// Readback confirms device mask state; it never proves pending IRQ/CPU
    /// callbacks drained or reserves a platform interrupt route/vector.
    pub fn mask_interrupts(&mut self) -> Result<(), Error> {
        self.guard(true)?;
        let result = (|| {
            for address in IRQ_MASKS {
                self.registers.write32(address, 0)?;
            }
            self.verify_masks()
        })();
        self.finish(result)
    }
    fn verify_masks(&mut self) -> Result<(), Error> {
        for address in IRQ_MASKS {
            let actual = self.read_control(address)?;
            if actual != 0 {
                return Err(Error::Readback {
                    address,
                    mask: u32::MAX,
                    expected: 0,
                    actual,
                });
            }
        }
        Ok(())
    }
    fn prefetch(&mut self) -> Result<(), Error> {
        // Exact normal MT7925 versus MT7921/22 mt792x_dma_prefetch settings.
        if self.registers.chip() == Chip::Mt7925 {
            for (queue, base) in [(0, 0x0000), (1, 0x0040), (2, 0x0080), (3, 0x00c0)] {
                self.registers
                    .write32(MT_WFDMA0_RX_RING0_EXT_CTRL + 4 * queue, base << 16 | 4)?;
            }
            for (queue, base, depth) in [
                (0, 0x0100, 0x10),
                (1, 0x0200, 0x10),
                (2, 0x0300, 0x10),
                (3, 0x0400, 0x10),
                (15, 0x0500, 4),
                (16, 0x0540, 4),
            ] {
                self.registers
                    .write32(MT_WFDMA0_TX_RING0_EXT_CTRL + 4 * queue, base << 16 | depth)?;
            }
        } else {
            for (queue, base) in [(0, 0), (2, 0x40), (3, 0x80), (4, 0xc0), (5, 0x100)] {
                self.registers
                    .write32(MT_WFDMA0_RX_RING0_EXT_CTRL + 4 * queue, base << 16 | 4)?;
            }
            for (queue, base) in [
                (0, 0x140),
                (1, 0x180),
                (2, 0x1c0),
                (3, 0x200),
                (4, 0x240),
                (5, 0x280),
                (6, 0x2c0),
                (16, 0x340),
                (17, 0x380),
            ] {
                self.registers
                    .write32(MT_WFDMA0_TX_RING0_EXT_CTRL + 4 * queue, base << 16 | 4)?;
            }
        }
        Ok(())
    }
    /// Enable the donor's ordinary WFDMA descriptor mode with IRQs masked for
    /// native polling. Success observes configuration, not completed device DMA.
    ///
    /// # Safety
    /// Every queue the chip/firmware can select (including ordinary data TX/RX,
    /// TX-free and event queues, not only the three boot mailbox queues) is
    /// installed or demonstrably disabled under this chip's hardware
    /// contract. Its current descriptors/buffers have the exact donor format,
    /// valid kept canonical pins and IOMMU mappings for this requester,
    /// sufficient complete sizes and synchronized visibility. Descriptor index
    /// resets below must not discard live DMA/software ownership. This exact
    /// requester is checked for coherent WB RAM with NoSnoop/ATS off,
    /// valid 32-bit DMA addresses and the current ordinary descriptor profile.
    /// All prior IRQ/deferred/firmware command work is drained, and no competing
    /// path changes engine state/masks/rings. All queue/requester/pin owners
    /// remain live on every uncertain failure and until complete hardware/CPU
    /// quiescence. This helper cannot prove those prerequisites or create a
    /// fresh MCU sequencing epoch; production full-device composition is separate.
    pub unsafe fn start_dma_polling(&mut self) -> Result<DmaEnabled, Error> {
        self.guard(true)?;
        if !self.dma_stopped {
            return Err(Error::DmaNotStopped);
        }
        self.dma_stopped = false;
        let result = (|| {
            self.mask_interrupts()?;
            let old = self.read_control(MT_WFDMA0_GLO_CFG)?;
            if old & (DISABLE | BUSY) != 0 {
                return Err(Error::Readback {
                    address: MT_WFDMA0_GLO_CFG,
                    mask: DISABLE | BUSY,
                    expected: 0,
                    actual: old,
                });
            }
            // The existing allocator/descriptor path is 32-bit ordinary DMA.
            // A stale extended-address engine mode is never silently inherited.
            if old & (1 << 26) != 0 {
                return Err(Error::UnsupportedDmaMode(old));
            }
            self.prefetch()?;
            self.registers.write32(MT_WFDMA0_RST_DTX_PTR, u32::MAX)?;
            if self.registers.chip() == Chip::Mt7925 {
                self.registers.write32(MT_WFDMA0_RST_DRX_PTR, u32::MAX)?;
            }
            self.registers.write32(MT_WFDMA0_PRI_DLY_INT_CFG0, 0)?;
            self.modify(MT_WFDMA0_GLO_CFG, 0, CONFIG)?;
            self.modify(MT_WFDMA0_GLO_CFG, 0, ENABLE)?;
            if self.registers.chip() == Chip::Mt7925 {
                self.modify(MT_UWFDMA0_GLO_CFG_EXT1, 1 << 28, 1 << 28)?;
                self.modify(MT_WFDMA0_INT_RX_PRI, 0, 0x0f00)?;
                self.modify(MT_WFDMA0_INT_TX_PRI, 0, 0x7f00)?;
            }
            self.modify(MT_WFDMA_DUMMY_CR, 0, MT_WFDMA_NEED_REINIT)?;
            // Linux enables IRQs here. Stela's serialized polling path keeps
            // the sources masked and verifies them after final writes.
            self.verify_masks()?;
            let actual = self.read_control(MT_WFDMA0_GLO_CFG)?;
            if actual & (CONFIG | ENABLE) != CONFIG | ENABLE {
                return Err(Error::Readback {
                    address: MT_WFDMA0_GLO_CFG,
                    mask: CONFIG | ENABLE,
                    expected: CONFIG | ENABLE,
                    actual,
                });
            }
            Ok(DmaEnabled {
                global_config: actual,
                polling_interrupts_masked: true,
            })
        })();
        self.finish(result)
    }
}
