// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
//! Exact RTL8156B12/13/15 PHY tuning from pinned r8156b_hw_phy_cfg.
//! No product-ID inference and no use by A,8157 or8159.
use super::*;
impl<C: Control> Chip<C> {
    pub(super) fn pre_8156b12(&mut self) -> Result<(), BlockError> {
        self.phy_write(0xbf86, 0x9000)?;
        self.phy_modify(0xc402, 0, 1 << 10)?;
        self.phy_modify(0xc402, 1 << 10, 0)?;
        self.phy_write(0xbd86, 0x1010)?;
        self.phy_write(0xbd88, 0x1010)?;
        self.phy_modify(0xbd4e, 1 << 10 | 1 << 11, 1 << 11)?;
        self.phy_modify(0xbf46, 0xf00, 0x700)?;
        Ok(())
    }
    pub(super) fn tune_8156b12(&mut self) -> Result<(), BlockError> {
        self.phy_modify(0xbc08, 0, 1 << 3 | 1 << 2)?;
        self.sram_modify(0x8fff, 0xff00, 0x0400)?;
        self.phy_modify(0xacda, 0, 0xff00)?;
        self.phy_modify(0xacde, 0, 0xf000)?;
        self.phy_write(0xac8c, 0x0ffc)?;
        self.phy_write(0xac46, 0xb7b4)?;
        self.phy_write(0xac50, 0x0fbc)?;
        self.phy_write(0xac3c, 0x9240)?;
        self.phy_write(0xac4e, 0x0db4)?;
        self.phy_write(0xacc6, 0x0707)?;
        self.phy_write(0xacc8, 0xa0d3)?;
        self.phy_write(0xad08, 0x0007)?;
        self.sram2_write(0x8560, 0x19cc)?;
        self.sram2_write(0x8562, 0x19cc)?;
        self.sram2_write(0x8564, 0x19cc)?;
        self.sram2_write(0x8566, 0x147d)?;
        self.sram2_write(0x8568, 0x147d)?;
        self.sram2_write(0x856a, 0x147d)?;
        self.sram2_write(0x8ffe, 0x0907)?;
        self.sram2_write(0x80d6, 0x2801)?;
        self.sram2_write(0x80f2, 0x2801)?;
        self.sram2_write(0x80f4, 0x6077)?;
        self.phy_write(0xb506, 0x01e7)?;
        self.sram2_write(0x8013, 0x0700)?;
        self.sram2_write(0x8fb9, 0x2801)?;
        self.sram2_write(0x8fba, 0x0100)?;
        self.sram2_write(0x8fbc, 0x1900)?;
        self.sram2_write(0x8fbe, 0xe100)?;
        self.sram2_write(0x8fc0, 0x0800)?;
        self.sram2_write(0x8fc2, 0xe500)?;
        self.sram2_write(0x8fc4, 0x0f00)?;
        self.sram2_write(0x8fc6, 0xf100)?;
        self.sram2_write(0x8fc8, 0x0400)?;
        self.sram2_write(0x8fca, 0xf300)?;
        self.sram2_write(0x8fcc, 0xfd00)?;
        self.sram2_write(0x8fce, 0xff00)?;
        self.sram2_write(0x8fd0, 0xfb00)?;
        self.sram2_write(0x8fd2, 0x0100)?;
        self.sram2_write(0x8fd4, 0xf400)?;
        self.sram2_write(0x8fd6, 0xff00)?;
        self.sram2_write(0x8fd8, 0xf600)?;
        self.modify(PLA, PLA_USB_CFG, 1, 0, EN_XG_LIP | EN_G_LIP)?;
        self.sram2_write(0x813d, 0x390e)?;
        self.sram2_write(0x814f, 0x790e)?;
        self.sram2_write(0x80b0, 0x0f31)?;
        self.phy_modify(0xbf4c, 0, 1 << 1)?;
        self.phy_modify(0xbcca, 0, 1 << 9 | 1 << 8)?;
        self.sram2_write(0x8141, 0x320e)?;
        self.sram2_write(0x8153, 0x720e)?;
        self.sram2_write(0x8529, 0x050e)?;
        self.phy_modify(OCP_EEE_CFG, CTAP_SHORT_EN, 0)?;
        self.sram_write(0x816c, 0xc4a0)?;
        self.sram_write(0x8170, 0xc4a0)?;
        self.sram_write(0x8174, 0x04a0)?;
        self.sram_write(0x8178, 0x04a0)?;
        self.sram_write(0x817c, 0x0719)?;
        self.sram_write(0x8ff4, 0x0400)?;
        self.sram_write(0x8ff1, 0x0404)?;
        self.phy_write(0xbf4a, 0x001b)?;
        self.sram2_write(0x8033, 0x7c13)?;
        self.sram2_write(0x8037, 0x7c13)?;
        self.sram2_write(0x803b, 0xfc32)?;
        self.sram2_write(0x803f, 0x7c13)?;
        self.sram2_write(0x8043, 0x7c13)?;
        self.sram2_write(0x8047, 0x7c13)?;
        self.sram2_write(0x8145, 0x370e)?;
        self.sram2_write(0x8157, 0x770e)?;
        self.sram2_write(0x8169, 0x0d0a)?;
        self.sram2_write(0x817b, 0x1d0a)?;
        self.sram_modify(0x8217, 0xff00, 0x5000)?;
        self.sram_modify(0x821a, 0xff00, 0x5000)?;
        self.sram_write(0x80da, 0x0403)?;
        self.sram_modify(0x80dc, 0xff00, 0x1000)?;
        self.sram_write(0x80b3, 0x0384)?;
        self.sram_write(0x80b7, 0x2007)?;
        self.sram_modify(0x80ba, 0xff00, 0x6c00)?;
        self.sram_write(0x80b5, 0xf009)?;
        self.sram_modify(0x80bd, 0xff00, 0x9f00)?;
        self.sram_write(0x80c7, 0xf083)?;
        self.sram_write(0x80dd, 0x03f0)?;
        self.sram_modify(0x80df, 0xff00, 0x1000)?;
        self.sram_write(0x80cb, 0x2007)?;
        self.sram_modify(0x80ce, 0xff00, 0x6c00)?;
        self.sram_write(0x80c9, 0x8009)?;
        self.sram_modify(0x80d1, 0xff00, 0x8000)?;
        self.sram_write(0x80a3, 0x200a)?;
        self.sram_write(0x80a5, 0xf0ad)?;
        self.sram_write(0x809f, 0x6073)?;
        self.sram_write(0x80a1, 0x000b)?;
        self.sram_modify(0x80a9, 0xff00, 0xc000)?;
        self.patch_request(true, true)?;
        self.phy_modify(0xb896, 1 << 0, 0)?;
        self.phy_modify(0xb892, 0xff00, 0)?;
        self.phy_write(0xb88e, 0xc23e)?;
        self.phy_write(0xb890, 0x0000)?;
        self.phy_write(0xb88e, 0xc240)?;
        self.phy_write(0xb890, 0x0103)?;
        self.phy_write(0xb88e, 0xc242)?;
        self.phy_write(0xb890, 0x0507)?;
        self.phy_write(0xb88e, 0xc244)?;
        self.phy_write(0xb890, 0x090b)?;
        self.phy_write(0xb88e, 0xc246)?;
        self.phy_write(0xb890, 0x0c0e)?;
        self.phy_write(0xb88e, 0xc248)?;
        self.phy_write(0xb890, 0x1012)?;
        self.phy_write(0xb88e, 0xc24a)?;
        self.phy_write(0xb890, 0x1416)?;
        self.phy_modify(0xb896, 0, 1 << 0)?;
        self.patch_request(false, true)?;
        self.phy_modify(0xa86a, 0, 1 << 0)?;
        self.phy_modify(0xa6f0, 0, 1 << 0)?;
        self.phy_write(0xbfa0, 0xd70d)?;
        self.phy_write(0xbfa2, 0x4100)?;
        self.phy_write(0xbfa4, 0xe868)?;
        self.phy_write(0xbfa6, 0xdc59)?;
        self.phy_write(0xb54c, 0x3c18)?;
        self.phy_modify(0xbfa4, 1 << 5, 0)?;
        self.sram_modify(0x817d, 0, 1 << 12)?;
        Ok(())
    }
    pub(super) fn tune_8156b13(&mut self) -> Result<(), BlockError> {
        self.phy_modify(0xac46, 0x00f0, 0x0090)?;
        self.phy_modify(0xad30, 0x0003, 0x0001)?;
        Ok(())
    }
    pub(super) fn tune_8156b13_15(&mut self) -> Result<(), BlockError> {
        self.sram2_write(0x80f5, 0x760e)?;
        self.sram2_write(0x8107, 0x360e)?;
        self.sram2_modify(0x8551, 0xff00, 0x0800)?;
        self.phy_modify(0xbf00, 0xe000, 0xa000)?;
        self.phy_modify(0xbf46, 0x0f00, 0x0300)?;
        self.sram_write(0x8044, 0x2417)?;
        self.sram_write(0x804a, 0x2417)?;
        self.sram_write(0x8050, 0x2417)?;
        self.sram_write(0x8056, 0x2417)?;
        self.sram_write(0x805c, 0x2417)?;
        self.sram_write(0x8062, 0x2417)?;
        self.sram_write(0x8068, 0x2417)?;
        self.sram_write(0x806e, 0x2417)?;
        self.sram_write(0x8074, 0x2417)?;
        self.sram_write(0x807a, 0x2417)?;
        self.phy_modify(0xbf84, 0xe000, 0xa000)?;
        Ok(())
    }
}
