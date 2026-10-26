// SPDX-License-Identifier: GPL-2.0-only
//! tg3_setup_copper_phy's actual endpoint CLKREQ_BUG workaround.
use super::{phy::Speed, *};

impl<R: Registers, D: Delay> Hardware<R, D> {
    pub(super) fn packet_clkreq(&mut self, speed: Speed) -> Result<(), Error> {
        if self.clkreq_bug != Some(true) {
            return Ok(());
        }
        let result = (|| {
            self.timer_ready()?;
            let at = self.pcie_capability()? + 0x10;
            let control = Self::checked(self.regs().config_read32(at)?)? as u16;
            if control == u16::MAX {
                return Err(Error::Removed);
            }
            let value = if matches!(
                speed,
                Speed::Mb10Half | Speed::Mb10 | Speed::Mb100Half | Speed::Mb100
            ) {
                control & !0x100
            } else {
                control | 0x100
            };
            // Native WORD only: Link Status is adjacent and contains W1C bits.
            self.regs().config_write16(at, value)?;
            let observed = Self::checked(self.regs().config_read32(at)?)?;
            if observed as u16 == u16::MAX || observed & 0x100 != u32::from(value & 0x100) {
                return Err(Error::ConfigDidNotLatch);
            }
            Ok(())
        })();
        // An uncertain clock-control effect cannot publish carrier or a TX BD.
        self.record(result)
    }
}
