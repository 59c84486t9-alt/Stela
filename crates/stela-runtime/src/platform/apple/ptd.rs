//! The PMP's PTD update registers: `/arm-io/pmp` `reg[ptd-update-reg-index]`,
//! 64-bit slots through which drivers hand the power management
//! coprocessor's firmware their readings. The 26A434 J473AP
//! `AppleT8112MemCacheController::writePTD` stores the DRAM refresh rate in
//! its slot (`/arm-io/mcc` `reg[pmp_ptd_reg_idx]` plus
//! `pmp_ptd_update_space_offset`) with one 64-bit store and never reads it
//! back. Without the PMP firmware a slot only holds what was written;
//! narrower accesses refuse.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::regfile::Held;

const NAME: &str = "ptd";

#[derive(Debug, Clone, Default)]
pub struct Ptd {
    slots: Held,
}

impl Ptd {
    pub fn new() -> Self {
        Self::default()
    }
}

fn slot(offset: u64, width: Width, direction: Direction) -> Result<u64, MmioError> {
    if width != Width::Double {
        return Err(refuse(
            NAME,
            offset,
            width,
            direction,
            "PTD access other than 64 bits",
        ));
    }
    Ok(offset)
}

impl MmioDevice for Ptd {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        Ok(self.slots.get(slot(offset, width, Direction::Read)?))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.slots
            .set(slot(offset, width, Direction::Write)?, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn slots_hold_64_bit_writes() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut ptd = Ptd::new();
        ptd.write(0x7a0, Width::Double, 0xa, &mut access).unwrap();
        assert_eq!(ptd.read(0x7a0, Width::Double, &mut access), Ok(0xa));
        assert_eq!(ptd.read(0x7a8, Width::Double, &mut access), Ok(0));
        assert!(ptd.write(0x7a0, Width::Word, 0, &mut access).is_err());
    }
}
