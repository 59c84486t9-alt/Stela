//! The architectural external-debug Software Lock of a CoreSight component.
//!
//! Arm SysReg_xml_A_profile-2026-06 `ext-edlar.xml` and `ext-edlsr.xml`
//! specify the 32-bit write-only EDLAR at +0xfb0 and read-only EDLSR at
//! +0xfb4. The key 0xc5acce55 unlocks; every other word locks. EDLSR reports
//! the implemented lock in bit 0, its locked state in bit 1 and nTT as zero.
//! The reset state is locked. This is the optional Software Lock, distinct
//! from the PE's architectural OS Lock and its debug exception controls.
//!
//! The kernel initializes each CPU's debug component with that key (26A434
//! file offset 0x4d6f1b4 and 0x4d6f280), using `/cpus/coresight-reg` or
//! `reg-private` and a 4 KiB component map within the DT's larger CoreSight
//! region. Only the lock pair of that component is mapped here; other debug registers
//! and accesses with undescribed widths or directions still refuse.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};

const NAME: &str = "coresight-software-lock";
/// Offset of the write-only external debug lock-access register.
pub const ACCESS: u64 = 0xfb0;
/// Offset of the read-only external debug lock-status register.
pub const STATUS: u64 = 0xfb4;
/// Size and alignment of an architectural CoreSight component map.
pub const BYTES: u64 = 0x1000;
const KEY: u64 = 0xc5acce55;
const IMPLEMENTED: u64 = 1;
const LOCKED: u64 = 1 << 1;

/// The optional memory-mapped Software Lock of one debug component.
#[derive(Debug, Clone)]
pub struct SoftwareLock {
    locked: bool,
}

impl SoftwareLock {
    /// A component whose Software Lock starts locked after debug reset.
    pub fn new() -> Self {
        Self { locked: true }
    }
}

impl Default for SoftwareLock {
    fn default() -> Self {
        Self::new()
    }
}

impl MmioDevice for SoftwareLock {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if offset != STATUS || width != Width::Word {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "only the 32-bit external debug lock status is readable",
            ));
        }
        Ok(IMPLEMENTED | if self.locked { LOCKED } else { 0 })
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if offset != ACCESS || width != Width::Word {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Write,
                "only the 32-bit external debug lock-access register is writable",
            ));
        }
        self.locked = value & width.mask() != KEY;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    #[test]
    fn key_unlocks_other_words_relock_and_unsupported_accesses_preserve_state() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut lock = SoftwareLock::new();
        assert_eq!(lock.read(STATUS, Width::Word, &mut a), Ok(3));
        lock.write(ACCESS, Width::Word, KEY, &mut a).unwrap();
        assert_eq!(lock.read(STATUS, Width::Word, &mut a), Ok(1));
        for (offset, width) in [
            (ACCESS, Width::Double),
            (STATUS, Width::Word),
            (0, Width::Word),
        ] {
            assert!(lock.write(offset, width, 0, &mut a).is_err());
        }
        assert_eq!(lock.read(STATUS, Width::Word, &mut a), Ok(1));
        assert!(lock.read(ACCESS, Width::Word, &mut a).is_err());
        lock.write(ACCESS, Width::Word, 0, &mut a).unwrap();
        assert_eq!(lock.read(STATUS, Width::Word, &mut a), Ok(3));
    }
}
