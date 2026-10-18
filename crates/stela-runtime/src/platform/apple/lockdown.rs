//! The lockdown registers of a CPU implementation block: the per-PE
//! `cpu-impl-reg` and the per-cluster `cpm-impl-reg` of an ADT `/cpus` node.
//!
//! No public source names these registers; their layout comes from what
//! SPTM 26A434 (T8112) does at the end of its CPU initialization
//! (`__text+0x1b0d8` to `__text+0x1b188`), the only access it or the kernel
//! makes to either block on that SoC:
//!
//! - the 64-bit MASK at CONTROL + 8 is read and ORed with every bit except
//!   54 (`cpu-impl-reg` + 0x5008) or 53 and 55 (`cpm-impl-reg` + 0x9008);
//! - then, under one boot configuration, bit 0 of the 64-bit CONTROL is ORed
//!   in (`+ 0x5000`, `+ 0x9000`);
//! - each PE of a cluster repeats the `cpm-impl-reg` sequence with the same
//!   values, and SPTM may read MASK back to record it.
//!
//! Inferred from that sequence: MASK selects what is locked, CONTROL bit 0
//! applies the lock, and both reset to 0. Once locked, a write that keeps
//! both values (as the cluster's other PEs make) completes; one that changes
//! them stops, because what hardware does is not documented. What each
//! MASK bit protects is not documented either; the block's other registers
//! are not modelled and refuse, so no access such a lock could forbid
//! completes here.
//!
//! A PE's `cpu-impl-reg` also holds its RVBAR at +0 (m1n1 `src/smp.c`): the
//! reset vector in bits 47:12, where the core leaves reset, and RVBAR_LOCK
//! in bit 0. Boot firmware programs and locks it before its client runs:
//! m1n1 finds it locked on the entry point iBoot gave it, and SPTM 26A434
//! (T8112) neither reads nor writes it, its warm reset path at the page
//! of its entry point (`b` to the code that looks the PE up by MPIDR). So a
//! block given the boot hand-off's entry point reads it locked, a write
//! that keeps it completes and one that changes it stops.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};

/// CONTROL and MASK.
pub const BYTES: u64 = 16;
/// The RVBAR of a PE's block.
pub const RVBAR_BYTES: u64 = 8;
const LOCK: u64 = 1;
const RVBAR: u64 = 0;
const RVBAR_ADDRESS: u64 = 0x0000_ffff_ffff_f000;

/// The lockdown pair of one implementation block, with CONTROL at
/// `control` bytes from the block's start.
#[derive(Debug, Clone)]
pub struct Lockdown {
    name: &'static str,
    control: u64,
    lock: u64,
    mask: u64,
    rvbar: Option<u64>,
}

impl Lockdown {
    pub fn new(name: &'static str, control: u64) -> Self {
        Self {
            name,
            control,
            lock: 0,
            mask: 0,
            rvbar: None,
        }
    }

    /// A PE's block, whose RVBAR the boot firmware locked on `entry`.
    pub fn with_reset_vector(mut self, entry: u64) -> Self {
        self.rvbar = Some(entry & RVBAR_ADDRESS | LOCK);
        self
    }

    /// Where the PE leaves reset, for a PE's block.
    pub fn reset_address(&self) -> Option<u64> {
        Some(self.rvbar? & RVBAR_ADDRESS)
    }

    /// Whether CONTROL bit 0 has applied the lock.
    pub fn locked(&self) -> bool {
        self.lock & LOCK != 0
    }

    fn register(&self, offset: u64, width: Width, direction: Direction) -> Result<bool, MmioError> {
        let refused = |reason| refuse(self.name, offset, width, direction, reason);
        let is_mask = match offset.checked_sub(self.control) {
            Some(0) => false,
            Some(8) => true,
            _ => return Err(refused("register without public description")),
        };
        if width != Width::Double {
            return Err(refused("lockdown register access narrower than 64 bits"));
        }
        Ok(is_mask)
    }
}

impl MmioDevice for Lockdown {
    fn name(&self) -> &'static str {
        self.name
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if let Some(rvbar) = self
            .rvbar
            .filter(|_| offset == RVBAR && width == Width::Double)
        {
            return Ok(rvbar);
        }
        Ok(if self.register(offset, width, Direction::Read)? {
            self.mask
        } else {
            self.lock
        })
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let refused = |reason| refuse(self.name, offset, width, Direction::Write, reason);
        if let Some(rvbar) = self
            .rvbar
            .filter(|_| offset == RVBAR && width == Width::Double)
        {
            return if value == rvbar {
                Ok(())
            } else {
                Err(refused("RVBAR change after the boot firmware locked it"))
            };
        }
        let is_mask = self.register(offset, width, Direction::Write)?;
        let current = if is_mask { self.mask } else { self.lock };
        if self.locked() && value != current {
            return Err(refused("lockdown register change after the lock"));
        }
        if is_mask {
            self.mask = value;
        } else if value & !LOCK != 0 {
            return Err(refused("lockdown CONTROL bit without documented meaning"));
        } else {
            self.lock = value;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn sptms_lockdown_sequence_completes_and_locks_the_pair() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut block = Lockdown::new("cpu-impl-reg", 0x5000);
        let rmw = |block: &mut Lockdown, access: &mut Access<'_>, offset, bits: u64| {
            let value = block.read(offset, Width::Double, access).unwrap() | bits;
            block.write(offset, Width::Double, value, access)
        };
        // MASK, every bit but 54, then CONTROL bit 0.
        rmw(&mut block, &mut access, 0x5008, !(1 << 54)).unwrap();
        assert!(!block.locked());
        rmw(&mut block, &mut access, 0x5000, 1).unwrap();
        assert!(block.locked());
        assert_eq!(
            block.read(0x5008, Width::Double, &mut access),
            Ok(!(1 << 54))
        );
        // Another PE of the cluster repeats it unchanged; a change stops.
        rmw(&mut block, &mut access, 0x5008, !(1 << 54)).unwrap();
        rmw(&mut block, &mut access, 0x5000, 1).unwrap();
        assert!(
            block
                .write(0x5008, Width::Double, u64::MAX, &mut access)
                .is_err()
        );
        assert!(block.write(0x5000, Width::Double, 0, &mut access).is_err());
        // Undocumented bits, narrow accesses and other registers refuse.
        let mut fresh = Lockdown::new("cpm-impl-reg", 0x9000);
        assert!(fresh.write(0x9000, Width::Double, 2, &mut access).is_err());
        assert!(fresh.read(0x9008, Width::Word, &mut access).is_err());
        assert!(fresh.read(0x9010, Width::Double, &mut access).is_err());
        assert!(fresh.read(0x100, Width::Double, &mut access).is_err());
        assert!(fresh.read(0, Width::Double, &mut access).is_err());
    }

    #[test]
    fn a_pes_rvbar_reads_locked_on_the_boot_entry_page() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut block = Lockdown::new("cpu-impl-reg", 0x5000).with_reset_vector(0x8_0300_c388);
        assert_eq!(block.reset_address(), Some(0x8_0300_c000));
        assert_eq!(block.read(0, Width::Double, &mut access), Ok(0x8_0300_c001));
        block
            .write(0, Width::Double, 0x8_0300_c001, &mut access)
            .unwrap();
        assert!(
            block
                .write(0, Width::Double, 0x8_0400_0001, &mut access)
                .is_err()
        );
        assert!(block.read(0, Width::Word, &mut access).is_err());
    }
}
