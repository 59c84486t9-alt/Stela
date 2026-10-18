//! The PMGR registers of one CPU cluster, at offsets from the cluster's
//! base (the T8112's E cluster at `0x210e00000`, its P cluster at
//! `0x211e00000`: m1n1 `src/cpufreq.c` `t8112_clusters`), as the 26A434
//! J473AP `AppleT8112PMGR` driver uses them through `readACCReg`:
//!
//! - the DVMR weight tables at `0x206a8..0x20700`, 64-bit registers of
//!   sixteen 4-bit weight types each. `getTunedDVMRWeightType` searches the
//!   E cluster's `0x206a8` and `0x206e0`, and the P cluster's `0x206e8`,
//!   `0x206e0`, `0x206b0` and `0x206a8`, for the requested type and asserts
//!   when no table holds it; `enableDVMR` sets and clears bit 63 of
//!   `0x206b8`, keeping its other bits. The boot firmware programs them
//!   from its tunables, which the board's SoC row carries; a register with
//!   no known tunable refuses rather than reading an invented one;
//! - the performance-state table at `0x78000`, eight 64-bit words per state
//!   every `0x40` bytes (m1n1 `cpufreq.c` reads its T8112 slots there).
//!   `AppleT8110PMGR::getDVMRMaxWeight` takes a state's DVMR weight type
//!   from word 1 bits 41:38, and the DPE power expressions take its
//!   voltage code from word 0 bits 63:56. The boot firmware builds the
//!   table from the die's calibration, which an emulated die does not
//!   have: every word reads 0, the lowest voltage code and DVMR weight
//!   type 0, until software writes it, and then holds what it wrote.
//!
//! Every other register refuses.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::regfile::Held;
use alloc::vec::Vec;

const NAME: &str = "cpu-cluster";

/// The cluster register window the DVMR tables lie in (J473AP
/// `/arm-io/pmgr` `reg[5]` and `reg[14]`).
pub const ACC_OFFSET: u64 = 0x20000;
pub const ACC_BYTES: u64 = 0x2000;

/// The DVMR weight tables.
const DVMR: core::ops::Range<u64> = 0x206a8..0x20700;

/// The performance-state table and its slot size.
pub const PSTATE_OFFSET: u64 = 0x78000;
pub const PSTATE_BYTES: u64 = 0x40;

/// One cluster's registers: the DVMR tables the boot firmware programmed,
/// as `(offset, value)`, and `pstates` performance-state slots.
#[derive(Debug, Clone)]
pub struct Cluster {
    dvmr: Vec<u64>,
    pstates: u64,
    registers: Held,
}

impl Cluster {
    pub fn new(dvmr: &[(u64, u64)], pstates: usize) -> Result<Self, &'static str> {
        let mut registers = Held::default();
        let mut offsets = Vec::new();
        for &(offset, value) in dvmr {
            if !DVMR.contains(&offset) || !offset.is_multiple_of(8) || offsets.contains(&offset) {
                return Err("DVMR tunable outside the DVMR tables");
            }
            offsets.push(offset);
            registers.set(offset, value);
        }
        Ok(Self {
            dvmr: offsets,
            pstates: pstates as u64,
            registers,
        })
    }

    /// The bytes the performance-state table spans.
    pub fn pstate_bytes(&self) -> u64 {
        self.pstates * PSTATE_BYTES
    }

    fn described(&self, offset: u64, width: Width) -> bool {
        let table = PSTATE_OFFSET..PSTATE_OFFSET + self.pstate_bytes();
        width == Width::Double
            && offset.is_multiple_of(8)
            && (self.dvmr.contains(&offset) || table.contains(&offset))
    }
}

impl MmioDevice for Cluster {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if !self.described(offset, width) {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "cluster register without a known value",
            ));
        }
        Ok(self.registers.get(offset))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if !self.described(offset, width) {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Write,
                "cluster register without a known value",
            ));
        }
        self.registers.set(offset, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn the_dvmr_tables_hold_the_firmware_tunables_and_the_pstates_start_empty() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut cluster = Cluster::new(&[(0x206a8, 0x4444_4433_3322_2110)], 16).unwrap();
        assert_eq!(
            cluster.read(0x206a8, Width::Double, &mut access),
            Ok(0x4444_4433_3322_2110)
        );
        assert!(cluster.read(0x206b0, Width::Double, &mut access).is_err());
        assert!(cluster.read(0x206a8, Width::Word, &mut access).is_err());
        assert_eq!(cluster.read(0x78048, Width::Double, &mut access), Ok(0));
        cluster
            .write(0x78048, Width::Double, 7, &mut access)
            .unwrap();
        assert_eq!(cluster.read(0x78048, Width::Double, &mut access), Ok(7));
        assert!(cluster.read(0x78400, Width::Double, &mut access).is_err());
        assert!(
            cluster
                .write(0x20020, Width::Double, 0, &mut access)
                .is_err()
        );
        assert!(Cluster::new(&[(0x20700, 0)], 1).is_err());
        assert!(Cluster::new(&[(0x206a8, 0), (0x206a8, 1)], 1).is_err());
    }
}
