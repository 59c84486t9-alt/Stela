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
//! ACC counters (`get/setCPUPerfCounter`, kernel file 0x2fa009c/0x2fa01c4,
//! T8112 P override 0x2fa4c38/0x2fa4ad8) are paired full64 banks at +20400
//! and +20480. The driver capacity is 16 (ApplePMGR constructor 0x2b67d80),
//! not the enclosing MMIO span. The P map at +20500 retains every full64
//! logical-state entry (`mapCPUPerfCounters`, 0x2fa7cb4); the first entry's
//! low32 determines software's remap and must read back the programmed 1.
//! Special event pairs at +20580+8*n are selected by DT events types2/7.
//! +20660 retains enable bits0/2/4/36 and other full64 RMW fields.
//!
//! Stela hands off counters, map and enables zero/disabled. Its emulated die
//! has no physical residency/transition event source or known scaling, so
//! counts retain software saves. No physical activity rate is invented.
//!
//! Every other register refuses.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::regfile::Held;
use alloc::vec::Vec;

const NAME: &str = "cpu-cluster";
const COUNTER_BASE: u64 = 0x20400;
const COUNTER_PAIR: u64 = 0x80;
const MAP_BASE: u64 = 0x20500;
const EVENT_BASE: u64 = 0x20580;
const COUNTER_ENABLE: u64 = 0x20660;
const COUNTER_BYTES: u64 = 8;

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
    counters: Vec<u64>,
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
            counters: Vec::new(),
        })
    }

    /// Extend only the DT-selected event counters and the hardware's state
    /// counter capacity. The P mapping table is separate from either bank.
    pub fn with_counters(
        mut self,
        capacity: usize,
        mapped: bool,
        events: &[u8],
    ) -> Result<Self, &'static str> {
        if capacity == 0 || capacity > 16 {
            return Err("ACC counter capacity exceeds a paired bank");
        }
        for index in 0..capacity {
            let offset = COUNTER_BASE + index as u64 * COUNTER_BYTES;
            self.counters.extend([offset, offset + COUNTER_PAIR]);
            if mapped {
                self.counters.push(MAP_BASE + index as u64 * COUNTER_BYTES);
            }
        }
        for &index in events {
            if index >= 27 {
                return Err("ACC special event selector is out of range");
            }
            let offset = EVENT_BASE + u64::from(index) * COUNTER_BYTES;
            self.counters.extend([offset, offset + COUNTER_BYTES]);
        }
        self.counters.push(COUNTER_ENABLE);
        self.counters.sort_unstable();
        self.counters.dedup();
        Ok(self)
    }

    /// The bytes the performance-state table spans.
    pub fn pstate_bytes(&self) -> u64 {
        self.pstates * PSTATE_BYTES
    }

    fn described(&self, offset: u64, width: Width) -> bool {
        let table = PSTATE_OFFSET..PSTATE_OFFSET + self.pstate_bytes();
        width == Width::Double
            && offset.is_multiple_of(8)
            && (self.dvmr.contains(&offset)
                || table.contains(&offset)
                || self.counters.contains(&offset))
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
    fn acc_state_maps_event_pairs_and_enable_configuration_retain_full64_values() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut cluster = Cluster::new(&[], 18)
            .unwrap()
            .with_counters(16, true, &[0, 12, 16, 20, 24])
            .unwrap();
        assert_eq!(cluster.read(MAP_BASE, Width::Double, &mut access), Ok(0));
        for index in 0..16 {
            cluster
                .write(MAP_BASE + index * 8, Width::Double, index + 1, &mut access)
                .unwrap();
        }
        assert_eq!(cluster.read(MAP_BASE, Width::Double, &mut access), Ok(1));
        for offset in [
            COUNTER_BASE + 8,
            COUNTER_BASE + COUNTER_PAIR + 8,
            EVENT_BASE,
            EVENT_BASE + 8,
            EVENT_BASE + 24 * 8,
            EVENT_BASE + 25 * 8,
            COUNTER_ENABLE,
        ] {
            assert_eq!(cluster.read(offset, Width::Double, &mut access), Ok(0));
            cluster
                .write(offset, Width::Double, 0x1234_5678_9abc_def0, &mut access)
                .unwrap();
            assert_eq!(
                cluster.read(offset, Width::Double, &mut access),
                Ok(0x1234_5678_9abc_def0)
            );
        }
        assert!(
            cluster
                .read(EVENT_BASE + 2 * 8, Width::Double, &mut access)
                .is_err()
        );
        assert!(
            cluster
                .write(MAP_BASE, Width::Word, 0, &mut access)
                .is_err()
        );
        assert!(
            Cluster::new(&[], 16)
                .unwrap()
                .with_counters(17, false, &[])
                .is_err()
        );
        let mut efficiency = Cluster::new(&[], 16)
            .unwrap()
            .with_counters(16, false, &[])
            .unwrap();
        assert!(
            efficiency
                .read(MAP_BASE, Width::Double, &mut access)
                .is_err()
        );
    }

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
