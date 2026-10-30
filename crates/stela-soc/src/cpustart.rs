//! The PMGR's CPU start registers, as m1n1 `src/smp.c` documents them (the
//! T8112's at `/arm-io/pmgr` `reg[0]` + 0x34000, `CPU_START_OFF_T8112`):
//!
//! - `+0x0`: a stop request per core, bit `4 * cluster + core`;
//! - `+0x4`: per core, bit `4 * cluster + core`, "some kind of system level
//!   startup/status bit; without this, IRQs don't work", which software sets
//!   before starting the core;
//! - `+0x8 + 4 * cluster`: writing bit `core` releases that core of the
//!   cluster from reset, at its `cpu-impl-reg` RVBAR.
//!
//! The 26A434 J473AP kernel's PMGR `enable_core` writes `+0x4` and each
//! cluster's start word for every secondary PE, a cleared bit leaving its
//! core alone. The J873GAP (M6) kernel's `T8152ACC::setCoreOnline` sets bit
//! `6 * cluster + core` of `+0x4` and `T8152ACC::wakeCore` bit `core` of
//! `+0x8 + 4 * cluster`, each read-modify-write and for clusters 0 and 1
//! only (kernelcache 0xfffffe000a0474cc and 0xfffffe000a047634). It reaches
//! them through `/arm-io/pmgr-child` register map 0x128, `reg[42]`
//! (0x1_0073_0000) + 0x4004 and + 0x4008, which is `reg[0]` + 0x34000, the
//! node's `misc-cores-offset`. Here `+0x4` holds what is written, a start bit queues that
//! core's release for the machine ([`CpuStart::take`]), and the start words
//! read 0. Stopping a core is not modelled: a stop request refuses, as does
//! every other register.
use alloc::vec::Vec;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

const NAME: &str = "cpu-start";

const STOP: u64 = 0x0;
const STARTUP: u64 = 0x4;
const START: u64 = 0x8;

use stela_soc_data::cpustart::{Core, bytes};

#[derive(Debug, Clone)]
pub struct CpuStart {
    clusters: u8,
    startup: u32,
    released: Vec<Core>,
}

impl CpuStart {
    pub fn new(clusters: u8) -> Self {
        Self {
            clusters,
            startup: 0,
            released: Vec::new(),
        }
    }

    /// The cores released since the last call, in release order.
    pub fn take(&mut self) -> Vec<Core> {
        core::mem::take(&mut self.released)
    }
}

impl MmioDevice for CpuStart {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let refused = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word {
            return Err(refused("CPU start registers are 32-bit"));
        }
        match offset {
            STARTUP => Ok(u64::from(self.startup)),
            _ if (START..bytes(self.clusters)).contains(&offset) && offset.is_multiple_of(4) => {
                Ok(0)
            }
            _ => Err(refused("CPU start register without described meaning")),
        }
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let refused = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word {
            return Err(refused("CPU start registers are 32-bit"));
        }
        let value = value as u32;
        match offset {
            STOP => Err(refused("stopping a core is not modelled")),
            STARTUP => {
                self.startup = value;
                Ok(())
            }
            _ if (START..bytes(self.clusters)).contains(&offset) && offset.is_multiple_of(4) => {
                let cluster = ((offset - START) / 4) as u8;
                self.released.extend(
                    (0..32)
                        .filter(|core| value & (1 << core) != 0)
                        .map(|core| Core { cluster, core }),
                );
                Ok(())
            }
            _ => Err(refused("CPU start register without described meaning")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;

    #[test]
    fn start_bits_release_their_cores_and_stops_refuse() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut start = CpuStart::new(2);
        // The kernel's sequence for cluster 1 core 3.
        start
            .write(STARTUP, Width::Word, 1 << 7, &mut access)
            .unwrap();
        start.write(START, Width::Word, 0, &mut access).unwrap();
        start
            .write(START + 4, Width::Word, 1 << 3, &mut access)
            .unwrap();
        assert_eq!(
            start.take(),
            [Core {
                cluster: 1,
                core: 3
            }]
        );
        assert_eq!(start.take(), []);
        assert_eq!(start.read(STARTUP, Width::Word, &mut access), Ok(1 << 7));
        assert_eq!(start.read(START + 4, Width::Word, &mut access), Ok(0));
        assert!(start.write(STOP, Width::Word, 1, &mut access).is_err());
        assert!(start.write(START + 8, Width::Word, 1, &mut access).is_err());
        assert!(start.read(STARTUP, Width::Double, &mut access).is_err());
    }
}
