//! Disjoint ranges owned by fixed physical executors. The loader maps one
//! guarded stack and private bounce leaves per core; native arenas and shadow
//! frames are partitioned, never concurrently reclaimed or patched by peers.
use super::topology::MAX_CORES;
use crate::{handoff::Region, tables::PAGE};

pub(crate) const STACK_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const STACK_STRIDE: u64 = STACK_BYTES + PAGE;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Resources {
    pub cores: u32,
    /// Owned LOADER_CODE page below 1 MiB, absent for the serial path.
    pub sipi: u64,
    /// Fixed physical stack ranges; virtual guards are not mapped.
    pub stacks: Region,
    /// Private bounce leaf physical addresses, indexed by fixed worker slot.
    pub bounce: [[u64; 2]; MAX_CORES],
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            cores: 1,
            sipi: 0,
            stacks: Region::default(),
            bounce: [[0; 2]; MAX_CORES],
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Partition {
    pub code_offset: u64,
    pub code_bytes: u64,
    pub pool_offset: u64,
    pub pool_bytes: u64,
}

/// Divide only whole frames/code ring units; unused tail bytes remain owned
/// by the allocation and cannot be lent to a second executor.
pub(crate) fn partition(
    cores: usize,
    slot: usize,
    code: u64,
    pool: u64,
) -> Result<Partition, &'static str> {
    if cores == 0 || cores > MAX_CORES || slot >= cores {
        return Err("invalid native executor slot");
    }
    // Each host ring has eight 16-byte-aligned code units. Each shadow pool
    // needs 64 permanent root frames and at least one frame in each half.
    let code_bytes = code / cores as u64 / 128 * 128;
    let pool_bytes = pool / cores as u64 / PAGE * PAGE;
    if code_bytes < 128 || pool_bytes < 66 * PAGE {
        return Err("native executor resources too small");
    }
    Ok(Partition {
        code_offset: slot as u64 * code_bytes,
        code_bytes,
        pool_offset: slot as u64 * pool_bytes,
        pool_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_arenas_have_no_overlap_or_fractional_ring_units() {
        for cores in 1..=MAX_CORES {
            let mut previous_code = 0;
            let mut previous_pool = 0;
            for slot in 0..cores {
                let part = partition(
                    cores,
                    slot,
                    128 * 1024 * 1024 + 127,
                    64 * 1024 * 1024 + PAGE - 1,
                )
                .unwrap();
                assert_eq!(part.code_offset, previous_code);
                assert_eq!(part.pool_offset, previous_pool);
                assert_eq!(part.code_bytes % 128, 0);
                assert_eq!(part.pool_bytes % PAGE, 0);
                previous_code += part.code_bytes;
                previous_pool += part.pool_bytes;
            }
            assert!(previous_code <= 128 * 1024 * 1024 + 127);
            assert!(previous_pool <= 64 * 1024 * 1024 + PAGE - 1);
        }
    }

    #[test]
    fn unavailable_slots_and_insufficient_private_roots_refuse() {
        for (cores, slot) in [(0, 0), (MAX_CORES + 1, 0), (2, 2)] {
            assert!(partition(cores, slot, 1024, 1024 * PAGE).is_err());
        }
        assert!(partition(2, 0, 255, 1024 * PAGE).is_err());
        assert!(partition(2, 0, 1024, 132 * PAGE - 1).is_err());
        assert!(partition(2, 0, 256, 132 * PAGE).is_ok());
    }
}
