//! Disjoint ranges owned by fixed physical executors. The loader maps one
//! guarded stack and private bounce leaves per core; native arenas and shadow
//! frames are partitioned, never concurrently reclaimed or patched by peers.
use super::topology::MAX_CORES;
use crate::{handoff::Region, tables::PAGE};

pub(crate) const STACK_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const STACK_STRIDE: u64 = STACK_BYTES + PAGE;
pub(crate) const INVOCATION_STACK_BYTES: u64 = 128 * 1024;
pub(crate) const TASK_STACK_BYTES: u64 = 128 * 1024;
pub(crate) const TASK_STACKS: usize = 16;

pub(crate) fn invocation_stacks(
    cores: usize,
) -> Result<stela_boot_core::guarded_stacks::Layout, stela_boot_core::guarded_stacks::Error> {
    stela_boot_core::guarded_stacks::Layout::new(INVOCATION_STACK_BYTES, cores)
}
pub(crate) fn task_stacks() -> stela_boot_core::guarded_stacks::Layout {
    stela_boot_core::guarded_stacks::Layout::new(TASK_STACK_BYTES, TASK_STACKS)
        .expect("constant guarded task-stack geometry")
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Resources {
    pub cores: u32,
    /// Owned LOADER_CODE page below 1 MiB, absent for the serial path.
    pub sipi: u64,
    /// Fixed physical stack ranges; virtual guards are not mapped.
    pub stacks: Region,
    /// Separate native invocation frames; never an executor's Rust stack.
    pub invocations: Region,
    /// One actual BSP work runtime's fixed pool; task roles are admitted later.
    pub tasks: Region,
    /// Private bounce leaf physical addresses, indexed by fixed worker slot.
    pub bounce: [[u64; 2]; MAX_CORES],
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            cores: 1,
            sipi: 0,
            stacks: Region::default(),
            invocations: Region::default(),
            tasks: Region::default(),
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

/// What each worker keeps of the code arena and shadow pool while the BSP
/// runs every PE serialized: none of them runs guest code then.
const WORKER_CODE: u64 = 4 * 1024 * 1024;
const WORKER_POOL: u64 = 4 * 1024 * 1024;

/// Divide only whole frames/code ring units; unused tail bytes remain owned
/// by the allocation and cannot be lent to a second executor. Executors
/// share alike while each runs PEs; `serialized`, the BSP takes all but the
/// workers' [`WORKER_CODE`] and [`WORKER_POOL`].
pub(crate) fn partition(
    cores: usize,
    slot: usize,
    code: u64,
    pool: u64,
    serialized: bool,
) -> Result<Partition, &'static str> {
    if cores == 0 || cores > MAX_CORES || slot >= cores {
        return Err("invalid native executor slot");
    }
    let workers = cores as u64 - 1;
    // Each host ring has eight 16-byte-aligned code units. Each shadow pool
    // needs 64 permanent root frames and at least one frame in each half.
    let (code_bytes, pool_bytes, code_offset, pool_offset) = if serialized && workers > 0 {
        let first = |total: u64, reserve: u64, unit: u64| {
            total.saturating_sub(workers * reserve) / unit * unit
        };
        let (code_first, pool_first) = (
            first(code, WORKER_CODE, 128),
            first(pool, WORKER_POOL, PAGE),
        );
        let behind = slot.saturating_sub(1) as u64;
        match slot {
            0 => (code_first, pool_first, 0, 0),
            _ => (
                WORKER_CODE,
                WORKER_POOL,
                code_first + behind * WORKER_CODE,
                pool_first + behind * WORKER_POOL,
            ),
        }
    } else {
        let code_bytes = code / cores as u64 / 128 * 128;
        let pool_bytes = pool / cores as u64 / PAGE * PAGE;
        (
            code_bytes,
            pool_bytes,
            slot as u64 * code_bytes,
            slot as u64 * pool_bytes,
        )
    };
    if code_bytes < 128 || pool_bytes < 66 * PAGE {
        return Err("native executor resources too small");
    }
    Ok(Partition {
        code_offset,
        code_bytes,
        pool_offset,
        pool_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_arenas_have_no_overlap_or_fractional_ring_units() {
        for (cores, serialized) in (1..=MAX_CORES).flat_map(|cores| [(cores, false), (cores, true)])
        {
            let mut previous_code = 0;
            let mut previous_pool = 0;
            for slot in 0..cores {
                let part = partition(
                    cores,
                    slot,
                    128 * 1024 * 1024 + 127,
                    64 * 1024 * 1024 + PAGE - 1,
                    serialized,
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

    /// Serialized, the BSP runs every PE and takes all but the workers'
    /// reserves.
    #[test]
    fn a_serialized_bsp_takes_all_but_the_workers_reserves() {
        let (code, pool) = (512 * 1024 * 1024, 1024 * 1024 * 1024);
        let bsp = partition(8, 0, code, pool, true).unwrap();
        assert_eq!(bsp.code_bytes, code - 7 * WORKER_CODE);
        assert_eq!(bsp.pool_bytes, pool - 7 * WORKER_POOL);
        let last = partition(8, 7, code, pool, true).unwrap();
        assert_eq!(last.code_offset + last.code_bytes, code);
        assert_eq!(last.pool_offset + last.pool_bytes, pool);
    }

    #[test]
    fn unavailable_slots_and_insufficient_private_roots_refuse() {
        for (cores, slot) in [(0, 0), (MAX_CORES + 1, 0), (2, 2)] {
            assert!(partition(cores, slot, 1024, 1024 * PAGE, false).is_err());
        }
        assert!(partition(2, 0, 255, 1024 * PAGE, false).is_err());
        assert!(partition(2, 0, 1024, 132 * PAGE - 1, false).is_err());
        assert!(partition(2, 0, 256, 132 * PAGE, false).is_ok());
        assert!(partition(2, 0, 256, 132 * PAGE, true).is_err());
    }
}
