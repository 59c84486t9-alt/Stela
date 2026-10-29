//! Disjoint ranges owned by fixed physical executors. The loader maps one
//! guarded stack and private bounce leaves per core; native arenas and shadow
//! frames are partitioned, never concurrently reclaimed or patched by peers.
use super::topology::MAX_CORES;
use crate::{handoff::Region, tables::PAGE};
mod allocation;
pub(crate) use allocation::{AllocationClaim, ClaimError, TaskAllocations, TaskPool};

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

/// Explicit diagnostic reservation metadata, never a task/current grant.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum PrototypeTaskPlan {
    #[default]
    Disabled = 0,
    FirmwarePrototype32Mixed = 1,
}
pub(crate) const PROTOTYPE_STACKS: usize = 32;
pub(crate) const PROTOTYPE_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) fn prototype_tasks(
    base: u64,
) -> Result<stela_boot_core::guarded_stacks::MixedLayout, stela_boot_core::guarded_stacks::Error> {
    use stela_boot_core::guarded_stacks::{Error, Geometry, MixedLayout};
    let kernel = Geometry::new(16 * 1024, 16 * 1024)?;
    let ordinary = Geometry::new(128 * 1024, PAGE)?;
    let geometries = core::array::from_fn::<_, PROTOTYPE_STACKS, _>(|index| {
        if index == 2 || (8..28).contains(&index) {
            kernel
        } else {
            ordinary
        }
    });
    let layout = MixedLayout::new(base, &geometries)?;
    if layout.virtual_bytes() > PROTOTYPE_WINDOW_BYTES {
        return Err(Error::Overflow);
    }
    Ok(layout)
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
    /// Optional bounded UP diagnostic pool; complete raw prefix/suffix remain owned.
    pub prototype_tasks: Region,
    pub prototype_task_plan: PrototypeTaskPlan,
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
            prototype_tasks: Region::default(),
            prototype_task_plan: PrototypeTaskPlan::Disabled,
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

/// The code and pool bytes the `cores - 1` workers keep while the BSP runs
/// every PE serialized. The loader adds them to the BSP's own share.
pub(crate) const fn serialized_reserve(cores: usize) -> (u64, u64) {
    let workers = cores.saturating_sub(1) as u64;
    (workers * WORKER_CODE, workers * WORKER_POOL)
}

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
    fn optional_mixed_plan_retains_exact_payload_padding_guards_and_classes() {
        let layout = prototype_tasks(0x9_0000_0000).unwrap();
        assert_eq!(layout.count(), 32);
        assert_eq!(layout.physical_bytes(), 1_785_856);
        assert_eq!(layout.raw_allocation_bytes(), 1_798_144);
        let mut counts = (0, 0);
        for index in 0..32 {
            let slot = layout.slot(index).unwrap();
            let bytes = slot.usable.end - slot.usable.start;
            if bytes == 16 * 1024 {
                counts.0 += 1;
                assert_eq!(slot.usable.start % (16 * 1024), 0);
            } else {
                assert_eq!(bytes, 128 * 1024);
                counts.1 += 1;
            }
            assert_eq!(slot.lower_guard.end, slot.usable.start);
            assert_eq!(slot.upper_guard.start, slot.usable.end);
        }
        assert_eq!(counts, (21, 11));
        assert!(layout.virtual_bytes() < PROTOTYPE_WINDOW_BYTES);
        let original = task_stacks();
        assert_eq!(original.count(), 16);
        assert_eq!(original.physical_bytes(), 16 * 128 * 1024);
    }
    #[test]
    fn private_arenas_have_no_overlap_or_fractional_ring_units() {
        for (cores, serialized) in (1..=MAX_CORES).flat_map(|cores| [(cores, false), (cores, true)])
        {
            let (code_reserve, pool_reserve) = if serialized {
                serialized_reserve(cores)
            } else {
                (0, 0)
            };
            let code = 128 * 1024 * 1024 + 127 + code_reserve;
            let pool = 64 * 1024 * 1024 + PAGE - 1 + pool_reserve;
            let mut previous_code = 0;
            let mut previous_pool = 0;
            for slot in 0..cores {
                let part = partition(cores, slot, code, pool, serialized).unwrap();
                assert_eq!(part.code_offset, previous_code);
                assert_eq!(part.pool_offset, previous_pool);
                assert_eq!(part.code_bytes % 128, 0);
                assert_eq!(part.pool_bytes % PAGE, 0);
                previous_code += part.code_bytes;
                previous_pool += part.pool_bytes;
            }
            assert!(previous_code <= code);
            assert!(previous_pool <= pool);
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
