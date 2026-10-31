//! Stack geometry and the per-executor partition of the code arena and
//! shadow pool. Each executor owns its own ranges; none is shared.
use crate::Result;
use crate::topology::MAX_CORES;
use stela_contracts::refuse;

const PAGE: u64 = 4096;

pub const STACK_BYTES: u64 = 2 * 1024 * 1024;
pub const STACK_STRIDE: u64 = STACK_BYTES + PAGE;
pub const INVOCATION_STACK_BYTES: u64 = 128 * 1024;
pub const TASK_STACK_BYTES: u64 = 128 * 1024;
pub const TASK_STACKS: usize = 16;

pub fn invocation_stacks(
    cores: usize,
) -> Result<crate::guarded_stacks::Layout, crate::guarded_stacks::Error> {
    crate::guarded_stacks::Layout::new(INVOCATION_STACK_BYTES, cores)
}
pub fn task_stacks() -> crate::guarded_stacks::Layout {
    crate::guarded_stacks::Layout::new(TASK_STACK_BYTES, TASK_STACKS)
        .expect("constant guarded task-stack geometry")
}

/// Explicit diagnostic reservation metadata, never a task/current grant.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrototypeTaskPlan {
    #[default]
    Disabled = 0,
    FirmwarePrototype32Mixed = 1,
}
pub const PROTOTYPE_STACKS: usize = 32;
pub const PROTOTYPE_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
pub fn prototype_tasks(
    base: u64,
) -> Result<crate::guarded_stacks::MixedLayout, crate::guarded_stacks::Error> {
    use crate::guarded_stacks::{Error, Geometry, MixedLayout};
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

#[derive(Debug, PartialEq, Eq)]
pub struct Partition {
    pub code_offset: u64,
    pub code_bytes: u64,
    pub pool_offset: u64,
    pub pool_bytes: u64,
}

/// What an executor that runs no PE keeps of the code arena and shadow pool.
const PARKED_CODE: u64 = 4 * 1024 * 1024;
const PARKED_POOL: u64 = 4 * 1024 * 1024;

/// The code and pool bytes the executors past the `runners` of `cores` keep.
/// The loader adds them to the runners' own shares.
pub const fn parked_reserve(cores: usize, runners: usize) -> (u64, u64) {
    let parked = cores.saturating_sub(runners) as u64;
    (parked * PARKED_CODE, parked * PARKED_POOL)
}

/// Divide only whole frames/code ring units; unused tail bytes remain owned
/// by the allocation and cannot be lent to a second executor. The first
/// `runners` executors run PEs and share alike all but the others'
/// [`PARKED_CODE`] and [`PARKED_POOL`].
pub fn partition(
    cores: usize,
    runners: usize,
    slot: usize,
    code: u64,
    pool: u64,
) -> Result<Partition> {
    if cores == 0 || cores > MAX_CORES || slot >= cores || runners == 0 || runners > cores {
        return Err(refuse!("invalid native executor slot"));
    }
    let parked = (cores - runners) as u64;
    let share = |total: u64, reserve: u64, unit: u64| {
        total.saturating_sub(parked * reserve) / runners as u64 / unit * unit
    };
    // Each host ring has eight 16-byte-aligned code units. Each shadow pool
    // needs 64 permanent root frames and at least one frame in each half.
    let (code_share, pool_share) = (
        share(code, PARKED_CODE, 128),
        share(pool, PARKED_POOL, PAGE),
    );
    let (code_bytes, pool_bytes, code_offset, pool_offset) = match slot.checked_sub(runners) {
        None => (
            code_share,
            pool_share,
            slot as u64 * code_share,
            slot as u64 * pool_share,
        ),
        Some(behind) => (
            PARKED_CODE,
            PARKED_POOL,
            runners as u64 * code_share + behind as u64 * PARKED_CODE,
            runners as u64 * pool_share + behind as u64 * PARKED_POOL,
        ),
    };
    if code_bytes < 128 || pool_bytes < 66 * PAGE {
        return Err(refuse!("native executor resources too small"));
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
    fn optional_mixed_plan_keeps_exact_payload_padding_guards_and_classes() {
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
        for (cores, runners) in
            (1..=MAX_CORES).flat_map(|cores| [(cores, cores), (cores, 1), (cores, cores.min(8))])
        {
            let (code_reserve, pool_reserve) = parked_reserve(cores, runners);
            let code = 128 * 1024 * 1024 + 127 + code_reserve;
            let pool = 64 * 1024 * 1024 + PAGE - 1 + pool_reserve;
            let mut previous_code = 0;
            let mut previous_pool = 0;
            for slot in 0..cores {
                let part = partition(cores, runners, slot, code, pool).unwrap();
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
        let bsp = partition(8, 1, 0, code, pool).unwrap();
        assert_eq!(bsp.code_bytes, code - 7 * PARKED_CODE);
        assert_eq!(bsp.pool_bytes, pool - 7 * PARKED_POOL);
        let last = partition(8, 1, 7, code, pool).unwrap();
        assert_eq!(last.code_offset + last.code_bytes, code);
        assert_eq!(last.pool_offset + last.pool_bytes, pool);
    }

    /// A host with more cores than the guest has PEs parks the rest, which
    /// take no share.
    #[test]
    fn cores_past_the_guests_pes_keep_only_a_reserve() {
        let (code, pool) = (56 * PARKED_CODE + (8 << 28), 56 * PARKED_POOL + (8 << 28));
        let share = 1 << 28;
        let first = partition(64, 8, 7, code, pool).unwrap();
        assert_eq!((first.code_bytes, first.pool_bytes), (share, share));
        assert_eq!(first.code_offset, 7 * share);
        let parked = partition(64, 8, 8, code, pool).unwrap();
        assert_eq!(
            (parked.code_bytes, parked.pool_bytes),
            (PARKED_CODE, PARKED_POOL)
        );
        assert_eq!(parked.code_offset, 8 * share);
        let last = partition(64, 8, 63, code, pool).unwrap();
        assert_eq!(last.code_offset + last.code_bytes, code);
    }

    #[test]
    fn unavailable_slots_and_insufficient_private_roots_refuse() {
        for (cores, runners, slot) in [
            (0, 1, 0),
            (MAX_CORES + 1, 1, 0),
            (2, 2, 2),
            (2, 0, 0),
            (2, 3, 0),
        ] {
            assert!(partition(cores, runners, slot, 1024, 1024 * PAGE).is_err());
        }
        assert!(partition(2, 2, 0, 255, 1024 * PAGE).is_err());
        assert!(partition(2, 2, 0, 1024, 132 * PAGE - 1).is_err());
        assert!(partition(2, 2, 0, 256, 132 * PAGE).is_ok());
        assert!(partition(2, 1, 0, 256, 132 * PAGE).is_err());
    }
}
