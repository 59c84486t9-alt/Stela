//! Stack geometry and the per-executor partition of the code arena and
//! shadow pool. Each executor owns its own ranges; none is shared.
use crate::Result;
use crate::topology::MAX_CORES;
use alloc::vec::Vec;
use core::ops::Range;
use stela_contracts::refuse;

const PAGE: u64 = 4096;
const MIB: u64 = 1024 * 1024;

pub const STACK_BYTES: u64 = 2 * 1024 * 1024;
pub const STACK_STRIDE: u64 = STACK_BYTES + PAGE;
pub const INVOCATION_STACK_BYTES: u64 = 128 * 1024;
pub const CODE_INSTALL_ALIGNMENT: u64 = 16;

/// Initialized code extents of one private arena part, stored by exclusive
/// end. Installs start at the aligned end of the preceding one, so retaining
/// that start as well would duplicate information.
#[derive(Default)]
pub struct CodeExtents(Vec<u32>);

impl CodeExtents {
    /// Reserve one ledger entry, initialize its code, then record the extent.
    /// A refusal leaves both the ledger and its code unchanged.
    pub fn append(
        &mut self,
        part_bytes: u64,
        code_bytes: usize,
        initialize: impl FnOnce(u64),
    ) -> Option<Range<u64>> {
        let previous = u64::from(self.0.last().copied().unwrap_or(0));
        let start = previous.next_multiple_of(CODE_INSTALL_ALIGNMENT);
        let end = start.checked_add(code_bytes as u64)?;
        if code_bytes == 0 || end > part_bytes {
            return None;
        }
        let finish = u32::try_from(end).ok()?;
        self.0.try_reserve(1).ok()?;
        initialize(start);
        self.0.push(finish);
        Some(start..end)
    }

    /// Whether one install owns the whole part-relative interval. Alignment
    /// gaps and spans across separately initialized installs are refused.
    pub fn contains(&self, range: Range<u64>) -> bool {
        if range.is_empty() {
            return false;
        }
        let index = self.0.partition_point(|&end| u64::from(end) <= range.start);
        self.0.get(index).is_some_and(|&end| {
            let previous = if index == 0 { 0 } else { self.0[index - 1] };
            let start = u64::from(previous).next_multiple_of(CODE_INSTALL_ALIGNMENT);
            start <= range.start && range.end <= u64::from(end)
        })
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Forget a part's code when the ring reuses it, keeping the ledger's
    /// capacity ready for new code.
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

pub fn invocation_stacks(
    cores: usize,
) -> Result<crate::guarded_stacks::Layout, crate::guarded_stacks::Error> {
    crate::guarded_stacks::Layout::new(INVOCATION_STACK_BYTES, cores)
}

/// The BSP's work pool holds as many stacks as its executor can.
pub const TASK_STACKS: usize = stela_driver_base::platform::work::MAX_CONTINUATIONS;
/// General workers on ordinary stacks, for native driver probes.
pub const ORDINARY_GENERAL_TASKS: usize = 4;
/// General workers on Linux task stacks: every General stack but the ordinary
/// ones. Each Linux kthread, ioctl worker and driver thread holds one.
pub const KERNEL_GENERAL_TASKS: usize =
    TASK_STACKS - stela_driver_base::platform::work::ROLE_STACKS - ORDINARY_GENERAL_TASKS;
/// An ordinary task's Rust stack. Native driver probes run on one, through
/// controller attach paths whose frames alone pass 128 KiB.
pub const ORDINARY_TASK_STACK_BYTES: u64 = 1024 * 1024;
pub const TASK_WINDOW_BYTES: u64 = 32 * 1024 * 1024;
/// The BSP's work pool. A Linux task runs only on a stack of exactly its
/// configured size and alignment, so the service and the kernel General
/// continuations have that shape; the other roles and the last
/// [`ORDINARY_GENERAL_TASKS`] keep generic stacks.
pub fn task_stacks(
    base: u64,
) -> Result<crate::guarded_stacks::MixedLayout, crate::guarded_stacks::Error> {
    use crate::guarded_stacks::{Error, Geometry, MixedLayout};
    let kernel = Geometry::new(16 * 1024, 16 * 1024)?;
    let ordinary = Geometry::new(ORDINARY_TASK_STACK_BYTES, PAGE)?;
    let geometries = core::array::from_fn::<_, TASK_STACKS, _>(|index| {
        let roles = stela_driver_base::platform::work::ROLE_STACKS;
        if index == 2 || (roles..roles + KERNEL_GENERAL_TASKS).contains(&index) {
            kernel
        } else {
            ordinary
        }
    });
    let layout = MixedLayout::new(base, &geometries)?;
    if layout.virtual_bytes() > TASK_WINDOW_BYTES {
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

const MIN_RUNNING_CODE: u64 = 128 * MIB;
const MAX_RUNNING_CODE: u64 = 512 * MIB;
/// Native code also carries recovery and lookup data in the engine heap.
const CODE_SHARE: u64 = 128;
/// Preserve the existing aggregate share of a 32-executor roster.
const CODE_AGGREGATE_SHARE: u64 = CODE_SHARE / 32;
const CODE_ALIGNMENT: u64 = 16 * MIB;
pub const MAX_CODE_PARTS: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeReservation {
    pub bytes: u64,
    pub parts: u32,
}

/// The aligned bytes in an install/eviction part. Reduced rings cover
/// their whole private arena; a legacy ring can leave a rounding tail.
pub fn code_part_bytes(bytes: u64, parts: u32) -> Result<u64> {
    if parts == MAX_CODE_PARTS {
        // Legacy partition callers can leave an unused sub-alignment tail.
        // Retain their established aligned unit calculation.
        return Ok(bytes / u64::from(parts) / CODE_INSTALL_ALIGNMENT * CODE_INSTALL_ALIGNMENT);
    }
    if !(2..MAX_CODE_PARTS).contains(&parts)
        || bytes == 0
        || !bytes.is_multiple_of(u64::from(parts) * CODE_INSTALL_ALIGNMENT)
    {
        return Err(refuse!("invalid native code ring geometry"));
    }
    Ok(bytes / u64::from(parts))
}

/// The executable window holds the largest reservation the loader can make.
/// Each active slot contributes at most `MAX_RUNNING_CODE`. The rounded
/// parked tail fits in what those slots would contribute when active.
pub const CODE_WINDOW_BYTES: u64 = MAX_CORES as u64 * MAX_RUNNING_CODE;

/// The code and pool bytes the executors past the `runners` of `cores` keep.
/// The loader adds them to the runners' own shares.
pub const fn parked_reserve(cores: usize, runners: usize) -> (u64, u64) {
    let parked = cores.saturating_sub(runners) as u64;
    (parked * PARKED_CODE, parked * PARKED_POOL)
}

/// The firmware code allocation, including the aligned parked tail, checked
/// before any firmware pages are reserved.
pub fn code_reservation(free: u64, cores: usize, runners: usize) -> Result<CodeReservation> {
    if cores == 0 || cores > MAX_CORES || runners == 0 || runners > cores {
        return Err(refuse!("invalid native executor count"));
    }
    let per_runner = (free / CODE_SHARE / CODE_ALIGNMENT * CODE_ALIGNMENT)
        .clamp(MIN_RUNNING_CODE, MAX_RUNNING_CODE);
    let part_bytes = per_runner / u64::from(MAX_CODE_PARTS);
    // Keep the original maximum single-install size. Exact active rosters
    // reduce part count when the old aggregate exceeds the budget of 32
    // legacy shares, retaining the original per-owner capacity floor.
    let parts = if cores == runners {
        let budget = free / CODE_AGGREGATE_SHARE / runners as u64;
        (budget / part_bytes).clamp(
            MIN_RUNNING_CODE.div_ceil(part_bytes),
            u64::from(MAX_CODE_PARTS),
        ) as u32
    } else {
        MAX_CODE_PARTS
    };
    let parked = parked_reserve(cores, runners)
        .0
        .next_multiple_of(CODE_ALIGNMENT);
    let bytes = part_bytes * u64::from(parts) * runners as u64 + parked;
    if bytes > CODE_WINDOW_BYTES {
        return Err(refuse!(
            "native code reservation exceeds its executable window"
        ));
    }
    Ok(CodeReservation { bytes, parts })
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
    // Each host ring uses 16-byte-aligned code units. Each shadow pool
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
    fn code_reservations_preserve_smaller_rosters_and_parked_budgets() {
        for (free, cores, runners, expected) in [
            (8 * 1024, 8, 8, 1024),
            (8 * 1024, 64, 8, 1248),
            (64 * 1024, 64, 8, 4320),
            (64 * 1024, 9, 8, 4112),
            (32 * 1024, 32, 32, 8 * 1024),
            (128 * 1024, 64, 64, 32 * 1024),
        ] {
            assert_eq!(
                code_reservation(free * MIB, cores, runners).unwrap(),
                CodeReservation {
                    bytes: expected * MIB,
                    parts: MAX_CODE_PARTS,
                },
            );
        }
        for (cores, runners) in [(0, 0), (1, 0), (2, 3), (MAX_CORES + 1, 1)] {
            assert!(code_reservation(0, cores, runners).is_err());
        }
    }

    #[test]
    fn legacy_parked_partition_keeps_its_aligned_ring_units() {
        let code = code_reservation(32 * 1024 * MIB, 5, 3).unwrap();
        let owner = partition(5, 3, 0, code.bytes, 64 * MIB).unwrap();
        assert_eq!(owner.code_bytes, 271_231_616);
        assert_eq!(owner.code_bytes % 512, 128);
        assert_eq!(
            code_part_bytes(owner.code_bytes, code.parts).unwrap(),
            owner.code_bytes / 512 * 16,
        );
    }

    #[test]
    fn larger_exact_rosters_reduce_part_count_without_reducing_install_size() {
        for (free, cores, bytes, parts, part_mib) in [
            (32 * 1024, 48, 8064, 21, 8),
            (32 * 1024, 64, 8 * 1024, 16, 8),
            (64 * 1024, 64, 16 * 1024, 16, 16),
        ] {
            let code = code_reservation(free * MIB, cores, cores).unwrap();
            assert_eq!(
                code,
                CodeReservation {
                    bytes: bytes * MIB,
                    parts
                }
            );
            let partition = partition(cores, cores, cores - 1, code.bytes, 2048 * MIB).unwrap();
            let part_bytes = code_part_bytes(partition.code_bytes, code.parts).unwrap();
            assert_eq!(part_bytes, part_mib * MIB);
            assert_eq!(partition.code_offset + partition.code_bytes, code.bytes);
            let mut empty = CodeExtents::default();
            assert!(
                empty
                    .append(part_bytes, part_bytes as usize + 1, |_| panic!())
                    .is_none()
            );
            assert_eq!(
                empty.append(part_bytes, part_bytes as usize, |_| {}),
                Some(0..part_bytes)
            );
        }
        assert!(code_part_bytes(16 * MIB, 0).is_err());
        assert!(code_part_bytes(16 * MIB, MAX_CODE_PARTS + 1).is_err());
        assert!(code_part_bytes(16 * MIB - 1, 16).is_err());
        assert_eq!(
            code_part_bytes(16 * MIB - 1, MAX_CODE_PARTS).unwrap(),
            512 * 1024 - 16
        );
    }

    #[test]
    fn all_supported_code_partitions_fit_inside_the_executable_window() {
        for cores in 1..=MAX_CORES {
            for runners in 1..=cores {
                for free in [
                    0,
                    8 * 1024 * MIB,
                    18 * 1024 * MIB,
                    24 * 1024 * MIB,
                    64 * 1024 * MIB,
                    u64::MAX,
                ] {
                    let code = code_reservation(free, cores, runners).unwrap();
                    let pool = 64 * MIB + parked_reserve(cores, runners).1;
                    let first = partition(cores, runners, 0, code.bytes, pool).unwrap();
                    let last = partition(cores, runners, cores - 1, code.bytes, pool).unwrap();
                    assert_eq!(first.code_offset, 0);
                    assert_eq!(code.bytes % PAGE, 0);
                    assert!(last.code_offset + last.code_bytes <= code.bytes);
                    assert!(code.bytes <= CODE_WINDOW_BYTES);
                    if cores == runners {
                        let original = (free / CODE_SHARE / CODE_ALIGNMENT * CODE_ALIGNMENT)
                            .clamp(MIN_RUNNING_CODE, MAX_RUNNING_CODE);
                        let part_bytes = code_part_bytes(first.code_bytes, code.parts).unwrap();
                        assert_eq!(part_bytes, original / u64::from(MAX_CODE_PARTS));
                        assert!(first.code_bytes >= MIN_RUNNING_CODE);
                        assert!(first.code_bytes <= original);
                        assert_eq!(last.code_offset + last.code_bytes, code.bytes);
                        let floor =
                            MIN_RUNNING_CODE.div_ceil(part_bytes) * part_bytes * cores as u64;
                        assert!(code.bytes <= (free / CODE_AGGREGATE_SHARE).max(floor));
                        if cores <= 32 {
                            assert_eq!(code.parts, MAX_CODE_PARTS);
                            assert_eq!(first.code_bytes, original);
                        }
                    } else {
                        assert_eq!(code.parts, MAX_CODE_PARTS);
                        assert_eq!(code.bytes % CODE_ALIGNMENT, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn installed_code_extents_cover_only_individual_initialized_ranges() {
        let mut ledger = CodeExtents::default();
        let mut exact = Vec::new();
        for bytes in [13, 16, 2, 9, 25, 1] {
            let start = exact.last().map_or(0, |range: &Range<u64>| {
                range.end.next_multiple_of(CODE_INSTALL_ALIGNMENT)
            });
            let range = ledger
                .append(128, bytes, |at| assert_eq!(at, start))
                .unwrap();
            assert_eq!(range, start..start + bytes as u64);
            exact.push(range);
        }
        for start in 0..=128 {
            for end in start..=129 {
                let expected = start < end
                    && exact
                        .iter()
                        .any(|extent| extent.start <= start && end <= extent.end);
                assert_eq!(ledger.contains(start..end), expected, "{start}..{end}");
            }
        }
        ledger.clear();
        assert!(ledger.is_empty());
        assert!(!ledger.contains(0..1));
        assert_eq!(ledger.append(64, 7, |_| {}), Some(0..7));
    }

    #[test]
    fn refused_code_installs_leave_the_end_and_backing_untouched() {
        let mut ledger = CodeExtents::default();
        assert_eq!(ledger.append(32, 13, |_| {}), Some(0..13));
        assert_eq!(ledger.append(32, 0, |_| panic!("empty code")), None);
        assert_eq!(ledger.append(32, 17, |_| panic!("over the part")), None);
        assert_eq!(
            ledger.append(u64::MAX, u32::MAX as usize, |_| panic!("over the ledger")),
            None
        );
        assert_eq!(ledger.append(32, 16, |_| {}), Some(16..32));
        assert!(!ledger.contains(13..16));
        assert!(ledger.contains(16..32));
    }

    #[test]
    fn task_plan_keeps_exact_payload_padding_guards_and_classes() {
        let layout = task_stacks(0x8_0000_0000).unwrap();
        let (kernel, ordinary) = (
            KERNEL_GENERAL_TASKS + 1,
            TASK_STACKS - KERNEL_GENERAL_TASKS - 1,
        );
        assert_eq!(layout.count(), TASK_STACKS);
        assert_eq!(
            layout.physical_bytes(),
            kernel as u64 * 16 * 1024 + ordinary as u64 * ORDINARY_TASK_STACK_BYTES
        );
        assert_eq!(
            layout.raw_allocation_bytes(),
            layout.physical_bytes() + 12_288
        );
        let mut counts = (0, 0);
        for index in 0..TASK_STACKS {
            let slot = layout.slot(index).unwrap();
            let bytes = slot.usable.end - slot.usable.start;
            if bytes == 16 * 1024 {
                counts.0 += 1;
                assert_eq!(slot.usable.start % (16 * 1024), 0);
            } else {
                assert_eq!(bytes, ORDINARY_TASK_STACK_BYTES);
                counts.1 += 1;
            }
            assert_eq!(slot.lower_guard.end, slot.usable.start);
            assert_eq!(slot.upper_guard.start, slot.usable.end);
        }
        assert_eq!(counts, (kernel, ordinary));
        assert!(layout.virtual_bytes() < TASK_WINDOW_BYTES);
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
