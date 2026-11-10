//! The parts of Stela's memory sized from the host RAM free at boot (the
//! engine heap, native code arena and shadow page-table pool), the share
//! left for the guest, and what is left of it for the translation pack
//! (`docs/design/system.md#memory-sizing`).
use crate::Result;
use crate::native_resources::{CodeReservation, code_reservation, parked_reserve};
use stela_contracts::refuse;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
/// Each part's alignment: the large page the engine maps it with.
const ALIGNMENT: u64 = 2 * MIB;
/// What the heap needs does not shrink with the RAM, which bounds it from
/// below: a 26A434 desktop boot holds about 1.5 GiB live when WindowServer
/// compiles Core Animation's generic Vfx shader (`fixed_frag_lph_cpf` with
/// `fc_generic`, 42 529 NAK instructions in about 4800 blocks), whose
/// per-block liveness takes NAK another 450 MiB for the compile. That
/// peaked at 2150 MiB, and a boot with a fuller translation pack ran out of
/// a 2304 MiB heap there.
pub const HEAP_FLOOR: u64 = 2816 * MIB;
/// Above the floor, the heap grows with the host to this: a larger host
/// runs more and larger pipelines, apps and translation packs.
pub const HEAP_CEILING: u64 = 16 * GIB;
/// Free host RAM bytes per byte of the engine heap. A 16 GiB guest's first
/// Metal shader compiles carved all of a sixteenth (1816 MiB) and failed.
const HEAP_SHARE: u64 = 12;
/// Guest DRAM bytes per byte of each running executor's shadow page-table
/// pool: room for its 8 roots to map all of guest DRAM once in 4 KiB pages
/// (8 bytes per page). An exhausted half resets and refills everything; a
/// 26A434 restore's userland filled 8 MiB halves 20 to 80 times a beat.
const POOL_SHARE: u64 = 64;
const POOL_FLOOR: u64 = 64 * MIB;
/// Each running executor's pool maps at most 64 GiB of guest DRAM once;
/// past that its halves reset as a cache of the guest's working set,
/// rather than hold a tenth of a large host's RAM.
const POOL_PER_RUNNER: u64 = GIB;
/// The least guest DRAM Stela boots macOS with. Below it macOS spends its
/// time paging; 26A434 reaches the desktop with 3.1 GiB.
pub const GUEST_FLOOR: u64 = 3 * GIB;
/// The step [`Shortfall::needed`] is found in.
const NEEDED_STEP: u64 = 256 * MIB;
/// Free host RAM bytes per byte of the persistent translation pack the
/// loader may hold: a cache, it takes no more than this share and only what
/// the parts and the guest's floor leave.
pub const PACK_SHARE: u64 = 16;
/// The least pack worth reading. Below it the loader leaves the pack on its
/// volume, unread and unwritten, for a PC with more RAM.
pub const PACK_FLOOR: u64 = 64 * MIB;
/// What the loader takes between measuring the free RAM for the pack and
/// reserving the parts, beyond the pack itself: the pack's placement page,
/// the storage drivers' rings and the firmware ranges' rounding to 2 MiB.
const PACK_MARGIN: u64 = 16 * MIB;

/// The parts' sizes and the guest DRAM left after them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizes {
    pub heap: u64,
    pub code: CodeReservation,
    pub pool: u64,
    /// Free RAM after the three parts; Stela's stacks, tables and image
    /// take a few more MiB of it.
    pub guest: u64,
}

/// Too little RAM for the guest's floor: `free` bytes, of `needed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shortfall {
    pub free: u64,
    pub needed: u64,
}

impl Shortfall {
    /// The refusal the boot stops with, in whole GB rounded up, as RAM is
    /// sold, and the free RAM to a tenth.
    pub fn refusal(self) -> crate::Refusal {
        let needed = self.needed.div_ceil(GIB);
        let free = alloc::format!("{}.{}", self.free / GIB, self.free % GIB * 10 / GIB);
        let floor = GUEST_FLOOR / GIB;
        refuse!(
            "this PC has {free} GB of RAM free; Stela needs at least {needed} GB free: \
             {floor} GB for macOS and the rest for its own memory",
            free = %free,
            needed = %needed,
            floor = %floor
        )
    }
}

/// The sizes for `free` host bytes and `runners` of the `cores` executors
/// running PEs; the others add only their parked reserves.
///
/// Each part takes a share of `free`, between its bounds:
/// - the heap a twelfth, an eighth of that more for each runner after the
///   first (its machine's translation metadata), within
///   [`HEAP_FLOOR`]..=[`HEAP_CEILING`];
/// - the code arena what `code_reservation` gives;
/// - the pool each runner's 1/[`POOL_SHARE`] of the guest's DRAM, which is
///   what the other parts leave: `pool = runners * (free - heap - code -
///   pool) / 64`, solved for `pool`.
///
/// A guest share under [`GUEST_FLOOR`] is a [`Shortfall`].
pub fn sizes(free: u64, cores: usize, runners: usize) -> Result<Sizes> {
    let estimate = estimate(free, cores, runners)?;
    if estimate.guest >= GUEST_FLOOR {
        return Ok(estimate);
    }
    let mut needed = free.next_multiple_of(NEEDED_STEP);
    while estimate_guest(needed, cores, runners)? < GUEST_FLOOR {
        needed += NEEDED_STEP;
    }
    Err(Shortfall { free, needed }.refusal())
}

/// The bytes of persistent translation pack the loader may read for
/// `free` host bytes, measured just before it reads the pack, with
/// `runners` of `cores` executors running PEs: at most a
/// 1/[`PACK_SHARE`] of `free`, and only as much as still leaves [`sizes`]
/// the guest's floor, after the pack and a margin for the loader's other
/// allocations. Zero, below [`PACK_FLOOR`]: the parts and the guest come
/// first, and the pack never makes a boot fail.
pub fn pack_budget(free: u64, cores: usize, runners: usize) -> u64 {
    let mut budget = free / PACK_SHARE / ALIGNMENT * ALIGNMENT;
    while budget >= PACK_FLOOR {
        let left = free.saturating_sub(budget + PACK_MARGIN);
        if estimate_guest(left, cores, runners).is_ok_and(|guest| guest >= GUEST_FLOOR) {
            return budget;
        }
        budget -= ALIGNMENT;
    }
    0
}

fn estimate_guest(free: u64, cores: usize, runners: usize) -> Result<u64> {
    estimate(free, cores, runners).map(|sizes| sizes.guest)
}

fn estimate(free: u64, cores: usize, runners: usize) -> Result<Sizes> {
    let code = code_reservation(free, cores, runners)?;
    let running = runners as u64;
    let share = free / HEAP_SHARE;
    let heap = (share + (running - 1) * (share / 8)) / ALIGNMENT * ALIGNMENT;
    let heap = heap.clamp(HEAP_FLOOR, HEAP_CEILING);
    let rest = free.saturating_sub(heap).saturating_sub(code.bytes);
    let pool = (u128::from(running) * u128::from(rest) / u128::from(POOL_SHARE + running)) as u64;
    let pool = (pool / ALIGNMENT * ALIGNMENT).clamp(POOL_FLOOR, running * POOL_PER_RUNNER);
    let (_, parked) = parked_reserve(cores, runners);
    let pool = pool + parked;
    Ok(Sizes {
        heap,
        code,
        pool,
        guest: rest.saturating_sub(pool),
    })
}

#[cfg(test)]
mod tests;
