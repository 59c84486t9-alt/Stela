//! The parts of Stela's memory sized from the host RAM free at boot (the
//! engine heap, native code arena and shadow page-table pool), the share
//! left for the guest, and what is left of it for the translation pack
//! (`docs/design/system.md#memory-sizing`).
use crate::Result;
use crate::native_resources::{
    CodeReservation, SMALL_WINDOW_PER_RUNNER, WINDOW_PER_RUNNER, code_reservation_per_runner,
    parked_reserve,
};
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
/// Free host RAM bytes per byte of the engine heap's base share. A 16 GiB
/// guest's first Metal shader compiles carved all of a sixteenth (1816 MiB)
/// and failed.
const HEAP_SHARE: u64 = 12;
/// Heap bytes per byte of the board's code window: the shared block records,
/// successors, recovery rows, index and lookup of the blocks it holds,
/// once for the board since the block store is shared. An 8-PE 26A434
/// boot with a full 448 MiB window (1.56 million of 1.69 million slots
/// live) held 437 MiB of them (`ENGINE MEMORY blocks=231M successors=53M
/// rows=14M index=19M lookup=120M`), 0.98 bytes per window byte. Before
/// the shared store each core kept its own, 2.9 bytes per byte.
const HEAP_PER_WINDOW: u64 = 1;
/// The code window [`HEAP_FLOOR`] was measured with. A larger window raises
/// the floor by [`HEAP_PER_WINDOW`] per byte past it: its block records
/// come on top of the peak the floor holds.
const FLOOR_WINDOW: u64 = 512 * MIB;
/// Heap each running PE keeps for itself: its machine (about 1 MiB at
/// start), ITLB (512 KiB), fetch and jump caches (about 0.8 MiB) and
/// successor scratch (under 1 MiB); four times that, for its own compiles.
const PE_HEAP: u64 = 16 * MIB;
/// Guest DRAM bytes per byte of a running executor's shadow page-table
/// pool: room for its 8 roots to map all of guest DRAM once in 4 KiB pages
/// (8 bytes per page). An exhausted half resets and refills everything; a
/// 26A434 restore's userland filled 8 MiB halves 20 to 80 times a beat.
const POOL_SHARE: u64 = 64;
/// Runners whose pools together map the guest's DRAM once each. Past them
/// the runners divide that total: each PE's tables are a cache of what it
/// touches, and more PEs divide the guest's working set between them.
const POOL_SHARERS: u64 = 8;
const POOL_FLOOR: u64 = 64 * MIB;
/// The least pool a running executor gets, a 16 MiB half, at any PE count.
const POOL_RUNNER_FLOOR: u64 = 32 * MIB;
/// Each sharer's pool maps at most 64 GiB of guest DRAM once; past that its
/// halves reset as a cache of the guest's working set, rather than hold a
/// tenth of a large host's RAM.
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

/// The DRAM the guest Mac reports and the host RAM it does not see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestDram {
    /// `/chosen dram-size` and `boot_args.memSizeActual`.
    pub reported: u64,
    /// Installed host RAM that Stela and the firmware keep.
    pub kept: u64,
}

/// The guest reports the DRAM that backs it, `backed` bytes, not the
/// host's `installed` RAM.
///
/// XNU sets `max_mem_actual` from `memSizeActual` and `max_mem` and
/// `sane_size` from `memSize` (the managed range). `hw.memsize` reads
/// `max_mem_actual`; `hw.memsize_usable` reads `max_mem`. User space
/// (`NSProcessInfo.physicalMemory`, Metal's working-set size, jetsam
/// limits, cache sizes) uses `hw.memsize`. A reported size above what
/// exists makes it plan for memory that is not there: a 26A434 boot with
/// 3.9 GB backed and 8 GB reported ran its compressor and pager at full
/// load after login. On a Mac the gap is iBoot's carveouts, a few percent;
/// here those carveouts lie inside the backed range (`memSize` excludes
/// them), so the backed size is the truthful `max_mem_actual`.
pub fn guest_dram(installed: u64, backed: u64) -> GuestDram {
    GuestDram {
        reported: backed,
        kept: installed.saturating_sub(backed),
    }
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
/// - the heap a twelfth, [`HEAP_PER_WINDOW`] byte per byte of the board's
///   code window and [`PE_HEAP`] per runner, within
///   [`HEAP_FLOOR`]..=[`HEAP_CEILING`], the floor raised by the window past
///   [`FLOOR_WINDOW`];
/// - the code arena what `code_reservation` gives: [`WINDOW_PER_RUNNER`]
///   per runner within free RAM / 16, or [`SMALL_WINDOW_PER_RUNNER`] where
///   the larger window would leave the guest under its floor;
/// - the pool 1/[`POOL_SHARE`] of the guest's DRAM for each of up to
///   [`POOL_SHARERS`] runners, which is what the other parts leave: `pool =
///   sharers * (free - heap - code - pool) / 64`, solved for `pool`; at least
///   [`POOL_RUNNER_FLOOR`] per runner, at most [`POOL_PER_RUNNER`] per sharer.
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

/// The sizes with the larger code window per runner, or with the smaller
/// one where the larger would leave the guest under its floor.
fn estimate(free: u64, cores: usize, runners: usize) -> Result<Sizes> {
    let large = estimate_with(free, cores, runners, WINDOW_PER_RUNNER)?;
    if large.guest >= GUEST_FLOOR {
        return Ok(large);
    }
    estimate_with(free, cores, runners, SMALL_WINDOW_PER_RUNNER)
}

fn estimate_with(free: u64, cores: usize, runners: usize, per_runner: u64) -> Result<Sizes> {
    let code = code_reservation_per_runner(free, cores, runners, per_runner)?;
    let running = runners as u64;
    let heap = free / HEAP_SHARE + HEAP_PER_WINDOW * code.window + running * PE_HEAP;
    let floor = HEAP_FLOOR + HEAP_PER_WINDOW * code.window.saturating_sub(FLOOR_WINDOW);
    let heap = (heap / ALIGNMENT * ALIGNMENT).clamp(floor, HEAP_CEILING.max(floor));
    let rest = free.saturating_sub(heap).saturating_sub(code.bytes);
    let sharers = running.min(POOL_SHARERS);
    let pool = (u128::from(sharers) * u128::from(rest) / u128::from(POOL_SHARE + sharers)) as u64;
    let pool = (pool / ALIGNMENT * ALIGNMENT).clamp(
        POOL_FLOOR.max(running * POOL_RUNNER_FLOOR),
        sharers * POOL_PER_RUNNER,
    );
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
