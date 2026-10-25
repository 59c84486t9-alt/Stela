//! The bare-metal [`Host`]: guest RAM, the native code arena, shadow paging,
//! precise native faults, the local APIC timer and the TSC counter.
//!
//! Shadow roots are PML5 pages under LA57 and PML4 pages otherwise, whose
//! entries hold the guest's native ranges and the shared window
//! (`layout::window_entries`), which native code's guest range checks keep
//! every guest access out of; no other entry is ever mapped, which those
//! checks rely on. There is one root per
//! permission view (EL0, EL1, EL1 with PAN, GL1), and a second set for the
//! same views while tag checks keep Tagged memory out (`Regime::tag_checks`),
//! filled on demand by the #PF handler from the software walk of the
//! guest's tables, a window of the guest leaf per fault. The views but
//! EL0's keep their roots of a few SPRR_PERM_EL1 values (`Bank`). Each half
//! takes its tables from its own part of the pool, so a change of TTBR0
//! alone (a context switch) drops the lower half and keeps the upper
//! half's, and records the leaves it was filled from
//! (`mmu::shadow::Extents`), so a TLBI unmaps only the ranges it reaches.
use super::interrupts::{Frame, SPURIOUS_VECTOR, TIMER_VECTOR};
use crate::{
    apic::{self, Apic},
    layout,
    tables::{self, Frames, NX, PAGE, PRESENT, WRITABLE},
};
use alloc::{sync::Arc, vec::Vec};
use core::arch::{asm, global_asm};
use stela_compiler::{GuestState, block::BlockExit};
use stela_runtime::machine::engine::installed_code::InstalledCodeCache;
use stela_runtime::machine::{
    FaultCause, Host, InstallError, NativeCode, NativeExit, NativeFault, Regime,
    mmu::{
        self, Access, Outcome,
        placement::Placement,
        shadow::{self, Extents},
        tlbi::Reach,
        translated::Tlb,
    },
};

pub(crate) mod fp_diagnostic;
pub(super) mod local;
#[cfg(feature = "native-profile")]
mod profile;
mod ram;
mod translated;
pub(crate) use local::Owner as HostOwner;
use local::state;
pub use ram::RamRange;

/// Page-table frames from the handoff pool: a permanent part for roots and a
/// shadow part, split between the guest's two halves, each of which resets
/// wholesale.
struct Pool {
    base: u64,
    bytes: u64,
    permanent: u64,
    /// The next free shadow frame's offset of each half ([`LOWER`],
    /// [`UPPER`]).
    shadow: [u64; 2],
    /// First shadow frame.
    shadow_base: u64,
    /// The half the next frames map.
    half: usize,
    /// The most bytes of shadow frames each half has held at once.
    peak: [u64; 2],
}

/// The guest halves: VAs with bit 63 clear and set.
const LOWER: usize = 0;
const UPPER: usize = 1;

impl Frames for Pool {
    fn frame(&mut self) -> Option<u64> {
        let (_, end) = self.range(self.half);
        if self.shadow[self.half] + PAGE > end {
            return None;
        }
        let frame = self.base + self.shadow[self.half];
        self.shadow[self.half] += PAGE;
        let used = self.shadow[self.half] - self.range(self.half).0;
        self.peak[self.half] = self.peak[self.half].max(used);
        zero(frame);
        Some(frame)
    }
    fn table(&self, physical: u64) -> *mut u64 {
        layout::physical(physical) as *mut u64
    }
}

fn zero(frame: u64) {
    // SAFETY: a pool frame reached through the physmap.
    unsafe { (layout::physical(frame) as *mut u8).write_bytes(0, PAGE as usize) };
}

impl Pool {
    fn permanent(&mut self) -> Option<u64> {
        if self.permanent + PAGE > self.shadow_base - self.base {
            return None;
        }
        let frame = self.base + self.permanent;
        self.permanent += PAGE;
        zero(frame);
        Some(frame)
    }
    /// The offsets of `half`'s shadow frames: the lower half of the shadow
    /// part, or the upper.
    fn range(&self, half: usize) -> (u64, u64) {
        let start = self.shadow_base - self.base;
        let middle = start + (self.bytes - start) / 2 / PAGE * PAGE;
        if half == LOWER {
            (start, middle)
        } else {
            (middle, self.bytes)
        }
    }
    fn reset_half(&mut self, half: usize) {
        self.shadow[half] = self.range(half).0;
    }
}

/// Permission views; the tag-checked roots follow the unchecked ones.
const VIEWS: usize = 4;
/// EL0's view (GL0's too), EL1's, EL1's with PAN, and the GXF guarded
/// level's (GL1).
const EL0_VIEW: usize = 0;
const EL1_VIEW: usize = 1;
const PAN_VIEW: usize = 2;
const GUARDED_VIEW: usize = 3;
/// Why the whole shadow was reset: a half ran out of frames; controls
/// that differ in SPRR state alone (more than its permission registers),
/// in TTBR0 alone (with an ASID the upper half's non-global entries were
/// made under), or otherwise; another
/// pattern of tag-checked halves; [`Host::invalidate_translations`]; or a
/// TLBI that reaches everything.
#[derive(Clone, Copy)]
enum Cause {
    Exhausted,
    Sprr,
    Table,
    Controls,
    Tags,
    Invalidated,
    Maintained,
}
const CAUSES: usize = 7;
/// The TCR fields of the EL1&0 and EL2&0 regimes that configure TTBR0's
/// range alone: T0SZ, EPD0, IRGN0, ORGN0, SH0, TG0 (bits 15:0), TBI0, HPD0,
/// TBID0, NFD0, E0PD0 and TCMA0.
const LOWER_TCR: u64 = 0xffff | 1 << 37 | 1 << 41 | 1 << 51 | 1 << 53 | 1 << 55 | 1 << 57;
/// The TCR field of those regimes that decides EL0's accesses to TTBR1's
/// range alone: E0PD1, which faults them without a walk.
const USER_TCR: u64 = 1 << 56;
/// The [`mmu::Controls`] fields a [`Cause::Controls`] reset counts as
/// differing: SCTLR, TCR, TTBR0, TTBR1, MAIR, SPRR, CTRR, the regime and
/// stage 2 (its requirement or controls).
const FIELDS: usize = 9;

fn differing(from: &mmu::Controls, to: &mmu::Controls) -> [bool; FIELDS] {
    [
        from.sctlr != to.sctlr,
        from.tcr != to.tcr,
        from.ttbr0 != to.ttbr0,
        from.ttbr1 != to.ttbr1,
        from.mair != to.mair || from.xs != to.xs || from.tagged != to.tagged,
        from.sprr != to.sprr,
        from.ctrr != to.ctrr,
        from.regime != to.regime,
        from.stage2 != to.stage2 || from.second_stage != to.second_stage,
    ]
}

/// The views whose rights SPRR_PERM_EL0 decides: EL0's, and EL1's with
/// PAN, which loses data access where EL0 has any
/// (`mmu::sprr::permissions`).
const USER_VIEWS: [usize; 2] = [EL0_VIEW, PAN_VIEW];
/// The views whose rights SPRR_PERM_EL1 decides: all but EL0's.
const KERNEL_VIEWS: [usize; 3] = [EL1_VIEW, PAN_VIEW, GUARDED_VIEW];
/// The roots of the [`KERNEL_VIEWS`], tag-checked ones after the others.
const KERNEL_ROOTS: [usize; 6] = [
    EL1_VIEW,
    PAN_VIEW,
    GUARDED_VIEW,
    VIEWS + EL1_VIEW,
    VIEWS + PAN_VIEW,
    VIEWS + GUARDED_VIEW,
];
/// The SPRR_PERM_EL1 values whose kernel roots the shadow keeps besides
/// the current one ([`Bank`]).
const BANKS: usize = 3;

/// The [`KERNEL_ROOTS`] the shadow filled under another SPRR_PERM_EL1
/// value, everything else as it is now: a kernel that makes one
/// permission index writable and back, as XNU does around its writes to
/// protected data, finds each value's tables again. Every reset and unmap
/// reaches them as it does the current roots.
#[derive(Clone, Copy)]
struct Bank {
    /// The SPRR_PERM_EL1 value, `None` while the roots are empty.
    el1: Option<u64>,
    roots: [u64; KERNEL_ROOTS.len()],
    /// When it was last the current bank, for replacement.
    used: u64,
}
const ROOTS: usize = 2 * VIEWS;
/// Frames reserved for roots and other permanent tables.
const PERMANENT_FRAMES: u64 = 64;
/// A root's entries.
const ROOT_ENTRIES: usize = 512;
/// log2 of the bytes a four-level root entry maps: 512 GiB.
const PML4_ENTRY_BITS: u32 = 39;
/// The last address of the lower half under LA57 (48 bits) and four-level
/// paging (47 bits).
const FIVE_LEVEL_LOWER_END: u64 = (1 << 48) - 1;
const FOUR_LEVEL_LOWER_END: u64 = (1 << 47) - 1;
/// The aligned bytes of a guest leaf one fault maps.
const FILL_WINDOW: u64 = 64 * 1024;
/// Pages a scoped invalidation flushes one by one; more reload CR3.
const INVLPG_PAGES: u64 = 16;
const FAULT_KIND: u64 = 0xffff;
pub(crate) const COUNTER_HZ: u64 = 24_000_000;

/// Fresh ticks from the actual installed physical Host's configured 24 MHz
/// clock. Native PMP services execute on the retained BSP owner and share this
/// same source, rather than reusing an Access timestamp or a copied sample.
pub(crate) fn fresh_counter() -> u64 {
    let state = state();
    counter_at_tsc(state, rdtsc())
}

fn counter_at_tsc(state: &State, tsc: u64) -> u64 {
    let ticks = tsc.saturating_sub(state.tsc_base);
    ((u128::from(ticks) * u128::from(state.counter_per_tsc)) >> 64) as u64
}

/// Convert an absolute BSP TSC deadline using the very same installed fixed
/// point ratio/base as fresh_counter; no guest-clock or nominal-Hz conversion.
pub(crate) fn counter_deadline(tsc: u64) -> stela_runtime::machine::engine::NativeEpochDeadline {
    stela_runtime::machine::engine::NativeEpochDeadline(counter_at_tsc(state(), tsc))
}

#[derive(Clone, Copy)]
struct Recorded {
    rip: u64,
    address: u64,
    write: bool,
    cause: FaultCause,
    /// RAX through R15 at the faulting instruction, by x86 register number.
    registers: [u64; 16],
}

pub struct State {
    ram: Vec<RamRange>,
    registered_ram: Option<alloc::sync::Arc<stela_runtime::memory::RegisteredSystemRam>>,
    pool: Pool,
    /// Engine root without any guest mapping.
    host_root: u64,
    roots: [u64; ROOTS],
    /// The kernel roots of other SPRR_PERM_EL1 values.
    banks: [Bank; BANKS],
    /// Switches to a bank's roots, and those that found the bank empty.
    bank_switches: u64,
    bank_misses: u64,
    /// A shadow-map attempt or software-TLB fill may have published guest
    /// translations. Only a complete reset can prove both halves clean again.
    legacy_translations_dirty: bool,
    current: usize,
    regime: Option<Regime>,
    /// The halves whose Tagged memory the tag-checked roots keep out.
    tag_checks: [bool; 2],
    code_virtual: u64,
    code_physical: u64,
    code_bytes: u64,
    /// The arena's part new code goes to, and the offset after the code
    /// installed last.
    code_unit: u64,
    code_used: u64,
    installed_immutable: InstalledCodeCache,
    recorded: Option<Recorded>,
    native: bool,
    tsc_base: u64,
    tsc_hz: u64,
    /// COUNTER_HZ / tsc_hz as a 0.64 fixed-point fraction: the counter is
    /// read several times per block, and a 128-bit division is a library
    /// call.
    counter_per_tsc: u64,
    apic: Apic,
    /// The APIC timer's ticks per second at divide-by-one.
    apic_hz: u64,
    pub fills: u64,
    pub resets: u64,
    /// Resets because a half's shadow frames ran out.
    pub exhausted: u64,
    /// Resets of the lower half alone.
    pub lower_resets: u64,
    /// Resets of the [`USER_VIEWS`] alone.
    pub user_resets: u64,
    /// Whole resets by [`Cause`].
    reset_causes: [u64; CAUSES],
    /// The [`Cause::Controls`] resets each field differed in ([`differing`]).
    control_fields: [u64; FIELDS],
    /// The controls the last of those resets went from and to.
    last_controls: Option<(mmu::Controls, mmu::Controls)>,
    /// The leaves each half was filled from.
    extents: [Extents; 2],
    /// TLBIs that unmapped ranges rather than whole halves.
    pub scoped: u64,
    /// Pages mapped beside a fault's from the same leaf.
    pub prefills: u64,
    pub stray: u64,
    /// TSC ticks spent in compiled guest code, its exits and faults.
    pub native_ticks: u64,
    #[cfg(feature = "native-profile")]
    native_profile: profile::Profile,
    /// Where the guest's address space lies beside the window.
    placement: Placement,
    /// The translated variant's software TLB, tagged by root, and the
    /// helper's bounce slot; without the slot the host has no helper.
    tlb: Tlb,
    bounce: Option<translated::Bounce>,
    /// Translation helper calls, the TLB fills they made and the accesses
    /// they ran through the bounce slot; shadow faults in the guard.
    pub helper_calls: u64,
    pub helper_fills: u64,
    pub bounces: u64,
    pub guard_faults: u64,
}

pub use crate::apic::rdtsc;

fn load_root(root: u64) {
    // SAFETY: every root maps the window, which holds all code and data in use.
    unsafe { asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) };
}

fn invlpg(address: u64) {
    // SAFETY: invalidating a TLB entry has no other effect.
    unsafe { asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags)) };
}

pub struct Config {
    pub ram: Vec<RamRange>,
    pub pool_physical: u64,
    pub pool_bytes: u64,
    /// The loader's root, whose window entries every root shares.
    pub window_root: u64,
    /// Processor-private executable alias; arena writes use the physmap.
    pub code_virtual: u64,
    pub code_physical: u64,
    pub code_bytes: u64,
    /// One common origin for every physical executor.
    pub tsc_base: u64,
    pub tsc_hz: u64,
    pub apic_base: u64,
    pub placement: Placement,
    /// The translation helper's bounce slot: its first page's address and
    /// the physical addresses of its two leaf entries.
    pub bounce: Option<(u64, [u64; 2])>,
}

/// Install the host state, leave the identity map and start the APIC.
///
/// # Safety
/// Runs once on this host processor, after its descriptor setup, with
/// interrupts disabled. Its pool, code arena and bounce entries are private to
/// this processor; the returned owner outlives every local native call/handler.
/// This owned post-EBS mount adopts stable relevant ISA/vendor/identity
/// declarations as a supported-platform requirement: trusted firmware and any
/// VMM preserve them throughout ownership. Stop and retire the owner before
/// physical reset/resume, microcode update or feature reconfiguration, including
/// SMT-shared changes; reinstall and re-enumerate afterwards. ExitBootServices
/// and CPUID do not prove that external promise or hardware qualification.
pub unsafe fn install(config: Config) -> Result<HostOwner, &'static str> {
    let mut pool = Pool {
        base: config.pool_physical,
        bytes: config.pool_bytes,
        permanent: 0,
        shadow: [0; 2],
        shadow_base: config.pool_physical + PERMANENT_FRAMES * PAGE,
        half: LOWER,
        peak: [0; 2],
    };
    for half in [LOWER, UPPER] {
        pool.reset_half(half);
    }
    let (first, last) = layout::window_entries();
    let window = layout::physical(config.window_root) as *const u64;
    let mut root = || -> Result<u64, &'static str> {
        let frame = pool.permanent().ok_or("page-table pool too small")?;
        for entry in first..=last {
            // SAFETY: a fresh permanent frame and the loader's root, both
            // through the physmap.
            unsafe {
                (layout::physical(frame) as *mut u64)
                    .add(entry)
                    .write(window.add(entry).read())
            };
        }
        Ok(frame)
    };
    let host_root = root()?;
    let mut roots = [0; ROOTS];
    for slot in &mut roots {
        *slot = root()?;
    }
    let mut banks = [Bank {
        el1: None,
        roots: [0; KERNEL_ROOTS.len()],
        used: 0,
    }; BANKS];
    for slot in banks.iter_mut().flat_map(|bank| &mut bank.roots) {
        *slot = root()?;
    }
    load_root(host_root);
    let apic = Apic::new(
        config.apic_base,
        layout::physical(config.apic_base & apic::BASE_ADDRESS),
    );
    // SAFETY: this processor owns its disjoint host state until the owner drops.
    let owner = unsafe {
        local::install(State {
            ram: config.ram,
            registered_ram: None,
            pool,
            host_root,
            roots,
            banks,
            bank_switches: 0,
            bank_misses: 0,
            legacy_translations_dirty: false,
            current: usize::MAX,
            regime: None,
            tag_checks: [false; 2],
            code_virtual: config.code_virtual,
            code_physical: config.code_physical,
            code_bytes: config.code_bytes,
            code_unit: 0,
            code_used: 0,
            installed_immutable: InstalledCodeCache::default(),
            recorded: None,
            native: false,
            tsc_base: config.tsc_base,
            tsc_hz: config.tsc_hz,
            counter_per_tsc: u64::try_from(
                (u128::from(COUNTER_HZ) << 64) / u128::from(config.tsc_hz),
            )
            .expect("the TSC is faster than the 24 MHz counter"),
            apic,
            apic_hz: 0,
            fills: 0,
            native_ticks: 0,
            #[cfg(feature = "native-profile")]
            native_profile: profile::Profile::default(),
            resets: 0,
            exhausted: 0,
            lower_resets: 0,
            user_resets: 0,
            reset_causes: [0; CAUSES],
            control_fields: [0; FIELDS],
            last_controls: None,
            extents: [Extents::new(), Extents::new()],
            scoped: 0,
            prefills: 0,
            stray: 0,
            placement: config.placement,
            tlb: Tlb::default(),
            bounce: config
                .bounce
                .map(|(address, entries)| translated::Bounce::new(address, entries)),
            helper_calls: 0,
            helper_fills: 0,
            bounces: 0,
            guard_faults: 0,
        })
    };
    let state = state();
    state.apic_hz = state
        .apic
        .start(SPURIOUS_VECTOR, TIMER_VECTOR, state.tsc_hz);
    Ok(owner)
}

/// The host's counters for the statistics line.
pub struct Statistics {
    /// Shadow faults filled, and the pages beside them mapped from the
    /// same leaves.
    pub fills: u64,
    pub prefills: u64,
    /// Resets of the whole shadow, those because a half ran out of frames,
    /// of the lower half alone, and TLBIs that unmapped ranges instead.
    pub resets: u64,
    pub exhausted: u64,
    pub lower_resets: u64,
    pub user_resets: u64,
    /// Whole resets by cause: exhausted frames, SPRR, TTBR0 and other
    /// controls, tag checks, invalidations and TLBIs of everything.
    pub reset_causes: [u64; CAUSES],
    /// The other-controls resets each field differed in: SCTLR, TCR, TTBR0,
    /// TTBR1, MAIR, SPRR, CTRR, the regime and stage 2.
    pub control_fields: [u64; FIELDS],
    /// The controls the last of those went from and to.
    pub last_controls: Option<(mmu::Controls, mmu::Controls)>,
    /// Switches to another SPRR_PERM_EL1 value's kernel roots, and those
    /// that found none kept.
    pub bank_switches: u64,
    pub bank_misses: u64,
    pub scoped: u64,
    pub stray: u64,
    /// The APIC timer frequency.
    pub apic_hz: u64,
    /// Translation helper calls, their TLB fills and bounced accesses, and
    /// shadow faults in the four-level guard.
    pub helper_calls: u64,
    pub helper_fills: u64,
    pub bounces: u64,
    pub guard_faults: u64,
    /// Each half's shadow bytes and the most it has held at once.
    pub shadow_bytes: u64,
    pub shadow_peak: [u64; 2],
}

pub fn statistics() -> Statistics {
    let state = state();
    Statistics {
        fills: state.fills,
        prefills: state.prefills,
        resets: state.resets,
        exhausted: state.exhausted,
        lower_resets: state.lower_resets,
        user_resets: state.user_resets,
        reset_causes: state.reset_causes,
        control_fields: state.control_fields,
        last_controls: state.last_controls,
        bank_switches: state.bank_switches,
        bank_misses: state.bank_misses,
        scoped: state.scoped,
        stray: state.stray,
        apic_hz: state.apic_hz,
        helper_calls: state.helper_calls,
        helper_fills: state.helper_fills,
        bounces: state.bounces,
        guard_faults: state.guard_faults,
        shadow_bytes: {
            let (start, end) = state.pool.range(LOWER);
            end - start
        },
        shadow_peak: state.pool.peak,
    }
}

/// TSC ticks spent in compiled guest code so far.
pub fn native_ticks() -> u64 {
    state().native_ticks
}

/// Serialize both sides of the reference-counter observation. Compiler fences
/// also prevent moving memory work across these opt-in profiling boundaries.
#[cfg(feature = "native-profile")]
fn profile_timestamp() -> u64 {
    use core::sync::atomic::{Ordering, compiler_fence};
    compiler_fence(Ordering::SeqCst);
    core::arch::x86_64::__cpuid(0);
    // SAFETY: the installed native Host runs at CPL0 with its live CPU owner.
    let value = unsafe { core::arch::x86_64::_rdtsc() };
    core::arch::x86_64::__cpuid(0);
    compiler_fence(Ordering::SeqCst);
    value
}

#[cfg(feature = "native-profile")]
pub(crate) fn profile_snapshot() -> profile::Snapshot {
    state().native_profile.snapshot()
}

/// Inclusive work counters retain the outer phase, so native helper calls in
/// stopped services do not masquerade as checked-body execution time.
#[cfg(feature = "native-profile")]
pub(crate) fn profile_work_report() {
    let snapshot = profile_snapshot();
    for work in stela_runtime::machine::engine::NativeTimingWork::ALL {
        let count = snapshot.work[work as usize];
        crate::output::arguments(format_args!(
            "NATIVE WORK sampled_bsp category={work:?} calls={} sampled_calls={} ticks={} phase_ticks={:?}\n",
            count.calls, count.sampled_calls, count.sampled_ticks, count.phase_ticks
        ));
    }
}

#[cfg(feature = "native-profile")]
pub(crate) fn profile_word_report() {
    use profile::words::Ranking;
    crate::output::arguments(format_args!(
        "NATIVE WORD coverage_sampled_bsp {:?}\n",
        state().native_profile.snapshot().words,
    ));
    for ranking in [
        Ranking::Frequency,
        Ranking::ObservedBytes,
        Ranking::MaximumBytes,
    ] {
        for row in state()
            .native_profile
            .top_words(ranking)
            .into_iter()
            .flatten()
        {
            crate::output::arguments(format_args!(
                "NATIVE WORD sampled_bsp rank={ranking:?} word={:#010x} event={:?} count_lower={} count_upper={} observed_attributed_bytes={} max_attributed_bytes={}\n",
                row.word,
                row.event,
                row.upper.saturating_sub(row.error),
                row.upper,
                row.observed_bytes,
                row.max_bytes,
            ));
        }
    }
}

impl State {
    fn host_physical(&self, guest: u64) -> Option<u64> {
        self.run(guest).map(|(host, _)| host)
    }

    /// The longest RAM run starting at `guest`, as (host, bytes).
    fn run(&self, guest: u64) -> Option<(u64, u64)> {
        ram::run(&self.ram, guest)
    }

    fn copy(&self, guest: u64, length: usize, mut action: impl FnMut(u64, usize, usize)) -> bool {
        ram::copy(&self.ram, guest, length, |host, done, chunk| {
            action(layout::physical(host), done, chunk);
        })
    }

    fn reset_shadow(&mut self, cause: Cause) {
        if !self.legacy_translations_dirty {
            return;
        }
        self.clear(LOWER);
        self.clear(UPPER);
        self.tlb.clear();
        self.resets += 1;
        self.reset_causes[cause as usize] += 1;
        self.reload();
        self.legacy_translations_dirty = false;
    }

    /// Drop the lower half's translations only.
    fn reset_lower(&mut self) {
        self.clear(LOWER);
        self.tlb.clear();
        self.lower_resets += 1;
        self.reload();
    }

    /// Drop the [`USER_VIEWS`] alone: what an SPRR_PERM_EL0 write changes.
    /// Their tables' frames stay taken until the next whole reset, as each
    /// half's frames are freed only together; a half that runs out of
    /// frames resets as it would otherwise.
    fn reset_user_views(&mut self) {
        for view in USER_VIEWS {
            for root in [self.roots[view], self.roots[VIEWS + view]] {
                self.detach(root, LOWER);
                self.detach(root, UPPER);
            }
        }
        // The banks' PAN roots too.
        for index in 0..BANKS {
            for (slot, &view) in KERNEL_ROOTS.iter().enumerate() {
                if USER_VIEWS.contains(&(view % VIEWS)) {
                    self.detach(self.banks[index].roots[slot], LOWER);
                    self.detach(self.banks[index].roots[slot], UPPER);
                }
            }
        }
        self.tlb.clear();
        self.user_resets += 1;
        if USER_VIEWS.contains(&(self.current % VIEWS)) {
            self.reload();
        }
    }

    /// Take the [`KERNEL_ROOTS`] of SPRR_PERM_EL1 value `to` from its bank,
    /// leaving those of `from` there: a bank of `to`, or else the least
    /// recently used, emptied.
    fn switch_bank(&mut self, from: u64, to: u64) {
        self.bank_switches += 1;
        let index = match self.banks.iter().position(|bank| bank.el1 == Some(to)) {
            Some(index) => index,
            None => {
                self.bank_misses += 1;
                let (index, _) = self
                    .banks
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, bank)| bank.used)
                    .expect("banks");
                for root in self.banks[index].roots {
                    self.detach(root, LOWER);
                    self.detach(root, UPPER);
                }
                index
            }
        };
        let bank = &mut self.banks[index];
        for (slot, &view) in KERNEL_ROOTS.iter().enumerate() {
            core::mem::swap(&mut bank.roots[slot], &mut self.roots[view]);
        }
        bank.el1 = Some(from);
        bank.used = self.bank_switches;
        // The software TLB is tagged by view, not root.
        self.tlb.clear();
        if KERNEL_VIEWS.contains(&(self.current % VIEWS)) {
            self.reload();
        }
    }

    /// Every root the shadow fills: the current ones and the banks'.
    fn all_roots(&self) -> impl Iterator<Item = u64> + use<> {
        let banked = self.banks.map(|bank| bank.roots);
        self.roots.into_iter().chain(banked.into_iter().flatten())
    }

    /// Unmap `half` from every root and free its frames.
    fn clear(&mut self, half: usize) {
        self.pool.reset_half(half);
        self.extents[half].clear();
        for root in self.all_roots() {
            self.detach(root, half);
        }
    }

    /// Unmap `half` from `root`, leaving its tables' frames taken.
    fn detach(&self, root: u64, half: usize) {
        let (first, last) = self.half_entries(half);
        for entry in first..=last {
            // SAFETY: permanent root frames through the physmap.
            unsafe { (layout::physical(root) as *mut u64).add(entry).write(0) };
        }
    }

    /// The first and last root entries of `half` of the guest's native
    /// ranges: under LA57 PML5 entry 0 or 511; on a four-level host the
    /// PML4 entries of the lower half, or those from `U` up.
    fn half_entries(&self, half: usize) -> (usize, usize) {
        match (self.placement, half) {
            (Placement::FiveLevel, LOWER) => (0, 0),
            (Placement::FiveLevel, _) => (ROOT_ENTRIES - 1, ROOT_ENTRIES - 1),
            (Placement::FourLevel { .. }, LOWER) => (0, ROOT_ENTRIES / 2 - 1),
            (Placement::FourLevel { .. }, _) => (
                ((self.placement.native_upper() >> PML4_ENTRY_BITS) as usize) % ROOT_ENTRIES,
                ROOT_ENTRIES - 1,
            ),
        }
    }

    /// The first and last address of `half` of the native ranges.
    fn half_range(&self, half: usize) -> (u64, u64) {
        match (self.placement, half) {
            (Placement::FiveLevel, LOWER) => (0, FIVE_LEVEL_LOWER_END),
            (Placement::FourLevel { .. }, LOWER) => (0, FOUR_LEVEL_LOWER_END),
            _ => (self.placement.native_upper(), u64::MAX),
        }
    }

    /// Load the current root again, which flushes the TLB of the guest's
    /// (non-global) mappings.
    fn reload(&mut self) {
        let root = if self.current < ROOTS {
            self.roots[self.current]
        } else {
            self.host_root
        };
        load_root(root);
    }
}

/// Guest page tables read through the RAM map.
struct GuestTables<'a>(&'a State);

impl mmu::TableMemory for GuestTables<'_> {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
        if let Some(ram) = &self.0.registered_ram {
            if !physical.is_multiple_of(8) {
                return None;
            }
            let mut bytes = [0; 8];
            // SAFETY: private descriptor staging; the retained canonical owner
            // supplies the all-writer mapping and exact native scalar read.
            unsafe { ram.read_physical(physical, &mut bytes) }.ok()?;
            return Some(u64::from_le_bytes(bytes));
        }
        let host = self.0.host_physical(physical)?;
        // SAFETY: guest RAM through the physmap.
        Some(unsafe { (layout::physical(host) as *const u64).read_volatile() })
    }
    fn update_descriptor(&mut self, physical: u64, old: u64, new: u64) -> Option<bool> {
        if let Some(ram) = &self.0.registered_ram {
            return ram.update_descriptor(physical, old, new).ok();
        }
        let host = self.0.host_physical(physical)?;
        let slot = layout::physical(host) as *mut u64;
        // SAFETY: guest RAM through the physmap; one PE, no concurrent walker.
        unsafe {
            if slot.read_volatile() != old {
                return Some(false);
            }
            slot.write_volatile(new);
        }
        Some(true)
    }
}

// Retained in the actual owning host stack through native/context execution.
// recovery_rsp points to the complete image, never to a naked GPR snapshot.
// The adjacent footer preserves both original stack ownership and BlockExit's
// two result registers across scalar-only state restoration.
#[repr(C)]
struct RecoveryFooter {
    xstate: super::xstate::EntryMetadata,
    saved_stack: u64,
    result_rax: u64,
    result_rdx: u64,
    context: u64,
}

global_asm!(
    r#"
.global stela_enter_block
stela_enter_block:
    xor r10d, r10d
    jmp stela_enter_owned
.global stela_enter_context_block
stela_enter_context_block:
    mov r10d, 1
stela_enter_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    push rdx
    mov rbx, rsp
    cmp qword ptr gs:[{recovery}], 0
    jne {refuse}
    cmp qword ptr gs:[{helper}], 0
    jne {refuse}
    mov r11, gs:[{image_bytes}]
    sub rsp, r11
    sub rsp, {footer_bytes}
    and rsp, -64
    lea rsi, [rsp + r11]
    mov [rsi + {saved_stack}], rbx
    mov [rsi + {context}], r10
    mov rdi, rsp
    call {save}
    fninit
    ldmxcsr [rip + {default_mxcsr}]
    // Publish only a complete actual owned image. IRQs use separate IST images;
    // a terminal NMI can never return through a half-published recovery frame.
    mov gs:[{recovery}], rsp
    mov r11, gs:[{image_bytes}]
    mov rbx, [rsp + r11 + {saved_stack}]
    mov rdi, [rbx + 16]
    mov rsi, [rbx + 8]
    cmp qword ptr [rsp + r11 + {context}], 0
    jne stela_enter_owned_context
    // Preserve the legacy generated-block entry alignment (RSP%16=0 in the
    // block); the separate context ABI remains SysV (RSP%16=8 in the block).
    sub rsp, 8
    call rsi
    add rsp, 8
    jmp stela_native_owned_return
stela_enter_owned_context:
    mov rdx, [rbx]
    call rdx
stela_native_owned_return:
    cmp qword ptr gs:[{helper}], 0
    jne {refuse}
    mov rsp, gs:[{recovery}]
    test rsp, rsp
    jz {refuse}
    mov r11, gs:[{image_bytes}]
    mov [rsp + r11 + {result_rax}], rax
    mov [rsp + r11 + {result_rdx}], rdx
    jmp stela_native_restore_host
.global stela_native_recover
stela_native_recover:
    mov rsp, gs:[{recovery}]
    test rsp, rsp
    jz {refuse}
    mov r11, gs:[{image_bytes}]
    mov qword ptr [rsp + r11 + {result_rax}], 0
    mov qword ptr [rsp + r11 + {result_rdx}], 0xffff
stela_native_restore_host:
    mov rdi, rsp
    lea rsi, [rsp + r11]
    call {restore}
    // No Rust runs between exact restoration and returning to the original
    // host stack. An abandoned helper has no surviving borrowed state/image.
    mov r11, gs:[{image_bytes}]
    mov rbx, [rsp + r11 + {saved_stack}]
    mov rax, [rsp + r11 + {result_rax}]
    mov rdx, [rsp + r11 + {result_rdx}]
    mov qword ptr gs:[{helper}], 0
    mov qword ptr gs:[{recovery}], 0
    mov rsp, rbx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
"#,
    recovery = const local::RECOVERY_RSP_OFFSET,
    helper = const local::HELPER_RSP_OFFSET,
    image_bytes = const local::XSTATE_IMAGE_BYTES_OFFSET,
    footer_bytes = const size_of::<RecoveryFooter>(),
    saved_stack = const core::mem::offset_of!(RecoveryFooter, saved_stack),
    result_rax = const core::mem::offset_of!(RecoveryFooter, result_rax),
    result_rdx = const core::mem::offset_of!(RecoveryFooter, result_rdx),
    context = const core::mem::offset_of!(RecoveryFooter, context),
    save = sym super::xstate::stela_xstate_save_owned,
    restore = sym super::xstate::stela_xstate_restore_owned,
    refuse = sym super::xstate::stela_xstate_boundary_refuse,
    default_mxcsr = sym super::xstate::DEFAULT_MXCSR,
);

unsafe extern "sysv64" {
    fn stela_enter_block(state: *mut GuestState, code: usize) -> BlockExit;
    fn stela_enter_context_block(
        state: *mut GuestState,
        context: *mut stela_compiler::context::ExecutionContext,
        code: usize,
    ) -> BlockExit;
    fn stela_native_recover();
}

fn in_code(state: &State, rip: u64) -> bool {
    state.native && (state.code_virtual..state.code_virtual + state.code_bytes).contains(&rip)
}

/// End the native block at `frame` and report `cause` to the engine.
fn abandon(state: &mut State, frame: &mut Frame, address: u64, write: bool, cause: FaultCause) {
    state.recorded = Some(Recorded {
        rip: frame.rip,
        address,
        write,
        cause,
        registers: [
            frame.rax, frame.rcx, frame.rdx, frame.rbx, frame.rsp, frame.rbp, frame.rsi, frame.rdi,
            frame.r8, frame.r9, frame.r10, frame.r11, frame.r12, frame.r13, frame.r14, frame.r15,
        ],
    });
    frame.rip = stela_native_recover as *const () as u64;
}

/// The guest's translation of the access at `address`, through the same
/// software walk for shadow faults and the translation helper: the
/// translation and the host physical address of its RAM page, or why the
/// engine must take the access (Arm checks watchpoints after translation,
/// `AArch64_TranslateAddress`, then Tag Checks).
fn resolve(
    state: &mut State,
    address: u64,
    write: bool,
    unprivileged: bool,
) -> Result<(mmu::Translation, u64), FaultCause> {
    let regime = state.regime.ok_or(FaultCause::NonCanonical)?;
    let access = if write { Access::Write } else { Access::Read };
    let requester = mmu::Requester {
        unprivileged: regime.requester.unprivileged || unprivileged,
        ..regime.requester
    };
    let translation = match mmu::translate(
        &regime.controls,
        address,
        access,
        requester,
        &mut GuestTables(state),
    ) {
        Outcome::Mapped(translation) => translation,
        Outcome::Fault(fault) => return Err(FaultCause::Guest(fault)),
        Outcome::Unsupported(unsupported) => return Err(FaultCause::Translation(unsupported)),
    };
    if regime.watch.blocks(address & !(PAGE - 1)) {
        return Err(FaultCause::Watched);
    }
    if regime.tag_blocks(address, translation.attributes) {
        return Err(FaultCause::TagChecked);
    }
    let page = translation.physical & !(PAGE - 1);
    let host = state.host_physical(page).ok_or(FaultCause::Device {
        physical: translation.physical,
    })?;
    Ok((translation, host))
}

/// #PF: fill the shadow from the guest's tables or end the block precisely.
pub fn page_fault(frame: &mut Frame, address: u64) {
    let state = state();
    if !in_code(state, frame.rip) {
        super::interrupts::fatal(frame);
    }
    let write = frame.error & 2 != 0;
    let Some(regime) = state.regime else {
        super::interrupts::fatal(frame);
    };
    // Only the native ranges are shadow; the rest is the engine's. An
    // access past a check an earlier one stood for may reach the guard
    // (`mmu::placement`): its own check finds where it goes.
    if !state.placement.native(address) {
        state.guard_faults += u64::from(state.placement.in_guard(address));
        return abandon(state, frame, address, write, FaultCause::NonCanonical);
    }
    let (translation, host) = match resolve(state, address, write, false) {
        Ok(resolved) => resolved,
        Err(cause) => return abandon(state, frame, address, write, cause),
    };
    let rights = PRESENT | NX | if translation.writable { WRITABLE } else { 0 };
    let root = state.roots[state.current];
    let virtual_page = address & !(PAGE - 1);
    let half = if address >> 63 == 0 { LOWER } else { UPPER };
    state.pool.half = half;
    // A failed allocation can already have installed intermediate tables.
    state.legacy_translations_dirty = true;
    if tables::map_page(&mut state.pool, root, virtual_page, host, rights).is_err() {
        // The shadow pool is exhausted: start over and map again.
        state.exhausted += 1;
        state.reset_shadow(Cause::Exhausted);
        state.pool.half = half;
        state.legacy_translations_dirty = true;
        if tables::map_page(&mut state.pool, root, virtual_page, host, rights).is_err() {
            super::interrupts::fatal(frame);
        }
    }
    invlpg(virtual_page);
    state.extents[half].record(address, translation.size, translation.global);
    // The rest of the leaf's window has the same translation and rights:
    // map its RAM pages that are not watched now, as a TLB entry covers
    // the whole leaf. Pages that were absent need no flush. A Tagged leaf
    // whose tags are checked maps only the passed page.
    if regime.tag_checks[half] && translation.attributes == mmu::attributes::TAGGED {
        state.fills += 1;
        return;
    }
    let (first, last) = shadow::window(address, translation.size, FILL_WINDOW);
    let mut page = first;
    loop {
        if page != virtual_page && !regime.watch.blocks(page) {
            let physical = translation
                .physical
                .wrapping_sub(address)
                .wrapping_add(page);
            if let Some(host) = state.host_physical(physical) {
                state.legacy_translations_dirty = true;
                if tables::map_page(&mut state.pool, root, page, host, rights).is_err() {
                    // Out of frames: the rest stays to fault.
                    break;
                }
                state.prefills += 1;
            }
        }
        if page >= last & !(PAGE - 1) {
            break;
        }
        page += PAGE;
    }
    state.fills += 1;
}

/// #GP or #UD inside native code ends the block; elsewhere it is fatal.
pub fn native_exception(frame: &mut Frame) {
    let state = state();
    if !in_code(state, frame.rip) {
        super::interrupts::fatal(frame);
    }
    let cause = if frame.vector == 13 {
        FaultCause::NonCanonical
    } else {
        FaultCause::InvalidOpcode
    };
    abandon(state, frame, 0, false, cause);
}

pub fn timer_interrupt() {
    local::interrupt();
    state().apic.eoi();
}

/// An idle-worker doorbell only. Stop requests live in generation-bound
/// mailboxes; delivery cannot authorize native-frame recovery or settlement.
pub(crate) fn wake_interrupt() {
    state().apic.eoi();
    // Release publication follows actual EOI; startup evidence cannot race
    // ahead of retirement of the directed interrupt at this physical LAPIC.
    local::doorbell();
}

pub(crate) fn doorbell_counter() -> &'static core::sync::atomic::AtomicU64 {
    local::doorbell_counter()
}

pub fn stray_interrupt(_vector: u8) {
    let state = state();
    state.stray += 1;
    state.apic.eoi();
}

/// Complete one real owner-local native return, retaining exact fault GPRs.
fn native_return(code: NativeCode, exit: BlockExit, entered: u64) -> NativeExit {
    let state = state();
    state.native = false;
    state.native_ticks += rdtsc() - entered;
    #[cfg(feature = "native-profile")]
    state.native_profile.exit(exit.kind);
    if exit.kind == FAULT_KIND
        && let Some(recorded) = state.recorded.take()
    {
        return NativeExit::Fault(NativeFault {
            // A chained block may lie below the entered one.
            offset: recorded.rip.wrapping_sub(code.0 as u64) as usize,
            address: recorded.address,
            write: recorded.write,
            cause: recorded.cause,
            registers: recorded.registers,
        });
    }
    NativeExit::Exit {
        next_pc: exit.next_pc,
        kind: exit.kind,
    }
}

/// The engine's handle; mutable native state belongs to this host processor.
pub struct BareHost<'a> {
    _owner: core::marker::PhantomData<&'a mut HostOwner>,
    _pinned: core::marker::PhantomData<*mut ()>,
}

/// The parts of the code arena, reclaimed for new code oldest first: the
/// code of the most recent seven eighths of the run is kept, and only the
/// oldest eighth's blocks compile again when they next run.
const CODE_UNITS: u64 = 8;

fn code_unit_bytes(state: &State) -> u64 {
    state.code_bytes / CODE_UNITS / 16 * 16
}

impl Host for BareHost<'_> {
    #[cfg(feature = "native-profile")]
    fn native_timing_work_start(
        &mut self,
        work: stela_runtime::machine::engine::NativeTimingWork,
    ) -> Option<u64> {
        state().native_profile.work_start(work, profile_timestamp)
    }
    #[cfg(feature = "native-profile")]
    fn native_timing_work_end(
        &mut self,
        work: stela_runtime::machine::engine::NativeTimingWork,
        started: u64,
    ) {
        state()
            .native_profile
            .work_end(work, started, profile_timestamp());
    }
    #[cfg(feature = "native-profile")]
    fn native_timing(&mut self, phase: stela_runtime::machine::engine::NativeTimingPhase) {
        let profile = &mut state().native_profile;
        if phase == stela_runtime::machine::engine::NativeTimingPhase::Begin
            && profile.needs_calibration()
        {
            profile.calibrate(profile_timestamp);
        }
        profile.event(phase, profile_timestamp);
    }
    #[cfg(feature = "native-profile")]
    fn native_instruction_sample(
        &mut self,
        sample: stela_runtime::machine::engine::NativeInstructionSample<'_>,
    ) {
        state().native_profile.instructions(sample);
    }
    fn native_worker(&self) -> Option<stela_runtime::machine::engine::publication::WorkerId> {
        local::native_worker()
    }

    fn native_cpu_lease(&self) -> Option<stela_runtime::NativeCpuLease> {
        local::native_cpu_lease()
    }

    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
        // The engine reads guest RAM only once its translation allowed it.
        super::speculation::fence();
        if let Some(ram) = &state().registered_ram {
            // SAFETY: the runtime passes private staging while the adopted
            // canonical reservation/mapping and source controls remain live.
            return unsafe { ram.read_physical(physical, buffer) }.is_ok();
        }
        state().copy(physical, buffer.len(), |host, done, chunk| {
            // SAFETY: guest RAM through the physmap and a distinct buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    host as *const u8,
                    buffer[done..].as_mut_ptr(),
                    chunk,
                )
            };
        })
    }

    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
        if let Some(ram) = &state().registered_ram {
            // SAFETY: private copyout staging; the canonical owner performs
            // every reached host write under the same physical writer gates.
            return unsafe { ram.publish_physical(physical, data) }.is_ok();
        }
        state().copy(physical, data.len(), |host, done, chunk| {
            // SAFETY: guest RAM through the physmap and a distinct buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), host as *mut u8, chunk)
            };
        })
    }

    fn check_ram_range(
        &mut self,
        physical: u64,
        bytes: usize,
        write: bool,
    ) -> Result<(), stela_runtime::machine::engine::DmaError> {
        let ram = state().registered_ram.as_ref().ok_or(
            stela_runtime::machine::engine::DmaError::Unsupported(
                "canonical DMA RAM owner is not installed",
            ),
        )?;
        ram.check_dma_range(physical, bytes, write)
            .map_err(|_| stela_runtime::machine::engine::DmaError::Memory)
    }
    fn read_ram_progress(
        &mut self,
        physical: u64,
        buffer: &mut [u8],
    ) -> Result<(), stela_runtime::machine::engine::TransferFault> {
        super::speculation::fence();
        let Some(ram) = &state().registered_ram else {
            return self.read_ram(physical, buffer).then_some(()).ok_or(
                stela_runtime::machine::engine::TransferFault {
                    error: stela_runtime::machine::engine::DmaError::Memory,
                    completed: 0,
                },
            );
        };
        // SAFETY: private DMA staging, same canonical reader/owner contract.
        unsafe { ram.read_physical_progress(physical, buffer) }.map_err(|fault| {
            stela_runtime::machine::engine::TransferFault {
                error: stela_runtime::machine::engine::DmaError::Memory,
                completed: fault.completed,
            }
        })
    }
    fn write_ram_progress(
        &mut self,
        physical: u64,
        data: &[u8],
    ) -> Result<(), stela_runtime::machine::engine::TransferFault> {
        let Some(ram) = &state().registered_ram else {
            return self.write_ram(physical, data).then_some(()).ok_or(
                stela_runtime::machine::engine::TransferFault {
                    error: stela_runtime::machine::engine::DmaError::Memory,
                    completed: 0,
                },
            );
        };
        // SAFETY: private staging, every writer participates in this same domain.
        unsafe { ram.publish_physical(physical, data) }.map_err(|fault| {
            stela_runtime::machine::engine::TransferFault {
                error: stela_runtime::machine::engine::DmaError::Memory,
                completed: fault.completed,
            }
        })
    }
    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        let state = state();
        let offset = state.code_used.next_multiple_of(16);
        let end = offset + code.len() as u64;
        if end > (state.code_unit + 1) * code_unit_bytes(state) {
            return Err(InstallError::Full);
        }
        // SAFETY: arena bytes through the writable physmap alias.
        unsafe {
            core::ptr::copy_nonoverlapping(
                code.as_ptr(),
                layout::physical(state.code_physical + offset) as *mut u8,
                code.len(),
            );
        }
        // Serialize before the executable alias runs the new bytes.
        core::arch::x86_64::__cpuid(0);
        state.code_used = end;
        #[cfg(feature = "native-profile")]
        state.native_profile.copied(code.len());
        Ok(NativeCode((state.code_virtual + offset) as usize))
    }

    fn install_immutable(&mut self, code: &Arc<Vec<u8>>) -> Result<NativeCode, InstallError> {
        if let Some(installed) = state().installed_immutable.lookup(code) {
            #[cfg(feature = "native-profile")]
            state().native_profile.installed(true);
            return Ok(installed);
        }
        #[cfg(feature = "native-profile")]
        state().native_profile.installed(false);
        let installed = self.install(code.as_slice())?;
        state().installed_immutable.record(code, installed);
        Ok(installed)
    }

    fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
        let state = state();
        state.installed_immutable.clear();
        let offset = code.0 as u64 - state.code_virtual;
        assert!(
            offset + bytes.len() as u64 <= state.code_bytes,
            "a patch outside the code arena"
        );
        // SAFETY: installed arena bytes through the writable physmap alias.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                layout::physical(state.code_physical + offset) as *mut u8,
                bytes.len(),
            );
        }
        // Serialize before the executable alias runs the new bytes.
        core::arch::x86_64::__cpuid(0);
    }

    fn discard_code(&mut self) {
        let state = state();
        state.installed_immutable.clear();
        state.code_unit = 0;
        state.code_used = 0;
    }

    fn reclaim_code(&mut self) -> Option<core::ops::Range<usize>> {
        let state = state();
        state.installed_immutable.clear();
        let unit = code_unit_bytes(state);
        state.code_unit = (state.code_unit + 1) % CODE_UNITS;
        state.code_used = state.code_unit * unit;
        let start = (state.code_virtual + state.code_used) as usize;
        Some(start..start + unit as usize)
    }

    fn memory_low(&self) -> bool {
        crate::ALLOCATOR.low()
    }

    unsafe fn execute(&mut self, code: NativeCode, guest: &mut GuestState) -> NativeExit {
        assert!(!state().native, "nested native block entry");
        state().native = true;
        let entered = rdtsc();
        // SAFETY: the engine passes installed system-mode block code.
        let exit = unsafe { stela_enter_block(guest, code.0) };
        native_return(code, exit, entered)
    }

    unsafe fn execute_context(
        &mut self,
        code: NativeCode,
        guest: &mut GuestState,
        context: &mut stela_compiler::context::ExecutionContext,
    ) -> Option<NativeExit> {
        assert!(!state().native, "nested native context entry");
        #[cfg(feature = "native-profile")]
        let measured = state().native_profile.work_start(
            stela_runtime::machine::engine::NativeTimingWork::NativeCall,
            profile_timestamp,
        );
        state().native = true;
        let entered = rdtsc();
        // SAFETY: caller holds the installed context block, exact live frame
        // and service owners. The current GS HostOwner retains recovery state.
        let exit = unsafe { stela_enter_context_block(guest, context, code.0) };
        let returned = native_return(code, exit, entered);
        #[cfg(feature = "native-profile")]
        if let Some(started) = measured {
            state().native_profile.work_end(
                stela_runtime::machine::engine::NativeTimingWork::NativeCall,
                started,
                profile_timestamp(),
            );
        }
        Some(returned)
    }

    fn context_entry(&mut self, code: NativeCode) -> Option<usize> {
        // Installed code is callable where it lies, through the executable arena alias.
        Some(code.0)
    }

    fn set_regime(&mut self, regime: &Regime) {
        let state = state();
        if let Some(current) = state.regime
            && current.controls != regime.controls
        {
            let (from, to) = (current.controls, regime.controls);
            // What the lower half's own inputs, E0PD1 and SPRR's
            // permission registers leave of the controls; each of those has
            // its own reset, and they compose (a context switch writes TTBR0 and
            // the thread's SPRR_PERM_EL0 together).
            let (lower_tcr, user_tcr) = match to.regime {
                mmu::Regime::El10 | mmu::Regime::El20 => (LOWER_TCR, USER_TCR),
                _ => (0, 0),
            };
            let own = lower_tcr | user_tcr;
            let rest = mmu::Controls {
                ttbr0: to.ttbr0,
                tcr: from.tcr & !own | to.tcr & own,
                // The fields that keep an index writable after the locks
                // change no access.
                sprr: mmu::Sprr {
                    el0: to.sprr.el0,
                    el1: to.sprr.el1,
                    fields: to.sprr.fields,
                    ..from.sprr
                },
                ..from
            };
            let lower = from.ttbr0 != to.ttbr0 || (from.tcr ^ to.tcr) & lower_tcr != 0;
            // TTBR0 translates only the lower half, but it can name the
            // ASID the upper half's non-global entries were made in.
            let asid = mmu::current_asid(&from) == mmu::current_asid(&to);
            if rest == to && (!lower || asid || !state.extents[UPPER].private()) {
                if lower {
                    state.reset_lower();
                }
                if from.sprr.el0 != to.sprr.el0 || (from.tcr ^ to.tcr) & user_tcr != 0 {
                    state.reset_user_views();
                }
                if from.sprr.el1 != to.sprr.el1 {
                    state.switch_bank(from.sprr.el1, to.sprr.el1);
                }
            } else {
                let ttbr0 = mmu::Controls {
                    ttbr0: to.ttbr0,
                    ..from
                };
                let sprr = mmu::Controls {
                    sprr: to.sprr,
                    ..from
                };
                let cause = if sprr == to {
                    Cause::Sprr
                } else if ttbr0 == to {
                    Cause::Table
                } else {
                    Cause::Controls
                };
                if matches!(cause, Cause::Controls) && state.legacy_translations_dirty {
                    let fields = differing(&from, &to);
                    for (count, differs) in state.control_fields.iter_mut().zip(fields) {
                        *count += u64::from(differs);
                    }
                    state.last_controls = Some((from, to));
                }
                state.reset_shadow(cause);
            }
        }
        // The tag-checked roots hold one pattern of checked halves.
        if regime.tag_checked() && regime.tag_checks != state.tag_checks {
            if state.tag_checks.contains(&true) {
                state.reset_shadow(Cause::Tags);
            }
            state.tag_checks = regime.tag_checks;
        }
        state.regime = Some(*regime);
        // EL0, EL1, EL1 with PAN, and the GXF guarded level (GL1).
        let view = match (
            regime.requester.el,
            regime.requester.pan,
            regime.requester.guarded,
        ) {
            (0, _, _) => EL0_VIEW,
            (_, _, true) => GUARDED_VIEW,
            (_, false, false) => EL1_VIEW,
            (_, true, false) => PAN_VIEW,
        } + if regime.tag_checked() { VIEWS } else { 0 };
        if state.current != view {
            state.current = view;
            load_root(state.roots[view]);
        }
    }

    fn isolate_predictions(&mut self) {
        super::speculation::isolate();
    }

    fn speculation_barrier(&self) {
        super::speculation::fence();
    }

    fn invalidate_translations(&mut self) {
        state().reset_shadow(Cause::Invalidated);
    }

    fn invalidate_reach(&mut self, reach: Reach) {
        let state = state();
        if reach == Reach::All {
            return state.reset_shadow(Cause::Maintained);
        }
        state.tlb.clear();
        let mut unmapped = Vec::new();
        let mut whole = false;
        for half in [LOWER, UPPER] {
            match state.extents[half].ranges(reach, state.half_range(half)) {
                None => {
                    state.clear(half);
                    whole = true;
                }
                Some(ranges) => unmapped.extend(ranges),
            }
        }
        let mut pages = 0u64;
        for &(first, last) in &unmapped {
            for root in state.all_roots() {
                tables::unmap(&state.pool, root, first, last);
            }
            pages = pages.saturating_add(((last - first) >> 12) + 1);
        }
        if whole || pages > INVLPG_PAGES {
            state.reload();
        } else {
            for &(first, last) in &unmapped {
                let mut page = first & !(PAGE - 1);
                loop {
                    invlpg(page);
                    if page >= last & !(PAGE - 1) {
                        break;
                    }
                    page += PAGE;
                }
            }
        }
        if whole {
            state.resets += 1;
        } else {
            state.scoped += 1;
        }
    }

    fn profile_ticks(&mut self) -> u64 {
        rdtsc()
    }

    fn counter(&mut self) -> u64 {
        fresh_counter()
    }

    fn arm_timer(&mut self, deadline: Option<u64>) {
        let now = self.counter();
        let state = state();
        let Some(deadline) = deadline else {
            state.apic.write(apic::INITIAL, 0);
            return;
        };
        let guest = deadline.saturating_sub(now).max(1);
        let ticks = u128::from(guest) * u128::from(state.apic_hz) / u128::from(COUNTER_HZ);
        let ticks = ticks.clamp(1, u128::from(u32::MAX)) as u32;
        state.apic.write(apic::LVT_TIMER, u32::from(TIMER_VECTOR));
        state.apic.write(apic::INITIAL, ticks);
    }

    fn wait_for_interrupt(&mut self) {
        local::clear_interrupt();
        // SAFETY: STI's interrupt shadow covers HLT, so no wake-up is lost.
        unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
    }

    fn report(&mut self, event: &stela_runtime::machine::Event) {
        super::report(event);
    }

    fn placement(&self) -> Placement {
        state().placement
    }

    fn translation_helper(&self) -> Option<u64> {
        state().bounce.as_ref().map(|_| translated::slot())
    }

    fn translations(&mut self) -> Option<&mut dyn stela_runtime::machine::Translations> {
        super::translations::store()
            .map(|store| store as &mut dyn stela_runtime::machine::Translations)
    }
}
